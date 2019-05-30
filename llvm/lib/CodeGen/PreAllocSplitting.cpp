//===-- PreAllocSplitting.cpp - Pre-allocation Interval Spltting Pass. ----===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements the machine instruction level pre-register allocation
// live interval splitting pass. It finds live interval barriers, i.e.
// instructions which will kill all physical registers in certain register
// classes, and split all live intervals which cross the barrier.
//
//===----------------------------------------------------------------------===//

#define DEBUG_TYPE "pre-alloc-split"
#include "VirtRegMap.h"
#include "llvm/CodeGen/CalcSpillWeights.h"
#include "llvm/CodeGen/LiveIntervalAnalysis.h"
#include "llvm/CodeGen/LiveStackAnalysis.h"
#include "llvm/CodeGen/MachineDominators.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineLoopInfo.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/CodeGen/Passes.h"
#include "llvm/CodeGen/RegisterCoalescer.h"
#include "llvm/Target/TargetInstrInfo.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/Target/TargetOptions.h"
#include "llvm/Target/TargetRegisterInfo.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DepthFirstIterator.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/Statistic.h"
using namespace llvm;

static cl::opt<int> PreSplitLimit("pre-split-limit", cl::init(-1), cl::Hidden);
static cl::opt<int> DeadSplitLimit("dead-split-limit", cl::init(-1),
                                   cl::Hidden);
static cl::opt<int> RestoreFoldLimit("restore-fold-limit", cl::init(-1),
                                     cl::Hidden);

STATISTIC(NumSplits, "Number of intervals split");
STATISTIC(NumRemats, "Number of intervals split by rematerialization");
STATISTIC(NumFolds, "Number of intervals split with spill folding");
STATISTIC(NumRestoreFolds, "Number of intervals split with restore folding");
STATISTIC(NumRenumbers, "Number of intervals renumbered into new registers");
STATISTIC(NumDeadSpills, "Number of dead spills removed");

namespace {
  class PreAllocSplitting : public MachineFunctionPass {
    MachineFunction       *CurrMF;
    const TargetMachine   *TM;
    const TargetInstrInfo *TII;
    const TargetRegisterInfo* TRI;
    MachineFrameInfo      *MFI;
    MachineRegisterInfo   *MRI;
    SlotIndexes           *SIs;
    LiveIntervals         *LIs;
    LiveStacks            *LSs;
    VirtRegMap            *VRM;

    // Barrier - Current barrier being processed.
    MachineInstr          *Barrier;

    // BarrierMBB - Basic block where the barrier resides in.
    MachineBasicBlock     *BarrierMBB;

    // Barrier - Current barrier index.
    SlotIndex     BarrierIdx;

    // CurrLI - Current live interval being split.
    LiveInterval          *CurrLI;

    // CurrSLI - Current stack slot live interval.
    LiveInterval          *CurrSLI;

    // CurrSValNo - Current val# for the stack slot live interval.
    VNInfo                *CurrSValNo;

    // IntervalSSMap - A map from live interval to spill slots.
    DenseMap<unsigned, int> IntervalSSMap;

    // Def2SpillMap - A map from a def instruction index to spill index.
    DenseMap<SlotIndex, SlotIndex> Def2SpillMap;

  public:
    static char ID;
    PreAllocSplitting()
      : MachineFunctionPass(&ID) {}

    virtual bool runOnMachineFunction(MachineFunction &MF);

    virtual void getAnalysisUsage(AnalysisUsage &AU) const {
      AU.setPreservesCFG();
      AU.addRequired<SlotIndexes>();
      AU.addPreserved<SlotIndexes>();
      AU.addRequired<LiveIntervals>();
      AU.addPreserved<LiveIntervals>();
      AU.addRequired<LiveStacks>();
      AU.addPreserved<LiveStacks>();
      AU.addPreserved<RegisterCoalescer>();
      AU.addPreserved<CalculateSpillWeights>();
      if (StrongPHIElim)
        AU.addPreservedID(StrongPHIEliminationID);
      else
        AU.addPreservedID(PHIEliminationID);
      AU.addRequired<MachineDominatorTree>();
      AU.addRequired<MachineLoopInfo>();
      AU.addRequired<VirtRegMap>();
      AU.addPreserved<MachineDominatorTree>();
      AU.addPreserved<MachineLoopInfo>();
      AU.addPreserved<VirtRegMap>();
      MachineFunctionPass::getAnalysisUsage(AU);
    }
    
    virtual void releaseMemory() {
      IntervalSSMap.clear();
      Def2SpillMap.clear();
    }

    virtual const char *getPassName() const {
      return "Pre-Register Allocaton Live Interval Splitting";
    }

    /// print - Implement the dump method.
    virtual void print(raw_ostream &O, const Module* M = 0) const {
      LIs->print(O, M);
    }


  private:

    MachineBasicBlock::iterator
      findSpillPoint(MachineBasicBlock*, MachineInstr*, MachineInstr*,
                     SmallPtrSet<MachineInstr*, 4>&);

    MachineBasicBlock::iterator
      findRestorePoint(MachineBasicBlock*, MachineInstr*, SlotIndex,
                     SmallPtrSet<MachineInstr*, 4>&);

    int CreateSpillStackSlot(unsigned, const TargetRegisterClass *);

    bool IsAvailableInStack(MachineBasicBlock*, unsigned,
                            SlotIndex, SlotIndex,
                            SlotIndex&, int&) const;

    void UpdateSpillSlotInterval(VNInfo*, SlotIndex, SlotIndex);

    bool SplitRegLiveInterval(LiveInterval*);

    bool SplitRegLiveIntervals(const TargetRegisterClass **,
                               SmallPtrSet<LiveInterval*, 8>&);
    
    bool createsNewJoin(LiveRange* LR, MachineBasicBlock* DefMBB,
                        MachineBasicBlock* BarrierMBB);
    bool Rematerialize(unsigned vreg, VNInfo* ValNo,
                       MachineInstr* DefMI,
                       MachineBasicBlock::iterator RestorePt,
                       SmallPtrSet<MachineInstr*, 4>& RefsInMBB);
    MachineInstr* FoldSpill(unsigned vreg, const TargetRegisterClass* RC,
                            MachineInstr* DefMI,
                            MachineInstr* Barrier,
                            MachineBasicBlock* MBB,
                            int& SS,
                            SmallPtrSet<MachineInstr*, 4>& RefsInMBB);
    MachineInstr* FoldRestore(unsigned vreg, 
                              const TargetRegisterClass* RC,
                              MachineInstr* Barrier,
                              MachineBasicBlock* MBB,
                              int SS,
                              SmallPtrSet<MachineInstr*, 4>& RefsInMBB);
    void RenumberValno(VNInfo* VN);
    void ReconstructLiveInterval(LiveInterval* LI);
    bool removeDeadSpills(SmallPtrSet<LiveInterval*, 8>& split);
    unsigned getNumberOfNonSpills(SmallPtrSet<MachineInstr*, 4>& MIs,
                               unsigned Reg, int FrameIndex, bool& TwoAddr);
    VNInfo* PerformPHIConstruction(MachineBasicBlock::iterator Use,
                                   MachineBasicBlock* MBB, LiveInterval* LI,
                                   SmallPtrSet<MachineInstr*, 4>& Visited,
            DenseMap<MachineBasicBlock*, SmallPtrSet<MachineInstr*, 2> >& Defs,
            DenseMap<MachineBasicBlock*, SmallPtrSet<MachineInstr*, 2> >& Uses,
                                      DenseMap<MachineInstr*, VNInfo*>& NewVNs,
                                DenseMap<MachineBasicBlock*, VNInfo*>& LiveOut,
                                DenseMap<MachineBasicBlock*, VNInfo*>& Phis,
                                        bool IsTopLevel, bool IsIntraBlock);
    VNInfo* PerformPHIConstructionFallBack(MachineBasicBlock::iterator Use,
                                   MachineBasicBlock* MBB, LiveInterval* LI,
                                   SmallPtrSet<MachineInstr*, 4>& Visited,
            DenseMap<MachineBasicBlock*, SmallPtrSet<MachineInstr*, 2> >& Defs,
            DenseMap<MachineBasicBlock*, SmallPtrSet<MachineInstr*, 2> >& Uses,
                                      DenseMap<MachineInstr*, VNInfo*>& NewVNs,
                                DenseMap<MachineBasicBlock*, VNInfo*>& LiveOut,
                                DenseMap<MachineBasicBlock*, VNInfo*>& Phis,
                                        bool IsTopLevel, bool IsIntraBlock);
};
} // end anonymous namespace

char PreAllocSplitting::ID = 0;

static RegisterPass<PreAllocSplitting>
X("pre-alloc-splitting", "Pre-Register Allocation Live Interval Splitting");

const PassInfo *const llvm::PreAllocSplittingID = &X;

/// findSpillPoint - Find a gap as far away from the given MI that's suitable
/// for spilling the current live interval. The index must be before any
/// defs and uses of the live interval register in the mbb. Return begin() if
/// none is found.
MachineBasicBlock::iterator
PreAllocSplitting::findSpillPoint(MachineBasicBlock *MBB, MachineInstr *MI,
                                  MachineInstr *DefMI,
                                  SmallPtrSet<MachineInstr*, 4> &RefsInMBB) {
  MachineBasicBlock::iterator Pt = MBB->begin();

  MachineBasicBlock::iterator MII = MI;
  MachineBasicBlock::iterator EndPt = DefMI
    ? MachineBasicBlock::iterator(DefMI) : MBB->begin();
    
  while (MII != EndPt && !RefsInMBB.count(MII) &&
         MII->getOpcode() != TRI->getCallFrameSetupOpcode())
    --MII;
  if (MII == EndPt || RefsInMBB.count(MII)) return Pt;
    
  while (MII != EndPt && !RefsInMBB.count(MII)) {
    // We can't insert the spill between the barrier (a call), and its
    // corresponding call frame setup.
    if (MII->getOpcode() == TRI->getCallFrameDestroyOpcode()) {
      while (MII->getOpcode() != TRI->getCallFrameSetupOpcode()) {
        --MII;
        if (MII == EndPt) {
          return Pt;
        }
      }
      continue;
    } else {
      Pt = MII;
    }
    
    if (RefsInMBB.count(MII))
      return Pt;
    
    
    --MII;
  }

  return Pt;
}

/// findRestorePoint - Find a gap in the instruction index map that's suitable
/// for restoring the current live interval value. The index must be before any
/// uses of the live interval register in the mbb. Return end() if none is
/// found.
MachineBasicBlock::iterator
PreAllocSplitting::findRestorePoint(MachineBasicBlock *MBB, MachineInstr *MI,
                                    SlotIndex LastIdx,
                                    SmallPtrSet<MachineInstr*, 4> &RefsInMBB) {
  // FIXME: Allow spill to be inserted to the beginning of the mbb. Update mbb
  // begin index accordingly.
  MachineBasicBlock::iterator Pt = MBB->end();
  MachineBasicBlock::iterator EndPt = MBB->getFirstTerminator();

  // We start at the call, so walk forward until we find the call frame teardown
  // since we can't insert restores before that.  Bail if we encounter a use
  // during this time.
  MachineBasicBlock::iterator MII = MI;
  if (MII == EndPt) return Pt;
  
  while (MII != EndPt && !RefsInMBB.count(MII) &&
         MII->getOpcode() != TRI->getCallFrameDestroyOpcode())
    ++MII;
  if (MII == EndPt || RefsInMBB.count(MII)) return Pt;
  ++MII;
  
  // FIXME: Limit the number of instructions to examine to reduce
  // compile time?
  while (MII != EndPt) {
    SlotIndex Index = LIs->getInstructionIndex(MII);
    if (Index > LastIdx)
      break;
      
    // We can't insert a restore between the barrier (a call) and its 
    // corresponding call frame teardown.
    if (MII->getOpcode() == TRI->getCallFrameSetupOpcode()) {
      do {
        if (MII == EndPt || RefsInMBB.count(MII)) return Pt;
        ++MII;
      } while (MII->getOpcode() != TRI->getCallFrameDestroyOpcode());
    } else {
      Pt = MII;
    }
    
    if (RefsInMBB.count(MII))
      return Pt;
    
    ++MII;
  }

  return Pt;
}

/// CreateSpillStackSlot - Create a stack slot for the live interval being
/// split. If the live interval was previously split, just reuse the same
/// slot.
int PreAllocSplitting::CreateSpillStackSlot(unsigned Reg,
                                            const TargetRegisterClass *RC) {
  int SS;
  DenseMap<unsigned, int>::iterator I = IntervalSSMap.find(Reg);
  if (I != IntervalSSMap.end()) {
    SS = I->second;
  } else {
    SS = MFI->CreateSpillStackObject(RC->getSize(), RC->getAlignment());
    IntervalSSMap[Reg] = SS;
  }

  // Create live interval for stack slot.
  CurrSLI = &LSs->getOrCreateInterval(SS, RC);
  if (CurrSLI->hasAtLeastOneValue())
    CurrSValNo = CurrSLI->getValNumInfo(0);
  else
    CurrSValNo = CurrSLI->getNextValue(SlotIndex(), 0, false,
                                       LSs->getVNInfoAllocator());
  return SS;
}

/// IsAvailableInStack - Return true if register is available in a split stack
/// slot at the specified index.
bool
PreAllocSplitting::IsAvailableInStack(MachineBasicBlock *DefMBB,
                                    unsigned Reg, SlotIndex DefIndex,
                                    SlotIndex RestoreIndex,
                                    SlotIndex &SpillIndex,
                                    int& SS) const {
  if (!DefMBB)
    return false;

  DenseMap<unsigned, int>::const_iterator I = IntervalSSMap.find(Reg);
  if (I == IntervalSSMap.end())
    return false;
  DenseMap<SlotIndex, SlotIndex>::const_iterator
    II = Def2SpillMap.find(DefIndex);
  if (II == Def2SpillMap.end())
    return false;

  // If last spill of def is in the same mbb as barrier mbb (where restore will
  // be), make sure it's not below the intended restore index.
  // FIXME: Undo the previous spill?
  assert(LIs->getMBBFromIndex(II->second) == DefMBB);
  if (DefMBB == BarrierMBB && II->second >= RestoreIndex)
    return false;

  SS = I->second;
  SpillIndex = II->second;
  return true;
}

/// UpdateSpillSlotInterval - Given the specified val# of the register live
/// interval being split, and the spill and restore indicies, update the live
/// interval of the spill stack slot.
void
PreAllocSplitting::UpdateSpillSlotInterval(VNInfo *ValNo, SlotIndex SpillIndex,
                                           SlotIndex RestoreIndex) {
  assert(LIs->getMBBFromIndex(RestoreIndex) == BarrierMBB &&
         "Expect restore in the barrier mbb");

  MachineBasicBlock *MBB = LIs->getMBBFromIndex(SpillIndex);
  if (MBB == BarrierMBB) {
    // Intra-block spill + restore. We are done.
    LiveRange SLR(SpillIndex, RestoreIndex, CurrSValNo);
    CurrSLI->addRange(SLR);
    return;
  }

  SmallPtrSet<MachineBasicBlock*, 4> Processed;
  SlotIndex EndIdx = LIs->getMBBEndIdx(MBB);
  LiveRange SLR(SpillIndex, EndIdx, CurrSValNo);
  CurrSLI->addRange(SLR);
  Processed.insert(MBB);

  // Start from the spill mbb, figure out the extend of the spill slot's
  // live interval.
  SmallVector<MachineBasicBlock*, 4> WorkList;
  const LiveRange *LR = CurrLI->getLiveRangeContaining(SpillIndex);
  if (LR->end > EndIdx)
    // If live range extend beyond end of mbb, add successors to work list.
    for (MachineBasicBlock::succ_iterator SI = MBB->succ_begin(),
           SE = MBB->succ_end(); SI != SE; ++SI)
      WorkList.push_back(*SI);

  while (!WorkList.empty()) {
    MachineBasicBlock *MBB = WorkList.back();
    WorkList.pop_back();
    if (Processed.count(MBB))
      continue;
    SlotIndex Idx = LIs->getMBBStartIdx(MBB);
    LR = CurrLI->getLiveRangeContaining(Idx);
    if (LR && LR->valno == ValNo) {
      EndIdx = LIs->getMBBEndIdx(MBB);
      if (Idx <= RestoreIndex && RestoreIndex < EndIdx) {
        // Spill slot live interval stops at the restore.
        LiveRange SLR(Idx, RestoreIndex, CurrSValNo);
        CurrSLI->addRange(SLR);
      } else if (LR->end > EndIdx) {
        // Live range extends beyond end of mbb, process successors.
        LiveRange SLR(Idx, EndIdx.getNextIndex(), CurrSValNo);
        CurrSLI->addRange(SLR);
        for (MachineBasicBlock::succ_iterator SI = MBB->succ_begin(),
               SE = MBB->succ_end(); SI != SE; ++SI)
          WorkList.push_back(*SI);
      } else {
        LiveRange SLR(Idx, LR->end, CurrSValNo);
        CurrSLI->addRange(SLR);
      }
      Processed.insert(MBB);
    }
  }
}

/// PerformPHIConstruction - From properly set up use and def lists, use a PHI
/// construction algorithm to compute the ranges and valnos for an interval.
VNInfo*
PreAllocSplitting::PerformPHIConstruction(MachineBasicBlock::iterator UseI,
                                       MachineBasicBlock* MBB, LiveInterval* LI,
                                       SmallPtrSet<MachineInstr*, 4>& Visited,
             DenseMap<MachineBasicBlock*, SmallPtrSet<MachineInstr*, 2> >& Defs,
             DenseMap<MachineBasicBlock*, SmallPtrSet<MachineInstr*, 2> >& Uses,
                                       DenseMap<MachineInstr*, VNInfo*>& NewVNs,
                                 DenseMap<MachineBasicBlock*, VNInfo*>& LiveOut,
                                 DenseMap<MachineBasicBlock*, VNInfo*>& Phis,
                                           bool IsTopLevel, bool IsIntraBlock) {
  // Return memoized result if it's available.
  if (IsTopLevel && Visited.count(UseI) && NewVNs.count(UseI))
    return NewVNs[UseI];
  else if (!IsTopLevel && IsIntraBlock && NewVNs.count(UseI))
    return NewVNs[UseI];
  else if (!IsIntraBlock && LiveOut.count(MBB))
    return LiveOut[MBB];
  
  // Check if our block contains any uses or defs.
  bool ContainsDefs = Defs.count(MBB);
  bool ContainsUses = Uses.count(MBB);
  
  VNInfo* RetVNI = 0;
  
  // Enumerate the cases of use/def contaning blocks.
  if (!ContainsDefs && !ContainsUses) {
    return PerformPHIConstructionFallBack(UseI, MBB, LI, Visited, Defs, Uses,
                                          NewVNs, LiveOut, Phis,
                                          IsTopLevel, IsIntraBlock);
  } else if (ContainsDefs && !ContainsUses) {
    SmallPtrSet<MachineInstr*, 2>& BlockDefs = Defs[MBB];

    // Search for the def in this block.  If we don't find it before the
    // instruction we care about, go to the fallback case.  Note that that
    // should never happen: this cannot be intrablock, so use should
    // always be an end() iterator.
    assert(UseI == MBB->end() && "No use marked in intrablock");
    
    MachineBasicBlock::iterator Walker = UseI;
    --Walker;
    while (Walker != MBB->begin()) {
      if (BlockDefs.count(Walker))
        break;
      --Walker;
    }
    
    // Once we've found it, extend its VNInfo to our instruction.
    SlotIndex DefIndex = LIs->getInstructionIndex(Walker);
    DefIndex = DefIndex.getDefIndex();
    SlotIndex EndIndex = LIs->getMBBEndIdx(MBB);
    
    RetVNI = NewVNs[Walker];
    LI->addRange(LiveRange(DefIndex, EndIndex, RetVNI));
  } else if (!ContainsDefs && ContainsUses) {
    SmallPtrSet<MachineInstr*, 2>& BlockUses = Uses[MBB];
    
    // Search for the use in this block that precedes the instruction we care 
    // about, going to the fallback case if we don't find it.    
    MachineBasicBlock::iterator Walker = UseI;
    bool found = false;
    while (Walker != MBB->begin()) {
      --Walker;
      if (BlockUses.count(Walker)) {
        found = true;
        break;
      }
    }

    if (!found)
      return PerformPHIConstructionFallBack(UseI, MBB, LI, Visited, Defs,
                                            Uses, NewVNs, LiveOut, Phis,
                                            IsTopLevel, IsIntraBlock);

    SlotIndex UseIndex = LIs->getInstructionIndex(Walker);
    UseIndex = UseIndex.getUseIndex();
    SlotIndex EndIndex;
    if (IsIntraBlock) {
      EndIndex = LIs->getInstructionIndex(UseI).getDefIndex();
    } else
      EndIndex = LIs->getMBBEndIdx(MBB);

    // Now, recursively phi construct the VNInfo for the use we found,
    // and then extend it to include the instruction we care about
    RetVNI = PerformPHIConstruction(Walker, MBB, LI, Visited, Defs, Uses,
                                    NewVNs, LiveOut, Phis, false, true);
    
    LI->addRange(LiveRange(UseIndex, EndIndex, RetVNI));
    
    // FIXME: Need to set kills properly for inter-block stuff.
    if (RetVNI->isKill(UseIndex)) RetVNI->removeKill(UseIndex);
    if (IsIntraBlock)
      RetVNI->addKill(EndIndex);
  } else if (ContainsDefs && ContainsUses) {
    SmallPtrSet<MachineInstr*, 2>& BlockDefs = Defs[MBB];
    SmallPtrSet<MachineInstr*, 2>& BlockUses = Uses[MBB];
    
    // This case is basically a merging of the two preceding case, with the
    // special note that checking for defs must take precedence over checking
    // for uses, because of two-address instructions.
    MachineBasicBlock::iterator Walker = UseI;
    bool foundDef = false;
    bool foundUse = false;
    while (Walker != MBB->begin()) {
      --Walker;
      if (BlockDefs.count(Walker)) {
        foundDef = true;
        break;
      } else if (BlockUses.count(Walker)) {
        foundUse = true;
        break;
      }
    }

    if (!foundDef && !foundUse)
      return PerformPHIConstructionFallBack(UseI, MBB, LI, Visited, Defs,
                                            Uses, NewVNs, LiveOut, Phis,
                                            IsTopLevel, IsIntraBlock);

    SlotIndex StartIndex = LIs->getInstructionIndex(Walker);
    StartIndex = foundDef ? StartIndex.getDefIndex() : StartIndex.getUseIndex();
    SlotIndex EndIndex;
    if (IsIntraBlock) {
      EndIndex = LIs->getInstructionIndex(UseI).getDefIndex();
    } else
      EndIndex = LIs->getMBBEndIdx(MBB);

    if (foundDef)
      RetVNI = NewVNs[Walker];
    else
      RetVNI = PerformPHIConstruction(Walker, MBB, LI, Visited, Defs, Uses,
                                      NewVNs, LiveOut, Phis, false, true);

    LI->addRange(LiveRange(StartIndex, EndIndex, RetVNI));
    
    if (foundUse && RetVNI->isKill(StartIndex))
      RetVNI->removeKill(StartIndex);
    if (IsIntraBlock) {
      RetVNI->addKill(EndIndex);
    }
  }
  
  // Memoize results so we don't have to recompute them.
  if (!IsIntraBlock) LiveOut[MBB] = RetVNI;
  else {
    if (!NewVNs.count(UseI))
      NewVNs[UseI] = RetVNI;
    Visited.insert(UseI);
  }

  return RetVNI;
}

/// PerformPHIConstructionFallBack - PerformPHIConstruction fall back path.
///
VNInfo*
PreAllocSplitting::PerformPHIConstructionFallBack(MachineBasicBlock::iterator UseI,
                                       MachineBasicBlock* MBB, LiveInterval* LI,
                                       SmallPtrSet<MachineInstr*, 4>& Visited,
             DenseMap<MachineBasicBlock*, SmallPtrSet<MachineInstr*, 2> >& Defs,
             DenseMap<MachineBasicBlock*, SmallPtrSet<MachineInstr*, 2> >& Uses,
                                       DenseMap<MachineInstr*, VNInfo*>& NewVNs,
                                 DenseMap<MachineBasicBlock*, VNInfo*>& LiveOut,
                                 DenseMap<MachineBasicBlock*, VNInfo*>& Phis,
                                           bool IsTopLevel, bool IsIntraBlock) {
  // NOTE: Because this is the fallback case from other cases, we do NOT
  // assume that we are not intrablock here.
  if (Phis.count(MBB)) return Phis[MBB]; 

  SlotIndex StartIndex = LIs->getMBBStartIdx(MBB);
  VNInfo *RetVNI = Phis[MBB] =
    LI->getNextValue(SlotIndex(), /*FIXME*/ 0, false,
                     LIs->getVNInfoAllocator());

  if (!IsIntraBlock) LiveOut[MBB] = RetVNI;
    
  // If there are no uses or defs between our starting point and the
  // beginning of the block, then recursive perform phi construction
  // on our predecessors.
  DenseMap<MachineBasicBlock*, VNInfo*> IncomingVNs;
  for (MachineBasicBlock::pred_iterator PI = MBB->pred_begin(),
         PE = MBB->pred_end(); PI != PE; ++PI) {
    VNInfo* Incoming = PerformPHIConstruction((*PI)->end(), *PI, LI, 
                                              Visited, Defs, Uses, NewVNs,
                                              LiveOut, Phis, false, false);
    if (Incoming != 0)
      IncomingVNs[*PI] = Incoming;
  }
    
  if (MBB->pred_size() == 1 && !RetVNI->hasPHIKill()) {
    VNInfo* OldVN = RetVNI;
    VNInfo* NewVN = IncomingVNs.begin()->second;
    VNInfo* MergedVN = LI->MergeValueNumberInto(OldVN, NewVN);
    if (MergedVN == OldVN) std::swap(OldVN, NewVN);
    
    for (DenseMap<MachineBasicBlock*, VNInfo*>::iterator LOI = LiveOut.begin(),
         LOE = LiveOut.end(); LOI != LOE; ++LOI)
      if (LOI->second == OldVN)
        LOI->second = MergedVN;
    for (DenseMap<MachineInstr*, VNInfo*>::iterator NVI = NewVNs.begin(),
         NVE = NewVNs.end(); NVI != NVE; ++NVI)
      if (NVI->second == OldVN)
        NVI->second = MergedVN;
    for (DenseMap<MachineBasicBlock*, VNInfo*>::iterator PI = Phis.begin(),
         PE = Phis.end(); PI != PE; ++PI)
      if (PI->second == OldVN)
        PI->second = MergedVN;
    RetVNI = MergedVN;
  } else {
    // Otherwise, merge the incoming VNInfos with a phi join.  Create a new
    // VNInfo to represent the joined value.
    for (DenseMap<MachineBasicBlock*, VNInfo*>::iterator I =
           IncomingVNs.begin(), E = IncomingVNs.end(); I != E; ++I) {
      I->second->setHasPHIKill(true);
      SlotIndex KillIndex(LIs->getMBBEndIdx(I->first), true);
      if (!I->second->isKill(KillIndex))
        I->second->addKill(KillIndex);
    }
  }
      
  SlotIndex EndIndex;
  if (IsIntraBlock) {
    EndIndex = LIs->getInstructionIndex(UseI).getDefIndex();
  } else
    EndIndex = LIs->getMBBEndIdx(MBB);
  LI->addRange(LiveRange(StartIndex, EndIndex, RetVNI));
  if (IsIntraBlock)
    RetVNI->addKill(EndIndex);

  // Memoize results so we don't have to recompute them.
  if (!IsIntraBlock)
    LiveOut[MBB] = RetVNI;
  else {
    if (!NewVNs.count(UseI))
      NewVNs[UseI] = RetVNI;
    Visited.insert(UseI);
  }

  return RetVNI;
}

/// ReconstructLiveInterval - Recompute a live interval from scratch.
void PreAllocSplitting::ReconstructLiveInterval(LiveInterval* LI) {
  VNInfo::Allocator& Alloc = LIs->getVNInfoAllocator();
  
  // Clear the old ranges and valnos;
  LI->clear();
  
  // Cache the uses and defs of the register
  typedef DenseMap<MachineBasicBlock*, SmallPtrSet<MachineInstr*, 2> > RegMap;
  RegMap Defs, Uses;
  
  // Keep track of the new VNs we're creating.
  DenseMap<MachineInstr*, VNInfo*> NewVNs;
  SmallPtrSet<VNInfo*, 2> PhiVNs;
  
  // Cache defs, and create a new VNInfo for each def.
  for (MachineRegisterInfo::def_iterator DI = MRI->def_begin(LI->reg),
       DE = MRI->def_end(); DI != DE; ++DI) {
    Defs[(*DI).getParent()].insert(&*DI);
    
    SlotIndex DefIdx = LIs->getInstructionIndex(&*DI);
    DefIdx = DefIdx.getDefIndex();
    
    assert(!DI->isPHI() && "PHI instr in code during pre-alloc splitting.");
    VNInfo* NewVN = LI->getNextValue(DefIdx, 0, true, Alloc);
    
    // If the def is a move, set the copy field.
    unsigned SrcReg, DstReg, SrcSubIdx, DstSubIdx;
    if (TII->isMoveInstr(*DI, SrcReg, DstReg, SrcSubIdx, DstSubIdx))
      if (DstReg == LI->reg)
        NewVN->setCopy(&*DI);
    
    NewVNs[&*DI] = NewVN;
  }
  
  // Cache uses as a separate pass from actually processing them.
  for (MachineRegisterInfo::use_iterator UI = MRI->use_begin(LI->reg),
       UE = MRI->use_end(); UI != UE; ++UI)
    Uses[(*UI).getParent()].insert(&*UI);
    
  // Now, actually process every use and use a phi construction algorithm
  // to walk from it to its reaching definitions, building VNInfos along
  // the way.
  DenseMap<MachineBasicBlock*, VNInfo*> LiveOut;
  DenseMap<MachineBasicBlock*, VNInfo*> Phis;
  SmallPtrSet<MachineInstr*, 4> Visited;
  for (MachineRegisterInfo::use_iterator UI = MRI->use_begin(LI->reg),
       UE = MRI->use_end(); UI != UE; ++UI) {
    PerformPHIConstruction(&*UI, UI->getParent(), LI, Visited, Defs,
                           Uses, NewVNs, LiveOut, Phis, true, true); 
  }
  
  // Add ranges for dead defs
  for (MachineRegisterInfo::def_iterator DI = MRI->def_begin(LI->reg),
       DE = MRI->def_end(); DI != DE; ++DI) {
    SlotIndex DefIdx = LIs->getInstructionIndex(&*DI);
    DefIdx = DefIdx.getDefIndex();
    
    if (LI->liveAt(DefIdx)) continue;
    
    VNInfo* DeadVN = NewVNs[&*DI];
    LI->addRange(LiveRange(DefIdx, DefIdx.getNextSlot(), DeadVN));
    DeadVN->addKill(DefIdx);
  }

  // Update kill markers.
  for (LiveInterval::vni_iterator VI = LI->vni_begin(), VE = LI->vni_end();
       VI != VE; ++VI) {
    VNInfo* VNI = *VI;
    for (unsigned i = 0, e = VNI->kills.size(); i != e; ++i) {
      SlotIndex KillIdx = VNI->kills[i];
      if (KillIdx.isPHI())
        continue;
      MachineInstr *KillMI = LIs->getInstructionFromIndex(KillIdx);
      if (KillMI) {
        MachineOperand *KillMO = KillMI->findRegisterUseOperand(CurrLI->reg);
        if (KillMO)
          // It could be a dead def.
          KillMO->setIsKill();
      }
    }
  }
}

/// RenumberValno - Split the given valno out into a new vreg, allowing it to
/// be allocated to a different register.  This function creates a new vreg,
/// copies the valno and its live ranges over to the new vreg's interval,
/// removes them from the old interval, and rewrites all uses and defs of
/// the original reg to the new vreg within those ranges.
void PreAllocSplitting::RenumberValno(VNInfo* VN) {
  SmallVector<VNInfo*, 4> Stack;
  SmallVector<VNInfo*, 4> VNsToCopy;
  Stack.push_back(VN);

  // Walk through and copy the valno we care about, and any other valnos
  // that are two-address redefinitions of the one we care about.  These
  // will need to be rewritten as well.  We also check for safety of the 
  // renumbering here, by making sure that none of the valno involved has
  // phi kills.
  while (!Stack.empty()) {
    VNInfo* OldVN = Stack.back();
    Stack.pop_back();
    
    // Bail out if we ever encounter a valno that has a PHI kill.  We can't
    // renumber these.
    if (OldVN->hasPHIKill()) return;
    
    VNsToCopy.push_back(OldVN);
    
    // Locate two-address redefinitions
    for (VNInfo::KillSet::iterator KI = OldVN->kills.begin(),
         KE = OldVN->kills.end(); KI != KE; ++KI) {
      assert(!KI->isPHI() &&
             "VN previously reported having no PHI kills.");
      MachineInstr* MI = LIs->getInstructionFromIndex(*KI);
      unsigned DefIdx = MI->findRegisterDefOperandIdx(CurrLI->reg);
      if (DefIdx == ~0U) continue;
      if (MI->isRegTiedToUseOperand(DefIdx)) {
        VNInfo* NextVN =
          CurrLI->findDefinedVNInfoForRegInt(KI->getDefIndex());
        if (NextVN == OldVN) continue;
        Stack.push_back(NextVN);
      }
    }
  }
  
  // Create the new vreg
  unsigned NewVReg = MRI->createVirtualRegister(MRI->getRegClass(CurrLI->reg));
  
  // Create the new live interval
  LiveInterval& NewLI = LIs->getOrCreateInterval(NewVReg);
  
  for (SmallVector<VNInfo*, 4>::iterator OI = VNsToCopy.begin(), OE = 
       VNsToCopy.end(); OI != OE; ++OI) {
    VNInfo* OldVN = *OI;
    
    // Copy the valno over
    VNInfo* NewVN = NewLI.createValueCopy(OldVN, LIs->getVNInfoAllocator());
    NewLI.MergeValueInAsValue(*CurrLI, OldVN, NewVN);

    // Remove the valno from the old interval
    CurrLI->removeValNo(OldVN);
  }
  
  // Rewrite defs and uses.  This is done in two stages to avoid invalidating
  // the reg_iterator.
  SmallVector<std::pair<MachineInstr*, unsigned>, 8> OpsToChange;
  
  for (MachineRegisterInfo::reg_iterator I = MRI->reg_begin(CurrLI->reg),
         E = MRI->reg_end(); I != E; ++I) {
    MachineOperand& MO = I.getOperand();
    SlotIndex InstrIdx = LIs->getInstructionIndex(&*I);
    
    if ((MO.isUse() && NewLI.liveAt(InstrIdx.getUseIndex())) ||
        (MO.isDef() && NewLI.liveAt(InstrIdx.getDefIndex())))
      OpsToChange.push_back(std::make_pair(&*I, I.getOperandNo()));
  }
  
  for (SmallVector<std::pair<MachineInstr*, unsigned>, 8>::iterator I =
       OpsToChange.begin(), E = OpsToChange.end(); I != E; ++I) {
    MachineInstr* Inst = I->first;
    unsigned OpIdx = I->second;
    MachineOperand& MO = Inst->getOperand(OpIdx);
    MO.setReg(NewVReg);
  }
  
  // Grow the VirtRegMap, since we've created a new vreg.
  VRM->grow();
  
  // The renumbered vreg shares a stack slot with the old register.
  if (IntervalSSMap.count(CurrLI->reg))
    IntervalSSMap[NewVReg] = IntervalSSMap[CurrLI->reg];
  
  NumRenumbers++;
}

bool PreAllocSplitting::Rematerialize(unsigned VReg, VNInfo* ValNo,
                                      MachineInstr* DefMI,
                                      MachineBasicBlock::iterator RestorePt,
                                    SmallPtrSet<MachineInstr*, 4>& RefsInMBB) {
  MachineBasicBlock& MBB = *RestorePt->getParent();
  
  MachineBasicBlock::iterator KillPt = BarrierMBB->end();
  if (!ValNo->isDefAccurate() || DefMI->getParent() == BarrierMBB)
    KillPt = findSpillPoint(BarrierMBB, Barrier, NULL, RefsInMBB);
  else
    KillPt = llvm::next(MachineBasicBlock::iterator(DefMI));
  
  if (KillPt == DefMI->getParent()->end())
    return false;
  
  TII->reMaterialize(MBB, RestorePt, VReg, 0, DefMI, TRI);
  SlotIndex RematIdx = LIs->InsertMachineInstrInMaps(prior(RestorePt));
  
  ReconstructLiveInterval(CurrLI);
  RematIdx = RematIdx.getDefIndex();
  RenumberValno(CurrLI->findDefinedVNInfoForRegInt(RematIdx));
  
  ++NumSplits;
  ++NumRemats;
  return true;  
}

MachineInstr* PreAllocSplitting::FoldSpill(unsigned vreg, 
                                           const TargetRegisterClass* RC,
                                           MachineInstr* DefMI,
                                           MachineInstr* Barrier,
                                           MachineBasicBlock* MBB,
                                           int& SS,
                                    SmallPtrSet<MachineInstr*, 4>& RefsInMBB) {
  // Go top down if RefsInMBB is empty.
  if (RefsInMBB.empty())
    return 0;
  
  MachineBasicBlock::iterator FoldPt = Barrier;
  while (&*FoldPt != DefMI && FoldPt != MBB->begin() &&
         !RefsInMBB.count(FoldPt))
    --FoldPt;
  
  int OpIdx = FoldPt->findRegisterDefOperandIdx(vreg, false);
  if (OpIdx == -1)
    return 0;
  
  SmallVector<unsigned, 1> Ops;
  Ops.push_back(OpIdx);
  
  if (!TII->canFoldMemoryOperand(FoldPt, Ops))
    return 0;
  
  DenseMap<unsigned, int>::iterator I = IntervalSSMap.find(vreg);
  if (I != IntervalSSMap.end()) {
    SS = I->second;
  } else {
    SS = MFI->CreateSpillStackObject(RC->getSize(), RC->getAlignment());
  }
  
  MachineInstr* FMI = TII->foldMemoryOperand(*MBB->getParent(),
                                             FoldPt, Ops, SS);
  
  if (FMI) {
    LIs->ReplaceMachineInstrInMaps(FoldPt, FMI);
    FMI = MBB->insert(MBB->erase(FoldPt), FMI);
    ++NumFolds;
    
    IntervalSSMap[vreg] = SS;
    CurrSLI = &LSs->getOrCreateInterval(SS, RC);
    if (CurrSLI->hasAtLeastOneValue())
      CurrSValNo = CurrSLI->getValNumInfo(0);
    else
      CurrSValNo = CurrSLI->getNextValue(SlotIndex(), 0, false,
                                         LSs->getVNInfoAllocator());
  }
  
  return FMI;
}

MachineInstr* PreAllocSplitting::FoldRestore(unsigned vreg, 
                                             const TargetRegisterClass* RC,
                                             MachineInstr* Barrier,
                                             MachineBasicBlock* MBB,
                                             int SS,
                                     SmallPtrSet<MachineInstr*, 4>& RefsInMBB) {
  if ((int)RestoreFoldLimit != -1 && RestoreFoldLimit == (int)NumRestoreFolds)
    return 0;
                                       
  // Go top down if RefsInMBB is empty.
  if (RefsInMBB.empty())
    return 0;
  
  // Can't fold a restore between a call stack setup and teardown.
  MachineBasicBlock::iterator FoldPt = Barrier;
  
  // Advance from barrier to call frame teardown.
  while (FoldPt != MBB->getFirstTerminator() &&
         FoldPt->getOpcode() != TRI->getCallFrameDestroyOpcode()) {
    if (RefsInMBB.count(FoldPt))
      return 0;
    
    ++FoldPt;
  }
  
  if (FoldPt == MBB->getFirstTerminator())
    return 0;
  else
    ++FoldPt;
  
  // Now find the restore point.
  while (FoldPt != MBB->getFirstTerminator() && !RefsInMBB.count(FoldPt)) {
    if (FoldPt->getOpcode() == TRI->getCallFrameSetupOpcode()) {
      while (FoldPt != MBB->getFirstTerminator() &&
             FoldPt->getOpcode() != TRI->getCallFrameDestroyOpcode()) {
        if (RefsInMBB.count(FoldPt))
          return 0;
        
        ++FoldPt;
      }
      
      if (FoldPt == MBB->getFirstTerminator())
        return 0;
    } 
    
    ++FoldPt;
  }
  
  if (FoldPt == MBB->getFirstTerminator())
    return 0;
  
  int OpIdx = FoldPt->findRegisterUseOperandIdx(vreg, true);
  if (OpIdx == -1)
    return 0;
  
  SmallVector<unsigned, 1> Ops;
  Ops.push_back(OpIdx);
  
  if (!TII->canFoldMemoryOperand(FoldPt, Ops))
    return 0;
  
  MachineInstr* FMI = TII->foldMemoryOperand(*MBB->getParent(),
                                             FoldPt, Ops, SS);
  
  if (FMI) {
    LIs->ReplaceMachineInstrInMaps(FoldPt, FMI);
    FMI = MBB->insert(MBB->erase(FoldPt), FMI);
    ++NumRestoreFolds;
  }
  
  return FMI;
}

/// SplitRegLiveInterval - Split (spill and restore) the given live interval
/// so it would not cross the barrier that's being processed. Shrink wrap
/// (minimize) the live interval to the last uses.
bool PreAllocSplitting::SplitRegLiveInterval(LiveInterval *LI) {
  DEBUG(dbgs() << "Pre-alloc splitting " << LI->reg << " for " << *Barrier
               << "  result: ");

  CurrLI = LI;

  // Find live range where current interval cross the barrier.
  LiveInterval::iterator LR =
    CurrLI->FindLiveRangeContaining(BarrierIdx.getUseIndex());
  VNInfo *ValNo = LR->valno;

  assert(!ValNo->isUnused() && "Val# is defined by a dead def?");

  MachineInstr *DefMI = ValNo->isDefAccurate()
    ? LIs->getInstructionFromIndex(ValNo->def) : NULL;

  // If this would create a new join point, do not split.
  if (DefMI && createsNewJoin(LR, DefMI->getParent(), Barrier->getParent())) {
    DEBUG(dbgs() << "FAILED (would create a new join point).\n");
    return false;
  }

  // Find all references in the barrier mbb.
  SmallPtrSet<MachineInstr*, 4> RefsInMBB;
  for (MachineRegisterInfo::reg_iterator I = MRI->reg_begin(CurrLI->reg),
         E = MRI->reg_end(); I != E; ++I) {
    MachineInstr *RefMI = &*I;
    if (RefMI->getParent() == BarrierMBB)
      RefsInMBB.insert(RefMI);
  }

  // Find a point to restore the value after the barrier.
  MachineBasicBlock::iterator RestorePt =
    findRestorePoint(BarrierMBB, Barrier, LR->end, RefsInMBB);
  if (RestorePt == BarrierMBB->end()) {
    DEBUG(dbgs() << "FAILED (could not find a suitable restore point).\n");
    return false;
  }

  if (DefMI && LIs->isReMaterializable(*LI, ValNo, DefMI))
    if (Rematerialize(LI->reg, ValNo, DefMI, RestorePt, RefsInMBB)) {
      DEBUG(dbgs() << "success (remat).\n");
      return true;
    }

  // Add a spill either before the barrier or after the definition.
  MachineBasicBlock *DefMBB = DefMI ? DefMI->getParent() : NULL;
  const TargetRegisterClass *RC = MRI->getRegClass(CurrLI->reg);
  SlotIndex SpillIndex;
  MachineInstr *SpillMI = NULL;
  int SS = -1;
  if (!ValNo->isDefAccurate()) {
    // If we don't know where the def is we must split just before the barrier.
    if ((SpillMI = FoldSpill(LI->reg, RC, 0, Barrier,
                            BarrierMBB, SS, RefsInMBB))) {
      SpillIndex = LIs->getInstructionIndex(SpillMI);
    } else {
      MachineBasicBlock::iterator SpillPt = 
        findSpillPoint(BarrierMBB, Barrier, NULL, RefsInMBB);
      if (SpillPt == BarrierMBB->begin()) {
        DEBUG(dbgs() << "FAILED (could not find a suitable spill point).\n");
        return false; // No gap to insert spill.
      }
      // Add spill.
    
      SS = CreateSpillStackSlot(CurrLI->reg, RC);
      TII->storeRegToStackSlot(*BarrierMBB, SpillPt, CurrLI->reg, true, SS, RC);
      SpillMI = prior(SpillPt);
      SpillIndex = LIs->InsertMachineInstrInMaps(SpillMI);
    }
  } else if (!IsAvailableInStack(DefMBB, CurrLI->reg, ValNo->def,
                                 LIs->getZeroIndex(), SpillIndex, SS)) {
    // If it's already split, just restore the value. There is no need to spill
    // the def again.
    if (!DefMI) {
      DEBUG(dbgs() << "FAILED (def is dead).\n");
      return false; // Def is dead. Do nothing.
    }
    
    if ((SpillMI = FoldSpill(LI->reg, RC, DefMI, Barrier,
                             BarrierMBB, SS, RefsInMBB))) {
      SpillIndex = LIs->getInstructionIndex(SpillMI);
    } else {
      // Check if it's possible to insert a spill after the def MI.
      MachineBasicBlock::iterator SpillPt;
      if (DefMBB == BarrierMBB) {
        // Add spill after the def and the last use before the barrier.
        SpillPt = findSpillPoint(BarrierMBB, Barrier, DefMI,
                                 RefsInMBB);
        if (SpillPt == DefMBB->begin()) {
          DEBUG(dbgs() << "FAILED (could not find a suitable spill point).\n");
          return false; // No gap to insert spill.
        }
      } else {
        SpillPt = llvm::next(MachineBasicBlock::iterator(DefMI));
        if (SpillPt == DefMBB->end()) {
          DEBUG(dbgs() << "FAILED (could not find a suitable spill point).\n");
          return false; // No gap to insert spill.
        }
      }
      // Add spill. 
      SS = CreateSpillStackSlot(CurrLI->reg, RC);
      TII->storeRegToStackSlot(*DefMBB, SpillPt, CurrLI->reg, false, SS, RC);
      SpillMI = prior(SpillPt);
      SpillIndex = LIs->InsertMachineInstrInMaps(SpillMI);
    }
  }

  // Remember def instruction index to spill index mapping.
  if (DefMI && SpillMI)
    Def2SpillMap[ValNo->def] = SpillIndex;

  // Add restore.
  bool FoldedRestore = false;
  SlotIndex RestoreIndex;
  if (MachineInstr* LMI = FoldRestore(CurrLI->reg, RC, Barrier,
                                      BarrierMBB, SS, RefsInMBB)) {
    RestorePt = LMI;
    RestoreIndex = LIs->getInstructionIndex(RestorePt);
    FoldedRestore = true;
  } else {
    TII->loadRegFromStackSlot(*BarrierMBB, RestorePt, CurrLI->reg, SS, RC);
    MachineInstr *LoadMI = prior(RestorePt);
    RestoreIndex = LIs->InsertMachineInstrInMaps(LoadMI);
  }

  // Update spill stack slot live interval.
  UpdateSpillSlotInterval(ValNo, SpillIndex.getUseIndex().getNextSlot(),
                          RestoreIndex.getDefIndex());

  ReconstructLiveInterval(CurrLI);

  if (!FoldedRestore) {
    SlotIndex RestoreIdx = LIs->getInstructionIndex(prior(RestorePt));
    RestoreIdx = RestoreIdx.getDefIndex();
    RenumberValno(CurrLI->findDefinedVNInfoForRegInt(RestoreIdx));
  }
  
  ++NumSplits;
  DEBUG(dbgs() << "success.\n");
  return true;
}

/// SplitRegLiveIntervals - Split all register live intervals that cross the
/// barrier that's being processed.
bool
PreAllocSplitting::SplitRegLiveIntervals(const TargetRegisterClass **RCs,
                                         SmallPtrSet<LiveInterval*, 8>& Split) {
  // First find all the virtual registers whose live intervals are intercepted
  // by the current barrier.
  SmallVector<LiveInterval*, 8> Intervals;
  for (const TargetRegisterClass **RC = RCs; *RC; ++RC) {
    // FIXME: If it's not safe to move any instruction that defines the barrier
    // register class, then it means there are some special dependencies which
    // codegen is not modelling. Ignore these barriers for now.
    if (!TII->isSafeToMoveRegClassDefs(*RC))
      continue;
    std::vector<unsigned> &VRs = MRI->getRegClassVirtRegs(*RC);
    for (unsigned i = 0, e = VRs.size(); i != e; ++i) {
      unsigned Reg = VRs[i];
      if (!LIs->hasInterval(Reg))
        continue;
      LiveInterval *LI = &LIs->getInterval(Reg);
      if (LI->liveAt(BarrierIdx) && !Barrier->readsRegister(Reg))
        // Virtual register live interval is intercepted by the barrier. We
        // should split and shrink wrap its interval if possible.
        Intervals.push_back(LI);
    }
  }

  // Process the affected live intervals.
  bool Change = false;
  while (!Intervals.empty()) {
    if (PreSplitLimit != -1 && (int)NumSplits == PreSplitLimit)
      break;
    LiveInterval *LI = Intervals.back();
    Intervals.pop_back();
    bool result = SplitRegLiveInterval(LI);
    if (result) Split.insert(LI);
    Change |= result;
  }

  return Change;
}

unsigned PreAllocSplitting::getNumberOfNonSpills(
                                  SmallPtrSet<MachineInstr*, 4>& MIs,
                                  unsigned Reg, int FrameIndex,
                                  bool& FeedsTwoAddr) {
  unsigned NonSpills = 0;
  for (SmallPtrSet<MachineInstr*, 4>::iterator UI = MIs.begin(), UE = MIs.end();
       UI != UE; ++UI) {
    int StoreFrameIndex;
    unsigned StoreVReg = TII->isStoreToStackSlot(*UI, StoreFrameIndex);
    if (StoreVReg != Reg || StoreFrameIndex != FrameIndex)
      NonSpills++;
    
    int DefIdx = (*UI)->findRegisterDefOperandIdx(Reg);
    if (DefIdx != -1 && (*UI)->isRegTiedToUseOperand(DefIdx))
      FeedsTwoAddr = true;
  }
  
  return NonSpills;
}

/// removeDeadSpills - After doing splitting, filter through all intervals we've
/// split, and see if any of the spills are unnecessary.  If so, remove them.
bool PreAllocSplitting::removeDeadSpills(SmallPtrSet<LiveInterval*, 8>& split) {
  bool changed = false;
  
  // Walk over all of the live intervals that were touched by the splitter,
  // and see if we can do any DCE and/or folding.
  for (SmallPtrSet<LiveInterval*, 8>::iterator LI = split.begin(),
       LE = split.end(); LI != LE; ++LI) {
    DenseMap<VNInfo*, SmallPtrSet<MachineInstr*, 4> > VNUseCount;
    
    // First, collect all the uses of the vreg, and sort them by their
    // reaching definition (VNInfo).
    for (MachineRegisterInfo::use_iterator UI = MRI->use_begin((*LI)->reg),
         UE = MRI->use_end(); UI != UE; ++UI) {
      SlotIndex index = LIs->getInstructionIndex(&*UI);
      index = index.getUseIndex();
      
      const LiveRange* LR = (*LI)->getLiveRangeContaining(index);
      VNUseCount[LR->valno].insert(&*UI);
    }
    
    // Now, take the definitions (VNInfo's) one at a time and try to DCE 
    // and/or fold them away.
    for (LiveInterval::vni_iterator VI = (*LI)->vni_begin(),
         VE = (*LI)->vni_end(); VI != VE; ++VI) {
      
      if (DeadSplitLimit != -1 && (int)NumDeadSpills == DeadSplitLimit) 
        return changed;
      
      VNInfo* CurrVN = *VI;
      
      // We don't currently try to handle definitions with PHI kills, because
      // it would involve processing more than one VNInfo at once.
      if (CurrVN->hasPHIKill()) continue;
      
      // We also don't try to handle the results of PHI joins, since there's
      // no defining instruction to analyze.
      if (!CurrVN->isDefAccurate() || CurrVN->isUnused()) continue;
    
      // We're only interested in eliminating cruft introduced by the splitter,
      // is of the form load-use or load-use-store.  First, check that the
      // definition is a load, and remember what stack slot we loaded it from.
      MachineInstr* DefMI = LIs->getInstructionFromIndex(CurrVN->def);
      int FrameIndex;
      if (!TII->isLoadFromStackSlot(DefMI, FrameIndex)) continue;
      
      // If the definition has no uses at all, just DCE it.
      if (VNUseCount[CurrVN].size() == 0) {
        LIs->RemoveMachineInstrFromMaps(DefMI);
        (*LI)->removeValNo(CurrVN);
        DefMI->eraseFromParent();
        VNUseCount.erase(CurrVN);
        NumDeadSpills++;
        changed = true;
        continue;
      }
      
      // Second, get the number of non-store uses of the definition, as well as
      // a flag indicating whether it feeds into a later two-address definition.
      bool FeedsTwoAddr = false;
      unsigned NonSpillCount = getNumberOfNonSpills(VNUseCount[CurrVN],
                                                    (*LI)->reg, FrameIndex,
                                                    FeedsTwoAddr);
      
      // If there's one non-store use and it doesn't feed a two-addr, then
      // this is a load-use-store case that we can try to fold.
      if (NonSpillCount == 1 && !FeedsTwoAddr) {
        // Start by finding the non-store use MachineInstr.
        SmallPtrSet<MachineInstr*, 4>::iterator UI = VNUseCount[CurrVN].begin();
        int StoreFrameIndex;
        unsigned StoreVReg = TII->isStoreToStackSlot(*UI, StoreFrameIndex);
        while (UI != VNUseCount[CurrVN].end() &&
               (StoreVReg == (*LI)->reg && StoreFrameIndex == FrameIndex)) {
          ++UI;
          if (UI != VNUseCount[CurrVN].end())
            StoreVReg = TII->isStoreToStackSlot(*UI, StoreFrameIndex);
        }
        if (UI == VNUseCount[CurrVN].end()) continue;
        
        MachineInstr* use = *UI;
        
        // Attempt to fold it away!
        int OpIdx = use->findRegisterUseOperandIdx((*LI)->reg, false);
        if (OpIdx == -1) continue;
        SmallVector<unsigned, 1> Ops;
        Ops.push_back(OpIdx);
        if (!TII->canFoldMemoryOperand(use, Ops)) continue;

        MachineInstr* NewMI =
                          TII->foldMemoryOperand(*use->getParent()->getParent(),  
                                                 use, Ops, FrameIndex);

        if (!NewMI) continue;

        // Update relevant analyses.
        LIs->RemoveMachineInstrFromMaps(DefMI);
        LIs->ReplaceMachineInstrInMaps(use, NewMI);
        (*LI)->removeValNo(CurrVN);

        DefMI->eraseFromParent();
        MachineBasicBlock* MBB = use->getParent();
        NewMI = MBB->insert(MBB->erase(use), NewMI);
        VNUseCount[CurrVN].erase(use);
        
        // Remove deleted instructions.  Note that we need to remove them from 
        // the VNInfo->use map as well, just to be safe.
        for (SmallPtrSet<MachineInstr*, 4>::iterator II = 
             VNUseCount[CurrVN].begin(), IE = VNUseCount[CurrVN].end();
             II != IE; ++II) {
          for (DenseMap<VNInfo*, SmallPtrSet<MachineInstr*, 4> >::iterator
               VNI = VNUseCount.begin(), VNE = VNUseCount.end(); VNI != VNE; 
               ++VNI)
            if (VNI->first != CurrVN)
              VNI->second.erase(*II);
          LIs->RemoveMachineInstrFromMaps(*II);
          (*II)->eraseFromParent();
        }
        
        VNUseCount.erase(CurrVN);

        for (DenseMap<VNInfo*, SmallPtrSet<MachineInstr*, 4> >::iterator
             VI = VNUseCount.begin(), VE = VNUseCount.end(); VI != VE; ++VI)
          if (VI->second.erase(use))
            VI->second.insert(NewMI);

        NumDeadSpills++;
        changed = true;
        continue;
      }
      
      // If there's more than one non-store instruction, we can't profitably
      // fold it, so bail.
      if (NonSpillCount) continue;
        
      // Otherwise, this is a load-store case, so DCE them.
      for (SmallPtrSet<MachineInstr*, 4>::iterator UI = 
           VNUseCount[CurrVN].begin(), UE = VNUseCount[CurrVN].end();
           UI != UE; ++UI) {
        LIs->RemoveMachineInstrFromMaps(*UI);
        (*UI)->eraseFromParent();
      }
        
      VNUseCount.erase(CurrVN);
        
      LIs->RemoveMachineInstrFromMaps(DefMI);
      (*LI)->removeValNo(CurrVN);
      DefMI->eraseFromParent();
      NumDeadSpills++;
      changed = true;
    }
  }
  
  return changed;
}

bool PreAllocSplitting::createsNewJoin(LiveRange* LR,
                                       MachineBasicBlock* DefMBB,
                                       MachineBasicBlock* BarrierMBB) {
  if (DefMBB == BarrierMBB)
    return false;
  
  if (LR->valno->hasPHIKill())
    return false;
  
  SlotIndex MBBEnd = LIs->getMBBEndIdx(BarrierMBB);
  if (LR->end < MBBEnd)
    return false;
  
  MachineLoopInfo& MLI = getAnalysis<MachineLoopInfo>();
  if (MLI.getLoopFor(DefMBB) != MLI.getLoopFor(BarrierMBB))
    return true;
  
  MachineDominatorTree& MDT = getAnalysis<MachineDominatorTree>();
  SmallPtrSet<MachineBasicBlock*, 4> Visited;
  typedef std::pair<MachineBasicBlock*,
                    MachineBasicBlock::succ_iterator> ItPair;
  SmallVector<ItPair, 4> Stack;
  Stack.push_back(std::make_pair(BarrierMBB, BarrierMBB->succ_begin()));
  
  while (!Stack.empty()) {
    ItPair P = Stack.back();
    Stack.pop_back();
    
    MachineBasicBlock* PredMBB = P.first;
    MachineBasicBlock::succ_iterator S = P.second;
    
    if (S == PredMBB->succ_end())
      continue;
    else if (Visited.count(*S)) {
      Stack.push_back(std::make_pair(PredMBB, ++S));
      continue;
    } else
      Stack.push_back(std::make_pair(PredMBB, S+1));
    
    MachineBasicBlock* MBB = *S;
    Visited.insert(MBB);
    
    if (MBB == BarrierMBB)
      return true;
    
    MachineDomTreeNode* DefMDTN = MDT.getNode(DefMBB);
    MachineDomTreeNode* BarrierMDTN = MDT.getNode(BarrierMBB);
    MachineDomTreeNode* MDTN = MDT.getNode(MBB)->getIDom();
    while (MDTN) {
      if (MDTN == DefMDTN)
        return true;
      else if (MDTN == BarrierMDTN)
        break;
      MDTN = MDTN->getIDom();
    }
    
    MBBEnd = LIs->getMBBEndIdx(MBB);
    if (LR->end > MBBEnd)
      Stack.push_back(std::make_pair(MBB, MBB->succ_begin()));
  }
  
  return false;
} 
  

bool PreAllocSplitting::runOnMachineFunction(MachineFunction &MF) {
  CurrMF = &MF;
  TM     = &MF.getTarget();
  TRI    = TM->getRegisterInfo();
  TII    = TM->getInstrInfo();
  MFI    = MF.getFrameInfo();
  MRI    = &MF.getRegInfo();
  SIs    = &getAnalysis<SlotIndexes>();
  LIs    = &getAnalysis<LiveIntervals>();
  LSs    = &getAnalysis<LiveStacks>();
  VRM    = &getAnalysis<VirtRegMap>();

  bool MadeChange = false;

  // Make sure blocks are numbered in order.
  MF.RenumberBlocks();

  MachineBasicBlock *Entry = MF.begin();
  SmallPtrSet<MachineBasicBlock*,16> Visited;

  SmallPtrSet<LiveInterval*, 8> Split;

  for (df_ext_iterator<MachineBasicBlock*, SmallPtrSet<MachineBasicBlock*,16> >
         DFI = df_ext_begin(Entry, Visited), E = df_ext_end(Entry, Visited);
       DFI != E; ++DFI) {
    BarrierMBB = *DFI;
    for (MachineBasicBlock::iterator I = BarrierMBB->begin(),
           E = BarrierMBB->end(); I != E; ++I) {
      Barrier = &*I;
      const TargetRegisterClass **BarrierRCs =
        Barrier->getDesc().getRegClassBarriers();
      if (!BarrierRCs)
        continue;
      BarrierIdx = LIs->getInstructionIndex(Barrier);
      MadeChange |= SplitRegLiveIntervals(BarrierRCs, Split);
    }
  }

  MadeChange |= removeDeadSpills(Split);

  return MadeChange;
}
