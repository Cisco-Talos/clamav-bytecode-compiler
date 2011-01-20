//===-- X86FloatingPoint.cpp - Floating point Reg -> Stack converter ------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines the pass which converts floating point instructions from
// pseudo registers into register stack instructions.  This pass uses live
// variable information to indicate where the FPn registers are used and their
// lifetimes.
//
// The x87 hardware tracks liveness of the stack registers, so it is necessary
// to implement exact liveness tracking between basic blocks. The CFG edges are
// partitioned into bundles where the same FP registers must be live in
// identical stack positions. Instructions are inserted at the end of each basic
// block to rearrange the live registers to match the outgoing bundle.
//
// This approach avoids splitting critical edges at the potential cost of more
// live register shuffling instructions when critical edges are present.
//
//===----------------------------------------------------------------------===//

#define DEBUG_TYPE "x86-codegen"
#include "X86.h"
#include "X86InstrInfo.h"
#include "llvm/ADT/DepthFirstIterator.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/CodeGen/Passes.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetInstrInfo.h"
#include "llvm/Target/TargetMachine.h"
#include <algorithm>
using namespace llvm;

STATISTIC(NumFXCH, "Number of fxch instructions inserted");
STATISTIC(NumFP  , "Number of floating point instructions");

namespace {
  struct FPS : public MachineFunctionPass {
    static char ID;
    FPS() : MachineFunctionPass(ID) {
      // This is really only to keep valgrind quiet.
      // The logic in isLive() is too much for it.
      memset(Stack, 0, sizeof(Stack));
      memset(RegMap, 0, sizeof(RegMap));
    }

    virtual void getAnalysisUsage(AnalysisUsage &AU) const {
      AU.setPreservesCFG();
      AU.addPreservedID(MachineLoopInfoID);
      AU.addPreservedID(MachineDominatorsID);
      MachineFunctionPass::getAnalysisUsage(AU);
    }

    virtual bool runOnMachineFunction(MachineFunction &MF);

    virtual const char *getPassName() const { return "X86 FP Stackifier"; }

  private:
    const TargetInstrInfo *TII; // Machine instruction info.

    // Two CFG edges are related if they leave the same block, or enter the same
    // block. The transitive closure of an edge under this relation is a
    // LiveBundle. It represents a set of CFG edges where the live FP stack
    // registers must be allocated identically in the x87 stack.
    //
    // A LiveBundle is usually all the edges leaving a block, or all the edges
    // entering a block, but it can contain more edges if critical edges are
    // present.
    //
    // The set of live FP registers in a LiveBundle is calculated by bundleCFG,
    // but the exact mapping of FP registers to stack slots is fixed later.
    struct LiveBundle {
      // Bit mask of live FP registers. Bit 0 = FP0, bit 1 = FP1, &c.
      unsigned Mask;

      // Number of pre-assigned live registers in FixStack. This is 0 when the
      // stack order has not yet been fixed.
      unsigned FixCount;

      // Assigned stack order for live-in registers.
      // FixStack[i] == getStackEntry(i) for all i < FixCount.
      unsigned char FixStack[8];

      LiveBundle(unsigned m = 0) : Mask(m), FixCount(0) {}

      // Have the live registers been assigned a stack order yet?
      bool isFixed() const { return !Mask || FixCount; }
    };

    // Numbered LiveBundle structs. LiveBundles[0] is used for all CFG edges
    // with no live FP registers.
    SmallVector<LiveBundle, 8> LiveBundles;

    // Map each MBB in the current function to an (ingoing, outgoing) index into
    // LiveBundles. Blocks with no FP registers live in or out map to (0, 0)
    // and are not actually stored in the map.
    DenseMap<MachineBasicBlock*, std::pair<unsigned, unsigned> > BlockBundle;

    // Return a bitmask of FP registers in block's live-in list.
    unsigned calcLiveInMask(MachineBasicBlock *MBB) {
      unsigned Mask = 0;
      for (MachineBasicBlock::livein_iterator I = MBB->livein_begin(),
           E = MBB->livein_end(); I != E; ++I) {
        unsigned Reg = *I - X86::FP0;
        if (Reg < 8)
          Mask |= 1 << Reg;
      }
      return Mask;
    }

    // Partition all the CFG edges into LiveBundles.
    void bundleCFG(MachineFunction &MF);

    MachineBasicBlock *MBB;     // Current basic block
    unsigned Stack[8];          // FP<n> Registers in each stack slot...
    unsigned RegMap[8];         // Track which stack slot contains each register
    unsigned StackTop;          // The current top of the FP stack.

    // Set up our stack model to match the incoming registers to MBB.
    void setupBlockStack();

    // Shuffle live registers to match the expectations of successor blocks.
    void finishBlockStack();

    void dumpStack() const {
      dbgs() << "Stack contents:";
      for (unsigned i = 0; i != StackTop; ++i) {
        dbgs() << " FP" << Stack[i];
        assert(RegMap[Stack[i]] == i && "Stack[] doesn't match RegMap[]!");
      }
      dbgs() << "\n";
    }

    /// getSlot - Return the stack slot number a particular register number is
    /// in.
    unsigned getSlot(unsigned RegNo) const {
      assert(RegNo < 8 && "Regno out of range!");
      return RegMap[RegNo];
    }

    /// isLive - Is RegNo currently live in the stack?
    bool isLive(unsigned RegNo) const {
      unsigned Slot = getSlot(RegNo);
      return Slot < StackTop && Stack[Slot] == RegNo;
    }

    /// getScratchReg - Return an FP register that is not currently in use.
    unsigned getScratchReg() {
      for (int i = 7; i >= 0; --i)
        if (!isLive(i))
          return i;
      llvm_unreachable("Ran out of scratch FP registers");
    }

    /// getStackEntry - Return the X86::FP<n> register in register ST(i).
    unsigned getStackEntry(unsigned STi) const {
      assert(STi < StackTop && "Access past stack top!");
      return Stack[StackTop-1-STi];
    }

    /// getSTReg - Return the X86::ST(i) register which contains the specified
    /// FP<RegNo> register.
    unsigned getSTReg(unsigned RegNo) const {
      return StackTop - 1 - getSlot(RegNo) + llvm::X86::ST0;
    }

    // pushReg - Push the specified FP<n> register onto the stack.
    void pushReg(unsigned Reg) {
      assert(Reg < 8 && "Register number out of range!");
      assert(StackTop < 8 && "Stack overflow!");
      Stack[StackTop] = Reg;
      RegMap[Reg] = StackTop++;
    }

    bool isAtTop(unsigned RegNo) const { return getSlot(RegNo) == StackTop-1; }
    void moveToTop(unsigned RegNo, MachineBasicBlock::iterator I) {
      DebugLoc dl = I == MBB->end() ? DebugLoc() : I->getDebugLoc();
      if (isAtTop(RegNo)) return;

      unsigned STReg = getSTReg(RegNo);
      unsigned RegOnTop = getStackEntry(0);

      // Swap the slots the regs are in.
      std::swap(RegMap[RegNo], RegMap[RegOnTop]);

      // Swap stack slot contents.
      assert(RegMap[RegOnTop] < StackTop);
      std::swap(Stack[RegMap[RegOnTop]], Stack[StackTop-1]);

      // Emit an fxch to update the runtime processors version of the state.
      BuildMI(*MBB, I, dl, TII->get(X86::XCH_F)).addReg(STReg);
      ++NumFXCH;
    }

    void duplicateToTop(unsigned RegNo, unsigned AsReg, MachineInstr *I) {
      DebugLoc dl = I == MBB->end() ? DebugLoc() : I->getDebugLoc();
      unsigned STReg = getSTReg(RegNo);
      pushReg(AsReg);   // New register on top of stack

      BuildMI(*MBB, I, dl, TII->get(X86::LD_Frr)).addReg(STReg);
    }

    /// popStackAfter - Pop the current value off of the top of the FP stack
    /// after the specified instruction.
    void popStackAfter(MachineBasicBlock::iterator &I);

    /// freeStackSlotAfter - Free the specified register from the register
    /// stack, so that it is no longer in a register.  If the register is
    /// currently at the top of the stack, we just pop the current instruction,
    /// otherwise we store the current top-of-stack into the specified slot,
    /// then pop the top of stack.
    void freeStackSlotAfter(MachineBasicBlock::iterator &I, unsigned Reg);

    /// freeStackSlotBefore - Just the pop, no folding. Return the inserted
    /// instruction.
    MachineBasicBlock::iterator
    freeStackSlotBefore(MachineBasicBlock::iterator I, unsigned FPRegNo);

    /// Adjust the live registers to be the set in Mask.
    void adjustLiveRegs(unsigned Mask, MachineBasicBlock::iterator I);

    /// Shuffle the top FixCount stack entries susch that FP reg FixStack[0] is
    /// st(0), FP reg FixStack[1] is st(1) etc.
    void shuffleStackTop(const unsigned char *FixStack, unsigned FixCount,
                         MachineBasicBlock::iterator I);

    bool processBasicBlock(MachineFunction &MF, MachineBasicBlock &MBB);

    void handleZeroArgFP(MachineBasicBlock::iterator &I);
    void handleOneArgFP(MachineBasicBlock::iterator &I);
    void handleOneArgFPRW(MachineBasicBlock::iterator &I);
    void handleTwoArgFP(MachineBasicBlock::iterator &I);
    void handleCompareFP(MachineBasicBlock::iterator &I);
    void handleCondMovFP(MachineBasicBlock::iterator &I);
    void handleSpecialFP(MachineBasicBlock::iterator &I);

    bool translateCopy(MachineInstr*);
  };
  char FPS::ID = 0;
}

FunctionPass *llvm::createX86FloatingPointStackifierPass() { return new FPS(); }

/// getFPReg - Return the X86::FPx register number for the specified operand.
/// For example, this returns 3 for X86::FP3.
static unsigned getFPReg(const MachineOperand &MO) {
  assert(MO.isReg() && "Expected an FP register!");
  unsigned Reg = MO.getReg();
  assert(Reg >= X86::FP0 && Reg <= X86::FP6 && "Expected FP register!");
  return Reg - X86::FP0;
}

/// runOnMachineFunction - Loop over all of the basic blocks, transforming FP
/// register references into FP stack references.
///
bool FPS::runOnMachineFunction(MachineFunction &MF) {
  // We only need to run this pass if there are any FP registers used in this
  // function.  If it is all integer, there is nothing for us to do!
  bool FPIsUsed = false;

  assert(X86::FP6 == X86::FP0+6 && "Register enums aren't sorted right!");
  for (unsigned i = 0; i <= 6; ++i)
    if (MF.getRegInfo().isPhysRegUsed(X86::FP0+i)) {
      FPIsUsed = true;
      break;
    }

  // Early exit.
  if (!FPIsUsed) return false;

  TII = MF.getTarget().getInstrInfo();

  // Prepare cross-MBB liveness.
  bundleCFG(MF);

  StackTop = 0;

  // Process the function in depth first order so that we process at least one
  // of the predecessors for every reachable block in the function.
  SmallPtrSet<MachineBasicBlock*, 8> Processed;
  MachineBasicBlock *Entry = MF.begin();

  bool Changed = false;
  for (df_ext_iterator<MachineBasicBlock*, SmallPtrSet<MachineBasicBlock*, 8> >
         I = df_ext_begin(Entry, Processed), E = df_ext_end(Entry, Processed);
       I != E; ++I)
    Changed |= processBasicBlock(MF, **I);

  // Process any unreachable blocks in arbitrary order now.
  if (MF.size() != Processed.size())
    for (MachineFunction::iterator BB = MF.begin(), E = MF.end(); BB != E; ++BB)
      if (Processed.insert(BB))
        Changed |= processBasicBlock(MF, *BB);

  BlockBundle.clear();
  LiveBundles.clear();

  return Changed;
}

/// bundleCFG - Scan all the basic blocks to determine consistent live-in and
/// live-out sets for the FP registers. Consistent means that the set of
/// registers live-out from a block is identical to the live-in set of all
/// successors. This is not enforced by the normal live-in lists since
/// registers may be implicitly defined, or not used by all successors.
void FPS::bundleCFG(MachineFunction &MF) {
  assert(LiveBundles.empty() && "Stale data in LiveBundles");
  assert(BlockBundle.empty() && "Stale data in BlockBundle");
  SmallPtrSet<MachineBasicBlock*, 8> PropDown, PropUp;

  // LiveBundle[0] is the empty live-in set.
  LiveBundles.resize(1);

  // First gather the actual live-in masks for all MBBs.
  for (MachineFunction::iterator I = MF.begin(), E = MF.end(); I != E; ++I) {
    MachineBasicBlock *MBB = I;
    const unsigned Mask = calcLiveInMask(MBB);
    if (!Mask)
      continue;
    // Ingoing bundle index.
    unsigned &Idx = BlockBundle[MBB].first;
    // Already assigned an ingoing bundle?
    if (Idx)
      continue;
    // Allocate a new LiveBundle struct for this block's live-ins.
    const unsigned BundleIdx = Idx = LiveBundles.size();
    DEBUG(dbgs() << "Creating LB#" << BundleIdx << ": in:BB#"
                 << MBB->getNumber());
    LiveBundles.push_back(Mask);
    LiveBundle &Bundle = LiveBundles.back();

    // Make sure all predecessors have the same live-out set.
    PropUp.insert(MBB);

    // Keep pushing liveness up and down the CFG until convergence.
    // Only critical edges cause iteration here, but when they do, multiple
    // blocks can be assigned to the same LiveBundle index.
    do {
      // Assign BundleIdx as liveout from predecessors in PropUp.
      for (SmallPtrSet<MachineBasicBlock*, 16>::iterator I = PropUp.begin(),
           E = PropUp.end(); I != E; ++I) {
        MachineBasicBlock *MBB = *I;
        for (MachineBasicBlock::const_pred_iterator LinkI = MBB->pred_begin(),
             LinkE = MBB->pred_end(); LinkI != LinkE; ++LinkI) {
          MachineBasicBlock *PredMBB = *LinkI;
          // PredMBB's liveout bundle should be set to LIIdx.
          unsigned &Idx = BlockBundle[PredMBB].second;
          if (Idx) {
            assert(Idx == BundleIdx && "Inconsistent CFG");
            continue;
          }
          Idx = BundleIdx;
          DEBUG(dbgs() << " out:BB#" << PredMBB->getNumber());
          // Propagate to siblings.
          if (PredMBB->succ_size() > 1)
            PropDown.insert(PredMBB);
        }
      }
      PropUp.clear();

      // Assign BundleIdx as livein to successors in PropDown.
      for (SmallPtrSet<MachineBasicBlock*, 16>::iterator I = PropDown.begin(),
           E = PropDown.end(); I != E; ++I) {
        MachineBasicBlock *MBB = *I;
        for (MachineBasicBlock::const_succ_iterator LinkI = MBB->succ_begin(),
             LinkE = MBB->succ_end(); LinkI != LinkE; ++LinkI) {
          MachineBasicBlock *SuccMBB = *LinkI;
          // LinkMBB's livein bundle should be set to BundleIdx.
          unsigned &Idx = BlockBundle[SuccMBB].first;
          if (Idx) {
            assert(Idx == BundleIdx && "Inconsistent CFG");
            continue;
          }
          Idx = BundleIdx;
          DEBUG(dbgs() << " in:BB#" << SuccMBB->getNumber());
          // Propagate to siblings.
          if (SuccMBB->pred_size() > 1)
            PropUp.insert(SuccMBB);
          // Also accumulate the bundle liveness mask from the liveins here.
          Bundle.Mask |= calcLiveInMask(SuccMBB);
        }
      }
      PropDown.clear();
    } while (!PropUp.empty());
    DEBUG({
      dbgs() << " live:";
      for (unsigned i = 0; i < 8; ++i)
        if (Bundle.Mask & (1<<i))
          dbgs() << " %FP" << i;
      dbgs() << '\n';
    });
  }
}

/// processBasicBlock - Loop over all of the instructions in the basic block,
/// transforming FP instructions into their stack form.
///
bool FPS::processBasicBlock(MachineFunction &MF, MachineBasicBlock &BB) {
  bool Changed = false;
  MBB = &BB;

  setupBlockStack();

  for (MachineBasicBlock::iterator I = BB.begin(); I != BB.end(); ++I) {
    MachineInstr *MI = I;
    uint64_t Flags = MI->getDesc().TSFlags;

    unsigned FPInstClass = Flags & X86II::FPTypeMask;
    if (MI->isInlineAsm())
      FPInstClass = X86II::SpecialFP;

    if (MI->isCopy() && translateCopy(MI))
      FPInstClass = X86II::SpecialFP;

    if (FPInstClass == X86II::NotFP)
      continue;  // Efficiently ignore non-fp insts!

    MachineInstr *PrevMI = 0;
    if (I != BB.begin())
      PrevMI = prior(I);

    ++NumFP;  // Keep track of # of pseudo instrs
    DEBUG(dbgs() << "\nFPInst:\t" << *MI);

    // Get dead variables list now because the MI pointer may be deleted as part
    // of processing!
    SmallVector<unsigned, 8> DeadRegs;
    for (unsigned i = 0, e = MI->getNumOperands(); i != e; ++i) {
      const MachineOperand &MO = MI->getOperand(i);
      if (MO.isReg() && MO.isDead())
        DeadRegs.push_back(MO.getReg());
    }

    switch (FPInstClass) {
    case X86II::ZeroArgFP:  handleZeroArgFP(I); break;
    case X86II::OneArgFP:   handleOneArgFP(I);  break;  // fstp ST(0)
    case X86II::OneArgFPRW: handleOneArgFPRW(I); break; // ST(0) = fsqrt(ST(0))
    case X86II::TwoArgFP:   handleTwoArgFP(I);  break;
    case X86II::CompareFP:  handleCompareFP(I); break;
    case X86II::CondMovFP:  handleCondMovFP(I); break;
    case X86II::SpecialFP:  handleSpecialFP(I); break;
    default: llvm_unreachable("Unknown FP Type!");
    }

    // Check to see if any of the values defined by this instruction are dead
    // after definition.  If so, pop them.
    for (unsigned i = 0, e = DeadRegs.size(); i != e; ++i) {
      unsigned Reg = DeadRegs[i];
      if (Reg >= X86::FP0 && Reg <= X86::FP6) {
        DEBUG(dbgs() << "Register FP#" << Reg-X86::FP0 << " is dead!\n");
        freeStackSlotAfter(I, Reg-X86::FP0);
      }
    }

    // Print out all of the instructions expanded to if -debug
    DEBUG(
      MachineBasicBlock::iterator PrevI(PrevMI);
      if (I == PrevI) {
        dbgs() << "Just deleted pseudo instruction\n";
      } else {
        MachineBasicBlock::iterator Start = I;
        // Rewind to first instruction newly inserted.
        while (Start != BB.begin() && prior(Start) != PrevI) --Start;
        dbgs() << "Inserted instructions:\n\t";
        Start->print(dbgs(), &MF.getTarget());
        while (++Start != llvm::next(I)) {}
      }
      dumpStack();
    );

    Changed = true;
  }

  finishBlockStack();

  return Changed;
}

/// setupBlockStack - Use the BlockBundle map to set up our model of the stack
/// to match predecessors' live out stack.
void FPS::setupBlockStack() {
  DEBUG(dbgs() << "\nSetting up live-ins for BB#" << MBB->getNumber()
               << " derived from " << MBB->getName() << ".\n");
  StackTop = 0;
  const LiveBundle &Bundle = LiveBundles[BlockBundle.lookup(MBB).first];

  if (!Bundle.Mask) {
    DEBUG(dbgs() << "Block has no FP live-ins.\n");
    return;
  }

  // Depth-first iteration should ensure that we always have an assigned stack.
  assert(Bundle.isFixed() && "Reached block before any predecessors");

  // Push the fixed live-in registers.
  for (unsigned i = Bundle.FixCount; i > 0; --i) {
    MBB->addLiveIn(X86::ST0+i-1);
    DEBUG(dbgs() << "Live-in st(" << (i-1) << "): %FP"
                 << unsigned(Bundle.FixStack[i-1]) << '\n');
    pushReg(Bundle.FixStack[i-1]);
  }

  // Kill off unwanted live-ins. This can happen with a critical edge.
  // FIXME: We could keep these live registers around as zombies. They may need
  // to be revived at the end of a short block. It might save a few instrs.
  adjustLiveRegs(calcLiveInMask(MBB), MBB->begin());
  DEBUG(MBB->dump());
}

/// finishBlockStack - Revive live-outs that are implicitly defined out of
/// MBB. Shuffle live registers to match the expected fixed stack of any
/// predecessors, and ensure that all predecessors are expecting the same
/// stack.
void FPS::finishBlockStack() {
  // The RET handling below takes care of return blocks for us.
  if (MBB->succ_empty())
    return;

  DEBUG(dbgs() << "Setting up live-outs for BB#" << MBB->getNumber()
               << " derived from " << MBB->getName() << ".\n");

  unsigned BundleIdx = BlockBundle.lookup(MBB).second;
  LiveBundle &Bundle = LiveBundles[BundleIdx];

  // We may need to kill and define some registers to match successors.
  // FIXME: This can probably be combined with the shuffle below.
  MachineBasicBlock::iterator Term = MBB->getFirstTerminator();
  adjustLiveRegs(Bundle.Mask, Term);

  if (!Bundle.Mask) {
    DEBUG(dbgs() << "No live-outs.\n");
    return;
  }

  // Has the stack order been fixed yet?
  DEBUG(dbgs() << "LB#" << BundleIdx << ": ");
  if (Bundle.isFixed()) {
    DEBUG(dbgs() << "Shuffling stack to match.\n");
    shuffleStackTop(Bundle.FixStack, Bundle.FixCount, Term);
  } else {
    // Not fixed yet, we get to choose.
    DEBUG(dbgs() << "Fixing stack order now.\n");
    Bundle.FixCount = StackTop;
    for (unsigned i = 0; i < StackTop; ++i)
      Bundle.FixStack[i] = getStackEntry(i);
  }
}


//===----------------------------------------------------------------------===//
// Efficient Lookup Table Support
//===----------------------------------------------------------------------===//

namespace {
  struct TableEntry {
    unsigned from;
    unsigned to;
    bool operator<(const TableEntry &TE) const { return from < TE.from; }
    friend bool operator<(const TableEntry &TE, unsigned V) {
      return TE.from < V;
    }
    friend bool ATTRIBUTE_USED operator<(unsigned V, const TableEntry &TE) {
      return V < TE.from;
    }
  };
}

#ifndef NDEBUG
static bool TableIsSorted(const TableEntry *Table, unsigned NumEntries) {
  for (unsigned i = 0; i != NumEntries-1; ++i)
    if (!(Table[i] < Table[i+1])) return false;
  return true;
}
#endif

static int Lookup(const TableEntry *Table, unsigned N, unsigned Opcode) {
  const TableEntry *I = std::lower_bound(Table, Table+N, Opcode);
  if (I != Table+N && I->from == Opcode)
    return I->to;
  return -1;
}

#ifdef NDEBUG
#define ASSERT_SORTED(TABLE)
#else
#define ASSERT_SORTED(TABLE)                                              \
  { static bool TABLE##Checked = false;                                   \
    if (!TABLE##Checked) {                                                \
       assert(TableIsSorted(TABLE, array_lengthof(TABLE)) &&              \
              "All lookup tables must be sorted for efficient access!");  \
       TABLE##Checked = true;                                             \
    }                                                                     \
  }
#endif

//===----------------------------------------------------------------------===//
// Register File -> Register Stack Mapping Methods
//===----------------------------------------------------------------------===//

// OpcodeTable - Sorted map of register instructions to their stack version.
// The first element is an register file pseudo instruction, the second is the
// concrete X86 instruction which uses the register stack.
//
static const TableEntry OpcodeTable[] = {
  { X86::ABS_Fp32     , X86::ABS_F     },
  { X86::ABS_Fp64     , X86::ABS_F     },
  { X86::ABS_Fp80     , X86::ABS_F     },
  { X86::ADD_Fp32m    , X86::ADD_F32m  },
  { X86::ADD_Fp64m    , X86::ADD_F64m  },
  { X86::ADD_Fp64m32  , X86::ADD_F32m  },
  { X86::ADD_Fp80m32  , X86::ADD_F32m  },
  { X86::ADD_Fp80m64  , X86::ADD_F64m  },
  { X86::ADD_FpI16m32 , X86::ADD_FI16m },
  { X86::ADD_FpI16m64 , X86::ADD_FI16m },
  { X86::ADD_FpI16m80 , X86::ADD_FI16m },
  { X86::ADD_FpI32m32 , X86::ADD_FI32m },
  { X86::ADD_FpI32m64 , X86::ADD_FI32m },
  { X86::ADD_FpI32m80 , X86::ADD_FI32m },
  { X86::CHS_Fp32     , X86::CHS_F     },
  { X86::CHS_Fp64     , X86::CHS_F     },
  { X86::CHS_Fp80     , X86::CHS_F     },
  { X86::CMOVBE_Fp32  , X86::CMOVBE_F  },
  { X86::CMOVBE_Fp64  , X86::CMOVBE_F  },
  { X86::CMOVBE_Fp80  , X86::CMOVBE_F  },
  { X86::CMOVB_Fp32   , X86::CMOVB_F   },
  { X86::CMOVB_Fp64   , X86::CMOVB_F  },
  { X86::CMOVB_Fp80   , X86::CMOVB_F  },
  { X86::CMOVE_Fp32   , X86::CMOVE_F  },
  { X86::CMOVE_Fp64   , X86::CMOVE_F   },
  { X86::CMOVE_Fp80   , X86::CMOVE_F   },
  { X86::CMOVNBE_Fp32 , X86::CMOVNBE_F },
  { X86::CMOVNBE_Fp64 , X86::CMOVNBE_F },
  { X86::CMOVNBE_Fp80 , X86::CMOVNBE_F },
  { X86::CMOVNB_Fp32  , X86::CMOVNB_F  },
  { X86::CMOVNB_Fp64  , X86::CMOVNB_F  },
  { X86::CMOVNB_Fp80  , X86::CMOVNB_F  },
  { X86::CMOVNE_Fp32  , X86::CMOVNE_F  },
  { X86::CMOVNE_Fp64  , X86::CMOVNE_F  },
  { X86::CMOVNE_Fp80  , X86::CMOVNE_F  },
  { X86::CMOVNP_Fp32  , X86::CMOVNP_F  },
  { X86::CMOVNP_Fp64  , X86::CMOVNP_F  },
  { X86::CMOVNP_Fp80  , X86::CMOVNP_F  },
  { X86::CMOVP_Fp32   , X86::CMOVP_F   },
  { X86::CMOVP_Fp64   , X86::CMOVP_F   },
  { X86::CMOVP_Fp80   , X86::CMOVP_F   },
  { X86::COS_Fp32     , X86::COS_F     },
  { X86::COS_Fp64     , X86::COS_F     },
  { X86::COS_Fp80     , X86::COS_F     },
  { X86::DIVR_Fp32m   , X86::DIVR_F32m },
  { X86::DIVR_Fp64m   , X86::DIVR_F64m },
  { X86::DIVR_Fp64m32 , X86::DIVR_F32m },
  { X86::DIVR_Fp80m32 , X86::DIVR_F32m },
  { X86::DIVR_Fp80m64 , X86::DIVR_F64m },
  { X86::DIVR_FpI16m32, X86::DIVR_FI16m},
  { X86::DIVR_FpI16m64, X86::DIVR_FI16m},
  { X86::DIVR_FpI16m80, X86::DIVR_FI16m},
  { X86::DIVR_FpI32m32, X86::DIVR_FI32m},
  { X86::DIVR_FpI32m64, X86::DIVR_FI32m},
  { X86::DIVR_FpI32m80, X86::DIVR_FI32m},
  { X86::DIV_Fp32m    , X86::DIV_F32m  },
  { X86::DIV_Fp64m    , X86::DIV_F64m  },
  { X86::DIV_Fp64m32  , X86::DIV_F32m  },
  { X86::DIV_Fp80m32  , X86::DIV_F32m  },
  { X86::DIV_Fp80m64  , X86::DIV_F64m  },
  { X86::DIV_FpI16m32 , X86::DIV_FI16m },
  { X86::DIV_FpI16m64 , X86::DIV_FI16m },
  { X86::DIV_FpI16m80 , X86::DIV_FI16m },
  { X86::DIV_FpI32m32 , X86::DIV_FI32m },
  { X86::DIV_FpI32m64 , X86::DIV_FI32m },
  { X86::DIV_FpI32m80 , X86::DIV_FI32m },
  { X86::ILD_Fp16m32  , X86::ILD_F16m  },
  { X86::ILD_Fp16m64  , X86::ILD_F16m  },
  { X86::ILD_Fp16m80  , X86::ILD_F16m  },
  { X86::ILD_Fp32m32  , X86::ILD_F32m  },
  { X86::ILD_Fp32m64  , X86::ILD_F32m  },
  { X86::ILD_Fp32m80  , X86::ILD_F32m  },
  { X86::ILD_Fp64m32  , X86::ILD_F64m  },
  { X86::ILD_Fp64m64  , X86::ILD_F64m  },
  { X86::ILD_Fp64m80  , X86::ILD_F64m  },
  { X86::ISTT_Fp16m32 , X86::ISTT_FP16m},
  { X86::ISTT_Fp16m64 , X86::ISTT_FP16m},
  { X86::ISTT_Fp16m80 , X86::ISTT_FP16m},
  { X86::ISTT_Fp32m32 , X86::ISTT_FP32m},
  { X86::ISTT_Fp32m64 , X86::ISTT_FP32m},
  { X86::ISTT_Fp32m80 , X86::ISTT_FP32m},
  { X86::ISTT_Fp64m32 , X86::ISTT_FP64m},
  { X86::ISTT_Fp64m64 , X86::ISTT_FP64m},
  { X86::ISTT_Fp64m80 , X86::ISTT_FP64m},
  { X86::IST_Fp16m32  , X86::IST_F16m  },
  { X86::IST_Fp16m64  , X86::IST_F16m  },
  { X86::IST_Fp16m80  , X86::IST_F16m  },
  { X86::IST_Fp32m32  , X86::IST_F32m  },
  { X86::IST_Fp32m64  , X86::IST_F32m  },
  { X86::IST_Fp32m80  , X86::IST_F32m  },
  { X86::IST_Fp64m32  , X86::IST_FP64m },
  { X86::IST_Fp64m64  , X86::IST_FP64m },
  { X86::IST_Fp64m80  , X86::IST_FP64m },
  { X86::LD_Fp032     , X86::LD_F0     },
  { X86::LD_Fp064     , X86::LD_F0     },
  { X86::LD_Fp080     , X86::LD_F0     },
  { X86::LD_Fp132     , X86::LD_F1     },
  { X86::LD_Fp164     , X86::LD_F1     },
  { X86::LD_Fp180     , X86::LD_F1     },
  { X86::LD_Fp32m     , X86::LD_F32m   },
  { X86::LD_Fp32m64   , X86::LD_F32m   },
  { X86::LD_Fp32m80   , X86::LD_F32m   },
  { X86::LD_Fp64m     , X86::LD_F64m   },
  { X86::LD_Fp64m80   , X86::LD_F64m   },
  { X86::LD_Fp80m     , X86::LD_F80m   },
  { X86::MUL_Fp32m    , X86::MUL_F32m  },
  { X86::MUL_Fp64m    , X86::MUL_F64m  },
  { X86::MUL_Fp64m32  , X86::MUL_F32m  },
  { X86::MUL_Fp80m32  , X86::MUL_F32m  },
  { X86::MUL_Fp80m64  , X86::MUL_F64m  },
  { X86::MUL_FpI16m32 , X86::MUL_FI16m },
  { X86::MUL_FpI16m64 , X86::MUL_FI16m },
  { X86::MUL_FpI16m80 , X86::MUL_FI16m },
  { X86::MUL_FpI32m32 , X86::MUL_FI32m },
  { X86::MUL_FpI32m64 , X86::MUL_FI32m },
  { X86::MUL_FpI32m80 , X86::MUL_FI32m },
  { X86::SIN_Fp32     , X86::SIN_F     },
  { X86::SIN_Fp64     , X86::SIN_F     },
  { X86::SIN_Fp80     , X86::SIN_F     },
  { X86::SQRT_Fp32    , X86::SQRT_F    },
  { X86::SQRT_Fp64    , X86::SQRT_F    },
  { X86::SQRT_Fp80    , X86::SQRT_F    },
  { X86::ST_Fp32m     , X86::ST_F32m   },
  { X86::ST_Fp64m     , X86::ST_F64m   },
  { X86::ST_Fp64m32   , X86::ST_F32m   },
  { X86::ST_Fp80m32   , X86::ST_F32m   },
  { X86::ST_Fp80m64   , X86::ST_F64m   },
  { X86::ST_FpP80m    , X86::ST_FP80m  },
  { X86::SUBR_Fp32m   , X86::SUBR_F32m },
  { X86::SUBR_Fp64m   , X86::SUBR_F64m },
  { X86::SUBR_Fp64m32 , X86::SUBR_F32m },
  { X86::SUBR_Fp80m32 , X86::SUBR_F32m },
  { X86::SUBR_Fp80m64 , X86::SUBR_F64m },
  { X86::SUBR_FpI16m32, X86::SUBR_FI16m},
  { X86::SUBR_FpI16m64, X86::SUBR_FI16m},
  { X86::SUBR_FpI16m80, X86::SUBR_FI16m},
  { X86::SUBR_FpI32m32, X86::SUBR_FI32m},
  { X86::SUBR_FpI32m64, X86::SUBR_FI32m},
  { X86::SUBR_FpI32m80, X86::SUBR_FI32m},
  { X86::SUB_Fp32m    , X86::SUB_F32m  },
  { X86::SUB_Fp64m    , X86::SUB_F64m  },
  { X86::SUB_Fp64m32  , X86::SUB_F32m  },
  { X86::SUB_Fp80m32  , X86::SUB_F32m  },
  { X86::SUB_Fp80m64  , X86::SUB_F64m  },
  { X86::SUB_FpI16m32 , X86::SUB_FI16m },
  { X86::SUB_FpI16m64 , X86::SUB_FI16m },
  { X86::SUB_FpI16m80 , X86::SUB_FI16m },
  { X86::SUB_FpI32m32 , X86::SUB_FI32m },
  { X86::SUB_FpI32m64 , X86::SUB_FI32m },
  { X86::SUB_FpI32m80 , X86::SUB_FI32m },
  { X86::TST_Fp32     , X86::TST_F     },
  { X86::TST_Fp64     , X86::TST_F     },
  { X86::TST_Fp80     , X86::TST_F     },
  { X86::UCOM_FpIr32  , X86::UCOM_FIr  },
  { X86::UCOM_FpIr64  , X86::UCOM_FIr  },
  { X86::UCOM_FpIr80  , X86::UCOM_FIr  },
  { X86::UCOM_Fpr32   , X86::UCOM_Fr   },
  { X86::UCOM_Fpr64   , X86::UCOM_Fr   },
  { X86::UCOM_Fpr80   , X86::UCOM_Fr   },
};

static unsigned getConcreteOpcode(unsigned Opcode) {
  ASSERT_SORTED(OpcodeTable);
  int Opc = Lookup(OpcodeTable, array_lengthof(OpcodeTable), Opcode);
  assert(Opc != -1 && "FP Stack instruction not in OpcodeTable!");
  return Opc;
}

//===----------------------------------------------------------------------===//
// Helper Methods
//===----------------------------------------------------------------------===//

// PopTable - Sorted map of instructions to their popping version.  The first
// element is an instruction, the second is the version which pops.
//
static const TableEntry PopTable[] = {
  { X86::ADD_FrST0 , X86::ADD_FPrST0  },

  { X86::DIVR_FrST0, X86::DIVR_FPrST0 },
  { X86::DIV_FrST0 , X86::DIV_FPrST0  },

  { X86::IST_F16m  , X86::IST_FP16m   },
  { X86::IST_F32m  , X86::IST_FP32m   },

  { X86::MUL_FrST0 , X86::MUL_FPrST0  },

  { X86::ST_F32m   , X86::ST_FP32m    },
  { X86::ST_F64m   , X86::ST_FP64m    },
  { X86::ST_Frr    , X86::ST_FPrr     },

  { X86::SUBR_FrST0, X86::SUBR_FPrST0 },
  { X86::SUB_FrST0 , X86::SUB_FPrST0  },

  { X86::UCOM_FIr  , X86::UCOM_FIPr   },

  { X86::UCOM_FPr  , X86::UCOM_FPPr   },
  { X86::UCOM_Fr   , X86::UCOM_FPr    },
};

/// popStackAfter - Pop the current value off of the top of the FP stack after
/// the specified instruction.  This attempts to be sneaky and combine the pop
/// into the instruction itself if possible.  The iterator is left pointing to
/// the last instruction, be it a new pop instruction inserted, or the old
/// instruction if it was modified in place.
///
void FPS::popStackAfter(MachineBasicBlock::iterator &I) {
  MachineInstr* MI = I;
  DebugLoc dl = MI->getDebugLoc();
  ASSERT_SORTED(PopTable);
  assert(StackTop > 0 && "Cannot pop empty stack!");
  RegMap[Stack[--StackTop]] = ~0;     // Update state

  // Check to see if there is a popping version of this instruction...
  int Opcode = Lookup(PopTable, array_lengthof(PopTable), I->getOpcode());
  if (Opcode != -1) {
    I->setDesc(TII->get(Opcode));
    if (Opcode == X86::UCOM_FPPr)
      I->RemoveOperand(0);
  } else {    // Insert an explicit pop
    I = BuildMI(*MBB, ++I, dl, TII->get(X86::ST_FPrr)).addReg(X86::ST0);
  }
}

/// freeStackSlotAfter - Free the specified register from the register stack, so
/// that it is no longer in a register.  If the register is currently at the top
/// of the stack, we just pop the current instruction, otherwise we store the
/// current top-of-stack into the specified slot, then pop the top of stack.
void FPS::freeStackSlotAfter(MachineBasicBlock::iterator &I, unsigned FPRegNo) {
  if (getStackEntry(0) == FPRegNo) {  // already at the top of stack? easy.
    popStackAfter(I);
    return;
  }

  // Otherwise, store the top of stack into the dead slot, killing the operand
  // without having to add in an explicit xchg then pop.
  //
  I = freeStackSlotBefore(++I, FPRegNo);
}

/// freeStackSlotBefore - Free the specified register without trying any
/// folding.
MachineBasicBlock::iterator
FPS::freeStackSlotBefore(MachineBasicBlock::iterator I, unsigned FPRegNo) {
  unsigned STReg    = getSTReg(FPRegNo);
  unsigned OldSlot  = getSlot(FPRegNo);
  unsigned TopReg   = Stack[StackTop-1];
  Stack[OldSlot]    = TopReg;
  RegMap[TopReg]    = OldSlot;
  RegMap[FPRegNo]   = ~0;
  Stack[--StackTop] = ~0;
  return BuildMI(*MBB, I, DebugLoc(), TII->get(X86::ST_FPrr)).addReg(STReg);
}

/// adjustLiveRegs - Kill and revive registers such that exactly the FP
/// registers with a bit in Mask are live.
void FPS::adjustLiveRegs(unsigned Mask, MachineBasicBlock::iterator I) {
  unsigned Defs = Mask;
  unsigned Kills = 0;
  for (unsigned i = 0; i < StackTop; ++i) {
    unsigned RegNo = Stack[i];
    if (!(Defs & (1 << RegNo)))
      // This register is live, but we don't want it.
      Kills |= (1 << RegNo);
    else
      // We don't need to imp-def this live register.
      Defs &= ~(1 << RegNo);
  }
  assert((Kills & Defs) == 0 && "Register needs killing and def'ing?");

  // Produce implicit-defs for free by using killed registers.
  while (Kills && Defs) {
    unsigned KReg = CountTrailingZeros_32(Kills);
    unsigned DReg = CountTrailingZeros_32(Defs);
    DEBUG(dbgs() << "Renaming %FP" << KReg << " as imp %FP" << DReg << "\n");
    std::swap(Stack[getSlot(KReg)], Stack[getSlot(DReg)]);
    std::swap(RegMap[KReg], RegMap[DReg]);
    Kills &= ~(1 << KReg);
    Defs &= ~(1 << DReg);
  }

  // Kill registers by popping.
  if (Kills && I != MBB->begin()) {
    MachineBasicBlock::iterator I2 = llvm::prior(I);
    for (;;) {
      unsigned KReg = getStackEntry(0);
      if (!(Kills & (1 << KReg)))
        break;
      DEBUG(dbgs() << "Popping %FP" << KReg << "\n");
      popStackAfter(I2);
      Kills &= ~(1 << KReg);
    }
  }

  // Manually kill the rest.
  while (Kills) {
    unsigned KReg = CountTrailingZeros_32(Kills);
    DEBUG(dbgs() << "Killing %FP" << KReg << "\n");
    freeStackSlotBefore(I, KReg);
    Kills &= ~(1 << KReg);
  }

  // Load zeros for all the imp-defs.
  while(Defs) {
    unsigned DReg = CountTrailingZeros_32(Defs);
    DEBUG(dbgs() << "Defining %FP" << DReg << " as 0\n");
    BuildMI(*MBB, I, DebugLoc(), TII->get(X86::LD_F0));
    pushReg(DReg);
    Defs &= ~(1 << DReg);
  }

  // Now we should have the correct registers live.
  DEBUG(dumpStack());
  assert(StackTop == CountPopulation_32(Mask) && "Live count mismatch");
}

/// shuffleStackTop - emit fxch instructions before I to shuffle the top
/// FixCount entries into the order given by FixStack.
/// FIXME: Is there a better algorithm than insertion sort?
void FPS::shuffleStackTop(const unsigned char *FixStack,
                          unsigned FixCount,
                          MachineBasicBlock::iterator I) {
  // Move items into place, starting from the desired stack bottom.
  while (FixCount--) {
    // Old register at position FixCount.
    unsigned OldReg = getStackEntry(FixCount);
    // Desired register at position FixCount.
    unsigned Reg = FixStack[FixCount];
    if (Reg == OldReg)
      continue;
    // (Reg st0) (OldReg st0) = (Reg OldReg st0)
    moveToTop(Reg, I);
    moveToTop(OldReg, I);
  }
  DEBUG(dumpStack());
}


//===----------------------------------------------------------------------===//
// Instruction transformation implementation
//===----------------------------------------------------------------------===//

/// handleZeroArgFP - ST(0) = fld0    ST(0) = flds <mem>
///
void FPS::handleZeroArgFP(MachineBasicBlock::iterator &I) {
  MachineInstr *MI = I;
  unsigned DestReg = getFPReg(MI->getOperand(0));

  // Change from the pseudo instruction to the concrete instruction.
  MI->RemoveOperand(0);   // Remove the explicit ST(0) operand
  MI->setDesc(TII->get(getConcreteOpcode(MI->getOpcode())));
  
  // Result gets pushed on the stack.
  pushReg(DestReg);
}

/// handleOneArgFP - fst <mem>, ST(0)
///
void FPS::handleOneArgFP(MachineBasicBlock::iterator &I) {
  MachineInstr *MI = I;
  unsigned NumOps = MI->getDesc().getNumOperands();
  assert((NumOps == X86::AddrNumOperands + 1 || NumOps == 1) &&
         "Can only handle fst* & ftst instructions!");

  // Is this the last use of the source register?
  unsigned Reg = getFPReg(MI->getOperand(NumOps-1));
  bool KillsSrc = MI->killsRegister(X86::FP0+Reg);

  // FISTP64m is strange because there isn't a non-popping versions.
  // If we have one _and_ we don't want to pop the operand, duplicate the value
  // on the stack instead of moving it.  This ensure that popping the value is
  // always ok.
  // Ditto FISTTP16m, FISTTP32m, FISTTP64m, ST_FpP80m.
  //
  if (!KillsSrc &&
      (MI->getOpcode() == X86::IST_Fp64m32 ||
       MI->getOpcode() == X86::ISTT_Fp16m32 ||
       MI->getOpcode() == X86::ISTT_Fp32m32 ||
       MI->getOpcode() == X86::ISTT_Fp64m32 ||
       MI->getOpcode() == X86::IST_Fp64m64 ||
       MI->getOpcode() == X86::ISTT_Fp16m64 ||
       MI->getOpcode() == X86::ISTT_Fp32m64 ||
       MI->getOpcode() == X86::ISTT_Fp64m64 ||
       MI->getOpcode() == X86::IST_Fp64m80 ||
       MI->getOpcode() == X86::ISTT_Fp16m80 ||
       MI->getOpcode() == X86::ISTT_Fp32m80 ||
       MI->getOpcode() == X86::ISTT_Fp64m80 ||
       MI->getOpcode() == X86::ST_FpP80m)) {
    duplicateToTop(Reg, getScratchReg(), I);
  } else {
    moveToTop(Reg, I);            // Move to the top of the stack...
  }
  
  // Convert from the pseudo instruction to the concrete instruction.
  MI->RemoveOperand(NumOps-1);    // Remove explicit ST(0) operand
  MI->setDesc(TII->get(getConcreteOpcode(MI->getOpcode())));

  if (MI->getOpcode() == X86::IST_FP64m ||
      MI->getOpcode() == X86::ISTT_FP16m ||
      MI->getOpcode() == X86::ISTT_FP32m ||
      MI->getOpcode() == X86::ISTT_FP64m ||
      MI->getOpcode() == X86::ST_FP80m) {
    assert(StackTop > 0 && "Stack empty??");
    --StackTop;
  } else if (KillsSrc) { // Last use of operand?
    popStackAfter(I);
  }
}


/// handleOneArgFPRW: Handle instructions that read from the top of stack and
/// replace the value with a newly computed value.  These instructions may have
/// non-fp operands after their FP operands.
///
///  Examples:
///     R1 = fchs R2
///     R1 = fadd R2, [mem]
///
void FPS::handleOneArgFPRW(MachineBasicBlock::iterator &I) {
  MachineInstr *MI = I;
#ifndef NDEBUG
  unsigned NumOps = MI->getDesc().getNumOperands();
  assert(NumOps >= 2 && "FPRW instructions must have 2 ops!!");
#endif

  // Is this the last use of the source register?
  unsigned Reg = getFPReg(MI->getOperand(1));
  bool KillsSrc = MI->killsRegister(X86::FP0+Reg);

  if (KillsSrc) {
    // If this is the last use of the source register, just make sure it's on
    // the top of the stack.
    moveToTop(Reg, I);
    assert(StackTop > 0 && "Stack cannot be empty!");
    --StackTop;
    pushReg(getFPReg(MI->getOperand(0)));
  } else {
    // If this is not the last use of the source register, _copy_ it to the top
    // of the stack.
    duplicateToTop(Reg, getFPReg(MI->getOperand(0)), I);
  }

  // Change from the pseudo instruction to the concrete instruction.
  MI->RemoveOperand(1);   // Drop the source operand.
  MI->RemoveOperand(0);   // Drop the destination operand.
  MI->setDesc(TII->get(getConcreteOpcode(MI->getOpcode())));
}


//===----------------------------------------------------------------------===//
// Define tables of various ways to map pseudo instructions
//

// ForwardST0Table - Map: A = B op C  into: ST(0) = ST(0) op ST(i)
static const TableEntry ForwardST0Table[] = {
  { X86::ADD_Fp32  , X86::ADD_FST0r },
  { X86::ADD_Fp64  , X86::ADD_FST0r },
  { X86::ADD_Fp80  , X86::ADD_FST0r },
  { X86::DIV_Fp32  , X86::DIV_FST0r },
  { X86::DIV_Fp64  , X86::DIV_FST0r },
  { X86::DIV_Fp80  , X86::DIV_FST0r },
  { X86::MUL_Fp32  , X86::MUL_FST0r },
  { X86::MUL_Fp64  , X86::MUL_FST0r },
  { X86::MUL_Fp80  , X86::MUL_FST0r },
  { X86::SUB_Fp32  , X86::SUB_FST0r },
  { X86::SUB_Fp64  , X86::SUB_FST0r },
  { X86::SUB_Fp80  , X86::SUB_FST0r },
};

// ReverseST0Table - Map: A = B op C  into: ST(0) = ST(i) op ST(0)
static const TableEntry ReverseST0Table[] = {
  { X86::ADD_Fp32  , X86::ADD_FST0r  },   // commutative
  { X86::ADD_Fp64  , X86::ADD_FST0r  },   // commutative
  { X86::ADD_Fp80  , X86::ADD_FST0r  },   // commutative
  { X86::DIV_Fp32  , X86::DIVR_FST0r },
  { X86::DIV_Fp64  , X86::DIVR_FST0r },
  { X86::DIV_Fp80  , X86::DIVR_FST0r },
  { X86::MUL_Fp32  , X86::MUL_FST0r  },   // commutative
  { X86::MUL_Fp64  , X86::MUL_FST0r  },   // commutative
  { X86::MUL_Fp80  , X86::MUL_FST0r  },   // commutative
  { X86::SUB_Fp32  , X86::SUBR_FST0r },
  { X86::SUB_Fp64  , X86::SUBR_FST0r },
  { X86::SUB_Fp80  , X86::SUBR_FST0r },
};

// ForwardSTiTable - Map: A = B op C  into: ST(i) = ST(0) op ST(i)
static const TableEntry ForwardSTiTable[] = {
  { X86::ADD_Fp32  , X86::ADD_FrST0  },   // commutative
  { X86::ADD_Fp64  , X86::ADD_FrST0  },   // commutative
  { X86::ADD_Fp80  , X86::ADD_FrST0  },   // commutative
  { X86::DIV_Fp32  , X86::DIVR_FrST0 },
  { X86::DIV_Fp64  , X86::DIVR_FrST0 },
  { X86::DIV_Fp80  , X86::DIVR_FrST0 },
  { X86::MUL_Fp32  , X86::MUL_FrST0  },   // commutative
  { X86::MUL_Fp64  , X86::MUL_FrST0  },   // commutative
  { X86::MUL_Fp80  , X86::MUL_FrST0  },   // commutative
  { X86::SUB_Fp32  , X86::SUBR_FrST0 },
  { X86::SUB_Fp64  , X86::SUBR_FrST0 },
  { X86::SUB_Fp80  , X86::SUBR_FrST0 },
};

// ReverseSTiTable - Map: A = B op C  into: ST(i) = ST(i) op ST(0)
static const TableEntry ReverseSTiTable[] = {
  { X86::ADD_Fp32  , X86::ADD_FrST0 },
  { X86::ADD_Fp64  , X86::ADD_FrST0 },
  { X86::ADD_Fp80  , X86::ADD_FrST0 },
  { X86::DIV_Fp32  , X86::DIV_FrST0 },
  { X86::DIV_Fp64  , X86::DIV_FrST0 },
  { X86::DIV_Fp80  , X86::DIV_FrST0 },
  { X86::MUL_Fp32  , X86::MUL_FrST0 },
  { X86::MUL_Fp64  , X86::MUL_FrST0 },
  { X86::MUL_Fp80  , X86::MUL_FrST0 },
  { X86::SUB_Fp32  , X86::SUB_FrST0 },
  { X86::SUB_Fp64  , X86::SUB_FrST0 },
  { X86::SUB_Fp80  , X86::SUB_FrST0 },
};


/// handleTwoArgFP - Handle instructions like FADD and friends which are virtual
/// instructions which need to be simplified and possibly transformed.
///
/// Result: ST(0) = fsub  ST(0), ST(i)
///         ST(i) = fsub  ST(0), ST(i)
///         ST(0) = fsubr ST(0), ST(i)
///         ST(i) = fsubr ST(0), ST(i)
///
void FPS::handleTwoArgFP(MachineBasicBlock::iterator &I) {
  ASSERT_SORTED(ForwardST0Table); ASSERT_SORTED(ReverseST0Table);
  ASSERT_SORTED(ForwardSTiTable); ASSERT_SORTED(ReverseSTiTable);
  MachineInstr *MI = I;

  unsigned NumOperands = MI->getDesc().getNumOperands();
  assert(NumOperands == 3 && "Illegal TwoArgFP instruction!");
  unsigned Dest = getFPReg(MI->getOperand(0));
  unsigned Op0 = getFPReg(MI->getOperand(NumOperands-2));
  unsigned Op1 = getFPReg(MI->getOperand(NumOperands-1));
  bool KillsOp0 = MI->killsRegister(X86::FP0+Op0);
  bool KillsOp1 = MI->killsRegister(X86::FP0+Op1);
  DebugLoc dl = MI->getDebugLoc();

  unsigned TOS = getStackEntry(0);

  // One of our operands must be on the top of the stack.  If neither is yet, we
  // need to move one.
  if (Op0 != TOS && Op1 != TOS) {   // No operand at TOS?
    // We can choose to move either operand to the top of the stack.  If one of
    // the operands is killed by this instruction, we want that one so that we
    // can update right on top of the old version.
    if (KillsOp0) {
      moveToTop(Op0, I);         // Move dead operand to TOS.
      TOS = Op0;
    } else if (KillsOp1) {
      moveToTop(Op1, I);
      TOS = Op1;
    } else {
      // All of the operands are live after this instruction executes, so we
      // cannot update on top of any operand.  Because of this, we must
      // duplicate one of the stack elements to the top.  It doesn't matter
      // which one we pick.
      //
      duplicateToTop(Op0, Dest, I);
      Op0 = TOS = Dest;
      KillsOp0 = true;
    }
  } else if (!KillsOp0 && !KillsOp1) {
    // If we DO have one of our operands at the top of the stack, but we don't
    // have a dead operand, we must duplicate one of the operands to a new slot
    // on the stack.
    duplicateToTop(Op0, Dest, I);
    Op0 = TOS = Dest;
    KillsOp0 = true;
  }

  // Now we know that one of our operands is on the top of the stack, and at
  // least one of our operands is killed by this instruction.
  assert((TOS == Op0 || TOS == Op1) && (KillsOp0 || KillsOp1) &&
         "Stack conditions not set up right!");

  // We decide which form to use based on what is on the top of the stack, and
  // which operand is killed by this instruction.
  const TableEntry *InstTable;
  bool isForward = TOS == Op0;
  bool updateST0 = (TOS == Op0 && !KillsOp1) || (TOS == Op1 && !KillsOp0);
  if (updateST0) {
    if (isForward)
      InstTable = ForwardST0Table;
    else
      InstTable = ReverseST0Table;
  } else {
    if (isForward)
      InstTable = ForwardSTiTable;
    else
      InstTable = ReverseSTiTable;
  }

  int Opcode = Lookup(InstTable, array_lengthof(ForwardST0Table),
                      MI->getOpcode());
  assert(Opcode != -1 && "Unknown TwoArgFP pseudo instruction!");

  // NotTOS - The register which is not on the top of stack...
  unsigned NotTOS = (TOS == Op0) ? Op1 : Op0;

  // Replace the old instruction with a new instruction
  MBB->remove(I++);
  I = BuildMI(*MBB, I, dl, TII->get(Opcode)).addReg(getSTReg(NotTOS));

  // If both operands are killed, pop one off of the stack in addition to
  // overwriting the other one.
  if (KillsOp0 && KillsOp1 && Op0 != Op1) {
    assert(!updateST0 && "Should have updated other operand!");
    popStackAfter(I);   // Pop the top of stack
  }

  // Update stack information so that we know the destination register is now on
  // the stack.
  unsigned UpdatedSlot = getSlot(updateST0 ? TOS : NotTOS);
  assert(UpdatedSlot < StackTop && Dest < 7);
  Stack[UpdatedSlot]   = Dest;
  RegMap[Dest]         = UpdatedSlot;
  MBB->getParent()->DeleteMachineInstr(MI); // Remove the old instruction
}

/// handleCompareFP - Handle FUCOM and FUCOMI instructions, which have two FP
/// register arguments and no explicit destinations.
///
void FPS::handleCompareFP(MachineBasicBlock::iterator &I) {
  ASSERT_SORTED(ForwardST0Table); ASSERT_SORTED(ReverseST0Table);
  ASSERT_SORTED(ForwardSTiTable); ASSERT_SORTED(ReverseSTiTable);
  MachineInstr *MI = I;

  unsigned NumOperands = MI->getDesc().getNumOperands();
  assert(NumOperands == 2 && "Illegal FUCOM* instruction!");
  unsigned Op0 = getFPReg(MI->getOperand(NumOperands-2));
  unsigned Op1 = getFPReg(MI->getOperand(NumOperands-1));
  bool KillsOp0 = MI->killsRegister(X86::FP0+Op0);
  bool KillsOp1 = MI->killsRegister(X86::FP0+Op1);

  // Make sure the first operand is on the top of stack, the other one can be
  // anywhere.
  moveToTop(Op0, I);

  // Change from the pseudo instruction to the concrete instruction.
  MI->getOperand(0).setReg(getSTReg(Op1));
  MI->RemoveOperand(1);
  MI->setDesc(TII->get(getConcreteOpcode(MI->getOpcode())));

  // If any of the operands are killed by this instruction, free them.
  if (KillsOp0) freeStackSlotAfter(I, Op0);
  if (KillsOp1 && Op0 != Op1) freeStackSlotAfter(I, Op1);
}

/// handleCondMovFP - Handle two address conditional move instructions.  These
/// instructions move a st(i) register to st(0) iff a condition is true.  These
/// instructions require that the first operand is at the top of the stack, but
/// otherwise don't modify the stack at all.
void FPS::handleCondMovFP(MachineBasicBlock::iterator &I) {
  MachineInstr *MI = I;

  unsigned Op0 = getFPReg(MI->getOperand(0));
  unsigned Op1 = getFPReg(MI->getOperand(2));
  bool KillsOp1 = MI->killsRegister(X86::FP0+Op1);

  // The first operand *must* be on the top of the stack.
  moveToTop(Op0, I);

  // Change the second operand to the stack register that the operand is in.
  // Change from the pseudo instruction to the concrete instruction.
  MI->RemoveOperand(0);
  MI->RemoveOperand(1);
  MI->getOperand(0).setReg(getSTReg(Op1));
  MI->setDesc(TII->get(getConcreteOpcode(MI->getOpcode())));
  
  // If we kill the second operand, make sure to pop it from the stack.
  if (Op0 != Op1 && KillsOp1) {
    // Get this value off of the register stack.
    freeStackSlotAfter(I, Op1);
  }
}


/// handleSpecialFP - Handle special instructions which behave unlike other
/// floating point instructions.  This is primarily intended for use by pseudo
/// instructions.
///
void FPS::handleSpecialFP(MachineBasicBlock::iterator &I) {
  MachineInstr *MI = I;
  DebugLoc dl = MI->getDebugLoc();
  switch (MI->getOpcode()) {
  default: llvm_unreachable("Unknown SpecialFP instruction!");
  case X86::FpGET_ST0_32:// Appears immediately after a call returning FP type!
  case X86::FpGET_ST0_64:// Appears immediately after a call returning FP type!
  case X86::FpGET_ST0_80:// Appears immediately after a call returning FP type!
    assert(StackTop == 0 && "Stack should be empty after a call!");
    pushReg(getFPReg(MI->getOperand(0)));
    break;
  case X86::FpGET_ST1_32:// Appears immediately after a call returning FP type!
  case X86::FpGET_ST1_64:// Appears immediately after a call returning FP type!
  case X86::FpGET_ST1_80:{// Appears immediately after a call returning FP type!
    // FpGET_ST1 should occur right after a FpGET_ST0 for a call or inline asm.
    // The pattern we expect is:
    //  CALL
    //  FP1 = FpGET_ST0
    //  FP4 = FpGET_ST1
    //
    // At this point, we've pushed FP1 on the top of stack, so it should be
    // present if it isn't dead.  If it was dead, we already emitted a pop to
    // remove it from the stack and StackTop = 0.
    
    // Push FP4 as top of stack next.
    pushReg(getFPReg(MI->getOperand(0)));

    // If StackTop was 0 before we pushed our operand, then ST(0) must have been
    // dead.  In this case, the ST(1) value is the only thing that is live, so
    // it should be on the TOS (after the pop that was emitted) and is.  Just
    // continue in this case.
    if (StackTop == 1)
      break;
    
    // Because pushReg just pushed ST(1) as TOS, we now have to swap the two top
    // elements so that our accounting is correct.
    unsigned RegOnTop = getStackEntry(0);
    unsigned RegNo = getStackEntry(1);
    
    // Swap the slots the regs are in.
    std::swap(RegMap[RegNo], RegMap[RegOnTop]);
    
    // Swap stack slot contents.
    assert(RegMap[RegOnTop] < StackTop);
    std::swap(Stack[RegMap[RegOnTop]], Stack[StackTop-1]);
    break;
  }
  case X86::FpSET_ST0_32:
  case X86::FpSET_ST0_64:
  case X86::FpSET_ST0_80: {
    // FpSET_ST0_80 is generated by copyRegToReg for setting up inline asm
    // arguments that use an st constraint. We expect a sequence of
    // instructions: Fp_SET_ST0 Fp_SET_ST1? INLINEASM
    unsigned Op0 = getFPReg(MI->getOperand(0));

    if (!MI->killsRegister(X86::FP0 + Op0)) {
      // Duplicate Op0 into a temporary on the stack top.
      duplicateToTop(Op0, getScratchReg(), I);
    } else {
      // Op0 is killed, so just swap it into position.
      moveToTop(Op0, I);
    }
    --StackTop;   // "Forget" we have something on the top of stack!
    break;
  }
  case X86::FpSET_ST1_32:
  case X86::FpSET_ST1_64:
  case X86::FpSET_ST1_80: {
    // Set up st(1) for inline asm. We are assuming that st(0) has already been
    // set up by FpSET_ST0, and our StackTop is off by one because of it.
    unsigned Op0 = getFPReg(MI->getOperand(0));
    // Restore the actual StackTop from before Fp_SET_ST0.
    // Note we can't handle Fp_SET_ST1 without a preceeding Fp_SET_ST0, and we
    // are not enforcing the constraint.
    ++StackTop;
    unsigned RegOnTop = getStackEntry(0); // This reg must remain in st(0).
    if (!MI->killsRegister(X86::FP0 + Op0)) {
      duplicateToTop(Op0, getScratchReg(), I);
      moveToTop(RegOnTop, I);
    } else if (getSTReg(Op0) != X86::ST1) {
      // We have the wrong value at st(1). Shuffle! Untested!
      moveToTop(getStackEntry(1), I);
      moveToTop(Op0, I);
      moveToTop(RegOnTop, I);
    }
    assert(StackTop >= 2 && "Too few live registers");
    StackTop -= 2; // "Forget" both st(0) and st(1).
    break;
  }
  case X86::MOV_Fp3232:
  case X86::MOV_Fp3264:
  case X86::MOV_Fp6432:
  case X86::MOV_Fp6464: 
  case X86::MOV_Fp3280:
  case X86::MOV_Fp6480:
  case X86::MOV_Fp8032:
  case X86::MOV_Fp8064: 
  case X86::MOV_Fp8080: {
    const MachineOperand &MO1 = MI->getOperand(1);
    unsigned SrcReg = getFPReg(MO1);

    const MachineOperand &MO0 = MI->getOperand(0);
    unsigned DestReg = getFPReg(MO0);
    if (MI->killsRegister(X86::FP0+SrcReg)) {
      // If the input operand is killed, we can just change the owner of the
      // incoming stack slot into the result.
      unsigned Slot = getSlot(SrcReg);
      assert(Slot < 7 && DestReg < 7 && "FpMOV operands invalid!");
      Stack[Slot] = DestReg;
      RegMap[DestReg] = Slot;

    } else {
      // For FMOV we just duplicate the specified value to a new stack slot.
      // This could be made better, but would require substantial changes.
      duplicateToTop(SrcReg, DestReg, I);
    }
    }
    break;
  case TargetOpcode::INLINEASM: {
    // The inline asm MachineInstr currently only *uses* FP registers for the
    // 'f' constraint.  These should be turned into the current ST(x) register
    // in the machine instr.  Also, any kills should be explicitly popped after
    // the inline asm.
    unsigned Kills = 0;
    for (unsigned i = 0, e = MI->getNumOperands(); i != e; ++i) {
      MachineOperand &Op = MI->getOperand(i);
      if (!Op.isReg() || Op.getReg() < X86::FP0 || Op.getReg() > X86::FP6)
        continue;
      assert(Op.isUse() && "Only handle inline asm uses right now");
      
      unsigned FPReg = getFPReg(Op);
      Op.setReg(getSTReg(FPReg));
      
      // If we kill this operand, make sure to pop it from the stack after the
      // asm.  We just remember it for now, and pop them all off at the end in
      // a batch.
      if (Op.isKill())
        Kills |= 1U << FPReg;
    }

    // If this asm kills any FP registers (is the last use of them) we must
    // explicitly emit pop instructions for them.  Do this now after the asm has
    // executed so that the ST(x) numbers are not off (which would happen if we
    // did this inline with operand rewriting).
    //
    // Note: this might be a non-optimal pop sequence.  We might be able to do
    // better by trying to pop in stack order or something.
    MachineBasicBlock::iterator InsertPt = MI;
    while (Kills) {
      unsigned FPReg = CountTrailingZeros_32(Kills);
      freeStackSlotAfter(InsertPt, FPReg);
      Kills &= ~(1U << FPReg);
    }
    // Don't delete the inline asm!
    return;
  }
      
  case X86::RET:
  case X86::RETI:
    // If RET has an FP register use operand, pass the first one in ST(0) and
    // the second one in ST(1).

    // Find the register operands.
    unsigned FirstFPRegOp = ~0U, SecondFPRegOp = ~0U;
    unsigned LiveMask = 0;

    for (unsigned i = 0, e = MI->getNumOperands(); i != e; ++i) {
      MachineOperand &Op = MI->getOperand(i);
      if (!Op.isReg() || Op.getReg() < X86::FP0 || Op.getReg() > X86::FP6)
        continue;
      // FP Register uses must be kills unless there are two uses of the same
      // register, in which case only one will be a kill.
      assert(Op.isUse() &&
             (Op.isKill() ||                        // Marked kill.
              getFPReg(Op) == FirstFPRegOp ||       // Second instance.
              MI->killsRegister(Op.getReg())) &&    // Later use is marked kill.
             "Ret only defs operands, and values aren't live beyond it");

      if (FirstFPRegOp == ~0U)
        FirstFPRegOp = getFPReg(Op);
      else {
        assert(SecondFPRegOp == ~0U && "More than two fp operands!");
        SecondFPRegOp = getFPReg(Op);
      }
      LiveMask |= (1 << getFPReg(Op));

      // Remove the operand so that later passes don't see it.
      MI->RemoveOperand(i);
      --i, --e;
    }

    // We may have been carrying spurious live-ins, so make sure only the returned
    // registers are left live.
    adjustLiveRegs(LiveMask, MI);
    if (!LiveMask) return;  // Quick check to see if any are possible.

    // There are only four possibilities here:
    // 1) we are returning a single FP value.  In this case, it has to be in
    //    ST(0) already, so just declare success by removing the value from the
    //    FP Stack.
    if (SecondFPRegOp == ~0U) {
      // Assert that the top of stack contains the right FP register.
      assert(StackTop == 1 && FirstFPRegOp == getStackEntry(0) &&
             "Top of stack not the right register for RET!");
      
      // Ok, everything is good, mark the value as not being on the stack
      // anymore so that our assertion about the stack being empty at end of
      // block doesn't fire.
      StackTop = 0;
      return;
    }
    
    // Otherwise, we are returning two values:
    // 2) If returning the same value for both, we only have one thing in the FP
    //    stack.  Consider:  RET FP1, FP1
    if (StackTop == 1) {
      assert(FirstFPRegOp == SecondFPRegOp && FirstFPRegOp == getStackEntry(0)&&
             "Stack misconfiguration for RET!");
      
      // Duplicate the TOS so that we return it twice.  Just pick some other FPx
      // register to hold it.
      unsigned NewReg = getScratchReg();
      duplicateToTop(FirstFPRegOp, NewReg, MI);
      FirstFPRegOp = NewReg;
    }
    
    /// Okay we know we have two different FPx operands now:
    assert(StackTop == 2 && "Must have two values live!");
    
    /// 3) If SecondFPRegOp is currently in ST(0) and FirstFPRegOp is currently
    ///    in ST(1).  In this case, emit an fxch.
    if (getStackEntry(0) == SecondFPRegOp) {
      assert(getStackEntry(1) == FirstFPRegOp && "Unknown regs live");
      moveToTop(FirstFPRegOp, MI);
    }
    
    /// 4) Finally, FirstFPRegOp must be in ST(0) and SecondFPRegOp must be in
    /// ST(1).  Just remove both from our understanding of the stack and return.
    assert(getStackEntry(0) == FirstFPRegOp && "Unknown regs live");
    assert(getStackEntry(1) == SecondFPRegOp && "Unknown regs live");
    StackTop = 0;
    return;
  }

  I = MBB->erase(I);  // Remove the pseudo instruction

  // We want to leave I pointing to the previous instruction, but what if we
  // just erased the first instruction?
  if (I == MBB->begin()) {
    DEBUG(dbgs() << "Inserting dummy KILL\n");
    I = BuildMI(*MBB, I, DebugLoc(), TII->get(TargetOpcode::KILL));
  } else
    --I;
}

// Translate a COPY instruction to a pseudo-op that handleSpecialFP understands.
bool FPS::translateCopy(MachineInstr *MI) {
  unsigned DstReg = MI->getOperand(0).getReg();
  unsigned SrcReg = MI->getOperand(1).getReg();

  if (DstReg == X86::ST0) {
    MI->setDesc(TII->get(X86::FpSET_ST0_80));
    MI->RemoveOperand(0);
    return true;
  }
  if (DstReg == X86::ST1) {
    MI->setDesc(TII->get(X86::FpSET_ST1_80));
    MI->RemoveOperand(0);
    return true;
  }
  if (SrcReg == X86::ST0) {
    MI->setDesc(TII->get(X86::FpGET_ST0_80));
    return true;
  }
  if (SrcReg == X86::ST1) {
    MI->setDesc(TII->get(X86::FpGET_ST1_80));
    return true;
  }
  if (X86::RFP80RegClass.contains(DstReg, SrcReg)) {
    MI->setDesc(TII->get(X86::MOV_Fp8080));
    return true;
  }
  return false;
}
