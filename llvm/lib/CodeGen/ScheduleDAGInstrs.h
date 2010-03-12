//==- ScheduleDAGInstrs.h - MachineInstr Scheduling --------------*- C++ -*-==//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements the ScheduleDAGInstrs class, which implements
// scheduling for a MachineInstr-based dependency graph.
//
//===----------------------------------------------------------------------===//

#ifndef SCHEDULEDAGINSTRS_H
#define SCHEDULEDAGINSTRS_H

#include "llvm/CodeGen/MachineDominators.h"
#include "llvm/CodeGen/MachineLoopInfo.h"
#include "llvm/CodeGen/ScheduleDAG.h"
#include "llvm/Support/Compiler.h"
#include "llvm/Target/TargetRegisterInfo.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallSet.h"
#include <map>

namespace llvm {
  class MachineLoopInfo;
  class MachineDominatorTree;

  /// LoopDependencies - This class analyzes loop-oriented register
  /// dependencies, which are used to guide scheduling decisions.
  /// For example, loop induction variable increments should be
  /// scheduled as soon as possible after the variable's last use.
  ///
  class VISIBILITY_HIDDEN LoopDependencies {
    const MachineLoopInfo &MLI;
    const MachineDominatorTree &MDT;

  public:
    typedef std::map<unsigned, std::pair<const MachineOperand *, unsigned> >
      LoopDeps;
    LoopDeps Deps;

    LoopDependencies(const MachineLoopInfo &mli,
                     const MachineDominatorTree &mdt) :
      MLI(mli), MDT(mdt) {}

    /// VisitLoop - Clear out any previous state and analyze the given loop.
    ///
    void VisitLoop(const MachineLoop *Loop) {
      Deps.clear();
      MachineBasicBlock *Header = Loop->getHeader();
      SmallSet<unsigned, 8> LoopLiveIns;
      for (MachineBasicBlock::livein_iterator LI = Header->livein_begin(),
           LE = Header->livein_end(); LI != LE; ++LI)
        LoopLiveIns.insert(*LI);

      const MachineDomTreeNode *Node = MDT.getNode(Header);
      const MachineBasicBlock *MBB = Node->getBlock();
      assert(Loop->contains(MBB) &&
             "Loop does not contain header!");
      VisitRegion(Node, MBB, Loop, LoopLiveIns);
    }

  private:
    void VisitRegion(const MachineDomTreeNode *Node,
                     const MachineBasicBlock *MBB,
                     const MachineLoop *Loop,
                     const SmallSet<unsigned, 8> &LoopLiveIns) {
      unsigned Count = 0;
      for (MachineBasicBlock::const_iterator I = MBB->begin(), E = MBB->end();
           I != E; ++I, ++Count) {
        const MachineInstr *MI = I;
        for (unsigned i = 0, e = MI->getNumOperands(); i != e; ++i) {
          const MachineOperand &MO = MI->getOperand(i);
          if (!MO.isReg() || !MO.isUse())
            continue;
          unsigned MOReg = MO.getReg();
          if (LoopLiveIns.count(MOReg))
            Deps.insert(std::make_pair(MOReg, std::make_pair(&MO, Count)));
        }
      }

      const std::vector<MachineDomTreeNode*> &Children = Node->getChildren();
      for (std::vector<MachineDomTreeNode*>::const_iterator I =
           Children.begin(), E = Children.end(); I != E; ++I) {
        const MachineDomTreeNode *ChildNode = *I;
        MachineBasicBlock *ChildBlock = ChildNode->getBlock();
        if (Loop->contains(ChildBlock))
          VisitRegion(ChildNode, ChildBlock, Loop, LoopLiveIns);
      }
    }
  };

  /// ScheduleDAGInstrs - A ScheduleDAG subclass for scheduling lists of
  /// MachineInstrs.
  class VISIBILITY_HIDDEN ScheduleDAGInstrs : public ScheduleDAG {
    const MachineLoopInfo &MLI;
    const MachineDominatorTree &MDT;
    const MachineFrameInfo *MFI;

    /// Defs, Uses - Remember where defs and uses of each physical register
    /// are as we iterate upward through the instructions. This is allocated
    /// here instead of inside BuildSchedGraph to avoid the need for it to be
    /// initialized and destructed for each block.
    std::vector<SUnit *> Defs[TargetRegisterInfo::FirstVirtualRegister];
    std::vector<SUnit *> Uses[TargetRegisterInfo::FirstVirtualRegister];

    /// PendingLoads - Remember where unknown loads are after the most recent
    /// unknown store, as we iterate. As with Defs and Uses, this is here
    /// to minimize construction/destruction.
    std::vector<SUnit *> PendingLoads;

    /// LoopRegs - Track which registers are used for loop-carried dependencies.
    ///
    LoopDependencies LoopRegs;

    /// LoopLiveInRegs - Track which regs are live into a loop, to help guide
    /// back-edge-aware scheduling.
    ///
    SmallSet<unsigned, 8> LoopLiveInRegs;

  public:
    MachineBasicBlock::iterator Begin;    // The beginning of the range to
                                          // be scheduled. The range extends
                                          // to InsertPos.
    unsigned InsertPosIndex;              // The index in BB of InsertPos.

    explicit ScheduleDAGInstrs(MachineFunction &mf,
                               const MachineLoopInfo &mli,
                               const MachineDominatorTree &mdt);

    virtual ~ScheduleDAGInstrs() {}

    /// NewSUnit - Creates a new SUnit and return a ptr to it.
    ///
    SUnit *NewSUnit(MachineInstr *MI) {
#ifndef NDEBUG
      const SUnit *Addr = SUnits.empty() ? 0 : &SUnits[0];
#endif
      SUnits.push_back(SUnit(MI, (unsigned)SUnits.size()));
      assert((Addr == 0 || Addr == &SUnits[0]) &&
             "SUnits std::vector reallocated on the fly!");
      SUnits.back().OrigNode = &SUnits.back();
      return &SUnits.back();
    }

    /// Run - perform scheduling.
    ///
    void Run(MachineBasicBlock *bb,
             MachineBasicBlock::iterator begin,
             MachineBasicBlock::iterator end,
             unsigned endindex);

    /// BuildSchedGraph - Build SUnits from the MachineBasicBlock that we are
    /// input.
    virtual void BuildSchedGraph(AliasAnalysis *AA);

    /// ComputeLatency - Compute node latency.
    ///
    virtual void ComputeLatency(SUnit *SU);

    /// ComputeOperandLatency - Override dependence edge latency using
    /// operand use/def information
    ///
    virtual void ComputeOperandLatency(SUnit *Def, SUnit *Use,
                                       SDep& dep) const;

    virtual MachineBasicBlock*
    EmitSchedule(DenseMap<MachineBasicBlock*, MachineBasicBlock*>*);

    /// StartBlock - Prepare to perform scheduling in the given block.
    ///
    virtual void StartBlock(MachineBasicBlock *BB);

    /// Schedule - Order nodes according to selected style, filling
    /// in the Sequence member.
    ///
    virtual void Schedule() = 0;

    /// FinishBlock - Clean up after scheduling in the given block.
    ///
    virtual void FinishBlock();

    virtual void dumpNode(const SUnit *SU) const;

    virtual std::string getGraphNodeLabel(const SUnit *SU) const;
  };
}

#endif
