//===------------------------ CalcSpillWeights.cpp ------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#define DEBUG_TYPE "calcspillweights"

#include "llvm/Function.h"
#include "llvm/ADT/SmallSet.h"
#include "llvm/CodeGen/CalcSpillWeights.h"
#include "llvm/CodeGen/LiveIntervalAnalysis.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineLoopInfo.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/CodeGen/SlotIndexes.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetInstrInfo.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/Target/TargetRegisterInfo.h"
using namespace llvm;

char CalculateSpillWeights::ID = 0;
INITIALIZE_PASS(CalculateSpillWeights, "calcspillweights",
                "Calculate spill weights", false, false);

void CalculateSpillWeights::getAnalysisUsage(AnalysisUsage &au) const {
  au.addRequired<LiveIntervals>();
  au.addRequired<MachineLoopInfo>();
  au.setPreservesAll();
  MachineFunctionPass::getAnalysisUsage(au);
}

bool CalculateSpillWeights::runOnMachineFunction(MachineFunction &fn) {

  DEBUG(dbgs() << "********** Compute Spill Weights **********\n"
               << "********** Function: "
               << fn.getFunction()->getName() << '\n');

  LiveIntervals &lis = getAnalysis<LiveIntervals>();
  VirtRegAuxInfo vrai(fn, lis, getAnalysis<MachineLoopInfo>());
  for (LiveIntervals::iterator I = lis.begin(), E = lis.end(); I != E; ++I) {
    LiveInterval &li = *I->second;
    if (TargetRegisterInfo::isVirtualRegister(li.reg))
      vrai.CalculateWeightAndHint(li);
  }
  return false;
}

// Return the preferred allocation register for reg, given a COPY instruction.
static unsigned copyHint(const MachineInstr *mi, unsigned reg,
                         const TargetRegisterInfo &tri,
                         const MachineRegisterInfo &mri) {
  unsigned sub, hreg, hsub;
  if (mi->getOperand(0).getReg() == reg) {
    sub = mi->getOperand(0).getSubReg();
    hreg = mi->getOperand(1).getReg();
    hsub = mi->getOperand(1).getSubReg();
  } else {
    sub = mi->getOperand(1).getSubReg();
    hreg = mi->getOperand(0).getReg();
    hsub = mi->getOperand(0).getSubReg();
  }

  if (!hreg)
    return 0;

  if (TargetRegisterInfo::isVirtualRegister(hreg))
    return sub == hsub ? hreg : 0;

  const TargetRegisterClass *rc = mri.getRegClass(reg);

  // Only allow physreg hints in rc.
  if (sub == 0)
    return rc->contains(hreg) ? hreg : 0;

  // reg:sub should match the physreg hreg.
  return tri.getMatchingSuperReg(hreg, sub, rc);
}

void VirtRegAuxInfo::CalculateWeightAndHint(LiveInterval &li) {
  MachineRegisterInfo &mri = mf_.getRegInfo();
  const TargetRegisterInfo &tri = *mf_.getTarget().getRegisterInfo();
  MachineBasicBlock *mbb = 0;
  MachineLoop *loop = 0;
  unsigned loopDepth = 0;
  bool isExiting = false;
  float totalWeight = 0;
  SmallPtrSet<MachineInstr*, 8> visited;

  // Find the best physreg hist and the best virtreg hint.
  float bestPhys = 0, bestVirt = 0;
  unsigned hintPhys = 0, hintVirt = 0;

  // Don't recompute a target specific hint.
  bool noHint = mri.getRegAllocationHint(li.reg).first != 0;

  for (MachineRegisterInfo::reg_iterator I = mri.reg_begin(li.reg);
       MachineInstr *mi = I.skipInstruction();) {
    if (mi->isIdentityCopy() || mi->isImplicitDef() || mi->isDebugValue())
      continue;
    if (!visited.insert(mi))
      continue;

    // Get loop info for mi.
    if (mi->getParent() != mbb) {
      mbb = mi->getParent();
      loop = loops_.getLoopFor(mbb);
      loopDepth = loop ? loop->getLoopDepth() : 0;
      isExiting = loop ? loop->isLoopExiting(mbb) : false;
    }

    // Calculate instr weight.
    bool reads, writes;
    tie(reads, writes) = mi->readsWritesVirtualRegister(li.reg);
    float weight = LiveIntervals::getSpillWeight(writes, reads, loopDepth);

    // Give extra weight to what looks like a loop induction variable update.
    if (writes && isExiting && lis_.isLiveOutOfMBB(li, mbb))
      weight *= 3;

    totalWeight += weight;

    // Get allocation hints from copies.
    if (noHint || !mi->isCopy())
      continue;
    unsigned hint = copyHint(mi, li.reg, tri, mri);
    if (!hint)
      continue;
    float hweight = hint_[hint] += weight;
    if (TargetRegisterInfo::isPhysicalRegister(hint)) {
      if (hweight > bestPhys && lis_.isAllocatable(hint))
        bestPhys = hweight, hintPhys = hint;
    } else {
      if (hweight > bestVirt)
        bestVirt = hweight, hintVirt = hint;
    }
  }

  hint_.clear();

  // Always prefer the physreg hint.
  if (unsigned hint = hintPhys ? hintPhys : hintVirt) {
    mri.setRegAllocationHint(li.reg, 0, hint);
    // Weakly boost the spill weifght of hinted registers.
    totalWeight *= 1.01F;
  }

  // Mark li as unspillable if all live ranges are tiny.
  if (li.isZeroLength()) {
    li.markNotSpillable();
    return;
  }

  // If all of the definitions of the interval are re-materializable,
  // it is a preferred candidate for spilling. If none of the defs are
  // loads, then it's potentially very cheap to re-materialize.
  // FIXME: this gets much more complicated once we support non-trivial
  // re-materialization.
  bool isLoad = false;
  SmallVector<LiveInterval*, 4> spillIs;
  if (lis_.isReMaterializable(li, spillIs, isLoad)) {
    if (isLoad)
      totalWeight *= 0.9F;
    else
      totalWeight *= 0.5F;
  }

  li.weight = totalWeight;
  lis_.normalizeSpillWeight(li);
}

void VirtRegAuxInfo::CalculateRegClass(unsigned reg) {
  MachineRegisterInfo &mri = mf_.getRegInfo();
  const TargetRegisterInfo *tri = mf_.getTarget().getRegisterInfo();
  const TargetRegisterClass *orc = mri.getRegClass(reg);
  SmallPtrSet<const TargetRegisterClass*,8> rcs;

  for (MachineRegisterInfo::reg_nodbg_iterator I = mri.reg_nodbg_begin(reg),
       E = mri.reg_nodbg_end(); I != E; ++I) {
    // The targets don't have accurate enough regclass descriptions that we can
    // handle subregs. We need something similar to
    // TRI::getMatchingSuperRegClass, but returning a super class instead of a
    // sub class.
    if (I.getOperand().getSubReg()) {
      DEBUG(dbgs() << "Cannot handle subregs: " << I.getOperand() << '\n');
      return;
    }
    if (const TargetRegisterClass *rc =
                                I->getDesc().getRegClass(I.getOperandNo(), tri))
      rcs.insert(rc);
  }

  // If we found no regclass constraints, just leave reg as is.
  // In theory, we could inflate to the largest superclass of reg's existing
  // class, but that might not be legal for the current cpu setting.
  // This could happen if reg is only used by COPY instructions, so we may need
  // to improve on this.
  if (rcs.empty()) {
    return;
  }

  // Compute the intersection of all classes in rcs.
  // This ought to be independent of iteration order, but if the target register
  // classes don't form a proper algebra, it is possible to get different
  // results. The solution is to make sure the intersection of any two register
  // classes is also a register class or the null set.
  const TargetRegisterClass *rc = 0;
  for (SmallPtrSet<const TargetRegisterClass*,8>::iterator I = rcs.begin(),
         E = rcs.end(); I != E; ++I) {
    rc = rc ? getCommonSubClass(rc, *I) : *I;
    assert(rc && "Incompatible regclass constraints found");
  }

  if (rc == orc)
    return;
  DEBUG(dbgs() << "Inflating " << orc->getName() << ":%reg" << reg << " to "
               << rc->getName() <<".\n");
  mri.setRegClass(reg, rc);
}
