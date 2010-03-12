//===- SPUInstrInfo.cpp - Cell SPU Instruction Information ----------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains the Cell SPU implementation of the TargetInstrInfo class.
//
//===----------------------------------------------------------------------===//

#include "SPURegisterNames.h"
#include "SPUInstrInfo.h"
#include "SPUInstrBuilder.h"
#include "SPUTargetMachine.h"
#include "SPUGenInstrInfo.inc"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

namespace {
  //! Predicate for an unconditional branch instruction
  inline bool isUncondBranch(const MachineInstr *I) {
    unsigned opc = I->getOpcode();

    return (opc == SPU::BR
            || opc == SPU::BRA
            || opc == SPU::BI);
  }

  //! Predicate for a conditional branch instruction
  inline bool isCondBranch(const MachineInstr *I) {
    unsigned opc = I->getOpcode();

    return (opc == SPU::BRNZr32
            || opc == SPU::BRNZv4i32
            || opc == SPU::BRZr32
            || opc == SPU::BRZv4i32
            || opc == SPU::BRHNZr16
            || opc == SPU::BRHNZv8i16
            || opc == SPU::BRHZr16
            || opc == SPU::BRHZv8i16);
  }
}

SPUInstrInfo::SPUInstrInfo(SPUTargetMachine &tm)
  : TargetInstrInfoImpl(SPUInsts, sizeof(SPUInsts)/sizeof(SPUInsts[0])),
    TM(tm),
    RI(*TM.getSubtargetImpl(), *this)
{ /* NOP */ }

bool
SPUInstrInfo::isMoveInstr(const MachineInstr& MI,
                          unsigned& sourceReg,
                          unsigned& destReg,
                          unsigned& SrcSR, unsigned& DstSR) const {
  SrcSR = DstSR = 0;  // No sub-registers.

  switch (MI.getOpcode()) {
  default:
    break;
  case SPU::ORIv4i32:
  case SPU::ORIr32:
  case SPU::ORHIv8i16:
  case SPU::ORHIr16:
  case SPU::ORHIi8i16:
  case SPU::ORBIv16i8:
  case SPU::ORBIr8:
  case SPU::ORIi16i32:
  case SPU::ORIi8i32:
  case SPU::AHIvec:
  case SPU::AHIr16:
  case SPU::AIv4i32:
    assert(MI.getNumOperands() == 3 &&
           MI.getOperand(0).isReg() &&
           MI.getOperand(1).isReg() &&
           MI.getOperand(2).isImm() &&
           "invalid SPU ORI/ORHI/ORBI/AHI/AI/SFI/SFHI instruction!");
    if (MI.getOperand(2).getImm() == 0) {
      sourceReg = MI.getOperand(1).getReg();
      destReg = MI.getOperand(0).getReg();
      return true;
    }
    break;
  case SPU::AIr32:
    assert(MI.getNumOperands() == 3 &&
           "wrong number of operands to AIr32");
    if (MI.getOperand(0).isReg() &&
        MI.getOperand(1).isReg() &&
        (MI.getOperand(2).isImm() &&
         MI.getOperand(2).getImm() == 0)) {
      sourceReg = MI.getOperand(1).getReg();
      destReg = MI.getOperand(0).getReg();
      return true;
    }
    break;
  case SPU::LRr8:
  case SPU::LRr16:
  case SPU::LRr32:
  case SPU::LRf32:
  case SPU::LRr64:
  case SPU::LRf64:
  case SPU::LRr128:
  case SPU::LRv16i8:
  case SPU::LRv8i16:
  case SPU::LRv4i32:
  case SPU::LRv4f32:
  case SPU::LRv2i64:
  case SPU::LRv2f64:
  case SPU::ORv16i8_i8:
  case SPU::ORv8i16_i16:
  case SPU::ORv4i32_i32:
  case SPU::ORv2i64_i64:
  case SPU::ORv4f32_f32:
  case SPU::ORv2f64_f64:
  case SPU::ORi8_v16i8:
  case SPU::ORi16_v8i16:
  case SPU::ORi32_v4i32:
  case SPU::ORi64_v2i64:
  case SPU::ORf32_v4f32:
  case SPU::ORf64_v2f64:
/*
  case SPU::ORi128_r64:
  case SPU::ORi128_f64:
  case SPU::ORi128_r32:
  case SPU::ORi128_f32:
  case SPU::ORi128_r16:
  case SPU::ORi128_r8:
*/
  case SPU::ORi128_vec:
/*
  case SPU::ORr64_i128:
  case SPU::ORf64_i128:
  case SPU::ORr32_i128:
  case SPU::ORf32_i128:
  case SPU::ORr16_i128:
  case SPU::ORr8_i128:
*/
  case SPU::ORvec_i128:
/*
  case SPU::ORr16_r32:
  case SPU::ORr8_r32:
  case SPU::ORf32_r32:
  case SPU::ORr32_f32:
  case SPU::ORr32_r16:
  case SPU::ORr32_r8:
  case SPU::ORr16_r64:
  case SPU::ORr8_r64:
  case SPU::ORr64_r16:
  case SPU::ORr64_r8:
*/
  case SPU::ORr64_r32:
  case SPU::ORr32_r64:
  case SPU::ORf32_r32:
  case SPU::ORr32_f32:
  case SPU::ORf64_r64:
  case SPU::ORr64_f64: {
    assert(MI.getNumOperands() == 2 &&
           MI.getOperand(0).isReg() &&
           MI.getOperand(1).isReg() &&
           "invalid SPU OR<type>_<vec> or LR instruction!");
    if (MI.getOperand(0).getReg() == MI.getOperand(1).getReg()) {
      sourceReg = MI.getOperand(1).getReg();
      destReg = MI.getOperand(0).getReg();
      return true;
    }
    break;
  }
  case SPU::ORv16i8:
  case SPU::ORv8i16:
  case SPU::ORv4i32:
  case SPU::ORv2i64:
  case SPU::ORr8:
  case SPU::ORr16:
  case SPU::ORr32:
  case SPU::ORr64:
  case SPU::ORr128:
  case SPU::ORf32:
  case SPU::ORf64:
    assert(MI.getNumOperands() == 3 &&
           MI.getOperand(0).isReg() &&
           MI.getOperand(1).isReg() &&
           MI.getOperand(2).isReg() &&
           "invalid SPU OR(vec|r32|r64|gprc) instruction!");
    if (MI.getOperand(1).getReg() == MI.getOperand(2).getReg()) {
      sourceReg = MI.getOperand(1).getReg();
      destReg = MI.getOperand(0).getReg();
      return true;
    }
    break;
  }

  return false;
}

unsigned
SPUInstrInfo::isLoadFromStackSlot(const MachineInstr *MI,
                                  int &FrameIndex) const {
  switch (MI->getOpcode()) {
  default: break;
  case SPU::LQDv16i8:
  case SPU::LQDv8i16:
  case SPU::LQDv4i32:
  case SPU::LQDv4f32:
  case SPU::LQDv2f64:
  case SPU::LQDr128:
  case SPU::LQDr64:
  case SPU::LQDr32:
  case SPU::LQDr16: {
    const MachineOperand MOp1 = MI->getOperand(1);
    const MachineOperand MOp2 = MI->getOperand(2);
    if (MOp1.isImm() && MOp2.isFI()) {
      FrameIndex = MOp2.getIndex();
      return MI->getOperand(0).getReg();
    }
    break;
  }
  }
  return 0;
}

unsigned
SPUInstrInfo::isStoreToStackSlot(const MachineInstr *MI,
                                 int &FrameIndex) const {
  switch (MI->getOpcode()) {
  default: break;
  case SPU::STQDv16i8:
  case SPU::STQDv8i16:
  case SPU::STQDv4i32:
  case SPU::STQDv4f32:
  case SPU::STQDv2f64:
  case SPU::STQDr128:
  case SPU::STQDr64:
  case SPU::STQDr32:
  case SPU::STQDr16:
  case SPU::STQDr8: {
    const MachineOperand MOp1 = MI->getOperand(1);
    const MachineOperand MOp2 = MI->getOperand(2);
    if (MOp1.isImm() && MOp2.isFI()) {
      FrameIndex = MOp2.getIndex();
      return MI->getOperand(0).getReg();
    }
    break;
  }
  }
  return 0;
}

bool SPUInstrInfo::copyRegToReg(MachineBasicBlock &MBB,
                                   MachineBasicBlock::iterator MI,
                                   unsigned DestReg, unsigned SrcReg,
                                   const TargetRegisterClass *DestRC,
                                   const TargetRegisterClass *SrcRC) const
{
  // We support cross register class moves for our aliases, such as R3 in any
  // reg class to any other reg class containing R3.  This is required because
  // we instruction select bitconvert i64 -> f64 as a noop for example, so our
  // types have no specific meaning.

  DebugLoc DL = DebugLoc::getUnknownLoc();
  if (MI != MBB.end()) DL = MI->getDebugLoc();

  if (DestRC == SPU::R8CRegisterClass) {
    BuildMI(MBB, MI, DL, get(SPU::LRr8), DestReg).addReg(SrcReg);
  } else if (DestRC == SPU::R16CRegisterClass) {
    BuildMI(MBB, MI, DL, get(SPU::LRr16), DestReg).addReg(SrcReg);
  } else if (DestRC == SPU::R32CRegisterClass) {
    BuildMI(MBB, MI, DL, get(SPU::LRr32), DestReg).addReg(SrcReg);
  } else if (DestRC == SPU::R32FPRegisterClass) {
    BuildMI(MBB, MI, DL, get(SPU::LRf32), DestReg).addReg(SrcReg);
  } else if (DestRC == SPU::R64CRegisterClass) {
    BuildMI(MBB, MI, DL, get(SPU::LRr64), DestReg).addReg(SrcReg);
  } else if (DestRC == SPU::R64FPRegisterClass) {
    BuildMI(MBB, MI, DL, get(SPU::LRf64), DestReg).addReg(SrcReg);
  } else if (DestRC == SPU::GPRCRegisterClass) {
    BuildMI(MBB, MI, DL, get(SPU::LRr128), DestReg).addReg(SrcReg);
  } else if (DestRC == SPU::VECREGRegisterClass) {
    BuildMI(MBB, MI, DL, get(SPU::LRv16i8), DestReg).addReg(SrcReg);
  } else {
    // Attempt to copy unknown/unsupported register class!
    return false;
  }

  return true;
}

void
SPUInstrInfo::storeRegToStackSlot(MachineBasicBlock &MBB,
                                     MachineBasicBlock::iterator MI,
                                     unsigned SrcReg, bool isKill, int FrameIdx,
                                     const TargetRegisterClass *RC) const
{
  unsigned opc;
  bool isValidFrameIdx = (FrameIdx < SPUFrameInfo::maxFrameOffset());
  if (RC == SPU::GPRCRegisterClass) {
    opc = (isValidFrameIdx ? SPU::STQDr128 : SPU::STQXr128);
  } else if (RC == SPU::R64CRegisterClass) {
    opc = (isValidFrameIdx ? SPU::STQDr64 : SPU::STQXr64);
  } else if (RC == SPU::R64FPRegisterClass) {
    opc = (isValidFrameIdx ? SPU::STQDr64 : SPU::STQXr64);
  } else if (RC == SPU::R32CRegisterClass) {
    opc = (isValidFrameIdx ? SPU::STQDr32 : SPU::STQXr32);
  } else if (RC == SPU::R32FPRegisterClass) {
    opc = (isValidFrameIdx ? SPU::STQDr32 : SPU::STQXr32);
  } else if (RC == SPU::R16CRegisterClass) {
    opc = (isValidFrameIdx ? SPU::STQDr16 : SPU::STQXr16);
  } else if (RC == SPU::R8CRegisterClass) {
    opc = (isValidFrameIdx ? SPU::STQDr8 : SPU::STQXr8);
  } else if (RC == SPU::VECREGRegisterClass) {
    opc = (isValidFrameIdx) ? SPU::STQDv16i8 : SPU::STQXv16i8;
  } else {
    llvm_unreachable("Unknown regclass!");
  }

  DebugLoc DL = DebugLoc::getUnknownLoc();
  if (MI != MBB.end()) DL = MI->getDebugLoc();
  addFrameReference(BuildMI(MBB, MI, DL, get(opc))
                    .addReg(SrcReg, getKillRegState(isKill)), FrameIdx);
}

void
SPUInstrInfo::loadRegFromStackSlot(MachineBasicBlock &MBB,
                                        MachineBasicBlock::iterator MI,
                                        unsigned DestReg, int FrameIdx,
                                        const TargetRegisterClass *RC) const
{
  unsigned opc;
  bool isValidFrameIdx = (FrameIdx < SPUFrameInfo::maxFrameOffset());
  if (RC == SPU::GPRCRegisterClass) {
    opc = (isValidFrameIdx ? SPU::LQDr128 : SPU::LQXr128);
  } else if (RC == SPU::R64CRegisterClass) {
    opc = (isValidFrameIdx ? SPU::LQDr64 : SPU::LQXr64);
  } else if (RC == SPU::R64FPRegisterClass) {
    opc = (isValidFrameIdx ? SPU::LQDr64 : SPU::LQXr64);
  } else if (RC == SPU::R32CRegisterClass) {
    opc = (isValidFrameIdx ? SPU::LQDr32 : SPU::LQXr32);
  } else if (RC == SPU::R32FPRegisterClass) {
    opc = (isValidFrameIdx ? SPU::LQDr32 : SPU::LQXr32);
  } else if (RC == SPU::R16CRegisterClass) {
    opc = (isValidFrameIdx ? SPU::LQDr16 : SPU::LQXr16);
  } else if (RC == SPU::R8CRegisterClass) {
    opc = (isValidFrameIdx ? SPU::LQDr8 : SPU::LQXr8);
  } else if (RC == SPU::VECREGRegisterClass) {
    opc = (isValidFrameIdx) ? SPU::LQDv16i8 : SPU::LQXv16i8;
  } else {
    llvm_unreachable("Unknown regclass in loadRegFromStackSlot!");
  }

  DebugLoc DL = DebugLoc::getUnknownLoc();
  if (MI != MBB.end()) DL = MI->getDebugLoc();
  addFrameReference(BuildMI(MBB, MI, DL, get(opc), DestReg), FrameIdx);
}

//! Return true if the specified load or store can be folded
bool
SPUInstrInfo::canFoldMemoryOperand(const MachineInstr *MI,
                                   const SmallVectorImpl<unsigned> &Ops) const {
  if (Ops.size() != 1) return false;

  // Make sure this is a reg-reg copy.
  unsigned Opc = MI->getOpcode();

  switch (Opc) {
  case SPU::ORv16i8:
  case SPU::ORv8i16:
  case SPU::ORv4i32:
  case SPU::ORv2i64:
  case SPU::ORr8:
  case SPU::ORr16:
  case SPU::ORr32:
  case SPU::ORr64:
  case SPU::ORf32:
  case SPU::ORf64:
    if (MI->getOperand(1).getReg() == MI->getOperand(2).getReg())
      return true;
    break;
  }

  return false;
}

/// foldMemoryOperand - SPU, like PPC, can only fold spills into
/// copy instructions, turning them into load/store instructions.
MachineInstr *
SPUInstrInfo::foldMemoryOperandImpl(MachineFunction &MF,
                                    MachineInstr *MI,
                                    const SmallVectorImpl<unsigned> &Ops,
                                    int FrameIndex) const
{
  if (Ops.size() != 1) return 0;

  unsigned OpNum = Ops[0];
  unsigned Opc = MI->getOpcode();
  MachineInstr *NewMI = 0;

  switch (Opc) {
  case SPU::ORv16i8:
  case SPU::ORv8i16:
  case SPU::ORv4i32:
  case SPU::ORv2i64:
  case SPU::ORr8:
  case SPU::ORr16:
  case SPU::ORr32:
  case SPU::ORr64:
  case SPU::ORf32:
  case SPU::ORf64:
    if (OpNum == 0) {  // move -> store
      unsigned InReg = MI->getOperand(1).getReg();
      bool isKill = MI->getOperand(1).isKill();
      bool isUndef = MI->getOperand(1).isUndef();
      if (FrameIndex < SPUFrameInfo::maxFrameOffset()) {
        MachineInstrBuilder MIB = BuildMI(MF, MI->getDebugLoc(),
                                          get(SPU::STQDr32));

        MIB.addReg(InReg, getKillRegState(isKill) | getUndefRegState(isUndef));
        NewMI = addFrameReference(MIB, FrameIndex);
      }
    } else {           // move -> load
      unsigned OutReg = MI->getOperand(0).getReg();
      bool isDead = MI->getOperand(0).isDead();
      bool isUndef = MI->getOperand(0).isUndef();
      MachineInstrBuilder MIB = BuildMI(MF, MI->getDebugLoc(), get(Opc));

      MIB.addReg(OutReg, RegState::Define | getDeadRegState(isDead) |
                 getUndefRegState(isUndef));
      Opc = (FrameIndex < SPUFrameInfo::maxFrameOffset())
        ? SPU::STQDr32 : SPU::STQXr32;
      NewMI = addFrameReference(MIB, FrameIndex);
    break;
  }
  }

  return NewMI;
}

//! Branch analysis
/*!
  \note This code was kiped from PPC. There may be more branch analysis for
  CellSPU than what's currently done here.
 */
bool
SPUInstrInfo::AnalyzeBranch(MachineBasicBlock &MBB, MachineBasicBlock *&TBB,
                            MachineBasicBlock *&FBB,
                            SmallVectorImpl<MachineOperand> &Cond,
                            bool AllowModify) const {
  // If the block has no terminators, it just falls into the block after it.
  MachineBasicBlock::iterator I = MBB.end();
  if (I == MBB.begin() || !isUnpredicatedTerminator(--I))
    return false;

  // Get the last instruction in the block.
  MachineInstr *LastInst = I;

  // If there is only one terminator instruction, process it.
  if (I == MBB.begin() || !isUnpredicatedTerminator(--I)) {
    if (isUncondBranch(LastInst)) {
      TBB = LastInst->getOperand(0).getMBB();
      return false;
    } else if (isCondBranch(LastInst)) {
      // Block ends with fall-through condbranch.
      TBB = LastInst->getOperand(1).getMBB();
      DEBUG(errs() << "Pushing LastInst:               ");
      DEBUG(LastInst->dump());
      Cond.push_back(MachineOperand::CreateImm(LastInst->getOpcode()));
      Cond.push_back(LastInst->getOperand(0));
      return false;
    }
    // Otherwise, don't know what this is.
    return true;
  }

  // Get the instruction before it if it's a terminator.
  MachineInstr *SecondLastInst = I;

  // If there are three terminators, we don't know what sort of block this is.
  if (SecondLastInst && I != MBB.begin() &&
      isUnpredicatedTerminator(--I))
    return true;

  // If the block ends with a conditional and unconditional branch, handle it.
  if (isCondBranch(SecondLastInst) && isUncondBranch(LastInst)) {
    TBB =  SecondLastInst->getOperand(1).getMBB();
    DEBUG(errs() << "Pushing SecondLastInst:         ");
    DEBUG(SecondLastInst->dump());
    Cond.push_back(MachineOperand::CreateImm(SecondLastInst->getOpcode()));
    Cond.push_back(SecondLastInst->getOperand(0));
    FBB = LastInst->getOperand(0).getMBB();
    return false;
  }

  // If the block ends with two unconditional branches, handle it.  The second
  // one is not executed, so remove it.
  if (isUncondBranch(SecondLastInst) && isUncondBranch(LastInst)) {
    TBB = SecondLastInst->getOperand(0).getMBB();
    I = LastInst;
    if (AllowModify)
      I->eraseFromParent();
    return false;
  }

  // Otherwise, can't handle this.
  return true;
}

unsigned
SPUInstrInfo::RemoveBranch(MachineBasicBlock &MBB) const {
  MachineBasicBlock::iterator I = MBB.end();
  if (I == MBB.begin())
    return 0;
  --I;
  if (!isCondBranch(I) && !isUncondBranch(I))
    return 0;

  // Remove the first branch.
  DEBUG(errs() << "Removing branch:                ");
  DEBUG(I->dump());
  I->eraseFromParent();
  I = MBB.end();
  if (I == MBB.begin())
    return 1;

  --I;
  if (!(isCondBranch(I) || isUncondBranch(I)))
    return 1;

  // Remove the second branch.
  DEBUG(errs() << "Removing second branch:         ");
  DEBUG(I->dump());
  I->eraseFromParent();
  return 2;
}

unsigned
SPUInstrInfo::InsertBranch(MachineBasicBlock &MBB, MachineBasicBlock *TBB,
                           MachineBasicBlock *FBB,
                           const SmallVectorImpl<MachineOperand> &Cond) const {
  // FIXME this should probably have a DebugLoc argument
  DebugLoc dl = DebugLoc::getUnknownLoc();
  // Shouldn't be a fall through.
  assert(TBB && "InsertBranch must not be told to insert a fallthrough");
  assert((Cond.size() == 2 || Cond.size() == 0) &&
         "SPU branch conditions have two components!");

  // One-way branch.
  if (FBB == 0) {
    if (Cond.empty()) {
      // Unconditional branch
      MachineInstrBuilder MIB = BuildMI(&MBB, dl, get(SPU::BR));
      MIB.addMBB(TBB);

      DEBUG(errs() << "Inserted one-way uncond branch: ");
      DEBUG((*MIB).dump());
    } else {
      // Conditional branch
      MachineInstrBuilder  MIB = BuildMI(&MBB, dl, get(Cond[0].getImm()));
      MIB.addReg(Cond[1].getReg()).addMBB(TBB);

      DEBUG(errs() << "Inserted one-way cond branch:   ");
      DEBUG((*MIB).dump());
    }
    return 1;
  } else {
    MachineInstrBuilder MIB = BuildMI(&MBB, dl, get(Cond[0].getImm()));
    MachineInstrBuilder MIB2 = BuildMI(&MBB, dl, get(SPU::BR));

    // Two-way Conditional Branch.
    MIB.addReg(Cond[1].getReg()).addMBB(TBB);
    MIB2.addMBB(FBB);

    DEBUG(errs() << "Inserted conditional branch:    ");
    DEBUG((*MIB).dump());
    DEBUG(errs() << "part 2: ");
    DEBUG((*MIB2).dump());
   return 2;
  }
}

//! Reverses a branch's condition, returning false on success.
bool
SPUInstrInfo::ReverseBranchCondition(SmallVectorImpl<MachineOperand> &Cond)
  const {
  // Pretty brainless way of inverting the condition, but it works, considering
  // there are only two conditions...
  static struct {
    unsigned Opc;               //! The incoming opcode
    unsigned RevCondOpc;        //! The reversed condition opcode
  } revconds[] = {
    { SPU::BRNZr32, SPU::BRZr32 },
    { SPU::BRNZv4i32, SPU::BRZv4i32 },
    { SPU::BRZr32, SPU::BRNZr32 },
    { SPU::BRZv4i32, SPU::BRNZv4i32 },
    { SPU::BRHNZr16, SPU::BRHZr16 },
    { SPU::BRHNZv8i16, SPU::BRHZv8i16 },
    { SPU::BRHZr16, SPU::BRHNZr16 },
    { SPU::BRHZv8i16, SPU::BRHNZv8i16 }
  };

  unsigned Opc = unsigned(Cond[0].getImm());
  // Pretty dull mapping between the two conditions that SPU can generate:
  for (int i = sizeof(revconds)/sizeof(revconds[0]) - 1; i >= 0; --i) {
    if (revconds[i].Opc == Opc) {
      Cond[0].setImm(revconds[i].RevCondOpc);
      return false;
    }
  }

  return true;
}
