//===- XCoreRegisterInfo.cpp - XCore Register Information -------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains the XCore implementation of the MRegisterInfo class.
//
//===----------------------------------------------------------------------===//

#include "XCoreRegisterInfo.h"
#include "XCoreMachineFunctionInfo.h"
#include "XCore.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineLocation.h"
#include "llvm/CodeGen/MachineModuleInfo.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/CodeGen/RegisterScavenging.h"
#include "llvm/Target/TargetFrameInfo.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/Target/TargetOptions.h"
#include "llvm/Target/TargetInstrInfo.h"
#include "llvm/Type.h"
#include "llvm/Function.h"
#include "llvm/ADT/BitVector.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

XCoreRegisterInfo::XCoreRegisterInfo(const TargetInstrInfo &tii)
  : XCoreGenRegisterInfo(XCore::ADJCALLSTACKDOWN, XCore::ADJCALLSTACKUP),
    TII(tii) {
}

// helper functions
static inline bool isImmUs(unsigned val) {
  return val <= 11;
}

static inline bool isImmU6(unsigned val) {
  return val < (1 << 6);
}

static inline bool isImmU16(unsigned val) {
  return val < (1 << 16);
}

static const unsigned XCore_ArgRegs[] = {
  XCore::R0, XCore::R1, XCore::R2, XCore::R3
};

const unsigned * XCoreRegisterInfo::getArgRegs(const MachineFunction *MF)
{
  return XCore_ArgRegs;
}

unsigned XCoreRegisterInfo::getNumArgRegs(const MachineFunction *MF)
{
  return array_lengthof(XCore_ArgRegs);
}

bool XCoreRegisterInfo::needsFrameMoves(const MachineFunction &MF) {
  return MF.getMMI().hasDebugInfo() || !MF.getFunction()->doesNotThrow() ||
          UnwindTablesMandatory;
}

const unsigned* XCoreRegisterInfo::getCalleeSavedRegs(const MachineFunction *MF)
                                                                         const {
  static const unsigned CalleeSavedRegs[] = {
    XCore::R4, XCore::R5, XCore::R6, XCore::R7,
    XCore::R8, XCore::R9, XCore::R10, XCore::LR,
    0
  };
  return CalleeSavedRegs;
}

BitVector XCoreRegisterInfo::getReservedRegs(const MachineFunction &MF) const {
  BitVector Reserved(getNumRegs());
  Reserved.set(XCore::CP);
  Reserved.set(XCore::DP);
  Reserved.set(XCore::SP);
  Reserved.set(XCore::LR);
  if (hasFP(MF)) {
    Reserved.set(XCore::R10);
  }
  return Reserved;
}

bool
XCoreRegisterInfo::requiresRegisterScavenging(const MachineFunction &MF) const {
  // TODO can we estimate stack size?
  return hasFP(MF);
}

bool XCoreRegisterInfo::hasFP(const MachineFunction &MF) const {
  return DisableFramePointerElim(MF) || MF.getFrameInfo()->hasVarSizedObjects();
}

// This function eliminates ADJCALLSTACKDOWN,
// ADJCALLSTACKUP pseudo instructions
void XCoreRegisterInfo::
eliminateCallFramePseudoInstr(MachineFunction &MF, MachineBasicBlock &MBB,
                              MachineBasicBlock::iterator I) const {
  if (!hasReservedCallFrame(MF)) {
    // Turn the adjcallstackdown instruction into 'extsp <amt>' and the
    // adjcallstackup instruction into 'ldaw sp, sp[<amt>]'
    MachineInstr *Old = I;
    uint64_t Amount = Old->getOperand(0).getImm();
    if (Amount != 0) {
      // We need to keep the stack aligned properly.  To do this, we round the
      // amount of space needed for the outgoing arguments up to the next
      // alignment boundary.
      unsigned Align = MF.getTarget().getFrameInfo()->getStackAlignment();
      Amount = (Amount+Align-1)/Align*Align;

      assert(Amount%4 == 0);
      Amount /= 4;
      
      bool isU6 = isImmU6(Amount);
      
      if (!isU6 && !isImmU16(Amount)) {
        // FIX could emit multiple instructions in this case.
#ifndef NDEBUG
        errs() << "eliminateCallFramePseudoInstr size too big: "
               << Amount << "\n";
#endif
        llvm_unreachable(0);
      }

      MachineInstr *New;
      if (Old->getOpcode() == XCore::ADJCALLSTACKDOWN) {
        int Opcode = isU6 ? XCore::EXTSP_u6 : XCore::EXTSP_lu6;
        New=BuildMI(MF, Old->getDebugLoc(), TII.get(Opcode))
          .addImm(Amount);
      } else {
        assert(Old->getOpcode() == XCore::ADJCALLSTACKUP);
        int Opcode = isU6 ? XCore::LDAWSP_ru6_RRegs : XCore::LDAWSP_lru6_RRegs;
        New=BuildMI(MF, Old->getDebugLoc(), TII.get(Opcode), XCore::SP)
          .addImm(Amount);
      }

      // Replace the pseudo instruction with a new instruction...
      MBB.insert(I, New);
    }
  }
  
  MBB.erase(I);
}

void
XCoreRegisterInfo::eliminateFrameIndex(MachineBasicBlock::iterator II,
                                       int SPAdj, RegScavenger *RS) const {
  assert(SPAdj == 0 && "Unexpected");
  MachineInstr &MI = *II;
  DebugLoc dl = MI.getDebugLoc();
  unsigned i = 0;

  while (!MI.getOperand(i).isFI()) {
    ++i;
    assert(i < MI.getNumOperands() && "Instr doesn't have FrameIndex operand!");
  }

  MachineOperand &FrameOp = MI.getOperand(i);
  int FrameIndex = FrameOp.getIndex();

  MachineFunction &MF = *MI.getParent()->getParent();
  int Offset = MF.getFrameInfo()->getObjectOffset(FrameIndex);
  int StackSize = MF.getFrameInfo()->getStackSize();

  #ifndef NDEBUG
  DEBUG(errs() << "\nFunction         : " 
        << MF.getFunction()->getName() << "\n");
  DEBUG(errs() << "<--------->\n");
  DEBUG(MI.print(errs()));
  DEBUG(errs() << "FrameIndex         : " << FrameIndex << "\n");
  DEBUG(errs() << "FrameOffset        : " << Offset << "\n");
  DEBUG(errs() << "StackSize          : " << StackSize << "\n");
  #endif

  Offset += StackSize;
  
  // fold constant into offset.
  Offset += MI.getOperand(i + 1).getImm();
  MI.getOperand(i + 1).ChangeToImmediate(0);
  
  assert(Offset%4 == 0 && "Misaligned stack offset");

  DEBUG(errs() << "Offset             : " << Offset << "\n" << "<--------->\n");
  
  Offset/=4;
  
  bool FP = hasFP(MF);
  
  unsigned Reg = MI.getOperand(0).getReg();
  bool isKill = MI.getOpcode() == XCore::STWFI && MI.getOperand(0).isKill();

  assert(XCore::GRRegsRegisterClass->contains(Reg) &&
         "Unexpected register operand");
  
  MachineBasicBlock &MBB = *MI.getParent();
  
  if (FP) {
    bool isUs = isImmUs(Offset);
    unsigned FramePtr = XCore::R10;
    
    if (!isUs) {
      if (!RS)
        report_fatal_error("eliminateFrameIndex Frame size too big: " +
                           Twine(Offset));
      unsigned ScratchReg = RS->scavengeRegister(XCore::GRRegsRegisterClass, II,
                                                 SPAdj);
      loadConstant(MBB, II, ScratchReg, Offset, dl);
      switch (MI.getOpcode()) {
      case XCore::LDWFI:
        BuildMI(MBB, II, dl, TII.get(XCore::LDW_3r), Reg)
              .addReg(FramePtr)
              .addReg(ScratchReg, RegState::Kill);
        break;
      case XCore::STWFI:
        BuildMI(MBB, II, dl, TII.get(XCore::STW_3r))
              .addReg(Reg, getKillRegState(isKill))
              .addReg(FramePtr)
              .addReg(ScratchReg, RegState::Kill);
        break;
      case XCore::LDAWFI:
        BuildMI(MBB, II, dl, TII.get(XCore::LDAWF_l3r), Reg)
              .addReg(FramePtr)
              .addReg(ScratchReg, RegState::Kill);
        break;
      default:
        llvm_unreachable("Unexpected Opcode");
      }
    } else {
      switch (MI.getOpcode()) {
      case XCore::LDWFI:
        BuildMI(MBB, II, dl, TII.get(XCore::LDW_2rus), Reg)
              .addReg(FramePtr)
              .addImm(Offset);
        break;
      case XCore::STWFI:
        BuildMI(MBB, II, dl, TII.get(XCore::STW_2rus))
              .addReg(Reg, getKillRegState(isKill))
              .addReg(FramePtr)
              .addImm(Offset);
        break;
      case XCore::LDAWFI:
        BuildMI(MBB, II, dl, TII.get(XCore::LDAWF_l2rus), Reg)
              .addReg(FramePtr)
              .addImm(Offset);
        break;
      default:
        llvm_unreachable("Unexpected Opcode");
      }
    }
  } else {
    bool isU6 = isImmU6(Offset);
    if (!isU6 && !isImmU16(Offset))
      report_fatal_error("eliminateFrameIndex Frame size too big: " +
                         Twine(Offset));

    switch (MI.getOpcode()) {
    int NewOpcode;
    case XCore::LDWFI:
      NewOpcode = (isU6) ? XCore::LDWSP_ru6 : XCore::LDWSP_lru6;
      BuildMI(MBB, II, dl, TII.get(NewOpcode), Reg)
            .addImm(Offset);
      break;
    case XCore::STWFI:
      NewOpcode = (isU6) ? XCore::STWSP_ru6 : XCore::STWSP_lru6;
      BuildMI(MBB, II, dl, TII.get(NewOpcode))
            .addReg(Reg, getKillRegState(isKill))
            .addImm(Offset);
      break;
    case XCore::LDAWFI:
      NewOpcode = (isU6) ? XCore::LDAWSP_ru6 : XCore::LDAWSP_lru6;
      BuildMI(MBB, II, dl, TII.get(NewOpcode), Reg)
            .addImm(Offset);
      break;
    default:
      llvm_unreachable("Unexpected Opcode");
    }
  }
  // Erase old instruction.
  MBB.erase(II);
}

void
XCoreRegisterInfo::processFunctionBeforeCalleeSavedScan(MachineFunction &MF,
                                                      RegScavenger *RS) const {
  MachineFrameInfo *MFI = MF.getFrameInfo();
  bool LRUsed = MF.getRegInfo().isPhysRegUsed(XCore::LR);
  const TargetRegisterClass *RC = XCore::GRRegsRegisterClass;
  XCoreFunctionInfo *XFI = MF.getInfo<XCoreFunctionInfo>();
  if (LRUsed) {
    MF.getRegInfo().setPhysRegUnused(XCore::LR);
    
    bool isVarArg = MF.getFunction()->isVarArg();
    int FrameIdx;
    if (! isVarArg) {
      // A fixed offset of 0 allows us to save / restore LR using entsp / retsp.
      FrameIdx = MFI->CreateFixedObject(RC->getSize(), 0, true);
    } else {
      FrameIdx = MFI->CreateStackObject(RC->getSize(), RC->getAlignment(),
                                        false);
    }
    XFI->setUsesLR(FrameIdx);
    XFI->setLRSpillSlot(FrameIdx);
  }
  if (requiresRegisterScavenging(MF)) {
    // Reserve a slot close to SP or frame pointer.
    RS->setScavengingFrameIndex(MFI->CreateStackObject(RC->getSize(),
                                                       RC->getAlignment(),
                                                       false));
  }
  if (hasFP(MF)) {
    // A callee save register is used to hold the FP.
    // This needs saving / restoring in the epilogue / prologue.
    XFI->setFPSpillSlot(MFI->CreateStackObject(RC->getSize(),
                                               RC->getAlignment(),
                                               false));
  }
}

void XCoreRegisterInfo::
processFunctionBeforeFrameFinalized(MachineFunction &MF) const {
  
}

void XCoreRegisterInfo::
loadConstant(MachineBasicBlock &MBB, MachineBasicBlock::iterator I,
            unsigned DstReg, int64_t Value, DebugLoc dl) const {
  // TODO use mkmsk if possible.
  if (!isImmU16(Value)) {
    // TODO use constant pool.
    report_fatal_error("loadConstant value too big " + Twine(Value));
  }
  int Opcode = isImmU6(Value) ? XCore::LDC_ru6 : XCore::LDC_lru6;
  BuildMI(MBB, I, dl, TII.get(Opcode), DstReg).addImm(Value);
}

void XCoreRegisterInfo::
storeToStack(MachineBasicBlock &MBB, MachineBasicBlock::iterator I,
                  unsigned SrcReg, int Offset, DebugLoc dl) const {
  assert(Offset%4 == 0 && "Misaligned stack offset");
  Offset/=4;
  bool isU6 = isImmU6(Offset);
  if (!isU6 && !isImmU16(Offset))
    report_fatal_error("storeToStack offset too big " + Twine(Offset));
  int Opcode = isU6 ? XCore::STWSP_ru6 : XCore::STWSP_lru6;
  BuildMI(MBB, I, dl, TII.get(Opcode))
    .addReg(SrcReg)
    .addImm(Offset);
}

void XCoreRegisterInfo::
loadFromStack(MachineBasicBlock &MBB, MachineBasicBlock::iterator I,
                  unsigned DstReg, int Offset, DebugLoc dl) const {
  assert(Offset%4 == 0 && "Misaligned stack offset");
  Offset/=4;
  bool isU6 = isImmU6(Offset);
  if (!isU6 && !isImmU16(Offset))
    report_fatal_error("loadFromStack offset too big " + Twine(Offset));
  int Opcode = isU6 ? XCore::LDWSP_ru6 : XCore::LDWSP_lru6;
  BuildMI(MBB, I, dl, TII.get(Opcode), DstReg)
    .addImm(Offset);
}

void XCoreRegisterInfo::emitPrologue(MachineFunction &MF) const {
  MachineBasicBlock &MBB = MF.front();   // Prolog goes in entry BB
  MachineBasicBlock::iterator MBBI = MBB.begin();
  MachineFrameInfo *MFI = MF.getFrameInfo();
  MachineModuleInfo *MMI = &MF.getMMI();
  XCoreFunctionInfo *XFI = MF.getInfo<XCoreFunctionInfo>();
  DebugLoc dl = MBBI != MBB.end() ? MBBI->getDebugLoc() : DebugLoc();

  bool FP = hasFP(MF);

  // Work out frame sizes.
  int FrameSize = MFI->getStackSize();

  assert(FrameSize%4 == 0 && "Misaligned frame size");
  
  FrameSize/=4;
  
  bool isU6 = isImmU6(FrameSize);

  if (!isU6 && !isImmU16(FrameSize)) {
    // FIXME could emit multiple instructions.
    report_fatal_error("emitPrologue Frame size too big: " + Twine(FrameSize));
  }
  bool emitFrameMoves = needsFrameMoves(MF);

  // Do we need to allocate space on the stack?
  if (FrameSize) {
    bool saveLR = XFI->getUsesLR();
    bool LRSavedOnEntry = false;
    int Opcode;
    if (saveLR && (MFI->getObjectOffset(XFI->getLRSpillSlot()) == 0)) {
      Opcode = (isU6) ? XCore::ENTSP_u6 : XCore::ENTSP_lu6;
      MBB.addLiveIn(XCore::LR);
      saveLR = false;
      LRSavedOnEntry = true;
    } else {
      Opcode = (isU6) ? XCore::EXTSP_u6 : XCore::EXTSP_lu6;
    }
    BuildMI(MBB, MBBI, dl, TII.get(Opcode)).addImm(FrameSize);
    
    if (emitFrameMoves) {
      std::vector<MachineMove> &Moves = MMI->getFrameMoves();
      
      // Show update of SP.
      MCSymbol *FrameLabel = MMI->getContext().CreateTempSymbol();
      BuildMI(MBB, MBBI, dl, TII.get(XCore::PROLOG_LABEL)).addSym(FrameLabel);
      
      MachineLocation SPDst(MachineLocation::VirtualFP);
      MachineLocation SPSrc(MachineLocation::VirtualFP, -FrameSize * 4);
      Moves.push_back(MachineMove(FrameLabel, SPDst, SPSrc));
      
      if (LRSavedOnEntry) {
        MachineLocation CSDst(MachineLocation::VirtualFP, 0);
        MachineLocation CSSrc(XCore::LR);
        Moves.push_back(MachineMove(FrameLabel, CSDst, CSSrc));
      }
    }
    if (saveLR) {
      int LRSpillOffset = MFI->getObjectOffset(XFI->getLRSpillSlot());
      storeToStack(MBB, MBBI, XCore::LR, LRSpillOffset + FrameSize*4, dl);
      MBB.addLiveIn(XCore::LR);
      
      if (emitFrameMoves) {
        MCSymbol *SaveLRLabel = MMI->getContext().CreateTempSymbol();
        BuildMI(MBB, MBBI, dl, TII.get(XCore::PROLOG_LABEL)).addSym(SaveLRLabel);
        MachineLocation CSDst(MachineLocation::VirtualFP, LRSpillOffset);
        MachineLocation CSSrc(XCore::LR);
        MMI->getFrameMoves().push_back(MachineMove(SaveLRLabel, CSDst, CSSrc));
      }
    }
  }
  
  if (FP) {
    // Save R10 to the stack.
    int FPSpillOffset = MFI->getObjectOffset(XFI->getFPSpillSlot());
    storeToStack(MBB, MBBI, XCore::R10, FPSpillOffset + FrameSize*4, dl);
    // R10 is live-in. It is killed at the spill.
    MBB.addLiveIn(XCore::R10);
    if (emitFrameMoves) {
      MCSymbol *SaveR10Label = MMI->getContext().CreateTempSymbol();
      BuildMI(MBB, MBBI, dl, TII.get(XCore::PROLOG_LABEL)).addSym(SaveR10Label);
      MachineLocation CSDst(MachineLocation::VirtualFP, FPSpillOffset);
      MachineLocation CSSrc(XCore::R10);
      MMI->getFrameMoves().push_back(MachineMove(SaveR10Label, CSDst, CSSrc));
    }
    // Set the FP from the SP.
    unsigned FramePtr = XCore::R10;
    BuildMI(MBB, MBBI, dl, TII.get(XCore::LDAWSP_ru6), FramePtr)
      .addImm(0);
    if (emitFrameMoves) {
      // Show FP is now valid.
      MCSymbol *FrameLabel = MMI->getContext().CreateTempSymbol();
      BuildMI(MBB, MBBI, dl, TII.get(XCore::PROLOG_LABEL)).addSym(FrameLabel);
      MachineLocation SPDst(FramePtr);
      MachineLocation SPSrc(MachineLocation::VirtualFP);
      MMI->getFrameMoves().push_back(MachineMove(FrameLabel, SPDst, SPSrc));
    }
  }
  
  if (emitFrameMoves) {
    // Frame moves for callee saved.
    std::vector<MachineMove> &Moves = MMI->getFrameMoves();
    std::vector<std::pair<MCSymbol*, CalleeSavedInfo> >&SpillLabels =
        XFI->getSpillLabels();
    for (unsigned I = 0, E = SpillLabels.size(); I != E; ++I) {
      MCSymbol *SpillLabel = SpillLabels[I].first;
      CalleeSavedInfo &CSI = SpillLabels[I].second;
      int Offset = MFI->getObjectOffset(CSI.getFrameIdx());
      unsigned Reg = CSI.getReg();
      MachineLocation CSDst(MachineLocation::VirtualFP, Offset);
      MachineLocation CSSrc(Reg);
      Moves.push_back(MachineMove(SpillLabel, CSDst, CSSrc));
    }
  }
}

void XCoreRegisterInfo::emitEpilogue(MachineFunction &MF,
                                     MachineBasicBlock &MBB) const {
  MachineFrameInfo *MFI            = MF.getFrameInfo();
  MachineBasicBlock::iterator MBBI = prior(MBB.end());
  DebugLoc dl = MBBI->getDebugLoc();
  
  bool FP = hasFP(MF);
  
  if (FP) {
    // Restore the stack pointer.
    unsigned FramePtr = XCore::R10;
    BuildMI(MBB, MBBI, dl, TII.get(XCore::SETSP_1r))
      .addReg(FramePtr);
  }

  // Work out frame sizes.
  int FrameSize = MFI->getStackSize();

  assert(FrameSize%4 == 0 && "Misaligned frame size");

  FrameSize/=4;
  
  bool isU6 = isImmU6(FrameSize);

  if (!isU6 && !isImmU16(FrameSize)) {
    // FIXME could emit multiple instructions.
    report_fatal_error("emitEpilogue Frame size too big: " + Twine(FrameSize));
  }

  if (FrameSize) {
    XCoreFunctionInfo *XFI = MF.getInfo<XCoreFunctionInfo>();
    
    if (FP) {
      // Restore R10
      int FPSpillOffset = MFI->getObjectOffset(XFI->getFPSpillSlot());
      FPSpillOffset += FrameSize*4;
      loadFromStack(MBB, MBBI, XCore::R10, FPSpillOffset, dl);
    }
    bool restoreLR = XFI->getUsesLR();
    if (restoreLR && MFI->getObjectOffset(XFI->getLRSpillSlot()) != 0) {
      int LRSpillOffset = MFI->getObjectOffset(XFI->getLRSpillSlot());
      LRSpillOffset += FrameSize*4;
      loadFromStack(MBB, MBBI, XCore::LR, LRSpillOffset, dl);
      restoreLR = false;
    }
    if (restoreLR) {
      // Fold prologue into return instruction
      assert(MBBI->getOpcode() == XCore::RETSP_u6
        || MBBI->getOpcode() == XCore::RETSP_lu6);
      int Opcode = (isU6) ? XCore::RETSP_u6 : XCore::RETSP_lu6;
      BuildMI(MBB, MBBI, dl, TII.get(Opcode)).addImm(FrameSize);
      MBB.erase(MBBI);
    } else {
      int Opcode = (isU6) ? XCore::LDAWSP_ru6_RRegs : XCore::LDAWSP_lru6_RRegs;
      BuildMI(MBB, MBBI, dl, TII.get(Opcode), XCore::SP).addImm(FrameSize);
    }
  }
}

int XCoreRegisterInfo::getDwarfRegNum(unsigned RegNum, bool isEH) const {
  return XCoreGenRegisterInfo::getDwarfRegNumFull(RegNum, 0);
}

unsigned XCoreRegisterInfo::getFrameRegister(const MachineFunction &MF) const {
  bool FP = hasFP(MF);
  
  return FP ? XCore::R10 : XCore::SP;
}

unsigned XCoreRegisterInfo::getRARegister() const {
  return XCore::LR;
}

void XCoreRegisterInfo::getInitialFrameState(std::vector<MachineMove> &Moves)
                                                                         const {
  // Initial state of the frame pointer is SP.
  MachineLocation Dst(MachineLocation::VirtualFP);
  MachineLocation Src(XCore::SP, 0);
  Moves.push_back(MachineMove(0, Dst, Src));
}

#include "XCoreGenRegisterInfo.inc"

