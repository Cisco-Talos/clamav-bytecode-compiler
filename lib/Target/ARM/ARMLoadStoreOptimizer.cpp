//===-- ARMLoadStoreOptimizer.cpp - ARM load / store opt. pass ----*- C++ -*-=//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains a pass that performs load / store related peephole
// optimizations. This pass should be run after register allocation.
//
//===----------------------------------------------------------------------===//

#define DEBUG_TYPE "arm-ldst-opt"
#include "ARM.h"
#include "ARMAddressingModes.h"
#include "ARMBaseInstrInfo.h"
#include "ARMMachineFunctionInfo.h"
#include "ARMRegisterInfo.h"
#include "llvm/DerivedTypes.h"
#include "llvm/Function.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/CodeGen/RegisterScavenging.h"
#include "llvm/Target/TargetData.h"
#include "llvm/Target/TargetInstrInfo.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/Target/TargetRegisterInfo.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
using namespace llvm;

STATISTIC(NumLDMGened , "Number of ldm instructions generated");
STATISTIC(NumSTMGened , "Number of stm instructions generated");
STATISTIC(NumVLDMGened, "Number of vldm instructions generated");
STATISTIC(NumVSTMGened, "Number of vstm instructions generated");
STATISTIC(NumLdStMoved, "Number of load / store instructions moved");
STATISTIC(NumLDRDFormed,"Number of ldrd created before allocation");
STATISTIC(NumSTRDFormed,"Number of strd created before allocation");
STATISTIC(NumLDRD2LDM,  "Number of ldrd instructions turned back into ldm");
STATISTIC(NumSTRD2STM,  "Number of strd instructions turned back into stm");
STATISTIC(NumLDRD2LDR,  "Number of ldrd instructions turned back into ldr's");
STATISTIC(NumSTRD2STR,  "Number of strd instructions turned back into str's");

/// ARMAllocLoadStoreOpt - Post- register allocation pass the combine
/// load / store instructions to form ldm / stm instructions.

namespace {
  struct ARMLoadStoreOpt : public MachineFunctionPass {
    static char ID;
    ARMLoadStoreOpt() : MachineFunctionPass(&ID) {}

    const TargetInstrInfo *TII;
    const TargetRegisterInfo *TRI;
    ARMFunctionInfo *AFI;
    RegScavenger *RS;
    bool isThumb2;

    virtual bool runOnMachineFunction(MachineFunction &Fn);

    virtual const char *getPassName() const {
      return "ARM load / store optimization pass";
    }

  private:
    struct MemOpQueueEntry {
      int Offset;
      unsigned Position;
      MachineBasicBlock::iterator MBBI;
      bool Merged;
      MemOpQueueEntry(int o, int p, MachineBasicBlock::iterator i)
        : Offset(o), Position(p), MBBI(i), Merged(false) {}
    };
    typedef SmallVector<MemOpQueueEntry,8> MemOpQueue;
    typedef MemOpQueue::iterator MemOpQueueIter;

    bool MergeOps(MachineBasicBlock &MBB, MachineBasicBlock::iterator MBBI,
                  int Offset, unsigned Base, bool BaseKill, int Opcode,
                  ARMCC::CondCodes Pred, unsigned PredReg, unsigned Scratch,
                  DebugLoc dl, SmallVector<std::pair<unsigned, bool>, 8> &Regs);
    void MergeOpsUpdate(MachineBasicBlock &MBB,
                        MachineBasicBlock::iterator MBBI,
                        int Offset,
                        unsigned Base,
                        bool BaseKill,
                        int Opcode,
                        ARMCC::CondCodes Pred,
                        unsigned PredReg,
                        unsigned Scratch,
                        DebugLoc dl,
                        SmallVector<std::pair<unsigned, bool>, 8> &Regs,
                        MemOpQueue &MemOps,
                        unsigned memOpsFrom,
                        unsigned memOpsTo,
                        SmallVector<MachineBasicBlock::iterator, 4> &Merges);
    void MergeLDR_STR(MachineBasicBlock &MBB, unsigned SIndex, unsigned Base,
                      int Opcode, unsigned Size,
                      ARMCC::CondCodes Pred, unsigned PredReg,
                      unsigned Scratch, MemOpQueue &MemOps,
                      SmallVector<MachineBasicBlock::iterator, 4> &Merges);

    void AdvanceRS(MachineBasicBlock &MBB, MemOpQueue &MemOps);
    bool FixInvalidRegPairOp(MachineBasicBlock &MBB,
                             MachineBasicBlock::iterator &MBBI);
    bool MergeBaseUpdateLoadStore(MachineBasicBlock &MBB,
                                  MachineBasicBlock::iterator MBBI,
                                  const TargetInstrInfo *TII,
                                  bool &Advance,
                                  MachineBasicBlock::iterator &I);
    bool MergeBaseUpdateLSMultiple(MachineBasicBlock &MBB,
                                   MachineBasicBlock::iterator MBBI,
                                   bool &Advance,
                                   MachineBasicBlock::iterator &I);
    bool LoadStoreMultipleOpti(MachineBasicBlock &MBB);
    bool MergeReturnIntoLDM(MachineBasicBlock &MBB);
  };
  char ARMLoadStoreOpt::ID = 0;
}

static int getLoadStoreMultipleOpcode(int Opcode) {
  switch (Opcode) {
  case ARM::LDR:
    NumLDMGened++;
    return ARM::LDM;
  case ARM::STR:
    NumSTMGened++;
    return ARM::STM;
  case ARM::t2LDRi8:
  case ARM::t2LDRi12:
    NumLDMGened++;
    return ARM::t2LDM;
  case ARM::t2STRi8:
  case ARM::t2STRi12:
    NumSTMGened++;
    return ARM::t2STM;
  case ARM::VLDRS:
    NumVLDMGened++;
    return ARM::VLDMS;
  case ARM::VSTRS:
    NumVSTMGened++;
    return ARM::VSTMS;
  case ARM::VLDRD:
    NumVLDMGened++;
    return ARM::VLDMD;
  case ARM::VSTRD:
    NumVSTMGened++;
    return ARM::VSTMD;
  default: llvm_unreachable("Unhandled opcode!");
  }
  return 0;
}

static bool isT2i32Load(unsigned Opc) {
  return Opc == ARM::t2LDRi12 || Opc == ARM::t2LDRi8;
}

static bool isi32Load(unsigned Opc) {
  return Opc == ARM::LDR || isT2i32Load(Opc);
}

static bool isT2i32Store(unsigned Opc) {
  return Opc == ARM::t2STRi12 || Opc == ARM::t2STRi8;
}

static bool isi32Store(unsigned Opc) {
  return Opc == ARM::STR || isT2i32Store(Opc);
}

/// MergeOps - Create and insert a LDM or STM with Base as base register and
/// registers in Regs as the register operands that would be loaded / stored.
/// It returns true if the transformation is done.
bool
ARMLoadStoreOpt::MergeOps(MachineBasicBlock &MBB,
                          MachineBasicBlock::iterator MBBI,
                          int Offset, unsigned Base, bool BaseKill,
                          int Opcode, ARMCC::CondCodes Pred,
                          unsigned PredReg, unsigned Scratch, DebugLoc dl,
                          SmallVector<std::pair<unsigned, bool>, 8> &Regs) {
  // Only a single register to load / store. Don't bother.
  unsigned NumRegs = Regs.size();
  if (NumRegs <= 1)
    return false;

  ARM_AM::AMSubMode Mode = ARM_AM::ia;
  bool isAM4 = isi32Load(Opcode) || isi32Store(Opcode);
  if (isAM4 && Offset == 4) {
    if (isThumb2)
      // Thumb2 does not support ldmib / stmib.
      return false;
    Mode = ARM_AM::ib;
  } else if (isAM4 && Offset == -4 * (int)NumRegs + 4) {
    if (isThumb2)
      // Thumb2 does not support ldmda / stmda.
      return false;
    Mode = ARM_AM::da;
  } else if (isAM4 && Offset == -4 * (int)NumRegs) {
    Mode = ARM_AM::db;
  } else if (Offset != 0) {
    // If starting offset isn't zero, insert a MI to materialize a new base.
    // But only do so if it is cost effective, i.e. merging more than two
    // loads / stores.
    if (NumRegs <= 2)
      return false;

    unsigned NewBase;
    if (isi32Load(Opcode))
      // If it is a load, then just use one of the destination register to
      // use as the new base.
      NewBase = Regs[NumRegs-1].first;
    else {
      // Use the scratch register to use as a new base.
      NewBase = Scratch;
      if (NewBase == 0)
        return false;
    }
    int BaseOpc = !isThumb2
      ? ARM::ADDri
      : ((Base == ARM::SP) ? ARM::t2ADDrSPi : ARM::t2ADDri);
    if (Offset < 0) {
      BaseOpc = !isThumb2
        ? ARM::SUBri
        : ((Base == ARM::SP) ? ARM::t2SUBrSPi : ARM::t2SUBri);
      Offset = - Offset;
    }
    int ImmedOffset = isThumb2
      ? ARM_AM::getT2SOImmVal(Offset) : ARM_AM::getSOImmVal(Offset);
    if (ImmedOffset == -1)
      // FIXME: Try t2ADDri12 or t2SUBri12?
      return false;  // Probably not worth it then.

    BuildMI(MBB, MBBI, dl, TII->get(BaseOpc), NewBase)
      .addReg(Base, getKillRegState(BaseKill)).addImm(Offset)
      .addImm(Pred).addReg(PredReg).addReg(0);
    Base = NewBase;
    BaseKill = true;  // New base is always killed right its use.
  }

  bool isDPR = Opcode == ARM::VLDRD || Opcode == ARM::VSTRD;
  bool isDef = isi32Load(Opcode) || Opcode == ARM::VLDRS || Opcode == ARM::VLDRD;
  Opcode = getLoadStoreMultipleOpcode(Opcode);
  MachineInstrBuilder MIB = (isAM4)
    ? BuildMI(MBB, MBBI, dl, TII->get(Opcode))
        .addReg(Base, getKillRegState(BaseKill))
        .addImm(ARM_AM::getAM4ModeImm(Mode)).addImm(Pred).addReg(PredReg)
    : BuildMI(MBB, MBBI, dl, TII->get(Opcode))
        .addReg(Base, getKillRegState(BaseKill))
        .addImm(ARM_AM::getAM5Opc(Mode, false, isDPR ? NumRegs<<1 : NumRegs))
        .addImm(Pred).addReg(PredReg);
  MIB.addReg(0); // Add optional writeback (0 for now).
  for (unsigned i = 0; i != NumRegs; ++i)
    MIB = MIB.addReg(Regs[i].first, getDefRegState(isDef)
                     | getKillRegState(Regs[i].second));

  return true;
}

// MergeOpsUpdate - call MergeOps and update MemOps and merges accordingly on
// success.
void ARMLoadStoreOpt::
MergeOpsUpdate(MachineBasicBlock &MBB,
               MachineBasicBlock::iterator MBBI,
               int Offset,
               unsigned Base,
               bool BaseKill,
               int Opcode,
               ARMCC::CondCodes Pred,
               unsigned PredReg,
               unsigned Scratch,
               DebugLoc dl,
               SmallVector<std::pair<unsigned, bool>, 8> &Regs,
               MemOpQueue &MemOps,
               unsigned memOpsFrom,
               unsigned memOpsTo,
               SmallVector<MachineBasicBlock::iterator, 4> &Merges) {
  if (!MergeOps(MBB, MBBI, Offset, Base, BaseKill, Opcode,
                Pred, PredReg, Scratch, dl, Regs))
    return;
  Merges.push_back(prior(MBBI));
  for (unsigned j = memOpsFrom; j < memOpsTo; ++j) {
    MBB.erase(MemOps[j].MBBI);
    MemOps[j].Merged = true;
  }
}

/// MergeLDR_STR - Merge a number of load / store instructions into one or more
/// load / store multiple instructions.
void
ARMLoadStoreOpt::MergeLDR_STR(MachineBasicBlock &MBB, unsigned SIndex,
                          unsigned Base, int Opcode, unsigned Size,
                          ARMCC::CondCodes Pred, unsigned PredReg,
                          unsigned Scratch, MemOpQueue &MemOps,
                          SmallVector<MachineBasicBlock::iterator, 4> &Merges) {
  bool isAM4 = isi32Load(Opcode) || isi32Store(Opcode);
  int Offset = MemOps[SIndex].Offset;
  int SOffset = Offset;
  unsigned Pos = MemOps[SIndex].Position;
  MachineBasicBlock::iterator Loc = MemOps[SIndex].MBBI;
  DebugLoc dl = Loc->getDebugLoc();
  unsigned PReg = Loc->getOperand(0).getReg();
  unsigned PRegNum = ARMRegisterInfo::getRegisterNumbering(PReg);
  bool isKill = Loc->getOperand(0).isKill();

  SmallVector<std::pair<unsigned,bool>, 8> Regs;
  Regs.push_back(std::make_pair(PReg, isKill));
  for (unsigned i = SIndex+1, e = MemOps.size(); i != e; ++i) {
    int NewOffset = MemOps[i].Offset;
    unsigned Reg = MemOps[i].MBBI->getOperand(0).getReg();
    unsigned RegNum = ARMRegisterInfo::getRegisterNumbering(Reg);
    isKill = MemOps[i].MBBI->getOperand(0).isKill();
    // AM4 - register numbers in ascending order.
    // AM5 - consecutive register numbers in ascending order.
    if (NewOffset == Offset + (int)Size &&
        ((isAM4 && RegNum > PRegNum) || RegNum == PRegNum+1)) {
      Offset += Size;
      Regs.push_back(std::make_pair(Reg, isKill));
      PRegNum = RegNum;
    } else {
      // Can't merge this in. Try merge the earlier ones first.
      MergeOpsUpdate(MBB, ++Loc, SOffset, Base, false, Opcode, Pred, PredReg,
                     Scratch, dl, Regs, MemOps, SIndex, i, Merges);
      MergeLDR_STR(MBB, i, Base, Opcode, Size, Pred, PredReg, Scratch,
                   MemOps, Merges);
      return;
    }

    if (MemOps[i].Position > Pos) {
      Pos = MemOps[i].Position;
      Loc = MemOps[i].MBBI;
    }
  }

  bool BaseKill = Loc->findRegisterUseOperandIdx(Base, true) != -1;
  MergeOpsUpdate(MBB, ++Loc, SOffset, Base, BaseKill, Opcode, Pred, PredReg,
                 Scratch, dl, Regs, MemOps, SIndex, MemOps.size(), Merges);
  return;
}

static inline bool isMatchingDecrement(MachineInstr *MI, unsigned Base,
                                       unsigned Bytes, unsigned Limit,
                                       ARMCC::CondCodes Pred, unsigned PredReg){
  unsigned MyPredReg = 0;
  if (!MI)
    return false;
  if (MI->getOpcode() != ARM::t2SUBri &&
      MI->getOpcode() != ARM::t2SUBrSPi &&
      MI->getOpcode() != ARM::t2SUBrSPi12 &&
      MI->getOpcode() != ARM::tSUBspi &&
      MI->getOpcode() != ARM::SUBri)
    return false;

  // Make sure the offset fits in 8 bits.
  if (Bytes <= 0 || (Limit && Bytes >= Limit))
    return false;

  unsigned Scale = (MI->getOpcode() == ARM::tSUBspi) ? 4 : 1; // FIXME
  return (MI->getOperand(0).getReg() == Base &&
          MI->getOperand(1).getReg() == Base &&
          (MI->getOperand(2).getImm()*Scale) == Bytes &&
          llvm::getInstrPredicate(MI, MyPredReg) == Pred &&
          MyPredReg == PredReg);
}

static inline bool isMatchingIncrement(MachineInstr *MI, unsigned Base,
                                       unsigned Bytes, unsigned Limit,
                                       ARMCC::CondCodes Pred, unsigned PredReg){
  unsigned MyPredReg = 0;
  if (!MI)
    return false;
  if (MI->getOpcode() != ARM::t2ADDri &&
      MI->getOpcode() != ARM::t2ADDrSPi &&
      MI->getOpcode() != ARM::t2ADDrSPi12 &&
      MI->getOpcode() != ARM::tADDspi &&
      MI->getOpcode() != ARM::ADDri)
    return false;

  if (Bytes <= 0 || (Limit && Bytes >= Limit))
    // Make sure the offset fits in 8 bits.
    return false;

  unsigned Scale = (MI->getOpcode() == ARM::tADDspi) ? 4 : 1; // FIXME
  return (MI->getOperand(0).getReg() == Base &&
          MI->getOperand(1).getReg() == Base &&
          (MI->getOperand(2).getImm()*Scale) == Bytes &&
          llvm::getInstrPredicate(MI, MyPredReg) == Pred &&
          MyPredReg == PredReg);
}

static inline unsigned getLSMultipleTransferSize(MachineInstr *MI) {
  switch (MI->getOpcode()) {
  default: return 0;
  case ARM::LDR:
  case ARM::STR:
  case ARM::t2LDRi8:
  case ARM::t2LDRi12:
  case ARM::t2STRi8:
  case ARM::t2STRi12:
  case ARM::VLDRS:
  case ARM::VSTRS:
    return 4;
  case ARM::VLDRD:
  case ARM::VSTRD:
    return 8;
  case ARM::LDM:
  case ARM::STM:
  case ARM::t2LDM:
  case ARM::t2STM:
    return (MI->getNumOperands() - 5) * 4;
  case ARM::VLDMS:
  case ARM::VSTMS:
  case ARM::VLDMD:
  case ARM::VSTMD:
    return ARM_AM::getAM5Offset(MI->getOperand(1).getImm()) * 4;
  }
}

/// MergeBaseUpdateLSMultiple - Fold proceeding/trailing inc/dec of base
/// register into the LDM/STM/VLDM{D|S}/VSTM{D|S} op when possible:
///
/// stmia rn, <ra, rb, rc>
/// rn := rn + 4 * 3;
/// =>
/// stmia rn!, <ra, rb, rc>
///
/// rn := rn - 4 * 3;
/// ldmia rn, <ra, rb, rc>
/// =>
/// ldmdb rn!, <ra, rb, rc>
bool ARMLoadStoreOpt::MergeBaseUpdateLSMultiple(MachineBasicBlock &MBB,
                                               MachineBasicBlock::iterator MBBI,
                                               bool &Advance,
                                               MachineBasicBlock::iterator &I) {
  MachineInstr *MI = MBBI;
  unsigned Base = MI->getOperand(0).getReg();
  unsigned Bytes = getLSMultipleTransferSize(MI);
  unsigned PredReg = 0;
  ARMCC::CondCodes Pred = llvm::getInstrPredicate(MI, PredReg);
  int Opcode = MI->getOpcode();
  bool isAM4 = Opcode == ARM::LDM || Opcode == ARM::t2LDM ||
    Opcode == ARM::STM || Opcode == ARM::t2STM;

  if (isAM4) {
    if (ARM_AM::getAM4WBFlag(MI->getOperand(1).getImm()))
      return false;

    // Can't use the updating AM4 sub-mode if the base register is also a dest
    // register. e.g. ldmdb r0!, {r0, r1, r2}. The behavior is undefined.
    for (unsigned i = 3, e = MI->getNumOperands(); i != e; ++i) {
      if (MI->getOperand(i).getReg() == Base)
        return false;
    }

    ARM_AM::AMSubMode Mode = ARM_AM::getAM4SubMode(MI->getOperand(1).getImm());
    if (MBBI != MBB.begin()) {
      MachineBasicBlock::iterator PrevMBBI = prior(MBBI);
      if (Mode == ARM_AM::ia &&
          isMatchingDecrement(PrevMBBI, Base, Bytes, 0, Pred, PredReg)) {
        MI->getOperand(1).setImm(ARM_AM::getAM4ModeImm(ARM_AM::db, true));
        MI->getOperand(4).setReg(Base);
        MI->getOperand(4).setIsDef();
        MBB.erase(PrevMBBI);
        return true;
      } else if (Mode == ARM_AM::ib &&
                 isMatchingDecrement(PrevMBBI, Base, Bytes, 0, Pred, PredReg)) {
        MI->getOperand(1).setImm(ARM_AM::getAM4ModeImm(ARM_AM::da, true));
        MI->getOperand(4).setReg(Base);  // WB to base
        MI->getOperand(4).setIsDef();
        MBB.erase(PrevMBBI);
        return true;
      }
    }

    if (MBBI != MBB.end()) {
      MachineBasicBlock::iterator NextMBBI = llvm::next(MBBI);
      if ((Mode == ARM_AM::ia || Mode == ARM_AM::ib) &&
          isMatchingIncrement(NextMBBI, Base, Bytes, 0, Pred, PredReg)) {
        MI->getOperand(1).setImm(ARM_AM::getAM4ModeImm(Mode, true));
        MI->getOperand(4).setReg(Base);  // WB to base
        MI->getOperand(4).setIsDef();
        if (NextMBBI == I) {
          Advance = true;
          ++I;
        }
        MBB.erase(NextMBBI);
        return true;
      } else if ((Mode == ARM_AM::da || Mode == ARM_AM::db) &&
                 isMatchingDecrement(NextMBBI, Base, Bytes, 0, Pred, PredReg)) {
        MI->getOperand(1).setImm(ARM_AM::getAM4ModeImm(Mode, true));
        MI->getOperand(4).setReg(Base);  // WB to base
        MI->getOperand(4).setIsDef();
        if (NextMBBI == I) {
          Advance = true;
          ++I;
        }
        MBB.erase(NextMBBI);
        return true;
      }
    }
  } else {
    // VLDM{D|S}, VSTM{D|S} addressing mode 5 ops.
    if (ARM_AM::getAM5WBFlag(MI->getOperand(1).getImm()))
      return false;

    ARM_AM::AMSubMode Mode = ARM_AM::getAM5SubMode(MI->getOperand(1).getImm());
    unsigned Offset = ARM_AM::getAM5Offset(MI->getOperand(1).getImm());
    if (MBBI != MBB.begin()) {
      MachineBasicBlock::iterator PrevMBBI = prior(MBBI);
      if (Mode == ARM_AM::ia &&
          isMatchingDecrement(PrevMBBI, Base, Bytes, 0, Pred, PredReg)) {
        MI->getOperand(1).setImm(ARM_AM::getAM5Opc(ARM_AM::db, true, Offset));
        MI->getOperand(4).setReg(Base);  // WB to base
        MI->getOperand(4).setIsDef();
        MBB.erase(PrevMBBI);
        return true;
      }
    }

    if (MBBI != MBB.end()) {
      MachineBasicBlock::iterator NextMBBI = llvm::next(MBBI);
      if (Mode == ARM_AM::ia &&
          isMatchingIncrement(NextMBBI, Base, Bytes, 0, Pred, PredReg)) {
        MI->getOperand(1).setImm(ARM_AM::getAM5Opc(ARM_AM::ia, true, Offset));
        MI->getOperand(4).setReg(Base);  // WB to base
        MI->getOperand(4).setIsDef();
        if (NextMBBI == I) {
          Advance = true;
          ++I;
        }
        MBB.erase(NextMBBI);
      }
      return true;
    }
  }

  return false;
}

static unsigned getPreIndexedLoadStoreOpcode(unsigned Opc) {
  switch (Opc) {
  case ARM::LDR: return ARM::LDR_PRE;
  case ARM::STR: return ARM::STR_PRE;
  case ARM::VLDRS: return ARM::VLDMS;
  case ARM::VLDRD: return ARM::VLDMD;
  case ARM::VSTRS: return ARM::VSTMS;
  case ARM::VSTRD: return ARM::VSTMD;
  case ARM::t2LDRi8:
  case ARM::t2LDRi12:
    return ARM::t2LDR_PRE;
  case ARM::t2STRi8:
  case ARM::t2STRi12:
    return ARM::t2STR_PRE;
  default: llvm_unreachable("Unhandled opcode!");
  }
  return 0;
}

static unsigned getPostIndexedLoadStoreOpcode(unsigned Opc) {
  switch (Opc) {
  case ARM::LDR: return ARM::LDR_POST;
  case ARM::STR: return ARM::STR_POST;
  case ARM::VLDRS: return ARM::VLDMS;
  case ARM::VLDRD: return ARM::VLDMD;
  case ARM::VSTRS: return ARM::VSTMS;
  case ARM::VSTRD: return ARM::VSTMD;
  case ARM::t2LDRi8:
  case ARM::t2LDRi12:
    return ARM::t2LDR_POST;
  case ARM::t2STRi8:
  case ARM::t2STRi12:
    return ARM::t2STR_POST;
  default: llvm_unreachable("Unhandled opcode!");
  }
  return 0;
}

/// MergeBaseUpdateLoadStore - Fold proceeding/trailing inc/dec of base
/// register into the LDR/STR/FLD{D|S}/FST{D|S} op when possible:
bool ARMLoadStoreOpt::MergeBaseUpdateLoadStore(MachineBasicBlock &MBB,
                                               MachineBasicBlock::iterator MBBI,
                                               const TargetInstrInfo *TII,
                                               bool &Advance,
                                               MachineBasicBlock::iterator &I) {
  MachineInstr *MI = MBBI;
  unsigned Base = MI->getOperand(1).getReg();
  bool BaseKill = MI->getOperand(1).isKill();
  unsigned Bytes = getLSMultipleTransferSize(MI);
  int Opcode = MI->getOpcode();
  DebugLoc dl = MI->getDebugLoc();
  bool isAM5 = Opcode == ARM::VLDRD || Opcode == ARM::VLDRS ||
    Opcode == ARM::VSTRD || Opcode == ARM::VSTRS;
  bool isAM2 = Opcode == ARM::LDR || Opcode == ARM::STR;
  if (isAM2 && ARM_AM::getAM2Offset(MI->getOperand(3).getImm()) != 0)
    return false;
  else if (isAM5 && ARM_AM::getAM5Offset(MI->getOperand(2).getImm()) != 0)
    return false;
  else if (isT2i32Load(Opcode) || isT2i32Store(Opcode))
    if (MI->getOperand(2).getImm() != 0)
      return false;

  bool isLd = isi32Load(Opcode) || Opcode == ARM::VLDRS || Opcode == ARM::VLDRD;
  // Can't do the merge if the destination register is the same as the would-be
  // writeback register.
  if (isLd && MI->getOperand(0).getReg() == Base)
    return false;

  unsigned PredReg = 0;
  ARMCC::CondCodes Pred = llvm::getInstrPredicate(MI, PredReg);
  bool DoMerge = false;
  ARM_AM::AddrOpc AddSub = ARM_AM::add;
  unsigned NewOpc = 0;
  // AM2 - 12 bits, thumb2 - 8 bits.
  unsigned Limit = isAM5 ? 0 : (isAM2 ? 0x1000 : 0x100);
  if (MBBI != MBB.begin()) {
    MachineBasicBlock::iterator PrevMBBI = prior(MBBI);
    if (isMatchingDecrement(PrevMBBI, Base, Bytes, Limit, Pred, PredReg)) {
      DoMerge = true;
      AddSub = ARM_AM::sub;
      NewOpc = getPreIndexedLoadStoreOpcode(Opcode);
    } else if (!isAM5 &&
               isMatchingIncrement(PrevMBBI, Base, Bytes, Limit,Pred,PredReg)) {
      DoMerge = true;
      NewOpc = getPreIndexedLoadStoreOpcode(Opcode);
    }
    if (DoMerge)
      MBB.erase(PrevMBBI);
  }

  if (!DoMerge && MBBI != MBB.end()) {
    MachineBasicBlock::iterator NextMBBI = llvm::next(MBBI);
    if (!isAM5 &&
        isMatchingDecrement(NextMBBI, Base, Bytes, Limit, Pred, PredReg)) {
      DoMerge = true;
      AddSub = ARM_AM::sub;
      NewOpc = getPostIndexedLoadStoreOpcode(Opcode);
    } else if (isMatchingIncrement(NextMBBI, Base, Bytes, Limit,Pred,PredReg)) {
      DoMerge = true;
      NewOpc = getPostIndexedLoadStoreOpcode(Opcode);
    }
    if (DoMerge) {
      if (NextMBBI == I) {
        Advance = true;
        ++I;
      }
      MBB.erase(NextMBBI);
    }
  }

  if (!DoMerge)
    return false;

  bool isDPR = NewOpc == ARM::VLDMD || NewOpc == ARM::VSTMD;
  unsigned Offset = 0;
  if (isAM5)
    Offset = ARM_AM::getAM5Opc((AddSub == ARM_AM::sub)
                               ? ARM_AM::db
                               : ARM_AM::ia, true, (isDPR ? 2 : 1));
  else if (isAM2)
    Offset = ARM_AM::getAM2Opc(AddSub, Bytes, ARM_AM::no_shift);
  else
    Offset = AddSub == ARM_AM::sub ? -Bytes : Bytes;
  if (isLd) {
    if (isAM5)
      // VLDMS, VLDMD
      BuildMI(MBB, MBBI, dl, TII->get(NewOpc))
        .addReg(Base, getKillRegState(BaseKill))
        .addImm(Offset).addImm(Pred).addReg(PredReg)
        .addReg(Base, getDefRegState(true)) // WB base register
        .addReg(MI->getOperand(0).getReg(), RegState::Define);
    else if (isAM2)
      // LDR_PRE, LDR_POST,
      BuildMI(MBB, MBBI, dl, TII->get(NewOpc), MI->getOperand(0).getReg())
        .addReg(Base, RegState::Define)
        .addReg(Base).addReg(0).addImm(Offset).addImm(Pred).addReg(PredReg);
    else
      // t2LDR_PRE, t2LDR_POST
      BuildMI(MBB, MBBI, dl, TII->get(NewOpc), MI->getOperand(0).getReg())
        .addReg(Base, RegState::Define)
        .addReg(Base).addImm(Offset).addImm(Pred).addReg(PredReg);
  } else {
    MachineOperand &MO = MI->getOperand(0);
    if (isAM5)
      // VSTMS, VSTMD
      BuildMI(MBB, MBBI, dl, TII->get(NewOpc)).addReg(Base).addImm(Offset)
        .addImm(Pred).addReg(PredReg)
        .addReg(Base, getDefRegState(true)) // WB base register
        .addReg(MO.getReg(), getKillRegState(MO.isKill()));
    else if (isAM2)
      // STR_PRE, STR_POST
      BuildMI(MBB, MBBI, dl, TII->get(NewOpc), Base)
        .addReg(MO.getReg(), getKillRegState(MO.isKill()))
        .addReg(Base).addReg(0).addImm(Offset).addImm(Pred).addReg(PredReg);
    else
      // t2STR_PRE, t2STR_POST
      BuildMI(MBB, MBBI, dl, TII->get(NewOpc), Base)
        .addReg(MO.getReg(), getKillRegState(MO.isKill()))
        .addReg(Base).addImm(Offset).addImm(Pred).addReg(PredReg);
  }
  MBB.erase(MBBI);

  return true;
}

/// isMemoryOp - Returns true if instruction is a memory operations (that this
/// pass is capable of operating on).
static bool isMemoryOp(const MachineInstr *MI) {
  int Opcode = MI->getOpcode();
  switch (Opcode) {
  default: break;
  case ARM::LDR:
  case ARM::STR:
    return MI->getOperand(1).isReg() && MI->getOperand(2).getReg() == 0;
  case ARM::VLDRS:
  case ARM::VSTRS:
    return MI->getOperand(1).isReg();
  case ARM::VLDRD:
  case ARM::VSTRD:
    return MI->getOperand(1).isReg();
  case ARM::t2LDRi8:
  case ARM::t2LDRi12:
  case ARM::t2STRi8:
  case ARM::t2STRi12:
    return MI->getOperand(1).isReg();
  }
  return false;
}

/// AdvanceRS - Advance register scavenger to just before the earliest memory
/// op that is being merged.
void ARMLoadStoreOpt::AdvanceRS(MachineBasicBlock &MBB, MemOpQueue &MemOps) {
  MachineBasicBlock::iterator Loc = MemOps[0].MBBI;
  unsigned Position = MemOps[0].Position;
  for (unsigned i = 1, e = MemOps.size(); i != e; ++i) {
    if (MemOps[i].Position < Position) {
      Position = MemOps[i].Position;
      Loc = MemOps[i].MBBI;
    }
  }

  if (Loc != MBB.begin())
    RS->forward(prior(Loc));
}

static int getMemoryOpOffset(const MachineInstr *MI) {
  int Opcode = MI->getOpcode();
  bool isAM2 = Opcode == ARM::LDR || Opcode == ARM::STR;
  bool isAM3 = Opcode == ARM::LDRD || Opcode == ARM::STRD;
  unsigned NumOperands = MI->getDesc().getNumOperands();
  unsigned OffField = MI->getOperand(NumOperands-3).getImm();

  if (Opcode == ARM::t2LDRi12 || Opcode == ARM::t2LDRi8 ||
      Opcode == ARM::t2STRi12 || Opcode == ARM::t2STRi8 ||
      Opcode == ARM::t2LDRDi8 || Opcode == ARM::t2STRDi8)
    return OffField;

  int Offset = isAM2
    ? ARM_AM::getAM2Offset(OffField)
    : (isAM3 ? ARM_AM::getAM3Offset(OffField)
             : ARM_AM::getAM5Offset(OffField) * 4);
  if (isAM2) {
    if (ARM_AM::getAM2Op(OffField) == ARM_AM::sub)
      Offset = -Offset;
  } else if (isAM3) {
    if (ARM_AM::getAM3Op(OffField) == ARM_AM::sub)
      Offset = -Offset;
  } else {
    if (ARM_AM::getAM5Op(OffField) == ARM_AM::sub)
      Offset = -Offset;
  }
  return Offset;
}

static void InsertLDR_STR(MachineBasicBlock &MBB,
                          MachineBasicBlock::iterator &MBBI,
                          int OffImm, bool isDef,
                          DebugLoc dl, unsigned NewOpc,
                          unsigned Reg, bool RegDeadKill, bool RegUndef,
                          unsigned BaseReg, bool BaseKill, bool BaseUndef,
                          unsigned OffReg, bool OffKill, bool OffUndef,
                          ARMCC::CondCodes Pred, unsigned PredReg,
                          const TargetInstrInfo *TII, bool isT2) {
  int Offset = OffImm;
  if (!isT2) {
    if (OffImm < 0)
      Offset = ARM_AM::getAM2Opc(ARM_AM::sub, -OffImm, ARM_AM::no_shift);
    else
      Offset = ARM_AM::getAM2Opc(ARM_AM::add, OffImm, ARM_AM::no_shift);
  }
  if (isDef) {
    MachineInstrBuilder MIB = BuildMI(MBB, MBBI, MBBI->getDebugLoc(),
                                      TII->get(NewOpc))
      .addReg(Reg, getDefRegState(true) | getDeadRegState(RegDeadKill))
      .addReg(BaseReg, getKillRegState(BaseKill)|getUndefRegState(BaseUndef));
    if (!isT2)
      MIB.addReg(OffReg,  getKillRegState(OffKill)|getUndefRegState(OffUndef));
    MIB.addImm(Offset).addImm(Pred).addReg(PredReg);
  } else {
    MachineInstrBuilder MIB = BuildMI(MBB, MBBI, MBBI->getDebugLoc(),
                                      TII->get(NewOpc))
      .addReg(Reg, getKillRegState(RegDeadKill) | getUndefRegState(RegUndef))
      .addReg(BaseReg, getKillRegState(BaseKill)|getUndefRegState(BaseUndef));
    if (!isT2)
      MIB.addReg(OffReg,  getKillRegState(OffKill)|getUndefRegState(OffUndef));
    MIB.addImm(Offset).addImm(Pred).addReg(PredReg);
  }
}

bool ARMLoadStoreOpt::FixInvalidRegPairOp(MachineBasicBlock &MBB,
                                          MachineBasicBlock::iterator &MBBI) {
  MachineInstr *MI = &*MBBI;
  unsigned Opcode = MI->getOpcode();
  if (Opcode == ARM::LDRD || Opcode == ARM::STRD ||
      Opcode == ARM::t2LDRDi8 || Opcode == ARM::t2STRDi8) {
    unsigned EvenReg = MI->getOperand(0).getReg();
    unsigned OddReg  = MI->getOperand(1).getReg();
    unsigned EvenRegNum = TRI->getDwarfRegNum(EvenReg, false);
    unsigned OddRegNum  = TRI->getDwarfRegNum(OddReg, false);
    if ((EvenRegNum & 1) == 0 && (EvenRegNum + 1) == OddRegNum)
      return false;

    bool isT2 = Opcode == ARM::t2LDRDi8 || Opcode == ARM::t2STRDi8;
    bool isLd = Opcode == ARM::LDRD || Opcode == ARM::t2LDRDi8;
    bool EvenDeadKill = isLd ?
      MI->getOperand(0).isDead() : MI->getOperand(0).isKill();
    bool EvenUndef = MI->getOperand(0).isUndef();
    bool OddDeadKill  = isLd ?
      MI->getOperand(1).isDead() : MI->getOperand(1).isKill();
    bool OddUndef = MI->getOperand(1).isUndef();
    const MachineOperand &BaseOp = MI->getOperand(2);
    unsigned BaseReg = BaseOp.getReg();
    bool BaseKill = BaseOp.isKill();
    bool BaseUndef = BaseOp.isUndef();
    unsigned OffReg = isT2 ? 0 : MI->getOperand(3).getReg();
    bool OffKill = isT2 ? false : MI->getOperand(3).isKill();
    bool OffUndef = isT2 ? false : MI->getOperand(3).isUndef();
    int OffImm = getMemoryOpOffset(MI);
    unsigned PredReg = 0;
    ARMCC::CondCodes Pred = llvm::getInstrPredicate(MI, PredReg);

    if (OddRegNum > EvenRegNum && OffReg == 0 && OffImm == 0) {
      // Ascending register numbers and no offset. It's safe to change it to a
      // ldm or stm.
      unsigned NewOpc = (isLd)
        ? (isT2 ? ARM::t2LDM : ARM::LDM)
        : (isT2 ? ARM::t2STM : ARM::STM);
      if (isLd) {
        BuildMI(MBB, MBBI, MBBI->getDebugLoc(), TII->get(NewOpc))
          .addReg(BaseReg, getKillRegState(BaseKill))
          .addImm(ARM_AM::getAM4ModeImm(ARM_AM::ia))
          .addImm(Pred).addReg(PredReg)
          .addReg(0)
          .addReg(EvenReg, getDefRegState(isLd) | getDeadRegState(EvenDeadKill))
          .addReg(OddReg,  getDefRegState(isLd) | getDeadRegState(OddDeadKill));
        ++NumLDRD2LDM;
      } else {
        BuildMI(MBB, MBBI, MBBI->getDebugLoc(), TII->get(NewOpc))
          .addReg(BaseReg, getKillRegState(BaseKill))
          .addImm(ARM_AM::getAM4ModeImm(ARM_AM::ia))
          .addImm(Pred).addReg(PredReg)
          .addReg(0)
          .addReg(EvenReg,
                  getKillRegState(EvenDeadKill) | getUndefRegState(EvenUndef))
          .addReg(OddReg,
                  getKillRegState(OddDeadKill)  | getUndefRegState(OddUndef));
        ++NumSTRD2STM;
      }
    } else {
      // Split into two instructions.
      assert((!isT2 || !OffReg) &&
             "Thumb2 ldrd / strd does not encode offset register!");
      unsigned NewOpc = (isLd)
        ? (isT2 ? (OffImm < 0 ? ARM::t2LDRi8 : ARM::t2LDRi12) : ARM::LDR)
        : (isT2 ? (OffImm < 0 ? ARM::t2STRi8 : ARM::t2STRi12) : ARM::STR);
      DebugLoc dl = MBBI->getDebugLoc();
      // If this is a load and base register is killed, it may have been
      // re-defed by the load, make sure the first load does not clobber it.
      if (isLd &&
          (BaseKill || OffKill) &&
          (TRI->regsOverlap(EvenReg, BaseReg) ||
           (OffReg && TRI->regsOverlap(EvenReg, OffReg)))) {
        assert(!TRI->regsOverlap(OddReg, BaseReg) &&
               (!OffReg || !TRI->regsOverlap(OddReg, OffReg)));
        InsertLDR_STR(MBB, MBBI, OffImm+4, isLd, dl, NewOpc,
                      OddReg, OddDeadKill, false,
                      BaseReg, false, BaseUndef, OffReg, false, OffUndef,
                      Pred, PredReg, TII, isT2);
        InsertLDR_STR(MBB, MBBI, OffImm, isLd, dl, NewOpc,
                      EvenReg, EvenDeadKill, false,
                      BaseReg, BaseKill, BaseUndef, OffReg, OffKill, OffUndef,
                      Pred, PredReg, TII, isT2);
      } else {
        if (OddReg == EvenReg && EvenDeadKill) {
          // If the two source operands are the same, the kill marker is probably
          // on the first one. e.g.
          // t2STRDi8 %R5<kill>, %R5, %R9<kill>, 0, 14, %reg0
          EvenDeadKill = false;
          OddDeadKill = true;
        }
        InsertLDR_STR(MBB, MBBI, OffImm, isLd, dl, NewOpc,
                      EvenReg, EvenDeadKill, EvenUndef,
                      BaseReg, false, BaseUndef, OffReg, false, OffUndef,
                      Pred, PredReg, TII, isT2);
        InsertLDR_STR(MBB, MBBI, OffImm+4, isLd, dl, NewOpc,
                      OddReg, OddDeadKill, OddUndef,
                      BaseReg, BaseKill, BaseUndef, OffReg, OffKill, OffUndef,
                      Pred, PredReg, TII, isT2);
      }
      if (isLd)
        ++NumLDRD2LDR;
      else
        ++NumSTRD2STR;
    }

    MBBI = prior(MBBI);
    MBB.erase(MI);
  }
  return false;
}

/// LoadStoreMultipleOpti - An optimization pass to turn multiple LDR / STR
/// ops of the same base and incrementing offset into LDM / STM ops.
bool ARMLoadStoreOpt::LoadStoreMultipleOpti(MachineBasicBlock &MBB) {
  unsigned NumMerges = 0;
  unsigned NumMemOps = 0;
  MemOpQueue MemOps;
  unsigned CurrBase = 0;
  int CurrOpc = -1;
  unsigned CurrSize = 0;
  ARMCC::CondCodes CurrPred = ARMCC::AL;
  unsigned CurrPredReg = 0;
  unsigned Position = 0;
  SmallVector<MachineBasicBlock::iterator,4> Merges;

  RS->enterBasicBlock(&MBB);
  MachineBasicBlock::iterator MBBI = MBB.begin(), E = MBB.end();
  while (MBBI != E) {
    if (FixInvalidRegPairOp(MBB, MBBI))
      continue;

    bool Advance  = false;
    bool TryMerge = false;
    bool Clobber  = false;

    bool isMemOp = isMemoryOp(MBBI);
    if (isMemOp) {
      int Opcode = MBBI->getOpcode();
      unsigned Size = getLSMultipleTransferSize(MBBI);
      unsigned Base = MBBI->getOperand(1).getReg();
      unsigned PredReg = 0;
      ARMCC::CondCodes Pred = llvm::getInstrPredicate(MBBI, PredReg);
      int Offset = getMemoryOpOffset(MBBI);
      // Watch out for:
      // r4 := ldr [r5]
      // r5 := ldr [r5, #4]
      // r6 := ldr [r5, #8]
      //
      // The second ldr has effectively broken the chain even though it
      // looks like the later ldr(s) use the same base register. Try to
      // merge the ldr's so far, including this one. But don't try to
      // combine the following ldr(s).
      Clobber = (isi32Load(Opcode) && Base == MBBI->getOperand(0).getReg());
      if (CurrBase == 0 && !Clobber) {
        // Start of a new chain.
        CurrBase = Base;
        CurrOpc  = Opcode;
        CurrSize = Size;
        CurrPred = Pred;
        CurrPredReg = PredReg;
        MemOps.push_back(MemOpQueueEntry(Offset, Position, MBBI));
        NumMemOps++;
        Advance = true;
      } else {
        if (Clobber) {
          TryMerge = true;
          Advance = true;
        }

        if (CurrOpc == Opcode && CurrBase == Base && CurrPred == Pred) {
          // No need to match PredReg.
          // Continue adding to the queue.
          if (Offset > MemOps.back().Offset) {
            MemOps.push_back(MemOpQueueEntry(Offset, Position, MBBI));
            NumMemOps++;
            Advance = true;
          } else {
            for (MemOpQueueIter I = MemOps.begin(), E = MemOps.end();
                 I != E; ++I) {
              if (Offset < I->Offset) {
                MemOps.insert(I, MemOpQueueEntry(Offset, Position, MBBI));
                NumMemOps++;
                Advance = true;
                break;
              } else if (Offset == I->Offset) {
                // Collision! This can't be merged!
                break;
              }
            }
          }
        }
      }
    }

    if (Advance) {
      ++Position;
      ++MBBI;
      if (MBBI == E)
        // Reach the end of the block, try merging the memory instructions.
        TryMerge = true;
    } else
      TryMerge = true;

    if (TryMerge) {
      if (NumMemOps > 1) {
        // Try to find a free register to use as a new base in case it's needed.
        // First advance to the instruction just before the start of the chain.
        AdvanceRS(MBB, MemOps);
        // Find a scratch register.
        unsigned Scratch = RS->FindUnusedReg(ARM::GPRRegisterClass);
        // Process the load / store instructions.
        RS->forward(prior(MBBI));

        // Merge ops.
        Merges.clear();
        MergeLDR_STR(MBB, 0, CurrBase, CurrOpc, CurrSize,
                     CurrPred, CurrPredReg, Scratch, MemOps, Merges);

        // Try folding preceeding/trailing base inc/dec into the generated
        // LDM/STM ops.
        for (unsigned i = 0, e = Merges.size(); i < e; ++i)
          if (MergeBaseUpdateLSMultiple(MBB, Merges[i], Advance, MBBI))
            ++NumMerges;
        NumMerges += Merges.size();

        // Try folding preceeding/trailing base inc/dec into those load/store
        // that were not merged to form LDM/STM ops.
        for (unsigned i = 0; i != NumMemOps; ++i)
          if (!MemOps[i].Merged)
            if (MergeBaseUpdateLoadStore(MBB, MemOps[i].MBBI, TII,Advance,MBBI))
              ++NumMerges;

        // RS may be pointing to an instruction that's deleted.
        RS->skipTo(prior(MBBI));
      } else if (NumMemOps == 1) {
        // Try folding preceeding/trailing base inc/dec into the single
        // load/store.
        if (MergeBaseUpdateLoadStore(MBB, MemOps[0].MBBI, TII, Advance, MBBI)) {
          ++NumMerges;
          RS->forward(prior(MBBI));
        }
      }

      CurrBase = 0;
      CurrOpc = -1;
      CurrSize = 0;
      CurrPred = ARMCC::AL;
      CurrPredReg = 0;
      if (NumMemOps) {
        MemOps.clear();
        NumMemOps = 0;
      }

      // If iterator hasn't been advanced and this is not a memory op, skip it.
      // It can't start a new chain anyway.
      if (!Advance && !isMemOp && MBBI != E) {
        ++Position;
        ++MBBI;
      }
    }
  }
  return NumMerges > 0;
}

namespace {
  struct OffsetCompare {
    bool operator()(const MachineInstr *LHS, const MachineInstr *RHS) const {
      int LOffset = getMemoryOpOffset(LHS);
      int ROffset = getMemoryOpOffset(RHS);
      assert(LHS == RHS || LOffset != ROffset);
      return LOffset > ROffset;
    }
  };
}

/// MergeReturnIntoLDM - If this is a exit BB, try merging the return op
/// (bx lr) into the preceeding stack restore so it directly restore the value
/// of LR into pc.
///   ldmfd sp!, {r7, lr}
///   bx lr
/// =>
///   ldmfd sp!, {r7, pc}
bool ARMLoadStoreOpt::MergeReturnIntoLDM(MachineBasicBlock &MBB) {
  if (MBB.empty()) return false;

  MachineBasicBlock::iterator MBBI = prior(MBB.end());
  if (MBBI != MBB.begin() &&
      (MBBI->getOpcode() == ARM::BX_RET || MBBI->getOpcode() == ARM::tBX_RET)) {
    MachineInstr *PrevMI = prior(MBBI);
    if (PrevMI->getOpcode() == ARM::LDM || PrevMI->getOpcode() == ARM::t2LDM) {
      MachineOperand &MO = PrevMI->getOperand(PrevMI->getNumOperands()-1);
      if (MO.getReg() != ARM::LR)
        return false;
      unsigned NewOpc = isThumb2 ? ARM::t2LDM_RET : ARM::LDM_RET;
      PrevMI->setDesc(TII->get(NewOpc));
      MO.setReg(ARM::PC);
      MBB.erase(MBBI);
      return true;
    }
  }
  return false;
}

bool ARMLoadStoreOpt::runOnMachineFunction(MachineFunction &Fn) {
  const TargetMachine &TM = Fn.getTarget();
  AFI = Fn.getInfo<ARMFunctionInfo>();
  TII = TM.getInstrInfo();
  TRI = TM.getRegisterInfo();
  RS = new RegScavenger();
  isThumb2 = AFI->isThumb2Function();

  bool Modified = false;
  for (MachineFunction::iterator MFI = Fn.begin(), E = Fn.end(); MFI != E;
       ++MFI) {
    MachineBasicBlock &MBB = *MFI;
    Modified |= LoadStoreMultipleOpti(MBB);
    Modified |= MergeReturnIntoLDM(MBB);
  }

  delete RS;
  return Modified;
}


/// ARMPreAllocLoadStoreOpt - Pre- register allocation pass that move
/// load / stores from consecutive locations close to make it more
/// likely they will be combined later.

namespace {
  struct ARMPreAllocLoadStoreOpt : public MachineFunctionPass{
    static char ID;
    ARMPreAllocLoadStoreOpt() : MachineFunctionPass(&ID) {}

    const TargetData *TD;
    const TargetInstrInfo *TII;
    const TargetRegisterInfo *TRI;
    const ARMSubtarget *STI;
    MachineRegisterInfo *MRI;
    MachineFunction *MF;

    virtual bool runOnMachineFunction(MachineFunction &Fn);

    virtual const char *getPassName() const {
      return "ARM pre- register allocation load / store optimization pass";
    }

  private:
    bool CanFormLdStDWord(MachineInstr *Op0, MachineInstr *Op1, DebugLoc &dl,
                          unsigned &NewOpc, unsigned &EvenReg,
                          unsigned &OddReg, unsigned &BaseReg,
                          unsigned &OffReg, int &Offset,
                          unsigned &PredReg, ARMCC::CondCodes &Pred,
                          bool &isT2);
    bool RescheduleOps(MachineBasicBlock *MBB,
                       SmallVector<MachineInstr*, 4> &Ops,
                       unsigned Base, bool isLd,
                       DenseMap<MachineInstr*, unsigned> &MI2LocMap);
    bool RescheduleLoadStoreInstrs(MachineBasicBlock *MBB);
  };
  char ARMPreAllocLoadStoreOpt::ID = 0;
}

bool ARMPreAllocLoadStoreOpt::runOnMachineFunction(MachineFunction &Fn) {
  TD  = Fn.getTarget().getTargetData();
  TII = Fn.getTarget().getInstrInfo();
  TRI = Fn.getTarget().getRegisterInfo();
  STI = &Fn.getTarget().getSubtarget<ARMSubtarget>();
  MRI = &Fn.getRegInfo();
  MF  = &Fn;

  bool Modified = false;
  for (MachineFunction::iterator MFI = Fn.begin(), E = Fn.end(); MFI != E;
       ++MFI)
    Modified |= RescheduleLoadStoreInstrs(MFI);

  return Modified;
}

static bool IsSafeAndProfitableToMove(bool isLd, unsigned Base,
                                      MachineBasicBlock::iterator I,
                                      MachineBasicBlock::iterator E,
                                      SmallPtrSet<MachineInstr*, 4> &MemOps,
                                      SmallSet<unsigned, 4> &MemRegs,
                                      const TargetRegisterInfo *TRI) {
  // Are there stores / loads / calls between them?
  // FIXME: This is overly conservative. We should make use of alias information
  // some day.
  SmallSet<unsigned, 4> AddedRegPressure;
  while (++I != E) {
    if (MemOps.count(&*I))
      continue;
    const TargetInstrDesc &TID = I->getDesc();
    if (TID.isCall() || TID.isTerminator() || TID.hasUnmodeledSideEffects())
      return false;
    if (isLd && TID.mayStore())
      return false;
    if (!isLd) {
      if (TID.mayLoad())
        return false;
      // It's not safe to move the first 'str' down.
      // str r1, [r0]
      // strh r5, [r0]
      // str r4, [r0, #+4]
      if (TID.mayStore())
        return false;
    }
    for (unsigned j = 0, NumOps = I->getNumOperands(); j != NumOps; ++j) {
      MachineOperand &MO = I->getOperand(j);
      if (!MO.isReg())
        continue;
      unsigned Reg = MO.getReg();
      if (MO.isDef() && TRI->regsOverlap(Reg, Base))
        return false;
      if (Reg != Base && !MemRegs.count(Reg))
        AddedRegPressure.insert(Reg);
    }
  }

  // Estimate register pressure increase due to the transformation.
  if (MemRegs.size() <= 4)
    // Ok if we are moving small number of instructions.
    return true;
  return AddedRegPressure.size() <= MemRegs.size() * 2;
}

bool
ARMPreAllocLoadStoreOpt::CanFormLdStDWord(MachineInstr *Op0, MachineInstr *Op1,
                                          DebugLoc &dl,
                                          unsigned &NewOpc, unsigned &EvenReg,
                                          unsigned &OddReg, unsigned &BaseReg,
                                          unsigned &OffReg, int &Offset,
                                          unsigned &PredReg,
                                          ARMCC::CondCodes &Pred,
                                          bool &isT2) {
  // Make sure we're allowed to generate LDRD/STRD.
  if (!STI->hasV5TEOps())
    return false;

  // FIXME: VLDRS / VSTRS -> VLDRD / VSTRD
  unsigned Scale = 1;
  unsigned Opcode = Op0->getOpcode();
  if (Opcode == ARM::LDR)
    NewOpc = ARM::LDRD;
  else if (Opcode == ARM::STR)
    NewOpc = ARM::STRD;
  else if (Opcode == ARM::t2LDRi8 || Opcode == ARM::t2LDRi12) {
    NewOpc = ARM::t2LDRDi8;
    Scale = 4;
    isT2 = true;
  } else if (Opcode == ARM::t2STRi8 || Opcode == ARM::t2STRi12) {
    NewOpc = ARM::t2STRDi8;
    Scale = 4;
    isT2 = true;
  } else
    return false;

  // Make sure the offset registers match.
  if (!isT2 &&
      (Op0->getOperand(2).getReg() != Op1->getOperand(2).getReg()))
      return false;

  // Must sure the base address satisfies i64 ld / st alignment requirement.
  if (!Op0->hasOneMemOperand() ||
      !(*Op0->memoperands_begin())->getValue() ||
      (*Op0->memoperands_begin())->isVolatile())
    return false;

  unsigned Align = (*Op0->memoperands_begin())->getAlignment();
  Function *Func = MF->getFunction();
  unsigned ReqAlign = STI->hasV6Ops()
    ? TD->getPrefTypeAlignment(Type::getInt64Ty(Func->getContext())) 
    : 8;  // Pre-v6 need 8-byte align
  if (Align < ReqAlign)
    return false;

  // Then make sure the immediate offset fits.
  int OffImm = getMemoryOpOffset(Op0);
  if (isT2) {
    if (OffImm < 0) {
      if (OffImm < -255)
        // Can't fall back to t2LDRi8 / t2STRi8.
        return false;
    } else {
      int Limit = (1 << 8) * Scale;
      if (OffImm >= Limit || (OffImm & (Scale-1)))
        return false;
    }
    Offset = OffImm;
  } else {
    ARM_AM::AddrOpc AddSub = ARM_AM::add;
    if (OffImm < 0) {
      AddSub = ARM_AM::sub;
      OffImm = - OffImm;
    }
    int Limit = (1 << 8) * Scale;
    if (OffImm >= Limit || (OffImm & (Scale-1)))
      return false;
    Offset = ARM_AM::getAM3Opc(AddSub, OffImm);
  }
  EvenReg = Op0->getOperand(0).getReg();
  OddReg  = Op1->getOperand(0).getReg();
  if (EvenReg == OddReg)
    return false;
  BaseReg = Op0->getOperand(1).getReg();
  if (!isT2)
    OffReg = Op0->getOperand(2).getReg();
  Pred = llvm::getInstrPredicate(Op0, PredReg);
  dl = Op0->getDebugLoc();
  return true;
}

bool ARMPreAllocLoadStoreOpt::RescheduleOps(MachineBasicBlock *MBB,
                                 SmallVector<MachineInstr*, 4> &Ops,
                                 unsigned Base, bool isLd,
                                 DenseMap<MachineInstr*, unsigned> &MI2LocMap) {
  bool RetVal = false;

  // Sort by offset (in reverse order).
  std::sort(Ops.begin(), Ops.end(), OffsetCompare());

  // The loads / stores of the same base are in order. Scan them from first to
  // last and check for the followins:
  // 1. Any def of base.
  // 2. Any gaps.
  while (Ops.size() > 1) {
    unsigned FirstLoc = ~0U;
    unsigned LastLoc = 0;
    MachineInstr *FirstOp = 0;
    MachineInstr *LastOp = 0;
    int LastOffset = 0;
    unsigned LastOpcode = 0;
    unsigned LastBytes = 0;
    unsigned NumMove = 0;
    for (int i = Ops.size() - 1; i >= 0; --i) {
      MachineInstr *Op = Ops[i];
      unsigned Loc = MI2LocMap[Op];
      if (Loc <= FirstLoc) {
        FirstLoc = Loc;
        FirstOp = Op;
      }
      if (Loc >= LastLoc) {
        LastLoc = Loc;
        LastOp = Op;
      }

      unsigned Opcode = Op->getOpcode();
      if (LastOpcode && Opcode != LastOpcode)
        break;

      int Offset = getMemoryOpOffset(Op);
      unsigned Bytes = getLSMultipleTransferSize(Op);
      if (LastBytes) {
        if (Bytes != LastBytes || Offset != (LastOffset + (int)Bytes))
          break;
      }
      LastOffset = Offset;
      LastBytes = Bytes;
      LastOpcode = Opcode;
      if (++NumMove == 8) // FIXME: Tune this limit.
        break;
    }

    if (NumMove <= 1)
      Ops.pop_back();
    else {
      SmallPtrSet<MachineInstr*, 4> MemOps;
      SmallSet<unsigned, 4> MemRegs;
      for (int i = NumMove-1; i >= 0; --i) {
        MemOps.insert(Ops[i]);
        MemRegs.insert(Ops[i]->getOperand(0).getReg());
      }

      // Be conservative, if the instructions are too far apart, don't
      // move them. We want to limit the increase of register pressure.
      bool DoMove = (LastLoc - FirstLoc) <= NumMove*4; // FIXME: Tune this.
      if (DoMove)
        DoMove = IsSafeAndProfitableToMove(isLd, Base, FirstOp, LastOp,
                                           MemOps, MemRegs, TRI);
      if (!DoMove) {
        for (unsigned i = 0; i != NumMove; ++i)
          Ops.pop_back();
      } else {
        // This is the new location for the loads / stores.
        MachineBasicBlock::iterator InsertPos = isLd ? FirstOp : LastOp;
        while (InsertPos != MBB->end() && MemOps.count(InsertPos))
          ++InsertPos;

        // If we are moving a pair of loads / stores, see if it makes sense
        // to try to allocate a pair of registers that can form register pairs.
        MachineInstr *Op0 = Ops.back();
        MachineInstr *Op1 = Ops[Ops.size()-2];
        unsigned EvenReg = 0, OddReg = 0;
        unsigned BaseReg = 0, OffReg = 0, PredReg = 0;
        ARMCC::CondCodes Pred = ARMCC::AL;
        bool isT2 = false;
        unsigned NewOpc = 0;
        int Offset = 0;
        DebugLoc dl;
        if (NumMove == 2 && CanFormLdStDWord(Op0, Op1, dl, NewOpc,
                                             EvenReg, OddReg, BaseReg, OffReg,
                                             Offset, PredReg, Pred, isT2)) {
          Ops.pop_back();
          Ops.pop_back();

          // Form the pair instruction.
          if (isLd) {
            MachineInstrBuilder MIB = BuildMI(*MBB, InsertPos,
                                              dl, TII->get(NewOpc))
              .addReg(EvenReg, RegState::Define)
              .addReg(OddReg, RegState::Define)
              .addReg(BaseReg);
            if (!isT2)
              MIB.addReg(OffReg);
            MIB.addImm(Offset).addImm(Pred).addReg(PredReg);
            ++NumLDRDFormed;
          } else {
            MachineInstrBuilder MIB = BuildMI(*MBB, InsertPos,
                                              dl, TII->get(NewOpc))
              .addReg(EvenReg)
              .addReg(OddReg)
              .addReg(BaseReg);
            if (!isT2)
              MIB.addReg(OffReg);
            MIB.addImm(Offset).addImm(Pred).addReg(PredReg);
            ++NumSTRDFormed;
          }
          MBB->erase(Op0);
          MBB->erase(Op1);

          // Add register allocation hints to form register pairs.
          MRI->setRegAllocationHint(EvenReg, ARMRI::RegPairEven, OddReg);
          MRI->setRegAllocationHint(OddReg,  ARMRI::RegPairOdd, EvenReg);
        } else {
          for (unsigned i = 0; i != NumMove; ++i) {
            MachineInstr *Op = Ops.back();
            Ops.pop_back();
            MBB->splice(InsertPos, MBB, Op);
          }
        }

        NumLdStMoved += NumMove;
        RetVal = true;
      }
    }
  }

  return RetVal;
}

bool
ARMPreAllocLoadStoreOpt::RescheduleLoadStoreInstrs(MachineBasicBlock *MBB) {
  bool RetVal = false;

  DenseMap<MachineInstr*, unsigned> MI2LocMap;
  DenseMap<unsigned, SmallVector<MachineInstr*, 4> > Base2LdsMap;
  DenseMap<unsigned, SmallVector<MachineInstr*, 4> > Base2StsMap;
  SmallVector<unsigned, 4> LdBases;
  SmallVector<unsigned, 4> StBases;

  unsigned Loc = 0;
  MachineBasicBlock::iterator MBBI = MBB->begin();
  MachineBasicBlock::iterator E = MBB->end();
  while (MBBI != E) {
    for (; MBBI != E; ++MBBI) {
      MachineInstr *MI = MBBI;
      const TargetInstrDesc &TID = MI->getDesc();
      if (TID.isCall() || TID.isTerminator()) {
        // Stop at barriers.
        ++MBBI;
        break;
      }

      MI2LocMap[MI] = Loc++;
      if (!isMemoryOp(MI))
        continue;
      unsigned PredReg = 0;
      if (llvm::getInstrPredicate(MI, PredReg) != ARMCC::AL)
        continue;

      int Opc = MI->getOpcode();
      bool isLd = isi32Load(Opc) || Opc == ARM::VLDRS || Opc == ARM::VLDRD;
      unsigned Base = MI->getOperand(1).getReg();
      int Offset = getMemoryOpOffset(MI);

      bool StopHere = false;
      if (isLd) {
        DenseMap<unsigned, SmallVector<MachineInstr*, 4> >::iterator BI =
          Base2LdsMap.find(Base);
        if (BI != Base2LdsMap.end()) {
          for (unsigned i = 0, e = BI->second.size(); i != e; ++i) {
            if (Offset == getMemoryOpOffset(BI->second[i])) {
              StopHere = true;
              break;
            }
          }
          if (!StopHere)
            BI->second.push_back(MI);
        } else {
          SmallVector<MachineInstr*, 4> MIs;
          MIs.push_back(MI);
          Base2LdsMap[Base] = MIs;
          LdBases.push_back(Base);
        }
      } else {
        DenseMap<unsigned, SmallVector<MachineInstr*, 4> >::iterator BI =
          Base2StsMap.find(Base);
        if (BI != Base2StsMap.end()) {
          for (unsigned i = 0, e = BI->second.size(); i != e; ++i) {
            if (Offset == getMemoryOpOffset(BI->second[i])) {
              StopHere = true;
              break;
            }
          }
          if (!StopHere)
            BI->second.push_back(MI);
        } else {
          SmallVector<MachineInstr*, 4> MIs;
          MIs.push_back(MI);
          Base2StsMap[Base] = MIs;
          StBases.push_back(Base);
        }
      }

      if (StopHere) {
        // Found a duplicate (a base+offset combination that's seen earlier).
        // Backtrack.
        --Loc;
        break;
      }
    }

    // Re-schedule loads.
    for (unsigned i = 0, e = LdBases.size(); i != e; ++i) {
      unsigned Base = LdBases[i];
      SmallVector<MachineInstr*, 4> &Lds = Base2LdsMap[Base];
      if (Lds.size() > 1)
        RetVal |= RescheduleOps(MBB, Lds, Base, true, MI2LocMap);
    }

    // Re-schedule stores.
    for (unsigned i = 0, e = StBases.size(); i != e; ++i) {
      unsigned Base = StBases[i];
      SmallVector<MachineInstr*, 4> &Sts = Base2StsMap[Base];
      if (Sts.size() > 1)
        RetVal |= RescheduleOps(MBB, Sts, Base, false, MI2LocMap);
    }

    if (MBBI != E) {
      Base2LdsMap.clear();
      Base2StsMap.clear();
      LdBases.clear();
      StBases.clear();
    }
  }

  return RetVal;
}


/// createARMLoadStoreOptimizationPass - returns an instance of the load / store
/// optimization pass.
FunctionPass *llvm::createARMLoadStoreOptimizationPass(bool PreAlloc) {
  if (PreAlloc)
    return new ARMPreAllocLoadStoreOpt();
  return new ARMLoadStoreOpt();
}
