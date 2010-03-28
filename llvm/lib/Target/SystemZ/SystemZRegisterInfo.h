//===- SystemZRegisterInfo.h - SystemZ Register Information Impl ----*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains the SystemZ implementation of the TargetRegisterInfo class.
//
//===----------------------------------------------------------------------===//

#ifndef SystemZREGISTERINFO_H
#define SystemZREGISTERINFO_H

#include "llvm/Target/TargetRegisterInfo.h"
#include "SystemZGenRegisterInfo.h.inc"

namespace llvm {

namespace SystemZ {
  /// SubregIndex - The index of various sized subregister classes. Note that
  /// these indices must be kept in sync with the class indices in the
  /// SystemZRegisterInfo.td file.
  enum SubregIndex {
    SUBREG_32BIT = 1, SUBREG_EVEN = 1, SUBREG_ODD = 2
  };
}

class SystemZSubtarget;
class SystemZInstrInfo;
class Type;

struct SystemZRegisterInfo : public SystemZGenRegisterInfo {
  SystemZTargetMachine &TM;
  const SystemZInstrInfo &TII;

  SystemZRegisterInfo(SystemZTargetMachine &tm, const SystemZInstrInfo &tii);

  /// Code Generation virtual methods...
  const unsigned *getCalleeSavedRegs(const MachineFunction *MF = 0) const;

  const TargetRegisterClass* const* getCalleeSavedRegClasses(
                                     const MachineFunction *MF = 0) const;

  BitVector getReservedRegs(const MachineFunction &MF) const;

  bool hasReservedCallFrame(MachineFunction &MF) const { return true; }
  bool hasFP(const MachineFunction &MF) const;

  int getFrameIndexOffset(const MachineFunction &MF, int FI) const;

  void eliminateCallFramePseudoInstr(MachineFunction &MF,
                                     MachineBasicBlock &MBB,
                                     MachineBasicBlock::iterator I) const;

  unsigned eliminateFrameIndex(MachineBasicBlock::iterator II,
                               int SPAdj, int *Value = NULL,
                               RegScavenger *RS = NULL) const;


  void processFunctionBeforeCalleeSavedScan(MachineFunction &MF,
                                            RegScavenger *RS) const;

  void emitPrologue(MachineFunction &MF) const;
  void emitEpilogue(MachineFunction &MF, MachineBasicBlock &MBB) const;

  // Debug information queries.
  unsigned getRARegister() const;
  unsigned getFrameRegister(const MachineFunction &MF) const;

  // Exception handling queries.
  unsigned getEHExceptionRegister() const;
  unsigned getEHHandlerRegister() const;

  int getDwarfRegNum(unsigned RegNum, bool isEH) const;
};

} // end namespace llvm

#endif
