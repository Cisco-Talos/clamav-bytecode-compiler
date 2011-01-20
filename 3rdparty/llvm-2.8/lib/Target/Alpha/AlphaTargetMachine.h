//===-- AlphaTargetMachine.h - Define TargetMachine for Alpha ---*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file declares the Alpha-specific subclass of TargetMachine.
//
//===----------------------------------------------------------------------===//

#ifndef ALPHA_TARGETMACHINE_H
#define ALPHA_TARGETMACHINE_H

#include "llvm/Target/TargetMachine.h"
#include "llvm/Target/TargetData.h"
#include "llvm/Target/TargetFrameInfo.h"
#include "AlphaInstrInfo.h"
#include "AlphaJITInfo.h"
#include "AlphaISelLowering.h"
#include "AlphaSelectionDAGInfo.h"
#include "AlphaSubtarget.h"

namespace llvm {

class GlobalValue;

class AlphaTargetMachine : public LLVMTargetMachine {
  const TargetData DataLayout;       // Calculates type size & alignment
  AlphaInstrInfo InstrInfo;
  TargetFrameInfo FrameInfo;
  AlphaJITInfo JITInfo;
  AlphaSubtarget Subtarget;
  AlphaTargetLowering TLInfo;
  AlphaSelectionDAGInfo TSInfo;

public:
  AlphaTargetMachine(const Target &T, const std::string &TT,
                     const std::string &FS);

  virtual const AlphaInstrInfo *getInstrInfo() const { return &InstrInfo; }
  virtual const TargetFrameInfo  *getFrameInfo() const { return &FrameInfo; }
  virtual const AlphaSubtarget   *getSubtargetImpl() const{ return &Subtarget; }
  virtual const AlphaRegisterInfo *getRegisterInfo() const {
    return &InstrInfo.getRegisterInfo();
  }
  virtual const AlphaTargetLowering* getTargetLowering() const {
    return &TLInfo;
  }
  virtual const AlphaSelectionDAGInfo* getSelectionDAGInfo() const {
    return &TSInfo;
  }
  virtual const TargetData       *getTargetData() const { return &DataLayout; }
  virtual AlphaJITInfo* getJITInfo() {
    return &JITInfo;
  }

  // Pass Pipeline Configuration
  virtual bool addInstSelector(PassManagerBase &PM, CodeGenOpt::Level OptLevel);
  virtual bool addPreEmitPass(PassManagerBase &PM, CodeGenOpt::Level OptLevel);
  virtual bool addCodeEmitter(PassManagerBase &PM, CodeGenOpt::Level OptLevel,
                              JITCodeEmitter &JCE);
};

} // end namespace llvm

#endif
