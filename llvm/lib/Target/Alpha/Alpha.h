//===-- Alpha.h - Top-level interface for Alpha representation --*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains the entry points for global functions defined in the LLVM
// Alpha back-end.
//
//===----------------------------------------------------------------------===//

#ifndef TARGET_ALPHA_H
#define TARGET_ALPHA_H

#include "llvm/Target/TargetMachine.h"

namespace llvm {

  class AlphaTargetMachine;
  class FunctionPass;
  class MachineCodeEmitter;
  class ObjectCodeEmitter;
  class formatted_raw_ostream;

  FunctionPass *createAlphaISelDag(AlphaTargetMachine &TM);
  FunctionPass *createAlphaPatternInstructionSelector(TargetMachine &TM);
  FunctionPass *createAlphaCodeEmitterPass(AlphaTargetMachine &TM,
                                           MachineCodeEmitter &MCE);
  FunctionPass *createAlphaJITCodeEmitterPass(AlphaTargetMachine &TM,
                                              JITCodeEmitter &JCE);
  FunctionPass *createAlphaObjectCodeEmitterPass(AlphaTargetMachine &TM,
                                                 ObjectCodeEmitter &OCE);
  FunctionPass *createAlphaLLRPPass(AlphaTargetMachine &tm);
  FunctionPass *createAlphaBranchSelectionPass();

  extern Target TheAlphaTarget;

} // end namespace llvm;

// Defines symbolic names for Alpha registers.  This defines a mapping from
// register name to register number.
//
#include "AlphaGenRegisterNames.inc"

// Defines symbolic names for the Alpha instructions.
//
#include "AlphaGenInstrNames.inc"

#endif
