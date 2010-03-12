//===-- FileWriters.h - File Writers Creation Functions ---------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// Functions to add the various file writer passes.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_CODEGEN_FILEWRITERS_H
#define LLVM_CODEGEN_FILEWRITERS_H

namespace llvm {

  class PassManagerBase;
  class ObjectCodeEmitter;
  class TargetMachine;
  class raw_ostream;

  ObjectCodeEmitter *AddELFWriter(PassManagerBase &FPM, raw_ostream &O,
                                  TargetMachine &TM);
  ObjectCodeEmitter *AddMachOWriter(PassManagerBase &FPM, raw_ostream &O,
                                    TargetMachine &TM);

} // end llvm namespace

#endif // LLVM_CODEGEN_FILEWRITERS_H
