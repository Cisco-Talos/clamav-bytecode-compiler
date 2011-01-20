//===-- MCCodeEmitter.cpp - Instruction Encoding --------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "llvm/MC/MCCodeEmitter.h"

using namespace llvm;

MCCodeEmitter::MCCodeEmitter() {
}

MCCodeEmitter::~MCCodeEmitter() {
}

const MCFixupKindInfo &MCCodeEmitter::getFixupKindInfo(MCFixupKind Kind) const {
  static const MCFixupKindInfo Builtins[] = {
    { "FK_Data_1", 0, 8, 0 },
    { "FK_Data_2", 0, 16, 0 },
    { "FK_Data_4", 0, 32, 0 },
    { "FK_Data_8", 0, 64, 0 }
  };
  
  assert(Kind <= 3 && "Unknown fixup kind");
  return Builtins[Kind];
}
