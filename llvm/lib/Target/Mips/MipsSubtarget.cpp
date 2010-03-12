//===- MipsSubtarget.cpp - Mips Subtarget Information -----------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements the Mips specific subclass of TargetSubtarget.
//
//===----------------------------------------------------------------------===//

#include "MipsSubtarget.h"
#include "Mips.h"
#include "MipsGenSubtarget.inc"
using namespace llvm;

MipsSubtarget::MipsSubtarget(const std::string &TT, const std::string &FS,
                             bool little) : 
  MipsArchVersion(Mips1), MipsABI(O32), IsLittle(little), IsSingleFloat(false),
  IsFP64bit(false), IsGP64bit(false), HasVFPU(false), IsLinux(true),
  HasSEInReg(false), HasCondMov(false), HasMulDivAdd(false), HasMinMax(false),
  HasSwap(false), HasBitCount(false)
{
  std::string CPU = "mips1";
  MipsArchVersion = Mips1;

  // Parse features string.
  ParseSubtargetFeatures(FS, CPU);

  // Is the target system Linux ?
  if (TT.find("linux") == std::string::npos)
    IsLinux = false;

  // When only the target triple is specified and is 
  // a allegrex target, set the features. We also match
  // big and little endian allegrex cores (dont really
  // know if a big one exists)
  if (TT.find("mipsallegrex") != std::string::npos ||
      TT.find("psp") != std::string::npos) {
    MipsABI = EABI;
    IsSingleFloat = true;
    MipsArchVersion = Mips2;
    HasVFPU = true; // Enables Allegrex Vector FPU (not supported yet)
    HasSEInReg = true;
    HasBitCount = true;
    HasSwap = true;
    HasCondMov = true;
  }
}
