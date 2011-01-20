//===- SystemZSubtarget.cpp - SystemZ Subtarget Information -------*- C++ -*-=//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements the SystemZ specific subclass of TargetSubtarget.
//
//===----------------------------------------------------------------------===//

#include "SystemZSubtarget.h"
#include "SystemZ.h"
#include "SystemZGenSubtarget.inc"
#include "llvm/GlobalValue.h"
#include "llvm/Target/TargetMachine.h"

using namespace llvm;

SystemZSubtarget::SystemZSubtarget(const std::string &TT, 
                                   const std::string &FS):
  HasZ10Insts(false) {
  std::string CPU = "z9";

  // Parse features string.
  ParseSubtargetFeatures(FS, CPU);
}

/// True if accessing the GV requires an extra load.
bool SystemZSubtarget::GVRequiresExtraLoad(const GlobalValue* GV,
                                           const TargetMachine& TM,
                                           bool isDirectCall) const {
  if (TM.getRelocationModel() == Reloc::PIC_) {
    // Extra load is needed for all externally visible.
    if (isDirectCall)
      return false;

    if (GV->hasLocalLinkage() || GV->hasHiddenVisibility())
      return false;

    return true;
  }

  return false;
}
