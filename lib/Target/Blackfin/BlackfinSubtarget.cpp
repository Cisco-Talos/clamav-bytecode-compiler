//===- BlackfinSubtarget.cpp - BLACKFIN Subtarget Information -------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements the blackfin specific subclass of TargetSubtarget.
//
//===----------------------------------------------------------------------===//

#include "BlackfinSubtarget.h"
#include "BlackfinGenSubtarget.inc"

using namespace llvm;

BlackfinSubtarget::BlackfinSubtarget(const std::string &TT,
                                     const std::string &FS)
  : sdram(false),
    icplb(false),
    wa_mi_shift(false),
    wa_csync(false),
    wa_specld(false),
    wa_mmr_stall(false),
    wa_lcregs(false),
    wa_hwloop(false),
    wa_ind_call(false),
    wa_killed_mmr(false),
    wa_rets(false)
{
  std::string CPU = "generic";
  // Parse features string.
  ParseSubtargetFeatures(FS, CPU);
}
