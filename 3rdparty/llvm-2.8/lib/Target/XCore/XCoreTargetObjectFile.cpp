//===-- XCoreTargetObjectFile.cpp - XCore object files --------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "XCoreTargetObjectFile.h"
#include "XCoreSubtarget.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCSectionELF.h"
#include "llvm/Target/TargetMachine.h"
using namespace llvm;


void XCoreTargetObjectFile::Initialize(MCContext &Ctx, const TargetMachine &TM){
  TargetLoweringObjectFileELF::Initialize(Ctx, TM);

  DataSection =
    Ctx.getELFSection(".dp.data", MCSectionELF::SHT_PROGBITS, 
                      MCSectionELF::SHF_ALLOC | MCSectionELF::SHF_WRITE |
                      MCSectionELF::XCORE_SHF_DP_SECTION,
                      SectionKind::getDataRel(), false);
  BSSSection =
    Ctx.getELFSection(".dp.bss", MCSectionELF::SHT_NOBITS,
                      MCSectionELF::SHF_ALLOC | MCSectionELF::SHF_WRITE |
                      MCSectionELF::XCORE_SHF_DP_SECTION,
                      SectionKind::getBSS(), false);
  
  MergeableConst4Section = 
    Ctx.getELFSection(".cp.rodata.cst4", MCSectionELF::SHT_PROGBITS,
                      MCSectionELF::SHF_ALLOC | MCSectionELF::SHF_MERGE |
                      MCSectionELF::XCORE_SHF_CP_SECTION,
                      SectionKind::getMergeableConst4(), false);
  MergeableConst8Section = 
    Ctx.getELFSection(".cp.rodata.cst8", MCSectionELF::SHT_PROGBITS,
                      MCSectionELF::SHF_ALLOC | MCSectionELF::SHF_MERGE |
                      MCSectionELF::XCORE_SHF_CP_SECTION,
                      SectionKind::getMergeableConst8(), false);
  MergeableConst16Section = 
    Ctx.getELFSection(".cp.rodata.cst16", MCSectionELF::SHT_PROGBITS,
                      MCSectionELF::SHF_ALLOC | MCSectionELF::SHF_MERGE |
                      MCSectionELF::XCORE_SHF_CP_SECTION,
                      SectionKind::getMergeableConst16(), false);
  
  // TLS globals are lowered in the backend to arrays indexed by the current
  // thread id. After lowering they require no special handling by the linker
  // and can be placed in the standard data / bss sections.
  TLSDataSection = DataSection;
  TLSBSSSection = BSSSection;

  ReadOnlySection = 
    Ctx.getELFSection(".cp.rodata", MCSectionELF::SHT_PROGBITS,
                      MCSectionELF::SHF_ALLOC |
                      MCSectionELF::XCORE_SHF_CP_SECTION,
                      SectionKind::getReadOnlyWithRel(), false);

  // Dynamic linking is not supported. Data with relocations is placed in the
  // same section as data without relocations.
  DataRelSection = DataRelLocalSection = DataSection;
  DataRelROSection = DataRelROLocalSection = ReadOnlySection;
}
