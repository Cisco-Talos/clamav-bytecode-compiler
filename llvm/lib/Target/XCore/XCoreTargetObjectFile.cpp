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
#include "MCSectionXCore.h"
#include "llvm/Target/TargetMachine.h"
using namespace llvm;


void XCoreTargetObjectFile::Initialize(MCContext &Ctx, const TargetMachine &TM){
  TargetLoweringObjectFileELF::Initialize(Ctx, TM);

  DataSection =
    MCSectionXCore::Create(".dp.data", MCSectionELF::SHT_PROGBITS, 
                           MCSectionELF::SHF_ALLOC | MCSectionELF::SHF_WRITE |
                           MCSectionXCore::SHF_DP_SECTION,
                           SectionKind::getDataRel(), false, getContext());
  BSSSection =
    MCSectionXCore::Create(".dp.bss", MCSectionELF::SHT_NOBITS,
                           MCSectionELF::SHF_ALLOC | MCSectionELF::SHF_WRITE |
                           MCSectionXCore::SHF_DP_SECTION,
                           SectionKind::getBSS(), false, getContext());
  
  MergeableConst4Section = 
    MCSectionXCore::Create(".cp.rodata.cst4", MCSectionELF::SHT_PROGBITS,
                           MCSectionELF::SHF_ALLOC | MCSectionELF::SHF_MERGE |
                           MCSectionXCore::SHF_CP_SECTION,
                           SectionKind::getMergeableConst4(), false,
                           getContext());
  MergeableConst8Section = 
    MCSectionXCore::Create(".cp.rodata.cst8", MCSectionELF::SHT_PROGBITS,
                           MCSectionELF::SHF_ALLOC | MCSectionELF::SHF_MERGE |
                           MCSectionXCore::SHF_CP_SECTION,
                           SectionKind::getMergeableConst8(), false,
                           getContext());
  MergeableConst16Section = 
    MCSectionXCore::Create(".cp.rodata.cst16", MCSectionELF::SHT_PROGBITS,
                           MCSectionELF::SHF_ALLOC | MCSectionELF::SHF_MERGE |
                           MCSectionXCore::SHF_CP_SECTION,
                           SectionKind::getMergeableConst16(), false,
                           getContext());
  
  // TLS globals are lowered in the backend to arrays indexed by the current
  // thread id. After lowering they require no special handling by the linker
  // and can be placed in the standard data / bss sections.
  TLSDataSection = DataSection;
  TLSBSSSection = BSSSection;

  ReadOnlySection = 
    MCSectionXCore::Create(".cp.rodata", MCSectionELF::SHT_PROGBITS,
                           MCSectionELF::SHF_ALLOC |
                           MCSectionXCore::SHF_CP_SECTION,
                           SectionKind::getReadOnlyWithRel(), false,
                           getContext());

  // Dynamic linking is not supported. Data with relocations is placed in the
  // same section as data without relocations.
  DataRelSection = DataRelLocalSection = DataSection;
  DataRelROSection = DataRelROLocalSection = ReadOnlySection;
}
