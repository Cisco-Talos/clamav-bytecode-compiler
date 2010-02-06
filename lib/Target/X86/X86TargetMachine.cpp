//===-- X86TargetMachine.cpp - Define TargetMachine for the X86 -----------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines the X86 specific subclass of TargetMachine.
//
//===----------------------------------------------------------------------===//

#include "X86MCAsmInfo.h"
#include "X86TargetMachine.h"
#include "X86.h"
#include "llvm/PassManager.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/Passes.h"
#include "llvm/Support/FormattedStream.h"
#include "llvm/Target/TargetOptions.h"
#include "llvm/Target/TargetRegistry.h"
using namespace llvm;

static const MCAsmInfo *createMCAsmInfo(const Target &T, StringRef TT) {
  Triple TheTriple(TT);
  switch (TheTriple.getOS()) {
  case Triple::Darwin:
    return new X86MCAsmInfoDarwin(TheTriple);
  case Triple::MinGW32:
  case Triple::MinGW64:
  case Triple::Cygwin:
    return new X86MCAsmInfoCOFF(TheTriple);
  case Triple::Win32:
    return new X86WinMCAsmInfo(TheTriple);
  default:
    return new X86ELFMCAsmInfo(TheTriple);
  }
}

extern "C" void LLVMInitializeX86Target() { 
  // Register the target.
  RegisterTargetMachine<X86_32TargetMachine> X(TheX86_32Target);
  RegisterTargetMachine<X86_64TargetMachine> Y(TheX86_64Target);

  // Register the target asm info.
  RegisterAsmInfoFn A(TheX86_32Target, createMCAsmInfo);
  RegisterAsmInfoFn B(TheX86_64Target, createMCAsmInfo);

  // Register the code emitter.
  // FIXME: Remove the heinous one when the new one works.
  TargetRegistry::RegisterCodeEmitter(TheX86_32Target,
                                      createHeinousX86MCCodeEmitter);
  TargetRegistry::RegisterCodeEmitter(TheX86_64Target,
                                      createHeinousX86MCCodeEmitter);
}


X86_32TargetMachine::X86_32TargetMachine(const Target &T, const std::string &TT,
                                         const std::string &FS)
  : X86TargetMachine(T, TT, FS, false) {
}


X86_64TargetMachine::X86_64TargetMachine(const Target &T, const std::string &TT,
                                         const std::string &FS)
  : X86TargetMachine(T, TT, FS, true) {
}

/// X86TargetMachine ctor - Create an X86 target.
///
X86TargetMachine::X86TargetMachine(const Target &T, const std::string &TT, 
                                   const std::string &FS, bool is64Bit)
  : LLVMTargetMachine(T, TT), 
    Subtarget(TT, FS, is64Bit),
    DataLayout(Subtarget.getDataLayout()),
    FrameInfo(TargetFrameInfo::StackGrowsDown,
              Subtarget.getStackAlignment(),
              (Subtarget.isTargetWin64() ? -40 :
               (Subtarget.is64Bit() ? -8 : -4))),
    InstrInfo(*this), JITInfo(*this), TLInfo(*this), ELFWriterInfo(*this) {
  DefRelocModel = getRelocationModel();
      
  // If no relocation model was picked, default as appropriate for the target.
  if (getRelocationModel() == Reloc::Default) {
    if (!Subtarget.isTargetDarwin())
      setRelocationModel(Reloc::Static);
    else if (Subtarget.is64Bit())
      setRelocationModel(Reloc::PIC_);
    else
      setRelocationModel(Reloc::DynamicNoPIC);
  }

  assert(getRelocationModel() != Reloc::Default &&
         "Relocation mode not picked");

  // ELF and X86-64 don't have a distinct DynamicNoPIC model.  DynamicNoPIC
  // is defined as a model for code which may be used in static or dynamic
  // executables but not necessarily a shared library. On X86-32 we just
  // compile in -static mode, in x86-64 we use PIC.
  if (getRelocationModel() == Reloc::DynamicNoPIC) {
    if (is64Bit)
      setRelocationModel(Reloc::PIC_);
    else if (!Subtarget.isTargetDarwin())
      setRelocationModel(Reloc::Static);
  }

  // If we are on Darwin, disallow static relocation model in X86-64 mode, since
  // the Mach-O file format doesn't support it.
  if (getRelocationModel() == Reloc::Static &&
      Subtarget.isTargetDarwin() &&
      is64Bit)
    setRelocationModel(Reloc::PIC_);
      
  // Determine the PICStyle based on the target selected.
  if (getRelocationModel() == Reloc::Static) {
    // Unless we're in PIC or DynamicNoPIC mode, set the PIC style to None.
    Subtarget.setPICStyle(PICStyles::None);
  } else if (Subtarget.isTargetCygMing()) {
    Subtarget.setPICStyle(PICStyles::None);
  } else if (Subtarget.isTargetDarwin()) {
    if (Subtarget.is64Bit())
      Subtarget.setPICStyle(PICStyles::RIPRel);
    else if (getRelocationModel() == Reloc::PIC_)
      Subtarget.setPICStyle(PICStyles::StubPIC);
    else {
      assert(getRelocationModel() == Reloc::DynamicNoPIC);
      Subtarget.setPICStyle(PICStyles::StubDynamicNoPIC);
    }
  } else if (Subtarget.isTargetELF()) {
    if (Subtarget.is64Bit())
      Subtarget.setPICStyle(PICStyles::RIPRel);
    else
      Subtarget.setPICStyle(PICStyles::GOT);
  }
      
  // Finally, if we have "none" as our PIC style, force to static mode.
  if (Subtarget.getPICStyle() == PICStyles::None)
    setRelocationModel(Reloc::Static);
}

//===----------------------------------------------------------------------===//
// Pass Pipeline Configuration
//===----------------------------------------------------------------------===//

bool X86TargetMachine::addInstSelector(PassManagerBase &PM,
                                       CodeGenOpt::Level OptLevel) {
  // Install an instruction selector.
  PM.add(createX86ISelDag(*this, OptLevel));

  // Install a pass to insert x87 FP_REG_KILL instructions, as needed.
  PM.add(createX87FPRegKillInserterPass());

  return false;
}

bool X86TargetMachine::addPreRegAlloc(PassManagerBase &PM,
                                      CodeGenOpt::Level OptLevel) {
  return false;  // -print-machineinstr shouldn't print after this.
}

bool X86TargetMachine::addPostRegAlloc(PassManagerBase &PM,
                                       CodeGenOpt::Level OptLevel) {
  PM.add(createX86FloatingPointStackifierPass());
  return true;  // -print-machineinstr should print after this.
}

bool X86TargetMachine::addCodeEmitter(PassManagerBase &PM,
                                      CodeGenOpt::Level OptLevel,
                                      JITCodeEmitter &JCE) {
  // FIXME: Move this to TargetJITInfo!
  // On Darwin, do not override 64-bit setting made in X86TargetMachine().
  if (DefRelocModel == Reloc::Default && 
      (!Subtarget.isTargetDarwin() || !Subtarget.is64Bit())) {
    setRelocationModel(Reloc::Static);
    Subtarget.setPICStyle(PICStyles::None);
  }
  

  PM.add(createX86JITCodeEmitterPass(*this, JCE));

  return false;
}

void X86TargetMachine::setCodeModelForStatic() {

    if (getCodeModel() != CodeModel::Default) return;

    // For static codegen, if we're not already set, use Small codegen.
    setCodeModel(CodeModel::Small);
}


void X86TargetMachine::setCodeModelForJIT() {

  if (getCodeModel() != CodeModel::Default) return;

  // 64-bit JIT places everything in the same buffer except external functions.
  if (Subtarget.is64Bit())
    setCodeModel(CodeModel::Large);
  else
    setCodeModel(CodeModel::Small);
}

/// getLSDAEncoding - Returns the LSDA pointer encoding. The choices are 4-byte,
/// 8-byte, and target default. The CIE is hard-coded to indicate that the LSDA
/// pointer in the FDE section is an "sdata4", and should be encoded as a 4-byte
/// pointer by default. However, some systems may require a different size due
/// to bugs or other conditions. We will default to a 4-byte encoding unless the
/// system tells us otherwise.
///
/// The issue is when the CIE says their is an LSDA. That mandates that every
/// FDE have an LSDA slot. But if the function does not need an LSDA. There
/// needs to be some way to signify there is none. The LSDA is encoded as
/// pc-rel. But you don't look for some magic value after adding the pc. You
/// have to look for a zero before adding the pc. The problem is that the size
/// of the zero to look for depends on the encoding. The unwinder bug in SL is
/// that it always checks for a pointer-size zero. So on x86_64 it looks for 8
/// bytes of zero. If you have an LSDA, it works fine since the 8-bytes are
/// non-zero so it goes ahead and then reads the value based on the encoding.
/// But if you use sdata4 and there is no LSDA, then the test for zero gives a
/// false negative and the unwinder thinks there is an LSDA.
///
/// FIXME: This call-back isn't good! We should be using the correct encoding
/// regardless of the system. However, there are some systems which have bugs
/// that prevent this from occuring.
DwarfLSDAEncoding::Encoding X86TargetMachine::getLSDAEncoding() const {
  if (Subtarget.isTargetDarwin() && Subtarget.getDarwinVers() != 10)
    return DwarfLSDAEncoding::Default;

  return DwarfLSDAEncoding::EightByte;
}
