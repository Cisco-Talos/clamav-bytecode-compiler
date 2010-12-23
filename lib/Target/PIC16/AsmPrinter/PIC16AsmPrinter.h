//===-- PIC16AsmPrinter.h - PIC16 LLVM assembly writer ----------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains a printer that converts from our internal representation
// of machine-dependent LLVM code to PIC16 assembly language.
//
//===----------------------------------------------------------------------===//

#ifndef PIC16ASMPRINTER_H
#define PIC16ASMPRINTER_H

#include "PIC16.h"
#include "PIC16TargetMachine.h"
#include "PIC16DebugInfo.h"
#include "PIC16MCAsmInfo.h"
#include "PIC16TargetObjectFile.h"
#include "llvm/Analysis/DebugInfo.h"
#include "llvm/CodeGen/AsmPrinter.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Target/TargetMachine.h"
#include <list>
#include <set>
#include <string>

namespace llvm {
  class LLVM_LIBRARY_VISIBILITY PIC16AsmPrinter : public AsmPrinter {
  public:
    explicit PIC16AsmPrinter(TargetMachine &TM, MCStreamer &Streamer);
  private:
    virtual const char *getPassName() const {
      return "PIC16 Assembly Printer";
    }
    
    const PIC16TargetObjectFile &getObjFileLowering() const {
      return (const PIC16TargetObjectFile &)AsmPrinter::getObjFileLowering();
    }

    bool runOnMachineFunction(MachineFunction &F);
    void printOperand(const MachineInstr *MI, int opNum, raw_ostream &O);
    void printCCOperand(const MachineInstr *MI, int opNum, raw_ostream &O);
    void printInstruction(const MachineInstr *MI, raw_ostream &O);
    static const char *getRegisterName(unsigned RegNo);

    void EmitInstruction(const MachineInstr *MI);
    void EmitFunctionDecls (Module &M);
    void EmitUndefinedVars (Module &M);
    void EmitDefinedVars (Module &M);
    void EmitIData (Module &M);
    void EmitUData (Module &M);
    void EmitAllAutos (Module &M);
    void EmitRomData (Module &M);
    void EmitSharedUdata(Module &M);
    void EmitUserSections (Module &M);
    void EmitFunctionFrame(MachineFunction &MF);
    void printLibcallDecls();
    void EmitUninitializedDataSection(const PIC16Section *S);
    void EmitInitializedDataSection(const PIC16Section *S);
    void EmitSingleSection(const PIC16Section *S);
    void EmitSectionList(Module &M, 
                         const std::vector< PIC16Section *> &SList);
    void ColorAutoSection(const Function *F);
  protected:
    bool doInitialization(Module &M);
    bool doFinalization(Module &M);

    /// EmitGlobalVariable - Emit the specified global variable and its
    /// initializer to the output stream.
    virtual void EmitGlobalVariable(const GlobalVariable *GV) {
      // PIC16 doesn't use normal hooks for this.
    }
    
  private:
    const PIC16TargetObjectFile *PTOF;
    PIC16DbgInfo DbgInfo;
    const PIC16MCAsmInfo *PMAI;
    std::set<std::string> LibcallDecls; // Sorted & uniqued set of extern decls.
    std::vector<const GlobalVariable *> ExternalVarDecls;
    std::vector<const GlobalVariable *> ExternalVarDefs;
  };
} // end of namespace

#endif
