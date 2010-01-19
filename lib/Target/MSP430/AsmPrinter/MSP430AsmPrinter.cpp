//===-- MSP430AsmPrinter.cpp - MSP430 LLVM assembly writer ----------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains a printer that converts from our internal representation
// of machine-dependent LLVM code to the MSP430 assembly language.
//
//===----------------------------------------------------------------------===//

#define DEBUG_TYPE "asm-printer"
#include "MSP430.h"
#include "MSP430InstrInfo.h"
#include "MSP430InstPrinter.h"
#include "MSP430MCAsmInfo.h"
#include "MSP430MCInstLower.h"
#include "MSP430TargetMachine.h"
#include "llvm/Constants.h"
#include "llvm/DerivedTypes.h"
#include "llvm/Module.h"
#include "llvm/Assembly/Writer.h"
#include "llvm/CodeGen/AsmPrinter.h"
#include "llvm/CodeGen/DwarfWriter.h"
#include "llvm/CodeGen/MachineModuleInfo.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineConstantPool.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCStreamer.h"
#include "llvm/MC/MCSymbol.h"
#include "llvm/Target/TargetData.h"
#include "llvm/Target/TargetLoweringObjectFile.h"
#include "llvm/Target/TargetRegistry.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FormattedStream.h"
#include "llvm/Support/ErrorHandling.h"
using namespace llvm;

STATISTIC(EmittedInsts, "Number of machine instrs printed");

static cl::opt<bool>
EnableMCInst("enable-msp430-mcinst-printer", cl::Hidden,
             cl::desc("enable experimental mcinst gunk in the msp430 backend"));

namespace {
  class MSP430AsmPrinter : public AsmPrinter {
  public:
    MSP430AsmPrinter(formatted_raw_ostream &O, TargetMachine &TM,
                     const MCAsmInfo *MAI, bool V)
      : AsmPrinter(O, TM, MAI, V) {}

    virtual const char *getPassName() const {
      return "MSP430 Assembly Printer";
    }

    void printMCInst(const MCInst *MI) {
      MSP430InstPrinter(O, *MAI).printInstruction(MI);
    }
    void printOperand(const MachineInstr *MI, int OpNum,
                      const char* Modifier = 0);
    void printPCRelImmOperand(const MachineInstr *MI, int OpNum) {
      printOperand(MI, OpNum);
    }
    void printSrcMemOperand(const MachineInstr *MI, int OpNum,
                            const char* Modifier = 0);
    void printCCOperand(const MachineInstr *MI, int OpNum);
    void printMachineInstruction(const MachineInstr * MI);
    bool PrintAsmOperand(const MachineInstr *MI, unsigned OpNo,
                         unsigned AsmVariant,
                         const char *ExtraCode);
    bool PrintAsmMemoryOperand(const MachineInstr *MI,
                               unsigned OpNo, unsigned AsmVariant,
                               const char *ExtraCode);
    void printInstructionThroughMCStreamer(const MachineInstr *MI);

    void emitFunctionHeader(const MachineFunction &MF);
    bool runOnMachineFunction(MachineFunction &F);

    void getAnalysisUsage(AnalysisUsage &AU) const {
      AsmPrinter::getAnalysisUsage(AU);
      AU.setPreservesAll();
    }
  };
} // end of anonymous namespace


void MSP430AsmPrinter::emitFunctionHeader(const MachineFunction &MF) {
  const Function *F = MF.getFunction();

  OutStreamer.SwitchSection(getObjFileLowering().SectionForGlobal(F, Mang, TM));

  unsigned FnAlign = MF.getAlignment();
  EmitAlignment(FnAlign, F);

  switch (F->getLinkage()) {
  default: llvm_unreachable("Unknown linkage type!");
  case Function::InternalLinkage:  // Symbols default to internal.
  case Function::PrivateLinkage:
  case Function::LinkerPrivateLinkage:
    break;
  case Function::ExternalLinkage:
    O << "\t.globl\t" << *CurrentFnSym << '\n';
    break;
  case Function::LinkOnceAnyLinkage:
  case Function::LinkOnceODRLinkage:
  case Function::WeakAnyLinkage:
  case Function::WeakODRLinkage:
    O << "\t.weak\t" << *CurrentFnSym << '\n';
    break;
  }

  printVisibility(CurrentFnSym, F->getVisibility());

  O << "\t.type\t" << *CurrentFnSym << ",@function\n";
  O << *CurrentFnSym << ":\n";
}

bool MSP430AsmPrinter::runOnMachineFunction(MachineFunction &MF) {
  SetupMachineFunction(MF);
  O << "\n\n";

  // Print the 'header' of function
  emitFunctionHeader(MF);

  // Print out code for the function.
  for (MachineFunction::const_iterator I = MF.begin(), E = MF.end();
       I != E; ++I) {
    // Print a label for the basic block.
    EmitBasicBlockStart(I);

    for (MachineBasicBlock::const_iterator II = I->begin(), E = I->end();
         II != E; ++II)
      // Print the assembly for the instruction.
      printMachineInstruction(II);
  }

  if (MAI->hasDotTypeDotSizeDirective())
    O << "\t.size\t" << *CurrentFnSym << ", .-" << *CurrentFnSym << '\n';

  // We didn't modify anything
  return false;
}

void MSP430AsmPrinter::printMachineInstruction(const MachineInstr *MI) {
  ++EmittedInsts;

  processDebugLoc(MI, true);

  printInstructionThroughMCStreamer(MI);

  if (VerboseAsm)
    EmitComments(*MI);
  O << '\n';

  processDebugLoc(MI, false);
}

void MSP430AsmPrinter::printOperand(const MachineInstr *MI, int OpNum,
                                    const char* Modifier) {
  const MachineOperand &MO = MI->getOperand(OpNum);
  switch (MO.getType()) {
  case MachineOperand::MO_Register:
    O << MSP430InstPrinter::getRegisterName(MO.getReg());
    return;
  case MachineOperand::MO_Immediate:
    if (!Modifier || strcmp(Modifier, "nohash"))
      O << '#';
    O << MO.getImm();
    return;
  case MachineOperand::MO_MachineBasicBlock:
    O << *GetMBBSymbol(MO.getMBB()->getNumber());
    return;
  case MachineOperand::MO_GlobalAddress: {
    bool isMemOp  = Modifier && !strcmp(Modifier, "mem");
    uint64_t Offset = MO.getOffset();

    O << (isMemOp ? '&' : '#');
    if (Offset)
      O << '(' << Offset << '+';

    O << *GetGlobalValueSymbol(MO.getGlobal());
    
    if (Offset)
      O << ')';

    return;
  }
  case MachineOperand::MO_ExternalSymbol: {
    bool isMemOp  = Modifier && !strcmp(Modifier, "mem");
    O << (isMemOp ? '&' : '#');
    O << MAI->getGlobalPrefix() << MO.getSymbolName();
    return;
  }
  default:
    llvm_unreachable("Not implemented yet!");
  }
}

void MSP430AsmPrinter::printSrcMemOperand(const MachineInstr *MI, int OpNum,
                                          const char* Modifier) {
  const MachineOperand &Base = MI->getOperand(OpNum);
  const MachineOperand &Disp = MI->getOperand(OpNum+1);

  // Print displacement first
  if (!Disp.isImm()) {
    printOperand(MI, OpNum+1, "mem");
  } else {
    if (!Base.getReg())
      O << '&';

    printOperand(MI, OpNum+1, "nohash");
  }


  // Print register base field
  if (Base.getReg()) {
    O << '(';
    printOperand(MI, OpNum);
    O << ')';
  }
}

void MSP430AsmPrinter::printCCOperand(const MachineInstr *MI, int OpNum) {
  unsigned CC = MI->getOperand(OpNum).getImm();

  switch (CC) {
  default:
   llvm_unreachable("Unsupported CC code");
   break;
  case MSP430CC::COND_E:
   O << "eq";
   break;
  case MSP430CC::COND_NE:
   O << "ne";
   break;
  case MSP430CC::COND_HS:
   O << "hs";
   break;
  case MSP430CC::COND_LO:
   O << "lo";
   break;
  case MSP430CC::COND_GE:
   O << "ge";
   break;
  case MSP430CC::COND_L:
   O << 'l';
   break;
  }
}

/// PrintAsmOperand - Print out an operand for an inline asm expression.
///
bool MSP430AsmPrinter::PrintAsmOperand(const MachineInstr *MI, unsigned OpNo,
                                       unsigned AsmVariant,
                                       const char *ExtraCode) {
  // Does this asm operand have a single letter operand modifier?
  if (ExtraCode && ExtraCode[0])
    return true; // Unknown modifier.

  printOperand(MI, OpNo);
  return false;
}

bool MSP430AsmPrinter::PrintAsmMemoryOperand(const MachineInstr *MI,
                                             unsigned OpNo, unsigned AsmVariant,
                                             const char *ExtraCode) {
  if (ExtraCode && ExtraCode[0]) {
    return true; // Unknown modifier.
  }
  printSrcMemOperand(MI, OpNo);
  return false;
}

//===----------------------------------------------------------------------===//
void MSP430AsmPrinter::printInstructionThroughMCStreamer(const MachineInstr *MI){

  MSP430MCInstLower MCInstLowering(OutContext, *Mang, *this);

  switch (MI->getOpcode()) {
  case TargetInstrInfo::DBG_LABEL:
  case TargetInstrInfo::EH_LABEL:
  case TargetInstrInfo::GC_LABEL:
    printLabel(MI);
    return;
  case TargetInstrInfo::KILL:
    printKill(MI);
    return;
  case TargetInstrInfo::INLINEASM:
    printInlineAsm(MI);
    return;
  case TargetInstrInfo::IMPLICIT_DEF:
    printImplicitDef(MI);
    return;
  default: break;
  }

  MCInst TmpInst;
  MCInstLowering.Lower(MI, TmpInst);

  printMCInst(&TmpInst);
}

static MCInstPrinter *createMSP430MCInstPrinter(const Target &T,
                                                unsigned SyntaxVariant,
                                                const MCAsmInfo &MAI,
                                                raw_ostream &O) {
  if (SyntaxVariant == 0)
    return new MSP430InstPrinter(O, MAI);
  return 0;
}

// Force static initialization.
extern "C" void LLVMInitializeMSP430AsmPrinter() {
  RegisterAsmPrinter<MSP430AsmPrinter> X(TheMSP430Target);
  TargetRegistry::RegisterMCInstPrinter(TheMSP430Target,
                                        createMSP430MCInstPrinter);
}
