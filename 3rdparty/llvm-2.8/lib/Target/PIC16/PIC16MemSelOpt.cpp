//===-- PIC16MemSelOpt.cpp - PIC16 banksel optimizer  --------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines the pass which optimizes the emitting of banksel 
// instructions before accessing data memory. This currently works within
// a basic block only and keep tracks of the last accessed memory bank.
// If memory access continues to be in the same bank it just makes banksel
// immediate, which is a part of the insn accessing the data memory, from 1
// to zero. The asm printer emits a banksel only if that immediate is 1. 
//
// FIXME: this is not implemented yet.  The banksel pass only works on local
// basic blocks.
//
//===----------------------------------------------------------------------===//

#define DEBUG_TYPE "pic16-codegen"
#include "PIC16.h"
#include "PIC16ABINames.h"
#include "PIC16InstrInfo.h"
#include "PIC16MCAsmInfo.h"
#include "PIC16TargetMachine.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/Passes.h"
#include "llvm/Target/TargetInstrInfo.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/GlobalValue.h"
#include "llvm/DerivedTypes.h"

using namespace llvm;

namespace {
  struct MemSelOpt : public MachineFunctionPass {
    static char ID;
    MemSelOpt() : MachineFunctionPass(ID) {}

    virtual void getAnalysisUsage(AnalysisUsage &AU) const {
      AU.addPreservedID(MachineLoopInfoID);
      AU.addPreservedID(MachineDominatorsID);
      MachineFunctionPass::getAnalysisUsage(AU);
    }

    virtual bool runOnMachineFunction(MachineFunction &MF);

    virtual const char *getPassName() const { 
      return "PIC16 Memsel Optimizer"; 
    }

   bool processBasicBlock(MachineFunction &MF, MachineBasicBlock &MBB);
   bool processInstruction(MachineInstr *MI);

  private:
    const TargetInstrInfo *TII; // Machine instruction info.
    MachineBasicBlock *MBB;     // Current basic block
    std::string CurBank;
    int PageChanged;

  };
  char MemSelOpt::ID = 0;
}

FunctionPass *llvm::createPIC16MemSelOptimizerPass() { 
  return new MemSelOpt(); 
}


/// runOnMachineFunction - Loop over all of the basic blocks, transforming FP
/// register references into FP stack references.
///
bool MemSelOpt::runOnMachineFunction(MachineFunction &MF) {
  TII = MF.getTarget().getInstrInfo();
  bool Changed = false;
  for (MachineFunction::iterator I = MF.begin(), E = MF.end();
       I != E; ++I) {
    Changed |= processBasicBlock(MF, *I);
  }

  return Changed;
}

/// processBasicBlock - Loop over all of the instructions in the basic block,
/// transforming FP instructions into their stack form.
///
bool MemSelOpt::processBasicBlock(MachineFunction &MF, MachineBasicBlock &BB) {
  bool Changed = false;
  MBB = &BB;

  // Let us assume that when entering a basic block now bank is selected.
  // Ideally we should look at the predecessors for this information.
  CurBank=""; 
  PageChanged=0;

  MachineBasicBlock::iterator I;
  for (I = BB.begin(); I != BB.end(); ++I) {
    Changed |= processInstruction(I);

    // if the page has changed insert a page sel before 
    // any instruction that needs one
    if (PageChanged == 1)
    {
      // Restore the page if it was changed, before leaving the basic block,
      // because it may be required by the goto terminator or the fall thru
      // basic blcok.
      // If the terminator is return, we don't need to restore since there
      // is no goto or fall thru basic block.
      if ((I->getOpcode() == PIC16::sublw_3) || //macro has goto
          (I->getOpcode() == PIC16::sublw_6) || //macro has goto
          (I->getOpcode() == PIC16::addlwc)  || //macro has goto
          (TII->get(I->getOpcode()).isBranch()))
      {
        DebugLoc dl = I->getDebugLoc();
        BuildMI(*MBB, I, dl, TII->get(PIC16::pagesel)).addExternalSymbol("$");
        Changed = true;
        PageChanged = 0;            
      }
    }
  }

   // The basic block is over, but if we did not find any goto yet,
   // we haven't restored the page.
   // Restore the page if it was changed, before leaving the basic block,
   // because it may be required by fall thru basic blcok.
   // If the terminator is return, we don't need to restore since there
   // is fall thru basic block.
   if (PageChanged == 1) {
      // save the end pointer before we move back to last insn.
     MachineBasicBlock::iterator J = I;
     I--;
     const TargetInstrDesc &TID = TII->get(I->getOpcode());
     if (! TID.isReturn())
     {
       DebugLoc dl = I->getDebugLoc();
       BuildMI(*MBB, J, dl, 
               TII->get(PIC16::pagesel)).addExternalSymbol("$");
       Changed = true;
       PageChanged = 0;
     }
   }


  return Changed;
}

bool MemSelOpt::processInstruction(MachineInstr *MI) {
  bool Changed = false;

  unsigned NumOperands = MI->getNumOperands();
  if (NumOperands == 0) return false;


  // If this insn is not going to access any memory, return.
  const TargetInstrDesc &TID = TII->get(MI->getOpcode());
  if (!(TID.isBranch() || TID.isCall() || TID.mayLoad() || TID.mayStore()))
    return false;

  // The first thing we should do is that record if banksel/pagesel are
  // changed in an unknown way. This can happend via any type of call. 
  // We do it here first before scanning of MemOp / BBOp as the indirect
  // call insns do not have any operands, but they still may change bank/page.
  if (TID.isCall()) {
    // Record that we have changed the page, so that we can restore it
    // before basic block ends.
    // We require to signal that a page anc bank change happened even for
    // indirect calls. 
    PageChanged = 1;

    // When a call is made, there may be banksel for variables in callee.
    // Hence the banksel in caller needs to be reset.
    CurBank = "";
  }

  // Scan for the memory address operand.
  // FIXME: Should we use standard interfaces like memoperands_iterator,
  // hasMemOperand() etc ?
  int MemOpPos = -1;
  int BBOpPos = -1;
  for (unsigned i = 0; i < NumOperands; i++) {
    MachineOperand Op = MI->getOperand(i);
    if (Op.getType() ==  MachineOperand::MO_GlobalAddress ||
        Op.getType() ==  MachineOperand::MO_ExternalSymbol) { 
      // We found one mem operand. Next one may be BS.
      MemOpPos = i;
    }
    if (Op.getType() ==  MachineOperand::MO_MachineBasicBlock) {
      // We found one BB operand. Next one may be pagesel.
      BBOpPos = i;
    }
  }

  // If we did not find an insn accessing memory. Continue.
  if ((MemOpPos == -1) &&
      (BBOpPos == -1))
    return false;
  assert ((BBOpPos != MemOpPos) && "operand can only be of one type");
 

  // If this is a pagesel material, handle it first.
  // CALL and br_ucond insns use MemOp (GA or ES) and not BBOp.
  // Pagesel is required only for a direct call.
  if ((MI->getOpcode() == PIC16::CALL)) {
    // Get the BBOp.
    MachineOperand &MemOp = MI->getOperand(MemOpPos);
    DebugLoc dl = MI->getDebugLoc();
    BuildMI(*MBB, MI, dl, TII->get(PIC16::pagesel)).addOperand(MemOp);   

    // CALL and br_ucond needs only pagesel. so we are done.
    return true; 
  }

  // Pagesel is handled. Now, add a Banksel if needed.
  if (MemOpPos == -1) return Changed;
  // Get the MemOp.
  MachineOperand &Op = MI->getOperand(MemOpPos);

  // Get the section name(NewBank) for MemOp.
  // This assumes that the section names for globals are already set by
  // AsmPrinter->doInitialization.
  std::string NewBank = CurBank;
  bool hasExternalLinkage = false;
  if (Op.getType() ==  MachineOperand::MO_GlobalAddress &&
      Op.getGlobal()->getType()->getAddressSpace() == PIC16ISD::RAM_SPACE) {
    if (Op.getGlobal()->hasExternalLinkage())
      hasExternalLinkage= true;
    NewBank = Op.getGlobal()->getSection();
  } else if (Op.getType() ==  MachineOperand::MO_ExternalSymbol) {
    // External Symbol is generated for temp data and arguments. They are
    // in fpdata.<functionname>.# section.
    std::string Sym = Op.getSymbolName();
    NewBank = PAN::getSectionNameForSym(Sym);
  }

  // If the section is shared section, do not emit banksel.
  if (NewBank == PAN::getSharedUDataSectionName())
    return Changed;

  // If the previous and new section names are same, we don't need to
  // emit banksel. 
  if (NewBank.compare(CurBank) != 0 || hasExternalLinkage) {
    DebugLoc dl = MI->getDebugLoc();
    BuildMI(*MBB, MI, dl, TII->get(PIC16::banksel)).
      addOperand(Op);
    Changed = true;
    CurBank = NewBank;
  }

  return Changed;
}

