/*
 *  Compile LLVM bytecode to ClamAV bytecode.
 *
 *  Copyright (C) 2009-2010 Sourcefire, Inc.
 *
 *  Authors: Török Edvin
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */

/*
 * aragusa: 
 * I haven't looked into everything this pass does, but one thing I have found is that it inserts run-time bounds
 * checking for pointers.  What it does is look at the access to a pointer, and insert a check for if that will
 * access too much memory.  If it would, it jumps to an "AbortBB", a basic block that calls abort.  One potential
 * improvement, would be to look at all the calls ahead of time and only have a check for the highest access, not
 * every access.  Instruction combining doesn't do a great job of fixing those up.
 *
 * There are cases where the IR would look like the following pseudocode.
 *
 * if (idx < 67){
 *   if (idx < 70) {
 *    do stuff ...
 *   } else {
 *    call abort
 *   }
 * } else {
 *   call abort
 * }
 */


#include "Common/ClamBCDiagnostics.h"
#include "Common/ClamBCModule.h"
#include "Common/clambc.h"
#include "Common/ClamBCUtilities.h"




#include <llvm/Pass.h>
#include <llvm/IR/Function.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Passes/PassPlugin.h>

//#include <llvm/IR/LegacyPassManager.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>


#include <llvm/IR/Verifier.h>
#include <llvm/IR/Dominators.h>
#include <llvm/Analysis/ConstantFolding.h>
#include <llvm/Analysis/ScalarEvolution.h>
#include <llvm/Analysis/ScalarEvolutionExpressions.h>
#include <llvm/Transforms/Utils/ScalarEvolutionExpander.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/Intrinsics.h>
#include <llvm/IR/Module.h>
#include <llvm/Pass.h>
#include "llvm/Support/CommandLine.h"
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/InstVisitor.h>
#include <llvm/IR/GetElementPtrTypeIterator.h>
#include <llvm/ADT/DepthFirstIterator.h>
#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Utils/BasicBlockUtils.h>
#include <llvm/IR/InstrTypes.h>

#include <llvm/ADT/SmallSet.h>


#include <llvm/IR/PassManager.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/PassPlugin.h>
#include <llvm/Support/raw_ostream.h>

#include <llvm/IR/Dominators.h>

#include <llvm/Transforms/IPO/PassManagerBuilder.h>





using namespace llvm;

#if 0
static cl::opt<bool>
    StopOnFirstError("clambc-stopfirst", cl::init(false),
                     cl::desc("Stop on first error in the verifier"));
#else
static bool StopOnFirstError = true;
#endif

namespace ClamBCVerifier
{
class ClamBCVerifier : public PassInfoMixin<ClamBCVerifier >,
                       public InstVisitor<ClamBCVerifier, bool>
{

    ScalarEvolution *SE;
    DominatorTree *DT;
    BasicBlock *AbrtBB;
    bool Final;
    llvm::Module *pMod = nullptr;

    friend class InstVisitor<ClamBCVerifier, bool>;

    bool visitUnreachableInst(UnreachableInst &I)
    {
        return true;
    }

    bool visitAllocaInst(AllocaInst &I)
    {
        return true;
    }
    bool visitCastInst(CastInst &I)
    {
        return true;
    }
    bool visitSelectInst(SelectInst &I)
    {
        return true;
    }
    bool visitBranchInst(BranchInst &BI)
    {
        return true;
    }
    bool visitSwitchInst(SwitchInst &I)
    {
        printDiagnostic("Need to lower switchInst's to branches", &I);
        return false;
    }
    bool visitBinaryOperator(Instruction &I)
    {
        return true;
    }
    bool visitReturnInst(ReturnInst &I)
    {
        return true;
    }
    bool visitICmpInst(ICmpInst &I)
    {
        return true;
    }

    bool visitInstruction(Instruction &I)
    {
        printDiagnostic("Unhandled instruction in verifier", &I);
        return false;
    }

    Function *getCalledFunctionFromCallInst(CallInst *pci)
    {
        Function *ret = pci->getCalledFunction();
        if (nullptr == ret) {
#if 0
            Value *v = pci->getCalledValue();
#else
            Value * v = pci->getOperand(0); /*This is the called operand.*/
            if (nullptr == v){
                llvm::errs() << "<" << __LINE__ << ">" << *pci << "<END>\n";
                llvm::errs() << "<" << __LINE__ << ">" << *(pci->getOperand(0)) << "<END>\n";
                assert (0 && "How do I handle function pointers?");
            }
#endif
            if (BitCastOperator *bco = llvm::dyn_cast<BitCastOperator>(v)) {
                ret = llvm::dyn_cast<Function>(bco->getOperand(0));
            }
        }

        return ret;
    }
    bool visitCallInst(CallInst &CI)
    {
        Function *F = getCalledFunctionFromCallInst(&CI);
        if (!F) {
            /*Determine if we want to allow indirect calls*/
            printDiagnostic("Indirect call checking not implemented!", &CI);
            return false;
        }

        if (F->getCallingConv() != CI.getCallingConv()) {
            printDiagnostic("For call to " + F->getName() + ", calling conventions don't match!", &CI);
            return false;
        }
        if (F->isVarArg()) {
            if (!F->getFunctionType()->getNumParams()) {
                printDiagnostic(("Calling implicitly declared function '" +
                                 F->getName() + "' is not supported (did you forget to"
                                                "implement it, or typoed the function name?)")
                                    .str(),
                                &CI);
            } else {
                printDiagnostic("Checking calls to vararg functions/functions without"
                                "a prototype is not supported!",
                                &CI);
            }
            return false;
        }

        return true;
    }

    bool visitPHINode(PHINode &PN)
    {
        for (unsigned i = 0; i < PN.getNumIncomingValues(); i++) {
            if (isa<UndefValue>(PN.getIncomingValue(i))) {
                const Module *M = PN.getParent()->getParent()->getParent();
                printDiagnosticValue("Undefined value in phi", M, &PN);
                break;
            }
        }
        return true;
    }

    bool visitGetElementPtrInst(GetElementPtrInst &GEP)
    {
        return true;
    }

    bool visitLoadInst(LoadInst &LI)
    {
        return true;
    }

    bool visitStoreInst(StoreInst &SI)
    {
        return true;
    }

  public:
    //static char ID;
    explicit ClamBCVerifier():
        Final(false) {}

    virtual llvm::StringRef getPassName() const
    {
        return "ClamAV Bytecode Verifier";
    }

#if 0
    virtual bool runOnFunction(Function &F)
#else
    PreservedAnalyses run(Function & F, FunctionAnalysisManager & fam)
#endif
    {
        pMod   = F.getParent();
        AbrtBB = 0;
        //SE     = &getAnalysis<ScalarEvolutionWrapperPass>().getSE();
        SE = &fam.getResult<ScalarEvolutionAnalysis>(F);
        //DT = &getAnalysis<DominatorTreeWrapperPass>().getDomTree();
        DT = &fam.getResult<DominatorTreeAnalysis>(F);

        bool OK = true;
        std::vector<Instruction *> insns;
        // verifying can insert runtime checks, so be safe and create an initial
        // list of instructions to process so we are not affected by transforms.
        for (inst_iterator I = inst_begin(&F), E = inst_end(&F); I != E; ++I) {
            insns.push_back(&*I);
        }
        for (std::vector<Instruction *>::iterator I = insns.begin(), E = insns.end();
             I != E; ++I) {
            OK &= visit(*I);
            if (!OK && StopOnFirstError)
                break;
        }
        if (!OK)
            ClamBCStop("Verifier rejected bytecode function due to errors",
                       &F);
        return PreservedAnalyses::all();
    }
    virtual void getAnalysisUsage(AnalysisUsage &AU) const
    {
        AU.addRequired<ScalarEvolutionWrapperPass>();
        AU.addRequired<DominatorTreeWrapperPass>();
        AU.setPreservesAll();
    }
};
//char ClamBCVerifier::ID = 0;

} // namespace

#if 0
static RegisterPass<ClamBCVerifier> X("clambc-verifier", "ClamBCVerifier Pass",
                                      false /* Only looks at CFG */,
                                      false /* Analysis Pass */);
#else



// This part is the new way of registering your pass
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {
  return {
    LLVM_PLUGIN_API_VERSION, "ClamBCVerifier", "v0.1",
    [](PassBuilder &PB) {
      PB.registerPipelineParsingCallback(
        [](StringRef Name, FunctionPassManager &FPM,
        ArrayRef<PassBuilder::PipelineElement>) {
          if(Name == "clambc-verifier"){
            FPM.addPass(ClamBCVerifier::ClamBCVerifier());
            return true;
          }
          return false;
        }
      );
    }
  };
}



#endif







