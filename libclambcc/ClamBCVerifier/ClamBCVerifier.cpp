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

#include <llvm/Pass.h>
#include "llvm/IR/Function.h"
#include "llvm/Support/raw_ostream.h"

#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

using namespace llvm;

#include "ClamBCDiagnostics.h"
#include "ClamBCModule.h"
#include <llvm/IR/Verifier.h>
#include <llvm/IR/Dominators.h>
#include "llvm/Analysis/ConstantFolding.h"
#include "llvm/Analysis/ScalarEvolution.h"
#include "llvm/Analysis/ScalarEvolutionExpressions.h"
#include "llvm/Analysis/ScalarEvolutionExpander.h"
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
#include "llvm/ADT/DepthFirstIterator.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include <llvm/IR/InstrTypes.h>

#include "llvm/ADT/SmallSet.h"

#include "Common/clambc.h"
#include "Common/ClamBCUtilities.h"

static cl::opt<bool>
    StopOnFirstError("clambc-stopfirst", cl::init(false),
                     cl::desc("Stop on first error in the verifier"));
namespace
{
class ClamBCVerifier : public FunctionPass,
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
            Value *v = pci->getCalledValue();
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
            printDiagnostic("Indirect call checking not implemented yet!", &CI);
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
    static char ID;
    explicit ClamBCVerifier()
        : FunctionPass(ID), Final(false) {}

    virtual llvm::StringRef getPassName() const
    {
        return "ClamAV Bytecode Verifier";
    }

    virtual bool runOnFunction(Function &F)
    {
        pMod   = F.getParent();
        AbrtBB = 0;
        SE     = &getAnalysis<ScalarEvolutionWrapperPass>().getSE();
        ;
        DT = &getAnalysis<DominatorTreeWrapperPass>().getDomTree();

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
        return false;
    }
    virtual void getAnalysisUsage(AnalysisUsage &AU) const
    {
        AU.addRequired<ScalarEvolutionWrapperPass>();
        AU.addRequired<DominatorTreeWrapperPass>();
        AU.setPreservesAll();
    }
};
char ClamBCVerifier::ID = 0;

} // namespace

static RegisterPass<ClamBCVerifier> X("clambc-verifier", "ClamBCVerifier Pass",
                                      false /* Only looks at CFG */,
                                      false /* Analysis Pass */);
