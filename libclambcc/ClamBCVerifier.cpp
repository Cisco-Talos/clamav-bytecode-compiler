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

#include "ClamBCDiagnostics.h"
#include "clambc.h"
#include "ClamBCUtilities.h"

#include <llvm/Pass.h>
#include <llvm/IR/Function.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Passes/PassPlugin.h>

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
#include <llvm/Support/CommandLine.h>
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

namespace ClamBCVerifier
{
class ClamBCVerifier : public PassInfoMixin<ClamBCVerifier>,
                       public InstVisitor<ClamBCVerifier, bool>
{

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
        llvm::errs() << "<" << __FUNCTION__ << "::" << __LINE__ << ">"
                     << "Selects need tobe removed, so this should be a false<END>\n";
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

    /*
     * FreezeInst's are used to guarantee a value being set to something fixed
     * if it is undef or a poison value.  They are a noop otherwise, so we will allow
     * them in the verifier, and remove them in a pass to be run after the verifier.
     * (a 'verifier' shouldn't be changing the IR).
     */
    bool visitFreezeInst(FreezeInst &I)
    {
        return true;
    }

    bool visitInstruction(Instruction &I)
    {

        DEBUG_VALUE(&I);
#define DEBUG_NODEREF(val) llvm::errs() << "<" << __FUNCTION__ << "::" << __LINE__ << ">" << val << "<END>\n";
        DEBUG_NODEREF(llvm::isa<FreezeInst>(&I));

        printDiagnostic("Unhandled instruction in verifier", &I);
        return false;
    }

    Function *getCalledFunctionFromCallInst(CallInst *pci)
    {

        Value *pCalledOperand = pci->getCalledOperand();
        Function *ret         = llvm::dyn_cast<Function>(pCalledOperand);
        if (nullptr == ret) {
            if (BitCastOperator *bco = llvm::dyn_cast<BitCastOperator>(pCalledOperand)) {
                ret = llvm::dyn_cast<Function>(bco->getOperand(0));
            }
        }

        if (nullptr == ret) {
            ClamBCStop("Verifier unable to get called function from call instruction", pci);
        }

        return ret;
    }

    bool validateFunction(const llvm::Function *pFunc)
    {

        if (pFunc->isVarArg()) {
            if (!pFunc->getFunctionType()->getNumParams()) {
                printDiagnostic(("Calling implicitly declared function '" +
                                 pFunc->getName() + "' is not supported (did you forget to"
                                                    "implement it, or typoed the function name?)")
                                    .str(),
                                pFunc);
            } else {
                printDiagnostic("Checking calls to vararg functions/functions without"
                                "a prototype is not supported!",
                                pFunc);
            }
            return false;
        }

        return true;
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

        return validateFunction(F);
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

    virtual bool isHandled(Instruction *pInst)
    {
        bool bRet = llvm::isa<StoreInst>(pInst) || llvm::isa<LoadInst>(pInst) || llvm::isa<GetElementPtrInst>(pInst) || llvm::isa<FreezeInst>(pInst) || llvm::isa<ICmpInst>(pInst) || llvm::isa<ReturnInst>(pInst) || llvm::isa<BinaryOperator>(pInst) || llvm::isa<BranchInst>(pInst) || llvm::isa<SelectInst>(pInst) || llvm::isa<CastInst>(pInst) || llvm::isa<AllocaInst>(pInst) || llvm::isa<UnreachableInst>(pInst);

        return bRet;
    }

    virtual bool isUndefOrPoisonValue(Value *pv)
    {
        return llvm::isa<UndefValue>(pv);
    }

    virtual bool hasUndefsOrPoisonValues(ConstantExpr *pce, std::set<Value *> &visited)
    {
        if (visited.end() != std::find(visited.begin(), visited.end(), pce)) {
            return false;
        }
        visited.insert(pce);

        for (size_t i = 0; i < pce->getNumOperands(); i++) {
            Value *pv = pce->getOperand(i);
            if (isUndefOrPoisonValue(pv)) {
                return true;
            }
            if (ConstantExpr *ce = llvm::dyn_cast<ConstantExpr>(pv)) {
                if (hasUndefsOrPoisonValues(ce, visited)) {
                    return true;
                }
            }
        }

        return false;
    }

    virtual bool hasUndefsOrPoisonValues(ConstantExpr *pce)
    {
        std::set<Value *> visited;
        return hasUndefsOrPoisonValues(pce, visited);
    }

    /*PoisonValue is derived from UndefValue, so we only have to check for that one.*/
    virtual bool hasUndefsOrPoisonValues(Instruction *pInst)
    {
        for (size_t i = 0; i < pInst->getNumOperands(); i++) {
            Value *pVal = pInst->getOperand(i);
            if (llvm::isa<Instruction>(pVal)) {
                continue;
            }

            if (isUndefOrPoisonValue(pVal)) {
                return true;
            }

            if (ConstantExpr *pce = llvm::dyn_cast<ConstantExpr>(pVal)) {
                if (hasUndefsOrPoisonValues(pce)) {
                    return true;
                }
            }
        }
        return false;
    }

    virtual bool walk(Function *pFunc)
    {
        bool bRet = true;
        for (auto fi = pFunc->begin(), fe = pFunc->end(); fi != fe; fi++) {
            BasicBlock *pBB = llvm::cast<BasicBlock>(fi);
            for (auto bi = pBB->begin(), be = pBB->end(); bi != be; bi++) {
                Instruction *pInst = llvm::cast<Instruction>(bi);
                if (hasUndefsOrPoisonValues(pInst)) {
                    printDiagnostic("Poison value or Undef value found in instruction.", pInst);
                    return false;
                }

                if (PHINode *pn = llvm::dyn_cast<PHINode>(pInst)) {
                    bRet = visitPHINode(*pn);
                } else if (CallInst *pci = llvm::dyn_cast<CallInst>(pInst)) {
                    bRet = visitCallInst(*pci);
                } else if (SwitchInst *psi = llvm::dyn_cast<SwitchInst>(pInst)) {
                    bRet = visitSwitchInst(*psi);
                } else {
                    bRet = isHandled(pInst);
                }

                if (!bRet) {
                    break;
                }
            }
        }

        return bRet;
    }

  public:
    explicit ClamBCVerifier()
        : Final(false) {}

    virtual llvm::StringRef getPassName() const
    {
        return "ClamAV Bytecode Verifier";
    }

    PreservedAnalyses run(Function &F, FunctionAnalysisManager &fam)
    {
        pMod    = F.getParent();
        bool OK = validateFunction(&F);
        if (OK) {
            OK = walk(&F);
        }

        if (!OK) {
            ClamBCStop("Verifier rejected bytecode function due to errors",
                       &F);
        }

        return PreservedAnalyses::all();
    }
    virtual void getAnalysisUsage(AnalysisUsage &AU) const
    {
        AU.addRequired<ScalarEvolutionWrapperPass>();
        AU.addRequired<DominatorTreeWrapperPass>();
        AU.setPreservesAll();
    }
};
// char ClamBCVerifier::ID = 0;

} // namespace ClamBCVerifier

// This part is the new way of registering your pass
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo()
{
    return {
        LLVM_PLUGIN_API_VERSION, "ClamBCVerifier", "v0.1",
        [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, FunctionPassManager &FPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                    if (Name == "clambc-verifier") {
                        FPM.addPass(ClamBCVerifier::ClamBCVerifier());
                        return true;
                    }
                    return false;
                });
        }};
}
