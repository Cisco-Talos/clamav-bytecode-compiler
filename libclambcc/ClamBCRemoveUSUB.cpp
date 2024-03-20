/*
 *  Compile LLVM bytecode to ClamAV bytecode.
 *
 *  Copyright (C) 2020-2023 Sourcefire, Inc.
 *
 *  Authors: Andy Ragusa
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

#include "clambc.h"
#include "ClamBCUtilities.h"

#include <llvm/IR/Module.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Support/raw_ostream.h>

#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/PassPlugin.h>

#include <vector>

using namespace llvm;
using namespace std;

namespace
{
/*
 * Remove usub intrinsic because it's not supported by our runtime.
 */
struct ClamBCRemoveUSUB : public PassInfoMixin<ClamBCRemoveUSUB> {
  protected:
    Module *pMod                = nullptr;
    const char *const USUB_NAME = ".usub";

    FunctionType *usubType = nullptr;

    virtual llvm::FunctionType *getUSUBFunctionType(Type *functionArgType)
    {
        return FunctionType::get(functionArgType, {functionArgType, functionArgType}, false);
    }

    virtual llvm::Function *addUSUB(Type *functionArgType)
    {
        uint32_t addressSpace = pMod->getDataLayout().getProgramAddressSpace();

        FunctionType *ft = getUSUBFunctionType(functionArgType);

        llvm::Function *usub  = Function::Create(ft, GlobalValue::InternalLinkage, USUB_NAME, *pMod);
        Value *pLeft          = usub->getArg(0);
        Value *pRight         = usub->getArg(1);
        BasicBlock *pEntry    = BasicBlock::Create(pMod->getContext(), "entry", usub);
        BasicBlock *pLHS      = BasicBlock::Create(pMod->getContext(), "left", usub);
        BasicBlock *pRHS      = BasicBlock::Create(pMod->getContext(), "right", usub);
        BasicBlock *pRetBlock = BasicBlock::Create(pMod->getContext(), "ret", usub);

        // entry  block
        AllocaInst *retVar = new AllocaInst(functionArgType, addressSpace, "ret", pEntry);
        ICmpInst *cmp      = new ICmpInst(*pEntry, CmpInst::ICMP_UGT, pLeft, pRight, "icmp");
        BranchInst::Create(pLHS, pRHS, cmp, pEntry);

        // left > right
        new StoreInst(BinaryOperator::Create(Instruction::Sub, pLeft, pRight, "ClamBCRemoveUSUB_", pLHS), retVar, pLHS);
        BranchInst::Create(pRetBlock, pLHS);

        // right >= left
        new StoreInst(ConstantInt::get(functionArgType, 0), retVar, pRHS);
        BranchInst::Create(pRetBlock, pRHS);

        LoadInst *pli = new LoadInst(functionArgType, retVar, "load", pRetBlock);
        ReturnInst::Create(pMod->getContext(), pli, pRetBlock);
        return usub;
    }

    virtual bool replaceCalls(const char *const intrinsicName, Type *functionArgType)
    {
        std::vector<CallInst *> calls;
        gatherCallsToIntrinsic(pMod, intrinsicName, calls);
        if (calls.size()) {
            Function *usub = addUSUB(functionArgType);
            replaceAllCalls(getUSUBFunctionType(functionArgType), usub, calls, "ClamBCRemoveUSUB_");

            return true;
        }
        return false;
    }

  public:
    virtual ~ClamBCRemoveUSUB() {}

    /*TODO: Add detection of these instructions to the validator.*/
    PreservedAnalyses run(Module &m, ModuleAnalysisManager &MAM)
    {
        pMod = &m;

        bool bRet = replaceCalls("llvm.usub.sat.i32", Type::getInt32Ty(pMod->getContext()));
        //                bRet |= replaceCalls("llvm.usub.i16", Type::getInt16Ty(pMod->getContext()));

        if (bRet) {
            return PreservedAnalyses::none();
        }

        return PreservedAnalyses::all();
    }

}; // end of struct ClamBCRemoveUSUB

} // end of anonymous namespace

// This part is the new way of registering your pass
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo()
{
    return {
        LLVM_PLUGIN_API_VERSION, "ClamBCRemoveUSUB", "v0.1",
        [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &FPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                    if (Name == "clambc-remove-usub") {
                        FPM.addPass(ClamBCRemoveUSUB());
                        return true;
                    }
                    return false;
                });
        }};
}
