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
 * Remove smin intrinsic because it's not supported by our runtime.
 */
struct ClamBCRemoveUnsupportedICMPIntrinsics : public PassInfoMixin<ClamBCRemoveUnsupportedICMPIntrinsics> {
  protected:
    Module *pMod = nullptr;
    // const char * const UnsupportedICMPIntrinsics_NAME = ".smin";

    FunctionType *sminType = nullptr;

    virtual llvm::FunctionType *getUnsupportedICMPIntrinsicsFunctionType(Type *functionArgType)
    {
        return FunctionType::get(functionArgType, {functionArgType, functionArgType}, false);
    }

    virtual llvm::Function *addFunction(Type *functionArgType,
                                        const char *const newName,
                                        llvm::CmpInst::Predicate predicate)
    {

        uint32_t addressSpace = pMod->getDataLayout().getProgramAddressSpace();

        FunctionType *ft = getUnsupportedICMPIntrinsicsFunctionType(functionArgType);

        llvm::Function *smin  = Function::Create(ft, GlobalValue::InternalLinkage, newName, *pMod);
        Value *pLeft          = smin->getArg(0);
        Value *pRight         = smin->getArg(1);
        BasicBlock *pEntry    = BasicBlock::Create(pMod->getContext(), "entry", smin);
        BasicBlock *pLHS      = BasicBlock::Create(pMod->getContext(), "left", smin);
        BasicBlock *pRHS      = BasicBlock::Create(pMod->getContext(), "right", smin);
        BasicBlock *pRetBlock = BasicBlock::Create(pMod->getContext(), "ret", smin);

        // entry  block
        AllocaInst *retVar = new AllocaInst(functionArgType, addressSpace, "ret", pEntry);
        ICmpInst *cmp      = new ICmpInst(*pEntry, predicate, pLeft, pRight, "icmp");
        BranchInst::Create(pLHS, pRHS, cmp, pEntry);

        // left > right
        new StoreInst(pLeft, retVar, pLHS);
        BranchInst::Create(pRetBlock, pLHS);

        // right >= left
        new StoreInst(pRight, retVar, pRHS);
        BranchInst::Create(pRetBlock, pRHS);

        LoadInst *pli = new LoadInst(functionArgType, retVar, "load", pRetBlock);
        ReturnInst::Create(pMod->getContext(), pli, pRetBlock);
        return smin;
    }

    virtual bool replaceCalls(const char *const intrinsicName,
                              const char *newName,
                              llvm::CmpInst::Predicate predicate,
                              Type *functionArgType)
    {
        std::vector<CallInst *> calls;
        gatherCallsToIntrinsic(pMod, intrinsicName, calls);
        if (calls.size()) {
            Function *smin = addFunction(functionArgType, newName, predicate);
            replaceAllCalls(getUnsupportedICMPIntrinsicsFunctionType(functionArgType), smin, calls, "ClamBCRemoveUnsupportedICMPIntrinsics_");

            return true;
        }
        return false;
    }

  public:
    virtual ~ClamBCRemoveUnsupportedICMPIntrinsics() {}

    /*TODO: Add detection of these instructions to the validator.*/
    PreservedAnalyses run(Module &m, ModuleAnalysisManager &MAM)
    {
        pMod = &m;

        bool bRet = replaceCalls("llvm.smin.i32", ".smin.32", CmpInst::ICMP_SLT, Type::getInt32Ty(pMod->getContext()));
        bRet |= replaceCalls("llvm.smin.i16", ".smin.16", CmpInst::ICMP_SLT, Type::getInt16Ty(pMod->getContext()));
        bRet |= replaceCalls("llvm.umin.i16", ".umin.16", CmpInst::ICMP_ULT, Type::getInt16Ty(pMod->getContext()));
        bRet |= replaceCalls("llvm.umin.i32", ".umin.32", CmpInst::ICMP_ULT, Type::getInt32Ty(pMod->getContext()));
        bRet |= replaceCalls("llvm.umax.i32", ".umax.32", CmpInst::ICMP_UGT, Type::getInt32Ty(pMod->getContext()));
        bRet |= replaceCalls("llvm.umax.i16", ".umax.16", CmpInst::ICMP_UGT, Type::getInt16Ty(pMod->getContext()));
        bRet |= replaceCalls("llvm.smax.i32", ".smax.32", CmpInst::ICMP_SGT, Type::getInt32Ty(pMod->getContext()));
        bRet |= replaceCalls("llvm.smax.i16", ".smax.16", CmpInst::ICMP_SGT, Type::getInt16Ty(pMod->getContext()));

        if (bRet) {
            return PreservedAnalyses::none();
        }

        return PreservedAnalyses::all();
    }

}; // end of struct ClamBCRemoveUnsupportedICMPIntrinsics

} // end of anonymous namespace

// This part is the new way of registering your pass
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo()
{
    return {
        LLVM_PLUGIN_API_VERSION, "ClamBCRemoveUnsupportedICMPIntrinsics", "v0.1",
        [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &FPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                    if (Name == "clambc-remove-unsupported-icmp-intrinsics") {
                        FPM.addPass(ClamBCRemoveUnsupportedICMPIntrinsics());
                        return true;
                    }
                    return false;
                });
        }};
}
