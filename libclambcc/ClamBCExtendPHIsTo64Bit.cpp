/*
 *  Compile LLVM bytecode to ClamAV bytecode.
 *
 *  Copyright (C) 2009-2010 Sourcefire, Inc.
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
#include "bytecode_api.h"
#include "clambc.h"
#include "ClamBCUtilities.h"

#include <llvm/Support/DataTypes.h>
#include <llvm/ADT/STLExtras.h>
#include <llvm/Analysis/ConstantFolding.h>
#include <llvm/IR/DebugInfo.h>
#include <llvm/IR/Dominators.h>
#include <llvm/Analysis/LoopInfo.h>
#include <llvm/Analysis/Passes.h>
#include <llvm/Analysis/ValueTracking.h>
#include <llvm/IR/Attributes.h>
#include <llvm/IR/CallingConv.h>
#include <llvm/CodeGen/IntrinsicLowering.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/Intrinsics.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

#include <llvm/Analysis/ValueTracking.h>

#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/PassPlugin.h>

using namespace llvm;

class ClamBCExtendPHIsTo64Bit : public PassInfoMixin<ClamBCExtendPHIsTo64Bit>
{
  protected:
    llvm::Module *pMod = nullptr;
    bool bChanged      = false;

    virtual void convertPHIs(Function *pFunc)
    {
        std::vector<PHINode *> phis;
        for (auto i = pFunc->begin(), e = pFunc->end(); i != e; i++) {
            BasicBlock *bb = llvm::cast<BasicBlock>(i);
            for (auto bi = bb->begin(), be = bb->end(); bi != be; bi++) {
                if (PHINode *phi = llvm::dyn_cast<PHINode>(bi)) {
                    phis.push_back(phi);
                }
            }
        }

        for (size_t i = 0; i < phis.size(); i++) {
            convertPHI(phis[i]);
        }
    }

    virtual void convertPHI(PHINode *pn)
    {
        IntegerType *dstType  = IntegerType::get(pMod->getContext(), 64);
        IntegerType *origType = llvm::dyn_cast<IntegerType>(pn->getType());
        if ((dstType == origType) || (nullptr == origType)) {
            return;
        }

        PHINode *newNode = PHINode::Create(dstType, pn->getNumIncomingValues(), "ClamBCConvertPHINodes_", pn);
        for (size_t i = 0; i < pn->getNumIncomingValues(); i++) {
            Value *incomingValue      = pn->getIncomingValue(i);
            BasicBlock *incomingBlock = pn->getIncomingBlock(i);

            if (ConstantInt *ci = llvm::dyn_cast<ConstantInt>(incomingValue)) {
                Constant *newCi = ConstantInt::get(dstType, ci->getLimitedValue());
                newNode->addIncoming(newCi, incomingBlock);
            } else {
                Instruction *insPt = llvm::cast<Instruction>(--(incomingBlock->end()));
                Instruction *inst  = CastInst::CreateIntegerCast(pn->getIncomingValue(i), dstType, true, "ClamBCConvertPHINodes_", insPt);

                newNode->addIncoming(inst, incomingBlock);
            }
        }
        Instruction *insPt = nullptr;
        for (auto i = pn->getParent()->begin(), e = pn->getParent()->end(); i != e; i++) {
            if (llvm::isa<PHINode>(i)) {
                continue;
            }

            // Not allowed in bytecode sigs, but no reason not to support it.
            if (llvm::isa<LandingPadInst>(i)) {
                continue;
            }

            insPt = llvm::cast<Instruction>(i);
            break;
        }

        Instruction *cast = CastInst::CreateIntegerCast(newNode, origType, true, "ClamBCConvertPHINodes_", insPt);
        pn->replaceAllUsesWith(cast);
        pn->eraseFromParent();
        bChanged = true;
    }

  public:
    static char ID;

    explicit ClamBCExtendPHIsTo64Bit() {}

    virtual ~ClamBCExtendPHIsTo64Bit() {}

    virtual PreservedAnalyses run(Module &m, ModuleAnalysisManager &MAM)
    {

        pMod = &m;

        for (auto i = pMod->begin(), e = pMod->end(); i != e; i++) {
            Function *pFunc = llvm::cast<Function>(i);
            convertPHIs(pFunc);
        }

        if (bChanged) {
            /* Since we changed the IR here invalidate all the previous analysis.
             * We only want to invalidate the analysis when we change something,
             * since it is expensive to compute.
             */
            return PreservedAnalyses::none();
        }
        /*We didn't change anything, so keep the previous analysis.*/
        return PreservedAnalyses::all();
    }
};

// This part is the new way of registering your pass
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo()
{
    return {
        LLVM_PLUGIN_API_VERSION, "ClamBCExtendPHIsTo64Bit", "v0.1",
        [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &FPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                    if (Name == "clambc-extend-phis-to-64-bit") {
                        FPM.addPass(ClamBCExtendPHIsTo64Bit());
                        return true;
                    }
                    return false;
                });
        }};
}
