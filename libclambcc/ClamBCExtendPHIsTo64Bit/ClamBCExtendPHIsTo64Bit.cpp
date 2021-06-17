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
#include "../Common/bytecode_api.h"
#include "clambc.h"
#include "ClamBCModule.h"
#include "ClamBCAnalyzer/ClamBCAnalyzer.h"
#include "Common/ClamBCUtilities.h"

#include <llvm/Support/DataTypes.h>
//#include "ClamBCTargetMachine.h"
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
//#include "llvm/Config/config.h"
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

using namespace llvm;

class ClamBCExtendPHIsTo64Bit : public ModulePass
{
  protected:
    llvm::Module *pMod = nullptr;

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

            //Not allowed in bytecode sigs, but no reason not to support it.
            if (llvm::isa<LandingPadInst>(i)) {
                continue;
            }

            insPt = llvm::cast<Instruction>(i);
            break;
        }

        Instruction *cast = CastInst::CreateIntegerCast(newNode, origType, true, "ClamBCConvertPHINodes_", insPt);
        pn->replaceAllUsesWith(cast);
        pn->eraseFromParent();
    }

  public:
    static char ID;

    explicit ClamBCExtendPHIsTo64Bit()
        : ModulePass(ID) {}

    virtual ~ClamBCExtendPHIsTo64Bit() {}

    virtual bool runOnModule(Module &m)
    {

        pMod = &m;

        for (auto i = pMod->begin(), e = pMod->end(); i != e; i++) {
            Function *pFunc = llvm::cast<Function>(i);
            convertPHIs(pFunc);
        }

        return true;
    }
};

char ClamBCExtendPHIsTo64Bit::ID = 0;
static RegisterPass<ClamBCExtendPHIsTo64Bit> X("clambc-extend-phis-to-64bit", "ClamBCExtendPHIsTo64Bit Pass",
                                               false /* Only looks at CFG */,
                                               false /* Analysis Pass */);

llvm::ModulePass *createClamBCExtendPHIsTo64Bit()
{
    return new ClamBCExtendPHIsTo64Bit();
}
