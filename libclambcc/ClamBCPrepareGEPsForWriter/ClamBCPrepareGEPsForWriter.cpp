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

//#define USE_ANALYZER

using namespace llvm;

class ClamBCPrepareGEPsForWriter : public ModulePass
{
  protected:
    llvm::Module *pMod        = nullptr;
    ClamBCAnalyzer *pAnalyzer = nullptr;

  public:
    static char ID;

    explicit ClamBCPrepareGEPsForWriter()
        : ModulePass(ID) {}

    virtual ~ClamBCPrepareGEPsForWriter() {}

    void getAnalysisUsage(AnalysisUsage &AU) const
    {
#ifdef USE_ANALYZER
        AU.addRequired<ClamBCAnalyzer>();
#endif
    }

    virtual bool runOnModule(Module &m)
    {

        pMod = &m;
#ifdef USE_ANALYZER
        pAnalyzer = &getAnalysis<ClamBCAnalyzer>();
#endif

        for (auto i = pMod->begin(), e = pMod->end(); i != e; i++) {
            Function *pFunc = llvm::cast<Function>(i);
            //fixGEPs(pFunc);

            fixGEPs2(pFunc);
        }

        for (auto i = pMod->begin(), e = pMod->end(); i != e; i++) {
            Function *pFunc = llvm::cast<Function>(i);

            fixCasts(pFunc);
        }

        return true;
    }

    virtual void fixCasts(Function *pFunc)
    {

        for (auto i = pFunc->begin(), e = pFunc->end(); i != e; i++) {
            BasicBlock *pBB = llvm::cast<BasicBlock>(i);
            fixCasts(pBB);
        }
    }

    virtual void fixCasts(BasicBlock *pBB)
    {
        for (auto i = pBB->begin(), e = pBB->end(); i != e; i++) {
            if (CastInst *pci = llvm::dyn_cast<CastInst>(i)) {
                if (GetElementPtrInst *pgepi = llvm::dyn_cast<GetElementPtrInst>(pci->getOperand(0))) {
                    if (pgepi->hasAllZeroIndices()) {
                        if (AllocaInst *pai = llvm::dyn_cast<AllocaInst>(pgepi->getPointerOperand())) {
                            if (pai->getType() == pci->getType()) {
                                pci->replaceAllUsesWith(pai);
                            }
                        }
                    }
                }
            }
        }
    }

    //BEGIN_FIX_GEP_2
    //The following GEP fixes are to prevent hitting the assert in hte default case of visitGetElementPtrInst
    //
    virtual void gatherGEPs2(BasicBlock *pBB, std::vector<GetElementPtrInst *> &geps)
    {
        for (auto i = pBB->begin(), e = pBB->end(); i != e; i++) {
            if (llvm::isa<GetElementPtrInst>(i)) {
                GetElementPtrInst *pGEP = llvm::cast<GetElementPtrInst>(i);
                if (pGEP->getNumIndices() > 1) {
                    geps.push_back(pGEP);
                }
            }
        }
    }

    virtual void gatherGEPs2(Function *pFunc, std::vector<GetElementPtrInst *> &geps)
    {
        for (auto i = pFunc->begin(), e = pFunc->end(); i != e; i++) {
            BasicBlock *pBB = llvm::cast<BasicBlock>(i);
            gatherGEPs2(pBB, geps);
        }
    }

    virtual int64_t getTypeSize(Type *pt)
    {
        int64_t size = pt->getScalarSizeInBits();
        if (size) {
            return size;
        }

        if (ArrayType *pat = llvm::dyn_cast<ArrayType>(pt)) {
            size = pat->getNumElements() * (getTypeSize(pat->getElementType()));
            if (size) {
                return size;
            }
        }

        if (StructType *pst = llvm::dyn_cast<StructType>(pt)) {

            for (size_t i = 0; i < pst->getNumElements(); i++) {
                size += getTypeSize(pst->getTypeAtIndex(i));
            }

            if (size) {
                return size;
            }
        }

        assert(0 && "Size has not been computed");
        return -1;
    }

    virtual int64_t getTypeSizeInBytes(Type *pt)
    {
        return getTypeSize(pt) / 8;
    }

    virtual int64_t computeOffsetInBytes(StructType *pst, int64_t idx)
    {
        assert((idx <= pst->getNumElements()) && "Idx too high");

        int64_t cnt = 0;
        for (int64_t i = 0; i < idx; i++) {
            Type *pt     = pst->getElementType(i);
            int64_t size = getTypeSizeInBytes(pt);
            cnt += size;
        }

        return cnt;
    }

    virtual int64_t computeOffsetInBytes(StructType *pst, ConstantInt *pIdx)
    {
        int64_t idx = pIdx->getLimitedValue();
        return computeOffsetInBytes(pst, idx);
    }

    virtual int64_t computeOffsetInBytes(StructType *pst)
    {
        return computeOffsetInBytes(pst, pst->getNumElements());
    }

    virtual void handleStruct(GetElementPtrInst *pGEP, StructType *pst)
    {

        size_t numIndices = pGEP->getNumIndices();

        assert(numIndices >= 2 && "HOW DID WE GET HERE???");
        assert(numIndices <= 3 && "DON'T KNOW WHAT TO DO WITH 4 OR MORE INDICES???");

        std::vector<Value *> idxs;

        Value *offsetIdx         = pGEP->getOperand(2);
        int64_t offset           = -1;
        ConstantInt *ciOffsetIdx = llvm::dyn_cast<ConstantInt>(offsetIdx);
        if (nullptr != ciOffsetIdx) {
            offset = computeOffsetInBytes(pst, ciOffsetIdx);

        } else {
            assert(0 && "DON'T THINK THIS IS POSSIBLE FOR A STRUCT???????");
        }

        assert((offset != -1) && "HANDLE CASE");

        if (numIndices == 2) {
            idxs.push_back(ConstantInt::get(offsetIdx->getType(), offset));
        } else {

            Value *addOffsetIdx = pGEP->getOperand(3);

            Type *structElementType  = pst->getElementType(ciOffsetIdx->getLimitedValue());
            uint64_t elementTypeSize = 0;

            if (ArrayType *at = llvm::dyn_cast<ArrayType>(structElementType)) {
                Type *elementType = at->getElementType();

                elementTypeSize = elementType->getPrimitiveSizeInBits();
                if (0 == elementTypeSize) {
                    if (StructType *pst = llvm::dyn_cast<StructType>(elementType)) {
                        //elementTypeSize = pStructLayout->getSizeInBits();
                        elementTypeSize = computeOffsetInBytes(pst) * 8;

                    } else {
                        DEBUGERR << *elementType << "<END>\n";
                        assert(0 && "FIGURE THIS OUT");
                    }
                }
                if (elementTypeSize && (elementTypeSize < 8)) {
                    elementTypeSize = 8;
                }
                elementTypeSize /= 8;

            } else {
                DEBUGERR << *structElementType << "<END>\n";
                assert(0 && "HANDLE OTHER TYPES");
            }
            assert(elementTypeSize && "Can't have zero type size and no types should be opaque");

            Constant *multiplier = ConstantInt::get(offsetIdx->getType(), elementTypeSize);
            Instruction *pInst   = BinaryOperator::Create(Instruction::Mul, multiplier, addOffsetIdx, "ClamBCPrepareGEPsForWriter_handleStruct_1_", pGEP);

            Constant *ciOffset = ConstantInt::get(addOffsetIdx->getType(), offset);
            pInst              = BinaryOperator::Create(Instruction::Add, pInst, ciOffset, "ClamBCPrepareGEPsForWriter_handleStruct_2_", pGEP);

            idxs.push_back(pInst);
        }

        Type *dstType           = Type::getInt8PtrTy(pMod->getContext());
        CastInst *pbci          = CastInst::CreatePointerCast(pGEP->getPointerOperand(), dstType, "ClamBCPrepareGEPsForWriter_handleStruct_3_", pGEP);
        GetElementPtrInst *gepi = GetElementPtrInst::Create(nullptr, pbci, idxs, "ClamBCPrepareGEPsForWriter_handleStruct_4_", pGEP);
        pbci                    = CastInst::CreatePointerCast(gepi, pGEP->getType(), "ClamBCPrepareGEPsForWriter_handleStruct_5_", pGEP);

        pGEP->replaceAllUsesWith(pbci);
        pGEP->eraseFromParent();
    }

    virtual void fixGEPs2(Function *pFunc)
    {

        std::vector<GetElementPtrInst *> geps;
        gatherGEPs2(pFunc, geps);

        std::vector<Instruction *> insts;

        for (size_t i = 0; i < geps.size(); i++) {
            GetElementPtrInst *pGEP = geps[i];
            Value *pv               = GetUnderlyingObject(pGEP->getPointerOperand(), pMod->getDataLayout());

            Type *origType       = pGEP->getPointerOperand()->getType()->getPointerElementType();
            Type *underlyingType = pv->getType()->getPointerElementType();
            Type *wanted         = Type::getInt8Ty(pMod->getContext());
            if (wanted != underlyingType) {
                ArrayType *at = llvm::dyn_cast<ArrayType>(underlyingType);
                if (at) {
                    if (wanted != at->getArrayElementType()) {
                        DEBUGERR << *underlyingType << "<END>\n";
                        assert(0 && "WRONG TYPE");
                    }
                }
            }

            ArrayType *at = llvm::dyn_cast<ArrayType>(origType);

            if (not at) {
                if (StructType *st = llvm::dyn_cast<StructType>(origType)) {
                    handleStruct(pGEP, st);
                    /*TODO: REWORK THIS WITHOUT HTE CONTINUE*/
                    continue;
                } else {
                    DEBUGERR << *origType << "<END>\n";
                    DEBUGERR << llvm::isa<StructType>(origType) << "<END>\n";
                    assert(at && "Handle this");
                }

                //in this case (to be in this function), it's either an array of structures, or a structure containing an array.  ;
            }

            Type *t = at->getArrayElementType();

            Instruction *pInst = BinaryOperator::Create(Instruction::Mul,
                                                        pGEP->getOperand(2),
                                                        ConstantInt::get(pGEP->getOperand(2)->getType(), pMod->getDataLayout().getTypeAllocSize(t)), "ClamBCPrepareGEPsForWriter_fixGEPs2_", pGEP);

            pInst = GetElementPtrInst::Create(nullptr, pv, {pGEP->getOperand(1), pInst}, "ClamBCPrepareGEPsForWriter_fixGEPs2_first_", pGEP);

            for (size_t idx = 3; idx <= pGEP->getNumIndices(); idx++) {

                Value *op       = pGEP->getOperand(idx);
                ConstantInt *pc = llvm::dyn_cast<ConstantInt>(op);
                assert(pc && "NOT A CONSTANT");

                StructType *pst = llvm::dyn_cast<StructType>(t);
                assert(pst && "NOT A STRUCT TYPE");
                const StructLayout *psl = pMod->getDataLayout().getStructLayout(pst);

                size_t offset = psl->getElementOffset(pc->getLimitedValue());

                pInst = GetElementPtrInst::Create(nullptr, pInst, ConstantInt::get(op->getType(), offset), "ClamBCPrepareGEPsForWriter_fixGEPs2_loop_", pGEP);

                pInst = CastInst::CreatePointerCast(pInst, pGEP->getType(), "ClamBCPrepareGEPsForWriter_fixGEPs2_second_", pGEP);
            }

            if (pInst->getType() != pGEP->getType()) {
                pInst = CastInst::CreatePointerCast(pInst, pGEP->getType(), "ClamBCPrepareGEPsForWriter_fixGEPs2_pointerCast_", pGEP);
            }
            assert(pGEP->getType() == pInst->getType() && "FIX GTHIS");
            pGEP->replaceAllUsesWith(pInst);
            pGEP->eraseFromParent();

            insts.push_back(pInst);
        }
    }
};

char ClamBCPrepareGEPsForWriter::ID = 0;
static RegisterPass<ClamBCPrepareGEPsForWriter> X("clambc-prepare-geps-for-writer", "ClamBCPrepareGEPsForWriter Pass",
                                                  false /* Only looks at CFG */,
                                                  false /* Analysis Pass */);

llvm::ModulePass *createClamBCPrepareGEPsForWriter()
{
    return new ClamBCPrepareGEPsForWriter();
}
