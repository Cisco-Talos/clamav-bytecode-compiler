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
#include "ClamBCModule.h"
#include "ClamBCUtilities.h"

#include "ClamBCAnalyzer.h"

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
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/PassPlugin.h>

#include <llvm/Analysis/ValueTracking.h>

using namespace llvm;

struct ClamBCPrepareGEPsForWriter : public PassInfoMixin<ClamBCPrepareGEPsForWriter> {
  protected:
    llvm::Module *pMod = nullptr;

  public:
    static char ID;

    explicit ClamBCPrepareGEPsForWriter() {}

    virtual ~ClamBCPrepareGEPsForWriter() {}

    virtual bool ignoreGEPI(GetElementPtrInst *pgepi)
    {
        Type *ignType = Type::getInt8Ty(pMod->getContext());

        Type *ptrTy = pgepi->getPointerOperand()->getType()->getPointerElementType();

        if (ptrTy == ignType) {
            return true;
        }

        if (ptrTy->isArrayTy()) {
            ptrTy = ptrTy->getArrayElementType();
            if (ptrTy == Type::getInt8Ty(pMod->getContext())) {
                return true;
            }
        }

        return false;
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
            const StructLayout *psl = pMod->getDataLayout().getStructLayout(pst);
            return psl->getSizeInBits();
        }

        assert(0 && "Size has not been computed");
        return -1;
    }

    virtual int64_t getTypeSizeInBytes(Type *pt)
    {
        return getTypeSize(pt) / 8;
    }

    virtual int64_t computeOffsetInBytes(Type *pt, uint64_t idx)
    {

        int64_t cnt = 0;

        assert((llvm::isa<StructType>(pt) || llvm::isa<ArrayType>(pt)) && "pt must be a complex type");

        if (StructType *pst = llvm::dyn_cast<StructType>(pt)) {
            assert((idx <= pst->getNumElements()) && "Idx too high");

            const StructLayout *psl = pMod->getDataLayout().getStructLayout(pst);
            assert(psl && "Could not get layout");

            cnt = psl->getElementOffsetInBits(idx) / 8;

        } else if (ArrayType *pat = llvm::dyn_cast<ArrayType>(pt)) {
            assert((idx <= pat->getNumElements()) && "Idx too high");
            cnt = idx * getTypeSizeInBytes(pat->getElementType());
        }

        return cnt;
    }

    virtual int64_t computeOffsetInBytes(Type *pst, ConstantInt *pIdx)
    {
        int64_t idx = pIdx->getLimitedValue();
        return computeOffsetInBytes(pst, idx);
    }

    virtual int64_t computeOffsetInBytes(Type *pst)
    {
        if (llvm::isa<StructType>(pst)) {
            return computeOffsetInBytes(pst, pst->getStructNumElements());
        } else if (llvm::isa<ArrayType>(pst)) {
            return computeOffsetInBytes(pst, pst->getArrayNumElements());
        } else {
            assert(0 && "pt must be a complex type");
        }

        return 0;
    }

    virtual Type *findTypeAtIndex(Type *pst, ConstantInt *ciIdx)
    {
        Type *ret = nullptr;
        if (StructType *st = llvm::dyn_cast<StructType>(pst)) {
            uint64_t idx = ciIdx->getLimitedValue();

            assert(idx < st->getNumElements() && "Something went wrong");
            return st->getTypeAtIndex(idx);
        }

        if (ArrayType *at = llvm::dyn_cast<ArrayType>(pst)) {
            return at->getArrayElementType();
        }
        return ret;
    }

    virtual void processGEPI(GetElementPtrInst *pgepi, BitCastInst *pbci, Value *underlyingObject, StructType *gepiDstType)
    {

        uint64_t size = getTypeSizeInBytes(gepiDstType);
        assert(size && "size not computed");

        Value *vCnt = nullptr;

        auto i      = pgepi->idx_begin();
        Value *vIdx = llvm::cast<Value>(i);
        vCnt        = ConstantInt::get(vIdx->getType(), size);
        vCnt        = BinaryOperator::Create(Instruction::Mul, vCnt, vIdx, "processGEPI_", pgepi);
        i++;

        Type *currType = gepiDstType;

        for (auto e = pgepi->idx_end(); i != e; i++) {
            Value *vIdx = llvm::cast<Value>(i);

            Value *ciAddend = nullptr;
            if (ConstantInt *ciIdx = llvm::dyn_cast<ConstantInt>(vIdx)) {

                uint64_t val = computeOffsetInBytes(currType, ciIdx);
                ciAddend     = ConstantInt::get(ciIdx->getType(), val);

                Type *tmp = findTypeAtIndex(currType, ciIdx);
                assert(tmp && "Should always be defined");

                if (llvm::isa<StructType>(tmp)) {
                    currType = llvm::cast<StructType>(tmp);
                } else if (llvm::isa<ArrayType>(tmp)) {
                    currType = tmp;
                }
            } else if (ArrayType *pat = llvm::dyn_cast<ArrayType>(currType)) {

                uint64_t size = getTypeSizeInBytes(pat->getArrayElementType());
                Constant *pci = ConstantInt::get(vIdx->getType(), size);
                ciAddend      = BinaryOperator::Create(Instruction::Mul, pci, vIdx, "processGEPI_", pgepi);

                Type *tmp = findTypeAtIndex(currType, ciIdx);
                assert(tmp && "Should always be defined");

                if (llvm::isa<StructType>(tmp)) {
                    currType = llvm::cast<StructType>(tmp);
                } else if (llvm::isa<ArrayType>(tmp)) {
                    currType = tmp;
                }

            } else {
                assert(0 && "Figure out what to do here");
            }

            vCnt = BinaryOperator::Create(Instruction::Add, vCnt, ciAddend, "processGEPI_", pgepi);
        }

        Constant *Zero                     = ConstantInt::get(vIdx->getType(), 0);
        llvm::ArrayRef<llvm::Value *> Idxs = {Zero, Zero};

        Value *gepiNew = underlyingObject;
        if (gepiNew->getType()->getPointerElementType()->isArrayTy()) {
            gepiNew = GetElementPtrInst::Create(gepiNew->getType()->getPointerElementType(), gepiNew, Idxs, "processGEPI_2_", pgepi);
        }

        gepiNew = GetElementPtrInst::Create(gepiNew->getType()->getPointerElementType(), gepiNew, vCnt, "processGEPI_3_", pgepi);

        CastInst *ciNew = CastInst::CreatePointerCast(gepiNew, pgepi->getType(), "processGEPI_", pgepi);

        pgepi->replaceAllUsesWith(ciNew);
        pgepi->eraseFromParent();
    }

    virtual void processGEPI(GetElementPtrInst *pgepi, BitCastInst *pbci, Value *underlyingObject, ArrayType *gepiDstType)
    {

        Type *currType = gepiDstType->getArrayElementType();

        uint64_t size = getTypeSizeInBytes(currType);
        assert(size && "size not computed");

        Value *vCnt = nullptr;

        auto i      = pgepi->idx_begin();
        Value *vIdx = llvm::cast<Value>(i);
        vCnt        = ConstantInt::get(vIdx->getType(), size);
        vCnt        = BinaryOperator::Create(Instruction::Mul, vCnt, vIdx, "processGEPI_", pgepi);
        i++;

        StructType *pCurrStruct = nullptr;

        for (auto e = pgepi->idx_end(); i != e; i++) {
            Value *vIdx = llvm::cast<Value>(i);

            if (nullptr == pCurrStruct) {
                if (StructType *st = llvm::dyn_cast<StructType>(currType)) {
                    pCurrStruct = st;
                }
            }

            ConstantInt *pc = llvm::dyn_cast<ConstantInt>(vIdx);
            if (pc) {
                Type *pt = findTypeAtIndex(currType, pc);
                if (pt) {
                    currType              = pt;
                    ConstantInt *ciAddend = nullptr;
                    if (StructType *pst = llvm::dyn_cast<StructType>(pt)) {
                        uint64_t val = computeOffsetInBytes(pst, pc);
                        ciAddend     = ConstantInt::get(pc->getType(), val);
                        pCurrStruct  = pst;

                    } else {
                        uint64_t val = computeOffsetInBytes(pCurrStruct, pc);
                        ciAddend     = ConstantInt::get(pc->getType(), val);
                        vIdx         = BinaryOperator::Create(Instruction::Add, ciAddend, vIdx, "processGEPI_", pgepi);
                    }

                    vCnt = BinaryOperator::Create(Instruction::Add, vCnt, ciAddend, "processGEPI_", pgepi);
                }

            } else {

                size       = getTypeSizeInBytes(currType);
                Value *tmp = ConstantInt::get(vIdx->getType(), size);
                vIdx       = BinaryOperator::Create(Instruction::Mul, tmp, vIdx, "processGEPI_", pgepi);

                vCnt = BinaryOperator::Create(Instruction::Add, vCnt, vIdx, "processGEPI_", pgepi);
            }
        }

        Constant *Zero                     = ConstantInt::get(vIdx->getType(), 0);
        llvm::ArrayRef<llvm::Value *> Idxs = {Zero, Zero};

        Value *gepiNew = underlyingObject;
        if (gepiNew->getType()->getPointerElementType()->isArrayTy()) {
            gepiNew = GetElementPtrInst::Create(gepiNew->getType()->getPointerElementType(), gepiNew, Idxs, "processGEPI_0_", pgepi);
        }

        gepiNew = GetElementPtrInst::Create(gepiNew->getType()->getPointerElementType(), gepiNew, vCnt, "processGEPI_1_", pgepi);

        CastInst *ciNew = CastInst::CreatePointerCast(gepiNew, pgepi->getType(), "processGEPI_", pgepi);

        pgepi->replaceAllUsesWith(ciNew);
        pgepi->eraseFromParent();
    }

    virtual Value *stripBitCasts(Value *pInst)
    {
        if (BitCastInst *pbci = llvm::dyn_cast<BitCastInst>(pInst)) {
            return stripBitCasts(pbci->getOperand(0));
        }

        return pInst;
    }

    virtual void processGEPI(GetElementPtrInst *pgepi)
    {

        Type *pdst = Type::getInt8Ty(pMod->getContext());

        Value *vPtr = pgepi->getPointerOperand();
        if (BitCastInst *pbci = llvm::dyn_cast<BitCastInst>(vPtr)) {
            vPtr = stripBitCasts(pbci);

            Type *ptrType = vPtr->getType()->getPointerElementType();

            if (ArrayType *pat = llvm::dyn_cast<ArrayType>(ptrType)) {
                assert((pdst == pat->getArrayElementType()) && "ClamBCLowering did not do it's job");
            } else if (ptrType != pdst) {
                assert(0 && "ClamBCLowering did not do it's job");
            }

            Type *gepiDstType = pbci->getType()->getPointerElementType();
            if (StructType *pst = llvm::dyn_cast<StructType>(gepiDstType)) {
                processGEPI(pgepi, pbci, vPtr, pst);
            } else if (ArrayType *pat = llvm::dyn_cast<ArrayType>(gepiDstType)) {
                processGEPI(pgepi, pbci, vPtr, pat);
            }
        }
    }

    virtual void convertArrayStructGEPIsToI8(Function *pFunc)
    {
        std::vector<GetElementPtrInst *> gepis;
        for (auto i = pFunc->begin(), e = pFunc->end(); i != e; i++) {
            BasicBlock *pBB = llvm::cast<BasicBlock>(i);
            for (auto bi = pBB->begin(), be = pBB->end(); bi != be; bi++) {
                if (GetElementPtrInst *pgepi = llvm::dyn_cast<GetElementPtrInst>(bi)) {
                    if (ignoreGEPI(pgepi)) {
                        continue;
                    }
                    gepis.push_back(pgepi);
                }
            }
        }

        for (size_t i = 0; i < gepis.size(); i++) {
            GetElementPtrInst *pgepi = gepis[i];
            processGEPI(pgepi);
        }
    }

    PreservedAnalyses run(Module &m, ModuleAnalysisManager &MAM)
    {
        pMod = &m;
        for (auto i = pMod->begin(), e = pMod->end(); i != e; i++) {
            Function *pFunc = llvm::cast<Function>(i);

            convertArrayStructGEPIsToI8(pFunc);
        }

        for (auto i = pMod->begin(), e = pMod->end(); i != e; i++) {
            Function *pFunc = llvm::cast<Function>(i);

            fixCasts(pFunc);
        }

        return PreservedAnalyses::none();
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
};

// This part is the new way of registering your pass
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo()
{
    return {
        LLVM_PLUGIN_API_VERSION, "ClamBCPrepareGEPsForWriter", "v0.1",
        [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &FPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                    if (Name == "clambc-prepare-geps-for-writer") {
                        FPM.addPass(ClamBCPrepareGEPsForWriter());
                        return true;
                    }
                    return false;
                });
        }};
}
