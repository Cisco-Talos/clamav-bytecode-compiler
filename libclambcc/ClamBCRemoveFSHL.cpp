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
 * Remove fshl intrinsic because it's not supported by our runtime.
 */
struct ClamBCRemoveFSHL : public PassInfoMixin<ClamBCRemoveFSHL> {
  protected:
    Module *pMod = nullptr;

    FunctionType *fshlType = nullptr;

    virtual llvm::FunctionType *getFSHLFunctionType(Type *functionArgType)
    {
        return FunctionType::get(functionArgType, {functionArgType, functionArgType, functionArgType}, false);
    }

    virtual llvm::Function *addFunction64(IntegerType *functionArgType, const char *const functionName)
    {
        /* TODO: Determine if this is necessary.*/
        /*
                This is an example function, needs to be converted to IR
                static uint8_t fshl8_noshifts(uint8_t left, uint8_t right, uint8_t shift){
                    uint8_t ret = 0;
                    uint8_t bitwidth = 8;
                    uint8_t bitIdx = (2 * bitwidth) - (shift % bitwidth) - 1;
                    uint8_t bit;

                    for (size_t i = 0; i < bitwidth; i++){
                        if (bitIdx >= bitwidth) {
                            bit = (left & (1 << (bitIdx - bitwidth))) ? 1 : 0;
                            ret |= (bit << ((bitwidth - 1) - i));
                        } else {
                            bit = right & (1 << bitIdx);
                            ret |= (bit << ((bitwidth - 1) - i));
                        }
                        bitIdx-- ;
                    }

                    return ret;
                }
                */
        assert(0 && "Unimplemented");
    }

    /*
     * addFunction was based on this.
     * static uint8_t fshl8_shifts(uint8_t left, uint8_t right, uint8_t shift){
     *      uint16_t tmp = (left << 8) | right;
     *      tmp <<= (shift % 8);
     *      tmp = (tmp & 0xff00) >> 8;
     *      return (uint8_t) (tmp & 0xff);
     * }
     */
    virtual llvm::Function *addFunction(IntegerType *functionArgType, const char *const functionName)
    {

        if (64 == functionArgType->getBitWidth()) {
            return addFunction64(functionArgType, functionName);
        }

        FunctionType *ft         = getFSHLFunctionType(functionArgType);
        IntegerType *i64         = IntegerType::get(pMod->getContext(), 64);
        ConstantInt *pciBitWidth = ConstantInt::get(i64, functionArgType->getBitWidth());

        llvm::Function *fshl = Function::Create(ft, GlobalValue::InternalLinkage, functionName, *pMod);
        Value *pLeft         = fshl->getArg(0);
        Value *pRight        = fshl->getArg(1);
        Value *pShift        = fshl->getArg(2);
        BasicBlock *pEntry   = BasicBlock::Create(pMod->getContext(), "entry", fshl);

        pLeft  = CastInst::CreateZExtOrBitCast(pLeft, i64, "zext_", pEntry);
        pLeft  = BinaryOperator::Create(Instruction::Shl, pLeft, pciBitWidth, "shl_", pEntry);
        pRight = CastInst::CreateZExtOrBitCast(pRight, i64, "zext_", pEntry);
        pLeft  = BinaryOperator::Create(Instruction::Or, pLeft, pRight, "or", pEntry);
        pShift = CastInst::CreateZExtOrBitCast(pShift, i64, "zext_", pEntry);

        pShift = BinaryOperator::Create(Instruction::URem, pShift, pciBitWidth, "urem_", pEntry);
        pLeft  = BinaryOperator::Create(Instruction::Shl, pLeft, pShift, "shl_", pEntry);

        pLeft = BinaryOperator::Create(Instruction::LShr, pLeft, pciBitWidth, "shr_", pEntry);
        pLeft = CastInst::CreateTruncOrBitCast(pLeft, functionArgType, "trunc_", pEntry);
        ReturnInst::Create(pMod->getContext(), pLeft, pEntry);

        return fshl;
    }

    virtual bool replaceCalls(const char *const intrinsicName, const char *functionName, IntegerType *functionArgType)
    {
        std::vector<CallInst *> calls;
        gatherCallsToIntrinsic(pMod, intrinsicName, calls);
        if (calls.size()) {
            Function *fshl = addFunction(functionArgType, functionName);
            replaceAllCalls(getFSHLFunctionType(functionArgType), fshl, calls, "ClamBCRemoveFSHL_");

            return true;
        }
        return false;
    }

  public:
    virtual ~ClamBCRemoveFSHL() {}

    /*TODO: Add this to validator.*/
    PreservedAnalyses run(Module &m, ModuleAnalysisManager &MAM)
    {
        pMod = &m;

        bool bRet = replaceCalls("llvm.fshl.i32", ".fshl.i32", Type::getInt32Ty(pMod->getContext()));
        bRet |= replaceCalls("llvm.fshl.i16", ".fshl.i16", Type::getInt16Ty(pMod->getContext()));
        bRet |= replaceCalls("llvm.fshl.i8", ".fshl.i8", Type::getInt16Ty(pMod->getContext()));

        if (bRet) {
            return PreservedAnalyses::none();
        }

        return PreservedAnalyses::all();
    }

}; // end of struct ClamBCRemoveFSHL

} // end of anonymous namespace

// This part is the new way of registering your pass
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo()
{
    return {
        LLVM_PLUGIN_API_VERSION, "ClamBCRemoveFSHL", "v0.1",
        [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &FPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                    if (Name == "clambc-remove-fshl") {
                        FPM.addPass(ClamBCRemoveFSHL());
                        return true;
                    }
                    return false;
                });
        }};
}
