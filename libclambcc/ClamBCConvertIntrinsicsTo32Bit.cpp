#include "clambc.h"

#include <llvm/Pass.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Support/raw_ostream.h>

#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/PassManager.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/PassPlugin.h>

#include <llvm/IR/Dominators.h>
#include <llvm/IR/Constants.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>

#include <vector>

using namespace llvm;

namespace ClamBCConvertIntrinsicsTo32Bit
{

class ClamBCConvertIntrinsicsTo32Bit : public PassInfoMixin<ClamBCConvertIntrinsicsTo32Bit>
{

  public:
    static char ID;

    ClamBCConvertIntrinsicsTo32Bit() {}

    virtual ~ClamBCConvertIntrinsicsTo32Bit() {}

    PreservedAnalyses run(Module& mod, ModuleAnalysisManager& MAM)
    {
        bChanged = false;
        pMod     = &mod;

        initializeReplacements();

        for (auto i = pMod->begin(), e = pMod->end(); i != e; i++) {
            Function* pFunc = llvm::cast<Function>(i);
            processFunction(pFunc);
        }

        for (size_t i = 0; i < delLst.size(); i++) {
            delLst[i]->eraseFromParent();
        }

        if (bChanged) {
            return PreservedAnalyses::none();
        }

        return PreservedAnalyses::all();
    }

  protected:
    Module* pMod  = nullptr;
    bool bChanged = false;
    std::vector<CallInst*> delLst;

    typedef struct {
        llvm::Function* oldFunc;
        llvm::FunctionCallee newFunc;
        const size_t paramIdx;
    } Replacement;
    std::vector<Replacement> replacements;

    llvm::FunctionType* getMemset32Type()
    {
        LLVMContext& c = pMod->getContext();
        return FunctionType::get(Type::getVoidTy(c),
                                 {Type::getInt8PtrTy(c), Type::getInt8Ty(c), Type::getInt32Ty(c), Type::getInt1Ty(c)},
                                 false);
    }

    llvm::FunctionType* getMemcpy32Type()
    {
        LLVMContext& c = pMod->getContext();
        return FunctionType::get(Type::getVoidTy(c),
                                 {Type::getInt8PtrTy(c), Type::getInt8PtrTy(c), Type::getInt32Ty(c), Type::getInt1Ty(c)},
                                 false);
    }

    llvm::FunctionType* getMemmove32Type()
    {
        LLVMContext& c = pMod->getContext();
        return FunctionType::get(Type::getVoidTy(c),
                                 {Type::getInt8PtrTy(c), Type::getInt8PtrTy(c), Type::getInt32Ty(c), Type::getInt1Ty(c)},
                                 false);
    }

    void initializeReplacements()
    {
        /*There are different calls when you use the -no-opaque flags.*/

        /*memsets*/
        FunctionType* ft = getMemset32Type();
        Function* pFunc  = pMod->getFunction("llvm.memset.p0i8.i64");
        if (pFunc) {
            FunctionCallee rep = pMod->getOrInsertFunction("llvm.memset.p0i8.i32", ft);
            replacements.push_back({pFunc, rep, 2});
        }
        pFunc = pMod->getFunction("llvm.memset.p0.i64");
        if (pFunc) {
            FunctionCallee rep = pMod->getOrInsertFunction("llvm.memset.p0.i32", ft);
            replacements.push_back({pFunc, rep, 2});
        }

        /*memcpys*/
        ft    = getMemcpy32Type();
        pFunc = pMod->getFunction("llvm.memcpy.p0i8.p0i8.i64");
        if (pFunc) {
            FunctionCallee rep = pMod->getOrInsertFunction("llvm.memcpy.p0i8.p0i8.i32", ft);
            replacements.push_back({pFunc, rep, 2});
        }
        pFunc = pMod->getFunction("llvm.memcpy.p0.p0.i64");
        if (pFunc) {
            FunctionCallee rep = pMod->getOrInsertFunction("llvm.memcpy.p0.p0.i32", ft);
            replacements.push_back({pFunc, rep, 2});
        }

        /*memmoves*/
        ft    = getMemmove32Type();
        pFunc = pMod->getFunction("llvm.memmove.p0.p0.i64");
        if (pFunc) {
            FunctionCallee rep = pMod->getOrInsertFunction("llvm.memmove.p0.p0.i32", ft);
            replacements.push_back({pFunc, rep, 2});
        }
        pFunc = pMod->getFunction("llvm.memmove.p0i8.p0i8.i64");
        if (pFunc) {
            FunctionCallee rep = pMod->getOrInsertFunction("llvm.memmove.p0i8.p0i8.i32", ft);
            replacements.push_back({pFunc, rep, 2});
        }
    }

    void processFunction(Function* pFunc)
    {
        for (auto i = pFunc->begin(), e = pFunc->end(); i != e; i++) {
            BasicBlock* pBB = llvm::cast<BasicBlock>(i);
            processBasicBlock(pBB);
        }
    }

    void processBasicBlock(BasicBlock* pBB)
    {
        for (auto i = pBB->begin(), e = pBB->end(); i != e; i++) {
            if (CallInst* pci = llvm::dyn_cast<CallInst>(i)) {
                Function* f = pci->getCalledFunction();
                if (nullptr != f) {
                    for (size_t i = 0; i < replacements.size(); i++) {
                        if (replacements[i].oldFunc == f) {
                            convertCall(pci, replacements[i]);
                        }
                    }
                }
            }
        }
    }

    void convertCall(CallInst* pci, const Replacement& r)
    {
        std::vector<Value*> args;
        Type* i32Ty = Type::getInt32Ty(pMod->getContext());

        for (size_t i = 0; i < pci->arg_size(); i++) {
            Value* pv = pci->getArgOperand(i);
            if (r.paramIdx == i) {
                if (ConstantInt* ci = llvm::dyn_cast<ConstantInt>(pv)) {
                    pv = ConstantInt::get(i32Ty, ci->getValue().getLimitedValue());
                } else {
                    pv = CastInst::CreateTruncOrBitCast(pv, i32Ty, "ClamBCConvertIntrinsicsTo32Bit_trunc_", pci);
                }

                pci->setArgOperand(i, pv);
            }
        }

        pci->setCalledFunction(r.newFunc);
    }
};

} // namespace ClamBCConvertIntrinsicsTo32Bit

// This part is the new way of registering your pass
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo()
{
    return {
        LLVM_PLUGIN_API_VERSION, "ClamBCConvertIntrinsicsTo32Bit", "v0.1",
        [](PassBuilder& PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager& FPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                    if (Name == "clambc-convert-intrinsics-to-32Bit") {
                        FPM.addPass(ClamBCConvertIntrinsicsTo32Bit::ClamBCConvertIntrinsicsTo32Bit());
                        return true;
                    }
                    return false;
                });
        }};
}
