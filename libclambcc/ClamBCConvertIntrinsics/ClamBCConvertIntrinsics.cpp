
#include <llvm/Pass.h>
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/raw_ostream.h"

#include "llvm/IR/DerivedTypes.h"

#include <llvm/IR/Dominators.h>

#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

#include "Common/clambc.h"

#include <vector>

using namespace llvm;

namespace
{

class ConvertIntrinsics : public ModulePass
{

  public:
    static char ID;

    ConvertIntrinsics()
        : ModulePass(ID) {}

    virtual ~ConvertIntrinsics() {}

    virtual bool runOnModule(Module& mod)
    {
        bChanged = false;
        pMod     = &mod;

        for (auto i = pMod->begin(), e = pMod->end(); i != e; i++) {
            Function* pFunc = llvm::cast<Function>(i);
            processFunction(pFunc);
        }

        for (size_t i = 0; i < delLst.size(); i++) {
            delLst[i]->eraseFromParent();
        }

        return bChanged;
    }

  protected:
    Module* pMod  = nullptr;
    bool bChanged = false;
    std::vector<CallInst*> delLst;

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
                if (Function* f = llvm::dyn_cast<Function>(pci->getCalledValue())) {
                    if ("llvm.memset.p0i8.i64" == f->getName()) {
                        convertMemset(pci);
                    }
                }
            }
        }
    }

    void convertMemset(CallInst* pci)
    {
        std::vector<Value*> args;
        Type* i32Ty = Type::getInt32Ty(pMod->getContext());

        for (size_t i = 0; i < pci->getNumArgOperands(); i++) {
            Value* pv = pci->getArgOperand(i);
            if (2 == i) {
                if (ConstantInt* ci = llvm::dyn_cast<ConstantInt>(pv)) {
                    pv = ConstantInt::get(i32Ty, ci->getValue().getLimitedValue());
                } else {
                    pv = CastInst::CreateTruncOrBitCast(pv, i32Ty, "ConvertIntrinsics_trunc_", pci);
                }
            }

            args.push_back(pv);
        }

        Constant* f = getNewMemset();
        CallInst::Create(getMemsetType(), f, args, "", pci);
        delLst.push_back(pci);
    }

    llvm::Constant* getNewMemset()
    {
        static llvm::Constant* ret = nullptr;

        if (nullptr == ret) {

            FunctionType* retType = getMemsetType();
            ret                   = pMod->getOrInsertFunction("llvm.memset.p0i8.i32", retType);

            assert(ret && "Could not get memset");
        }

        return ret;
    }

    llvm::FunctionType* getMemsetType()
    {
        static FunctionType* retType = nullptr;
        if (nullptr == retType) {
            LLVMContext& c = pMod->getContext();
            retType        = FunctionType::get(Type::getVoidTy(c),
                                        {Type::getInt8PtrTy(c), Type::getInt8Ty(c), Type::getInt32Ty(c), Type::getInt1Ty(c)},
                                        false);
        }
        return retType;
    }
};

} // end of anonymous namespace

char ConvertIntrinsics::ID = 0;
static RegisterPass<ConvertIntrinsics> XX("clambc-convert-intrinsics", "Convert Intrinsics to 32-bit",
                                          false /* Only looks at CFG */,
                                          false /* Analysis Pass */);
