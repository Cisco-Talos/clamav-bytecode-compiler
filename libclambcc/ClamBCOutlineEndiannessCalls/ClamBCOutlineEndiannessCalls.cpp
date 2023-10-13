
#include <llvm/Pass.h>
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/raw_ostream.h"

#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/PassPlugin.h>

#include "Common/clambc.h"

using namespace llvm;

namespace OutlineEndiannessCalls {
    class OutlineEndiannessCalls : public PassInfoMixin<OutlineEndiannessCalls> 
    {
        protected:
            bool bChanged = false;
            Module* pMod  = nullptr;

            void findCalls(BasicBlock* pBB, std::vector<CallInst*>& calls)
            {
                for (auto i = pBB->begin(), e = pBB->end(); i != e; i++) {
                    CallInst* pCall = llvm::dyn_cast<CallInst>(i);
                    if (pCall) {
                        Function * pFunc = pCall->getCalledFunction();
                        if (pFunc && ("__is_bigendian" == pFunc->getName())) {
                            calls.push_back(pCall);
                        }
                    }
                }
            }

            void findCalls(Function* pFunc, std::vector<CallInst*>& calls)
            {
                for (auto i = pFunc->begin(), e = pFunc->end(); i != e; i++) {
                    findCalls(llvm::cast<BasicBlock>(i), calls);
                }
            }

            std::vector<CallInst*> findCalls()
            {
                std::vector<CallInst*> ret;
                for (auto i = pMod->begin(), e = pMod->end(); i != e; i++) {
                    findCalls(llvm::cast<Function>(i), ret);
                }

                return ret;
            }

            Function* getNewEndiannessFunction(CallInst* ci)
            {
                Function* func = ci->getCalledFunction();
                assert(func && "HOW DID WE GET HERE?");

                //FunctionType* pft = llvm::cast<FunctionType>(func->getType()->getPointerElementType());
                FunctionType* pft = func->getFunctionType();

                Function* pNew = Function::Create(pft, GlobalValue::PrivateLinkage, "new__is_bigendian", pMod);
                assert(pNew && "Could not create function");

                BasicBlock* pEntry = BasicBlock::Create(pMod->getContext(), "entry", pNew, nullptr);
                assert(pEntry && "Could not create basic block");

                CallInst* pCallInst = CallInst::Create(func, "newCall", pEntry);
                assert(pCallInst && "Could not create call instruction");

                ReturnInst* pReturnInst = ReturnInst::Create(pMod->getContext(), pCallInst, pEntry);
                assert(pReturnInst && "Could not create return instruction.");

                pNew->addFnAttr(Attribute::OptimizeNone);
                pNew->addFnAttr(Attribute::NoInline);

                //TODO: Test with NoInline, but not OptimizeNone (Hopefully I can have the function return 1 or 0, and
                //not have to actually call the function.

                return pNew;
            }

        public:
            OutlineEndiannessCalls()
            {}

            //virtual bool runOnModule(Module& m) override
            virtual PreservedAnalyses run(Module & m, ModuleAnalysisManager & MAM)
            {
                pMod = &m;

                std::vector<CallInst*> calls = findCalls();

                if (0 == calls.size()) {
                    return PreservedAnalyses::all();
                }

                Function* pNew = getNewEndiannessFunction(calls[0]);

                for (size_t i = 0; i < calls.size(); i++) {
                    CallInst* pNewCall = CallInst::Create(pNew, "OutlineEndiannessCalls_", calls[i]);
                    calls[i]->replaceAllUsesWith(pNewCall);
                    calls[i]->eraseFromParent();
                }

                if (bChanged){
                    return PreservedAnalyses::none();
                }
                return PreservedAnalyses::all();
            }
    }; // end of struct OutlineEndiannessCalls
} // end of OutlineEndiannessCalls namespace

#if 0
char OutlineEndiannessCalls::ID = 0;
static RegisterPass<OutlineEndiannessCalls> X("clambc-outline-endianness-calls", "OutlineEndiannessCalls TEST Pass",
        false /* Only looks at CFG */,
        false /* Analyses Pass */);
#else
// This part is the new way of registering your pass
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {
    return {
        LLVM_PLUGIN_API_VERSION, "OutlineEndiannessCalls", "v0.1",
            [](PassBuilder &PB) {
                PB.registerPipelineParsingCallback(
                        [](StringRef Name, ModulePassManager &FPM,
                            ArrayRef<PassBuilder::PipelineElement>) {
                        if(Name == "clambc-outline-endianness-calls"){
                        FPM.addPass(OutlineEndiannessCalls::OutlineEndiannessCalls());
                        return true;
                        }
                        return false;
                        }
                        );
            }
    };
}



#endif
