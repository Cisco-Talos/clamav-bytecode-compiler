
#include <llvm/Pass.h>
#include "llvm/IR/Function.h"
#include "llvm/Support/raw_ostream.h"

#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

#include "clambc.h"

using namespace llvm;

namespace
{
struct ClamBCModule : public FunctionPass {
    static char ID;
    ClamBCModule()
        : FunctionPass(ID) {}

    bool runOnFunction(Function &F) override
    {
        return false;
    }
}; // end of struct ClamBCModule
} // end of anonymous namespace

char ClamBCModule::ID = 0;
static RegisterPass<ClamBCModule> X("clambc-module", "ClamBCModule Pass",
                                    false /* Only looks at CFG */,
                                    false /* Analysis Pass */);
