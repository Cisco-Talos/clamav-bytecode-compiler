
#include <llvm/Pass.h>
#include "llvm/IR/Function.h"
#include "llvm/Support/raw_ostream.h"

#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

using namespace llvm;

namespace
{
struct ClamBCSplitter : public FunctionPass {
    static char ID;
    ClamBCSplitter()
        : FunctionPass(ID) {}

    bool runOnFunction(Function &F) override
    {
        //      llvm::errs() << "<" << __LINE__ << ">" << "THIS IS NOT A CLAM PASS.  IT IS JUST A PLACEHOLDER TO DETERMINE IF WE NEED THE FUNCTIONALITY OF THE GEPSplitter that no longer exists (probably not)" << "<END>\n";
        //      llvm::errs() << "<" << __LINE__ << ">" << "ClamBCSplitter UMIMPLEMENTED" << "<END>\n";
        return false;
    }
}; // end of struct ClamBCSplitter
} // end of anonymous namespace

char ClamBCSplitter::ID = 0;
static RegisterPass<ClamBCSplitter> X("clambc-gepsplitter-placeholder", "ClamBCSplitter Pass",
                                      false /* Only looks at CFG */,
                                      false /* Analysis Pass */);
