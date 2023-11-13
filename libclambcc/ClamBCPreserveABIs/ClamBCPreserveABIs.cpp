
#include "clambc.h"
#include "ClamBCUtilities.h"

#include <llvm/Pass.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Support/raw_ostream.h>

#include <llvm/IR/Dominators.h>

#include <llvm/Transforms/IPO/PassManagerBuilder.h>
#include <llvm/Passes/PassPlugin.h>
#include <llvm/Passes/PassBuilder.h>

#include <sstream>
#include <string>
using namespace llvm;

namespace
{
/*
 * Preserve ABIs, and guarantee that -O3 doesn't remove arguments in functions
 * or calls.  We do this by calling an extern function declaration with all of
 * the parameters passed into the function, for each function in our module.
 * This guarantees that those * arguments cannot be removed, even if they are
 * unused.  This also prevents the optimizer from adding 'undef' values to the
 * call instruction when it sees that the argument is unused.
 *
 * This pass is run twice.  When it is run, it looks for 'clambc.fakefunctions'
 * metadata object.  If it does not find it (the first time), it adds calls
 * to fake functions.  If it does find it (the second time), it removes those
 * calls.
 */
class ClamBCPreserveABIs : public PassInfoMixin<ClamBCPreserveABIs>
{
  protected:
    llvm::Module *pMod = nullptr;
    bool bChanged      = false;
    std::vector<Function *> fakeFunctions;
    const char *const CLAMBC_FAKE_FUNCTION_METADATA_NAME = "clambc.fakefunctions";

    virtual void processFunction(Function *pFunc)
    {
        if (0 == pFunc->arg_size()) {
            return;
        }
        FunctionType *pFunctionType = llvm::dyn_cast<FunctionType>(pFunc->getType());
        std::string newname(pFunc->getName());
        pFunctionType = pFunc->getFunctionType();
        newname += "_fake";
        Function *fakeFunction = Function::Create(pFunctionType, Function::ExternalLinkage, newname, pFunc->getParent());
        fakeFunctions.push_back(fakeFunction);
        std::vector<Value *> args;
        for (auto i = pFunc->arg_begin(), e = pFunc->arg_end(); i != e; i++) {
            Value *pv = llvm::cast<Value>(i);
            args.push_back(pv);
        }

        Instruction *pInsertBefore = nullptr;
        for (auto i = pFunc->begin()->begin(), e = pFunc->begin()->end(); i != e; i++) {
            Instruction *pInst = llvm::cast<Instruction>(i);
            if (not llvm::isa<AllocaInst>(pInst)) {
                pInsertBefore = pInst;
                break;
            }
        }

        assert(pInsertBefore && "IMPOSSIBLE");
        if (pFunc->getReturnType()->isVoidTy()) {
            CallInst::Create(pFunctionType, fakeFunction, args, "", pInsertBefore);
        } else {
            CallInst::Create(pFunctionType, fakeFunction, args, "a", pInsertBefore);
        }
    }

    virtual void writeMetadata()
    {
        NamedMDNode *Node = pMod->getOrInsertNamedMetadata(CLAMBC_FAKE_FUNCTION_METADATA_NAME);
        for (size_t i = 0; i < fakeFunctions.size(); i++) {
            MDString *S = MDString::get(pMod->getContext(), llvm::StringRef(fakeFunctions[i]->getName()));
            MDNode *N   = MDNode::get(pMod->getContext(), S);
            Node->addOperand(N);
        }
        bChanged = true;
    }

    virtual bool removeFakeFunctions()
    {
        bool bRet         = false;
        NamedMDNode *node = pMod->getNamedMetadata(CLAMBC_FAKE_FUNCTION_METADATA_NAME);
        if (nullptr != node) {
            bRet = true;

            for (size_t i = 0; i < node->getNumOperands(); i++) {
                MDNode *mdn = node->getOperand(i);
                if (mdn->getNumOperands()) {
                    if (MDString *mds = llvm::dyn_cast<MDString>(mdn->getOperand(0))) {

                        Function *pf = pMod->getFunction(mds->getString());

                        std::set<llvm::Instruction *> insts;
                        std::set<llvm::GlobalVariable *> globs;
                        getDependentValues(pf, insts, globs);

                        assert(0 == globs.size() && "what globals");
                        for (auto i : insts) {
                            if (CallInst *pci = llvm::dyn_cast<CallInst>(i)) {
                                pci->eraseFromParent();
                            } else {
                                DEBUGERR << *i << "<END>\n";
                                assert(0 && "WHAT HAPPENED");
                            }
                        }
                        pf->eraseFromParent();

                    } else {
                        assert(0 && "What happened here?");
                    }
                }
            }

            node->eraseFromParent();
        }

        return bRet;
    }

  public:
    ClamBCPreserveABIs() {}

    virtual ~ClamBCPreserveABIs() {}

    virtual PreservedAnalyses run(Module &m, ModuleAnalysisManager &MAM)
    {
        pMod = &m;

        if (removeFakeFunctions()) {
            return PreservedAnalyses::none();
        }

        for (auto i = pMod->begin(), e = pMod->end(); i != e; i++) {
            Function *pFunc = llvm::cast<Function>(i);
            if (pFunc->isDeclaration()) {
                continue;
            }

            if (GlobalValue::InternalLinkage == pFunc->getLinkage()) {
                /*Set the linkage type to external so that the optimizer cannot remove the arguments.*/
                pFunc->setLinkage(GlobalValue::ExternalLinkage);
            }

            processFunction(pFunc);
        }

        writeMetadata();

        if (bChanged) {
            return PreservedAnalyses::none();
        }
        return PreservedAnalyses::all();
    }
}; // end of struct ClamBCPreserveABIs

} // end of anonymous namespace

// This part is the new way of registering your pass
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo()
{
    return {
        LLVM_PLUGIN_API_VERSION, "ClamBCPreserveABIs", "v0.1",
        [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &FPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                    if (Name == "clambc-preserve-abis") {
                        FPM.addPass(ClamBCPreserveABIs());
                        return true;
                    }
                    return false;
                });
        }};
}
