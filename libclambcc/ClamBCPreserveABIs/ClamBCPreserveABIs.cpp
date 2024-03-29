
#include <llvm/Pass.h>
#include "llvm/IR/Module.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/raw_ostream.h"

#include <llvm/IR/Dominators.h>

#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

#include "Common/clambc.h"
#include "Common/ClamBCUtilities.h"

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
class ClamBCPreserveABIs : public ModulePass
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
        std::string newname         = pFunc->getName();
        newname += "_fake";
        pFunctionType          = llvm::cast<FunctionType>(llvm::cast<PointerType>(pFunc->getType())->getElementType());
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
    static char ID;
    ClamBCPreserveABIs()
        : ModulePass(ID) {}

    virtual ~ClamBCPreserveABIs() {}

    bool runOnModule(Module &m) override
    {
        pMod = &m;

        if (removeFakeFunctions()) {
            return bChanged;
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

        return bChanged;
    }
}; // end of struct ClamBCPreserveABIs

} // end of anonymous namespace

char ClamBCPreserveABIs::ID = 0;
static RegisterPass<ClamBCPreserveABIs> X("clambc-preserve-abis", "Preserve ABIs",
                                          false /* Only looks at CFG */,
                                          false /* Analysis Pass */);
