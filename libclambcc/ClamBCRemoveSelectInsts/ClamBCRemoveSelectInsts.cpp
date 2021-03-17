
#include <llvm/Pass.h>
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/raw_ostream.h"

#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

#include "Common/clambc.h"

using namespace llvm;

namespace
{
class RemoveSelectInsts : public ModulePass
{
  protected:
    bool bChanged = false;
    Module* pMod  = nullptr;

    void processBasicBlock(BasicBlock* pBB, std::vector<SelectInst*>& selects)
    {
        for (auto i = pBB->begin(), e = pBB->end(); i != e; i++) {
            SelectInst* pSelect = llvm::dyn_cast<SelectInst>(i);
            if (pSelect) {
                selects.push_back(pSelect);
            }
        }
    }

    void processFunction(Function* pFunc, std::vector<SelectInst*>& selects)
    {
        for (auto i = pFunc->begin(), e = pFunc->end(); i != e; i++) {
            BasicBlock* pBB = llvm::cast<BasicBlock>(i);
            processBasicBlock(pBB, selects);
        }
    }

    std::vector<SelectInst*> gatherSelects()
    {
        std::vector<SelectInst*> selects;
        for (auto i = pMod->begin(), e = pMod->end(); i != e; i++) {
            Function* pFunc = llvm::cast<Function>(i);

            processFunction(pFunc, selects);
        }

        return selects;
    }

    Instruction* getAllocaInsertPoint(SelectInst* pSelect)
    {
        BasicBlock* entryBlock = llvm::cast<BasicBlock>(pSelect->getParent()->getParent()->begin());
        for (auto i = entryBlock->begin(), e = entryBlock->end(); i != e; i++) {
            Instruction* pInst = llvm::cast<Instruction>(i);
            if (not llvm::isa<AllocaInst>(pInst)) {
                return pInst;
            }
        }

        assert(0 && "MALFORMED BASIC BLOCK");
        return nullptr;
    }

    void replaceSelectInst(SelectInst* pSelect)
    {

        Instruction* insertBefore = getAllocaInsertPoint(pSelect);
        AllocaInst* pAlloca       = new AllocaInst(pSelect->getType(),
                                             pMod->getDataLayout().getProgramAddressSpace(),
                                             "ClamBCRemoveSelectInst", insertBefore);

        BasicBlock* pBB = llvm::cast<BasicBlock>(pSelect->getParent());

        BasicBlock* pSplit = pBB->splitBasicBlock(pSelect, "ClamBCRemoveSelectInst");
        new StoreInst(pSelect->getFalseValue(), pAlloca, pBB->getTerminator());

        new StoreInst(pSelect->getTrueValue(), pAlloca, pSelect);

        BasicBlock* pSplit2 = pSplit->splitBasicBlock(pSelect, "ClamBCRemoveSelectInst");
        BranchInst::Create(pSplit, pSplit2, pSelect->getCondition(), pBB->getTerminator());

        LoadInst* pLoad = new LoadInst(pAlloca->getType()->getPointerElementType(), pAlloca, "ClamBCRemoveSelectInst", pSelect);
        pSelect->replaceAllUsesWith(pLoad);

        pBB->getTerminator()->eraseFromParent();
        pSelect->eraseFromParent();
    }

  public:
    static char ID;
    RemoveSelectInsts()
        : ModulePass(ID) {}

    virtual bool runOnModule(Module& m) override
    {
        pMod = &m;

        std::vector<SelectInst*> selects = gatherSelects();
        for (size_t i = 0; i < selects.size(); i++) {
            SelectInst* pSelect = selects[i];

            replaceSelectInst(pSelect);
        }

        return bChanged;
    }
}; // end of struct RemoveSelectInsts
} // end of anonymous namespace

char RemoveSelectInsts::ID = 0;
static RegisterPass<RemoveSelectInsts> X("remove-selects", "RemoveSelectInsts Pass",
                                         false /* Only looks at CFG */,
                                         false /* Analysis Pass */);
