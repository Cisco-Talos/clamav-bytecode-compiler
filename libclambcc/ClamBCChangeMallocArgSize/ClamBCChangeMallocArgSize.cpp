
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
class ChangeMallocArgSize : public ModulePass
{
  protected:
    std::vector<PHINode*> changeValues;

    Module* pMod         = nullptr;
    IntegerType* dstType = nullptr;

    void addChangeValue(PHINode* pv)
    {
        if (llvm::isa<Constant>(pv)) {
            return;
        }

        if (changeValues.end() == std::find(changeValues.begin(), changeValues.end(), pv)) {
            changeValues.push_back(pv);
        }
    }

    void findSizes(BasicBlock* pBB)
    {
        for (auto i = pBB->begin(), e = pBB->end(); i != e; i++) {
            CallInst* pCall = llvm::dyn_cast<CallInst>(i);
            if (pCall) {
                if ("malloc" == pCall->getCalledValue()->getName()) {
                    Value* pv = pCall->getOperand(0);
                    if (PHINode* pn = llvm::dyn_cast<PHINode>(pv)) {
                        addChangeValue(pn);
                    }
                }
            }
        }
    }

    void findSizes(Function* pFunc)
    {
        for (auto i = pFunc->begin(), e = pFunc->end(); i != e; i++) {
            findSizes(llvm::cast<BasicBlock>(i));
        }
    }

    void findSizes()
    {
        for (auto i = pMod->begin(), e = pMod->end(); i != e; i++) {
            findSizes(llvm::cast<Function>(i));
        }
    }

    /* Yes, I know there is a "getTerminator" function, but I have come across blocks 
     * that have more than one branch instruction (I think it is a bug in the runtime), but
     * until that is resolved, I want to use this function.
     */
    Instruction* findTerminator(BasicBlock* pb)
    {
        Instruction* inst = nullptr;
        for (auto i = pb->begin(), e = pb->end(); i != e; i++) {
            inst = llvm::cast<Instruction>(i);
            if (llvm::isa<BranchInst>(inst) || llvm::isa<ReturnInst>(inst)) {
                break;
            }
        }
        assert(inst && "Impossible, there is always a terminator.");
        assert(inst == pb->getTerminator() && "How did this happen");

        return inst;
    }

    PHINode* getNewPHI(PHINode* pn)
    {

        PHINode* newPN = PHINode::Create(dstType, pn->getNumIncomingValues(), "ChangeMallocArgSize_", pn);
        for (size_t i = 0; i < pn->getNumIncomingValues(); i++) {
            Value* pv          = pn->getIncomingValue(i);
            BasicBlock* pb     = pn->getIncomingBlock(i);
            Instruction* bTerm = findTerminator(pb);

            Instruction* pNew = CastInst::CreateZExtOrBitCast(pv, dstType, "ChangeMallocArgSize_zext_", bTerm);
            newPN->addIncoming(pNew, pb);
        }

        return newPN;
    }

    void fixBitWidths()
    {

        for (size_t i = 0; i < changeValues.size(); i++) {
            PHINode* pn = changeValues[i];

            if (dstType != pn->getType()) {
                PHINode* pRep = getNewPHI(pn);

                std::vector<Instruction*> insts;

                for (auto i = pn->user_begin(), e = pn->user_end(); i != e; i++) {
                    Instruction* inst = llvm::cast<Instruction>(*i);
                    insts.push_back(inst);
                }
                for (size_t i = 0; i < insts.size(); i++) {
                    Instruction* inst = insts[i];

                    if (PHINode* pn2 = llvm::dyn_cast<PHINode>(inst)) {
                        DEBUGERR << *pn2 << "<END>\n";
                        assert(0 && "SHOULD NEVER HAPPEN");
                    } else {
                        auto* val = CastInst::CreateTruncOrBitCast(pRep, pn->getType(), "ChangeMallocArgSize_trunc_", inst);

                        for (size_t j = 0; j < inst->getNumOperands(); j++) {
                            if (inst->getOperand(j) == pn) {
                                inst->setOperand(j, val);
                                break;
                            }
                        }
                    }
                }

                pn->eraseFromParent();
            }
        }
    }

  public:
    static char ID;
    ChangeMallocArgSize()
        : ModulePass(ID)
    {
    }

    virtual bool runOnModule(Module& m) override
    {
        pMod    = &m;
        dstType = Type::getInt64Ty(pMod->getContext());

        findSizes();

        fixBitWidths();

        return true;
    }
}; // end of struct ChangeMallocArgSize
} // end of anonymous namespace

char ChangeMallocArgSize::ID = 0;
static RegisterPass<ChangeMallocArgSize> X("clambc-change-malloc-arg-size", "ChangeMallocArgSize Pass",
                                           false /* Only looks at CFG */,
                                           false /* Analysis Pass */);
