#include "clambc.h"
#include "ClamBCUtilities.h"
#include "ClamBCModule.h"

#include <llvm/Pass.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Analysis/ValueTracking.h>

#include <llvm/IR/Dominators.h>

#include <llvm/Transforms/IPO/PassManagerBuilder.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/PassPlugin.h>

using namespace llvm;

#include <set>

/*
 * This Pass is only needed for 0.103 on Windows, so when we no longer need to support 0.103, it can be removed.
 */

namespace
{
class ClamBCRemovePointerPHIs : public PassInfoMixin<ClamBCRemovePointerPHIs>
{
  protected:
    llvm::Module *pMod = nullptr;

    std::vector<PHINode *> gatherPHIs(llvm::Function *pFunc)
    {

        std::vector<PHINode *> ret;

        for (auto i = pFunc->begin(), e = pFunc->end(); i != e; i++) {
            BasicBlock *pBB = llvm::cast<BasicBlock>(i);
            for (auto bbi = pBB->begin(), bbe = pBB->end(); bbi != bbe; bbi++) {
                if (PHINode *pn = llvm::dyn_cast<PHINode>(bbi)) {
                    ret.push_back(pn);
                }
            }
        }

        return ret;
    }

    Value *getOrigValue(Value *pv)
    {
        Value *pRet = pv;

        if (GetElementPtrInst *gepi = llvm::dyn_cast<GetElementPtrInst>(pv)) {
            Value *tmp = gepi->getPointerOperand();
            pRet       = getOrigValue(tmp);
        }

        if (CastInst *ci = llvm::dyn_cast<BitCastInst>(pv)) {
            Value *tmp = ci->getOperand(0);
            pRet       = getOrigValue(tmp);
        }

        return pRet;
    }

    Value *findBasePointer(PHINode *pn)
    {

        Value *pRet = nullptr;

        std::vector<Value *> vals;
        for (size_t i = 0; i < pn->getNumIncomingValues(); i++) {
            Value *pv = pn->getIncomingValue(i);
            pv        = getOrigValue(pv);

            if (pv != pn) {
                vals.push_back(pv);
            }
        }

        if (1 != vals.size()) {
            /*
             * This may not be an issue, but want to investigate it.
             * This would be due to the phi node not being the same base pointer with a different index.
             */

            return nullptr;
        } else {
            pRet = vals[0];
        }

        return pRet;
    }

    /*Returns true if phiNode is a dependent instruction of pVal.*/
    bool phiIsDependent(Value *pVal, PHINode *phiNode)
    {

        std::set<llvm::Instruction *> insts;
        std::set<llvm::GlobalVariable *> globs;

        getDependentValues(pVal, insts, globs);

        for (auto i : insts) {
            if (phiNode == i) {
                return true;
            }
        }

        return false;
    }

    BranchInst *findBranch(BasicBlock *bi)
    {
        BranchInst *ret = nullptr;
        for (auto i = bi->begin(), e = bi->end(); i != e; i++) {
            if (BranchInst *bi = llvm::dyn_cast<BranchInst>(i)) {
                ret = bi;
                break;
            }
        }

        return ret;
    }

    BasicBlock *findPredecessor(BasicBlock *dst, BasicBlock *src,
                                std::vector<BasicBlock *> &omit,
                                std::vector<BasicBlock *> &visited)
    {

        if (std::find(visited.begin(), visited.end(), src) != visited.end()) {
            return nullptr;
        }
        visited.push_back(src);

        BranchInst *bi = findBranch(src);
        if (nullptr == bi) {
            return nullptr;
        }

        for (size_t i = 0; i < bi->getNumSuccessors(); i++) {
            BasicBlock *bb = bi->getSuccessor(i);
            if (bb == dst) {
                if (std::find(omit.begin(), omit.end(), src) == omit.end()) {
                    omit.push_back(src);
                    return src;
                }
            }

            BasicBlock *res = findPredecessor(dst, bb, omit, visited);
            if (nullptr != res) {
                return res;
            }
        }

        return nullptr;
    }

    BasicBlock *findPredecessor(BasicBlock *dst, BasicBlock *src, std::vector<BasicBlock *> &omit)
    {
        std::vector<BasicBlock *> visited;
        BasicBlock *ret = findPredecessor(dst, src, omit, visited);
        return ret;
    }

    Instruction *findFirstNonPHI(BasicBlock *bb)
    {
        for (auto i = bb->begin(), e = bb->end(); i != e; i++) {
            Instruction *inst = llvm::dyn_cast<Instruction>(i);
            if (not llvm::isa<PHINode>(inst)) {
                return inst;
            }
        }

        assert(0 && "Broken block, no terminator");

        return nullptr;
    }

    bool handlePHI(PHINode *pn)
    {
        if (not pn->getType()->isPointerTy()) {
            return false;
        }

        Value *pBasePtr = findBasePointer(pn);
        if (nullptr == pBasePtr) { /*No unique base pointer.*/
            return false;
        }

        IntegerType *pType = Type::getInt64Ty(pMod->getContext());
        Constant *zero     = ConstantInt::get(pType, 0);
        Value *initValue   = zero;
        PHINode *idxNode   = PHINode::Create(pType, pn->getNumIncomingValues(), "ClamBCRemovePointerPHIs_idx_", pn);

        assert(0 == idxNode->getNumIncomingValues() && "Just a test");

        std::vector<BasicBlock *> omitNodes;

        for (size_t i = 0; i < pn->getNumIncomingValues(); i++) {
            Value *incoming = getOrigValue(pn->getIncomingValue(i));

            // If this value is dependent on the phi node, then it cannot
            // be what the PHINode was initialized to the first time the
            // block was entered, which is what we are looking for.
            if (not(phiIsDependent(incoming, pn))) {
                continue;
            }

            if (GetElementPtrInst *p = llvm::dyn_cast<GetElementPtrInst>(pn->getIncomingValue(i))) {
                // Replace initValue with the index operand of the GetElementPtrInst here.
                for (auto idx = p->idx_begin(), idxe = p->idx_end(); idx != idxe; idx++) {
                    initValue = llvm::cast<Value>(idx);
                }
                if (initValue->getType() != pType) {
                    initValue = CastInst::CreateZExtOrBitCast(initValue, pType, "ClamBCRemovePointerPHIs_idx_cast_", p);
                }
            }

            if (pBasePtr == incoming) {
                idxNode->addIncoming(initValue, pn->getIncomingBlock(i));
                omitNodes.push_back(pn->getIncomingBlock(i));
                break;
            }
        }

        assert(0 < idxNode->getNumIncomingValues() && "Did not find the pointer");

        std::vector<Instruction *> newInsts;
        Instruction *insPt = findFirstNonPHI(pn->getParent());

        if (pBasePtr->getType() != pn->getType()) {
            pBasePtr = CastInst::CreatePointerCast(pBasePtr, pn->getType(), "ClamBCRemovePointerPHIs_cast_", insPt);
        }

        PointerType *pt = llvm::dyn_cast<PointerType>(pBasePtr->getType());
        if (nullptr == pt) {
            assert(0 && "This pass is only for pointer phis, how did we get here???");
        }
        Type *elementType = pt->getPointerElementType();

        Instruction *gepiNew = GetElementPtrInst::Create(elementType, pBasePtr, idxNode, "ClamBCRemovePointerPHIs_gepi_", insPt);
        if (pn->getType() != gepiNew->getType()) {
            gepiNew = CastInst::CreatePointerCast(gepiNew, pn->getType(), "ClamBCRemovePointerPHIs_cast_", insPt);
        }
        newInsts.push_back(gepiNew);

        for (auto i = pn->user_begin(), e = pn->user_end(); i != e; i++) {
            User *pu = llvm::dyn_cast<User>(*i);

            if (GetElementPtrInst *pgepi = llvm::dyn_cast<GetElementPtrInst>(pu)) {
                if (phiIsDependent(pgepi, pn)) {

                    assert(2 == pgepi->getNumOperands() && "Handle the case of more than 2 operands");

                    Value *incVal = pgepi->getOperand(1);

                    if (incVal->getType() != pType) {
                        incVal = CastInst::CreateIntegerCast(incVal, pType, false, "ClamBCRemovePointerPHIs_cast_", pgepi);
                    }

                    Instruction *add = BinaryOperator::Create(Instruction::Add, idxNode, incVal, "ClamBCRemovePointerPHIs_add_", pgepi);
                    BasicBlock *pred = findPredecessor(idxNode->getParent(), pgepi->getParent(), omitNodes);
                    assert(pred && "Could not find predecessor");
                    idxNode->addIncoming(add, pred);

                    Instruction *gepiNew2 = gepiNew;
                    if (pgepi->getType() != gepiNew2->getType()) {
                        gepiNew2 = CastInst::CreatePointerCast(gepiNew2, pgepi->getType(), "ClamBCRemovePointerPHIs_cast_", pgepi);
                        newInsts.push_back(gepiNew2);
                    }

                    pgepi->replaceAllUsesWith(gepiNew2);
                }
            }
        }

        std::vector<Instruction *> users;
        for (auto i = pn->user_begin(), e = pn->user_end(); i != e; i++) {
            if (Instruction *pUser = llvm::dyn_cast<Instruction>(*i)) {
                users.push_back(pUser);
            }
        }

        for (size_t i = 0; i < users.size(); i++) {
            Instruction *pUser = users[i];

            for (size_t j = 0; j < newInsts.size(); j++) {
                Instruction *pJ = newInsts[j];
                for (size_t k = 0; k < pUser->getNumOperands(); k++) {
                    if (pUser->getOperand(k) == pn) {
                        pUser->setOperand(k, pJ);
                        break;
                    }
                }
            }
        }

        return true;
    }

    /*The idea here is that we get the insertion point for where our calculated value
     * will be saved.  pInst is the value we want to save, so it will have to be*/
    Instruction *getInsertionPoint(Instruction *pInst)
    {
        BasicBlock *pBB   = pInst->getParent();
        bool canBreak     = false;
        Instruction *pRet = nullptr;
        for (auto i = pBB->begin(), e = pBB->end(); i != e; i++) {
            pRet = llvm::cast<Instruction>(i);
            if (canBreak && (not llvm::isa<PHINode>(pRet))) {
                break;
            }
            if (pRet == pInst) {
                canBreak = true;
            }
        }
        return pRet;
    }

    /* Load the value from our AllocaInst, and
     * replace the PHINode everywhere it is used.*/
    virtual void replaceUses(PHINode *pn, AllocaInst *pai)
    {
        std::vector<Instruction *> users;
        for (auto i = pn->user_begin(), e = pn->user_end(); i != e; i++) {
            if (Instruction *pUser = llvm::dyn_cast<Instruction>(*i)) {
                users.push_back(pUser);
            }
        }

        for (size_t i = 0; i < users.size(); i++) {
            Instruction *pUser = users[i];
            Instruction *insPt = nullptr;

            if (PHINode *pnUser = llvm::dyn_cast<PHINode>(pUser)) {
                for (size_t j = 0; j < pnUser->getNumIncomingValues(); j++) {
                    if (pn == pnUser->getIncomingValue(j)) {
                        insPt = pnUser->getIncomingBlock(j)->getTerminator();
                        break;
                    }
                }
            } else {
                insPt = pUser;
            }

            LoadInst *pli = new LoadInst(pn->getType(), pai, "ClamBCRemovePointerPHIs_load_", insPt);
            for (size_t j = 0; j < pUser->getNumOperands(); j++) {
                if (pn == pUser->getOperand(j)) {
                    pUser->setOperand(j, pli);
                    break;
                }
            }
        }
    }

  public:
    ClamBCRemovePointerPHIs() {}

    /*This is only necessary for 0.103 on windows.*/
    virtual PreservedAnalyses run(Module &m, ModuleAnalysisManager &mam)
    {
        pMod     = &m;
        bool ret = false;

        for (auto i = pMod->begin(), e = pMod->end(); i != e; i++) {
            llvm::Function *pFunc = llvm::dyn_cast<Function>(i);
            if (nullptr == pFunc) {
                continue;
            }
            std::vector<PHINode *> phis = gatherPHIs(pFunc);
            for (size_t i = 0; i < phis.size(); i++) {
                PHINode *pn = phis[i];

                if (handlePHI(pn)) {
                    ret = true;
                }
            }
        }

        if (ret) {
            return PreservedAnalyses::none();
        }
        return PreservedAnalyses::all();
    }

}; // end of class ClambcRemovePointerPHIs

} // end of anonymous namespace

// This part is the new way of registering your pass
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo()
{
    return {
        LLVM_PLUGIN_API_VERSION, "ClamBCRemovePointerPHIs", "v0.1",
        [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &FPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                    if (Name == "clambc-remove-pointer-phis") {
                        FPM.addPass(ClamBCRemovePointerPHIs());
                        return true;
                    }
                    return false;
                });
        }};
}
