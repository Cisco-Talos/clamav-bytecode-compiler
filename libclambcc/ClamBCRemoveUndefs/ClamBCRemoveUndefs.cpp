
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
using namespace llvm;

namespace
{
/*
     * This pass requires -mem2reg before it (TEMPORARILY) 
     * and must be run before -O3.  
     *
     * This will remove storing parameters in stack variables and loading from there.  
     *
     * ; Function Attrs: noinline nounwind uwtable
       define dso_local i32 @decrypt_config(i32 %config_location, %struct._state* %state, i32 %sizeof_state) #0 {
        entry:
           ...
           %state.addr = alloca %struct._state*, align 8
           %sizeof_state.addr = alloca i32, align 4
           ...
           store %struct._state* %state, %struct._state** %state.addr, align 8
           store i32 %sizeof_state, i32* %sizeof_state.addr, align 4
     */
class ClamBCRemoveUndefs : public ModulePass
{
  protected:
    llvm::Module *pMod = nullptr;
    std::map<Function *, BasicBlock *> aborts;

    bool bChanged = false;

    std::vector<Instruction *> delLst;

    BasicBlock *getAbortBB(unsigned MDDbgKind, BasicBlock *BB)
    {
        Function *pFunc = BB->getParent();

        //BasicBlock abrt = std::find(pFunc, aborts.begin(), aborts.end());
        auto iter = aborts.find(pFunc);
        if (aborts.end() != iter) {
            return iter->second;
        }

        FunctionType *abrtTy = FunctionType::get(
            Type::getVoidTy(BB->getContext()), false);
        //args.push_back(Type::getInt32Ty(BB->getContext()));
        FunctionType *rterrTy = FunctionType::get(
            Type::getInt32Ty(BB->getContext()),
            {Type::getInt32Ty(BB->getContext())}, false);
        Constant *func_abort =
            BB->getParent()->getParent()->getOrInsertFunction("abort", abrtTy);
        Constant *func_rterr =
            BB->getParent()->getParent()->getOrInsertFunction("bytecode_rt_error", rterrTy);
        BasicBlock *abort = BasicBlock::Create(BB->getContext(), "rterr.trig", BB->getParent());
        //                 PHINode * PN     = PHINode::Create(Type::getInt32Ty(BB->getContext()), 0, "ClamBCRTChecks_abort",
        //                         abort);
        Constant *PN = ConstantInt::get(Type::getInt32Ty(BB->getContext()), 99);
        if (MDDbgKind) {
            CallInst *RtErrCall = CallInst::Create(func_rterr, PN, "", abort);
            RtErrCall->setCallingConv(CallingConv::C);
            RtErrCall->setTailCall(true);
            RtErrCall->setDoesNotThrow();
        }
        CallInst *AbrtC = CallInst::Create(func_abort, "", abort);
        AbrtC->setCallingConv(CallingConv::C);
        AbrtC->setTailCall(true);
        AbrtC->setDoesNotReturn();
        AbrtC->setDoesNotThrow();
        new UnreachableInst(BB->getContext(), abort);

        aborts[pFunc] = abort;

        return abort;
    }

    virtual Type *getTargetType(Value *v1, Value *v2)
    {

        IntegerType *v1t = llvm::dyn_cast<IntegerType>(v1->getType());
        IntegerType *v2t = llvm::dyn_cast<IntegerType>(v2->getType());

        assert((v1t and v2t) and "This function is only for integer types.");

        if (v1t->getBitWidth() > v2t->getBitWidth()) {
            return v1t;
        }

        return v2t;
    }

    virtual void insertChecks(GetElementPtrInst *pgepi, Value *vsize)
    {

        Value *pIdx = pgepi->getOperand(pgepi->getNumOperands() - 1);

        BasicBlock *old     = pgepi->getParent();
        BasicBlock *abortBB = getAbortBB(0, old);
        BasicBlock *pSplit  = old->splitBasicBlock(pgepi, "ClamBCRemoveUndefs_");

        Instruction *term = old->getTerminator();

        Type *pTargetType = getTargetType(pIdx, vsize);
        if (pIdx->getType() != pTargetType) {
            pIdx = CastInst::CreateZExtOrBitCast(pIdx, pTargetType, "ClamBCRemoveUndefs_", term);
        }

        if (vsize->getType() != pTargetType) {
            vsize = CastInst::CreateZExtOrBitCast(vsize, pTargetType, "ClamBCRemoveUndefs_", term);
        }

        Value *cond = new ICmpInst(term, ICmpInst::ICMP_UGE, pIdx, vsize);
        BranchInst::Create(abortBB, pSplit, cond, term);

        delLst.push_back(term);
        bChanged = true;
    }

    virtual void insertChecks(Value *ptr, Value *size)
    {

        std::set<llvm::Instruction *> insts;
        std::set<llvm::GlobalVariable *> globs;
        getDependentValues(ptr, insts, globs);

        for (auto i : insts) {
            if (GetElementPtrInst *pgepi = llvm::dyn_cast<GetElementPtrInst>(i)) {
                insertChecks(pgepi, size);
            }
        }
    }

    virtual void processFunction(Function *pFunc)
    {
        for (auto i = pFunc->arg_begin(), e = pFunc->arg_end(); i != e; i++) {
            Argument *pArg = llvm::cast<Argument>(i);

            Type *pType = pArg->getType();
            if (not pType->isPointerTy()) {
                continue;
            }

            i++;
            if (i == pFunc->arg_end()) {
                break;
            }

            Argument *pArgSize = llvm::cast<Argument>(i);

            Type *pArgSizeType = pArgSize->getType();
            assert(pArgSizeType->isIntegerTy() && "This needs to be the size of the pointer");

            insertChecks(pArg, pArgSize);
        }
    }

  public:
    static char ID;
    ClamBCRemoveUndefs()
        : ModulePass(ID) {}

    virtual ~ClamBCRemoveUndefs() {}

    bool runOnModule(Module &m) override
    {
        pMod = &m;

        for (auto i = pMod->begin(), e = pMod->end(); i != e; i++) {
            Function *pFunc = llvm::cast<Function>(i);
            if (pFunc->isDeclaration()) {
                continue;
            }

            processFunction(pFunc);
        }

        for (size_t i = 0; i < delLst.size(); i++) {
            delLst[i]->eraseFromParent();
        }

        return bChanged;
    }
}; // end of struct ClamBCRemoveUndefs

} // end of anonymous namespace

char ClamBCRemoveUndefs::ID = 0;
static RegisterPass<ClamBCRemoveUndefs> X("clambc-remove-undefs", "Remove Undefs",
                                          false /* Only looks at CFG */,
                                          false /* Analysis Pass */);
