
#include "Common/ClamBCUtilities.h"
#include "Common/ClamBCDiagnostics.h"
#include "Common/clambc.h"

#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Operator.h>

using namespace llvm;

void ClamBCStop(const Twine &Msg, const Module *M)
{
    printDiagnostic(Msg, M);
    exit(42);
}

void ClamBCStop(const Twine &Msg, const Function *F)
{
    printDiagnostic(Msg, F);
    exit(42);
}

void ClamBCStop(const Twine &Msg, const Instruction *I)
{
    printDiagnostic(Msg, I);
    exit(42);
}

bool functionRecurses(Function *pFunc, Function *orig, std::vector<Function *> &visited)
{
    if (visited.end() != std::find(visited.begin(), visited.end(), pFunc)) {
        return false;
    }
    visited.push_back(pFunc);

    for (auto funcIter = pFunc->begin(), funcEnd = pFunc->end(); funcIter != funcEnd; funcIter++) {
        BasicBlock *bb = llvm::cast<BasicBlock>(funcIter);

        for (auto blockIter = bb->begin(), blockEnd = bb->end(); blockIter != blockEnd; blockIter++) {
            Instruction *inst = llvm::cast<Instruction>(blockIter);
            CallInst *ci      = llvm::dyn_cast<CallInst>(inst);
            if (nullptr != ci) {
#if 0
                Value *calledValue = ci->getCalledValue();
#else
                Function *calledValue = ci->getCalledFunction();
                if (nullptr == calledValue) {
                    assert(0 && "ci->getCalledFunction returned NULL\n");
                }
#endif
                if (calledValue == orig) {
                    return true;
                } else {
                    Function *callee = dyn_cast<Function>(calledValue);
                    if (nullptr != callee) {
                        if (functionRecurses(callee, orig, visited)) {
                            return true;
                        }
                    }
                }
            }
        }
    }
    return false;
}

bool functionRecurses(Function *pFunc)
{
    std::vector<Function *> visited;
    return functionRecurses(pFunc, pFunc, visited);
}

void getDependentValues(llvm::Value *pv, std::set<llvm::Instruction *> &insts,
                        std::set<llvm::GlobalVariable *> &globs, std::set<llvm::ConstantExpr *> &ces,
                        std::set<llvm::Value *> &visited)
{
    if (visited.end() != std::find(visited.begin(), visited.end(), pv)) {
        return;
    }

    bool first = (0 == visited.size());
    visited.insert(pv);

    if (not first) {
        if (llvm::isa<Instruction>(pv)) {
            Instruction *inst = llvm::cast<Instruction>(pv);
            insts.insert(inst);
        } else if (llvm::isa<GlobalVariable>(pv)) {
            GlobalVariable *gv = llvm::cast<GlobalVariable>(pv);
            globs.insert(gv);
        } else if (llvm::isa<GEPOperator>(pv)) {
            GEPOperator *tmp = llvm::cast<GEPOperator>(pv);
            assert(llvm::isa<ConstantExpr>(pv) && "Not a ConstantExpr");
            getDependentValues(tmp->getOperand(0), insts, globs, ces, visited);
        } else if (llvm::isa<BitCastOperator>(pv)) {
            BitCastOperator *tmp = llvm::cast<BitCastOperator>(pv);
            assert(llvm::isa<ConstantExpr>(pv) && "Not a ConstantExpr");
            getDependentValues(tmp->getOperand(0), insts, globs, ces, visited);
        } else if (llvm::isa<PtrToIntOperator>(pv)) {
            PtrToIntOperator *tmp = llvm::cast<PtrToIntOperator>(pv);
            assert(llvm::isa<ConstantExpr>(pv) && "Not a ConstantExpr");
            getDependentValues(tmp->getOperand(0), insts, globs, ces, visited);
        } else if (llvm::isa<ZExtOperator>(pv)) {
            ZExtOperator *tmp = llvm::cast<ZExtOperator>(pv);
            assert(llvm::isa<ConstantExpr>(pv) && "Not a ConstantExpr");
            getDependentValues(tmp->getOperand(0), insts, globs, ces, visited);
        }

        if (llvm::isa<ConstantExpr>(pv)) {
            ConstantExpr *ce = llvm::cast<ConstantExpr>(pv);
            ces.insert(ce);
            getDependentValues(ce->getOperand(0), insts, globs, ces, visited);
        }
    }

    for (auto i = pv->user_begin(), e = pv->user_end(); i != e; i++) {
        Value *val = llvm::cast<Value>(*i);
        getDependentValues(val, insts, globs, ces, visited);
    }
}

void getDependentValues(llvm::Value *pv, std::set<llvm::Instruction *> &insts,
                        std::set<llvm::GlobalVariable *> &globs)
{
    std::set<llvm::ConstantExpr *> ces;
    std::set<llvm::Value *> visited;
    getDependentValues(pv, insts, globs, ces, visited);
}

void getDependentValues(llvm::Value *pv, std::set<llvm::Instruction *> &insts,
                        std::set<llvm::GlobalVariable *> &globs, std::set<llvm::ConstantExpr *> &ces)
{
    std::set<llvm::Value *> visited;
    getDependentValues(pv, insts, globs, ces, visited);
}

bool functionHasLoop(llvm::Function *pFunc, llvm::LoopInfo &loopInfo)
{
    for (auto i = pFunc->begin(), e = pFunc->end(); i != e; i++) {
        BasicBlock *pBB = llvm::cast<BasicBlock>(i);
        if (nullptr != loopInfo.getLoopFor(pBB)) {
            return true;
        }
    }
    return false;
}

llvm::BasicBlock *getEntryBlock(llvm::BasicBlock *pBlock)
{
    return llvm::cast<llvm::BasicBlock>(pBlock->getParent()->begin());
}

int64_t getTypeSize(llvm::Module *pMod, llvm::Type *pt)
{

    int64_t size = pt->getScalarSizeInBits();
    if (size) {
        return size;
    }

    ArrayType *pat = llvm::dyn_cast<ArrayType>(pt);
    if (nullptr != pat) {
        size = pat->getNumElements() * (getTypeSize(pMod, pat->getElementType()));
        if (size) {
            return size;
        }
    }

    StructType *pst = llvm::dyn_cast<StructType>(pt);
    if (nullptr != pst) {
        const StructLayout *psl = pMod->getDataLayout().getStructLayout(pst);
        return psl->getSizeInBits();
    }

    assert(0 && "Size has not been computed");
    return -1;
}

int64_t getTypeSizeInBytes(llvm::Module *pMod, Type *pt)
{
    return getTypeSize(pMod, pt) / 8;
}

int64_t computeOffsetInBytes(llvm::Module *pMod, Type *pt, uint64_t idx)
{

    int64_t cnt = 0;

    assert((llvm::isa<StructType>(pt) || llvm::isa<ArrayType>(pt)) && "pt must be a complex type");

    StructType *pst = llvm::dyn_cast<StructType>(pt);
    if (nullptr != pst) {
        assert((idx <= pst->getNumElements()) && "Idx too high");

        const StructLayout *psl = pMod->getDataLayout().getStructLayout(pst);
        assert(psl && "Could not get layout");

        cnt = psl->getElementOffsetInBits(idx) / 8;

    } else {
        ArrayType *pat = llvm::dyn_cast<ArrayType>(pt);
        if (nullptr != pat) {
            assert((idx <= pat->getNumElements()) && "Idx too high");
            cnt = idx * getTypeSizeInBytes(pMod, pat->getElementType());
        }
    }

    return cnt;
}

int64_t computeOffsetInBytes(llvm::Module *pMod, Type *pst, ConstantInt *pIdx)
{
    int64_t idx = pIdx->getLimitedValue();
    return computeOffsetInBytes(pMod, pst, idx);
}

int64_t computeOffsetInBytes(llvm::Module *pMod, Type *pst)
{
    if (llvm::isa<StructType>(pst)) {
        return computeOffsetInBytes(pMod, pst, pst->getStructNumElements());
    } else if (llvm::isa<ArrayType>(pst)) {
        return computeOffsetInBytes(pMod, pst, pst->getArrayNumElements());
    } else {
        assert(0 && "pt must be a complex type");
    }

    return 0;
}

Type *findTypeAtIndex(Type *pst, ConstantInt *ciIdx)
{
    Type *ret      = nullptr;
    StructType *st = llvm::dyn_cast<StructType>(pst);
    if (nullptr != st) {
        uint64_t idx = ciIdx->getLimitedValue();

        assert(idx < st->getNumElements() && "Something went wrong");
        return st->getTypeAtIndex(idx);
    }

    ArrayType *at = llvm::dyn_cast<ArrayType>(pst);
    if (nullptr != at) {
        return at->getArrayElementType();
    }
    return ret;
}
