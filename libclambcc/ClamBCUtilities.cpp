
#include "ClamBCUtilities.h"
#include "ClamBCDiagnostics.h"
#include "clambc.h"

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
            if (CallInst *ci = llvm::dyn_cast<CallInst>(inst)) {
                Value *calledValue = ci->getCalledFunction();
                if (nullptr == calledValue) {
                    ClamBCStop("Calls to function pointers not allowed", ci);
                }
                if (calledValue == orig) {
                    return true;
                } else if (Function *callee = dyn_cast<Function>(calledValue)) {
                    if (functionRecurses(callee, orig, visited)) {
                        return true;
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

/*Only pass in either ConstantExpr or Instruction */
Type *getResultType(Value *pVal)
{

    Type *type = nullptr;

    if (llvm::isa<ConstantExpr>(pVal)) {
        ConstantExpr *pce = llvm::cast<ConstantExpr>(pVal);
        type              = pce->getOperand(0)->getType();
    } else if (llvm::isa<Instruction>(pVal)) {
        Instruction *pInst = llvm::cast<Instruction>(pVal);
        type               = pInst->getOperand(0)->getType();
    } else {
        assert(0 && "This function must be called with either Instruction or a ConstantExpr");
        return nullptr;
    }

    if (llvm::isa<PointerType>(type)) {
        if (llvm::isa<GEPOperator>(pVal)) {
            GEPOperator *pgep = llvm::cast<GEPOperator>(pVal);
            type              = pgep->getSourceElementType();

        } else if (llvm::isa<GetElementPtrInst>(pVal)) {
            GetElementPtrInst *pInst = llvm::cast<GetElementPtrInst>(pVal);
            type                     = pInst->getSourceElementType();
        } else if (llvm::isa<BitCastOperator>(pVal)) {
            BitCastOperator *pbco = llvm::cast<BitCastOperator>(pVal);
            type                  = pbco->getDestTy();
        } else if (llvm::isa<BitCastInst>(pVal)) {
            BitCastInst *pInst = llvm::cast<BitCastInst>(pVal);
            type               = pInst->getDestTy();
        } else {
            llvm::errs() << "<" << __LINE__ << ">"
                         << "https://llvm.org/docs/OpaquePointers.html"
                         << "<END>\n";
            llvm::errs() << "<" << __LINE__ << ">" << *pVal << "<END>\n";
            assert(0 && "FIGURE OUT WHAT TO DO HERE");
        }
    }

    return type;
}

void gatherCallsToIntrinsic(Function *pFunc, const char *const functionName, std::vector<CallInst *> &calls)
{
    for (auto fi = pFunc->begin(), fe = pFunc->end(); fi != fe; fi++) {
        BasicBlock *pBB = llvm::cast<BasicBlock>(fi);
        for (auto bi = pBB->begin(), be = pBB->end(); bi != be; bi++) {
            if (CallInst *pci = llvm::dyn_cast<CallInst>(bi)) {
                Function *pCalled = pci->getCalledFunction();
                if (pCalled && pCalled->isIntrinsic()) {
                    if (functionName == pCalled->getName()) {
                        calls.push_back(pci);
                    }
                }
            }
        }
    }
}

void gatherCallsToIntrinsic(Module *pMod, const char *const functionName, std::vector<CallInst *> &calls)
{
    for (auto i = pMod->begin(), e = pMod->end(); i != e; i++) {
        Function *pFunc = llvm::cast<Function>(i);
        if (pFunc->isDeclaration()) {
            continue;
        }

        gatherCallsToIntrinsic(pFunc, functionName, calls);
    }
}

void replaceAllCalls(FunctionType *pFuncType, Function *pFunc,
                     const std::vector<CallInst *> &calls, const char *const namePrefix)
{

    for (size_t i = 0; i < calls.size(); i++) {
        CallInst *pci = calls[i];

        std::vector<Value *> args;
        for (size_t i = 0; i < pci->arg_size(); i++) {
            args.push_back(pci->getArgOperand(i));
        }
        CallInst *pNew = CallInst::Create(pFuncType, pFunc, args,
                                          namePrefix, pci);
        pci->replaceAllUsesWith(pNew);
        pci->eraseFromParent();
    }
}
