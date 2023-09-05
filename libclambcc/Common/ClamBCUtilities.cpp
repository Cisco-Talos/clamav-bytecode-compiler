
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
            if (CallInst *ci = llvm::dyn_cast<CallInst>(inst)) {
#if 0
                Value *calledValue = ci->getCalledValue();
#else
		Function * calledValue = ci->getCalledFunction();
		if (nullptr == calledValue){
			assert (0 && "ci->getCalledFunction returned NULL\n");
		}
#endif
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
