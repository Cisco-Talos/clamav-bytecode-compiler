#ifndef CLAMBC_UTILITIES_H_
#define CLAMBC_UTILITIES_H_

#include "ClamBCDiagnostics.h"

#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Operator.h>

#include <llvm/ADT/Twine.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/Constants.h>
#include <llvm/Analysis/LoopInfo.h>

#include <set>
#include <map>

/*These are a temporary replacement for ClamBCModule::stop.  */
void ClamBCStop(const llvm::Twine &Msg, const llvm::Module *M);

void ClamBCStop(const llvm::Twine &Msg, const llvm::Function *F);

void ClamBCStop(const llvm::Twine &Msg, const llvm::Instruction *I);

bool functionRecurses(llvm::Function *pFunc);

void getDependentValues(llvm::Value *pv, std::set<llvm::Instruction *> &insts, std::set<llvm::GlobalVariable *> &globs);

void getDependentValues(llvm::Value *pv, std::set<llvm::Instruction *> &insts, std::set<llvm::GlobalVariable *> &globs, std::set<llvm::ConstantExpr *> &ces);

bool functionHasLoop(llvm::Function *pFunc, llvm::LoopInfo &loopInfo);

llvm::BasicBlock *getEntryBlock(llvm::BasicBlock *pBlock);

int64_t getTypeSize(llvm::Module *pMod, llvm::Type *pt);

int64_t getTypeSizeInBytes(llvm::Module *pMod, llvm::Type *pt);

int64_t computeOffsetInBytes(llvm::Module *pMod, llvm::Type *pt, uint64_t idx);

int64_t computeOffsetInBytes(llvm::Module *pMod, llvm::Type *pst, llvm::ConstantInt *pIdx);

int64_t computeOffsetInBytes(llvm::Module *pMod, llvm::Type *pst);

llvm::Type *findTypeAtIndex(llvm::Type *pst, llvm::ConstantInt *ciIdx);

llvm::Type *getResultType(llvm::Value *pVal);

void gatherCallsToIntrinsic(llvm::Function *pFunc, const char *const functionName,
                            std::vector<llvm::CallInst *> &calls);

void gatherCallsToIntrinsic(llvm::Module *pMod, const char *const functionName,
                            std::vector<llvm::CallInst *> &calls);

void replaceAllCalls(llvm::FunctionType *pFuncType, llvm::Function *pFunc,
                     const std::vector<llvm::CallInst *> &calls, const char *const namePrefix);

#endif // CLAMBC_UTILITIES_H_
