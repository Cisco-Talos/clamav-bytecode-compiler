/*
 *  Compile LLVM bytecode to ClamAV bytecode.
 *
 *  Copyright (C) 2009-2010 Sourcefire, Inc.
 *
 *  Authors: Török Edvin
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */
#define DEBUG_TYPE "clambc-opt"
#include "ClamBCModule.h"
#include "llvm/Analysis/Dominators.h"
#include "llvm/Analysis/LiveValues.h"
#include "llvm/Config/config.h"
#include "llvm/DerivedTypes.h"
#include "llvm/Instructions.h"
#include "llvm/IntrinsicInst.h"
#include "llvm/Intrinsics.h"
#include "llvm/Module.h"
#include "llvm/Pass.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Support/InstIterator.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/Utils/UnifyFunctionExitNodes.h"

using namespace llvm;

namespace
{
class SpeculativeOptimizer : public FunctionPass
{
  public:
    static char ID;
    SpeculativeOptimizer()
        : FunctionPass((intptr_t)&ID) {}
    virtual bool runOnFunction(Function &F);
    virtual void getAnalysisUsage(AnalysisUsage &AU) const
    {
        AU.addRequired<UnifyFunctionExitNodes>();
    }
};
char SpeculativeOptimizer::ID = 0;
RegisterPass<SpeculativeOptimizer> X("clambc-speculative",
                                     "ClamAV speculative execution optimizer");
} // namespace

static bool canHoist(Instruction *I)
{
    if (!I->isSafeToSpeculativelyExecute())
        return false;
    for (Instruction::op_iterator O = I->op_begin(), OE = I->op_end();
         O != OE; ++O) {
        if (*O == I) //recursive PHI
            continue;
        Instruction *OI = dyn_cast<Instruction>(O);
        if (OI && !canHoist(OI))
            return false;
    }
    return true;
}

static Value *Hoist(Instruction *I, BasicBlock *From, BasicBlock *To)
{
    Value *NewI = I->DoPHITranslation(From, To);
    for (Instruction::op_iterator O = I->op_begin(), OE = I->op_end();
         O != OE; ++O) {
        if (*O == I) { //recursive PHI
            O->set(NewI);
            continue;
        }
        Instruction *OI = dyn_cast<Instruction>(O);
        if (!OI)
            continue;
        O->set(Hoist(OI, From, To));
    }
    if (Instruction *NewII = dyn_cast<Instruction>(NewI)) {
        if (NewII->getParent() == From)
            NewII->moveBefore(To->getTerminator());
    }
    return NewI;
}

bool SpeculativeOptimizer::runOnFunction(Function &F)
{
    getAnalysis<UnifyFunctionExitNodes>();
    unsigned it = 0;
    bool Changed, EverMadeChange = false;
    do {
        Changed = false;
        DEBUG(errs() << "SpeculativelyExecute iteration #" << it++ << "\n");
        for (Function::iterator I = F.begin(); I != F.end();) {
            if (I != F.begin()) {
                if (SimplifyCFG(I++)) {
                    Changed = true;
                    continue;
                }
            } else {
                ++I;
            }
            BasicBlock *Pred = I->getUniquePredecessor();
            if (!Pred)
                continue;
            BranchInst *BI = dyn_cast<BranchInst>(I->getTerminator());
            if (!BI || BI->isUnconditional())
                continue;
            BranchInst *PBI = dyn_cast<BranchInst>(Pred->getTerminator());
            if (!PBI || PBI->isUnconditional())
                continue;
            BasicBlock *TrueSucc  = BI->getSuccessor(0);
            BasicBlock *FalseSucc = BI->getSuccessor(1);

            // The other BB successor (not the current one)
            BasicBlock *PredOtherSucc = PBI->getSuccessor(0);
            if (PredOtherSucc == I)
                PredOtherSucc = PBI->getSuccessor(1);

            // The predecessor and current BB must have a common successor
            if (TrueSucc != PredOtherSucc && FalseSucc != PredOtherSucc)
                continue;

            Instruction *Cond = dyn_cast<Instruction>(BI->getCondition());
            if (!Cond)
                continue;
            if (Cond->getParent() != I)
                continue;
            if (!canHoist(Cond))
                continue;
            DEBUG(errs() << "Hoisting instruction: " << *Cond);
            Value *NewI = Hoist(Cond, I, Pred);
            DEBUG(errs() << "to: " << *NewI << "\n");
            // br i1 %cond1, ThisBB, PredOtherSucc
            // ThisBB:
            // br i1 %cond2, TrueSucc, PredOtherSucc
            // ->
            // %cond3 = and i1 %cond1, %cond2
            // br i1 %cond3, TrueSucc, PredOtherSucc
            //
            // br i1 %cond1, ThisBB, PredOtherSucc
            // ThisBB:
            // br i1 %cond2, PredOtherSucc, FalseSucc
            // ->
            // %cond2.not = xor i1 %cond2, 1
            // %cond3 = and i1 %cond1, %cond2.not
            // br i1 %cond3, FalseSucc, PredOtherSucc
            if (TrueSucc == PredOtherSucc)
                NewI = BinaryOperator::CreateNot(NewI, "", PBI);
            Value *And = BinaryOperator::Create(BinaryOperator::And,
                                                PBI->getCondition(),
                                                NewI, "", PBI);
            PBI->setCondition(And);
            if (TrueSucc == PredOtherSucc)
                BI->setUnconditionalDest(FalseSucc);
            else
                BI->setUnconditionalDest(TrueSucc);
            Changed = true;
        }
        EverMadeChange |= Changed;
    } while (Changed);

    return EverMadeChange;
}
