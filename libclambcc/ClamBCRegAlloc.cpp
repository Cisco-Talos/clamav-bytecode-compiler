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
#include "ClamBCRegAlloc.h"
#include "ClamBCUtilities.h"
#include "clambc.h"

#include <llvm/IR/Dominators.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/Intrinsics.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/Pass.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/TypedPointerType.h>

using namespace llvm;
// We do have a virtually unlimited number of registers, but it is more cache
// efficient at runtime if we use a small number of them.
// Also it is easier for the interpreter if there are no phi nodes,
// so we transform phi nodes into a store/load pair into a temporary stack
// location.
// We don't use LLVM's register allocators, because they are for
// targets with fixed number of registers, and a much simpler allocator
// suffices for us.

llvm::AnalysisKey ClamBCRegAllocAnalyzer::Key;

/*TODO: Should rework this so that we are not changing things with open iterators.*/
void ClamBCRegAllocAnalysis::handlePHI(PHINode *PN)
{
    BasicBlock *BB = PN->getIncomingBlock(0);
    for (unsigned i = 1; i < PN->getNumIncomingValues(); i++) {
        BB = DT->findNearestCommonDominator(BB, PN->getIncomingBlock(i));
    }
    Function *pFunc     = BB->getParent();
    BasicBlock *pEntry  = llvm::cast<BasicBlock>(pFunc->begin());
    Instruction *pFirst = llvm::cast<Instruction>(pEntry->begin());
    AllocaInst *AI      = new AllocaInst(PN->getType(), pFunc->getAddressSpace(), ".phi",
                                         pFirst);
    llvm::IRBuilder<> builder(PN->getContext());
    unsigned MDDbgKind = PN->getContext().getMDKindID("dbg");
    if (MDDbgKind) {
        if (MDNode *Dbg = PN->getMetadata(MDDbgKind)) {
            DebugLoc dl(Dbg);
            builder.SetCurrentDebugLocation(dl);
        }
    }
    for (unsigned i = 0; i < PN->getNumIncomingValues(); i++) {
        BasicBlock *BB = PN->getIncomingBlock(i);
        Value *V       = PN->getIncomingValue(i);
        builder.SetInsertPoint(BB->getTerminator());
        Instruction *I = builder.CreateStore(V, AI);
        builder.SetInstDebugLocation(I);
    }
    BasicBlock::iterator It(PN);
    do {
        ++It;
    } while (isa<PHINode>(It));
    builder.SetInsertPoint(&*It);
    LoadInst *LI = builder.CreateLoad(AI->getAllocatedType(), AI, ".phiload");
    builder.SetInstDebugLocation(LI);
    PN->replaceAllUsesWith(LI);
    PN->eraseFromParent();
}

bool ClamBCRegAllocAnalysis::runOnFunction(Function &F)
{
    ValueMap.clear();
    RevValueMap.clear();
    bool Changed = false;
    std::vector<PHINode *> pns;
    for (Function::iterator I = F.begin(), E = F.end(); I != E; ++I) {
        BasicBlock &BB         = *I;
        BasicBlock::iterator J = BB.begin();
        while (J != BB.end()) {
            PHINode *PN = dyn_cast<PHINode>(J);
            if (!PN)
                break;
            ++J;
            pns.push_back(PN);
        }
    }
    for (size_t i = 0; i < pns.size(); i++) {
        PHINode *PN = pns[i];
        handlePHI(PN);
    }

    unsigned id = 0;
    for (Function::arg_iterator I = F.arg_begin(), E = F.arg_end();
         I != E; ++I) {
        Argument *A = llvm::cast<Argument>(I);
        ValueMap[A] = id;
        if (RevValueMap.size() == id) {
            RevValueMap.push_back(A);
        }
        ++id;
    }

    for (inst_iterator I = inst_begin(F), E = inst_end(F); I != E; ++I) {
        Instruction *II = llvm::cast<Instruction>(&*I);
        if (ValueMap.count(II))
            continue;
        if (II->getType()->getTypeID() == Type::VoidTyID) {
            ValueMap[II] = ~0u;
            continue;
        }
        if (II->use_empty() && !II->mayHaveSideEffects()) {
            SkipMap.insert(II);
            ValueMap[II] = ~0u;
            continue;
        }

        {
            static int first = 1;
            if (first) {
                first = 0;
            }
        }
        if (CastInst *BC = dyn_cast<CastInst>(II)) {
            if (BitCastInst *BCI = dyn_cast<BitCastInst>(BC)) {
                if (!BCI->isLosslessCast()) {
                    ClamBCStop("Non lossless bitcast is not supported", BCI);
                }

                if (BCI->getSrcTy()->isPointerTy() and (not BCI->getDestTy()->isPointerTy())) {
                    ClamBCStop("Cast from pointer to non-pointer element",
                               BCI);
                }

                if (AllocaInst *AI = dyn_cast<AllocaInst>(BCI->getOperand(0))) {
                    if (!AI->isArrayAllocation()) {
                        // we need to use a GEP 0,0 for bitcast here
                        ValueMap[II] = id;
                        if (RevValueMap.size() == id) {
                            RevValueMap.push_back(II);
                        }
                        ++id;
                        continue;
                    }
                }
                SkipMap.insert(II);
                ValueMap[II] = getValueID(II->getOperand(0));
                continue;
            } else if (llvm::isa<PtrToIntInst>(BC) or llvm::isa<IntToPtrInst>(BC)) {
                ClamBCStop("Cast from pointer to non-pointer element",
                           BCI);
            }
        }
        if (II->hasOneUse()) {
            // single-use store to alloca -> store directly to alloca
            if (StoreInst *SI = dyn_cast<StoreInst>(*II->use_begin())) {
                if (AllocaInst *AI = dyn_cast<AllocaInst>(SI->getPointerOperand())) {
                    if (!ValueMap.count(AI)) {
                        ValueMap[AI] = id;
                        if (RevValueMap.size() == id) {
                            RevValueMap.push_back(II);
                        } else {
                            errs() << id << " " << __FILE__ << ":" << __LINE__ << "\n";
                        }
                        ++id;
                    }
                    ValueMap[II] = getValueID(AI);
                    continue;
                }
            }
            // single-use of load from alloca -> use directly value id of alloca
        }
        ValueMap[II] = id;
        if (RevValueMap.size() == id) {
            RevValueMap.push_back(II);
        } else {
            errs() << id << " " << __FILE__ << ":" << __LINE__ << "\n";
        }
        ++id;
    }
    // TODO: reduce the number of virtual registers used, by using
    //  an algorithms that walks the dominatortree and does value liveness
    //  analysis.
    return Changed;
}

void ClamBCRegAllocAnalysis::dump() const
{
    for (ValueIDMap::const_iterator I = ValueMap.begin(), E = ValueMap.end();
         I != E; ++I) {
        errs() << *I->first << " = " << I->second << "\n";
    }
}

void ClamBCRegAllocAnalysis::revdump() const
{
    for (unsigned i = 0; i < RevValueMap.size(); ++i) {
        errs() << i << ": ";
        RevValueMap[i]->print(errs(), 0);
        errs() << "\n";
    }
}

unsigned ClamBCRegAllocAnalysis::buildReverseMap(std::vector<const Value *> &reverseMap)
{
    // Check using the older building code to determine changes due to building difference
    // Note: this code can be removed if necessary
    unsigned max = 0;
    for (ValueIDMap::iterator I = ValueMap.begin(), E = ValueMap.end(); I != E; ++I) {
        if (const Instruction *II = dyn_cast<Instruction>(I->first)) {
            if (SkipMap.count(II))
                continue;
        }
        if (I->second == ~0u)
            continue;
        if (I->second > max)
            max = I->second;
    }
    if ((max != 0) && (max + 1 != RevValueMap.size())) {
        errs() << "mismatch in expected number of values in map at ";
        errs() << __FILE__ << ":" << __LINE__ << "\n";
        errs() << "found " << max + 1 << ", expected " << RevValueMap.size() << "\n";
        revdump();
        assert(max + 1 == RevValueMap.size());
        return 0;
    }

    // New building code, copies previously-built vector
    reverseMap.resize(RevValueMap.size());
    for (unsigned i = 0; i < RevValueMap.size(); ++i) {
        reverseMap[i] = RevValueMap[i];
    }
    return RevValueMap.size();
}

void ClamBCRegAllocAnalysis::getAnalysisUsage(AnalysisUsage &AU) const
{
    AU.addRequired<DominatorTreeWrapperPass>();

    // Preserve the CFG, we only eliminate PHIs, and introduce some
    // loads/stores.
    AU.setPreservesCFG();
}

// This part is the new way of registering your pass
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo()
{
    return {
        LLVM_PLUGIN_API_VERSION, "ClamBCRegAlloc", "v0.1",
        [](PassBuilder &PB) {
            PB.registerAnalysisRegistrationCallback(
                [](FunctionAnalysisManager &mam) {
                    mam.registerPass([]() { return ClamBCRegAllocAnalyzer(); });
                });
        }};
}
