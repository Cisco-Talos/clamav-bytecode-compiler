//===- LoopDeletion.cpp - Dead Loop Deletion Pass ---------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements the Dead Loop Deletion Pass. This pass is responsible
// for eliminating loops with non-infinite computable trip counts that have no
// side effects or volatile instructions, and do not contribute to the
// computation of the function's return value.
//
//===----------------------------------------------------------------------===//

#define DEBUG_TYPE "loop-delete"
#include "llvm/Transforms/Scalar.h"
#include "llvm/Analysis/LoopPass.h"
#include "llvm/Analysis/ScalarEvolution.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/SmallVector.h"
using namespace llvm;

STATISTIC(NumDeleted, "Number of loops deleted");

namespace {
  class LoopDeletion : public LoopPass {
  public:
    static char ID; // Pass ID, replacement for typeid
    LoopDeletion() : LoopPass(ID) {}
    
    // Possibly eliminate loop L if it is dead.
    bool runOnLoop(Loop* L, LPPassManager& LPM);
    
    bool IsLoopDead(Loop* L, SmallVector<BasicBlock*, 4>& exitingBlocks,
                    SmallVector<BasicBlock*, 4>& exitBlocks,
                    bool &Changed, BasicBlock *Preheader);

    virtual void getAnalysisUsage(AnalysisUsage& AU) const {
      AU.addRequired<DominatorTree>();
      AU.addRequired<LoopInfo>();
      AU.addRequired<ScalarEvolution>();
      AU.addRequiredID(LoopSimplifyID);
      AU.addRequiredID(LCSSAID);
      
      AU.addPreserved<ScalarEvolution>();
      AU.addPreserved<DominatorTree>();
      AU.addPreserved<LoopInfo>();
      AU.addPreservedID(LoopSimplifyID);
      AU.addPreservedID(LCSSAID);
      AU.addPreserved<DominanceFrontier>();
    }
  };
}
  
char LoopDeletion::ID = 0;
INITIALIZE_PASS(LoopDeletion, "loop-deletion",
                "Delete dead loops", false, false);

Pass* llvm::createLoopDeletionPass() {
  return new LoopDeletion();
}

/// IsLoopDead - Determined if a loop is dead.  This assumes that we've already
/// checked for unique exit and exiting blocks, and that the code is in LCSSA
/// form.
bool LoopDeletion::IsLoopDead(Loop* L,
                              SmallVector<BasicBlock*, 4>& exitingBlocks,
                              SmallVector<BasicBlock*, 4>& exitBlocks,
                              bool &Changed, BasicBlock *Preheader) {
  BasicBlock* exitingBlock = exitingBlocks[0];
  BasicBlock* exitBlock = exitBlocks[0];
  
  // Make sure that all PHI entries coming from the loop are loop invariant.
  // Because the code is in LCSSA form, any values used outside of the loop
  // must pass through a PHI in the exit block, meaning that this check is
  // sufficient to guarantee that no loop-variant values are used outside
  // of the loop.
  BasicBlock::iterator BI = exitBlock->begin();
  while (PHINode* P = dyn_cast<PHINode>(BI)) {
    Value* incoming = P->getIncomingValueForBlock(exitingBlock);
    if (Instruction* I = dyn_cast<Instruction>(incoming))
      if (!L->makeLoopInvariant(I, Changed, Preheader->getTerminator()))
        return false;
      
    ++BI;
  }
  
  // Make sure that no instructions in the block have potential side-effects.
  // This includes instructions that could write to memory, and loads that are
  // marked volatile.  This could be made more aggressive by using aliasing
  // information to identify readonly and readnone calls.
  for (Loop::block_iterator LI = L->block_begin(), LE = L->block_end();
       LI != LE; ++LI) {
    for (BasicBlock::iterator BI = (*LI)->begin(), BE = (*LI)->end();
         BI != BE; ++BI) {
      if (BI->mayHaveSideEffects())
        return false;
    }
  }
  
  return true;
}

/// runOnLoop - Remove dead loops, by which we mean loops that do not impact the
/// observable behavior of the program other than finite running time.  Note 
/// we do ensure that this never remove a loop that might be infinite, as doing
/// so could change the halting/non-halting nature of a program.
/// NOTE: This entire process relies pretty heavily on LoopSimplify and LCSSA
/// in order to make various safety checks work.
bool LoopDeletion::runOnLoop(Loop* L, LPPassManager& LPM) {
  // We can only remove the loop if there is a preheader that we can 
  // branch from after removing it.
  BasicBlock* preheader = L->getLoopPreheader();
  if (!preheader)
    return false;
  
  // If LoopSimplify form is not available, stay out of trouble.
  if (!L->hasDedicatedExits())
    return false;

  // We can't remove loops that contain subloops.  If the subloops were dead,
  // they would already have been removed in earlier executions of this pass.
  if (L->begin() != L->end())
    return false;
  
  SmallVector<BasicBlock*, 4> exitingBlocks;
  L->getExitingBlocks(exitingBlocks);
  
  SmallVector<BasicBlock*, 4> exitBlocks;
  L->getUniqueExitBlocks(exitBlocks);
  
  // We require that the loop only have a single exit block.  Otherwise, we'd
  // be in the situation of needing to be able to solve statically which exit
  // block will be branched to, or trying to preserve the branching logic in
  // a loop invariant manner.
  if (exitBlocks.size() != 1)
    return false;
  
  // Loops with multiple exits are too complicated to handle correctly.
  if (exitingBlocks.size() != 1)
    return false;
  
  // Finally, we have to check that the loop really is dead.
  bool Changed = false;
  if (!IsLoopDead(L, exitingBlocks, exitBlocks, Changed, preheader))
    return Changed;
  
  // Don't remove loops for which we can't solve the trip count.
  // They could be infinite, in which case we'd be changing program behavior.
  ScalarEvolution& SE = getAnalysis<ScalarEvolution>();
  const SCEV *S = SE.getMaxBackedgeTakenCount(L);
  if (isa<SCEVCouldNotCompute>(S))
    return Changed;
  
  // Now that we know the removal is safe, remove the loop by changing the
  // branch from the preheader to go to the single exit block.  
  BasicBlock* exitBlock = exitBlocks[0];
  BasicBlock* exitingBlock = exitingBlocks[0];
  
  // Because we're deleting a large chunk of code at once, the sequence in which
  // we remove things is very important to avoid invalidation issues.  Don't
  // mess with this unless you have good reason and know what you're doing.

  // Tell ScalarEvolution that the loop is deleted. Do this before
  // deleting the loop so that ScalarEvolution can look at the loop
  // to determine what it needs to clean up.
  SE.forgetLoop(L);

  // Connect the preheader directly to the exit block.
  TerminatorInst* TI = preheader->getTerminator();
  TI->replaceUsesOfWith(L->getHeader(), exitBlock);

  // Rewrite phis in the exit block to get their inputs from
  // the preheader instead of the exiting block.
  BasicBlock::iterator BI = exitBlock->begin();
  while (PHINode* P = dyn_cast<PHINode>(BI)) {
    P->replaceUsesOfWith(exitingBlock, preheader);
    ++BI;
  }
  
  // Update the dominator tree and remove the instructions and blocks that will
  // be deleted from the reference counting scheme.
  DominatorTree& DT = getAnalysis<DominatorTree>();
  DominanceFrontier* DF = getAnalysisIfAvailable<DominanceFrontier>();
  SmallPtrSet<DomTreeNode*, 8> ChildNodes;
  for (Loop::block_iterator LI = L->block_begin(), LE = L->block_end();
       LI != LE; ++LI) {
    // Move all of the block's children to be children of the preheader, which
    // allows us to remove the domtree entry for the block.
    ChildNodes.insert(DT[*LI]->begin(), DT[*LI]->end());
    for (SmallPtrSet<DomTreeNode*, 8>::iterator DI = ChildNodes.begin(),
         DE = ChildNodes.end(); DI != DE; ++DI) {
      DT.changeImmediateDominator(*DI, DT[preheader]);
      if (DF) DF->changeImmediateDominator((*DI)->getBlock(), preheader, &DT);
    }
    
    ChildNodes.clear();
    DT.eraseNode(*LI);
    if (DF) DF->removeBlock(*LI);

    // Remove the block from the reference counting scheme, so that we can
    // delete it freely later.
    (*LI)->dropAllReferences();
  }
  
  // Erase the instructions and the blocks without having to worry
  // about ordering because we already dropped the references.
  // NOTE: This iteration is safe because erasing the block does not remove its
  // entry from the loop's block list.  We do that in the next section.
  for (Loop::block_iterator LI = L->block_begin(), LE = L->block_end();
       LI != LE; ++LI)
    (*LI)->eraseFromParent();

  // Finally, the blocks from loopinfo.  This has to happen late because
  // otherwise our loop iterators won't work.
  LoopInfo& loopInfo = getAnalysis<LoopInfo>();
  SmallPtrSet<BasicBlock*, 8> blocks;
  blocks.insert(L->block_begin(), L->block_end());
  for (SmallPtrSet<BasicBlock*,8>::iterator I = blocks.begin(),
       E = blocks.end(); I != E; ++I)
    loopInfo.removeBlock(*I);
  
  // The last step is to inform the loop pass manager that we've
  // eliminated this loop.
  LPM.deleteLoopFromQueue(L);
  Changed = true;
  
  ++NumDeleted;
  
  return Changed;
}
