//===- BreakCriticalEdges.cpp - Critical Edge Elimination Pass ------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// BreakCriticalEdges pass - Break all of the critical edges in the CFG by
// inserting a dummy basic block.  This pass may be "required" by passes that
// cannot deal with critical edges.  For this usage, the structure type is
// forward declared.  This pass obviously invalidates the CFG, but can update
// forward dominator (set, immediate dominators, tree, and frontier)
// information.
//
//===----------------------------------------------------------------------===//

#define DEBUG_TYPE "break-crit-edges"
#include "llvm/Transforms/Scalar.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Analysis/Dominators.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/ProfileInfo.h"
#include "llvm/Function.h"
#include "llvm/Instructions.h"
#include "llvm/Type.h"
#include "llvm/Support/CFG.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
using namespace llvm;

STATISTIC(NumBroken, "Number of blocks inserted");

namespace {
  struct BreakCriticalEdges : public FunctionPass {
    static char ID; // Pass identification, replacement for typeid
    BreakCriticalEdges() : FunctionPass(&ID) {}

    virtual bool runOnFunction(Function &F);

    virtual void getAnalysisUsage(AnalysisUsage &AU) const {
      AU.addPreserved<DominatorTree>();
      AU.addPreserved<DominanceFrontier>();
      AU.addPreserved<LoopInfo>();
      AU.addPreserved<ProfileInfo>();

      // No loop canonicalization guarantees are broken by this pass.
      AU.addPreservedID(LoopSimplifyID);
    }
  };
}

char BreakCriticalEdges::ID = 0;
static RegisterPass<BreakCriticalEdges>
X("break-crit-edges", "Break critical edges in CFG");

// Publically exposed interface to pass...
const PassInfo *const llvm::BreakCriticalEdgesID = &X;
FunctionPass *llvm::createBreakCriticalEdgesPass() {
  return new BreakCriticalEdges();
}

// runOnFunction - Loop over all of the edges in the CFG, breaking critical
// edges as they are found.
//
bool BreakCriticalEdges::runOnFunction(Function &F) {
  bool Changed = false;
  for (Function::iterator I = F.begin(), E = F.end(); I != E; ++I) {
    TerminatorInst *TI = I->getTerminator();
    if (TI->getNumSuccessors() > 1 && !isa<IndirectBrInst>(TI))
      for (unsigned i = 0, e = TI->getNumSuccessors(); i != e; ++i)
        if (SplitCriticalEdge(TI, i, this)) {
          ++NumBroken;
          Changed = true;
        }
  }

  return Changed;
}

//===----------------------------------------------------------------------===//
//    Implementation of the external critical edge manipulation functions
//===----------------------------------------------------------------------===//

// isCriticalEdge - Return true if the specified edge is a critical edge.
// Critical edges are edges from a block with multiple successors to a block
// with multiple predecessors.
//
bool llvm::isCriticalEdge(const TerminatorInst *TI, unsigned SuccNum,
                          bool AllowIdenticalEdges) {
  assert(SuccNum < TI->getNumSuccessors() && "Illegal edge specification!");
  if (TI->getNumSuccessors() == 1) return false;

  const BasicBlock *Dest = TI->getSuccessor(SuccNum);
  pred_const_iterator I = pred_begin(Dest), E = pred_end(Dest);

  // If there is more than one predecessor, this is a critical edge...
  assert(I != E && "No preds, but we have an edge to the block?");
  const BasicBlock *FirstPred = *I;
  ++I;        // Skip one edge due to the incoming arc from TI.
  if (!AllowIdenticalEdges)
    return I != E;
  
  // If AllowIdenticalEdges is true, then we allow this edge to be considered
  // non-critical iff all preds come from TI's block.
  while (I != E) {
    if (*I != FirstPred)
      return true;
    // Note: leave this as is until no one ever compiles with either gcc 4.0.1
    // or Xcode 2. This seems to work around the pred_iterator assert in PR 2207
    E = pred_end(*I);
    ++I;
  }
  return false;
}

/// CreatePHIsForSplitLoopExit - When a loop exit edge is split, LCSSA form
/// may require new PHIs in the new exit block. This function inserts the
/// new PHIs, as needed.  Preds is a list of preds inside the loop, SplitBB
/// is the new loop exit block, and DestBB is the old loop exit, now the
/// successor of SplitBB.
static void CreatePHIsForSplitLoopExit(SmallVectorImpl<BasicBlock *> &Preds,
                                       BasicBlock *SplitBB,
                                       BasicBlock *DestBB) {
  // SplitBB shouldn't have anything non-trivial in it yet.
  assert(SplitBB->getFirstNonPHI() == SplitBB->getTerminator() &&
         "SplitBB has non-PHI nodes!");

  // For each PHI in the destination block...
  for (BasicBlock::iterator I = DestBB->begin();
       PHINode *PN = dyn_cast<PHINode>(I); ++I) {
    unsigned Idx = PN->getBasicBlockIndex(SplitBB);
    Value *V = PN->getIncomingValue(Idx);
    // If the input is a PHI which already satisfies LCSSA, don't create
    // a new one.
    if (const PHINode *VP = dyn_cast<PHINode>(V))
      if (VP->getParent() == SplitBB)
        continue;
    // Otherwise a new PHI is needed. Create one and populate it.
    PHINode *NewPN = PHINode::Create(PN->getType(), "split",
                                     SplitBB->getTerminator());
    for (unsigned i = 0, e = Preds.size(); i != e; ++i)
      NewPN->addIncoming(V, Preds[i]);
    // Update the original PHI.
    PN->setIncomingValue(Idx, NewPN);
  }
}

/// SplitCriticalEdge - If this edge is a critical edge, insert a new node to
/// split the critical edge.  This will update DominatorTree and
/// DominatorFrontier information if it is available, thus calling this pass
/// will not invalidate either of them. This returns the new block if the edge
/// was split, null otherwise.
///
/// If MergeIdenticalEdges is true (not the default), *all* edges from TI to the
/// specified successor will be merged into the same critical edge block.  
/// This is most commonly interesting with switch instructions, which may 
/// have many edges to any one destination.  This ensures that all edges to that
/// dest go to one block instead of each going to a different block, but isn't 
/// the standard definition of a "critical edge".
///
/// It is invalid to call this function on a critical edge that starts at an
/// IndirectBrInst.  Splitting these edges will almost always create an invalid
/// program because the address of the new block won't be the one that is jumped
/// to.
///
BasicBlock *llvm::SplitCriticalEdge(TerminatorInst *TI, unsigned SuccNum,
                                    Pass *P, bool MergeIdenticalEdges) {
  if (!isCriticalEdge(TI, SuccNum, MergeIdenticalEdges)) return 0;
  
  assert(!isa<IndirectBrInst>(TI) &&
         "Cannot split critical edge from IndirectBrInst");
  
  BasicBlock *TIBB = TI->getParent();
  BasicBlock *DestBB = TI->getSuccessor(SuccNum);

  // Create a new basic block, linking it into the CFG.
  BasicBlock *NewBB = BasicBlock::Create(TI->getContext(),
                      TIBB->getName() + "." + DestBB->getName() + "_crit_edge");
  // Create our unconditional branch...
  BranchInst::Create(DestBB, NewBB);

  // Branch to the new block, breaking the edge.
  TI->setSuccessor(SuccNum, NewBB);

  // Insert the block into the function... right after the block TI lives in.
  Function &F = *TIBB->getParent();
  Function::iterator FBBI = TIBB;
  F.getBasicBlockList().insert(++FBBI, NewBB);
  
  // If there are any PHI nodes in DestBB, we need to update them so that they
  // merge incoming values from NewBB instead of from TIBB.
  //
  for (BasicBlock::iterator I = DestBB->begin(); isa<PHINode>(I); ++I) {
    PHINode *PN = cast<PHINode>(I);
    // We no longer enter through TIBB, now we come in through NewBB.  Revector
    // exactly one entry in the PHI node that used to come from TIBB to come
    // from NewBB.
    int BBIdx = PN->getBasicBlockIndex(TIBB);
    PN->setIncomingBlock(BBIdx, NewBB);
  }
  
  // If there are any other edges from TIBB to DestBB, update those to go
  // through the split block, making those edges non-critical as well (and
  // reducing the number of phi entries in the DestBB if relevant).
  if (MergeIdenticalEdges) {
    for (unsigned i = SuccNum+1, e = TI->getNumSuccessors(); i != e; ++i) {
      if (TI->getSuccessor(i) != DestBB) continue;
      
      // Remove an entry for TIBB from DestBB phi nodes.
      DestBB->removePredecessor(TIBB);
      
      // We found another edge to DestBB, go to NewBB instead.
      TI->setSuccessor(i, NewBB);
    }
  }
  
  

  // If we don't have a pass object, we can't update anything...
  if (P == 0) return NewBB;

  // Now update analysis information.  Since the only predecessor of NewBB is
  // the TIBB, TIBB clearly dominates NewBB.  TIBB usually doesn't dominate
  // anything, as there are other successors of DestBB.  However, if all other
  // predecessors of DestBB are already dominated by DestBB (e.g. DestBB is a
  // loop header) then NewBB dominates DestBB.
  SmallVector<BasicBlock*, 8> OtherPreds;

  for (pred_iterator I = pred_begin(DestBB), E = pred_end(DestBB); I != E; ++I)
    if (*I != NewBB)
      OtherPreds.push_back(*I);
  
  bool NewBBDominatesDestBB = true;
  
  // Should we update DominatorTree information?
  if (DominatorTree *DT = P->getAnalysisIfAvailable<DominatorTree>()) {
    DomTreeNode *TINode = DT->getNode(TIBB);

    // The new block is not the immediate dominator for any other nodes, but
    // TINode is the immediate dominator for the new node.
    //
    if (TINode) {       // Don't break unreachable code!
      DomTreeNode *NewBBNode = DT->addNewBlock(NewBB, TIBB);
      DomTreeNode *DestBBNode = 0;
     
      // If NewBBDominatesDestBB hasn't been computed yet, do so with DT.
      if (!OtherPreds.empty()) {
        DestBBNode = DT->getNode(DestBB);
        while (!OtherPreds.empty() && NewBBDominatesDestBB) {
          if (DomTreeNode *OPNode = DT->getNode(OtherPreds.back()))
            NewBBDominatesDestBB = DT->dominates(DestBBNode, OPNode);
          OtherPreds.pop_back();
        }
        OtherPreds.clear();
      }
      
      // If NewBBDominatesDestBB, then NewBB dominates DestBB, otherwise it
      // doesn't dominate anything.
      if (NewBBDominatesDestBB) {
        if (!DestBBNode) DestBBNode = DT->getNode(DestBB);
        DT->changeImmediateDominator(DestBBNode, NewBBNode);
      }
    }
  }

  // Should we update DominanceFrontier information?
  if (DominanceFrontier *DF = P->getAnalysisIfAvailable<DominanceFrontier>()) {
    // If NewBBDominatesDestBB hasn't been computed yet, do so with DF.
    if (!OtherPreds.empty()) {
      // FIXME: IMPLEMENT THIS!
      llvm_unreachable("Requiring domfrontiers but not idom/domtree/domset."
                       " not implemented yet!");
    }
    
    // Since the new block is dominated by its only predecessor TIBB,
    // it cannot be in any block's dominance frontier.  If NewBB dominates
    // DestBB, its dominance frontier is the same as DestBB's, otherwise it is
    // just {DestBB}.
    DominanceFrontier::DomSetType NewDFSet;
    if (NewBBDominatesDestBB) {
      DominanceFrontier::iterator I = DF->find(DestBB);
      if (I != DF->end()) {
        DF->addBasicBlock(NewBB, I->second);
        
        if (I->second.count(DestBB)) {
          // However NewBB's frontier does not include DestBB.
          DominanceFrontier::iterator NF = DF->find(NewBB);
          DF->removeFromFrontier(NF, DestBB);
        }
      }
      else
        DF->addBasicBlock(NewBB, DominanceFrontier::DomSetType());
    } else {
      DominanceFrontier::DomSetType NewDFSet;
      NewDFSet.insert(DestBB);
      DF->addBasicBlock(NewBB, NewDFSet);
    }
  }
  
  // Update LoopInfo if it is around.
  if (LoopInfo *LI = P->getAnalysisIfAvailable<LoopInfo>()) {
    if (Loop *TIL = LI->getLoopFor(TIBB)) {
      // If one or the other blocks were not in a loop, the new block is not
      // either, and thus LI doesn't need to be updated.
      if (Loop *DestLoop = LI->getLoopFor(DestBB)) {
        if (TIL == DestLoop) {
          // Both in the same loop, the NewBB joins loop.
          DestLoop->addBasicBlockToLoop(NewBB, LI->getBase());
        } else if (TIL->contains(DestLoop)) {
          // Edge from an outer loop to an inner loop.  Add to the outer loop.
          TIL->addBasicBlockToLoop(NewBB, LI->getBase());
        } else if (DestLoop->contains(TIL)) {
          // Edge from an inner loop to an outer loop.  Add to the outer loop.
          DestLoop->addBasicBlockToLoop(NewBB, LI->getBase());
        } else {
          // Edge from two loops with no containment relation.  Because these
          // are natural loops, we know that the destination block must be the
          // header of its loop (adding a branch into a loop elsewhere would
          // create an irreducible loop).
          assert(DestLoop->getHeader() == DestBB &&
                 "Should not create irreducible loops!");
          if (Loop *P = DestLoop->getParentLoop())
            P->addBasicBlockToLoop(NewBB, LI->getBase());
        }
      }
      // If TIBB is in a loop and DestBB is outside of that loop, split the
      // other exit blocks of the loop that also have predecessors outside
      // the loop, to maintain a LoopSimplify guarantee.
      if (!TIL->contains(DestBB) &&
          P->mustPreserveAnalysisID(LoopSimplifyID)) {
        assert(!TIL->contains(NewBB) &&
               "Split point for loop exit is contained in loop!");

        // Update LCSSA form in the newly created exit block.
        if (P->mustPreserveAnalysisID(LCSSAID)) {
          SmallVector<BasicBlock *, 1> OrigPred;
          OrigPred.push_back(TIBB);
          CreatePHIsForSplitLoopExit(OrigPred, NewBB, DestBB);
        }

        // For each unique exit block...
        SmallVector<BasicBlock *, 4> ExitBlocks;
        TIL->getExitBlocks(ExitBlocks);
        for (unsigned i = 0, e = ExitBlocks.size(); i != e; ++i) {
          // Collect all the preds that are inside the loop, and note
          // whether there are any preds outside the loop.
          SmallVector<BasicBlock *, 4> Preds;
          bool HasPredOutsideOfLoop = false;
          BasicBlock *Exit = ExitBlocks[i];
          for (pred_iterator I = pred_begin(Exit), E = pred_end(Exit);
               I != E; ++I)
            if (TIL->contains(*I))
              Preds.push_back(*I);
            else
              HasPredOutsideOfLoop = true;
          // If there are any preds not in the loop, we'll need to split
          // the edges. The Preds.empty() check is needed because a block
          // may appear multiple times in the list. We can't use
          // getUniqueExitBlocks above because that depends on LoopSimplify
          // form, which we're in the process of restoring!
          if (!Preds.empty() && HasPredOutsideOfLoop) {
            BasicBlock *NewExitBB =
              SplitBlockPredecessors(Exit, Preds.data(), Preds.size(),
                                     "split", P);
            if (P->mustPreserveAnalysisID(LCSSAID))
              CreatePHIsForSplitLoopExit(Preds, NewExitBB, Exit);
          }
        }
      }
      // LCSSA form was updated above for the case where LoopSimplify is
      // available, which means that all predecessors of loop exit blocks
      // are within the loop. Without LoopSimplify form, it would be
      // necessary to insert a new phi.
      assert((!P->mustPreserveAnalysisID(LCSSAID) ||
              P->mustPreserveAnalysisID(LoopSimplifyID)) &&
             "SplitCriticalEdge doesn't know how to update LCCSA form "
             "without LoopSimplify!");
    }
  }

  // Update ProfileInfo if it is around.
  if (ProfileInfo *PI = P->getAnalysisIfAvailable<ProfileInfo>()) {
    PI->splitEdge(TIBB,DestBB,NewBB,MergeIdenticalEdges);
  }

  return NewBB;
}
