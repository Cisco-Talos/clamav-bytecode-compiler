//===- IVUsers.cpp - Induction Variable Users -------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements bookkeeping for "interesting" users of expressions
// computed from induction variables.
//
//===----------------------------------------------------------------------===//

#define DEBUG_TYPE "iv-users"
#include "llvm/Analysis/IVUsers.h"
#include "llvm/Constants.h"
#include "llvm/Instructions.h"
#include "llvm/Type.h"
#include "llvm/DerivedTypes.h"
#include "llvm/Analysis/Dominators.h"
#include "llvm/Analysis/LoopPass.h"
#include "llvm/Analysis/ScalarEvolutionExpressions.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include <algorithm>
using namespace llvm;

char IVUsers::ID = 0;
static RegisterPass<IVUsers>
X("iv-users", "Induction Variable Users", false, true);

Pass *llvm::createIVUsersPass() {
  return new IVUsers();
}

/// containsAddRecFromDifferentLoop - Determine whether expression S involves a
/// subexpression that is an AddRec from a loop other than L.  An outer loop
/// of L is OK, but not an inner loop nor a disjoint loop.
static bool containsAddRecFromDifferentLoop(const SCEV *S, Loop *L) {
  // This is very common, put it first.
  if (isa<SCEVConstant>(S))
    return false;
  if (const SCEVCommutativeExpr *AE = dyn_cast<SCEVCommutativeExpr>(S)) {
    for (unsigned int i=0; i< AE->getNumOperands(); i++)
      if (containsAddRecFromDifferentLoop(AE->getOperand(i), L))
        return true;
    return false;
  }
  if (const SCEVAddRecExpr *AE = dyn_cast<SCEVAddRecExpr>(S)) {
    if (const Loop *newLoop = AE->getLoop()) {
      if (newLoop == L)
        return false;
      // if newLoop is an outer loop of L, this is OK.
      if (newLoop->contains(L->getHeader()))
        return false;
    }
    return true;
  }
  if (const SCEVUDivExpr *DE = dyn_cast<SCEVUDivExpr>(S))
    return containsAddRecFromDifferentLoop(DE->getLHS(), L) ||
           containsAddRecFromDifferentLoop(DE->getRHS(), L);
#if 0
  // SCEVSDivExpr has been backed out temporarily, but will be back; we'll
  // need this when it is.
  if (const SCEVSDivExpr *DE = dyn_cast<SCEVSDivExpr>(S))
    return containsAddRecFromDifferentLoop(DE->getLHS(), L) ||
           containsAddRecFromDifferentLoop(DE->getRHS(), L);
#endif
  if (const SCEVCastExpr *CE = dyn_cast<SCEVCastExpr>(S))
    return containsAddRecFromDifferentLoop(CE->getOperand(), L);
  return false;
}

/// getSCEVStartAndStride - Compute the start and stride of this expression,
/// returning false if the expression is not a start/stride pair, or true if it
/// is.  The stride must be a loop invariant expression, but the start may be
/// a mix of loop invariant and loop variant expressions.  The start cannot,
/// however, contain an AddRec from a different loop, unless that loop is an
/// outer loop of the current loop.
static bool getSCEVStartAndStride(const SCEV *&SH, Loop *L, Loop *UseLoop,
                                  const SCEV *&Start, const SCEV *&Stride,
                                  ScalarEvolution *SE, DominatorTree *DT) {
  const SCEV *TheAddRec = Start;   // Initialize to zero.

  // If the outer level is an AddExpr, the operands are all start values except
  // for a nested AddRecExpr.
  if (const SCEVAddExpr *AE = dyn_cast<SCEVAddExpr>(SH)) {
    for (unsigned i = 0, e = AE->getNumOperands(); i != e; ++i)
      if (const SCEVAddRecExpr *AddRec =
             dyn_cast<SCEVAddRecExpr>(AE->getOperand(i))) {
        if (AddRec->getLoop() == L)
          TheAddRec = SE->getAddExpr(AddRec, TheAddRec);
        else
          return false;  // Nested IV of some sort?
      } else {
        Start = SE->getAddExpr(Start, AE->getOperand(i));
      }
  } else if (isa<SCEVAddRecExpr>(SH)) {
    TheAddRec = SH;
  } else {
    return false;  // not analyzable.
  }

  const SCEVAddRecExpr *AddRec = dyn_cast<SCEVAddRecExpr>(TheAddRec);
  if (!AddRec || AddRec->getLoop() != L) return false;

  // Use getSCEVAtScope to attempt to simplify other loops out of
  // the picture.
  const SCEV *AddRecStart = AddRec->getStart();
  AddRecStart = SE->getSCEVAtScope(AddRecStart, UseLoop);
  const SCEV *AddRecStride = AddRec->getStepRecurrence(*SE);

  // FIXME: If Start contains an SCEVAddRecExpr from a different loop, other
  // than an outer loop of the current loop, reject it.  LSR has no concept of
  // operating on more than one loop at a time so don't confuse it with such
  // expressions.
  if (containsAddRecFromDifferentLoop(AddRecStart, L))
    return false;

  Start = SE->getAddExpr(Start, AddRecStart);

  // If stride is an instruction, make sure it properly dominates the header.
  // Otherwise we could end up with a use before def situation.
  if (!isa<SCEVConstant>(AddRecStride)) {
    BasicBlock *Header = L->getHeader();
    if (!AddRecStride->properlyDominates(Header, DT))
      return false;

    DEBUG(errs() << "[" << L->getHeader()->getName()
                 << "] Variable stride: " << *AddRec << "\n");
  }

  Stride = AddRecStride;
  return true;
}

/// IVUseShouldUsePostIncValue - We have discovered a "User" of an IV expression
/// and now we need to decide whether the user should use the preinc or post-inc
/// value.  If this user should use the post-inc version of the IV, return true.
///
/// Choosing wrong here can break dominance properties (if we choose to use the
/// post-inc value when we cannot) or it can end up adding extra live-ranges to
/// the loop, resulting in reg-reg copies (if we use the pre-inc value when we
/// should use the post-inc value).
static bool IVUseShouldUsePostIncValue(Instruction *User, Instruction *IV,
                                       Loop *L, LoopInfo *LI, DominatorTree *DT,
                                       Pass *P) {
  // If the user is in the loop, use the preinc value.
  if (L->contains(User->getParent())) return false;

  BasicBlock *LatchBlock = L->getLoopLatch();
  if (!LatchBlock)
    return false;

  // Ok, the user is outside of the loop.  If it is dominated by the latch
  // block, use the post-inc value.
  if (DT->dominates(LatchBlock, User->getParent()))
    return true;

  // There is one case we have to be careful of: PHI nodes.  These little guys
  // can live in blocks that are not dominated by the latch block, but (since
  // their uses occur in the predecessor block, not the block the PHI lives in)
  // should still use the post-inc value.  Check for this case now.
  PHINode *PN = dyn_cast<PHINode>(User);
  if (!PN) return false;  // not a phi, not dominated by latch block.

  // Look at all of the uses of IV by the PHI node.  If any use corresponds to
  // a block that is not dominated by the latch block, give up and use the
  // preincremented value.
  unsigned NumUses = 0;
  for (unsigned i = 0, e = PN->getNumIncomingValues(); i != e; ++i)
    if (PN->getIncomingValue(i) == IV) {
      ++NumUses;
      if (!DT->dominates(LatchBlock, PN->getIncomingBlock(i)))
        return false;
    }

  // Okay, all uses of IV by PN are in predecessor blocks that really are
  // dominated by the latch block.  Use the post-incremented value.
  return true;
}

/// AddUsersIfInteresting - Inspect the specified instruction.  If it is a
/// reducible SCEV, recursively add its users to the IVUsesByStride set and
/// return true.  Otherwise, return false.
bool IVUsers::AddUsersIfInteresting(Instruction *I) {
  if (!SE->isSCEVable(I->getType()))
    return false;   // Void and FP expressions cannot be reduced.

  // LSR is not APInt clean, do not touch integers bigger than 64-bits.
  if (SE->getTypeSizeInBits(I->getType()) > 64)
    return false;

  if (!Processed.insert(I))
    return true;    // Instruction already handled.

  // Get the symbolic expression for this instruction.
  const SCEV *ISE = SE->getSCEV(I);
  if (isa<SCEVCouldNotCompute>(ISE)) return false;

  // Get the start and stride for this expression.
  Loop *UseLoop = LI->getLoopFor(I->getParent());
  const SCEV *Start = SE->getIntegerSCEV(0, ISE->getType());
  const SCEV *Stride = Start;

  if (!getSCEVStartAndStride(ISE, L, UseLoop, Start, Stride, SE, DT))
    return false;  // Non-reducible symbolic expression, bail out.

  // Keep things simple. Don't touch loop-variant strides.
  if (!Stride->isLoopInvariant(L) && L->contains(I->getParent()))
    return false;

  SmallPtrSet<Instruction *, 4> UniqueUsers;
  for (Value::use_iterator UI = I->use_begin(), E = I->use_end();
       UI != E; ++UI) {
    Instruction *User = cast<Instruction>(*UI);
    if (!UniqueUsers.insert(User))
      continue;

    // Do not infinitely recurse on PHI nodes.
    if (isa<PHINode>(User) && Processed.count(User))
      continue;

    // Descend recursively, but not into PHI nodes outside the current loop.
    // It's important to see the entire expression outside the loop to get
    // choices that depend on addressing mode use right, although we won't
    // consider references ouside the loop in all cases.
    // If User is already in Processed, we don't want to recurse into it again,
    // but do want to record a second reference in the same instruction.
    bool AddUserToIVUsers = false;
    if (LI->getLoopFor(User->getParent()) != L) {
      if (isa<PHINode>(User) || Processed.count(User) ||
          !AddUsersIfInteresting(User)) {
        DEBUG(errs() << "FOUND USER in other loop: " << *User << '\n'
                     << "   OF SCEV: " << *ISE << '\n');
        AddUserToIVUsers = true;
      }
    } else if (Processed.count(User) ||
               !AddUsersIfInteresting(User)) {
      DEBUG(errs() << "FOUND USER: " << *User << '\n'
                   << "   OF SCEV: " << *ISE << '\n');
      AddUserToIVUsers = true;
    }

    if (AddUserToIVUsers) {
      IVUsersOfOneStride *StrideUses = IVUsesByStride[Stride];
      if (!StrideUses) {    // First occurrence of this stride?
        StrideOrder.push_back(Stride);
        StrideUses = new IVUsersOfOneStride(Stride);
        IVUses.push_back(StrideUses);
        IVUsesByStride[Stride] = StrideUses;
      }

      // Okay, we found a user that we cannot reduce.  Analyze the instruction
      // and decide what to do with it.  If we are a use inside of the loop, use
      // the value before incrementation, otherwise use it after incrementation.
      if (IVUseShouldUsePostIncValue(User, I, L, LI, DT, this)) {
        // The value used will be incremented by the stride more than we are
        // expecting, so subtract this off.
        const SCEV *NewStart = SE->getMinusSCEV(Start, Stride);
        StrideUses->addUser(NewStart, User, I);
        StrideUses->Users.back().setIsUseOfPostIncrementedValue(true);
        DEBUG(errs() << "   USING POSTINC SCEV, START=" << *NewStart<< "\n");
      } else {
        StrideUses->addUser(Start, User, I);
      }
    }
  }
  return true;
}

void IVUsers::AddUser(const SCEV *Stride, const SCEV *Offset,
                      Instruction *User, Value *Operand) {
  IVUsersOfOneStride *StrideUses = IVUsesByStride[Stride];
  if (!StrideUses) {    // First occurrence of this stride?
    StrideOrder.push_back(Stride);
    StrideUses = new IVUsersOfOneStride(Stride);
    IVUses.push_back(StrideUses);
    IVUsesByStride[Stride] = StrideUses;
  }
  IVUsesByStride[Stride]->addUser(Offset, User, Operand);
}

IVUsers::IVUsers()
 : LoopPass(&ID) {
}

void IVUsers::getAnalysisUsage(AnalysisUsage &AU) const {
  AU.addRequired<LoopInfo>();
  AU.addRequired<DominatorTree>();
  AU.addRequired<ScalarEvolution>();
  AU.setPreservesAll();
}

bool IVUsers::runOnLoop(Loop *l, LPPassManager &LPM) {

  L = l;
  LI = &getAnalysis<LoopInfo>();
  DT = &getAnalysis<DominatorTree>();
  SE = &getAnalysis<ScalarEvolution>();

  // Find all uses of induction variables in this loop, and categorize
  // them by stride.  Start by finding all of the PHI nodes in the header for
  // this loop.  If they are induction variables, inspect their uses.
  for (BasicBlock::iterator I = L->getHeader()->begin(); isa<PHINode>(I); ++I)
    AddUsersIfInteresting(I);

  return false;
}

/// getReplacementExpr - Return a SCEV expression which computes the
/// value of the OperandValToReplace of the given IVStrideUse.
const SCEV *IVUsers::getReplacementExpr(const IVStrideUse &U) const {
  // Start with zero.
  const SCEV *RetVal = SE->getIntegerSCEV(0, U.getParent()->Stride->getType());
  // Create the basic add recurrence.
  RetVal = SE->getAddRecExpr(RetVal, U.getParent()->Stride, L);
  // Add the offset in a separate step, because it may be loop-variant.
  RetVal = SE->getAddExpr(RetVal, U.getOffset());
  // For uses of post-incremented values, add an extra stride to compute
  // the actual replacement value.
  if (U.isUseOfPostIncrementedValue())
    RetVal = SE->getAddExpr(RetVal, U.getParent()->Stride);
  // Evaluate the expression out of the loop, if possible.
  if (!L->contains(U.getUser()->getParent())) {
    const SCEV *ExitVal = SE->getSCEVAtScope(RetVal, L->getParentLoop());
    if (ExitVal->isLoopInvariant(L))
      RetVal = ExitVal;
  }
  return RetVal;
}

void IVUsers::print(raw_ostream &OS, const Module *M) const {
  OS << "IV Users for loop ";
  WriteAsOperand(OS, L->getHeader(), false);
  if (SE->hasLoopInvariantBackedgeTakenCount(L)) {
    OS << " with backedge-taken count "
       << *SE->getBackedgeTakenCount(L);
  }
  OS << ":\n";

  for (unsigned Stride = 0, e = StrideOrder.size(); Stride != e; ++Stride) {
    std::map<const SCEV *, IVUsersOfOneStride*>::const_iterator SI =
      IVUsesByStride.find(StrideOrder[Stride]);
    assert(SI != IVUsesByStride.end() && "Stride doesn't exist!");
    OS << "  Stride " << *SI->first->getType() << " " << *SI->first << ":\n";

    for (ilist<IVStrideUse>::const_iterator UI = SI->second->Users.begin(),
         E = SI->second->Users.end(); UI != E; ++UI) {
      OS << "    ";
      WriteAsOperand(OS, UI->getOperandValToReplace(), false);
      OS << " = ";
      OS << *getReplacementExpr(*UI);
      if (UI->isUseOfPostIncrementedValue())
        OS << " (post-inc)";
      OS << " in ";
      UI->getUser()->print(OS);
      OS << '\n';
    }
  }
}

void IVUsers::dump() const {
  print(errs());
}

void IVUsers::releaseMemory() {
  IVUsesByStride.clear();
  StrideOrder.clear();
  Processed.clear();
  IVUses.clear();
}

void IVStrideUse::deleted() {
  // Remove this user from the list.
  Parent->Users.erase(this);
  // this now dangles!
}
