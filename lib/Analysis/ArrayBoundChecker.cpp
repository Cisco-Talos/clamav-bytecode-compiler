//== ArrayBoundChecker.cpp ------------------------------*- C++ -*--==//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines ArrayBoundChecker, which is a path-sensitive check
// which looks for an out-of-bound array element access.
//
//===----------------------------------------------------------------------===//

#include "GRExprEngineInternalChecks.h"
#include "clang/Analysis/PathSensitive/GRExprEngine.h"
#include "clang/Analysis/PathSensitive/BugReporter.h"
#include "clang/Analysis/PathSensitive/CheckerVisitor.h"

using namespace clang;

namespace {
class VISIBILITY_HIDDEN ArrayBoundChecker : 
    public CheckerVisitor<ArrayBoundChecker> {      
  BuiltinBug *BT;
public:
    ArrayBoundChecker() : BT(0) {}
    static void *getTag();
    void VisitLocation(CheckerContext &C, const Stmt *S, SVal l);
};
}

void clang::RegisterArrayBoundChecker(GRExprEngine &Eng) {
  Eng.registerCheck(new ArrayBoundChecker());
}

void *ArrayBoundChecker::getTag() {
  static int x = 0; return &x;
}

void ArrayBoundChecker::VisitLocation(CheckerContext &C, const Stmt *S, SVal l){
  // Check for out of bound array element access.
  const MemRegion *R = l.getAsRegion();
  if (!R)
    return;

  R = R->StripCasts();

  const ElementRegion *ER = dyn_cast<ElementRegion>(R);
  if (!ER)
    return;

  // Get the index of the accessed element.
  DefinedOrUnknownSVal &Idx = cast<DefinedOrUnknownSVal>(ER->getIndex());

  const GRState *state = C.getState();

  // Get the size of the array.
  SVal NumVal = C.getStoreManager().getSizeInElements(state,
                                                      ER->getSuperRegion());
  DefinedOrUnknownSVal &NumElements = cast<DefinedOrUnknownSVal>(NumVal);

  const GRState *StInBound = state->AssumeInBound(Idx, NumElements, true);
  const GRState *StOutBound = state->AssumeInBound(Idx, NumElements, false);
  if (StOutBound && !StInBound) {
    ExplodedNode *N = C.GenerateNode(S, StOutBound, true);

    if (!N)
      return;
  
    if (!BT)
      BT = new BuiltinBug("Out-of-bound array access",
                       "Access out-of-bound array element (buffer overflow)");

    // FIXME: It would be nice to eventually make this diagnostic more clear,
    // e.g., by referencing the original declaration or by saying *why* this
    // reference is outside the range.

    // Generate a report for this bug.
    RangedBugReport *report = 
      new RangedBugReport(*BT, BT->getDescription().c_str(), N);

    report->addRange(S->getSourceRange());

    C.EmitReport(report);
  }
}
