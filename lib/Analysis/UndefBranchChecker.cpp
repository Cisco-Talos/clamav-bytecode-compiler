//=== UndefBranchChecker.cpp -----------------------------------*- C++ -*--===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines UndefBranchChecker, which checks for undefined branch
// condition.
//
//===----------------------------------------------------------------------===//

#include "GRExprEngineInternalChecks.h"
#include "clang/Analysis/PathSensitive/Checker.h"

using namespace clang;

namespace {

class VISIBILITY_HIDDEN UndefBranchChecker : public Checker {
  BuiltinBug *BT;

  struct VISIBILITY_HIDDEN FindUndefExpr {
    GRStateManager& VM;
    const GRState* St;

    FindUndefExpr(GRStateManager& V, const GRState* S) : VM(V), St(S) {}

    Expr* FindExpr(Expr* Ex) {
      if (!MatchesCriteria(Ex))
        return 0;

      for (Stmt::child_iterator I=Ex->child_begin(), E=Ex->child_end();I!=E;++I)
        if (Expr* ExI = dyn_cast_or_null<Expr>(*I)) {
          Expr* E2 = FindExpr(ExI);
          if (E2) return E2;
        }

      return Ex;
    }

    bool MatchesCriteria(Expr* Ex) { return St->getSVal(Ex).isUndef(); }
  };

public:
  UndefBranchChecker() : BT(0) {}
  static void *getTag();
  void VisitBranchCondition(GRBranchNodeBuilder &Builder, GRExprEngine &Eng,
                            Stmt *Condition, void *tag);
};

}

void clang::RegisterUndefBranchChecker(GRExprEngine &Eng) {
  Eng.registerCheck(new UndefBranchChecker());
}

void *UndefBranchChecker::getTag() {
  static int x;
  return &x;
}

void UndefBranchChecker::VisitBranchCondition(GRBranchNodeBuilder &Builder, 
                                              GRExprEngine &Eng,
                                              Stmt *Condition, void *tag) {
  const GRState *state = Builder.getState();
  SVal X = state->getSVal(Condition);
  if (X.isUndef()) {
    ExplodedNode *N = Builder.generateNode(state, true);
    if (N) {
      N->markAsSink();
      if (!BT)
        BT = new BuiltinBug("Branch condition evaluates to a garbage value");
      EnhancedBugReport *R = new EnhancedBugReport(*BT, BT->getDescription(),N);
      R->addVisitorCreator(bugreporter::registerTrackNullOrUndefValue, 
                           Condition);

      // What's going on here: we want to highlight the subexpression of the
      // condition that is the most likely source of the "uninitialized
      // branch condition."  We do a recursive walk of the condition's
      // subexpressions and roughly look for the most nested subexpression
      // that binds to Undefined.  We then highlight that expression's range.
      BlockEdge B = cast<BlockEdge>(N->getLocation());
      Expr* Ex = cast<Expr>(B.getSrc()->getTerminatorCondition());
      assert (Ex && "Block must have a terminator.");

      // Get the predecessor node and check if is a PostStmt with the Stmt
      // being the terminator condition.  We want to inspect the state
      // of that node instead because it will contain main information about
      // the subexpressions.
      assert (!N->pred_empty());

      // Note: any predecessor will do.  They should have identical state,
      // since all the BlockEdge did was act as an error sink since the value
      // had to already be undefined.
      ExplodedNode *PrevN = *N->pred_begin();
      ProgramPoint P = PrevN->getLocation();
      const GRState* St = N->getState();

      if (PostStmt* PS = dyn_cast<PostStmt>(&P))
        if (PS->getStmt() == Ex)
          St = PrevN->getState();

      FindUndefExpr FindIt(Eng.getStateManager(), St);
      Ex = FindIt.FindExpr(Ex);
      R->addRange(Ex->getSourceRange());

      Eng.getBugReporter().EmitReport(R);
    }

    Builder.markInfeasible(true);
    Builder.markInfeasible(false);
  }
}
