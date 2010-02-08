//== AdjustedReturnValueChecker.cpp -----------------------------*- C++ -*--==//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines AdjustedReturnValueChecker, a simple check to see if the
// return value of a function call is different than the one the caller thinks
// it is.
//
//===----------------------------------------------------------------------===//

#include "GRExprEngineInternalChecks.h"
#include "clang/Checker/PathSensitive/GRExprEngine.h"
#include "clang/Checker/BugReporter/BugReporter.h"
#include "clang/Checker/PathSensitive/CheckerVisitor.h"
#include "clang/Basic/SourceManager.h"
#include "llvm/ADT/SmallString.h"

using namespace clang;

namespace {
class AdjustedReturnValueChecker : 
    public CheckerVisitor<AdjustedReturnValueChecker> {      
public:
  AdjustedReturnValueChecker() {}

  void PostVisitCallExpr(CheckerContext &C, const CallExpr *CE);
      
  static void *getTag() {
    static int x = 0; return &x;
  }      
};
}

void clang::RegisterAdjustedReturnValueChecker(GRExprEngine &Eng) {
  Eng.registerCheck(new AdjustedReturnValueChecker());
}

void AdjustedReturnValueChecker::PostVisitCallExpr(CheckerContext &C,
                                                   const CallExpr *CE) {
  
  // Get the result type of the call.
  QualType expectedResultTy = CE->getType();

  // Fetch the signature of the called function.
  const GRState *state = C.getState();

  SVal V = state->getSVal(CE);
  
  if (V.isUnknown())
    return;
  
  // Casting to void?  Discard the value.
  if (expectedResultTy->isVoidType()) {
    C.GenerateNode(state->BindExpr(CE, UnknownVal()));
    return;
  }                   

  const MemRegion *callee = state->getSVal(CE->getCallee()).getAsRegion();
  if (!callee)
    return;

  QualType actualResultTy;
  
  if (const FunctionTextRegion *FT = dyn_cast<FunctionTextRegion>(callee)) {
    const FunctionDecl *FD = FT->getDecl();
    actualResultTy = FD->getResultType();
  }
  else if (const BlockDataRegion *BD = dyn_cast<BlockDataRegion>(callee)) {
    const BlockTextRegion *BR = BD->getCodeRegion();
    const BlockPointerType *BT =
      BR->getLocationType(C.getASTContext())->getAs<BlockPointerType>();
    const FunctionType *FT = BT->getPointeeType()->getAs<FunctionType>();
    actualResultTy = FT->getResultType();
  }

  // Can this happen?
  if (actualResultTy.isNull())
    return;

  // For now, ignore references.
  if (actualResultTy->getAs<ReferenceType>())
    return;
  

  // Are they the same?
  if (expectedResultTy != actualResultTy) {
    // FIXME: Do more checking and actual emit an error. At least performing
    // the cast avoids some assertion failures elsewhere.
    SValuator &SVator = C.getSValuator();
    V = SVator.EvalCast(V, expectedResultTy, actualResultTy);
    C.GenerateNode(state->BindExpr(CE, V));
  }
}
