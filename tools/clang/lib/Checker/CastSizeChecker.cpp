//=== CastSizeChecker.cpp ---------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// CastSizeChecker checks when casting a malloc'ed symbolic region to type T,
// whether the size of the symbolic region is a multiple of the size of T.
//
//===----------------------------------------------------------------------===//
#include "clang/AST/CharUnits.h"
#include "clang/Checker/BugReporter/BugType.h"
#include "clang/Checker/PathSensitive/CheckerVisitor.h"
#include "GRExprEngineInternalChecks.h"

using namespace clang;

namespace {
class CastSizeChecker : public CheckerVisitor<CastSizeChecker> {
  BuiltinBug *BT;
public:
  CastSizeChecker() : BT(0) {}
  static void *getTag();
  void PreVisitCastExpr(CheckerContext &C, const CastExpr *B);
};
}

void *CastSizeChecker::getTag() {
  static int x;
  return &x;
}

void CastSizeChecker::PreVisitCastExpr(CheckerContext &C, const CastExpr *CE) {
  const Expr *E = CE->getSubExpr();
  ASTContext &Ctx = C.getASTContext();
  QualType ToTy = Ctx.getCanonicalType(CE->getType());
  PointerType *ToPTy = dyn_cast<PointerType>(ToTy.getTypePtr());

  if (!ToPTy)
    return;

  QualType ToPointeeTy = ToPTy->getPointeeType();

  // Only perform the check if 'ToPointeeTy' is a complete type.
  if (ToPointeeTy->isIncompleteType())
    return;

  const GRState *state = C.getState();
  const MemRegion *R = state->getSVal(E).getAsRegion();
  if (R == 0)
    return;

  const SymbolicRegion *SR = dyn_cast<SymbolicRegion>(R);
  if (SR == 0)
    return;

  ValueManager &ValMgr = C.getValueManager();
  SVal Extent = SR->getExtent(ValMgr);

  SValuator &SVator = ValMgr.getSValuator();
  const llvm::APSInt *ExtentInt = SVator.getKnownValue(state, Extent);
  if (!ExtentInt)
    return;

  CharUnits RegionSize = CharUnits::fromQuantity(ExtentInt->getSExtValue());
  CharUnits TypeSize = C.getASTContext().getTypeSizeInChars(ToPointeeTy);
  
  // Ignore void, and a few other un-sizeable types.
  if (TypeSize.isZero())
    return;
  
  if (RegionSize % TypeSize != 0) {
    if (ExplodedNode *N = C.GenerateSink()) {
      if (!BT)
        BT = new BuiltinBug("Cast region with wrong size.",
                            "Cast a region whose size is not a multiple of the"
                            " destination type size.");
      RangedBugReport *R = new RangedBugReport(*BT, BT->getDescription(), N);
      R->addRange(CE->getSourceRange());
      C.EmitReport(R);
    }
  }
}


void clang::RegisterCastSizeChecker(GRExprEngine &Eng) {
  Eng.registerCheck(new CastSizeChecker());
}
