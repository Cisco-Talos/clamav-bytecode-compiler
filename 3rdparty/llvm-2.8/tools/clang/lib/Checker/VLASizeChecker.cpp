//=== VLASizeChecker.cpp - Undefined dereference checker --------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This defines VLASizeChecker, a builtin check in GRExprEngine that 
// performs checks for declaration of VLA of undefined or zero size.
// In addition, VLASizeChecker is responsible for defining the extent
// of the MemRegion that represents a VLA.
//
//===----------------------------------------------------------------------===//

#include "GRExprEngineInternalChecks.h"
#include "clang/AST/CharUnits.h"
#include "clang/Checker/BugReporter/BugType.h"
#include "clang/Checker/PathSensitive/CheckerVisitor.h"
#include "clang/Checker/PathSensitive/GRExprEngine.h"

using namespace clang;

namespace {
class VLASizeChecker : public CheckerVisitor<VLASizeChecker> {
  BugType *BT_zero;
  BugType *BT_undef;
  
public:
  VLASizeChecker() : BT_zero(0), BT_undef(0) {}
  static void *getTag() { static int tag = 0; return &tag; }
  void PreVisitDeclStmt(CheckerContext &C, const DeclStmt *DS);
};
} // end anonymous namespace

void clang::RegisterVLASizeChecker(GRExprEngine &Eng) {
  Eng.registerCheck(new VLASizeChecker());
}

void VLASizeChecker::PreVisitDeclStmt(CheckerContext &C, const DeclStmt *DS) {
  if (!DS->isSingleDecl())
    return;
  
  const VarDecl *VD = dyn_cast<VarDecl>(DS->getSingleDecl());
  if (!VD)
    return;

  ASTContext &Ctx = C.getASTContext();
  const VariableArrayType *VLA = Ctx.getAsVariableArrayType(VD->getType());
  if (!VLA)
    return;

  // FIXME: Handle multi-dimensional VLAs.
  const Expr* SE = VLA->getSizeExpr();
  const GRState *state = C.getState();
  SVal sizeV = state->getSVal(SE);

  if (sizeV.isUndef()) {
    // Generate an error node.
    ExplodedNode *N = C.GenerateSink();
    if (!N)
      return;
    
    if (!BT_undef)
      BT_undef = new BuiltinBug("Declared variable-length array (VLA) uses a "
                                "garbage value as its size");

    EnhancedBugReport *report =
      new EnhancedBugReport(*BT_undef, BT_undef->getName(), N);
    report->addRange(SE->getSourceRange());
    report->addVisitorCreator(bugreporter::registerTrackNullOrUndefValue, SE);
    C.EmitReport(report);
    return;
  }

  // See if the size value is known. It can't be undefined because we would have
  // warned about that already.
  if (sizeV.isUnknown())
    return;
  
  // Check if the size is zero.
  DefinedSVal sizeD = cast<DefinedSVal>(sizeV);

  const GRState *stateNotZero, *stateZero;
  llvm::tie(stateNotZero, stateZero) = state->Assume(sizeD);

  if (stateZero && !stateNotZero) {
    ExplodedNode* N = C.GenerateSink(stateZero);
    if (!BT_zero)
      BT_zero = new BuiltinBug("Declared variable-length array (VLA) has zero "
                               "size");

    EnhancedBugReport *report =
      new EnhancedBugReport(*BT_zero, BT_zero->getName(), N);
    report->addRange(SE->getSourceRange());
    report->addVisitorCreator(bugreporter::registerTrackNullOrUndefValue, SE);
    C.EmitReport(report);
    return;
  }
 
  // From this point on, assume that the size is not zero.
  state = stateNotZero;

  // VLASizeChecker is responsible for defining the extent of the array being
  // declared. We do this by multiplying the array length by the element size,
  // then matching that with the array region's extent symbol.

  // Convert the array length to size_t.
  ValueManager &ValMgr = C.getValueManager();
  SValuator &SV = ValMgr.getSValuator();
  QualType SizeTy = Ctx.getSizeType();
  NonLoc ArrayLength = cast<NonLoc>(SV.EvalCast(sizeD, SizeTy, SE->getType()));

  // Get the element size.
  CharUnits EleSize = Ctx.getTypeSizeInChars(VLA->getElementType());
  SVal EleSizeVal = ValMgr.makeIntVal(EleSize.getQuantity(), SizeTy);

  // Multiply the array length by the element size.
  SVal ArraySizeVal = SV.EvalBinOpNN(state, BO_Mul, ArrayLength,
                                     cast<NonLoc>(EleSizeVal), SizeTy);

  // Finally, Assume that the array's extent matches the given size.
  const LocationContext *LC = C.getPredecessor()->getLocationContext();
  DefinedOrUnknownSVal Extent = state->getRegion(VD, LC)->getExtent(ValMgr);
  DefinedOrUnknownSVal ArraySize = cast<DefinedOrUnknownSVal>(ArraySizeVal);
  DefinedOrUnknownSVal SizeIsKnown = SV.EvalEQ(state, Extent, ArraySize);
  state = state->Assume(SizeIsKnown, true);

  // Assume should not fail at this point.
  assert(state);

  // Remember our assumptions!
  C.addTransition(state);
}
