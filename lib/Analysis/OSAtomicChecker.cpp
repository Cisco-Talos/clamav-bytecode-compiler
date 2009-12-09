//=== OSAtomicChecker.cpp - OSAtomic functions evaluator --------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This checker evaluates OSAtomic functions.
//
//===----------------------------------------------------------------------===//

#include "GRExprEngineInternalChecks.h"
#include "clang/Analysis/PathSensitive/Checker.h"
#include "clang/Basic/Builtins.h"
#include "llvm/ADT/StringSwitch.h"

using namespace clang;

namespace {

class OSAtomicChecker : public Checker {
public:
  static void *getTag() { static int tag = 0; return &tag; }
  virtual bool EvalCallExpr(CheckerContext &C, const CallExpr *CE);

private:
  bool EvalOSAtomicCompareAndSwap(CheckerContext &C, const CallExpr *CE);
};

}

void clang::RegisterOSAtomicChecker(GRExprEngine &Eng) {
  Eng.registerCheck(new OSAtomicChecker());
}

bool OSAtomicChecker::EvalCallExpr(CheckerContext &C,const CallExpr *CE) {
  const GRState *state = C.getState();
  const Expr *Callee = CE->getCallee();
  SVal L = state->getSVal(Callee);

  const FunctionDecl* FD = L.getAsFunctionDecl();
  if (!FD)
    return false;

  const char *FName = FD->getNameAsCString();

  // Check for compare and swap.
  if (strncmp(FName, "OSAtomicCompareAndSwap", 22) == 0 ||
      strncmp(FName, "objc_atomicCompareAndSwap", 25) == 0)
    return EvalOSAtomicCompareAndSwap(C, CE);

  // FIXME: Other atomics.
  return false;
}

bool OSAtomicChecker::EvalOSAtomicCompareAndSwap(CheckerContext &C, 
                                                 const CallExpr *CE) {
  // Not enough arguments to match OSAtomicCompareAndSwap?
  if (CE->getNumArgs() != 3)
    return false;

  ASTContext &Ctx = C.getASTContext();
  const Expr *oldValueExpr = CE->getArg(0);
  QualType oldValueType = Ctx.getCanonicalType(oldValueExpr->getType());

  const Expr *newValueExpr = CE->getArg(1);
  QualType newValueType = Ctx.getCanonicalType(newValueExpr->getType());

  // Do the types of 'oldValue' and 'newValue' match?
  if (oldValueType != newValueType)
    return false;

  const Expr *theValueExpr = CE->getArg(2);
  const PointerType *theValueType=theValueExpr->getType()->getAs<PointerType>();

  // theValueType not a pointer?
  if (!theValueType)
    return false;

  QualType theValueTypePointee =
    Ctx.getCanonicalType(theValueType->getPointeeType()).getUnqualifiedType();

  // The pointee must match newValueType and oldValueType.
  if (theValueTypePointee != newValueType)
    return false;

  static unsigned magic_load = 0;
  static unsigned magic_store = 0;

  const void *OSAtomicLoadTag = &magic_load;
  const void *OSAtomicStoreTag = &magic_store;

  // Load 'theValue'.
  GRExprEngine &Engine = C.getEngine();
  const GRState *state = C.getState();
  ExplodedNodeSet Tmp;
  SVal location = state->getSVal(theValueExpr);
  // Here we should use the value type of the region as the load type.
  const MemRegion *R = location.getAsRegion()->StripCasts();
  QualType LoadTy;
  if (R) {
    LoadTy = cast<TypedRegion>(R)->getValueType(Ctx);
    location = loc::MemRegionVal(R);
  }
  Engine.EvalLoad(Tmp, const_cast<Expr *>(theValueExpr), C.getPredecessor(), 
                  state, location, OSAtomicLoadTag, LoadTy);

  if (Tmp.empty()) {
    // If no nodes were generated, other checkers must generated sinks. But 
    // since the builder state was restored, we set it manually to prevent 
    // auto transition.
    // FIXME: there should be a better approach.
    C.getNodeBuilder().BuildSinks = true;
    return true;
  }
 
  for (ExplodedNodeSet::iterator I = Tmp.begin(), E = Tmp.end();
       I != E; ++I) {

    ExplodedNode *N = *I;
    const GRState *stateLoad = N->getState();
    SVal theValueVal_untested = stateLoad->getSVal(theValueExpr);
    SVal oldValueVal_untested = stateLoad->getSVal(oldValueExpr);

    // FIXME: Issue an error.
    if (theValueVal_untested.isUndef() || oldValueVal_untested.isUndef()) {
      return false;
    }
    
    DefinedOrUnknownSVal theValueVal =
      cast<DefinedOrUnknownSVal>(theValueVal_untested);
    DefinedOrUnknownSVal oldValueVal =
      cast<DefinedOrUnknownSVal>(oldValueVal_untested);

    SValuator &SVator = Engine.getSValuator();

    // Perform the comparison.
    DefinedOrUnknownSVal Cmp = SVator.EvalEQ(stateLoad,theValueVal,oldValueVal);

    const GRState *stateEqual = stateLoad->Assume(Cmp, true);

    // Were they equal?
    if (stateEqual) {
      // Perform the store.
      ExplodedNodeSet TmpStore;
      SVal val = stateEqual->getSVal(newValueExpr);

      // Handle implicit value casts.
      if (const TypedRegion *R =
          dyn_cast_or_null<TypedRegion>(location.getAsRegion())) {
        llvm::tie(state, val) = SVator.EvalCast(val, state,R->getValueType(Ctx),
                                                newValueExpr->getType());
      }

      Engine.EvalStore(TmpStore, NULL, const_cast<Expr *>(theValueExpr), N, 
                       stateEqual, location, val, OSAtomicStoreTag);

      if (TmpStore.empty()) {
        // If no nodes were generated, other checkers must generated sinks. But 
        // since the builder state was restored, we set it manually to prevent 
        // auto transition.
        // FIXME: there should be a better approach.
        C.getNodeBuilder().BuildSinks = true;
        return true;
      }

      // Now bind the result of the comparison.
      for (ExplodedNodeSet::iterator I2 = TmpStore.begin(),
           E2 = TmpStore.end(); I2 != E2; ++I2) {
        ExplodedNode *predNew = *I2;
        const GRState *stateNew = predNew->getState();
        SVal Res = Engine.getValueManager().makeTruthVal(true, CE->getType());
        C.GenerateNode(stateNew->BindExpr(CE, Res), predNew);
      }
    }

    // Were they not equal?
    if (const GRState *stateNotEqual = stateLoad->Assume(Cmp, false)) {
      SVal Res = Engine.getValueManager().makeTruthVal(false, CE->getType());
      C.GenerateNode(stateNotEqual->BindExpr(CE, Res), N);
    }
  }

  return true;
}
