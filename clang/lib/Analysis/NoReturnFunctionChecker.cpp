//=== NoReturnFunctionChecker.cpp -------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This defines NoReturnFunctionChecker, which evaluates functions that do not
// return to the caller.
//
//===----------------------------------------------------------------------===//

#include "GRExprEngineInternalChecks.h"
#include "clang/Analysis/PathSensitive/Checker.h"
#include "llvm/ADT/StringSwitch.h"

using namespace clang;

namespace {

class NoReturnFunctionChecker : public Checker {
public:
  static void *getTag() { static int tag = 0; return &tag; }
  virtual bool EvalCallExpr(CheckerContext &C, const CallExpr *CE);
};

}

void clang::RegisterNoReturnFunctionChecker(GRExprEngine &Eng) {
  Eng.registerCheck(new NoReturnFunctionChecker());
}

bool NoReturnFunctionChecker::EvalCallExpr(CheckerContext &C, 
                                           const CallExpr *CE) {
  const GRState *state = C.getState();
  const Expr *Callee = CE->getCallee();
  SVal L = state->getSVal(Callee);
  const FunctionDecl *FD = L.getAsFunctionDecl();
  if (!FD)
    return false;

  bool BuildSinks = false;

  if (FD->getAttr<NoReturnAttr>() || FD->getAttr<AnalyzerNoReturnAttr>())
    BuildSinks = true;
  else if (const IdentifierInfo *II = FD->getIdentifier()) {
    // HACK: Some functions are not marked noreturn, and don't return.
    //  Here are a few hardwired ones.  If this takes too long, we can
    //  potentially cache these results.
    BuildSinks 
      = llvm::StringSwitch<bool>(llvm::StringRef(II->getName()))
          .Case("exit", true)
          .Case("panic", true)
          .Case("error", true)
          .Case("Assert", true)
          // FIXME: This is just a wrapper around throwing an exception.
          //  Eventually inter-procedural analysis should handle this easily.
          .Case("ziperr", true)
          .Case("assfail", true)
          .Case("db_error", true)
          .Case("__assert", true)
          .Case("__assert_rtn", true)
          .Case("__assert_fail", true)
          .Case("dtrace_assfail", true)
          .Case("yy_fatal_error", true)
          .Case("_XCAssertionFailureHandler", true)
          .Case("_DTAssertionFailureHandler", true)
          .Case("_TSAssertionFailureHandler", true)
          .Default(false);
  }
  
  if (!BuildSinks)
    return false;

  C.GenerateSink(CE);
  return true;
}
