//== SimpleConstraintManager.h ----------------------------------*- C++ -*--==//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
//  Code shared between BasicConstraintManager and RangeConstraintManager.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_CLANG_ANALYSIS_SIMPLE_CONSTRAINT_MANAGER_H
#define LLVM_CLANG_ANALYSIS_SIMPLE_CONSTRAINT_MANAGER_H

#include "clang/Analysis/PathSensitive/ConstraintManager.h"
#include "clang/Analysis/PathSensitive/GRState.h"

namespace clang {

class SimpleConstraintManager : public ConstraintManager {
public:
  SimpleConstraintManager() {}
  virtual ~SimpleConstraintManager();

  //===------------------------------------------------------------------===//
  // Common implementation for the interface provided by ConstraintManager.
  //===------------------------------------------------------------------===//

  bool canReasonAbout(SVal X) const;

  const GRState *Assume(const GRState *state, SVal Cond, bool Assumption);

  const GRState *Assume(const GRState *state, Loc Cond, bool Assumption);

  const GRState *Assume(const GRState *state, NonLoc Cond, bool Assumption);

  const GRState *AssumeSymInt(const GRState *state, bool Assumption,
                              const SymIntExpr *SE);

  const GRState *AssumeInBound(const GRState *state, SVal Idx, SVal UpperBound,
                               bool Assumption);

protected:

  //===------------------------------------------------------------------===//
  // Interface that subclasses must implement.
  //===------------------------------------------------------------------===//

  virtual const GRState *AssumeSymNE(const GRState *state, SymbolRef sym,
                                     const llvm::APSInt& V) = 0;

  virtual const GRState *AssumeSymEQ(const GRState *state, SymbolRef sym,
                                     const llvm::APSInt& V) = 0;

  virtual const GRState *AssumeSymLT(const GRState *state, SymbolRef sym,
                                     const llvm::APSInt& V) = 0;

  virtual const GRState *AssumeSymGT(const GRState *state, SymbolRef sym,
                                     const llvm::APSInt& V) = 0;

  virtual const GRState *AssumeSymLE(const GRState *state, SymbolRef sym,
                                     const llvm::APSInt& V) = 0;

  virtual const GRState *AssumeSymGE(const GRState *state, SymbolRef sym,
                                     const llvm::APSInt& V) = 0;

  //===------------------------------------------------------------------===//
  // Internal implementation.
  //===------------------------------------------------------------------===//

  const GRState *AssumeAux(const GRState *state, Loc Cond,bool Assumption);

  const GRState *AssumeAux(const GRState *state, NonLoc Cond, bool Assumption);
};

}  // end clang namespace

#endif
