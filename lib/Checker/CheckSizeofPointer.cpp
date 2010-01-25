//==- CheckSizeofPointer.cpp - Check for sizeof on pointers ------*- C++ -*-==//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
//  This file defines a check for unintended use of sizeof() on pointer
//  expressions.
//
//===----------------------------------------------------------------------===//

#include "clang/Checker/BugReporter/BugReporter.h"
#include "clang/AST/StmtVisitor.h"
#include "clang/Checker/LocalCheckers.h"

using namespace clang;

namespace {
class WalkAST : public StmtVisitor<WalkAST> {
  BugReporter &BR;

public:
  WalkAST(BugReporter &br) : BR(br) {}
  void VisitSizeOfAlignOfExpr(SizeOfAlignOfExpr *E);
  void VisitStmt(Stmt *S) { VisitChildren(S); }
  void VisitChildren(Stmt *S);
};
}

void WalkAST::VisitChildren(Stmt *S) {
  for (Stmt::child_iterator I = S->child_begin(), E = S->child_end(); I!=E; ++I)
    if (Stmt *child = *I)
      Visit(child);
}

// CWE-467: Use of sizeof() on a Pointer Type
void WalkAST::VisitSizeOfAlignOfExpr(SizeOfAlignOfExpr *E) {
  if (!E->isSizeOf())
    return;

  // If an explicit type is used in the code, usually the coder knows what he is
  // doing.
  if (E->isArgumentType())
    return;

  QualType T = E->getTypeOfArgument();
  if (T->isPointerType()) {

    // Many false positives have the form 'sizeof *p'. This is reasonable 
    // because people know what they are doing when they intentionally 
    // dereference the pointer.
    Expr *ArgEx = E->getArgumentExpr();
    if (!isa<DeclRefExpr>(ArgEx->IgnoreParens()))
      return;

    SourceRange R = ArgEx->getSourceRange();
    BR.EmitBasicReport("Potential unintended use of sizeof() on pointer type",
                       "Logic",
                       "The code calls sizeof() on a pointer type. "
                       "This can produce an unexpected result.",
                       E->getLocStart(), &R, 1);
  }
}

void clang::CheckSizeofPointer(const Decl *D, BugReporter &BR) {
  WalkAST walker(BR);
  walker.Visit(D->getBody());
}
