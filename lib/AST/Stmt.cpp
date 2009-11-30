//===--- Stmt.cpp - Statement AST Node Implementation ---------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements the Stmt class and statement subclasses.
//
//===----------------------------------------------------------------------===//

#include "clang/AST/Stmt.h"
#include "clang/AST/ExprCXX.h"
#include "clang/AST/ExprObjC.h"
#include "clang/AST/StmtCXX.h"
#include "clang/AST/StmtObjC.h"
#include "clang/AST/Type.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/ASTDiagnostic.h"
#include <cstdio>
using namespace clang;

static struct StmtClassNameTable {
  const char *Name;
  unsigned Counter;
  unsigned Size;
} StmtClassInfo[Stmt::lastExprConstant+1];

static StmtClassNameTable &getStmtInfoTableEntry(Stmt::StmtClass E) {
  static bool Initialized = false;
  if (Initialized)
    return StmtClassInfo[E];

  // Intialize the table on the first use.
  Initialized = true;
#define STMT(CLASS, PARENT) \
  StmtClassInfo[(unsigned)Stmt::CLASS##Class].Name = #CLASS;    \
  StmtClassInfo[(unsigned)Stmt::CLASS##Class].Size = sizeof(CLASS);
#include "clang/AST/StmtNodes.def"

  return StmtClassInfo[E];
}

const char *Stmt::getStmtClassName() const {
  return getStmtInfoTableEntry((StmtClass)sClass).Name;
}

void Stmt::DestroyChildren(ASTContext &C) {
  for (child_iterator I = child_begin(), E = child_end(); I !=E; )
    if (Stmt* Child = *I++) Child->Destroy(C);
}

void Stmt::DoDestroy(ASTContext &C) {
  DestroyChildren(C);
  this->~Stmt();
  C.Deallocate((void *)this);
}

void Stmt::PrintStats() {
  // Ensure the table is primed.
  getStmtInfoTableEntry(Stmt::NullStmtClass);

  unsigned sum = 0;
  fprintf(stderr, "*** Stmt/Expr Stats:\n");
  for (int i = 0; i != Stmt::lastExprConstant+1; i++) {
    if (StmtClassInfo[i].Name == 0) continue;
    sum += StmtClassInfo[i].Counter;
  }
  fprintf(stderr, "  %d stmts/exprs total.\n", sum);
  sum = 0;
  for (int i = 0; i != Stmt::lastExprConstant+1; i++) {
    if (StmtClassInfo[i].Name == 0) continue;
    if (StmtClassInfo[i].Counter == 0) continue;
    fprintf(stderr, "    %d %s, %d each (%d bytes)\n",
            StmtClassInfo[i].Counter, StmtClassInfo[i].Name,
            StmtClassInfo[i].Size,
            StmtClassInfo[i].Counter*StmtClassInfo[i].Size);
    sum += StmtClassInfo[i].Counter*StmtClassInfo[i].Size;
  }
  fprintf(stderr, "Total bytes = %d\n", sum);
}

void Stmt::addStmtClass(StmtClass s) {
  ++getStmtInfoTableEntry(s).Counter;
}

static bool StatSwitch = false;

bool Stmt::CollectingStats(bool Enable) {
  if (Enable) StatSwitch = true;
  return StatSwitch;
}

void SwitchStmt::DoDestroy(ASTContext &Ctx) {
  // Destroy the SwitchCase statements in this switch. In the normal
  // case, this loop will merely decrement the reference counts from
  // the Retain() calls in addSwitchCase();
  SwitchCase *SC = FirstCase;
  while (SC) {
    SwitchCase *Next = SC->getNextSwitchCase();
    SC->Destroy(Ctx);
    SC = Next;
  }

  Stmt::DoDestroy(Ctx);
}

void CompoundStmt::setStmts(ASTContext &C, Stmt **Stmts, unsigned NumStmts) {
  if (this->Body)
    C.Deallocate(Body);
  this->NumStmts = NumStmts;

  Body = new (C) Stmt*[NumStmts];
  memcpy(Body, Stmts, sizeof(Stmt *) * NumStmts);
}

const char *LabelStmt::getName() const {
  return getID()->getNameStart();
}

// This is defined here to avoid polluting Stmt.h with importing Expr.h
SourceRange ReturnStmt::getSourceRange() const {
  if (RetExpr)
    return SourceRange(RetLoc, RetExpr->getLocEnd());
  else
    return SourceRange(RetLoc);
}

bool Stmt::hasImplicitControlFlow() const {
  switch (sClass) {
    default:
      return false;

    case CallExprClass:
    case ConditionalOperatorClass:
    case ChooseExprClass:
    case StmtExprClass:
    case DeclStmtClass:
      return true;

    case Stmt::BinaryOperatorClass: {
      const BinaryOperator* B = cast<BinaryOperator>(this);
      if (B->isLogicalOp() || B->getOpcode() == BinaryOperator::Comma)
        return true;
      else
        return false;
    }
  }
}

Expr *AsmStmt::getOutputExpr(unsigned i) {
  return cast<Expr>(Exprs[i]);
}

/// getOutputConstraint - Return the constraint string for the specified
/// output operand.  All output constraints are known to be non-empty (either
/// '=' or '+').
std::string AsmStmt::getOutputConstraint(unsigned i) const {
  return std::string(Constraints[i]->getStrData(),
                     Constraints[i]->getByteLength());
}

/// getNumPlusOperands - Return the number of output operands that have a "+"
/// constraint.
unsigned AsmStmt::getNumPlusOperands() const {
  unsigned Res = 0;
  for (unsigned i = 0, e = getNumOutputs(); i != e; ++i)
    if (isOutputPlusConstraint(i))
      ++Res;
  return Res;
}



Expr *AsmStmt::getInputExpr(unsigned i) {
  return cast<Expr>(Exprs[i + NumOutputs]);
}

/// getInputConstraint - Return the specified input constraint.  Unlike output
/// constraints, these can be empty.
std::string AsmStmt::getInputConstraint(unsigned i) const {
  return std::string(Constraints[i + NumOutputs]->getStrData(),
                     Constraints[i + NumOutputs]->getByteLength());
}


void AsmStmt::setOutputsAndInputs(unsigned NumOutputs,
                                  unsigned NumInputs,
                                  const std::string *Names,
                                  StringLiteral **Constraints,
                                  Stmt **Exprs) {
  this->NumOutputs = NumOutputs;
  this->NumInputs = NumInputs;
  this->Names.clear();
  this->Names.insert(this->Names.end(), Names, Names + NumOutputs + NumInputs);
  this->Constraints.clear();
  this->Constraints.insert(this->Constraints.end(),
                           Constraints, Constraints + NumOutputs + NumInputs);
  this->Exprs.clear();
  this->Exprs.insert(this->Exprs.end(), Exprs, Exprs + NumOutputs + NumInputs);
}

/// getNamedOperand - Given a symbolic operand reference like %[foo],
/// translate this into a numeric value needed to reference the same operand.
/// This returns -1 if the operand name is invalid.
int AsmStmt::getNamedOperand(const std::string &SymbolicName) const {
  unsigned NumPlusOperands = 0;

  // Check if this is an output operand.
  for (unsigned i = 0, e = getNumOutputs(); i != e; ++i) {
    if (getOutputName(i) == SymbolicName)
      return i;
  }

  for (unsigned i = 0, e = getNumInputs(); i != e; ++i)
    if (getInputName(i) == SymbolicName)
      return getNumOutputs() + NumPlusOperands + i;

  // Not found.
  return -1;
}

void AsmStmt::setClobbers(StringLiteral **Clobbers, unsigned NumClobbers) {
  this->Clobbers.clear();
  this->Clobbers.insert(this->Clobbers.end(), Clobbers, Clobbers + NumClobbers);
}

/// AnalyzeAsmString - Analyze the asm string of the current asm, decomposing
/// it into pieces.  If the asm string is erroneous, emit errors and return
/// true, otherwise return false.
unsigned AsmStmt::AnalyzeAsmString(llvm::SmallVectorImpl<AsmStringPiece>&Pieces,
                                   ASTContext &C, unsigned &DiagOffs) const {
  const char *StrStart = getAsmString()->getStrData();
  const char *StrEnd = StrStart + getAsmString()->getByteLength();
  const char *CurPtr = StrStart;

  // "Simple" inline asms have no constraints or operands, just convert the asm
  // string to escape $'s.
  if (isSimple()) {
    std::string Result;
    for (; CurPtr != StrEnd; ++CurPtr) {
      switch (*CurPtr) {
      case '$':
        Result += "$$";
        break;
      default:
        Result += *CurPtr;
        break;
      }
    }
    Pieces.push_back(AsmStringPiece(Result));
    return 0;
  }

  // CurStringPiece - The current string that we are building up as we scan the
  // asm string.
  std::string CurStringPiece;

  while (1) {
    // Done with the string?
    if (CurPtr == StrEnd) {
      if (!CurStringPiece.empty())
        Pieces.push_back(AsmStringPiece(CurStringPiece));
      return 0;
    }

    char CurChar = *CurPtr++;
    if (CurChar == '$') {
      CurStringPiece += "$$";
      continue;
    } else if (CurChar != '%') {
      CurStringPiece += CurChar;
      continue;
    }

    // Escaped "%" character in asm string.
    if (CurPtr == StrEnd) {
      // % at end of string is invalid (no escape).
      DiagOffs = CurPtr-StrStart-1;
      return diag::err_asm_invalid_escape;
    }

    char EscapedChar = *CurPtr++;
    if (EscapedChar == '%') {  // %% -> %
      // Escaped percentage sign.
      CurStringPiece += '%';
      continue;
    }

    if (EscapedChar == '=') {  // %= -> Generate an unique ID.
      CurStringPiece += "${:uid}";
      continue;
    }

    // Otherwise, we have an operand.  If we have accumulated a string so far,
    // add it to the Pieces list.
    if (!CurStringPiece.empty()) {
      Pieces.push_back(AsmStringPiece(CurStringPiece));
      CurStringPiece.clear();
    }

    // Handle %x4 and %x[foo] by capturing x as the modifier character.
    char Modifier = '\0';
    if (isalpha(EscapedChar)) {
      Modifier = EscapedChar;
      EscapedChar = *CurPtr++;
    }

    if (isdigit(EscapedChar)) {
      // %n - Assembler operand n
      unsigned N = 0;

      --CurPtr;
      while (CurPtr != StrEnd && isdigit(*CurPtr))
        N = N*10 + ((*CurPtr++)-'0');

      unsigned NumOperands =
        getNumOutputs() + getNumPlusOperands() + getNumInputs();
      if (N >= NumOperands) {
        DiagOffs = CurPtr-StrStart-1;
        return diag::err_asm_invalid_operand_number;
      }

      Pieces.push_back(AsmStringPiece(N, Modifier));
      continue;
    }

    // Handle %[foo], a symbolic operand reference.
    if (EscapedChar == '[') {
      DiagOffs = CurPtr-StrStart-1;

      // Find the ']'.
      const char *NameEnd = (const char*)memchr(CurPtr, ']', StrEnd-CurPtr);
      if (NameEnd == 0)
        return diag::err_asm_unterminated_symbolic_operand_name;
      if (NameEnd == CurPtr)
        return diag::err_asm_empty_symbolic_operand_name;

      std::string SymbolicName(CurPtr, NameEnd);

      int N = getNamedOperand(SymbolicName);
      if (N == -1) {
        // Verify that an operand with that name exists.
        DiagOffs = CurPtr-StrStart;
        return diag::err_asm_unknown_symbolic_operand_name;
      }
      Pieces.push_back(AsmStringPiece(N, Modifier));

      CurPtr = NameEnd+1;
      continue;
    }

    DiagOffs = CurPtr-StrStart-1;
    return diag::err_asm_invalid_escape;
  }
}

//===----------------------------------------------------------------------===//
// Constructors
//===----------------------------------------------------------------------===//

AsmStmt::AsmStmt(SourceLocation asmloc, bool issimple, bool isvolatile,
                 unsigned numoutputs, unsigned numinputs,
                 std::string *names, StringLiteral **constraints,
                 Expr **exprs, StringLiteral *asmstr, unsigned numclobbers,
                 StringLiteral **clobbers, SourceLocation rparenloc)
  : Stmt(AsmStmtClass), AsmLoc(asmloc), RParenLoc(rparenloc), AsmStr(asmstr)
  , IsSimple(issimple), IsVolatile(isvolatile)
  , NumOutputs(numoutputs), NumInputs(numinputs) {
  for (unsigned i = 0, e = numinputs + numoutputs; i != e; i++) {
    Names.push_back(names[i]);
    Exprs.push_back(exprs[i]);
    Constraints.push_back(constraints[i]);
  }

  for (unsigned i = 0; i != numclobbers; i++)
    Clobbers.push_back(clobbers[i]);
}

ObjCForCollectionStmt::ObjCForCollectionStmt(Stmt *Elem, Expr *Collect,
                                             Stmt *Body,  SourceLocation FCL,
                                             SourceLocation RPL)
: Stmt(ObjCForCollectionStmtClass) {
  SubExprs[ELEM] = Elem;
  SubExprs[COLLECTION] = reinterpret_cast<Stmt*>(Collect);
  SubExprs[BODY] = Body;
  ForLoc = FCL;
  RParenLoc = RPL;
}


ObjCAtCatchStmt::ObjCAtCatchStmt(SourceLocation atCatchLoc,
                                 SourceLocation rparenloc,
                                 ParmVarDecl *catchVarDecl, Stmt *atCatchStmt,
                                 Stmt *atCatchList)
: Stmt(ObjCAtCatchStmtClass) {
  ExceptionDecl = catchVarDecl;
  SubExprs[BODY] = atCatchStmt;
  SubExprs[NEXT_CATCH] = NULL;
  // FIXME: O(N^2) in number of catch blocks.
  if (atCatchList) {
    ObjCAtCatchStmt *AtCatchList = static_cast<ObjCAtCatchStmt*>(atCatchList);

    while (ObjCAtCatchStmt* NextCatch = AtCatchList->getNextCatchStmt())
      AtCatchList = NextCatch;

    AtCatchList->SubExprs[NEXT_CATCH] = this;
  }
  AtCatchLoc = atCatchLoc;
  RParenLoc = rparenloc;
}


//===----------------------------------------------------------------------===//
//  Child Iterators for iterating over subexpressions/substatements
//===----------------------------------------------------------------------===//

// DeclStmt
Stmt::child_iterator DeclStmt::child_begin() {
  return StmtIterator(DG.begin(), DG.end());
}

Stmt::child_iterator DeclStmt::child_end() {
  return StmtIterator(DG.end(), DG.end());
}

// NullStmt
Stmt::child_iterator NullStmt::child_begin() { return child_iterator(); }
Stmt::child_iterator NullStmt::child_end() { return child_iterator(); }

// CompoundStmt
Stmt::child_iterator CompoundStmt::child_begin() { return &Body[0]; }
Stmt::child_iterator CompoundStmt::child_end() { return &Body[0]+NumStmts; }

// CaseStmt
Stmt::child_iterator CaseStmt::child_begin() { return &SubExprs[0]; }
Stmt::child_iterator CaseStmt::child_end() { return &SubExprs[END_EXPR]; }

// DefaultStmt
Stmt::child_iterator DefaultStmt::child_begin() { return &SubStmt; }
Stmt::child_iterator DefaultStmt::child_end() { return &SubStmt+1; }

// LabelStmt
Stmt::child_iterator LabelStmt::child_begin() { return &SubStmt; }
Stmt::child_iterator LabelStmt::child_end() { return &SubStmt+1; }

// IfStmt
Stmt::child_iterator IfStmt::child_begin() { return &SubExprs[0]; }
Stmt::child_iterator IfStmt::child_end() { return &SubExprs[0]+END_EXPR; }

// SwitchStmt
Stmt::child_iterator SwitchStmt::child_begin() { return &SubExprs[0]; }
Stmt::child_iterator SwitchStmt::child_end() { return &SubExprs[0]+END_EXPR; }

// WhileStmt
Stmt::child_iterator WhileStmt::child_begin() { return &SubExprs[0]; }
Stmt::child_iterator WhileStmt::child_end() { return &SubExprs[0]+END_EXPR; }

// DoStmt
Stmt::child_iterator DoStmt::child_begin() { return &SubExprs[0]; }
Stmt::child_iterator DoStmt::child_end() { return &SubExprs[0]+END_EXPR; }

// ForStmt
Stmt::child_iterator ForStmt::child_begin() { return &SubExprs[0]; }
Stmt::child_iterator ForStmt::child_end() { return &SubExprs[0]+END_EXPR; }

// ObjCForCollectionStmt
Stmt::child_iterator ObjCForCollectionStmt::child_begin() {
  return &SubExprs[0];
}
Stmt::child_iterator ObjCForCollectionStmt::child_end() {
  return &SubExprs[0]+END_EXPR;
}

// GotoStmt
Stmt::child_iterator GotoStmt::child_begin() { return child_iterator(); }
Stmt::child_iterator GotoStmt::child_end() { return child_iterator(); }

// IndirectGotoStmt
Expr* IndirectGotoStmt::getTarget() { return cast<Expr>(Target); }
const Expr* IndirectGotoStmt::getTarget() const { return cast<Expr>(Target); }

Stmt::child_iterator IndirectGotoStmt::child_begin() { return &Target; }
Stmt::child_iterator IndirectGotoStmt::child_end() { return &Target+1; }

// ContinueStmt
Stmt::child_iterator ContinueStmt::child_begin() { return child_iterator(); }
Stmt::child_iterator ContinueStmt::child_end() { return child_iterator(); }

// BreakStmt
Stmt::child_iterator BreakStmt::child_begin() { return child_iterator(); }
Stmt::child_iterator BreakStmt::child_end() { return child_iterator(); }

// ReturnStmt
const Expr* ReturnStmt::getRetValue() const {
  return cast_or_null<Expr>(RetExpr);
}
Expr* ReturnStmt::getRetValue() {
  return cast_or_null<Expr>(RetExpr);
}

Stmt::child_iterator ReturnStmt::child_begin() {
  return &RetExpr;
}
Stmt::child_iterator ReturnStmt::child_end() {
  return RetExpr ? &RetExpr+1 : &RetExpr;
}

// AsmStmt
Stmt::child_iterator AsmStmt::child_begin() {
  return Exprs.empty() ? 0 : &Exprs[0];
}
Stmt::child_iterator AsmStmt::child_end() {
  return Exprs.empty() ? 0 : &Exprs[0] + Exprs.size();
}

// ObjCAtCatchStmt
Stmt::child_iterator ObjCAtCatchStmt::child_begin() { return &SubExprs[0]; }
Stmt::child_iterator ObjCAtCatchStmt::child_end() {
  return &SubExprs[0]+END_EXPR;
}

// ObjCAtFinallyStmt
Stmt::child_iterator ObjCAtFinallyStmt::child_begin() { return &AtFinallyStmt; }
Stmt::child_iterator ObjCAtFinallyStmt::child_end() { return &AtFinallyStmt+1; }

// ObjCAtTryStmt
Stmt::child_iterator ObjCAtTryStmt::child_begin() { return &SubStmts[0]; }
Stmt::child_iterator ObjCAtTryStmt::child_end()   {
  return &SubStmts[0]+END_EXPR;
}

// ObjCAtThrowStmt
Stmt::child_iterator ObjCAtThrowStmt::child_begin() {
  return &Throw;
}

Stmt::child_iterator ObjCAtThrowStmt::child_end() {
  return &Throw+1;
}

// ObjCAtSynchronizedStmt
Stmt::child_iterator ObjCAtSynchronizedStmt::child_begin() {
  return &SubStmts[0];
}

Stmt::child_iterator ObjCAtSynchronizedStmt::child_end() {
  return &SubStmts[0]+END_EXPR;
}

// CXXCatchStmt
Stmt::child_iterator CXXCatchStmt::child_begin() {
  return &HandlerBlock;
}

Stmt::child_iterator CXXCatchStmt::child_end() {
  return &HandlerBlock + 1;
}

QualType CXXCatchStmt::getCaughtType() const {
  if (ExceptionDecl)
    return ExceptionDecl->getType();
  return QualType();
}

void CXXCatchStmt::DoDestroy(ASTContext& C) {
  if (ExceptionDecl)
    ExceptionDecl->Destroy(C);
  Stmt::DoDestroy(C);
}

// CXXTryStmt
Stmt::child_iterator CXXTryStmt::child_begin() { return &Stmts[0]; }
Stmt::child_iterator CXXTryStmt::child_end() { return &Stmts[0]+Stmts.size(); }

CXXTryStmt::CXXTryStmt(SourceLocation tryLoc, Stmt *tryBlock,
                       Stmt **handlers, unsigned numHandlers)
  : Stmt(CXXTryStmtClass), TryLoc(tryLoc) {
  Stmts.push_back(tryBlock);
  Stmts.insert(Stmts.end(), handlers, handlers + numHandlers);
}
