//===--- ExprClassification.cpp - Expression AST Node Implementation ------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements Expr::classify.
//
//===----------------------------------------------------------------------===//

#include "llvm/Support/ErrorHandling.h"
#include "clang/AST/Expr.h"
#include "clang/AST/ExprCXX.h"
#include "clang/AST/ExprObjC.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/DeclObjC.h"
#include "clang/AST/DeclCXX.h"
#include "clang/AST/DeclTemplate.h"
using namespace clang;

typedef Expr::Classification Cl;

static Cl::Kinds ClassifyInternal(ASTContext &Ctx, const Expr *E);
static Cl::Kinds ClassifyDecl(ASTContext &Ctx, const Decl *D);
static Cl::Kinds ClassifyUnnamed(ASTContext &Ctx, QualType T);
static Cl::Kinds ClassifyMemberExpr(ASTContext &Ctx, const MemberExpr *E);
static Cl::Kinds ClassifyBinaryOp(ASTContext &Ctx, const BinaryOperator *E);
static Cl::Kinds ClassifyConditional(ASTContext &Ctx,
                                    const ConditionalOperator *E);
static Cl::ModifiableType IsModifiable(ASTContext &Ctx, const Expr *E,
                                       Cl::Kinds Kind, SourceLocation &Loc);

Cl Expr::ClassifyImpl(ASTContext &Ctx, SourceLocation *Loc) const {
  assert(!TR->isReferenceType() && "Expressions can't have reference type.");

  Cl::Kinds kind = ClassifyInternal(Ctx, this);
  // C99 6.3.2.1: An lvalue is an expression with an object type or an
  //   incomplete type other than void.
  if (!Ctx.getLangOptions().CPlusPlus) {
    // Thus, no functions.
    if (TR->isFunctionType() || TR == Ctx.OverloadTy)
      kind = Cl::CL_Function;
    // No void either, but qualified void is OK because it is "other than void".
    else if (TR->isVoidType() && !Ctx.getCanonicalType(TR).hasQualifiers())
      kind = Cl::CL_Void;
  }

  Cl::ModifiableType modifiable = Cl::CM_Untested;
  if (Loc)
    modifiable = IsModifiable(Ctx, this, kind, *Loc);
  return Classification(kind, modifiable);
}

static Cl::Kinds ClassifyInternal(ASTContext &Ctx, const Expr *E) {
  // This function takes the first stab at classifying expressions.
  const LangOptions &Lang = Ctx.getLangOptions();

  switch (E->getStmtClass()) {
    // First come the expressions that are always lvalues, unconditionally.

  case Expr::ObjCIsaExprClass:
    // C++ [expr.prim.general]p1: A string literal is an lvalue.
  case Expr::StringLiteralClass:
    // @encode is equivalent to its string
  case Expr::ObjCEncodeExprClass:
    // __func__ and friends are too.
  case Expr::PredefinedExprClass:
    // Property references are lvalues
  case Expr::ObjCPropertyRefExprClass:
  case Expr::ObjCImplicitSetterGetterRefExprClass:
    // C++ [expr.typeid]p1: The result of a typeid expression is an lvalue of...
  case Expr::CXXTypeidExprClass:
    // Unresolved lookups get classified as lvalues.
    // FIXME: Is this wise? Should they get their own kind?
  case Expr::UnresolvedLookupExprClass:
  case Expr::UnresolvedMemberExprClass:
    // ObjC instance variables are lvalues
    // FIXME: ObjC++0x might have different rules
  case Expr::ObjCIvarRefExprClass:
    // C99 6.5.2.5p5 says that compound literals are lvalues.
    // FIXME: C++ might have a different opinion.
  case Expr::CompoundLiteralExprClass:
    return Cl::CL_LValue;

    // Next come the complicated cases.

    // C++ [expr.sub]p1: The result is an lvalue of type "T".
    // However, subscripting vector types is more like member access.
  case Expr::ArraySubscriptExprClass:
    if (cast<ArraySubscriptExpr>(E)->getBase()->getType()->isVectorType())
      return ClassifyInternal(Ctx, cast<ArraySubscriptExpr>(E)->getBase());
    return Cl::CL_LValue;

    // C++ [expr.prim.general]p3: The result is an lvalue if the entity is a
    //   function or variable and a prvalue otherwise.
  case Expr::DeclRefExprClass:
    return ClassifyDecl(Ctx, cast<DeclRefExpr>(E)->getDecl());
    // We deal with names referenced from blocks the same way.
  case Expr::BlockDeclRefExprClass:
    return ClassifyDecl(Ctx, cast<BlockDeclRefExpr>(E)->getDecl());

    // Member access is complex.
  case Expr::MemberExprClass:
    return ClassifyMemberExpr(Ctx, cast<MemberExpr>(E));

  case Expr::UnaryOperatorClass:
    switch (cast<UnaryOperator>(E)->getOpcode()) {
      // C++ [expr.unary.op]p1: The unary * operator performs indirection:
      //   [...] the result is an lvalue referring to the object or function
      //   to which the expression points.
    case UO_Deref:
      return Cl::CL_LValue;

      // GNU extensions, simply look through them.
    case UO_Real:
    case UO_Imag:
    case UO_Extension:
      return ClassifyInternal(Ctx, cast<UnaryOperator>(E)->getSubExpr());

      // C++ [expr.pre.incr]p1: The result is the updated operand; it is an
      //   lvalue, [...]
      // Not so in C.
    case UO_PreInc:
    case UO_PreDec:
      return Lang.CPlusPlus ? Cl::CL_LValue : Cl::CL_PRValue;

    default:
      return Cl::CL_PRValue;
    }

    // Implicit casts are lvalues if they're lvalue casts. Other than that, we
    // only specifically record class temporaries.
  case Expr::ImplicitCastExprClass:
    switch (cast<ImplicitCastExpr>(E)->getValueKind()) {
    case VK_RValue:
      return Lang.CPlusPlus && E->getType()->isRecordType() ?
        Cl::CL_ClassTemporary : Cl::CL_PRValue;
    case VK_LValue:
      return Cl::CL_LValue;
    case VK_XValue:
      return Cl::CL_XValue;
    }
    llvm_unreachable("Invalid value category of implicit cast.");

    // C++ [expr.prim.general]p4: The presence of parentheses does not affect
    //   whether the expression is an lvalue.
  case Expr::ParenExprClass:
    return ClassifyInternal(Ctx, cast<ParenExpr>(E)->getSubExpr());

  case Expr::BinaryOperatorClass:
  case Expr::CompoundAssignOperatorClass:
    // C doesn't have any binary expressions that are lvalues.
    if (Lang.CPlusPlus)
      return ClassifyBinaryOp(Ctx, cast<BinaryOperator>(E));
    return Cl::CL_PRValue;

  case Expr::CallExprClass:
  case Expr::CXXOperatorCallExprClass:
  case Expr::CXXMemberCallExprClass:
    return ClassifyUnnamed(Ctx, cast<CallExpr>(E)->getCallReturnType());

    // __builtin_choose_expr is equivalent to the chosen expression.
  case Expr::ChooseExprClass:
    return ClassifyInternal(Ctx, cast<ChooseExpr>(E)->getChosenSubExpr(Ctx));

    // Extended vector element access is an lvalue unless there are duplicates
    // in the shuffle expression.
  case Expr::ExtVectorElementExprClass:
    return cast<ExtVectorElementExpr>(E)->containsDuplicateElements() ?
      Cl::CL_DuplicateVectorComponents : Cl::CL_LValue;

    // Simply look at the actual default argument.
  case Expr::CXXDefaultArgExprClass:
    return ClassifyInternal(Ctx, cast<CXXDefaultArgExpr>(E)->getExpr());

    // Same idea for temporary binding.
  case Expr::CXXBindTemporaryExprClass:
    return ClassifyInternal(Ctx, cast<CXXBindTemporaryExpr>(E)->getSubExpr());

    // And the temporary lifetime guard.
  case Expr::CXXExprWithTemporariesClass:
    return ClassifyInternal(Ctx, cast<CXXExprWithTemporaries>(E)->getSubExpr());

    // Casts depend completely on the target type. All casts work the same.
  case Expr::CStyleCastExprClass:
  case Expr::CXXFunctionalCastExprClass:
  case Expr::CXXStaticCastExprClass:
  case Expr::CXXDynamicCastExprClass:
  case Expr::CXXReinterpretCastExprClass:
  case Expr::CXXConstCastExprClass:
    // Only in C++ can casts be interesting at all.
    if (!Lang.CPlusPlus) return Cl::CL_PRValue;
    return ClassifyUnnamed(Ctx, cast<ExplicitCastExpr>(E)->getTypeAsWritten());

  case Expr::ConditionalOperatorClass:
    // Once again, only C++ is interesting.
    if (!Lang.CPlusPlus) return Cl::CL_PRValue;
    return ClassifyConditional(Ctx, cast<ConditionalOperator>(E));

    // ObjC message sends are effectively function calls, if the target function
    // is known.
  case Expr::ObjCMessageExprClass:
    if (const ObjCMethodDecl *Method =
          cast<ObjCMessageExpr>(E)->getMethodDecl()) {
      return ClassifyUnnamed(Ctx, Method->getResultType());
    }

    // Some C++ expressions are always class temporaries.
  case Expr::CXXConstructExprClass:
  case Expr::CXXTemporaryObjectExprClass:
  case Expr::CXXScalarValueInitExprClass:
    return Cl::CL_ClassTemporary;

    // Everything we haven't handled is a prvalue.
  default:
    return Cl::CL_PRValue;
  }
}

/// ClassifyDecl - Return the classification of an expression referencing the
/// given declaration.
static Cl::Kinds ClassifyDecl(ASTContext &Ctx, const Decl *D) {
  // C++ [expr.prim.general]p6: The result is an lvalue if the entity is a
  //   function, variable, or data member and a prvalue otherwise.
  // In C, functions are not lvalues.
  // In addition, NonTypeTemplateParmDecl derives from VarDecl but isn't an
  // lvalue unless it's a reference type (C++ [temp.param]p6), so we need to
  // special-case this.

  if (isa<CXXMethodDecl>(D) && cast<CXXMethodDecl>(D)->isInstance())
    return Cl::CL_MemberFunction;

  bool islvalue;
  if (const NonTypeTemplateParmDecl *NTTParm =
        dyn_cast<NonTypeTemplateParmDecl>(D))
    islvalue = NTTParm->getType()->isReferenceType();
  else
    islvalue = isa<VarDecl>(D) || isa<FieldDecl>(D) ||
      (Ctx.getLangOptions().CPlusPlus &&
        (isa<FunctionDecl>(D) || isa<FunctionTemplateDecl>(D)));

  return islvalue ? Cl::CL_LValue : Cl::CL_PRValue;
}

/// ClassifyUnnamed - Return the classification of an expression yielding an
/// unnamed value of the given type. This applies in particular to function
/// calls and casts.
static Cl::Kinds ClassifyUnnamed(ASTContext &Ctx, QualType T) {
  // In C, function calls are always rvalues.
  if (!Ctx.getLangOptions().CPlusPlus) return Cl::CL_PRValue;

  // C++ [expr.call]p10: A function call is an lvalue if the result type is an
  //   lvalue reference type or an rvalue reference to function type, an xvalue
  //   if the result type is an rvalue refernence to object type, and a prvalue
  //   otherwise.
  if (T->isLValueReferenceType())
    return Cl::CL_LValue;
  const RValueReferenceType *RV = T->getAs<RValueReferenceType>();
  if (!RV) // Could still be a class temporary, though.
    return T->isRecordType() ? Cl::CL_ClassTemporary : Cl::CL_PRValue;

  return RV->getPointeeType()->isFunctionType() ? Cl::CL_LValue : Cl::CL_XValue;
}

static Cl::Kinds ClassifyMemberExpr(ASTContext &Ctx, const MemberExpr *E) {
  // Handle C first, it's easier.
  if (!Ctx.getLangOptions().CPlusPlus) {
    // C99 6.5.2.3p3
    // For dot access, the expression is an lvalue if the first part is. For
    // arrow access, it always is an lvalue.
    if (E->isArrow())
      return Cl::CL_LValue;
    // ObjC property accesses are not lvalues, but get special treatment.
    Expr *Base = E->getBase();
    if (isa<ObjCPropertyRefExpr>(Base) ||
        isa<ObjCImplicitSetterGetterRefExpr>(Base))
      return Cl::CL_SubObjCPropertySetting;
    return ClassifyInternal(Ctx, Base);
  }

  NamedDecl *Member = E->getMemberDecl();
  // C++ [expr.ref]p3: E1->E2 is converted to the equivalent form (*(E1)).E2.
  // C++ [expr.ref]p4: If E2 is declared to have type "reference to T", then
  //   E1.E2 is an lvalue.
  if (ValueDecl *Value = dyn_cast<ValueDecl>(Member))
    if (Value->getType()->isReferenceType())
      return Cl::CL_LValue;

  //   Otherwise, one of the following rules applies.
  //   -- If E2 is a static member [...] then E1.E2 is an lvalue.
  if (isa<VarDecl>(Member) && Member->getDeclContext()->isRecord())
    return Cl::CL_LValue;

  //   -- If E2 is a non-static data member [...]. If E1 is an lvalue, then
  //      E1.E2 is an lvalue; if E1 is an xvalue, then E1.E2 is an xvalue;
  //      otherwise, it is a prvalue.
  if (isa<FieldDecl>(Member)) {
    // *E1 is an lvalue
    if (E->isArrow())
      return Cl::CL_LValue;
    return ClassifyInternal(Ctx, E->getBase());
  }

  //   -- If E2 is a [...] member function, [...]
  //      -- If it refers to a static member function [...], then E1.E2 is an
  //         lvalue; [...]
  //      -- Otherwise [...] E1.E2 is a prvalue.
  if (CXXMethodDecl *Method = dyn_cast<CXXMethodDecl>(Member))
    return Method->isStatic() ? Cl::CL_LValue : Cl::CL_MemberFunction;

  //   -- If E2 is a member enumerator [...], the expression E1.E2 is a prvalue.
  // So is everything else we haven't handled yet.
  return Cl::CL_PRValue;
}

static Cl::Kinds ClassifyBinaryOp(ASTContext &Ctx, const BinaryOperator *E) {
  assert(Ctx.getLangOptions().CPlusPlus &&
         "This is only relevant for C++.");
  // C++ [expr.ass]p1: All [...] return an lvalue referring to the left operand.
  if (E->isAssignmentOp())
    return Cl::CL_LValue;

  // C++ [expr.comma]p1: the result is of the same value category as its right
  //   operand, [...].
  if (E->getOpcode() == BO_Comma)
    return ClassifyInternal(Ctx, E->getRHS());

  // C++ [expr.mptr.oper]p6: The result of a .* expression whose second operand
  //   is a pointer to a data member is of the same value category as its first
  //   operand.
  if (E->getOpcode() == BO_PtrMemD)
    return E->getType()->isFunctionType() ? Cl::CL_MemberFunction :
      ClassifyInternal(Ctx, E->getLHS());

  // C++ [expr.mptr.oper]p6: The result of an ->* expression is an lvalue if its
  //   second operand is a pointer to data member and a prvalue otherwise.
  if (E->getOpcode() == BO_PtrMemI)
    return E->getType()->isFunctionType() ?
      Cl::CL_MemberFunction : Cl::CL_LValue;

  // All other binary operations are prvalues.
  return Cl::CL_PRValue;
}

static Cl::Kinds ClassifyConditional(ASTContext &Ctx,
                                     const ConditionalOperator *E) {
  assert(Ctx.getLangOptions().CPlusPlus &&
         "This is only relevant for C++.");

  Expr *True = E->getTrueExpr();
  Expr *False = E->getFalseExpr();
  // C++ [expr.cond]p2
  //   If either the second or the third operand has type (cv) void, [...]
  //   the result [...] is a prvalue.
  if (True->getType()->isVoidType() || False->getType()->isVoidType())
    return Cl::CL_PRValue;

  // Note that at this point, we have already performed all conversions
  // according to [expr.cond]p3.
  // C++ [expr.cond]p4: If the second and third operands are glvalues of the
  //   same value category [...], the result is of that [...] value category.
  // C++ [expr.cond]p5: Otherwise, the result is a prvalue.
  Cl::Kinds LCl = ClassifyInternal(Ctx, True),
            RCl = ClassifyInternal(Ctx, False);
  return LCl == RCl ? LCl : Cl::CL_PRValue;
}

static Cl::ModifiableType IsModifiable(ASTContext &Ctx, const Expr *E,
                                       Cl::Kinds Kind, SourceLocation &Loc) {
  // As a general rule, we only care about lvalues. But there are some rvalues
  // for which we want to generate special results.
  if (Kind == Cl::CL_PRValue) {
    // For the sake of better diagnostics, we want to specifically recognize
    // use of the GCC cast-as-lvalue extension.
    if (const CStyleCastExpr *CE = dyn_cast<CStyleCastExpr>(E->IgnoreParens())){
      if (CE->getSubExpr()->Classify(Ctx).isLValue()) {
        Loc = CE->getLParenLoc();
        return Cl::CM_LValueCast;
      }
    }
  }
  if (Kind != Cl::CL_LValue)
    return Cl::CM_RValue;

  // This is the lvalue case.
  // Functions are lvalues in C++, but not modifiable. (C++ [basic.lval]p6)
  if (Ctx.getLangOptions().CPlusPlus && E->getType()->isFunctionType())
    return Cl::CM_Function;

  // You cannot assign to a variable outside a block from within the block if
  // it is not marked __block, e.g.
  //   void takeclosure(void (^C)(void));
  //   void func() { int x = 1; takeclosure(^{ x = 7; }); }
  if (const BlockDeclRefExpr *BDR = dyn_cast<BlockDeclRefExpr>(E)) {
    if (!BDR->isByRef() && isa<VarDecl>(BDR->getDecl()))
      return Cl::CM_NotBlockQualified;
  }

  // Assignment to a property in ObjC is an implicit setter access. But a
  // setter might not exist.
  if (const ObjCImplicitSetterGetterRefExpr *Expr =
        dyn_cast<ObjCImplicitSetterGetterRefExpr>(E)) {
    if (Expr->getSetterMethod() == 0)
      return Cl::CM_NoSetterProperty;
  }

  CanQualType CT = Ctx.getCanonicalType(E->getType());
  // Const stuff is obviously not modifiable.
  if (CT.isConstQualified())
    return Cl::CM_ConstQualified;
  // Arrays are not modifiable, only their elements are.
  if (CT->isArrayType())
    return Cl::CM_ArrayType;
  // Incomplete types are not modifiable.
  if (CT->isIncompleteType())
    return Cl::CM_IncompleteType;

  // Records with any const fields (recursively) are not modifiable.
  if (const RecordType *R = CT->getAs<RecordType>()) {
    assert(!Ctx.getLangOptions().CPlusPlus &&
           "C++ struct assignment should be resolved by the "
           "copy assignment operator.");
    if (R->hasConstFields())
      return Cl::CM_ConstQualified;
  }

  return Cl::CM_Modifiable;
}

Expr::isLvalueResult Expr::isLvalue(ASTContext &Ctx) const {
  Classification VC = Classify(Ctx);
  switch (VC.getKind()) {
  case Cl::CL_LValue: return LV_Valid;
  case Cl::CL_XValue: return LV_InvalidExpression;
  case Cl::CL_Function: return LV_NotObjectType;
  case Cl::CL_Void: return LV_IncompleteVoidType;
  case Cl::CL_DuplicateVectorComponents: return LV_DuplicateVectorComponents;
  case Cl::CL_MemberFunction: return LV_MemberFunction;
  case Cl::CL_SubObjCPropertySetting: return LV_SubObjCPropertySetting;
  case Cl::CL_ClassTemporary: return LV_ClassTemporary;
  case Cl::CL_PRValue: return LV_InvalidExpression;
  }
  llvm_unreachable("Unhandled kind");
}

Expr::isModifiableLvalueResult
Expr::isModifiableLvalue(ASTContext &Ctx, SourceLocation *Loc) const {
  SourceLocation dummy;
  Classification VC = ClassifyModifiable(Ctx, Loc ? *Loc : dummy);
  switch (VC.getKind()) {
  case Cl::CL_LValue: break;
  case Cl::CL_XValue: return MLV_InvalidExpression;
  case Cl::CL_Function: return MLV_NotObjectType;
  case Cl::CL_Void: return MLV_IncompleteVoidType;
  case Cl::CL_DuplicateVectorComponents: return MLV_DuplicateVectorComponents;
  case Cl::CL_MemberFunction: return MLV_MemberFunction;
  case Cl::CL_SubObjCPropertySetting: return MLV_SubObjCPropertySetting;
  case Cl::CL_ClassTemporary: return MLV_ClassTemporary;
  case Cl::CL_PRValue:
    return VC.getModifiable() == Cl::CM_LValueCast ?
      MLV_LValueCast : MLV_InvalidExpression;
  }
  assert(VC.getKind() == Cl::CL_LValue && "Unhandled kind");
  switch (VC.getModifiable()) {
  case Cl::CM_Untested: llvm_unreachable("Did not test modifiability");
  case Cl::CM_Modifiable: return MLV_Valid;
  case Cl::CM_RValue: llvm_unreachable("CM_RValue and CL_LValue don't match");
  case Cl::CM_Function: return MLV_NotObjectType;
  case Cl::CM_LValueCast:
    llvm_unreachable("CM_LValueCast and CL_LValue don't match");
  case Cl::CM_NotBlockQualified: return MLV_NotBlockQualified;
  case Cl::CM_NoSetterProperty: return MLV_NoSetterProperty;
  case Cl::CM_ConstQualified: return MLV_ConstQualified;
  case Cl::CM_ArrayType: return MLV_ArrayType;
  case Cl::CM_IncompleteType: return MLV_IncompleteType;
  }
  llvm_unreachable("Unhandled modifiable type");
}
