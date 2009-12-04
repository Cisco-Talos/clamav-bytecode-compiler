//===--- CGExprAgg.cpp - Emit LLVM Code from Aggregate Expressions --------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This contains code to emit Aggregate Expr nodes as LLVM code.
//
//===----------------------------------------------------------------------===//

#include "CodeGenFunction.h"
#include "CodeGenModule.h"
#include "CGObjCRuntime.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/DeclCXX.h"
#include "clang/AST/StmtVisitor.h"
#include "llvm/Constants.h"
#include "llvm/Function.h"
#include "llvm/GlobalVariable.h"
#include "llvm/Intrinsics.h"
using namespace clang;
using namespace CodeGen;

//===----------------------------------------------------------------------===//
//                        Aggregate Expression Emitter
//===----------------------------------------------------------------------===//

namespace  {
class AggExprEmitter : public StmtVisitor<AggExprEmitter> {
  CodeGenFunction &CGF;
  CGBuilderTy &Builder;
  llvm::Value *DestPtr;
  bool VolatileDest;
  bool IgnoreResult;
  bool IsInitializer;
  bool RequiresGCollection;
public:
  AggExprEmitter(CodeGenFunction &cgf, llvm::Value *destPtr, bool v,
                 bool ignore, bool isinit, bool requiresGCollection)
    : CGF(cgf), Builder(CGF.Builder),
      DestPtr(destPtr), VolatileDest(v), IgnoreResult(ignore),
      IsInitializer(isinit), RequiresGCollection(requiresGCollection) {
  }

  //===--------------------------------------------------------------------===//
  //                               Utilities
  //===--------------------------------------------------------------------===//

  /// EmitAggLoadOfLValue - Given an expression with aggregate type that
  /// represents a value lvalue, this method emits the address of the lvalue,
  /// then loads the result into DestPtr.
  void EmitAggLoadOfLValue(const Expr *E);

  /// EmitFinalDestCopy - Perform the final copy to DestPtr, if desired.
  void EmitFinalDestCopy(const Expr *E, LValue Src, bool Ignore = false);
  void EmitFinalDestCopy(const Expr *E, RValue Src, bool Ignore = false);

  //===--------------------------------------------------------------------===//
  //                            Visitor Methods
  //===--------------------------------------------------------------------===//

  void VisitStmt(Stmt *S) {
    CGF.ErrorUnsupported(S, "aggregate expression");
  }
  void VisitParenExpr(ParenExpr *PE) { Visit(PE->getSubExpr()); }
  void VisitUnaryExtension(UnaryOperator *E) { Visit(E->getSubExpr()); }

  // l-values.
  void VisitDeclRefExpr(DeclRefExpr *DRE) { EmitAggLoadOfLValue(DRE); }
  void VisitMemberExpr(MemberExpr *ME) { EmitAggLoadOfLValue(ME); }
  void VisitUnaryDeref(UnaryOperator *E) { EmitAggLoadOfLValue(E); }
  void VisitStringLiteral(StringLiteral *E) { EmitAggLoadOfLValue(E); }
  void VisitCompoundLiteralExpr(CompoundLiteralExpr *E) {
    EmitAggLoadOfLValue(E);
  }
  void VisitArraySubscriptExpr(ArraySubscriptExpr *E) {
    EmitAggLoadOfLValue(E);
  }
  void VisitBlockDeclRefExpr(const BlockDeclRefExpr *E) {
    EmitAggLoadOfLValue(E);
  }
  void VisitPredefinedExpr(const PredefinedExpr *E) {
    EmitAggLoadOfLValue(E);
  }

  // Operators.
  void VisitCastExpr(CastExpr *E);
  void VisitCallExpr(const CallExpr *E);
  void VisitStmtExpr(const StmtExpr *E);
  void VisitBinaryOperator(const BinaryOperator *BO);
  void VisitPointerToDataMemberBinaryOperator(const BinaryOperator *BO);
  void VisitBinAssign(const BinaryOperator *E);
  void VisitBinComma(const BinaryOperator *E);
  void VisitUnaryAddrOf(const UnaryOperator *E);

  void VisitObjCMessageExpr(ObjCMessageExpr *E);
  void VisitObjCIvarRefExpr(ObjCIvarRefExpr *E) {
    EmitAggLoadOfLValue(E);
  }
  void VisitObjCPropertyRefExpr(ObjCPropertyRefExpr *E);
  void VisitObjCImplicitSetterGetterRefExpr(ObjCImplicitSetterGetterRefExpr *E);

  void VisitConditionalOperator(const ConditionalOperator *CO);
  void VisitChooseExpr(const ChooseExpr *CE);
  void VisitInitListExpr(InitListExpr *E);
  void VisitCXXDefaultArgExpr(CXXDefaultArgExpr *DAE) {
    Visit(DAE->getExpr());
  }
  void VisitCXXBindTemporaryExpr(CXXBindTemporaryExpr *E);
  void VisitCXXConstructExpr(const CXXConstructExpr *E);
  void VisitCXXExprWithTemporaries(CXXExprWithTemporaries *E);
  void VisitCXXZeroInitValueExpr(CXXZeroInitValueExpr *E);
  void VisitCXXTypeidExpr(CXXTypeidExpr *E) { EmitAggLoadOfLValue(E); }

  void VisitVAArgExpr(VAArgExpr *E);

  void EmitInitializationToLValue(Expr *E, LValue Address);
  void EmitNullInitializationToLValue(LValue Address, QualType T);
  //  case Expr::ChooseExprClass:

};
}  // end anonymous namespace.

//===----------------------------------------------------------------------===//
//                                Utilities
//===----------------------------------------------------------------------===//

/// EmitAggLoadOfLValue - Given an expression with aggregate type that
/// represents a value lvalue, this method emits the address of the lvalue,
/// then loads the result into DestPtr.
void AggExprEmitter::EmitAggLoadOfLValue(const Expr *E) {
  LValue LV = CGF.EmitLValue(E);
  EmitFinalDestCopy(E, LV);
}

/// EmitFinalDestCopy - Perform the final copy to DestPtr, if desired.
void AggExprEmitter::EmitFinalDestCopy(const Expr *E, RValue Src, bool Ignore) {
  assert(Src.isAggregate() && "value must be aggregate value!");

  // If the result is ignored, don't copy from the value.
  if (DestPtr == 0) {
    if (!Src.isVolatileQualified() || (IgnoreResult && Ignore))
      return;
    // If the source is volatile, we must read from it; to do that, we need
    // some place to put it.
    DestPtr = CGF.CreateTempAlloca(CGF.ConvertType(E->getType()), "agg.tmp");
  }

  if (RequiresGCollection) {
    CGF.CGM.getObjCRuntime().EmitGCMemmoveCollectable(CGF,
                                              DestPtr, Src.getAggregateAddr(),
                                              E->getType());
    return;
  }
  // If the result of the assignment is used, copy the LHS there also.
  // FIXME: Pass VolatileDest as well.  I think we also need to merge volatile
  // from the source as well, as we can't eliminate it if either operand
  // is volatile, unless copy has volatile for both source and destination..
  CGF.EmitAggregateCopy(DestPtr, Src.getAggregateAddr(), E->getType(),
                        VolatileDest|Src.isVolatileQualified());
}

/// EmitFinalDestCopy - Perform the final copy to DestPtr, if desired.
void AggExprEmitter::EmitFinalDestCopy(const Expr *E, LValue Src, bool Ignore) {
  assert(Src.isSimple() && "Can't have aggregate bitfield, vector, etc");

  EmitFinalDestCopy(E, RValue::getAggregate(Src.getAddress(),
                                            Src.isVolatileQualified()),
                    Ignore);
}

//===----------------------------------------------------------------------===//
//                            Visitor Methods
//===----------------------------------------------------------------------===//

void AggExprEmitter::VisitCastExpr(CastExpr *E) {
  switch (E->getCastKind()) {
  default: assert(0 && "Unhandled cast kind!");

  case CastExpr::CK_ToUnion: {
    // GCC union extension
    QualType PtrTy =
    CGF.getContext().getPointerType(E->getSubExpr()->getType());
    llvm::Value *CastPtr = Builder.CreateBitCast(DestPtr,
                                                 CGF.ConvertType(PtrTy));
    EmitInitializationToLValue(E->getSubExpr(),
                               LValue::MakeAddr(CastPtr, Qualifiers()));
    break;
  }

  // FIXME: Remove the CK_Unknown check here.
  case CastExpr::CK_Unknown:
  case CastExpr::CK_NoOp:
  case CastExpr::CK_UserDefinedConversion:
  case CastExpr::CK_ConstructorConversion:
    assert(CGF.getContext().hasSameUnqualifiedType(E->getSubExpr()->getType(),
                                                   E->getType()) &&
           "Implicit cast types must be compatible");
    Visit(E->getSubExpr());
    break;

  case CastExpr::CK_NullToMemberPointer: {
    const llvm::Type *PtrDiffTy = 
      CGF.ConvertType(CGF.getContext().getPointerDiffType());

    llvm::Value *NullValue = llvm::Constant::getNullValue(PtrDiffTy);
    llvm::Value *Ptr = Builder.CreateStructGEP(DestPtr, 0, "ptr");
    Builder.CreateStore(NullValue, Ptr, VolatileDest);
    
    llvm::Value *Adj = Builder.CreateStructGEP(DestPtr, 1, "adj");
    Builder.CreateStore(NullValue, Adj, VolatileDest);

    break;
  }
      
  case CastExpr::CK_BitCast: {
    // This must be a member function pointer cast.
    Visit(E->getSubExpr());
    break;
  }

  case CastExpr::CK_DerivedToBaseMemberPointer:
  case CastExpr::CK_BaseToDerivedMemberPointer: {
    QualType SrcType = E->getSubExpr()->getType();
    
    llvm::Value *Src = CGF.CreateTempAlloca(CGF.ConvertTypeForMem(SrcType), 
                                            "tmp");
    CGF.EmitAggExpr(E->getSubExpr(), Src, SrcType.isVolatileQualified());
    
    llvm::Value *SrcPtr = Builder.CreateStructGEP(Src, 0, "src.ptr");
    SrcPtr = Builder.CreateLoad(SrcPtr);
    
    llvm::Value *SrcAdj = Builder.CreateStructGEP(Src, 1, "src.adj");
    SrcAdj = Builder.CreateLoad(SrcAdj);
    
    llvm::Value *DstPtr = Builder.CreateStructGEP(DestPtr, 0, "dst.ptr");
    Builder.CreateStore(SrcPtr, DstPtr, VolatileDest);
    
    llvm::Value *DstAdj = Builder.CreateStructGEP(DestPtr, 1, "dst.adj");
    
    // Now See if we need to update the adjustment.
    const CXXRecordDecl *BaseDecl = 
      cast<CXXRecordDecl>(SrcType->getAs<MemberPointerType>()->
                          getClass()->getAs<RecordType>()->getDecl());
    const CXXRecordDecl *DerivedDecl = 
      cast<CXXRecordDecl>(E->getType()->getAs<MemberPointerType>()->
                          getClass()->getAs<RecordType>()->getDecl());
    if (E->getCastKind() == CastExpr::CK_DerivedToBaseMemberPointer)
      std::swap(DerivedDecl, BaseDecl);

    llvm::Constant *Adj = CGF.CGM.GetCXXBaseClassOffset(DerivedDecl, BaseDecl);
    if (Adj) {
      if (E->getCastKind() == CastExpr::CK_DerivedToBaseMemberPointer)
        SrcAdj = Builder.CreateSub(SrcAdj, Adj, "adj");
      else
        SrcAdj = Builder.CreateAdd(SrcAdj, Adj, "adj");
    }
    
    Builder.CreateStore(SrcAdj, DstAdj, VolatileDest);
    break;
  }
  }
}

void AggExprEmitter::VisitCallExpr(const CallExpr *E) {
  if (E->getCallReturnType()->isReferenceType()) {
    EmitAggLoadOfLValue(E);
    return;
  }

  RValue RV = CGF.EmitCallExpr(E);
  EmitFinalDestCopy(E, RV);
}

void AggExprEmitter::VisitObjCMessageExpr(ObjCMessageExpr *E) {
  RValue RV = CGF.EmitObjCMessageExpr(E);
  EmitFinalDestCopy(E, RV);
}

void AggExprEmitter::VisitObjCPropertyRefExpr(ObjCPropertyRefExpr *E) {
  RValue RV = CGF.EmitObjCPropertyGet(E);
  EmitFinalDestCopy(E, RV);
}

void AggExprEmitter::VisitObjCImplicitSetterGetterRefExpr(
                                   ObjCImplicitSetterGetterRefExpr *E) {
  RValue RV = CGF.EmitObjCPropertyGet(E);
  EmitFinalDestCopy(E, RV);
}

void AggExprEmitter::VisitBinComma(const BinaryOperator *E) {
  CGF.EmitAnyExpr(E->getLHS(), 0, false, true);
  CGF.EmitAggExpr(E->getRHS(), DestPtr, VolatileDest,
                  /*IgnoreResult=*/false, IsInitializer);
}

void AggExprEmitter::VisitUnaryAddrOf(const UnaryOperator *E) {
  // We have a member function pointer.
  const MemberPointerType *MPT = E->getType()->getAs<MemberPointerType>();
  (void) MPT;
  assert(MPT->getPointeeType()->isFunctionProtoType() &&
         "Unexpected member pointer type!");
  
  const DeclRefExpr *DRE = cast<DeclRefExpr>(E->getSubExpr());
  const CXXMethodDecl *MD = cast<CXXMethodDecl>(DRE->getDecl());

  const llvm::Type *PtrDiffTy = 
    CGF.ConvertType(CGF.getContext().getPointerDiffType());

  llvm::Value *DstPtr = Builder.CreateStructGEP(DestPtr, 0, "dst.ptr");
  llvm::Value *FuncPtr;
  
  if (MD->isVirtual()) {
    int64_t Index = 
      CGF.CGM.getVtableInfo().getMethodVtableIndex(MD);
    
    FuncPtr = llvm::ConstantInt::get(PtrDiffTy, Index + 1);
  } else {
    FuncPtr = llvm::ConstantExpr::getPtrToInt(CGF.CGM.GetAddrOfFunction(MD), 
                                              PtrDiffTy);
  }
  Builder.CreateStore(FuncPtr, DstPtr, VolatileDest);

  llvm::Value *AdjPtr = Builder.CreateStructGEP(DestPtr, 1, "dst.adj");
  
  // The adjustment will always be 0.
  Builder.CreateStore(llvm::ConstantInt::get(PtrDiffTy, 0), AdjPtr,
                      VolatileDest);
}

void AggExprEmitter::VisitStmtExpr(const StmtExpr *E) {
  CGF.EmitCompoundStmt(*E->getSubStmt(), true, DestPtr, VolatileDest);
}

void AggExprEmitter::VisitBinaryOperator(const BinaryOperator *E) {
  if (E->getOpcode() == BinaryOperator::PtrMemD ||
      E->getOpcode() == BinaryOperator::PtrMemI)
    VisitPointerToDataMemberBinaryOperator(E);
  else
    CGF.ErrorUnsupported(E, "aggregate binary expression");
}

void AggExprEmitter::VisitPointerToDataMemberBinaryOperator(
                                                    const BinaryOperator *E) {
  LValue LV = CGF.EmitPointerToDataMemberBinaryExpr(E);
  EmitFinalDestCopy(E, LV);
}

void AggExprEmitter::VisitBinAssign(const BinaryOperator *E) {
  // For an assignment to work, the value on the right has
  // to be compatible with the value on the left.
  assert(CGF.getContext().hasSameUnqualifiedType(E->getLHS()->getType(),
                                                 E->getRHS()->getType())
         && "Invalid assignment");
  LValue LHS = CGF.EmitLValue(E->getLHS());

  // We have to special case property setters, otherwise we must have
  // a simple lvalue (no aggregates inside vectors, bitfields).
  if (LHS.isPropertyRef()) {
    llvm::Value *AggLoc = DestPtr;
    if (!AggLoc)
      AggLoc = CGF.CreateTempAlloca(CGF.ConvertType(E->getRHS()->getType()));
    CGF.EmitAggExpr(E->getRHS(), AggLoc, VolatileDest);
    CGF.EmitObjCPropertySet(LHS.getPropertyRefExpr(),
                            RValue::getAggregate(AggLoc, VolatileDest));
  } else if (LHS.isKVCRef()) {
    llvm::Value *AggLoc = DestPtr;
    if (!AggLoc)
      AggLoc = CGF.CreateTempAlloca(CGF.ConvertType(E->getRHS()->getType()));
    CGF.EmitAggExpr(E->getRHS(), AggLoc, VolatileDest);
    CGF.EmitObjCPropertySet(LHS.getKVCRefExpr(),
                            RValue::getAggregate(AggLoc, VolatileDest));
  } else {
    bool RequiresGCollection = false;
    if (CGF.getContext().getLangOptions().NeXTRuntime) {
      QualType LHSTy = E->getLHS()->getType();
      if (const RecordType *FDTTy = LHSTy.getTypePtr()->getAs<RecordType>())
        RequiresGCollection = FDTTy->getDecl()->hasObjectMember();
    }
    // Codegen the RHS so that it stores directly into the LHS.
    CGF.EmitAggExpr(E->getRHS(), LHS.getAddress(), LHS.isVolatileQualified(),
                    false, false, RequiresGCollection);
    EmitFinalDestCopy(E, LHS, true);
  }
}

void AggExprEmitter::VisitConditionalOperator(const ConditionalOperator *E) {
  llvm::BasicBlock *LHSBlock = CGF.createBasicBlock("cond.true");
  llvm::BasicBlock *RHSBlock = CGF.createBasicBlock("cond.false");
  llvm::BasicBlock *ContBlock = CGF.createBasicBlock("cond.end");

  llvm::Value *Cond = CGF.EvaluateExprAsBool(E->getCond());
  Builder.CreateCondBr(Cond, LHSBlock, RHSBlock);

  CGF.StartConditionalBranch();
  CGF.EmitBlock(LHSBlock);

  // Handle the GNU extension for missing LHS.
  assert(E->getLHS() && "Must have LHS for aggregate value");

  Visit(E->getLHS());
  CGF.FinishConditionalBranch();
  CGF.EmitBranch(ContBlock);

  CGF.StartConditionalBranch();
  CGF.EmitBlock(RHSBlock);

  Visit(E->getRHS());
  CGF.FinishConditionalBranch();
  CGF.EmitBranch(ContBlock);

  CGF.EmitBlock(ContBlock);
}

void AggExprEmitter::VisitChooseExpr(const ChooseExpr *CE) {
  Visit(CE->getChosenSubExpr(CGF.getContext()));
}

void AggExprEmitter::VisitVAArgExpr(VAArgExpr *VE) {
  llvm::Value *ArgValue = CGF.EmitVAListRef(VE->getSubExpr());
  llvm::Value *ArgPtr = CGF.EmitVAArg(ArgValue, VE->getType());

  if (!ArgPtr) {
    CGF.ErrorUnsupported(VE, "aggregate va_arg expression");
    return;
  }

  EmitFinalDestCopy(VE, LValue::MakeAddr(ArgPtr, Qualifiers()));
}

void AggExprEmitter::VisitCXXBindTemporaryExpr(CXXBindTemporaryExpr *E) {
  llvm::Value *Val = DestPtr;

  if (!Val) {
    // Create a temporary variable.
    Val = CGF.CreateTempAlloca(CGF.ConvertTypeForMem(E->getType()), "tmp");

    // FIXME: volatile
    CGF.EmitAggExpr(E->getSubExpr(), Val, false);
  } else
    Visit(E->getSubExpr());

  // Don't make this a live temporary if we're emitting an initializer expr.
  if (!IsInitializer)
    CGF.PushCXXTemporary(E->getTemporary(), Val);
}

void
AggExprEmitter::VisitCXXConstructExpr(const CXXConstructExpr *E) {
  llvm::Value *Val = DestPtr;

  if (!Val) {
    // Create a temporary variable.
    Val = CGF.CreateTempAlloca(CGF.ConvertTypeForMem(E->getType()), "tmp");
  }

  CGF.EmitCXXConstructExpr(Val, E);
}

void AggExprEmitter::VisitCXXExprWithTemporaries(CXXExprWithTemporaries *E) {
  CGF.EmitCXXExprWithTemporaries(E, DestPtr, VolatileDest, IsInitializer);
}

void AggExprEmitter::VisitCXXZeroInitValueExpr(CXXZeroInitValueExpr *E) {
  LValue lvalue = LValue::MakeAddr(DestPtr, Qualifiers());
  EmitNullInitializationToLValue(lvalue, E->getType());
}

void AggExprEmitter::EmitInitializationToLValue(Expr* E, LValue LV) {
  // FIXME: Ignore result?
  // FIXME: Are initializers affected by volatile?
  if (isa<ImplicitValueInitExpr>(E)) {
    EmitNullInitializationToLValue(LV, E->getType());
  } else if (E->getType()->isComplexType()) {
    CGF.EmitComplexExprIntoAddr(E, LV.getAddress(), false);
  } else if (CGF.hasAggregateLLVMType(E->getType())) {
    CGF.EmitAnyExpr(E, LV.getAddress(), false);
  } else {
    CGF.EmitStoreThroughLValue(CGF.EmitAnyExpr(E), LV, E->getType());
  }
}

void AggExprEmitter::EmitNullInitializationToLValue(LValue LV, QualType T) {
  if (!CGF.hasAggregateLLVMType(T)) {
    // For non-aggregates, we can store zero
    llvm::Value *Null = llvm::Constant::getNullValue(CGF.ConvertType(T));
    CGF.EmitStoreThroughLValue(RValue::get(Null), LV, T);
  } else {
    // Otherwise, just memset the whole thing to zero.  This is legal
    // because in LLVM, all default initializers are guaranteed to have a
    // bit pattern of all zeros.
    // FIXME: That isn't true for member pointers!
    // There's a potential optimization opportunity in combining
    // memsets; that would be easy for arrays, but relatively
    // difficult for structures with the current code.
    CGF.EmitMemSetToZero(LV.getAddress(), T);
  }
}

void AggExprEmitter::VisitInitListExpr(InitListExpr *E) {
#if 0
  // FIXME: Assess perf here?  Figure out what cases are worth optimizing here
  // (Length of globals? Chunks of zeroed-out space?).
  //
  // If we can, prefer a copy from a global; this is a lot less code for long
  // globals, and it's easier for the current optimizers to analyze.
  if (llvm::Constant* C = CGF.CGM.EmitConstantExpr(E, E->getType(), &CGF)) {
    llvm::GlobalVariable* GV =
    new llvm::GlobalVariable(CGF.CGM.getModule(), C->getType(), true,
                             llvm::GlobalValue::InternalLinkage, C, "");
    EmitFinalDestCopy(E, LValue::MakeAddr(GV, Qualifiers()));
    return;
  }
#endif
  if (E->hadArrayRangeDesignator()) {
    CGF.ErrorUnsupported(E, "GNU array range designator extension");
  }

  // Handle initialization of an array.
  if (E->getType()->isArrayType()) {
    const llvm::PointerType *APType =
      cast<llvm::PointerType>(DestPtr->getType());
    const llvm::ArrayType *AType =
      cast<llvm::ArrayType>(APType->getElementType());

    uint64_t NumInitElements = E->getNumInits();

    if (E->getNumInits() > 0) {
      QualType T1 = E->getType();
      QualType T2 = E->getInit(0)->getType();
      if (CGF.getContext().hasSameUnqualifiedType(T1, T2)) {
        EmitAggLoadOfLValue(E->getInit(0));
        return;
      }
    }

    uint64_t NumArrayElements = AType->getNumElements();
    QualType ElementType = CGF.getContext().getCanonicalType(E->getType());
    ElementType = CGF.getContext().getAsArrayType(ElementType)->getElementType();

    // FIXME: were we intentionally ignoring address spaces and GC attributes?
    Qualifiers Quals = CGF.MakeQualifiers(ElementType);

    for (uint64_t i = 0; i != NumArrayElements; ++i) {
      llvm::Value *NextVal = Builder.CreateStructGEP(DestPtr, i, ".array");
      if (i < NumInitElements)
        EmitInitializationToLValue(E->getInit(i),
                                   LValue::MakeAddr(NextVal, Quals));
      else
        EmitNullInitializationToLValue(LValue::MakeAddr(NextVal, Quals),
                                       ElementType);
    }
    return;
  }

  assert(E->getType()->isRecordType() && "Only support structs/unions here!");

  // Do struct initialization; this code just sets each individual member
  // to the approprate value.  This makes bitfield support automatic;
  // the disadvantage is that the generated code is more difficult for
  // the optimizer, especially with bitfields.
  unsigned NumInitElements = E->getNumInits();
  RecordDecl *SD = E->getType()->getAs<RecordType>()->getDecl();
  unsigned CurInitVal = 0;

  if (E->getType()->isUnionType()) {
    // Only initialize one field of a union. The field itself is
    // specified by the initializer list.
    if (!E->getInitializedFieldInUnion()) {
      // Empty union; we have nothing to do.

#ifndef NDEBUG
      // Make sure that it's really an empty and not a failure of
      // semantic analysis.
      for (RecordDecl::field_iterator Field = SD->field_begin(),
                                   FieldEnd = SD->field_end();
           Field != FieldEnd; ++Field)
        assert(Field->isUnnamedBitfield() && "Only unnamed bitfields allowed");
#endif
      return;
    }

    // FIXME: volatility
    FieldDecl *Field = E->getInitializedFieldInUnion();
    LValue FieldLoc = CGF.EmitLValueForField(DestPtr, Field, true, 0);

    if (NumInitElements) {
      // Store the initializer into the field
      EmitInitializationToLValue(E->getInit(0), FieldLoc);
    } else {
      // Default-initialize to null
      EmitNullInitializationToLValue(FieldLoc, Field->getType());
    }

    return;
  }

  // Here we iterate over the fields; this makes it simpler to both
  // default-initialize fields and skip over unnamed fields.
  for (RecordDecl::field_iterator Field = SD->field_begin(),
                               FieldEnd = SD->field_end();
       Field != FieldEnd; ++Field) {
    // We're done once we hit the flexible array member
    if (Field->getType()->isIncompleteArrayType())
      break;

    if (Field->isUnnamedBitfield())
      continue;

    // FIXME: volatility
    LValue FieldLoc = CGF.EmitLValueForField(DestPtr, *Field, false, 0);
    // We never generate write-barries for initialized fields.
    LValue::SetObjCNonGC(FieldLoc, true);
    if (CurInitVal < NumInitElements) {
      // Store the initializer into the field
      EmitInitializationToLValue(E->getInit(CurInitVal++), FieldLoc);
    } else {
      // We're out of initalizers; default-initialize to null
      EmitNullInitializationToLValue(FieldLoc, Field->getType());
    }
  }
}

//===----------------------------------------------------------------------===//
//                        Entry Points into this File
//===----------------------------------------------------------------------===//

/// EmitAggExpr - Emit the computation of the specified expression of aggregate
/// type.  The result is computed into DestPtr.  Note that if DestPtr is null,
/// the value of the aggregate expression is not needed.  If VolatileDest is
/// true, DestPtr cannot be 0.
void CodeGenFunction::EmitAggExpr(const Expr *E, llvm::Value *DestPtr,
                                  bool VolatileDest, bool IgnoreResult,
                                  bool IsInitializer,
                                  bool RequiresGCollection) {
  assert(E && hasAggregateLLVMType(E->getType()) &&
         "Invalid aggregate expression to emit");
  assert ((DestPtr != 0 || VolatileDest == false)
          && "volatile aggregate can't be 0");

  AggExprEmitter(*this, DestPtr, VolatileDest, IgnoreResult, IsInitializer,
                 RequiresGCollection)
    .Visit(const_cast<Expr*>(E));
}

void CodeGenFunction::EmitAggregateClear(llvm::Value *DestPtr, QualType Ty) {
  assert(!Ty->isAnyComplexType() && "Shouldn't happen for complex");

  EmitMemSetToZero(DestPtr, Ty);
}

void CodeGenFunction::EmitAggregateCopy(llvm::Value *DestPtr,
                                        llvm::Value *SrcPtr, QualType Ty,
                                        bool isVolatile) {
  assert(!Ty->isAnyComplexType() && "Shouldn't happen for complex");

  // Aggregate assignment turns into llvm.memcpy.  This is almost valid per
  // C99 6.5.16.1p3, which states "If the value being stored in an object is
  // read from another object that overlaps in anyway the storage of the first
  // object, then the overlap shall be exact and the two objects shall have
  // qualified or unqualified versions of a compatible type."
  //
  // memcpy is not defined if the source and destination pointers are exactly
  // equal, but other compilers do this optimization, and almost every memcpy
  // implementation handles this case safely.  If there is a libc that does not
  // safely handle this, we can add a target hook.
  const llvm::Type *BP = llvm::Type::getInt8PtrTy(VMContext);
  if (DestPtr->getType() != BP)
    DestPtr = Builder.CreateBitCast(DestPtr, BP, "tmp");
  if (SrcPtr->getType() != BP)
    SrcPtr = Builder.CreateBitCast(SrcPtr, BP, "tmp");

  // Get size and alignment info for this aggregate.
  std::pair<uint64_t, unsigned> TypeInfo = getContext().getTypeInfo(Ty);

  // FIXME: Handle variable sized types.
  const llvm::Type *IntPtr =
          llvm::IntegerType::get(VMContext, LLVMPointerWidth);

  // FIXME: If we have a volatile struct, the optimizer can remove what might
  // appear to be `extra' memory ops:
  //
  // volatile struct { int i; } a, b;
  //
  // int main() {
  //   a = b;
  //   a = b;
  // }
  //
  // we need to use a differnt call here.  We use isVolatile to indicate when
  // either the source or the destination is volatile.
  Builder.CreateCall4(CGM.getMemCpyFn(),
                      DestPtr, SrcPtr,
                      // TypeInfo.first describes size in bits.
                      llvm::ConstantInt::get(IntPtr, TypeInfo.first/8),
                      llvm::ConstantInt::get(llvm::Type::getInt32Ty(VMContext),
                                             TypeInfo.second/8));
}
