//===--- ASTImporter.cpp - Importing ASTs from other Contexts ---*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
//  This file defines the ASTImporter class which imports AST nodes from one
//  context into another context.
//
//===----------------------------------------------------------------------===//
#include "clang/AST/ASTImporter.h"

#include "clang/AST/ASTContext.h"
#include "clang/AST/ASTDiagnostic.h"
#include "clang/AST/DeclCXX.h"
#include "clang/AST/DeclObjC.h"
#include "clang/AST/DeclVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "clang/AST/TypeLoc.h"
#include "clang/AST/TypeVisitor.h"
#include "clang/Basic/FileManager.h"
#include "clang/Basic/SourceManager.h"
#include "llvm/Support/MemoryBuffer.h"
#include <deque>

using namespace clang;

namespace {
  class ASTNodeImporter : public TypeVisitor<ASTNodeImporter, QualType>,
                          public DeclVisitor<ASTNodeImporter, Decl *>,
                          public StmtVisitor<ASTNodeImporter, Stmt *> {
    ASTImporter &Importer;
    
  public:
    explicit ASTNodeImporter(ASTImporter &Importer) : Importer(Importer) { }
    
    using TypeVisitor<ASTNodeImporter, QualType>::Visit;
    using DeclVisitor<ASTNodeImporter, Decl *>::Visit;
    using StmtVisitor<ASTNodeImporter, Stmt *>::Visit;

    // Importing types
    QualType VisitType(Type *T);
    QualType VisitBuiltinType(BuiltinType *T);
    QualType VisitComplexType(ComplexType *T);
    QualType VisitPointerType(PointerType *T);
    QualType VisitBlockPointerType(BlockPointerType *T);
    QualType VisitLValueReferenceType(LValueReferenceType *T);
    QualType VisitRValueReferenceType(RValueReferenceType *T);
    QualType VisitMemberPointerType(MemberPointerType *T);
    QualType VisitConstantArrayType(ConstantArrayType *T);
    QualType VisitIncompleteArrayType(IncompleteArrayType *T);
    QualType VisitVariableArrayType(VariableArrayType *T);
    // FIXME: DependentSizedArrayType
    // FIXME: DependentSizedExtVectorType
    QualType VisitVectorType(VectorType *T);
    QualType VisitExtVectorType(ExtVectorType *T);
    QualType VisitFunctionNoProtoType(FunctionNoProtoType *T);
    QualType VisitFunctionProtoType(FunctionProtoType *T);
    // FIXME: UnresolvedUsingType
    QualType VisitTypedefType(TypedefType *T);
    QualType VisitTypeOfExprType(TypeOfExprType *T);
    // FIXME: DependentTypeOfExprType
    QualType VisitTypeOfType(TypeOfType *T);
    QualType VisitDecltypeType(DecltypeType *T);
    // FIXME: DependentDecltypeType
    QualType VisitRecordType(RecordType *T);
    QualType VisitEnumType(EnumType *T);
    QualType VisitElaboratedType(ElaboratedType *T);
    // FIXME: TemplateTypeParmType
    // FIXME: SubstTemplateTypeParmType
    // FIXME: TemplateSpecializationType
    QualType VisitQualifiedNameType(QualifiedNameType *T);
    // FIXME: TypenameType
    QualType VisitObjCInterfaceType(ObjCInterfaceType *T);
    QualType VisitObjCObjectPointerType(ObjCObjectPointerType *T);
                            
    // Importing declarations
    bool ImportDeclParts(NamedDecl *D, DeclContext *&DC, 
                         DeclContext *&LexicalDC, DeclarationName &Name, 
                         SourceLocation &Loc);
    void ImportDeclContext(DeclContext *FromDC);
    bool IsStructuralMatch(RecordDecl *FromRecord, RecordDecl *ToRecord);
    bool IsStructuralMatch(EnumDecl *FromEnum, EnumDecl *ToRecord);
    Decl *VisitDecl(Decl *D);
    Decl *VisitNamespaceDecl(NamespaceDecl *D);
    Decl *VisitTypedefDecl(TypedefDecl *D);
    Decl *VisitEnumDecl(EnumDecl *D);
    Decl *VisitRecordDecl(RecordDecl *D);
    Decl *VisitEnumConstantDecl(EnumConstantDecl *D);
    Decl *VisitFunctionDecl(FunctionDecl *D);
    Decl *VisitCXXMethodDecl(CXXMethodDecl *D);
    Decl *VisitCXXConstructorDecl(CXXConstructorDecl *D);
    Decl *VisitCXXDestructorDecl(CXXDestructorDecl *D);
    Decl *VisitCXXConversionDecl(CXXConversionDecl *D);
    Decl *VisitFieldDecl(FieldDecl *D);
    Decl *VisitObjCIvarDecl(ObjCIvarDecl *D);
    Decl *VisitVarDecl(VarDecl *D);
    Decl *VisitImplicitParamDecl(ImplicitParamDecl *D);
    Decl *VisitParmVarDecl(ParmVarDecl *D);
    Decl *VisitObjCMethodDecl(ObjCMethodDecl *D);
    Decl *VisitObjCCategoryDecl(ObjCCategoryDecl *D);
    Decl *VisitObjCProtocolDecl(ObjCProtocolDecl *D);
    Decl *VisitObjCInterfaceDecl(ObjCInterfaceDecl *D);
    Decl *VisitObjCPropertyDecl(ObjCPropertyDecl *D);
    Decl *VisitObjCForwardProtocolDecl(ObjCForwardProtocolDecl *D);
    Decl *VisitObjCClassDecl(ObjCClassDecl *D);
                            
    // Importing statements
    Stmt *VisitStmt(Stmt *S);

    // Importing expressions
    Expr *VisitExpr(Expr *E);
    Expr *VisitDeclRefExpr(DeclRefExpr *E);
    Expr *VisitIntegerLiteral(IntegerLiteral *E);
    Expr *VisitCharacterLiteral(CharacterLiteral *E);
    Expr *VisitParenExpr(ParenExpr *E);
    Expr *VisitUnaryOperator(UnaryOperator *E);
    Expr *VisitSizeOfAlignOfExpr(SizeOfAlignOfExpr *E);
    Expr *VisitBinaryOperator(BinaryOperator *E);
    Expr *VisitCompoundAssignOperator(CompoundAssignOperator *E);
    Expr *VisitImplicitCastExpr(ImplicitCastExpr *E);
    Expr *VisitCStyleCastExpr(CStyleCastExpr *E);
  };
}

//----------------------------------------------------------------------------
// Structural Equivalence
//----------------------------------------------------------------------------

namespace {
  struct StructuralEquivalenceContext {
    /// \brief AST contexts for which we are checking structural equivalence.
    ASTContext &C1, &C2;
    
    /// \brief Diagnostic object used to emit diagnostics.
    Diagnostic &Diags;
    
    /// \brief The set of "tentative" equivalences between two canonical 
    /// declarations, mapping from a declaration in the first context to the
    /// declaration in the second context that we believe to be equivalent.
    llvm::DenseMap<Decl *, Decl *> TentativeEquivalences;
    
    /// \brief Queue of declarations in the first context whose equivalence
    /// with a declaration in the second context still needs to be verified.
    std::deque<Decl *> DeclsToCheck;
    
    /// \brief Declaration (from, to) pairs that are known not to be equivalent
    /// (which we have already complained about).
    llvm::DenseSet<std::pair<Decl *, Decl *> > &NonEquivalentDecls;
    
    /// \brief Whether we're being strict about the spelling of types when 
    /// unifying two types.
    bool StrictTypeSpelling;
    
    StructuralEquivalenceContext(ASTContext &C1, ASTContext &C2,
                                 Diagnostic &Diags,
               llvm::DenseSet<std::pair<Decl *, Decl *> > &NonEquivalentDecls,
                                 bool StrictTypeSpelling = false)
      : C1(C1), C2(C2), Diags(Diags), NonEquivalentDecls(NonEquivalentDecls),
        StrictTypeSpelling(StrictTypeSpelling) { }

    /// \brief Determine whether the two declarations are structurally
    /// equivalent.
    bool IsStructurallyEquivalent(Decl *D1, Decl *D2);
    
    /// \brief Determine whether the two types are structurally equivalent.
    bool IsStructurallyEquivalent(QualType T1, QualType T2);

  private:
    /// \brief Finish checking all of the structural equivalences.
    ///
    /// \returns true if an error occurred, false otherwise.
    bool Finish();
    
  public:
    DiagnosticBuilder Diag1(SourceLocation Loc, unsigned DiagID) {
      return Diags.Report(FullSourceLoc(Loc, C1.getSourceManager()), DiagID);
    }

    DiagnosticBuilder Diag2(SourceLocation Loc, unsigned DiagID) {
      return Diags.Report(FullSourceLoc(Loc, C2.getSourceManager()), DiagID);
    }
  };
}

static bool IsStructurallyEquivalent(StructuralEquivalenceContext &Context,
                                     QualType T1, QualType T2);
static bool IsStructurallyEquivalent(StructuralEquivalenceContext &Context,
                                     Decl *D1, Decl *D2);

/// \brief Determine if two APInts have the same value, after zero-extending
/// one of them (if needed!) to ensure that the bit-widths match.
static bool IsSameValue(const llvm::APInt &I1, const llvm::APInt &I2) {
  if (I1.getBitWidth() == I2.getBitWidth())
    return I1 == I2;
  
  if (I1.getBitWidth() > I2.getBitWidth())
    return I1 == llvm::APInt(I2).zext(I1.getBitWidth());
  
  return llvm::APInt(I1).zext(I2.getBitWidth()) == I2;
}

/// \brief Determine if two APSInts have the same value, zero- or sign-extending
/// as needed.
static bool IsSameValue(const llvm::APSInt &I1, const llvm::APSInt &I2) {
  if (I1.getBitWidth() == I2.getBitWidth() && I1.isSigned() == I2.isSigned())
    return I1 == I2;
  
  // Check for a bit-width mismatch.
  if (I1.getBitWidth() > I2.getBitWidth())
    return IsSameValue(I1, llvm::APSInt(I2).extend(I1.getBitWidth()));
  else if (I2.getBitWidth() > I1.getBitWidth())
    return IsSameValue(llvm::APSInt(I1).extend(I2.getBitWidth()), I2);
  
  // We have a signedness mismatch. Turn the signed value into an unsigned 
  // value.
  if (I1.isSigned()) {
    if (I1.isNegative())
      return false;
    
    return llvm::APSInt(I1, true) == I2;
  }
 
  if (I2.isNegative())
    return false;
  
  return I1 == llvm::APSInt(I2, true);
}

/// \brief Determine structural equivalence of two expressions.
static bool IsStructurallyEquivalent(StructuralEquivalenceContext &Context,
                                     Expr *E1, Expr *E2) {
  if (!E1 || !E2)
    return E1 == E2;
  
  // FIXME: Actually perform a structural comparison!
  return true;
}

/// \brief Determine whether two identifiers are equivalent.
static bool IsStructurallyEquivalent(const IdentifierInfo *Name1,
                                     const IdentifierInfo *Name2) {
  if (!Name1 || !Name2)
    return Name1 == Name2;
  
  return Name1->getName() == Name2->getName();
}

/// \brief Determine whether two nested-name-specifiers are equivalent.
static bool IsStructurallyEquivalent(StructuralEquivalenceContext &Context,
                                     NestedNameSpecifier *NNS1,
                                     NestedNameSpecifier *NNS2) {
  // FIXME: Implement!
  return true;
}

/// \brief Determine whether two template arguments are equivalent.
static bool IsStructurallyEquivalent(StructuralEquivalenceContext &Context,
                                     const TemplateArgument &Arg1,
                                     const TemplateArgument &Arg2) {
  // FIXME: Implement!
  return true;
}

/// \brief Determine structural equivalence for the common part of array 
/// types.
static bool IsArrayStructurallyEquivalent(StructuralEquivalenceContext &Context,
                                          const ArrayType *Array1, 
                                          const ArrayType *Array2) {
  if (!IsStructurallyEquivalent(Context, 
                                Array1->getElementType(), 
                                Array2->getElementType()))
    return false;
  if (Array1->getSizeModifier() != Array2->getSizeModifier())
    return false;
  if (Array1->getIndexTypeQualifiers() != Array2->getIndexTypeQualifiers())
    return false;
  
  return true;
}

/// \brief Determine structural equivalence of two types.
static bool IsStructurallyEquivalent(StructuralEquivalenceContext &Context,
                                     QualType T1, QualType T2) {
  if (T1.isNull() || T2.isNull())
    return T1.isNull() && T2.isNull();
  
  if (!Context.StrictTypeSpelling) {
    // We aren't being strict about token-to-token equivalence of types,
    // so map down to the canonical type.
    T1 = Context.C1.getCanonicalType(T1);
    T2 = Context.C2.getCanonicalType(T2);
  }
  
  if (T1.getQualifiers() != T2.getQualifiers())
    return false;
  
  Type::TypeClass TC = T1->getTypeClass();
  
  if (T1->getTypeClass() != T2->getTypeClass()) {
    // Compare function types with prototypes vs. without prototypes as if
    // both did not have prototypes.
    if (T1->getTypeClass() == Type::FunctionProto &&
        T2->getTypeClass() == Type::FunctionNoProto)
      TC = Type::FunctionNoProto;
    else if (T1->getTypeClass() == Type::FunctionNoProto &&
             T2->getTypeClass() == Type::FunctionProto)
      TC = Type::FunctionNoProto;
    else
      return false;
  }
  
  switch (TC) {
  case Type::Builtin:
    // FIXME: Deal with Char_S/Char_U. 
    if (cast<BuiltinType>(T1)->getKind() != cast<BuiltinType>(T2)->getKind())
      return false;
    break;
  
  case Type::Complex:
    if (!IsStructurallyEquivalent(Context,
                                  cast<ComplexType>(T1)->getElementType(),
                                  cast<ComplexType>(T2)->getElementType()))
      return false;
    break;
  
  case Type::Pointer:
    if (!IsStructurallyEquivalent(Context,
                                  cast<PointerType>(T1)->getPointeeType(),
                                  cast<PointerType>(T2)->getPointeeType()))
      return false;
    break;

  case Type::BlockPointer:
    if (!IsStructurallyEquivalent(Context,
                                  cast<BlockPointerType>(T1)->getPointeeType(),
                                  cast<BlockPointerType>(T2)->getPointeeType()))
      return false;
    break;

  case Type::LValueReference:
  case Type::RValueReference: {
    const ReferenceType *Ref1 = cast<ReferenceType>(T1);
    const ReferenceType *Ref2 = cast<ReferenceType>(T2);
    if (Ref1->isSpelledAsLValue() != Ref2->isSpelledAsLValue())
      return false;
    if (Ref1->isInnerRef() != Ref2->isInnerRef())
      return false;
    if (!IsStructurallyEquivalent(Context,
                                  Ref1->getPointeeTypeAsWritten(),
                                  Ref2->getPointeeTypeAsWritten()))
      return false;
    break;
  }
      
  case Type::MemberPointer: {
    const MemberPointerType *MemPtr1 = cast<MemberPointerType>(T1);
    const MemberPointerType *MemPtr2 = cast<MemberPointerType>(T2);
    if (!IsStructurallyEquivalent(Context,
                                  MemPtr1->getPointeeType(),
                                  MemPtr2->getPointeeType()))
      return false;
    if (!IsStructurallyEquivalent(Context,
                                  QualType(MemPtr1->getClass(), 0),
                                  QualType(MemPtr2->getClass(), 0)))
      return false;
    break;
  }
      
  case Type::ConstantArray: {
    const ConstantArrayType *Array1 = cast<ConstantArrayType>(T1);
    const ConstantArrayType *Array2 = cast<ConstantArrayType>(T2);
    if (!IsSameValue(Array1->getSize(), Array2->getSize()))
      return false;
    
    if (!IsArrayStructurallyEquivalent(Context, Array1, Array2))
      return false;
    break;
  }

  case Type::IncompleteArray:
    if (!IsArrayStructurallyEquivalent(Context, 
                                       cast<ArrayType>(T1), 
                                       cast<ArrayType>(T2)))
      return false;
    break;
      
  case Type::VariableArray: {
    const VariableArrayType *Array1 = cast<VariableArrayType>(T1);
    const VariableArrayType *Array2 = cast<VariableArrayType>(T2);
    if (!IsStructurallyEquivalent(Context, 
                                  Array1->getSizeExpr(), Array2->getSizeExpr()))
      return false;
    
    if (!IsArrayStructurallyEquivalent(Context, Array1, Array2))
      return false;
    
    break;
  }
  
  case Type::DependentSizedArray: {
    const DependentSizedArrayType *Array1 = cast<DependentSizedArrayType>(T1);
    const DependentSizedArrayType *Array2 = cast<DependentSizedArrayType>(T2);
    if (!IsStructurallyEquivalent(Context, 
                                  Array1->getSizeExpr(), Array2->getSizeExpr()))
      return false;
    
    if (!IsArrayStructurallyEquivalent(Context, Array1, Array2))
      return false;
    
    break;
  }
      
  case Type::DependentSizedExtVector: {
    const DependentSizedExtVectorType *Vec1
      = cast<DependentSizedExtVectorType>(T1);
    const DependentSizedExtVectorType *Vec2
      = cast<DependentSizedExtVectorType>(T2);
    if (!IsStructurallyEquivalent(Context, 
                                  Vec1->getSizeExpr(), Vec2->getSizeExpr()))
      return false;
    if (!IsStructurallyEquivalent(Context, 
                                  Vec1->getElementType(), 
                                  Vec2->getElementType()))
      return false;
    break;
  }
   
  case Type::Vector: 
  case Type::ExtVector: {
    const VectorType *Vec1 = cast<VectorType>(T1);
    const VectorType *Vec2 = cast<VectorType>(T2);
    if (!IsStructurallyEquivalent(Context, 
                                  Vec1->getElementType(),
                                  Vec2->getElementType()))
      return false;
    if (Vec1->getNumElements() != Vec2->getNumElements())
      return false;
    if (Vec1->isAltiVec() != Vec2->isAltiVec())
      return false;
    if (Vec1->isPixel() != Vec2->isPixel())
      return false;
    break;
  }

  case Type::FunctionProto: {
    const FunctionProtoType *Proto1 = cast<FunctionProtoType>(T1);
    const FunctionProtoType *Proto2 = cast<FunctionProtoType>(T2);
    if (Proto1->getNumArgs() != Proto2->getNumArgs())
      return false;
    for (unsigned I = 0, N = Proto1->getNumArgs(); I != N; ++I) {
      if (!IsStructurallyEquivalent(Context, 
                                    Proto1->getArgType(I),
                                    Proto2->getArgType(I)))
        return false;
    }
    if (Proto1->isVariadic() != Proto2->isVariadic())
      return false;
    if (Proto1->hasExceptionSpec() != Proto2->hasExceptionSpec())
      return false;
    if (Proto1->hasAnyExceptionSpec() != Proto2->hasAnyExceptionSpec())
      return false;
    if (Proto1->getNumExceptions() != Proto2->getNumExceptions())
      return false;
    for (unsigned I = 0, N = Proto1->getNumExceptions(); I != N; ++I) {
      if (!IsStructurallyEquivalent(Context,
                                    Proto1->getExceptionType(I),
                                    Proto2->getExceptionType(I)))
        return false;
    }
    if (Proto1->getTypeQuals() != Proto2->getTypeQuals())
      return false;
    
    // Fall through to check the bits common with FunctionNoProtoType.
  }
      
  case Type::FunctionNoProto: {
    const FunctionType *Function1 = cast<FunctionType>(T1);
    const FunctionType *Function2 = cast<FunctionType>(T2);
    if (!IsStructurallyEquivalent(Context, 
                                  Function1->getResultType(),
                                  Function2->getResultType()))
      return false;
    if (Function1->getNoReturnAttr() != Function2->getNoReturnAttr())
      return false;
    if (Function1->getCallConv() != Function2->getCallConv())
      return false;
    break;
  }
   
  case Type::UnresolvedUsing:
    if (!IsStructurallyEquivalent(Context,
                                  cast<UnresolvedUsingType>(T1)->getDecl(),
                                  cast<UnresolvedUsingType>(T2)->getDecl()))
      return false;
      
    break;
      
  case Type::Typedef:
    if (!IsStructurallyEquivalent(Context,
                                  cast<TypedefType>(T1)->getDecl(),
                                  cast<TypedefType>(T2)->getDecl()))
      return false;
    break;
      
  case Type::TypeOfExpr:
    if (!IsStructurallyEquivalent(Context,
                                cast<TypeOfExprType>(T1)->getUnderlyingExpr(),
                                cast<TypeOfExprType>(T2)->getUnderlyingExpr()))
      return false;
    break;
      
  case Type::TypeOf:
    if (!IsStructurallyEquivalent(Context,
                                  cast<TypeOfType>(T1)->getUnderlyingType(),
                                  cast<TypeOfType>(T2)->getUnderlyingType()))
      return false;
    break;
      
  case Type::Decltype:
    if (!IsStructurallyEquivalent(Context,
                                  cast<DecltypeType>(T1)->getUnderlyingExpr(),
                                  cast<DecltypeType>(T2)->getUnderlyingExpr()))
      return false;
    break;

  case Type::Record:
  case Type::Enum:
    if (!IsStructurallyEquivalent(Context,
                                  cast<TagType>(T1)->getDecl(),
                                  cast<TagType>(T2)->getDecl()))
      return false;
    break;
      
  case Type::Elaborated: {
    const ElaboratedType *Elab1 = cast<ElaboratedType>(T1);
    const ElaboratedType *Elab2 = cast<ElaboratedType>(T2);
    if (Elab1->getTagKind() != Elab2->getTagKind())
      return false;
    if (!IsStructurallyEquivalent(Context, 
                                  Elab1->getUnderlyingType(),
                                  Elab2->getUnderlyingType()))
      return false;
    break;
  }
   
  case Type::TemplateTypeParm: {
    const TemplateTypeParmType *Parm1 = cast<TemplateTypeParmType>(T1);
    const TemplateTypeParmType *Parm2 = cast<TemplateTypeParmType>(T2);
    if (Parm1->getDepth() != Parm2->getDepth())
      return false;
    if (Parm1->getIndex() != Parm2->getIndex())
      return false;
    if (Parm1->isParameterPack() != Parm2->isParameterPack())
      return false;
    
    // Names of template type parameters are never significant.
    break;
  }
      
  case Type::SubstTemplateTypeParm: {
    const SubstTemplateTypeParmType *Subst1
      = cast<SubstTemplateTypeParmType>(T1);
    const SubstTemplateTypeParmType *Subst2
      = cast<SubstTemplateTypeParmType>(T2);
    if (!IsStructurallyEquivalent(Context,
                                  QualType(Subst1->getReplacedParameter(), 0),
                                  QualType(Subst2->getReplacedParameter(), 0)))
      return false;
    if (!IsStructurallyEquivalent(Context, 
                                  Subst1->getReplacementType(),
                                  Subst2->getReplacementType()))
      return false;
    break;
  }

  case Type::TemplateSpecialization: {
    const TemplateSpecializationType *Spec1
      = cast<TemplateSpecializationType>(T1);
    const TemplateSpecializationType *Spec2
      = cast<TemplateSpecializationType>(T2);
    if (!IsStructurallyEquivalent(Context,
                                  Spec1->getTemplateName(),
                                  Spec2->getTemplateName()))
      return false;
    if (Spec1->getNumArgs() != Spec2->getNumArgs())
      return false;
    for (unsigned I = 0, N = Spec1->getNumArgs(); I != N; ++I) {
      if (!IsStructurallyEquivalent(Context, 
                                    Spec1->getArg(I), Spec2->getArg(I)))
        return false;
    }
    break;
  }
      
  case Type::QualifiedName: {
    const QualifiedNameType *Qual1 = cast<QualifiedNameType>(T1);
    const QualifiedNameType *Qual2 = cast<QualifiedNameType>(T2);
    if (!IsStructurallyEquivalent(Context, 
                                  Qual1->getQualifier(), 
                                  Qual2->getQualifier()))
      return false;
    if (!IsStructurallyEquivalent(Context,
                                  Qual1->getNamedType(),
                                  Qual2->getNamedType()))
      return false;
    break;
  }

  case Type::InjectedClassName: {
    const InjectedClassNameType *Inj1 = cast<InjectedClassNameType>(T1);
    const InjectedClassNameType *Inj2 = cast<InjectedClassNameType>(T2);
    if (!IsStructurallyEquivalent(Context,
                                  Inj1->getUnderlyingType(),
                                  Inj2->getUnderlyingType()))
      return false;
    break;
  }

  case Type::Typename: {
    const TypenameType *Typename1 = cast<TypenameType>(T1);
    const TypenameType *Typename2 = cast<TypenameType>(T2);
    if (!IsStructurallyEquivalent(Context, 
                                  Typename1->getQualifier(),
                                  Typename2->getQualifier()))
      return false;
    if (!IsStructurallyEquivalent(Typename1->getIdentifier(),
                                  Typename2->getIdentifier()))
      return false;
    if (!IsStructurallyEquivalent(Context,
                                  QualType(Typename1->getTemplateId(), 0),
                                  QualType(Typename2->getTemplateId(), 0)))
      return false;
    
    break;
  }
  
  case Type::ObjCInterface: {
    const ObjCInterfaceType *Iface1 = cast<ObjCInterfaceType>(T1);
    const ObjCInterfaceType *Iface2 = cast<ObjCInterfaceType>(T2);
    if (!IsStructurallyEquivalent(Context, 
                                  Iface1->getDecl(), Iface2->getDecl()))
      return false;
    if (Iface1->getNumProtocols() != Iface2->getNumProtocols())
      return false;
    for (unsigned I = 0, N = Iface1->getNumProtocols(); I != N; ++I) {
      if (!IsStructurallyEquivalent(Context,
                                    Iface1->getProtocol(I),
                                    Iface2->getProtocol(I)))
        return false;
    }
    break;
  }

  case Type::ObjCObjectPointer: {
    const ObjCObjectPointerType *Ptr1 = cast<ObjCObjectPointerType>(T1);
    const ObjCObjectPointerType *Ptr2 = cast<ObjCObjectPointerType>(T2);
    if (!IsStructurallyEquivalent(Context, 
                                  Ptr1->getPointeeType(),
                                  Ptr2->getPointeeType()))
      return false;
    if (Ptr1->getNumProtocols() != Ptr2->getNumProtocols())
      return false;
    for (unsigned I = 0, N = Ptr1->getNumProtocols(); I != N; ++I) {
      if (!IsStructurallyEquivalent(Context,
                                    Ptr1->getProtocol(I),
                                    Ptr2->getProtocol(I)))
        return false;
    }
    break;
  }
      
  } // end switch

  return true;
}

/// \brief Determine structural equivalence of two records.
static bool IsStructurallyEquivalent(StructuralEquivalenceContext &Context,
                                     RecordDecl *D1, RecordDecl *D2) {
  if (D1->isUnion() != D2->isUnion()) {
    Context.Diag2(D2->getLocation(), diag::warn_odr_tag_type_inconsistent)
      << Context.C2.getTypeDeclType(D2);
    Context.Diag1(D1->getLocation(), diag::note_odr_tag_kind_here)
      << D1->getDeclName() << (unsigned)D1->getTagKind();
    return false;
  }
  
  // Compare the definitions of these two records. If either or both are
  // incomplete, we assume that they are equivalent.
  D1 = D1->getDefinition();
  D2 = D2->getDefinition();
  if (!D1 || !D2)
    return true;
  
  if (CXXRecordDecl *D1CXX = dyn_cast<CXXRecordDecl>(D1)) {
    if (CXXRecordDecl *D2CXX = dyn_cast<CXXRecordDecl>(D2)) {
      if (D1CXX->getNumBases() != D2CXX->getNumBases()) {
        Context.Diag2(D2->getLocation(), diag::warn_odr_tag_type_inconsistent)
        << Context.C2.getTypeDeclType(D2);
        Context.Diag2(D2->getLocation(), diag::note_odr_number_of_bases)
        << D2CXX->getNumBases();
        Context.Diag1(D1->getLocation(), diag::note_odr_number_of_bases)
        << D1CXX->getNumBases();
        return false;
      }
      
      // Check the base classes. 
      for (CXXRecordDecl::base_class_iterator Base1 = D1CXX->bases_begin(), 
                                           BaseEnd1 = D1CXX->bases_end(),
                                                Base2 = D2CXX->bases_begin();
           Base1 != BaseEnd1;
           ++Base1, ++Base2) {        
        if (!IsStructurallyEquivalent(Context, 
                                      Base1->getType(), Base2->getType())) {
          Context.Diag2(D2->getLocation(), diag::warn_odr_tag_type_inconsistent)
            << Context.C2.getTypeDeclType(D2);
          Context.Diag2(Base2->getSourceRange().getBegin(), diag::note_odr_base)
            << Base2->getType()
            << Base2->getSourceRange();
          Context.Diag1(Base1->getSourceRange().getBegin(), diag::note_odr_base)
            << Base1->getType()
            << Base1->getSourceRange();
          return false;
        }
        
        // Check virtual vs. non-virtual inheritance mismatch.
        if (Base1->isVirtual() != Base2->isVirtual()) {
          Context.Diag2(D2->getLocation(), diag::warn_odr_tag_type_inconsistent)
            << Context.C2.getTypeDeclType(D2);
          Context.Diag2(Base2->getSourceRange().getBegin(),
                        diag::note_odr_virtual_base)
            << Base2->isVirtual() << Base2->getSourceRange();
          Context.Diag1(Base1->getSourceRange().getBegin(), diag::note_odr_base)
            << Base1->isVirtual()
            << Base1->getSourceRange();
          return false;
        }
      }
    } else if (D1CXX->getNumBases() > 0) {
      Context.Diag2(D2->getLocation(), diag::warn_odr_tag_type_inconsistent)
        << Context.C2.getTypeDeclType(D2);
      const CXXBaseSpecifier *Base1 = D1CXX->bases_begin();
      Context.Diag1(Base1->getSourceRange().getBegin(), diag::note_odr_base)
        << Base1->getType()
        << Base1->getSourceRange();
      Context.Diag2(D2->getLocation(), diag::note_odr_missing_base);
      return false;
    }
  }
  
  // Check the fields for consistency.
  CXXRecordDecl::field_iterator Field2 = D2->field_begin(),
                             Field2End = D2->field_end();
  for (CXXRecordDecl::field_iterator Field1 = D1->field_begin(),
                                  Field1End = D1->field_end();
       Field1 != Field1End;
       ++Field1, ++Field2) {
    if (Field2 == Field2End) {
      Context.Diag2(D2->getLocation(), diag::warn_odr_tag_type_inconsistent)
        << Context.C2.getTypeDeclType(D2);
      Context.Diag1(Field1->getLocation(), diag::note_odr_field)
        << Field1->getDeclName() << Field1->getType();
      Context.Diag2(D2->getLocation(), diag::note_odr_missing_field);
      return false;
    }
    
    if (!IsStructurallyEquivalent(Context, 
                                  Field1->getType(), Field2->getType())) {
      Context.Diag2(D2->getLocation(), diag::warn_odr_tag_type_inconsistent)
        << Context.C2.getTypeDeclType(D2);
      Context.Diag2(Field2->getLocation(), diag::note_odr_field)
        << Field2->getDeclName() << Field2->getType();
      Context.Diag1(Field1->getLocation(), diag::note_odr_field)
        << Field1->getDeclName() << Field1->getType();
      return false;
    }
    
    if (Field1->isBitField() != Field2->isBitField()) {
      Context.Diag2(D2->getLocation(), diag::warn_odr_tag_type_inconsistent)
        << Context.C2.getTypeDeclType(D2);
      if (Field1->isBitField()) {
        llvm::APSInt Bits;
        Field1->getBitWidth()->isIntegerConstantExpr(Bits, Context.C1);
        Context.Diag1(Field1->getLocation(), diag::note_odr_bit_field)
          << Field1->getDeclName() << Field1->getType()
          << Bits.toString(10, false);
        Context.Diag2(Field2->getLocation(), diag::note_odr_not_bit_field)
          << Field2->getDeclName();
      } else {
        llvm::APSInt Bits;
        Field2->getBitWidth()->isIntegerConstantExpr(Bits, Context.C2);
        Context.Diag2(Field2->getLocation(), diag::note_odr_bit_field)
          << Field2->getDeclName() << Field2->getType()
          << Bits.toString(10, false);
        Context.Diag1(Field1->getLocation(), 
                          diag::note_odr_not_bit_field)
        << Field1->getDeclName();
      }
      return false;
    }
    
    if (Field1->isBitField()) {
      // Make sure that the bit-fields are the same length.
      llvm::APSInt Bits1, Bits2;
      if (!Field1->getBitWidth()->isIntegerConstantExpr(Bits1, Context.C1))
        return false;
      if (!Field2->getBitWidth()->isIntegerConstantExpr(Bits2, Context.C2))
        return false;
      
      if (!IsSameValue(Bits1, Bits2)) {
        Context.Diag2(D2->getLocation(), diag::warn_odr_tag_type_inconsistent)
          << Context.C2.getTypeDeclType(D2);
        Context.Diag2(Field2->getLocation(), diag::note_odr_bit_field)
          << Field2->getDeclName() << Field2->getType()
          << Bits2.toString(10, false);
        Context.Diag1(Field1->getLocation(), diag::note_odr_bit_field)
          << Field1->getDeclName() << Field1->getType()
          << Bits1.toString(10, false);
        return false;
      }
    }
  }
  
  if (Field2 != Field2End) {
    Context.Diag2(D2->getLocation(), diag::warn_odr_tag_type_inconsistent)
      << Context.C2.getTypeDeclType(D2);
    Context.Diag2(Field2->getLocation(), diag::note_odr_field)
      << Field2->getDeclName() << Field2->getType();
    Context.Diag1(D1->getLocation(), diag::note_odr_missing_field);
    return false;
  }
  
  return true;
}
     
/// \brief Determine structural equivalence of two enums.
static bool IsStructurallyEquivalent(StructuralEquivalenceContext &Context,
                                     EnumDecl *D1, EnumDecl *D2) {
  EnumDecl::enumerator_iterator EC2 = D2->enumerator_begin(),
                             EC2End = D2->enumerator_end();
  for (EnumDecl::enumerator_iterator EC1 = D1->enumerator_begin(),
                                  EC1End = D1->enumerator_end();
       EC1 != EC1End; ++EC1, ++EC2) {
    if (EC2 == EC2End) {
      Context.Diag2(D2->getLocation(), diag::warn_odr_tag_type_inconsistent)
        << Context.C2.getTypeDeclType(D2);
      Context.Diag1(EC1->getLocation(), diag::note_odr_enumerator)
        << EC1->getDeclName() 
        << EC1->getInitVal().toString(10);
      Context.Diag2(D2->getLocation(), diag::note_odr_missing_enumerator);
      return false;
    }
    
    llvm::APSInt Val1 = EC1->getInitVal();
    llvm::APSInt Val2 = EC2->getInitVal();
    if (!IsSameValue(Val1, Val2) || 
        !IsStructurallyEquivalent(EC1->getIdentifier(), EC2->getIdentifier())) {
      Context.Diag2(D2->getLocation(), diag::warn_odr_tag_type_inconsistent)
        << Context.C2.getTypeDeclType(D2);
      Context.Diag2(EC2->getLocation(), diag::note_odr_enumerator)
        << EC2->getDeclName() 
        << EC2->getInitVal().toString(10);
      Context.Diag1(EC1->getLocation(), diag::note_odr_enumerator)
        << EC1->getDeclName() 
        << EC1->getInitVal().toString(10);
      return false;
    }
  }
  
  if (EC2 != EC2End) {
    Context.Diag2(D2->getLocation(), diag::warn_odr_tag_type_inconsistent)
      << Context.C2.getTypeDeclType(D2);
    Context.Diag2(EC2->getLocation(), diag::note_odr_enumerator)
      << EC2->getDeclName() 
      << EC2->getInitVal().toString(10);
    Context.Diag1(D1->getLocation(), diag::note_odr_missing_enumerator);
    return false;
  }
  
  return true;
}
  
/// \brief Determine structural equivalence of two declarations.
static bool IsStructurallyEquivalent(StructuralEquivalenceContext &Context,
                                     Decl *D1, Decl *D2) {
  // FIXME: Check for known structural equivalences via a callback of some sort.
  
  // Check whether we already know that these two declarations are not
  // structurally equivalent.
  if (Context.NonEquivalentDecls.count(std::make_pair(D1->getCanonicalDecl(),
                                                      D2->getCanonicalDecl())))
    return false;
  
  // Determine whether we've already produced a tentative equivalence for D1.
  Decl *&EquivToD1 = Context.TentativeEquivalences[D1->getCanonicalDecl()];
  if (EquivToD1)
    return EquivToD1 == D2->getCanonicalDecl();
  
  // Produce a tentative equivalence D1 <-> D2, which will be checked later.
  EquivToD1 = D2->getCanonicalDecl();
  Context.DeclsToCheck.push_back(D1->getCanonicalDecl());
  return true;
}

bool StructuralEquivalenceContext::IsStructurallyEquivalent(Decl *D1, 
                                                            Decl *D2) {
  if (!::IsStructurallyEquivalent(*this, D1, D2))
    return false;
  
  return !Finish();
}

bool StructuralEquivalenceContext::IsStructurallyEquivalent(QualType T1, 
                                                            QualType T2) {
  if (!::IsStructurallyEquivalent(*this, T1, T2))
    return false;
  
  return !Finish();
}

bool StructuralEquivalenceContext::Finish() {
  while (!DeclsToCheck.empty()) {
    // Check the next declaration.
    Decl *D1 = DeclsToCheck.front();
    DeclsToCheck.pop_front();
    
    Decl *D2 = TentativeEquivalences[D1];
    assert(D2 && "Unrecorded tentative equivalence?");
    
    bool Equivalent = true;
    
    // FIXME: Switch on all declaration kinds. For now, we're just going to
    // check the obvious ones.
    if (RecordDecl *Record1 = dyn_cast<RecordDecl>(D1)) {
      if (RecordDecl *Record2 = dyn_cast<RecordDecl>(D2)) {
        // Check for equivalent structure names.
        IdentifierInfo *Name1 = Record1->getIdentifier();
        if (!Name1 && Record1->getTypedefForAnonDecl())
          Name1 = Record1->getTypedefForAnonDecl()->getIdentifier();
        IdentifierInfo *Name2 = Record2->getIdentifier();
        if (!Name2 && Record2->getTypedefForAnonDecl())
          Name2 = Record2->getTypedefForAnonDecl()->getIdentifier();
        if (!::IsStructurallyEquivalent(Name1, Name2) ||
            !::IsStructurallyEquivalent(*this, Record1, Record2))
          Equivalent = false;
      } else {
        // Record/non-record mismatch.
        Equivalent = false;
      }
    } else if (EnumDecl *Enum1 = dyn_cast<EnumDecl>(D1)) {
      if (EnumDecl *Enum2 = dyn_cast<EnumDecl>(D2)) {
        // Check for equivalent enum names.
        IdentifierInfo *Name1 = Enum1->getIdentifier();
        if (!Name1 && Enum1->getTypedefForAnonDecl())
          Name1 = Enum1->getTypedefForAnonDecl()->getIdentifier();
        IdentifierInfo *Name2 = Enum2->getIdentifier();
        if (!Name2 && Enum2->getTypedefForAnonDecl())
          Name2 = Enum2->getTypedefForAnonDecl()->getIdentifier();
        if (!::IsStructurallyEquivalent(Name1, Name2) ||
            !::IsStructurallyEquivalent(*this, Enum1, Enum2))
          Equivalent = false;
      } else {
        // Enum/non-enum mismatch
        Equivalent = false;
      }
    } else if (TypedefDecl *Typedef1 = dyn_cast<TypedefDecl>(D1)) {
      if (TypedefDecl *Typedef2 = dyn_cast<TypedefDecl>(D2)) {
        if (!::IsStructurallyEquivalent(Typedef1->getIdentifier(),
                                        Typedef2->getIdentifier()) ||
            !::IsStructurallyEquivalent(*this,
                                        Typedef1->getUnderlyingType(),
                                        Typedef2->getUnderlyingType()))
          Equivalent = false;
      } else {
        // Typedef/non-typedef mismatch.
        Equivalent = false;
      }
    } 

    if (!Equivalent) {
      // Note that these two declarations are not equivalent (and we already
      // know about it).
      NonEquivalentDecls.insert(std::make_pair(D1->getCanonicalDecl(),
                                               D2->getCanonicalDecl()));
      return true;
    }
    // FIXME: Check other declaration kinds!
  }
  
  return false;
}

//----------------------------------------------------------------------------
// Import Types
//----------------------------------------------------------------------------

QualType ASTNodeImporter::VisitType(Type *T) {
  Importer.FromDiag(SourceLocation(), diag::err_unsupported_ast_node)
    << T->getTypeClassName();
  return QualType();
}

QualType ASTNodeImporter::VisitBuiltinType(BuiltinType *T) {
  switch (T->getKind()) {
  case BuiltinType::Void: return Importer.getToContext().VoidTy;
  case BuiltinType::Bool: return Importer.getToContext().BoolTy;
    
  case BuiltinType::Char_U:
    // The context we're importing from has an unsigned 'char'. If we're 
    // importing into a context with a signed 'char', translate to 
    // 'unsigned char' instead.
    if (Importer.getToContext().getLangOptions().CharIsSigned)
      return Importer.getToContext().UnsignedCharTy;
    
    return Importer.getToContext().CharTy;

  case BuiltinType::UChar: return Importer.getToContext().UnsignedCharTy;
    
  case BuiltinType::Char16:
    // FIXME: Make sure that the "to" context supports C++!
    return Importer.getToContext().Char16Ty;
    
  case BuiltinType::Char32: 
    // FIXME: Make sure that the "to" context supports C++!
    return Importer.getToContext().Char32Ty;

  case BuiltinType::UShort: return Importer.getToContext().UnsignedShortTy;
  case BuiltinType::UInt: return Importer.getToContext().UnsignedIntTy;
  case BuiltinType::ULong: return Importer.getToContext().UnsignedLongTy;
  case BuiltinType::ULongLong: 
    return Importer.getToContext().UnsignedLongLongTy;
  case BuiltinType::UInt128: return Importer.getToContext().UnsignedInt128Ty;
    
  case BuiltinType::Char_S:
    // The context we're importing from has an unsigned 'char'. If we're 
    // importing into a context with a signed 'char', translate to 
    // 'unsigned char' instead.
    if (!Importer.getToContext().getLangOptions().CharIsSigned)
      return Importer.getToContext().SignedCharTy;
    
    return Importer.getToContext().CharTy;

  case BuiltinType::SChar: return Importer.getToContext().SignedCharTy;
  case BuiltinType::WChar:
    // FIXME: If not in C++, shall we translate to the C equivalent of
    // wchar_t?
    return Importer.getToContext().WCharTy;
    
  case BuiltinType::Short : return Importer.getToContext().ShortTy;
  case BuiltinType::Int : return Importer.getToContext().IntTy;
  case BuiltinType::Long : return Importer.getToContext().LongTy;
  case BuiltinType::LongLong : return Importer.getToContext().LongLongTy;
  case BuiltinType::Int128 : return Importer.getToContext().Int128Ty;
  case BuiltinType::Float: return Importer.getToContext().FloatTy;
  case BuiltinType::Double: return Importer.getToContext().DoubleTy;
  case BuiltinType::LongDouble: return Importer.getToContext().LongDoubleTy;

  case BuiltinType::NullPtr:
    // FIXME: Make sure that the "to" context supports C++0x!
    return Importer.getToContext().NullPtrTy;
    
  case BuiltinType::Overload: return Importer.getToContext().OverloadTy;
  case BuiltinType::Dependent: return Importer.getToContext().DependentTy;
  case BuiltinType::UndeducedAuto: 
    // FIXME: Make sure that the "to" context supports C++0x!
    return Importer.getToContext().UndeducedAutoTy;

  case BuiltinType::ObjCId:
    // FIXME: Make sure that the "to" context supports Objective-C!
    return Importer.getToContext().ObjCBuiltinIdTy;
    
  case BuiltinType::ObjCClass:
    return Importer.getToContext().ObjCBuiltinClassTy;

  case BuiltinType::ObjCSel:
    return Importer.getToContext().ObjCBuiltinSelTy;
  }
  
  return QualType();
}

QualType ASTNodeImporter::VisitComplexType(ComplexType *T) {
  QualType ToElementType = Importer.Import(T->getElementType());
  if (ToElementType.isNull())
    return QualType();
  
  return Importer.getToContext().getComplexType(ToElementType);
}

QualType ASTNodeImporter::VisitPointerType(PointerType *T) {
  QualType ToPointeeType = Importer.Import(T->getPointeeType());
  if (ToPointeeType.isNull())
    return QualType();
  
  return Importer.getToContext().getPointerType(ToPointeeType);
}

QualType ASTNodeImporter::VisitBlockPointerType(BlockPointerType *T) {
  // FIXME: Check for blocks support in "to" context.
  QualType ToPointeeType = Importer.Import(T->getPointeeType());
  if (ToPointeeType.isNull())
    return QualType();
  
  return Importer.getToContext().getBlockPointerType(ToPointeeType);
}

QualType ASTNodeImporter::VisitLValueReferenceType(LValueReferenceType *T) {
  // FIXME: Check for C++ support in "to" context.
  QualType ToPointeeType = Importer.Import(T->getPointeeTypeAsWritten());
  if (ToPointeeType.isNull())
    return QualType();
  
  return Importer.getToContext().getLValueReferenceType(ToPointeeType);
}

QualType ASTNodeImporter::VisitRValueReferenceType(RValueReferenceType *T) {
  // FIXME: Check for C++0x support in "to" context.
  QualType ToPointeeType = Importer.Import(T->getPointeeTypeAsWritten());
  if (ToPointeeType.isNull())
    return QualType();
  
  return Importer.getToContext().getRValueReferenceType(ToPointeeType);  
}

QualType ASTNodeImporter::VisitMemberPointerType(MemberPointerType *T) {
  // FIXME: Check for C++ support in "to" context.
  QualType ToPointeeType = Importer.Import(T->getPointeeType());
  if (ToPointeeType.isNull())
    return QualType();
  
  QualType ClassType = Importer.Import(QualType(T->getClass(), 0));
  return Importer.getToContext().getMemberPointerType(ToPointeeType, 
                                                      ClassType.getTypePtr());
}

QualType ASTNodeImporter::VisitConstantArrayType(ConstantArrayType *T) {
  QualType ToElementType = Importer.Import(T->getElementType());
  if (ToElementType.isNull())
    return QualType();
  
  return Importer.getToContext().getConstantArrayType(ToElementType, 
                                                      T->getSize(),
                                                      T->getSizeModifier(),
                                               T->getIndexTypeCVRQualifiers());
}

QualType ASTNodeImporter::VisitIncompleteArrayType(IncompleteArrayType *T) {
  QualType ToElementType = Importer.Import(T->getElementType());
  if (ToElementType.isNull())
    return QualType();
  
  return Importer.getToContext().getIncompleteArrayType(ToElementType, 
                                                        T->getSizeModifier(),
                                                T->getIndexTypeCVRQualifiers());
}

QualType ASTNodeImporter::VisitVariableArrayType(VariableArrayType *T) {
  QualType ToElementType = Importer.Import(T->getElementType());
  if (ToElementType.isNull())
    return QualType();

  Expr *Size = Importer.Import(T->getSizeExpr());
  if (!Size)
    return QualType();
  
  SourceRange Brackets = Importer.Import(T->getBracketsRange());
  return Importer.getToContext().getVariableArrayType(ToElementType, Size,
                                                      T->getSizeModifier(),
                                                T->getIndexTypeCVRQualifiers(),
                                                      Brackets);
}

QualType ASTNodeImporter::VisitVectorType(VectorType *T) {
  QualType ToElementType = Importer.Import(T->getElementType());
  if (ToElementType.isNull())
    return QualType();
  
  return Importer.getToContext().getVectorType(ToElementType, 
                                               T->getNumElements(),
                                               T->isAltiVec(),
                                               T->isPixel());
}

QualType ASTNodeImporter::VisitExtVectorType(ExtVectorType *T) {
  QualType ToElementType = Importer.Import(T->getElementType());
  if (ToElementType.isNull())
    return QualType();
  
  return Importer.getToContext().getExtVectorType(ToElementType, 
                                                  T->getNumElements());
}

QualType ASTNodeImporter::VisitFunctionNoProtoType(FunctionNoProtoType *T) {
  // FIXME: What happens if we're importing a function without a prototype 
  // into C++? Should we make it variadic?
  QualType ToResultType = Importer.Import(T->getResultType());
  if (ToResultType.isNull())
    return QualType();
  
  return Importer.getToContext().getFunctionNoProtoType(ToResultType,
                                                        T->getNoReturnAttr(), 
                                                        T->getCallConv());
}

QualType ASTNodeImporter::VisitFunctionProtoType(FunctionProtoType *T) {
  QualType ToResultType = Importer.Import(T->getResultType());
  if (ToResultType.isNull())
    return QualType();
  
  // Import argument types
  llvm::SmallVector<QualType, 4> ArgTypes;
  for (FunctionProtoType::arg_type_iterator A = T->arg_type_begin(),
                                         AEnd = T->arg_type_end();
       A != AEnd; ++A) {
    QualType ArgType = Importer.Import(*A);
    if (ArgType.isNull())
      return QualType();
    ArgTypes.push_back(ArgType);
  }
  
  // Import exception types
  llvm::SmallVector<QualType, 4> ExceptionTypes;
  for (FunctionProtoType::exception_iterator E = T->exception_begin(),
                                          EEnd = T->exception_end();
       E != EEnd; ++E) {
    QualType ExceptionType = Importer.Import(*E);
    if (ExceptionType.isNull())
      return QualType();
    ExceptionTypes.push_back(ExceptionType);
  }
       
  return Importer.getToContext().getFunctionType(ToResultType, ArgTypes.data(),
                                                 ArgTypes.size(),
                                                 T->isVariadic(),
                                                 T->getTypeQuals(),
                                                 T->hasExceptionSpec(), 
                                                 T->hasAnyExceptionSpec(),
                                                 ExceptionTypes.size(),
                                                 ExceptionTypes.data(),
                                                 T->getNoReturnAttr(),
                                                 T->getCallConv());
}

QualType ASTNodeImporter::VisitTypedefType(TypedefType *T) {
  TypedefDecl *ToDecl
                 = dyn_cast_or_null<TypedefDecl>(Importer.Import(T->getDecl()));
  if (!ToDecl)
    return QualType();
  
  return Importer.getToContext().getTypeDeclType(ToDecl);
}

QualType ASTNodeImporter::VisitTypeOfExprType(TypeOfExprType *T) {
  Expr *ToExpr = Importer.Import(T->getUnderlyingExpr());
  if (!ToExpr)
    return QualType();
  
  return Importer.getToContext().getTypeOfExprType(ToExpr);
}

QualType ASTNodeImporter::VisitTypeOfType(TypeOfType *T) {
  QualType ToUnderlyingType = Importer.Import(T->getUnderlyingType());
  if (ToUnderlyingType.isNull())
    return QualType();
  
  return Importer.getToContext().getTypeOfType(ToUnderlyingType);
}

QualType ASTNodeImporter::VisitDecltypeType(DecltypeType *T) {
  Expr *ToExpr = Importer.Import(T->getUnderlyingExpr());
  if (!ToExpr)
    return QualType();
  
  return Importer.getToContext().getDecltypeType(ToExpr);
}

QualType ASTNodeImporter::VisitRecordType(RecordType *T) {
  RecordDecl *ToDecl
    = dyn_cast_or_null<RecordDecl>(Importer.Import(T->getDecl()));
  if (!ToDecl)
    return QualType();

  return Importer.getToContext().getTagDeclType(ToDecl);
}

QualType ASTNodeImporter::VisitEnumType(EnumType *T) {
  EnumDecl *ToDecl
    = dyn_cast_or_null<EnumDecl>(Importer.Import(T->getDecl()));
  if (!ToDecl)
    return QualType();

  return Importer.getToContext().getTagDeclType(ToDecl);
}

QualType ASTNodeImporter::VisitElaboratedType(ElaboratedType *T) {
  QualType ToUnderlyingType = Importer.Import(T->getUnderlyingType());
  if (ToUnderlyingType.isNull())
    return QualType();

  return Importer.getToContext().getElaboratedType(ToUnderlyingType,
                                                   T->getTagKind());
}

QualType ASTNodeImporter::VisitQualifiedNameType(QualifiedNameType *T) {
  NestedNameSpecifier *ToQualifier = Importer.Import(T->getQualifier());
  if (!ToQualifier)
    return QualType();

  QualType ToNamedType = Importer.Import(T->getNamedType());
  if (ToNamedType.isNull())
    return QualType();

  return Importer.getToContext().getQualifiedNameType(ToQualifier, ToNamedType);
}

QualType ASTNodeImporter::VisitObjCInterfaceType(ObjCInterfaceType *T) {
  ObjCInterfaceDecl *Class
    = dyn_cast_or_null<ObjCInterfaceDecl>(Importer.Import(T->getDecl()));
  if (!Class)
    return QualType();

  llvm::SmallVector<ObjCProtocolDecl *, 4> Protocols;
  for (ObjCInterfaceType::qual_iterator P = T->qual_begin(), 
                                     PEnd = T->qual_end();
       P != PEnd; ++P) {
    ObjCProtocolDecl *Protocol
      = dyn_cast_or_null<ObjCProtocolDecl>(Importer.Import(*P));
    if (!Protocol)
      return QualType();
    Protocols.push_back(Protocol);
  }

  return Importer.getToContext().getObjCInterfaceType(Class,
                                                      Protocols.data(),
                                                      Protocols.size());
}

QualType ASTNodeImporter::VisitObjCObjectPointerType(ObjCObjectPointerType *T) {
  QualType ToPointeeType = Importer.Import(T->getPointeeType());
  if (ToPointeeType.isNull())
    return QualType();

  llvm::SmallVector<ObjCProtocolDecl *, 4> Protocols;
  for (ObjCObjectPointerType::qual_iterator P = T->qual_begin(), 
                                         PEnd = T->qual_end();
       P != PEnd; ++P) {
    ObjCProtocolDecl *Protocol
      = dyn_cast_or_null<ObjCProtocolDecl>(Importer.Import(*P));
    if (!Protocol)
      return QualType();
    Protocols.push_back(Protocol);
  }

  return Importer.getToContext().getObjCObjectPointerType(ToPointeeType,
                                                          Protocols.data(),
                                                          Protocols.size());
}

//----------------------------------------------------------------------------
// Import Declarations
//----------------------------------------------------------------------------
bool ASTNodeImporter::ImportDeclParts(NamedDecl *D, DeclContext *&DC, 
                                      DeclContext *&LexicalDC, 
                                      DeclarationName &Name, 
                                      SourceLocation &Loc) {
  // Import the context of this declaration.
  DC = Importer.ImportContext(D->getDeclContext());
  if (!DC)
    return true;
  
  LexicalDC = DC;
  if (D->getDeclContext() != D->getLexicalDeclContext()) {
    LexicalDC = Importer.ImportContext(D->getLexicalDeclContext());
    if (!LexicalDC)
      return true;
  }
  
  // Import the name of this declaration.
  Name = Importer.Import(D->getDeclName());
  if (D->getDeclName() && !Name)
    return true;
  
  // Import the location of this declaration.
  Loc = Importer.Import(D->getLocation());
  return false;
}

void ASTNodeImporter::ImportDeclContext(DeclContext *FromDC) {
  for (DeclContext::decl_iterator From = FromDC->decls_begin(),
                               FromEnd = FromDC->decls_end();
       From != FromEnd;
       ++From)
    Importer.Import(*From);
}

bool ASTNodeImporter::IsStructuralMatch(RecordDecl *FromRecord, 
                                        RecordDecl *ToRecord) {
  StructuralEquivalenceContext Ctx(Importer.getFromContext(),
                                   Importer.getToContext(),
                                   Importer.getDiags(),
                                   Importer.getNonEquivalentDecls());
  return Ctx.IsStructurallyEquivalent(FromRecord, ToRecord);
}

bool ASTNodeImporter::IsStructuralMatch(EnumDecl *FromEnum, EnumDecl *ToEnum) {
  StructuralEquivalenceContext Ctx(Importer.getFromContext(),
                                   Importer.getToContext(),
                                   Importer.getDiags(),
                                   Importer.getNonEquivalentDecls());
  return Ctx.IsStructurallyEquivalent(FromEnum, ToEnum);
}

Decl *ASTNodeImporter::VisitDecl(Decl *D) {
  Importer.FromDiag(D->getLocation(), diag::err_unsupported_ast_node)
    << D->getDeclKindName();
  return 0;
}

Decl *ASTNodeImporter::VisitNamespaceDecl(NamespaceDecl *D) {
  // Import the major distinguishing characteristics of this namespace.
  DeclContext *DC, *LexicalDC;
  DeclarationName Name;
  SourceLocation Loc;
  if (ImportDeclParts(D, DC, LexicalDC, Name, Loc))
    return 0;
  
  NamespaceDecl *MergeWithNamespace = 0;
  if (!Name) {
    // This is an anonymous namespace. Adopt an existing anonymous
    // namespace if we can.
    // FIXME: Not testable.
    if (TranslationUnitDecl *TU = dyn_cast<TranslationUnitDecl>(DC))
      MergeWithNamespace = TU->getAnonymousNamespace();
    else
      MergeWithNamespace = cast<NamespaceDecl>(DC)->getAnonymousNamespace();
  } else {
    llvm::SmallVector<NamedDecl *, 4> ConflictingDecls;
    for (DeclContext::lookup_result Lookup = DC->lookup(Name);
         Lookup.first != Lookup.second; 
         ++Lookup.first) {
      if (!(*Lookup.first)->isInIdentifierNamespace(Decl::IDNS_Ordinary))
        continue;
      
      if (NamespaceDecl *FoundNS = dyn_cast<NamespaceDecl>(*Lookup.first)) {
        MergeWithNamespace = FoundNS;
        ConflictingDecls.clear();
        break;
      }
      
      ConflictingDecls.push_back(*Lookup.first);
    }
    
    if (!ConflictingDecls.empty()) {
      Name = Importer.HandleNameConflict(Name, DC, Decl::IDNS_Ordinary,
                                         ConflictingDecls.data(), 
                                         ConflictingDecls.size());
    }
  }
  
  // Create the "to" namespace, if needed.
  NamespaceDecl *ToNamespace = MergeWithNamespace;
  if (!ToNamespace) {
    ToNamespace = NamespaceDecl::Create(Importer.getToContext(), DC, Loc,
                                        Name.getAsIdentifierInfo());
    ToNamespace->setLexicalDeclContext(LexicalDC);
    LexicalDC->addDecl(ToNamespace);
    
    // If this is an anonymous namespace, register it as the anonymous
    // namespace within its context.
    if (!Name) {
      if (TranslationUnitDecl *TU = dyn_cast<TranslationUnitDecl>(DC))
        TU->setAnonymousNamespace(ToNamespace);
      else
        cast<NamespaceDecl>(DC)->setAnonymousNamespace(ToNamespace);
    }
  }
  Importer.Imported(D, ToNamespace);
  
  ImportDeclContext(D);
  
  return ToNamespace;
}

Decl *ASTNodeImporter::VisitTypedefDecl(TypedefDecl *D) {
  // Import the major distinguishing characteristics of this typedef.
  DeclContext *DC, *LexicalDC;
  DeclarationName Name;
  SourceLocation Loc;
  if (ImportDeclParts(D, DC, LexicalDC, Name, Loc))
    return 0;
  
  // If this typedef is not in block scope, determine whether we've
  // seen a typedef with the same name (that we can merge with) or any
  // other entity by that name (which name lookup could conflict with).
  if (!DC->isFunctionOrMethod()) {
    llvm::SmallVector<NamedDecl *, 4> ConflictingDecls;
    unsigned IDNS = Decl::IDNS_Ordinary;
    for (DeclContext::lookup_result Lookup = DC->lookup(Name);
         Lookup.first != Lookup.second; 
         ++Lookup.first) {
      if (!(*Lookup.first)->isInIdentifierNamespace(IDNS))
        continue;
      if (TypedefDecl *FoundTypedef = dyn_cast<TypedefDecl>(*Lookup.first)) {
        if (Importer.IsStructurallyEquivalent(D->getUnderlyingType(),
                                            FoundTypedef->getUnderlyingType()))
          return Importer.Imported(D, FoundTypedef);
      }
      
      ConflictingDecls.push_back(*Lookup.first);
    }
    
    if (!ConflictingDecls.empty()) {
      Name = Importer.HandleNameConflict(Name, DC, IDNS,
                                         ConflictingDecls.data(), 
                                         ConflictingDecls.size());
      if (!Name)
        return 0;
    }
  }
  
  // Import the underlying type of this typedef;
  QualType T = Importer.Import(D->getUnderlyingType());
  if (T.isNull())
    return 0;
  
  // Create the new typedef node.
  TypeSourceInfo *TInfo = Importer.Import(D->getTypeSourceInfo());
  TypedefDecl *ToTypedef = TypedefDecl::Create(Importer.getToContext(), DC,
                                               Loc, Name.getAsIdentifierInfo(),
                                               TInfo);
  ToTypedef->setAccess(D->getAccess());
  ToTypedef->setLexicalDeclContext(LexicalDC);
  Importer.Imported(D, ToTypedef);
  LexicalDC->addDecl(ToTypedef);
  
  return ToTypedef;
}

Decl *ASTNodeImporter::VisitEnumDecl(EnumDecl *D) {
  // Import the major distinguishing characteristics of this enum.
  DeclContext *DC, *LexicalDC;
  DeclarationName Name;
  SourceLocation Loc;
  if (ImportDeclParts(D, DC, LexicalDC, Name, Loc))
    return 0;
  
  // Figure out what enum name we're looking for.
  unsigned IDNS = Decl::IDNS_Tag;
  DeclarationName SearchName = Name;
  if (!SearchName && D->getTypedefForAnonDecl()) {
    SearchName = Importer.Import(D->getTypedefForAnonDecl()->getDeclName());
    IDNS = Decl::IDNS_Ordinary;
  } else if (Importer.getToContext().getLangOptions().CPlusPlus)
    IDNS |= Decl::IDNS_Ordinary;
  
  // We may already have an enum of the same name; try to find and match it.
  if (!DC->isFunctionOrMethod() && SearchName) {
    llvm::SmallVector<NamedDecl *, 4> ConflictingDecls;
    for (DeclContext::lookup_result Lookup = DC->lookup(Name);
         Lookup.first != Lookup.second; 
         ++Lookup.first) {
      if (!(*Lookup.first)->isInIdentifierNamespace(IDNS))
        continue;
      
      Decl *Found = *Lookup.first;
      if (TypedefDecl *Typedef = dyn_cast<TypedefDecl>(Found)) {
        if (const TagType *Tag = Typedef->getUnderlyingType()->getAs<TagType>())
          Found = Tag->getDecl();
      }
      
      if (EnumDecl *FoundEnum = dyn_cast<EnumDecl>(Found)) {
        if (IsStructuralMatch(D, FoundEnum))
          return Importer.Imported(D, FoundEnum);
      }
      
      ConflictingDecls.push_back(*Lookup.first);
    }
    
    if (!ConflictingDecls.empty()) {
      Name = Importer.HandleNameConflict(Name, DC, IDNS,
                                         ConflictingDecls.data(), 
                                         ConflictingDecls.size());
    }
  }
  
  // Create the enum declaration.
  EnumDecl *D2 = EnumDecl::Create(Importer.getToContext(), DC, Loc,
                                      Name.getAsIdentifierInfo(),
                                      Importer.Import(D->getTagKeywordLoc()),
                                      0);
  D2->setAccess(D->getAccess());
  D2->setLexicalDeclContext(LexicalDC);
  Importer.Imported(D, D2);
  LexicalDC->addDecl(D2);

  // Import the integer type.
  QualType ToIntegerType = Importer.Import(D->getIntegerType());
  if (ToIntegerType.isNull())
    return 0;
  D2->setIntegerType(ToIntegerType);
  
  // Import the definition
  if (D->isDefinition()) {
    QualType T = Importer.Import(Importer.getFromContext().getTypeDeclType(D));
    if (T.isNull())
      return 0;

    QualType ToPromotionType = Importer.Import(D->getPromotionType());
    if (ToPromotionType.isNull())
      return 0;
    
    D2->startDefinition();
    ImportDeclContext(D);
    D2->completeDefinition(T, ToPromotionType);
  }
  
  return D2;
}

Decl *ASTNodeImporter::VisitRecordDecl(RecordDecl *D) {
  // If this record has a definition in the translation unit we're coming from,
  // but this particular declaration is not that definition, import the
  // definition and map to that.
  TagDecl *Definition = D->getDefinition();
  if (Definition && Definition != D) {
    Decl *ImportedDef = Importer.Import(Definition);
    if (!ImportedDef)
      return 0;
    
    return Importer.Imported(D, ImportedDef);
  }
  
  // Import the major distinguishing characteristics of this record.
  DeclContext *DC, *LexicalDC;
  DeclarationName Name;
  SourceLocation Loc;
  if (ImportDeclParts(D, DC, LexicalDC, Name, Loc))
    return 0;
      
  // Figure out what structure name we're looking for.
  unsigned IDNS = Decl::IDNS_Tag;
  DeclarationName SearchName = Name;
  if (!SearchName && D->getTypedefForAnonDecl()) {
    SearchName = Importer.Import(D->getTypedefForAnonDecl()->getDeclName());
    IDNS = Decl::IDNS_Ordinary;
  } else if (Importer.getToContext().getLangOptions().CPlusPlus)
    IDNS |= Decl::IDNS_Ordinary;

  // We may already have a record of the same name; try to find and match it.
  RecordDecl *AdoptDecl = 0;
  if (!DC->isFunctionOrMethod() && SearchName) {
    llvm::SmallVector<NamedDecl *, 4> ConflictingDecls;
    for (DeclContext::lookup_result Lookup = DC->lookup(Name);
         Lookup.first != Lookup.second; 
         ++Lookup.first) {
      if (!(*Lookup.first)->isInIdentifierNamespace(IDNS))
        continue;
      
      Decl *Found = *Lookup.first;
      if (TypedefDecl *Typedef = dyn_cast<TypedefDecl>(Found)) {
        if (const TagType *Tag = Typedef->getUnderlyingType()->getAs<TagType>())
          Found = Tag->getDecl();
      }
      
      if (RecordDecl *FoundRecord = dyn_cast<RecordDecl>(Found)) {
        if (RecordDecl *FoundDef = FoundRecord->getDefinition()) {
          if (!D->isDefinition() || IsStructuralMatch(D, FoundDef)) {
            // The record types structurally match, or the "from" translation
            // unit only had a forward declaration anyway; call it the same
            // function.
            // FIXME: For C++, we should also merge methods here.
            return Importer.Imported(D, FoundDef);
          }
        } else {
          // We have a forward declaration of this type, so adopt that forward
          // declaration rather than building a new one.
          AdoptDecl = FoundRecord;
          continue;
        }          
      }
      
      ConflictingDecls.push_back(*Lookup.first);
    }
    
    if (!ConflictingDecls.empty()) {
      Name = Importer.HandleNameConflict(Name, DC, IDNS,
                                         ConflictingDecls.data(), 
                                         ConflictingDecls.size());
    }
  }
  
  // Create the record declaration.
  RecordDecl *D2 = AdoptDecl;
  if (!D2) {
    if (CXXRecordDecl *D1CXX = dyn_cast<CXXRecordDecl>(D)) {
      CXXRecordDecl *D2CXX = CXXRecordDecl::Create(Importer.getToContext(), 
                                                   D->getTagKind(),
                                                   DC, Loc,
                                                   Name.getAsIdentifierInfo(), 
                                        Importer.Import(D->getTagKeywordLoc()));
      D2 = D2CXX;
      D2->setAccess(D->getAccess());
      
      if (D->isDefinition()) {
        // Add base classes.
        llvm::SmallVector<CXXBaseSpecifier *, 4> Bases;
        for (CXXRecordDecl::base_class_iterator 
                  Base1 = D1CXX->bases_begin(),
               FromBaseEnd = D1CXX->bases_end();
             Base1 != FromBaseEnd;
             ++Base1) {
          QualType T = Importer.Import(Base1->getType());
          if (T.isNull())
            return 0;
          
          Bases.push_back(
            new (Importer.getToContext()) 
                  CXXBaseSpecifier(Importer.Import(Base1->getSourceRange()),
                                   Base1->isVirtual(),
                                   Base1->isBaseOfClass(),
                                   Base1->getAccessSpecifierAsWritten(),
                                   T));
        }
        if (!Bases.empty())
          D2CXX->setBases(Bases.data(), Bases.size());
      }
    } else {
      D2 = RecordDecl::Create(Importer.getToContext(), D->getTagKind(),
                                    DC, Loc,
                                    Name.getAsIdentifierInfo(), 
                                    Importer.Import(D->getTagKeywordLoc()));
    }
    D2->setLexicalDeclContext(LexicalDC);
    LexicalDC->addDecl(D2);
  }
  
  Importer.Imported(D, D2);

  if (D->isDefinition()) {
    D2->startDefinition();
    ImportDeclContext(D);
    D2->completeDefinition();
  }
  
  return D2;
}

Decl *ASTNodeImporter::VisitEnumConstantDecl(EnumConstantDecl *D) {
  // Import the major distinguishing characteristics of this enumerator.
  DeclContext *DC, *LexicalDC;
  DeclarationName Name;
  SourceLocation Loc;
  if (ImportDeclParts(D, DC, LexicalDC, Name, Loc))
    return 0;

  QualType T = Importer.Import(D->getType());
  if (T.isNull())
    return 0;

  // Determine whether there are any other declarations with the same name and 
  // in the same context.
  if (!LexicalDC->isFunctionOrMethod()) {
    llvm::SmallVector<NamedDecl *, 4> ConflictingDecls;
    unsigned IDNS = Decl::IDNS_Ordinary;
    for (DeclContext::lookup_result Lookup = DC->lookup(Name);
         Lookup.first != Lookup.second; 
         ++Lookup.first) {
      if (!(*Lookup.first)->isInIdentifierNamespace(IDNS))
        continue;
      
      ConflictingDecls.push_back(*Lookup.first);
    }
    
    if (!ConflictingDecls.empty()) {
      Name = Importer.HandleNameConflict(Name, DC, IDNS,
                                         ConflictingDecls.data(), 
                                         ConflictingDecls.size());
      if (!Name)
        return 0;
    }
  }
  
  Expr *Init = Importer.Import(D->getInitExpr());
  if (D->getInitExpr() && !Init)
    return 0;
  
  EnumConstantDecl *ToEnumerator
    = EnumConstantDecl::Create(Importer.getToContext(), cast<EnumDecl>(DC), Loc, 
                               Name.getAsIdentifierInfo(), T, 
                               Init, D->getInitVal());
  ToEnumerator->setAccess(D->getAccess());
  ToEnumerator->setLexicalDeclContext(LexicalDC);
  Importer.Imported(D, ToEnumerator);
  LexicalDC->addDecl(ToEnumerator);
  return ToEnumerator;
}

Decl *ASTNodeImporter::VisitFunctionDecl(FunctionDecl *D) {
  // Import the major distinguishing characteristics of this function.
  DeclContext *DC, *LexicalDC;
  DeclarationName Name;
  SourceLocation Loc;
  if (ImportDeclParts(D, DC, LexicalDC, Name, Loc))
    return 0;
  
  // Try to find a function in our own ("to") context with the same name, same
  // type, and in the same context as the function we're importing.
  if (!LexicalDC->isFunctionOrMethod()) {
    llvm::SmallVector<NamedDecl *, 4> ConflictingDecls;
    unsigned IDNS = Decl::IDNS_Ordinary;
    for (DeclContext::lookup_result Lookup = DC->lookup(Name);
         Lookup.first != Lookup.second; 
         ++Lookup.first) {
      if (!(*Lookup.first)->isInIdentifierNamespace(IDNS))
        continue;
    
      if (FunctionDecl *FoundFunction = dyn_cast<FunctionDecl>(*Lookup.first)) {
        if (isExternalLinkage(FoundFunction->getLinkage()) &&
            isExternalLinkage(D->getLinkage())) {
          if (Importer.IsStructurallyEquivalent(D->getType(), 
                                                FoundFunction->getType())) {
            // FIXME: Actually try to merge the body and other attributes.
            return Importer.Imported(D, FoundFunction);
          }
        
          // FIXME: Check for overloading more carefully, e.g., by boosting
          // Sema::IsOverload out to the AST library.
          
          // Function overloading is okay in C++.
          if (Importer.getToContext().getLangOptions().CPlusPlus)
            continue;
          
          // Complain about inconsistent function types.
          Importer.ToDiag(Loc, diag::err_odr_function_type_inconsistent)
            << Name << D->getType() << FoundFunction->getType();
          Importer.ToDiag(FoundFunction->getLocation(), 
                          diag::note_odr_value_here)
            << FoundFunction->getType();
        }
      }
      
      ConflictingDecls.push_back(*Lookup.first);
    }
    
    if (!ConflictingDecls.empty()) {
      Name = Importer.HandleNameConflict(Name, DC, IDNS,
                                         ConflictingDecls.data(), 
                                         ConflictingDecls.size());
      if (!Name)
        return 0;
    }    
  }

  // Import the type.
  QualType T = Importer.Import(D->getType());
  if (T.isNull())
    return 0;
  
  // Import the function parameters.
  llvm::SmallVector<ParmVarDecl *, 8> Parameters;
  for (FunctionDecl::param_iterator P = D->param_begin(), PEnd = D->param_end();
       P != PEnd; ++P) {
    ParmVarDecl *ToP = cast_or_null<ParmVarDecl>(Importer.Import(*P));
    if (!ToP)
      return 0;
    
    Parameters.push_back(ToP);
  }
  
  // Create the imported function.
  TypeSourceInfo *TInfo = Importer.Import(D->getTypeSourceInfo());
  FunctionDecl *ToFunction = 0;
  if (CXXConstructorDecl *FromConstructor = dyn_cast<CXXConstructorDecl>(D)) {
    ToFunction = CXXConstructorDecl::Create(Importer.getToContext(),
                                            cast<CXXRecordDecl>(DC),
                                            Loc, Name, T, TInfo, 
                                            FromConstructor->isExplicit(),
                                            D->isInlineSpecified(), 
                                            D->isImplicit());
  } else if (isa<CXXDestructorDecl>(D)) {
    ToFunction = CXXDestructorDecl::Create(Importer.getToContext(),
                                           cast<CXXRecordDecl>(DC),
                                           Loc, Name, T, 
                                           D->isInlineSpecified(),
                                           D->isImplicit());
  } else if (CXXConversionDecl *FromConversion
                                           = dyn_cast<CXXConversionDecl>(D)) {
    ToFunction = CXXConversionDecl::Create(Importer.getToContext(), 
                                           cast<CXXRecordDecl>(DC),
                                           Loc, Name, T, TInfo,
                                           D->isInlineSpecified(),
                                           FromConversion->isExplicit());
  } else {
    ToFunction = FunctionDecl::Create(Importer.getToContext(), DC, Loc, 
                                      Name, T, TInfo, D->getStorageClass(), 
                                      D->isInlineSpecified(),
                                      D->hasWrittenPrototype());
  }
  ToFunction->setAccess(D->getAccess());
  ToFunction->setLexicalDeclContext(LexicalDC);
  Importer.Imported(D, ToFunction);
  LexicalDC->addDecl(ToFunction);

  // Set the parameters.
  for (unsigned I = 0, N = Parameters.size(); I != N; ++I) {
    Parameters[I]->setOwningFunction(ToFunction);
    ToFunction->addDecl(Parameters[I]);
  }
  ToFunction->setParams(Parameters.data(), Parameters.size());

  // FIXME: Other bits to merge?
  
  return ToFunction;
}

Decl *ASTNodeImporter::VisitCXXMethodDecl(CXXMethodDecl *D) {
  return VisitFunctionDecl(D);
}

Decl *ASTNodeImporter::VisitCXXConstructorDecl(CXXConstructorDecl *D) {
  return VisitCXXMethodDecl(D);
}

Decl *ASTNodeImporter::VisitCXXDestructorDecl(CXXDestructorDecl *D) {
  return VisitCXXMethodDecl(D);
}

Decl *ASTNodeImporter::VisitCXXConversionDecl(CXXConversionDecl *D) {
  return VisitCXXMethodDecl(D);
}

Decl *ASTNodeImporter::VisitFieldDecl(FieldDecl *D) {
  // Import the major distinguishing characteristics of a variable.
  DeclContext *DC, *LexicalDC;
  DeclarationName Name;
  SourceLocation Loc;
  if (ImportDeclParts(D, DC, LexicalDC, Name, Loc))
    return 0;
  
  // Import the type.
  QualType T = Importer.Import(D->getType());
  if (T.isNull())
    return 0;
  
  TypeSourceInfo *TInfo = Importer.Import(D->getTypeSourceInfo());
  Expr *BitWidth = Importer.Import(D->getBitWidth());
  if (!BitWidth && D->getBitWidth())
    return 0;
  
  FieldDecl *ToField = FieldDecl::Create(Importer.getToContext(), DC, 
                                         Loc, Name.getAsIdentifierInfo(),
                                         T, TInfo, BitWidth, D->isMutable());
  ToField->setAccess(D->getAccess());
  ToField->setLexicalDeclContext(LexicalDC);
  Importer.Imported(D, ToField);
  LexicalDC->addDecl(ToField);
  return ToField;
}

Decl *ASTNodeImporter::VisitObjCIvarDecl(ObjCIvarDecl *D) {
  // Import the major distinguishing characteristics of an ivar.
  DeclContext *DC, *LexicalDC;
  DeclarationName Name;
  SourceLocation Loc;
  if (ImportDeclParts(D, DC, LexicalDC, Name, Loc))
    return 0;
  
  // Determine whether we've already imported this ivar 
  for (DeclContext::lookup_result Lookup = DC->lookup(Name);
       Lookup.first != Lookup.second; 
       ++Lookup.first) {
    if (ObjCIvarDecl *FoundIvar = dyn_cast<ObjCIvarDecl>(*Lookup.first)) {
      if (Importer.IsStructurallyEquivalent(D->getType(), 
                                            FoundIvar->getType())) {
        Importer.Imported(D, FoundIvar);
        return FoundIvar;
      }

      Importer.ToDiag(Loc, diag::err_odr_ivar_type_inconsistent)
        << Name << D->getType() << FoundIvar->getType();
      Importer.ToDiag(FoundIvar->getLocation(), diag::note_odr_value_here)
        << FoundIvar->getType();
      return 0;
    }
  }

  // Import the type.
  QualType T = Importer.Import(D->getType());
  if (T.isNull())
    return 0;
  
  TypeSourceInfo *TInfo = Importer.Import(D->getTypeSourceInfo());
  Expr *BitWidth = Importer.Import(D->getBitWidth());
  if (!BitWidth && D->getBitWidth())
    return 0;
  
  ObjCIvarDecl *ToIvar = ObjCIvarDecl::Create(Importer.getToContext(), DC, 
                                              Loc, Name.getAsIdentifierInfo(),
                                              T, TInfo, D->getAccessControl(),
                                              BitWidth);
  ToIvar->setLexicalDeclContext(LexicalDC);
  Importer.Imported(D, ToIvar);
  LexicalDC->addDecl(ToIvar);
  return ToIvar;
  
}

Decl *ASTNodeImporter::VisitVarDecl(VarDecl *D) {
  // Import the major distinguishing characteristics of a variable.
  DeclContext *DC, *LexicalDC;
  DeclarationName Name;
  SourceLocation Loc;
  if (ImportDeclParts(D, DC, LexicalDC, Name, Loc))
    return 0;
  
  // Try to find a variable in our own ("to") context with the same name and
  // in the same context as the variable we're importing.
  if (D->isFileVarDecl()) {
    VarDecl *MergeWithVar = 0;
    llvm::SmallVector<NamedDecl *, 4> ConflictingDecls;
    unsigned IDNS = Decl::IDNS_Ordinary;
    for (DeclContext::lookup_result Lookup = DC->lookup(Name);
         Lookup.first != Lookup.second; 
         ++Lookup.first) {
      if (!(*Lookup.first)->isInIdentifierNamespace(IDNS))
        continue;
      
      if (VarDecl *FoundVar = dyn_cast<VarDecl>(*Lookup.first)) {
        // We have found a variable that we may need to merge with. Check it.
        if (isExternalLinkage(FoundVar->getLinkage()) &&
            isExternalLinkage(D->getLinkage())) {
          if (Importer.IsStructurallyEquivalent(D->getType(), 
                                                FoundVar->getType())) {
            MergeWithVar = FoundVar;
            break;
          }

          const ArrayType *FoundArray
            = Importer.getToContext().getAsArrayType(FoundVar->getType());
          const ArrayType *TArray
            = Importer.getToContext().getAsArrayType(D->getType());
          if (FoundArray && TArray) {
            if (isa<IncompleteArrayType>(FoundArray) &&
                isa<ConstantArrayType>(TArray)) {
              // Import the type.
              QualType T = Importer.Import(D->getType());
              if (T.isNull())
                return 0;
              
              FoundVar->setType(T);
              MergeWithVar = FoundVar;
              break;
            } else if (isa<IncompleteArrayType>(TArray) &&
                       isa<ConstantArrayType>(FoundArray)) {
              MergeWithVar = FoundVar;
              break;
            }
          }

          Importer.ToDiag(Loc, diag::err_odr_variable_type_inconsistent)
            << Name << D->getType() << FoundVar->getType();
          Importer.ToDiag(FoundVar->getLocation(), diag::note_odr_value_here)
            << FoundVar->getType();
        }
      }
      
      ConflictingDecls.push_back(*Lookup.first);
    }

    if (MergeWithVar) {
      // An equivalent variable with external linkage has been found. Link 
      // the two declarations, then merge them.
      Importer.Imported(D, MergeWithVar);
      
      if (VarDecl *DDef = D->getDefinition()) {
        if (VarDecl *ExistingDef = MergeWithVar->getDefinition()) {
          Importer.ToDiag(ExistingDef->getLocation(), 
                          diag::err_odr_variable_multiple_def)
            << Name;
          Importer.FromDiag(DDef->getLocation(), diag::note_odr_defined_here);
        } else {
          Expr *Init = Importer.Import(DDef->getInit());
          MergeWithVar->setInit(Init);
        }
      }
      
      return MergeWithVar;
    }
    
    if (!ConflictingDecls.empty()) {
      Name = Importer.HandleNameConflict(Name, DC, IDNS,
                                         ConflictingDecls.data(), 
                                         ConflictingDecls.size());
      if (!Name)
        return 0;
    }
  }
    
  // Import the type.
  QualType T = Importer.Import(D->getType());
  if (T.isNull())
    return 0;
  
  // Create the imported variable.
  TypeSourceInfo *TInfo = Importer.Import(D->getTypeSourceInfo());
  VarDecl *ToVar = VarDecl::Create(Importer.getToContext(), DC, Loc, 
                                   Name.getAsIdentifierInfo(), T, TInfo,
                                   D->getStorageClass());
  ToVar->setAccess(D->getAccess());
  ToVar->setLexicalDeclContext(LexicalDC);
  Importer.Imported(D, ToVar);
  LexicalDC->addDecl(ToVar);

  // Merge the initializer.
  // FIXME: Can we really import any initializer? Alternatively, we could force
  // ourselves to import every declaration of a variable and then only use
  // getInit() here.
  ToVar->setInit(Importer.Import(const_cast<Expr *>(D->getAnyInitializer())));

  // FIXME: Other bits to merge?
  
  return ToVar;
}

Decl *ASTNodeImporter::VisitImplicitParamDecl(ImplicitParamDecl *D) {
  // Parameters are created in the translation unit's context, then moved
  // into the function declaration's context afterward.
  DeclContext *DC = Importer.getToContext().getTranslationUnitDecl();
  
  // Import the name of this declaration.
  DeclarationName Name = Importer.Import(D->getDeclName());
  if (D->getDeclName() && !Name)
    return 0;
  
  // Import the location of this declaration.
  SourceLocation Loc = Importer.Import(D->getLocation());
  
  // Import the parameter's type.
  QualType T = Importer.Import(D->getType());
  if (T.isNull())
    return 0;
  
  // Create the imported parameter.
  ImplicitParamDecl *ToParm
    = ImplicitParamDecl::Create(Importer.getToContext(), DC,
                                Loc, Name.getAsIdentifierInfo(),
                                T);
  return Importer.Imported(D, ToParm);
}

Decl *ASTNodeImporter::VisitParmVarDecl(ParmVarDecl *D) {
  // Parameters are created in the translation unit's context, then moved
  // into the function declaration's context afterward.
  DeclContext *DC = Importer.getToContext().getTranslationUnitDecl();
  
  // Import the name of this declaration.
  DeclarationName Name = Importer.Import(D->getDeclName());
  if (D->getDeclName() && !Name)
    return 0;
  
  // Import the location of this declaration.
  SourceLocation Loc = Importer.Import(D->getLocation());
  
  // Import the parameter's type.
  QualType T = Importer.Import(D->getType());
  if (T.isNull())
    return 0;
  
  // Create the imported parameter.
  TypeSourceInfo *TInfo = Importer.Import(D->getTypeSourceInfo());
  ParmVarDecl *ToParm = ParmVarDecl::Create(Importer.getToContext(), DC,
                                            Loc, Name.getAsIdentifierInfo(),
                                            T, TInfo, D->getStorageClass(),
                                            /*FIXME: Default argument*/ 0);
  return Importer.Imported(D, ToParm);
}

Decl *ASTNodeImporter::VisitObjCMethodDecl(ObjCMethodDecl *D) {
  // Import the major distinguishing characteristics of a method.
  DeclContext *DC, *LexicalDC;
  DeclarationName Name;
  SourceLocation Loc;
  if (ImportDeclParts(D, DC, LexicalDC, Name, Loc))
    return 0;
  
  for (DeclContext::lookup_result Lookup = DC->lookup(Name);
       Lookup.first != Lookup.second; 
       ++Lookup.first) {
    if (ObjCMethodDecl *FoundMethod = dyn_cast<ObjCMethodDecl>(*Lookup.first)) {
      if (FoundMethod->isInstanceMethod() != D->isInstanceMethod())
        continue;

      // Check return types.
      if (!Importer.IsStructurallyEquivalent(D->getResultType(),
                                             FoundMethod->getResultType())) {
        Importer.ToDiag(Loc, diag::err_odr_objc_method_result_type_inconsistent)
          << D->isInstanceMethod() << Name
          << D->getResultType() << FoundMethod->getResultType();
        Importer.ToDiag(FoundMethod->getLocation(), 
                        diag::note_odr_objc_method_here)
          << D->isInstanceMethod() << Name;
        return 0;
      }

      // Check the number of parameters.
      if (D->param_size() != FoundMethod->param_size()) {
        Importer.ToDiag(Loc, diag::err_odr_objc_method_num_params_inconsistent)
          << D->isInstanceMethod() << Name
          << D->param_size() << FoundMethod->param_size();
        Importer.ToDiag(FoundMethod->getLocation(), 
                        diag::note_odr_objc_method_here)
          << D->isInstanceMethod() << Name;
        return 0;
      }

      // Check parameter types.
      for (ObjCMethodDecl::param_iterator P = D->param_begin(), 
             PEnd = D->param_end(), FoundP = FoundMethod->param_begin();
           P != PEnd; ++P, ++FoundP) {
        if (!Importer.IsStructurallyEquivalent((*P)->getType(), 
                                               (*FoundP)->getType())) {
          Importer.FromDiag((*P)->getLocation(), 
                            diag::err_odr_objc_method_param_type_inconsistent)
            << D->isInstanceMethod() << Name
            << (*P)->getType() << (*FoundP)->getType();
          Importer.ToDiag((*FoundP)->getLocation(), diag::note_odr_value_here)
            << (*FoundP)->getType();
          return 0;
        }
      }

      // Check variadic/non-variadic.
      // Check the number of parameters.
      if (D->isVariadic() != FoundMethod->isVariadic()) {
        Importer.ToDiag(Loc, diag::err_odr_objc_method_variadic_inconsistent)
          << D->isInstanceMethod() << Name;
        Importer.ToDiag(FoundMethod->getLocation(), 
                        diag::note_odr_objc_method_here)
          << D->isInstanceMethod() << Name;
        return 0;
      }

      // FIXME: Any other bits we need to merge?
      return Importer.Imported(D, FoundMethod);
    }
  }

  // Import the result type.
  QualType ResultTy = Importer.Import(D->getResultType());
  if (ResultTy.isNull())
    return 0;

  TypeSourceInfo *ResultTInfo = Importer.Import(D->getResultTypeSourceInfo());

  ObjCMethodDecl *ToMethod
    = ObjCMethodDecl::Create(Importer.getToContext(),
                             Loc,
                             Importer.Import(D->getLocEnd()),
                             Name.getObjCSelector(),
                             ResultTy, ResultTInfo, DC,
                             D->isInstanceMethod(),
                             D->isVariadic(),
                             D->isSynthesized(),
                             D->getImplementationControl());

  // FIXME: When we decide to merge method definitions, we'll need to
  // deal with implicit parameters.

  // Import the parameters
  llvm::SmallVector<ParmVarDecl *, 5> ToParams;
  for (ObjCMethodDecl::param_iterator FromP = D->param_begin(),
                                   FromPEnd = D->param_end();
       FromP != FromPEnd; 
       ++FromP) {
    ParmVarDecl *ToP = cast_or_null<ParmVarDecl>(Importer.Import(*FromP));
    if (!ToP)
      return 0;
    
    ToParams.push_back(ToP);
  }
  
  // Set the parameters.
  for (unsigned I = 0, N = ToParams.size(); I != N; ++I) {
    ToParams[I]->setOwningFunction(ToMethod);
    ToMethod->addDecl(ToParams[I]);
  }
  ToMethod->setMethodParams(Importer.getToContext(), 
                            ToParams.data(), ToParams.size());

  ToMethod->setLexicalDeclContext(LexicalDC);
  Importer.Imported(D, ToMethod);
  LexicalDC->addDecl(ToMethod);
  return ToMethod;
}

Decl *ASTNodeImporter::VisitObjCCategoryDecl(ObjCCategoryDecl *D) {
  // Import the major distinguishing characteristics of a category.
  DeclContext *DC, *LexicalDC;
  DeclarationName Name;
  SourceLocation Loc;
  if (ImportDeclParts(D, DC, LexicalDC, Name, Loc))
    return 0;
  
  ObjCInterfaceDecl *ToInterface
    = cast_or_null<ObjCInterfaceDecl>(Importer.Import(D->getClassInterface()));
  if (!ToInterface)
    return 0;
  
  // Determine if we've already encountered this category.
  ObjCCategoryDecl *MergeWithCategory
    = ToInterface->FindCategoryDeclaration(Name.getAsIdentifierInfo());
  ObjCCategoryDecl *ToCategory = MergeWithCategory;
  if (!ToCategory) {
    ToCategory = ObjCCategoryDecl::Create(Importer.getToContext(), DC,
                                          Importer.Import(D->getAtLoc()),
                                          Loc, 
                                       Importer.Import(D->getCategoryNameLoc()), 
                                          Name.getAsIdentifierInfo());
    ToCategory->setLexicalDeclContext(LexicalDC);
    LexicalDC->addDecl(ToCategory);
    Importer.Imported(D, ToCategory);
    
    // Link this category into its class's category list.
    ToCategory->setClassInterface(ToInterface);
    ToCategory->insertNextClassCategory();
    
    // Import protocols
    llvm::SmallVector<ObjCProtocolDecl *, 4> Protocols;
    llvm::SmallVector<SourceLocation, 4> ProtocolLocs;
    ObjCCategoryDecl::protocol_loc_iterator FromProtoLoc
      = D->protocol_loc_begin();
    for (ObjCCategoryDecl::protocol_iterator FromProto = D->protocol_begin(),
                                          FromProtoEnd = D->protocol_end();
         FromProto != FromProtoEnd;
         ++FromProto, ++FromProtoLoc) {
      ObjCProtocolDecl *ToProto
        = cast_or_null<ObjCProtocolDecl>(Importer.Import(*FromProto));
      if (!ToProto)
        return 0;
      Protocols.push_back(ToProto);
      ProtocolLocs.push_back(Importer.Import(*FromProtoLoc));
    }
    
    // FIXME: If we're merging, make sure that the protocol list is the same.
    ToCategory->setProtocolList(Protocols.data(), Protocols.size(),
                                ProtocolLocs.data(), Importer.getToContext());
    
  } else {
    Importer.Imported(D, ToCategory);
  }
  
  // Import all of the members of this category.
  ImportDeclContext(D);
 
  // If we have an implementation, import it as well.
  if (D->getImplementation()) {
    ObjCCategoryImplDecl *Impl
      = cast<ObjCCategoryImplDecl>(Importer.Import(D->getImplementation()));
    if (!Impl)
      return 0;
    
    ToCategory->setImplementation(Impl);
  }
  
  return ToCategory;
}

Decl *ASTNodeImporter::VisitObjCProtocolDecl(ObjCProtocolDecl *D) {
  // Import the major distinguishing characteristics of a protocol.
  DeclContext *DC, *LexicalDC;
  DeclarationName Name;
  SourceLocation Loc;
  if (ImportDeclParts(D, DC, LexicalDC, Name, Loc))
    return 0;

  ObjCProtocolDecl *MergeWithProtocol = 0;
  for (DeclContext::lookup_result Lookup = DC->lookup(Name);
       Lookup.first != Lookup.second; 
       ++Lookup.first) {
    if (!(*Lookup.first)->isInIdentifierNamespace(Decl::IDNS_ObjCProtocol))
      continue;
    
    if ((MergeWithProtocol = dyn_cast<ObjCProtocolDecl>(*Lookup.first)))
      break;
  }
  
  ObjCProtocolDecl *ToProto = MergeWithProtocol;
  if (!ToProto || ToProto->isForwardDecl()) {
    if (!ToProto) {
      ToProto = ObjCProtocolDecl::Create(Importer.getToContext(), DC, Loc,
                                         Name.getAsIdentifierInfo());
      ToProto->setForwardDecl(D->isForwardDecl());
      ToProto->setLexicalDeclContext(LexicalDC);
      LexicalDC->addDecl(ToProto);
    }
    Importer.Imported(D, ToProto);

    // Import protocols
    llvm::SmallVector<ObjCProtocolDecl *, 4> Protocols;
    llvm::SmallVector<SourceLocation, 4> ProtocolLocs;
    ObjCProtocolDecl::protocol_loc_iterator 
      FromProtoLoc = D->protocol_loc_begin();
    for (ObjCProtocolDecl::protocol_iterator FromProto = D->protocol_begin(),
                                          FromProtoEnd = D->protocol_end();
       FromProto != FromProtoEnd;
       ++FromProto, ++FromProtoLoc) {
      ObjCProtocolDecl *ToProto
        = cast_or_null<ObjCProtocolDecl>(Importer.Import(*FromProto));
      if (!ToProto)
        return 0;
      Protocols.push_back(ToProto);
      ProtocolLocs.push_back(Importer.Import(*FromProtoLoc));
    }
    
    // FIXME: If we're merging, make sure that the protocol list is the same.
    ToProto->setProtocolList(Protocols.data(), Protocols.size(),
                             ProtocolLocs.data(), Importer.getToContext());
  } else {
    Importer.Imported(D, ToProto);
  }

  // Import all of the members of this protocol.
  ImportDeclContext(D);

  return ToProto;
}

Decl *ASTNodeImporter::VisitObjCInterfaceDecl(ObjCInterfaceDecl *D) {
  // Import the major distinguishing characteristics of an @interface.
  DeclContext *DC, *LexicalDC;
  DeclarationName Name;
  SourceLocation Loc;
  if (ImportDeclParts(D, DC, LexicalDC, Name, Loc))
    return 0;

  ObjCInterfaceDecl *MergeWithIface = 0;
  for (DeclContext::lookup_result Lookup = DC->lookup(Name);
       Lookup.first != Lookup.second; 
       ++Lookup.first) {
    if (!(*Lookup.first)->isInIdentifierNamespace(Decl::IDNS_Ordinary))
      continue;
    
    if ((MergeWithIface = dyn_cast<ObjCInterfaceDecl>(*Lookup.first)))
      break;
  }
  
  ObjCInterfaceDecl *ToIface = MergeWithIface;
  if (!ToIface || ToIface->isForwardDecl()) {
    if (!ToIface) {
      ToIface = ObjCInterfaceDecl::Create(Importer.getToContext(),
                                          DC, Loc,
                                          Name.getAsIdentifierInfo(),
                                          Importer.Import(D->getClassLoc()),
                                          D->isForwardDecl(),
                                          D->isImplicitInterfaceDecl());
      ToIface->setForwardDecl(D->isForwardDecl());
      ToIface->setLexicalDeclContext(LexicalDC);
      LexicalDC->addDecl(ToIface);
    }
    Importer.Imported(D, ToIface);

    if (D->getSuperClass()) {
      ObjCInterfaceDecl *Super
        = cast_or_null<ObjCInterfaceDecl>(Importer.Import(D->getSuperClass()));
      if (!Super)
        return 0;
      
      ToIface->setSuperClass(Super);
      ToIface->setSuperClassLoc(Importer.Import(D->getSuperClassLoc()));
    }
    
    // Import protocols
    llvm::SmallVector<ObjCProtocolDecl *, 4> Protocols;
    llvm::SmallVector<SourceLocation, 4> ProtocolLocs;
    ObjCInterfaceDecl::protocol_loc_iterator 
      FromProtoLoc = D->protocol_loc_begin();
    for (ObjCInterfaceDecl::protocol_iterator FromProto = D->protocol_begin(),
                                           FromProtoEnd = D->protocol_end();
       FromProto != FromProtoEnd;
       ++FromProto, ++FromProtoLoc) {
      ObjCProtocolDecl *ToProto
        = cast_or_null<ObjCProtocolDecl>(Importer.Import(*FromProto));
      if (!ToProto)
        return 0;
      Protocols.push_back(ToProto);
      ProtocolLocs.push_back(Importer.Import(*FromProtoLoc));
    }
    
    // FIXME: If we're merging, make sure that the protocol list is the same.
    ToIface->setProtocolList(Protocols.data(), Protocols.size(),
                             ProtocolLocs.data(), Importer.getToContext());
    
    // Import @end range
    ToIface->setAtEndRange(Importer.Import(D->getAtEndRange()));
  } else {
    Importer.Imported(D, ToIface);

    // Check for consistency of superclasses.
    DeclarationName FromSuperName, ToSuperName;
    if (D->getSuperClass())
      FromSuperName = Importer.Import(D->getSuperClass()->getDeclName());
    if (ToIface->getSuperClass())
      ToSuperName = ToIface->getSuperClass()->getDeclName();
    if (FromSuperName != ToSuperName) {
      Importer.ToDiag(ToIface->getLocation(), 
                      diag::err_odr_objc_superclass_inconsistent)
        << ToIface->getDeclName();
      if (ToIface->getSuperClass())
        Importer.ToDiag(ToIface->getSuperClassLoc(), 
                        diag::note_odr_objc_superclass)
          << ToIface->getSuperClass()->getDeclName();
      else
        Importer.ToDiag(ToIface->getLocation(), 
                        diag::note_odr_objc_missing_superclass);
      if (D->getSuperClass())
        Importer.FromDiag(D->getSuperClassLoc(), 
                          diag::note_odr_objc_superclass)
          << D->getSuperClass()->getDeclName();
      else
        Importer.FromDiag(D->getLocation(), 
                          diag::note_odr_objc_missing_superclass);
      return 0;
    }
  }
  
  // Import categories. When the categories themselves are imported, they'll
  // hook themselves into this interface.
  for (ObjCCategoryDecl *FromCat = D->getCategoryList(); FromCat;
       FromCat = FromCat->getNextClassCategory())
    Importer.Import(FromCat);
  
  // Import all of the members of this class.
  ImportDeclContext(D);
  
  // If we have an @implementation, import it as well.
  if (D->getImplementation()) {
    ObjCImplementationDecl *Impl
      = cast<ObjCImplementationDecl>(Importer.Import(D->getImplementation()));
    if (!Impl)
      return 0;
    
    ToIface->setImplementation(Impl);
  }
  
  return ToIface;
}

Decl *ASTNodeImporter::VisitObjCPropertyDecl(ObjCPropertyDecl *D) {
  // Import the major distinguishing characteristics of an @property.
  DeclContext *DC, *LexicalDC;
  DeclarationName Name;
  SourceLocation Loc;
  if (ImportDeclParts(D, DC, LexicalDC, Name, Loc))
    return 0;

  // Check whether we have already imported this property.
  for (DeclContext::lookup_result Lookup = DC->lookup(Name);
       Lookup.first != Lookup.second; 
       ++Lookup.first) {
    if (ObjCPropertyDecl *FoundProp
                                = dyn_cast<ObjCPropertyDecl>(*Lookup.first)) {
      // Check property types.
      if (!Importer.IsStructurallyEquivalent(D->getType(), 
                                             FoundProp->getType())) {
        Importer.ToDiag(Loc, diag::err_odr_objc_property_type_inconsistent)
          << Name << D->getType() << FoundProp->getType();
        Importer.ToDiag(FoundProp->getLocation(), diag::note_odr_value_here)
          << FoundProp->getType();
        return 0;
      }

      // FIXME: Check property attributes, getters, setters, etc.?

      // Consider these properties to be equivalent.
      Importer.Imported(D, FoundProp);
      return FoundProp;
    }
  }

  // Import the type.
  QualType T = Importer.Import(D->getType());
  if (T.isNull())
    return 0;

  // Create the new property.
  ObjCPropertyDecl *ToProperty
    = ObjCPropertyDecl::Create(Importer.getToContext(), DC, Loc,
                               Name.getAsIdentifierInfo(), 
                               Importer.Import(D->getAtLoc()),
                               T,
                               D->getPropertyImplementation());
  Importer.Imported(D, ToProperty);
  ToProperty->setLexicalDeclContext(LexicalDC);
  LexicalDC->addDecl(ToProperty);

  ToProperty->setPropertyAttributes(D->getPropertyAttributes());
  ToProperty->setGetterName(Importer.Import(D->getGetterName()));
  ToProperty->setSetterName(Importer.Import(D->getSetterName()));
  ToProperty->setGetterMethodDecl(
     cast_or_null<ObjCMethodDecl>(Importer.Import(D->getGetterMethodDecl())));
  ToProperty->setSetterMethodDecl(
     cast_or_null<ObjCMethodDecl>(Importer.Import(D->getSetterMethodDecl())));
  ToProperty->setPropertyIvarDecl(
       cast_or_null<ObjCIvarDecl>(Importer.Import(D->getPropertyIvarDecl())));
  return ToProperty;
}

Decl *
ASTNodeImporter::VisitObjCForwardProtocolDecl(ObjCForwardProtocolDecl *D) {
  // Import the context of this declaration.
  DeclContext *DC = Importer.ImportContext(D->getDeclContext());
  if (!DC)
    return 0;
  
  DeclContext *LexicalDC = DC;
  if (D->getDeclContext() != D->getLexicalDeclContext()) {
    LexicalDC = Importer.ImportContext(D->getLexicalDeclContext());
    if (!LexicalDC)
      return 0;
  }
  
  // Import the location of this declaration.
  SourceLocation Loc = Importer.Import(D->getLocation());
  
  llvm::SmallVector<ObjCProtocolDecl *, 4> Protocols;
  llvm::SmallVector<SourceLocation, 4> Locations;
  ObjCForwardProtocolDecl::protocol_loc_iterator FromProtoLoc
    = D->protocol_loc_begin();
  for (ObjCForwardProtocolDecl::protocol_iterator FromProto
         = D->protocol_begin(), FromProtoEnd = D->protocol_end();
       FromProto != FromProtoEnd; 
       ++FromProto, ++FromProtoLoc) {
    ObjCProtocolDecl *ToProto
      = cast_or_null<ObjCProtocolDecl>(Importer.Import(*FromProto));
    if (!ToProto)
      continue;
    
    Protocols.push_back(ToProto);
    Locations.push_back(Importer.Import(*FromProtoLoc));
  }
  
  ObjCForwardProtocolDecl *ToForward
    = ObjCForwardProtocolDecl::Create(Importer.getToContext(), DC, Loc, 
                                      Protocols.data(), Protocols.size(),
                                      Locations.data());
  ToForward->setLexicalDeclContext(LexicalDC);
  LexicalDC->addDecl(ToForward);
  Importer.Imported(D, ToForward);
  return ToForward;
}

Decl *ASTNodeImporter::VisitObjCClassDecl(ObjCClassDecl *D) {
  // Import the context of this declaration.
  DeclContext *DC = Importer.ImportContext(D->getDeclContext());
  if (!DC)
    return 0;
  
  DeclContext *LexicalDC = DC;
  if (D->getDeclContext() != D->getLexicalDeclContext()) {
    LexicalDC = Importer.ImportContext(D->getLexicalDeclContext());
    if (!LexicalDC)
      return 0;
  }
  
  // Import the location of this declaration.
  SourceLocation Loc = Importer.Import(D->getLocation());

  llvm::SmallVector<ObjCInterfaceDecl *, 4> Interfaces;
  llvm::SmallVector<SourceLocation, 4> Locations;
  for (ObjCClassDecl::iterator From = D->begin(), FromEnd = D->end();
       From != FromEnd; ++From) {
    ObjCInterfaceDecl *ToIface
      = cast_or_null<ObjCInterfaceDecl>(Importer.Import(From->getInterface()));
    if (!ToIface)
      continue;
    
    Interfaces.push_back(ToIface);
    Locations.push_back(Importer.Import(From->getLocation()));
  }
  
  ObjCClassDecl *ToClass = ObjCClassDecl::Create(Importer.getToContext(), DC,
                                                 Loc, 
                                                 Interfaces.data(),
                                                 Locations.data(),
                                                 Interfaces.size());
  ToClass->setLexicalDeclContext(LexicalDC);
  LexicalDC->addDecl(ToClass);
  Importer.Imported(D, ToClass);
  return ToClass;
}

//----------------------------------------------------------------------------
// Import Statements
//----------------------------------------------------------------------------

Stmt *ASTNodeImporter::VisitStmt(Stmt *S) {
  Importer.FromDiag(S->getLocStart(), diag::err_unsupported_ast_node)
    << S->getStmtClassName();
  return 0;
}

//----------------------------------------------------------------------------
// Import Expressions
//----------------------------------------------------------------------------
Expr *ASTNodeImporter::VisitExpr(Expr *E) {
  Importer.FromDiag(E->getLocStart(), diag::err_unsupported_ast_node)
    << E->getStmtClassName();
  return 0;
}

Expr *ASTNodeImporter::VisitDeclRefExpr(DeclRefExpr *E) {
  NestedNameSpecifier *Qualifier = 0;
  if (E->getQualifier()) {
    Qualifier = Importer.Import(E->getQualifier());
    if (!E->getQualifier())
      return 0;
  }
  
  ValueDecl *ToD = cast_or_null<ValueDecl>(Importer.Import(E->getDecl()));
  if (!ToD)
    return 0;
  
  QualType T = Importer.Import(E->getType());
  if (T.isNull())
    return 0;
  
  return DeclRefExpr::Create(Importer.getToContext(), Qualifier,
                             Importer.Import(E->getQualifierRange()),
                             ToD,
                             Importer.Import(E->getLocation()),
                             T,
                             /*FIXME:TemplateArgs=*/0);
}

Expr *ASTNodeImporter::VisitIntegerLiteral(IntegerLiteral *E) {
  QualType T = Importer.Import(E->getType());
  if (T.isNull())
    return 0;

  return new (Importer.getToContext()) 
    IntegerLiteral(E->getValue(), T, Importer.Import(E->getLocation()));
}

Expr *ASTNodeImporter::VisitCharacterLiteral(CharacterLiteral *E) {
  QualType T = Importer.Import(E->getType());
  if (T.isNull())
    return 0;
  
  return new (Importer.getToContext()) CharacterLiteral(E->getValue(), 
                                                        E->isWide(), T,
                                          Importer.Import(E->getLocation()));
}

Expr *ASTNodeImporter::VisitParenExpr(ParenExpr *E) {
  Expr *SubExpr = Importer.Import(E->getSubExpr());
  if (!SubExpr)
    return 0;
  
  return new (Importer.getToContext()) 
                                  ParenExpr(Importer.Import(E->getLParen()),
                                            Importer.Import(E->getRParen()),
                                            SubExpr);
}

Expr *ASTNodeImporter::VisitUnaryOperator(UnaryOperator *E) {
  QualType T = Importer.Import(E->getType());
  if (T.isNull())
    return 0;

  Expr *SubExpr = Importer.Import(E->getSubExpr());
  if (!SubExpr)
    return 0;
  
  return new (Importer.getToContext()) UnaryOperator(SubExpr, E->getOpcode(),
                                                     T,
                                         Importer.Import(E->getOperatorLoc()));                                        
}

Expr *ASTNodeImporter::VisitSizeOfAlignOfExpr(SizeOfAlignOfExpr *E) {
  QualType ResultType = Importer.Import(E->getType());
  
  if (E->isArgumentType()) {
    TypeSourceInfo *TInfo = Importer.Import(E->getArgumentTypeInfo());
    if (!TInfo)
      return 0;
    
    return new (Importer.getToContext()) SizeOfAlignOfExpr(E->isSizeOf(),
                                                           TInfo, ResultType,
                                           Importer.Import(E->getOperatorLoc()),
                                           Importer.Import(E->getRParenLoc()));
  }
  
  Expr *SubExpr = Importer.Import(E->getArgumentExpr());
  if (!SubExpr)
    return 0;
  
  return new (Importer.getToContext()) SizeOfAlignOfExpr(E->isSizeOf(),
                                                         SubExpr, ResultType,
                                          Importer.Import(E->getOperatorLoc()),
                                          Importer.Import(E->getRParenLoc()));
}

Expr *ASTNodeImporter::VisitBinaryOperator(BinaryOperator *E) {
  QualType T = Importer.Import(E->getType());
  if (T.isNull())
    return 0;

  Expr *LHS = Importer.Import(E->getLHS());
  if (!LHS)
    return 0;
  
  Expr *RHS = Importer.Import(E->getRHS());
  if (!RHS)
    return 0;
  
  return new (Importer.getToContext()) BinaryOperator(LHS, RHS, E->getOpcode(),
                                                      T,
                                          Importer.Import(E->getOperatorLoc()));
}

Expr *ASTNodeImporter::VisitCompoundAssignOperator(CompoundAssignOperator *E) {
  QualType T = Importer.Import(E->getType());
  if (T.isNull())
    return 0;
  
  QualType CompLHSType = Importer.Import(E->getComputationLHSType());
  if (CompLHSType.isNull())
    return 0;
  
  QualType CompResultType = Importer.Import(E->getComputationResultType());
  if (CompResultType.isNull())
    return 0;
  
  Expr *LHS = Importer.Import(E->getLHS());
  if (!LHS)
    return 0;
  
  Expr *RHS = Importer.Import(E->getRHS());
  if (!RHS)
    return 0;
  
  return new (Importer.getToContext()) 
                        CompoundAssignOperator(LHS, RHS, E->getOpcode(),
                                               T, CompLHSType, CompResultType,
                                          Importer.Import(E->getOperatorLoc()));
}

Expr *ASTNodeImporter::VisitImplicitCastExpr(ImplicitCastExpr *E) {
  QualType T = Importer.Import(E->getType());
  if (T.isNull())
    return 0;

  Expr *SubExpr = Importer.Import(E->getSubExpr());
  if (!SubExpr)
    return 0;
  
  return new (Importer.getToContext()) ImplicitCastExpr(T, E->getCastKind(),
                                                        SubExpr, 
                                                        E->isLvalueCast());
}

Expr *ASTNodeImporter::VisitCStyleCastExpr(CStyleCastExpr *E) {
  QualType T = Importer.Import(E->getType());
  if (T.isNull())
    return 0;
  
  Expr *SubExpr = Importer.Import(E->getSubExpr());
  if (!SubExpr)
    return 0;

  TypeSourceInfo *TInfo = Importer.Import(E->getTypeInfoAsWritten());
  if (!TInfo && E->getTypeInfoAsWritten())
    return 0;
  
  return new (Importer.getToContext()) CStyleCastExpr(T, E->getCastKind(),
                                                      SubExpr, TInfo,
                                            Importer.Import(E->getLParenLoc()),
                                            Importer.Import(E->getRParenLoc()));
}

ASTImporter::ASTImporter(Diagnostic &Diags,
                         ASTContext &ToContext, FileManager &ToFileManager,
                         ASTContext &FromContext, FileManager &FromFileManager)
  : ToContext(ToContext), FromContext(FromContext),
    ToFileManager(ToFileManager), FromFileManager(FromFileManager),
    Diags(Diags) {
  ImportedDecls[FromContext.getTranslationUnitDecl()]
    = ToContext.getTranslationUnitDecl();
}

ASTImporter::~ASTImporter() { }

QualType ASTImporter::Import(QualType FromT) {
  if (FromT.isNull())
    return QualType();
  
  // Check whether we've already imported this type.  
  llvm::DenseMap<Type *, Type *>::iterator Pos
    = ImportedTypes.find(FromT.getTypePtr());
  if (Pos != ImportedTypes.end())
    return ToContext.getQualifiedType(Pos->second, FromT.getQualifiers());
  
  // Import the type
  ASTNodeImporter Importer(*this);
  QualType ToT = Importer.Visit(FromT.getTypePtr());
  if (ToT.isNull())
    return ToT;
  
  // Record the imported type.
  ImportedTypes[FromT.getTypePtr()] = ToT.getTypePtr();
  
  return ToContext.getQualifiedType(ToT, FromT.getQualifiers());
}

TypeSourceInfo *ASTImporter::Import(TypeSourceInfo *FromTSI) {
  if (!FromTSI)
    return FromTSI;

  // FIXME: For now we just create a "trivial" type source info based
  // on the type and a seingle location. Implement a real version of
  // this.
  QualType T = Import(FromTSI->getType());
  if (T.isNull())
    return 0;

  return ToContext.getTrivialTypeSourceInfo(T, 
                        FromTSI->getTypeLoc().getFullSourceRange().getBegin());
}

Decl *ASTImporter::Import(Decl *FromD) {
  if (!FromD)
    return 0;

  // Check whether we've already imported this declaration.  
  llvm::DenseMap<Decl *, Decl *>::iterator Pos = ImportedDecls.find(FromD);
  if (Pos != ImportedDecls.end())
    return Pos->second;
  
  // Import the type
  ASTNodeImporter Importer(*this);
  Decl *ToD = Importer.Visit(FromD);
  if (!ToD)
    return 0;
  
  // Record the imported declaration.
  ImportedDecls[FromD] = ToD;
  
  if (TagDecl *FromTag = dyn_cast<TagDecl>(FromD)) {
    // Keep track of anonymous tags that have an associated typedef.
    if (FromTag->getTypedefForAnonDecl())
      AnonTagsWithPendingTypedefs.push_back(FromTag);
  } else if (TypedefDecl *FromTypedef = dyn_cast<TypedefDecl>(FromD)) {
    // When we've finished transforming a typedef, see whether it was the
    // typedef for an anonymous tag.
    for (llvm::SmallVector<TagDecl *, 4>::iterator
               FromTag = AnonTagsWithPendingTypedefs.begin(), 
            FromTagEnd = AnonTagsWithPendingTypedefs.end();
         FromTag != FromTagEnd; ++FromTag) {
      if ((*FromTag)->getTypedefForAnonDecl() == FromTypedef) {
        if (TagDecl *ToTag = cast_or_null<TagDecl>(Import(*FromTag))) {
          // We found the typedef for an anonymous tag; link them.
          ToTag->setTypedefForAnonDecl(cast<TypedefDecl>(ToD));
          AnonTagsWithPendingTypedefs.erase(FromTag);
          break;
        }
      }
    }
  }
  
  return ToD;
}

DeclContext *ASTImporter::ImportContext(DeclContext *FromDC) {
  if (!FromDC)
    return FromDC;

  return cast_or_null<DeclContext>(Import(cast<Decl>(FromDC)));
}

Expr *ASTImporter::Import(Expr *FromE) {
  if (!FromE)
    return 0;

  return cast_or_null<Expr>(Import(cast<Stmt>(FromE)));
}

Stmt *ASTImporter::Import(Stmt *FromS) {
  if (!FromS)
    return 0;

  // Check whether we've already imported this declaration.  
  llvm::DenseMap<Stmt *, Stmt *>::iterator Pos = ImportedStmts.find(FromS);
  if (Pos != ImportedStmts.end())
    return Pos->second;
  
  // Import the type
  ASTNodeImporter Importer(*this);
  Stmt *ToS = Importer.Visit(FromS);
  if (!ToS)
    return 0;
  
  // Record the imported declaration.
  ImportedStmts[FromS] = ToS;
  return ToS;
}

NestedNameSpecifier *ASTImporter::Import(NestedNameSpecifier *FromNNS) {
  if (!FromNNS)
    return 0;

  // FIXME: Implement!
  return 0;
}

SourceLocation ASTImporter::Import(SourceLocation FromLoc) {
  if (FromLoc.isInvalid())
    return SourceLocation();

  SourceManager &FromSM = FromContext.getSourceManager();
  
  // For now, map everything down to its spelling location, so that we
  // don't have to import macro instantiations.
  // FIXME: Import macro instantiations!
  FromLoc = FromSM.getSpellingLoc(FromLoc);
  std::pair<FileID, unsigned> Decomposed = FromSM.getDecomposedLoc(FromLoc);
  SourceManager &ToSM = ToContext.getSourceManager();
  return ToSM.getLocForStartOfFile(Import(Decomposed.first))
             .getFileLocWithOffset(Decomposed.second);
}

SourceRange ASTImporter::Import(SourceRange FromRange) {
  return SourceRange(Import(FromRange.getBegin()), Import(FromRange.getEnd()));
}

FileID ASTImporter::Import(FileID FromID) {
  llvm::DenseMap<unsigned, FileID>::iterator Pos
    = ImportedFileIDs.find(FromID.getHashValue());
  if (Pos != ImportedFileIDs.end())
    return Pos->second;
  
  SourceManager &FromSM = FromContext.getSourceManager();
  SourceManager &ToSM = ToContext.getSourceManager();
  const SrcMgr::SLocEntry &FromSLoc = FromSM.getSLocEntry(FromID);
  assert(FromSLoc.isFile() && "Cannot handle macro instantiations yet");
  
  // Include location of this file.
  SourceLocation ToIncludeLoc = Import(FromSLoc.getFile().getIncludeLoc());
  
  // Map the FileID for to the "to" source manager.
  FileID ToID;
  const SrcMgr::ContentCache *Cache = FromSLoc.getFile().getContentCache();
  if (Cache->Entry) {
    // FIXME: We probably want to use getVirtualFile(), so we don't hit the
    // disk again
    // FIXME: We definitely want to re-use the existing MemoryBuffer, rather
    // than mmap the files several times.
    const FileEntry *Entry = ToFileManager.getFile(Cache->Entry->getName());
    ToID = ToSM.createFileID(Entry, ToIncludeLoc, 
                             FromSLoc.getFile().getFileCharacteristic());
  } else {
    // FIXME: We want to re-use the existing MemoryBuffer!
    const llvm::MemoryBuffer *FromBuf = Cache->getBuffer();
    llvm::MemoryBuffer *ToBuf
      = llvm::MemoryBuffer::getMemBufferCopy(FromBuf->getBufferStart(),
                                             FromBuf->getBufferEnd(),
                                             FromBuf->getBufferIdentifier());
    ToID = ToSM.createFileIDForMemBuffer(ToBuf);
  }
  
  
  ImportedFileIDs[FromID.getHashValue()] = ToID;
  return ToID;
}

DeclarationName ASTImporter::Import(DeclarationName FromName) {
  if (!FromName)
    return DeclarationName();

  switch (FromName.getNameKind()) {
  case DeclarationName::Identifier:
    return Import(FromName.getAsIdentifierInfo());

  case DeclarationName::ObjCZeroArgSelector:
  case DeclarationName::ObjCOneArgSelector:
  case DeclarationName::ObjCMultiArgSelector:
    return Import(FromName.getObjCSelector());

  case DeclarationName::CXXConstructorName: {
    QualType T = Import(FromName.getCXXNameType());
    if (T.isNull())
      return DeclarationName();

    return ToContext.DeclarationNames.getCXXConstructorName(
                                               ToContext.getCanonicalType(T));
  }

  case DeclarationName::CXXDestructorName: {
    QualType T = Import(FromName.getCXXNameType());
    if (T.isNull())
      return DeclarationName();

    return ToContext.DeclarationNames.getCXXDestructorName(
                                               ToContext.getCanonicalType(T));
  }

  case DeclarationName::CXXConversionFunctionName: {
    QualType T = Import(FromName.getCXXNameType());
    if (T.isNull())
      return DeclarationName();

    return ToContext.DeclarationNames.getCXXConversionFunctionName(
                                               ToContext.getCanonicalType(T));
  }

  case DeclarationName::CXXOperatorName:
    return ToContext.DeclarationNames.getCXXOperatorName(
                                          FromName.getCXXOverloadedOperator());

  case DeclarationName::CXXLiteralOperatorName:
    return ToContext.DeclarationNames.getCXXLiteralOperatorName(
                                   Import(FromName.getCXXLiteralIdentifier()));

  case DeclarationName::CXXUsingDirective:
    // FIXME: STATICS!
    return DeclarationName::getUsingDirectiveName();
  }

  // Silence bogus GCC warning
  return DeclarationName();
}

IdentifierInfo *ASTImporter::Import(IdentifierInfo *FromId) {
  if (!FromId)
    return 0;

  return &ToContext.Idents.get(FromId->getName());
}

Selector ASTImporter::Import(Selector FromSel) {
  if (FromSel.isNull())
    return Selector();

  llvm::SmallVector<IdentifierInfo *, 4> Idents;
  Idents.push_back(Import(FromSel.getIdentifierInfoForSlot(0)));
  for (unsigned I = 1, N = FromSel.getNumArgs(); I < N; ++I)
    Idents.push_back(Import(FromSel.getIdentifierInfoForSlot(I)));
  return ToContext.Selectors.getSelector(FromSel.getNumArgs(), Idents.data());
}

DeclarationName ASTImporter::HandleNameConflict(DeclarationName Name,
                                                DeclContext *DC,
                                                unsigned IDNS,
                                                NamedDecl **Decls,
                                                unsigned NumDecls) {
  return Name;
}

DiagnosticBuilder ASTImporter::ToDiag(SourceLocation Loc, unsigned DiagID) {
  return Diags.Report(FullSourceLoc(Loc, ToContext.getSourceManager()), 
                      DiagID);
}

DiagnosticBuilder ASTImporter::FromDiag(SourceLocation Loc, unsigned DiagID) {
  return Diags.Report(FullSourceLoc(Loc, FromContext.getSourceManager()), 
                      DiagID);
}

Decl *ASTImporter::Imported(Decl *From, Decl *To) {
  ImportedDecls[From] = To;
  return To;
}

bool ASTImporter::IsStructurallyEquivalent(QualType From, QualType To) {
  llvm::DenseMap<Type *, Type *>::iterator Pos
   = ImportedTypes.find(From.getTypePtr());
  if (Pos != ImportedTypes.end() && ToContext.hasSameType(Import(From), To))
    return true;
      
  StructuralEquivalenceContext Ctx(FromContext, ToContext, Diags, 
                                   NonEquivalentDecls);
  return Ctx.IsStructurallyEquivalent(From, To);
}
