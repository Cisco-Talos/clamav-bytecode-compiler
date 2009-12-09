//===--- SemaInit.cpp - Semantic Analysis for Initializers ----------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements semantic analysis for initializers. The main entry
// point is Sema::CheckInitList(), but all of the work is performed
// within the InitListChecker class.
//
// This file also implements Sema::CheckInitializerTypes.
//
//===----------------------------------------------------------------------===//

#include "SemaInit.h"
#include "Sema.h"
#include "clang/Parse/Designator.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/ExprCXX.h"
#include "clang/AST/ExprObjC.h"
#include "llvm/Support/ErrorHandling.h"
#include <map>
using namespace clang;

//===----------------------------------------------------------------------===//
// Sema Initialization Checking
//===----------------------------------------------------------------------===//

static Expr *IsStringInit(Expr *Init, QualType DeclType, ASTContext &Context) {
  const ArrayType *AT = Context.getAsArrayType(DeclType);
  if (!AT) return 0;

  if (!isa<ConstantArrayType>(AT) && !isa<IncompleteArrayType>(AT))
    return 0;

  // See if this is a string literal or @encode.
  Init = Init->IgnoreParens();

  // Handle @encode, which is a narrow string.
  if (isa<ObjCEncodeExpr>(Init) && AT->getElementType()->isCharType())
    return Init;

  // Otherwise we can only handle string literals.
  StringLiteral *SL = dyn_cast<StringLiteral>(Init);
  if (SL == 0) return 0;

  QualType ElemTy = Context.getCanonicalType(AT->getElementType());
  // char array can be initialized with a narrow string.
  // Only allow char x[] = "foo";  not char x[] = L"foo";
  if (!SL->isWide())
    return ElemTy->isCharType() ? Init : 0;

  // wchar_t array can be initialized with a wide string: C99 6.7.8p15 (with
  // correction from DR343): "An array with element type compatible with a
  // qualified or unqualified version of wchar_t may be initialized by a wide
  // string literal, optionally enclosed in braces."
  if (Context.typesAreCompatible(Context.getWCharType(),
                                 ElemTy.getUnqualifiedType()))
    return Init;

  return 0;
}

static bool CheckSingleInitializer(Expr *&Init, QualType DeclType,
                                   bool DirectInit, Sema &S) {
  // Get the type before calling CheckSingleAssignmentConstraints(), since
  // it can promote the expression.
  QualType InitType = Init->getType();

  if (S.getLangOptions().CPlusPlus) {
    // FIXME: I dislike this error message. A lot.
    if (S.PerformImplicitConversion(Init, DeclType, 
                                    "initializing", DirectInit)) {
      ImplicitConversionSequence ICS;
      OverloadCandidateSet CandidateSet;
      if (S.IsUserDefinedConversion(Init, DeclType, ICS.UserDefined,
                              CandidateSet,
                              true, false, false) != OR_Ambiguous)
        return S.Diag(Init->getSourceRange().getBegin(),
                      diag::err_typecheck_convert_incompatible)
                      << DeclType << Init->getType() << "initializing"
                      << Init->getSourceRange();
      S.Diag(Init->getSourceRange().getBegin(),
             diag::err_typecheck_convert_ambiguous)
            << DeclType << Init->getType() << Init->getSourceRange();
      S.PrintOverloadCandidates(CandidateSet, /*OnlyViable=*/false);
      return true;
    }
    return false;
  }

  Sema::AssignConvertType ConvTy =
    S.CheckSingleAssignmentConstraints(DeclType, Init);
  return S.DiagnoseAssignmentResult(ConvTy, Init->getLocStart(), DeclType,
                                  InitType, Init, "initializing");
}

static void CheckStringInit(Expr *Str, QualType &DeclT, Sema &S) {
  // Get the length of the string as parsed.
  uint64_t StrLength =
    cast<ConstantArrayType>(Str->getType())->getSize().getZExtValue();


  const ArrayType *AT = S.Context.getAsArrayType(DeclT);
  if (const IncompleteArrayType *IAT = dyn_cast<IncompleteArrayType>(AT)) {
    // C99 6.7.8p14. We have an array of character type with unknown size
    // being initialized to a string literal.
    llvm::APSInt ConstVal(32);
    ConstVal = StrLength;
    // Return a new array type (C99 6.7.8p22).
    DeclT = S.Context.getConstantArrayType(IAT->getElementType(),
                                           ConstVal,
                                           ArrayType::Normal, 0);
    return;
  }

  const ConstantArrayType *CAT = cast<ConstantArrayType>(AT);

  // C99 6.7.8p14. We have an array of character type with known size.  However,
  // the size may be smaller or larger than the string we are initializing.
  // FIXME: Avoid truncation for 64-bit length strings.
  if (StrLength-1 > CAT->getSize().getZExtValue())
    S.Diag(Str->getSourceRange().getBegin(),
           diag::warn_initializer_string_for_char_array_too_long)
      << Str->getSourceRange();

  // Set the type to the actual size that we are initializing.  If we have
  // something like:
  //   char x[1] = "foo";
  // then this will set the string literal's type to char[1].
  Str->setType(DeclT);
}

bool Sema::CheckInitializerTypes(Expr *&Init, QualType &DeclType,
                                 SourceLocation InitLoc,
                                 DeclarationName InitEntity, bool DirectInit) {
  if (DeclType->isDependentType() ||
      Init->isTypeDependent() || Init->isValueDependent()) {
    // We have either a dependent type or a type- or value-dependent
    // initializer, so we don't perform any additional checking at
    // this point.

    // If the declaration is a non-dependent, incomplete array type
    // that has an initializer, then its type will be completed once
    // the initializer is instantiated.
    if (!DeclType->isDependentType()) {
      if (const IncompleteArrayType *ArrayT
                           = Context.getAsIncompleteArrayType(DeclType)) {
        if (InitListExpr *ILE = dyn_cast<InitListExpr>(Init)) {
          if (!ILE->isTypeDependent()) {
            // Compute the constant array type from the length of the 
            // initializer list. 
            // FIXME: This will be wrong if there are designated 
            // initializations. Good thing they don't exist in C++!
            llvm::APInt NumElements(Context.getTypeSize(Context.getSizeType()),
                                    ILE->getNumInits());
            llvm::APInt Zero(Context.getTypeSize(Context.getSizeType()), 0);
            if (NumElements == Zero) {
              // Sizing an array implicitly to zero is not allowed by ISO C,
              // but is supported by GNU.
              Diag(ILE->getLocStart(), diag::ext_typecheck_zero_array_size);
            }
            
            DeclType = Context.getConstantArrayType(ArrayT->getElementType(),
                                                    NumElements,
                                                    ArrayT->getSizeModifier(),
                                           ArrayT->getIndexTypeCVRQualifiers());
            return false;
          }
        }
        
        // Make the array type-dependent by making it dependently-sized.
        DeclType = Context.getDependentSizedArrayType(ArrayT->getElementType(),
                                                      /*NumElts=*/0,
                                                     ArrayT->getSizeModifier(),
                                           ArrayT->getIndexTypeCVRQualifiers(),
                                                      SourceRange());
      }
    }

    return false;
  }

  // C++ [dcl.init.ref]p1:
  //   A variable declared to be a T& or T&&, that is "reference to type T"
  //   (8.3.2), shall be initialized by an object, or function, of
  //   type T or by an object that can be converted into a T.
  if (DeclType->isReferenceType())
    return CheckReferenceInit(Init, DeclType, InitLoc,
                              /*SuppressUserConversions=*/false,
                              /*AllowExplicit=*/DirectInit,
                              /*ForceRValue=*/false);

  // C99 6.7.8p3: The type of the entity to be initialized shall be an array
  // of unknown size ("[]") or an object type that is not a variable array type.
  if (const VariableArrayType *VAT = Context.getAsVariableArrayType(DeclType))
    return Diag(InitLoc,  diag::err_variable_object_no_init)
    << VAT->getSizeExpr()->getSourceRange();

  InitListExpr *InitList = dyn_cast<InitListExpr>(Init);
  if (!InitList) {
    // FIXME: Handle wide strings
    if (Expr *Str = IsStringInit(Init, DeclType, Context)) {
      CheckStringInit(Str, DeclType, *this);
      return false;
    }

    // C++ [dcl.init]p14:
    //   -- If the destination type is a (possibly cv-qualified) class
    //      type:
    if (getLangOptions().CPlusPlus && DeclType->isRecordType()) {
      QualType DeclTypeC = Context.getCanonicalType(DeclType);
      QualType InitTypeC = Context.getCanonicalType(Init->getType());

      //   -- If the initialization is direct-initialization, or if it is
      //      copy-initialization where the cv-unqualified version of the
      //      source type is the same class as, or a derived class of, the
      //      class of the destination, constructors are considered.
      if ((DeclTypeC.getLocalUnqualifiedType() 
                                     == InitTypeC.getLocalUnqualifiedType()) ||
          IsDerivedFrom(InitTypeC, DeclTypeC)) {
        const CXXRecordDecl *RD =
          cast<CXXRecordDecl>(DeclType->getAs<RecordType>()->getDecl());

        // No need to make a CXXConstructExpr if both the ctor and dtor are
        // trivial.
        if (RD->hasTrivialConstructor() && RD->hasTrivialDestructor())
          return false;

        ASTOwningVector<&ActionBase::DeleteExpr> ConstructorArgs(*this);

        // FIXME: Poor location information
        InitializationKind InitKind
          = InitializationKind::CreateCopy(Init->getLocStart(), 
                                           SourceLocation());
        if (DirectInit)
          InitKind = InitializationKind::CreateDirect(Init->getLocStart(),
                                                      SourceLocation(), 
                                                      SourceLocation());
        CXXConstructorDecl *Constructor
          = PerformInitializationByConstructor(DeclType, 
                                               MultiExprArg(*this, 
                                                            (void **)&Init, 1),
                                               InitLoc, Init->getSourceRange(),
                                               InitEntity, InitKind,
                                               ConstructorArgs);
        if (!Constructor)
          return true;

        OwningExprResult InitResult =
          BuildCXXConstructExpr(/*FIXME:ConstructLoc*/SourceLocation(),
                                DeclType, Constructor,
                                move_arg(ConstructorArgs));
        if (InitResult.isInvalid())
          return true;

        Init = InitResult.takeAs<Expr>();
        return false;
      }

      //   -- Otherwise (i.e., for the remaining copy-initialization
      //      cases), user-defined conversion sequences that can
      //      convert from the source type to the destination type or
      //      (when a conversion function is used) to a derived class
      //      thereof are enumerated as described in 13.3.1.4, and the
      //      best one is chosen through overload resolution
      //      (13.3). If the conversion cannot be done or is
      //      ambiguous, the initialization is ill-formed. The
      //      function selected is called with the initializer
      //      expression as its argument; if the function is a
      //      constructor, the call initializes a temporary of the
      //      destination type.
      // FIXME: We're pretending to do copy elision here; return to this when we
      // have ASTs for such things.
      if (!PerformImplicitConversion(Init, DeclType, "initializing"))
        return false;

      if (InitEntity)
        return Diag(InitLoc, diag::err_cannot_initialize_decl)
          << InitEntity << (int)(Init->isLvalue(Context) == Expr::LV_Valid)
          << Init->getType() << Init->getSourceRange();
      return Diag(InitLoc, diag::err_cannot_initialize_decl_noname)
        << DeclType << (int)(Init->isLvalue(Context) == Expr::LV_Valid)
        << Init->getType() << Init->getSourceRange();
    }

    // C99 6.7.8p16.
    if (DeclType->isArrayType())
      return Diag(Init->getLocStart(), diag::err_array_init_list_required)
        << Init->getSourceRange();

    return CheckSingleInitializer(Init, DeclType, DirectInit, *this);
  }

  bool hadError = CheckInitList(InitList, DeclType);
  Init = InitList;
  return hadError;
}

//===----------------------------------------------------------------------===//
// Semantic checking for initializer lists.
//===----------------------------------------------------------------------===//

/// @brief Semantic checking for initializer lists.
///
/// The InitListChecker class contains a set of routines that each
/// handle the initialization of a certain kind of entity, e.g.,
/// arrays, vectors, struct/union types, scalars, etc. The
/// InitListChecker itself performs a recursive walk of the subobject
/// structure of the type to be initialized, while stepping through
/// the initializer list one element at a time. The IList and Index
/// parameters to each of the Check* routines contain the active
/// (syntactic) initializer list and the index into that initializer
/// list that represents the current initializer. Each routine is
/// responsible for moving that Index forward as it consumes elements.
///
/// Each Check* routine also has a StructuredList/StructuredIndex
/// arguments, which contains the current the "structured" (semantic)
/// initializer list and the index into that initializer list where we
/// are copying initializers as we map them over to the semantic
/// list. Once we have completed our recursive walk of the subobject
/// structure, we will have constructed a full semantic initializer
/// list.
///
/// C99 designators cause changes in the initializer list traversal,
/// because they make the initialization "jump" into a specific
/// subobject and then continue the initialization from that
/// point. CheckDesignatedInitializer() recursively steps into the
/// designated subobject and manages backing out the recursion to
/// initialize the subobjects after the one designated.
namespace {
class InitListChecker {
  Sema &SemaRef;
  bool hadError;
  std::map<InitListExpr *, InitListExpr *> SyntacticToSemantic;
  InitListExpr *FullyStructuredList;

  void CheckImplicitInitList(InitListExpr *ParentIList, QualType T,
                             unsigned &Index, InitListExpr *StructuredList,
                             unsigned &StructuredIndex,
                             bool TopLevelObject = false);
  void CheckExplicitInitList(InitListExpr *IList, QualType &T,
                             unsigned &Index, InitListExpr *StructuredList,
                             unsigned &StructuredIndex,
                             bool TopLevelObject = false);
  void CheckListElementTypes(InitListExpr *IList, QualType &DeclType,
                             bool SubobjectIsDesignatorContext,
                             unsigned &Index,
                             InitListExpr *StructuredList,
                             unsigned &StructuredIndex,
                             bool TopLevelObject = false);
  void CheckSubElementType(InitListExpr *IList, QualType ElemType,
                           unsigned &Index,
                           InitListExpr *StructuredList,
                           unsigned &StructuredIndex);
  void CheckScalarType(InitListExpr *IList, QualType DeclType,
                       unsigned &Index,
                       InitListExpr *StructuredList,
                       unsigned &StructuredIndex);
  void CheckReferenceType(InitListExpr *IList, QualType DeclType,
                          unsigned &Index,
                          InitListExpr *StructuredList,
                          unsigned &StructuredIndex);
  void CheckVectorType(InitListExpr *IList, QualType DeclType, unsigned &Index,
                       InitListExpr *StructuredList,
                       unsigned &StructuredIndex);
  void CheckStructUnionTypes(InitListExpr *IList, QualType DeclType,
                             RecordDecl::field_iterator Field,
                             bool SubobjectIsDesignatorContext, unsigned &Index,
                             InitListExpr *StructuredList,
                             unsigned &StructuredIndex,
                             bool TopLevelObject = false);
  void CheckArrayType(InitListExpr *IList, QualType &DeclType,
                      llvm::APSInt elementIndex,
                      bool SubobjectIsDesignatorContext, unsigned &Index,
                      InitListExpr *StructuredList,
                      unsigned &StructuredIndex);
  bool CheckDesignatedInitializer(InitListExpr *IList, DesignatedInitExpr *DIE,
                                  unsigned DesigIdx,
                                  QualType &CurrentObjectType,
                                  RecordDecl::field_iterator *NextField,
                                  llvm::APSInt *NextElementIndex,
                                  unsigned &Index,
                                  InitListExpr *StructuredList,
                                  unsigned &StructuredIndex,
                                  bool FinishSubobjectInit,
                                  bool TopLevelObject);
  InitListExpr *getStructuredSubobjectInit(InitListExpr *IList, unsigned Index,
                                           QualType CurrentObjectType,
                                           InitListExpr *StructuredList,
                                           unsigned StructuredIndex,
                                           SourceRange InitRange);
  void UpdateStructuredListElement(InitListExpr *StructuredList,
                                   unsigned &StructuredIndex,
                                   Expr *expr);
  int numArrayElements(QualType DeclType);
  int numStructUnionElements(QualType DeclType);

  void FillInValueInitializations(InitListExpr *ILE);
public:
  InitListChecker(Sema &S, InitListExpr *IL, QualType &T);
  bool HadError() { return hadError; }

  // @brief Retrieves the fully-structured initializer list used for
  // semantic analysis and code generation.
  InitListExpr *getFullyStructuredList() const { return FullyStructuredList; }
};
} // end anonymous namespace

/// Recursively replaces NULL values within the given initializer list
/// with expressions that perform value-initialization of the
/// appropriate type.
void InitListChecker::FillInValueInitializations(InitListExpr *ILE) {
  assert((ILE->getType() != SemaRef.Context.VoidTy) &&
         "Should not have void type");
  SourceLocation Loc = ILE->getSourceRange().getBegin();
  if (ILE->getSyntacticForm())
    Loc = ILE->getSyntacticForm()->getSourceRange().getBegin();

  if (const RecordType *RType = ILE->getType()->getAs<RecordType>()) {
    unsigned Init = 0, NumInits = ILE->getNumInits();
    for (RecordDecl::field_iterator
           Field = RType->getDecl()->field_begin(),
           FieldEnd = RType->getDecl()->field_end();
         Field != FieldEnd; ++Field) {
      if (Field->isUnnamedBitfield())
        continue;

      if (Init >= NumInits || !ILE->getInit(Init)) {
        if (Field->getType()->isReferenceType()) {
          // C++ [dcl.init.aggr]p9:
          //   If an incomplete or empty initializer-list leaves a
          //   member of reference type uninitialized, the program is
          //   ill-formed.
          SemaRef.Diag(Loc, diag::err_init_reference_member_uninitialized)
            << Field->getType()
            << ILE->getSyntacticForm()->getSourceRange();
          SemaRef.Diag(Field->getLocation(),
                        diag::note_uninit_reference_member);
          hadError = true;
          return;
        } else if (SemaRef.CheckValueInitialization(Field->getType(), Loc)) {
          hadError = true;
          return;
        }

        // FIXME: If value-initialization involves calling a constructor, should
        // we make that call explicit in the representation (even when it means
        // extending the initializer list)?
        if (Init < NumInits && !hadError)
          ILE->setInit(Init,
              new (SemaRef.Context) ImplicitValueInitExpr(Field->getType()));
      } else if (InitListExpr *InnerILE
                 = dyn_cast<InitListExpr>(ILE->getInit(Init)))
        FillInValueInitializations(InnerILE);
      ++Init;

      // Only look at the first initialization of a union.
      if (RType->getDecl()->isUnion())
        break;
    }

    return;
  }

  QualType ElementType;

  unsigned NumInits = ILE->getNumInits();
  unsigned NumElements = NumInits;
  if (const ArrayType *AType = SemaRef.Context.getAsArrayType(ILE->getType())) {
    ElementType = AType->getElementType();
    if (const ConstantArrayType *CAType = dyn_cast<ConstantArrayType>(AType))
      NumElements = CAType->getSize().getZExtValue();
  } else if (const VectorType *VType = ILE->getType()->getAs<VectorType>()) {
    ElementType = VType->getElementType();
    NumElements = VType->getNumElements();
  } else
    ElementType = ILE->getType();

  for (unsigned Init = 0; Init != NumElements; ++Init) {
    if (Init >= NumInits || !ILE->getInit(Init)) {
      if (SemaRef.CheckValueInitialization(ElementType, Loc)) {
        hadError = true;
        return;
      }

      // FIXME: If value-initialization involves calling a constructor, should
      // we make that call explicit in the representation (even when it means
      // extending the initializer list)?
      if (Init < NumInits && !hadError)
        ILE->setInit(Init,
                     new (SemaRef.Context) ImplicitValueInitExpr(ElementType));
    } else if (InitListExpr *InnerILE
               = dyn_cast<InitListExpr>(ILE->getInit(Init)))
      FillInValueInitializations(InnerILE);
  }
}


InitListChecker::InitListChecker(Sema &S, InitListExpr *IL, QualType &T)
  : SemaRef(S) {
  hadError = false;

  unsigned newIndex = 0;
  unsigned newStructuredIndex = 0;
  FullyStructuredList
    = getStructuredSubobjectInit(IL, newIndex, T, 0, 0, IL->getSourceRange());
  CheckExplicitInitList(IL, T, newIndex, FullyStructuredList, newStructuredIndex,
                        /*TopLevelObject=*/true);

  if (!hadError)
    FillInValueInitializations(FullyStructuredList);
}

int InitListChecker::numArrayElements(QualType DeclType) {
  // FIXME: use a proper constant
  int maxElements = 0x7FFFFFFF;
  if (const ConstantArrayType *CAT =
        SemaRef.Context.getAsConstantArrayType(DeclType)) {
    maxElements = static_cast<int>(CAT->getSize().getZExtValue());
  }
  return maxElements;
}

int InitListChecker::numStructUnionElements(QualType DeclType) {
  RecordDecl *structDecl = DeclType->getAs<RecordType>()->getDecl();
  int InitializableMembers = 0;
  for (RecordDecl::field_iterator
         Field = structDecl->field_begin(),
         FieldEnd = structDecl->field_end();
       Field != FieldEnd; ++Field) {
    if ((*Field)->getIdentifier() || !(*Field)->isBitField())
      ++InitializableMembers;
  }
  if (structDecl->isUnion())
    return std::min(InitializableMembers, 1);
  return InitializableMembers - structDecl->hasFlexibleArrayMember();
}

void InitListChecker::CheckImplicitInitList(InitListExpr *ParentIList,
                                            QualType T, unsigned &Index,
                                            InitListExpr *StructuredList,
                                            unsigned &StructuredIndex,
                                            bool TopLevelObject) {
  int maxElements = 0;

  if (T->isArrayType())
    maxElements = numArrayElements(T);
  else if (T->isStructureType() || T->isUnionType())
    maxElements = numStructUnionElements(T);
  else if (T->isVectorType())
    maxElements = T->getAs<VectorType>()->getNumElements();
  else
    assert(0 && "CheckImplicitInitList(): Illegal type");

  if (maxElements == 0) {
    SemaRef.Diag(ParentIList->getInit(Index)->getLocStart(),
                  diag::err_implicit_empty_initializer);
    ++Index;
    hadError = true;
    return;
  }

  // Build a structured initializer list corresponding to this subobject.
  InitListExpr *StructuredSubobjectInitList
    = getStructuredSubobjectInit(ParentIList, Index, T, StructuredList,
                                 StructuredIndex,
          SourceRange(ParentIList->getInit(Index)->getSourceRange().getBegin(),
                      ParentIList->getSourceRange().getEnd()));
  unsigned StructuredSubobjectInitIndex = 0;

  // Check the element types and build the structural subobject.
  unsigned StartIndex = Index;
  CheckListElementTypes(ParentIList, T, false, Index,
                        StructuredSubobjectInitList,
                        StructuredSubobjectInitIndex,
                        TopLevelObject);
  unsigned EndIndex = (Index == StartIndex? StartIndex : Index - 1);
  StructuredSubobjectInitList->setType(T);

  // Update the structured sub-object initializer so that it's ending
  // range corresponds with the end of the last initializer it used.
  if (EndIndex < ParentIList->getNumInits()) {
    SourceLocation EndLoc
      = ParentIList->getInit(EndIndex)->getSourceRange().getEnd();
    StructuredSubobjectInitList->setRBraceLoc(EndLoc);
  }
}

void InitListChecker::CheckExplicitInitList(InitListExpr *IList, QualType &T,
                                            unsigned &Index,
                                            InitListExpr *StructuredList,
                                            unsigned &StructuredIndex,
                                            bool TopLevelObject) {
  assert(IList->isExplicit() && "Illegal Implicit InitListExpr");
  SyntacticToSemantic[IList] = StructuredList;
  StructuredList->setSyntacticForm(IList);
  CheckListElementTypes(IList, T, true, Index, StructuredList,
                        StructuredIndex, TopLevelObject);
  IList->setType(T);
  StructuredList->setType(T);
  if (hadError)
    return;

  if (Index < IList->getNumInits()) {
    // We have leftover initializers
    if (StructuredIndex == 1 &&
        IsStringInit(StructuredList->getInit(0), T, SemaRef.Context)) {
      unsigned DK = diag::warn_excess_initializers_in_char_array_initializer;
      if (SemaRef.getLangOptions().CPlusPlus) {
        DK = diag::err_excess_initializers_in_char_array_initializer;
        hadError = true;
      }
      // Special-case
      SemaRef.Diag(IList->getInit(Index)->getLocStart(), DK)
        << IList->getInit(Index)->getSourceRange();
    } else if (!T->isIncompleteType()) {
      // Don't complain for incomplete types, since we'll get an error
      // elsewhere
      QualType CurrentObjectType = StructuredList->getType();
      int initKind =
        CurrentObjectType->isArrayType()? 0 :
        CurrentObjectType->isVectorType()? 1 :
        CurrentObjectType->isScalarType()? 2 :
        CurrentObjectType->isUnionType()? 3 :
        4;

      unsigned DK = diag::warn_excess_initializers;
      if (SemaRef.getLangOptions().CPlusPlus) {
        DK = diag::err_excess_initializers;
        hadError = true;
      }
      if (SemaRef.getLangOptions().OpenCL && initKind == 1) {
        DK = diag::err_excess_initializers;
        hadError = true;
      }

      SemaRef.Diag(IList->getInit(Index)->getLocStart(), DK)
        << initKind << IList->getInit(Index)->getSourceRange();
    }
  }

  if (T->isScalarType() && !TopLevelObject)
    SemaRef.Diag(IList->getLocStart(), diag::warn_braces_around_scalar_init)
      << IList->getSourceRange()
      << CodeModificationHint::CreateRemoval(IList->getLocStart())
      << CodeModificationHint::CreateRemoval(IList->getLocEnd());
}

void InitListChecker::CheckListElementTypes(InitListExpr *IList,
                                            QualType &DeclType,
                                            bool SubobjectIsDesignatorContext,
                                            unsigned &Index,
                                            InitListExpr *StructuredList,
                                            unsigned &StructuredIndex,
                                            bool TopLevelObject) {
  if (DeclType->isScalarType()) {
    CheckScalarType(IList, DeclType, Index, StructuredList, StructuredIndex);
  } else if (DeclType->isVectorType()) {
    CheckVectorType(IList, DeclType, Index, StructuredList, StructuredIndex);
  } else if (DeclType->isAggregateType()) {
    if (DeclType->isRecordType()) {
      RecordDecl *RD = DeclType->getAs<RecordType>()->getDecl();
      CheckStructUnionTypes(IList, DeclType, RD->field_begin(),
                            SubobjectIsDesignatorContext, Index,
                            StructuredList, StructuredIndex,
                            TopLevelObject);
    } else if (DeclType->isArrayType()) {
      llvm::APSInt Zero(
                      SemaRef.Context.getTypeSize(SemaRef.Context.getSizeType()),
                      false);
      CheckArrayType(IList, DeclType, Zero, SubobjectIsDesignatorContext, Index,
                     StructuredList, StructuredIndex);
    } else
      assert(0 && "Aggregate that isn't a structure or array?!");
  } else if (DeclType->isVoidType() || DeclType->isFunctionType()) {
    // This type is invalid, issue a diagnostic.
    ++Index;
    SemaRef.Diag(IList->getLocStart(), diag::err_illegal_initializer_type)
      << DeclType;
    hadError = true;
  } else if (DeclType->isRecordType()) {
    // C++ [dcl.init]p14:
    //   [...] If the class is an aggregate (8.5.1), and the initializer
    //   is a brace-enclosed list, see 8.5.1.
    //
    // Note: 8.5.1 is handled below; here, we diagnose the case where
    // we have an initializer list and a destination type that is not
    // an aggregate.
    // FIXME: In C++0x, this is yet another form of initialization.
    SemaRef.Diag(IList->getLocStart(), diag::err_init_non_aggr_init_list)
      << DeclType << IList->getSourceRange();
    hadError = true;
  } else if (DeclType->isReferenceType()) {
    CheckReferenceType(IList, DeclType, Index, StructuredList, StructuredIndex);
  } else {
    // In C, all types are either scalars or aggregates, but
    // additional handling is needed here for C++ (and possibly others?).
    assert(0 && "Unsupported initializer type");
  }
}

void InitListChecker::CheckSubElementType(InitListExpr *IList,
                                          QualType ElemType,
                                          unsigned &Index,
                                          InitListExpr *StructuredList,
                                          unsigned &StructuredIndex) {
  Expr *expr = IList->getInit(Index);
  if (InitListExpr *SubInitList = dyn_cast<InitListExpr>(expr)) {
    unsigned newIndex = 0;
    unsigned newStructuredIndex = 0;
    InitListExpr *newStructuredList
      = getStructuredSubobjectInit(IList, Index, ElemType,
                                   StructuredList, StructuredIndex,
                                   SubInitList->getSourceRange());
    CheckExplicitInitList(SubInitList, ElemType, newIndex,
                          newStructuredList, newStructuredIndex);
    ++StructuredIndex;
    ++Index;
  } else if (Expr *Str = IsStringInit(expr, ElemType, SemaRef.Context)) {
    CheckStringInit(Str, ElemType, SemaRef);
    UpdateStructuredListElement(StructuredList, StructuredIndex, Str);
    ++Index;
  } else if (ElemType->isScalarType()) {
    CheckScalarType(IList, ElemType, Index, StructuredList, StructuredIndex);
  } else if (ElemType->isReferenceType()) {
    CheckReferenceType(IList, ElemType, Index, StructuredList, StructuredIndex);
  } else {
    if (SemaRef.getLangOptions().CPlusPlus) {
      // C++ [dcl.init.aggr]p12:
      //   All implicit type conversions (clause 4) are considered when
      //   initializing the aggregate member with an ini- tializer from
      //   an initializer-list. If the initializer can initialize a
      //   member, the member is initialized. [...]
      ImplicitConversionSequence ICS
        = SemaRef.TryCopyInitialization(expr, ElemType,
                                        /*SuppressUserConversions=*/false,
                                        /*ForceRValue=*/false,
                                        /*InOverloadResolution=*/false);

      if (ICS.ConversionKind != ImplicitConversionSequence::BadConversion) {
        if (SemaRef.PerformImplicitConversion(expr, ElemType, ICS,
                                               "initializing"))
          hadError = true;
        UpdateStructuredListElement(StructuredList, StructuredIndex, expr);
        ++Index;
        return;
      }

      // Fall through for subaggregate initialization
    } else {
      // C99 6.7.8p13:
      //
      //   The initializer for a structure or union object that has
      //   automatic storage duration shall be either an initializer
      //   list as described below, or a single expression that has
      //   compatible structure or union type. In the latter case, the
      //   initial value of the object, including unnamed members, is
      //   that of the expression.
      if ((ElemType->isRecordType() || ElemType->isVectorType()) &&
          SemaRef.Context.hasSameUnqualifiedType(expr->getType(), ElemType)) {
        UpdateStructuredListElement(StructuredList, StructuredIndex, expr);
        ++Index;
        return;
      }

      // Fall through for subaggregate initialization
    }

    // C++ [dcl.init.aggr]p12:
    //
    //   [...] Otherwise, if the member is itself a non-empty
    //   subaggregate, brace elision is assumed and the initializer is
    //   considered for the initialization of the first member of
    //   the subaggregate.
    if (ElemType->isAggregateType() || ElemType->isVectorType()) {
      CheckImplicitInitList(IList, ElemType, Index, StructuredList,
                            StructuredIndex);
      ++StructuredIndex;
    } else {
      // We cannot initialize this element, so let
      // PerformCopyInitialization produce the appropriate diagnostic.
      SemaRef.PerformCopyInitialization(expr, ElemType, "initializing");
      hadError = true;
      ++Index;
      ++StructuredIndex;
    }
  }
}

void InitListChecker::CheckScalarType(InitListExpr *IList, QualType DeclType,
                                      unsigned &Index,
                                      InitListExpr *StructuredList,
                                      unsigned &StructuredIndex) {
  if (Index < IList->getNumInits()) {
    Expr *expr = IList->getInit(Index);
    if (isa<InitListExpr>(expr)) {
      SemaRef.Diag(IList->getLocStart(),
                    diag::err_many_braces_around_scalar_init)
        << IList->getSourceRange();
      hadError = true;
      ++Index;
      ++StructuredIndex;
      return;
    } else if (isa<DesignatedInitExpr>(expr)) {
      SemaRef.Diag(expr->getSourceRange().getBegin(),
                    diag::err_designator_for_scalar_init)
        << DeclType << expr->getSourceRange();
      hadError = true;
      ++Index;
      ++StructuredIndex;
      return;
    }

    Expr *savExpr = expr; // Might be promoted by CheckSingleInitializer.
    if (CheckSingleInitializer(expr, DeclType, false, SemaRef))
      hadError = true; // types weren't compatible.
    else if (savExpr != expr) {
      // The type was promoted, update initializer list.
      IList->setInit(Index, expr);
    }
    if (hadError)
      ++StructuredIndex;
    else
      UpdateStructuredListElement(StructuredList, StructuredIndex, expr);
    ++Index;
  } else {
    SemaRef.Diag(IList->getLocStart(), diag::err_empty_scalar_initializer)
      << IList->getSourceRange();
    hadError = true;
    ++Index;
    ++StructuredIndex;
    return;
  }
}

void InitListChecker::CheckReferenceType(InitListExpr *IList, QualType DeclType,
                                         unsigned &Index,
                                         InitListExpr *StructuredList,
                                         unsigned &StructuredIndex) {
  if (Index < IList->getNumInits()) {
    Expr *expr = IList->getInit(Index);
    if (isa<InitListExpr>(expr)) {
      SemaRef.Diag(IList->getLocStart(), diag::err_init_non_aggr_init_list)
        << DeclType << IList->getSourceRange();
      hadError = true;
      ++Index;
      ++StructuredIndex;
      return;
    }

    Expr *savExpr = expr; // Might be promoted by CheckSingleInitializer.
    if (SemaRef.CheckReferenceInit(expr, DeclType,
                                   /*FIXME:*/expr->getLocStart(),
                                   /*SuppressUserConversions=*/false,
                                   /*AllowExplicit=*/false,
                                   /*ForceRValue=*/false))
      hadError = true;
    else if (savExpr != expr) {
      // The type was promoted, update initializer list.
      IList->setInit(Index, expr);
    }
    if (hadError)
      ++StructuredIndex;
    else
      UpdateStructuredListElement(StructuredList, StructuredIndex, expr);
    ++Index;
  } else {
    // FIXME: It would be wonderful if we could point at the actual member. In
    // general, it would be useful to pass location information down the stack,
    // so that we know the location (or decl) of the "current object" being
    // initialized.
    SemaRef.Diag(IList->getLocStart(),
                  diag::err_init_reference_member_uninitialized)
      << DeclType
      << IList->getSourceRange();
    hadError = true;
    ++Index;
    ++StructuredIndex;
    return;
  }
}

void InitListChecker::CheckVectorType(InitListExpr *IList, QualType DeclType,
                                      unsigned &Index,
                                      InitListExpr *StructuredList,
                                      unsigned &StructuredIndex) {
  if (Index < IList->getNumInits()) {
    const VectorType *VT = DeclType->getAs<VectorType>();
    unsigned maxElements = VT->getNumElements();
    unsigned numEltsInit = 0;
    QualType elementType = VT->getElementType();

    if (!SemaRef.getLangOptions().OpenCL) {
      for (unsigned i = 0; i < maxElements; ++i, ++numEltsInit) {
        // Don't attempt to go past the end of the init list
        if (Index >= IList->getNumInits())
          break;
        CheckSubElementType(IList, elementType, Index,
                            StructuredList, StructuredIndex);
      }
    } else {
      // OpenCL initializers allows vectors to be constructed from vectors.
      for (unsigned i = 0; i < maxElements; ++i) {
        // Don't attempt to go past the end of the init list
        if (Index >= IList->getNumInits())
          break;
        QualType IType = IList->getInit(Index)->getType();
        if (!IType->isVectorType()) {
          CheckSubElementType(IList, elementType, Index,
                              StructuredList, StructuredIndex);
          ++numEltsInit;
        } else {
          const VectorType *IVT = IType->getAs<VectorType>();
          unsigned numIElts = IVT->getNumElements();
          QualType VecType = SemaRef.Context.getExtVectorType(elementType,
                                                              numIElts);
          CheckSubElementType(IList, VecType, Index,
                              StructuredList, StructuredIndex);
          numEltsInit += numIElts;
        }
      }
    }

    // OpenCL & AltiVec require all elements to be initialized.
    if (numEltsInit != maxElements)
      if (SemaRef.getLangOptions().OpenCL || SemaRef.getLangOptions().AltiVec)
        SemaRef.Diag(IList->getSourceRange().getBegin(),
                     diag::err_vector_incorrect_num_initializers)
          << (numEltsInit < maxElements) << maxElements << numEltsInit;
  }
}

void InitListChecker::CheckArrayType(InitListExpr *IList, QualType &DeclType,
                                     llvm::APSInt elementIndex,
                                     bool SubobjectIsDesignatorContext,
                                     unsigned &Index,
                                     InitListExpr *StructuredList,
                                     unsigned &StructuredIndex) {
  // Check for the special-case of initializing an array with a string.
  if (Index < IList->getNumInits()) {
    if (Expr *Str = IsStringInit(IList->getInit(Index), DeclType,
                                 SemaRef.Context)) {
      CheckStringInit(Str, DeclType, SemaRef);
      // We place the string literal directly into the resulting
      // initializer list. This is the only place where the structure
      // of the structured initializer list doesn't match exactly,
      // because doing so would involve allocating one character
      // constant for each string.
      UpdateStructuredListElement(StructuredList, StructuredIndex, Str);
      StructuredList->resizeInits(SemaRef.Context, StructuredIndex);
      ++Index;
      return;
    }
  }
  if (const VariableArrayType *VAT =
        SemaRef.Context.getAsVariableArrayType(DeclType)) {
    // Check for VLAs; in standard C it would be possible to check this
    // earlier, but I don't know where clang accepts VLAs (gcc accepts
    // them in all sorts of strange places).
    SemaRef.Diag(VAT->getSizeExpr()->getLocStart(),
                  diag::err_variable_object_no_init)
      << VAT->getSizeExpr()->getSourceRange();
    hadError = true;
    ++Index;
    ++StructuredIndex;
    return;
  }

  // We might know the maximum number of elements in advance.
  llvm::APSInt maxElements(elementIndex.getBitWidth(),
                           elementIndex.isUnsigned());
  bool maxElementsKnown = false;
  if (const ConstantArrayType *CAT =
        SemaRef.Context.getAsConstantArrayType(DeclType)) {
    maxElements = CAT->getSize();
    elementIndex.extOrTrunc(maxElements.getBitWidth());
    elementIndex.setIsUnsigned(maxElements.isUnsigned());
    maxElementsKnown = true;
  }

  QualType elementType = SemaRef.Context.getAsArrayType(DeclType)
                             ->getElementType();
  while (Index < IList->getNumInits()) {
    Expr *Init = IList->getInit(Index);
    if (DesignatedInitExpr *DIE = dyn_cast<DesignatedInitExpr>(Init)) {
      // If we're not the subobject that matches up with the '{' for
      // the designator, we shouldn't be handling the
      // designator. Return immediately.
      if (!SubobjectIsDesignatorContext)
        return;

      // Handle this designated initializer. elementIndex will be
      // updated to be the next array element we'll initialize.
      if (CheckDesignatedInitializer(IList, DIE, 0,
                                     DeclType, 0, &elementIndex, Index,
                                     StructuredList, StructuredIndex, true,
                                     false)) {
        hadError = true;
        continue;
      }

      if (elementIndex.getBitWidth() > maxElements.getBitWidth())
        maxElements.extend(elementIndex.getBitWidth());
      else if (elementIndex.getBitWidth() < maxElements.getBitWidth())
        elementIndex.extend(maxElements.getBitWidth());
      elementIndex.setIsUnsigned(maxElements.isUnsigned());

      // If the array is of incomplete type, keep track of the number of
      // elements in the initializer.
      if (!maxElementsKnown && elementIndex > maxElements)
        maxElements = elementIndex;

      continue;
    }

    // If we know the maximum number of elements, and we've already
    // hit it, stop consuming elements in the initializer list.
    if (maxElementsKnown && elementIndex == maxElements)
      break;

    // Check this element.
    CheckSubElementType(IList, elementType, Index,
                        StructuredList, StructuredIndex);
    ++elementIndex;

    // If the array is of incomplete type, keep track of the number of
    // elements in the initializer.
    if (!maxElementsKnown && elementIndex > maxElements)
      maxElements = elementIndex;
  }
  if (!hadError && DeclType->isIncompleteArrayType()) {
    // If this is an incomplete array type, the actual type needs to
    // be calculated here.
    llvm::APSInt Zero(maxElements.getBitWidth(), maxElements.isUnsigned());
    if (maxElements == Zero) {
      // Sizing an array implicitly to zero is not allowed by ISO C,
      // but is supported by GNU.
      SemaRef.Diag(IList->getLocStart(),
                    diag::ext_typecheck_zero_array_size);
    }

    DeclType = SemaRef.Context.getConstantArrayType(elementType, maxElements,
                                                     ArrayType::Normal, 0);
  }
}

void InitListChecker::CheckStructUnionTypes(InitListExpr *IList,
                                            QualType DeclType,
                                            RecordDecl::field_iterator Field,
                                            bool SubobjectIsDesignatorContext,
                                            unsigned &Index,
                                            InitListExpr *StructuredList,
                                            unsigned &StructuredIndex,
                                            bool TopLevelObject) {
  RecordDecl* structDecl = DeclType->getAs<RecordType>()->getDecl();

  // If the record is invalid, some of it's members are invalid. To avoid
  // confusion, we forgo checking the intializer for the entire record.
  if (structDecl->isInvalidDecl()) {
    hadError = true;
    return;
  }

  if (DeclType->isUnionType() && IList->getNumInits() == 0) {
    // Value-initialize the first named member of the union.
    RecordDecl *RD = DeclType->getAs<RecordType>()->getDecl();
    for (RecordDecl::field_iterator FieldEnd = RD->field_end();
         Field != FieldEnd; ++Field) {
      if (Field->getDeclName()) {
        StructuredList->setInitializedFieldInUnion(*Field);
        break;
      }
    }
    return;
  }

  // If structDecl is a forward declaration, this loop won't do
  // anything except look at designated initializers; That's okay,
  // because an error should get printed out elsewhere. It might be
  // worthwhile to skip over the rest of the initializer, though.
  RecordDecl *RD = DeclType->getAs<RecordType>()->getDecl();
  RecordDecl::field_iterator FieldEnd = RD->field_end();
  bool InitializedSomething = false;
  while (Index < IList->getNumInits()) {
    Expr *Init = IList->getInit(Index);

    if (DesignatedInitExpr *DIE = dyn_cast<DesignatedInitExpr>(Init)) {
      // If we're not the subobject that matches up with the '{' for
      // the designator, we shouldn't be handling the
      // designator. Return immediately.
      if (!SubobjectIsDesignatorContext)
        return;

      // Handle this designated initializer. Field will be updated to
      // the next field that we'll be initializing.
      if (CheckDesignatedInitializer(IList, DIE, 0,
                                     DeclType, &Field, 0, Index,
                                     StructuredList, StructuredIndex,
                                     true, TopLevelObject))
        hadError = true;

      InitializedSomething = true;
      continue;
    }

    if (Field == FieldEnd) {
      // We've run out of fields. We're done.
      break;
    }

    // We've already initialized a member of a union. We're done.
    if (InitializedSomething && DeclType->isUnionType())
      break;

    // If we've hit the flexible array member at the end, we're done.
    if (Field->getType()->isIncompleteArrayType())
      break;

    if (Field->isUnnamedBitfield()) {
      // Don't initialize unnamed bitfields, e.g. "int : 20;"
      ++Field;
      continue;
    }

    CheckSubElementType(IList, Field->getType(), Index,
                        StructuredList, StructuredIndex);
    InitializedSomething = true;

    if (DeclType->isUnionType()) {
      // Initialize the first field within the union.
      StructuredList->setInitializedFieldInUnion(*Field);
    }

    ++Field;
  }

  if (Field == FieldEnd || !Field->getType()->isIncompleteArrayType() ||
      Index >= IList->getNumInits())
    return;

  // Handle GNU flexible array initializers.
  if (!TopLevelObject &&
      (!isa<InitListExpr>(IList->getInit(Index)) ||
       cast<InitListExpr>(IList->getInit(Index))->getNumInits() > 0)) {
    SemaRef.Diag(IList->getInit(Index)->getSourceRange().getBegin(),
                  diag::err_flexible_array_init_nonempty)
      << IList->getInit(Index)->getSourceRange().getBegin();
    SemaRef.Diag(Field->getLocation(), diag::note_flexible_array_member)
      << *Field;
    hadError = true;
    ++Index;
    return;
  } else {
    SemaRef.Diag(IList->getInit(Index)->getSourceRange().getBegin(),
                 diag::ext_flexible_array_init)
      << IList->getInit(Index)->getSourceRange().getBegin();
    SemaRef.Diag(Field->getLocation(), diag::note_flexible_array_member)
      << *Field;
  }

  if (isa<InitListExpr>(IList->getInit(Index)))
    CheckSubElementType(IList, Field->getType(), Index, StructuredList,
                        StructuredIndex);
  else
    CheckImplicitInitList(IList, Field->getType(), Index, StructuredList,
                          StructuredIndex);
}

/// \brief Expand a field designator that refers to a member of an
/// anonymous struct or union into a series of field designators that
/// refers to the field within the appropriate subobject.
///
/// Field/FieldIndex will be updated to point to the (new)
/// currently-designated field.
static void ExpandAnonymousFieldDesignator(Sema &SemaRef,
                                           DesignatedInitExpr *DIE,
                                           unsigned DesigIdx,
                                           FieldDecl *Field,
                                        RecordDecl::field_iterator &FieldIter,
                                           unsigned &FieldIndex) {
  typedef DesignatedInitExpr::Designator Designator;

  // Build the path from the current object to the member of the
  // anonymous struct/union (backwards).
  llvm::SmallVector<FieldDecl *, 4> Path;
  SemaRef.BuildAnonymousStructUnionMemberPath(Field, Path);

  // Build the replacement designators.
  llvm::SmallVector<Designator, 4> Replacements;
  for (llvm::SmallVector<FieldDecl *, 4>::reverse_iterator
         FI = Path.rbegin(), FIEnd = Path.rend();
       FI != FIEnd; ++FI) {
    if (FI + 1 == FIEnd)
      Replacements.push_back(Designator((IdentifierInfo *)0,
                                    DIE->getDesignator(DesigIdx)->getDotLoc(),
                                DIE->getDesignator(DesigIdx)->getFieldLoc()));
    else
      Replacements.push_back(Designator((IdentifierInfo *)0, SourceLocation(),
                                        SourceLocation()));
    Replacements.back().setField(*FI);
  }

  // Expand the current designator into the set of replacement
  // designators, so we have a full subobject path down to where the
  // member of the anonymous struct/union is actually stored.
  DIE->ExpandDesignator(DesigIdx, &Replacements[0],
                        &Replacements[0] + Replacements.size());

  // Update FieldIter/FieldIndex;
  RecordDecl *Record = cast<RecordDecl>(Path.back()->getDeclContext());
  FieldIter = Record->field_begin();
  FieldIndex = 0;
  for (RecordDecl::field_iterator FEnd = Record->field_end();
       FieldIter != FEnd; ++FieldIter) {
    if (FieldIter->isUnnamedBitfield())
        continue;

    if (*FieldIter == Path.back())
      return;

    ++FieldIndex;
  }

  assert(false && "Unable to find anonymous struct/union field");
}

/// @brief Check the well-formedness of a C99 designated initializer.
///
/// Determines whether the designated initializer @p DIE, which
/// resides at the given @p Index within the initializer list @p
/// IList, is well-formed for a current object of type @p DeclType
/// (C99 6.7.8). The actual subobject that this designator refers to
/// within the current subobject is returned in either
/// @p NextField or @p NextElementIndex (whichever is appropriate).
///
/// @param IList  The initializer list in which this designated
/// initializer occurs.
///
/// @param DIE The designated initializer expression.
///
/// @param DesigIdx  The index of the current designator.
///
/// @param DeclType  The type of the "current object" (C99 6.7.8p17),
/// into which the designation in @p DIE should refer.
///
/// @param NextField  If non-NULL and the first designator in @p DIE is
/// a field, this will be set to the field declaration corresponding
/// to the field named by the designator.
///
/// @param NextElementIndex  If non-NULL and the first designator in @p
/// DIE is an array designator or GNU array-range designator, this
/// will be set to the last index initialized by this designator.
///
/// @param Index  Index into @p IList where the designated initializer
/// @p DIE occurs.
///
/// @param StructuredList  The initializer list expression that
/// describes all of the subobject initializers in the order they'll
/// actually be initialized.
///
/// @returns true if there was an error, false otherwise.
bool
InitListChecker::CheckDesignatedInitializer(InitListExpr *IList,
                                      DesignatedInitExpr *DIE,
                                      unsigned DesigIdx,
                                      QualType &CurrentObjectType,
                                      RecordDecl::field_iterator *NextField,
                                      llvm::APSInt *NextElementIndex,
                                      unsigned &Index,
                                      InitListExpr *StructuredList,
                                      unsigned &StructuredIndex,
                                            bool FinishSubobjectInit,
                                            bool TopLevelObject) {
  if (DesigIdx == DIE->size()) {
    // Check the actual initialization for the designated object type.
    bool prevHadError = hadError;

    // Temporarily remove the designator expression from the
    // initializer list that the child calls see, so that we don't try
    // to re-process the designator.
    unsigned OldIndex = Index;
    IList->setInit(OldIndex, DIE->getInit());

    CheckSubElementType(IList, CurrentObjectType, Index,
                        StructuredList, StructuredIndex);

    // Restore the designated initializer expression in the syntactic
    // form of the initializer list.
    if (IList->getInit(OldIndex) != DIE->getInit())
      DIE->setInit(IList->getInit(OldIndex));
    IList->setInit(OldIndex, DIE);

    return hadError && !prevHadError;
  }

  bool IsFirstDesignator = (DesigIdx == 0);
  assert((IsFirstDesignator || StructuredList) &&
         "Need a non-designated initializer list to start from");

  DesignatedInitExpr::Designator *D = DIE->getDesignator(DesigIdx);
  // Determine the structural initializer list that corresponds to the
  // current subobject.
  StructuredList = IsFirstDesignator? SyntacticToSemantic[IList]
    : getStructuredSubobjectInit(IList, Index, CurrentObjectType,
                                 StructuredList, StructuredIndex,
                                 SourceRange(D->getStartLocation(),
                                             DIE->getSourceRange().getEnd()));
  assert(StructuredList && "Expected a structured initializer list");

  if (D->isFieldDesignator()) {
    // C99 6.7.8p7:
    //
    //   If a designator has the form
    //
    //      . identifier
    //
    //   then the current object (defined below) shall have
    //   structure or union type and the identifier shall be the
    //   name of a member of that type.
    const RecordType *RT = CurrentObjectType->getAs<RecordType>();
    if (!RT) {
      SourceLocation Loc = D->getDotLoc();
      if (Loc.isInvalid())
        Loc = D->getFieldLoc();
      SemaRef.Diag(Loc, diag::err_field_designator_non_aggr)
        << SemaRef.getLangOptions().CPlusPlus << CurrentObjectType;
      ++Index;
      return true;
    }

    // Note: we perform a linear search of the fields here, despite
    // the fact that we have a faster lookup method, because we always
    // need to compute the field's index.
    FieldDecl *KnownField = D->getField();
    IdentifierInfo *FieldName = D->getFieldName();
    unsigned FieldIndex = 0;
    RecordDecl::field_iterator
      Field = RT->getDecl()->field_begin(),
      FieldEnd = RT->getDecl()->field_end();
    for (; Field != FieldEnd; ++Field) {
      if (Field->isUnnamedBitfield())
        continue;

      if (KnownField == *Field || Field->getIdentifier() == FieldName)
        break;

      ++FieldIndex;
    }

    if (Field == FieldEnd) {
      // There was no normal field in the struct with the designated
      // name. Perform another lookup for this name, which may find
      // something that we can't designate (e.g., a member function),
      // may find nothing, or may find a member of an anonymous
      // struct/union.
      DeclContext::lookup_result Lookup = RT->getDecl()->lookup(FieldName);
      if (Lookup.first == Lookup.second) {
        // Name lookup didn't find anything.
        SemaRef.Diag(D->getFieldLoc(), diag::err_field_designator_unknown)
          << FieldName << CurrentObjectType;
        ++Index;
        return true;
      } else if (!KnownField && isa<FieldDecl>(*Lookup.first) &&
                 cast<RecordDecl>((*Lookup.first)->getDeclContext())
                   ->isAnonymousStructOrUnion()) {
        // Handle an field designator that refers to a member of an
        // anonymous struct or union.
        ExpandAnonymousFieldDesignator(SemaRef, DIE, DesigIdx,
                                       cast<FieldDecl>(*Lookup.first),
                                       Field, FieldIndex);
        D = DIE->getDesignator(DesigIdx);
      } else {
        // Name lookup found something, but it wasn't a field.
        SemaRef.Diag(D->getFieldLoc(), diag::err_field_designator_nonfield)
          << FieldName;
        SemaRef.Diag((*Lookup.first)->getLocation(),
                      diag::note_field_designator_found);
        ++Index;
        return true;
      }
    } else if (!KnownField &&
               cast<RecordDecl>((*Field)->getDeclContext())
                 ->isAnonymousStructOrUnion()) {
      ExpandAnonymousFieldDesignator(SemaRef, DIE, DesigIdx, *Field,
                                     Field, FieldIndex);
      D = DIE->getDesignator(DesigIdx);
    }

    // All of the fields of a union are located at the same place in
    // the initializer list.
    if (RT->getDecl()->isUnion()) {
      FieldIndex = 0;
      StructuredList->setInitializedFieldInUnion(*Field);
    }

    // Update the designator with the field declaration.
    D->setField(*Field);

    // Make sure that our non-designated initializer list has space
    // for a subobject corresponding to this field.
    if (FieldIndex >= StructuredList->getNumInits())
      StructuredList->resizeInits(SemaRef.Context, FieldIndex + 1);

    // This designator names a flexible array member.
    if (Field->getType()->isIncompleteArrayType()) {
      bool Invalid = false;
      if ((DesigIdx + 1) != DIE->size()) {
        // We can't designate an object within the flexible array
        // member (because GCC doesn't allow it).
        DesignatedInitExpr::Designator *NextD
          = DIE->getDesignator(DesigIdx + 1);
        SemaRef.Diag(NextD->getStartLocation(),
                      diag::err_designator_into_flexible_array_member)
          << SourceRange(NextD->getStartLocation(),
                         DIE->getSourceRange().getEnd());
        SemaRef.Diag(Field->getLocation(), diag::note_flexible_array_member)
          << *Field;
        Invalid = true;
      }

      if (!hadError && !isa<InitListExpr>(DIE->getInit())) {
        // The initializer is not an initializer list.
        SemaRef.Diag(DIE->getInit()->getSourceRange().getBegin(),
                      diag::err_flexible_array_init_needs_braces)
          << DIE->getInit()->getSourceRange();
        SemaRef.Diag(Field->getLocation(), diag::note_flexible_array_member)
          << *Field;
        Invalid = true;
      }

      // Handle GNU flexible array initializers.
      if (!Invalid && !TopLevelObject &&
          cast<InitListExpr>(DIE->getInit())->getNumInits() > 0) {
        SemaRef.Diag(DIE->getSourceRange().getBegin(),
                      diag::err_flexible_array_init_nonempty)
          << DIE->getSourceRange().getBegin();
        SemaRef.Diag(Field->getLocation(), diag::note_flexible_array_member)
          << *Field;
        Invalid = true;
      }

      if (Invalid) {
        ++Index;
        return true;
      }

      // Initialize the array.
      bool prevHadError = hadError;
      unsigned newStructuredIndex = FieldIndex;
      unsigned OldIndex = Index;
      IList->setInit(Index, DIE->getInit());
      CheckSubElementType(IList, Field->getType(), Index,
                          StructuredList, newStructuredIndex);
      IList->setInit(OldIndex, DIE);
      if (hadError && !prevHadError) {
        ++Field;
        ++FieldIndex;
        if (NextField)
          *NextField = Field;
        StructuredIndex = FieldIndex;
        return true;
      }
    } else {
      // Recurse to check later designated subobjects.
      QualType FieldType = (*Field)->getType();
      unsigned newStructuredIndex = FieldIndex;
      if (CheckDesignatedInitializer(IList, DIE, DesigIdx + 1, FieldType, 0, 0,
                                     Index, StructuredList, newStructuredIndex,
                                     true, false))
        return true;
    }

    // Find the position of the next field to be initialized in this
    // subobject.
    ++Field;
    ++FieldIndex;

    // If this the first designator, our caller will continue checking
    // the rest of this struct/class/union subobject.
    if (IsFirstDesignator) {
      if (NextField)
        *NextField = Field;
      StructuredIndex = FieldIndex;
      return false;
    }

    if (!FinishSubobjectInit)
      return false;

    // We've already initialized something in the union; we're done.
    if (RT->getDecl()->isUnion())
      return hadError;

    // Check the remaining fields within this class/struct/union subobject.
    bool prevHadError = hadError;
    CheckStructUnionTypes(IList, CurrentObjectType, Field, false, Index,
                          StructuredList, FieldIndex);
    return hadError && !prevHadError;
  }

  // C99 6.7.8p6:
  //
  //   If a designator has the form
  //
  //      [ constant-expression ]
  //
  //   then the current object (defined below) shall have array
  //   type and the expression shall be an integer constant
  //   expression. If the array is of unknown size, any
  //   nonnegative value is valid.
  //
  // Additionally, cope with the GNU extension that permits
  // designators of the form
  //
  //      [ constant-expression ... constant-expression ]
  const ArrayType *AT = SemaRef.Context.getAsArrayType(CurrentObjectType);
  if (!AT) {
    SemaRef.Diag(D->getLBracketLoc(), diag::err_array_designator_non_array)
      << CurrentObjectType;
    ++Index;
    return true;
  }

  Expr *IndexExpr = 0;
  llvm::APSInt DesignatedStartIndex, DesignatedEndIndex;
  if (D->isArrayDesignator()) {
    IndexExpr = DIE->getArrayIndex(*D);
    DesignatedStartIndex = IndexExpr->EvaluateAsInt(SemaRef.Context);
    DesignatedEndIndex = DesignatedStartIndex;
  } else {
    assert(D->isArrayRangeDesignator() && "Need array-range designator");


    DesignatedStartIndex =
      DIE->getArrayRangeStart(*D)->EvaluateAsInt(SemaRef.Context);
    DesignatedEndIndex =
      DIE->getArrayRangeEnd(*D)->EvaluateAsInt(SemaRef.Context);
    IndexExpr = DIE->getArrayRangeEnd(*D);

    if (DesignatedStartIndex.getZExtValue() !=DesignatedEndIndex.getZExtValue())
      FullyStructuredList->sawArrayRangeDesignator();
  }

  if (isa<ConstantArrayType>(AT)) {
    llvm::APSInt MaxElements(cast<ConstantArrayType>(AT)->getSize(), false);
    DesignatedStartIndex.extOrTrunc(MaxElements.getBitWidth());
    DesignatedStartIndex.setIsUnsigned(MaxElements.isUnsigned());
    DesignatedEndIndex.extOrTrunc(MaxElements.getBitWidth());
    DesignatedEndIndex.setIsUnsigned(MaxElements.isUnsigned());
    if (DesignatedEndIndex >= MaxElements) {
      SemaRef.Diag(IndexExpr->getSourceRange().getBegin(),
                    diag::err_array_designator_too_large)
        << DesignatedEndIndex.toString(10) << MaxElements.toString(10)
        << IndexExpr->getSourceRange();
      ++Index;
      return true;
    }
  } else {
    // Make sure the bit-widths and signedness match.
    if (DesignatedStartIndex.getBitWidth() > DesignatedEndIndex.getBitWidth())
      DesignatedEndIndex.extend(DesignatedStartIndex.getBitWidth());
    else if (DesignatedStartIndex.getBitWidth() <
             DesignatedEndIndex.getBitWidth())
      DesignatedStartIndex.extend(DesignatedEndIndex.getBitWidth());
    DesignatedStartIndex.setIsUnsigned(true);
    DesignatedEndIndex.setIsUnsigned(true);
  }

  // Make sure that our non-designated initializer list has space
  // for a subobject corresponding to this array element.
  if (DesignatedEndIndex.getZExtValue() >= StructuredList->getNumInits())
    StructuredList->resizeInits(SemaRef.Context,
                                DesignatedEndIndex.getZExtValue() + 1);

  // Repeatedly perform subobject initializations in the range
  // [DesignatedStartIndex, DesignatedEndIndex].

  // Move to the next designator
  unsigned ElementIndex = DesignatedStartIndex.getZExtValue();
  unsigned OldIndex = Index;
  while (DesignatedStartIndex <= DesignatedEndIndex) {
    // Recurse to check later designated subobjects.
    QualType ElementType = AT->getElementType();
    Index = OldIndex;
    if (CheckDesignatedInitializer(IList, DIE, DesigIdx + 1, ElementType, 0, 0,
                                   Index, StructuredList, ElementIndex,
                                   (DesignatedStartIndex == DesignatedEndIndex),
                                   false))
      return true;

    // Move to the next index in the array that we'll be initializing.
    ++DesignatedStartIndex;
    ElementIndex = DesignatedStartIndex.getZExtValue();
  }

  // If this the first designator, our caller will continue checking
  // the rest of this array subobject.
  if (IsFirstDesignator) {
    if (NextElementIndex)
      *NextElementIndex = DesignatedStartIndex;
    StructuredIndex = ElementIndex;
    return false;
  }

  if (!FinishSubobjectInit)
    return false;

  // Check the remaining elements within this array subobject.
  bool prevHadError = hadError;
  CheckArrayType(IList, CurrentObjectType, DesignatedStartIndex, false, Index,
                 StructuredList, ElementIndex);
  return hadError && !prevHadError;
}

// Get the structured initializer list for a subobject of type
// @p CurrentObjectType.
InitListExpr *
InitListChecker::getStructuredSubobjectInit(InitListExpr *IList, unsigned Index,
                                            QualType CurrentObjectType,
                                            InitListExpr *StructuredList,
                                            unsigned StructuredIndex,
                                            SourceRange InitRange) {
  Expr *ExistingInit = 0;
  if (!StructuredList)
    ExistingInit = SyntacticToSemantic[IList];
  else if (StructuredIndex < StructuredList->getNumInits())
    ExistingInit = StructuredList->getInit(StructuredIndex);

  if (InitListExpr *Result = dyn_cast_or_null<InitListExpr>(ExistingInit))
    return Result;

  if (ExistingInit) {
    // We are creating an initializer list that initializes the
    // subobjects of the current object, but there was already an
    // initialization that completely initialized the current
    // subobject, e.g., by a compound literal:
    //
    // struct X { int a, b; };
    // struct X xs[] = { [0] = (struct X) { 1, 2 }, [0].b = 3 };
    //
    // Here, xs[0].a == 0 and xs[0].b == 3, since the second,
    // designated initializer re-initializes the whole
    // subobject [0], overwriting previous initializers.
    SemaRef.Diag(InitRange.getBegin(),
                 diag::warn_subobject_initializer_overrides)
      << InitRange;
    SemaRef.Diag(ExistingInit->getSourceRange().getBegin(),
                  diag::note_previous_initializer)
      << /*FIXME:has side effects=*/0
      << ExistingInit->getSourceRange();
  }

  InitListExpr *Result
    = new (SemaRef.Context) InitListExpr(InitRange.getBegin(), 0, 0,
                                         InitRange.getEnd());

  Result->setType(CurrentObjectType);

  // Pre-allocate storage for the structured initializer list.
  unsigned NumElements = 0;
  unsigned NumInits = 0;
  if (!StructuredList)
    NumInits = IList->getNumInits();
  else if (Index < IList->getNumInits()) {
    if (InitListExpr *SubList = dyn_cast<InitListExpr>(IList->getInit(Index)))
      NumInits = SubList->getNumInits();
  }

  if (const ArrayType *AType
      = SemaRef.Context.getAsArrayType(CurrentObjectType)) {
    if (const ConstantArrayType *CAType = dyn_cast<ConstantArrayType>(AType)) {
      NumElements = CAType->getSize().getZExtValue();
      // Simple heuristic so that we don't allocate a very large
      // initializer with many empty entries at the end.
      if (NumInits && NumElements > NumInits)
        NumElements = 0;
    }
  } else if (const VectorType *VType = CurrentObjectType->getAs<VectorType>())
    NumElements = VType->getNumElements();
  else if (const RecordType *RType = CurrentObjectType->getAs<RecordType>()) {
    RecordDecl *RDecl = RType->getDecl();
    if (RDecl->isUnion())
      NumElements = 1;
    else
      NumElements = std::distance(RDecl->field_begin(),
                                  RDecl->field_end());
  }

  if (NumElements < NumInits)
    NumElements = IList->getNumInits();

  Result->reserveInits(NumElements);

  // Link this new initializer list into the structured initializer
  // lists.
  if (StructuredList)
    StructuredList->updateInit(StructuredIndex, Result);
  else {
    Result->setSyntacticForm(IList);
    SyntacticToSemantic[IList] = Result;
  }

  return Result;
}

/// Update the initializer at index @p StructuredIndex within the
/// structured initializer list to the value @p expr.
void InitListChecker::UpdateStructuredListElement(InitListExpr *StructuredList,
                                                  unsigned &StructuredIndex,
                                                  Expr *expr) {
  // No structured initializer list to update
  if (!StructuredList)
    return;

  if (Expr *PrevInit = StructuredList->updateInit(StructuredIndex, expr)) {
    // This initializer overwrites a previous initializer. Warn.
    SemaRef.Diag(expr->getSourceRange().getBegin(),
                  diag::warn_initializer_overrides)
      << expr->getSourceRange();
    SemaRef.Diag(PrevInit->getSourceRange().getBegin(),
                  diag::note_previous_initializer)
      << /*FIXME:has side effects=*/0
      << PrevInit->getSourceRange();
  }

  ++StructuredIndex;
}

/// Check that the given Index expression is a valid array designator
/// value. This is essentailly just a wrapper around
/// VerifyIntegerConstantExpression that also checks for negative values
/// and produces a reasonable diagnostic if there is a
/// failure. Returns true if there was an error, false otherwise.  If
/// everything went okay, Value will receive the value of the constant
/// expression.
static bool
CheckArrayDesignatorExpr(Sema &S, Expr *Index, llvm::APSInt &Value) {
  SourceLocation Loc = Index->getSourceRange().getBegin();

  // Make sure this is an integer constant expression.
  if (S.VerifyIntegerConstantExpression(Index, &Value))
    return true;

  if (Value.isSigned() && Value.isNegative())
    return S.Diag(Loc, diag::err_array_designator_negative)
      << Value.toString(10) << Index->getSourceRange();

  Value.setIsUnsigned(true);
  return false;
}

Sema::OwningExprResult Sema::ActOnDesignatedInitializer(Designation &Desig,
                                                        SourceLocation Loc,
                                                        bool GNUSyntax,
                                                        OwningExprResult Init) {
  typedef DesignatedInitExpr::Designator ASTDesignator;

  bool Invalid = false;
  llvm::SmallVector<ASTDesignator, 32> Designators;
  llvm::SmallVector<Expr *, 32> InitExpressions;

  // Build designators and check array designator expressions.
  for (unsigned Idx = 0; Idx < Desig.getNumDesignators(); ++Idx) {
    const Designator &D = Desig.getDesignator(Idx);
    switch (D.getKind()) {
    case Designator::FieldDesignator:
      Designators.push_back(ASTDesignator(D.getField(), D.getDotLoc(),
                                          D.getFieldLoc()));
      break;

    case Designator::ArrayDesignator: {
      Expr *Index = static_cast<Expr *>(D.getArrayIndex());
      llvm::APSInt IndexValue;
      if (!Index->isTypeDependent() &&
          !Index->isValueDependent() &&
          CheckArrayDesignatorExpr(*this, Index, IndexValue))
        Invalid = true;
      else {
        Designators.push_back(ASTDesignator(InitExpressions.size(),
                                            D.getLBracketLoc(),
                                            D.getRBracketLoc()));
        InitExpressions.push_back(Index);
      }
      break;
    }

    case Designator::ArrayRangeDesignator: {
      Expr *StartIndex = static_cast<Expr *>(D.getArrayRangeStart());
      Expr *EndIndex = static_cast<Expr *>(D.getArrayRangeEnd());
      llvm::APSInt StartValue;
      llvm::APSInt EndValue;
      bool StartDependent = StartIndex->isTypeDependent() ||
                            StartIndex->isValueDependent();
      bool EndDependent = EndIndex->isTypeDependent() ||
                          EndIndex->isValueDependent();
      if ((!StartDependent &&
           CheckArrayDesignatorExpr(*this, StartIndex, StartValue)) ||
          (!EndDependent &&
           CheckArrayDesignatorExpr(*this, EndIndex, EndValue)))
        Invalid = true;
      else {
        // Make sure we're comparing values with the same bit width.
        if (StartDependent || EndDependent) {
          // Nothing to compute.
        } else if (StartValue.getBitWidth() > EndValue.getBitWidth())
          EndValue.extend(StartValue.getBitWidth());
        else if (StartValue.getBitWidth() < EndValue.getBitWidth())
          StartValue.extend(EndValue.getBitWidth());

        if (!StartDependent && !EndDependent && EndValue < StartValue) {
          Diag(D.getEllipsisLoc(), diag::err_array_designator_empty_range)
            << StartValue.toString(10) << EndValue.toString(10)
            << StartIndex->getSourceRange() << EndIndex->getSourceRange();
          Invalid = true;
        } else {
          Designators.push_back(ASTDesignator(InitExpressions.size(),
                                              D.getLBracketLoc(),
                                              D.getEllipsisLoc(),
                                              D.getRBracketLoc()));
          InitExpressions.push_back(StartIndex);
          InitExpressions.push_back(EndIndex);
        }
      }
      break;
    }
    }
  }

  if (Invalid || Init.isInvalid())
    return ExprError();

  // Clear out the expressions within the designation.
  Desig.ClearExprs(*this);

  DesignatedInitExpr *DIE
    = DesignatedInitExpr::Create(Context,
                                 Designators.data(), Designators.size(),
                                 InitExpressions.data(), InitExpressions.size(),
                                 Loc, GNUSyntax, Init.takeAs<Expr>());
  return Owned(DIE);
}

bool Sema::CheckInitList(InitListExpr *&InitList, QualType &DeclType) {
  InitListChecker CheckInitList(*this, InitList, DeclType);
  if (!CheckInitList.HadError())
    InitList = CheckInitList.getFullyStructuredList();

  return CheckInitList.HadError();
}

/// \brief Diagnose any semantic errors with value-initialization of
/// the given type.
///
/// Value-initialization effectively zero-initializes any types
/// without user-declared constructors, and calls the default
/// constructor for a for any type that has a user-declared
/// constructor (C++ [dcl.init]p5). Value-initialization can fail when
/// a type with a user-declared constructor does not have an
/// accessible, non-deleted default constructor. In C, everything can
/// be value-initialized, which corresponds to C's notion of
/// initializing objects with static storage duration when no
/// initializer is provided for that object.
///
/// \returns true if there was an error, false otherwise.
bool Sema::CheckValueInitialization(QualType Type, SourceLocation Loc) {
  // C++ [dcl.init]p5:
  //
  //   To value-initialize an object of type T means:

  //     -- if T is an array type, then each element is value-initialized;
  if (const ArrayType *AT = Context.getAsArrayType(Type))
    return CheckValueInitialization(AT->getElementType(), Loc);

  if (const RecordType *RT = Type->getAs<RecordType>()) {
    if (CXXRecordDecl *ClassDecl = dyn_cast<CXXRecordDecl>(RT->getDecl())) {
      // -- if T is a class type (clause 9) with a user-declared
      //    constructor (12.1), then the default constructor for T is
      //    called (and the initialization is ill-formed if T has no
      //    accessible default constructor);
      if (ClassDecl->hasUserDeclaredConstructor()) {
        ASTOwningVector<&ActionBase::DeleteExpr> ConstructorArgs(*this);

        // FIXME: Poor location information
        CXXConstructorDecl *Constructor
          = PerformInitializationByConstructor(Type, 
                                               MultiExprArg(*this, 0, 0),
                                               Loc, SourceRange(Loc),
                                               DeclarationName(),
                                 InitializationKind::CreateValue(Loc, Loc, Loc),
                                               ConstructorArgs);
        if (!Constructor)
          return true;
        
        OwningExprResult Init
          = BuildCXXConstructExpr(Loc, Type, Constructor,
                                  move_arg(ConstructorArgs));
        if (Init.isInvalid())
          return true;
        
        // FIXME: Actually perform the value-initialization!
        return false;
      }
    }
  }

  if (Type->isReferenceType()) {
    // C++ [dcl.init]p5:
    //   [...] A program that calls for default-initialization or
    //   value-initialization of an entity of reference type is
    //   ill-formed. [...]
    // FIXME: Once we have code that goes through this path, add an actual
    // diagnostic :)
  }

  return false;
}

//===----------------------------------------------------------------------===//
// Initialization entity
//===----------------------------------------------------------------------===//

void InitializedEntity::InitDeclLoc() {
  assert((Kind == EK_Variable || Kind == EK_Parameter || Kind == EK_Member) &&
         "InitDeclLoc cannot be used with non-declaration entities.");
  
  if (TypeSourceInfo *DI = VariableOrMember->getTypeSourceInfo()) {
    TL = DI->getTypeLoc();
    return;
  }
  
  // FIXME: Once we've gone through the effort to create the fake 
  // TypeSourceInfo, should we cache it in the declaration?
  // (If not, we "leak" it).
  TypeSourceInfo *DI = VariableOrMember->getASTContext()
                             .CreateTypeSourceInfo(VariableOrMember->getType());
  DI->getTypeLoc().initialize(VariableOrMember->getLocation());
  TL = DI->getTypeLoc();
}

InitializedEntity InitializedEntity::InitializeBase(ASTContext &Context, 
                                                    CXXBaseSpecifier *Base)
{
  InitializedEntity Result;
  Result.Kind = EK_Base;
  Result.Base = Base;
  // FIXME: CXXBaseSpecifier should store a TypeLoc.
  TypeSourceInfo *DI = Context.CreateTypeSourceInfo(Base->getType());
  DI->getTypeLoc().initialize(Base->getSourceRange().getBegin());
  Result.TL = DI->getTypeLoc();
  return Result;
}

//===----------------------------------------------------------------------===//
// Initialization sequence
//===----------------------------------------------------------------------===//

void InitializationSequence::Step::Destroy() {
  switch (Kind) {
  case SK_ResolveAddressOfOverloadedFunction:
  case SK_CastDerivedToBaseRValue:
  case SK_CastDerivedToBaseLValue:
  case SK_BindReference:
  case SK_BindReferenceToTemporary:
  case SK_UserConversion:
  case SK_QualificationConversionRValue:
  case SK_QualificationConversionLValue:
    break;
    
  case SK_ConversionSequence:
    delete ICS;
  }
}

void InitializationSequence::AddAddressOverloadResolutionStep(
                                                      FunctionDecl *Function) {
  Step S;
  S.Kind = SK_ResolveAddressOfOverloadedFunction;
  S.Type = Function->getType();
  S.Function = Function;
  Steps.push_back(S);
}

void InitializationSequence::AddDerivedToBaseCastStep(QualType BaseType, 
                                                      bool IsLValue) {
  Step S;
  S.Kind = IsLValue? SK_CastDerivedToBaseLValue : SK_CastDerivedToBaseRValue;
  S.Type = BaseType;
  Steps.push_back(S);
}

void InitializationSequence::AddReferenceBindingStep(QualType T, 
                                                     bool BindingTemporary) {
  Step S;
  S.Kind = BindingTemporary? SK_BindReferenceToTemporary : SK_BindReference;
  S.Type = T;
  Steps.push_back(S);
}

void InitializationSequence::AddUserConversionStep(FunctionDecl *Function) {
  Step S;
  S.Kind = SK_UserConversion;
  S.Type = Function->getResultType().getNonReferenceType();
  S.Function = Function;
  Steps.push_back(S);
}

void InitializationSequence::AddQualificationConversionStep(QualType Ty,
                                                            bool IsLValue) {
  Step S;
  S.Kind = IsLValue? SK_QualificationConversionLValue 
                   : SK_QualificationConversionRValue;
  S.Type = Ty;
  Steps.push_back(S);
}

void InitializationSequence::AddConversionSequenceStep(
                                       const ImplicitConversionSequence &ICS,
                                                       QualType T) {
  Step S;
  S.Kind = SK_ConversionSequence;
  S.Type = T;
  S.ICS = new ImplicitConversionSequence(ICS);
  Steps.push_back(S);
}

void InitializationSequence::SetOverloadFailure(FailureKind Failure, 
                                                OverloadingResult Result) {
  SequenceKind = FailedSequence;
  this->Failure = Failure;
  this->FailedOverloadResult = Result;
}

//===----------------------------------------------------------------------===//
// Attempt initialization
//===----------------------------------------------------------------------===//

/// \brief Attempt list initialization (C++0x [dcl.init.list]) 
static bool TryListInitialization(Sema &S, 
                                  const InitializedEntity &Entity,
                                  const InitializationKind &Kind,
                                  InitListExpr *InitList,
                                  InitializationSequence &Sequence) {
  // FIXME: For now, it is safe to assume that list initialization always
  // works. When we actually perform list initialization, we'll do all of the
  // necessary checking.
  // C++0x initializer lists will force us to perform more checking here.
  return true;
}

/// \brief Try a reference initialization that involves calling a conversion
/// function.
///
/// FIXME: look intos DRs 656, 896
static OverloadingResult TryRefInitWithConversionFunction(Sema &S,
                                             const InitializedEntity &Entity,
                                             const InitializationKind &Kind,
                                                          Expr *Initializer,
                                                          bool AllowRValues,
                                             InitializationSequence &Sequence) {
  QualType DestType = Entity.getType().getType();
  QualType cv1T1 = DestType->getAs<ReferenceType>()->getPointeeType();
  QualType T1 = cv1T1.getUnqualifiedType();
  QualType cv2T2 = Initializer->getType();
  QualType T2 = cv2T2.getUnqualifiedType();

  bool DerivedToBase;
  assert(!S.CompareReferenceRelationship(Initializer->getLocStart(), 
                                         T1, T2, DerivedToBase) &&
         "Must have incompatible references when binding via conversion");

  // Build the candidate set directly in the initialization sequence
  // structure, so that it will persist if we fail.
  OverloadCandidateSet &CandidateSet = Sequence.getFailedCandidateSet();
  CandidateSet.clear();

  // Determine whether we are allowed to call explicit constructors or
  // explicit conversion operators.
  bool AllowExplicit = Kind.getKind() == InitializationKind::IK_Direct;
  
  const RecordType *T1RecordType = 0;
  if (AllowRValues && (T1RecordType = T1->getAs<RecordType>())) {
    // The type we're converting to is a class type. Enumerate its constructors
    // to see if there is a suitable conversion.
    CXXRecordDecl *T1RecordDecl = cast<CXXRecordDecl>(T1RecordType->getDecl());
    
    DeclarationName ConstructorName
      = S.Context.DeclarationNames.getCXXConstructorName(
                           S.Context.getCanonicalType(T1).getUnqualifiedType());
    DeclContext::lookup_iterator Con, ConEnd;
    for (llvm::tie(Con, ConEnd) = T1RecordDecl->lookup(ConstructorName);
         Con != ConEnd; ++Con) {
      // Find the constructor (which may be a template).
      CXXConstructorDecl *Constructor = 0;
      FunctionTemplateDecl *ConstructorTmpl
        = dyn_cast<FunctionTemplateDecl>(*Con);
      if (ConstructorTmpl)
        Constructor = cast<CXXConstructorDecl>(
                                         ConstructorTmpl->getTemplatedDecl());
      else
        Constructor = cast<CXXConstructorDecl>(*Con);
      
      if (!Constructor->isInvalidDecl() &&
          Constructor->isConvertingConstructor(AllowExplicit)) {
        if (ConstructorTmpl)
          S.AddTemplateOverloadCandidate(ConstructorTmpl, /*ExplicitArgs*/ 0,
                                         &Initializer, 1, CandidateSet);
        else
          S.AddOverloadCandidate(Constructor, &Initializer, 1, CandidateSet);
      }
    }    
  }
  
  if (const RecordType *T2RecordType = T2->getAs<RecordType>()) {
    // The type we're converting from is a class type, enumerate its conversion
    // functions.
    CXXRecordDecl *T2RecordDecl = cast<CXXRecordDecl>(T2RecordType->getDecl());

    // Determine the type we are converting to. If we are allowed to
    // convert to an rvalue, take the type that the destination type
    // refers to.
    QualType ToType = AllowRValues? cv1T1 : DestType;

    const UnresolvedSet *Conversions
      = T2RecordDecl->getVisibleConversionFunctions();
    for (UnresolvedSet::iterator I = Conversions->begin(),
         E = Conversions->end(); 
         I != E; ++I) {
      NamedDecl *D = *I;
      CXXRecordDecl *ActingDC = cast<CXXRecordDecl>(D->getDeclContext());
      if (isa<UsingShadowDecl>(D))
        D = cast<UsingShadowDecl>(D)->getTargetDecl();
      
      FunctionTemplateDecl *ConvTemplate = dyn_cast<FunctionTemplateDecl>(D);
      CXXConversionDecl *Conv;
      if (ConvTemplate)
        Conv = cast<CXXConversionDecl>(ConvTemplate->getTemplatedDecl());
      else
        Conv = cast<CXXConversionDecl>(*I);
      
      // If the conversion function doesn't return a reference type,
      // it can't be considered for this conversion unless we're allowed to
      // consider rvalues.
      // FIXME: Do we need to make sure that we only consider conversion 
      // candidates with reference-compatible results? That might be needed to 
      // break recursion.
      if ((AllowExplicit || !Conv->isExplicit()) &&
          (AllowRValues || Conv->getConversionType()->isLValueReferenceType())){
        if (ConvTemplate)
          S.AddTemplateConversionCandidate(ConvTemplate, ActingDC, Initializer,
                                           ToType, CandidateSet);
        else
          S.AddConversionCandidate(Conv, ActingDC, Initializer, cv1T1,
                                   CandidateSet);
      }
    }
  }
  
  SourceLocation DeclLoc = Initializer->getLocStart();

  // Perform overload resolution. If it fails, return the failed result.  
  OverloadCandidateSet::iterator Best;
  if (OverloadingResult Result 
        = S.BestViableFunction(CandidateSet, DeclLoc, Best))
    return Result;
  
  // Add the user-defined conversion step.
  FunctionDecl *Function = Best->Function;
  Sequence.AddUserConversionStep(Function);
  
  // Determine whether we need to perform derived-to-base or 
  // cv-qualification adjustments.
  if (isa<CXXConversionDecl>(Function))
    T2 = Function->getResultType();
  else
    T2 = cv1T1;
    
  bool NewDerivedToBase = false;
  Sema::ReferenceCompareResult NewRefRelationship
    = S.CompareReferenceRelationship(DeclLoc, T1, T2.getNonReferenceType(),
                                     NewDerivedToBase);
  assert(NewRefRelationship != Sema::Ref_Incompatible &&
         "Overload resolution picked a bad conversion function");
  (void)NewRefRelationship;
  if (NewDerivedToBase)
    Sequence.AddDerivedToBaseCastStep(
                                S.Context.getQualifiedType(T1,
                                  T2.getNonReferenceType().getQualifiers()), 
                                  /*isLValue=*/true);
  
  if (cv1T1.getQualifiers() != T2.getNonReferenceType().getQualifiers())
    Sequence.AddQualificationConversionStep(cv1T1, T2->isReferenceType());
  
  Sequence.AddReferenceBindingStep(cv1T1, !T2->isReferenceType());
  return OR_Success;
}
  
/// \brief Attempt reference initialization (C++0x [dcl.init.list]) 
static void TryReferenceInitialization(Sema &S, 
                                       const InitializedEntity &Entity,
                                       const InitializationKind &Kind,
                                       Expr *Initializer,
                                       InitializationSequence &Sequence) {
  Sequence.setSequenceKind(InitializationSequence::ReferenceBinding);
  
  QualType DestType = Entity.getType().getType();
  QualType cv1T1 = DestType->getAs<ReferenceType>()->getPointeeType();
  QualType T1 = cv1T1.getUnqualifiedType();
  QualType cv2T2 = Initializer->getType();
  QualType T2 = cv2T2.getUnqualifiedType();
  SourceLocation DeclLoc = Initializer->getLocStart();
  
  // If the initializer is the address of an overloaded function, try
  // to resolve the overloaded function. If all goes well, T2 is the
  // type of the resulting function.
  if (S.Context.getCanonicalType(T2) == S.Context.OverloadTy) {
    FunctionDecl *Fn = S.ResolveAddressOfOverloadedFunction(Initializer, 
                                                            T1,
                                                            false);
    if (!Fn) {
      Sequence.SetFailed(InitializationSequence::FK_AddressOfOverloadFailed);
      return;
    }
    
    Sequence.AddAddressOverloadResolutionStep(Fn);
    cv2T2 = Fn->getType();
    T2 = cv2T2.getUnqualifiedType();
  }
  
  // FIXME: Rvalue references
  bool ForceRValue = false;
  
  // Compute some basic properties of the types and the initializer.
  bool isLValueRef = DestType->isLValueReferenceType();
  bool isRValueRef = !isLValueRef;
  bool DerivedToBase = false;
  Expr::isLvalueResult InitLvalue = ForceRValue ? Expr::LV_InvalidExpression :
                                    Initializer->isLvalue(S.Context);
  Sema::ReferenceCompareResult RefRelationship
    = S.CompareReferenceRelationship(DeclLoc, cv1T1, cv2T2, DerivedToBase);
  
  // C++0x [dcl.init.ref]p5:
  //   A reference to type "cv1 T1" is initialized by an expression of type 
  //   "cv2 T2" as follows:
  //
  //     - If the reference is an lvalue reference and the initializer 
  //       expression
  OverloadingResult ConvOvlResult = OR_Success;
  if (isLValueRef) {
    if (InitLvalue == Expr::LV_Valid && 
        RefRelationship >= Sema::Ref_Compatible_With_Added_Qualification) {
      //   - is an lvalue (but is not a bit-field), and "cv1 T1" is 
      //     reference-compatible with "cv2 T2," or
      //
      // Per C++ [over.best.ics]p2, we ignore whether the lvalue is a 
      // bit-field when we're determining whether the reference initialization
      // can occur. This property will be checked by PerformInitialization.
      if (DerivedToBase)
        Sequence.AddDerivedToBaseCastStep(
                         S.Context.getQualifiedType(T1, cv2T2.getQualifiers()), 
                         /*isLValue=*/true);
      if (cv1T1.getQualifiers() != cv2T2.getQualifiers())
        Sequence.AddQualificationConversionStep(cv1T1, /*IsLValue=*/true);
      Sequence.AddReferenceBindingStep(cv1T1, /*bindingTemporary=*/false);
      return;
    }
    
    //     - has a class type (i.e., T2 is a class type), where T1 is not 
    //       reference-related to T2, and can be implicitly converted to an 
    //       lvalue of type "cv3 T3," where "cv1 T1" is reference-compatible 
    //       with "cv3 T3" (this conversion is selected by enumerating the 
    //       applicable conversion functions (13.3.1.6) and choosing the best
    //       one through overload resolution (13.3)),
    if (RefRelationship == Sema::Ref_Incompatible && T2->isRecordType()) {
      ConvOvlResult = TryRefInitWithConversionFunction(S, Entity, Kind, 
                                                       Initializer,
                                                       /*AllowRValues=*/false,
                                                       Sequence);
      if (ConvOvlResult == OR_Success)
        return;
    }
  }
  
  //     - Otherwise, the reference shall be an lvalue reference to a 
  //       non-volatile const type (i.e., cv1 shall be const), or the reference
  //       shall be an rvalue reference and the initializer expression shall 
  //       be an rvalue.
  if (!((isLValueRef && cv1T1.getCVRQualifiers() == Qualifiers::Const) ||
        (isRValueRef && InitLvalue != Expr::LV_Valid))) {
    if (ConvOvlResult && !Sequence.getFailedCandidateSet().empty())
      Sequence.SetOverloadFailure(
                        InitializationSequence::FK_ReferenceInitOverloadFailed,
                                  ConvOvlResult);
    else if (isLValueRef)
      Sequence.SetFailed(InitLvalue == Expr::LV_Valid
        ? (RefRelationship == Sema::Ref_Related
             ? InitializationSequence::FK_ReferenceInitDropsQualifiers
             : InitializationSequence::FK_NonConstLValueReferenceBindingToUnrelated)
        : InitializationSequence::FK_NonConstLValueReferenceBindingToTemporary);
    else
      Sequence.SetFailed(
                    InitializationSequence::FK_RValueReferenceBindingToLValue);
    
    return;
  }
  
  //       - If T1 and T2 are class types and
  if (T1->isRecordType() && T2->isRecordType()) {
    //       - the initializer expression is an rvalue and "cv1 T1" is 
    //         reference-compatible with "cv2 T2", or
    if (InitLvalue != Expr::LV_Valid && 
        RefRelationship >= Sema::Ref_Compatible_With_Added_Qualification) {
      if (DerivedToBase)
        Sequence.AddDerivedToBaseCastStep(
                         S.Context.getQualifiedType(T1, cv2T2.getQualifiers()), 
                         /*isLValue=*/false);
      if (cv1T1.getQualifiers() != cv2T2.getQualifiers())
        Sequence.AddQualificationConversionStep(cv1T1, /*IsLValue=*/false);
      Sequence.AddReferenceBindingStep(cv1T1, /*bindingTemporary=*/true);
      return;
    }
    
    //       - T1 is not reference-related to T2 and the initializer expression
    //         can be implicitly converted to an rvalue of type "cv3 T3" (this
    //         conversion is selected by enumerating the applicable conversion
    //         functions (13.3.1.6) and choosing the best one through overload 
    //         resolution (13.3)),
    if (RefRelationship == Sema::Ref_Incompatible) {
      ConvOvlResult = TryRefInitWithConversionFunction(S, Entity,
                                                       Kind, Initializer,
                                                       /*AllowRValues=*/true,
                                                       Sequence);
      if (ConvOvlResult)
        Sequence.SetOverloadFailure(
                      InitializationSequence::FK_ReferenceInitOverloadFailed,
                                    ConvOvlResult);
        
      return;
    }
    
    Sequence.SetFailed(InitializationSequence::FK_ReferenceInitDropsQualifiers);
    return;
  }
  
  //      - If the initializer expression is an rvalue, with T2 an array type,
  //        and "cv1 T1" is reference-compatible with "cv2 T2," the reference
  //        is bound to the object represented by the rvalue (see 3.10).
  // FIXME: How can an array type be reference-compatible with anything?
  // Don't we mean the element types of T1 and T2?
  
  //      - Otherwise, a temporary of type “cv1 T1” is created and initialized
  //        from the initializer expression using the rules for a non-reference
  //        copy initialization (8.5). The reference is then bound to the 
  //        temporary. [...]
  // Determine whether we are allowed to call explicit constructors or
  // explicit conversion operators.
  bool AllowExplicit = (Kind.getKind() == InitializationKind::IK_Direct);
  ImplicitConversionSequence ICS
    = S.TryImplicitConversion(Initializer, cv1T1,
                              /*SuppressUserConversions=*/false, AllowExplicit, 
                              /*ForceRValue=*/false, 
                              /*FIXME:InOverloadResolution=*/false,
                              /*UserCast=*/Kind.isExplicitCast());
            
  if (ICS.ConversionKind == ImplicitConversionSequence::BadConversion) {
    // FIXME: Use the conversion function set stored in ICS to turn
    // this into an overloading ambiguity diagnostic. However, we need
    // to keep that set as an OverloadCandidateSet rather than as some
    // other kind of set.
    Sequence.SetFailed(InitializationSequence::FK_ReferenceInitFailed);
    return;
  }

  //        [...] If T1 is reference-related to T2, cv1 must be the
  //        same cv-qualification as, or greater cv-qualification
  //        than, cv2; otherwise, the program is ill-formed.
  if (RefRelationship == Sema::Ref_Related && 
      !cv1T1.isAtLeastAsQualifiedAs(cv2T2)) {
    Sequence.SetFailed(InitializationSequence::FK_ReferenceInitDropsQualifiers);
    return;
  }

  // Perform the actual conversion.
  Sequence.AddConversionSequenceStep(ICS, cv1T1);
  Sequence.AddReferenceBindingStep(cv1T1, /*bindingTemporary=*/true);
  return;
}

/// \brief Attempt character array initialization from a string literal
/// (C++ [dcl.init.string], C99 6.7.8). 
static void TryStringLiteralInitialization(Sema &S, 
                                           const InitializedEntity &Entity,
                                           const InitializationKind &Kind,
                                           Expr *Initializer,
                                       InitializationSequence &Sequence) {
  // FIXME: Implement!
}

/// \brief Attempt value initialization (C++ [dcl.init]p7).
static void TryValueInitialization(Sema &S, 
                                   const InitializedEntity &Entity,
                                   const InitializationKind &Kind,
                                   InitializationSequence &Sequence) {
  // FIXME: Implement!
}

/// \brief Attempt initialization by constructor (C++ [dcl.init]), which
/// enumerates the constructors of the initialized entity and performs overload
/// resolution to select the best.
static void TryConstructorInitialization(Sema &S, 
                                         const InitializedEntity &Entity,
                                         const InitializationKind &Kind,
                                         Expr **Args, unsigned NumArgs,
                                         InitializationSequence &Sequence) {
  // FIXME: Implement!
}

/// \brief Attempt a user-defined conversion between two types (C++ [dcl.init]),
/// which enumerates all conversion functions and performs overload resolution
/// to select the best.
static void TryUserDefinedConversion(Sema &S, 
                                     const InitializedEntity &Entity,
                                     const InitializationKind &Kind,
                                     Expr *Initializer,
                                     InitializationSequence &Sequence) {
  // FIXME: Implement!
}

/// \brief Attempt an implicit conversion (C++ [conv]) converting from one
/// non-class type to another.
static void TryImplicitConversion(Sema &S, 
                                  const InitializedEntity &Entity,
                                  const InitializationKind &Kind,
                                  Expr *Initializer,
                                  InitializationSequence &Sequence) {
  ImplicitConversionSequence ICS
    = S.TryImplicitConversion(Initializer, Entity.getType().getType(),
                              /*SuppressUserConversions=*/true, 
                              /*AllowExplicit=*/false,
                              /*ForceRValue=*/false, 
                              /*FIXME:InOverloadResolution=*/false,
                              /*UserCast=*/Kind.isExplicitCast());
  
  if (ICS.ConversionKind == ImplicitConversionSequence::BadConversion) {
    Sequence.SetFailed(InitializationSequence::FK_ConversionFailed);
    return;
  }
  
  Sequence.AddConversionSequenceStep(ICS, Entity.getType().getType());
}

InitializationSequence::InitializationSequence(Sema &S,
                                               const InitializedEntity &Entity,
                                               const InitializationKind &Kind,
                                               Expr **Args,
                                               unsigned NumArgs) {
  ASTContext &Context = S.Context;
  
  // C++0x [dcl.init]p16:
  //   The semantics of initializers are as follows. The destination type is 
  //   the type of the object or reference being initialized and the source 
  //   type is the type of the initializer expression. The source type is not
  //   defined when the initializer is a braced-init-list or when it is a 
  //   parenthesized list of expressions.
  QualType DestType = Entity.getType().getType();

  if (DestType->isDependentType() ||
      Expr::hasAnyTypeDependentArguments(Args, NumArgs)) {
    SequenceKind = DependentSequence;
    return;
  }

  QualType SourceType;
  Expr *Initializer = 0;
  if (Kind.getKind() == InitializationKind::IK_Copy) {
    Initializer = Args[0];
    if (!isa<InitListExpr>(Initializer))
      SourceType = Initializer->getType();
  }
  
  //     - If the initializer is a braced-init-list, the object is 
  //       list-initialized (8.5.4).
  if (InitListExpr *InitList = dyn_cast_or_null<InitListExpr>(Initializer)) {
    TryListInitialization(S, Entity, Kind, InitList, *this);
  }
  
  //     - If the destination type is a reference type, see 8.5.3.
  if (DestType->isReferenceType()) {
    // C++0x [dcl.init.ref]p1:
    //   A variable declared to be a T& or T&&, that is, "reference to type T"
    //   (8.3.2), shall be initialized by an object, or function, of type T or
    //   by an object that can be converted into a T.
    // (Therefore, multiple arguments are not permitted.)
    if (NumArgs != 1)
      SetFailed(FK_TooManyInitsForReference);
    else
      TryReferenceInitialization(S, Entity, Kind, Args[0], *this);
    return;
  }
  
  //     - If the destination type is an array of characters, an array of 
  //       char16_t, an array of char32_t, or an array of wchar_t, and the 
  //       initializer is a string literal, see 8.5.2.
  if (Initializer && IsStringInit(Initializer, DestType, Context)) {
    TryStringLiteralInitialization(S, Entity, Kind, Initializer, *this);
    return;
  }
  
  //     - If the initializer is (), the object is value-initialized.
  if (Kind.getKind() == InitializationKind::IK_Value) {
    TryValueInitialization(S, Entity, Kind, *this);
    return;
  }
  
  //     - Otherwise, if the destination type is an array, the program is 
  //       ill-formed.
  if (const ArrayType *AT = Context.getAsArrayType(DestType)) {
    if (AT->getElementType()->isAnyCharacterType())
      SetFailed(FK_ArrayNeedsInitListOrStringLiteral);
    else
      SetFailed(FK_ArrayNeedsInitList);
    
    return;
  }
  
  //     - If the destination type is a (possibly cv-qualified) class type:
  if (DestType->isRecordType()) {
    //     - If the initialization is direct-initialization, or if it is 
    //       copy-initialization where the cv-unqualified version of the 
    //       source type is the same class as, or a derived class of, the 
    //       class of the destination, constructors are considered. [...]
    if (Kind.getKind() == InitializationKind::IK_Direct ||
        (Kind.getKind() == InitializationKind::IK_Copy &&
         (Context.hasSameUnqualifiedType(SourceType, DestType) ||
          S.IsDerivedFrom(SourceType, DestType))))
      TryConstructorInitialization(S, Entity, Kind, Args, NumArgs, *this);
    //     - Otherwise (i.e., for the remaining copy-initialization cases), 
    //       user-defined conversion sequences that can convert from the source
    //       type to the destination type or (when a conversion function is 
    //       used) to a derived class thereof are enumerated as described in
    //       13.3.1.4, and the best one is chosen through overload resolution
    //       (13.3).
    else
      TryUserDefinedConversion(S, Entity, Kind, Initializer, *this);
    return;
  }
  
  //    - Otherwise, if the source type is a (possibly cv-qualified) class 
  //      type, conversion functions are considered.
  if (SourceType->isRecordType()) {
    TryUserDefinedConversion(S, Entity, Kind, Initializer, *this);
    return;
  }
  
  //    - Otherwise, the initial value of the object being initialized is the
  //      (possibly converted) value of the ini- tializer expression. Standard
  //      conversions (Clause 4) will be used, if necessary, to convert the
  //      initializer expression to the cv-unqualified version of the 
  //      destination type; no user-defined conversions are considered.
  TryImplicitConversion(S, Entity, Kind, Initializer, *this);
}

InitializationSequence::~InitializationSequence() {
  for (llvm::SmallVectorImpl<Step>::iterator Step = Steps.begin(),
                                          StepEnd = Steps.end();
       Step != StepEnd; ++Step)
    Step->Destroy();
}

//===----------------------------------------------------------------------===//
// Perform initialization
//===----------------------------------------------------------------------===//

Action::OwningExprResult 
InitializationSequence::Perform(Sema &S,
                                const InitializedEntity &Entity,
                                const InitializationKind &Kind,
                                Action::MultiExprArg Args) {
  if (SequenceKind == FailedSequence) {
    unsigned NumArgs = Args.size();
    Diagnose(S, Entity, Kind, (Expr **)Args.release(), NumArgs);
    return S.ExprError();
  }
  
  if (SequenceKind == DependentSequence) {
    if (Kind.getKind() == InitializationKind::IK_Copy)
      return Sema::OwningExprResult(S, Args.release()[0]);

    unsigned NumArgs = Args.size();
    return S.Owned(new (S.Context) ParenListExpr(S.Context,
                                                 SourceLocation(),
                                                 (Expr **)Args.release(), 
                                                 NumArgs,
                                                 SourceLocation()));
  }

  QualType DestType = Entity.getType().getType().getNonReferenceType();

  Sema::OwningExprResult CurInit(S);
  // For copy initialization and any other initialization forms that
  // only have a single initializer, we start with the (only)
  // initializer we have.
  // FIXME: DPG is not happy about this. There's confusion regarding whether
  // we're supposed to start the conversion from the solitary initializer or
  // from the set of arguments.
  if (Kind.getKind() == InitializationKind::IK_Copy ||
      SequenceKind == ReferenceBinding) {
    assert(Args.size() == 1);
    CurInit = Sema::OwningExprResult(S, Args.release()[0]);
    if (CurInit.isInvalid())
      return S.ExprError();
  }
    
  // Walk through the computed steps for the initialization sequence, 
  // performing the specified conversions along the way.
  for (step_iterator Step = step_begin(), StepEnd = step_end();
       Step != StepEnd; ++Step) {
    if (CurInit.isInvalid())
      return S.ExprError();
    
    Expr *CurInitExpr = (Expr *)CurInit.get();
    QualType SourceType = CurInitExpr->getType();
    
    switch (Step->Kind) {
    case SK_ResolveAddressOfOverloadedFunction:
      // Overload resolution determined which function invoke; update the 
      // initializer to reflect that choice.
      CurInit = S.FixOverloadedFunctionReference(move(CurInit), Step->Function);
      break;
        
    case SK_CastDerivedToBaseRValue:
    case SK_CastDerivedToBaseLValue: {
      // We have a derived-to-base cast that produces either an rvalue or an
      // lvalue. Perform that cast.
      
      // Casts to inaccessible base classes are allowed with C-style casts.
      bool IgnoreBaseAccess = Kind.isCStyleOrFunctionalCast();
      if (S.CheckDerivedToBaseConversion(SourceType, Step->Type,
                                         CurInitExpr->getLocStart(),
                                         CurInitExpr->getSourceRange(),
                                         IgnoreBaseAccess))
        return S.ExprError();
        
      CurInit = S.Owned(new (S.Context) ImplicitCastExpr(Step->Type,
                                                    CastExpr::CK_DerivedToBase,
                                                      (Expr*)CurInit.release(),
                                     Step->Kind == SK_CastDerivedToBaseLValue));
      break;
    }
        
    case SK_BindReference:
      if (FieldDecl *BitField = CurInitExpr->getBitField()) {
        // References cannot bind to bit fields (C++ [dcl.init.ref]p5).
        S.Diag(Kind.getLocation(), diag::err_reference_bind_to_bitfield)
          << Entity.getType().getType().isVolatileQualified()
          << BitField->getDeclName()
          << CurInitExpr->getSourceRange();
        S.Diag(BitField->getLocation(), diag::note_bitfield_decl);
        return S.ExprError();
      }
        
      // Reference binding does not have any corresponding ASTs.

      // Check exception specifications
      if (S.CheckExceptionSpecCompatibility(CurInitExpr, DestType))
        return S.ExprError();
      break;
        
    case SK_BindReferenceToTemporary:
      // Check exception specifications
      if (S.CheckExceptionSpecCompatibility(CurInitExpr, DestType))
        return S.ExprError();

      // FIXME: At present, we have no AST to describe when we need to make a
      // temporary to bind a reference to. We should.
      break;
        
    case SK_UserConversion: {
      // We have a user-defined conversion that invokes either a constructor
      // or a conversion function.
      CastExpr::CastKind CastKind = CastExpr::CK_Unknown;
      if (CXXConstructorDecl *Constructor
                              = dyn_cast<CXXConstructorDecl>(Step->Function)) {
        // Build a call to the selected constructor.
        ASTOwningVector<&ActionBase::DeleteExpr> ConstructorArgs(S);
        SourceLocation Loc = CurInitExpr->getLocStart();
        CurInit.release(); // Ownership transferred into MultiExprArg, below.
        
        // Determine the arguments required to actually perform the constructor
        // call.
        if (S.CompleteConstructorCall(Constructor,
                                      Sema::MultiExprArg(S, 
                                                         (void **)&CurInitExpr,
                                                         1),
                                      Loc, ConstructorArgs))
          return S.ExprError();
        
        // Build the an expression that constructs a temporary.
        CurInit = S.BuildCXXConstructExpr(Loc, Step->Type, Constructor, 
                                          move_arg(ConstructorArgs));
        if (CurInit.isInvalid())
          return S.ExprError();
        
        CastKind = CastExpr::CK_ConstructorConversion;
      } else {
        // Build a call to the conversion function.
        CXXConversionDecl *Conversion = cast<CXXConversionDecl>(Step->Function);
        
        // FIXME: Should we move this initialization into a separate 
        // derived-to-base conversion? I believe the answer is "no", because
        // we don't want to turn off access control here for c-style casts.
        if (S.PerformObjectArgumentInitialization(CurInitExpr, Conversion))
          return S.ExprError();

        // Do a little dance to make sure that CurInit has the proper
        // pointer.
        CurInit.release();
        
        // Build the actual call to the conversion function.
        CurInit = S.Owned(S.BuildCXXMemberCallExpr(CurInitExpr, Conversion));
        if (CurInit.isInvalid() || !CurInit.get())
          return S.ExprError();
        
        CastKind = CastExpr::CK_UserDefinedConversion;
      }
      
      CurInit = S.MaybeBindToTemporary(CurInit.takeAs<Expr>());
      CurInitExpr = CurInit.takeAs<Expr>();
      CurInit = S.Owned(new (S.Context) ImplicitCastExpr(CurInitExpr->getType(),
                                                         CastKind, 
                                                         CurInitExpr,
                                                         false));                                                        
      break;
    }
        
    case SK_QualificationConversionLValue:
    case SK_QualificationConversionRValue:
      // Perform a qualification conversion; these can never go wrong.
      S.ImpCastExprToType(CurInitExpr, Step->Type,
                          CastExpr::CK_NoOp, 
                          Step->Kind == SK_QualificationConversionLValue);
      CurInit.release();
      CurInit = S.Owned(CurInitExpr);
      break;
        
    case SK_ConversionSequence:
      if (S.PerformImplicitConversion(CurInitExpr, Step->Type, "converting", 
                                      false, false, *Step->ICS))
        return S.ExprError();
        
      CurInit.release();
      CurInit = S.Owned(CurInitExpr);        
      break;
    }
  }
  
  return move(CurInit);
}

//===----------------------------------------------------------------------===//
// Diagnose initialization failures
//===----------------------------------------------------------------------===//
bool InitializationSequence::Diagnose(Sema &S, 
                                      const InitializedEntity &Entity,
                                      const InitializationKind &Kind,
                                      Expr **Args, unsigned NumArgs) {
  if (SequenceKind != FailedSequence)
    return false;
  
  QualType DestType = Entity.getType().getType();
  switch (Failure) {
  case FK_TooManyInitsForReference:
    S.Diag(Kind.getLocation(), diag::err_reference_has_multiple_inits)
      << SourceRange(Args[0]->getLocStart(), Args[NumArgs - 1]->getLocEnd());
    break;
    
  case FK_ArrayNeedsInitList:
  case FK_ArrayNeedsInitListOrStringLiteral:
    S.Diag(Kind.getLocation(), diag::err_array_init_not_init_list)
      << (Failure == FK_ArrayNeedsInitListOrStringLiteral);
    break;
      
  case FK_AddressOfOverloadFailed:
    S.ResolveAddressOfOverloadedFunction(Args[0], 
                                         DestType.getNonReferenceType(),
                                         true);
    break;
      
  case FK_ReferenceInitOverloadFailed:
    switch (FailedOverloadResult) {
    case OR_Ambiguous:
      S.Diag(Kind.getLocation(), diag::err_typecheck_ambiguous_condition)
        << Args[0]->getType() << DestType.getNonReferenceType()
        << Args[0]->getSourceRange();
      S.PrintOverloadCandidates(FailedCandidateSet, true);
      break;
        
    case OR_No_Viable_Function:
      S.Diag(Kind.getLocation(), diag::err_typecheck_nonviable_condition)
        << Args[0]->getType() << DestType.getNonReferenceType()
        << Args[0]->getSourceRange();
      S.PrintOverloadCandidates(FailedCandidateSet, false);
      break;
        
    case OR_Deleted: {
      S.Diag(Kind.getLocation(), diag::err_typecheck_deleted_function)
        << Args[0]->getType() << DestType.getNonReferenceType()
        << Args[0]->getSourceRange();
      OverloadCandidateSet::iterator Best;
      OverloadingResult Ovl = S.BestViableFunction(FailedCandidateSet,
                                                   Kind.getLocation(),
                                                   Best);
      if (Ovl == OR_Deleted) {
        S.Diag(Best->Function->getLocation(), diag::note_unavailable_here)
          << Best->Function->isDeleted();
      } else {
        llvm::llvm_unreachable("Inconsistent overload resolution?");
      }
      break;
    }
        
    case OR_Success:
      llvm::llvm_unreachable("Conversion did not fail!");
      break;
    }
    break;
      
  case FK_NonConstLValueReferenceBindingToTemporary:
  case FK_NonConstLValueReferenceBindingToUnrelated:
    S.Diag(Kind.getLocation(), 
           Failure == FK_NonConstLValueReferenceBindingToTemporary
             ? diag::err_lvalue_reference_bind_to_temporary
             : diag::err_lvalue_reference_bind_to_unrelated)
      << DestType.getNonReferenceType()
      << Args[0]->getType()
      << Args[0]->getSourceRange();
    break;
      
  case FK_RValueReferenceBindingToLValue:
    S.Diag(Kind.getLocation(), diag::err_lvalue_to_rvalue_ref)
      << Args[0]->getSourceRange();
    break;
      
  case FK_ReferenceInitDropsQualifiers:
    S.Diag(Kind.getLocation(), diag::err_reference_bind_drops_quals)
      << DestType.getNonReferenceType()
      << Args[0]->getType()
      << Args[0]->getSourceRange();
    break;
      
  case FK_ReferenceInitFailed:
    S.Diag(Kind.getLocation(), diag::err_reference_bind_failed)
      << DestType.getNonReferenceType()
      << (Args[0]->isLvalue(S.Context) == Expr::LV_Valid)
      << Args[0]->getType()
      << Args[0]->getSourceRange();
    break;
      
  case FK_ConversionFailed:
    S.Diag(Kind.getLocation(), diag::err_cannot_initialize_decl_noname)
      << DestType
      << (Args[0]->isLvalue(S.Context) == Expr::LV_Valid)
      << Args[0]->getType()
      << Args[0]->getSourceRange();
      break;
  }
  
  return true;
}
