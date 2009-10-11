//===--- SemaExceptionSpec.cpp - C++ Exception Specifications ---*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file provides Sema routines for C++ exception specification testing.
//
//===----------------------------------------------------------------------===//

#include "Sema.h"
#include "clang/Basic/Diagnostic.h"
#include "clang/AST/CXXInheritance.h"
#include "clang/AST/Expr.h"
#include "clang/AST/ExprCXX.h"
#include "llvm/ADT/SmallPtrSet.h"

namespace clang {

static const FunctionProtoType *GetUnderlyingFunction(QualType T)
{
  if (const PointerType *PtrTy = T->getAs<PointerType>())
    T = PtrTy->getPointeeType();
  else if (const ReferenceType *RefTy = T->getAs<ReferenceType>())
    T = RefTy->getPointeeType();
  return T->getAs<FunctionProtoType>();
}

/// CheckSpecifiedExceptionType - Check if the given type is valid in an
/// exception specification. Incomplete types, or pointers to incomplete types
/// other than void are not allowed.
bool Sema::CheckSpecifiedExceptionType(QualType T, const SourceRange &Range) {
  // FIXME: This may not correctly work with the fix for core issue 437,
  // where a class's own type is considered complete within its body. But
  // perhaps RequireCompleteType itself should contain this logic?

  // C++ 15.4p2: A type denoted in an exception-specification shall not denote
  //   an incomplete type.
  // FIXME: This isn't right. This will supress diagnostics from template
  // instantiation and then simply emit the invalid type diagnostic.
  if (RequireCompleteType(Range.getBegin(), T, 0))
    return Diag(Range.getBegin(), diag::err_incomplete_in_exception_spec)
      << Range << T << /*direct*/0;

  // C++ 15.4p2: A type denoted in an exception-specification shall not denote
  //   an incomplete type a pointer or reference to an incomplete type, other
  //   than (cv) void*.
  int kind;
  if (const PointerType* IT = T->getAs<PointerType>()) {
    T = IT->getPointeeType();
    kind = 1;
  } else if (const ReferenceType* IT = T->getAs<ReferenceType>()) {
    T = IT->getPointeeType();
    kind = 2;
  } else
    return false;

  if (!T->isVoidType() && RequireCompleteType(Range.getBegin(), T, 0))
    return Diag(Range.getBegin(), diag::err_incomplete_in_exception_spec)
      << Range << T << /*indirect*/kind;

  return false;
}

/// CheckDistantExceptionSpec - Check if the given type is a pointer or pointer
/// to member to a function with an exception specification. This means that
/// it is invalid to add another level of indirection.
bool Sema::CheckDistantExceptionSpec(QualType T) {
  if (const PointerType *PT = T->getAs<PointerType>())
    T = PT->getPointeeType();
  else if (const MemberPointerType *PT = T->getAs<MemberPointerType>())
    T = PT->getPointeeType();
  else
    return false;

  const FunctionProtoType *FnT = T->getAs<FunctionProtoType>();
  if (!FnT)
    return false;

  return FnT->hasExceptionSpec();
}

/// CheckEquivalentExceptionSpec - Check if the two types have equivalent
/// exception specifications. Exception specifications are equivalent if
/// they allow exactly the same set of exception types. It does not matter how
/// that is achieved. See C++ [except.spec]p2.
bool Sema::CheckEquivalentExceptionSpec(
    const FunctionProtoType *Old, SourceLocation OldLoc,
    const FunctionProtoType *New, SourceLocation NewLoc) {
  return CheckEquivalentExceptionSpec(diag::err_mismatched_exception_spec,
                                      diag::note_previous_declaration,
                                      Old, OldLoc, New, NewLoc);
}

/// CheckEquivalentExceptionSpec - Check if the two types have equivalent
/// exception specifications. Exception specifications are equivalent if
/// they allow exactly the same set of exception types. It does not matter how
/// that is achieved. See C++ [except.spec]p2.
bool Sema::CheckEquivalentExceptionSpec(
    unsigned DiagID, unsigned NoteID,
    const FunctionProtoType *Old, SourceLocation OldLoc,
    const FunctionProtoType *New, SourceLocation NewLoc) {
  bool OldAny = !Old->hasExceptionSpec() || Old->hasAnyExceptionSpec();
  bool NewAny = !New->hasExceptionSpec() || New->hasAnyExceptionSpec();
  if (OldAny && NewAny)
    return false;
  if (OldAny || NewAny) {
    Diag(NewLoc, DiagID);
    if (NoteID != 0)
      Diag(OldLoc, NoteID);
    return true;
  }

  bool Success = true;
  // Both have a definite exception spec. Collect the first set, then compare
  // to the second.
  llvm::SmallPtrSet<const Type*, 8> OldTypes, NewTypes;
  for (FunctionProtoType::exception_iterator I = Old->exception_begin(),
       E = Old->exception_end(); I != E; ++I)
    OldTypes.insert(Context.getCanonicalType(*I).getTypePtr());

  for (FunctionProtoType::exception_iterator I = New->exception_begin(),
       E = New->exception_end(); I != E && Success; ++I) {
    const Type *TypePtr = Context.getCanonicalType(*I).getTypePtr();
    if(OldTypes.count(TypePtr))
      NewTypes.insert(TypePtr);
    else
      Success = false;
  }

  Success = Success && OldTypes.size() == NewTypes.size();

  if (Success) {
    return false;
  }
  Diag(NewLoc, DiagID);
  if (NoteID != 0)
    Diag(OldLoc, NoteID);
  return true;
}

/// CheckExceptionSpecSubset - Check whether the second function type's
/// exception specification is a subset (or equivalent) of the first function
/// type. This is used by override and pointer assignment checks.
bool Sema::CheckExceptionSpecSubset(unsigned DiagID, unsigned NoteID,
    const FunctionProtoType *Superset, SourceLocation SuperLoc,
    const FunctionProtoType *Subset, SourceLocation SubLoc) {
  // FIXME: As usual, we could be more specific in our error messages, but
  // that better waits until we've got types with source locations.

  if (!SubLoc.isValid())
    SubLoc = SuperLoc;

  // If superset contains everything, we're done.
  if (!Superset->hasExceptionSpec() || Superset->hasAnyExceptionSpec())
    return CheckParamExceptionSpec(NoteID, Superset, SuperLoc, Subset, SubLoc);

  // It does not. If the subset contains everything, we've failed.
  if (!Subset->hasExceptionSpec() || Subset->hasAnyExceptionSpec()) {
    Diag(SubLoc, DiagID);
    if (NoteID != 0)
      Diag(SuperLoc, NoteID);
    return true;
  }

  // Neither contains everything. Do a proper comparison.
  for (FunctionProtoType::exception_iterator SubI = Subset->exception_begin(),
       SubE = Subset->exception_end(); SubI != SubE; ++SubI) {
    // Take one type from the subset.
    QualType CanonicalSubT = Context.getCanonicalType(*SubI);
    bool SubIsPointer = false;
    if (const ReferenceType *RefTy = CanonicalSubT->getAs<ReferenceType>())
      CanonicalSubT = RefTy->getPointeeType();
    if (const PointerType *PtrTy = CanonicalSubT->getAs<PointerType>()) {
      CanonicalSubT = PtrTy->getPointeeType();
      SubIsPointer = true;
    }
    bool SubIsClass = CanonicalSubT->isRecordType();
    CanonicalSubT = CanonicalSubT.getUnqualifiedType();

    CXXBasePaths Paths(/*FindAmbiguities=*/true, /*RecordPaths=*/true,
                       /*DetectVirtual=*/false);

    bool Contained = false;
    // Make sure it's in the superset.
    for (FunctionProtoType::exception_iterator SuperI =
           Superset->exception_begin(), SuperE = Superset->exception_end();
         SuperI != SuperE; ++SuperI) {
      QualType CanonicalSuperT = Context.getCanonicalType(*SuperI);
      // SubT must be SuperT or derived from it, or pointer or reference to
      // such types.
      if (const ReferenceType *RefTy = CanonicalSuperT->getAs<ReferenceType>())
        CanonicalSuperT = RefTy->getPointeeType();
      if (SubIsPointer) {
        if (const PointerType *PtrTy = CanonicalSuperT->getAs<PointerType>())
          CanonicalSuperT = PtrTy->getPointeeType();
        else {
          continue;
        }
      }
      CanonicalSuperT = CanonicalSuperT.getUnqualifiedType();
      // If the types are the same, move on to the next type in the subset.
      if (CanonicalSubT == CanonicalSuperT) {
        Contained = true;
        break;
      }

      // Otherwise we need to check the inheritance.
      if (!SubIsClass || !CanonicalSuperT->isRecordType())
        continue;

      Paths.clear();
      if (!IsDerivedFrom(CanonicalSubT, CanonicalSuperT, Paths))
        continue;

      if (Paths.isAmbiguous(CanonicalSuperT))
        continue;

      if (FindInaccessibleBase(CanonicalSubT, CanonicalSuperT, Paths, true))
        continue;

      Contained = true;
      break;
    }
    if (!Contained) {
      Diag(SubLoc, DiagID);
      if (NoteID != 0)
        Diag(SuperLoc, NoteID);
      return true;
    }
  }
  // We've run half the gauntlet.
  return CheckParamExceptionSpec(NoteID, Superset, SuperLoc, Subset, SubLoc);
}

static bool CheckSpecForTypesEquivalent(Sema &S,
    unsigned DiagID, unsigned NoteID,
    QualType Target, SourceLocation TargetLoc,
    QualType Source, SourceLocation SourceLoc)
{
  const FunctionProtoType *TFunc = GetUnderlyingFunction(Target);
  if (!TFunc)
    return false;
  const FunctionProtoType *SFunc = GetUnderlyingFunction(Source);
  if (!SFunc)
    return false;

  return S.CheckEquivalentExceptionSpec(DiagID, NoteID, TFunc, TargetLoc,
                                        SFunc, SourceLoc);
}

/// CheckParamExceptionSpec - Check if the parameter and return types of the
/// two functions have equivalent exception specs. This is part of the
/// assignment and override compatibility check. We do not check the parameters
/// of parameter function pointers recursively, as no sane programmer would
/// even be able to write such a function type.
bool Sema::CheckParamExceptionSpec(unsigned NoteID,
    const FunctionProtoType *Target, SourceLocation TargetLoc,
    const FunctionProtoType *Source, SourceLocation SourceLoc)
{
  if (CheckSpecForTypesEquivalent(*this, diag::err_return_type_specs_differ, 0,
                                  Target->getResultType(), TargetLoc,
                                  Source->getResultType(), SourceLoc))
    return true;

  // We shouldn't even testing this unless the arguments are otherwise
  // compatible.
  assert(Target->getNumArgs() == Source->getNumArgs() &&
         "Functions have different argument counts.");
  for (unsigned i = 0, E = Target->getNumArgs(); i != E; ++i) {
    if (CheckSpecForTypesEquivalent(*this, diag::err_arg_type_specs_differ, 0,
                                    Target->getArgType(i), TargetLoc,
                                    Source->getArgType(i), SourceLoc))
      return true;
  }
  return false;
}

bool Sema::CheckExceptionSpecCompatibility(Expr *From, QualType ToType)
{
  // First we check for applicability.
  // Target type must be a function, function pointer or function reference.
  const FunctionProtoType *ToFunc = GetUnderlyingFunction(ToType);
  if (!ToFunc)
    return false;

  // SourceType must be a function or function pointer.
  const FunctionProtoType *FromFunc = GetUnderlyingFunction(From->getType());
  if (!FromFunc)
    return false;

  // Now we've got the correct types on both sides, check their compatibility.
  // This means that the source of the conversion can only throw a subset of
  // the exceptions of the target, and any exception specs on arguments or
  // return types must be equivalent.
  return CheckExceptionSpecSubset(diag::err_incompatible_exception_specs,
                                  0, ToFunc, From->getSourceRange().getBegin(),
                                  FromFunc, SourceLocation());
}

bool Sema::CheckOverridingFunctionExceptionSpec(const CXXMethodDecl *New,
                                                const CXXMethodDecl *Old) {
  return CheckExceptionSpecSubset(diag::err_override_exception_spec,
                                  diag::note_overridden_virtual_function,
                                  Old->getType()->getAs<FunctionProtoType>(),
                                  Old->getLocation(),
                                  New->getType()->getAs<FunctionProtoType>(),
                                  New->getLocation());
}

} // end namespace clang
