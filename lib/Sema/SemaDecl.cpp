//===--- SemaDecl.cpp - Semantic Analysis for Declarations ----------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
//  This file implements semantic analysis for declarations.
//
//===----------------------------------------------------------------------===//

#include "Sema.h"
#include "SemaInit.h"
#include "Lookup.h"
#include "clang/Analysis/AnalysisContext.h"
#include "clang/AST/APValue.h"
#include "clang/AST/ASTConsumer.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/CXXInheritance.h"
#include "clang/AST/DeclTemplate.h"
#include "clang/AST/ExprCXX.h"
#include "clang/AST/StmtCXX.h"
#include "clang/Parse/DeclSpec.h"
#include "clang/Parse/ParseDiagnostic.h"
#include "clang/Parse/Template.h"
#include "clang/Basic/PartialDiagnostic.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Basic/TargetInfo.h"
// FIXME: layering (ideally, Sema shouldn't be dependent on Lex API's)
#include "clang/Lex/Preprocessor.h"
#include "clang/Lex/HeaderSearch.h"
#include "llvm/ADT/Triple.h"
#include <algorithm>
#include <cstring>
#include <functional>
using namespace clang;

/// getDeclName - Return a pretty name for the specified decl if possible, or
/// an empty string if not.  This is used for pretty crash reporting.
std::string Sema::getDeclName(DeclPtrTy d) {
  Decl *D = d.getAs<Decl>();
  if (NamedDecl *DN = dyn_cast_or_null<NamedDecl>(D))
    return DN->getQualifiedNameAsString();
  return "";
}

Sema::DeclGroupPtrTy Sema::ConvertDeclToDeclGroup(DeclPtrTy Ptr) {
  return DeclGroupPtrTy::make(DeclGroupRef(Ptr.getAs<Decl>()));
}

/// \brief If the identifier refers to a type name within this scope,
/// return the declaration of that type.
///
/// This routine performs ordinary name lookup of the identifier II
/// within the given scope, with optional C++ scope specifier SS, to
/// determine whether the name refers to a type. If so, returns an
/// opaque pointer (actually a QualType) corresponding to that
/// type. Otherwise, returns NULL.
///
/// If name lookup results in an ambiguity, this routine will complain
/// and then return NULL.
Sema::TypeTy *Sema::getTypeName(IdentifierInfo &II, SourceLocation NameLoc,
                                Scope *S, const CXXScopeSpec *SS,
                                bool isClassName,
                                TypeTy *ObjectTypePtr) {
  // Determine where we will perform name lookup.
  DeclContext *LookupCtx = 0;
  if (ObjectTypePtr) {
    QualType ObjectType = QualType::getFromOpaquePtr(ObjectTypePtr);
    if (ObjectType->isRecordType())
      LookupCtx = computeDeclContext(ObjectType);
  } else if (SS && SS->isSet()) {
    LookupCtx = computeDeclContext(*SS, false);

    if (!LookupCtx) {
      if (isDependentScopeSpecifier(*SS)) {
        // C++ [temp.res]p3:
        //   A qualified-id that refers to a type and in which the
        //   nested-name-specifier depends on a template-parameter (14.6.2)
        //   shall be prefixed by the keyword typename to indicate that the
        //   qualified-id denotes a type, forming an
        //   elaborated-type-specifier (7.1.5.3).
        //
        // We therefore do not perform any name lookup if the result would
        // refer to a member of an unknown specialization.
        if (!isClassName)
          return 0;
        
        // We know from the grammar that this name refers to a type, so build a
        // TypenameType node to describe the type.
        // FIXME: Record somewhere that this TypenameType node has no "typename"
        // keyword associated with it.
        return CheckTypenameType((NestedNameSpecifier *)SS->getScopeRep(),
                                 II, SS->getRange()).getAsOpaquePtr();
      }
      
      return 0;
    }
    
    if (!LookupCtx->isDependentContext() && RequireCompleteDeclContext(*SS))
      return 0;
  }

  // FIXME: LookupNestedNameSpecifierName isn't the right kind of
  // lookup for class-names.
  LookupNameKind Kind = isClassName ? LookupNestedNameSpecifierName :
                                      LookupOrdinaryName;
  LookupResult Result(*this, &II, NameLoc, Kind);
  if (LookupCtx) {
    // Perform "qualified" name lookup into the declaration context we
    // computed, which is either the type of the base of a member access
    // expression or the declaration context associated with a prior
    // nested-name-specifier.
    LookupQualifiedName(Result, LookupCtx);

    if (ObjectTypePtr && Result.empty()) {
      // C++ [basic.lookup.classref]p3:
      //   If the unqualified-id is ~type-name, the type-name is looked up
      //   in the context of the entire postfix-expression. If the type T of 
      //   the object expression is of a class type C, the type-name is also
      //   looked up in the scope of class C. At least one of the lookups shall
      //   find a name that refers to (possibly cv-qualified) T.
      LookupName(Result, S);
    }
  } else {
    // Perform unqualified name lookup.
    LookupName(Result, S);
  }
  
  NamedDecl *IIDecl = 0;
  switch (Result.getResultKind()) {
  case LookupResult::NotFound:
  case LookupResult::NotFoundInCurrentInstantiation:
  case LookupResult::FoundOverloaded:
  case LookupResult::FoundUnresolvedValue:
    Result.suppressDiagnostics();
    return 0;

  case LookupResult::Ambiguous:
    // Recover from type-hiding ambiguities by hiding the type.  We'll
    // do the lookup again when looking for an object, and we can
    // diagnose the error then.  If we don't do this, then the error
    // about hiding the type will be immediately followed by an error
    // that only makes sense if the identifier was treated like a type.
    if (Result.getAmbiguityKind() == LookupResult::AmbiguousTagHiding) {
      Result.suppressDiagnostics();
      return 0;
    }

    // Look to see if we have a type anywhere in the list of results.
    for (LookupResult::iterator Res = Result.begin(), ResEnd = Result.end();
         Res != ResEnd; ++Res) {
      if (isa<TypeDecl>(*Res) || isa<ObjCInterfaceDecl>(*Res)) {
        if (!IIDecl ||
            (*Res)->getLocation().getRawEncoding() <
              IIDecl->getLocation().getRawEncoding())
          IIDecl = *Res;
      }
    }

    if (!IIDecl) {
      // None of the entities we found is a type, so there is no way
      // to even assume that the result is a type. In this case, don't
      // complain about the ambiguity. The parser will either try to
      // perform this lookup again (e.g., as an object name), which
      // will produce the ambiguity, or will complain that it expected
      // a type name.
      Result.suppressDiagnostics();
      return 0;
    }

    // We found a type within the ambiguous lookup; diagnose the
    // ambiguity and then return that type. This might be the right
    // answer, or it might not be, but it suppresses any attempt to
    // perform the name lookup again.
    break;

  case LookupResult::Found:
    IIDecl = Result.getFoundDecl();
    break;
  }

  assert(IIDecl && "Didn't find decl");

  QualType T;
  if (TypeDecl *TD = dyn_cast<TypeDecl>(IIDecl)) {
    DiagnoseUseOfDecl(IIDecl, NameLoc);

    // C++ [temp.local]p2:
    //   Within the scope of a class template specialization or
    //   partial specialization, when the injected-class-name is
    //   not followed by a <, it is equivalent to the
    //   injected-class-name followed by the template-argument s
    //   of the class template specialization or partial
    //   specialization enclosed in <>.
    if (CXXRecordDecl *RD = dyn_cast<CXXRecordDecl>(TD))
      if (RD->isInjectedClassName())
        if (ClassTemplateDecl *Template = RD->getDescribedClassTemplate())
          T = Template->getInjectedClassNameType(Context);

    if (T.isNull())
      T = Context.getTypeDeclType(TD);
    
    if (SS)
      T = getQualifiedNameType(*SS, T);
    
  } else if (ObjCInterfaceDecl *IDecl = dyn_cast<ObjCInterfaceDecl>(IIDecl)) {
    T = Context.getObjCInterfaceType(IDecl);
  } else if (UnresolvedUsingTypenameDecl *UUDecl =
               dyn_cast<UnresolvedUsingTypenameDecl>(IIDecl)) {
    // FIXME: preserve source structure information.
    T = Context.getTypenameType(UUDecl->getTargetNestedNameSpecifier(), &II);
  } else {
    // If it's not plausibly a type, suppress diagnostics.
    Result.suppressDiagnostics();
    return 0;
  }

  return T.getAsOpaquePtr();
}

/// isTagName() - This method is called *for error recovery purposes only*
/// to determine if the specified name is a valid tag name ("struct foo").  If
/// so, this returns the TST for the tag corresponding to it (TST_enum,
/// TST_union, TST_struct, TST_class).  This is used to diagnose cases in C
/// where the user forgot to specify the tag.
DeclSpec::TST Sema::isTagName(IdentifierInfo &II, Scope *S) {
  // Do a tag name lookup in this scope.
  LookupResult R(*this, &II, SourceLocation(), LookupTagName);
  LookupName(R, S, false);
  R.suppressDiagnostics();
  if (R.getResultKind() == LookupResult::Found)
    if (const TagDecl *TD = R.getAsSingle<TagDecl>()) {
      switch (TD->getTagKind()) {
      case TagDecl::TK_struct: return DeclSpec::TST_struct;
      case TagDecl::TK_union:  return DeclSpec::TST_union;
      case TagDecl::TK_class:  return DeclSpec::TST_class;
      case TagDecl::TK_enum:   return DeclSpec::TST_enum;
      }
    }

  return DeclSpec::TST_unspecified;
}

bool Sema::DiagnoseUnknownTypeName(const IdentifierInfo &II, 
                                   SourceLocation IILoc,
                                   Scope *S,
                                   const CXXScopeSpec *SS,
                                   TypeTy *&SuggestedType) {
  // We don't have anything to suggest (yet).
  SuggestedType = 0;
  
  // There may have been a typo in the name of the type. Look up typo
  // results, in case we have something that we can suggest.
  LookupResult Lookup(*this, &II, IILoc, LookupOrdinaryName, 
                      NotForRedeclaration);

  // FIXME: It would be nice if we could correct for typos in built-in
  // names, such as "itn" for "int".

  if (CorrectTypo(Lookup, S, SS) && Lookup.isSingleResult()) {
    NamedDecl *Result = Lookup.getAsSingle<NamedDecl>();
    if ((isa<TypeDecl>(Result) || isa<ObjCInterfaceDecl>(Result)) &&
        !Result->isInvalidDecl()) {
      // We found a similarly-named type or interface; suggest that.
      if (!SS || !SS->isSet())
        Diag(IILoc, diag::err_unknown_typename_suggest)
          << &II << Lookup.getLookupName()
          << CodeModificationHint::CreateReplacement(SourceRange(IILoc),
                                                     Result->getNameAsString());
      else if (DeclContext *DC = computeDeclContext(*SS, false))
        Diag(IILoc, diag::err_unknown_nested_typename_suggest) 
          << &II << DC << Lookup.getLookupName() << SS->getRange()
          << CodeModificationHint::CreateReplacement(SourceRange(IILoc),
                                                     Result->getNameAsString());
      else
        llvm_unreachable("could not have corrected a typo here");

      Diag(Result->getLocation(), diag::note_previous_decl)
        << Result->getDeclName();
      
      SuggestedType = getTypeName(*Result->getIdentifier(), IILoc, S, SS);
      return true;
    }
  }

  // FIXME: Should we move the logic that tries to recover from a missing tag
  // (struct, union, enum) from Parser::ParseImplicitInt here, instead?
  
  if (!SS || (!SS->isSet() && !SS->isInvalid()))
    Diag(IILoc, diag::err_unknown_typename) << &II;
  else if (DeclContext *DC = computeDeclContext(*SS, false))
    Diag(IILoc, diag::err_typename_nested_not_found) 
      << &II << DC << SS->getRange();
  else if (isDependentScopeSpecifier(*SS)) {
    Diag(SS->getRange().getBegin(), diag::err_typename_missing)
      << (NestedNameSpecifier *)SS->getScopeRep() << II.getName()
      << SourceRange(SS->getRange().getBegin(), IILoc)
      << CodeModificationHint::CreateInsertion(SS->getRange().getBegin(),
                                               "typename ");
    SuggestedType = ActOnTypenameType(SourceLocation(), *SS, II, IILoc).get();
  } else {
    assert(SS && SS->isInvalid() && 
           "Invalid scope specifier has already been diagnosed");
  }
  
  return true;
}

// Determines the context to return to after temporarily entering a
// context.  This depends in an unnecessarily complicated way on the
// exact ordering of callbacks from the parser.
DeclContext *Sema::getContainingDC(DeclContext *DC) {

  // Functions defined inline within classes aren't parsed until we've
  // finished parsing the top-level class, so the top-level class is
  // the context we'll need to return to.
  if (isa<FunctionDecl>(DC)) {
    DC = DC->getLexicalParent();

    // A function not defined within a class will always return to its
    // lexical context.
    if (!isa<CXXRecordDecl>(DC))
      return DC;

    // A C++ inline method/friend is parsed *after* the topmost class
    // it was declared in is fully parsed ("complete");  the topmost
    // class is the context we need to return to.
    while (CXXRecordDecl *RD = dyn_cast<CXXRecordDecl>(DC->getLexicalParent()))
      DC = RD;

    // Return the declaration context of the topmost class the inline method is
    // declared in.
    return DC;
  }

  if (isa<ObjCMethodDecl>(DC))
    return Context.getTranslationUnitDecl();

  return DC->getLexicalParent();
}

void Sema::PushDeclContext(Scope *S, DeclContext *DC) {
  assert(getContainingDC(DC) == CurContext &&
      "The next DeclContext should be lexically contained in the current one.");
  CurContext = DC;
  S->setEntity(DC);
}

void Sema::PopDeclContext() {
  assert(CurContext && "DeclContext imbalance!");

  CurContext = getContainingDC(CurContext);
}

/// EnterDeclaratorContext - Used when we must lookup names in the context
/// of a declarator's nested name specifier.
///
void Sema::EnterDeclaratorContext(Scope *S, DeclContext *DC) {
  // C++0x [basic.lookup.unqual]p13:
  //   A name used in the definition of a static data member of class
  //   X (after the qualified-id of the static member) is looked up as
  //   if the name was used in a member function of X.
  // C++0x [basic.lookup.unqual]p14:
  //   If a variable member of a namespace is defined outside of the
  //   scope of its namespace then any name used in the definition of
  //   the variable member (after the declarator-id) is looked up as
  //   if the definition of the variable member occurred in its
  //   namespace.
  // Both of these imply that we should push a scope whose context
  // is the semantic context of the declaration.  We can't use
  // PushDeclContext here because that context is not necessarily
  // lexically contained in the current context.  Fortunately,
  // the containing scope should have the appropriate information.

  assert(!S->getEntity() && "scope already has entity");

#ifndef NDEBUG
  Scope *Ancestor = S->getParent();
  while (!Ancestor->getEntity()) Ancestor = Ancestor->getParent();
  assert(Ancestor->getEntity() == CurContext && "ancestor context mismatch");
#endif

  CurContext = DC;
  S->setEntity(DC);
}

void Sema::ExitDeclaratorContext(Scope *S) {
  assert(S->getEntity() == CurContext && "Context imbalance!");

  // Switch back to the lexical context.  The safety of this is
  // enforced by an assert in EnterDeclaratorContext.
  Scope *Ancestor = S->getParent();
  while (!Ancestor->getEntity()) Ancestor = Ancestor->getParent();
  CurContext = (DeclContext*) Ancestor->getEntity();

  // We don't need to do anything with the scope, which is going to
  // disappear.
}

/// \brief Determine whether we allow overloading of the function
/// PrevDecl with another declaration.
///
/// This routine determines whether overloading is possible, not
/// whether some new function is actually an overload. It will return
/// true in C++ (where we can always provide overloads) or, as an
/// extension, in C when the previous function is already an
/// overloaded function declaration or has the "overloadable"
/// attribute.
static bool AllowOverloadingOfFunction(LookupResult &Previous,
                                       ASTContext &Context) {
  if (Context.getLangOptions().CPlusPlus)
    return true;

  if (Previous.getResultKind() == LookupResult::FoundOverloaded)
    return true;

  return (Previous.getResultKind() == LookupResult::Found
          && Previous.getFoundDecl()->hasAttr<OverloadableAttr>());
}

/// Add this decl to the scope shadowed decl chains.
void Sema::PushOnScopeChains(NamedDecl *D, Scope *S, bool AddToContext) {
  // Move up the scope chain until we find the nearest enclosing
  // non-transparent context. The declaration will be introduced into this
  // scope.
  while (S->getEntity() &&
         ((DeclContext *)S->getEntity())->isTransparentContext())
    S = S->getParent();

  // Add scoped declarations into their context, so that they can be
  // found later. Declarations without a context won't be inserted
  // into any context.
  if (AddToContext)
    CurContext->addDecl(D);

  // Out-of-line definitions shouldn't be pushed into scope in C++.
  // Out-of-line variable and function definitions shouldn't even in C.
  if ((getLangOptions().CPlusPlus || isa<VarDecl>(D) || isa<FunctionDecl>(D)) &&
      D->isOutOfLine())
    return;

  // Template instantiations should also not be pushed into scope.
  if (isa<FunctionDecl>(D) &&
      cast<FunctionDecl>(D)->isFunctionTemplateSpecialization())
    return;

  // If this replaces anything in the current scope, 
  IdentifierResolver::iterator I = IdResolver.begin(D->getDeclName()),
                               IEnd = IdResolver.end();
  for (; I != IEnd; ++I) {
    if (S->isDeclScope(DeclPtrTy::make(*I)) && D->declarationReplaces(*I)) {
      S->RemoveDecl(DeclPtrTy::make(*I));
      IdResolver.RemoveDecl(*I);

      // Should only need to replace one decl.
      break;
    }
  }

  S->AddDecl(DeclPtrTy::make(D));
  IdResolver.AddDecl(D);
}

bool Sema::isDeclInScope(NamedDecl *&D, DeclContext *Ctx, Scope *S) {
  return IdResolver.isDeclInScope(D, Ctx, Context, S);
}

static bool isOutOfScopePreviousDeclaration(NamedDecl *,
                                            DeclContext*,
                                            ASTContext&);

/// Filters out lookup results that don't fall within the given scope
/// as determined by isDeclInScope.
static void FilterLookupForScope(Sema &SemaRef, LookupResult &R,
                                 DeclContext *Ctx, Scope *S,
                                 bool ConsiderLinkage) {
  LookupResult::Filter F = R.makeFilter();
  while (F.hasNext()) {
    NamedDecl *D = F.next();

    if (SemaRef.isDeclInScope(D, Ctx, S))
      continue;

    if (ConsiderLinkage &&
        isOutOfScopePreviousDeclaration(D, Ctx, SemaRef.Context))
      continue;
    
    F.erase();
  }

  F.done();
}

static bool isUsingDecl(NamedDecl *D) {
  return isa<UsingShadowDecl>(D) ||
         isa<UnresolvedUsingTypenameDecl>(D) ||
         isa<UnresolvedUsingValueDecl>(D);
}

/// Removes using shadow declarations from the lookup results.
static void RemoveUsingDecls(LookupResult &R) {
  LookupResult::Filter F = R.makeFilter();
  while (F.hasNext())
    if (isUsingDecl(F.next()))
      F.erase();

  F.done();
}

static bool ShouldDiagnoseUnusedDecl(const NamedDecl *D) {
  if (D->isInvalidDecl())
    return false;

  if (D->isUsed() || D->hasAttr<UnusedAttr>())
    return false;

  // White-list anything that isn't a local variable.
  if (!isa<VarDecl>(D) || isa<ParmVarDecl>(D) || isa<ImplicitParamDecl>(D) ||
      !D->getDeclContext()->isFunctionOrMethod())
    return false;

  // Types of valid local variables should be complete, so this should succeed.
  if (const ValueDecl *VD = dyn_cast<ValueDecl>(D)) {
    if (const RecordType *RT = VD->getType()->getAs<RecordType>()) {
      if (const CXXRecordDecl *RD = dyn_cast<CXXRecordDecl>(RT->getDecl())) {
        if (!RD->hasTrivialConstructor())
          return false;
        if (!RD->hasTrivialDestructor())
          return false;
      }
    }
  }
  
  return true;
}

void Sema::ActOnPopScope(SourceLocation Loc, Scope *S) {
  if (S->decl_empty()) return;
  assert((S->getFlags() & (Scope::DeclScope | Scope::TemplateParamScope)) &&
         "Scope shouldn't contain decls!");

  for (Scope::decl_iterator I = S->decl_begin(), E = S->decl_end();
       I != E; ++I) {
    Decl *TmpD = (*I).getAs<Decl>();
    assert(TmpD && "This decl didn't get pushed??");

    assert(isa<NamedDecl>(TmpD) && "Decl isn't NamedDecl?");
    NamedDecl *D = cast<NamedDecl>(TmpD);

    if (!D->getDeclName()) continue;

    // Diagnose unused variables in this scope.
    if (ShouldDiagnoseUnusedDecl(D) &&
        NumErrorsAtStartOfFunction == getDiagnostics().getNumErrors())
      Diag(D->getLocation(), diag::warn_unused_variable) << D->getDeclName();
    
    // Remove this name from our lexical scope.
    IdResolver.RemoveDecl(D);
  }
}

/// getObjCInterfaceDecl - Look up a for a class declaration in the scope.
/// return 0 if one not found.
///
/// \param Id the name of the Objective-C class we're looking for. If
/// typo-correction fixes this name, the Id will be updated
/// to the fixed name.
///
/// \param RecoverLoc if provided, this routine will attempt to
/// recover from a typo in the name of an existing Objective-C class
/// and, if successful, will return the lookup that results from
/// typo-correction.
ObjCInterfaceDecl *Sema::getObjCInterfaceDecl(IdentifierInfo *&Id,
                                              SourceLocation RecoverLoc) {
  // The third "scope" argument is 0 since we aren't enabling lazy built-in
  // creation from this context.
  NamedDecl *IDecl = LookupSingleName(TUScope, Id, LookupOrdinaryName);

  if (!IDecl && !RecoverLoc.isInvalid()) {
    // Perform typo correction at the given location, but only if we
    // find an Objective-C class name.
    LookupResult R(*this, Id, RecoverLoc, LookupOrdinaryName);
    if (CorrectTypo(R, TUScope, 0) &&
        (IDecl = R.getAsSingle<ObjCInterfaceDecl>())) {
      Diag(RecoverLoc, diag::err_undef_interface_suggest)
        << Id << IDecl->getDeclName() 
        << CodeModificationHint::CreateReplacement(RecoverLoc, 
                                                   IDecl->getNameAsString());
      Diag(IDecl->getLocation(), diag::note_previous_decl)
        << IDecl->getDeclName();
      
      Id = IDecl->getIdentifier();
    }
  }

  return dyn_cast_or_null<ObjCInterfaceDecl>(IDecl);
}

/// getNonFieldDeclScope - Retrieves the innermost scope, starting
/// from S, where a non-field would be declared. This routine copes
/// with the difference between C and C++ scoping rules in structs and
/// unions. For example, the following code is well-formed in C but
/// ill-formed in C++:
/// @code
/// struct S6 {
///   enum { BAR } e;
/// };
///
/// void test_S6() {
///   struct S6 a;
///   a.e = BAR;
/// }
/// @endcode
/// For the declaration of BAR, this routine will return a different
/// scope. The scope S will be the scope of the unnamed enumeration
/// within S6. In C++, this routine will return the scope associated
/// with S6, because the enumeration's scope is a transparent
/// context but structures can contain non-field names. In C, this
/// routine will return the translation unit scope, since the
/// enumeration's scope is a transparent context and structures cannot
/// contain non-field names.
Scope *Sema::getNonFieldDeclScope(Scope *S) {
  while (((S->getFlags() & Scope::DeclScope) == 0) ||
         (S->getEntity() &&
          ((DeclContext *)S->getEntity())->isTransparentContext()) ||
         (S->isClassScope() && !getLangOptions().CPlusPlus))
    S = S->getParent();
  return S;
}

void Sema::InitBuiltinVaListType() {
  if (!Context.getBuiltinVaListType().isNull())
    return;

  IdentifierInfo *VaIdent = &Context.Idents.get("__builtin_va_list");
  NamedDecl *VaDecl = LookupSingleName(TUScope, VaIdent, LookupOrdinaryName);
  TypedefDecl *VaTypedef = cast<TypedefDecl>(VaDecl);
  Context.setBuiltinVaListType(Context.getTypedefType(VaTypedef));
}

/// LazilyCreateBuiltin - The specified Builtin-ID was first used at
/// file scope.  lazily create a decl for it. ForRedeclaration is true
/// if we're creating this built-in in anticipation of redeclaring the
/// built-in.
NamedDecl *Sema::LazilyCreateBuiltin(IdentifierInfo *II, unsigned bid,
                                     Scope *S, bool ForRedeclaration,
                                     SourceLocation Loc) {
  Builtin::ID BID = (Builtin::ID)bid;

  if (Context.BuiltinInfo.hasVAListUse(BID))
    InitBuiltinVaListType();

  ASTContext::GetBuiltinTypeError Error;
  QualType R = Context.GetBuiltinType(BID, Error);
  switch (Error) {
  case ASTContext::GE_None:
    // Okay
    break;

  case ASTContext::GE_Missing_stdio:
    if (ForRedeclaration)
      Diag(Loc, diag::err_implicit_decl_requires_stdio)
        << Context.BuiltinInfo.GetName(BID);
    return 0;

  case ASTContext::GE_Missing_setjmp:
    if (ForRedeclaration)
      Diag(Loc, diag::err_implicit_decl_requires_setjmp)
        << Context.BuiltinInfo.GetName(BID);
    return 0;
  }

  if (!ForRedeclaration && Context.BuiltinInfo.isPredefinedLibFunction(BID)) {
    Diag(Loc, diag::ext_implicit_lib_function_decl)
      << Context.BuiltinInfo.GetName(BID)
      << R;
    if (Context.BuiltinInfo.getHeaderName(BID) &&
        Diags.getDiagnosticLevel(diag::ext_implicit_lib_function_decl)
          != Diagnostic::Ignored)
      Diag(Loc, diag::note_please_include_header)
        << Context.BuiltinInfo.getHeaderName(BID)
        << Context.BuiltinInfo.GetName(BID);
  }

  FunctionDecl *New = FunctionDecl::Create(Context,
                                           Context.getTranslationUnitDecl(),
                                           Loc, II, R, /*TInfo=*/0,
                                           FunctionDecl::Extern, false,
                                           /*hasPrototype=*/true);
  New->setImplicit();

  // Create Decl objects for each parameter, adding them to the
  // FunctionDecl.
  if (FunctionProtoType *FT = dyn_cast<FunctionProtoType>(R)) {
    llvm::SmallVector<ParmVarDecl*, 16> Params;
    for (unsigned i = 0, e = FT->getNumArgs(); i != e; ++i)
      Params.push_back(ParmVarDecl::Create(Context, New, SourceLocation(), 0,
                                           FT->getArgType(i), /*TInfo=*/0,
                                           VarDecl::None, 0));
    New->setParams(Params.data(), Params.size());
  }

  AddKnownFunctionAttributes(New);

  // TUScope is the translation-unit scope to insert this function into.
  // FIXME: This is hideous. We need to teach PushOnScopeChains to
  // relate Scopes to DeclContexts, and probably eliminate CurContext
  // entirely, but we're not there yet.
  DeclContext *SavedContext = CurContext;
  CurContext = Context.getTranslationUnitDecl();
  PushOnScopeChains(New, TUScope);
  CurContext = SavedContext;
  return New;
}

/// MergeTypeDefDecl - We just parsed a typedef 'New' which has the
/// same name and scope as a previous declaration 'Old'.  Figure out
/// how to resolve this situation, merging decls or emitting
/// diagnostics as appropriate. If there was an error, set New to be invalid.
///
void Sema::MergeTypeDefDecl(TypedefDecl *New, LookupResult &OldDecls) {
  // If the new decl is known invalid already, don't bother doing any
  // merging checks.
  if (New->isInvalidDecl()) return;

  // Allow multiple definitions for ObjC built-in typedefs.
  // FIXME: Verify the underlying types are equivalent!
  if (getLangOptions().ObjC1) {
    const IdentifierInfo *TypeID = New->getIdentifier();
    switch (TypeID->getLength()) {
    default: break;
    case 2:
      if (!TypeID->isStr("id"))
        break;
      Context.ObjCIdRedefinitionType = New->getUnderlyingType();
      // Install the built-in type for 'id', ignoring the current definition.
      New->setTypeForDecl(Context.getObjCIdType().getTypePtr());
      return;
    case 5:
      if (!TypeID->isStr("Class"))
        break;
      Context.ObjCClassRedefinitionType = New->getUnderlyingType();
      // Install the built-in type for 'Class', ignoring the current definition.
      New->setTypeForDecl(Context.getObjCClassType().getTypePtr());
      return;
    case 3:
      if (!TypeID->isStr("SEL"))
        break;
      Context.ObjCSelRedefinitionType = New->getUnderlyingType();
      // Install the built-in type for 'SEL', ignoring the current definition.
      New->setTypeForDecl(Context.getObjCSelType().getTypePtr());
      return;
    case 8:
      if (!TypeID->isStr("Protocol"))
        break;
      Context.setObjCProtoType(New->getUnderlyingType());
      return;
    }
    // Fall through - the typedef name was not a builtin type.
  }

  // Verify the old decl was also a type.
  TypeDecl *Old = OldDecls.getAsSingle<TypeDecl>();
  if (!Old) {
    Diag(New->getLocation(), diag::err_redefinition_different_kind)
      << New->getDeclName();

    NamedDecl *OldD = OldDecls.getRepresentativeDecl();
    if (OldD->getLocation().isValid())
      Diag(OldD->getLocation(), diag::note_previous_definition);

    return New->setInvalidDecl();
  }

  // If the old declaration is invalid, just give up here.
  if (Old->isInvalidDecl())
    return New->setInvalidDecl();

  // Determine the "old" type we'll use for checking and diagnostics.
  QualType OldType;
  if (TypedefDecl *OldTypedef = dyn_cast<TypedefDecl>(Old))
    OldType = OldTypedef->getUnderlyingType();
  else
    OldType = Context.getTypeDeclType(Old);

  // If the typedef types are not identical, reject them in all languages and
  // with any extensions enabled.

  if (OldType != New->getUnderlyingType() &&
      Context.getCanonicalType(OldType) !=
      Context.getCanonicalType(New->getUnderlyingType())) {
    Diag(New->getLocation(), diag::err_redefinition_different_typedef)
      << New->getUnderlyingType() << OldType;
    if (Old->getLocation().isValid())
      Diag(Old->getLocation(), diag::note_previous_definition);
    return New->setInvalidDecl();
  }

  // The types match.  Link up the redeclaration chain if the old
  // declaration was a typedef.
  // FIXME: this is a potential source of wierdness if the type
  // spellings don't match exactly.
  if (isa<TypedefDecl>(Old))
    New->setPreviousDeclaration(cast<TypedefDecl>(Old));

  if (getLangOptions().Microsoft)
    return;

  if (getLangOptions().CPlusPlus) {
    // C++ [dcl.typedef]p2:
    //   In a given non-class scope, a typedef specifier can be used to
    //   redefine the name of any type declared in that scope to refer
    //   to the type to which it already refers.
    if (!isa<CXXRecordDecl>(CurContext))
      return;

    // C++0x [dcl.typedef]p4:
    //   In a given class scope, a typedef specifier can be used to redefine 
    //   any class-name declared in that scope that is not also a typedef-name
    //   to refer to the type to which it already refers.
    //
    // This wording came in via DR424, which was a correction to the
    // wording in DR56, which accidentally banned code like:
    //
    //   struct S {
    //     typedef struct A { } A;
    //   };
    //
    // in the C++03 standard. We implement the C++0x semantics, which
    // allow the above but disallow
    //
    //   struct S {
    //     typedef int I;
    //     typedef int I;
    //   };
    //
    // since that was the intent of DR56.
    if (!isa<TypedefDecl >(Old))
      return;

    Diag(New->getLocation(), diag::err_redefinition)
      << New->getDeclName();
    Diag(Old->getLocation(), diag::note_previous_definition);
    return New->setInvalidDecl();
  }

  // If we have a redefinition of a typedef in C, emit a warning.  This warning
  // is normally mapped to an error, but can be controlled with
  // -Wtypedef-redefinition.  If either the original or the redefinition is
  // in a system header, don't emit this for compatibility with GCC.
  if (getDiagnostics().getSuppressSystemWarnings() &&
      (Context.getSourceManager().isInSystemHeader(Old->getLocation()) ||
       Context.getSourceManager().isInSystemHeader(New->getLocation())))
    return;

  Diag(New->getLocation(), diag::warn_redefinition_of_typedef)
    << New->getDeclName();
  Diag(Old->getLocation(), diag::note_previous_definition);
  return;
}

/// DeclhasAttr - returns true if decl Declaration already has the target
/// attribute.
static bool
DeclHasAttr(const Decl *decl, const Attr *target) {
  for (const Attr *attr = decl->getAttrs(); attr; attr = attr->getNext())
    if (attr->getKind() == target->getKind())
      return true;

  return false;
}

/// MergeAttributes - append attributes from the Old decl to the New one.
static void MergeAttributes(Decl *New, Decl *Old, ASTContext &C) {
  for (const Attr *attr = Old->getAttrs(); attr; attr = attr->getNext()) {
    if (!DeclHasAttr(New, attr) && attr->isMerged()) {
      Attr *NewAttr = attr->clone(C);
      NewAttr->setInherited(true);
      New->addAttr(NewAttr);
    }
  }
}

/// Used in MergeFunctionDecl to keep track of function parameters in
/// C.
struct GNUCompatibleParamWarning {
  ParmVarDecl *OldParm;
  ParmVarDecl *NewParm;
  QualType PromotedType;
};


/// getSpecialMember - get the special member enum for a method.
static Sema::CXXSpecialMember getSpecialMember(ASTContext &Ctx,
                                               const CXXMethodDecl *MD) {
  if (const CXXConstructorDecl *Ctor = dyn_cast<CXXConstructorDecl>(MD)) {
    if (Ctor->isDefaultConstructor())
      return Sema::CXXDefaultConstructor;
    if (Ctor->isCopyConstructor())
      return Sema::CXXCopyConstructor;
  } 
  
  if (isa<CXXDestructorDecl>(MD))
    return Sema::CXXDestructor;
  
  assert(MD->isCopyAssignment() && "Must have copy assignment operator");
  return Sema::CXXCopyAssignment;
}

/// canREdefineFunction - checks if a function can be redefined. Currently,
/// only extern inline functions can be redefined, and even then only in
/// GNU89 mode.
static bool canRedefineFunction(const FunctionDecl *FD,
                                const LangOptions& LangOpts) {
  return (LangOpts.GNUMode && !LangOpts.C99 && !LangOpts.CPlusPlus &&
          FD->isInlineSpecified() &&
          FD->getStorageClass() == FunctionDecl::Extern);
}

/// MergeFunctionDecl - We just parsed a function 'New' from
/// declarator D which has the same name and scope as a previous
/// declaration 'Old'.  Figure out how to resolve this situation,
/// merging decls or emitting diagnostics as appropriate.
///
/// In C++, New and Old must be declarations that are not
/// overloaded. Use IsOverload to determine whether New and Old are
/// overloaded, and to select the Old declaration that New should be
/// merged with.
///
/// Returns true if there was an error, false otherwise.
bool Sema::MergeFunctionDecl(FunctionDecl *New, Decl *OldD) {
  // Verify the old decl was also a function.
  FunctionDecl *Old = 0;
  if (FunctionTemplateDecl *OldFunctionTemplate
        = dyn_cast<FunctionTemplateDecl>(OldD))
    Old = OldFunctionTemplate->getTemplatedDecl();
  else
    Old = dyn_cast<FunctionDecl>(OldD);
  if (!Old) {
    if (UsingShadowDecl *Shadow = dyn_cast<UsingShadowDecl>(OldD)) {
      Diag(New->getLocation(), diag::err_using_decl_conflict_reverse);
      Diag(Shadow->getTargetDecl()->getLocation(),
           diag::note_using_decl_target);
      Diag(Shadow->getUsingDecl()->getLocation(),
           diag::note_using_decl) << 0;
      return true;
    }

    Diag(New->getLocation(), diag::err_redefinition_different_kind)
      << New->getDeclName();
    Diag(OldD->getLocation(), diag::note_previous_definition);
    return true;
  }

  // Determine whether the previous declaration was a definition,
  // implicit declaration, or a declaration.
  diag::kind PrevDiag;
  if (Old->isThisDeclarationADefinition())
    PrevDiag = diag::note_previous_definition;
  else if (Old->isImplicit())
    PrevDiag = diag::note_previous_implicit_declaration;
  else
    PrevDiag = diag::note_previous_declaration;

  QualType OldQType = Context.getCanonicalType(Old->getType());
  QualType NewQType = Context.getCanonicalType(New->getType());

  // Don't complain about this if we're in GNU89 mode and the old function
  // is an extern inline function.
  if (!isa<CXXMethodDecl>(New) && !isa<CXXMethodDecl>(Old) &&
      New->getStorageClass() == FunctionDecl::Static &&
      Old->getStorageClass() != FunctionDecl::Static &&
      !canRedefineFunction(Old, getLangOptions())) {
    Diag(New->getLocation(), diag::err_static_non_static)
      << New;
    Diag(Old->getLocation(), PrevDiag);
    return true;
  }

  // If a function is first declared with a calling convention, but is
  // later declared or defined without one, the second decl assumes the
  // calling convention of the first.
  //
  // For the new decl, we have to look at the NON-canonical type to tell the
  // difference between a function that really doesn't have a calling
  // convention and one that is declared cdecl. That's because in
  // canonicalization (see ASTContext.cpp), cdecl is canonicalized away
  // because it is the default calling convention.
  //
  // Note also that we DO NOT return at this point, because we still have
  // other tests to run.
  const FunctionType *OldType = OldQType->getAs<FunctionType>();
  const FunctionType *NewType = New->getType()->getAs<FunctionType>();
  if (OldType->getCallConv() != CC_Default &&
      NewType->getCallConv() == CC_Default) {
    NewQType = Context.getCallConvType(NewQType, OldType->getCallConv());
    New->setType(NewQType);
    NewQType = Context.getCanonicalType(NewQType);
  } else if (!Context.isSameCallConv(OldType->getCallConv(),
                                     NewType->getCallConv())) {
    // Calling conventions really aren't compatible, so complain.
    Diag(New->getLocation(), diag::err_cconv_change)
      << FunctionType::getNameForCallConv(NewType->getCallConv())
      << (OldType->getCallConv() == CC_Default)
      << (OldType->getCallConv() == CC_Default ? "" :
          FunctionType::getNameForCallConv(OldType->getCallConv()));
    Diag(Old->getLocation(), diag::note_previous_declaration);
    return true;
  }

  // FIXME: diagnose the other way around?
  if (OldType->getNoReturnAttr() && !NewType->getNoReturnAttr()) {
    NewQType = Context.getNoReturnType(NewQType);
    New->setType(NewQType);
    assert(NewQType.isCanonical());
  }

  if (getLangOptions().CPlusPlus) {
    // (C++98 13.1p2):
    //   Certain function declarations cannot be overloaded:
    //     -- Function declarations that differ only in the return type
    //        cannot be overloaded.
    QualType OldReturnType
      = cast<FunctionType>(OldQType.getTypePtr())->getResultType();
    QualType NewReturnType
      = cast<FunctionType>(NewQType.getTypePtr())->getResultType();
    if (OldReturnType != NewReturnType) {
      Diag(New->getLocation(), diag::err_ovl_diff_return_type);
      Diag(Old->getLocation(), PrevDiag) << Old << Old->getType();
      return true;
    }

    const CXXMethodDecl* OldMethod = dyn_cast<CXXMethodDecl>(Old);
    const CXXMethodDecl* NewMethod = dyn_cast<CXXMethodDecl>(New);
    if (OldMethod && NewMethod) {
      if (!NewMethod->getFriendObjectKind() &&
          NewMethod->getLexicalDeclContext()->isRecord()) {
        //    -- Member function declarations with the same name and the
        //       same parameter types cannot be overloaded if any of them
        //       is a static member function declaration.
        if (OldMethod->isStatic() || NewMethod->isStatic()) {
          Diag(New->getLocation(), diag::err_ovl_static_nonstatic_member);
          Diag(Old->getLocation(), PrevDiag) << Old << Old->getType();
          return true;
        }
      
        // C++ [class.mem]p1:
        //   [...] A member shall not be declared twice in the
        //   member-specification, except that a nested class or member
        //   class template can be declared and then later defined.
        unsigned NewDiag;
        if (isa<CXXConstructorDecl>(OldMethod))
          NewDiag = diag::err_constructor_redeclared;
        else if (isa<CXXDestructorDecl>(NewMethod))
          NewDiag = diag::err_destructor_redeclared;
        else if (isa<CXXConversionDecl>(NewMethod))
          NewDiag = diag::err_conv_function_redeclared;
        else
          NewDiag = diag::err_member_redeclared;

        Diag(New->getLocation(), NewDiag);
        Diag(Old->getLocation(), PrevDiag) << Old << Old->getType();
      } else {
        if (OldMethod->isImplicit()) {
          Diag(NewMethod->getLocation(),
               diag::err_definition_of_implicitly_declared_member) 
          << New << getSpecialMember(Context, OldMethod);
        
          Diag(OldMethod->getLocation(),
               diag::note_previous_implicit_declaration);
          return true;
        }
      }
    }

    // (C++98 8.3.5p3):
    //   All declarations for a function shall agree exactly in both the
    //   return type and the parameter-type-list.
    // attributes should be ignored when comparing.
    if (Context.getNoReturnType(OldQType, false) ==
        Context.getNoReturnType(NewQType, false))
      return MergeCompatibleFunctionDecls(New, Old);

    // Fall through for conflicting redeclarations and redefinitions.
  }

  // C: Function types need to be compatible, not identical. This handles
  // duplicate function decls like "void f(int); void f(enum X);" properly.
  if (!getLangOptions().CPlusPlus &&
      Context.typesAreCompatible(OldQType, NewQType)) {
    const FunctionType *OldFuncType = OldQType->getAs<FunctionType>();
    const FunctionType *NewFuncType = NewQType->getAs<FunctionType>();
    const FunctionProtoType *OldProto = 0;
    if (isa<FunctionNoProtoType>(NewFuncType) &&
        (OldProto = dyn_cast<FunctionProtoType>(OldFuncType))) {
      // The old declaration provided a function prototype, but the
      // new declaration does not. Merge in the prototype.
      assert(!OldProto->hasExceptionSpec() && "Exception spec in C");
      llvm::SmallVector<QualType, 16> ParamTypes(OldProto->arg_type_begin(),
                                                 OldProto->arg_type_end());
      NewQType = Context.getFunctionType(NewFuncType->getResultType(),
                                         ParamTypes.data(), ParamTypes.size(),
                                         OldProto->isVariadic(),
                                         OldProto->getTypeQuals(),
                                         false, false, 0, 0,
                                         OldProto->getNoReturnAttr(),
                                         OldProto->getCallConv());
      New->setType(NewQType);
      New->setHasInheritedPrototype();

      // Synthesize a parameter for each argument type.
      llvm::SmallVector<ParmVarDecl*, 16> Params;
      for (FunctionProtoType::arg_type_iterator
             ParamType = OldProto->arg_type_begin(),
             ParamEnd = OldProto->arg_type_end();
           ParamType != ParamEnd; ++ParamType) {
        ParmVarDecl *Param = ParmVarDecl::Create(Context, New,
                                                 SourceLocation(), 0,
                                                 *ParamType, /*TInfo=*/0,
                                                 VarDecl::None, 0);
        Param->setImplicit();
        Params.push_back(Param);
      }

      New->setParams(Params.data(), Params.size());
    }

    return MergeCompatibleFunctionDecls(New, Old);
  }

  // GNU C permits a K&R definition to follow a prototype declaration
  // if the declared types of the parameters in the K&R definition
  // match the types in the prototype declaration, even when the
  // promoted types of the parameters from the K&R definition differ
  // from the types in the prototype. GCC then keeps the types from
  // the prototype.
  //
  // If a variadic prototype is followed by a non-variadic K&R definition,
  // the K&R definition becomes variadic.  This is sort of an edge case, but
  // it's legal per the standard depending on how you read C99 6.7.5.3p15 and
  // C99 6.9.1p8.
  if (!getLangOptions().CPlusPlus &&
      Old->hasPrototype() && !New->hasPrototype() &&
      New->getType()->getAs<FunctionProtoType>() &&
      Old->getNumParams() == New->getNumParams()) {
    llvm::SmallVector<QualType, 16> ArgTypes;
    llvm::SmallVector<GNUCompatibleParamWarning, 16> Warnings;
    const FunctionProtoType *OldProto
      = Old->getType()->getAs<FunctionProtoType>();
    const FunctionProtoType *NewProto
      = New->getType()->getAs<FunctionProtoType>();

    // Determine whether this is the GNU C extension.
    QualType MergedReturn = Context.mergeTypes(OldProto->getResultType(),
                                               NewProto->getResultType());
    bool LooseCompatible = !MergedReturn.isNull();
    for (unsigned Idx = 0, End = Old->getNumParams();
         LooseCompatible && Idx != End; ++Idx) {
      ParmVarDecl *OldParm = Old->getParamDecl(Idx);
      ParmVarDecl *NewParm = New->getParamDecl(Idx);
      if (Context.typesAreCompatible(OldParm->getType(),
                                     NewProto->getArgType(Idx))) {
        ArgTypes.push_back(NewParm->getType());
      } else if (Context.typesAreCompatible(OldParm->getType(),
                                            NewParm->getType())) {
        GNUCompatibleParamWarning Warn
          = { OldParm, NewParm, NewProto->getArgType(Idx) };
        Warnings.push_back(Warn);
        ArgTypes.push_back(NewParm->getType());
      } else
        LooseCompatible = false;
    }

    if (LooseCompatible) {
      for (unsigned Warn = 0; Warn < Warnings.size(); ++Warn) {
        Diag(Warnings[Warn].NewParm->getLocation(),
             diag::ext_param_promoted_not_compatible_with_prototype)
          << Warnings[Warn].PromotedType
          << Warnings[Warn].OldParm->getType();
        Diag(Warnings[Warn].OldParm->getLocation(),
             diag::note_previous_declaration);
      }

      New->setType(Context.getFunctionType(MergedReturn, &ArgTypes[0],
                                           ArgTypes.size(),
                                           OldProto->isVariadic(), 0,
                                           false, false, 0, 0,
                                           OldProto->getNoReturnAttr(),
                                           OldProto->getCallConv()));
      return MergeCompatibleFunctionDecls(New, Old);
    }

    // Fall through to diagnose conflicting types.
  }

  // A function that has already been declared has been redeclared or defined
  // with a different type- show appropriate diagnostic
  if (unsigned BuiltinID = Old->getBuiltinID()) {
    // The user has declared a builtin function with an incompatible
    // signature.
    if (Context.BuiltinInfo.isPredefinedLibFunction(BuiltinID)) {
      // The function the user is redeclaring is a library-defined
      // function like 'malloc' or 'printf'. Warn about the
      // redeclaration, then pretend that we don't know about this
      // library built-in.
      Diag(New->getLocation(), diag::warn_redecl_library_builtin) << New;
      Diag(Old->getLocation(), diag::note_previous_builtin_declaration)
        << Old << Old->getType();
      New->getIdentifier()->setBuiltinID(Builtin::NotBuiltin);
      Old->setInvalidDecl();
      return false;
    }

    PrevDiag = diag::note_previous_builtin_declaration;
  }

  Diag(New->getLocation(), diag::err_conflicting_types) << New->getDeclName();
  Diag(Old->getLocation(), PrevDiag) << Old << Old->getType();
  return true;
}

/// \brief Completes the merge of two function declarations that are
/// known to be compatible.
///
/// This routine handles the merging of attributes and other
/// properties of function declarations form the old declaration to
/// the new declaration, once we know that New is in fact a
/// redeclaration of Old.
///
/// \returns false
bool Sema::MergeCompatibleFunctionDecls(FunctionDecl *New, FunctionDecl *Old) {
  // Merge the attributes
  MergeAttributes(New, Old, Context);

  // Merge the storage class.
  if (Old->getStorageClass() != FunctionDecl::Extern &&
      Old->getStorageClass() != FunctionDecl::None)
    New->setStorageClass(Old->getStorageClass());

  // Merge "pure" flag.
  if (Old->isPure())
    New->setPure();

  // Merge the "deleted" flag.
  if (Old->isDeleted())
    New->setDeleted();

  if (getLangOptions().CPlusPlus)
    return MergeCXXFunctionDecl(New, Old);

  return false;
}

/// MergeVarDecl - We just parsed a variable 'New' which has the same name
/// and scope as a previous declaration 'Old'.  Figure out how to resolve this
/// situation, merging decls or emitting diagnostics as appropriate.
///
/// Tentative definition rules (C99 6.9.2p2) are checked by
/// FinalizeDeclaratorGroup. Unfortunately, we can't analyze tentative
/// definitions here, since the initializer hasn't been attached.
///
void Sema::MergeVarDecl(VarDecl *New, LookupResult &Previous) {
  // If the new decl is already invalid, don't do any other checking.
  if (New->isInvalidDecl())
    return;

  // Verify the old decl was also a variable.
  VarDecl *Old = 0;
  if (!Previous.isSingleResult() ||
      !(Old = dyn_cast<VarDecl>(Previous.getFoundDecl()))) {
    Diag(New->getLocation(), diag::err_redefinition_different_kind)
      << New->getDeclName();
    Diag(Previous.getRepresentativeDecl()->getLocation(),
         diag::note_previous_definition);
    return New->setInvalidDecl();
  }

  MergeAttributes(New, Old, Context);

  // Merge the types
  QualType MergedT;
  if (getLangOptions().CPlusPlus) {
    if (Context.hasSameType(New->getType(), Old->getType()))
      MergedT = New->getType();
    // C++ [basic.link]p10:
    //   [...] the types specified by all declarations referring to a given
    //   object or function shall be identical, except that declarations for an
    //   array object can specify array types that differ by the presence or
    //   absence of a major array bound (8.3.4).
    else if (Old->getType()->isIncompleteArrayType() &&
             New->getType()->isArrayType()) {
      CanQual<ArrayType> OldArray
        = Context.getCanonicalType(Old->getType())->getAs<ArrayType>();
      CanQual<ArrayType> NewArray
        = Context.getCanonicalType(New->getType())->getAs<ArrayType>();
      if (OldArray->getElementType() == NewArray->getElementType())
        MergedT = New->getType();
    } else if (Old->getType()->isArrayType() &&
             New->getType()->isIncompleteArrayType()) {
      CanQual<ArrayType> OldArray
        = Context.getCanonicalType(Old->getType())->getAs<ArrayType>();
      CanQual<ArrayType> NewArray
        = Context.getCanonicalType(New->getType())->getAs<ArrayType>();
      if (OldArray->getElementType() == NewArray->getElementType())
        MergedT = Old->getType();
    }
  } else {
    MergedT = Context.mergeTypes(New->getType(), Old->getType());
  }
  if (MergedT.isNull()) {
    Diag(New->getLocation(), diag::err_redefinition_different_type)
      << New->getDeclName();
    Diag(Old->getLocation(), diag::note_previous_definition);
    return New->setInvalidDecl();
  }
  New->setType(MergedT);

  // C99 6.2.2p4: Check if we have a static decl followed by a non-static.
  if (New->getStorageClass() == VarDecl::Static &&
      (Old->getStorageClass() == VarDecl::None || Old->hasExternalStorage())) {
    Diag(New->getLocation(), diag::err_static_non_static) << New->getDeclName();
    Diag(Old->getLocation(), diag::note_previous_definition);
    return New->setInvalidDecl();
  }
  // C99 6.2.2p4:
  //   For an identifier declared with the storage-class specifier
  //   extern in a scope in which a prior declaration of that
  //   identifier is visible,23) if the prior declaration specifies
  //   internal or external linkage, the linkage of the identifier at
  //   the later declaration is the same as the linkage specified at
  //   the prior declaration. If no prior declaration is visible, or
  //   if the prior declaration specifies no linkage, then the
  //   identifier has external linkage.
  if (New->hasExternalStorage() && Old->hasLinkage())
    /* Okay */;
  else if (New->getStorageClass() != VarDecl::Static &&
           Old->getStorageClass() == VarDecl::Static) {
    Diag(New->getLocation(), diag::err_non_static_static) << New->getDeclName();
    Diag(Old->getLocation(), diag::note_previous_definition);
    return New->setInvalidDecl();
  }

  // Variables with external linkage are analyzed in FinalizeDeclaratorGroup.

  // FIXME: The test for external storage here seems wrong? We still
  // need to check for mismatches.
  if (!New->hasExternalStorage() && !New->isFileVarDecl() &&
      // Don't complain about out-of-line definitions of static members.
      !(Old->getLexicalDeclContext()->isRecord() &&
        !New->getLexicalDeclContext()->isRecord())) {
    Diag(New->getLocation(), diag::err_redefinition) << New->getDeclName();
    Diag(Old->getLocation(), diag::note_previous_definition);
    return New->setInvalidDecl();
  }

  if (New->isThreadSpecified() && !Old->isThreadSpecified()) {
    Diag(New->getLocation(), diag::err_thread_non_thread) << New->getDeclName();
    Diag(Old->getLocation(), diag::note_previous_definition);
  } else if (!New->isThreadSpecified() && Old->isThreadSpecified()) {
    Diag(New->getLocation(), diag::err_non_thread_thread) << New->getDeclName();
    Diag(Old->getLocation(), diag::note_previous_definition);
  }

  // C++ doesn't have tentative definitions, so go right ahead and check here.
  const VarDecl *Def;
  if (getLangOptions().CPlusPlus &&
      New->isThisDeclarationADefinition() == VarDecl::Definition &&
      (Def = Old->getDefinition())) {
    Diag(New->getLocation(), diag::err_redefinition)
      << New->getDeclName();
    Diag(Def->getLocation(), diag::note_previous_definition);
    New->setInvalidDecl();
    return;
  }

  // Keep a chain of previous declarations.
  New->setPreviousDeclaration(Old);

  // Inherit access appropriately.
  New->setAccess(Old->getAccess());
}

/// ParsedFreeStandingDeclSpec - This method is invoked when a declspec with
/// no declarator (e.g. "struct foo;") is parsed.
Sema::DeclPtrTy Sema::ParsedFreeStandingDeclSpec(Scope *S, DeclSpec &DS) {
  // FIXME: Error on auto/register at file scope
  // FIXME: Error on inline/virtual/explicit
  // FIXME: Warn on useless __thread
  // FIXME: Warn on useless const/volatile
  // FIXME: Warn on useless static/extern/typedef/private_extern/mutable
  // FIXME: Warn on useless attributes
  Decl *TagD = 0;
  TagDecl *Tag = 0;
  if (DS.getTypeSpecType() == DeclSpec::TST_class ||
      DS.getTypeSpecType() == DeclSpec::TST_struct ||
      DS.getTypeSpecType() == DeclSpec::TST_union ||
      DS.getTypeSpecType() == DeclSpec::TST_enum) {
    TagD = static_cast<Decl *>(DS.getTypeRep());

    if (!TagD) // We probably had an error
      return DeclPtrTy();

    // Note that the above type specs guarantee that the
    // type rep is a Decl, whereas in many of the others
    // it's a Type.
    Tag = dyn_cast<TagDecl>(TagD);
  }

  if (unsigned TypeQuals = DS.getTypeQualifiers()) {
    // Enforce C99 6.7.3p2: "Types other than pointer types derived from object
    // or incomplete types shall not be restrict-qualified."
    if (TypeQuals & DeclSpec::TQ_restrict)
      Diag(DS.getRestrictSpecLoc(),
           diag::err_typecheck_invalid_restrict_not_pointer_noarg)
           << DS.getSourceRange();
  }

  if (DS.isFriendSpecified()) {
    // If we're dealing with a class template decl, assume that the
    // template routines are handling it.
    if (TagD && isa<ClassTemplateDecl>(TagD))
      return DeclPtrTy();
    return ActOnFriendTypeDecl(S, DS, MultiTemplateParamsArg(*this, 0, 0));
  }
         
  if (RecordDecl *Record = dyn_cast_or_null<RecordDecl>(Tag)) {
    // If there are attributes in the DeclSpec, apply them to the record.
    if (const AttributeList *AL = DS.getAttributes())
      ProcessDeclAttributeList(S, Record, AL);
    
    if (!Record->getDeclName() && Record->isDefinition() &&
        DS.getStorageClassSpec() != DeclSpec::SCS_typedef) {
      if (getLangOptions().CPlusPlus ||
          Record->getDeclContext()->isRecord())
        return BuildAnonymousStructOrUnion(S, DS, Record);

      Diag(DS.getSourceRange().getBegin(), diag::err_no_declarators)
        << DS.getSourceRange();
    }

    // Microsoft allows unnamed struct/union fields. Don't complain
    // about them.
    // FIXME: Should we support Microsoft's extensions in this area?
    if (Record->getDeclName() && getLangOptions().Microsoft)
      return DeclPtrTy::make(Tag);
  }
  
  if (!DS.isMissingDeclaratorOk() &&
      DS.getTypeSpecType() != DeclSpec::TST_error) {
    // Warn about typedefs of enums without names, since this is an
    // extension in both Microsoft an GNU.
    if (DS.getStorageClassSpec() == DeclSpec::SCS_typedef &&
        Tag && isa<EnumDecl>(Tag)) {
      Diag(DS.getSourceRange().getBegin(), diag::ext_typedef_without_a_name)
        << DS.getSourceRange();
      return DeclPtrTy::make(Tag);
    }

    Diag(DS.getSourceRange().getBegin(), diag::err_no_declarators)
      << DS.getSourceRange();
    return DeclPtrTy();
  }

  return DeclPtrTy::make(Tag);
}

/// We are trying to inject an anonymous member into the given scope;
/// check if there's an existing declaration that can't be overloaded.
///
/// \return true if this is a forbidden redeclaration
static bool CheckAnonMemberRedeclaration(Sema &SemaRef,
                                         Scope *S,
                                         DeclContext *Owner,
                                         DeclarationName Name,
                                         SourceLocation NameLoc,
                                         unsigned diagnostic) {
  LookupResult R(SemaRef, Name, NameLoc, Sema::LookupMemberName,
                 Sema::ForRedeclaration);
  if (!SemaRef.LookupName(R, S)) return false;

  if (R.getAsSingle<TagDecl>())
    return false;

  // Pick a representative declaration.
  NamedDecl *PrevDecl = R.getRepresentativeDecl()->getUnderlyingDecl();
  if (PrevDecl && Owner->isRecord()) {
    RecordDecl *Record = cast<RecordDecl>(Owner);
    if (!SemaRef.isDeclInScope(PrevDecl, Record, S))
      return false;
  }

  SemaRef.Diag(NameLoc, diagnostic) << Name;
  SemaRef.Diag(PrevDecl->getLocation(), diag::note_previous_declaration);

  return true;
}

/// InjectAnonymousStructOrUnionMembers - Inject the members of the
/// anonymous struct or union AnonRecord into the owning context Owner
/// and scope S. This routine will be invoked just after we realize
/// that an unnamed union or struct is actually an anonymous union or
/// struct, e.g.,
///
/// @code
/// union {
///   int i;
///   float f;
/// }; // InjectAnonymousStructOrUnionMembers called here to inject i and
///    // f into the surrounding scope.x
/// @endcode
///
/// This routine is recursive, injecting the names of nested anonymous
/// structs/unions into the owning context and scope as well.
bool Sema::InjectAnonymousStructOrUnionMembers(Scope *S, DeclContext *Owner,
                                               RecordDecl *AnonRecord) {
  unsigned diagKind
    = AnonRecord->isUnion() ? diag::err_anonymous_union_member_redecl
                            : diag::err_anonymous_struct_member_redecl;

  bool Invalid = false;
  for (RecordDecl::field_iterator F = AnonRecord->field_begin(),
                               FEnd = AnonRecord->field_end();
       F != FEnd; ++F) {
    if ((*F)->getDeclName()) {
      if (CheckAnonMemberRedeclaration(*this, S, Owner, (*F)->getDeclName(),
                                       (*F)->getLocation(), diagKind)) {
        // C++ [class.union]p2:
        //   The names of the members of an anonymous union shall be
        //   distinct from the names of any other entity in the
        //   scope in which the anonymous union is declared.
        Invalid = true;
      } else {
        // C++ [class.union]p2:
        //   For the purpose of name lookup, after the anonymous union
        //   definition, the members of the anonymous union are
        //   considered to have been defined in the scope in which the
        //   anonymous union is declared.
        Owner->makeDeclVisibleInContext(*F);
        S->AddDecl(DeclPtrTy::make(*F));
        IdResolver.AddDecl(*F);
      }
    } else if (const RecordType *InnerRecordType
                 = (*F)->getType()->getAs<RecordType>()) {
      RecordDecl *InnerRecord = InnerRecordType->getDecl();
      if (InnerRecord->isAnonymousStructOrUnion())
        Invalid = Invalid ||
          InjectAnonymousStructOrUnionMembers(S, Owner, InnerRecord);
    }
  }

  return Invalid;
}

/// ActOnAnonymousStructOrUnion - Handle the declaration of an
/// anonymous structure or union. Anonymous unions are a C++ feature
/// (C++ [class.union]) and a GNU C extension; anonymous structures
/// are a GNU C and GNU C++ extension.
Sema::DeclPtrTy Sema::BuildAnonymousStructOrUnion(Scope *S, DeclSpec &DS,
                                                  RecordDecl *Record) {
  DeclContext *Owner = Record->getDeclContext();

  // Diagnose whether this anonymous struct/union is an extension.
  if (Record->isUnion() && !getLangOptions().CPlusPlus)
    Diag(Record->getLocation(), diag::ext_anonymous_union);
  else if (!Record->isUnion())
    Diag(Record->getLocation(), diag::ext_anonymous_struct);

  // C and C++ require different kinds of checks for anonymous
  // structs/unions.
  bool Invalid = false;
  if (getLangOptions().CPlusPlus) {
    const char* PrevSpec = 0;
    unsigned DiagID;
    // C++ [class.union]p3:
    //   Anonymous unions declared in a named namespace or in the
    //   global namespace shall be declared static.
    if (DS.getStorageClassSpec() != DeclSpec::SCS_static &&
        (isa<TranslationUnitDecl>(Owner) ||
         (isa<NamespaceDecl>(Owner) &&
          cast<NamespaceDecl>(Owner)->getDeclName()))) {
      Diag(Record->getLocation(), diag::err_anonymous_union_not_static);
      Invalid = true;

      // Recover by adding 'static'.
      DS.SetStorageClassSpec(DeclSpec::SCS_static, SourceLocation(),
                             PrevSpec, DiagID);
    }
    // C++ [class.union]p3:
    //   A storage class is not allowed in a declaration of an
    //   anonymous union in a class scope.
    else if (DS.getStorageClassSpec() != DeclSpec::SCS_unspecified &&
             isa<RecordDecl>(Owner)) {
      Diag(DS.getStorageClassSpecLoc(),
           diag::err_anonymous_union_with_storage_spec);
      Invalid = true;

      // Recover by removing the storage specifier.
      DS.SetStorageClassSpec(DeclSpec::SCS_unspecified, SourceLocation(),
                             PrevSpec, DiagID);
    }

    // C++ [class.union]p2:
    //   The member-specification of an anonymous union shall only
    //   define non-static data members. [Note: nested types and
    //   functions cannot be declared within an anonymous union. ]
    for (DeclContext::decl_iterator Mem = Record->decls_begin(),
                                 MemEnd = Record->decls_end();
         Mem != MemEnd; ++Mem) {
      if (FieldDecl *FD = dyn_cast<FieldDecl>(*Mem)) {
        // C++ [class.union]p3:
        //   An anonymous union shall not have private or protected
        //   members (clause 11).
        if (FD->getAccess() == AS_protected || FD->getAccess() == AS_private) {
          Diag(FD->getLocation(), diag::err_anonymous_record_nonpublic_member)
            << (int)Record->isUnion() << (int)(FD->getAccess() == AS_protected);
          Invalid = true;
        }
      } else if ((*Mem)->isImplicit()) {
        // Any implicit members are fine.
      } else if (isa<TagDecl>(*Mem) && (*Mem)->getDeclContext() != Record) {
        // This is a type that showed up in an
        // elaborated-type-specifier inside the anonymous struct or
        // union, but which actually declares a type outside of the
        // anonymous struct or union. It's okay.
      } else if (RecordDecl *MemRecord = dyn_cast<RecordDecl>(*Mem)) {
        if (!MemRecord->isAnonymousStructOrUnion() &&
            MemRecord->getDeclName()) {
          // This is a nested type declaration.
          Diag(MemRecord->getLocation(), diag::err_anonymous_record_with_type)
            << (int)Record->isUnion();
          Invalid = true;
        }
      } else {
        // We have something that isn't a non-static data
        // member. Complain about it.
        unsigned DK = diag::err_anonymous_record_bad_member;
        if (isa<TypeDecl>(*Mem))
          DK = diag::err_anonymous_record_with_type;
        else if (isa<FunctionDecl>(*Mem))
          DK = diag::err_anonymous_record_with_function;
        else if (isa<VarDecl>(*Mem))
          DK = diag::err_anonymous_record_with_static;
        Diag((*Mem)->getLocation(), DK)
            << (int)Record->isUnion();
          Invalid = true;
      }
    }
  }

  if (!Record->isUnion() && !Owner->isRecord()) {
    Diag(Record->getLocation(), diag::err_anonymous_struct_not_member)
      << (int)getLangOptions().CPlusPlus;
    Invalid = true;
  }

  // Mock up a declarator.
  Declarator Dc(DS, Declarator::TypeNameContext);
  TypeSourceInfo *TInfo = 0;
  GetTypeForDeclarator(Dc, S, &TInfo);
  assert(TInfo && "couldn't build declarator info for anonymous struct/union");

  // Create a declaration for this anonymous struct/union.
  NamedDecl *Anon = 0;
  if (RecordDecl *OwningClass = dyn_cast<RecordDecl>(Owner)) {
    Anon = FieldDecl::Create(Context, OwningClass, Record->getLocation(),
                             /*IdentifierInfo=*/0,
                             Context.getTypeDeclType(Record),
                             TInfo,
                             /*BitWidth=*/0, /*Mutable=*/false);
    Anon->setAccess(AS_public);
    if (getLangOptions().CPlusPlus)
      FieldCollector->Add(cast<FieldDecl>(Anon));
  } else {
    VarDecl::StorageClass SC;
    switch (DS.getStorageClassSpec()) {
    default: assert(0 && "Unknown storage class!");
    case DeclSpec::SCS_unspecified:    SC = VarDecl::None; break;
    case DeclSpec::SCS_extern:         SC = VarDecl::Extern; break;
    case DeclSpec::SCS_static:         SC = VarDecl::Static; break;
    case DeclSpec::SCS_auto:           SC = VarDecl::Auto; break;
    case DeclSpec::SCS_register:       SC = VarDecl::Register; break;
    case DeclSpec::SCS_private_extern: SC = VarDecl::PrivateExtern; break;
    case DeclSpec::SCS_mutable:
      // mutable can only appear on non-static class members, so it's always
      // an error here
      Diag(Record->getLocation(), diag::err_mutable_nonmember);
      Invalid = true;
      SC = VarDecl::None;
      break;
    }

    Anon = VarDecl::Create(Context, Owner, Record->getLocation(),
                           /*IdentifierInfo=*/0,
                           Context.getTypeDeclType(Record),
                           TInfo,
                           SC);
  }
  Anon->setImplicit();

  // Add the anonymous struct/union object to the current
  // context. We'll be referencing this object when we refer to one of
  // its members.
  Owner->addDecl(Anon);

  // Inject the members of the anonymous struct/union into the owning
  // context and into the identifier resolver chain for name lookup
  // purposes.
  if (InjectAnonymousStructOrUnionMembers(S, Owner, Record))
    Invalid = true;

  // Mark this as an anonymous struct/union type. Note that we do not
  // do this until after we have already checked and injected the
  // members of this anonymous struct/union type, because otherwise
  // the members could be injected twice: once by DeclContext when it
  // builds its lookup table, and once by
  // InjectAnonymousStructOrUnionMembers.
  Record->setAnonymousStructOrUnion(true);

  if (Invalid)
    Anon->setInvalidDecl();

  return DeclPtrTy::make(Anon);
}


/// GetNameForDeclarator - Determine the full declaration name for the
/// given Declarator.
DeclarationName Sema::GetNameForDeclarator(Declarator &D) {
  return GetNameFromUnqualifiedId(D.getName());
}

/// \brief Retrieves the canonicalized name from a parsed unqualified-id.
DeclarationName Sema::GetNameFromUnqualifiedId(const UnqualifiedId &Name) {
  switch (Name.getKind()) {
    case UnqualifiedId::IK_Identifier:
      return DeclarationName(Name.Identifier);
      
    case UnqualifiedId::IK_OperatorFunctionId:
      return Context.DeclarationNames.getCXXOperatorName(
                                              Name.OperatorFunctionId.Operator);

    case UnqualifiedId::IK_LiteralOperatorId:
      return Context.DeclarationNames.getCXXLiteralOperatorName(
                                                               Name.Identifier);

    case UnqualifiedId::IK_ConversionFunctionId: {
      QualType Ty = GetTypeFromParser(Name.ConversionFunctionId);
      if (Ty.isNull())
        return DeclarationName();
      
      return Context.DeclarationNames.getCXXConversionFunctionName(
                                                  Context.getCanonicalType(Ty));
    }
      
    case UnqualifiedId::IK_ConstructorName: {
      QualType Ty = GetTypeFromParser(Name.ConstructorName);
      if (Ty.isNull())
        return DeclarationName();
      
      return Context.DeclarationNames.getCXXConstructorName(
                                                  Context.getCanonicalType(Ty));
    }
      
    case UnqualifiedId::IK_ConstructorTemplateId: {
      // In well-formed code, we can only have a constructor
      // template-id that refers to the current context, so go there
      // to find the actual type being constructed.
      CXXRecordDecl *CurClass = dyn_cast<CXXRecordDecl>(CurContext);
      if (!CurClass || CurClass->getIdentifier() != Name.TemplateId->Name)
        return DeclarationName();

      // Determine the type of the class being constructed.
      QualType CurClassType;
      if (ClassTemplateDecl *ClassTemplate
            = CurClass->getDescribedClassTemplate())
        CurClassType = ClassTemplate->getInjectedClassNameType(Context);
      else
        CurClassType = Context.getTypeDeclType(CurClass);

      // FIXME: Check two things: that the template-id names the same type as
      // CurClassType, and that the template-id does not occur when the name
      // was qualified.

      return Context.DeclarationNames.getCXXConstructorName(
                                       Context.getCanonicalType(CurClassType));
    }

    case UnqualifiedId::IK_DestructorName: {
      QualType Ty = GetTypeFromParser(Name.DestructorName);
      if (Ty.isNull())
        return DeclarationName();
      
      return Context.DeclarationNames.getCXXDestructorName(
                                                           Context.getCanonicalType(Ty));
    }
      
    case UnqualifiedId::IK_TemplateId: {
      TemplateName TName
        = TemplateName::getFromVoidPointer(Name.TemplateId->Template);
      return Context.getNameForTemplate(TName);
    }
  }
  
  assert(false && "Unknown name kind");
  return DeclarationName();  
}

/// isNearlyMatchingFunction - Determine whether the C++ functions
/// Declaration and Definition are "nearly" matching. This heuristic
/// is used to improve diagnostics in the case where an out-of-line
/// function definition doesn't match any declaration within
/// the class or namespace.
static bool isNearlyMatchingFunction(ASTContext &Context,
                                     FunctionDecl *Declaration,
                                     FunctionDecl *Definition) {
  if (Declaration->param_size() != Definition->param_size())
    return false;
  for (unsigned Idx = 0; Idx < Declaration->param_size(); ++Idx) {
    QualType DeclParamTy = Declaration->getParamDecl(Idx)->getType();
    QualType DefParamTy = Definition->getParamDecl(Idx)->getType();

    if (!Context.hasSameUnqualifiedType(DeclParamTy.getNonReferenceType(),
                                        DefParamTy.getNonReferenceType()))
      return false;
  }

  return true;
}

Sema::DeclPtrTy
Sema::HandleDeclarator(Scope *S, Declarator &D,
                       MultiTemplateParamsArg TemplateParamLists,
                       bool IsFunctionDefinition) {
  DeclarationName Name = GetNameForDeclarator(D);

  // All of these full declarators require an identifier.  If it doesn't have
  // one, the ParsedFreeStandingDeclSpec action should be used.
  if (!Name) {
    if (!D.isInvalidType())  // Reject this if we think it is valid.
      Diag(D.getDeclSpec().getSourceRange().getBegin(),
           diag::err_declarator_need_ident)
        << D.getDeclSpec().getSourceRange() << D.getSourceRange();
    return DeclPtrTy();
  }

  // The scope passed in may not be a decl scope.  Zip up the scope tree until
  // we find one that is.
  while ((S->getFlags() & Scope::DeclScope) == 0 ||
         (S->getFlags() & Scope::TemplateParamScope) != 0)
    S = S->getParent();

  // If this is an out-of-line definition of a member of a class template
  // or class template partial specialization, we may need to rebuild the
  // type specifier in the declarator. See RebuildTypeInCurrentInstantiation()
  // for more information.
  // FIXME: cope with decltype(expr) and typeof(expr) once the rebuilder can
  // handle expressions properly.
  DeclSpec &DS = const_cast<DeclSpec&>(D.getDeclSpec());
  if (D.getCXXScopeSpec().isSet() && !D.getCXXScopeSpec().isInvalid() &&
      isDependentScopeSpecifier(D.getCXXScopeSpec()) &&
      (DS.getTypeSpecType() == DeclSpec::TST_typename ||
       DS.getTypeSpecType() == DeclSpec::TST_typeofType ||
       DS.getTypeSpecType() == DeclSpec::TST_typeofExpr ||
       DS.getTypeSpecType() == DeclSpec::TST_decltype)) {
    if (DeclContext *DC = computeDeclContext(D.getCXXScopeSpec(), true)) {
      // FIXME: Preserve type source info.
      QualType T = GetTypeFromParser(DS.getTypeRep());

      DeclContext *SavedContext = CurContext;
      CurContext = DC;
      T = RebuildTypeInCurrentInstantiation(T, D.getIdentifierLoc(), Name);
      CurContext = SavedContext;

      if (T.isNull())
        return DeclPtrTy();
      DS.UpdateTypeRep(T.getAsOpaquePtr());
    }
  }

  DeclContext *DC;
  NamedDecl *New;

  TypeSourceInfo *TInfo = 0;
  QualType R = GetTypeForDeclarator(D, S, &TInfo);

  LookupResult Previous(*this, Name, D.getIdentifierLoc(), LookupOrdinaryName,
                        ForRedeclaration);

  // See if this is a redefinition of a variable in the same scope.
  if (D.getCXXScopeSpec().isInvalid()) {
    DC = CurContext;
    D.setInvalidType();
  } else if (!D.getCXXScopeSpec().isSet()) {
    bool IsLinkageLookup = false;

    // If the declaration we're planning to build will be a function
    // or object with linkage, then look for another declaration with
    // linkage (C99 6.2.2p4-5 and C++ [basic.link]p6).
    if (D.getDeclSpec().getStorageClassSpec() == DeclSpec::SCS_typedef)
      /* Do nothing*/;
    else if (R->isFunctionType()) {
      if (CurContext->isFunctionOrMethod() ||
          D.getDeclSpec().getStorageClassSpec() != DeclSpec::SCS_static)
        IsLinkageLookup = true;
    } else if (D.getDeclSpec().getStorageClassSpec() == DeclSpec::SCS_extern)
      IsLinkageLookup = true;
    else if (CurContext->getLookupContext()->isTranslationUnit() &&
             D.getDeclSpec().getStorageClassSpec() != DeclSpec::SCS_static)
      IsLinkageLookup = true;

    if (IsLinkageLookup)
      Previous.clear(LookupRedeclarationWithLinkage);

    DC = CurContext;
    LookupName(Previous, S, /* CreateBuiltins = */ IsLinkageLookup);
  } else { // Something like "int foo::x;"
    DC = computeDeclContext(D.getCXXScopeSpec(), true);

    if (!DC) {
      // If we could not compute the declaration context, it's because the
      // declaration context is dependent but does not refer to a class,
      // class template, or class template partial specialization. Complain
      // and return early, to avoid the coming semantic disaster.
      Diag(D.getIdentifierLoc(),
           diag::err_template_qualified_declarator_no_match)
        << (NestedNameSpecifier*)D.getCXXScopeSpec().getScopeRep()
        << D.getCXXScopeSpec().getRange();
      return DeclPtrTy();
    }

    if (!DC->isDependentContext() && 
        RequireCompleteDeclContext(D.getCXXScopeSpec()))
      return DeclPtrTy();

    if (isa<CXXRecordDecl>(DC) && !cast<CXXRecordDecl>(DC)->hasDefinition()) {
      Diag(D.getIdentifierLoc(),
           diag::err_member_def_undefined_record)
        << Name << DC << D.getCXXScopeSpec().getRange();
      D.setInvalidType();
    }
    
    LookupQualifiedName(Previous, DC);

    // Don't consider using declarations as previous declarations for
    // out-of-line members.
    RemoveUsingDecls(Previous);

    // C++ 7.3.1.2p2:
    // Members (including explicit specializations of templates) of a named
    // namespace can also be defined outside that namespace by explicit
    // qualification of the name being defined, provided that the entity being
    // defined was already declared in the namespace and the definition appears
    // after the point of declaration in a namespace that encloses the
    // declarations namespace.
    //
    // Note that we only check the context at this point. We don't yet
    // have enough information to make sure that PrevDecl is actually
    // the declaration we want to match. For example, given:
    //
    //   class X {
    //     void f();
    //     void f(float);
    //   };
    //
    //   void X::f(int) { } // ill-formed
    //
    // In this case, PrevDecl will point to the overload set
    // containing the two f's declared in X, but neither of them
    // matches.

    // First check whether we named the global scope.
    if (isa<TranslationUnitDecl>(DC)) {
      Diag(D.getIdentifierLoc(), diag::err_invalid_declarator_global_scope)
        << Name << D.getCXXScopeSpec().getRange();
    } else {
      DeclContext *Cur = CurContext;
      while (isa<LinkageSpecDecl>(Cur))
        Cur = Cur->getParent();
      if (!Cur->Encloses(DC)) {
        // The qualifying scope doesn't enclose the original declaration.
        // Emit diagnostic based on current scope.
        SourceLocation L = D.getIdentifierLoc();
        SourceRange R = D.getCXXScopeSpec().getRange();
        if (isa<FunctionDecl>(Cur))
          Diag(L, diag::err_invalid_declarator_in_function) << Name << R;
        else
          Diag(L, diag::err_invalid_declarator_scope)
            << Name << cast<NamedDecl>(DC) << R;
        D.setInvalidType();
      }
    }
  }

  if (Previous.isSingleResult() &&
      Previous.getFoundDecl()->isTemplateParameter()) {
    // Maybe we will complain about the shadowed template parameter.
    if (!D.isInvalidType())
      if (DiagnoseTemplateParameterShadow(D.getIdentifierLoc(),
                                          Previous.getFoundDecl()))
        D.setInvalidType();

    // Just pretend that we didn't see the previous declaration.
    Previous.clear();
  }

  // In C++, the previous declaration we find might be a tag type
  // (class or enum). In this case, the new declaration will hide the
  // tag type. Note that this does does not apply if we're declaring a
  // typedef (C++ [dcl.typedef]p4).
  if (Previous.isSingleTagDecl() &&
      D.getDeclSpec().getStorageClassSpec() != DeclSpec::SCS_typedef)
    Previous.clear();

  bool Redeclaration = false;
  if (D.getDeclSpec().getStorageClassSpec() == DeclSpec::SCS_typedef) {
    if (TemplateParamLists.size()) {
      Diag(D.getIdentifierLoc(), diag::err_template_typedef);
      return DeclPtrTy();
    }

    New = ActOnTypedefDeclarator(S, D, DC, R, TInfo, Previous, Redeclaration);
  } else if (R->isFunctionType()) {
    New = ActOnFunctionDeclarator(S, D, DC, R, TInfo, Previous,
                                  move(TemplateParamLists),
                                  IsFunctionDefinition, Redeclaration);
  } else {
    New = ActOnVariableDeclarator(S, D, DC, R, TInfo, Previous,
                                  move(TemplateParamLists),
                                  Redeclaration);
  }

  if (New == 0)
    return DeclPtrTy();

  // If this has an identifier and is not an invalid redeclaration or 
  // function template specialization, add it to the scope stack.
  if (Name && !(Redeclaration && New->isInvalidDecl()))
    PushOnScopeChains(New, S);

  return DeclPtrTy::make(New);
}

/// TryToFixInvalidVariablyModifiedType - Helper method to turn variable array
/// types into constant array types in certain situations which would otherwise
/// be errors (for GCC compatibility).
static QualType TryToFixInvalidVariablyModifiedType(QualType T,
                                                    ASTContext &Context,
                                                    bool &SizeIsNegative) {
  // This method tries to turn a variable array into a constant
  // array even when the size isn't an ICE.  This is necessary
  // for compatibility with code that depends on gcc's buggy
  // constant expression folding, like struct {char x[(int)(char*)2];}
  SizeIsNegative = false;

  QualifierCollector Qs;
  const Type *Ty = Qs.strip(T);

  if (const PointerType* PTy = dyn_cast<PointerType>(Ty)) {
    QualType Pointee = PTy->getPointeeType();
    QualType FixedType =
        TryToFixInvalidVariablyModifiedType(Pointee, Context, SizeIsNegative);
    if (FixedType.isNull()) return FixedType;
    FixedType = Context.getPointerType(FixedType);
    return Qs.apply(FixedType);
  }

  const VariableArrayType* VLATy = dyn_cast<VariableArrayType>(T);
  if (!VLATy)
    return QualType();
  // FIXME: We should probably handle this case
  if (VLATy->getElementType()->isVariablyModifiedType())
    return QualType();

  Expr::EvalResult EvalResult;
  if (!VLATy->getSizeExpr() ||
      !VLATy->getSizeExpr()->Evaluate(EvalResult, Context) ||
      !EvalResult.Val.isInt())
    return QualType();

  llvm::APSInt &Res = EvalResult.Val.getInt();
  if (Res >= llvm::APSInt(Res.getBitWidth(), Res.isUnsigned())) {
    // TODO: preserve the size expression in declarator info
    return Context.getConstantArrayType(VLATy->getElementType(),
                                        Res, ArrayType::Normal, 0);
  }

  SizeIsNegative = true;
  return QualType();
}

/// \brief Register the given locally-scoped external C declaration so
/// that it can be found later for redeclarations
void
Sema::RegisterLocallyScopedExternCDecl(NamedDecl *ND,
                                       const LookupResult &Previous,
                                       Scope *S) {
  assert(ND->getLexicalDeclContext()->isFunctionOrMethod() &&
         "Decl is not a locally-scoped decl!");
  // Note that we have a locally-scoped external with this name.
  LocallyScopedExternalDecls[ND->getDeclName()] = ND;

  if (!Previous.isSingleResult())
    return;

  NamedDecl *PrevDecl = Previous.getFoundDecl();

  // If there was a previous declaration of this variable, it may be
  // in our identifier chain. Update the identifier chain with the new
  // declaration.
  if (S && IdResolver.ReplaceDecl(PrevDecl, ND)) {
    // The previous declaration was found on the identifer resolver
    // chain, so remove it from its scope.
    while (S && !S->isDeclScope(DeclPtrTy::make(PrevDecl)))
      S = S->getParent();

    if (S)
      S->RemoveDecl(DeclPtrTy::make(PrevDecl));
  }
}

/// \brief Diagnose function specifiers on a declaration of an identifier that
/// does not identify a function.
void Sema::DiagnoseFunctionSpecifiers(Declarator& D) {
  // FIXME: We should probably indicate the identifier in question to avoid
  // confusion for constructs like "inline int a(), b;"
  if (D.getDeclSpec().isInlineSpecified())
    Diag(D.getDeclSpec().getInlineSpecLoc(),
         diag::err_inline_non_function);

  if (D.getDeclSpec().isVirtualSpecified())
    Diag(D.getDeclSpec().getVirtualSpecLoc(),
         diag::err_virtual_non_function);

  if (D.getDeclSpec().isExplicitSpecified())
    Diag(D.getDeclSpec().getExplicitSpecLoc(),
         diag::err_explicit_non_function);
}

NamedDecl*
Sema::ActOnTypedefDeclarator(Scope* S, Declarator& D, DeclContext* DC,
                             QualType R,  TypeSourceInfo *TInfo,
                             LookupResult &Previous, bool &Redeclaration) {
  // Typedef declarators cannot be qualified (C++ [dcl.meaning]p1).
  if (D.getCXXScopeSpec().isSet()) {
    Diag(D.getIdentifierLoc(), diag::err_qualified_typedef_declarator)
      << D.getCXXScopeSpec().getRange();
    D.setInvalidType();
    // Pretend we didn't see the scope specifier.
    DC = 0;
  }

  if (getLangOptions().CPlusPlus) {
    // Check that there are no default arguments (C++ only).
    CheckExtraCXXDefaultArguments(D);
  }

  DiagnoseFunctionSpecifiers(D);

  if (D.getDeclSpec().isThreadSpecified())
    Diag(D.getDeclSpec().getThreadSpecLoc(), diag::err_invalid_thread);

  TypedefDecl *NewTD = ParseTypedefDecl(S, D, R, TInfo);
  if (!NewTD) return 0;

  // Handle attributes prior to checking for duplicates in MergeVarDecl
  ProcessDeclAttributes(S, NewTD, D);

  // Merge the decl with the existing one if appropriate. If the decl is
  // in an outer scope, it isn't the same thing.
  FilterLookupForScope(*this, Previous, DC, S, /*ConsiderLinkage*/ false);
  if (!Previous.empty()) {
    Redeclaration = true;
    MergeTypeDefDecl(NewTD, Previous);
  }

  // C99 6.7.7p2: If a typedef name specifies a variably modified type
  // then it shall have block scope.
  QualType T = NewTD->getUnderlyingType();
  if (T->isVariablyModifiedType()) {
    CurFunctionNeedsScopeChecking = true;

    if (S->getFnParent() == 0) {
      bool SizeIsNegative;
      QualType FixedTy =
          TryToFixInvalidVariablyModifiedType(T, Context, SizeIsNegative);
      if (!FixedTy.isNull()) {
        Diag(D.getIdentifierLoc(), diag::warn_illegal_constant_array_size);
        NewTD->setTypeSourceInfo(Context.getTrivialTypeSourceInfo(FixedTy));
      } else {
        if (SizeIsNegative)
          Diag(D.getIdentifierLoc(), diag::err_typecheck_negative_array_size);
        else if (T->isVariableArrayType())
          Diag(D.getIdentifierLoc(), diag::err_vla_decl_in_file_scope);
        else
          Diag(D.getIdentifierLoc(), diag::err_vm_decl_in_file_scope);
        NewTD->setInvalidDecl();
      }
    }
  }

  // If this is the C FILE type, notify the AST context.
  if (IdentifierInfo *II = NewTD->getIdentifier())
    if (!NewTD->isInvalidDecl() &&
        NewTD->getDeclContext()->getLookupContext()->isTranslationUnit()) {
      if (II->isStr("FILE"))
        Context.setFILEDecl(NewTD);
      else if (II->isStr("jmp_buf"))
        Context.setjmp_bufDecl(NewTD);
      else if (II->isStr("sigjmp_buf"))
        Context.setsigjmp_bufDecl(NewTD);
    }

  return NewTD;
}

/// \brief Determines whether the given declaration is an out-of-scope
/// previous declaration.
///
/// This routine should be invoked when name lookup has found a
/// previous declaration (PrevDecl) that is not in the scope where a
/// new declaration by the same name is being introduced. If the new
/// declaration occurs in a local scope, previous declarations with
/// linkage may still be considered previous declarations (C99
/// 6.2.2p4-5, C++ [basic.link]p6).
///
/// \param PrevDecl the previous declaration found by name
/// lookup
///
/// \param DC the context in which the new declaration is being
/// declared.
///
/// \returns true if PrevDecl is an out-of-scope previous declaration
/// for a new delcaration with the same name.
static bool
isOutOfScopePreviousDeclaration(NamedDecl *PrevDecl, DeclContext *DC,
                                ASTContext &Context) {
  if (!PrevDecl)
    return 0;

  if (!PrevDecl->hasLinkage())
    return false;

  if (Context.getLangOptions().CPlusPlus) {
    // C++ [basic.link]p6:
    //   If there is a visible declaration of an entity with linkage
    //   having the same name and type, ignoring entities declared
    //   outside the innermost enclosing namespace scope, the block
    //   scope declaration declares that same entity and receives the
    //   linkage of the previous declaration.
    DeclContext *OuterContext = DC->getLookupContext();
    if (!OuterContext->isFunctionOrMethod())
      // This rule only applies to block-scope declarations.
      return false;
    else {
      DeclContext *PrevOuterContext = PrevDecl->getDeclContext();
      if (PrevOuterContext->isRecord())
        // We found a member function: ignore it.
        return false;
      else {
        // Find the innermost enclosing namespace for the new and
        // previous declarations.
        while (!OuterContext->isFileContext())
          OuterContext = OuterContext->getParent();
        while (!PrevOuterContext->isFileContext())
          PrevOuterContext = PrevOuterContext->getParent();

        // The previous declaration is in a different namespace, so it
        // isn't the same function.
        if (OuterContext->getPrimaryContext() !=
            PrevOuterContext->getPrimaryContext())
          return false;
      }
    }
  }

  return true;
}

NamedDecl*
Sema::ActOnVariableDeclarator(Scope* S, Declarator& D, DeclContext* DC,
                              QualType R, TypeSourceInfo *TInfo,
                              LookupResult &Previous,
                              MultiTemplateParamsArg TemplateParamLists,
                              bool &Redeclaration) {
  DeclarationName Name = GetNameForDeclarator(D);

  // Check that there are no default arguments (C++ only).
  if (getLangOptions().CPlusPlus)
    CheckExtraCXXDefaultArguments(D);

  VarDecl *NewVD;
  VarDecl::StorageClass SC;
  switch (D.getDeclSpec().getStorageClassSpec()) {
  default: assert(0 && "Unknown storage class!");
  case DeclSpec::SCS_unspecified:    SC = VarDecl::None; break;
  case DeclSpec::SCS_extern:         SC = VarDecl::Extern; break;
  case DeclSpec::SCS_static:         SC = VarDecl::Static; break;
  case DeclSpec::SCS_auto:           SC = VarDecl::Auto; break;
  case DeclSpec::SCS_register:       SC = VarDecl::Register; break;
  case DeclSpec::SCS_private_extern: SC = VarDecl::PrivateExtern; break;
  case DeclSpec::SCS_mutable:
    // mutable can only appear on non-static class members, so it's always
    // an error here
    Diag(D.getIdentifierLoc(), diag::err_mutable_nonmember);
    D.setInvalidType();
    SC = VarDecl::None;
    break;
  }

  IdentifierInfo *II = Name.getAsIdentifierInfo();
  if (!II) {
    Diag(D.getIdentifierLoc(), diag::err_bad_variable_name)
      << Name.getAsString();
    return 0;
  }

  DiagnoseFunctionSpecifiers(D);

  if (!DC->isRecord() && S->getFnParent() == 0) {
    // C99 6.9p2: The storage-class specifiers auto and register shall not
    // appear in the declaration specifiers in an external declaration.
    if (SC == VarDecl::Auto || SC == VarDecl::Register) {

      // If this is a register variable with an asm label specified, then this
      // is a GNU extension.
      if (SC == VarDecl::Register && D.getAsmLabel())
        Diag(D.getIdentifierLoc(), diag::err_unsupported_global_register);
      else
        Diag(D.getIdentifierLoc(), diag::err_typecheck_sclass_fscope);
      D.setInvalidType();
    }
  }
  if (DC->isRecord() && !CurContext->isRecord()) {
    // This is an out-of-line definition of a static data member.
    if (SC == VarDecl::Static) {
      Diag(D.getDeclSpec().getStorageClassSpecLoc(),
           diag::err_static_out_of_line)
        << CodeModificationHint::CreateRemoval(
                                      D.getDeclSpec().getStorageClassSpecLoc());
    } else if (SC == VarDecl::None)
      SC = VarDecl::Static;
  }
  if (SC == VarDecl::Static) {
    if (const CXXRecordDecl *RD = dyn_cast<CXXRecordDecl>(DC)) {
      if (RD->isLocalClass())
        Diag(D.getIdentifierLoc(),
             diag::err_static_data_member_not_allowed_in_local_class)
          << Name << RD->getDeclName();
    }
  }

  // Match up the template parameter lists with the scope specifier, then
  // determine whether we have a template or a template specialization.
  bool isExplicitSpecialization = false;
  if (TemplateParameterList *TemplateParams
        = MatchTemplateParametersToScopeSpecifier(
                                  D.getDeclSpec().getSourceRange().getBegin(),
                                                  D.getCXXScopeSpec(),
                        (TemplateParameterList**)TemplateParamLists.get(),
                                                   TemplateParamLists.size(),
                                                  isExplicitSpecialization)) {
    if (TemplateParams->size() > 0) {
      // There is no such thing as a variable template.
      Diag(D.getIdentifierLoc(), diag::err_template_variable)
        << II
        << SourceRange(TemplateParams->getTemplateLoc(),
                       TemplateParams->getRAngleLoc());
      return 0;
    } else {
      // There is an extraneous 'template<>' for this variable. Complain
      // about it, but allow the declaration of the variable.
      Diag(TemplateParams->getTemplateLoc(),
           diag::err_template_variable_noparams)
        << II
        << SourceRange(TemplateParams->getTemplateLoc(),
                       TemplateParams->getRAngleLoc());
      
      isExplicitSpecialization = true;
    }
  }

  NewVD = VarDecl::Create(Context, DC, D.getIdentifierLoc(),
                          II, R, TInfo, SC);

  if (D.isInvalidType())
    NewVD->setInvalidDecl();

  if (D.getDeclSpec().isThreadSpecified()) {
    if (NewVD->hasLocalStorage())
      Diag(D.getDeclSpec().getThreadSpecLoc(), diag::err_thread_non_global);
    else if (!Context.Target.isTLSSupported())
      Diag(D.getDeclSpec().getThreadSpecLoc(), diag::err_thread_unsupported);
    else
      NewVD->setThreadSpecified(true);
  }

  // Set the lexical context. If the declarator has a C++ scope specifier, the
  // lexical context will be different from the semantic context.
  NewVD->setLexicalDeclContext(CurContext);

  // Handle attributes prior to checking for duplicates in MergeVarDecl
  ProcessDeclAttributes(S, NewVD, D);

  // Handle GNU asm-label extension (encoded as an attribute).
  if (Expr *E = (Expr*) D.getAsmLabel()) {
    // The parser guarantees this is a string.
    StringLiteral *SE = cast<StringLiteral>(E);
    NewVD->addAttr(::new (Context) AsmLabelAttr(Context, SE->getString()));
  }

  // Don't consider existing declarations that are in a different
  // scope and are out-of-semantic-context declarations (if the new
  // declaration has linkage).
  FilterLookupForScope(*this, Previous, DC, S, NewVD->hasLinkage());
  
  // Merge the decl with the existing one if appropriate.
  if (!Previous.empty()) {
    if (Previous.isSingleResult() &&
        isa<FieldDecl>(Previous.getFoundDecl()) &&
        D.getCXXScopeSpec().isSet()) {
      // The user tried to define a non-static data member
      // out-of-line (C++ [dcl.meaning]p1).
      Diag(NewVD->getLocation(), diag::err_nonstatic_member_out_of_line)
        << D.getCXXScopeSpec().getRange();
      Previous.clear();
      NewVD->setInvalidDecl();
    }
  } else if (D.getCXXScopeSpec().isSet()) {
    // No previous declaration in the qualifying scope.
    Diag(D.getIdentifierLoc(), diag::err_no_member)
      << Name << computeDeclContext(D.getCXXScopeSpec(), true)
      << D.getCXXScopeSpec().getRange();
    NewVD->setInvalidDecl();
  }

  CheckVariableDeclaration(NewVD, Previous, Redeclaration);

  // This is an explicit specialization of a static data member. Check it.
  if (isExplicitSpecialization && !NewVD->isInvalidDecl() &&
      CheckMemberSpecialization(NewVD, Previous))
    NewVD->setInvalidDecl();

  // attributes declared post-definition are currently ignored
  if (Previous.isSingleResult()) {
    VarDecl *Def = dyn_cast<VarDecl>(Previous.getFoundDecl());
    if (Def && (Def = Def->getDefinition()) &&
        Def != NewVD && D.hasAttributes()) {
      Diag(NewVD->getLocation(), diag::warn_attribute_precede_definition);
      Diag(Def->getLocation(), diag::note_previous_definition);
    }
  }

  // If this is a locally-scoped extern C variable, update the map of
  // such variables.
  if (CurContext->isFunctionOrMethod() && NewVD->isExternC() &&
      !NewVD->isInvalidDecl())
    RegisterLocallyScopedExternCDecl(NewVD, Previous, S);

  return NewVD;
}

/// \brief Perform semantic checking on a newly-created variable
/// declaration.
///
/// This routine performs all of the type-checking required for a
/// variable declaration once it has been built. It is used both to
/// check variables after they have been parsed and their declarators
/// have been translated into a declaration, and to check variables
/// that have been instantiated from a template.
///
/// Sets NewVD->isInvalidDecl() if an error was encountered.
void Sema::CheckVariableDeclaration(VarDecl *NewVD,
                                    LookupResult &Previous,
                                    bool &Redeclaration) {
  // If the decl is already known invalid, don't check it.
  if (NewVD->isInvalidDecl())
    return;

  QualType T = NewVD->getType();

  if (T->isObjCInterfaceType()) {
    Diag(NewVD->getLocation(), diag::err_statically_allocated_object);
    return NewVD->setInvalidDecl();
  }

  // Emit an error if an address space was applied to decl with local storage.
  // This includes arrays of objects with address space qualifiers, but not
  // automatic variables that point to other address spaces.
  // ISO/IEC TR 18037 S5.1.2
  if (NewVD->hasLocalStorage() && (T.getAddressSpace() != 0)) {
    Diag(NewVD->getLocation(), diag::err_as_qualified_auto_decl);
    return NewVD->setInvalidDecl();
  }

  if (NewVD->hasLocalStorage() && T.isObjCGCWeak()
      && !NewVD->hasAttr<BlocksAttr>())
    Diag(NewVD->getLocation(), diag::warn_attribute_weak_on_local);

  bool isVM = T->isVariablyModifiedType();
  if (isVM || NewVD->hasAttr<CleanupAttr>() ||
      NewVD->hasAttr<BlocksAttr>() ||
      // FIXME: We need to diagnose jumps passed initialized variables in C++.
      // However, this turns on the scope checker for everything with a variable
      // which may impact compile time.  See if we can find a better solution
      // to this, perhaps only checking functions that contain gotos in C++?
      (LangOpts.CPlusPlus && NewVD->hasLocalStorage()))
    CurFunctionNeedsScopeChecking = true;

  if ((isVM && NewVD->hasLinkage()) ||
      (T->isVariableArrayType() && NewVD->hasGlobalStorage())) {
    bool SizeIsNegative;
    QualType FixedTy =
        TryToFixInvalidVariablyModifiedType(T, Context, SizeIsNegative);

    if (FixedTy.isNull() && T->isVariableArrayType()) {
      const VariableArrayType *VAT = Context.getAsVariableArrayType(T);
      // FIXME: This won't give the correct result for
      // int a[10][n];
      SourceRange SizeRange = VAT->getSizeExpr()->getSourceRange();

      if (NewVD->isFileVarDecl())
        Diag(NewVD->getLocation(), diag::err_vla_decl_in_file_scope)
        << SizeRange;
      else if (NewVD->getStorageClass() == VarDecl::Static)
        Diag(NewVD->getLocation(), diag::err_vla_decl_has_static_storage)
        << SizeRange;
      else
        Diag(NewVD->getLocation(), diag::err_vla_decl_has_extern_linkage)
        << SizeRange;
      return NewVD->setInvalidDecl();
    }

    if (FixedTy.isNull()) {
      if (NewVD->isFileVarDecl())
        Diag(NewVD->getLocation(), diag::err_vm_decl_in_file_scope);
      else
        Diag(NewVD->getLocation(), diag::err_vm_decl_has_extern_linkage);
      return NewVD->setInvalidDecl();
    }

    Diag(NewVD->getLocation(), diag::warn_illegal_constant_array_size);
    NewVD->setType(FixedTy);
  }

  if (Previous.empty() && NewVD->isExternC()) {
    // Since we did not find anything by this name and we're declaring
    // an extern "C" variable, look for a non-visible extern "C"
    // declaration with the same name.
    llvm::DenseMap<DeclarationName, NamedDecl *>::iterator Pos
      = LocallyScopedExternalDecls.find(NewVD->getDeclName());
    if (Pos != LocallyScopedExternalDecls.end())
      Previous.addDecl(Pos->second);
  }

  if (T->isVoidType() && !NewVD->hasExternalStorage()) {
    Diag(NewVD->getLocation(), diag::err_typecheck_decl_incomplete_type)
      << T;
    return NewVD->setInvalidDecl();
  }

  if (!NewVD->hasLocalStorage() && NewVD->hasAttr<BlocksAttr>()) {
    Diag(NewVD->getLocation(), diag::err_block_on_nonlocal);
    return NewVD->setInvalidDecl();
  }

  if (isVM && NewVD->hasAttr<BlocksAttr>()) {
    Diag(NewVD->getLocation(), diag::err_block_on_vm);
    return NewVD->setInvalidDecl();
  }

  if (!Previous.empty()) {
    Redeclaration = true;
    MergeVarDecl(NewVD, Previous);
  }
}

/// \brief Data used with FindOverriddenMethod
struct FindOverriddenMethodData {
  Sema *S;
  CXXMethodDecl *Method;
};

/// \brief Member lookup function that determines whether a given C++
/// method overrides a method in a base class, to be used with
/// CXXRecordDecl::lookupInBases().
static bool FindOverriddenMethod(const CXXBaseSpecifier *Specifier,
                                 CXXBasePath &Path,
                                 void *UserData) {
  RecordDecl *BaseRecord = Specifier->getType()->getAs<RecordType>()->getDecl();

  FindOverriddenMethodData *Data 
    = reinterpret_cast<FindOverriddenMethodData*>(UserData);
  
  DeclarationName Name = Data->Method->getDeclName();
  
  // FIXME: Do we care about other names here too?
  if (Name.getNameKind() == DeclarationName::CXXDestructorName) {
    // We really want to find the base class constructor here.
    QualType T = Data->S->Context.getTypeDeclType(BaseRecord);
    CanQualType CT = Data->S->Context.getCanonicalType(T);
    
    Name = Data->S->Context.DeclarationNames.getCXXDestructorName(CT);
  }    
  
  for (Path.Decls = BaseRecord->lookup(Name);
       Path.Decls.first != Path.Decls.second;
       ++Path.Decls.first) {
    if (CXXMethodDecl *MD = dyn_cast<CXXMethodDecl>(*Path.Decls.first)) {
      if (MD->isVirtual() && !Data->S->IsOverload(Data->Method, MD))
        return true;
    }
  }
  
  return false;
}

/// AddOverriddenMethods - See if a method overrides any in the base classes,
/// and if so, check that it's a valid override and remember it.
void Sema::AddOverriddenMethods(CXXRecordDecl *DC, CXXMethodDecl *MD) {
  // Look for virtual methods in base classes that this method might override.
  CXXBasePaths Paths;
  FindOverriddenMethodData Data;
  Data.Method = MD;
  Data.S = this;
  if (DC->lookupInBases(&FindOverriddenMethod, &Data, Paths)) {
    for (CXXBasePaths::decl_iterator I = Paths.found_decls_begin(),
         E = Paths.found_decls_end(); I != E; ++I) {
      if (CXXMethodDecl *OldMD = dyn_cast<CXXMethodDecl>(*I)) {
        if (!CheckOverridingFunctionReturnType(MD, OldMD) &&
            !CheckOverridingFunctionExceptionSpec(MD, OldMD) &&
            !CheckOverridingFunctionAttributes(MD, OldMD))
          MD->addOverriddenMethod(OldMD->getCanonicalDecl());
      }
    }
  }
}

NamedDecl*
Sema::ActOnFunctionDeclarator(Scope* S, Declarator& D, DeclContext* DC,
                              QualType R, TypeSourceInfo *TInfo,
                              LookupResult &Previous,
                              MultiTemplateParamsArg TemplateParamLists,
                              bool IsFunctionDefinition, bool &Redeclaration) {
  assert(R.getTypePtr()->isFunctionType());

  DeclarationName Name = GetNameForDeclarator(D);
  FunctionDecl::StorageClass SC = FunctionDecl::None;
  switch (D.getDeclSpec().getStorageClassSpec()) {
  default: assert(0 && "Unknown storage class!");
  case DeclSpec::SCS_auto:
  case DeclSpec::SCS_register:
  case DeclSpec::SCS_mutable:
    Diag(D.getDeclSpec().getStorageClassSpecLoc(),
         diag::err_typecheck_sclass_func);
    D.setInvalidType();
    break;
  case DeclSpec::SCS_unspecified: SC = FunctionDecl::None; break;
  case DeclSpec::SCS_extern:      SC = FunctionDecl::Extern; break;
  case DeclSpec::SCS_static: {
    if (CurContext->getLookupContext()->isFunctionOrMethod()) {
      // C99 6.7.1p5:
      //   The declaration of an identifier for a function that has
      //   block scope shall have no explicit storage-class specifier
      //   other than extern
      // See also (C++ [dcl.stc]p4).
      Diag(D.getDeclSpec().getStorageClassSpecLoc(),
           diag::err_static_block_func);
      SC = FunctionDecl::None;
    } else
      SC = FunctionDecl::Static;
    break;
  }
  case DeclSpec::SCS_private_extern: SC = FunctionDecl::PrivateExtern;break;
  }

  if (D.getDeclSpec().isThreadSpecified())
    Diag(D.getDeclSpec().getThreadSpecLoc(), diag::err_invalid_thread);

  bool isFriend = D.getDeclSpec().isFriendSpecified();
  bool isInline = D.getDeclSpec().isInlineSpecified();
  bool isVirtual = D.getDeclSpec().isVirtualSpecified();
  bool isExplicit = D.getDeclSpec().isExplicitSpecified();

  // Check that the return type is not an abstract class type.
  // For record types, this is done by the AbstractClassUsageDiagnoser once
  // the class has been completely parsed.
  if (!DC->isRecord() &&
      RequireNonAbstractType(D.getIdentifierLoc(),
                             R->getAs<FunctionType>()->getResultType(),
                             diag::err_abstract_type_in_decl,
                             AbstractReturnType))
    D.setInvalidType();

  // Do not allow returning a objc interface by-value.
  if (R->getAs<FunctionType>()->getResultType()->isObjCInterfaceType()) {
    Diag(D.getIdentifierLoc(),
         diag::err_object_cannot_be_passed_returned_by_value) << 0
      << R->getAs<FunctionType>()->getResultType();
    D.setInvalidType();
  }

  bool isVirtualOkay = false;
  FunctionDecl *NewFD;

  if (isFriend) {
    // C++ [class.friend]p5
    //   A function can be defined in a friend declaration of a
    //   class . . . . Such a function is implicitly inline.
    isInline |= IsFunctionDefinition;
  }

  if (Name.getNameKind() == DeclarationName::CXXConstructorName) {
    // This is a C++ constructor declaration.
    assert(DC->isRecord() &&
           "Constructors can only be declared in a member context");

    R = CheckConstructorDeclarator(D, R, SC);

    // Create the new declaration
    NewFD = CXXConstructorDecl::Create(Context,
                                       cast<CXXRecordDecl>(DC),
                                       D.getIdentifierLoc(), Name, R, TInfo,
                                       isExplicit, isInline,
                                       /*isImplicitlyDeclared=*/false);
  } else if (Name.getNameKind() == DeclarationName::CXXDestructorName) {
    // This is a C++ destructor declaration.
    if (DC->isRecord()) {
      R = CheckDestructorDeclarator(D, SC);

      NewFD = CXXDestructorDecl::Create(Context,
                                        cast<CXXRecordDecl>(DC),
                                        D.getIdentifierLoc(), Name, R,
                                        isInline,
                                        /*isImplicitlyDeclared=*/false);

      isVirtualOkay = true;
    } else {
      Diag(D.getIdentifierLoc(), diag::err_destructor_not_member);

      // Create a FunctionDecl to satisfy the function definition parsing
      // code path.
      NewFD = FunctionDecl::Create(Context, DC, D.getIdentifierLoc(),
                                   Name, R, TInfo, SC, isInline,
                                   /*hasPrototype=*/true);
      D.setInvalidType();
    }
  } else if (Name.getNameKind() == DeclarationName::CXXConversionFunctionName) {
    if (!DC->isRecord()) {
      Diag(D.getIdentifierLoc(),
           diag::err_conv_function_not_member);
      return 0;
    }

    CheckConversionDeclarator(D, R, SC);
    NewFD = CXXConversionDecl::Create(Context, cast<CXXRecordDecl>(DC),
                                      D.getIdentifierLoc(), Name, R, TInfo,
                                      isInline, isExplicit);

    isVirtualOkay = true;
  } else if (DC->isRecord()) {
    // If the of the function is the same as the name of the record, then this
    // must be an invalid constructor that has a return type.
    // (The parser checks for a return type and makes the declarator a
    // constructor if it has no return type).
    // must have an invalid constructor that has a return type
    if (Name.getAsIdentifierInfo() &&
        Name.getAsIdentifierInfo() == cast<CXXRecordDecl>(DC)->getIdentifier()){
      Diag(D.getIdentifierLoc(), diag::err_constructor_return_type)
        << SourceRange(D.getDeclSpec().getTypeSpecTypeLoc())
        << SourceRange(D.getIdentifierLoc());
      return 0;
    }

    bool isStatic = SC == FunctionDecl::Static;
    
    // [class.free]p1:
    // Any allocation function for a class T is a static member
    // (even if not explicitly declared static).
    if (Name.getCXXOverloadedOperator() == OO_New ||
        Name.getCXXOverloadedOperator() == OO_Array_New)
      isStatic = true;

    // [class.free]p6 Any deallocation function for a class X is a static member
    // (even if not explicitly declared static).
    if (Name.getCXXOverloadedOperator() == OO_Delete ||
        Name.getCXXOverloadedOperator() == OO_Array_Delete)
      isStatic = true;
    
    // This is a C++ method declaration.
    NewFD = CXXMethodDecl::Create(Context, cast<CXXRecordDecl>(DC),
                                  D.getIdentifierLoc(), Name, R, TInfo,
                                  isStatic, isInline);

    isVirtualOkay = !isStatic;
  } else {
    // Determine whether the function was written with a
    // prototype. This true when:
    //   - we're in C++ (where every function has a prototype),
    //   - there is a prototype in the declarator, or
    //   - the type R of the function is some kind of typedef or other reference
    //     to a type name (which eventually refers to a function type).
    bool HasPrototype =
       getLangOptions().CPlusPlus ||
       (D.getNumTypeObjects() && D.getTypeObject(0).Fun.hasPrototype) ||
       (!isa<FunctionType>(R.getTypePtr()) && R->isFunctionProtoType());

    NewFD = FunctionDecl::Create(Context, DC,
                                 D.getIdentifierLoc(),
                                 Name, R, TInfo, SC, isInline, HasPrototype);
  }

  if (D.isInvalidType())
    NewFD->setInvalidDecl();

  // Set the lexical context. If the declarator has a C++
  // scope specifier, or is the object of a friend declaration, the
  // lexical context will be different from the semantic context.
  NewFD->setLexicalDeclContext(CurContext);

  // Match up the template parameter lists with the scope specifier, then
  // determine whether we have a template or a template specialization.
  FunctionTemplateDecl *FunctionTemplate = 0;
  bool isExplicitSpecialization = false;
  bool isFunctionTemplateSpecialization = false;
  if (TemplateParameterList *TemplateParams
        = MatchTemplateParametersToScopeSpecifier(
                                  D.getDeclSpec().getSourceRange().getBegin(),
                                  D.getCXXScopeSpec(),
                           (TemplateParameterList**)TemplateParamLists.get(),
                                                  TemplateParamLists.size(),
                                                  isExplicitSpecialization)) {
    if (TemplateParams->size() > 0) {
      // This is a function template

      // Check that we can declare a template here.
      if (CheckTemplateDeclScope(S, TemplateParams))
        return 0;

      FunctionTemplate = FunctionTemplateDecl::Create(Context, DC,
                                                      NewFD->getLocation(),
                                                      Name, TemplateParams,
                                                      NewFD);
      FunctionTemplate->setLexicalDeclContext(CurContext);
      NewFD->setDescribedFunctionTemplate(FunctionTemplate);
    } else {
      // This is a function template specialization.
      isFunctionTemplateSpecialization = true;
    }

    // FIXME: Free this memory properly.
    TemplateParamLists.release();
  }
  
  // C++ [dcl.fct.spec]p5:
  //   The virtual specifier shall only be used in declarations of
  //   nonstatic class member functions that appear within a
  //   member-specification of a class declaration; see 10.3.
  //
  if (isVirtual && !NewFD->isInvalidDecl()) {
    if (!isVirtualOkay) {
       Diag(D.getDeclSpec().getVirtualSpecLoc(),
           diag::err_virtual_non_function);
    } else if (!CurContext->isRecord()) {
      // 'virtual' was specified outside of the class.
      Diag(D.getDeclSpec().getVirtualSpecLoc(), diag::err_virtual_out_of_class)
        << CodeModificationHint::CreateRemoval(
                                           D.getDeclSpec().getVirtualSpecLoc());
    } else {
      // Okay: Add virtual to the method.
      CXXRecordDecl *CurClass = cast<CXXRecordDecl>(DC);
      CurClass->setMethodAsVirtual(NewFD);
    }
  }

  // C++ [dcl.fct.spec]p6:
  //  The explicit specifier shall be used only in the declaration of a
  //  constructor or conversion function within its class definition; see 12.3.1
  //  and 12.3.2.
  if (isExplicit && !NewFD->isInvalidDecl()) {
    if (!CurContext->isRecord()) {
      // 'explicit' was specified outside of the class.
      Diag(D.getDeclSpec().getExplicitSpecLoc(), 
           diag::err_explicit_out_of_class)
        << CodeModificationHint::CreateRemoval(
                                          D.getDeclSpec().getExplicitSpecLoc());
    } else if (!isa<CXXConstructorDecl>(NewFD) && 
               !isa<CXXConversionDecl>(NewFD)) {
      // 'explicit' was specified on a function that wasn't a constructor
      // or conversion function.
      Diag(D.getDeclSpec().getExplicitSpecLoc(),
           diag::err_explicit_non_ctor_or_conv_function)
        << CodeModificationHint::CreateRemoval(
                                          D.getDeclSpec().getExplicitSpecLoc());
    }      
  }

  // Filter out previous declarations that don't match the scope.
  FilterLookupForScope(*this, Previous, DC, S, NewFD->hasLinkage());

  if (isFriend) {
    // DC is the namespace in which the function is being declared.
    assert((DC->isFileContext() || !Previous.empty()) &&
           "previously-undeclared friend function being created "
           "in a non-namespace context");

    if (FunctionTemplate) {
      FunctionTemplate->setObjectOfFriendDecl(
                                   /* PreviouslyDeclared= */ !Previous.empty());
      FunctionTemplate->setAccess(AS_public);
    }
    else
      NewFD->setObjectOfFriendDecl(/* PreviouslyDeclared= */ !Previous.empty());

    NewFD->setAccess(AS_public);
  }

  if (SC == FunctionDecl::Static && isa<CXXMethodDecl>(NewFD) &&
      !CurContext->isRecord()) {
    // C++ [class.static]p1:
    //   A data or function member of a class may be declared static
    //   in a class definition, in which case it is a static member of
    //   the class.

    // Complain about the 'static' specifier if it's on an out-of-line
    // member function definition.
    Diag(D.getDeclSpec().getStorageClassSpecLoc(),
         diag::err_static_out_of_line)
      << CodeModificationHint::CreateRemoval(
                                      D.getDeclSpec().getStorageClassSpecLoc());
  }

  // Handle GNU asm-label extension (encoded as an attribute).
  if (Expr *E = (Expr*) D.getAsmLabel()) {
    // The parser guarantees this is a string.
    StringLiteral *SE = cast<StringLiteral>(E);
    NewFD->addAttr(::new (Context) AsmLabelAttr(Context, SE->getString()));
  }

  // Copy the parameter declarations from the declarator D to the function
  // declaration NewFD, if they are available.  First scavenge them into Params.
  llvm::SmallVector<ParmVarDecl*, 16> Params;
  if (D.getNumTypeObjects() > 0) {
    DeclaratorChunk::FunctionTypeInfo &FTI = D.getTypeObject(0).Fun;

    // Check for C99 6.7.5.3p10 - foo(void) is a non-varargs
    // function that takes no arguments, not a function that takes a
    // single void argument.
    // We let through "const void" here because Sema::GetTypeForDeclarator
    // already checks for that case.
    if (FTI.NumArgs == 1 && !FTI.isVariadic && FTI.ArgInfo[0].Ident == 0 &&
        FTI.ArgInfo[0].Param &&
        FTI.ArgInfo[0].Param.getAs<ParmVarDecl>()->getType()->isVoidType()) {
      // Empty arg list, don't push any params.
      ParmVarDecl *Param = FTI.ArgInfo[0].Param.getAs<ParmVarDecl>();

      // In C++, the empty parameter-type-list must be spelled "void"; a
      // typedef of void is not permitted.
      if (getLangOptions().CPlusPlus &&
          Param->getType().getUnqualifiedType() != Context.VoidTy)
        Diag(Param->getLocation(), diag::err_param_typedef_of_void);
      // FIXME: Leaks decl?
    } else if (FTI.NumArgs > 0 && FTI.ArgInfo[0].Param != 0) {
      for (unsigned i = 0, e = FTI.NumArgs; i != e; ++i) {
        ParmVarDecl *Param = FTI.ArgInfo[i].Param.getAs<ParmVarDecl>();
        assert(Param->getDeclContext() != NewFD && "Was set before ?");
        Param->setDeclContext(NewFD);
        Params.push_back(Param);
      }
    }

  } else if (const FunctionProtoType *FT = R->getAs<FunctionProtoType>()) {
    // When we're declaring a function with a typedef, typeof, etc as in the
    // following example, we'll need to synthesize (unnamed)
    // parameters for use in the declaration.
    //
    // @code
    // typedef void fn(int);
    // fn f;
    // @endcode

    // Synthesize a parameter for each argument type.
    for (FunctionProtoType::arg_type_iterator AI = FT->arg_type_begin(),
         AE = FT->arg_type_end(); AI != AE; ++AI) {
      ParmVarDecl *Param = ParmVarDecl::Create(Context, NewFD,
                                               SourceLocation(), 0,
                                               *AI, /*TInfo=*/0,
                                               VarDecl::None, 0);
      Param->setImplicit();
      Params.push_back(Param);
    }
  } else {
    assert(R->isFunctionNoProtoType() && NewFD->getNumParams() == 0 &&
           "Should not need args for typedef of non-prototype fn");
  }
  // Finally, we know we have the right number of parameters, install them.
  NewFD->setParams(Params.data(), Params.size());

  // If the declarator is a template-id, translate the parser's template 
  // argument list into our AST format.
  bool HasExplicitTemplateArgs = false;
  TemplateArgumentListInfo TemplateArgs;
  if (D.getName().getKind() == UnqualifiedId::IK_TemplateId) {
    TemplateIdAnnotation *TemplateId = D.getName().TemplateId;
    TemplateArgs.setLAngleLoc(TemplateId->LAngleLoc);
    TemplateArgs.setRAngleLoc(TemplateId->RAngleLoc);
    ASTTemplateArgsPtr TemplateArgsPtr(*this,
                                       TemplateId->getTemplateArgs(),
                                       TemplateId->NumArgs);
    translateTemplateArguments(TemplateArgsPtr,
                               TemplateArgs);
    TemplateArgsPtr.release();
    
    HasExplicitTemplateArgs = true;
    
    if (FunctionTemplate) {
      // FIXME: Diagnose function template with explicit template
      // arguments.
      HasExplicitTemplateArgs = false;
    } else if (!isFunctionTemplateSpecialization && 
               !D.getDeclSpec().isFriendSpecified()) {
      // We have encountered something that the user meant to be a 
      // specialization (because it has explicitly-specified template
      // arguments) but that was not introduced with a "template<>" (or had
      // too few of them).
      Diag(D.getIdentifierLoc(), diag::err_template_spec_needs_header)
        << SourceRange(TemplateId->LAngleLoc, TemplateId->RAngleLoc)
        << CodeModificationHint::CreateInsertion(
                                   D.getDeclSpec().getSourceRange().getBegin(),
                                                 "template<> ");
      isFunctionTemplateSpecialization = true;
    }
  }

  if (isFunctionTemplateSpecialization) {
      if (CheckFunctionTemplateSpecialization(NewFD,
                               (HasExplicitTemplateArgs ? &TemplateArgs : 0),
                                              Previous))
        NewFD->setInvalidDecl();
  } else if (isExplicitSpecialization && isa<CXXMethodDecl>(NewFD) &&
             CheckMemberSpecialization(NewFD, Previous))
    NewFD->setInvalidDecl();
    
  // Perform semantic checking on the function declaration.
  bool OverloadableAttrRequired = false; // FIXME: HACK!
  CheckFunctionDeclaration(S, NewFD, Previous, isExplicitSpecialization,
                           Redeclaration, /*FIXME:*/OverloadableAttrRequired);

  assert((NewFD->isInvalidDecl() || !Redeclaration ||
          Previous.getResultKind() != LookupResult::FoundOverloaded) &&
         "previous declaration set still overloaded");

  // If we have a function template, check the template parameter
  // list. This will check and merge default template arguments.
  if (FunctionTemplate) {
    FunctionTemplateDecl *PrevTemplate = FunctionTemplate->getPreviousDeclaration();
    CheckTemplateParameterList(FunctionTemplate->getTemplateParameters(),
                      PrevTemplate? PrevTemplate->getTemplateParameters() : 0,
             D.getDeclSpec().isFriendSpecified()? TPC_FriendFunctionTemplate
                                                : TPC_FunctionTemplate);
  }

  if (D.getCXXScopeSpec().isSet() && !NewFD->isInvalidDecl()) {
    // Fake up an access specifier if it's supposed to be a class member.
    if (!Redeclaration && isa<CXXRecordDecl>(NewFD->getDeclContext()))
      NewFD->setAccess(AS_public);

    // An out-of-line member function declaration must also be a
    // definition (C++ [dcl.meaning]p1).
    // Note that this is not the case for explicit specializations of
    // function templates or member functions of class templates, per
    // C++ [temp.expl.spec]p2.
    if (!IsFunctionDefinition && !isFriend &&
        !isFunctionTemplateSpecialization && !isExplicitSpecialization) {
      Diag(NewFD->getLocation(), diag::err_out_of_line_declaration)
        << D.getCXXScopeSpec().getRange();
      NewFD->setInvalidDecl();
    } else if (!Redeclaration && 
               !(isFriend && CurContext->isDependentContext())) {
      // The user tried to provide an out-of-line definition for a
      // function that is a member of a class or namespace, but there
      // was no such member function declared (C++ [class.mfct]p2,
      // C++ [namespace.memdef]p2). For example:
      //
      // class X {
      //   void f() const;
      // };
      //
      // void X::f() { } // ill-formed
      //
      // Complain about this problem, and attempt to suggest close
      // matches (e.g., those that differ only in cv-qualifiers and
      // whether the parameter types are references).
      Diag(D.getIdentifierLoc(), diag::err_member_def_does_not_match)
        << Name << DC << D.getCXXScopeSpec().getRange();
      NewFD->setInvalidDecl();

      LookupResult Prev(*this, Name, D.getIdentifierLoc(), LookupOrdinaryName,
                        ForRedeclaration);
      LookupQualifiedName(Prev, DC);
      assert(!Prev.isAmbiguous() &&
             "Cannot have an ambiguity in previous-declaration lookup");
      for (LookupResult::iterator Func = Prev.begin(), FuncEnd = Prev.end();
           Func != FuncEnd; ++Func) {
        if (isa<FunctionDecl>(*Func) &&
            isNearlyMatchingFunction(Context, cast<FunctionDecl>(*Func), NewFD))
          Diag((*Func)->getLocation(), diag::note_member_def_close_match);
      }
    }
  }

  // Handle attributes. We need to have merged decls when handling attributes
  // (for example to check for conflicts, etc).
  // FIXME: This needs to happen before we merge declarations. Then,
  // let attribute merging cope with attribute conflicts.
  ProcessDeclAttributes(S, NewFD, D);

  // attributes declared post-definition are currently ignored
  if (Redeclaration && Previous.isSingleResult()) {
    const FunctionDecl *Def;
    FunctionDecl *PrevFD = dyn_cast<FunctionDecl>(Previous.getFoundDecl());
    if (PrevFD && PrevFD->getBody(Def) && D.hasAttributes()) {
      Diag(NewFD->getLocation(), diag::warn_attribute_precede_definition);
      Diag(Def->getLocation(), diag::note_previous_definition);
    }
  }

  AddKnownFunctionAttributes(NewFD);

  if (OverloadableAttrRequired && !NewFD->getAttr<OverloadableAttr>()) {
    // If a function name is overloadable in C, then every function
    // with that name must be marked "overloadable".
    Diag(NewFD->getLocation(), diag::err_attribute_overloadable_missing)
      << Redeclaration << NewFD;
    if (!Previous.empty())
      Diag(Previous.getRepresentativeDecl()->getLocation(),
           diag::note_attribute_overloadable_prev_overload);
    NewFD->addAttr(::new (Context) OverloadableAttr());
  }

  // If this is a locally-scoped extern C function, update the
  // map of such names.
  if (CurContext->isFunctionOrMethod() && NewFD->isExternC()
      && !NewFD->isInvalidDecl())
    RegisterLocallyScopedExternCDecl(NewFD, Previous, S);

  // Set this FunctionDecl's range up to the right paren.
  NewFD->setLocEnd(D.getSourceRange().getEnd());

  if (FunctionTemplate && NewFD->isInvalidDecl())
    FunctionTemplate->setInvalidDecl();

  if (FunctionTemplate)
    return FunctionTemplate;

  
  // Keep track of static, non-inlined function definitions that
  // have not been used. We will warn later.
  // FIXME: Also include static functions declared but not defined.
  if (!NewFD->isInvalidDecl() && IsFunctionDefinition 
      && !NewFD->isInlined() && NewFD->getLinkage() == InternalLinkage
      && !NewFD->isUsed() && !NewFD->hasAttr<UnusedAttr>())
    UnusedStaticFuncs.push_back(NewFD);
  
  return NewFD;
}

/// \brief Perform semantic checking of a new function declaration.
///
/// Performs semantic analysis of the new function declaration
/// NewFD. This routine performs all semantic checking that does not
/// require the actual declarator involved in the declaration, and is
/// used both for the declaration of functions as they are parsed
/// (called via ActOnDeclarator) and for the declaration of functions
/// that have been instantiated via C++ template instantiation (called
/// via InstantiateDecl).
///
/// \param IsExplicitSpecialiation whether this new function declaration is
/// an explicit specialization of the previous declaration.
///
/// This sets NewFD->isInvalidDecl() to true if there was an error.
void Sema::CheckFunctionDeclaration(Scope *S, FunctionDecl *NewFD,
                                    LookupResult &Previous,
                                    bool IsExplicitSpecialization,
                                    bool &Redeclaration,
                                    bool &OverloadableAttrRequired) {
  // If NewFD is already known erroneous, don't do any of this checking.
  if (NewFD->isInvalidDecl())
    return;

  if (NewFD->getResultType()->isVariablyModifiedType()) {
    // Functions returning a variably modified type violate C99 6.7.5.2p2
    // because all functions have linkage.
    Diag(NewFD->getLocation(), diag::err_vm_func_decl);
    return NewFD->setInvalidDecl();
  }

  if (NewFD->isMain()) 
    CheckMain(NewFD);

  // Check for a previous declaration of this name.
  if (Previous.empty() && NewFD->isExternC()) {
    // Since we did not find anything by this name and we're declaring
    // an extern "C" function, look for a non-visible extern "C"
    // declaration with the same name.
    llvm::DenseMap<DeclarationName, NamedDecl *>::iterator Pos
      = LocallyScopedExternalDecls.find(NewFD->getDeclName());
    if (Pos != LocallyScopedExternalDecls.end())
      Previous.addDecl(Pos->second);
  }

  // Merge or overload the declaration with an existing declaration of
  // the same name, if appropriate.
  if (!Previous.empty()) {
    // Determine whether NewFD is an overload of PrevDecl or
    // a declaration that requires merging. If it's an overload,
    // there's no more work to do here; we'll just add the new
    // function to the scope.

    NamedDecl *OldDecl = 0;
    if (!AllowOverloadingOfFunction(Previous, Context)) {
      Redeclaration = true;
      OldDecl = Previous.getFoundDecl();
    } else {
      if (!getLangOptions().CPlusPlus) {
        OverloadableAttrRequired = true;

        // Functions marked "overloadable" must have a prototype (that
        // we can't get through declaration merging).
        if (!NewFD->getType()->getAs<FunctionProtoType>()) {
          Diag(NewFD->getLocation(),
               diag::err_attribute_overloadable_no_prototype)
            << NewFD;
          Redeclaration = true;

          // Turn this into a variadic function with no parameters.
          QualType R = Context.getFunctionType(
                     NewFD->getType()->getAs<FunctionType>()->getResultType(),
                     0, 0, true, 0, false, false, 0, 0, false, CC_Default);
          NewFD->setType(R);
          return NewFD->setInvalidDecl();
        }
      }

      switch (CheckOverload(NewFD, Previous, OldDecl)) {
      case Ovl_Match:
        Redeclaration = true;
        if (isa<UsingShadowDecl>(OldDecl) && CurContext->isRecord()) {
          HideUsingShadowDecl(S, cast<UsingShadowDecl>(OldDecl));
          Redeclaration = false;
        }
        break;

      case Ovl_NonFunction:
        Redeclaration = true;
        break;

      case Ovl_Overload:
        Redeclaration = false;
        break;
      }
    }

    if (Redeclaration) {
      // NewFD and OldDecl represent declarations that need to be
      // merged.
      if (MergeFunctionDecl(NewFD, OldDecl))
        return NewFD->setInvalidDecl();

      Previous.clear();
      Previous.addDecl(OldDecl);

      if (FunctionTemplateDecl *OldTemplateDecl
                                    = dyn_cast<FunctionTemplateDecl>(OldDecl)) {
        NewFD->setPreviousDeclaration(OldTemplateDecl->getTemplatedDecl());        
        FunctionTemplateDecl *NewTemplateDecl
          = NewFD->getDescribedFunctionTemplate();
        assert(NewTemplateDecl && "Template/non-template mismatch");
        if (CXXMethodDecl *Method 
              = dyn_cast<CXXMethodDecl>(NewTemplateDecl->getTemplatedDecl())) {
          Method->setAccess(OldTemplateDecl->getAccess());
          NewTemplateDecl->setAccess(OldTemplateDecl->getAccess());
        }
        
        // If this is an explicit specialization of a member that is a function
        // template, mark it as a member specialization.
        if (IsExplicitSpecialization && 
            NewTemplateDecl->getInstantiatedFromMemberTemplate()) {
          NewTemplateDecl->setMemberSpecialization();
          assert(OldTemplateDecl->isMemberSpecialization());
        }
      } else {
        if (isa<CXXMethodDecl>(NewFD)) // Set access for out-of-line definitions
          NewFD->setAccess(OldDecl->getAccess());
        NewFD->setPreviousDeclaration(cast<FunctionDecl>(OldDecl));
      }
    }
  }

  // Semantic checking for this function declaration (in isolation).
  if (getLangOptions().CPlusPlus) {
    // C++-specific checks.
    if (CXXConstructorDecl *Constructor = dyn_cast<CXXConstructorDecl>(NewFD)) {
      CheckConstructor(Constructor);
    } else if (CXXDestructorDecl *Destructor = 
                dyn_cast<CXXDestructorDecl>(NewFD)) {
      CXXRecordDecl *Record = Destructor->getParent();
      QualType ClassType = Context.getTypeDeclType(Record);
      
      // FIXME: Shouldn't we be able to perform thisc heck even when the class
      // type is dependent? Both gcc and edg can handle that.
      if (!ClassType->isDependentType()) {
        DeclarationName Name
          = Context.DeclarationNames.getCXXDestructorName(
                                        Context.getCanonicalType(ClassType));
        if (NewFD->getDeclName() != Name) {
          Diag(NewFD->getLocation(), diag::err_destructor_name);
          return NewFD->setInvalidDecl();
        }
      }

      Record->setUserDeclaredDestructor(true);
      // C++ [class]p4: A POD-struct is an aggregate class that has [...] no
      // user-defined destructor.
      Record->setPOD(false);

      // C++ [class.dtor]p3: A destructor is trivial if it is an implicitly-
      // declared destructor.
      // FIXME: C++0x: don't do this for "= default" destructors
      Record->setHasTrivialDestructor(false);
    } else if (CXXConversionDecl *Conversion
               = dyn_cast<CXXConversionDecl>(NewFD)) {
      ActOnConversionDeclarator(Conversion);
    }

    // Find any virtual functions that this function overrides.
    if (CXXMethodDecl *Method = dyn_cast<CXXMethodDecl>(NewFD)) {
      if (!Method->isFunctionTemplateSpecialization() && 
          !Method->getDescribedFunctionTemplate())
        AddOverriddenMethods(Method->getParent(), Method);
    }

    // Additional checks for the destructor; make sure we do this after we
    // figure out whether the destructor is virtual.
    if (CXXDestructorDecl *Destructor = dyn_cast<CXXDestructorDecl>(NewFD))
      if (!Destructor->getParent()->isDependentType())
        CheckDestructor(Destructor);

    // Extra checking for C++ overloaded operators (C++ [over.oper]).
    if (NewFD->isOverloadedOperator() &&
        CheckOverloadedOperatorDeclaration(NewFD))
      return NewFD->setInvalidDecl();

    // Extra checking for C++0x literal operators (C++0x [over.literal]).
    if (NewFD->getLiteralIdentifier() &&
        CheckLiteralOperatorDeclaration(NewFD))
      return NewFD->setInvalidDecl();

    // In C++, check default arguments now that we have merged decls. Unless
    // the lexical context is the class, because in this case this is done
    // during delayed parsing anyway.
    if (!CurContext->isRecord())
      CheckCXXDefaultArguments(NewFD);
  }
}

void Sema::CheckMain(FunctionDecl* FD) {
  // C++ [basic.start.main]p3:  A program that declares main to be inline
  //   or static is ill-formed.
  // C99 6.7.4p4:  In a hosted environment, the inline function specifier
  //   shall not appear in a declaration of main.
  // static main is not an error under C99, but we should warn about it.
  bool isInline = FD->isInlineSpecified();
  bool isStatic = FD->getStorageClass() == FunctionDecl::Static;
  if (isInline || isStatic) {
    unsigned diagID = diag::warn_unusual_main_decl;
    if (isInline || getLangOptions().CPlusPlus)
      diagID = diag::err_unusual_main_decl;

    int which = isStatic + (isInline << 1) - 1;
    Diag(FD->getLocation(), diagID) << which;
  }

  QualType T = FD->getType();
  assert(T->isFunctionType() && "function decl is not of function type");
  const FunctionType* FT = T->getAs<FunctionType>();

  if (!Context.hasSameUnqualifiedType(FT->getResultType(), Context.IntTy)) {
    // TODO: add a replacement fixit to turn the return type into 'int'.
    Diag(FD->getTypeSpecStartLoc(), diag::err_main_returns_nonint);
    FD->setInvalidDecl(true);
  }

  // Treat protoless main() as nullary.
  if (isa<FunctionNoProtoType>(FT)) return;

  const FunctionProtoType* FTP = cast<const FunctionProtoType>(FT);
  unsigned nparams = FTP->getNumArgs();
  assert(FD->getNumParams() == nparams);

  bool HasExtraParameters = (nparams > 3);

  // Darwin passes an undocumented fourth argument of type char**.  If
  // other platforms start sprouting these, the logic below will start
  // getting shifty.
  if (nparams == 4 &&
      Context.Target.getTriple().getOS() == llvm::Triple::Darwin)
    HasExtraParameters = false;

  if (HasExtraParameters) {
    Diag(FD->getLocation(), diag::err_main_surplus_args) << nparams;
    FD->setInvalidDecl(true);
    nparams = 3;
  }

  // FIXME: a lot of the following diagnostics would be improved
  // if we had some location information about types.

  QualType CharPP =
    Context.getPointerType(Context.getPointerType(Context.CharTy));
  QualType Expected[] = { Context.IntTy, CharPP, CharPP, CharPP };

  for (unsigned i = 0; i < nparams; ++i) {
    QualType AT = FTP->getArgType(i);

    bool mismatch = true;

    if (Context.hasSameUnqualifiedType(AT, Expected[i]))
      mismatch = false;
    else if (Expected[i] == CharPP) {
      // As an extension, the following forms are okay:
      //   char const **
      //   char const * const *
      //   char * const *

      QualifierCollector qs;
      const PointerType* PT;
      if ((PT = qs.strip(AT)->getAs<PointerType>()) &&
          (PT = qs.strip(PT->getPointeeType())->getAs<PointerType>()) &&
          (QualType(qs.strip(PT->getPointeeType()), 0) == Context.CharTy)) {
        qs.removeConst();
        mismatch = !qs.empty();
      }
    }

    if (mismatch) {
      Diag(FD->getLocation(), diag::err_main_arg_wrong) << i << Expected[i];
      // TODO: suggest replacing given type with expected type
      FD->setInvalidDecl(true);
    }
  }

  if (nparams == 1 && !FD->isInvalidDecl()) {
    Diag(FD->getLocation(), diag::warn_main_one_arg);
  }
}

bool Sema::CheckForConstantInitializer(Expr *Init, QualType DclT) {
  // FIXME: Need strict checking.  In C89, we need to check for
  // any assignment, increment, decrement, function-calls, or
  // commas outside of a sizeof.  In C99, it's the same list,
  // except that the aforementioned are allowed in unevaluated
  // expressions.  Everything else falls under the
  // "may accept other forms of constant expressions" exception.
  // (We never end up here for C++, so the constant expression
  // rules there don't matter.)
  if (Init->isConstantInitializer(Context))
    return false;
  Diag(Init->getExprLoc(), diag::err_init_element_not_constant)
    << Init->getSourceRange();
  return true;
}

void Sema::AddInitializerToDecl(DeclPtrTy dcl, ExprArg init) {
  AddInitializerToDecl(dcl, move(init), /*DirectInit=*/false);
}

/// AddInitializerToDecl - Adds the initializer Init to the
/// declaration dcl. If DirectInit is true, this is C++ direct
/// initialization rather than copy initialization.
void Sema::AddInitializerToDecl(DeclPtrTy dcl, ExprArg init, bool DirectInit) {
  Decl *RealDecl = dcl.getAs<Decl>();
  // If there is no declaration, there was an error parsing it.  Just ignore
  // the initializer.
  if (RealDecl == 0)
    return;

  if (CXXMethodDecl *Method = dyn_cast<CXXMethodDecl>(RealDecl)) {
    // With declarators parsed the way they are, the parser cannot
    // distinguish between a normal initializer and a pure-specifier.
    // Thus this grotesque test.
    IntegerLiteral *IL;
    Expr *Init = static_cast<Expr *>(init.get());
    if ((IL = dyn_cast<IntegerLiteral>(Init)) && IL->getValue() == 0 &&
        Context.getCanonicalType(IL->getType()) == Context.IntTy)
      CheckPureMethod(Method, Init->getSourceRange());
    else {
      Diag(Method->getLocation(), diag::err_member_function_initialization)
        << Method->getDeclName() << Init->getSourceRange();
      Method->setInvalidDecl();
    }
    return;
  }

  VarDecl *VDecl = dyn_cast<VarDecl>(RealDecl);
  if (!VDecl) {
    if (getLangOptions().CPlusPlus &&
        RealDecl->getLexicalDeclContext()->isRecord() &&
        isa<NamedDecl>(RealDecl))
      Diag(RealDecl->getLocation(), diag::err_member_initialization)
        << cast<NamedDecl>(RealDecl)->getDeclName();
    else
      Diag(RealDecl->getLocation(), diag::err_illegal_initializer);
    RealDecl->setInvalidDecl();
    return;
  }

  // A definition must end up with a complete type, which means it must be
  // complete with the restriction that an array type might be completed by the
  // initializer; note that later code assumes this restriction.
  QualType BaseDeclType = VDecl->getType();
  if (const ArrayType *Array = Context.getAsIncompleteArrayType(BaseDeclType))
    BaseDeclType = Array->getElementType();
  if (RequireCompleteType(VDecl->getLocation(), BaseDeclType,
                          diag::err_typecheck_decl_incomplete_type)) {
    RealDecl->setInvalidDecl();
    return;
  }

  // The variable can not have an abstract class type.
  if (RequireNonAbstractType(VDecl->getLocation(), VDecl->getType(),
                             diag::err_abstract_type_in_decl,
                             AbstractVariableType))
    VDecl->setInvalidDecl();

  const VarDecl *Def;
  if ((Def = VDecl->getDefinition()) && Def != VDecl) {
    Diag(VDecl->getLocation(), diag::err_redefinition)
      << VDecl->getDeclName();
    Diag(Def->getLocation(), diag::note_previous_definition);
    VDecl->setInvalidDecl();
    return;
  }

  // Take ownership of the expression, now that we're sure we have somewhere
  // to put it.
  Expr *Init = init.takeAs<Expr>();
  assert(Init && "missing initializer");

  // Capture the variable that is being initialized and the style of
  // initialization.
  InitializedEntity Entity = InitializedEntity::InitializeVariable(VDecl);
  
  // FIXME: Poor source location information.
  InitializationKind Kind
    = DirectInit? InitializationKind::CreateDirect(VDecl->getLocation(),
                                                   Init->getLocStart(),
                                                   Init->getLocEnd())
                : InitializationKind::CreateCopy(VDecl->getLocation(),
                                                 Init->getLocStart());
  
  // Get the decls type and save a reference for later, since
  // CheckInitializerTypes may change it.
  QualType DclT = VDecl->getType(), SavT = DclT;
  if (VDecl->isBlockVarDecl()) {
    if (VDecl->hasExternalStorage()) { // C99 6.7.8p5
      Diag(VDecl->getLocation(), diag::err_block_extern_cant_init);
      VDecl->setInvalidDecl();
    } else if (!VDecl->isInvalidDecl()) {
      InitializationSequence InitSeq(*this, Entity, Kind, &Init, 1);
      OwningExprResult Result = InitSeq.Perform(*this, Entity, Kind,
                                          MultiExprArg(*this, (void**)&Init, 1),
                                                &DclT);
      if (Result.isInvalid()) {
        VDecl->setInvalidDecl();
        return;
      }

      Init = Result.takeAs<Expr>();

      // C++ 3.6.2p2, allow dynamic initialization of static initializers.
      // Don't check invalid declarations to avoid emitting useless diagnostics.
      if (!getLangOptions().CPlusPlus && !VDecl->isInvalidDecl()) {
        if (VDecl->getStorageClass() == VarDecl::Static) // C99 6.7.8p4.
          CheckForConstantInitializer(Init, DclT);
      }
    }
  } else if (VDecl->isStaticDataMember() &&
             VDecl->getLexicalDeclContext()->isRecord()) {
    // This is an in-class initialization for a static data member, e.g.,
    //
    // struct S {
    //   static const int value = 17;
    // };

    // Attach the initializer
    VDecl->setInit(Init);

    // C++ [class.mem]p4:
    //   A member-declarator can contain a constant-initializer only
    //   if it declares a static member (9.4) of const integral or
    //   const enumeration type, see 9.4.2.
    QualType T = VDecl->getType();
    if (!T->isDependentType() &&
        (!Context.getCanonicalType(T).isConstQualified() ||
         !T->isIntegralType())) {
      Diag(VDecl->getLocation(), diag::err_member_initialization)
        << VDecl->getDeclName() << Init->getSourceRange();
      VDecl->setInvalidDecl();
    } else {
      // C++ [class.static.data]p4:
      //   If a static data member is of const integral or const
      //   enumeration type, its declaration in the class definition
      //   can specify a constant-initializer which shall be an
      //   integral constant expression (5.19).
      if (!Init->isTypeDependent() &&
          !Init->getType()->isIntegralType()) {
        // We have a non-dependent, non-integral or enumeration type.
        Diag(Init->getSourceRange().getBegin(),
             diag::err_in_class_initializer_non_integral_type)
          << Init->getType() << Init->getSourceRange();
        VDecl->setInvalidDecl();
      } else if (!Init->isTypeDependent() && !Init->isValueDependent()) {
        // Check whether the expression is a constant expression.
        llvm::APSInt Value;
        SourceLocation Loc;
        if (!Init->isIntegerConstantExpr(Value, Context, &Loc)) {
          Diag(Loc, diag::err_in_class_initializer_non_constant)
            << Init->getSourceRange();
          VDecl->setInvalidDecl();
        } else if (!VDecl->getType()->isDependentType())
          ImpCastExprToType(Init, VDecl->getType(), CastExpr::CK_IntegralCast);
      }
    }
  } else if (VDecl->isFileVarDecl()) {
    if (VDecl->getStorageClass() == VarDecl::Extern)
      Diag(VDecl->getLocation(), diag::warn_extern_init);
    if (!VDecl->isInvalidDecl()) {
      InitializationSequence InitSeq(*this, Entity, Kind, &Init, 1);
      OwningExprResult Result = InitSeq.Perform(*this, Entity, Kind,
                                          MultiExprArg(*this, (void**)&Init, 1),
                                                &DclT);
      if (Result.isInvalid()) {
        VDecl->setInvalidDecl();
        return;
      }

      Init = Result.takeAs<Expr>();
    }

    // C++ 3.6.2p2, allow dynamic initialization of static initializers.
    // Don't check invalid declarations to avoid emitting useless diagnostics.
    if (!getLangOptions().CPlusPlus && !VDecl->isInvalidDecl()) {
      // C99 6.7.8p4. All file scoped initializers need to be constant.
      CheckForConstantInitializer(Init, DclT);
    }
  }
  // If the type changed, it means we had an incomplete type that was
  // completed by the initializer. For example:
  //   int ary[] = { 1, 3, 5 };
  // "ary" transitions from a VariableArrayType to a ConstantArrayType.
  if (!VDecl->isInvalidDecl() && (DclT != SavT)) {
    VDecl->setType(DclT);
    Init->setType(DclT);
  }

  Init = MaybeCreateCXXExprWithTemporaries(Init);
  // Attach the initializer to the decl.
  VDecl->setInit(Init);

  if (getLangOptions().CPlusPlus) {
    // Make sure we mark the destructor as used if necessary.
    QualType InitType = VDecl->getType();
    while (const ArrayType *Array = Context.getAsArrayType(InitType))
      InitType = Context.getBaseElementType(Array);
    if (const RecordType *Record = InitType->getAs<RecordType>())
      FinalizeVarWithDestructor(VDecl, Record);
  }

  return;
}

void Sema::ActOnUninitializedDecl(DeclPtrTy dcl,
                                  bool TypeContainsUndeducedAuto) {
  Decl *RealDecl = dcl.getAs<Decl>();

  // If there is no declaration, there was an error parsing it. Just ignore it.
  if (RealDecl == 0)
    return;

  if (VarDecl *Var = dyn_cast<VarDecl>(RealDecl)) {
    QualType Type = Var->getType();

    // C++0x [dcl.spec.auto]p3
    if (TypeContainsUndeducedAuto) {
      Diag(Var->getLocation(), diag::err_auto_var_requires_init)
        << Var->getDeclName() << Type;
      Var->setInvalidDecl();
      return;
    }

    switch (Var->isThisDeclarationADefinition()) {
    case VarDecl::Definition:
      if (!Var->isStaticDataMember() || !Var->getAnyInitializer())
        break;

      // We have an out-of-line definition of a static data member
      // that has an in-class initializer, so we type-check this like
      // a declaration. 
      //
      // Fall through
      
    case VarDecl::DeclarationOnly:
      // It's only a declaration. 

      // Block scope. C99 6.7p7: If an identifier for an object is
      // declared with no linkage (C99 6.2.2p6), the type for the
      // object shall be complete.
      if (!Type->isDependentType() && Var->isBlockVarDecl() && 
          !Var->getLinkage() && !Var->isInvalidDecl() &&
          RequireCompleteType(Var->getLocation(), Type,
                              diag::err_typecheck_decl_incomplete_type))
        Var->setInvalidDecl();

      // Make sure that the type is not abstract.
      if (!Type->isDependentType() && !Var->isInvalidDecl() &&
          RequireNonAbstractType(Var->getLocation(), Type,
                                 diag::err_abstract_type_in_decl,
                                 AbstractVariableType))
        Var->setInvalidDecl();
      return;

    case VarDecl::TentativeDefinition:
      // File scope. C99 6.9.2p2: A declaration of an identifier for an
      // object that has file scope without an initializer, and without a
      // storage-class specifier or with the storage-class specifier "static",
      // constitutes a tentative definition. Note: A tentative definition with
      // external linkage is valid (C99 6.2.2p5).
      if (!Var->isInvalidDecl()) {
        if (const IncompleteArrayType *ArrayT
                                    = Context.getAsIncompleteArrayType(Type)) {
          if (RequireCompleteType(Var->getLocation(),
                                  ArrayT->getElementType(),
                                  diag::err_illegal_decl_array_incomplete_type))
            Var->setInvalidDecl();
        } else if (Var->getStorageClass() == VarDecl::Static) {
          // C99 6.9.2p3: If the declaration of an identifier for an object is
          // a tentative definition and has internal linkage (C99 6.2.2p3), the
          // declared type shall not be an incomplete type.
          // NOTE: code such as the following
          //     static struct s;
          //     struct s { int a; };
          // is accepted by gcc. Hence here we issue a warning instead of
          // an error and we do not invalidate the static declaration.
          // NOTE: to avoid multiple warnings, only check the first declaration.
          if (Var->getPreviousDeclaration() == 0)
            RequireCompleteType(Var->getLocation(), Type,
                                diag::ext_typecheck_decl_incomplete_type);
        }
      }

      // Record the tentative definition; we're done.
      if (!Var->isInvalidDecl())
        TentativeDefinitions.push_back(Var);
      return;
    }

    // Provide a specific diagnostic for uninitialized variable
    // definitions with incomplete array type.
    if (Type->isIncompleteArrayType()) {
      Diag(Var->getLocation(),
           diag::err_typecheck_incomplete_array_needs_initializer);
      Var->setInvalidDecl();
      return;
    }

   // Provide a specific diagnostic for uninitialized variable
   // definitions with reference type.
   if (Type->isReferenceType()) {
     Diag(Var->getLocation(), diag::err_reference_var_requires_init)
       << Var->getDeclName()
       << SourceRange(Var->getLocation(), Var->getLocation());
     Var->setInvalidDecl();
     return;
   }

    // Do not attempt to type-check the default initializer for a
    // variable with dependent type.
    if (Type->isDependentType())
      return;

    if (Var->isInvalidDecl())
      return;

    if (RequireCompleteType(Var->getLocation(), 
                            Context.getBaseElementType(Type),
                            diag::err_typecheck_decl_incomplete_type)) {
      Var->setInvalidDecl();
      return;
    }

    // The variable can not have an abstract class type.
    if (RequireNonAbstractType(Var->getLocation(), Type,
                               diag::err_abstract_type_in_decl,
                               AbstractVariableType)) {
      Var->setInvalidDecl();
      return;
    }

    InitializedEntity Entity = InitializedEntity::InitializeVariable(Var);
    InitializationKind Kind
      = InitializationKind::CreateDefault(Var->getLocation());
    
    InitializationSequence InitSeq(*this, Entity, Kind, 0, 0);
    OwningExprResult Init = InitSeq.Perform(*this, Entity, Kind,
                                            MultiExprArg(*this, 0, 0));
    if (Init.isInvalid())
      Var->setInvalidDecl();
    else {
      if (Init.get())
        Var->setInit(MaybeCreateCXXExprWithTemporaries(Init.takeAs<Expr>()));

      if (getLangOptions().CPlusPlus)
        if (const RecordType *Record
                        = Context.getBaseElementType(Type)->getAs<RecordType>())
          FinalizeVarWithDestructor(Var, Record);
    }
  }
}

Sema::DeclGroupPtrTy Sema::FinalizeDeclaratorGroup(Scope *S, const DeclSpec &DS,
                                                   DeclPtrTy *Group,
                                                   unsigned NumDecls) {
  llvm::SmallVector<Decl*, 8> Decls;

  if (DS.isTypeSpecOwned())
    Decls.push_back((Decl*)DS.getTypeRep());

  for (unsigned i = 0; i != NumDecls; ++i)
    if (Decl *D = Group[i].getAs<Decl>())
      Decls.push_back(D);

  return DeclGroupPtrTy::make(DeclGroupRef::Create(Context,
                                                   Decls.data(), Decls.size()));
}


/// ActOnParamDeclarator - Called from Parser::ParseFunctionDeclarator()
/// to introduce parameters into function prototype scope.
Sema::DeclPtrTy
Sema::ActOnParamDeclarator(Scope *S, Declarator &D) {
  const DeclSpec &DS = D.getDeclSpec();

  // Verify C99 6.7.5.3p2: The only SCS allowed is 'register'.
  VarDecl::StorageClass StorageClass = VarDecl::None;
  if (DS.getStorageClassSpec() == DeclSpec::SCS_register) {
    StorageClass = VarDecl::Register;
  } else if (DS.getStorageClassSpec() != DeclSpec::SCS_unspecified) {
    Diag(DS.getStorageClassSpecLoc(),
         diag::err_invalid_storage_class_in_func_decl);
    D.getMutableDeclSpec().ClearStorageClassSpecs();
  }

  if (D.getDeclSpec().isThreadSpecified())
    Diag(D.getDeclSpec().getThreadSpecLoc(), diag::err_invalid_thread);

  DiagnoseFunctionSpecifiers(D);

  // Check that there are no default arguments inside the type of this
  // parameter (C++ only).
  if (getLangOptions().CPlusPlus)
    CheckExtraCXXDefaultArguments(D);

  TypeSourceInfo *TInfo = 0;
  TagDecl *OwnedDecl = 0;
  QualType parmDeclType = GetTypeForDeclarator(D, S, &TInfo, &OwnedDecl);

  if (getLangOptions().CPlusPlus && OwnedDecl && OwnedDecl->isDefinition()) {
    // C++ [dcl.fct]p6:
    //   Types shall not be defined in return or parameter types.
    Diag(OwnedDecl->getLocation(), diag::err_type_defined_in_param_type)
      << Context.getTypeDeclType(OwnedDecl);
  }

  // Check for redeclaration of parameters, e.g. int foo(int x, int x);
  IdentifierInfo *II = D.getIdentifier();
  if (II) {
    if (NamedDecl *PrevDecl = LookupSingleName(S, II, LookupOrdinaryName)) {
      if (PrevDecl->isTemplateParameter()) {
        // Maybe we will complain about the shadowed template parameter.
        DiagnoseTemplateParameterShadow(D.getIdentifierLoc(), PrevDecl);
        // Just pretend that we didn't see the previous declaration.
        PrevDecl = 0;
      } else if (S->isDeclScope(DeclPtrTy::make(PrevDecl))) {
        Diag(D.getIdentifierLoc(), diag::err_param_redefinition) << II;
        Diag(PrevDecl->getLocation(), diag::note_previous_declaration);

        // Recover by removing the name
        II = 0;
        D.SetIdentifier(0, D.getIdentifierLoc());
        D.setInvalidType(true);
      }
    }
  }

  // Parameters can not be abstract class types.
  // For record types, this is done by the AbstractClassUsageDiagnoser once
  // the class has been completely parsed.
  if (!CurContext->isRecord() &&
      RequireNonAbstractType(D.getIdentifierLoc(), parmDeclType,
                             diag::err_abstract_type_in_decl,
                             AbstractParamType))
    D.setInvalidType(true);

  QualType T = adjustParameterType(parmDeclType);

  // Temporarily put parameter variables in the translation unit, not
  // the enclosing context.  This prevents them from accidentally
  // looking like class members in C++.
  DeclContext *DC = Context.getTranslationUnitDecl();

  ParmVarDecl *New
    = ParmVarDecl::Create(Context, DC, D.getIdentifierLoc(), II,
                          T, TInfo, StorageClass, 0);

  if (D.isInvalidType())
    New->setInvalidDecl();

  // Parameter declarators cannot be interface types. All ObjC objects are
  // passed by reference.
  if (T->isObjCInterfaceType()) {
    Diag(D.getIdentifierLoc(),
         diag::err_object_cannot_be_passed_returned_by_value) << 1 << T;
    New->setInvalidDecl();
  }

  // Parameter declarators cannot be qualified (C++ [dcl.meaning]p1).
  if (D.getCXXScopeSpec().isSet()) {
    Diag(D.getIdentifierLoc(), diag::err_qualified_param_declarator)
      << D.getCXXScopeSpec().getRange();
    New->setInvalidDecl();
  }
  
  // ISO/IEC TR 18037 S6.7.3: "The type of an object with automatic storage 
  // duration shall not be qualified by an address-space qualifier."
  // Since all parameters have automatic store duration, they can not have
  // an address space.
  if (T.getAddressSpace() != 0) {
    Diag(D.getIdentifierLoc(),  
         diag::err_arg_with_address_space);
    New->setInvalidDecl();
  }   
  
  
  // Add the parameter declaration into this scope.
  S->AddDecl(DeclPtrTy::make(New));
  if (II)
    IdResolver.AddDecl(New);

  ProcessDeclAttributes(S, New, D);

  if (New->hasAttr<BlocksAttr>()) {
    Diag(New->getLocation(), diag::err_block_on_nonlocal);
  }
  return DeclPtrTy::make(New);
}

void Sema::ActOnObjCCatchParam(DeclPtrTy D) {
  ParmVarDecl *Param = cast<ParmVarDecl>(D.getAs<Decl>());
  Param->setDeclContext(CurContext);
}

void Sema::ActOnFinishKNRParamDeclarations(Scope *S, Declarator &D,
                                           SourceLocation LocAfterDecls) {
  assert(D.getTypeObject(0).Kind == DeclaratorChunk::Function &&
         "Not a function declarator!");
  DeclaratorChunk::FunctionTypeInfo &FTI = D.getTypeObject(0).Fun;

  // Verify 6.9.1p6: 'every identifier in the identifier list shall be declared'
  // for a K&R function.
  if (!FTI.hasPrototype) {
    for (int i = FTI.NumArgs; i != 0; /* decrement in loop */) {
      --i;
      if (FTI.ArgInfo[i].Param == 0) {
        llvm::SmallString<256> Code;
        llvm::raw_svector_ostream(Code) << "  int "
                                        << FTI.ArgInfo[i].Ident->getName()
                                        << ";\n";
        Diag(FTI.ArgInfo[i].IdentLoc, diag::ext_param_not_declared)
          << FTI.ArgInfo[i].Ident
          << CodeModificationHint::CreateInsertion(LocAfterDecls, Code.str());

        // Implicitly declare the argument as type 'int' for lack of a better
        // type.
        DeclSpec DS;
        const char* PrevSpec; // unused
        unsigned DiagID; // unused
        DS.SetTypeSpecType(DeclSpec::TST_int, FTI.ArgInfo[i].IdentLoc,
                           PrevSpec, DiagID);
        Declarator ParamD(DS, Declarator::KNRTypeListContext);
        ParamD.SetIdentifier(FTI.ArgInfo[i].Ident, FTI.ArgInfo[i].IdentLoc);
        FTI.ArgInfo[i].Param = ActOnParamDeclarator(S, ParamD);
      }
    }
  }
}

Sema::DeclPtrTy Sema::ActOnStartOfFunctionDef(Scope *FnBodyScope,
                                              Declarator &D) {
  assert(getCurFunctionDecl() == 0 && "Function parsing confused");
  assert(D.getTypeObject(0).Kind == DeclaratorChunk::Function &&
         "Not a function declarator!");
  DeclaratorChunk::FunctionTypeInfo &FTI = D.getTypeObject(0).Fun;

  if (FTI.hasPrototype) {
    // FIXME: Diagnose arguments without names in C.
  }

  Scope *ParentScope = FnBodyScope->getParent();

  DeclPtrTy DP = HandleDeclarator(ParentScope, D,
                                  MultiTemplateParamsArg(*this),
                                  /*IsFunctionDefinition=*/true);
  return ActOnStartOfFunctionDef(FnBodyScope, DP);
}

static bool ShouldWarnAboutMissingPrototype(const FunctionDecl *FD) {
  // Don't warn about invalid declarations.
  if (FD->isInvalidDecl())
    return false;

  // Or declarations that aren't global.
  if (!FD->isGlobal())
    return false;

  // Don't warn about C++ member functions.
  if (isa<CXXMethodDecl>(FD))
    return false;

  // Don't warn about 'main'.
  if (FD->isMain())
    return false;

  // Don't warn about inline functions.
  if (FD->isInlineSpecified())
    return false;

  // Don't warn about function templates.
  if (FD->getDescribedFunctionTemplate())
    return false;

  // Don't warn about function template specializations.
  if (FD->isFunctionTemplateSpecialization())
    return false;

  bool MissingPrototype = true;
  for (const FunctionDecl *Prev = FD->getPreviousDeclaration();
       Prev; Prev = Prev->getPreviousDeclaration()) {
    // Ignore any declarations that occur in function or method
    // scope, because they aren't visible from the header.
    if (Prev->getDeclContext()->isFunctionOrMethod())
      continue;
      
    MissingPrototype = !Prev->getType()->isFunctionProtoType();
    break;
  }
    
  return MissingPrototype;
}

Sema::DeclPtrTy Sema::ActOnStartOfFunctionDef(Scope *FnBodyScope, DeclPtrTy D) {
  // Clear the last template instantiation error context.
  LastTemplateInstantiationErrorContext = ActiveTemplateInstantiation();
  
  if (!D)
    return D;
  FunctionDecl *FD = 0;

  if (FunctionTemplateDecl *FunTmpl
        = dyn_cast<FunctionTemplateDecl>(D.getAs<Decl>()))
    FD = FunTmpl->getTemplatedDecl();
  else
    FD = cast<FunctionDecl>(D.getAs<Decl>());

  CurFunctionNeedsScopeChecking = false;
  NumErrorsAtStartOfFunction = getDiagnostics().getNumErrors();

  // See if this is a redefinition.
  // But don't complain if we're in GNU89 mode and the previous definition
  // was an extern inline function.
  const FunctionDecl *Definition;
  if (FD->getBody(Definition) &&
      !canRedefineFunction(Definition, getLangOptions())) {
    Diag(FD->getLocation(), diag::err_redefinition) << FD->getDeclName();
    Diag(Definition->getLocation(), diag::note_previous_definition);
  }

  // Builtin functions cannot be defined.
  if (unsigned BuiltinID = FD->getBuiltinID()) {
    if (!Context.BuiltinInfo.isPredefinedLibFunction(BuiltinID)) {
      Diag(FD->getLocation(), diag::err_builtin_definition) << FD;
      FD->setInvalidDecl();
    }
  }

  // The return type of a function definition must be complete
  // (C99 6.9.1p3, C++ [dcl.fct]p6).
  QualType ResultType = FD->getResultType();
  if (!ResultType->isDependentType() && !ResultType->isVoidType() &&
      !FD->isInvalidDecl() &&
      RequireCompleteType(FD->getLocation(), ResultType,
                          diag::err_func_def_incomplete_result))
    FD->setInvalidDecl();

  // GNU warning -Wmissing-prototypes:
  //   Warn if a global function is defined without a previous
  //   prototype declaration. This warning is issued even if the
  //   definition itself provides a prototype. The aim is to detect
  //   global functions that fail to be declared in header files.
  if (ShouldWarnAboutMissingPrototype(FD))
    Diag(FD->getLocation(), diag::warn_missing_prototype) << FD;

  if (FnBodyScope)
    PushDeclContext(FnBodyScope, FD);

  // Check the validity of our function parameters
  CheckParmsForFunctionDef(FD);

  // Introduce our parameters into the function scope
  for (unsigned p = 0, NumParams = FD->getNumParams(); p < NumParams; ++p) {
    ParmVarDecl *Param = FD->getParamDecl(p);
    Param->setOwningFunction(FD);

    // If this has an identifier, add it to the scope stack.
    if (Param->getIdentifier() && FnBodyScope)
      PushOnScopeChains(Param, FnBodyScope);
  }

  // Checking attributes of current function definition
  // dllimport attribute.
  if (FD->getAttr<DLLImportAttr>() &&
      (!FD->getAttr<DLLExportAttr>())) {
    // dllimport attribute cannot be applied to definition.
    if (!(FD->getAttr<DLLImportAttr>())->isInherited()) {
      Diag(FD->getLocation(),
           diag::err_attribute_can_be_applied_only_to_symbol_declaration)
        << "dllimport";
      FD->setInvalidDecl();
      return DeclPtrTy::make(FD);
    }

    // Visual C++ appears to not think this is an issue, so only issue
    // a warning when Microsoft extensions are disabled.
    if (!LangOpts.Microsoft) {
      // If a symbol previously declared dllimport is later defined, the
      // attribute is ignored in subsequent references, and a warning is
      // emitted.
      Diag(FD->getLocation(),
           diag::warn_redeclaration_without_attribute_prev_attribute_ignored)
        << FD->getNameAsCString() << "dllimport";
    }
  }
  return DeclPtrTy::make(FD);
}

Sema::DeclPtrTy Sema::ActOnFinishFunctionBody(DeclPtrTy D, StmtArg BodyArg) {
  return ActOnFinishFunctionBody(D, move(BodyArg), false);
}

Sema::DeclPtrTy Sema::ActOnFinishFunctionBody(DeclPtrTy D, StmtArg BodyArg,
                                              bool IsInstantiation) {
  Decl *dcl = D.getAs<Decl>();
  Stmt *Body = BodyArg.takeAs<Stmt>();

  // Don't generate EH edges for CallExprs as we'd like to avoid the n^2
  // explosion for destrutors that can result and the compile time hit.
  AnalysisContext AC(dcl, false);
  FunctionDecl *FD = 0;
  FunctionTemplateDecl *FunTmpl = dyn_cast_or_null<FunctionTemplateDecl>(dcl);
  if (FunTmpl)
    FD = FunTmpl->getTemplatedDecl();
  else
    FD = dyn_cast_or_null<FunctionDecl>(dcl);

  if (FD) {
    FD->setBody(Body);
    if (FD->isMain())
      // C and C++ allow for main to automagically return 0.
      // Implements C++ [basic.start.main]p5 and C99 5.1.2.2.3.
      FD->setHasImplicitReturnZero(true);
    else
      CheckFallThroughForFunctionDef(FD, Body, AC);

    if (!FD->isInvalidDecl())
      DiagnoseUnusedParameters(FD->param_begin(), FD->param_end());

    if (CXXMethodDecl *Method = dyn_cast<CXXMethodDecl>(FD))
      MaybeMarkVirtualMembersReferenced(Method->getLocation(), Method);

    assert(FD == getCurFunctionDecl() && "Function parsing confused");
  } else if (ObjCMethodDecl *MD = dyn_cast_or_null<ObjCMethodDecl>(dcl)) {
    assert(MD == getCurMethodDecl() && "Method parsing confused");
    MD->setBody(Body);
    CheckFallThroughForFunctionDef(MD, Body, AC);
    MD->setEndLoc(Body->getLocEnd());

    if (!MD->isInvalidDecl())
      DiagnoseUnusedParameters(MD->param_begin(), MD->param_end());
  } else {
    Body->Destroy(Context);
    return DeclPtrTy();
  }
  if (!IsInstantiation)
    PopDeclContext();

  // Verify and clean out per-function state.

  assert(&getLabelMap() == &FunctionLabelMap && "Didn't pop block right?");

  // Check goto/label use.
  for (llvm::DenseMap<IdentifierInfo*, LabelStmt*>::iterator
       I = FunctionLabelMap.begin(), E = FunctionLabelMap.end(); I != E; ++I) {
    LabelStmt *L = I->second;

    // Verify that we have no forward references left.  If so, there was a goto
    // or address of a label taken, but no definition of it.  Label fwd
    // definitions are indicated with a null substmt.
    if (L->getSubStmt() != 0)
      continue;

    // Emit error.
    Diag(L->getIdentLoc(), diag::err_undeclared_label_use) << L->getName();

    // At this point, we have gotos that use the bogus label.  Stitch it into
    // the function body so that they aren't leaked and that the AST is well
    // formed.
    if (Body == 0) {
      // The whole function wasn't parsed correctly, just delete this.
      L->Destroy(Context);
      continue;
    }

    // Otherwise, the body is valid: we want to stitch the label decl into the
    // function somewhere so that it is properly owned and so that the goto
    // has a valid target.  Do this by creating a new compound stmt with the
    // label in it.

    // Give the label a sub-statement.
    L->setSubStmt(new (Context) NullStmt(L->getIdentLoc()));

    CompoundStmt *Compound = isa<CXXTryStmt>(Body) ?
                               cast<CXXTryStmt>(Body)->getTryBlock() :
                               cast<CompoundStmt>(Body);
    std::vector<Stmt*> Elements(Compound->body_begin(), Compound->body_end());
    Elements.push_back(L);
    Compound->setStmts(Context, &Elements[0], Elements.size());
  }
  FunctionLabelMap.clear();

  if (!Body) return D;

  CheckUnreachable(AC);

  // Verify that that gotos and switch cases don't jump into scopes illegally.
  if (CurFunctionNeedsScopeChecking &&
      NumErrorsAtStartOfFunction == getDiagnostics().getNumErrors())
    DiagnoseInvalidJumps(Body);

  // C++ constructors that have function-try-blocks can't have return
  // statements in the handlers of that block. (C++ [except.handle]p14)
  // Verify this.
  if (FD && isa<CXXConstructorDecl>(FD) && isa<CXXTryStmt>(Body))
    DiagnoseReturnInConstructorExceptionHandler(cast<CXXTryStmt>(Body));

  if (CXXDestructorDecl *Destructor = dyn_cast<CXXDestructorDecl>(dcl))
    MarkBaseAndMemberDestructorsReferenced(Destructor);
  
  // If any errors have occurred, clear out any temporaries that may have
  // been leftover. This ensures that these temporaries won't be picked up for
  // deletion in some later function.
  if (getDiagnostics().hasErrorOccurred())
    ExprTemporaries.clear();
  
  assert(ExprTemporaries.empty() && "Leftover temporaries in function");
  return D;
}

/// ImplicitlyDefineFunction - An undeclared identifier was used in a function
/// call, forming a call to an implicitly defined function (per C99 6.5.1p2).
NamedDecl *Sema::ImplicitlyDefineFunction(SourceLocation Loc,
                                          IdentifierInfo &II, Scope *S) {
  // Before we produce a declaration for an implicitly defined
  // function, see whether there was a locally-scoped declaration of
  // this name as a function or variable. If so, use that
  // (non-visible) declaration, and complain about it.
  llvm::DenseMap<DeclarationName, NamedDecl *>::iterator Pos
    = LocallyScopedExternalDecls.find(&II);
  if (Pos != LocallyScopedExternalDecls.end()) {
    Diag(Loc, diag::warn_use_out_of_scope_declaration) << Pos->second;
    Diag(Pos->second->getLocation(), diag::note_previous_declaration);
    return Pos->second;
  }

  // Extension in C99.  Legal in C90, but warn about it.
  if (II.getName().startswith("__builtin_"))
    Diag(Loc, diag::warn_builtin_unknown) << &II;
  else if (getLangOptions().C99)
    Diag(Loc, diag::ext_implicit_function_decl) << &II;
  else
    Diag(Loc, diag::warn_implicit_function_decl) << &II;

  // Set a Declarator for the implicit definition: int foo();
  const char *Dummy;
  DeclSpec DS;
  unsigned DiagID;
  bool Error = DS.SetTypeSpecType(DeclSpec::TST_int, Loc, Dummy, DiagID);
  Error = Error; // Silence warning.
  assert(!Error && "Error setting up implicit decl!");
  Declarator D(DS, Declarator::BlockContext);
  D.AddTypeInfo(DeclaratorChunk::getFunction(false, false, SourceLocation(), 0,
                                             0, 0, false, SourceLocation(),
                                             false, 0,0,0, Loc, Loc, D),
                SourceLocation());
  D.SetIdentifier(&II, Loc);

  // Insert this function into translation-unit scope.

  DeclContext *PrevDC = CurContext;
  CurContext = Context.getTranslationUnitDecl();

  FunctionDecl *FD =
 dyn_cast<FunctionDecl>(ActOnDeclarator(TUScope, D).getAs<Decl>());
  FD->setImplicit();

  CurContext = PrevDC;

  AddKnownFunctionAttributes(FD);

  return FD;
}

/// \brief Adds any function attributes that we know a priori based on
/// the declaration of this function.
///
/// These attributes can apply both to implicitly-declared builtins
/// (like __builtin___printf_chk) or to library-declared functions
/// like NSLog or printf.
void Sema::AddKnownFunctionAttributes(FunctionDecl *FD) {
  if (FD->isInvalidDecl())
    return;

  // If this is a built-in function, map its builtin attributes to
  // actual attributes.
  if (unsigned BuiltinID = FD->getBuiltinID()) {
    // Handle printf-formatting attributes.
    unsigned FormatIdx;
    bool HasVAListArg;
    if (Context.BuiltinInfo.isPrintfLike(BuiltinID, FormatIdx, HasVAListArg)) {
      if (!FD->getAttr<FormatAttr>())
        FD->addAttr(::new (Context) FormatAttr(Context, "printf", FormatIdx+1,
                                               HasVAListArg ? 0 : FormatIdx+2));
    }

    // Mark const if we don't care about errno and that is the only
    // thing preventing the function from being const. This allows
    // IRgen to use LLVM intrinsics for such functions.
    if (!getLangOptions().MathErrno &&
        Context.BuiltinInfo.isConstWithoutErrno(BuiltinID)) {
      if (!FD->getAttr<ConstAttr>())
        FD->addAttr(::new (Context) ConstAttr());
    }

    if (Context.BuiltinInfo.isNoReturn(BuiltinID))
      FD->setType(Context.getNoReturnType(FD->getType()));
    if (Context.BuiltinInfo.isNoThrow(BuiltinID))
      FD->addAttr(::new (Context) NoThrowAttr());
    if (Context.BuiltinInfo.isConst(BuiltinID))
      FD->addAttr(::new (Context) ConstAttr());
  }

  IdentifierInfo *Name = FD->getIdentifier();
  if (!Name)
    return;
  if ((!getLangOptions().CPlusPlus &&
       FD->getDeclContext()->isTranslationUnit()) ||
      (isa<LinkageSpecDecl>(FD->getDeclContext()) &&
       cast<LinkageSpecDecl>(FD->getDeclContext())->getLanguage() ==
       LinkageSpecDecl::lang_c)) {
    // Okay: this could be a libc/libm/Objective-C function we know
    // about.
  } else
    return;

  if (Name->isStr("NSLog") || Name->isStr("NSLogv")) {
    // FIXME: NSLog and NSLogv should be target specific
    if (const FormatAttr *Format = FD->getAttr<FormatAttr>()) {
      // FIXME: We known better than our headers.
      const_cast<FormatAttr *>(Format)->setType(Context, "printf");
    } else
      FD->addAttr(::new (Context) FormatAttr(Context, "printf", 1,
                                             Name->isStr("NSLogv") ? 0 : 2));
  } else if (Name->isStr("asprintf") || Name->isStr("vasprintf")) {
    // FIXME: asprintf and vasprintf aren't C99 functions. Should they be
    // target-specific builtins, perhaps?
    if (!FD->getAttr<FormatAttr>())
      FD->addAttr(::new (Context) FormatAttr(Context, "printf", 2,
                                             Name->isStr("vasprintf") ? 0 : 3));
  }
}

TypedefDecl *Sema::ParseTypedefDecl(Scope *S, Declarator &D, QualType T,
                                    TypeSourceInfo *TInfo) {
  assert(D.getIdentifier() && "Wrong callback for declspec without declarator");
  assert(!T.isNull() && "GetTypeForDeclarator() returned null type");

  if (!TInfo) {
    assert(D.isInvalidType() && "no declarator info for valid type");
    TInfo = Context.getTrivialTypeSourceInfo(T);
  }

  // Scope manipulation handled by caller.
  TypedefDecl *NewTD = TypedefDecl::Create(Context, CurContext,
                                           D.getIdentifierLoc(),
                                           D.getIdentifier(),
                                           TInfo);

  if (const TagType *TT = T->getAs<TagType>()) {
    TagDecl *TD = TT->getDecl();

    // If the TagDecl that the TypedefDecl points to is an anonymous decl
    // keep track of the TypedefDecl.
    if (!TD->getIdentifier() && !TD->getTypedefForAnonDecl())
      TD->setTypedefForAnonDecl(NewTD);
  }

  if (D.isInvalidType())
    NewTD->setInvalidDecl();
  return NewTD;
}


/// \brief Determine whether a tag with a given kind is acceptable
/// as a redeclaration of the given tag declaration.
///
/// \returns true if the new tag kind is acceptable, false otherwise.
bool Sema::isAcceptableTagRedeclaration(const TagDecl *Previous,
                                        TagDecl::TagKind NewTag,
                                        SourceLocation NewTagLoc,
                                        const IdentifierInfo &Name) {
  // C++ [dcl.type.elab]p3:
  //   The class-key or enum keyword present in the
  //   elaborated-type-specifier shall agree in kind with the
  //   declaration to which the name in theelaborated-type-specifier
  //   refers. This rule also applies to the form of
  //   elaborated-type-specifier that declares a class-name or
  //   friend class since it can be construed as referring to the
  //   definition of the class. Thus, in any
  //   elaborated-type-specifier, the enum keyword shall be used to
  //   refer to an enumeration (7.2), the union class-keyshall be
  //   used to refer to a union (clause 9), and either the class or
  //   struct class-key shall be used to refer to a class (clause 9)
  //   declared using the class or struct class-key.
  TagDecl::TagKind OldTag = Previous->getTagKind();
  if (OldTag == NewTag)
    return true;

  if ((OldTag == TagDecl::TK_struct || OldTag == TagDecl::TK_class) &&
      (NewTag == TagDecl::TK_struct || NewTag == TagDecl::TK_class)) {
    // Warn about the struct/class tag mismatch.
    bool isTemplate = false;
    if (const CXXRecordDecl *Record = dyn_cast<CXXRecordDecl>(Previous))
      isTemplate = Record->getDescribedClassTemplate();

    Diag(NewTagLoc, diag::warn_struct_class_tag_mismatch)
      << (NewTag == TagDecl::TK_class)
      << isTemplate << &Name
      << CodeModificationHint::CreateReplacement(SourceRange(NewTagLoc),
                              OldTag == TagDecl::TK_class? "class" : "struct");
    Diag(Previous->getLocation(), diag::note_previous_use);
    return true;
  }
  return false;
}

/// ActOnTag - This is invoked when we see 'struct foo' or 'struct {'.  In the
/// former case, Name will be non-null.  In the later case, Name will be null.
/// TagSpec indicates what kind of tag this is. TUK indicates whether this is a
/// reference/declaration/definition of a tag.
Sema::DeclPtrTy Sema::ActOnTag(Scope *S, unsigned TagSpec, TagUseKind TUK,
                               SourceLocation KWLoc, const CXXScopeSpec &SS,
                               IdentifierInfo *Name, SourceLocation NameLoc,
                               AttributeList *Attr, AccessSpecifier AS,
                               MultiTemplateParamsArg TemplateParameterLists,
                               bool &OwnedDecl, bool &IsDependent) {
  // If this is not a definition, it must have a name.
  assert((Name != 0 || TUK == TUK_Definition) &&
         "Nameless record must be a definition!");

  OwnedDecl = false;
  TagDecl::TagKind Kind = TagDecl::getTagKindForTypeSpec(TagSpec);

  // FIXME: Check explicit specializations more carefully.
  bool isExplicitSpecialization = false;
  if (TUK != TUK_Reference) {
    if (TemplateParameterList *TemplateParams
          = MatchTemplateParametersToScopeSpecifier(KWLoc, SS,
                        (TemplateParameterList**)TemplateParameterLists.get(),
                                              TemplateParameterLists.size(),
                                                    isExplicitSpecialization)) {
      if (TemplateParams->size() > 0) {
        // This is a declaration or definition of a class template (which may
        // be a member of another template).
        OwnedDecl = false;
        DeclResult Result = CheckClassTemplate(S, TagSpec, TUK, KWLoc,
                                               SS, Name, NameLoc, Attr,
                                               TemplateParams,
                                               AS);
        TemplateParameterLists.release();
        return Result.get();
      } else {
        // The "template<>" header is extraneous.
        Diag(TemplateParams->getTemplateLoc(), diag::err_template_tag_noparams)
          << ElaboratedType::getNameForTagKind(Kind) << Name;
        isExplicitSpecialization = true;
      }
    }
             
    TemplateParameterLists.release();
  }

  DeclContext *SearchDC = CurContext;
  DeclContext *DC = CurContext;
  bool isStdBadAlloc = false;
  bool Invalid = false;

  RedeclarationKind Redecl = (TUK != TUK_Reference ? ForRedeclaration
                                                   : NotForRedeclaration);

  LookupResult Previous(*this, Name, NameLoc, LookupTagName, Redecl);

  if (Name && SS.isNotEmpty()) {
    // We have a nested-name tag ('struct foo::bar').

    // Check for invalid 'foo::'.
    if (SS.isInvalid()) {
      Name = 0;
      goto CreateNewDecl;
    }

    // If this is a friend or a reference to a class in a dependent
    // context, don't try to make a decl for it.
    if (TUK == TUK_Friend || TUK == TUK_Reference) {
      DC = computeDeclContext(SS, false);
      if (!DC) {
        IsDependent = true;
        return DeclPtrTy();
      }
    }

    if (RequireCompleteDeclContext(SS))
      return DeclPtrTy::make((Decl *)0);

    DC = computeDeclContext(SS, true);
    SearchDC = DC;
    // Look-up name inside 'foo::'.
    LookupQualifiedName(Previous, DC);

    if (Previous.isAmbiguous())
      return DeclPtrTy();

    if (Previous.empty()) {
      // Name lookup did not find anything. However, if the
      // nested-name-specifier refers to the current instantiation,
      // and that current instantiation has any dependent base
      // classes, we might find something at instantiation time: treat
      // this as a dependent elaborated-type-specifier.
      if (Previous.wasNotFoundInCurrentInstantiation()) {
        IsDependent = true;
        return DeclPtrTy();
      }

      // A tag 'foo::bar' must already exist.
      Diag(NameLoc, diag::err_not_tag_in_scope) << Name << SS.getRange();
      Name = 0;
      Invalid = true;
      goto CreateNewDecl;
    }
  } else if (Name) {
    // If this is a named struct, check to see if there was a previous forward
    // declaration or definition.
    // FIXME: We're looking into outer scopes here, even when we
    // shouldn't be. Doing so can result in ambiguities that we
    // shouldn't be diagnosing.
    LookupName(Previous, S);

    // Note:  there used to be some attempt at recovery here.
    if (Previous.isAmbiguous())
      return DeclPtrTy();

    if (!getLangOptions().CPlusPlus && TUK != TUK_Reference) {
      // FIXME: This makes sure that we ignore the contexts associated
      // with C structs, unions, and enums when looking for a matching
      // tag declaration or definition. See the similar lookup tweak
      // in Sema::LookupName; is there a better way to deal with this?
      while (isa<RecordDecl>(SearchDC) || isa<EnumDecl>(SearchDC))
        SearchDC = SearchDC->getParent();
    }
  }

  if (Previous.isSingleResult() &&
      Previous.getFoundDecl()->isTemplateParameter()) {
    // Maybe we will complain about the shadowed template parameter.
    DiagnoseTemplateParameterShadow(NameLoc, Previous.getFoundDecl());
    // Just pretend that we didn't see the previous declaration.
    Previous.clear();
  }

  if (getLangOptions().CPlusPlus && Name && DC && StdNamespace &&
      DC->Equals(StdNamespace) && Name->isStr("bad_alloc")) {
    // This is a declaration of or a reference to "std::bad_alloc".
    isStdBadAlloc = true;
    
    if (Previous.empty() && StdBadAlloc) {
      // std::bad_alloc has been implicitly declared (but made invisible to
      // name lookup). Fill in this implicit declaration as the previous 
      // declaration, so that the declarations get chained appropriately.
      Previous.addDecl(StdBadAlloc);
    }
  }

  if (!Previous.empty()) {
    assert(Previous.isSingleResult());
    NamedDecl *PrevDecl = Previous.getFoundDecl();
    if (TagDecl *PrevTagDecl = dyn_cast<TagDecl>(PrevDecl)) {
      // If this is a use of a previous tag, or if the tag is already declared
      // in the same scope (so that the definition/declaration completes or
      // rementions the tag), reuse the decl.
      if (TUK == TUK_Reference || TUK == TUK_Friend ||
          isDeclInScope(PrevDecl, SearchDC, S)) {
        // Make sure that this wasn't declared as an enum and now used as a
        // struct or something similar.
        if (!isAcceptableTagRedeclaration(PrevTagDecl, Kind, KWLoc, *Name)) {
          bool SafeToContinue
            = (PrevTagDecl->getTagKind() != TagDecl::TK_enum &&
               Kind != TagDecl::TK_enum);
          if (SafeToContinue)
            Diag(KWLoc, diag::err_use_with_wrong_tag)
              << Name
              << CodeModificationHint::CreateReplacement(SourceRange(KWLoc),
                                                  PrevTagDecl->getKindName());
          else
            Diag(KWLoc, diag::err_use_with_wrong_tag) << Name;
          Diag(PrevTagDecl->getLocation(), diag::note_previous_use);

          if (SafeToContinue)
            Kind = PrevTagDecl->getTagKind();
          else {
            // Recover by making this an anonymous redefinition.
            Name = 0;
            Previous.clear();
            Invalid = true;
          }
        }

        if (!Invalid) {
          // If this is a use, just return the declaration we found.

          // FIXME: In the future, return a variant or some other clue
          // for the consumer of this Decl to know it doesn't own it.
          // For our current ASTs this shouldn't be a problem, but will
          // need to be changed with DeclGroups.
          if (TUK == TUK_Reference || TUK == TUK_Friend)
            return DeclPtrTy::make(PrevTagDecl);

          // Diagnose attempts to redefine a tag.
          if (TUK == TUK_Definition) {
            if (TagDecl *Def = PrevTagDecl->getDefinition()) {
              // If we're defining a specialization and the previous definition
              // is from an implicit instantiation, don't emit an error
              // here; we'll catch this in the general case below.
              if (!isExplicitSpecialization ||
                  !isa<CXXRecordDecl>(Def) ||
                  cast<CXXRecordDecl>(Def)->getTemplateSpecializationKind() 
                                               == TSK_ExplicitSpecialization) {
                Diag(NameLoc, diag::err_redefinition) << Name;
                Diag(Def->getLocation(), diag::note_previous_definition);
                // If this is a redefinition, recover by making this
                // struct be anonymous, which will make any later
                // references get the previous definition.
                Name = 0;
                Previous.clear();
                Invalid = true;
              }
            } else {
              // If the type is currently being defined, complain
              // about a nested redefinition.
              TagType *Tag = cast<TagType>(Context.getTagDeclType(PrevTagDecl));
              if (Tag->isBeingDefined()) {
                Diag(NameLoc, diag::err_nested_redefinition) << Name;
                Diag(PrevTagDecl->getLocation(),
                     diag::note_previous_definition);
                Name = 0;
                Previous.clear();
                Invalid = true;
              }
            }

            // Okay, this is definition of a previously declared or referenced
            // tag PrevDecl. We're going to create a new Decl for it.
          }
        }
        // If we get here we have (another) forward declaration or we
        // have a definition.  Just create a new decl.

      } else {
        // If we get here, this is a definition of a new tag type in a nested
        // scope, e.g. "struct foo; void bar() { struct foo; }", just create a
        // new decl/type.  We set PrevDecl to NULL so that the entities
        // have distinct types.
        Previous.clear();
      }
      // If we get here, we're going to create a new Decl. If PrevDecl
      // is non-NULL, it's a definition of the tag declared by
      // PrevDecl. If it's NULL, we have a new definition.
    } else {
      // PrevDecl is a namespace, template, or anything else
      // that lives in the IDNS_Tag identifier namespace.
      if (isDeclInScope(PrevDecl, SearchDC, S)) {
        // The tag name clashes with a namespace name, issue an error and
        // recover by making this tag be anonymous.
        Diag(NameLoc, diag::err_redefinition_different_kind) << Name;
        Diag(PrevDecl->getLocation(), diag::note_previous_definition);
        Name = 0;
        Previous.clear();
        Invalid = true;
      } else {
        // The existing declaration isn't relevant to us; we're in a
        // new scope, so clear out the previous declaration.
        Previous.clear();
      }
    }
  } else if (TUK == TUK_Reference && SS.isEmpty() && Name) {
    // C++ [basic.scope.pdecl]p5:
    //   -- for an elaborated-type-specifier of the form
    //
    //          class-key identifier
    //
    //      if the elaborated-type-specifier is used in the
    //      decl-specifier-seq or parameter-declaration-clause of a
    //      function defined in namespace scope, the identifier is
    //      declared as a class-name in the namespace that contains
    //      the declaration; otherwise, except as a friend
    //      declaration, the identifier is declared in the smallest
    //      non-class, non-function-prototype scope that contains the
    //      declaration.
    //
    // C99 6.7.2.3p8 has a similar (but not identical!) provision for
    // C structs and unions.
    //
    // It is an error in C++ to declare (rather than define) an enum
    // type, including via an elaborated type specifier.  We'll
    // diagnose that later; for now, declare the enum in the same
    // scope as we would have picked for any other tag type.
    //
    // GNU C also supports this behavior as part of its incomplete
    // enum types extension, while GNU C++ does not.
    //
    // Find the context where we'll be declaring the tag.
    // FIXME: We would like to maintain the current DeclContext as the
    // lexical context,
    while (SearchDC->isRecord())
      SearchDC = SearchDC->getParent();

    // Find the scope where we'll be declaring the tag.
    while (S->isClassScope() ||
           (getLangOptions().CPlusPlus && S->isFunctionPrototypeScope()) ||
           ((S->getFlags() & Scope::DeclScope) == 0) ||
           (S->getEntity() &&
            ((DeclContext *)S->getEntity())->isTransparentContext()))
      S = S->getParent();

  } else if (TUK == TUK_Friend && SS.isEmpty() && Name) {
    // C++ [namespace.memdef]p3:
    //   If a friend declaration in a non-local class first declares a
    //   class or function, the friend class or function is a member of
    //   the innermost enclosing namespace.
    SearchDC = SearchDC->getEnclosingNamespaceContext();

    // Look up through our scopes until we find one with an entity which
    // matches our declaration context.
    while (S->getEntity() &&
           ((DeclContext *)S->getEntity())->getPrimaryContext() != SearchDC) {
      S = S->getParent();
      assert(S && "No enclosing scope matching the enclosing namespace.");
    }
  }

CreateNewDecl:

  TagDecl *PrevDecl = 0;
  if (Previous.isSingleResult())
    PrevDecl = cast<TagDecl>(Previous.getFoundDecl());

  // If there is an identifier, use the location of the identifier as the
  // location of the decl, otherwise use the location of the struct/union
  // keyword.
  SourceLocation Loc = NameLoc.isValid() ? NameLoc : KWLoc;

  // Otherwise, create a new declaration. If there is a previous
  // declaration of the same entity, the two will be linked via
  // PrevDecl.
  TagDecl *New;

  if (Kind == TagDecl::TK_enum) {
    // FIXME: Tag decls should be chained to any simultaneous vardecls, e.g.:
    // enum X { A, B, C } D;    D should chain to X.
    New = EnumDecl::Create(Context, SearchDC, Loc, Name, KWLoc,
                           cast_or_null<EnumDecl>(PrevDecl));
    // If this is an undefined enum, warn.
    if (TUK != TUK_Definition && !Invalid)  {
      unsigned DK = getLangOptions().CPlusPlus? diag::err_forward_ref_enum
                                              : diag::ext_forward_ref_enum;
      Diag(Loc, DK);
    }
  } else {
    // struct/union/class

    // FIXME: Tag decls should be chained to any simultaneous vardecls, e.g.:
    // struct X { int A; } D;    D should chain to X.
    if (getLangOptions().CPlusPlus) {
      // FIXME: Look for a way to use RecordDecl for simple structs.
      New = CXXRecordDecl::Create(Context, Kind, SearchDC, Loc, Name, KWLoc,
                                  cast_or_null<CXXRecordDecl>(PrevDecl));
      
      if (isStdBadAlloc && (!StdBadAlloc || StdBadAlloc->isImplicit()))
        StdBadAlloc = cast<CXXRecordDecl>(New);
    } else
      New = RecordDecl::Create(Context, Kind, SearchDC, Loc, Name, KWLoc,
                               cast_or_null<RecordDecl>(PrevDecl));
  }

  if (Kind != TagDecl::TK_enum) {
    // Handle #pragma pack: if the #pragma pack stack has non-default
    // alignment, make up a packed attribute for this decl. These
    // attributes are checked when the ASTContext lays out the
    // structure.
    //
    // It is important for implementing the correct semantics that this
    // happen here (in act on tag decl). The #pragma pack stack is
    // maintained as a result of parser callbacks which can occur at
    // many points during the parsing of a struct declaration (because
    // the #pragma tokens are effectively skipped over during the
    // parsing of the struct).
    if (unsigned Alignment = getPragmaPackAlignment())
      New->addAttr(::new (Context) PragmaPackAttr(Alignment * 8));
  }

  if (getLangOptions().CPlusPlus && SS.isEmpty() && Name && !Invalid) {
    // C++ [dcl.typedef]p3:
    //   [...] Similarly, in a given scope, a class or enumeration
    //   shall not be declared with the same name as a typedef-name
    //   that is declared in that scope and refers to a type other
    //   than the class or enumeration itself.
    LookupResult Lookup(*this, Name, NameLoc, LookupOrdinaryName,
                        ForRedeclaration);
    LookupName(Lookup, S);
    TypedefDecl *PrevTypedef = Lookup.getAsSingle<TypedefDecl>();
    NamedDecl *PrevTypedefNamed = PrevTypedef;
    if (PrevTypedef && isDeclInScope(PrevTypedefNamed, SearchDC, S) &&
        Context.getCanonicalType(Context.getTypeDeclType(PrevTypedef)) !=
          Context.getCanonicalType(Context.getTypeDeclType(New))) {
      Diag(Loc, diag::err_tag_definition_of_typedef)
        << Context.getTypeDeclType(New)
        << PrevTypedef->getUnderlyingType();
      Diag(PrevTypedef->getLocation(), diag::note_previous_definition);
      Invalid = true;
    }
  }

  // If this is a specialization of a member class (of a class template),
  // check the specialization.
  if (isExplicitSpecialization && CheckMemberSpecialization(New, Previous))
    Invalid = true;
      
  if (Invalid)
    New->setInvalidDecl();

  if (Attr)
    ProcessDeclAttributeList(S, New, Attr);

  // If we're declaring or defining a tag in function prototype scope
  // in C, note that this type can only be used within the function.
  if (Name && S->isFunctionPrototypeScope() && !getLangOptions().CPlusPlus)
    Diag(Loc, diag::warn_decl_in_param_list) << Context.getTagDeclType(New);

  // Set the lexical context. If the tag has a C++ scope specifier, the
  // lexical context will be different from the semantic context.
  New->setLexicalDeclContext(CurContext);

  // Mark this as a friend decl if applicable.
  if (TUK == TUK_Friend)
    New->setObjectOfFriendDecl(/* PreviouslyDeclared = */ !Previous.empty());

  // Set the access specifier.
  if (!Invalid && TUK != TUK_Friend)
    SetMemberAccessSpecifier(New, PrevDecl, AS);

  if (TUK == TUK_Definition)
    New->startDefinition();

  // If this has an identifier, add it to the scope stack.
  if (TUK == TUK_Friend) {
    // We might be replacing an existing declaration in the lookup tables;
    // if so, borrow its access specifier.
    if (PrevDecl)
      New->setAccess(PrevDecl->getAccess());

    // Friend tag decls are visible in fairly strange ways.
    if (!CurContext->isDependentContext()) {
      DeclContext *DC = New->getDeclContext()->getLookupContext();
      DC->makeDeclVisibleInContext(New, /* Recoverable = */ false);
      if (Scope *EnclosingScope = getScopeForDeclContext(S, DC))
        PushOnScopeChains(New, EnclosingScope, /* AddToContext = */ false);
    }
  } else if (Name) {
    S = getNonFieldDeclScope(S);
    PushOnScopeChains(New, S);
  } else {
    CurContext->addDecl(New);
  }

  // If this is the C FILE type, notify the AST context.
  if (IdentifierInfo *II = New->getIdentifier())
    if (!New->isInvalidDecl() &&
        New->getDeclContext()->getLookupContext()->isTranslationUnit() &&
        II->isStr("FILE"))
      Context.setFILEDecl(New);

  OwnedDecl = true;
  return DeclPtrTy::make(New);
}

void Sema::ActOnTagStartDefinition(Scope *S, DeclPtrTy TagD) {
  AdjustDeclIfTemplate(TagD);
  TagDecl *Tag = cast<TagDecl>(TagD.getAs<Decl>());

  // Enter the tag context.
  PushDeclContext(S, Tag);
}

void Sema::ActOnStartCXXMemberDeclarations(Scope *S, DeclPtrTy TagD,
                                           SourceLocation LBraceLoc) {
  AdjustDeclIfTemplate(TagD);
  CXXRecordDecl *Record = cast<CXXRecordDecl>(TagD.getAs<Decl>());

  FieldCollector->StartClass();

  if (!Record->getIdentifier())
    return;

  // C++ [class]p2:
  //   [...] The class-name is also inserted into the scope of the
  //   class itself; this is known as the injected-class-name. For
  //   purposes of access checking, the injected-class-name is treated
  //   as if it were a public member name.
  CXXRecordDecl *InjectedClassName
    = CXXRecordDecl::Create(Context, Record->getTagKind(),
                            CurContext, Record->getLocation(),
                            Record->getIdentifier(),
                            Record->getTagKeywordLoc(),
                            Record);
  InjectedClassName->setImplicit();
  InjectedClassName->setAccess(AS_public);
  if (ClassTemplateDecl *Template = Record->getDescribedClassTemplate())
      InjectedClassName->setDescribedClassTemplate(Template);
  PushOnScopeChains(InjectedClassName, S);
  assert(InjectedClassName->isInjectedClassName() &&
         "Broken injected-class-name");
}

// Traverses the class and any nested classes, making a note of any 
// dynamic classes that have no key function so that we can mark all of
// their virtual member functions as "used" at the end of the translation
// unit. This ensures that all functions needed by the vtable will get
// instantiated/synthesized.
static void 
RecordDynamicClassesWithNoKeyFunction(Sema &S, CXXRecordDecl *Record,
                                      SourceLocation Loc) {
  // We don't look at dependent or undefined classes.
  if (Record->isDependentContext() || !Record->isDefinition())
    return;
  
  if (Record->isDynamicClass()) {
    const CXXMethodDecl *KeyFunction = S.Context.getKeyFunction(Record);
  
    if (!KeyFunction)
      S.ClassesWithUnmarkedVirtualMembers.push_back(std::make_pair(Record,
                                                                   Loc));

    if ((!KeyFunction || (KeyFunction->getBody() && KeyFunction->isInlined()))
        && Record->getLinkage() == ExternalLinkage)
      S.Diag(Record->getLocation(), diag::warn_weak_vtable) << Record;
  }
  for (DeclContext::decl_iterator D = Record->decls_begin(), 
                               DEnd = Record->decls_end();
       D != DEnd; ++D) {
    if (CXXRecordDecl *Nested = dyn_cast<CXXRecordDecl>(*D))
      RecordDynamicClassesWithNoKeyFunction(S, Nested, Loc);
  }
}

void Sema::ActOnTagFinishDefinition(Scope *S, DeclPtrTy TagD,
                                    SourceLocation RBraceLoc) {
  AdjustDeclIfTemplate(TagD);
  TagDecl *Tag = cast<TagDecl>(TagD.getAs<Decl>());
  Tag->setRBraceLoc(RBraceLoc);

  if (isa<CXXRecordDecl>(Tag))
    FieldCollector->FinishClass();

  // Exit this scope of this tag's definition.
  PopDeclContext();

  if (isa<CXXRecordDecl>(Tag) && !Tag->getDeclContext()->isRecord())
    RecordDynamicClassesWithNoKeyFunction(*this, cast<CXXRecordDecl>(Tag),
                                          RBraceLoc);
                                          
  // Notify the consumer that we've defined a tag.
  Consumer.HandleTagDeclDefinition(Tag);
}

// Note that FieldName may be null for anonymous bitfields.
bool Sema::VerifyBitField(SourceLocation FieldLoc, IdentifierInfo *FieldName,
                          QualType FieldTy, const Expr *BitWidth,
                          bool *ZeroWidth) {
  // Default to true; that shouldn't confuse checks for emptiness
  if (ZeroWidth)
    *ZeroWidth = true;

  // C99 6.7.2.1p4 - verify the field type.
  // C++ 9.6p3: A bit-field shall have integral or enumeration type.
  if (!FieldTy->isDependentType() && !FieldTy->isIntegralType()) {
    // Handle incomplete types with specific error.
    if (RequireCompleteType(FieldLoc, FieldTy, diag::err_field_incomplete))
      return true;
    if (FieldName)
      return Diag(FieldLoc, diag::err_not_integral_type_bitfield)
        << FieldName << FieldTy << BitWidth->getSourceRange();
    return Diag(FieldLoc, diag::err_not_integral_type_anon_bitfield)
      << FieldTy << BitWidth->getSourceRange();
  }

  // If the bit-width is type- or value-dependent, don't try to check
  // it now.
  if (BitWidth->isValueDependent() || BitWidth->isTypeDependent())
    return false;

  llvm::APSInt Value;
  if (VerifyIntegerConstantExpression(BitWidth, &Value))
    return true;

  if (Value != 0 && ZeroWidth)
    *ZeroWidth = false;

  // Zero-width bitfield is ok for anonymous field.
  if (Value == 0 && FieldName)
    return Diag(FieldLoc, diag::err_bitfield_has_zero_width) << FieldName;

  if (Value.isSigned() && Value.isNegative()) {
    if (FieldName)
      return Diag(FieldLoc, diag::err_bitfield_has_negative_width)
               << FieldName << Value.toString(10);
    return Diag(FieldLoc, diag::err_anon_bitfield_has_negative_width)
      << Value.toString(10);
  }

  if (!FieldTy->isDependentType()) {
    uint64_t TypeSize = Context.getTypeSize(FieldTy);
    if (Value.getZExtValue() > TypeSize) {
      if (FieldName)
        return Diag(FieldLoc, diag::err_bitfield_width_exceeds_type_size)
          << FieldName << (unsigned)TypeSize;
      return Diag(FieldLoc, diag::err_anon_bitfield_width_exceeds_type_size)
        << (unsigned)TypeSize;
    }
  }

  return false;
}

/// ActOnField - Each field of a struct/union/class is passed into this in order
/// to create a FieldDecl object for it.
Sema::DeclPtrTy Sema::ActOnField(Scope *S, DeclPtrTy TagD,
                                 SourceLocation DeclStart,
                                 Declarator &D, ExprTy *BitfieldWidth) {
  FieldDecl *Res = HandleField(S, cast_or_null<RecordDecl>(TagD.getAs<Decl>()),
                               DeclStart, D, static_cast<Expr*>(BitfieldWidth),
                               AS_public);
  return DeclPtrTy::make(Res);
}

/// HandleField - Analyze a field of a C struct or a C++ data member.
///
FieldDecl *Sema::HandleField(Scope *S, RecordDecl *Record,
                             SourceLocation DeclStart,
                             Declarator &D, Expr *BitWidth,
                             AccessSpecifier AS) {
  IdentifierInfo *II = D.getIdentifier();
  SourceLocation Loc = DeclStart;
  if (II) Loc = D.getIdentifierLoc();

  TypeSourceInfo *TInfo = 0;
  QualType T = GetTypeForDeclarator(D, S, &TInfo);
  if (getLangOptions().CPlusPlus)
    CheckExtraCXXDefaultArguments(D);

  DiagnoseFunctionSpecifiers(D);

  if (D.getDeclSpec().isThreadSpecified())
    Diag(D.getDeclSpec().getThreadSpecLoc(), diag::err_invalid_thread);

  NamedDecl *PrevDecl = LookupSingleName(S, II, LookupMemberName,
                                         ForRedeclaration);

  if (PrevDecl && PrevDecl->isTemplateParameter()) {
    // Maybe we will complain about the shadowed template parameter.
    DiagnoseTemplateParameterShadow(D.getIdentifierLoc(), PrevDecl);
    // Just pretend that we didn't see the previous declaration.
    PrevDecl = 0;
  }

  if (PrevDecl && !isDeclInScope(PrevDecl, Record, S))
    PrevDecl = 0;

  bool Mutable
    = (D.getDeclSpec().getStorageClassSpec() == DeclSpec::SCS_mutable);
  SourceLocation TSSL = D.getSourceRange().getBegin();
  FieldDecl *NewFD
    = CheckFieldDecl(II, T, TInfo, Record, Loc, Mutable, BitWidth, TSSL,
                     AS, PrevDecl, &D);
  if (NewFD->isInvalidDecl() && PrevDecl) {
    // Don't introduce NewFD into scope; there's already something
    // with the same name in the same scope.
  } else if (II) {
    PushOnScopeChains(NewFD, S);
  } else
    Record->addDecl(NewFD);

  return NewFD;
}

/// \brief Build a new FieldDecl and check its well-formedness.
///
/// This routine builds a new FieldDecl given the fields name, type,
/// record, etc. \p PrevDecl should refer to any previous declaration
/// with the same name and in the same scope as the field to be
/// created.
///
/// \returns a new FieldDecl.
///
/// \todo The Declarator argument is a hack. It will be removed once
FieldDecl *Sema::CheckFieldDecl(DeclarationName Name, QualType T,
                                TypeSourceInfo *TInfo,
                                RecordDecl *Record, SourceLocation Loc,
                                bool Mutable, Expr *BitWidth,
                                SourceLocation TSSL,
                                AccessSpecifier AS, NamedDecl *PrevDecl,
                                Declarator *D) {
  IdentifierInfo *II = Name.getAsIdentifierInfo();
  bool InvalidDecl = false;
  if (D) InvalidDecl = D->isInvalidType();

  // If we receive a broken type, recover by assuming 'int' and
  // marking this declaration as invalid.
  if (T.isNull()) {
    InvalidDecl = true;
    T = Context.IntTy;
  }

  QualType EltTy = Context.getBaseElementType(T);
  if (!EltTy->isDependentType() &&
      RequireCompleteType(Loc, EltTy, diag::err_field_incomplete))
    InvalidDecl = true;

  // C99 6.7.2.1p8: A member of a structure or union may have any type other
  // than a variably modified type.
  if (!InvalidDecl && T->isVariablyModifiedType()) {
    bool SizeIsNegative;
    QualType FixedTy = TryToFixInvalidVariablyModifiedType(T, Context,
                                                           SizeIsNegative);
    if (!FixedTy.isNull()) {
      Diag(Loc, diag::warn_illegal_constant_array_size);
      T = FixedTy;
    } else {
      if (SizeIsNegative)
        Diag(Loc, diag::err_typecheck_negative_array_size);
      else
        Diag(Loc, diag::err_typecheck_field_variable_size);
      InvalidDecl = true;
    }
  }

  // Fields can not have abstract class types
  if (!InvalidDecl && RequireNonAbstractType(Loc, T,
                                             diag::err_abstract_type_in_decl,
                                             AbstractFieldType))
    InvalidDecl = true;

  bool ZeroWidth = false;
  // If this is declared as a bit-field, check the bit-field.
  if (!InvalidDecl && BitWidth &&
      VerifyBitField(Loc, II, T, BitWidth, &ZeroWidth)) {
    InvalidDecl = true;
    DeleteExpr(BitWidth);
    BitWidth = 0;
    ZeroWidth = false;
  }

  FieldDecl *NewFD = FieldDecl::Create(Context, Record, Loc, II, T, TInfo,
                                       BitWidth, Mutable);
  if (InvalidDecl)
    NewFD->setInvalidDecl();

  if (PrevDecl && !isa<TagDecl>(PrevDecl)) {
    Diag(Loc, diag::err_duplicate_member) << II;
    Diag(PrevDecl->getLocation(), diag::note_previous_declaration);
    NewFD->setInvalidDecl();
  }

  if (!InvalidDecl && getLangOptions().CPlusPlus) {
    CXXRecordDecl* CXXRecord = cast<CXXRecordDecl>(Record);

    if (!T->isPODType())
      CXXRecord->setPOD(false);
    if (!ZeroWidth)
      CXXRecord->setEmpty(false);

    if (const RecordType *RT = EltTy->getAs<RecordType>()) {
      CXXRecordDecl* RDecl = cast<CXXRecordDecl>(RT->getDecl());

      if (!RDecl->hasTrivialConstructor())
        CXXRecord->setHasTrivialConstructor(false);
      if (!RDecl->hasTrivialCopyConstructor())
        CXXRecord->setHasTrivialCopyConstructor(false);
      if (!RDecl->hasTrivialCopyAssignment())
        CXXRecord->setHasTrivialCopyAssignment(false);
      if (!RDecl->hasTrivialDestructor())
        CXXRecord->setHasTrivialDestructor(false);

      // C++ 9.5p1: An object of a class with a non-trivial
      // constructor, a non-trivial copy constructor, a non-trivial
      // destructor, or a non-trivial copy assignment operator
      // cannot be a member of a union, nor can an array of such
      // objects.
      // TODO: C++0x alters this restriction significantly.
      if (Record->isUnion()) {
        // We check for copy constructors before constructors
        // because otherwise we'll never get complaints about
        // copy constructors.

        const CXXSpecialMember invalid = (CXXSpecialMember) -1;

        CXXSpecialMember member;
        if (!RDecl->hasTrivialCopyConstructor())
          member = CXXCopyConstructor;
        else if (!RDecl->hasTrivialConstructor())
          member = CXXDefaultConstructor;
        else if (!RDecl->hasTrivialCopyAssignment())
          member = CXXCopyAssignment;
        else if (!RDecl->hasTrivialDestructor())
          member = CXXDestructor;
        else
          member = invalid;

        if (member != invalid) {
          Diag(Loc, diag::err_illegal_union_member) << Name << member;
          DiagnoseNontrivial(RT, member);
          NewFD->setInvalidDecl();
        }
      }
    }
  }

  // FIXME: We need to pass in the attributes given an AST
  // representation, not a parser representation.
  if (D)
    // FIXME: What to pass instead of TUScope?
    ProcessDeclAttributes(TUScope, NewFD, *D);

  if (T.isObjCGCWeak())
    Diag(Loc, diag::warn_attribute_weak_on_field);

  NewFD->setAccess(AS);

  // C++ [dcl.init.aggr]p1:
  //   An aggregate is an array or a class (clause 9) with [...] no
  //   private or protected non-static data members (clause 11).
  // A POD must be an aggregate.
  if (getLangOptions().CPlusPlus &&
      (AS == AS_private || AS == AS_protected)) {
    CXXRecordDecl *CXXRecord = cast<CXXRecordDecl>(Record);
    CXXRecord->setAggregate(false);
    CXXRecord->setPOD(false);
  }

  return NewFD;
}

/// DiagnoseNontrivial - Given that a class has a non-trivial
/// special member, figure out why.
void Sema::DiagnoseNontrivial(const RecordType* T, CXXSpecialMember member) {
  QualType QT(T, 0U);
  CXXRecordDecl* RD = cast<CXXRecordDecl>(T->getDecl());

  // Check whether the member was user-declared.
  switch (member) {
  case CXXDefaultConstructor:
    if (RD->hasUserDeclaredConstructor()) {
      typedef CXXRecordDecl::ctor_iterator ctor_iter;
      for (ctor_iter ci = RD->ctor_begin(), ce = RD->ctor_end(); ci != ce;++ci){
        const FunctionDecl *body = 0;
        ci->getBody(body);
        if (!body ||
            !cast<CXXConstructorDecl>(body)->isImplicitlyDefined(Context)) {
          SourceLocation CtorLoc = ci->getLocation();
          Diag(CtorLoc, diag::note_nontrivial_user_defined) << QT << member;
          return;
        }
      }

      assert(0 && "found no user-declared constructors");
      return;
    }
    break;

  case CXXCopyConstructor:
    if (RD->hasUserDeclaredCopyConstructor()) {
      SourceLocation CtorLoc =
        RD->getCopyConstructor(Context, 0)->getLocation();
      Diag(CtorLoc, diag::note_nontrivial_user_defined) << QT << member;
      return;
    }
    break;

  case CXXCopyAssignment:
    if (RD->hasUserDeclaredCopyAssignment()) {
      // FIXME: this should use the location of the copy
      // assignment, not the type.
      SourceLocation TyLoc = RD->getSourceRange().getBegin();
      Diag(TyLoc, diag::note_nontrivial_user_defined) << QT << member;
      return;
    }
    break;

  case CXXDestructor:
    if (RD->hasUserDeclaredDestructor()) {
      SourceLocation DtorLoc = RD->getDestructor(Context)->getLocation();
      Diag(DtorLoc, diag::note_nontrivial_user_defined) << QT << member;
      return;
    }
    break;
  }

  typedef CXXRecordDecl::base_class_iterator base_iter;

  // Virtual bases and members inhibit trivial copying/construction,
  // but not trivial destruction.
  if (member != CXXDestructor) {
    // Check for virtual bases.  vbases includes indirect virtual bases,
    // so we just iterate through the direct bases.
    for (base_iter bi = RD->bases_begin(), be = RD->bases_end(); bi != be; ++bi)
      if (bi->isVirtual()) {
        SourceLocation BaseLoc = bi->getSourceRange().getBegin();
        Diag(BaseLoc, diag::note_nontrivial_has_virtual) << QT << 1;
        return;
      }

    // Check for virtual methods.
    typedef CXXRecordDecl::method_iterator meth_iter;
    for (meth_iter mi = RD->method_begin(), me = RD->method_end(); mi != me;
         ++mi) {
      if (mi->isVirtual()) {
        SourceLocation MLoc = mi->getSourceRange().getBegin();
        Diag(MLoc, diag::note_nontrivial_has_virtual) << QT << 0;
        return;
      }
    }
  }

  bool (CXXRecordDecl::*hasTrivial)() const;
  switch (member) {
  case CXXDefaultConstructor:
    hasTrivial = &CXXRecordDecl::hasTrivialConstructor; break;
  case CXXCopyConstructor:
    hasTrivial = &CXXRecordDecl::hasTrivialCopyConstructor; break;
  case CXXCopyAssignment:
    hasTrivial = &CXXRecordDecl::hasTrivialCopyAssignment; break;
  case CXXDestructor:
    hasTrivial = &CXXRecordDecl::hasTrivialDestructor; break;
  default:
    assert(0 && "unexpected special member"); return;
  }

  // Check for nontrivial bases (and recurse).
  for (base_iter bi = RD->bases_begin(), be = RD->bases_end(); bi != be; ++bi) {
    const RecordType *BaseRT = bi->getType()->getAs<RecordType>();
    assert(BaseRT && "Don't know how to handle dependent bases");
    CXXRecordDecl *BaseRecTy = cast<CXXRecordDecl>(BaseRT->getDecl());
    if (!(BaseRecTy->*hasTrivial)()) {
      SourceLocation BaseLoc = bi->getSourceRange().getBegin();
      Diag(BaseLoc, diag::note_nontrivial_has_nontrivial) << QT << 1 << member;
      DiagnoseNontrivial(BaseRT, member);
      return;
    }
  }

  // Check for nontrivial members (and recurse).
  typedef RecordDecl::field_iterator field_iter;
  for (field_iter fi = RD->field_begin(), fe = RD->field_end(); fi != fe;
       ++fi) {
    QualType EltTy = Context.getBaseElementType((*fi)->getType());
    if (const RecordType *EltRT = EltTy->getAs<RecordType>()) {
      CXXRecordDecl* EltRD = cast<CXXRecordDecl>(EltRT->getDecl());

      if (!(EltRD->*hasTrivial)()) {
        SourceLocation FLoc = (*fi)->getLocation();
        Diag(FLoc, diag::note_nontrivial_has_nontrivial) << QT << 0 << member;
        DiagnoseNontrivial(EltRT, member);
        return;
      }
    }
  }

  assert(0 && "found no explanation for non-trivial member");
}

/// TranslateIvarVisibility - Translate visibility from a token ID to an
///  AST enum value.
static ObjCIvarDecl::AccessControl
TranslateIvarVisibility(tok::ObjCKeywordKind ivarVisibility) {
  switch (ivarVisibility) {
  default: assert(0 && "Unknown visitibility kind");
  case tok::objc_private: return ObjCIvarDecl::Private;
  case tok::objc_public: return ObjCIvarDecl::Public;
  case tok::objc_protected: return ObjCIvarDecl::Protected;
  case tok::objc_package: return ObjCIvarDecl::Package;
  }
}

/// ActOnIvar - Each ivar field of an objective-c class is passed into this
/// in order to create an IvarDecl object for it.
Sema::DeclPtrTy Sema::ActOnIvar(Scope *S,
                                SourceLocation DeclStart,
                                DeclPtrTy IntfDecl,
                                Declarator &D, ExprTy *BitfieldWidth,
                                tok::ObjCKeywordKind Visibility) {

  IdentifierInfo *II = D.getIdentifier();
  Expr *BitWidth = (Expr*)BitfieldWidth;
  SourceLocation Loc = DeclStart;
  if (II) Loc = D.getIdentifierLoc();

  // FIXME: Unnamed fields can be handled in various different ways, for
  // example, unnamed unions inject all members into the struct namespace!

  TypeSourceInfo *TInfo = 0;
  QualType T = GetTypeForDeclarator(D, S, &TInfo);

  if (BitWidth) {
    // 6.7.2.1p3, 6.7.2.1p4
    if (VerifyBitField(Loc, II, T, BitWidth)) {
      D.setInvalidType();
      DeleteExpr(BitWidth);
      BitWidth = 0;
    }
  } else {
    // Not a bitfield.

    // validate II.

  }

  // C99 6.7.2.1p8: A member of a structure or union may have any type other
  // than a variably modified type.
  if (T->isVariablyModifiedType()) {
    Diag(Loc, diag::err_typecheck_ivar_variable_size);
    D.setInvalidType();
  }

  // Get the visibility (access control) for this ivar.
  ObjCIvarDecl::AccessControl ac =
    Visibility != tok::objc_not_keyword ? TranslateIvarVisibility(Visibility)
                                        : ObjCIvarDecl::None;
  // Must set ivar's DeclContext to its enclosing interface.
  Decl *EnclosingDecl = IntfDecl.getAs<Decl>();
  DeclContext *EnclosingContext;
  if (ObjCImplementationDecl *IMPDecl =
      dyn_cast<ObjCImplementationDecl>(EnclosingDecl)) {
    // Case of ivar declared in an implementation. Context is that of its class.
    ObjCInterfaceDecl* IDecl = IMPDecl->getClassInterface();
    assert(IDecl && "No class- ActOnIvar");
    EnclosingContext = cast_or_null<DeclContext>(IDecl);
  } else
    EnclosingContext = dyn_cast<DeclContext>(EnclosingDecl);
  assert(EnclosingContext && "null DeclContext for ivar - ActOnIvar");

  // Construct the decl.
  ObjCIvarDecl *NewID = ObjCIvarDecl::Create(Context,
                                             EnclosingContext, Loc, II, T,
                                             TInfo, ac, (Expr *)BitfieldWidth);

  if (II) {
    NamedDecl *PrevDecl = LookupSingleName(S, II, LookupMemberName,
                                           ForRedeclaration);
    if (PrevDecl && isDeclInScope(PrevDecl, EnclosingContext, S)
        && !isa<TagDecl>(PrevDecl)) {
      Diag(Loc, diag::err_duplicate_member) << II;
      Diag(PrevDecl->getLocation(), diag::note_previous_declaration);
      NewID->setInvalidDecl();
    }
  }

  // Process attributes attached to the ivar.
  ProcessDeclAttributes(S, NewID, D);

  if (D.isInvalidType())
    NewID->setInvalidDecl();

  if (II) {
    // FIXME: When interfaces are DeclContexts, we'll need to add
    // these to the interface.
    S->AddDecl(DeclPtrTy::make(NewID));
    IdResolver.AddDecl(NewID);
  }

  return DeclPtrTy::make(NewID);
}

void Sema::ActOnFields(Scope* S,
                       SourceLocation RecLoc, DeclPtrTy RecDecl,
                       DeclPtrTy *Fields, unsigned NumFields,
                       SourceLocation LBrac, SourceLocation RBrac,
                       AttributeList *Attr) {
  Decl *EnclosingDecl = RecDecl.getAs<Decl>();
  assert(EnclosingDecl && "missing record or interface decl");

  // If the decl this is being inserted into is invalid, then it may be a
  // redeclaration or some other bogus case.  Don't try to add fields to it.
  if (EnclosingDecl->isInvalidDecl()) {
    // FIXME: Deallocate fields?
    return;
  }


  // Verify that all the fields are okay.
  unsigned NumNamedMembers = 0;
  llvm::SmallVector<FieldDecl*, 32> RecFields;

  RecordDecl *Record = dyn_cast<RecordDecl>(EnclosingDecl);
  for (unsigned i = 0; i != NumFields; ++i) {
    FieldDecl *FD = cast<FieldDecl>(Fields[i].getAs<Decl>());

    // Get the type for the field.
    Type *FDTy = FD->getType().getTypePtr();

    if (!FD->isAnonymousStructOrUnion()) {
      // Remember all fields written by the user.
      RecFields.push_back(FD);
    }

    // If the field is already invalid for some reason, don't emit more
    // diagnostics about it.
    if (FD->isInvalidDecl()) {
      EnclosingDecl->setInvalidDecl();
      continue;
    }

    // C99 6.7.2.1p2:
    //   A structure or union shall not contain a member with
    //   incomplete or function type (hence, a structure shall not
    //   contain an instance of itself, but may contain a pointer to
    //   an instance of itself), except that the last member of a
    //   structure with more than one named member may have incomplete
    //   array type; such a structure (and any union containing,
    //   possibly recursively, a member that is such a structure)
    //   shall not be a member of a structure or an element of an
    //   array.
    if (FDTy->isFunctionType()) {
      // Field declared as a function.
      Diag(FD->getLocation(), diag::err_field_declared_as_function)
        << FD->getDeclName();
      FD->setInvalidDecl();
      EnclosingDecl->setInvalidDecl();
      continue;
    } else if (FDTy->isIncompleteArrayType() && i == NumFields - 1 &&
               Record && Record->isStruct()) {
      // Flexible array member.
      if (NumNamedMembers < 1) {
        Diag(FD->getLocation(), diag::err_flexible_array_empty_struct)
          << FD->getDeclName();
        FD->setInvalidDecl();
        EnclosingDecl->setInvalidDecl();
        continue;
      }
      // Okay, we have a legal flexible array member at the end of the struct.
      if (Record)
        Record->setHasFlexibleArrayMember(true);
    } else if (!FDTy->isDependentType() &&
               RequireCompleteType(FD->getLocation(), FD->getType(),
                                   diag::err_field_incomplete)) {
      // Incomplete type
      FD->setInvalidDecl();
      EnclosingDecl->setInvalidDecl();
      continue;
    } else if (const RecordType *FDTTy = FDTy->getAs<RecordType>()) {
      if (FDTTy->getDecl()->hasFlexibleArrayMember()) {
        // If this is a member of a union, then entire union becomes "flexible".
        if (Record && Record->isUnion()) {
          Record->setHasFlexibleArrayMember(true);
        } else {
          // If this is a struct/class and this is not the last element, reject
          // it.  Note that GCC supports variable sized arrays in the middle of
          // structures.
          if (i != NumFields-1)
            Diag(FD->getLocation(), diag::ext_variable_sized_type_in_struct)
              << FD->getDeclName() << FD->getType();
          else {
            // We support flexible arrays at the end of structs in
            // other structs as an extension.
            Diag(FD->getLocation(), diag::ext_flexible_array_in_struct)
              << FD->getDeclName();
            if (Record)
              Record->setHasFlexibleArrayMember(true);
          }
        }
      }
      if (Record && FDTTy->getDecl()->hasObjectMember())
        Record->setHasObjectMember(true);
    } else if (FDTy->isObjCInterfaceType()) {
      /// A field cannot be an Objective-c object
      Diag(FD->getLocation(), diag::err_statically_allocated_object);
      FD->setInvalidDecl();
      EnclosingDecl->setInvalidDecl();
      continue;
    } else if (getLangOptions().ObjC1 &&
               getLangOptions().getGCMode() != LangOptions::NonGC &&
               Record &&
               (FD->getType()->isObjCObjectPointerType() ||
                FD->getType().isObjCGCStrong()))
      Record->setHasObjectMember(true);
    // Keep track of the number of named members.
    if (FD->getIdentifier())
      ++NumNamedMembers;
  }

  // Okay, we successfully defined 'Record'.
  if (Record) {
    Record->completeDefinition();
  } else {
    ObjCIvarDecl **ClsFields =
      reinterpret_cast<ObjCIvarDecl**>(RecFields.data());
    if (ObjCInterfaceDecl *ID = dyn_cast<ObjCInterfaceDecl>(EnclosingDecl)) {
      ID->setLocEnd(RBrac);
      // Add ivar's to class's DeclContext.
      for (unsigned i = 0, e = RecFields.size(); i != e; ++i) {
        ClsFields[i]->setLexicalDeclContext(ID);
        ID->addDecl(ClsFields[i]);
      }
      // Must enforce the rule that ivars in the base classes may not be
      // duplicates.
      if (ID->getSuperClass())
        DiagnoseDuplicateIvars(ID, ID->getSuperClass());
    } else if (ObjCImplementationDecl *IMPDecl =
                  dyn_cast<ObjCImplementationDecl>(EnclosingDecl)) {
      assert(IMPDecl && "ActOnFields - missing ObjCImplementationDecl");
      for (unsigned I = 0, N = RecFields.size(); I != N; ++I)
        // Ivar declared in @implementation never belongs to the implementation.
        // Only it is in implementation's lexical context.
        ClsFields[I]->setLexicalDeclContext(IMPDecl);
      CheckImplementationIvars(IMPDecl, ClsFields, RecFields.size(), RBrac);
    } else if (ObjCCategoryDecl *CDecl = 
                dyn_cast<ObjCCategoryDecl>(EnclosingDecl)) {
      if (!LangOpts.ObjCNonFragileABI2 || !CDecl->IsClassExtension())
        Diag(LBrac, diag::err_misplaced_ivar);
      else {
        // FIXME. Class extension does not have a LocEnd field.
        // CDecl->setLocEnd(RBrac);
        // Add ivar's to class extension's DeclContext.
        for (unsigned i = 0, e = RecFields.size(); i != e; ++i) {
          ClsFields[i]->setLexicalDeclContext(CDecl);
          CDecl->addDecl(ClsFields[i]);
        }
      }
    }
  }

  if (Attr)
    ProcessDeclAttributeList(S, Record, Attr);
}

/// \brief Determine whether the given integral value is representable within
/// the given type T.
static bool isRepresentableIntegerValue(ASTContext &Context,
                                        llvm::APSInt &Value,
                                        QualType T) {
  assert(T->isIntegralType() && "Integral type required!");
  unsigned BitWidth = Context.getTypeSize(T);
  
  if (Value.isUnsigned() || Value.isNonNegative())
    return Value.getActiveBits() < BitWidth;
  
  return Value.getMinSignedBits() <= BitWidth;
}

// \brief Given an integral type, return the next larger integral type
// (or a NULL type of no such type exists).
static QualType getNextLargerIntegralType(ASTContext &Context, QualType T) {
  // FIXME: Int128/UInt128 support, which also needs to be introduced into 
  // enum checking below.
  assert(T->isIntegralType() && "Integral type required!");
  const unsigned NumTypes = 4;
  QualType SignedIntegralTypes[NumTypes] = { 
    Context.ShortTy, Context.IntTy, Context.LongTy, Context.LongLongTy
  };
  QualType UnsignedIntegralTypes[NumTypes] = { 
    Context.UnsignedShortTy, Context.UnsignedIntTy, Context.UnsignedLongTy, 
    Context.UnsignedLongLongTy
  };
  
  unsigned BitWidth = Context.getTypeSize(T);
  QualType *Types = T->isSignedIntegerType()? SignedIntegralTypes
                                            : UnsignedIntegralTypes;
  for (unsigned I = 0; I != NumTypes; ++I)
    if (Context.getTypeSize(Types[I]) > BitWidth)
      return Types[I];
  
  return QualType();
}

EnumConstantDecl *Sema::CheckEnumConstant(EnumDecl *Enum,
                                          EnumConstantDecl *LastEnumConst,
                                          SourceLocation IdLoc,
                                          IdentifierInfo *Id,
                                          ExprArg val) {
  Expr *Val = (Expr *)val.get();

  unsigned IntWidth = Context.Target.getIntWidth();
  llvm::APSInt EnumVal(IntWidth);
  QualType EltTy;
  if (Val) {
    if (Enum->isDependentType())
      EltTy = Context.DependentTy;
    else {
      // C99 6.7.2.2p2: Make sure we have an integer constant expression.
      SourceLocation ExpLoc;
      if (VerifyIntegerConstantExpression(Val, &EnumVal)) {
        Val = 0;
      } else {        
        if (!getLangOptions().CPlusPlus) {
          // C99 6.7.2.2p2:
          //   The expression that defines the value of an enumeration constant
          //   shall be an integer constant expression that has a value 
          //   representable as an int.
          
          // Complain if the value is not representable in an int.
          if (!isRepresentableIntegerValue(Context, EnumVal, Context.IntTy))
            Diag(IdLoc, diag::ext_enum_value_not_int)
              << EnumVal.toString(10) << Val->getSourceRange()
              << (EnumVal.isUnsigned() || EnumVal.isNonNegative());
          else if (!Context.hasSameType(Val->getType(), Context.IntTy)) {
            // Force the type of the expression to 'int'.
            ImpCastExprToType(Val, Context.IntTy, CastExpr::CK_IntegralCast);
            
            if (Val != val.get()) {
              val.release();
              val = Val;
            }
          }
        }
        
        // C++0x [dcl.enum]p5:
        //   If the underlying type is not fixed, the type of each enumerator
        //   is the type of its initializing value:
        //     - If an initializer is specified for an enumerator, the 
        //       initializing value has the same type as the expression.
        EltTy = Val->getType();
      }
    }
  }

  if (!Val) {
    if (Enum->isDependentType())
      EltTy = Context.DependentTy;
    else if (!LastEnumConst) {
      // C++0x [dcl.enum]p5:
      //   If the underlying type is not fixed, the type of each enumerator
      //   is the type of its initializing value:
      //     - If no initializer is specified for the first enumerator, the 
      //       initializing value has an unspecified integral type.
      //
      // GCC uses 'int' for its unspecified integral type, as does 
      // C99 6.7.2.2p3.
      EltTy = Context.IntTy;
    } else {
      // Assign the last value + 1.
      EnumVal = LastEnumConst->getInitVal();
      ++EnumVal;
      EltTy = LastEnumConst->getType();

      // Check for overflow on increment.
      if (EnumVal < LastEnumConst->getInitVal()) {
        // C++0x [dcl.enum]p5:
        //   If the underlying type is not fixed, the type of each enumerator
        //   is the type of its initializing value:
        //
        //     - Otherwise the type of the initializing value is the same as
        //       the type of the initializing value of the preceding enumerator
        //       unless the incremented value is not representable in that type,
        //       in which case the type is an unspecified integral type 
        //       sufficient to contain the incremented value. If no such type
        //       exists, the program is ill-formed.
        QualType T = getNextLargerIntegralType(Context, EltTy);
        if (T.isNull()) {
          // There is no integral type larger enough to represent this 
          // value. Complain, then allow the value to wrap around.
          EnumVal = LastEnumConst->getInitVal();
          EnumVal.zext(EnumVal.getBitWidth() * 2);
          Diag(IdLoc, diag::warn_enumerator_too_large)
            << EnumVal.toString(10);
        } else {
          EltTy = T;
        }
        
        // Retrieve the last enumerator's value, extent that type to the
        // type that is supposed to be large enough to represent the incremented
        // value, then increment.
        EnumVal = LastEnumConst->getInitVal();
        EnumVal.setIsSigned(EltTy->isSignedIntegerType());
        EnumVal.zextOrTrunc(Context.getTypeSize(EltTy));
        ++EnumVal;        
        
        // If we're not in C++, diagnose the overflow of enumerator values,
        // which in C99 means that the enumerator value is not representable in
        // an int (C99 6.7.2.2p2). However, we support GCC's extension that
        // permits enumerator values that are representable in some larger
        // integral type.
        if (!getLangOptions().CPlusPlus && !T.isNull())
          Diag(IdLoc, diag::warn_enum_value_overflow);
      } else if (!getLangOptions().CPlusPlus &&
                 !isRepresentableIntegerValue(Context, EnumVal, EltTy)) {
        // Enforce C99 6.7.2.2p2 even when we compute the next value.
        Diag(IdLoc, diag::ext_enum_value_not_int)
          << EnumVal.toString(10) << 1;
      }
    }
  }

  if (!Enum->isDependentType()) {
    // Make the enumerator value match the signedness and size of the 
    // enumerator's type.
    EnumVal.zextOrTrunc(Context.getTypeSize(EltTy));
    EnumVal.setIsSigned(EltTy->isSignedIntegerType());
  }
  
  val.release();
  return EnumConstantDecl::Create(Context, Enum, IdLoc, Id, EltTy,
                                  Val, EnumVal);
}


Sema::DeclPtrTy Sema::ActOnEnumConstant(Scope *S, DeclPtrTy theEnumDecl,
                                        DeclPtrTy lastEnumConst,
                                        SourceLocation IdLoc,
                                        IdentifierInfo *Id,
                                        SourceLocation EqualLoc, ExprTy *val) {
  EnumDecl *TheEnumDecl = cast<EnumDecl>(theEnumDecl.getAs<Decl>());
  EnumConstantDecl *LastEnumConst =
    cast_or_null<EnumConstantDecl>(lastEnumConst.getAs<Decl>());
  Expr *Val = static_cast<Expr*>(val);

  // The scope passed in may not be a decl scope.  Zip up the scope tree until
  // we find one that is.
  S = getNonFieldDeclScope(S);

  // Verify that there isn't already something declared with this name in this
  // scope.
  NamedDecl *PrevDecl = LookupSingleName(S, Id, LookupOrdinaryName,
                                         ForRedeclaration);
  if (PrevDecl && PrevDecl->isTemplateParameter()) {
    // Maybe we will complain about the shadowed template parameter.
    DiagnoseTemplateParameterShadow(IdLoc, PrevDecl);
    // Just pretend that we didn't see the previous declaration.
    PrevDecl = 0;
  }

  if (PrevDecl) {
    // When in C++, we may get a TagDecl with the same name; in this case the
    // enum constant will 'hide' the tag.
    assert((getLangOptions().CPlusPlus || !isa<TagDecl>(PrevDecl)) &&
           "Received TagDecl when not in C++!");
    if (!isa<TagDecl>(PrevDecl) && isDeclInScope(PrevDecl, CurContext, S)) {
      if (isa<EnumConstantDecl>(PrevDecl))
        Diag(IdLoc, diag::err_redefinition_of_enumerator) << Id;
      else
        Diag(IdLoc, diag::err_redefinition) << Id;
      Diag(PrevDecl->getLocation(), diag::note_previous_definition);
      if (Val) Val->Destroy(Context);
      return DeclPtrTy();
    }
  }

  EnumConstantDecl *New = CheckEnumConstant(TheEnumDecl, LastEnumConst,
                                            IdLoc, Id, Owned(Val));

  // Register this decl in the current scope stack.
  if (New) {
    New->setAccess(TheEnumDecl->getAccess());
    PushOnScopeChains(New, S);
  }

  return DeclPtrTy::make(New);
}

void Sema::ActOnEnumBody(SourceLocation EnumLoc, SourceLocation LBraceLoc,
                         SourceLocation RBraceLoc, DeclPtrTy EnumDeclX,
                         DeclPtrTy *Elements, unsigned NumElements,
                         Scope *S, AttributeList *Attr) {
  EnumDecl *Enum = cast<EnumDecl>(EnumDeclX.getAs<Decl>());
  QualType EnumType = Context.getTypeDeclType(Enum);

  if (Attr)
    ProcessDeclAttributeList(S, Enum, Attr);

  if (Enum->isDependentType()) {
    for (unsigned i = 0; i != NumElements; ++i) {
      EnumConstantDecl *ECD =
        cast_or_null<EnumConstantDecl>(Elements[i].getAs<Decl>());
      if (!ECD) continue;

      ECD->setType(EnumType);
    }

    Enum->completeDefinition(Context.DependentTy, Context.DependentTy);
    return;
  }

  // TODO: If the result value doesn't fit in an int, it must be a long or long
  // long value.  ISO C does not support this, but GCC does as an extension,
  // emit a warning.
  unsigned IntWidth = Context.Target.getIntWidth();
  unsigned CharWidth = Context.Target.getCharWidth();
  unsigned ShortWidth = Context.Target.getShortWidth();

  // Verify that all the values are okay, compute the size of the values, and
  // reverse the list.
  unsigned NumNegativeBits = 0;
  unsigned NumPositiveBits = 0;

  // Keep track of whether all elements have type int.
  bool AllElementsInt = true;

  for (unsigned i = 0; i != NumElements; ++i) {
    EnumConstantDecl *ECD =
      cast_or_null<EnumConstantDecl>(Elements[i].getAs<Decl>());
    if (!ECD) continue;  // Already issued a diagnostic.

    const llvm::APSInt &InitVal = ECD->getInitVal();

    // Keep track of the size of positive and negative values.
    if (InitVal.isUnsigned() || InitVal.isNonNegative())
      NumPositiveBits = std::max(NumPositiveBits,
                                 (unsigned)InitVal.getActiveBits());
    else
      NumNegativeBits = std::max(NumNegativeBits,
                                 (unsigned)InitVal.getMinSignedBits());

    // Keep track of whether every enum element has type int (very commmon).
    if (AllElementsInt)
      AllElementsInt = ECD->getType() == Context.IntTy;
  }

  // Figure out the type that should be used for this enum.
  // FIXME: Support -fshort-enums.
  QualType BestType;
  unsigned BestWidth;

  // C++0x N3000 [conv.prom]p3:
  //   An rvalue of an unscoped enumeration type whose underlying
  //   type is not fixed can be converted to an rvalue of the first
  //   of the following types that can represent all the values of
  //   the enumeration: int, unsigned int, long int, unsigned long
  //   int, long long int, or unsigned long long int.
  // C99 6.4.4.3p2:
  //   An identifier declared as an enumeration constant has type int.
  // The C99 rule is modified by a gcc extension 
  QualType BestPromotionType;

  bool Packed = Enum->getAttr<PackedAttr>() ? true : false;

  if (NumNegativeBits) {
    // If there is a negative value, figure out the smallest integer type (of
    // int/long/longlong) that fits.
    // If it's packed, check also if it fits a char or a short.
    if (Packed && NumNegativeBits <= CharWidth && NumPositiveBits < CharWidth) {
      BestType = Context.SignedCharTy;
      BestWidth = CharWidth;
    } else if (Packed && NumNegativeBits <= ShortWidth &&
               NumPositiveBits < ShortWidth) {
      BestType = Context.ShortTy;
      BestWidth = ShortWidth;
    } else if (NumNegativeBits <= IntWidth && NumPositiveBits < IntWidth) {
      BestType = Context.IntTy;
      BestWidth = IntWidth;
    } else {
      BestWidth = Context.Target.getLongWidth();

      if (NumNegativeBits <= BestWidth && NumPositiveBits < BestWidth) {
        BestType = Context.LongTy;
      } else {
        BestWidth = Context.Target.getLongLongWidth();

        if (NumNegativeBits > BestWidth || NumPositiveBits >= BestWidth)
          Diag(Enum->getLocation(), diag::warn_enum_too_large);
        BestType = Context.LongLongTy;
      }
    }
    BestPromotionType = (BestWidth <= IntWidth ? Context.IntTy : BestType);
  } else {
    // If there is no negative value, figure out the smallest type that fits
    // all of the enumerator values.
    // If it's packed, check also if it fits a char or a short.
    if (Packed && NumPositiveBits <= CharWidth) {
      BestType = Context.UnsignedCharTy;
      BestPromotionType = Context.IntTy;
      BestWidth = CharWidth;
    } else if (Packed && NumPositiveBits <= ShortWidth) {
      BestType = Context.UnsignedShortTy;
      BestPromotionType = Context.IntTy;
      BestWidth = ShortWidth;
    } else if (NumPositiveBits <= IntWidth) {
      BestType = Context.UnsignedIntTy;
      BestWidth = IntWidth;
      BestPromotionType
        = (NumPositiveBits == BestWidth || !getLangOptions().CPlusPlus)
                           ? Context.UnsignedIntTy : Context.IntTy;
    } else if (NumPositiveBits <=
               (BestWidth = Context.Target.getLongWidth())) {
      BestType = Context.UnsignedLongTy;
      BestPromotionType
        = (NumPositiveBits == BestWidth || !getLangOptions().CPlusPlus)
                           ? Context.UnsignedLongTy : Context.LongTy;
    } else {
      BestWidth = Context.Target.getLongLongWidth();
      assert(NumPositiveBits <= BestWidth &&
             "How could an initializer get larger than ULL?");
      BestType = Context.UnsignedLongLongTy;
      BestPromotionType
        = (NumPositiveBits == BestWidth || !getLangOptions().CPlusPlus)
                           ? Context.UnsignedLongLongTy : Context.LongLongTy;
    }
  }

  // Loop over all of the enumerator constants, changing their types to match
  // the type of the enum if needed.
  for (unsigned i = 0; i != NumElements; ++i) {
    EnumConstantDecl *ECD =
      cast_or_null<EnumConstantDecl>(Elements[i].getAs<Decl>());
    if (!ECD) continue;  // Already issued a diagnostic.

    // Standard C says the enumerators have int type, but we allow, as an
    // extension, the enumerators to be larger than int size.  If each
    // enumerator value fits in an int, type it as an int, otherwise type it the
    // same as the enumerator decl itself.  This means that in "enum { X = 1U }"
    // that X has type 'int', not 'unsigned'.

    // Determine whether the value fits into an int.
    llvm::APSInt InitVal = ECD->getInitVal();

    // If it fits into an integer type, force it.  Otherwise force it to match
    // the enum decl type.
    QualType NewTy;
    unsigned NewWidth;
    bool NewSign;
    if (!getLangOptions().CPlusPlus &&
        isRepresentableIntegerValue(Context, InitVal, Context.IntTy)) {
      NewTy = Context.IntTy;
      NewWidth = IntWidth;
      NewSign = true;
    } else if (ECD->getType() == BestType) {
      // Already the right type!
      if (getLangOptions().CPlusPlus)
        // C++ [dcl.enum]p4: Following the closing brace of an
        // enum-specifier, each enumerator has the type of its
        // enumeration.
        ECD->setType(EnumType);
      continue;
    } else {
      NewTy = BestType;
      NewWidth = BestWidth;
      NewSign = BestType->isSignedIntegerType();
    }

    // Adjust the APSInt value.
    InitVal.extOrTrunc(NewWidth);
    InitVal.setIsSigned(NewSign);
    ECD->setInitVal(InitVal);

    // Adjust the Expr initializer and type.
    if (ECD->getInitExpr())
      ECD->setInitExpr(new (Context) ImplicitCastExpr(NewTy,
                                                      CastExpr::CK_IntegralCast,
                                                      ECD->getInitExpr(),
                                                      /*isLvalue=*/false));
    if (getLangOptions().CPlusPlus)
      // C++ [dcl.enum]p4: Following the closing brace of an
      // enum-specifier, each enumerator has the type of its
      // enumeration.
      ECD->setType(EnumType);
    else
      ECD->setType(NewTy);
  }

  Enum->completeDefinition(BestType, BestPromotionType);
}

Sema::DeclPtrTy Sema::ActOnFileScopeAsmDecl(SourceLocation Loc,
                                            ExprArg expr) {
  StringLiteral *AsmString = cast<StringLiteral>(expr.takeAs<Expr>());

  FileScopeAsmDecl *New = FileScopeAsmDecl::Create(Context, CurContext,
                                                   Loc, AsmString);
  CurContext->addDecl(New);
  return DeclPtrTy::make(New);
}

void Sema::ActOnPragmaWeakID(IdentifierInfo* Name,
                             SourceLocation PragmaLoc,
                             SourceLocation NameLoc) {
  Decl *PrevDecl = LookupSingleName(TUScope, Name, LookupOrdinaryName);

  if (PrevDecl) {
    PrevDecl->addAttr(::new (Context) WeakAttr());
  } else {
    (void)WeakUndeclaredIdentifiers.insert(
      std::pair<IdentifierInfo*,WeakInfo>
        (Name, WeakInfo((IdentifierInfo*)0, NameLoc)));
  }
}

void Sema::ActOnPragmaWeakAlias(IdentifierInfo* Name,
                                IdentifierInfo* AliasName,
                                SourceLocation PragmaLoc,
                                SourceLocation NameLoc,
                                SourceLocation AliasNameLoc) {
  Decl *PrevDecl = LookupSingleName(TUScope, AliasName, LookupOrdinaryName);
  WeakInfo W = WeakInfo(Name, NameLoc);

  if (PrevDecl) {
    if (!PrevDecl->hasAttr<AliasAttr>())
      if (NamedDecl *ND = dyn_cast<NamedDecl>(PrevDecl))
        DeclApplyPragmaWeak(TUScope, ND, W);
  } else {
    (void)WeakUndeclaredIdentifiers.insert(
      std::pair<IdentifierInfo*,WeakInfo>(AliasName, W));
  }
}
