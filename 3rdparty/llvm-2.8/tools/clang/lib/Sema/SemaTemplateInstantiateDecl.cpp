//===--- SemaTemplateInstantiateDecl.cpp - C++ Template Decl Instantiation ===/
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//===----------------------------------------------------------------------===/
//
//  This file implements C++ template instantiation for declarations.
//
//===----------------------------------------------------------------------===/
#include "clang/Sema/SemaInternal.h"
#include "clang/Sema/Lookup.h"
#include "clang/Sema/PrettyDeclStackTrace.h"
#include "clang/Sema/Template.h"
#include "clang/AST/ASTConsumer.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/DeclTemplate.h"
#include "clang/AST/DeclVisitor.h"
#include "clang/AST/DependentDiagnostic.h"
#include "clang/AST/Expr.h"
#include "clang/AST/ExprCXX.h"
#include "clang/AST/TypeLoc.h"
#include "clang/Lex/Preprocessor.h"

using namespace clang;

namespace {
  class TemplateDeclInstantiator
    : public DeclVisitor<TemplateDeclInstantiator, Decl *> {
    Sema &SemaRef;
    DeclContext *Owner;
    const MultiLevelTemplateArgumentList &TemplateArgs;

  public:
    TemplateDeclInstantiator(Sema &SemaRef, DeclContext *Owner,
                             const MultiLevelTemplateArgumentList &TemplateArgs)
      : SemaRef(SemaRef), Owner(Owner), TemplateArgs(TemplateArgs) { }

    // FIXME: Once we get closer to completion, replace these manually-written
    // declarations with automatically-generated ones from
    // clang/AST/DeclNodes.inc.
    Decl *VisitTranslationUnitDecl(TranslationUnitDecl *D);
    Decl *VisitNamespaceDecl(NamespaceDecl *D);
    Decl *VisitNamespaceAliasDecl(NamespaceAliasDecl *D);
    Decl *VisitTypedefDecl(TypedefDecl *D);
    Decl *VisitVarDecl(VarDecl *D);
    Decl *VisitAccessSpecDecl(AccessSpecDecl *D);
    Decl *VisitFieldDecl(FieldDecl *D);
    Decl *VisitStaticAssertDecl(StaticAssertDecl *D);
    Decl *VisitEnumDecl(EnumDecl *D);
    Decl *VisitEnumConstantDecl(EnumConstantDecl *D);
    Decl *VisitFriendDecl(FriendDecl *D);
    Decl *VisitFunctionDecl(FunctionDecl *D,
                            TemplateParameterList *TemplateParams = 0);
    Decl *VisitCXXRecordDecl(CXXRecordDecl *D);
    Decl *VisitCXXMethodDecl(CXXMethodDecl *D,
                             TemplateParameterList *TemplateParams = 0);
    Decl *VisitCXXConstructorDecl(CXXConstructorDecl *D);
    Decl *VisitCXXDestructorDecl(CXXDestructorDecl *D);
    Decl *VisitCXXConversionDecl(CXXConversionDecl *D);
    ParmVarDecl *VisitParmVarDecl(ParmVarDecl *D);
    Decl *VisitClassTemplateDecl(ClassTemplateDecl *D);
    Decl *VisitClassTemplatePartialSpecializationDecl(
                                    ClassTemplatePartialSpecializationDecl *D);
    Decl *VisitFunctionTemplateDecl(FunctionTemplateDecl *D);
    Decl *VisitTemplateTypeParmDecl(TemplateTypeParmDecl *D);
    Decl *VisitNonTypeTemplateParmDecl(NonTypeTemplateParmDecl *D);
    Decl *VisitTemplateTemplateParmDecl(TemplateTemplateParmDecl *D);
    Decl *VisitUsingDirectiveDecl(UsingDirectiveDecl *D);
    Decl *VisitUsingDecl(UsingDecl *D);
    Decl *VisitUsingShadowDecl(UsingShadowDecl *D);
    Decl *VisitUnresolvedUsingValueDecl(UnresolvedUsingValueDecl *D);
    Decl *VisitUnresolvedUsingTypenameDecl(UnresolvedUsingTypenameDecl *D);

    // Base case. FIXME: Remove once we can instantiate everything.
    Decl *VisitDecl(Decl *D) {
      unsigned DiagID = SemaRef.getDiagnostics().getCustomDiagID(
                                                            Diagnostic::Error,
                                                   "cannot instantiate %0 yet");
      SemaRef.Diag(D->getLocation(), DiagID)
        << D->getDeclKindName();
      
      return 0;
    }

    // Helper functions for instantiating methods.
    TypeSourceInfo *SubstFunctionType(FunctionDecl *D,
                             llvm::SmallVectorImpl<ParmVarDecl *> &Params);
    bool InitFunctionInstantiation(FunctionDecl *New, FunctionDecl *Tmpl);
    bool InitMethodInstantiation(CXXMethodDecl *New, CXXMethodDecl *Tmpl);

    TemplateParameterList *
      SubstTemplateParams(TemplateParameterList *List);

    bool SubstQualifier(const DeclaratorDecl *OldDecl,
                        DeclaratorDecl *NewDecl);
    bool SubstQualifier(const TagDecl *OldDecl,
                        TagDecl *NewDecl);
      
    bool InstantiateClassTemplatePartialSpecialization(
                                              ClassTemplateDecl *ClassTemplate,
                           ClassTemplatePartialSpecializationDecl *PartialSpec);
  };
}

bool TemplateDeclInstantiator::SubstQualifier(const DeclaratorDecl *OldDecl,
                                              DeclaratorDecl *NewDecl) {
  NestedNameSpecifier *OldQual = OldDecl->getQualifier();
  if (!OldQual) return false;

  SourceRange QualRange = OldDecl->getQualifierRange();

  NestedNameSpecifier *NewQual
    = SemaRef.SubstNestedNameSpecifier(OldQual, QualRange, TemplateArgs);
  if (!NewQual)
    return true;

  NewDecl->setQualifierInfo(NewQual, QualRange);
  return false;
}

bool TemplateDeclInstantiator::SubstQualifier(const TagDecl *OldDecl,
                                              TagDecl *NewDecl) {
  NestedNameSpecifier *OldQual = OldDecl->getQualifier();
  if (!OldQual) return false;

  SourceRange QualRange = OldDecl->getQualifierRange();

  NestedNameSpecifier *NewQual
    = SemaRef.SubstNestedNameSpecifier(OldQual, QualRange, TemplateArgs);
  if (!NewQual)
    return true;

  NewDecl->setQualifierInfo(NewQual, QualRange);
  return false;
}

// FIXME: Is this still too simple?
void Sema::InstantiateAttrs(const MultiLevelTemplateArgumentList &TemplateArgs,
                            Decl *Tmpl, Decl *New) {
  for (AttrVec::const_iterator i = Tmpl->attr_begin(), e = Tmpl->attr_end();
       i != e; ++i) {
    const Attr *TmplAttr = *i;
    // FIXME: This should be generalized to more than just the AlignedAttr.
    if (const AlignedAttr *Aligned = dyn_cast<AlignedAttr>(TmplAttr)) {
      if (Aligned->isAlignmentDependent()) {
        // The alignment expression is not potentially evaluated.
        EnterExpressionEvaluationContext Unevaluated(*this,
                                                     Sema::Unevaluated);

        if (Aligned->isAlignmentExpr()) {
          ExprResult Result = SubstExpr(Aligned->getAlignmentExpr(),
                                              TemplateArgs);
          if (!Result.isInvalid())
            AddAlignedAttr(Aligned->getLocation(), New, Result.takeAs<Expr>());
        }
        else {
          TypeSourceInfo *Result = SubstType(Aligned->getAlignmentType(),
                                              TemplateArgs,
                                              Aligned->getLocation(), 
                                              DeclarationName());
          if (Result)
            AddAlignedAttr(Aligned->getLocation(), New, Result);
        }
        continue;
      }
    }

    // FIXME: Is cloning correct for all attributes?
    Attr *NewAttr = TmplAttr->clone(Context);
    New->addAttr(NewAttr);
  }
}

Decl *
TemplateDeclInstantiator::VisitTranslationUnitDecl(TranslationUnitDecl *D) {
  assert(false && "Translation units cannot be instantiated");
  return D;
}

Decl *
TemplateDeclInstantiator::VisitNamespaceDecl(NamespaceDecl *D) {
  assert(false && "Namespaces cannot be instantiated");
  return D;
}

Decl *
TemplateDeclInstantiator::VisitNamespaceAliasDecl(NamespaceAliasDecl *D) {
  NamespaceAliasDecl *Inst
    = NamespaceAliasDecl::Create(SemaRef.Context, Owner,
                                 D->getNamespaceLoc(),
                                 D->getAliasLoc(),
                                 D->getNamespace()->getIdentifier(),
                                 D->getQualifierRange(),
                                 D->getQualifier(),
                                 D->getTargetNameLoc(),
                                 D->getNamespace());
  Owner->addDecl(Inst);
  return Inst;
}

Decl *TemplateDeclInstantiator::VisitTypedefDecl(TypedefDecl *D) {
  bool Invalid = false;
  TypeSourceInfo *DI = D->getTypeSourceInfo();
  if (DI->getType()->isDependentType() ||
      DI->getType()->isVariablyModifiedType()) {
    DI = SemaRef.SubstType(DI, TemplateArgs,
                           D->getLocation(), D->getDeclName());
    if (!DI) {
      Invalid = true;
      DI = SemaRef.Context.getTrivialTypeSourceInfo(SemaRef.Context.IntTy);
    }
  } else {
    SemaRef.MarkDeclarationsReferencedInType(D->getLocation(), DI->getType());
  }

  // Create the new typedef
  TypedefDecl *Typedef
    = TypedefDecl::Create(SemaRef.Context, Owner, D->getLocation(),
                          D->getIdentifier(), DI);
  if (Invalid)
    Typedef->setInvalidDecl();

  if (const TagType *TT = DI->getType()->getAs<TagType>()) {
    TagDecl *TD = TT->getDecl();
    
    // If the TagDecl that the TypedefDecl points to is an anonymous decl
    // keep track of the TypedefDecl.
    if (!TD->getIdentifier() && !TD->getTypedefForAnonDecl())
      TD->setTypedefForAnonDecl(Typedef);
  }
  
  if (TypedefDecl *Prev = D->getPreviousDeclaration()) {
    NamedDecl *InstPrev = SemaRef.FindInstantiatedDecl(D->getLocation(), Prev,
                                                       TemplateArgs);
    Typedef->setPreviousDeclaration(cast<TypedefDecl>(InstPrev));
  }

  SemaRef.InstantiateAttrs(TemplateArgs, D, Typedef);

  Typedef->setAccess(D->getAccess());
  Owner->addDecl(Typedef);

  return Typedef;
}

/// \brief Instantiate the arguments provided as part of initialization.
///
/// \returns true if an error occurred, false otherwise.
static bool InstantiateInitializationArguments(Sema &SemaRef,
                                               Expr **Args, unsigned NumArgs,
                           const MultiLevelTemplateArgumentList &TemplateArgs,
                         llvm::SmallVectorImpl<SourceLocation> &FakeCommaLocs,
                           ASTOwningVector<Expr*> &InitArgs) {
  for (unsigned I = 0; I != NumArgs; ++I) {
    // When we hit the first defaulted argument, break out of the loop:
    // we don't pass those default arguments on.
    if (Args[I]->isDefaultArgument())
      break;
  
    ExprResult Arg = SemaRef.SubstExpr(Args[I], TemplateArgs);
    if (Arg.isInvalid())
      return true;
  
    Expr *ArgExpr = (Expr *)Arg.get();
    InitArgs.push_back(Arg.release());
    
    // FIXME: We're faking all of the comma locations. Do we need them?
    FakeCommaLocs.push_back(
                          SemaRef.PP.getLocForEndOfToken(ArgExpr->getLocEnd()));
  }
  
  return false;
}

/// \brief Instantiate an initializer, breaking it into separate
/// initialization arguments.
///
/// \param S The semantic analysis object.
///
/// \param Init The initializer to instantiate.
///
/// \param TemplateArgs Template arguments to be substituted into the
/// initializer.
///
/// \param NewArgs Will be filled in with the instantiation arguments.
///
/// \returns true if an error occurred, false otherwise
static bool InstantiateInitializer(Sema &S, Expr *Init,
                            const MultiLevelTemplateArgumentList &TemplateArgs,
                                   SourceLocation &LParenLoc,
                               llvm::SmallVector<SourceLocation, 4> &CommaLocs,
                             ASTOwningVector<Expr*> &NewArgs,
                                   SourceLocation &RParenLoc) {
  NewArgs.clear();
  LParenLoc = SourceLocation();
  RParenLoc = SourceLocation();

  if (!Init)
    return false;

  if (CXXExprWithTemporaries *ExprTemp = dyn_cast<CXXExprWithTemporaries>(Init))
    Init = ExprTemp->getSubExpr();

  while (CXXBindTemporaryExpr *Binder = dyn_cast<CXXBindTemporaryExpr>(Init))
    Init = Binder->getSubExpr();

  if (ImplicitCastExpr *ICE = dyn_cast<ImplicitCastExpr>(Init))
    Init = ICE->getSubExprAsWritten();

  if (ParenListExpr *ParenList = dyn_cast<ParenListExpr>(Init)) {
    LParenLoc = ParenList->getLParenLoc();
    RParenLoc = ParenList->getRParenLoc();
    return InstantiateInitializationArguments(S, ParenList->getExprs(),
                                              ParenList->getNumExprs(),
                                              TemplateArgs, CommaLocs, 
                                              NewArgs);
  }

  if (CXXConstructExpr *Construct = dyn_cast<CXXConstructExpr>(Init)) {
    if (!isa<CXXTemporaryObjectExpr>(Construct)) {
      if (InstantiateInitializationArguments(S,
                                             Construct->getArgs(),
                                             Construct->getNumArgs(),
                                             TemplateArgs,
                                             CommaLocs, NewArgs))
        return true;

      // FIXME: Fake locations!
      LParenLoc = S.PP.getLocForEndOfToken(Init->getLocStart());
      RParenLoc = CommaLocs.empty()? LParenLoc : CommaLocs.back();
      return false;
    }
  }
 
  ExprResult Result = S.SubstExpr(Init, TemplateArgs);
  if (Result.isInvalid())
    return true;

  NewArgs.push_back(Result.takeAs<Expr>());
  return false;
}

Decl *TemplateDeclInstantiator::VisitVarDecl(VarDecl *D) {
  // If this is the variable for an anonymous struct or union,
  // instantiate the anonymous struct/union type first.
  if (const RecordType *RecordTy = D->getType()->getAs<RecordType>())
    if (RecordTy->getDecl()->isAnonymousStructOrUnion())
      if (!VisitCXXRecordDecl(cast<CXXRecordDecl>(RecordTy->getDecl())))
        return 0;

  // Do substitution on the type of the declaration
  TypeSourceInfo *DI = SemaRef.SubstType(D->getTypeSourceInfo(),
                                         TemplateArgs,
                                         D->getTypeSpecStartLoc(),
                                         D->getDeclName());
  if (!DI)
    return 0;

  // Build the instantiated declaration
  VarDecl *Var = VarDecl::Create(SemaRef.Context, Owner,
                                 D->getLocation(), D->getIdentifier(),
                                 DI->getType(), DI,
                                 D->getStorageClass(),
                                 D->getStorageClassAsWritten());
  Var->setThreadSpecified(D->isThreadSpecified());
  Var->setCXXDirectInitializer(D->hasCXXDirectInitializer());

  // Substitute the nested name specifier, if any.
  if (SubstQualifier(D, Var))
    return 0;

  // If we are instantiating a static data member defined
  // out-of-line, the instantiation will have the same lexical
  // context (which will be a namespace scope) as the template.
  if (D->isOutOfLine())
    Var->setLexicalDeclContext(D->getLexicalDeclContext());

  Var->setAccess(D->getAccess());
  
  if (!D->isStaticDataMember())
    Var->setUsed(D->isUsed(false));
  
  // FIXME: In theory, we could have a previous declaration for variables that
  // are not static data members.
  bool Redeclaration = false;
  // FIXME: having to fake up a LookupResult is dumb.
  LookupResult Previous(SemaRef, Var->getDeclName(), Var->getLocation(),
                        Sema::LookupOrdinaryName, Sema::ForRedeclaration);
  if (D->isStaticDataMember())
    SemaRef.LookupQualifiedName(Previous, Owner, false);
  SemaRef.CheckVariableDeclaration(Var, Previous, Redeclaration);

  if (D->isOutOfLine()) {
    if (!D->isStaticDataMember())
      D->getLexicalDeclContext()->addDecl(Var);
    Owner->makeDeclVisibleInContext(Var);
  } else {
    Owner->addDecl(Var);
    if (Owner->isFunctionOrMethod())
      SemaRef.CurrentInstantiationScope->InstantiatedLocal(D, Var);
  }
  SemaRef.InstantiateAttrs(TemplateArgs, D, Var);
  
  // Link instantiations of static data members back to the template from
  // which they were instantiated.
  if (Var->isStaticDataMember())
    SemaRef.Context.setInstantiatedFromStaticDataMember(Var, D, 
                                                     TSK_ImplicitInstantiation);
  
  if (Var->getAnyInitializer()) {
    // We already have an initializer in the class.
  } else if (D->getInit()) {
    if (Var->isStaticDataMember() && !D->isOutOfLine())
      SemaRef.PushExpressionEvaluationContext(Sema::Unevaluated);
    else
      SemaRef.PushExpressionEvaluationContext(Sema::PotentiallyEvaluated);

    // Instantiate the initializer.
    SourceLocation LParenLoc, RParenLoc;
    llvm::SmallVector<SourceLocation, 4> CommaLocs;
    ASTOwningVector<Expr*> InitArgs(SemaRef);
    if (!InstantiateInitializer(SemaRef, D->getInit(), TemplateArgs, LParenLoc,
                                CommaLocs, InitArgs, RParenLoc)) {
      // Attach the initializer to the declaration.
      if (D->hasCXXDirectInitializer()) {
        // Add the direct initializer to the declaration.
        SemaRef.AddCXXDirectInitializerToDecl(Var,
                                              LParenLoc,
                                              move_arg(InitArgs),
                                              CommaLocs.data(),
                                              RParenLoc);
      } else if (InitArgs.size() == 1) {
        Expr *Init = InitArgs.take()[0];
        SemaRef.AddInitializerToDecl(Var, Init, false);
      } else {
        assert(InitArgs.size() == 0);
        SemaRef.ActOnUninitializedDecl(Var, false);    
      }
    } else {
      // FIXME: Not too happy about invalidating the declaration
      // because of a bogus initializer.
      Var->setInvalidDecl();
    }
    
    SemaRef.PopExpressionEvaluationContext();
  } else if (!Var->isStaticDataMember() || Var->isOutOfLine())
    SemaRef.ActOnUninitializedDecl(Var, false);

  // Diagnose unused local variables.
  if (!Var->isInvalidDecl() && Owner->isFunctionOrMethod() && !Var->isUsed())
    SemaRef.DiagnoseUnusedDecl(Var);

  return Var;
}

Decl *TemplateDeclInstantiator::VisitAccessSpecDecl(AccessSpecDecl *D) {
  AccessSpecDecl* AD
    = AccessSpecDecl::Create(SemaRef.Context, D->getAccess(), Owner,
                             D->getAccessSpecifierLoc(), D->getColonLoc());
  Owner->addHiddenDecl(AD);
  return AD;
}

Decl *TemplateDeclInstantiator::VisitFieldDecl(FieldDecl *D) {
  bool Invalid = false;
  TypeSourceInfo *DI = D->getTypeSourceInfo();
  if (DI->getType()->isDependentType() ||
      DI->getType()->isVariablyModifiedType())  {
    DI = SemaRef.SubstType(DI, TemplateArgs,
                           D->getLocation(), D->getDeclName());
    if (!DI) {
      DI = D->getTypeSourceInfo();
      Invalid = true;
    } else if (DI->getType()->isFunctionType()) {
      // C++ [temp.arg.type]p3:
      //   If a declaration acquires a function type through a type
      //   dependent on a template-parameter and this causes a
      //   declaration that does not use the syntactic form of a
      //   function declarator to have function type, the program is
      //   ill-formed.
      SemaRef.Diag(D->getLocation(), diag::err_field_instantiates_to_function)
        << DI->getType();
      Invalid = true;
    }
  } else {
    SemaRef.MarkDeclarationsReferencedInType(D->getLocation(), DI->getType());
  }

  Expr *BitWidth = D->getBitWidth();
  if (Invalid)
    BitWidth = 0;
  else if (BitWidth) {
    // The bit-width expression is not potentially evaluated.
    EnterExpressionEvaluationContext Unevaluated(SemaRef, Sema::Unevaluated);

    ExprResult InstantiatedBitWidth
      = SemaRef.SubstExpr(BitWidth, TemplateArgs);
    if (InstantiatedBitWidth.isInvalid()) {
      Invalid = true;
      BitWidth = 0;
    } else
      BitWidth = InstantiatedBitWidth.takeAs<Expr>();
  }

  FieldDecl *Field = SemaRef.CheckFieldDecl(D->getDeclName(),
                                            DI->getType(), DI,
                                            cast<RecordDecl>(Owner),
                                            D->getLocation(),
                                            D->isMutable(),
                                            BitWidth,
                                            D->getTypeSpecStartLoc(),
                                            D->getAccess(),
                                            0);
  if (!Field) {
    cast<Decl>(Owner)->setInvalidDecl();
    return 0;
  }

  SemaRef.InstantiateAttrs(TemplateArgs, D, Field);
  
  if (Invalid)
    Field->setInvalidDecl();

  if (!Field->getDeclName()) {
    // Keep track of where this decl came from.
    SemaRef.Context.setInstantiatedFromUnnamedFieldDecl(Field, D);
  } 
  if (CXXRecordDecl *Parent= dyn_cast<CXXRecordDecl>(Field->getDeclContext())) {
    if (Parent->isAnonymousStructOrUnion() &&
        Parent->getRedeclContext()->isFunctionOrMethod())
      SemaRef.CurrentInstantiationScope->InstantiatedLocal(D, Field);
  }

  Field->setImplicit(D->isImplicit());
  Field->setAccess(D->getAccess());
  Owner->addDecl(Field);

  return Field;
}

Decl *TemplateDeclInstantiator::VisitFriendDecl(FriendDecl *D) {
  // Handle friend type expressions by simply substituting template
  // parameters into the pattern type and checking the result.
  if (TypeSourceInfo *Ty = D->getFriendType()) {
    TypeSourceInfo *InstTy = 
      SemaRef.SubstType(Ty, TemplateArgs,
                        D->getLocation(), DeclarationName());
    if (!InstTy) 
      return 0;

    FriendDecl *FD = SemaRef.CheckFriendTypeDecl(D->getFriendLoc(), InstTy);
    if (!FD)
      return 0;
    
    FD->setAccess(AS_public);
    Owner->addDecl(FD);
    return FD;
  } 
  
  NamedDecl *ND = D->getFriendDecl();
  assert(ND && "friend decl must be a decl or a type!");

  // All of the Visit implementations for the various potential friend
  // declarations have to be carefully written to work for friend
  // objects, with the most important detail being that the target
  // decl should almost certainly not be placed in Owner.
  Decl *NewND = Visit(ND);
  if (!NewND) return 0;

  FriendDecl *FD =
    FriendDecl::Create(SemaRef.Context, Owner, D->getLocation(), 
                       cast<NamedDecl>(NewND), D->getFriendLoc());
  FD->setAccess(AS_public);
  Owner->addDecl(FD);
  return FD;
}

Decl *TemplateDeclInstantiator::VisitStaticAssertDecl(StaticAssertDecl *D) {
  Expr *AssertExpr = D->getAssertExpr();

  // The expression in a static assertion is not potentially evaluated.
  EnterExpressionEvaluationContext Unevaluated(SemaRef, Sema::Unevaluated);

  ExprResult InstantiatedAssertExpr
    = SemaRef.SubstExpr(AssertExpr, TemplateArgs);
  if (InstantiatedAssertExpr.isInvalid())
    return 0;

  ExprResult Message(D->getMessage());
  D->getMessage()->Retain();
  return SemaRef.ActOnStaticAssertDeclaration(D->getLocation(),
                                              InstantiatedAssertExpr.get(),
                                              Message.get());
}

Decl *TemplateDeclInstantiator::VisitEnumDecl(EnumDecl *D) {
  EnumDecl *Enum = EnumDecl::Create(SemaRef.Context, Owner,
                                    D->getLocation(), D->getIdentifier(),
                                    D->getTagKeywordLoc(),
                                    /*PrevDecl=*/0);
  Enum->setInstantiationOfMemberEnum(D);
  Enum->setAccess(D->getAccess());
  if (SubstQualifier(D, Enum)) return 0;
  Owner->addDecl(Enum);
  Enum->startDefinition();

  if (D->getDeclContext()->isFunctionOrMethod())
    SemaRef.CurrentInstantiationScope->InstantiatedLocal(D, Enum);
    
  llvm::SmallVector<Decl*, 4> Enumerators;

  EnumConstantDecl *LastEnumConst = 0;
  for (EnumDecl::enumerator_iterator EC = D->enumerator_begin(),
         ECEnd = D->enumerator_end();
       EC != ECEnd; ++EC) {
    // The specified value for the enumerator.
    ExprResult Value = SemaRef.Owned((Expr *)0);
    if (Expr *UninstValue = EC->getInitExpr()) {
      // The enumerator's value expression is not potentially evaluated.
      EnterExpressionEvaluationContext Unevaluated(SemaRef,
                                                   Sema::Unevaluated);

      Value = SemaRef.SubstExpr(UninstValue, TemplateArgs);
    }

    // Drop the initial value and continue.
    bool isInvalid = false;
    if (Value.isInvalid()) {
      Value = SemaRef.Owned((Expr *)0);
      isInvalid = true;
    }

    EnumConstantDecl *EnumConst
      = SemaRef.CheckEnumConstant(Enum, LastEnumConst,
                                  EC->getLocation(), EC->getIdentifier(),
                                  Value.get());

    if (isInvalid) {
      if (EnumConst)
        EnumConst->setInvalidDecl();
      Enum->setInvalidDecl();
    }

    if (EnumConst) {
      EnumConst->setAccess(Enum->getAccess());
      Enum->addDecl(EnumConst);
      Enumerators.push_back(EnumConst);
      LastEnumConst = EnumConst;
      
      if (D->getDeclContext()->isFunctionOrMethod()) {
        // If the enumeration is within a function or method, record the enum
        // constant as a local.
        SemaRef.CurrentInstantiationScope->InstantiatedLocal(*EC, EnumConst);
      }
    }
  }

  // FIXME: Fixup LBraceLoc and RBraceLoc
  // FIXME: Empty Scope and AttributeList (required to handle attribute packed).
  SemaRef.ActOnEnumBody(Enum->getLocation(), SourceLocation(), SourceLocation(),
                        Enum,
                        Enumerators.data(), Enumerators.size(),
                        0, 0);

  return Enum;
}

Decl *TemplateDeclInstantiator::VisitEnumConstantDecl(EnumConstantDecl *D) {
  assert(false && "EnumConstantDecls can only occur within EnumDecls.");
  return 0;
}

Decl *TemplateDeclInstantiator::VisitClassTemplateDecl(ClassTemplateDecl *D) {
  bool isFriend = (D->getFriendObjectKind() != Decl::FOK_None);

  // Create a local instantiation scope for this class template, which
  // will contain the instantiations of the template parameters.
  LocalInstantiationScope Scope(SemaRef);
  TemplateParameterList *TempParams = D->getTemplateParameters();
  TemplateParameterList *InstParams = SubstTemplateParams(TempParams);
  if (!InstParams)
    return NULL;

  CXXRecordDecl *Pattern = D->getTemplatedDecl();

  // Instantiate the qualifier.  We have to do this first in case
  // we're a friend declaration, because if we are then we need to put
  // the new declaration in the appropriate context.
  NestedNameSpecifier *Qualifier = Pattern->getQualifier();
  if (Qualifier) {
    Qualifier = SemaRef.SubstNestedNameSpecifier(Qualifier,
                                                 Pattern->getQualifierRange(),
                                                 TemplateArgs);
    if (!Qualifier) return 0;
  }

  CXXRecordDecl *PrevDecl = 0;
  ClassTemplateDecl *PrevClassTemplate = 0;

  // If this isn't a friend, then it's a member template, in which
  // case we just want to build the instantiation in the
  // specialization.  If it is a friend, we want to build it in
  // the appropriate context.
  DeclContext *DC = Owner;
  if (isFriend) {
    if (Qualifier) {
      CXXScopeSpec SS;
      SS.setScopeRep(Qualifier);
      SS.setRange(Pattern->getQualifierRange());
      DC = SemaRef.computeDeclContext(SS);
      if (!DC) return 0;
    } else {
      DC = SemaRef.FindInstantiatedContext(Pattern->getLocation(),
                                           Pattern->getDeclContext(),
                                           TemplateArgs);
    }

    // Look for a previous declaration of the template in the owning
    // context.
    LookupResult R(SemaRef, Pattern->getDeclName(), Pattern->getLocation(),
                   Sema::LookupOrdinaryName, Sema::ForRedeclaration);
    SemaRef.LookupQualifiedName(R, DC);

    if (R.isSingleResult()) {
      PrevClassTemplate = R.getAsSingle<ClassTemplateDecl>();
      if (PrevClassTemplate)
        PrevDecl = PrevClassTemplate->getTemplatedDecl();
    }

    if (!PrevClassTemplate && Qualifier) {
      SemaRef.Diag(Pattern->getLocation(), diag::err_not_tag_in_scope)
        << D->getTemplatedDecl()->getTagKind() << Pattern->getDeclName() << DC
        << Pattern->getQualifierRange();
      return 0;
    }

    bool AdoptedPreviousTemplateParams = false;
    if (PrevClassTemplate) {
      bool Complain = true;

      // HACK: libstdc++ 4.2.1 contains an ill-formed friend class
      // template for struct std::tr1::__detail::_Map_base, where the
      // template parameters of the friend declaration don't match the
      // template parameters of the original declaration. In this one
      // case, we don't complain about the ill-formed friend
      // declaration.
      if (isFriend && Pattern->getIdentifier() && 
          Pattern->getIdentifier()->isStr("_Map_base") &&
          DC->isNamespace() &&
          cast<NamespaceDecl>(DC)->getIdentifier() &&
          cast<NamespaceDecl>(DC)->getIdentifier()->isStr("__detail")) {
        DeclContext *DCParent = DC->getParent();
        if (DCParent->isNamespace() &&
            cast<NamespaceDecl>(DCParent)->getIdentifier() &&
            cast<NamespaceDecl>(DCParent)->getIdentifier()->isStr("tr1")) {
          DeclContext *DCParent2 = DCParent->getParent();
          if (DCParent2->isNamespace() &&
              cast<NamespaceDecl>(DCParent2)->getIdentifier() &&
              cast<NamespaceDecl>(DCParent2)->getIdentifier()->isStr("std") &&
              DCParent2->getParent()->isTranslationUnit())
            Complain = false;
        }
      }

      TemplateParameterList *PrevParams
        = PrevClassTemplate->getTemplateParameters();

      // Make sure the parameter lists match.
      if (!SemaRef.TemplateParameterListsAreEqual(InstParams, PrevParams,
                                                  Complain, 
                                                  Sema::TPL_TemplateMatch)) {
        if (Complain)
          return 0;

        AdoptedPreviousTemplateParams = true;
        InstParams = PrevParams;
      }

      // Do some additional validation, then merge default arguments
      // from the existing declarations.
      if (!AdoptedPreviousTemplateParams &&
          SemaRef.CheckTemplateParameterList(InstParams, PrevParams,
                                             Sema::TPC_ClassTemplate))
        return 0;
    }
  }

  CXXRecordDecl *RecordInst
    = CXXRecordDecl::Create(SemaRef.Context, Pattern->getTagKind(), DC,
                            Pattern->getLocation(), Pattern->getIdentifier(),
                            Pattern->getTagKeywordLoc(), PrevDecl,
                            /*DelayTypeCreation=*/true);

  if (Qualifier)
    RecordInst->setQualifierInfo(Qualifier, Pattern->getQualifierRange());

  ClassTemplateDecl *Inst
    = ClassTemplateDecl::Create(SemaRef.Context, DC, D->getLocation(),
                                D->getIdentifier(), InstParams, RecordInst,
                                PrevClassTemplate);
  RecordInst->setDescribedClassTemplate(Inst);

  if (isFriend) {
    if (PrevClassTemplate)
      Inst->setAccess(PrevClassTemplate->getAccess());
    else
      Inst->setAccess(D->getAccess());

    Inst->setObjectOfFriendDecl(PrevClassTemplate != 0);
    // TODO: do we want to track the instantiation progeny of this
    // friend target decl?
  } else {
    Inst->setAccess(D->getAccess());
    Inst->setInstantiatedFromMemberTemplate(D);
  }
  
  // Trigger creation of the type for the instantiation.
  SemaRef.Context.getInjectedClassNameType(RecordInst,
                                    Inst->getInjectedClassNameSpecialization());

  // Finish handling of friends.
  if (isFriend) {
    DC->makeDeclVisibleInContext(Inst, /*Recoverable*/ false);
    return Inst;
  }
  
  Owner->addDecl(Inst);
  
  // Instantiate all of the partial specializations of this member class 
  // template.
  llvm::SmallVector<ClassTemplatePartialSpecializationDecl *, 4> PartialSpecs;
  D->getPartialSpecializations(PartialSpecs);
  for (unsigned I = 0, N = PartialSpecs.size(); I != N; ++I)
    InstantiateClassTemplatePartialSpecialization(Inst, PartialSpecs[I]);
  
  return Inst;
}

Decl *
TemplateDeclInstantiator::VisitClassTemplatePartialSpecializationDecl(
                                   ClassTemplatePartialSpecializationDecl *D) {
  ClassTemplateDecl *ClassTemplate = D->getSpecializedTemplate();
  
  // Lookup the already-instantiated declaration in the instantiation
  // of the class template and return that.
  DeclContext::lookup_result Found
    = Owner->lookup(ClassTemplate->getDeclName());
  if (Found.first == Found.second)
    return 0;
  
  ClassTemplateDecl *InstClassTemplate
    = dyn_cast<ClassTemplateDecl>(*Found.first);
  if (!InstClassTemplate)
    return 0;
  
  return InstClassTemplate->findPartialSpecInstantiatedFromMember(D);
}

Decl *
TemplateDeclInstantiator::VisitFunctionTemplateDecl(FunctionTemplateDecl *D) {
  // Create a local instantiation scope for this function template, which
  // will contain the instantiations of the template parameters and then get
  // merged with the local instantiation scope for the function template 
  // itself.
  LocalInstantiationScope Scope(SemaRef);

  TemplateParameterList *TempParams = D->getTemplateParameters();
  TemplateParameterList *InstParams = SubstTemplateParams(TempParams);
  if (!InstParams)
    return NULL;
  
  FunctionDecl *Instantiated = 0;
  if (CXXMethodDecl *DMethod = dyn_cast<CXXMethodDecl>(D->getTemplatedDecl()))
    Instantiated = cast_or_null<FunctionDecl>(VisitCXXMethodDecl(DMethod, 
                                                                 InstParams));
  else
    Instantiated = cast_or_null<FunctionDecl>(VisitFunctionDecl(
                                                          D->getTemplatedDecl(), 
                                                                InstParams));
  
  if (!Instantiated)
    return 0;

  Instantiated->setAccess(D->getAccess());

  // Link the instantiated function template declaration to the function
  // template from which it was instantiated.
  FunctionTemplateDecl *InstTemplate 
    = Instantiated->getDescribedFunctionTemplate();
  InstTemplate->setAccess(D->getAccess());
  assert(InstTemplate && 
         "VisitFunctionDecl/CXXMethodDecl didn't create a template!");

  bool isFriend = (InstTemplate->getFriendObjectKind() != Decl::FOK_None);

  // Link the instantiation back to the pattern *unless* this is a
  // non-definition friend declaration.
  if (!InstTemplate->getInstantiatedFromMemberTemplate() &&
      !(isFriend && !D->getTemplatedDecl()->isThisDeclarationADefinition()))
    InstTemplate->setInstantiatedFromMemberTemplate(D);
  
  // Make declarations visible in the appropriate context.
  if (!isFriend)
    Owner->addDecl(InstTemplate);

  return InstTemplate;
}

Decl *TemplateDeclInstantiator::VisitCXXRecordDecl(CXXRecordDecl *D) {
  CXXRecordDecl *PrevDecl = 0;
  if (D->isInjectedClassName())
    PrevDecl = cast<CXXRecordDecl>(Owner);
  else if (D->getPreviousDeclaration()) {
    NamedDecl *Prev = SemaRef.FindInstantiatedDecl(D->getLocation(),
                                                   D->getPreviousDeclaration(),
                                                   TemplateArgs);
    if (!Prev) return 0;
    PrevDecl = cast<CXXRecordDecl>(Prev);
  }

  CXXRecordDecl *Record
    = CXXRecordDecl::Create(SemaRef.Context, D->getTagKind(), Owner,
                            D->getLocation(), D->getIdentifier(),
                            D->getTagKeywordLoc(), PrevDecl);

  // Substitute the nested name specifier, if any.
  if (SubstQualifier(D, Record))
    return 0;

  Record->setImplicit(D->isImplicit());
  // FIXME: Check against AS_none is an ugly hack to work around the issue that
  // the tag decls introduced by friend class declarations don't have an access
  // specifier. Remove once this area of the code gets sorted out.
  if (D->getAccess() != AS_none)
    Record->setAccess(D->getAccess());
  if (!D->isInjectedClassName())
    Record->setInstantiationOfMemberClass(D, TSK_ImplicitInstantiation);

  // If the original function was part of a friend declaration,
  // inherit its namespace state.
  if (Decl::FriendObjectKind FOK = D->getFriendObjectKind())
    Record->setObjectOfFriendDecl(FOK == Decl::FOK_Declared);

  // Make sure that anonymous structs and unions are recorded.
  if (D->isAnonymousStructOrUnion()) {
    Record->setAnonymousStructOrUnion(true);
    if (Record->getDeclContext()->getRedeclContext()->isFunctionOrMethod())
      SemaRef.CurrentInstantiationScope->InstantiatedLocal(D, Record);
  }

  Owner->addDecl(Record);
  return Record;
}

/// Normal class members are of more specific types and therefore
/// don't make it here.  This function serves two purposes:
///   1) instantiating function templates
///   2) substituting friend declarations
/// FIXME: preserve function definitions in case #2
Decl *TemplateDeclInstantiator::VisitFunctionDecl(FunctionDecl *D,
                                       TemplateParameterList *TemplateParams) {
  // Check whether there is already a function template specialization for
  // this declaration.
  FunctionTemplateDecl *FunctionTemplate = D->getDescribedFunctionTemplate();
  void *InsertPos = 0;
  if (FunctionTemplate && !TemplateParams) {
    std::pair<const TemplateArgument *, unsigned> Innermost 
      = TemplateArgs.getInnermost();

    FunctionDecl *SpecFunc
      = FunctionTemplate->findSpecialization(Innermost.first, Innermost.second,
                                             InsertPos);

    // If we already have a function template specialization, return it.
    if (SpecFunc)
      return SpecFunc;
  }

  bool isFriend;
  if (FunctionTemplate)
    isFriend = (FunctionTemplate->getFriendObjectKind() != Decl::FOK_None);
  else
    isFriend = (D->getFriendObjectKind() != Decl::FOK_None);

  bool MergeWithParentScope = (TemplateParams != 0) ||
    Owner->isFunctionOrMethod() ||
    !(isa<Decl>(Owner) && 
      cast<Decl>(Owner)->isDefinedOutsideFunctionOrMethod());
  LocalInstantiationScope Scope(SemaRef, MergeWithParentScope);

  llvm::SmallVector<ParmVarDecl *, 4> Params;
  TypeSourceInfo *TInfo = D->getTypeSourceInfo();
  TInfo = SubstFunctionType(D, Params);
  if (!TInfo)
    return 0;
  QualType T = TInfo->getType();

  NestedNameSpecifier *Qualifier = D->getQualifier();
  if (Qualifier) {
    Qualifier = SemaRef.SubstNestedNameSpecifier(Qualifier,
                                                 D->getQualifierRange(),
                                                 TemplateArgs);
    if (!Qualifier) return 0;
  }

  // If we're instantiating a local function declaration, put the result
  // in the owner;  otherwise we need to find the instantiated context.
  DeclContext *DC;
  if (D->getDeclContext()->isFunctionOrMethod())
    DC = Owner;
  else if (isFriend && Qualifier) {
    CXXScopeSpec SS;
    SS.setScopeRep(Qualifier);
    SS.setRange(D->getQualifierRange());
    DC = SemaRef.computeDeclContext(SS);
    if (!DC) return 0;
  } else {
    DC = SemaRef.FindInstantiatedContext(D->getLocation(), D->getDeclContext(), 
                                         TemplateArgs);
  }

  FunctionDecl *Function =
      FunctionDecl::Create(SemaRef.Context, DC, D->getLocation(),
                           D->getDeclName(), T, TInfo,
                           D->getStorageClass(), D->getStorageClassAsWritten(),
                           D->isInlineSpecified(), D->hasWrittenPrototype());

  if (Qualifier)
    Function->setQualifierInfo(Qualifier, D->getQualifierRange());

  DeclContext *LexicalDC = Owner;
  if (!isFriend && D->isOutOfLine()) {
    assert(D->getDeclContext()->isFileContext());
    LexicalDC = D->getDeclContext();
  }

  Function->setLexicalDeclContext(LexicalDC);

  // Attach the parameters
  for (unsigned P = 0; P < Params.size(); ++P)
    Params[P]->setOwningFunction(Function);
  Function->setParams(Params.data(), Params.size());

  SourceLocation InstantiateAtPOI;
  if (TemplateParams) {
    // Our resulting instantiation is actually a function template, since we
    // are substituting only the outer template parameters. For example, given
    //
    //   template<typename T>
    //   struct X {
    //     template<typename U> friend void f(T, U);
    //   };
    //
    //   X<int> x;
    //
    // We are instantiating the friend function template "f" within X<int>, 
    // which means substituting int for T, but leaving "f" as a friend function
    // template.
    // Build the function template itself.
    FunctionTemplate = FunctionTemplateDecl::Create(SemaRef.Context, DC,
                                                    Function->getLocation(),
                                                    Function->getDeclName(),
                                                    TemplateParams, Function);
    Function->setDescribedFunctionTemplate(FunctionTemplate);

    FunctionTemplate->setLexicalDeclContext(LexicalDC);

    if (isFriend && D->isThisDeclarationADefinition()) {
      // TODO: should we remember this connection regardless of whether
      // the friend declaration provided a body?
      FunctionTemplate->setInstantiatedFromMemberTemplate(
                                           D->getDescribedFunctionTemplate());
    }
  } else if (FunctionTemplate) {
    // Record this function template specialization.
    std::pair<const TemplateArgument *, unsigned> Innermost 
      = TemplateArgs.getInnermost();
    Function->setFunctionTemplateSpecialization(FunctionTemplate,
                  new (SemaRef.Context) TemplateArgumentList(SemaRef.Context,
                                                             Innermost.first,
                                                             Innermost.second),
                                                InsertPos);
  } else if (isFriend && D->isThisDeclarationADefinition()) {
    // TODO: should we remember this connection regardless of whether
    // the friend declaration provided a body?
    Function->setInstantiationOfMemberFunction(D, TSK_ImplicitInstantiation);
  }
    
  if (InitFunctionInstantiation(Function, D))
    Function->setInvalidDecl();

  bool Redeclaration = false;
  bool OverloadableAttrRequired = false;
  bool isExplicitSpecialization = false;
    
  LookupResult Previous(SemaRef, Function->getDeclName(), SourceLocation(),
                        Sema::LookupOrdinaryName, Sema::ForRedeclaration);

  if (DependentFunctionTemplateSpecializationInfo *Info
        = D->getDependentSpecializationInfo()) {
    assert(isFriend && "non-friend has dependent specialization info?");

    // This needs to be set now for future sanity.
    Function->setObjectOfFriendDecl(/*HasPrevious*/ true);

    // Instantiate the explicit template arguments.
    TemplateArgumentListInfo ExplicitArgs(Info->getLAngleLoc(),
                                          Info->getRAngleLoc());
    for (unsigned I = 0, E = Info->getNumTemplateArgs(); I != E; ++I) {
      TemplateArgumentLoc Loc;
      if (SemaRef.Subst(Info->getTemplateArg(I), Loc, TemplateArgs))
        return 0;

      ExplicitArgs.addArgument(Loc);
    }

    // Map the candidate templates to their instantiations.
    for (unsigned I = 0, E = Info->getNumTemplates(); I != E; ++I) {
      Decl *Temp = SemaRef.FindInstantiatedDecl(D->getLocation(),
                                                Info->getTemplate(I),
                                                TemplateArgs);
      if (!Temp) return 0;

      Previous.addDecl(cast<FunctionTemplateDecl>(Temp));
    }

    if (SemaRef.CheckFunctionTemplateSpecialization(Function,
                                                    &ExplicitArgs,
                                                    Previous))
      Function->setInvalidDecl();
                                          
    isExplicitSpecialization = true;

  } else if (TemplateParams || !FunctionTemplate) {
    // Look only into the namespace where the friend would be declared to 
    // find a previous declaration. This is the innermost enclosing namespace, 
    // as described in ActOnFriendFunctionDecl.
    SemaRef.LookupQualifiedName(Previous, DC);
    
    // In C++, the previous declaration we find might be a tag type
    // (class or enum). In this case, the new declaration will hide the
    // tag type. Note that this does does not apply if we're declaring a
    // typedef (C++ [dcl.typedef]p4).
    if (Previous.isSingleTagDecl())
      Previous.clear();
  }
  
  SemaRef.CheckFunctionDeclaration(/*Scope*/ 0, Function, Previous,
                                   isExplicitSpecialization, Redeclaration,
                                   /*FIXME:*/OverloadableAttrRequired);

  NamedDecl *PrincipalDecl = (TemplateParams
                              ? cast<NamedDecl>(FunctionTemplate)
                              : Function);

  // If the original function was part of a friend declaration,
  // inherit its namespace state and add it to the owner.
  if (isFriend) {
    NamedDecl *PrevDecl;
    if (TemplateParams)
      PrevDecl = FunctionTemplate->getPreviousDeclaration();
    else
      PrevDecl = Function->getPreviousDeclaration();

    PrincipalDecl->setObjectOfFriendDecl(PrevDecl != 0);
    DC->makeDeclVisibleInContext(PrincipalDecl, /*Recoverable=*/ false);

    bool queuedInstantiation = false;

    if (!SemaRef.getLangOptions().CPlusPlus0x &&
        D->isThisDeclarationADefinition()) {
      // Check for a function body.
      const FunctionDecl *Definition = 0;
      if (Function->hasBody(Definition) &&
          Definition->getTemplateSpecializationKind() == TSK_Undeclared) {
        SemaRef.Diag(Function->getLocation(), diag::err_redefinition) 
          << Function->getDeclName();
        SemaRef.Diag(Definition->getLocation(), diag::note_previous_definition);
        Function->setInvalidDecl();        
      } 
      // Check for redefinitions due to other instantiations of this or
      // a similar friend function.
      else for (FunctionDecl::redecl_iterator R = Function->redecls_begin(),
                                           REnd = Function->redecls_end();
                R != REnd; ++R) {
        if (*R == Function)
          continue;
        switch (R->getFriendObjectKind()) {
        case Decl::FOK_None:
          if (!queuedInstantiation && R->isUsed(false)) {
            if (MemberSpecializationInfo *MSInfo
                = Function->getMemberSpecializationInfo()) {
              if (MSInfo->getPointOfInstantiation().isInvalid()) {
                SourceLocation Loc = R->getLocation(); // FIXME
                MSInfo->setPointOfInstantiation(Loc);
                SemaRef.PendingLocalImplicitInstantiations.push_back(
                                                 std::make_pair(Function, Loc));
                queuedInstantiation = true;
              }
            }
          }
          break;
        default:
          if (const FunctionDecl *RPattern
              = R->getTemplateInstantiationPattern())
            if (RPattern->hasBody(RPattern)) {
              SemaRef.Diag(Function->getLocation(), diag::err_redefinition) 
                << Function->getDeclName();
              SemaRef.Diag(R->getLocation(), diag::note_previous_definition);
              Function->setInvalidDecl();
              break;
            }
        }
      }
    }
  }

  if (Function->isOverloadedOperator() && !DC->isRecord() &&
      PrincipalDecl->isInIdentifierNamespace(Decl::IDNS_Ordinary))
    PrincipalDecl->setNonMemberOperator();

  return Function;
}

Decl *
TemplateDeclInstantiator::VisitCXXMethodDecl(CXXMethodDecl *D,
                                      TemplateParameterList *TemplateParams) {
  FunctionTemplateDecl *FunctionTemplate = D->getDescribedFunctionTemplate();
  void *InsertPos = 0;
  if (FunctionTemplate && !TemplateParams) {
    // We are creating a function template specialization from a function
    // template. Check whether there is already a function template
    // specialization for this particular set of template arguments.
    std::pair<const TemplateArgument *, unsigned> Innermost 
      = TemplateArgs.getInnermost();

    FunctionDecl *SpecFunc
      = FunctionTemplate->findSpecialization(Innermost.first, Innermost.second,
                                             InsertPos);

    // If we already have a function template specialization, return it.
    if (SpecFunc)
      return SpecFunc;
  }

  bool isFriend;
  if (FunctionTemplate)
    isFriend = (FunctionTemplate->getFriendObjectKind() != Decl::FOK_None);
  else
    isFriend = (D->getFriendObjectKind() != Decl::FOK_None);

  bool MergeWithParentScope = (TemplateParams != 0) ||
    !(isa<Decl>(Owner) && 
      cast<Decl>(Owner)->isDefinedOutsideFunctionOrMethod());
  LocalInstantiationScope Scope(SemaRef, MergeWithParentScope);

  llvm::SmallVector<ParmVarDecl *, 4> Params;
  TypeSourceInfo *TInfo = D->getTypeSourceInfo();
  TInfo = SubstFunctionType(D, Params);
  if (!TInfo)
    return 0;
  QualType T = TInfo->getType();

  // \brief If the type of this function is not *directly* a function
  // type, then we're instantiating the a function that was declared
  // via a typedef, e.g.,
  //
  //   typedef int functype(int, int);
  //   functype func;
  //
  // In this case, we'll just go instantiate the ParmVarDecls that we
  // synthesized in the method declaration.
  if (!isa<FunctionProtoType>(T)) {
    assert(!Params.size() && "Instantiating type could not yield parameters");
    for (unsigned I = 0, N = D->getNumParams(); I != N; ++I) {
      ParmVarDecl *P = SemaRef.SubstParmVarDecl(D->getParamDecl(I), 
                                                TemplateArgs);
      if (!P)
        return 0;

      Params.push_back(P);
    }
  }

  NestedNameSpecifier *Qualifier = D->getQualifier();
  if (Qualifier) {
    Qualifier = SemaRef.SubstNestedNameSpecifier(Qualifier,
                                                 D->getQualifierRange(),
                                                 TemplateArgs);
    if (!Qualifier) return 0;
  }

  DeclContext *DC = Owner;
  if (isFriend) {
    if (Qualifier) {
      CXXScopeSpec SS;
      SS.setScopeRep(Qualifier);
      SS.setRange(D->getQualifierRange());
      DC = SemaRef.computeDeclContext(SS);
    } else {
      DC = SemaRef.FindInstantiatedContext(D->getLocation(),
                                           D->getDeclContext(),
                                           TemplateArgs);
    }
    if (!DC) return 0;
  }

  // Build the instantiated method declaration.
  CXXRecordDecl *Record = cast<CXXRecordDecl>(DC);
  CXXMethodDecl *Method = 0;

  DeclarationNameInfo NameInfo
    = SemaRef.SubstDeclarationNameInfo(D->getNameInfo(), TemplateArgs);
  if (CXXConstructorDecl *Constructor = dyn_cast<CXXConstructorDecl>(D)) {
    Method = CXXConstructorDecl::Create(SemaRef.Context, Record,
                                        NameInfo, T, TInfo,
                                        Constructor->isExplicit(),
                                        Constructor->isInlineSpecified(),
                                        false);
  } else if (CXXDestructorDecl *Destructor = dyn_cast<CXXDestructorDecl>(D)) {
    Method = CXXDestructorDecl::Create(SemaRef.Context, Record,
                                       NameInfo, T,
                                       Destructor->isInlineSpecified(),
                                       false);
  } else if (CXXConversionDecl *Conversion = dyn_cast<CXXConversionDecl>(D)) {
    Method = CXXConversionDecl::Create(SemaRef.Context, Record,
                                       NameInfo, T, TInfo,
                                       Conversion->isInlineSpecified(),
                                       Conversion->isExplicit());
  } else {
    Method = CXXMethodDecl::Create(SemaRef.Context, Record,
                                   NameInfo, T, TInfo,
                                   D->isStatic(),
                                   D->getStorageClassAsWritten(),
                                   D->isInlineSpecified());
  }

  if (Qualifier)
    Method->setQualifierInfo(Qualifier, D->getQualifierRange());

  if (TemplateParams) {
    // Our resulting instantiation is actually a function template, since we
    // are substituting only the outer template parameters. For example, given
    //
    //   template<typename T>
    //   struct X {
    //     template<typename U> void f(T, U);
    //   };
    //
    //   X<int> x;
    //
    // We are instantiating the member template "f" within X<int>, which means
    // substituting int for T, but leaving "f" as a member function template.
    // Build the function template itself.
    FunctionTemplate = FunctionTemplateDecl::Create(SemaRef.Context, Record,
                                                    Method->getLocation(),
                                                    Method->getDeclName(),
                                                    TemplateParams, Method);
    if (isFriend) {
      FunctionTemplate->setLexicalDeclContext(Owner);
      FunctionTemplate->setObjectOfFriendDecl(true);
    } else if (D->isOutOfLine())
      FunctionTemplate->setLexicalDeclContext(D->getLexicalDeclContext());
    Method->setDescribedFunctionTemplate(FunctionTemplate);
  } else if (FunctionTemplate) {
    // Record this function template specialization.
    std::pair<const TemplateArgument *, unsigned> Innermost 
      = TemplateArgs.getInnermost();
    Method->setFunctionTemplateSpecialization(FunctionTemplate,
                    new (SemaRef.Context) TemplateArgumentList(SemaRef.Context,
                                                              Innermost.first,
                                                              Innermost.second),
                                              InsertPos);
  } else if (!isFriend) {
    // Record that this is an instantiation of a member function.
    Method->setInstantiationOfMemberFunction(D, TSK_ImplicitInstantiation);
  }
  
  // If we are instantiating a member function defined
  // out-of-line, the instantiation will have the same lexical
  // context (which will be a namespace scope) as the template.
  if (isFriend) {
    Method->setLexicalDeclContext(Owner);
    Method->setObjectOfFriendDecl(true);
  } else if (D->isOutOfLine())
    Method->setLexicalDeclContext(D->getLexicalDeclContext());

  // Attach the parameters
  for (unsigned P = 0; P < Params.size(); ++P)
    Params[P]->setOwningFunction(Method);
  Method->setParams(Params.data(), Params.size());

  if (InitMethodInstantiation(Method, D))
    Method->setInvalidDecl();

  LookupResult Previous(SemaRef, NameInfo, Sema::LookupOrdinaryName,
                        Sema::ForRedeclaration);

  if (!FunctionTemplate || TemplateParams || isFriend) {
    SemaRef.LookupQualifiedName(Previous, Record);

    // In C++, the previous declaration we find might be a tag type
    // (class or enum). In this case, the new declaration will hide the
    // tag type. Note that this does does not apply if we're declaring a
    // typedef (C++ [dcl.typedef]p4).
    if (Previous.isSingleTagDecl())
      Previous.clear();
  }

  bool Redeclaration = false;
  bool OverloadableAttrRequired = false;
  SemaRef.CheckFunctionDeclaration(0, Method, Previous, false, Redeclaration,
                                   /*FIXME:*/OverloadableAttrRequired);

  if (D->isPure())
    SemaRef.CheckPureMethod(Method, SourceRange());

  Method->setAccess(D->getAccess());

  if (FunctionTemplate) {
    // If there's a function template, let our caller handle it.
  } else if (Method->isInvalidDecl() && !Previous.empty()) {
    // Don't hide a (potentially) valid declaration with an invalid one.
  } else {
    NamedDecl *DeclToAdd = (TemplateParams
                            ? cast<NamedDecl>(FunctionTemplate)
                            : Method);
    if (isFriend)
      Record->makeDeclVisibleInContext(DeclToAdd);
    else
      Owner->addDecl(DeclToAdd);
  }
  
  return Method;
}

Decl *TemplateDeclInstantiator::VisitCXXConstructorDecl(CXXConstructorDecl *D) {
  return VisitCXXMethodDecl(D);
}

Decl *TemplateDeclInstantiator::VisitCXXDestructorDecl(CXXDestructorDecl *D) {
  return VisitCXXMethodDecl(D);
}

Decl *TemplateDeclInstantiator::VisitCXXConversionDecl(CXXConversionDecl *D) {
  return VisitCXXMethodDecl(D);
}

ParmVarDecl *TemplateDeclInstantiator::VisitParmVarDecl(ParmVarDecl *D) {
  return SemaRef.SubstParmVarDecl(D, TemplateArgs);
}

Decl *TemplateDeclInstantiator::VisitTemplateTypeParmDecl(
                                                    TemplateTypeParmDecl *D) {
  // TODO: don't always clone when decls are refcounted.
  const Type* T = D->getTypeForDecl();
  assert(T->isTemplateTypeParmType());
  const TemplateTypeParmType *TTPT = T->getAs<TemplateTypeParmType>();

  TemplateTypeParmDecl *Inst =
    TemplateTypeParmDecl::Create(SemaRef.Context, Owner, D->getLocation(),
                                 TTPT->getDepth() - TemplateArgs.getNumLevels(),
                                 TTPT->getIndex(),TTPT->getName(),
                                 D->wasDeclaredWithTypename(),
                                 D->isParameterPack());

  if (D->hasDefaultArgument())
    Inst->setDefaultArgument(D->getDefaultArgumentInfo(), false);  

  // Introduce this template parameter's instantiation into the instantiation 
  // scope.
  SemaRef.CurrentInstantiationScope->InstantiatedLocal(D, Inst);
  
  return Inst;
}

Decl *TemplateDeclInstantiator::VisitNonTypeTemplateParmDecl(
                                                 NonTypeTemplateParmDecl *D) {
  // Substitute into the type of the non-type template parameter.
  QualType T;
  TypeSourceInfo *DI = D->getTypeSourceInfo();
  if (DI) {
    DI = SemaRef.SubstType(DI, TemplateArgs, D->getLocation(),
                           D->getDeclName());
    if (DI) T = DI->getType();
  } else {
    T = SemaRef.SubstType(D->getType(), TemplateArgs, D->getLocation(),
                          D->getDeclName());
    DI = 0;
  }
  if (T.isNull())
    return 0;
  
  // Check that this type is acceptable for a non-type template parameter.
  bool Invalid = false;
  T = SemaRef.CheckNonTypeTemplateParameterType(T, D->getLocation());
  if (T.isNull()) {
    T = SemaRef.Context.IntTy;
    Invalid = true;
  }
  
  NonTypeTemplateParmDecl *Param
    = NonTypeTemplateParmDecl::Create(SemaRef.Context, Owner, D->getLocation(),
                                    D->getDepth() - TemplateArgs.getNumLevels(), 
                                      D->getPosition(), D->getIdentifier(), T, 
                                      DI);
  if (Invalid)
    Param->setInvalidDecl();
  
  Param->setDefaultArgument(D->getDefaultArgument(), false);
  
  // Introduce this template parameter's instantiation into the instantiation 
  // scope.
  SemaRef.CurrentInstantiationScope->InstantiatedLocal(D, Param);
  return Param;
}

Decl *
TemplateDeclInstantiator::VisitTemplateTemplateParmDecl(
                                                  TemplateTemplateParmDecl *D) {
  // Instantiate the template parameter list of the template template parameter.
  TemplateParameterList *TempParams = D->getTemplateParameters();
  TemplateParameterList *InstParams;
  {
    // Perform the actual substitution of template parameters within a new,
    // local instantiation scope.
    LocalInstantiationScope Scope(SemaRef);
    InstParams = SubstTemplateParams(TempParams);
    if (!InstParams)
      return NULL;
  }  
  
  // Build the template template parameter.
  TemplateTemplateParmDecl *Param
    = TemplateTemplateParmDecl::Create(SemaRef.Context, Owner, D->getLocation(),
                                   D->getDepth() - TemplateArgs.getNumLevels(), 
                                       D->getPosition(), D->getIdentifier(), 
                                       InstParams);
  Param->setDefaultArgument(D->getDefaultArgument(), false);
  
  // Introduce this template parameter's instantiation into the instantiation 
  // scope.
  SemaRef.CurrentInstantiationScope->InstantiatedLocal(D, Param);
  
  return Param;
}

Decl *TemplateDeclInstantiator::VisitUsingDirectiveDecl(UsingDirectiveDecl *D) {
  // Using directives are never dependent, so they require no explicit
  
  UsingDirectiveDecl *Inst
    = UsingDirectiveDecl::Create(SemaRef.Context, Owner, D->getLocation(),
                                 D->getNamespaceKeyLocation(), 
                                 D->getQualifierRange(), D->getQualifier(), 
                                 D->getIdentLocation(), 
                                 D->getNominatedNamespace(), 
                                 D->getCommonAncestor());
  Owner->addDecl(Inst);
  return Inst;
}

Decl *TemplateDeclInstantiator::VisitUsingDecl(UsingDecl *D) {
  // The nested name specifier is non-dependent, so no transformation
  // is required. The same holds for the name info.
  DeclarationNameInfo NameInfo = D->getNameInfo();

  // We only need to do redeclaration lookups if we're in a class
  // scope (in fact, it's not really even possible in non-class
  // scopes).
  bool CheckRedeclaration = Owner->isRecord();

  LookupResult Prev(SemaRef, NameInfo, Sema::LookupUsingDeclName,
                    Sema::ForRedeclaration);

  UsingDecl *NewUD = UsingDecl::Create(SemaRef.Context, Owner,
                                       D->getNestedNameRange(),
                                       D->getUsingLocation(),
                                       D->getTargetNestedNameDecl(),
                                       NameInfo,
                                       D->isTypeName());

  CXXScopeSpec SS;
  SS.setScopeRep(D->getTargetNestedNameDecl());
  SS.setRange(D->getNestedNameRange());

  if (CheckRedeclaration) {
    Prev.setHideTags(false);
    SemaRef.LookupQualifiedName(Prev, Owner);

    // Check for invalid redeclarations.
    if (SemaRef.CheckUsingDeclRedeclaration(D->getUsingLocation(),
                                            D->isTypeName(), SS,
                                            D->getLocation(), Prev))
      NewUD->setInvalidDecl();

  }

  if (!NewUD->isInvalidDecl() &&
      SemaRef.CheckUsingDeclQualifier(D->getUsingLocation(), SS,
                                      D->getLocation()))
    NewUD->setInvalidDecl();

  SemaRef.Context.setInstantiatedFromUsingDecl(NewUD, D);
  NewUD->setAccess(D->getAccess());
  Owner->addDecl(NewUD);

  // Don't process the shadow decls for an invalid decl.
  if (NewUD->isInvalidDecl())
    return NewUD;

  bool isFunctionScope = Owner->isFunctionOrMethod();

  // Process the shadow decls.
  for (UsingDecl::shadow_iterator I = D->shadow_begin(), E = D->shadow_end();
         I != E; ++I) {
    UsingShadowDecl *Shadow = *I;
    NamedDecl *InstTarget =
      cast<NamedDecl>(SemaRef.FindInstantiatedDecl(Shadow->getLocation(),
                                                   Shadow->getTargetDecl(),
                                                   TemplateArgs));

    if (CheckRedeclaration &&
        SemaRef.CheckUsingShadowDecl(NewUD, InstTarget, Prev))
      continue;

    UsingShadowDecl *InstShadow
      = SemaRef.BuildUsingShadowDecl(/*Scope*/ 0, NewUD, InstTarget);
    SemaRef.Context.setInstantiatedFromUsingShadowDecl(InstShadow, Shadow);

    if (isFunctionScope)
      SemaRef.CurrentInstantiationScope->InstantiatedLocal(Shadow, InstShadow);
  }

  return NewUD;
}

Decl *TemplateDeclInstantiator::VisitUsingShadowDecl(UsingShadowDecl *D) {
  // Ignore these;  we handle them in bulk when processing the UsingDecl.
  return 0;
}

Decl * TemplateDeclInstantiator
    ::VisitUnresolvedUsingTypenameDecl(UnresolvedUsingTypenameDecl *D) {
  NestedNameSpecifier *NNS =
    SemaRef.SubstNestedNameSpecifier(D->getTargetNestedNameSpecifier(),
                                     D->getTargetNestedNameRange(),
                                     TemplateArgs);
  if (!NNS)
    return 0;

  CXXScopeSpec SS;
  SS.setRange(D->getTargetNestedNameRange());
  SS.setScopeRep(NNS);

  // Since NameInfo refers to a typename, it cannot be a C++ special name.
  // Hence, no tranformation is required for it.
  DeclarationNameInfo NameInfo(D->getDeclName(), D->getLocation());
  NamedDecl *UD =
    SemaRef.BuildUsingDeclaration(/*Scope*/ 0, D->getAccess(),
                                  D->getUsingLoc(), SS, NameInfo, 0,
                                  /*instantiation*/ true,
                                  /*typename*/ true, D->getTypenameLoc());
  if (UD)
    SemaRef.Context.setInstantiatedFromUsingDecl(cast<UsingDecl>(UD), D);

  return UD;
}

Decl * TemplateDeclInstantiator
    ::VisitUnresolvedUsingValueDecl(UnresolvedUsingValueDecl *D) {
  NestedNameSpecifier *NNS =
    SemaRef.SubstNestedNameSpecifier(D->getTargetNestedNameSpecifier(),
                                     D->getTargetNestedNameRange(),
                                     TemplateArgs);
  if (!NNS)
    return 0;

  CXXScopeSpec SS;
  SS.setRange(D->getTargetNestedNameRange());
  SS.setScopeRep(NNS);

  DeclarationNameInfo NameInfo
    = SemaRef.SubstDeclarationNameInfo(D->getNameInfo(), TemplateArgs);

  NamedDecl *UD =
    SemaRef.BuildUsingDeclaration(/*Scope*/ 0, D->getAccess(),
                                  D->getUsingLoc(), SS, NameInfo, 0,
                                  /*instantiation*/ true,
                                  /*typename*/ false, SourceLocation());
  if (UD)
    SemaRef.Context.setInstantiatedFromUsingDecl(cast<UsingDecl>(UD), D);

  return UD;
}

Decl *Sema::SubstDecl(Decl *D, DeclContext *Owner,
                      const MultiLevelTemplateArgumentList &TemplateArgs) {
  TemplateDeclInstantiator Instantiator(*this, Owner, TemplateArgs);
  if (D->isInvalidDecl())
    return 0;

  return Instantiator.Visit(D);
}

/// \brief Instantiates a nested template parameter list in the current
/// instantiation context.
///
/// \param L The parameter list to instantiate
///
/// \returns NULL if there was an error
TemplateParameterList *
TemplateDeclInstantiator::SubstTemplateParams(TemplateParameterList *L) {
  // Get errors for all the parameters before bailing out.
  bool Invalid = false;

  unsigned N = L->size();
  typedef llvm::SmallVector<NamedDecl *, 8> ParamVector;
  ParamVector Params;
  Params.reserve(N);
  for (TemplateParameterList::iterator PI = L->begin(), PE = L->end();
       PI != PE; ++PI) {
    NamedDecl *D = cast_or_null<NamedDecl>(Visit(*PI));
    Params.push_back(D);
    Invalid = Invalid || !D || D->isInvalidDecl();
  }

  // Clean up if we had an error.
  if (Invalid)
    return NULL;

  TemplateParameterList *InstL
    = TemplateParameterList::Create(SemaRef.Context, L->getTemplateLoc(),
                                    L->getLAngleLoc(), &Params.front(), N,
                                    L->getRAngleLoc());
  return InstL;
}

/// \brief Instantiate the declaration of a class template partial 
/// specialization.
///
/// \param ClassTemplate the (instantiated) class template that is partially
// specialized by the instantiation of \p PartialSpec.
///
/// \param PartialSpec the (uninstantiated) class template partial 
/// specialization that we are instantiating.
///
/// \returns true if there was an error, false otherwise.
bool 
TemplateDeclInstantiator::InstantiateClassTemplatePartialSpecialization(
                                            ClassTemplateDecl *ClassTemplate,
                          ClassTemplatePartialSpecializationDecl *PartialSpec) {
  // Create a local instantiation scope for this class template partial
  // specialization, which will contain the instantiations of the template
  // parameters.
  LocalInstantiationScope Scope(SemaRef);
  
  // Substitute into the template parameters of the class template partial
  // specialization.
  TemplateParameterList *TempParams = PartialSpec->getTemplateParameters();
  TemplateParameterList *InstParams = SubstTemplateParams(TempParams);
  if (!InstParams)
    return true;
  
  // Substitute into the template arguments of the class template partial
  // specialization.
  const TemplateArgumentLoc *PartialSpecTemplateArgs
    = PartialSpec->getTemplateArgsAsWritten();
  unsigned N = PartialSpec->getNumTemplateArgsAsWritten();

  TemplateArgumentListInfo InstTemplateArgs; // no angle locations
  for (unsigned I = 0; I != N; ++I) {
    TemplateArgumentLoc Loc;
    if (SemaRef.Subst(PartialSpecTemplateArgs[I], Loc, TemplateArgs))
      return true;
    InstTemplateArgs.addArgument(Loc);
  }
  

  // Check that the template argument list is well-formed for this
  // class template.
  TemplateArgumentListBuilder Converted(ClassTemplate->getTemplateParameters(), 
                                        InstTemplateArgs.size());
  if (SemaRef.CheckTemplateArgumentList(ClassTemplate, 
                                        PartialSpec->getLocation(),
                                        InstTemplateArgs, 
                                        false,
                                        Converted))
    return true;

  // Figure out where to insert this class template partial specialization
  // in the member template's set of class template partial specializations.
  void *InsertPos = 0;
  ClassTemplateSpecializationDecl *PrevDecl
    = ClassTemplate->findPartialSpecialization(Converted.getFlatArguments(),
                                                Converted.flatSize(), InsertPos);
  
  // Build the canonical type that describes the converted template
  // arguments of the class template partial specialization.
  QualType CanonType 
    = SemaRef.Context.getTemplateSpecializationType(TemplateName(ClassTemplate),
                                                  Converted.getFlatArguments(),
                                                    Converted.flatSize());

  // Build the fully-sugared type for this class template
  // specialization as the user wrote in the specialization
  // itself. This means that we'll pretty-print the type retrieved
  // from the specialization's declaration the way that the user
  // actually wrote the specialization, rather than formatting the
  // name based on the "canonical" representation used to store the
  // template arguments in the specialization.
  TypeSourceInfo *WrittenTy
    = SemaRef.Context.getTemplateSpecializationTypeInfo(
                                                    TemplateName(ClassTemplate),
                                                    PartialSpec->getLocation(),
                                                    InstTemplateArgs,
                                                    CanonType);
  
  if (PrevDecl) {
    // We've already seen a partial specialization with the same template
    // parameters and template arguments. This can happen, for example, when
    // substituting the outer template arguments ends up causing two
    // class template partial specializations of a member class template
    // to have identical forms, e.g.,
    //
    //   template<typename T, typename U>
    //   struct Outer {
    //     template<typename X, typename Y> struct Inner;
    //     template<typename Y> struct Inner<T, Y>;
    //     template<typename Y> struct Inner<U, Y>;
    //   };
    //
    //   Outer<int, int> outer; // error: the partial specializations of Inner
    //                          // have the same signature.
    SemaRef.Diag(PartialSpec->getLocation(), diag::err_partial_spec_redeclared)
      << WrittenTy;
    SemaRef.Diag(PrevDecl->getLocation(), diag::note_prev_partial_spec_here)
      << SemaRef.Context.getTypeDeclType(PrevDecl);
    return true;
  }
  
  
  // Create the class template partial specialization declaration.
  ClassTemplatePartialSpecializationDecl *InstPartialSpec
    = ClassTemplatePartialSpecializationDecl::Create(SemaRef.Context, 
                                                     PartialSpec->getTagKind(),
                                                     Owner, 
                                                     PartialSpec->getLocation(), 
                                                     InstParams,
                                                     ClassTemplate, 
                                                     Converted,
                                                     InstTemplateArgs,
                                                     CanonType,
                                                     0,
                             ClassTemplate->getNextPartialSpecSequenceNumber());
  // Substitute the nested name specifier, if any.
  if (SubstQualifier(PartialSpec, InstPartialSpec))
    return 0;

  InstPartialSpec->setInstantiatedFromMember(PartialSpec);
  InstPartialSpec->setTypeAsWritten(WrittenTy);
  
  // Add this partial specialization to the set of class template partial
  // specializations.
  ClassTemplate->AddPartialSpecialization(InstPartialSpec, InsertPos);
  return false;
}

TypeSourceInfo*
TemplateDeclInstantiator::SubstFunctionType(FunctionDecl *D,
                              llvm::SmallVectorImpl<ParmVarDecl *> &Params) {
  TypeSourceInfo *OldTInfo = D->getTypeSourceInfo();
  assert(OldTInfo && "substituting function without type source info");
  assert(Params.empty() && "parameter vector is non-empty at start");
  TypeSourceInfo *NewTInfo
    = SemaRef.SubstFunctionDeclType(OldTInfo, TemplateArgs,
                                    D->getTypeSpecStartLoc(),
                                    D->getDeclName());
  if (!NewTInfo)
    return 0;

  if (NewTInfo != OldTInfo) {
    // Get parameters from the new type info.
    TypeLoc OldTL = OldTInfo->getTypeLoc();
    if (FunctionProtoTypeLoc *OldProtoLoc
                                  = dyn_cast<FunctionProtoTypeLoc>(&OldTL)) {
      TypeLoc NewTL = NewTInfo->getTypeLoc();
      FunctionProtoTypeLoc *NewProtoLoc = cast<FunctionProtoTypeLoc>(&NewTL);
      assert(NewProtoLoc && "Missing prototype?");
      for (unsigned i = 0, i_end = NewProtoLoc->getNumArgs(); i != i_end; ++i) {
        // FIXME: Variadic templates will break this.
        Params.push_back(NewProtoLoc->getArg(i));
        SemaRef.CurrentInstantiationScope->InstantiatedLocal(
                                                        OldProtoLoc->getArg(i),
                                                        NewProtoLoc->getArg(i));
      }
    }
  } else {
    // The function type itself was not dependent and therefore no
    // substitution occurred. However, we still need to instantiate
    // the function parameters themselves.
    TypeLoc OldTL = OldTInfo->getTypeLoc();
    if (FunctionProtoTypeLoc *OldProtoLoc
                                    = dyn_cast<FunctionProtoTypeLoc>(&OldTL)) {
      for (unsigned i = 0, i_end = OldProtoLoc->getNumArgs(); i != i_end; ++i) {
        ParmVarDecl *Parm = VisitParmVarDecl(OldProtoLoc->getArg(i));
        if (!Parm)
          return 0;
        Params.push_back(Parm);
      }
    }
  }
  return NewTInfo;
}

/// \brief Initializes the common fields of an instantiation function
/// declaration (New) from the corresponding fields of its template (Tmpl).
///
/// \returns true if there was an error
bool
TemplateDeclInstantiator::InitFunctionInstantiation(FunctionDecl *New,
                                                    FunctionDecl *Tmpl) {
  if (Tmpl->isDeleted())
    New->setDeleted();

  // If we are performing substituting explicitly-specified template arguments
  // or deduced template arguments into a function template and we reach this
  // point, we are now past the point where SFINAE applies and have committed
  // to keeping the new function template specialization. We therefore
  // convert the active template instantiation for the function template
  // into a template instantiation for this specific function template
  // specialization, which is not a SFINAE context, so that we diagnose any
  // further errors in the declaration itself.
  typedef Sema::ActiveTemplateInstantiation ActiveInstType;
  ActiveInstType &ActiveInst = SemaRef.ActiveTemplateInstantiations.back();
  if (ActiveInst.Kind == ActiveInstType::ExplicitTemplateArgumentSubstitution ||
      ActiveInst.Kind == ActiveInstType::DeducedTemplateArgumentSubstitution) {
    if (FunctionTemplateDecl *FunTmpl
          = dyn_cast<FunctionTemplateDecl>((Decl *)ActiveInst.Entity)) {
      assert(FunTmpl->getTemplatedDecl() == Tmpl &&
             "Deduction from the wrong function template?");
      (void) FunTmpl;
      ActiveInst.Kind = ActiveInstType::TemplateInstantiation;
      ActiveInst.Entity = reinterpret_cast<uintptr_t>(New);
      --SemaRef.NonInstantiationEntries;
    }
  }

  const FunctionProtoType *Proto = Tmpl->getType()->getAs<FunctionProtoType>();
  assert(Proto && "Function template without prototype?");

  if (Proto->hasExceptionSpec() || Proto->hasAnyExceptionSpec() ||
      Proto->getNoReturnAttr()) {
    // The function has an exception specification or a "noreturn"
    // attribute. Substitute into each of the exception types.
    llvm::SmallVector<QualType, 4> Exceptions;
    for (unsigned I = 0, N = Proto->getNumExceptions(); I != N; ++I) {
      // FIXME: Poor location information!
      QualType T
        = SemaRef.SubstType(Proto->getExceptionType(I), TemplateArgs,
                            New->getLocation(), New->getDeclName());
      if (T.isNull() || 
          SemaRef.CheckSpecifiedExceptionType(T, New->getLocation()))
        continue;

      Exceptions.push_back(T);
    }

    // Rebuild the function type 

    const FunctionProtoType *NewProto
      = New->getType()->getAs<FunctionProtoType>();
    assert(NewProto && "Template instantiation without function prototype?");
    New->setType(SemaRef.Context.getFunctionType(NewProto->getResultType(),
                                                 NewProto->arg_type_begin(),
                                                 NewProto->getNumArgs(),
                                                 NewProto->isVariadic(),
                                                 NewProto->getTypeQuals(),
                                                 Proto->hasExceptionSpec(),
                                                 Proto->hasAnyExceptionSpec(),
                                                 Exceptions.size(),
                                                 Exceptions.data(),
                                                 Proto->getExtInfo()));
  }

  SemaRef.InstantiateAttrs(TemplateArgs, Tmpl, New);

  return false;
}

/// \brief Initializes common fields of an instantiated method
/// declaration (New) from the corresponding fields of its template
/// (Tmpl).
///
/// \returns true if there was an error
bool
TemplateDeclInstantiator::InitMethodInstantiation(CXXMethodDecl *New,
                                                  CXXMethodDecl *Tmpl) {
  if (InitFunctionInstantiation(New, Tmpl))
    return true;

  CXXRecordDecl *Record = cast<CXXRecordDecl>(Owner);
  New->setAccess(Tmpl->getAccess());
  if (Tmpl->isVirtualAsWritten())
    Record->setMethodAsVirtual(New);

  // FIXME: attributes
  // FIXME: New needs a pointer to Tmpl
  return false;
}

/// \brief Instantiate the definition of the given function from its
/// template.
///
/// \param PointOfInstantiation the point at which the instantiation was
/// required. Note that this is not precisely a "point of instantiation"
/// for the function, but it's close.
///
/// \param Function the already-instantiated declaration of a
/// function template specialization or member function of a class template
/// specialization.
///
/// \param Recursive if true, recursively instantiates any functions that
/// are required by this instantiation.
///
/// \param DefinitionRequired if true, then we are performing an explicit
/// instantiation where the body of the function is required. Complain if
/// there is no such body.
void Sema::InstantiateFunctionDefinition(SourceLocation PointOfInstantiation,
                                         FunctionDecl *Function,
                                         bool Recursive,
                                         bool DefinitionRequired) {
  if (Function->isInvalidDecl() || Function->hasBody())
    return;

  // Never instantiate an explicit specialization.
  if (Function->getTemplateSpecializationKind() == TSK_ExplicitSpecialization)
    return;

  // Find the function body that we'll be substituting.
  const FunctionDecl *PatternDecl = Function->getTemplateInstantiationPattern();
  Stmt *Pattern = 0;
  if (PatternDecl)
    Pattern = PatternDecl->getBody(PatternDecl);

  if (!Pattern) {
    if (DefinitionRequired) {
      if (Function->getPrimaryTemplate())
        Diag(PointOfInstantiation, 
             diag::err_explicit_instantiation_undefined_func_template)
          << Function->getPrimaryTemplate();
      else
        Diag(PointOfInstantiation, 
             diag::err_explicit_instantiation_undefined_member)
          << 1 << Function->getDeclName() << Function->getDeclContext();
      
      if (PatternDecl)
        Diag(PatternDecl->getLocation(), 
             diag::note_explicit_instantiation_here);
      Function->setInvalidDecl();
    } else if (Function->getTemplateSpecializationKind()
                 == TSK_ExplicitInstantiationDefinition) {
      PendingInstantiations.push_back(
        std::make_pair(Function, PointOfInstantiation));
    }

    return;
  }

  // C++0x [temp.explicit]p9:
  //   Except for inline functions, other explicit instantiation declarations
  //   have the effect of suppressing the implicit instantiation of the entity
  //   to which they refer.
  if (Function->getTemplateSpecializationKind()
        == TSK_ExplicitInstantiationDeclaration &&
      !PatternDecl->isInlined())
    return;

  InstantiatingTemplate Inst(*this, PointOfInstantiation, Function);
  if (Inst)
    return;  
  
  // If we're performing recursive template instantiation, create our own
  // queue of pending implicit instantiations that we will instantiate later,
  // while we're still within our own instantiation context.
  std::deque<PendingImplicitInstantiation> SavedPendingInstantiations;
  if (Recursive)
    PendingInstantiations.swap(SavedPendingInstantiations);

  EnterExpressionEvaluationContext EvalContext(*this, 
                                               Sema::PotentiallyEvaluated);
  ActOnStartOfFunctionDef(0, Function);

  // Introduce a new scope where local variable instantiations will be
  // recorded, unless we're actually a member function within a local
  // class, in which case we need to merge our results with the parent
  // scope (of the enclosing function).
  bool MergeWithParentScope = false;
  if (CXXRecordDecl *Rec = dyn_cast<CXXRecordDecl>(Function->getDeclContext()))
    MergeWithParentScope = Rec->isLocalClass();

  LocalInstantiationScope Scope(*this, MergeWithParentScope);

  // Introduce the instantiated function parameters into the local
  // instantiation scope, and set the parameter names to those used
  // in the template.
  for (unsigned I = 0, N = PatternDecl->getNumParams(); I != N; ++I) {
    const ParmVarDecl *PatternParam = PatternDecl->getParamDecl(I);
    ParmVarDecl *FunctionParam = Function->getParamDecl(I);
    FunctionParam->setDeclName(PatternParam->getDeclName());
    Scope.InstantiatedLocal(PatternParam, FunctionParam);
  }

  // Enter the scope of this instantiation. We don't use
  // PushDeclContext because we don't have a scope.
  DeclContext *PreviousContext = CurContext;
  CurContext = Function;

  MultiLevelTemplateArgumentList TemplateArgs =
    getTemplateInstantiationArgs(Function, 0, false, PatternDecl);

  // If this is a constructor, instantiate the member initializers.
  if (const CXXConstructorDecl *Ctor =
        dyn_cast<CXXConstructorDecl>(PatternDecl)) {
    InstantiateMemInitializers(cast<CXXConstructorDecl>(Function), Ctor,
                               TemplateArgs);
  }

  // Instantiate the function body.
  StmtResult Body = SubstStmt(Pattern, TemplateArgs);

  if (Body.isInvalid())
    Function->setInvalidDecl();
  
  ActOnFinishFunctionBody(Function, Body.get(),
                          /*IsInstantiation=*/true);

  PerformDependentDiagnostics(PatternDecl, TemplateArgs);

  CurContext = PreviousContext;

  DeclGroupRef DG(Function);
  Consumer.HandleTopLevelDecl(DG);

  // This class may have local implicit instantiations that need to be
  // instantiation within this scope.
  PerformPendingInstantiations(/*LocalOnly=*/true);
  Scope.Exit();

  if (Recursive) {
    // Instantiate any pending implicit instantiations found during the
    // instantiation of this template.
    PerformPendingInstantiations();

    // Restore the set of pending implicit instantiations.
    PendingInstantiations.swap(SavedPendingInstantiations);
  }
}

/// \brief Instantiate the definition of the given variable from its
/// template.
///
/// \param PointOfInstantiation the point at which the instantiation was
/// required. Note that this is not precisely a "point of instantiation"
/// for the function, but it's close.
///
/// \param Var the already-instantiated declaration of a static member
/// variable of a class template specialization.
///
/// \param Recursive if true, recursively instantiates any functions that
/// are required by this instantiation.
///
/// \param DefinitionRequired if true, then we are performing an explicit
/// instantiation where an out-of-line definition of the member variable
/// is required. Complain if there is no such definition.
void Sema::InstantiateStaticDataMemberDefinition(
                                          SourceLocation PointOfInstantiation,
                                                 VarDecl *Var,
                                                 bool Recursive,
                                                 bool DefinitionRequired) {
  if (Var->isInvalidDecl())
    return;

  // Find the out-of-line definition of this static data member.
  VarDecl *Def = Var->getInstantiatedFromStaticDataMember();
  assert(Def && "This data member was not instantiated from a template?");
  assert(Def->isStaticDataMember() && "Not a static data member?");  
  Def = Def->getOutOfLineDefinition();

  if (!Def) {
    // We did not find an out-of-line definition of this static data member,
    // so we won't perform any instantiation. Rather, we rely on the user to
    // instantiate this definition (or provide a specialization for it) in
    // another translation unit.
    if (DefinitionRequired) {
      Def = Var->getInstantiatedFromStaticDataMember();
      Diag(PointOfInstantiation, 
           diag::err_explicit_instantiation_undefined_member)
        << 2 << Var->getDeclName() << Var->getDeclContext();
      Diag(Def->getLocation(), diag::note_explicit_instantiation_here);
    } else if (Var->getTemplateSpecializationKind()
                 == TSK_ExplicitInstantiationDefinition) {
      PendingInstantiations.push_back(
        std::make_pair(Var, PointOfInstantiation));
    }

    return;
  }

  // Never instantiate an explicit specialization.
  if (Var->getTemplateSpecializationKind() == TSK_ExplicitSpecialization)
    return;
  
  // C++0x [temp.explicit]p9:
  //   Except for inline functions, other explicit instantiation declarations
  //   have the effect of suppressing the implicit instantiation of the entity
  //   to which they refer.
  if (Var->getTemplateSpecializationKind() 
        == TSK_ExplicitInstantiationDeclaration)
    return;

  InstantiatingTemplate Inst(*this, PointOfInstantiation, Var);
  if (Inst)
    return;

  // If we're performing recursive template instantiation, create our own
  // queue of pending implicit instantiations that we will instantiate later,
  // while we're still within our own instantiation context.
  std::deque<PendingImplicitInstantiation> SavedPendingInstantiations;
  if (Recursive)
    PendingInstantiations.swap(SavedPendingInstantiations);

  // Enter the scope of this instantiation. We don't use
  // PushDeclContext because we don't have a scope.
  DeclContext *PreviousContext = CurContext;
  CurContext = Var->getDeclContext();

  VarDecl *OldVar = Var;
  Var = cast_or_null<VarDecl>(SubstDecl(Def, Var->getDeclContext(),
                                          getTemplateInstantiationArgs(Var)));
  CurContext = PreviousContext;

  if (Var) {
    MemberSpecializationInfo *MSInfo = OldVar->getMemberSpecializationInfo();
    assert(MSInfo && "Missing member specialization information?");
    Var->setTemplateSpecializationKind(MSInfo->getTemplateSpecializationKind(),
                                       MSInfo->getPointOfInstantiation());
    DeclGroupRef DG(Var);
    Consumer.HandleTopLevelDecl(DG);
  }

  if (Recursive) {
    // Instantiate any pending implicit instantiations found during the
    // instantiation of this template.
    PerformPendingInstantiations();

    // Restore the set of pending implicit instantiations.
    PendingInstantiations.swap(SavedPendingInstantiations);
  }
}

void
Sema::InstantiateMemInitializers(CXXConstructorDecl *New,
                                 const CXXConstructorDecl *Tmpl,
                           const MultiLevelTemplateArgumentList &TemplateArgs) {

  llvm::SmallVector<MemInitTy*, 4> NewInits;
  bool AnyErrors = false;
  
  // Instantiate all the initializers.
  for (CXXConstructorDecl::init_const_iterator Inits = Tmpl->init_begin(),
                                            InitsEnd = Tmpl->init_end();
       Inits != InitsEnd; ++Inits) {
    CXXBaseOrMemberInitializer *Init = *Inits;

    // Only instantiate written initializers, let Sema re-construct implicit
    // ones.
    if (!Init->isWritten())
      continue;

    SourceLocation LParenLoc, RParenLoc;
    ASTOwningVector<Expr*> NewArgs(*this);
    llvm::SmallVector<SourceLocation, 4> CommaLocs;

    // Instantiate the initializer.
    if (InstantiateInitializer(*this, Init->getInit(), TemplateArgs, 
                               LParenLoc, CommaLocs, NewArgs, RParenLoc)) {
      AnyErrors = true;
      continue;
    }
    
    MemInitResult NewInit;
    if (Init->isBaseInitializer()) {
      TypeSourceInfo *BaseTInfo = SubstType(Init->getBaseClassInfo(), 
                                            TemplateArgs, 
                                            Init->getSourceLocation(), 
                                            New->getDeclName());
      if (!BaseTInfo) {
        AnyErrors = true;
        New->setInvalidDecl();
        continue;
      }
      
      NewInit = BuildBaseInitializer(BaseTInfo->getType(), BaseTInfo,
                                     (Expr **)NewArgs.data(),
                                     NewArgs.size(),
                                     Init->getLParenLoc(),
                                     Init->getRParenLoc(),
                                     New->getParent());
    } else if (Init->isMemberInitializer()) {
      FieldDecl *Member;

      // Is this an anonymous union?
      if (FieldDecl *UnionInit = Init->getAnonUnionMember())
        Member = cast<FieldDecl>(FindInstantiatedDecl(Init->getMemberLocation(),
                                                      UnionInit, TemplateArgs));
      else
        Member = cast<FieldDecl>(FindInstantiatedDecl(Init->getMemberLocation(),
                                                      Init->getMember(),
                                                      TemplateArgs));

      NewInit = BuildMemberInitializer(Member, (Expr **)NewArgs.data(),
                                       NewArgs.size(),
                                       Init->getSourceLocation(),
                                       Init->getLParenLoc(),
                                       Init->getRParenLoc());
    }

    if (NewInit.isInvalid()) {
      AnyErrors = true;
      New->setInvalidDecl();
    } else {
      // FIXME: It would be nice if ASTOwningVector had a release function.
      NewArgs.take();

      NewInits.push_back((MemInitTy *)NewInit.get());
    }
  }

  // Assign all the initializers to the new constructor.
  ActOnMemInitializers(New,
                       /*FIXME: ColonLoc */
                       SourceLocation(),
                       NewInits.data(), NewInits.size(),
                       AnyErrors);
}

// TODO: this could be templated if the various decl types used the
// same method name.
static bool isInstantiationOf(ClassTemplateDecl *Pattern,
                              ClassTemplateDecl *Instance) {
  Pattern = Pattern->getCanonicalDecl();

  do {
    Instance = Instance->getCanonicalDecl();
    if (Pattern == Instance) return true;
    Instance = Instance->getInstantiatedFromMemberTemplate();
  } while (Instance);

  return false;
}

static bool isInstantiationOf(FunctionTemplateDecl *Pattern,
                              FunctionTemplateDecl *Instance) {
  Pattern = Pattern->getCanonicalDecl();
  
  do {
    Instance = Instance->getCanonicalDecl();
    if (Pattern == Instance) return true;
    Instance = Instance->getInstantiatedFromMemberTemplate();
  } while (Instance);
  
  return false;
}

static bool 
isInstantiationOf(ClassTemplatePartialSpecializationDecl *Pattern,
                  ClassTemplatePartialSpecializationDecl *Instance) {
  Pattern 
    = cast<ClassTemplatePartialSpecializationDecl>(Pattern->getCanonicalDecl());
  do {
    Instance = cast<ClassTemplatePartialSpecializationDecl>(
                                                Instance->getCanonicalDecl());
    if (Pattern == Instance)
      return true;
    Instance = Instance->getInstantiatedFromMember();
  } while (Instance);
  
  return false;
}

static bool isInstantiationOf(CXXRecordDecl *Pattern,
                              CXXRecordDecl *Instance) {
  Pattern = Pattern->getCanonicalDecl();

  do {
    Instance = Instance->getCanonicalDecl();
    if (Pattern == Instance) return true;
    Instance = Instance->getInstantiatedFromMemberClass();
  } while (Instance);

  return false;
}

static bool isInstantiationOf(FunctionDecl *Pattern,
                              FunctionDecl *Instance) {
  Pattern = Pattern->getCanonicalDecl();

  do {
    Instance = Instance->getCanonicalDecl();
    if (Pattern == Instance) return true;
    Instance = Instance->getInstantiatedFromMemberFunction();
  } while (Instance);

  return false;
}

static bool isInstantiationOf(EnumDecl *Pattern,
                              EnumDecl *Instance) {
  Pattern = Pattern->getCanonicalDecl();

  do {
    Instance = Instance->getCanonicalDecl();
    if (Pattern == Instance) return true;
    Instance = Instance->getInstantiatedFromMemberEnum();
  } while (Instance);

  return false;
}

static bool isInstantiationOf(UsingShadowDecl *Pattern,
                              UsingShadowDecl *Instance,
                              ASTContext &C) {
  return C.getInstantiatedFromUsingShadowDecl(Instance) == Pattern;
}

static bool isInstantiationOf(UsingDecl *Pattern,
                              UsingDecl *Instance,
                              ASTContext &C) {
  return C.getInstantiatedFromUsingDecl(Instance) == Pattern;
}

static bool isInstantiationOf(UnresolvedUsingValueDecl *Pattern,
                              UsingDecl *Instance,
                              ASTContext &C) {
  return C.getInstantiatedFromUsingDecl(Instance) == Pattern;
}

static bool isInstantiationOf(UnresolvedUsingTypenameDecl *Pattern,
                              UsingDecl *Instance,
                              ASTContext &C) {
  return C.getInstantiatedFromUsingDecl(Instance) == Pattern;
}

static bool isInstantiationOfStaticDataMember(VarDecl *Pattern,
                                              VarDecl *Instance) {
  assert(Instance->isStaticDataMember());

  Pattern = Pattern->getCanonicalDecl();

  do {
    Instance = Instance->getCanonicalDecl();
    if (Pattern == Instance) return true;
    Instance = Instance->getInstantiatedFromStaticDataMember();
  } while (Instance);

  return false;
}

// Other is the prospective instantiation
// D is the prospective pattern
static bool isInstantiationOf(ASTContext &Ctx, NamedDecl *D, Decl *Other) {
  if (D->getKind() != Other->getKind()) {
    if (UnresolvedUsingTypenameDecl *UUD
          = dyn_cast<UnresolvedUsingTypenameDecl>(D)) {
      if (UsingDecl *UD = dyn_cast<UsingDecl>(Other)) {
        return isInstantiationOf(UUD, UD, Ctx);
      }
    }

    if (UnresolvedUsingValueDecl *UUD
          = dyn_cast<UnresolvedUsingValueDecl>(D)) {
      if (UsingDecl *UD = dyn_cast<UsingDecl>(Other)) {
        return isInstantiationOf(UUD, UD, Ctx);
      }
    }

    return false;
  }

  if (CXXRecordDecl *Record = dyn_cast<CXXRecordDecl>(Other))
    return isInstantiationOf(cast<CXXRecordDecl>(D), Record);

  if (FunctionDecl *Function = dyn_cast<FunctionDecl>(Other))
    return isInstantiationOf(cast<FunctionDecl>(D), Function);

  if (EnumDecl *Enum = dyn_cast<EnumDecl>(Other))
    return isInstantiationOf(cast<EnumDecl>(D), Enum);

  if (VarDecl *Var = dyn_cast<VarDecl>(Other))
    if (Var->isStaticDataMember())
      return isInstantiationOfStaticDataMember(cast<VarDecl>(D), Var);

  if (ClassTemplateDecl *Temp = dyn_cast<ClassTemplateDecl>(Other))
    return isInstantiationOf(cast<ClassTemplateDecl>(D), Temp);

  if (FunctionTemplateDecl *Temp = dyn_cast<FunctionTemplateDecl>(Other))
    return isInstantiationOf(cast<FunctionTemplateDecl>(D), Temp);

  if (ClassTemplatePartialSpecializationDecl *PartialSpec
        = dyn_cast<ClassTemplatePartialSpecializationDecl>(Other))
    return isInstantiationOf(cast<ClassTemplatePartialSpecializationDecl>(D),
                             PartialSpec);

  if (FieldDecl *Field = dyn_cast<FieldDecl>(Other)) {
    if (!Field->getDeclName()) {
      // This is an unnamed field.
      return Ctx.getInstantiatedFromUnnamedFieldDecl(Field) ==
        cast<FieldDecl>(D);
    }
  }

  if (UsingDecl *Using = dyn_cast<UsingDecl>(Other))
    return isInstantiationOf(cast<UsingDecl>(D), Using, Ctx);

  if (UsingShadowDecl *Shadow = dyn_cast<UsingShadowDecl>(Other))
    return isInstantiationOf(cast<UsingShadowDecl>(D), Shadow, Ctx);

  return D->getDeclName() && isa<NamedDecl>(Other) &&
    D->getDeclName() == cast<NamedDecl>(Other)->getDeclName();
}

template<typename ForwardIterator>
static NamedDecl *findInstantiationOf(ASTContext &Ctx,
                                      NamedDecl *D,
                                      ForwardIterator first,
                                      ForwardIterator last) {
  for (; first != last; ++first)
    if (isInstantiationOf(Ctx, D, *first))
      return cast<NamedDecl>(*first);

  return 0;
}

/// \brief Finds the instantiation of the given declaration context
/// within the current instantiation.
///
/// \returns NULL if there was an error
DeclContext *Sema::FindInstantiatedContext(SourceLocation Loc, DeclContext* DC,
                          const MultiLevelTemplateArgumentList &TemplateArgs) {
  if (NamedDecl *D = dyn_cast<NamedDecl>(DC)) {
    Decl* ID = FindInstantiatedDecl(Loc, D, TemplateArgs);
    return cast_or_null<DeclContext>(ID);
  } else return DC;
}

/// \brief Find the instantiation of the given declaration within the
/// current instantiation.
///
/// This routine is intended to be used when \p D is a declaration
/// referenced from within a template, that needs to mapped into the
/// corresponding declaration within an instantiation. For example,
/// given:
///
/// \code
/// template<typename T>
/// struct X {
///   enum Kind {
///     KnownValue = sizeof(T)
///   };
///
///   bool getKind() const { return KnownValue; }
/// };
///
/// template struct X<int>;
/// \endcode
///
/// In the instantiation of X<int>::getKind(), we need to map the
/// EnumConstantDecl for KnownValue (which refers to
/// X<T>::<Kind>::KnownValue) to its instantiation
/// (X<int>::<Kind>::KnownValue). InstantiateCurrentDeclRef() performs
/// this mapping from within the instantiation of X<int>.
NamedDecl *Sema::FindInstantiatedDecl(SourceLocation Loc, NamedDecl *D,
                          const MultiLevelTemplateArgumentList &TemplateArgs) {
  DeclContext *ParentDC = D->getDeclContext();
  if (isa<ParmVarDecl>(D) || isa<NonTypeTemplateParmDecl>(D) ||
      isa<TemplateTypeParmDecl>(D) || isa<TemplateTemplateParmDecl>(D) ||
      (ParentDC->isFunctionOrMethod() && ParentDC->isDependentContext())) {
    // D is a local of some kind. Look into the map of local
    // declarations to their instantiations.
    return cast<NamedDecl>(CurrentInstantiationScope->getInstantiationOf(D));
  }

  if (CXXRecordDecl *Record = dyn_cast<CXXRecordDecl>(D)) {
    if (!Record->isDependentContext())
      return D;
    
    // If the RecordDecl is actually the injected-class-name or a
    // "templated" declaration for a class template, class template
    // partial specialization, or a member class of a class template,
    // substitute into the injected-class-name of the class template
    // or partial specialization to find the new DeclContext.
    QualType T;
    ClassTemplateDecl *ClassTemplate = Record->getDescribedClassTemplate();
    
    if (ClassTemplate) {
      T = ClassTemplate->getInjectedClassNameSpecialization();
    } else if (ClassTemplatePartialSpecializationDecl *PartialSpec
                 = dyn_cast<ClassTemplatePartialSpecializationDecl>(Record)) {
      ClassTemplate = PartialSpec->getSpecializedTemplate();

      // If we call SubstType with an InjectedClassNameType here we
      // can end up in an infinite loop.
      T = Context.getTypeDeclType(Record);
      assert(isa<InjectedClassNameType>(T) &&
             "type of partial specialization is not an InjectedClassNameType");
      T = cast<InjectedClassNameType>(T)->getInjectedSpecializationType();
    }  
    
    if (!T.isNull()) {
      // Substitute into the injected-class-name to get the type
      // corresponding to the instantiation we want, which may also be
      // the current instantiation (if we're in a template
      // definition). This substitution should never fail, since we
      // know we can instantiate the injected-class-name or we
      // wouldn't have gotten to the injected-class-name!  

      // FIXME: Can we use the CurrentInstantiationScope to avoid this
      // extra instantiation in the common case?
      T = SubstType(T, TemplateArgs, SourceLocation(), DeclarationName());
      assert(!T.isNull() && "Instantiation of injected-class-name cannot fail.");
    
      if (!T->isDependentType()) {
        assert(T->isRecordType() && "Instantiation must produce a record type");
        return T->getAs<RecordType>()->getDecl();
      }
    
      // We are performing "partial" template instantiation to create
      // the member declarations for the members of a class template
      // specialization. Therefore, D is actually referring to something
      // in the current instantiation. Look through the current
      // context, which contains actual instantiations, to find the
      // instantiation of the "current instantiation" that D refers
      // to.
      bool SawNonDependentContext = false;
      for (DeclContext *DC = CurContext; !DC->isFileContext();
           DC = DC->getParent()) {
        if (ClassTemplateSpecializationDecl *Spec
                          = dyn_cast<ClassTemplateSpecializationDecl>(DC))
          if (isInstantiationOf(ClassTemplate, 
                                Spec->getSpecializedTemplate()))
            return Spec;

        if (!DC->isDependentContext())
          SawNonDependentContext = true;
      }

      // We're performing "instantiation" of a member of the current
      // instantiation while we are type-checking the
      // definition. Compute the declaration context and return that.
      assert(!SawNonDependentContext && 
             "No dependent context while instantiating record");
      DeclContext *DC = computeDeclContext(T);
      assert(DC && 
             "Unable to find declaration for the current instantiation");
      return cast<CXXRecordDecl>(DC);
    }

    // Fall through to deal with other dependent record types (e.g.,
    // anonymous unions in class templates).
  }

  if (!ParentDC->isDependentContext())
    return D;
  
  ParentDC = FindInstantiatedContext(Loc, ParentDC, TemplateArgs);
  if (!ParentDC)
    return 0;

  if (ParentDC != D->getDeclContext()) {
    // We performed some kind of instantiation in the parent context,
    // so now we need to look into the instantiated parent context to
    // find the instantiation of the declaration D.

    // If our context used to be dependent, we may need to instantiate
    // it before performing lookup into that context.
    if (CXXRecordDecl *Spec = dyn_cast<CXXRecordDecl>(ParentDC)) {
      if (!Spec->isDependentContext()) {
        QualType T = Context.getTypeDeclType(Spec);
        const RecordType *Tag = T->getAs<RecordType>();
        assert(Tag && "type of non-dependent record is not a RecordType");
        if (!Tag->isBeingDefined() &&
            RequireCompleteType(Loc, T, diag::err_incomplete_type))
          return 0;
      }
    }

    NamedDecl *Result = 0;
    if (D->getDeclName()) {
      DeclContext::lookup_result Found = ParentDC->lookup(D->getDeclName());
      Result = findInstantiationOf(Context, D, Found.first, Found.second);
    } else {
      // Since we don't have a name for the entity we're looking for,
      // our only option is to walk through all of the declarations to
      // find that name. This will occur in a few cases:
      //
      //   - anonymous struct/union within a template
      //   - unnamed class/struct/union/enum within a template
      //
      // FIXME: Find a better way to find these instantiations!
      Result = findInstantiationOf(Context, D,
                                   ParentDC->decls_begin(),
                                   ParentDC->decls_end());
    }

    // UsingShadowDecls can instantiate to nothing because of using hiding.
    assert((Result || isa<UsingShadowDecl>(D) || D->isInvalidDecl() ||
            cast<Decl>(ParentDC)->isInvalidDecl())
           && "Unable to find instantiation of declaration!");

    D = Result;
  }

  return D;
}

/// \brief Performs template instantiation for all implicit template
/// instantiations we have seen until this point.
void Sema::PerformPendingInstantiations(bool LocalOnly) {
  while (!PendingLocalImplicitInstantiations.empty() ||
         (!LocalOnly && !PendingInstantiations.empty())) {
    PendingImplicitInstantiation Inst;

    if (PendingLocalImplicitInstantiations.empty()) {
      Inst = PendingInstantiations.front();
      PendingInstantiations.pop_front();
    } else {
      Inst = PendingLocalImplicitInstantiations.front();
      PendingLocalImplicitInstantiations.pop_front();
    }

    // Instantiate function definitions
    if (FunctionDecl *Function = dyn_cast<FunctionDecl>(Inst.first)) {
      PrettyDeclStackTraceEntry CrashInfo(*this, Function, SourceLocation(),
                                          "instantiating function definition");
      bool DefinitionRequired = Function->getTemplateSpecializationKind() ==
                                TSK_ExplicitInstantiationDefinition;
      InstantiateFunctionDefinition(/*FIXME:*/Inst.second, Function, true,
                                    DefinitionRequired);
      continue;
    }

    // Instantiate static data member definitions.
    VarDecl *Var = cast<VarDecl>(Inst.first);
    assert(Var->isStaticDataMember() && "Not a static data member?");

    // Don't try to instantiate declarations if the most recent redeclaration
    // is invalid.
    if (Var->getMostRecentDeclaration()->isInvalidDecl())
      continue;

    // Check if the most recent declaration has changed the specialization kind
    // and removed the need for implicit instantiation.
    switch (Var->getMostRecentDeclaration()->getTemplateSpecializationKind()) {
    case TSK_Undeclared:
      assert(false && "Cannot instantitiate an undeclared specialization.");
    case TSK_ExplicitInstantiationDeclaration:
    case TSK_ExplicitSpecialization:
      continue;  // No longer need to instantiate this type.
    case TSK_ExplicitInstantiationDefinition:
      // We only need an instantiation if the pending instantiation *is* the
      // explicit instantiation.
      if (Var != Var->getMostRecentDeclaration()) continue;
    case TSK_ImplicitInstantiation:
      break;
    }

    PrettyDeclStackTraceEntry CrashInfo(*this, Var, Var->getLocation(),
                                        "instantiating static data member "
                                        "definition");

    bool DefinitionRequired = Var->getTemplateSpecializationKind() ==
                              TSK_ExplicitInstantiationDefinition;
    InstantiateStaticDataMemberDefinition(/*FIXME:*/Inst.second, Var, true,
                                          DefinitionRequired);
  }
}

void Sema::PerformDependentDiagnostics(const DeclContext *Pattern,
                       const MultiLevelTemplateArgumentList &TemplateArgs) {
  for (DeclContext::ddiag_iterator I = Pattern->ddiag_begin(),
         E = Pattern->ddiag_end(); I != E; ++I) {
    DependentDiagnostic *DD = *I;

    switch (DD->getKind()) {
    case DependentDiagnostic::Access:
      HandleDependentAccessCheck(*DD, TemplateArgs);
      break;
    }
  }
}

