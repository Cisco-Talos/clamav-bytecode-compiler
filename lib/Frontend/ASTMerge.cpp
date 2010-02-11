//===-- ASTMerge.cpp - AST Merging Frontent Action --------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
#include "clang/Frontend/ASTUnit.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendActions.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/ASTDiagnostic.h"
#include "clang/AST/ASTImporter.h"

using namespace clang;

ASTConsumer *ASTMergeAction::CreateASTConsumer(CompilerInstance &CI,
                                               llvm::StringRef InFile) {
  return AdaptedAction->CreateASTConsumer(CI, InFile);
}

bool ASTMergeAction::BeginSourceFileAction(CompilerInstance &CI,
                                           llvm::StringRef Filename) {
  // FIXME: This is a hack. We need a better way to communicate the
  // AST file, compiler instance, and file name than member variables
  // of FrontendAction.
  AdaptedAction->setCurrentFile(getCurrentFile(), takeCurrentASTUnit());
  AdaptedAction->setCompilerInstance(&CI);
  return AdaptedAction->BeginSourceFileAction(CI, Filename);
}

void ASTMergeAction::ExecuteAction() {
  CompilerInstance &CI = getCompilerInstance();
  CI.getDiagnostics().getClient()->BeginSourceFile(
                                         CI.getASTContext().getLangOptions());
  CI.getDiagnostics().SetArgToStringFn(&FormatASTNodeDiagnosticArgument,
                                       &CI.getASTContext());
  for (unsigned I = 0, N = ASTFiles.size(); I != N; ++I) {
    ASTUnit *Unit = ASTUnit::LoadFromPCHFile(ASTFiles[I], CI.getDiagnostics(),
                                             false, true);
    if (!Unit)
      continue;

    ASTImporter Importer(CI.getDiagnostics(),
                         CI.getASTContext(), 
                         CI.getFileManager(),
                         Unit->getASTContext(), 
                         Unit->getFileManager());

    TranslationUnitDecl *TU = Unit->getASTContext().getTranslationUnitDecl();
    for (DeclContext::decl_iterator D = TU->decls_begin(), 
                                 DEnd = TU->decls_end();
         D != DEnd; ++D) {
      // FIXME: We only merge variables whose names start with x and functions
      // whose names start with 'f'. Why would anyone want anything else?
      if (VarDecl *VD = dyn_cast<VarDecl>(*D)) {
        if (VD->getIdentifier() && 
            *VD->getIdentifier()->getNameStart() == 'x') {
          Decl *Merged = Importer.Import(VD);
          (void)Merged;
        }
      } else if (FunctionDecl *FD = dyn_cast<FunctionDecl>(*D)) {
        if (FD->getIdentifier() &&
            *FD->getIdentifier()->getNameStart() == 'f') {
          Decl *Merged = Importer.Import(FD);
          (void)Merged;
        }
      }
    }

    delete Unit;
  }

  AdaptedAction->ExecuteAction();
  CI.getDiagnostics().getClient()->EndSourceFile();
}

void ASTMergeAction::EndSourceFileAction() {
  return AdaptedAction->EndSourceFileAction();
}

ASTMergeAction::ASTMergeAction(FrontendAction *AdaptedAction,
                               std::string *ASTFiles, unsigned NumASTFiles)
  : AdaptedAction(AdaptedAction), ASTFiles(ASTFiles, ASTFiles + NumASTFiles) {
  assert(AdaptedAction && "ASTMergeAction needs an action to adapt");
}

ASTMergeAction::~ASTMergeAction() { 
  delete AdaptedAction;
}

bool ASTMergeAction::usesPreprocessorOnly() const {
  return AdaptedAction->usesPreprocessorOnly();
}

bool ASTMergeAction::usesCompleteTranslationUnit() {
  return AdaptedAction->usesCompleteTranslationUnit();
}

bool ASTMergeAction::hasPCHSupport() const {
  return AdaptedAction->hasPCHSupport();
}

bool ASTMergeAction::hasASTSupport() const {
  return AdaptedAction->hasASTSupport();
}

bool ASTMergeAction::hasCodeCompletionSupport() const {
  return AdaptedAction->hasCodeCompletionSupport();
}
