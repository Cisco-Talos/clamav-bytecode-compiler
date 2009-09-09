//===--- TemplateName.h - C++ Template Name Representation-------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
//  This file defines the TemplateName interface and subclasses.
//
//===----------------------------------------------------------------------===//

#include "clang/AST/TemplateName.h"
#include "clang/AST/DeclTemplate.h"
#include "clang/AST/NestedNameSpecifier.h"
#include "clang/AST/PrettyPrinter.h"
#include "clang/Basic/LangOptions.h"
#include "llvm/Support/raw_ostream.h"
using namespace clang;

TemplateDecl *TemplateName::getAsTemplateDecl() const {
  if (TemplateDecl *Template = Storage.dyn_cast<TemplateDecl *>())
    return Template;
  
  if (QualifiedTemplateName *QTN = getAsQualifiedTemplateName())
    return QTN->getTemplateDecl();

  return 0;
}

OverloadedFunctionDecl *TemplateName::getAsOverloadedFunctionDecl() const {
  if (OverloadedFunctionDecl *Ovl 
        = Storage.dyn_cast<OverloadedFunctionDecl *>())
    return Ovl;
  
  if (QualifiedTemplateName *QTN = getAsQualifiedTemplateName())
    return QTN->getOverloadedFunctionDecl();
  
  return 0;
}

bool TemplateName::isDependent() const {
  if (TemplateDecl *Template = getAsTemplateDecl()) {
    return isa<TemplateTemplateParmDecl>(Template) || 
      Template->getDeclContext()->isDependentContext();
  }

  if (OverloadedFunctionDecl *Ovl = getAsOverloadedFunctionDecl())
    return Ovl->getDeclContext()->isDependentContext();
  
  return true;
}

void 
TemplateName::print(llvm::raw_ostream &OS, const PrintingPolicy &Policy,
                    bool SuppressNNS) const {
  if (TemplateDecl *Template = Storage.dyn_cast<TemplateDecl *>())
    OS << Template->getIdentifier()->getName();
  else if (OverloadedFunctionDecl *Ovl 
             = Storage.dyn_cast<OverloadedFunctionDecl *>())
    OS << Ovl->getNameAsString();
  else if (QualifiedTemplateName *QTN = getAsQualifiedTemplateName()) {
    if (!SuppressNNS)
      QTN->getQualifier()->print(OS, Policy);
    if (QTN->hasTemplateKeyword())
      OS << "template ";
    OS << QTN->getDecl()->getNameAsString();
  } else if (DependentTemplateName *DTN = getAsDependentTemplateName()) {
    if (!SuppressNNS && DTN->getQualifier())
      DTN->getQualifier()->print(OS, Policy);
    OS << "template ";
    // FIXME: Shouldn't we have a more general kind of name?
    OS << DTN->getName()->getName();
  }
}

void TemplateName::dump() const {
  LangOptions LO;  // FIXME!
  LO.CPlusPlus = true;
  LO.Bool = true;
  print(llvm::errs(), PrintingPolicy(LO));
}

TemplateDecl *QualifiedTemplateName::getTemplateDecl() const { 
  return dyn_cast<TemplateDecl>(Template); 
}

OverloadedFunctionDecl *
QualifiedTemplateName::getOverloadedFunctionDecl() const {
  return dyn_cast<OverloadedFunctionDecl>(Template); 
}

