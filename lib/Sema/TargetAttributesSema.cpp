//===-- TargetAttributesSema.cpp - Encapsulate target attributes-*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains semantic analysis implementation for target-specific
// attributes.
//
//===----------------------------------------------------------------------===//

#include "Sema.h"
#include "TargetAttributesSema.h"
#include "clang/Basic/TargetInfo.h"
#include "llvm/ADT/Triple.h"

using namespace clang;

TargetAttributesSema::~TargetAttributesSema() {}
bool TargetAttributesSema::ProcessDeclAttribute(Scope *scope, Decl *D,
                                    const AttributeList &Attr, Sema &S) const {
  return false;
}

static void HandleMSP430InterruptAttr(Decl *d,
                                      const AttributeList &Attr, Sema &S) {
    // Check the attribute arguments.
    if (Attr.getNumArgs() != 1) {
      S.Diag(Attr.getLoc(), diag::err_attribute_wrong_number_arguments) << 1;
      return;
    }

    // FIXME: Check for decl - it should be void ()(void).

    Expr *NumParamsExpr = static_cast<Expr *>(Attr.getArg(0));
    llvm::APSInt NumParams(32);
    if (!NumParamsExpr->isIntegerConstantExpr(NumParams, S.Context)) {
      S.Diag(Attr.getLoc(), diag::err_attribute_argument_not_int)
        << "interrupt" << NumParamsExpr->getSourceRange();
      return;
    }

    unsigned Num = NumParams.getLimitedValue(255);
    if ((Num & 1) || Num > 30) {
      S.Diag(Attr.getLoc(), diag::err_attribute_argument_out_of_bounds)
        << "interrupt" << (int)NumParams.getSExtValue()
        << NumParamsExpr->getSourceRange();
      return;
    }

    d->addAttr(::new (S.Context) MSP430InterruptAttr(Num));
    d->addAttr(::new (S.Context) UsedAttr());
  }

namespace {
  class MSP430AttributesSema : public TargetAttributesSema {
  public:
    MSP430AttributesSema() { }
    bool ProcessDeclAttribute(Scope *scope, Decl *D,
                              const AttributeList &Attr, Sema &S) const {
      if (Attr.getName()->getName() == "interrupt") {
        HandleMSP430InterruptAttr(D, Attr, S);
        return true;
      }
      return false;
    }
  };
}

static void HandleX86ForceAlignArgPointerAttr(Decl *D,
                                              const AttributeList& Attr,
                                              Sema &S) {
  // Check the attribute arguments.
  if (Attr.getNumArgs() != 0) {
    S.Diag(Attr.getLoc(), diag::err_attribute_wrong_number_arguments) << 0;
    return;
  }

  // If we try to apply it to a function pointer, don't warn, but don't
  // do anything, either. It doesn't matter anyway, because there's nothing
  // special about calling a force_align_arg_pointer function.
  ValueDecl *VD = dyn_cast<ValueDecl>(D);
  if (VD && VD->getType()->isFunctionPointerType())
    return;
  // Also don't warn on function pointer typedefs.
  TypedefDecl *TD = dyn_cast<TypedefDecl>(D);
  if (TD && TD->getUnderlyingType()->isFunctionPointerType())
    return;
  // Attribute can only be applied to function types.
  if (!isa<FunctionDecl>(D)) {
    S.Diag(Attr.getLoc(), diag::warn_attribute_wrong_decl_type)
      << Attr.getName() << /* function */0;
    return;
  }

  D->addAttr(::new (S.Context) X86ForceAlignArgPointerAttr());
}

static void HandleDLLImportAttr(Decl *D, const AttributeList &Attr, Sema &S) {
  // check the attribute arguments.
  if (Attr.getNumArgs() != 0) {
    S.Diag(Attr.getLoc(), diag::err_attribute_wrong_number_arguments) << 0;
    return;
  }

  // Attribute can be applied only to functions or variables.
  if (isa<VarDecl>(D)) {
    D->addAttr(::new (S.Context) DLLImportAttr());
    return;
  }

  FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD) {
    S.Diag(Attr.getLoc(), diag::warn_attribute_wrong_decl_type)
      << Attr.getName() << 2 /*variable and function*/;
    return;
  }

  // Currently, the dllimport attribute is ignored for inlined functions.
  // Warning is emitted.
  if (FD->isInlineSpecified()) {
    S.Diag(Attr.getLoc(), diag::warn_attribute_ignored) << "dllimport";
    return;
  }

  // The attribute is also overridden by a subsequent declaration as dllexport.
  // Warning is emitted.
  for (AttributeList *nextAttr = Attr.getNext(); nextAttr;
       nextAttr = nextAttr->getNext()) {
    if (nextAttr->getKind() == AttributeList::AT_dllexport) {
      S.Diag(Attr.getLoc(), diag::warn_attribute_ignored) << "dllimport";
      return;
    }
  }

  if (D->getAttr<DLLExportAttr>()) {
    S.Diag(Attr.getLoc(), diag::warn_attribute_ignored) << "dllimport";
    return;
  }

  D->addAttr(::new (S.Context) DLLImportAttr());
}

static void HandleDLLExportAttr(Decl *D, const AttributeList &Attr, Sema &S) {
  // check the attribute arguments.
  if (Attr.getNumArgs() != 0) {
    S.Diag(Attr.getLoc(), diag::err_attribute_wrong_number_arguments) << 0;
    return;
  }

  // Attribute can be applied only to functions or variables.
  if (isa<VarDecl>(D)) {
    D->addAttr(::new (S.Context) DLLExportAttr());
    return;
  }

  FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD) {
    S.Diag(Attr.getLoc(), diag::warn_attribute_wrong_decl_type)
      << Attr.getName() << 2 /*variable and function*/;
    return;
  }

  // Currently, the dllexport attribute is ignored for inlined functions, unless
  // the -fkeep-inline-functions flag has been used. Warning is emitted;
  if (FD->isInlineSpecified()) {
    // FIXME: ... unless the -fkeep-inline-functions flag has been used.
    S.Diag(Attr.getLoc(), diag::warn_attribute_ignored) << "dllexport";
    return;
  }

  D->addAttr(::new (S.Context) DLLExportAttr());
}

namespace {
  class X86AttributesSema : public TargetAttributesSema {
  public:
    X86AttributesSema() { }
    bool ProcessDeclAttribute(Scope *scope, Decl *D,
                              const AttributeList &Attr, Sema &S) const {
      const llvm::Triple &Triple(S.Context.Target.getTriple());
      if (Triple.getOS() == llvm::Triple::Win32 ||
          Triple.getOS() == llvm::Triple::MinGW32 ||
          Triple.getOS() == llvm::Triple::MinGW64) {
        switch (Attr.getKind()) {
        case AttributeList::AT_dllimport: HandleDLLImportAttr(D, Attr, S);
                                          return true;
        case AttributeList::AT_dllexport: HandleDLLExportAttr(D, Attr, S);
                                          return true;
        default:                          break;
        }
      }
      if (Attr.getName()->getName() == "force_align_arg_pointer" ||
          Attr.getName()->getName() == "__force_align_arg_pointer__") {
        HandleX86ForceAlignArgPointerAttr(D, Attr, S);
        return true;
      }
      return false;
    }
  };
}

const TargetAttributesSema &Sema::getTargetAttributesSema() const {
  if (TheTargetAttributesSema)
    return *TheTargetAttributesSema;

  const llvm::Triple &Triple(Context.Target.getTriple());
  switch (Triple.getArch()) {
  default:
    return *(TheTargetAttributesSema = new TargetAttributesSema);

  case llvm::Triple::msp430:
    return *(TheTargetAttributesSema = new MSP430AttributesSema);
  case llvm::Triple::x86:
    return *(TheTargetAttributesSema = new X86AttributesSema);
  }
}

