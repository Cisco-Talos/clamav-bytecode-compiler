//===------- MicrosoftCXXABI.cpp - AST support for the Microsoft C++ ABI --===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This provides C++ AST support targetting the Microsoft Visual C++
// ABI.
//
//===----------------------------------------------------------------------===//

#include "CXXABI.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Type.h"
#include "clang/AST/DeclCXX.h"

using namespace clang;

namespace {
class MicrosoftCXXABI : public CXXABI {
  ASTContext &Context;
public:
  MicrosoftCXXABI(ASTContext &Ctx) : Context(Ctx) { }

  unsigned getMemberPointerSize(const MemberPointerType *MPT) const;
};
}

unsigned MicrosoftCXXABI::getMemberPointerSize(const MemberPointerType *MPT) const {
  QualType Pointee = MPT->getPointeeType();
  CXXRecordDecl *RD = MPT->getClass()->getAsCXXRecordDecl();
  if (RD->getNumVBases() > 0) {
    if (Pointee->isFunctionType())
      return 3;
    else
      return 2;
  } else if (RD->getNumBases() > 1 && Pointee->isFunctionType())
    return 2;
  return 1;
}

CXXABI *clang::CreateMicrosoftCXXABI(ASTContext &Ctx) {
  return new MicrosoftCXXABI(Ctx);
}

