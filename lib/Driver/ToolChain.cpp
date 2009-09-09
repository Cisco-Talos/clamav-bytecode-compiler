//===--- ToolChain.cpp - Collections of tools for one platform ----------*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "clang/Driver/ToolChain.h"

#include "clang/Driver/Action.h"
#include "clang/Driver/Driver.h"
#include "clang/Driver/HostInfo.h"

using namespace clang::driver;

ToolChain::ToolChain(const HostInfo &_Host, const llvm::Triple &_Triple)
  : Host(_Host), Triple(_Triple) {
}

ToolChain::~ToolChain() {
}

llvm::sys::Path ToolChain::GetFilePath(const Compilation &C,
                                       const char *Name) const {
  return Host.getDriver().GetFilePath(Name, *this);

}

llvm::sys::Path ToolChain::GetProgramPath(const Compilation &C,
                                          const char *Name,
                                          bool WantFile) const {
  return Host.getDriver().GetProgramPath(Name, *this, WantFile);
}
