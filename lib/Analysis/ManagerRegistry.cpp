//===- ManagerRegistry.cpp - Pluggble Analyzer module creators --*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
//  This file defines the pluggable analyzer module creators.
//
//===----------------------------------------------------------------------===//

#include "clang/Analysis/ManagerRegistry.h"

using namespace clang;

StoreManagerCreator ManagerRegistry::StoreMgrCreator = 0;

ConstraintManagerCreator ManagerRegistry::ConstraintMgrCreator = 0;
