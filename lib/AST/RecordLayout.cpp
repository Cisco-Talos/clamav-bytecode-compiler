//===-- RecordLayout.cpp - Layout information for a struct/union -*- C++ -*-==//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
//  This file defines the RecordLayout interface.
//
//===----------------------------------------------------------------------===//

#include "clang/AST/ASTContext.h"
#include "clang/AST/RecordLayout.h"

using namespace clang;

void ASTRecordLayout::Destroy(ASTContext &Ctx) {
  if (FieldOffsets)
    Ctx.Deallocate(FieldOffsets);
  if (CXXInfo)
    Ctx.Deallocate(CXXInfo);
  this->~ASTRecordLayout();
  Ctx.Deallocate(this);
}

ASTRecordLayout::ASTRecordLayout(ASTContext &Ctx, uint64_t size, unsigned alignment,
                unsigned datasize, const uint64_t *fieldoffsets,
                unsigned fieldcount)
  : Size(size), DataSize(datasize), FieldOffsets(0), Alignment(alignment),
    FieldCount(fieldcount), CXXInfo(0) {
  if (FieldCount > 0)  {
    FieldOffsets = new (Ctx) uint64_t[FieldCount];
    for (unsigned i = 0; i < FieldCount; ++i)
      FieldOffsets[i] = fieldoffsets[i];
  }
}

// Constructor for C++ records.
ASTRecordLayout::ASTRecordLayout(ASTContext &Ctx,
                       uint64_t size, unsigned alignment,
                       uint64_t datasize,
                       const uint64_t *fieldoffsets,
                       unsigned fieldcount,
                       uint64_t nonvirtualsize,
                       unsigned nonvirtualalign,
                       const PrimaryBaseInfo &PrimaryBase,
                       const std::pair<const CXXRecordDecl *, uint64_t> *bases,
                       unsigned numbases,
                       const std::pair<const CXXRecordDecl *, uint64_t> *vbases,
                       unsigned numvbases)
  : Size(size), DataSize(datasize), FieldOffsets(0), Alignment(alignment),
    FieldCount(fieldcount), CXXInfo(new (Ctx) CXXRecordLayoutInfo)
{
  if (FieldCount > 0)  {
    FieldOffsets = new (Ctx) uint64_t[FieldCount];
    for (unsigned i = 0; i < FieldCount; ++i)
      FieldOffsets[i] = fieldoffsets[i];
  }

  CXXInfo->PrimaryBase = PrimaryBase;
  CXXInfo->NonVirtualSize = nonvirtualsize;
  CXXInfo->NonVirtualAlign = nonvirtualalign;
  for (unsigned i = 0; i != numbases; ++i)
    CXXInfo->BaseOffsets[bases[i].first] = bases[i].second;
  for (unsigned i = 0; i != numvbases; ++i)
    CXXInfo->VBaseOffsets[vbases[i].first] = vbases[i].second;
}
