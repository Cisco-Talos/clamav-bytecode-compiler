//===- CIndexInclusionStack.cpp - Clang-C Source Indexing Library ---------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines a callback mechanism for clients to get the inclusion
// stack from a translation unit.
//
//===----------------------------------------------------------------------===//

#include "CIndexer.h"
#include "CXSourceLocation.h"
#include "clang/AST/DeclVisitor.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/Support/raw_ostream.h"

extern "C" {
void clang_getInclusions(CXTranslationUnit TU, CXInclusionVisitor CB,
                         CXClientData clientData) {
  
  ASTUnit *CXXUnit = static_cast<ASTUnit *>(TU);
  SourceManager &SM = CXXUnit->getSourceManager();
  ASTContext &Ctx = CXXUnit->getASTContext();

  llvm::SmallVector<CXSourceLocation, 10> InclusionStack;
  unsigned i = SM.sloc_loaded_entry_size();
  unsigned n =  SM.sloc_entry_size();

  // In the case where all the SLocEntries are in an external source, traverse
  // those SLocEntries as well.  This is the case where we are looking
  // at the inclusion stack of an AST/PCH file.
  if (i >= n)
    i = 0;
  
  for ( ; i < n ; ++i) {

    const SrcMgr::SLocEntry &SL = SM.getSLocEntry(i);
    
    if (!SL.isFile())
      continue;

    const SrcMgr::FileInfo &FI = SL.getFile();
    if (!FI.getContentCache()->Entry)
      continue;
    
    // Build the inclusion stack.
    SourceLocation L = FI.getIncludeLoc();
    InclusionStack.clear();
    while (L.isValid()) {
      PresumedLoc PLoc = SM.getPresumedLoc(L);
      InclusionStack.push_back(cxloc::translateSourceLocation(Ctx, L));
      L = PLoc.getIncludeLoc();
    }
            
    // Callback to the client.
    // FIXME: We should have a function to construct CXFiles.
    CB((CXFile) FI.getContentCache()->Entry, 
       InclusionStack.data(), InclusionStack.size(), clientData);
  }    
}
} // end extern C
