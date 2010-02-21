/*===-- CIndexDiagnostics.cpp - Diagnostics C Interface ---------*- C++ -*-===*\
|*                                                                            *|
|*                     The LLVM Compiler Infrastructure                       *|
|*                                                                            *|
|* This file is distributed under the University of Illinois Open Source      *|
|* License. See LICENSE.TXT for details.                                      *|
|*                                                                            *|
|*===----------------------------------------------------------------------===*|
|*                                                                            *|
|* Implements the diagnostic functions of the Clang C interface.              *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/
#include "CIndexDiagnostic.h"
#include "CIndexer.h"
#include "CXSourceLocation.h"

#include "clang/Frontend/FrontendDiagnostic.h"
#include "llvm/ADT/Twine.h"
#include "llvm/Support/MemoryBuffer.h"

using namespace clang;
using namespace clang::cxloc;
using namespace clang::cxstring;
using namespace llvm;

//-----------------------------------------------------------------------------
// C Interface Routines
//-----------------------------------------------------------------------------
extern "C" {

unsigned clang_getNumDiagnostics(CXTranslationUnit Unit) {
  ASTUnit *CXXUnit = static_cast<ASTUnit *>(Unit);
  return CXXUnit? CXXUnit->diag_size() : 0;
}

CXDiagnostic clang_getDiagnostic(CXTranslationUnit Unit, unsigned Index) {
  ASTUnit *CXXUnit = static_cast<ASTUnit *>(Unit);
  if (!CXXUnit || Index >= CXXUnit->diag_size())
    return 0;

  return new CXStoredDiagnostic(CXXUnit->diag_begin()[Index],
                                CXXUnit->getASTContext().getLangOptions());
}

void clang_disposeDiagnostic(CXDiagnostic Diagnostic) {
  CXStoredDiagnostic *Stored = static_cast<CXStoredDiagnostic *>(Diagnostic);
  delete Stored;
}

void clang_displayDiagnostic(CXDiagnostic Diagnostic, FILE *Out, 
                             unsigned Options) {
  if (!Diagnostic || !Out)
    return;

  CXDiagnosticSeverity Severity = clang_getDiagnosticSeverity(Diagnostic);

  // Ignore diagnostics that should be ignored.
  if (Severity == CXDiagnostic_Ignored)
    return;

  if (Options & CXDiagnostic_DisplaySourceLocation) {
    // Print source location (file:line), along with optional column
    // and source ranges.
    CXFile File;
    unsigned Line, Column;
    clang_getInstantiationLocation(clang_getDiagnosticLocation(Diagnostic),
                                   &File, &Line, &Column, 0);
    if (File) {
      CXString FName = clang_getFileName(File);
      fprintf(Out, "%s:%d:", clang_getCString(FName), Line);
      clang_disposeString(FName);
      if (Options & CXDiagnostic_DisplayColumn)
        fprintf(Out, "%d:", Column);

      if (Options & CXDiagnostic_DisplaySourceRanges) {
        unsigned N = clang_getDiagnosticNumRanges(Diagnostic);
        bool PrintedRange = false;
        for (unsigned I = 0; I != N; ++I) {
          CXFile StartFile, EndFile;
          CXSourceRange Range = clang_getDiagnosticRange(Diagnostic, I);
          
          unsigned StartLine, StartColumn, EndLine, EndColumn;
          clang_getInstantiationLocation(clang_getRangeStart(Range),
                                         &StartFile, &StartLine, &StartColumn,
                                         0);
          clang_getInstantiationLocation(clang_getRangeEnd(Range),
                                         &EndFile, &EndLine, &EndColumn, 0);
          
          if (StartFile != EndFile || StartFile != File)
            continue;
          
          fprintf(Out, "{%d:%d-%d:%d}", StartLine, StartColumn, 
                  EndLine, EndColumn);
          PrintedRange = true;
        }
        if (PrintedRange)
          fprintf(Out, ":");
      }
    }

    fprintf(Out, " ");
  }

  /* Print warning/error/etc. */
  switch (Severity) {
  case CXDiagnostic_Ignored: assert(0 && "impossible"); break;
  case CXDiagnostic_Note: fprintf(Out, "note: "); break;
  case CXDiagnostic_Warning: fprintf(Out, "warning: "); break;
  case CXDiagnostic_Error: fprintf(Out, "error: "); break;
  case CXDiagnostic_Fatal: fprintf(Out, "fatal error: "); break;
  }

  CXString Text = clang_getDiagnosticSpelling(Diagnostic);
  if (clang_getCString(Text))
    fprintf(Out, "%s\n", clang_getCString(Text));
  else
    fprintf(Out, "<no diagnostic text>\n");
  clang_disposeString(Text);

#ifdef LLVM_ON_WIN32
  // On Windows, force a flush, since there may be multiple copies of
  // stderr and stdout in the file system, all with different buffers
  // but writing to the same device.
  fflush(Out);
#endif
}

unsigned clang_defaultDiagnosticDisplayOptions() {
  return CXDiagnostic_DisplaySourceLocation | CXDiagnostic_DisplayColumn;
}

enum CXDiagnosticSeverity clang_getDiagnosticSeverity(CXDiagnostic Diag) {
  CXStoredDiagnostic *StoredDiag = static_cast<CXStoredDiagnostic *>(Diag);
  if (!StoredDiag)
    return CXDiagnostic_Ignored;

  switch (StoredDiag->Diag.getLevel()) {
  case Diagnostic::Ignored: return CXDiagnostic_Ignored;
  case Diagnostic::Note:    return CXDiagnostic_Note;
  case Diagnostic::Warning: return CXDiagnostic_Warning;
  case Diagnostic::Error:   return CXDiagnostic_Error;
  case Diagnostic::Fatal:   return CXDiagnostic_Fatal;
  }

  llvm_unreachable("Invalid diagnostic level");
  return CXDiagnostic_Ignored;
}

CXSourceLocation clang_getDiagnosticLocation(CXDiagnostic Diag) {
  CXStoredDiagnostic *StoredDiag = static_cast<CXStoredDiagnostic *>(Diag);
  if (!StoredDiag || StoredDiag->Diag.getLocation().isInvalid())
    return clang_getNullLocation();

  return translateSourceLocation(StoredDiag->Diag.getLocation().getManager(),
                                 StoredDiag->LangOpts,
                                 StoredDiag->Diag.getLocation());
}

CXString clang_getDiagnosticSpelling(CXDiagnostic Diag) {
  CXStoredDiagnostic *StoredDiag = static_cast<CXStoredDiagnostic *>(Diag);
  if (!StoredDiag)
    return createCXString("");

  return createCXString(StoredDiag->Diag.getMessage(), false);
}

unsigned clang_getDiagnosticNumRanges(CXDiagnostic Diag) {
  CXStoredDiagnostic *StoredDiag = static_cast<CXStoredDiagnostic *>(Diag);
  if (!StoredDiag || StoredDiag->Diag.getLocation().isInvalid())
    return 0;

  return StoredDiag->Diag.range_size();
}

CXSourceRange clang_getDiagnosticRange(CXDiagnostic Diag, unsigned Range) {
  CXStoredDiagnostic *StoredDiag = static_cast<CXStoredDiagnostic *>(Diag);
  if (!StoredDiag || Range >= StoredDiag->Diag.range_size() ||
      StoredDiag->Diag.getLocation().isInvalid())
    return clang_getNullRange();

  return translateSourceRange(StoredDiag->Diag.getLocation().getManager(),
                              StoredDiag->LangOpts,
                              StoredDiag->Diag.range_begin()[Range]);
}

unsigned clang_getDiagnosticNumFixIts(CXDiagnostic Diag) {
  CXStoredDiagnostic *StoredDiag = static_cast<CXStoredDiagnostic *>(Diag);
  if (!StoredDiag)
    return 0;

  return StoredDiag->Diag.fixit_size();
}

CXString clang_getDiagnosticFixIt(CXDiagnostic Diagnostic, unsigned FixIt,
                                  CXSourceRange *ReplacementRange) {
  CXStoredDiagnostic *StoredDiag
    = static_cast<CXStoredDiagnostic *>(Diagnostic);
  if (!StoredDiag || FixIt >= StoredDiag->Diag.fixit_size() ||
      StoredDiag->Diag.getLocation().isInvalid()) {
    if (ReplacementRange)
      *ReplacementRange = clang_getNullRange();

    return createCXString("");
  }

  const CodeModificationHint &Hint = StoredDiag->Diag.fixit_begin()[FixIt];
  if (ReplacementRange) {
    if (Hint.RemoveRange.isInvalid())  {
      // Create an empty range that refers to a single source
      // location (which is the insertion point).
      CXSourceRange Range = { 
        { (void *)&StoredDiag->Diag.getLocation().getManager(), 
          (void *)&StoredDiag->LangOpts },
        Hint.InsertionLoc.getRawEncoding(),
        Hint.InsertionLoc.getRawEncoding() 
      };

      *ReplacementRange = Range;
    } else {
      // Create a range that covers the entire replacement (or
      // removal) range, adjusting the end of the range to point to
      // the end of the token.
      *ReplacementRange
          = translateSourceRange(StoredDiag->Diag.getLocation().getManager(),
                                 StoredDiag->LangOpts,
                                 Hint.RemoveRange);
    }
  }

  return createCXString(Hint.CodeToInsert);
}

} // end extern "C"

void clang::LoadSerializedDiagnostics(const llvm::sys::Path &DiagnosticsPath,
                                      unsigned num_unsaved_files,
                                      struct CXUnsavedFile *unsaved_files,
                                      FileManager &FileMgr,
                                      SourceManager &SourceMgr,
                                     SmallVectorImpl<StoredDiagnostic> &Diags) {
  using llvm::MemoryBuffer;
  using llvm::StringRef;
  MemoryBuffer *F = MemoryBuffer::getFile(DiagnosticsPath.c_str());
  if (!F)
    return;

  // Enter the unsaved files into the file manager.
  for (unsigned I = 0; I != num_unsaved_files; ++I) {
    const FileEntry *File = FileMgr.getVirtualFile(unsaved_files[I].Filename,
                                                   unsaved_files[I].Length,
                                                   0);
    if (!File) {
      // FIXME: Hard to localize when we have no diagnostics engine!
      Diags.push_back(StoredDiagnostic(Diagnostic::Fatal,
                            (Twine("could not remap from missing file ") +
                                   unsaved_files[I].Filename).str()));
      delete F;
      return;
    }

    MemoryBuffer *Buffer
      = MemoryBuffer::getMemBuffer(unsaved_files[I].Contents,
                           unsaved_files[I].Contents + unsaved_files[I].Length);
    if (!Buffer) {
      delete F;
      return;
    }
    
    SourceMgr.overrideFileContents(File, Buffer);
  }

  // Parse the diagnostics, emitting them one by one until we've
  // exhausted the data.
  StringRef Buffer = F->getBuffer();
  const char *Memory = Buffer.data(), *MemoryEnd = Memory + Buffer.size();
  while (Memory != MemoryEnd) {
    StoredDiagnostic Stored = StoredDiagnostic::Deserialize(FileMgr, SourceMgr,
                                                            Memory, MemoryEnd);
    if (!Stored)
      break;

    Diags.push_back(Stored);
  }
  delete F;
}
