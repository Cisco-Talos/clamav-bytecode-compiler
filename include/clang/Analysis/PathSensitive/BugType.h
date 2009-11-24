//===---  BugType.h - Bug Information Desciption ----------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
//  This file defines BugType, a class representing a bug type.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_CLANG_ANALYSIS_BUGTYPE
#define LLVM_CLANG_ANALYSIS_BUGTYPE

#include <llvm/ADT/FoldingSet.h>
#include <string>

namespace clang {

class BugReportEquivClass;
class BugReporter;
class BuiltinBugReport;
class BugReporterContext;
class ExplodedNode;
class GRExprEngine;

class BugType {
private:
  const std::string Name;
  const std::string Category;
  llvm::FoldingSet<BugReportEquivClass> EQClasses;
  friend class BugReporter;
  bool SuppressonSink;
public:
  BugType(const char *name, const char* cat)
    : Name(name), Category(cat), SuppressonSink(false) {}
  virtual ~BugType();

  // FIXME: Should these be made strings as well?
  llvm::StringRef getName() const { return Name; }
  llvm::StringRef getCategory() const { return Category; }
  
  /// isSuppressOnSink - Returns true if bug reports associated with this bug
  ///  type should be suppressed if the end node of the report is post-dominated
  ///  by a sink node.
  bool isSuppressOnSink() const { return SuppressonSink; }
  void setSuppressOnSink(bool x) { SuppressonSink = x; }

  virtual void FlushReports(BugReporter& BR);

  typedef llvm::FoldingSet<BugReportEquivClass>::iterator iterator;
  iterator begin() { return EQClasses.begin(); }
  iterator end() { return EQClasses.end(); }

  typedef llvm::FoldingSet<BugReportEquivClass>::const_iterator const_iterator;
  const_iterator begin() const { return EQClasses.begin(); }
  const_iterator end() const { return EQClasses.end(); }
};

class BuiltinBug : public BugType {
  GRExprEngine *Eng;
protected:
  const std::string desc;
public:
  BuiltinBug(const char *name, const char *description)
    : BugType(name, "Logic error"), Eng(0), desc(description) {}
  
  BuiltinBug(const char *name)
    : BugType(name, "Logic error"), Eng(0), desc(name) {}
  
  BuiltinBug(GRExprEngine *eng, const char* n, const char* d)
    : BugType(n, "Logic error"), Eng(eng), desc(d) {}

  BuiltinBug(GRExprEngine *eng, const char* n)
    : BugType(n, "Logic error"), Eng(eng), desc(n) {}

  llvm::StringRef getDescription() const { return desc; }

  virtual void FlushReportsImpl(BugReporter& BR, GRExprEngine& Eng) {}

  void FlushReports(BugReporter& BR) { FlushReportsImpl(BR, *Eng); }

  virtual void registerInitialVisitors(BugReporterContext& BRC,
                                       const ExplodedNode* N,
                                       BuiltinBugReport *R) {}

  template <typename ITER> void Emit(BugReporter& BR, ITER I, ITER E);
};

} // end clang namespace
#endif
