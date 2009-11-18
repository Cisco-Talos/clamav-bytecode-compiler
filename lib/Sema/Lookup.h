//===--- Lookup.h - Classes for name lookup ---------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines the LookupResult class, which is integral to
// Sema's name-lookup subsystem.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_CLANG_SEMA_LOOKUP_H
#define LLVM_CLANG_SEMA_LOOKUP_H

#include "Sema.h"

namespace clang {

/// @brief Represents the results of name lookup.
///
/// An instance of the LookupResult class captures the results of a
/// single name lookup, which can return no result (nothing found),
/// a single declaration, a set of overloaded functions, or an
/// ambiguity. Use the getKind() method to determine which of these
/// results occurred for a given lookup.
///
/// Any non-ambiguous lookup can be converted into a single
/// (possibly NULL) @c NamedDecl* via the getAsSingleDecl() method.
/// This permits the common-case usage in C and Objective-C where
/// name lookup will always return a single declaration.  Use of
/// this is largely deprecated; callers should handle the possibility
/// of multiple declarations.
class LookupResult {
public:
  enum LookupResultKind {
    /// @brief No entity found met the criteria.
    NotFound = 0,

    /// @brief Name lookup found a single declaration that met the
    /// criteria. getAsDecl will return this declaration.
    Found,

    /// @brief Name lookup found a set of overloaded functions that
    /// met the criteria. getAsDecl will turn this set of overloaded
    /// functions into an OverloadedFunctionDecl.
    FoundOverloaded,

    /// @brief Name lookup found an unresolvable value declaration
    /// and cannot yet complete.  This only happens in C++ dependent
    /// contexts with dependent using declarations.
    FoundUnresolvedValue,

    /// @brief Name lookup results in an ambiguity; use
    /// getAmbiguityKind to figure out what kind of ambiguity
    /// we have.
    Ambiguous
  };

  enum AmbiguityKind {
    /// Name lookup results in an ambiguity because multiple
    /// entities that meet the lookup criteria were found in
    /// subobjects of different types. For example:
    /// @code
    /// struct A { void f(int); }
    /// struct B { void f(double); }
    /// struct C : A, B { };
    /// void test(C c) {
    ///   c.f(0); // error: A::f and B::f come from subobjects of different
    ///           // types. overload resolution is not performed.
    /// }
    /// @endcode
    AmbiguousBaseSubobjectTypes,

    /// Name lookup results in an ambiguity because multiple
    /// nonstatic entities that meet the lookup criteria were found
    /// in different subobjects of the same type. For example:
    /// @code
    /// struct A { int x; };
    /// struct B : A { };
    /// struct C : A { };
    /// struct D : B, C { };
    /// int test(D d) {
    ///   return d.x; // error: 'x' is found in two A subobjects (of B and C)
    /// }
    /// @endcode
    AmbiguousBaseSubobjects,

    /// Name lookup results in an ambiguity because multiple definitions
    /// of entity that meet the lookup criteria were found in different
    /// declaration contexts.
    /// @code
    /// namespace A {
    ///   int i;
    ///   namespace B { int i; }
    ///   int test() {
    ///     using namespace B;
    ///     return i; // error 'i' is found in namespace A and A::B
    ///    }
    /// }
    /// @endcode
    AmbiguousReference,

    /// Name lookup results in an ambiguity because an entity with a
    /// tag name was hidden by an entity with an ordinary name from
    /// a different context.
    /// @code
    /// namespace A { struct Foo {}; }
    /// namespace B { void Foo(); }
    /// namespace C {
    ///   using namespace A;
    ///   using namespace B;
    /// }
    /// void test() {
    ///   C::Foo(); // error: tag 'A::Foo' is hidden by an object in a
    ///             // different namespace
    /// }
    /// @endcode
    AmbiguousTagHiding
  };

  /// A little identifier for flagging temporary lookup results.
  enum TemporaryToken {
    Temporary
  };

  typedef llvm::SmallVector<NamedDecl*, 4> DeclsTy;
  typedef DeclsTy::const_iterator iterator;

  LookupResult(Sema &SemaRef, DeclarationName Name, SourceLocation NameLoc,
               Sema::LookupNameKind LookupKind,
               Sema::RedeclarationKind Redecl = Sema::NotForRedeclaration)
    : ResultKind(NotFound),
      Paths(0),
      SemaRef(SemaRef),
      Name(Name),
      NameLoc(NameLoc),
      LookupKind(LookupKind),
      IDNS(0),
      Redecl(Redecl != Sema::NotForRedeclaration),
      HideTags(true),
      Diagnose(Redecl == Sema::NotForRedeclaration)
  {}

  /// Creates a temporary lookup result, initializing its core data
  /// using the information from another result.  Diagnostics are always
  /// disabled.
  LookupResult(TemporaryToken _, const LookupResult &Other)
    : ResultKind(NotFound),
      Paths(0),
      SemaRef(Other.SemaRef),
      Name(Other.Name),
      NameLoc(Other.NameLoc),
      LookupKind(Other.LookupKind),
      IDNS(Other.IDNS),
      Redecl(Other.Redecl),
      HideTags(Other.HideTags),
      Diagnose(false)
  {}

  ~LookupResult() {
    if (Diagnose) diagnose();
    if (Paths) deletePaths(Paths);
  }

  /// Gets the name to look up.
  DeclarationName getLookupName() const {
    return Name;
  }

  /// Gets the kind of lookup to perform.
  Sema::LookupNameKind getLookupKind() const {
    return LookupKind;
  }

  /// True if this lookup is just looking for an existing declaration.
  bool isForRedeclaration() const {
    return Redecl;
  }

  /// Sets whether tag declarations should be hidden by non-tag
  /// declarations during resolution.  The default is true.
  void setHideTags(bool Hide) {
    HideTags = Hide;
  }

  /// The identifier namespace of this lookup.  This information is
  /// private to the lookup routines.
  unsigned getIdentifierNamespace() const {
    assert(IDNS);
    return IDNS;
  }

  void setIdentifierNamespace(unsigned NS) {
    IDNS = NS;
  }

  bool isAmbiguous() const {
    return getResultKind() == Ambiguous;
  }

  /// Determines if this names a single result which is not an
  /// unresolved value using decl.  If so, it is safe to call
  /// getFoundDecl().
  bool isSingleResult() const {
    return getResultKind() == Found;
  }

  LookupResultKind getResultKind() const {
    sanity();
    return ResultKind;
  }

  AmbiguityKind getAmbiguityKind() const {
    assert(isAmbiguous());
    return Ambiguity;
  }

  iterator begin() const { return Decls.begin(); }
  iterator end() const { return Decls.end(); }

  /// \brief Return true if no decls were found
  bool empty() const { return Decls.empty(); }

  /// \brief Return the base paths structure that's associated with
  /// these results, or null if none is.
  CXXBasePaths *getBasePaths() const {
    return Paths;
  }

  /// \brief Add a declaration to these results.
  void addDecl(NamedDecl *D) {
    Decls.push_back(D);
    ResultKind = Found;
  }

  /// \brief Add all the declarations from another set of lookup
  /// results.
  void addAllDecls(const LookupResult &Other) {
    Decls.append(Other.begin(), Other.end());
    ResultKind = Found;
  }

  /// \brief Hides a set of declarations.
  template <class NamedDeclSet> void hideDecls(const NamedDeclSet &Set) {
    unsigned I = 0, N = Decls.size();
    while (I < N) {
      if (Set.count(Decls[I]))
        Decls[I] = Decls[--N];
      else
        I++;
    }
    Decls.set_size(N);
  }

  /// \brief Resolves the result kind of the lookup, possibly hiding
  /// decls.
  ///
  /// This should be called in any environment where lookup might
  /// generate multiple lookup results.
  void resolveKind();

  /// \brief Re-resolves the result kind of the lookup after a set of
  /// removals has been performed.
  void resolveKindAfterFilter() {
    if (Decls.empty())
      ResultKind = NotFound;
    else {
      ResultKind = Found;
      resolveKind();
    }
  }

  /// \brief Fetch this as an unambiguous single declaration
  /// (possibly an overloaded one).
  ///
  /// This is deprecated; users should be written to handle
  /// ambiguous and overloaded lookups.
  NamedDecl *getAsSingleDecl(ASTContext &Context) const;

  /// \brief Fetch the unique decl found by this lookup.  Asserts
  /// that one was found.
  ///
  /// This is intended for users who have examined the result kind
  /// and are certain that there is only one result.
  NamedDecl *getFoundDecl() const {
    assert(getResultKind() == Found
           && "getFoundDecl called on non-unique result");
    return Decls[0]->getUnderlyingDecl();
  }

  /// Fetches a representative decl.  Useful for lazy diagnostics.
  NamedDecl *getRepresentativeDecl() const {
    assert(!Decls.empty() && "cannot get representative of empty set");
    return Decls[0];
  }

  /// \brief Asks if the result is a single tag decl.
  bool isSingleTagDecl() const {
    return getResultKind() == Found && isa<TagDecl>(getFoundDecl());
  }

  /// \brief Make these results show that the name was found in
  /// base classes of different types.
  ///
  /// The given paths object is copied and invalidated.
  void setAmbiguousBaseSubobjectTypes(CXXBasePaths &P);

  /// \brief Make these results show that the name was found in
  /// distinct base classes of the same type.
  ///
  /// The given paths object is copied and invalidated.
  void setAmbiguousBaseSubobjects(CXXBasePaths &P);

  /// \brief Make these results show that the name was found in
  /// different contexts and a tag decl was hidden by an ordinary
  /// decl in a different context.
  void setAmbiguousQualifiedTagHiding() {
    setAmbiguous(AmbiguousTagHiding);
  }

  /// \brief Clears out any current state.
  void clear() {
    ResultKind = NotFound;
    Decls.clear();
    if (Paths) deletePaths(Paths);
    Paths = NULL;
  }

  /// \brief Clears out any current state and re-initializes for a
  /// different kind of lookup.
  void clear(Sema::LookupNameKind Kind) {
    clear();
    LookupKind = Kind;
  }

  void print(llvm::raw_ostream &);

  /// Suppress the diagnostics that would normally fire because of this
  /// lookup.  This happens during (e.g.) redeclaration lookups.
  void suppressDiagnostics() {
    Diagnose = false;
  }

  /// Sets a 'context' source range.
  void setContextRange(SourceRange SR) {
    NameContextRange = SR;
  }

  /// Gets the source range of the context of this name; for C++
  /// qualified lookups, this is the source range of the scope
  /// specifier.
  SourceRange getContextRange() const {
    return NameContextRange;
  }

  /// Gets the location of the identifier.  This isn't always defined:
  /// sometimes we're doing lookups on synthesized names.
  SourceLocation getNameLoc() const {
    return NameLoc;
  }

  /// A class for iterating through a result set and possibly
  /// filtering out results.  The results returned are possibly
  /// sugared.
  class Filter {
    LookupResult &Results;
    unsigned I;
    bool ErasedAny;
#ifndef NDEBUG
    bool CalledDone;
#endif
    
    friend class LookupResult;
    Filter(LookupResult &Results)
      : Results(Results), I(0), ErasedAny(false)
#ifndef NDEBUG
      , CalledDone(false)
#endif
    {}

  public:
#ifndef NDEBUG
    ~Filter() {
      assert(CalledDone &&
             "LookupResult::Filter destroyed without done() call");
    }
#endif

    bool hasNext() const {
      return I != Results.Decls.size();
    }

    NamedDecl *next() {
      assert(I < Results.Decls.size() && "next() called on empty filter");
      return Results.Decls[I++];
    }

    /// Erase the last element returned from this iterator.
    void erase() {
      Results.Decls[--I] = Results.Decls.back();
      Results.Decls.pop_back();
      ErasedAny = true;
    }

    void done() {
#ifndef NDEBUG
      assert(!CalledDone && "done() called twice");
      CalledDone = true;
#endif

      if (ErasedAny)
        Results.resolveKindAfterFilter();
    }
  };

  /// Create a filter for this result set.
  Filter makeFilter() {
    return Filter(*this);
  }

private:
  void diagnose() {
    if (isAmbiguous())
      SemaRef.DiagnoseAmbiguousLookup(*this);
  }

  void setAmbiguous(AmbiguityKind AK) {
    ResultKind = Ambiguous;
    Ambiguity = AK;
  }

  void addDeclsFromBasePaths(const CXXBasePaths &P);

  // Sanity checks.
  void sanity() const {
    assert(ResultKind != NotFound || Decls.size() == 0);
    assert(ResultKind != Found || Decls.size() == 1);
    assert(ResultKind == NotFound || ResultKind == Found ||
           ResultKind == FoundUnresolvedValue ||
           (ResultKind == Ambiguous && Ambiguity == AmbiguousBaseSubobjects)
           || Decls.size() > 1);
    assert((Paths != NULL) == (ResultKind == Ambiguous &&
                               (Ambiguity == AmbiguousBaseSubobjectTypes ||
                                Ambiguity == AmbiguousBaseSubobjects)));
  }

  static void deletePaths(CXXBasePaths *);

  // Results.
  LookupResultKind ResultKind;
  AmbiguityKind Ambiguity; // ill-defined unless ambiguous
  DeclsTy Decls;
  CXXBasePaths *Paths;

  // Parameters.
  Sema &SemaRef;
  DeclarationName Name;
  SourceLocation NameLoc;
  SourceRange NameContextRange;
  Sema::LookupNameKind LookupKind;
  unsigned IDNS; // ill-defined until set by lookup
  bool Redecl;

  /// \brief True if tag declarations should be hidden if non-tags
  ///   are present
  bool HideTags;

  bool Diagnose;
};

}

#endif
