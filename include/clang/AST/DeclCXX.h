//===-- DeclCXX.h - Classes for representing C++ declarations -*- C++ -*-=====//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
//  This file defines the C++ Decl subclasses.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_CLANG_AST_DECLCXX_H
#define LLVM_CLANG_AST_DECLCXX_H

#include "clang/AST/Expr.h"
#include "clang/AST/Decl.h"
#include "clang/AST/UnresolvedSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/SmallPtrSet.h"

namespace clang {

class ClassTemplateDecl;
class ClassTemplateSpecializationDecl;
class CXXBasePath;
class CXXBasePaths;
class CXXConstructorDecl;
class CXXConversionDecl;
class CXXDestructorDecl;
class CXXMethodDecl;
class CXXRecordDecl;
class CXXMemberLookupCriteria;
  
/// \brief Represents any kind of function declaration, whether it is a
/// concrete function or a function template.
class AnyFunctionDecl {
  NamedDecl *Function;

  AnyFunctionDecl(NamedDecl *ND) : Function(ND) { }

public:
  AnyFunctionDecl(FunctionDecl *FD) : Function(FD) { }
  AnyFunctionDecl(FunctionTemplateDecl *FTD);

  /// \brief Implicily converts any function or function template into a
  /// named declaration.
  operator NamedDecl *() const { return Function; }

  /// \brief Retrieve the underlying function or function template.
  NamedDecl *get() const { return Function; }

  static AnyFunctionDecl getFromNamedDecl(NamedDecl *ND) {
    return AnyFunctionDecl(ND);
  }
};

} // end namespace clang

namespace llvm {
  /// Implement simplify_type for AnyFunctionDecl, so that we can dyn_cast from
  /// AnyFunctionDecl to any function or function template declaration.
  template<> struct simplify_type<const ::clang::AnyFunctionDecl> {
    typedef ::clang::NamedDecl* SimpleType;
    static SimpleType getSimplifiedValue(const ::clang::AnyFunctionDecl &Val) {
      return Val;
    }
  };
  template<> struct simplify_type< ::clang::AnyFunctionDecl>
  : public simplify_type<const ::clang::AnyFunctionDecl> {};

  // Provide PointerLikeTypeTraits for non-cvr pointers.
  template<>
  class PointerLikeTypeTraits< ::clang::AnyFunctionDecl> {
  public:
    static inline void *getAsVoidPointer(::clang::AnyFunctionDecl F) {
      return F.get();
    }
    static inline ::clang::AnyFunctionDecl getFromVoidPointer(void *P) {
      return ::clang::AnyFunctionDecl::getFromNamedDecl(
                                      static_cast< ::clang::NamedDecl*>(P));
    }

    enum { NumLowBitsAvailable = 2 };
  };

} // end namespace llvm

namespace clang {

/// CXXBaseSpecifier - A base class of a C++ class.
///
/// Each CXXBaseSpecifier represents a single, direct base class (or
/// struct) of a C++ class (or struct). It specifies the type of that
/// base class, whether it is a virtual or non-virtual base, and what
/// level of access (public, protected, private) is used for the
/// derivation. For example:
///
/// @code
///   class A { };
///   class B { };
///   class C : public virtual A, protected B { };
/// @endcode
///
/// In this code, C will have two CXXBaseSpecifiers, one for "public
/// virtual A" and the other for "protected B".
class CXXBaseSpecifier {
  /// Range - The source code range that covers the full base
  /// specifier, including the "virtual" (if present) and access
  /// specifier (if present).
  // FIXME: Move over to a TypeLoc!
  SourceRange Range;

  /// Virtual - Whether this is a virtual base class or not.
  bool Virtual : 1;

  /// BaseOfClass - Whether this is the base of a class (true) or of a
  /// struct (false). This determines the mapping from the access
  /// specifier as written in the source code to the access specifier
  /// used for semantic analysis.
  bool BaseOfClass : 1;

  /// Access - Access specifier as written in the source code (which
  /// may be AS_none). The actual type of data stored here is an
  /// AccessSpecifier, but we use "unsigned" here to work around a
  /// VC++ bug.
  unsigned Access : 2;

  /// BaseType - The type of the base class. This will be a class or
  /// struct (or a typedef of such).
  QualType BaseType;

public:
  CXXBaseSpecifier() { }

  CXXBaseSpecifier(SourceRange R, bool V, bool BC, AccessSpecifier A, QualType T)
    : Range(R), Virtual(V), BaseOfClass(BC), Access(A), BaseType(T) { }

  /// getSourceRange - Retrieves the source range that contains the
  /// entire base specifier.
  SourceRange getSourceRange() const { return Range; }

  /// isVirtual - Determines whether the base class is a virtual base
  /// class (or not).
  bool isVirtual() const { return Virtual; }

  /// \brief Determine whether this base class if a base of a class declared
  /// with the 'class' keyword (vs. one declared with the 'struct' keyword).
  bool isBaseOfClass() const { return BaseOfClass; }
  
  /// getAccessSpecifier - Returns the access specifier for this base
  /// specifier. This is the actual base specifier as used for
  /// semantic analysis, so the result can never be AS_none. To
  /// retrieve the access specifier as written in the source code, use
  /// getAccessSpecifierAsWritten().
  AccessSpecifier getAccessSpecifier() const {
    if ((AccessSpecifier)Access == AS_none)
      return BaseOfClass? AS_private : AS_public;
    else
      return (AccessSpecifier)Access;
  }

  /// getAccessSpecifierAsWritten - Retrieves the access specifier as
  /// written in the source code (which may mean that no access
  /// specifier was explicitly written). Use getAccessSpecifier() to
  /// retrieve the access specifier for use in semantic analysis.
  AccessSpecifier getAccessSpecifierAsWritten() const {
    return (AccessSpecifier)Access;
  }

  /// getType - Retrieves the type of the base class. This type will
  /// always be an unqualified class type.
  QualType getType() const { return BaseType; }
};

/// CXXRecordDecl - Represents a C++ struct/union/class.
/// FIXME: This class will disappear once we've properly taught RecordDecl
/// to deal with C++-specific things.
class CXXRecordDecl : public RecordDecl {

  friend void TagDecl::startDefinition();

  struct DefinitionData {
    DefinitionData(CXXRecordDecl *D);

    /// UserDeclaredConstructor - True when this class has a
    /// user-declared constructor.
    bool UserDeclaredConstructor : 1;

    /// UserDeclaredCopyConstructor - True when this class has a
    /// user-declared copy constructor.
    bool UserDeclaredCopyConstructor : 1;

    /// UserDeclaredCopyAssignment - True when this class has a
    /// user-declared copy assignment operator.
    bool UserDeclaredCopyAssignment : 1;

    /// UserDeclaredDestructor - True when this class has a
    /// user-declared destructor.
    bool UserDeclaredDestructor : 1;

    /// Aggregate - True when this class is an aggregate.
    bool Aggregate : 1;

    /// PlainOldData - True when this class is a POD-type.
    bool PlainOldData : 1;

    /// Empty - true when this class is empty for traits purposes,
    /// i.e. has no data members other than 0-width bit-fields, has no
    /// virtual function/base, and doesn't inherit from a non-empty
    /// class. Doesn't take union-ness into account.
    bool Empty : 1;

    /// Polymorphic - True when this class is polymorphic, i.e. has at
    /// least one virtual member or derives from a polymorphic class.
    bool Polymorphic : 1;

    /// Abstract - True when this class is abstract, i.e. has at least
    /// one pure virtual function, (that can come from a base class).
    bool Abstract : 1;

    /// HasTrivialConstructor - True when this class has a trivial constructor.
    ///
    /// C++ [class.ctor]p5.  A constructor is trivial if it is an
    /// implicitly-declared default constructor and if:
    /// * its class has no virtual functions and no virtual base classes, and
    /// * all the direct base classes of its class have trivial constructors, and
    /// * for all the nonstatic data members of its class that are of class type
    ///   (or array thereof), each such class has a trivial constructor.
    bool HasTrivialConstructor : 1;

    /// HasTrivialCopyConstructor - True when this class has a trivial copy
    /// constructor.
    ///
    /// C++ [class.copy]p6.  A copy constructor for class X is trivial
    /// if it is implicitly declared and if
    /// * class X has no virtual functions and no virtual base classes, and
    /// * each direct base class of X has a trivial copy constructor, and
    /// * for all the nonstatic data members of X that are of class type (or
    ///   array thereof), each such class type has a trivial copy constructor;
    /// otherwise the copy constructor is non-trivial.
    bool HasTrivialCopyConstructor : 1;

    /// HasTrivialCopyAssignment - True when this class has a trivial copy
    /// assignment operator.
    ///
    /// C++ [class.copy]p11.  A copy assignment operator for class X is
    /// trivial if it is implicitly declared and if
    /// * class X has no virtual functions and no virtual base classes, and
    /// * each direct base class of X has a trivial copy assignment operator, and
    /// * for all the nonstatic data members of X that are of class type (or
    ///   array thereof), each such class type has a trivial copy assignment
    ///   operator;
    /// otherwise the copy assignment operator is non-trivial.
    bool HasTrivialCopyAssignment : 1;

    /// HasTrivialDestructor - True when this class has a trivial destructor.
    ///
    /// C++ [class.dtor]p3.  A destructor is trivial if it is an
    /// implicitly-declared destructor and if:
    /// * all of the direct base classes of its class have trivial destructors
    ///   and
    /// * for all of the non-static data members of its class that are of class
    ///   type (or array thereof), each such class has a trivial destructor.
    bool HasTrivialDestructor : 1;

    /// ComputedVisibleConversions - True when visible conversion functions are
    /// already computed and are available.
    bool ComputedVisibleConversions : 1;
  
    /// Bases - Base classes of this class.
    /// FIXME: This is wasted space for a union.
    CXXBaseSpecifier *Bases;

    /// NumBases - The number of base class specifiers in Bases.
    unsigned NumBases;

    /// VBases - direct and indirect virtual base classes of this class.
    CXXBaseSpecifier *VBases;

    /// NumVBases - The number of virtual base class specifiers in VBases.
    unsigned NumVBases;

    /// Conversions - Overload set containing the conversion functions
    /// of this C++ class (but not its inherited conversion
    /// functions). Each of the entries in this overload set is a
    /// CXXConversionDecl.
    UnresolvedSet<4> Conversions;

    /// VisibleConversions - Overload set containing the conversion
    /// functions of this C++ class and all those inherited conversion
    /// functions that are visible in this class. Each of the entries
    /// in this overload set is a CXXConversionDecl or a
    /// FunctionTemplateDecl.
    UnresolvedSet<4> VisibleConversions;

    /// Definition - The declaration which defines this record.
    CXXRecordDecl *Definition;

  } *DefinitionData;

  struct DefinitionData &data() {
    assert(DefinitionData && "queried property of class with no definition");
    return *DefinitionData;
  }

  const struct DefinitionData &data() const {
    assert(DefinitionData && "queried property of class with no definition");
    return *DefinitionData;
  }
  
  /// \brief The template or declaration that this declaration
  /// describes or was instantiated from, respectively.
  ///
  /// For non-templates, this value will be NULL. For record
  /// declarations that describe a class template, this will be a
  /// pointer to a ClassTemplateDecl. For member
  /// classes of class template specializations, this will be the
  /// MemberSpecializationInfo referring to the member class that was 
  /// instantiated or specialized.
  llvm::PointerUnion<ClassTemplateDecl*, MemberSpecializationInfo*>
    TemplateOrInstantiation;
  
  void getNestedVisibleConversionFunctions(CXXRecordDecl *RD,
          const llvm::SmallPtrSet<CanQualType, 8> &TopConversionsTypeSet,
          const llvm::SmallPtrSet<CanQualType, 8> &HiddenConversionTypes);
  void collectConversionFunctions(
    llvm::SmallPtrSet<CanQualType, 8>& ConversionsTypeSet) const;
  
protected:
  CXXRecordDecl(Kind K, TagKind TK, DeclContext *DC,
                SourceLocation L, IdentifierInfo *Id,
                CXXRecordDecl *PrevDecl,
                SourceLocation TKL = SourceLocation());

  ~CXXRecordDecl();

public:
  /// base_class_iterator - Iterator that traverses the base classes
  /// of a class.
  typedef CXXBaseSpecifier*       base_class_iterator;

  /// base_class_const_iterator - Iterator that traverses the base
  /// classes of a class.
  typedef const CXXBaseSpecifier* base_class_const_iterator;

  /// reverse_base_class_iterator = Iterator that traverses the base classes
  /// of a class in reverse order.
  typedef std::reverse_iterator<base_class_iterator>
    reverse_base_class_iterator;

  /// reverse_base_class_iterator = Iterator that traverses the base classes
  /// of a class in reverse order.
  typedef std::reverse_iterator<base_class_const_iterator>
    reverse_base_class_const_iterator;

  virtual CXXRecordDecl *getCanonicalDecl() {
    return cast<CXXRecordDecl>(RecordDecl::getCanonicalDecl());
  }
  virtual const CXXRecordDecl *getCanonicalDecl() const {
    return cast<CXXRecordDecl>(RecordDecl::getCanonicalDecl());
  }

  CXXRecordDecl *getDefinition() const {
    if (!DefinitionData) return 0;
    return data().Definition;
  }

  bool hasDefinition() const { return DefinitionData != 0; }

  static CXXRecordDecl *Create(ASTContext &C, TagKind TK, DeclContext *DC,
                               SourceLocation L, IdentifierInfo *Id,
                               SourceLocation TKL = SourceLocation(),
                               CXXRecordDecl* PrevDecl=0,
                               bool DelayTypeCreation = false);

  virtual void Destroy(ASTContext& C);

  bool isDynamicClass() const {
    return data().Polymorphic || data().NumVBases != 0;
  }

  /// setBases - Sets the base classes of this struct or class.
  void setBases(CXXBaseSpecifier const * const *Bases, unsigned NumBases);

  /// getNumBases - Retrieves the number of base classes of this
  /// class.
  unsigned getNumBases() const { return data().NumBases; }

  base_class_iterator bases_begin() { return data().Bases; }
  base_class_const_iterator bases_begin() const { return data().Bases; }
  base_class_iterator bases_end() { return bases_begin() + data().NumBases; }
  base_class_const_iterator bases_end() const {
    return bases_begin() + data().NumBases;
  }
  reverse_base_class_iterator       bases_rbegin() {
    return reverse_base_class_iterator(bases_end());
  }
  reverse_base_class_const_iterator bases_rbegin() const {
    return reverse_base_class_const_iterator(bases_end());
  }
  reverse_base_class_iterator bases_rend() {
    return reverse_base_class_iterator(bases_begin());
  }
  reverse_base_class_const_iterator bases_rend() const {
    return reverse_base_class_const_iterator(bases_begin());
  }

  /// getNumVBases - Retrieves the number of virtual base classes of this
  /// class.
  unsigned getNumVBases() const { return data().NumVBases; }

  base_class_iterator vbases_begin() { return data().VBases; }
  base_class_const_iterator vbases_begin() const { return data().VBases; }
  base_class_iterator vbases_end() { return vbases_begin() + data().NumVBases; }
  base_class_const_iterator vbases_end() const {
    return vbases_begin() + data().NumVBases;
  }
  reverse_base_class_iterator vbases_rbegin() {
    return reverse_base_class_iterator(vbases_end());
  }
  reverse_base_class_const_iterator vbases_rbegin() const {
    return reverse_base_class_const_iterator(vbases_end());
  }
  reverse_base_class_iterator vbases_rend() {
    return reverse_base_class_iterator(vbases_begin());
  }
  reverse_base_class_const_iterator vbases_rend() const {
    return reverse_base_class_const_iterator(vbases_begin());
 }

  /// \brief Determine whether this class has any dependent base classes.
  bool hasAnyDependentBases() const;

  /// Iterator access to method members.  The method iterator visits
  /// all method members of the class, including non-instance methods,
  /// special methods, etc.
  typedef specific_decl_iterator<CXXMethodDecl> method_iterator;

  /// method_begin - Method begin iterator.  Iterates in the order the methods
  /// were declared.
  method_iterator method_begin() const {
    return method_iterator(decls_begin());
  }
  /// method_end - Method end iterator.
  method_iterator method_end() const {
    return method_iterator(decls_end());
  }

  /// Iterator access to constructor members.
  typedef specific_decl_iterator<CXXConstructorDecl> ctor_iterator;

  ctor_iterator ctor_begin() const {
    return ctor_iterator(decls_begin());
  }
  ctor_iterator ctor_end() const {
    return ctor_iterator(decls_end());
  }

  /// hasConstCopyConstructor - Determines whether this class has a
  /// copy constructor that accepts a const-qualified argument.
  bool hasConstCopyConstructor(ASTContext &Context) const;

  /// getCopyConstructor - Returns the copy constructor for this class
  CXXConstructorDecl *getCopyConstructor(ASTContext &Context,
                                         unsigned TypeQuals) const;

  /// hasConstCopyAssignment - Determines whether this class has a
  /// copy assignment operator that accepts a const-qualified argument.
  /// It returns its decl in MD if found.
  bool hasConstCopyAssignment(ASTContext &Context,
                              const CXXMethodDecl *&MD) const;

  /// addedConstructor - Notify the class that another constructor has
  /// been added. This routine helps maintain information about the
  /// class based on which constructors have been added.
  void addedConstructor(ASTContext &Context, CXXConstructorDecl *ConDecl);

  /// hasUserDeclaredConstructor - Whether this class has any
  /// user-declared constructors. When true, a default constructor
  /// will not be implicitly declared.
  bool hasUserDeclaredConstructor() const {
    return data().UserDeclaredConstructor;
  }

  /// hasUserDeclaredCopyConstructor - Whether this class has a
  /// user-declared copy constructor. When false, a copy constructor
  /// will be implicitly declared.
  bool hasUserDeclaredCopyConstructor() const {
    return data().UserDeclaredCopyConstructor;
  }

  /// addedAssignmentOperator - Notify the class that another assignment
  /// operator has been added. This routine helps maintain information about the
   /// class based on which operators have been added.
  void addedAssignmentOperator(ASTContext &Context, CXXMethodDecl *OpDecl);

  /// hasUserDeclaredCopyAssignment - Whether this class has a
  /// user-declared copy assignment operator. When false, a copy
  /// assigment operator will be implicitly declared.
  bool hasUserDeclaredCopyAssignment() const {
    return data().UserDeclaredCopyAssignment;
  }

  /// hasUserDeclaredDestructor - Whether this class has a
  /// user-declared destructor. When false, a destructor will be
  /// implicitly declared.
  bool hasUserDeclaredDestructor() const {
    return data().UserDeclaredDestructor;
  }

  /// setUserDeclaredDestructor - Set whether this class has a
  /// user-declared destructor. If not set by the time the class is
  /// fully defined, a destructor will be implicitly declared.
  void setUserDeclaredDestructor(bool UCD) {
    data().UserDeclaredDestructor = UCD;
  }

  /// getConversions - Retrieve the overload set containing all of the
  /// conversion functions in this class.
  UnresolvedSetImpl *getConversionFunctions() {
    return &data().Conversions;
  }
  const UnresolvedSetImpl *getConversionFunctions() const {
    return &data().Conversions;
  }

  typedef UnresolvedSetImpl::iterator conversion_iterator;
  conversion_iterator conversion_begin() const {
    return getConversionFunctions()->begin();
  }
  conversion_iterator conversion_end() const {
    return getConversionFunctions()->end();
  }

  /// Replaces a conversion function with a new declaration.
  ///
  /// Returns true if the old conversion was found.
  bool replaceConversion(const NamedDecl* Old, NamedDecl *New) {
    return getConversionFunctions()->replace(Old, New);
  }

  /// getVisibleConversionFunctions - get all conversion functions visible
  /// in current class; including conversion function templates.
  const UnresolvedSetImpl *getVisibleConversionFunctions();

  /// addVisibleConversionFunction - Add a new conversion function to the
  /// list of visible conversion functions.
  void addVisibleConversionFunction(CXXConversionDecl *ConvDecl);
  
  /// \brief Add a new conversion function template to the list of visible
  /// conversion functions.
  void addVisibleConversionFunction(FunctionTemplateDecl *ConvDecl);
  
  /// addConversionFunction - Add a new conversion function to the
  /// list of conversion functions.
  void addConversionFunction(CXXConversionDecl *ConvDecl);

  /// \brief Add a new conversion function template to the list of conversion
  /// functions.
  void addConversionFunction(FunctionTemplateDecl *ConvDecl);

  /// isAggregate - Whether this class is an aggregate (C++
  /// [dcl.init.aggr]), which is a class with no user-declared
  /// constructors, no private or protected non-static data members,
  /// no base classes, and no virtual functions (C++ [dcl.init.aggr]p1).
  bool isAggregate() const { return data().Aggregate; }

  /// setAggregate - Set whether this class is an aggregate (C++
  /// [dcl.init.aggr]).
  void setAggregate(bool Agg) { data().Aggregate = Agg; }

  /// setMethodAsVirtual - Make input method virtual and set the necesssary 
  /// special function bits and other bits accordingly.
  void setMethodAsVirtual(FunctionDecl *Method);

  /// isPOD - Whether this class is a POD-type (C++ [class]p4), which is a class
  /// that is an aggregate that has no non-static non-POD data members, no
  /// reference data members, no user-defined copy assignment operator and no
  /// user-defined destructor.
  bool isPOD() const { return data().PlainOldData; }

  /// setPOD - Set whether this class is a POD-type (C++ [class]p4).
  void setPOD(bool POD) { data().PlainOldData = POD; }

  /// isEmpty - Whether this class is empty (C++0x [meta.unary.prop]), which
  /// means it has a virtual function, virtual base, data member (other than
  /// 0-width bit-field) or inherits from a non-empty class. Does NOT include
  /// a check for union-ness.
  bool isEmpty() const { return data().Empty; }

  /// Set whether this class is empty (C++0x [meta.unary.prop])
  void setEmpty(bool Emp) { data().Empty = Emp; }

  /// isPolymorphic - Whether this class is polymorphic (C++ [class.virtual]),
  /// which means that the class contains or inherits a virtual function.
  bool isPolymorphic() const { return data().Polymorphic; }

  /// setPolymorphic - Set whether this class is polymorphic (C++
  /// [class.virtual]).
  void setPolymorphic(bool Poly) { data().Polymorphic = Poly; }

  /// isAbstract - Whether this class is abstract (C++ [class.abstract]),
  /// which means that the class contains or inherits a pure virtual function.
  bool isAbstract() const { return data().Abstract; }

  /// setAbstract - Set whether this class is abstract (C++ [class.abstract])
  void setAbstract(bool Abs) { data().Abstract = Abs; }

  // hasTrivialConstructor - Whether this class has a trivial constructor
  // (C++ [class.ctor]p5)
  bool hasTrivialConstructor() const { return data().HasTrivialConstructor; }

  // setHasTrivialConstructor - Set whether this class has a trivial constructor
  // (C++ [class.ctor]p5)
  void setHasTrivialConstructor(bool TC) { data().HasTrivialConstructor = TC; }

  // hasTrivialCopyConstructor - Whether this class has a trivial copy
  // constructor (C++ [class.copy]p6)
  bool hasTrivialCopyConstructor() const {
    return data().HasTrivialCopyConstructor;
  }

  // setHasTrivialCopyConstructor - Set whether this class has a trivial
  // copy constructor (C++ [class.copy]p6)
  void setHasTrivialCopyConstructor(bool TC) {
    data().HasTrivialCopyConstructor = TC;
  }

  // hasTrivialCopyAssignment - Whether this class has a trivial copy
  // assignment operator (C++ [class.copy]p11)
  bool hasTrivialCopyAssignment() const {
    return data().HasTrivialCopyAssignment;
  }

  // setHasTrivialCopyAssignment - Set whether this class has a
  // trivial copy assignment operator (C++ [class.copy]p11)
  void setHasTrivialCopyAssignment(bool TC) {
    data().HasTrivialCopyAssignment = TC;
  }

  // hasTrivialDestructor - Whether this class has a trivial destructor
  // (C++ [class.dtor]p3)
  bool hasTrivialDestructor() const { return data().HasTrivialDestructor; }

  // setHasTrivialDestructor - Set whether this class has a trivial destructor
  // (C++ [class.dtor]p3)
  void setHasTrivialDestructor(bool TC) { data().HasTrivialDestructor = TC; }

  /// \brief If this record is an instantiation of a member class,
  /// retrieves the member class from which it was instantiated.
  ///
  /// This routine will return non-NULL for (non-templated) member
  /// classes of class templates. For example, given:
  ///
  /// \code
  /// template<typename T>
  /// struct X {
  ///   struct A { };
  /// };
  /// \endcode
  ///
  /// The declaration for X<int>::A is a (non-templated) CXXRecordDecl
  /// whose parent is the class template specialization X<int>. For
  /// this declaration, getInstantiatedFromMemberClass() will return
  /// the CXXRecordDecl X<T>::A. When a complete definition of
  /// X<int>::A is required, it will be instantiated from the
  /// declaration returned by getInstantiatedFromMemberClass().
  CXXRecordDecl *getInstantiatedFromMemberClass() const;
  
  /// \brief If this class is an instantiation of a member class of a
  /// class template specialization, retrieves the member specialization
  /// information.
  MemberSpecializationInfo *getMemberSpecializationInfo() const;
  
  /// \brief Specify that this record is an instantiation of the
  /// member class RD.
  void setInstantiationOfMemberClass(CXXRecordDecl *RD,
                                     TemplateSpecializationKind TSK);

  /// \brief Retrieves the class template that is described by this
  /// class declaration.
  ///
  /// Every class template is represented as a ClassTemplateDecl and a
  /// CXXRecordDecl. The former contains template properties (such as
  /// the template parameter lists) while the latter contains the
  /// actual description of the template's
  /// contents. ClassTemplateDecl::getTemplatedDecl() retrieves the
  /// CXXRecordDecl that from a ClassTemplateDecl, while
  /// getDescribedClassTemplate() retrieves the ClassTemplateDecl from
  /// a CXXRecordDecl.
  ClassTemplateDecl *getDescribedClassTemplate() const {
    return TemplateOrInstantiation.dyn_cast<ClassTemplateDecl*>();
  }

  void setDescribedClassTemplate(ClassTemplateDecl *Template) {
    TemplateOrInstantiation = Template;
  }

  /// \brief Determine whether this particular class is a specialization or
  /// instantiation of a class template or member class of a class template,
  /// and how it was instantiated or specialized.
  TemplateSpecializationKind getTemplateSpecializationKind() const;
  
  /// \brief Set the kind of specialization or template instantiation this is.
  void setTemplateSpecializationKind(TemplateSpecializationKind TSK);
  
  /// getDefaultConstructor - Returns the default constructor for this class
  CXXConstructorDecl *getDefaultConstructor(ASTContext &Context);

  /// getDestructor - Returns the destructor decl for this class.
  CXXDestructorDecl *getDestructor(ASTContext &Context) const;

  /// isLocalClass - If the class is a local class [class.local], returns
  /// the enclosing function declaration.
  const FunctionDecl *isLocalClass() const {
    if (const CXXRecordDecl *RD = dyn_cast<CXXRecordDecl>(getDeclContext()))
      return RD->isLocalClass();

    return dyn_cast<FunctionDecl>(getDeclContext());
  }

  /// \brief Determine whether this class is derived from the class \p Base.
  ///
  /// This routine only determines whether this class is derived from \p Base,
  /// but does not account for factors that may make a Derived -> Base class
  /// ill-formed, such as private/protected inheritance or multiple, ambiguous
  /// base class subobjects.
  ///
  /// \param Base the base class we are searching for.
  ///
  /// \returns true if this class is derived from Base, false otherwise.
  bool isDerivedFrom(CXXRecordDecl *Base) const;
  
  /// \brief Determine whether this class is derived from the type \p Base.
  ///
  /// This routine only determines whether this class is derived from \p Base,
  /// but does not account for factors that may make a Derived -> Base class
  /// ill-formed, such as private/protected inheritance or multiple, ambiguous
  /// base class subobjects.
  ///
  /// \param Base the base class we are searching for.
  ///
  /// \param Paths will contain the paths taken from the current class to the
  /// given \p Base class.
  ///
  /// \returns true if this class is derived from Base, false otherwise.
  ///
  /// \todo add a separate paramaeter to configure IsDerivedFrom, rather than 
  /// tangling input and output in \p Paths  
  bool isDerivedFrom(CXXRecordDecl *Base, CXXBasePaths &Paths) const;

  /// \brief Determine whether this class is virtually derived from
  /// the class \p Base.
  ///
  /// This routine only determines whether this class is virtually
  /// derived from \p Base, but does not account for factors that may
  /// make a Derived -> Base class ill-formed, such as
  /// private/protected inheritance or multiple, ambiguous base class
  /// subobjects.
  ///
  /// \param Base the base class we are searching for.
  ///
  /// \returns true if this class is virtually derived from Base,
  /// false otherwise.
  bool isVirtuallyDerivedFrom(CXXRecordDecl *Base) const;

  /// \brief Determine whether this class is provably not derived from
  /// the type \p Base.
  bool isProvablyNotDerivedFrom(const CXXRecordDecl *Base) const;

  /// \brief Function type used by forallBases() as a callback.
  ///
  /// \param Base the definition of the base class
  ///
  /// \returns true if this base matched the search criteria
  typedef bool ForallBasesCallback(const CXXRecordDecl *BaseDefinition,
                                   void *UserData);

  /// \brief Determines if the given callback holds for all the direct
  /// or indirect base classes of this type.
  ///
  /// The class itself does not count as a base class.  This routine
  /// returns false if the class has non-computable base classes.
  /// 
  /// \param AllowShortCircuit if false, forces the callback to be called
  /// for every base class, even if a dependent or non-matching base was
  /// found.
  bool forallBases(ForallBasesCallback *BaseMatches, void *UserData,
                   bool AllowShortCircuit = true) const;
  
  /// \brief Function type used by lookupInBases() to determine whether a 
  /// specific base class subobject matches the lookup criteria.
  ///
  /// \param Specifier the base-class specifier that describes the inheritance 
  /// from the base class we are trying to match.
  ///
  /// \param Path the current path, from the most-derived class down to the 
  /// base named by the \p Specifier.
  ///
  /// \param UserData a single pointer to user-specified data, provided to
  /// lookupInBases().
  ///
  /// \returns true if this base matched the search criteria, false otherwise.
  typedef bool BaseMatchesCallback(const CXXBaseSpecifier *Specifier,
                                   CXXBasePath &Path,
                                   void *UserData);
  
  /// \brief Look for entities within the base classes of this C++ class,
  /// transitively searching all base class subobjects.
  ///
  /// This routine uses the callback function \p BaseMatches to find base 
  /// classes meeting some search criteria, walking all base class subobjects
  /// and populating the given \p Paths structure with the paths through the 
  /// inheritance hierarchy that resulted in a match. On a successful search,
  /// the \p Paths structure can be queried to retrieve the matching paths and
  /// to determine if there were any ambiguities.
  ///
  /// \param BaseMatches callback function used to determine whether a given
  /// base matches the user-defined search criteria.
  ///
  /// \param UserData user data pointer that will be provided to \p BaseMatches.
  ///
  /// \param Paths used to record the paths from this class to its base class
  /// subobjects that match the search criteria.
  ///
  /// \returns true if there exists any path from this class to a base class
  /// subobject that matches the search criteria.
  bool lookupInBases(BaseMatchesCallback *BaseMatches, void *UserData,
                     CXXBasePaths &Paths) const;
  
  /// \brief Base-class lookup callback that determines whether the given
  /// base class specifier refers to a specific class declaration.
  ///
  /// This callback can be used with \c lookupInBases() to determine whether
  /// a given derived class has is a base class subobject of a particular type.
  /// The user data pointer should refer to the canonical CXXRecordDecl of the
  /// base class that we are searching for.
  static bool FindBaseClass(const CXXBaseSpecifier *Specifier,
                            CXXBasePath &Path, void *BaseRecord);

  /// \brief Base-class lookup callback that determines whether the
  /// given base class specifier refers to a specific class
  /// declaration and describes virtual derivation.
  ///
  /// This callback can be used with \c lookupInBases() to determine
  /// whether a given derived class has is a virtual base class
  /// subobject of a particular type.  The user data pointer should
  /// refer to the canonical CXXRecordDecl of the base class that we
  /// are searching for.
  static bool FindVirtualBaseClass(const CXXBaseSpecifier *Specifier,
                                   CXXBasePath &Path, void *BaseRecord);
  
  /// \brief Base-class lookup callback that determines whether there exists
  /// a tag with the given name.
  ///
  /// This callback can be used with \c lookupInBases() to find tag members
  /// of the given name within a C++ class hierarchy. The user data pointer
  /// is an opaque \c DeclarationName pointer.
  static bool FindTagMember(const CXXBaseSpecifier *Specifier,
                            CXXBasePath &Path, void *Name);

  /// \brief Base-class lookup callback that determines whether there exists
  /// a member with the given name.
  ///
  /// This callback can be used with \c lookupInBases() to find members
  /// of the given name within a C++ class hierarchy. The user data pointer
  /// is an opaque \c DeclarationName pointer.
  static bool FindOrdinaryMember(const CXXBaseSpecifier *Specifier,
                                 CXXBasePath &Path, void *Name);
  
  /// \brief Base-class lookup callback that determines whether there exists
  /// a member with the given name that can be used in a nested-name-specifier.
  ///
  /// This callback can be used with \c lookupInBases() to find membes of
  /// the given name within a C++ class hierarchy that can occur within
  /// nested-name-specifiers.
  static bool FindNestedNameSpecifierMember(const CXXBaseSpecifier *Specifier,
                                            CXXBasePath &Path,
                                            void *UserData);
  
  /// viewInheritance - Renders and displays an inheritance diagram
  /// for this C++ class and all of its base classes (transitively) using
  /// GraphViz.
  void viewInheritance(ASTContext& Context) const;

  /// MergeAccess - Calculates the access of a decl that is reached
  /// along a path.
  static AccessSpecifier MergeAccess(AccessSpecifier PathAccess,
                                     AccessSpecifier DeclAccess) {
    assert(DeclAccess != AS_none);
    if (DeclAccess == AS_private) return AS_none;
    return (PathAccess > DeclAccess ? PathAccess : DeclAccess);
  }

  static bool classof(const Decl *D) { return classofKind(D->getKind()); }
  static bool classofKind(Kind K) {
    return K == CXXRecord ||
           K == ClassTemplateSpecialization ||
           K == ClassTemplatePartialSpecialization;
  }
  static bool classof(const CXXRecordDecl *D) { return true; }
  static bool classof(const ClassTemplateSpecializationDecl *D) {
    return true;
  }
};

/// CXXMethodDecl - Represents a static or instance method of a
/// struct/union/class.
class CXXMethodDecl : public FunctionDecl {
protected:
  CXXMethodDecl(Kind DK, CXXRecordDecl *RD, SourceLocation L,
                DeclarationName N, QualType T, TypeSourceInfo *TInfo,
                bool isStatic, bool isInline)
    : FunctionDecl(DK, RD, L, N, T, TInfo, (isStatic ? Static : None),
                   isInline) {}

public:
  static CXXMethodDecl *Create(ASTContext &C, CXXRecordDecl *RD,
                              SourceLocation L, DeclarationName N,
                              QualType T, TypeSourceInfo *TInfo,
                              bool isStatic = false,
                              bool isInline = false);

  bool isStatic() const { return getStorageClass() == Static; }
  bool isInstance() const { return !isStatic(); }

  bool isVirtual() const {
    CXXMethodDecl *CD = 
      cast<CXXMethodDecl>(const_cast<CXXMethodDecl*>(this)->getCanonicalDecl());

    if (CD->isVirtualAsWritten())
      return true;
    
    return (CD->begin_overridden_methods() != CD->end_overridden_methods());
  }
  
  /// \brief Determine whether this is a usual deallocation function
  /// (C++ [basic.stc.dynamic.deallocation]p2), which is an overloaded
  /// delete or delete[] operator with a particular signature.
  bool isUsualDeallocationFunction() const;
  
  const CXXMethodDecl *getCanonicalDecl() const {
    return cast<CXXMethodDecl>(FunctionDecl::getCanonicalDecl());
  }
  CXXMethodDecl *getCanonicalDecl() {
    return cast<CXXMethodDecl>(FunctionDecl::getCanonicalDecl());
  }
  
  ///
  void addOverriddenMethod(const CXXMethodDecl *MD);

  typedef const CXXMethodDecl ** method_iterator;

  method_iterator begin_overridden_methods() const;
  method_iterator end_overridden_methods() const;

  /// getParent - Returns the parent of this method declaration, which
  /// is the class in which this method is defined.
  const CXXRecordDecl *getParent() const {
    return cast<CXXRecordDecl>(FunctionDecl::getParent());
  }

  /// getParent - Returns the parent of this method declaration, which
  /// is the class in which this method is defined.
  CXXRecordDecl *getParent() {
    return const_cast<CXXRecordDecl *>(
             cast<CXXRecordDecl>(FunctionDecl::getParent()));
  }

  /// getThisType - Returns the type of 'this' pointer.
  /// Should only be called for instance methods.
  QualType getThisType(ASTContext &C) const;

  unsigned getTypeQualifiers() const {
    return getType()->getAs<FunctionProtoType>()->getTypeQuals();
  }

  bool hasInlineBody() const;

  // Implement isa/cast/dyncast/etc.
  static bool classof(const Decl *D) { return classofKind(D->getKind()); }
  static bool classof(const CXXMethodDecl *D) { return true; }
  static bool classofKind(Kind K) {
    return K >= CXXMethod && K <= CXXConversion;
  }
};

/// CXXBaseOrMemberInitializer - Represents a C++ base or member
/// initializer, which is part of a constructor initializer that
/// initializes one non-static member variable or one base class. For
/// example, in the following, both 'A(a)' and 'f(3.14159)' are member
/// initializers:
///
/// @code
/// class A { };
/// class B : public A {
///   float f;
/// public:
///   B(A& a) : A(a), f(3.14159) { }
/// };
/// @endcode
class CXXBaseOrMemberInitializer {
  /// \brief Either the base class name (stored as a TypeSourceInfo*) or the
  /// field being initialized.
  llvm::PointerUnion<TypeSourceInfo *, FieldDecl *> BaseOrMember;
  
  /// \brief The source location for the field name.
  SourceLocation MemberLocation;
  
  /// \brief The argument used to initialize the base or member, which may
  /// end up constructing an object (when multiple arguments are involved).
  Stmt *Init;

  /// \brief Stores either the constructor to call to initialize this base or
  /// member (a CXXConstructorDecl pointer), or stores the anonymous union of
  /// which the initialized value is a member.
  ///
  /// When the value is a FieldDecl pointer, 'BaseOrMember' is class's
  /// anonymous union data member, this field holds the FieldDecl for the
  /// member of the anonymous union being initialized.
  /// @code
  /// struct X {
  ///   X() : au_i1(123) {}
  ///   union {
  ///     int au_i1;
  ///     float au_f1;
  ///   };
  /// };
  /// @endcode
  /// In above example, BaseOrMember holds the field decl. for anonymous union
  /// and AnonUnionMember holds field decl for au_i1.
  FieldDecl *AnonUnionMember;

  /// LParenLoc - Location of the left paren of the ctor-initializer.
  SourceLocation LParenLoc;

  /// RParenLoc - Location of the right paren of the ctor-initializer.
  SourceLocation RParenLoc;

public:
  /// CXXBaseOrMemberInitializer - Creates a new base-class initializer.
  explicit
  CXXBaseOrMemberInitializer(ASTContext &Context,
                             TypeSourceInfo *TInfo,
                             SourceLocation L, 
                             Expr *Init,
                             SourceLocation R);

  /// CXXBaseOrMemberInitializer - Creates a new member initializer.
  explicit
  CXXBaseOrMemberInitializer(ASTContext &Context,
                             FieldDecl *Member, SourceLocation MemberLoc,
                             SourceLocation L,
                             Expr *Init,
                             SourceLocation R);

  /// \brief Destroy the base or member initializer.
  void Destroy(ASTContext &Context);

  /// isBaseInitializer - Returns true when this initializer is
  /// initializing a base class.
  bool isBaseInitializer() const { return BaseOrMember.is<TypeSourceInfo*>(); }

  /// isMemberInitializer - Returns true when this initializer is
  /// initializing a non-static data member.
  bool isMemberInitializer() const { return BaseOrMember.is<FieldDecl*>(); }

  /// If this is a base class initializer, returns the type of the 
  /// base class with location information. Otherwise, returns an NULL
  /// type location.
  TypeLoc getBaseClassLoc() const;

  /// If this is a base class initializer, returns the type of the base class.
  /// Otherwise, returns NULL.
  const Type *getBaseClass() const;
  Type *getBaseClass();
  
  /// \brief Returns the declarator information for a base class initializer.
  TypeSourceInfo *getBaseClassInfo() const {
    return BaseOrMember.dyn_cast<TypeSourceInfo *>();
  }
  
  /// getMember - If this is a member initializer, returns the
  /// declaration of the non-static data member being
  /// initialized. Otherwise, returns NULL.
  FieldDecl *getMember() {
    if (isMemberInitializer())
      return BaseOrMember.get<FieldDecl*>();
    else
      return 0;
  }

  SourceLocation getMemberLocation() const { 
    return MemberLocation;
  }

  void setMember(FieldDecl *Member) {
    assert(isMemberInitializer());
    BaseOrMember = Member;
  }
  
  /// \brief Determine the source location of the initializer.
  SourceLocation getSourceLocation() const;
  
  /// \brief Determine the source range covering the entire initializer.
  SourceRange getSourceRange() const;
  
  FieldDecl *getAnonUnionMember() const {
    return AnonUnionMember;
  }
  void setAnonUnionMember(FieldDecl *anonMember) {
    AnonUnionMember = anonMember;
  }

  SourceLocation getLParenLoc() const { return LParenLoc; }
  SourceLocation getRParenLoc() const { return RParenLoc; }

  Expr *getInit() { return static_cast<Expr *>(Init); }
};

/// CXXConstructorDecl - Represents a C++ constructor within a
/// class. For example:
///
/// @code
/// class X {
/// public:
///   explicit X(int); // represented by a CXXConstructorDecl.
/// };
/// @endcode
class CXXConstructorDecl : public CXXMethodDecl {
  /// IsExplicitSpecified - Whether this constructor declaration has the
  /// 'explicit' keyword specified.
  bool IsExplicitSpecified : 1;

  /// ImplicitlyDefined - Whether this constructor was implicitly
  /// defined by the compiler. When false, the constructor was defined
  /// by the user. In C++03, this flag will have the same value as
  /// Implicit. In C++0x, however, a constructor that is
  /// explicitly defaulted (i.e., defined with " = default") will have
  /// @c !Implicit && ImplicitlyDefined.
  bool ImplicitlyDefined : 1;

  /// Support for base and member initializers.
  /// BaseOrMemberInitializers - The arguments used to initialize the base
  /// or member.
  CXXBaseOrMemberInitializer **BaseOrMemberInitializers;
  unsigned NumBaseOrMemberInitializers;

  CXXConstructorDecl(CXXRecordDecl *RD, SourceLocation L,
                     DeclarationName N, QualType T, TypeSourceInfo *TInfo,
                     bool isExplicitSpecified, bool isInline, 
                     bool isImplicitlyDeclared)
    : CXXMethodDecl(CXXConstructor, RD, L, N, T, TInfo, false, isInline),
      IsExplicitSpecified(isExplicitSpecified), ImplicitlyDefined(false),
      BaseOrMemberInitializers(0), NumBaseOrMemberInitializers(0) {
    setImplicit(isImplicitlyDeclared);
  }
  virtual void Destroy(ASTContext& C);

public:
  static CXXConstructorDecl *Create(ASTContext &C, CXXRecordDecl *RD,
                                    SourceLocation L, DeclarationName N,
                                    QualType T, TypeSourceInfo *TInfo,
                                    bool isExplicit,
                                    bool isInline, bool isImplicitlyDeclared);

  /// isExplicitSpecified - Whether this constructor declaration has the
  /// 'explicit' keyword specified.
  bool isExplicitSpecified() const { return IsExplicitSpecified; }
  
  /// isExplicit - Whether this constructor was marked "explicit" or not.
  bool isExplicit() const {
    return cast<CXXConstructorDecl>(getFirstDeclaration())
      ->isExplicitSpecified();
  }

  /// isImplicitlyDefined - Whether this constructor was implicitly
  /// defined. If false, then this constructor was defined by the
  /// user. This operation can only be invoked if the constructor has
  /// already been defined.
  bool isImplicitlyDefined(ASTContext &C) const {
    assert(isThisDeclarationADefinition() &&
           "Can only get the implicit-definition flag once the "
           "constructor has been defined");
    return ImplicitlyDefined;
  }

  /// setImplicitlyDefined - Set whether this constructor was
  /// implicitly defined or not.
  void setImplicitlyDefined(bool ID) {
    assert(isThisDeclarationADefinition() &&
           "Can only set the implicit-definition flag once the constructor "
           "has been defined");
    ImplicitlyDefined = ID;
  }

  /// init_iterator - Iterates through the member/base initializer list.
  typedef CXXBaseOrMemberInitializer **init_iterator;

  /// init_const_iterator - Iterates through the memberbase initializer list.
  typedef CXXBaseOrMemberInitializer * const * init_const_iterator;

  /// init_begin() - Retrieve an iterator to the first initializer.
  init_iterator       init_begin()       { return BaseOrMemberInitializers; }
  /// begin() - Retrieve an iterator to the first initializer.
  init_const_iterator init_begin() const { return BaseOrMemberInitializers; }

  /// init_end() - Retrieve an iterator past the last initializer.
  init_iterator       init_end()       {
    return BaseOrMemberInitializers + NumBaseOrMemberInitializers;
  }
  /// end() - Retrieve an iterator past the last initializer.
  init_const_iterator init_end() const {
    return BaseOrMemberInitializers + NumBaseOrMemberInitializers;
  }

  /// getNumArgs - Determine the number of arguments used to
  /// initialize the member or base.
  unsigned getNumBaseOrMemberInitializers() const {
      return NumBaseOrMemberInitializers;
  }

  void setNumBaseOrMemberInitializers(unsigned numBaseOrMemberInitializers) {
    NumBaseOrMemberInitializers = numBaseOrMemberInitializers;
  }

  void setBaseOrMemberInitializers(CXXBaseOrMemberInitializer ** initializers) {
    BaseOrMemberInitializers = initializers;
  }
  /// isDefaultConstructor - Whether this constructor is a default
  /// constructor (C++ [class.ctor]p5), which can be used to
  /// default-initialize a class of this type.
  bool isDefaultConstructor() const;

  /// isCopyConstructor - Whether this constructor is a copy
  /// constructor (C++ [class.copy]p2, which can be used to copy the
  /// class. @p TypeQuals will be set to the qualifiers on the
  /// argument type. For example, @p TypeQuals would be set to @c
  /// QualType::Const for the following copy constructor:
  ///
  /// @code
  /// class X {
  /// public:
  ///   X(const X&);
  /// };
  /// @endcode
  bool isCopyConstructor(unsigned &TypeQuals) const;

  /// isCopyConstructor - Whether this constructor is a copy
  /// constructor (C++ [class.copy]p2, which can be used to copy the
  /// class.
  bool isCopyConstructor() const {
    unsigned TypeQuals = 0;
    return isCopyConstructor(TypeQuals);
  }

  /// isConvertingConstructor - Whether this constructor is a
  /// converting constructor (C++ [class.conv.ctor]), which can be
  /// used for user-defined conversions.
  bool isConvertingConstructor(bool AllowExplicit) const;

  /// \brief Determine whether this is a member template specialization that
  /// looks like a copy constructor. Such constructors are never used to copy
  /// an object.
  bool isCopyConstructorLikeSpecialization() const;
  
  // Implement isa/cast/dyncast/etc.
  static bool classof(const Decl *D) { return classofKind(D->getKind()); }
  static bool classof(const CXXConstructorDecl *D) { return true; }
  static bool classofKind(Kind K) { return K == CXXConstructor; }
};

/// CXXDestructorDecl - Represents a C++ destructor within a
/// class. For example:
///
/// @code
/// class X {
/// public:
///   ~X(); // represented by a CXXDestructorDecl.
/// };
/// @endcode
class CXXDestructorDecl : public CXXMethodDecl {
  /// ImplicitlyDefined - Whether this destructor was implicitly
  /// defined by the compiler. When false, the destructor was defined
  /// by the user. In C++03, this flag will have the same value as
  /// Implicit. In C++0x, however, a destructor that is
  /// explicitly defaulted (i.e., defined with " = default") will have
  /// @c !Implicit && ImplicitlyDefined.
  bool ImplicitlyDefined : 1;

  FunctionDecl *OperatorDelete;
  
  CXXDestructorDecl(CXXRecordDecl *RD, SourceLocation L,
                    DeclarationName N, QualType T,
                    bool isInline, bool isImplicitlyDeclared)
    : CXXMethodDecl(CXXDestructor, RD, L, N, T, /*TInfo=*/0, false, isInline),
      ImplicitlyDefined(false), OperatorDelete(0) {
    setImplicit(isImplicitlyDeclared);
  }

public:
  static CXXDestructorDecl *Create(ASTContext &C, CXXRecordDecl *RD,
                                   SourceLocation L, DeclarationName N,
                                   QualType T, bool isInline,
                                   bool isImplicitlyDeclared);

  /// isImplicitlyDefined - Whether this destructor was implicitly
  /// defined. If false, then this destructor was defined by the
  /// user. This operation can only be invoked if the destructor has
  /// already been defined.
  bool isImplicitlyDefined() const {
    assert(isThisDeclarationADefinition() &&
           "Can only get the implicit-definition flag once the destructor has been defined");
    return ImplicitlyDefined;
  }

  /// setImplicitlyDefined - Set whether this destructor was
  /// implicitly defined or not.
  void setImplicitlyDefined(bool ID) {
    assert(isThisDeclarationADefinition() &&
           "Can only set the implicit-definition flag once the destructor has been defined");
    ImplicitlyDefined = ID;
  }

  void setOperatorDelete(FunctionDecl *OD) { OperatorDelete = OD; }
  const FunctionDecl *getOperatorDelete() const { return OperatorDelete; }

  // Implement isa/cast/dyncast/etc.
  static bool classof(const Decl *D) { return classofKind(D->getKind()); }
  static bool classof(const CXXDestructorDecl *D) { return true; }
  static bool classofKind(Kind K) { return K == CXXDestructor; }
};

/// CXXConversionDecl - Represents a C++ conversion function within a
/// class. For example:
///
/// @code
/// class X {
/// public:
///   operator bool();
/// };
/// @endcode
class CXXConversionDecl : public CXXMethodDecl {
  /// IsExplicitSpecified - Whether this conversion function declaration is 
  /// marked "explicit", meaning that it can only be applied when the user
  /// explicitly wrote a cast. This is a C++0x feature.
  bool IsExplicitSpecified : 1;

  CXXConversionDecl(CXXRecordDecl *RD, SourceLocation L,
                    DeclarationName N, QualType T, TypeSourceInfo *TInfo,
                    bool isInline, bool isExplicitSpecified)
    : CXXMethodDecl(CXXConversion, RD, L, N, T, TInfo, false, isInline),
      IsExplicitSpecified(isExplicitSpecified) { }

public:
  static CXXConversionDecl *Create(ASTContext &C, CXXRecordDecl *RD,
                                   SourceLocation L, DeclarationName N,
                                   QualType T, TypeSourceInfo *TInfo,
                                   bool isInline, bool isExplicit);

  /// IsExplicitSpecified - Whether this conversion function declaration is 
  /// marked "explicit", meaning that it can only be applied when the user
  /// explicitly wrote a cast. This is a C++0x feature.
  bool isExplicitSpecified() const { return IsExplicitSpecified; }

  /// isExplicit - Whether this is an explicit conversion operator
  /// (C++0x only). Explicit conversion operators are only considered
  /// when the user has explicitly written a cast.
  bool isExplicit() const {
    return cast<CXXConversionDecl>(getFirstDeclaration())
      ->isExplicitSpecified();
  }

  /// getConversionType - Returns the type that this conversion
  /// function is converting to.
  QualType getConversionType() const {
    return getType()->getAs<FunctionType>()->getResultType();
  }

  // Implement isa/cast/dyncast/etc.
  static bool classof(const Decl *D) { return classofKind(D->getKind()); }
  static bool classof(const CXXConversionDecl *D) { return true; }
  static bool classofKind(Kind K) { return K == CXXConversion; }
};

/// FriendDecl - Represents the declaration of a friend entity,
/// which can be a function, a type, or a templated function or type.
//  For example:
///
/// @code
/// template <typename T> class A {
///   friend int foo(T);
///   friend class B;
///   friend T; // only in C++0x
///   template <typename U> friend class C;
///   template <typename U> friend A& operator+=(A&, const U&) { ... }
/// };
/// @endcode
///
/// The semantic context of a friend decl is its declaring class.
class FriendDecl : public Decl {
public:
  typedef llvm::PointerUnion<NamedDecl*,Type*> FriendUnion;

private:
  // The declaration that's a friend of this class.
  FriendUnion Friend;

  // Location of the 'friend' specifier.
  SourceLocation FriendLoc;

  // FIXME: Hack to keep track of whether this was a friend function
  // template specialization.
  bool WasSpecialization;

  FriendDecl(DeclContext *DC, SourceLocation L, FriendUnion Friend,
             SourceLocation FriendL)
    : Decl(Decl::Friend, DC, L),
      Friend(Friend),
      FriendLoc(FriendL),
      WasSpecialization(false) {
  }

public:
  static FriendDecl *Create(ASTContext &C, DeclContext *DC,
                            SourceLocation L, FriendUnion Friend_,
                            SourceLocation FriendL);

  /// If this friend declaration names an (untemplated but
  /// possibly dependent) type, return the type;  otherwise
  /// return null.  This is used only for C++0x's unelaborated
  /// friend type declarations.
  Type *getFriendType() const {
    return Friend.dyn_cast<Type*>();
  }

  /// If this friend declaration doesn't name an unelaborated
  /// type, return the inner declaration.
  NamedDecl *getFriendDecl() const {
    return Friend.dyn_cast<NamedDecl*>();
  }

  /// Retrieves the location of the 'friend' keyword.
  SourceLocation getFriendLoc() const {
    return FriendLoc;
  }

  bool wasSpecialization() const { return WasSpecialization; }
  void setSpecialization(bool WS) { WasSpecialization = WS; }

  // Implement isa/cast/dyncast/etc.
  static bool classof(const Decl *D) { return classofKind(D->getKind()); }
  static bool classof(const FriendDecl *D) { return true; }
  static bool classofKind(Kind K) { return K == Decl::Friend; }
};

/// LinkageSpecDecl - This represents a linkage specification.  For example:
///   extern "C" void foo();
///
class LinkageSpecDecl : public Decl, public DeclContext {
public:
  /// LanguageIDs - Used to represent the language in a linkage
  /// specification.  The values are part of the serialization abi for
  /// ASTs and cannot be changed without altering that abi.  To help
  /// ensure a stable abi for this, we choose the DW_LANG_ encodings
  /// from the dwarf standard.
  enum LanguageIDs { lang_c = /* DW_LANG_C */ 0x0002,
  lang_cxx = /* DW_LANG_C_plus_plus */ 0x0004 };
private:
  /// Language - The language for this linkage specification.
  LanguageIDs Language;

  /// HadBraces - Whether this linkage specification had curly braces or not.
  bool HadBraces : 1;

  LinkageSpecDecl(DeclContext *DC, SourceLocation L, LanguageIDs lang,
                  bool Braces)
    : Decl(LinkageSpec, DC, L),
      DeclContext(LinkageSpec), Language(lang), HadBraces(Braces) { }

public:
  static LinkageSpecDecl *Create(ASTContext &C, DeclContext *DC,
                                 SourceLocation L, LanguageIDs Lang,
                                 bool Braces);

  LanguageIDs getLanguage() const { return Language; }

  /// hasBraces - Determines whether this linkage specification had
  /// braces in its syntactic form.
  bool hasBraces() const { return HadBraces; }

  static bool classof(const Decl *D) { return classofKind(D->getKind()); }
  static bool classof(const LinkageSpecDecl *D) { return true; }
  static bool classofKind(Kind K) { return K == LinkageSpec; }
  static DeclContext *castToDeclContext(const LinkageSpecDecl *D) {
    return static_cast<DeclContext *>(const_cast<LinkageSpecDecl*>(D));
  }
  static LinkageSpecDecl *castFromDeclContext(const DeclContext *DC) {
    return static_cast<LinkageSpecDecl *>(const_cast<DeclContext*>(DC));
  }
};

/// UsingDirectiveDecl - Represents C++ using-directive. For example:
///
///    using namespace std;
///
// NB: UsingDirectiveDecl should be Decl not NamedDecl, but we provide
// artificial name, for all using-directives in order to store
// them in DeclContext effectively.
class UsingDirectiveDecl : public NamedDecl {

  /// SourceLocation - Location of 'namespace' token.
  SourceLocation NamespaceLoc;

  /// \brief The source range that covers the nested-name-specifier
  /// preceding the namespace name.
  SourceRange QualifierRange;

  /// \brief The nested-name-specifier that precedes the namespace
  /// name, if any.
  NestedNameSpecifier *Qualifier;

  /// IdentLoc - Location of nominated namespace-name identifier.
  // FIXME: We don't store location of scope specifier.
  SourceLocation IdentLoc;

  /// NominatedNamespace - Namespace nominated by using-directive.
  NamedDecl *NominatedNamespace;

  /// Enclosing context containing both using-directive and nominated
  /// namespace.
  DeclContext *CommonAncestor;

  /// getUsingDirectiveName - Returns special DeclarationName used by
  /// using-directives. This is only used by DeclContext for storing
  /// UsingDirectiveDecls in its lookup structure.
  static DeclarationName getName() {
    return DeclarationName::getUsingDirectiveName();
  }

  UsingDirectiveDecl(DeclContext *DC, SourceLocation L,
                     SourceLocation NamespcLoc,
                     SourceRange QualifierRange,
                     NestedNameSpecifier *Qualifier,
                     SourceLocation IdentLoc,
                     NamedDecl *Nominated,
                     DeclContext *CommonAncestor)
    : NamedDecl(Decl::UsingDirective, DC, L, getName()),
      NamespaceLoc(NamespcLoc), QualifierRange(QualifierRange),
      Qualifier(Qualifier), IdentLoc(IdentLoc),
      NominatedNamespace(Nominated),
      CommonAncestor(CommonAncestor) {
  }

public:
  /// \brief Retrieve the source range of the nested-name-specifier
  /// that qualifiers the namespace name.
  SourceRange getQualifierRange() const { return QualifierRange; }

  /// \brief Retrieve the nested-name-specifier that qualifies the
  /// name of the namespace.
  NestedNameSpecifier *getQualifier() const { return Qualifier; }

  NamedDecl *getNominatedNamespaceAsWritten() { return NominatedNamespace; }
  const NamedDecl *getNominatedNamespaceAsWritten() const {
    return NominatedNamespace;
  }

  /// getNominatedNamespace - Returns namespace nominated by using-directive.
  NamespaceDecl *getNominatedNamespace();

  const NamespaceDecl *getNominatedNamespace() const {
    return const_cast<UsingDirectiveDecl*>(this)->getNominatedNamespace();
  }

  /// getCommonAncestor - returns common ancestor context of using-directive,
  /// and nominated by it namespace.
  DeclContext *getCommonAncestor() { return CommonAncestor; }
  const DeclContext *getCommonAncestor() const { return CommonAncestor; }

  /// getNamespaceKeyLocation - Returns location of namespace keyword.
  SourceLocation getNamespaceKeyLocation() const { return NamespaceLoc; }

  /// getIdentLocation - Returns location of identifier.
  SourceLocation getIdentLocation() const { return IdentLoc; }

  static UsingDirectiveDecl *Create(ASTContext &C, DeclContext *DC,
                                    SourceLocation L,
                                    SourceLocation NamespaceLoc,
                                    SourceRange QualifierRange,
                                    NestedNameSpecifier *Qualifier,
                                    SourceLocation IdentLoc,
                                    NamedDecl *Nominated,
                                    DeclContext *CommonAncestor);

  static bool classof(const Decl *D) { return classofKind(D->getKind()); }
  static bool classof(const UsingDirectiveDecl *D) { return true; }
  static bool classofKind(Kind K) { return K == Decl::UsingDirective; }

  // Friend for getUsingDirectiveName.
  friend class DeclContext;
};

/// NamespaceAliasDecl - Represents a C++ namespace alias. For example:
///
/// @code
/// namespace Foo = Bar;
/// @endcode
class NamespaceAliasDecl : public NamedDecl {
  SourceLocation AliasLoc;

  /// \brief The source range that covers the nested-name-specifier
  /// preceding the namespace name.
  SourceRange QualifierRange;

  /// \brief The nested-name-specifier that precedes the namespace
  /// name, if any.
  NestedNameSpecifier *Qualifier;

  /// IdentLoc - Location of namespace identifier.
  SourceLocation IdentLoc;

  /// Namespace - The Decl that this alias points to. Can either be a
  /// NamespaceDecl or a NamespaceAliasDecl.
  NamedDecl *Namespace;

  NamespaceAliasDecl(DeclContext *DC, SourceLocation L,
                     SourceLocation AliasLoc, IdentifierInfo *Alias,
                     SourceRange QualifierRange,
                     NestedNameSpecifier *Qualifier,
                     SourceLocation IdentLoc, NamedDecl *Namespace)
    : NamedDecl(Decl::NamespaceAlias, DC, L, Alias), AliasLoc(AliasLoc),
      QualifierRange(QualifierRange), Qualifier(Qualifier),
      IdentLoc(IdentLoc), Namespace(Namespace) { }

public:
  /// \brief Retrieve the source range of the nested-name-specifier
  /// that qualifiers the namespace name.
  SourceRange getQualifierRange() const { return QualifierRange; }

  /// \brief Retrieve the nested-name-specifier that qualifies the
  /// name of the namespace.
  NestedNameSpecifier *getQualifier() const { return Qualifier; }

  NamespaceDecl *getNamespace() {
    if (NamespaceAliasDecl *AD = dyn_cast<NamespaceAliasDecl>(Namespace))
      return AD->getNamespace();

    return cast<NamespaceDecl>(Namespace);
  }

  const NamespaceDecl *getNamespace() const {
    return const_cast<NamespaceAliasDecl*>(this)->getNamespace();
  }

  /// Returns the location of the alias name, i.e. 'foo' in
  /// "namespace foo = ns::bar;".
  SourceLocation getAliasLoc() const { return AliasLoc; }

  /// Returns the location of the 'namespace' keyword.
  SourceLocation getNamespaceLoc() const { return getLocation(); }

  /// Returns the location of the identifier in the named namespace.
  SourceLocation getTargetNameLoc() const { return IdentLoc; }

  /// \brief Retrieve the namespace that this alias refers to, which
  /// may either be a NamespaceDecl or a NamespaceAliasDecl.
  NamedDecl *getAliasedNamespace() const { return Namespace; }

  static NamespaceAliasDecl *Create(ASTContext &C, DeclContext *DC,
                                    SourceLocation L, SourceLocation AliasLoc,
                                    IdentifierInfo *Alias,
                                    SourceRange QualifierRange,
                                    NestedNameSpecifier *Qualifier,
                                    SourceLocation IdentLoc,
                                    NamedDecl *Namespace);

  static bool classof(const Decl *D) { return classofKind(D->getKind()); }
  static bool classof(const NamespaceAliasDecl *D) { return true; }
  static bool classofKind(Kind K) { return K == Decl::NamespaceAlias; }
};

/// UsingShadowDecl - Represents a shadow declaration introduced into
/// a scope by a (resolved) using declaration.  For example,
///
/// namespace A {
///   void foo();
/// }
/// namespace B {
///   using A::foo(); // <- a UsingDecl
///                   // Also creates a UsingShadowDecl for A::foo in B
/// }
///
class UsingShadowDecl : public NamedDecl {
  /// The referenced declaration.
  NamedDecl *Underlying;

  /// The using declaration which introduced this decl.
  UsingDecl *Using;

  UsingShadowDecl(DeclContext *DC, SourceLocation Loc, UsingDecl *Using,
                  NamedDecl *Target)
    : NamedDecl(UsingShadow, DC, Loc, Target->getDeclName()),
      Underlying(Target), Using(Using) {
    IdentifierNamespace = Target->getIdentifierNamespace();
    setImplicit();
  }

public:
  static UsingShadowDecl *Create(ASTContext &C, DeclContext *DC,
                                 SourceLocation Loc, UsingDecl *Using,
                                 NamedDecl *Target) {
    return new (C) UsingShadowDecl(DC, Loc, Using, Target);
  }

  /// Gets the underlying declaration which has been brought into the
  /// local scope.
  NamedDecl *getTargetDecl() const {
    return Underlying;
  }

  /// Gets the using declaration to which this declaration is tied.
  UsingDecl *getUsingDecl() const {
    return Using;
  }

  static bool classof(const Decl *D) { return classofKind(D->getKind()); }
  static bool classof(const UsingShadowDecl *D) { return true; }
  static bool classofKind(Kind K) { return K == Decl::UsingShadow; }
};

/// UsingDecl - Represents a C++ using-declaration. For example:
///    using someNameSpace::someIdentifier;
class UsingDecl : public NamedDecl {
  /// \brief The source range that covers the nested-name-specifier
  /// preceding the declaration name.
  SourceRange NestedNameRange;

  /// \brief The source location of the "using" location itself.
  SourceLocation UsingLocation;

  /// \brief Target nested name specifier.
  NestedNameSpecifier* TargetNestedName;

  /// \brief The collection of shadow declarations associated with
  /// this using declaration.  This set can change as a class is
  /// processed.
  llvm::SmallPtrSet<UsingShadowDecl*, 8> Shadows;

  // \brief Has 'typename' keyword.
  bool IsTypeName;

  UsingDecl(DeclContext *DC, SourceLocation L, SourceRange NNR,
            SourceLocation UL, NestedNameSpecifier* TargetNNS,
            DeclarationName Name, bool IsTypeNameArg)
    : NamedDecl(Decl::Using, DC, L, Name),
      NestedNameRange(NNR), UsingLocation(UL), TargetNestedName(TargetNNS),
      IsTypeName(IsTypeNameArg) {
  }

public:
  /// \brief Returns the source range that covers the nested-name-specifier
  /// preceding the namespace name.
  SourceRange getNestedNameRange() { return NestedNameRange; }

  /// \brief Returns the source location of the "using" location itself.
  SourceLocation getUsingLocation() { return UsingLocation; }

  /// \brief Get target nested name declaration.
  NestedNameSpecifier* getTargetNestedNameDecl() {
    return TargetNestedName;
  }

  /// isTypeName - Return true if using decl has 'typename'.
  bool isTypeName() const { return IsTypeName; }

  typedef llvm::SmallPtrSet<UsingShadowDecl*,8>::const_iterator shadow_iterator;
  shadow_iterator shadow_begin() const { return Shadows.begin(); }
  shadow_iterator shadow_end() const { return Shadows.end(); }

  void addShadowDecl(UsingShadowDecl *S) {
    assert(S->getUsingDecl() == this);
    if (!Shadows.insert(S)) {
      assert(false && "declaration already in set");
    }
  }
  void removeShadowDecl(UsingShadowDecl *S) {
    assert(S->getUsingDecl() == this);
    if (!Shadows.erase(S)) {
      assert(false && "declaration not in set");
    }
  }

  static UsingDecl *Create(ASTContext &C, DeclContext *DC,
      SourceLocation IdentL, SourceRange NNR, SourceLocation UsingL,
      NestedNameSpecifier* TargetNNS, DeclarationName Name, bool IsTypeNameArg);

  static bool classof(const Decl *D) { return classofKind(D->getKind()); }
  static bool classof(const UsingDecl *D) { return true; }
  static bool classofKind(Kind K) { return K == Decl::Using; }
};

/// UnresolvedUsingValueDecl - Represents a dependent using
/// declaration which was not marked with 'typename'.  Unlike
/// non-dependent using declarations, these *only* bring through
/// non-types; otherwise they would break two-phase lookup.
///
/// template <class T> class A : public Base<T> {
///   using Base<T>::foo;
/// };
class UnresolvedUsingValueDecl : public ValueDecl {
  /// \brief The source range that covers the nested-name-specifier
  /// preceding the declaration name.
  SourceRange TargetNestedNameRange;

  /// \brief The source location of the 'using' keyword
  SourceLocation UsingLocation;

  NestedNameSpecifier *TargetNestedNameSpecifier;

  UnresolvedUsingValueDecl(DeclContext *DC, QualType Ty,
                           SourceLocation UsingLoc, SourceRange TargetNNR,
                           NestedNameSpecifier *TargetNNS,
                           SourceLocation TargetNameLoc,
                           DeclarationName TargetName)
    : ValueDecl(Decl::UnresolvedUsingValue, DC, TargetNameLoc, TargetName, Ty),
    TargetNestedNameRange(TargetNNR), UsingLocation(UsingLoc),
    TargetNestedNameSpecifier(TargetNNS)
  { }

public:
  /// \brief Returns the source range that covers the nested-name-specifier
  /// preceding the namespace name.
  SourceRange getTargetNestedNameRange() const { return TargetNestedNameRange; }

  /// \brief Get target nested name declaration.
  NestedNameSpecifier* getTargetNestedNameSpecifier() {
    return TargetNestedNameSpecifier;
  }

  /// \brief Returns the source location of the 'using' keyword.
  SourceLocation getUsingLoc() const { return UsingLocation; }

  static UnresolvedUsingValueDecl *
    Create(ASTContext &C, DeclContext *DC, SourceLocation UsingLoc,
           SourceRange TargetNNR, NestedNameSpecifier *TargetNNS,
           SourceLocation TargetNameLoc, DeclarationName TargetName);

  static bool classof(const Decl *D) { return classofKind(D->getKind()); }
  static bool classof(const UnresolvedUsingValueDecl *D) { return true; }
  static bool classofKind(Kind K) { return K == Decl::UnresolvedUsingValue; }
};

/// UnresolvedUsingTypenameDecl - Represents a dependent using
/// declaration which was marked with 'typename'.
///
/// template <class T> class A : public Base<T> {
///   using typename Base<T>::foo;
/// };
///
/// The type associated with a unresolved using typename decl is
/// currently always a typename type.
class UnresolvedUsingTypenameDecl : public TypeDecl {
  /// \brief The source range that covers the nested-name-specifier
  /// preceding the declaration name.
  SourceRange TargetNestedNameRange;

  /// \brief The source location of the 'using' keyword
  SourceLocation UsingLocation;

  /// \brief The source location of the 'typename' keyword
  SourceLocation TypenameLocation;

  NestedNameSpecifier *TargetNestedNameSpecifier;

  UnresolvedUsingTypenameDecl(DeclContext *DC, SourceLocation UsingLoc,
                    SourceLocation TypenameLoc,
                    SourceRange TargetNNR, NestedNameSpecifier *TargetNNS,
                    SourceLocation TargetNameLoc, IdentifierInfo *TargetName)
  : TypeDecl(Decl::UnresolvedUsingTypename, DC, TargetNameLoc, TargetName),
    TargetNestedNameRange(TargetNNR), UsingLocation(UsingLoc),
    TypenameLocation(TypenameLoc), TargetNestedNameSpecifier(TargetNNS)
  { }

public:
  /// \brief Returns the source range that covers the nested-name-specifier
  /// preceding the namespace name.
  SourceRange getTargetNestedNameRange() const { return TargetNestedNameRange; }

  /// \brief Get target nested name declaration.
  NestedNameSpecifier* getTargetNestedNameSpecifier() {
    return TargetNestedNameSpecifier;
  }

  /// \brief Returns the source location of the 'using' keyword.
  SourceLocation getUsingLoc() const { return UsingLocation; }

  /// \brief Returns the source location of the 'typename' keyword.
  SourceLocation getTypenameLoc() const { return TypenameLocation; }

  static UnresolvedUsingTypenameDecl *
    Create(ASTContext &C, DeclContext *DC, SourceLocation UsingLoc,
           SourceLocation TypenameLoc,
           SourceRange TargetNNR, NestedNameSpecifier *TargetNNS,
           SourceLocation TargetNameLoc, DeclarationName TargetName);

  static bool classof(const Decl *D) { return classofKind(D->getKind()); }
  static bool classof(const UnresolvedUsingTypenameDecl *D) { return true; }
  static bool classofKind(Kind K) { return K == Decl::UnresolvedUsingTypename; }
};

/// StaticAssertDecl - Represents a C++0x static_assert declaration.
class StaticAssertDecl : public Decl {
  Expr *AssertExpr;
  StringLiteral *Message;

  StaticAssertDecl(DeclContext *DC, SourceLocation L,
                   Expr *assertexpr, StringLiteral *message)
  : Decl(StaticAssert, DC, L), AssertExpr(assertexpr), Message(message) { }

public:
  static StaticAssertDecl *Create(ASTContext &C, DeclContext *DC,
                                  SourceLocation L, Expr *AssertExpr,
                                  StringLiteral *Message);

  Expr *getAssertExpr() { return AssertExpr; }
  const Expr *getAssertExpr() const { return AssertExpr; }

  StringLiteral *getMessage() { return Message; }
  const StringLiteral *getMessage() const { return Message; }

  virtual ~StaticAssertDecl();
  virtual void Destroy(ASTContext& C);

  static bool classof(const Decl *D) { return classofKind(D->getKind()); }
  static bool classof(StaticAssertDecl *D) { return true; }
  static bool classofKind(Kind K) { return K == Decl::StaticAssert; }
};

/// Insertion operator for diagnostics.  This allows sending AccessSpecifier's
/// into a diagnostic with <<.
const DiagnosticBuilder &operator<<(const DiagnosticBuilder &DB,
                                    AccessSpecifier AS);

} // end namespace clang

#endif
