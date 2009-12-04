//===--- TypeLoc.h - Type Source Info Wrapper -------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
//  This file defines the TypeLoc interface and subclasses.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_CLANG_AST_TYPELOC_H
#define LLVM_CLANG_AST_TYPELOC_H

#include "clang/AST/Type.h"
#include "clang/AST/TemplateBase.h"

namespace clang {
  class ParmVarDecl;
  class DeclaratorInfo;
  class UnqualTypeLoc;

// Predeclare all the type nodes.
#define ABSTRACT_TYPELOC(Class, Base)
#define TYPELOC(Class, Base) \
  class Class##TypeLoc;
#include "clang/AST/TypeLocNodes.def"

/// \brief Base wrapper for a particular "section" of type source info.
///
/// A client should use the TypeLoc subclasses through cast/dyn_cast in order to
/// get at the actual information.
class TypeLoc {
protected:
  // The correctness of this relies on the property that, for Type *Ty,
  //   QualType(Ty, 0).getAsOpaquePtr() == (void*) Ty
  void *Ty;
  void *Data;

public:
  /// The kinds of TypeLocs.  Equivalent to the Type::TypeClass enum,
  /// except it also defines a Qualified enum that corresponds to the
  /// QualifiedLoc class.
  enum TypeLocClass {
#define ABSTRACT_TYPE(Class, Base)
#define TYPE(Class, Base) \
    Class = Type::Class,
#include "clang/AST/TypeNodes.def"
    Qualified
  };

  TypeLoc() : Ty(0), Data(0) { }
  TypeLoc(QualType ty, void *opaqueData)
    : Ty(ty.getAsOpaquePtr()), Data(opaqueData) { }
  TypeLoc(Type *ty, void *opaqueData)
    : Ty(ty), Data(opaqueData) { }

  TypeLocClass getTypeLocClass() const {
    if (getType().hasLocalQualifiers()) return Qualified;
    return (TypeLocClass) getType()->getTypeClass();
  }

  bool isNull() const { return !Ty; }
  operator bool() const { return Ty; }

  /// \brief Returns the size of type source info data block for the given type.
  static unsigned getFullDataSizeForType(QualType Ty);

  /// \brief Get the type for which this source info wrapper provides
  /// information.
  QualType getType() const {
    return QualType::getFromOpaquePtr(Ty);
  }

  Type *getTypePtr() const {
    return QualType::getFromOpaquePtr(Ty).getTypePtr();
  }

  /// \brief Get the pointer where source information is stored.
  void *getOpaqueData() const {
    return Data;
  }

  /// \brief Get the full source range.
  SourceRange getFullSourceRange() const {
    SourceLocation End = getSourceRange().getEnd();
    TypeLoc Cur = *this;
    while (true) {
      TypeLoc Next = Cur.getNextTypeLoc();
      if (Next.isNull()) break;
      Cur = Next;
    }
    return SourceRange(Cur.getSourceRange().getBegin(), End);
  }

  /// \brief Get the local source range.
  SourceRange getSourceRange() const {
    return getSourceRangeImpl(*this);
  }

  /// \brief Returns the size of the type source info data block.
  unsigned getFullDataSize() const {
    return getFullDataSizeForType(getType());
  }

  /// \brief Get the next TypeLoc pointed by this TypeLoc, e.g for "int*" the
  /// TypeLoc is a PointerLoc and next TypeLoc is for "int".
  TypeLoc getNextTypeLoc() const {
    return getNextTypeLocImpl(*this);
  }

  /// \brief Skips past any qualifiers, if this is qualified.
  UnqualTypeLoc getUnqualifiedLoc() const; // implemented in this header

  /// \brief Initializes this to state that every location in this
  /// type is the given location.
  ///
  /// This method exists to provide a simple transition for code that
  /// relies on location-less types.
  void initialize(SourceLocation Loc) const {
    initializeImpl(*this, Loc);
  }

  friend bool operator==(const TypeLoc &LHS, const TypeLoc &RHS) {
    return LHS.Ty == RHS.Ty && LHS.Data == RHS.Data;
  }

  friend bool operator!=(const TypeLoc &LHS, const TypeLoc &RHS) {
    return !(LHS == RHS);
  }

  static bool classof(const TypeLoc *TL) { return true; }

private:
  static void initializeImpl(TypeLoc TL, SourceLocation Loc);
  static TypeLoc getNextTypeLocImpl(TypeLoc TL);
  static SourceRange getSourceRangeImpl(TypeLoc TL);
};

/// \brief Wrapper of type source information for a type with
/// no direct quqlaifiers.
class UnqualTypeLoc : public TypeLoc {
public:
  UnqualTypeLoc() {}
  UnqualTypeLoc(Type *Ty, void *Data) : TypeLoc(Ty, Data) {}

  Type *getTypePtr() const {
    return reinterpret_cast<Type*>(Ty);
  }

  TypeLocClass getTypeLocClass() const {
    return (TypeLocClass) getTypePtr()->getTypeClass();
  }

  static bool classof(const TypeLoc *TL) {
    return !TL->getType().hasLocalQualifiers();
  }
  static bool classof(const UnqualTypeLoc *TL) { return true; }
};

/// \brief Wrapper of type source information for a type with
/// non-trivial direct qualifiers.
///
/// Currently, we intentionally do not provide source location for
/// type qualifiers.
class QualifiedTypeLoc : public TypeLoc {
public:
  SourceRange getSourceRange() const {
    return SourceRange();
  }

  UnqualTypeLoc getUnqualifiedLoc() const {
    return UnqualTypeLoc(getTypePtr(), Data);
  }

  /// Initializes the local data of this type source info block to
  /// provide no information.
  void initializeLocal(SourceLocation Loc) {
    // do nothing
  }

  TypeLoc getNextTypeLoc() const {
    return getUnqualifiedLoc();
  }

  /// \brief Returns the size of the type source info data block that is
  /// specific to this type.
  unsigned getLocalDataSize() const {
    // In fact, we don't currently preserve any location information
    // for qualifiers.
    return 0;
  }

  /// \brief Returns the size of the type source info data block.
  unsigned getFullDataSize() const {
    return getLocalDataSize() + 
      getFullDataSizeForType(getType().getLocalUnqualifiedType());
  }

  static bool classof(const TypeLoc *TL) {
    return TL->getType().hasLocalQualifiers();
  }
  static bool classof(const QualifiedTypeLoc *TL) { return true; }
};

inline UnqualTypeLoc TypeLoc::getUnqualifiedLoc() const {
  if (isa<QualifiedTypeLoc>(this))
    return cast<QualifiedTypeLoc>(this)->getUnqualifiedLoc();
  return cast<UnqualTypeLoc>(*this);
}

/// A metaprogramming base class for TypeLoc classes which correspond
/// to a particular Type subclass.  It is accepted for a single
/// TypeLoc class to correspond to multiple Type classes.
///
/// \param Base a class from which to derive
/// \param Derived the class deriving from this one
/// \param TypeClass the concrete Type subclass associated with this
///   location type
/// \param LocalData the structure type of local location data for
///   this type
///
/// sizeof(LocalData) needs to be a multiple of sizeof(void*) or
/// else the world will end.
///
/// TypeLocs with non-constant amounts of local data should override
/// getExtraLocalDataSize(); getExtraLocalData() will then point to
/// this extra memory.
///
/// TypeLocs with an inner type should define
///   QualType getInnerType() const
/// and getInnerTypeLoc() will then point to this inner type's
/// location data.
///
/// A word about hierarchies: this template is not designed to be
/// derived from multiple times in a hierarchy.  It is also not
/// designed to be used for classes where subtypes might provide
/// different amounts of source information.  It should be subclassed
/// only at the deepest portion of the hierarchy where all children
/// have identical source information; if that's an abstract type,
/// then further descendents should inherit from
/// InheritingConcreteTypeLoc instead.
template <class Base, class Derived, class TypeClass, class LocalData>
class ConcreteTypeLoc : public Base {

  const Derived *asDerived() const {
    return static_cast<const Derived*>(this);
  }

public:
  unsigned getLocalDataSize() const {
    return sizeof(LocalData) + asDerived()->getExtraLocalDataSize();
  }
  // Give a default implementation that's useful for leaf types.
  unsigned getFullDataSize() const {
    return asDerived()->getLocalDataSize() + getInnerTypeSize();
  }

  static bool classofType(const Type *Ty) {
    return TypeClass::classof(Ty);
  }

  TypeLoc getNextTypeLoc() const {
    return getNextTypeLoc(asDerived()->getInnerType());
  }

  TypeClass *getTypePtr() const {
    return cast<TypeClass>(Base::getTypePtr());
  }

protected:
  unsigned getExtraLocalDataSize() const {
    return 0;
  }

  LocalData *getLocalData() const {
    return static_cast<LocalData*>(Base::Data);
  }

  /// Gets a pointer past the Info structure; useful for classes with
  /// local data that can't be captured in the Info (e.g. because it's
  /// of variable size).
  void *getExtraLocalData() const {
    return getLocalData() + 1;
  }
  
  void *getNonLocalData() const {
    return static_cast<char*>(Base::Data) + asDerived()->getLocalDataSize();
  }

  struct HasNoInnerType {};
  HasNoInnerType getInnerType() const { return HasNoInnerType(); }

  TypeLoc getInnerTypeLoc() const {
    return TypeLoc(asDerived()->getInnerType(), getNonLocalData());
  }

private:
  unsigned getInnerTypeSize() const {
    return getInnerTypeSize(asDerived()->getInnerType());
  }

  unsigned getInnerTypeSize(HasNoInnerType _) const {
    return 0;
  }

  unsigned getInnerTypeSize(QualType _) const {
    return getInnerTypeLoc().getFullDataSize();
  }

  TypeLoc getNextTypeLoc(HasNoInnerType _) const {
    return TypeLoc();
  }

  TypeLoc getNextTypeLoc(QualType T) const {
    return TypeLoc(T, getNonLocalData());
  }
};

/// A metaprogramming class designed for concrete subtypes of abstract
/// types where all subtypes share equivalently-structured source
/// information.  See the note on ConcreteTypeLoc.
template <class Base, class Derived, class TypeClass>
class InheritingConcreteTypeLoc : public Base {
public:
  static bool classof(const TypeLoc *TL) {
    return Derived::classofType(TL->getTypePtr());
  }
  static bool classof(const UnqualTypeLoc *TL) {
    return Derived::classofType(TL->getTypePtr());
  }
  static bool classof(const Derived *TL) {
    return true;
  }

  TypeClass *getTypePtr() const {
    return cast<TypeClass>(Base::getTypePtr());
  }
};


struct TypeSpecLocInfo {
  SourceLocation NameLoc;
};

/// \brief A reasonable base class for TypeLocs that correspond to
/// types that are written as a type-specifier.
class TypeSpecTypeLoc : public ConcreteTypeLoc<UnqualTypeLoc, 
                                               TypeSpecTypeLoc,
                                               Type,
                                               TypeSpecLocInfo> {
public:
  enum { LocalDataSize = sizeof(TypeSpecLocInfo) };

  SourceLocation getNameLoc() const {
    return this->getLocalData()->NameLoc;
  }
  void setNameLoc(SourceLocation Loc) {
    this->getLocalData()->NameLoc = Loc;
  }
  SourceRange getSourceRange() const {
    return SourceRange(getNameLoc(), getNameLoc());
  }
  void initializeLocal(SourceLocation Loc) {
    setNameLoc(Loc);
  }

  static bool classof(const TypeLoc *TL);
  static bool classof(const TypeSpecTypeLoc *TL) { return true; }
};


/// \brief Wrapper for source info for typedefs.
class TypedefTypeLoc : public InheritingConcreteTypeLoc<TypeSpecTypeLoc,
                                                        TypedefTypeLoc,
                                                        TypedefType> {
public:
  TypedefDecl *getTypedefDecl() const {
    return getTypePtr()->getDecl();
  }
};

/// \brief Wrapper for source info for unresolved typename using decls.
class UnresolvedUsingTypeLoc :
    public InheritingConcreteTypeLoc<TypeSpecTypeLoc,
                                     UnresolvedUsingTypeLoc,
                                     UnresolvedUsingType> {
public:
  UnresolvedUsingTypenameDecl *getDecl() const {
    return getTypePtr()->getDecl();
  }
};

/// \brief Wrapper for source info for tag types.  Note that this only
/// records source info for the name itself; a type written 'struct foo'
/// should be represented as an ElaboratedTypeLoc.  We currently
/// only do that when C++ is enabled because of the expense of
/// creating an ElaboratedType node for so many type references in C.
class TagTypeLoc : public InheritingConcreteTypeLoc<TypeSpecTypeLoc,
                                                    TagTypeLoc,
                                                    TagType> {
public:
  TagDecl *getDecl() const { return getTypePtr()->getDecl(); }
};

/// \brief Wrapper for source info for record types.
class RecordTypeLoc : public InheritingConcreteTypeLoc<TagTypeLoc,
                                                       RecordTypeLoc,
                                                       RecordType> {
public:
  RecordDecl *getDecl() const { return getTypePtr()->getDecl(); }
};

/// \brief Wrapper for source info for enum types.
class EnumTypeLoc : public InheritingConcreteTypeLoc<TagTypeLoc,
                                                     EnumTypeLoc,
                                                     EnumType> {
public:
  EnumDecl *getDecl() const { return getTypePtr()->getDecl(); }
};

/// \brief Wrapper for source info for builtin types.
class BuiltinTypeLoc : public InheritingConcreteTypeLoc<TypeSpecTypeLoc,
                                                        BuiltinTypeLoc,
                                                        BuiltinType> {
};

/// \brief Wrapper for template type parameters.
class TemplateTypeParmTypeLoc :
    public InheritingConcreteTypeLoc<TypeSpecTypeLoc,
                                     TemplateTypeParmTypeLoc,
                                     TemplateTypeParmType> {
};

/// \brief Wrapper for substituted template type parameters.
class SubstTemplateTypeParmTypeLoc :
    public InheritingConcreteTypeLoc<TypeSpecTypeLoc,
                                     SubstTemplateTypeParmTypeLoc,
                                     SubstTemplateTypeParmType> {
};


struct ObjCProtocolListLocInfo {
  SourceLocation LAngleLoc;
  SourceLocation RAngleLoc;
};

// A helper class for defining ObjC TypeLocs that can qualified with
// protocols.
//
// TypeClass basically has to be either ObjCInterfaceType or
// ObjCObjectPointerType.
template <class Derived, class TypeClass, class LocalData>
class ObjCProtocolListTypeLoc : public ConcreteTypeLoc<UnqualTypeLoc,
                                                       Derived,
                                                       TypeClass,
                                                       LocalData> {
  // SourceLocations are stored after Info, one for each Protocol.
  SourceLocation *getProtocolLocArray() const {
    return (SourceLocation*) this->getExtraLocalData();
  }

protected:
  void initializeLocalBase(SourceLocation Loc) {
    setLAngleLoc(Loc);
    setRAngleLoc(Loc);
    for (unsigned i = 0, e = getNumProtocols(); i != e; ++i)
      setProtocolLoc(i, Loc);
  }

public:
  SourceLocation getLAngleLoc() const {
    return this->getLocalData()->LAngleLoc;
  }
  void setLAngleLoc(SourceLocation Loc) {
    this->getLocalData()->LAngleLoc = Loc;
  }

  SourceLocation getRAngleLoc() const {
    return this->getLocalData()->RAngleLoc;
  }
  void setRAngleLoc(SourceLocation Loc) {
    this->getLocalData()->RAngleLoc = Loc;
  }

  unsigned getNumProtocols() const {
    return this->getTypePtr()->getNumProtocols();
  }

  SourceLocation getProtocolLoc(unsigned i) const {
    assert(i < getNumProtocols() && "Index is out of bounds!");
    return getProtocolLocArray()[i];
  }
  void setProtocolLoc(unsigned i, SourceLocation Loc) {
    assert(i < getNumProtocols() && "Index is out of bounds!");
    getProtocolLocArray()[i] = Loc;
  }

  ObjCProtocolDecl *getProtocol(unsigned i) const {
    assert(i < getNumProtocols() && "Index is out of bounds!");
    return *(this->getTypePtr()->qual_begin() + i);
  }
  
  SourceRange getSourceRange() const {
    return SourceRange(getLAngleLoc(), getRAngleLoc());
  }

  void initializeLocal(SourceLocation Loc) {
    initializeLocalBase(Loc);
  }

  unsigned getExtraLocalDataSize() const {
    return this->getNumProtocols() * sizeof(SourceLocation);
  }
};


struct ObjCInterfaceLocInfo : ObjCProtocolListLocInfo {
  SourceLocation NameLoc;
};

/// \brief Wrapper for source info for ObjC interfaces.
class ObjCInterfaceTypeLoc :
    public ObjCProtocolListTypeLoc<ObjCInterfaceTypeLoc,
                                   ObjCInterfaceType,
                                   ObjCInterfaceLocInfo> {
public:
  ObjCInterfaceDecl *getIFaceDecl() const {
    return getTypePtr()->getDecl();
  }

  SourceLocation getNameLoc() const {
    return getLocalData()->NameLoc;
  }

  void setNameLoc(SourceLocation Loc) {
    getLocalData()->NameLoc = Loc;
  }

  SourceRange getSourceRange() const {
    if (getNumProtocols()) 
      return SourceRange(getNameLoc(), getRAngleLoc());
    else
      return SourceRange(getNameLoc(), getNameLoc());
  }

  void initializeLocal(SourceLocation Loc) {
    initializeLocalBase(Loc);
    setNameLoc(Loc);
  }
};


struct ObjCObjectPointerLocInfo : ObjCProtocolListLocInfo {
  SourceLocation StarLoc;
  bool HasProtocols;
  bool HasBaseType;
};

/// Wraps an ObjCPointerType with source location information.  Note
/// that not all ObjCPointerTypes actually have a star location; nor
/// are protocol locations necessarily written in the source just
/// because they're present on the type.
class ObjCObjectPointerTypeLoc :
    public ObjCProtocolListTypeLoc<ObjCObjectPointerTypeLoc,
                                   ObjCObjectPointerType,
                                   ObjCObjectPointerLocInfo> {
public:
  bool hasProtocolsAsWritten() const {
    return getLocalData()->HasProtocols;
  }

  void setHasProtocolsAsWritten(bool HasProtocols) {
    getLocalData()->HasProtocols = HasProtocols;
  }

  bool hasBaseTypeAsWritten() const {
    return getLocalData()->HasBaseType;
  }

  void setHasBaseTypeAsWritten(bool HasBaseType) {
    getLocalData()->HasBaseType = HasBaseType;
  }

  SourceLocation getStarLoc() const {
    return getLocalData()->StarLoc;
  }

  void setStarLoc(SourceLocation Loc) {
    getLocalData()->StarLoc = Loc;
  }

  SourceRange getSourceRange() const {
    // Being written with protocols is incompatible with being written
    // with a star.
    if (hasProtocolsAsWritten())
      return SourceRange(getLAngleLoc(), getRAngleLoc());
    else
      return SourceRange(getStarLoc(), getStarLoc());
  }

  void initializeLocal(SourceLocation Loc) {
    initializeLocalBase(Loc);
    setHasProtocolsAsWritten(false);
    setHasBaseTypeAsWritten(false);
    setStarLoc(Loc);
  }

  TypeLoc getBaseTypeLoc() const {
    return getInnerTypeLoc();
  }

  QualType getInnerType() const {
    return getTypePtr()->getPointeeType();
  }
};


struct PointerLikeLocInfo {
  SourceLocation StarLoc;
};

/// A base class for 
template <class Derived, class TypeClass, class LocalData = PointerLikeLocInfo>
class PointerLikeTypeLoc : public ConcreteTypeLoc<UnqualTypeLoc, Derived,
                                                  TypeClass, LocalData> {
public:  
  SourceLocation getSigilLoc() const {
    return this->getLocalData()->StarLoc;
  }
  void setSigilLoc(SourceLocation Loc) {
    this->getLocalData()->StarLoc = Loc;
  }

  TypeLoc getPointeeLoc() const {
    return this->getInnerTypeLoc();
  }

  SourceRange getSourceRange() const {
    return SourceRange(getSigilLoc(), getSigilLoc());
  }

  void initializeLocal(SourceLocation Loc) {
    setSigilLoc(Loc);
  }

  QualType getInnerType() const {
    return this->getTypePtr()->getPointeeType();
  }
};


/// \brief Wrapper for source info for pointers.
class PointerTypeLoc : public PointerLikeTypeLoc<PointerTypeLoc,
                                                 PointerType> {
public:
  SourceLocation getStarLoc() const {
    return getSigilLoc();
  }
  void setStarLoc(SourceLocation Loc) {
    setSigilLoc(Loc);
  }
};


/// \brief Wrapper for source info for block pointers.
class BlockPointerTypeLoc : public PointerLikeTypeLoc<BlockPointerTypeLoc,
                                                      BlockPointerType> {
public:
  SourceLocation getCaretLoc() const {
    return getSigilLoc();
  }
  void setCaretLoc(SourceLocation Loc) {
    setSigilLoc(Loc);
  }
};


/// \brief Wrapper for source info for member pointers.
class MemberPointerTypeLoc : public PointerLikeTypeLoc<MemberPointerTypeLoc,
                                                       MemberPointerType> {
public:
  SourceLocation getStarLoc() const {
    return getSigilLoc();
  }
  void setStarLoc(SourceLocation Loc) {
    setSigilLoc(Loc);
  }
};


class ReferenceTypeLoc : public PointerLikeTypeLoc<ReferenceTypeLoc,
                                                   ReferenceType> {
public:
  QualType getInnerType() const {
    return getTypePtr()->getPointeeTypeAsWritten();
  }
};

class LValueReferenceTypeLoc :
    public InheritingConcreteTypeLoc<ReferenceTypeLoc,
                                     LValueReferenceTypeLoc,
                                     LValueReferenceType> {
public:
  SourceLocation getAmpLoc() const {
    return getSigilLoc();
  }
  void setAmpLoc(SourceLocation Loc) {
    setSigilLoc(Loc);
  }
};

class RValueReferenceTypeLoc :
    public InheritingConcreteTypeLoc<ReferenceTypeLoc,
                                     RValueReferenceTypeLoc,
                                     RValueReferenceType> {
public:
  SourceLocation getAmpAmpLoc() const {
    return getSigilLoc();
  }
  void setAmpAmpLoc(SourceLocation Loc) {
    setSigilLoc(Loc);
  }
};


struct FunctionLocInfo {
  SourceLocation LParenLoc, RParenLoc;
};

/// \brief Wrapper for source info for functions.
class FunctionTypeLoc : public ConcreteTypeLoc<UnqualTypeLoc,
                                               FunctionTypeLoc,
                                               FunctionType,
                                               FunctionLocInfo> {
  // ParmVarDecls* are stored after Info, one for each argument.
  ParmVarDecl **getParmArray() const {
    return (ParmVarDecl**) getExtraLocalData();
  }

public:
  SourceLocation getLParenLoc() const {
    return getLocalData()->LParenLoc;
  }
  void setLParenLoc(SourceLocation Loc) {
    getLocalData()->LParenLoc = Loc;
  }

  SourceLocation getRParenLoc() const {
    return getLocalData()->RParenLoc;
  }
  void setRParenLoc(SourceLocation Loc) {
    getLocalData()->RParenLoc = Loc;
  }

  unsigned getNumArgs() const {
    if (isa<FunctionNoProtoType>(getTypePtr()))
      return 0;
    return cast<FunctionProtoType>(getTypePtr())->getNumArgs();
  }
  ParmVarDecl *getArg(unsigned i) const { return getParmArray()[i]; }
  void setArg(unsigned i, ParmVarDecl *VD) { getParmArray()[i] = VD; }

  TypeLoc getArgLoc(unsigned i) const;

  TypeLoc getResultLoc() const {
    return getInnerTypeLoc();
  }

  SourceRange getSourceRange() const {
    return SourceRange(getLParenLoc(), getRParenLoc());
  }

  void initializeLocal(SourceLocation Loc) {
    setLParenLoc(Loc);
    setRParenLoc(Loc);
    for (unsigned i = 0, e = getNumArgs(); i != e; ++i)
      setArg(i, NULL);
  }

  /// \brief Returns the size of the type source info data block that is
  /// specific to this type.
  unsigned getExtraLocalDataSize() const {
    return getNumArgs() * sizeof(ParmVarDecl*);
  }

  QualType getInnerType() const { return getTypePtr()->getResultType(); }
};

class FunctionProtoTypeLoc :
    public InheritingConcreteTypeLoc<FunctionTypeLoc,
                                     FunctionProtoTypeLoc,
                                     FunctionProtoType> {
};

class FunctionNoProtoTypeLoc :
    public InheritingConcreteTypeLoc<FunctionTypeLoc,
                                     FunctionNoProtoTypeLoc,
                                     FunctionNoProtoType> {
};


struct ArrayLocInfo {
  SourceLocation LBracketLoc, RBracketLoc;
  Expr *Size;
};

/// \brief Wrapper for source info for arrays.
class ArrayTypeLoc : public ConcreteTypeLoc<UnqualTypeLoc,
                                            ArrayTypeLoc,
                                            ArrayType,
                                            ArrayLocInfo> {
public:
  SourceLocation getLBracketLoc() const {
    return getLocalData()->LBracketLoc;
  }
  void setLBracketLoc(SourceLocation Loc) {
    getLocalData()->LBracketLoc = Loc;
  }

  SourceLocation getRBracketLoc() const {
    return getLocalData()->RBracketLoc;
  }
  void setRBracketLoc(SourceLocation Loc) {
    getLocalData()->RBracketLoc = Loc;
  }

  SourceRange getBracketsRange() const {
    return SourceRange(getLBracketLoc(), getRBracketLoc());
  }

  Expr *getSizeExpr() const {
    return getLocalData()->Size;
  }
  void setSizeExpr(Expr *Size) {
    getLocalData()->Size = Size;
  }

  TypeLoc getElementLoc() const {
    return getInnerTypeLoc();
  }

  SourceRange getSourceRange() const {
    return SourceRange(getLBracketLoc(), getRBracketLoc());
  }

  void initializeLocal(SourceLocation Loc) {
    setLBracketLoc(Loc);
    setRBracketLoc(Loc);
    setSizeExpr(NULL);
  }

  QualType getInnerType() const { return getTypePtr()->getElementType(); }
};

class ConstantArrayTypeLoc :
    public InheritingConcreteTypeLoc<ArrayTypeLoc,
                                     ConstantArrayTypeLoc,
                                     ConstantArrayType> {
};

class IncompleteArrayTypeLoc :
    public InheritingConcreteTypeLoc<ArrayTypeLoc,
                                     IncompleteArrayTypeLoc,
                                     IncompleteArrayType> {
};

class DependentSizedArrayTypeLoc :
    public InheritingConcreteTypeLoc<ArrayTypeLoc,
                                     DependentSizedArrayTypeLoc,
                                     DependentSizedArrayType> {

};

class VariableArrayTypeLoc :
    public InheritingConcreteTypeLoc<ArrayTypeLoc,
                                     VariableArrayTypeLoc,
                                     VariableArrayType> {
};


// Location information for a TemplateName.  Rudimentary for now.
struct TemplateNameLocInfo {
  SourceLocation NameLoc;
};

struct TemplateSpecializationLocInfo : TemplateNameLocInfo {
  SourceLocation LAngleLoc;
  SourceLocation RAngleLoc;
};

class TemplateSpecializationTypeLoc :
    public ConcreteTypeLoc<UnqualTypeLoc,
                           TemplateSpecializationTypeLoc,
                           TemplateSpecializationType,
                           TemplateSpecializationLocInfo> {
public:
  SourceLocation getLAngleLoc() const {
    return getLocalData()->LAngleLoc;
  }
  void setLAngleLoc(SourceLocation Loc) {
    getLocalData()->LAngleLoc = Loc;
  }

  SourceLocation getRAngleLoc() const {
    return getLocalData()->RAngleLoc;
  }
  void setRAngleLoc(SourceLocation Loc) {
    getLocalData()->RAngleLoc = Loc;
  }

  unsigned getNumArgs() const {
    return getTypePtr()->getNumArgs();
  }
  void setArgLocInfo(unsigned i, TemplateArgumentLocInfo AI) {
#ifndef NDEBUG
    AI.validateForArgument(getTypePtr()->getArg(i));
#endif
    getArgInfos()[i] = AI;
  }
  TemplateArgumentLocInfo getArgLocInfo(unsigned i) const {
    return getArgInfos()[i];
  }

  TemplateArgumentLoc getArgLoc(unsigned i) const {
    return TemplateArgumentLoc(getTypePtr()->getArg(i), getArgLocInfo(i));
  }

  SourceLocation getTemplateNameLoc() const {
    return getLocalData()->NameLoc;
  }
  void setTemplateNameLoc(SourceLocation Loc) {
    getLocalData()->NameLoc = Loc;
  }

  /// \brief - Copy the location information from the given info.
  void copy(TemplateSpecializationTypeLoc Loc) {
    unsigned size = getFullDataSize();
    assert(size == Loc.getFullDataSize());

    // We're potentially copying Expr references here.  We don't
    // bother retaining them because DeclaratorInfos live forever, so
    // as long as the Expr was retained when originally written into
    // the TypeLoc, we're okay.
    memcpy(Data, Loc.Data, size);
  }

  SourceRange getSourceRange() const {
    return SourceRange(getTemplateNameLoc(), getRAngleLoc());
  }

  void initializeLocal(SourceLocation Loc) {
    setLAngleLoc(Loc);
    setRAngleLoc(Loc);
    setTemplateNameLoc(Loc);

    for (unsigned i = 0, e = getNumArgs(); i != e; ++i) {
      TemplateArgumentLocInfo Info;
#ifndef NDEBUG
      // If asserts are enabled, be sure to initialize the argument
      // loc with the right kind of pointer.
      switch (getTypePtr()->getArg(i).getKind()) {
      case TemplateArgument::Expression:
      case TemplateArgument::Declaration:
        Info = TemplateArgumentLocInfo((Expr*) 0);
        break;

      case TemplateArgument::Type:
        Info = TemplateArgumentLocInfo((DeclaratorInfo*) 0);
        break;

      case TemplateArgument::Template:
        Info = TemplateArgumentLocInfo(SourceRange(), SourceLocation());
        break;
          
      case TemplateArgument::Integral:
      case TemplateArgument::Pack:
      case TemplateArgument::Null:
        // K_None is fine.
        break;
      }
#endif
      getArgInfos()[i] = Info;
    }
  }

  unsigned getExtraLocalDataSize() const {
    return getNumArgs() * sizeof(TemplateArgumentLocInfo);
  }

private:
  TemplateArgumentLocInfo *getArgInfos() const {
    return static_cast<TemplateArgumentLocInfo*>(getExtraLocalData());
  }
};

//===----------------------------------------------------------------------===//
//
//  All of these need proper implementations.
//
//===----------------------------------------------------------------------===//

// FIXME: size expression and attribute locations (or keyword if we
// ever fully support altivec syntax).
class VectorTypeLoc : public InheritingConcreteTypeLoc<TypeSpecTypeLoc,
                                                       VectorTypeLoc,
                                                       VectorType> {
};

// FIXME: size expression and attribute locations.
class ExtVectorTypeLoc : public InheritingConcreteTypeLoc<VectorTypeLoc,
                                                          ExtVectorTypeLoc,
                                                          ExtVectorType> {
};

// FIXME: attribute locations.
// For some reason, this isn't a subtype of VectorType.
class DependentSizedExtVectorTypeLoc :
    public InheritingConcreteTypeLoc<TypeSpecTypeLoc,
                                     DependentSizedExtVectorTypeLoc,
                                     DependentSizedExtVectorType> {
};

// FIXME: I'm not sure how you actually specify these;  with attributes?
class FixedWidthIntTypeLoc :
    public InheritingConcreteTypeLoc<TypeSpecTypeLoc,
                                     FixedWidthIntTypeLoc,
                                     FixedWidthIntType> {
};

// FIXME: location of the '_Complex' keyword.
class ComplexTypeLoc : public InheritingConcreteTypeLoc<TypeSpecTypeLoc,
                                                        ComplexTypeLoc,
                                                        ComplexType> {
};

// FIXME: location of the 'typeof' and parens (the expression is
// carried by the type).
class TypeOfExprTypeLoc : public InheritingConcreteTypeLoc<TypeSpecTypeLoc,
                                                           TypeOfExprTypeLoc,
                                                           TypeOfExprType> {
};

// FIXME: location of the 'typeof' and parens; also the DeclaratorInfo
// for the inner type, or (maybe) just express that inline to the TypeLoc.
class TypeOfTypeLoc : public InheritingConcreteTypeLoc<TypeSpecTypeLoc,
                                                       TypeOfTypeLoc,
                                                       TypeOfType> {
};

// FIXME: location of the 'decltype' and parens.
class DecltypeTypeLoc : public InheritingConcreteTypeLoc<TypeSpecTypeLoc,
                                                         DecltypeTypeLoc,
                                                         DecltypeType> {
};

// FIXME: location of the tag keyword.
class ElaboratedTypeLoc : public InheritingConcreteTypeLoc<TypeSpecTypeLoc,
                                                           ElaboratedTypeLoc,
                                                           ElaboratedType> {
};

// FIXME: locations for the nested name specifier;  at the very least,
// a SourceRange.
class QualifiedNameTypeLoc :
    public InheritingConcreteTypeLoc<TypeSpecTypeLoc,
                                     QualifiedNameTypeLoc,
                                     QualifiedNameType> {
};

// FIXME: locations for the typename keyword and nested name specifier.
class TypenameTypeLoc : public InheritingConcreteTypeLoc<TypeSpecTypeLoc,
                                                         TypenameTypeLoc,
                                                         TypenameType> {
};

}

#endif
