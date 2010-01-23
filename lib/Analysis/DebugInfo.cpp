//===--- DebugInfo.cpp - Debug Information Helper Classes -----------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements the helper classes used to build and interpret debug
// information in LLVM IR form.
//
//===----------------------------------------------------------------------===//

#include "llvm/Analysis/DebugInfo.h"
#include "llvm/Target/TargetMachine.h"  // FIXME: LAYERING VIOLATION!
#include "llvm/Constants.h"
#include "llvm/DerivedTypes.h"
#include "llvm/Intrinsics.h"
#include "llvm/IntrinsicInst.h"
#include "llvm/Instructions.h"
#include "llvm/Module.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/Dwarf.h"
#include "llvm/Support/DebugLoc.h"
#include "llvm/Support/raw_ostream.h"
using namespace llvm;
using namespace llvm::dwarf;

//===----------------------------------------------------------------------===//
// DIDescriptor
//===----------------------------------------------------------------------===//

/// ValidDebugInfo - Return true if V represents valid debug info value.
/// FIXME : Add DIDescriptor.isValid()
bool DIDescriptor::ValidDebugInfo(MDNode *N, unsigned OptLevel) {
  if (!N)
    return false;

  DIDescriptor DI(N);

  // Check current version. Allow Version6 for now.
  unsigned Version = DI.getVersion();
  if (Version != LLVMDebugVersion && Version != LLVMDebugVersion6)
    return false;

  switch (DI.getTag()) {
  case DW_TAG_variable:
    assert(DIVariable(N).Verify() && "Invalid DebugInfo value");
    break;
  case DW_TAG_compile_unit:
    assert(DICompileUnit(N).Verify() && "Invalid DebugInfo value");
    break;
  case DW_TAG_subprogram:
    assert(DISubprogram(N).Verify() && "Invalid DebugInfo value");
    break;
  case DW_TAG_lexical_block:
    // FIXME: This interfers with the quality of generated code during
    // optimization.
    if (OptLevel != CodeGenOpt::None)
      return false;
    // FALLTHROUGH
  default:
    break;
  }

  return true;
}

DIDescriptor::DIDescriptor(MDNode *N, unsigned RequiredTag) {
  DbgNode = N;

  // If this is non-null, check to see if the Tag matches. If not, set to null.
  if (N && getTag() != RequiredTag) {
    DbgNode = 0;
  }
}

StringRef 
DIDescriptor::getStringField(unsigned Elt) const {
  if (DbgNode == 0)
    return StringRef();

  if (Elt < DbgNode->getNumOperands())
    if (MDString *MDS = dyn_cast_or_null<MDString>(DbgNode->getOperand(Elt)))
      return MDS->getString();

  return StringRef();
}

uint64_t DIDescriptor::getUInt64Field(unsigned Elt) const {
  if (DbgNode == 0)
    return 0;

  if (Elt < DbgNode->getNumOperands())
    if (ConstantInt *CI = dyn_cast<ConstantInt>(DbgNode->getOperand(Elt)))
      return CI->getZExtValue();

  return 0;
}

DIDescriptor DIDescriptor::getDescriptorField(unsigned Elt) const {
  if (DbgNode == 0)
    return DIDescriptor();

  if (Elt < DbgNode->getNumOperands() && DbgNode->getOperand(Elt))
    return DIDescriptor(dyn_cast<MDNode>(DbgNode->getOperand(Elt)));

  return DIDescriptor();
}

GlobalVariable *DIDescriptor::getGlobalVariableField(unsigned Elt) const {
  if (DbgNode == 0)
    return 0;

  if (Elt < DbgNode->getNumOperands())
      return dyn_cast_or_null<GlobalVariable>(DbgNode->getOperand(Elt));
  return 0;
}

unsigned DIVariable::getNumAddrElements() const {
  return DbgNode->getNumOperands()-6;
}


//===----------------------------------------------------------------------===//
// Predicates
//===----------------------------------------------------------------------===//

/// isBasicType - Return true if the specified tag is legal for
/// DIBasicType.
bool DIDescriptor::isBasicType() const {
  assert(!isNull() && "Invalid descriptor!");
  return getTag() == dwarf::DW_TAG_base_type;
}

/// isDerivedType - Return true if the specified tag is legal for DIDerivedType.
bool DIDescriptor::isDerivedType() const {
  assert(!isNull() && "Invalid descriptor!");
  switch (getTag()) {
  case dwarf::DW_TAG_typedef:
  case dwarf::DW_TAG_pointer_type:
  case dwarf::DW_TAG_reference_type:
  case dwarf::DW_TAG_const_type:
  case dwarf::DW_TAG_volatile_type:
  case dwarf::DW_TAG_restrict_type:
  case dwarf::DW_TAG_member:
  case dwarf::DW_TAG_inheritance:
    return true;
  default:
    // CompositeTypes are currently modelled as DerivedTypes.
    return isCompositeType();
  }
}

/// isCompositeType - Return true if the specified tag is legal for
/// DICompositeType.
bool DIDescriptor::isCompositeType() const {
  assert(!isNull() && "Invalid descriptor!");
  switch (getTag()) {
  case dwarf::DW_TAG_array_type:
  case dwarf::DW_TAG_structure_type:
  case dwarf::DW_TAG_union_type:
  case dwarf::DW_TAG_enumeration_type:
  case dwarf::DW_TAG_vector_type:
  case dwarf::DW_TAG_subroutine_type:
  case dwarf::DW_TAG_class_type:
    return true;
  default:
    return false;
  }
}

/// isVariable - Return true if the specified tag is legal for DIVariable.
bool DIDescriptor::isVariable() const {
  assert(!isNull() && "Invalid descriptor!");
  switch (getTag()) {
  case dwarf::DW_TAG_auto_variable:
  case dwarf::DW_TAG_arg_variable:
  case dwarf::DW_TAG_return_variable:
    return true;
  default:
    return false;
  }
}

/// isType - Return true if the specified tag is legal for DIType.
bool DIDescriptor::isType() const {
  return isBasicType() || isCompositeType() || isDerivedType();
}

/// isSubprogram - Return true if the specified tag is legal for
/// DISubprogram.
bool DIDescriptor::isSubprogram() const {
  assert(!isNull() && "Invalid descriptor!");
  return getTag() == dwarf::DW_TAG_subprogram;
}

/// isGlobalVariable - Return true if the specified tag is legal for
/// DIGlobalVariable.
bool DIDescriptor::isGlobalVariable() const {
  assert(!isNull() && "Invalid descriptor!");
  return getTag() == dwarf::DW_TAG_variable;
}

/// isGlobal - Return true if the specified tag is legal for DIGlobal.
bool DIDescriptor::isGlobal() const {
  return isGlobalVariable();
}

/// isScope - Return true if the specified tag is one of the scope
/// related tag.
bool DIDescriptor::isScope() const {
  assert(!isNull() && "Invalid descriptor!");
  switch (getTag()) {
  case dwarf::DW_TAG_compile_unit:
  case dwarf::DW_TAG_lexical_block:
  case dwarf::DW_TAG_subprogram:
  case dwarf::DW_TAG_namespace:
    return true;
  default:
    break;
  }
  return false;
}

/// isCompileUnit - Return true if the specified tag is DW_TAG_compile_unit.
bool DIDescriptor::isCompileUnit() const {
  assert(!isNull() && "Invalid descriptor!");
  return getTag() == dwarf::DW_TAG_compile_unit;
}

/// isNameSpace - Return true if the specified tag is DW_TAG_namespace.
bool DIDescriptor::isNameSpace() const {
  assert(!isNull() && "Invalid descriptor!");
  return getTag() == dwarf::DW_TAG_namespace;
}

/// isLexicalBlock - Return true if the specified tag is DW_TAG_lexical_block.
bool DIDescriptor::isLexicalBlock() const {
  assert(!isNull() && "Invalid descriptor!");
  return getTag() == dwarf::DW_TAG_lexical_block;
}

/// isSubrange - Return true if the specified tag is DW_TAG_subrange_type.
bool DIDescriptor::isSubrange() const {
  assert(!isNull() && "Invalid descriptor!");
  return getTag() == dwarf::DW_TAG_subrange_type;
}

/// isEnumerator - Return true if the specified tag is DW_TAG_enumerator.
bool DIDescriptor::isEnumerator() const {
  assert(!isNull() && "Invalid descriptor!");
  return getTag() == dwarf::DW_TAG_enumerator;
}

//===----------------------------------------------------------------------===//
// Simple Descriptor Constructors and other Methods
//===----------------------------------------------------------------------===//

DIType::DIType(MDNode *N) : DIDescriptor(N) {
  if (!N) return;
  if (!isBasicType() && !isDerivedType() && !isCompositeType()) {
    DbgNode = 0;
  }
}

unsigned DIArray::getNumElements() const {
  assert(DbgNode && "Invalid DIArray");
  return DbgNode->getNumOperands();
}

/// replaceAllUsesWith - Replace all uses of debug info referenced by
/// this descriptor. After this completes, the current debug info value
/// is erased.
void DIDerivedType::replaceAllUsesWith(DIDescriptor &D) {
  if (isNull())
    return;

  assert(!D.isNull() && "Can not replace with null");

  // Since we use a TrackingVH for the node, its easy for clients to manufacture
  // legitimate situations where they want to replaceAllUsesWith() on something
  // which, due to uniquing, has merged with the source. We shield clients from
  // this detail by allowing a value to be replaced with replaceAllUsesWith()
  // itself.
  if (getNode() != D.getNode()) {
    MDNode *Node = DbgNode;
    Node->replaceAllUsesWith(D.getNode());
    Node->destroy();
  }
}

/// Verify - Verify that a compile unit is well formed.
bool DICompileUnit::Verify() const {
  if (isNull())
    return false;
  StringRef N = getFilename();
  if (N.empty())
    return false;
  // It is possible that directory and produce string is empty.
  return true;
}

/// Verify - Verify that a type descriptor is well formed.
bool DIType::Verify() const {
  if (isNull())
    return false;
  if (getContext().isNull())
    return false;

  DICompileUnit CU = getCompileUnit();
  if (!CU.isNull() && !CU.Verify())
    return false;
  return true;
}

/// Verify - Verify that a composite type descriptor is well formed.
bool DICompositeType::Verify() const {
  if (isNull())
    return false;
  if (getContext().isNull())
    return false;

  DICompileUnit CU = getCompileUnit();
  if (!CU.isNull() && !CU.Verify())
    return false;
  return true;
}

/// Verify - Verify that a subprogram descriptor is well formed.
bool DISubprogram::Verify() const {
  if (isNull())
    return false;

  if (getContext().isNull())
    return false;

  DICompileUnit CU = getCompileUnit();
  if (!CU.Verify())
    return false;

  DICompositeType Ty = getType();
  if (!Ty.isNull() && !Ty.Verify())
    return false;
  return true;
}

/// Verify - Verify that a global variable descriptor is well formed.
bool DIGlobalVariable::Verify() const {
  if (isNull())
    return false;

  if (getDisplayName().empty())
    return false;

  if (getContext().isNull())
    return false;

  DICompileUnit CU = getCompileUnit();
  if (!CU.isNull() && !CU.Verify())
    return false;

  DIType Ty = getType();
  if (!Ty.Verify())
    return false;

  if (!getGlobal())
    return false;

  return true;
}

/// Verify - Verify that a variable descriptor is well formed.
bool DIVariable::Verify() const {
  if (isNull())
    return false;

  if (getContext().isNull())
    return false;

  DIType Ty = getType();
  if (!Ty.Verify())
    return false;

  return true;
}

/// getOriginalTypeSize - If this type is derived from a base type then
/// return base type size.
uint64_t DIDerivedType::getOriginalTypeSize() const {
  unsigned Tag = getTag();
  if (Tag == dwarf::DW_TAG_member || Tag == dwarf::DW_TAG_typedef ||
      Tag == dwarf::DW_TAG_const_type || Tag == dwarf::DW_TAG_volatile_type ||
      Tag == dwarf::DW_TAG_restrict_type) {
    DIType BaseType = getTypeDerivedFrom();
    // If this type is not derived from any type then take conservative 
    // approach.
    if (BaseType.isNull())
      return getSizeInBits();
    if (BaseType.isDerivedType())
      return DIDerivedType(BaseType.getNode()).getOriginalTypeSize();
    else
      return BaseType.getSizeInBits();
  }
    
  return getSizeInBits();
}

/// describes - Return true if this subprogram provides debugging
/// information for the function F.
bool DISubprogram::describes(const Function *F) {
  assert(F && "Invalid function");
  StringRef Name = getLinkageName();
  if (Name.empty())
    Name = getName();
  if (F->getName() == Name)
    return true;
  return false;
}

StringRef DIScope::getFilename() const {
  if (isLexicalBlock()) 
    return DILexicalBlock(DbgNode).getFilename();
  if (isSubprogram())
    return DISubprogram(DbgNode).getFilename();
  if (isCompileUnit())
    return DICompileUnit(DbgNode).getFilename();
  if (isNameSpace())
    return DINameSpace(DbgNode).getFilename();
  assert(0 && "Invalid DIScope!");
  return StringRef();
}

StringRef DIScope::getDirectory() const {
  if (isLexicalBlock()) 
    return DILexicalBlock(DbgNode).getDirectory();
  if (isSubprogram())
    return DISubprogram(DbgNode).getDirectory();
  if (isCompileUnit())
    return DICompileUnit(DbgNode).getDirectory();
  if (isNameSpace())
    return DINameSpace(DbgNode).getDirectory();
  assert(0 && "Invalid DIScope!");
  return StringRef();
}

//===----------------------------------------------------------------------===//
// DIDescriptor: dump routines for all descriptors.
//===----------------------------------------------------------------------===//


/// dump - Print descriptor.
void DIDescriptor::dump() const {
  dbgs() << "[" << dwarf::TagString(getTag()) << "] ";
  dbgs().write_hex((intptr_t) &*DbgNode) << ']';
}

/// dump - Print compile unit.
void DICompileUnit::dump() const {
  if (getLanguage())
    dbgs() << " [" << dwarf::LanguageString(getLanguage()) << "] ";

  dbgs() << " [" << getDirectory() << "/" << getFilename() << " ]";
}

/// dump - Print type.
void DIType::dump() const {
  if (isNull()) return;

  StringRef Res = getName();
  if (!Res.empty())
    dbgs() << " [" << Res << "] ";

  unsigned Tag = getTag();
  dbgs() << " [" << dwarf::TagString(Tag) << "] ";

  // TODO : Print context
  getCompileUnit().dump();
  dbgs() << " ["
         << getLineNumber() << ", "
         << getSizeInBits() << ", "
         << getAlignInBits() << ", "
         << getOffsetInBits()
         << "] ";

  if (isPrivate())
    dbgs() << " [private] ";
  else if (isProtected())
    dbgs() << " [protected] ";

  if (isForwardDecl())
    dbgs() << " [fwd] ";

  if (isBasicType())
    DIBasicType(DbgNode).dump();
  else if (isDerivedType())
    DIDerivedType(DbgNode).dump();
  else if (isCompositeType())
    DICompositeType(DbgNode).dump();
  else {
    dbgs() << "Invalid DIType\n";
    return;
  }

  dbgs() << "\n";
}

/// dump - Print basic type.
void DIBasicType::dump() const {
  dbgs() << " [" << dwarf::AttributeEncodingString(getEncoding()) << "] ";
}

/// dump - Print derived type.
void DIDerivedType::dump() const {
  dbgs() << "\n\t Derived From: "; getTypeDerivedFrom().dump();
}

/// dump - Print composite type.
void DICompositeType::dump() const {
  DIArray A = getTypeArray();
  if (A.isNull())
    return;
  dbgs() << " [" << A.getNumElements() << " elements]";
}

/// dump - Print global.
void DIGlobal::dump() const {
  StringRef Res = getName();
  if (!Res.empty())
    dbgs() << " [" << Res << "] ";

  unsigned Tag = getTag();
  dbgs() << " [" << dwarf::TagString(Tag) << "] ";

  // TODO : Print context
  getCompileUnit().dump();
  dbgs() << " [" << getLineNumber() << "] ";

  if (isLocalToUnit())
    dbgs() << " [local] ";

  if (isDefinition())
    dbgs() << " [def] ";

  if (isGlobalVariable())
    DIGlobalVariable(DbgNode).dump();

  dbgs() << "\n";
}

/// dump - Print subprogram.
void DISubprogram::dump() const {
  StringRef Res = getName();
  if (!Res.empty())
    dbgs() << " [" << Res << "] ";

  unsigned Tag = getTag();
  dbgs() << " [" << dwarf::TagString(Tag) << "] ";

  // TODO : Print context
  getCompileUnit().dump();
  dbgs() << " [" << getLineNumber() << "] ";

  if (isLocalToUnit())
    dbgs() << " [local] ";

  if (isDefinition())
    dbgs() << " [def] ";

  dbgs() << "\n";
}

/// dump - Print global variable.
void DIGlobalVariable::dump() const {
  dbgs() << " [";
  getGlobal()->dump();
  dbgs() << "] ";
}

/// dump - Print variable.
void DIVariable::dump() const {
  StringRef Res = getName();
  if (!Res.empty())
    dbgs() << " [" << Res << "] ";

  getCompileUnit().dump();
  dbgs() << " [" << getLineNumber() << "] ";
  getType().dump();
  dbgs() << "\n";

  // FIXME: Dump complex addresses
}

//===----------------------------------------------------------------------===//
// DIFactory: Basic Helpers
//===----------------------------------------------------------------------===//

DIFactory::DIFactory(Module &m)
  : M(m), VMContext(M.getContext()), DeclareFn(0), ValueFn(0) {}

Constant *DIFactory::GetTagConstant(unsigned TAG) {
  assert((TAG & LLVMDebugVersionMask) == 0 &&
         "Tag too large for debug encoding!");
  return ConstantInt::get(Type::getInt32Ty(VMContext), TAG | LLVMDebugVersion);
}

//===----------------------------------------------------------------------===//
// DIFactory: Primary Constructors
//===----------------------------------------------------------------------===//

/// GetOrCreateArray - Create an descriptor for an array of descriptors.
/// This implicitly uniques the arrays created.
DIArray DIFactory::GetOrCreateArray(DIDescriptor *Tys, unsigned NumTys) {
  SmallVector<Value*, 16> Elts;

  if (NumTys == 0)
    Elts.push_back(llvm::Constant::getNullValue(Type::getInt32Ty(VMContext)));
  else
    for (unsigned i = 0; i != NumTys; ++i)
      Elts.push_back(Tys[i].getNode());

  return DIArray(MDNode::get(VMContext,Elts.data(), Elts.size()));
}

/// GetOrCreateSubrange - Create a descriptor for a value range.  This
/// implicitly uniques the values returned.
DISubrange DIFactory::GetOrCreateSubrange(int64_t Lo, int64_t Hi) {
  Value *Elts[] = {
    GetTagConstant(dwarf::DW_TAG_subrange_type),
    ConstantInt::get(Type::getInt64Ty(VMContext), Lo),
    ConstantInt::get(Type::getInt64Ty(VMContext), Hi)
  };

  return DISubrange(MDNode::get(VMContext, &Elts[0], 3));
}



/// CreateCompileUnit - Create a new descriptor for the specified compile
/// unit.  Note that this does not unique compile units within the module.
DICompileUnit DIFactory::CreateCompileUnit(unsigned LangID,
                                           StringRef Filename,
                                           StringRef Directory,
                                           StringRef Producer,
                                           bool isMain,
                                           bool isOptimized,
                                           StringRef Flags,
                                           unsigned RunTimeVer) {
  Value *Elts[] = {
    GetTagConstant(dwarf::DW_TAG_compile_unit),
    llvm::Constant::getNullValue(Type::getInt32Ty(VMContext)),
    ConstantInt::get(Type::getInt32Ty(VMContext), LangID),
    MDString::get(VMContext, Filename),
    MDString::get(VMContext, Directory),
    MDString::get(VMContext, Producer),
    ConstantInt::get(Type::getInt1Ty(VMContext), isMain),
    ConstantInt::get(Type::getInt1Ty(VMContext), isOptimized),
    MDString::get(VMContext, Flags),
    ConstantInt::get(Type::getInt32Ty(VMContext), RunTimeVer)
  };

  return DICompileUnit(MDNode::get(VMContext, &Elts[0], 10));
}

/// CreateEnumerator - Create a single enumerator value.
DIEnumerator DIFactory::CreateEnumerator(StringRef Name, uint64_t Val){
  Value *Elts[] = {
    GetTagConstant(dwarf::DW_TAG_enumerator),
    MDString::get(VMContext, Name),
    ConstantInt::get(Type::getInt64Ty(VMContext), Val)
  };
  return DIEnumerator(MDNode::get(VMContext, &Elts[0], 3));
}


/// CreateBasicType - Create a basic type like int, float, etc.
DIBasicType DIFactory::CreateBasicType(DIDescriptor Context,
                                       StringRef Name,
                                       DICompileUnit CompileUnit,
                                       unsigned LineNumber,
                                       uint64_t SizeInBits,
                                       uint64_t AlignInBits,
                                       uint64_t OffsetInBits, unsigned Flags,
                                       unsigned Encoding) {
  Value *Elts[] = {
    GetTagConstant(dwarf::DW_TAG_base_type),
    Context.getNode(),
    MDString::get(VMContext, Name),
    CompileUnit.getNode(),
    ConstantInt::get(Type::getInt32Ty(VMContext), LineNumber),
    ConstantInt::get(Type::getInt64Ty(VMContext), SizeInBits),
    ConstantInt::get(Type::getInt64Ty(VMContext), AlignInBits),
    ConstantInt::get(Type::getInt64Ty(VMContext), OffsetInBits),
    ConstantInt::get(Type::getInt32Ty(VMContext), Flags),
    ConstantInt::get(Type::getInt32Ty(VMContext), Encoding)
  };
  return DIBasicType(MDNode::get(VMContext, &Elts[0], 10));
}


/// CreateBasicType - Create a basic type like int, float, etc.
DIBasicType DIFactory::CreateBasicTypeEx(DIDescriptor Context,
                                         StringRef Name,
                                         DICompileUnit CompileUnit,
                                         unsigned LineNumber,
                                         Constant *SizeInBits,
                                         Constant *AlignInBits,
                                         Constant *OffsetInBits, unsigned Flags,
                                         unsigned Encoding) {
  Value *Elts[] = {
    GetTagConstant(dwarf::DW_TAG_base_type),
    Context.getNode(),
    MDString::get(VMContext, Name),
    CompileUnit.getNode(),
    ConstantInt::get(Type::getInt32Ty(VMContext), LineNumber),
    SizeInBits,
    AlignInBits,
    OffsetInBits,
    ConstantInt::get(Type::getInt32Ty(VMContext), Flags),
    ConstantInt::get(Type::getInt32Ty(VMContext), Encoding)
  };
  return DIBasicType(MDNode::get(VMContext, &Elts[0], 10));
}


/// CreateDerivedType - Create a derived type like const qualified type,
/// pointer, typedef, etc.
DIDerivedType DIFactory::CreateDerivedType(unsigned Tag,
                                           DIDescriptor Context,
                                           StringRef Name,
                                           DICompileUnit CompileUnit,
                                           unsigned LineNumber,
                                           uint64_t SizeInBits,
                                           uint64_t AlignInBits,
                                           uint64_t OffsetInBits,
                                           unsigned Flags,
                                           DIType DerivedFrom) {
  Value *Elts[] = {
    GetTagConstant(Tag),
    Context.getNode(),
    MDString::get(VMContext, Name),
    CompileUnit.getNode(),
    ConstantInt::get(Type::getInt32Ty(VMContext), LineNumber),
    ConstantInt::get(Type::getInt64Ty(VMContext), SizeInBits),
    ConstantInt::get(Type::getInt64Ty(VMContext), AlignInBits),
    ConstantInt::get(Type::getInt64Ty(VMContext), OffsetInBits),
    ConstantInt::get(Type::getInt32Ty(VMContext), Flags),
    DerivedFrom.getNode(),
  };
  return DIDerivedType(MDNode::get(VMContext, &Elts[0], 10));
}


/// CreateDerivedType - Create a derived type like const qualified type,
/// pointer, typedef, etc.
DIDerivedType DIFactory::CreateDerivedTypeEx(unsigned Tag,
                                             DIDescriptor Context,
                                             StringRef Name,
                                             DICompileUnit CompileUnit,
                                             unsigned LineNumber,
                                             Constant *SizeInBits,
                                             Constant *AlignInBits,
                                             Constant *OffsetInBits,
                                             unsigned Flags,
                                             DIType DerivedFrom) {
  Value *Elts[] = {
    GetTagConstant(Tag),
    Context.getNode(),
    MDString::get(VMContext, Name),
    CompileUnit.getNode(),
    ConstantInt::get(Type::getInt32Ty(VMContext), LineNumber),
    SizeInBits,
    AlignInBits,
    OffsetInBits,
    ConstantInt::get(Type::getInt32Ty(VMContext), Flags),
    DerivedFrom.getNode(),
  };
  return DIDerivedType(MDNode::get(VMContext, &Elts[0], 10));
}


/// CreateCompositeType - Create a composite type like array, struct, etc.
DICompositeType DIFactory::CreateCompositeType(unsigned Tag,
                                               DIDescriptor Context,
                                               StringRef Name,
                                               DICompileUnit CompileUnit,
                                               unsigned LineNumber,
                                               uint64_t SizeInBits,
                                               uint64_t AlignInBits,
                                               uint64_t OffsetInBits,
                                               unsigned Flags,
                                               DIType DerivedFrom,
                                               DIArray Elements,
                                               unsigned RuntimeLang) {

  Value *Elts[] = {
    GetTagConstant(Tag),
    Context.getNode(),
    MDString::get(VMContext, Name),
    CompileUnit.getNode(),
    ConstantInt::get(Type::getInt32Ty(VMContext), LineNumber),
    ConstantInt::get(Type::getInt64Ty(VMContext), SizeInBits),
    ConstantInt::get(Type::getInt64Ty(VMContext), AlignInBits),
    ConstantInt::get(Type::getInt64Ty(VMContext), OffsetInBits),
    ConstantInt::get(Type::getInt32Ty(VMContext), Flags),
    DerivedFrom.getNode(),
    Elements.getNode(),
    ConstantInt::get(Type::getInt32Ty(VMContext), RuntimeLang)
  };
  return DICompositeType(MDNode::get(VMContext, &Elts[0], 12));
}


/// CreateCompositeType - Create a composite type like array, struct, etc.
DICompositeType DIFactory::CreateCompositeTypeEx(unsigned Tag,
                                                 DIDescriptor Context,
                                                 StringRef Name,
                                                 DICompileUnit CompileUnit,
                                                 unsigned LineNumber,
                                                 Constant *SizeInBits,
                                                 Constant *AlignInBits,
                                                 Constant *OffsetInBits,
                                                 unsigned Flags,
                                                 DIType DerivedFrom,
                                                 DIArray Elements,
                                                 unsigned RuntimeLang) {

  Value *Elts[] = {
    GetTagConstant(Tag),
    Context.getNode(),
    MDString::get(VMContext, Name),
    CompileUnit.getNode(),
    ConstantInt::get(Type::getInt32Ty(VMContext), LineNumber),
    SizeInBits,
    AlignInBits,
    OffsetInBits,
    ConstantInt::get(Type::getInt32Ty(VMContext), Flags),
    DerivedFrom.getNode(),
    Elements.getNode(),
    ConstantInt::get(Type::getInt32Ty(VMContext), RuntimeLang)
  };
  return DICompositeType(MDNode::get(VMContext, &Elts[0], 12));
}


/// CreateSubprogram - Create a new descriptor for the specified subprogram.
/// See comments in DISubprogram for descriptions of these fields.  This
/// method does not unique the generated descriptors.
DISubprogram DIFactory::CreateSubprogram(DIDescriptor Context,
                                         StringRef Name,
                                         StringRef DisplayName,
                                         StringRef LinkageName,
                                         DICompileUnit CompileUnit,
                                         unsigned LineNo, DIType Type,
                                         bool isLocalToUnit,
                                         bool isDefinition,
                                         unsigned VK, unsigned VIndex,
                                         DIType ContainingType) {

  Value *Elts[] = {
    GetTagConstant(dwarf::DW_TAG_subprogram),
    llvm::Constant::getNullValue(Type::getInt32Ty(VMContext)),
    Context.getNode(),
    MDString::get(VMContext, Name),
    MDString::get(VMContext, DisplayName),
    MDString::get(VMContext, LinkageName),
    CompileUnit.getNode(),
    ConstantInt::get(Type::getInt32Ty(VMContext), LineNo),
    Type.getNode(),
    ConstantInt::get(Type::getInt1Ty(VMContext), isLocalToUnit),
    ConstantInt::get(Type::getInt1Ty(VMContext), isDefinition),
    ConstantInt::get(Type::getInt32Ty(VMContext), (unsigned)VK),
    ConstantInt::get(Type::getInt32Ty(VMContext), VIndex),
    ContainingType.getNode()
  };
  return DISubprogram(MDNode::get(VMContext, &Elts[0], 14));
}

/// CreateSubprogramDefinition - Create new subprogram descriptor for the
/// given declaration. 
DISubprogram DIFactory::CreateSubprogramDefinition(DISubprogram &SPDeclaration) {
  if (SPDeclaration.isDefinition())
    return DISubprogram(SPDeclaration.getNode());

  MDNode *DeclNode = SPDeclaration.getNode();
  Value *Elts[] = {
    GetTagConstant(dwarf::DW_TAG_subprogram),
    llvm::Constant::getNullValue(Type::getInt32Ty(VMContext)),
    DeclNode->getOperand(2), // Context
    DeclNode->getOperand(3), // Name
    DeclNode->getOperand(4), // DisplayName
    DeclNode->getOperand(5), // LinkageName
    DeclNode->getOperand(6), // CompileUnit
    DeclNode->getOperand(7), // LineNo
    DeclNode->getOperand(8), // Type
    DeclNode->getOperand(9), // isLocalToUnit
    ConstantInt::get(Type::getInt1Ty(VMContext), true),
    DeclNode->getOperand(11), // Virtuality
    DeclNode->getOperand(12), // VIndex
    DeclNode->getOperand(13)  // Containting Type
  };
  return DISubprogram(MDNode::get(VMContext, &Elts[0], 14));
}

/// CreateGlobalVariable - Create a new descriptor for the specified global.
DIGlobalVariable
DIFactory::CreateGlobalVariable(DIDescriptor Context, StringRef Name,
                                StringRef DisplayName,
                                StringRef LinkageName,
                                DICompileUnit CompileUnit,
                                unsigned LineNo, DIType Type,bool isLocalToUnit,
                                bool isDefinition, llvm::GlobalVariable *Val) {
  Value *Elts[] = {
    GetTagConstant(dwarf::DW_TAG_variable),
    llvm::Constant::getNullValue(Type::getInt32Ty(VMContext)),
    Context.getNode(),
    MDString::get(VMContext, Name),
    MDString::get(VMContext, DisplayName),
    MDString::get(VMContext, LinkageName),
    CompileUnit.getNode(),
    ConstantInt::get(Type::getInt32Ty(VMContext), LineNo),
    Type.getNode(),
    ConstantInt::get(Type::getInt1Ty(VMContext), isLocalToUnit),
    ConstantInt::get(Type::getInt1Ty(VMContext), isDefinition),
    Val
  };

  Value *const *Vs = &Elts[0];
  MDNode *Node = MDNode::get(VMContext,Vs, 12);

  // Create a named metadata so that we do not lose this mdnode.
  NamedMDNode *NMD = M.getOrInsertNamedMetadata("llvm.dbg.gv");
  NMD->addOperand(Node);

  return DIGlobalVariable(Node);
}


/// CreateVariable - Create a new descriptor for the specified variable.
DIVariable DIFactory::CreateVariable(unsigned Tag, DIDescriptor Context,
                                     StringRef Name,
                                     DICompileUnit CompileUnit, unsigned LineNo,
                                     DIType Type) {
  Value *Elts[] = {
    GetTagConstant(Tag),
    Context.getNode(),
    MDString::get(VMContext, Name),
    CompileUnit.getNode(),
    ConstantInt::get(Type::getInt32Ty(VMContext), LineNo),
    Type.getNode(),
  };
  return DIVariable(MDNode::get(VMContext, &Elts[0], 6));
}


/// CreateComplexVariable - Create a new descriptor for the specified variable
/// which has a complex address expression for its address.
DIVariable DIFactory::CreateComplexVariable(unsigned Tag, DIDescriptor Context,
                                            const std::string &Name,
                                            DICompileUnit CompileUnit,
                                            unsigned LineNo,
                                   DIType Type, SmallVector<Value *, 9> &addr) {
  SmallVector<Value *, 9> Elts;
  Elts.push_back(GetTagConstant(Tag));
  Elts.push_back(Context.getNode());
  Elts.push_back(MDString::get(VMContext, Name));
  Elts.push_back(CompileUnit.getNode());
  Elts.push_back(ConstantInt::get(Type::getInt32Ty(VMContext), LineNo));
  Elts.push_back(Type.getNode());
  Elts.insert(Elts.end(), addr.begin(), addr.end());

  return DIVariable(MDNode::get(VMContext, &Elts[0], 6+addr.size()));
}


/// CreateBlock - This creates a descriptor for a lexical block with the
/// specified parent VMContext.
DILexicalBlock DIFactory::CreateLexicalBlock(DIDescriptor Context) {
  Value *Elts[] = {
    GetTagConstant(dwarf::DW_TAG_lexical_block),
    Context.getNode()
  };
  return DILexicalBlock(MDNode::get(VMContext, &Elts[0], 2));
}

/// CreateNameSpace - This creates new descriptor for a namespace
/// with the specified parent context.
DINameSpace DIFactory::CreateNameSpace(DIDescriptor Context, StringRef Name,
                                       DICompileUnit CompileUnit, 
                                       unsigned LineNo) {
  Value *Elts[] = {
    GetTagConstant(dwarf::DW_TAG_namespace),
    Context.getNode(),
    MDString::get(VMContext, Name),
    CompileUnit.getNode(),
    ConstantInt::get(Type::getInt32Ty(VMContext), LineNo)
  };
  return DINameSpace(MDNode::get(VMContext, &Elts[0], 5));
}

/// CreateLocation - Creates a debug info location.
DILocation DIFactory::CreateLocation(unsigned LineNo, unsigned ColumnNo,
                                     DIScope S, DILocation OrigLoc) {
  Value *Elts[] = {
    ConstantInt::get(Type::getInt32Ty(VMContext), LineNo),
    ConstantInt::get(Type::getInt32Ty(VMContext), ColumnNo),
    S.getNode(),
    OrigLoc.getNode(),
  };
  return DILocation(MDNode::get(VMContext, &Elts[0], 4));
}

/// CreateLocation - Creates a debug info location.
DILocation DIFactory::CreateLocation(unsigned LineNo, unsigned ColumnNo,
                                     DIScope S, MDNode *OrigLoc) {
 Value *Elts[] = {
    ConstantInt::get(Type::getInt32Ty(VMContext), LineNo),
    ConstantInt::get(Type::getInt32Ty(VMContext), ColumnNo),
    S.getNode(),
    OrigLoc
  };
  return DILocation(MDNode::get(VMContext, &Elts[0], 4));
}

//===----------------------------------------------------------------------===//
// DIFactory: Routines for inserting code into a function
//===----------------------------------------------------------------------===//

/// InsertDeclare - Insert a new llvm.dbg.declare intrinsic call.
Instruction *DIFactory::InsertDeclare(Value *Storage, DIVariable D,
                                      Instruction *InsertBefore) {
  if (!DeclareFn)
    DeclareFn = Intrinsic::getDeclaration(&M, Intrinsic::dbg_declare);

  Value *Args[] = { MDNode::get(Storage->getContext(), &Storage, 1),
                    D.getNode() };
  return CallInst::Create(DeclareFn, Args, Args+2, "", InsertBefore);
}

/// InsertDeclare - Insert a new llvm.dbg.declare intrinsic call.
Instruction *DIFactory::InsertDeclare(Value *Storage, DIVariable D,
                                      BasicBlock *InsertAtEnd) {
  if (!DeclareFn)
    DeclareFn = Intrinsic::getDeclaration(&M, Intrinsic::dbg_declare);

  Value *Args[] = { MDNode::get(Storage->getContext(), &Storage, 1),
                    D.getNode() };
  return CallInst::Create(DeclareFn, Args, Args+2, "", InsertAtEnd);
}

/// InsertDbgValueIntrinsic - Insert a new llvm.dbg.value intrinsic call.
Instruction *DIFactory::InsertDbgValueIntrinsic(Value *V, uint64_t Offset,
                                                DIVariable D,
                                                Instruction *InsertBefore) {
  assert(V && "no value passed to dbg.value");
  if (!ValueFn)
    ValueFn = Intrinsic::getDeclaration(&M, Intrinsic::dbg_value);

  Value *Args[] = { MDNode::get(V->getContext(), &V, 1),
                    ConstantInt::get(Type::getInt64Ty(V->getContext()), Offset),
                    D.getNode() };
  return CallInst::Create(ValueFn, Args, Args+3, "", InsertBefore);
}

/// InsertDbgValueIntrinsic - Insert a new llvm.dbg.value intrinsic call.
Instruction *DIFactory::InsertDbgValueIntrinsic(Value *V, uint64_t Offset,
                                                DIVariable D,
                                                BasicBlock *InsertAtEnd) {
  assert(V && "no value passed to dbg.value");
  if (!ValueFn)
    ValueFn = Intrinsic::getDeclaration(&M, Intrinsic::dbg_value);

  Value *Args[] = { MDNode::get(V->getContext(), &V, 1), 
                    ConstantInt::get(Type::getInt64Ty(V->getContext()), Offset),
                    D.getNode() };
  return CallInst::Create(ValueFn, Args, Args+3, "", InsertAtEnd);
}

//===----------------------------------------------------------------------===//
// DebugInfoFinder implementations.
//===----------------------------------------------------------------------===//

/// processModule - Process entire module and collect debug info.
void DebugInfoFinder::processModule(Module &M) {
  unsigned MDDbgKind = M.getMDKindID("dbg");

  for (Module::iterator I = M.begin(), E = M.end(); I != E; ++I)
    for (Function::iterator FI = (*I).begin(), FE = (*I).end(); FI != FE; ++FI)
      for (BasicBlock::iterator BI = (*FI).begin(), BE = (*FI).end(); BI != BE;
           ++BI) {
        if (DbgDeclareInst *DDI = dyn_cast<DbgDeclareInst>(BI))
          processDeclare(DDI);
        else if (MDNode *L = BI->getMetadata(MDDbgKind)) 
          processLocation(DILocation(L));
      }

  NamedMDNode *NMD = M.getNamedMetadata("llvm.dbg.gv");
  if (!NMD)
    return;

  for (unsigned i = 0, e = NMD->getNumOperands(); i != e; ++i) {
    DIGlobalVariable DIG(cast<MDNode>(NMD->getOperand(i)));
    if (addGlobalVariable(DIG)) {
      addCompileUnit(DIG.getCompileUnit());
      processType(DIG.getType());
    }
  }
}

/// processLocation - Process DILocation.
void DebugInfoFinder::processLocation(DILocation Loc) {
  if (Loc.isNull()) return;
  DIScope S(Loc.getScope().getNode());
  if (S.isNull()) return;
  if (S.isCompileUnit())
    addCompileUnit(DICompileUnit(S.getNode()));
  else if (S.isSubprogram())
    processSubprogram(DISubprogram(S.getNode()));
  else if (S.isLexicalBlock())
    processLexicalBlock(DILexicalBlock(S.getNode()));
  processLocation(Loc.getOrigLocation());
}

/// processType - Process DIType.
void DebugInfoFinder::processType(DIType DT) {
  if (!addType(DT))
    return;

  addCompileUnit(DT.getCompileUnit());
  if (DT.isCompositeType()) {
    DICompositeType DCT(DT.getNode());
    processType(DCT.getTypeDerivedFrom());
    DIArray DA = DCT.getTypeArray();
    if (!DA.isNull())
      for (unsigned i = 0, e = DA.getNumElements(); i != e; ++i) {
        DIDescriptor D = DA.getElement(i);
        DIType TypeE = DIType(D.getNode());
        if (!TypeE.isNull())
          processType(TypeE);
        else
          processSubprogram(DISubprogram(D.getNode()));
      }
  } else if (DT.isDerivedType()) {
    DIDerivedType DDT(DT.getNode());
    if (!DDT.isNull())
      processType(DDT.getTypeDerivedFrom());
  }
}

/// processLexicalBlock
void DebugInfoFinder::processLexicalBlock(DILexicalBlock LB) {
  if (LB.isNull())
    return;
  DIScope Context = LB.getContext();
  if (Context.isLexicalBlock())
    return processLexicalBlock(DILexicalBlock(Context.getNode()));
  else
    return processSubprogram(DISubprogram(Context.getNode()));
}

/// processSubprogram - Process DISubprogram.
void DebugInfoFinder::processSubprogram(DISubprogram SP) {
  if (SP.isNull())
    return;
  if (!addSubprogram(SP))
    return;
  addCompileUnit(SP.getCompileUnit());
  processType(SP.getType());
}

/// processDeclare - Process DbgDeclareInst.
void DebugInfoFinder::processDeclare(DbgDeclareInst *DDI) {
  DIVariable DV(cast<MDNode>(DDI->getVariable()));
  if (DV.isNull())
    return;

  if (!NodesSeen.insert(DV.getNode()))
    return;

  addCompileUnit(DV.getCompileUnit());
  processType(DV.getType());
}

/// addType - Add type into Tys.
bool DebugInfoFinder::addType(DIType DT) {
  if (DT.isNull())
    return false;

  if (!NodesSeen.insert(DT.getNode()))
    return false;

  TYs.push_back(DT.getNode());
  return true;
}

/// addCompileUnit - Add compile unit into CUs.
bool DebugInfoFinder::addCompileUnit(DICompileUnit CU) {
  if (CU.isNull())
    return false;

  if (!NodesSeen.insert(CU.getNode()))
    return false;

  CUs.push_back(CU.getNode());
  return true;
}

/// addGlobalVariable - Add global variable into GVs.
bool DebugInfoFinder::addGlobalVariable(DIGlobalVariable DIG) {
  if (DIG.isNull())
    return false;

  if (!NodesSeen.insert(DIG.getNode()))
    return false;

  GVs.push_back(DIG.getNode());
  return true;
}

// addSubprogram - Add subprgoram into SPs.
bool DebugInfoFinder::addSubprogram(DISubprogram SP) {
  if (SP.isNull())
    return false;

  if (!NodesSeen.insert(SP.getNode()))
    return false;

  SPs.push_back(SP.getNode());
  return true;
}

/// Find the debug info descriptor corresponding to this global variable.
static Value *findDbgGlobalDeclare(GlobalVariable *V) {
  const Module *M = V->getParent();
  NamedMDNode *NMD = M->getNamedMetadata("llvm.dbg.gv");
  if (!NMD)
    return 0;

  for (unsigned i = 0, e = NMD->getNumOperands(); i != e; ++i) {
    DIGlobalVariable DIG(cast_or_null<MDNode>(NMD->getOperand(i)));
    if (DIG.isNull())
      continue;
    if (DIG.getGlobal() == V)
      return DIG.getNode();
  }
  return 0;
}

/// Finds the llvm.dbg.declare intrinsic corresponding to this value if any.
/// It looks through pointer casts too.
static const DbgDeclareInst *findDbgDeclare(const Value *V) {
  V = V->stripPointerCasts();
  
  if (!isa<Instruction>(V) && !isa<Argument>(V))
    return 0;
    
  const Function *F = NULL;
  if (const Instruction *I = dyn_cast<Instruction>(V))
    F = I->getParent()->getParent();
  else if (const Argument *A = dyn_cast<Argument>(V))
    F = A->getParent();
  
  for (Function::const_iterator FI = F->begin(), FE = F->end(); FI != FE; ++FI)
    for (BasicBlock::const_iterator BI = (*FI).begin(), BE = (*FI).end();
         BI != BE; ++BI)
      if (const DbgDeclareInst *DDI = dyn_cast<DbgDeclareInst>(BI))
        if (DDI->getAddress() == V)
          return DDI;

  return 0;
}

bool llvm::getLocationInfo(const Value *V, std::string &DisplayName,
                           std::string &Type, unsigned &LineNo,
                           std::string &File, std::string &Dir) {
  DICompileUnit Unit;
  DIType TypeD;

  if (GlobalVariable *GV = dyn_cast<GlobalVariable>(const_cast<Value*>(V))) {
    Value *DIGV = findDbgGlobalDeclare(GV);
    if (!DIGV) return false;
    DIGlobalVariable Var(cast<MDNode>(DIGV));

    StringRef D = Var.getDisplayName();
    if (!D.empty())
      DisplayName = D;
    LineNo = Var.getLineNumber();
    Unit = Var.getCompileUnit();
    TypeD = Var.getType();
  } else {
    const DbgDeclareInst *DDI = findDbgDeclare(V);
    if (!DDI) return false;
    DIVariable Var(cast<MDNode>(DDI->getVariable()));

    StringRef D = Var.getName();
    if (!D.empty())
      DisplayName = D;
    LineNo = Var.getLineNumber();
    Unit = Var.getCompileUnit();
    TypeD = Var.getType();
  }

  StringRef T = TypeD.getName();
  if (!T.empty())
    Type = T;
  StringRef F = Unit.getFilename();
  if (!F.empty())
    File = F;
  StringRef D = Unit.getDirectory();
  if (!D.empty())
    Dir = D;
  return true;
}

/// ExtractDebugLocation - Extract debug location information
/// from DILocation.
DebugLoc llvm::ExtractDebugLocation(DILocation &Loc,
                                    DebugLocTracker &DebugLocInfo) {
  DenseMap<MDNode *, unsigned>::iterator II
    = DebugLocInfo.DebugIdMap.find(Loc.getNode());
  if (II != DebugLocInfo.DebugIdMap.end())
    return DebugLoc::get(II->second);

  // Add a new location entry.
  unsigned Id = DebugLocInfo.DebugLocations.size();
  DebugLocInfo.DebugLocations.push_back(Loc.getNode());
  DebugLocInfo.DebugIdMap[Loc.getNode()] = Id;

  return DebugLoc::get(Id);
}

/// getDISubprogram - Find subprogram that is enclosing this scope.
DISubprogram llvm::getDISubprogram(MDNode *Scope) {
  DIDescriptor D(Scope);
  if (D.isNull())
    return DISubprogram();
  
  if (D.isCompileUnit())
    return DISubprogram();
  
  if (D.isSubprogram())
    return DISubprogram(Scope);
  
  if (D.isLexicalBlock())
    return getDISubprogram(DILexicalBlock(Scope).getContext().getNode());
  
  return DISubprogram();
}

/// getDICompositeType - Find underlying composite type.
DICompositeType llvm::getDICompositeType(DIType T) {
  if (T.isNull())
    return DICompositeType();
  
  if (T.isCompositeType())
    return DICompositeType(T.getNode());
  
  if (T.isDerivedType())
    return getDICompositeType(DIDerivedType(T.getNode()).getTypeDerivedFrom());
  
  return DICompositeType();
}
