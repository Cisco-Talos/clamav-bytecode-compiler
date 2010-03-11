//===--- CGVtable.h - Emit LLVM Code for C++ vtables ----------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This contains code dealing with C++ code generation of virtual tables.
//
//===----------------------------------------------------------------------===//

#ifndef CLANG_CODEGEN_CGVTABLE_H
#define CLANG_CODEGEN_CGVTABLE_H

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/GlobalVariable.h"
#include "GlobalDecl.h"

namespace clang {
  class CXXRecordDecl;

namespace CodeGen {
  class CodeGenModule;

/// ThunkAdjustment - Virtual and non-virtual adjustment for thunks.
class ThunkAdjustment {
public:
  ThunkAdjustment(int64_t NonVirtual, int64_t Virtual)
  : NonVirtual(NonVirtual),
    Virtual(Virtual) { }

  ThunkAdjustment()
    : NonVirtual(0), Virtual(0) { }

  // isEmpty - Return whether this thunk adjustment is empty.
  bool isEmpty() const {
    return NonVirtual == 0 && Virtual == 0;
  }

  /// NonVirtual - The non-virtual adjustment.
  int64_t NonVirtual;

  /// Virtual - The virtual adjustment.
  int64_t Virtual;
};

/// CovariantThunkAdjustment - Adjustment of the 'this' pointer and the
/// return pointer for covariant thunks.
class CovariantThunkAdjustment {
public:
  CovariantThunkAdjustment(const ThunkAdjustment &ThisAdjustment,
                           const ThunkAdjustment &ReturnAdjustment)
  : ThisAdjustment(ThisAdjustment), ReturnAdjustment(ReturnAdjustment) { }

  CovariantThunkAdjustment() { }

  ThunkAdjustment ThisAdjustment;
  ThunkAdjustment ReturnAdjustment;
};

// BaseSubobject - Uniquely identifies a direct or indirect base class. 
// Stores both the base class decl and the offset from the most derived class to
// the base class.
class BaseSubobject {
  /// Base - The base class declaration.
  const CXXRecordDecl *Base;
  
  /// BaseOffset - The offset from the most derived class to the base class.
  uint64_t BaseOffset;
  
public:
  BaseSubobject(const CXXRecordDecl *Base, uint64_t BaseOffset)
    : Base(Base), BaseOffset(BaseOffset) { }
  
  /// getBase - Returns the base class declaration.
  const CXXRecordDecl *getBase() const { return Base; }

  /// getBaseOffset - Returns the base class offset.
  uint64_t getBaseOffset() const { return BaseOffset; }

  friend bool operator==(const BaseSubobject &LHS, const BaseSubobject &RHS) {
    return LHS.Base == RHS.Base && LHS.BaseOffset == RHS.BaseOffset;
 }
};

} // end namespace CodeGen
} // end namespace clang

namespace llvm {

template<> struct DenseMapInfo<clang::CodeGen::BaseSubobject> {
  static clang::CodeGen::BaseSubobject getEmptyKey() {
    return clang::CodeGen::BaseSubobject(
      DenseMapInfo<const clang::CXXRecordDecl *>::getEmptyKey(),
      DenseMapInfo<uint64_t>::getEmptyKey());
  }

  static clang::CodeGen::BaseSubobject getTombstoneKey() {
    return clang::CodeGen::BaseSubobject(
      DenseMapInfo<const clang::CXXRecordDecl *>::getTombstoneKey(),
      DenseMapInfo<uint64_t>::getTombstoneKey());
  }

  static unsigned getHashValue(const clang::CodeGen::BaseSubobject &Base) {
    return 
      DenseMapInfo<const clang::CXXRecordDecl *>::getHashValue(Base.getBase()) ^
      DenseMapInfo<uint64_t>::getHashValue(Base.getBaseOffset());
  }

  static bool isEqual(const clang::CodeGen::BaseSubobject &LHS, 
                      const clang::CodeGen::BaseSubobject &RHS) {
    return LHS == RHS;
  }
};

// It's OK to treat BaseSubobject as a POD type.
template <> struct isPodLike<clang::CodeGen::BaseSubobject> {
  static const bool value = true;
};

}

namespace clang {
namespace CodeGen {

class CGVtableInfo {
public:
  typedef std::vector<std::pair<GlobalDecl, ThunkAdjustment> >
      AdjustmentVectorTy;

  typedef std::pair<const CXXRecordDecl *, uint64_t> CtorVtable_t;
  typedef llvm::DenseMap<CtorVtable_t, int64_t> AddrSubMap_t;
  typedef llvm::DenseMap<const CXXRecordDecl *, AddrSubMap_t *> AddrMap_t;
  llvm::DenseMap<const CXXRecordDecl *, AddrMap_t*> AddressPoints;

  typedef llvm::DenseMap<BaseSubobject, uint64_t> AddressPointsMapTy;

private:
  CodeGenModule &CGM;

  /// MethodVtableIndices - Contains the index (relative to the vtable address
  /// point) where the function pointer for a virtual function is stored.
  typedef llvm::DenseMap<GlobalDecl, int64_t> MethodVtableIndicesTy;
  MethodVtableIndicesTy MethodVtableIndices;

  typedef std::pair<const CXXRecordDecl *,
                    const CXXRecordDecl *> ClassPairTy;

  /// VirtualBaseClassOffsetOffsets - Contains the vtable offset (relative to 
  /// the address point) in bytes where the offsets for virtual bases of a class
  /// are stored.
  typedef llvm::DenseMap<ClassPairTy, int64_t> 
    VirtualBaseClassOffsetOffsetsMapTy;
  VirtualBaseClassOffsetOffsetsMapTy VirtualBaseClassOffsetOffsets;

  /// Vtables - All the vtables which have been defined.
  llvm::DenseMap<const CXXRecordDecl *, llvm::GlobalVariable *> Vtables;
  
  /// NumVirtualFunctionPointers - Contains the number of virtual function 
  /// pointers in the vtable for a given record decl.
  llvm::DenseMap<const CXXRecordDecl *, uint64_t> NumVirtualFunctionPointers;

  typedef llvm::DenseMap<GlobalDecl, AdjustmentVectorTy> SavedAdjustmentsTy;
  SavedAdjustmentsTy SavedAdjustments;
  llvm::DenseSet<const CXXRecordDecl*> SavedAdjustmentRecords;

  typedef llvm::DenseMap<ClassPairTy, uint64_t> SubVTTIndiciesTy;
  SubVTTIndiciesTy SubVTTIndicies;

  /// getNumVirtualFunctionPointers - Return the number of virtual function
  /// pointers in the vtable for a given record decl.
  uint64_t getNumVirtualFunctionPointers(const CXXRecordDecl *RD);
  
  void ComputeMethodVtableIndices(const CXXRecordDecl *RD);
   
  llvm::GlobalVariable *
  GenerateVtable(llvm::GlobalVariable::LinkageTypes Linkage,
                 bool GenerateDefinition, const CXXRecordDecl *LayoutClass, 
                 const CXXRecordDecl *RD, uint64_t Offset, bool IsVirtual,
                 AddressPointsMapTy& AddressPoints);

  llvm::GlobalVariable *GenerateVTT(llvm::GlobalVariable::LinkageTypes Linkage,
                                    bool GenerateDefinition,
                                    const CXXRecordDecl *RD);

public:
  CGVtableInfo(CodeGenModule &CGM)
    : CGM(CGM) { }

  /// needsVTTParameter - Return whether the given global decl needs a VTT
  /// parameter, which it does if it's a base constructor or destructor with
  /// virtual bases.
  static bool needsVTTParameter(GlobalDecl GD);

  /// getSubVTTIndex - Return the index of the sub-VTT for the base class of the
  /// given record decl.
  uint64_t getSubVTTIndex(const CXXRecordDecl *RD, const CXXRecordDecl *Base);
  
  /// getMethodVtableIndex - Return the index (relative to the vtable address
  /// point) where the function pointer for the given virtual function is
  /// stored.
  uint64_t getMethodVtableIndex(GlobalDecl GD);

  /// getVirtualBaseOffsetOffset - Return the offset in bytes (relative to the
  /// vtable address point) where the offset of the virtual base that contains 
  /// the given base is stored, otherwise, if no virtual base contains the given
  /// class, return 0.  Base must be a virtual base class or an unambigious
  /// base.
  int64_t getVirtualBaseOffsetOffset(const CXXRecordDecl *RD,
                                     const CXXRecordDecl *VBase);

  AdjustmentVectorTy *getAdjustments(GlobalDecl GD);

  /// getVtableAddressPoint - returns the address point of the vtable for the
  /// given record decl.
  /// FIXME: This should return a list of address points.
  uint64_t getVtableAddressPoint(const CXXRecordDecl *RD);
  
  llvm::GlobalVariable *getVtable(const CXXRecordDecl *RD);
  
  /// CtorVtableInfo - Information about a constructor vtable.
  struct CtorVtableInfo {
    /// Vtable - The vtable itself.
    llvm::GlobalVariable *Vtable;
  
    /// AddressPoints - The address points in this constructor vtable.
    AddressPointsMapTy AddressPoints;
    
    CtorVtableInfo() : Vtable(0) { }
  };
  
  CtorVtableInfo getCtorVtable(const CXXRecordDecl *RD, 
                               const BaseSubobject &Base,
                               bool BaseIsVirtual);
  
  llvm::GlobalVariable *getVTT(const CXXRecordDecl *RD);
  
  void MaybeEmitVtable(GlobalDecl GD);

  /// GenerateClassData - Generate all the class data requires to be generated
  /// upon definition of a KeyFunction.  This includes the vtable, the
  /// rtti data structure and the VTT.
  ///
  /// \param Linkage - The desired linkage of the vtable, the RTTI and the VTT.
  void GenerateClassData(llvm::GlobalVariable::LinkageTypes Linkage,
                         const CXXRecordDecl *RD);
};

} // end namespace CodeGen
} // end namespace clang
#endif
