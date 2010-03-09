//===--- CGDebugInfo.h - DebugInfo for LLVM CodeGen -------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This is the source level debug info generator for llvm translation.
//
//===----------------------------------------------------------------------===//

#ifndef CLANG_CODEGEN_CGDEBUGINFO_H
#define CLANG_CODEGEN_CGDEBUGINFO_H

#include "clang/AST/Type.h"
#include "clang/AST/Expr.h"
#include "clang/Basic/SourceLocation.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/Analysis/DebugInfo.h"
#include "llvm/Support/ValueHandle.h"
#include "llvm/Support/Allocator.h"
#include <map>

#include "CGBuilder.h"

namespace llvm {
  class MDNode;
}

namespace clang {
  class VarDecl;
  class ObjCInterfaceDecl;

namespace CodeGen {
  class CodeGenModule;
  class CodeGenFunction;
  class GlobalDecl;

/// CGDebugInfo - This class gathers all debug information during compilation
/// and is responsible for emitting to llvm globals or pass directly to
/// the backend.
class CGDebugInfo {
  CodeGenModule &CGM;
  llvm::DIFactory DebugFactory;
  llvm::DICompileUnit TheCU;
  SourceLocation CurLoc, PrevLoc;
  llvm::DIType VTablePtrType;
  /// FwdDeclCount - This counter is used to ensure unique names for forward
  /// record decls.
  unsigned FwdDeclCount;
  
  /// TypeCache - Cache of previously constructed Types.
  // FIXME: Eliminate this map.  Be careful of iterator invalidation.
  std::map<void *, llvm::WeakVH> TypeCache;

  bool BlockLiteralGenericSet;
  llvm::DIType BlockLiteralGeneric;

  std::vector<llvm::TrackingVH<llvm::MDNode> > RegionStack;
  llvm::DenseMap<const Decl *, llvm::WeakVH> RegionMap;

  /// DebugInfoNames - This is a storage for names that are
  /// constructed on demand. For example, C++ destructors, C++ operators etc..
  llvm::BumpPtrAllocator DebugInfoNames;

  llvm::DenseMap<const FunctionDecl *, llvm::WeakVH> SPCache;
  llvm::DenseMap<const NamespaceDecl *, llvm::WeakVH> NameSpaceCache;

  /// Helper functions for getOrCreateType.
  llvm::DIType CreateType(const BuiltinType *Ty, llvm::DIFile F);
  llvm::DIType CreateType(const ComplexType *Ty, llvm::DIFile F);
  llvm::DIType CreateQualifiedType(QualType Ty, llvm::DIFile F);
  llvm::DIType CreateType(const TypedefType *Ty, llvm::DIFile F);
  llvm::DIType CreateType(const ObjCObjectPointerType *Ty,
                          llvm::DIFile F);
  llvm::DIType CreateType(const PointerType *Ty, llvm::DIFile F);
  llvm::DIType CreateType(const BlockPointerType *Ty, llvm::DIFile F);
  llvm::DIType CreateType(const FunctionType *Ty, llvm::DIFile F);
  llvm::DIType CreateType(const TagType *Ty, llvm::DIFile F);
  llvm::DIType CreateType(const RecordType *Ty, llvm::DIFile F);
  llvm::DIType CreateType(const ObjCInterfaceType *Ty, llvm::DIFile F);
  llvm::DIType CreateType(const EnumType *Ty, llvm::DIFile F);
  llvm::DIType CreateType(const VectorType *Ty, llvm::DIFile F);
  llvm::DIType CreateType(const ArrayType *Ty, llvm::DIFile F);
  llvm::DIType CreateType(const LValueReferenceType *Ty, llvm::DIFile F);
  llvm::DIType CreateType(const MemberPointerType *Ty, llvm::DIFile F);
  llvm::DIType getOrCreateMethodType(const CXXMethodDecl *Method,
                                     llvm::DIFile F);
  llvm::DIType getOrCreateVTablePtrType(llvm::DIFile F);
  llvm::DINameSpace getOrCreateNameSpace(const NamespaceDecl *N, 
                                         llvm::DIDescriptor Unit);

  llvm::DIType CreatePointerLikeType(unsigned Tag,
                                     const Type *Ty, QualType PointeeTy,
                                     llvm::DIFile F);
  
  llvm::DISubprogram CreateCXXMemberFunction(const CXXMethodDecl *Method,
                                             llvm::DIFile F,
                                             llvm::DICompositeType &RecordTy);
  
  void CollectCXXMemberFunctions(const CXXRecordDecl *Decl,
                                 llvm::DIFile F,
                                 llvm::SmallVectorImpl<llvm::DIDescriptor> &E,
                                 llvm::DICompositeType &T);
  void CollectCXXBases(const CXXRecordDecl *Decl,
                       llvm::DIFile F,
                       llvm::SmallVectorImpl<llvm::DIDescriptor> &EltTys,
                       llvm::DICompositeType &RecordTy);


  void CollectRecordFields(const RecordDecl *Decl, llvm::DIFile F,
                           llvm::SmallVectorImpl<llvm::DIDescriptor> &E);

  void CollectVtableInfo(const CXXRecordDecl *Decl,
                         llvm::DIFile F,
                         llvm::SmallVectorImpl<llvm::DIDescriptor> &EltTys);

public:
  CGDebugInfo(CodeGenModule &CGM);
  ~CGDebugInfo();

  /// setLocation - Update the current source location. If \arg loc is
  /// invalid it is ignored.
  void setLocation(SourceLocation Loc);

  /// EmitStopPoint - Emit a call to llvm.dbg.stoppoint to indicate a change of
  /// source line.
  void EmitStopPoint(llvm::Function *Fn, CGBuilderTy &Builder);

  /// EmitFunctionStart - Emit a call to llvm.dbg.function.start to indicate
  /// start of a new function.
  void EmitFunctionStart(GlobalDecl GD, QualType FnType,
                         llvm::Function *Fn, CGBuilderTy &Builder);

  /// EmitRegionStart - Emit a call to llvm.dbg.region.start to indicate start
  /// of a new block.
  void EmitRegionStart(llvm::Function *Fn, CGBuilderTy &Builder);

  /// EmitRegionEnd - Emit call to llvm.dbg.region.end to indicate end of a
  /// block.
  void EmitRegionEnd(llvm::Function *Fn, CGBuilderTy &Builder);

  /// EmitDeclareOfAutoVariable - Emit call to llvm.dbg.declare for an automatic
  /// variable declaration.
  void EmitDeclareOfAutoVariable(const VarDecl *Decl, llvm::Value *AI,
                                 CGBuilderTy &Builder);

  /// EmitDeclareOfBlockDeclRefVariable - Emit call to llvm.dbg.declare for an
  /// imported variable declaration in a block.
  void EmitDeclareOfBlockDeclRefVariable(const BlockDeclRefExpr *BDRE,
                                         llvm::Value *AI,
                                         CGBuilderTy &Builder,
                                         CodeGenFunction *CGF);

  /// EmitDeclareOfArgVariable - Emit call to llvm.dbg.declare for an argument
  /// variable declaration.
  void EmitDeclareOfArgVariable(const VarDecl *Decl, llvm::Value *AI,
                                CGBuilderTy &Builder);

  /// EmitGlobalVariable - Emit information about a global variable.
  void EmitGlobalVariable(llvm::GlobalVariable *GV, const VarDecl *Decl);

  /// EmitGlobalVariable - Emit information about an objective-c interface.
  void EmitGlobalVariable(llvm::GlobalVariable *GV, ObjCInterfaceDecl *Decl);

private:
  /// EmitDeclare - Emit call to llvm.dbg.declare for a variable declaration.
  void EmitDeclare(const VarDecl *decl, unsigned Tag, llvm::Value *AI,
                   CGBuilderTy &Builder);

  /// EmitDeclare - Emit call to llvm.dbg.declare for a variable declaration.
  void EmitDeclare(const BlockDeclRefExpr *BDRE, unsigned Tag, llvm::Value *AI,
                   CGBuilderTy &Builder, CodeGenFunction *CGF);

  // EmitTypeForVarWithBlocksAttr - Build up structure info for the byref.  
  // See BuildByRefType.
  llvm::DIType EmitTypeForVarWithBlocksAttr(const ValueDecl *VD, 
                                            uint64_t *OffSet);

  /// getContextDescriptor - Get context info for the decl.
  llvm::DIDescriptor getContextDescriptor(const Decl *Decl,
                                          llvm::DIDescriptor &CU);

  /// CreateCompileUnit - Create new compile unit.
  void CreateCompileUnit();

  /// getOrCreateFile - Get the file debug info descriptor for the input 
  /// location.
  llvm::DIFile getOrCreateFile(SourceLocation Loc);

  /// getOrCreateType - Get the type from the cache or create a new type if
  /// necessary.
  llvm::DIType getOrCreateType(QualType Ty, llvm::DIFile F);

  /// CreateTypeNode - Create type metadata for a source language type.
  llvm::DIType CreateTypeNode(QualType Ty, llvm::DIFile F);

  /// getFunctionName - Get function name for the given FunctionDecl. If the
  /// name is constructred on demand (e.g. C++ destructor) then the name
  /// is stored on the side.
  llvm::StringRef getFunctionName(const FunctionDecl *FD);

  /// getVtableName - Get vtable name for the given Class.
  llvm::StringRef getVtableName(const CXXRecordDecl *Decl);

};
} // namespace CodeGen
} // namespace clang


#endif
