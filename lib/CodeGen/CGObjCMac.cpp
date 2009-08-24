//===------- CGObjCMac.cpp - Interface to Apple Objective-C Runtime -------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This provides Objective-C code generation targetting the Apple runtime.
//
//===----------------------------------------------------------------------===//

#include "CGObjCRuntime.h"

#include "CodeGenModule.h"
#include "CodeGenFunction.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/DeclObjC.h"
#include "clang/AST/RecordLayout.h"
#include "clang/AST/StmtObjC.h"
#include "clang/Basic/LangOptions.h"

#include "llvm/Intrinsics.h"
#include "llvm/LLVMContext.h"
#include "llvm/Module.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/Target/TargetData.h"
#include <sstream>
#include <cstdio>

using namespace clang;
using namespace CodeGen;

// Common CGObjCRuntime functions, these don't belong here, but they
// don't belong in CGObjCRuntime either so we will live with it for
// now.

/// FindIvarInterface - Find the interface containing the ivar.
///
/// FIXME: We shouldn't need to do this, the containing context should
/// be fixed.
static const ObjCInterfaceDecl *FindIvarInterface(ASTContext &Context,
                                                  const ObjCInterfaceDecl *OID,
                                                  const ObjCIvarDecl *OIVD,
                                                  unsigned &Index) {
  // FIXME: The index here is closely tied to how
  // ASTContext::getObjCLayout is implemented. This should be fixed to
  // get the information from the layout directly.
  Index = 0;
  llvm::SmallVector<ObjCIvarDecl*, 16> Ivars;
  Context.ShallowCollectObjCIvars(OID, Ivars);
  for (unsigned k = 0, e = Ivars.size(); k != e; ++k) {
    if (OIVD == Ivars[k])
      return OID;
    ++Index;
  }

  // Otherwise check in the super class.
  if (const ObjCInterfaceDecl *Super = OID->getSuperClass())
    return FindIvarInterface(Context, Super, OIVD, Index);

  return 0;
}

static uint64_t LookupFieldBitOffset(CodeGen::CodeGenModule &CGM,
                                     const ObjCInterfaceDecl *OID,
                                     const ObjCImplementationDecl *ID,
                                     const ObjCIvarDecl *Ivar) {
  unsigned Index;
  const ObjCInterfaceDecl *Container =
    FindIvarInterface(CGM.getContext(), OID, Ivar, Index);
  assert(Container && "Unable to find ivar container");

  // If we know have an implementation (and the ivar is in it) then
  // look up in the implementation layout.
  const ASTRecordLayout *RL;
  if (ID && ID->getClassInterface() == Container)
    RL = &CGM.getContext().getASTObjCImplementationLayout(ID);
  else
    RL = &CGM.getContext().getASTObjCInterfaceLayout(Container);
  return RL->getFieldOffset(Index);
}

uint64_t CGObjCRuntime::ComputeIvarBaseOffset(CodeGen::CodeGenModule &CGM,
                                              const ObjCInterfaceDecl *OID,
                                              const ObjCIvarDecl *Ivar) {
  return LookupFieldBitOffset(CGM, OID, 0, Ivar) / 8;
}

uint64_t CGObjCRuntime::ComputeIvarBaseOffset(CodeGen::CodeGenModule &CGM,
                                              const ObjCImplementationDecl *OID,
                                              const ObjCIvarDecl *Ivar) {
  return LookupFieldBitOffset(CGM, OID->getClassInterface(), OID, Ivar) / 8;
}

LValue CGObjCRuntime::EmitValueForIvarAtOffset(CodeGen::CodeGenFunction &CGF,
                                               const ObjCInterfaceDecl *OID,
                                               llvm::Value *BaseValue,
                                               const ObjCIvarDecl *Ivar,
                                               unsigned CVRQualifiers,
                                               llvm::Value *Offset) {
  // Compute (type*) ( (char *) BaseValue + Offset)
  llvm::Type *I8Ptr = 
      llvm::PointerType::getUnqual(llvm::Type::getInt8Ty(CGF.getLLVMContext()));
  QualType IvarTy = Ivar->getType();
  const llvm::Type *LTy = CGF.CGM.getTypes().ConvertTypeForMem(IvarTy);
  llvm::Value *V = CGF.Builder.CreateBitCast(BaseValue, I8Ptr);
  V = CGF.Builder.CreateGEP(V, Offset, "add.ptr");
  V = CGF.Builder.CreateBitCast(V, llvm::PointerType::getUnqual(LTy));

  if (Ivar->isBitField()) {
    // We need to compute the bit offset for the bit-field, the offset
    // is to the byte. Note, there is a subtle invariant here: we can
    // only call this routine on non-sythesized ivars but we may be
    // called for synthesized ivars. However, a synthesized ivar can
    // never be a bit-field so this is safe.
    uint64_t BitOffset = LookupFieldBitOffset(CGF.CGM, OID, 0, Ivar) % 8;

    uint64_t BitFieldSize =
      Ivar->getBitWidth()->EvaluateAsInt(CGF.getContext()).getZExtValue();
    return LValue::MakeBitfield(V, BitOffset, BitFieldSize,
                                IvarTy->isSignedIntegerType(),
                                IvarTy.getCVRQualifiers()|CVRQualifiers);
  }

  LValue LV = LValue::MakeAddr(V, IvarTy.getCVRQualifiers()|CVRQualifiers,
                               CGF.CGM.getContext().getObjCGCAttrKind(IvarTy));
  LValue::SetObjCIvar(LV, true);
  return LV;
}

///

namespace {

typedef std::vector<llvm::Constant*> ConstantVector;

// FIXME: We should find a nicer way to make the labels for metadata, string
// concatenation is lame.

class ObjCCommonTypesHelper {
protected:
  llvm::LLVMContext &VMContext;

private:
  llvm::Constant *getMessageSendFn() const {
    // id objc_msgSend (id, SEL, ...)
    std::vector<const llvm::Type*> Params;
    Params.push_back(ObjectPtrTy);
    Params.push_back(SelectorPtrTy);
    return
      CGM.CreateRuntimeFunction(llvm::FunctionType::get(ObjectPtrTy,
                                                        Params, true),
                                "objc_msgSend");
  }

  llvm::Constant *getMessageSendStretFn() const {
    // id objc_msgSend_stret (id, SEL, ...)
    std::vector<const llvm::Type*> Params;
    Params.push_back(ObjectPtrTy);
    Params.push_back(SelectorPtrTy);
    return
      CGM.CreateRuntimeFunction(llvm::FunctionType::get(llvm::Type::getVoidTy(VMContext),
                                                        Params, true),
                                "objc_msgSend_stret");

  }

  llvm::Constant *getMessageSendFpretFn() const {
    // FIXME: This should be long double on x86_64?
    // [double | long double] objc_msgSend_fpret(id self, SEL op, ...)
    std::vector<const llvm::Type*> Params;
    Params.push_back(ObjectPtrTy);
    Params.push_back(SelectorPtrTy);
    return
      CGM.CreateRuntimeFunction(llvm::FunctionType::get(
                                             llvm::Type::getDoubleTy(VMContext),
                                                        Params,
                                                        true),
                                "objc_msgSend_fpret");

  }

  llvm::Constant *getMessageSendSuperFn() const {
    // id objc_msgSendSuper(struct objc_super *super, SEL op, ...)
    const char *SuperName = "objc_msgSendSuper";
    std::vector<const llvm::Type*> Params;
    Params.push_back(SuperPtrTy);
    Params.push_back(SelectorPtrTy);
    return CGM.CreateRuntimeFunction(llvm::FunctionType::get(ObjectPtrTy,
                                                             Params, true),
                                     SuperName);
  }

  llvm::Constant *getMessageSendSuperFn2() const {
    // id objc_msgSendSuper2(struct objc_super *super, SEL op, ...)
    const char *SuperName = "objc_msgSendSuper2";
    std::vector<const llvm::Type*> Params;
    Params.push_back(SuperPtrTy);
    Params.push_back(SelectorPtrTy);
    return CGM.CreateRuntimeFunction(llvm::FunctionType::get(ObjectPtrTy,
                                                             Params, true),
                                     SuperName);
  }

  llvm::Constant *getMessageSendSuperStretFn() const {
    // void objc_msgSendSuper_stret(void * stretAddr, struct objc_super *super,
    //                              SEL op, ...)
    std::vector<const llvm::Type*> Params;
    Params.push_back(Int8PtrTy);
    Params.push_back(SuperPtrTy);
    Params.push_back(SelectorPtrTy);
    return CGM.CreateRuntimeFunction(
      llvm::FunctionType::get(llvm::Type::getVoidTy(VMContext),
                              Params, true),
      "objc_msgSendSuper_stret");
  }

  llvm::Constant *getMessageSendSuperStretFn2() const {
    // void objc_msgSendSuper2_stret(void * stretAddr, struct objc_super *super,
    //                               SEL op, ...)
    std::vector<const llvm::Type*> Params;
    Params.push_back(Int8PtrTy);
    Params.push_back(SuperPtrTy);
    Params.push_back(SelectorPtrTy);
    return CGM.CreateRuntimeFunction(
      llvm::FunctionType::get(llvm::Type::getVoidTy(VMContext),
                              Params, true),
      "objc_msgSendSuper2_stret");
  }

  llvm::Constant *getMessageSendSuperFpretFn() const {
    // There is no objc_msgSendSuper_fpret? How can that work?
    return getMessageSendSuperFn();
  }

  llvm::Constant *getMessageSendSuperFpretFn2() const {
    // There is no objc_msgSendSuper_fpret? How can that work?
    return getMessageSendSuperFn2();
  }

protected:
  CodeGen::CodeGenModule &CGM;

public:
  const llvm::Type *ShortTy, *IntTy, *LongTy, *LongLongTy;
  const llvm::Type *Int8PtrTy;

  /// ObjectPtrTy - LLVM type for object handles (typeof(id))
  const llvm::Type *ObjectPtrTy;

  /// PtrObjectPtrTy - LLVM type for id *
  const llvm::Type *PtrObjectPtrTy;

  /// SelectorPtrTy - LLVM type for selector handles (typeof(SEL))
  const llvm::Type *SelectorPtrTy;
  /// ProtocolPtrTy - LLVM type for external protocol handles
  /// (typeof(Protocol))
  const llvm::Type *ExternalProtocolPtrTy;

  // SuperCTy - clang type for struct objc_super.
  QualType SuperCTy;
  // SuperPtrCTy - clang type for struct objc_super *.
  QualType SuperPtrCTy;

  /// SuperTy - LLVM type for struct objc_super.
  const llvm::StructType *SuperTy;
  /// SuperPtrTy - LLVM type for struct objc_super *.
  const llvm::Type *SuperPtrTy;

  /// PropertyTy - LLVM type for struct objc_property (struct _prop_t
  /// in GCC parlance).
  const llvm::StructType *PropertyTy;

  /// PropertyListTy - LLVM type for struct objc_property_list
  /// (_prop_list_t in GCC parlance).
  const llvm::StructType *PropertyListTy;
  /// PropertyListPtrTy - LLVM type for struct objc_property_list*.
  const llvm::Type *PropertyListPtrTy;

  // MethodTy - LLVM type for struct objc_method.
  const llvm::StructType *MethodTy;

  /// CacheTy - LLVM type for struct objc_cache.
  const llvm::Type *CacheTy;
  /// CachePtrTy - LLVM type for struct objc_cache *.
  const llvm::Type *CachePtrTy;

  llvm::Constant *getGetPropertyFn() {
    CodeGen::CodeGenTypes &Types = CGM.getTypes();
    ASTContext &Ctx = CGM.getContext();
    // id objc_getProperty (id, SEL, ptrdiff_t, bool)
    llvm::SmallVector<QualType,16> Params;
    QualType IdType = Ctx.getObjCIdType();
    QualType SelType = Ctx.getObjCSelType();
    Params.push_back(IdType);
    Params.push_back(SelType);
    Params.push_back(Ctx.LongTy);
    Params.push_back(Ctx.BoolTy);
    const llvm::FunctionType *FTy =
      Types.GetFunctionType(Types.getFunctionInfo(IdType, Params), false);
    return CGM.CreateRuntimeFunction(FTy, "objc_getProperty");
  }

  llvm::Constant *getSetPropertyFn() {
    CodeGen::CodeGenTypes &Types = CGM.getTypes();
    ASTContext &Ctx = CGM.getContext();
    // void objc_setProperty (id, SEL, ptrdiff_t, id, bool, bool)
    llvm::SmallVector<QualType,16> Params;
    QualType IdType = Ctx.getObjCIdType();
    QualType SelType = Ctx.getObjCSelType();
    Params.push_back(IdType);
    Params.push_back(SelType);
    Params.push_back(Ctx.LongTy);
    Params.push_back(IdType);
    Params.push_back(Ctx.BoolTy);
    Params.push_back(Ctx.BoolTy);
    const llvm::FunctionType *FTy =
      Types.GetFunctionType(Types.getFunctionInfo(Ctx.VoidTy, Params), false);
    return CGM.CreateRuntimeFunction(FTy, "objc_setProperty");
  }

  llvm::Constant *getEnumerationMutationFn() {
    CodeGen::CodeGenTypes &Types = CGM.getTypes();
    ASTContext &Ctx = CGM.getContext();
    // void objc_enumerationMutation (id)
    llvm::SmallVector<QualType,16> Params;
    Params.push_back(Ctx.getObjCIdType());
    const llvm::FunctionType *FTy =
      Types.GetFunctionType(Types.getFunctionInfo(Ctx.VoidTy, Params), false);
    return CGM.CreateRuntimeFunction(FTy, "objc_enumerationMutation");
  }

  /// GcReadWeakFn -- LLVM objc_read_weak (id *src) function.
  llvm::Constant *getGcReadWeakFn() {
    // id objc_read_weak (id *)
    std::vector<const llvm::Type*> Args;
    Args.push_back(ObjectPtrTy->getPointerTo());
    llvm::FunctionType *FTy =
      llvm::FunctionType::get(ObjectPtrTy, Args, false);
    return CGM.CreateRuntimeFunction(FTy, "objc_read_weak");
  }

  /// GcAssignWeakFn -- LLVM objc_assign_weak function.
  llvm::Constant *getGcAssignWeakFn() {
    // id objc_assign_weak (id, id *)
    std::vector<const llvm::Type*> Args(1, ObjectPtrTy);
    Args.push_back(ObjectPtrTy->getPointerTo());
    llvm::FunctionType *FTy =
      llvm::FunctionType::get(ObjectPtrTy, Args, false);
    return CGM.CreateRuntimeFunction(FTy, "objc_assign_weak");
  }

  /// GcAssignGlobalFn -- LLVM objc_assign_global function.
  llvm::Constant *getGcAssignGlobalFn() {
    // id objc_assign_global(id, id *)
    std::vector<const llvm::Type*> Args(1, ObjectPtrTy);
    Args.push_back(ObjectPtrTy->getPointerTo());
    llvm::FunctionType *FTy =
      llvm::FunctionType::get(ObjectPtrTy, Args, false);
    return CGM.CreateRuntimeFunction(FTy, "objc_assign_global");
  }

  /// GcAssignIvarFn -- LLVM objc_assign_ivar function.
  llvm::Constant *getGcAssignIvarFn() {
    // id objc_assign_ivar(id, id *)
    std::vector<const llvm::Type*> Args(1, ObjectPtrTy);
    Args.push_back(ObjectPtrTy->getPointerTo());
    llvm::FunctionType *FTy =
      llvm::FunctionType::get(ObjectPtrTy, Args, false);
    return CGM.CreateRuntimeFunction(FTy, "objc_assign_ivar");
  }

  /// GcMemmoveCollectableFn -- LLVM objc_memmove_collectable function.
  llvm::Constant *GcMemmoveCollectableFn() {
    // void *objc_memmove_collectable(void *dst, const void *src, size_t size)
    std::vector<const llvm::Type*> Args(1, Int8PtrTy);
    Args.push_back(Int8PtrTy);
    Args.push_back(LongTy);
    llvm::FunctionType *FTy = llvm::FunctionType::get(Int8PtrTy, Args, false);
    return CGM.CreateRuntimeFunction(FTy, "objc_memmove_collectable");
  }

  /// GcAssignStrongCastFn -- LLVM objc_assign_strongCast function.
  llvm::Constant *getGcAssignStrongCastFn() {
    // id objc_assign_global(id, id *)
    std::vector<const llvm::Type*> Args(1, ObjectPtrTy);
    Args.push_back(ObjectPtrTy->getPointerTo());
    llvm::FunctionType *FTy =
      llvm::FunctionType::get(ObjectPtrTy, Args, false);
    return CGM.CreateRuntimeFunction(FTy, "objc_assign_strongCast");
  }

  /// ExceptionThrowFn - LLVM objc_exception_throw function.
  llvm::Constant *getExceptionThrowFn() {
    // void objc_exception_throw(id)
    std::vector<const llvm::Type*> Args(1, ObjectPtrTy);
    llvm::FunctionType *FTy =
      llvm::FunctionType::get(llvm::Type::getVoidTy(VMContext), Args, false);
    return CGM.CreateRuntimeFunction(FTy, "objc_exception_throw");
  }

  /// SyncEnterFn - LLVM object_sync_enter function.
  llvm::Constant *getSyncEnterFn() {
    // void objc_sync_enter (id)
    std::vector<const llvm::Type*> Args(1, ObjectPtrTy);
    llvm::FunctionType *FTy =
      llvm::FunctionType::get(llvm::Type::getVoidTy(VMContext), Args, false);
    return CGM.CreateRuntimeFunction(FTy, "objc_sync_enter");
  }

  /// SyncExitFn - LLVM object_sync_exit function.
  llvm::Constant *getSyncExitFn() {
    // void objc_sync_exit (id)
    std::vector<const llvm::Type*> Args(1, ObjectPtrTy);
    llvm::FunctionType *FTy =
      llvm::FunctionType::get(llvm::Type::getVoidTy(VMContext), Args, false);
    return CGM.CreateRuntimeFunction(FTy, "objc_sync_exit");
  }

  llvm::Constant *getSendFn(bool IsSuper) const {
    return IsSuper ? getMessageSendSuperFn() : getMessageSendFn();
  }

  llvm::Constant *getSendFn2(bool IsSuper) const {
    return IsSuper ? getMessageSendSuperFn2() : getMessageSendFn();
  }

  llvm::Constant *getSendStretFn(bool IsSuper) const {
    return IsSuper ? getMessageSendSuperStretFn() : getMessageSendStretFn();
  }

  llvm::Constant *getSendStretFn2(bool IsSuper) const {
    return IsSuper ? getMessageSendSuperStretFn2() : getMessageSendStretFn();
  }

  llvm::Constant *getSendFpretFn(bool IsSuper) const {
    return IsSuper ? getMessageSendSuperFpretFn() : getMessageSendFpretFn();
  }

  llvm::Constant *getSendFpretFn2(bool IsSuper) const {
    return IsSuper ? getMessageSendSuperFpretFn2() : getMessageSendFpretFn();
  }

  ObjCCommonTypesHelper(CodeGen::CodeGenModule &cgm);
  ~ObjCCommonTypesHelper(){}
};

/// ObjCTypesHelper - Helper class that encapsulates lazy
/// construction of varies types used during ObjC generation.
class ObjCTypesHelper : public ObjCCommonTypesHelper {
public:
  /// SymtabTy - LLVM type for struct objc_symtab.
  const llvm::StructType *SymtabTy;
  /// SymtabPtrTy - LLVM type for struct objc_symtab *.
  const llvm::Type *SymtabPtrTy;
  /// ModuleTy - LLVM type for struct objc_module.
  const llvm::StructType *ModuleTy;

  /// ProtocolTy - LLVM type for struct objc_protocol.
  const llvm::StructType *ProtocolTy;
  /// ProtocolPtrTy - LLVM type for struct objc_protocol *.
  const llvm::Type *ProtocolPtrTy;
  /// ProtocolExtensionTy - LLVM type for struct
  /// objc_protocol_extension.
  const llvm::StructType *ProtocolExtensionTy;
  /// ProtocolExtensionTy - LLVM type for struct
  /// objc_protocol_extension *.
  const llvm::Type *ProtocolExtensionPtrTy;
  /// MethodDescriptionTy - LLVM type for struct
  /// objc_method_description.
  const llvm::StructType *MethodDescriptionTy;
  /// MethodDescriptionListTy - LLVM type for struct
  /// objc_method_description_list.
  const llvm::StructType *MethodDescriptionListTy;
  /// MethodDescriptionListPtrTy - LLVM type for struct
  /// objc_method_description_list *.
  const llvm::Type *MethodDescriptionListPtrTy;
  /// ProtocolListTy - LLVM type for struct objc_property_list.
  const llvm::Type *ProtocolListTy;
  /// ProtocolListPtrTy - LLVM type for struct objc_property_list*.
  const llvm::Type *ProtocolListPtrTy;
  /// CategoryTy - LLVM type for struct objc_category.
  const llvm::StructType *CategoryTy;
  /// ClassTy - LLVM type for struct objc_class.
  const llvm::StructType *ClassTy;
  /// ClassPtrTy - LLVM type for struct objc_class *.
  const llvm::Type *ClassPtrTy;
  /// ClassExtensionTy - LLVM type for struct objc_class_ext.
  const llvm::StructType *ClassExtensionTy;
  /// ClassExtensionPtrTy - LLVM type for struct objc_class_ext *.
  const llvm::Type *ClassExtensionPtrTy;
  // IvarTy - LLVM type for struct objc_ivar.
  const llvm::StructType *IvarTy;
  /// IvarListTy - LLVM type for struct objc_ivar_list.
  const llvm::Type *IvarListTy;
  /// IvarListPtrTy - LLVM type for struct objc_ivar_list *.
  const llvm::Type *IvarListPtrTy;
  /// MethodListTy - LLVM type for struct objc_method_list.
  const llvm::Type *MethodListTy;
  /// MethodListPtrTy - LLVM type for struct objc_method_list *.
  const llvm::Type *MethodListPtrTy;

  /// ExceptionDataTy - LLVM type for struct _objc_exception_data.
  const llvm::Type *ExceptionDataTy;

  /// ExceptionTryEnterFn - LLVM objc_exception_try_enter function.
  llvm::Constant *getExceptionTryEnterFn() {
    std::vector<const llvm::Type*> Params;
    Params.push_back(llvm::PointerType::getUnqual(ExceptionDataTy));
    return CGM.CreateRuntimeFunction(
      llvm::FunctionType::get(llvm::Type::getVoidTy(VMContext),
                              Params, false),
      "objc_exception_try_enter");
  }

  /// ExceptionTryExitFn - LLVM objc_exception_try_exit function.
  llvm::Constant *getExceptionTryExitFn() {
    std::vector<const llvm::Type*> Params;
    Params.push_back(llvm::PointerType::getUnqual(ExceptionDataTy));
    return CGM.CreateRuntimeFunction(
      llvm::FunctionType::get(llvm::Type::getVoidTy(VMContext),
                              Params, false),
      "objc_exception_try_exit");
  }

  /// ExceptionExtractFn - LLVM objc_exception_extract function.
  llvm::Constant *getExceptionExtractFn() {
    std::vector<const llvm::Type*> Params;
    Params.push_back(llvm::PointerType::getUnqual(ExceptionDataTy));
    return CGM.CreateRuntimeFunction(llvm::FunctionType::get(ObjectPtrTy,
                                                             Params, false),
                                     "objc_exception_extract");

  }

  /// ExceptionMatchFn - LLVM objc_exception_match function.
  llvm::Constant *getExceptionMatchFn() {
    std::vector<const llvm::Type*> Params;
    Params.push_back(ClassPtrTy);
    Params.push_back(ObjectPtrTy);
    return CGM.CreateRuntimeFunction(
      llvm::FunctionType::get(llvm::Type::getInt32Ty(VMContext),
                              Params, false),
      "objc_exception_match");

  }

  /// SetJmpFn - LLVM _setjmp function.
  llvm::Constant *getSetJmpFn() {
    std::vector<const llvm::Type*> Params;
    Params.push_back(llvm::PointerType::getUnqual(llvm::Type::getInt32Ty(VMContext)));
    return
      CGM.CreateRuntimeFunction(llvm::FunctionType::get(llvm::Type::getInt32Ty(VMContext),
                                                        Params, false),
                                "_setjmp");

  }

public:
  ObjCTypesHelper(CodeGen::CodeGenModule &cgm);
  ~ObjCTypesHelper() {}
};

/// ObjCNonFragileABITypesHelper - will have all types needed by objective-c's
/// modern abi
class ObjCNonFragileABITypesHelper : public ObjCCommonTypesHelper {
public:

  // MethodListnfABITy - LLVM for struct _method_list_t
  const llvm::StructType *MethodListnfABITy;

  // MethodListnfABIPtrTy - LLVM for struct _method_list_t*
  const llvm::Type *MethodListnfABIPtrTy;

  // ProtocolnfABITy = LLVM for struct _protocol_t
  const llvm::StructType *ProtocolnfABITy;

  // ProtocolnfABIPtrTy = LLVM for struct _protocol_t*
  const llvm::Type *ProtocolnfABIPtrTy;

  // ProtocolListnfABITy - LLVM for struct _objc_protocol_list
  const llvm::StructType *ProtocolListnfABITy;

  // ProtocolListnfABIPtrTy - LLVM for struct _objc_protocol_list*
  const llvm::Type *ProtocolListnfABIPtrTy;

  // ClassnfABITy - LLVM for struct _class_t
  const llvm::StructType *ClassnfABITy;

  // ClassnfABIPtrTy - LLVM for struct _class_t*
  const llvm::Type *ClassnfABIPtrTy;

  // IvarnfABITy - LLVM for struct _ivar_t
  const llvm::StructType *IvarnfABITy;

  // IvarListnfABITy - LLVM for struct _ivar_list_t
  const llvm::StructType *IvarListnfABITy;

  // IvarListnfABIPtrTy = LLVM for struct _ivar_list_t*
  const llvm::Type *IvarListnfABIPtrTy;

  // ClassRonfABITy - LLVM for struct _class_ro_t
  const llvm::StructType *ClassRonfABITy;

  // ImpnfABITy - LLVM for id (*)(id, SEL, ...)
  const llvm::Type *ImpnfABITy;

  // CategorynfABITy - LLVM for struct _category_t
  const llvm::StructType *CategorynfABITy;

  // New types for nonfragile abi messaging.

  // MessageRefTy - LLVM for:
  // struct _message_ref_t {
  //   IMP messenger;
  //   SEL name;
  // };
  const llvm::StructType *MessageRefTy;
  // MessageRefCTy - clang type for struct _message_ref_t
  QualType MessageRefCTy;

  // MessageRefPtrTy - LLVM for struct _message_ref_t*
  const llvm::Type *MessageRefPtrTy;
  // MessageRefCPtrTy - clang type for struct _message_ref_t*
  QualType MessageRefCPtrTy;

  // MessengerTy - Type of the messenger (shown as IMP above)
  const llvm::FunctionType *MessengerTy;

  // SuperMessageRefTy - LLVM for:
  // struct _super_message_ref_t {
  //   SUPER_IMP messenger;
  //   SEL name;
  // };
  const llvm::StructType *SuperMessageRefTy;

  // SuperMessageRefPtrTy - LLVM for struct _super_message_ref_t*
  const llvm::Type *SuperMessageRefPtrTy;

  llvm::Constant *getMessageSendFixupFn() {
    // id objc_msgSend_fixup(id, struct message_ref_t*, ...)
    std::vector<const llvm::Type*> Params;
    Params.push_back(ObjectPtrTy);
    Params.push_back(MessageRefPtrTy);
    return CGM.CreateRuntimeFunction(llvm::FunctionType::get(ObjectPtrTy,
                                                             Params, true),
                                     "objc_msgSend_fixup");
  }

  llvm::Constant *getMessageSendFpretFixupFn() {
    // id objc_msgSend_fpret_fixup(id, struct message_ref_t*, ...)
    std::vector<const llvm::Type*> Params;
    Params.push_back(ObjectPtrTy);
    Params.push_back(MessageRefPtrTy);
    return CGM.CreateRuntimeFunction(llvm::FunctionType::get(ObjectPtrTy,
                                                             Params, true),
                                     "objc_msgSend_fpret_fixup");
  }

  llvm::Constant *getMessageSendStretFixupFn() {
    // id objc_msgSend_stret_fixup(id, struct message_ref_t*, ...)
    std::vector<const llvm::Type*> Params;
    Params.push_back(ObjectPtrTy);
    Params.push_back(MessageRefPtrTy);
    return CGM.CreateRuntimeFunction(llvm::FunctionType::get(ObjectPtrTy,
                                                             Params, true),
                                     "objc_msgSend_stret_fixup");
  }

  llvm::Constant *getMessageSendIdFixupFn() {
    // id objc_msgSendId_fixup(id, struct message_ref_t*, ...)
    std::vector<const llvm::Type*> Params;
    Params.push_back(ObjectPtrTy);
    Params.push_back(MessageRefPtrTy);
    return CGM.CreateRuntimeFunction(llvm::FunctionType::get(ObjectPtrTy,
                                                             Params, true),
                                     "objc_msgSendId_fixup");
  }

  llvm::Constant *getMessageSendIdStretFixupFn() {
    // id objc_msgSendId_stret_fixup(id, struct message_ref_t*, ...)
    std::vector<const llvm::Type*> Params;
    Params.push_back(ObjectPtrTy);
    Params.push_back(MessageRefPtrTy);
    return CGM.CreateRuntimeFunction(llvm::FunctionType::get(ObjectPtrTy,
                                                             Params, true),
                                     "objc_msgSendId_stret_fixup");
  }
  llvm::Constant *getMessageSendSuper2FixupFn() {
    // id objc_msgSendSuper2_fixup (struct objc_super *,
    //                              struct _super_message_ref_t*, ...)
    std::vector<const llvm::Type*> Params;
    Params.push_back(SuperPtrTy);
    Params.push_back(SuperMessageRefPtrTy);
    return  CGM.CreateRuntimeFunction(llvm::FunctionType::get(ObjectPtrTy,
                                                              Params, true),
                                      "objc_msgSendSuper2_fixup");
  }

  llvm::Constant *getMessageSendSuper2StretFixupFn() {
    // id objc_msgSendSuper2_stret_fixup(struct objc_super *,
    //                                   struct _super_message_ref_t*, ...)
    std::vector<const llvm::Type*> Params;
    Params.push_back(SuperPtrTy);
    Params.push_back(SuperMessageRefPtrTy);
    return  CGM.CreateRuntimeFunction(llvm::FunctionType::get(ObjectPtrTy,
                                                              Params, true),
                                      "objc_msgSendSuper2_stret_fixup");
  }



  /// EHPersonalityPtr - LLVM value for an i8* to the Objective-C
  /// exception personality function.
  llvm::Value *getEHPersonalityPtr() {
    llvm::Constant *Personality =
      CGM.CreateRuntimeFunction(llvm::FunctionType::get(llvm::Type::getInt32Ty(VMContext),
                                                        true),
                                "__objc_personality_v0");
    return llvm::ConstantExpr::getBitCast(Personality, Int8PtrTy);
  }

  llvm::Constant *getUnwindResumeOrRethrowFn() {
    std::vector<const llvm::Type*> Params;
    Params.push_back(Int8PtrTy);
    return CGM.CreateRuntimeFunction(
      llvm::FunctionType::get(llvm::Type::getVoidTy(VMContext),
                              Params, false),
      "_Unwind_Resume_or_Rethrow");
  }

  llvm::Constant *getObjCEndCatchFn() {
    return CGM.CreateRuntimeFunction(llvm::FunctionType::get(llvm::Type::getVoidTy(VMContext),
                                                             false),
                                     "objc_end_catch");

  }

  llvm::Constant *getObjCBeginCatchFn() {
    std::vector<const llvm::Type*> Params;
    Params.push_back(Int8PtrTy);
    return CGM.CreateRuntimeFunction(llvm::FunctionType::get(Int8PtrTy,
                                                             Params, false),
                                     "objc_begin_catch");
  }

  const llvm::StructType *EHTypeTy;
  const llvm::Type *EHTypePtrTy;

  ObjCNonFragileABITypesHelper(CodeGen::CodeGenModule &cgm);
  ~ObjCNonFragileABITypesHelper(){}
};

class CGObjCCommonMac : public CodeGen::CGObjCRuntime {
public:
  // FIXME - accessibility
  class GC_IVAR {
  public:
    unsigned ivar_bytepos;
    unsigned ivar_size;
    GC_IVAR(unsigned bytepos = 0, unsigned size = 0)
      : ivar_bytepos(bytepos), ivar_size(size) {}

    // Allow sorting based on byte pos.
    bool operator<(const GC_IVAR &b) const {
      return ivar_bytepos < b.ivar_bytepos;
    }
  };

  class SKIP_SCAN {
  public:
    unsigned skip;
    unsigned scan;
    SKIP_SCAN(unsigned _skip = 0, unsigned _scan = 0)
      : skip(_skip), scan(_scan) {}
  };

protected:
  CodeGen::CodeGenModule &CGM;
  llvm::LLVMContext &VMContext;
  // FIXME! May not be needing this after all.
  unsigned ObjCABI;

  // gc ivar layout bitmap calculation helper caches.
  llvm::SmallVector<GC_IVAR, 16> SkipIvars;
  llvm::SmallVector<GC_IVAR, 16> IvarsInfo;

  /// LazySymbols - Symbols to generate a lazy reference for. See
  /// DefinedSymbols and FinishModule().
  std::set<IdentifierInfo*> LazySymbols;

  /// DefinedSymbols - External symbols which are defined by this
  /// module. The symbols in this list and LazySymbols are used to add
  /// special linker symbols which ensure that Objective-C modules are
  /// linked properly.
  std::set<IdentifierInfo*> DefinedSymbols;

  /// ClassNames - uniqued class names.
  llvm::DenseMap<IdentifierInfo*, llvm::GlobalVariable*> ClassNames;

  /// MethodVarNames - uniqued method variable names.
  llvm::DenseMap<Selector, llvm::GlobalVariable*> MethodVarNames;

  /// MethodVarTypes - uniqued method type signatures. We have to use
  /// a StringMap here because have no other unique reference.
  llvm::StringMap<llvm::GlobalVariable*> MethodVarTypes;

  /// MethodDefinitions - map of methods which have been defined in
  /// this translation unit.
  llvm::DenseMap<const ObjCMethodDecl*, llvm::Function*> MethodDefinitions;

  /// PropertyNames - uniqued method variable names.
  llvm::DenseMap<IdentifierInfo*, llvm::GlobalVariable*> PropertyNames;

  /// ClassReferences - uniqued class references.
  llvm::DenseMap<IdentifierInfo*, llvm::GlobalVariable*> ClassReferences;

  /// SelectorReferences - uniqued selector references.
  llvm::DenseMap<Selector, llvm::GlobalVariable*> SelectorReferences;

  /// Protocols - Protocols for which an objc_protocol structure has
  /// been emitted. Forward declarations are handled by creating an
  /// empty structure whose initializer is filled in when/if defined.
  llvm::DenseMap<IdentifierInfo*, llvm::GlobalVariable*> Protocols;

  /// DefinedProtocols - Protocols which have actually been
  /// defined. We should not need this, see FIXME in GenerateProtocol.
  llvm::DenseSet<IdentifierInfo*> DefinedProtocols;

  /// DefinedClasses - List of defined classes.
  std::vector<llvm::GlobalValue*> DefinedClasses;

  /// DefinedNonLazyClasses - List of defined "non-lazy" classes.
  std::vector<llvm::GlobalValue*> DefinedNonLazyClasses;

  /// DefinedCategories - List of defined categories.
  std::vector<llvm::GlobalValue*> DefinedCategories;

  /// DefinedNonLazyCategories - List of defined "non-lazy" categories.
  std::vector<llvm::GlobalValue*> DefinedNonLazyCategories;

  /// GetNameForMethod - Return a name for the given method.
  /// \param[out] NameOut - The return value.
  void GetNameForMethod(const ObjCMethodDecl *OMD,
                        const ObjCContainerDecl *CD,
                        std::string &NameOut);

  /// GetMethodVarName - Return a unique constant for the given
  /// selector's name. The return value has type char *.
  llvm::Constant *GetMethodVarName(Selector Sel);
  llvm::Constant *GetMethodVarName(IdentifierInfo *Ident);
  llvm::Constant *GetMethodVarName(const std::string &Name);

  /// GetMethodVarType - Return a unique constant for the given
  /// selector's name. The return value has type char *.

  // FIXME: This is a horrible name.
  llvm::Constant *GetMethodVarType(const ObjCMethodDecl *D);
  llvm::Constant *GetMethodVarType(const FieldDecl *D);

  /// GetPropertyName - Return a unique constant for the given
  /// name. The return value has type char *.
  llvm::Constant *GetPropertyName(IdentifierInfo *Ident);

  // FIXME: This can be dropped once string functions are unified.
  llvm::Constant *GetPropertyTypeString(const ObjCPropertyDecl *PD,
                                        const Decl *Container);

  /// GetClassName - Return a unique constant for the given selector's
  /// name. The return value has type char *.
  llvm::Constant *GetClassName(IdentifierInfo *Ident);

  /// BuildIvarLayout - Builds ivar layout bitmap for the class
  /// implementation for the __strong or __weak case.
  ///
  llvm::Constant *BuildIvarLayout(const ObjCImplementationDecl *OI,
                                  bool ForStrongLayout);

  void BuildAggrIvarRecordLayout(const RecordType *RT,
                                 unsigned int BytePos, bool ForStrongLayout,
                                 bool &HasUnion);
  void BuildAggrIvarLayout(const ObjCImplementationDecl *OI,
                           const llvm::StructLayout *Layout,
                           const RecordDecl *RD,
                           const llvm::SmallVectorImpl<FieldDecl*> &RecFields,
                           unsigned int BytePos, bool ForStrongLayout,
                           bool &HasUnion);

  /// GetIvarLayoutName - Returns a unique constant for the given
  /// ivar layout bitmap.
  llvm::Constant *GetIvarLayoutName(IdentifierInfo *Ident,
                                    const ObjCCommonTypesHelper &ObjCTypes);

  /// EmitPropertyList - Emit the given property list. The return
  /// value has type PropertyListPtrTy.
  llvm::Constant *EmitPropertyList(const std::string &Name,
                                   const Decl *Container,
                                   const ObjCContainerDecl *OCD,
                                   const ObjCCommonTypesHelper &ObjCTypes);

  /// GetProtocolRef - Return a reference to the internal protocol
  /// description, creating an empty one if it has not been
  /// defined. The return value has type ProtocolPtrTy.
  llvm::Constant *GetProtocolRef(const ObjCProtocolDecl *PD);

  /// CreateMetadataVar - Create a global variable with internal
  /// linkage for use by the Objective-C runtime.
  ///
  /// This is a convenience wrapper which not only creates the
  /// variable, but also sets the section and alignment and adds the
  /// global to the "llvm.used" list.
  ///
  /// \param Name - The variable name.
  /// \param Init - The variable initializer; this is also used to
  /// define the type of the variable.
  /// \param Section - The section the variable should go into, or 0.
  /// \param Align - The alignment for the variable, or 0.
  /// \param AddToUsed - Whether the variable should be added to
  /// "llvm.used".
  llvm::GlobalVariable *CreateMetadataVar(const std::string &Name,
                                          llvm::Constant *Init,
                                          const char *Section,
                                          unsigned Align,
                                          bool AddToUsed);

  CodeGen::RValue EmitLegacyMessageSend(CodeGen::CodeGenFunction &CGF,
                                        QualType ResultType,
                                        llvm::Value *Sel,
                                        llvm::Value *Arg0,
                                        QualType Arg0Ty,
                                        bool IsSuper,
                                        const CallArgList &CallArgs,
                                        const ObjCCommonTypesHelper &ObjCTypes);

public:
  CGObjCCommonMac(CodeGen::CodeGenModule &cgm) :
    CGM(cgm), VMContext(cgm.getLLVMContext())
    { }

  virtual llvm::Constant *GenerateConstantString(const ObjCStringLiteral *SL);

  virtual llvm::Function *GenerateMethod(const ObjCMethodDecl *OMD,
                                         const ObjCContainerDecl *CD=0);

  virtual void GenerateProtocol(const ObjCProtocolDecl *PD);

  /// GetOrEmitProtocol - Get the protocol object for the given
  /// declaration, emitting it if necessary. The return value has type
  /// ProtocolPtrTy.
  virtual llvm::Constant *GetOrEmitProtocol(const ObjCProtocolDecl *PD)=0;

  /// GetOrEmitProtocolRef - Get a forward reference to the protocol
  /// object for the given declaration, emitting it if needed. These
  /// forward references will be filled in with empty bodies if no
  /// definition is seen. The return value has type ProtocolPtrTy.
  virtual llvm::Constant *GetOrEmitProtocolRef(const ObjCProtocolDecl *PD)=0;
};

class CGObjCMac : public CGObjCCommonMac {
private:
  ObjCTypesHelper ObjCTypes;
  /// EmitImageInfo - Emit the image info marker used to encode some module
  /// level information.
  void EmitImageInfo();

  /// EmitModuleInfo - Another marker encoding module level
  /// information.
  void EmitModuleInfo();

  /// EmitModuleSymols - Emit module symbols, the list of defined
  /// classes and categories. The result has type SymtabPtrTy.
  llvm::Constant *EmitModuleSymbols();

  /// FinishModule - Write out global data structures at the end of
  /// processing a translation unit.
  void FinishModule();

  /// EmitClassExtension - Generate the class extension structure used
  /// to store the weak ivar layout and properties. The return value
  /// has type ClassExtensionPtrTy.
  llvm::Constant *EmitClassExtension(const ObjCImplementationDecl *ID);

  /// EmitClassRef - Return a Value*, of type ObjCTypes.ClassPtrTy,
  /// for the given class.
  llvm::Value *EmitClassRef(CGBuilderTy &Builder,
                            const ObjCInterfaceDecl *ID);

  CodeGen::RValue EmitMessageSend(CodeGen::CodeGenFunction &CGF,
                                  QualType ResultType,
                                  Selector Sel,
                                  llvm::Value *Arg0,
                                  QualType Arg0Ty,
                                  bool IsSuper,
                                  const CallArgList &CallArgs);

  /// EmitIvarList - Emit the ivar list for the given
  /// implementation. If ForClass is true the list of class ivars
  /// (i.e. metaclass ivars) is emitted, otherwise the list of
  /// interface ivars will be emitted. The return value has type
  /// IvarListPtrTy.
  llvm::Constant *EmitIvarList(const ObjCImplementationDecl *ID,
                               bool ForClass);

  /// EmitMetaClass - Emit a forward reference to the class structure
  /// for the metaclass of the given interface. The return value has
  /// type ClassPtrTy.
  llvm::Constant *EmitMetaClassRef(const ObjCInterfaceDecl *ID);

  /// EmitMetaClass - Emit a class structure for the metaclass of the
  /// given implementation. The return value has type ClassPtrTy.
  llvm::Constant *EmitMetaClass(const ObjCImplementationDecl *ID,
                                llvm::Constant *Protocols,
                                const ConstantVector &Methods);

  llvm::Constant *GetMethodConstant(const ObjCMethodDecl *MD);

  llvm::Constant *GetMethodDescriptionConstant(const ObjCMethodDecl *MD);

  /// EmitMethodList - Emit the method list for the given
  /// implementation. The return value has type MethodListPtrTy.
  llvm::Constant *EmitMethodList(const std::string &Name,
                                 const char *Section,
                                 const ConstantVector &Methods);

  /// EmitMethodDescList - Emit a method description list for a list of
  /// method declarations.
  ///  - TypeName: The name for the type containing the methods.
  ///  - IsProtocol: True iff these methods are for a protocol.
  ///  - ClassMethds: True iff these are class methods.
  ///  - Required: When true, only "required" methods are
  ///    listed. Similarly, when false only "optional" methods are
  ///    listed. For classes this should always be true.
  ///  - begin, end: The method list to output.
  ///
  /// The return value has type MethodDescriptionListPtrTy.
  llvm::Constant *EmitMethodDescList(const std::string &Name,
                                     const char *Section,
                                     const ConstantVector &Methods);

  /// GetOrEmitProtocol - Get the protocol object for the given
  /// declaration, emitting it if necessary. The return value has type
  /// ProtocolPtrTy.
  virtual llvm::Constant *GetOrEmitProtocol(const ObjCProtocolDecl *PD);

  /// GetOrEmitProtocolRef - Get a forward reference to the protocol
  /// object for the given declaration, emitting it if needed. These
  /// forward references will be filled in with empty bodies if no
  /// definition is seen. The return value has type ProtocolPtrTy.
  virtual llvm::Constant *GetOrEmitProtocolRef(const ObjCProtocolDecl *PD);

  /// EmitProtocolExtension - Generate the protocol extension
  /// structure used to store optional instance and class methods, and
  /// protocol properties. The return value has type
  /// ProtocolExtensionPtrTy.
  llvm::Constant *
  EmitProtocolExtension(const ObjCProtocolDecl *PD,
                        const ConstantVector &OptInstanceMethods,
                        const ConstantVector &OptClassMethods);

  /// EmitProtocolList - Generate the list of referenced
  /// protocols. The return value has type ProtocolListPtrTy.
  llvm::Constant *EmitProtocolList(const std::string &Name,
                                   ObjCProtocolDecl::protocol_iterator begin,
                                   ObjCProtocolDecl::protocol_iterator end);

  /// EmitSelector - Return a Value*, of type ObjCTypes.SelectorPtrTy,
  /// for the given selector.
  llvm::Value *EmitSelector(CGBuilderTy &Builder, Selector Sel);

public:
  CGObjCMac(CodeGen::CodeGenModule &cgm);

  virtual llvm::Function *ModuleInitFunction();

  virtual CodeGen::RValue GenerateMessageSend(CodeGen::CodeGenFunction &CGF,
                                              QualType ResultType,
                                              Selector Sel,
                                              llvm::Value *Receiver,
                                              bool IsClassMessage,
                                              const CallArgList &CallArgs,
                                              const ObjCMethodDecl *Method);

  virtual CodeGen::RValue
  GenerateMessageSendSuper(CodeGen::CodeGenFunction &CGF,
                           QualType ResultType,
                           Selector Sel,
                           const ObjCInterfaceDecl *Class,
                           bool isCategoryImpl,
                           llvm::Value *Receiver,
                           bool IsClassMessage,
                           const CallArgList &CallArgs);

  virtual llvm::Value *GetClass(CGBuilderTy &Builder,
                                const ObjCInterfaceDecl *ID);

  virtual llvm::Value *GetSelector(CGBuilderTy &Builder, Selector Sel);

  /// The NeXT/Apple runtimes do not support typed selectors; just emit an
  /// untyped one.
  virtual llvm::Value *GetSelector(CGBuilderTy &Builder,
                                   const ObjCMethodDecl *Method);

  virtual void GenerateCategory(const ObjCCategoryImplDecl *CMD);

  virtual void GenerateClass(const ObjCImplementationDecl *ClassDecl);

  virtual llvm::Value *GenerateProtocolRef(CGBuilderTy &Builder,
                                           const ObjCProtocolDecl *PD);

  virtual llvm::Constant *GetPropertyGetFunction();
  virtual llvm::Constant *GetPropertySetFunction();
  virtual llvm::Constant *EnumerationMutationFunction();

  virtual void EmitTryOrSynchronizedStmt(CodeGen::CodeGenFunction &CGF,
                                         const Stmt &S);
  virtual void EmitThrowStmt(CodeGen::CodeGenFunction &CGF,
                             const ObjCAtThrowStmt &S);
  virtual llvm::Value * EmitObjCWeakRead(CodeGen::CodeGenFunction &CGF,
                                         llvm::Value *AddrWeakObj);
  virtual void EmitObjCWeakAssign(CodeGen::CodeGenFunction &CGF,
                                  llvm::Value *src, llvm::Value *dst);
  virtual void EmitObjCGlobalAssign(CodeGen::CodeGenFunction &CGF,
                                    llvm::Value *src, llvm::Value *dest);
  virtual void EmitObjCIvarAssign(CodeGen::CodeGenFunction &CGF,
                                  llvm::Value *src, llvm::Value *dest);
  virtual void EmitObjCStrongCastAssign(CodeGen::CodeGenFunction &CGF,
                                        llvm::Value *src, llvm::Value *dest);
  virtual void EmitGCMemmoveCollectable(CodeGen::CodeGenFunction &CGF,
                                        llvm::Value *dest, llvm::Value *src,
                                        unsigned long size);

  virtual LValue EmitObjCValueForIvar(CodeGen::CodeGenFunction &CGF,
                                      QualType ObjectTy,
                                      llvm::Value *BaseValue,
                                      const ObjCIvarDecl *Ivar,
                                      unsigned CVRQualifiers);
  virtual llvm::Value *EmitIvarOffset(CodeGen::CodeGenFunction &CGF,
                                      const ObjCInterfaceDecl *Interface,
                                      const ObjCIvarDecl *Ivar);
};

class CGObjCNonFragileABIMac : public CGObjCCommonMac {
private:
  ObjCNonFragileABITypesHelper ObjCTypes;
  llvm::GlobalVariable* ObjCEmptyCacheVar;
  llvm::GlobalVariable* ObjCEmptyVtableVar;

  /// SuperClassReferences - uniqued super class references.
  llvm::DenseMap<IdentifierInfo*, llvm::GlobalVariable*> SuperClassReferences;

  /// MetaClassReferences - uniqued meta class references.
  llvm::DenseMap<IdentifierInfo*, llvm::GlobalVariable*> MetaClassReferences;

  /// EHTypeReferences - uniqued class ehtype references.
  llvm::DenseMap<IdentifierInfo*, llvm::GlobalVariable*> EHTypeReferences;

  /// NonLegacyDispatchMethods - List of methods for which we do *not* generate
  /// legacy messaging dispatch.
  llvm::DenseSet<Selector> NonLegacyDispatchMethods;

  /// LegacyDispatchedSelector - Returns true if SEL is not in the list of
  /// NonLegacyDispatchMethods; false otherwise.
  bool LegacyDispatchedSelector(Selector Sel);

  /// FinishNonFragileABIModule - Write out global data structures at the end of
  /// processing a translation unit.
  void FinishNonFragileABIModule();

  /// AddModuleClassList - Add the given list of class pointers to the
  /// module with the provided symbol and section names.
  void AddModuleClassList(const std::vector<llvm::GlobalValue*> &Container,
                          const char *SymbolName,
                          const char *SectionName);

  llvm::GlobalVariable * BuildClassRoTInitializer(unsigned flags,
                                              unsigned InstanceStart,
                                              unsigned InstanceSize,
                                              const ObjCImplementationDecl *ID);
  llvm::GlobalVariable * BuildClassMetaData(std::string &ClassName,
                                            llvm::Constant *IsAGV,
                                            llvm::Constant *SuperClassGV,
                                            llvm::Constant *ClassRoGV,
                                            bool HiddenVisibility);

  llvm::Constant *GetMethodConstant(const ObjCMethodDecl *MD);

  llvm::Constant *GetMethodDescriptionConstant(const ObjCMethodDecl *MD);

  /// EmitMethodList - Emit the method list for the given
  /// implementation. The return value has type MethodListnfABITy.
  llvm::Constant *EmitMethodList(const std::string &Name,
                                 const char *Section,
                                 const ConstantVector &Methods);
  /// EmitIvarList - Emit the ivar list for the given
  /// implementation. If ForClass is true the list of class ivars
  /// (i.e. metaclass ivars) is emitted, otherwise the list of
  /// interface ivars will be emitted. The return value has type
  /// IvarListnfABIPtrTy.
  llvm::Constant *EmitIvarList(const ObjCImplementationDecl *ID);

  llvm::Constant *EmitIvarOffsetVar(const ObjCInterfaceDecl *ID,
                                    const ObjCIvarDecl *Ivar,
                                    unsigned long int offset);

  /// GetOrEmitProtocol - Get the protocol object for the given
  /// declaration, emitting it if necessary. The return value has type
  /// ProtocolPtrTy.
  virtual llvm::Constant *GetOrEmitProtocol(const ObjCProtocolDecl *PD);

  /// GetOrEmitProtocolRef - Get a forward reference to the protocol
  /// object for the given declaration, emitting it if needed. These
  /// forward references will be filled in with empty bodies if no
  /// definition is seen. The return value has type ProtocolPtrTy.
  virtual llvm::Constant *GetOrEmitProtocolRef(const ObjCProtocolDecl *PD);

  /// EmitProtocolList - Generate the list of referenced
  /// protocols. The return value has type ProtocolListPtrTy.
  llvm::Constant *EmitProtocolList(const std::string &Name,
                                   ObjCProtocolDecl::protocol_iterator begin,
                                   ObjCProtocolDecl::protocol_iterator end);

  CodeGen::RValue EmitMessageSend(CodeGen::CodeGenFunction &CGF,
                                  QualType ResultType,
                                  Selector Sel,
                                  llvm::Value *Receiver,
                                  QualType Arg0Ty,
                                  bool IsSuper,
                                  const CallArgList &CallArgs);

  /// GetClassGlobal - Return the global variable for the Objective-C
  /// class of the given name.
  llvm::GlobalVariable *GetClassGlobal(const std::string &Name);

  /// EmitClassRef - Return a Value*, of type ObjCTypes.ClassPtrTy,
  /// for the given class reference.
  llvm::Value *EmitClassRef(CGBuilderTy &Builder,
                            const ObjCInterfaceDecl *ID);

  /// EmitSuperClassRef - Return a Value*, of type ObjCTypes.ClassPtrTy,
  /// for the given super class reference.
  llvm::Value *EmitSuperClassRef(CGBuilderTy &Builder,
                                 const ObjCInterfaceDecl *ID);

  /// EmitMetaClassRef - Return a Value * of the address of _class_t
  /// meta-data
  llvm::Value *EmitMetaClassRef(CGBuilderTy &Builder,
                                const ObjCInterfaceDecl *ID);

  /// ObjCIvarOffsetVariable - Returns the ivar offset variable for
  /// the given ivar.
  ///
  llvm::GlobalVariable * ObjCIvarOffsetVariable(
    const ObjCInterfaceDecl *ID,
    const ObjCIvarDecl *Ivar);

  /// EmitSelector - Return a Value*, of type ObjCTypes.SelectorPtrTy,
  /// for the given selector.
  llvm::Value *EmitSelector(CGBuilderTy &Builder, Selector Sel);

  /// GetInterfaceEHType - Get the cached ehtype for the given Objective-C
  /// interface. The return value has type EHTypePtrTy.
  llvm::Value *GetInterfaceEHType(const ObjCInterfaceDecl *ID,
                                  bool ForDefinition);

  const char *getMetaclassSymbolPrefix() const {
    return "OBJC_METACLASS_$_";
  }

  const char *getClassSymbolPrefix() const {
    return "OBJC_CLASS_$_";
  }

  void GetClassSizeInfo(const ObjCImplementationDecl *OID,
                        uint32_t &InstanceStart,
                        uint32_t &InstanceSize);

  // Shamelessly stolen from Analysis/CFRefCount.cpp
  Selector GetNullarySelector(const char* name) const {
    IdentifierInfo* II = &CGM.getContext().Idents.get(name);
    return CGM.getContext().Selectors.getSelector(0, &II);
  }

  Selector GetUnarySelector(const char* name) const {
    IdentifierInfo* II = &CGM.getContext().Idents.get(name);
    return CGM.getContext().Selectors.getSelector(1, &II);
  }

  /// ImplementationIsNonLazy - Check whether the given category or
  /// class implementation is "non-lazy".
  bool ImplementationIsNonLazy(const ObjCImplDecl *OD) const;

public:
  CGObjCNonFragileABIMac(CodeGen::CodeGenModule &cgm);
  // FIXME. All stubs for now!
  virtual llvm::Function *ModuleInitFunction();

  virtual CodeGen::RValue GenerateMessageSend(CodeGen::CodeGenFunction &CGF,
                                              QualType ResultType,
                                              Selector Sel,
                                              llvm::Value *Receiver,
                                              bool IsClassMessage,
                                              const CallArgList &CallArgs,
                                              const ObjCMethodDecl *Method);

  virtual CodeGen::RValue
  GenerateMessageSendSuper(CodeGen::CodeGenFunction &CGF,
                           QualType ResultType,
                           Selector Sel,
                           const ObjCInterfaceDecl *Class,
                           bool isCategoryImpl,
                           llvm::Value *Receiver,
                           bool IsClassMessage,
                           const CallArgList &CallArgs);

  virtual llvm::Value *GetClass(CGBuilderTy &Builder,
                                const ObjCInterfaceDecl *ID);

  virtual llvm::Value *GetSelector(CGBuilderTy &Builder, Selector Sel)
    { return EmitSelector(Builder, Sel); }

  /// The NeXT/Apple runtimes do not support typed selectors; just emit an
  /// untyped one.
  virtual llvm::Value *GetSelector(CGBuilderTy &Builder,
                                   const ObjCMethodDecl *Method)
    { return EmitSelector(Builder, Method->getSelector()); }

  virtual void GenerateCategory(const ObjCCategoryImplDecl *CMD);

  virtual void GenerateClass(const ObjCImplementationDecl *ClassDecl);
  virtual llvm::Value *GenerateProtocolRef(CGBuilderTy &Builder,
                                           const ObjCProtocolDecl *PD);

  virtual llvm::Constant *GetPropertyGetFunction() {
    return ObjCTypes.getGetPropertyFn();
  }
  virtual llvm::Constant *GetPropertySetFunction() {
    return ObjCTypes.getSetPropertyFn();
  }
  virtual llvm::Constant *EnumerationMutationFunction() {
    return ObjCTypes.getEnumerationMutationFn();
  }

  virtual void EmitTryOrSynchronizedStmt(CodeGen::CodeGenFunction &CGF,
                                         const Stmt &S);
  virtual void EmitThrowStmt(CodeGen::CodeGenFunction &CGF,
                             const ObjCAtThrowStmt &S);
  virtual llvm::Value * EmitObjCWeakRead(CodeGen::CodeGenFunction &CGF,
                                         llvm::Value *AddrWeakObj);
  virtual void EmitObjCWeakAssign(CodeGen::CodeGenFunction &CGF,
                                  llvm::Value *src, llvm::Value *dst);
  virtual void EmitObjCGlobalAssign(CodeGen::CodeGenFunction &CGF,
                                    llvm::Value *src, llvm::Value *dest);
  virtual void EmitObjCIvarAssign(CodeGen::CodeGenFunction &CGF,
                                  llvm::Value *src, llvm::Value *dest);
  virtual void EmitObjCStrongCastAssign(CodeGen::CodeGenFunction &CGF,
                                        llvm::Value *src, llvm::Value *dest);
  virtual void EmitGCMemmoveCollectable(CodeGen::CodeGenFunction &CGF,
                                        llvm::Value *dest, llvm::Value *src,
                                        unsigned long size);
  virtual LValue EmitObjCValueForIvar(CodeGen::CodeGenFunction &CGF,
                                      QualType ObjectTy,
                                      llvm::Value *BaseValue,
                                      const ObjCIvarDecl *Ivar,
                                      unsigned CVRQualifiers);
  virtual llvm::Value *EmitIvarOffset(CodeGen::CodeGenFunction &CGF,
                                      const ObjCInterfaceDecl *Interface,
                                      const ObjCIvarDecl *Ivar);
};

} // end anonymous namespace

/* *** Helper Functions *** */

/// getConstantGEP() - Help routine to construct simple GEPs.
static llvm::Constant *getConstantGEP(llvm::LLVMContext &VMContext,
                                      llvm::Constant *C,
                                      unsigned idx0,
                                      unsigned idx1) {
  llvm::Value *Idxs[] = {
    llvm::ConstantInt::get(llvm::Type::getInt32Ty(VMContext), idx0),
    llvm::ConstantInt::get(llvm::Type::getInt32Ty(VMContext), idx1)
  };
  return llvm::ConstantExpr::getGetElementPtr(C, Idxs, 2);
}

/// hasObjCExceptionAttribute - Return true if this class or any super
/// class has the __objc_exception__ attribute.
static bool hasObjCExceptionAttribute(ASTContext &Context,
                                      const ObjCInterfaceDecl *OID) {
  if (OID->hasAttr<ObjCExceptionAttr>())
    return true;
  if (const ObjCInterfaceDecl *Super = OID->getSuperClass())
    return hasObjCExceptionAttribute(Context, Super);
  return false;
}

/* *** CGObjCMac Public Interface *** */

CGObjCMac::CGObjCMac(CodeGen::CodeGenModule &cgm) : CGObjCCommonMac(cgm),
                                                    ObjCTypes(cgm)
{
  ObjCABI = 1;
  EmitImageInfo();
}

/// GetClass - Return a reference to the class for the given interface
/// decl.
llvm::Value *CGObjCMac::GetClass(CGBuilderTy &Builder,
                                 const ObjCInterfaceDecl *ID) {
  return EmitClassRef(Builder, ID);
}

/// GetSelector - Return the pointer to the unique'd string for this selector.
llvm::Value *CGObjCMac::GetSelector(CGBuilderTy &Builder, Selector Sel) {
  return EmitSelector(Builder, Sel);
}
llvm::Value *CGObjCMac::GetSelector(CGBuilderTy &Builder, const ObjCMethodDecl
                                    *Method) {
  return EmitSelector(Builder, Method->getSelector());
}

/// Generate a constant CFString object.
/*
  struct __builtin_CFString {
  const int *isa; // point to __CFConstantStringClassReference
  int flags;
  const char *str;
  long length;
  };
*/

llvm::Constant *CGObjCCommonMac::GenerateConstantString(
  const ObjCStringLiteral *SL) {
  return CGM.GetAddrOfConstantCFString(SL->getString());
}

/// Generates a message send where the super is the receiver.  This is
/// a message send to self with special delivery semantics indicating
/// which class's method should be called.
CodeGen::RValue
CGObjCMac::GenerateMessageSendSuper(CodeGen::CodeGenFunction &CGF,
                                    QualType ResultType,
                                    Selector Sel,
                                    const ObjCInterfaceDecl *Class,
                                    bool isCategoryImpl,
                                    llvm::Value *Receiver,
                                    bool IsClassMessage,
                                    const CodeGen::CallArgList &CallArgs) {
  // Create and init a super structure; this is a (receiver, class)
  // pair we will pass to objc_msgSendSuper.
  llvm::Value *ObjCSuper =
    CGF.Builder.CreateAlloca(ObjCTypes.SuperTy, 0, "objc_super");
  llvm::Value *ReceiverAsObject =
    CGF.Builder.CreateBitCast(Receiver, ObjCTypes.ObjectPtrTy);
  CGF.Builder.CreateStore(ReceiverAsObject,
                          CGF.Builder.CreateStructGEP(ObjCSuper, 0));

  // If this is a class message the metaclass is passed as the target.
  llvm::Value *Target;
  if (IsClassMessage) {
    if (isCategoryImpl) {
      // Message sent to 'super' in a class method defined in a category
      // implementation requires an odd treatment.
      // If we are in a class method, we must retrieve the
      // _metaclass_ for the current class, pointed at by
      // the class's "isa" pointer.  The following assumes that
      // isa" is the first ivar in a class (which it must be).
      Target = EmitClassRef(CGF.Builder, Class->getSuperClass());
      Target = CGF.Builder.CreateStructGEP(Target, 0);
      Target = CGF.Builder.CreateLoad(Target);
    } else {
      llvm::Value *MetaClassPtr = EmitMetaClassRef(Class);
      llvm::Value *SuperPtr = CGF.Builder.CreateStructGEP(MetaClassPtr, 1);
      llvm::Value *Super = CGF.Builder.CreateLoad(SuperPtr);
      Target = Super;
    }
  } else {
    Target = EmitClassRef(CGF.Builder, Class->getSuperClass());
  }
  // FIXME: We shouldn't need to do this cast, rectify the ASTContext and
  // ObjCTypes types.
  const llvm::Type *ClassTy =
    CGM.getTypes().ConvertType(CGF.getContext().getObjCClassType());
  Target = CGF.Builder.CreateBitCast(Target, ClassTy);
  CGF.Builder.CreateStore(Target,
                          CGF.Builder.CreateStructGEP(ObjCSuper, 1));
  return EmitLegacyMessageSend(CGF, ResultType,
                               EmitSelector(CGF.Builder, Sel),
                               ObjCSuper, ObjCTypes.SuperPtrCTy,
                               true, CallArgs, ObjCTypes);
}

/// Generate code for a message send expression.
CodeGen::RValue CGObjCMac::GenerateMessageSend(CodeGen::CodeGenFunction &CGF,
                                               QualType ResultType,
                                               Selector Sel,
                                               llvm::Value *Receiver,
                                               bool IsClassMessage,
                                               const CallArgList &CallArgs,
                                               const ObjCMethodDecl *Method) {
  return EmitLegacyMessageSend(CGF, ResultType,
                               EmitSelector(CGF.Builder, Sel),
                               Receiver, CGF.getContext().getObjCIdType(),
                               false, CallArgs, ObjCTypes);
}

CodeGen::RValue CGObjCCommonMac::EmitLegacyMessageSend(
  CodeGen::CodeGenFunction &CGF,
  QualType ResultType,
  llvm::Value *Sel,
  llvm::Value *Arg0,
  QualType Arg0Ty,
  bool IsSuper,
  const CallArgList &CallArgs,
  const ObjCCommonTypesHelper &ObjCTypes) {
  CallArgList ActualArgs;
  if (!IsSuper)
    Arg0 = CGF.Builder.CreateBitCast(Arg0, ObjCTypes.ObjectPtrTy, "tmp");
  ActualArgs.push_back(std::make_pair(RValue::get(Arg0), Arg0Ty));
  ActualArgs.push_back(std::make_pair(RValue::get(Sel),
                                      CGF.getContext().getObjCSelType()));
  ActualArgs.insert(ActualArgs.end(), CallArgs.begin(), CallArgs.end());

  CodeGenTypes &Types = CGM.getTypes();
  const CGFunctionInfo &FnInfo = Types.getFunctionInfo(ResultType, ActualArgs);
  // In 64bit ABI, type must be assumed VARARG. In 32bit abi,
  // it seems not to matter.
  const llvm::FunctionType *FTy = Types.GetFunctionType(FnInfo, (ObjCABI == 2));

  llvm::Constant *Fn = NULL;
  if (CGM.ReturnTypeUsesSret(FnInfo)) {
    Fn = (ObjCABI == 2) ?  ObjCTypes.getSendStretFn2(IsSuper)
      : ObjCTypes.getSendStretFn(IsSuper);
  } else if (ResultType->isFloatingType()) {
    if (ObjCABI == 2) {
      if (const BuiltinType *BT = ResultType->getAsBuiltinType()) {
        BuiltinType::Kind k = BT->getKind();
        Fn = (k == BuiltinType::LongDouble) ? ObjCTypes.getSendFpretFn2(IsSuper)
          : ObjCTypes.getSendFn2(IsSuper);
      } else {
        Fn = ObjCTypes.getSendFn2(IsSuper);
      }
    } else
      // FIXME. This currently matches gcc's API for x86-32. May need to change
      // for others if we have their API.
      Fn = ObjCTypes.getSendFpretFn(IsSuper);
  } else {
    Fn = (ObjCABI == 2) ? ObjCTypes.getSendFn2(IsSuper)
      : ObjCTypes.getSendFn(IsSuper);
  }
  assert(Fn && "EmitLegacyMessageSend - unknown API");
  Fn = llvm::ConstantExpr::getBitCast(Fn,
                                      llvm::PointerType::getUnqual(FTy));
  return CGF.EmitCall(FnInfo, Fn, ActualArgs);
}

llvm::Value *CGObjCMac::GenerateProtocolRef(CGBuilderTy &Builder,
                                            const ObjCProtocolDecl *PD) {
  // FIXME: I don't understand why gcc generates this, or where it is
  // resolved. Investigate. Its also wasteful to look this up over and over.
  LazySymbols.insert(&CGM.getContext().Idents.get("Protocol"));

  return llvm::ConstantExpr::getBitCast(GetProtocolRef(PD),
                                        ObjCTypes.ExternalProtocolPtrTy);
}

void CGObjCCommonMac::GenerateProtocol(const ObjCProtocolDecl *PD) {
  // FIXME: We shouldn't need this, the protocol decl should contain enough
  // information to tell us whether this was a declaration or a definition.
  DefinedProtocols.insert(PD->getIdentifier());

  // If we have generated a forward reference to this protocol, emit
  // it now. Otherwise do nothing, the protocol objects are lazily
  // emitted.
  if (Protocols.count(PD->getIdentifier()))
    GetOrEmitProtocol(PD);
}

llvm::Constant *CGObjCCommonMac::GetProtocolRef(const ObjCProtocolDecl *PD) {
  if (DefinedProtocols.count(PD->getIdentifier()))
    return GetOrEmitProtocol(PD);
  return GetOrEmitProtocolRef(PD);
}

/*
// APPLE LOCAL radar 4585769 - Objective-C 1.0 extensions
struct _objc_protocol {
struct _objc_protocol_extension *isa;
char *protocol_name;
struct _objc_protocol_list *protocol_list;
struct _objc__method_prototype_list *instance_methods;
struct _objc__method_prototype_list *class_methods
};

See EmitProtocolExtension().
*/
llvm::Constant *CGObjCMac::GetOrEmitProtocol(const ObjCProtocolDecl *PD) {
  llvm::GlobalVariable *&Entry = Protocols[PD->getIdentifier()];

  // Early exit if a defining object has already been generated.
  if (Entry && Entry->hasInitializer())
    return Entry;

  // FIXME: I don't understand why gcc generates this, or where it is
  // resolved. Investigate. Its also wasteful to look this up over and over.
  LazySymbols.insert(&CGM.getContext().Idents.get("Protocol"));

  const char *ProtocolName = PD->getNameAsCString();

  // Construct method lists.
  std::vector<llvm::Constant*> InstanceMethods, ClassMethods;
  std::vector<llvm::Constant*> OptInstanceMethods, OptClassMethods;
  for (ObjCProtocolDecl::instmeth_iterator
         i = PD->instmeth_begin(), e = PD->instmeth_end(); i != e; ++i) {
    ObjCMethodDecl *MD = *i;
    llvm::Constant *C = GetMethodDescriptionConstant(MD);
    if (MD->getImplementationControl() == ObjCMethodDecl::Optional) {
      OptInstanceMethods.push_back(C);
    } else {
      InstanceMethods.push_back(C);
    }
  }

  for (ObjCProtocolDecl::classmeth_iterator
         i = PD->classmeth_begin(), e = PD->classmeth_end(); i != e; ++i) {
    ObjCMethodDecl *MD = *i;
    llvm::Constant *C = GetMethodDescriptionConstant(MD);
    if (MD->getImplementationControl() == ObjCMethodDecl::Optional) {
      OptClassMethods.push_back(C);
    } else {
      ClassMethods.push_back(C);
    }
  }

  std::vector<llvm::Constant*> Values(5);
  Values[0] = EmitProtocolExtension(PD, OptInstanceMethods, OptClassMethods);
  Values[1] = GetClassName(PD->getIdentifier());
  Values[2] =
    EmitProtocolList("\01L_OBJC_PROTOCOL_REFS_" + PD->getNameAsString(),
                     PD->protocol_begin(),
                     PD->protocol_end());
  Values[3] =
    EmitMethodDescList("\01L_OBJC_PROTOCOL_INSTANCE_METHODS_"
                       + PD->getNameAsString(),
                       "__OBJC,__cat_inst_meth,regular,no_dead_strip",
                       InstanceMethods);
  Values[4] =
    EmitMethodDescList("\01L_OBJC_PROTOCOL_CLASS_METHODS_"
                       + PD->getNameAsString(),
                       "__OBJC,__cat_cls_meth,regular,no_dead_strip",
                       ClassMethods);
  llvm::Constant *Init = llvm::ConstantStruct::get(ObjCTypes.ProtocolTy,
                                                   Values);

  if (Entry) {
    // Already created, fix the linkage and update the initializer.
    Entry->setLinkage(llvm::GlobalValue::InternalLinkage);
    Entry->setInitializer(Init);
  } else {
    Entry =
      new llvm::GlobalVariable(CGM.getModule(), ObjCTypes.ProtocolTy, false,
                               llvm::GlobalValue::InternalLinkage,
                               Init,
                               std::string("\01L_OBJC_PROTOCOL_")+ProtocolName);
    Entry->setSection("__OBJC,__protocol,regular,no_dead_strip");
    Entry->setAlignment(4);
    // FIXME: Is this necessary? Why only for protocol?
    Entry->setAlignment(4);
  }
  CGM.AddUsedGlobal(Entry);

  return Entry;
}

llvm::Constant *CGObjCMac::GetOrEmitProtocolRef(const ObjCProtocolDecl *PD) {
  llvm::GlobalVariable *&Entry = Protocols[PD->getIdentifier()];

  if (!Entry) {
    // We use the initializer as a marker of whether this is a forward
    // reference or not. At module finalization we add the empty
    // contents for protocols which were referenced but never defined.
    Entry =
      new llvm::GlobalVariable(CGM.getModule(), ObjCTypes.ProtocolTy, false,
                               llvm::GlobalValue::ExternalLinkage,
                               0,
                               "\01L_OBJC_PROTOCOL_" + PD->getNameAsString());
    Entry->setSection("__OBJC,__protocol,regular,no_dead_strip");
    Entry->setAlignment(4);
    // FIXME: Is this necessary? Why only for protocol?
    Entry->setAlignment(4);
  }

  return Entry;
}

/*
  struct _objc_protocol_extension {
  uint32_t size;
  struct objc_method_description_list *optional_instance_methods;
  struct objc_method_description_list *optional_class_methods;
  struct objc_property_list *instance_properties;
  };
*/
llvm::Constant *
CGObjCMac::EmitProtocolExtension(const ObjCProtocolDecl *PD,
                                 const ConstantVector &OptInstanceMethods,
                                 const ConstantVector &OptClassMethods) {
  uint64_t Size =
    CGM.getTargetData().getTypeAllocSize(ObjCTypes.ProtocolExtensionTy);
  std::vector<llvm::Constant*> Values(4);
  Values[0] = llvm::ConstantInt::get(ObjCTypes.IntTy, Size);
  Values[1] =
    EmitMethodDescList("\01L_OBJC_PROTOCOL_INSTANCE_METHODS_OPT_"
                       + PD->getNameAsString(),
                       "__OBJC,__cat_inst_meth,regular,no_dead_strip",
                       OptInstanceMethods);
  Values[2] =
    EmitMethodDescList("\01L_OBJC_PROTOCOL_CLASS_METHODS_OPT_"
                       + PD->getNameAsString(),
                       "__OBJC,__cat_cls_meth,regular,no_dead_strip",
                       OptClassMethods);
  Values[3] = EmitPropertyList("\01L_OBJC_$_PROP_PROTO_LIST_" +
                               PD->getNameAsString(),
                               0, PD, ObjCTypes);

  // Return null if no extension bits are used.
  if (Values[1]->isNullValue() && Values[2]->isNullValue() &&
      Values[3]->isNullValue())
    return llvm::Constant::getNullValue(ObjCTypes.ProtocolExtensionPtrTy);

  llvm::Constant *Init =
    llvm::ConstantStruct::get(ObjCTypes.ProtocolExtensionTy, Values);

  // No special section, but goes in llvm.used
  return CreateMetadataVar("\01L_OBJC_PROTOCOLEXT_" + PD->getNameAsString(),
                           Init,
                           0, 0, true);
}

/*
  struct objc_protocol_list {
  struct objc_protocol_list *next;
  long count;
  Protocol *list[];
  };
*/
llvm::Constant *
CGObjCMac::EmitProtocolList(const std::string &Name,
                            ObjCProtocolDecl::protocol_iterator begin,
                            ObjCProtocolDecl::protocol_iterator end) {
  std::vector<llvm::Constant*> ProtocolRefs;

  for (; begin != end; ++begin)
    ProtocolRefs.push_back(GetProtocolRef(*begin));

  // Just return null for empty protocol lists
  if (ProtocolRefs.empty())
    return llvm::Constant::getNullValue(ObjCTypes.ProtocolListPtrTy);

  // This list is null terminated.
  ProtocolRefs.push_back(llvm::Constant::getNullValue(ObjCTypes.ProtocolPtrTy));

  std::vector<llvm::Constant*> Values(3);
  // This field is only used by the runtime.
  Values[0] = llvm::Constant::getNullValue(ObjCTypes.ProtocolListPtrTy);
  Values[1] = llvm::ConstantInt::get(ObjCTypes.LongTy,
                                     ProtocolRefs.size() - 1);
  Values[2] =
    llvm::ConstantArray::get(llvm::ArrayType::get(ObjCTypes.ProtocolPtrTy,
                                                  ProtocolRefs.size()),
                             ProtocolRefs);

  llvm::Constant *Init = llvm::ConstantStruct::get(VMContext, Values);
  llvm::GlobalVariable *GV =
    CreateMetadataVar(Name, Init, "__OBJC,__cat_cls_meth,regular,no_dead_strip",
                      4, false);
  return llvm::ConstantExpr::getBitCast(GV, ObjCTypes.ProtocolListPtrTy);
}

/*
  struct _objc_property {
  const char * const name;
  const char * const attributes;
  };

  struct _objc_property_list {
  uint32_t entsize; // sizeof (struct _objc_property)
  uint32_t prop_count;
  struct _objc_property[prop_count];
  };
*/
llvm::Constant *CGObjCCommonMac::EmitPropertyList(const std::string &Name,
                                       const Decl *Container,
                                       const ObjCContainerDecl *OCD,
                                       const ObjCCommonTypesHelper &ObjCTypes) {
  std::vector<llvm::Constant*> Properties, Prop(2);
  for (ObjCContainerDecl::prop_iterator I = OCD->prop_begin(),
         E = OCD->prop_end(); I != E; ++I) {
    const ObjCPropertyDecl *PD = *I;
    Prop[0] = GetPropertyName(PD->getIdentifier());
    Prop[1] = GetPropertyTypeString(PD, Container);
    Properties.push_back(llvm::ConstantStruct::get(ObjCTypes.PropertyTy,
                                                   Prop));
  }

  // Return null for empty list.
  if (Properties.empty())
    return llvm::Constant::getNullValue(ObjCTypes.PropertyListPtrTy);

  unsigned PropertySize =
    CGM.getTargetData().getTypeAllocSize(ObjCTypes.PropertyTy);
  std::vector<llvm::Constant*> Values(3);
  Values[0] = llvm::ConstantInt::get(ObjCTypes.IntTy, PropertySize);
  Values[1] = llvm::ConstantInt::get(ObjCTypes.IntTy, Properties.size());
  llvm::ArrayType *AT = llvm::ArrayType::get(ObjCTypes.PropertyTy,
                                             Properties.size());
  Values[2] = llvm::ConstantArray::get(AT, Properties);
  llvm::Constant *Init = llvm::ConstantStruct::get(VMContext, Values);

  llvm::GlobalVariable *GV =
    CreateMetadataVar(Name, Init,
                      (ObjCABI == 2) ? "__DATA, __objc_const" :
                      "__OBJC,__property,regular,no_dead_strip",
                      (ObjCABI == 2) ? 8 : 4,
                      true);
  return llvm::ConstantExpr::getBitCast(GV, ObjCTypes.PropertyListPtrTy);
}

/*
  struct objc_method_description_list {
  int count;
  struct objc_method_description list[];
  };
*/
llvm::Constant *
CGObjCMac::GetMethodDescriptionConstant(const ObjCMethodDecl *MD) {
  std::vector<llvm::Constant*> Desc(2);
  Desc[0] =
    llvm::ConstantExpr::getBitCast(GetMethodVarName(MD->getSelector()),
                                   ObjCTypes.SelectorPtrTy);
  Desc[1] = GetMethodVarType(MD);
  return llvm::ConstantStruct::get(ObjCTypes.MethodDescriptionTy,
                                   Desc);
}

llvm::Constant *CGObjCMac::EmitMethodDescList(const std::string &Name,
                                              const char *Section,
                                              const ConstantVector &Methods) {
  // Return null for empty list.
  if (Methods.empty())
    return llvm::Constant::getNullValue(ObjCTypes.MethodDescriptionListPtrTy);

  std::vector<llvm::Constant*> Values(2);
  Values[0] = llvm::ConstantInt::get(ObjCTypes.IntTy, Methods.size());
  llvm::ArrayType *AT = llvm::ArrayType::get(ObjCTypes.MethodDescriptionTy,
                                             Methods.size());
  Values[1] = llvm::ConstantArray::get(AT, Methods);
  llvm::Constant *Init = llvm::ConstantStruct::get(VMContext, Values);

  llvm::GlobalVariable *GV = CreateMetadataVar(Name, Init, Section, 4, true);
  return llvm::ConstantExpr::getBitCast(GV,
                                        ObjCTypes.MethodDescriptionListPtrTy);
}

/*
  struct _objc_category {
  char *category_name;
  char *class_name;
  struct _objc_method_list *instance_methods;
  struct _objc_method_list *class_methods;
  struct _objc_protocol_list *protocols;
  uint32_t size; // <rdar://4585769>
  struct _objc_property_list *instance_properties;
  };
*/
void CGObjCMac::GenerateCategory(const ObjCCategoryImplDecl *OCD) {
  unsigned Size = CGM.getTargetData().getTypeAllocSize(ObjCTypes.CategoryTy);

  // FIXME: This is poor design, the OCD should have a pointer to the category
  // decl. Additionally, note that Category can be null for the @implementation
  // w/o an @interface case. Sema should just create one for us as it does for
  // @implementation so everyone else can live life under a clear blue sky.
  const ObjCInterfaceDecl *Interface = OCD->getClassInterface();
  const ObjCCategoryDecl *Category =
    Interface->FindCategoryDeclaration(OCD->getIdentifier());
  std::string ExtName(Interface->getNameAsString() + "_" +
                      OCD->getNameAsString());

  std::vector<llvm::Constant*> InstanceMethods, ClassMethods;
  for (ObjCCategoryImplDecl::instmeth_iterator
         i = OCD->instmeth_begin(), e = OCD->instmeth_end(); i != e; ++i) {
    // Instance methods should always be defined.
    InstanceMethods.push_back(GetMethodConstant(*i));
  }
  for (ObjCCategoryImplDecl::classmeth_iterator
         i = OCD->classmeth_begin(), e = OCD->classmeth_end(); i != e; ++i) {
    // Class methods should always be defined.
    ClassMethods.push_back(GetMethodConstant(*i));
  }

  std::vector<llvm::Constant*> Values(7);
  Values[0] = GetClassName(OCD->getIdentifier());
  Values[1] = GetClassName(Interface->getIdentifier());
  LazySymbols.insert(Interface->getIdentifier());
  Values[2] =
    EmitMethodList(std::string("\01L_OBJC_CATEGORY_INSTANCE_METHODS_") +
                   ExtName,
                   "__OBJC,__cat_inst_meth,regular,no_dead_strip",
                   InstanceMethods);
  Values[3] =
    EmitMethodList(std::string("\01L_OBJC_CATEGORY_CLASS_METHODS_") + ExtName,
                   "__OBJC,__cat_cls_meth,regular,no_dead_strip",
                   ClassMethods);
  if (Category) {
    Values[4] =
      EmitProtocolList(std::string("\01L_OBJC_CATEGORY_PROTOCOLS_") + ExtName,
                       Category->protocol_begin(),
                       Category->protocol_end());
  } else {
    Values[4] = llvm::Constant::getNullValue(ObjCTypes.ProtocolListPtrTy);
  }
  Values[5] = llvm::ConstantInt::get(ObjCTypes.IntTy, Size);

  // If there is no category @interface then there can be no properties.
  if (Category) {
    Values[6] = EmitPropertyList(std::string("\01l_OBJC_$_PROP_LIST_")+ExtName,
                                 OCD, Category, ObjCTypes);
  } else {
    Values[6] = llvm::Constant::getNullValue(ObjCTypes.PropertyListPtrTy);
  }

  llvm::Constant *Init = llvm::ConstantStruct::get(ObjCTypes.CategoryTy,
                                                   Values);

  llvm::GlobalVariable *GV =
    CreateMetadataVar(std::string("\01L_OBJC_CATEGORY_")+ExtName, Init,
                      "__OBJC,__category,regular,no_dead_strip",
                      4, true);
  DefinedCategories.push_back(GV);
}

// FIXME: Get from somewhere?
enum ClassFlags {
  eClassFlags_Factory              = 0x00001,
  eClassFlags_Meta                 = 0x00002,
  // <rdr://5142207>
  eClassFlags_HasCXXStructors      = 0x02000,
  eClassFlags_Hidden               = 0x20000,
  eClassFlags_ABI2_Hidden          = 0x00010,
  eClassFlags_ABI2_HasCXXStructors = 0x00004   // <rdr://4923634>
};

/*
  struct _objc_class {
  Class isa;
  Class super_class;
  const char *name;
  long version;
  long info;
  long instance_size;
  struct _objc_ivar_list *ivars;
  struct _objc_method_list *methods;
  struct _objc_cache *cache;
  struct _objc_protocol_list *protocols;
  // Objective-C 1.0 extensions (<rdr://4585769>)
  const char *ivar_layout;
  struct _objc_class_ext *ext;
  };

  See EmitClassExtension();
*/
void CGObjCMac::GenerateClass(const ObjCImplementationDecl *ID) {
  DefinedSymbols.insert(ID->getIdentifier());

  std::string ClassName = ID->getNameAsString();
  // FIXME: Gross
  ObjCInterfaceDecl *Interface =
    const_cast<ObjCInterfaceDecl*>(ID->getClassInterface());
  llvm::Constant *Protocols =
    EmitProtocolList("\01L_OBJC_CLASS_PROTOCOLS_" + ID->getNameAsString(),
                     Interface->protocol_begin(),
                     Interface->protocol_end());
  unsigned Flags = eClassFlags_Factory;
  unsigned Size =
    CGM.getContext().getASTObjCImplementationLayout(ID).getSize() / 8;

  // FIXME: Set CXX-structors flag.
  if (CGM.getDeclVisibilityMode(ID->getClassInterface()) == LangOptions::Hidden)
    Flags |= eClassFlags_Hidden;

  std::vector<llvm::Constant*> InstanceMethods, ClassMethods;
  for (ObjCImplementationDecl::instmeth_iterator
         i = ID->instmeth_begin(), e = ID->instmeth_end(); i != e; ++i) {
    // Instance methods should always be defined.
    InstanceMethods.push_back(GetMethodConstant(*i));
  }
  for (ObjCImplementationDecl::classmeth_iterator
         i = ID->classmeth_begin(), e = ID->classmeth_end(); i != e; ++i) {
    // Class methods should always be defined.
    ClassMethods.push_back(GetMethodConstant(*i));
  }

  for (ObjCImplementationDecl::propimpl_iterator
         i = ID->propimpl_begin(), e = ID->propimpl_end(); i != e; ++i) {
    ObjCPropertyImplDecl *PID = *i;

    if (PID->getPropertyImplementation() == ObjCPropertyImplDecl::Synthesize) {
      ObjCPropertyDecl *PD = PID->getPropertyDecl();

      if (ObjCMethodDecl *MD = PD->getGetterMethodDecl())
        if (llvm::Constant *C = GetMethodConstant(MD))
          InstanceMethods.push_back(C);
      if (ObjCMethodDecl *MD = PD->getSetterMethodDecl())
        if (llvm::Constant *C = GetMethodConstant(MD))
          InstanceMethods.push_back(C);
    }
  }

  std::vector<llvm::Constant*> Values(12);
  Values[ 0] = EmitMetaClass(ID, Protocols, ClassMethods);
  if (ObjCInterfaceDecl *Super = Interface->getSuperClass()) {
    // Record a reference to the super class.
    LazySymbols.insert(Super->getIdentifier());

    Values[ 1] =
      llvm::ConstantExpr::getBitCast(GetClassName(Super->getIdentifier()),
                                     ObjCTypes.ClassPtrTy);
  } else {
    Values[ 1] = llvm::Constant::getNullValue(ObjCTypes.ClassPtrTy);
  }
  Values[ 2] = GetClassName(ID->getIdentifier());
  // Version is always 0.
  Values[ 3] = llvm::ConstantInt::get(ObjCTypes.LongTy, 0);
  Values[ 4] = llvm::ConstantInt::get(ObjCTypes.LongTy, Flags);
  Values[ 5] = llvm::ConstantInt::get(ObjCTypes.LongTy, Size);
  Values[ 6] = EmitIvarList(ID, false);
  Values[ 7] =
    EmitMethodList("\01L_OBJC_INSTANCE_METHODS_" + ID->getNameAsString(),
                   "__OBJC,__inst_meth,regular,no_dead_strip",
                   InstanceMethods);
  // cache is always NULL.
  Values[ 8] = llvm::Constant::getNullValue(ObjCTypes.CachePtrTy);
  Values[ 9] = Protocols;
  Values[10] = BuildIvarLayout(ID, true);
  Values[11] = EmitClassExtension(ID);
  llvm::Constant *Init = llvm::ConstantStruct::get(ObjCTypes.ClassTy,
                                                   Values);

  llvm::GlobalVariable *GV =
    CreateMetadataVar(std::string("\01L_OBJC_CLASS_")+ClassName, Init,
                      "__OBJC,__class,regular,no_dead_strip",
                      4, true);
  DefinedClasses.push_back(GV);
}

llvm::Constant *CGObjCMac::EmitMetaClass(const ObjCImplementationDecl *ID,
                                         llvm::Constant *Protocols,
                                         const ConstantVector &Methods) {
  unsigned Flags = eClassFlags_Meta;
  unsigned Size = CGM.getTargetData().getTypeAllocSize(ObjCTypes.ClassTy);

  if (CGM.getDeclVisibilityMode(ID->getClassInterface()) == LangOptions::Hidden)
    Flags |= eClassFlags_Hidden;

  std::vector<llvm::Constant*> Values(12);
  // The isa for the metaclass is the root of the hierarchy.
  const ObjCInterfaceDecl *Root = ID->getClassInterface();
  while (const ObjCInterfaceDecl *Super = Root->getSuperClass())
    Root = Super;
  Values[ 0] =
    llvm::ConstantExpr::getBitCast(GetClassName(Root->getIdentifier()),
                                   ObjCTypes.ClassPtrTy);
  // The super class for the metaclass is emitted as the name of the
  // super class. The runtime fixes this up to point to the
  // *metaclass* for the super class.
  if (ObjCInterfaceDecl *Super = ID->getClassInterface()->getSuperClass()) {
    Values[ 1] =
      llvm::ConstantExpr::getBitCast(GetClassName(Super->getIdentifier()),
                                     ObjCTypes.ClassPtrTy);
  } else {
    Values[ 1] = llvm::Constant::getNullValue(ObjCTypes.ClassPtrTy);
  }
  Values[ 2] = GetClassName(ID->getIdentifier());
  // Version is always 0.
  Values[ 3] = llvm::ConstantInt::get(ObjCTypes.LongTy, 0);
  Values[ 4] = llvm::ConstantInt::get(ObjCTypes.LongTy, Flags);
  Values[ 5] = llvm::ConstantInt::get(ObjCTypes.LongTy, Size);
  Values[ 6] = EmitIvarList(ID, true);
  Values[ 7] =
    EmitMethodList("\01L_OBJC_CLASS_METHODS_" + ID->getNameAsString(),
                   "__OBJC,__cls_meth,regular,no_dead_strip",
                   Methods);
  // cache is always NULL.
  Values[ 8] = llvm::Constant::getNullValue(ObjCTypes.CachePtrTy);
  Values[ 9] = Protocols;
  // ivar_layout for metaclass is always NULL.
  Values[10] = llvm::Constant::getNullValue(ObjCTypes.Int8PtrTy);
  // The class extension is always unused for metaclasses.
  Values[11] = llvm::Constant::getNullValue(ObjCTypes.ClassExtensionPtrTy);
  llvm::Constant *Init = llvm::ConstantStruct::get(ObjCTypes.ClassTy,
                                                   Values);

  std::string Name("\01L_OBJC_METACLASS_");
  Name += ID->getNameAsCString();

  // Check for a forward reference.
  llvm::GlobalVariable *GV = CGM.getModule().getGlobalVariable(Name);
  if (GV) {
    assert(GV->getType()->getElementType() == ObjCTypes.ClassTy &&
           "Forward metaclass reference has incorrect type.");
    GV->setLinkage(llvm::GlobalValue::InternalLinkage);
    GV->setInitializer(Init);
  } else {
    GV = new llvm::GlobalVariable(CGM.getModule(), ObjCTypes.ClassTy, false,
                                  llvm::GlobalValue::InternalLinkage,
                                  Init, Name);
  }
  GV->setSection("__OBJC,__meta_class,regular,no_dead_strip");
  GV->setAlignment(4);
  CGM.AddUsedGlobal(GV);

  return GV;
}

llvm::Constant *CGObjCMac::EmitMetaClassRef(const ObjCInterfaceDecl *ID) {
  std::string Name = "\01L_OBJC_METACLASS_" + ID->getNameAsString();

  // FIXME: Should we look these up somewhere other than the module. Its a bit
  // silly since we only generate these while processing an implementation, so
  // exactly one pointer would work if know when we entered/exitted an
  // implementation block.

  // Check for an existing forward reference.
  // Previously, metaclass with internal linkage may have been defined.
  // pass 'true' as 2nd argument so it is returned.
  if (llvm::GlobalVariable *GV = CGM.getModule().getGlobalVariable(Name,
                                                                   true)) {
    assert(GV->getType()->getElementType() == ObjCTypes.ClassTy &&
           "Forward metaclass reference has incorrect type.");
    return GV;
  } else {
    // Generate as an external reference to keep a consistent
    // module. This will be patched up when we emit the metaclass.
    return new llvm::GlobalVariable(CGM.getModule(), ObjCTypes.ClassTy, false,
                                    llvm::GlobalValue::ExternalLinkage,
                                    0,
                                    Name);
  }
}

/*
  struct objc_class_ext {
  uint32_t size;
  const char *weak_ivar_layout;
  struct _objc_property_list *properties;
  };
*/
llvm::Constant *
CGObjCMac::EmitClassExtension(const ObjCImplementationDecl *ID) {
  uint64_t Size =
    CGM.getTargetData().getTypeAllocSize(ObjCTypes.ClassExtensionTy);

  std::vector<llvm::Constant*> Values(3);
  Values[0] = llvm::ConstantInt::get(ObjCTypes.IntTy, Size);
  Values[1] = BuildIvarLayout(ID, false);
  Values[2] = EmitPropertyList("\01l_OBJC_$_PROP_LIST_" + ID->getNameAsString(),
                               ID, ID->getClassInterface(), ObjCTypes);

  // Return null if no extension bits are used.
  if (Values[1]->isNullValue() && Values[2]->isNullValue())
    return llvm::Constant::getNullValue(ObjCTypes.ClassExtensionPtrTy);

  llvm::Constant *Init =
    llvm::ConstantStruct::get(ObjCTypes.ClassExtensionTy, Values);
  return CreateMetadataVar("\01L_OBJC_CLASSEXT_" + ID->getNameAsString(),
                           Init, "__OBJC,__class_ext,regular,no_dead_strip",
                           4, true);
}

/*
  struct objc_ivar {
  char *ivar_name;
  char *ivar_type;
  int ivar_offset;
  };

  struct objc_ivar_list {
  int ivar_count;
  struct objc_ivar list[count];
  };
*/
llvm::Constant *CGObjCMac::EmitIvarList(const ObjCImplementationDecl *ID,
                                        bool ForClass) {
  std::vector<llvm::Constant*> Ivars, Ivar(3);

  // When emitting the root class GCC emits ivar entries for the
  // actual class structure. It is not clear if we need to follow this
  // behavior; for now lets try and get away with not doing it. If so,
  // the cleanest solution would be to make up an ObjCInterfaceDecl
  // for the class.
  if (ForClass)
    return llvm::Constant::getNullValue(ObjCTypes.IvarListPtrTy);

  ObjCInterfaceDecl *OID =
    const_cast<ObjCInterfaceDecl*>(ID->getClassInterface());

  llvm::SmallVector<ObjCIvarDecl*, 16> OIvars;
  CGM.getContext().ShallowCollectObjCIvars(OID, OIvars);

  for (unsigned i = 0, e = OIvars.size(); i != e; ++i) {
    ObjCIvarDecl *IVD = OIvars[i];
    // Ignore unnamed bit-fields.
    if (!IVD->getDeclName())
      continue;
    Ivar[0] = GetMethodVarName(IVD->getIdentifier());
    Ivar[1] = GetMethodVarType(IVD);
    Ivar[2] = llvm::ConstantInt::get(ObjCTypes.IntTy,
                                     ComputeIvarBaseOffset(CGM, OID, IVD));
    Ivars.push_back(llvm::ConstantStruct::get(ObjCTypes.IvarTy, Ivar));
  }

  // Return null for empty list.
  if (Ivars.empty())
    return llvm::Constant::getNullValue(ObjCTypes.IvarListPtrTy);

  std::vector<llvm::Constant*> Values(2);
  Values[0] = llvm::ConstantInt::get(ObjCTypes.IntTy, Ivars.size());
  llvm::ArrayType *AT = llvm::ArrayType::get(ObjCTypes.IvarTy,
                                             Ivars.size());
  Values[1] = llvm::ConstantArray::get(AT, Ivars);
  llvm::Constant *Init = llvm::ConstantStruct::get(VMContext, Values);

  llvm::GlobalVariable *GV;
  if (ForClass)
    GV = CreateMetadataVar("\01L_OBJC_CLASS_VARIABLES_" + ID->getNameAsString(),
                           Init, "__OBJC,__class_vars,regular,no_dead_strip",
                           4, true);
  else
    GV = CreateMetadataVar("\01L_OBJC_INSTANCE_VARIABLES_"
                           + ID->getNameAsString(),
                           Init, "__OBJC,__instance_vars,regular,no_dead_strip",
                           4, true);
  return llvm::ConstantExpr::getBitCast(GV, ObjCTypes.IvarListPtrTy);
}

/*
  struct objc_method {
  SEL method_name;
  char *method_types;
  void *method;
  };

  struct objc_method_list {
  struct objc_method_list *obsolete;
  int count;
  struct objc_method methods_list[count];
  };
*/

/// GetMethodConstant - Return a struct objc_method constant for the
/// given method if it has been defined. The result is null if the
/// method has not been defined. The return value has type MethodPtrTy.
llvm::Constant *CGObjCMac::GetMethodConstant(const ObjCMethodDecl *MD) {
  // FIXME: Use DenseMap::lookup
  llvm::Function *Fn = MethodDefinitions[MD];
  if (!Fn)
    return 0;

  std::vector<llvm::Constant*> Method(3);
  Method[0] =
    llvm::ConstantExpr::getBitCast(GetMethodVarName(MD->getSelector()),
                                   ObjCTypes.SelectorPtrTy);
  Method[1] = GetMethodVarType(MD);
  Method[2] = llvm::ConstantExpr::getBitCast(Fn, ObjCTypes.Int8PtrTy);
  return llvm::ConstantStruct::get(ObjCTypes.MethodTy, Method);
}

llvm::Constant *CGObjCMac::EmitMethodList(const std::string &Name,
                                          const char *Section,
                                          const ConstantVector &Methods) {
  // Return null for empty list.
  if (Methods.empty())
    return llvm::Constant::getNullValue(ObjCTypes.MethodListPtrTy);

  std::vector<llvm::Constant*> Values(3);
  Values[0] = llvm::Constant::getNullValue(ObjCTypes.Int8PtrTy);
  Values[1] = llvm::ConstantInt::get(ObjCTypes.IntTy, Methods.size());
  llvm::ArrayType *AT = llvm::ArrayType::get(ObjCTypes.MethodTy,
                                             Methods.size());
  Values[2] = llvm::ConstantArray::get(AT, Methods);
  llvm::Constant *Init = llvm::ConstantStruct::get(VMContext, Values);

  llvm::GlobalVariable *GV = CreateMetadataVar(Name, Init, Section, 4, true);
  return llvm::ConstantExpr::getBitCast(GV,
                                        ObjCTypes.MethodListPtrTy);
}

llvm::Function *CGObjCCommonMac::GenerateMethod(const ObjCMethodDecl *OMD,
                                                const ObjCContainerDecl *CD) {
  std::string Name;
  GetNameForMethod(OMD, CD, Name);

  CodeGenTypes &Types = CGM.getTypes();
  const llvm::FunctionType *MethodTy =
    Types.GetFunctionType(Types.getFunctionInfo(OMD), OMD->isVariadic());
  llvm::Function *Method =
    llvm::Function::Create(MethodTy,
                           llvm::GlobalValue::InternalLinkage,
                           Name,
                           &CGM.getModule());
  MethodDefinitions.insert(std::make_pair(OMD, Method));

  return Method;
}

llvm::GlobalVariable *
CGObjCCommonMac::CreateMetadataVar(const std::string &Name,
                                   llvm::Constant *Init,
                                   const char *Section,
                                   unsigned Align,
                                   bool AddToUsed) {
  const llvm::Type *Ty = Init->getType();
  llvm::GlobalVariable *GV =
    new llvm::GlobalVariable(CGM.getModule(), Ty, false,
                             llvm::GlobalValue::InternalLinkage, Init, Name);
  if (Section)
    GV->setSection(Section);
  if (Align)
    GV->setAlignment(Align);
  if (AddToUsed)
    CGM.AddUsedGlobal(GV);
  return GV;
}

llvm::Function *CGObjCMac::ModuleInitFunction() {
  // Abuse this interface function as a place to finalize.
  FinishModule();
  return NULL;
}

llvm::Constant *CGObjCMac::GetPropertyGetFunction() {
  return ObjCTypes.getGetPropertyFn();
}

llvm::Constant *CGObjCMac::GetPropertySetFunction() {
  return ObjCTypes.getSetPropertyFn();
}

llvm::Constant *CGObjCMac::EnumerationMutationFunction() {
  return ObjCTypes.getEnumerationMutationFn();
}

/*

  Objective-C setjmp-longjmp (sjlj) Exception Handling
  --

  The basic framework for a @try-catch-finally is as follows:
  {
  objc_exception_data d;
  id _rethrow = null;
  bool _call_try_exit = true;

  objc_exception_try_enter(&d);
  if (!setjmp(d.jmp_buf)) {
  ... try body ...
  } else {
  // exception path
  id _caught = objc_exception_extract(&d);

  // enter new try scope for handlers
  if (!setjmp(d.jmp_buf)) {
  ... match exception and execute catch blocks ...

  // fell off end, rethrow.
  _rethrow = _caught;
  ... jump-through-finally to finally_rethrow ...
  } else {
  // exception in catch block
  _rethrow = objc_exception_extract(&d);
  _call_try_exit = false;
  ... jump-through-finally to finally_rethrow ...
  }
  }
  ... jump-through-finally to finally_end ...

  finally:
  if (_call_try_exit)
  objc_exception_try_exit(&d);

  ... finally block ....
  ... dispatch to finally destination ...

  finally_rethrow:
  objc_exception_throw(_rethrow);

  finally_end:
  }

  This framework differs slightly from the one gcc uses, in that gcc
  uses _rethrow to determine if objc_exception_try_exit should be called
  and if the object should be rethrown. This breaks in the face of
  throwing nil and introduces unnecessary branches.

  We specialize this framework for a few particular circumstances:

  - If there are no catch blocks, then we avoid emitting the second
  exception handling context.

  - If there is a catch-all catch block (i.e. @catch(...) or @catch(id
  e)) we avoid emitting the code to rethrow an uncaught exception.

  - FIXME: If there is no @finally block we can do a few more
  simplifications.

  Rethrows and Jumps-Through-Finally
  --

  Support for implicit rethrows and jumping through the finally block is
  handled by storing the current exception-handling context in
  ObjCEHStack.

  In order to implement proper @finally semantics, we support one basic
  mechanism for jumping through the finally block to an arbitrary
  destination. Constructs which generate exits from a @try or @catch
  block use this mechanism to implement the proper semantics by chaining
  jumps, as necessary.

  This mechanism works like the one used for indirect goto: we
  arbitrarily assign an ID to each destination and store the ID for the
  destination in a variable prior to entering the finally block. At the
  end of the finally block we simply create a switch to the proper
  destination.

  Code gen for @synchronized(expr) stmt;
  Effectively generating code for:
  objc_sync_enter(expr);
  @try stmt @finally { objc_sync_exit(expr); }
*/

void CGObjCMac::EmitTryOrSynchronizedStmt(CodeGen::CodeGenFunction &CGF,
                                          const Stmt &S) {
  bool isTry = isa<ObjCAtTryStmt>(S);
  // Create various blocks we refer to for handling @finally.
  llvm::BasicBlock *FinallyBlock = CGF.createBasicBlock("finally");
  llvm::BasicBlock *FinallyExit = CGF.createBasicBlock("finally.exit");
  llvm::BasicBlock *FinallyNoExit = CGF.createBasicBlock("finally.noexit");
  llvm::BasicBlock *FinallyRethrow = CGF.createBasicBlock("finally.throw");
  llvm::BasicBlock *FinallyEnd = CGF.createBasicBlock("finally.end");

  // For @synchronized, call objc_sync_enter(sync.expr). The
  // evaluation of the expression must occur before we enter the
  // @synchronized. We can safely avoid a temp here because jumps into
  // @synchronized are illegal & this will dominate uses.
  llvm::Value *SyncArg = 0;
  if (!isTry) {
    SyncArg =
      CGF.EmitScalarExpr(cast<ObjCAtSynchronizedStmt>(S).getSynchExpr());
    SyncArg = CGF.Builder.CreateBitCast(SyncArg, ObjCTypes.ObjectPtrTy);
    CGF.Builder.CreateCall(ObjCTypes.getSyncEnterFn(), SyncArg);
  }

  // Push an EH context entry, used for handling rethrows and jumps
  // through finally.
  CGF.PushCleanupBlock(FinallyBlock);

  CGF.ObjCEHValueStack.push_back(0);

  // Allocate memory for the exception data and rethrow pointer.
  llvm::Value *ExceptionData = CGF.CreateTempAlloca(ObjCTypes.ExceptionDataTy,
                                                    "exceptiondata.ptr");
  llvm::Value *RethrowPtr = CGF.CreateTempAlloca(ObjCTypes.ObjectPtrTy,
                                                 "_rethrow");
  llvm::Value *CallTryExitPtr = CGF.CreateTempAlloca(
                                               llvm::Type::getInt1Ty(VMContext),
                                                     "_call_try_exit");
  CGF.Builder.CreateStore(llvm::ConstantInt::getTrue(VMContext),
                          CallTryExitPtr);

  // Enter a new try block and call setjmp.
  CGF.Builder.CreateCall(ObjCTypes.getExceptionTryEnterFn(), ExceptionData);
  llvm::Value *JmpBufPtr = CGF.Builder.CreateStructGEP(ExceptionData, 0,
                                                       "jmpbufarray");
  JmpBufPtr = CGF.Builder.CreateStructGEP(JmpBufPtr, 0, "tmp");
  llvm::Value *SetJmpResult = CGF.Builder.CreateCall(ObjCTypes.getSetJmpFn(),
                                                     JmpBufPtr, "result");

  llvm::BasicBlock *TryBlock = CGF.createBasicBlock("try");
  llvm::BasicBlock *TryHandler = CGF.createBasicBlock("try.handler");
  CGF.Builder.CreateCondBr(CGF.Builder.CreateIsNotNull(SetJmpResult, "threw"),
                           TryHandler, TryBlock);

  // Emit the @try block.
  CGF.EmitBlock(TryBlock);
  CGF.EmitStmt(isTry ? cast<ObjCAtTryStmt>(S).getTryBody()
               : cast<ObjCAtSynchronizedStmt>(S).getSynchBody());
  CGF.EmitBranchThroughCleanup(FinallyEnd);

  // Emit the "exception in @try" block.
  CGF.EmitBlock(TryHandler);

  // Retrieve the exception object.  We may emit multiple blocks but
  // nothing can cross this so the value is already in SSA form.
  llvm::Value *Caught =
    CGF.Builder.CreateCall(ObjCTypes.getExceptionExtractFn(),
                           ExceptionData, "caught");
  CGF.ObjCEHValueStack.back() = Caught;
  if (!isTry) {
    CGF.Builder.CreateStore(Caught, RethrowPtr);
    CGF.Builder.CreateStore(llvm::ConstantInt::getFalse(VMContext),
                            CallTryExitPtr);
    CGF.EmitBranchThroughCleanup(FinallyRethrow);
  } else if (const ObjCAtCatchStmt* CatchStmt =
             cast<ObjCAtTryStmt>(S).getCatchStmts()) {
    // Enter a new exception try block (in case a @catch block throws
    // an exception).
    CGF.Builder.CreateCall(ObjCTypes.getExceptionTryEnterFn(), ExceptionData);

    llvm::Value *SetJmpResult = CGF.Builder.CreateCall(ObjCTypes.getSetJmpFn(),
                                                       JmpBufPtr, "result");
    llvm::Value *Threw = CGF.Builder.CreateIsNotNull(SetJmpResult, "threw");

    llvm::BasicBlock *CatchBlock = CGF.createBasicBlock("catch");
    llvm::BasicBlock *CatchHandler = CGF.createBasicBlock("catch.handler");
    CGF.Builder.CreateCondBr(Threw, CatchHandler, CatchBlock);

    CGF.EmitBlock(CatchBlock);

    // Handle catch list. As a special case we check if everything is
    // matched and avoid generating code for falling off the end if
    // so.
    bool AllMatched = false;
    for (; CatchStmt; CatchStmt = CatchStmt->getNextCatchStmt()) {
      llvm::BasicBlock *NextCatchBlock = CGF.createBasicBlock("catch");

      const ParmVarDecl *CatchParam = CatchStmt->getCatchParamDecl();
      const ObjCObjectPointerType *OPT = 0;

      // catch(...) always matches.
      if (!CatchParam) {
        AllMatched = true;
      } else {
        OPT = CatchParam->getType()->getAsObjCObjectPointerType();

        // catch(id e) always matches.
        // FIXME: For the time being we also match id<X>; this should
        // be rejected by Sema instead.
        if (OPT && (OPT->isObjCIdType() || OPT->isObjCQualifiedIdType()))
          AllMatched = true;
      }

      if (AllMatched) {
        if (CatchParam) {
          CGF.EmitLocalBlockVarDecl(*CatchParam);
          assert(CGF.HaveInsertPoint() && "DeclStmt destroyed insert point?");
          CGF.Builder.CreateStore(Caught, CGF.GetAddrOfLocalVar(CatchParam));
        }

        CGF.EmitStmt(CatchStmt->getCatchBody());
        CGF.EmitBranchThroughCleanup(FinallyEnd);
        break;
      }

      assert(OPT && "Unexpected non-object pointer type in @catch");
      QualType T = OPT->getPointeeType();
      const ObjCInterfaceType *ObjCType = T->getAsObjCInterfaceType();
      assert(ObjCType && "Catch parameter must have Objective-C type!");

      // Check if the @catch block matches the exception object.
      llvm::Value *Class = EmitClassRef(CGF.Builder, ObjCType->getDecl());

      llvm::Value *Match =
        CGF.Builder.CreateCall2(ObjCTypes.getExceptionMatchFn(),
                                Class, Caught, "match");

      llvm::BasicBlock *MatchedBlock = CGF.createBasicBlock("matched");

      CGF.Builder.CreateCondBr(CGF.Builder.CreateIsNotNull(Match, "matched"),
                               MatchedBlock, NextCatchBlock);

      // Emit the @catch block.
      CGF.EmitBlock(MatchedBlock);
      CGF.EmitLocalBlockVarDecl(*CatchParam);
      assert(CGF.HaveInsertPoint() && "DeclStmt destroyed insert point?");

      llvm::Value *Tmp =
        CGF.Builder.CreateBitCast(Caught,
                                  CGF.ConvertType(CatchParam->getType()),
                                  "tmp");
      CGF.Builder.CreateStore(Tmp, CGF.GetAddrOfLocalVar(CatchParam));

      CGF.EmitStmt(CatchStmt->getCatchBody());
      CGF.EmitBranchThroughCleanup(FinallyEnd);

      CGF.EmitBlock(NextCatchBlock);
    }

    if (!AllMatched) {
      // None of the handlers caught the exception, so store it to be
      // rethrown at the end of the @finally block.
      CGF.Builder.CreateStore(Caught, RethrowPtr);
      CGF.EmitBranchThroughCleanup(FinallyRethrow);
    }

    // Emit the exception handler for the @catch blocks.
    CGF.EmitBlock(CatchHandler);
    CGF.Builder.CreateStore(
      CGF.Builder.CreateCall(ObjCTypes.getExceptionExtractFn(),
                             ExceptionData),
      RethrowPtr);
    CGF.Builder.CreateStore(llvm::ConstantInt::getFalse(VMContext),
                            CallTryExitPtr);
    CGF.EmitBranchThroughCleanup(FinallyRethrow);
  } else {
    CGF.Builder.CreateStore(Caught, RethrowPtr);
    CGF.Builder.CreateStore(llvm::ConstantInt::getFalse(VMContext),
                            CallTryExitPtr);
    CGF.EmitBranchThroughCleanup(FinallyRethrow);
  }

  // Pop the exception-handling stack entry. It is important to do
  // this now, because the code in the @finally block is not in this
  // context.
  CodeGenFunction::CleanupBlockInfo Info = CGF.PopCleanupBlock();

  CGF.ObjCEHValueStack.pop_back();

  // Emit the @finally block.
  CGF.EmitBlock(FinallyBlock);
  llvm::Value* CallTryExit = CGF.Builder.CreateLoad(CallTryExitPtr, "tmp");

  CGF.Builder.CreateCondBr(CallTryExit, FinallyExit, FinallyNoExit);

  CGF.EmitBlock(FinallyExit);
  CGF.Builder.CreateCall(ObjCTypes.getExceptionTryExitFn(), ExceptionData);

  CGF.EmitBlock(FinallyNoExit);
  if (isTry) {
    if (const ObjCAtFinallyStmt* FinallyStmt =
        cast<ObjCAtTryStmt>(S).getFinallyStmt())
      CGF.EmitStmt(FinallyStmt->getFinallyBody());
  } else {
    // Emit objc_sync_exit(expr); as finally's sole statement for
    // @synchronized.
    CGF.Builder.CreateCall(ObjCTypes.getSyncExitFn(), SyncArg);
  }

  // Emit the switch block
  if (Info.SwitchBlock)
    CGF.EmitBlock(Info.SwitchBlock);
  if (Info.EndBlock)
    CGF.EmitBlock(Info.EndBlock);

  CGF.EmitBlock(FinallyRethrow);
  CGF.Builder.CreateCall(ObjCTypes.getExceptionThrowFn(),
                         CGF.Builder.CreateLoad(RethrowPtr));
  CGF.Builder.CreateUnreachable();

  CGF.EmitBlock(FinallyEnd);
}

void CGObjCMac::EmitThrowStmt(CodeGen::CodeGenFunction &CGF,
                              const ObjCAtThrowStmt &S) {
  llvm::Value *ExceptionAsObject;

  if (const Expr *ThrowExpr = S.getThrowExpr()) {
    llvm::Value *Exception = CGF.EmitScalarExpr(ThrowExpr);
    ExceptionAsObject =
      CGF.Builder.CreateBitCast(Exception, ObjCTypes.ObjectPtrTy, "tmp");
  } else {
    assert((!CGF.ObjCEHValueStack.empty() && CGF.ObjCEHValueStack.back()) &&
           "Unexpected rethrow outside @catch block.");
    ExceptionAsObject = CGF.ObjCEHValueStack.back();
  }

  CGF.Builder.CreateCall(ObjCTypes.getExceptionThrowFn(), ExceptionAsObject);
  CGF.Builder.CreateUnreachable();

  // Clear the insertion point to indicate we are in unreachable code.
  CGF.Builder.ClearInsertionPoint();
}

/// EmitObjCWeakRead - Code gen for loading value of a __weak
/// object: objc_read_weak (id *src)
///
llvm::Value * CGObjCMac::EmitObjCWeakRead(CodeGen::CodeGenFunction &CGF,
                                          llvm::Value *AddrWeakObj)
{
  const llvm::Type* DestTy =
    cast<llvm::PointerType>(AddrWeakObj->getType())->getElementType();
  AddrWeakObj = CGF.Builder.CreateBitCast(AddrWeakObj,
                                          ObjCTypes.PtrObjectPtrTy);
  llvm::Value *read_weak = CGF.Builder.CreateCall(ObjCTypes.getGcReadWeakFn(),
                                                  AddrWeakObj, "weakread");
  read_weak = CGF.Builder.CreateBitCast(read_weak, DestTy);
  return read_weak;
}

/// EmitObjCWeakAssign - Code gen for assigning to a __weak object.
/// objc_assign_weak (id src, id *dst)
///
void CGObjCMac::EmitObjCWeakAssign(CodeGen::CodeGenFunction &CGF,
                                   llvm::Value *src, llvm::Value *dst)
{
  const llvm::Type * SrcTy = src->getType();
  if (!isa<llvm::PointerType>(SrcTy)) {
    unsigned Size = CGM.getTargetData().getTypeAllocSize(SrcTy);
    assert(Size <= 8 && "does not support size > 8");
    src = (Size == 4) ? CGF.Builder.CreateBitCast(src, ObjCTypes.IntTy)
      : CGF.Builder.CreateBitCast(src, ObjCTypes.LongLongTy);
    src = CGF.Builder.CreateIntToPtr(src, ObjCTypes.Int8PtrTy);
  }
  src = CGF.Builder.CreateBitCast(src, ObjCTypes.ObjectPtrTy);
  dst = CGF.Builder.CreateBitCast(dst, ObjCTypes.PtrObjectPtrTy);
  CGF.Builder.CreateCall2(ObjCTypes.getGcAssignWeakFn(),
                          src, dst, "weakassign");
  return;
}

/// EmitObjCGlobalAssign - Code gen for assigning to a __strong object.
/// objc_assign_global (id src, id *dst)
///
void CGObjCMac::EmitObjCGlobalAssign(CodeGen::CodeGenFunction &CGF,
                                     llvm::Value *src, llvm::Value *dst)
{
  const llvm::Type * SrcTy = src->getType();
  if (!isa<llvm::PointerType>(SrcTy)) {
    unsigned Size = CGM.getTargetData().getTypeAllocSize(SrcTy);
    assert(Size <= 8 && "does not support size > 8");
    src = (Size == 4) ? CGF.Builder.CreateBitCast(src, ObjCTypes.IntTy)
      : CGF.Builder.CreateBitCast(src, ObjCTypes.LongLongTy);
    src = CGF.Builder.CreateIntToPtr(src, ObjCTypes.Int8PtrTy);
  }
  src = CGF.Builder.CreateBitCast(src, ObjCTypes.ObjectPtrTy);
  dst = CGF.Builder.CreateBitCast(dst, ObjCTypes.PtrObjectPtrTy);
  CGF.Builder.CreateCall2(ObjCTypes.getGcAssignGlobalFn(),
                          src, dst, "globalassign");
  return;
}

/// EmitObjCIvarAssign - Code gen for assigning to a __strong object.
/// objc_assign_ivar (id src, id *dst)
///
void CGObjCMac::EmitObjCIvarAssign(CodeGen::CodeGenFunction &CGF,
                                   llvm::Value *src, llvm::Value *dst)
{
  const llvm::Type * SrcTy = src->getType();
  if (!isa<llvm::PointerType>(SrcTy)) {
    unsigned Size = CGM.getTargetData().getTypeAllocSize(SrcTy);
    assert(Size <= 8 && "does not support size > 8");
    src = (Size == 4) ? CGF.Builder.CreateBitCast(src, ObjCTypes.IntTy)
      : CGF.Builder.CreateBitCast(src, ObjCTypes.LongLongTy);
    src = CGF.Builder.CreateIntToPtr(src, ObjCTypes.Int8PtrTy);
  }
  src = CGF.Builder.CreateBitCast(src, ObjCTypes.ObjectPtrTy);
  dst = CGF.Builder.CreateBitCast(dst, ObjCTypes.PtrObjectPtrTy);
  CGF.Builder.CreateCall2(ObjCTypes.getGcAssignIvarFn(),
                          src, dst, "assignivar");
  return;
}

/// EmitObjCStrongCastAssign - Code gen for assigning to a __strong cast object.
/// objc_assign_strongCast (id src, id *dst)
///
void CGObjCMac::EmitObjCStrongCastAssign(CodeGen::CodeGenFunction &CGF,
                                         llvm::Value *src, llvm::Value *dst)
{
  const llvm::Type * SrcTy = src->getType();
  if (!isa<llvm::PointerType>(SrcTy)) {
    unsigned Size = CGM.getTargetData().getTypeAllocSize(SrcTy);
    assert(Size <= 8 && "does not support size > 8");
    src = (Size == 4) ? CGF.Builder.CreateBitCast(src, ObjCTypes.IntTy)
      : CGF.Builder.CreateBitCast(src, ObjCTypes.LongLongTy);
    src = CGF.Builder.CreateIntToPtr(src, ObjCTypes.Int8PtrTy);
  }
  src = CGF.Builder.CreateBitCast(src, ObjCTypes.ObjectPtrTy);
  dst = CGF.Builder.CreateBitCast(dst, ObjCTypes.PtrObjectPtrTy);
  CGF.Builder.CreateCall2(ObjCTypes.getGcAssignStrongCastFn(),
                          src, dst, "weakassign");
  return;
}

void CGObjCMac::EmitGCMemmoveCollectable(CodeGen::CodeGenFunction &CGF,
                                         llvm::Value *DestPtr,
                                         llvm::Value *SrcPtr,
                                         unsigned long size) {
  SrcPtr = CGF.Builder.CreateBitCast(SrcPtr, ObjCTypes.Int8PtrTy);
  DestPtr = CGF.Builder.CreateBitCast(DestPtr, ObjCTypes.Int8PtrTy);
  llvm::Value *N = llvm::ConstantInt::get(ObjCTypes.LongTy, size);
  CGF.Builder.CreateCall3(ObjCTypes.GcMemmoveCollectableFn(),
                          DestPtr, SrcPtr, N);
  return;
}

/// EmitObjCValueForIvar - Code Gen for ivar reference.
///
LValue CGObjCMac::EmitObjCValueForIvar(CodeGen::CodeGenFunction &CGF,
                                       QualType ObjectTy,
                                       llvm::Value *BaseValue,
                                       const ObjCIvarDecl *Ivar,
                                       unsigned CVRQualifiers) {
  const ObjCInterfaceDecl *ID = ObjectTy->getAsObjCInterfaceType()->getDecl();
  return EmitValueForIvarAtOffset(CGF, ID, BaseValue, Ivar, CVRQualifiers,
                                  EmitIvarOffset(CGF, ID, Ivar));
}

llvm::Value *CGObjCMac::EmitIvarOffset(CodeGen::CodeGenFunction &CGF,
                                       const ObjCInterfaceDecl *Interface,
                                       const ObjCIvarDecl *Ivar) {
  uint64_t Offset = ComputeIvarBaseOffset(CGM, Interface, Ivar);
  return llvm::ConstantInt::get(
    CGM.getTypes().ConvertType(CGM.getContext().LongTy),
    Offset);
}

/* *** Private Interface *** */

/// EmitImageInfo - Emit the image info marker used to encode some module
/// level information.
///
/// See: <rdr://4810609&4810587&4810587>
/// struct IMAGE_INFO {
///   unsigned version;
///   unsigned flags;
/// };
enum ImageInfoFlags {
  eImageInfo_FixAndContinue      = (1 << 0), // FIXME: Not sure what
                                             // this implies.
  eImageInfo_GarbageCollected    = (1 << 1),
  eImageInfo_GCOnly              = (1 << 2),
  eImageInfo_OptimizedByDyld     = (1 << 3), // FIXME: When is this set.

  // A flag indicating that the module has no instances of an
  // @synthesize of a superclass variable. <rdar://problem/6803242>
  eImageInfo_CorrectedSynthesize = (1 << 4)
};

void CGObjCMac::EmitImageInfo() {
  unsigned version = 0; // Version is unused?
  unsigned flags = 0;

  // FIXME: Fix and continue?
  if (CGM.getLangOptions().getGCMode() != LangOptions::NonGC)
    flags |= eImageInfo_GarbageCollected;
  if (CGM.getLangOptions().getGCMode() == LangOptions::GCOnly)
    flags |= eImageInfo_GCOnly;

  // We never allow @synthesize of a superclass property.
  flags |= eImageInfo_CorrectedSynthesize;

  // Emitted as int[2];
  llvm::Constant *values[2] = {
    llvm::ConstantInt::get(llvm::Type::getInt32Ty(VMContext), version),
    llvm::ConstantInt::get(llvm::Type::getInt32Ty(VMContext), flags)
  };
  llvm::ArrayType *AT = llvm::ArrayType::get(llvm::Type::getInt32Ty(VMContext), 2);

  const char *Section;
  if (ObjCABI == 1)
    Section = "__OBJC, __image_info,regular";
  else
    Section = "__DATA, __objc_imageinfo, regular, no_dead_strip";
  llvm::GlobalVariable *GV =
    CreateMetadataVar("\01L_OBJC_IMAGE_INFO",
                      llvm::ConstantArray::get(AT, values, 2),
                      Section,
                      0,
                      true);
  GV->setConstant(true);
}


// struct objc_module {
//   unsigned long version;
//   unsigned long size;
//   const char *name;
//   Symtab symtab;
// };

// FIXME: Get from somewhere
static const int ModuleVersion = 7;

void CGObjCMac::EmitModuleInfo() {
  uint64_t Size = CGM.getTargetData().getTypeAllocSize(ObjCTypes.ModuleTy);

  std::vector<llvm::Constant*> Values(4);
  Values[0] = llvm::ConstantInt::get(ObjCTypes.LongTy, ModuleVersion);
  Values[1] = llvm::ConstantInt::get(ObjCTypes.LongTy, Size);
  // This used to be the filename, now it is unused. <rdr://4327263>
  Values[2] = GetClassName(&CGM.getContext().Idents.get(""));
  Values[3] = EmitModuleSymbols();
  CreateMetadataVar("\01L_OBJC_MODULES",
                    llvm::ConstantStruct::get(ObjCTypes.ModuleTy, Values),
                    "__OBJC,__module_info,regular,no_dead_strip",
                    4, true);
}

llvm::Constant *CGObjCMac::EmitModuleSymbols() {
  unsigned NumClasses = DefinedClasses.size();
  unsigned NumCategories = DefinedCategories.size();

  // Return null if no symbols were defined.
  if (!NumClasses && !NumCategories)
    return llvm::Constant::getNullValue(ObjCTypes.SymtabPtrTy);

  std::vector<llvm::Constant*> Values(5);
  Values[0] = llvm::ConstantInt::get(ObjCTypes.LongTy, 0);
  Values[1] = llvm::Constant::getNullValue(ObjCTypes.SelectorPtrTy);
  Values[2] = llvm::ConstantInt::get(ObjCTypes.ShortTy, NumClasses);
  Values[3] = llvm::ConstantInt::get(ObjCTypes.ShortTy, NumCategories);

  // The runtime expects exactly the list of defined classes followed
  // by the list of defined categories, in a single array.
  std::vector<llvm::Constant*> Symbols(NumClasses + NumCategories);
  for (unsigned i=0; i<NumClasses; i++)
    Symbols[i] = llvm::ConstantExpr::getBitCast(DefinedClasses[i],
                                                ObjCTypes.Int8PtrTy);
  for (unsigned i=0; i<NumCategories; i++)
    Symbols[NumClasses + i] =
      llvm::ConstantExpr::getBitCast(DefinedCategories[i],
                                     ObjCTypes.Int8PtrTy);

  Values[4] =
    llvm::ConstantArray::get(llvm::ArrayType::get(ObjCTypes.Int8PtrTy,
                                                  NumClasses + NumCategories),
                             Symbols);

  llvm::Constant *Init = llvm::ConstantStruct::get(VMContext, Values);

  llvm::GlobalVariable *GV =
    CreateMetadataVar("\01L_OBJC_SYMBOLS", Init,
                      "__OBJC,__symbols,regular,no_dead_strip",
                      4, true);
  return llvm::ConstantExpr::getBitCast(GV, ObjCTypes.SymtabPtrTy);
}

llvm::Value *CGObjCMac::EmitClassRef(CGBuilderTy &Builder,
                                     const ObjCInterfaceDecl *ID) {
  LazySymbols.insert(ID->getIdentifier());

  llvm::GlobalVariable *&Entry = ClassReferences[ID->getIdentifier()];

  if (!Entry) {
    llvm::Constant *Casted =
      llvm::ConstantExpr::getBitCast(GetClassName(ID->getIdentifier()),
                                     ObjCTypes.ClassPtrTy);
    Entry =
      CreateMetadataVar("\01L_OBJC_CLASS_REFERENCES_", Casted,
                        "__OBJC,__cls_refs,literal_pointers,no_dead_strip",
                        4, true);
  }

  return Builder.CreateLoad(Entry, false, "tmp");
}

llvm::Value *CGObjCMac::EmitSelector(CGBuilderTy &Builder, Selector Sel) {
  llvm::GlobalVariable *&Entry = SelectorReferences[Sel];

  if (!Entry) {
    llvm::Constant *Casted =
      llvm::ConstantExpr::getBitCast(GetMethodVarName(Sel),
                                     ObjCTypes.SelectorPtrTy);
    Entry =
      CreateMetadataVar("\01L_OBJC_SELECTOR_REFERENCES_", Casted,
                        "__OBJC,__message_refs,literal_pointers,no_dead_strip",
                        4, true);
  }

  return Builder.CreateLoad(Entry, false, "tmp");
}

llvm::Constant *CGObjCCommonMac::GetClassName(IdentifierInfo *Ident) {
  llvm::GlobalVariable *&Entry = ClassNames[Ident];

  if (!Entry)
    Entry = CreateMetadataVar("\01L_OBJC_CLASS_NAME_",
                          llvm::ConstantArray::get(VMContext, Ident->getName()),
                              "__TEXT,__cstring,cstring_literals",
                              1, true);

  return getConstantGEP(VMContext, Entry, 0, 0);
}

/// GetIvarLayoutName - Returns a unique constant for the given
/// ivar layout bitmap.
llvm::Constant *CGObjCCommonMac::GetIvarLayoutName(IdentifierInfo *Ident,
                                       const ObjCCommonTypesHelper &ObjCTypes) {
  return llvm::Constant::getNullValue(ObjCTypes.Int8PtrTy);
}

static QualType::GCAttrTypes GetGCAttrTypeForType(ASTContext &Ctx,
                                                  QualType FQT) {
  if (FQT.isObjCGCStrong())
    return QualType::Strong;

  if (FQT.isObjCGCWeak())
    return QualType::Weak;

  if (FQT->isObjCObjectPointerType())
    return QualType::Strong;

  if (const PointerType *PT = FQT->getAs<PointerType>())
    return GetGCAttrTypeForType(Ctx, PT->getPointeeType());

  return QualType::GCNone;
}

void CGObjCCommonMac::BuildAggrIvarRecordLayout(const RecordType *RT,
                                                unsigned int BytePos,
                                                bool ForStrongLayout,
                                                bool &HasUnion) {
  const RecordDecl *RD = RT->getDecl();
  // FIXME - Use iterator.
  llvm::SmallVector<FieldDecl*, 16> Fields(RD->field_begin(), RD->field_end());
  const llvm::Type *Ty = CGM.getTypes().ConvertType(QualType(RT, 0));
  const llvm::StructLayout *RecLayout =
    CGM.getTargetData().getStructLayout(cast<llvm::StructType>(Ty));

  BuildAggrIvarLayout(0, RecLayout, RD, Fields, BytePos,
                      ForStrongLayout, HasUnion);
}

void CGObjCCommonMac::BuildAggrIvarLayout(const ObjCImplementationDecl *OI,
                             const llvm::StructLayout *Layout,
                             const RecordDecl *RD,
                             const llvm::SmallVectorImpl<FieldDecl*> &RecFields,
                             unsigned int BytePos, bool ForStrongLayout,
                             bool &HasUnion) {
  bool IsUnion = (RD && RD->isUnion());
  uint64_t MaxUnionIvarSize = 0;
  uint64_t MaxSkippedUnionIvarSize = 0;
  FieldDecl *MaxField = 0;
  FieldDecl *MaxSkippedField = 0;
  FieldDecl *LastFieldBitfield = 0;
  uint64_t MaxFieldOffset = 0;
  uint64_t MaxSkippedFieldOffset = 0;
  uint64_t LastBitfieldOffset = 0;

  if (RecFields.empty())
    return;
  unsigned WordSizeInBits = CGM.getContext().Target.getPointerWidth(0);
  unsigned ByteSizeInBits = CGM.getContext().Target.getCharWidth();

  for (unsigned i = 0, e = RecFields.size(); i != e; ++i) {
    FieldDecl *Field = RecFields[i];
    uint64_t FieldOffset;
    if (RD) {
      if (Field->isBitField()) {
        CodeGenTypes::BitFieldInfo Info = CGM.getTypes().getBitFieldInfo(Field);
        FieldOffset = Layout->getElementOffset(Info.FieldNo);
      } else
        FieldOffset =
          Layout->getElementOffset(CGM.getTypes().getLLVMFieldNo(Field));
    } else
      FieldOffset = ComputeIvarBaseOffset(CGM, OI, cast<ObjCIvarDecl>(Field));

    // Skip over unnamed or bitfields
    if (!Field->getIdentifier() || Field->isBitField()) {
      LastFieldBitfield = Field;
      LastBitfieldOffset = FieldOffset;
      continue;
    }

    LastFieldBitfield = 0;
    QualType FQT = Field->getType();
    if (FQT->isRecordType() || FQT->isUnionType()) {
      if (FQT->isUnionType())
        HasUnion = true;

      BuildAggrIvarRecordLayout(FQT->getAs<RecordType>(),
                                BytePos + FieldOffset,
                                ForStrongLayout, HasUnion);
      continue;
    }

    if (const ArrayType *Array = CGM.getContext().getAsArrayType(FQT)) {
      const ConstantArrayType *CArray =
        dyn_cast_or_null<ConstantArrayType>(Array);
      uint64_t ElCount = CArray->getSize().getZExtValue();
      assert(CArray && "only array with known element size is supported");
      FQT = CArray->getElementType();
      while (const ArrayType *Array = CGM.getContext().getAsArrayType(FQT)) {
        const ConstantArrayType *CArray =
          dyn_cast_or_null<ConstantArrayType>(Array);
        ElCount *= CArray->getSize().getZExtValue();
        FQT = CArray->getElementType();
      }

      assert(!FQT->isUnionType() &&
             "layout for array of unions not supported");
      if (FQT->isRecordType()) {
        int OldIndex = IvarsInfo.size() - 1;
        int OldSkIndex = SkipIvars.size() -1;

        const RecordType *RT = FQT->getAs<RecordType>();
        BuildAggrIvarRecordLayout(RT, BytePos + FieldOffset,
                                  ForStrongLayout, HasUnion);

        // Replicate layout information for each array element. Note that
        // one element is already done.
        uint64_t ElIx = 1;
        for (int FirstIndex = IvarsInfo.size() - 1,
               FirstSkIndex = SkipIvars.size() - 1 ;ElIx < ElCount; ElIx++) {
          uint64_t Size = CGM.getContext().getTypeSize(RT)/ByteSizeInBits;
          for (int i = OldIndex+1; i <= FirstIndex; ++i)
            IvarsInfo.push_back(GC_IVAR(IvarsInfo[i].ivar_bytepos + Size*ElIx,
                                        IvarsInfo[i].ivar_size));
          for (int i = OldSkIndex+1; i <= FirstSkIndex; ++i)
            SkipIvars.push_back(GC_IVAR(SkipIvars[i].ivar_bytepos + Size*ElIx,
                                        SkipIvars[i].ivar_size));
        }
        continue;
      }
    }
    // At this point, we are done with Record/Union and array there of.
    // For other arrays we are down to its element type.
    QualType::GCAttrTypes GCAttr = GetGCAttrTypeForType(CGM.getContext(), FQT);

    unsigned FieldSize = CGM.getContext().getTypeSize(Field->getType());
    if ((ForStrongLayout && GCAttr == QualType::Strong)
        || (!ForStrongLayout && GCAttr == QualType::Weak)) {
      if (IsUnion) {
        uint64_t UnionIvarSize = FieldSize / WordSizeInBits;
        if (UnionIvarSize > MaxUnionIvarSize) {
          MaxUnionIvarSize = UnionIvarSize;
          MaxField = Field;
          MaxFieldOffset = FieldOffset;
        }
      } else {
        IvarsInfo.push_back(GC_IVAR(BytePos + FieldOffset,
                                    FieldSize / WordSizeInBits));
      }
    } else if ((ForStrongLayout &&
                (GCAttr == QualType::GCNone || GCAttr == QualType::Weak))
               || (!ForStrongLayout && GCAttr != QualType::Weak)) {
      if (IsUnion) {
        // FIXME: Why the asymmetry? We divide by word size in bits on other
        // side.
        uint64_t UnionIvarSize = FieldSize;
        if (UnionIvarSize > MaxSkippedUnionIvarSize) {
          MaxSkippedUnionIvarSize = UnionIvarSize;
          MaxSkippedField = Field;
          MaxSkippedFieldOffset = FieldOffset;
        }
      } else {
        // FIXME: Why the asymmetry, we divide by byte size in bits here?
        SkipIvars.push_back(GC_IVAR(BytePos + FieldOffset,
                                    FieldSize / ByteSizeInBits));
      }
    }
  }

  if (LastFieldBitfield) {
    // Last field was a bitfield. Must update skip info.
    Expr *BitWidth = LastFieldBitfield->getBitWidth();
    uint64_t BitFieldSize =
      BitWidth->EvaluateAsInt(CGM.getContext()).getZExtValue();
    GC_IVAR skivar;
    skivar.ivar_bytepos = BytePos + LastBitfieldOffset;
    skivar.ivar_size = (BitFieldSize / ByteSizeInBits)
      + ((BitFieldSize % ByteSizeInBits) != 0);
    SkipIvars.push_back(skivar);
  }

  if (MaxField)
    IvarsInfo.push_back(GC_IVAR(BytePos + MaxFieldOffset,
                                MaxUnionIvarSize));
  if (MaxSkippedField)
    SkipIvars.push_back(GC_IVAR(BytePos + MaxSkippedFieldOffset,
                                MaxSkippedUnionIvarSize));
}

/// BuildIvarLayout - Builds ivar layout bitmap for the class
/// implementation for the __strong or __weak case.
/// The layout map displays which words in ivar list must be skipped
/// and which must be scanned by GC (see below). String is built of bytes.
/// Each byte is divided up in two nibbles (4-bit each). Left nibble is count
/// of words to skip and right nibble is count of words to scan. So, each
/// nibble represents up to 15 workds to skip or scan. Skipping the rest is
/// represented by a 0x00 byte which also ends the string.
/// 1. when ForStrongLayout is true, following ivars are scanned:
/// - id, Class
/// - object *
/// - __strong anything
///
/// 2. When ForStrongLayout is false, following ivars are scanned:
/// - __weak anything
///
llvm::Constant *CGObjCCommonMac::BuildIvarLayout(
  const ObjCImplementationDecl *OMD,
  bool ForStrongLayout) {
  bool hasUnion = false;

  unsigned int WordsToScan, WordsToSkip;
  const llvm::Type *PtrTy = llvm::PointerType::getUnqual(llvm::Type::getInt8Ty(VMContext));
  if (CGM.getLangOptions().getGCMode() == LangOptions::NonGC)
    return llvm::Constant::getNullValue(PtrTy);

  llvm::SmallVector<FieldDecl*, 32> RecFields;
  const ObjCInterfaceDecl *OI = OMD->getClassInterface();
  CGM.getContext().CollectObjCIvars(OI, RecFields);

  // Add this implementations synthesized ivars.
  llvm::SmallVector<ObjCIvarDecl*, 16> Ivars;
  CGM.getContext().CollectSynthesizedIvars(OI, Ivars);
  for (unsigned k = 0, e = Ivars.size(); k != e; ++k)
    RecFields.push_back(cast<FieldDecl>(Ivars[k]));

  if (RecFields.empty())
    return llvm::Constant::getNullValue(PtrTy);

  SkipIvars.clear();
  IvarsInfo.clear();

  BuildAggrIvarLayout(OMD, 0, 0, RecFields, 0, ForStrongLayout, hasUnion);
  if (IvarsInfo.empty())
    return llvm::Constant::getNullValue(PtrTy);

  // Sort on byte position in case we encounterred a union nested in
  // the ivar list.
  if (hasUnion && !IvarsInfo.empty())
    std::sort(IvarsInfo.begin(), IvarsInfo.end());
  if (hasUnion && !SkipIvars.empty())
    std::sort(SkipIvars.begin(), SkipIvars.end());

  // Build the string of skip/scan nibbles
  llvm::SmallVector<SKIP_SCAN, 32> SkipScanIvars;
  unsigned int WordSize =
    CGM.getTypes().getTargetData().getTypeAllocSize(PtrTy);
  if (IvarsInfo[0].ivar_bytepos == 0) {
    WordsToSkip = 0;
    WordsToScan = IvarsInfo[0].ivar_size;
  } else {
    WordsToSkip = IvarsInfo[0].ivar_bytepos/WordSize;
    WordsToScan = IvarsInfo[0].ivar_size;
  }
  for (unsigned int i=1, Last=IvarsInfo.size(); i != Last; i++) {
    unsigned int TailPrevGCObjC =
      IvarsInfo[i-1].ivar_bytepos + IvarsInfo[i-1].ivar_size * WordSize;
    if (IvarsInfo[i].ivar_bytepos == TailPrevGCObjC) {
      // consecutive 'scanned' object pointers.
      WordsToScan += IvarsInfo[i].ivar_size;
    } else {
      // Skip over 'gc'able object pointer which lay over each other.
      if (TailPrevGCObjC > IvarsInfo[i].ivar_bytepos)
        continue;
      // Must skip over 1 or more words. We save current skip/scan values
      //  and start a new pair.
      SKIP_SCAN SkScan;
      SkScan.skip = WordsToSkip;
      SkScan.scan = WordsToScan;
      SkipScanIvars.push_back(SkScan);

      // Skip the hole.
      SkScan.skip = (IvarsInfo[i].ivar_bytepos - TailPrevGCObjC) / WordSize;
      SkScan.scan = 0;
      SkipScanIvars.push_back(SkScan);
      WordsToSkip = 0;
      WordsToScan = IvarsInfo[i].ivar_size;
    }
  }
  if (WordsToScan > 0) {
    SKIP_SCAN SkScan;
    SkScan.skip = WordsToSkip;
    SkScan.scan = WordsToScan;
    SkipScanIvars.push_back(SkScan);
  }

  bool BytesSkipped = false;
  if (!SkipIvars.empty()) {
    unsigned int LastIndex = SkipIvars.size()-1;
    int LastByteSkipped =
      SkipIvars[LastIndex].ivar_bytepos + SkipIvars[LastIndex].ivar_size;
    LastIndex = IvarsInfo.size()-1;
    int LastByteScanned =
      IvarsInfo[LastIndex].ivar_bytepos +
      IvarsInfo[LastIndex].ivar_size * WordSize;
    BytesSkipped = (LastByteSkipped > LastByteScanned);
    // Compute number of bytes to skip at the tail end of the last ivar scanned.
    if (BytesSkipped) {
      unsigned int TotalWords = (LastByteSkipped + (WordSize -1)) / WordSize;
      SKIP_SCAN SkScan;
      SkScan.skip = TotalWords - (LastByteScanned/WordSize);
      SkScan.scan = 0;
      SkipScanIvars.push_back(SkScan);
    }
  }
  // Mini optimization of nibbles such that an 0xM0 followed by 0x0N is produced
  // as 0xMN.
  int SkipScan = SkipScanIvars.size()-1;
  for (int i = 0; i <= SkipScan; i++) {
    if ((i < SkipScan) && SkipScanIvars[i].skip && SkipScanIvars[i].scan == 0
        && SkipScanIvars[i+1].skip == 0 && SkipScanIvars[i+1].scan) {
      // 0xM0 followed by 0x0N detected.
      SkipScanIvars[i].scan = SkipScanIvars[i+1].scan;
      for (int j = i+1; j < SkipScan; j++)
        SkipScanIvars[j] = SkipScanIvars[j+1];
      --SkipScan;
    }
  }

  // Generate the string.
  std::string BitMap;
  for (int i = 0; i <= SkipScan; i++) {
    unsigned char byte;
    unsigned int skip_small = SkipScanIvars[i].skip % 0xf;
    unsigned int scan_small = SkipScanIvars[i].scan % 0xf;
    unsigned int skip_big  = SkipScanIvars[i].skip / 0xf;
    unsigned int scan_big  = SkipScanIvars[i].scan / 0xf;

    if (skip_small > 0 || skip_big > 0)
      BytesSkipped = true;
    // first skip big.
    for (unsigned int ix = 0; ix < skip_big; ix++)
      BitMap += (unsigned char)(0xf0);

    // next (skip small, scan)
    if (skip_small) {
      byte = skip_small << 4;
      if (scan_big > 0) {
        byte |= 0xf;
        --scan_big;
      } else if (scan_small) {
        byte |= scan_small;
        scan_small = 0;
      }
      BitMap += byte;
    }
    // next scan big
    for (unsigned int ix = 0; ix < scan_big; ix++)
      BitMap += (unsigned char)(0x0f);
    // last scan small
    if (scan_small) {
      byte = scan_small;
      BitMap += byte;
    }
  }
  // null terminate string.
  unsigned char zero = 0;
  BitMap += zero;

  if (CGM.getLangOptions().ObjCGCBitmapPrint) {
    printf("\n%s ivar layout for class '%s': ",
           ForStrongLayout ? "strong" : "weak",
           OMD->getClassInterface()->getNameAsCString());
    const unsigned char *s = (unsigned char*)BitMap.c_str();
    for (unsigned i = 0; i < BitMap.size(); i++)
      if (!(s[i] & 0xf0))
        printf("0x0%x%s", s[i], s[i] != 0 ? ", " : "");
      else
        printf("0x%x%s",  s[i], s[i] != 0 ? ", " : "");
    printf("\n");
  }

  // if ivar_layout bitmap is all 1 bits (nothing skipped) then use NULL as
  // final layout.
  if (ForStrongLayout && !BytesSkipped)
    return llvm::Constant::getNullValue(PtrTy);
  llvm::GlobalVariable * Entry =
    CreateMetadataVar("\01L_OBJC_CLASS_NAME_",
                      llvm::ConstantArray::get(VMContext, BitMap.c_str()),
                      "__TEXT,__cstring,cstring_literals",
                      1, true);
  return getConstantGEP(VMContext, Entry, 0, 0);
}

llvm::Constant *CGObjCCommonMac::GetMethodVarName(Selector Sel) {
  llvm::GlobalVariable *&Entry = MethodVarNames[Sel];

  // FIXME: Avoid std::string copying.
  if (!Entry)
    Entry = CreateMetadataVar("\01L_OBJC_METH_VAR_NAME_",
                        llvm::ConstantArray::get(VMContext, Sel.getAsString()),
                              "__TEXT,__cstring,cstring_literals",
                              1, true);

  return getConstantGEP(VMContext, Entry, 0, 0);
}

// FIXME: Merge into a single cstring creation function.
llvm::Constant *CGObjCCommonMac::GetMethodVarName(IdentifierInfo *ID) {
  return GetMethodVarName(CGM.getContext().Selectors.getNullarySelector(ID));
}

// FIXME: Merge into a single cstring creation function.
llvm::Constant *CGObjCCommonMac::GetMethodVarName(const std::string &Name) {
  return GetMethodVarName(&CGM.getContext().Idents.get(Name));
}

llvm::Constant *CGObjCCommonMac::GetMethodVarType(const FieldDecl *Field) {
  std::string TypeStr;
  CGM.getContext().getObjCEncodingForType(Field->getType(), TypeStr, Field);

  llvm::GlobalVariable *&Entry = MethodVarTypes[TypeStr];

  if (!Entry)
    Entry = CreateMetadataVar("\01L_OBJC_METH_VAR_TYPE_",
                              llvm::ConstantArray::get(VMContext, TypeStr),
                              "__TEXT,__cstring,cstring_literals",
                              1, true);

  return getConstantGEP(VMContext, Entry, 0, 0);
}

llvm::Constant *CGObjCCommonMac::GetMethodVarType(const ObjCMethodDecl *D) {
  std::string TypeStr;
  CGM.getContext().getObjCEncodingForMethodDecl(const_cast<ObjCMethodDecl*>(D),
                                                TypeStr);

  llvm::GlobalVariable *&Entry = MethodVarTypes[TypeStr];

  if (!Entry)
    Entry = CreateMetadataVar("\01L_OBJC_METH_VAR_TYPE_",
                              llvm::ConstantArray::get(VMContext, TypeStr),
                              "__TEXT,__cstring,cstring_literals",
                              1, true);

  return getConstantGEP(VMContext, Entry, 0, 0);
}

// FIXME: Merge into a single cstring creation function.
llvm::Constant *CGObjCCommonMac::GetPropertyName(IdentifierInfo *Ident) {
  llvm::GlobalVariable *&Entry = PropertyNames[Ident];

  if (!Entry)
    Entry = CreateMetadataVar("\01L_OBJC_PROP_NAME_ATTR_",
                          llvm::ConstantArray::get(VMContext, Ident->getName()),
                              "__TEXT,__cstring,cstring_literals",
                              1, true);

  return getConstantGEP(VMContext, Entry, 0, 0);
}

// FIXME: Merge into a single cstring creation function.
// FIXME: This Decl should be more precise.
llvm::Constant *
CGObjCCommonMac::GetPropertyTypeString(const ObjCPropertyDecl *PD,
                                       const Decl *Container) {
  std::string TypeStr;
  CGM.getContext().getObjCEncodingForPropertyDecl(PD, Container, TypeStr);
  return GetPropertyName(&CGM.getContext().Idents.get(TypeStr));
}

void CGObjCCommonMac::GetNameForMethod(const ObjCMethodDecl *D,
                                       const ObjCContainerDecl *CD,
                                       std::string &NameOut) {
  NameOut = '\01';
  NameOut += (D->isInstanceMethod() ? '-' : '+');
  NameOut += '[';
  assert (CD && "Missing container decl in GetNameForMethod");
  NameOut += CD->getNameAsString();
  if (const ObjCCategoryImplDecl *CID =
      dyn_cast<ObjCCategoryImplDecl>(D->getDeclContext())) {
    NameOut += '(';
    NameOut += CID->getNameAsString();
    NameOut+= ')';
  }
  NameOut += ' ';
  NameOut += D->getSelector().getAsString();
  NameOut += ']';
}

void CGObjCMac::FinishModule() {
  EmitModuleInfo();

  // Emit the dummy bodies for any protocols which were referenced but
  // never defined.
  for (llvm::DenseMap<IdentifierInfo*, llvm::GlobalVariable*>::iterator
         I = Protocols.begin(), e = Protocols.end(); I != e; ++I) {
    if (I->second->hasInitializer())
      continue;

    std::vector<llvm::Constant*> Values(5);
    Values[0] = llvm::Constant::getNullValue(ObjCTypes.ProtocolExtensionPtrTy);
    Values[1] = GetClassName(I->first);
    Values[2] = llvm::Constant::getNullValue(ObjCTypes.ProtocolListPtrTy);
    Values[3] = Values[4] =
      llvm::Constant::getNullValue(ObjCTypes.MethodDescriptionListPtrTy);
    I->second->setLinkage(llvm::GlobalValue::InternalLinkage);
    I->second->setInitializer(llvm::ConstantStruct::get(ObjCTypes.ProtocolTy,
                                                        Values));
    CGM.AddUsedGlobal(I->second);
  }

  // Add assembler directives to add lazy undefined symbol references
  // for classes which are referenced but not defined. This is
  // important for correct linker interaction.

  // FIXME: Uh, this isn't particularly portable.
  std::stringstream s;

  if (!CGM.getModule().getModuleInlineAsm().empty())
    s << "\n";

  // FIXME: This produces non-determinstic output.
  for (std::set<IdentifierInfo*>::iterator I = LazySymbols.begin(),
         e = LazySymbols.end(); I != e; ++I) {
    s << "\t.lazy_reference .objc_class_name_" << (*I)->getName() << "\n";
  }
  for (std::set<IdentifierInfo*>::iterator I = DefinedSymbols.begin(),
         e = DefinedSymbols.end(); I != e; ++I) {
    s << "\t.objc_class_name_" << (*I)->getName() << "=0\n"
      << "\t.globl .objc_class_name_" << (*I)->getName() << "\n";
  }

  CGM.getModule().appendModuleInlineAsm(s.str());
}

CGObjCNonFragileABIMac::CGObjCNonFragileABIMac(CodeGen::CodeGenModule &cgm)
  : CGObjCCommonMac(cgm),
    ObjCTypes(cgm)
{
  ObjCEmptyCacheVar = ObjCEmptyVtableVar = NULL;
  ObjCABI = 2;
}

/* *** */

ObjCCommonTypesHelper::ObjCCommonTypesHelper(CodeGen::CodeGenModule &cgm)
  : VMContext(cgm.getLLVMContext()), CGM(cgm)
{
  CodeGen::CodeGenTypes &Types = CGM.getTypes();
  ASTContext &Ctx = CGM.getContext();

  ShortTy = Types.ConvertType(Ctx.ShortTy);
  IntTy = Types.ConvertType(Ctx.IntTy);
  LongTy = Types.ConvertType(Ctx.LongTy);
  LongLongTy = Types.ConvertType(Ctx.LongLongTy);
  Int8PtrTy = llvm::PointerType::getUnqual(llvm::Type::getInt8Ty(VMContext));

  ObjectPtrTy = Types.ConvertType(Ctx.getObjCIdType());
  PtrObjectPtrTy = llvm::PointerType::getUnqual(ObjectPtrTy);
  SelectorPtrTy = Types.ConvertType(Ctx.getObjCSelType());

  // FIXME: It would be nice to unify this with the opaque type, so that the IR
  // comes out a bit cleaner.
  const llvm::Type *T = Types.ConvertType(Ctx.getObjCProtoType());
  ExternalProtocolPtrTy = llvm::PointerType::getUnqual(T);

  // I'm not sure I like this. The implicit coordination is a bit
  // gross. We should solve this in a reasonable fashion because this
  // is a pretty common task (match some runtime data structure with
  // an LLVM data structure).

  // FIXME: This is leaked.
  // FIXME: Merge with rewriter code?

  // struct _objc_super {
  //   id self;
  //   Class cls;
  // }
  RecordDecl *RD = RecordDecl::Create(Ctx, TagDecl::TK_struct, 0,
                                      SourceLocation(),
                                      &Ctx.Idents.get("_objc_super"));
  RD->addDecl(FieldDecl::Create(Ctx, RD, SourceLocation(), 0,
                                Ctx.getObjCIdType(), 0, 0, false));
  RD->addDecl(FieldDecl::Create(Ctx, RD, SourceLocation(), 0,
                                Ctx.getObjCClassType(), 0, 0, false));
  RD->completeDefinition(Ctx);

  SuperCTy = Ctx.getTagDeclType(RD);
  SuperPtrCTy = Ctx.getPointerType(SuperCTy);

  SuperTy = cast<llvm::StructType>(Types.ConvertType(SuperCTy));
  SuperPtrTy = llvm::PointerType::getUnqual(SuperTy);

  // struct _prop_t {
  //   char *name;
  //   char *attributes;
  // }
  PropertyTy = llvm::StructType::get(VMContext, Int8PtrTy, Int8PtrTy, NULL);
  CGM.getModule().addTypeName("struct._prop_t",
                              PropertyTy);

  // struct _prop_list_t {
  //   uint32_t entsize;      // sizeof(struct _prop_t)
  //   uint32_t count_of_properties;
  //   struct _prop_t prop_list[count_of_properties];
  // }
  PropertyListTy = llvm::StructType::get(VMContext, IntTy,
                                         IntTy,
                                         llvm::ArrayType::get(PropertyTy, 0),
                                         NULL);
  CGM.getModule().addTypeName("struct._prop_list_t",
                              PropertyListTy);
  // struct _prop_list_t *
  PropertyListPtrTy = llvm::PointerType::getUnqual(PropertyListTy);

  // struct _objc_method {
  //   SEL _cmd;
  //   char *method_type;
  //   char *_imp;
  // }
  MethodTy = llvm::StructType::get(VMContext, SelectorPtrTy,
                                   Int8PtrTy,
                                   Int8PtrTy,
                                   NULL);
  CGM.getModule().addTypeName("struct._objc_method", MethodTy);

  // struct _objc_cache *
  CacheTy = llvm::OpaqueType::get(VMContext);
  CGM.getModule().addTypeName("struct._objc_cache", CacheTy);
  CachePtrTy = llvm::PointerType::getUnqual(CacheTy);
}

ObjCTypesHelper::ObjCTypesHelper(CodeGen::CodeGenModule &cgm)
  : ObjCCommonTypesHelper(cgm)
{
  // struct _objc_method_description {
  //   SEL name;
  //   char *types;
  // }
  MethodDescriptionTy =
    llvm::StructType::get(VMContext, SelectorPtrTy,
                          Int8PtrTy,
                          NULL);
  CGM.getModule().addTypeName("struct._objc_method_description",
                              MethodDescriptionTy);

  // struct _objc_method_description_list {
  //   int count;
  //   struct _objc_method_description[1];
  // }
  MethodDescriptionListTy =
    llvm::StructType::get(VMContext, IntTy,
                          llvm::ArrayType::get(MethodDescriptionTy, 0),
                          NULL);
  CGM.getModule().addTypeName("struct._objc_method_description_list",
                              MethodDescriptionListTy);

  // struct _objc_method_description_list *
  MethodDescriptionListPtrTy =
    llvm::PointerType::getUnqual(MethodDescriptionListTy);

  // Protocol description structures

  // struct _objc_protocol_extension {
  //   uint32_t size;  // sizeof(struct _objc_protocol_extension)
  //   struct _objc_method_description_list *optional_instance_methods;
  //   struct _objc_method_description_list *optional_class_methods;
  //   struct _objc_property_list *instance_properties;
  // }
  ProtocolExtensionTy =
    llvm::StructType::get(VMContext, IntTy,
                          MethodDescriptionListPtrTy,
                          MethodDescriptionListPtrTy,
                          PropertyListPtrTy,
                          NULL);
  CGM.getModule().addTypeName("struct._objc_protocol_extension",
                              ProtocolExtensionTy);

  // struct _objc_protocol_extension *
  ProtocolExtensionPtrTy = llvm::PointerType::getUnqual(ProtocolExtensionTy);

  // Handle recursive construction of Protocol and ProtocolList types

  llvm::PATypeHolder ProtocolTyHolder = llvm::OpaqueType::get(VMContext);
  llvm::PATypeHolder ProtocolListTyHolder = llvm::OpaqueType::get(VMContext);

  const llvm::Type *T =
    llvm::StructType::get(VMContext, 
                          llvm::PointerType::getUnqual(ProtocolListTyHolder),
                          LongTy,
                          llvm::ArrayType::get(ProtocolTyHolder, 0),
                          NULL);
  cast<llvm::OpaqueType>(ProtocolListTyHolder.get())->refineAbstractTypeTo(T);

  // struct _objc_protocol {
  //   struct _objc_protocol_extension *isa;
  //   char *protocol_name;
  //   struct _objc_protocol **_objc_protocol_list;
  //   struct _objc_method_description_list *instance_methods;
  //   struct _objc_method_description_list *class_methods;
  // }
  T = llvm::StructType::get(VMContext, ProtocolExtensionPtrTy,
                            Int8PtrTy,
                            llvm::PointerType::getUnqual(ProtocolListTyHolder),
                            MethodDescriptionListPtrTy,
                            MethodDescriptionListPtrTy,
                            NULL);
  cast<llvm::OpaqueType>(ProtocolTyHolder.get())->refineAbstractTypeTo(T);

  ProtocolListTy = cast<llvm::StructType>(ProtocolListTyHolder.get());
  CGM.getModule().addTypeName("struct._objc_protocol_list",
                              ProtocolListTy);
  // struct _objc_protocol_list *
  ProtocolListPtrTy = llvm::PointerType::getUnqual(ProtocolListTy);

  ProtocolTy = cast<llvm::StructType>(ProtocolTyHolder.get());
  CGM.getModule().addTypeName("struct._objc_protocol", ProtocolTy);
  ProtocolPtrTy = llvm::PointerType::getUnqual(ProtocolTy);

  // Class description structures

  // struct _objc_ivar {
  //   char *ivar_name;
  //   char *ivar_type;
  //   int  ivar_offset;
  // }
  IvarTy = llvm::StructType::get(VMContext, Int8PtrTy,
                                 Int8PtrTy,
                                 IntTy,
                                 NULL);
  CGM.getModule().addTypeName("struct._objc_ivar", IvarTy);

  // struct _objc_ivar_list *
  IvarListTy = llvm::OpaqueType::get(VMContext);
  CGM.getModule().addTypeName("struct._objc_ivar_list", IvarListTy);
  IvarListPtrTy = llvm::PointerType::getUnqual(IvarListTy);

  // struct _objc_method_list *
  MethodListTy = llvm::OpaqueType::get(VMContext);
  CGM.getModule().addTypeName("struct._objc_method_list", MethodListTy);
  MethodListPtrTy = llvm::PointerType::getUnqual(MethodListTy);

  // struct _objc_class_extension *
  ClassExtensionTy =
    llvm::StructType::get(VMContext, IntTy,
                          Int8PtrTy,
                          PropertyListPtrTy,
                          NULL);
  CGM.getModule().addTypeName("struct._objc_class_extension", ClassExtensionTy);
  ClassExtensionPtrTy = llvm::PointerType::getUnqual(ClassExtensionTy);

  llvm::PATypeHolder ClassTyHolder = llvm::OpaqueType::get(VMContext);

  // struct _objc_class {
  //   Class isa;
  //   Class super_class;
  //   char *name;
  //   long version;
  //   long info;
  //   long instance_size;
  //   struct _objc_ivar_list *ivars;
  //   struct _objc_method_list *methods;
  //   struct _objc_cache *cache;
  //   struct _objc_protocol_list *protocols;
  //   char *ivar_layout;
  //   struct _objc_class_ext *ext;
  // };
  T = llvm::StructType::get(VMContext,
                            llvm::PointerType::getUnqual(ClassTyHolder),
                            llvm::PointerType::getUnqual(ClassTyHolder),
                            Int8PtrTy,
                            LongTy,
                            LongTy,
                            LongTy,
                            IvarListPtrTy,
                            MethodListPtrTy,
                            CachePtrTy,
                            ProtocolListPtrTy,
                            Int8PtrTy,
                            ClassExtensionPtrTy,
                            NULL);
  cast<llvm::OpaqueType>(ClassTyHolder.get())->refineAbstractTypeTo(T);

  ClassTy = cast<llvm::StructType>(ClassTyHolder.get());
  CGM.getModule().addTypeName("struct._objc_class", ClassTy);
  ClassPtrTy = llvm::PointerType::getUnqual(ClassTy);

  // struct _objc_category {
  //   char *category_name;
  //   char *class_name;
  //   struct _objc_method_list *instance_method;
  //   struct _objc_method_list *class_method;
  //   uint32_t size;  // sizeof(struct _objc_category)
  //   struct _objc_property_list *instance_properties;// category's @property
  // }
  CategoryTy = llvm::StructType::get(VMContext, Int8PtrTy,
                                     Int8PtrTy,
                                     MethodListPtrTy,
                                     MethodListPtrTy,
                                     ProtocolListPtrTy,
                                     IntTy,
                                     PropertyListPtrTy,
                                     NULL);
  CGM.getModule().addTypeName("struct._objc_category", CategoryTy);

  // Global metadata structures

  // struct _objc_symtab {
  //   long sel_ref_cnt;
  //   SEL *refs;
  //   short cls_def_cnt;
  //   short cat_def_cnt;
  //   char *defs[cls_def_cnt + cat_def_cnt];
  // }
  SymtabTy = llvm::StructType::get(VMContext, LongTy,
                                   SelectorPtrTy,
                                   ShortTy,
                                   ShortTy,
                                   llvm::ArrayType::get(Int8PtrTy, 0),
                                   NULL);
  CGM.getModule().addTypeName("struct._objc_symtab", SymtabTy);
  SymtabPtrTy = llvm::PointerType::getUnqual(SymtabTy);

  // struct _objc_module {
  //   long version;
  //   long size;   // sizeof(struct _objc_module)
  //   char *name;
  //   struct _objc_symtab* symtab;
  //  }
  ModuleTy =
    llvm::StructType::get(VMContext, LongTy,
                          LongTy,
                          Int8PtrTy,
                          SymtabPtrTy,
                          NULL);
  CGM.getModule().addTypeName("struct._objc_module", ModuleTy);


  // FIXME: This is the size of the setjmp buffer and should be target
  // specific. 18 is what's used on 32-bit X86.
  uint64_t SetJmpBufferSize = 18;

  // Exceptions
  const llvm::Type *StackPtrTy = llvm::ArrayType::get(
    llvm::PointerType::getUnqual(llvm::Type::getInt8Ty(VMContext)), 4);

  ExceptionDataTy =
    llvm::StructType::get(VMContext, llvm::ArrayType::get(llvm::Type::getInt32Ty(VMContext),
                                                          SetJmpBufferSize),
                          StackPtrTy, NULL);
  CGM.getModule().addTypeName("struct._objc_exception_data",
                              ExceptionDataTy);

}

ObjCNonFragileABITypesHelper::ObjCNonFragileABITypesHelper(CodeGen::CodeGenModule &cgm)
  : ObjCCommonTypesHelper(cgm)
{
  // struct _method_list_t {
  //   uint32_t entsize;  // sizeof(struct _objc_method)
  //   uint32_t method_count;
  //   struct _objc_method method_list[method_count];
  // }
  MethodListnfABITy = llvm::StructType::get(VMContext, IntTy,
                                            IntTy,
                                            llvm::ArrayType::get(MethodTy, 0),
                                            NULL);
  CGM.getModule().addTypeName("struct.__method_list_t",
                              MethodListnfABITy);
  // struct method_list_t *
  MethodListnfABIPtrTy = llvm::PointerType::getUnqual(MethodListnfABITy);

  // struct _protocol_t {
  //   id isa;  // NULL
  //   const char * const protocol_name;
  //   const struct _protocol_list_t * protocol_list; // super protocols
  //   const struct method_list_t * const instance_methods;
  //   const struct method_list_t * const class_methods;
  //   const struct method_list_t *optionalInstanceMethods;
  //   const struct method_list_t *optionalClassMethods;
  //   const struct _prop_list_t * properties;
  //   const uint32_t size;  // sizeof(struct _protocol_t)
  //   const uint32_t flags;  // = 0
  // }

  // Holder for struct _protocol_list_t *
  llvm::PATypeHolder ProtocolListTyHolder = llvm::OpaqueType::get(VMContext);

  ProtocolnfABITy = llvm::StructType::get(VMContext, ObjectPtrTy,
                                          Int8PtrTy,
                                          llvm::PointerType::getUnqual(
                                            ProtocolListTyHolder),
                                          MethodListnfABIPtrTy,
                                          MethodListnfABIPtrTy,
                                          MethodListnfABIPtrTy,
                                          MethodListnfABIPtrTy,
                                          PropertyListPtrTy,
                                          IntTy,
                                          IntTy,
                                          NULL);
  CGM.getModule().addTypeName("struct._protocol_t",
                              ProtocolnfABITy);

  // struct _protocol_t*
  ProtocolnfABIPtrTy = llvm::PointerType::getUnqual(ProtocolnfABITy);

  // struct _protocol_list_t {
  //   long protocol_count;   // Note, this is 32/64 bit
  //   struct _protocol_t *[protocol_count];
  // }
  ProtocolListnfABITy = llvm::StructType::get(VMContext, LongTy,
                                              llvm::ArrayType::get(
                                                ProtocolnfABIPtrTy, 0),
                                              NULL);
  CGM.getModule().addTypeName("struct._objc_protocol_list",
                              ProtocolListnfABITy);
  cast<llvm::OpaqueType>(ProtocolListTyHolder.get())->refineAbstractTypeTo(
    ProtocolListnfABITy);

  // struct _objc_protocol_list*
  ProtocolListnfABIPtrTy = llvm::PointerType::getUnqual(ProtocolListnfABITy);

  // struct _ivar_t {
  //   unsigned long int *offset;  // pointer to ivar offset location
  //   char *name;
  //   char *type;
  //   uint32_t alignment;
  //   uint32_t size;
  // }
  IvarnfABITy = llvm::StructType::get(VMContext, 
                                      llvm::PointerType::getUnqual(LongTy),
                                      Int8PtrTy,
                                      Int8PtrTy,
                                      IntTy,
                                      IntTy,
                                      NULL);
  CGM.getModule().addTypeName("struct._ivar_t", IvarnfABITy);

  // struct _ivar_list_t {
  //   uint32 entsize;  // sizeof(struct _ivar_t)
  //   uint32 count;
  //   struct _iver_t list[count];
  // }
  IvarListnfABITy = llvm::StructType::get(VMContext, IntTy,
                                          IntTy,
                                          llvm::ArrayType::get(
                                            IvarnfABITy, 0),
                                          NULL);
  CGM.getModule().addTypeName("struct._ivar_list_t", IvarListnfABITy);

  IvarListnfABIPtrTy = llvm::PointerType::getUnqual(IvarListnfABITy);

  // struct _class_ro_t {
  //   uint32_t const flags;
  //   uint32_t const instanceStart;
  //   uint32_t const instanceSize;
  //   uint32_t const reserved;  // only when building for 64bit targets
  //   const uint8_t * const ivarLayout;
  //   const char *const name;
  //   const struct _method_list_t * const baseMethods;
  //   const struct _objc_protocol_list *const baseProtocols;
  //   const struct _ivar_list_t *const ivars;
  //   const uint8_t * const weakIvarLayout;
  //   const struct _prop_list_t * const properties;
  // }

  // FIXME. Add 'reserved' field in 64bit abi mode!
  ClassRonfABITy = llvm::StructType::get(VMContext, IntTy,
                                         IntTy,
                                         IntTy,
                                         Int8PtrTy,
                                         Int8PtrTy,
                                         MethodListnfABIPtrTy,
                                         ProtocolListnfABIPtrTy,
                                         IvarListnfABIPtrTy,
                                         Int8PtrTy,
                                         PropertyListPtrTy,
                                         NULL);
  CGM.getModule().addTypeName("struct._class_ro_t",
                              ClassRonfABITy);

  // ImpnfABITy - LLVM for id (*)(id, SEL, ...)
  std::vector<const llvm::Type*> Params;
  Params.push_back(ObjectPtrTy);
  Params.push_back(SelectorPtrTy);
  ImpnfABITy = llvm::PointerType::getUnqual(
    llvm::FunctionType::get(ObjectPtrTy, Params, false));

  // struct _class_t {
  //   struct _class_t *isa;
  //   struct _class_t * const superclass;
  //   void *cache;
  //   IMP *vtable;
  //   struct class_ro_t *ro;
  // }

  llvm::PATypeHolder ClassTyHolder = llvm::OpaqueType::get(VMContext);
  ClassnfABITy =
    llvm::StructType::get(VMContext,
                          llvm::PointerType::getUnqual(ClassTyHolder),
                          llvm::PointerType::getUnqual(ClassTyHolder),
                          CachePtrTy,
                          llvm::PointerType::getUnqual(ImpnfABITy),
                          llvm::PointerType::getUnqual(ClassRonfABITy),
                          NULL);
  CGM.getModule().addTypeName("struct._class_t", ClassnfABITy);

  cast<llvm::OpaqueType>(ClassTyHolder.get())->refineAbstractTypeTo(
    ClassnfABITy);

  // LLVM for struct _class_t *
  ClassnfABIPtrTy = llvm::PointerType::getUnqual(ClassnfABITy);

  // struct _category_t {
  //   const char * const name;
  //   struct _class_t *const cls;
  //   const struct _method_list_t * const instance_methods;
  //   const struct _method_list_t * const class_methods;
  //   const struct _protocol_list_t * const protocols;
  //   const struct _prop_list_t * const properties;
  // }
  CategorynfABITy = llvm::StructType::get(VMContext, Int8PtrTy,
                                          ClassnfABIPtrTy,
                                          MethodListnfABIPtrTy,
                                          MethodListnfABIPtrTy,
                                          ProtocolListnfABIPtrTy,
                                          PropertyListPtrTy,
                                          NULL);
  CGM.getModule().addTypeName("struct._category_t", CategorynfABITy);

  // New types for nonfragile abi messaging.
  CodeGen::CodeGenTypes &Types = CGM.getTypes();
  ASTContext &Ctx = CGM.getContext();

  // MessageRefTy - LLVM for:
  // struct _message_ref_t {
  //   IMP messenger;
  //   SEL name;
  // };

  // First the clang type for struct _message_ref_t
  RecordDecl *RD = RecordDecl::Create(Ctx, TagDecl::TK_struct, 0,
                                      SourceLocation(),
                                      &Ctx.Idents.get("_message_ref_t"));
  RD->addDecl(FieldDecl::Create(Ctx, RD, SourceLocation(), 0,
                                Ctx.VoidPtrTy, 0, 0, false));
  RD->addDecl(FieldDecl::Create(Ctx, RD, SourceLocation(), 0,
                                Ctx.getObjCSelType(), 0, 0, false));
  RD->completeDefinition(Ctx);

  MessageRefCTy = Ctx.getTagDeclType(RD);
  MessageRefCPtrTy = Ctx.getPointerType(MessageRefCTy);
  MessageRefTy = cast<llvm::StructType>(Types.ConvertType(MessageRefCTy));

  // MessageRefPtrTy - LLVM for struct _message_ref_t*
  MessageRefPtrTy = llvm::PointerType::getUnqual(MessageRefTy);

  // SuperMessageRefTy - LLVM for:
  // struct _super_message_ref_t {
  //   SUPER_IMP messenger;
  //   SEL name;
  // };
  SuperMessageRefTy = llvm::StructType::get(VMContext, ImpnfABITy,
                                            SelectorPtrTy,
                                            NULL);
  CGM.getModule().addTypeName("struct._super_message_ref_t", SuperMessageRefTy);

  // SuperMessageRefPtrTy - LLVM for struct _super_message_ref_t*
  SuperMessageRefPtrTy = llvm::PointerType::getUnqual(SuperMessageRefTy);


  // struct objc_typeinfo {
  //   const void** vtable; // objc_ehtype_vtable + 2
  //   const char*  name;    // c++ typeinfo string
  //   Class        cls;
  // };
  EHTypeTy = llvm::StructType::get(VMContext,
                                   llvm::PointerType::getUnqual(Int8PtrTy),
                                   Int8PtrTy,
                                   ClassnfABIPtrTy,
                                   NULL);
  CGM.getModule().addTypeName("struct._objc_typeinfo", EHTypeTy);
  EHTypePtrTy = llvm::PointerType::getUnqual(EHTypeTy);
}

llvm::Function *CGObjCNonFragileABIMac::ModuleInitFunction() {
  FinishNonFragileABIModule();

  return NULL;
}

void CGObjCNonFragileABIMac::AddModuleClassList(const
                                                std::vector<llvm::GlobalValue*>
                                                &Container,
                                                const char *SymbolName,
                                                const char *SectionName) {
  unsigned NumClasses = Container.size();

  if (!NumClasses)
    return;

  std::vector<llvm::Constant*> Symbols(NumClasses);
  for (unsigned i=0; i<NumClasses; i++)
    Symbols[i] = llvm::ConstantExpr::getBitCast(Container[i],
                                                ObjCTypes.Int8PtrTy);
  llvm::Constant* Init =
    llvm::ConstantArray::get(llvm::ArrayType::get(ObjCTypes.Int8PtrTy,
                                                  NumClasses),
                             Symbols);

  llvm::GlobalVariable *GV =
    new llvm::GlobalVariable(CGM.getModule(), Init->getType(), false,
                             llvm::GlobalValue::InternalLinkage,
                             Init,
                             SymbolName);
  GV->setAlignment(8);
  GV->setSection(SectionName);
  CGM.AddUsedGlobal(GV);
}

void CGObjCNonFragileABIMac::FinishNonFragileABIModule() {
  // nonfragile abi has no module definition.

  // Build list of all implemented class addresses in array
  // L_OBJC_LABEL_CLASS_$.
  AddModuleClassList(DefinedClasses,
                     "\01L_OBJC_LABEL_CLASS_$",
                     "__DATA, __objc_classlist, regular, no_dead_strip");
  AddModuleClassList(DefinedNonLazyClasses,
                     "\01L_OBJC_LABEL_NONLAZY_CLASS_$",
                     "__DATA, __objc_nlclslist, regular, no_dead_strip");

  // Build list of all implemented category addresses in array
  // L_OBJC_LABEL_CATEGORY_$.
  AddModuleClassList(DefinedCategories,
                     "\01L_OBJC_LABEL_CATEGORY_$",
                     "__DATA, __objc_catlist, regular, no_dead_strip");
  AddModuleClassList(DefinedNonLazyCategories,
                     "\01L_OBJC_LABEL_NONLAZY_CATEGORY_$",
                     "__DATA, __objc_nlcatlist, regular, no_dead_strip");

  //  static int L_OBJC_IMAGE_INFO[2] = { 0, flags };
  // FIXME. flags can be 0 | 1 | 2 | 6. For now just use 0
  std::vector<llvm::Constant*> Values(2);
  Values[0] = llvm::ConstantInt::get(ObjCTypes.IntTy, 0);
  unsigned int flags = 0;
  // FIXME: Fix and continue?
  if (CGM.getLangOptions().getGCMode() != LangOptions::NonGC)
    flags |= eImageInfo_GarbageCollected;
  if (CGM.getLangOptions().getGCMode() == LangOptions::GCOnly)
    flags |= eImageInfo_GCOnly;
  Values[1] = llvm::ConstantInt::get(ObjCTypes.IntTy, flags);
  llvm::Constant* Init = llvm::ConstantArray::get(
    llvm::ArrayType::get(ObjCTypes.IntTy, 2),
    Values);
  llvm::GlobalVariable *IMGV =
    new llvm::GlobalVariable(CGM.getModule(), Init->getType(), false,
                             llvm::GlobalValue::InternalLinkage,
                             Init,
                             "\01L_OBJC_IMAGE_INFO");
  IMGV->setSection("__DATA, __objc_imageinfo, regular, no_dead_strip");
  IMGV->setConstant(true);
  CGM.AddUsedGlobal(IMGV);
}

/// LegacyDispatchedSelector - Returns true if SEL is not in the list of
/// NonLegacyDispatchMethods; false otherwise. What this means is that
/// except for the 19 selectors in the list, we generate 32bit-style
/// message dispatch call for all the rest.
///
bool CGObjCNonFragileABIMac::LegacyDispatchedSelector(Selector Sel) {
  if (NonLegacyDispatchMethods.empty()) {
    NonLegacyDispatchMethods.insert(GetNullarySelector("alloc"));
    NonLegacyDispatchMethods.insert(GetNullarySelector("class"));
    NonLegacyDispatchMethods.insert(GetNullarySelector("self"));
    NonLegacyDispatchMethods.insert(GetNullarySelector("isFlipped"));
    NonLegacyDispatchMethods.insert(GetNullarySelector("length"));
    NonLegacyDispatchMethods.insert(GetNullarySelector("count"));
    NonLegacyDispatchMethods.insert(GetNullarySelector("retain"));
    NonLegacyDispatchMethods.insert(GetNullarySelector("release"));
    NonLegacyDispatchMethods.insert(GetNullarySelector("autorelease"));
    NonLegacyDispatchMethods.insert(GetNullarySelector("hash"));

    NonLegacyDispatchMethods.insert(GetUnarySelector("allocWithZone"));
    NonLegacyDispatchMethods.insert(GetUnarySelector("isKindOfClass"));
    NonLegacyDispatchMethods.insert(GetUnarySelector("respondsToSelector"));
    NonLegacyDispatchMethods.insert(GetUnarySelector("objectForKey"));
    NonLegacyDispatchMethods.insert(GetUnarySelector("objectAtIndex"));
    NonLegacyDispatchMethods.insert(GetUnarySelector("isEqualToString"));
    NonLegacyDispatchMethods.insert(GetUnarySelector("isEqual"));
    NonLegacyDispatchMethods.insert(GetUnarySelector("addObject"));
    // "countByEnumeratingWithState:objects:count"
    IdentifierInfo *KeyIdents[] = {
      &CGM.getContext().Idents.get("countByEnumeratingWithState"),
      &CGM.getContext().Idents.get("objects"),
      &CGM.getContext().Idents.get("count")
    };
    NonLegacyDispatchMethods.insert(
      CGM.getContext().Selectors.getSelector(3, KeyIdents));
  }
  return (NonLegacyDispatchMethods.count(Sel) == 0);
}

// Metadata flags
enum MetaDataDlags {
  CLS = 0x0,
  CLS_META = 0x1,
  CLS_ROOT = 0x2,
  OBJC2_CLS_HIDDEN = 0x10,
  CLS_EXCEPTION = 0x20
};
/// BuildClassRoTInitializer - generate meta-data for:
/// struct _class_ro_t {
///   uint32_t const flags;
///   uint32_t const instanceStart;
///   uint32_t const instanceSize;
///   uint32_t const reserved;  // only when building for 64bit targets
///   const uint8_t * const ivarLayout;
///   const char *const name;
///   const struct _method_list_t * const baseMethods;
///   const struct _protocol_list_t *const baseProtocols;
///   const struct _ivar_list_t *const ivars;
///   const uint8_t * const weakIvarLayout;
///   const struct _prop_list_t * const properties;
/// }
///
llvm::GlobalVariable * CGObjCNonFragileABIMac::BuildClassRoTInitializer(
  unsigned flags,
  unsigned InstanceStart,
  unsigned InstanceSize,
  const ObjCImplementationDecl *ID) {
  std::string ClassName = ID->getNameAsString();
  std::vector<llvm::Constant*> Values(10); // 11 for 64bit targets!
  Values[ 0] = llvm::ConstantInt::get(ObjCTypes.IntTy, flags);
  Values[ 1] = llvm::ConstantInt::get(ObjCTypes.IntTy, InstanceStart);
  Values[ 2] = llvm::ConstantInt::get(ObjCTypes.IntTy, InstanceSize);
  // FIXME. For 64bit targets add 0 here.
  Values[ 3] = (flags & CLS_META) ? GetIvarLayoutName(0, ObjCTypes)
    : BuildIvarLayout(ID, true);
  Values[ 4] = GetClassName(ID->getIdentifier());
  // const struct _method_list_t * const baseMethods;
  std::vector<llvm::Constant*> Methods;
  std::string MethodListName("\01l_OBJC_$_");
  if (flags & CLS_META) {
    MethodListName += "CLASS_METHODS_" + ID->getNameAsString();
    for (ObjCImplementationDecl::classmeth_iterator
           i = ID->classmeth_begin(), e = ID->classmeth_end(); i != e; ++i) {
      // Class methods should always be defined.
      Methods.push_back(GetMethodConstant(*i));
    }
  } else {
    MethodListName += "INSTANCE_METHODS_" + ID->getNameAsString();
    for (ObjCImplementationDecl::instmeth_iterator
           i = ID->instmeth_begin(), e = ID->instmeth_end(); i != e; ++i) {
      // Instance methods should always be defined.
      Methods.push_back(GetMethodConstant(*i));
    }
    for (ObjCImplementationDecl::propimpl_iterator
           i = ID->propimpl_begin(), e = ID->propimpl_end(); i != e; ++i) {
      ObjCPropertyImplDecl *PID = *i;

      if (PID->getPropertyImplementation() == ObjCPropertyImplDecl::Synthesize){
        ObjCPropertyDecl *PD = PID->getPropertyDecl();

        if (ObjCMethodDecl *MD = PD->getGetterMethodDecl())
          if (llvm::Constant *C = GetMethodConstant(MD))
            Methods.push_back(C);
        if (ObjCMethodDecl *MD = PD->getSetterMethodDecl())
          if (llvm::Constant *C = GetMethodConstant(MD))
            Methods.push_back(C);
      }
    }
  }
  Values[ 5] = EmitMethodList(MethodListName,
                              "__DATA, __objc_const", Methods);

  const ObjCInterfaceDecl *OID = ID->getClassInterface();
  assert(OID && "CGObjCNonFragileABIMac::BuildClassRoTInitializer");
  Values[ 6] = EmitProtocolList("\01l_OBJC_CLASS_PROTOCOLS_$_"
                                + OID->getNameAsString(),
                                OID->protocol_begin(),
                                OID->protocol_end());

  if (flags & CLS_META)
    Values[ 7] = llvm::Constant::getNullValue(ObjCTypes.IvarListnfABIPtrTy);
  else
    Values[ 7] = EmitIvarList(ID);
  Values[ 8] = (flags & CLS_META) ? GetIvarLayoutName(0, ObjCTypes)
    : BuildIvarLayout(ID, false);
  if (flags & CLS_META)
    Values[ 9] = llvm::Constant::getNullValue(ObjCTypes.PropertyListPtrTy);
  else
    Values[ 9] =
      EmitPropertyList("\01l_OBJC_$_PROP_LIST_" + ID->getNameAsString(),
                       ID, ID->getClassInterface(), ObjCTypes);
  llvm::Constant *Init = llvm::ConstantStruct::get(ObjCTypes.ClassRonfABITy,
                                                   Values);
  llvm::GlobalVariable *CLASS_RO_GV =
    new llvm::GlobalVariable(CGM.getModule(), ObjCTypes.ClassRonfABITy, false,
                             llvm::GlobalValue::InternalLinkage,
                             Init,
                             (flags & CLS_META) ?
                             std::string("\01l_OBJC_METACLASS_RO_$_")+ClassName :
                             std::string("\01l_OBJC_CLASS_RO_$_")+ClassName);
  CLASS_RO_GV->setAlignment(
    CGM.getTargetData().getPrefTypeAlignment(ObjCTypes.ClassRonfABITy));
  CLASS_RO_GV->setSection("__DATA, __objc_const");
  return CLASS_RO_GV;

}

/// BuildClassMetaData - This routine defines that to-level meta-data
/// for the given ClassName for:
/// struct _class_t {
///   struct _class_t *isa;
///   struct _class_t * const superclass;
///   void *cache;
///   IMP *vtable;
///   struct class_ro_t *ro;
/// }
///
llvm::GlobalVariable * CGObjCNonFragileABIMac::BuildClassMetaData(
  std::string &ClassName,
  llvm::Constant *IsAGV,
  llvm::Constant *SuperClassGV,
  llvm::Constant *ClassRoGV,
  bool HiddenVisibility) {
  std::vector<llvm::Constant*> Values(5);
  Values[0] = IsAGV;
  Values[1] = SuperClassGV;
  if (!Values[1])
    Values[1] = llvm::Constant::getNullValue(ObjCTypes.ClassnfABIPtrTy);
  Values[2] = ObjCEmptyCacheVar;  // &ObjCEmptyCacheVar
  Values[3] = ObjCEmptyVtableVar; // &ObjCEmptyVtableVar
  Values[4] = ClassRoGV;                 // &CLASS_RO_GV
  llvm::Constant *Init = llvm::ConstantStruct::get(ObjCTypes.ClassnfABITy,
                                                   Values);
  llvm::GlobalVariable *GV = GetClassGlobal(ClassName);
  GV->setInitializer(Init);
  GV->setSection("__DATA, __objc_data");
  GV->setAlignment(
    CGM.getTargetData().getPrefTypeAlignment(ObjCTypes.ClassnfABITy));
  if (HiddenVisibility)
    GV->setVisibility(llvm::GlobalValue::HiddenVisibility);
  return GV;
}

bool
CGObjCNonFragileABIMac::ImplementationIsNonLazy(const ObjCImplDecl *OD) const {
  return OD->getClassMethod(GetNullarySelector("load")) != 0;
}

void CGObjCNonFragileABIMac::GetClassSizeInfo(const ObjCImplementationDecl *OID,
                                              uint32_t &InstanceStart,
                                              uint32_t &InstanceSize) {
  const ASTRecordLayout &RL =
    CGM.getContext().getASTObjCImplementationLayout(OID);

  // InstanceSize is really instance end.
  InstanceSize = llvm::RoundUpToAlignment(RL.getDataSize(), 8) / 8;

  // If there are no fields, the start is the same as the end.
  if (!RL.getFieldCount())
    InstanceStart = InstanceSize;
  else
    InstanceStart = RL.getFieldOffset(0) / 8;
}

void CGObjCNonFragileABIMac::GenerateClass(const ObjCImplementationDecl *ID) {
  std::string ClassName = ID->getNameAsString();
  if (!ObjCEmptyCacheVar) {
    ObjCEmptyCacheVar = new llvm::GlobalVariable(
      CGM.getModule(),
      ObjCTypes.CacheTy,
      false,
      llvm::GlobalValue::ExternalLinkage,
      0,
      "_objc_empty_cache");

    ObjCEmptyVtableVar = new llvm::GlobalVariable(
      CGM.getModule(),
      ObjCTypes.ImpnfABITy,
      false,
      llvm::GlobalValue::ExternalLinkage,
      0,
      "_objc_empty_vtable");
  }
  assert(ID->getClassInterface() &&
         "CGObjCNonFragileABIMac::GenerateClass - class is 0");
  // FIXME: Is this correct (that meta class size is never computed)?
  uint32_t InstanceStart =
    CGM.getTargetData().getTypeAllocSize(ObjCTypes.ClassnfABITy);
  uint32_t InstanceSize = InstanceStart;
  uint32_t flags = CLS_META;
  std::string ObjCMetaClassName(getMetaclassSymbolPrefix());
  std::string ObjCClassName(getClassSymbolPrefix());

  llvm::GlobalVariable *SuperClassGV, *IsAGV;

  bool classIsHidden =
    CGM.getDeclVisibilityMode(ID->getClassInterface()) == LangOptions::Hidden;
  if (classIsHidden)
    flags |= OBJC2_CLS_HIDDEN;
  if (!ID->getClassInterface()->getSuperClass()) {
    // class is root
    flags |= CLS_ROOT;
    SuperClassGV = GetClassGlobal(ObjCClassName + ClassName);
    IsAGV = GetClassGlobal(ObjCMetaClassName + ClassName);
  } else {
    // Has a root. Current class is not a root.
    const ObjCInterfaceDecl *Root = ID->getClassInterface();
    while (const ObjCInterfaceDecl *Super = Root->getSuperClass())
      Root = Super;
    IsAGV = GetClassGlobal(ObjCMetaClassName + Root->getNameAsString());
    // work on super class metadata symbol.
    std::string SuperClassName =
      ObjCMetaClassName + ID->getClassInterface()->getSuperClass()->getNameAsString();
    SuperClassGV = GetClassGlobal(SuperClassName);
  }
  llvm::GlobalVariable *CLASS_RO_GV = BuildClassRoTInitializer(flags,
                                                               InstanceStart,
                                                               InstanceSize,ID);
  std::string TClassName = ObjCMetaClassName + ClassName;
  llvm::GlobalVariable *MetaTClass =
    BuildClassMetaData(TClassName, IsAGV, SuperClassGV, CLASS_RO_GV,
                       classIsHidden);

  // Metadata for the class
  flags = CLS;
  if (classIsHidden)
    flags |= OBJC2_CLS_HIDDEN;

  if (hasObjCExceptionAttribute(CGM.getContext(), ID->getClassInterface()))
    flags |= CLS_EXCEPTION;

  if (!ID->getClassInterface()->getSuperClass()) {
    flags |= CLS_ROOT;
    SuperClassGV = 0;
  } else {
    // Has a root. Current class is not a root.
    std::string RootClassName =
      ID->getClassInterface()->getSuperClass()->getNameAsString();
    SuperClassGV = GetClassGlobal(ObjCClassName + RootClassName);
  }
  GetClassSizeInfo(ID, InstanceStart, InstanceSize);
  CLASS_RO_GV = BuildClassRoTInitializer(flags,
                                         InstanceStart,
                                         InstanceSize,
                                         ID);

  TClassName = ObjCClassName + ClassName;
  llvm::GlobalVariable *ClassMD =
    BuildClassMetaData(TClassName, MetaTClass, SuperClassGV, CLASS_RO_GV,
                       classIsHidden);
  DefinedClasses.push_back(ClassMD);

  // Determine if this class is also "non-lazy".
  if (ImplementationIsNonLazy(ID))
    DefinedNonLazyClasses.push_back(ClassMD);

  // Force the definition of the EHType if necessary.
  if (flags & CLS_EXCEPTION)
    GetInterfaceEHType(ID->getClassInterface(), true);
}

/// GenerateProtocolRef - This routine is called to generate code for
/// a protocol reference expression; as in:
/// @code
///   @protocol(Proto1);
/// @endcode
/// It generates a weak reference to l_OBJC_PROTOCOL_REFERENCE_$_Proto1
/// which will hold address of the protocol meta-data.
///
llvm::Value *CGObjCNonFragileABIMac::GenerateProtocolRef(CGBuilderTy &Builder,
                                                         const ObjCProtocolDecl *PD) {

  // This routine is called for @protocol only. So, we must build definition
  // of protocol's meta-data (not a reference to it!)
  //
  llvm::Constant *Init =
    llvm::ConstantExpr::getBitCast(GetOrEmitProtocol(PD),
                                   ObjCTypes.ExternalProtocolPtrTy);

  std::string ProtocolName("\01l_OBJC_PROTOCOL_REFERENCE_$_");
  ProtocolName += PD->getNameAsCString();

  llvm::GlobalVariable *PTGV = CGM.getModule().getGlobalVariable(ProtocolName);
  if (PTGV)
    return Builder.CreateLoad(PTGV, false, "tmp");
  PTGV = new llvm::GlobalVariable(
    CGM.getModule(),
    Init->getType(), false,
    llvm::GlobalValue::WeakAnyLinkage,
    Init,
    ProtocolName);
  PTGV->setSection("__DATA, __objc_protorefs, coalesced, no_dead_strip");
  PTGV->setVisibility(llvm::GlobalValue::HiddenVisibility);
  CGM.AddUsedGlobal(PTGV);
  return Builder.CreateLoad(PTGV, false, "tmp");
}

/// GenerateCategory - Build metadata for a category implementation.
/// struct _category_t {
///   const char * const name;
///   struct _class_t *const cls;
///   const struct _method_list_t * const instance_methods;
///   const struct _method_list_t * const class_methods;
///   const struct _protocol_list_t * const protocols;
///   const struct _prop_list_t * const properties;
/// }
///
void CGObjCNonFragileABIMac::GenerateCategory(const ObjCCategoryImplDecl *OCD) {
  const ObjCInterfaceDecl *Interface = OCD->getClassInterface();
  const char *Prefix = "\01l_OBJC_$_CATEGORY_";
  std::string ExtCatName(Prefix + Interface->getNameAsString()+
                         "_$_" + OCD->getNameAsString());
  std::string ExtClassName(getClassSymbolPrefix() +
                           Interface->getNameAsString());

  std::vector<llvm::Constant*> Values(6);
  Values[0] = GetClassName(OCD->getIdentifier());
  // meta-class entry symbol
  llvm::GlobalVariable *ClassGV = GetClassGlobal(ExtClassName);
  Values[1] = ClassGV;
  std::vector<llvm::Constant*> Methods;
  std::string MethodListName(Prefix);
  MethodListName += "INSTANCE_METHODS_" + Interface->getNameAsString() +
    "_$_" + OCD->getNameAsString();

  for (ObjCCategoryImplDecl::instmeth_iterator
         i = OCD->instmeth_begin(), e = OCD->instmeth_end(); i != e; ++i) {
    // Instance methods should always be defined.
    Methods.push_back(GetMethodConstant(*i));
  }

  Values[2] = EmitMethodList(MethodListName,
                             "__DATA, __objc_const",
                             Methods);

  MethodListName = Prefix;
  MethodListName += "CLASS_METHODS_" + Interface->getNameAsString() + "_$_" +
    OCD->getNameAsString();
  Methods.clear();
  for (ObjCCategoryImplDecl::classmeth_iterator
         i = OCD->classmeth_begin(), e = OCD->classmeth_end(); i != e; ++i) {
    // Class methods should always be defined.
    Methods.push_back(GetMethodConstant(*i));
  }

  Values[3] = EmitMethodList(MethodListName,
                             "__DATA, __objc_const",
                             Methods);
  const ObjCCategoryDecl *Category =
    Interface->FindCategoryDeclaration(OCD->getIdentifier());
  if (Category) {
    std::string ExtName(Interface->getNameAsString() + "_$_" +
                        OCD->getNameAsString());
    Values[4] = EmitProtocolList("\01l_OBJC_CATEGORY_PROTOCOLS_$_"
                                 + Interface->getNameAsString() + "_$_"
                                 + Category->getNameAsString(),
                                 Category->protocol_begin(),
                                 Category->protocol_end());
    Values[5] =
      EmitPropertyList(std::string("\01l_OBJC_$_PROP_LIST_") + ExtName,
                       OCD, Category, ObjCTypes);
  } else {
    Values[4] = llvm::Constant::getNullValue(ObjCTypes.ProtocolListnfABIPtrTy);
    Values[5] = llvm::Constant::getNullValue(ObjCTypes.PropertyListPtrTy);
  }

  llvm::Constant *Init =
    llvm::ConstantStruct::get(ObjCTypes.CategorynfABITy,
                              Values);
  llvm::GlobalVariable *GCATV
    = new llvm::GlobalVariable(CGM.getModule(), ObjCTypes.CategorynfABITy,
                               false,
                               llvm::GlobalValue::InternalLinkage,
                               Init,
                               ExtCatName);
  GCATV->setAlignment(
    CGM.getTargetData().getPrefTypeAlignment(ObjCTypes.CategorynfABITy));
  GCATV->setSection("__DATA, __objc_const");
  CGM.AddUsedGlobal(GCATV);
  DefinedCategories.push_back(GCATV);

  // Determine if this category is also "non-lazy".
  if (ImplementationIsNonLazy(OCD))
    DefinedNonLazyCategories.push_back(GCATV);
}

/// GetMethodConstant - Return a struct objc_method constant for the
/// given method if it has been defined. The result is null if the
/// method has not been defined. The return value has type MethodPtrTy.
llvm::Constant *CGObjCNonFragileABIMac::GetMethodConstant(
  const ObjCMethodDecl *MD) {
  // FIXME: Use DenseMap::lookup
  llvm::Function *Fn = MethodDefinitions[MD];
  if (!Fn)
    return 0;

  std::vector<llvm::Constant*> Method(3);
  Method[0] =
    llvm::ConstantExpr::getBitCast(GetMethodVarName(MD->getSelector()),
                                   ObjCTypes.SelectorPtrTy);
  Method[1] = GetMethodVarType(MD);
  Method[2] = llvm::ConstantExpr::getBitCast(Fn, ObjCTypes.Int8PtrTy);
  return llvm::ConstantStruct::get(ObjCTypes.MethodTy, Method);
}

/// EmitMethodList - Build meta-data for method declarations
/// struct _method_list_t {
///   uint32_t entsize;  // sizeof(struct _objc_method)
///   uint32_t method_count;
///   struct _objc_method method_list[method_count];
/// }
///
llvm::Constant *CGObjCNonFragileABIMac::EmitMethodList(
  const std::string &Name,
  const char *Section,
  const ConstantVector &Methods) {
  // Return null for empty list.
  if (Methods.empty())
    return llvm::Constant::getNullValue(ObjCTypes.MethodListnfABIPtrTy);

  std::vector<llvm::Constant*> Values(3);
  // sizeof(struct _objc_method)
  unsigned Size = CGM.getTargetData().getTypeAllocSize(ObjCTypes.MethodTy);
  Values[0] = llvm::ConstantInt::get(ObjCTypes.IntTy, Size);
  // method_count
  Values[1] = llvm::ConstantInt::get(ObjCTypes.IntTy, Methods.size());
  llvm::ArrayType *AT = llvm::ArrayType::get(ObjCTypes.MethodTy,
                                             Methods.size());
  Values[2] = llvm::ConstantArray::get(AT, Methods);
  llvm::Constant *Init = llvm::ConstantStruct::get(VMContext, Values);

  llvm::GlobalVariable *GV =
    new llvm::GlobalVariable(CGM.getModule(), Init->getType(), false,
                             llvm::GlobalValue::InternalLinkage,
                             Init,
                             Name);
  GV->setAlignment(
    CGM.getTargetData().getPrefTypeAlignment(Init->getType()));
  GV->setSection(Section);
  CGM.AddUsedGlobal(GV);
  return llvm::ConstantExpr::getBitCast(GV,
                                        ObjCTypes.MethodListnfABIPtrTy);
}

/// ObjCIvarOffsetVariable - Returns the ivar offset variable for
/// the given ivar.
llvm::GlobalVariable * CGObjCNonFragileABIMac::ObjCIvarOffsetVariable(
  const ObjCInterfaceDecl *ID,
  const ObjCIvarDecl *Ivar) {
  // FIXME: We shouldn't need to do this lookup.
  unsigned Index;
  const ObjCInterfaceDecl *Container =
    FindIvarInterface(CGM.getContext(), ID, Ivar, Index);
  assert(Container && "Unable to find ivar container!");
  std::string Name = "OBJC_IVAR_$_" + Container->getNameAsString() +
    '.' + Ivar->getNameAsString();
  llvm::GlobalVariable *IvarOffsetGV =
    CGM.getModule().getGlobalVariable(Name);
  if (!IvarOffsetGV)
    IvarOffsetGV =
      new llvm::GlobalVariable(CGM.getModule(), ObjCTypes.LongTy,
                               false,
                               llvm::GlobalValue::ExternalLinkage,
                               0,
                               Name);
  return IvarOffsetGV;
}

llvm::Constant * CGObjCNonFragileABIMac::EmitIvarOffsetVar(
  const ObjCInterfaceDecl *ID,
  const ObjCIvarDecl *Ivar,
  unsigned long int Offset) {
  llvm::GlobalVariable *IvarOffsetGV = ObjCIvarOffsetVariable(ID, Ivar);
  IvarOffsetGV->setInitializer(llvm::ConstantInt::get(ObjCTypes.LongTy,
                                                      Offset));
  IvarOffsetGV->setAlignment(
    CGM.getTargetData().getPrefTypeAlignment(ObjCTypes.LongTy));

  // FIXME: This matches gcc, but shouldn't the visibility be set on the use as
  // well (i.e., in ObjCIvarOffsetVariable).
  if (Ivar->getAccessControl() == ObjCIvarDecl::Private ||
      Ivar->getAccessControl() == ObjCIvarDecl::Package ||
      CGM.getDeclVisibilityMode(ID) == LangOptions::Hidden)
    IvarOffsetGV->setVisibility(llvm::GlobalValue::HiddenVisibility);
  else
    IvarOffsetGV->setVisibility(llvm::GlobalValue::DefaultVisibility);
  IvarOffsetGV->setSection("__DATA, __objc_const");
  return IvarOffsetGV;
}

/// EmitIvarList - Emit the ivar list for the given
/// implementation. The return value has type
/// IvarListnfABIPtrTy.
///  struct _ivar_t {
///   unsigned long int *offset;  // pointer to ivar offset location
///   char *name;
///   char *type;
///   uint32_t alignment;
///   uint32_t size;
/// }
/// struct _ivar_list_t {
///   uint32 entsize;  // sizeof(struct _ivar_t)
///   uint32 count;
///   struct _iver_t list[count];
/// }
///

llvm::Constant *CGObjCNonFragileABIMac::EmitIvarList(
  const ObjCImplementationDecl *ID) {

  std::vector<llvm::Constant*> Ivars, Ivar(5);

  const ObjCInterfaceDecl *OID = ID->getClassInterface();
  assert(OID && "CGObjCNonFragileABIMac::EmitIvarList - null interface");

  // FIXME. Consolidate this with similar code in GenerateClass.

  // Collect declared and synthesized ivars in a small vector.
  llvm::SmallVector<ObjCIvarDecl*, 16> OIvars;
  CGM.getContext().ShallowCollectObjCIvars(OID, OIvars);

  for (unsigned i = 0, e = OIvars.size(); i != e; ++i) {
    ObjCIvarDecl *IVD = OIvars[i];
    // Ignore unnamed bit-fields.
    if (!IVD->getDeclName())
      continue;
    Ivar[0] = EmitIvarOffsetVar(ID->getClassInterface(), IVD,
                                ComputeIvarBaseOffset(CGM, ID, IVD));
    Ivar[1] = GetMethodVarName(IVD->getIdentifier());
    Ivar[2] = GetMethodVarType(IVD);
    const llvm::Type *FieldTy =
      CGM.getTypes().ConvertTypeForMem(IVD->getType());
    unsigned Size = CGM.getTargetData().getTypeAllocSize(FieldTy);
    unsigned Align = CGM.getContext().getPreferredTypeAlign(
      IVD->getType().getTypePtr()) >> 3;
    Align = llvm::Log2_32(Align);
    Ivar[3] = llvm::ConstantInt::get(ObjCTypes.IntTy, Align);
    // NOTE. Size of a bitfield does not match gcc's, because of the
    // way bitfields are treated special in each. But I am told that
    // 'size' for bitfield ivars is ignored by the runtime so it does
    // not matter.  If it matters, there is enough info to get the
    // bitfield right!
    Ivar[4] = llvm::ConstantInt::get(ObjCTypes.IntTy, Size);
    Ivars.push_back(llvm::ConstantStruct::get(ObjCTypes.IvarnfABITy, Ivar));
  }
  // Return null for empty list.
  if (Ivars.empty())
    return llvm::Constant::getNullValue(ObjCTypes.IvarListnfABIPtrTy);
  std::vector<llvm::Constant*> Values(3);
  unsigned Size = CGM.getTargetData().getTypeAllocSize(ObjCTypes.IvarnfABITy);
  Values[0] = llvm::ConstantInt::get(ObjCTypes.IntTy, Size);
  Values[1] = llvm::ConstantInt::get(ObjCTypes.IntTy, Ivars.size());
  llvm::ArrayType *AT = llvm::ArrayType::get(ObjCTypes.IvarnfABITy,
                                             Ivars.size());
  Values[2] = llvm::ConstantArray::get(AT, Ivars);
  llvm::Constant *Init = llvm::ConstantStruct::get(VMContext, Values);
  const char *Prefix = "\01l_OBJC_$_INSTANCE_VARIABLES_";
  llvm::GlobalVariable *GV =
    new llvm::GlobalVariable(CGM.getModule(), Init->getType(), false,
                             llvm::GlobalValue::InternalLinkage,
                             Init,
                             Prefix + OID->getNameAsString());
  GV->setAlignment(
    CGM.getTargetData().getPrefTypeAlignment(Init->getType()));
  GV->setSection("__DATA, __objc_const");

  CGM.AddUsedGlobal(GV);
  return llvm::ConstantExpr::getBitCast(GV, ObjCTypes.IvarListnfABIPtrTy);
}

llvm::Constant *CGObjCNonFragileABIMac::GetOrEmitProtocolRef(
  const ObjCProtocolDecl *PD) {
  llvm::GlobalVariable *&Entry = Protocols[PD->getIdentifier()];

  if (!Entry) {
    // We use the initializer as a marker of whether this is a forward
    // reference or not. At module finalization we add the empty
    // contents for protocols which were referenced but never defined.
    Entry =
      new llvm::GlobalVariable(CGM.getModule(), ObjCTypes.ProtocolnfABITy, false,
                               llvm::GlobalValue::ExternalLinkage,
                               0,
                               "\01l_OBJC_PROTOCOL_$_" + PD->getNameAsString());
    Entry->setSection("__DATA,__datacoal_nt,coalesced");
  }

  return Entry;
}

/// GetOrEmitProtocol - Generate the protocol meta-data:
/// @code
/// struct _protocol_t {
///   id isa;  // NULL
///   const char * const protocol_name;
///   const struct _protocol_list_t * protocol_list; // super protocols
///   const struct method_list_t * const instance_methods;
///   const struct method_list_t * const class_methods;
///   const struct method_list_t *optionalInstanceMethods;
///   const struct method_list_t *optionalClassMethods;
///   const struct _prop_list_t * properties;
///   const uint32_t size;  // sizeof(struct _protocol_t)
///   const uint32_t flags;  // = 0
/// }
/// @endcode
///

llvm::Constant *CGObjCNonFragileABIMac::GetOrEmitProtocol(
  const ObjCProtocolDecl *PD) {
  llvm::GlobalVariable *&Entry = Protocols[PD->getIdentifier()];

  // Early exit if a defining object has already been generated.
  if (Entry && Entry->hasInitializer())
    return Entry;

  const char *ProtocolName = PD->getNameAsCString();

  // Construct method lists.
  std::vector<llvm::Constant*> InstanceMethods, ClassMethods;
  std::vector<llvm::Constant*> OptInstanceMethods, OptClassMethods;
  for (ObjCProtocolDecl::instmeth_iterator
         i = PD->instmeth_begin(), e = PD->instmeth_end(); i != e; ++i) {
    ObjCMethodDecl *MD = *i;
    llvm::Constant *C = GetMethodDescriptionConstant(MD);
    if (MD->getImplementationControl() == ObjCMethodDecl::Optional) {
      OptInstanceMethods.push_back(C);
    } else {
      InstanceMethods.push_back(C);
    }
  }

  for (ObjCProtocolDecl::classmeth_iterator
         i = PD->classmeth_begin(), e = PD->classmeth_end(); i != e; ++i) {
    ObjCMethodDecl *MD = *i;
    llvm::Constant *C = GetMethodDescriptionConstant(MD);
    if (MD->getImplementationControl() == ObjCMethodDecl::Optional) {
      OptClassMethods.push_back(C);
    } else {
      ClassMethods.push_back(C);
    }
  }

  std::vector<llvm::Constant*> Values(10);
  // isa is NULL
  Values[0] = llvm::Constant::getNullValue(ObjCTypes.ObjectPtrTy);
  Values[1] = GetClassName(PD->getIdentifier());
  Values[2] = EmitProtocolList(
    "\01l_OBJC_$_PROTOCOL_REFS_" + PD->getNameAsString(),
    PD->protocol_begin(),
    PD->protocol_end());

  Values[3] = EmitMethodList("\01l_OBJC_$_PROTOCOL_INSTANCE_METHODS_"
                             + PD->getNameAsString(),
                             "__DATA, __objc_const",
                             InstanceMethods);
  Values[4] = EmitMethodList("\01l_OBJC_$_PROTOCOL_CLASS_METHODS_"
                             + PD->getNameAsString(),
                             "__DATA, __objc_const",
                             ClassMethods);
  Values[5] = EmitMethodList("\01l_OBJC_$_PROTOCOL_INSTANCE_METHODS_OPT_"
                             + PD->getNameAsString(),
                             "__DATA, __objc_const",
                             OptInstanceMethods);
  Values[6] = EmitMethodList("\01l_OBJC_$_PROTOCOL_CLASS_METHODS_OPT_"
                             + PD->getNameAsString(),
                             "__DATA, __objc_const",
                             OptClassMethods);
  Values[7] = EmitPropertyList("\01l_OBJC_$_PROP_LIST_" + PD->getNameAsString(),
                               0, PD, ObjCTypes);
  uint32_t Size =
    CGM.getTargetData().getTypeAllocSize(ObjCTypes.ProtocolnfABITy);
  Values[8] = llvm::ConstantInt::get(ObjCTypes.IntTy, Size);
  Values[9] = llvm::Constant::getNullValue(ObjCTypes.IntTy);
  llvm::Constant *Init = llvm::ConstantStruct::get(ObjCTypes.ProtocolnfABITy,
                                                   Values);

  if (Entry) {
    // Already created, fix the linkage and update the initializer.
    Entry->setLinkage(llvm::GlobalValue::WeakAnyLinkage);
    Entry->setInitializer(Init);
  } else {
    Entry =
      new llvm::GlobalVariable(CGM.getModule(), ObjCTypes.ProtocolnfABITy, false,
                               llvm::GlobalValue::WeakAnyLinkage,
                               Init,
                               std::string("\01l_OBJC_PROTOCOL_$_")+ProtocolName);
    Entry->setAlignment(
      CGM.getTargetData().getPrefTypeAlignment(ObjCTypes.ProtocolnfABITy));
    Entry->setSection("__DATA,__datacoal_nt,coalesced");
  }
  Entry->setVisibility(llvm::GlobalValue::HiddenVisibility);
  CGM.AddUsedGlobal(Entry);

  // Use this protocol meta-data to build protocol list table in section
  // __DATA, __objc_protolist
  llvm::GlobalVariable *PTGV = new llvm::GlobalVariable(
    CGM.getModule(),
    ObjCTypes.ProtocolnfABIPtrTy, false,
    llvm::GlobalValue::WeakAnyLinkage,
    Entry,
    std::string("\01l_OBJC_LABEL_PROTOCOL_$_")
    +ProtocolName);
  PTGV->setAlignment(
    CGM.getTargetData().getPrefTypeAlignment(ObjCTypes.ProtocolnfABIPtrTy));
  PTGV->setSection("__DATA, __objc_protolist, coalesced, no_dead_strip");
  PTGV->setVisibility(llvm::GlobalValue::HiddenVisibility);
  CGM.AddUsedGlobal(PTGV);
  return Entry;
}

/// EmitProtocolList - Generate protocol list meta-data:
/// @code
/// struct _protocol_list_t {
///   long protocol_count;   // Note, this is 32/64 bit
///   struct _protocol_t[protocol_count];
/// }
/// @endcode
///
llvm::Constant *
CGObjCNonFragileABIMac::EmitProtocolList(const std::string &Name,
                                         ObjCProtocolDecl::protocol_iterator begin,
                                         ObjCProtocolDecl::protocol_iterator end) {
  std::vector<llvm::Constant*> ProtocolRefs;

  // Just return null for empty protocol lists
  if (begin == end)
    return llvm::Constant::getNullValue(ObjCTypes.ProtocolListnfABIPtrTy);

  // FIXME: We shouldn't need to do this lookup here, should we?
  llvm::GlobalVariable *GV = CGM.getModule().getGlobalVariable(Name, true);
  if (GV)
    return llvm::ConstantExpr::getBitCast(GV,
                                          ObjCTypes.ProtocolListnfABIPtrTy);

  for (; begin != end; ++begin)
    ProtocolRefs.push_back(GetProtocolRef(*begin));  // Implemented???

  // This list is null terminated.
  ProtocolRefs.push_back(llvm::Constant::getNullValue(
                           ObjCTypes.ProtocolnfABIPtrTy));

  std::vector<llvm::Constant*> Values(2);
  Values[0] =
    llvm::ConstantInt::get(ObjCTypes.LongTy, ProtocolRefs.size() - 1);
  Values[1] =
    llvm::ConstantArray::get(
      llvm::ArrayType::get(ObjCTypes.ProtocolnfABIPtrTy,
                           ProtocolRefs.size()),
      ProtocolRefs);

  llvm::Constant *Init = llvm::ConstantStruct::get(VMContext, Values);
  GV = new llvm::GlobalVariable(CGM.getModule(), Init->getType(), false,
                                llvm::GlobalValue::InternalLinkage,
                                Init,
                                Name);
  GV->setSection("__DATA, __objc_const");
  GV->setAlignment(
    CGM.getTargetData().getPrefTypeAlignment(Init->getType()));
  CGM.AddUsedGlobal(GV);
  return llvm::ConstantExpr::getBitCast(GV,
                                        ObjCTypes.ProtocolListnfABIPtrTy);
}

/// GetMethodDescriptionConstant - This routine build following meta-data:
/// struct _objc_method {
///   SEL _cmd;
///   char *method_type;
///   char *_imp;
/// }

llvm::Constant *
CGObjCNonFragileABIMac::GetMethodDescriptionConstant(const ObjCMethodDecl *MD) {
  std::vector<llvm::Constant*> Desc(3);
  Desc[0] =
    llvm::ConstantExpr::getBitCast(GetMethodVarName(MD->getSelector()),
                                   ObjCTypes.SelectorPtrTy);
  Desc[1] = GetMethodVarType(MD);
  // Protocol methods have no implementation. So, this entry is always NULL.
  Desc[2] = llvm::Constant::getNullValue(ObjCTypes.Int8PtrTy);
  return llvm::ConstantStruct::get(ObjCTypes.MethodTy, Desc);
}

/// EmitObjCValueForIvar - Code Gen for nonfragile ivar reference.
/// This code gen. amounts to generating code for:
/// @code
/// (type *)((char *)base + _OBJC_IVAR_$_.ivar;
/// @encode
///
LValue CGObjCNonFragileABIMac::EmitObjCValueForIvar(
  CodeGen::CodeGenFunction &CGF,
  QualType ObjectTy,
  llvm::Value *BaseValue,
  const ObjCIvarDecl *Ivar,
  unsigned CVRQualifiers) {
  const ObjCInterfaceDecl *ID = ObjectTy->getAsObjCInterfaceType()->getDecl();
  return EmitValueForIvarAtOffset(CGF, ID, BaseValue, Ivar, CVRQualifiers,
                                  EmitIvarOffset(CGF, ID, Ivar));
}

llvm::Value *CGObjCNonFragileABIMac::EmitIvarOffset(
  CodeGen::CodeGenFunction &CGF,
  const ObjCInterfaceDecl *Interface,
  const ObjCIvarDecl *Ivar) {
  return CGF.Builder.CreateLoad(ObjCIvarOffsetVariable(Interface, Ivar),
                                false, "ivar");
}

CodeGen::RValue CGObjCNonFragileABIMac::EmitMessageSend(
  CodeGen::CodeGenFunction &CGF,
  QualType ResultType,
  Selector Sel,
  llvm::Value *Receiver,
  QualType Arg0Ty,
  bool IsSuper,
  const CallArgList &CallArgs) {
  // FIXME. Even though IsSuper is passes. This function doese not handle calls
  // to 'super' receivers.
  CodeGenTypes &Types = CGM.getTypes();
  llvm::Value *Arg0 = Receiver;
  if (!IsSuper)
    Arg0 = CGF.Builder.CreateBitCast(Arg0, ObjCTypes.ObjectPtrTy, "tmp");

  // Find the message function name.
  // FIXME. This is too much work to get the ABI-specific result type needed to
  // find the message name.
  const CGFunctionInfo &FnInfo = Types.getFunctionInfo(ResultType,
                                                       llvm::SmallVector<QualType, 16>());
  llvm::Constant *Fn = 0;
  std::string Name("\01l_");
  if (CGM.ReturnTypeUsesSret(FnInfo)) {
#if 0
    // unlike what is documented. gcc never generates this API!!
    if (Receiver->getType() == ObjCTypes.ObjectPtrTy) {
      Fn = ObjCTypes.getMessageSendIdStretFixupFn();
      // FIXME. Is there a better way of getting these names.
      // They are available in RuntimeFunctions vector pair.
      Name += "objc_msgSendId_stret_fixup";
    } else
#endif
      if (IsSuper) {
        Fn = ObjCTypes.getMessageSendSuper2StretFixupFn();
        Name += "objc_msgSendSuper2_stret_fixup";
      } else {
        Fn = ObjCTypes.getMessageSendStretFixupFn();
        Name += "objc_msgSend_stret_fixup";
      }
  } else if (!IsSuper && ResultType->isFloatingType()) {
    if (ResultType->isSpecificBuiltinType(BuiltinType::LongDouble)) {
      Fn = ObjCTypes.getMessageSendFpretFixupFn();
      Name += "objc_msgSend_fpret_fixup";
    } else {
      Fn = ObjCTypes.getMessageSendFixupFn();
      Name += "objc_msgSend_fixup";
    }
  } else {
#if 0
// unlike what is documented. gcc never generates this API!!
    if (Receiver->getType() == ObjCTypes.ObjectPtrTy) {
      Fn = ObjCTypes.getMessageSendIdFixupFn();
      Name += "objc_msgSendId_fixup";
    } else
#endif
      if (IsSuper) {
        Fn = ObjCTypes.getMessageSendSuper2FixupFn();
        Name += "objc_msgSendSuper2_fixup";
      } else {
        Fn = ObjCTypes.getMessageSendFixupFn();
        Name += "objc_msgSend_fixup";
      }
  }
  assert(Fn && "CGObjCNonFragileABIMac::EmitMessageSend");
  Name += '_';
  std::string SelName(Sel.getAsString());
  // Replace all ':' in selector name with '_'  ouch!
  for(unsigned i = 0; i < SelName.size(); i++)
    if (SelName[i] == ':')
      SelName[i] = '_';
  Name += SelName;
  llvm::GlobalVariable *GV = CGM.getModule().getGlobalVariable(Name);
  if (!GV) {
    // Build message ref table entry.
    std::vector<llvm::Constant*> Values(2);
    Values[0] = Fn;
    Values[1] = GetMethodVarName(Sel);
    llvm::Constant *Init = llvm::ConstantStruct::get(VMContext, Values);
    GV =  new llvm::GlobalVariable(CGM.getModule(), Init->getType(), false,
                                   llvm::GlobalValue::WeakAnyLinkage,
                                   Init,
                                   Name);
    GV->setVisibility(llvm::GlobalValue::HiddenVisibility);
    GV->setAlignment(16);
    GV->setSection("__DATA, __objc_msgrefs, coalesced");
  }
  llvm::Value *Arg1 = CGF.Builder.CreateBitCast(GV, ObjCTypes.MessageRefPtrTy);

  CallArgList ActualArgs;
  ActualArgs.push_back(std::make_pair(RValue::get(Arg0), Arg0Ty));
  ActualArgs.push_back(std::make_pair(RValue::get(Arg1),
                                      ObjCTypes.MessageRefCPtrTy));
  ActualArgs.insert(ActualArgs.end(), CallArgs.begin(), CallArgs.end());
  const CGFunctionInfo &FnInfo1 = Types.getFunctionInfo(ResultType, ActualArgs);
  llvm::Value *Callee = CGF.Builder.CreateStructGEP(Arg1, 0);
  Callee = CGF.Builder.CreateLoad(Callee);
  const llvm::FunctionType *FTy = Types.GetFunctionType(FnInfo1, true);
  Callee = CGF.Builder.CreateBitCast(Callee,
                                     llvm::PointerType::getUnqual(FTy));
  return CGF.EmitCall(FnInfo1, Callee, ActualArgs);
}

/// Generate code for a message send expression in the nonfragile abi.
CodeGen::RValue CGObjCNonFragileABIMac::GenerateMessageSend(
  CodeGen::CodeGenFunction &CGF,
  QualType ResultType,
  Selector Sel,
  llvm::Value *Receiver,
  bool IsClassMessage,
  const CallArgList &CallArgs,
  const ObjCMethodDecl *Method) {
  return LegacyDispatchedSelector(Sel)
    ? EmitLegacyMessageSend(CGF, ResultType, EmitSelector(CGF.Builder, Sel),
                            Receiver, CGF.getContext().getObjCIdType(),
                            false, CallArgs, ObjCTypes)
    : EmitMessageSend(CGF, ResultType, Sel,
                      Receiver, CGF.getContext().getObjCIdType(),
                      false, CallArgs);
}

llvm::GlobalVariable *
CGObjCNonFragileABIMac::GetClassGlobal(const std::string &Name) {
  llvm::GlobalVariable *GV = CGM.getModule().getGlobalVariable(Name);

  if (!GV) {
    GV = new llvm::GlobalVariable(CGM.getModule(), ObjCTypes.ClassnfABITy,
                                  false, llvm::GlobalValue::ExternalLinkage,
                                  0, Name);
  }

  return GV;
}

llvm::Value *CGObjCNonFragileABIMac::EmitClassRef(CGBuilderTy &Builder,
                                                  const ObjCInterfaceDecl *ID) {
  llvm::GlobalVariable *&Entry = ClassReferences[ID->getIdentifier()];

  if (!Entry) {
    std::string ClassName(getClassSymbolPrefix() + ID->getNameAsString());
    llvm::GlobalVariable *ClassGV = GetClassGlobal(ClassName);
    Entry =
      new llvm::GlobalVariable(CGM.getModule(), ObjCTypes.ClassnfABIPtrTy,
                               false, llvm::GlobalValue::InternalLinkage,
                               ClassGV,
                               "\01L_OBJC_CLASSLIST_REFERENCES_$_");
    Entry->setAlignment(
      CGM.getTargetData().getPrefTypeAlignment(
        ObjCTypes.ClassnfABIPtrTy));
    Entry->setSection("__DATA, __objc_classrefs, regular, no_dead_strip");
    CGM.AddUsedGlobal(Entry);
  }

  return Builder.CreateLoad(Entry, false, "tmp");
}

llvm::Value *
CGObjCNonFragileABIMac::EmitSuperClassRef(CGBuilderTy &Builder,
                                          const ObjCInterfaceDecl *ID) {
  llvm::GlobalVariable *&Entry = SuperClassReferences[ID->getIdentifier()];

  if (!Entry) {
    std::string ClassName(getClassSymbolPrefix() + ID->getNameAsString());
    llvm::GlobalVariable *ClassGV = GetClassGlobal(ClassName);
    Entry =
      new llvm::GlobalVariable(CGM.getModule(), ObjCTypes.ClassnfABIPtrTy,
                               false, llvm::GlobalValue::InternalLinkage,
                               ClassGV,
                               "\01L_OBJC_CLASSLIST_SUP_REFS_$_");
    Entry->setAlignment(
      CGM.getTargetData().getPrefTypeAlignment(
        ObjCTypes.ClassnfABIPtrTy));
    Entry->setSection("__DATA, __objc_superrefs, regular, no_dead_strip");
    CGM.AddUsedGlobal(Entry);
  }

  return Builder.CreateLoad(Entry, false, "tmp");
}

/// EmitMetaClassRef - Return a Value * of the address of _class_t
/// meta-data
///
llvm::Value *CGObjCNonFragileABIMac::EmitMetaClassRef(CGBuilderTy &Builder,
                                                      const ObjCInterfaceDecl *ID) {
  llvm::GlobalVariable * &Entry = MetaClassReferences[ID->getIdentifier()];
  if (Entry)
    return Builder.CreateLoad(Entry, false, "tmp");

  std::string MetaClassName(getMetaclassSymbolPrefix() + ID->getNameAsString());
  llvm::GlobalVariable *MetaClassGV = GetClassGlobal(MetaClassName);
  Entry =
    new llvm::GlobalVariable(CGM.getModule(), ObjCTypes.ClassnfABIPtrTy, false,
                             llvm::GlobalValue::InternalLinkage,
                             MetaClassGV,
                             "\01L_OBJC_CLASSLIST_SUP_REFS_$_");
  Entry->setAlignment(
    CGM.getTargetData().getPrefTypeAlignment(
      ObjCTypes.ClassnfABIPtrTy));

  Entry->setSection("__DATA, __objc_superrefs, regular, no_dead_strip");
  CGM.AddUsedGlobal(Entry);

  return Builder.CreateLoad(Entry, false, "tmp");
}

/// GetClass - Return a reference to the class for the given interface
/// decl.
llvm::Value *CGObjCNonFragileABIMac::GetClass(CGBuilderTy &Builder,
                                              const ObjCInterfaceDecl *ID) {
  return EmitClassRef(Builder, ID);
}

/// Generates a message send where the super is the receiver.  This is
/// a message send to self with special delivery semantics indicating
/// which class's method should be called.
CodeGen::RValue
CGObjCNonFragileABIMac::GenerateMessageSendSuper(CodeGen::CodeGenFunction &CGF,
                                                 QualType ResultType,
                                                 Selector Sel,
                                                 const ObjCInterfaceDecl *Class,
                                                 bool isCategoryImpl,
                                                 llvm::Value *Receiver,
                                                 bool IsClassMessage,
                                                 const CodeGen::CallArgList &CallArgs) {
  // ...
  // Create and init a super structure; this is a (receiver, class)
  // pair we will pass to objc_msgSendSuper.
  llvm::Value *ObjCSuper =
    CGF.Builder.CreateAlloca(ObjCTypes.SuperTy, 0, "objc_super");

  llvm::Value *ReceiverAsObject =
    CGF.Builder.CreateBitCast(Receiver, ObjCTypes.ObjectPtrTy);
  CGF.Builder.CreateStore(ReceiverAsObject,
                          CGF.Builder.CreateStructGEP(ObjCSuper, 0));

  // If this is a class message the metaclass is passed as the target.
  llvm::Value *Target;
  if (IsClassMessage) {
    if (isCategoryImpl) {
      // Message sent to "super' in a class method defined in
      // a category implementation.
      Target = EmitClassRef(CGF.Builder, Class);
      Target = CGF.Builder.CreateStructGEP(Target, 0);
      Target = CGF.Builder.CreateLoad(Target);
    } else
      Target = EmitMetaClassRef(CGF.Builder, Class);
  } else
    Target = EmitSuperClassRef(CGF.Builder, Class);

  // FIXME: We shouldn't need to do this cast, rectify the ASTContext and
  // ObjCTypes types.
  const llvm::Type *ClassTy =
    CGM.getTypes().ConvertType(CGF.getContext().getObjCClassType());
  Target = CGF.Builder.CreateBitCast(Target, ClassTy);
  CGF.Builder.CreateStore(Target,
                          CGF.Builder.CreateStructGEP(ObjCSuper, 1));

  return (LegacyDispatchedSelector(Sel))
    ? EmitLegacyMessageSend(CGF, ResultType,EmitSelector(CGF.Builder, Sel),
                            ObjCSuper, ObjCTypes.SuperPtrCTy,
                            true, CallArgs,
                            ObjCTypes)
    : EmitMessageSend(CGF, ResultType, Sel,
                      ObjCSuper, ObjCTypes.SuperPtrCTy,
                      true, CallArgs);
}

llvm::Value *CGObjCNonFragileABIMac::EmitSelector(CGBuilderTy &Builder,
                                                  Selector Sel) {
  llvm::GlobalVariable *&Entry = SelectorReferences[Sel];

  if (!Entry) {
    llvm::Constant *Casted =
      llvm::ConstantExpr::getBitCast(GetMethodVarName(Sel),
                                     ObjCTypes.SelectorPtrTy);
    Entry =
      new llvm::GlobalVariable(CGM.getModule(), ObjCTypes.SelectorPtrTy, false,
                               llvm::GlobalValue::InternalLinkage,
                               Casted, "\01L_OBJC_SELECTOR_REFERENCES_");
    Entry->setSection("__DATA, __objc_selrefs, literal_pointers, no_dead_strip");
    CGM.AddUsedGlobal(Entry);
  }

  return Builder.CreateLoad(Entry, false, "tmp");
}
/// EmitObjCIvarAssign - Code gen for assigning to a __strong object.
/// objc_assign_ivar (id src, id *dst)
///
void CGObjCNonFragileABIMac::EmitObjCIvarAssign(CodeGen::CodeGenFunction &CGF,
                                                llvm::Value *src, llvm::Value *dst)
{
  const llvm::Type * SrcTy = src->getType();
  if (!isa<llvm::PointerType>(SrcTy)) {
    unsigned Size = CGM.getTargetData().getTypeAllocSize(SrcTy);
    assert(Size <= 8 && "does not support size > 8");
    src = (Size == 4 ? CGF.Builder.CreateBitCast(src, ObjCTypes.IntTy)
           : CGF.Builder.CreateBitCast(src, ObjCTypes.LongTy));
    src = CGF.Builder.CreateIntToPtr(src, ObjCTypes.Int8PtrTy);
  }
  src = CGF.Builder.CreateBitCast(src, ObjCTypes.ObjectPtrTy);
  dst = CGF.Builder.CreateBitCast(dst, ObjCTypes.PtrObjectPtrTy);
  CGF.Builder.CreateCall2(ObjCTypes.getGcAssignIvarFn(),
                          src, dst, "assignivar");
  return;
}

/// EmitObjCStrongCastAssign - Code gen for assigning to a __strong cast object.
/// objc_assign_strongCast (id src, id *dst)
///
void CGObjCNonFragileABIMac::EmitObjCStrongCastAssign(
  CodeGen::CodeGenFunction &CGF,
  llvm::Value *src, llvm::Value *dst)
{
  const llvm::Type * SrcTy = src->getType();
  if (!isa<llvm::PointerType>(SrcTy)) {
    unsigned Size = CGM.getTargetData().getTypeAllocSize(SrcTy);
    assert(Size <= 8 && "does not support size > 8");
    src = (Size == 4 ? CGF.Builder.CreateBitCast(src, ObjCTypes.IntTy)
           : CGF.Builder.CreateBitCast(src, ObjCTypes.LongTy));
    src = CGF.Builder.CreateIntToPtr(src, ObjCTypes.Int8PtrTy);
  }
  src = CGF.Builder.CreateBitCast(src, ObjCTypes.ObjectPtrTy);
  dst = CGF.Builder.CreateBitCast(dst, ObjCTypes.PtrObjectPtrTy);
  CGF.Builder.CreateCall2(ObjCTypes.getGcAssignStrongCastFn(),
                          src, dst, "weakassign");
  return;
}

void CGObjCNonFragileABIMac::EmitGCMemmoveCollectable(
  CodeGen::CodeGenFunction &CGF,
  llvm::Value *DestPtr,
  llvm::Value *SrcPtr,
  unsigned long size) {
  SrcPtr = CGF.Builder.CreateBitCast(SrcPtr, ObjCTypes.Int8PtrTy);
  DestPtr = CGF.Builder.CreateBitCast(DestPtr, ObjCTypes.Int8PtrTy);
  llvm::Value *N = llvm::ConstantInt::get(ObjCTypes.LongTy, size);
  CGF.Builder.CreateCall3(ObjCTypes.GcMemmoveCollectableFn(),
                          DestPtr, SrcPtr, N);
  return;
}

/// EmitObjCWeakRead - Code gen for loading value of a __weak
/// object: objc_read_weak (id *src)
///
llvm::Value * CGObjCNonFragileABIMac::EmitObjCWeakRead(
  CodeGen::CodeGenFunction &CGF,
  llvm::Value *AddrWeakObj)
{
  const llvm::Type* DestTy =
    cast<llvm::PointerType>(AddrWeakObj->getType())->getElementType();
  AddrWeakObj = CGF.Builder.CreateBitCast(AddrWeakObj, ObjCTypes.PtrObjectPtrTy);
  llvm::Value *read_weak = CGF.Builder.CreateCall(ObjCTypes.getGcReadWeakFn(),
                                                  AddrWeakObj, "weakread");
  read_weak = CGF.Builder.CreateBitCast(read_weak, DestTy);
  return read_weak;
}

/// EmitObjCWeakAssign - Code gen for assigning to a __weak object.
/// objc_assign_weak (id src, id *dst)
///
void CGObjCNonFragileABIMac::EmitObjCWeakAssign(CodeGen::CodeGenFunction &CGF,
                                                llvm::Value *src, llvm::Value *dst)
{
  const llvm::Type * SrcTy = src->getType();
  if (!isa<llvm::PointerType>(SrcTy)) {
    unsigned Size = CGM.getTargetData().getTypeAllocSize(SrcTy);
    assert(Size <= 8 && "does not support size > 8");
    src = (Size == 4 ? CGF.Builder.CreateBitCast(src, ObjCTypes.IntTy)
           : CGF.Builder.CreateBitCast(src, ObjCTypes.LongTy));
    src = CGF.Builder.CreateIntToPtr(src, ObjCTypes.Int8PtrTy);
  }
  src = CGF.Builder.CreateBitCast(src, ObjCTypes.ObjectPtrTy);
  dst = CGF.Builder.CreateBitCast(dst, ObjCTypes.PtrObjectPtrTy);
  CGF.Builder.CreateCall2(ObjCTypes.getGcAssignWeakFn(),
                          src, dst, "weakassign");
  return;
}

/// EmitObjCGlobalAssign - Code gen for assigning to a __strong object.
/// objc_assign_global (id src, id *dst)
///
void CGObjCNonFragileABIMac::EmitObjCGlobalAssign(CodeGen::CodeGenFunction &CGF,
                                                  llvm::Value *src, llvm::Value *dst)
{
  const llvm::Type * SrcTy = src->getType();
  if (!isa<llvm::PointerType>(SrcTy)) {
    unsigned Size = CGM.getTargetData().getTypeAllocSize(SrcTy);
    assert(Size <= 8 && "does not support size > 8");
    src = (Size == 4 ? CGF.Builder.CreateBitCast(src, ObjCTypes.IntTy)
           : CGF.Builder.CreateBitCast(src, ObjCTypes.LongTy));
    src = CGF.Builder.CreateIntToPtr(src, ObjCTypes.Int8PtrTy);
  }
  src = CGF.Builder.CreateBitCast(src, ObjCTypes.ObjectPtrTy);
  dst = CGF.Builder.CreateBitCast(dst, ObjCTypes.PtrObjectPtrTy);
  CGF.Builder.CreateCall2(ObjCTypes.getGcAssignGlobalFn(),
                          src, dst, "globalassign");
  return;
}

void
CGObjCNonFragileABIMac::EmitTryOrSynchronizedStmt(CodeGen::CodeGenFunction &CGF,
                                                  const Stmt &S) {
  bool isTry = isa<ObjCAtTryStmt>(S);
  llvm::BasicBlock *TryBlock = CGF.createBasicBlock("try");
  llvm::BasicBlock *PrevLandingPad = CGF.getInvokeDest();
  llvm::BasicBlock *TryHandler = CGF.createBasicBlock("try.handler");
  llvm::BasicBlock *FinallyBlock = CGF.createBasicBlock("finally");
  llvm::BasicBlock *FinallyRethrow = CGF.createBasicBlock("finally.throw");
  llvm::BasicBlock *FinallyEnd = CGF.createBasicBlock("finally.end");

  // For @synchronized, call objc_sync_enter(sync.expr). The
  // evaluation of the expression must occur before we enter the
  // @synchronized. We can safely avoid a temp here because jumps into
  // @synchronized are illegal & this will dominate uses.
  llvm::Value *SyncArg = 0;
  if (!isTry) {
    SyncArg =
      CGF.EmitScalarExpr(cast<ObjCAtSynchronizedStmt>(S).getSynchExpr());
    SyncArg = CGF.Builder.CreateBitCast(SyncArg, ObjCTypes.ObjectPtrTy);
    CGF.Builder.CreateCall(ObjCTypes.getSyncEnterFn(), SyncArg);
  }

  // Push an EH context entry, used for handling rethrows and jumps
  // through finally.
  CGF.PushCleanupBlock(FinallyBlock);

  CGF.setInvokeDest(TryHandler);

  CGF.EmitBlock(TryBlock);
  CGF.EmitStmt(isTry ? cast<ObjCAtTryStmt>(S).getTryBody()
               : cast<ObjCAtSynchronizedStmt>(S).getSynchBody());
  CGF.EmitBranchThroughCleanup(FinallyEnd);

  // Emit the exception handler.

  CGF.EmitBlock(TryHandler);

  llvm::Value *llvm_eh_exception =
    CGF.CGM.getIntrinsic(llvm::Intrinsic::eh_exception);
  llvm::Value *llvm_eh_selector_i64 =
    CGF.CGM.getIntrinsic(llvm::Intrinsic::eh_selector_i64);
  llvm::Value *llvm_eh_typeid_for_i64 =
    CGF.CGM.getIntrinsic(llvm::Intrinsic::eh_typeid_for_i64);
  llvm::Value *Exc = CGF.Builder.CreateCall(llvm_eh_exception, "exc");
  llvm::Value *RethrowPtr = CGF.CreateTempAlloca(Exc->getType(), "_rethrow");

  llvm::SmallVector<llvm::Value*, 8> SelectorArgs;
  SelectorArgs.push_back(Exc);
  SelectorArgs.push_back(ObjCTypes.getEHPersonalityPtr());

  // Construct the lists of (type, catch body) to handle.
  llvm::SmallVector<std::pair<const ParmVarDecl*, const Stmt*>, 8> Handlers;
  bool HasCatchAll = false;
  if (isTry) {
    if (const ObjCAtCatchStmt* CatchStmt =
        cast<ObjCAtTryStmt>(S).getCatchStmts())  {
      for (; CatchStmt; CatchStmt = CatchStmt->getNextCatchStmt()) {
        const ParmVarDecl *CatchDecl = CatchStmt->getCatchParamDecl();
        Handlers.push_back(std::make_pair(CatchDecl, CatchStmt->getCatchBody()));

        // catch(...) always matches.
        if (!CatchDecl) {
          // Use i8* null here to signal this is a catch all, not a cleanup.
          llvm::Value *Null = llvm::Constant::getNullValue(ObjCTypes.Int8PtrTy);
          SelectorArgs.push_back(Null);
          HasCatchAll = true;
          break;
        }

        if (CatchDecl->getType()->isObjCIdType() ||
            CatchDecl->getType()->isObjCQualifiedIdType()) {
          llvm::Value *IDEHType =
            CGM.getModule().getGlobalVariable("OBJC_EHTYPE_id");
          if (!IDEHType)
            IDEHType =
              new llvm::GlobalVariable(CGM.getModule(), ObjCTypes.EHTypeTy,
                                       false,
                                       llvm::GlobalValue::ExternalLinkage,
                                       0, "OBJC_EHTYPE_id");
          SelectorArgs.push_back(IDEHType);
        } else {
          // All other types should be Objective-C interface pointer types.
          const ObjCObjectPointerType *PT =
            CatchDecl->getType()->getAsObjCObjectPointerType();
          assert(PT && "Invalid @catch type.");
          const ObjCInterfaceType *IT = PT->getInterfaceType();
          assert(IT && "Invalid @catch type.");
          llvm::Value *EHType = GetInterfaceEHType(IT->getDecl(), false);
          SelectorArgs.push_back(EHType);
        }
      }
    }
  }

  // We use a cleanup unless there was already a catch all.
  if (!HasCatchAll) {
    // Even though this is a cleanup, treat it as a catch all to avoid the C++
    // personality behavior of terminating the process if only cleanups are
    // found in the exception handling stack.
    SelectorArgs.push_back(llvm::Constant::getNullValue(ObjCTypes.Int8PtrTy));
    Handlers.push_back(std::make_pair((const ParmVarDecl*) 0, (const Stmt*) 0));
  }

  llvm::Value *Selector =
    CGF.Builder.CreateCall(llvm_eh_selector_i64,
                           SelectorArgs.begin(), SelectorArgs.end(),
                           "selector");
  for (unsigned i = 0, e = Handlers.size(); i != e; ++i) {
    const ParmVarDecl *CatchParam = Handlers[i].first;
    const Stmt *CatchBody = Handlers[i].second;

    llvm::BasicBlock *Next = 0;

    // The last handler always matches.
    if (i + 1 != e) {
      assert(CatchParam && "Only last handler can be a catch all.");

      llvm::BasicBlock *Match = CGF.createBasicBlock("match");
      Next = CGF.createBasicBlock("catch.next");
      llvm::Value *Id =
        CGF.Builder.CreateCall(llvm_eh_typeid_for_i64,
                               CGF.Builder.CreateBitCast(SelectorArgs[i+2],
                                                         ObjCTypes.Int8PtrTy));
      CGF.Builder.CreateCondBr(CGF.Builder.CreateICmpEQ(Selector, Id),
                               Match, Next);

      CGF.EmitBlock(Match);
    }

    if (CatchBody) {
      llvm::BasicBlock *MatchEnd = CGF.createBasicBlock("match.end");
      llvm::BasicBlock *MatchHandler = CGF.createBasicBlock("match.handler");

      // Cleanups must call objc_end_catch.
      //
      // FIXME: It seems incorrect for objc_begin_catch to be inside this
      // context, but this matches gcc.
      CGF.PushCleanupBlock(MatchEnd);
      CGF.setInvokeDest(MatchHandler);

      llvm::Value *ExcObject =
        CGF.Builder.CreateCall(ObjCTypes.getObjCBeginCatchFn(), Exc);

      // Bind the catch parameter if it exists.
      if (CatchParam) {
        ExcObject =
          CGF.Builder.CreateBitCast(ExcObject,
                                    CGF.ConvertType(CatchParam->getType()));
        // CatchParam is a ParmVarDecl because of the grammar
        // construction used to handle this, but for codegen purposes
        // we treat this as a local decl.
        CGF.EmitLocalBlockVarDecl(*CatchParam);
        CGF.Builder.CreateStore(ExcObject, CGF.GetAddrOfLocalVar(CatchParam));
      }

      CGF.ObjCEHValueStack.push_back(ExcObject);
      CGF.EmitStmt(CatchBody);
      CGF.ObjCEHValueStack.pop_back();

      CGF.EmitBranchThroughCleanup(FinallyEnd);

      CGF.EmitBlock(MatchHandler);

      llvm::Value *Exc = CGF.Builder.CreateCall(llvm_eh_exception, "exc");
      // We are required to emit this call to satisfy LLVM, even
      // though we don't use the result.
      llvm::SmallVector<llvm::Value*, 8> Args;
      Args.push_back(Exc);
      Args.push_back(ObjCTypes.getEHPersonalityPtr());
      Args.push_back(llvm::ConstantInt::get(llvm::Type::getInt32Ty(VMContext),
                                            0));
      CGF.Builder.CreateCall(llvm_eh_selector_i64, Args.begin(), Args.end());
      CGF.Builder.CreateStore(Exc, RethrowPtr);
      CGF.EmitBranchThroughCleanup(FinallyRethrow);

      CodeGenFunction::CleanupBlockInfo Info = CGF.PopCleanupBlock();

      CGF.EmitBlock(MatchEnd);

      // Unfortunately, we also have to generate another EH frame here
      // in case this throws.
      llvm::BasicBlock *MatchEndHandler =
        CGF.createBasicBlock("match.end.handler");
      llvm::BasicBlock *Cont = CGF.createBasicBlock("invoke.cont");
      CGF.Builder.CreateInvoke(ObjCTypes.getObjCEndCatchFn(),
                               Cont, MatchEndHandler,
                               Args.begin(), Args.begin());

      CGF.EmitBlock(Cont);
      if (Info.SwitchBlock)
        CGF.EmitBlock(Info.SwitchBlock);
      if (Info.EndBlock)
        CGF.EmitBlock(Info.EndBlock);

      CGF.EmitBlock(MatchEndHandler);
      Exc = CGF.Builder.CreateCall(llvm_eh_exception, "exc");
      // We are required to emit this call to satisfy LLVM, even
      // though we don't use the result.
      Args.clear();
      Args.push_back(Exc);
      Args.push_back(ObjCTypes.getEHPersonalityPtr());
      Args.push_back(llvm::ConstantInt::get(llvm::Type::getInt32Ty(VMContext),
                                            0));
      CGF.Builder.CreateCall(llvm_eh_selector_i64, Args.begin(), Args.end());
      CGF.Builder.CreateStore(Exc, RethrowPtr);
      CGF.EmitBranchThroughCleanup(FinallyRethrow);

      if (Next)
        CGF.EmitBlock(Next);
    } else {
      assert(!Next && "catchup should be last handler.");

      CGF.Builder.CreateStore(Exc, RethrowPtr);
      CGF.EmitBranchThroughCleanup(FinallyRethrow);
    }
  }

  // Pop the cleanup entry, the @finally is outside this cleanup
  // scope.
  CodeGenFunction::CleanupBlockInfo Info = CGF.PopCleanupBlock();
  CGF.setInvokeDest(PrevLandingPad);

  CGF.EmitBlock(FinallyBlock);

  if (isTry) {
    if (const ObjCAtFinallyStmt* FinallyStmt =
        cast<ObjCAtTryStmt>(S).getFinallyStmt())
      CGF.EmitStmt(FinallyStmt->getFinallyBody());
  } else {
    // Emit 'objc_sync_exit(expr)' as finally's sole statement for
    // @synchronized.
    CGF.Builder.CreateCall(ObjCTypes.getSyncExitFn(), SyncArg);
  }

  if (Info.SwitchBlock)
    CGF.EmitBlock(Info.SwitchBlock);
  if (Info.EndBlock)
    CGF.EmitBlock(Info.EndBlock);

  // Branch around the rethrow code.
  CGF.EmitBranch(FinallyEnd);

  CGF.EmitBlock(FinallyRethrow);
  CGF.Builder.CreateCall(ObjCTypes.getUnwindResumeOrRethrowFn(),
                         CGF.Builder.CreateLoad(RethrowPtr));
  CGF.Builder.CreateUnreachable();

  CGF.EmitBlock(FinallyEnd);
}

/// EmitThrowStmt - Generate code for a throw statement.
void CGObjCNonFragileABIMac::EmitThrowStmt(CodeGen::CodeGenFunction &CGF,
                                           const ObjCAtThrowStmt &S) {
  llvm::Value *Exception;
  if (const Expr *ThrowExpr = S.getThrowExpr()) {
    Exception = CGF.EmitScalarExpr(ThrowExpr);
  } else {
    assert((!CGF.ObjCEHValueStack.empty() && CGF.ObjCEHValueStack.back()) &&
           "Unexpected rethrow outside @catch block.");
    Exception = CGF.ObjCEHValueStack.back();
  }

  llvm::Value *ExceptionAsObject =
    CGF.Builder.CreateBitCast(Exception, ObjCTypes.ObjectPtrTy, "tmp");
  llvm::BasicBlock *InvokeDest = CGF.getInvokeDest();
  if (InvokeDest) {
    llvm::BasicBlock *Cont = CGF.createBasicBlock("invoke.cont");
    CGF.Builder.CreateInvoke(ObjCTypes.getExceptionThrowFn(),
                             Cont, InvokeDest,
                             &ExceptionAsObject, &ExceptionAsObject + 1);
    CGF.EmitBlock(Cont);
  } else
    CGF.Builder.CreateCall(ObjCTypes.getExceptionThrowFn(), ExceptionAsObject);
  CGF.Builder.CreateUnreachable();

  // Clear the insertion point to indicate we are in unreachable code.
  CGF.Builder.ClearInsertionPoint();
}

llvm::Value *
CGObjCNonFragileABIMac::GetInterfaceEHType(const ObjCInterfaceDecl *ID,
                                           bool ForDefinition) {
  llvm::GlobalVariable * &Entry = EHTypeReferences[ID->getIdentifier()];

  // If we don't need a definition, return the entry if found or check
  // if we use an external reference.
  if (!ForDefinition) {
    if (Entry)
      return Entry;

    // If this type (or a super class) has the __objc_exception__
    // attribute, emit an external reference.
    if (hasObjCExceptionAttribute(CGM.getContext(), ID))
      return Entry =
        new llvm::GlobalVariable(CGM.getModule(), ObjCTypes.EHTypeTy, false,
                                 llvm::GlobalValue::ExternalLinkage,
                                 0,
                                 (std::string("OBJC_EHTYPE_$_") +
                                  ID->getIdentifier()->getName()));
  }

  // Otherwise we need to either make a new entry or fill in the
  // initializer.
  assert((!Entry || !Entry->hasInitializer()) && "Duplicate EHType definition");
  std::string ClassName(getClassSymbolPrefix() + ID->getNameAsString());
  std::string VTableName = "objc_ehtype_vtable";
  llvm::GlobalVariable *VTableGV =
    CGM.getModule().getGlobalVariable(VTableName);
  if (!VTableGV)
    VTableGV = new llvm::GlobalVariable(CGM.getModule(), ObjCTypes.Int8PtrTy,
                                        false,
                                        llvm::GlobalValue::ExternalLinkage,
                                        0, VTableName);

  llvm::Value *VTableIdx = llvm::ConstantInt::get(llvm::Type::getInt32Ty(VMContext), 2);

  std::vector<llvm::Constant*> Values(3);
  Values[0] = llvm::ConstantExpr::getGetElementPtr(VTableGV, &VTableIdx, 1);
  Values[1] = GetClassName(ID->getIdentifier());
  Values[2] = GetClassGlobal(ClassName);
  llvm::Constant *Init =
    llvm::ConstantStruct::get(ObjCTypes.EHTypeTy, Values);

  if (Entry) {
    Entry->setInitializer(Init);
  } else {
    Entry = new llvm::GlobalVariable(CGM.getModule(), ObjCTypes.EHTypeTy, false,
                                     llvm::GlobalValue::WeakAnyLinkage,
                                     Init,
                                     (std::string("OBJC_EHTYPE_$_") +
                                      ID->getIdentifier()->getName()));
  }

  if (CGM.getLangOptions().getVisibilityMode() == LangOptions::Hidden)
    Entry->setVisibility(llvm::GlobalValue::HiddenVisibility);
  Entry->setAlignment(8);

  if (ForDefinition) {
    Entry->setSection("__DATA,__objc_const");
    Entry->setLinkage(llvm::GlobalValue::ExternalLinkage);
  } else {
    Entry->setSection("__DATA,__datacoal_nt,coalesced");
  }

  return Entry;
}

/* *** */

CodeGen::CGObjCRuntime *
CodeGen::CreateMacObjCRuntime(CodeGen::CodeGenModule &CGM) {
  return new CGObjCMac(CGM);
}

CodeGen::CGObjCRuntime *
CodeGen::CreateMacNonFragileABIObjCRuntime(CodeGen::CodeGenModule &CGM) {
  return new CGObjCNonFragileABIMac(CGM);
}
