//===--- CGCXXClass.cpp - Emit LLVM Code for C++ classes ------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This contains code dealing with C++ code generation of classes
//
//===----------------------------------------------------------------------===//

#include "CodeGenFunction.h"
#include "clang/AST/RecordLayout.h"
using namespace clang;
using namespace CodeGen;

static bool
GetNestedPaths(llvm::SmallVectorImpl<const CXXRecordDecl *> &NestedBasePaths,
               const CXXRecordDecl *ClassDecl,
               const CXXRecordDecl *BaseClassDecl) {
  for (CXXRecordDecl::base_class_const_iterator i = ClassDecl->bases_begin(),
      e = ClassDecl->bases_end(); i != e; ++i) {
    if (i->isVirtual())
      continue;
    const CXXRecordDecl *Base =
      cast<CXXRecordDecl>(i->getType()->getAs<RecordType>()->getDecl());
    if (Base == BaseClassDecl) {
      NestedBasePaths.push_back(BaseClassDecl);
      return true;
    }
  }
  // BaseClassDecl not an immediate base of ClassDecl.
  for (CXXRecordDecl::base_class_const_iterator i = ClassDecl->bases_begin(),
       e = ClassDecl->bases_end(); i != e; ++i) {
    if (i->isVirtual())
      continue;
    const CXXRecordDecl *Base =
      cast<CXXRecordDecl>(i->getType()->getAs<RecordType>()->getDecl());
    if (GetNestedPaths(NestedBasePaths, Base, BaseClassDecl)) {
      NestedBasePaths.push_back(Base);
      return true;
    }
  }
  return false;
}

static uint64_t ComputeBaseClassOffset(ASTContext &Context,
                                       const CXXRecordDecl *ClassDecl,
                                       const CXXRecordDecl *BaseClassDecl) {
    uint64_t Offset = 0;

    llvm::SmallVector<const CXXRecordDecl *, 16> NestedBasePaths;
    GetNestedPaths(NestedBasePaths, ClassDecl, BaseClassDecl);
    assert(NestedBasePaths.size() > 0 &&
           "AddressCXXOfBaseClass - inheritence path failed");
    NestedBasePaths.push_back(ClassDecl);
    
    for (unsigned i = NestedBasePaths.size() - 1; i > 0; i--) {
        const CXXRecordDecl *DerivedClass = NestedBasePaths[i];
        const CXXRecordDecl *BaseClass = NestedBasePaths[i-1];
        const ASTRecordLayout &Layout = 
            Context.getASTRecordLayout(DerivedClass);
        
        Offset += Layout.getBaseClassOffset(BaseClass) / 8;
    }
    
    return Offset;
}

llvm::Value *
CodeGenFunction::GetAddressCXXOfBaseClass(llvm::Value *BaseValue,
                                          const CXXRecordDecl *ClassDecl,
                                          const CXXRecordDecl *BaseClassDecl,
                                          bool NullCheckValue) {
  if (ClassDecl == BaseClassDecl)
    return BaseValue;


  uint64_t Offset = ComputeBaseClassOffset(getContext(), 
                                           ClassDecl, BaseClassDecl);

  const llvm::Type *LongTy = 
    CGM.getTypes().ConvertType(CGM.getContext().LongTy);
  const llvm::Type *Int8PtrTy = 
    llvm::PointerType::getUnqual(llvm::Type::getInt8Ty(VMContext));
  
  llvm::Value *OffsetVal = llvm::ConstantInt::get(LongTy, Offset);
  
  // Apply the offset.
  BaseValue = Builder.CreateBitCast(BaseValue, Int8PtrTy);
  BaseValue = Builder.CreateGEP(BaseValue, OffsetVal, "add.ptr");
  
  QualType BTy =
    getContext().getCanonicalType(
      getContext().getTypeDeclType(const_cast<CXXRecordDecl*>(BaseClassDecl)));
  
  // Cast back.
  const llvm::Type *BasePtr = llvm::PointerType::getUnqual(ConvertType(BTy));
  BaseValue = Builder.CreateBitCast(BaseValue, BasePtr);
  
  return BaseValue;
}
