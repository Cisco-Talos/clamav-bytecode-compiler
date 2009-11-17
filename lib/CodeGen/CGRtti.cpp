//===--- CGCXXRtti.cpp - Emit LLVM Code for C++ RTTI descriptors ----------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This contains code dealing with C++ code generation of RTTI descriptors.
//
//===----------------------------------------------------------------------===//

#include "CodeGenModule.h"
#include "clang/AST/RecordLayout.h"
using namespace clang;
using namespace CodeGen;

class RttiBuilder {
  CodeGenModule &CGM;  // Per-module state.
  llvm::LLVMContext &VMContext;
  const llvm::Type *Int8PtrTy;
  llvm::SmallSet<const CXXRecordDecl *, 16> SeenVBase;
  llvm::SmallSet<const CXXRecordDecl *, 32> SeenBase;
public:
  RttiBuilder(CodeGenModule &cgm)
    : CGM(cgm), VMContext(cgm.getModule().getContext()),
      Int8PtrTy(llvm::Type::getInt8PtrTy(VMContext)) { }

  /// BuildVtableRef - Build a reference to a vtable.
  llvm::Constant *BuildVtableRef(const char *Name) {
    // Build a descriptor for Name
    llvm::Constant *GV = CGM.getModule().getGlobalVariable(Name);
    if (GV)
      GV = llvm::ConstantExpr::getBitCast(GV,
                                          llvm::PointerType::get(Int8PtrTy, 0));
    else {
      llvm::GlobalVariable::LinkageTypes linktype;
      linktype = llvm::GlobalValue::ExternalLinkage;
      GV = new llvm::GlobalVariable(CGM.getModule(), Int8PtrTy,
                                    true, linktype, 0, Name);
    }
    llvm::Constant *C;
    C = llvm::ConstantInt::get(llvm::Type::getInt64Ty(VMContext), 2);
    C = llvm::ConstantExpr::getInBoundsGetElementPtr(GV, &C, 1);
    return llvm::ConstantExpr::getBitCast(C, Int8PtrTy);
  }

  llvm::Constant *BuildName(const CXXRecordDecl *RD) {
    llvm::SmallString<256> OutName;
    llvm::raw_svector_ostream Out(OutName);
    mangleCXXRttiName(CGM.getMangleContext(),
                      CGM.getContext().getTagDeclType(RD), Out);

    llvm::GlobalVariable::LinkageTypes linktype;
    linktype = llvm::GlobalValue::LinkOnceODRLinkage;

    llvm::Constant *C;
    C = llvm::ConstantArray::get(VMContext, Out.str().substr(4));

    llvm::Constant *s = new llvm::GlobalVariable(CGM.getModule(), C->getType(),
                                                 true, linktype, C,
                                                 Out.str());
    s = llvm::ConstantExpr::getBitCast(s, Int8PtrTy);
    return s;
  };

  /// - BuildFlags - Build a psABI __flags value for __vmi_class_type_info.
  llvm::Constant *BuildFlags(int f) {
    return llvm::ConstantInt::get(llvm::Type::getInt32Ty(VMContext), f);
  }

  /// BuildBaseCount - Build a psABI __base_count value for
  /// __vmi_class_type_info.
  llvm::Constant *BuildBaseCount(unsigned c) {
    return llvm::ConstantInt::get(llvm::Type::getInt32Ty(VMContext), c);
  }

  llvm::Constant *BuildTypeRef(QualType Ty) {
    const llvm::Type *Int8PtrTy = llvm::Type::getInt8PtrTy(VMContext);
    llvm::Constant *C;

    if (!CGM.getContext().getLangOptions().Rtti)
      return llvm::Constant::getNullValue(Int8PtrTy);

    llvm::SmallString<256> OutName;
    llvm::raw_svector_ostream Out(OutName);
    mangleCXXRtti(CGM.getMangleContext(), Ty, Out);

    C = CGM.getModule().getGlobalVariable(Out.str());
    if (C)
      return llvm::ConstantExpr::getBitCast(C, Int8PtrTy);

    llvm::GlobalVariable::LinkageTypes linktype;
    linktype = llvm::GlobalValue::ExternalLinkage;;

    C = new llvm::GlobalVariable(CGM.getModule(), Int8PtrTy, true, linktype,
                                 0, Out.str());
    return llvm::ConstantExpr::getBitCast(C, Int8PtrTy);
  }

  llvm::Constant *Buildclass_type_infoRef(const CXXRecordDecl *RD) {
    return BuildTypeRef(CGM.getContext().getTagDeclType(RD));
  }

  /// CalculateFlags - Calculate the flags for the __vmi_class_type_info
  /// datastructure.  1 for non-diamond repeated inheritance, 2 for a dimond
  /// shaped class.
  int CalculateFlags(const CXXRecordDecl*RD) {
    int flags = 0;
    if (SeenBase.count(RD))
      flags |= 1;
    else
      SeenBase.insert(RD);
    for (CXXRecordDecl::base_class_const_iterator i = RD->bases_begin(),
           e = RD->bases_end(); i != e; ++i) {
      const CXXRecordDecl *Base =
        cast<CXXRecordDecl>(i->getType()->getAs<RecordType>()->getDecl());
      if (i->isVirtual()) {
        if (SeenVBase.count(Base))
          flags |= 2;
        else
          SeenVBase.insert(Base);
      }
      flags |= CalculateFlags(Base);
    }
    return flags;
  }

  bool SimpleInheritance(const CXXRecordDecl *RD) {
    if (RD->getNumBases() != 1)
      return false;
    CXXRecordDecl::base_class_const_iterator i = RD->bases_begin();
    if (i->isVirtual())
      return false;
    if (i->getAccessSpecifier() != AS_public)
      return false;

    const ASTRecordLayout &Layout = CGM.getContext().getASTRecordLayout(RD);
    const CXXRecordDecl *Base =
      cast<CXXRecordDecl>(i->getType()->getAs<RecordType>()->getDecl());
    if (Layout.getBaseClassOffset(Base) != 0)
      return false;
    return true;
  }

  llvm::Constant *Buildclass_type_info(const CXXRecordDecl *RD) {
    const llvm::Type *Int8PtrTy = llvm::Type::getInt8PtrTy(VMContext);
    llvm::Constant *C;

    if (!CGM.getContext().getLangOptions().Rtti)
      return llvm::Constant::getNullValue(Int8PtrTy);

    llvm::SmallString<256> OutName;
    llvm::raw_svector_ostream Out(OutName);
    mangleCXXRtti(CGM.getMangleContext(), CGM.getContext().getTagDeclType(RD),
                  Out);

    llvm::GlobalVariable *GV;
    GV = CGM.getModule().getGlobalVariable(Out.str());
    if (GV && !GV->isDeclaration())
      return llvm::ConstantExpr::getBitCast(GV, Int8PtrTy);

    llvm::GlobalVariable::LinkageTypes linktype;
    linktype = llvm::GlobalValue::LinkOnceODRLinkage;
    std::vector<llvm::Constant *> info;

    bool simple = false;
    if (RD->getNumBases() == 0)
      C = BuildVtableRef("_ZTVN10__cxxabiv117__class_type_infoE");
    else if (SimpleInheritance(RD)) {
      simple = true;
      C = BuildVtableRef("_ZTVN10__cxxabiv120__si_class_type_infoE");
    } else
      C = BuildVtableRef("_ZTVN10__cxxabiv121__vmi_class_type_infoE");
    info.push_back(C);
    info.push_back(BuildName(RD));

    // If we have no bases, there are no more fields.
    if (RD->getNumBases()) {
      if (!simple) {
        info.push_back(BuildFlags(CalculateFlags(RD)));
        info.push_back(BuildBaseCount(RD->getNumBases()));
      }

      const ASTRecordLayout &Layout = CGM.getContext().getASTRecordLayout(RD);
      for (CXXRecordDecl::base_class_const_iterator i = RD->bases_begin(),
             e = RD->bases_end(); i != e; ++i) {
        const CXXRecordDecl *Base =
          cast<CXXRecordDecl>(i->getType()->getAs<RecordType>()->getDecl());
        info.push_back(CGM.GenerateRttiRef(Base));
        if (simple)
          break;
        int64_t offset;
        if (!i->isVirtual())
          offset = Layout.getBaseClassOffset(Base)/8;
        else
          offset = CGM.getVtableInfo().getVirtualBaseOffsetIndex(RD, Base);
        offset <<= 8;
        // Now set the flags.
        offset += i->isVirtual() ? 1 : 0;;
        offset += i->getAccessSpecifier() == AS_public ? 2 : 0;
        const llvm::Type *LongTy =
          CGM.getTypes().ConvertType(CGM.getContext().LongTy);
        C = llvm::ConstantInt::get(LongTy, offset);
        info.push_back(C);
      }
    }

    std::vector<const llvm::Type *> Types(info.size());
    for (unsigned i=0; i<info.size(); ++i)
      Types[i] = info[i]->getType();
    // llvm::StructType *Ty = llvm::StructType::get(VMContext, Types, true);
    C = llvm::ConstantStruct::get(VMContext, &info[0], info.size(), false);

    if (GV == 0)
      GV = new llvm::GlobalVariable(CGM.getModule(), C->getType(), true, linktype,
                                    C, Out.str());
    else {
      llvm::GlobalVariable *OGV = GV;
      GV = new llvm::GlobalVariable(CGM.getModule(), C->getType(), true, linktype,
                                    C, Out.str());
      GV->takeName(OGV);
      llvm::Constant *NewPtr = llvm::ConstantExpr::getBitCast(GV, OGV->getType());
      OGV->replaceAllUsesWith(NewPtr);
      OGV->eraseFromParent();
    }
    return llvm::ConstantExpr::getBitCast(GV, Int8PtrTy);

#if 0
    llvm::ArrayType *type = llvm::ArrayType::get(Int8PtrTy, info.size());
    C = llvm::ConstantArray::get(type, info);
    llvm::Constant *Rtti =
      new llvm::GlobalVariable(CGM.getModule(), type, true, linktype, C,
                               Out.str());
    Rtti = llvm::ConstantExpr::getBitCast(Rtti, Int8PtrTy);
    return Rtti;
#endif
  }

  llvm::Constant *BuildType(QualType Ty) {
    const clang::Type &Type
      = *CGM.getContext().getCanonicalType(Ty).getTypePtr();
    switch (Type.getTypeClass()) {
    default: {
      // FIXME: Add all the missing types, such as pointer, array...
      assert(0 && "typeid expression");
      const llvm::Type *Int8PtrTy = llvm::Type::getInt8PtrTy(VMContext);
      return llvm::Constant::getNullValue(Int8PtrTy);
    }

    case Type::Builtin: {
      // We expect all type_info objects for builtin types to be in the library.
      return BuildTypeRef(Ty);
    }
    }
  }
};

llvm::Constant *CodeGenModule::GenerateRttiRef(const CXXRecordDecl *RD) {
  RttiBuilder b(*this);

  return b.Buildclass_type_infoRef(RD);
}

llvm::Constant *CodeGenModule::GenerateRtti(const CXXRecordDecl *RD) {
  RttiBuilder b(*this);

  return b.Buildclass_type_info(RD);
}

llvm::Constant *CodeGenModule::GenerateRttiNonClass(QualType Ty) {
  RttiBuilder b(*this);

  return b.BuildType(Ty);
}
