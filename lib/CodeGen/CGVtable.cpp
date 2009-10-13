//===--- CGVtable.cpp - Emit LLVM Code for C++ vtables --------------------===//
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

#include "CodeGenModule.h"
#include "CodeGenFunction.h"

#include "clang/AST/RecordLayout.h"

using namespace clang;
using namespace CodeGen;

class VtableBuilder {
public:
  /// Index_t - Vtable index type.
  typedef uint64_t Index_t;
private:
  std::vector<llvm::Constant *> &methods;
  std::vector<llvm::Constant *> submethods;
  llvm::Type *Ptr8Ty;
  /// Class - The most derived class that this vtable is being built for.
  const CXXRecordDecl *Class;
  /// BLayout - Layout for the most derived class that this vtable is being
  /// built for.
  const ASTRecordLayout &BLayout;
  llvm::SmallSet<const CXXRecordDecl *, 32> IndirectPrimary;
  llvm::SmallSet<const CXXRecordDecl *, 32> SeenVBase;
  llvm::Constant *rtti;
  llvm::LLVMContext &VMContext;
  CodeGenModule &CGM;  // Per-module state.
  /// Index - Maps a method decl into a vtable index.  Useful for virtual
  /// dispatch codegen.
  llvm::DenseMap<const CXXMethodDecl *, Index_t> Index;
  llvm::DenseMap<const CXXMethodDecl *, Index_t> VCall;
  llvm::DenseMap<const CXXMethodDecl *, Index_t> VCallOffset;
  llvm::DenseMap<const CXXRecordDecl *, Index_t> VBIndex;
  typedef std::pair<Index_t, Index_t>  CallOffset;
  typedef llvm::DenseMap<const CXXMethodDecl *, CallOffset> Thunks_t;
  Thunks_t Thunks;
  typedef llvm::DenseMap<const CXXMethodDecl *,
                         std::pair<std::pair<CallOffset, CallOffset>,
                                   CanQualType> > CovariantThunks_t;
  CovariantThunks_t CovariantThunks;
  std::vector<Index_t> VCalls;
  typedef CXXRecordDecl::method_iterator method_iter;
  // FIXME: Linkage should follow vtable
  const bool Extern;
  const uint32_t LLVMPointerWidth;
  Index_t extra;
public:
  VtableBuilder(std::vector<llvm::Constant *> &meth,
                const CXXRecordDecl *c,
                CodeGenModule &cgm)
    : methods(meth), Class(c), BLayout(cgm.getContext().getASTRecordLayout(c)),
      rtti(cgm.GenerateRtti(c)), VMContext(cgm.getModule().getContext()),
      CGM(cgm), Extern(true),
      LLVMPointerWidth(cgm.getContext().Target.getPointerWidth(0)) {
    Ptr8Ty = llvm::PointerType::get(llvm::Type::getInt8Ty(VMContext), 0);
  }

  llvm::DenseMap<const CXXMethodDecl *, Index_t> &getIndex() { return Index; }
  llvm::DenseMap<const CXXRecordDecl *, Index_t> &getVBIndex()
    { return VBIndex; }

  llvm::Constant *wrap(Index_t i) {
    llvm::Constant *m;
    m = llvm::ConstantInt::get(llvm::Type::getInt64Ty(VMContext), i);
    return llvm::ConstantExpr::getIntToPtr(m, Ptr8Ty);
  }

  llvm::Constant *wrap(llvm::Constant *m) {
    return llvm::ConstantExpr::getBitCast(m, Ptr8Ty);
  }

  void GenerateVBaseOffsets(std::vector<llvm::Constant *> &offsets,
                            const CXXRecordDecl *RD, uint64_t Offset,
                            bool updateVBIndex) {
    for (CXXRecordDecl::base_class_const_iterator i = RD->bases_begin(),
           e = RD->bases_end(); i != e; ++i) {
      const CXXRecordDecl *Base =
        cast<CXXRecordDecl>(i->getType()->getAs<RecordType>()->getDecl());
      if (i->isVirtual() && !SeenVBase.count(Base)) {
        SeenVBase.insert(Base);
        int64_t BaseOffset = -(Offset/8) + BLayout.getVBaseClassOffset(Base)/8;
        llvm::Constant *m = wrap(BaseOffset);
        m = wrap((0?700:0) + BaseOffset);
        if (updateVBIndex)
          VBIndex[Base] = -(offsets.size()*LLVMPointerWidth/8)
            - 3*LLVMPointerWidth/8;
        offsets.push_back(m);
      }
      GenerateVBaseOffsets(offsets, Base, Offset, updateVBIndex);
    }
  }

  void StartNewTable() {
    SeenVBase.clear();
  }

  Index_t VBlookup(CXXRecordDecl *D, CXXRecordDecl *B);

  /// getVbaseOffset - Returns the index into the vtable for the virtual base
  /// offset for the given (B) virtual base of the derived class D.
  Index_t getVbaseOffset(QualType qB, QualType qD) {
    qD = qD->getAs<PointerType>()->getPointeeType();
    qB = qB->getAs<PointerType>()->getPointeeType();
    CXXRecordDecl *D = cast<CXXRecordDecl>(qD->getAs<RecordType>()->getDecl());
    CXXRecordDecl *B = cast<CXXRecordDecl>(qB->getAs<RecordType>()->getDecl());
    if (D != Class)
      return VBlookup(D, B);
    llvm::DenseMap<const CXXRecordDecl *, Index_t>::iterator i;
    i = VBIndex.find(B);
    if (i != VBIndex.end())
      return i->second;

    assert(false && "FIXME: Locate the containing virtual base first");
    return 0;
  }

  bool OverrideMethod(const CXXMethodDecl *MD, llvm::Constant *m,
                      bool MorallyVirtual, Index_t Offset) {
    typedef CXXMethodDecl::method_iterator meth_iter;

    // FIXME: Don't like the nested loops.  For very large inheritance
    // heirarchies we could have a table on the side with the final overridder
    // and just replace each instance of an overridden method once.  Would be
    // nice to measure the cost/benefit on real code.

    for (meth_iter mi = MD->begin_overridden_methods(),
           e = MD->end_overridden_methods();
         mi != e; ++mi) {
      const CXXMethodDecl *OMD = *mi;
      llvm::Constant *om;
      om = CGM.GetAddrOfFunction(OMD, Ptr8Ty);
      om = llvm::ConstantExpr::getBitCast(om, Ptr8Ty);

      for (Index_t i = 0, e = submethods.size();
           i != e; ++i) {
        // FIXME: begin_overridden_methods might be too lax, covariance */
        if (submethods[i] != om)
          continue;
        QualType nc_oret = OMD->getType()->getAs<FunctionType>()->getResultType();
        CanQualType oret = CGM.getContext().getCanonicalType(nc_oret);
        QualType nc_ret = MD->getType()->getAs<FunctionType>()->getResultType();
        CanQualType ret = CGM.getContext().getCanonicalType(nc_ret);
        CallOffset ReturnOffset = std::make_pair(0, 0);
        if (oret != ret) {
          // FIXME: calculate offsets for covariance
          Index_t nv = 0;
          if (CovariantThunks.count(OMD)) {
            oret = CovariantThunks[OMD].second;
            CovariantThunks.erase(OMD);
          }
          ReturnOffset = std::make_pair(nv, getVbaseOffset(oret, ret));
        }
        Index[MD] = i;
        submethods[i] = m;

        Thunks.erase(OMD);
        if (MorallyVirtual) {
          Index_t &idx = VCall[OMD];
          if (idx == 0) {
            VCallOffset[MD] = Offset/8;
            idx = VCalls.size()+1;
            VCalls.push_back(0);
          } else {
            VCallOffset[MD] = VCallOffset[OMD];
            VCalls[idx-1] = -VCallOffset[OMD] + Offset/8;
          }
          VCall[MD] = idx;
          CallOffset ThisOffset;
          // FIXME: calculate non-virtual offset
          ThisOffset = std::make_pair(0, -((idx+extra+2)*LLVMPointerWidth/8));
          if (ReturnOffset.first || ReturnOffset.second)
            CovariantThunks[MD] = std::make_pair(std::make_pair(ThisOffset,
                                                                ReturnOffset),
                                                 oret);
          else
            Thunks[MD] = ThisOffset;
          return true;
        }
#if 0
        // FIXME: finish off
        int64_t O = VCallOffset[OMD] - Offset/8;
        if (O) {
          Thunks[MD] = std::make_pair(O, 0);
        }
#endif
        return true;
      }
    }

    return false;
  }

  void InstallThunks() {
    for (Thunks_t::iterator i = Thunks.begin(), e = Thunks.end();
         i != e; ++i) {
      const CXXMethodDecl *MD = i->first;
      Index_t idx = Index[MD];
      Index_t nv_O = i->second.first;
      Index_t v_O = i->second.second;
      submethods[idx] = CGM.BuildThunk(MD, Extern, nv_O, v_O);
    }
    Thunks.clear();
    for (CovariantThunks_t::iterator i = CovariantThunks.begin(),
           e = CovariantThunks.end();
         i != e; ++i) {
      const CXXMethodDecl *MD = i->first;
      Index_t idx = Index[MD];
      Index_t nv_t = i->second.first.first.first;
      Index_t v_t = i->second.first.first.second;
      Index_t nv_r = i->second.first.second.first;
      Index_t v_r = i->second.first.second.second;
      submethods[idx] = CGM.BuildCovariantThunk(MD, Extern, nv_t, v_t, nv_r,
                                                v_r);
    }
    CovariantThunks.clear();
  }

  void OverrideMethods(std::vector<std::pair<const CXXRecordDecl *,
                       int64_t> > *Path, bool MorallyVirtual) {
      for (std::vector<std::pair<const CXXRecordDecl *,
             int64_t> >::reverse_iterator i =Path->rbegin(),
           e = Path->rend(); i != e; ++i) {
      const CXXRecordDecl *RD = i->first;
      int64_t Offset = i->second;
      for (method_iter mi = RD->method_begin(), me = RD->method_end(); mi != me;
           ++mi) {
        if (!mi->isVirtual())
          continue;

        const CXXMethodDecl *MD = *mi;
        llvm::Constant *m = 0;
        if (const CXXDestructorDecl *Dtor = dyn_cast<CXXDestructorDecl>(MD))
          m = wrap(CGM.GetAddrOfCXXDestructor(Dtor, Dtor_Complete));
        else {
          const FunctionProtoType *FPT = 
            MD->getType()->getAs<FunctionProtoType>();
          const llvm::Type *Ty =
            CGM.getTypes().GetFunctionType(CGM.getTypes().getFunctionInfo(MD),
                                           FPT->isVariadic());
          
          m = wrap(CGM.GetAddrOfFunction(MD, Ty));
        }

        OverrideMethod(MD, m, MorallyVirtual, Offset);
      }
    }
  }

  void AddMethod(const CXXMethodDecl *MD, bool MorallyVirtual, Index_t Offset) {
    llvm::Constant *m = 0;
    if (const CXXDestructorDecl *Dtor = dyn_cast<CXXDestructorDecl>(MD))
      m = wrap(CGM.GetAddrOfCXXDestructor(Dtor, Dtor_Complete));
    else {
      const FunctionProtoType *FPT = MD->getType()->getAs<FunctionProtoType>();
      const llvm::Type *Ty =
        CGM.getTypes().GetFunctionType(CGM.getTypes().getFunctionInfo(MD),
                                       FPT->isVariadic());
      
      m = wrap(CGM.GetAddrOfFunction(MD, Ty));
    }
    
    // If we can find a previously allocated slot for this, reuse it.
    if (OverrideMethod(MD, m, MorallyVirtual, Offset))
      return;

    // else allocate a new slot.
    Index[MD] = submethods.size();
    submethods.push_back(m);
    if (MorallyVirtual) {
      VCallOffset[MD] = Offset/8;
      Index_t &idx = VCall[MD];
      // Allocate the first one, after that, we reuse the previous one.
      if (idx == 0) {
        idx = VCalls.size()+1;
        VCalls.push_back(0);
      }
    }
  }

  void AddMethods(const CXXRecordDecl *RD, bool MorallyVirtual,
                  Index_t Offset) {
    for (method_iter mi = RD->method_begin(), me = RD->method_end(); mi != me;
         ++mi)
      if (mi->isVirtual())
        AddMethod(*mi, MorallyVirtual, Offset);
  }

  void NonVirtualBases(const CXXRecordDecl *RD, const ASTRecordLayout &Layout,
                       const CXXRecordDecl *PrimaryBase,
                       bool PrimaryBaseWasVirtual, bool MorallyVirtual,
                       int64_t Offset) {
    for (CXXRecordDecl::base_class_const_iterator i = RD->bases_begin(),
           e = RD->bases_end(); i != e; ++i) {
      if (i->isVirtual())
        continue;
      const CXXRecordDecl *Base =
        cast<CXXRecordDecl>(i->getType()->getAs<RecordType>()->getDecl());
      if (Base != PrimaryBase || PrimaryBaseWasVirtual) {
        uint64_t o = Offset + Layout.getBaseClassOffset(Base);
        StartNewTable();
        std::vector<std::pair<const CXXRecordDecl *,
          int64_t> > S;
        S.push_back(std::make_pair(RD, Offset));
        GenerateVtableForBase(Base, MorallyVirtual, o, false, &S);
      }
    }
  }

  Index_t end(const CXXRecordDecl *RD, std::vector<llvm::Constant *> &offsets,
              const ASTRecordLayout &Layout,
              const CXXRecordDecl *PrimaryBase,
              bool PrimaryBaseWasVirtual, bool MorallyVirtual,
              int64_t Offset, bool ForVirtualBase) {
    StartNewTable();
    extra = 0;
    // FIXME: Cleanup.
    if (!ForVirtualBase) {
      // then virtual base offsets...
      for (std::vector<llvm::Constant *>::reverse_iterator i = offsets.rbegin(),
             e = offsets.rend(); i != e; ++i)
        methods.push_back(*i);
    }

    // The vcalls come first...
    for (std::vector<Index_t>::reverse_iterator i=VCalls.rbegin(),
           e=VCalls.rend();
         i != e; ++i)
      methods.push_back(wrap((0?600:0) + *i));
    VCalls.clear();

    if (ForVirtualBase) {
      // then virtual base offsets...
      for (std::vector<llvm::Constant *>::reverse_iterator i = offsets.rbegin(),
             e = offsets.rend(); i != e; ++i)
        methods.push_back(*i);
    }

    methods.push_back(wrap(-(Offset/8)));
    methods.push_back(rtti);
    Index_t AddressPoint = methods.size();

    InstallThunks();
    methods.insert(methods.end(), submethods.begin(), submethods.end());
    submethods.clear();

    // and then the non-virtual bases.
    NonVirtualBases(RD, Layout, PrimaryBase, PrimaryBaseWasVirtual,
                    MorallyVirtual, Offset);
    return AddressPoint;
  }

  void Primaries(const CXXRecordDecl *RD, bool MorallyVirtual, int64_t Offset) {
    if (!RD->isDynamicClass())
      return;

    const ASTRecordLayout &Layout = CGM.getContext().getASTRecordLayout(RD);
    const CXXRecordDecl *PrimaryBase = Layout.getPrimaryBase();
    const bool PrimaryBaseWasVirtual = Layout.getPrimaryBaseWasVirtual();

    // vtables are composed from the chain of primaries.
    if (PrimaryBase) {
      if (PrimaryBaseWasVirtual)
        IndirectPrimary.insert(PrimaryBase);
      Primaries(PrimaryBase, PrimaryBaseWasVirtual|MorallyVirtual, Offset);
    }

    // And add the virtuals for the class to the primary vtable.
    AddMethods(RD, MorallyVirtual, Offset);
  }

  int64_t GenerateVtableForBase(const CXXRecordDecl *RD,
                                bool MorallyVirtual = false, int64_t Offset = 0,
                                bool ForVirtualBase = false,
                                std::vector<std::pair<const CXXRecordDecl *,
                                int64_t> > *Path = 0) {
    if (!RD->isDynamicClass())
      return 0;

    const ASTRecordLayout &Layout = CGM.getContext().getASTRecordLayout(RD);
    const CXXRecordDecl *PrimaryBase = Layout.getPrimaryBase();
    const bool PrimaryBaseWasVirtual = Layout.getPrimaryBaseWasVirtual();

    std::vector<llvm::Constant *> offsets;
    extra = 0;
    GenerateVBaseOffsets(offsets, RD, Offset, !ForVirtualBase);
    if (ForVirtualBase)
      extra = offsets.size();

    // vtables are composed from the chain of primaries.
    if (PrimaryBase) {
      if (PrimaryBaseWasVirtual)
        IndirectPrimary.insert(PrimaryBase);
      Primaries(PrimaryBase, PrimaryBaseWasVirtual|MorallyVirtual, Offset);
    }

    // And add the virtuals for the class to the primary vtable.
    AddMethods(RD, MorallyVirtual, Offset);

    if (Path)
      OverrideMethods(Path, MorallyVirtual);

    return end(RD, offsets, Layout, PrimaryBase, PrimaryBaseWasVirtual,
               MorallyVirtual, Offset, ForVirtualBase);
  }

  void GenerateVtableForVBases(const CXXRecordDecl *RD,
                               int64_t Offset = 0,
                               std::vector<std::pair<const CXXRecordDecl *,
                               int64_t> > *Path = 0) {
    bool alloc = false;
    if (Path == 0) {
      alloc = true;
      Path = new std::vector<std::pair<const CXXRecordDecl *,
        int64_t> >;
    }
    // FIXME: We also need to override using all paths to a virtual base,
    // right now, we just process the first path
    Path->push_back(std::make_pair(RD, Offset));
    for (CXXRecordDecl::base_class_const_iterator i = RD->bases_begin(),
           e = RD->bases_end(); i != e; ++i) {
      const CXXRecordDecl *Base =
        cast<CXXRecordDecl>(i->getType()->getAs<RecordType>()->getDecl());
      if (i->isVirtual() && !IndirectPrimary.count(Base)) {
        // Mark it so we don't output it twice.
        IndirectPrimary.insert(Base);
        StartNewTable();
        int64_t BaseOffset = BLayout.getVBaseClassOffset(Base);
        GenerateVtableForBase(Base, true, BaseOffset, true, Path);
      }
      int64_t BaseOffset = Offset;
      if (i->isVirtual())
        BaseOffset = BLayout.getVBaseClassOffset(Base);
      if (Base->getNumVBases())
        GenerateVtableForVBases(Base, BaseOffset, Path);
    }
    Path->pop_back();
    if (alloc)
      delete Path;
  }
};


VtableBuilder::Index_t VtableBuilder::VBlookup(CXXRecordDecl *D,
                                               CXXRecordDecl *B) {
  return CGM.getVtableInfo().getVirtualBaseOffsetIndex(D, B);
}

int64_t CGVtableInfo::getMethodVtableIndex(const CXXMethodDecl *MD) {
  MD = MD->getCanonicalDecl();

  MethodVtableIndicesTy::iterator I = MethodVtableIndices.find(MD);
  if (I != MethodVtableIndices.end())
    return I->second;
  
  const CXXRecordDecl *RD = MD->getParent();
  
  std::vector<llvm::Constant *> methods;
  // FIXME: This seems expensive.  Can we do a partial job to get
  // just this data.
  VtableBuilder b(methods, RD, CGM);
  b.GenerateVtableForBase(RD);
  b.GenerateVtableForVBases(RD);
  
  MethodVtableIndices.insert(b.getIndex().begin(),
                             b.getIndex().end());
  
  I = MethodVtableIndices.find(MD);
  assert(I != MethodVtableIndices.end() && "Did not find index!");
  return I->second;
}

int64_t CGVtableInfo::getVirtualBaseOffsetIndex(const CXXRecordDecl *RD, 
                                                const CXXRecordDecl *VBase) {
  ClassPairTy ClassPair(RD, VBase);
  
  VirtualBaseClassIndiciesTy::iterator I = 
    VirtualBaseClassIndicies.find(ClassPair);
  if (I != VirtualBaseClassIndicies.end())
    return I->second;
  
  std::vector<llvm::Constant *> methods;
  // FIXME: This seems expensive.  Can we do a partial job to get
  // just this data.
  VtableBuilder b(methods, RD, CGM);
  b.GenerateVtableForBase(RD);
  b.GenerateVtableForVBases(RD);
  
  for (llvm::DenseMap<const CXXRecordDecl *, uint64_t>::iterator I =
       b.getVBIndex().begin(), E = b.getVBIndex().end(); I != E; ++I) {
    // Insert all types.
    ClassPairTy ClassPair(RD, I->first);
    
    VirtualBaseClassIndicies.insert(std::make_pair(ClassPair, I->second));
  }
  
  I = VirtualBaseClassIndicies.find(ClassPair);
  assert(I != VirtualBaseClassIndicies.end() && "Did not find index!");
  
  return I->second;
}

llvm::Value *CodeGenFunction::GenerateVtable(const CXXRecordDecl *RD) {
  llvm::SmallString<256> OutName;
  llvm::raw_svector_ostream Out(OutName);
  mangleCXXVtable(CGM.getMangleContext(), RD, Out);

  llvm::GlobalVariable::LinkageTypes linktype;
  linktype = llvm::GlobalValue::WeakAnyLinkage;
  std::vector<llvm::Constant *> methods;
  llvm::Type *Ptr8Ty=llvm::PointerType::get(llvm::Type::getInt8Ty(VMContext),0);
  int64_t AddressPoint;

  VtableBuilder b(methods, RD, CGM);

  // First comes the vtables for all the non-virtual bases...
  AddressPoint = b.GenerateVtableForBase(RD);

  // then the vtables for all the virtual bases.
  b.GenerateVtableForVBases(RD);

  llvm::Constant *C;
  llvm::ArrayType *type = llvm::ArrayType::get(Ptr8Ty, methods.size());
  C = llvm::ConstantArray::get(type, methods);
  llvm::Value *vtable = new llvm::GlobalVariable(CGM.getModule(), type, true,
                                                 linktype, C, Out.str());
  vtable = Builder.CreateBitCast(vtable, Ptr8Ty);
  vtable = Builder.CreateGEP(vtable,
                       llvm::ConstantInt::get(llvm::Type::getInt64Ty(VMContext),
                                              AddressPoint*LLVMPointerWidth/8));
  return vtable;
}
