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
#include "clang/AST/CXXInheritance.h"
#include "clang/AST/RecordLayout.h"
#include "llvm/ADT/DenseSet.h"
#include <cstdio>

using namespace clang;
using namespace CodeGen;

namespace {
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
  /// LayoutClass - The most derived class used for virtual base layout
  /// information.
  const CXXRecordDecl *LayoutClass;
  /// LayoutOffset - The offset for Class in LayoutClass.
  uint64_t LayoutOffset;
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
  llvm::DenseMap<GlobalDecl, Index_t> Index;
  llvm::DenseMap<GlobalDecl, Index_t> VCall;
  llvm::DenseMap<GlobalDecl, Index_t> VCallOffset;
  // This is the offset to the nearest virtual base
  llvm::DenseMap<GlobalDecl, Index_t> NonVirtualOffset;
  llvm::DenseMap<const CXXRecordDecl *, Index_t> VBIndex;

  /// PureVirtualFunction - Points to __cxa_pure_virtual.
  llvm::Constant *PureVirtualFn;
  
  /// VtableMethods - A data structure for keeping track of methods in a vtable.
  /// Can add methods, override methods and iterate in vtable order.
  class VtableMethods {
    // MethodToIndexMap - Maps from a global decl to the index it has in the
    // Methods vector.
    llvm::DenseMap<GlobalDecl, uint64_t> MethodToIndexMap;

    /// Methods - The methods, in vtable order.
    typedef llvm::SmallVector<GlobalDecl, 16> MethodsVectorTy;
    MethodsVectorTy Methods;

  public:
    /// AddMethod - Add a method to the vtable methods.
    void AddMethod(GlobalDecl GD) {
      assert(!MethodToIndexMap.count(GD) && 
             "Method has already been added!");
      
      MethodToIndexMap[GD] = Methods.size();
      Methods.push_back(GD);
    }
    
    /// OverrideMethod - Replace a method with another.
    void OverrideMethod(GlobalDecl OverriddenGD, GlobalDecl GD) {
      llvm::DenseMap<GlobalDecl, uint64_t>::iterator i 
        = MethodToIndexMap.find(OverriddenGD);
      assert(i != MethodToIndexMap.end() && "Did not find entry!");

      // Get the index of the old decl.
      uint64_t Index = i->second;
      
      // Replace the old decl with the new decl.
      Methods[Index] = GD;

      // Now remove the old decl from the method to index map.
      MethodToIndexMap.erase(i);
        
      // And add the new.
      MethodToIndexMap[GD] = Index;
    }

    MethodsVectorTy::size_type size() const {
      return Methods.size();
    }

    void clear() {
      MethodToIndexMap.clear();
      Methods.clear();
    }
    
    GlobalDecl operator[](unsigned Index) const {
      return Methods[Index];
    }
  };
  
  /// Methods - The vtable methods we're currently building.
  VtableMethods Methods;
  
  /// Thunk - Represents a single thunk.
  struct Thunk {
    Thunk() { }
    
    Thunk(GlobalDecl GD, const ThunkAdjustment &Adjustment)
      : GD(GD), Adjustment(Adjustment) { }
    
    GlobalDecl GD;

    /// Adjustment - The thunk adjustment.
    ThunkAdjustment Adjustment;
  };

  /// Thunks - The thunks in a vtable.
  typedef llvm::DenseMap<uint64_t, Thunk> ThunksMapTy;
  ThunksMapTy Thunks;

  /// CovariantThunk - Represents a single covariant thunk.
  struct CovariantThunk {
    CovariantThunk() { }

    CovariantThunk(GlobalDecl GD, CanQualType ReturnType) 
      : GD(GD), ReturnType(ReturnType) { }

    GlobalDecl GD;
    
    /// ReturnType - The return type of the function.
    CanQualType ReturnType;
  };
  
  /// CovariantThunks - The covariant thunks in a vtable.
  typedef llvm::DenseMap<uint64_t, CovariantThunk> CovariantThunksMapTy;
  CovariantThunksMapTy CovariantThunks;
  
  /// PureVirtualMethods - Pure virtual methods.
  typedef llvm::DenseSet<GlobalDecl> PureVirtualMethodsSetTy;
  PureVirtualMethodsSetTy PureVirtualMethods;

  std::vector<Index_t> VCalls;

  typedef std::pair<const CXXRecordDecl *, uint64_t> CtorVtable_t;
  // subAddressPoints - Used to hold the AddressPoints (offsets) into the built
  // vtable for use in computing the initializers for the VTT.
  llvm::DenseMap<CtorVtable_t, int64_t> &subAddressPoints;

  typedef CXXRecordDecl::method_iterator method_iter;
  const bool Extern;
  const uint32_t LLVMPointerWidth;
  Index_t extra;
  typedef std::vector<std::pair<const CXXRecordDecl *, int64_t> > Path_t;
  static llvm::DenseMap<CtorVtable_t, int64_t>&
  AllocAddressPoint(CodeGenModule &cgm, const CXXRecordDecl *l,
                    const CXXRecordDecl *c) {
    CodeGenModule::AddrMap_t *&oref = cgm.AddressPoints[l];
    if (oref == 0)
      oref = new CodeGenModule::AddrMap_t;

    llvm::DenseMap<CtorVtable_t, int64_t> *&ref = (*oref)[c];
    if (ref == 0)
      ref = new llvm::DenseMap<CtorVtable_t, int64_t>;
    return *ref;
  }
  
  /// getPureVirtualFn - Return the __cxa_pure_virtual function.
  llvm::Constant* getPureVirtualFn() {
    if (!PureVirtualFn) {
      const llvm::FunctionType *Ty = 
        llvm::FunctionType::get(llvm::Type::getVoidTy(VMContext), 
                                /*isVarArg=*/false);
      PureVirtualFn = wrap(CGM.CreateRuntimeFunction(Ty, "__cxa_pure_virtual"));
    }
    
    return PureVirtualFn;
  }
  
public:
  VtableBuilder(std::vector<llvm::Constant *> &meth, const CXXRecordDecl *c,
                const CXXRecordDecl *l, uint64_t lo, CodeGenModule &cgm)
    : methods(meth), Class(c), LayoutClass(l), LayoutOffset(lo),
      BLayout(cgm.getContext().getASTRecordLayout(l)),
      rtti(cgm.GenerateRTTIRef(c)), VMContext(cgm.getModule().getContext()),
      CGM(cgm), PureVirtualFn(0),subAddressPoints(AllocAddressPoint(cgm, l, c)),
      Extern(!l->isInAnonymousNamespace()),
    LLVMPointerWidth(cgm.getContext().Target.getPointerWidth(0)) {
    Ptr8Ty = llvm::PointerType::get(llvm::Type::getInt8Ty(VMContext), 0);
  }

  llvm::DenseMap<GlobalDecl, Index_t> &getIndex() { return Index; }
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

#define D1(x)
//#define D1(X) do { if (getenv("DEBUG")) { X; } } while (0)

  void GenerateVBaseOffsets(const CXXRecordDecl *RD, uint64_t Offset,
                            bool updateVBIndex, Index_t current_vbindex) {
    for (CXXRecordDecl::base_class_const_iterator i = RD->bases_begin(),
           e = RD->bases_end(); i != e; ++i) {
      const CXXRecordDecl *Base =
        cast<CXXRecordDecl>(i->getType()->getAs<RecordType>()->getDecl());
      Index_t next_vbindex = current_vbindex;
      if (i->isVirtual() && !SeenVBase.count(Base)) {
        SeenVBase.insert(Base);
        if (updateVBIndex) {
          next_vbindex = (ssize_t)(-(VCalls.size()*LLVMPointerWidth/8)
                                   - 3*LLVMPointerWidth/8);
          VBIndex[Base] = next_vbindex;
        }
        int64_t BaseOffset = -(Offset/8) + BLayout.getVBaseClassOffset(Base)/8;
        VCalls.push_back((0?700:0) + BaseOffset);
        D1(printf("  vbase for %s at %d delta %d most derived %s\n",
                  Base->getNameAsCString(),
                  (int)-VCalls.size()-3, (int)BaseOffset,
                  Class->getNameAsCString()));
      }
      // We also record offsets for non-virtual bases to closest enclosing
      // virtual base.  We do this so that we don't have to search
      // for the nearst virtual base class when generating thunks.
      if (updateVBIndex && VBIndex.count(Base) == 0)
        VBIndex[Base] = next_vbindex;
      GenerateVBaseOffsets(Base, Offset, updateVBIndex, next_vbindex);
    }
  }

  void StartNewTable() {
    SeenVBase.clear();
  }

  Index_t getNVOffset_1(const CXXRecordDecl *D, const CXXRecordDecl *B,
    Index_t Offset = 0) {

    if (B == D)
      return Offset;

    const ASTRecordLayout &Layout = CGM.getContext().getASTRecordLayout(D);
    for (CXXRecordDecl::base_class_const_iterator i = D->bases_begin(),
           e = D->bases_end(); i != e; ++i) {
      const CXXRecordDecl *Base =
        cast<CXXRecordDecl>(i->getType()->getAs<RecordType>()->getDecl());
      int64_t BaseOffset = 0;
      if (!i->isVirtual())
        BaseOffset = Offset + Layout.getBaseClassOffset(Base);
      int64_t o = getNVOffset_1(Base, B, BaseOffset);
      if (o >= 0)
        return o;
    }

    return -1;
  }

  /// getNVOffset - Returns the non-virtual offset for the given (B) base of the
  /// derived class D.
  Index_t getNVOffset(QualType qB, QualType qD) {
    qD = qD->getPointeeType();
    qB = qB->getPointeeType();
    CXXRecordDecl *D = cast<CXXRecordDecl>(qD->getAs<RecordType>()->getDecl());
    CXXRecordDecl *B = cast<CXXRecordDecl>(qB->getAs<RecordType>()->getDecl());
    int64_t o = getNVOffset_1(D, B);
    if (o >= 0)
      return o;

    assert(false && "FIXME: non-virtual base not found");
    return 0;
  }

  /// getVbaseOffset - Returns the index into the vtable for the virtual base
  /// offset for the given (B) virtual base of the derived class D.
  Index_t getVbaseOffset(QualType qB, QualType qD) {
    qD = qD->getPointeeType();
    qB = qB->getPointeeType();
    CXXRecordDecl *D = cast<CXXRecordDecl>(qD->getAs<RecordType>()->getDecl());
    CXXRecordDecl *B = cast<CXXRecordDecl>(qB->getAs<RecordType>()->getDecl());
    if (D != Class)
      return CGM.getVtableInfo().getVirtualBaseOffsetIndex(D, B);
    llvm::DenseMap<const CXXRecordDecl *, Index_t>::iterator i;
    i = VBIndex.find(B);
    if (i != VBIndex.end())
      return i->second;

    assert(false && "FIXME: Base not found");
    return 0;
  }

  bool OverrideMethod(GlobalDecl GD, llvm::Constant *m,
                      bool MorallyVirtual, Index_t OverrideOffset,
                      Index_t Offset, int64_t CurrentVBaseOffset);

  void InstallThunks() {
    for (CovariantThunksMapTy::const_iterator i = CovariantThunks.begin(),
         e = CovariantThunks.end(); i != e; ++i) {
      GlobalDecl GD = i->second.GD;
      const CXXMethodDecl *MD = cast<CXXMethodDecl>(GD.getDecl());
      if (MD->isPure())
        continue;
      
      uint64_t Index = i->first;
      const CovariantThunk &Thunk = i->second;
      assert(Index == VtableBuilder::Index[GD] && "Thunk index mismatch!");
      
      // Check if there is an adjustment for the 'this' pointer.
      ThunkAdjustment ThisAdjustment;
      ThunksMapTy::iterator it = Thunks.find(Index);
      if (it != Thunks.end()) {
        ThisAdjustment = it->second.Adjustment;
        
        Thunks.erase(it);
      }
      
      // Construct the return adjustment.
      QualType DerivedType = 
        MD->getType()->getAs<FunctionType>()->getResultType();
      
      int64_t NonVirtualAdjustment = 
        getNVOffset(Thunk.ReturnType, DerivedType) / 8;
      
      int64_t VirtualAdjustment = 
        getVbaseOffset(Thunk.ReturnType, DerivedType);
      
      ThunkAdjustment ReturnAdjustment(NonVirtualAdjustment, VirtualAdjustment);
      
      CovariantThunkAdjustment Adjustment(ThisAdjustment, ReturnAdjustment);
      submethods[Index] = CGM.BuildCovariantThunk(MD, Extern, Adjustment);
    }
    CovariantThunks.clear();
    
    for (ThunksMapTy::const_iterator i = Thunks.begin(), e = Thunks.end();
         i != e; ++i) {
      uint64_t Index = i->first;
      const Thunk& Thunk = i->second;

      GlobalDecl GD = Thunk.GD;
      const CXXMethodDecl *MD = cast<CXXMethodDecl>(GD.getDecl());
      assert(!MD->isPure() && "Can't thunk pure virtual methods!");

      assert(Index == VtableBuilder::Index[GD] && "Thunk index mismatch!");
             
      submethods[Index] = CGM.BuildThunk(GD, Extern, Thunk.Adjustment);
    }
    Thunks.clear();

    for (PureVirtualMethodsSetTy::iterator i = PureVirtualMethods.begin(),
         e = PureVirtualMethods.end(); i != e; ++i) {
      GlobalDecl GD = *i;
      submethods[Index[GD]] = getPureVirtualFn();
    }
    PureVirtualMethods.clear();
  }

  llvm::Constant *WrapAddrOf(GlobalDecl GD) {
    const CXXMethodDecl *MD = cast<CXXMethodDecl>(GD.getDecl());

    const llvm::Type *Ty = CGM.getTypes().GetFunctionTypeForVtable(MD);

    return wrap(CGM.GetAddrOfFunction(GD, Ty));
  }

  void OverrideMethods(Path_t *Path, bool MorallyVirtual, int64_t Offset,
                       int64_t CurrentVBaseOffset) {
    for (Path_t::reverse_iterator i = Path->rbegin(),
           e = Path->rend(); i != e; ++i) {
      const CXXRecordDecl *RD = i->first;
      int64_t OverrideOffset = i->second;
      for (method_iter mi = RD->method_begin(), me = RD->method_end(); mi != me;
           ++mi) {
        const CXXMethodDecl *MD = *mi;

        if (!MD->isVirtual())
          continue;

        if (const CXXDestructorDecl *DD = dyn_cast<CXXDestructorDecl>(MD)) {
          // Override both the complete and the deleting destructor.
          GlobalDecl CompDtor(DD, Dtor_Complete);
          OverrideMethod(CompDtor, WrapAddrOf(CompDtor), MorallyVirtual, 
                         OverrideOffset, Offset, CurrentVBaseOffset);
          
          GlobalDecl DeletingDtor(DD, Dtor_Deleting);
          OverrideMethod(DeletingDtor, WrapAddrOf(DeletingDtor), MorallyVirtual, 
                         OverrideOffset, Offset, CurrentVBaseOffset);
        } else {
          OverrideMethod(MD, WrapAddrOf(MD), MorallyVirtual, OverrideOffset, 
                         Offset, CurrentVBaseOffset);
        }
      }
    }
  }

  void AddMethod(const GlobalDecl GD, bool MorallyVirtual, Index_t Offset,
                 int64_t CurrentVBaseOffset) {
    llvm::Constant *m = WrapAddrOf(GD);

    // If we can find a previously allocated slot for this, reuse it.
    if (OverrideMethod(GD, m, MorallyVirtual, Offset, Offset,
                       CurrentVBaseOffset))
      return;

    const CXXMethodDecl *MD = cast<CXXMethodDecl>(GD.getDecl());
    
    // else allocate a new slot.
    Index[GD] = submethods.size();
    submethods.push_back(m);
    D1(printf("  vfn for %s at %d\n", MD->getNameAsString().c_str(),
              (int)Index[GD]));
    if (MD->isPure())
      PureVirtualMethods.insert(GD);
    if (MorallyVirtual) {
      VCallOffset[GD] = Offset/8;
      Index_t &idx = VCall[GD];
      // Allocate the first one, after that, we reuse the previous one.
      if (idx == 0) {
        NonVirtualOffset[GD] = CurrentVBaseOffset/8 - Offset/8;
        idx = VCalls.size()+1;
        VCalls.push_back(0);
        D1(printf("  vcall for %s at %d with delta %d\n",
                  MD->getNameAsString().c_str(), (int)-VCalls.size()-3, 0));
      }
    }
  }

  void AddMethods(const CXXRecordDecl *RD, bool MorallyVirtual,
                  Index_t Offset, int64_t CurrentVBaseOffset) {
    for (method_iter mi = RD->method_begin(), me = RD->method_end(); mi != me;
         ++mi) {
      const CXXMethodDecl *MD = *mi;
      if (!MD->isVirtual())
        continue;
      
      if (const CXXDestructorDecl *DD = dyn_cast<CXXDestructorDecl>(MD)) {
        // For destructors, add both the complete and the deleting destructor
        // to the vtable.
        AddMethod(GlobalDecl(DD, Dtor_Complete), MorallyVirtual, Offset, 
                  CurrentVBaseOffset);
        AddMethod(GlobalDecl(DD, Dtor_Deleting), MorallyVirtual, Offset, 
                  CurrentVBaseOffset);
      } else
        AddMethod(MD, MorallyVirtual, Offset, CurrentVBaseOffset);
    }
  }

  void NonVirtualBases(const CXXRecordDecl *RD, const ASTRecordLayout &Layout,
                       const CXXRecordDecl *PrimaryBase,
                       bool PrimaryBaseWasVirtual, bool MorallyVirtual,
                       int64_t Offset, int64_t CurrentVBaseOffset,
                       Path_t *Path) {
    Path->push_back(std::make_pair(RD, Offset));
    for (CXXRecordDecl::base_class_const_iterator i = RD->bases_begin(),
           e = RD->bases_end(); i != e; ++i) {
      if (i->isVirtual())
        continue;
      const CXXRecordDecl *Base =
        cast<CXXRecordDecl>(i->getType()->getAs<RecordType>()->getDecl());
      if (Base != PrimaryBase || PrimaryBaseWasVirtual) {
        uint64_t o = Offset + Layout.getBaseClassOffset(Base);
        StartNewTable();
        GenerateVtableForBase(Base, o, MorallyVirtual, false,
                              CurrentVBaseOffset, Path);
      }
    }
    Path->pop_back();
  }

// #define D(X) do { X; } while (0)
#define D(X)

  void insertVCalls(int InsertionPoint) {
    llvm::Constant *e = 0;
    D1(printf("============= combining vbase/vcall\n"));
    D(VCalls.insert(VCalls.begin(), 673));
    D(VCalls.push_back(672));
    methods.insert(methods.begin() + InsertionPoint, VCalls.size(), e);
    // The vcalls come first...
    for (std::vector<Index_t>::reverse_iterator i = VCalls.rbegin(),
           e = VCalls.rend();
         i != e; ++i)
      methods[InsertionPoint++] = wrap((0?600:0) + *i);
    VCalls.clear();
    VCall.clear();
  }

  void AddAddressPoints(const CXXRecordDecl *RD, uint64_t Offset,
                       Index_t AddressPoint) {
    D1(printf("XXX address point for %s in %s layout %s at offset %d is %d\n",
              RD->getNameAsCString(), Class->getNameAsCString(),
              LayoutClass->getNameAsCString(), (int)Offset, (int)AddressPoint));
    subAddressPoints[std::make_pair(RD, Offset)] = AddressPoint;

    // Now also add the address point for all our primary bases.
    while (1) {
      const ASTRecordLayout &Layout = CGM.getContext().getASTRecordLayout(RD);
      RD = Layout.getPrimaryBase();
      const bool PrimaryBaseWasVirtual = Layout.getPrimaryBaseWasVirtual();
      // FIXME: Double check this.
      if (RD == 0)
        break;
      if (PrimaryBaseWasVirtual &&
          BLayout.getVBaseClassOffset(RD) != Offset)
        break;
      D1(printf("XXX address point for %s in %s layout %s at offset %d is %d\n",
                RD->getNameAsCString(), Class->getNameAsCString(),
                LayoutClass->getNameAsCString(), (int)Offset, (int)AddressPoint));
      subAddressPoints[std::make_pair(RD, Offset)] = AddressPoint;
    }
  }


  Index_t end(const CXXRecordDecl *RD, const ASTRecordLayout &Layout,
              const CXXRecordDecl *PrimaryBase, bool PrimaryBaseWasVirtual,
              bool MorallyVirtual, int64_t Offset, bool ForVirtualBase,
              int64_t CurrentVBaseOffset,
              Path_t *Path) {
    bool alloc = false;
    if (Path == 0) {
      alloc = true;
      Path = new Path_t;
    }

    StartNewTable();
    extra = 0;
    bool DeferVCalls = MorallyVirtual || ForVirtualBase;
    int VCallInsertionPoint = methods.size();
    if (!DeferVCalls) {
      insertVCalls(VCallInsertionPoint);
    } else
      // FIXME: just for extra, or for all uses of VCalls.size post this?
      extra = -VCalls.size();

    methods.push_back(wrap(-((Offset-LayoutOffset)/8)));
    methods.push_back(rtti);
    Index_t AddressPoint = methods.size();

    InstallThunks();
    D1(printf("============= combining methods\n"));
    methods.insert(methods.end(), submethods.begin(), submethods.end());
    submethods.clear();

    // and then the non-virtual bases.
    NonVirtualBases(RD, Layout, PrimaryBase, PrimaryBaseWasVirtual,
                    MorallyVirtual, Offset, CurrentVBaseOffset, Path);

    if (ForVirtualBase) {
      // FIXME: We're adding to VCalls in callers, we need to do the overrides
      // in the inner part, so that we know the complete set of vcalls during
      // the build and don't have to insert into methods.  Saving out the
      // AddressPoint here, would need to be fixed, if we didn't do that.  Also
      // retroactively adding vcalls for overrides later wind up in the wrong
      // place, the vcall slot has to be alloted during the walk of the base
      // when the function is first introduces.
      AddressPoint += VCalls.size();
      insertVCalls(VCallInsertionPoint);
    }
    
    AddAddressPoints(RD, Offset, AddressPoint);

    if (alloc) {
      delete Path;
    }
    return AddressPoint;
  }

  void Primaries(const CXXRecordDecl *RD, bool MorallyVirtual, int64_t Offset,
                 bool updateVBIndex, Index_t current_vbindex,
                 int64_t CurrentVBaseOffset) {
    if (!RD->isDynamicClass())
      return;

    const ASTRecordLayout &Layout = CGM.getContext().getASTRecordLayout(RD);
    const CXXRecordDecl *PrimaryBase = Layout.getPrimaryBase();
    const bool PrimaryBaseWasVirtual = Layout.getPrimaryBaseWasVirtual();

    // vtables are composed from the chain of primaries.
    if (PrimaryBase) {
      D1(printf(" doing primaries for %s most derived %s\n",
                RD->getNameAsCString(), Class->getNameAsCString()));
      
      int BaseCurrentVBaseOffset = CurrentVBaseOffset;
      if (PrimaryBaseWasVirtual)
        BaseCurrentVBaseOffset = BLayout.getVBaseClassOffset(PrimaryBase);
        
      if (!PrimaryBaseWasVirtual)
        Primaries(PrimaryBase, PrimaryBaseWasVirtual|MorallyVirtual, Offset,
                  updateVBIndex, current_vbindex, BaseCurrentVBaseOffset);
    }

    D1(printf(" doing vcall entries for %s most derived %s\n",
              RD->getNameAsCString(), Class->getNameAsCString()));

    // And add the virtuals for the class to the primary vtable.
    AddMethods(RD, MorallyVirtual, Offset, CurrentVBaseOffset);
  }

  void VBPrimaries(const CXXRecordDecl *RD, bool MorallyVirtual, int64_t Offset,
                   bool updateVBIndex, Index_t current_vbindex,
                   bool RDisVirtualBase, int64_t CurrentVBaseOffset,
                   bool bottom) {
    if (!RD->isDynamicClass())
      return;

    const ASTRecordLayout &Layout = CGM.getContext().getASTRecordLayout(RD);
    const CXXRecordDecl *PrimaryBase = Layout.getPrimaryBase();
    const bool PrimaryBaseWasVirtual = Layout.getPrimaryBaseWasVirtual();

    // vtables are composed from the chain of primaries.
    if (PrimaryBase) {
      int BaseCurrentVBaseOffset = CurrentVBaseOffset;
      if (PrimaryBaseWasVirtual) {
        IndirectPrimary.insert(PrimaryBase);
        BaseCurrentVBaseOffset = BLayout.getVBaseClassOffset(PrimaryBase);
      }

      D1(printf(" doing primaries for %s most derived %s\n",
                RD->getNameAsCString(), Class->getNameAsCString()));
      
      VBPrimaries(PrimaryBase, PrimaryBaseWasVirtual|MorallyVirtual, Offset,
                  updateVBIndex, current_vbindex, PrimaryBaseWasVirtual,
                  BaseCurrentVBaseOffset, false);
    }

    D1(printf(" doing vbase entries for %s most derived %s\n",
              RD->getNameAsCString(), Class->getNameAsCString()));
    GenerateVBaseOffsets(RD, Offset, updateVBIndex, current_vbindex);

    if (RDisVirtualBase || bottom) {
      Primaries(RD, MorallyVirtual, Offset, updateVBIndex, current_vbindex,
                CurrentVBaseOffset);
    }
  }

  int64_t GenerateVtableForBase(const CXXRecordDecl *RD, int64_t Offset = 0,
                                bool MorallyVirtual = false, 
                                bool ForVirtualBase = false,
                                int CurrentVBaseOffset = 0,
                                Path_t *Path = 0) {
    if (!RD->isDynamicClass())
      return 0;

    // Construction vtable don't need parts that have no virtual bases and
    // aren't morally virtual.
    if ((LayoutClass != Class) && RD->getNumVBases() == 0 && !MorallyVirtual)
      return 0;

    const ASTRecordLayout &Layout = CGM.getContext().getASTRecordLayout(RD);
    const CXXRecordDecl *PrimaryBase = Layout.getPrimaryBase();
    const bool PrimaryBaseWasVirtual = Layout.getPrimaryBaseWasVirtual();

    extra = 0;
    D1(printf("building entries for base %s most derived %s\n",
              RD->getNameAsCString(), Class->getNameAsCString()));

    if (ForVirtualBase)
      extra = VCalls.size();

    VBPrimaries(RD, MorallyVirtual, Offset, !ForVirtualBase, 0, ForVirtualBase,
                CurrentVBaseOffset, true);

    if (Path)
      OverrideMethods(Path, MorallyVirtual, Offset, CurrentVBaseOffset);

    return end(RD, Layout, PrimaryBase, PrimaryBaseWasVirtual, MorallyVirtual,
               Offset, ForVirtualBase, CurrentVBaseOffset, Path);
  }

  void GenerateVtableForVBases(const CXXRecordDecl *RD,
                               int64_t Offset = 0,
                               Path_t *Path = 0) {
    bool alloc = false;
    if (Path == 0) {
      alloc = true;
      Path = new Path_t;
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
        VCall.clear();
        int64_t BaseOffset = BLayout.getVBaseClassOffset(Base);
        int64_t CurrentVBaseOffset = BaseOffset;
        D1(printf("vtable %s virtual base %s\n",
                  Class->getNameAsCString(), Base->getNameAsCString()));
        GenerateVtableForBase(Base, BaseOffset, true, true, CurrentVBaseOffset,
                              Path);
      }
      int64_t BaseOffset;
      if (i->isVirtual())
        BaseOffset = BLayout.getVBaseClassOffset(Base);
      else {
        const ASTRecordLayout &Layout = CGM.getContext().getASTRecordLayout(RD);
        BaseOffset = Offset + Layout.getBaseClassOffset(Base);
      }
        
      if (Base->getNumVBases()) {
        GenerateVtableForVBases(Base, BaseOffset, Path);
      }
    }
    Path->pop_back();
    if (alloc)
      delete Path;
  }
};
} // end anonymous namespace

/// TypeConversionRequiresAdjustment - Returns whether conversion from a 
/// derived type to a base type requires adjustment.
static bool
TypeConversionRequiresAdjustment(ASTContext &Ctx,
                                 const CXXRecordDecl *DerivedDecl,
                                 const CXXRecordDecl *BaseDecl) {
  CXXBasePaths Paths(/*FindAmbiguities=*/false,
                     /*RecordPaths=*/true, /*DetectVirtual=*/true);
  if (!const_cast<CXXRecordDecl *>(DerivedDecl)->
      isDerivedFrom(const_cast<CXXRecordDecl *>(BaseDecl), Paths)) {
    assert(false && "Class must be derived from the passed in base class!");
    return false;
  }
  
  // If we found a virtual base we always want to require adjustment.
  if (Paths.getDetectedVirtual())
    return true;
  
  const CXXBasePath &Path = Paths.front();
  
  for (size_t Start = 0, End = Path.size(); Start != End; ++Start) {
    const CXXBasePathElement &Element = Path[Start];
    
    // Check the base class offset.
    const ASTRecordLayout &Layout = Ctx.getASTRecordLayout(Element.Class);
    
    const RecordType *BaseType = Element.Base->getType()->getAs<RecordType>();
    const CXXRecordDecl *Base = cast<CXXRecordDecl>(BaseType->getDecl());
    
    if (Layout.getBaseClassOffset(Base) != 0) {
      // This requires an adjustment.
      return true;
    }
  }
  
  return false;
}

static bool 
TypeConversionRequiresAdjustment(ASTContext &Ctx,
                                 QualType DerivedType, QualType BaseType) {
  // Canonicalize the types.
  QualType CanDerivedType = Ctx.getCanonicalType(DerivedType);
  QualType CanBaseType = Ctx.getCanonicalType(BaseType);
  
  assert(CanDerivedType->getTypeClass() == CanBaseType->getTypeClass() && 
         "Types must have same type class!");
  
  if (CanDerivedType == CanBaseType) {
    // No adjustment needed.
    return false;
  }
  
  if (const ReferenceType *RT = dyn_cast<ReferenceType>(CanDerivedType)) {
    CanDerivedType = RT->getPointeeType();
    CanBaseType = cast<ReferenceType>(CanBaseType)->getPointeeType();
  } else if (const PointerType *PT = dyn_cast<PointerType>(CanDerivedType)) {
    CanDerivedType = PT->getPointeeType();
    CanBaseType = cast<PointerType>(CanBaseType)->getPointeeType();
  } else {
    assert(false && "Unexpected return type!");
  }
  
  if (CanDerivedType == CanBaseType) {
    // No adjustment needed.
    return false;
  }
  
  const CXXRecordDecl *DerivedDecl = 
  cast<CXXRecordDecl>(cast<RecordType>(CanDerivedType)->getDecl());
  
  const CXXRecordDecl *BaseDecl = 
  cast<CXXRecordDecl>(cast<RecordType>(CanBaseType)->getDecl());
  
  return TypeConversionRequiresAdjustment(Ctx, DerivedDecl, BaseDecl);
}

bool VtableBuilder::OverrideMethod(GlobalDecl GD, llvm::Constant *m,
                                   bool MorallyVirtual, Index_t OverrideOffset,
                                   Index_t Offset, int64_t CurrentVBaseOffset) {
  const CXXMethodDecl *MD = cast<CXXMethodDecl>(GD.getDecl());

  const bool isPure = MD->isPure();
  typedef CXXMethodDecl::method_iterator meth_iter;
  // FIXME: Should OverrideOffset's be Offset?

  // FIXME: Don't like the nested loops.  For very large inheritance
  // heirarchies we could have a table on the side with the final overridder
  // and just replace each instance of an overridden method once.  Would be
  // nice to measure the cost/benefit on real code.

  for (meth_iter mi = MD->begin_overridden_methods(),
         e = MD->end_overridden_methods();
       mi != e; ++mi) {
    GlobalDecl OGD;
    
    const CXXMethodDecl *OMD = *mi;
    if (const CXXDestructorDecl *DD = dyn_cast<CXXDestructorDecl>(OMD))
      OGD = GlobalDecl(DD, GD.getDtorType());
    else
      OGD = OMD;
    
    llvm::Constant *om;
    om = WrapAddrOf(OGD);
    om = llvm::ConstantExpr::getBitCast(om, Ptr8Ty);

    for (Index_t i = 0, e = submethods.size();
         i != e; ++i) {
      // FIXME: begin_overridden_methods might be too lax, covariance */
      if (submethods[i] != om)
        continue;
      
      QualType ReturnType = 
        MD->getType()->getAs<FunctionType>()->getResultType();
      QualType OverriddenReturnType = 
        OMD->getType()->getAs<FunctionType>()->getResultType();
      
      // Check if we need a return type adjustment.
      if (TypeConversionRequiresAdjustment(CGM.getContext(), ReturnType, 
                                           OverriddenReturnType)) {
        CovariantThunk &Adjustment = CovariantThunks[i];

        // Get the canonical return type.
        CanQualType CanReturnType = 
          CGM.getContext().getCanonicalType(ReturnType);

        // Insert the base return type.
        if (Adjustment.ReturnType.isNull())
          Adjustment.ReturnType =
            CGM.getContext().getCanonicalType(OverriddenReturnType);
        
        Adjustment.GD = GD;
      }

      Index[GD] = i;
      submethods[i] = m;
      if (isPure)
        PureVirtualMethods.insert(GD);
      PureVirtualMethods.erase(OGD);
      Thunks.erase(i);
      if (MorallyVirtual || VCall.count(OGD)) {
        Index_t &idx = VCall[OGD];
        if (idx == 0) {
          NonVirtualOffset[GD] = -OverrideOffset/8 + CurrentVBaseOffset/8;
          VCallOffset[GD] = OverrideOffset/8;
          idx = VCalls.size()+1;
          VCalls.push_back(0);
          D1(printf("  vcall for %s at %d with delta %d most derived %s\n",
                    MD->getNameAsString().c_str(), (int)-idx-3,
                    (int)VCalls[idx-1], Class->getNameAsCString()));
        } else {
          NonVirtualOffset[GD] = NonVirtualOffset[OGD];
          VCallOffset[GD] = VCallOffset[OGD];
          VCalls[idx-1] = -VCallOffset[OGD] + OverrideOffset/8;
          D1(printf("  vcall patch for %s at %d with delta %d most derived %s\n",
                    MD->getNameAsString().c_str(), (int)-idx-3,
                    (int)VCalls[idx-1], Class->getNameAsCString()));
        }
        VCall[GD] = idx;
        int64_t NonVirtualAdjustment = NonVirtualOffset[GD];
        int64_t VirtualAdjustment = 
          -((idx + extra + 2) * LLVMPointerWidth / 8);
        
        // Optimize out virtual adjustments of 0.
        if (VCalls[idx-1] == 0)
          VirtualAdjustment = 0;
        
        ThunkAdjustment ThisAdjustment(NonVirtualAdjustment,
                                       VirtualAdjustment);

        if (!isPure && !ThisAdjustment.isEmpty())
          Thunks[i] = Thunk(GD, ThisAdjustment);
        return true;
      }

      // FIXME: finish off
      int64_t NonVirtualAdjustment = VCallOffset[OGD] - OverrideOffset/8;

      if (NonVirtualAdjustment) {
        ThunkAdjustment ThisAdjustment(NonVirtualAdjustment, 0);
        
        if (!isPure)
          Thunks[i] = Thunk(GD, ThisAdjustment);
      }
      return true;
    }
  }

  return false;
}

void CGVtableInfo::ComputeMethodVtableIndices(const CXXRecordDecl *RD) {
  
  // Itanium C++ ABI 2.5.2:
  // The order of the virtual function pointers in a virtual table is the 
  // order of declaration of the corresponding member functions in the class.
  //
  // There is an entry for any virtual function declared in a class, 
  // whether it is a new function or overrides a base class function, 
  // unless it overrides a function from the primary base, and conversion
  // between their return types does not require an adjustment. 

  int64_t CurrentIndex = 0;
  
  const ASTRecordLayout &Layout = CGM.getContext().getASTRecordLayout(RD);
  const CXXRecordDecl *PrimaryBase = Layout.getPrimaryBase();
  
  if (PrimaryBase) {
    assert(PrimaryBase->isDefinition() && 
           "Should have the definition decl of the primary base!");

    // Since the record decl shares its vtable pointer with the primary base
    // we need to start counting at the end of the primary base's vtable.
    CurrentIndex = getNumVirtualFunctionPointers(PrimaryBase);
  }
  
  const CXXDestructorDecl *ImplicitVirtualDtor = 0;
  
  for (CXXRecordDecl::method_iterator i = RD->method_begin(),
       e = RD->method_end(); i != e; ++i) {
    const CXXMethodDecl *MD = *i;

    // We only want virtual methods.
    if (!MD->isVirtual())
      continue;

    bool ShouldAddEntryForMethod = true;
    
    // Check if this method overrides a method in the primary base.
    for (CXXMethodDecl::method_iterator i = MD->begin_overridden_methods(),
         e = MD->end_overridden_methods(); i != e; ++i) {
      const CXXMethodDecl *OverriddenMD = *i;
      const CXXRecordDecl *OverriddenRD = OverriddenMD->getParent();
      assert(OverriddenMD->isCanonicalDecl() &&
             "Should have the canonical decl of the overridden RD!");
      
      if (OverriddenRD == PrimaryBase) {
        // Check if converting from the return type of the method to the 
        // return type of the overridden method requires conversion.
        QualType ReturnType = 
          MD->getType()->getAs<FunctionType>()->getResultType();
        QualType OverriddenReturnType =
          OverriddenMD->getType()->getAs<FunctionType>()->getResultType();
        
        if (!TypeConversionRequiresAdjustment(CGM.getContext(), 
                                            ReturnType, OverriddenReturnType)) {
          // This index is shared between the index in the vtable of the primary
          // base class.
          if (const CXXDestructorDecl *DD = dyn_cast<CXXDestructorDecl>(MD)) {
            const CXXDestructorDecl *OverriddenDD = 
              cast<CXXDestructorDecl>(OverriddenMD);
            
            // Add both the complete and deleting entries.
            MethodVtableIndices[GlobalDecl(DD, Dtor_Complete)] = 
              getMethodVtableIndex(GlobalDecl(OverriddenDD, Dtor_Complete));
            MethodVtableIndices[GlobalDecl(DD, Dtor_Deleting)] = 
              getMethodVtableIndex(GlobalDecl(OverriddenDD, Dtor_Deleting));
          } else {
            MethodVtableIndices[MD] = getMethodVtableIndex(OverriddenMD);
          }
          
          // We don't need to add an entry for this method.
          ShouldAddEntryForMethod = false;
          break;
        }        
      }
    }
    
    if (!ShouldAddEntryForMethod)
      continue;
    
    if (const CXXDestructorDecl *DD = dyn_cast<CXXDestructorDecl>(MD)) {
      if (MD->isImplicit()) {
        assert(!ImplicitVirtualDtor && 
               "Did already see an implicit virtual dtor!");
        ImplicitVirtualDtor = DD;
        continue;
      } 

      // Add the complete dtor.
      MethodVtableIndices[GlobalDecl(DD, Dtor_Complete)] = CurrentIndex++;
      
      // Add the deleting dtor.
      MethodVtableIndices[GlobalDecl(DD, Dtor_Deleting)] = CurrentIndex++;
    } else {
      // Add the entry.
      MethodVtableIndices[MD] = CurrentIndex++;
    }
  }

  if (ImplicitVirtualDtor) {
    // Itanium C++ ABI 2.5.2:
    // If a class has an implicitly-defined virtual destructor, 
    // its entries come after the declared virtual function pointers.

    // Add the complete dtor.
    MethodVtableIndices[GlobalDecl(ImplicitVirtualDtor, Dtor_Complete)] = 
      CurrentIndex++;
    
    // Add the deleting dtor.
    MethodVtableIndices[GlobalDecl(ImplicitVirtualDtor, Dtor_Deleting)] = 
      CurrentIndex++;
  }
  
  NumVirtualFunctionPointers[RD] = CurrentIndex;
}

uint64_t CGVtableInfo::getNumVirtualFunctionPointers(const CXXRecordDecl *RD) {
  llvm::DenseMap<const CXXRecordDecl *, uint64_t>::iterator I = 
    NumVirtualFunctionPointers.find(RD);
  if (I != NumVirtualFunctionPointers.end())
    return I->second;

  ComputeMethodVtableIndices(RD);

  I = NumVirtualFunctionPointers.find(RD);
  assert(I != NumVirtualFunctionPointers.end() && "Did not find entry!");
  return I->second;
}
      
uint64_t CGVtableInfo::getMethodVtableIndex(GlobalDecl GD) {
  MethodVtableIndicesTy::iterator I = MethodVtableIndices.find(GD);
  if (I != MethodVtableIndices.end())
    return I->second;
  
  const CXXRecordDecl *RD = cast<CXXMethodDecl>(GD.getDecl())->getParent();

  ComputeMethodVtableIndices(RD);

  I = MethodVtableIndices.find(GD);
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
  VtableBuilder b(methods, RD, RD, 0, CGM);
  D1(printf("vtable %s\n", RD->getNameAsCString()));
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

llvm::Constant *CodeGenModule::GenerateVtable(const CXXRecordDecl *LayoutClass,
                                              const CXXRecordDecl *RD,
                                              uint64_t Offset) {
  llvm::SmallString<256> OutName;
  if (LayoutClass != RD)
    getMangleContext().mangleCXXCtorVtable(LayoutClass, Offset/8, RD, OutName);
  else
    getMangleContext().mangleCXXVtable(RD, OutName);
  llvm::StringRef Name = OutName.str();

  std::vector<llvm::Constant *> methods;
  llvm::Type *Ptr8Ty=llvm::PointerType::get(llvm::Type::getInt8Ty(VMContext),0);
  int64_t AddressPoint;

  llvm::GlobalVariable *GV = getModule().getGlobalVariable(Name);
  if (GV && AddressPoints[LayoutClass] && !GV->isDeclaration()) {
    AddressPoint=(*(*(AddressPoints[LayoutClass]))[RD])[std::make_pair(RD,
                                                                       Offset)];
    // FIXME: We can never have 0 address point.  Do this for now so gepping
    // retains the same structure.  Later, we'll just assert.
    if (AddressPoint == 0)
      AddressPoint = 1;
  } else {
    VtableBuilder b(methods, RD, LayoutClass, Offset, *this);

    D1(printf("vtable %s\n", RD->getNameAsCString()));
    // First comes the vtables for all the non-virtual bases...
    AddressPoint = b.GenerateVtableForBase(RD, Offset);

    // then the vtables for all the virtual bases.
    b.GenerateVtableForVBases(RD, Offset);

    bool CreateDefinition = true;
    if (LayoutClass != RD)
      CreateDefinition = true;
    else {
      const ASTRecordLayout &Layout = 
        getContext().getASTRecordLayout(LayoutClass);
      
      if (const CXXMethodDecl *KeyFunction = Layout.getKeyFunction()) {
        if (!KeyFunction->getBody()) {
          // If there is a KeyFunction, and it isn't defined, just build a
          // reference to the vtable.
          CreateDefinition = false;
        }
      }
    }

    llvm::Constant *C = 0;
    llvm::Type *type = Ptr8Ty;
    llvm::GlobalVariable::LinkageTypes linktype
      = llvm::GlobalValue::ExternalLinkage;
    if (CreateDefinition) {
      llvm::ArrayType *ntype = llvm::ArrayType::get(Ptr8Ty, methods.size());
      C = llvm::ConstantArray::get(ntype, methods);
      linktype = llvm::GlobalValue::LinkOnceODRLinkage;
      if (LayoutClass->isInAnonymousNamespace())
        linktype = llvm::GlobalValue::InternalLinkage;
      type = ntype;
    }
    llvm::GlobalVariable *OGV = GV;
    GV = new llvm::GlobalVariable(getModule(), type, true, linktype, C, Name);
    if (OGV) {
      GV->takeName(OGV);
      llvm::Constant *NewPtr = llvm::ConstantExpr::getBitCast(GV,
                                                              OGV->getType());
      OGV->replaceAllUsesWith(NewPtr);
      OGV->eraseFromParent();
    }
    bool Hidden = getDeclVisibilityMode(RD) == LangOptions::Hidden;
    if (Hidden)
      GV->setVisibility(llvm::GlobalVariable::HiddenVisibility);
  }
  llvm::Constant *vtable = llvm::ConstantExpr::getBitCast(GV, Ptr8Ty);
  llvm::Constant *AddressPointC;
  uint32_t LLVMPointerWidth = getContext().Target.getPointerWidth(0);
  AddressPointC = llvm::ConstantInt::get(llvm::Type::getInt64Ty(VMContext),
                                         AddressPoint*LLVMPointerWidth/8);
  vtable = llvm::ConstantExpr::getInBoundsGetElementPtr(vtable, &AddressPointC,
                                                        1);

  assert(vtable->getType() == Ptr8Ty);
  return vtable;
}

namespace {
class VTTBuilder {
  /// Inits - The list of values built for the VTT.
  std::vector<llvm::Constant *> &Inits;
  /// Class - The most derived class that this vtable is being built for.
  const CXXRecordDecl *Class;
  CodeGenModule &CGM;  // Per-module state.
  llvm::SmallSet<const CXXRecordDecl *, 32> SeenVBase;
  /// BLayout - Layout for the most derived class that this vtable is being
  /// built for.
  const ASTRecordLayout &BLayout;
  CodeGenModule::AddrMap_t &AddressPoints;
  // vtbl - A pointer to the vtable for Class.
  llvm::Constant *ClassVtbl;
  llvm::LLVMContext &VMContext;

  /// BuildVtablePtr - Build up a referene to the given secondary vtable
  llvm::Constant *BuildVtablePtr(llvm::Constant *vtbl,
                                 const CXXRecordDecl *VtblClass,
                                 const CXXRecordDecl *RD,
                                 uint64_t Offset) {
    int64_t AddressPoint;
    AddressPoint = (*AddressPoints[VtblClass])[std::make_pair(RD, Offset)];    
    // FIXME: We can never have 0 address point.  Do this for now so gepping
    // retains the same structure.  Later we'll just assert.
    if (AddressPoint == 0)
      AddressPoint = 1;
    D1(printf("XXX address point for %s in %s layout %s at offset %d was %d\n",
              RD->getNameAsCString(), VtblClass->getNameAsCString(),
              Class->getNameAsCString(), (int)Offset, (int)AddressPoint));
    uint32_t LLVMPointerWidth = CGM.getContext().Target.getPointerWidth(0);
    llvm::Constant *init;
    init = llvm::ConstantInt::get(llvm::Type::getInt64Ty(VMContext),
                                  AddressPoint*LLVMPointerWidth/8);
    init = llvm::ConstantExpr::getInBoundsGetElementPtr(vtbl, &init, 1);
    return init;
  }

  /// Secondary - Add the secondary vtable pointers to Inits.  Offset is the
  /// current offset in bits to the object we're working on.
  void Secondary(const CXXRecordDecl *RD, llvm::Constant *vtbl,
                 const CXXRecordDecl *VtblClass, uint64_t Offset=0,
                 bool MorallyVirtual=false) {
    if (RD->getNumVBases() == 0 && ! MorallyVirtual)
      return;

    for (CXXRecordDecl::base_class_const_iterator i = RD->bases_begin(),
           e = RD->bases_end(); i != e; ++i) {
      const CXXRecordDecl *Base =
        cast<CXXRecordDecl>(i->getType()->getAs<RecordType>()->getDecl());
      const ASTRecordLayout &Layout = CGM.getContext().getASTRecordLayout(RD);
      const CXXRecordDecl *PrimaryBase = Layout.getPrimaryBase();
      const bool PrimaryBaseWasVirtual = Layout.getPrimaryBaseWasVirtual();
      bool NonVirtualPrimaryBase;
      NonVirtualPrimaryBase = !PrimaryBaseWasVirtual && Base == PrimaryBase;
      bool BaseMorallyVirtual = MorallyVirtual | i->isVirtual();
      uint64_t BaseOffset;
      if (!i->isVirtual()) {
        const ASTRecordLayout &Layout = CGM.getContext().getASTRecordLayout(RD);
        BaseOffset = Offset + Layout.getBaseClassOffset(Base);
      } else
        BaseOffset = BLayout.getVBaseClassOffset(Base);
      llvm::Constant *subvtbl = vtbl;
      const CXXRecordDecl *subVtblClass = VtblClass;
      if ((Base->getNumVBases() || BaseMorallyVirtual)
          && !NonVirtualPrimaryBase) {
        // FIXME: Slightly too many of these for __ZTT8test8_B2
        llvm::Constant *init;
        if (BaseMorallyVirtual)
          init = BuildVtablePtr(vtbl, VtblClass, RD, Offset);
        else {
          init = CGM.getVtableInfo().getCtorVtable(Class, Base, BaseOffset);
          subvtbl = dyn_cast<llvm::Constant>(init->getOperand(0));
          subVtblClass = Base;
        }
        Inits.push_back(init);
      }
      Secondary(Base, subvtbl, subVtblClass, BaseOffset, BaseMorallyVirtual);
    }
  }

  /// BuiltVTT - Add the VTT to Inits.  Offset is the offset in bits to the
  /// currnet object we're working on.
  void BuildVTT(const CXXRecordDecl *RD, uint64_t Offset, bool MorallyVirtual) {
    if (RD->getNumVBases() == 0 && !MorallyVirtual)
      return;

    llvm::Constant *init;
    const CXXRecordDecl *VtblClass;

    // First comes the primary virtual table pointer...
    if (MorallyVirtual) {
      init = BuildVtablePtr(ClassVtbl, Class, RD, Offset);
      VtblClass = Class;
    } else {
      init = CGM.getVtableInfo().getCtorVtable(Class, RD, Offset);
      VtblClass = RD;
    }
    llvm::Constant *vtbl = dyn_cast<llvm::Constant>(init->getOperand(0));
    Inits.push_back(init);

    // then the secondary VTTs....
    SecondaryVTTs(RD, Offset, MorallyVirtual);

    // and last the secondary vtable pointers.
    Secondary(RD, vtbl, VtblClass, Offset, MorallyVirtual);
  }

  /// SecondaryVTTs - Add the secondary VTTs to Inits.  The secondary VTTs are
  /// built from each direct non-virtual proper base that requires a VTT in
  /// declaration order.
  void SecondaryVTTs(const CXXRecordDecl *RD, uint64_t Offset=0,
                     bool MorallyVirtual=false) {
    for (CXXRecordDecl::base_class_const_iterator i = RD->bases_begin(),
           e = RD->bases_end(); i != e; ++i) {
      const CXXRecordDecl *Base =
        cast<CXXRecordDecl>(i->getType()->getAs<RecordType>()->getDecl());
      if (i->isVirtual())
        continue;
      const ASTRecordLayout &Layout = CGM.getContext().getASTRecordLayout(RD);
      uint64_t BaseOffset = Offset + Layout.getBaseClassOffset(Base);
      BuildVTT(Base, BaseOffset, MorallyVirtual);
    }
  }

  /// VirtualVTTs - Add the VTT for each proper virtual base in inheritance
  /// graph preorder.
  void VirtualVTTs(const CXXRecordDecl *RD) {
    for (CXXRecordDecl::base_class_const_iterator i = RD->bases_begin(),
           e = RD->bases_end(); i != e; ++i) {
      const CXXRecordDecl *Base =
        cast<CXXRecordDecl>(i->getType()->getAs<RecordType>()->getDecl());
      if (i->isVirtual() && !SeenVBase.count(Base)) {
        SeenVBase.insert(Base);
        uint64_t BaseOffset = BLayout.getVBaseClassOffset(Base);
        BuildVTT(Base, BaseOffset, true);
      }
      VirtualVTTs(Base);
    }
  }
public:
  VTTBuilder(std::vector<llvm::Constant *> &inits, const CXXRecordDecl *c,
             CodeGenModule &cgm)
    : Inits(inits), Class(c), CGM(cgm),
      BLayout(cgm.getContext().getASTRecordLayout(c)),
      AddressPoints(*cgm.AddressPoints[c]),
      VMContext(cgm.getModule().getContext()) {
    
    // First comes the primary virtual table pointer for the complete class...
    ClassVtbl = CGM.getVtableInfo().getVtable(Class);
    Inits.push_back(ClassVtbl);
    ClassVtbl = dyn_cast<llvm::Constant>(ClassVtbl->getOperand(0));
    
    // then the secondary VTTs...
    SecondaryVTTs(Class);

    // then the secondary vtable pointers...
    Secondary(Class, ClassVtbl, Class);

    // and last, the virtual VTTs.
    VirtualVTTs(Class);
  }
};
}

llvm::Constant *CodeGenModule::GenerateVTT(const CXXRecordDecl *RD) {
  // Only classes that have virtual bases need a VTT.
  if (RD->getNumVBases() == 0)
    return 0;

  llvm::SmallString<256> OutName;
  getMangleContext().mangleCXXVTT(RD, OutName);
  llvm::StringRef Name = OutName.str();

  llvm::GlobalVariable::LinkageTypes linktype;
  linktype = llvm::GlobalValue::LinkOnceODRLinkage;
  if (RD->isInAnonymousNamespace())
    linktype = llvm::GlobalValue::InternalLinkage;
  std::vector<llvm::Constant *> inits;
  llvm::Type *Ptr8Ty=llvm::PointerType::get(llvm::Type::getInt8Ty(VMContext),0);

  D1(printf("vtt %s\n", RD->getNameAsCString()));

  VTTBuilder b(inits, RD, *this);

  llvm::Constant *C;
  llvm::ArrayType *type = llvm::ArrayType::get(Ptr8Ty, inits.size());
  C = llvm::ConstantArray::get(type, inits);
  llvm::GlobalVariable *vtt = new llvm::GlobalVariable(getModule(), type, true,
                                                       linktype, C, Name);
  bool Hidden = getDeclVisibilityMode(RD) == LangOptions::Hidden;
  if (Hidden)
    vtt->setVisibility(llvm::GlobalVariable::HiddenVisibility);
  return llvm::ConstantExpr::getBitCast(vtt, Ptr8Ty);
}

void CGVtableInfo::GenerateClassData(const CXXRecordDecl *RD) {
  Vtables[RD] = CGM.GenerateVtable(RD, RD);
  CGM.GenerateRTTI(RD);
  CGM.GenerateVTT(RD);  
}

llvm::Constant *CGVtableInfo::getVtable(const CXXRecordDecl *RD) {
  llvm::Constant *&vtbl = Vtables[RD];
  if (vtbl)
    return vtbl;
  vtbl = CGM.GenerateVtable(RD, RD);

  bool CreateDefinition = true;

  const ASTRecordLayout &Layout = CGM.getContext().getASTRecordLayout(RD);
  if (const CXXMethodDecl *KeyFunction = Layout.getKeyFunction()) {
    if (!KeyFunction->getBody()) {
      // If there is a KeyFunction, and it isn't defined, just build a
      // reference to the vtable.
      CreateDefinition = false;
    }
  }

  if (CreateDefinition) {
    CGM.GenerateRTTI(RD);
    CGM.GenerateVTT(RD);
  }
  return vtbl;
}

llvm::Constant *CGVtableInfo::getCtorVtable(const CXXRecordDecl *LayoutClass,
                                            const CXXRecordDecl *RD,
                                            uint64_t Offset) {
  return CGM.GenerateVtable(LayoutClass, RD, Offset);
}

void CGVtableInfo::MaybeEmitVtable(GlobalDecl GD) {
  const CXXMethodDecl *MD = cast<CXXMethodDecl>(GD.getDecl());
  const CXXRecordDecl *RD = MD->getParent();

  const ASTRecordLayout &Layout = CGM.getContext().getASTRecordLayout(RD);
  
  // Get the key function.
  const CXXMethodDecl *KeyFunction = Layout.getKeyFunction();
  
  if (!KeyFunction) {
    // If there's no key function, we don't want to emit the vtable here.
    return;
  }

  // Check if we have the key function.
  if (KeyFunction->getCanonicalDecl() != MD->getCanonicalDecl())
    return;
  
  // If the key function is a destructor, we only want to emit the vtable once,
  // so do it for the complete destructor.
  if (isa<CXXDestructorDecl>(MD) && GD.getDtorType() != Dtor_Complete)
    return;

  // Emit the data.
  GenerateClassData(RD);
}

