//== RegionStore.cpp - Field-sensitive store model --------------*- C++ -*--==//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines a basic region store model. In this model, we do have field
// sensitivity. But we assume nothing about the heap shape. So recursive data
// structures are largely ignored. Basically we do 1-limiting analysis.
// Parameter pointers are assumed with no aliasing. Pointee objects of
// parameters are created lazily.
//
//===----------------------------------------------------------------------===//
#include "clang/Checker/PathSensitive/MemRegion.h"
#include "clang/Analysis/AnalysisContext.h"
#include "clang/Checker/PathSensitive/GRState.h"
#include "clang/Checker/PathSensitive/GRStateTrait.h"
#include "clang/Analysis/Analyses/LiveVariables.h"
#include "clang/Analysis/Support/Optional.h"
#include "clang/Basic/TargetInfo.h"
#include "clang/AST/CharUnits.h"

#include "llvm/ADT/ImmutableMap.h"
#include "llvm/ADT/ImmutableList.h"
#include "llvm/Support/raw_ostream.h"

using namespace clang;

#define USE_EXPLICIT_COMPOUND 0

//===----------------------------------------------------------------------===//
// Representation of binding keys.
//===----------------------------------------------------------------------===//

namespace {
class BindingKey {
public:
  enum Kind { Direct = 0x0, Default = 0x1 };
private:
  llvm ::PointerIntPair<const MemRegion*, 1> P;
  uint64_t Offset;  
  
  explicit BindingKey(const MemRegion *r, uint64_t offset, Kind k)
    : P(r, (unsigned) k), Offset(offset) { assert(r); }
public:
  
  bool isDefault() const { return P.getInt() == Default; }
  bool isDirect() const { return P.getInt() == Direct; }
  
  const MemRegion *getRegion() const { return P.getPointer(); }
  uint64_t getOffset() const { return Offset; }
  
  void Profile(llvm::FoldingSetNodeID& ID) const {
    ID.AddPointer(P.getOpaqueValue());
    ID.AddInteger(Offset);
  }
  
  static BindingKey Make(const MemRegion *R, Kind k);
  
  bool operator<(const BindingKey &X) const {
    if (P.getOpaqueValue() < X.P.getOpaqueValue())
      return true;
    if (P.getOpaqueValue() > X.P.getOpaqueValue())
      return false;
    return Offset < X.Offset;
  }
  
  bool operator==(const BindingKey &X) const {
    return P.getOpaqueValue() == X.P.getOpaqueValue() &&
           Offset == X.Offset;
  }
};    
} // end anonymous namespace

namespace llvm {
  static inline 
  llvm::raw_ostream& operator<<(llvm::raw_ostream& os, BindingKey K) {
    os << '(' << K.getRegion() << ',' << K.getOffset()
       << ',' << (K.isDirect() ? "direct" : "default")
       << ')';
    return os;
  }
} // end llvm namespace

//===----------------------------------------------------------------------===//
// Actual Store type.
//===----------------------------------------------------------------------===//

typedef llvm::ImmutableMap<BindingKey, SVal> RegionBindings;

//===----------------------------------------------------------------------===//
// Fine-grained control of RegionStoreManager.
//===----------------------------------------------------------------------===//

namespace {
struct minimal_features_tag {};
struct maximal_features_tag {};

class RegionStoreFeatures {
  bool SupportsFields;
  bool SupportsRemaining;

public:
  RegionStoreFeatures(minimal_features_tag) :
    SupportsFields(false), SupportsRemaining(false) {}

  RegionStoreFeatures(maximal_features_tag) :
    SupportsFields(true), SupportsRemaining(false) {}

  void enableFields(bool t) { SupportsFields = t; }

  bool supportsFields() const { return SupportsFields; }
  bool supportsRemaining() const { return SupportsRemaining; }
};
}

//===----------------------------------------------------------------------===//
// Region "Extents"
//===----------------------------------------------------------------------===//
//
//  MemRegions represent chunks of memory with a size (their "extent").  This
//  GDM entry tracks the extents for regions.  Extents are in bytes.
//
namespace { class RegionExtents {}; }
static int RegionExtentsIndex = 0;
namespace clang {
  template<> struct GRStateTrait<RegionExtents>
    : public GRStatePartialTrait<llvm::ImmutableMap<const MemRegion*, SVal> > {
    static void* GDMIndex() { return &RegionExtentsIndex; }
  };
}

//===----------------------------------------------------------------------===//
// Utility functions.
//===----------------------------------------------------------------------===//

static bool IsAnyPointerOrIntptr(QualType ty, ASTContext &Ctx) {
  if (ty->isAnyPointerType())
    return true;

  return ty->isIntegerType() && ty->isScalarType() &&
         Ctx.getTypeSize(ty) == Ctx.getTypeSize(Ctx.VoidPtrTy);
}

//===----------------------------------------------------------------------===//
// Main RegionStore logic.
//===----------------------------------------------------------------------===//

namespace {

class RegionStoreSubRegionMap : public SubRegionMap {
public:
  typedef llvm::ImmutableSet<const MemRegion*> Set;
  typedef llvm::DenseMap<const MemRegion*, Set> Map;
private:
  Set::Factory F;
  Map M;
public:
  bool add(const MemRegion* Parent, const MemRegion* SubRegion) {
    Map::iterator I = M.find(Parent);

    if (I == M.end()) {
      M.insert(std::make_pair(Parent, F.Add(F.GetEmptySet(), SubRegion)));
      return true;
    }

    I->second = F.Add(I->second, SubRegion);
    return false;
  }

  void process(llvm::SmallVectorImpl<const SubRegion*> &WL, const SubRegion *R);

  ~RegionStoreSubRegionMap() {}
  
  const Set *getSubRegions(const MemRegion *Parent) const {
    Map::const_iterator I = M.find(Parent);
    return I == M.end() ? NULL : &I->second;
  }

  bool iterSubRegions(const MemRegion* Parent, Visitor& V) const {
    Map::const_iterator I = M.find(Parent);

    if (I == M.end())
      return true;

    Set S = I->second;
    for (Set::iterator SI=S.begin(),SE=S.end(); SI != SE; ++SI) {
      if (!V.Visit(Parent, *SI))
        return false;
    }

    return true;
  }
};

  
class RegionStoreManager : public StoreManager {
  const RegionStoreFeatures Features;
  RegionBindings::Factory RBFactory;
  
  typedef llvm::DenseMap<Store, RegionStoreSubRegionMap*> SMCache;
  SMCache SC;

public:
  RegionStoreManager(GRStateManager& mgr, const RegionStoreFeatures &f)
    : StoreManager(mgr),
      Features(f),
      RBFactory(mgr.getAllocator()) {}

  virtual ~RegionStoreManager() {
    for (SMCache::iterator I = SC.begin(), E = SC.end(); I != E; ++I)
      delete (*I).second;
  }

  SubRegionMap *getSubRegionMap(Store store) {
    return getRegionStoreSubRegionMap(store);
  }

  RegionStoreSubRegionMap *getRegionStoreSubRegionMap(Store store);

  Optional<SVal> getBinding(RegionBindings B, const MemRegion *R);
  Optional<SVal> getDirectBinding(RegionBindings B, const MemRegion *R);
  /// getDefaultBinding - Returns an SVal* representing an optional default
  ///  binding associated with a region and its subregions.
  Optional<SVal> getDefaultBinding(RegionBindings B, const MemRegion *R);
  
  /// setImplicitDefaultValue - Set the default binding for the provided
  ///  MemRegion to the value implicitly defined for compound literals when
  ///  the value is not specified.  
  Store setImplicitDefaultValue(Store store, const MemRegion *R, QualType T);

  /// getLValueString - Returns an SVal representing the lvalue of a
  ///  StringLiteral.  Within RegionStore a StringLiteral has an
  ///  associated StringRegion, and the lvalue of a StringLiteral is
  ///  the lvalue of that region.
  SVal getLValueString(const StringLiteral* S);

  /// getLValueCompoundLiteral - Returns an SVal representing the
  ///   lvalue of a compound literal.  Within RegionStore a compound
  ///   literal has an associated region, and the lvalue of the
  ///   compound literal is the lvalue of that region.
  SVal getLValueCompoundLiteral(const CompoundLiteralExpr*);

  /// getLValueVar - Returns an SVal that represents the lvalue of a
  ///  variable.  Within RegionStore a variable has an associated
  ///  VarRegion, and the lvalue of the variable is the lvalue of that region.
  SVal getLValueVar(const VarDecl *VD, const LocationContext *LC);

  SVal getLValueIvar(const ObjCIvarDecl* D, SVal Base);

  SVal getLValueField(const FieldDecl* D, SVal Base);

  SVal getLValueFieldOrIvar(const Decl* D, SVal Base);

  SVal getLValueElement(QualType elementType, SVal Offset, SVal Base);


  /// ArrayToPointer - Emulates the "decay" of an array to a pointer
  ///  type.  'Array' represents the lvalue of the array being decayed
  ///  to a pointer, and the returned SVal represents the decayed
  ///  version of that lvalue (i.e., a pointer to the first element of
  ///  the array).  This is called by GRExprEngine when evaluating
  ///  casts from arrays to pointers.
  SVal ArrayToPointer(Loc Array);

  SVal EvalBinOp(BinaryOperator::Opcode Op,Loc L, NonLoc R, QualType resultTy);

  Store getInitialStore(const LocationContext *InitLoc) {
    return RBFactory.GetEmptyMap().getRoot();
  }

  //===-------------------------------------------------------------------===//
  // Binding values to regions.
  //===-------------------------------------------------------------------===//

  Store InvalidateRegion(Store store, const MemRegion *R, const Expr *E, 
                         unsigned Count, InvalidatedSymbols *IS) {
    return RegionStoreManager::InvalidateRegions(store, &R, &R+1, E, Count, IS);
  }
  
  Store InvalidateRegions(Store store,
                          const MemRegion * const *Begin,
                          const MemRegion * const *End,
                          const Expr *E, unsigned Count,
                          InvalidatedSymbols *IS);

public:   // Made public for helper classes.
  
  void RemoveSubRegionBindings(RegionBindings &B, const MemRegion *R,
                               RegionStoreSubRegionMap &M);

  RegionBindings Add(RegionBindings B, BindingKey K, SVal V);

  RegionBindings Add(RegionBindings B, const MemRegion *R,
                     BindingKey::Kind k, SVal V);
  
  const SVal *Lookup(RegionBindings B, BindingKey K);
  const SVal *Lookup(RegionBindings B, const MemRegion *R, BindingKey::Kind k);

  RegionBindings Remove(RegionBindings B, BindingKey K);
  RegionBindings Remove(RegionBindings B, const MemRegion *R,
                        BindingKey::Kind k);
  
  RegionBindings Remove(RegionBindings B, const MemRegion *R) {
    return Remove(Remove(B, R, BindingKey::Direct), R, BindingKey::Default);
  }    

  Store Remove(Store store, BindingKey K);

public: // Part of public interface to class.

  Store Bind(Store store, Loc LV, SVal V);

  Store BindCompoundLiteral(Store store, const CompoundLiteralExpr* CL,
                            const LocationContext *LC, SVal V);

  Store BindDecl(Store store, const VarRegion *VR, SVal InitVal);

  Store BindDeclWithNoInit(Store store, const VarRegion *) {
    return store;
  }

  /// BindStruct - Bind a compound value to a structure.
  Store BindStruct(Store store, const TypedRegion* R, SVal V);

  Store BindArray(Store store, const TypedRegion* R, SVal V);

  /// KillStruct - Set the entire struct to unknown.
  Store KillStruct(Store store, const TypedRegion* R);

  Store Remove(Store store, Loc LV);
  

  //===------------------------------------------------------------------===//
  // Loading values from regions.
  //===------------------------------------------------------------------===//

  /// The high level logic for this method is this:
  /// Retrieve (L)
  ///   if L has binding
  ///     return L's binding
  ///   else if L is in killset
  ///     return unknown
  ///   else
  ///     if L is on stack or heap
  ///       return undefined
  ///     else
  ///       return symbolic
  SVal Retrieve(Store store, Loc L, QualType T = QualType());

  SVal RetrieveElement(Store store, const ElementRegion *R);

  SVal RetrieveField(Store store, const FieldRegion *R);

  SVal RetrieveObjCIvar(Store store, const ObjCIvarRegion *R);

  SVal RetrieveVar(Store store, const VarRegion *R);

  SVal RetrieveLazySymbol(const TypedRegion *R);

  SVal RetrieveFieldOrElementCommon(Store store, const TypedRegion *R,
                                    QualType Ty, const MemRegion *superR);

  /// Retrieve the values in a struct and return a CompoundVal, used when doing
  /// struct copy:
  /// struct s x, y;
  /// x = y;
  /// y's value is retrieved by this method.
  SVal RetrieveStruct(Store store, const TypedRegion* R);

  SVal RetrieveArray(Store store, const TypedRegion* R);

  /// Get the state and region whose binding this region R corresponds to.
  std::pair<Store, const MemRegion*>
  GetLazyBinding(RegionBindings B, const MemRegion *R);

  Store CopyLazyBindings(nonloc::LazyCompoundVal V, Store store,
                         const TypedRegion *R);

  const ElementRegion *GetElementZeroRegion(const SymbolicRegion *SR,
                                            QualType T);

  //===------------------------------------------------------------------===//
  // State pruning.
  //===------------------------------------------------------------------===//

  /// RemoveDeadBindings - Scans the RegionStore of 'state' for dead values.
  ///  It returns a new Store with these values removed.
  Store RemoveDeadBindings(Store store, Stmt* Loc, SymbolReaper& SymReaper,
                          llvm::SmallVectorImpl<const MemRegion*>& RegionRoots);

  const GRState *EnterStackFrame(const GRState *state,
                                 const StackFrameContext *frame);

  //===------------------------------------------------------------------===//
  // Region "extents".
  //===------------------------------------------------------------------===//

  const GRState *setExtent(const GRState *state,const MemRegion* R,SVal Extent);
  DefinedOrUnknownSVal getSizeInElements(const GRState *state, 
                                         const MemRegion* R, QualType EleTy);

  //===------------------------------------------------------------------===//
  // Utility methods.
  //===------------------------------------------------------------------===//

  static inline RegionBindings GetRegionBindings(Store store) {
    return RegionBindings(static_cast<const RegionBindings::TreeTy*>(store));
  }

  void print(Store store, llvm::raw_ostream& Out, const char* nl,
             const char *sep);

  void iterBindings(Store store, BindingsHandler& f) {
    // FIXME: Implement.
  }

  // FIXME: Remove.
  BasicValueFactory& getBasicVals() {
      return StateMgr.getBasicVals();
  }

  // FIXME: Remove.
  ASTContext& getContext() { return StateMgr.getContext(); }
};

} // end anonymous namespace

//===----------------------------------------------------------------------===//
// RegionStore creation.
//===----------------------------------------------------------------------===//

StoreManager *clang::CreateRegionStoreManager(GRStateManager& StMgr) {
  RegionStoreFeatures F = maximal_features_tag();
  return new RegionStoreManager(StMgr, F);
}

StoreManager *clang::CreateFieldsOnlyRegionStoreManager(GRStateManager &StMgr) {
  RegionStoreFeatures F = minimal_features_tag();
  F.enableFields(true);
  return new RegionStoreManager(StMgr, F);
}

void
RegionStoreSubRegionMap::process(llvm::SmallVectorImpl<const SubRegion*> &WL,
                                 const SubRegion *R) {
  const MemRegion *superR = R->getSuperRegion();
  if (add(superR, R))
    if (const SubRegion *sr = dyn_cast<SubRegion>(superR))
      WL.push_back(sr);
}

RegionStoreSubRegionMap*
RegionStoreManager::getRegionStoreSubRegionMap(Store store) {
  RegionBindings B = GetRegionBindings(store);
  RegionStoreSubRegionMap *M = new RegionStoreSubRegionMap();

  llvm::SmallVector<const SubRegion*, 10> WL;

  for (RegionBindings::iterator I=B.begin(), E=B.end(); I!=E; ++I)
    if (const SubRegion *R = dyn_cast<SubRegion>(I.getKey().getRegion()))
      M->process(WL, R);

  // We also need to record in the subregion map "intermediate" regions that
  // don't have direct bindings but are super regions of those that do.
  while (!WL.empty()) {
    const SubRegion *R = WL.back();
    WL.pop_back();
    M->process(WL, R);
  }

  return M;
}

//===----------------------------------------------------------------------===//
// Binding invalidation.
//===----------------------------------------------------------------------===//

void RegionStoreManager::RemoveSubRegionBindings(RegionBindings &B,
                                                 const MemRegion *R,
                                                 RegionStoreSubRegionMap &M) {
  
  if (const RegionStoreSubRegionMap::Set *S = M.getSubRegions(R))
    for (RegionStoreSubRegionMap::Set::iterator I = S->begin(), E = S->end();
         I != E; ++I)
      RemoveSubRegionBindings(B, *I, M);
  
  B = Remove(B, R);
}

namespace {
class InvalidateRegionsWorker {
  typedef BumpVector<BindingKey> RegionCluster;
  typedef llvm::DenseMap<const MemRegion *, RegionCluster *> ClusterMap;
  typedef llvm::SmallVector<std::pair<const MemRegion *,RegionCluster*>, 10>
          WorkList;

  BumpVectorContext BVC;
  ClusterMap ClusterM;
  WorkList WL;  
public:
  Store InvalidateRegions(RegionStoreManager &RM, Store store,
                          const MemRegion * const *I,const MemRegion * const *E,
                          const Expr *Ex, unsigned Count,
                          StoreManager::InvalidatedSymbols *IS,
                          ASTContext &Ctx, ValueManager &ValMgr);
  
private:
  void AddToWorkList(BindingKey K);
  void AddToWorkList(const MemRegion *R);
  void AddToCluster(BindingKey K);
  RegionCluster **getCluster(const MemRegion *R);
};  
}

void InvalidateRegionsWorker::AddToCluster(BindingKey K) {
  const MemRegion *R = K.getRegion();
  const MemRegion *baseR = R->getBaseRegion();
  RegionCluster **CPtr = getCluster(baseR);
  assert(*CPtr);
  (*CPtr)->push_back(K, BVC);
}

void InvalidateRegionsWorker::AddToWorkList(BindingKey K) {
  AddToWorkList(K.getRegion());
}

void InvalidateRegionsWorker::AddToWorkList(const MemRegion *R) {
  const MemRegion *baseR = R->getBaseRegion();
  RegionCluster **CPtr = getCluster(baseR);
  if (RegionCluster *C = *CPtr) {
    WL.push_back(std::make_pair(baseR, C));
    *CPtr = NULL;
  }
}  

InvalidateRegionsWorker::RegionCluster **
InvalidateRegionsWorker::getCluster(const MemRegion *R) {
  RegionCluster *&CRef = ClusterM[R];
  if (!CRef) {
    void *Mem = BVC.getAllocator().Allocate<RegionCluster>();
    CRef = new (Mem) RegionCluster(BVC, 10);
  }
  return &CRef;
}

Store InvalidateRegionsWorker::InvalidateRegions(RegionStoreManager &RM,
                                                 Store store,
                                                 const MemRegion * const *I,
                                                 const MemRegion * const *E,
                                                 const Expr *Ex, unsigned Count,
                                           StoreManager::InvalidatedSymbols *IS,
                                                 ASTContext &Ctx,
                                                 ValueManager &ValMgr) {
  RegionBindings B = RegionStoreManager::GetRegionBindings(store);

  // Scan the entire store and make the region clusters.
  for (RegionBindings::iterator RI = B.begin(), RE = B.end(); RI != RE; ++RI) {
    AddToCluster(RI.getKey());
    if (const MemRegion *R = RI.getData().getAsRegion()) {
      // Generate a cluster, but don't add the region to the cluster
      // if there aren't any bindings.
      getCluster(R->getBaseRegion());
    }
  }
  
  // Add the cluster for I .. E to a worklist.
  for ( ; I != E; ++I)
    AddToWorkList(*I);

  while (!WL.empty()) {
    const MemRegion *baseR;
    RegionCluster *C;    
    llvm::tie(baseR, C) = WL.back();
    WL.pop_back();
    
    for (RegionCluster::iterator I = C->begin(), E = C->end(); I != E; ++I) {
      BindingKey K = *I;
      
      // Get the old binding.  Is it a region?  If so, add it to the worklist.
      if (const SVal *V = RM.Lookup(B, K)) {
        if (const MemRegion *R = V->getAsRegion())
          AddToWorkList(R);
    
        // A symbol?  Mark it touched by the invalidation.
        if (IS)
          if (SymbolRef Sym = V->getAsSymbol())
            IS->insert(Sym);
      }

      B = RM.Remove(B, K);
    }
    
    // Now inspect the base region.

    if (IS) {
      // Symbolic region?  Mark that symbol touched by the invalidation.
      if (const SymbolicRegion *SR = dyn_cast<SymbolicRegion>(baseR))
        IS->insert(SR->getSymbol());
    }
    
    // BlockDataRegion?  If so, invalidate captured variables that are passed
    // by reference.
    if (const BlockDataRegion *BR = dyn_cast<BlockDataRegion>(baseR)) {
      for (BlockDataRegion::referenced_vars_iterator
           BI = BR->referenced_vars_begin(), BE = BR->referenced_vars_end() ;
           BI != BE; ++BI) {
        const VarRegion *VR = *BI;
        const VarDecl *VD = VR->getDecl();
        if (VD->getAttr<BlocksAttr>() || !VD->hasLocalStorage())
          AddToWorkList(VR);
      }
      continue;
    }
    
    if (isa<AllocaRegion>(baseR) || isa<SymbolicRegion>(baseR)) {
      // Invalidate the region by setting its default value to
      // conjured symbol. The type of the symbol is irrelavant.
      DefinedOrUnknownSVal V = ValMgr.getConjuredSymbolVal(baseR, Ex, Ctx.IntTy,
                                                           Count);
      B = RM.Add(B, baseR, BindingKey::Default, V);
      continue;
    }
    
    if (!baseR->isBoundable())
      continue;      
      
    const TypedRegion *TR = cast<TypedRegion>(baseR);
    QualType T = TR->getValueType(Ctx);
    
    // Invalidate the binding.      
    if (const RecordType *RT = T->getAsStructureType()) {
      const RecordDecl *RD = RT->getDecl()->getDefinition(Ctx);      
      // No record definition.  There is nothing we can do.
      if (!RD) {
        B = RM.Remove(B, baseR);
        continue;
      }
    
      // Invalidate the region by setting its default value to
      // conjured symbol. The type of the symbol is irrelavant.
      DefinedOrUnknownSVal V = ValMgr.getConjuredSymbolVal(baseR, Ex, Ctx.IntTy,
                                                           Count);
      B = RM.Add(B, baseR, BindingKey::Default, V);
      continue;
    }    

    if (const ArrayType *AT = Ctx.getAsArrayType(T)) {
      // Set the default value of the array to conjured symbol.
      DefinedOrUnknownSVal V =
        ValMgr.getConjuredSymbolVal(baseR, Ex, AT->getElementType(), Count);
      B = RM.Add(B, baseR, BindingKey::Default, V);
      continue;
    }
      
    DefinedOrUnknownSVal V = ValMgr.getConjuredSymbolVal(baseR, Ex, T, Count);
    assert(SymbolManager::canSymbolicate(T) || V.isUnknown());
    B = RM.Add(B, baseR, BindingKey::Direct, V);
  }

  // Create a new state with the updated bindings.
  return B.getRoot();
}

Store RegionStoreManager::InvalidateRegions(Store store,
                                            const MemRegion * const *I,
                                            const MemRegion * const *E,
                                            const Expr *Ex, unsigned Count,
                                            InvalidatedSymbols *IS) {
  InvalidateRegionsWorker W;
  return W.InvalidateRegions(*this, store, I, E, Ex, Count, IS, getContext(),
                             StateMgr.getValueManager());
}
  
 
//===----------------------------------------------------------------------===//
// getLValueXXX methods.
//===----------------------------------------------------------------------===//

/// getLValueString - Returns an SVal representing the lvalue of a
///  StringLiteral.  Within RegionStore a StringLiteral has an
///  associated StringRegion, and the lvalue of a StringLiteral is the
///  lvalue of that region.
SVal RegionStoreManager::getLValueString(const StringLiteral* S) {
  return loc::MemRegionVal(MRMgr.getStringRegion(S));
}

/// getLValueVar - Returns an SVal that represents the lvalue of a
///  variable.  Within RegionStore a variable has an associated
///  VarRegion, and the lvalue of the variable is the lvalue of that region.
SVal RegionStoreManager::getLValueVar(const VarDecl *VD, 
                                      const LocationContext *LC) {
  return loc::MemRegionVal(MRMgr.getVarRegion(VD, LC));
}

SVal RegionStoreManager::getLValueIvar(const ObjCIvarDecl* D, SVal Base) {
  return getLValueFieldOrIvar(D, Base);
}

SVal RegionStoreManager::getLValueField(const FieldDecl* D, SVal Base) {
  return getLValueFieldOrIvar(D, Base);
}

SVal RegionStoreManager::getLValueFieldOrIvar(const Decl* D, SVal Base) {
  if (Base.isUnknownOrUndef())
    return Base;

  Loc BaseL = cast<Loc>(Base);
  const MemRegion* BaseR = 0;

  switch (BaseL.getSubKind()) {
  case loc::MemRegionKind:
    BaseR = cast<loc::MemRegionVal>(BaseL).getRegion();
    break;

  case loc::GotoLabelKind:
    // These are anormal cases. Flag an undefined value.
    return UndefinedVal();

  case loc::ConcreteIntKind:
    // While these seem funny, this can happen through casts.
    // FIXME: What we should return is the field offset.  For example,
    //  add the field offset to the integer value.  That way funny things
    //  like this work properly:  &(((struct foo *) 0xa)->f)
    return Base;

  default:
    assert(0 && "Unhandled Base.");
    return Base;
  }

  // NOTE: We must have this check first because ObjCIvarDecl is a subclass
  // of FieldDecl.
  if (const ObjCIvarDecl *ID = dyn_cast<ObjCIvarDecl>(D))
    return loc::MemRegionVal(MRMgr.getObjCIvarRegion(ID, BaseR));

  return loc::MemRegionVal(MRMgr.getFieldRegion(cast<FieldDecl>(D), BaseR));
}

SVal RegionStoreManager::getLValueElement(QualType elementType, SVal Offset, 
                                          SVal Base) {

  // If the base is an unknown or undefined value, just return it back.
  // FIXME: For absolute pointer addresses, we just return that value back as
  //  well, although in reality we should return the offset added to that
  //  value.
  if (Base.isUnknownOrUndef() || isa<loc::ConcreteInt>(Base))
    return Base;

  // Only handle integer offsets... for now.
  if (!isa<nonloc::ConcreteInt>(Offset))
    return UnknownVal();

  const MemRegion* BaseRegion = cast<loc::MemRegionVal>(Base).getRegion();

  // Pointer of any type can be cast and used as array base.
  const ElementRegion *ElemR = dyn_cast<ElementRegion>(BaseRegion);

  // Convert the offset to the appropriate size and signedness.
  Offset = ValMgr.convertToArrayIndex(Offset);

  if (!ElemR) {
    //
    // If the base region is not an ElementRegion, create one.
    // This can happen in the following example:
    //
    //   char *p = __builtin_alloc(10);
    //   p[1] = 8;
    //
    //  Observe that 'p' binds to an AllocaRegion.
    //
    return loc::MemRegionVal(MRMgr.getElementRegion(elementType, Offset,
                                                    BaseRegion, getContext()));
  }

  SVal BaseIdx = ElemR->getIndex();

  if (!isa<nonloc::ConcreteInt>(BaseIdx))
    return UnknownVal();

  const llvm::APSInt& BaseIdxI = cast<nonloc::ConcreteInt>(BaseIdx).getValue();
  const llvm::APSInt& OffI = cast<nonloc::ConcreteInt>(Offset).getValue();
  assert(BaseIdxI.isSigned());

  // Compute the new index.
  SVal NewIdx = nonloc::ConcreteInt(getBasicVals().getValue(BaseIdxI + OffI));

  // Construct the new ElementRegion.
  const MemRegion *ArrayR = ElemR->getSuperRegion();
  return loc::MemRegionVal(MRMgr.getElementRegion(elementType, NewIdx, ArrayR,
                                                  getContext()));
}

//===----------------------------------------------------------------------===//
// Extents for regions.
//===----------------------------------------------------------------------===//

DefinedOrUnknownSVal RegionStoreManager::getSizeInElements(const GRState *state,
                                                           const MemRegion *R,
                                                           QualType EleTy) {

  switch (R->getKind()) {
    case MemRegion::CXXThisRegionKind:
      assert(0 && "Cannot get size of 'this' region");      
    case MemRegion::GenericMemSpaceRegionKind:
    case MemRegion::StackLocalsSpaceRegionKind:
    case MemRegion::StackArgumentsSpaceRegionKind:
    case MemRegion::HeapSpaceRegionKind:
    case MemRegion::GlobalsSpaceRegionKind:
    case MemRegion::UnknownSpaceRegionKind:
      assert(0 && "Cannot index into a MemSpace");
      return UnknownVal();

    case MemRegion::FunctionTextRegionKind:
    case MemRegion::BlockTextRegionKind:
    case MemRegion::BlockDataRegionKind:
      // Technically this can happen if people do funny things with casts.
      return UnknownVal();

      // Not yet handled.
    case MemRegion::AllocaRegionKind:
    case MemRegion::CompoundLiteralRegionKind:
    case MemRegion::ElementRegionKind:
    case MemRegion::FieldRegionKind:
    case MemRegion::ObjCIvarRegionKind:
    case MemRegion::CXXObjectRegionKind:
      return UnknownVal();

    case MemRegion::SymbolicRegionKind: {
      const SVal *Size = state->get<RegionExtents>(R);
      if (!Size)
        return UnknownVal();
      const nonloc::ConcreteInt *CI = dyn_cast<nonloc::ConcreteInt>(Size);
      if (!CI)
        return UnknownVal();

      CharUnits RegionSize = 
        CharUnits::fromQuantity(CI->getValue().getSExtValue());
      CharUnits EleSize = getContext().getTypeSizeInChars(EleTy);
      assert(RegionSize % EleSize == 0);

      return ValMgr.makeIntVal(RegionSize / EleSize, false);
    }

    case MemRegion::StringRegionKind: {
      const StringLiteral* Str = cast<StringRegion>(R)->getStringLiteral();
      // We intentionally made the size value signed because it participates in
      // operations with signed indices.
      return ValMgr.makeIntVal(Str->getByteLength()+1, false);
    }

    case MemRegion::VarRegionKind: {
      const VarRegion* VR = cast<VarRegion>(R);
      // Get the type of the variable.
      QualType T = VR->getDesugaredValueType(getContext());

      // FIXME: Handle variable-length arrays.
      if (isa<VariableArrayType>(T))
        return UnknownVal();

      if (const ConstantArrayType* CAT = dyn_cast<ConstantArrayType>(T)) {
        // return the size as signed integer.
        return ValMgr.makeIntVal(CAT->getSize(), false);
      }

      // Clients can use ordinary variables as if they were arrays.  These
      // essentially are arrays of size 1.
      return ValMgr.makeIntVal(1, false);
    }
  }

  assert(0 && "Unreachable");
  return UnknownVal();
}

const GRState *RegionStoreManager::setExtent(const GRState *state,
                                             const MemRegion *region,
                                             SVal extent) {
  return state->set<RegionExtents>(region, extent);
}

//===----------------------------------------------------------------------===//
// Location and region casting.
//===----------------------------------------------------------------------===//

/// ArrayToPointer - Emulates the "decay" of an array to a pointer
///  type.  'Array' represents the lvalue of the array being decayed
///  to a pointer, and the returned SVal represents the decayed
///  version of that lvalue (i.e., a pointer to the first element of
///  the array).  This is called by GRExprEngine when evaluating casts
///  from arrays to pointers.
SVal RegionStoreManager::ArrayToPointer(Loc Array) {
  if (!isa<loc::MemRegionVal>(Array))
    return UnknownVal();

  const MemRegion* R = cast<loc::MemRegionVal>(&Array)->getRegion();
  const TypedRegion* ArrayR = dyn_cast<TypedRegion>(R);

  if (!ArrayR)
    return UnknownVal();

  // Strip off typedefs from the ArrayRegion's ValueType.
  QualType T = ArrayR->getValueType(getContext()).getDesugaredType();
  ArrayType *AT = cast<ArrayType>(T);
  T = AT->getElementType();

  SVal ZeroIdx = ValMgr.makeZeroArrayIndex();
  return loc::MemRegionVal(MRMgr.getElementRegion(T, ZeroIdx, ArrayR,
                                                  getContext()));
}

//===----------------------------------------------------------------------===//
// Pointer arithmetic.
//===----------------------------------------------------------------------===//

SVal RegionStoreManager::EvalBinOp(BinaryOperator::Opcode Op, Loc L, NonLoc R,
                                   QualType resultTy) {
  // Assume the base location is MemRegionVal.
  if (!isa<loc::MemRegionVal>(L))
    return UnknownVal();

  const MemRegion* MR = cast<loc::MemRegionVal>(L).getRegion();
  const ElementRegion *ER = 0;

  switch (MR->getKind()) {
    case MemRegion::SymbolicRegionKind: {
      const SymbolicRegion *SR = cast<SymbolicRegion>(MR);
      SymbolRef Sym = SR->getSymbol();
      QualType T = Sym->getType(getContext());
      QualType EleTy;

      if (const PointerType *PT = T->getAs<PointerType>())
        EleTy = PT->getPointeeType();
      else
        EleTy = T->getAs<ObjCObjectPointerType>()->getPointeeType();

      SVal ZeroIdx = ValMgr.makeZeroArrayIndex();
      ER = MRMgr.getElementRegion(EleTy, ZeroIdx, SR, getContext());
      break;
    }
    case MemRegion::AllocaRegionKind: {
      const AllocaRegion *AR = cast<AllocaRegion>(MR);
      QualType T = getContext().CharTy; // Create an ElementRegion of bytes.
      QualType EleTy = T->getAs<PointerType>()->getPointeeType();
      SVal ZeroIdx = ValMgr.makeZeroArrayIndex();
      ER = MRMgr.getElementRegion(EleTy, ZeroIdx, AR, getContext());
      break;
    }

    case MemRegion::ElementRegionKind: {
      ER = cast<ElementRegion>(MR);
      break;
    }

    // Not yet handled.
    case MemRegion::VarRegionKind:
    case MemRegion::StringRegionKind: {
      
    }
    // Fall-through.
    case MemRegion::CompoundLiteralRegionKind:
    case MemRegion::FieldRegionKind:
    case MemRegion::ObjCIvarRegionKind:
    case MemRegion::CXXObjectRegionKind:
      return UnknownVal();

    case MemRegion::FunctionTextRegionKind:
    case MemRegion::BlockTextRegionKind:
    case MemRegion::BlockDataRegionKind:
      // Technically this can happen if people do funny things with casts.
      return UnknownVal();

    case MemRegion::CXXThisRegionKind:
      assert(0 &&
             "Cannot perform pointer arithmetic on implicit argument 'this'");
    case MemRegion::GenericMemSpaceRegionKind:
    case MemRegion::StackLocalsSpaceRegionKind:
    case MemRegion::StackArgumentsSpaceRegionKind:
    case MemRegion::HeapSpaceRegionKind:
    case MemRegion::GlobalsSpaceRegionKind:
    case MemRegion::UnknownSpaceRegionKind:
      assert(0 && "Cannot perform pointer arithmetic on a MemSpace");
      return UnknownVal();
  }

  SVal Idx = ER->getIndex();
  nonloc::ConcreteInt* Base = dyn_cast<nonloc::ConcreteInt>(&Idx);

  // For now, only support:
  //  (a) concrete integer indices that can easily be resolved
  //  (b) 0 + symbolic index
  if (Base) {
    if (nonloc::ConcreteInt *Offset = dyn_cast<nonloc::ConcreteInt>(&R)) {
      // FIXME: Should use SValuator here.
      SVal NewIdx =
        Base->evalBinOp(ValMgr, Op,
                cast<nonloc::ConcreteInt>(ValMgr.convertToArrayIndex(*Offset)));
      const MemRegion* NewER =
        MRMgr.getElementRegion(ER->getElementType(), NewIdx,
                               ER->getSuperRegion(), getContext());
      return ValMgr.makeLoc(NewER);
    }    
    if (0 == Base->getValue()) {
      const MemRegion* NewER =
        MRMgr.getElementRegion(ER->getElementType(), R,
                               ER->getSuperRegion(), getContext());
      return ValMgr.makeLoc(NewER);      
    }    
  }

  return UnknownVal();
}

//===----------------------------------------------------------------------===//
// Loading values from regions.
//===----------------------------------------------------------------------===//

Optional<SVal> RegionStoreManager::getDirectBinding(RegionBindings B, 
                                                 const MemRegion *R) {
  if (const SVal *V = Lookup(B, R, BindingKey::Direct))
    return *V;  

  return Optional<SVal>();
}

Optional<SVal> RegionStoreManager::getDefaultBinding(RegionBindings B,
                                                     const MemRegion *R) {
  if (R->isBoundable())
    if (const TypedRegion *TR = dyn_cast<TypedRegion>(R))
      if (TR->getValueType(getContext())->isUnionType())
        return UnknownVal();

  if (const SVal *V = Lookup(B, R, BindingKey::Default))
    return *V;

  return Optional<SVal>();
}

Optional<SVal> RegionStoreManager::getBinding(RegionBindings B,
                                              const MemRegion *R) {
  
  if (Optional<SVal> V = getDirectBinding(B, R))
    return V;
  
  return getDefaultBinding(B, R);
}

static bool IsReinterpreted(QualType RTy, QualType UsedTy, ASTContext &Ctx) {
  RTy = Ctx.getCanonicalType(RTy);
  UsedTy = Ctx.getCanonicalType(UsedTy);

  if (RTy == UsedTy)
    return false;


  // Recursively check the types.  We basically want to see if a pointer value
  // is ever reinterpreted as a non-pointer, e.g. void** and intptr_t*
  // represents a reinterpretation.
  if (Loc::IsLocType(RTy) && Loc::IsLocType(UsedTy)) {
    const PointerType *PRTy = RTy->getAs<PointerType>();
    const PointerType *PUsedTy = UsedTy->getAs<PointerType>();

    return PUsedTy && PRTy &&
           IsReinterpreted(PRTy->getPointeeType(),
                           PUsedTy->getPointeeType(), Ctx);
  }

  return true;
}

const ElementRegion *
RegionStoreManager::GetElementZeroRegion(const SymbolicRegion *SR, QualType T) {
  ASTContext &Ctx = getContext();
  SVal idx = ValMgr.makeZeroArrayIndex();
  assert(!T.isNull());
  return MRMgr.getElementRegion(T, idx, SR, Ctx);
}

SVal RegionStoreManager::Retrieve(Store store, Loc L, QualType T) {
  assert(!isa<UnknownVal>(L) && "location unknown");
  assert(!isa<UndefinedVal>(L) && "location undefined");
  
  // FIXME: Is this even possible?  Shouldn't this be treated as a null
  //  dereference at a higher level?
  if (isa<loc::ConcreteInt>(L))
    return UndefinedVal();
  
  const MemRegion *MR = cast<loc::MemRegionVal>(L).getRegion();

  // FIXME: return symbolic value for these cases.
  // Example:
  // void f(int* p) { int x = *p; }
  // char* p = alloca();
  // read(p);
  // c = *p;
  if (isa<AllocaRegion>(MR))
    return UnknownVal();

  if (const SymbolicRegion *SR = dyn_cast<SymbolicRegion>(MR))
    MR = GetElementZeroRegion(SR, T);

  if (isa<CodeTextRegion>(MR))
    return UnknownVal();

  // FIXME: Perhaps this method should just take a 'const MemRegion*' argument
  //  instead of 'Loc', and have the other Loc cases handled at a higher level.
  const TypedRegion *R = cast<TypedRegion>(MR);
  QualType RTy = R->getValueType(getContext());

  // FIXME: We should eventually handle funny addressing.  e.g.:
  //
  //   int x = ...;
  //   int *p = &x;
  //   char *q = (char*) p;
  //   char c = *q;  // returns the first byte of 'x'.
  //
  // Such funny addressing will occur due to layering of regions.

#if 0
  ASTContext &Ctx = getContext();
  if (!T.isNull() && IsReinterpreted(RTy, T, Ctx)) {
    SVal ZeroIdx = ValMgr.makeZeroArrayIndex();
    R = MRMgr.getElementRegion(T, ZeroIdx, R, Ctx);
    RTy = T;
    assert(Ctx.getCanonicalType(RTy) ==
           Ctx.getCanonicalType(R->getValueType(Ctx)));
  }
#endif

  if (RTy->isStructureType())
    return RetrieveStruct(store, R);

  // FIXME: Handle unions.
  if (RTy->isUnionType())
    return UnknownVal();

  if (RTy->isArrayType())
    return RetrieveArray(store, R);

  // FIXME: handle Vector types.
  if (RTy->isVectorType())
    return UnknownVal();

  if (const FieldRegion* FR = dyn_cast<FieldRegion>(R))
    return CastRetrievedVal(RetrieveField(store, FR), FR, T, false);

  if (const ElementRegion* ER = dyn_cast<ElementRegion>(R)) {
    // FIXME: Here we actually perform an implicit conversion from the loaded
    // value to the element type.  Eventually we want to compose these values
    // more intelligently.  For example, an 'element' can encompass multiple
    // bound regions (e.g., several bound bytes), or could be a subset of
    // a larger value.
    return CastRetrievedVal(RetrieveElement(store, ER), ER, T, false);
  }    

  if (const ObjCIvarRegion *IVR = dyn_cast<ObjCIvarRegion>(R)) {
    // FIXME: Here we actually perform an implicit conversion from the loaded
    // value to the ivar type.  What we should model is stores to ivars
    // that blow past the extent of the ivar.  If the address of the ivar is
    // reinterpretted, it is possible we stored a different value that could
    // fit within the ivar.  Either we need to cast these when storing them
    // or reinterpret them lazily (as we do here).
    return CastRetrievedVal(RetrieveObjCIvar(store, IVR), IVR, T, false);
  }

  if (const VarRegion *VR = dyn_cast<VarRegion>(R)) {
    // FIXME: Here we actually perform an implicit conversion from the loaded
    // value to the variable type.  What we should model is stores to variables
    // that blow past the extent of the variable.  If the address of the
    // variable is reinterpretted, it is possible we stored a different value
    // that could fit within the variable.  Either we need to cast these when
    // storing them or reinterpret them lazily (as we do here).    
    return CastRetrievedVal(RetrieveVar(store, VR), VR, T, false);
  }

  RegionBindings B = GetRegionBindings(store);
  const SVal *V = Lookup(B, R, BindingKey::Direct);

  // Check if the region has a binding.
  if (V)
    return *V;

  // The location does not have a bound value.  This means that it has
  // the value it had upon its creation and/or entry to the analyzed
  // function/method.  These are either symbolic values or 'undefined'.
  if (R->hasStackNonParametersStorage()) {
    // All stack variables are considered to have undefined values
    // upon creation.  All heap allocated blocks are considered to
    // have undefined values as well unless they are explicitly bound
    // to specific values.
    return UndefinedVal();
  }

  // All other values are symbolic.
  return ValMgr.getRegionValueSymbolVal(R, RTy);
}

std::pair<Store, const MemRegion *>
RegionStoreManager::GetLazyBinding(RegionBindings B, const MemRegion *R) {
  if (Optional<SVal> OV = getDirectBinding(B, R))
    if (const nonloc::LazyCompoundVal *V =
        dyn_cast<nonloc::LazyCompoundVal>(OV.getPointer()))
      return std::make_pair(V->getStore(), V->getRegion());

  if (const ElementRegion *ER = dyn_cast<ElementRegion>(R)) {
    const std::pair<Store, const MemRegion *> &X =
      GetLazyBinding(B, ER->getSuperRegion());

    if (X.first)
      return std::make_pair(X.first,
                            MRMgr.getElementRegionWithSuper(ER, X.second));
  }
  else if (const FieldRegion *FR = dyn_cast<FieldRegion>(R)) {
    const std::pair<Store, const MemRegion *> &X =
      GetLazyBinding(B, FR->getSuperRegion());

    if (X.first)
      return std::make_pair(X.first,
                            MRMgr.getFieldRegionWithSuper(FR, X.second));
  }

  return std::make_pair((Store) 0, (const MemRegion *) 0);
}

SVal RegionStoreManager::RetrieveElement(Store store,
                                         const ElementRegion* R) {
  // Check if the region has a binding.
  RegionBindings B = GetRegionBindings(store);
  if (Optional<SVal> V = getDirectBinding(B, R))
    return *V;

  const MemRegion* superR = R->getSuperRegion();

  // Check if the region is an element region of a string literal.
  if (const StringRegion *StrR=dyn_cast<StringRegion>(superR)) {
    // FIXME: Handle loads from strings where the literal is treated as 
    // an integer, e.g., *((unsigned int*)"hello")
    ASTContext &Ctx = getContext();
    QualType T = Ctx.getAsArrayType(StrR->getValueType(Ctx))->getElementType();
    if (T != Ctx.getCanonicalType(R->getElementType()))
      return UnknownVal();
    
    const StringLiteral *Str = StrR->getStringLiteral();
    SVal Idx = R->getIndex();
    if (nonloc::ConcreteInt *CI = dyn_cast<nonloc::ConcreteInt>(&Idx)) {
      int64_t i = CI->getValue().getSExtValue();
      int64_t byteLength = Str->getByteLength();
      if (i > byteLength) {
        // Buffer overflow checking in GRExprEngine should handle this case,
        // but we shouldn't rely on it to not overflow here if that checking
        // is disabled.
        return UnknownVal();
      }
      char c = (i == byteLength) ? '\0' : Str->getStrData()[i];
      return ValMgr.makeIntVal(c, T);
    }
  }

  // Check if the immediate super region has a direct binding.
  if (Optional<SVal> V = getDirectBinding(B, superR)) {
    if (SymbolRef parentSym = V->getAsSymbol())
      return ValMgr.getDerivedRegionValueSymbolVal(parentSym, R);

    if (V->isUnknownOrUndef())
      return *V;

    // Handle LazyCompoundVals for the immediate super region.  Other cases
    // are handled in 'RetrieveFieldOrElementCommon'.
    if (const nonloc::LazyCompoundVal *LCV =
        dyn_cast<nonloc::LazyCompoundVal>(V)) {

      R = MRMgr.getElementRegionWithSuper(R, LCV->getRegion());
      return RetrieveElement(LCV->getStore(), R);
    }

    // Other cases: give up.
    return UnknownVal();
  }
    
  return RetrieveFieldOrElementCommon(store, R, R->getElementType(), superR);
}

SVal RegionStoreManager::RetrieveField(Store store,
                                       const FieldRegion* R) {

  // Check if the region has a binding.
  RegionBindings B = GetRegionBindings(store);
  if (Optional<SVal> V = getDirectBinding(B, R))
    return *V;

  QualType Ty = R->getValueType(getContext());
  return RetrieveFieldOrElementCommon(store, R, Ty, R->getSuperRegion());
}

SVal RegionStoreManager::RetrieveFieldOrElementCommon(Store store,
                                                      const TypedRegion *R,
                                                      QualType Ty,
                                                      const MemRegion *superR) {

  // At this point we have already checked in either RetrieveElement or
  // RetrieveField if 'R' has a direct binding.

  RegionBindings B = GetRegionBindings(store);

  while (superR) {
    if (const Optional<SVal> &D = getDefaultBinding(B, superR)) {
      if (SymbolRef parentSym = D->getAsSymbol())
        return ValMgr.getDerivedRegionValueSymbolVal(parentSym, R);

      if (D->isZeroConstant())
        return ValMgr.makeZeroVal(Ty);

      if (D->isUnknown())
        return *D;

      assert(0 && "Unknown default value");
    }

    // If our super region is a field or element itself, walk up the region
    // hierarchy to see if there is a default value installed in an ancestor.
    if (isa<FieldRegion>(superR) || isa<ElementRegion>(superR)) {
      superR = cast<SubRegion>(superR)->getSuperRegion();
      continue;
    }

    break;
  }

  // Lazy binding?
  Store lazyBindingStore = NULL;
  const MemRegion *lazyBindingRegion = NULL;
  llvm::tie(lazyBindingStore, lazyBindingRegion) = GetLazyBinding(B, R);

  if (lazyBindingStore) {
    assert(lazyBindingRegion && "Lazy-binding region not set");

    if (isa<ElementRegion>(R))
      return RetrieveElement(lazyBindingStore,
                             cast<ElementRegion>(lazyBindingRegion));

    return RetrieveField(lazyBindingStore,
                         cast<FieldRegion>(lazyBindingRegion));
  }

  if (R->hasStackNonParametersStorage()) {
    if (isa<ElementRegion>(R)) {
      // Currently we don't reason specially about Clang-style vectors.  Check
      // if superR is a vector and if so return Unknown.
      if (const TypedRegion *typedSuperR = dyn_cast<TypedRegion>(superR)) {
        if (typedSuperR->getValueType(getContext())->isVectorType())
          return UnknownVal();
      }
    }

    return UndefinedVal();
  }

  // All other values are symbolic.
  return ValMgr.getRegionValueSymbolVal(R, Ty);
}

SVal RegionStoreManager::RetrieveObjCIvar(Store store, const ObjCIvarRegion* R){

    // Check if the region has a binding.
  RegionBindings B = GetRegionBindings(store);

  if (Optional<SVal> V = getDirectBinding(B, R))
    return *V;

  const MemRegion *superR = R->getSuperRegion();

  // Check if the super region has a default binding.
  if (Optional<SVal> V = getDefaultBinding(B, superR)) {
    if (SymbolRef parentSym = V->getAsSymbol())
      return ValMgr.getDerivedRegionValueSymbolVal(parentSym, R);

    // Other cases: give up.
    return UnknownVal();
  }

  return RetrieveLazySymbol(R);
}

SVal RegionStoreManager::RetrieveVar(Store store, const VarRegion *R) {

  // Check if the region has a binding.
  RegionBindings B = GetRegionBindings(store);

  if (Optional<SVal> V = getDirectBinding(B, R))
    return *V;

  // Lazily derive a value for the VarRegion.
  const VarDecl *VD = R->getDecl();
  QualType T = VD->getType();
  const MemSpaceRegion *MS = R->getMemorySpace();
  
  if (isa<UnknownSpaceRegion>(MS) || 
      isa<StackArgumentsSpaceRegion>(MS))
    return ValMgr.getRegionValueSymbolVal(R, T);

  if (isa<GlobalsSpaceRegion>(MS)) {
    if (VD->isFileVarDecl())
      return ValMgr.getRegionValueSymbolVal(R, T);

    if (T->isIntegerType())
      return ValMgr.makeIntVal(0, T);
    
    return UnknownVal();    
  }
    
  return UndefinedVal();
}

SVal RegionStoreManager::RetrieveLazySymbol(const TypedRegion *R) {

  QualType valTy = R->getValueType(getContext());

  // All other values are symbolic.
  return ValMgr.getRegionValueSymbolVal(R, valTy);
}

SVal RegionStoreManager::RetrieveStruct(Store store, const TypedRegion* R) {
  QualType T = R->getValueType(getContext());
  assert(T->isStructureType());

  const RecordType* RT = T->getAsStructureType();
  RecordDecl* RD = RT->getDecl();
  assert(RD->isDefinition());
  (void)RD;
#if USE_EXPLICIT_COMPOUND
  llvm::ImmutableList<SVal> StructVal = getBasicVals().getEmptySValList();

  // FIXME: We shouldn't use a std::vector.  If RecordDecl doesn't have a
  // reverse iterator, we should implement one.
  std::vector<FieldDecl *> Fields(RD->field_begin(), RD->field_end());

  for (std::vector<FieldDecl *>::reverse_iterator Field = Fields.rbegin(),
                                               FieldEnd = Fields.rend();
       Field != FieldEnd; ++Field) {
    FieldRegion* FR = MRMgr.getFieldRegion(*Field, R);
    QualType FTy = (*Field)->getType();
    SVal FieldValue = Retrieve(store, loc::MemRegionVal(FR), FTy).getSVal();
    StructVal = getBasicVals().consVals(FieldValue, StructVal);
  }

  return ValMgr.makeCompoundVal(T, StructVal);
#else
  return ValMgr.makeLazyCompoundVal(store, R);
#endif
}

SVal RegionStoreManager::RetrieveArray(Store store, const TypedRegion * R) {
#if USE_EXPLICIT_COMPOUND
  QualType T = R->getValueType(getContext());
  ConstantArrayType* CAT = cast<ConstantArrayType>(T.getTypePtr());

  llvm::ImmutableList<SVal> ArrayVal = getBasicVals().getEmptySValList();
  uint64_t size = CAT->getSize().getZExtValue();
  for (uint64_t i = 0; i < size; ++i) {
    SVal Idx = ValMgr.makeArrayIndex(i);
    ElementRegion* ER = MRMgr.getElementRegion(CAT->getElementType(), Idx, R,
                                               getContext());
    QualType ETy = ER->getElementType();
    SVal ElementVal = Retrieve(store, loc::MemRegionVal(ER), ETy).getSVal();
    ArrayVal = getBasicVals().consVals(ElementVal, ArrayVal);
  }

  return ValMgr.makeCompoundVal(T, ArrayVal);
#else
  assert(isa<ConstantArrayType>(R->getValueType(getContext())));
  return ValMgr.makeLazyCompoundVal(store, R);
#endif
}

//===----------------------------------------------------------------------===//
// Binding values to regions.
//===----------------------------------------------------------------------===//

Store RegionStoreManager::Remove(Store store, Loc L) {
  if (isa<loc::MemRegionVal>(L))
    if (const MemRegion* R = cast<loc::MemRegionVal>(L).getRegion())
      return Remove(GetRegionBindings(store), R).getRoot();

  return store;
}

Store RegionStoreManager::Bind(Store store, Loc L, SVal V) {
  if (isa<loc::ConcreteInt>(L))
    return store;

  // If we get here, the location should be a region.
  const MemRegion *R = cast<loc::MemRegionVal>(L).getRegion();

  // Check if the region is a struct region.
  if (const TypedRegion* TR = dyn_cast<TypedRegion>(R))
    if (TR->getValueType(getContext())->isStructureType())
      return BindStruct(store, TR, V);

  // Special case: the current region represents a cast and it and the super
  // region both have pointer types or intptr_t types.  If so, perform the
  // bind to the super region.
  // This is needed to support OSAtomicCompareAndSwap and friends or other
  // loads that treat integers as pointers and vis versa.
  if (const ElementRegion *ER = dyn_cast<ElementRegion>(R)) {
    if (ER->getIndex().isZeroConstant()) {
      if (const TypedRegion *superR =
            dyn_cast<TypedRegion>(ER->getSuperRegion())) {
        ASTContext &Ctx = getContext();
        QualType superTy = superR->getValueType(Ctx);
        QualType erTy = ER->getValueType(Ctx);

        if (IsAnyPointerOrIntptr(superTy, Ctx) &&
            IsAnyPointerOrIntptr(erTy, Ctx)) {
          V = ValMgr.getSValuator().EvalCast(V, superTy, erTy);
          return Bind(store, loc::MemRegionVal(superR), V);
        }
        // For now, just invalidate the fields of the struct/union/class.
        // FIXME: Precisely handle the fields of the record.
        if (superTy->isRecordType())
          return InvalidateRegion(store, superR, NULL, 0, NULL);
      }
    }
  }
  else if (const SymbolicRegion *SR = dyn_cast<SymbolicRegion>(R)) {
    // Binding directly to a symbolic region should be treated as binding
    // to element 0.
    QualType T = SR->getSymbol()->getType(getContext());
    
    // FIXME: Is this the right way to handle symbols that are references?
    if (const PointerType *PT = T->getAs<PointerType>())
      T = PT->getPointeeType();
    else
      T = T->getAs<ReferenceType>()->getPointeeType();

    R = GetElementZeroRegion(SR, T);
  }

  // Perform the binding.
  RegionBindings B = GetRegionBindings(store);
  return Add(B, R, BindingKey::Direct, V).getRoot();
}

Store RegionStoreManager::BindDecl(Store store, const VarRegion *VR, 
                                   SVal InitVal) {

  QualType T = VR->getDecl()->getType();

  if (T->isArrayType())
    return BindArray(store, VR, InitVal);
  if (T->isStructureType())
    return BindStruct(store, VR, InitVal);

  return Bind(store, ValMgr.makeLoc(VR), InitVal);
}

// FIXME: this method should be merged into Bind().
Store RegionStoreManager::BindCompoundLiteral(Store store,
                                              const CompoundLiteralExpr *CL,
                                              const LocationContext *LC,
                                              SVal V) {
  return Bind(store, loc::MemRegionVal(MRMgr.getCompoundLiteralRegion(CL, LC)),
              V);
}

Store RegionStoreManager::setImplicitDefaultValue(Store store,
                                                  const MemRegion *R,
                                                  QualType T) {
  RegionBindings B = GetRegionBindings(store);
  SVal V;

  if (Loc::IsLocType(T))
    V = ValMgr.makeNull();
  else if (T->isIntegerType())
    V = ValMgr.makeZeroVal(T);
  else if (T->isStructureType() || T->isArrayType()) {
    // Set the default value to a zero constant when it is a structure
    // or array.  The type doesn't really matter.
    V = ValMgr.makeZeroVal(ValMgr.getContext().IntTy);
  }
  else {
    return store;
  }

  return Add(B, R, BindingKey::Default, V).getRoot();
}
  
Store RegionStoreManager::BindArray(Store store, const TypedRegion* R, 
                                    SVal Init) {
  
  ASTContext &Ctx = getContext();
  const ArrayType *AT =
    cast<ArrayType>(Ctx.getCanonicalType(R->getValueType(Ctx)));
  QualType ElementTy = AT->getElementType();  
  Optional<uint64_t> Size;
  
  if (const ConstantArrayType* CAT = dyn_cast<ConstantArrayType>(AT))
    Size = CAT->getSize().getZExtValue();
    
  // Check if the init expr is a StringLiteral.
  if (isa<loc::MemRegionVal>(Init)) {
    const MemRegion* InitR = cast<loc::MemRegionVal>(Init).getRegion();
    const StringLiteral* S = cast<StringRegion>(InitR)->getStringLiteral();
    const char* str = S->getStrData();
    unsigned len = S->getByteLength();
    unsigned j = 0;

    // Copy bytes from the string literal into the target array. Trailing bytes
    // in the array that are not covered by the string literal are initialized
    // to zero.
    
    // We assume that string constants are bound to
    // constant arrays.
    uint64_t size = Size.getValue();
    
    for (uint64_t i = 0; i < size; ++i, ++j) {
      if (j >= len)
        break;

      SVal Idx = ValMgr.makeArrayIndex(i);
      const ElementRegion* ER = MRMgr.getElementRegion(ElementTy, Idx, R,
                                                       getContext());

      SVal V = ValMgr.makeIntVal(str[j], sizeof(char)*8, true);
      store = Bind(store, loc::MemRegionVal(ER), V);
    }

    return store;
  }

  // Handle lazy compound values.
  if (nonloc::LazyCompoundVal *LCV = dyn_cast<nonloc::LazyCompoundVal>(&Init))
    return CopyLazyBindings(*LCV, store, R);

  // Remaining case: explicit compound values.
  
  if (Init.isUnknown())
    return setImplicitDefaultValue(store, R, ElementTy);    
  
  nonloc::CompoundVal& CV = cast<nonloc::CompoundVal>(Init);
  nonloc::CompoundVal::iterator VI = CV.begin(), VE = CV.end();
  uint64_t i = 0;

  for (; Size.hasValue() ? i < Size.getValue() : true ; ++i, ++VI) {
    // The init list might be shorter than the array length.
    if (VI == VE)
      break;

    SVal Idx = ValMgr.makeArrayIndex(i);
    const ElementRegion *ER = MRMgr.getElementRegion(ElementTy, Idx, R, getContext());

    if (ElementTy->isStructureType())
      store = BindStruct(store, ER, *VI);
    else
      store = Bind(store, ValMgr.makeLoc(ER), *VI);
  }

  // If the init list is shorter than the array length, set the
  // array default value.
  if (Size.hasValue() && i < Size.getValue())
    store = setImplicitDefaultValue(store, R, ElementTy);

  return store;
}

Store RegionStoreManager::BindStruct(Store store, const TypedRegion* R,
                                     SVal V) {

  if (!Features.supportsFields())
    return store;

  QualType T = R->getValueType(getContext());
  assert(T->isStructureType());

  const RecordType* RT = T->getAs<RecordType>();
  RecordDecl* RD = RT->getDecl();

  if (!RD->isDefinition())
    return store;

  // Handle lazy compound values.
  if (const nonloc::LazyCompoundVal *LCV=dyn_cast<nonloc::LazyCompoundVal>(&V))
    return CopyLazyBindings(*LCV, store, R);

  // We may get non-CompoundVal accidentally due to imprecise cast logic.
  // Ignore them and kill the field values.
  if (V.isUnknown() || !isa<nonloc::CompoundVal>(V))
    return KillStruct(store, R);

  nonloc::CompoundVal& CV = cast<nonloc::CompoundVal>(V);
  nonloc::CompoundVal::iterator VI = CV.begin(), VE = CV.end();

  RecordDecl::field_iterator FI, FE;

  for (FI = RD->field_begin(), FE = RD->field_end(); FI != FE; ++FI, ++VI) {

    if (VI == VE)
      break;

    QualType FTy = (*FI)->getType();
    const FieldRegion* FR = MRMgr.getFieldRegion(*FI, R);

    if (FTy->isArrayType())
      store = BindArray(store, FR, *VI);
    else if (FTy->isStructureType())
      store = BindStruct(store, FR, *VI);
    else
      store = Bind(store, ValMgr.makeLoc(FR), *VI);
  }

  // There may be fewer values in the initialize list than the fields of struct.
  if (FI != FE) {
    RegionBindings B = GetRegionBindings(store);
    B = Add(B, R, BindingKey::Default, ValMgr.makeIntVal(0, false));
    store = B.getRoot();
  }

  return store;
}

Store RegionStoreManager::KillStruct(Store store, const TypedRegion* R) {
  RegionBindings B = GetRegionBindings(store);
  llvm::OwningPtr<RegionStoreSubRegionMap>
    SubRegions(getRegionStoreSubRegionMap(store));
  RemoveSubRegionBindings(B, R, *SubRegions);

  // Set the default value of the struct region to "unknown".
  return Add(B, R, BindingKey::Default, UnknownVal()).getRoot();
}

Store RegionStoreManager::CopyLazyBindings(nonloc::LazyCompoundVal V,
                                           Store store, const TypedRegion *R) {

  // Nuke the old bindings stemming from R.
  RegionBindings B = GetRegionBindings(store);

  llvm::OwningPtr<RegionStoreSubRegionMap>
    SubRegions(getRegionStoreSubRegionMap(store));

  // B and DVM are updated after the call to RemoveSubRegionBindings.
  RemoveSubRegionBindings(B, R, *SubRegions.get());

  // Now copy the bindings.  This amounts to just binding 'V' to 'R'.  This
  // results in a zero-copy algorithm.
  return Add(B, R, BindingKey::Direct, V).getRoot();
}

//===----------------------------------------------------------------------===//
// "Raw" retrievals and bindings.
//===----------------------------------------------------------------------===//

BindingKey BindingKey::Make(const MemRegion *R, Kind k) {
  if (const ElementRegion *ER = dyn_cast<ElementRegion>(R)) {
    const RegionRawOffset &O = ER->getAsRawOffset();
    
    if (O.getRegion())
      return BindingKey(O.getRegion(), O.getByteOffset(), k);
    
    // FIXME: There are some ElementRegions for which we cannot compute
    // raw offsets yet, including regions with symbolic offsets.
  }
  
  return BindingKey(R, 0, k);
}

RegionBindings RegionStoreManager::Add(RegionBindings B, BindingKey K, SVal V) {
  return RBFactory.Add(B, K, V);
}

RegionBindings RegionStoreManager::Add(RegionBindings B, const MemRegion *R,
                                       BindingKey::Kind k, SVal V) {
  return Add(B, BindingKey::Make(R, k), V);
}

const SVal *RegionStoreManager::Lookup(RegionBindings B, BindingKey K) {
  return B.lookup(K);
}

const SVal *RegionStoreManager::Lookup(RegionBindings B,
                                       const MemRegion *R,
                                       BindingKey::Kind k) {
  return Lookup(B, BindingKey::Make(R, k));
}

RegionBindings RegionStoreManager::Remove(RegionBindings B, BindingKey K) {
  return RBFactory.Remove(B, K);
}

RegionBindings RegionStoreManager::Remove(RegionBindings B, const MemRegion *R,
                                          BindingKey::Kind k){
  return Remove(B, BindingKey::Make(R, k));
}

Store RegionStoreManager::Remove(Store store, BindingKey K) {
  RegionBindings B = GetRegionBindings(store);
  return Remove(B, K).getRoot();
}

//===----------------------------------------------------------------------===//
// State pruning.
//===----------------------------------------------------------------------===//
  
Store RegionStoreManager::RemoveDeadBindings(Store store, Stmt* Loc,
                                             SymbolReaper& SymReaper,
                           llvm::SmallVectorImpl<const MemRegion*>& RegionRoots)
{
  typedef std::pair<Store, const MemRegion *> RBDNode;

  RegionBindings B = GetRegionBindings(store);

  // The backmap from regions to subregions.
  llvm::OwningPtr<RegionStoreSubRegionMap>
    SubRegions(getRegionStoreSubRegionMap(store));
  
  // Do a pass over the regions in the store.  For VarRegions we check if
  // the variable is still live and if so add it to the list of live roots.
  // For other regions we populate our region backmap.
  llvm::SmallVector<const MemRegion*, 10> IntermediateRoots;
  
  // Scan the direct bindings for "intermediate" roots.
  for (RegionBindings::iterator I = B.begin(), E = B.end(); I != E; ++I) {
    const MemRegion *R = I.getKey().getRegion();
    IntermediateRoots.push_back(R);
  }
  
  // Process the "intermediate" roots to find if they are referenced by
  // real roots.
  llvm::SmallVector<RBDNode, 10> WorkList;
  llvm::SmallVector<RBDNode, 10> Postponed;

  llvm::DenseSet<const MemRegion*> IntermediateVisited;
  
  while (!IntermediateRoots.empty()) {
    const MemRegion* R = IntermediateRoots.back();
    IntermediateRoots.pop_back();
    
    if (IntermediateVisited.count(R))
      continue;
    IntermediateVisited.insert(R);
    
    if (const VarRegion* VR = dyn_cast<VarRegion>(R)) {
      if (SymReaper.isLive(Loc, VR))
        WorkList.push_back(std::make_pair(store, VR));
      continue;
    }
    
    if (const SymbolicRegion* SR = dyn_cast<SymbolicRegion>(R)) {
      llvm::SmallVectorImpl<RBDNode> &Q =      
        SymReaper.isLive(SR->getSymbol()) ? WorkList : Postponed;
      
        Q.push_back(std::make_pair(store, SR));

      continue;
    }
    
      // Add the super region for R to the worklist if it is a subregion.
    if (const SubRegion* superR =
        dyn_cast<SubRegion>(cast<SubRegion>(R)->getSuperRegion()))
      IntermediateRoots.push_back(superR);
  }

  // Enqueue the RegionRoots onto WorkList.
  for (llvm::SmallVectorImpl<const MemRegion*>::iterator I=RegionRoots.begin(),
       E=RegionRoots.end(); I!=E; ++I) {
    WorkList.push_back(std::make_pair(store, *I));
  }
  RegionRoots.clear();
  
  llvm::DenseSet<RBDNode> Visited;
  
tryAgain:
  while (!WorkList.empty()) {
    RBDNode N = WorkList.back();
    WorkList.pop_back();
    
    // Have we visited this node before?
    if (Visited.count(N))
      continue;
    Visited.insert(N);

    const MemRegion *R = N.second;
    Store store_N = N.first;
    
    // Enqueue subregions.
    RegionStoreSubRegionMap *M;
      
    if (store == store_N)
      M = SubRegions.get();
    else {
      RegionStoreSubRegionMap *& SM = SC[store_N];
      if (!SM)
        SM = getRegionStoreSubRegionMap(store_N);
      M = SM;
    }

    if (const RegionStoreSubRegionMap::Set *S = M->getSubRegions(R))
      for (RegionStoreSubRegionMap::Set::iterator I = S->begin(), E = S->end();
           I != E; ++I)
        WorkList.push_back(std::make_pair(store_N, *I));

    // Enqueue the super region.
    if (const SubRegion *SR = dyn_cast<SubRegion>(R)) {
      const MemRegion *superR = SR->getSuperRegion();
      if (!isa<MemSpaceRegion>(superR)) {
        // If 'R' is a field or an element, we want to keep the bindings
        // for the other fields and elements around.  The reason is that
        // pointer arithmetic can get us to the other fields or elements.
        assert(isa<FieldRegion>(R) || isa<ElementRegion>(R) 
               || isa<ObjCIvarRegion>(R));
        WorkList.push_back(std::make_pair(store_N, superR));
      }
    }

    // Mark the symbol for any live SymbolicRegion as "live".  This means we
    // should continue to track that symbol.
    if (const SymbolicRegion *SymR = dyn_cast<SymbolicRegion>(R))
      SymReaper.markLive(SymR->getSymbol());
    
    // For BlockDataRegions, enqueue the VarRegions for variables marked
    // with __block (passed-by-reference).
    // via BlockDeclRefExprs.
    if (const BlockDataRegion *BD = dyn_cast<BlockDataRegion>(R)) {
      for (BlockDataRegion::referenced_vars_iterator
            RI = BD->referenced_vars_begin(), RE = BD->referenced_vars_end();
           RI != RE; ++RI) {
        if ((*RI)->getDecl()->getAttr<BlocksAttr>())
          WorkList.push_back(std::make_pair(store_N, *RI));
      }
      // No possible data bindings on a BlockDataRegion.  Continue to the
      // next region in the worklist.
      continue;
    }

    RegionBindings B_N = GetRegionBindings(store_N);
    
    // Get the data binding for R (if any).
    Optional<SVal> V = getBinding(B_N, R);

    if (V) {
      // Check for lazy bindings.
      if (const nonloc::LazyCompoundVal *LCV =
            dyn_cast<nonloc::LazyCompoundVal>(V.getPointer())) {
      
        const LazyCompoundValData *D = LCV->getCVData();
        WorkList.push_back(std::make_pair(D->getStore(), D->getRegion()));
      }
      else {
        // Update the set of live symbols.
        for (SVal::symbol_iterator SI=V->symbol_begin(), SE=V->symbol_end();
             SI!=SE;++SI)
          SymReaper.markLive(*SI);
        
        // If V is a region, then add it to the worklist.
        if (const MemRegion *RX = V->getAsRegion())
          WorkList.push_back(std::make_pair(store_N, RX));
      }
    }
  }
  
  // See if any postponed SymbolicRegions are actually live now, after
  // having done a scan.
  for (llvm::SmallVectorImpl<RBDNode>::iterator I = Postponed.begin(),
       E = Postponed.end() ; I != E ; ++I) {    
    if (const SymbolicRegion *SR = cast_or_null<SymbolicRegion>(I->second)) {
      if (SymReaper.isLive(SR->getSymbol())) {
        WorkList.push_back(*I);
        I->second = NULL;
      }
    }
  }
  
  if (!WorkList.empty())
    goto tryAgain;
  
  // We have now scanned the store, marking reachable regions and symbols
  // as live.  We now remove all the regions that are dead from the store
  // as well as update DSymbols with the set symbols that are now dead.
  Store new_store = store;
  for (RegionBindings::iterator I = B.begin(), E = B.end(); I != E; ++I) {
    const MemRegion* R = I.getKey().getRegion();
    // If this region live?  Is so, none of its symbols are dead.
    if (Visited.count(std::make_pair(store, R)))
      continue;

    // Remove this dead region from the store.
    new_store = Remove(new_store, I.getKey());

    // Mark all non-live symbols that this region references as dead.
    if (const SymbolicRegion* SymR = dyn_cast<SymbolicRegion>(R))
      SymReaper.maybeDead(SymR->getSymbol());

    SVal X = I.getData();
    SVal::symbol_iterator SI = X.symbol_begin(), SE = X.symbol_end();
    for (; SI != SE; ++SI)
      SymReaper.maybeDead(*SI);
  }

  return new_store;
}

GRState const *RegionStoreManager::EnterStackFrame(GRState const *state,
                                               StackFrameContext const *frame) {
  FunctionDecl const *FD = cast<FunctionDecl>(frame->getDecl());
  CallExpr const *CE = cast<CallExpr>(frame->getCallSite());

  FunctionDecl::param_const_iterator PI = FD->param_begin();

  CallExpr::const_arg_iterator AI = CE->arg_begin(), AE = CE->arg_end();

  // Copy the arg expression value to the arg variables.
  Store store = state->getStore();
  for (; AI != AE; ++AI, ++PI) {
    SVal ArgVal = state->getSVal(*AI);
    store = Bind(store, ValMgr.makeLoc(MRMgr.getVarRegion(*PI, frame)), ArgVal);
  }

  return state->makeWithStore(store);
}

//===----------------------------------------------------------------------===//
// Utility methods.
//===----------------------------------------------------------------------===//

void RegionStoreManager::print(Store store, llvm::raw_ostream& OS,
                               const char* nl, const char *sep) {
  RegionBindings B = GetRegionBindings(store);
  OS << "Store (direct and default bindings):" << nl;

  for (RegionBindings::iterator I = B.begin(), E = B.end(); I != E; ++I)
    OS << ' ' << I.getKey() << " : " << I.getData() << nl;
}
