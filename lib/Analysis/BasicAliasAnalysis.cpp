//===- BasicAliasAnalysis.cpp - Local Alias Analysis Impl -----------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines the default implementation of the Alias Analysis interface
// that simply implements a few identities (two different globals cannot alias,
// etc), but otherwise does no analysis.
//
//===----------------------------------------------------------------------===//

#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Analysis/Passes.h"
#include "llvm/Constants.h"
#include "llvm/DerivedTypes.h"
#include "llvm/Function.h"
#include "llvm/GlobalVariable.h"
#include "llvm/Instructions.h"
#include "llvm/IntrinsicInst.h"
#include "llvm/Operator.h"
#include "llvm/Pass.h"
#include "llvm/Analysis/CaptureTracking.h"
#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/Target/TargetData.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Support/ErrorHandling.h"
#include <algorithm>
using namespace llvm;

//===----------------------------------------------------------------------===//
// Useful predicates
//===----------------------------------------------------------------------===//

/// isKnownNonNull - Return true if we know that the specified value is never
/// null.
static bool isKnownNonNull(const Value *V) {
  // Alloca never returns null, malloc might.
  if (isa<AllocaInst>(V)) return true;
  
  // A byval argument is never null.
  if (const Argument *A = dyn_cast<Argument>(V))
    return A->hasByValAttr();

  // Global values are not null unless extern weak.
  if (const GlobalValue *GV = dyn_cast<GlobalValue>(V))
    return !GV->hasExternalWeakLinkage();
  return false;
}

/// isNonEscapingLocalObject - Return true if the pointer is to a function-local
/// object that never escapes from the function.
static bool isNonEscapingLocalObject(const Value *V) {
  // If this is a local allocation, check to see if it escapes.
  if (isa<AllocaInst>(V) || isNoAliasCall(V))
    // Set StoreCaptures to True so that we can assume in our callers that the
    // pointer is not the result of a load instruction. Currently
    // PointerMayBeCaptured doesn't have any special analysis for the
    // StoreCaptures=false case; if it did, our callers could be refined to be
    // more precise.
    return !PointerMayBeCaptured(V, false, /*StoreCaptures=*/true);

  // If this is an argument that corresponds to a byval or noalias argument,
  // then it has not escaped before entering the function.  Check if it escapes
  // inside the function.
  if (const Argument *A = dyn_cast<Argument>(V))
    if (A->hasByValAttr() || A->hasNoAliasAttr()) {
      // Don't bother analyzing arguments already known not to escape.
      if (A->hasNoCaptureAttr())
        return true;
      return !PointerMayBeCaptured(V, false, /*StoreCaptures=*/true);
    }
  return false;
}


/// isObjectSmallerThan - Return true if we can prove that the object specified
/// by V is smaller than Size.
static bool isObjectSmallerThan(const Value *V, unsigned Size,
                                const TargetData &TD) {
  const Type *AccessTy;
  if (const GlobalVariable *GV = dyn_cast<GlobalVariable>(V)) {
    AccessTy = GV->getType()->getElementType();
  } else if (const AllocaInst *AI = dyn_cast<AllocaInst>(V)) {
    if (!AI->isArrayAllocation())
      AccessTy = AI->getType()->getElementType();
    else
      return false;
  } else if (const CallInst* CI = extractMallocCall(V)) {
    if (!isArrayMalloc(V, &TD))
      // The size is the argument to the malloc call.
      if (const ConstantInt* C = dyn_cast<ConstantInt>(CI->getOperand(1)))
        return (C->getZExtValue() < Size);
    return false;
  } else if (const Argument *A = dyn_cast<Argument>(V)) {
    if (A->hasByValAttr())
      AccessTy = cast<PointerType>(A->getType())->getElementType();
    else
      return false;
  } else {
    return false;
  }
  
  if (AccessTy->isSized())
    return TD.getTypeAllocSize(AccessTy) < Size;
  return false;
}

//===----------------------------------------------------------------------===//
// NoAA Pass
//===----------------------------------------------------------------------===//

namespace {
  /// NoAA - This class implements the -no-aa pass, which always returns "I
  /// don't know" for alias queries.  NoAA is unlike other alias analysis
  /// implementations, in that it does not chain to a previous analysis.  As
  /// such it doesn't follow many of the rules that other alias analyses must.
  ///
  struct NoAA : public ImmutablePass, public AliasAnalysis {
    static char ID; // Class identification, replacement for typeinfo
    NoAA() : ImmutablePass(&ID) {}
    explicit NoAA(void *PID) : ImmutablePass(PID) { }

    virtual void getAnalysisUsage(AnalysisUsage &AU) const {
    }

    virtual void initializePass() {
      TD = getAnalysisIfAvailable<TargetData>();
    }

    virtual AliasResult alias(const Value *V1, unsigned V1Size,
                              const Value *V2, unsigned V2Size) {
      return MayAlias;
    }

    virtual void getArgumentAccesses(Function *F, CallSite CS,
                                     std::vector<PointerAccessInfo> &Info) {
      llvm_unreachable("This method may not be called on this function!");
    }

    virtual bool pointsToConstantMemory(const Value *P) { return false; }
    virtual ModRefResult getModRefInfo(CallSite CS, Value *P, unsigned Size) {
      return ModRef;
    }
    virtual ModRefResult getModRefInfo(CallSite CS1, CallSite CS2) {
      return ModRef;
    }

    virtual void deleteValue(Value *V) {}
    virtual void copyValue(Value *From, Value *To) {}
    
    /// getAdjustedAnalysisPointer - This method is used when a pass implements
    /// an analysis interface through multiple inheritance.  If needed, it should
    /// override this to adjust the this pointer as needed for the specified pass
    /// info.
    virtual void *getAdjustedAnalysisPointer(const PassInfo *PI) {
      if (PI->isPassID(&AliasAnalysis::ID))
        return (AliasAnalysis*)this;
      return this;
    }
  };
}  // End of anonymous namespace

// Register this pass...
char NoAA::ID = 0;
static RegisterPass<NoAA>
U("no-aa", "No Alias Analysis (always returns 'may' alias)", true, true);

// Declare that we implement the AliasAnalysis interface
static RegisterAnalysisGroup<AliasAnalysis> V(U);

ImmutablePass *llvm::createNoAAPass() { return new NoAA(); }

//===----------------------------------------------------------------------===//
// BasicAA Pass
//===----------------------------------------------------------------------===//

namespace {
  /// BasicAliasAnalysis - This is the default alias analysis implementation.
  /// Because it doesn't chain to a previous alias analysis (like -no-aa), it
  /// derives from the NoAA class.
  struct BasicAliasAnalysis : public NoAA {
    static char ID; // Class identification, replacement for typeinfo
    BasicAliasAnalysis() : NoAA(&ID) {}
    AliasResult alias(const Value *V1, unsigned V1Size,
                      const Value *V2, unsigned V2Size) {
      assert(VisitedPHIs.empty() && "VisitedPHIs must be cleared after use!");
      AliasResult Alias = aliasCheck(V1, V1Size, V2, V2Size);
      VisitedPHIs.clear();
      return Alias;
    }

    ModRefResult getModRefInfo(CallSite CS, Value *P, unsigned Size);
    ModRefResult getModRefInfo(CallSite CS1, CallSite CS2);

    /// pointsToConstantMemory - Chase pointers until we find a (constant
    /// global) or not.
    bool pointsToConstantMemory(const Value *P);

    /// getAdjustedAnalysisPointer - This method is used when a pass implements
    /// an analysis interface through multiple inheritance.  If needed, it should
    /// override this to adjust the this pointer as needed for the specified pass
    /// info.
    virtual void *getAdjustedAnalysisPointer(const PassInfo *PI) {
      if (PI->isPassID(&AliasAnalysis::ID))
        return (AliasAnalysis*)this;
      return this;
    }
    
  private:
    // VisitedPHIs - Track PHI nodes visited by a aliasCheck() call.
    SmallPtrSet<const Value*, 16> VisitedPHIs;

    // aliasGEP - Provide a bunch of ad-hoc rules to disambiguate a GEP
    // instruction against another.
    AliasResult aliasGEP(const GEPOperator *V1, unsigned V1Size,
                         const Value *V2, unsigned V2Size,
                         const Value *UnderlyingV1, const Value *UnderlyingV2);

    // aliasPHI - Provide a bunch of ad-hoc rules to disambiguate a PHI
    // instruction against another.
    AliasResult aliasPHI(const PHINode *PN, unsigned PNSize,
                         const Value *V2, unsigned V2Size);

    /// aliasSelect - Disambiguate a Select instruction against another value.
    AliasResult aliasSelect(const SelectInst *SI, unsigned SISize,
                            const Value *V2, unsigned V2Size);

    AliasResult aliasCheck(const Value *V1, unsigned V1Size,
                           const Value *V2, unsigned V2Size);
  };
}  // End of anonymous namespace

// Register this pass...
char BasicAliasAnalysis::ID = 0;
static RegisterPass<BasicAliasAnalysis>
X("basicaa", "Basic Alias Analysis (default AA impl)", false, true);

// Declare that we implement the AliasAnalysis interface
static RegisterAnalysisGroup<AliasAnalysis, true> Y(X);

ImmutablePass *llvm::createBasicAliasAnalysisPass() {
  return new BasicAliasAnalysis();
}


/// pointsToConstantMemory - Chase pointers until we find a (constant
/// global) or not.
bool BasicAliasAnalysis::pointsToConstantMemory(const Value *P) {
  if (const GlobalVariable *GV = 
        dyn_cast<GlobalVariable>(P->getUnderlyingObject()))
    // Note: this doesn't require GV to be "ODR" because it isn't legal for a
    // global to be marked constant in some modules and non-constant in others.
    // GV may even be a declaration, not a definition.
    return GV->isConstant();
  return false;
}


/// getModRefInfo - Check to see if the specified callsite can clobber the
/// specified memory object.  Since we only look at local properties of this
/// function, we really can't say much about this query.  We do, however, use
/// simple "address taken" analysis on local objects.
AliasAnalysis::ModRefResult
BasicAliasAnalysis::getModRefInfo(CallSite CS, Value *P, unsigned Size) {
  const Value *Object = P->getUnderlyingObject();
  
  // If this is a tail call and P points to a stack location, we know that
  // the tail call cannot access or modify the local stack.
  // We cannot exclude byval arguments here; these belong to the caller of
  // the current function not to the current function, and a tail callee
  // may reference them.
  if (isa<AllocaInst>(Object))
    if (CallInst *CI = dyn_cast<CallInst>(CS.getInstruction()))
      if (CI->isTailCall())
        return NoModRef;
  
  // If the pointer is to a locally allocated object that does not escape,
  // then the call can not mod/ref the pointer unless the call takes the pointer
  // as an argument, and itself doesn't capture it.
  if (!isa<Constant>(Object) && CS.getInstruction() != Object &&
      isNonEscapingLocalObject(Object)) {
    bool PassedAsArg = false;
    unsigned ArgNo = 0;
    for (CallSite::arg_iterator CI = CS.arg_begin(), CE = CS.arg_end();
         CI != CE; ++CI, ++ArgNo) {
      // Only look at the no-capture pointer arguments.
      if (!isa<PointerType>((*CI)->getType()) ||
          !CS.paramHasAttr(ArgNo+1, Attribute::NoCapture))
        continue;
      
      // If  this is a no-capture pointer argument, see if we can tell that it
      // is impossible to alias the pointer we're checking.  If not, we have to
      // assume that the call could touch the pointer, even though it doesn't
      // escape.
      if (!isNoAlias(cast<Value>(CI), ~0U, P, ~0U)) {
        PassedAsArg = true;
        break;
      }
    }
    
    if (!PassedAsArg)
      return NoModRef;
  }

  // Finally, handle specific knowledge of intrinsics.
  IntrinsicInst *II = dyn_cast<IntrinsicInst>(CS.getInstruction());
  if (II == 0)
    return AliasAnalysis::getModRefInfo(CS, P, Size);

  switch (II->getIntrinsicID()) {
  default: break;
  case Intrinsic::memcpy:
  case Intrinsic::memmove: {
    unsigned Len = ~0U;
    if (ConstantInt *LenCI = dyn_cast<ConstantInt>(II->getOperand(3)))
      Len = LenCI->getZExtValue();
    Value *Dest = II->getOperand(1);
    Value *Src = II->getOperand(2);
    if (isNoAlias(Dest, Len, P, Size)) {
      if (isNoAlias(Src, Len, P, Size))
        return NoModRef;
      return Ref;
    }
    break;
  }
  case Intrinsic::memset:
    // Since memset is 'accesses arguments' only, the AliasAnalysis base class
    // will handle it for the variable length case.
    if (ConstantInt *LenCI = dyn_cast<ConstantInt>(II->getOperand(3))) {
      unsigned Len = LenCI->getZExtValue();
      Value *Dest = II->getOperand(1);
      if (isNoAlias(Dest, Len, P, Size))
        return NoModRef;
    }
    break;
  case Intrinsic::atomic_cmp_swap:
  case Intrinsic::atomic_swap:
  case Intrinsic::atomic_load_add:
  case Intrinsic::atomic_load_sub:
  case Intrinsic::atomic_load_and:
  case Intrinsic::atomic_load_nand:
  case Intrinsic::atomic_load_or:
  case Intrinsic::atomic_load_xor:
  case Intrinsic::atomic_load_max:
  case Intrinsic::atomic_load_min:
  case Intrinsic::atomic_load_umax:
  case Intrinsic::atomic_load_umin:
    if (TD) {
      Value *Op1 = II->getOperand(1);
      unsigned Op1Size = TD->getTypeStoreSize(Op1->getType());
      if (isNoAlias(Op1, Op1Size, P, Size))
        return NoModRef;
    }
    break;
  case Intrinsic::lifetime_start:
  case Intrinsic::lifetime_end:
  case Intrinsic::invariant_start: {
    unsigned PtrSize = cast<ConstantInt>(II->getOperand(1))->getZExtValue();
    if (isNoAlias(II->getOperand(2), PtrSize, P, Size))
      return NoModRef;
    break;
  }
  case Intrinsic::invariant_end: {
    unsigned PtrSize = cast<ConstantInt>(II->getOperand(2))->getZExtValue();
    if (isNoAlias(II->getOperand(3), PtrSize, P, Size))
      return NoModRef;
    break;
  }
  }

  // The AliasAnalysis base class has some smarts, lets use them.
  return AliasAnalysis::getModRefInfo(CS, P, Size);
}


AliasAnalysis::ModRefResult 
BasicAliasAnalysis::getModRefInfo(CallSite CS1, CallSite CS2) {
  // If CS1 or CS2 are readnone, they don't interact.
  ModRefBehavior CS1B = AliasAnalysis::getModRefBehavior(CS1);
  if (CS1B == DoesNotAccessMemory) return NoModRef;
  
  ModRefBehavior CS2B = AliasAnalysis::getModRefBehavior(CS2);
  if (CS2B == DoesNotAccessMemory) return NoModRef;
  
  // If they both only read from memory, just return ref.
  if (CS1B == OnlyReadsMemory && CS2B == OnlyReadsMemory)
    return Ref;
  
  // Otherwise, fall back to NoAA (mod+ref).
  return NoAA::getModRefInfo(CS1, CS2);
}

/// GetIndiceDifference - Dest and Src are the variable indices from two
/// decomposed GetElementPtr instructions GEP1 and GEP2 which have common base
/// pointers.  Subtract the GEP2 indices from GEP1 to find the symbolic
/// difference between the two pointers. 
static void GetIndiceDifference(
                      SmallVectorImpl<std::pair<const Value*, int64_t> > &Dest,
                const SmallVectorImpl<std::pair<const Value*, int64_t> > &Src) {
  if (Src.empty()) return;

  for (unsigned i = 0, e = Src.size(); i != e; ++i) {
    const Value *V = Src[i].first;
    int64_t Scale = Src[i].second;
    
    // Find V in Dest.  This is N^2, but pointer indices almost never have more
    // than a few variable indexes.
    for (unsigned j = 0, e = Dest.size(); j != e; ++j) {
      if (Dest[j].first != V) continue;
      
      // If we found it, subtract off Scale V's from the entry in Dest.  If it
      // goes to zero, remove the entry.
      if (Dest[j].second != Scale)
        Dest[j].second -= Scale;
      else
        Dest.erase(Dest.begin()+j);
      Scale = 0;
      break;
    }
    
    // If we didn't consume this entry, add it to the end of the Dest list.
    if (Scale)
      Dest.push_back(std::make_pair(V, -Scale));
  }
}

/// aliasGEP - Provide a bunch of ad-hoc rules to disambiguate a GEP instruction
/// against another pointer.  We know that V1 is a GEP, but we don't know
/// anything about V2.  UnderlyingV1 is GEP1->getUnderlyingObject(),
/// UnderlyingV2 is the same for V2.
///
AliasAnalysis::AliasResult
BasicAliasAnalysis::aliasGEP(const GEPOperator *GEP1, unsigned V1Size,
                             const Value *V2, unsigned V2Size,
                             const Value *UnderlyingV1,
                             const Value *UnderlyingV2) {
  int64_t GEP1BaseOffset;
  SmallVector<std::pair<const Value*, int64_t>, 4> GEP1VariableIndices;

  // If we have two gep instructions with must-alias'ing base pointers, figure
  // out if the indexes to the GEP tell us anything about the derived pointer.
  if (const GEPOperator *GEP2 = dyn_cast<GEPOperator>(V2)) {
    // Do the base pointers alias?
    AliasResult BaseAlias = aliasCheck(UnderlyingV1, ~0U, UnderlyingV2, ~0U);
    
    // If we get a No or May, then return it immediately, no amount of analysis
    // will improve this situation.
    if (BaseAlias != MustAlias) return BaseAlias;
    
    // Otherwise, we have a MustAlias.  Since the base pointers alias each other
    // exactly, see if the computed offset from the common pointer tells us
    // about the relation of the resulting pointer.
    const Value *GEP1BasePtr =
      DecomposeGEPExpression(GEP1, GEP1BaseOffset, GEP1VariableIndices, TD);
    
    int64_t GEP2BaseOffset;
    SmallVector<std::pair<const Value*, int64_t>, 4> GEP2VariableIndices;
    const Value *GEP2BasePtr =
      DecomposeGEPExpression(GEP2, GEP2BaseOffset, GEP2VariableIndices, TD);
    
    // If DecomposeGEPExpression isn't able to look all the way through the
    // addressing operation, we must not have TD and this is too complex for us
    // to handle without it.
    if (GEP1BasePtr != UnderlyingV1 || GEP2BasePtr != UnderlyingV2) {
      assert(TD == 0 &&
             "DecomposeGEPExpression and getUnderlyingObject disagree!");
      return MayAlias;
    }
    
    // Subtract the GEP2 pointer from the GEP1 pointer to find out their
    // symbolic difference.
    GEP1BaseOffset -= GEP2BaseOffset;
    GetIndiceDifference(GEP1VariableIndices, GEP2VariableIndices);
    
  } else {
    // Check to see if these two pointers are related by the getelementptr
    // instruction.  If one pointer is a GEP with a non-zero index of the other
    // pointer, we know they cannot alias.

    // If both accesses are unknown size, we can't do anything useful here.
    if (V1Size == ~0U && V2Size == ~0U)
      return MayAlias;

    AliasResult R = aliasCheck(UnderlyingV1, ~0U, V2, V2Size);
    if (R != MustAlias)
      // If V2 may alias GEP base pointer, conservatively returns MayAlias.
      // If V2 is known not to alias GEP base pointer, then the two values
      // cannot alias per GEP semantics: "A pointer value formed from a
      // getelementptr instruction is associated with the addresses associated
      // with the first operand of the getelementptr".
      return R;

    const Value *GEP1BasePtr =
      DecomposeGEPExpression(GEP1, GEP1BaseOffset, GEP1VariableIndices, TD);
    
    // If DecomposeGEPExpression isn't able to look all the way through the
    // addressing operation, we must not have TD and this is too complex for us
    // to handle without it.
    if (GEP1BasePtr != UnderlyingV1) {
      assert(TD == 0 &&
             "DecomposeGEPExpression and getUnderlyingObject disagree!");
      return MayAlias;
    }
  }
  
  // In the two GEP Case, if there is no difference in the offsets of the
  // computed pointers, the resultant pointers are a must alias.  This
  // hapens when we have two lexically identical GEP's (for example).
  //
  // In the other case, if we have getelementptr <ptr>, 0, 0, 0, 0, ... and V2
  // must aliases the GEP, the end result is a must alias also.
  if (GEP1BaseOffset == 0 && GEP1VariableIndices.empty())
    return MustAlias;

  // If we have a known constant offset, see if this offset is larger than the
  // access size being queried.  If so, and if no variable indices can remove
  // pieces of this constant, then we know we have a no-alias.  For example,
  //   &A[100] != &A.
  
  // In order to handle cases like &A[100][i] where i is an out of range
  // subscript, we have to ignore all constant offset pieces that are a multiple
  // of a scaled index.  Do this by removing constant offsets that are a
  // multiple of any of our variable indices.  This allows us to transform
  // things like &A[i][1] because i has a stride of (e.g.) 8 bytes but the 1
  // provides an offset of 4 bytes (assuming a <= 4 byte access).
  for (unsigned i = 0, e = GEP1VariableIndices.size();
       i != e && GEP1BaseOffset;++i)
    if (int64_t RemovedOffset = GEP1BaseOffset/GEP1VariableIndices[i].second)
      GEP1BaseOffset -= RemovedOffset*GEP1VariableIndices[i].second;
  
  // If our known offset is bigger than the access size, we know we don't have
  // an alias.
  if (GEP1BaseOffset) {
    if (GEP1BaseOffset >= (int64_t)V2Size ||
        GEP1BaseOffset <= -(int64_t)V1Size)
      return NoAlias;
  }
  
  return MayAlias;
}

/// aliasSelect - Provide a bunch of ad-hoc rules to disambiguate a Select
/// instruction against another.
AliasAnalysis::AliasResult
BasicAliasAnalysis::aliasSelect(const SelectInst *SI, unsigned SISize,
                                const Value *V2, unsigned V2Size) {
  // If the values are Selects with the same condition, we can do a more precise
  // check: just check for aliases between the values on corresponding arms.
  if (const SelectInst *SI2 = dyn_cast<SelectInst>(V2))
    if (SI->getCondition() == SI2->getCondition()) {
      AliasResult Alias =
        aliasCheck(SI->getTrueValue(), SISize,
                   SI2->getTrueValue(), V2Size);
      if (Alias == MayAlias)
        return MayAlias;
      AliasResult ThisAlias =
        aliasCheck(SI->getFalseValue(), SISize,
                   SI2->getFalseValue(), V2Size);
      if (ThisAlias != Alias)
        return MayAlias;
      return Alias;
    }

  // If both arms of the Select node NoAlias or MustAlias V2, then returns
  // NoAlias / MustAlias. Otherwise, returns MayAlias.
  AliasResult Alias =
    aliasCheck(SI->getTrueValue(), SISize, V2, V2Size);
  if (Alias == MayAlias)
    return MayAlias;
  AliasResult ThisAlias =
    aliasCheck(SI->getFalseValue(), SISize, V2, V2Size);
  if (ThisAlias != Alias)
    return MayAlias;
  return Alias;
}

// aliasPHI - Provide a bunch of ad-hoc rules to disambiguate a PHI instruction
// against another.
AliasAnalysis::AliasResult
BasicAliasAnalysis::aliasPHI(const PHINode *PN, unsigned PNSize,
                             const Value *V2, unsigned V2Size) {
  // The PHI node has already been visited, avoid recursion any further.
  if (!VisitedPHIs.insert(PN))
    return MayAlias;

  // If the values are PHIs in the same block, we can do a more precise
  // as well as efficient check: just check for aliases between the values
  // on corresponding edges.
  if (const PHINode *PN2 = dyn_cast<PHINode>(V2))
    if (PN2->getParent() == PN->getParent()) {
      AliasResult Alias =
        aliasCheck(PN->getIncomingValue(0), PNSize,
                   PN2->getIncomingValueForBlock(PN->getIncomingBlock(0)),
                   V2Size);
      if (Alias == MayAlias)
        return MayAlias;
      for (unsigned i = 1, e = PN->getNumIncomingValues(); i != e; ++i) {
        AliasResult ThisAlias =
          aliasCheck(PN->getIncomingValue(i), PNSize,
                     PN2->getIncomingValueForBlock(PN->getIncomingBlock(i)),
                     V2Size);
        if (ThisAlias != Alias)
          return MayAlias;
      }
      return Alias;
    }

  SmallPtrSet<Value*, 4> UniqueSrc;
  SmallVector<Value*, 4> V1Srcs;
  for (unsigned i = 0, e = PN->getNumIncomingValues(); i != e; ++i) {
    Value *PV1 = PN->getIncomingValue(i);
    if (isa<PHINode>(PV1))
      // If any of the source itself is a PHI, return MayAlias conservatively
      // to avoid compile time explosion. The worst possible case is if both
      // sides are PHI nodes. In which case, this is O(m x n) time where 'm'
      // and 'n' are the number of PHI sources.
      return MayAlias;
    if (UniqueSrc.insert(PV1))
      V1Srcs.push_back(PV1);
  }

  AliasResult Alias = aliasCheck(V2, V2Size, V1Srcs[0], PNSize);
  // Early exit if the check of the first PHI source against V2 is MayAlias.
  // Other results are not possible.
  if (Alias == MayAlias)
    return MayAlias;

  // If all sources of the PHI node NoAlias or MustAlias V2, then returns
  // NoAlias / MustAlias. Otherwise, returns MayAlias.
  for (unsigned i = 1, e = V1Srcs.size(); i != e; ++i) {
    Value *V = V1Srcs[i];

    // If V2 is a PHI, the recursive case will have been caught in the
    // above aliasCheck call, so these subsequent calls to aliasCheck
    // don't need to assume that V2 is being visited recursively.
    VisitedPHIs.erase(V2);

    AliasResult ThisAlias = aliasCheck(V2, V2Size, V, PNSize);
    if (ThisAlias != Alias || ThisAlias == MayAlias)
      return MayAlias;
  }

  return Alias;
}

// aliasCheck - Provide a bunch of ad-hoc rules to disambiguate in common cases,
// such as array references.
//
AliasAnalysis::AliasResult
BasicAliasAnalysis::aliasCheck(const Value *V1, unsigned V1Size,
                               const Value *V2, unsigned V2Size) {
  // Strip off any casts if they exist.
  V1 = V1->stripPointerCasts();
  V2 = V2->stripPointerCasts();

  // Are we checking for alias of the same value?
  if (V1 == V2) return MustAlias;

  if (!isa<PointerType>(V1->getType()) || !isa<PointerType>(V2->getType()))
    return NoAlias;  // Scalars cannot alias each other

  // Figure out what objects these things are pointing to if we can.
  const Value *O1 = V1->getUnderlyingObject();
  const Value *O2 = V2->getUnderlyingObject();

  // Null values in the default address space don't point to any object, so they
  // don't alias any other pointer.
  if (const ConstantPointerNull *CPN = dyn_cast<ConstantPointerNull>(O1))
    if (CPN->getType()->getAddressSpace() == 0)
      return NoAlias;
  if (const ConstantPointerNull *CPN = dyn_cast<ConstantPointerNull>(O2))
    if (CPN->getType()->getAddressSpace() == 0)
      return NoAlias;

  if (O1 != O2) {
    // If V1/V2 point to two different objects we know that we have no alias.
    if (isIdentifiedObject(O1) && isIdentifiedObject(O2))
      return NoAlias;

    // Constant pointers can't alias with non-const isIdentifiedObject objects.
    if ((isa<Constant>(O1) && isIdentifiedObject(O2) && !isa<Constant>(O2)) ||
        (isa<Constant>(O2) && isIdentifiedObject(O1) && !isa<Constant>(O1)))
      return NoAlias;

    // Arguments can't alias with local allocations or noalias calls.
    if ((isa<Argument>(O1) && (isa<AllocaInst>(O2) || isNoAliasCall(O2))) ||
        (isa<Argument>(O2) && (isa<AllocaInst>(O1) || isNoAliasCall(O1))))
      return NoAlias;

    // Most objects can't alias null.
    if ((isa<ConstantPointerNull>(V2) && isKnownNonNull(O1)) ||
        (isa<ConstantPointerNull>(V1) && isKnownNonNull(O2)))
      return NoAlias;
  }
  
  // If the size of one access is larger than the entire object on the other
  // side, then we know such behavior is undefined and can assume no alias.
  if (TD)
    if ((V1Size != ~0U && isObjectSmallerThan(O2, V1Size, *TD)) ||
        (V2Size != ~0U && isObjectSmallerThan(O1, V2Size, *TD)))
      return NoAlias;
  
  // If one pointer is the result of a call/invoke or load and the other is a
  // non-escaping local object, then we know the object couldn't escape to a
  // point where the call could return it. The load case works because
  // isNonEscapingLocalObject considers all stores to be escapes (it
  // passes true for the StoreCaptures argument to PointerMayBeCaptured).
  if (O1 != O2) {
    if ((isa<CallInst>(O1) || isa<InvokeInst>(O1) || isa<LoadInst>(O1) ||
         isa<Argument>(O1)) &&
        isNonEscapingLocalObject(O2))
      return NoAlias;
    if ((isa<CallInst>(O2) || isa<InvokeInst>(O2) || isa<LoadInst>(O2) ||
         isa<Argument>(O2)) &&
        isNonEscapingLocalObject(O1))
      return NoAlias;
  }

  // FIXME: This isn't aggressively handling alias(GEP, PHI) for example: if the
  // GEP can't simplify, we don't even look at the PHI cases.
  if (!isa<GEPOperator>(V1) && isa<GEPOperator>(V2)) {
    std::swap(V1, V2);
    std::swap(V1Size, V2Size);
    std::swap(O1, O2);
  }
  if (const GEPOperator *GV1 = dyn_cast<GEPOperator>(V1))
    return aliasGEP(GV1, V1Size, V2, V2Size, O1, O2);

  if (isa<PHINode>(V2) && !isa<PHINode>(V1)) {
    std::swap(V1, V2);
    std::swap(V1Size, V2Size);
  }
  if (const PHINode *PN = dyn_cast<PHINode>(V1))
    return aliasPHI(PN, V1Size, V2, V2Size);

  if (isa<SelectInst>(V2) && !isa<SelectInst>(V1)) {
    std::swap(V1, V2);
    std::swap(V1Size, V2Size);
  }
  if (const SelectInst *S1 = dyn_cast<SelectInst>(V1))
    return aliasSelect(S1, V1Size, V2, V2Size);

  return MayAlias;
}

// Make sure that anything that uses AliasAnalysis pulls in this file.
DEFINING_FILE_FOR(BasicAliasAnalysis)
