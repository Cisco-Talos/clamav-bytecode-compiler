//===- MemoryDependenceAnalysis.cpp - Mem Deps Implementation  --*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements an analysis that determines, for a given memory
// operation, what preceding memory operations it depends on.  It builds on 
// alias analysis information, and tries to provide a lazy, caching interface to
// a common kind of alias information query.
//
//===----------------------------------------------------------------------===//

#define DEBUG_TYPE "memdep"
#include "llvm/Analysis/MemoryDependenceAnalysis.h"
#include "llvm/Instructions.h"
#include "llvm/IntrinsicInst.h"
#include "llvm/Function.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Analysis/Dominators.h"
#include "llvm/Analysis/InstructionSimplify.h"
#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/Analysis/PHITransAddr.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/Support/PredIteratorCache.h"
#include "llvm/Support/Debug.h"
using namespace llvm;

STATISTIC(NumCacheNonLocal, "Number of fully cached non-local responses");
STATISTIC(NumCacheDirtyNonLocal, "Number of dirty cached non-local responses");
STATISTIC(NumUncacheNonLocal, "Number of uncached non-local responses");

STATISTIC(NumCacheNonLocalPtr,
          "Number of fully cached non-local ptr responses");
STATISTIC(NumCacheDirtyNonLocalPtr,
          "Number of cached, but dirty, non-local ptr responses");
STATISTIC(NumUncacheNonLocalPtr,
          "Number of uncached non-local ptr responses");
STATISTIC(NumCacheCompleteNonLocalPtr,
          "Number of block queries that were completely cached");

char MemoryDependenceAnalysis::ID = 0;
  
// Register this pass...
static RegisterPass<MemoryDependenceAnalysis> X("memdep",
                                     "Memory Dependence Analysis", false, true);

MemoryDependenceAnalysis::MemoryDependenceAnalysis()
: FunctionPass(&ID), PredCache(0) {
}
MemoryDependenceAnalysis::~MemoryDependenceAnalysis() {
}

/// Clean up memory in between runs
void MemoryDependenceAnalysis::releaseMemory() {
  LocalDeps.clear();
  NonLocalDeps.clear();
  NonLocalPointerDeps.clear();
  ReverseLocalDeps.clear();
  ReverseNonLocalDeps.clear();
  ReverseNonLocalPtrDeps.clear();
  PredCache->clear();
}



/// getAnalysisUsage - Does not modify anything.  It uses Alias Analysis.
///
void MemoryDependenceAnalysis::getAnalysisUsage(AnalysisUsage &AU) const {
  AU.setPreservesAll();
  AU.addRequiredTransitive<AliasAnalysis>();
}

bool MemoryDependenceAnalysis::runOnFunction(Function &) {
  AA = &getAnalysis<AliasAnalysis>();
  if (PredCache == 0)
    PredCache.reset(new PredIteratorCache());
  return false;
}

/// RemoveFromReverseMap - This is a helper function that removes Val from
/// 'Inst's set in ReverseMap.  If the set becomes empty, remove Inst's entry.
template <typename KeyTy>
static void RemoveFromReverseMap(DenseMap<Instruction*, 
                                 SmallPtrSet<KeyTy, 4> > &ReverseMap,
                                 Instruction *Inst, KeyTy Val) {
  typename DenseMap<Instruction*, SmallPtrSet<KeyTy, 4> >::iterator
  InstIt = ReverseMap.find(Inst);
  assert(InstIt != ReverseMap.end() && "Reverse map out of sync?");
  bool Found = InstIt->second.erase(Val);
  assert(Found && "Invalid reverse map!"); Found=Found;
  if (InstIt->second.empty())
    ReverseMap.erase(InstIt);
}


/// getCallSiteDependencyFrom - Private helper for finding the local
/// dependencies of a call site.
MemDepResult MemoryDependenceAnalysis::
getCallSiteDependencyFrom(CallSite CS, bool isReadOnlyCall,
                          BasicBlock::iterator ScanIt, BasicBlock *BB) {
  // Walk backwards through the block, looking for dependencies
  while (ScanIt != BB->begin()) {
    Instruction *Inst = --ScanIt;
    
    // If this inst is a memory op, get the pointer it accessed
    Value *Pointer = 0;
    uint64_t PointerSize = 0;
    if (StoreInst *S = dyn_cast<StoreInst>(Inst)) {
      Pointer = S->getPointerOperand();
      PointerSize = AA->getTypeStoreSize(S->getOperand(0)->getType());
    } else if (VAArgInst *V = dyn_cast<VAArgInst>(Inst)) {
      Pointer = V->getOperand(0);
      PointerSize = AA->getTypeStoreSize(V->getType());
    } else if (isFreeCall(Inst)) {
      Pointer = Inst->getOperand(1);
      // calls to free() erase the entire structure
      PointerSize = ~0ULL;
    } else if (isa<CallInst>(Inst) || isa<InvokeInst>(Inst)) {
      // Debug intrinsics don't cause dependences.
      if (isa<DbgInfoIntrinsic>(Inst)) continue;
      CallSite InstCS = CallSite::get(Inst);
      // If these two calls do not interfere, look past it.
      switch (AA->getModRefInfo(CS, InstCS)) {
      case AliasAnalysis::NoModRef:
        // If the two calls don't interact (e.g. InstCS is readnone) keep
        // scanning.
        continue;
      case AliasAnalysis::Ref:
        // If the two calls read the same memory locations and CS is a readonly
        // function, then we have two cases: 1) the calls may not interfere with
        // each other at all.  2) the calls may produce the same value.  In case
        // #1 we want to ignore the values, in case #2, we want to return Inst
        // as a Def dependence.  This allows us to CSE in cases like:
        //   X = strlen(P);
        //    memchr(...);
        //   Y = strlen(P);  // Y = X
        if (isReadOnlyCall) {
          if (CS.getCalledFunction() != 0 &&
              CS.getCalledFunction() == InstCS.getCalledFunction())
            return MemDepResult::getDef(Inst);
          // Ignore unrelated read/read call dependences.
          continue;
        }
        // FALL THROUGH
      default:
        return MemDepResult::getClobber(Inst);
      }
    } else {
      // Non-memory instruction.
      continue;
    }
    
    if (AA->getModRefInfo(CS, Pointer, PointerSize) != AliasAnalysis::NoModRef)
      return MemDepResult::getClobber(Inst);
  }
  
  // No dependence found.  If this is the entry block of the function, it is a
  // clobber, otherwise it is non-local.
  if (BB != &BB->getParent()->getEntryBlock())
    return MemDepResult::getNonLocal();
  return MemDepResult::getClobber(ScanIt);
}

/// getPointerDependencyFrom - Return the instruction on which a memory
/// location depends.  If isLoad is true, this routine ignore may-aliases with
/// read-only operations.
MemDepResult MemoryDependenceAnalysis::
getPointerDependencyFrom(Value *MemPtr, uint64_t MemSize, bool isLoad, 
                         BasicBlock::iterator ScanIt, BasicBlock *BB) {

  Value *InvariantTag = 0;

  // Walk backwards through the basic block, looking for dependencies.
  while (ScanIt != BB->begin()) {
    Instruction *Inst = --ScanIt;

    // If we're in an invariant region, no dependencies can be found before
    // we pass an invariant-begin marker.
    if (InvariantTag == Inst) {
      InvariantTag = 0;
      continue;
    }
    
    if (IntrinsicInst *II = dyn_cast<IntrinsicInst>(Inst)) {
      // Debug intrinsics don't cause dependences.
      if (isa<DbgInfoIntrinsic>(Inst)) continue;
      
      // If we pass an invariant-end marker, then we've just entered an
      // invariant region and can start ignoring dependencies.
      if (II->getIntrinsicID() == Intrinsic::invariant_end) {
        // FIXME: This only considers queries directly on the invariant-tagged
        // pointer, not on query pointers that are indexed off of them.  It'd
        // be nice to handle that at some point.
        AliasAnalysis::AliasResult R = 
          AA->alias(II->getOperand(3), ~0U, MemPtr, ~0U);
        if (R == AliasAnalysis::MustAlias) {
          InvariantTag = II->getOperand(1);
          continue;
        }
      
      // If we reach a lifetime begin or end marker, then the query ends here
      // because the value is undefined.
      } else if (II->getIntrinsicID() == Intrinsic::lifetime_start) {
        // FIXME: This only considers queries directly on the invariant-tagged
        // pointer, not on query pointers that are indexed off of them.  It'd
        // be nice to handle that at some point.
        AliasAnalysis::AliasResult R =
          AA->alias(II->getOperand(2), ~0U, MemPtr, ~0U);
        if (R == AliasAnalysis::MustAlias)
          return MemDepResult::getDef(II);
      }
    }

    // If we're querying on a load and we're in an invariant region, we're done
    // at this point. Nothing a load depends on can live in an invariant region.
    if (isLoad && InvariantTag) continue;

    // Values depend on loads if the pointers are must aliased.  This means that
    // a load depends on another must aliased load from the same value.
    if (LoadInst *LI = dyn_cast<LoadInst>(Inst)) {
      Value *Pointer = LI->getPointerOperand();
      uint64_t PointerSize = AA->getTypeStoreSize(LI->getType());
      
      // If we found a pointer, check if it could be the same as our pointer.
      AliasAnalysis::AliasResult R =
        AA->alias(Pointer, PointerSize, MemPtr, MemSize);
      if (R == AliasAnalysis::NoAlias)
        continue;
      
      // May-alias loads don't depend on each other without a dependence.
      if (isLoad && R == AliasAnalysis::MayAlias)
        continue;
      // Stores depend on may and must aliased loads, loads depend on must-alias
      // loads.
      return MemDepResult::getDef(Inst);
    }
    
    if (StoreInst *SI = dyn_cast<StoreInst>(Inst)) {
      // There can't be stores to the value we care about inside an 
      // invariant region.
      if (InvariantTag) continue;
      
      // If alias analysis can tell that this store is guaranteed to not modify
      // the query pointer, ignore it.  Use getModRefInfo to handle cases where
      // the query pointer points to constant memory etc.
      if (AA->getModRefInfo(SI, MemPtr, MemSize) == AliasAnalysis::NoModRef)
        continue;

      // Ok, this store might clobber the query pointer.  Check to see if it is
      // a must alias: in this case, we want to return this as a def.
      Value *Pointer = SI->getPointerOperand();
      uint64_t PointerSize = AA->getTypeStoreSize(SI->getOperand(0)->getType());
      
      // If we found a pointer, check if it could be the same as our pointer.
      AliasAnalysis::AliasResult R =
        AA->alias(Pointer, PointerSize, MemPtr, MemSize);
      
      if (R == AliasAnalysis::NoAlias)
        continue;
      if (R == AliasAnalysis::MayAlias)
        return MemDepResult::getClobber(Inst);
      return MemDepResult::getDef(Inst);
    }

    // If this is an allocation, and if we know that the accessed pointer is to
    // the allocation, return Def.  This means that there is no dependence and
    // the access can be optimized based on that.  For example, a load could
    // turn into undef.
    // Note: Only determine this to be a malloc if Inst is the malloc call, not
    // a subsequent bitcast of the malloc call result.  There can be stores to
    // the malloced memory between the malloc call and its bitcast uses, and we
    // need to continue scanning until the malloc call.
    if (isa<AllocaInst>(Inst) ||
        (isa<CallInst>(Inst) && extractMallocCall(Inst))) {
      Value *AccessPtr = MemPtr->getUnderlyingObject();
      
      if (AccessPtr == Inst ||
          AA->alias(Inst, 1, AccessPtr, 1) == AliasAnalysis::MustAlias)
        return MemDepResult::getDef(Inst);
      continue;
    }

    // See if this instruction (e.g. a call or vaarg) mod/ref's the pointer.
    switch (AA->getModRefInfo(Inst, MemPtr, MemSize)) {
    case AliasAnalysis::NoModRef:
      // If the call has no effect on the queried pointer, just ignore it.
      continue;
    case AliasAnalysis::Mod:
      // If we're in an invariant region, we can ignore calls that ONLY
      // modify the pointer.
      if (InvariantTag) continue;
      return MemDepResult::getClobber(Inst);
    case AliasAnalysis::Ref:
      // If the call is known to never store to the pointer, and if this is a
      // load query, we can safely ignore it (scan past it).
      if (isLoad)
        continue;
    default:
      // Otherwise, there is a potential dependence.  Return a clobber.
      return MemDepResult::getClobber(Inst);
    }
  }
  
  // No dependence found.  If this is the entry block of the function, it is a
  // clobber, otherwise it is non-local.
  if (BB != &BB->getParent()->getEntryBlock())
    return MemDepResult::getNonLocal();
  return MemDepResult::getClobber(ScanIt);
}

/// getDependency - Return the instruction on which a memory operation
/// depends.
MemDepResult MemoryDependenceAnalysis::getDependency(Instruction *QueryInst) {
  Instruction *ScanPos = QueryInst;
  
  // Check for a cached result
  MemDepResult &LocalCache = LocalDeps[QueryInst];
  
  // If the cached entry is non-dirty, just return it.  Note that this depends
  // on MemDepResult's default constructing to 'dirty'.
  if (!LocalCache.isDirty())
    return LocalCache;
    
  // Otherwise, if we have a dirty entry, we know we can start the scan at that
  // instruction, which may save us some work.
  if (Instruction *Inst = LocalCache.getInst()) {
    ScanPos = Inst;
   
    RemoveFromReverseMap(ReverseLocalDeps, Inst, QueryInst);
  }
  
  BasicBlock *QueryParent = QueryInst->getParent();
  
  Value *MemPtr = 0;
  uint64_t MemSize = 0;
  
  // Do the scan.
  if (BasicBlock::iterator(QueryInst) == QueryParent->begin()) {
    // No dependence found.  If this is the entry block of the function, it is a
    // clobber, otherwise it is non-local.
    if (QueryParent != &QueryParent->getParent()->getEntryBlock())
      LocalCache = MemDepResult::getNonLocal();
    else
      LocalCache = MemDepResult::getClobber(QueryInst);
  } else if (StoreInst *SI = dyn_cast<StoreInst>(QueryInst)) {
    // If this is a volatile store, don't mess around with it.  Just return the
    // previous instruction as a clobber.
    if (SI->isVolatile())
      LocalCache = MemDepResult::getClobber(--BasicBlock::iterator(ScanPos));
    else {
      MemPtr = SI->getPointerOperand();
      MemSize = AA->getTypeStoreSize(SI->getOperand(0)->getType());
    }
  } else if (LoadInst *LI = dyn_cast<LoadInst>(QueryInst)) {
    // If this is a volatile load, don't mess around with it.  Just return the
    // previous instruction as a clobber.
    if (LI->isVolatile())
      LocalCache = MemDepResult::getClobber(--BasicBlock::iterator(ScanPos));
    else {
      MemPtr = LI->getPointerOperand();
      MemSize = AA->getTypeStoreSize(LI->getType());
    }
  } else if (isFreeCall(QueryInst)) {
    MemPtr = QueryInst->getOperand(1);
    // calls to free() erase the entire structure, not just a field.
    MemSize = ~0UL;
  } else if (isa<CallInst>(QueryInst) || isa<InvokeInst>(QueryInst)) {
    int IntrinsicID = 0;  // Intrinsic IDs start at 1.
    if (IntrinsicInst *II = dyn_cast<IntrinsicInst>(QueryInst))
      IntrinsicID = II->getIntrinsicID();

    switch (IntrinsicID) {
    case Intrinsic::lifetime_start:
    case Intrinsic::lifetime_end:
    case Intrinsic::invariant_start:
      MemPtr = QueryInst->getOperand(2);
      MemSize = cast<ConstantInt>(QueryInst->getOperand(1))->getZExtValue();
      break;
    case Intrinsic::invariant_end:
      MemPtr = QueryInst->getOperand(3);
      MemSize = cast<ConstantInt>(QueryInst->getOperand(2))->getZExtValue();
      break;
    default:
      CallSite QueryCS = CallSite::get(QueryInst);
      bool isReadOnly = AA->onlyReadsMemory(QueryCS);
      LocalCache = getCallSiteDependencyFrom(QueryCS, isReadOnly, ScanPos,
                                             QueryParent);
      break;
    }
  } else {
    // Non-memory instruction.
    LocalCache = MemDepResult::getClobber(--BasicBlock::iterator(ScanPos));
  }
  
  // If we need to do a pointer scan, make it happen.
  if (MemPtr) {
    bool isLoad = !QueryInst->mayWriteToMemory();
    if (IntrinsicInst *II = dyn_cast<MemoryUseIntrinsic>(QueryInst)) {
      isLoad |= II->getIntrinsicID() == Intrinsic::lifetime_end;
    }
    LocalCache = getPointerDependencyFrom(MemPtr, MemSize, isLoad, ScanPos,
                                          QueryParent);
  }
  
  // Remember the result!
  if (Instruction *I = LocalCache.getInst())
    ReverseLocalDeps[I].insert(QueryInst);
  
  return LocalCache;
}

#ifndef NDEBUG
/// AssertSorted - This method is used when -debug is specified to verify that
/// cache arrays are properly kept sorted.
static void AssertSorted(MemoryDependenceAnalysis::NonLocalDepInfo &Cache,
                         int Count = -1) {
  if (Count == -1) Count = Cache.size();
  if (Count == 0) return;

  for (unsigned i = 1; i != unsigned(Count); ++i)
    assert(!(Cache[i] < Cache[i-1]) && "Cache isn't sorted!");
}
#endif

/// getNonLocalCallDependency - Perform a full dependency query for the
/// specified call, returning the set of blocks that the value is
/// potentially live across.  The returned set of results will include a
/// "NonLocal" result for all blocks where the value is live across.
///
/// This method assumes the instruction returns a "NonLocal" dependency
/// within its own block.
///
/// This returns a reference to an internal data structure that may be
/// invalidated on the next non-local query or when an instruction is
/// removed.  Clients must copy this data if they want it around longer than
/// that.
const MemoryDependenceAnalysis::NonLocalDepInfo &
MemoryDependenceAnalysis::getNonLocalCallDependency(CallSite QueryCS) {
  assert(getDependency(QueryCS.getInstruction()).isNonLocal() &&
 "getNonLocalCallDependency should only be used on calls with non-local deps!");
  PerInstNLInfo &CacheP = NonLocalDeps[QueryCS.getInstruction()];
  NonLocalDepInfo &Cache = CacheP.first;

  /// DirtyBlocks - This is the set of blocks that need to be recomputed.  In
  /// the cached case, this can happen due to instructions being deleted etc. In
  /// the uncached case, this starts out as the set of predecessors we care
  /// about.
  SmallVector<BasicBlock*, 32> DirtyBlocks;
  
  if (!Cache.empty()) {
    // Okay, we have a cache entry.  If we know it is not dirty, just return it
    // with no computation.
    if (!CacheP.second) {
      NumCacheNonLocal++;
      return Cache;
    }
    
    // If we already have a partially computed set of results, scan them to
    // determine what is dirty, seeding our initial DirtyBlocks worklist.
    for (NonLocalDepInfo::iterator I = Cache.begin(), E = Cache.end();
       I != E; ++I)
      if (I->getResult().isDirty())
        DirtyBlocks.push_back(I->getBB());
    
    // Sort the cache so that we can do fast binary search lookups below.
    std::sort(Cache.begin(), Cache.end());
    
    ++NumCacheDirtyNonLocal;
    //cerr << "CACHED CASE: " << DirtyBlocks.size() << " dirty: "
    //     << Cache.size() << " cached: " << *QueryInst;
  } else {
    // Seed DirtyBlocks with each of the preds of QueryInst's block.
    BasicBlock *QueryBB = QueryCS.getInstruction()->getParent();
    for (BasicBlock **PI = PredCache->GetPreds(QueryBB); *PI; ++PI)
      DirtyBlocks.push_back(*PI);
    NumUncacheNonLocal++;
  }
  
  // isReadonlyCall - If this is a read-only call, we can be more aggressive.
  bool isReadonlyCall = AA->onlyReadsMemory(QueryCS);

  SmallPtrSet<BasicBlock*, 64> Visited;
  
  unsigned NumSortedEntries = Cache.size();
  DEBUG(AssertSorted(Cache));
  
  // Iterate while we still have blocks to update.
  while (!DirtyBlocks.empty()) {
    BasicBlock *DirtyBB = DirtyBlocks.back();
    DirtyBlocks.pop_back();
    
    // Already processed this block?
    if (!Visited.insert(DirtyBB))
      continue;
    
    // Do a binary search to see if we already have an entry for this block in
    // the cache set.  If so, find it.
    DEBUG(AssertSorted(Cache, NumSortedEntries));
    NonLocalDepInfo::iterator Entry = 
      std::upper_bound(Cache.begin(), Cache.begin()+NumSortedEntries,
                       NonLocalDepEntry(DirtyBB));
    if (Entry != Cache.begin() && prior(Entry)->getBB() == DirtyBB)
      --Entry;
    
    NonLocalDepEntry *ExistingResult = 0;
    if (Entry != Cache.begin()+NumSortedEntries && 
        Entry->getBB() == DirtyBB) {
      // If we already have an entry, and if it isn't already dirty, the block
      // is done.
      if (!Entry->getResult().isDirty())
        continue;
      
      // Otherwise, remember this slot so we can update the value.
      ExistingResult = &*Entry;
    }
    
    // If the dirty entry has a pointer, start scanning from it so we don't have
    // to rescan the entire block.
    BasicBlock::iterator ScanPos = DirtyBB->end();
    if (ExistingResult) {
      if (Instruction *Inst = ExistingResult->getResult().getInst()) {
        ScanPos = Inst;
        // We're removing QueryInst's use of Inst.
        RemoveFromReverseMap(ReverseNonLocalDeps, Inst,
                             QueryCS.getInstruction());
      }
    }
    
    // Find out if this block has a local dependency for QueryInst.
    MemDepResult Dep;
    
    if (ScanPos != DirtyBB->begin()) {
      Dep = getCallSiteDependencyFrom(QueryCS, isReadonlyCall,ScanPos, DirtyBB);
    } else if (DirtyBB != &DirtyBB->getParent()->getEntryBlock()) {
      // No dependence found.  If this is the entry block of the function, it is
      // a clobber, otherwise it is non-local.
      Dep = MemDepResult::getNonLocal();
    } else {
      Dep = MemDepResult::getClobber(ScanPos);
    }
    
    // If we had a dirty entry for the block, update it.  Otherwise, just add
    // a new entry.
    if (ExistingResult)
      ExistingResult->setResult(Dep);
    else
      Cache.push_back(NonLocalDepEntry(DirtyBB, Dep));
    
    // If the block has a dependency (i.e. it isn't completely transparent to
    // the value), remember the association!
    if (!Dep.isNonLocal()) {
      // Keep the ReverseNonLocalDeps map up to date so we can efficiently
      // update this when we remove instructions.
      if (Instruction *Inst = Dep.getInst())
        ReverseNonLocalDeps[Inst].insert(QueryCS.getInstruction());
    } else {
    
      // If the block *is* completely transparent to the load, we need to check
      // the predecessors of this block.  Add them to our worklist.
      for (BasicBlock **PI = PredCache->GetPreds(DirtyBB); *PI; ++PI)
        DirtyBlocks.push_back(*PI);
    }
  }
  
  return Cache;
}

/// getNonLocalPointerDependency - Perform a full dependency query for an
/// access to the specified (non-volatile) memory location, returning the
/// set of instructions that either define or clobber the value.
///
/// This method assumes the pointer has a "NonLocal" dependency within its
/// own block.
///
void MemoryDependenceAnalysis::
getNonLocalPointerDependency(Value *Pointer, bool isLoad, BasicBlock *FromBB,
                             SmallVectorImpl<NonLocalDepResult> &Result) {
  assert(Pointer->getType()->isPointerTy() &&
         "Can't get pointer deps of a non-pointer!");
  Result.clear();
  
  // We know that the pointer value is live into FromBB find the def/clobbers
  // from presecessors.
  const Type *EltTy = cast<PointerType>(Pointer->getType())->getElementType();
  uint64_t PointeeSize = AA->getTypeStoreSize(EltTy);
  
  PHITransAddr Address(Pointer, TD);
  
  // This is the set of blocks we've inspected, and the pointer we consider in
  // each block.  Because of critical edges, we currently bail out if querying
  // a block with multiple different pointers.  This can happen during PHI
  // translation.
  DenseMap<BasicBlock*, Value*> Visited;
  if (!getNonLocalPointerDepFromBB(Address, PointeeSize, isLoad, FromBB,
                                   Result, Visited, true))
    return;
  Result.clear();
  Result.push_back(NonLocalDepResult(FromBB,
                                     MemDepResult::getClobber(FromBB->begin()),
                                     Pointer));
}

/// GetNonLocalInfoForBlock - Compute the memdep value for BB with
/// Pointer/PointeeSize using either cached information in Cache or by doing a
/// lookup (which may use dirty cache info if available).  If we do a lookup,
/// add the result to the cache.
MemDepResult MemoryDependenceAnalysis::
GetNonLocalInfoForBlock(Value *Pointer, uint64_t PointeeSize,
                        bool isLoad, BasicBlock *BB,
                        NonLocalDepInfo *Cache, unsigned NumSortedEntries) {
  
  // Do a binary search to see if we already have an entry for this block in
  // the cache set.  If so, find it.
  NonLocalDepInfo::iterator Entry =
    std::upper_bound(Cache->begin(), Cache->begin()+NumSortedEntries,
                     NonLocalDepEntry(BB));
  if (Entry != Cache->begin() && (Entry-1)->getBB() == BB)
    --Entry;
  
  NonLocalDepEntry *ExistingResult = 0;
  if (Entry != Cache->begin()+NumSortedEntries && Entry->getBB() == BB)
    ExistingResult = &*Entry;
  
  // If we have a cached entry, and it is non-dirty, use it as the value for
  // this dependency.
  if (ExistingResult && !ExistingResult->getResult().isDirty()) {
    ++NumCacheNonLocalPtr;
    return ExistingResult->getResult();
  }    
  
  // Otherwise, we have to scan for the value.  If we have a dirty cache
  // entry, start scanning from its position, otherwise we scan from the end
  // of the block.
  BasicBlock::iterator ScanPos = BB->end();
  if (ExistingResult && ExistingResult->getResult().getInst()) {
    assert(ExistingResult->getResult().getInst()->getParent() == BB &&
           "Instruction invalidated?");
    ++NumCacheDirtyNonLocalPtr;
    ScanPos = ExistingResult->getResult().getInst();
    
    // Eliminating the dirty entry from 'Cache', so update the reverse info.
    ValueIsLoadPair CacheKey(Pointer, isLoad);
    RemoveFromReverseMap(ReverseNonLocalPtrDeps, ScanPos, CacheKey);
  } else {
    ++NumUncacheNonLocalPtr;
  }
  
  // Scan the block for the dependency.
  MemDepResult Dep = getPointerDependencyFrom(Pointer, PointeeSize, isLoad, 
                                              ScanPos, BB);
  
  // If we had a dirty entry for the block, update it.  Otherwise, just add
  // a new entry.
  if (ExistingResult)
    ExistingResult->setResult(Dep);
  else
    Cache->push_back(NonLocalDepEntry(BB, Dep));
  
  // If the block has a dependency (i.e. it isn't completely transparent to
  // the value), remember the reverse association because we just added it
  // to Cache!
  if (Dep.isNonLocal())
    return Dep;
  
  // Keep the ReverseNonLocalPtrDeps map up to date so we can efficiently
  // update MemDep when we remove instructions.
  Instruction *Inst = Dep.getInst();
  assert(Inst && "Didn't depend on anything?");
  ValueIsLoadPair CacheKey(Pointer, isLoad);
  ReverseNonLocalPtrDeps[Inst].insert(CacheKey);
  return Dep;
}

/// SortNonLocalDepInfoCache - Sort the a NonLocalDepInfo cache, given a certain
/// number of elements in the array that are already properly ordered.  This is
/// optimized for the case when only a few entries are added.
static void 
SortNonLocalDepInfoCache(MemoryDependenceAnalysis::NonLocalDepInfo &Cache,
                         unsigned NumSortedEntries) {
  switch (Cache.size() - NumSortedEntries) {
  case 0:
    // done, no new entries.
    break;
  case 2: {
    // Two new entries, insert the last one into place.
    NonLocalDepEntry Val = Cache.back();
    Cache.pop_back();
    MemoryDependenceAnalysis::NonLocalDepInfo::iterator Entry =
      std::upper_bound(Cache.begin(), Cache.end()-1, Val);
    Cache.insert(Entry, Val);
    // FALL THROUGH.
  }
  case 1:
    // One new entry, Just insert the new value at the appropriate position.
    if (Cache.size() != 1) {
      NonLocalDepEntry Val = Cache.back();
      Cache.pop_back();
      MemoryDependenceAnalysis::NonLocalDepInfo::iterator Entry =
        std::upper_bound(Cache.begin(), Cache.end(), Val);
      Cache.insert(Entry, Val);
    }
    break;
  default:
    // Added many values, do a full scale sort.
    std::sort(Cache.begin(), Cache.end());
    break;
  }
}

/// getNonLocalPointerDepFromBB - Perform a dependency query based on
/// pointer/pointeesize starting at the end of StartBB.  Add any clobber/def
/// results to the results vector and keep track of which blocks are visited in
/// 'Visited'.
///
/// This has special behavior for the first block queries (when SkipFirstBlock
/// is true).  In this special case, it ignores the contents of the specified
/// block and starts returning dependence info for its predecessors.
///
/// This function returns false on success, or true to indicate that it could
/// not compute dependence information for some reason.  This should be treated
/// as a clobber dependence on the first instruction in the predecessor block.
bool MemoryDependenceAnalysis::
getNonLocalPointerDepFromBB(const PHITransAddr &Pointer, uint64_t PointeeSize,
                            bool isLoad, BasicBlock *StartBB,
                            SmallVectorImpl<NonLocalDepResult> &Result,
                            DenseMap<BasicBlock*, Value*> &Visited,
                            bool SkipFirstBlock) {
  
  // Look up the cached info for Pointer.
  ValueIsLoadPair CacheKey(Pointer.getAddr(), isLoad);
  
  std::pair<BBSkipFirstBlockPair, NonLocalDepInfo> *CacheInfo =
    &NonLocalPointerDeps[CacheKey];
  NonLocalDepInfo *Cache = &CacheInfo->second;

  // If we have valid cached information for exactly the block we are
  // investigating, just return it with no recomputation.
  if (CacheInfo->first == BBSkipFirstBlockPair(StartBB, SkipFirstBlock)) {
    // We have a fully cached result for this query then we can just return the
    // cached results and populate the visited set.  However, we have to verify
    // that we don't already have conflicting results for these blocks.  Check
    // to ensure that if a block in the results set is in the visited set that
    // it was for the same pointer query.
    if (!Visited.empty()) {
      for (NonLocalDepInfo::iterator I = Cache->begin(), E = Cache->end();
           I != E; ++I) {
        DenseMap<BasicBlock*, Value*>::iterator VI = Visited.find(I->getBB());
        if (VI == Visited.end() || VI->second == Pointer.getAddr())
          continue;
        
        // We have a pointer mismatch in a block.  Just return clobber, saying
        // that something was clobbered in this result.  We could also do a
        // non-fully cached query, but there is little point in doing this.
        return true;
      }
    }
    
    Value *Addr = Pointer.getAddr();
    for (NonLocalDepInfo::iterator I = Cache->begin(), E = Cache->end();
         I != E; ++I) {
      Visited.insert(std::make_pair(I->getBB(), Addr));
      if (!I->getResult().isNonLocal())
        Result.push_back(NonLocalDepResult(I->getBB(), I->getResult(), Addr));
    }
    ++NumCacheCompleteNonLocalPtr;
    return false;
  }
  
  // Otherwise, either this is a new block, a block with an invalid cache
  // pointer or one that we're about to invalidate by putting more info into it
  // than its valid cache info.  If empty, the result will be valid cache info,
  // otherwise it isn't.
  if (Cache->empty())
    CacheInfo->first = BBSkipFirstBlockPair(StartBB, SkipFirstBlock);
  else
    CacheInfo->first = BBSkipFirstBlockPair();
  
  SmallVector<BasicBlock*, 32> Worklist;
  Worklist.push_back(StartBB);
  
  // Keep track of the entries that we know are sorted.  Previously cached
  // entries will all be sorted.  The entries we add we only sort on demand (we
  // don't insert every element into its sorted position).  We know that we
  // won't get any reuse from currently inserted values, because we don't
  // revisit blocks after we insert info for them.
  unsigned NumSortedEntries = Cache->size();
  DEBUG(AssertSorted(*Cache));
  
  while (!Worklist.empty()) {
    BasicBlock *BB = Worklist.pop_back_val();
    
    // Skip the first block if we have it.
    if (!SkipFirstBlock) {
      // Analyze the dependency of *Pointer in FromBB.  See if we already have
      // been here.
      assert(Visited.count(BB) && "Should check 'visited' before adding to WL");

      // Get the dependency info for Pointer in BB.  If we have cached
      // information, we will use it, otherwise we compute it.
      DEBUG(AssertSorted(*Cache, NumSortedEntries));
      MemDepResult Dep = GetNonLocalInfoForBlock(Pointer.getAddr(), PointeeSize,
                                                 isLoad, BB, Cache,
                                                 NumSortedEntries);
      
      // If we got a Def or Clobber, add this to the list of results.
      if (!Dep.isNonLocal()) {
        Result.push_back(NonLocalDepResult(BB, Dep, Pointer.getAddr()));
        continue;
      }
    }
    
    // If 'Pointer' is an instruction defined in this block, then we need to do
    // phi translation to change it into a value live in the predecessor block.
    // If not, we just add the predecessors to the worklist and scan them with
    // the same Pointer.
    if (!Pointer.NeedsPHITranslationFromBlock(BB)) {
      SkipFirstBlock = false;
      for (BasicBlock **PI = PredCache->GetPreds(BB); *PI; ++PI) {
        // Verify that we haven't looked at this block yet.
        std::pair<DenseMap<BasicBlock*,Value*>::iterator, bool>
          InsertRes = Visited.insert(std::make_pair(*PI, Pointer.getAddr()));
        if (InsertRes.second) {
          // First time we've looked at *PI.
          Worklist.push_back(*PI);
          continue;
        }
        
        // If we have seen this block before, but it was with a different
        // pointer then we have a phi translation failure and we have to treat
        // this as a clobber.
        if (InsertRes.first->second != Pointer.getAddr())
          goto PredTranslationFailure;
      }
      continue;
    }
    
    // We do need to do phi translation, if we know ahead of time we can't phi
    // translate this value, don't even try.
    if (!Pointer.IsPotentiallyPHITranslatable())
      goto PredTranslationFailure;
    
    // We may have added values to the cache list before this PHI translation.
    // If so, we haven't done anything to ensure that the cache remains sorted.
    // Sort it now (if needed) so that recursive invocations of
    // getNonLocalPointerDepFromBB and other routines that could reuse the cache
    // value will only see properly sorted cache arrays.
    if (Cache && NumSortedEntries != Cache->size()) {
      SortNonLocalDepInfoCache(*Cache, NumSortedEntries);
      NumSortedEntries = Cache->size();
    }
    Cache = 0;
    
    for (BasicBlock **PI = PredCache->GetPreds(BB); *PI; ++PI) {
      BasicBlock *Pred = *PI;
      
      // Get the PHI translated pointer in this predecessor.  This can fail if
      // not translatable, in which case the getAddr() returns null.
      PHITransAddr PredPointer(Pointer);
      PredPointer.PHITranslateValue(BB, Pred);

      Value *PredPtrVal = PredPointer.getAddr();
      
      // Check to see if we have already visited this pred block with another
      // pointer.  If so, we can't do this lookup.  This failure can occur
      // with PHI translation when a critical edge exists and the PHI node in
      // the successor translates to a pointer value different than the
      // pointer the block was first analyzed with.
      std::pair<DenseMap<BasicBlock*,Value*>::iterator, bool>
        InsertRes = Visited.insert(std::make_pair(Pred, PredPtrVal));

      if (!InsertRes.second) {
        // If the predecessor was visited with PredPtr, then we already did
        // the analysis and can ignore it.
        if (InsertRes.first->second == PredPtrVal)
          continue;
        
        // Otherwise, the block was previously analyzed with a different
        // pointer.  We can't represent the result of this case, so we just
        // treat this as a phi translation failure.
        goto PredTranslationFailure;
      }
      
      // If PHI translation was unable to find an available pointer in this
      // predecessor, then we have to assume that the pointer is clobbered in
      // that predecessor.  We can still do PRE of the load, which would insert
      // a computation of the pointer in this predecessor.
      if (PredPtrVal == 0) {
        // Add the entry to the Result list.
        NonLocalDepResult Entry(Pred,
                                MemDepResult::getClobber(Pred->getTerminator()),
                                PredPtrVal);
        Result.push_back(Entry);

        // Since we had a phi translation failure, the cache for CacheKey won't
        // include all of the entries that we need to immediately satisfy future
        // queries.  Mark this in NonLocalPointerDeps by setting the
        // BBSkipFirstBlockPair pointer to null.  This requires reuse of the
        // cached value to do more work but not miss the phi trans failure.
        NonLocalPointerDeps[CacheKey].first = BBSkipFirstBlockPair();
        continue;
      }

      // FIXME: it is entirely possible that PHI translating will end up with
      // the same value.  Consider PHI translating something like:
      // X = phi [x, bb1], [y, bb2].  PHI translating for bb1 doesn't *need*
      // to recurse here, pedantically speaking.
      
      // If we have a problem phi translating, fall through to the code below
      // to handle the failure condition.
      if (getNonLocalPointerDepFromBB(PredPointer, PointeeSize, isLoad, Pred,
                                      Result, Visited))
        goto PredTranslationFailure;
    }
    
    // Refresh the CacheInfo/Cache pointer so that it isn't invalidated.
    CacheInfo = &NonLocalPointerDeps[CacheKey];
    Cache = &CacheInfo->second;
    NumSortedEntries = Cache->size();
    
    // Since we did phi translation, the "Cache" set won't contain all of the
    // results for the query.  This is ok (we can still use it to accelerate
    // specific block queries) but we can't do the fastpath "return all
    // results from the set"  Clear out the indicator for this.
    CacheInfo->first = BBSkipFirstBlockPair();
    SkipFirstBlock = false;
    continue;

  PredTranslationFailure:
    
    if (Cache == 0) {
      // Refresh the CacheInfo/Cache pointer if it got invalidated.
      CacheInfo = &NonLocalPointerDeps[CacheKey];
      Cache = &CacheInfo->second;
      NumSortedEntries = Cache->size();
    }
    
    // Since we failed phi translation, the "Cache" set won't contain all of the
    // results for the query.  This is ok (we can still use it to accelerate
    // specific block queries) but we can't do the fastpath "return all
    // results from the set".  Clear out the indicator for this.
    CacheInfo->first = BBSkipFirstBlockPair();
    
    // If *nothing* works, mark the pointer as being clobbered by the first
    // instruction in this block.
    //
    // If this is the magic first block, return this as a clobber of the whole
    // incoming value.  Since we can't phi translate to one of the predecessors,
    // we have to bail out.
    if (SkipFirstBlock)
      return true;
    
    for (NonLocalDepInfo::reverse_iterator I = Cache->rbegin(); ; ++I) {
      assert(I != Cache->rend() && "Didn't find current block??");
      if (I->getBB() != BB)
        continue;
      
      assert(I->getResult().isNonLocal() &&
             "Should only be here with transparent block");
      I->setResult(MemDepResult::getClobber(BB->begin()));
      ReverseNonLocalPtrDeps[BB->begin()].insert(CacheKey);
      Result.push_back(NonLocalDepResult(I->getBB(), I->getResult(),
                                         Pointer.getAddr()));
      break;
    }
  }

  // Okay, we're done now.  If we added new values to the cache, re-sort it.
  SortNonLocalDepInfoCache(*Cache, NumSortedEntries);
  DEBUG(AssertSorted(*Cache));
  return false;
}

/// RemoveCachedNonLocalPointerDependencies - If P exists in
/// CachedNonLocalPointerInfo, remove it.
void MemoryDependenceAnalysis::
RemoveCachedNonLocalPointerDependencies(ValueIsLoadPair P) {
  CachedNonLocalPointerInfo::iterator It = 
    NonLocalPointerDeps.find(P);
  if (It == NonLocalPointerDeps.end()) return;
  
  // Remove all of the entries in the BB->val map.  This involves removing
  // instructions from the reverse map.
  NonLocalDepInfo &PInfo = It->second.second;
  
  for (unsigned i = 0, e = PInfo.size(); i != e; ++i) {
    Instruction *Target = PInfo[i].getResult().getInst();
    if (Target == 0) continue;  // Ignore non-local dep results.
    assert(Target->getParent() == PInfo[i].getBB());
    
    // Eliminating the dirty entry from 'Cache', so update the reverse info.
    RemoveFromReverseMap(ReverseNonLocalPtrDeps, Target, P);
  }
  
  // Remove P from NonLocalPointerDeps (which deletes NonLocalDepInfo).
  NonLocalPointerDeps.erase(It);
}


/// invalidateCachedPointerInfo - This method is used to invalidate cached
/// information about the specified pointer, because it may be too
/// conservative in memdep.  This is an optional call that can be used when
/// the client detects an equivalence between the pointer and some other
/// value and replaces the other value with ptr. This can make Ptr available
/// in more places that cached info does not necessarily keep.
void MemoryDependenceAnalysis::invalidateCachedPointerInfo(Value *Ptr) {
  // If Ptr isn't really a pointer, just ignore it.
  if (!Ptr->getType()->isPointerTy()) return;
  // Flush store info for the pointer.
  RemoveCachedNonLocalPointerDependencies(ValueIsLoadPair(Ptr, false));
  // Flush load info for the pointer.
  RemoveCachedNonLocalPointerDependencies(ValueIsLoadPair(Ptr, true));
}

/// invalidateCachedPredecessors - Clear the PredIteratorCache info.
/// This needs to be done when the CFG changes, e.g., due to splitting
/// critical edges.
void MemoryDependenceAnalysis::invalidateCachedPredecessors() {
  PredCache->clear();
}

/// removeInstruction - Remove an instruction from the dependence analysis,
/// updating the dependence of instructions that previously depended on it.
/// This method attempts to keep the cache coherent using the reverse map.
void MemoryDependenceAnalysis::removeInstruction(Instruction *RemInst) {
  // Walk through the Non-local dependencies, removing this one as the value
  // for any cached queries.
  NonLocalDepMapType::iterator NLDI = NonLocalDeps.find(RemInst);
  if (NLDI != NonLocalDeps.end()) {
    NonLocalDepInfo &BlockMap = NLDI->second.first;
    for (NonLocalDepInfo::iterator DI = BlockMap.begin(), DE = BlockMap.end();
         DI != DE; ++DI)
      if (Instruction *Inst = DI->getResult().getInst())
        RemoveFromReverseMap(ReverseNonLocalDeps, Inst, RemInst);
    NonLocalDeps.erase(NLDI);
  }

  // If we have a cached local dependence query for this instruction, remove it.
  //
  LocalDepMapType::iterator LocalDepEntry = LocalDeps.find(RemInst);
  if (LocalDepEntry != LocalDeps.end()) {
    // Remove us from DepInst's reverse set now that the local dep info is gone.
    if (Instruction *Inst = LocalDepEntry->second.getInst())
      RemoveFromReverseMap(ReverseLocalDeps, Inst, RemInst);

    // Remove this local dependency info.
    LocalDeps.erase(LocalDepEntry);
  }
  
  // If we have any cached pointer dependencies on this instruction, remove
  // them.  If the instruction has non-pointer type, then it can't be a pointer
  // base.
  
  // Remove it from both the load info and the store info.  The instruction
  // can't be in either of these maps if it is non-pointer.
  if (RemInst->getType()->isPointerTy()) {
    RemoveCachedNonLocalPointerDependencies(ValueIsLoadPair(RemInst, false));
    RemoveCachedNonLocalPointerDependencies(ValueIsLoadPair(RemInst, true));
  }
  
  // Loop over all of the things that depend on the instruction we're removing.
  // 
  SmallVector<std::pair<Instruction*, Instruction*>, 8> ReverseDepsToAdd;

  // If we find RemInst as a clobber or Def in any of the maps for other values,
  // we need to replace its entry with a dirty version of the instruction after
  // it.  If RemInst is a terminator, we use a null dirty value.
  //
  // Using a dirty version of the instruction after RemInst saves having to scan
  // the entire block to get to this point.
  MemDepResult NewDirtyVal;
  if (!RemInst->isTerminator())
    NewDirtyVal = MemDepResult::getDirty(++BasicBlock::iterator(RemInst));
  
  ReverseDepMapType::iterator ReverseDepIt = ReverseLocalDeps.find(RemInst);
  if (ReverseDepIt != ReverseLocalDeps.end()) {
    SmallPtrSet<Instruction*, 4> &ReverseDeps = ReverseDepIt->second;
    // RemInst can't be the terminator if it has local stuff depending on it.
    assert(!ReverseDeps.empty() && !isa<TerminatorInst>(RemInst) &&
           "Nothing can locally depend on a terminator");
    
    for (SmallPtrSet<Instruction*, 4>::iterator I = ReverseDeps.begin(),
         E = ReverseDeps.end(); I != E; ++I) {
      Instruction *InstDependingOnRemInst = *I;
      assert(InstDependingOnRemInst != RemInst &&
             "Already removed our local dep info");
                        
      LocalDeps[InstDependingOnRemInst] = NewDirtyVal;
      
      // Make sure to remember that new things depend on NewDepInst.
      assert(NewDirtyVal.getInst() && "There is no way something else can have "
             "a local dep on this if it is a terminator!");
      ReverseDepsToAdd.push_back(std::make_pair(NewDirtyVal.getInst(), 
                                                InstDependingOnRemInst));
    }
    
    ReverseLocalDeps.erase(ReverseDepIt);

    // Add new reverse deps after scanning the set, to avoid invalidating the
    // 'ReverseDeps' reference.
    while (!ReverseDepsToAdd.empty()) {
      ReverseLocalDeps[ReverseDepsToAdd.back().first]
        .insert(ReverseDepsToAdd.back().second);
      ReverseDepsToAdd.pop_back();
    }
  }
  
  ReverseDepIt = ReverseNonLocalDeps.find(RemInst);
  if (ReverseDepIt != ReverseNonLocalDeps.end()) {
    SmallPtrSet<Instruction*, 4> &Set = ReverseDepIt->second;
    for (SmallPtrSet<Instruction*, 4>::iterator I = Set.begin(), E = Set.end();
         I != E; ++I) {
      assert(*I != RemInst && "Already removed NonLocalDep info for RemInst");
      
      PerInstNLInfo &INLD = NonLocalDeps[*I];
      // The information is now dirty!
      INLD.second = true;
      
      for (NonLocalDepInfo::iterator DI = INLD.first.begin(), 
           DE = INLD.first.end(); DI != DE; ++DI) {
        if (DI->getResult().getInst() != RemInst) continue;
        
        // Convert to a dirty entry for the subsequent instruction.
        DI->setResult(NewDirtyVal);
        
        if (Instruction *NextI = NewDirtyVal.getInst())
          ReverseDepsToAdd.push_back(std::make_pair(NextI, *I));
      }
    }

    ReverseNonLocalDeps.erase(ReverseDepIt);

    // Add new reverse deps after scanning the set, to avoid invalidating 'Set'
    while (!ReverseDepsToAdd.empty()) {
      ReverseNonLocalDeps[ReverseDepsToAdd.back().first]
        .insert(ReverseDepsToAdd.back().second);
      ReverseDepsToAdd.pop_back();
    }
  }
  
  // If the instruction is in ReverseNonLocalPtrDeps then it appears as a
  // value in the NonLocalPointerDeps info.
  ReverseNonLocalPtrDepTy::iterator ReversePtrDepIt =
    ReverseNonLocalPtrDeps.find(RemInst);
  if (ReversePtrDepIt != ReverseNonLocalPtrDeps.end()) {
    SmallPtrSet<ValueIsLoadPair, 4> &Set = ReversePtrDepIt->second;
    SmallVector<std::pair<Instruction*, ValueIsLoadPair>,8> ReversePtrDepsToAdd;
    
    for (SmallPtrSet<ValueIsLoadPair, 4>::iterator I = Set.begin(),
         E = Set.end(); I != E; ++I) {
      ValueIsLoadPair P = *I;
      assert(P.getPointer() != RemInst &&
             "Already removed NonLocalPointerDeps info for RemInst");
      
      NonLocalDepInfo &NLPDI = NonLocalPointerDeps[P].second;
      
      // The cache is not valid for any specific block anymore.
      NonLocalPointerDeps[P].first = BBSkipFirstBlockPair();
      
      // Update any entries for RemInst to use the instruction after it.
      for (NonLocalDepInfo::iterator DI = NLPDI.begin(), DE = NLPDI.end();
           DI != DE; ++DI) {
        if (DI->getResult().getInst() != RemInst) continue;
        
        // Convert to a dirty entry for the subsequent instruction.
        DI->setResult(NewDirtyVal);
        
        if (Instruction *NewDirtyInst = NewDirtyVal.getInst())
          ReversePtrDepsToAdd.push_back(std::make_pair(NewDirtyInst, P));
      }
      
      // Re-sort the NonLocalDepInfo.  Changing the dirty entry to its
      // subsequent value may invalidate the sortedness.
      std::sort(NLPDI.begin(), NLPDI.end());
    }
    
    ReverseNonLocalPtrDeps.erase(ReversePtrDepIt);
    
    while (!ReversePtrDepsToAdd.empty()) {
      ReverseNonLocalPtrDeps[ReversePtrDepsToAdd.back().first]
        .insert(ReversePtrDepsToAdd.back().second);
      ReversePtrDepsToAdd.pop_back();
    }
  }
  
  
  assert(!NonLocalDeps.count(RemInst) && "RemInst got reinserted?");
  AA->deleteValue(RemInst);
  DEBUG(verifyRemoved(RemInst));
}
/// verifyRemoved - Verify that the specified instruction does not occur
/// in our internal data structures.
void MemoryDependenceAnalysis::verifyRemoved(Instruction *D) const {
  for (LocalDepMapType::const_iterator I = LocalDeps.begin(),
       E = LocalDeps.end(); I != E; ++I) {
    assert(I->first != D && "Inst occurs in data structures");
    assert(I->second.getInst() != D &&
           "Inst occurs in data structures");
  }
  
  for (CachedNonLocalPointerInfo::const_iterator I =NonLocalPointerDeps.begin(),
       E = NonLocalPointerDeps.end(); I != E; ++I) {
    assert(I->first.getPointer() != D && "Inst occurs in NLPD map key");
    const NonLocalDepInfo &Val = I->second.second;
    for (NonLocalDepInfo::const_iterator II = Val.begin(), E = Val.end();
         II != E; ++II)
      assert(II->getResult().getInst() != D && "Inst occurs as NLPD value");
  }
  
  for (NonLocalDepMapType::const_iterator I = NonLocalDeps.begin(),
       E = NonLocalDeps.end(); I != E; ++I) {
    assert(I->first != D && "Inst occurs in data structures");
    const PerInstNLInfo &INLD = I->second;
    for (NonLocalDepInfo::const_iterator II = INLD.first.begin(),
         EE = INLD.first.end(); II  != EE; ++II)
      assert(II->getResult().getInst() != D && "Inst occurs in data structures");
  }
  
  for (ReverseDepMapType::const_iterator I = ReverseLocalDeps.begin(),
       E = ReverseLocalDeps.end(); I != E; ++I) {
    assert(I->first != D && "Inst occurs in data structures");
    for (SmallPtrSet<Instruction*, 4>::const_iterator II = I->second.begin(),
         EE = I->second.end(); II != EE; ++II)
      assert(*II != D && "Inst occurs in data structures");
  }
  
  for (ReverseDepMapType::const_iterator I = ReverseNonLocalDeps.begin(),
       E = ReverseNonLocalDeps.end();
       I != E; ++I) {
    assert(I->first != D && "Inst occurs in data structures");
    for (SmallPtrSet<Instruction*, 4>::const_iterator II = I->second.begin(),
         EE = I->second.end(); II != EE; ++II)
      assert(*II != D && "Inst occurs in data structures");
  }
  
  for (ReverseNonLocalPtrDepTy::const_iterator
       I = ReverseNonLocalPtrDeps.begin(),
       E = ReverseNonLocalPtrDeps.end(); I != E; ++I) {
    assert(I->first != D && "Inst occurs in rev NLPD map");
    
    for (SmallPtrSet<ValueIsLoadPair, 4>::const_iterator II = I->second.begin(),
         E = I->second.end(); II != E; ++II)
      assert(*II != ValueIsLoadPair(D, false) &&
             *II != ValueIsLoadPair(D, true) &&
             "Inst occurs in ReverseNonLocalPtrDeps map");
  }
  
}
