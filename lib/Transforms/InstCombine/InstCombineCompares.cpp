//===- InstCombineCompares.cpp --------------------------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements the visitICmp and visitFCmp functions.
//
//===----------------------------------------------------------------------===//

#include "InstCombine.h"
#include "llvm/IntrinsicInst.h"
#include "llvm/Analysis/InstructionSimplify.h"
#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/Target/TargetData.h"
#include "llvm/Support/ConstantRange.h"
#include "llvm/Support/GetElementPtrTypeIterator.h"
#include "llvm/Support/PatternMatch.h"
using namespace llvm;
using namespace PatternMatch;

/// AddOne - Add one to a ConstantInt
static Constant *AddOne(Constant *C) {
  return ConstantExpr::getAdd(C, ConstantInt::get(C->getType(), 1));
}
/// SubOne - Subtract one from a ConstantInt
static Constant *SubOne(ConstantInt *C) {
  return ConstantExpr::getSub(C,  ConstantInt::get(C->getType(), 1));
}

static ConstantInt *ExtractElement(Constant *V, Constant *Idx) {
  return cast<ConstantInt>(ConstantExpr::getExtractElement(V, Idx));
}

static bool HasAddOverflow(ConstantInt *Result,
                           ConstantInt *In1, ConstantInt *In2,
                           bool IsSigned) {
  if (IsSigned)
    if (In2->getValue().isNegative())
      return Result->getValue().sgt(In1->getValue());
    else
      return Result->getValue().slt(In1->getValue());
  else
    return Result->getValue().ult(In1->getValue());
}

/// AddWithOverflow - Compute Result = In1+In2, returning true if the result
/// overflowed for this type.
static bool AddWithOverflow(Constant *&Result, Constant *In1,
                            Constant *In2, bool IsSigned = false) {
  Result = ConstantExpr::getAdd(In1, In2);

  if (const VectorType *VTy = dyn_cast<VectorType>(In1->getType())) {
    for (unsigned i = 0, e = VTy->getNumElements(); i != e; ++i) {
      Constant *Idx = ConstantInt::get(Type::getInt32Ty(In1->getContext()), i);
      if (HasAddOverflow(ExtractElement(Result, Idx),
                         ExtractElement(In1, Idx),
                         ExtractElement(In2, Idx),
                         IsSigned))
        return true;
    }
    return false;
  }

  return HasAddOverflow(cast<ConstantInt>(Result),
                        cast<ConstantInt>(In1), cast<ConstantInt>(In2),
                        IsSigned);
}

static bool HasSubOverflow(ConstantInt *Result,
                           ConstantInt *In1, ConstantInt *In2,
                           bool IsSigned) {
  if (IsSigned)
    if (In2->getValue().isNegative())
      return Result->getValue().slt(In1->getValue());
    else
      return Result->getValue().sgt(In1->getValue());
  else
    return Result->getValue().ugt(In1->getValue());
}

/// SubWithOverflow - Compute Result = In1-In2, returning true if the result
/// overflowed for this type.
static bool SubWithOverflow(Constant *&Result, Constant *In1,
                            Constant *In2, bool IsSigned = false) {
  Result = ConstantExpr::getSub(In1, In2);

  if (const VectorType *VTy = dyn_cast<VectorType>(In1->getType())) {
    for (unsigned i = 0, e = VTy->getNumElements(); i != e; ++i) {
      Constant *Idx = ConstantInt::get(Type::getInt32Ty(In1->getContext()), i);
      if (HasSubOverflow(ExtractElement(Result, Idx),
                         ExtractElement(In1, Idx),
                         ExtractElement(In2, Idx),
                         IsSigned))
        return true;
    }
    return false;
  }

  return HasSubOverflow(cast<ConstantInt>(Result),
                        cast<ConstantInt>(In1), cast<ConstantInt>(In2),
                        IsSigned);
}

/// isSignBitCheck - Given an exploded icmp instruction, return true if the
/// comparison only checks the sign bit.  If it only checks the sign bit, set
/// TrueIfSigned if the result of the comparison is true when the input value is
/// signed.
static bool isSignBitCheck(ICmpInst::Predicate pred, ConstantInt *RHS,
                           bool &TrueIfSigned) {
  switch (pred) {
  case ICmpInst::ICMP_SLT:   // True if LHS s< 0
    TrueIfSigned = true;
    return RHS->isZero();
  case ICmpInst::ICMP_SLE:   // True if LHS s<= RHS and RHS == -1
    TrueIfSigned = true;
    return RHS->isAllOnesValue();
  case ICmpInst::ICMP_SGT:   // True if LHS s> -1
    TrueIfSigned = false;
    return RHS->isAllOnesValue();
  case ICmpInst::ICMP_UGT:
    // True if LHS u> RHS and RHS == high-bit-mask - 1
    TrueIfSigned = true;
    return RHS->getValue() ==
      APInt::getSignedMaxValue(RHS->getType()->getPrimitiveSizeInBits());
  case ICmpInst::ICMP_UGE: 
    // True if LHS u>= RHS and RHS == high-bit-mask (2^7, 2^15, 2^31, etc)
    TrueIfSigned = true;
    return RHS->getValue().isSignBit();
  default:
    return false;
  }
}

// isHighOnes - Return true if the constant is of the form 1+0+.
// This is the same as lowones(~X).
static bool isHighOnes(const ConstantInt *CI) {
  return (~CI->getValue() + 1).isPowerOf2();
}

/// ComputeSignedMinMaxValuesFromKnownBits - Given a signed integer type and a 
/// set of known zero and one bits, compute the maximum and minimum values that
/// could have the specified known zero and known one bits, returning them in
/// min/max.
static void ComputeSignedMinMaxValuesFromKnownBits(const APInt& KnownZero,
                                                   const APInt& KnownOne,
                                                   APInt& Min, APInt& Max) {
  assert(KnownZero.getBitWidth() == KnownOne.getBitWidth() &&
         KnownZero.getBitWidth() == Min.getBitWidth() &&
         KnownZero.getBitWidth() == Max.getBitWidth() &&
         "KnownZero, KnownOne and Min, Max must have equal bitwidth.");
  APInt UnknownBits = ~(KnownZero|KnownOne);

  // The minimum value is when all unknown bits are zeros, EXCEPT for the sign
  // bit if it is unknown.
  Min = KnownOne;
  Max = KnownOne|UnknownBits;
  
  if (UnknownBits.isNegative()) { // Sign bit is unknown
    Min.set(Min.getBitWidth()-1);
    Max.clear(Max.getBitWidth()-1);
  }
}

// ComputeUnsignedMinMaxValuesFromKnownBits - Given an unsigned integer type and
// a set of known zero and one bits, compute the maximum and minimum values that
// could have the specified known zero and known one bits, returning them in
// min/max.
static void ComputeUnsignedMinMaxValuesFromKnownBits(const APInt &KnownZero,
                                                     const APInt &KnownOne,
                                                     APInt &Min, APInt &Max) {
  assert(KnownZero.getBitWidth() == KnownOne.getBitWidth() &&
         KnownZero.getBitWidth() == Min.getBitWidth() &&
         KnownZero.getBitWidth() == Max.getBitWidth() &&
         "Ty, KnownZero, KnownOne and Min, Max must have equal bitwidth.");
  APInt UnknownBits = ~(KnownZero|KnownOne);
  
  // The minimum value is when the unknown bits are all zeros.
  Min = KnownOne;
  // The maximum value is when the unknown bits are all ones.
  Max = KnownOne|UnknownBits;
}



/// FoldCmpLoadFromIndexedGlobal - Called we see this pattern:
///   cmp pred (load (gep GV, ...)), cmpcst
/// where GV is a global variable with a constant initializer.  Try to simplify
/// this into some simple computation that does not need the load.  For example
/// we can optimize "icmp eq (load (gep "foo", 0, i)), 0" into "icmp eq i, 3".
///
/// If AndCst is non-null, then the loaded value is masked with that constant
/// before doing the comparison.  This handles cases like "A[i]&4 == 0".
Instruction *InstCombiner::
FoldCmpLoadFromIndexedGlobal(GetElementPtrInst *GEP, GlobalVariable *GV,
                             CmpInst &ICI, ConstantInt *AndCst) {
  // We need TD information to know the pointer size unless this is inbounds.
  if (!GEP->isInBounds() && TD == 0) return 0;
  
  ConstantArray *Init = dyn_cast<ConstantArray>(GV->getInitializer());
  if (Init == 0 || Init->getNumOperands() > 1024) return 0;
  
  // There are many forms of this optimization we can handle, for now, just do
  // the simple index into a single-dimensional array.
  //
  // Require: GEP GV, 0, i {{, constant indices}}
  if (GEP->getNumOperands() < 3 ||
      !isa<ConstantInt>(GEP->getOperand(1)) ||
      !cast<ConstantInt>(GEP->getOperand(1))->isZero() ||
      isa<Constant>(GEP->getOperand(2)))
    return 0;

  // Check that indices after the variable are constants and in-range for the
  // type they index.  Collect the indices.  This is typically for arrays of
  // structs.
  SmallVector<unsigned, 4> LaterIndices;
  
  const Type *EltTy = cast<ArrayType>(Init->getType())->getElementType();
  for (unsigned i = 3, e = GEP->getNumOperands(); i != e; ++i) {
    ConstantInt *Idx = dyn_cast<ConstantInt>(GEP->getOperand(i));
    if (Idx == 0) return 0;  // Variable index.
    
    uint64_t IdxVal = Idx->getZExtValue();
    if ((unsigned)IdxVal != IdxVal) return 0; // Too large array index.
    
    if (const StructType *STy = dyn_cast<StructType>(EltTy))
      EltTy = STy->getElementType(IdxVal);
    else if (const ArrayType *ATy = dyn_cast<ArrayType>(EltTy)) {
      if (IdxVal >= ATy->getNumElements()) return 0;
      EltTy = ATy->getElementType();
    } else {
      return 0; // Unknown type.
    }
    
    LaterIndices.push_back(IdxVal);
  }
  
  enum { Overdefined = -3, Undefined = -2 };

  // Variables for our state machines.
  
  // FirstTrueElement/SecondTrueElement - Used to emit a comparison of the form
  // "i == 47 | i == 87", where 47 is the first index the condition is true for,
  // and 87 is the second (and last) index.  FirstTrueElement is -2 when
  // undefined, otherwise set to the first true element.  SecondTrueElement is
  // -2 when undefined, -3 when overdefined and >= 0 when that index is true.
  int FirstTrueElement = Undefined, SecondTrueElement = Undefined;

  // FirstFalseElement/SecondFalseElement - Used to emit a comparison of the
  // form "i != 47 & i != 87".  Same state transitions as for true elements.
  int FirstFalseElement = Undefined, SecondFalseElement = Undefined;
  
  /// TrueRangeEnd/FalseRangeEnd - In conjunction with First*Element, these
  /// define a state machine that triggers for ranges of values that the index
  /// is true or false for.  This triggers on things like "abbbbc"[i] == 'b'.
  /// This is -2 when undefined, -3 when overdefined, and otherwise the last
  /// index in the range (inclusive).  We use -2 for undefined here because we
  /// use relative comparisons and don't want 0-1 to match -1.
  int TrueRangeEnd = Undefined, FalseRangeEnd = Undefined;
  
  // MagicBitvector - This is a magic bitvector where we set a bit if the
  // comparison is true for element 'i'.  If there are 64 elements or less in
  // the array, this will fully represent all the comparison results.
  uint64_t MagicBitvector = 0;
  
  
  // Scan the array and see if one of our patterns matches.
  Constant *CompareRHS = cast<Constant>(ICI.getOperand(1));
  for (unsigned i = 0, e = Init->getNumOperands(); i != e; ++i) {
    Constant *Elt = Init->getOperand(i);
    
    // If this is indexing an array of structures, get the structure element.
    if (!LaterIndices.empty())
      Elt = ConstantExpr::getExtractValue(Elt, LaterIndices.data(),
                                          LaterIndices.size());
    
    // If the element is masked, handle it.
    if (AndCst) Elt = ConstantExpr::getAnd(Elt, AndCst);
    
    // Find out if the comparison would be true or false for the i'th element.
    Constant *C = ConstantFoldCompareInstOperands(ICI.getPredicate(), Elt,
                                                  CompareRHS, TD);
    // If the result is undef for this element, ignore it.
    if (isa<UndefValue>(C)) {
      // Extend range state machines to cover this element in case there is an
      // undef in the middle of the range.
      if (TrueRangeEnd == (int)i-1)
        TrueRangeEnd = i;
      if (FalseRangeEnd == (int)i-1)
        FalseRangeEnd = i;
      continue;
    }
    
    // If we can't compute the result for any of the elements, we have to give
    // up evaluating the entire conditional.
    if (!isa<ConstantInt>(C)) return 0;
    
    // Otherwise, we know if the comparison is true or false for this element,
    // update our state machines.
    bool IsTrueForElt = !cast<ConstantInt>(C)->isZero();
    
    // State machine for single/double/range index comparison.
    if (IsTrueForElt) {
      // Update the TrueElement state machine.
      if (FirstTrueElement == Undefined)
        FirstTrueElement = TrueRangeEnd = i;  // First true element.
      else {
        // Update double-compare state machine.
        if (SecondTrueElement == Undefined)
          SecondTrueElement = i;
        else
          SecondTrueElement = Overdefined;
        
        // Update range state machine.
        if (TrueRangeEnd == (int)i-1)
          TrueRangeEnd = i;
        else
          TrueRangeEnd = Overdefined;
      }
    } else {
      // Update the FalseElement state machine.
      if (FirstFalseElement == Undefined)
        FirstFalseElement = FalseRangeEnd = i; // First false element.
      else {
        // Update double-compare state machine.
        if (SecondFalseElement == Undefined)
          SecondFalseElement = i;
        else
          SecondFalseElement = Overdefined;
        
        // Update range state machine.
        if (FalseRangeEnd == (int)i-1)
          FalseRangeEnd = i;
        else
          FalseRangeEnd = Overdefined;
      }
    }
    
    
    // If this element is in range, update our magic bitvector.
    if (i < 64 && IsTrueForElt)
      MagicBitvector |= 1ULL << i;
    
    // If all of our states become overdefined, bail out early.  Since the
    // predicate is expensive, only check it every 8 elements.  This is only
    // really useful for really huge arrays.
    if ((i & 8) == 0 && i >= 64 && SecondTrueElement == Overdefined &&
        SecondFalseElement == Overdefined && TrueRangeEnd == Overdefined &&
        FalseRangeEnd == Overdefined)
      return 0;
  }

  // Now that we've scanned the entire array, emit our new comparison(s).  We
  // order the state machines in complexity of the generated code.
  Value *Idx = GEP->getOperand(2);

  // If the index is larger than the pointer size of the target, truncate the
  // index down like the GEP would do implicitly.  We don't have to do this for
  // an inbounds GEP because the index can't be out of range.
  if (!GEP->isInBounds() &&
      Idx->getType()->getPrimitiveSizeInBits() > TD->getPointerSizeInBits())
    Idx = Builder->CreateTrunc(Idx, TD->getIntPtrType(Idx->getContext()));
  
  // If the comparison is only true for one or two elements, emit direct
  // comparisons.
  if (SecondTrueElement != Overdefined) {
    // None true -> false.
    if (FirstTrueElement == Undefined)
      return ReplaceInstUsesWith(ICI, ConstantInt::getFalse(GEP->getContext()));
    
    Value *FirstTrueIdx = ConstantInt::get(Idx->getType(), FirstTrueElement);
    
    // True for one element -> 'i == 47'.
    if (SecondTrueElement == Undefined)
      return new ICmpInst(ICmpInst::ICMP_EQ, Idx, FirstTrueIdx);
    
    // True for two elements -> 'i == 47 | i == 72'.
    Value *C1 = Builder->CreateICmpEQ(Idx, FirstTrueIdx);
    Value *SecondTrueIdx = ConstantInt::get(Idx->getType(), SecondTrueElement);
    Value *C2 = Builder->CreateICmpEQ(Idx, SecondTrueIdx);
    return BinaryOperator::CreateOr(C1, C2);
  }

  // If the comparison is only false for one or two elements, emit direct
  // comparisons.
  if (SecondFalseElement != Overdefined) {
    // None false -> true.
    if (FirstFalseElement == Undefined)
      return ReplaceInstUsesWith(ICI, ConstantInt::getTrue(GEP->getContext()));
    
    Value *FirstFalseIdx = ConstantInt::get(Idx->getType(), FirstFalseElement);

    // False for one element -> 'i != 47'.
    if (SecondFalseElement == Undefined)
      return new ICmpInst(ICmpInst::ICMP_NE, Idx, FirstFalseIdx);
     
    // False for two elements -> 'i != 47 & i != 72'.
    Value *C1 = Builder->CreateICmpNE(Idx, FirstFalseIdx);
    Value *SecondFalseIdx = ConstantInt::get(Idx->getType(),SecondFalseElement);
    Value *C2 = Builder->CreateICmpNE(Idx, SecondFalseIdx);
    return BinaryOperator::CreateAnd(C1, C2);
  }
  
  // If the comparison can be replaced with a range comparison for the elements
  // where it is true, emit the range check.
  if (TrueRangeEnd != Overdefined) {
    assert(TrueRangeEnd != FirstTrueElement && "Should emit single compare");
    
    // Generate (i-FirstTrue) <u (TrueRangeEnd-FirstTrue+1).
    if (FirstTrueElement) {
      Value *Offs = ConstantInt::get(Idx->getType(), -FirstTrueElement);
      Idx = Builder->CreateAdd(Idx, Offs);
    }
    
    Value *End = ConstantInt::get(Idx->getType(),
                                  TrueRangeEnd-FirstTrueElement+1);
    return new ICmpInst(ICmpInst::ICMP_ULT, Idx, End);
  }
  
  // False range check.
  if (FalseRangeEnd != Overdefined) {
    assert(FalseRangeEnd != FirstFalseElement && "Should emit single compare");
    // Generate (i-FirstFalse) >u (FalseRangeEnd-FirstFalse).
    if (FirstFalseElement) {
      Value *Offs = ConstantInt::get(Idx->getType(), -FirstFalseElement);
      Idx = Builder->CreateAdd(Idx, Offs);
    }
    
    Value *End = ConstantInt::get(Idx->getType(),
                                  FalseRangeEnd-FirstFalseElement);
    return new ICmpInst(ICmpInst::ICMP_UGT, Idx, End);
  }
  
  
  // If a 32-bit or 64-bit magic bitvector captures the entire comparison state
  // of this load, replace it with computation that does:
  //   ((magic_cst >> i) & 1) != 0
  if (Init->getNumOperands() <= 32 ||
      (TD && Init->getNumOperands() <= 64 && TD->isLegalInteger(64))) {
    const Type *Ty;
    if (Init->getNumOperands() <= 32)
      Ty = Type::getInt32Ty(Init->getContext());
    else
      Ty = Type::getInt64Ty(Init->getContext());
    Value *V = Builder->CreateIntCast(Idx, Ty, false);
    V = Builder->CreateLShr(ConstantInt::get(Ty, MagicBitvector), V);
    V = Builder->CreateAnd(ConstantInt::get(Ty, 1), V);
    return new ICmpInst(ICmpInst::ICMP_NE, V, ConstantInt::get(Ty, 0));
  }
  
  return 0;
}


/// EvaluateGEPOffsetExpression - Return a value that can be used to compare
/// the *offset* implied by a GEP to zero.  For example, if we have &A[i], we
/// want to return 'i' for "icmp ne i, 0".  Note that, in general, indices can
/// be complex, and scales are involved.  The above expression would also be
/// legal to codegen as "icmp ne (i*4), 0" (assuming A is a pointer to i32).
/// This later form is less amenable to optimization though, and we are allowed
/// to generate the first by knowing that pointer arithmetic doesn't overflow.
///
/// If we can't emit an optimized form for this expression, this returns null.
/// 
static Value *EvaluateGEPOffsetExpression(User *GEP, Instruction &I,
                                          InstCombiner &IC) {
  TargetData &TD = *IC.getTargetData();
  gep_type_iterator GTI = gep_type_begin(GEP);
  
  // Check to see if this gep only has a single variable index.  If so, and if
  // any constant indices are a multiple of its scale, then we can compute this
  // in terms of the scale of the variable index.  For example, if the GEP
  // implies an offset of "12 + i*4", then we can codegen this as "3 + i",
  // because the expression will cross zero at the same point.
  unsigned i, e = GEP->getNumOperands();
  int64_t Offset = 0;
  for (i = 1; i != e; ++i, ++GTI) {
    if (ConstantInt *CI = dyn_cast<ConstantInt>(GEP->getOperand(i))) {
      // Compute the aggregate offset of constant indices.
      if (CI->isZero()) continue;
      
      // Handle a struct index, which adds its field offset to the pointer.
      if (const StructType *STy = dyn_cast<StructType>(*GTI)) {
        Offset += TD.getStructLayout(STy)->getElementOffset(CI->getZExtValue());
      } else {
        uint64_t Size = TD.getTypeAllocSize(GTI.getIndexedType());
        Offset += Size*CI->getSExtValue();
      }
    } else {
      // Found our variable index.
      break;
    }
  }
  
  // If there are no variable indices, we must have a constant offset, just
  // evaluate it the general way.
  if (i == e) return 0;
  
  Value *VariableIdx = GEP->getOperand(i);
  // Determine the scale factor of the variable element.  For example, this is
  // 4 if the variable index is into an array of i32.
  uint64_t VariableScale = TD.getTypeAllocSize(GTI.getIndexedType());
  
  // Verify that there are no other variable indices.  If so, emit the hard way.
  for (++i, ++GTI; i != e; ++i, ++GTI) {
    ConstantInt *CI = dyn_cast<ConstantInt>(GEP->getOperand(i));
    if (!CI) return 0;
    
    // Compute the aggregate offset of constant indices.
    if (CI->isZero()) continue;
    
    // Handle a struct index, which adds its field offset to the pointer.
    if (const StructType *STy = dyn_cast<StructType>(*GTI)) {
      Offset += TD.getStructLayout(STy)->getElementOffset(CI->getZExtValue());
    } else {
      uint64_t Size = TD.getTypeAllocSize(GTI.getIndexedType());
      Offset += Size*CI->getSExtValue();
    }
  }
  
  // Okay, we know we have a single variable index, which must be a
  // pointer/array/vector index.  If there is no offset, life is simple, return
  // the index.
  unsigned IntPtrWidth = TD.getPointerSizeInBits();
  if (Offset == 0) {
    // Cast to intptrty in case a truncation occurs.  If an extension is needed,
    // we don't need to bother extending: the extension won't affect where the
    // computation crosses zero.
    if (VariableIdx->getType()->getPrimitiveSizeInBits() > IntPtrWidth)
      VariableIdx = new TruncInst(VariableIdx, 
                                  TD.getIntPtrType(VariableIdx->getContext()),
                                  VariableIdx->getName(), &I);
    return VariableIdx;
  }
  
  // Otherwise, there is an index.  The computation we will do will be modulo
  // the pointer size, so get it.
  uint64_t PtrSizeMask = ~0ULL >> (64-IntPtrWidth);
  
  Offset &= PtrSizeMask;
  VariableScale &= PtrSizeMask;
  
  // To do this transformation, any constant index must be a multiple of the
  // variable scale factor.  For example, we can evaluate "12 + 4*i" as "3 + i",
  // but we can't evaluate "10 + 3*i" in terms of i.  Check that the offset is a
  // multiple of the variable scale.
  int64_t NewOffs = Offset / (int64_t)VariableScale;
  if (Offset != NewOffs*(int64_t)VariableScale)
    return 0;
  
  // Okay, we can do this evaluation.  Start by converting the index to intptr.
  const Type *IntPtrTy = TD.getIntPtrType(VariableIdx->getContext());
  if (VariableIdx->getType() != IntPtrTy)
    VariableIdx = CastInst::CreateIntegerCast(VariableIdx, IntPtrTy,
                                              true /*SExt*/, 
                                              VariableIdx->getName(), &I);
  Constant *OffsetVal = ConstantInt::get(IntPtrTy, NewOffs);
  return BinaryOperator::CreateAdd(VariableIdx, OffsetVal, "offset", &I);
}

/// FoldGEPICmp - Fold comparisons between a GEP instruction and something
/// else.  At this point we know that the GEP is on the LHS of the comparison.
Instruction *InstCombiner::FoldGEPICmp(GEPOperator *GEPLHS, Value *RHS,
                                       ICmpInst::Predicate Cond,
                                       Instruction &I) {
  // Look through bitcasts.
  if (BitCastInst *BCI = dyn_cast<BitCastInst>(RHS))
    RHS = BCI->getOperand(0);

  Value *PtrBase = GEPLHS->getOperand(0);
  if (TD && PtrBase == RHS && GEPLHS->isInBounds()) {
    // ((gep Ptr, OFFSET) cmp Ptr)   ---> (OFFSET cmp 0).
    // This transformation (ignoring the base and scales) is valid because we
    // know pointers can't overflow since the gep is inbounds.  See if we can
    // output an optimized form.
    Value *Offset = EvaluateGEPOffsetExpression(GEPLHS, I, *this);
    
    // If not, synthesize the offset the hard way.
    if (Offset == 0)
      Offset = EmitGEPOffset(GEPLHS);
    return new ICmpInst(ICmpInst::getSignedPredicate(Cond), Offset,
                        Constant::getNullValue(Offset->getType()));
  } else if (GEPOperator *GEPRHS = dyn_cast<GEPOperator>(RHS)) {
    // If the base pointers are different, but the indices are the same, just
    // compare the base pointer.
    if (PtrBase != GEPRHS->getOperand(0)) {
      bool IndicesTheSame = GEPLHS->getNumOperands()==GEPRHS->getNumOperands();
      IndicesTheSame &= GEPLHS->getOperand(0)->getType() ==
                        GEPRHS->getOperand(0)->getType();
      if (IndicesTheSame)
        for (unsigned i = 1, e = GEPLHS->getNumOperands(); i != e; ++i)
          if (GEPLHS->getOperand(i) != GEPRHS->getOperand(i)) {
            IndicesTheSame = false;
            break;
          }

      // If all indices are the same, just compare the base pointers.
      if (IndicesTheSame)
        return new ICmpInst(ICmpInst::getSignedPredicate(Cond),
                            GEPLHS->getOperand(0), GEPRHS->getOperand(0));

      // Otherwise, the base pointers are different and the indices are
      // different, bail out.
      return 0;
    }

    // If one of the GEPs has all zero indices, recurse.
    bool AllZeros = true;
    for (unsigned i = 1, e = GEPLHS->getNumOperands(); i != e; ++i)
      if (!isa<Constant>(GEPLHS->getOperand(i)) ||
          !cast<Constant>(GEPLHS->getOperand(i))->isNullValue()) {
        AllZeros = false;
        break;
      }
    if (AllZeros)
      return FoldGEPICmp(GEPRHS, GEPLHS->getOperand(0),
                          ICmpInst::getSwappedPredicate(Cond), I);

    // If the other GEP has all zero indices, recurse.
    AllZeros = true;
    for (unsigned i = 1, e = GEPRHS->getNumOperands(); i != e; ++i)
      if (!isa<Constant>(GEPRHS->getOperand(i)) ||
          !cast<Constant>(GEPRHS->getOperand(i))->isNullValue()) {
        AllZeros = false;
        break;
      }
    if (AllZeros)
      return FoldGEPICmp(GEPLHS, GEPRHS->getOperand(0), Cond, I);

    if (GEPLHS->getNumOperands() == GEPRHS->getNumOperands()) {
      // If the GEPs only differ by one index, compare it.
      unsigned NumDifferences = 0;  // Keep track of # differences.
      unsigned DiffOperand = 0;     // The operand that differs.
      for (unsigned i = 1, e = GEPRHS->getNumOperands(); i != e; ++i)
        if (GEPLHS->getOperand(i) != GEPRHS->getOperand(i)) {
          if (GEPLHS->getOperand(i)->getType()->getPrimitiveSizeInBits() !=
                   GEPRHS->getOperand(i)->getType()->getPrimitiveSizeInBits()) {
            // Irreconcilable differences.
            NumDifferences = 2;
            break;
          } else {
            if (NumDifferences++) break;
            DiffOperand = i;
          }
        }

      if (NumDifferences == 0)   // SAME GEP?
        return ReplaceInstUsesWith(I, // No comparison is needed here.
                               ConstantInt::get(Type::getInt1Ty(I.getContext()),
                                             ICmpInst::isTrueWhenEqual(Cond)));

      else if (NumDifferences == 1) {
        Value *LHSV = GEPLHS->getOperand(DiffOperand);
        Value *RHSV = GEPRHS->getOperand(DiffOperand);
        // Make sure we do a signed comparison here.
        return new ICmpInst(ICmpInst::getSignedPredicate(Cond), LHSV, RHSV);
      }
    }

    // Only lower this if the icmp is the only user of the GEP or if we expect
    // the result to fold to a constant!
    if (TD &&
        (isa<ConstantExpr>(GEPLHS) || GEPLHS->hasOneUse()) &&
        (isa<ConstantExpr>(GEPRHS) || GEPRHS->hasOneUse())) {
      // ((gep Ptr, OFFSET1) cmp (gep Ptr, OFFSET2)  --->  (OFFSET1 cmp OFFSET2)
      Value *L = EmitGEPOffset(GEPLHS);
      Value *R = EmitGEPOffset(GEPRHS);
      return new ICmpInst(ICmpInst::getSignedPredicate(Cond), L, R);
    }
  }
  return 0;
}

/// FoldICmpAddOpCst - Fold "icmp pred (X+CI), X".
Instruction *InstCombiner::FoldICmpAddOpCst(ICmpInst &ICI,
                                            Value *X, ConstantInt *CI,
                                            ICmpInst::Predicate Pred,
                                            Value *TheAdd) {
  // If we have X+0, exit early (simplifying logic below) and let it get folded
  // elsewhere.   icmp X+0, X  -> icmp X, X
  if (CI->isZero()) {
    bool isTrue = ICmpInst::isTrueWhenEqual(Pred);
    return ReplaceInstUsesWith(ICI, ConstantInt::get(ICI.getType(), isTrue));
  }
  
  // (X+4) == X -> false.
  if (Pred == ICmpInst::ICMP_EQ)
    return ReplaceInstUsesWith(ICI, ConstantInt::getFalse(X->getContext()));

  // (X+4) != X -> true.
  if (Pred == ICmpInst::ICMP_NE)
    return ReplaceInstUsesWith(ICI, ConstantInt::getTrue(X->getContext()));

  // If this is an instruction (as opposed to constantexpr) get NUW/NSW info.
  bool isNUW = false, isNSW = false;
  if (BinaryOperator *Add = dyn_cast<BinaryOperator>(TheAdd)) {
    isNUW = Add->hasNoUnsignedWrap();
    isNSW = Add->hasNoSignedWrap();
  }      
  
  // From this point on, we know that (X+C <= X) --> (X+C < X) because C != 0,
  // so the values can never be equal.  Similiarly for all other "or equals"
  // operators.
  
  // (X+1) <u X        --> X >u (MAXUINT-1)        --> X != 255
  // (X+2) <u X        --> X >u (MAXUINT-2)        --> X > 253
  // (X+MAXUINT) <u X  --> X >u (MAXUINT-MAXUINT)  --> X != 0
  if (Pred == ICmpInst::ICMP_ULT || Pred == ICmpInst::ICMP_ULE) {
    // If this is an NUW add, then this is always false.
    if (isNUW)
      return ReplaceInstUsesWith(ICI, ConstantInt::getFalse(X->getContext())); 
    
    Value *R = ConstantExpr::getSub(ConstantInt::get(CI->getType(), -1ULL), CI);
    return new ICmpInst(ICmpInst::ICMP_UGT, X, R);
  }
  
  // (X+1) >u X        --> X <u (0-1)        --> X != 255
  // (X+2) >u X        --> X <u (0-2)        --> X <u 254
  // (X+MAXUINT) >u X  --> X <u (0-MAXUINT)  --> X <u 1  --> X == 0
  if (Pred == ICmpInst::ICMP_UGT || Pred == ICmpInst::ICMP_UGE) {
    // If this is an NUW add, then this is always true.
    if (isNUW)
      return ReplaceInstUsesWith(ICI, ConstantInt::getTrue(X->getContext())); 
    return new ICmpInst(ICmpInst::ICMP_ULT, X, ConstantExpr::getNeg(CI));
  }
  
  unsigned BitWidth = CI->getType()->getPrimitiveSizeInBits();
  ConstantInt *SMax = ConstantInt::get(X->getContext(),
                                       APInt::getSignedMaxValue(BitWidth));

  // (X+ 1) <s X       --> X >s (MAXSINT-1)          --> X == 127
  // (X+ 2) <s X       --> X >s (MAXSINT-2)          --> X >s 125
  // (X+MAXSINT) <s X  --> X >s (MAXSINT-MAXSINT)    --> X >s 0
  // (X+MINSINT) <s X  --> X >s (MAXSINT-MINSINT)    --> X >s -1
  // (X+ -2) <s X      --> X >s (MAXSINT- -2)        --> X >s 126
  // (X+ -1) <s X      --> X >s (MAXSINT- -1)        --> X != 127
  if (Pred == ICmpInst::ICMP_SLT || Pred == ICmpInst::ICMP_SLE) {
    // If this is an NSW add, then we have two cases: if the constant is
    // positive, then this is always false, if negative, this is always true.
    if (isNSW) {
      bool isTrue = CI->getValue().isNegative();
      return ReplaceInstUsesWith(ICI, ConstantInt::get(ICI.getType(), isTrue));
    }
    
    return new ICmpInst(ICmpInst::ICMP_SGT, X, ConstantExpr::getSub(SMax, CI));
  }
  
  // (X+ 1) >s X       --> X <s (MAXSINT-(1-1))       --> X != 127
  // (X+ 2) >s X       --> X <s (MAXSINT-(2-1))       --> X <s 126
  // (X+MAXSINT) >s X  --> X <s (MAXSINT-(MAXSINT-1)) --> X <s 1
  // (X+MINSINT) >s X  --> X <s (MAXSINT-(MINSINT-1)) --> X <s -2
  // (X+ -2) >s X      --> X <s (MAXSINT-(-2-1))      --> X <s -126
  // (X+ -1) >s X      --> X <s (MAXSINT-(-1-1))      --> X == -128
  
  // If this is an NSW add, then we have two cases: if the constant is
  // positive, then this is always true, if negative, this is always false.
  if (isNSW) {
    bool isTrue = !CI->getValue().isNegative();
    return ReplaceInstUsesWith(ICI, ConstantInt::get(ICI.getType(), isTrue));
  }
  
  assert(Pred == ICmpInst::ICMP_SGT || Pred == ICmpInst::ICMP_SGE);
  Constant *C = ConstantInt::get(X->getContext(), CI->getValue()-1);
  return new ICmpInst(ICmpInst::ICMP_SLT, X, ConstantExpr::getSub(SMax, C));
}

/// FoldICmpDivCst - Fold "icmp pred, ([su]div X, DivRHS), CmpRHS" where DivRHS
/// and CmpRHS are both known to be integer constants.
Instruction *InstCombiner::FoldICmpDivCst(ICmpInst &ICI, BinaryOperator *DivI,
                                          ConstantInt *DivRHS) {
  ConstantInt *CmpRHS = cast<ConstantInt>(ICI.getOperand(1));
  const APInt &CmpRHSV = CmpRHS->getValue();
  
  // FIXME: If the operand types don't match the type of the divide 
  // then don't attempt this transform. The code below doesn't have the
  // logic to deal with a signed divide and an unsigned compare (and
  // vice versa). This is because (x /s C1) <s C2  produces different 
  // results than (x /s C1) <u C2 or (x /u C1) <s C2 or even
  // (x /u C1) <u C2.  Simply casting the operands and result won't 
  // work. :(  The if statement below tests that condition and bails 
  // if it finds it. 
  bool DivIsSigned = DivI->getOpcode() == Instruction::SDiv;
  if (!ICI.isEquality() && DivIsSigned != ICI.isSigned())
    return 0;
  if (DivRHS->isZero())
    return 0; // The ProdOV computation fails on divide by zero.
  if (DivIsSigned && DivRHS->isAllOnesValue())
    return 0; // The overflow computation also screws up here
  if (DivRHS->isOne())
    return 0; // Not worth bothering, and eliminates some funny cases
              // with INT_MIN.

  // Compute Prod = CI * DivRHS. We are essentially solving an equation
  // of form X/C1=C2. We solve for X by multiplying C1 (DivRHS) and 
  // C2 (CI). By solving for X we can turn this into a range check 
  // instead of computing a divide. 
  Constant *Prod = ConstantExpr::getMul(CmpRHS, DivRHS);

  // Determine if the product overflows by seeing if the product is
  // not equal to the divide. Make sure we do the same kind of divide
  // as in the LHS instruction that we're folding. 
  bool ProdOV = (DivIsSigned ? ConstantExpr::getSDiv(Prod, DivRHS) :
                 ConstantExpr::getUDiv(Prod, DivRHS)) != CmpRHS;

  // Get the ICmp opcode
  ICmpInst::Predicate Pred = ICI.getPredicate();

  // Figure out the interval that is being checked.  For example, a comparison
  // like "X /u 5 == 0" is really checking that X is in the interval [0, 5). 
  // Compute this interval based on the constants involved and the signedness of
  // the compare/divide.  This computes a half-open interval, keeping track of
  // whether either value in the interval overflows.  After analysis each
  // overflow variable is set to 0 if it's corresponding bound variable is valid
  // -1 if overflowed off the bottom end, or +1 if overflowed off the top end.
  int LoOverflow = 0, HiOverflow = 0;
  Constant *LoBound = 0, *HiBound = 0;
  
  if (!DivIsSigned) {  // udiv
    // e.g. X/5 op 3  --> [15, 20)
    LoBound = Prod;
    HiOverflow = LoOverflow = ProdOV;
    if (!HiOverflow)
      HiOverflow = AddWithOverflow(HiBound, LoBound, DivRHS, false);
  } else if (DivRHS->getValue().isStrictlyPositive()) { // Divisor is > 0.
    if (CmpRHSV == 0) {       // (X / pos) op 0
      // Can't overflow.  e.g.  X/2 op 0 --> [-1, 2)
      LoBound = cast<ConstantInt>(ConstantExpr::getNeg(SubOne(DivRHS)));
      HiBound = DivRHS;
    } else if (CmpRHSV.isStrictlyPositive()) {   // (X / pos) op pos
      LoBound = Prod;     // e.g.   X/5 op 3 --> [15, 20)
      HiOverflow = LoOverflow = ProdOV;
      if (!HiOverflow)
        HiOverflow = AddWithOverflow(HiBound, Prod, DivRHS, true);
    } else {                       // (X / pos) op neg
      // e.g. X/5 op -3  --> [-15-4, -15+1) --> [-19, -14)
      HiBound = AddOne(Prod);
      LoOverflow = HiOverflow = ProdOV ? -1 : 0;
      if (!LoOverflow) {
        ConstantInt* DivNeg =
                         cast<ConstantInt>(ConstantExpr::getNeg(DivRHS));
        LoOverflow = AddWithOverflow(LoBound, HiBound, DivNeg, true) ? -1 : 0;
       }
    }
  } else if (DivRHS->getValue().isNegative()) { // Divisor is < 0.
    if (CmpRHSV == 0) {       // (X / neg) op 0
      // e.g. X/-5 op 0  --> [-4, 5)
      LoBound = AddOne(DivRHS);
      HiBound = cast<ConstantInt>(ConstantExpr::getNeg(DivRHS));
      if (HiBound == DivRHS) {     // -INTMIN = INTMIN
        HiOverflow = 1;            // [INTMIN+1, overflow)
        HiBound = 0;               // e.g. X/INTMIN = 0 --> X > INTMIN
      }
    } else if (CmpRHSV.isStrictlyPositive()) {   // (X / neg) op pos
      // e.g. X/-5 op 3  --> [-19, -14)
      HiBound = AddOne(Prod);
      HiOverflow = LoOverflow = ProdOV ? -1 : 0;
      if (!LoOverflow)
        LoOverflow = AddWithOverflow(LoBound, HiBound, DivRHS, true) ? -1 : 0;
    } else {                       // (X / neg) op neg
      LoBound = Prod;       // e.g. X/-5 op -3  --> [15, 20)
      LoOverflow = HiOverflow = ProdOV;
      if (!HiOverflow)
        HiOverflow = SubWithOverflow(HiBound, Prod, DivRHS, true);
    }
    
    // Dividing by a negative swaps the condition.  LT <-> GT
    Pred = ICmpInst::getSwappedPredicate(Pred);
  }

  Value *X = DivI->getOperand(0);
  switch (Pred) {
  default: llvm_unreachable("Unhandled icmp opcode!");
  case ICmpInst::ICMP_EQ:
    if (LoOverflow && HiOverflow)
      return ReplaceInstUsesWith(ICI, ConstantInt::getFalse(ICI.getContext()));
    else if (HiOverflow)
      return new ICmpInst(DivIsSigned ? ICmpInst::ICMP_SGE :
                          ICmpInst::ICMP_UGE, X, LoBound);
    else if (LoOverflow)
      return new ICmpInst(DivIsSigned ? ICmpInst::ICMP_SLT :
                          ICmpInst::ICMP_ULT, X, HiBound);
    else
      return InsertRangeTest(X, LoBound, HiBound, DivIsSigned, true, ICI);
  case ICmpInst::ICMP_NE:
    if (LoOverflow && HiOverflow)
      return ReplaceInstUsesWith(ICI, ConstantInt::getTrue(ICI.getContext()));
    else if (HiOverflow)
      return new ICmpInst(DivIsSigned ? ICmpInst::ICMP_SLT :
                          ICmpInst::ICMP_ULT, X, LoBound);
    else if (LoOverflow)
      return new ICmpInst(DivIsSigned ? ICmpInst::ICMP_SGE :
                          ICmpInst::ICMP_UGE, X, HiBound);
    else
      return InsertRangeTest(X, LoBound, HiBound, DivIsSigned, false, ICI);
  case ICmpInst::ICMP_ULT:
  case ICmpInst::ICMP_SLT:
    if (LoOverflow == +1)   // Low bound is greater than input range.
      return ReplaceInstUsesWith(ICI, ConstantInt::getTrue(ICI.getContext()));
    if (LoOverflow == -1)   // Low bound is less than input range.
      return ReplaceInstUsesWith(ICI, ConstantInt::getFalse(ICI.getContext()));
    return new ICmpInst(Pred, X, LoBound);
  case ICmpInst::ICMP_UGT:
  case ICmpInst::ICMP_SGT:
    if (HiOverflow == +1)       // High bound greater than input range.
      return ReplaceInstUsesWith(ICI, ConstantInt::getFalse(ICI.getContext()));
    else if (HiOverflow == -1)  // High bound less than input range.
      return ReplaceInstUsesWith(ICI, ConstantInt::getTrue(ICI.getContext()));
    if (Pred == ICmpInst::ICMP_UGT)
      return new ICmpInst(ICmpInst::ICMP_UGE, X, HiBound);
    else
      return new ICmpInst(ICmpInst::ICMP_SGE, X, HiBound);
  }
}


/// visitICmpInstWithInstAndIntCst - Handle "icmp (instr, intcst)".
///
Instruction *InstCombiner::visitICmpInstWithInstAndIntCst(ICmpInst &ICI,
                                                          Instruction *LHSI,
                                                          ConstantInt *RHS) {
  const APInt &RHSV = RHS->getValue();
  
  switch (LHSI->getOpcode()) {
  case Instruction::Trunc:
    if (ICI.isEquality() && LHSI->hasOneUse()) {
      // Simplify icmp eq (trunc x to i8), 42 -> icmp eq x, 42|highbits if all
      // of the high bits truncated out of x are known.
      unsigned DstBits = LHSI->getType()->getPrimitiveSizeInBits(),
             SrcBits = LHSI->getOperand(0)->getType()->getPrimitiveSizeInBits();
      APInt Mask(APInt::getHighBitsSet(SrcBits, SrcBits-DstBits));
      APInt KnownZero(SrcBits, 0), KnownOne(SrcBits, 0);
      ComputeMaskedBits(LHSI->getOperand(0), Mask, KnownZero, KnownOne);
      
      // If all the high bits are known, we can do this xform.
      if ((KnownZero|KnownOne).countLeadingOnes() >= SrcBits-DstBits) {
        // Pull in the high bits from known-ones set.
        APInt NewRHS(RHS->getValue());
        NewRHS.zext(SrcBits);
        NewRHS |= KnownOne;
        return new ICmpInst(ICI.getPredicate(), LHSI->getOperand(0),
                            ConstantInt::get(ICI.getContext(), NewRHS));
      }
    }
    break;
      
  case Instruction::Xor:         // (icmp pred (xor X, XorCST), CI)
    if (ConstantInt *XorCST = dyn_cast<ConstantInt>(LHSI->getOperand(1))) {
      // If this is a comparison that tests the signbit (X < 0) or (x > -1),
      // fold the xor.
      if ((ICI.getPredicate() == ICmpInst::ICMP_SLT && RHSV == 0) ||
          (ICI.getPredicate() == ICmpInst::ICMP_SGT && RHSV.isAllOnesValue())) {
        Value *CompareVal = LHSI->getOperand(0);
        
        // If the sign bit of the XorCST is not set, there is no change to
        // the operation, just stop using the Xor.
        if (!XorCST->getValue().isNegative()) {
          ICI.setOperand(0, CompareVal);
          Worklist.Add(LHSI);
          return &ICI;
        }
        
        // Was the old condition true if the operand is positive?
        bool isTrueIfPositive = ICI.getPredicate() == ICmpInst::ICMP_SGT;
        
        // If so, the new one isn't.
        isTrueIfPositive ^= true;
        
        if (isTrueIfPositive)
          return new ICmpInst(ICmpInst::ICMP_SGT, CompareVal,
                              SubOne(RHS));
        else
          return new ICmpInst(ICmpInst::ICMP_SLT, CompareVal,
                              AddOne(RHS));
      }

      if (LHSI->hasOneUse()) {
        // (icmp u/s (xor A SignBit), C) -> (icmp s/u A, (xor C SignBit))
        if (!ICI.isEquality() && XorCST->getValue().isSignBit()) {
          const APInt &SignBit = XorCST->getValue();
          ICmpInst::Predicate Pred = ICI.isSigned()
                                         ? ICI.getUnsignedPredicate()
                                         : ICI.getSignedPredicate();
          return new ICmpInst(Pred, LHSI->getOperand(0),
                              ConstantInt::get(ICI.getContext(),
                                               RHSV ^ SignBit));
        }

        // (icmp u/s (xor A ~SignBit), C) -> (icmp s/u (xor C ~SignBit), A)
        if (!ICI.isEquality() && XorCST->getValue().isMaxSignedValue()) {
          const APInt &NotSignBit = XorCST->getValue();
          ICmpInst::Predicate Pred = ICI.isSigned()
                                         ? ICI.getUnsignedPredicate()
                                         : ICI.getSignedPredicate();
          Pred = ICI.getSwappedPredicate(Pred);
          return new ICmpInst(Pred, LHSI->getOperand(0),
                              ConstantInt::get(ICI.getContext(),
                                               RHSV ^ NotSignBit));
        }
      }
    }
    break;
  case Instruction::And:         // (icmp pred (and X, AndCST), RHS)
    if (LHSI->hasOneUse() && isa<ConstantInt>(LHSI->getOperand(1)) &&
        LHSI->getOperand(0)->hasOneUse()) {
      ConstantInt *AndCST = cast<ConstantInt>(LHSI->getOperand(1));
      
      // If the LHS is an AND of a truncating cast, we can widen the
      // and/compare to be the input width without changing the value
      // produced, eliminating a cast.
      if (TruncInst *Cast = dyn_cast<TruncInst>(LHSI->getOperand(0))) {
        // We can do this transformation if either the AND constant does not
        // have its sign bit set or if it is an equality comparison. 
        // Extending a relational comparison when we're checking the sign
        // bit would not work.
        if (Cast->hasOneUse() &&
            (ICI.isEquality() ||
             (AndCST->getValue().isNonNegative() && RHSV.isNonNegative()))) {
          uint32_t BitWidth = 
            cast<IntegerType>(Cast->getOperand(0)->getType())->getBitWidth();
          APInt NewCST = AndCST->getValue();
          NewCST.zext(BitWidth);
          APInt NewCI = RHSV;
          NewCI.zext(BitWidth);
          Value *NewAnd = 
            Builder->CreateAnd(Cast->getOperand(0),
                           ConstantInt::get(ICI.getContext(), NewCST),
                               LHSI->getName());
          return new ICmpInst(ICI.getPredicate(), NewAnd,
                              ConstantInt::get(ICI.getContext(), NewCI));
        }
      }
      
      // If this is: (X >> C1) & C2 != C3 (where any shift and any compare
      // could exist), turn it into (X & (C2 << C1)) != (C3 << C1).  This
      // happens a LOT in code produced by the C front-end, for bitfield
      // access.
      BinaryOperator *Shift = dyn_cast<BinaryOperator>(LHSI->getOperand(0));
      if (Shift && !Shift->isShift())
        Shift = 0;
      
      ConstantInt *ShAmt;
      ShAmt = Shift ? dyn_cast<ConstantInt>(Shift->getOperand(1)) : 0;
      const Type *Ty = Shift ? Shift->getType() : 0;  // Type of the shift.
      const Type *AndTy = AndCST->getType();          // Type of the and.
      
      // We can fold this as long as we can't shift unknown bits
      // into the mask.  This can only happen with signed shift
      // rights, as they sign-extend.
      if (ShAmt) {
        bool CanFold = Shift->isLogicalShift();
        if (!CanFold) {
          // To test for the bad case of the signed shr, see if any
          // of the bits shifted in could be tested after the mask.
          uint32_t TyBits = Ty->getPrimitiveSizeInBits();
          int ShAmtVal = TyBits - ShAmt->getLimitedValue(TyBits);
          
          uint32_t BitWidth = AndTy->getPrimitiveSizeInBits();
          if ((APInt::getHighBitsSet(BitWidth, BitWidth-ShAmtVal) & 
               AndCST->getValue()) == 0)
            CanFold = true;
        }
        
        if (CanFold) {
          Constant *NewCst;
          if (Shift->getOpcode() == Instruction::Shl)
            NewCst = ConstantExpr::getLShr(RHS, ShAmt);
          else
            NewCst = ConstantExpr::getShl(RHS, ShAmt);
          
          // Check to see if we are shifting out any of the bits being
          // compared.
          if (ConstantExpr::get(Shift->getOpcode(),
                                       NewCst, ShAmt) != RHS) {
            // If we shifted bits out, the fold is not going to work out.
            // As a special case, check to see if this means that the
            // result is always true or false now.
            if (ICI.getPredicate() == ICmpInst::ICMP_EQ)
              return ReplaceInstUsesWith(ICI,
                                       ConstantInt::getFalse(ICI.getContext()));
            if (ICI.getPredicate() == ICmpInst::ICMP_NE)
              return ReplaceInstUsesWith(ICI,
                                       ConstantInt::getTrue(ICI.getContext()));
          } else {
            ICI.setOperand(1, NewCst);
            Constant *NewAndCST;
            if (Shift->getOpcode() == Instruction::Shl)
              NewAndCST = ConstantExpr::getLShr(AndCST, ShAmt);
            else
              NewAndCST = ConstantExpr::getShl(AndCST, ShAmt);
            LHSI->setOperand(1, NewAndCST);
            LHSI->setOperand(0, Shift->getOperand(0));
            Worklist.Add(Shift); // Shift is dead.
            return &ICI;
          }
        }
      }
      
      // Turn ((X >> Y) & C) == 0  into  (X & (C << Y)) == 0.  The later is
      // preferable because it allows the C<<Y expression to be hoisted out
      // of a loop if Y is invariant and X is not.
      if (Shift && Shift->hasOneUse() && RHSV == 0 &&
          ICI.isEquality() && !Shift->isArithmeticShift() &&
          !isa<Constant>(Shift->getOperand(0))) {
        // Compute C << Y.
        Value *NS;
        if (Shift->getOpcode() == Instruction::LShr) {
          NS = Builder->CreateShl(AndCST, Shift->getOperand(1), "tmp");
        } else {
          // Insert a logical shift.
          NS = Builder->CreateLShr(AndCST, Shift->getOperand(1), "tmp");
        }
        
        // Compute X & (C << Y).
        Value *NewAnd = 
          Builder->CreateAnd(Shift->getOperand(0), NS, LHSI->getName());
        
        ICI.setOperand(0, NewAnd);
        return &ICI;
      }
    }
      
    // Try to optimize things like "A[i]&42 == 0" to index computations.
    if (LoadInst *LI = dyn_cast<LoadInst>(LHSI->getOperand(0))) {
      if (GetElementPtrInst *GEP =
          dyn_cast<GetElementPtrInst>(LI->getOperand(0)))
        if (GlobalVariable *GV = dyn_cast<GlobalVariable>(GEP->getOperand(0)))
          if (GV->isConstant() && GV->hasDefinitiveInitializer() &&
              !LI->isVolatile() && isa<ConstantInt>(LHSI->getOperand(1))) {
            ConstantInt *C = cast<ConstantInt>(LHSI->getOperand(1));
            if (Instruction *Res = FoldCmpLoadFromIndexedGlobal(GEP, GV,ICI, C))
              return Res;
          }
    }
    break;

  case Instruction::Or: {
    if (!ICI.isEquality() || !RHS->isNullValue() || !LHSI->hasOneUse())
      break;
    Value *P, *Q;
    if (match(LHSI, m_Or(m_PtrToInt(m_Value(P)), m_PtrToInt(m_Value(Q))))) {
      // Simplify icmp eq (or (ptrtoint P), (ptrtoint Q)), 0
      // -> and (icmp eq P, null), (icmp eq Q, null).

      Value *ICIP = Builder->CreateICmp(ICI.getPredicate(), P,
                                        Constant::getNullValue(P->getType()));
      Value *ICIQ = Builder->CreateICmp(ICI.getPredicate(), Q,
                                        Constant::getNullValue(Q->getType()));
      Instruction *Op;
      if (ICI.getPredicate() == ICmpInst::ICMP_EQ)
        Op = BinaryOperator::CreateAnd(ICIP, ICIQ);
      else
        Op = BinaryOperator::CreateOr(ICIP, ICIQ);
      return Op;
    }
    break;
  }
    
  case Instruction::Shl: {       // (icmp pred (shl X, ShAmt), CI)
    ConstantInt *ShAmt = dyn_cast<ConstantInt>(LHSI->getOperand(1));
    if (!ShAmt) break;
    
    uint32_t TypeBits = RHSV.getBitWidth();
    
    // Check that the shift amount is in range.  If not, don't perform
    // undefined shifts.  When the shift is visited it will be
    // simplified.
    if (ShAmt->uge(TypeBits))
      break;
    
    if (ICI.isEquality()) {
      // If we are comparing against bits always shifted out, the
      // comparison cannot succeed.
      Constant *Comp =
        ConstantExpr::getShl(ConstantExpr::getLShr(RHS, ShAmt),
                                                                 ShAmt);
      if (Comp != RHS) {// Comparing against a bit that we know is zero.
        bool IsICMP_NE = ICI.getPredicate() == ICmpInst::ICMP_NE;
        Constant *Cst =
          ConstantInt::get(Type::getInt1Ty(ICI.getContext()), IsICMP_NE);
        return ReplaceInstUsesWith(ICI, Cst);
      }
      
      if (LHSI->hasOneUse()) {
        // Otherwise strength reduce the shift into an and.
        uint32_t ShAmtVal = (uint32_t)ShAmt->getLimitedValue(TypeBits);
        Constant *Mask =
          ConstantInt::get(ICI.getContext(), APInt::getLowBitsSet(TypeBits, 
                                                       TypeBits-ShAmtVal));
        
        Value *And =
          Builder->CreateAnd(LHSI->getOperand(0),Mask, LHSI->getName()+".mask");
        return new ICmpInst(ICI.getPredicate(), And,
                            ConstantInt::get(ICI.getContext(),
                                             RHSV.lshr(ShAmtVal)));
      }
    }
    
    // Otherwise, if this is a comparison of the sign bit, simplify to and/test.
    bool TrueIfSigned = false;
    if (LHSI->hasOneUse() &&
        isSignBitCheck(ICI.getPredicate(), RHS, TrueIfSigned)) {
      // (X << 31) <s 0  --> (X&1) != 0
      Constant *Mask = ConstantInt::get(ICI.getContext(), APInt(TypeBits, 1) <<
                                           (TypeBits-ShAmt->getZExtValue()-1));
      Value *And =
        Builder->CreateAnd(LHSI->getOperand(0), Mask, LHSI->getName()+".mask");
      return new ICmpInst(TrueIfSigned ? ICmpInst::ICMP_NE : ICmpInst::ICMP_EQ,
                          And, Constant::getNullValue(And->getType()));
    }
    break;
  }
    
  case Instruction::LShr:         // (icmp pred (shr X, ShAmt), CI)
  case Instruction::AShr: {
    // Only handle equality comparisons of shift-by-constant.
    ConstantInt *ShAmt = dyn_cast<ConstantInt>(LHSI->getOperand(1));
    if (!ShAmt || !ICI.isEquality()) break;

    // Check that the shift amount is in range.  If not, don't perform
    // undefined shifts.  When the shift is visited it will be
    // simplified.
    uint32_t TypeBits = RHSV.getBitWidth();
    if (ShAmt->uge(TypeBits))
      break;
    
    uint32_t ShAmtVal = (uint32_t)ShAmt->getLimitedValue(TypeBits);
      
    // If we are comparing against bits always shifted out, the
    // comparison cannot succeed.
    APInt Comp = RHSV << ShAmtVal;
    if (LHSI->getOpcode() == Instruction::LShr)
      Comp = Comp.lshr(ShAmtVal);
    else
      Comp = Comp.ashr(ShAmtVal);
    
    if (Comp != RHSV) { // Comparing against a bit that we know is zero.
      bool IsICMP_NE = ICI.getPredicate() == ICmpInst::ICMP_NE;
      Constant *Cst = ConstantInt::get(Type::getInt1Ty(ICI.getContext()),
                                       IsICMP_NE);
      return ReplaceInstUsesWith(ICI, Cst);
    }
    
    // Otherwise, check to see if the bits shifted out are known to be zero.
    // If so, we can compare against the unshifted value:
    //  (X & 4) >> 1 == 2  --> (X & 4) == 4.
    if (LHSI->hasOneUse() &&
        MaskedValueIsZero(LHSI->getOperand(0), 
                          APInt::getLowBitsSet(Comp.getBitWidth(), ShAmtVal))) {
      return new ICmpInst(ICI.getPredicate(), LHSI->getOperand(0),
                          ConstantExpr::getShl(RHS, ShAmt));
    }
      
    if (LHSI->hasOneUse()) {
      // Otherwise strength reduce the shift into an and.
      APInt Val(APInt::getHighBitsSet(TypeBits, TypeBits - ShAmtVal));
      Constant *Mask = ConstantInt::get(ICI.getContext(), Val);
      
      Value *And = Builder->CreateAnd(LHSI->getOperand(0),
                                      Mask, LHSI->getName()+".mask");
      return new ICmpInst(ICI.getPredicate(), And,
                          ConstantExpr::getShl(RHS, ShAmt));
    }
    break;
  }
    
  case Instruction::SDiv:
  case Instruction::UDiv:
    // Fold: icmp pred ([us]div X, C1), C2 -> range test
    // Fold this div into the comparison, producing a range check. 
    // Determine, based on the divide type, what the range is being 
    // checked.  If there is an overflow on the low or high side, remember 
    // it, otherwise compute the range [low, hi) bounding the new value.
    // See: InsertRangeTest above for the kinds of replacements possible.
    if (ConstantInt *DivRHS = dyn_cast<ConstantInt>(LHSI->getOperand(1)))
      if (Instruction *R = FoldICmpDivCst(ICI, cast<BinaryOperator>(LHSI),
                                          DivRHS))
        return R;
    break;

  case Instruction::Add:
    // Fold: icmp pred (add X, C1), C2
    if (!ICI.isEquality()) {
      ConstantInt *LHSC = dyn_cast<ConstantInt>(LHSI->getOperand(1));
      if (!LHSC) break;
      const APInt &LHSV = LHSC->getValue();

      ConstantRange CR = ICI.makeConstantRange(ICI.getPredicate(), RHSV)
                            .subtract(LHSV);

      if (ICI.isSigned()) {
        if (CR.getLower().isSignBit()) {
          return new ICmpInst(ICmpInst::ICMP_SLT, LHSI->getOperand(0),
                              ConstantInt::get(ICI.getContext(),CR.getUpper()));
        } else if (CR.getUpper().isSignBit()) {
          return new ICmpInst(ICmpInst::ICMP_SGE, LHSI->getOperand(0),
                              ConstantInt::get(ICI.getContext(),CR.getLower()));
        }
      } else {
        if (CR.getLower().isMinValue()) {
          return new ICmpInst(ICmpInst::ICMP_ULT, LHSI->getOperand(0),
                              ConstantInt::get(ICI.getContext(),CR.getUpper()));
        } else if (CR.getUpper().isMinValue()) {
          return new ICmpInst(ICmpInst::ICMP_UGE, LHSI->getOperand(0),
                              ConstantInt::get(ICI.getContext(),CR.getLower()));
        }
      }
    }
    break;
  }
  
  // Simplify icmp_eq and icmp_ne instructions with integer constant RHS.
  if (ICI.isEquality()) {
    bool isICMP_NE = ICI.getPredicate() == ICmpInst::ICMP_NE;
    
    // If the first operand is (add|sub|and|or|xor|rem) with a constant, and 
    // the second operand is a constant, simplify a bit.
    if (BinaryOperator *BO = dyn_cast<BinaryOperator>(LHSI)) {
      switch (BO->getOpcode()) {
      case Instruction::SRem:
        // If we have a signed (X % (2^c)) == 0, turn it into an unsigned one.
        if (RHSV == 0 && isa<ConstantInt>(BO->getOperand(1)) &&BO->hasOneUse()){
          const APInt &V = cast<ConstantInt>(BO->getOperand(1))->getValue();
          if (V.sgt(APInt(V.getBitWidth(), 1)) && V.isPowerOf2()) {
            Value *NewRem =
              Builder->CreateURem(BO->getOperand(0), BO->getOperand(1),
                                  BO->getName());
            return new ICmpInst(ICI.getPredicate(), NewRem,
                                Constant::getNullValue(BO->getType()));
          }
        }
        break;
      case Instruction::Add:
        // Replace ((add A, B) != C) with (A != C-B) if B & C are constants.
        if (ConstantInt *BOp1C = dyn_cast<ConstantInt>(BO->getOperand(1))) {
          if (BO->hasOneUse())
            return new ICmpInst(ICI.getPredicate(), BO->getOperand(0),
                                ConstantExpr::getSub(RHS, BOp1C));
        } else if (RHSV == 0) {
          // Replace ((add A, B) != 0) with (A != -B) if A or B is
          // efficiently invertible, or if the add has just this one use.
          Value *BOp0 = BO->getOperand(0), *BOp1 = BO->getOperand(1);
          
          if (Value *NegVal = dyn_castNegVal(BOp1))
            return new ICmpInst(ICI.getPredicate(), BOp0, NegVal);
          else if (Value *NegVal = dyn_castNegVal(BOp0))
            return new ICmpInst(ICI.getPredicate(), NegVal, BOp1);
          else if (BO->hasOneUse()) {
            Value *Neg = Builder->CreateNeg(BOp1);
            Neg->takeName(BO);
            return new ICmpInst(ICI.getPredicate(), BOp0, Neg);
          }
        }
        break;
      case Instruction::Xor:
        // For the xor case, we can xor two constants together, eliminating
        // the explicit xor.
        if (Constant *BOC = dyn_cast<Constant>(BO->getOperand(1)))
          return new ICmpInst(ICI.getPredicate(), BO->getOperand(0), 
                              ConstantExpr::getXor(RHS, BOC));
        
        // FALLTHROUGH
      case Instruction::Sub:
        // Replace (([sub|xor] A, B) != 0) with (A != B)
        if (RHSV == 0)
          return new ICmpInst(ICI.getPredicate(), BO->getOperand(0),
                              BO->getOperand(1));
        break;
        
      case Instruction::Or:
        // If bits are being or'd in that are not present in the constant we
        // are comparing against, then the comparison could never succeed!
        if (Constant *BOC = dyn_cast<Constant>(BO->getOperand(1))) {
          Constant *NotCI = ConstantExpr::getNot(RHS);
          if (!ConstantExpr::getAnd(BOC, NotCI)->isNullValue())
            return ReplaceInstUsesWith(ICI,
                             ConstantInt::get(Type::getInt1Ty(ICI.getContext()), 
                                       isICMP_NE));
        }
        break;
        
      case Instruction::And:
        if (ConstantInt *BOC = dyn_cast<ConstantInt>(BO->getOperand(1))) {
          // If bits are being compared against that are and'd out, then the
          // comparison can never succeed!
          if ((RHSV & ~BOC->getValue()) != 0)
            return ReplaceInstUsesWith(ICI,
                             ConstantInt::get(Type::getInt1Ty(ICI.getContext()),
                                       isICMP_NE));
          
          // If we have ((X & C) == C), turn it into ((X & C) != 0).
          if (RHS == BOC && RHSV.isPowerOf2())
            return new ICmpInst(isICMP_NE ? ICmpInst::ICMP_EQ :
                                ICmpInst::ICMP_NE, LHSI,
                                Constant::getNullValue(RHS->getType()));
          
          // Replace (and X, (1 << size(X)-1) != 0) with x s< 0
          if (BOC->getValue().isSignBit()) {
            Value *X = BO->getOperand(0);
            Constant *Zero = Constant::getNullValue(X->getType());
            ICmpInst::Predicate pred = isICMP_NE ? 
              ICmpInst::ICMP_SLT : ICmpInst::ICMP_SGE;
            return new ICmpInst(pred, X, Zero);
          }
          
          // ((X & ~7) == 0) --> X < 8
          if (RHSV == 0 && isHighOnes(BOC)) {
            Value *X = BO->getOperand(0);
            Constant *NegX = ConstantExpr::getNeg(BOC);
            ICmpInst::Predicate pred = isICMP_NE ? 
              ICmpInst::ICMP_UGE : ICmpInst::ICMP_ULT;
            return new ICmpInst(pred, X, NegX);
          }
        }
      default: break;
      }
    } else if (IntrinsicInst *II = dyn_cast<IntrinsicInst>(LHSI)) {
      // Handle icmp {eq|ne} <intrinsic>, intcst.
      if (II->getIntrinsicID() == Intrinsic::bswap) {
        Worklist.Add(II);
        ICI.setOperand(0, II->getOperand(1));
        ICI.setOperand(1, ConstantInt::get(II->getContext(), RHSV.byteSwap()));
        return &ICI;
      }
    }
  }
  return 0;
}

/// visitICmpInstWithCastAndCast - Handle icmp (cast x to y), (cast/cst).
/// We only handle extending casts so far.
///
Instruction *InstCombiner::visitICmpInstWithCastAndCast(ICmpInst &ICI) {
  const CastInst *LHSCI = cast<CastInst>(ICI.getOperand(0));
  Value *LHSCIOp        = LHSCI->getOperand(0);
  const Type *SrcTy     = LHSCIOp->getType();
  const Type *DestTy    = LHSCI->getType();
  Value *RHSCIOp;

  // Turn icmp (ptrtoint x), (ptrtoint/c) into a compare of the input if the 
  // integer type is the same size as the pointer type.
  if (TD && LHSCI->getOpcode() == Instruction::PtrToInt &&
      TD->getPointerSizeInBits() ==
         cast<IntegerType>(DestTy)->getBitWidth()) {
    Value *RHSOp = 0;
    if (Constant *RHSC = dyn_cast<Constant>(ICI.getOperand(1))) {
      RHSOp = ConstantExpr::getIntToPtr(RHSC, SrcTy);
    } else if (PtrToIntInst *RHSC = dyn_cast<PtrToIntInst>(ICI.getOperand(1))) {
      RHSOp = RHSC->getOperand(0);
      // If the pointer types don't match, insert a bitcast.
      if (LHSCIOp->getType() != RHSOp->getType())
        RHSOp = Builder->CreateBitCast(RHSOp, LHSCIOp->getType());
    }

    if (RHSOp)
      return new ICmpInst(ICI.getPredicate(), LHSCIOp, RHSOp);
  }
  
  // The code below only handles extension cast instructions, so far.
  // Enforce this.
  if (LHSCI->getOpcode() != Instruction::ZExt &&
      LHSCI->getOpcode() != Instruction::SExt)
    return 0;

  bool isSignedExt = LHSCI->getOpcode() == Instruction::SExt;
  bool isSignedCmp = ICI.isSigned();

  if (CastInst *CI = dyn_cast<CastInst>(ICI.getOperand(1))) {
    // Not an extension from the same type?
    RHSCIOp = CI->getOperand(0);
    if (RHSCIOp->getType() != LHSCIOp->getType()) 
      return 0;
    
    // If the signedness of the two casts doesn't agree (i.e. one is a sext
    // and the other is a zext), then we can't handle this.
    if (CI->getOpcode() != LHSCI->getOpcode())
      return 0;

    // Deal with equality cases early.
    if (ICI.isEquality())
      return new ICmpInst(ICI.getPredicate(), LHSCIOp, RHSCIOp);

    // A signed comparison of sign extended values simplifies into a
    // signed comparison.
    if (isSignedCmp && isSignedExt)
      return new ICmpInst(ICI.getPredicate(), LHSCIOp, RHSCIOp);

    // The other three cases all fold into an unsigned comparison.
    return new ICmpInst(ICI.getUnsignedPredicate(), LHSCIOp, RHSCIOp);
  }

  // If we aren't dealing with a constant on the RHS, exit early
  ConstantInt *CI = dyn_cast<ConstantInt>(ICI.getOperand(1));
  if (!CI)
    return 0;

  // Compute the constant that would happen if we truncated to SrcTy then
  // reextended to DestTy.
  Constant *Res1 = ConstantExpr::getTrunc(CI, SrcTy);
  Constant *Res2 = ConstantExpr::getCast(LHSCI->getOpcode(),
                                                Res1, DestTy);

  // If the re-extended constant didn't change...
  if (Res2 == CI) {
    // Deal with equality cases early.
    if (ICI.isEquality())
      return new ICmpInst(ICI.getPredicate(), LHSCIOp, Res1);

    // A signed comparison of sign extended values simplifies into a
    // signed comparison.
    if (isSignedExt && isSignedCmp)
      return new ICmpInst(ICI.getPredicate(), LHSCIOp, Res1);

    // The other three cases all fold into an unsigned comparison.
    return new ICmpInst(ICI.getUnsignedPredicate(), LHSCIOp, Res1);
  }

  // The re-extended constant changed so the constant cannot be represented 
  // in the shorter type. Consequently, we cannot emit a simple comparison.

  // First, handle some easy cases. We know the result cannot be equal at this
  // point so handle the ICI.isEquality() cases
  if (ICI.getPredicate() == ICmpInst::ICMP_EQ)
    return ReplaceInstUsesWith(ICI, ConstantInt::getFalse(ICI.getContext()));
  if (ICI.getPredicate() == ICmpInst::ICMP_NE)
    return ReplaceInstUsesWith(ICI, ConstantInt::getTrue(ICI.getContext()));

  // Evaluate the comparison for LT (we invert for GT below). LE and GE cases
  // should have been folded away previously and not enter in here.
  Value *Result;
  if (isSignedCmp) {
    // We're performing a signed comparison.
    if (cast<ConstantInt>(CI)->getValue().isNegative())
      Result = ConstantInt::getFalse(ICI.getContext()); // X < (small) --> false
    else
      Result = ConstantInt::getTrue(ICI.getContext());  // X < (large) --> true
  } else {
    // We're performing an unsigned comparison.
    if (isSignedExt) {
      // We're performing an unsigned comp with a sign extended value.
      // This is true if the input is >= 0. [aka >s -1]
      Constant *NegOne = Constant::getAllOnesValue(SrcTy);
      Result = Builder->CreateICmpSGT(LHSCIOp, NegOne, ICI.getName());
    } else {
      // Unsigned extend & unsigned compare -> always true.
      Result = ConstantInt::getTrue(ICI.getContext());
    }
  }

  // Finally, return the value computed.
  if (ICI.getPredicate() == ICmpInst::ICMP_ULT ||
      ICI.getPredicate() == ICmpInst::ICMP_SLT)
    return ReplaceInstUsesWith(ICI, Result);

  assert((ICI.getPredicate()==ICmpInst::ICMP_UGT || 
          ICI.getPredicate()==ICmpInst::ICMP_SGT) &&
         "ICmp should be folded!");
  if (Constant *CI = dyn_cast<Constant>(Result))
    return ReplaceInstUsesWith(ICI, ConstantExpr::getNot(CI));
  return BinaryOperator::CreateNot(Result);
}



Instruction *InstCombiner::visitICmpInst(ICmpInst &I) {
  bool Changed = false;
  
  /// Orders the operands of the compare so that they are listed from most
  /// complex to least complex.  This puts constants before unary operators,
  /// before binary operators.
  if (getComplexity(I.getOperand(0)) < getComplexity(I.getOperand(1))) {
    I.swapOperands();
    Changed = true;
  }
  
  Value *Op0 = I.getOperand(0), *Op1 = I.getOperand(1);
  
  if (Value *V = SimplifyICmpInst(I.getPredicate(), Op0, Op1, TD))
    return ReplaceInstUsesWith(I, V);
  
  const Type *Ty = Op0->getType();

  // icmp's with boolean values can always be turned into bitwise operations
  if (Ty == Type::getInt1Ty(I.getContext())) {
    switch (I.getPredicate()) {
    default: llvm_unreachable("Invalid icmp instruction!");
    case ICmpInst::ICMP_EQ: {               // icmp eq i1 A, B -> ~(A^B)
      Value *Xor = Builder->CreateXor(Op0, Op1, I.getName()+"tmp");
      return BinaryOperator::CreateNot(Xor);
    }
    case ICmpInst::ICMP_NE:                  // icmp eq i1 A, B -> A^B
      return BinaryOperator::CreateXor(Op0, Op1);

    case ICmpInst::ICMP_UGT:
      std::swap(Op0, Op1);                   // Change icmp ugt -> icmp ult
      // FALL THROUGH
    case ICmpInst::ICMP_ULT:{               // icmp ult i1 A, B -> ~A & B
      Value *Not = Builder->CreateNot(Op0, I.getName()+"tmp");
      return BinaryOperator::CreateAnd(Not, Op1);
    }
    case ICmpInst::ICMP_SGT:
      std::swap(Op0, Op1);                   // Change icmp sgt -> icmp slt
      // FALL THROUGH
    case ICmpInst::ICMP_SLT: {               // icmp slt i1 A, B -> A & ~B
      Value *Not = Builder->CreateNot(Op1, I.getName()+"tmp");
      return BinaryOperator::CreateAnd(Not, Op0);
    }
    case ICmpInst::ICMP_UGE:
      std::swap(Op0, Op1);                   // Change icmp uge -> icmp ule
      // FALL THROUGH
    case ICmpInst::ICMP_ULE: {               //  icmp ule i1 A, B -> ~A | B
      Value *Not = Builder->CreateNot(Op0, I.getName()+"tmp");
      return BinaryOperator::CreateOr(Not, Op1);
    }
    case ICmpInst::ICMP_SGE:
      std::swap(Op0, Op1);                   // Change icmp sge -> icmp sle
      // FALL THROUGH
    case ICmpInst::ICMP_SLE: {               //  icmp sle i1 A, B -> A | ~B
      Value *Not = Builder->CreateNot(Op1, I.getName()+"tmp");
      return BinaryOperator::CreateOr(Not, Op0);
    }
    }
  }

  unsigned BitWidth = 0;
  if (TD)
    BitWidth = TD->getTypeSizeInBits(Ty->getScalarType());
  else if (Ty->isIntOrIntVector())
    BitWidth = Ty->getScalarSizeInBits();

  bool isSignBit = false;

  // See if we are doing a comparison with a constant.
  if (ConstantInt *CI = dyn_cast<ConstantInt>(Op1)) {
    Value *A = 0, *B = 0;
    
    // (icmp ne/eq (sub A B) 0) -> (icmp ne/eq A, B)
    if (I.isEquality() && CI->isZero() &&
        match(Op0, m_Sub(m_Value(A), m_Value(B)))) {
      // (icmp cond A B) if cond is equality
      return new ICmpInst(I.getPredicate(), A, B);
    }
    
    // If we have an icmp le or icmp ge instruction, turn it into the
    // appropriate icmp lt or icmp gt instruction.  This allows us to rely on
    // them being folded in the code below.  The SimplifyICmpInst code has
    // already handled the edge cases for us, so we just assert on them.
    switch (I.getPredicate()) {
    default: break;
    case ICmpInst::ICMP_ULE:
      assert(!CI->isMaxValue(false));                 // A <=u MAX -> TRUE
      return new ICmpInst(ICmpInst::ICMP_ULT, Op0,
                          ConstantInt::get(CI->getContext(), CI->getValue()+1));
    case ICmpInst::ICMP_SLE:
      assert(!CI->isMaxValue(true));                  // A <=s MAX -> TRUE
      return new ICmpInst(ICmpInst::ICMP_SLT, Op0,
                          ConstantInt::get(CI->getContext(), CI->getValue()+1));
    case ICmpInst::ICMP_UGE:
      assert(!CI->isMinValue(false));                  // A >=u MIN -> TRUE
      return new ICmpInst(ICmpInst::ICMP_UGT, Op0,
                          ConstantInt::get(CI->getContext(), CI->getValue()-1));
    case ICmpInst::ICMP_SGE:
      assert(!CI->isMinValue(true));                   // A >=s MIN -> TRUE
      return new ICmpInst(ICmpInst::ICMP_SGT, Op0,
                          ConstantInt::get(CI->getContext(), CI->getValue()-1));
    }
    
    // If this comparison is a normal comparison, it demands all
    // bits, if it is a sign bit comparison, it only demands the sign bit.
    bool UnusedBit;
    isSignBit = isSignBitCheck(I.getPredicate(), CI, UnusedBit);
  }

  // See if we can fold the comparison based on range information we can get
  // by checking whether bits are known to be zero or one in the input.
  if (BitWidth != 0) {
    APInt Op0KnownZero(BitWidth, 0), Op0KnownOne(BitWidth, 0);
    APInt Op1KnownZero(BitWidth, 0), Op1KnownOne(BitWidth, 0);

    if (SimplifyDemandedBits(I.getOperandUse(0),
                             isSignBit ? APInt::getSignBit(BitWidth)
                                       : APInt::getAllOnesValue(BitWidth),
                             Op0KnownZero, Op0KnownOne, 0))
      return &I;
    if (SimplifyDemandedBits(I.getOperandUse(1),
                             APInt::getAllOnesValue(BitWidth),
                             Op1KnownZero, Op1KnownOne, 0))
      return &I;

    // Given the known and unknown bits, compute a range that the LHS could be
    // in.  Compute the Min, Max and RHS values based on the known bits. For the
    // EQ and NE we use unsigned values.
    APInt Op0Min(BitWidth, 0), Op0Max(BitWidth, 0);
    APInt Op1Min(BitWidth, 0), Op1Max(BitWidth, 0);
    if (I.isSigned()) {
      ComputeSignedMinMaxValuesFromKnownBits(Op0KnownZero, Op0KnownOne,
                                             Op0Min, Op0Max);
      ComputeSignedMinMaxValuesFromKnownBits(Op1KnownZero, Op1KnownOne,
                                             Op1Min, Op1Max);
    } else {
      ComputeUnsignedMinMaxValuesFromKnownBits(Op0KnownZero, Op0KnownOne,
                                               Op0Min, Op0Max);
      ComputeUnsignedMinMaxValuesFromKnownBits(Op1KnownZero, Op1KnownOne,
                                               Op1Min, Op1Max);
    }

    // If Min and Max are known to be the same, then SimplifyDemandedBits
    // figured out that the LHS is a constant.  Just constant fold this now so
    // that code below can assume that Min != Max.
    if (!isa<Constant>(Op0) && Op0Min == Op0Max)
      return new ICmpInst(I.getPredicate(),
                          ConstantInt::get(I.getContext(), Op0Min), Op1);
    if (!isa<Constant>(Op1) && Op1Min == Op1Max)
      return new ICmpInst(I.getPredicate(), Op0,
                          ConstantInt::get(I.getContext(), Op1Min));

    // Based on the range information we know about the LHS, see if we can
    // simplify this comparison.  For example, (x&4) < 8  is always true.
    switch (I.getPredicate()) {
    default: llvm_unreachable("Unknown icmp opcode!");
    case ICmpInst::ICMP_EQ:
      if (Op0Max.ult(Op1Min) || Op0Min.ugt(Op1Max))
        return ReplaceInstUsesWith(I, ConstantInt::getFalse(I.getContext()));
      break;
    case ICmpInst::ICMP_NE:
      if (Op0Max.ult(Op1Min) || Op0Min.ugt(Op1Max))
        return ReplaceInstUsesWith(I, ConstantInt::getTrue(I.getContext()));
      break;
    case ICmpInst::ICMP_ULT:
      if (Op0Max.ult(Op1Min))          // A <u B -> true if max(A) < min(B)
        return ReplaceInstUsesWith(I, ConstantInt::getTrue(I.getContext()));
      if (Op0Min.uge(Op1Max))          // A <u B -> false if min(A) >= max(B)
        return ReplaceInstUsesWith(I, ConstantInt::getFalse(I.getContext()));
      if (Op1Min == Op0Max)            // A <u B -> A != B if max(A) == min(B)
        return new ICmpInst(ICmpInst::ICMP_NE, Op0, Op1);
      if (ConstantInt *CI = dyn_cast<ConstantInt>(Op1)) {
        if (Op1Max == Op0Min+1)        // A <u C -> A == C-1 if min(A)+1 == C
          return new ICmpInst(ICmpInst::ICMP_EQ, Op0,
                          ConstantInt::get(CI->getContext(), CI->getValue()-1));

        // (x <u 2147483648) -> (x >s -1)  -> true if sign bit clear
        if (CI->isMinValue(true))
          return new ICmpInst(ICmpInst::ICMP_SGT, Op0,
                           Constant::getAllOnesValue(Op0->getType()));
      }
      break;
    case ICmpInst::ICMP_UGT:
      if (Op0Min.ugt(Op1Max))          // A >u B -> true if min(A) > max(B)
        return ReplaceInstUsesWith(I, ConstantInt::getTrue(I.getContext()));
      if (Op0Max.ule(Op1Min))          // A >u B -> false if max(A) <= max(B)
        return ReplaceInstUsesWith(I, ConstantInt::getFalse(I.getContext()));

      if (Op1Max == Op0Min)            // A >u B -> A != B if min(A) == max(B)
        return new ICmpInst(ICmpInst::ICMP_NE, Op0, Op1);
      if (ConstantInt *CI = dyn_cast<ConstantInt>(Op1)) {
        if (Op1Min == Op0Max-1)        // A >u C -> A == C+1 if max(a)-1 == C
          return new ICmpInst(ICmpInst::ICMP_EQ, Op0,
                          ConstantInt::get(CI->getContext(), CI->getValue()+1));

        // (x >u 2147483647) -> (x <s 0)  -> true if sign bit set
        if (CI->isMaxValue(true))
          return new ICmpInst(ICmpInst::ICMP_SLT, Op0,
                              Constant::getNullValue(Op0->getType()));
      }
      break;
    case ICmpInst::ICMP_SLT:
      if (Op0Max.slt(Op1Min))          // A <s B -> true if max(A) < min(C)
        return ReplaceInstUsesWith(I, ConstantInt::getTrue(I.getContext()));
      if (Op0Min.sge(Op1Max))          // A <s B -> false if min(A) >= max(C)
        return ReplaceInstUsesWith(I, ConstantInt::getFalse(I.getContext()));
      if (Op1Min == Op0Max)            // A <s B -> A != B if max(A) == min(B)
        return new ICmpInst(ICmpInst::ICMP_NE, Op0, Op1);
      if (ConstantInt *CI = dyn_cast<ConstantInt>(Op1)) {
        if (Op1Max == Op0Min+1)        // A <s C -> A == C-1 if min(A)+1 == C
          return new ICmpInst(ICmpInst::ICMP_EQ, Op0,
                          ConstantInt::get(CI->getContext(), CI->getValue()-1));
      }
      break;
    case ICmpInst::ICMP_SGT:
      if (Op0Min.sgt(Op1Max))          // A >s B -> true if min(A) > max(B)
        return ReplaceInstUsesWith(I, ConstantInt::getTrue(I.getContext()));
      if (Op0Max.sle(Op1Min))          // A >s B -> false if max(A) <= min(B)
        return ReplaceInstUsesWith(I, ConstantInt::getFalse(I.getContext()));

      if (Op1Max == Op0Min)            // A >s B -> A != B if min(A) == max(B)
        return new ICmpInst(ICmpInst::ICMP_NE, Op0, Op1);
      if (ConstantInt *CI = dyn_cast<ConstantInt>(Op1)) {
        if (Op1Min == Op0Max-1)        // A >s C -> A == C+1 if max(A)-1 == C
          return new ICmpInst(ICmpInst::ICMP_EQ, Op0,
                          ConstantInt::get(CI->getContext(), CI->getValue()+1));
      }
      break;
    case ICmpInst::ICMP_SGE:
      assert(!isa<ConstantInt>(Op1) && "ICMP_SGE with ConstantInt not folded!");
      if (Op0Min.sge(Op1Max))          // A >=s B -> true if min(A) >= max(B)
        return ReplaceInstUsesWith(I, ConstantInt::getTrue(I.getContext()));
      if (Op0Max.slt(Op1Min))          // A >=s B -> false if max(A) < min(B)
        return ReplaceInstUsesWith(I, ConstantInt::getFalse(I.getContext()));
      break;
    case ICmpInst::ICMP_SLE:
      assert(!isa<ConstantInt>(Op1) && "ICMP_SLE with ConstantInt not folded!");
      if (Op0Max.sle(Op1Min))          // A <=s B -> true if max(A) <= min(B)
        return ReplaceInstUsesWith(I, ConstantInt::getTrue(I.getContext()));
      if (Op0Min.sgt(Op1Max))          // A <=s B -> false if min(A) > max(B)
        return ReplaceInstUsesWith(I, ConstantInt::getFalse(I.getContext()));
      break;
    case ICmpInst::ICMP_UGE:
      assert(!isa<ConstantInt>(Op1) && "ICMP_UGE with ConstantInt not folded!");
      if (Op0Min.uge(Op1Max))          // A >=u B -> true if min(A) >= max(B)
        return ReplaceInstUsesWith(I, ConstantInt::getTrue(I.getContext()));
      if (Op0Max.ult(Op1Min))          // A >=u B -> false if max(A) < min(B)
        return ReplaceInstUsesWith(I, ConstantInt::getFalse(I.getContext()));
      break;
    case ICmpInst::ICMP_ULE:
      assert(!isa<ConstantInt>(Op1) && "ICMP_ULE with ConstantInt not folded!");
      if (Op0Max.ule(Op1Min))          // A <=u B -> true if max(A) <= min(B)
        return ReplaceInstUsesWith(I, ConstantInt::getTrue(I.getContext()));
      if (Op0Min.ugt(Op1Max))          // A <=u B -> false if min(A) > max(B)
        return ReplaceInstUsesWith(I, ConstantInt::getFalse(I.getContext()));
      break;
    }

    // Turn a signed comparison into an unsigned one if both operands
    // are known to have the same sign.
    if (I.isSigned() &&
        ((Op0KnownZero.isNegative() && Op1KnownZero.isNegative()) ||
         (Op0KnownOne.isNegative() && Op1KnownOne.isNegative())))
      return new ICmpInst(I.getUnsignedPredicate(), Op0, Op1);
  }

  // Test if the ICmpInst instruction is used exclusively by a select as
  // part of a minimum or maximum operation. If so, refrain from doing
  // any other folding. This helps out other analyses which understand
  // non-obfuscated minimum and maximum idioms, such as ScalarEvolution
  // and CodeGen. And in this case, at least one of the comparison
  // operands has at least one user besides the compare (the select),
  // which would often largely negate the benefit of folding anyway.
  if (I.hasOneUse())
    if (SelectInst *SI = dyn_cast<SelectInst>(*I.use_begin()))
      if ((SI->getOperand(1) == Op0 && SI->getOperand(2) == Op1) ||
          (SI->getOperand(2) == Op0 && SI->getOperand(1) == Op1))
        return 0;

  // See if we are doing a comparison between a constant and an instruction that
  // can be folded into the comparison.
  if (ConstantInt *CI = dyn_cast<ConstantInt>(Op1)) {
    // Since the RHS is a ConstantInt (CI), if the left hand side is an 
    // instruction, see if that instruction also has constants so that the 
    // instruction can be folded into the icmp 
    if (Instruction *LHSI = dyn_cast<Instruction>(Op0))
      if (Instruction *Res = visitICmpInstWithInstAndIntCst(I, LHSI, CI))
        return Res;
  }

  // Handle icmp with constant (but not simple integer constant) RHS
  if (Constant *RHSC = dyn_cast<Constant>(Op1)) {
    if (Instruction *LHSI = dyn_cast<Instruction>(Op0))
      switch (LHSI->getOpcode()) {
      case Instruction::GetElementPtr:
          // icmp pred GEP (P, int 0, int 0, int 0), null -> icmp pred P, null
        if (RHSC->isNullValue() &&
            cast<GetElementPtrInst>(LHSI)->hasAllZeroIndices())
          return new ICmpInst(I.getPredicate(), LHSI->getOperand(0),
                  Constant::getNullValue(LHSI->getOperand(0)->getType()));
        break;
      case Instruction::PHI:
        // Only fold icmp into the PHI if the phi and icmp are in the same
        // block.  If in the same block, we're encouraging jump threading.  If
        // not, we are just pessimizing the code by making an i1 phi.
        if (LHSI->getParent() == I.getParent())
          if (Instruction *NV = FoldOpIntoPhi(I, true))
            return NV;
        break;
      case Instruction::Select: {
        // If either operand of the select is a constant, we can fold the
        // comparison into the select arms, which will cause one to be
        // constant folded and the select turned into a bitwise or.
        Value *Op1 = 0, *Op2 = 0;
        if (Constant *C = dyn_cast<Constant>(LHSI->getOperand(1)))
          Op1 = ConstantExpr::getICmp(I.getPredicate(), C, RHSC);
        if (Constant *C = dyn_cast<Constant>(LHSI->getOperand(2)))
          Op2 = ConstantExpr::getICmp(I.getPredicate(), C, RHSC);

        // We only want to perform this transformation if it will not lead to
        // additional code. This is true if either both sides of the select
        // fold to a constant (in which case the icmp is replaced with a select
        // which will usually simplify) or this is the only user of the
        // select (in which case we are trading a select+icmp for a simpler
        // select+icmp).
        if ((Op1 && Op2) || (LHSI->hasOneUse() && (Op1 || Op2))) {
          if (!Op1)
            Op1 = Builder->CreateICmp(I.getPredicate(), LHSI->getOperand(1),
                                      RHSC, I.getName());
          if (!Op2)
            Op2 = Builder->CreateICmp(I.getPredicate(), LHSI->getOperand(2),
                                      RHSC, I.getName());
          return SelectInst::Create(LHSI->getOperand(0), Op1, Op2);
        }
        break;
      }
      case Instruction::Call:
        // If we have (malloc != null), and if the malloc has a single use, we
        // can assume it is successful and remove the malloc.
        if (isMalloc(LHSI) && LHSI->hasOneUse() &&
            isa<ConstantPointerNull>(RHSC)) {
          // Need to explicitly erase malloc call here, instead of adding it to
          // Worklist, because it won't get DCE'd from the Worklist since
          // isInstructionTriviallyDead() returns false for function calls.
          // It is OK to replace LHSI/MallocCall with Undef because the 
          // instruction that uses it will be erased via Worklist.
          if (extractMallocCall(LHSI)) {
            LHSI->replaceAllUsesWith(UndefValue::get(LHSI->getType()));
            EraseInstFromFunction(*LHSI);
            return ReplaceInstUsesWith(I,
                               ConstantInt::get(Type::getInt1Ty(I.getContext()),
                                                      !I.isTrueWhenEqual()));
          }
          if (CallInst* MallocCall = extractMallocCallFromBitCast(LHSI))
            if (MallocCall->hasOneUse()) {
              MallocCall->replaceAllUsesWith(
                                        UndefValue::get(MallocCall->getType()));
              EraseInstFromFunction(*MallocCall);
              Worklist.Add(LHSI); // The malloc's bitcast use.
              return ReplaceInstUsesWith(I,
                               ConstantInt::get(Type::getInt1Ty(I.getContext()),
                                                      !I.isTrueWhenEqual()));
            }
        }
        break;
      case Instruction::IntToPtr:
        // icmp pred inttoptr(X), null -> icmp pred X, 0
        if (RHSC->isNullValue() && TD &&
            TD->getIntPtrType(RHSC->getContext()) == 
               LHSI->getOperand(0)->getType())
          return new ICmpInst(I.getPredicate(), LHSI->getOperand(0),
                        Constant::getNullValue(LHSI->getOperand(0)->getType()));
        break;

      case Instruction::Load:
        // Try to optimize things like "A[i] > 4" to index computations.
        if (GetElementPtrInst *GEP =
              dyn_cast<GetElementPtrInst>(LHSI->getOperand(0))) {
          if (GlobalVariable *GV = dyn_cast<GlobalVariable>(GEP->getOperand(0)))
            if (GV->isConstant() && GV->hasDefinitiveInitializer() &&
                !cast<LoadInst>(LHSI)->isVolatile())
              if (Instruction *Res = FoldCmpLoadFromIndexedGlobal(GEP, GV, I))
                return Res;
        }
        break;
      }
  }

  // If we can optimize a 'icmp GEP, P' or 'icmp P, GEP', do so now.
  if (GEPOperator *GEP = dyn_cast<GEPOperator>(Op0))
    if (Instruction *NI = FoldGEPICmp(GEP, Op1, I.getPredicate(), I))
      return NI;
  if (GEPOperator *GEP = dyn_cast<GEPOperator>(Op1))
    if (Instruction *NI = FoldGEPICmp(GEP, Op0,
                           ICmpInst::getSwappedPredicate(I.getPredicate()), I))
      return NI;

  // Test to see if the operands of the icmp are casted versions of other
  // values.  If the ptr->ptr cast can be stripped off both arguments, we do so
  // now.
  if (BitCastInst *CI = dyn_cast<BitCastInst>(Op0)) {
    if (isa<PointerType>(Op0->getType()) && 
        (isa<Constant>(Op1) || isa<BitCastInst>(Op1))) { 
      // We keep moving the cast from the left operand over to the right
      // operand, where it can often be eliminated completely.
      Op0 = CI->getOperand(0);

      // If operand #1 is a bitcast instruction, it must also be a ptr->ptr cast
      // so eliminate it as well.
      if (BitCastInst *CI2 = dyn_cast<BitCastInst>(Op1))
        Op1 = CI2->getOperand(0);

      // If Op1 is a constant, we can fold the cast into the constant.
      if (Op0->getType() != Op1->getType()) {
        if (Constant *Op1C = dyn_cast<Constant>(Op1)) {
          Op1 = ConstantExpr::getBitCast(Op1C, Op0->getType());
        } else {
          // Otherwise, cast the RHS right before the icmp
          Op1 = Builder->CreateBitCast(Op1, Op0->getType());
        }
      }
      return new ICmpInst(I.getPredicate(), Op0, Op1);
    }
  }
  
  if (isa<CastInst>(Op0)) {
    // Handle the special case of: icmp (cast bool to X), <cst>
    // This comes up when you have code like
    //   int X = A < B;
    //   if (X) ...
    // For generality, we handle any zero-extension of any operand comparison
    // with a constant or another cast from the same type.
    if (isa<Constant>(Op1) || isa<CastInst>(Op1))
      if (Instruction *R = visitICmpInstWithCastAndCast(I))
        return R;
  }
  
  // See if it's the same type of instruction on the left and right.
  if (BinaryOperator *Op0I = dyn_cast<BinaryOperator>(Op0)) {
    if (BinaryOperator *Op1I = dyn_cast<BinaryOperator>(Op1)) {
      if (Op0I->getOpcode() == Op1I->getOpcode() && Op0I->hasOneUse() &&
          Op1I->hasOneUse() && Op0I->getOperand(1) == Op1I->getOperand(1)) {
        switch (Op0I->getOpcode()) {
        default: break;
        case Instruction::Add:
        case Instruction::Sub:
        case Instruction::Xor:
          if (I.isEquality())    // a+x icmp eq/ne b+x --> a icmp b
            return new ICmpInst(I.getPredicate(), Op0I->getOperand(0),
                                Op1I->getOperand(0));
          // icmp u/s (a ^ signbit), (b ^ signbit) --> icmp s/u a, b
          if (ConstantInt *CI = dyn_cast<ConstantInt>(Op0I->getOperand(1))) {
            if (CI->getValue().isSignBit()) {
              ICmpInst::Predicate Pred = I.isSigned()
                                             ? I.getUnsignedPredicate()
                                             : I.getSignedPredicate();
              return new ICmpInst(Pred, Op0I->getOperand(0),
                                  Op1I->getOperand(0));
            }
            
            if (CI->getValue().isMaxSignedValue()) {
              ICmpInst::Predicate Pred = I.isSigned()
                                             ? I.getUnsignedPredicate()
                                             : I.getSignedPredicate();
              Pred = I.getSwappedPredicate(Pred);
              return new ICmpInst(Pred, Op0I->getOperand(0),
                                  Op1I->getOperand(0));
            }
          }
          break;
        case Instruction::Mul:
          if (!I.isEquality())
            break;

          if (ConstantInt *CI = dyn_cast<ConstantInt>(Op0I->getOperand(1))) {
            // a * Cst icmp eq/ne b * Cst --> a & Mask icmp b & Mask
            // Mask = -1 >> count-trailing-zeros(Cst).
            if (!CI->isZero() && !CI->isOne()) {
              const APInt &AP = CI->getValue();
              ConstantInt *Mask = ConstantInt::get(I.getContext(), 
                                      APInt::getLowBitsSet(AP.getBitWidth(),
                                                           AP.getBitWidth() -
                                                      AP.countTrailingZeros()));
              Value *And1 = Builder->CreateAnd(Op0I->getOperand(0), Mask);
              Value *And2 = Builder->CreateAnd(Op1I->getOperand(0), Mask);
              return new ICmpInst(I.getPredicate(), And1, And2);
            }
          }
          break;
        }
      }
    }
  }
  
  // ~x < ~y --> y < x
  { Value *A, *B;
    if (match(Op0, m_Not(m_Value(A))) &&
        match(Op1, m_Not(m_Value(B))))
      return new ICmpInst(I.getPredicate(), B, A);
  }
  
  if (I.isEquality()) {
    Value *A, *B, *C, *D;
    
    // -x == -y --> x == y
    if (match(Op0, m_Neg(m_Value(A))) &&
        match(Op1, m_Neg(m_Value(B))))
      return new ICmpInst(I.getPredicate(), A, B);
    
    if (match(Op0, m_Xor(m_Value(A), m_Value(B)))) {
      if (A == Op1 || B == Op1) {    // (A^B) == A  ->  B == 0
        Value *OtherVal = A == Op1 ? B : A;
        return new ICmpInst(I.getPredicate(), OtherVal,
                            Constant::getNullValue(A->getType()));
      }

      if (match(Op1, m_Xor(m_Value(C), m_Value(D)))) {
        // A^c1 == C^c2 --> A == C^(c1^c2)
        ConstantInt *C1, *C2;
        if (match(B, m_ConstantInt(C1)) &&
            match(D, m_ConstantInt(C2)) && Op1->hasOneUse()) {
          Constant *NC = ConstantInt::get(I.getContext(),
                                          C1->getValue() ^ C2->getValue());
          Value *Xor = Builder->CreateXor(C, NC, "tmp");
          return new ICmpInst(I.getPredicate(), A, Xor);
        }
        
        // A^B == A^D -> B == D
        if (A == C) return new ICmpInst(I.getPredicate(), B, D);
        if (A == D) return new ICmpInst(I.getPredicate(), B, C);
        if (B == C) return new ICmpInst(I.getPredicate(), A, D);
        if (B == D) return new ICmpInst(I.getPredicate(), A, C);
      }
    }
    
    if (match(Op1, m_Xor(m_Value(A), m_Value(B))) &&
        (A == Op0 || B == Op0)) {
      // A == (A^B)  ->  B == 0
      Value *OtherVal = A == Op0 ? B : A;
      return new ICmpInst(I.getPredicate(), OtherVal,
                          Constant::getNullValue(A->getType()));
    }

    // (A-B) == A  ->  B == 0
    if (match(Op0, m_Sub(m_Specific(Op1), m_Value(B))))
      return new ICmpInst(I.getPredicate(), B, 
                          Constant::getNullValue(B->getType()));

    // A == (A-B)  ->  B == 0
    if (match(Op1, m_Sub(m_Specific(Op0), m_Value(B))))
      return new ICmpInst(I.getPredicate(), B,
                          Constant::getNullValue(B->getType()));
    
    // (X&Z) == (Y&Z) -> (X^Y) & Z == 0
    if (Op0->hasOneUse() && Op1->hasOneUse() &&
        match(Op0, m_And(m_Value(A), m_Value(B))) && 
        match(Op1, m_And(m_Value(C), m_Value(D)))) {
      Value *X = 0, *Y = 0, *Z = 0;
      
      if (A == C) {
        X = B; Y = D; Z = A;
      } else if (A == D) {
        X = B; Y = C; Z = A;
      } else if (B == C) {
        X = A; Y = D; Z = B;
      } else if (B == D) {
        X = A; Y = C; Z = B;
      }
      
      if (X) {   // Build (X^Y) & Z
        Op1 = Builder->CreateXor(X, Y, "tmp");
        Op1 = Builder->CreateAnd(Op1, Z, "tmp");
        I.setOperand(0, Op1);
        I.setOperand(1, Constant::getNullValue(Op1->getType()));
        return &I;
      }
    }
  }
  
  {
    Value *X; ConstantInt *Cst;
    // icmp X+Cst, X
    if (match(Op0, m_Add(m_Value(X), m_ConstantInt(Cst))) && Op1 == X)
      return FoldICmpAddOpCst(I, X, Cst, I.getPredicate(), Op0);

    // icmp X, X+Cst
    if (match(Op1, m_Add(m_Value(X), m_ConstantInt(Cst))) && Op0 == X)
      return FoldICmpAddOpCst(I, X, Cst, I.getSwappedPredicate(), Op1);
  }
  return Changed ? &I : 0;
}






/// FoldFCmp_IntToFP_Cst - Fold fcmp ([us]itofp x, cst) if possible.
///
Instruction *InstCombiner::FoldFCmp_IntToFP_Cst(FCmpInst &I,
                                                Instruction *LHSI,
                                                Constant *RHSC) {
  if (!isa<ConstantFP>(RHSC)) return 0;
  const APFloat &RHS = cast<ConstantFP>(RHSC)->getValueAPF();
  
  // Get the width of the mantissa.  We don't want to hack on conversions that
  // might lose information from the integer, e.g. "i64 -> float"
  int MantissaWidth = LHSI->getType()->getFPMantissaWidth();
  if (MantissaWidth == -1) return 0;  // Unknown.
  
  // Check to see that the input is converted from an integer type that is small
  // enough that preserves all bits.  TODO: check here for "known" sign bits.
  // This would allow us to handle (fptosi (x >>s 62) to float) if x is i64 f.e.
  unsigned InputSize = LHSI->getOperand(0)->getType()->getScalarSizeInBits();
  
  // If this is a uitofp instruction, we need an extra bit to hold the sign.
  bool LHSUnsigned = isa<UIToFPInst>(LHSI);
  if (LHSUnsigned)
    ++InputSize;
  
  // If the conversion would lose info, don't hack on this.
  if ((int)InputSize > MantissaWidth)
    return 0;
  
  // Otherwise, we can potentially simplify the comparison.  We know that it
  // will always come through as an integer value and we know the constant is
  // not a NAN (it would have been previously simplified).
  assert(!RHS.isNaN() && "NaN comparison not already folded!");
  
  ICmpInst::Predicate Pred;
  switch (I.getPredicate()) {
  default: llvm_unreachable("Unexpected predicate!");
  case FCmpInst::FCMP_UEQ:
  case FCmpInst::FCMP_OEQ:
    Pred = ICmpInst::ICMP_EQ;
    break;
  case FCmpInst::FCMP_UGT:
  case FCmpInst::FCMP_OGT:
    Pred = LHSUnsigned ? ICmpInst::ICMP_UGT : ICmpInst::ICMP_SGT;
    break;
  case FCmpInst::FCMP_UGE:
  case FCmpInst::FCMP_OGE:
    Pred = LHSUnsigned ? ICmpInst::ICMP_UGE : ICmpInst::ICMP_SGE;
    break;
  case FCmpInst::FCMP_ULT:
  case FCmpInst::FCMP_OLT:
    Pred = LHSUnsigned ? ICmpInst::ICMP_ULT : ICmpInst::ICMP_SLT;
    break;
  case FCmpInst::FCMP_ULE:
  case FCmpInst::FCMP_OLE:
    Pred = LHSUnsigned ? ICmpInst::ICMP_ULE : ICmpInst::ICMP_SLE;
    break;
  case FCmpInst::FCMP_UNE:
  case FCmpInst::FCMP_ONE:
    Pred = ICmpInst::ICMP_NE;
    break;
  case FCmpInst::FCMP_ORD:
    return ReplaceInstUsesWith(I, ConstantInt::getTrue(I.getContext()));
  case FCmpInst::FCMP_UNO:
    return ReplaceInstUsesWith(I, ConstantInt::getFalse(I.getContext()));
  }
  
  const IntegerType *IntTy = cast<IntegerType>(LHSI->getOperand(0)->getType());
  
  // Now we know that the APFloat is a normal number, zero or inf.
  
  // See if the FP constant is too large for the integer.  For example,
  // comparing an i8 to 300.0.
  unsigned IntWidth = IntTy->getScalarSizeInBits();
  
  if (!LHSUnsigned) {
    // If the RHS value is > SignedMax, fold the comparison.  This handles +INF
    // and large values.
    APFloat SMax(RHS.getSemantics(), APFloat::fcZero, false);
    SMax.convertFromAPInt(APInt::getSignedMaxValue(IntWidth), true,
                          APFloat::rmNearestTiesToEven);
    if (SMax.compare(RHS) == APFloat::cmpLessThan) {  // smax < 13123.0
      if (Pred == ICmpInst::ICMP_NE  || Pred == ICmpInst::ICMP_SLT ||
          Pred == ICmpInst::ICMP_SLE)
        return ReplaceInstUsesWith(I, ConstantInt::getTrue(I.getContext()));
      return ReplaceInstUsesWith(I, ConstantInt::getFalse(I.getContext()));
    }
  } else {
    // If the RHS value is > UnsignedMax, fold the comparison. This handles
    // +INF and large values.
    APFloat UMax(RHS.getSemantics(), APFloat::fcZero, false);
    UMax.convertFromAPInt(APInt::getMaxValue(IntWidth), false,
                          APFloat::rmNearestTiesToEven);
    if (UMax.compare(RHS) == APFloat::cmpLessThan) {  // umax < 13123.0
      if (Pred == ICmpInst::ICMP_NE  || Pred == ICmpInst::ICMP_ULT ||
          Pred == ICmpInst::ICMP_ULE)
        return ReplaceInstUsesWith(I, ConstantInt::getTrue(I.getContext()));
      return ReplaceInstUsesWith(I, ConstantInt::getFalse(I.getContext()));
    }
  }
  
  if (!LHSUnsigned) {
    // See if the RHS value is < SignedMin.
    APFloat SMin(RHS.getSemantics(), APFloat::fcZero, false);
    SMin.convertFromAPInt(APInt::getSignedMinValue(IntWidth), true,
                          APFloat::rmNearestTiesToEven);
    if (SMin.compare(RHS) == APFloat::cmpGreaterThan) { // smin > 12312.0
      if (Pred == ICmpInst::ICMP_NE || Pred == ICmpInst::ICMP_SGT ||
          Pred == ICmpInst::ICMP_SGE)
        return ReplaceInstUsesWith(I, ConstantInt::getTrue(I.getContext()));
      return ReplaceInstUsesWith(I, ConstantInt::getFalse(I.getContext()));
    }
  }

  // Okay, now we know that the FP constant fits in the range [SMIN, SMAX] or
  // [0, UMAX], but it may still be fractional.  See if it is fractional by
  // casting the FP value to the integer value and back, checking for equality.
  // Don't do this for zero, because -0.0 is not fractional.
  Constant *RHSInt = LHSUnsigned
    ? ConstantExpr::getFPToUI(RHSC, IntTy)
    : ConstantExpr::getFPToSI(RHSC, IntTy);
  if (!RHS.isZero()) {
    bool Equal = LHSUnsigned
      ? ConstantExpr::getUIToFP(RHSInt, RHSC->getType()) == RHSC
      : ConstantExpr::getSIToFP(RHSInt, RHSC->getType()) == RHSC;
    if (!Equal) {
      // If we had a comparison against a fractional value, we have to adjust
      // the compare predicate and sometimes the value.  RHSC is rounded towards
      // zero at this point.
      switch (Pred) {
      default: llvm_unreachable("Unexpected integer comparison!");
      case ICmpInst::ICMP_NE:  // (float)int != 4.4   --> true
        return ReplaceInstUsesWith(I, ConstantInt::getTrue(I.getContext()));
      case ICmpInst::ICMP_EQ:  // (float)int == 4.4   --> false
        return ReplaceInstUsesWith(I, ConstantInt::getFalse(I.getContext()));
      case ICmpInst::ICMP_ULE:
        // (float)int <= 4.4   --> int <= 4
        // (float)int <= -4.4  --> false
        if (RHS.isNegative())
          return ReplaceInstUsesWith(I, ConstantInt::getFalse(I.getContext()));
        break;
      case ICmpInst::ICMP_SLE:
        // (float)int <= 4.4   --> int <= 4
        // (float)int <= -4.4  --> int < -4
        if (RHS.isNegative())
          Pred = ICmpInst::ICMP_SLT;
        break;
      case ICmpInst::ICMP_ULT:
        // (float)int < -4.4   --> false
        // (float)int < 4.4    --> int <= 4
        if (RHS.isNegative())
          return ReplaceInstUsesWith(I, ConstantInt::getFalse(I.getContext()));
        Pred = ICmpInst::ICMP_ULE;
        break;
      case ICmpInst::ICMP_SLT:
        // (float)int < -4.4   --> int < -4
        // (float)int < 4.4    --> int <= 4
        if (!RHS.isNegative())
          Pred = ICmpInst::ICMP_SLE;
        break;
      case ICmpInst::ICMP_UGT:
        // (float)int > 4.4    --> int > 4
        // (float)int > -4.4   --> true
        if (RHS.isNegative())
          return ReplaceInstUsesWith(I, ConstantInt::getTrue(I.getContext()));
        break;
      case ICmpInst::ICMP_SGT:
        // (float)int > 4.4    --> int > 4
        // (float)int > -4.4   --> int >= -4
        if (RHS.isNegative())
          Pred = ICmpInst::ICMP_SGE;
        break;
      case ICmpInst::ICMP_UGE:
        // (float)int >= -4.4   --> true
        // (float)int >= 4.4    --> int > 4
        if (!RHS.isNegative())
          return ReplaceInstUsesWith(I, ConstantInt::getTrue(I.getContext()));
        Pred = ICmpInst::ICMP_UGT;
        break;
      case ICmpInst::ICMP_SGE:
        // (float)int >= -4.4   --> int >= -4
        // (float)int >= 4.4    --> int > 4
        if (!RHS.isNegative())
          Pred = ICmpInst::ICMP_SGT;
        break;
      }
    }
  }

  // Lower this FP comparison into an appropriate integer version of the
  // comparison.
  return new ICmpInst(Pred, LHSI->getOperand(0), RHSInt);
}

Instruction *InstCombiner::visitFCmpInst(FCmpInst &I) {
  bool Changed = false;
  
  /// Orders the operands of the compare so that they are listed from most
  /// complex to least complex.  This puts constants before unary operators,
  /// before binary operators.
  if (getComplexity(I.getOperand(0)) < getComplexity(I.getOperand(1))) {
    I.swapOperands();
    Changed = true;
  }

  Value *Op0 = I.getOperand(0), *Op1 = I.getOperand(1);
  
  if (Value *V = SimplifyFCmpInst(I.getPredicate(), Op0, Op1, TD))
    return ReplaceInstUsesWith(I, V);

  // Simplify 'fcmp pred X, X'
  if (Op0 == Op1) {
    switch (I.getPredicate()) {
    default: llvm_unreachable("Unknown predicate!");
    case FCmpInst::FCMP_UNO:    // True if unordered: isnan(X) | isnan(Y)
    case FCmpInst::FCMP_ULT:    // True if unordered or less than
    case FCmpInst::FCMP_UGT:    // True if unordered or greater than
    case FCmpInst::FCMP_UNE:    // True if unordered or not equal
      // Canonicalize these to be 'fcmp uno %X, 0.0'.
      I.setPredicate(FCmpInst::FCMP_UNO);
      I.setOperand(1, Constant::getNullValue(Op0->getType()));
      return &I;
      
    case FCmpInst::FCMP_ORD:    // True if ordered (no nans)
    case FCmpInst::FCMP_OEQ:    // True if ordered and equal
    case FCmpInst::FCMP_OGE:    // True if ordered and greater than or equal
    case FCmpInst::FCMP_OLE:    // True if ordered and less than or equal
      // Canonicalize these to be 'fcmp ord %X, 0.0'.
      I.setPredicate(FCmpInst::FCMP_ORD);
      I.setOperand(1, Constant::getNullValue(Op0->getType()));
      return &I;
    }
  }
    
  // Handle fcmp with constant RHS
  if (Constant *RHSC = dyn_cast<Constant>(Op1)) {
    if (Instruction *LHSI = dyn_cast<Instruction>(Op0))
      switch (LHSI->getOpcode()) {
      case Instruction::PHI:
        // Only fold fcmp into the PHI if the phi and fcmp are in the same
        // block.  If in the same block, we're encouraging jump threading.  If
        // not, we are just pessimizing the code by making an i1 phi.
        if (LHSI->getParent() == I.getParent())
          if (Instruction *NV = FoldOpIntoPhi(I, true))
            return NV;
        break;
      case Instruction::SIToFP:
      case Instruction::UIToFP:
        if (Instruction *NV = FoldFCmp_IntToFP_Cst(I, LHSI, RHSC))
          return NV;
        break;
      case Instruction::Select: {
        // If either operand of the select is a constant, we can fold the
        // comparison into the select arms, which will cause one to be
        // constant folded and the select turned into a bitwise or.
        Value *Op1 = 0, *Op2 = 0;
        if (LHSI->hasOneUse()) {
          if (Constant *C = dyn_cast<Constant>(LHSI->getOperand(1))) {
            // Fold the known value into the constant operand.
            Op1 = ConstantExpr::getCompare(I.getPredicate(), C, RHSC);
            // Insert a new FCmp of the other select operand.
            Op2 = Builder->CreateFCmp(I.getPredicate(),
                                      LHSI->getOperand(2), RHSC, I.getName());
          } else if (Constant *C = dyn_cast<Constant>(LHSI->getOperand(2))) {
            // Fold the known value into the constant operand.
            Op2 = ConstantExpr::getCompare(I.getPredicate(), C, RHSC);
            // Insert a new FCmp of the other select operand.
            Op1 = Builder->CreateFCmp(I.getPredicate(), LHSI->getOperand(1),
                                      RHSC, I.getName());
          }
        }

        if (Op1)
          return SelectInst::Create(LHSI->getOperand(0), Op1, Op2);
        break;
      }
    case Instruction::Load:
      if (GetElementPtrInst *GEP =
          dyn_cast<GetElementPtrInst>(LHSI->getOperand(0))) {
        if (GlobalVariable *GV = dyn_cast<GlobalVariable>(GEP->getOperand(0)))
          if (GV->isConstant() && GV->hasDefinitiveInitializer() &&
              !cast<LoadInst>(LHSI)->isVolatile())
            if (Instruction *Res = FoldCmpLoadFromIndexedGlobal(GEP, GV, I))
              return Res;
      }
      break;
    }
  }

  return Changed ? &I : 0;
}
