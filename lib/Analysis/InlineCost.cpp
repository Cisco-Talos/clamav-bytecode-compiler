//===- InlineCost.cpp - Cost analysis for inliner -------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements inline cost analysis.
//
//===----------------------------------------------------------------------===//

#include "llvm/Analysis/InlineCost.h"
#include "llvm/Support/CallSite.h"
#include "llvm/CallingConv.h"
#include "llvm/IntrinsicInst.h"
#include "llvm/ADT/SmallPtrSet.h"
using namespace llvm;

// CountCodeReductionForConstant - Figure out an approximation for how many
// instructions will be constant folded if the specified value is constant.
//
unsigned InlineCostAnalyzer::FunctionInfo::
         CountCodeReductionForConstant(Value *V) {
  unsigned Reduction = 0;
  for (Value::use_iterator UI = V->use_begin(), E = V->use_end(); UI != E; ++UI)
    if (isa<BranchInst>(*UI))
      Reduction += 40;          // Eliminating a conditional branch is a big win
    else if (SwitchInst *SI = dyn_cast<SwitchInst>(*UI))
      // Eliminating a switch is a big win, proportional to the number of edges
      // deleted.
      Reduction += (SI->getNumSuccessors()-1) * 40;
    else if (isa<IndirectBrInst>(*UI))
      // Eliminating an indirect branch is a big win.
      Reduction += 200;
    else if (CallInst *CI = dyn_cast<CallInst>(*UI)) {
      // Turning an indirect call into a direct call is a BIG win
      Reduction += CI->getCalledValue() == V ? 500 : 0;
    } else if (InvokeInst *II = dyn_cast<InvokeInst>(*UI)) {
      // Turning an indirect call into a direct call is a BIG win
      Reduction += II->getCalledValue() == V ? 500 : 0;
    } else {
      // Figure out if this instruction will be removed due to simple constant
      // propagation.
      Instruction &Inst = cast<Instruction>(**UI);
      
      // We can't constant propagate instructions which have effects or
      // read memory.
      //
      // FIXME: It would be nice to capture the fact that a load from a
      // pointer-to-constant-global is actually a *really* good thing to zap.
      // Unfortunately, we don't know the pointer that may get propagated here,
      // so we can't make this decision.
      if (Inst.mayReadFromMemory() || Inst.mayHaveSideEffects() ||
          isa<AllocaInst>(Inst)) 
        continue;

      bool AllOperandsConstant = true;
      for (unsigned i = 0, e = Inst.getNumOperands(); i != e; ++i)
        if (!isa<Constant>(Inst.getOperand(i)) && Inst.getOperand(i) != V) {
          AllOperandsConstant = false;
          break;
        }

      if (AllOperandsConstant) {
        // We will get to remove this instruction...
        Reduction += 7;

        // And any other instructions that use it which become constants
        // themselves.
        Reduction += CountCodeReductionForConstant(&Inst);
      }
    }

  return Reduction;
}

// CountCodeReductionForAlloca - Figure out an approximation of how much smaller
// the function will be if it is inlined into a context where an argument
// becomes an alloca.
//
unsigned InlineCostAnalyzer::FunctionInfo::
         CountCodeReductionForAlloca(Value *V) {
  if (!isa<PointerType>(V->getType())) return 0;  // Not a pointer
  unsigned Reduction = 0;
  for (Value::use_iterator UI = V->use_begin(), E = V->use_end(); UI != E;++UI){
    Instruction *I = cast<Instruction>(*UI);
    if (isa<LoadInst>(I) || isa<StoreInst>(I))
      Reduction += 10;
    else if (GetElementPtrInst *GEP = dyn_cast<GetElementPtrInst>(I)) {
      // If the GEP has variable indices, we won't be able to do much with it.
      if (!GEP->hasAllConstantIndices())
        Reduction += CountCodeReductionForAlloca(GEP)+15;
    } else {
      // If there is some other strange instruction, we're not going to be able
      // to do much if we inline this.
      return 0;
    }
  }

  return Reduction;
}

// callIsSmall - If a call is likely to lower to a single target instruction, or
// is otherwise deemed small return true.
// TODO: Perhaps calls like memcpy, strcpy, etc?
static bool callIsSmall(const Function *F) {
  if (!F) return false;
  
  if (F->hasLocalLinkage()) return false;
  
  if (!F->hasName()) return false;
  
  StringRef Name = F->getName();
  
  // These will all likely lower to a single selection DAG node.
  if (Name == "copysign" || Name == "copysignf" ||
      Name == "fabs" || Name == "fabsf" || Name == "fabsl" ||
      Name == "sin" || Name == "sinf" || Name == "sinl" ||
      Name == "cos" || Name == "cosf" || Name == "cosl" ||
      Name == "sqrt" || Name == "sqrtf" || Name == "sqrtl" )
    return true;
  
  // These are all likely to be optimized into something smaller.
  if (Name == "pow" || Name == "powf" || Name == "powl" ||
      Name == "exp2" || Name == "exp2l" || Name == "exp2f" ||
      Name == "floor" || Name == "floorf" || Name == "ceil" ||
      Name == "round" || Name == "ffs" || Name == "ffsl" ||
      Name == "abs" || Name == "labs" || Name == "llabs")
    return true;
  
  return false;
}

/// analyzeBasicBlock - Fill in the current structure with information gleaned
/// from the specified block.
void CodeMetrics::analyzeBasicBlock(const BasicBlock *BB) {
  ++NumBlocks;

  for (BasicBlock::const_iterator II = BB->begin(), E = BB->end();
       II != E; ++II) {
    if (isa<PHINode>(II)) continue;           // PHI nodes don't count.

    // Special handling for calls.
    if (isa<CallInst>(II) || isa<InvokeInst>(II)) {
      if (isa<DbgInfoIntrinsic>(II))
        continue;  // Debug intrinsics don't count as size.
      
      CallSite CS = CallSite::get(const_cast<Instruction*>(&*II));
      
      // If this function contains a call to setjmp or _setjmp, never inline
      // it.  This is a hack because we depend on the user marking their local
      // variables as volatile if they are live across a setjmp call, and they
      // probably won't do this in callers.
      if (Function *F = CS.getCalledFunction())
        if (F->isDeclaration() && 
            (F->getName() == "setjmp" || F->getName() == "_setjmp"))
          NeverInline = true;

      // Calls often compile into many machine instructions.  Bump up their
      // cost to reflect this.
      if (!isa<IntrinsicInst>(II) && !callIsSmall(CS.getCalledFunction()))
        NumInsts += InlineConstants::CallPenalty;
    }
    
    if (const AllocaInst *AI = dyn_cast<AllocaInst>(II)) {
      if (!AI->isStaticAlloca())
        this->usesDynamicAlloca = true;
    }

    if (isa<ExtractElementInst>(II) || isa<VectorType>(II->getType()))
      ++NumVectorInsts; 
    
    if (const CastInst *CI = dyn_cast<CastInst>(II)) {
      // Noop casts, including ptr <-> int,  don't count.
      if (CI->isLosslessCast() || isa<IntToPtrInst>(CI) || 
          isa<PtrToIntInst>(CI))
        continue;
      // Result of a cmp instruction is often extended (to be used by other
      // cmp instructions, logical or return instructions). These are usually
      // nop on most sane targets.
      if (isa<CmpInst>(CI->getOperand(0)))
        continue;
    } else if (const GetElementPtrInst *GEPI = dyn_cast<GetElementPtrInst>(II)){
      // If a GEP has all constant indices, it will probably be folded with
      // a load/store.
      if (GEPI->hasAllConstantIndices())
        continue;
    }

    ++NumInsts;
  }
  
  if (isa<ReturnInst>(BB->getTerminator()))
    ++NumRets;
  
  // We never want to inline functions that contain an indirectbr.  This is
  // incorrect because all the blockaddress's (in static global initializers
  // for example) would be referring to the original function, and this indirect
  // jump would jump from the inlined copy of the function into the original
  // function which is extremely undefined behavior.
  if (isa<IndirectBrInst>(BB->getTerminator()))
    NeverInline = true;
}

/// analyzeFunction - Fill in the current structure with information gleaned
/// from the specified function.
void CodeMetrics::analyzeFunction(Function *F) {
  // Look at the size of the callee.
  for (Function::const_iterator BB = F->begin(), E = F->end(); BB != E; ++BB)
    analyzeBasicBlock(&*BB);
}

/// analyzeFunction - Fill in the current structure with information gleaned
/// from the specified function.
void InlineCostAnalyzer::FunctionInfo::analyzeFunction(Function *F) {
  Metrics.analyzeFunction(F);

  // A function with exactly one return has it removed during the inlining
  // process (see InlineFunction), so don't count it.
  // FIXME: This knowledge should really be encoded outside of FunctionInfo.
  if (Metrics.NumRets==1)
    --Metrics.NumInsts;

  // Don't bother calculating argument weights if we are never going to inline
  // the function anyway.
  if (Metrics.NeverInline)
    return;

  // Check out all of the arguments to the function, figuring out how much
  // code can be eliminated if one of the arguments is a constant.
  ArgumentWeights.reserve(F->arg_size());
  for (Function::arg_iterator I = F->arg_begin(), E = F->arg_end(); I != E; ++I)
    ArgumentWeights.push_back(ArgInfo(CountCodeReductionForConstant(I),
                                      CountCodeReductionForAlloca(I)));
}

// getInlineCost - The heuristic used to determine if we should inline the
// function call or not.
//
InlineCost InlineCostAnalyzer::getInlineCost(CallSite CS,
                               SmallPtrSet<const Function *, 16> &NeverInline) {
  Instruction *TheCall = CS.getInstruction();
  Function *Callee = CS.getCalledFunction();
  Function *Caller = TheCall->getParent()->getParent();

  // Don't inline functions which can be redefined at link-time to mean
  // something else.  Don't inline functions marked noinline.
  if (Callee->mayBeOverridden() ||
      Callee->hasFnAttr(Attribute::NoInline) || NeverInline.count(Callee))
    return llvm::InlineCost::getNever();

  // InlineCost - This value measures how good of an inline candidate this call
  // site is to inline.  A lower inline cost make is more likely for the call to
  // be inlined.  This value may go negative.
  //
  int InlineCost = 0;
  
  // If there is only one call of the function, and it has internal linkage,
  // make it almost guaranteed to be inlined.
  //
  if (Callee->hasLocalLinkage() && Callee->hasOneUse())
    InlineCost += InlineConstants::LastCallToStaticBonus;
  
  // If this function uses the coldcc calling convention, prefer not to inline
  // it.
  if (Callee->getCallingConv() == CallingConv::Cold)
    InlineCost += InlineConstants::ColdccPenalty;
  
  // If the instruction after the call, or if the normal destination of the
  // invoke is an unreachable instruction, the function is noreturn.  As such,
  // there is little point in inlining this.
  if (InvokeInst *II = dyn_cast<InvokeInst>(TheCall)) {
    if (isa<UnreachableInst>(II->getNormalDest()->begin()))
      InlineCost += InlineConstants::NoreturnPenalty;
  } else if (isa<UnreachableInst>(++BasicBlock::iterator(TheCall)))
    InlineCost += InlineConstants::NoreturnPenalty;
  
  // Get information about the callee...
  FunctionInfo &CalleeFI = CachedFunctionInfo[Callee];
  
  // If we haven't calculated this information yet, do so now.
  if (CalleeFI.Metrics.NumBlocks == 0)
    CalleeFI.analyzeFunction(Callee);

  // If we should never inline this, return a huge cost.
  if (CalleeFI.Metrics.NeverInline)
    return InlineCost::getNever();

  // FIXME: It would be nice to kill off CalleeFI.NeverInline. Then we
  // could move this up and avoid computing the FunctionInfo for
  // things we are going to just return always inline for. This
  // requires handling setjmp somewhere else, however.
  if (!Callee->isDeclaration() && Callee->hasFnAttr(Attribute::AlwaysInline))
    return InlineCost::getAlways();
    
  if (CalleeFI.Metrics.usesDynamicAlloca) {
    // Get infomation about the caller...
    FunctionInfo &CallerFI = CachedFunctionInfo[Caller];

    // If we haven't calculated this information yet, do so now.
    if (CallerFI.Metrics.NumBlocks == 0)
      CallerFI.analyzeFunction(Caller);

    // Don't inline a callee with dynamic alloca into a caller without them.
    // Functions containing dynamic alloca's are inefficient in various ways;
    // don't create more inefficiency.
    if (!CallerFI.Metrics.usesDynamicAlloca)
      return InlineCost::getNever();
  }

  // Add to the inline quality for properties that make the call valuable to
  // inline.  This includes factors that indicate that the result of inlining
  // the function will be optimizable.  Currently this just looks at arguments
  // passed into the function.
  //
  unsigned ArgNo = 0;
  for (CallSite::arg_iterator I = CS.arg_begin(), E = CS.arg_end();
       I != E; ++I, ++ArgNo) {
    // Each argument passed in has a cost at both the caller and the callee
    // sides.  This favors functions that take many arguments over functions
    // that take few arguments.
    InlineCost -= 20;
    
    // If this is a function being passed in, it is very likely that we will be
    // able to turn an indirect function call into a direct function call.
    if (isa<Function>(I))
      InlineCost -= 100;
    
    // If an alloca is passed in, inlining this function is likely to allow
    // significant future optimization possibilities (like scalar promotion, and
    // scalarization), so encourage the inlining of the function.
    //
    else if (isa<AllocaInst>(I)) {
      if (ArgNo < CalleeFI.ArgumentWeights.size())
        InlineCost -= CalleeFI.ArgumentWeights[ArgNo].AllocaWeight;
      
      // If this is a constant being passed into the function, use the argument
      // weights calculated for the callee to determine how much will be folded
      // away with this information.
    } else if (isa<Constant>(I)) {
      if (ArgNo < CalleeFI.ArgumentWeights.size())
        InlineCost -= CalleeFI.ArgumentWeights[ArgNo].ConstantWeight;
    }
  }
  
  // Now that we have considered all of the factors that make the call site more
  // likely to be inlined, look at factors that make us not want to inline it.
  
  // Don't inline into something too big, which would make it bigger.
  // "size" here is the number of basic blocks, not instructions.
  //
  InlineCost += Caller->size()/15;
  
  // Look at the size of the callee. Each instruction counts as 5.
  InlineCost += CalleeFI.Metrics.NumInsts*5;

  return llvm::InlineCost::get(InlineCost);
}

// getInlineFudgeFactor - Return a > 1.0 factor if the inliner should use a
// higher threshold to determine if the function call should be inlined.
float InlineCostAnalyzer::getInlineFudgeFactor(CallSite CS) {
  Function *Callee = CS.getCalledFunction();
  
  // Get information about the callee...
  FunctionInfo &CalleeFI = CachedFunctionInfo[Callee];
  
  // If we haven't calculated this information yet, do so now.
  if (CalleeFI.Metrics.NumBlocks == 0)
    CalleeFI.analyzeFunction(Callee);

  float Factor = 1.0f;
  // Single BB functions are often written to be inlined.
  if (CalleeFI.Metrics.NumBlocks == 1)
    Factor += 0.5f;

  // Be more aggressive if the function contains a good chunk (if it mades up
  // at least 10% of the instructions) of vector instructions.
  if (CalleeFI.Metrics.NumVectorInsts > CalleeFI.Metrics.NumInsts/2)
    Factor += 2.0f;
  else if (CalleeFI.Metrics.NumVectorInsts > CalleeFI.Metrics.NumInsts/10)
    Factor += 1.5f;
  return Factor;
}
