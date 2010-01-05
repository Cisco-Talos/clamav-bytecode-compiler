//===- InlineFunction.cpp - Code to perform function inlining -------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements inlining of a function into a call site, resolving
// parameters and the return value as appropriate.
//
//===----------------------------------------------------------------------===//

#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Constants.h"
#include "llvm/DerivedTypes.h"
#include "llvm/LLVMContext.h"
#include "llvm/Module.h"
#include "llvm/Instructions.h"
#include "llvm/IntrinsicInst.h"
#include "llvm/Intrinsics.h"
#include "llvm/Attributes.h"
#include "llvm/Analysis/CallGraph.h"
#include "llvm/Analysis/DebugInfo.h"
#include "llvm/Target/TargetData.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/Support/CallSite.h"
using namespace llvm;

bool llvm::InlineFunction(CallInst *CI, CallGraph *CG, const TargetData *TD,
                          SmallVectorImpl<AllocaInst*> *StaticAllocas) {
  return InlineFunction(CallSite(CI), CG, TD, StaticAllocas);
}
bool llvm::InlineFunction(InvokeInst *II, CallGraph *CG, const TargetData *TD,
                          SmallVectorImpl<AllocaInst*> *StaticAllocas) {
  return InlineFunction(CallSite(II), CG, TD, StaticAllocas);
}


/// HandleCallsInBlockInlinedThroughInvoke - When we inline a basic block into
/// an invoke, we have to turn all of the calls that can throw into
/// invokes.  This function analyze BB to see if there are any calls, and if so,
/// it rewrites them to be invokes that jump to InvokeDest and fills in the PHI
/// nodes in that block with the values specified in InvokeDestPHIValues.
///
static void HandleCallsInBlockInlinedThroughInvoke(BasicBlock *BB,
                                                   BasicBlock *InvokeDest,
                           const SmallVectorImpl<Value*> &InvokeDestPHIValues) {
  for (BasicBlock::iterator BBI = BB->begin(), E = BB->end(); BBI != E; ) {
    Instruction *I = BBI++;
    
    // We only need to check for function calls: inlined invoke
    // instructions require no special handling.
    CallInst *CI = dyn_cast<CallInst>(I);
    if (CI == 0) continue;
    
    // If this call cannot unwind, don't convert it to an invoke.
    if (CI->doesNotThrow())
      continue;
    
    // Convert this function call into an invoke instruction.
    // First, split the basic block.
    BasicBlock *Split = BB->splitBasicBlock(CI, CI->getName()+".noexc");
    
    // Next, create the new invoke instruction, inserting it at the end
    // of the old basic block.
    SmallVector<Value*, 8> InvokeArgs(CI->op_begin()+1, CI->op_end());
    InvokeInst *II =
      InvokeInst::Create(CI->getCalledValue(), Split, InvokeDest,
                         InvokeArgs.begin(), InvokeArgs.end(),
                         CI->getName(), BB->getTerminator());
    II->setCallingConv(CI->getCallingConv());
    II->setAttributes(CI->getAttributes());
    
    // Make sure that anything using the call now uses the invoke!  This also
    // updates the CallGraph if present.
    CI->replaceAllUsesWith(II);
    
    // Delete the unconditional branch inserted by splitBasicBlock
    BB->getInstList().pop_back();
    Split->getInstList().pop_front();  // Delete the original call
    
    // Update any PHI nodes in the exceptional block to indicate that
    // there is now a new entry in them.
    unsigned i = 0;
    for (BasicBlock::iterator I = InvokeDest->begin();
         isa<PHINode>(I); ++I, ++i)
      cast<PHINode>(I)->addIncoming(InvokeDestPHIValues[i], BB);
    
    // This basic block is now complete, the caller will continue scanning the
    // next one.
    return;
  }
}
  

/// HandleInlinedInvoke - If we inlined an invoke site, we need to convert calls
/// in the body of the inlined function into invokes and turn unwind
/// instructions into branches to the invoke unwind dest.
///
/// II is the invoke instruction being inlined.  FirstNewBlock is the first
/// block of the inlined code (the last block is the end of the function),
/// and InlineCodeInfo is information about the code that got inlined.
static void HandleInlinedInvoke(InvokeInst *II, BasicBlock *FirstNewBlock,
                                ClonedCodeInfo &InlinedCodeInfo) {
  BasicBlock *InvokeDest = II->getUnwindDest();
  SmallVector<Value*, 8> InvokeDestPHIValues;

  // If there are PHI nodes in the unwind destination block, we need to
  // keep track of which values came into them from this invoke, then remove
  // the entry for this block.
  BasicBlock *InvokeBlock = II->getParent();
  for (BasicBlock::iterator I = InvokeDest->begin(); isa<PHINode>(I); ++I) {
    PHINode *PN = cast<PHINode>(I);
    // Save the value to use for this edge.
    InvokeDestPHIValues.push_back(PN->getIncomingValueForBlock(InvokeBlock));
  }

  Function *Caller = FirstNewBlock->getParent();

  // The inlined code is currently at the end of the function, scan from the
  // start of the inlined code to its end, checking for stuff we need to
  // rewrite.  If the code doesn't have calls or unwinds, we know there is
  // nothing to rewrite.
  if (!InlinedCodeInfo.ContainsCalls && !InlinedCodeInfo.ContainsUnwinds) {
    // Now that everything is happy, we have one final detail.  The PHI nodes in
    // the exception destination block still have entries due to the original
    // invoke instruction.  Eliminate these entries (which might even delete the
    // PHI node) now.
    InvokeDest->removePredecessor(II->getParent());
    return;
  }
  
  for (Function::iterator BB = FirstNewBlock, E = Caller->end(); BB != E; ++BB){
    if (InlinedCodeInfo.ContainsCalls)
      HandleCallsInBlockInlinedThroughInvoke(BB, InvokeDest,
                                             InvokeDestPHIValues);

    if (UnwindInst *UI = dyn_cast<UnwindInst>(BB->getTerminator())) {
      // An UnwindInst requires special handling when it gets inlined into an
      // invoke site.  Once this happens, we know that the unwind would cause
      // a control transfer to the invoke exception destination, so we can
      // transform it into a direct branch to the exception destination.
      BranchInst::Create(InvokeDest, UI);

      // Delete the unwind instruction!
      UI->eraseFromParent();

      // Update any PHI nodes in the exceptional block to indicate that
      // there is now a new entry in them.
      unsigned i = 0;
      for (BasicBlock::iterator I = InvokeDest->begin();
           isa<PHINode>(I); ++I, ++i) {
        PHINode *PN = cast<PHINode>(I);
        PN->addIncoming(InvokeDestPHIValues[i], BB);
      }
    }
  }

  // Now that everything is happy, we have one final detail.  The PHI nodes in
  // the exception destination block still have entries due to the original
  // invoke instruction.  Eliminate these entries (which might even delete the
  // PHI node) now.
  InvokeDest->removePredecessor(II->getParent());
}

/// UpdateCallGraphAfterInlining - Once we have cloned code over from a callee
/// into the caller, update the specified callgraph to reflect the changes we
/// made.  Note that it's possible that not all code was copied over, so only
/// some edges of the callgraph may remain.
static void UpdateCallGraphAfterInlining(CallSite CS,
                                         Function::iterator FirstNewBlock,
                                       DenseMap<const Value*, Value*> &ValueMap,
                                         CallGraph &CG) {
  const Function *Caller = CS.getInstruction()->getParent()->getParent();
  const Function *Callee = CS.getCalledFunction();
  CallGraphNode *CalleeNode = CG[Callee];
  CallGraphNode *CallerNode = CG[Caller];

  // Since we inlined some uninlined call sites in the callee into the caller,
  // add edges from the caller to all of the callees of the callee.
  CallGraphNode::iterator I = CalleeNode->begin(), E = CalleeNode->end();

  // Consider the case where CalleeNode == CallerNode.
  CallGraphNode::CalledFunctionsVector CallCache;
  if (CalleeNode == CallerNode) {
    CallCache.assign(I, E);
    I = CallCache.begin();
    E = CallCache.end();
  }

  for (; I != E; ++I) {
    const Value *OrigCall = I->first;

    DenseMap<const Value*, Value*>::iterator VMI = ValueMap.find(OrigCall);
    // Only copy the edge if the call was inlined!
    if (VMI == ValueMap.end() || VMI->second == 0)
      continue;
    
    // If the call was inlined, but then constant folded, there is no edge to
    // add.  Check for this case.
    if (Instruction *NewCall = dyn_cast<Instruction>(VMI->second))
      CallerNode->addCalledFunction(CallSite::get(NewCall), I->second);
  }
  
  // Update the call graph by deleting the edge from Callee to Caller.  We must
  // do this after the loop above in case Caller and Callee are the same.
  CallerNode->removeCallEdgeFor(CS);
}

// InlineFunction - This function inlines the called function into the basic
// block of the caller.  This returns false if it is not possible to inline this
// call.  The program is still in a well defined state if this occurs though.
//
// Note that this only does one level of inlining.  For example, if the
// instruction 'call B' is inlined, and 'B' calls 'C', then the call to 'C' now
// exists in the instruction stream.  Similiarly this will inline a recursive
// function by one level.
//
bool llvm::InlineFunction(CallSite CS, CallGraph *CG, const TargetData *TD,
                          SmallVectorImpl<AllocaInst*> *StaticAllocas) {
  Instruction *TheCall = CS.getInstruction();
  LLVMContext &Context = TheCall->getContext();
  assert(TheCall->getParent() && TheCall->getParent()->getParent() &&
         "Instruction not in function!");

  const Function *CalledFunc = CS.getCalledFunction();
  if (CalledFunc == 0 ||          // Can't inline external function or indirect
      CalledFunc->isDeclaration() || // call, or call to a vararg function!
      CalledFunc->getFunctionType()->isVarArg()) return false;


  // If the call to the callee is not a tail call, we must clear the 'tail'
  // flags on any calls that we inline.
  bool MustClearTailCallFlags =
    !(isa<CallInst>(TheCall) && cast<CallInst>(TheCall)->isTailCall());

  // If the call to the callee cannot throw, set the 'nounwind' flag on any
  // calls that we inline.
  bool MarkNoUnwind = CS.doesNotThrow();

  BasicBlock *OrigBB = TheCall->getParent();
  Function *Caller = OrigBB->getParent();

  // GC poses two hazards to inlining, which only occur when the callee has GC:
  //  1. If the caller has no GC, then the callee's GC must be propagated to the
  //     caller.
  //  2. If the caller has a differing GC, it is invalid to inline.
  if (CalledFunc->hasGC()) {
    if (!Caller->hasGC())
      Caller->setGC(CalledFunc->getGC());
    else if (CalledFunc->getGC() != Caller->getGC())
      return false;
  }

  // Get an iterator to the last basic block in the function, which will have
  // the new function inlined after it.
  //
  Function::iterator LastBlock = &Caller->back();

  // Make sure to capture all of the return instructions from the cloned
  // function.
  SmallVector<ReturnInst*, 8> Returns;
  ClonedCodeInfo InlinedFunctionInfo;
  Function::iterator FirstNewBlock;

  { // Scope to destroy ValueMap after cloning.
    DenseMap<const Value*, Value*> ValueMap;

    assert(CalledFunc->arg_size() == CS.arg_size() &&
           "No varargs calls can be inlined!");

    // Calculate the vector of arguments to pass into the function cloner, which
    // matches up the formal to the actual argument values.
    CallSite::arg_iterator AI = CS.arg_begin();
    unsigned ArgNo = 0;
    for (Function::const_arg_iterator I = CalledFunc->arg_begin(),
         E = CalledFunc->arg_end(); I != E; ++I, ++AI, ++ArgNo) {
      Value *ActualArg = *AI;

      // When byval arguments actually inlined, we need to make the copy implied
      // by them explicit.  However, we don't do this if the callee is readonly
      // or readnone, because the copy would be unneeded: the callee doesn't
      // modify the struct.
      if (CalledFunc->paramHasAttr(ArgNo+1, Attribute::ByVal) &&
          !CalledFunc->onlyReadsMemory()) {
        const Type *AggTy = cast<PointerType>(I->getType())->getElementType();
        const Type *VoidPtrTy = 
            Type::getInt8PtrTy(Context);

        // Create the alloca.  If we have TargetData, use nice alignment.
        unsigned Align = 1;
        if (TD) Align = TD->getPrefTypeAlignment(AggTy);
        Value *NewAlloca = new AllocaInst(AggTy, 0, Align, 
                                          I->getName(), 
                                          &*Caller->begin()->begin());
        // Emit a memcpy.
        const Type *Tys[] = { Type::getInt64Ty(Context) };
        Function *MemCpyFn = Intrinsic::getDeclaration(Caller->getParent(),
                                                       Intrinsic::memcpy, 
                                                       Tys, 1);
        Value *DestCast = new BitCastInst(NewAlloca, VoidPtrTy, "tmp", TheCall);
        Value *SrcCast = new BitCastInst(*AI, VoidPtrTy, "tmp", TheCall);

        Value *Size;
        if (TD == 0)
          Size = ConstantExpr::getSizeOf(AggTy);
        else
          Size = ConstantInt::get(Type::getInt64Ty(Context),
                                         TD->getTypeStoreSize(AggTy));

        // Always generate a memcpy of alignment 1 here because we don't know
        // the alignment of the src pointer.  Other optimizations can infer
        // better alignment.
        Value *CallArgs[] = {
          DestCast, SrcCast, Size,
          ConstantInt::get(Type::getInt32Ty(Context), 1)
        };
        CallInst *TheMemCpy =
          CallInst::Create(MemCpyFn, CallArgs, CallArgs+4, "", TheCall);

        // If we have a call graph, update it.
        if (CG) {
          CallGraphNode *MemCpyCGN = CG->getOrInsertFunction(MemCpyFn);
          CallGraphNode *CallerNode = (*CG)[Caller];
          CallerNode->addCalledFunction(TheMemCpy, MemCpyCGN);
        }

        // Uses of the argument in the function should use our new alloca
        // instead.
        ActualArg = NewAlloca;
      }

      ValueMap[I] = ActualArg;
    }

    // We want the inliner to prune the code as it copies.  We would LOVE to
    // have no dead or constant instructions leftover after inlining occurs
    // (which can happen, e.g., because an argument was constant), but we'll be
    // happy with whatever the cloner can do.
    CloneAndPruneFunctionInto(Caller, CalledFunc, ValueMap, Returns, ".i",
                              &InlinedFunctionInfo, TD, TheCall);

    // Remember the first block that is newly cloned over.
    FirstNewBlock = LastBlock; ++FirstNewBlock;

    // Update the callgraph if requested.
    if (CG)
      UpdateCallGraphAfterInlining(CS, FirstNewBlock, ValueMap, *CG);
  }

  // If there are any alloca instructions in the block that used to be the entry
  // block for the callee, move them to the entry block of the caller.  First
  // calculate which instruction they should be inserted before.  We insert the
  // instructions at the end of the current alloca list.
  //
  {
    BasicBlock::iterator InsertPoint = Caller->begin()->begin();
    for (BasicBlock::iterator I = FirstNewBlock->begin(),
         E = FirstNewBlock->end(); I != E; ) {
      AllocaInst *AI = dyn_cast<AllocaInst>(I++);
      if (AI == 0) continue;
      
      // If the alloca is now dead, remove it.  This often occurs due to code
      // specialization.
      if (AI->use_empty()) {
        AI->eraseFromParent();
        continue;
      }

      if (!isa<Constant>(AI->getArraySize()))
        continue;
      
      // Keep track of the static allocas that we inline into the caller if the
      // StaticAllocas pointer is non-null.
      if (StaticAllocas) StaticAllocas->push_back(AI);
      
      // Scan for the block of allocas that we can move over, and move them
      // all at once.
      while (isa<AllocaInst>(I) &&
             isa<Constant>(cast<AllocaInst>(I)->getArraySize())) {
        if (StaticAllocas) StaticAllocas->push_back(cast<AllocaInst>(I));
        ++I;
      }

      // Transfer all of the allocas over in a block.  Using splice means
      // that the instructions aren't removed from the symbol table, then
      // reinserted.
      Caller->getEntryBlock().getInstList().splice(InsertPoint,
                                                   FirstNewBlock->getInstList(),
                                                   AI, I);
    }
  }

  // If the inlined code contained dynamic alloca instructions, wrap the inlined
  // code with llvm.stacksave/llvm.stackrestore intrinsics.
  if (InlinedFunctionInfo.ContainsDynamicAllocas) {
    Module *M = Caller->getParent();
    // Get the two intrinsics we care about.
    Function *StackSave = Intrinsic::getDeclaration(M, Intrinsic::stacksave);
    Function *StackRestore=Intrinsic::getDeclaration(M,Intrinsic::stackrestore);

    // If we are preserving the callgraph, add edges to the stacksave/restore
    // functions for the calls we insert.
    CallGraphNode *StackSaveCGN = 0, *StackRestoreCGN = 0, *CallerNode = 0;
    if (CG) {
      StackSaveCGN    = CG->getOrInsertFunction(StackSave);
      StackRestoreCGN = CG->getOrInsertFunction(StackRestore);
      CallerNode = (*CG)[Caller];
    }

    // Insert the llvm.stacksave.
    CallInst *SavedPtr = CallInst::Create(StackSave, "savedstack",
                                          FirstNewBlock->begin());
    if (CG) CallerNode->addCalledFunction(SavedPtr, StackSaveCGN);

    // Insert a call to llvm.stackrestore before any return instructions in the
    // inlined function.
    for (unsigned i = 0, e = Returns.size(); i != e; ++i) {
      CallInst *CI = CallInst::Create(StackRestore, SavedPtr, "", Returns[i]);
      if (CG) CallerNode->addCalledFunction(CI, StackRestoreCGN);
    }

    // Count the number of StackRestore calls we insert.
    unsigned NumStackRestores = Returns.size();

    // If we are inlining an invoke instruction, insert restores before each
    // unwind.  These unwinds will be rewritten into branches later.
    if (InlinedFunctionInfo.ContainsUnwinds && isa<InvokeInst>(TheCall)) {
      for (Function::iterator BB = FirstNewBlock, E = Caller->end();
           BB != E; ++BB)
        if (UnwindInst *UI = dyn_cast<UnwindInst>(BB->getTerminator())) {
          CallInst *CI = CallInst::Create(StackRestore, SavedPtr, "", UI);
          if (CG) CallerNode->addCalledFunction(CI, StackRestoreCGN);
          ++NumStackRestores;
        }
    }
  }

  // If we are inlining tail call instruction through a call site that isn't
  // marked 'tail', we must remove the tail marker for any calls in the inlined
  // code.  Also, calls inlined through a 'nounwind' call site should be marked
  // 'nounwind'.
  if (InlinedFunctionInfo.ContainsCalls &&
      (MustClearTailCallFlags || MarkNoUnwind)) {
    for (Function::iterator BB = FirstNewBlock, E = Caller->end();
         BB != E; ++BB)
      for (BasicBlock::iterator I = BB->begin(), E = BB->end(); I != E; ++I)
        if (CallInst *CI = dyn_cast<CallInst>(I)) {
          if (MustClearTailCallFlags)
            CI->setTailCall(false);
          if (MarkNoUnwind)
            CI->setDoesNotThrow();
        }
  }

  // If we are inlining through a 'nounwind' call site then any inlined 'unwind'
  // instructions are unreachable.
  if (InlinedFunctionInfo.ContainsUnwinds && MarkNoUnwind)
    for (Function::iterator BB = FirstNewBlock, E = Caller->end();
         BB != E; ++BB) {
      TerminatorInst *Term = BB->getTerminator();
      if (isa<UnwindInst>(Term)) {
        new UnreachableInst(Context, Term);
        BB->getInstList().erase(Term);
      }
    }

  // If we are inlining for an invoke instruction, we must make sure to rewrite
  // any inlined 'unwind' instructions into branches to the invoke exception
  // destination, and call instructions into invoke instructions.
  if (InvokeInst *II = dyn_cast<InvokeInst>(TheCall))
    HandleInlinedInvoke(II, FirstNewBlock, InlinedFunctionInfo);

  // If we cloned in _exactly one_ basic block, and if that block ends in a
  // return instruction, we splice the body of the inlined callee directly into
  // the calling basic block.
  if (Returns.size() == 1 && std::distance(FirstNewBlock, Caller->end()) == 1) {
    // Move all of the instructions right before the call.
    OrigBB->getInstList().splice(TheCall, FirstNewBlock->getInstList(),
                                 FirstNewBlock->begin(), FirstNewBlock->end());
    // Remove the cloned basic block.
    Caller->getBasicBlockList().pop_back();

    // If the call site was an invoke instruction, add a branch to the normal
    // destination.
    if (InvokeInst *II = dyn_cast<InvokeInst>(TheCall))
      BranchInst::Create(II->getNormalDest(), TheCall);

    // If the return instruction returned a value, replace uses of the call with
    // uses of the returned value.
    if (!TheCall->use_empty()) {
      ReturnInst *R = Returns[0];
      if (TheCall == R->getReturnValue())
        TheCall->replaceAllUsesWith(UndefValue::get(TheCall->getType()));
      else
        TheCall->replaceAllUsesWith(R->getReturnValue());
    }
    // Since we are now done with the Call/Invoke, we can delete it.
    TheCall->eraseFromParent();

    // Since we are now done with the return instruction, delete it also.
    Returns[0]->eraseFromParent();

    // We are now done with the inlining.
    return true;
  }

  // Otherwise, we have the normal case, of more than one block to inline or
  // multiple return sites.

  // We want to clone the entire callee function into the hole between the
  // "starter" and "ender" blocks.  How we accomplish this depends on whether
  // this is an invoke instruction or a call instruction.
  BasicBlock *AfterCallBB;
  if (InvokeInst *II = dyn_cast<InvokeInst>(TheCall)) {

    // Add an unconditional branch to make this look like the CallInst case...
    BranchInst *NewBr = BranchInst::Create(II->getNormalDest(), TheCall);

    // Split the basic block.  This guarantees that no PHI nodes will have to be
    // updated due to new incoming edges, and make the invoke case more
    // symmetric to the call case.
    AfterCallBB = OrigBB->splitBasicBlock(NewBr,
                                          CalledFunc->getName()+".exit");

  } else {  // It's a call
    // If this is a call instruction, we need to split the basic block that
    // the call lives in.
    //
    AfterCallBB = OrigBB->splitBasicBlock(TheCall,
                                          CalledFunc->getName()+".exit");
  }

  // Change the branch that used to go to AfterCallBB to branch to the first
  // basic block of the inlined function.
  //
  TerminatorInst *Br = OrigBB->getTerminator();
  assert(Br && Br->getOpcode() == Instruction::Br &&
         "splitBasicBlock broken!");
  Br->setOperand(0, FirstNewBlock);


  // Now that the function is correct, make it a little bit nicer.  In
  // particular, move the basic blocks inserted from the end of the function
  // into the space made by splitting the source basic block.
  Caller->getBasicBlockList().splice(AfterCallBB, Caller->getBasicBlockList(),
                                     FirstNewBlock, Caller->end());

  // Handle all of the return instructions that we just cloned in, and eliminate
  // any users of the original call/invoke instruction.
  const Type *RTy = CalledFunc->getReturnType();

  if (Returns.size() > 1) {
    // The PHI node should go at the front of the new basic block to merge all
    // possible incoming values.
    PHINode *PHI = 0;
    if (!TheCall->use_empty()) {
      PHI = PHINode::Create(RTy, TheCall->getName(),
                            AfterCallBB->begin());
      // Anything that used the result of the function call should now use the
      // PHI node as their operand.
      TheCall->replaceAllUsesWith(PHI);
    }

    // Loop over all of the return instructions adding entries to the PHI node
    // as appropriate.
    if (PHI) {
      for (unsigned i = 0, e = Returns.size(); i != e; ++i) {
        ReturnInst *RI = Returns[i];
        assert(RI->getReturnValue()->getType() == PHI->getType() &&
               "Ret value not consistent in function!");
        PHI->addIncoming(RI->getReturnValue(), RI->getParent());
      }
    
      // Now that we inserted the PHI, check to see if it has a single value
      // (e.g. all the entries are the same or undef).  If so, remove the PHI so
      // it doesn't block other optimizations.
      if (Value *V = PHI->hasConstantValue()) {
        PHI->replaceAllUsesWith(V);
        PHI->eraseFromParent();
      }
    }


    // Add a branch to the merge points and remove return instructions.
    for (unsigned i = 0, e = Returns.size(); i != e; ++i) {
      ReturnInst *RI = Returns[i];
      BranchInst::Create(AfterCallBB, RI);
      RI->eraseFromParent();
    }
  } else if (!Returns.empty()) {
    // Otherwise, if there is exactly one return value, just replace anything
    // using the return value of the call with the computed value.
    if (!TheCall->use_empty()) {
      if (TheCall == Returns[0]->getReturnValue())
        TheCall->replaceAllUsesWith(UndefValue::get(TheCall->getType()));
      else
        TheCall->replaceAllUsesWith(Returns[0]->getReturnValue());
    }

    // Splice the code from the return block into the block that it will return
    // to, which contains the code that was after the call.
    BasicBlock *ReturnBB = Returns[0]->getParent();
    AfterCallBB->getInstList().splice(AfterCallBB->begin(),
                                      ReturnBB->getInstList());

    // Update PHI nodes that use the ReturnBB to use the AfterCallBB.
    ReturnBB->replaceAllUsesWith(AfterCallBB);

    // Delete the return instruction now and empty ReturnBB now.
    Returns[0]->eraseFromParent();
    ReturnBB->eraseFromParent();
  } else if (!TheCall->use_empty()) {
    // No returns, but something is using the return value of the call.  Just
    // nuke the result.
    TheCall->replaceAllUsesWith(UndefValue::get(TheCall->getType()));
  }

  // Since we are now done with the Call/Invoke, we can delete it.
  TheCall->eraseFromParent();

  // We should always be able to fold the entry block of the function into the
  // single predecessor of the block...
  assert(cast<BranchInst>(Br)->isUnconditional() && "splitBasicBlock broken!");
  BasicBlock *CalleeEntry = cast<BranchInst>(Br)->getSuccessor(0);

  // Splice the code entry block into calling block, right before the
  // unconditional branch.
  OrigBB->getInstList().splice(Br, CalleeEntry->getInstList());
  CalleeEntry->replaceAllUsesWith(OrigBB);  // Update PHI nodes

  // Remove the unconditional branch.
  OrigBB->getInstList().erase(Br);

  // Now we can remove the CalleeEntry block, which is now empty.
  Caller->getBasicBlockList().erase(CalleeEntry);

  return true;
}
