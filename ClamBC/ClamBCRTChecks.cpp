/*
 *  Compile LLVM bytecode to ClamAV bytecode.
 *
 *  Copyright (C) 2009-2010 Sourcefire, Inc.
 *
 *  Authors: Török Edvin
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */
#define DEBUG_TYPE "clambc-rtcheck"
#include "ClamBCModule.h"
#include "llvm/ADT/PostOrderIterator.h"
#include "llvm/Analysis/Verifier.h"
#include "llvm/Analysis/DebugInfo.h"
#include "llvm/Analysis/Dominators.h"
#include "llvm/Analysis/ConstantFolding.h"
#include "llvm/Analysis/LiveValues.h"
#include "llvm/Analysis/PointerTracking.h"
#include "llvm/Analysis/ScalarEvolution.h"
#include "llvm/Analysis/ScalarEvolutionExpressions.h"
#include "llvm/Analysis/ScalarEvolutionExpander.h"
#include "llvm/Config/config.h"
#include "llvm/DerivedTypes.h"
#include "llvm/Instructions.h"
#include "llvm/IntrinsicInst.h"
#include "llvm/Intrinsics.h"
#include "llvm/LLVMContext.h"
#include "llvm/Module.h"
#include "llvm/Pass.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/DataFlow.h"
#include "llvm/Support/InstIterator.h"
#include "llvm/Support/InstVisitor.h"
#include "llvm/Support/GetElementPtrTypeIterator.h"
#include "llvm/ADT/DepthFirstIterator.h"
#include "llvm/Target/TargetData.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Support/Debug.h"

using namespace llvm;
namespace {

  class PtrVerifier : public FunctionPass {
  public:
    static char ID;
    PtrVerifier() : FunctionPass((intptr_t)&ID) {}

    virtual bool runOnFunction(Function &F) {
      DEBUG(F.dump());
      Changed = false;
      BaseMap.clear();
      BoundsMap.clear();
      AbrtBB = 0;
      valid = true;

      BasicBlock::iterator It = F.getEntryBlock().begin();
      while (isa<AllocaInst>(It) || isa<PHINode>(It)) ++It;
      EP = &*It;

      TD = &getAnalysis<TargetData>();
      SE = &getAnalysis<ScalarEvolution>();
      PT = &getAnalysis<PointerTracking>();
      DT = &getAnalysis<DominatorTree>();

      std::vector<Instruction*> insns;

      for (inst_iterator I=inst_begin(F),E=inst_end(F); I != E;++I) {
        Instruction *II = &*I;
        if (isa<LoadInst>(II) || isa<StoreInst>(II) || isa<MemIntrinsic>(II))
          insns.push_back(II);
        if (CallInst *CI = dyn_cast<CallInst>(II)) {
          Value *V = CI->getCalledValue()->stripPointerCasts();
          Function *F = dyn_cast<Function>(V);
          if (!F) {
            printLocation(errs(), CI);
            errs() << "Could not determine call target\n";
            valid = 0;
            continue;
          }
          if (!F->isDeclaration())
            continue;
          insns.push_back(CI);
        }
      }
      while (!insns.empty()) {
        Instruction *II = insns.back();
        insns.pop_back();
        DEBUG(dbgs() << "checking " << *II << "\n");
        if (LoadInst *LI = dyn_cast<LoadInst>(II)) {
          const Type *Ty = LI->getType();
          valid &= validateAccess(LI->getPointerOperand(),
                                  TD->getTypeAllocSize(Ty), LI);
        } else if (StoreInst *SI = dyn_cast<StoreInst>(II)) {
          const Type *Ty = SI->getOperand(0)->getType();
          valid &= validateAccess(SI->getPointerOperand(),
                                  TD->getTypeAllocSize(Ty), SI);
        } else if (MemIntrinsic *MI = dyn_cast<MemIntrinsic>(II)) {
          valid &= validateAccess(MI->getDest(), MI->getLength(), MI);
          if (MemTransferInst *MTI = dyn_cast<MemTransferInst>(MI)) {
            valid &= validateAccess(MTI->getSource(), MI->getLength(), MI);
          }
        } else if (CallInst *CI = dyn_cast<CallInst>(II)) {
          Value *V = CI->getCalledValue()->stripPointerCasts();
          Function *F = cast<Function>(V);
          const FunctionType *FTy = F->getFunctionType();
          if (F->getName().equals("memcmp") && FTy->getNumParams() == 3) {
            valid &= validateAccess(CI->getOperand(1), CI->getOperand(3), CI);
            valid &= validateAccess(CI->getOperand(2), CI->getOperand(3), CI);
            continue;
          }
          for (unsigned i=0;i<FTy->getNumParams();i++) {
            if (isa<PointerType>(FTy->getParamType(i))) {
              Value *Ptr = CI->getOperand(i+1);
              if (i+1 >= FTy->getNumParams()) {
                printLocation(errs(), CI);
                errs() << "Call to external function with pointer parameter last cannot be analyzed\n";
                errs() << *CI << "\n";
                valid = 0;
                break;
              }
              Value *Size = CI->getOperand(i+2);
              if (!Size->getType()->isIntegerTy()) {
                printLocation(errs(), CI);
                errs() << "Pointer argument must be followed by integer argument representing its size\n";
                errs() << *CI << "\n";
                valid = 0;
                break;
              }
              valid &= validateAccess(Ptr, Size, CI);
            }
          }
        }
      }

      if (!valid) {
	DEBUG(F.dump());
        ClamBCModule::stop("Verification found errors!", &F, 0);	
	// replace function with call to abort
        std::vector<const Type*>args;
        FunctionType* abrtTy = FunctionType::get(
          Type::getVoidTy(F.getContext()),args,false);
        Constant *func_abort =
          F.getParent()->getOrInsertFunction("abort", abrtTy);

	BasicBlock *BB = &F.getEntryBlock();
	Instruction *I = &*BB->begin();
	Instruction *UI = new UnreachableInst(F.getContext(), I);
	CallInst *AbrtC = CallInst::Create(func_abort, "", UI);
        AbrtC->setCallingConv(CallingConv::C);
        AbrtC->setTailCall(true);
        AbrtC->setDoesNotReturn(true);
        AbrtC->setDoesNotThrow(true);
	// remove all instructions from entry
	BasicBlock::iterator BBI = I, BBE=BB->end();
	while (BBI != BBE) {
	    if (!BBI->use_empty())
		BBI->replaceAllUsesWith(UndefValue::get(BBI->getType()));
	    BB->getInstList().erase(BBI++);
	}
      }
      return Changed;
    }

    virtual void getAnalysisUsage(AnalysisUsage &AU) const {
      AU.addRequired<TargetData>();
      AU.addRequired<DominatorTree>();
      AU.addRequired<ScalarEvolution>();
      AU.addRequired<PointerTracking>();
    }

    bool isValid() const { return valid; }
  private:
    PointerTracking *PT;
    TargetData *TD;
    ScalarEvolution *SE;
    DominatorTree *DT;
    DenseMap<Value*, Value*> BaseMap;
    DenseMap<Value*, Value*> BoundsMap;
    BasicBlock *AbrtBB;
    bool Changed;
    bool valid;
    Instruction *EP;

    Instruction *getInsertPoint(Value *V)
    {
      BasicBlock::iterator It =  EP;
      if (Instruction *I = dyn_cast<Instruction>(V)) {
        It = I;
        ++It;
      }
      return &*It;
    }

    Value *getPointerBase(Value *Ptr)
    {
      if (BaseMap.count(Ptr))
        return BaseMap[Ptr];
      Value *P = Ptr->stripPointerCasts();
      if (BaseMap.count(P)) {
        return BaseMap[Ptr] = BaseMap[P];
      }
      Value *P2 = P->getUnderlyingObject();
      if (P2 != P) {
        Value *V = getPointerBase(P2);
        return BaseMap[Ptr] = V;
      }

      const Type *P8Ty =
        PointerType::getUnqual(Type::getInt8Ty(Ptr->getContext()));
      if (PHINode *PN = dyn_cast<PHINode>(Ptr)) {
        BasicBlock::iterator It = PN;
        ++It;
        PHINode *newPN = PHINode::Create(P8Ty, ".verif.base", &*It);
        Changed = true;
        BaseMap[Ptr] = newPN;

        for (unsigned i=0;i<PN->getNumIncomingValues();i++) {
          Value *Inc = PN->getIncomingValue(i);
          Value *V = getPointerBase(Inc);
          newPN->addIncoming(V, PN->getIncomingBlock(i));
        }
        return newPN;
      }
      if (SelectInst *SI = dyn_cast<SelectInst>(Ptr)) {
        BasicBlock::iterator It = SI;
        ++It;
        Value *TrueB = getPointerBase(SI->getTrueValue());
        Value *FalseB = getPointerBase(SI->getFalseValue());
        if (TrueB && FalseB) {
          SelectInst *NewSI = SelectInst::Create(SI->getCondition(), TrueB,
                                                 FalseB, ".select.base", &*It);
          Changed = true;
          return BaseMap[Ptr] = NewSI;
        }
      }
      if (Ptr->getType() != P8Ty) {
        if (Constant *C = dyn_cast<Constant>(Ptr))
          Ptr = ConstantExpr::getPointerCast(C, P8Ty);
        else {
          Instruction *I = getInsertPoint(Ptr);
          Ptr = new BitCastInst(Ptr, P8Ty, "", I);
        }
      }
      return BaseMap[Ptr] = Ptr;
    }

    Value* getPointerBounds(Value *Base) {
      if (BoundsMap.count(Base))
        return BoundsMap[Base];
      const Type *I64Ty =
        Type::getInt64Ty(Base->getContext());
      if (PHINode *PN = dyn_cast<PHINode>(Base)) {
        BasicBlock::iterator It = PN;
        ++It;
        PHINode *newPN = PHINode::Create(I64Ty, ".verif.bounds", &*It);
        Changed = true;
        BoundsMap[Base] = newPN;

        bool good = true;
        for (unsigned i=0;i<PN->getNumIncomingValues();i++) {
          Value *Inc = PN->getIncomingValue(i);
          Value *B = getPointerBounds(Inc);
          if (!B) {
            good = false;
            B = ConstantInt::get(newPN->getType(), 0);
            DEBUG(dbgs() << "bounds not found while solving phi node: " << *Inc
                  << "\n");
          }
          newPN->addIncoming(B, PN->getIncomingBlock(i));
        }
        if (!good)
          newPN = 0;
        return BoundsMap[Base] = newPN;
      }
      if (SelectInst *SI = dyn_cast<SelectInst>(Base)) {
        BasicBlock::iterator It = SI;
        ++It;
        Value *TrueB = getPointerBounds(SI->getTrueValue());
        Value *FalseB = getPointerBounds(SI->getFalseValue());
        if (TrueB && FalseB) {
          SelectInst *NewSI = SelectInst::Create(SI->getCondition(), TrueB,
                                                 FalseB, ".select.bounds", &*It);
          Changed = true;
          return BoundsMap[Base] = NewSI;
        }
      }

      const Type *Ty;
      Value *V = PT->computeAllocationCountValue(Base, Ty);
      if (!V) {
	  Base = Base->stripPointerCasts();
	  if (CallInst *CI = dyn_cast<CallInst>(Base)) {
	      Function *F = CI->getCalledFunction();
              const FunctionType *FTy = F->getFunctionType();
              // last operand is always size for this API call kind
              if (F->isDeclaration() && FTy->getNumParams() > 0) {
                if (FTy->getParamType(FTy->getNumParams()-1)->isIntegerTy())
                  V = CI->getOperand(FTy->getNumParams());
              }
	  }
	  if (!V)
	      return BoundsMap[Base] = 0;
      } else {
        unsigned size = TD->getTypeAllocSize(Ty);
        if (size > 1) {
          Constant *C = cast<Constant>(V);
          C = ConstantExpr::getMul(C,
                                   ConstantInt::get(Type::getInt32Ty(C->getContext()),
                                                    size));
          V = C;
        }
      }
      if (V->getType() != I64Ty) {
        if (Constant *C = dyn_cast<Constant>(V))
          V = ConstantExpr::getZExt(C, I64Ty);
        else {
          Instruction *I = getInsertPoint(V);
          V = new ZExtInst(V, I64Ty, "", I);
        }
      }
      return BoundsMap[Base] = V;
    }

    bool insertCheck(const SCEV *Idx, const SCEV *Limit, Instruction *I)
    {
      if (isa<SCEVCouldNotCompute>(Idx) && isa<SCEVCouldNotCompute>(Limit)) {
        errs() << "Could not compute the index and the limit!: \n" << *I << "\n";
        return false;
      }
      if (isa<SCEVCouldNotCompute>(Idx)) {
        errs() << "Could not compute index: \n" << *I << "\n";
        return false;
      }
      if (isa<SCEVCouldNotCompute>(Limit)) {
        errs() << "Could not compute limit: " << *I << "\n";
        return false;
      }
      BasicBlock *BB = I->getParent();
      BasicBlock::iterator It = I;
      BasicBlock *newBB = SplitBlock(BB, &*It, this);
      PHINode *PN;
      //verifyFunction(*BB->getParent());
      if (!AbrtBB) {
        std::vector<const Type*>args;
        FunctionType* abrtTy = FunctionType::get(
          Type::getVoidTy(BB->getContext()),args,false);
        args.push_back(Type::getInt32Ty(BB->getContext()));
//        FunctionType* rterrTy = FunctionType::get(
//          Type::getInt32Ty(BB->getContext()),args,false);
        Constant *func_abort =
          BB->getParent()->getParent()->getOrInsertFunction("abort", abrtTy);
//        Constant *func_rterr =
//          BB->getParent()->getParent()->getOrInsertFunction("bytecode_rt_error", rterrTy);
        AbrtBB = BasicBlock::Create(BB->getContext(), "", BB->getParent());
        PN = PHINode::Create(Type::getInt32Ty(BB->getContext()),"",
                                      AbrtBB);
//        CallInst *RtErrCall = CallInst::Create(func_rterr, PN, "", AbrtBB);
        CallInst* AbrtC = CallInst::Create(func_abort, "", AbrtBB);
        AbrtC->setCallingConv(CallingConv::C);
        AbrtC->setTailCall(true);
        AbrtC->setDoesNotReturn(true);
        AbrtC->setDoesNotThrow(true);
        new UnreachableInst(BB->getContext(), AbrtBB);
        DT->addNewBlock(AbrtBB, BB);
        //verifyFunction(*BB->getParent());
      } else {
        PN = cast<PHINode>(AbrtBB->begin());
      }
      unsigned MDDbgKind = I->getContext().getMDKindID("dbg");
      unsigned locationid = 0;
      if (MDNode *Dbg = I->getMetadata(MDDbgKind)) {
        DILocation Loc(Dbg);
        locationid = Loc.getLineNumber() << 8;
        unsigned col = Loc.getColumnNumber();
        if (col > 255)
          col = 255;
        locationid |= col;
//      Loc.getFilename();
      }
      PN->addIncoming(ConstantInt::get(Type::getInt32Ty(BB->getContext()),
                                       locationid), BB);

      TerminatorInst *TI = BB->getTerminator();
      SCEVExpander expander(*SE);
      Value *IdxV = expander.expandCodeFor(Idx, Limit->getType(), TI);
/*      if (isa<PointerType>(IdxV->getType())) {
        IdxV = new PtrToIntInst(IdxV, Idx->getType(), "", TI);
      }*/
      //verifyFunction(*BB->getParent());
      Value *LimitV = expander.expandCodeFor(Limit, Limit->getType(), TI);
      //verifyFunction(*BB->getParent());
      Value *Cond = new ICmpInst(TI, ICmpInst::ICMP_ULT, IdxV, LimitV);
      //verifyFunction(*BB->getParent());
      BranchInst::Create(newBB, AbrtBB, Cond, TI);
      TI->eraseFromParent();
      // Update dominator info
      BasicBlock *DomBB =
        DT->findNearestCommonDominator(BB,
                                       DT->getNode(AbrtBB)->getIDom()->getBlock());
      DT->changeImmediateDominator(AbrtBB, DomBB);
      //verifyFunction(*BB->getParent());
      return true;
    }
   
    static void MakeCompatible(ScalarEvolution *SE, const SCEV*& LHS, const SCEV*& RHS) 
    {
      if (const SCEVZeroExtendExpr *ZL = dyn_cast<SCEVZeroExtendExpr>(LHS))
        LHS = ZL->getOperand();
      if (const SCEVZeroExtendExpr *ZR = dyn_cast<SCEVZeroExtendExpr>(RHS))
        RHS = ZR->getOperand();

      const Type* LTy = SE->getEffectiveSCEVType(LHS->getType());
      const Type *RTy = SE->getEffectiveSCEVType(RHS->getType());
      if (SE->getTypeSizeInBits(RTy) > SE->getTypeSizeInBits(LTy))
        LTy = RTy;
      LHS = SE->getNoopOrZeroExtend(LHS, LTy);
      RHS = SE->getNoopOrZeroExtend(RHS, LTy);
    }
    bool checkCondition(CallInst *CI, Instruction *I)
    {
      for (Value::use_iterator U=CI->use_begin(),UE=CI->use_end();
           U != UE; ++U) {
        if (ICmpInst *ICI = dyn_cast<ICmpInst>(U)) {
          if (ICI->getOperand(0)->stripPointerCasts() == CI &&
              isa<ConstantPointerNull>(ICI->getOperand(1))) {
            for (Value::use_iterator JU=ICI->use_begin(),JUE=ICI->use_end();
                 JU != JUE; ++JU) {
              if (BranchInst *BI = dyn_cast<BranchInst>(JU)) {
                if (!BI->isConditional())
                  continue;
                BasicBlock *S = BI->getSuccessor(ICI->getPredicate() ==
                                                 ICmpInst::ICMP_EQ);
                if (DT->dominates(S, I->getParent()))
                  return true;
              }
            }
          }
        }
      }
      return false;
    }
    static void printValue(llvm::raw_ostream &Out, llvm::Value *V) {
      std::string DisplayName;
      std::string Type;
      unsigned Line;
      std::string File;
      std::string Dir;
      if (!getLocationInfo(V, DisplayName, Type, Line, File, Dir)) {
        Out << *V << "\n";
        return;
      }
      Out << "'" << DisplayName << "' (" << File << ":" << Line << ")";
    }

    static void printLocation(llvm::raw_ostream &Out, llvm::Instruction *I) {
      if (MDNode *N = I->getMetadata("dbg")) {
        DILocation Loc(N);
        Out << Loc.getFilename() << ":" << Loc.getLineNumber();
        if (unsigned Col = Loc.getColumnNumber()) {
          Out << ":" << Col;
        }
        Out << ": ";
        return;
      }
      Out << *I << ":\n";
    }

    bool validateAccess(Value *Pointer, Value *Length, Instruction *I)
    {
        // get base
        Value *Base = getPointerBase(Pointer);

	Value *SBase = Base->stripPointerCasts();
        // get bounds
        Value *Bounds = getPointerBounds(SBase);
        if (!Bounds) {
          printLocation(errs(), I);
          errs() << "no bounds for base ";
          printValue(errs(), SBase);
          errs() << " while checking access to ";
          printValue(errs(), Pointer);
          errs() << " of length ";
          printValue(errs(), Length);
          errs() << "\n";

          return false;
        }

        if (CallInst *CI = dyn_cast<CallInst>(Base->stripPointerCasts())) {
          if (I->getParent() == CI->getParent()) {
            printLocation(errs(), I);
            errs() << "no null pointer check of pointer ";
            printValue(errs(), Base);
            errs() << " obtained by function call";
            errs() << " before use in same block\n";
            return false;
          }
          if (!checkCondition(CI, I)) {
            printLocation(errs(), I);
            errs() << "no null pointer check of pointer ";
            printValue(errs(), Base);
            errs() << " obtained by function call";
            errs() << " before use\n";
            return false;
          }
        }

        const Type *I64Ty =
          Type::getInt64Ty(Base->getContext());
        const SCEV *SLen = SE->getSCEV(Length);
        const SCEV *OffsetP = SE->getMinusSCEV(SE->getSCEV(Pointer),
                                               SE->getSCEV(Base));
        SLen = SE->getNoopOrZeroExtend(SLen, I64Ty);
        OffsetP = SE->getNoopOrZeroExtend(OffsetP, I64Ty);
        const SCEV *Limit = SE->getSCEV(Bounds);
        Limit = SE->getNoopOrZeroExtend(Limit, I64Ty);

        DEBUG(dbgs() << "Checking access to " << *Pointer << " of length " <<
              *Length << "\n");
        if (OffsetP == Limit)
          return true;

        if (SLen == Limit) {
          if (const SCEVConstant *SC = dyn_cast<SCEVConstant>(OffsetP)) {
            if (SC->isZero())
              return true;
          }
          errs() << "SLen == Limit: " << *SLen << "\n";
          errs() << " while checking access to " << *Pointer << " of length "
            << *Length << " at " << *I << "\n";
          return false;//TODO: insert abort
        }

        const SCEV *MaxL = SE->getUMaxExpr(SLen, Limit);
        if (MaxL != Limit) {
          DEBUG(dbgs() << "MaxL != Limit: " << *MaxL << ", " << *Limit << "\n");
          return insertCheck(SLen, Limit, I);
        }

        //TODO: nullpointer check
        const SCEV *Max = SE->getUMaxExpr(OffsetP, Limit);
        if (Max == Limit)
          return true;
        DEBUG(dbgs() << "Max != Limit: " << *Max << ", " << *Limit << "\n");

        return insertCheck(OffsetP, Limit, I);
    }

    bool validateAccess(Value *Pointer, unsigned size, Instruction *I)
    {
      return validateAccess(Pointer,
                            ConstantInt::get(Type::getInt32Ty(Pointer->getContext()),
                                             size), I);
    }

  };
  char PtrVerifier::ID;

}

llvm::Pass *createClamBCRTChecks()
{
  return new PtrVerifier();
}
