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
 *  along with this program; if not, write to the Free Softwaref
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */
#define DEBUG_TYPE "bclowering"
#include "llvm/System/DataTypes.h" 
#include "clambc.h"
#include "ClamBCModule.h"
#include "ClamBCTargetMachine.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/Analysis/ConstantFolding.h"
#include "llvm/Analysis/DebugInfo.h"
#include "llvm/Analysis/Dominators.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/Passes.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/Attributes.h"
#include "llvm/CallingConv.h"
#include "llvm/CodeGen/IntrinsicLowering.h"
#include "llvm/Config/config.h"
#include "llvm/Constants.h"
#include "llvm/DerivedTypes.h"
#include "llvm/Instructions.h"
#include "llvm/IntrinsicInst.h"
#include "llvm/Intrinsics.h"
#include "llvm/Module.h"
#include "llvm/Pass.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/GetElementPtrTypeIterator.h"
#include "llvm/Support/InstIterator.h"
#include "llvm/Support/InstVisitor.h"
#include "llvm/Support/FormattedStream.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/PatternMatch.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/CodeGen/IntrinsicLowering.h"

using namespace llvm;

namespace {
class ClamBCLowering : public ModulePass {
public:
  static char ID;
  ClamBCLowering(bool final) : ModulePass((uintptr_t)&ID), final(final) {}
  virtual bool runOnModule(Module &M);
  virtual void getAnalysisUsage(AnalysisUsage &AU) const {
//    AU.addRequired<TargetData>();
  }
private:
  bool final;
  void lowerIntrinsics(IntrinsicLowering *IL, Function &F);
  void splitGEPZArray(Function &F);
  void fixupBitCasts(Function &F);
  void fixupGEPs(Function &F);
  void fixupPtrToInts(Function &F);
};
char ClamBCLowering::ID=0;
void ClamBCLowering::lowerIntrinsics(IntrinsicLowering *IL, Function &F) {
  std::vector<Function*> prototypesToGen;
  IRBuilder<false> Builder(F.getContext());

  for (Function::iterator BB = F.begin(), EE = F.end(); BB != EE; ++BB)
    for (BasicBlock::iterator I = BB->begin(); I != BB->end(); ) {
      Instruction *II = &*I;
      ++I;
      if (CallInst *CI = dyn_cast<CallInst>(II)) {
        if (Function *F = CI->getCalledFunction()) {
          unsigned iid = F->getIntrinsicID();
          switch (iid) {
          default: break;
/*
            {
              Instruction *Before = 0;
              if (CI != &BB->front())
                Before = prior(BasicBlock::iterator(CI));
              IL->LowerIntrinsicCall(CI);
              if (Before) {
                I = Before; ++I;
              } else {
                I = BB->begin();
              }
              if (CallInst *Call = dyn_cast<CallInst>(I))
                if (Function *NewF = Call->getCalledFunction())
                  if (!NewF->isDeclaration())
                    prototypesToGen.push_back(NewF);
            }
*/
          case Intrinsic::memset:
          case Intrinsic::memcpy:
          case Intrinsic::memmove:
            /* these have opcodes associated */
            break;
          case Intrinsic::not_intrinsic:
            break;
          }
        }
      } else if (BinaryOperator *BO = dyn_cast<BinaryOperator>(II)) {
        if (BO->getOpcode() != BinaryOperator::Add)
          continue;
        PtrToIntInst *PII = 0;
        Value *Idx = 0;
        if (PtrToIntInst *P1 = dyn_cast<PtrToIntInst>(BO->getOperand(0))) {
          PII = P1;
          Idx = BO->getOperand(1);
        } else if (PtrToIntInst *P2 = dyn_cast<PtrToIntInst>(BO->getOperand(1))) {
          PII = P2;
          Idx = BO->getOperand(0);
        }
        if (!PII || !isa<IntegerType>(Idx->getType())
            || isa<PtrToIntInst>(Idx) ||
	    Idx->getType() == Type::getInt64Ty(F.getContext()))
          continue;
        Builder.SetInsertPoint(BO->getParent(), BO);
        Value *V = Builder.CreatePointerCast(PII->getOperand(0),
                                             PointerType::getUnqual(Type::getInt8Ty(F.getContext())));
        V = Builder.CreateGEP(V, Idx);
        V = Builder.CreatePtrToInt(V, BO->getType());
        BO->replaceAllUsesWith(V);
      } else if (GetElementPtrInst *GEPI = dyn_cast<GetElementPtrInst>(II)) {
        LLVMContext &C = GEPI->getContext();
        Builder.SetInsertPoint(GEPI->getParent(), GEPI);
        for (unsigned i=1;i<GEPI->getNumOperands();i++) {
          Value *V = GEPI->getOperand(i);
          if (V->getType() != Type::getInt32Ty(C)) {
            Instruction *IVI = dyn_cast<Instruction>(V);
            if (!IVI || (IVI->getOpcode() != Instruction::Sub &&
                         IVI->getOpcode() != Instruction::Mul)) {
	      if (IVI && isa<CastInst>(IVI))
		  V = IVI->getOperand(0);
              Value *V2 = Builder.CreateTrunc(V, Type::getInt32Ty(C));
              GEPI->setOperand(i, V2);
            }
/*
            // {s,z}ext i32 %foo to i64, getelementptr %ptr, i64 %sext ->
            // getelementptr %ptr, i32 %foo
            if (SExtInst *Ext = dyn_cast<SExtInst>(V))
              GEPI->setOperand(i, Ext->getOperand(0));
            if (ZExtInst *Ext = dyn_cast<ZExtInst>(V))
              GEPI->setOperand(i, Ext->getOperand(0));
            if (ConstantInt *CI = dyn_cast<ConstantInt>(V)) {
              GEPI->setOperand(i, ConstantExpr::getTrunc(CI,
                                                         Type::getInt32Ty(C)));
            }*/
          }
        }
      } else if (ICmpInst *ICI = dyn_cast<ICmpInst>(II)) {
        if (ConstantExpr *CE = dyn_cast<ConstantExpr>(ICI->getOperand(1))) {
          if (CE->getOpcode() != Instruction::IntToPtr)
            continue;
          Builder.SetInsertPoint(ICI->getParent(), ICI);

          Value *R = CE->getOperand(0);
          Value *L = Builder.CreatePtrToInt(ICI->getOperand(0), R->getType());
          Value *ICI2 = Builder.CreateICmp(ICI->getPredicate(), L, R);
          ICI->replaceAllUsesWith(ICI2);
        }
      } else if (PtrToIntInst *PI = dyn_cast<PtrToIntInst>(II)) {
        // ptrtoint (getelementptr i8* P0, V1)
	// -> add (ptrtoint P0), V1
        GetElementPtrInst *GEP = dyn_cast<GetElementPtrInst>(PI->getOperand(0));
        if (GEP && GEP->getNumOperands() == 2) {
	    Value *V1 = GEP->getOperand(1);
	    if (GEP->getType()->getElementType() == Type::getInt8Ty(F.getContext())) {
                Value *P0 = Builder.CreatePtrToInt(GEP->getOperand(0),
                                                   V1->getType());
                Value *A = Builder.CreateAdd(P0, V1);
		if (A->getType() != PI->getType())
		    A = Builder.CreateZExt(A, PI->getType());
		PI->replaceAllUsesWith(A);
		PI->eraseFromParent();
	    }
	}
      }
    }
}

// has non-noop bitcast use?
static bool hasBitcastUse(Instruction *I)
{
  if (!I)
    return false;
  for (Value::use_iterator UI=I->use_begin(),UE=I->use_end();
       UI != UE; ++UI) {
    if (BitCastInst *BCI = dyn_cast<BitCastInst>(*UI)) {
      if (BCI->getSrcTy() != BCI->getDestTy())
        return true;
    }
  }
  return false;
}

void ClamBCLowering::fixupBitCasts(Function &F)
{
  // bitcast of alloca doesn't work properly in libclamav,
  // so change these allocas to be arrays of 1 element, and gep into it.
  // that fixes the casts.
  for (Function::iterator I=F.begin(),E=F.end();
       I != E; ++I)
  {
    std::vector<AllocaInst*> allocas;
    BasicBlock::iterator J = I->begin();
    AllocaInst *AI;
    do {
      AI = dyn_cast<AllocaInst>(J);
      if (!AI)
        break;
      if (AI->isArrayAllocation() ||
	  isa<ArrayType>(AI->getAllocatedType())) {
//TODO: this workaround works for JIT but not interpreter
//	  ++J;
//	  continue;
      }
      if (hasBitcastUse(AI))
        allocas.push_back(AI);
      ++J;
    } while (AI);
    Instruction *InsertBefore = J;
    for (std::vector<AllocaInst*>::iterator J=allocas.begin(),JE=allocas.end();
         J != JE; ++J) {
      AllocaInst *AI = *J;
      const Type *Ty = ArrayType::get(AI->getAllocatedType(), 1);
      AllocaInst *NewAI = new AllocaInst(Ty, "", InsertBefore);
      Constant *Zero = ConstantInt::get(Type::getInt32Ty(Ty->getContext()), 0);
      Value *V[] = {
        Zero,
        Zero
      };
      Value *GEP = GetElementPtrInst::CreateInBounds(NewAI, &V[0], &V[0]+2, "", InsertBefore);
      AI->replaceAllUsesWith(GEP);
      AI->eraseFromParent();
    }
  }
}

void ClamBCLowering::fixupGEPs(Function &F)
{
  // GEP of a global/constantexpr hits a libclamav interpreter bug,
  // so instead create a constantexpression, store it and GEP that.
  std::vector<GetElementPtrInst*> geps;
  for (inst_iterator I=inst_begin(F),E=inst_end(F);
       I != E; ++I) {
    if (GetElementPtrInst *GEPI = dyn_cast<GetElementPtrInst>(&*I)) {
      if (isa<GlobalVariable>(GEPI->getOperand(0)))
        geps.push_back(GEPI);
    }
  }
  BasicBlock *Entry = &F.getEntryBlock();
  for (std::vector<GetElementPtrInst*>::iterator I=geps.begin(),E=geps.end();
       I != E; ++I) {
    GetElementPtrInst *GEPI = *I;
    std::vector<Value*> indexes;
    GetElementPtrInst::op_iterator J = GEPI->idx_begin(), JE = GEPI->idx_end();
    for (;J != JE; ++J) {
      // push all constants
      if (Constant *C = dyn_cast<Constant>(*J)) {
        indexes.push_back(C);
        continue;
      }
      // and a 0 instead of the first variable gep index
      indexes.push_back(ConstantInt::get(Type::getInt32Ty(GEPI->getContext()),
                                         0));
      break;
    }
    Constant *C = cast<Constant>(GEPI->getOperand(0));
    Constant *GC = ConstantExpr::getInBoundsGetElementPtr(C,
                                                          &indexes[0],
                                                          indexes.size());
    if (J != JE) {
      indexes.clear();
      for (;J != JE; ++J) {
        indexes.push_back(*J);
      }
      AllocaInst *AI = new AllocaInst(GC->getType(), "", Entry->begin());
      new StoreInst(GC, AI, GEPI);
      Value *L = new LoadInst(AI, "", GEPI);
      Value *V = GetElementPtrInst::CreateInBounds(L, indexes.begin(),
                                                   indexes.end(), "",
                                                   GEPI);
      GEPI->replaceAllUsesWith(V);
      GEPI->eraseFromParent();
    } else {
      GEPI->replaceAllUsesWith(GC);
    }
  }
}

void ClamBCLowering::fixupPtrToInts(Function &F)
{
    // we only have ptrtoint -> i64, not i32
    // so emit as ptrtoint -> 64, followed by trunc to i32
  const Type *I64Ty = Type::getInt64Ty(F.getContext());
  const Type *I32Ty = Type::getInt32Ty(F.getContext());
  std::vector<PtrToIntInst*> insts;
  for (inst_iterator I=inst_begin(F),E=inst_end(F);
       I != E; ++I) {
      if (PtrToIntInst *PI = dyn_cast<PtrToIntInst>(&*I)) {
	  if (PI->getType() != I64Ty)
	      insts.push_back(PI);
      }
  }
  IRBuilder<false> Builder(F.getContext());
  for (std::vector<PtrToIntInst*>::iterator I=insts.begin(),E=insts.end();
       I != E; ++I) {
      PtrToIntInst *PI = *I;
      Builder.SetInsertPoint(PI->getParent(), PI);
      Value *PI2 = Builder.CreatePtrToInt(PI->getOperand(0), I64Ty);
      Value *R = Builder.CreateTrunc(PI2, I32Ty);
      PI->replaceAllUsesWith(R);
      PI->eraseFromParent();
  }
}

void ClamBCLowering::splitGEPZArray(Function &F)
{
    for (inst_iterator I=inst_begin(F),E=inst_end(F);
	 I != E; )
    {
	Instruction *II = &*I;
	++I;
	if (GetElementPtrInst *GEPI = dyn_cast<GetElementPtrInst>(II)) {
	    if (GEPI->getNumIndices() != 2)
		continue;
	    ConstantInt *CI = dyn_cast<ConstantInt>(GEPI->getOperand(1));
	    if (!CI->isZero())
		continue;
	    CI = dyn_cast<ConstantInt>(GEPI->getOperand(2));
	    if (CI && CI->isZero())
		continue;
	    const PointerType *Ty = cast<PointerType>(GEPI->getPointerOperand()->getType());
	    const ArrayType *ATy = dyn_cast<ArrayType>(Ty->getElementType());
	    if (!ATy)
		continue;
	    const Type *ETy = PointerType::getUnqual(ATy->getElementType());
	    Value *V[] = { GEPI->getOperand(2) };
	    Constant *Zero = ConstantInt::get(Type::getInt32Ty(Ty->getContext()), 0);
	    Value *VZ[] = { Zero,  Zero };
	    // transform GEPZ: [4 x i16]* %p, 0, %i -> GEP1 i16* (bitcast)%p, %i
	    Value *C = GetElementPtrInst::CreateInBounds(GEPI->getPointerOperand(), &VZ[0], &VZ[0]+2, "", GEPI);
	    Value *NG = GetElementPtrInst::CreateInBounds(C, V, V+1, "", GEPI);
	    GEPI->replaceAllUsesWith(NG);
	    GEPI->eraseFromParent();
	}
    }
}

bool ClamBCLowering::runOnModule(Module &M)
{

//  TargetData &TD = getAnalysis<TargetData>();
  //IntrinsicLowering *IL = new IntrinsicLowering(TD);
  //IL->AddPrototypes(M);
  for (Module::iterator I=M.begin(),E=M.end();
       I != E; ++I) {
    if (I->isDeclaration())
      continue;
    lowerIntrinsics(0, *I);
    if (final) {
      fixupBitCasts(*I);
      fixupGEPs(*I);
      fixupPtrToInts(*I);
      splitGEPZArray(*I);
    }
  }
  //delete IL;
  return true;
}
}

llvm::ModulePass *createClamBCLowering(bool final) {
  return new ClamBCLowering(final);
}


