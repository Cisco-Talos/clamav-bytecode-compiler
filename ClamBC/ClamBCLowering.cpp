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
#include "llvm/Support/CallSite.h"
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
  virtual const char *getPassName() const { return "ClamAV Bytecode Lowering"; }
  virtual bool runOnModule(Module &M);
  virtual void getAnalysisUsage(AnalysisUsage &AU) const {
//    AU.addRequired<TargetData>();
  }
private:
  bool final;
  void lowerIntrinsics(IntrinsicLowering *IL, Function &F);
  void simplifyOperands(Function &F);
  void downsizeIntrinsics(Function &F);
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
	    // assuming we what the operands to be precisely Int32Ty
            Instruction *IVI = dyn_cast<Instruction>(V);
            if (!IVI || (IVI->getOpcode() != Instruction::Sub &&
                         IVI->getOpcode() != Instruction::Mul)) {
	      if (IVI && isa<CastInst>(IVI))
		V = IVI->getOperand(0);

	      // take care of varying sizes
	      unsigned VSz = V->getType()->getPrimitiveSizeInBits();
	      Value *V2;
	      if (VSz < 32) {
		// needs zext, never sext (as index cannot be negative)
		V2 = Builder.CreateZExtOrBitCast(V, Type::getInt32Ty(C));
	      }
	      else if (VSz == 32) { //possible through CastInst path
		// pass-through
		V2 = V;
	      }
	      else { // VSz > 32
		// truncation
		V2 = Builder.CreateTrunc(V, Type::getInt32Ty(C));
	      }

	      // replace the operand with the 32-bit sized index
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

void replaceUses(Instruction *V2, Instruction *V, const Type *APTy)
{
    for (Value::use_iterator UI=V2->use_begin(),UE=V2->use_end();
	 UI != UE; ++UI) {
	Instruction *II = dyn_cast<BitCastInst>(*UI);
	if (!II) {
	    if (GetElementPtrInst *G = dyn_cast<GetElementPtrInst>(*UI)) {
		if (!G->hasAllZeroIndices())
		    continue;
		II = G;
	    } else
		continue;
	}
	replaceUses(II, V, APTy);
    }
    if (V2->use_empty()) {
	V2->eraseFromParent();
	return;
    }
    if (V->getType() != V2->getType()) {
	Instruction *BC = new BitCastInst(V, V2->getType(), "bcastrr");
	BC->insertAfter(V);
	V2->replaceAllUsesWith(BC);
    } else
	V2->replaceAllUsesWith(V);
}

void ClamBCLowering::simplifyOperands(Function &F)
{
  std::vector<Instruction *> InstDel;

  for (inst_iterator I=inst_begin(F),E=inst_end(F); I != E; ++I) {
    Instruction *II = &*I;
    if (SelectInst *SI = dyn_cast<SelectInst>(II)) {
      //Builder->SetInsertPoint(SI->getParent(), SI);
      std::vector<Value *> Ops;
      bool Changed = false;
      for (unsigned i = 0; i < II->getNumOperands(); ++i) {
        if (ConstantExpr *CE = dyn_cast<ConstantExpr>(II->getOperand(i))) {
          if (CE->getOpcode() == Instruction::GetElementPtr) {
	    // rip out GEP expr and load it
            Ops.push_back(new LoadInst(CE, "gepex_load", SI));
	    Changed = true;
          }
        }
	else {
	  Ops.push_back(II->getOperand(i));
	}
      }
      if (!Changed)
	continue;

      // generate new select instruction using loaded values
      assert(Ops.size() == 3 && "malformed selectInst has occurred!");
      SelectInst *NSI = SelectInst::Create(Ops[0], Ops[1], Ops[2],
				      "load_sel", SI);

      for (Value::use_iterator UI=SI->use_begin(),UE=SI->use_end();
	   UI != UE; ++UI) {
	if (LoadInst *LI = dyn_cast<LoadInst>(*UI)) {
	  // read it
	  replaceUses(LI, NSI, NULL);
	  
	  // push old LoadInst for deletion
	  InstDel.push_back(LI);
	}
	// TODO: handle StoreInst, CallInst, MemIntrinsicInst
	else {
	  assert(0 && "unhandled inst in simplying operands ClamAV Bytecode Lowering!");
	}
      }
      
      // push old SelectInst for deletion
      InstDel.push_back(SI);
    }
  }

  // delete obsolete instructions
  for (unsigned i = 0; i < InstDel.size(); ++i) {
    InstDel[i]->eraseFromParent();
  }
}

void ClamBCLowering::downsizeIntrinsics(Function &F)
{
  LLVMContext &Context = F.getContext();
  std::vector<Instruction *> InstDel;
  Function *MemCpy32 = NULL, *MemSet32 = NULL, *MemMove32 = NULL;

  const Type* MemCpyArgs [] = { Type::getInt32Ty(Context) };
  MemCpy32 = Intrinsic::getDeclaration(F.getParent(), Intrinsic::memcpy, MemCpyArgs, 1);
  const Type* MemSetArgs [] = { Type::getInt32Ty(Context) };
  MemSet32 = Intrinsic::getDeclaration(F.getParent(), Intrinsic::memset, MemSetArgs, 1);
  const Type* MemMoveArgs [] = { Type::getInt32Ty(Context) };
  MemMove32 = Intrinsic::getDeclaration(F.getParent(), Intrinsic::memmove, MemMoveArgs, 1);

  for (inst_iterator I=inst_begin(F),E=inst_end(F); I != E; ++I) {
    Instruction *II = &*I;
    if (MemIntrinsic *MI = dyn_cast<MemIntrinsic>(II)) {

      //errs() << *MI << "\n";

      StringRef FName = MI->getCalledFunction()->getName();

      /* TODO - needs to modified for newer intrinsic naming scheme */
      if (FName.equals("llvm.memcpy.i64") || FName.equals("llvm.memset.i64") ||
          FName.equals("llvm.memmove.i64")) {
        CallSite CS(MI);
        std::vector<Value *> Ops;

        Value *Len = CS.getArgument(2);
        Value *NewLen = NULL;
        if (ConstantInt *C = dyn_cast<ConstantInt>(Len)) {
            NewLen = ConstantInt::get(Type::getInt32Ty(Context), 
                                      C->getValue().getLimitedValue((1ULL<<32)-1));
        }
        else {
          NewLen = new TruncInst(Len, Type::getInt32Ty(Context), "lvl_dwn", MI);
        }

        for (unsigned i = 0; i < CS.arg_size(); ++i) {
          if (i == 2) {
            Ops.push_back(NewLen);
          }
          else {
            Ops.push_back(CS.getArgument(i));
          }
        }

        CallInst *NMI = NULL;
        if (FName.equals("llvm.memcpy.i64")) {
            assert(Ops.size() == 4 && "malformed MemCpyInst has occurred!");

            NMI = CallInst::Create(MemCpy32, Ops.begin(), Ops.end(), MI->getName(), MI);
        }
        else if (FName.equals("llvm.memset.i64")) {
            assert(Ops.size() == 4 && "malformed MemSetInst has occurred!");

            NMI = CallInst::Create(MemSet32, Ops.begin(), Ops.end(), MI->getName(), MI);
        }
        else if (FName.equals("llvm.memmove.i64")) {
            assert(Ops.size() == 4 && "malformed MemMoveInst has occurred!");

            NMI = CallInst::Create(MemMove32, Ops.begin(), Ops.end(), MI->getName(), MI);
        }
        else {
            /* impossible case */
        }

        if (!NMI)
            errs() << "failed to generated lowered intrinsic instruction!\n";
        //errs() << *NMI << "\n\n";
        //replaceUses(MI, NMI, NULL); /* memory intrinsics return void */
        InstDel.push_back(MI);
      }
      else {
          errs() << "unhandled memory intrinsic: " << FName << "\n";
      }
    }
  }

  for (unsigned i = 0; i < InstDel.size(); ++i) {
    InstDel[i]->eraseFromParent();
  }  
}

void ClamBCLowering::fixupBitCasts(Function &F)
{
  // bitcast of alloca doesn't work properly in libclamav,
  // so introduce an additional alloca of the correct type and load/store its
  // address.
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
      if (hasBitcastUse(AI))
        allocas.push_back(AI);
      ++J;
    } while (AI);
    ConstantInt *Zero = ConstantInt::get(Type::getInt32Ty(F.getContext()),
					 0);
    for (std::vector<AllocaInst*>::iterator J=allocas.begin(),JE=allocas.end();
         J != JE; ++J) {
      AllocaInst *AI = *J;
      Instruction *V = AI;
      if (AI->getAllocatedType()->isIntegerTy())
	  continue;
      const ArrayType *arTy = cast<ArrayType>(AI->getAllocatedType());
      const Type *APTy = PointerType::getUnqual(arTy->getElementType());

      Instruction *AIC = AI->clone();
      AIC->insertBefore(AI);
      BasicBlock::iterator IP = AI;
      while (isa<AllocaInst>(IP)) ++IP;
      Value *Idx[] = {Zero, Zero};
      V = GetElementPtrInst::Create(AIC, &Idx[0], &Idx[2], "base_gepz", IP);

      replaceUses(AI, V, APTy);
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
	    //const Type *ETy = PointerType::getUnqual(ATy->getElementType());
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
      simplifyOperands(*I);
      downsizeIntrinsics(*I);
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


