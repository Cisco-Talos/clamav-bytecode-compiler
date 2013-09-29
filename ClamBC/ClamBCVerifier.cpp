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
#include "ClamBCDiagnostics.h"
#include "ClamBCModule.h"
#include "llvm/Analysis/Verifier.h"
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
#include "llvm/Module.h"
#include "llvm/Pass.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/DataFlow.h"
#include "llvm/Support/InstIterator.h"
#include "llvm/Support/InstVisitor.h"
#include "llvm/Support/GetElementPtrTypeIterator.h"
#include "llvm/ADT/DepthFirstIterator.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"


// TODO: we should use this verifier in libclamav too for freshclam/sigtool.
using namespace llvm;
static cl::opt<bool>
StopOnFirstError("clambc-stopfirst",cl::init(false),
                 cl::desc("Stop on first error in the verifier"));
namespace {
class ClamBCVerifier : public FunctionPass,
  public InstVisitor<ClamBCVerifier,bool> {

    ScalarEvolution *SE;
    PointerTracking *PT;
    DominatorTree *DT;
    BasicBlock *AbrtBB;
    bool Final;

    friend class InstVisitor<ClamBCVerifier,bool>;

    bool visitUnreachableInst(UnreachableInst &I)
    {
      return true;
    }

    bool visitAllocaInst(AllocaInst &I)
    {
      return true;
    }
    bool visitCastInst(CastInst &I)
    {
      return true;
    }
    bool visitSelectInst(SelectInst &I)
    {
      return true;
    }
    bool visitBranchInst(BranchInst &BI)
    {
      return true;
    }
    bool visitSwitchInst(SwitchInst &I)
    {
      printDiagnostic("Need to lower switchInst's to branches", &I);
      return false;
    }
    bool visitBinaryOperator(Instruction &I)
    {
      return true;
    }
    bool visitReturnInst(ReturnInst &I)
    {
      return true;
    }
    bool visitICmpInst(ICmpInst &I)
    {
      return true;
    }
    bool visitCallInst(CallInst &CI) {
      Function *F = CI.getCalledFunction();
      if (!F) {
        printDiagnostic("Indirect call checking not implemented yet!", &CI);
        return false;
      }
      if (F->getCallingConv() != CI.getCallingConv()) {
        printDiagnostic("Calling conventions don't match!", &CI);
        return false;
      }
      if (F->isVarArg()) {
        if (!F->getFunctionType()->getNumParams())
          printDiagnostic(("Calling implicitly declared function '" +
                           F->getName()+ "' is not supported (did you forget to"
                           "implement it, or typoed the function name?)").str(),
                          &CI);
        else
          printDiagnostic("Checking calls to vararg functions/functions without"
                          "a prototype is not supported!", &CI);
        return false;
      }
      return true;
    }

    bool visitPHINode(PHINode &PN)
    {
      for (unsigned i=0;i<PN.getNumIncomingValues();i++) {
        if (isa<UndefValue>(PN.getIncomingValue(i))) {
          const Module *M = PN.getParent()->getParent()->getParent();
          printDiagnosticValue("Undefined value in phi", M, &PN);
          break;
        }
      }
      return true;
    }

    bool visitInstruction(Instruction &I) {
      printDiagnostic("Unhandled instruction in verifier", &I);
      return false;
    }

    bool checkLimits(const SCEV *I, const SCEV *Limit, BasicBlock *BB)
    {
      return PT->checkLimits(I, Limit, BB) == AlwaysTrue;
    }

    const SCEV *getPointerSize(Value *V)
    {
      return PT->getAllocationElementCount(V);
    }

    // returns the basicblock that dominates all uses of I.
    BasicBlock *findDomBB(Instruction *II)
    {
      SmallSet<BasicBlock*, 2> useBB;
      for (Value::use_iterator UI=II->use_begin(), UE=II->use_end(); UI != UE; ++UI) {
        if (Instruction *I = dyn_cast<Instruction>(UI))      
          useBB.insert(I->getParent());
      }
      BasicBlock *BB = 0;
      for (SmallSet<BasicBlock*, 2>::iterator I=useBB.begin(), E=useBB.end(); 
           I != E; ++I)
      {
        if (!BB)
          BB = *I;
        else {
          BB = DT->findNearestCommonDominator(BB, *I);
          if (!BB)
            return II->getParent();// fallback, shouldn't happen, entry block should always dominate
        }
      }
      return BB;
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
    bool insertCheck(const SCEV *Idx, const SCEV *Limit, Instruction *I)
    {
      if (isa<SCEVCouldNotCompute>(Idx) && isa<SCEVCouldNotCompute>(Limit)) {
        errs() << "Could not compute the index and the limit!\n";
        return false;
      }
      if (isa<SCEVCouldNotCompute>(Idx)) {
        errs() << "Could not compute index\n";
        return false;
      }
      if (isa<SCEVCouldNotCompute>(Limit)) {
        errs() << "Could not compute limit!\n";
        return false;
      }
      MakeCompatible(SE, Idx, Limit);
      BasicBlock *BB = I->getParent();
      BasicBlock::iterator It = I;
      BasicBlock *newBB = SplitBlock(BB, &*It, this);
      verifyFunction(*BB->getParent());
      if (!AbrtBB) {
        std::vector<const Type*>args;
        FunctionType* abrtTy = FunctionType::get(
          Type::getVoidTy(BB->getContext()),args,false);
        Constant *func_abort =
          BB->getParent()->getParent()->getOrInsertFunction("abort", abrtTy);
        AbrtBB = BasicBlock::Create(BB->getContext(), "", BB->getParent());
        CallInst* AbrtC = CallInst::Create(func_abort, "", AbrtBB);
        AbrtC->setCallingConv(CallingConv::C);
        AbrtC->setTailCall(true);
        AbrtC->setDoesNotReturn(true);
        AbrtC->setDoesNotThrow(true);
        new UnreachableInst(BB->getContext(), AbrtBB);
        DT->addNewBlock(AbrtBB, BB);
        verifyFunction(*BB->getParent());
      }
      TerminatorInst *TI = BB->getTerminator();
      SCEVExpander expander(*SE);
      Value *IdxV = expander.expandCodeFor(Idx, Idx->getType(), TI);
      verifyFunction(*BB->getParent());
      Value *LimitV = expander.expandCodeFor(Limit, Limit->getType(), TI);
      verifyFunction(*BB->getParent());
      Value *Cond = new ICmpInst(TI, ICmpInst::ICMP_ULT, IdxV, LimitV);
      verifyFunction(*BB->getParent());
      BranchInst::Create(newBB, AbrtBB, Cond, TI);
      TI->eraseFromParent();
      // Update dominator info
      BasicBlock *DomBB =
        DT->findNearestCommonDominator(BB,
                                       DT->getNode(AbrtBB)->getIDom()->getBlock());
      DT->changeImmediateDominator(AbrtBB, DomBB);
      verifyFunction(*BB->getParent());
      return true;
    }

    bool checkGEP(GetElementPtrInst &GEP, std::string &Msg)
    {
      return true;//TODO:
      SmallVector<Value*, 8> IndicesVector(GEP.idx_begin(), GEP.idx_end());
      Value* const* Indices = &IndicesVector[0];
      const unsigned NumIndices = IndicesVector.size();
      Value *V = GEP.getOperand(0);
      const Type *Ty = V->getType();
      generic_gep_type_iterator<Value* const*>
        TI = gep_type_begin(Ty, Indices, Indices+NumIndices);
      BasicBlock *BB = findDomBB(&GEP);
      LLVMContext &C = GEP.getContext();
      GEPOperator* sizeField = 0;
      Module *M = GEP.getParent()->getParent()->getParent();
      bool atLeastOne = false;

      if (LoadInst *LI = dyn_cast<LoadInst>(V)) {
        GEPOperator *GO = dyn_cast<GEPOperator>(LI->getPointerOperand());
        generic_gep_type_iterator<Operator::op_iterator>
          TTI = gep_type_begin(GO->getPointerOperandType(),
                               GO->idx_begin(), GO->idx_end());
        for (unsigned i=0;i<GO->getNumIndices()-1;i++)
          ++TTI;
        const Type *ETy = *TTI;
        if (isa<StructType>(ETy)) {
          if (NamedMDNode *NMD = M->getNamedMetadata("llvm.boundsinfo."+M->getTypeName(ETy))) {
            MDNode *MD = cast<MDNode>(NMD->getOperand(0));
            ConstantInt *PtrField = cast<ConstantInt>(MD->getOperand(0));
            ConstantInt *lastIdx = cast<ConstantInt>(*(GO->idx_begin() + GO->getNumIndices()-1));
            atLeastOne = true;
            if (PtrField->getValue() == lastIdx->getValue()) {
              SmallVector<Value*, 8> Indices(GO->idx_begin(),
                                             GO->idx_end()-1);
              Indices.push_back(cast<ConstantInt>(MD->getOperand(1)));
              sizeField = cast<GEPOperator>(
                ConstantExpr::getGetElementPtr(
                  cast<Constant>(GO->getPointerOperand()),
                  Indices.begin(), Indices.size()));
            }
          }
        }
      }

      for (unsigned CurIDX = 0; CurIDX != NumIndices; ++CurIDX, ++TI) {
        if (const StructType *STy = dyn_cast<StructType>(*TI)) {
          assert(Indices[CurIDX]->getType() == Type::getInt32Ty(C) &&
                 "Illegal struct idx");
          unsigned FieldNo = cast<ConstantInt>(Indices[CurIDX])->getZExtValue();
          sizeField = 0;
          if (NamedMDNode *NMD = M->getNamedMetadata("llvm.boundsinfo."+M->getTypeName(STy))) {
            MDNode *MD = cast<MDNode>(NMD->getOperand(0));
            ConstantInt *PtrField = cast<ConstantInt>(MD->getOperand(0));
            atLeastOne = true;// Having a boundsinfo implies that neither fields are null,
            //and store at least one element. TODO:validate this!
            if (PtrField->getValue() == FieldNo) {
              SmallVector<Value*, 8> Indices(IndicesVector.begin(),
                                             IndicesVector.begin() + CurIDX);
              Indices.push_back(cast<ConstantInt>(MD->getOperand(1)));
              sizeField = cast<GEPOperator>(GetElementPtrInst::Create(V,
                                                                      Indices.begin(),
                                                                      Indices.end()));
            }
          }
          // Update Ty to refer to current element
          Ty = STy->getElementType(FieldNo);
        } else {
          // Get the array index and the size of each array element.
          Value* arrayIdx = Indices[CurIDX];
          const SCEV* Idx = SE->getSCEV(arrayIdx);
          if(const ArrayType* ATy = dyn_cast<ArrayType>(Ty)) {
            unsigned num = ATy->getNumElements();
            if (!num) {
              // 0 size array mean any size
              Msg = "Flexible array members in structs are not supported";
              return false;
            }
            const Type *Ty = SE->getEffectiveSCEVType(Idx->getType());
            const SCEV *Limit = SE->getConstant(Ty, num);
            if (!checkLimits(Idx, Limit, BB)) {
              if (!insertCheck(Idx, Limit, &GEP)) {
                Msg = "Cannot insert bounds check for this array index!";
                return false;
              }
            }
          } else {
            if (CurIDX != 0) {
              Msg = "Arbitrary nested pointer indexing not supported yet!";
              return false;
            }
            const SCEV *Limit = 0;
            if (sizeField) {
              const SCEV *S = SE->getSCEV(sizeField);
              for (df_iterator<Value*> UI=df_begin(sizeField->getPointerOperand()),UE=df_end(sizeField->getPointerOperand());
                   UI != UE; ++UI) {
                Instruction *I = dyn_cast<Instruction>(*UI);
                if (!I || I->getParent()->getParent() != GEP.getParent()->getParent())
                  continue;
                if (LoadInst *LI = dyn_cast<LoadInst>(I)) {
                  if (S == SE->getSCEV(LI->getPointerOperand())) {
                    Limit = SE->getSCEV(LI);
                    break;
                  }
                }
              }
            }
            if (!Limit)
              Limit = getPointerSize(V);
            if (isa<SCEVCouldNotCompute>(Limit) && atLeastOne)
              Limit = SE->getConstant(IntegerType::get(SE->getContext(), 32), 1);
            if (!checkLimits(Idx, Limit, BB)) {
              if (!insertCheck(Idx, Limit, &GEP)) {
                Msg = "Arbitrary pointer indexing not supported yet!";
                return false;
              }
            }
          }
          Ty = cast<SequentialType>(Ty)->getElementType();
          sizeField = 0;
          atLeastOne = false;
        }
      }
      return true;
    }

    bool checkGEP(ConstantExpr *CE, std::string &Msg)
    {
      gep_type_iterator GEPI = gep_type_begin(CE),
                        E = gep_type_end(CE);
      User::const_op_iterator OI = CE->op_begin();
      if (!checkAccess(*OI))
        return false;
      ++OI;
      ConstantInt *CI = dyn_cast<ConstantInt>(*OI);
      if (!CI || !CI->isZero()) {
        Msg = "Overindexed base pointer";
        return false;
      }

      ++GEPI;
      ++OI;
      for (; GEPI != E; ++GEPI, ++OI) {
        ConstantInt *CI = dyn_cast<ConstantInt>(*OI);
        if (!CI) return false;
        if (const ArrayType *ATy = dyn_cast<ArrayType>(*GEPI))
          if (CI->getValue().getActiveBits() > 64 ||
              CI->getZExtValue() >= ATy->getNumElements()) {
            Msg = "Overindexed";
            return false;
          }
      }
      return true;
    }

    bool checkAccess(Value *V)
    {
      return true;
      V = V->stripPointerCasts();
      if (isa<AllocaInst>(V) || isa<GlobalVariable>(V))
        return true;
      if (GetElementPtrInst *GEP = dyn_cast<GetElementPtrInst>(V)) {
        std::string Msg;
        if (checkGEP(*GEP, Msg)) {
          return true;
        }
      }
      if (ConstantExpr *CE = dyn_cast<ConstantExpr>(V)) {
        if (CE->getOpcode() == Instruction::GetElementPtr) {
          std::string Msg;
          if (checkGEP(CE, Msg))
            return true;
        }
      }
      return false;
    }

    bool visitGetElementPtrInst(GetElementPtrInst &GEP)
    {
      if (Final) {
        for (unsigned i=1;i<GEP.getNumOperands();i++) {
          if (GEP.getOperand(i)->getType() !=
              Type::getInt32Ty(GEP.getContext())) {
            printDiagnostic("Will fail to load with JIT (non 32-bit GEP index)", &GEP);
          }
        }
      }
      std::string Msg;
      if (!checkGEP(GEP, Msg)) {
        printDiagnostic(Msg, &GEP);
        return false;
      }
      return true;
    }

    bool visitLoadInst(LoadInst &LI)
    {
      if (checkAccess(LI.getPointerOperand()))
        return true;
      printDiagnostic("Arbitrary load instructions not yet implemented!", &LI);
      return false;
    }

    bool visitStoreInst(StoreInst &SI)
    {
      if (checkAccess(SI.getPointerOperand()))
        return true;
      printDiagnostic("Arbitrary store instructions not yet implemented!", &SI);
      return false;
    }

  public:
    static char ID;
    explicit ClamBCVerifier(bool final)
      : FunctionPass(&ID), Final(final) {}
    virtual const char *getPassName() const { return "ClamAV Bytecode Verifier"; }

    virtual bool runOnFunction(Function &F)
    {
      AbrtBB = 0;
      SE = &getAnalysis<ScalarEvolution>();
      PT = &getAnalysis<PointerTracking>();
      DT = &getAnalysis<DominatorTree>();

      bool OK = true;
      std::vector<Instruction*> insns;
      // verifying can insert runtime checks, so be safe and create an initial
      // list of instructions to process so we are not affected by transforms.
      for (inst_iterator I = inst_begin(&F), E = inst_end(&F); I != E; ++I) {
        insns.push_back(&*I);
      }
      for (std::vector<Instruction*>::iterator I=insns.begin(),E=insns.end();
           I != E; ++I) {
        OK &= visit(*I);
        if (!OK && StopOnFirstError)
          break;
      }
      if (!OK)
        ClamBCModule::stop("Verifier rejected bytecode function due to errors",
                           &F);
      return false;
    }
    virtual void getAnalysisUsage(AnalysisUsage &AU) const {
      AU.addRequired<ScalarEvolution>();
      AU.addRequired<PointerTracking>();
      AU.addRequired<DominatorTree>();
      AU.setPreservesAll();
    }
  };
char ClamBCVerifier::ID=0;
}

llvm::FunctionPass* createClamBCVerifier(bool final) {
  return new ClamBCVerifier(final);
}
