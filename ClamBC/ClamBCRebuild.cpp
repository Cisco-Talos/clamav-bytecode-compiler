/*
 *  Compile LLVM bytecode to ClamAV bytecode.
 *
 *  Copyright (C) 2011 Sourcefire, Inc.
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
#include "llvm/System/DataTypes.h"
#include "ClamBCModule.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/Analysis/ScalarEvolution.h"
#include "llvm/Analysis/ScalarEvolutionExpander.h"
#include "llvm/BasicBlock.h"
#include "llvm/Constants.h"
#include "llvm/DerivedTypes.h"
#include "llvm/Function.h"
#include "llvm/Module.h"
#include "llvm/Pass.h"
#include "llvm/PassManager.h"
#include "llvm/Target/TargetData.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/InstIterator.h"
#include "llvm/Support/InstVisitor.h"
#include "llvm/Support/IRBuilder.h"
#include "llvm/Support/TargetFolder.h"

using namespace llvm;

class ClamBCRebuild : public FunctionPass, public InstVisitor<ClamBCRebuild> {
public:
  static char ID;
  explicit ClamBCRebuild() : FunctionPass(&ID) {}
  virtual const char *getPassName() const { return "ClamAV bytecode backend rebuilder"; }

  void getAnalysisUsage(AnalysisUsage &AU) const {
      AU.addRequired<TargetData>();
      AU.addRequired<ScalarEvolution>();
  }

  bool doInitialization(Module &M) {
      FMap.clear();
      FMapRev.clear();
      Context = &M.getContext();
      i8pTy = PointerType::getUnqual(Type::getInt8Ty(*Context));

      for (Module::iterator I=M.begin(),E=M.end(); I != E; ++I) {
	  Function *F = &*I;
	  if (F->isDeclaration())
	      continue;
	  functions.push_back(F);
      }
      for (std::vector<Function*>::iterator I=functions.begin(),
	   E=functions.end(); I != E; ++I) {
	  Function *F;
	  FMap[*I] = F = createFunction(*I, &M);
	  FMapRev[F] = *I;
	  BasicBlock *BB = BasicBlock::Create(*Context, "dummy", F, 0);
	  new UnreachableInst(*Context, BB);
      }
      return true;
  }

  bool doFinalization(Module &M)
  {
      for (std::vector<Function*>::iterator I=functions.begin(),
	   E=functions.end(); I != E; ++I) {
	  Function *F = *I;
	  F->deleteBody();
      }
      for (std::vector<Function*>::iterator I=functions.begin(),
	   E=functions.end(); I != E; ++I) {
	  Function *F = *I;
	  F->eraseFromParent();
      }
      return true;
  }

  bool runOnFunction(Function &NF)
  {
      Function *F = FMapRev[&NF];
      if (!F)
	  return false;
      NF.getEntryBlock().eraseFromParent();
      VMap.clear();
      CastMap.clear();
      BBMap.clear();
      visitedBB.clear();
      TargetFolder TF(TD);
      Builder = new IRBuilder<true,TargetFolder>(*Context, TF);

      TD = &getAnalysis<TargetData>();
      SE = &getAnalysis<ScalarEvolution>();
      Expander = new SCEVExpander(*SE);
      for (Function::iterator I=F->begin(),E=F->end(); I != E; ++I) {
	  BasicBlock *BB = &*I;
	  BBMap[BB] = BasicBlock::Create(BB->getContext(), BB->getName(), &NF, 0);
      }
      for (Function::iterator I=F->begin(),E=F->end(); I != E; ++I) {
	  runOnBasicBlock(&*I);
      }
      //phase 2: map PHI operands now
      for (inst_iterator I=inst_begin(F),E=inst_end(F); I != E; ++I) {
	 if (PHINode *N = dyn_cast<PHINode>(&*I)) {
	     PHINode *PN = dyn_cast<PHINode>(VMap[N]);
	     assert(PN);
	     PN->reserveOperandSpace(N->getNumIncomingValues());
	     for (unsigned i=0;i<N->getNumIncomingValues();i++) {
		 Value *V = mapPHIValue(N->getIncomingValue(i));
		 BasicBlock *BB = mapBlock(N->getIncomingBlock(i));
		 PN->addIncoming(V, BB);
	     }
	     assert(PN->getNumIncomingValues() > 0);
	 }
      }
      //phase 3: map GEPs, SCEVs need fully built function (including PHIs)
      for (inst_iterator I=inst_begin(F),E=inst_end(F); I != E; ++I) {
	  if (GetElementPtrInst *G = dyn_cast<GetElementPtrInst>(&*I))
	     rebuildGEP(G);
      }
      delete Expander;
      delete Builder;
      return true;
  }

private:
  typedef DenseMap<const Function*, Function*> FMapTy;
  typedef DenseMap<const BasicBlock*, BasicBlock*> BBMapTy;
  typedef DenseMap<const Value*, Value*> ValueMapTy;
  typedef SmallVector<std::pair<const Value*, int64_t>,4 > IndicesVectorTy;

  std::vector<Function*> functions;
  FMapTy FMap;
  FMapTy FMapRev;
  BBMapTy BBMap;
  ValueMapTy VMap;
  DenseMap<std::pair<const Value*, const Type*>, Value*> CastMap;
  TargetData *TD;
  ScalarEvolution *SE;
  const Type *i8pTy;
  FunctionPassManager *FPM;
  LLVMContext *Context;
  DenseSet<const BasicBlock*> visitedBB;
  IRBuilder<true,TargetFolder> *Builder;
  SCEVExpander *Expander;


  void stop(const std::string &Msg, const llvm::Instruction *I) {
    ClamBCModule::stop(Msg, I);
  }
  friend class InstVisitor<ClamBCRebuild>;

  const Type *getInnerElementType(const CompositeType *CTy)
  {
      const Type *ETy;
      // get pointer to first element
      do {
	  assert(CTy->indexValid(0u));
	  ETy = CTy->getTypeAtIndex(0u);
	  CTy = dyn_cast<CompositeType>(ETy);
      } while (CTy);
      assert(ETy->isIntegerTy());
      return ETy;
  }

  const Type *rebuildType(const Type *Ty)
  {
      if (Ty->isIntegerTy() || Ty->isVoidTy())
	  return Ty;
      if (const PointerType *PTy = dyn_cast<PointerType>(Ty))
	  return PointerType::getUnqual(getInnerElementType(PTy));
      if (const CompositeType *CTy = dyn_cast<CompositeType>(Ty)) {
	  const Type *ETy = getInnerElementType(CTy);
	  unsigned bytes = TD->getTypeAllocSize(CTy);
	  unsigned esize = TD->getTypeAllocSize(ETy);
	  unsigned n = bytes / esize;
	  assert(!(bytes % esize));
	  return ArrayType::get(ETy, n);
      }
      llvm_unreachable("unknown type");
  }

  ConstantInt *u32const(uint32_t n)
  {
      return ConstantInt::get(Type::getInt32Ty(*Context), n);
  }

  ConstantInt *i32const(int32_t n)
  {
      return ConstantInt::get(Type::getInt32Ty(*Context), n, true);
  }

  void visitAllocaInst(AllocaInst &AI) {
      if (!isa<ConstantInt>(AI.getArraySize()))
	  stop("VLA not supported", &AI);
      uint32_t n = cast<ConstantInt>(AI.getArraySize())->getZExtValue();
      const Type *Ty = rebuildType(AI.getAllocatedType());
      if (const ArrayType *ATy = dyn_cast<ArrayType>(Ty)) {
	  Ty = ATy->getElementType();
	  //TODO: check for overflow
	  n *= ATy->getNumElements();
      }
      if (n != 1)
	  Ty = ArrayType::get(Ty, n);
      VMap[&AI] = Builder->CreateAlloca(Ty, 0, AI.getName());
  }

  Constant *mapConstant(Constant *C)
  {
      //TODO: compute any gep exprs here
      return C;
  }

  Value *mapValue(Value *V)
  {
      if (Constant *C = dyn_cast<Constant>(V))
	  return mapConstant(C);
      if (isa<MDNode>(V))
	  return V;
      Value *NV = VMap[V];
      if (!NV) {
	  Instruction *I = cast<Instruction>(V);
	  BasicBlock *NowBB = Builder->GetInsertBlock();
	  BasicBlock *IBB = I->getParent();
	  assert(IBB != NowBB);

	  runOnBasicBlock(IBB);
	  Builder->SetInsertPoint(NowBB);

	  NV = VMap[V];
      }
      if (!NV) {
	  errs() << "not remapped: " << *V << "\n";
      }
      assert(NV);
      return NV;
  }

  Value *makeCast(Value *V, const Type *Ty)
  {
      if (V->getType() == Ty)
	  return V;
      Instruction *I = dyn_cast<Instruction>(V);
      if (!I)
	  return Builder->CreatePointerCast(V, Ty, "rbcastc");
      std::pair<const Value*, const Type*> pair(V, Ty);
      Value *R = CastMap[pair];
      if (!R) {
	  BasicBlock *thisBB = Builder->GetInsertBlock();
	  BasicBlock::iterator thisP = Builder->GetInsertPoint();
	  BasicBlock *targetBB = I->getParent();
	  if (thisBB != targetBB) {
	      BasicBlock::iterator IP = I;
	      ++IP;
	      while (isa<AllocaInst>(IP)) ++IP;
	      Builder->SetInsertPoint(targetBB, IP);
	  }
	  CastMap[pair] = R = Builder->CreatePointerCast(V, Ty, "rbcast");
	  if (thisBB != targetBB)
	      Builder->SetInsertPoint(thisBB, thisP);
      }
      return R;
  }

  Value *mapPointer(Value *P, const Type *Ty)
  {
      Value *PV = mapValue(P);
      if (PV->getType() == Ty) {
	  assert(!isa<AllocaInst>(PV) ||
		 cast<PointerType>(Ty)->getElementType()->isIntegerTy());
	  return PV;
      }
      PV = PV->stripPointerCasts();
      if (isa<AllocaInst>(PV))
	  PV = makeCast(PV, i8pTy);
      return makeCast(PV, Ty);
  }

  BasicBlock *mapBlock(const BasicBlock *BB)
  {
      BasicBlock *NBB =  BBMap[BB];
      assert(NBB);
      return NBB;
  }

  void visitReturnInst(ReturnInst &I) {
      Value *V = I.getReturnValue();
      if (!V)
	  Builder->CreateRetVoid();
      else
	  Builder->CreateRet(mapValue(V));
  }

  void visitBranchInst(BranchInst &I) {
      if (I.isConditional()) {
	  Builder->CreateCondBr(mapValue(I.getCondition()),
				mapBlock(I.getSuccessor(0)),
				mapBlock(I.getSuccessor(1)));
      } else
	  Builder->CreateBr(mapBlock(I.getSuccessor(0)));
  }

  void visitSwitchInst(SwitchInst &I) {
      SwitchInst *SI = Builder->CreateSwitch(mapValue(I.getCondition()),
					     mapBlock(I.getDefaultDest()),
					     I.getNumCases());
      for (unsigned i=1;i<I.getNumCases();i++) {
	  BasicBlock *BB = mapBlock(I.getSuccessor(i));
	  SI->addCase(I.getCaseValue(i), BB);
      }
  }

  void visitUnreachableInst(UnreachableInst &I) {
      Builder->CreateUnreachable();
  }

  void visitICmpInst(ICmpInst &I) {
      VMap[&I] = Builder->CreateICmp(I.getPredicate(),
				     mapValue(I.getOperand(0)),
				     mapValue(I.getOperand(1)), I.getName());
  }

  void visitLoadInst(LoadInst &I) {
      Value *P = I.getPointerOperand();
      VMap[&I] = Builder->CreateLoad(mapPointer(P, P->getType()),
				     I.getName());
  }

  void visitStoreInst(StoreInst &I) {
      Value *P = I.getPointerOperand();
      Builder->CreateStore(mapValue(I.getOperand(0)),
			   mapPointer(P, P->getType()));
  }

  void visitGetElementPtrInst(GetElementPtrInst &II)
  {
      if (II.hasAllZeroIndices()) {
	  //just a bitcast
	  VMap[&II] = mapPointer(II.getOperand(0), rebuildType(II.getType()));
	  return;
      }
      // will replace this later once the entire function is built,
      // needed because we use SCEVs
      Value *P = mapPointer(II.getOperand(0), II.getOperand(0)->getType());
      std::vector<Value*> idxs;
      for (GetElementPtrInst::op_iterator I=II.idx_begin(),E=II.idx_end();
	   I != E; ++I) {
	  idxs.push_back(mapValue(*I));
      }
      if (II.isInBounds())
	  P = Builder->CreateInBoundsGEP(P, idxs.begin(), idxs.end());
      else
	  P = Builder->CreateGEP(P, idxs.begin(), idxs.end());
      VMap[&II] = makeCast(P, rebuildType(II.getType()));;
  }

  void rebuildGEP(GetElementPtrInst *II)
  {
      Instruction *Old = dyn_cast<Instruction>(VMap[II]);
      if (II->hasAllZeroIndices() || !Old)
	  return;
      int64_t BaseOffs;
      IndicesVectorTy VarIndices;
      const Type *i32Ty = Type::getInt32Ty(*Context);

      Value *P = const_cast<Value*>(DecomposeGEPExpression(II, BaseOffs, VarIndices, TD));
      P = mapValue(P)->stripPointerCasts();
      const PointerType *PTy = cast<PointerType>(P->getType());
      unsigned divisor = TD->getTypeAllocSize(PTy->getElementType());
      bool allDivisible = true;
      bool inbounds = II->isInBounds();
      Builder->SetInsertPoint(Old->getParent(), Old);

      if (!(BaseOffs % divisor)) {
	  BaseOffs /= divisor;
	  if (inbounds)
	      P = Builder->CreateConstInBoundsGEP1_64(P, BaseOffs, "rb.based");
	  else
	      P = Builder->CreateConstGEP1_64(P, BaseOffs, "rb.based");
      }  else {
	  allDivisible = false;
	  P = makeCast(P, i8pTy);
	  if (inbounds)
	      P = Builder->CreateConstInBoundsGEP1_64(P, BaseOffs, "rb.base8");
	  else
	      P = Builder->CreateConstGEP1_64(P, BaseOffs, "rb.base8");
      }
      if (allDivisible) {
	  for (IndicesVectorTy::iterator I=VarIndices.begin(),E=VarIndices.end();
	       I != E; ++I) {
	      if (I->second % divisor) {
		  allDivisible = false;
		  break;
	      }
	  }
      }
      if (!allDivisible) {
	  divisor = 1;
	  P = makeCast(P, i8pTy);
      }
      const SCEV *Zero = SE->getIntegerSCEV(0, i32Ty);
      const SCEV *S = Zero;
      BasicBlock *thisBB = Old->getParent();
      Instruction *IP = thisBB->getFirstNonPHI();
      for (IndicesVectorTy::iterator I=VarIndices.begin(),E=VarIndices.end();
	   I != E; ++I) {
	  int64_t m = I->second / divisor;
	  int32_t m2 = m;
	  assert((int64_t)m2 == m);
	  Value *V = const_cast<Value*>(I->first);
	  V = mapValue(V);
	  if (Instruction *IV = dyn_cast<Instruction>(V)) {
	      unsigned i = IV - IV->getParent()->begin();
	      unsigned ip = IP - thisBB->begin();
	      if (IV->getParent() == thisBB &&
		  i > ip)
		  IP = IV;
	  }
	  const SCEV *SV = SE->getSCEV(V);
	  SV = SE->getTruncateOrNoop(SV, i32Ty);
	  const SCEV *mulc = SE->getIntegerSCEV(m2, i32Ty);
	  S = SE->getAddExpr(S, SE->getMulExpr(SV, mulc, false, true),
			     false, true);
      }
      if (S != Zero) {
	  Value *SC = Expander->expandCodeFor(S, i32Ty, IP);
	  Builder->SetInsertPoint(Old->getParent(), Old);//move to end of BB
	  if (inbounds)
	      P = Builder->CreateInBoundsGEP(P, SC);
	  else
	      P = Builder->CreateGEP(P, SC);
      }
      P = makeCast(P, Old->getType());
      Old->replaceAllUsesWith(P);
      VMap[II] = P;
      Old->eraseFromParent();
  }


  Value *mapPHIValue(Value *V)
  {
      Value *NV;
      if (isa<PHINode>(V)) {
	  NV = VMap[V];
	  if (!NV) // break recursion
	      VMap[V] = NV = Builder->CreatePHI(V->getType());
	  return NV;
      }
      return mapValue(V);
  }

  void visitPHINode(PHINode &I)
  {
      VMap[&I] = Builder->CreatePHI(I.getType());
      //2nd phase will map the operands
  }

  void visitCastInst(CastInst &I)
  {
      VMap[&I] = Builder->CreateCast(I.getOpcode(),
				     mapValue(I.getOperand(0)),
				     rebuildType(I.getType()),
				     I.getName());
  }

  void visitSelectInst(SelectInst &I)
  {
      VMap[&I] = Builder->CreateSelect(mapValue(I.getCondition()),
				       mapValue(I.getTrueValue()),
				       mapValue(I.getFalseValue()),
				       I.getName());
  }

  void visitCallInst(CallInst &I)
  {
      std::vector<Value*> params;
      Function *F = I.getCalledFunction();
      const FunctionType *FTy = F->getFunctionType();
      if (F->isDeclaration()) {
	  //APIcall, types preserved, no mapping of F
	  assert(!FTy->isVarArg());
	  for (unsigned i=0;i<FTy->getNumParams();i++) {
	      Value *V = mapValue(I.getOperand(i+1));
	      const Type *Ty = FTy->getParamType(i);
	      if (V->getType() != Ty)
		  V = Builder->CreateBitCast(V, Ty);
	      params.push_back(V);
	  }
	  VMap[&I] = Builder->CreateCall(F, params.begin(), params.end(),
					 I.getName());
	  return;
      }
      F = FMap[F];
      assert(F);
      for (unsigned i=0;i<FTy->getNumParams();i++) {
	  params.push_back(mapValue(I.getOperand(i+1)));
      }
      VMap[&I] = Builder->CreateCall(F, params.begin(), params.end(), I.getName());
  }

  void visitBinaryOperator(BinaryOperator &I)
  {
      VMap[&I] = Builder->CreateBinOp(I.getOpcode(),
				      mapValue(I.getOperand(0)),
				      mapValue(I.getOperand(1)),
				      I.getName());
  }

  void visitInstruction(Instruction &I) {
    stop("ClamAV bytecode backend rebuilder does not know about ", &I);
  }

  void runOnBasicBlock(BasicBlock *BB)
  {
      BasicBlock *NBB = BBMap[BB];
      assert(NBB);
      if (visitedBB.count(BB))
	  return;
      Builder->SetInsertPoint(NBB);
      visitedBB.insert(BB);
      visit(BB);
  }


  Function* createFunction(Function *F, Module *M)
  {
      unsigned i;
      std::vector<const Type*> params;
      const FunctionType *FTy = F->getFunctionType();
      assert(!F->isVarArg());
      for (i=0;i<FTy->getNumParams();i++) {
	  params.push_back(rebuildType(FTy->getParamType(i)));
      }

      FTy = FunctionType::get(rebuildType(FTy->getReturnType()), params, false);
      std::string Name = F->getName().str();
      F->setName("");

      return Function::Create(FTy, F->getLinkage(), Name, M);
  }
};
char ClamBCRebuild::ID = 0;

llvm::FunctionPass *createClamBCRebuild(void)
{
    return new ClamBCRebuild();
}
