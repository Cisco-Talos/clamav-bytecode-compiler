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
#include "llvm/Transforms/Scalar.h"
#include "llvm/CodeGen/IntrinsicLowering.h"

using namespace llvm;

namespace {
class ClamBCLowering : public ModulePass {
public:
  static char ID;
  ClamBCLowering() : ModulePass((uintptr_t)&ID) {}
  virtual bool runOnModule(Module &M);
  virtual void getAnalysisUsage(AnalysisUsage &AU) const {
//    AU.addRequired<TargetData>();
  }
private:
  void lowerIntrinsics(IntrinsicLowering *IL, Function &F);
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
          case Intrinsic::dbg_stoppoint:
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
            || isa<PtrToIntInst>(Idx))
          continue;
        Builder.SetInsertPoint(BO->getParent(), BO);
        Value *V = Builder.CreatePointerCast(PII->getOperand(0),
                                             PointerType::getUnqual(Type::getInt8Ty(F.getContext())));
        V = Builder.CreateGEP(V, Idx);
        V = Builder.CreatePtrToInt(V, BO->getType());
        V->dump();
        BO->dump();
        BO->replaceAllUsesWith(V);
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
    lowerIntrinsics(0, *I);
  }
  //delete IL;
  return true;
}
}

llvm::ModulePass *createClamBCLowering() {
  return new ClamBCLowering();
}


