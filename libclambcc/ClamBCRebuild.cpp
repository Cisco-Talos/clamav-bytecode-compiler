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

#include "ClamBCModule.h"
#include "clambc.h"
#include "ClamBCUtilities.h"

#include <llvm/Support/DataTypes.h>
#include <llvm/ADT/DenseMap.h>
#include <llvm/ADT/DenseSet.h>
#include <llvm/Analysis/ValueTracking.h>
#include <llvm/Analysis/ScalarEvolution.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Module.h>
#include <llvm/Pass.h>
#include <llvm/IR/PassManager.h>
#include <llvm/Passes/PassPlugin.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Support/Casting.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/InstVisitor.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/Analysis/TargetFolder.h>

using namespace llvm;

class ClamBCRebuild : public PassInfoMixin<ClamBCRebuild>, public InstVisitor<ClamBCRebuild>
{
  public:
    static char ID;
    explicit ClamBCRebuild() {}
    virtual llvm::StringRef getPassName() const
    {
        return "ClamAV Bytecode Backend Rebuilder";
    }

    void getAnalysisUsage(AnalysisUsage &AU) const
    {
        AU.addRequired<ScalarEvolutionWrapperPass>();
    }

    bool runOnFunction(Function &func)
    {

        if (func.isDeclaration()) {
            return false;
        }

        Function *F    = &func;
        Function *copy = createFunction(F, pMod);
        Function &NF   = *copy;
        FMap[F]        = copy;

        NF.getEntryBlock().eraseFromParent();
        VMap.clear();
        CastMap.clear();
        BBMap.clear();
        visitedBB.clear();

        TargetFolder TF(NF.getParent()->getDataLayout());

        Builder = new IRBuilder<TargetFolder>(*Context, TF);

        SE = nullptr;

        visitFunction(F, &NF);
        for (Function::iterator I = F->begin(), E = F->end(); I != E; ++I) {
            BasicBlock *BB = &*I;
            BBMap[BB]      = BasicBlock::Create(*Context, BB->getName(), &NF, 0);
        }
        for (Function::iterator I = F->begin(), E = F->end(); I != E; ++I) {
            BasicBlock *bb = llvm::cast<BasicBlock>(I);
            runOnBasicBlock(bb);
        }

        // phase 2: map PHI operands now
        for (inst_iterator I = inst_begin(F), E = inst_end(F); I != E; ++I) {
            if (PHINode *N = dyn_cast<PHINode>(&*I)) {
                PHINode *PN = dyn_cast<PHINode>(VMap[N]);
                assert(PN);

                for (unsigned i = 0; i < N->getNumIncomingValues(); i++) {
                    Value *V       = mapPHIValue(N->getIncomingValue(i));
                    BasicBlock *BB = mapBlock(N->getIncomingBlock(i));

                    if (V->getType() != N->getType()) {
                        if (V->getType()->isPointerTy() and N->getType()->isPointerTy()) {
                            V = CastInst::CreatePointerCast(V, N->getType(),
                                                            "ClamBCRebuild_fixCast_", BB->getTerminator());
                        }
                    }
                    PN->addIncoming(V, BB);
                }
                assert(PN->getNumIncomingValues() > 0);
            }
        }

        /*Iterate through all uses of this function, and change all references.*/
        fixupCalls(F, copy);
        F->setLinkage(GlobalValue::InternalLinkage);

        delete Builder;
        return true;
    }

    void fixupCalls(Function *pOrig, Function *pNew)
    {
        pOrig->replaceAllUsesWith(pNew);

        std::vector<CallInst *> cis;
        for (auto i = pNew->user_begin(), e = pNew->user_end(); i != e; i++) {
            Value *val = llvm::cast<Value>(*i);
            if (llvm::isa<CallInst>(val)) {
                CallInst *pCallInst = llvm::cast<CallInst>(val);
                cis.push_back(pCallInst);
            } else {
                DEBUGERR << *val << "<END>\n";
                assert(0 && "NOT IMPLEMENTED");
            }
        }
        for (size_t i = 0; i < cis.size(); i++) {
            CallInst *pCallInst = cis[i];
            fixupCallInst(pCallInst, pNew);
            pCallInst->setCalledFunction(pNew);
        }
    }

    void fixupCallInst(CallInst *pCallInst, Function *pFunc)
    {
        assert(pCallInst->arg_size() == pFunc->arg_size() && "Incorrect number of arguments");

        auto argIter = pFunc->arg_begin(), argEnd = pFunc->arg_end();
        auto callIter = pCallInst->arg_begin(), callEnd = pCallInst->arg_end();

        size_t i = 0;
        while ((argIter != argEnd) && (callIter != callEnd)) {
            Argument *funcArg = llvm::cast<Argument>(argIter);
            Value *callArg    = llvm::cast<Value>(callIter);

            Type *fat = funcArg->getType();
            Type *cat = callArg->getType();

            if (fat != cat) {
                if (fat->isPointerTy() && cat->isPointerTy()) {
                    CastInst *ci = CastInst::CreatePointerCast(callArg, fat, "fixupCallInst", pCallInst);
                    pCallInst->setArgOperand(i, ci);
                } else {
                    assert(0 && "NOT IMPLEMENTED");
                }
            }

            argIter++;
            callIter++;
            i++;
        }
    }

    /*MAIN*/
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM)
    {
        pMod = &M;

        /* Taken from doInitialization.  */
        FMap.clear();

        Context = &(pMod->getContext());
        i8Ty    = Type::getInt8Ty(*Context);
        i8pTy   = PointerType::getUnqual(i8Ty);

        std::vector<Function *> funcs;
        for (auto i = pMod->begin(), e = pMod->end(); i != e; i++) {
            Function *pFunc         = llvm::cast<Function>(i);
            const FunctionType *FTy = pFunc->getFunctionType();
            if (FTy->isVarArg()) {
                return PreservedAnalyses::all();
            }
            funcs.push_back(pFunc);
        }
        for (size_t i = 0; i < funcs.size(); i++) {
            Function *pFunc = funcs[i];
            runOnFunction(*pFunc);
        }

        return PreservedAnalyses::none();
    }

  private:
    typedef DenseMap<const Function *, Function *> FMapTy;
    typedef DenseMap<const BasicBlock *, BasicBlock *> BBMapTy;
    typedef DenseMap<const Value *, Value *> ValueMapTy;
    typedef SmallVector<std::pair<const Value *, int64_t>, 4> IndicesVectorTy;

    llvm::Module *pMod = nullptr;

    std::vector<Function *> functions;
    FMapTy FMap;
    FMapTy FMapRev;
    BBMapTy BBMap;
    ValueMapTy VMap;
    DenseMap<std::pair<const Value *, const Type *>, Value *> CastMap;

    ScalarEvolution *SE  = nullptr;
    Type *i8Ty           = nullptr;
    Type *i8pTy          = nullptr;
    LLVMContext *Context = nullptr;
    DenseSet<const BasicBlock *> visitedBB;
    IRBuilder<TargetFolder> *Builder = nullptr;

    void stop(const std::string &Msg, const llvm::Instruction *I)
    {
        ClamBCStop(Msg, I);
    }
    friend class InstVisitor<ClamBCRebuild>;

    Type *rebuildType(Type *Ty, bool i8only = false)
    {
        assert(Ty);
        if (!i8only && Ty->isIntegerTy())
            return Ty;
        if (isa<PointerType>(Ty))
            return i8pTy;
        if (Ty->isVoidTy() || Ty == i8Ty)
            return Ty;
        unsigned bytes = pMod->getDataLayout().getTypeAllocSize(Ty);
        return ArrayType::get(i8Ty, bytes);
    }

    ConstantInt *u32const(uint32_t n)
    {
        return ConstantInt::get(Type::getInt32Ty(*Context), n);
    }

    ConstantInt *i32const(int32_t n)
    {
        return ConstantInt::get(Type::getInt32Ty(*Context), n, true);
    }

    void visitAllocaInst(AllocaInst &AI)
    {
        if (!isa<ConstantInt>(AI.getArraySize()))
            stop("VLA not supported", &AI);
        uint32_t n = cast<ConstantInt>(AI.getArraySize())->getZExtValue();
        Type *Ty   = rebuildType(AI.getAllocatedType(), true);
        if (const ArrayType *ATy = dyn_cast<ArrayType>(Ty)) {
            Ty = ATy->getElementType();
            // TODO: check for overflow
            n *= ATy->getNumElements();
        }
        if (n != 1)
            Ty = ArrayType::get(Ty, n);
        Instruction *I = Builder->CreateAlloca(Ty, 0, AI.getName());
        VMap[&AI]      = I;
    }

    Constant *mapConstant(Constant *C)
    {
        // TODO: compute any gep exprs here
        return C;
    }

    Value *mapValue(Value *V)
    {
        if (Constant *C = dyn_cast<Constant>(V)) {
            return mapConstant(C);
        }

        Value *NV = VMap[V];
        if (!NV) {
            Instruction *I    = cast<Instruction>(V);
            BasicBlock *NowBB = Builder->GetInsertBlock();
            BasicBlock *IBB   = I->getParent();
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

    /* findDuplicateType looks through all the casts of a value to find if it
     * is ultimately being casted to a type that it is already casted from.
     * If that is the case, it just returns the original, instead of creating
     * another cast.
     *
     * In addition to being inefficient, the excessive casting was causing
     * issues in 0.103 and 0.105.
     */
    Value *findDuplicateType(Value *v, Type *t)
    {
        if (BitCastInst *bci = llvm::dyn_cast<BitCastInst>(v)) {
            if (bci->getSrcTy() == t) {
                return bci->getOperand(0);
            }

            return findDuplicateType(bci->getOperand(0), t);
        }
        return nullptr;
    }

    Value *makeCast(Value *V, Type *Ty)
    {

        Value *v = findDuplicateType(V, Ty);
        if (v) {
            return v;
        }

        if (V->getType() == Ty) {
            return V;
        }
        Instruction *I = dyn_cast<Instruction>(V);
        if (!I) {
            return Builder->CreatePointerCast(V, Ty, "ClamBCRebuild_castc");
        }
        std::pair<const Value *, const Type *> pair(V, Ty);
        Value *R = CastMap[pair];
        if (!R) {
            BasicBlock *thisBB         = Builder->GetInsertBlock();
            BasicBlock::iterator thisP = Builder->GetInsertPoint();
            BasicBlock *targetBB       = I->getParent();
            if (thisBB != targetBB) {
                // BasicBlock::iterator IP = I;
                BasicBlock::iterator IP(I);
                ++IP;
                while (isa<AllocaInst>(IP)) ++IP;
                Builder->SetInsertPoint(targetBB, IP);
            }
            CastMap[pair] = R = Builder->CreatePointerCast(V, Ty, "ClamBCRebuild_castp");
            if (thisBB != targetBB)
                Builder->SetInsertPoint(thisBB, thisP);
        }
        return R;
    }

    Value *mapPointer(Value *P, Type *Ty)
    {
        Value *PV = mapValue(P);
        if (PV->getType() == Ty && !isa<AllocaInst>(PV)) {
            assert(!isa<AllocaInst>(PV) ||
                   Ty->getPointerElementType()->isIntegerTy());

            return PV;
        }
        PV = PV->stripPointerCasts();
        if (isa<AllocaInst>(PV))
            PV = makeCast(PV, i8pTy);
        return makeCast(PV, Ty);
    }

    BasicBlock *mapBlock(const BasicBlock *BB)
    {
        BasicBlock *NBB = BBMap[BB];
        assert(NBB);
        return NBB;
    }

    void visitReturnInst(ReturnInst &I)
    {
        Value *V = I.getReturnValue();
        if (!V)
            Builder->CreateRetVoid();
        else
            Builder->CreateRet(mapValue(V));
    }

    void visitBranchInst(BranchInst &I)
    {
        if (I.isConditional()) {
            Builder->CreateCondBr(mapValue(I.getCondition()),
                                  mapBlock(I.getSuccessor(0)),
                                  mapBlock(I.getSuccessor(1)));
        } else
            Builder->CreateBr(mapBlock(I.getSuccessor(0)));
    }

    void visitSwitchInst(SwitchInst &I)
    {
        SwitchInst *SI = Builder->CreateSwitch(mapValue(I.getCondition()),
                                               mapBlock(I.getDefaultDest()),
                                               I.getNumCases());
        // 0 is the default destination.
        for (unsigned i = 1; i < I.getNumCases(); i++) {
            BasicBlock *BB = mapBlock(I.getSuccessor(i));
            SI->addCase(I.findCaseDest(I.getSuccessor(i)), BB);
        }
    }

    void visitUnreachableInst(UnreachableInst &I)
    {
        Builder->CreateUnreachable();
    }

    void visitICmpInst(ICmpInst &I)
    {
        Value *op0 = mapValue(I.getOperand(0));
        Value *op1 = mapValue(I.getOperand(1));

        /*
         * bb#11515: Structure pointers are translated to uint8_t* pointers
         * but constants are kept to their original type so a type
         * conversion may be necessary on a icmp inst with a constant
         */
        if (op0->getType() != op1->getType()) {
            if (isa<Constant>(op0))
                op0 = makeCast(op0, op1->getType());
            else if (isa<Constant>(op1))
                op1 = makeCast(op1, op0->getType());

            /* if neither can be casted, CreateICmp will throw an assertion */
        }

        VMap[&I] = Builder->CreateICmp(I.getPredicate(),
                                       op0, op1, I.getName());
    }

    void visitLoadInst(LoadInst &I)
    {
        Value *P = I.getPointerOperand();
        VMap[&I] = Builder->CreateLoad(I.getType(), mapPointer(P, P->getType()),
                                       I.getName());
    }

    void visitStoreInst(StoreInst &I)
    {
        Value *P = I.getPointerOperand();
        Builder->CreateStore(mapValue(I.getOperand(0)),
                             mapPointer(P, P->getType()));
    }

    void visitGetElementPtrInst(GetElementPtrInst &II)
    {
        if (II.hasAllZeroIndices()) {
            // just a bitcast
            VMap[&II] = mapPointer(II.getOperand(0), rebuildType(II.getType()));
            return;
        }
        // will replace this later once the entire function is built,
        // needed because we use SCEVs
        Value *P = mapPointer(II.getOperand(0), II.getOperand(0)->getType());
        std::vector<Value *> idxs;
        for (GetElementPtrInst::op_iterator I = II.idx_begin(), E = II.idx_end();
             I != E; ++I) {
            idxs.push_back(mapValue(*I));
        }

        Type *pt = P->getType();
        if (llvm::isa<PointerType>(pt)) {
            pt = pt->getPointerElementType();
        }

        if (II.isInBounds()) {
            // P = Builder->CreateInBoundsGEP(P, idxs.begin(), idxs.end());
            P = Builder->CreateInBoundsGEP(pt, P, idxs, "clambcRebuildInboundsGEP");
        } else {
            // P = Builder->CreateGEP(P, idxs.begin(), idxs.end());
            P = Builder->CreateGEP(pt, P, idxs, "clambcRebuildGEP");
        }
        VMap[&II] = makeCast(P, rebuildType(II.getType()));
        ;
    }

    Value *mapPHIValue(Value *V)
    {
        Value *NV;
        if (isa<PHINode>(V)) {
            NV = VMap[V];
            if (!NV) { // break recursion
                VMap[V] = NV = Builder->CreatePHI(V->getType(), 0, "ClamBCRebuild_phi_mapPHIValue_");
            }
            return NV;
        }
        return mapValue(V);
    }

    void visitPHINode(PHINode &I)
    {
        VMap[&I] = Builder->CreatePHI(I.getType(), 0, "ClamBCRebuild_phi_visitPHINode_");
        // 2nd phase will map the operands
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
        Function *F             = I.getCalledFunction();
        const FunctionType *FTy = F->getFunctionType();

        // Variable argument functions NOT allowed
        assert(!FTy->isVarArg());

        std::vector<Value *> params;
        for (unsigned i = 0; i < FTy->getNumParams(); i++) {
            Value *V = mapValue(I.getOperand(i));

            Type *Ty = FTy->getParamType(i);
            if (V->getType() != Ty) {
                // CompositeType, FunctionType, IntegerType; not all are handled TODO
                if (Ty->isIntegerTy()) {
                    V = Builder->CreateBitCast(V, Ty, "ClamBCRebuild_cast");
                } else if (Ty->isPointerTy()) { // A CompositeType

                    /*This appears to be necessary for 0.103 on windows.*/
                    if (Ty != i8pTy) {
                        V = Builder->CreatePointerCast(V, i8pTy, "ClamBCRebuild");
                    }

                    V = Builder->CreatePointerCast(V, Ty, "ClamBCRebuild");
                } else {
                    stop("Type conversion unhandled in ClamAV Bytecode Backend Rebuilder", &I);
                }
            }
            params.push_back(V);
        }

        CallInst *ci = Builder->CreateCall(F, params, I.getName());
        ci->setCallingConv(F->getCallingConv());
        VMap[&I] = ci;
        assert((ci->getCallingConv() == F->getCallingConv()) && "Calling convention doesn't match");
    }

    void visitBinaryOperator(BinaryOperator &I)
    {
        VMap[&I] = Builder->CreateBinOp(I.getOpcode(),
                                        mapValue(I.getOperand(0)),
                                        mapValue(I.getOperand(1)),
                                        I.getName());
    }

    void visitInstruction(Instruction &I)
    {
        stop("ClamAV bytecode backend rebuilder does not know about ", &I);
    }

    void runOnBasicBlock(BasicBlock *BB)
    {
        BasicBlock *NBB = BBMap[BB];
        assert(NBB);
        if (visitedBB.count(BB)) {
            return;
        }
        Builder->SetInsertPoint(NBB);
        visitedBB.insert(BB);
        visit(BB);
    }

    void visitFunction(Function *F, Function *NF)
    {
        assert(!F->isVarArg() || !NF->isVarArg());
        Function::arg_iterator FAI = F->arg_begin(), FAIE = F->arg_end();
        Function::arg_iterator NFAI = NF->arg_begin();
        for (; FAI != FAIE; ++FAI, ++NFAI) {
            VMap[&*FAI] = &*NFAI;
        }
    }

    Function *createFunction(Function *F, Module *M)
    {
        unsigned i;
        std::vector<Type *> params;
        FunctionType *FTy = F->getFunctionType();
        assert(!F->isVarArg());
        for (i = 0; i < FTy->getNumParams(); i++) {
            params.push_back(rebuildType(FTy->getParamType(i)));
        }

        FTy              = FunctionType::get(rebuildType(FTy->getReturnType()), params, false);
        std::string Name = F->getName().str();
        F->setName("");

        Function *ret = Function::Create(FTy, F->getLinkage(), Name, M);
        ret->setCallingConv(F->getCallingConv());

        auto fIter = F->arg_begin(), fEnd = F->arg_end();
        auto retIter = ret->arg_begin(), retEnd = ret->arg_end();

        while ((fIter != fEnd) && (retIter != retEnd)) {
            Argument *fArg   = llvm::cast<Argument>(fIter);
            Argument *retArg = llvm::cast<Argument>(retIter);
            retArg->setName(fArg->getName());

            fIter++;
            retIter++;
        }

        BasicBlock *BB = BasicBlock::Create(*Context, "dummy", ret, 0);
        new UnreachableInst(*Context, BB);

        return ret;
    }
};

// This part is the new way of registering your pass
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo()
{
    return {
        LLVM_PLUGIN_API_VERSION, "ClamBCRebuild", "v0.1",
        [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &FPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                    if (Name == "clambc-rebuild") {
                        FPM.addPass(ClamBCRebuild());
                        return true;
                    }
                    return false;
                });
        }};
}
