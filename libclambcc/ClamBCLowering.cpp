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
#include "ClamBCLowering.h"

#include "clambc.h"

#include <llvm/Passes/PassPlugin.h>
#include <llvm/IR/InstIterator.h>

using namespace llvm;

namespace ClamBCLowering
{

void ClamBCLowering::lowerIntrinsics(IntrinsicLowering *IL, Function &F)
{
    std::vector<Function *> prototypesToGen;
    IRBuilder<> Builder(F.getContext());

    for (Function::iterator BB = F.begin(), EE = F.end(); BB != EE; ++BB)
        for (BasicBlock::iterator I = BB->begin(); I != BB->end();) {
            Instruction *II = &*I;
            ++I;
            if (CallInst *CI = dyn_cast<CallInst>(II)) {
                if (Function *F = CI->getCalledFunction()) {
                    unsigned iid = F->getIntrinsicID();
                    switch (iid) {
                        default:
                            break;
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
                Value *Idx        = 0;
                if (PtrToIntInst *P1 = dyn_cast<PtrToIntInst>(BO->getOperand(0))) {
                    PII = P1;
                    Idx = BO->getOperand(1);
                } else if (PtrToIntInst *P2 = dyn_cast<PtrToIntInst>(BO->getOperand(1))) {
                    PII = P2;
                    Idx = BO->getOperand(0);
                }
                if (!PII || !isa<IntegerType>(Idx->getType()) || isa<PtrToIntInst>(Idx) ||
                    Idx->getType() == Type::getInt64Ty(F.getContext()))
                    continue;
                Builder.SetInsertPoint(BO);
                Value *V = Builder.CreatePointerCast(PII->getOperand(0),
                                                     PointerType::getUnqual(Type::getInt8Ty(F.getContext())));
                V        = Builder.CreateGEP(V->getType(), V, Idx);
                V        = Builder.CreatePtrToInt(V, BO->getType());
                BO->replaceAllUsesWith(V);
            } else if (GetElementPtrInst *GEPI = dyn_cast<GetElementPtrInst>(II)) {
                LLVMContext &C = GEPI->getContext();
                Builder.SetInsertPoint(GEPI);
                for (unsigned i = 1; i < GEPI->getNumOperands(); i++) {
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
                            } else if (VSz == 32) { // possible through CastInst path
                                // pass-through
                                V2 = V;
                            } else { // VSz > 32
                                // truncation
                                V2 = Builder.CreateTrunc(V, Type::getInt32Ty(C));
                            }

                            // replace the operand with the 32-bit sized index
                            GEPI->setOperand(i, V2);
                        }
                    }
                }
            } else if (ICmpInst *ICI = dyn_cast<ICmpInst>(II)) {
                if (ConstantExpr *CE = dyn_cast<ConstantExpr>(ICI->getOperand(1))) {
                    if (CE->getOpcode() != Instruction::IntToPtr)
                        continue;
                    Builder.SetInsertPoint(ICI);

                    Value *R    = CE->getOperand(0);
                    Value *L    = Builder.CreatePtrToInt(ICI->getOperand(0), R->getType());
                    Value *ICI2 = Builder.CreateICmp(ICI->getPredicate(), L, R);
                    ICI->replaceAllUsesWith(ICI2);
                }
            } else if (PtrToIntInst *PI = dyn_cast<PtrToIntInst>(II)) {
                // ptrtoint (getelementptr i8* P0, V1)
                // -> add (ptrtoint P0), V1
                GetElementPtrInst *GEP = dyn_cast<GetElementPtrInst>(PI->getOperand(0));
                if (GEP && GEP->getNumOperands() == 2) {
                    Value *V1 = GEP->getOperand(1);
                    if (GEP->getSourceElementType() == Type::getInt8Ty(F.getContext())) {
                        Value *P0 = Builder.CreatePtrToInt(GEP->getOperand(0),
                                                           V1->getType());
                        Value *A  = Builder.CreateAdd(P0, V1);
                        if (A->getType() != PI->getType()) {
                            A = Builder.CreateZExt(A, PI->getType());
                        }
                        PI->replaceAllUsesWith(A);
                        PI->eraseFromParent();
                    } else {
                        llvm::errs() << "<" << __LINE__ << ">" << *GEP << "<END>\n";
                        assert(0 && "Check out why this check failed.  It may not be an error");
                    }
                }
            }
        }
}

// has non-noop bitcast use?
static bool hasBitcastUse(Instruction *I)
{
    assert(I && "Bad pointer passed in");
    for (auto i : I->users()) {
        Value *vUser = llvm::cast<Value>(i);
        if (BitCastInst *BCI = dyn_cast<BitCastInst>(vUser)) {
            if (BCI->getSrcTy() != BCI->getDestTy()) {
                return true;
            }
        }
    }
    return false;
}

void replaceUses(Instruction *V2, Instruction *V, const Type *APTy)
{
    for (auto i : V2->users()) {
        llvm::User *UI  = llvm::cast<llvm::User>(i);
        Instruction *II = dyn_cast<BitCastInst>(UI);
        if (!II) {
            if (GetElementPtrInst *G = dyn_cast<GetElementPtrInst>(UI)) {
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
    } else {
        V2->replaceAllUsesWith(V);
    }
}

void ClamBCLowering::simplifyOperands(Function &F)
{
    std::vector<Instruction *> InstDel;

    for (inst_iterator I = inst_begin(F), E = inst_end(F); I != E; ++I) {
        Instruction *II = &*I;
        if (SelectInst *SI = dyn_cast<SelectInst>(II)) {
            std::vector<Value *> Ops;
            bool Changed = false;
            for (unsigned i = 0; i < II->getNumOperands(); ++i) {
                if (ConstantExpr *CE = dyn_cast<ConstantExpr>(II->getOperand(i))) {
                    if (CE->getOpcode() == Instruction::GetElementPtr) {
                        // rip out GEP expr and load it
                        Ops.push_back(new LoadInst(CE->getType(), CE, "gepex_load", SI));
                        Changed = true;
                    }
                } else {
                    Ops.push_back(II->getOperand(i));
                }
            }
            if (!Changed) {
                continue;
            }

            // generate new select instruction using loaded values
            assert(Ops.size() == 3 && "malformed selectInst has occurred!");
            SelectInst *NSI = SelectInst::Create(Ops[0], Ops[1], Ops[2],
                                                 "load_sel", SI);

            for (auto i : SI->users()) {
                Value *vUser = llvm::cast<Value>(i);

                if (llvm::LoadInst *LI = llvm::dyn_cast<llvm::LoadInst>(vUser)) {

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

/*
 * For whatever reason, there are 2 different memcpy intrinsics (names), and the mangling is weird.  We
 * need to keep track of which one we are replacing with which.
 */
static inline void addIntrinsicFunctions(llvm::Module *pMod,
                                         std::vector<std::pair<llvm::Function *, llvm::Function *>> &replacements)
{

    llvm::LLVMContext &Context = pMod->getContext();
    llvm::Type *i8Ptr          = PointerType::get(Type::getInt8Ty(Context), 0);
    llvm::Type *i32            = Type::getInt32Ty(Context);
    llvm::Type *i64            = Type::getInt64Ty(Context);
    llvm::Type *i1             = Type::getInt1Ty(Context);
    llvm::Type *i8             = Type::getInt8Ty(Context);

    replacements.push_back(std::pair<llvm::Function *, llvm::Function *>(
        Intrinsic::getDeclaration(pMod, Intrinsic::memcpy, {i8Ptr, i8Ptr, i64}),
        Intrinsic::getDeclaration(pMod, Intrinsic::memcpy, {i8Ptr, i8Ptr, i32})));

    replacements.push_back(std::pair<llvm::Function *, llvm::Function *>(
        Intrinsic::getDeclaration(pMod, Intrinsic::memcpy, {i8Ptr, i8Ptr, i64, i1}),
        Intrinsic::getDeclaration(pMod, Intrinsic::memcpy, {i8Ptr, i8Ptr, i32, i1})));

    replacements.push_back(std::pair<llvm::Function *, llvm::Function *>(
        Intrinsic::getDeclaration(pMod, Intrinsic::memset, {i8Ptr, i8, i64}),
        Intrinsic::getDeclaration(pMod, Intrinsic::memset, {i8Ptr, i8, i32})));

    replacements.push_back(std::pair<llvm::Function *, llvm::Function *>(
        Intrinsic::getDeclaration(pMod, Intrinsic::memset, {i8Ptr, i8, i64, i1}),
        Intrinsic::getDeclaration(pMod, Intrinsic::memset, {i8Ptr, i8, i32, i1})));

    replacements.push_back(std::pair<llvm::Function *, llvm::Function *>(
        Intrinsic::getDeclaration(pMod, Intrinsic::memmove, {i8Ptr, i8Ptr, i64}),
        Intrinsic::getDeclaration(pMod, Intrinsic::memmove, {i8Ptr, i8Ptr, i32})));

    replacements.push_back(std::pair<llvm::Function *, llvm::Function *>(
        Intrinsic::getDeclaration(pMod, Intrinsic::memmove, {i8Ptr, i8Ptr, i64, i1}),
        Intrinsic::getDeclaration(pMod, Intrinsic::memmove, {i8Ptr, i8Ptr, i32, i1})));
}

static llvm::Value *getReplacementSizeOperand(llvm::CallInst *pCallInst, llvm::Value *Len)
{
    LLVMContext &context = pCallInst->getParent()->getParent()->getParent()->getContext();
    Value *NewLen        = NULL;
    if (ConstantInt *C = dyn_cast<ConstantInt>(Len)) {
        NewLen = ConstantInt::get(Type::getInt32Ty(context),
                                  C->getValue().getLimitedValue((1ULL << 32) - 1));
    } else {
        NewLen = new TruncInst(Len, Type::getInt32Ty(context), "lvl_dwn", pCallInst);
    }
    return NewLen;
}

static void populateArgumentList(llvm::CallInst *pCallInst, llvm::Value *newLen, size_t idx, std::vector<llvm::Value *> &Ops)
{

    for (unsigned i = 0; i < pCallInst->arg_size(); ++i) {
        if (i == idx) {
            Ops.push_back(newLen);
        } else {
            Ops.push_back(pCallInst->getArgOperand(i));
        }
    }
}

static bool replaceIntrinsicCalls(llvm::MemIntrinsic *pMemIntrinsic, std::pair<llvm::Function *, llvm::Function *> rep, size_t idx)
{

    llvm::Function *pCalled = pMemIntrinsic->getCalledFunction();
    {
        if (rep.first == pCalled) {
            // llvm::CallSite CS(MI);
            Value *Len          = pMemIntrinsic->getArgOperand(2);
            llvm::Value *newLen = getReplacementSizeOperand(pMemIntrinsic, Len);

            std::vector<llvm::Value *> args;
            populateArgumentList(pMemIntrinsic, newLen, idx, args);

            assert(args.size() == 4 && "malformed intrinsic call!");

            llvm::Instruction *i = CallInst::Create(rep.second, args, pMemIntrinsic->getName(), pMemIntrinsic);
            assert(i && "Failed to create new CallInst");

            return true;
        }
    }
    return false;
}

// The following is probably not necessary, since we can just build with i386 target triple, but probably still a good idea.
void ClamBCLowering::downsizeIntrinsics(Function &F)
{

    std::vector<Instruction *> InstDel;

    std::vector<std::pair<llvm::Function *, llvm::Function *>> repPairs;
    addIntrinsicFunctions(F.getParent(), repPairs);

    for (inst_iterator I = inst_begin(F), E = inst_end(F); I != E; ++I) {
        Instruction *II = &*I;
        if (MemIntrinsic *MI = dyn_cast<MemIntrinsic>(II)) {

            for (size_t i = 0; i < repPairs.size(); i++) {
                if (replaceIntrinsicCalls(MI, repPairs[i], 2)) {
                    InstDel.push_back(MI);
                    break;
                }
            }
        }
    }

    for (unsigned i = 0; i < InstDel.size(); ++i) {
        InstDel[i]->eraseFromParent();
    }
}

// There is no guarantee that the alloca's will all be at the beginning of the block
//  so don't stop when we see a non-alloca
static void gatherAllocasWithBitcasts(llvm::BasicBlock *bb, std::vector<llvm::AllocaInst *> &allocas)
{
    for (auto i = bb->begin(), e = bb->end(); i != e; i++) {
        if (llvm::AllocaInst *ai = llvm::dyn_cast<llvm::AllocaInst>(i)) {
            if (hasBitcastUse(ai)) {
                allocas.push_back(ai);
            }
        }
    }
}

/*
 * The following function makes changes similar to the following.
 * BEFORE
 *   %st = alloca [264 x i8]                         ; <[264 x i8]*> [#uses=2]
 *   ...
 *   %16 = bitcast [264 x i8]* %st to i8*            ; <i8*> [#uses=1]
 *   %call133 = call i32 @rc4_stream_setup(i8* %16, i32 264, i8* %rbcastp, i32 32) ; <i32> [#uses=1]
 *
 * AFTER
 *   %0 = alloca [264 x i8]                          ; <[264 x i8]*> [#uses=1]
 *   %base_gepz = getelementptr [264 x i8]* %0, i32 0, i32 0 ; <i8*> [#uses=3]
 *   %bcastrr = bitcast i8* %base_gepz to [264 x i8]* ; <[264 x i8]*> [#uses=2]
 *   ...
 *   %18 = bitcast [264 x i8]* %bcastrr to i8*       ; <i8*> [#uses=0]
 *   %call133 = call i32 @rc4_stream_setup(i8* %base_gepz, i32 264, i8* %base_gepz22, i32 32) ; <i32> [#uses=1]
 *
 */
void ClamBCLowering::fixupBitCasts(Function &F)
{
    // bitcast of alloca doesn't work properly in libclamav,
    // so introduce an additional alloca of the correct type and load/store its
    // address.
    for (Function::iterator I = F.begin(), E = F.end();
         I != E; ++I) {
        std::vector<AllocaInst *> allocas;
        llvm::BasicBlock *bb = llvm::cast<llvm::BasicBlock>(I);
        gatherAllocasWithBitcasts(bb, allocas);

        ConstantInt *Zero = ConstantInt::get(Type::getInt32Ty(F.getContext()),
                                             0);
        for (std::vector<AllocaInst *>::iterator J = allocas.begin(), JE = allocas.end();
             J != JE; ++J) {
            AllocaInst *AI = *J;
            Instruction *V = AI;
            if (AI->getAllocatedType()->isIntegerTy()) {
                continue;
            }

            if (not llvm::isa<ArrayType>(AI->getAllocatedType())) {
                continue;
            }
            const ArrayType *arTy = cast<ArrayType>(AI->getAllocatedType());
            Type *APTy            = PointerType::getUnqual(arTy->getElementType());

            Instruction *AIC = AI->clone();
            AIC->insertBefore(AI);
            AIC->setName("ClamBCLowering_fixupBitCasts");
            BasicBlock::iterator IP = AI->getParent()->begin();
            while (isa<AllocaInst>(IP)) ++IP;
            llvm::ArrayRef<llvm::Value *> Idxs = {Zero, Zero};
            V                                  = GetElementPtrInst::Create(nullptr, AIC, Idxs, "base_gepz", AI);

            replaceUses(AI, V, APTy);
        }
    }
}

void ClamBCLowering::fixupGEPs(Function &F)
{
    // GEP of a global/constantexpr hits a libclamav interpreter bug,
    // so instead create a constantexpression, store it and GEP that.
    std::vector<GetElementPtrInst *> geps;
    for (inst_iterator I = inst_begin(F), E = inst_end(F);
         I != E; ++I) {
        if (GetElementPtrInst *GEPI = dyn_cast<GetElementPtrInst>(&*I)) {
            if (isa<GlobalVariable>(GEPI->getOperand(0)))
                geps.push_back(GEPI);
        }
    }
    BasicBlock *Entry = &F.getEntryBlock();
    for (std::vector<GetElementPtrInst *>::iterator I = geps.begin(), E = geps.end();
         I != E; ++I) {
        GetElementPtrInst *GEPI = *I;
        std::vector<Value *> indexes;
        GetElementPtrInst::op_iterator J = GEPI->idx_begin(), JE = GEPI->idx_end();
        for (; J != JE; ++J) {
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
        Constant *C  = cast<Constant>(GEPI->getOperand(0));
        Constant *GC = ConstantExpr::getInBoundsGetElementPtr(nullptr, C,
                                                              indexes);
        if (J != JE) {
            indexes.clear();
            for (; J != JE; ++J) {
                indexes.push_back(*J);
            }
            AllocaInst *AI = new AllocaInst(GC->getType(), 0, "ClamBCLowering_fixupGEPs", llvm::cast<llvm::Instruction>(Entry->begin()));
            new StoreInst(GC, AI, GEPI);
            Value *L = new LoadInst(AI->getType(), AI, "ClamBCLowering_fixupGEPs", GEPI);
            Value *V = GetElementPtrInst::CreateInBounds(L->getType(), L, indexes, "ClamBCLowering_fixupGEPs", GEPI);
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
    Type *I64Ty = Type::getInt64Ty(F.getContext());
    Type *I32Ty = Type::getInt32Ty(F.getContext());
    std::vector<PtrToIntInst *> insts;
    for (inst_iterator I = inst_begin(F), E = inst_end(F);
         I != E; ++I) {
        if (PtrToIntInst *PI = dyn_cast<PtrToIntInst>(&*I)) {
            if (PI->getType() != I64Ty)
                insts.push_back(PI);
        }
    }
    IRBuilder<> Builder(F.getContext());
    for (std::vector<PtrToIntInst *>::iterator I = insts.begin(), E = insts.end();
         I != E; ++I) {
        PtrToIntInst *PI = *I;
        // Builder.SetInsertPoint(PI->getParent(), PI);
        Builder.SetInsertPoint(PI);
        Value *PI2 = Builder.CreatePtrToInt(PI->getOperand(0), I64Ty);
        Value *R   = Builder.CreateTrunc(PI2, I32Ty);
        PI->replaceAllUsesWith(R);
        PI->eraseFromParent();
    }
}

void ClamBCLowering::splitGEPZArray(Function &F)
{
    for (inst_iterator I = inst_begin(F), E = inst_end(F);
         I != E;) {
        Instruction *II = &*I;
        ++I;
        if (GetElementPtrInst *GEPI = dyn_cast<GetElementPtrInst>(II)) {
            if (GEPI->getNumIndices() != 2) {
                continue;
            }
            ConstantInt *CI = dyn_cast<ConstantInt>(GEPI->getOperand(1));
            if (!CI) {
                continue;
            }
            if (!CI->isZero()) {
                continue;
            }
            CI = dyn_cast<ConstantInt>(GEPI->getOperand(2));
            if (CI && CI->isZero()) {
                continue;
            }
            const PointerType *Ty = cast<PointerType>(GEPI->getPointerOperand()->getType());
            const ArrayType *ATy  = dyn_cast<ArrayType>(Ty->getArrayElementType());
            if (!ATy) {
                continue;
            }
            Value *V[]     = {GEPI->getOperand(2)};
            Constant *Zero = ConstantInt::get(Type::getInt32Ty(Ty->getContext()), 0);
            Value *VZ[]    = {Zero, Zero};
            // transform GEPZ: [4 x i16]* %p, 0, %i -> GEP1 i16* (bitcast)%p, %i
            Value *C  = GetElementPtrInst::CreateInBounds(GEPI->getPointerOperand()->getType(), GEPI->getPointerOperand(), VZ, "ClamBCLowering_splitGEPZArray", GEPI);
            Value *NG = GetElementPtrInst::CreateInBounds(C->getType(), C, V, "ClamBCLowering_splitGEPZArray", GEPI);
            GEPI->replaceAllUsesWith(NG);
            GEPI->eraseFromParent();
        }
    }
}

PreservedAnalyses ClamBCLowering::run(Module &m, ModuleAnalysisManager &MAM)
{

    pMod     = &m;
    pContext = &(pMod->getContext());

    for (Module::iterator I = pMod->begin(), E = pMod->end();
         I != E; ++I) {
        if (I->isDeclaration())
            continue;
        lowerIntrinsics(0, *I);
        if (isFinal()) {
            simplifyOperands(*I);
            downsizeIntrinsics(*I);
            fixupBitCasts(*I);
            fixupGEPs(*I);
            fixupPtrToInts(*I);
            splitGEPZArray(*I);
        }
    }

    return PreservedAnalyses::none();
}

} // namespace ClamBCLowering
