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

#include "Common/ClamBCModule.h"
#include "Common/clambc.h"
#include "Common/ClamBCUtilities.h"

#include <llvm/Support/DataTypes.h>
#include <llvm/ADT/DenseMap.h>
#include <llvm/ADT/DenseSet.h>
#include <llvm/Analysis/ValueTracking.h>
#include <llvm/Analysis/ScalarEvolution.h>
//#include <llvm/Analysis/ScalarEvolutionExpander.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Module.h>
#include <llvm/Pass.h>
#include <llvm/IR/PassManager.h>
#include <llvm/IR/TypedPointerType.h>
#include <llvm/Passes/PassPlugin.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/InstVisitor.h>
#include <llvm/Analysis/TargetFolder.h>
#include <llvm/IR/TypedPointerType.h>

/*
 *
 * Since the interpreter/runtime doesn't have a notion of complex types, we
 * are using the 'Rebuild' pass to fix these types to arrays of bytes
 * and calculate the offsets.  Similar to 
 *
 *   %metadata = alloca [1500 x %struct._metadata], align 16

 changes to 

     %metadata = alloca [12000 x i8]


     List of some test files.

    BC.Js.Downloader.Adodb-4553522-2.optimized.ll
    BC.Win.Packer.GandCrab-6539706-3.optimized.ll
    BC.Js.Downloader.Adodb-5999914-0.optimized.ll
    BC.Win.Packer.script2exe-6754169-0.optimized.ll
    BC.Unix.Packer.UPX-7086472-2.optimized.ll
    BC.Win.Virus.Virut-7001009-0.optimized.ll

 */

/*
 *
 * Since the interpreter/runtime doesn't have a notion of complex types, we
 * are using the 'Rebuild' pass to fix these types to arrays of bytes
 * and calculate the offsets.  Similar to 
 *
 *   %metadata = alloca [1500 x %struct._metadata], align 16

 changes to 

     %metadata = alloca [12000 x i8]


     List of some test files.

    BC.Js.Downloader.Adodb-4553522-2.optimized.ll
    BC.Win.Packer.GandCrab-6539706-3.optimized.ll
    BC.Js.Downloader.Adodb-5999914-0.optimized.ll
    BC.Win.Packer.script2exe-6754169-0.optimized.ll
    BC.Unix.Packer.UPX-7086472-2.optimized.ll
    BC.Win.Virus.Virut-7001009-0.optimized.ll

 */





using namespace llvm;

namespace ClamBCRebuild {

#if 0
class ClamBCRebuild : public ModulePass, public InstVisitor<ClamBCRebuild>
#else
class ClamBCRebuild : public PassInfoMixin<ClamBCRebuild>, public InstVisitor<ClamBCRebuild>
#endif
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

    /*Copy each function.*/
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

        Builder = new IRBuilder<TargetFolder>(*pContext, TF);

        SE       = nullptr;
#if 0
        Expander = nullptr;
#endif

        /*Create a map of all the arguments in the 'old' function to the corresponding values in the new function.*/
        visitFunction(F, &NF);
        for (Function::iterator I = F->begin(), E = F->end(); I != E; ++I) {
            BasicBlock *BB = &*I;
            BBMap[BB]      = BasicBlock::Create(*pContext, BB->getName(), &NF, 0);
        }
        for (Function::iterator I = F->begin(), E = F->end(); I != E; ++I) {
            BasicBlock *bb = llvm::cast<BasicBlock>(I);
            runOnBasicBlock(bb);
        }

        //phase 2: map PHI operands now
        for (inst_iterator I = inst_begin(F), E = inst_end(F); I != E; ++I) {
            if (PHINode *N = dyn_cast<PHINode>(&*I)) {
                PHINode *PN = dyn_cast<PHINode>(VMap[N]);
                assert(PN);

                for (unsigned i = 0; i < N->getNumIncomingValues(); i++) {
                    Value *V       = mapPHIValue(N->getIncomingValue(i));
                    BasicBlock *BB = mapBlock(N->getIncomingBlock(i));
                    PN->addIncoming(V, BB);
                }
                assert(PN->getNumIncomingValues() > 0);
            }
        }

        /*Iterate through all uses of this function, and change all references.*/
        fixupCalls(F, copy);
        F->setLinkage(GlobalValue::InternalLinkage);

#if 0
        if (Expander) {
            delete Expander;
        }
#endif
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
        assert(pCallInst->getCalledFunction() == pFunc && "This CallInst doesn't call this function");

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

    bool needsTypeChanged(AllocaInst* pAlloca){
        Type * pType = pAlloca->getAllocatedType();

        /*For now, we are not going to change integer types that are larger than
         *i8.   That seems really unnecessary.
         */
        if (pType->isVoidTy()){
            return false;
        }

        if (pType->isPointerTy()){
            PointerType * pPointerType = llvm::cast<PointerType>(pType);

            DEBUGERR << "TODO: MOVE THIS CHECK TO THE VALIDATOR" << "<END>\n";
            if (pPointerType->isOpaque()){
                DEBUG_VALUE(pPointerType);
                DEBUG_VALUE(pAlloca);
                assert (0 && "Fail gracefully, when we move to the validator");
            }

            Type * pt = pPointerType->getNonOpaquePointerElementType();
            return (not pt->isIntegerTy(8));
        }

        if (pType->isArrayTy()){
            Type * pt = pType->getArrayElementType();
            return (not pt->isIntegerTy(8));
        }

        if (pType->isStructTy()){
            return true;
        }
        return false ;
    }


    void gatherAllocas(BasicBlock * pBB, std::vector<AllocaInst*> & allocas){

        for (auto i = pBB->begin(), e = pBB->end(); i != e; i++){
            if (AllocaInst * pAlloca = llvm::dyn_cast<AllocaInst>(i)) {
                if (!isa<ConstantInt>(pAlloca->getArraySize())) {
                    stop("VLA not supported", pAlloca);
                }
                if (needsTypeChanged(pAlloca)){
                    allocas.push_back(pAlloca);
                }
            }
        }
    }






    /*The following code copied from ClamBCPrepareGEPsForWriter.  Determine whether or
     * not we can get rid of that pass all together.
     *
     */

#if 0


NOTE: I am not ready to delete this block yet, I want to revisit this when I am doing runtime testing.


    virtual void processGEPI(GetElementPtrInst *pgepi, AllocaInst *pNew, StructType *gepiDstType)
    {
        Type * pIdxType = Type::getInt32Ty(pMod->getContext());

            Type * curr = gepiDstType;
            std::vector<Value*> idxs;
            for (auto i = pgepi->idx_begin(), e = pgepi->idx_end(); i != e; i++){
                Value * pIdx = llvm::cast<Value>(i);
                idxs.push_back(pIdx);
            }

            Value * vTot = nullptr;
            for (size_t i = 0; i < idxs.size(); i++){
                Value * pIdx = idxs[i];

                Type * pType = nullptr;
                if (StructType * pst = llvm::dyn_cast<StructType>(curr)){
                    pType = pst->getTypeAtIndex(pIdx);
                } else if (ArrayType * pat = llvm::dyn_cast<ArrayType>(curr)){
                    pType = pat->getArrayElementType();
                }else {
                    pType = curr;
#if 1
                    DEBUG_VALUE(curr);
                    //verify this is correct;
                    assert (0 && "FIGURE OUT WHAT TO DO HERE");
#endif
                }

                Value * tmp = ConstantInt::get(pIdxType, getTypeSizeInBytes(pMod, pType));

                tmp = BinaryOperator::Create(Instruction::Mul, tmp, pIdx, "processGEPI_mul_", pgepi);
                DEBUG_VALUE(tmp);

                curr = pType;

                if (vTot){
                    vTot = BinaryOperator::Create(Instruction::Add, tmp, vTot, "processGEPI_add_", pgepi);
                DEBUG_VALUE(vTot);
                } else {
                    vTot = tmp;
                }
            }

            vTot = GetElementPtrInst::Create(pgepi->getResultElementType(), pNew, vTot, "processGEPI_gepi_", pgepi);
                DEBUG_VALUE(pgepi);
                DEBUG_VALUE(vTot);
                exit(121);

            pgepi->replaceAllUsesWith(vTot);
            pgepi->eraseFromParent();
        }
#else



    virtual void processGEPI(GetElementPtrInst *pgepi, AllocaInst *pNew, StructType *gepiDstType)
    {
        Type * pIdxType = Type::getInt32Ty(pMod->getContext());


        uint64_t size = getTypeSizeInBytes(pMod, gepiDstType);
        assert(size && "size not computed");

        Value *vCnt = nullptr;

        auto i      = pgepi->idx_begin();
        Value *vIdx = llvm::cast<Value>(i);
        vCnt        = ConstantInt::get(vIdx->getType(), size);
        vCnt        = BinaryOperator::Create(Instruction::Mul, vCnt, vIdx, "processGEPI_", pgepi);
        i++;

        Type *currType = gepiDstType;

        for (auto e = pgepi->idx_end(); i != e; i++) {
            Value *vIdx = llvm::cast<Value>(i);

            Value *ciAddend = nullptr;
            if (ConstantInt *ciIdx = llvm::dyn_cast<ConstantInt>(vIdx)) {

                uint64_t val = computeOffsetInBytes(pMod, currType, ciIdx);
                ciAddend     = ConstantInt::get(ciIdx->getType(), val);

                Type *tmp = findTypeAtIndex(currType, ciIdx);
                assert(tmp && "Should always be defined");

                if (llvm::isa<StructType>(tmp)) {
                    currType = llvm::cast<StructType>(tmp);
                } else if (llvm::isa<ArrayType>(tmp)) {
                    currType = tmp;
                }
            } else if (ArrayType *pat = llvm::dyn_cast<ArrayType>(currType)) {

                uint64_t size = getTypeSizeInBytes(pMod, pat->getArrayElementType());
                Constant *pci = ConstantInt::get(vIdx->getType(), size);
                ciAddend      = BinaryOperator::Create(Instruction::Mul, pci, vIdx, "processGEPI_else_", pgepi);

                Type *tmp = findTypeAtIndex(currType, ciIdx);
                assert(tmp && "Should always be defined");

                if (llvm::isa<StructType>(tmp)) {
                    currType = llvm::cast<StructType>(tmp);
                } else if (llvm::isa<ArrayType>(tmp)) {
                    currType = tmp;
                }

            } else {
                assert(0 && "Figure out what to do here");
            }

            vCnt = BinaryOperator::Create(Instruction::Add, vCnt, ciAddend, "processGEPI_after_", pgepi);
        }

        Constant *Zero                     = ConstantInt::get(vIdx->getType(), 0);
        Value * gepiNew = pNew;
        llvm::ArrayRef<llvm::Value *> Idxs = {Zero, vCnt};

        gepiNew = GetElementPtrInst::Create(pgepi->getResultElementType(), gepiNew, vCnt, "processGEPI_3_", pgepi);

        CastInst *ciNew = CastInst::CreatePointerCast(gepiNew, pgepi->getType(), "processGEPI_cast_", pgepi);

        pgepi->replaceAllUsesWith(ciNew);
        pgepi->eraseFromParent();
    }
#endif





    virtual void processGEPI(GetElementPtrInst *pgepi, AllocaInst *pNew, ArrayType *gepiDstType)
    {
        Type *currType = gepiDstType->getArrayElementType();

        uint64_t size = getTypeSizeInBytes(pMod, currType);
        assert(size && "size not computed");

        Value *vCnt = nullptr;

        auto i      = pgepi->idx_begin();
        Value *vIdx = llvm::cast<Value>(i);
        vCnt        = ConstantInt::get(vIdx->getType(), size);
        vCnt        = BinaryOperator::Create(Instruction::Mul, vCnt, vIdx, "processGEPI_", pgepi);
        i++;

        StructType *pCurrStruct = nullptr;

        for (auto e = pgepi->idx_end(); i != e; i++) {
            Value *vIdx = llvm::cast<Value>(i);

            if (nullptr == pCurrStruct) {
                if (StructType *st = llvm::dyn_cast<StructType>(currType)) {
                    pCurrStruct = st;
                }
            }

            ConstantInt *pc = llvm::dyn_cast<ConstantInt>(vIdx);
            if (pc) {
                Type *pt = findTypeAtIndex(currType, pc);
                if (pt) {
                    currType              = pt;
                    ConstantInt *ciAddend = nullptr;
                    if (StructType *pst = llvm::dyn_cast<StructType>(pt)) {
                        uint64_t val = computeOffsetInBytes(pMod, pst, pc);
                        ciAddend     = ConstantInt::get(pc->getType(), val);
                        pCurrStruct  = pst;

                    } else {
                        uint64_t val = computeOffsetInBytes(pMod, pCurrStruct, pc);
                        ciAddend     = ConstantInt::get(pc->getType(), val);
                        vIdx         = BinaryOperator::Create(Instruction::Add, ciAddend, vIdx, "processGEPI_", pgepi);
                    }

                    vCnt = BinaryOperator::Create(Instruction::Add, vCnt, ciAddend, "processGEPI_", pgepi);
                }

            } else {

                size       = getTypeSizeInBytes(pMod, currType);
                Value *tmp = ConstantInt::get(vIdx->getType(), size);
                vIdx       = BinaryOperator::Create(Instruction::Mul, tmp, vIdx, "processGEPI_", pgepi);

                vCnt = BinaryOperator::Create(Instruction::Add, vCnt, vIdx, "processGEPI_", pgepi);
            }
        }

        Constant *Zero                     = ConstantInt::get(vIdx->getType(), 0);
        Value * gepiNew = pNew;
        llvm::ArrayRef<llvm::Value *> Idxs = {Zero, vCnt};
        gepiNew = GetElementPtrInst::Create(pgepi->getType(), gepiNew, vCnt, "processGEPI_1_", pgepi);

        pgepi->replaceAllUsesWith(gepiNew);
        pgepi->eraseFromParent();
    }

    virtual Value *stripBitCasts(Value *pInst)
    {
        if (BitCastInst *pbci = llvm::dyn_cast<BitCastInst>(pInst)) {
            return stripBitCasts(pbci->getOperand(0));
        }

        return pInst;
    }

    virtual void processGEPI(GetElementPtrInst *pgepi, AllocaInst * pOld, AllocaInst * pNew)
    {

        Type *pdst = Type::getInt8Ty(pMod->getContext());

        Value *vPtr = pgepi->getPointerOperand();
        if (BitCastInst *pbci = llvm::dyn_cast<BitCastInst>(vPtr)) {
            vPtr = stripBitCasts(pbci);
        }

        PointerType *ptrType = llvm::dyn_cast<PointerType>(vPtr->getType());
        if (nullptr == ptrType){
            ClamBCStop("ClamBCRebuild: expected PointerType", pgepi);
        }

        Type *gepiDstType = pOld->getAllocatedType();
        if (StructType *pst = llvm::dyn_cast<StructType>(gepiDstType)) {
            processGEPI(pgepi, pNew, pst);
        } else if (ArrayType *pat = llvm::dyn_cast<ArrayType>(gepiDstType)) {
            processGEPI(pgepi, pNew, pat);
        }

    }

    void handleInstruction(Instruction * pInst, AllocaInst * pOld, AllocaInst * pNew){
        for (size_t i = 0; i < pInst->getNumOperands(); i++){
            if (pOld == pInst->getOperand(i)){
                pInst->setOperand(i, pNew);
            }
        }
        llvm::errs() << "\n";
    }

    void changeAccesses(AllocaInst * pOld, AllocaInst * pNew){

        std::vector<llvm::Value*> users;
        for (auto i = pOld->user_begin(), e = pOld->user_end(); i != e; i++) {
            Value * pUser = llvm::cast<User>(*i);
            users.push_back(pUser);
        }

        for (size_t i = 0; i < users.size(); i++){
            Value * pUser = users[i];

            /*For now, we are going to skip GEPs, because I
             * *think* they are handled by ClamBCPrepareGEPsForWriter
             */
            if (GetElementPtrInst * pgepi = llvm::dyn_cast<GetElementPtrInst>(pUser)){
                processGEPI(pgepi, pOld, pNew);
                continue;
            }

            if (CallInst * pInst = llvm::dyn_cast<CallInst>(pUser)){
                handleInstruction(pInst, pOld, pNew);
                continue;
            }

            if (LoadInst * pInst = llvm::dyn_cast<LoadInst>(pUser)){
                handleInstruction(pInst, pOld, pNew);

                DEBUGERR << "TODO: DETERMINE WHETHER THIS IS SAFE WITH THE NEW POINTER LOAD CONTEXT" << "<END>\n";
                continue;
            }

            DEBUGERR << "TAKE THIS OUT" << "<END>\n";
            DEBUG_VALUE(pUser);
            //assert (0 && "NOT HANDLED");

        }
    }

    bool processBasicBlock(BasicBlock * pBB){
        bool bRet = false;
        std::vector<AllocaInst*> allocas;

        gatherAllocas(pBB, allocas);

        for (size_t i = 0; i < allocas.size(); i++){
            bRet = true;
            AllocaInst * pAlloca = allocas[i];

            Type *pType   = rebuildType(pAlloca->getAllocatedType(), true);
            AllocaInst * pNewAlloca = new AllocaInst(pType, pBB->getParent()->getAddressSpace(),
                    "ClamBCRebuild_processBasicBlock", pAlloca);

            changeAccesses(pAlloca, pNewAlloca);
        }

        return bRet;
    }

    bool processFunction(Function* pFunc){
        bool bRet = false;

        for (auto i = pFunc->begin(), e = pFunc->end(); i != e; i++){
            BasicBlock * pBB = llvm::dyn_cast<BasicBlock>(i);
            if (nullptr == pBB){
                /*Not sure how this would be possible.*/
                continue;
            }

            if (processBasicBlock(pBB)){
                bRet = true;
            }
        }

        return bRet;
    }

#if 0
    bool runOnModule(Module &M)
#else
    PreservedAnalyses run(Module & M, ModuleAnalysisManager & MAM)
#endif
    {

        bool bChanged = false;
        DEBUGERR << "TODO: REMOVE ALL THE VISITOR STUFF" << "<END>\n";
        pMod = &M;
        pContext = &(pMod->getContext());
        i8Ty    = Type::getInt8Ty(*pContext);
        i8pTy   = PointerType::getUnqual(i8Ty);

        for (auto i = pMod->begin(), e = pMod->end(); i != e; i++){
            if (Function * pFunc = llvm::dyn_cast<Function>(i)){
                if (pFunc->isDeclaration()){
                    continue;
                }

                processFunction(pFunc);
            }
        }

        DEBUGERR << "LEAVING" << "<END>\n";

        if (bChanged){
            return PreservedAnalyses::none();
        }

        return PreservedAnalyses::all();





        /* Taken from doInitialization.  */
        FMap.clear();
        //FMapRev.clear();

        std::vector<Function *> funcs;
        DEBUG_WHERE;
        for (auto i = pMod->begin(), e = pMod->end(); i != e; i++) {
            Function *pFunc = llvm::cast<Function>(i);
            funcs.push_back(pFunc);
        }
        DEBUG_WHERE;
        for (size_t i = 0; i < funcs.size(); i++) {
            Function *pFunc = funcs[i];
            if (runOnFunction(*pFunc)){
                bChanged = true;
            }
        }

        if (bChanged){
            return PreservedAnalyses::none();
        }

        return PreservedAnalyses::all();
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

    ScalarEvolution *SE = nullptr;
    Type *i8Ty          = nullptr;
    PointerType *i8pTy         = nullptr;
    //FunctionPassManager *FPM = nullptr;
    LLVMContext *pContext = nullptr;
    DenseSet<const BasicBlock *> visitedBB;
    IRBuilder<TargetFolder> *Builder = nullptr;
#if 0
    SCEVExpander *Expander           = nullptr;
#endif

    void stop(const std::string &Msg, const llvm::Instruction *I)
    {
        ClamBCStop(Msg, I);
    }
    friend class InstVisitor<ClamBCRebuild>;

#if 0
    const Type *getInnerElementType(const CompositeType *CTy)
    {
        const Type *ETy = nullptr;
        // get pointer to first element
        do {
            assert(CTy->indexValid(0u));
            ETy = CTy->getTypeAtIndex(0u);
            CTy = dyn_cast<CompositeType>(ETy);
        } while (CTy);
        assert(ETy->isIntegerTy());
        return ETy;
    }
#endif

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

        ArrayType::get(i8Ty, 1);

        return ArrayType::get(i8Ty, bytes);

    }

    ConstantInt *u32const(uint32_t n)
    {
        return ConstantInt::get(Type::getInt32Ty(*pContext), n);
    }

    ConstantInt *i32const(int32_t n)
    {
        return ConstantInt::get(Type::getInt32Ty(*pContext), n, true);
    }

    void visitAllocaInst(AllocaInst &AI)
    {
        if (!isa<ConstantInt>(AI.getArraySize()))
            stop("VLA not supported", &AI);
        uint32_t n = cast<ConstantInt>(AI.getArraySize())->getZExtValue();
        Type *Ty   = rebuildType(AI.getAllocatedType(), true);
        if (const ArrayType *ATy = dyn_cast<ArrayType>(Ty)) {
            Ty = ATy->getElementType();
            //TODO: check for overflow
            n *= ATy->getNumElements();
        }
        if (n != 1)
            Ty = ArrayType::get(Ty, n);
        Instruction *I = Builder->CreateAlloca(Ty, 0, AI.getName());
        VMap[&AI]      = I;
    }

    Constant *mapConstant(Constant *C)
    {
        //TODO: compute any gep exprs here
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

    Value *makeCast(Value *V, Type *Ty)
    {
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
                //BasicBlock::iterator IP = I;
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
#if 0
            assert(!isa<AllocaInst>(PV) ||
                   cast<PointerType>(Ty)->getElementType()->isIntegerTy());
#else
            assert(!isa<AllocaInst>(PV) ||
                   cast<TypedPointerType>(Ty)->getElementType()->isIntegerTy());
#endif
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
        VMap[&I] = Builder->CreateLoad(P->getType(), mapPointer(P, P->getType()),
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
            //just a bitcast
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
        if (II.isInBounds()) {
            P = Builder->CreateInBoundsGEP(P->getType(), P, idxs, "clambcRebuildInboundsGEP");
        } else {
            P = Builder->CreateGEP(P->getType(), P, idxs, "clambcRebuildGEP");
        }
        VMap[&II] = makeCast(P, rebuildType(II.getType()));
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
        assert(!F->isVarArg() && "VARIDAIC FUNCTIONS ARE NOT ALLOWED");
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

        BasicBlock *BB = BasicBlock::Create(*pContext, "dummy", ret, 0);
        new UnreachableInst(*pContext, BB);

        return ret;
    }
};


#if 0

char ClamBCRebuild::ID = 0;
static RegisterPass<ClamBCRebuild> X("clambc-rebuild", "ClamBCRebuild Pass",
                                     false /* Only looks at CFG */,
                                     false /* Analysis Pass */);

llvm::ModulePass *createClamBCRebuild(void)
{
    return new ClamBCRebuild();
}

#else

// This part is the new way of registering your pass
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {
  return {
    LLVM_PLUGIN_API_VERSION, "ClamBCRebuild", "v0.1",
    [](PassBuilder &PB) {
      PB.registerPipelineParsingCallback(
        [](StringRef Name, ModulePassManager &FPM,
        ArrayRef<PassBuilder::PipelineElement>) {
          if(Name == "clambc-rebuild"){
            FPM.addPass(ClamBCRebuild());
            return true;
          }
          return false;
        }
      );
    }
  };
}


#endif



} //namespace







