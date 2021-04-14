/*
 *  Compile LLVM bytecode to ClamAV bytecode.
 *
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2009-2013 Sourcefire, Inc.
 *
 *  Authors: Török Edvin, Kevin Lin
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
#include <llvm/ADT/DenseSet.h>
#include <llvm/ADT/PostOrderIterator.h>
#include <llvm/ADT/SCCIterator.h>
#include <llvm/Analysis/CallGraph.h>
#include <llvm/IR/Verifier.h>
#include <llvm/IR/DebugInfo.h>
#include <llvm/IR/Dominators.h>
#include <llvm/Analysis/ConstantFolding.h>
#include <llvm/Analysis/ScalarEvolution.h>
#include <llvm/Analysis/ScalarEvolutionExpressions.h>
#include <llvm/Analysis/ScalarEvolutionExpander.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/Intrinsics.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/Pass.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/InstVisitor.h>
#include <llvm/IR/GetElementPtrTypeIterator.h>
#include <llvm/ADT/DepthFirstIterator.h>
#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Utils/BasicBlockUtils.h>
#include <llvm/Support/Debug.h>

#include <llvm/Analysis/ValueTracking.h>
#include <llvm/Analysis/MemoryBuiltins.h> //extractMallocCall
#include <llvm/Analysis/TargetLibraryInfo.h>

//aragusa: This will need to be updated in version 9 or 10.
//#include <llvm/Support/TypeSize.h>

#define DEBUG_TYPE "clambc-rtcheck"
#include "ClamBCModule.h"
#include "ClamBCDiagnostics.h"

#include "Common/clambc.h"
#include "Common/ClamBCUtilities.h"
#include "Common/ClamBCCommon.h"

using namespace llvm;
namespace
{

class PtrVerifier : public FunctionPass
{
  private:
    DenseSet<Function *> badFunctions;
    std::vector<Instruction *> delInst;
    //CallGraphNode *rootNode = nullptr;
    Module *pMod = nullptr;

    bool saveMemoryInsts(BasicBlock *pBB, std::vector<Instruction *> &insts)
    {
        bool valid = true;
        for (auto i = pBB->begin(), e = pBB->end(); i != e; i++) {
            Instruction *pInst = llvm::cast<Instruction>(i);
            if (isa<LoadInst>(pInst) || isa<StoreInst>(pInst) || isa<MemIntrinsic>(pInst)) {
                insts.push_back(pInst);
            } else if (CallInst *CI = dyn_cast<CallInst>(pInst)) {
                Value *V    = CI->getCalledValue()->stripPointerCasts();
                Function *F = dyn_cast<Function>(V);
                if (!F) {
                    printLocation(CI, true);
                    errs() << "Could not determine call target\n";
                    valid = false;
                    continue;
                }
                // this statement disable checks on user-defined CallInst
                //if (!F->isDeclaration())
                //continue;
                insts.push_back(CI);
            }
        }
        return valid;
    }

    bool saveMemoryInsts(Function *pFunc, std::vector<Instruction *> &insts)
    {
        bool valid = true;
        for (auto i = pFunc->begin(), e = pFunc->end(); i != e; i++) {
            BasicBlock *pBB = llvm::cast<BasicBlock>(i);
            if (not saveMemoryInsts(pBB, insts)) {
                valid = false;
            }
        }
        return valid;
    }

  public:
    static char ID;
    PtrVerifier()
        : FunctionPass(ID) {}

    virtual llvm::StringRef getPassName() const
    {
        return "ClamAV Bytecode RT Checks";
    }

    virtual void dumpValue(Value *pv)
    {
        std::set<llvm::Instruction *> insts;
        std::set<llvm::GlobalVariable *> globs;
        getDependentValues(pv, insts, globs);

#if 1

        DEBUGERR << *pv << "<END>\n";
        DEBUGERR << "___Instructions___"
                 << "<END>\n";
        for (auto i = insts.begin(), e = insts.end(); i != e; i++) {
            DEBUGERR << **i << "<END>\n";
        }
        DEBUGERR << "DONE<END>\n";
        DEBUGERR << "___Globals___"
                 << "<END>\n";
        for (auto i = globs.begin(), e = globs.end(); i != e; i++) {
            DEBUGERR << **i << "<END>\n";
        }
        DEBUGERR << "DONE<END>\n";
#endif
    }

    virtual void dumpGlobals()
    {

        for (auto i = pMod->global_begin(), e = pMod->global_end(); i != e; i++) {
            GlobalVariable *pgv = llvm::cast<GlobalVariable>(i);
            dumpValue(pgv);
        }
    }

    virtual void dumpLocals(llvm::Function *pFunc)
    {
        for (auto fi = pFunc->begin(), fe = pFunc->end(); fi != fe; fi++) {
            BasicBlock *bb = llvm::cast<BasicBlock>(fi);
            /*Yes, I know that you should only have to look at the first
                     * block, but it is possible to have an Alloca in a different block.
                     */
            for (auto bbi = bb->begin(), bbe = bb->end(); bbi != bbe; bbi++) {
                if (llvm::isa<AllocaInst>(bbi)) {
                    AllocaInst *pai = llvm::cast<AllocaInst>(bbi);
                    dumpValue(pai);
                }
            }
        }
    }

    virtual void dumpPointers(llvm::Function *pFunc)
    {

        dumpGlobals();
        dumpLocals(pFunc);

        assert(0 && "NOT IMPLEMENTED");
    }

    BasicBlock *getAbortBB(unsigned MDDbgKind, BasicBlock *BB)
    {
        if (!AbrtBB) {
            FunctionType *abrtTy = FunctionType::get(
                Type::getVoidTy(BB->getContext()), false);
            //args.push_back(Type::getInt32Ty(BB->getContext()));
            FunctionType *rterrTy = FunctionType::get(
                Type::getInt32Ty(BB->getContext()),
                {Type::getInt32Ty(BB->getContext())}, false);
            Constant *func_abort =
                BB->getParent()->getParent()->getOrInsertFunction("abort", abrtTy);
            Constant *func_rterr =
                BB->getParent()->getParent()->getOrInsertFunction("bytecode_rt_error", rterrTy);
            AbrtBB      = BasicBlock::Create(BB->getContext(), "rterr.trig", BB->getParent());
            PHINode *PN = PHINode::Create(Type::getInt32Ty(BB->getContext()), 0, "ClamBCRTChecks_abort",
                                          AbrtBB);
            if (MDDbgKind) {
                CallInst *RtErrCall = CallInst::Create(func_rterr, PN, "", AbrtBB);
                RtErrCall->setCallingConv(CallingConv::C);
                RtErrCall->setTailCall(true);
                RtErrCall->setDoesNotThrow();
            }
            CallInst *AbrtC = CallInst::Create(func_abort, "", AbrtBB);
            AbrtC->setCallingConv(CallingConv::C);
            AbrtC->setTailCall(true);
            AbrtC->setDoesNotReturn();
            AbrtC->setDoesNotThrow();
            new UnreachableInst(BB->getContext(), AbrtBB);
            DT->addNewBlock(AbrtBB, BB);
        }
        return AbrtBB;
    }

    virtual Constant *getMaxSize(Value *actualPtr, Value *size)
    {

        DEBUGERR << actualPtr->getType()->isPointerTy() << "<END>\n";
        DEBUGERR << *actualPtr << "<END>\n";
        ;
        DEBUGERR << llvm::isa<CallInst>(actualPtr) << "<END>\n";
        ;
        if (GlobalVariable *pGlobal = llvm::dyn_cast<GlobalVariable>(actualPtr)) {
            DEBUGERR << "ISA GLOBAL, pGlobal = " << *pGlobal << "\n";
        }

        if (LoadInst *pLoadInst = llvm::dyn_cast<LoadInst>(actualPtr)) {
            Value *pVal = pLoadInst->getPointerOperand();
            DEBUGERR << *pVal << "<END>\n";
        }

        if (actualPtr->getType()->isPointerTy()) {
        }

        assert(0 && "BLAH");
        return nullptr;
    }

    virtual bool validatePointerAccess(Value *ptr, Value *size, Instruction *pInst)
    {

        DEBUGERR << "ptr = " << *ptr << "<END>\n";
        DEBUGERR << "SIZE = " << *size << "<END>\n";
        DEBUGERR << *(size->getType()) << "<END>\n";
        DEBUGERR << *pInst << "<END>\n";

        Value *actualPtr = GetUnderlyingObject(ptr, pMod->getDataLayout());

        DEBUGERR << "actualPtr = " << *actualPtr << "<END>\n";
        DEBUGERR << (actualPtr->getType()->isPointerTy()) << "<END>\n";
        DEBUGERR << *(actualPtr->getType()) << "<END>\n";
        DEBUGERR << *(actualPtr->getType()->getPointerElementType()) << "<END>\n";

        if (actualPtr->getType()->getPointerElementType()->isPointerTy()) {
            /*
                     * Find a way to determine how much space was allocated.
                     */
            assert(0 && "Handle this");
        } else {
            /*
                     * Insert a call for if 'size' is >= '
                     */
            Constant *maxSize = ConstantInt::get(size->getType(),
                                                 pMod->getDataLayout().getTypeAllocSize(actualPtr->getType()->getPointerElementType()));

            DEBUGERR << "MAX SIZE = " << *maxSize << "<END>\n";

            maxSize = getMaxSize(actualPtr, size);

            DEBUGERR << "MAX SIZE = " << *maxSize << "<END>\n";
            assert(0 && "jfkdlsjfkldsjfdklsfdjsklj");
            BasicBlock *orig  = pInst->getParent();
            BasicBlock *newBB = SplitBlock(pInst->getParent(), pInst);

            Instruction *insertPoint = orig->getTerminator();
            //ICmpInst * cond = new ICmpInst(insertPoint, CmpInst::ICMP_UGE, size, maxSize, "uge");
            ICmpInst *cond = new ICmpInst(insertPoint, CmpInst::ICMP_UGT, size, maxSize, "ugt_269_");
            assert(cond && "Cannot allocate memory");

            BasicBlock *abrtBB = getAbortBB(0, orig);
            PHINode *phiNode   = cast<PHINode>(abrtBB->begin());
            Value *location    = ConstantInt::get(phiNode->getType(), 0); /*TODO: Get a reasonable location.*/
            phiNode->addIncoming(location, orig);

            BranchInst::Create(abrtBB, newBB, cond, insertPoint);

            delInst.push_back(insertPoint);
        }

        return true;
    }

    virtual bool validateStoreInst(StoreInst *psi)
    {
        bool ret = true;

#if 0
                assert(0 && "PUT THIS BACK");
#else
        DEBUGERR << "PUT THIS BACK"
                 << "<END>\n";
        return true;
#endif

        Value *pSrc = psi->getValueOperand();

        if (not pSrc->getType()->isPointerTy()) {
            /* If we aren't storing to an actual pointer value, there is nothing to worry about.*/
            return true;
        }

        Value *pDest = GetUnderlyingObject(psi->getPointerOperand(), pMod->getDataLayout());
        assert(pDest->getType()->isPointerTy() && "How could this happen");

        Type *pDestTy = pDest->getType()->getPointerElementType();
        assert(pDestTy->isPointerTy() && "Handle this ");

        assert(0 && "Determine if we need to handle this case.");
#if 0
                if (pDestTy->isPointerTy()){
                    assert (0 && "Handle htis");
                } else {
                    DEBUGERR << pMod->getDataLayout().getTypeAllocSize(pDestTy) << "<END>\n";
                    DEBUGERR << pMod->getDataLayout().getTypeAllocSize(pSrc->getType()) << "<END>\n";

                    DEBUGERR << "ALL GOOD!!!" << "<END>\n";
                }

                assert (0 && "fjklsdfjklsdjfklsdjfl");
#endif

        return ret;
    }

    virtual bool validateCallInst(CallInst *pci)
    {

#if 0
                assert(0 && "PUT THIS BACK");
#else
        DEBUGERR << "PUT THIS BACK"
                 << "<END>\n";
        return true;
#endif

        Value *pCalled = pci->getCalledValue();
        if (nullptr == pCalled) {
            return false;
        }

        /*TODO: How would this handle dynamically changed function pointers?*/
        pCalled = pCalled->stripPointerCasts();

        if (not llvm::isa<Function>(pCalled)) {
            return false;
        }
        Function *pFunc           = llvm::cast<Function>(pCalled);
        const FunctionType *fType = pFunc->getFunctionType();

        if (pFunc->getName().equals("memcmp") && fType->getNumParams() == 3) {
            /*
                     * TODO: Verify that the lengths of the pointers are big enough to handle this compare.  
                     * This was done in the original, but memcpy, memset, ... were not.  Figure out 
                     * if there is a reason why.
                     */

            if (not validatePointerAccess_andy(pci->getOperand(0), pci->getOperand(2), pci)) {
                return false;
            }

            if (not validatePointerAccess_andy(pci->getOperand(1), pci->getOperand(2), pci)) {
                return false;
            }

        } else {

            /*Look at parameters.*/
            for (size_t i = 0; i < fType->getNumParams(); i++) {
                if (isa<PointerType>(fType->getParamType(i))) {
                    /*
                             * aragusa: TODO:
                             * Changed the way index's are checked.  This seems correct, but double-check later.
                             */
                    size_t idx = i;
                    Value *Ptr = pci->getOperand(idx);
                    if (idx >= fType->getNumParams()) {
                        printLocation(pci, false);
                        errs() << "Call to external function with pointer parameter last cannot be analyzed\n";
                        errs() << *pci << "\n";
                        return false;
                    }
                    idx++;
                    Value *Size = pci->getOperand(idx);
                    if (!Size->getType()->isIntegerTy()) {
                        printLocation(pci, false);
                        errs() << "Pointer argument must be followed by integer argument representing its size\n";
                        errs() << *pci << "\n";
                        return false;
                    }

                    if (not validatePointerAccess_andy(Ptr, Size, pci)) {
                        return false;
                    }
                }
            }
        }

        return true;
    }

    virtual bool validateLoadInst(LoadInst *pli)
    {
        bool ret = true;

#if 0
                assert(0 && "PUT THIS BACK");
#else
        DEBUGERR << "PUT THIS BACK"
                 << "<END>\n";
        return true;
#endif

        Value *pointer = pli->getPointerOperand();

        Value *pTmp    = GetUnderlyingObject(pointer, pMod->getDataLayout());
        Type *pTmpType = pTmp->getType()->getPointerElementType();

        if (not pTmpType->isPointerTy()) {
            /* If we aren't loading an actual pointer value, there is nothing to worry about.*/
            return true;
        }

        assert(0 && "Determine if we need to handle this case.");

        return ret;
    }

    virtual Value *getSizeOfAlloc(CallInst *pCallInst)
    {
        Value *pVal = pCallInst->getCalledValue();
        if (not llvm::isa<Function>(pVal)) {
            assert(0 && "INline assembly is not allowed, this should have been caught in our validator");
        }

        Function *pFunc = llvm::cast<Function>(pVal);
        if ("calloc" == pFunc->getName()) {
            return BinaryOperator::Create(Instruction::Mul,
                                          pCallInst->getArgOperand(0),
                                          pCallInst->getArgOperand(1),
                                          "ClamBCRTChecks_test",
                                          pCallInst);
        }
        if ("malloc" == pFunc->getName()) {
            return pCallInst->getOperand(0);
        }

        assert(0 && "HOW DID WE GET HERE?");
        return nullptr;
    }

    virtual void populateReturnList(Function *pFunc, std::vector<ReturnInst *> &rets)
    {
        for (auto i = pFunc->begin(), e = pFunc->end(); i != e; i++) {
            BasicBlock *pBB = llvm::cast<BasicBlock>(i);
            for (auto i = pBB->begin(), e = pBB->end(); i != e; i++) {
                if (ReturnInst *ri = llvm::dyn_cast<ReturnInst>(i)) {
                    rets.push_back(ri);
                }
            }
        }
    }

    virtual void addGlobalSetInstructions(PHINode *phiNode, GlobalVariable *pgv)
    {
        for (size_t i = 0; i < phiNode->getNumIncomingValues(); i++) {
            Value *pv = phiNode->getIncomingValue(i);
            if (CallInst *pci = llvm::dyn_cast<CallInst>(pv)) {
                getMaxSize(pci, pgv);
            } else {
                DEBUGERR << *pv << "<END>\n";
                DEBUGERR << "REVISIT WHETHER OR NOT I NEED THIS"
                         << "<END>\n";
                //                        assert (0 && "DETERMINE IF I NEED TO HANDLE THIS");
            }
        }
    }

    virtual bool sameObj(Value *pStoredValue, Value *pParam)
    {
        bool bRet = false;
        User *pu  = nullptr;

        if (pStoredValue == pParam) {
            return true;
        }

        pu = llvm::dyn_cast<User>(pParam);
        if (nullptr == pu) {
            return false;
        }

        for (size_t i = 0; i < pu->getNumOperands(); i++) {
            if (sameObj(pStoredValue, pu->getOperand(i))) {
                return true;
            }
        }

        return bRet;
    }

    /*pStoredValue must either be storage (AllocaInst or GlobalVariable) or a 
             * function parameter.*/
    virtual void addGlobalSetInstructions2(Value *pStoredValue, GlobalVariable *pgv)
    {
        std::set<llvm::Instruction *> insts;
        std::set<llvm::GlobalVariable *> globs;

        if (Argument *pArg = llvm::dyn_cast<Argument>(pStoredValue)) {
            /*We don't support calling functions that we cannot see inside of, but
                     * allowing it in the individual passes makes it easier to do testing.
                     *
                     * There will be a separate validator that is run first, to catch
                     * any rule breakage at the beginning.
                     */
            Function *pFunc = pArg->getParent();
            if (pFunc->begin() == pFunc->end()) {
                return;
            }
        }
        getDependentValues(pStoredValue, insts, globs);

        for (auto i : insts) {
            if (CallInst *pci = llvm::dyn_cast<CallInst>(i)) {
                bool bFound = false;

                for (size_t i = 0; i < pci->getNumArgOperands(); i++) {
                    if (sameObj(pStoredValue, pci->getArgOperand(i))) {
                        bFound            = true;
                        Function *pCalled = pci->getCalledFunction();

                        size_t j       = 0;
                        auto paramIter = pCalled->arg_begin();
                        Value *pArg    = nullptr;
                        for (auto paramEnd = pCalled->arg_end();
                             paramIter != paramEnd; paramIter++) {
                            if (j == i) {
                                pArg = llvm::cast<Value>(paramIter);
                                break;
                            }
                            j++;
                        }

                        /*The only way this seems possible is for a variadic function.*/
                        if (nullptr != pArg) {
                            addGlobalSetInstructions2(pArg, pgv);
                            break;
                        }
                    }
                }
                assert(bFound && "Not in arg operands");
            } else if (llvm::isa<LoadInst>(i)) {
                /*Nothing to do for LoadInst, but want to make sure I handle all of the cases.*/
            } else if (llvm::isa<ReturnInst>(i)) {
            } else if (StoreInst *psi = llvm::dyn_cast<StoreInst>(i)) {
                DEBUGERR << *psi << "<END>\n";
                DEBUGERR << (psi->getPointerOperand() == pStoredValue) << "<END>\n";
                DEBUGERR << *(psi->getValueOperand()) << "<END>\n";
                Value *val = psi->getValueOperand();
                if (CallInst *pci = llvm::dyn_cast<CallInst>(val)) {
                    getMaxSize(pci, pgv);
                } else if (PHINode *phi = llvm::dyn_cast<PHINode>(val)) {
                    addGlobalSetInstructions(phi, pgv);
                } else {
                    assert(0 && "UNIMPLEMENTED IN STORE INST");
                }
            } else if (llvm::isa<SExtInst>(i)) {
                //Nothing to do, but I want to make sure I handle all the cases.
            } else if (llvm::isa<GetElementPtrInst>(i)) {
            } else {
                DEBUGERR << *i << "<END>\n";
                assert(0 && "UNIMPLEMENTED");
            }

            //                    if (StoreInst * psi = llvm::dyn_cast<);

            DEBUGERR << *i << "<END>\n";
        }
    }

    virtual void addGlobalSetInstructions(LoadInst *pLoadInst, GlobalVariable *pgv)
    {

        DEBUGERR << *pLoadInst << "<END>\n";
        Value *loadedValue = pLoadInst->getPointerOperand();
        DEBUGERR << *loadedValue << "<END>\n";

        addGlobalSetInstructions2(loadedValue, pgv);
    }

    virtual void addGlobalSetInstructions(Value *retVal, GlobalVariable *pgv)
    {
        if (PHINode *pn = llvm::dyn_cast<PHINode>(retVal)) {
            DEBUGERR << *pn << "<END>\n";
            addGlobalSetInstructions(pn, pgv);
        } else if (LoadInst *pli = llvm::dyn_cast<LoadInst>(retVal)) {
            addGlobalSetInstructions(pli, pgv);
        } else if (CallInst *pci = llvm::dyn_cast<CallInst>(retVal)) {
            getMaxSize(pci, pgv);
        } else {
            DEBUGERR << *retVal << "<END>\n";
            assert(0 && "NOT IMPLEMENTED");
        }
    }

    virtual void saveSize(Value *pSize, GlobalVariable *pgv, Instruction *insertBefore)
    {
        Type *pointeeType = pgv->getType()->getPointerElementType();
        if (pSize->getType() != pointeeType) {
            DEBUGERR << *insertBefore << "<END>\n";
            pSize = CastInst::CreateZExtOrBitCast(pSize, pointeeType, "ClamBCRTChecks_cast", insertBefore);
            DEBUGERR << *pSize << "<END>\n";
            assert(pSize && "Cannot allocate memory");
        }
        pSize = new StoreInst(pSize, pgv, insertBefore);

        assert(pSize && "Cannot allocate memory");
    }

    virtual Value *getMaxSize(CallInst *pCallInst, GlobalVariable *pgv)
    {
        Value *pRet     = nullptr;
        Function *pFunc = pCallInst->getCalledFunction();
        if (pFunc->getName() == "calloc") {
            pRet = getSizeOfAlloc(pCallInst);
            if (pgv) {
                saveSize(pRet, pgv, pCallInst);
            }
        } else if (pFunc->getName() == "malloc") {
            pRet = getSizeOfAlloc(pCallInst);
            if (pgv) {
                saveSize(pRet, pgv, pCallInst);
            }
        } else {

            /*
                     * This only handles the case where the result pointer is returned from a 
                     * function.  The case where it is initialized
                     * as part of the argument list would end up being a phi/load/select instruction
                     */

            DEBUGERR << *pCallInst << "<END>\n";
            DEBUGERR << *pFunc << "<END>\n";
            DEBUGERR << *(pCallInst->getType()) << "<END>\n";

            std::vector<ReturnInst *> rets;
            populateReturnList(pFunc, rets);

            Type *t = Type::getInt64Ty(pMod->getContext());
            if (nullptr == pgv) {
                assert(0 && "Should have a global passed in");
                pgv = new GlobalVariable(*pMod, t, false,
                                         GlobalValue::InternalLinkage, ConstantInt::get(t, 0), "ClamBCRTChecks_traceSize");
            }
            DEBUGERR << *pgv << "<END>\n";

            for (size_t i = 0; i < rets.size(); i++) {
                ReturnInst *ri = rets[i];
                DEBUGERR << *ri << "<END>\n";
                Value *rv = ri->getReturnValue();
                DEBUGERR << *rv << "<END>\n";

                addGlobalSetInstructions(rv, pgv);
            }

            pRet = pgv;

            //assert (0 && "HANDLE LOCAL INIT FUNCTION");
        }

        return pRet;
    }

    virtual GlobalVariable *getSizeGlobal(Value *access)
    {
        static std::map<Value *, GlobalVariable *> globals;

        if (globals.end() == globals.find(access)) {
            Type *t             = Type::getInt64Ty(pMod->getContext());
            GlobalVariable *pgv = new GlobalVariable(*pMod, t, false,
                                                     GlobalValue::InternalLinkage, ConstantInt::get(t, 0), "ClamBCRTChecks_traceSize");
            globals[access]     = pgv;
        }

        return globals[access];
    }

    virtual bool validatePointerAccess_andy(Value *ptr, Value *size, Instruction *pInst)
    {

        Value *actualPtr = GetUnderlyingObject(ptr, pMod->getDataLayout());

        Value *sizeMax = nullptr;

        if (CallInst *pCallInst = llvm::dyn_cast<CallInst>(actualPtr)) {
            GlobalVariable *pgv = getSizeGlobal(pInst);
            sizeMax             = getMaxSize(pCallInst, pgv);
            assert(sizeMax && "getMaxSize returned NULL");

        } else if (GlobalVariable *pgv = llvm::dyn_cast<GlobalVariable>(actualPtr)) {

            /*Check for constness.*/

            //                    if (pgv->hasInitializer()){
            //                        Value * pInit = pgv->getInitializer();
            //                    }

            GlobalVariable *sizeTracker = getSizeGlobal(pInst);

            addGlobalSetInstructions2(pgv, sizeTracker);
            sizeMax = sizeTracker;

            //assert (0 && "handle globals 2");

        } else if (PHINode *pn = llvm::dyn_cast<PHINode>(actualPtr)) {
            GlobalVariable *pgv = getSizeGlobal(pInst);
            addGlobalSetInstructions(pn, pgv);
            sizeMax = pgv;
        } else if (LoadInst *pli = llvm::dyn_cast<LoadInst>(actualPtr)) {
            validatePointerAccess_andy(pli->getPointerOperand(), size, pInst);
        } else if (llvm::isa<AllocaInst>(actualPtr)) {
            sizeMax = size;
        } else if (llvm::isa<Argument>(actualPtr)) {
        } else {
            //Nothing to do here, but want to leave the assert for testing.
            DEBUGERR << *actualPtr << "<END>\n";
            DEBUGERR << *ptr << "<END>\n";
            DEBUGERR << *size << "<END>\n";
            DEBUGERR << *pInst << "<END>\n";

            assert(0 && "HANDLE ELSE CASE");
        }

        if (nullptr != sizeMax) {
            DEBUGERR << *actualPtr << "<END>\n";
            DEBUGERR << *sizeMax << "<END>\n";

            if (GlobalVariable *pgv = llvm::dyn_cast<GlobalVariable>(sizeMax)) {
                DEBUGERR << "<END>\n";
                sizeMax = new LoadInst(pgv, "ClamBCRTChecks_load_traceSize", pInst);
            }
            if (sizeMax->getType() != size->getType()) {
                IntegerType *sizeIT    = llvm::dyn_cast<IntegerType>(size->getType());
                IntegerType *sizeMaxIT = llvm::dyn_cast<IntegerType>(sizeMax->getType());
                if (not(sizeIT and sizeMaxIT)) {
                    assert(0 && "HOW IS THIS POSSIBLE?");
                }

                if (sizeIT->getBitWidth() > sizeMaxIT->getBitWidth()) {
                    sizeMax = CastInst::CreateZExtOrBitCast(sizeMax, size->getType(), "ClamBCRTChecks_cast", pInst);
                } else {
                    size = CastInst::CreateZExtOrBitCast(size, sizeMax->getType(), "ClamBCRTChecks_cast", pInst);
                }
                DEBUGERR << sizeMax->getType()->isIntegerTy() << "<END>\n";
                DEBUGERR << size->getType()->isIntegerTy() << "<END>\n";
            }

            BasicBlock *orig  = pInst->getParent();
            BasicBlock *newBB = SplitBlock(pInst->getParent(), pInst);

            Instruction *insertPoint = orig->getTerminator();
            //ICmpInst * cond = new ICmpInst(insertPoint, CmpInst::ICMP_UGE, size, maxSize, "uge");
            DEBUGERR << *size->getType() << "<END>\n";
            DEBUGERR << *sizeMax->getType() << "<END>\n";
            //ICmpInst * cond = new ICmpInst(insertPoint, CmpInst::ICMP_UGE, size, sizeMax, "ugt");
            ICmpInst *cond = new ICmpInst(insertPoint, CmpInst::ICMP_UGT, size, sizeMax, "ugt_761_");
            DEBUGERR << *cond << "<END>\n";
            assert(cond && "Cannot allocate memory");

            BasicBlock *abrtBB = getAbortBB(0, orig);
            PHINode *phiNode   = cast<PHINode>(abrtBB->begin());
            Value *location    = ConstantInt::get(phiNode->getType(), 0); /*TODO: Get a reasonable location.*/
            phiNode->addIncoming(location, orig);

            BranchInst::Create(abrtBB, newBB, cond, insertPoint);

            delInst.push_back(insertPoint);
        }

        return true;
    }

    virtual bool validateMemIntrinsic(MemIntrinsic *pmi)
    {

#if 0
                {
                    static int cnt = 0;
                    cnt++;
                    if (cnt > 1){
                        return true;
                    }
                }
#endif

        if (not validatePointerAccess_andy(pmi->getDest(), pmi->getLength(), pmi)) {
            return false;
        }

        if (llvm::isa<MemTransferInst>(pmi)) {
            MemTransferInst *mti = llvm::cast<MemTransferInst>(pmi);
            if (not validatePointerAccess_andy(mti->getSource(), mti->getLength(), pmi)) {
                return false;
            }
        }

        DEBUGERR << "FIXMEREALBAD::TAKE THIS OUT<END>\n";
        return true;

        if (not validatePointerAccess(pmi->getDest(), pmi->getLength(), pmi)) {
            DEBUGERR << "RETURNING validate failed<END>\n";
            return false;
        }

        DEBUGERR << "validate passed<END>\n";
        if (llvm::isa<MemTransferInst>(pmi)) {
            MemTransferInst *mti = llvm::cast<MemTransferInst>(pmi);
            if (not validatePointerAccess(mti->getSource(), mti->getLength(), pmi)) {
                return false;
            }
        }

        assert(0 && "RETURNING TRUE, BUT WANT TO SEE MY OUTPUT :)");
        return true;
    }

    virtual bool runOnFunction(Function &F)
    {

        DEBUGERR << "TEMPORARILY REMOVING the runtime checks."
                 << "<END>\n";
        return false;
#if 0
                if ("entrypoint" == F.getName()){
                    DEBUGERR << "DUMPING ENTRYPOINT::BEFORE PTRVERIFIER<END>\n";
                    DEBUGERR << F << "<END>\n";
                }
#endif

#ifndef CLAMBC_COMPILER
        // Bytecode was already verified and had stack protector applied.
        // We get called again because ALL bytecode functions loaded are part of
        // the same module.
        if (F.hasFnAttribute(Attribute::StackProtectReq))
            return false;
#endif
        TLI = &getAnalysis<TargetLibraryInfoWrapperPass>().getTLI();

        pMod = F.getParent();

        Changed = false;
        BaseMap.clear();
        BoundsMap.clear();
        delInst.clear();
        AbrtBB = 0;
        valid  = true;

        if (functionRecurses(&F)) {
            errs() << "INVALID: Recursion detected, callgraph SCC components: ";
            errs() << F.getName() << ", "
                   << "(self-loop)\n";
            valid = false;
        }

        setInsertPoint(&F);

#if 0
                TD       = &getAnalysis<TargetData>();
#endif
        SE = &getAnalysis<ScalarEvolutionWrapperPass>().getSE();
        ;
#if 0
                PT       = &getAnalysis<PointerTracking>();
#endif
        DT       = &getAnalysis<DominatorTreeWrapperPass>().getDomTree();
        expander = new SCEVExpander(*SE, pMod->getDataLayout(), "ClamBCRTChecksExpander");

        std::vector<Instruction *> insts;
        valid &= saveMemoryInsts(&F, insts);

        if (valid) {
            for (unsigned Idx = 0; Idx < insts.size(); ++Idx) {
                Instruction *pInst = insts[Idx];
                if (llvm::isa<LoadInst>(pInst)) {
                    LoadInst *pli = llvm::cast<LoadInst>(pInst);
                    valid &= validateLoadInst(pli);
                } else if (llvm::isa<StoreInst>(pInst)) {
                    StoreInst *psi = llvm::cast<StoreInst>(pInst);
                    valid &= validateStoreInst(psi);
                } else if (llvm::isa<MemIntrinsic>(pInst)) {
                    MemIntrinsic *pmi = llvm::cast<MemIntrinsic>(pInst);
                    valid &= validateMemIntrinsic(pmi);
                } else if (llvm::isa<CallInst>(pInst)) {
                    CallInst *pci = llvm::cast<CallInst>(pInst);
                    valid &= validateCallInst(pci);
                }

                if (!valid) {
                    break;
                }
            }
        }

        if (!valid) {
            //TODO: FIX THIS.
            bool standardCompiler = false;
            if (not standardCompiler) {
                assert(0 && "NOT VALID");
            }
        } else {
            Changed = true;
        }

        for (unsigned i = 0; i < delInst.size(); ++i) {
            delInst[i]->eraseFromParent();
        }

        if ("entrypoint" == F.getName()) {
            DEBUGERR << "DUMPING ENTRYPOINT::AFTER PTRVERIFIER<END>\n";
            DEBUGERR << F << "<END>\n";
        }

        /*TODO: Only return true when we actually change something.*/
        return Changed;

        for (unsigned Idx = 0; Idx < insts.size(); ++Idx) {
            Instruction *II = insts[Idx];
#if 0
                    DEBUG(dbgs() << "checking " << *II << "\n");
#else
            //                    DEBUGERR << "checking " << *II << "<END>\n"; //TODO: create a logger.
#endif
            if (LoadInst *LI = dyn_cast<LoadInst>(II)) {
                Type *Ty = LI->getType();
#if 0
                        valid &= validateAccess(LI->getPointerOperand(),
                                TD->getTypeAllocSize(Ty), LI);
#else
                valid &= validateAccess(LI->getPointerOperand(),
                                        pMod->getDataLayout().getTypeAllocSize(Ty), LI);
#endif
            } else if (StoreInst *SI = dyn_cast<StoreInst>(II)) {
                Type *Ty = SI->getOperand(0)->getType();
#if 0
                        valid &= validateAccess(SI->getPointerOperand(),
                                TD->getTypeAllocSize(Ty), SI);
#else
                valid &= validateAccess(SI->getPointerOperand(),
                                        pMod->getDataLayout().getTypeAllocSize(Ty), SI);
#endif
            } else if (MemIntrinsic *MI = dyn_cast<MemIntrinsic>(II)) {
                valid &= validateAccess(MI->getDest(), MI->getLength(), MI);
                if (MemTransferInst *MTI = dyn_cast<MemTransferInst>(MI)) {
                    valid &= validateAccess(MTI->getSource(), MI->getLength(), MI);
                }
            } else if (CallInst *CI = dyn_cast<CallInst>(II)) {
                Value *V                = CI->getCalledValue()->stripPointerCasts();
                Function *F             = cast<Function>(V);
                const FunctionType *FTy = F->getFunctionType();
                if (F->getName().equals("memcmp") && FTy->getNumParams() == 3) {
                    valid &= validateAccess(CI->getOperand(1), CI->getOperand(3), CI);
                    valid &= validateAccess(CI->getOperand(2), CI->getOperand(3), CI);
                    continue;
                }
                unsigned i;
#ifdef CLAMBC_COMPILER
                i = 0;
#else
                i = 1; // skip hidden ctx*
#endif
                for (; i < FTy->getNumParams(); i++) {
                    if (isa<PointerType>(FTy->getParamType(i))) {
                        /*
                                 * aragusa: TODO:
                                 * Changed the way index's are checked.  This seems correct, but double-check later.
                                 */
                        size_t idx = i;
                        Value *Ptr = CI->getOperand(idx);
                        if (idx >= FTy->getNumParams()) {
                            printLocation(CI, false);
                            errs() << "Call to external function with pointer parameter last cannot be analyzed\n";
                            errs() << *CI << "\n";
                            valid = 0;
                            break;
                        }
                        idx++;
                        Value *Size = CI->getOperand(idx);
                        if (!Size->getType()->isIntegerTy()) {
                            DEBUGERR << *Ptr << "<END>\n";
                            DEBUGERR << *Size << "<END>\n";
                            printLocation(CI, false);
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
        if (badFunctions.count(&F)) {
            valid = 0;
        }

        /* aragusa:
                 * I don't understand why we are doing this, instead of failing the compile.
                 */
        if (!valid) {
            //DEBUG(F.dump());
            //F.dump();
            DEBUGERR << "ERRORS<END>\n";
            DEBUGERR << *(F.getParent()) << "<END>\n";
            ClamBCStop("Verification found errors!", &F);
            // replace function with call to abort
#if 0
                    std::vector<const Type *> args;
                    FunctionType *abrtTy = FunctionType::get(
                            Type::getVoidTy(F.getContext()), args, false);
#else
            FunctionType *abrtTy = FunctionType::get(Type::getVoidTy(F.getContext()), false);
#endif
            Constant *func_abort =
                F.getParent()->getOrInsertFunction("abort", abrtTy);

            BasicBlock *BB  = &F.getEntryBlock();
            Instruction *I  = llvm::cast<Instruction>(BB->begin());
            Instruction *UI = new UnreachableInst(F.getContext(), I);
            CallInst *AbrtC = CallInst::Create(func_abort, "ClamBCRTChecks_call_abort", UI);
            AbrtC->setCallingConv(CallingConv::C);
            AbrtC->setTailCall(true);
            AbrtC->setDoesNotReturn();
            AbrtC->setDoesNotThrow();
            // remove all instructions from entry
#if 0
                    BasicBlock::iterator BBI = I, BBE = BB->end();
                    while (BBI != BBE) {
#else
            for (auto BBI = BB->begin(), BBE = BB->end(); BBI != BBE; BBI++) {
#endif
            if (!BBI->use_empty())
                BBI->replaceAllUsesWith(UndefValue::get(BBI->getType()));
            BB->getInstList().erase(BBI++);
        }
    }

    // bb#9967 - deleting obsolete termination instructions
    for (unsigned i = 0; i < delInst.size(); ++i) {
        delInst[i]->eraseFromParent();
    }

    delete expander;
    expander = nullptr;

#if 0
                if ("entrypoint" == F.getName()){
                    DEBUGERR << "DUMPING ENTRYPOINT::AFTER PTRVERIFIER<END>\n";
                    DEBUGERR << F << "<END>\n";
                }
#endif

    return Changed;
}

#if 0
aragusa: appears to never be called.
             virtual void releaseMemory()
             {
                 badFunctions.clear();
             }
#endif

virtual void
getAnalysisUsage(AnalysisUsage &AU) const
{
#if 0
             AU.addRequired<TargetData>();
#endif
    AU.addRequired<DominatorTreeWrapperPass>();
    AU.addRequired<ScalarEvolutionWrapperPass>();
#if 0
             AU.addRequired<PointerTracking>();
#endif
    AU.addRequired<CallGraphWrapperPass>();
    AU.addRequired<TargetLibraryInfoWrapperPass>();
}

bool isValid() const
{
    return valid;
}

private:
#if 0
         PointerTracking *PT;
         TargetData *TD;
#endif
ScalarEvolution *SE    = nullptr;
SCEVExpander *expander = nullptr;
DominatorTree *DT      = nullptr;
TargetLibraryInfo *TLI = nullptr;
DenseMap<Value *, Value *> BaseMap;
DenseMap<Value *, Value *> BoundsMap;
BasicBlock *AbrtBB = nullptr;
bool Changed       = false;
bool valid         = true;

/*
          * aragusa:
          *
          * I don't understand the reason for having all the bitcast and zext instructions inserted 
          * into the first basic block, why not just insert them where they will be used?
          *
          * They are only inserted into the first basic block if getInsertPoint is called with a non-Instruction.
          */
Instruction *insertPoint = nullptr;

void setInsertPoint(Function *pFunc)
{
    BasicBlock::iterator It = pFunc->getEntryBlock().begin();
    while (isa<AllocaInst>(It) || isa<PHINode>(It)) ++It;
    insertPoint = llvm::cast<Instruction>(It);
}

Instruction *getInsertPoint(Value *V)
{
    BasicBlock::iterator It(insertPoint);
    if (Instruction *I = dyn_cast<Instruction>(V)) {
        BasicBlock::iterator n(I);
        It = n;
        ++It;
    }
    return llvm::cast<Instruction>(It);
}

Instruction *getTerminator(BasicBlock *pBB)
{
    for (auto i = pBB->begin(), e = pBB->end(); i != e; i++) {
        Instruction *inst = llvm::cast<Instruction>(i);
        if (inst->isTerminator()) {
            return inst;
        }
    }

    DEBUGERR << *pBB << "<END>\n";
    assert(0 && "Broken block, no terminator");

    return nullptr;
}

Instruction *getTerminator(Function *pFunc)
{
    return getTerminator(&(pFunc->getEntryBlock()));
}

Function *getReallocFunc() const
{
    static Function *pRet = nullptr;
    if (nullptr == pRet) {
        DEBUGERR << "Implement this"
                 << "<END>\n";
        assert(0 && "Determine if we need to handle this case.");
    }

    return pRet;
}

/*computeAllocationCountValue ripped from PointerTracking analysis pass that was removed.*/
Value *computeAllocationCountValue(Value *P, Type *&Ty) const
{

    Value *V = P->stripPointerCasts();
    if (AllocaInst *AI = dyn_cast<AllocaInst>(V)) {
        Ty = AI->getAllocatedType();
        // arraySize elements of type Ty.
        return AI->getArraySize();
    }

    /*aragusa: should we be looking for calloc?  (I couldn't find it in mrt-bytecode-signatures)*/
    if (CallInst *CI = extractMallocCall(V, TLI)) {
        Ty = getMallocAllocatedType(CI, TLI);
        if (!Ty)
            return nullptr;
        Value *arraySize = getMallocArraySize(CI, pMod->getDataLayout(), TLI);
        if (!arraySize) {
            Ty = Type::getInt8Ty(P->getContext());
            return CI->getOperand(1);
        }
        // arraySize elements of type Ty.
        return arraySize;
    }

    if (GlobalVariable *GV = dyn_cast<GlobalVariable>(V)) {
        if (GV->hasDefinitiveInitializer()) {
            Constant *C = GV->getInitializer();
            if (const ArrayType *ATy = dyn_cast<ArrayType>(C->getType())) {
                Ty = ATy->getElementType();
                return ConstantInt::get(Type::getInt32Ty(P->getContext()),
                                        ATy->getNumElements());
            }
        }
        Ty = cast<PointerType>(GV->getType())->getElementType();
        return ConstantInt::get(Type::getInt32Ty(P->getContext()), 1);
        //TODO: implement more tracking for globals
    }

    if (CallInst *CI = dyn_cast<CallInst>(V)) {
        Function *reallocFunc = getReallocFunc();
        CallSite CS(CI);
        Function *F = dyn_cast<Function>(CS.getCalledValue()->stripPointerCasts());
        if (F == reallocFunc) {
            Ty = Type::getInt8Ty(P->getContext());
            // realloc allocates arg1 bytes.
            return CS.getArgument(1);
        }
    }

    return nullptr;
}

#if 0
         Value *getPointerBase(Value *Ptr)
         {
             DEBUGERR << Ptr << "::" << *Ptr << "<END>\n";
             if (BaseMap.count(Ptr)) {
                 DEBUGERR << "RETURNING" << BaseMap[Ptr] << "::" << *(BaseMap[Ptr]) << "<END>\n";
                 return BaseMap[Ptr];
             }
             Value *P = Ptr->stripPointerCasts();
             if (BaseMap.count(P)) {
                 DEBUGERR << "RETURNING" << BaseMap[P] << "::" << *(BaseMap[P]) << "<END>\n";
                 return BaseMap[Ptr] = BaseMap[P];
             }
#if 0
             Value *P2 = P->getUnderlyingObject();
#else
             /*aragusa: 
              * Parameter 2 is the max number of checks.  
              * I can't imagine there would be more than the default, but keep going until you find it.
              */
             Value * P2 = GetUnderlyingObject(P, pMod->getDataLayout(), 0);
#endif
             if (P2 != P) {
                 DEBUGERR << P2 << "::" << *P2 << "<END>\n";
                 Value *V            = getPointerBase(P2);
                 DEBUGERR << "RETURNING" << V << "::" << *V << "<END>\n";
                 return BaseMap[Ptr] = V;
             }

             Type *P8Ty = PointerType::getUnqual(Type::getInt8Ty(Ptr->getContext()));
             /* 
              * aragusa: 
              * The additional PHI node is to determine which poiner to do bounds checking on.
              */
             if (PHINode *PN = dyn_cast<PHINode>(Ptr)) {
                 /* aragusa: should we be advancing past all phi nodes, and not just the first one??? */
                 BasicBlock::iterator It (PN);
                 ++It;
#if 0
                 PHINode *newPN = PHINode::Create(P8Ty, ".verif.base", &*It);
#else
                 PHINode *newPN = PHINode::Create(P8Ty, PN->getNumIncomingValues(), ".verif.base", llvm::cast<Instruction>(It));
#endif
                 Changed        = true;
                 BaseMap[Ptr]   = newPN;
                 DEBUGERR << Ptr << "::" << *Ptr << "<END>\n";

                 for (unsigned i = 0; i < PN->getNumIncomingValues(); i++) {
                     Value *Inc = PN->getIncomingValue(i);
                     DEBUGERR << Inc << "<END>\n";
                     Value *V   = getPointerBase(Inc);

                     /*
                      * aragusa:
                      * TODO: put this back to when it used the expander, after I fix this issue with the circular PHINodes.
                      * MIGHT NEED TO CHECK OUT the original, and add the changes, once the PHI Node issue is resolved.
                      * This problem exists when there is a circular reference between a PHINode and another instruction.  These
                      * are created by clang/llvm, not us.
                      *
                      * I think the way to handle this is to find all references to each pointer variable, and add the checks that way. 
                      * This will also need to be done with functions that allocate memory, and pointers returned from functions.
                      *
                      * %.03 = phi i8* [ %2, %10 ], [ %56, %23 ]
                      * ...
                      * %56 = getelementptr inbounds i8, i8* %.03, i32 1
                      */
                     if (V == newPN){
                         DEBUGERR << *Ptr << "<END>\n";
                         DEBUGERR << *Inc << "<END>\n";
                         DEBUGERR << *V << "<END>\n";
                     }
                     assert ((V != newPN) && "Can't have a phinode reference itself.");

                     DEBUGERR << Inc << "<END>\n";
                     DEBUGERR << *Inc << "<END>\n";
                     DEBUGERR << V << "<END>\n";
                     DEBUGERR << *V << "<END>\n";
                     DEBUGERR << (V == newPN) << "<END>\n";

                     newPN->addIncoming(V, PN->getIncomingBlock(i));
                 }
                 return newPN;
             }
             if (SelectInst *SI = dyn_cast<SelectInst>(Ptr)) {
                 BasicBlock::iterator It (SI);
                 ++It;
                 Value *TrueB  = getPointerBase(SI->getTrueValue());
                 Value *FalseB = getPointerBase(SI->getFalseValue());
                 if (TrueB && FalseB) {
                     SelectInst *NewSI   = SelectInst::Create(SI->getCondition(), TrueB,
                             FalseB, ".select.base", llvm::cast<Instruction>(It));
                     Changed             = true;
                     return BaseMap[Ptr] = NewSI;
                 }
             }
             if (Ptr->getType() != P8Ty) {
                 if (Constant *C = dyn_cast<Constant>(Ptr))
                     Ptr = ConstantExpr::getPointerCast(C, P8Ty);
                 else {
                     /*aragusa: Why not just insert the bit cast directly before it is used?*/
                     Instruction *I = getInsertPoint(Ptr);
                     Ptr            = new BitCastInst(Ptr, P8Ty, "", I);
                 }
                 Changed             = true;
             }
             return BaseMap[Ptr] = Ptr;
         }
#endif

Value *getValAtIdx(Function *F, unsigned Idx)
{
    Value *Val = NULL;

    // check if accessed Idx is within function parameter list
    if (Idx < F->arg_size()) {
        Function::arg_iterator It    = F->arg_begin();
        Function::arg_iterator ItEnd = F->arg_end();
        for (unsigned i = 0; i < Idx; ++i, ++It) {
            // redundant check, should not be possible
            if (It == ItEnd) {
                // Houston, the impossible has become possible
                printDiagnostic("Idx is outside of Function parameters", F);
                break;
            }
        }
        // retrieve value ptr of argument of F at Idx
        Val = &(*It);
    } else {
        // Idx is outside function parameter list
        printDiagnostic("Idx is outside of Function parameters", F);
    }
    return Val;
}

#if 0
         Value *getPointerBounds(Value *Base)
         {
             if (BoundsMap.count(Base)) {
                 return BoundsMap[Base];
             }
             Type *I64Ty = Type::getInt64Ty(Base->getContext());

             if (Base->getType()->isPointerTy()) {
                 if (Argument *A = dyn_cast<Argument>(Base)) {
                     Function *F            = A->getParent();
                     const FunctionType *FT = F->getFunctionType();

                     bool checks = true;
                     // last argument check
                     if (A->getArgNo() == (FT->getNumParams() - 1)) {
                         printDiagnostic("pointer argument cannot be last argument", F);
                         checks = false;
                     }

                     // argument after pointer MUST be a integer (unsigned probably too)
                     if (checks && !FT->getParamType(A->getArgNo() + 1)->isIntegerTy()) {
                         printDiagnostic("argument following pointer argument is not an integer", F);
                         checks = false;
                     }

                     if (checks) {
                         return BoundsMap[Base] = getValAtIdx(F, A->getArgNo() + 1);
                     }
                 }
             }

#ifndef CLAMBC_COMPILER
             // first arg is hidden ctx
             if (Argument *A = dyn_cast<Argument>(Base)) {
                 if (A->getArgNo() == 0) {
                     Type *Ty = cast<PointerType>(A->getType())->getElementType();
#if 0
                     return ConstantInt::get(I64Ty, TD->getTypeAllocSize(Ty));
#else
                     return ConstantInt::get(I64Ty, pMod->getDataLayout().getTypeAllocSize(Ty));
#endif
                 }
             }
             if (LoadInst *LI = dyn_cast<LoadInst>(Base)) {
#if 0
                 Value *V = LI->getPointerOperand()->stripPointerCasts()->getUnderlyingObject();
#else
                 Value *V = GetUnderlyingObject(LI->getPointerOperand()->stripPointerCasts(), pMod->getDataLayout(), 0);
#endif
                 if (Argument *A = dyn_cast<Argument>(V)) {
                     if (A->getArgNo() == 0) {
                         // pointers from hidden ctx are trusted to be at least the
                         // size they say they are
                         Type *Ty = cast<PointerType>(LI->getType())->getElementType();
#if 0
                         return ConstantInt::get(I64Ty, TD->getTypeAllocSize(Ty));
#else
                         return ConstantInt::get(I64Ty, pMod->getDataLayout().getTypeAllocSize(Ty));
#endif
                     }
                 }
             }
#endif
             /* 
              * aragusa: 
              * Inserting a new phi node to know what bounds to check.  It has to match the pointer that we are actually 
              * looking at.
              */
             if (PHINode *PN = dyn_cast<PHINode>(Base)) {
                 BasicBlock::iterator It (PN);
                 ++It;
#if 0
                 PHINode *newPN  = PHINode::Create(I64Ty, ".verif.bounds", &*It);
#else
                 PHINode *newPN  = PHINode::Create(I64Ty, PN->getNumIncomingValues(), ".verif.bounds", llvm::cast<Instruction>(It));
#endif
                 Changed         = true;
                 BoundsMap[Base] = newPN;

                 bool good = true;
                 DEBUGERR << PN->getNumIncomingValues() << "<END>\n";
                 DEBUGERR << *PN << "<END>\n";
                 for (unsigned i = 0; i < PN->getNumIncomingValues(); i++) {
                     DEBUGERR << "<END>\n";
                     Value *Inc = PN->getIncomingValue(i);
                     DEBUGERR << Inc << "<END>\n";
                     DEBUGERR << *Inc << "<END>\n";
                     Value *B   = getPointerBounds(Inc);
                     DEBUGERR << B << "<END>\n";
                     DEBUGERR << *B << "<END>\n";
                     if (!B) {
                         good = false;
                         B    = ConstantInt::get(newPN->getType(), 0);
                         //DEBUG(dbgs() << "bounds not found while solving phi node: " << *Inc
                         //             << "\n");
                         DEBUGERR << "bounds not found while solving phi node: " << *Inc << "<END>\n";
                     }
                     DEBUGERR << PN->getIncomingBlock(i) << "<END>\n";
                     DEBUGERR << *(PN->getIncomingBlock(i)) << "<END>\n";
                     newPN->addIncoming(B, PN->getIncomingBlock(i));
                 }
                 if (!good)
                     newPN = 0;
                 return BoundsMap[Base] = newPN;
             }
             if (SelectInst *SI = dyn_cast<SelectInst>(Base)) {
                 BasicBlock::iterator It (SI);
                 ++It;
                 Value *TrueB  = getPointerBounds(SI->getTrueValue());
                 Value *FalseB = getPointerBounds(SI->getFalseValue());
                 if (TrueB && FalseB) {
                     SelectInst *NewSI      = SelectInst::Create(SI->getCondition(), TrueB,
                             FalseB, ".select.bounds", llvm::cast<Instruction>(It));
                     Changed                = true;
                     return BoundsMap[Base] = NewSI;
                 }
             }

             Type *Ty = nullptr;
#if 0
             Value *V = PT->computeAllocationCountValue(Base, Ty);
#else

             Value * V = computeAllocationCountValue(Base, Ty);
#endif
             if (!V) {
                 Base = Base->stripPointerCasts();
                 if (CallInst *CI = dyn_cast<CallInst>(Base)) {
                     Function *F             = CI->getCalledFunction();
                     const FunctionType *FTy = F->getFunctionType();
                     // last operand is always size for this API call kind
                     if (F->isDeclaration() && FTy->getNumParams() > 0) {
                         if (FTy->getParamType(FTy->getNumParams() - 1)->isIntegerTy())
                             V = CI->getOperand(FTy->getNumParams());
                     }
                 }
                 if (!V)
                     return BoundsMap[Base] = 0;
             } else {
#if 0
                 unsigned size = TD->getTypeAllocSize(Ty);
#else
                 uint64_t size = pMod->getDataLayout().getTypeAllocSize(Ty);
#endif
                 if (size > 1) {
                     Constant *C = cast<Constant>(V);
                     C           = ConstantExpr::getMul(C,
                             ConstantInt::get(Type::getInt32Ty(C->getContext()),
                                 size));
                     V           = C;
                 }
             }
             if (V->getType() != I64Ty) {
                 if (Constant *C = dyn_cast<Constant>(V))
                     V = ConstantExpr::getZExt(C, I64Ty);
                 else {
                     /*aragusa: Why not just insert the zero extend directly before it is used?*/
                     Instruction *I = getInsertPoint(V);
                     V              = new ZExtInst(V, I64Ty, "", I);
                 }
             }
             return BoundsMap[Base] = V;
         }
#else
    Value *getPointerBounds(Value *base)
    {
        Value *underlyingBase = GetUnderlyingObject(base, pMod->getDataLayout(), 0);
        //DEBUGERR << *ptr2 << "<END>\n";
        //

        DEBUGERR << "PROCESSEDOBJ" << *base << "<END>\n";
        DEBUGERR << "PROCESSEDOBJ" << *underlyingBase << "<END>\n";

        Type *returnType = Type::getInt64Ty(pMod->getContext());
        if (llvm::isa<AllocaInst>(underlyingBase) || llvm::isa<GlobalVariable>(underlyingBase)) {
            Type *pType = underlyingBase->getType();
            while (pType->isPointerTy()) {
                pType = llvm::cast<PointerType>(pType)->getElementType();
            }

            uint64_t size = pMod->getDataLayout().getTypeAllocSize(pType);
            DEBUGERR << *underlyingBase << "<END>\n";
            DEBUGERR << size << "<END>\n";
            return ConstantInt::get(returnType, size);
        }

        DEBUGERR << *base << "<END>\n";
        assert(0 && "Determine if we need to handle this case.");
        return nullptr;
    }
#endif

MDNode *getLocation(Instruction *I, bool &Approximate, unsigned MDDbgKind)
{
    Approximate = false;
    if (MDNode *Dbg = I->getMetadata(MDDbgKind))
        return Dbg;
    if (!MDDbgKind)
        return 0;
    Approximate = true;
    BasicBlock::iterator It(I);
    while (It != I->getParent()->begin()) {
        --It;
        if (MDNode *Dbg = It->getMetadata(MDDbgKind))
            return Dbg;
    }
    BasicBlock *BB = I->getParent();
    while ((BB = BB->getUniquePredecessor())) {
        It = BB->end();
        while (It != BB->begin()) {
            --It;
            if (MDNode *Dbg = It->getMetadata(MDDbgKind))
                return Dbg;
        }
    }
    return 0;
}

#if 1
bool insertCheck(const SCEV *Idx, const SCEV *Limit, Instruction *I,
                 bool strict)
{
    if (isa<SCEVCouldNotCompute>(Idx) && isa<SCEVCouldNotCompute>(Limit)) {
        errs() << "Could not compute the index and the limit!: \n"
               << *I << "\n";
        return false;
    }
    if (isa<SCEVCouldNotCompute>(Idx)) {
        errs() << "Could not compute index: \n"
               << *I << "\n";
        return false;
    }
    if (isa<SCEVCouldNotCompute>(Limit)) {
        errs() << "Could not compute limit: " << *I << "\n";
        return false;
    }
    BasicBlock *BB = I->getParent();
    BasicBlock::iterator It(I);
#if 0
             BasicBlock *newBB       = SplitBlock(BB, &*It, this);
#else
    BasicBlock *newBB = SplitBlock(BB, llvm::cast<Instruction>(It));
#endif
    PHINode *PN;
    unsigned MDDbgKind = I->getContext().getMDKindID("dbg");
    //verifyFunction(*BB->getParent());
    if (!AbrtBB) {
#if 0
                 std::vector<const Type *> args;
                 FunctionType *abrtTy = FunctionType::get(
                         Type::getVoidTy(BB->getContext()), args, false);
#else
        FunctionType *abrtTy = FunctionType::get(
            Type::getVoidTy(BB->getContext()), false);
#endif
#if 0
                 args.push_back(Type::getInt32Ty(BB->getContext()));
                 FunctionType *rterrTy = FunctionType::get(
                         Type::getInt32Ty(BB->getContext()), args, false);
#else
        //args.push_back(Type::getInt32Ty(BB->getContext()));
        FunctionType *rterrTy = FunctionType::get(
            Type::getInt32Ty(BB->getContext()),
            {Type::getInt32Ty(BB->getContext())}, false);
#endif
        Constant *func_abort =
            BB->getParent()->getParent()->getOrInsertFunction("abort", abrtTy);
        Constant *func_rterr =
            BB->getParent()->getParent()->getOrInsertFunction("bytecode_rt_error", rterrTy);
        AbrtBB = BasicBlock::Create(BB->getContext(), "rterr.trig", BB->getParent());
        PN     = PHINode::Create(Type::getInt32Ty(BB->getContext()), 0, "ClamBCRTChecks_abort",
                             AbrtBB);
        if (MDDbgKind) {
            CallInst *RtErrCall = CallInst::Create(func_rterr, PN, "", AbrtBB);
            RtErrCall->setCallingConv(CallingConv::C);
            RtErrCall->setTailCall(true);
            RtErrCall->setDoesNotThrow();
        }
        CallInst *AbrtC = CallInst::Create(func_abort, "", AbrtBB);
        AbrtC->setCallingConv(CallingConv::C);
        AbrtC->setTailCall(true);
        AbrtC->setDoesNotReturn();
        AbrtC->setDoesNotThrow();
        new UnreachableInst(BB->getContext(), AbrtBB);
        DT->addNewBlock(AbrtBB, BB);
    } else {
        PN = cast<PHINode>(AbrtBB->begin());
    }
    unsigned locationid = 0;
    bool Approximate;
    if (MDNode *Dbg = getLocation(I, Approximate, MDDbgKind)) {
#if 0
                 DILocation Loc(Dbg);
                 locationid   = Loc.getLineNumber() << 8;
                 unsigned col = Loc.getColumnNumber();
                 if (col > 254)
                     col = 254;
                 if (Approximate)
                     col = 255;
                 locationid |= col;
#else
        llvm::errs() << *Dbg << "<END>\n";
        assert(0 && "FIGURE OUT WHAT TO DO HERE");
#endif
    }
    PN->addIncoming(ConstantInt::get(Type::getInt32Ty(BB->getContext()),
                                     locationid),
                    BB);

    Instruction *terminatorInst = BB->getTerminator();
    DEBUGERR << *(BB->getParent()) << "<END>\n";
#if 0
             Value *IdxV        = expander->expandCodeFor(Idx, Limit->getType(), terminatorInst);
             Value *LimitV      = expander->expandCodeFor(Limit, Limit->getType(), terminatorInst);
#else
    Value *IdxV   = nullptr;
    Value *LimitV = nullptr;
    {
        DEBUGERR << *(terminatorInst->getParent()) << "<END>\n";

        SCEVExpander exp(getAnalysis<ScalarEvolutionWrapperPass>().getSE(), pMod->getDataLayout(), "ClamBCRTChecksExpander");
        IdxV = exp.expandCodeFor(Idx, Limit->getType(), terminatorInst);
        DEBUGERR << llvm::isa<SCEVCouldNotCompute>(Idx) << "<END>\n";
        DEBUGERR << llvm::isa<SCEVCastExpr>(Idx) << "<END>\n";
        DEBUGERR << llvm::isa<SCEVNAryExpr>(Idx) << "<END>\n";
        DEBUGERR << llvm::isa<SCEVUDivExpr>(Idx) << "<END>\n";
        DEBUGERR << llvm::isa<SCEVUnknown>(Idx) << "<END>\n";
        DEBUGERR << *(terminatorInst->getParent()) << "<END>\n";
        DEBUGERR << *Idx << "<END>\n";
        DEBUGERR << *IdxV << "<END>\n";

        LimitV = exp.expandCodeFor(Limit, Limit->getType(), terminatorInst);
    }
    DEBUGERR << "<END>\n";
#endif
    DEBUGERR << IdxV << "<END>\n";
    DEBUGERR << LimitV << "<END>\n";
    DEBUGERR << *IdxV << "<END>\n";
    DEBUGERR << *LimitV << "<END>\n";
    DEBUGERR << *(BB->getParent()) << "<END>\n";
    if (isa<Instruction>(IdxV) &&
        !DT->dominates(cast<Instruction>(IdxV)->getParent(), I->getParent())) {
        printLocation(I, true);
        errs() << "basic block with value [ " << IdxV->getName();
        errs() << " ] with limit [ " << LimitV->getName();
        errs() << " ] does not dominate" << *I << "\n";
        return false;
    }
    if (isa<Instruction>(LimitV) &&
        !DT->dominates(cast<Instruction>(LimitV)->getParent(), I->getParent())) {
        printLocation(I, true);
        errs() << "basic block with limit [" << LimitV->getName();
        errs() << " ] on value [ " << IdxV->getName();
        errs() << " ] does not dominate" << *I << "\n";
        return false;
    }
    Value *Cond = new ICmpInst(terminatorInst, strict ? ICmpInst::ICMP_ULT : ICmpInst::ICMP_ULE, IdxV, LimitV);
    BranchInst::Create(newBB, AbrtBB, Cond, terminatorInst);
    //terminatorInst->eraseFromParent();
    delInst.push_back(terminatorInst);
    // Update dominator info
    BasicBlock *DomBB =
        DT->findNearestCommonDominator(BB,
                                       DT->getNode(AbrtBB)->getIDom()->getBlock());
    DT->changeImmediateDominator(AbrtBB, DomBB);
    DEBUGERR << "<END>\n";
    return true;
}
#endif

static void MakeCompatible(ScalarEvolution *SE, const SCEV *&LHS, const SCEV *&RHS)
{
    if (const SCEVZeroExtendExpr *ZL = dyn_cast<SCEVZeroExtendExpr>(LHS))
        LHS = ZL->getOperand();
    if (const SCEVZeroExtendExpr *ZR = dyn_cast<SCEVZeroExtendExpr>(RHS))
        RHS = ZR->getOperand();

    Type *LTy = SE->getEffectiveSCEVType(LHS->getType());
    Type *RTy = SE->getEffectiveSCEVType(RHS->getType());
    if (SE->getTypeSizeInBits(RTy) > SE->getTypeSizeInBits(LTy)) {
        LTy = RTy;
    }
    LHS = SE->getNoopOrZeroExtend(LHS, LTy);
    RHS = SE->getNoopOrZeroExtend(RHS, LTy);
}
bool checkCond(Instruction *ICI, Instruction *I, bool equal)
{
    for (Value::use_iterator JU = ICI->use_begin(), JUE = ICI->use_end();
         JU != JUE; ++JU) {
        Value *val = llvm::cast<Value>(*JU);
        if (BranchInst *BI = dyn_cast<BranchInst>(val)) {
            if (!BI->isConditional())
                continue;
            BasicBlock *S = BI->getSuccessor(equal);
            if (DT->dominates(S, I->getParent()))
                return true;
        }
        if (BinaryOperator *BI = dyn_cast<BinaryOperator>(val)) {
            if (BI->getOpcode() == Instruction::Or &&
                checkCond(BI, I, equal))
                return true;
            if (BI->getOpcode() == Instruction::And &&
                checkCond(BI, I, !equal))
                return true;
        }
    }
    return false;
}

bool checkCondition(Instruction *CI, Instruction *I)
{
    for (Value::use_iterator U = CI->use_begin(), UE = CI->use_end();
         U != UE; ++U) {
        Value *val = llvm::cast<Value>(*U);
        if (CastInst *CSI = dyn_cast<CastInst>(val)) {
            if (checkCondition(CSI, I))
                return true;
        } else if (0) {
        } else if (ICmpInst *ICI = dyn_cast<ICmpInst>(val)) {
            if (ICI->getOperand(0) == CI &&
                isa<ConstantPointerNull>(ICI->getOperand(1))) {
                if (checkCond(ICI, I, ICI->getPredicate() == ICmpInst::ICMP_EQ))
                    return true;
            }
        }
    }
    return false;
}

Value *getPointerBase_PHINode(PHINode *phiNode)
{

    PHINode *ret = PHINode::Create(phiNode->getType(),
                                   phiNode->getNumIncomingValues(),
                                   ".verif.base",
                                   llvm::cast<Instruction>(phiNode));

    for (size_t i = 0; i < phiNode->getNumIncomingValues(); i++) {
        Value *pv   = phiNode->getIncomingValue(i);
        Value *newV = getPointerBase(pv);
        if (newV != pv) {

            if (newV->getType() != ret->getType()) {

                /*Returns the terminator of the first basic block.*/
                Instruction *insBefore = getTerminator(llvm::cast<Function>(phiNode->getParent()->getParent()));

                /*TODO: Should I have a GEPOperator here???, use ConstantExpr::getGetElementPtr*/
                newV = BitCastInst::CreateZExtOrBitCast(newV, ret->getType(), "bci", insBefore);
            }
            ret->addIncoming(newV, phiNode->getIncomingBlock(i));
        } else {
            DEBUGERR << *pv << "<END>\n";
            assert(0 && "Determine if we need to handle this case.");
        }
    }

    return ret;
}

Value *getPointerBase(Value *ptr)
{
    Value *ptr2 = GetUnderlyingObject(ptr, pMod->getDataLayout(), 0);

    DEBUGERR << "PROCESSEDOBJ" << *ptr << "<END>\n";
    DEBUGERR << "PROCESSEDOBJ" << *ptr2 << "<END>\n";

    if (ptr != ptr2) {
        return ptr2;
    }

    if (llvm::isa<PHINode>(ptr)) {
        return getPointerBase_PHINode(llvm::cast<PHINode>(ptr));
    }

    /* TODO: BEGIN: add select */

    DEBUGERR << *ptr << "<END>\n";
    assert(0 && "Determine if we need to handle this case.");
}

#if 1
bool validateAccess(Value *Pointer, Value *Length, Instruction *I)
{
    // get base
    Value *Base = getPointerBase(Pointer);

    Value *SBase = Base->stripPointerCasts();
    // get bounds
    Value *Bounds = getPointerBounds(SBase);
    if (!Bounds) {
        printLocation(I, true);
        errs() << "no bounds for base ";
        printValue(SBase);
        errs() << " while checking access to ";
        printValue(Pointer);
        errs() << " of length ";
        printValue(Length);
        errs() << "\n";

        return false;
    }

    // checks if a NULL pointer check (returned from function) is made:
    if (CallInst *CI = dyn_cast<CallInst>(Base->stripPointerCasts())) {
        // by checking if use is in the same block (i.e. no branching decisions)
        if (I->getParent() == CI->getParent()) {
            printLocation(I, true);
            errs() << "no null pointer check of pointer ";
            printValue(Base, false, true);
            errs() << " obtained by function call";
            errs() << " before use in same block\n";
            return false;
        }
        // by checking if a conditional contains the values in question somewhere
        // between their usage
        if (!checkCondition(CI, I)) {
            printLocation(I, true);
            errs() << "no null pointer check of pointer ";
            printValue(Base, false, true);
            errs() << " obtained by function call";
            errs() << " before use\n";
            return false;
        }
    }

    Type *I64Ty =
        Type::getInt64Ty(Base->getContext());
    const SCEV *SLen = SE->getSCEV(Length);
    DEBUGERR << *SLen << "<END>\n";
    DEBUGERR << *Length << "<END>\n";
    const SCEV *OffsetP = SE->getMinusSCEV(SE->getSCEV(Pointer),
                                           SE->getSCEV(Base));
    SLen                = SE->getNoopOrZeroExtend(SLen, I64Ty);
    DEBUGERR << *SLen << "<END>\n";
    OffsetP           = SE->getNoopOrZeroExtend(OffsetP, I64Ty);
    const SCEV *Limit = SE->getSCEV(Bounds);
    DEBUGERR << *Bounds << "<END>\n";
    DEBUGERR << *Limit << "<END>\n";
    Limit = SE->getNoopOrZeroExtend(Limit, I64Ty);
    DEBUGERR << *Limit << "<END>\n";

    //DEBUG(dbgs() << "Checking access to " << *Pointer << " of length " << *Length << "\n");
    DEBUGERR << "Checking access to " << *Pointer << " of length " << *Length << "<END>\n";
    if (OffsetP == Limit) {
        printLocation(I, true);
        errs() << "OffsetP == Limit: " << *OffsetP << "\n";
        errs() << " while checking access to ";
        printValue(Pointer);
        errs() << " of length ";
        printValue(Length);
        errs() << "\n";
        return false;
    }

    if (SLen == Limit) {
        if (const SCEVConstant *SC = dyn_cast<SCEVConstant>(OffsetP)) {
            if (SC->isZero())
                return true;
        }
        errs() << "SLen == Limit: " << *SLen << "\n";
        errs() << " while checking access to " << *Pointer << " of length "
               << *Length << " at " << *I << "\n";
        return false;
    }

    bool valid = true;
    SLen       = SE->getAddExpr(OffsetP, SLen);
    DEBUGERR << *SLen << "<END>\n";
    // check that offset + slen <= limit;
    // umax(offset+slen, limit) == limit is a sufficient (but not necessary
    // condition)
    const SCEV *MaxL = SE->getUMaxExpr(SLen, Limit);
    DEBUGERR << *MaxL << "<END>\n";
    if (MaxL != Limit) {
        //DEBUG(dbgs() << "MaxL != Limit: " << *MaxL << ", " << *Limit << "\n");
        DEBUGERR << "MaxL != Limit: " << *MaxL << ", " << *Limit << "<END>\n";
        valid &= insertCheck(SLen, Limit, I, false);
        DEBUGERR << "<END>\n";
    }

    //TODO: nullpointer check
    const SCEV *Max = SE->getUMaxExpr(OffsetP, Limit);
    if (Max == Limit)
        return valid;
    //DEBUG(dbgs() << "Max != Limit: " << *Max << ", " << *Limit << "\n");
    DEBUGERR << "Max != Limit: " << *Max << ", " << *Limit << "<END>\n";

    // check that offset < limit
    valid &= insertCheck(OffsetP, Limit, I, true);
    DEBUGERR << "<END>\n";
    return valid;
}
#else

    bool insertCheck(Value *basePtr, Value *limit, Value *ptr, Value *ptrLen, Instruction *I,
                     bool strict)
    {

        BasicBlock *BB = I->getParent();
        BasicBlock::iterator It(I);
        BasicBlock *newBB = SplitBlock(BB, llvm::cast<Instruction>(It), DT);

        unsigned MDDbgKind = I->getContext().getMDKindID("dbg");
        //verifyFunction(*BB->getParent());
        BasicBlock *abrtBB = getAbortBB(MDDbgKind, BB);
        PHINode *PN = cast<PHINode>(abrtBB->begin());

        unsigned locationid = 0;
        bool Approximate;
        if (MDNode *Dbg = getLocation(I, Approximate, MDDbgKind)) {
#if 0
                 DILocation Loc(Dbg);
                 locationid   = Loc.getLineNumber() << 8;
                 unsigned col = Loc.getColumnNumber();
                 if (col > 254)
                     col = 254;
                 if (Approximate)
                     col = 255;
                 locationid |= col;
#else
            llvm::errs() << *Dbg << "<END>\n";
            assert(0 && "FIGURE OUT WHAT TO DO HERE");
#endif
        }
        PN->addIncoming(ConstantInt::get(Type::getInt32Ty(BB->getContext()),
                                         locationid),
                        BB);

        Instruction *terminatorInst = BB->getTerminator();
        //             Value *IdxV        = expander->expandCodeFor(Idx, Limit->getType(), terminatorInst);
        //             Value *LimitV      = expander->expandCodeFor(Limit, Limit->getType(), terminatorInst);
        //DEBUGERR << *IdxV << "<END>\n";
        //DEBUGERR << *LimitV << "<END>\n";
#if 0
             if (isa<Instruction>(IdxV) &&
                     !DT->dominates(cast<Instruction>(IdxV)->getParent(), I->getParent())) {
                 printLocation(I, true);
                 errs() << "basic block with value [ " << IdxV->getName();
                 errs() << " ] with limit [ " << LimitV->getName();
                 errs() << " ] does not dominate" << *I << "\n";
                 return false;
             }
             if (isa<Instruction>(LimitV) &&
                     !DT->dominates(cast<Instruction>(LimitV)->getParent(), I->getParent())) {
                 printLocation(I, true);
                 errs() << "basic block with limit [" << LimitV->getName();
                 errs() << " ] on value [ " << IdxV->getName();
                 errs() << " ] does not dominate" << *I << "\n";
                 return false;
             }
#endif

        Type *i64Ty = Type::getInt64Ty(pMod->getContext());

        /*(Base Pointer + Size of Base Pointer)*/
        PtrToIntInst *basePtrToInt = new PtrToIntInst(basePtr, i64Ty, "bpti_rtchecks", terminatorInst);
        CastInst *limitSized = CastInst::CreateZExtOrBitCast(limit, i64Ty, "bci_rtchecks", terminatorInst);
        Instruction *add = BinaryOperator::Create(Instruction::Add, basePtrToInt, limitSized, "add_rtchecks", terminatorInst);

        /*(Pointer + Length)*/
        PtrToIntInst *ptrToInt = new PtrToIntInst(ptr, i64Ty, "pti_rtchecks", terminatorInst);
        CastInst *ptrLenSized = CastInst::CreateZExtOrBitCast(ptrLen, i64Ty, "bci_rtchecks", terminatorInst);
        Instruction *add2 = BinaryOperator::Create(Instruction::Add, ptrToInt, ptrLenSized, "add_rtchecks", terminatorInst);

        Value *Cond = new ICmpInst(terminatorInst, strict ? ICmpInst::ICMP_ULT : ICmpInst::ICMP_ULE, add2, add);
        BranchInst::Create(newBB, abrtBB, Cond, terminatorInst);
        //terminatorInst->eraseFromParent();
        delInst.push_back(terminatorInst);

        // Update dominator info
        BasicBlock *DomBB =
            DT->findNearestCommonDominator(BB,
                                           DT->getNode(abrtBB)->getIDom()->getBlock());
        DEBUGERR << *I << "<END>\n";
        DEBUGERR << DT->getNode(abrtBB) << "<END>\n";
        DEBUGERR << DT->getNode(abrtBB)->getIDom() << "<END>\n";
        DEBUGERR << DT->getNode(abrtBB)->getBlock() << "<END>\n";
        DEBUGERR << BB->getParent()->getName() << "<END>\n";
        DEBUGERR << (*BB) << "<END>\n";
        DEBUGERR << (*abrtBB) << "<END>\n";
        DT->changeImmediateDominator(abrtBB, DomBB);
        DEBUGERR << "<END>\n";
        return true;
    }

#if 0
         bool validateAccess(Value *ptr, Value *ptrLen, Instruction *inst)
         {
             /*here;*/

             //if (isa<PHINode>(ptr)) return true;
             //DEBUGERR << *inst << "<END>\n";
             //DEBUGERR << *ptr << "<END>\n";
             //return true;

             // get base
             DEBUGERR << "::" << ptr << *ptr << "<END>\n";
             Value *ptrBase = getPointerBase(ptr);

             Value *sPtrBase = ptrBase->stripPointerCasts();
             DEBUGERR << *(inst->getParent()->getParent()) << "<END>\n";
             DEBUGERR << *ptr << "<END>\n";
             DEBUGERR << *ptrBase << "<END>\n";

             // get bounds
             Value *ptrBounds = getPointerBounds(sPtrBase);
             DEBUGERR << *ptrBounds << "<END>\n";
             if (!ptrBounds) {
                 printLocation(inst, true);
                 errs() << "no bounds for base ";
                 printValue(sPtrBase);
                 errs() << " while checking access to ";
                 printValue(ptr);
                 errs() << " of length ";
                 printValue(ptrLen);
                 errs() << "\n";

                 return false;
             }

             // checks if a NULL pointer check (returned from function) is made:
             if (CallInst *callInst = dyn_cast<CallInst>(sPtrBase)) {
                 // by checking if use is in the same block (i.e. no branching decisions)
                 if (inst->getParent() == callInst->getParent()) {
                     printLocation(inst, true);
                     errs() << "no null pointer check of pointer ";
                     printValue(ptrBase, false, true);
                     errs() << " obtained by function call";
                     errs() << " before use in same block\n";
                     return false;
                 }
                 // by checking if a conditional contains the values in question somewhere
                 // between their usage
                 if (!checkCondition(callInst, inst)) {
                     printLocation(inst, true);
                     errs() << "no null pointer check of pointer ";
                     printValue(ptrBase, false, true);
                     errs() << " obtained by function call";
                     errs() << " before use\n";
                     return false;
                 }
             }

             /*Add a check for if (basePtr + ptrBounds) >= (ptr + ptrLen)*/
             if (not insertCheck( sPtrBase, ptrBounds, ptr, ptrLen, inst, true)){
                 return false;
             }

             return true;
         }
#endif
#endif

bool validateAccess(Value *Pointer, unsigned size, Instruction *I)
{
    return validateAccess(Pointer,
                          ConstantInt::get(Type::getInt32Ty(Pointer->getContext()),
                                           size),
                          I);
}
}; // namespace
char PtrVerifier::ID = 0;

} // namespace

llvm::Pass *createPtrVerifier()
{
    return new PtrVerifier();
}

static RegisterPass<PtrVerifier> X("clambc-rtchecks", "ClamBCRTChecks Pass",
                                   false /* Only looks at CFG */,
                                   false /* Analysis Pass */);
