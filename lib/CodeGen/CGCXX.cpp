//===--- CGDecl.cpp - Emit LLVM Code for declarations ---------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This contains code dealing with C++ code generation.
//
//===----------------------------------------------------------------------===//

// We might split this into multiple files if it gets too unwieldy

#include "CodeGenFunction.h"
#include "CodeGenModule.h"
#include "Mangle.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/RecordLayout.h"
#include "clang/AST/Decl.h"
#include "clang/AST/DeclCXX.h"
#include "clang/AST/DeclObjC.h"
#include "clang/AST/StmtCXX.h"
#include "clang/CodeGen/CodeGenOptions.h"
#include "llvm/ADT/StringExtras.h"
using namespace clang;
using namespace CodeGen;

/// Try to emit a definition as a global alias for another definition.
bool CodeGenModule::TryEmitDefinitionAsAlias(GlobalDecl AliasDecl,
                                             GlobalDecl TargetDecl) {
  if (!getCodeGenOpts().CXXCtorDtorAliases)
    return true;

  // Find the referrent.
  llvm::GlobalValue *Ref = cast<llvm::GlobalValue>(GetAddrOfGlobal(TargetDecl));

  // Look for an existing entry.
  const char *MangledName = getMangledName(AliasDecl);
  llvm::GlobalValue *&Entry = GlobalDeclMap[MangledName];
  if (Entry) {
    assert(Entry->isDeclaration() && "definition already exists for alias");
    assert(Entry->getType() == Ref->getType() &&
           "declaration exists with different type");
  }

  // The alias will use the linkage of the referrent.  If we can't
  // support aliases with that linkage, fail.
  llvm::GlobalValue::LinkageTypes Linkage
    = getFunctionLinkage(cast<FunctionDecl>(AliasDecl.getDecl()));

  switch (Linkage) {
  // We can definitely emit aliases to definitions with external linkage.
  case llvm::GlobalValue::ExternalLinkage:
  case llvm::GlobalValue::ExternalWeakLinkage:
    break;

  // Same with local linkage.
  case llvm::GlobalValue::InternalLinkage:
  case llvm::GlobalValue::PrivateLinkage:
  case llvm::GlobalValue::LinkerPrivateLinkage:
    break;

  // We should try to support linkonce linkages.
  case llvm::GlobalValue::LinkOnceAnyLinkage:
  case llvm::GlobalValue::LinkOnceODRLinkage:
    return true;

  // Other linkages will probably never be supported.
  default:
    return true;
  }

  // Create the alias with no name.
  llvm::GlobalAlias *Alias = 
    new llvm::GlobalAlias(Ref->getType(), Linkage, "", Ref, &getModule());

  // Switch any previous uses to the alias and continue.
  if (Entry) {
    Entry->replaceAllUsesWith(Alias);
    Entry->eraseFromParent();
  }
  Entry = Alias;

  // Finally, set up the alias with its proper name and attributes.
  Alias->setName(MangledName);
  SetCommonAttributes(AliasDecl.getDecl(), Alias);

  return false;
}


void CodeGenModule::EmitCXXConstructors(const CXXConstructorDecl *D) {
  // The constructor used for constructing this as a complete class;
  // constucts the virtual bases, then calls the base constructor.
  EmitGlobal(GlobalDecl(D, Ctor_Complete));

  // The constructor used for constructing this as a base class;
  // ignores virtual bases.
  EmitGlobal(GlobalDecl(D, Ctor_Base));
}

void CodeGenModule::EmitCXXConstructor(const CXXConstructorDecl *D,
                                       CXXCtorType Type) {
  // The complete constructor is equivalent to the base constructor
  // for classes with no virtual bases.  Try to emit it as an alias.
  if (Type == Ctor_Complete &&
      !D->getParent()->getNumVBases() &&
      !TryEmitDefinitionAsAlias(GlobalDecl(D, Ctor_Complete),
                                GlobalDecl(D, Ctor_Base)))
    return;

  llvm::Function *Fn = cast<llvm::Function>(GetAddrOfCXXConstructor(D, Type));

  CodeGenFunction(*this).GenerateCode(GlobalDecl(D, Type), Fn);

  SetFunctionDefinitionAttributes(D, Fn);
  SetLLVMFunctionAttributesForDefinition(D, Fn);
}

llvm::GlobalValue *
CodeGenModule::GetAddrOfCXXConstructor(const CXXConstructorDecl *D,
                                       CXXCtorType Type) {
  const char *Name = getMangledCXXCtorName(D, Type);
  if (llvm::GlobalValue *V = GlobalDeclMap[Name])
    return V;

  const FunctionProtoType *FPT = D->getType()->getAs<FunctionProtoType>();
  const llvm::FunctionType *FTy =
    getTypes().GetFunctionType(getTypes().getFunctionInfo(D, Type), 
                               FPT->isVariadic());
  return cast<llvm::Function>(
                      GetOrCreateLLVMFunction(Name, FTy, GlobalDecl(D, Type)));
}

const char *CodeGenModule::getMangledCXXCtorName(const CXXConstructorDecl *D,
                                                 CXXCtorType Type) {
  llvm::SmallString<256> Name;
  getMangleContext().mangleCXXCtor(D, Type, Name);

  Name += '\0';
  return UniqueMangledName(Name.begin(), Name.end());
}

void CodeGenModule::EmitCXXDestructors(const CXXDestructorDecl *D) {
  // The destructor in a virtual table is always a 'deleting'
  // destructor, which calls the complete destructor and then uses the
  // appropriate operator delete.
  if (D->isVirtual())
    EmitGlobal(GlobalDecl(D, Dtor_Deleting));

  // The destructor used for destructing this as a most-derived class;
  // call the base destructor and then destructs any virtual bases.
  EmitGlobal(GlobalDecl(D, Dtor_Complete));

  // The destructor used for destructing this as a base class; ignores
  // virtual bases.
  EmitGlobal(GlobalDecl(D, Dtor_Base));
}

void CodeGenModule::EmitCXXDestructor(const CXXDestructorDecl *D,
                                      CXXDtorType Type) {
  // The complete destructor is equivalent to the base destructor for
  // classes with no virtual bases, so try to emit it as an alias.
  if (Type == Dtor_Complete &&
      !D->getParent()->getNumVBases() &&
      !TryEmitDefinitionAsAlias(GlobalDecl(D, Dtor_Complete),
                                GlobalDecl(D, Dtor_Base)))
    return;

  llvm::Function *Fn = cast<llvm::Function>(GetAddrOfCXXDestructor(D, Type));

  CodeGenFunction(*this).GenerateCode(GlobalDecl(D, Type), Fn);

  SetFunctionDefinitionAttributes(D, Fn);
  SetLLVMFunctionAttributesForDefinition(D, Fn);
}

llvm::GlobalValue *
CodeGenModule::GetAddrOfCXXDestructor(const CXXDestructorDecl *D,
                                      CXXDtorType Type) {
  const char *Name = getMangledCXXDtorName(D, Type);
  if (llvm::GlobalValue *V = GlobalDeclMap[Name])
    return V;

  const llvm::FunctionType *FTy =
    getTypes().GetFunctionType(getTypes().getFunctionInfo(D, Type), false);

  return cast<llvm::Function>(
                      GetOrCreateLLVMFunction(Name, FTy, GlobalDecl(D, Type)));
}

const char *CodeGenModule::getMangledCXXDtorName(const CXXDestructorDecl *D,
                                                 CXXDtorType Type) {
  llvm::SmallString<256> Name;
  getMangleContext().mangleCXXDtor(D, Type, Name);

  Name += '\0';
  return UniqueMangledName(Name.begin(), Name.end());
}

llvm::Constant *
CodeGenFunction::GenerateThunk(llvm::Function *Fn, GlobalDecl GD,
                               bool Extern, 
                               const ThunkAdjustment &ThisAdjustment) {
  return GenerateCovariantThunk(Fn, GD, Extern,
                                CovariantThunkAdjustment(ThisAdjustment,
                                                         ThunkAdjustment()));
}

llvm::Value *
CodeGenFunction::DynamicTypeAdjust(llvm::Value *V, 
                                   const ThunkAdjustment &Adjustment) {
  const llvm::Type *Int8PtrTy = llvm::Type::getInt8PtrTy(VMContext);

  const llvm::Type *OrigTy = V->getType();
  if (Adjustment.NonVirtual) {
    // Do the non-virtual adjustment
    V = Builder.CreateBitCast(V, Int8PtrTy);
    V = Builder.CreateConstInBoundsGEP1_64(V, Adjustment.NonVirtual);
    V = Builder.CreateBitCast(V, OrigTy);
  }
  
  if (!Adjustment.Virtual)
    return V;

  assert(Adjustment.Virtual % (LLVMPointerWidth / 8) == 0 && 
         "vtable entry unaligned");

  // Do the virtual this adjustment
  const llvm::Type *PtrDiffTy = ConvertType(getContext().getPointerDiffType());
  const llvm::Type *PtrDiffPtrTy = PtrDiffTy->getPointerTo();
  
  llvm::Value *ThisVal = Builder.CreateBitCast(V, Int8PtrTy);
  V = Builder.CreateBitCast(V, PtrDiffPtrTy->getPointerTo());
  V = Builder.CreateLoad(V, "vtable");
  
  llvm::Value *VTablePtr = V;
  uint64_t VirtualAdjustment = Adjustment.Virtual / (LLVMPointerWidth / 8);
  V = Builder.CreateConstInBoundsGEP1_64(VTablePtr, VirtualAdjustment);
  V = Builder.CreateLoad(V);
  V = Builder.CreateGEP(ThisVal, V);
  
  return Builder.CreateBitCast(V, OrigTy);
}

llvm::Constant *
CodeGenFunction::GenerateCovariantThunk(llvm::Function *Fn,
                                   GlobalDecl GD, bool Extern,
                                   const CovariantThunkAdjustment &Adjustment) {
  const CXXMethodDecl *MD = cast<CXXMethodDecl>(GD.getDecl());
  const FunctionProtoType *FPT = MD->getType()->getAs<FunctionProtoType>();
  QualType ResultType = FPT->getResultType();

  FunctionArgList Args;
  ImplicitParamDecl *ThisDecl =
    ImplicitParamDecl::Create(getContext(), 0, SourceLocation(), 0,
                              MD->getThisType(getContext()));
  Args.push_back(std::make_pair(ThisDecl, ThisDecl->getType()));
  for (FunctionDecl::param_const_iterator i = MD->param_begin(),
         e = MD->param_end();
       i != e; ++i) {
    ParmVarDecl *D = *i;
    Args.push_back(std::make_pair(D, D->getType()));
  }
  IdentifierInfo *II
    = &CGM.getContext().Idents.get("__thunk_named_foo_");
  FunctionDecl *FD = FunctionDecl::Create(getContext(),
                                          getContext().getTranslationUnitDecl(),
                                          SourceLocation(), II, ResultType, 0,
                                          Extern
                                            ? FunctionDecl::Extern
                                            : FunctionDecl::Static,
                                          false, true);
  StartFunction(FD, ResultType, Fn, Args, SourceLocation());

  // generate body
  const llvm::Type *Ty =
    CGM.getTypes().GetFunctionType(CGM.getTypes().getFunctionInfo(MD),
                                   FPT->isVariadic());
  llvm::Value *Callee = CGM.GetAddrOfFunction(GD, Ty);

  CallArgList CallArgs;

  bool ShouldAdjustReturnPointer = true;
  QualType ArgType = MD->getThisType(getContext());
  llvm::Value *Arg = Builder.CreateLoad(LocalDeclMap[ThisDecl], "this");
  if (!Adjustment.ThisAdjustment.isEmpty()) {
    // Do the this adjustment.
    const llvm::Type *OrigTy = Callee->getType();
    Arg = DynamicTypeAdjust(Arg, Adjustment.ThisAdjustment);
    
    if (!Adjustment.ReturnAdjustment.isEmpty()) {
      const CovariantThunkAdjustment &ReturnAdjustment = 
        CovariantThunkAdjustment(ThunkAdjustment(),
                                 Adjustment.ReturnAdjustment);
      
      Callee = CGM.BuildCovariantThunk(GD, Extern, ReturnAdjustment);
      
      Callee = Builder.CreateBitCast(Callee, OrigTy);
      ShouldAdjustReturnPointer = false;
    }
  }    

  CallArgs.push_back(std::make_pair(RValue::get(Arg), ArgType));

  for (FunctionDecl::param_const_iterator i = MD->param_begin(),
         e = MD->param_end();
       i != e; ++i) {
    ParmVarDecl *D = *i;
    QualType ArgType = D->getType();

    // llvm::Value *Arg = CGF.GetAddrOfLocalVar(Dst);
    Expr *Arg = new (getContext()) DeclRefExpr(D, ArgType.getNonReferenceType(),
                                               SourceLocation());
    CallArgs.push_back(std::make_pair(EmitCallArg(Arg, ArgType), ArgType));
  }

  RValue RV = EmitCall(CGM.getTypes().getFunctionInfo(ResultType, CallArgs,
                                                      FPT->getCallConv(),
                                                      FPT->getNoReturnAttr()),
                       Callee, ReturnValueSlot(), CallArgs, MD);
  if (ShouldAdjustReturnPointer && !Adjustment.ReturnAdjustment.isEmpty()) {
    bool CanBeZero = !(ResultType->isReferenceType()
    // FIXME: attr nonnull can't be zero either
                       /* || ResultType->hasAttr<NonNullAttr>() */ );
    // Do the return result adjustment.
    if (CanBeZero) {
      llvm::BasicBlock *NonZeroBlock = createBasicBlock();
      llvm::BasicBlock *ZeroBlock = createBasicBlock();
      llvm::BasicBlock *ContBlock = createBasicBlock();

      const llvm::Type *Ty = RV.getScalarVal()->getType();
      llvm::Value *Zero = llvm::Constant::getNullValue(Ty);
      Builder.CreateCondBr(Builder.CreateICmpNE(RV.getScalarVal(), Zero),
                           NonZeroBlock, ZeroBlock);
      EmitBlock(NonZeroBlock);
      llvm::Value *NZ = 
        DynamicTypeAdjust(RV.getScalarVal(), Adjustment.ReturnAdjustment);
      EmitBranch(ContBlock);
      EmitBlock(ZeroBlock);
      llvm::Value *Z = RV.getScalarVal();
      EmitBlock(ContBlock);
      llvm::PHINode *RVOrZero = Builder.CreatePHI(Ty);
      RVOrZero->reserveOperandSpace(2);
      RVOrZero->addIncoming(NZ, NonZeroBlock);
      RVOrZero->addIncoming(Z, ZeroBlock);
      RV = RValue::get(RVOrZero);
    } else
      RV = RValue::get(DynamicTypeAdjust(RV.getScalarVal(), 
                                         Adjustment.ReturnAdjustment));
  }

  if (!ResultType->isVoidType())
    EmitReturnOfRValue(RV, ResultType);

  FinishFunction();
  return Fn;
}

llvm::Constant *
CodeGenModule::GetAddrOfThunk(GlobalDecl GD,
                              const ThunkAdjustment &ThisAdjustment) {
  const CXXMethodDecl *MD = cast<CXXMethodDecl>(GD.getDecl());

  // Compute mangled name
  llvm::SmallString<256> OutName;
  if (const CXXDestructorDecl* DD = dyn_cast<CXXDestructorDecl>(MD))
    getMangleContext().mangleCXXDtorThunk(DD, GD.getDtorType(), ThisAdjustment,
                                          OutName);
  else
    getMangleContext().mangleThunk(MD, ThisAdjustment, OutName);
  OutName += '\0';
  const char* Name = UniqueMangledName(OutName.begin(), OutName.end());

  // Get function for mangled name
  const llvm::Type *Ty = getTypes().GetFunctionTypeForVtable(MD);
  return GetOrCreateLLVMFunction(Name, Ty, GlobalDecl());
}

llvm::Constant *
CodeGenModule::GetAddrOfCovariantThunk(GlobalDecl GD,
                                   const CovariantThunkAdjustment &Adjustment) {
  const CXXMethodDecl *MD = cast<CXXMethodDecl>(GD.getDecl());

  // Compute mangled name
  llvm::SmallString<256> OutName;
  getMangleContext().mangleCovariantThunk(MD, Adjustment, OutName);
  OutName += '\0';
  const char* Name = UniqueMangledName(OutName.begin(), OutName.end());

  // Get function for mangled name
  const llvm::Type *Ty = getTypes().GetFunctionTypeForVtable(MD);
  return GetOrCreateLLVMFunction(Name, Ty, GlobalDecl());
}

void CodeGenModule::BuildThunksForVirtual(GlobalDecl GD) {
  CGVtableInfo::AdjustmentVectorTy *AdjPtr = getVtableInfo().getAdjustments(GD);
  if (!AdjPtr)
    return;
  CGVtableInfo::AdjustmentVectorTy &Adj = *AdjPtr;
  const CXXMethodDecl *MD = cast<CXXMethodDecl>(GD.getDecl());
  for (unsigned i = 0; i < Adj.size(); i++) {
    GlobalDecl OGD = Adj[i].first;
    const CXXMethodDecl *OMD = cast<CXXMethodDecl>(OGD.getDecl());
    QualType nc_oret = OMD->getType()->getAs<FunctionType>()->getResultType();
    CanQualType oret = getContext().getCanonicalType(nc_oret);
    QualType nc_ret = MD->getType()->getAs<FunctionType>()->getResultType();
    CanQualType ret = getContext().getCanonicalType(nc_ret);
    ThunkAdjustment ReturnAdjustment;
    if (oret != ret) {
      QualType qD = nc_ret->getPointeeType();
      QualType qB = nc_oret->getPointeeType();
      CXXRecordDecl *D = cast<CXXRecordDecl>(qD->getAs<RecordType>()->getDecl());
      CXXRecordDecl *B = cast<CXXRecordDecl>(qB->getAs<RecordType>()->getDecl());
      ReturnAdjustment = ComputeThunkAdjustment(D, B);
    }
    ThunkAdjustment ThisAdjustment = Adj[i].second;
    bool Extern = !cast<CXXRecordDecl>(OMD->getDeclContext())->isInAnonymousNamespace();
    if (!ReturnAdjustment.isEmpty() || !ThisAdjustment.isEmpty()) {
      CovariantThunkAdjustment CoAdj(ThisAdjustment, ReturnAdjustment);
      llvm::Constant *FnConst;
      if (!ReturnAdjustment.isEmpty())
        FnConst = GetAddrOfCovariantThunk(GD, CoAdj);
      else
        FnConst = GetAddrOfThunk(GD, ThisAdjustment);
      if (!isa<llvm::Function>(FnConst)) {
        llvm::Constant *SubExpr =
            cast<llvm::ConstantExpr>(FnConst)->getOperand(0);
        llvm::Function *OldFn = cast<llvm::Function>(SubExpr);
        std::string Name = OldFn->getNameStr();
        GlobalDeclMap.erase(UniqueMangledName(Name.data(),
                                              Name.data() + Name.size() + 1));
        llvm::Constant *NewFnConst;
        if (!ReturnAdjustment.isEmpty())
          NewFnConst = GetAddrOfCovariantThunk(GD, CoAdj);
        else
          NewFnConst = GetAddrOfThunk(GD, ThisAdjustment);
        llvm::Function *NewFn = cast<llvm::Function>(NewFnConst);
        NewFn->takeName(OldFn);
        llvm::Constant *NewPtrForOldDecl =
            llvm::ConstantExpr::getBitCast(NewFn, OldFn->getType());
        OldFn->replaceAllUsesWith(NewPtrForOldDecl);
        OldFn->eraseFromParent();
        FnConst = NewFn;
      }
      llvm::Function *Fn = cast<llvm::Function>(FnConst);
      if (Fn->isDeclaration()) {
        llvm::GlobalVariable::LinkageTypes linktype;
        linktype = llvm::GlobalValue::WeakAnyLinkage;
        if (!Extern)
          linktype = llvm::GlobalValue::InternalLinkage;
        Fn->setLinkage(linktype);
        if (!Features.Exceptions && !Features.ObjCNonFragileABI)
          Fn->addFnAttr(llvm::Attribute::NoUnwind);
        Fn->setAlignment(2);
        CodeGenFunction(*this).GenerateCovariantThunk(Fn, GD, Extern, CoAdj);
      }
    }
  }
}

llvm::Constant *
CodeGenModule::BuildThunk(GlobalDecl GD, bool Extern,
                          const ThunkAdjustment &ThisAdjustment) {
  const CXXMethodDecl *MD = cast<CXXMethodDecl>(GD.getDecl());
  llvm::SmallString<256> OutName;
  if (const CXXDestructorDecl *D = dyn_cast<CXXDestructorDecl>(MD)) {
    getMangleContext().mangleCXXDtorThunk(D, GD.getDtorType(), ThisAdjustment,
                                          OutName);
  } else 
    getMangleContext().mangleThunk(MD, ThisAdjustment, OutName);
  
  llvm::GlobalVariable::LinkageTypes linktype;
  linktype = llvm::GlobalValue::WeakAnyLinkage;
  if (!Extern)
    linktype = llvm::GlobalValue::InternalLinkage;
  llvm::Type *Ptr8Ty=llvm::PointerType::get(llvm::Type::getInt8Ty(VMContext),0);
  const FunctionProtoType *FPT = MD->getType()->getAs<FunctionProtoType>();
  const llvm::FunctionType *FTy =
    getTypes().GetFunctionType(getTypes().getFunctionInfo(MD),
                               FPT->isVariadic());

  llvm::Function *Fn = llvm::Function::Create(FTy, linktype, OutName.str(),
                                              &getModule());
  CodeGenFunction(*this).GenerateThunk(Fn, GD, Extern, ThisAdjustment);
  llvm::Constant *m = llvm::ConstantExpr::getBitCast(Fn, Ptr8Ty);
  return m;
}

llvm::Constant *
CodeGenModule::BuildCovariantThunk(const GlobalDecl &GD, bool Extern,
                                   const CovariantThunkAdjustment &Adjustment) {
  const CXXMethodDecl *MD = cast<CXXMethodDecl>(GD.getDecl());
  llvm::SmallString<256> OutName;
  getMangleContext().mangleCovariantThunk(MD, Adjustment, OutName);
  llvm::GlobalVariable::LinkageTypes linktype;
  linktype = llvm::GlobalValue::WeakAnyLinkage;
  if (!Extern)
    linktype = llvm::GlobalValue::InternalLinkage;
  llvm::Type *Ptr8Ty=llvm::PointerType::get(llvm::Type::getInt8Ty(VMContext),0);
  const FunctionProtoType *FPT = MD->getType()->getAs<FunctionProtoType>();
  const llvm::FunctionType *FTy =
    getTypes().GetFunctionType(getTypes().getFunctionInfo(MD),
                               FPT->isVariadic());

  llvm::Function *Fn = llvm::Function::Create(FTy, linktype, OutName.str(),
                                              &getModule());
  CodeGenFunction(*this).GenerateCovariantThunk(Fn, MD, Extern, Adjustment);
  llvm::Constant *m = llvm::ConstantExpr::getBitCast(Fn, Ptr8Ty);
  return m;
}

static llvm::Value *BuildVirtualCall(CodeGenFunction &CGF, uint64_t VtableIndex, 
                                     llvm::Value *This, const llvm::Type *Ty) {
  Ty = Ty->getPointerTo()->getPointerTo()->getPointerTo();
  
  llvm::Value *Vtable = CGF.Builder.CreateBitCast(This, Ty);
  Vtable = CGF.Builder.CreateLoad(Vtable);
  
  llvm::Value *VFuncPtr = 
    CGF.Builder.CreateConstInBoundsGEP1_64(Vtable, VtableIndex, "vfn");
  return CGF.Builder.CreateLoad(VFuncPtr);
}

llvm::Value *
CodeGenFunction::BuildVirtualCall(const CXXMethodDecl *MD, llvm::Value *This,
                                  const llvm::Type *Ty) {
  MD = MD->getCanonicalDecl();
  uint64_t VtableIndex = CGM.getVtableInfo().getMethodVtableIndex(MD);
  
  return ::BuildVirtualCall(*this, VtableIndex, This, Ty);
}

llvm::Value *
CodeGenFunction::BuildVirtualCall(const CXXDestructorDecl *DD, CXXDtorType Type, 
                                  llvm::Value *&This, const llvm::Type *Ty) {
  DD = cast<CXXDestructorDecl>(DD->getCanonicalDecl());
  uint64_t VtableIndex = 
    CGM.getVtableInfo().getMethodVtableIndex(GlobalDecl(DD, Type));

  return ::BuildVirtualCall(*this, VtableIndex, This, Ty);
}
