//===-- LLParser.cpp - Parser Class ---------------------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
//  This file defines the parser class for .ll files.
//
//===----------------------------------------------------------------------===//

#include "LLParser.h"
#include "llvm/AutoUpgrade.h"
#include "llvm/CallingConv.h"
#include "llvm/Constants.h"
#include "llvm/DerivedTypes.h"
#include "llvm/InlineAsm.h"
#include "llvm/Instructions.h"
#include "llvm/Module.h"
#include "llvm/Operator.h"
#include "llvm/ValueSymbolTable.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/raw_ostream.h"
using namespace llvm;

/// Run: module ::= toplevelentity*
bool LLParser::Run() {
  // Prime the lexer.
  Lex.Lex();

  return ParseTopLevelEntities() ||
         ValidateEndOfModule();
}

/// ValidateEndOfModule - Do final validity and sanity checks at the end of the
/// module.
bool LLParser::ValidateEndOfModule() {
  // Update auto-upgraded malloc calls to "malloc".
  // FIXME: Remove in LLVM 3.0.
  if (MallocF) {
    MallocF->setName("malloc");
    // If setName() does not set the name to "malloc", then there is already a 
    // declaration of "malloc".  In that case, iterate over all calls to MallocF
    // and get them to call the declared "malloc" instead.
    if (MallocF->getName() != "malloc") {
      Constant *RealMallocF = M->getFunction("malloc");
      if (RealMallocF->getType() != MallocF->getType())
        RealMallocF = ConstantExpr::getBitCast(RealMallocF, MallocF->getType());
      MallocF->replaceAllUsesWith(RealMallocF);
      MallocF->eraseFromParent();
      MallocF = NULL;
    }
  }
  
  
  // If there are entries in ForwardRefBlockAddresses at this point, they are
  // references after the function was defined.  Resolve those now.
  while (!ForwardRefBlockAddresses.empty()) {
    // Okay, we are referencing an already-parsed function, resolve them now.
    Function *TheFn = 0;
    const ValID &Fn = ForwardRefBlockAddresses.begin()->first;
    if (Fn.Kind == ValID::t_GlobalName)
      TheFn = M->getFunction(Fn.StrVal);
    else if (Fn.UIntVal < NumberedVals.size())
      TheFn = dyn_cast<Function>(NumberedVals[Fn.UIntVal]);
    
    if (TheFn == 0)
      return Error(Fn.Loc, "unknown function referenced by blockaddress");
    
    // Resolve all these references.
    if (ResolveForwardRefBlockAddresses(TheFn, 
                                      ForwardRefBlockAddresses.begin()->second,
                                        0))
      return true;
    
    ForwardRefBlockAddresses.erase(ForwardRefBlockAddresses.begin());
  }
  
  
  if (!ForwardRefTypes.empty())
    return Error(ForwardRefTypes.begin()->second.second,
                 "use of undefined type named '" +
                 ForwardRefTypes.begin()->first + "'");
  if (!ForwardRefTypeIDs.empty())
    return Error(ForwardRefTypeIDs.begin()->second.second,
                 "use of undefined type '%" +
                 utostr(ForwardRefTypeIDs.begin()->first) + "'");

  if (!ForwardRefVals.empty())
    return Error(ForwardRefVals.begin()->second.second,
                 "use of undefined value '@" + ForwardRefVals.begin()->first +
                 "'");

  if (!ForwardRefValIDs.empty())
    return Error(ForwardRefValIDs.begin()->second.second,
                 "use of undefined value '@" +
                 utostr(ForwardRefValIDs.begin()->first) + "'");

  if (!ForwardRefMDNodes.empty())
    return Error(ForwardRefMDNodes.begin()->second.second,
                 "use of undefined metadata '!" +
                 utostr(ForwardRefMDNodes.begin()->first) + "'");


  // Look for intrinsic functions and CallInst that need to be upgraded
  for (Module::iterator FI = M->begin(), FE = M->end(); FI != FE; )
    UpgradeCallsToIntrinsic(FI++); // must be post-increment, as we remove

  // Check debug info intrinsics.
  CheckDebugInfoIntrinsics(M);
  return false;
}

bool LLParser::ResolveForwardRefBlockAddresses(Function *TheFn, 
                             std::vector<std::pair<ValID, GlobalValue*> > &Refs,
                                               PerFunctionState *PFS) {
  // Loop over all the references, resolving them.
  for (unsigned i = 0, e = Refs.size(); i != e; ++i) {
    BasicBlock *Res;
    if (PFS) {
      if (Refs[i].first.Kind == ValID::t_LocalName)
        Res = PFS->GetBB(Refs[i].first.StrVal, Refs[i].first.Loc);
      else
        Res = PFS->GetBB(Refs[i].first.UIntVal, Refs[i].first.Loc);
    } else if (Refs[i].first.Kind == ValID::t_LocalID) {
      return Error(Refs[i].first.Loc,
       "cannot take address of numeric label after the function is defined");
    } else {
      Res = dyn_cast_or_null<BasicBlock>(
                     TheFn->getValueSymbolTable().lookup(Refs[i].first.StrVal));
    }
    
    if (Res == 0)
      return Error(Refs[i].first.Loc,
                   "referenced value is not a basic block");
    
    // Get the BlockAddress for this and update references to use it.
    BlockAddress *BA = BlockAddress::get(TheFn, Res);
    Refs[i].second->replaceAllUsesWith(BA);
    Refs[i].second->eraseFromParent();
  }
  return false;
}


//===----------------------------------------------------------------------===//
// Top-Level Entities
//===----------------------------------------------------------------------===//

bool LLParser::ParseTopLevelEntities() {
  while (1) {
    switch (Lex.getKind()) {
    default:         return TokError("expected top-level entity");
    case lltok::Eof: return false;
    //case lltok::kw_define:
    case lltok::kw_declare: if (ParseDeclare()) return true; break;
    case lltok::kw_define:  if (ParseDefine()) return true; break;
    case lltok::kw_module:  if (ParseModuleAsm()) return true; break;
    case lltok::kw_target:  if (ParseTargetDefinition()) return true; break;
    case lltok::kw_deplibs: if (ParseDepLibs()) return true; break;
    case lltok::kw_type:    if (ParseUnnamedType()) return true; break;
    case lltok::LocalVarID: if (ParseUnnamedType()) return true; break;
    case lltok::StringConstant: // FIXME: REMOVE IN LLVM 3.0
    case lltok::LocalVar:   if (ParseNamedType()) return true; break;
    case lltok::GlobalID:   if (ParseUnnamedGlobal()) return true; break;
    case lltok::GlobalVar:  if (ParseNamedGlobal()) return true; break;
    case lltok::exclaim:    if (ParseStandaloneMetadata()) return true; break;
    case lltok::MetadataVar: if (ParseNamedMetadata()) return true; break;

    // The Global variable production with no name can have many different
    // optional leading prefixes, the production is:
    // GlobalVar ::= OptionalLinkage OptionalVisibility OptionalThreadLocal
    //               OptionalAddrSpace ('constant'|'global') ...
    case lltok::kw_private :       // OptionalLinkage
    case lltok::kw_linker_private: // OptionalLinkage
    case lltok::kw_internal:       // OptionalLinkage
    case lltok::kw_weak:           // OptionalLinkage
    case lltok::kw_weak_odr:       // OptionalLinkage
    case lltok::kw_linkonce:       // OptionalLinkage
    case lltok::kw_linkonce_odr:   // OptionalLinkage
    case lltok::kw_appending:      // OptionalLinkage
    case lltok::kw_dllexport:      // OptionalLinkage
    case lltok::kw_common:         // OptionalLinkage
    case lltok::kw_dllimport:      // OptionalLinkage
    case lltok::kw_extern_weak:    // OptionalLinkage
    case lltok::kw_external: {     // OptionalLinkage
      unsigned Linkage, Visibility;
      if (ParseOptionalLinkage(Linkage) ||
          ParseOptionalVisibility(Visibility) ||
          ParseGlobal("", SMLoc(), Linkage, true, Visibility))
        return true;
      break;
    }
    case lltok::kw_default:       // OptionalVisibility
    case lltok::kw_hidden:        // OptionalVisibility
    case lltok::kw_protected: {   // OptionalVisibility
      unsigned Visibility;
      if (ParseOptionalVisibility(Visibility) ||
          ParseGlobal("", SMLoc(), 0, false, Visibility))
        return true;
      break;
    }

    case lltok::kw_thread_local:  // OptionalThreadLocal
    case lltok::kw_addrspace:     // OptionalAddrSpace
    case lltok::kw_constant:      // GlobalType
    case lltok::kw_global:        // GlobalType
      if (ParseGlobal("", SMLoc(), 0, false, 0)) return true;
      break;
    }
  }
}


/// toplevelentity
///   ::= 'module' 'asm' STRINGCONSTANT
bool LLParser::ParseModuleAsm() {
  assert(Lex.getKind() == lltok::kw_module);
  Lex.Lex();

  std::string AsmStr;
  if (ParseToken(lltok::kw_asm, "expected 'module asm'") ||
      ParseStringConstant(AsmStr)) return true;

  const std::string &AsmSoFar = M->getModuleInlineAsm();
  if (AsmSoFar.empty())
    M->setModuleInlineAsm(AsmStr);
  else
    M->setModuleInlineAsm(AsmSoFar+"\n"+AsmStr);
  return false;
}

/// toplevelentity
///   ::= 'target' 'triple' '=' STRINGCONSTANT
///   ::= 'target' 'datalayout' '=' STRINGCONSTANT
bool LLParser::ParseTargetDefinition() {
  assert(Lex.getKind() == lltok::kw_target);
  std::string Str;
  switch (Lex.Lex()) {
  default: return TokError("unknown target property");
  case lltok::kw_triple:
    Lex.Lex();
    if (ParseToken(lltok::equal, "expected '=' after target triple") ||
        ParseStringConstant(Str))
      return true;
    M->setTargetTriple(Str);
    return false;
  case lltok::kw_datalayout:
    Lex.Lex();
    if (ParseToken(lltok::equal, "expected '=' after target datalayout") ||
        ParseStringConstant(Str))
      return true;
    M->setDataLayout(Str);
    return false;
  }
}

/// toplevelentity
///   ::= 'deplibs' '=' '[' ']'
///   ::= 'deplibs' '=' '[' STRINGCONSTANT (',' STRINGCONSTANT)* ']'
bool LLParser::ParseDepLibs() {
  assert(Lex.getKind() == lltok::kw_deplibs);
  Lex.Lex();
  if (ParseToken(lltok::equal, "expected '=' after deplibs") ||
      ParseToken(lltok::lsquare, "expected '=' after deplibs"))
    return true;

  if (EatIfPresent(lltok::rsquare))
    return false;

  std::string Str;
  if (ParseStringConstant(Str)) return true;
  M->addLibrary(Str);

  while (EatIfPresent(lltok::comma)) {
    if (ParseStringConstant(Str)) return true;
    M->addLibrary(Str);
  }

  return ParseToken(lltok::rsquare, "expected ']' at end of list");
}

/// ParseUnnamedType:
///   ::= 'type' type
///   ::= LocalVarID '=' 'type' type
bool LLParser::ParseUnnamedType() {
  unsigned TypeID = NumberedTypes.size();

  // Handle the LocalVarID form.
  if (Lex.getKind() == lltok::LocalVarID) {
    if (Lex.getUIntVal() != TypeID)
      return Error(Lex.getLoc(), "type expected to be numbered '%" +
                   utostr(TypeID) + "'");
    Lex.Lex(); // eat LocalVarID;

    if (ParseToken(lltok::equal, "expected '=' after name"))
      return true;
  }

  assert(Lex.getKind() == lltok::kw_type);
  LocTy TypeLoc = Lex.getLoc();
  Lex.Lex(); // eat kw_type

  PATypeHolder Ty(Type::getVoidTy(Context));
  if (ParseType(Ty)) return true;

  // See if this type was previously referenced.
  std::map<unsigned, std::pair<PATypeHolder, LocTy> >::iterator
    FI = ForwardRefTypeIDs.find(TypeID);
  if (FI != ForwardRefTypeIDs.end()) {
    if (FI->second.first.get() == Ty)
      return Error(TypeLoc, "self referential type is invalid");

    cast<DerivedType>(FI->second.first.get())->refineAbstractTypeTo(Ty);
    Ty = FI->second.first.get();
    ForwardRefTypeIDs.erase(FI);
  }

  NumberedTypes.push_back(Ty);

  return false;
}

/// toplevelentity
///   ::= LocalVar '=' 'type' type
bool LLParser::ParseNamedType() {
  std::string Name = Lex.getStrVal();
  LocTy NameLoc = Lex.getLoc();
  Lex.Lex();  // eat LocalVar.

  PATypeHolder Ty(Type::getVoidTy(Context));

  if (ParseToken(lltok::equal, "expected '=' after name") ||
      ParseToken(lltok::kw_type, "expected 'type' after name") ||
      ParseType(Ty))
    return true;

  // Set the type name, checking for conflicts as we do so.
  bool AlreadyExists = M->addTypeName(Name, Ty);
  if (!AlreadyExists) return false;

  // See if this type is a forward reference.  We need to eagerly resolve
  // types to allow recursive type redefinitions below.
  std::map<std::string, std::pair<PATypeHolder, LocTy> >::iterator
  FI = ForwardRefTypes.find(Name);
  if (FI != ForwardRefTypes.end()) {
    if (FI->second.first.get() == Ty)
      return Error(NameLoc, "self referential type is invalid");

    cast<DerivedType>(FI->second.first.get())->refineAbstractTypeTo(Ty);
    Ty = FI->second.first.get();
    ForwardRefTypes.erase(FI);
  }

  // Inserting a name that is already defined, get the existing name.
  const Type *Existing = M->getTypeByName(Name);
  assert(Existing && "Conflict but no matching type?!");

  // Otherwise, this is an attempt to redefine a type. That's okay if
  // the redefinition is identical to the original.
  // FIXME: REMOVE REDEFINITIONS IN LLVM 3.0
  if (Existing == Ty) return false;

  // Any other kind of (non-equivalent) redefinition is an error.
  return Error(NameLoc, "redefinition of type named '" + Name + "' of type '" +
               Ty->getDescription() + "'");
}


/// toplevelentity
///   ::= 'declare' FunctionHeader
bool LLParser::ParseDeclare() {
  assert(Lex.getKind() == lltok::kw_declare);
  Lex.Lex();

  Function *F;
  return ParseFunctionHeader(F, false);
}

/// toplevelentity
///   ::= 'define' FunctionHeader '{' ...
bool LLParser::ParseDefine() {
  assert(Lex.getKind() == lltok::kw_define);
  Lex.Lex();

  Function *F;
  return ParseFunctionHeader(F, true) ||
         ParseFunctionBody(*F);
}

/// ParseGlobalType
///   ::= 'constant'
///   ::= 'global'
bool LLParser::ParseGlobalType(bool &IsConstant) {
  if (Lex.getKind() == lltok::kw_constant)
    IsConstant = true;
  else if (Lex.getKind() == lltok::kw_global)
    IsConstant = false;
  else {
    IsConstant = false;
    return TokError("expected 'global' or 'constant'");
  }
  Lex.Lex();
  return false;
}

/// ParseUnnamedGlobal:
///   OptionalVisibility ALIAS ...
///   OptionalLinkage OptionalVisibility ...   -> global variable
///   GlobalID '=' OptionalVisibility ALIAS ...
///   GlobalID '=' OptionalLinkage OptionalVisibility ...   -> global variable
bool LLParser::ParseUnnamedGlobal() {
  unsigned VarID = NumberedVals.size();
  std::string Name;
  LocTy NameLoc = Lex.getLoc();

  // Handle the GlobalID form.
  if (Lex.getKind() == lltok::GlobalID) {
    if (Lex.getUIntVal() != VarID)
      return Error(Lex.getLoc(), "variable expected to be numbered '%" +
                   utostr(VarID) + "'");
    Lex.Lex(); // eat GlobalID;

    if (ParseToken(lltok::equal, "expected '=' after name"))
      return true;
  }

  bool HasLinkage;
  unsigned Linkage, Visibility;
  if (ParseOptionalLinkage(Linkage, HasLinkage) ||
      ParseOptionalVisibility(Visibility))
    return true;

  if (HasLinkage || Lex.getKind() != lltok::kw_alias)
    return ParseGlobal(Name, NameLoc, Linkage, HasLinkage, Visibility);
  return ParseAlias(Name, NameLoc, Visibility);
}

/// ParseNamedGlobal:
///   GlobalVar '=' OptionalVisibility ALIAS ...
///   GlobalVar '=' OptionalLinkage OptionalVisibility ...   -> global variable
bool LLParser::ParseNamedGlobal() {
  assert(Lex.getKind() == lltok::GlobalVar);
  LocTy NameLoc = Lex.getLoc();
  std::string Name = Lex.getStrVal();
  Lex.Lex();

  bool HasLinkage;
  unsigned Linkage, Visibility;
  if (ParseToken(lltok::equal, "expected '=' in global variable") ||
      ParseOptionalLinkage(Linkage, HasLinkage) ||
      ParseOptionalVisibility(Visibility))
    return true;

  if (HasLinkage || Lex.getKind() != lltok::kw_alias)
    return ParseGlobal(Name, NameLoc, Linkage, HasLinkage, Visibility);
  return ParseAlias(Name, NameLoc, Visibility);
}

// MDString:
//   ::= '!' STRINGCONSTANT
bool LLParser::ParseMDString(MDString *&Result) {
  std::string Str;
  if (ParseStringConstant(Str)) return true;
  Result = MDString::get(Context, Str);
  return false;
}

// MDNode:
//   ::= '!' MDNodeNumber
bool LLParser::ParseMDNodeID(MDNode *&Result) {
  // !{ ..., !42, ... }
  unsigned MID = 0;
  if (ParseUInt32(MID)) return true;

  // Check existing MDNode.
  if (MID < NumberedMetadata.size() && NumberedMetadata[MID] != 0) {
    Result = NumberedMetadata[MID];
    return false;
  }

  // Create MDNode forward reference.

  // FIXME: This is not unique enough!
  std::string FwdRefName = "llvm.mdnode.fwdref." + utostr(MID);
  Value *V = MDString::get(Context, FwdRefName);
  MDNode *FwdNode = MDNode::get(Context, &V, 1);
  ForwardRefMDNodes[MID] = std::make_pair(FwdNode, Lex.getLoc());
  
  if (NumberedMetadata.size() <= MID)
    NumberedMetadata.resize(MID+1);
  NumberedMetadata[MID] = FwdNode;
  Result = FwdNode;
  return false;
}

/// ParseNamedMetadata:
///   !foo = !{ !1, !2 }
bool LLParser::ParseNamedMetadata() {
  assert(Lex.getKind() == lltok::MetadataVar);
  std::string Name = Lex.getStrVal();
  Lex.Lex();

  if (ParseToken(lltok::equal, "expected '=' here") ||
      ParseToken(lltok::exclaim, "Expected '!' here") ||
      ParseToken(lltok::lbrace, "Expected '{' here"))
    return true;

  SmallVector<MetadataBase *, 8> Elts;
  do {
    if (ParseToken(lltok::exclaim, "Expected '!' here"))
      return true;
    
    // FIXME: This rejects MDStrings.  Are they legal in an named MDNode or not?
    MDNode *N = 0;
    if (ParseMDNodeID(N)) return true;
    Elts.push_back(N);
  } while (EatIfPresent(lltok::comma));

  if (ParseToken(lltok::rbrace, "expected end of metadata node"))
    return true;

  NamedMDNode::Create(Context, Name, Elts.data(), Elts.size(), M);
  return false;
}

/// ParseStandaloneMetadata:
///   !42 = !{...}
bool LLParser::ParseStandaloneMetadata() {
  assert(Lex.getKind() == lltok::exclaim);
  Lex.Lex();
  unsigned MetadataID = 0;

  LocTy TyLoc;
  PATypeHolder Ty(Type::getVoidTy(Context));
  SmallVector<Value *, 16> Elts;
  // FIXME: This doesn't make sense here.  Pull braced MD stuff parsing out!
  if (ParseUInt32(MetadataID) ||
      ParseToken(lltok::equal, "expected '=' here") ||
      ParseType(Ty, TyLoc) ||
      ParseToken(lltok::exclaim, "Expected '!' here") ||
      ParseToken(lltok::lbrace, "Expected '{' here") ||
      ParseMDNodeVector(Elts) ||
      ParseToken(lltok::rbrace, "expected end of metadata node"))
    return true;

  MDNode *Init = MDNode::get(Context, Elts.data(), Elts.size());
  
  // See if this was forward referenced, if so, handle it.
  std::map<unsigned, std::pair<TrackingVH<MDNode>, LocTy> >::iterator
    FI = ForwardRefMDNodes.find(MetadataID);
  if (FI != ForwardRefMDNodes.end()) {
    FI->second.first->replaceAllUsesWith(Init);
    ForwardRefMDNodes.erase(FI);
    
    assert(NumberedMetadata[MetadataID] == Init && "Tracking VH didn't work");
  } else {
    if (MetadataID >= NumberedMetadata.size())
      NumberedMetadata.resize(MetadataID+1);

    if (NumberedMetadata[MetadataID] != 0)
      return TokError("Metadata id is already used");
    NumberedMetadata[MetadataID] = Init;
  }

  return false;
}

/// ParseAlias:
///   ::= GlobalVar '=' OptionalVisibility 'alias' OptionalLinkage Aliasee
/// Aliasee
///   ::= TypeAndValue
///   ::= 'bitcast' '(' TypeAndValue 'to' Type ')'
///   ::= 'getelementptr' 'inbounds'? '(' ... ')'
///
/// Everything through visibility has already been parsed.
///
bool LLParser::ParseAlias(const std::string &Name, LocTy NameLoc,
                          unsigned Visibility) {
  assert(Lex.getKind() == lltok::kw_alias);
  Lex.Lex();
  unsigned Linkage;
  LocTy LinkageLoc = Lex.getLoc();
  if (ParseOptionalLinkage(Linkage))
    return true;

  if (Linkage != GlobalValue::ExternalLinkage &&
      Linkage != GlobalValue::WeakAnyLinkage &&
      Linkage != GlobalValue::WeakODRLinkage &&
      Linkage != GlobalValue::InternalLinkage &&
      Linkage != GlobalValue::PrivateLinkage &&
      Linkage != GlobalValue::LinkerPrivateLinkage)
    return Error(LinkageLoc, "invalid linkage type for alias");

  Constant *Aliasee;
  LocTy AliaseeLoc = Lex.getLoc();
  if (Lex.getKind() != lltok::kw_bitcast &&
      Lex.getKind() != lltok::kw_getelementptr) {
    if (ParseGlobalTypeAndValue(Aliasee)) return true;
  } else {
    // The bitcast dest type is not present, it is implied by the dest type.
    ValID ID;
    if (ParseValID(ID)) return true;
    if (ID.Kind != ValID::t_Constant)
      return Error(AliaseeLoc, "invalid aliasee");
    Aliasee = ID.ConstantVal;
  }

  if (!isa<PointerType>(Aliasee->getType()))
    return Error(AliaseeLoc, "alias must have pointer type");

  // Okay, create the alias but do not insert it into the module yet.
  GlobalAlias* GA = new GlobalAlias(Aliasee->getType(),
                                    (GlobalValue::LinkageTypes)Linkage, Name,
                                    Aliasee);
  GA->setVisibility((GlobalValue::VisibilityTypes)Visibility);

  // See if this value already exists in the symbol table.  If so, it is either
  // a redefinition or a definition of a forward reference.
  if (GlobalValue *Val = M->getNamedValue(Name)) {
    // See if this was a redefinition.  If so, there is no entry in
    // ForwardRefVals.
    std::map<std::string, std::pair<GlobalValue*, LocTy> >::iterator
      I = ForwardRefVals.find(Name);
    if (I == ForwardRefVals.end())
      return Error(NameLoc, "redefinition of global named '@" + Name + "'");

    // Otherwise, this was a definition of forward ref.  Verify that types
    // agree.
    if (Val->getType() != GA->getType())
      return Error(NameLoc,
              "forward reference and definition of alias have different types");

    // If they agree, just RAUW the old value with the alias and remove the
    // forward ref info.
    Val->replaceAllUsesWith(GA);
    Val->eraseFromParent();
    ForwardRefVals.erase(I);
  }

  // Insert into the module, we know its name won't collide now.
  M->getAliasList().push_back(GA);
  assert(GA->getNameStr() == Name && "Should not be a name conflict!");

  return false;
}

/// ParseGlobal
///   ::= GlobalVar '=' OptionalLinkage OptionalVisibility OptionalThreadLocal
///       OptionalAddrSpace GlobalType Type Const
///   ::= OptionalLinkage OptionalVisibility OptionalThreadLocal
///       OptionalAddrSpace GlobalType Type Const
///
/// Everything through visibility has been parsed already.
///
bool LLParser::ParseGlobal(const std::string &Name, LocTy NameLoc,
                           unsigned Linkage, bool HasLinkage,
                           unsigned Visibility) {
  unsigned AddrSpace;
  bool ThreadLocal, IsConstant;
  LocTy TyLoc;

  PATypeHolder Ty(Type::getVoidTy(Context));
  if (ParseOptionalToken(lltok::kw_thread_local, ThreadLocal) ||
      ParseOptionalAddrSpace(AddrSpace) ||
      ParseGlobalType(IsConstant) ||
      ParseType(Ty, TyLoc))
    return true;

  // If the linkage is specified and is external, then no initializer is
  // present.
  Constant *Init = 0;
  if (!HasLinkage || (Linkage != GlobalValue::DLLImportLinkage &&
                      Linkage != GlobalValue::ExternalWeakLinkage &&
                      Linkage != GlobalValue::ExternalLinkage)) {
    if (ParseGlobalValue(Ty, Init))
      return true;
  }

  if (isa<FunctionType>(Ty) || Ty->isLabelTy())
    return Error(TyLoc, "invalid type for global variable");

  GlobalVariable *GV = 0;

  // See if the global was forward referenced, if so, use the global.
  if (!Name.empty()) {
    if (GlobalValue *GVal = M->getNamedValue(Name)) {
      if (!ForwardRefVals.erase(Name) || !isa<GlobalValue>(GVal))
        return Error(NameLoc, "redefinition of global '@" + Name + "'");
      GV = cast<GlobalVariable>(GVal);
    }
  } else {
    std::map<unsigned, std::pair<GlobalValue*, LocTy> >::iterator
      I = ForwardRefValIDs.find(NumberedVals.size());
    if (I != ForwardRefValIDs.end()) {
      GV = cast<GlobalVariable>(I->second.first);
      ForwardRefValIDs.erase(I);
    }
  }

  if (GV == 0) {
    GV = new GlobalVariable(*M, Ty, false, GlobalValue::ExternalLinkage, 0,
                            Name, 0, false, AddrSpace);
  } else {
    if (GV->getType()->getElementType() != Ty)
      return Error(TyLoc,
            "forward reference and definition of global have different types");

    // Move the forward-reference to the correct spot in the module.
    M->getGlobalList().splice(M->global_end(), M->getGlobalList(), GV);
  }

  if (Name.empty())
    NumberedVals.push_back(GV);

  // Set the parsed properties on the global.
  if (Init)
    GV->setInitializer(Init);
  GV->setConstant(IsConstant);
  GV->setLinkage((GlobalValue::LinkageTypes)Linkage);
  GV->setVisibility((GlobalValue::VisibilityTypes)Visibility);
  GV->setThreadLocal(ThreadLocal);

  // Parse attributes on the global.
  while (Lex.getKind() == lltok::comma) {
    Lex.Lex();

    if (Lex.getKind() == lltok::kw_section) {
      Lex.Lex();
      GV->setSection(Lex.getStrVal());
      if (ParseToken(lltok::StringConstant, "expected global section string"))
        return true;
    } else if (Lex.getKind() == lltok::kw_align) {
      unsigned Alignment;
      if (ParseOptionalAlignment(Alignment)) return true;
      GV->setAlignment(Alignment);
    } else {
      TokError("unknown global variable property!");
    }
  }

  return false;
}


//===----------------------------------------------------------------------===//
// GlobalValue Reference/Resolution Routines.
//===----------------------------------------------------------------------===//

/// GetGlobalVal - Get a value with the specified name or ID, creating a
/// forward reference record if needed.  This can return null if the value
/// exists but does not have the right type.
GlobalValue *LLParser::GetGlobalVal(const std::string &Name, const Type *Ty,
                                    LocTy Loc) {
  const PointerType *PTy = dyn_cast<PointerType>(Ty);
  if (PTy == 0) {
    Error(Loc, "global variable reference must have pointer type");
    return 0;
  }

  // Look this name up in the normal function symbol table.
  GlobalValue *Val =
    cast_or_null<GlobalValue>(M->getValueSymbolTable().lookup(Name));

  // If this is a forward reference for the value, see if we already created a
  // forward ref record.
  if (Val == 0) {
    std::map<std::string, std::pair<GlobalValue*, LocTy> >::iterator
      I = ForwardRefVals.find(Name);
    if (I != ForwardRefVals.end())
      Val = I->second.first;
  }

  // If we have the value in the symbol table or fwd-ref table, return it.
  if (Val) {
    if (Val->getType() == Ty) return Val;
    Error(Loc, "'@" + Name + "' defined with type '" +
          Val->getType()->getDescription() + "'");
    return 0;
  }

  // Otherwise, create a new forward reference for this value and remember it.
  GlobalValue *FwdVal;
  if (const FunctionType *FT = dyn_cast<FunctionType>(PTy->getElementType())) {
    // Function types can return opaque but functions can't.
    if (isa<OpaqueType>(FT->getReturnType())) {
      Error(Loc, "function may not return opaque type");
      return 0;
    }

    FwdVal = Function::Create(FT, GlobalValue::ExternalWeakLinkage, Name, M);
  } else {
    FwdVal = new GlobalVariable(*M, PTy->getElementType(), false,
                                GlobalValue::ExternalWeakLinkage, 0, Name);
  }

  ForwardRefVals[Name] = std::make_pair(FwdVal, Loc);
  return FwdVal;
}

GlobalValue *LLParser::GetGlobalVal(unsigned ID, const Type *Ty, LocTy Loc) {
  const PointerType *PTy = dyn_cast<PointerType>(Ty);
  if (PTy == 0) {
    Error(Loc, "global variable reference must have pointer type");
    return 0;
  }

  GlobalValue *Val = ID < NumberedVals.size() ? NumberedVals[ID] : 0;

  // If this is a forward reference for the value, see if we already created a
  // forward ref record.
  if (Val == 0) {
    std::map<unsigned, std::pair<GlobalValue*, LocTy> >::iterator
      I = ForwardRefValIDs.find(ID);
    if (I != ForwardRefValIDs.end())
      Val = I->second.first;
  }

  // If we have the value in the symbol table or fwd-ref table, return it.
  if (Val) {
    if (Val->getType() == Ty) return Val;
    Error(Loc, "'@" + utostr(ID) + "' defined with type '" +
          Val->getType()->getDescription() + "'");
    return 0;
  }

  // Otherwise, create a new forward reference for this value and remember it.
  GlobalValue *FwdVal;
  if (const FunctionType *FT = dyn_cast<FunctionType>(PTy->getElementType())) {
    // Function types can return opaque but functions can't.
    if (isa<OpaqueType>(FT->getReturnType())) {
      Error(Loc, "function may not return opaque type");
      return 0;
    }
    FwdVal = Function::Create(FT, GlobalValue::ExternalWeakLinkage, "", M);
  } else {
    FwdVal = new GlobalVariable(*M, PTy->getElementType(), false,
                                GlobalValue::ExternalWeakLinkage, 0, "");
  }

  ForwardRefValIDs[ID] = std::make_pair(FwdVal, Loc);
  return FwdVal;
}


//===----------------------------------------------------------------------===//
// Helper Routines.
//===----------------------------------------------------------------------===//

/// ParseToken - If the current token has the specified kind, eat it and return
/// success.  Otherwise, emit the specified error and return failure.
bool LLParser::ParseToken(lltok::Kind T, const char *ErrMsg) {
  if (Lex.getKind() != T)
    return TokError(ErrMsg);
  Lex.Lex();
  return false;
}

/// ParseStringConstant
///   ::= StringConstant
bool LLParser::ParseStringConstant(std::string &Result) {
  if (Lex.getKind() != lltok::StringConstant)
    return TokError("expected string constant");
  Result = Lex.getStrVal();
  Lex.Lex();
  return false;
}

/// ParseUInt32
///   ::= uint32
bool LLParser::ParseUInt32(unsigned &Val) {
  if (Lex.getKind() != lltok::APSInt || Lex.getAPSIntVal().isSigned())
    return TokError("expected integer");
  uint64_t Val64 = Lex.getAPSIntVal().getLimitedValue(0xFFFFFFFFULL+1);
  if (Val64 != unsigned(Val64))
    return TokError("expected 32-bit integer (too large)");
  Val = Val64;
  Lex.Lex();
  return false;
}


/// ParseOptionalAddrSpace
///   := /*empty*/
///   := 'addrspace' '(' uint32 ')'
bool LLParser::ParseOptionalAddrSpace(unsigned &AddrSpace) {
  AddrSpace = 0;
  if (!EatIfPresent(lltok::kw_addrspace))
    return false;
  return ParseToken(lltok::lparen, "expected '(' in address space") ||
         ParseUInt32(AddrSpace) ||
         ParseToken(lltok::rparen, "expected ')' in address space");
}

/// ParseOptionalAttrs - Parse a potentially empty attribute list.  AttrKind
/// indicates what kind of attribute list this is: 0: function arg, 1: result,
/// 2: function attr.
/// 3: function arg after value: FIXME: REMOVE IN LLVM 3.0
bool LLParser::ParseOptionalAttrs(unsigned &Attrs, unsigned AttrKind) {
  Attrs = Attribute::None;
  LocTy AttrLoc = Lex.getLoc();

  while (1) {
    switch (Lex.getKind()) {
    case lltok::kw_sext:
    case lltok::kw_zext:
      // Treat these as signext/zeroext if they occur in the argument list after
      // the value, as in "call i8 @foo(i8 10 sext)".  If they occur before the
      // value, as in "call i8 @foo(i8 sext (" then it is part of a constant
      // expr.
      // FIXME: REMOVE THIS IN LLVM 3.0
      if (AttrKind == 3) {
        if (Lex.getKind() == lltok::kw_sext)
          Attrs |= Attribute::SExt;
        else
          Attrs |= Attribute::ZExt;
        break;
      }
      // FALL THROUGH.
    default:  // End of attributes.
      if (AttrKind != 2 && (Attrs & Attribute::FunctionOnly))
        return Error(AttrLoc, "invalid use of function-only attribute");

      if (AttrKind != 0 && AttrKind != 3 && (Attrs & Attribute::ParameterOnly))
        return Error(AttrLoc, "invalid use of parameter-only attribute");

      return false;
    case lltok::kw_zeroext:         Attrs |= Attribute::ZExt; break;
    case lltok::kw_signext:         Attrs |= Attribute::SExt; break;
    case lltok::kw_inreg:           Attrs |= Attribute::InReg; break;
    case lltok::kw_sret:            Attrs |= Attribute::StructRet; break;
    case lltok::kw_noalias:         Attrs |= Attribute::NoAlias; break;
    case lltok::kw_nocapture:       Attrs |= Attribute::NoCapture; break;
    case lltok::kw_byval:           Attrs |= Attribute::ByVal; break;
    case lltok::kw_nest:            Attrs |= Attribute::Nest; break;

    case lltok::kw_noreturn:        Attrs |= Attribute::NoReturn; break;
    case lltok::kw_nounwind:        Attrs |= Attribute::NoUnwind; break;
    case lltok::kw_noinline:        Attrs |= Attribute::NoInline; break;
    case lltok::kw_readnone:        Attrs |= Attribute::ReadNone; break;
    case lltok::kw_readonly:        Attrs |= Attribute::ReadOnly; break;
    case lltok::kw_inlinehint:      Attrs |= Attribute::InlineHint; break;
    case lltok::kw_alwaysinline:    Attrs |= Attribute::AlwaysInline; break;
    case lltok::kw_optsize:         Attrs |= Attribute::OptimizeForSize; break;
    case lltok::kw_ssp:             Attrs |= Attribute::StackProtect; break;
    case lltok::kw_sspreq:          Attrs |= Attribute::StackProtectReq; break;
    case lltok::kw_noredzone:       Attrs |= Attribute::NoRedZone; break;
    case lltok::kw_noimplicitfloat: Attrs |= Attribute::NoImplicitFloat; break;
    case lltok::kw_naked:           Attrs |= Attribute::Naked; break;

    case lltok::kw_align: {
      unsigned Alignment;
      if (ParseOptionalAlignment(Alignment))
        return true;
      Attrs |= Attribute::constructAlignmentFromInt(Alignment);
      continue;
    }
    }
    Lex.Lex();
  }
}

/// ParseOptionalLinkage
///   ::= /*empty*/
///   ::= 'private'
///   ::= 'linker_private'
///   ::= 'internal'
///   ::= 'weak'
///   ::= 'weak_odr'
///   ::= 'linkonce'
///   ::= 'linkonce_odr'
///   ::= 'appending'
///   ::= 'dllexport'
///   ::= 'common'
///   ::= 'dllimport'
///   ::= 'extern_weak'
///   ::= 'external'
bool LLParser::ParseOptionalLinkage(unsigned &Res, bool &HasLinkage) {
  HasLinkage = false;
  switch (Lex.getKind()) {
  default:                       Res=GlobalValue::ExternalLinkage; return false;
  case lltok::kw_private:        Res = GlobalValue::PrivateLinkage;       break;
  case lltok::kw_linker_private: Res = GlobalValue::LinkerPrivateLinkage; break;
  case lltok::kw_internal:       Res = GlobalValue::InternalLinkage;      break;
  case lltok::kw_weak:           Res = GlobalValue::WeakAnyLinkage;       break;
  case lltok::kw_weak_odr:       Res = GlobalValue::WeakODRLinkage;       break;
  case lltok::kw_linkonce:       Res = GlobalValue::LinkOnceAnyLinkage;   break;
  case lltok::kw_linkonce_odr:   Res = GlobalValue::LinkOnceODRLinkage;   break;
  case lltok::kw_available_externally:
    Res = GlobalValue::AvailableExternallyLinkage;
    break;
  case lltok::kw_appending:      Res = GlobalValue::AppendingLinkage;     break;
  case lltok::kw_dllexport:      Res = GlobalValue::DLLExportLinkage;     break;
  case lltok::kw_common:         Res = GlobalValue::CommonLinkage;        break;
  case lltok::kw_dllimport:      Res = GlobalValue::DLLImportLinkage;     break;
  case lltok::kw_extern_weak:    Res = GlobalValue::ExternalWeakLinkage;  break;
  case lltok::kw_external:       Res = GlobalValue::ExternalLinkage;      break;
  }
  Lex.Lex();
  HasLinkage = true;
  return false;
}

/// ParseOptionalVisibility
///   ::= /*empty*/
///   ::= 'default'
///   ::= 'hidden'
///   ::= 'protected'
///
bool LLParser::ParseOptionalVisibility(unsigned &Res) {
  switch (Lex.getKind()) {
  default:                  Res = GlobalValue::DefaultVisibility; return false;
  case lltok::kw_default:   Res = GlobalValue::DefaultVisibility; break;
  case lltok::kw_hidden:    Res = GlobalValue::HiddenVisibility; break;
  case lltok::kw_protected: Res = GlobalValue::ProtectedVisibility; break;
  }
  Lex.Lex();
  return false;
}

/// ParseOptionalCallingConv
///   ::= /*empty*/
///   ::= 'ccc'
///   ::= 'fastcc'
///   ::= 'coldcc'
///   ::= 'x86_stdcallcc'
///   ::= 'x86_fastcallcc'
///   ::= 'arm_apcscc'
///   ::= 'arm_aapcscc'
///   ::= 'arm_aapcs_vfpcc'
///   ::= 'msp430_intrcc'
///   ::= 'cc' UINT
///
bool LLParser::ParseOptionalCallingConv(CallingConv::ID &CC) {
  switch (Lex.getKind()) {
  default:                       CC = CallingConv::C; return false;
  case lltok::kw_ccc:            CC = CallingConv::C; break;
  case lltok::kw_fastcc:         CC = CallingConv::Fast; break;
  case lltok::kw_coldcc:         CC = CallingConv::Cold; break;
  case lltok::kw_x86_stdcallcc:  CC = CallingConv::X86_StdCall; break;
  case lltok::kw_x86_fastcallcc: CC = CallingConv::X86_FastCall; break;
  case lltok::kw_arm_apcscc:     CC = CallingConv::ARM_APCS; break;
  case lltok::kw_arm_aapcscc:    CC = CallingConv::ARM_AAPCS; break;
  case lltok::kw_arm_aapcs_vfpcc:CC = CallingConv::ARM_AAPCS_VFP; break;
  case lltok::kw_msp430_intrcc:  CC = CallingConv::MSP430_INTR; break;
  case lltok::kw_cc: {
      unsigned ArbitraryCC;
      Lex.Lex();
      if (ParseUInt32(ArbitraryCC)) {
        return true;
      } else
        CC = static_cast<CallingConv::ID>(ArbitraryCC);
        return false;
    }
    break;
  }

  Lex.Lex();
  return false;
}

/// ParseOptionalCustomMetadata
///   ::= /* empty */
///   ::= !dbg !42 (',' !dbg !57)*
bool LLParser::ParseOptionalCustomMetadata() {
  if (Lex.getKind() != lltok::MetadataVar)
    return false;

  while (1) {
    std::string Name = Lex.getStrVal();
    Lex.Lex();

    MDNode *Node;
    if (ParseToken(lltok::exclaim, "expected '!' here") ||
        ParseMDNodeID(Node))
      return true;

    unsigned MDK = M->getMDKindID(Name.c_str());
    MDsOnInst.push_back(std::make_pair(MDK, Node));

    // If this is the end of the list, we're done.
    if (!EatIfPresent(lltok::comma))
      return false;

    // The next value must be a custom metadata id.
    if (Lex.getKind() != lltok::MetadataVar)
      return TokError("expected more custom metadata ids");
  }
}

/// ParseOptionalAlignment
///   ::= /* empty */
///   ::= 'align' 4
bool LLParser::ParseOptionalAlignment(unsigned &Alignment) {
  Alignment = 0;
  if (!EatIfPresent(lltok::kw_align))
    return false;
  LocTy AlignLoc = Lex.getLoc();
  if (ParseUInt32(Alignment)) return true;
  if (!isPowerOf2_32(Alignment))
    return Error(AlignLoc, "alignment is not a power of two");
  return false;
}

/// ParseOptionalInfo
///   ::= OptionalInfo (',' OptionalInfo)+
bool LLParser::ParseOptionalInfo(unsigned &Alignment) {

  // FIXME: Handle customized metadata info attached with an instruction.
  do {
    if (Lex.getKind() == lltok::MetadataVar) {
      if (ParseOptionalCustomMetadata()) return true;
    } else if (Lex.getKind() == lltok::kw_align) {
      if (ParseOptionalAlignment(Alignment)) return true;
    } else
      return true;
  } while (EatIfPresent(lltok::comma));

  return false;
}


/// ParseIndexList
///    ::=  (',' uint32)+
bool LLParser::ParseIndexList(SmallVectorImpl<unsigned> &Indices) {
  if (Lex.getKind() != lltok::comma)
    return TokError("expected ',' as start of index list");

  while (EatIfPresent(lltok::comma)) {
    // FIXME: TERRIBLE HACK.  Loses comma state.
    if (Lex.getKind() == lltok::MetadataVar)
      break;
    unsigned Idx;
    if (ParseUInt32(Idx)) return true;
    Indices.push_back(Idx);
  }

  return false;
}

//===----------------------------------------------------------------------===//
// Type Parsing.
//===----------------------------------------------------------------------===//

/// ParseType - Parse and resolve a full type.
bool LLParser::ParseType(PATypeHolder &Result, bool AllowVoid) {
  LocTy TypeLoc = Lex.getLoc();
  if (ParseTypeRec(Result)) return true;

  // Verify no unresolved uprefs.
  if (!UpRefs.empty())
    return Error(UpRefs.back().Loc, "invalid unresolved type up reference");

  if (!AllowVoid && Result.get()->isVoidTy())
    return Error(TypeLoc, "void type only allowed for function results");

  return false;
}

/// HandleUpRefs - Every time we finish a new layer of types, this function is
/// called.  It loops through the UpRefs vector, which is a list of the
/// currently active types.  For each type, if the up-reference is contained in
/// the newly completed type, we decrement the level count.  When the level
/// count reaches zero, the up-referenced type is the type that is passed in:
/// thus we can complete the cycle.
///
PATypeHolder LLParser::HandleUpRefs(const Type *ty) {
  // If Ty isn't abstract, or if there are no up-references in it, then there is
  // nothing to resolve here.
  if (!ty->isAbstract() || UpRefs.empty()) return ty;

  PATypeHolder Ty(ty);
#if 0
  dbgs() << "Type '" << Ty->getDescription()
         << "' newly formed.  Resolving upreferences.\n"
         << UpRefs.size() << " upreferences active!\n";
#endif

  // If we find any resolvable upreferences (i.e., those whose NestingLevel goes
  // to zero), we resolve them all together before we resolve them to Ty.  At
  // the end of the loop, if there is anything to resolve to Ty, it will be in
  // this variable.
  OpaqueType *TypeToResolve = 0;

  for (unsigned i = 0; i != UpRefs.size(); ++i) {
    // Determine if 'Ty' directly contains this up-references 'LastContainedTy'.
    bool ContainsType =
      std::find(Ty->subtype_begin(), Ty->subtype_end(),
                UpRefs[i].LastContainedTy) != Ty->subtype_end();

#if 0
    dbgs() << "  UR#" << i << " - TypeContains(" << Ty->getDescription() << ", "
           << UpRefs[i].LastContainedTy->getDescription() << ") = "
           << (ContainsType ? "true" : "false")
           << " level=" << UpRefs[i].NestingLevel << "\n";
#endif
    if (!ContainsType)
      continue;

    // Decrement level of upreference
    unsigned Level = --UpRefs[i].NestingLevel;
    UpRefs[i].LastContainedTy = Ty;

    // If the Up-reference has a non-zero level, it shouldn't be resolved yet.
    if (Level != 0)
      continue;

#if 0
    dbgs() << "  * Resolving upreference for " << UpRefs[i].UpRefTy << "\n";
#endif
    if (!TypeToResolve)
      TypeToResolve = UpRefs[i].UpRefTy;
    else
      UpRefs[i].UpRefTy->refineAbstractTypeTo(TypeToResolve);
    UpRefs.erase(UpRefs.begin()+i);     // Remove from upreference list.
    --i;                                // Do not skip the next element.
  }

  if (TypeToResolve)
    TypeToResolve->refineAbstractTypeTo(Ty);

  return Ty;
}


/// ParseTypeRec - The recursive function used to process the internal
/// implementation details of types.
bool LLParser::ParseTypeRec(PATypeHolder &Result) {
  switch (Lex.getKind()) {
  default:
    return TokError("expected type");
  case lltok::Type:
    // TypeRec ::= 'float' | 'void' (etc)
    Result = Lex.getTyVal();
    Lex.Lex();
    break;
  case lltok::kw_opaque:
    // TypeRec ::= 'opaque'
    Result = OpaqueType::get(Context);
    Lex.Lex();
    break;
  case lltok::lbrace:
    // TypeRec ::= '{' ... '}'
    if (ParseStructType(Result, false))
      return true;
    break;
  case lltok::lsquare:
    // TypeRec ::= '[' ... ']'
    Lex.Lex(); // eat the lsquare.
    if (ParseArrayVectorType(Result, false))
      return true;
    break;
  case lltok::less: // Either vector or packed struct.
    // TypeRec ::= '<' ... '>'
    Lex.Lex();
    if (Lex.getKind() == lltok::lbrace) {
      if (ParseStructType(Result, true) ||
          ParseToken(lltok::greater, "expected '>' at end of packed struct"))
        return true;
    } else if (ParseArrayVectorType(Result, true))
      return true;
    break;
  case lltok::LocalVar:
  case lltok::StringConstant:  // FIXME: REMOVE IN LLVM 3.0
    // TypeRec ::= %foo
    if (const Type *T = M->getTypeByName(Lex.getStrVal())) {
      Result = T;
    } else {
      Result = OpaqueType::get(Context);
      ForwardRefTypes.insert(std::make_pair(Lex.getStrVal(),
                                            std::make_pair(Result,
                                                           Lex.getLoc())));
      M->addTypeName(Lex.getStrVal(), Result.get());
    }
    Lex.Lex();
    break;

  case lltok::LocalVarID:
    // TypeRec ::= %4
    if (Lex.getUIntVal() < NumberedTypes.size())
      Result = NumberedTypes[Lex.getUIntVal()];
    else {
      std::map<unsigned, std::pair<PATypeHolder, LocTy> >::iterator
        I = ForwardRefTypeIDs.find(Lex.getUIntVal());
      if (I != ForwardRefTypeIDs.end())
        Result = I->second.first;
      else {
        Result = OpaqueType::get(Context);
        ForwardRefTypeIDs.insert(std::make_pair(Lex.getUIntVal(),
                                                std::make_pair(Result,
                                                               Lex.getLoc())));
      }
    }
    Lex.Lex();
    break;
  case lltok::backslash: {
    // TypeRec ::= '\' 4
    Lex.Lex();
    unsigned Val;
    if (ParseUInt32(Val)) return true;
    OpaqueType *OT = OpaqueType::get(Context); //Use temporary placeholder.
    UpRefs.push_back(UpRefRecord(Lex.getLoc(), Val, OT));
    Result = OT;
    break;
  }
  }

  // Parse the type suffixes.
  while (1) {
    switch (Lex.getKind()) {
    // End of type.
    default: return false;

    // TypeRec ::= TypeRec '*'
    case lltok::star:
      if (Result.get()->isLabelTy())
        return TokError("basic block pointers are invalid");
      if (Result.get()->isVoidTy())
        return TokError("pointers to void are invalid; use i8* instead");
      if (!PointerType::isValidElementType(Result.get()))
        return TokError("pointer to this type is invalid");
      Result = HandleUpRefs(PointerType::getUnqual(Result.get()));
      Lex.Lex();
      break;

    // TypeRec ::= TypeRec 'addrspace' '(' uint32 ')' '*'
    case lltok::kw_addrspace: {
      if (Result.get()->isLabelTy())
        return TokError("basic block pointers are invalid");
      if (Result.get()->isVoidTy())
        return TokError("pointers to void are invalid; use i8* instead");
      if (!PointerType::isValidElementType(Result.get()))
        return TokError("pointer to this type is invalid");
      unsigned AddrSpace;
      if (ParseOptionalAddrSpace(AddrSpace) ||
          ParseToken(lltok::star, "expected '*' in address space"))
        return true;

      Result = HandleUpRefs(PointerType::get(Result.get(), AddrSpace));
      break;
    }

    /// Types '(' ArgTypeListI ')' OptFuncAttrs
    case lltok::lparen:
      if (ParseFunctionType(Result))
        return true;
      break;
    }
  }
}

/// ParseParameterList
///    ::= '(' ')'
///    ::= '(' Arg (',' Arg)* ')'
///  Arg
///    ::= Type OptionalAttributes Value OptionalAttributes
bool LLParser::ParseParameterList(SmallVectorImpl<ParamInfo> &ArgList,
                                  PerFunctionState &PFS) {
  if (ParseToken(lltok::lparen, "expected '(' in call"))
    return true;

  while (Lex.getKind() != lltok::rparen) {
    // If this isn't the first argument, we need a comma.
    if (!ArgList.empty() &&
        ParseToken(lltok::comma, "expected ',' in argument list"))
      return true;

    // Parse the argument.
    LocTy ArgLoc;
    PATypeHolder ArgTy(Type::getVoidTy(Context));
    unsigned ArgAttrs1 = Attribute::None;
    unsigned ArgAttrs2 = Attribute::None;
    Value *V;
    if (ParseType(ArgTy, ArgLoc))
      return true;

    // Otherwise, handle normal operands.
    if (ParseOptionalAttrs(ArgAttrs1, 0) ||
        ParseValue(ArgTy, V, PFS) ||
        // FIXME: Should not allow attributes after the argument, remove this
        // in LLVM 3.0.
        ParseOptionalAttrs(ArgAttrs2, 3))
      return true;
    ArgList.push_back(ParamInfo(ArgLoc, V, ArgAttrs1|ArgAttrs2));
  }

  Lex.Lex();  // Lex the ')'.
  return false;
}



/// ParseArgumentList - Parse the argument list for a function type or function
/// prototype.  If 'inType' is true then we are parsing a FunctionType.
///   ::= '(' ArgTypeListI ')'
/// ArgTypeListI
///   ::= /*empty*/
///   ::= '...'
///   ::= ArgTypeList ',' '...'
///   ::= ArgType (',' ArgType)*
///
bool LLParser::ParseArgumentList(std::vector<ArgInfo> &ArgList,
                                 bool &isVarArg, bool inType) {
  isVarArg = false;
  assert(Lex.getKind() == lltok::lparen);
  Lex.Lex(); // eat the (.

  if (Lex.getKind() == lltok::rparen) {
    // empty
  } else if (Lex.getKind() == lltok::dotdotdot) {
    isVarArg = true;
    Lex.Lex();
  } else {
    LocTy TypeLoc = Lex.getLoc();
    PATypeHolder ArgTy(Type::getVoidTy(Context));
    unsigned Attrs;
    std::string Name;

    // If we're parsing a type, use ParseTypeRec, because we allow recursive
    // types (such as a function returning a pointer to itself).  If parsing a
    // function prototype, we require fully resolved types.
    if ((inType ? ParseTypeRec(ArgTy) : ParseType(ArgTy)) ||
        ParseOptionalAttrs(Attrs, 0)) return true;

    if (ArgTy->isVoidTy())
      return Error(TypeLoc, "argument can not have void type");

    if (Lex.getKind() == lltok::LocalVar ||
        Lex.getKind() == lltok::StringConstant) { // FIXME: REMOVE IN LLVM 3.0
      Name = Lex.getStrVal();
      Lex.Lex();
    }

    if (!FunctionType::isValidArgumentType(ArgTy))
      return Error(TypeLoc, "invalid type for function argument");

    ArgList.push_back(ArgInfo(TypeLoc, ArgTy, Attrs, Name));

    while (EatIfPresent(lltok::comma)) {
      // Handle ... at end of arg list.
      if (EatIfPresent(lltok::dotdotdot)) {
        isVarArg = true;
        break;
      }

      // Otherwise must be an argument type.
      TypeLoc = Lex.getLoc();
      if ((inType ? ParseTypeRec(ArgTy) : ParseType(ArgTy)) ||
          ParseOptionalAttrs(Attrs, 0)) return true;

      if (ArgTy->isVoidTy())
        return Error(TypeLoc, "argument can not have void type");

      if (Lex.getKind() == lltok::LocalVar ||
          Lex.getKind() == lltok::StringConstant) { // FIXME: REMOVE IN LLVM 3.0
        Name = Lex.getStrVal();
        Lex.Lex();
      } else {
        Name = "";
      }

      if (!ArgTy->isFirstClassType() && !isa<OpaqueType>(ArgTy))
        return Error(TypeLoc, "invalid type for function argument");

      ArgList.push_back(ArgInfo(TypeLoc, ArgTy, Attrs, Name));
    }
  }

  return ParseToken(lltok::rparen, "expected ')' at end of argument list");
}

/// ParseFunctionType
///  ::= Type ArgumentList OptionalAttrs
bool LLParser::ParseFunctionType(PATypeHolder &Result) {
  assert(Lex.getKind() == lltok::lparen);

  if (!FunctionType::isValidReturnType(Result))
    return TokError("invalid function return type");

  std::vector<ArgInfo> ArgList;
  bool isVarArg;
  unsigned Attrs;
  if (ParseArgumentList(ArgList, isVarArg, true) ||
      // FIXME: Allow, but ignore attributes on function types!
      // FIXME: Remove in LLVM 3.0
      ParseOptionalAttrs(Attrs, 2))
    return true;

  // Reject names on the arguments lists.
  for (unsigned i = 0, e = ArgList.size(); i != e; ++i) {
    if (!ArgList[i].Name.empty())
      return Error(ArgList[i].Loc, "argument name invalid in function type");
    if (!ArgList[i].Attrs != 0) {
      // Allow but ignore attributes on function types; this permits
      // auto-upgrade.
      // FIXME: REJECT ATTRIBUTES ON FUNCTION TYPES in LLVM 3.0
    }
  }

  std::vector<const Type*> ArgListTy;
  for (unsigned i = 0, e = ArgList.size(); i != e; ++i)
    ArgListTy.push_back(ArgList[i].Type);

  Result = HandleUpRefs(FunctionType::get(Result.get(),
                                                ArgListTy, isVarArg));
  return false;
}

/// ParseStructType: Handles packed and unpacked types.  </> parsed elsewhere.
///   TypeRec
///     ::= '{' '}'
///     ::= '{' TypeRec (',' TypeRec)* '}'
///     ::= '<' '{' '}' '>'
///     ::= '<' '{' TypeRec (',' TypeRec)* '}' '>'
bool LLParser::ParseStructType(PATypeHolder &Result, bool Packed) {
  assert(Lex.getKind() == lltok::lbrace);
  Lex.Lex(); // Consume the '{'

  if (EatIfPresent(lltok::rbrace)) {
    Result = StructType::get(Context, Packed);
    return false;
  }

  std::vector<PATypeHolder> ParamsList;
  LocTy EltTyLoc = Lex.getLoc();
  if (ParseTypeRec(Result)) return true;
  ParamsList.push_back(Result);

  if (Result->isVoidTy())
    return Error(EltTyLoc, "struct element can not have void type");
  if (!StructType::isValidElementType(Result))
    return Error(EltTyLoc, "invalid element type for struct");

  while (EatIfPresent(lltok::comma)) {
    EltTyLoc = Lex.getLoc();
    if (ParseTypeRec(Result)) return true;

    if (Result->isVoidTy())
      return Error(EltTyLoc, "struct element can not have void type");
    if (!StructType::isValidElementType(Result))
      return Error(EltTyLoc, "invalid element type for struct");

    ParamsList.push_back(Result);
  }

  if (ParseToken(lltok::rbrace, "expected '}' at end of struct"))
    return true;

  std::vector<const Type*> ParamsListTy;
  for (unsigned i = 0, e = ParamsList.size(); i != e; ++i)
    ParamsListTy.push_back(ParamsList[i].get());
  Result = HandleUpRefs(StructType::get(Context, ParamsListTy, Packed));
  return false;
}

/// ParseArrayVectorType - Parse an array or vector type, assuming the first
/// token has already been consumed.
///   TypeRec
///     ::= '[' APSINTVAL 'x' Types ']'
///     ::= '<' APSINTVAL 'x' Types '>'
bool LLParser::ParseArrayVectorType(PATypeHolder &Result, bool isVector) {
  if (Lex.getKind() != lltok::APSInt || Lex.getAPSIntVal().isSigned() ||
      Lex.getAPSIntVal().getBitWidth() > 64)
    return TokError("expected number in address space");

  LocTy SizeLoc = Lex.getLoc();
  uint64_t Size = Lex.getAPSIntVal().getZExtValue();
  Lex.Lex();

  if (ParseToken(lltok::kw_x, "expected 'x' after element count"))
      return true;

  LocTy TypeLoc = Lex.getLoc();
  PATypeHolder EltTy(Type::getVoidTy(Context));
  if (ParseTypeRec(EltTy)) return true;

  if (EltTy->isVoidTy())
    return Error(TypeLoc, "array and vector element type cannot be void");

  if (ParseToken(isVector ? lltok::greater : lltok::rsquare,
                 "expected end of sequential type"))
    return true;

  if (isVector) {
    if (Size == 0)
      return Error(SizeLoc, "zero element vector is illegal");
    if ((unsigned)Size != Size)
      return Error(SizeLoc, "size too large for vector");
    if (!VectorType::isValidElementType(EltTy))
      return Error(TypeLoc, "vector element type must be fp or integer");
    Result = VectorType::get(EltTy, unsigned(Size));
  } else {
    if (!ArrayType::isValidElementType(EltTy))
      return Error(TypeLoc, "invalid array element type");
    Result = HandleUpRefs(ArrayType::get(EltTy, Size));
  }
  return false;
}

//===----------------------------------------------------------------------===//
// Function Semantic Analysis.
//===----------------------------------------------------------------------===//

LLParser::PerFunctionState::PerFunctionState(LLParser &p, Function &f,
                                             int functionNumber)
  : P(p), F(f), FunctionNumber(functionNumber) {

  // Insert unnamed arguments into the NumberedVals list.
  for (Function::arg_iterator AI = F.arg_begin(), E = F.arg_end();
       AI != E; ++AI)
    if (!AI->hasName())
      NumberedVals.push_back(AI);
}

LLParser::PerFunctionState::~PerFunctionState() {
  // If there were any forward referenced non-basicblock values, delete them.
  for (std::map<std::string, std::pair<Value*, LocTy> >::iterator
       I = ForwardRefVals.begin(), E = ForwardRefVals.end(); I != E; ++I)
    if (!isa<BasicBlock>(I->second.first)) {
      I->second.first->replaceAllUsesWith(
                           UndefValue::get(I->second.first->getType()));
      delete I->second.first;
      I->second.first = 0;
    }

  for (std::map<unsigned, std::pair<Value*, LocTy> >::iterator
       I = ForwardRefValIDs.begin(), E = ForwardRefValIDs.end(); I != E; ++I)
    if (!isa<BasicBlock>(I->second.first)) {
      I->second.first->replaceAllUsesWith(
                           UndefValue::get(I->second.first->getType()));
      delete I->second.first;
      I->second.first = 0;
    }
}

bool LLParser::PerFunctionState::FinishFunction() {
  // Check to see if someone took the address of labels in this block.
  if (!P.ForwardRefBlockAddresses.empty()) {
    ValID FunctionID;
    if (!F.getName().empty()) {
      FunctionID.Kind = ValID::t_GlobalName;
      FunctionID.StrVal = F.getName();
    } else {
      FunctionID.Kind = ValID::t_GlobalID;
      FunctionID.UIntVal = FunctionNumber;
    }
  
    std::map<ValID, std::vector<std::pair<ValID, GlobalValue*> > >::iterator
      FRBAI = P.ForwardRefBlockAddresses.find(FunctionID);
    if (FRBAI != P.ForwardRefBlockAddresses.end()) {
      // Resolve all these references.
      if (P.ResolveForwardRefBlockAddresses(&F, FRBAI->second, this))
        return true;
      
      P.ForwardRefBlockAddresses.erase(FRBAI);
    }
  }
  
  if (!ForwardRefVals.empty())
    return P.Error(ForwardRefVals.begin()->second.second,
                   "use of undefined value '%" + ForwardRefVals.begin()->first +
                   "'");
  if (!ForwardRefValIDs.empty())
    return P.Error(ForwardRefValIDs.begin()->second.second,
                   "use of undefined value '%" +
                   utostr(ForwardRefValIDs.begin()->first) + "'");
  return false;
}


/// GetVal - Get a value with the specified name or ID, creating a
/// forward reference record if needed.  This can return null if the value
/// exists but does not have the right type.
Value *LLParser::PerFunctionState::GetVal(const std::string &Name,
                                          const Type *Ty, LocTy Loc) {
  // Look this name up in the normal function symbol table.
  Value *Val = F.getValueSymbolTable().lookup(Name);

  // If this is a forward reference for the value, see if we already created a
  // forward ref record.
  if (Val == 0) {
    std::map<std::string, std::pair<Value*, LocTy> >::iterator
      I = ForwardRefVals.find(Name);
    if (I != ForwardRefVals.end())
      Val = I->second.first;
  }

  // If we have the value in the symbol table or fwd-ref table, return it.
  if (Val) {
    if (Val->getType() == Ty) return Val;
    if (Ty->isLabelTy())
      P.Error(Loc, "'%" + Name + "' is not a basic block");
    else
      P.Error(Loc, "'%" + Name + "' defined with type '" +
              Val->getType()->getDescription() + "'");
    return 0;
  }

  // Don't make placeholders with invalid type.
  if (!Ty->isFirstClassType() && !isa<OpaqueType>(Ty) &&
      Ty != Type::getLabelTy(F.getContext())) {
    P.Error(Loc, "invalid use of a non-first-class type");
    return 0;
  }

  // Otherwise, create a new forward reference for this value and remember it.
  Value *FwdVal;
  if (Ty->isLabelTy())
    FwdVal = BasicBlock::Create(F.getContext(), Name, &F);
  else
    FwdVal = new Argument(Ty, Name);

  ForwardRefVals[Name] = std::make_pair(FwdVal, Loc);
  return FwdVal;
}

Value *LLParser::PerFunctionState::GetVal(unsigned ID, const Type *Ty,
                                          LocTy Loc) {
  // Look this name up in the normal function symbol table.
  Value *Val = ID < NumberedVals.size() ? NumberedVals[ID] : 0;

  // If this is a forward reference for the value, see if we already created a
  // forward ref record.
  if (Val == 0) {
    std::map<unsigned, std::pair<Value*, LocTy> >::iterator
      I = ForwardRefValIDs.find(ID);
    if (I != ForwardRefValIDs.end())
      Val = I->second.first;
  }

  // If we have the value in the symbol table or fwd-ref table, return it.
  if (Val) {
    if (Val->getType() == Ty) return Val;
    if (Ty->isLabelTy())
      P.Error(Loc, "'%" + utostr(ID) + "' is not a basic block");
    else
      P.Error(Loc, "'%" + utostr(ID) + "' defined with type '" +
              Val->getType()->getDescription() + "'");
    return 0;
  }

  if (!Ty->isFirstClassType() && !isa<OpaqueType>(Ty) &&
      Ty != Type::getLabelTy(F.getContext())) {
    P.Error(Loc, "invalid use of a non-first-class type");
    return 0;
  }

  // Otherwise, create a new forward reference for this value and remember it.
  Value *FwdVal;
  if (Ty->isLabelTy())
    FwdVal = BasicBlock::Create(F.getContext(), "", &F);
  else
    FwdVal = new Argument(Ty);

  ForwardRefValIDs[ID] = std::make_pair(FwdVal, Loc);
  return FwdVal;
}

/// SetInstName - After an instruction is parsed and inserted into its
/// basic block, this installs its name.
bool LLParser::PerFunctionState::SetInstName(int NameID,
                                             const std::string &NameStr,
                                             LocTy NameLoc, Instruction *Inst) {
  // If this instruction has void type, it cannot have a name or ID specified.
  if (Inst->getType()->isVoidTy()) {
    if (NameID != -1 || !NameStr.empty())
      return P.Error(NameLoc, "instructions returning void cannot have a name");
    return false;
  }

  // If this was a numbered instruction, verify that the instruction is the
  // expected value and resolve any forward references.
  if (NameStr.empty()) {
    // If neither a name nor an ID was specified, just use the next ID.
    if (NameID == -1)
      NameID = NumberedVals.size();

    if (unsigned(NameID) != NumberedVals.size())
      return P.Error(NameLoc, "instruction expected to be numbered '%" +
                     utostr(NumberedVals.size()) + "'");

    std::map<unsigned, std::pair<Value*, LocTy> >::iterator FI =
      ForwardRefValIDs.find(NameID);
    if (FI != ForwardRefValIDs.end()) {
      if (FI->second.first->getType() != Inst->getType())
        return P.Error(NameLoc, "instruction forward referenced with type '" +
                       FI->second.first->getType()->getDescription() + "'");
      FI->second.first->replaceAllUsesWith(Inst);
      delete FI->second.first;
      ForwardRefValIDs.erase(FI);
    }

    NumberedVals.push_back(Inst);
    return false;
  }

  // Otherwise, the instruction had a name.  Resolve forward refs and set it.
  std::map<std::string, std::pair<Value*, LocTy> >::iterator
    FI = ForwardRefVals.find(NameStr);
  if (FI != ForwardRefVals.end()) {
    if (FI->second.first->getType() != Inst->getType())
      return P.Error(NameLoc, "instruction forward referenced with type '" +
                     FI->second.first->getType()->getDescription() + "'");
    FI->second.first->replaceAllUsesWith(Inst);
    delete FI->second.first;
    ForwardRefVals.erase(FI);
  }

  // Set the name on the instruction.
  Inst->setName(NameStr);

  if (Inst->getNameStr() != NameStr)
    return P.Error(NameLoc, "multiple definition of local value named '" +
                   NameStr + "'");
  return false;
}

/// GetBB - Get a basic block with the specified name or ID, creating a
/// forward reference record if needed.
BasicBlock *LLParser::PerFunctionState::GetBB(const std::string &Name,
                                              LocTy Loc) {
  return cast_or_null<BasicBlock>(GetVal(Name,
                                        Type::getLabelTy(F.getContext()), Loc));
}

BasicBlock *LLParser::PerFunctionState::GetBB(unsigned ID, LocTy Loc) {
  return cast_or_null<BasicBlock>(GetVal(ID,
                                        Type::getLabelTy(F.getContext()), Loc));
}

/// DefineBB - Define the specified basic block, which is either named or
/// unnamed.  If there is an error, this returns null otherwise it returns
/// the block being defined.
BasicBlock *LLParser::PerFunctionState::DefineBB(const std::string &Name,
                                                 LocTy Loc) {
  BasicBlock *BB;
  if (Name.empty())
    BB = GetBB(NumberedVals.size(), Loc);
  else
    BB = GetBB(Name, Loc);
  if (BB == 0) return 0; // Already diagnosed error.

  // Move the block to the end of the function.  Forward ref'd blocks are
  // inserted wherever they happen to be referenced.
  F.getBasicBlockList().splice(F.end(), F.getBasicBlockList(), BB);

  // Remove the block from forward ref sets.
  if (Name.empty()) {
    ForwardRefValIDs.erase(NumberedVals.size());
    NumberedVals.push_back(BB);
  } else {
    // BB forward references are already in the function symbol table.
    ForwardRefVals.erase(Name);
  }

  return BB;
}

//===----------------------------------------------------------------------===//
// Constants.
//===----------------------------------------------------------------------===//

/// ParseValID - Parse an abstract value that doesn't necessarily have a
/// type implied.  For example, if we parse "4" we don't know what integer type
/// it has.  The value will later be combined with its type and checked for
/// sanity.
bool LLParser::ParseValID(ValID &ID) {
  ID.Loc = Lex.getLoc();
  switch (Lex.getKind()) {
  default: return TokError("expected value token");
  case lltok::GlobalID:  // @42
    ID.UIntVal = Lex.getUIntVal();
    ID.Kind = ValID::t_GlobalID;
    break;
  case lltok::GlobalVar:  // @foo
    ID.StrVal = Lex.getStrVal();
    ID.Kind = ValID::t_GlobalName;
    break;
  case lltok::LocalVarID:  // %42
    ID.UIntVal = Lex.getUIntVal();
    ID.Kind = ValID::t_LocalID;
    break;
  case lltok::LocalVar:  // %foo
  case lltok::StringConstant:  // "foo" - FIXME: REMOVE IN LLVM 3.0
    ID.StrVal = Lex.getStrVal();
    ID.Kind = ValID::t_LocalName;
    break;
  case lltok::exclaim:   // !{...} MDNode, !"foo" MDString
    Lex.Lex();
    
    // FIXME: This doesn't belong here.
    if (EatIfPresent(lltok::lbrace)) {
      SmallVector<Value*, 16> Elts;
      if (ParseMDNodeVector(Elts) ||
          ParseToken(lltok::rbrace, "expected end of metadata node"))
        return true;

      ID.MDNodeVal = MDNode::get(Context, Elts.data(), Elts.size());
      ID.Kind = ValID::t_MDNode;
      return false;
    }

    // Standalone metadata reference
    // !{ ..., !42, ... }
    if (Lex.getKind() == lltok::APSInt) {
      if (ParseMDNodeID(ID.MDNodeVal)) return true;
      ID.Kind = ValID::t_MDNode;
      return false;
    }
    
    // MDString:
    //   ::= '!' STRINGCONSTANT
    if (ParseMDString(ID.MDStringVal)) return true;
    ID.Kind = ValID::t_MDString;
    return false;
  case lltok::APSInt:
    ID.APSIntVal = Lex.getAPSIntVal();
    ID.Kind = ValID::t_APSInt;
    break;
  case lltok::APFloat:
    ID.APFloatVal = Lex.getAPFloatVal();
    ID.Kind = ValID::t_APFloat;
    break;
  case lltok::kw_true:
    ID.ConstantVal = ConstantInt::getTrue(Context);
    ID.Kind = ValID::t_Constant;
    break;
  case lltok::kw_false:
    ID.ConstantVal = ConstantInt::getFalse(Context);
    ID.Kind = ValID::t_Constant;
    break;
  case lltok::kw_null: ID.Kind = ValID::t_Null; break;
  case lltok::kw_undef: ID.Kind = ValID::t_Undef; break;
  case lltok::kw_zeroinitializer: ID.Kind = ValID::t_Zero; break;

  case lltok::lbrace: {
    // ValID ::= '{' ConstVector '}'
    Lex.Lex();
    SmallVector<Constant*, 16> Elts;
    if (ParseGlobalValueVector(Elts) ||
        ParseToken(lltok::rbrace, "expected end of struct constant"))
      return true;

    ID.ConstantVal = ConstantStruct::get(Context, Elts.data(),
                                         Elts.size(), false);
    ID.Kind = ValID::t_Constant;
    return false;
  }
  case lltok::less: {
    // ValID ::= '<' ConstVector '>'         --> Vector.
    // ValID ::= '<' '{' ConstVector '}' '>' --> Packed Struct.
    Lex.Lex();
    bool isPackedStruct = EatIfPresent(lltok::lbrace);

    SmallVector<Constant*, 16> Elts;
    LocTy FirstEltLoc = Lex.getLoc();
    if (ParseGlobalValueVector(Elts) ||
        (isPackedStruct &&
         ParseToken(lltok::rbrace, "expected end of packed struct")) ||
        ParseToken(lltok::greater, "expected end of constant"))
      return true;

    if (isPackedStruct) {
      ID.ConstantVal =
        ConstantStruct::get(Context, Elts.data(), Elts.size(), true);
      ID.Kind = ValID::t_Constant;
      return false;
    }

    if (Elts.empty())
      return Error(ID.Loc, "constant vector must not be empty");

    if (!Elts[0]->getType()->isInteger() &&
        !Elts[0]->getType()->isFloatingPoint())
      return Error(FirstEltLoc,
                   "vector elements must have integer or floating point type");

    // Verify that all the vector elements have the same type.
    for (unsigned i = 1, e = Elts.size(); i != e; ++i)
      if (Elts[i]->getType() != Elts[0]->getType())
        return Error(FirstEltLoc,
                     "vector element #" + utostr(i) +
                    " is not of type '" + Elts[0]->getType()->getDescription());

    ID.ConstantVal = ConstantVector::get(Elts.data(), Elts.size());
    ID.Kind = ValID::t_Constant;
    return false;
  }
  case lltok::lsquare: {   // Array Constant
    Lex.Lex();
    SmallVector<Constant*, 16> Elts;
    LocTy FirstEltLoc = Lex.getLoc();
    if (ParseGlobalValueVector(Elts) ||
        ParseToken(lltok::rsquare, "expected end of array constant"))
      return true;

    // Handle empty element.
    if (Elts.empty()) {
      // Use undef instead of an array because it's inconvenient to determine
      // the element type at this point, there being no elements to examine.
      ID.Kind = ValID::t_EmptyArray;
      return false;
    }

    if (!Elts[0]->getType()->isFirstClassType())
      return Error(FirstEltLoc, "invalid array element type: " +
                   Elts[0]->getType()->getDescription());

    ArrayType *ATy = ArrayType::get(Elts[0]->getType(), Elts.size());

    // Verify all elements are correct type!
    for (unsigned i = 0, e = Elts.size(); i != e; ++i) {
      if (Elts[i]->getType() != Elts[0]->getType())
        return Error(FirstEltLoc,
                     "array element #" + utostr(i) +
                     " is not of type '" +Elts[0]->getType()->getDescription());
    }

    ID.ConstantVal = ConstantArray::get(ATy, Elts.data(), Elts.size());
    ID.Kind = ValID::t_Constant;
    return false;
  }
  case lltok::kw_c:  // c "foo"
    Lex.Lex();
    ID.ConstantVal = ConstantArray::get(Context, Lex.getStrVal(), false);
    if (ParseToken(lltok::StringConstant, "expected string")) return true;
    ID.Kind = ValID::t_Constant;
    return false;

  case lltok::kw_asm: {
    // ValID ::= 'asm' SideEffect? AlignStack? STRINGCONSTANT ',' STRINGCONSTANT
    bool HasSideEffect, AlignStack;
    Lex.Lex();
    if (ParseOptionalToken(lltok::kw_sideeffect, HasSideEffect) ||
        ParseOptionalToken(lltok::kw_alignstack, AlignStack) ||
        ParseStringConstant(ID.StrVal) ||
        ParseToken(lltok::comma, "expected comma in inline asm expression") ||
        ParseToken(lltok::StringConstant, "expected constraint string"))
      return true;
    ID.StrVal2 = Lex.getStrVal();
    ID.UIntVal = unsigned(HasSideEffect) | (unsigned(AlignStack)<<1);
    ID.Kind = ValID::t_InlineAsm;
    return false;
  }

  case lltok::kw_blockaddress: {
    // ValID ::= 'blockaddress' '(' @foo ',' %bar ')'
    Lex.Lex();

    ValID Fn, Label;
    LocTy FnLoc, LabelLoc;
    
    if (ParseToken(lltok::lparen, "expected '(' in block address expression") ||
        ParseValID(Fn) ||
        ParseToken(lltok::comma, "expected comma in block address expression")||
        ParseValID(Label) ||
        ParseToken(lltok::rparen, "expected ')' in block address expression"))
      return true;
    
    if (Fn.Kind != ValID::t_GlobalID && Fn.Kind != ValID::t_GlobalName)
      return Error(Fn.Loc, "expected function name in blockaddress");
    if (Label.Kind != ValID::t_LocalID && Label.Kind != ValID::t_LocalName)
      return Error(Label.Loc, "expected basic block name in blockaddress");
    
    // Make a global variable as a placeholder for this reference.
    GlobalVariable *FwdRef = new GlobalVariable(*M, Type::getInt8Ty(Context),
                                           false, GlobalValue::InternalLinkage,
                                                0, "");
    ForwardRefBlockAddresses[Fn].push_back(std::make_pair(Label, FwdRef));
    ID.ConstantVal = FwdRef;
    ID.Kind = ValID::t_Constant;
    return false;
  }
      
  case lltok::kw_trunc:
  case lltok::kw_zext:
  case lltok::kw_sext:
  case lltok::kw_fptrunc:
  case lltok::kw_fpext:
  case lltok::kw_bitcast:
  case lltok::kw_uitofp:
  case lltok::kw_sitofp:
  case lltok::kw_fptoui:
  case lltok::kw_fptosi:
  case lltok::kw_inttoptr:
  case lltok::kw_ptrtoint: {
    unsigned Opc = Lex.getUIntVal();
    PATypeHolder DestTy(Type::getVoidTy(Context));
    Constant *SrcVal;
    Lex.Lex();
    if (ParseToken(lltok::lparen, "expected '(' after constantexpr cast") ||
        ParseGlobalTypeAndValue(SrcVal) ||
        ParseToken(lltok::kw_to, "expected 'to' in constantexpr cast") ||
        ParseType(DestTy) ||
        ParseToken(lltok::rparen, "expected ')' at end of constantexpr cast"))
      return true;
    if (!CastInst::castIsValid((Instruction::CastOps)Opc, SrcVal, DestTy))
      return Error(ID.Loc, "invalid cast opcode for cast from '" +
                   SrcVal->getType()->getDescription() + "' to '" +
                   DestTy->getDescription() + "'");
    ID.ConstantVal = ConstantExpr::getCast((Instruction::CastOps)Opc,
                                                 SrcVal, DestTy);
    ID.Kind = ValID::t_Constant;
    return false;
  }
  case lltok::kw_extractvalue: {
    Lex.Lex();
    Constant *Val;
    SmallVector<unsigned, 4> Indices;
    if (ParseToken(lltok::lparen, "expected '(' in extractvalue constantexpr")||
        ParseGlobalTypeAndValue(Val) ||
        ParseIndexList(Indices) ||
        ParseToken(lltok::rparen, "expected ')' in extractvalue constantexpr"))
      return true;

    if (!isa<StructType>(Val->getType()) && !isa<ArrayType>(Val->getType()))
      return Error(ID.Loc, "extractvalue operand must be array or struct");
    if (!ExtractValueInst::getIndexedType(Val->getType(), Indices.begin(),
                                          Indices.end()))
      return Error(ID.Loc, "invalid indices for extractvalue");
    ID.ConstantVal =
      ConstantExpr::getExtractValue(Val, Indices.data(), Indices.size());
    ID.Kind = ValID::t_Constant;
    return false;
  }
  case lltok::kw_insertvalue: {
    Lex.Lex();
    Constant *Val0, *Val1;
    SmallVector<unsigned, 4> Indices;
    if (ParseToken(lltok::lparen, "expected '(' in insertvalue constantexpr")||
        ParseGlobalTypeAndValue(Val0) ||
        ParseToken(lltok::comma, "expected comma in insertvalue constantexpr")||
        ParseGlobalTypeAndValue(Val1) ||
        ParseIndexList(Indices) ||
        ParseToken(lltok::rparen, "expected ')' in insertvalue constantexpr"))
      return true;
    if (!isa<StructType>(Val0->getType()) && !isa<ArrayType>(Val0->getType()))
      return Error(ID.Loc, "extractvalue operand must be array or struct");
    if (!ExtractValueInst::getIndexedType(Val0->getType(), Indices.begin(),
                                          Indices.end()))
      return Error(ID.Loc, "invalid indices for insertvalue");
    ID.ConstantVal = ConstantExpr::getInsertValue(Val0, Val1,
                       Indices.data(), Indices.size());
    ID.Kind = ValID::t_Constant;
    return false;
  }
  case lltok::kw_icmp:
  case lltok::kw_fcmp: {
    unsigned PredVal, Opc = Lex.getUIntVal();
    Constant *Val0, *Val1;
    Lex.Lex();
    if (ParseCmpPredicate(PredVal, Opc) ||
        ParseToken(lltok::lparen, "expected '(' in compare constantexpr") ||
        ParseGlobalTypeAndValue(Val0) ||
        ParseToken(lltok::comma, "expected comma in compare constantexpr") ||
        ParseGlobalTypeAndValue(Val1) ||
        ParseToken(lltok::rparen, "expected ')' in compare constantexpr"))
      return true;

    if (Val0->getType() != Val1->getType())
      return Error(ID.Loc, "compare operands must have the same type");

    CmpInst::Predicate Pred = (CmpInst::Predicate)PredVal;

    if (Opc == Instruction::FCmp) {
      if (!Val0->getType()->isFPOrFPVector())
        return Error(ID.Loc, "fcmp requires floating point operands");
      ID.ConstantVal = ConstantExpr::getFCmp(Pred, Val0, Val1);
    } else {
      assert(Opc == Instruction::ICmp && "Unexpected opcode for CmpInst!");
      if (!Val0->getType()->isIntOrIntVector() &&
          !isa<PointerType>(Val0->getType()))
        return Error(ID.Loc, "icmp requires pointer or integer operands");
      ID.ConstantVal = ConstantExpr::getICmp(Pred, Val0, Val1);
    }
    ID.Kind = ValID::t_Constant;
    return false;
  }

  // Binary Operators.
  case lltok::kw_add:
  case lltok::kw_fadd:
  case lltok::kw_sub:
  case lltok::kw_fsub:
  case lltok::kw_mul:
  case lltok::kw_fmul:
  case lltok::kw_udiv:
  case lltok::kw_sdiv:
  case lltok::kw_fdiv:
  case lltok::kw_urem:
  case lltok::kw_srem:
  case lltok::kw_frem: {
    bool NUW = false;
    bool NSW = false;
    bool Exact = false;
    unsigned Opc = Lex.getUIntVal();
    Constant *Val0, *Val1;
    Lex.Lex();
    LocTy ModifierLoc = Lex.getLoc();
    if (Opc == Instruction::Add ||
        Opc == Instruction::Sub ||
        Opc == Instruction::Mul) {
      if (EatIfPresent(lltok::kw_nuw))
        NUW = true;
      if (EatIfPresent(lltok::kw_nsw)) {
        NSW = true;
        if (EatIfPresent(lltok::kw_nuw))
          NUW = true;
      }
    } else if (Opc == Instruction::SDiv) {
      if (EatIfPresent(lltok::kw_exact))
        Exact = true;
    }
    if (ParseToken(lltok::lparen, "expected '(' in binary constantexpr") ||
        ParseGlobalTypeAndValue(Val0) ||
        ParseToken(lltok::comma, "expected comma in binary constantexpr") ||
        ParseGlobalTypeAndValue(Val1) ||
        ParseToken(lltok::rparen, "expected ')' in binary constantexpr"))
      return true;
    if (Val0->getType() != Val1->getType())
      return Error(ID.Loc, "operands of constexpr must have same type");
    if (!Val0->getType()->isIntOrIntVector()) {
      if (NUW)
        return Error(ModifierLoc, "nuw only applies to integer operations");
      if (NSW)
        return Error(ModifierLoc, "nsw only applies to integer operations");
    }
    // API compatibility: Accept either integer or floating-point types with
    // add, sub, and mul.
    if (!Val0->getType()->isIntOrIntVector() &&
        !Val0->getType()->isFPOrFPVector())
      return Error(ID.Loc,"constexpr requires integer, fp, or vector operands");
    unsigned Flags = 0;
    if (NUW)   Flags |= OverflowingBinaryOperator::NoUnsignedWrap;
    if (NSW)   Flags |= OverflowingBinaryOperator::NoSignedWrap;
    if (Exact) Flags |= SDivOperator::IsExact;
    Constant *C = ConstantExpr::get(Opc, Val0, Val1, Flags);
    ID.ConstantVal = C;
    ID.Kind = ValID::t_Constant;
    return false;
  }

  // Logical Operations
  case lltok::kw_shl:
  case lltok::kw_lshr:
  case lltok::kw_ashr:
  case lltok::kw_and:
  case lltok::kw_or:
  case lltok::kw_xor: {
    unsigned Opc = Lex.getUIntVal();
    Constant *Val0, *Val1;
    Lex.Lex();
    if (ParseToken(lltok::lparen, "expected '(' in logical constantexpr") ||
        ParseGlobalTypeAndValue(Val0) ||
        ParseToken(lltok::comma, "expected comma in logical constantexpr") ||
        ParseGlobalTypeAndValue(Val1) ||
        ParseToken(lltok::rparen, "expected ')' in logical constantexpr"))
      return true;
    if (Val0->getType() != Val1->getType())
      return Error(ID.Loc, "operands of constexpr must have same type");
    if (!Val0->getType()->isIntOrIntVector())
      return Error(ID.Loc,
                   "constexpr requires integer or integer vector operands");
    ID.ConstantVal = ConstantExpr::get(Opc, Val0, Val1);
    ID.Kind = ValID::t_Constant;
    return false;
  }

  case lltok::kw_getelementptr:
  case lltok::kw_shufflevector:
  case lltok::kw_insertelement:
  case lltok::kw_extractelement:
  case lltok::kw_select: {
    unsigned Opc = Lex.getUIntVal();
    SmallVector<Constant*, 16> Elts;
    bool InBounds = false;
    Lex.Lex();
    if (Opc == Instruction::GetElementPtr)
      InBounds = EatIfPresent(lltok::kw_inbounds);
    if (ParseToken(lltok::lparen, "expected '(' in constantexpr") ||
        ParseGlobalValueVector(Elts) ||
        ParseToken(lltok::rparen, "expected ')' in constantexpr"))
      return true;

    if (Opc == Instruction::GetElementPtr) {
      if (Elts.size() == 0 || !isa<PointerType>(Elts[0]->getType()))
        return Error(ID.Loc, "getelementptr requires pointer operand");

      if (!GetElementPtrInst::getIndexedType(Elts[0]->getType(),
                                             (Value**)(Elts.data() + 1),
                                             Elts.size() - 1))
        return Error(ID.Loc, "invalid indices for getelementptr");
      ID.ConstantVal = InBounds ?
        ConstantExpr::getInBoundsGetElementPtr(Elts[0],
                                               Elts.data() + 1,
                                               Elts.size() - 1) :
        ConstantExpr::getGetElementPtr(Elts[0],
                                       Elts.data() + 1, Elts.size() - 1);
    } else if (Opc == Instruction::Select) {
      if (Elts.size() != 3)
        return Error(ID.Loc, "expected three operands to select");
      if (const char *Reason = SelectInst::areInvalidOperands(Elts[0], Elts[1],
                                                              Elts[2]))
        return Error(ID.Loc, Reason);
      ID.ConstantVal = ConstantExpr::getSelect(Elts[0], Elts[1], Elts[2]);
    } else if (Opc == Instruction::ShuffleVector) {
      if (Elts.size() != 3)
        return Error(ID.Loc, "expected three operands to shufflevector");
      if (!ShuffleVectorInst::isValidOperands(Elts[0], Elts[1], Elts[2]))
        return Error(ID.Loc, "invalid operands to shufflevector");
      ID.ConstantVal =
                 ConstantExpr::getShuffleVector(Elts[0], Elts[1],Elts[2]);
    } else if (Opc == Instruction::ExtractElement) {
      if (Elts.size() != 2)
        return Error(ID.Loc, "expected two operands to extractelement");
      if (!ExtractElementInst::isValidOperands(Elts[0], Elts[1]))
        return Error(ID.Loc, "invalid extractelement operands");
      ID.ConstantVal = ConstantExpr::getExtractElement(Elts[0], Elts[1]);
    } else {
      assert(Opc == Instruction::InsertElement && "Unknown opcode");
      if (Elts.size() != 3)
      return Error(ID.Loc, "expected three operands to insertelement");
      if (!InsertElementInst::isValidOperands(Elts[0], Elts[1], Elts[2]))
        return Error(ID.Loc, "invalid insertelement operands");
      ID.ConstantVal =
                 ConstantExpr::getInsertElement(Elts[0], Elts[1],Elts[2]);
    }

    ID.Kind = ValID::t_Constant;
    return false;
  }
  }

  Lex.Lex();
  return false;
}

/// ParseGlobalValue - Parse a global value with the specified type.
bool LLParser::ParseGlobalValue(const Type *Ty, Constant *&V) {
  V = 0;
  ValID ID;
  return ParseValID(ID) ||
         ConvertGlobalValIDToValue(Ty, ID, V);
}

/// ConvertGlobalValIDToValue - Apply a type to a ValID to get a fully resolved
/// constant.
bool LLParser::ConvertGlobalValIDToValue(const Type *Ty, ValID &ID,
                                         Constant *&V) {
  if (isa<FunctionType>(Ty))
    return Error(ID.Loc, "functions are not values, refer to them as pointers");

  switch (ID.Kind) {
  default: llvm_unreachable("Unknown ValID!");
  case ValID::t_MDNode:
  case ValID::t_MDString:
    return Error(ID.Loc, "invalid use of metadata");
  case ValID::t_LocalID:
  case ValID::t_LocalName:
    return Error(ID.Loc, "invalid use of function-local name");
  case ValID::t_InlineAsm:
    return Error(ID.Loc, "inline asm can only be an operand of call/invoke");
  case ValID::t_GlobalName:
    V = GetGlobalVal(ID.StrVal, Ty, ID.Loc);
    return V == 0;
  case ValID::t_GlobalID:
    V = GetGlobalVal(ID.UIntVal, Ty, ID.Loc);
    return V == 0;
  case ValID::t_APSInt:
    if (!isa<IntegerType>(Ty))
      return Error(ID.Loc, "integer constant must have integer type");
    ID.APSIntVal.extOrTrunc(Ty->getPrimitiveSizeInBits());
    V = ConstantInt::get(Context, ID.APSIntVal);
    return false;
  case ValID::t_APFloat:
    if (!Ty->isFloatingPoint() ||
        !ConstantFP::isValueValidForType(Ty, ID.APFloatVal))
      return Error(ID.Loc, "floating point constant invalid for type");

    // The lexer has no type info, so builds all float and double FP constants
    // as double.  Fix this here.  Long double does not need this.
    if (&ID.APFloatVal.getSemantics() == &APFloat::IEEEdouble &&
        Ty->isFloatTy()) {
      bool Ignored;
      ID.APFloatVal.convert(APFloat::IEEEsingle, APFloat::rmNearestTiesToEven,
                            &Ignored);
    }
    V = ConstantFP::get(Context, ID.APFloatVal);

    if (V->getType() != Ty)
      return Error(ID.Loc, "floating point constant does not have type '" +
                   Ty->getDescription() + "'");

    return false;
  case ValID::t_Null:
    if (!isa<PointerType>(Ty))
      return Error(ID.Loc, "null must be a pointer type");
    V = ConstantPointerNull::get(cast<PointerType>(Ty));
    return false;
  case ValID::t_Undef:
    // FIXME: LabelTy should not be a first-class type.
    if ((!Ty->isFirstClassType() || Ty->isLabelTy()) &&
        !isa<OpaqueType>(Ty))
      return Error(ID.Loc, "invalid type for undef constant");
    V = UndefValue::get(Ty);
    return false;
  case ValID::t_EmptyArray:
    if (!isa<ArrayType>(Ty) || cast<ArrayType>(Ty)->getNumElements() != 0)
      return Error(ID.Loc, "invalid empty array initializer");
    V = UndefValue::get(Ty);
    return false;
  case ValID::t_Zero:
    // FIXME: LabelTy should not be a first-class type.
    if (!Ty->isFirstClassType() || Ty->isLabelTy())
      return Error(ID.Loc, "invalid type for null constant");
    V = Constant::getNullValue(Ty);
    return false;
  case ValID::t_Constant:
    if (ID.ConstantVal->getType() != Ty)
      return Error(ID.Loc, "constant expression type mismatch");
    V = ID.ConstantVal;
    return false;
  }
}

/// ConvertGlobalOrMetadataValIDToValue - Apply a type to a ValID to get a fully
/// resolved constant or metadata value.
bool LLParser::ConvertGlobalOrMetadataValIDToValue(const Type *Ty, ValID &ID,
                                                   Value *&V) {
  switch (ID.Kind) {
  case ValID::t_MDNode:
    if (!Ty->isMetadataTy())
      return Error(ID.Loc, "metadata value must have metadata type");
    V = ID.MDNodeVal;
    return false;
  case ValID::t_MDString:
    if (!Ty->isMetadataTy())
      return Error(ID.Loc, "metadata value must have metadata type");
    V = ID.MDStringVal;
    return false;
  default:
    Constant *C;
    if (ConvertGlobalValIDToValue(Ty, ID, C)) return true;
    V = C;
    return false;
  }
}
  

bool LLParser::ParseGlobalTypeAndValue(Constant *&V) {
  PATypeHolder Type(Type::getVoidTy(Context));
  return ParseType(Type) ||
         ParseGlobalValue(Type, V);
}

/// ParseGlobalValueVector
///   ::= /*empty*/
///   ::= TypeAndValue (',' TypeAndValue)*
bool LLParser::ParseGlobalValueVector(SmallVectorImpl<Constant*> &Elts) {
  // Empty list.
  if (Lex.getKind() == lltok::rbrace ||
      Lex.getKind() == lltok::rsquare ||
      Lex.getKind() == lltok::greater ||
      Lex.getKind() == lltok::rparen)
    return false;

  Constant *C;
  if (ParseGlobalTypeAndValue(C)) return true;
  Elts.push_back(C);

  while (EatIfPresent(lltok::comma)) {
    if (ParseGlobalTypeAndValue(C)) return true;
    Elts.push_back(C);
  }

  return false;
}


//===----------------------------------------------------------------------===//
// Function Parsing.
//===----------------------------------------------------------------------===//

bool LLParser::ConvertValIDToValue(const Type *Ty, ValID &ID, Value *&V,
                                   PerFunctionState &PFS) {
  switch (ID.Kind) {
  case ValID::t_LocalID: V = PFS.GetVal(ID.UIntVal, Ty, ID.Loc); break;
  case ValID::t_LocalName: V = PFS.GetVal(ID.StrVal, Ty, ID.Loc); break;
  case ValID::t_InlineAsm: {
    const PointerType *PTy = dyn_cast<PointerType>(Ty);
    const FunctionType *FTy = 
      PTy ? dyn_cast<FunctionType>(PTy->getElementType()) : 0;
    if (!FTy || !InlineAsm::Verify(FTy, ID.StrVal2))
      return Error(ID.Loc, "invalid type for inline asm constraint string");
    V = InlineAsm::get(FTy, ID.StrVal, ID.StrVal2, ID.UIntVal&1, ID.UIntVal>>1);
    return false;
  }
  default:
    return ConvertGlobalOrMetadataValIDToValue(Ty, ID, V);
  }

  return V == 0;
}

bool LLParser::ParseValue(const Type *Ty, Value *&V, PerFunctionState &PFS) {
  V = 0;
  ValID ID;
  return ParseValID(ID) ||
         ConvertValIDToValue(Ty, ID, V, PFS);
}

bool LLParser::ParseTypeAndValue(Value *&V, PerFunctionState &PFS) {
  PATypeHolder T(Type::getVoidTy(Context));
  return ParseType(T) ||
         ParseValue(T, V, PFS);
}

bool LLParser::ParseTypeAndBasicBlock(BasicBlock *&BB, LocTy &Loc,
                                      PerFunctionState &PFS) {
  Value *V;
  Loc = Lex.getLoc();
  if (ParseTypeAndValue(V, PFS)) return true;
  if (!isa<BasicBlock>(V))
    return Error(Loc, "expected a basic block");
  BB = cast<BasicBlock>(V);
  return false;
}


/// FunctionHeader
///   ::= OptionalLinkage OptionalVisibility OptionalCallingConv OptRetAttrs
///       Type GlobalName '(' ArgList ')' OptFuncAttrs OptSection
///       OptionalAlign OptGC
bool LLParser::ParseFunctionHeader(Function *&Fn, bool isDefine) {
  // Parse the linkage.
  LocTy LinkageLoc = Lex.getLoc();
  unsigned Linkage;

  unsigned Visibility, RetAttrs;
  CallingConv::ID CC;
  PATypeHolder RetType(Type::getVoidTy(Context));
  LocTy RetTypeLoc = Lex.getLoc();
  if (ParseOptionalLinkage(Linkage) ||
      ParseOptionalVisibility(Visibility) ||
      ParseOptionalCallingConv(CC) ||
      ParseOptionalAttrs(RetAttrs, 1) ||
      ParseType(RetType, RetTypeLoc, true /*void allowed*/))
    return true;

  // Verify that the linkage is ok.
  switch ((GlobalValue::LinkageTypes)Linkage) {
  case GlobalValue::ExternalLinkage:
    break; // always ok.
  case GlobalValue::DLLImportLinkage:
  case GlobalValue::ExternalWeakLinkage:
    if (isDefine)
      return Error(LinkageLoc, "invalid linkage for function definition");
    break;
  case GlobalValue::PrivateLinkage:
  case GlobalValue::LinkerPrivateLinkage:
  case GlobalValue::InternalLinkage:
  case GlobalValue::AvailableExternallyLinkage:
  case GlobalValue::LinkOnceAnyLinkage:
  case GlobalValue::LinkOnceODRLinkage:
  case GlobalValue::WeakAnyLinkage:
  case GlobalValue::WeakODRLinkage:
  case GlobalValue::DLLExportLinkage:
    if (!isDefine)
      return Error(LinkageLoc, "invalid linkage for function declaration");
    break;
  case GlobalValue::AppendingLinkage:
  case GlobalValue::GhostLinkage:
  case GlobalValue::CommonLinkage:
    return Error(LinkageLoc, "invalid function linkage type");
  }

  if (!FunctionType::isValidReturnType(RetType) ||
      isa<OpaqueType>(RetType))
    return Error(RetTypeLoc, "invalid function return type");

  LocTy NameLoc = Lex.getLoc();

  std::string FunctionName;
  if (Lex.getKind() == lltok::GlobalVar) {
    FunctionName = Lex.getStrVal();
  } else if (Lex.getKind() == lltok::GlobalID) {     // @42 is ok.
    unsigned NameID = Lex.getUIntVal();

    if (NameID != NumberedVals.size())
      return TokError("function expected to be numbered '%" +
                      utostr(NumberedVals.size()) + "'");
  } else {
    return TokError("expected function name");
  }

  Lex.Lex();

  if (Lex.getKind() != lltok::lparen)
    return TokError("expected '(' in function argument list");

  std::vector<ArgInfo> ArgList;
  bool isVarArg;
  unsigned FuncAttrs;
  std::string Section;
  unsigned Alignment;
  std::string GC;

  if (ParseArgumentList(ArgList, isVarArg, false) ||
      ParseOptionalAttrs(FuncAttrs, 2) ||
      (EatIfPresent(lltok::kw_section) &&
       ParseStringConstant(Section)) ||
      ParseOptionalAlignment(Alignment) ||
      (EatIfPresent(lltok::kw_gc) &&
       ParseStringConstant(GC)))
    return true;

  // If the alignment was parsed as an attribute, move to the alignment field.
  if (FuncAttrs & Attribute::Alignment) {
    Alignment = Attribute::getAlignmentFromAttrs(FuncAttrs);
    FuncAttrs &= ~Attribute::Alignment;
  }

  // Okay, if we got here, the function is syntactically valid.  Convert types
  // and do semantic checks.
  std::vector<const Type*> ParamTypeList;
  SmallVector<AttributeWithIndex, 8> Attrs;
  // FIXME : In 3.0, stop accepting zext, sext and inreg as optional function
  // attributes.
  unsigned ObsoleteFuncAttrs = Attribute::ZExt|Attribute::SExt|Attribute::InReg;
  if (FuncAttrs & ObsoleteFuncAttrs) {
    RetAttrs |= FuncAttrs & ObsoleteFuncAttrs;
    FuncAttrs &= ~ObsoleteFuncAttrs;
  }

  if (RetAttrs != Attribute::None)
    Attrs.push_back(AttributeWithIndex::get(0, RetAttrs));

  for (unsigned i = 0, e = ArgList.size(); i != e; ++i) {
    ParamTypeList.push_back(ArgList[i].Type);
    if (ArgList[i].Attrs != Attribute::None)
      Attrs.push_back(AttributeWithIndex::get(i+1, ArgList[i].Attrs));
  }

  if (FuncAttrs != Attribute::None)
    Attrs.push_back(AttributeWithIndex::get(~0, FuncAttrs));

  AttrListPtr PAL = AttrListPtr::get(Attrs.begin(), Attrs.end());

  if (PAL.paramHasAttr(1, Attribute::StructRet) &&
      RetType != Type::getVoidTy(Context))
    return Error(RetTypeLoc, "functions with 'sret' argument must return void");

  const FunctionType *FT =
    FunctionType::get(RetType, ParamTypeList, isVarArg);
  const PointerType *PFT = PointerType::getUnqual(FT);

  Fn = 0;
  if (!FunctionName.empty()) {
    // If this was a definition of a forward reference, remove the definition
    // from the forward reference table and fill in the forward ref.
    std::map<std::string, std::pair<GlobalValue*, LocTy> >::iterator FRVI =
      ForwardRefVals.find(FunctionName);
    if (FRVI != ForwardRefVals.end()) {
      Fn = M->getFunction(FunctionName);
      ForwardRefVals.erase(FRVI);
    } else if ((Fn = M->getFunction(FunctionName))) {
      // If this function already exists in the symbol table, then it is
      // multiply defined.  We accept a few cases for old backwards compat.
      // FIXME: Remove this stuff for LLVM 3.0.
      if (Fn->getType() != PFT || Fn->getAttributes() != PAL ||
          (!Fn->isDeclaration() && isDefine)) {
        // If the redefinition has different type or different attributes,
        // reject it.  If both have bodies, reject it.
        return Error(NameLoc, "invalid redefinition of function '" +
                     FunctionName + "'");
      } else if (Fn->isDeclaration()) {
        // Make sure to strip off any argument names so we can't get conflicts.
        for (Function::arg_iterator AI = Fn->arg_begin(), AE = Fn->arg_end();
             AI != AE; ++AI)
          AI->setName("");
      }
    } else if (M->getNamedValue(FunctionName)) {
      return Error(NameLoc, "redefinition of function '@" + FunctionName + "'");
    }

  } else {
    // If this is a definition of a forward referenced function, make sure the
    // types agree.
    std::map<unsigned, std::pair<GlobalValue*, LocTy> >::iterator I
      = ForwardRefValIDs.find(NumberedVals.size());
    if (I != ForwardRefValIDs.end()) {
      Fn = cast<Function>(I->second.first);
      if (Fn->getType() != PFT)
        return Error(NameLoc, "type of definition and forward reference of '@" +
                     utostr(NumberedVals.size()) +"' disagree");
      ForwardRefValIDs.erase(I);
    }
  }

  if (Fn == 0)
    Fn = Function::Create(FT, GlobalValue::ExternalLinkage, FunctionName, M);
  else // Move the forward-reference to the correct spot in the module.
    M->getFunctionList().splice(M->end(), M->getFunctionList(), Fn);

  if (FunctionName.empty())
    NumberedVals.push_back(Fn);

  Fn->setLinkage((GlobalValue::LinkageTypes)Linkage);
  Fn->setVisibility((GlobalValue::VisibilityTypes)Visibility);
  Fn->setCallingConv(CC);
  Fn->setAttributes(PAL);
  Fn->setAlignment(Alignment);
  Fn->setSection(Section);
  if (!GC.empty()) Fn->setGC(GC.c_str());

  // Add all of the arguments we parsed to the function.
  Function::arg_iterator ArgIt = Fn->arg_begin();
  for (unsigned i = 0, e = ArgList.size(); i != e; ++i, ++ArgIt) {
    // If we run out of arguments in the Function prototype, exit early.
    // FIXME: REMOVE THIS IN LLVM 3.0, this is just for the mismatch case above.
    if (ArgIt == Fn->arg_end()) break;
    
    // If the argument has a name, insert it into the argument symbol table.
    if (ArgList[i].Name.empty()) continue;

    // Set the name, if it conflicted, it will be auto-renamed.
    ArgIt->setName(ArgList[i].Name);

    if (ArgIt->getNameStr() != ArgList[i].Name)
      return Error(ArgList[i].Loc, "redefinition of argument '%" +
                   ArgList[i].Name + "'");
  }

  return false;
}


/// ParseFunctionBody
///   ::= '{' BasicBlock+ '}'
///   ::= 'begin' BasicBlock+ 'end'  // FIXME: remove in LLVM 3.0
///
bool LLParser::ParseFunctionBody(Function &Fn) {
  if (Lex.getKind() != lltok::lbrace && Lex.getKind() != lltok::kw_begin)
    return TokError("expected '{' in function body");
  Lex.Lex();  // eat the {.

  int FunctionNumber = -1;
  if (!Fn.hasName()) FunctionNumber = NumberedVals.size()-1;
  
  PerFunctionState PFS(*this, Fn, FunctionNumber);

  while (Lex.getKind() != lltok::rbrace && Lex.getKind() != lltok::kw_end)
    if (ParseBasicBlock(PFS)) return true;

  // Eat the }.
  Lex.Lex();

  // Verify function is ok.
  return PFS.FinishFunction();
}

/// ParseBasicBlock
///   ::= LabelStr? Instruction*
bool LLParser::ParseBasicBlock(PerFunctionState &PFS) {
  // If this basic block starts out with a name, remember it.
  std::string Name;
  LocTy NameLoc = Lex.getLoc();
  if (Lex.getKind() == lltok::LabelStr) {
    Name = Lex.getStrVal();
    Lex.Lex();
  }

  BasicBlock *BB = PFS.DefineBB(Name, NameLoc);
  if (BB == 0) return true;

  std::string NameStr;

  // Parse the instructions in this block until we get a terminator.
  Instruction *Inst;
  do {
    // This instruction may have three possibilities for a name: a) none
    // specified, b) name specified "%foo =", c) number specified: "%4 =".
    LocTy NameLoc = Lex.getLoc();
    int NameID = -1;
    NameStr = "";

    if (Lex.getKind() == lltok::LocalVarID) {
      NameID = Lex.getUIntVal();
      Lex.Lex();
      if (ParseToken(lltok::equal, "expected '=' after instruction id"))
        return true;
    } else if (Lex.getKind() == lltok::LocalVar ||
               // FIXME: REMOVE IN LLVM 3.0
               Lex.getKind() == lltok::StringConstant) {
      NameStr = Lex.getStrVal();
      Lex.Lex();
      if (ParseToken(lltok::equal, "expected '=' after instruction name"))
        return true;
    }

    if (ParseInstruction(Inst, BB, PFS)) return true;
    if (EatIfPresent(lltok::comma))
      ParseOptionalCustomMetadata();

    // Set metadata attached with this instruction.
    for (SmallVector<std::pair<unsigned, MDNode *>, 2>::iterator
           MDI = MDsOnInst.begin(), MDE = MDsOnInst.end(); MDI != MDE; ++MDI)
      Inst->setMetadata(MDI->first, MDI->second);
    MDsOnInst.clear();

    BB->getInstList().push_back(Inst);

    // Set the name on the instruction.
    if (PFS.SetInstName(NameID, NameStr, NameLoc, Inst)) return true;
  } while (!isa<TerminatorInst>(Inst));

  return false;
}

//===----------------------------------------------------------------------===//
// Instruction Parsing.
//===----------------------------------------------------------------------===//

/// ParseInstruction - Parse one of the many different instructions.
///
bool LLParser::ParseInstruction(Instruction *&Inst, BasicBlock *BB,
                                PerFunctionState &PFS) {
  lltok::Kind Token = Lex.getKind();
  if (Token == lltok::Eof)
    return TokError("found end of file when expecting more instructions");
  LocTy Loc = Lex.getLoc();
  unsigned KeywordVal = Lex.getUIntVal();
  Lex.Lex();  // Eat the keyword.

  switch (Token) {
  default:                    return Error(Loc, "expected instruction opcode");
  // Terminator Instructions.
  case lltok::kw_unwind:      Inst = new UnwindInst(Context); return false;
  case lltok::kw_unreachable: Inst = new UnreachableInst(Context); return false;
  case lltok::kw_ret:         return ParseRet(Inst, BB, PFS);
  case lltok::kw_br:          return ParseBr(Inst, PFS);
  case lltok::kw_switch:      return ParseSwitch(Inst, PFS);
  case lltok::kw_indirectbr:  return ParseIndirectBr(Inst, PFS);
  case lltok::kw_invoke:      return ParseInvoke(Inst, PFS);
  // Binary Operators.
  case lltok::kw_add:
  case lltok::kw_sub:
  case lltok::kw_mul: {
    bool NUW = false;
    bool NSW = false;
    LocTy ModifierLoc = Lex.getLoc();
    if (EatIfPresent(lltok::kw_nuw))
      NUW = true;
    if (EatIfPresent(lltok::kw_nsw)) {
      NSW = true;
      if (EatIfPresent(lltok::kw_nuw))
        NUW = true;
    }
    // API compatibility: Accept either integer or floating-point types.
    bool Result = ParseArithmetic(Inst, PFS, KeywordVal, 0);
    if (!Result) {
      if (!Inst->getType()->isIntOrIntVector()) {
        if (NUW)
          return Error(ModifierLoc, "nuw only applies to integer operations");
        if (NSW)
          return Error(ModifierLoc, "nsw only applies to integer operations");
      }
      if (NUW)
        cast<BinaryOperator>(Inst)->setHasNoUnsignedWrap(true);
      if (NSW)
        cast<BinaryOperator>(Inst)->setHasNoSignedWrap(true);
    }
    return Result;
  }
  case lltok::kw_fadd:
  case lltok::kw_fsub:
  case lltok::kw_fmul:    return ParseArithmetic(Inst, PFS, KeywordVal, 2);

  case lltok::kw_sdiv: {
    bool Exact = false;
    if (EatIfPresent(lltok::kw_exact))
      Exact = true;
    bool Result = ParseArithmetic(Inst, PFS, KeywordVal, 1);
    if (!Result)
      if (Exact)
        cast<BinaryOperator>(Inst)->setIsExact(true);
    return Result;
  }

  case lltok::kw_udiv:
  case lltok::kw_urem:
  case lltok::kw_srem:   return ParseArithmetic(Inst, PFS, KeywordVal, 1);
  case lltok::kw_fdiv:
  case lltok::kw_frem:   return ParseArithmetic(Inst, PFS, KeywordVal, 2);
  case lltok::kw_shl:
  case lltok::kw_lshr:
  case lltok::kw_ashr:
  case lltok::kw_and:
  case lltok::kw_or:
  case lltok::kw_xor:    return ParseLogical(Inst, PFS, KeywordVal);
  case lltok::kw_icmp:
  case lltok::kw_fcmp:   return ParseCompare(Inst, PFS, KeywordVal);
  // Casts.
  case lltok::kw_trunc:
  case lltok::kw_zext:
  case lltok::kw_sext:
  case lltok::kw_fptrunc:
  case lltok::kw_fpext:
  case lltok::kw_bitcast:
  case lltok::kw_uitofp:
  case lltok::kw_sitofp:
  case lltok::kw_fptoui:
  case lltok::kw_fptosi:
  case lltok::kw_inttoptr:
  case lltok::kw_ptrtoint:       return ParseCast(Inst, PFS, KeywordVal);
  // Other.
  case lltok::kw_select:         return ParseSelect(Inst, PFS);
  case lltok::kw_va_arg:         return ParseVA_Arg(Inst, PFS);
  case lltok::kw_extractelement: return ParseExtractElement(Inst, PFS);
  case lltok::kw_insertelement:  return ParseInsertElement(Inst, PFS);
  case lltok::kw_shufflevector:  return ParseShuffleVector(Inst, PFS);
  case lltok::kw_phi:            return ParsePHI(Inst, PFS);
  case lltok::kw_call:           return ParseCall(Inst, PFS, false);
  case lltok::kw_tail:           return ParseCall(Inst, PFS, true);
  // Memory.
  case lltok::kw_alloca:         return ParseAlloc(Inst, PFS);
  case lltok::kw_malloc:         return ParseAlloc(Inst, PFS, BB, false);
  case lltok::kw_free:           return ParseFree(Inst, PFS, BB);
  case lltok::kw_load:           return ParseLoad(Inst, PFS, false);
  case lltok::kw_store:          return ParseStore(Inst, PFS, false);
  case lltok::kw_volatile:
    if (EatIfPresent(lltok::kw_load))
      return ParseLoad(Inst, PFS, true);
    else if (EatIfPresent(lltok::kw_store))
      return ParseStore(Inst, PFS, true);
    else
      return TokError("expected 'load' or 'store'");
  case lltok::kw_getresult:     return ParseGetResult(Inst, PFS);
  case lltok::kw_getelementptr: return ParseGetElementPtr(Inst, PFS);
  case lltok::kw_extractvalue:  return ParseExtractValue(Inst, PFS);
  case lltok::kw_insertvalue:   return ParseInsertValue(Inst, PFS);
  }
}

/// ParseCmpPredicate - Parse an integer or fp predicate, based on Kind.
bool LLParser::ParseCmpPredicate(unsigned &P, unsigned Opc) {
  if (Opc == Instruction::FCmp) {
    switch (Lex.getKind()) {
    default: TokError("expected fcmp predicate (e.g. 'oeq')");
    case lltok::kw_oeq: P = CmpInst::FCMP_OEQ; break;
    case lltok::kw_one: P = CmpInst::FCMP_ONE; break;
    case lltok::kw_olt: P = CmpInst::FCMP_OLT; break;
    case lltok::kw_ogt: P = CmpInst::FCMP_OGT; break;
    case lltok::kw_ole: P = CmpInst::FCMP_OLE; break;
    case lltok::kw_oge: P = CmpInst::FCMP_OGE; break;
    case lltok::kw_ord: P = CmpInst::FCMP_ORD; break;
    case lltok::kw_uno: P = CmpInst::FCMP_UNO; break;
    case lltok::kw_ueq: P = CmpInst::FCMP_UEQ; break;
    case lltok::kw_une: P = CmpInst::FCMP_UNE; break;
    case lltok::kw_ult: P = CmpInst::FCMP_ULT; break;
    case lltok::kw_ugt: P = CmpInst::FCMP_UGT; break;
    case lltok::kw_ule: P = CmpInst::FCMP_ULE; break;
    case lltok::kw_uge: P = CmpInst::FCMP_UGE; break;
    case lltok::kw_true: P = CmpInst::FCMP_TRUE; break;
    case lltok::kw_false: P = CmpInst::FCMP_FALSE; break;
    }
  } else {
    switch (Lex.getKind()) {
    default: TokError("expected icmp predicate (e.g. 'eq')");
    case lltok::kw_eq:  P = CmpInst::ICMP_EQ; break;
    case lltok::kw_ne:  P = CmpInst::ICMP_NE; break;
    case lltok::kw_slt: P = CmpInst::ICMP_SLT; break;
    case lltok::kw_sgt: P = CmpInst::ICMP_SGT; break;
    case lltok::kw_sle: P = CmpInst::ICMP_SLE; break;
    case lltok::kw_sge: P = CmpInst::ICMP_SGE; break;
    case lltok::kw_ult: P = CmpInst::ICMP_ULT; break;
    case lltok::kw_ugt: P = CmpInst::ICMP_UGT; break;
    case lltok::kw_ule: P = CmpInst::ICMP_ULE; break;
    case lltok::kw_uge: P = CmpInst::ICMP_UGE; break;
    }
  }
  Lex.Lex();
  return false;
}

//===----------------------------------------------------------------------===//
// Terminator Instructions.
//===----------------------------------------------------------------------===//

/// ParseRet - Parse a return instruction.
///   ::= 'ret' void (',' !dbg, !1)*
///   ::= 'ret' TypeAndValue (',' !dbg, !1)*
///   ::= 'ret' TypeAndValue (',' TypeAndValue)+  (',' !dbg, !1)*
///         [[obsolete: LLVM 3.0]]
bool LLParser::ParseRet(Instruction *&Inst, BasicBlock *BB,
                        PerFunctionState &PFS) {
  PATypeHolder Ty(Type::getVoidTy(Context));
  if (ParseType(Ty, true /*void allowed*/)) return true;

  if (Ty->isVoidTy()) {
    Inst = ReturnInst::Create(Context);
    return false;
  }

  Value *RV;
  if (ParseValue(Ty, RV, PFS)) return true;

  if (EatIfPresent(lltok::comma)) {
    // Parse optional custom metadata, e.g. !dbg
    if (Lex.getKind() == lltok::MetadataVar) {
      if (ParseOptionalCustomMetadata()) return true;
    } else {
      // The normal case is one return value.
      // FIXME: LLVM 3.0 remove MRV support for 'ret i32 1, i32 2', requiring
      // use of 'ret {i32,i32} {i32 1, i32 2}'
      SmallVector<Value*, 8> RVs;
      RVs.push_back(RV);

      do {
        // If optional custom metadata, e.g. !dbg is seen then this is the 
        // end of MRV.
        if (Lex.getKind() == lltok::MetadataVar)
          break;
        if (ParseTypeAndValue(RV, PFS)) return true;
        RVs.push_back(RV);
      } while (EatIfPresent(lltok::comma));

      RV = UndefValue::get(PFS.getFunction().getReturnType());
      for (unsigned i = 0, e = RVs.size(); i != e; ++i) {
        Instruction *I = InsertValueInst::Create(RV, RVs[i], i, "mrv");
        BB->getInstList().push_back(I);
        RV = I;
      }
    }
  }

  Inst = ReturnInst::Create(Context, RV);
  return false;
}


/// ParseBr
///   ::= 'br' TypeAndValue
///   ::= 'br' TypeAndValue ',' TypeAndValue ',' TypeAndValue
bool LLParser::ParseBr(Instruction *&Inst, PerFunctionState &PFS) {
  LocTy Loc, Loc2;
  Value *Op0;
  BasicBlock *Op1, *Op2;
  if (ParseTypeAndValue(Op0, Loc, PFS)) return true;

  if (BasicBlock *BB = dyn_cast<BasicBlock>(Op0)) {
    Inst = BranchInst::Create(BB);
    return false;
  }

  if (Op0->getType() != Type::getInt1Ty(Context))
    return Error(Loc, "branch condition must have 'i1' type");

  if (ParseToken(lltok::comma, "expected ',' after branch condition") ||
      ParseTypeAndBasicBlock(Op1, Loc, PFS) ||
      ParseToken(lltok::comma, "expected ',' after true destination") ||
      ParseTypeAndBasicBlock(Op2, Loc2, PFS))
    return true;

  Inst = BranchInst::Create(Op1, Op2, Op0);
  return false;
}

/// ParseSwitch
///  Instruction
///    ::= 'switch' TypeAndValue ',' TypeAndValue '[' JumpTable ']'
///  JumpTable
///    ::= (TypeAndValue ',' TypeAndValue)*
bool LLParser::ParseSwitch(Instruction *&Inst, PerFunctionState &PFS) {
  LocTy CondLoc, BBLoc;
  Value *Cond;
  BasicBlock *DefaultBB;
  if (ParseTypeAndValue(Cond, CondLoc, PFS) ||
      ParseToken(lltok::comma, "expected ',' after switch condition") ||
      ParseTypeAndBasicBlock(DefaultBB, BBLoc, PFS) ||
      ParseToken(lltok::lsquare, "expected '[' with switch table"))
    return true;

  if (!isa<IntegerType>(Cond->getType()))
    return Error(CondLoc, "switch condition must have integer type");

  // Parse the jump table pairs.
  SmallPtrSet<Value*, 32> SeenCases;
  SmallVector<std::pair<ConstantInt*, BasicBlock*>, 32> Table;
  while (Lex.getKind() != lltok::rsquare) {
    Value *Constant;
    BasicBlock *DestBB;

    if (ParseTypeAndValue(Constant, CondLoc, PFS) ||
        ParseToken(lltok::comma, "expected ',' after case value") ||
        ParseTypeAndBasicBlock(DestBB, PFS))
      return true;
    
    if (!SeenCases.insert(Constant))
      return Error(CondLoc, "duplicate case value in switch");
    if (!isa<ConstantInt>(Constant))
      return Error(CondLoc, "case value is not a constant integer");

    Table.push_back(std::make_pair(cast<ConstantInt>(Constant), DestBB));
  }

  Lex.Lex();  // Eat the ']'.

  SwitchInst *SI = SwitchInst::Create(Cond, DefaultBB, Table.size());
  for (unsigned i = 0, e = Table.size(); i != e; ++i)
    SI->addCase(Table[i].first, Table[i].second);
  Inst = SI;
  return false;
}

/// ParseIndirectBr
///  Instruction
///    ::= 'indirectbr' TypeAndValue ',' '[' LabelList ']'
bool LLParser::ParseIndirectBr(Instruction *&Inst, PerFunctionState &PFS) {
  LocTy AddrLoc;
  Value *Address;
  if (ParseTypeAndValue(Address, AddrLoc, PFS) ||
      ParseToken(lltok::comma, "expected ',' after indirectbr address") ||
      ParseToken(lltok::lsquare, "expected '[' with indirectbr"))
    return true;
  
  if (!isa<PointerType>(Address->getType()))
    return Error(AddrLoc, "indirectbr address must have pointer type");
  
  // Parse the destination list.
  SmallVector<BasicBlock*, 16> DestList;
  
  if (Lex.getKind() != lltok::rsquare) {
    BasicBlock *DestBB;
    if (ParseTypeAndBasicBlock(DestBB, PFS))
      return true;
    DestList.push_back(DestBB);
    
    while (EatIfPresent(lltok::comma)) {
      if (ParseTypeAndBasicBlock(DestBB, PFS))
        return true;
      DestList.push_back(DestBB);
    }
  }
  
  if (ParseToken(lltok::rsquare, "expected ']' at end of block list"))
    return true;

  IndirectBrInst *IBI = IndirectBrInst::Create(Address, DestList.size());
  for (unsigned i = 0, e = DestList.size(); i != e; ++i)
    IBI->addDestination(DestList[i]);
  Inst = IBI;
  return false;
}


/// ParseInvoke
///   ::= 'invoke' OptionalCallingConv OptionalAttrs Type Value ParamList
///       OptionalAttrs 'to' TypeAndValue 'unwind' TypeAndValue
bool LLParser::ParseInvoke(Instruction *&Inst, PerFunctionState &PFS) {
  LocTy CallLoc = Lex.getLoc();
  unsigned RetAttrs, FnAttrs;
  CallingConv::ID CC;
  PATypeHolder RetType(Type::getVoidTy(Context));
  LocTy RetTypeLoc;
  ValID CalleeID;
  SmallVector<ParamInfo, 16> ArgList;

  BasicBlock *NormalBB, *UnwindBB;
  if (ParseOptionalCallingConv(CC) ||
      ParseOptionalAttrs(RetAttrs, 1) ||
      ParseType(RetType, RetTypeLoc, true /*void allowed*/) ||
      ParseValID(CalleeID) ||
      ParseParameterList(ArgList, PFS) ||
      ParseOptionalAttrs(FnAttrs, 2) ||
      ParseToken(lltok::kw_to, "expected 'to' in invoke") ||
      ParseTypeAndBasicBlock(NormalBB, PFS) ||
      ParseToken(lltok::kw_unwind, "expected 'unwind' in invoke") ||
      ParseTypeAndBasicBlock(UnwindBB, PFS))
    return true;

  // If RetType is a non-function pointer type, then this is the short syntax
  // for the call, which means that RetType is just the return type.  Infer the
  // rest of the function argument types from the arguments that are present.
  const PointerType *PFTy = 0;
  const FunctionType *Ty = 0;
  if (!(PFTy = dyn_cast<PointerType>(RetType)) ||
      !(Ty = dyn_cast<FunctionType>(PFTy->getElementType()))) {
    // Pull out the types of all of the arguments...
    std::vector<const Type*> ParamTypes;
    for (unsigned i = 0, e = ArgList.size(); i != e; ++i)
      ParamTypes.push_back(ArgList[i].V->getType());

    if (!FunctionType::isValidReturnType(RetType))
      return Error(RetTypeLoc, "Invalid result type for LLVM function");

    Ty = FunctionType::get(RetType, ParamTypes, false);
    PFTy = PointerType::getUnqual(Ty);
  }

  // Look up the callee.
  Value *Callee;
  if (ConvertValIDToValue(PFTy, CalleeID, Callee, PFS)) return true;

  // FIXME: In LLVM 3.0, stop accepting zext, sext and inreg as optional
  // function attributes.
  unsigned ObsoleteFuncAttrs = Attribute::ZExt|Attribute::SExt|Attribute::InReg;
  if (FnAttrs & ObsoleteFuncAttrs) {
    RetAttrs |= FnAttrs & ObsoleteFuncAttrs;
    FnAttrs &= ~ObsoleteFuncAttrs;
  }

  // Set up the Attributes for the function.
  SmallVector<AttributeWithIndex, 8> Attrs;
  if (RetAttrs != Attribute::None)
    Attrs.push_back(AttributeWithIndex::get(0, RetAttrs));

  SmallVector<Value*, 8> Args;

  // Loop through FunctionType's arguments and ensure they are specified
  // correctly.  Also, gather any parameter attributes.
  FunctionType::param_iterator I = Ty->param_begin();
  FunctionType::param_iterator E = Ty->param_end();
  for (unsigned i = 0, e = ArgList.size(); i != e; ++i) {
    const Type *ExpectedTy = 0;
    if (I != E) {
      ExpectedTy = *I++;
    } else if (!Ty->isVarArg()) {
      return Error(ArgList[i].Loc, "too many arguments specified");
    }

    if (ExpectedTy && ExpectedTy != ArgList[i].V->getType())
      return Error(ArgList[i].Loc, "argument is not of expected type '" +
                   ExpectedTy->getDescription() + "'");
    Args.push_back(ArgList[i].V);
    if (ArgList[i].Attrs != Attribute::None)
      Attrs.push_back(AttributeWithIndex::get(i+1, ArgList[i].Attrs));
  }

  if (I != E)
    return Error(CallLoc, "not enough parameters specified for call");

  if (FnAttrs != Attribute::None)
    Attrs.push_back(AttributeWithIndex::get(~0, FnAttrs));

  // Finish off the Attributes and check them
  AttrListPtr PAL = AttrListPtr::get(Attrs.begin(), Attrs.end());

  InvokeInst *II = InvokeInst::Create(Callee, NormalBB, UnwindBB,
                                      Args.begin(), Args.end());
  II->setCallingConv(CC);
  II->setAttributes(PAL);
  Inst = II;
  return false;
}



//===----------------------------------------------------------------------===//
// Binary Operators.
//===----------------------------------------------------------------------===//

/// ParseArithmetic
///  ::= ArithmeticOps TypeAndValue ',' Value
///
/// If OperandType is 0, then any FP or integer operand is allowed.  If it is 1,
/// then any integer operand is allowed, if it is 2, any fp operand is allowed.
bool LLParser::ParseArithmetic(Instruction *&Inst, PerFunctionState &PFS,
                               unsigned Opc, unsigned OperandType) {
  LocTy Loc; Value *LHS, *RHS;
  if (ParseTypeAndValue(LHS, Loc, PFS) ||
      ParseToken(lltok::comma, "expected ',' in arithmetic operation") ||
      ParseValue(LHS->getType(), RHS, PFS))
    return true;

  bool Valid;
  switch (OperandType) {
  default: llvm_unreachable("Unknown operand type!");
  case 0: // int or FP.
    Valid = LHS->getType()->isIntOrIntVector() ||
            LHS->getType()->isFPOrFPVector();
    break;
  case 1: Valid = LHS->getType()->isIntOrIntVector(); break;
  case 2: Valid = LHS->getType()->isFPOrFPVector(); break;
  }

  if (!Valid)
    return Error(Loc, "invalid operand type for instruction");

  Inst = BinaryOperator::Create((Instruction::BinaryOps)Opc, LHS, RHS);
  return false;
}

/// ParseLogical
///  ::= ArithmeticOps TypeAndValue ',' Value {
bool LLParser::ParseLogical(Instruction *&Inst, PerFunctionState &PFS,
                            unsigned Opc) {
  LocTy Loc; Value *LHS, *RHS;
  if (ParseTypeAndValue(LHS, Loc, PFS) ||
      ParseToken(lltok::comma, "expected ',' in logical operation") ||
      ParseValue(LHS->getType(), RHS, PFS))
    return true;

  if (!LHS->getType()->isIntOrIntVector())
    return Error(Loc,"instruction requires integer or integer vector operands");

  Inst = BinaryOperator::Create((Instruction::BinaryOps)Opc, LHS, RHS);
  return false;
}


/// ParseCompare
///  ::= 'icmp' IPredicates TypeAndValue ',' Value
///  ::= 'fcmp' FPredicates TypeAndValue ',' Value
bool LLParser::ParseCompare(Instruction *&Inst, PerFunctionState &PFS,
                            unsigned Opc) {
  // Parse the integer/fp comparison predicate.
  LocTy Loc;
  unsigned Pred;
  Value *LHS, *RHS;
  if (ParseCmpPredicate(Pred, Opc) ||
      ParseTypeAndValue(LHS, Loc, PFS) ||
      ParseToken(lltok::comma, "expected ',' after compare value") ||
      ParseValue(LHS->getType(), RHS, PFS))
    return true;

  if (Opc == Instruction::FCmp) {
    if (!LHS->getType()->isFPOrFPVector())
      return Error(Loc, "fcmp requires floating point operands");
    Inst = new FCmpInst(CmpInst::Predicate(Pred), LHS, RHS);
  } else {
    assert(Opc == Instruction::ICmp && "Unknown opcode for CmpInst!");
    if (!LHS->getType()->isIntOrIntVector() &&
        !isa<PointerType>(LHS->getType()))
      return Error(Loc, "icmp requires integer operands");
    Inst = new ICmpInst(CmpInst::Predicate(Pred), LHS, RHS);
  }
  return false;
}

//===----------------------------------------------------------------------===//
// Other Instructions.
//===----------------------------------------------------------------------===//


/// ParseCast
///   ::= CastOpc TypeAndValue 'to' Type
bool LLParser::ParseCast(Instruction *&Inst, PerFunctionState &PFS,
                         unsigned Opc) {
  LocTy Loc;  Value *Op;
  PATypeHolder DestTy(Type::getVoidTy(Context));
  if (ParseTypeAndValue(Op, Loc, PFS) ||
      ParseToken(lltok::kw_to, "expected 'to' after cast value") ||
      ParseType(DestTy))
    return true;

  if (!CastInst::castIsValid((Instruction::CastOps)Opc, Op, DestTy)) {
    CastInst::castIsValid((Instruction::CastOps)Opc, Op, DestTy);
    return Error(Loc, "invalid cast opcode for cast from '" +
                 Op->getType()->getDescription() + "' to '" +
                 DestTy->getDescription() + "'");
  }
  Inst = CastInst::Create((Instruction::CastOps)Opc, Op, DestTy);
  return false;
}

/// ParseSelect
///   ::= 'select' TypeAndValue ',' TypeAndValue ',' TypeAndValue
bool LLParser::ParseSelect(Instruction *&Inst, PerFunctionState &PFS) {
  LocTy Loc;
  Value *Op0, *Op1, *Op2;
  if (ParseTypeAndValue(Op0, Loc, PFS) ||
      ParseToken(lltok::comma, "expected ',' after select condition") ||
      ParseTypeAndValue(Op1, PFS) ||
      ParseToken(lltok::comma, "expected ',' after select value") ||
      ParseTypeAndValue(Op2, PFS))
    return true;

  if (const char *Reason = SelectInst::areInvalidOperands(Op0, Op1, Op2))
    return Error(Loc, Reason);

  Inst = SelectInst::Create(Op0, Op1, Op2);
  return false;
}

/// ParseVA_Arg
///   ::= 'va_arg' TypeAndValue ',' Type
bool LLParser::ParseVA_Arg(Instruction *&Inst, PerFunctionState &PFS) {
  Value *Op;
  PATypeHolder EltTy(Type::getVoidTy(Context));
  LocTy TypeLoc;
  if (ParseTypeAndValue(Op, PFS) ||
      ParseToken(lltok::comma, "expected ',' after vaarg operand") ||
      ParseType(EltTy, TypeLoc))
    return true;

  if (!EltTy->isFirstClassType())
    return Error(TypeLoc, "va_arg requires operand with first class type");

  Inst = new VAArgInst(Op, EltTy);
  return false;
}

/// ParseExtractElement
///   ::= 'extractelement' TypeAndValue ',' TypeAndValue
bool LLParser::ParseExtractElement(Instruction *&Inst, PerFunctionState &PFS) {
  LocTy Loc;
  Value *Op0, *Op1;
  if (ParseTypeAndValue(Op0, Loc, PFS) ||
      ParseToken(lltok::comma, "expected ',' after extract value") ||
      ParseTypeAndValue(Op1, PFS))
    return true;

  if (!ExtractElementInst::isValidOperands(Op0, Op1))
    return Error(Loc, "invalid extractelement operands");

  Inst = ExtractElementInst::Create(Op0, Op1);
  return false;
}

/// ParseInsertElement
///   ::= 'insertelement' TypeAndValue ',' TypeAndValue ',' TypeAndValue
bool LLParser::ParseInsertElement(Instruction *&Inst, PerFunctionState &PFS) {
  LocTy Loc;
  Value *Op0, *Op1, *Op2;
  if (ParseTypeAndValue(Op0, Loc, PFS) ||
      ParseToken(lltok::comma, "expected ',' after insertelement value") ||
      ParseTypeAndValue(Op1, PFS) ||
      ParseToken(lltok::comma, "expected ',' after insertelement value") ||
      ParseTypeAndValue(Op2, PFS))
    return true;

  if (!InsertElementInst::isValidOperands(Op0, Op1, Op2))
    return Error(Loc, "invalid insertelement operands");

  Inst = InsertElementInst::Create(Op0, Op1, Op2);
  return false;
}

/// ParseShuffleVector
///   ::= 'shufflevector' TypeAndValue ',' TypeAndValue ',' TypeAndValue
bool LLParser::ParseShuffleVector(Instruction *&Inst, PerFunctionState &PFS) {
  LocTy Loc;
  Value *Op0, *Op1, *Op2;
  if (ParseTypeAndValue(Op0, Loc, PFS) ||
      ParseToken(lltok::comma, "expected ',' after shuffle mask") ||
      ParseTypeAndValue(Op1, PFS) ||
      ParseToken(lltok::comma, "expected ',' after shuffle value") ||
      ParseTypeAndValue(Op2, PFS))
    return true;

  if (!ShuffleVectorInst::isValidOperands(Op0, Op1, Op2))
    return Error(Loc, "invalid extractelement operands");

  Inst = new ShuffleVectorInst(Op0, Op1, Op2);
  return false;
}

/// ParsePHI
///   ::= 'phi' Type '[' Value ',' Value ']' (',' '[' Value ',' Value ']')*
bool LLParser::ParsePHI(Instruction *&Inst, PerFunctionState &PFS) {
  PATypeHolder Ty(Type::getVoidTy(Context));
  Value *Op0, *Op1;
  LocTy TypeLoc = Lex.getLoc();

  if (ParseType(Ty) ||
      ParseToken(lltok::lsquare, "expected '[' in phi value list") ||
      ParseValue(Ty, Op0, PFS) ||
      ParseToken(lltok::comma, "expected ',' after insertelement value") ||
      ParseValue(Type::getLabelTy(Context), Op1, PFS) ||
      ParseToken(lltok::rsquare, "expected ']' in phi value list"))
    return true;

  SmallVector<std::pair<Value*, BasicBlock*>, 16> PHIVals;
  while (1) {
    PHIVals.push_back(std::make_pair(Op0, cast<BasicBlock>(Op1)));

    if (!EatIfPresent(lltok::comma))
      break;

    if (Lex.getKind() == lltok::MetadataVar)
      break;

    if (ParseToken(lltok::lsquare, "expected '[' in phi value list") ||
        ParseValue(Ty, Op0, PFS) ||
        ParseToken(lltok::comma, "expected ',' after insertelement value") ||
        ParseValue(Type::getLabelTy(Context), Op1, PFS) ||
        ParseToken(lltok::rsquare, "expected ']' in phi value list"))
      return true;
  }

  if (Lex.getKind() == lltok::MetadataVar)
    if (ParseOptionalCustomMetadata()) return true;

  if (!Ty->isFirstClassType())
    return Error(TypeLoc, "phi node must have first class type");

  PHINode *PN = PHINode::Create(Ty);
  PN->reserveOperandSpace(PHIVals.size());
  for (unsigned i = 0, e = PHIVals.size(); i != e; ++i)
    PN->addIncoming(PHIVals[i].first, PHIVals[i].second);
  Inst = PN;
  return false;
}

/// ParseCall
///   ::= 'tail'? 'call' OptionalCallingConv OptionalAttrs Type Value
///       ParameterList OptionalAttrs
bool LLParser::ParseCall(Instruction *&Inst, PerFunctionState &PFS,
                         bool isTail) {
  unsigned RetAttrs, FnAttrs;
  CallingConv::ID CC;
  PATypeHolder RetType(Type::getVoidTy(Context));
  LocTy RetTypeLoc;
  ValID CalleeID;
  SmallVector<ParamInfo, 16> ArgList;
  LocTy CallLoc = Lex.getLoc();

  if ((isTail && ParseToken(lltok::kw_call, "expected 'tail call'")) ||
      ParseOptionalCallingConv(CC) ||
      ParseOptionalAttrs(RetAttrs, 1) ||
      ParseType(RetType, RetTypeLoc, true /*void allowed*/) ||
      ParseValID(CalleeID) ||
      ParseParameterList(ArgList, PFS) ||
      ParseOptionalAttrs(FnAttrs, 2))
    return true;

  // If RetType is a non-function pointer type, then this is the short syntax
  // for the call, which means that RetType is just the return type.  Infer the
  // rest of the function argument types from the arguments that are present.
  const PointerType *PFTy = 0;
  const FunctionType *Ty = 0;
  if (!(PFTy = dyn_cast<PointerType>(RetType)) ||
      !(Ty = dyn_cast<FunctionType>(PFTy->getElementType()))) {
    // Pull out the types of all of the arguments...
    std::vector<const Type*> ParamTypes;
    for (unsigned i = 0, e = ArgList.size(); i != e; ++i)
      ParamTypes.push_back(ArgList[i].V->getType());

    if (!FunctionType::isValidReturnType(RetType))
      return Error(RetTypeLoc, "Invalid result type for LLVM function");

    Ty = FunctionType::get(RetType, ParamTypes, false);
    PFTy = PointerType::getUnqual(Ty);
  }

  // Look up the callee.
  Value *Callee;
  if (ConvertValIDToValue(PFTy, CalleeID, Callee, PFS)) return true;

  // FIXME: In LLVM 3.0, stop accepting zext, sext and inreg as optional
  // function attributes.
  unsigned ObsoleteFuncAttrs = Attribute::ZExt|Attribute::SExt|Attribute::InReg;
  if (FnAttrs & ObsoleteFuncAttrs) {
    RetAttrs |= FnAttrs & ObsoleteFuncAttrs;
    FnAttrs &= ~ObsoleteFuncAttrs;
  }

  // Set up the Attributes for the function.
  SmallVector<AttributeWithIndex, 8> Attrs;
  if (RetAttrs != Attribute::None)
    Attrs.push_back(AttributeWithIndex::get(0, RetAttrs));

  SmallVector<Value*, 8> Args;

  // Loop through FunctionType's arguments and ensure they are specified
  // correctly.  Also, gather any parameter attributes.
  FunctionType::param_iterator I = Ty->param_begin();
  FunctionType::param_iterator E = Ty->param_end();
  for (unsigned i = 0, e = ArgList.size(); i != e; ++i) {
    const Type *ExpectedTy = 0;
    if (I != E) {
      ExpectedTy = *I++;
    } else if (!Ty->isVarArg()) {
      return Error(ArgList[i].Loc, "too many arguments specified");
    }

    if (ExpectedTy && ExpectedTy != ArgList[i].V->getType())
      return Error(ArgList[i].Loc, "argument is not of expected type '" +
                   ExpectedTy->getDescription() + "'");
    Args.push_back(ArgList[i].V);
    if (ArgList[i].Attrs != Attribute::None)
      Attrs.push_back(AttributeWithIndex::get(i+1, ArgList[i].Attrs));
  }

  if (I != E)
    return Error(CallLoc, "not enough parameters specified for call");

  if (FnAttrs != Attribute::None)
    Attrs.push_back(AttributeWithIndex::get(~0, FnAttrs));

  // Finish off the Attributes and check them
  AttrListPtr PAL = AttrListPtr::get(Attrs.begin(), Attrs.end());

  CallInst *CI = CallInst::Create(Callee, Args.begin(), Args.end());
  CI->setTailCall(isTail);
  CI->setCallingConv(CC);
  CI->setAttributes(PAL);
  Inst = CI;
  return false;
}

//===----------------------------------------------------------------------===//
// Memory Instructions.
//===----------------------------------------------------------------------===//

/// ParseAlloc
///   ::= 'malloc' Type (',' TypeAndValue)? (',' OptionalInfo)?
///   ::= 'alloca' Type (',' TypeAndValue)? (',' OptionalInfo)?
bool LLParser::ParseAlloc(Instruction *&Inst, PerFunctionState &PFS,
                          BasicBlock* BB, bool isAlloca) {
  PATypeHolder Ty(Type::getVoidTy(Context));
  Value *Size = 0;
  LocTy SizeLoc;
  unsigned Alignment = 0;
  if (ParseType(Ty)) return true;

  if (EatIfPresent(lltok::comma)) {
    if (Lex.getKind() == lltok::kw_align 
        || Lex.getKind() == lltok::MetadataVar) {
      if (ParseOptionalInfo(Alignment)) return true;
    } else {
      if (ParseTypeAndValue(Size, SizeLoc, PFS)) return true;
      if (EatIfPresent(lltok::comma))
        if (ParseOptionalInfo(Alignment)) return true;
    }
  }

  if (Size && Size->getType() != Type::getInt32Ty(Context))
    return Error(SizeLoc, "element count must be i32");

  if (isAlloca) {
    Inst = new AllocaInst(Ty, Size, Alignment);
    return false;
  }

  // Autoupgrade old malloc instruction to malloc call.
  // FIXME: Remove in LLVM 3.0.
  const Type *IntPtrTy = Type::getInt32Ty(Context);
  Constant *AllocSize = ConstantExpr::getSizeOf(Ty);
  AllocSize = ConstantExpr::getTruncOrBitCast(AllocSize, IntPtrTy);
  if (!MallocF)
    // Prototype malloc as "void *(int32)".
    // This function is renamed as "malloc" in ValidateEndOfModule().
    MallocF = cast<Function>(
       M->getOrInsertFunction("", Type::getInt8PtrTy(Context), IntPtrTy, NULL));
  Inst = CallInst::CreateMalloc(BB, IntPtrTy, Ty, AllocSize, Size, MallocF);
  return false;
}

/// ParseFree
///   ::= 'free' TypeAndValue
bool LLParser::ParseFree(Instruction *&Inst, PerFunctionState &PFS,
                         BasicBlock* BB) {
  Value *Val; LocTy Loc;
  if (ParseTypeAndValue(Val, Loc, PFS)) return true;
  if (!isa<PointerType>(Val->getType()))
    return Error(Loc, "operand to free must be a pointer");
  Inst = CallInst::CreateFree(Val, BB);
  return false;
}

/// ParseLoad
///   ::= 'volatile'? 'load' TypeAndValue (',' OptionalInfo)?
bool LLParser::ParseLoad(Instruction *&Inst, PerFunctionState &PFS,
                         bool isVolatile) {
  Value *Val; LocTy Loc;
  unsigned Alignment = 0;
  if (ParseTypeAndValue(Val, Loc, PFS)) return true;

  if (EatIfPresent(lltok::comma))
    if (ParseOptionalInfo(Alignment)) return true;

  if (!isa<PointerType>(Val->getType()) ||
      !cast<PointerType>(Val->getType())->getElementType()->isFirstClassType())
    return Error(Loc, "load operand must be a pointer to a first class type");

  Inst = new LoadInst(Val, "", isVolatile, Alignment);
  return false;
}

/// ParseStore
///   ::= 'volatile'? 'store' TypeAndValue ',' TypeAndValue (',' 'align' i32)?
bool LLParser::ParseStore(Instruction *&Inst, PerFunctionState &PFS,
                          bool isVolatile) {
  Value *Val, *Ptr; LocTy Loc, PtrLoc;
  unsigned Alignment = 0;
  if (ParseTypeAndValue(Val, Loc, PFS) ||
      ParseToken(lltok::comma, "expected ',' after store operand") ||
      ParseTypeAndValue(Ptr, PtrLoc, PFS))
    return true;

  if (EatIfPresent(lltok::comma))
    if (ParseOptionalInfo(Alignment)) return true;

  if (!isa<PointerType>(Ptr->getType()))
    return Error(PtrLoc, "store operand must be a pointer");
  if (!Val->getType()->isFirstClassType())
    return Error(Loc, "store operand must be a first class value");
  if (cast<PointerType>(Ptr->getType())->getElementType() != Val->getType())
    return Error(Loc, "stored value and pointer type do not match");

  Inst = new StoreInst(Val, Ptr, isVolatile, Alignment);
  return false;
}

/// ParseGetResult
///   ::= 'getresult' TypeAndValue ',' i32
/// FIXME: Remove support for getresult in LLVM 3.0
bool LLParser::ParseGetResult(Instruction *&Inst, PerFunctionState &PFS) {
  Value *Val; LocTy ValLoc, EltLoc;
  unsigned Element;
  if (ParseTypeAndValue(Val, ValLoc, PFS) ||
      ParseToken(lltok::comma, "expected ',' after getresult operand") ||
      ParseUInt32(Element, EltLoc))
    return true;

  if (!isa<StructType>(Val->getType()) && !isa<ArrayType>(Val->getType()))
    return Error(ValLoc, "getresult inst requires an aggregate operand");
  if (!ExtractValueInst::getIndexedType(Val->getType(), Element))
    return Error(EltLoc, "invalid getresult index for value");
  Inst = ExtractValueInst::Create(Val, Element);
  return false;
}

/// ParseGetElementPtr
///   ::= 'getelementptr' 'inbounds'? TypeAndValue (',' TypeAndValue)*
bool LLParser::ParseGetElementPtr(Instruction *&Inst, PerFunctionState &PFS) {
  Value *Ptr, *Val; LocTy Loc, EltLoc;

  bool InBounds = EatIfPresent(lltok::kw_inbounds);

  if (ParseTypeAndValue(Ptr, Loc, PFS)) return true;

  if (!isa<PointerType>(Ptr->getType()))
    return Error(Loc, "base of getelementptr must be a pointer");

  SmallVector<Value*, 16> Indices;
  while (EatIfPresent(lltok::comma)) {
    if (Lex.getKind() == lltok::MetadataVar)
      break;
    if (ParseTypeAndValue(Val, EltLoc, PFS)) return true;
    if (!isa<IntegerType>(Val->getType()))
      return Error(EltLoc, "getelementptr index must be an integer");
    Indices.push_back(Val);
  }
  if (Lex.getKind() == lltok::MetadataVar)
    if (ParseOptionalCustomMetadata()) return true;

  if (!GetElementPtrInst::getIndexedType(Ptr->getType(),
                                         Indices.begin(), Indices.end()))
    return Error(Loc, "invalid getelementptr indices");
  Inst = GetElementPtrInst::Create(Ptr, Indices.begin(), Indices.end());
  if (InBounds)
    cast<GetElementPtrInst>(Inst)->setIsInBounds(true);
  return false;
}

/// ParseExtractValue
///   ::= 'extractvalue' TypeAndValue (',' uint32)+
bool LLParser::ParseExtractValue(Instruction *&Inst, PerFunctionState &PFS) {
  Value *Val; LocTy Loc;
  SmallVector<unsigned, 4> Indices;
  if (ParseTypeAndValue(Val, Loc, PFS) ||
      ParseIndexList(Indices))
    return true;
  if (Lex.getKind() == lltok::MetadataVar)
    if (ParseOptionalCustomMetadata()) return true;

  if (!isa<StructType>(Val->getType()) && !isa<ArrayType>(Val->getType()))
    return Error(Loc, "extractvalue operand must be array or struct");

  if (!ExtractValueInst::getIndexedType(Val->getType(), Indices.begin(),
                                        Indices.end()))
    return Error(Loc, "invalid indices for extractvalue");
  Inst = ExtractValueInst::Create(Val, Indices.begin(), Indices.end());
  return false;
}

/// ParseInsertValue
///   ::= 'insertvalue' TypeAndValue ',' TypeAndValue (',' uint32)+
bool LLParser::ParseInsertValue(Instruction *&Inst, PerFunctionState &PFS) {
  Value *Val0, *Val1; LocTy Loc0, Loc1;
  SmallVector<unsigned, 4> Indices;
  if (ParseTypeAndValue(Val0, Loc0, PFS) ||
      ParseToken(lltok::comma, "expected comma after insertvalue operand") ||
      ParseTypeAndValue(Val1, Loc1, PFS) ||
      ParseIndexList(Indices))
    return true;
  if (Lex.getKind() == lltok::MetadataVar)
    if (ParseOptionalCustomMetadata()) return true;

  if (!isa<StructType>(Val0->getType()) && !isa<ArrayType>(Val0->getType()))
    return Error(Loc0, "extractvalue operand must be array or struct");

  if (!ExtractValueInst::getIndexedType(Val0->getType(), Indices.begin(),
                                        Indices.end()))
    return Error(Loc0, "invalid indices for insertvalue");
  Inst = InsertValueInst::Create(Val0, Val1, Indices.begin(), Indices.end());
  return false;
}

//===----------------------------------------------------------------------===//
// Embedded metadata.
//===----------------------------------------------------------------------===//

/// ParseMDNodeVector
///   ::= Element (',' Element)*
/// Element
///   ::= 'null' | TypeAndValue
bool LLParser::ParseMDNodeVector(SmallVectorImpl<Value*> &Elts) {
  do {
    // Null is a special case since it is typeless.
    if (EatIfPresent(lltok::kw_null)) {
      Elts.push_back(0);
      continue;
    }
    
    Value *V = 0;
    PATypeHolder Ty(Type::getVoidTy(Context));
    ValID ID;
    if (ParseType(Ty) || ParseValID(ID) ||
        ConvertGlobalOrMetadataValIDToValue(Ty, ID, V))
      return true;
    
    Elts.push_back(V);
  } while (EatIfPresent(lltok::comma));

  return false;
}
