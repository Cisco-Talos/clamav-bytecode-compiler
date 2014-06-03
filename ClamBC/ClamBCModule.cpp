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
#define DEBUG_TYPE "bcmodule"
#include "llvm/System/DataTypes.h"
#include "../clang/lib/Headers/bytecode_api.h"
#include "clambc.h"
#include "ClamBCDiagnostics.h"
#include "ClamBCModule.h"
#include "ClamBCCommon.h"
#include "llvm/ADT/FoldingSet.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/Assembly/Writer.h"
#include "llvm/Analysis/ConstantFolding.h"
#include "llvm/Analysis/DebugInfo.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/Config/config.h"
#include "llvm/DerivedTypes.h"
#include "llvm/IntrinsicInst.h"
#include "llvm/Module.h"
#include "llvm/Pass.h"
#include "llvm/PassManager.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/ConstantRange.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/InstIterator.h"
#include "llvm/Support/FormattedStream.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetData.h"
#include "llvm/System/Process.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Transforms/IPO.h"
#include "llvm/Type.h"
using namespace llvm;

static cl::opt<bool>
WriteDI("clambc-dbg", cl::Hidden, cl::init(false),
        cl::desc("Write debug information into output bytecode"));

static cl::opt<std::string>
SrcFile("clambc-src",cl::desc("Source file"),
        cl::value_desc("Source file coressponding"
                       "to this compiled file"),
        cl::init(""));

ClamBCModule::ClamBCModule(llvm::formatted_raw_ostream &o,
                           const std::vector<std::string> &APIList)
: ModulePass(&ID), Out(lineBuffer), OutReal(o), lastLinePos(0), maxLineLength(0), anyDbgIds(false) {
  unsigned id = 1;
  for (std::vector<std::string>::const_iterator I=APIList.begin(), E=APIList.end();
       I != E; ++I) {
    apiMap[*I] = id++;
  }
  //banMap["malloc"] = 0;

  // Assign IDs to globals. Each global variable that is filled by libclamav
  // must be listed here.
  globalsMap["__clambc_match_counts"] = GLOBAL_MATCH_COUNTS;
  globalsMap["__clambc_virusnames"] = GLOBAL_VIRUSNAMES;
  globalsMap["__clambc_pedata"] = GLOBAL_PEDATA;
  globalsMap["__clambc_filesize"] = GLOBAL_FILESIZE;
  globalsMap["__clambc_match_offsets"] = GLOBAL_MATCH_OFFSETS;
}

void ClamBCModule::dumpTypes(llvm::raw_ostream &OS)
{
  // Print type IDs to debug.map
  const Type **revmap = new const Type*[typeIDs.size()];
  for (TypeMapTy::iterator I=typeIDs.begin(), E=typeIDs.end();
       I != E; ++I) {
    revmap[I->second] = I->first;
  }
  for (unsigned i=65;i<typeIDs.size();i++)
    OS << "type " << i << ": " << *revmap[i] << "\n";
  OS << "\n";
  delete [] revmap;
}

void ClamBCModule::getAnalysisUsage(AnalysisUsage &AU) const {
  AU.addRequired<TargetData>();
}

static unsigned getSpecialIndex(StringRef Name)
{
  // Ensure main/entrypoint is sorted before any other function
  // Function ID 0 must be the entrypoint!
  if (Name.equals("entrypoint"))
    return 0;
  if (Name.equals("logical_trigger"))
    return 1;
  return ~0u;
}

static bool compare_lt_functions(Function *A, Function *B)
{
  // Sort functions: first special functions,
  // next sorted by parameter count ascending, next sorted by name.
  StringRef NA = A->getName();
  StringRef NB = B->getName();
  unsigned naidx = getSpecialIndex(NA);
  unsigned nbidx = getSpecialIndex(NB);
  if (naidx != ~0u || nbidx != ~0u)
    return naidx < nbidx;
  naidx = A->getFunctionType()->getNumParams();
  nbidx = B->getFunctionType()->getNumParams();
  if (naidx != nbidx)
    return naidx < nbidx;
  return NA.compare(NB) < 0;
}

bool ClamBCModule::runOnModule(Module &M)
{
  // Determine bytecode kind, default is 0 (generic).
  kind = 0;
  GlobalVariable *GVKind = M.getGlobalVariable("__clambc_kind");
  if (GVKind && GVKind->hasDefinitiveInitializer()) {
    kind = cast<ConstantInt>(GVKind->getInitializer())->getValue().
      getZExtValue();
    GVKind->setLinkage(GlobalValue::InternalLinkage);
    if (kind >= 65536)
      ClamBCModule::stop("Bytecode kind cannot be higher than 64k\n", &M);
  }
  DEBUG(errs() << "Bytecode kind is " << kind << "\n");

  GlobalVariable *G = M.getGlobalVariable("__Copyright");
  if (G && G->hasDefinitiveInitializer()) {
    Constant *C = G->getInitializer();
    std::string c;
    if (!GetConstantStringInfo(C, c))
      ClamBCModule::stop("Failed to extract copyright string\n", &M);
    copyright = strdup(c.c_str());
    G->setLinkage(GlobalValue::InternalLinkage);
  } else
    copyright = NULL;

  // Logical signature created by ClamBCLogicalCompiler.
  NamedMDNode *Node = M.getNamedMetadata("clambc.logicalsignature");
  LogicalSignature = Node ?
    cast<MDString>(Node->getOperand(0)->getOperand(0))->getString() : "";

  Node = M.getNamedMetadata("clambc.virusnames");
  virusnames = Node ?
    cast<MDString>(Node->getOperand(0)->getOperand(0))->getString() : "";

  unsigned tid, fid; 
  //unsigned cid;
  startTID = tid = clamav::initTypeIDs(typeIDs, M.getContext());
  // arrays of [2 x i8] .. [7 x i8] used for struct padding
  for (unsigned i=1;i<8;i++) {
    const Type *Ty = llvm::ArrayType::get(llvm::Type::getInt8Ty(M.getContext()),
                                          i);
    typeIDs[Ty] = tid++;
    extraTypes.push_back(Ty);
  }

  std::vector<const Type*> types;
  //cid=1;
  fid=1;
  for (Module::global_iterator I = M.global_begin(); I != M.global_end(); ++I) {
    for (Value::use_iterator J=I->use_begin(), JE=I->use_end(); J != JE; ++J) {
      ConstantExpr *CE = dyn_cast<ConstantExpr>(*J);
      if (!CE)
        continue;
      // ClamAV bytecode doesn't support arbitrary constant expressions for 
      // globals, so introduce helper globals for nested constant expressions. 
      if (CE->getOpcode() != Instruction::GetElementPtr /*||
          CE->getNumOperands() != 3*/) {
        if (CE->getOpcode() == Instruction::BitCast) {
          GlobalVariable *GV = new GlobalVariable(M, CE->getType(), true, 
                                                  GlobalValue::InternalLinkage, 
                                                  CE, I->getName()+"_bc");
          CEMap[CE] = GV;
          continue;
        }
        errs() << "UNSUPPORTED: " << *CE << "\n";
        ClamBCModule::stop("Unsupported constant expression", &M);
      }
      ConstantInt *C0 = dyn_cast<ConstantInt>(CE->getOperand(1));
      ConstantInt *C1 = dyn_cast<ConstantInt>(CE->getOperand(2));
      uint64_t v = C1->getValue().getZExtValue();
      if (!C0->isZero()) {
        errs() << "UNSUPPORTED: " << *CE << "\n";
        ClamBCModule::stop("Unsupported constant expression, nonzero first"
                           " index", &M);
      }
//      if (CE->getNumOperands() > 3) {
        TargetData *TD = &getAnalysis<TargetData>();
        std::vector<Value*> indices;
        for (unsigned i=1;i<CE->getNumOperands();i++)
          indices.push_back(CE->getOperand(i));
        const Type *IP8Ty = PointerType::getUnqual(Type::getInt8Ty(CE->getContext()));
        uint64_t idx = TD->getIndexedOffset(CE->getOperand(0)->getType(),
                                            &indices[0], indices.size());
        Value *Idxs[2];
        Idxs[0] = ConstantInt::get(Type::getInt64Ty(CE->getContext()), idx);
        Constant *C = ConstantExpr::getPointerCast(CE->getOperand(0), IP8Ty);
        ConstantExpr *NewCE =
          cast<ConstantExpr>(ConstantExpr::getGetElementPtr(C,
                                                            Idxs, 1));
        NewCE = cast<ConstantExpr>(ConstantExpr::getPointerCast(NewCE,
                                                                CE->getType()));
        if (CE != NewCE) {
          CE->replaceAllUsesWith(NewCE);
        }
        CE = NewCE;
  //    }
      GlobalVariable *GV = new GlobalVariable(M, CE->getType(), true, 
                                              GlobalValue::InternalLinkage, 
                                              CE,
                                              I->getName()+"_"+Twine(v));
      CEMap[CE] = GV;
    }

    // Collect types of all globals.
    const Type *Ty = I->getType();
    if (!typeIDs.count(Ty)) {
      extraTypes.push_back(Ty);
      typeIDs[Ty] = tid++;
      types.push_back(Ty);
    }
  }

  // Sort functions.
  std::vector<Function*> functions;
  for (Module::iterator I=M.begin(),E=M.end(); I != E; ) {
    Function *F = &*I;
    ++I;
    functions.push_back(F);
    F->removeFromParent();
  }
  std::sort(functions.begin(), functions.end(), compare_lt_functions);
  for (std::vector<Function*>::iterator I=functions.begin(),
       E=functions.end(); I != E; ++I) {
    M.getFunctionList().push_back(*I);
  }

  Function *Ep = M.getFunction("entrypoint");
  if (!Ep)
    stop("Bytecode must define an entrypoint (with 0 parameters)!\n", &M);
  if (Ep->getFunctionType()->getNumParams() != 0)
    stop("Bytecode must define an entrypoint with 0 parameters!\n", &M);

  unsigned dbgid = 0;
  MDDbgKind = M.getContext().getMDKindID("dbg");
  for (Module::iterator I=M.begin(),E=M.end(); I != E; ++I) {
    Function &F = *I;
    if (F.isDeclaration()) {
      // Don't add prototypes of debug intrinsics
      if (F.getName().substr(0,8).equals("llvm.dbg"))
        continue;
      if (F.isVarArg()) {
        if (!F.getFunctionType()->getNumParams())
          ClamBCModule::stop("Calling implicitly declared function '" +
                             F.getName()+
                             "' is not supported (did you forget to implement "
                             "it, or called the wrong function?)", &F);
        else
          ClamBCModule::stop("Vararg functions are not supported ('"+
                             F.getName()+"')", &F);
      }
      assert(!F.isVarArg());
      // Add function type
      const FunctionType *FTy = F.getFunctionType();
      if (!typeIDs.count(FTy)) {
        extraTypes.push_back(FTy);
        typeIDs[FTy] = tid++;
        types.push_back(FTy);
      }
      continue;
    }
    functionIDs[&F]=fid++;
    for(Function::arg_iterator I=F.arg_begin(), E=F.arg_end(); I != E; ++I) {
      const Type *Ty = I->getType();
      if (typeIDs.count(Ty))
        continue;
      types.push_back(Ty);
      extraTypes.push_back(Ty);
      typeIDs[Ty] = tid++;
    }
    for(inst_iterator II=inst_begin(F),IE=inst_end(F); II != IE; ++II) {
      const Type *Ty;
      // Skip debug intrinsics, so we don't add llvm.dbg.* types
      if (isa<DbgInfoIntrinsic>(&*II))
        continue;
      if (WriteDI) {
        if (MDNode *Dbg = II->getMetadata(MDDbgKind)) {
          if (!dbgMap.count(Dbg))
            dbgMap[Dbg] = dbgid++;
          anyDbgIds = true;
        }
      }

      // Collect types of all instructions.
      if (const AllocaInst *AI = dyn_cast<AllocaInst>(&*II))
        Ty = AI->getAllocatedType();
      else
        Ty = II->getType();
      if (const GetElementPtrInst *GEPI = dyn_cast<GetElementPtrInst>(&*II)) {
        const Type *GTy = GEPI->getPointerOperand()->getType();
        if (!typeIDs.count(GTy)) {
          types.push_back(GTy);
          extraTypes.push_back(GTy);
          typeIDs[GTy] = tid++;
        }
      }
      if (typeIDs.count(Ty))
        continue;
      types.push_back(Ty);
      extraTypes.push_back(Ty);
      typeIDs[Ty] = tid++;
    }
  }

  // If a type references other types, add those to our typemap too.
  while (!types.empty()) {
    const Type *Ty = types.back();
    types.pop_back();
    for (Type::subtype_iterator I=Ty->subtype_begin(), E=Ty->subtype_end();
         I != E; ++I) {
      const Type *STy = I->get();
      if (isa<OpaqueType>(STy)) {
        if (isa<PointerType>(Ty))
          continue;
        errs() << *STy << "\n";
        stop("Bytecode cannot use abstract types (only pointers to them)!", &M);
      }
      if (!typeIDs.count(STy)) {
        extraTypes.push_back(STy);
        typeIDs[STy] = tid++;
        types.push_back(STy);
      }
    }
  }

  if (tid >= 65536)
    stop("Attempted to use more than 64k types", &M);

  printGlobals(M, startTID);
  return true;
}

void ClamBCModule::describeType(llvm::raw_ostream &Out, const Type *Ty, Module
                                *M)
{
  if (const FunctionType *FTy = dyn_cast<FunctionType>(Ty)) {
    printFixedNumber(Out, 1, 1);
    assert(!FTy->isVarArg());
    printNumber(Out, FTy->getNumParams()+1);
    printNumber(Out, getTypeID(FTy->getReturnType()));
    for (FunctionType::param_iterator I=FTy->param_begin(), E=FTy->param_end();
         I != E; ++I) {
      printNumber(Out, getTypeID(I->get()));
    }
    return;
  }

  if (const StructType *STy = dyn_cast<StructType>(Ty)) {
    TargetData *TD = &getAnalysis<TargetData>();
    // get field offsets and insert explicit padding
    //const StructLayout *SL = TD->getStructLayout(STy);
    //unsigned offset = 0;
    std::vector<unsigned> elements;
    //const Type *I8Ty = Type::getInt8Ty(STy->getContext());
    for (unsigned i=0;i<STy->getNumElements();i++) {
      const Type *Ty = STy->getTypeAtIndex(i);
      if (isa<PointerType>(Ty)) {
        WriteTypeSymbolic(errs(), STy, M);
        STy->dump();
        stop("Pointers inside structs are not supported\n", M);
      }
      unsigned abiAlign = TD->getABITypeAlignment(Ty);
      unsigned typeBits = TD->getTypeSizeInBits(Ty);
      if (Ty->isIntegerTy() && 8*abiAlign < typeBits) {
        Ty->dump();
        errs() << 8*abiAlign << " < " << typeBits << "\n";
        // we've set up a targetdata where alignof(32) == 32, alignof(64) == 64,
        // so that each type is maximally aligned on all architectures.
        stop("Internal error: ABI alignment less than typesize for integer!\n",
             M);
      }
      elements.push_back(getTypeID(Ty));
    }

    printFixedNumber(Out, STy->isPacked() ? 2 : 3, 1);
    printNumber(Out, elements.size());
    for (std::vector<unsigned>::iterator I=elements.begin(), E=elements.end();
         I != E; ++I) {
      printNumber(Out, *I);
    }
    return;
  }

  if (const ArrayType *ATy = dyn_cast<ArrayType>(Ty)) {
    printFixedNumber(Out, 4, 1);
    printNumber(Out, ATy->getNumElements());
    printNumber(Out, getTypeID(ATy->getElementType()));
    return;
  }

  if (const PointerType *PTy = dyn_cast<PointerType>(Ty)) {
    printFixedNumber(Out, 5, 1);
    const Type *ETy = PTy->getElementType();
    // pointers to opaque types are treated as i8*
    int id = isa<OpaqueType>(ETy) ? 8 : getTypeID(ETy);
    printNumber(Out, id);
    return;
  }

  stop ("Unsupported type "+Ty->getDescription(), M);
}

extern "C" const char *clambc_getversion(void);

void ClamBCModule::printString(raw_ostream &Out, const char *string, 
                               unsigned maxlength)
{
  std::string str;
  if (string) {
    StringRef truncatedStr;
    truncatedStr = StringRef(string).substr(0, maxlength);
    str = truncatedStr.str();
  }
  const char *cstr = str.c_str();
  // null terminated cstring
  printConstData(Out, (const unsigned char*)cstr, strlen(cstr)+1);
}


// checks whether the queried functionality level is between min and max.
// a min/max of 0 means no min/max.
static bool checkFunctionalityLevel(unsigned query, unsigned min, unsigned max)
{
  if (min && query < min)
    return false;
  if (max && query > max)
    return false;
  return true;
}

void ClamBCModule::printModuleHeader(Module &M, unsigned startTID, unsigned
                                     maxLine)
{
  NamedMDNode *MinFunc = M.getNamedMetadata("clambc.funcmin");
  NamedMDNode *MaxFunc = M.getNamedMetadata("clambc.funcmax");
  unsigned minfunc = 0;
  unsigned maxfunc = 0;
  if (MinFunc) {
    minfunc = cast<ConstantInt>(MinFunc->getOperand(0)->getOperand(0))->
      getZExtValue();
  }
  if (MaxFunc) {
    maxfunc = cast<ConstantInt>(MaxFunc->getOperand(0)->getOperand(0))->
      getZExtValue();
  }

  OutReal << "ClamBC";
  // Print functionality level
  // 0.96 only knows to skip based on bytecode format level, and has no min/max
  // verification.
  // So if this bytecode is supposed to load on 0.96 use 0.96's format,
  // otherwise use post 0.96 format.
  // In both cases we output the min/max functionality level fields (using 2
  // unused fields from 0.96).
  // 0.96 will ignore these and load it (but we already checked it should load
  // at least on 0.96 via bytecode format). Post 0.96 will check the fields and
  // load/skip based on that.
  // For post 0.96 we use a higher format, so 0.96 will not load it.
  if (checkFunctionalityLevel(FUNC_LEVEL_096, minfunc, maxfunc))
    printNumber(OutReal, BC_FORMAT_096);
  else
    printNumber(OutReal, BC_FORMAT_LEVEL);
  // Bytecode compile timestamp
  printNumber(OutReal, sys::TimeValue::now().toEpochTime());
  const char *user = getenv("SIGNDUSER");
  // fallback to $USER
  if (!user) user = getenv("USER");
  // Sigmaker name
  printString(OutReal, user, 64);
  // Target-exclude. TODO: allow override via a global variable.
  printNumber(OutReal, 0);

  printNumber(OutReal, kind);
  // functionality level min, max, unusued in 0.96!
  printNumber(OutReal, minfunc);
  printNumber(OutReal, maxfunc);

  // Some maximum (unused)
  printNumber(OutReal, 0);

  // Compiler version
  printString(OutReal, clambc_getversion(), 64);

  // Print extra types
  printNumber(OutReal, extraTypes.size() + startTID - 64);
  // Print number of functions
  unsigned count=0;
  for (Module::iterator I=M.begin(),E=M.end(); I != E; ++I) {
    if (I->isDeclaration())
      continue;
    count++;
  }
  printNumber(OutReal, count);

  // Print 2 magic number to ensure reader works properly
  printNumber(OutReal, 0x53e5493e9f3d1c30ull);
  printFixedNumber(OutReal, 42, 2);
  if (maxLine < 4096)
      maxLine = 4096;
  OutReal << ":" << maxLine << "\n";
  // first line must fit into 8k
  assert(OutReal.tell() < 8192);
}

void ClamBCModule::printConstant(Module &M, Constant *C)
{
  if (ConstantExpr *CE = dyn_cast<ConstantExpr>(C)) {
    ConstantExpr *VCE = dyn_cast<ConstantExpr>(CE->stripPointerCasts());
    if (!VCE)
      VCE = CE;
    GlobalVariable *GV =
      dyn_cast<GlobalVariable>(VCE->getOperand(0)->stripPointerCasts());
    if (VCE->getOpcode() == Instruction::GetElementPtr &&
        VCE->getNumOperands() == 2 && GV)  {
      ConstantInt *C1 = dyn_cast<ConstantInt>(VCE->getOperand(1));
      uint64_t v = C1->getValue().getZExtValue();
      printNumber(Out, v, true);
      printNumber(Out, getGlobalID(GV), true);
      return;
    }
    if (VCE->getNumOperands() == 3 && GV) {
      ConstantInt *C0 = dyn_cast<ConstantInt>(VCE->getOperand(1));
      ConstantInt *C1 = dyn_cast<ConstantInt>(VCE->getOperand(2));
      if (C0->isZero()) {
        printNumber(Out, C1->getValue().getZExtValue(), true);
        printNumber(Out, getGlobalID(GV), true);
        return;
      }
    }
    if (CE->getOpcode() == Instruction::BitCast && GV) {
      printNumber(Out, 0, true);
      printNumber(Out, getGlobalID(GV), true);
      return;
    }
  }
  if (C->isNullValue()) {
    printNumber(Out, 0, true);
    return;
  }
  if (ConstantInt *CI = dyn_cast<ConstantInt>(C)) {
    uint64_t v = CI->getValue().getZExtValue();
    printNumber(Out, v, true);
    return;
  }
  assert(!isa<ConstantAggregateZero>(C) && "ConstantAggregateZero with non-null value?");
  assert(!isa<ConstantPointerNull>(C) && "ConstantPointerNull with non-null value?");
  if (isa<ConstantArray>(C) || isa<ConstantStruct>(C)) {
    assert(C->getNumOperands() && "[0xty] arrays are not supported!");
    for (User::op_iterator I=C->op_begin(), E=C->op_end(); I != E; ++I) {
      printConstant(M, cast<Constant>(*I));
    }
    return;
  }
  //TODO: better diagnostics here
  if (isa<ConstantFP>(C)) {
    stop("Floating point constants are not supported!", &M);
  }
  if (isa<ConstantExpr>(C)) {
    C->dump();
    stop("Global variable has runtime-computable constant expression"
         " initializer", &M);
  }
  stop("Unsupported constant type", &M);
}

void ClamBCModule::printGlobals(Module &M, uint16_t stid)
{
  // Describe types
  if (!LogicalSignature.empty())
    Out << LogicalSignature;
  else
    Out << virusnames;
  printEOL();
  Out << "T";
  printFixedNumber(Out, stid, 2);
  unsigned tid = stid;
  for (std::vector<const Type*>::iterator I=extraTypes.begin(),
       E=extraTypes.end(); I != E; ++I) {
    assert(typeIDs[*I] == tid && "internal type ID mismatch");
    describeType(Out, *I, &M);
    tid++;
  }

  // External function calls
  printEOL();
  Out << "E";
  unsigned maxApi = 0;
  std::vector<const Function*> apis;
  for (Module::iterator I=M.begin(), E=M.end(); I != E; ++I) {
    // Skip dead declarations
    if (I->use_empty())
      continue;

    StringRef Name = I->getName();

    // Forbid declaring functions with same name as API call
    if (!I->isDeclaration()) {
      if (apiMap.count(Name)) {
        stop("Attempted to declare function that is part of ClamAV API: "+Name,
             I);
      }
      continue;
    }

    // Forbid the usage of specified functions
    StringMap<unsigned>::iterator K = banMap.find(Name);
    if (K != banMap.end()) {
      stop("Usage of function '"+Name+"' is currently disabled", &M);
    }

    // Skip llvm.* intrinsics
    if (Name.substr(0, 5).equals("llvm."))
      continue;
    if (Name.equals("__is_bigendian") || Name.equals("memcmp") || Name.equals("abort"))
      continue;
    StringMap<unsigned>::iterator J = apiMap.find(Name);
    if (J == apiMap.end()) {
      stop("Call to unknown external function: "+Name, I);
    }

    apiCalls[&*I] = J->second;
    apis.push_back(&*I);
    if (J->second > maxApi)
      maxApi = J->second;
  }

  printNumber(Out, maxApi);
  printNumber(Out, apiCalls.size());
  assert(apis.size() == apiCalls.size());
  for (std::vector<const Function*>::iterator I=apis.begin(),E=apis.end();
       I != E; ++I) {
    const Function *F = *I;
    // function api ID
    printNumber(Out, apiCalls[F]);
    // function prototype
    printNumber(Out, getTypeID(F->getFunctionType()));
    // function name
    std::string Name = F->getNameStr();
    printConstData(Out, (const unsigned char*) Name.c_str(), Name.size()+1);
  }

  // Global constants
  printEOL();
  Out << "G";
  // Collect the initializers for global variables, and their type
  unsigned int i=1;
  unsigned maxGlobal=0;
  SmallPtrSet<GlobalVariable*, 1> specialGlobals;
  for (StringMap<unsigned>::iterator I=globalsMap.begin(),
       E=globalsMap.end(); I != E; ++I) {
    if (GlobalVariable *GV = M.getGlobalVariable(I->getKey())) {
      specialGlobals.insert(GV);
      globals[GV] = I->getValue();
      if (I->getValue() > maxGlobal)
        maxGlobal = I->getValue();
    }
  }
  if (GlobalVariable *GV = M.getGlobalVariable("__clambc_kind"))
    specialGlobals.insert(GV);
  printNumber(Out, maxGlobal);

  std::vector<Constant*> globalInits;
  globalInits.push_back(0);//ConstantPointerNul placeholder
  for (Module::global_iterator I = M.global_begin(), E = M.global_end(); I != E; ++I) {
    if (specialGlobals.count(I))
      continue;
    if (!I->isConstant()) {
      // Non-constant globals can introduce potential race conditions, we
      // don't want that.
      stop("Attempting to declare non-constant global variable: " +
           I->getName(), &M);
    }
    if (!I->hasDefinitiveInitializer()) {
      stop("Attempting to declare a global variable without initializer: " +
           I->getName(), &M);
    }
    if (I->isThreadLocal()) {
      stop("Attempting to declare thread local global variable: " +
           I->getName(), &M);
    }
    if (I->hasSection()) {
      stop("Attempting to declare section for global variable: " +
           I->getName(), &M);
    }
    Constant *C = I->getInitializer();
    if (C->use_empty())
      continue;
    globalInits.push_back(C);
    globals[I] = i++;
    if (i >= 32768) {
      stop("Attempted to use more than 32k global variables!", &M);
    }
  }
  printNumber(Out, globalInits.size());
  for (std::vector<Constant*>::iterator I=globalInits.begin(),
       E=globalInits.end(); I != E; ++I) {
    if (I == globalInits.begin()) {
      assert(!*I);
      printNumber(Out, 0);
      printNumber(Out, 0, true);
      printNumber(Out, 0, false); 
      continue;
    }
    // type of constant
    uint16_t id = getTypeID((*I)->getType());
    printNumber(Out, id);
    // value of constant
    printConstant(M, *I);
    printNumber(Out, 0, false);
  }
  if (anyDbgIds) {
    std::vector<const MDNode*> mds;
    mds.resize(dbgMap.size());
    printEOL();
    Out << "D";
    unsigned mdid = dbgMap.size();
    for (DbgMapTy::iterator I=dbgMap.begin(),E=dbgMap.end();
         I != E; ++I) {
      mds[I->second] = I->first;
    }
    unsigned mdnodes = mdid;
    for (unsigned i=0;i<mdnodes;i++) {
      const MDNode *B = mds[i];
      std::vector<const MDNode*> nodes;
      nodes.push_back(cast<MDNode>(B));
      while (!nodes.empty()) {
        const MDNode *N = nodes.back();
        nodes.pop_back();
        for (unsigned i=0;i<N->getNumOperands();i++) {
          if (MDNode *MD = dyn_cast_or_null<MDNode>(N->getOperand(i))) {
            if (!dbgMap.count(MD)) {
              mds.push_back(MD);
              dbgMap[MD] = mdid++;
              nodes.push_back(MD);
            }
          }
        }
      }
    }
    unsigned size = mds.size();
    if (size > 32) {
      printNumber(Out, 32);
      size -= 32;
    } else
      printNumber(Out, size);
    unsigned cnt = 0, c=0;
    for (std::vector<const MDNode*>::iterator I=mds.begin(),E=mds.end();
         I != E; ++I) {
      if (const MDNode *N = dyn_cast<MDNode>(*I)) {
        printNumber(Out, N->getNumOperands());
        errs() <<  c++ << ":";
        for (unsigned i=0;i<N->getNumOperands();i++) {
          Value *V = N->getOperand(i);
          if (!V) {
            printNumber(Out, 0);
            printNumber(Out, ~0u);
          } else if (MDNode *MB = dyn_cast<MDNode>(V)) {
            printNumber(Out, 0);
            printNumber(Out, getDbgId(MB));
            errs() << getDbgId(MB) << ", ";
          } else if (MDString *MS = dyn_cast<MDString>(V)) {
            printConstData(Out, (const unsigned char*)MS->getString().data(), MS->getLength());
          } else {
            ConstantInt *CI = cast<ConstantInt>(V);
            printNumber(Out, CI->getBitWidth());
            printNumber(Out, CI->getZExtValue());
          }
        }
        errs() << "\n";
      }
      if (++cnt >= 32) {
        printEOL();
        Out << "D";
        if (size > 32) {
          printNumber(Out, 32);
          size -= 32;
        } else
          printNumber(Out, size);
        cnt = 0;
      }
    }
  }
}

char ClamBCModule::ID = 0;


static inline void printSep(bool hasColors)
{
  if (hasColors)
    errs().resetColor();
  errs() << ":";
  if (hasColors)
    errs().changeColor(raw_ostream::SAVEDCOLOR, true);
}

void ClamBCModule::stop(const Twine& Msg, const Module *M)
{
  printDiagnostic(Msg, M);
  exit(42);
}

void ClamBCModule::stop(const Twine& Msg, const Function *F)
{
  printDiagnostic(Msg, F);
  exit(42);
}

void ClamBCModule::stop(const Twine& Msg, const Instruction *I)
{
  printDiagnostic(Msg, I);
  exit(42);
}

void ClamBCModule::printNumber(raw_ostream &Out, uint64_t n, bool constant)
{
  char number[32];
  unsigned i = 0;
  while (n > 0) {
    number[++i] = 0x60 | (n&0xf);
    n >>= 4;
  }
  if (!constant)
    number[0] = 0x60 | i;
  else
    number[0] = 0x40 | i;
  number[++i] = '\0';
  Out << number;
}

void ClamBCModule::printEOL()
{
  int diff;
  Out << "\n";
  Out.flush();
  diff = lineBuffer.size() - lastLinePos;
  lastLinePos = lineBuffer.size();
  assert(diff > 0);
  if (diff > maxLineLength)
    maxLineLength = diff;
}

void ClamBCModule::finished(Module &M)
{
  //maxline+1, 1 more for \0
  printModuleHeader(M, startTID, maxLineLength+1);
  OutReal << Out.str();
  MemoryBuffer *MB = 0;
  const char *start = NULL;
  if (copyright) {
    start = copyright;
  } else {
    if (!SrcFile.empty()) {
      std::string ErrStr;
      MemoryBuffer *MB = MemoryBuffer::getFile(SrcFile, &ErrStr);
      if (!MB) {
        stop("Unable to (re)open input file: "+SrcFile, &M);
      }
      // mapped file is \0 terminated by getFile()
      start = MB->getBufferStart();
    }
  }
  if (!start) {
    ClamBCModule::stop("Bytecode should either have source code or include copyright statement\n", &M);
  }
  OutReal << "S";
  char c;
  unsigned linelength = 0;
  do {
    // skip whitespace at BOL
    do {
      c = *start++;
    } while (c == ' ' || c == '\t');
    while (c != '\n' && c) {
      char b[3] = {0x60 | (c&0xf), 0x60 | ((c>>4)&0xf), '\0'};
      OutReal << b;
      c = *start++;
      linelength++;
    }
    if (c && linelength < 80) {
      OutReal << "S";
    } else {
      OutReal << "\n";
      linelength = 0;
    }
  } while (c);
  if (copyright) {
    free(copyright);
    copyright = 0;
  }
  if (MB)
    delete MB;
}

void ClamBCModule::printFixedNumber(raw_ostream &Out, unsigned n,
                                    unsigned fixed)
{
  char number[32];
  unsigned i=0;
  while (fixed > 0) {
    number[i++] = 0x60 | (n&0xf);
    n >>= 4;
    fixed--;
  }
  assert((n == 0) && "Fixed-width number cannot exceed width");
  number[i] = '\0';
  Out << number;
}

void ClamBCModule::printConstData(raw_ostream &Out, const unsigned char *s,
                                  size_t len)
{
  size_t i;

  Out << "|";
  printNumber(Out, len);
  for (i=0;i<len;i++) {
    char b[3] = {0x60 | (s[i]&0xf), 0x60 | ((s[i]>>4)&0xf), '\0'};
    Out << b;
  }
}

void ClamBCModule::writeGlobalMap(llvm::raw_ostream* Out)
{
  if (!Out)
    return;
  for (GlobalMapTy::iterator I=globals.begin(),E=globals.end();
       I != E; ++I) {
    *Out << "g" << I->second << ": " << *I->first << "\n";
  }
}
