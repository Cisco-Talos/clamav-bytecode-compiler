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
#include "llvm/LLVMContext.h"
#include "llvm/Metadata.h"
#include "llvm/Module.h"
#include "llvm/Pass.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/GetElementPtrTypeIterator.h"
#include "llvm/Support/InstIterator.h"
#include "llvm/Support/InstVisitor.h"
#include "llvm/Support/FormattedStream.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Scalar.h"
using namespace llvm;

static cl::opt<std::string> MapFile("clambc-map",cl::desc("Write compilation map"),
                                    cl::value_desc("File to write the map to"),
                                    cl::init(""));
static cl::opt<bool>
DumpDI("clambc-dumpdi", cl::Hidden, cl::init(false),
       cl::desc("Dump LLVM IR with debug info to standard output"));

class ClamBCWriter : public FunctionPass, public InstVisitor<ClamBCWriter> {
  typedef DenseMap<const BasicBlock*, unsigned> BBIDMap;
  BBIDMap BBMap;

  ClamBCModule *OModule;
  const Module *TheModule;
  const TargetData* TD;
  unsigned opcodecvt[Instruction::OtherOpsEnd];
  raw_ostream *MapOut;
  FunctionPass *Dumper;
  ClamBCRegAlloc *RA;
  unsigned fid;
  MetadataContext *TheMetadata;
  unsigned MDDbgKind;
  std::vector<unsigned> dbgInfo;
  bool anyDbg;

public:
  static char ID;
  explicit ClamBCWriter(ClamBCModule *module)
    : FunctionPass(&ID),
      OModule(module), TheModule(0), TD(0), MapOut(0), Dumper(0) {
    if (!MapFile.empty()) {
      std::string ErrorInfo;
      MapOut = new raw_fd_ostream(MapFile.c_str(), ErrorInfo);
      if (!ErrorInfo.empty()) {
        errs() << "error opening mapfile" << MapFile << ": " << ErrorInfo << "\n";
        MapOut = 0;
      }
    }
  }

  ~ClamBCWriter() {
    if (MapOut) {
      delete MapOut;
    }
  }
  virtual const char *getPassName() const { return "ClamAV Bytecode Backend Writer"; }

  void getAnalysisUsage(AnalysisUsage &AU) const {
    AU.addRequiredID(ClamBCRegAllocID);
    AU.setPreservesAll();
  }

  virtual bool doInitialization(Module &M);

  bool runOnFunction(Function &F) {
    BBMap.clear();
    dbgInfo.clear();
    anyDbg = false;

    if (F.hasAvailableExternallyLinkage())
      return false;
    fid++;
    assert(OModule->getFunctionID(&F) == fid);
    RA = &getAnalysis<ClamBCRegAlloc>();
    printFunction(F);
    if (Dumper)
      Dumper->runOnFunction(F);
    return false;
  }

  virtual bool doFinalization(Module &M) {
    printEOL();
    OModule->finished(M);
    if (MapOut) {
      OModule->dumpTypes(*MapOut);
      MapOut->flush();
    }
    delete TD;
    if (Dumper)
      delete Dumper;
    return false;
  }

private :
  void printNumber(uint64_t c, bool constant=false) {
    OModule->printNumber(c, constant);
  }
  void printFixedNumber(unsigned c, unsigned fixed) {
    OModule->printFixedNumber(c, fixed);
  }
  void printEOL() {
    OModule->printEOL();
  }
  void stop(const std::string &Msg, const llvm::Function *F) {
    ClamBCModule::stop(Msg, F);
  }
  void stop(const std::string &Msg, const llvm::Instruction *I) {
    ClamBCModule::stop(Msg, I);
  }
  void printCount(Module &M, unsigned count, const std::string &What);
  void printType(const Type *Ty, const Function *F=0, const Instruction *I=0);
  void printFunction(Function &);
  void printMapping(const Value *V, unsigned id, bool newline=false);
  void printBasicBlock(BasicBlock *BB);

  static const AllocaInst *isDirectAlloca(const Value *V) {
    const AllocaInst *AI = dyn_cast<AllocaInst>(V);
    if (!AI) return false;
    if (AI->isArrayAllocation())
      return 0;
    if (AI->getParent() != &AI->getParent()->getParent()->getEntryBlock())
      return 0;
    return AI;
  }

  static bool isInlineAsm(const Instruction& I) {
    if (isa<CallInst>(&I) && isa<InlineAsm>(I.getOperand(0)))
      return true;
    return false;
  }

  friend class InstVisitor<ClamBCWriter>;

  void visitGetElementPtrInst(GetElementPtrInst &GEP)
  {
    // Checking is done by the verifier!

    unsigned ops = GEP.getNumIndices();
    assert(ops && "GEP without indices?");
    if (ops > 15) {
      stop("Too many levels of pointer indexing, at most 15 is supported!",
           &GEP);
    }

    switch (ops) {
    case 1:
      printFixedNumber(OP_BC_GEP1, 2);
      assert(!isa<GlobalVariable>(GEP.getOperand(0)) &&
             !isa<ConstantExpr>(GEP.getOperand(0)) &&
             "would hit libclamav interpreter bug");
      {
        int iid = OModule->getTypeID(GEP.getPointerOperand()->getType());
        if (iid > 65)
          stop("gep1 with type > 65 won't work on interpreter", &GEP);
      }
      break;
    case 2:
      if (const ConstantInt *CI = dyn_cast<ConstantInt>(GEP.getOperand(1))) {
        if (CI->isZero()) {
          assert(!isa<GlobalVariable>(GEP.getOperand(0)) &&
                 !isa<ConstantExpr>(GEP.getOperand(0)) &&
                 "would hit libclamav interpreter bug");
	      printFixedNumber(OP_BC_GEPZ, 2);
	      printType(GEP.getPointerOperand()->getType(), 0, &GEP);
	      printOperand(GEP, GEP.getOperand(0));
	      printOperand(GEP, GEP.getOperand(2));
          if (ConstantInt *CI = dyn_cast<ConstantInt>(GEP.getOperand(1))) {
            if (!CI->isZero()) {
              const PointerType *Ty = cast<PointerType>(GEP.getPointerOperand()->getType());
              const ArrayType *ATy = dyn_cast<ArrayType>(Ty->getElementType());
              if (ATy)
                stop("ATy", &GEP);
            }
          }
          return;
        }
      }
      // fall through
    default:
      stop("GEPN", &GEP);
      printFixedNumber(OP_BC_GEPN, 2);
      // If needed we could use DecomposeGEPExpression here.
      if (ops >= 16)
        stop("GEP with more than 15 indices", &GEP);
      printFixedNumber(ops, 1);
      break;
    }
    printType(GEP.getPointerOperand()->getType(), 0, &GEP);
    for (Instruction::op_iterator II=GEP.op_begin(),IE=GEP.op_end(); II != IE;
         ++II) {
      Value *V = *II;
      printOperand(GEP, V);
    }
  }

  void visitLoadInst(LoadInst &LI)
  {
    // Checking is done by the verifier!
    Value *V = LI.getPointerOperand();
    if (isa<AllocaInst>(V) || isa<GlobalVariable>(V)) {
      printFixedNumber(OP_BC_COPY, 2);
      printOperand(LI, V);
      printOperand(LI, &LI);
      return;
    }
    printFixedNumber(OP_BC_LOAD, 2);
    printOperand(LI, V);
  }

  void visitStoreInst(StoreInst &SI)
  {
    Value *V = SI.getPointerOperand();
    // checking is done by the verifier!
    if (isa<GetElementPtrInst>(V) ||
        isa<BitCastInst>(V)) {
      printFixedNumber(OP_BC_STORE, 2);
      printOperand(SI, SI.getOperand(0));
      printOperand(SI, V);
      return;
    }
    V = V->stripPointerCasts();
    if (isa<AllocaInst>(V) || isa<GlobalVariable>(V)) {
      printFixedNumber(OP_BC_COPY, 2);
      printOperand(SI, SI.getOperand(0));
      printOperand(SI, V);
      return;
    }
    // checking is done by the verifier!
    if (isa<GetElementPtrInst>(V)) {
      printFixedNumber(OP_BC_STORE, 2);
      printOperand(SI, SI.getOperand(0));
      printOperand(SI, V);
      return;
    }
    stop("Arbitrary store instructions not yet implemented!\n", &SI);
  }

  void visitCastInst (CastInst &I)
  {
    if (BitCastInst *BCI = dyn_cast<BitCastInst>(&I)) {
      if (BCI->isLosslessCast()) {
        printFixedNumber(OP_BC_GEPZ, 2);
        printType(BCI->getOperand(0)->getType(), 0, BCI);
        printOperand(*BCI, BCI->getOperand(0));
        printNumber(0, true);
        printFixedNumber(4, 1);
        return;
      }
    }

    assert (!I.isLosslessCast());
    LLVMContext &C = I.getContext();
    if (isa<PtrToIntInst>(I) && I.getType() == Type::getInt64Ty(C)) {
      printFixedNumber(OP_BC_PTRTOINT64, 2);
      printOperand(I, I.getOperand(0));
      return;
    }
    HandleOpcodes(I);
  }

  void visitSelectInst (SelectInst &I)
  {
    HandleOpcodes(I);
  }

  void HandleOpcodes(Instruction &I, bool printTy = false)
  {
    unsigned Opc = I.getOpcode();
    assert(Opc < sizeof(opcodecvt)/sizeof(opcodecvt[0]));

    unsigned mapped = opcodecvt[Opc];
    unsigned n = I.getNumOperands();
    assert(mapped < 256 && "At most 255 instruction types are supported!");
    assert(n < 16 && "At most 15 operands are supported!");

    if (!mapped)
      stop("Instruction is not mapped", &I);

    assert(operand_counts[mapped] == n && "Operand count mismatch");
    printFixedNumber(mapped, 2);
    for (Instruction::op_iterator II=I.op_begin(),IE=I.op_end(); II != IE;
         ++II) {
      Value *V = *II;
      if (printTy)
        printType(V->getType());
      printOperand(I, V);
    }
  }

  void printBasicBlockID(BasicBlock *BB)
  {
    unsigned bbid = BBMap[BB];
    assert(bbid && "Unknown basicblock?");
    printNumber(bbid);
  }

  void visitBranchInst(BranchInst &I)
  {
    if (I.isUnconditional()) {
      printFixedNumber(OP_BC_JMP, 2);
      printBasicBlockID(I.getSuccessor(0));
      return;
    }

    assert(I.getNumSuccessors() == 2);
    printFixedNumber(OP_BC_BRANCH, 2);
    printOperand(I, I.getCondition());
    printBasicBlockID(I.getSuccessor(0));
    printBasicBlockID(I.getSuccessor(1));
  }

  void visitSwitchInst(SwitchInst &I)
  {
    stop("ClamAV bytecode backend has not implemented switch statements, please lower ", &I);
  }

  void visitBinaryOperator(Instruction &I)
  {
    assert(!isa<PointerType>(I.getType()));
    if (I.getOpcode() == Instruction::Sub) {
      // sub ptrtoint, ptrtoint
      //TODO: push ptrtoinst through phi nodes!
      LLVMContext &C = I.getContext();
      Instruction *LI = dyn_cast<Instruction>(I.getOperand(0));
      Instruction *RI = dyn_cast<Instruction>(I.getOperand(1));
      if (LI && RI) {
        PtrToIntInst *L = dyn_cast<PtrToIntInst>(LI);
        PtrToIntInst *R = dyn_cast<PtrToIntInst>(RI);
        if (L && R && I.getType() == Type::getInt32Ty(C)) {
          printFixedNumber(OP_BC_PTRDIFF32, 2);
          printOperand(I, L->getOperand(0));
          printOperand(I, R->getOperand(0));
          return;
        }
      }
    }
    HandleOpcodes(I);
  }
  void visitReturnInst(ReturnInst &I)
  {
    if (I.getNumOperands() == 0) {
      // special case ret of void
      printFixedNumber(OP_BC_RET_VOID, 2);
      return;
    }
    HandleOpcodes(I, true);
  }

  void visitUnreachableInst(UnreachableInst &I)
  {
    printFixedNumber(OP_BC_ABORT, 2);
    return;
  }

  void printOperand(Instruction &I, Value *V)
  {
    if(isa<UndefValue>(V)) {
      V = Constant::getNullValue(V->getType());
    }
    if (Constant *C = dyn_cast<Constant>(V)) {
      if (ConstantInt *CI = dyn_cast<ConstantInt>(C)) {
        if (CI->getBitWidth() > 64)
          stop("Integers of more than 64-bits are not supported", &I);
        uint64_t v = CI->getValue().getZExtValue();
        printNumber(v, true);
        printFixedNumber((CI->getBitWidth()+7)/8, 1);
      } else {
        if (GlobalVariable *GV = dyn_cast<GlobalVariable>(C)) {
          printNumber(OModule->getGlobalID(GV), true);
          // a Constant of bitwidth 0 is a global variable
          printFixedNumber(0, 1);
        } else if (ConstantExpr *CE = dyn_cast<ConstantExpr>(C)) {
          if (CE->getOpcode() == Instruction::IntToPtr)
            stop("Cast of integer to pointer not supported", &I);
          printNumber(OModule->getGlobalID(CE), true);
          // a Constant of bitwidth 0 is a global variable
          printFixedNumber(0, 1);
        } else if (isa<ConstantPointerNull>(C)) {
          printNumber(0, true);
          printFixedNumber(0, 1);
        } else {
          stop("Unhandled constant type", &I);
        }
      }
    } else {
      printNumber(RA->getValueID(V));
    }
  }

  void visitICmpInst(ICmpInst &I)
  {
    enum bc_opcode opc;
    switch (I.getPredicate()) {
    case CmpInst::ICMP_EQ:
      opc = OP_BC_ICMP_EQ;
      break;
    case CmpInst::ICMP_NE:
      opc = OP_BC_ICMP_NE;
      break;
    case CmpInst::ICMP_UGT:
      opc = OP_BC_ICMP_UGT;
      break;
    case CmpInst::ICMP_UGE:
      opc = OP_BC_ICMP_UGE;
      break;
    case CmpInst::ICMP_ULT:
      opc = OP_BC_ICMP_ULT;
      break;
    case CmpInst::ICMP_ULE:
      opc = OP_BC_ICMP_ULE;
      break;
    case CmpInst::ICMP_SGT:
      opc = OP_BC_ICMP_SGT;
      break;
    case CmpInst::ICMP_SGE:
      opc = OP_BC_ICMP_SGE;
      break;
    case CmpInst::ICMP_SLE:
      opc = OP_BC_ICMP_SLE;
      break;
    case CmpInst::ICMP_SLT:
      opc = OP_BC_ICMP_SLT;
      break;
    default:
      stop("Unsupported icmp predicate", &I);
    }
    printFixedNumber(opc, 2);
    printType(I.getOperand(0)->getType());
    for (Instruction::op_iterator II=I.op_begin(),IE=I.op_end(); II != IE;
         ++II) {
      Value *V = *II;
      printOperand(I, V);
    }
  }

  void validateAttribute(Attributes A, CallInst &CI, bool internal=false)
  {
    // attributes that don't change codegen from our perspective,
    // ignoring them may pessimize the code.
    const unsigned AcceptMask =
      Attribute::NoUnwind | Attribute::NoAlias |
      Attribute::AlwaysInline | Attribute::NoInline |
      Attribute::OptimizeForSize | Attribute::StackProtect |
      Attribute::NoCapture | Attribute::NoRedZone |
      Attribute::NoImplicitFloat | Attribute::ReadOnly |
      Attribute::ReadNone;
    A &= ~AcceptMask;
    if (internal)
      A &= ~(Attribute::SExt | Attribute::ZExt);
    if (A) {
      std::string Msg = Attribute::getAsString(A);
      stop("Unsupported attributes in call: "+Msg, &CI);
    }
  }

  void visitIntrinsic(unsigned iid, CallInst &CI)
  {
    unsigned numop = 0;
    if (isa<DbgInfoIntrinsic>(CI))
      return;
    switch (iid) {
    case Intrinsic::memset:
      assert(CI.getNumOperands() == 5);
      printFixedNumber(OP_BC_MEMSET, 2);
      numop = 3;
      break;
    case Intrinsic::memcpy:
      assert(CI.getNumOperands() == 5);
      printFixedNumber(OP_BC_MEMCPY, 2);
      numop = 3;
      break;
    case Intrinsic::memmove:
      assert(CI.getNumOperands() == 5);
      printFixedNumber(OP_BC_MEMMOVE, 2);
      numop = 3;
      break;
    case Intrinsic::bswap:
      assert(CI.getNumOperands() == 2);
      numop = 1;
      switch (CI.getType()->getPrimitiveSizeInBits()) {
      case 16:
        printFixedNumber(OP_BC_BSWAP16, 2);
        break;
      case 32:
        printFixedNumber(OP_BC_BSWAP32, 2);
        break;
      case 64:
        printFixedNumber(OP_BC_BSWAP64, 2);
        break;
      default:
        stop("Unsupported bswap bitwidth", &CI);
      }
      break;
    default:
      stop("Unsupported intrinsic call ", &CI);
    }
    for (unsigned i=1;i<numop+1;i++)
      printOperand(CI, CI.getOperand(i));
  }

  void visitCallInst(CallInst &CI) {
    Function *F = CI.getCalledFunction();
    if (!F) {
      stop("Indirect calls are not implemented yet!", &CI);
    }
    if (F->getCallingConv() != CI.getCallingConv()) {
      stop("Calling conventions don't match!", &CI);
    }
    if (F->isVarArg()) {
      stop("Calls to vararg functions are not supported!", &CI);
    }
    if (F->isDeclaration() && F->getName().equals("__is_bigendian")) {
      printFixedNumber(OP_BC_ISBIGENDIAN, 2);
      return;
    }
    if (F->isDeclaration() && F->getName().equals("abort")) {
      printFixedNumber(OP_BC_ABORT, 2);
      return;
    }
    const AttrListPtr &Attrs = CI.getAttributes();
    bool internal = !F->isDeclaration();
    validateAttribute(Attrs.getRetAttributes(), CI, internal);
    validateAttribute(Attrs.getFnAttributes(), CI, internal);
    for (unsigned i=0;i < F->arg_size(); i++)
      validateAttribute(Attrs.getParamAttributes(i+1), CI, internal);

    unsigned iid = F->getIntrinsicID();
    if (iid != Intrinsic::not_intrinsic) {
      visitIntrinsic(iid, CI);
      return;
    }
    if (F->isDeclaration()) {
      if (F->getName().equals("memcmp")) {
        printFixedNumber(OP_BC_MEMCMP, 2);
        printOperand(CI, CI.getOperand(1));
        printOperand(CI, CI.getOperand(2));
        printOperand(CI, CI.getOperand(3));
        return;
      }
      unsigned id = OModule->getExternalID(F);
      printFixedNumber(OP_BC_CALL_API, 2);
      // API calls can have max 15 args
      printFixedNumber(F->arg_size(), 1);
      printNumber(id);
    } else {
      printFixedNumber(OP_BC_CALL_DIRECT, 2);
      if (F->arg_size() > 255)
        stop("Calls can have max 15 parameters", &CI);
      printFixedNumber(F->arg_size(), 1);
      printNumber(OModule->getFunctionID(F));
    }

    for (unsigned i=1;i<CI.getNumOperands();i++) {
      printOperand(CI, CI.getOperand(i));
    }
  }

  void visitInstruction(Instruction &I) {
    stop("ClamAV bytecode backend does not know about ", &I);
  }
};
char ClamBCWriter::ID = 0;
bool ClamBCWriter::doInitialization(Module &M) {
  memset(opcodecvt, 0, sizeof(opcodecvt));

  opcodecvt[Instruction::Add] = OP_BC_ADD;
  opcodecvt[Instruction::Sub] = OP_BC_SUB;
  opcodecvt[Instruction::Mul] = OP_BC_MUL;
  opcodecvt[Instruction::UDiv] = OP_BC_UDIV;
  opcodecvt[Instruction::SDiv] = OP_BC_SDIV;
  opcodecvt[Instruction::URem] = OP_BC_UREM;
  opcodecvt[Instruction::SRem] = OP_BC_SREM;

  opcodecvt[Instruction::Shl] = OP_BC_SHL;
  opcodecvt[Instruction::LShr] = OP_BC_LSHR;
  opcodecvt[Instruction::AShr] = OP_BC_ASHR;
  opcodecvt[Instruction::And] = OP_BC_AND;
  opcodecvt[Instruction::Or] = OP_BC_OR;
  opcodecvt[Instruction::Xor] = OP_BC_XOR;

  opcodecvt[Instruction::Trunc] = OP_BC_TRUNC;
  opcodecvt[Instruction::SExt] = OP_BC_SEXT;
  opcodecvt[Instruction::ZExt] = OP_BC_ZEXT;
  opcodecvt[Instruction::Ret] = OP_BC_RET;
  opcodecvt[Instruction::Select] = OP_BC_SELECT;
  TheModule = &M;

  TD = new TargetData(&M);

  if (DumpDI)
    Dumper = createDbgInfoPrinterPass();
  fid = 0;
  OModule->writeGlobalMap(MapOut);
  MDDbgKind = M.getContext().getMDKindID("dbg");
  return false;
}

void ClamBCWriter::printType(const Type *Ty, const Function *F, const Instruction *I)
{
  if (Ty->isIntegerTy()) {
    LLVMContext &C = Ty->getContext();
    if ((Ty != Type::getInt1Ty(C) && Ty != Type::getInt8Ty(C) && 
         Ty !=Type::getInt16Ty(C) && Ty != Type::getInt32Ty(C) && 
         Ty != Type::getInt64Ty(C))) {
      stop("The ClamAV bytecode backend does not currently support"
           "integer types of widths other than 1, 8, 16, 32, 64.", I);
    }
  } else if (Ty->isFloatingPointTy()) {
    stop("The ClamAV bytecode backend does not support floating point"
         "types", I);
  }

  unsigned id = OModule->getTypeID(Ty);
  assert(id < 32768 && "At most 32k types are supported");
  printNumber(id);
}

void ClamBCWriter::printCount(Module &M, unsigned id, const std::string &What)
{
  if (id >= 65536) {
    std::string Msg("Attempted to use more than 64k " + What);
    ClamBCModule::stop(Msg, &M);
  }
  printNumber(id);
}

void ClamBCWriter::printMapping(const Value *V, unsigned id, bool newline)
{
  if (!MapOut)
    return;
  *MapOut << "Value id " << id << ": " << *V << "\n";
}

void ClamBCWriter::printFunction(Function &F) {     
  if (F.hasStructRetAttr())
    stop("Functions with struct ret are not supported", &F);

  if (MapOut) {
    *MapOut << "Function " << (OModule->getFunctionID(&F)-1) << ": " <<
      F.getName() << "\n\n";
  }
  printEOL();
  OModule->printOne('A');
  printFixedNumber(F.arg_size(), 1);
  printType(F.getReturnType());

  OModule->printOne('L');

  unsigned id = 0;
  for (inst_iterator I = inst_begin(&F), E = inst_end(&F); I != E; ++I) {
    id++;
  }
  if (id >= 32768) /* upper 32k "operands" are globals */
    stop("Attempted to use more than 32k instructions", &F);


  std::vector<const Value*> reverseValueMap;
  id = RA->buildReverseMap(reverseValueMap);
  printCount(*F.getParent(), id - F.arg_size(), "values");
  /* We can't iterate directly on the densemap when writing bytecode, because:
   *  - iteration is non-deterministic, because DenseMaps are  sorted by pointer
   *      values that change each run
   *  - we need to write out types in order of increasing IDs, otherwise we'd
   *      have to write out the ID with the type */
  for (unsigned i=0;i<id;i++) {
    const Type *Ty;
    const Value *V = reverseValueMap[i];
    assert(V && "Null Value in idmap?");
    if (const AllocaInst *AI = dyn_cast<AllocaInst>(V)) {
      if (AI->isArrayAllocation() && !isa<ArrayType>(AI->getAllocatedType()))
        stop("VLAs are not (yet) supported", AI);
      if (AI->isArrayAllocation())
	    stop("Array allocs are not supported", AI);
      Ty = AI->getAllocatedType();
    } else {
      Ty = V->getType();
    }
    printMapping(V, i, isa<Argument>(V));
    printType(Ty, 0, dyn_cast<Instruction>(V));
    printFixedNumber(isa<AllocaInst>(V), 1);
  }

  OModule->printOne('F');
  unsigned instructions=0;
  for(inst_iterator II=inst_begin(F),IE=inst_end(F); II != IE; ++II) {
    if (isa<AllocaInst>(*II) || isa<DbgInfoIntrinsic>(*II))
      continue;
    if (!isa<TerminatorInst>(&*II) && RA->skipInstruction(&*II)) {
      continue;
    }
    instructions++;
  }
  printNumber(instructions);

  id = 0;// entry BB gets ID 0, because it can have no predecessors
  for (Function::iterator BB = F.begin(), E = F.end(); BB != E; ++BB) {
    BBMap[&*BB] = id++;
  }
  printCount(*F.getParent(), id, "basic blocks");

  for (Function::iterator BB = F.begin(), E = F.end(); BB != E; ++BB) {
    printBasicBlock(BB);
  }

  OModule->printOne('E');
  if (anyDbg) {
    OModule->printOne('D');
    OModule->printOne('B');
    OModule->printOne('G');
    printNumber(dbgInfo.size());
    for (std::vector<unsigned>::iterator I=dbgInfo.begin(),E=dbgInfo.end();
         I != E; ++I) {
      printNumber(*I);
    }
  }
}

void ClamBCWriter::printBasicBlock(BasicBlock *BB) {
  printEOL();
  OModule->printOne('B');

  for (BasicBlock::iterator II = BB->begin(), E = --BB->end(); II != E;
       ++II) {
    if (isa<AllocaInst>(II) || isa<DbgInfoIntrinsic>(II))
      continue;
    if (isInlineAsm(*II))
      stop("Inline assembly is not allowed", II);
    if (RA->skipInstruction(&*II))
      continue;
    const Type *Ty = II->getType();
    if (StoreInst *SI = dyn_cast<StoreInst>(II)) {
      printType(SI->getOperand(0)->getType());
    } else {
      printType(Ty);
    }
    if (Ty->getTypeID() != Type::VoidTyID)
      printNumber(RA->getValueID(&*II));
    else
      printNumber(0);
    visit(*II);
    if (OModule->hasDbgIds() && MDDbgKind) {
      MDNode *Dbg = II->getMetadata(MDDbgKind);
      if (Dbg) {
        dbgInfo.push_back(OModule->getDbgId(Dbg));
        anyDbg = true;
      }
      else
        dbgInfo.push_back(~0u);
    }
  }

  OModule->printOne('T');
  visit(*BB->getTerminator());
  if (OModule->hasDbgIds() && MDDbgKind) {
    MDNode *Dbg = BB->getTerminator()->getMetadata(MDDbgKind);
    if (Dbg) {
      dbgInfo.push_back(OModule->getDbgId(Dbg));
      anyDbg = true;
    }
    else
      dbgInfo.push_back(~0u);
  }
}

llvm::FunctionPass *createClamBCWriter(ClamBCModule *module)
{
  return new ClamBCWriter(module);
}
