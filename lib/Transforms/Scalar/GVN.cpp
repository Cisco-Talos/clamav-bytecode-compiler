//===- GVN.cpp - Eliminate redundant values and loads ---------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This pass performs global value numbering to eliminate fully redundant
// instructions.  It also performs simple dead load elimination.
//
// Note that this pass does the value numbering itself; it does not use the
// ValueNumbering analysis passes.
//
//===----------------------------------------------------------------------===//

#define DEBUG_TYPE "gvn"
#include "llvm/Transforms/Scalar.h"
#include "llvm/BasicBlock.h"
#include "llvm/Constants.h"
#include "llvm/DerivedTypes.h"
#include "llvm/GlobalVariable.h"
#include "llvm/Function.h"
#include "llvm/IntrinsicInst.h"
#include "llvm/LLVMContext.h"
#include "llvm/Operator.h"
#include "llvm/Value.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DepthFirstIterator.h"
#include "llvm/ADT/PostOrderIterator.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Analysis/ConstantFolding.h"
#include "llvm/Analysis/Dominators.h"
#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/Analysis/MemoryDependenceAnalysis.h"
#include "llvm/Analysis/PHITransAddr.h"
#include "llvm/Support/CFG.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/GetElementPtrTypeIterator.h"
#include "llvm/Support/IRBuilder.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetData.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Transforms/Utils/SSAUpdater.h"
using namespace llvm;

STATISTIC(NumGVNInstr,  "Number of instructions deleted");
STATISTIC(NumGVNLoad,   "Number of loads deleted");
STATISTIC(NumGVNPRE,    "Number of instructions PRE'd");
STATISTIC(NumGVNBlocks, "Number of blocks merged");
STATISTIC(NumPRELoad,   "Number of loads PRE'd");

static cl::opt<bool> EnablePRE("enable-pre",
                               cl::init(true), cl::Hidden);
static cl::opt<bool> EnableLoadPRE("enable-load-pre", cl::init(true));
static cl::opt<bool> EnableFullLoadPRE("enable-full-load-pre", cl::init(false));

//===----------------------------------------------------------------------===//
//                         ValueTable Class
//===----------------------------------------------------------------------===//

/// This class holds the mapping between values and value numbers.  It is used
/// as an efficient mechanism to determine the expression-wise equivalence of
/// two values.
namespace {
  struct Expression {
    enum ExpressionOpcode { 
      ADD = Instruction::Add,
      FADD = Instruction::FAdd,
      SUB = Instruction::Sub,
      FSUB = Instruction::FSub,
      MUL = Instruction::Mul,
      FMUL = Instruction::FMul,
      UDIV = Instruction::UDiv,
      SDIV = Instruction::SDiv,
      FDIV = Instruction::FDiv,
      UREM = Instruction::URem,
      SREM = Instruction::SRem,
      FREM = Instruction::FRem,
      SHL = Instruction::Shl,
      LSHR = Instruction::LShr,
      ASHR = Instruction::AShr,
      AND = Instruction::And,
      OR = Instruction::Or,
      XOR = Instruction::Xor,
      TRUNC = Instruction::Trunc,
      ZEXT = Instruction::ZExt,
      SEXT = Instruction::SExt,
      FPTOUI = Instruction::FPToUI,
      FPTOSI = Instruction::FPToSI,
      UITOFP = Instruction::UIToFP,
      SITOFP = Instruction::SIToFP,
      FPTRUNC = Instruction::FPTrunc,
      FPEXT = Instruction::FPExt,
      PTRTOINT = Instruction::PtrToInt,
      INTTOPTR = Instruction::IntToPtr,
      BITCAST = Instruction::BitCast,
      ICMPEQ, ICMPNE, ICMPUGT, ICMPUGE, ICMPULT, ICMPULE,
      ICMPSGT, ICMPSGE, ICMPSLT, ICMPSLE, FCMPOEQ,
      FCMPOGT, FCMPOGE, FCMPOLT, FCMPOLE, FCMPONE,
      FCMPORD, FCMPUNO, FCMPUEQ, FCMPUGT, FCMPUGE,
      FCMPULT, FCMPULE, FCMPUNE, EXTRACT, INSERT,
      SHUFFLE, SELECT, GEP, CALL, CONSTANT,
      INSERTVALUE, EXTRACTVALUE, EMPTY, TOMBSTONE };

    ExpressionOpcode opcode;
    const Type* type;
    SmallVector<uint32_t, 4> varargs;
    Value *function;

    Expression() { }
    Expression(ExpressionOpcode o) : opcode(o) { }

    bool operator==(const Expression &other) const {
      if (opcode != other.opcode)
        return false;
      else if (opcode == EMPTY || opcode == TOMBSTONE)
        return true;
      else if (type != other.type)
        return false;
      else if (function != other.function)
        return false;
      else {
        if (varargs.size() != other.varargs.size())
          return false;

        for (size_t i = 0; i < varargs.size(); ++i)
          if (varargs[i] != other.varargs[i])
            return false;

        return true;
      }
    }

    bool operator!=(const Expression &other) const {
      return !(*this == other);
    }
  };

  class ValueTable {
    private:
      DenseMap<Value*, uint32_t> valueNumbering;
      DenseMap<Expression, uint32_t> expressionNumbering;
      AliasAnalysis* AA;
      MemoryDependenceAnalysis* MD;
      DominatorTree* DT;

      uint32_t nextValueNumber;

      Expression::ExpressionOpcode getOpcode(CmpInst* C);
      Expression create_expression(BinaryOperator* BO);
      Expression create_expression(CmpInst* C);
      Expression create_expression(ShuffleVectorInst* V);
      Expression create_expression(ExtractElementInst* C);
      Expression create_expression(InsertElementInst* V);
      Expression create_expression(SelectInst* V);
      Expression create_expression(CastInst* C);
      Expression create_expression(GetElementPtrInst* G);
      Expression create_expression(CallInst* C);
      Expression create_expression(Constant* C);
      Expression create_expression(ExtractValueInst* C);
      Expression create_expression(InsertValueInst* C);
      
      uint32_t lookup_or_add_call(CallInst* C);
    public:
      ValueTable() : nextValueNumber(1) { }
      uint32_t lookup_or_add(Value *V);
      uint32_t lookup(Value *V) const;
      void add(Value *V, uint32_t num);
      void clear();
      void erase(Value *v);
      unsigned size();
      void setAliasAnalysis(AliasAnalysis* A) { AA = A; }
      AliasAnalysis *getAliasAnalysis() const { return AA; }
      void setMemDep(MemoryDependenceAnalysis* M) { MD = M; }
      void setDomTree(DominatorTree* D) { DT = D; }
      uint32_t getNextUnusedValueNumber() { return nextValueNumber; }
      void verifyRemoved(const Value *) const;
  };
}

namespace llvm {
template <> struct DenseMapInfo<Expression> {
  static inline Expression getEmptyKey() {
    return Expression(Expression::EMPTY);
  }

  static inline Expression getTombstoneKey() {
    return Expression(Expression::TOMBSTONE);
  }

  static unsigned getHashValue(const Expression e) {
    unsigned hash = e.opcode;

    hash = ((unsigned)((uintptr_t)e.type >> 4) ^
            (unsigned)((uintptr_t)e.type >> 9));

    for (SmallVector<uint32_t, 4>::const_iterator I = e.varargs.begin(),
         E = e.varargs.end(); I != E; ++I)
      hash = *I + hash * 37;

    hash = ((unsigned)((uintptr_t)e.function >> 4) ^
            (unsigned)((uintptr_t)e.function >> 9)) +
           hash * 37;

    return hash;
  }
  static bool isEqual(const Expression &LHS, const Expression &RHS) {
    return LHS == RHS;
  }
};
  
template <>
struct isPodLike<Expression> { static const bool value = true; };

}

//===----------------------------------------------------------------------===//
//                     ValueTable Internal Functions
//===----------------------------------------------------------------------===//

Expression::ExpressionOpcode ValueTable::getOpcode(CmpInst* C) {
  if (isa<ICmpInst>(C)) {
    switch (C->getPredicate()) {
    default:  // THIS SHOULD NEVER HAPPEN
      llvm_unreachable("Comparison with unknown predicate?");
    case ICmpInst::ICMP_EQ:  return Expression::ICMPEQ;
    case ICmpInst::ICMP_NE:  return Expression::ICMPNE;
    case ICmpInst::ICMP_UGT: return Expression::ICMPUGT;
    case ICmpInst::ICMP_UGE: return Expression::ICMPUGE;
    case ICmpInst::ICMP_ULT: return Expression::ICMPULT;
    case ICmpInst::ICMP_ULE: return Expression::ICMPULE;
    case ICmpInst::ICMP_SGT: return Expression::ICMPSGT;
    case ICmpInst::ICMP_SGE: return Expression::ICMPSGE;
    case ICmpInst::ICMP_SLT: return Expression::ICMPSLT;
    case ICmpInst::ICMP_SLE: return Expression::ICMPSLE;
    }
  } else {
    switch (C->getPredicate()) {
    default: // THIS SHOULD NEVER HAPPEN
      llvm_unreachable("Comparison with unknown predicate?");
    case FCmpInst::FCMP_OEQ: return Expression::FCMPOEQ;
    case FCmpInst::FCMP_OGT: return Expression::FCMPOGT;
    case FCmpInst::FCMP_OGE: return Expression::FCMPOGE;
    case FCmpInst::FCMP_OLT: return Expression::FCMPOLT;
    case FCmpInst::FCMP_OLE: return Expression::FCMPOLE;
    case FCmpInst::FCMP_ONE: return Expression::FCMPONE;
    case FCmpInst::FCMP_ORD: return Expression::FCMPORD;
    case FCmpInst::FCMP_UNO: return Expression::FCMPUNO;
    case FCmpInst::FCMP_UEQ: return Expression::FCMPUEQ;
    case FCmpInst::FCMP_UGT: return Expression::FCMPUGT;
    case FCmpInst::FCMP_UGE: return Expression::FCMPUGE;
    case FCmpInst::FCMP_ULT: return Expression::FCMPULT;
    case FCmpInst::FCMP_ULE: return Expression::FCMPULE;
    case FCmpInst::FCMP_UNE: return Expression::FCMPUNE;
    }
  }
}

Expression ValueTable::create_expression(CallInst* C) {
  Expression e;

  e.type = C->getType();
  e.function = C->getCalledFunction();
  e.opcode = Expression::CALL;

  for (CallInst::op_iterator I = C->op_begin()+1, E = C->op_end();
       I != E; ++I)
    e.varargs.push_back(lookup_or_add(*I));

  return e;
}

Expression ValueTable::create_expression(BinaryOperator* BO) {
  Expression e;
  e.varargs.push_back(lookup_or_add(BO->getOperand(0)));
  e.varargs.push_back(lookup_or_add(BO->getOperand(1)));
  e.function = 0;
  e.type = BO->getType();
  e.opcode = static_cast<Expression::ExpressionOpcode>(BO->getOpcode());

  return e;
}

Expression ValueTable::create_expression(CmpInst* C) {
  Expression e;

  e.varargs.push_back(lookup_or_add(C->getOperand(0)));
  e.varargs.push_back(lookup_or_add(C->getOperand(1)));
  e.function = 0;
  e.type = C->getType();
  e.opcode = getOpcode(C);

  return e;
}

Expression ValueTable::create_expression(CastInst* C) {
  Expression e;

  e.varargs.push_back(lookup_or_add(C->getOperand(0)));
  e.function = 0;
  e.type = C->getType();
  e.opcode = static_cast<Expression::ExpressionOpcode>(C->getOpcode());

  return e;
}

Expression ValueTable::create_expression(ShuffleVectorInst* S) {
  Expression e;

  e.varargs.push_back(lookup_or_add(S->getOperand(0)));
  e.varargs.push_back(lookup_or_add(S->getOperand(1)));
  e.varargs.push_back(lookup_or_add(S->getOperand(2)));
  e.function = 0;
  e.type = S->getType();
  e.opcode = Expression::SHUFFLE;

  return e;
}

Expression ValueTable::create_expression(ExtractElementInst* E) {
  Expression e;

  e.varargs.push_back(lookup_or_add(E->getOperand(0)));
  e.varargs.push_back(lookup_or_add(E->getOperand(1)));
  e.function = 0;
  e.type = E->getType();
  e.opcode = Expression::EXTRACT;

  return e;
}

Expression ValueTable::create_expression(InsertElementInst* I) {
  Expression e;

  e.varargs.push_back(lookup_or_add(I->getOperand(0)));
  e.varargs.push_back(lookup_or_add(I->getOperand(1)));
  e.varargs.push_back(lookup_or_add(I->getOperand(2)));
  e.function = 0;
  e.type = I->getType();
  e.opcode = Expression::INSERT;

  return e;
}

Expression ValueTable::create_expression(SelectInst* I) {
  Expression e;

  e.varargs.push_back(lookup_or_add(I->getCondition()));
  e.varargs.push_back(lookup_or_add(I->getTrueValue()));
  e.varargs.push_back(lookup_or_add(I->getFalseValue()));
  e.function = 0;
  e.type = I->getType();
  e.opcode = Expression::SELECT;

  return e;
}

Expression ValueTable::create_expression(GetElementPtrInst* G) {
  Expression e;

  e.varargs.push_back(lookup_or_add(G->getPointerOperand()));
  e.function = 0;
  e.type = G->getType();
  e.opcode = Expression::GEP;

  for (GetElementPtrInst::op_iterator I = G->idx_begin(), E = G->idx_end();
       I != E; ++I)
    e.varargs.push_back(lookup_or_add(*I));

  return e;
}

Expression ValueTable::create_expression(ExtractValueInst* E) {
  Expression e;

  e.varargs.push_back(lookup_or_add(E->getAggregateOperand()));
  for (ExtractValueInst::idx_iterator II = E->idx_begin(), IE = E->idx_end();
       II != IE; ++II)
    e.varargs.push_back(*II);
  e.function = 0;
  e.type = E->getType();
  e.opcode = Expression::EXTRACTVALUE;

  return e;
}

Expression ValueTable::create_expression(InsertValueInst* E) {
  Expression e;

  e.varargs.push_back(lookup_or_add(E->getAggregateOperand()));
  e.varargs.push_back(lookup_or_add(E->getInsertedValueOperand()));
  for (InsertValueInst::idx_iterator II = E->idx_begin(), IE = E->idx_end();
       II != IE; ++II)
    e.varargs.push_back(*II);
  e.function = 0;
  e.type = E->getType();
  e.opcode = Expression::INSERTVALUE;

  return e;
}

//===----------------------------------------------------------------------===//
//                     ValueTable External Functions
//===----------------------------------------------------------------------===//

/// add - Insert a value into the table with a specified value number.
void ValueTable::add(Value *V, uint32_t num) {
  valueNumbering.insert(std::make_pair(V, num));
}

uint32_t ValueTable::lookup_or_add_call(CallInst* C) {
  if (AA->doesNotAccessMemory(C)) {
    Expression exp = create_expression(C);
    uint32_t& e = expressionNumbering[exp];
    if (!e) e = nextValueNumber++;
    valueNumbering[C] = e;
    return e;
  } else if (AA->onlyReadsMemory(C)) {
    Expression exp = create_expression(C);
    uint32_t& e = expressionNumbering[exp];
    if (!e) {
      e = nextValueNumber++;
      valueNumbering[C] = e;
      return e;
    }
    if (!MD) {
      e = nextValueNumber++;
      valueNumbering[C] = e;
      return e;
    }

    MemDepResult local_dep = MD->getDependency(C);

    if (!local_dep.isDef() && !local_dep.isNonLocal()) {
      valueNumbering[C] =  nextValueNumber;
      return nextValueNumber++;
    }

    if (local_dep.isDef()) {
      CallInst* local_cdep = cast<CallInst>(local_dep.getInst());

      if (local_cdep->getNumOperands() != C->getNumOperands()) {
        valueNumbering[C] = nextValueNumber;
        return nextValueNumber++;
      }

      for (unsigned i = 1; i < C->getNumOperands(); ++i) {
        uint32_t c_vn = lookup_or_add(C->getOperand(i));
        uint32_t cd_vn = lookup_or_add(local_cdep->getOperand(i));
        if (c_vn != cd_vn) {
          valueNumbering[C] = nextValueNumber;
          return nextValueNumber++;
        }
      }

      uint32_t v = lookup_or_add(local_cdep);
      valueNumbering[C] = v;
      return v;
    }

    // Non-local case.
    const MemoryDependenceAnalysis::NonLocalDepInfo &deps =
      MD->getNonLocalCallDependency(CallSite(C));
    // FIXME: call/call dependencies for readonly calls should return def, not
    // clobber!  Move the checking logic to MemDep!
    CallInst* cdep = 0;

    // Check to see if we have a single dominating call instruction that is
    // identical to C.
    for (unsigned i = 0, e = deps.size(); i != e; ++i) {
      const NonLocalDepEntry *I = &deps[i];
      // Ignore non-local dependencies.
      if (I->getResult().isNonLocal())
        continue;

      // We don't handle non-depedencies.  If we already have a call, reject
      // instruction dependencies.
      if (I->getResult().isClobber() || cdep != 0) {
        cdep = 0;
        break;
      }

      CallInst *NonLocalDepCall = dyn_cast<CallInst>(I->getResult().getInst());
      // FIXME: All duplicated with non-local case.
      if (NonLocalDepCall && DT->properlyDominates(I->getBB(), C->getParent())){
        cdep = NonLocalDepCall;
        continue;
      }

      cdep = 0;
      break;
    }

    if (!cdep) {
      valueNumbering[C] = nextValueNumber;
      return nextValueNumber++;
    }

    if (cdep->getNumOperands() != C->getNumOperands()) {
      valueNumbering[C] = nextValueNumber;
      return nextValueNumber++;
    }
    for (unsigned i = 1; i < C->getNumOperands(); ++i) {
      uint32_t c_vn = lookup_or_add(C->getOperand(i));
      uint32_t cd_vn = lookup_or_add(cdep->getOperand(i));
      if (c_vn != cd_vn) {
        valueNumbering[C] = nextValueNumber;
        return nextValueNumber++;
      }
    }

    uint32_t v = lookup_or_add(cdep);
    valueNumbering[C] = v;
    return v;

  } else {
    valueNumbering[C] = nextValueNumber;
    return nextValueNumber++;
  }
}

/// lookup_or_add - Returns the value number for the specified value, assigning
/// it a new number if it did not have one before.
uint32_t ValueTable::lookup_or_add(Value *V) {
  DenseMap<Value*, uint32_t>::iterator VI = valueNumbering.find(V);
  if (VI != valueNumbering.end())
    return VI->second;

  if (!isa<Instruction>(V)) {
    valueNumbering[V] = nextValueNumber;
    return nextValueNumber++;
  }
  
  Instruction* I = cast<Instruction>(V);
  Expression exp;
  switch (I->getOpcode()) {
    case Instruction::Call:
      return lookup_or_add_call(cast<CallInst>(I));
    case Instruction::Add:
    case Instruction::FAdd:
    case Instruction::Sub:
    case Instruction::FSub:
    case Instruction::Mul:
    case Instruction::FMul:
    case Instruction::UDiv:
    case Instruction::SDiv:
    case Instruction::FDiv:
    case Instruction::URem:
    case Instruction::SRem:
    case Instruction::FRem:
    case Instruction::Shl:
    case Instruction::LShr:
    case Instruction::AShr:
    case Instruction::And:
    case Instruction::Or :
    case Instruction::Xor:
      exp = create_expression(cast<BinaryOperator>(I));
      break;
    case Instruction::ICmp:
    case Instruction::FCmp:
      exp = create_expression(cast<CmpInst>(I));
      break;
    case Instruction::Trunc:
    case Instruction::ZExt:
    case Instruction::SExt:
    case Instruction::FPToUI:
    case Instruction::FPToSI:
    case Instruction::UIToFP:
    case Instruction::SIToFP:
    case Instruction::FPTrunc:
    case Instruction::FPExt:
    case Instruction::PtrToInt:
    case Instruction::IntToPtr:
    case Instruction::BitCast:
      exp = create_expression(cast<CastInst>(I));
      break;
    case Instruction::Select:
      exp = create_expression(cast<SelectInst>(I));
      break;
    case Instruction::ExtractElement:
      exp = create_expression(cast<ExtractElementInst>(I));
      break;
    case Instruction::InsertElement:
      exp = create_expression(cast<InsertElementInst>(I));
      break;
    case Instruction::ShuffleVector:
      exp = create_expression(cast<ShuffleVectorInst>(I));
      break;
    case Instruction::ExtractValue:
      exp = create_expression(cast<ExtractValueInst>(I));
      break;
    case Instruction::InsertValue:
      exp = create_expression(cast<InsertValueInst>(I));
      break;      
    case Instruction::GetElementPtr:
      exp = create_expression(cast<GetElementPtrInst>(I));
      break;
    default:
      valueNumbering[V] = nextValueNumber;
      return nextValueNumber++;
  }

  uint32_t& e = expressionNumbering[exp];
  if (!e) e = nextValueNumber++;
  valueNumbering[V] = e;
  return e;
}

/// lookup - Returns the value number of the specified value. Fails if
/// the value has not yet been numbered.
uint32_t ValueTable::lookup(Value *V) const {
  DenseMap<Value*, uint32_t>::const_iterator VI = valueNumbering.find(V);
  assert(VI != valueNumbering.end() && "Value not numbered?");
  return VI->second;
}

/// clear - Remove all entries from the ValueTable
void ValueTable::clear() {
  valueNumbering.clear();
  expressionNumbering.clear();
  nextValueNumber = 1;
}

/// erase - Remove a value from the value numbering
void ValueTable::erase(Value *V) {
  valueNumbering.erase(V);
}

/// verifyRemoved - Verify that the value is removed from all internal data
/// structures.
void ValueTable::verifyRemoved(const Value *V) const {
  for (DenseMap<Value*, uint32_t>::const_iterator
         I = valueNumbering.begin(), E = valueNumbering.end(); I != E; ++I) {
    assert(I->first != V && "Inst still occurs in value numbering map!");
  }
}

//===----------------------------------------------------------------------===//
//                                GVN Pass
//===----------------------------------------------------------------------===//

namespace {
  struct ValueNumberScope {
    ValueNumberScope* parent;
    DenseMap<uint32_t, Value*> table;

    ValueNumberScope(ValueNumberScope* p) : parent(p) { }
  };
}

namespace {

  class GVN : public FunctionPass {
    bool runOnFunction(Function &F);
  public:
    static char ID; // Pass identification, replacement for typeid
    explicit GVN(bool nopre = false, bool noloads = false)
      : FunctionPass(&ID), NoPRE(nopre), NoLoads(noloads), MD(0) { }

  private:
    bool NoPRE;
    bool NoLoads;
    MemoryDependenceAnalysis *MD;
    DominatorTree *DT;

    ValueTable VN;
    DenseMap<BasicBlock*, ValueNumberScope*> localAvail;

    // List of critical edges to be split between iterations.
    SmallVector<std::pair<TerminatorInst*, unsigned>, 4> toSplit;

    // This transformation requires dominator postdominator info
    virtual void getAnalysisUsage(AnalysisUsage &AU) const {
      AU.addRequired<DominatorTree>();
      if (!NoLoads)
        AU.addRequired<MemoryDependenceAnalysis>();
      AU.addRequired<AliasAnalysis>();

      AU.addPreserved<DominatorTree>();
      AU.addPreserved<AliasAnalysis>();
    }

    // Helper fuctions
    // FIXME: eliminate or document these better
    bool processLoad(LoadInst* L,
                     SmallVectorImpl<Instruction*> &toErase);
    bool processInstruction(Instruction *I,
                            SmallVectorImpl<Instruction*> &toErase);
    bool processNonLocalLoad(LoadInst* L,
                             SmallVectorImpl<Instruction*> &toErase);
    bool processBlock(BasicBlock *BB);
    void dump(DenseMap<uint32_t, Value*>& d);
    bool iterateOnFunction(Function &F);
    Value *CollapsePhi(PHINode* p);
    bool performPRE(Function& F);
    Value *lookupNumber(BasicBlock *BB, uint32_t num);
    void cleanupGlobalSets();
    void verifyRemoved(const Instruction *I) const;
    bool splitCriticalEdges();
  };

  char GVN::ID = 0;
}

// createGVNPass - The public interface to this file...
FunctionPass *llvm::createGVNPass(bool NoPRE, bool NoLoads) {
  return new GVN(NoPRE, NoLoads);
}

static RegisterPass<GVN> X("gvn",
                           "Global Value Numbering");

void GVN::dump(DenseMap<uint32_t, Value*>& d) {
  errs() << "{\n";
  for (DenseMap<uint32_t, Value*>::iterator I = d.begin(),
       E = d.end(); I != E; ++I) {
      errs() << I->first << "\n";
      I->second->dump();
  }
  errs() << "}\n";
}

static bool isSafeReplacement(PHINode* p, Instruction *inst) {
  if (!isa<PHINode>(inst))
    return true;

  for (Instruction::use_iterator UI = p->use_begin(), E = p->use_end();
       UI != E; ++UI)
    if (PHINode* use_phi = dyn_cast<PHINode>(UI))
      if (use_phi->getParent() == inst->getParent())
        return false;

  return true;
}

Value *GVN::CollapsePhi(PHINode *PN) {
  Value *ConstVal = PN->hasConstantValue(DT);
  if (!ConstVal) return 0;

  Instruction *Inst = dyn_cast<Instruction>(ConstVal);
  if (!Inst)
    return ConstVal;

  if (DT->dominates(Inst, PN))
    if (isSafeReplacement(PN, Inst))
      return Inst;
  return 0;
}

/// IsValueFullyAvailableInBlock - Return true if we can prove that the value
/// we're analyzing is fully available in the specified block.  As we go, keep
/// track of which blocks we know are fully alive in FullyAvailableBlocks.  This
/// map is actually a tri-state map with the following values:
///   0) we know the block *is not* fully available.
///   1) we know the block *is* fully available.
///   2) we do not know whether the block is fully available or not, but we are
///      currently speculating that it will be.
///   3) we are speculating for this block and have used that to speculate for
///      other blocks.
static bool IsValueFullyAvailableInBlock(BasicBlock *BB,
                            DenseMap<BasicBlock*, char> &FullyAvailableBlocks) {
  // Optimistically assume that the block is fully available and check to see
  // if we already know about this block in one lookup.
  std::pair<DenseMap<BasicBlock*, char>::iterator, char> IV =
    FullyAvailableBlocks.insert(std::make_pair(BB, 2));

  // If the entry already existed for this block, return the precomputed value.
  if (!IV.second) {
    // If this is a speculative "available" value, mark it as being used for
    // speculation of other blocks.
    if (IV.first->second == 2)
      IV.first->second = 3;
    return IV.first->second != 0;
  }

  // Otherwise, see if it is fully available in all predecessors.
  pred_iterator PI = pred_begin(BB), PE = pred_end(BB);

  // If this block has no predecessors, it isn't live-in here.
  if (PI == PE)
    goto SpeculationFailure;

  for (; PI != PE; ++PI)
    // If the value isn't fully available in one of our predecessors, then it
    // isn't fully available in this block either.  Undo our previous
    // optimistic assumption and bail out.
    if (!IsValueFullyAvailableInBlock(*PI, FullyAvailableBlocks))
      goto SpeculationFailure;

  return true;

// SpeculationFailure - If we get here, we found out that this is not, after
// all, a fully-available block.  We have a problem if we speculated on this and
// used the speculation to mark other blocks as available.
SpeculationFailure:
  char &BBVal = FullyAvailableBlocks[BB];

  // If we didn't speculate on this, just return with it set to false.
  if (BBVal == 2) {
    BBVal = 0;
    return false;
  }

  // If we did speculate on this value, we could have blocks set to 1 that are
  // incorrect.  Walk the (transitive) successors of this block and mark them as
  // 0 if set to one.
  SmallVector<BasicBlock*, 32> BBWorklist;
  BBWorklist.push_back(BB);

  do {
    BasicBlock *Entry = BBWorklist.pop_back_val();
    // Note that this sets blocks to 0 (unavailable) if they happen to not
    // already be in FullyAvailableBlocks.  This is safe.
    char &EntryVal = FullyAvailableBlocks[Entry];
    if (EntryVal == 0) continue;  // Already unavailable.

    // Mark as unavailable.
    EntryVal = 0;

    for (succ_iterator I = succ_begin(Entry), E = succ_end(Entry); I != E; ++I)
      BBWorklist.push_back(*I);
  } while (!BBWorklist.empty());

  return false;
}


/// CanCoerceMustAliasedValueToLoad - Return true if
/// CoerceAvailableValueToLoadType will succeed.
static bool CanCoerceMustAliasedValueToLoad(Value *StoredVal,
                                            const Type *LoadTy,
                                            const TargetData &TD) {
  // If the loaded or stored value is an first class array or struct, don't try
  // to transform them.  We need to be able to bitcast to integer.
  if (LoadTy->isStructTy() || LoadTy->isArrayTy() ||
      StoredVal->getType()->isStructTy() ||
      StoredVal->getType()->isArrayTy())
    return false;
  
  // The store has to be at least as big as the load.
  if (TD.getTypeSizeInBits(StoredVal->getType()) <
        TD.getTypeSizeInBits(LoadTy))
    return false;
  
  return true;
}
  

/// CoerceAvailableValueToLoadType - If we saw a store of a value to memory, and
/// then a load from a must-aliased pointer of a different type, try to coerce
/// the stored value.  LoadedTy is the type of the load we want to replace and
/// InsertPt is the place to insert new instructions.
///
/// If we can't do it, return null.
static Value *CoerceAvailableValueToLoadType(Value *StoredVal, 
                                             const Type *LoadedTy,
                                             Instruction *InsertPt,
                                             const TargetData &TD) {
  if (!CanCoerceMustAliasedValueToLoad(StoredVal, LoadedTy, TD))
    return 0;
  
  const Type *StoredValTy = StoredVal->getType();
  
  uint64_t StoreSize = TD.getTypeSizeInBits(StoredValTy);
  uint64_t LoadSize = TD.getTypeSizeInBits(LoadedTy);
  
  // If the store and reload are the same size, we can always reuse it.
  if (StoreSize == LoadSize) {
    if (StoredValTy->isPointerTy() && LoadedTy->isPointerTy()) {
      // Pointer to Pointer -> use bitcast.
      return new BitCastInst(StoredVal, LoadedTy, "", InsertPt);
    }
    
    // Convert source pointers to integers, which can be bitcast.
    if (StoredValTy->isPointerTy()) {
      StoredValTy = TD.getIntPtrType(StoredValTy->getContext());
      StoredVal = new PtrToIntInst(StoredVal, StoredValTy, "", InsertPt);
    }
    
    const Type *TypeToCastTo = LoadedTy;
    if (TypeToCastTo->isPointerTy())
      TypeToCastTo = TD.getIntPtrType(StoredValTy->getContext());
    
    if (StoredValTy != TypeToCastTo)
      StoredVal = new BitCastInst(StoredVal, TypeToCastTo, "", InsertPt);
    
    // Cast to pointer if the load needs a pointer type.
    if (LoadedTy->isPointerTy())
      StoredVal = new IntToPtrInst(StoredVal, LoadedTy, "", InsertPt);
    
    return StoredVal;
  }
  
  // If the loaded value is smaller than the available value, then we can
  // extract out a piece from it.  If the available value is too small, then we
  // can't do anything.
  assert(StoreSize >= LoadSize && "CanCoerceMustAliasedValueToLoad fail");
  
  // Convert source pointers to integers, which can be manipulated.
  if (StoredValTy->isPointerTy()) {
    StoredValTy = TD.getIntPtrType(StoredValTy->getContext());
    StoredVal = new PtrToIntInst(StoredVal, StoredValTy, "", InsertPt);
  }
  
  // Convert vectors and fp to integer, which can be manipulated.
  if (!StoredValTy->isIntegerTy()) {
    StoredValTy = IntegerType::get(StoredValTy->getContext(), StoreSize);
    StoredVal = new BitCastInst(StoredVal, StoredValTy, "", InsertPt);
  }
  
  // If this is a big-endian system, we need to shift the value down to the low
  // bits so that a truncate will work.
  if (TD.isBigEndian()) {
    Constant *Val = ConstantInt::get(StoredVal->getType(), StoreSize-LoadSize);
    StoredVal = BinaryOperator::CreateLShr(StoredVal, Val, "tmp", InsertPt);
  }
  
  // Truncate the integer to the right size now.
  const Type *NewIntTy = IntegerType::get(StoredValTy->getContext(), LoadSize);
  StoredVal = new TruncInst(StoredVal, NewIntTy, "trunc", InsertPt);
  
  if (LoadedTy == NewIntTy)
    return StoredVal;
  
  // If the result is a pointer, inttoptr.
  if (LoadedTy->isPointerTy())
    return new IntToPtrInst(StoredVal, LoadedTy, "inttoptr", InsertPt);
  
  // Otherwise, bitcast.
  return new BitCastInst(StoredVal, LoadedTy, "bitcast", InsertPt);
}

/// GetBaseWithConstantOffset - Analyze the specified pointer to see if it can
/// be expressed as a base pointer plus a constant offset.  Return the base and
/// offset to the caller.
static Value *GetBaseWithConstantOffset(Value *Ptr, int64_t &Offset,
                                        const TargetData &TD) {
  Operator *PtrOp = dyn_cast<Operator>(Ptr);
  if (PtrOp == 0) return Ptr;
  
  // Just look through bitcasts.
  if (PtrOp->getOpcode() == Instruction::BitCast)
    return GetBaseWithConstantOffset(PtrOp->getOperand(0), Offset, TD);
  
  // If this is a GEP with constant indices, we can look through it.
  GEPOperator *GEP = dyn_cast<GEPOperator>(PtrOp);
  if (GEP == 0 || !GEP->hasAllConstantIndices()) return Ptr;
  
  gep_type_iterator GTI = gep_type_begin(GEP);
  for (User::op_iterator I = GEP->idx_begin(), E = GEP->idx_end(); I != E;
       ++I, ++GTI) {
    ConstantInt *OpC = cast<ConstantInt>(*I);
    if (OpC->isZero()) continue;
    
    // Handle a struct and array indices which add their offset to the pointer.
    if (const StructType *STy = dyn_cast<StructType>(*GTI)) {
      Offset += TD.getStructLayout(STy)->getElementOffset(OpC->getZExtValue());
    } else {
      uint64_t Size = TD.getTypeAllocSize(GTI.getIndexedType());
      Offset += OpC->getSExtValue()*Size;
    }
  }
  
  // Re-sign extend from the pointer size if needed to get overflow edge cases
  // right.
  unsigned PtrSize = TD.getPointerSizeInBits();
  if (PtrSize < 64)
    Offset = (Offset << (64-PtrSize)) >> (64-PtrSize);
  
  return GetBaseWithConstantOffset(GEP->getPointerOperand(), Offset, TD);
}


/// AnalyzeLoadFromClobberingWrite - This function is called when we have a
/// memdep query of a load that ends up being a clobbering memory write (store,
/// memset, memcpy, memmove).  This means that the write *may* provide bits used
/// by the load but we can't be sure because the pointers don't mustalias.
///
/// Check this case to see if there is anything more we can do before we give
/// up.  This returns -1 if we have to give up, or a byte number in the stored
/// value of the piece that feeds the load.
static int AnalyzeLoadFromClobberingWrite(const Type *LoadTy, Value *LoadPtr,
                                          Value *WritePtr,
                                          uint64_t WriteSizeInBits,
                                          const TargetData &TD) {
  // If the loaded or stored value is an first class array or struct, don't try
  // to transform them.  We need to be able to bitcast to integer.
  if (LoadTy->isStructTy() || LoadTy->isArrayTy())
    return -1;
  
  int64_t StoreOffset = 0, LoadOffset = 0;
  Value *StoreBase = GetBaseWithConstantOffset(WritePtr, StoreOffset, TD);
  Value *LoadBase = 
    GetBaseWithConstantOffset(LoadPtr, LoadOffset, TD);
  if (StoreBase != LoadBase)
    return -1;
  
  // If the load and store are to the exact same address, they should have been
  // a must alias.  AA must have gotten confused.
  // FIXME: Study to see if/when this happens.
  if (LoadOffset == StoreOffset) {
#if 0
    dbgs() << "STORE/LOAD DEP WITH COMMON POINTER MISSED:\n"
    << "Base       = " << *StoreBase << "\n"
    << "Store Ptr  = " << *WritePtr << "\n"
    << "Store Offs = " << StoreOffset << "\n"
    << "Load Ptr   = " << *LoadPtr << "\n";
    abort();
#endif
    return -1;
  }
  
  // If the load and store don't overlap at all, the store doesn't provide
  // anything to the load.  In this case, they really don't alias at all, AA
  // must have gotten confused.
  // FIXME: Investigate cases where this bails out, e.g. rdar://7238614. Then
  // remove this check, as it is duplicated with what we have below.
  uint64_t LoadSize = TD.getTypeSizeInBits(LoadTy);
  
  if ((WriteSizeInBits & 7) | (LoadSize & 7))
    return -1;
  uint64_t StoreSize = WriteSizeInBits >> 3;  // Convert to bytes.
  LoadSize >>= 3;
  
  
  bool isAAFailure = false;
  if (StoreOffset < LoadOffset) {
    isAAFailure = StoreOffset+int64_t(StoreSize) <= LoadOffset;
  } else {
    isAAFailure = LoadOffset+int64_t(LoadSize) <= StoreOffset;
  }
  if (isAAFailure) {
#if 0
    dbgs() << "STORE LOAD DEP WITH COMMON BASE:\n"
    << "Base       = " << *StoreBase << "\n"
    << "Store Ptr  = " << *WritePtr << "\n"
    << "Store Offs = " << StoreOffset << "\n"
    << "Load Ptr   = " << *LoadPtr << "\n";
    abort();
#endif
    return -1;
  }
  
  // If the Load isn't completely contained within the stored bits, we don't
  // have all the bits to feed it.  We could do something crazy in the future
  // (issue a smaller load then merge the bits in) but this seems unlikely to be
  // valuable.
  if (StoreOffset > LoadOffset ||
      StoreOffset+StoreSize < LoadOffset+LoadSize)
    return -1;
  
  // Okay, we can do this transformation.  Return the number of bytes into the
  // store that the load is.
  return LoadOffset-StoreOffset;
}  

/// AnalyzeLoadFromClobberingStore - This function is called when we have a
/// memdep query of a load that ends up being a clobbering store.
static int AnalyzeLoadFromClobberingStore(const Type *LoadTy, Value *LoadPtr,
                                          StoreInst *DepSI,
                                          const TargetData &TD) {
  // Cannot handle reading from store of first-class aggregate yet.
  if (DepSI->getOperand(0)->getType()->isStructTy() ||
      DepSI->getOperand(0)->getType()->isArrayTy())
    return -1;

  Value *StorePtr = DepSI->getPointerOperand();
  uint64_t StoreSize = TD.getTypeSizeInBits(DepSI->getOperand(0)->getType());
  return AnalyzeLoadFromClobberingWrite(LoadTy, LoadPtr,
                                        StorePtr, StoreSize, TD);
}

static int AnalyzeLoadFromClobberingMemInst(const Type *LoadTy, Value *LoadPtr,
                                            MemIntrinsic *MI,
                                            const TargetData &TD) {
  // If the mem operation is a non-constant size, we can't handle it.
  ConstantInt *SizeCst = dyn_cast<ConstantInt>(MI->getLength());
  if (SizeCst == 0) return -1;
  uint64_t MemSizeInBits = SizeCst->getZExtValue()*8;

  // If this is memset, we just need to see if the offset is valid in the size
  // of the memset..
  if (MI->getIntrinsicID() == Intrinsic::memset)
    return AnalyzeLoadFromClobberingWrite(LoadTy, LoadPtr, MI->getDest(),
                                          MemSizeInBits, TD);
  
  // If we have a memcpy/memmove, the only case we can handle is if this is a
  // copy from constant memory.  In that case, we can read directly from the
  // constant memory.
  MemTransferInst *MTI = cast<MemTransferInst>(MI);
  
  Constant *Src = dyn_cast<Constant>(MTI->getSource());
  if (Src == 0) return -1;
  
  GlobalVariable *GV = dyn_cast<GlobalVariable>(Src->getUnderlyingObject());
  if (GV == 0 || !GV->isConstant()) return -1;
  
  // See if the access is within the bounds of the transfer.
  int Offset = AnalyzeLoadFromClobberingWrite(LoadTy, LoadPtr,
                                              MI->getDest(), MemSizeInBits, TD);
  if (Offset == -1)
    return Offset;
  
  // Otherwise, see if we can constant fold a load from the constant with the
  // offset applied as appropriate.
  Src = ConstantExpr::getBitCast(Src,
                                 llvm::Type::getInt8PtrTy(Src->getContext()));
  Constant *OffsetCst = 
    ConstantInt::get(Type::getInt64Ty(Src->getContext()), (unsigned)Offset);
  Src = ConstantExpr::getGetElementPtr(Src, &OffsetCst, 1);
  Src = ConstantExpr::getBitCast(Src, PointerType::getUnqual(LoadTy));
  if (ConstantFoldLoadFromConstPtr(Src, &TD))
    return Offset;
  return -1;
}
                                            

/// GetStoreValueForLoad - This function is called when we have a
/// memdep query of a load that ends up being a clobbering store.  This means
/// that the store *may* provide bits used by the load but we can't be sure
/// because the pointers don't mustalias.  Check this case to see if there is
/// anything more we can do before we give up.
static Value *GetStoreValueForLoad(Value *SrcVal, unsigned Offset,
                                   const Type *LoadTy,
                                   Instruction *InsertPt, const TargetData &TD){
  LLVMContext &Ctx = SrcVal->getType()->getContext();
  
  uint64_t StoreSize = TD.getTypeSizeInBits(SrcVal->getType())/8;
  uint64_t LoadSize = TD.getTypeSizeInBits(LoadTy)/8;
  
  IRBuilder<> Builder(InsertPt->getParent(), InsertPt);
  
  // Compute which bits of the stored value are being used by the load.  Convert
  // to an integer type to start with.
  if (SrcVal->getType()->isPointerTy())
    SrcVal = Builder.CreatePtrToInt(SrcVal, TD.getIntPtrType(Ctx), "tmp");
  if (!SrcVal->getType()->isIntegerTy())
    SrcVal = Builder.CreateBitCast(SrcVal, IntegerType::get(Ctx, StoreSize*8),
                                   "tmp");
  
  // Shift the bits to the least significant depending on endianness.
  unsigned ShiftAmt;
  if (TD.isLittleEndian())
    ShiftAmt = Offset*8;
  else
    ShiftAmt = (StoreSize-LoadSize-Offset)*8;
  
  if (ShiftAmt)
    SrcVal = Builder.CreateLShr(SrcVal, ShiftAmt, "tmp");
  
  if (LoadSize != StoreSize)
    SrcVal = Builder.CreateTrunc(SrcVal, IntegerType::get(Ctx, LoadSize*8),
                                 "tmp");
  
  return CoerceAvailableValueToLoadType(SrcVal, LoadTy, InsertPt, TD);
}

/// GetMemInstValueForLoad - This function is called when we have a
/// memdep query of a load that ends up being a clobbering mem intrinsic.
static Value *GetMemInstValueForLoad(MemIntrinsic *SrcInst, unsigned Offset,
                                     const Type *LoadTy, Instruction *InsertPt,
                                     const TargetData &TD){
  LLVMContext &Ctx = LoadTy->getContext();
  uint64_t LoadSize = TD.getTypeSizeInBits(LoadTy)/8;

  IRBuilder<> Builder(InsertPt->getParent(), InsertPt);
  
  // We know that this method is only called when the mem transfer fully
  // provides the bits for the load.
  if (MemSetInst *MSI = dyn_cast<MemSetInst>(SrcInst)) {
    // memset(P, 'x', 1234) -> splat('x'), even if x is a variable, and
    // independently of what the offset is.
    Value *Val = MSI->getValue();
    if (LoadSize != 1)
      Val = Builder.CreateZExt(Val, IntegerType::get(Ctx, LoadSize*8));
    
    Value *OneElt = Val;
    
    // Splat the value out to the right number of bits.
    for (unsigned NumBytesSet = 1; NumBytesSet != LoadSize; ) {
      // If we can double the number of bytes set, do it.
      if (NumBytesSet*2 <= LoadSize) {
        Value *ShVal = Builder.CreateShl(Val, NumBytesSet*8);
        Val = Builder.CreateOr(Val, ShVal);
        NumBytesSet <<= 1;
        continue;
      }
      
      // Otherwise insert one byte at a time.
      Value *ShVal = Builder.CreateShl(Val, 1*8);
      Val = Builder.CreateOr(OneElt, ShVal);
      ++NumBytesSet;
    }
    
    return CoerceAvailableValueToLoadType(Val, LoadTy, InsertPt, TD);
  }
 
  // Otherwise, this is a memcpy/memmove from a constant global.
  MemTransferInst *MTI = cast<MemTransferInst>(SrcInst);
  Constant *Src = cast<Constant>(MTI->getSource());

  // Otherwise, see if we can constant fold a load from the constant with the
  // offset applied as appropriate.
  Src = ConstantExpr::getBitCast(Src,
                                 llvm::Type::getInt8PtrTy(Src->getContext()));
  Constant *OffsetCst = 
  ConstantInt::get(Type::getInt64Ty(Src->getContext()), (unsigned)Offset);
  Src = ConstantExpr::getGetElementPtr(Src, &OffsetCst, 1);
  Src = ConstantExpr::getBitCast(Src, PointerType::getUnqual(LoadTy));
  return ConstantFoldLoadFromConstPtr(Src, &TD);
}



struct AvailableValueInBlock {
  /// BB - The basic block in question.
  BasicBlock *BB;
  enum ValType {
    SimpleVal,  // A simple offsetted value that is accessed.
    MemIntrin   // A memory intrinsic which is loaded from.
  };
  
  /// V - The value that is live out of the block.
  PointerIntPair<Value *, 1, ValType> Val;
  
  /// Offset - The byte offset in Val that is interesting for the load query.
  unsigned Offset;
  
  static AvailableValueInBlock get(BasicBlock *BB, Value *V,
                                   unsigned Offset = 0) {
    AvailableValueInBlock Res;
    Res.BB = BB;
    Res.Val.setPointer(V);
    Res.Val.setInt(SimpleVal);
    Res.Offset = Offset;
    return Res;
  }

  static AvailableValueInBlock getMI(BasicBlock *BB, MemIntrinsic *MI,
                                     unsigned Offset = 0) {
    AvailableValueInBlock Res;
    Res.BB = BB;
    Res.Val.setPointer(MI);
    Res.Val.setInt(MemIntrin);
    Res.Offset = Offset;
    return Res;
  }
  
  bool isSimpleValue() const { return Val.getInt() == SimpleVal; }
  Value *getSimpleValue() const {
    assert(isSimpleValue() && "Wrong accessor");
    return Val.getPointer();
  }
  
  MemIntrinsic *getMemIntrinValue() const {
    assert(!isSimpleValue() && "Wrong accessor");
    return cast<MemIntrinsic>(Val.getPointer());
  }
  
  /// MaterializeAdjustedValue - Emit code into this block to adjust the value
  /// defined here to the specified type.  This handles various coercion cases.
  Value *MaterializeAdjustedValue(const Type *LoadTy,
                                  const TargetData *TD) const {
    Value *Res;
    if (isSimpleValue()) {
      Res = getSimpleValue();
      if (Res->getType() != LoadTy) {
        assert(TD && "Need target data to handle type mismatch case");
        Res = GetStoreValueForLoad(Res, Offset, LoadTy, BB->getTerminator(),
                                   *TD);
        
        DEBUG(errs() << "GVN COERCED NONLOCAL VAL:\nOffset: " << Offset << "  "
                     << *getSimpleValue() << '\n'
                     << *Res << '\n' << "\n\n\n");
      }
    } else {
      Res = GetMemInstValueForLoad(getMemIntrinValue(), Offset,
                                   LoadTy, BB->getTerminator(), *TD);
      DEBUG(errs() << "GVN COERCED NONLOCAL MEM INTRIN:\nOffset: " << Offset
                   << "  " << *getMemIntrinValue() << '\n'
                   << *Res << '\n' << "\n\n\n");
    }
    return Res;
  }
};

/// ConstructSSAForLoadSet - Given a set of loads specified by ValuesPerBlock,
/// construct SSA form, allowing us to eliminate LI.  This returns the value
/// that should be used at LI's definition site.
static Value *ConstructSSAForLoadSet(LoadInst *LI, 
                         SmallVectorImpl<AvailableValueInBlock> &ValuesPerBlock,
                                     const TargetData *TD,
                                     const DominatorTree &DT,
                                     AliasAnalysis *AA) {
  // Check for the fully redundant, dominating load case.  In this case, we can
  // just use the dominating value directly.
  if (ValuesPerBlock.size() == 1 && 
      DT.properlyDominates(ValuesPerBlock[0].BB, LI->getParent()))
    return ValuesPerBlock[0].MaterializeAdjustedValue(LI->getType(), TD);

  // Otherwise, we have to construct SSA form.
  SmallVector<PHINode*, 8> NewPHIs;
  SSAUpdater SSAUpdate(&NewPHIs);
  SSAUpdate.Initialize(LI);
  
  const Type *LoadTy = LI->getType();
  
  for (unsigned i = 0, e = ValuesPerBlock.size(); i != e; ++i) {
    const AvailableValueInBlock &AV = ValuesPerBlock[i];
    BasicBlock *BB = AV.BB;
    
    if (SSAUpdate.HasValueForBlock(BB))
      continue;

    SSAUpdate.AddAvailableValue(BB, AV.MaterializeAdjustedValue(LoadTy, TD));
  }
  
  // Perform PHI construction.
  Value *V = SSAUpdate.GetValueInMiddleOfBlock(LI->getParent());
  
  // If new PHI nodes were created, notify alias analysis.
  if (V->getType()->isPointerTy())
    for (unsigned i = 0, e = NewPHIs.size(); i != e; ++i)
      AA->copyValue(LI, NewPHIs[i]);

  return V;
}

static bool isLifetimeStart(Instruction *Inst) {
  if (IntrinsicInst* II = dyn_cast<IntrinsicInst>(Inst))
    return II->getIntrinsicID() == Intrinsic::lifetime_start;
  return false;
}

/// processNonLocalLoad - Attempt to eliminate a load whose dependencies are
/// non-local by performing PHI construction.
bool GVN::processNonLocalLoad(LoadInst *LI,
                              SmallVectorImpl<Instruction*> &toErase) {
  // Find the non-local dependencies of the load.
  SmallVector<NonLocalDepResult, 64> Deps;
  MD->getNonLocalPointerDependency(LI->getOperand(0), true, LI->getParent(),
                                   Deps);
  //DEBUG(dbgs() << "INVESTIGATING NONLOCAL LOAD: "
  //             << Deps.size() << *LI << '\n');

  // If we had to process more than one hundred blocks to find the
  // dependencies, this load isn't worth worrying about.  Optimizing
  // it will be too expensive.
  if (Deps.size() > 100)
    return false;

  // If we had a phi translation failure, we'll have a single entry which is a
  // clobber in the current block.  Reject this early.
  if (Deps.size() == 1 && Deps[0].getResult().isClobber()) {
    DEBUG(
      dbgs() << "GVN: non-local load ";
      WriteAsOperand(dbgs(), LI);
      dbgs() << " is clobbered by " << *Deps[0].getResult().getInst() << '\n';
    );
    return false;
  }

  // Filter out useless results (non-locals, etc).  Keep track of the blocks
  // where we have a value available in repl, also keep track of whether we see
  // dependencies that produce an unknown value for the load (such as a call
  // that could potentially clobber the load).
  SmallVector<AvailableValueInBlock, 16> ValuesPerBlock;
  SmallVector<BasicBlock*, 16> UnavailableBlocks;

  const TargetData *TD = 0;
  
  for (unsigned i = 0, e = Deps.size(); i != e; ++i) {
    BasicBlock *DepBB = Deps[i].getBB();
    MemDepResult DepInfo = Deps[i].getResult();

    if (DepInfo.isClobber()) {
      // The address being loaded in this non-local block may not be the same as
      // the pointer operand of the load if PHI translation occurs.  Make sure
      // to consider the right address.
      Value *Address = Deps[i].getAddress();
      
      // If the dependence is to a store that writes to a superset of the bits
      // read by the load, we can extract the bits we need for the load from the
      // stored value.
      if (StoreInst *DepSI = dyn_cast<StoreInst>(DepInfo.getInst())) {
        if (TD == 0)
          TD = getAnalysisIfAvailable<TargetData>();
        if (TD && Address) {
          int Offset = AnalyzeLoadFromClobberingStore(LI->getType(), Address,
                                                      DepSI, *TD);
          if (Offset != -1) {
            ValuesPerBlock.push_back(AvailableValueInBlock::get(DepBB,
                                                           DepSI->getOperand(0),
                                                                Offset));
            continue;
          }
        }
      }

      // If the clobbering value is a memset/memcpy/memmove, see if we can
      // forward a value on from it.
      if (MemIntrinsic *DepMI = dyn_cast<MemIntrinsic>(DepInfo.getInst())) {
        if (TD == 0)
          TD = getAnalysisIfAvailable<TargetData>();
        if (TD && Address) {
          int Offset = AnalyzeLoadFromClobberingMemInst(LI->getType(), Address,
                                                        DepMI, *TD);
          if (Offset != -1) {
            ValuesPerBlock.push_back(AvailableValueInBlock::getMI(DepBB, DepMI,
                                                                  Offset));
            continue;
          }            
        }
      }
      
      UnavailableBlocks.push_back(DepBB);
      continue;
    }

    Instruction *DepInst = DepInfo.getInst();

    // Loading the allocation -> undef.
    if (isa<AllocaInst>(DepInst) || isMalloc(DepInst) ||
        // Loading immediately after lifetime begin -> undef.
        isLifetimeStart(DepInst)) {
      ValuesPerBlock.push_back(AvailableValueInBlock::get(DepBB,
                                             UndefValue::get(LI->getType())));
      continue;
    }
    
    if (StoreInst *S = dyn_cast<StoreInst>(DepInst)) {
      // Reject loads and stores that are to the same address but are of
      // different types if we have to.
      if (S->getOperand(0)->getType() != LI->getType()) {
        if (TD == 0)
          TD = getAnalysisIfAvailable<TargetData>();
        
        // If the stored value is larger or equal to the loaded value, we can
        // reuse it.
        if (TD == 0 || !CanCoerceMustAliasedValueToLoad(S->getOperand(0),
                                                        LI->getType(), *TD)) {
          UnavailableBlocks.push_back(DepBB);
          continue;
        }
      }

      ValuesPerBlock.push_back(AvailableValueInBlock::get(DepBB,
                                                          S->getOperand(0)));
      continue;
    }
    
    if (LoadInst *LD = dyn_cast<LoadInst>(DepInst)) {
      // If the types mismatch and we can't handle it, reject reuse of the load.
      if (LD->getType() != LI->getType()) {
        if (TD == 0)
          TD = getAnalysisIfAvailable<TargetData>();
        
        // If the stored value is larger or equal to the loaded value, we can
        // reuse it.
        if (TD == 0 || !CanCoerceMustAliasedValueToLoad(LD, LI->getType(),*TD)){
          UnavailableBlocks.push_back(DepBB);
          continue;
        }          
      }
      ValuesPerBlock.push_back(AvailableValueInBlock::get(DepBB, LD));
      continue;
    }
    
    UnavailableBlocks.push_back(DepBB);
    continue;
  }

  // If we have no predecessors that produce a known value for this load, exit
  // early.
  if (ValuesPerBlock.empty()) return false;

  // If all of the instructions we depend on produce a known value for this
  // load, then it is fully redundant and we can use PHI insertion to compute
  // its value.  Insert PHIs and remove the fully redundant value now.
  if (UnavailableBlocks.empty()) {
    DEBUG(dbgs() << "GVN REMOVING NONLOCAL LOAD: " << *LI << '\n');
    
    // Perform PHI construction.
    Value *V = ConstructSSAForLoadSet(LI, ValuesPerBlock, TD, *DT,
                                      VN.getAliasAnalysis());
    LI->replaceAllUsesWith(V);

    if (isa<PHINode>(V))
      V->takeName(LI);
    if (V->getType()->isPointerTy())
      MD->invalidateCachedPointerInfo(V);
    VN.erase(LI);
    toErase.push_back(LI);
    NumGVNLoad++;
    return true;
  }

  if (!EnablePRE || !EnableLoadPRE)
    return false;

  // Okay, we have *some* definitions of the value.  This means that the value
  // is available in some of our (transitive) predecessors.  Lets think about
  // doing PRE of this load.  This will involve inserting a new load into the
  // predecessor when it's not available.  We could do this in general, but
  // prefer to not increase code size.  As such, we only do this when we know
  // that we only have to insert *one* load (which means we're basically moving
  // the load, not inserting a new one).

  SmallPtrSet<BasicBlock *, 4> Blockers;
  for (unsigned i = 0, e = UnavailableBlocks.size(); i != e; ++i)
    Blockers.insert(UnavailableBlocks[i]);

  // Lets find first basic block with more than one predecessor.  Walk backwards
  // through predecessors if needed.
  BasicBlock *LoadBB = LI->getParent();
  BasicBlock *TmpBB = LoadBB;

  bool isSinglePred = false;
  bool allSingleSucc = true;
  while (TmpBB->getSinglePredecessor()) {
    isSinglePred = true;
    TmpBB = TmpBB->getSinglePredecessor();
    if (TmpBB == LoadBB) // Infinite (unreachable) loop.
      return false;
    if (Blockers.count(TmpBB))
      return false;
    if (TmpBB->getTerminator()->getNumSuccessors() != 1)
      allSingleSucc = false;
  }

  assert(TmpBB);
  LoadBB = TmpBB;

  // If we have a repl set with LI itself in it, this means we have a loop where
  // at least one of the values is LI.  Since this means that we won't be able
  // to eliminate LI even if we insert uses in the other predecessors, we will
  // end up increasing code size.  Reject this by scanning for LI.
  if (!EnableFullLoadPRE) {
    for (unsigned i = 0, e = ValuesPerBlock.size(); i != e; ++i)
      if (ValuesPerBlock[i].isSimpleValue() &&
          ValuesPerBlock[i].getSimpleValue() == LI)
        return false;
  }

  // FIXME: It is extremely unclear what this loop is doing, other than
  // artificially restricting loadpre.
  if (isSinglePred) {
    bool isHot = false;
    for (unsigned i = 0, e = ValuesPerBlock.size(); i != e; ++i) {
      const AvailableValueInBlock &AV = ValuesPerBlock[i];
      if (AV.isSimpleValue())
        // "Hot" Instruction is in some loop (because it dominates its dep.
        // instruction).
        if (Instruction *I = dyn_cast<Instruction>(AV.getSimpleValue()))
          if (DT->dominates(LI, I)) {
            isHot = true;
            break;
          }
    }

    // We are interested only in "hot" instructions. We don't want to do any
    // mis-optimizations here.
    if (!isHot)
      return false;
  }

  // Check to see how many predecessors have the loaded value fully
  // available.
  DenseMap<BasicBlock*, Value*> PredLoads;
  DenseMap<BasicBlock*, char> FullyAvailableBlocks;
  for (unsigned i = 0, e = ValuesPerBlock.size(); i != e; ++i)
    FullyAvailableBlocks[ValuesPerBlock[i].BB] = true;
  for (unsigned i = 0, e = UnavailableBlocks.size(); i != e; ++i)
    FullyAvailableBlocks[UnavailableBlocks[i]] = false;

  for (pred_iterator PI = pred_begin(LoadBB), E = pred_end(LoadBB);
       PI != E; ++PI) {
    BasicBlock *Pred = *PI;
    if (IsValueFullyAvailableInBlock(Pred, FullyAvailableBlocks)) {
      continue;
    }
    PredLoads[Pred] = 0;

    if (Pred->getTerminator()->getNumSuccessors() != 1) {
      if (isa<IndirectBrInst>(Pred->getTerminator())) {
        DEBUG(dbgs() << "COULD NOT PRE LOAD BECAUSE OF INDBR CRITICAL EDGE '"
              << Pred->getName() << "': " << *LI << '\n');
        return false;
      }
      unsigned SuccNum = GetSuccessorNumber(Pred, LoadBB);
      toSplit.push_back(std::make_pair(Pred->getTerminator(), SuccNum));
      return false;
    }
  }

  // Decide whether PRE is profitable for this load.
  unsigned NumUnavailablePreds = PredLoads.size();
  assert(NumUnavailablePreds != 0 &&
         "Fully available value should be eliminated above!");
  if (!EnableFullLoadPRE) {
    // If this load is unavailable in multiple predecessors, reject it.
    // FIXME: If we could restructure the CFG, we could make a common pred with
    // all the preds that don't have an available LI and insert a new load into
    // that one block.
    if (NumUnavailablePreds != 1)
      return false;
  }

  // Check if the load can safely be moved to all the unavailable predecessors.
  bool CanDoPRE = true;
  SmallVector<Instruction*, 8> NewInsts;
  for (DenseMap<BasicBlock*, Value*>::iterator I = PredLoads.begin(),
         E = PredLoads.end(); I != E; ++I) {
    BasicBlock *UnavailablePred = I->first;

    // Do PHI translation to get its value in the predecessor if necessary.  The
    // returned pointer (if non-null) is guaranteed to dominate UnavailablePred.

    // If all preds have a single successor, then we know it is safe to insert
    // the load on the pred (?!?), so we can insert code to materialize the
    // pointer if it is not available.
    PHITransAddr Address(LI->getOperand(0), TD);
    Value *LoadPtr = 0;
    if (allSingleSucc) {
      LoadPtr = Address.PHITranslateWithInsertion(LoadBB, UnavailablePred,
                                                  *DT, NewInsts);
    } else {
      Address.PHITranslateValue(LoadBB, UnavailablePred);
      LoadPtr = Address.getAddr();
    
      // Make sure the value is live in the predecessor.
      if (Instruction *Inst = dyn_cast_or_null<Instruction>(LoadPtr))
        if (!DT->dominates(Inst->getParent(), UnavailablePred))
          LoadPtr = 0;
    }

    // If we couldn't find or insert a computation of this phi translated value,
    // we fail PRE.
    if (LoadPtr == 0) {
      DEBUG(dbgs() << "COULDN'T INSERT PHI TRANSLATED VALUE OF: "
            << *LI->getOperand(0) << "\n");
      CanDoPRE = false;
      break;
    }

    // Make sure it is valid to move this load here.  We have to watch out for:
    //  @1 = getelementptr (i8* p, ...
    //  test p and branch if == 0
    //  load @1
    // It is valid to have the getelementptr before the test, even if p can be 0,
    // as getelementptr only does address arithmetic.
    // If we are not pushing the value through any multiple-successor blocks
    // we do not have this case.  Otherwise, check that the load is safe to
    // put anywhere; this can be improved, but should be conservatively safe.
    if (!allSingleSucc &&
        // FIXME: REEVALUTE THIS.
        !isSafeToLoadUnconditionally(LoadPtr,
                                     UnavailablePred->getTerminator(),
                                     LI->getAlignment(), TD)) {
      CanDoPRE = false;
      break;
    }

    I->second = LoadPtr;
  }

  if (!CanDoPRE) {
    while (!NewInsts.empty())
      NewInsts.pop_back_val()->eraseFromParent();
    return false;
  }

  // Okay, we can eliminate this load by inserting a reload in the predecessor
  // and using PHI construction to get the value in the other predecessors, do
  // it.
  DEBUG(dbgs() << "GVN REMOVING PRE LOAD: " << *LI << '\n');
  DEBUG(if (!NewInsts.empty())
          dbgs() << "INSERTED " << NewInsts.size() << " INSTS: "
                 << *NewInsts.back() << '\n');
  
  // Assign value numbers to the new instructions.
  for (unsigned i = 0, e = NewInsts.size(); i != e; ++i) {
    // FIXME: We really _ought_ to insert these value numbers into their 
    // parent's availability map.  However, in doing so, we risk getting into
    // ordering issues.  If a block hasn't been processed yet, we would be
    // marking a value as AVAIL-IN, which isn't what we intend.
    VN.lookup_or_add(NewInsts[i]);
  }

  for (DenseMap<BasicBlock*, Value*>::iterator I = PredLoads.begin(),
         E = PredLoads.end(); I != E; ++I) {
    BasicBlock *UnavailablePred = I->first;
    Value *LoadPtr = I->second;

    Value *NewLoad = new LoadInst(LoadPtr, LI->getName()+".pre", false,
                                  LI->getAlignment(),
                                  UnavailablePred->getTerminator());

    // Add the newly created load.
    ValuesPerBlock.push_back(AvailableValueInBlock::get(UnavailablePred,
                                                        NewLoad));
  }

  // Perform PHI construction.
  Value *V = ConstructSSAForLoadSet(LI, ValuesPerBlock, TD, *DT,
                                    VN.getAliasAnalysis());
  LI->replaceAllUsesWith(V);
  if (isa<PHINode>(V))
    V->takeName(LI);
  if (V->getType()->isPointerTy())
    MD->invalidateCachedPointerInfo(V);
  VN.erase(LI);
  toErase.push_back(LI);
  NumPRELoad++;
  return true;
}

/// processLoad - Attempt to eliminate a load, first by eliminating it
/// locally, and then attempting non-local elimination if that fails.
bool GVN::processLoad(LoadInst *L, SmallVectorImpl<Instruction*> &toErase) {
  if (!MD)
    return false;

  if (L->isVolatile())
    return false;

  // ... to a pointer that has been loaded from before...
  MemDepResult Dep = MD->getDependency(L);

  // If the value isn't available, don't do anything!
  if (Dep.isClobber()) {
    // Check to see if we have something like this:
    //   store i32 123, i32* %P
    //   %A = bitcast i32* %P to i8*
    //   %B = gep i8* %A, i32 1
    //   %C = load i8* %B
    //
    // We could do that by recognizing if the clobber instructions are obviously
    // a common base + constant offset, and if the previous store (or memset)
    // completely covers this load.  This sort of thing can happen in bitfield
    // access code.
    Value *AvailVal = 0;
    if (StoreInst *DepSI = dyn_cast<StoreInst>(Dep.getInst()))
      if (const TargetData *TD = getAnalysisIfAvailable<TargetData>()) {
        int Offset = AnalyzeLoadFromClobberingStore(L->getType(),
                                                    L->getPointerOperand(),
                                                    DepSI, *TD);
        if (Offset != -1)
          AvailVal = GetStoreValueForLoad(DepSI->getOperand(0), Offset,
                                          L->getType(), L, *TD);
      }
    
    // If the clobbering value is a memset/memcpy/memmove, see if we can forward
    // a value on from it.
    if (MemIntrinsic *DepMI = dyn_cast<MemIntrinsic>(Dep.getInst())) {
      if (const TargetData *TD = getAnalysisIfAvailable<TargetData>()) {
        int Offset = AnalyzeLoadFromClobberingMemInst(L->getType(),
                                                      L->getPointerOperand(),
                                                      DepMI, *TD);
        if (Offset != -1)
          AvailVal = GetMemInstValueForLoad(DepMI, Offset, L->getType(), L,*TD);
      }
    }
        
    if (AvailVal) {
      DEBUG(dbgs() << "GVN COERCED INST:\n" << *Dep.getInst() << '\n'
            << *AvailVal << '\n' << *L << "\n\n\n");
      
      // Replace the load!
      L->replaceAllUsesWith(AvailVal);
      if (AvailVal->getType()->isPointerTy())
        MD->invalidateCachedPointerInfo(AvailVal);
      VN.erase(L);
      toErase.push_back(L);
      NumGVNLoad++;
      return true;
    }
        
    DEBUG(
      // fast print dep, using operator<< on instruction would be too slow
      dbgs() << "GVN: load ";
      WriteAsOperand(dbgs(), L);
      Instruction *I = Dep.getInst();
      dbgs() << " is clobbered by " << *I << '\n';
    );
    return false;
  }

  // If it is defined in another block, try harder.
  if (Dep.isNonLocal())
    return processNonLocalLoad(L, toErase);

  Instruction *DepInst = Dep.getInst();
  if (StoreInst *DepSI = dyn_cast<StoreInst>(DepInst)) {
    Value *StoredVal = DepSI->getOperand(0);
    
    // The store and load are to a must-aliased pointer, but they may not
    // actually have the same type.  See if we know how to reuse the stored
    // value (depending on its type).
    const TargetData *TD = 0;
    if (StoredVal->getType() != L->getType()) {
      if ((TD = getAnalysisIfAvailable<TargetData>())) {
        StoredVal = CoerceAvailableValueToLoadType(StoredVal, L->getType(),
                                                   L, *TD);
        if (StoredVal == 0)
          return false;
        
        DEBUG(dbgs() << "GVN COERCED STORE:\n" << *DepSI << '\n' << *StoredVal
                     << '\n' << *L << "\n\n\n");
      }
      else 
        return false;
    }

    // Remove it!
    L->replaceAllUsesWith(StoredVal);
    if (StoredVal->getType()->isPointerTy())
      MD->invalidateCachedPointerInfo(StoredVal);
    VN.erase(L);
    toErase.push_back(L);
    NumGVNLoad++;
    return true;
  }

  if (LoadInst *DepLI = dyn_cast<LoadInst>(DepInst)) {
    Value *AvailableVal = DepLI;
    
    // The loads are of a must-aliased pointer, but they may not actually have
    // the same type.  See if we know how to reuse the previously loaded value
    // (depending on its type).
    const TargetData *TD = 0;
    if (DepLI->getType() != L->getType()) {
      if ((TD = getAnalysisIfAvailable<TargetData>())) {
        AvailableVal = CoerceAvailableValueToLoadType(DepLI, L->getType(), L,*TD);
        if (AvailableVal == 0)
          return false;
      
        DEBUG(dbgs() << "GVN COERCED LOAD:\n" << *DepLI << "\n" << *AvailableVal
                     << "\n" << *L << "\n\n\n");
      }
      else 
        return false;
    }
    
    // Remove it!
    L->replaceAllUsesWith(AvailableVal);
    if (DepLI->getType()->isPointerTy())
      MD->invalidateCachedPointerInfo(DepLI);
    VN.erase(L);
    toErase.push_back(L);
    NumGVNLoad++;
    return true;
  }

  // If this load really doesn't depend on anything, then we must be loading an
  // undef value.  This can happen when loading for a fresh allocation with no
  // intervening stores, for example.
  if (isa<AllocaInst>(DepInst) || isMalloc(DepInst)) {
    L->replaceAllUsesWith(UndefValue::get(L->getType()));
    VN.erase(L);
    toErase.push_back(L);
    NumGVNLoad++;
    return true;
  }
  
  // If this load occurs either right after a lifetime begin,
  // then the loaded value is undefined.
  if (IntrinsicInst* II = dyn_cast<IntrinsicInst>(DepInst)) {
    if (II->getIntrinsicID() == Intrinsic::lifetime_start) {
      L->replaceAllUsesWith(UndefValue::get(L->getType()));
      VN.erase(L);
      toErase.push_back(L);
      NumGVNLoad++;
      return true;
    }
  }

  return false;
}

Value *GVN::lookupNumber(BasicBlock *BB, uint32_t num) {
  DenseMap<BasicBlock*, ValueNumberScope*>::iterator I = localAvail.find(BB);
  if (I == localAvail.end())
    return 0;

  ValueNumberScope *Locals = I->second;
  while (Locals) {
    DenseMap<uint32_t, Value*>::iterator I = Locals->table.find(num);
    if (I != Locals->table.end())
      return I->second;
    Locals = Locals->parent;
  }

  return 0;
}


/// processInstruction - When calculating availability, handle an instruction
/// by inserting it into the appropriate sets
bool GVN::processInstruction(Instruction *I,
                             SmallVectorImpl<Instruction*> &toErase) {
  // Ignore dbg info intrinsics.
  if (isa<DbgInfoIntrinsic>(I))
    return false;

  if (LoadInst *LI = dyn_cast<LoadInst>(I)) {
    bool Changed = processLoad(LI, toErase);

    if (!Changed) {
      unsigned Num = VN.lookup_or_add(LI);
      localAvail[I->getParent()]->table.insert(std::make_pair(Num, LI));
    }

    return Changed;
  }

  uint32_t NextNum = VN.getNextUnusedValueNumber();
  unsigned Num = VN.lookup_or_add(I);

  if (BranchInst *BI = dyn_cast<BranchInst>(I)) {
    localAvail[I->getParent()]->table.insert(std::make_pair(Num, I));

    if (!BI->isConditional() || isa<Constant>(BI->getCondition()))
      return false;

    Value *BranchCond = BI->getCondition();
    uint32_t CondVN = VN.lookup_or_add(BranchCond);

    BasicBlock *TrueSucc = BI->getSuccessor(0);
    BasicBlock *FalseSucc = BI->getSuccessor(1);

    if (TrueSucc->getSinglePredecessor())
      localAvail[TrueSucc]->table[CondVN] =
        ConstantInt::getTrue(TrueSucc->getContext());
    if (FalseSucc->getSinglePredecessor())
      localAvail[FalseSucc]->table[CondVN] =
        ConstantInt::getFalse(TrueSucc->getContext());

    return false;

  // Allocations are always uniquely numbered, so we can save time and memory
  // by fast failing them.
  } else if (isa<AllocaInst>(I) || isa<TerminatorInst>(I)) {
    localAvail[I->getParent()]->table.insert(std::make_pair(Num, I));
    return false;
  }

  // Collapse PHI nodes
  if (PHINode* p = dyn_cast<PHINode>(I)) {
    Value *constVal = CollapsePhi(p);

    if (constVal) {
      p->replaceAllUsesWith(constVal);
      if (MD && constVal->getType()->isPointerTy())
        MD->invalidateCachedPointerInfo(constVal);
      VN.erase(p);

      toErase.push_back(p);
    } else {
      localAvail[I->getParent()]->table.insert(std::make_pair(Num, I));
    }

  // If the number we were assigned was a brand new VN, then we don't
  // need to do a lookup to see if the number already exists
  // somewhere in the domtree: it can't!
  } else if (Num == NextNum) {
    localAvail[I->getParent()]->table.insert(std::make_pair(Num, I));

  // Perform fast-path value-number based elimination of values inherited from
  // dominators.
  } else if (Value *repl = lookupNumber(I->getParent(), Num)) {
    // Remove it!
    VN.erase(I);
    I->replaceAllUsesWith(repl);
    if (MD && repl->getType()->isPointerTy())
      MD->invalidateCachedPointerInfo(repl);
    toErase.push_back(I);
    return true;

  } else {
    localAvail[I->getParent()]->table.insert(std::make_pair(Num, I));
  }

  return false;
}

/// runOnFunction - This is the main transformation entry point for a function.
bool GVN::runOnFunction(Function& F) {
  if (!NoLoads)
    MD = &getAnalysis<MemoryDependenceAnalysis>();
  DT = &getAnalysis<DominatorTree>();
  VN.setAliasAnalysis(&getAnalysis<AliasAnalysis>());
  VN.setMemDep(MD);
  VN.setDomTree(DT);

  bool Changed = false;
  bool ShouldContinue = true;

  // Merge unconditional branches, allowing PRE to catch more
  // optimization opportunities.
  for (Function::iterator FI = F.begin(), FE = F.end(); FI != FE; ) {
    BasicBlock *BB = FI;
    ++FI;
    bool removedBlock = MergeBlockIntoPredecessor(BB, this);
    if (removedBlock) NumGVNBlocks++;

    Changed |= removedBlock;
  }

  unsigned Iteration = 0;

  while (ShouldContinue) {
    DEBUG(dbgs() << "GVN iteration: " << Iteration << "\n");
    ShouldContinue = iterateOnFunction(F);
    if (splitCriticalEdges())
      ShouldContinue = true;
    Changed |= ShouldContinue;
    ++Iteration;
  }

  if (EnablePRE) {
    bool PREChanged = true;
    while (PREChanged) {
      PREChanged = performPRE(F);
      Changed |= PREChanged;
    }
  }
  // FIXME: Should perform GVN again after PRE does something.  PRE can move
  // computations into blocks where they become fully redundant.  Note that
  // we can't do this until PRE's critical edge splitting updates memdep.
  // Actually, when this happens, we should just fully integrate PRE into GVN.

  cleanupGlobalSets();

  return Changed;
}


bool GVN::processBlock(BasicBlock *BB) {
  // FIXME: Kill off toErase by doing erasing eagerly in a helper function (and
  // incrementing BI before processing an instruction).
  SmallVector<Instruction*, 8> toErase;
  bool ChangedFunction = false;

  for (BasicBlock::iterator BI = BB->begin(), BE = BB->end();
       BI != BE;) {
    ChangedFunction |= processInstruction(BI, toErase);
    if (toErase.empty()) {
      ++BI;
      continue;
    }

    // If we need some instructions deleted, do it now.
    NumGVNInstr += toErase.size();

    // Avoid iterator invalidation.
    bool AtStart = BI == BB->begin();
    if (!AtStart)
      --BI;

    for (SmallVector<Instruction*, 4>::iterator I = toErase.begin(),
         E = toErase.end(); I != E; ++I) {
      DEBUG(dbgs() << "GVN removed: " << **I << '\n');
      if (MD) MD->removeInstruction(*I);
      (*I)->eraseFromParent();
      DEBUG(verifyRemoved(*I));
    }
    toErase.clear();

    if (AtStart)
      BI = BB->begin();
    else
      ++BI;
  }

  return ChangedFunction;
}

/// performPRE - Perform a purely local form of PRE that looks for diamond
/// control flow patterns and attempts to perform simple PRE at the join point.
bool GVN::performPRE(Function &F) {
  bool Changed = false;
  DenseMap<BasicBlock*, Value*> predMap;
  for (df_iterator<BasicBlock*> DI = df_begin(&F.getEntryBlock()),
       DE = df_end(&F.getEntryBlock()); DI != DE; ++DI) {
    BasicBlock *CurrentBlock = *DI;

    // Nothing to PRE in the entry block.
    if (CurrentBlock == &F.getEntryBlock()) continue;

    for (BasicBlock::iterator BI = CurrentBlock->begin(),
         BE = CurrentBlock->end(); BI != BE; ) {
      Instruction *CurInst = BI++;

      if (isa<AllocaInst>(CurInst) ||
          isa<TerminatorInst>(CurInst) || isa<PHINode>(CurInst) ||
          CurInst->getType()->isVoidTy() ||
          CurInst->mayReadFromMemory() || CurInst->mayHaveSideEffects() ||
          isa<DbgInfoIntrinsic>(CurInst))
        continue;

      uint32_t ValNo = VN.lookup(CurInst);

      // Look for the predecessors for PRE opportunities.  We're
      // only trying to solve the basic diamond case, where
      // a value is computed in the successor and one predecessor,
      // but not the other.  We also explicitly disallow cases
      // where the successor is its own predecessor, because they're
      // more complicated to get right.
      unsigned NumWith = 0;
      unsigned NumWithout = 0;
      BasicBlock *PREPred = 0;
      predMap.clear();

      for (pred_iterator PI = pred_begin(CurrentBlock),
           PE = pred_end(CurrentBlock); PI != PE; ++PI) {
        // We're not interested in PRE where the block is its
        // own predecessor, or in blocks with predecessors
        // that are not reachable.
        if (*PI == CurrentBlock) {
          NumWithout = 2;
          break;
        } else if (!localAvail.count(*PI))  {
          NumWithout = 2;
          break;
        }

        DenseMap<uint32_t, Value*>::iterator predV =
                                            localAvail[*PI]->table.find(ValNo);
        if (predV == localAvail[*PI]->table.end()) {
          PREPred = *PI;
          NumWithout++;
        } else if (predV->second == CurInst) {
          NumWithout = 2;
        } else {
          predMap[*PI] = predV->second;
          NumWith++;
        }
      }

      // Don't do PRE when it might increase code size, i.e. when
      // we would need to insert instructions in more than one pred.
      if (NumWithout != 1 || NumWith == 0)
        continue;
      
      // Don't do PRE across indirect branch.
      if (isa<IndirectBrInst>(PREPred->getTerminator()))
        continue;

      // We can't do PRE safely on a critical edge, so instead we schedule
      // the edge to be split and perform the PRE the next time we iterate
      // on the function.
      unsigned SuccNum = GetSuccessorNumber(PREPred, CurrentBlock);
      if (isCriticalEdge(PREPred->getTerminator(), SuccNum)) {
        toSplit.push_back(std::make_pair(PREPred->getTerminator(), SuccNum));
        continue;
      }

      // Instantiate the expression in the predecessor that lacked it.
      // Because we are going top-down through the block, all value numbers
      // will be available in the predecessor by the time we need them.  Any
      // that weren't originally present will have been instantiated earlier
      // in this loop.
      Instruction *PREInstr = CurInst->clone();
      bool success = true;
      for (unsigned i = 0, e = CurInst->getNumOperands(); i != e; ++i) {
        Value *Op = PREInstr->getOperand(i);
        if (isa<Argument>(Op) || isa<Constant>(Op) || isa<GlobalValue>(Op))
          continue;

        if (Value *V = lookupNumber(PREPred, VN.lookup(Op))) {
          PREInstr->setOperand(i, V);
        } else {
          success = false;
          break;
        }
      }

      // Fail out if we encounter an operand that is not available in
      // the PRE predecessor.  This is typically because of loads which
      // are not value numbered precisely.
      if (!success) {
        delete PREInstr;
        DEBUG(verifyRemoved(PREInstr));
        continue;
      }

      PREInstr->insertBefore(PREPred->getTerminator());
      PREInstr->setName(CurInst->getName() + ".pre");
      predMap[PREPred] = PREInstr;
      VN.add(PREInstr, ValNo);
      NumGVNPRE++;

      // Update the availability map to include the new instruction.
      localAvail[PREPred]->table.insert(std::make_pair(ValNo, PREInstr));

      // Create a PHI to make the value available in this block.
      PHINode* Phi = PHINode::Create(CurInst->getType(),
                                     CurInst->getName() + ".pre-phi",
                                     CurrentBlock->begin());
      for (pred_iterator PI = pred_begin(CurrentBlock),
           PE = pred_end(CurrentBlock); PI != PE; ++PI)
        Phi->addIncoming(predMap[*PI], *PI);

      VN.add(Phi, ValNo);
      localAvail[CurrentBlock]->table[ValNo] = Phi;

      CurInst->replaceAllUsesWith(Phi);
      if (MD && Phi->getType()->isPointerTy())
        MD->invalidateCachedPointerInfo(Phi);
      VN.erase(CurInst);

      DEBUG(dbgs() << "GVN PRE removed: " << *CurInst << '\n');
      if (MD) MD->removeInstruction(CurInst);
      CurInst->eraseFromParent();
      DEBUG(verifyRemoved(CurInst));
      Changed = true;
    }
  }

  if (splitCriticalEdges())
    Changed = true;

  return Changed;
}

/// splitCriticalEdges - Split critical edges found during the previous
/// iteration that may enable further optimization.
bool GVN::splitCriticalEdges() {
  if (toSplit.empty())
    return false;
  do {
    std::pair<TerminatorInst*, unsigned> Edge = toSplit.pop_back_val();
    SplitCriticalEdge(Edge.first, Edge.second, this);
  } while (!toSplit.empty());
  MD->invalidateCachedPredecessors();
  return true;
}

/// iterateOnFunction - Executes one iteration of GVN
bool GVN::iterateOnFunction(Function &F) {
  cleanupGlobalSets();

  for (df_iterator<DomTreeNode*> DI = df_begin(DT->getRootNode()),
       DE = df_end(DT->getRootNode()); DI != DE; ++DI) {
    if (DI->getIDom())
      localAvail[DI->getBlock()] =
                   new ValueNumberScope(localAvail[DI->getIDom()->getBlock()]);
    else
      localAvail[DI->getBlock()] = new ValueNumberScope(0);
  }

  // Top-down walk of the dominator tree
  bool Changed = false;
#if 0
  // Needed for value numbering with phi construction to work.
  ReversePostOrderTraversal<Function*> RPOT(&F);
  for (ReversePostOrderTraversal<Function*>::rpo_iterator RI = RPOT.begin(),
       RE = RPOT.end(); RI != RE; ++RI)
    Changed |= processBlock(*RI);
#else
  for (df_iterator<DomTreeNode*> DI = df_begin(DT->getRootNode()),
       DE = df_end(DT->getRootNode()); DI != DE; ++DI)
    Changed |= processBlock(DI->getBlock());
#endif

  return Changed;
}

void GVN::cleanupGlobalSets() {
  VN.clear();

  for (DenseMap<BasicBlock*, ValueNumberScope*>::iterator
       I = localAvail.begin(), E = localAvail.end(); I != E; ++I)
    delete I->second;
  localAvail.clear();
}

/// verifyRemoved - Verify that the specified instruction does not occur in our
/// internal data structures.
void GVN::verifyRemoved(const Instruction *Inst) const {
  VN.verifyRemoved(Inst);

  // Walk through the value number scope to make sure the instruction isn't
  // ferreted away in it.
  for (DenseMap<BasicBlock*, ValueNumberScope*>::const_iterator
         I = localAvail.begin(), E = localAvail.end(); I != E; ++I) {
    const ValueNumberScope *VNS = I->second;

    while (VNS) {
      for (DenseMap<uint32_t, Value*>::const_iterator
             II = VNS->table.begin(), IE = VNS->table.end(); II != IE; ++II) {
        assert(II->second != Inst && "Inst still in value numbering scope!");
      }

      VNS = VNS->parent;
    }
  }
}
