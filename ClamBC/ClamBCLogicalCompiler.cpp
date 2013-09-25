/*
 *  Compile LLVM bytecode to logical signatures.
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

#define DEBUG_TYPE "lsigcompiler"
#include "ClamBCModule.h"
#include "llvm/System/DataTypes.h"
#include "../clang/lib/Headers/bytecode_api.h"
#include "clambc.h"
#include "ClamBCDiagnostics.h"
#include "ClamBCModule.h"
#include "ClamBCCommon.h"
#include "llvm/ADT/FoldingSet.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/Analysis/ConstantFolding.h"
#include "llvm/Analysis/DebugInfo.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/Config/config.h"
#include "llvm/DerivedTypes.h"
#include "llvm/IntrinsicInst.h"
#include "llvm/Module.h"
#include "llvm/Pass.h"
#include "llvm/PassManager.h"
#include "llvm/Support/CallSite.h"
#include "llvm/Support/ConstantRange.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/InstIterator.h"
#include "llvm/Support/FormattedStream.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetData.h"
#include "llvm/System/Process.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Transforms/IPO.h"
#include "llvm/Type.h"

using namespace llvm;

namespace {
class ClamBCLogicalCompiler : public ModulePass {
public:
  static char ID;
  ClamBCLogicalCompiler() : ModulePass((uintptr_t)&ID) {}
  virtual bool runOnModule(Module &M);
  virtual void getAnalysisUsage(AnalysisUsage &AU) const {
    AU.setPreservesCFG();
  }
private:
  std::string LogicalSignature;
  std::string virusnames;
  bool compileLogicalSignature(Function &F, unsigned target, unsigned min,
                               unsigned max, const std::string& icon1,
                               const std::string &icon2,
			       const std::string &container,
                               int kind);
  bool validateVirusName(const std::string& name, Module &M, bool suffix=false);
  bool compileVirusNames(Module &M, unsigned kind);
};
char ClamBCLogicalCompiler::ID = 0;
RegisterPass<ClamBCLogicalCompiler> X("clambc-lcompiler",
                                      "ClamAV Logical Compiler");
enum LogicalKind {
  LOG_SUBSIGNATURE,
  LOG_AND,
  LOG_OR,
  LOG_EQ,
  LOG_GT,
  LOG_LT,
  LOG_ADDBOTH,/* checks both the sum of the individual matches, and the number of different subsignatures that matched */
  /* not actually supported by libclamav, will be folded */
  LOG_NOT,
  LOG_TRUE,
  LOG_FALSE,
  LOG_ADD,
  LOG_ADDSUM,/* sum up counts of (logical) subsignatures */
  LOG_ADDUNIQ/* sum up number of different subsignatures that matched */
};

// LogicalNodes are uniqued
class LogicalNode;
typedef FoldingSet<LogicalNode> LogicalNodes;
class LogicalNode : public FoldingSetNode {
private:
  LogicalNodes &Set;
public:
  void Profile(FoldingSetNodeID &ID) const {
    ID.AddInteger(op0);
    ID.AddInteger(op1);
    ID.AddInteger(kind);
    for (std::vector<LogicalNode*>::const_iterator I=children.begin(), E=children.end();
         I != E; ++I) {
      ID.AddPointer(*I);
    }
  }

  static LogicalNode* getNode(const LogicalNode &N)
  {
    assert(!N.children.empty() || N.kind == LOG_SUBSIGNATURE || N.kind == LOG_TRUE || N.kind == LOG_FALSE);
    FoldingSetNodeID ID;
    N.Profile(ID);
    void *InsertPoint;
    LogicalNode *M = N.Set.FindNodeOrInsertPos(ID, InsertPoint);
    if (M)
      return M;
    M = new LogicalNode(N);
    N.Set.InsertNode(M, InsertPoint);
    return M;
  }

  static LogicalNode *getTrue(LogicalNodes& Set)
  {
    LogicalNode N(Set, LOG_TRUE);
    return getNode(N);
  }

  static LogicalNode *getFalse(LogicalNodes& Set)
  {
    LogicalNode N(Set, LOG_FALSE);
    return getNode(N);
  }

  static LogicalNode* getSubSig(LogicalNodes &Set, unsigned subsigid)
  {
    LogicalNode N(Set, LOG_SUBSIGNATURE, subsigid);
    return getNode(N);
  }

  static LogicalNode *getEQ(LogicalNode *Node, uint32_t value)
  {
    // a + c == b -> a == b - c
    if (Node->kind == LOG_ADD) {
      value -= Node->op0;
      Node = Node->children[0];
    }
    uint32_t uniq = ~0u;
    switch (Node->kind) {
    case LOG_ADDUNIQ:
      uniq = value;
      /* Fall-through */
    case LOG_ADDSUM:
      {
        LogicalNode N(Node->Set, LOG_ADDBOTH);
        N.children.assign(Node->begin(), Node->end());
        Node = getNode(N);
        break;
      }
    default:
      break;
    }
    LogicalNode N(Node->Set, LOG_EQ, value, uniq);
    N.children.push_back(Node);
    return getNode(N);
  }

  static LogicalNode *getRange(LogicalNode *Node, uint32_t min, uint32_t max)
  {
    std::vector<LogicalNode*> nodes;
    // a in [min, max] -> a >= min && a <= max
    if (min) {// a >= 0 -> true
      // a >= min, min != 0 ->  a > min-1
      min--;
      nodes.push_back(getGT(Node, min));
    }
    if (++max) {// a <= ~0u -> true
      nodes.push_back(getLT(Node, max));
    }
    if (nodes.empty())
      return getTrue(Node->Set);
    return getAnd(nodes);
  }

  static LogicalNode *getLT(LogicalNode *Node, uint32_t value)
  {
    if (!value)
      // a < 0 -> false
      return getFalse(Node->Set);
    if (Node->kind == LOG_ADD) {
      ConstantRange Cmp(APInt(32, value));
      // a + c < b -> a+c in [0, b) -> a in [0-c, b-c)
      ConstantRange ltRange = ConstantRange::makeICmpRegion(CmpInst::ICMP_ULT, Cmp);
      ltRange = ltRange.subtract(APInt(32, Node->op0));
      Node = Node->children[0];
      uint32_t min = ltRange.getUnsignedMin().getLimitedValue(~0u);
      uint32_t max = ltRange.getUnsignedMax().getLimitedValue(~0u);
      return getRange(Node, min, max);
    }
    LogicalNode N(Node->Set, LOG_LT, value);
    N.children.push_back(Node);
    return getNode(N);
  }

  static LogicalNode *getGT(LogicalNode *Node, uint32_t value)
  {
    if (!value)
      // a > 0 -> a
      return Node;
    if (Node->kind == LOG_ADD) {
      ConstantRange Cmp(APInt(32, value));
      // a + c < b -> a+c in [0, b) -> a in [0-c, b-c)
      ConstantRange ltRange = ConstantRange::makeICmpRegion(CmpInst::ICMP_UGT, Cmp);
      ltRange = ltRange.subtract(APInt(32, Node->op0));
      Node = Node->children[0];
      // a in [min, max] -> 
      // (a > min || a == min) && (a == max || a < max)
      uint32_t min = ltRange.getUnsignedMin().getLimitedValue(~0u);
      uint32_t max = ltRange.getUnsignedMax().getLimitedValue(~0u);
      return getRange(Node, min, max);
    }
    LogicalNode N(Node->Set, LOG_GT, value);
    N.children.push_back(Node);
    return getNode(N);
  }

  static LogicalNode *getUniqueSigs(LogicalNode *Node)
  {
    LogicalNode N(Node->Set, LOG_ADDUNIQ);
    N.children.push_back(Node);
    return getNode(N);
  }

  static LogicalNode *getOr(LogicalNode *LHS, LogicalNode *RHS)
  {
    std::vector<LogicalNode*> V;
    V.reserve(2);
    V.push_back(LHS);
    V.push_back(RHS);
    return getOr(V);
  }

  static LogicalNode *getAnd(LogicalNode *LHS, LogicalNode *RHS)
  {
    std::vector<LogicalNode*> V;
    V.reserve(2);
    V.push_back(LHS);
    V.push_back(RHS);
    return getAnd(V);
  }

  static LogicalNode* getNot(LogicalNode *Op)
  {
    std::vector<LogicalNode*> nodes;
    // 'Not' is not supported by libclamav, lower it
    switch (Op->kind) {
    case LOG_SUBSIGNATURE:
      // !a -> a == 0
      return getEQ(Op, 0);
    case LOG_AND:
      // DeMorgan's law: !(a && b) -> !a || !b
      for (std::vector<LogicalNode*>::iterator I=Op->children.begin(),
           E=Op->children.end(); I != E; ++I) {
        nodes.push_back(getNot(*I));
      }
      return getOr(nodes);
    case LOG_OR:
      // DeMorgan's law: !(a || b) -> !a && !b
      for (std::vector<LogicalNode*>::iterator I=Op->children.begin(),
           E=Op->children.end(); I != E; ++I) {
        nodes.push_back(getNot(*I));
      }
      return getAnd(nodes);
    case LOG_EQ:
      // !(a == b) -> (a < b || a > b)
      nodes.push_back(getLT(Op->children[0], Op->op0));
      nodes.push_back(getGT(Op->children[0], Op->op0));
      return getOr(nodes);
    case LOG_GT:
      // !(a > b) -> (a < b || a == b)
      nodes.push_back(getLT(Op->children[0], Op->op0));
      nodes.push_back(getEQ(Op->children[0], Op->op0));
      return getOr(nodes);
    case LOG_LT:
      // !(a < b) -> (a > b || a == b)
      nodes.push_back(getGT(Op->children[0],  Op->op0));
      nodes.push_back(getEQ(Op->children[0], Op->op0));
      return getOr(nodes);
    case LOG_NOT:
      // !!a -> a 
      return Op->children[0];
    case LOG_TRUE:
      return getFalse(Op->Set);
    case LOG_FALSE:
      return getTrue(Op->Set);
    default:
      assert(0 && "Invalid negation operation");
      return 0;
    }
  }


  static LogicalNode *getAdd(LogicalNode *N, uint32_t off)
  {
    LogicalNode M(N->Set, LOG_ADD, off);
    M.children.push_back(N);
    return getNode(M);
  }

  bool checkUniq()
  {
    LogicalSet nodes;
    for (const_iterator I=begin(), E=end(); I != E; ++I) {
      if (!nodes.insert(*I))
        return false;
    }
    return true;
  }

  static bool compare_lt(LogicalNode* LHS, LogicalNode* RHS)
  {
    if (LHS->kind != RHS->kind)
      return LHS->kind < RHS->kind;
    if (LHS->op0 != RHS->op0)
      return LHS->op0 < RHS->op0;
    if (LHS->op1 != RHS->op1)
      return LHS->op0 < RHS->op0;
    if (LHS->children.size() != RHS->children.size())
      return LHS->children.size() < RHS->children.size();
    for (const_iterator I=LHS->begin(), J=RHS->begin(), E=LHS->end(); I != E; ++I, ++J) {
      if (*I == *J)
        continue;
      return compare_lt(*I, *J);
    }
    return false;
  }

  static LogicalNode *getAdd(LogicalNode *LHS, LogicalNode *RHS)
  {
    if ((LHS->kind == RHS->kind) &&
        (LHS->kind == LOG_ADDUNIQ || LHS->kind == LOG_ADDSUM)) {
      LogicalNode N(LHS->Set, LHS->kind);
      N.children.insert(N.children.end(), LHS->children.begin(), LHS->children.end());
      N.children.insert(N.children.end(), RHS->children.begin(), RHS->children.end());
      std::sort(N.children.begin(), N.children.end(), compare_lt);
      return getNode(N);
    }
    if (LHS->kind == LOG_SUBSIGNATURE && RHS->kind == LOG_SUBSIGNATURE) {
      LogicalNode N(LHS->Set, LOG_ADDSUM);
      N.children.push_back(LHS);
      N.children.push_back(RHS);
      std::sort(N.children.begin(), N.children.end(), compare_lt);
      return getNode(N);
    }
    if (RHS->kind == LOG_SUBSIGNATURE)
      std::swap(LHS, RHS);
    if (LHS->kind == LOG_SUBSIGNATURE && RHS->kind == LOG_ADDSUM) {
      LogicalNode N(LHS->Set, LOG_ADDSUM);
      N.children.push_back(LHS);
      N.children.insert(N.children.end(), RHS->children.begin(), RHS->children.end());
      std::sort(N.children.begin(), N.children.end(), compare_lt);
      return getNode(N);
    }
    if (RHS->kind == LOG_ADD && (LHS->kind == LOG_SUBSIGNATURE ||
                                 LHS->kind == LOG_ADD)) {
      unsigned op0 = RHS->op0 + (LHS->kind == LOG_ADD ? LHS->op0 : 0);
      LogicalNode N(LHS->Set, LOG_ADD, op0);
      N.children.push_back(getAdd(LHS, RHS->children[0]));
      return getNode(N);
    }
    return 0;
  }

  static LogicalNode *getAnd(LogicalNodes &Set, const std::vector<LogicalNode*>& V)
  {
    if (V.empty())
      return getTrue(Set);
    return getAnd(V);
  }

  static LogicalNode *getOr(LogicalNodes &Set, const std::vector<LogicalNode*>& V)
  {
    if (V.empty())
      return getTrue(Set);
    return getOr(V);
  }

  const uint32_t op0, op1;
  const enum LogicalKind kind;
  typedef std::vector<LogicalNode*>::const_iterator const_iterator;
  const_iterator begin() const { return children.begin(); }
  const_iterator end() const { return children.end(); }
  size_t size() const { return children.size(); }
  LogicalNode *front() const { return children[0]; }
private:
  LogicalNode(LogicalNodes &Set, enum LogicalKind kind, uint32_t value=~0u, uint32_t uniq=~0u)
    : Set(Set), op0(value), op1(uniq), kind(kind) {}
  std::vector<LogicalNode*> children;
  typedef SmallPtrSet<LogicalNode*, 4> LogicalSet;

  static LogicalNode *getAnd(const std::vector<LogicalNode*>& V)
  {
    assert(!V.empty());
    LogicalNode N(V[0]->Set, LOG_AND);
    typedef DenseMap<LogicalNode*, SmallVector<LogicalNode*, 2> > LogicalMap;
    // There can be multiple addcounts/addmatchs with same subexpression
    // but different =X,Y modifier, so we need a map of vector.
    LogicalMap adds;
    LogicalSet others;

    std::vector<LogicalNode*> nodes(V);

    while (!nodes.empty()) {
      LogicalNode *S = nodes.back();
      nodes.pop_back();
      switch (S->kind) {
      case LOG_TRUE:
        continue;
      case LOG_FALSE:
        return S;
      case LOG_AND:
        // fold (a & b) & c -> (a & b & c)
        nodes.insert(nodes.end(), S->children.begin(),
                     S->children.end());
        break;
      case LOG_EQ:
        {
          LogicalNode *C = S->front();
          // op1 == ~0u is =X modifier
          // op1 == op0 is =Y,Y modifier
          if (C->kind == LOG_ADDBOTH &&
              (S->op1 == ~0u || S->op0 == S->op1)) {
            adds[C].push_back(S);
          } else
            others.insert(S);
          break;
        }
      default:
        others.insert(S);
        break;
      }
    }


    for (LogicalMap::iterator I=adds.begin(), E=adds.end();
         I != E; ++I) {
      std::vector<LogicalNode*> adduniq;
      std::vector<LogicalNode*> addsum;
      // all =X and =Y,Y with same subexpression is in this
      // vector, so separate them into addcounts, addmatch
      for (SmallVector<LogicalNode*, 2>::iterator J=I->second.begin(),
           JE=I->second.end(); J != JE; ++J) {
        LogicalNode *N = *J;
        if (N->op1 == ~0u) {
          addsum.push_back(N);
          continue;
        }
        assert(N->op1 == N->op0);
        adduniq.push_back(N);
      }

      for (std::vector<LogicalNode*>::iterator J=addsum.begin(),
           JE=addsum.end(); J != JE; ++J) {
        LogicalNode *N1 = *J;
        if (!adduniq.empty()) {
          LogicalNode *N2 = adduniq.back();
          adduniq.pop_back();
          LogicalNode N(N1->Set, LOG_EQ, N1->op0, N2->op1);
          N.children.push_back(I->first);
          others.insert(getNode(N));
          continue;
        }
        others.insert(N1);
      }
      for (std::vector<LogicalNode*>::iterator J=adduniq.begin(),
           JE=adduniq.end(); J != JE; ++J) {
        others.insert(*J);
      }
    }

    if (others.empty())
      return getTrue(V[0]->Set);
    if (others.size() == 1) {
      return *others.begin();
    }
    N.children.assign(others.begin(), others.end());
    return getNode(N);
  }

  static LogicalNode *getOr(const std::vector<LogicalNode*>& V)
  {
    assert(!V.empty());
    LogicalNode N(V[0]->Set, LOG_OR);
    LogicalSet nodes;
    for (std::vector<LogicalNode*>::const_iterator I=V.begin(), E=V.end();
         I != E; ++I) {
      LogicalNode *S = *I;
      if (S->kind == LOG_FALSE)
        continue;
      if (S->kind == LOG_TRUE)
        return S;
      if (S->kind == LOG_OR)
        // fold (a || b) & c -> (a || b || c)
        nodes.insert(S->children.begin(), S->children.end());
      else
        nodes.insert(S);
    }
    if (nodes.empty())
      return getFalse(V[0]->Set);
    if (nodes.size() == 1)
      return *nodes.begin();
    N.children.assign(nodes.begin(), nodes.end());
    return getNode(N);
  }
};

struct SpeculativeExecution : public FunctionPass {
  static char ID;
  SpeculativeExecution() : FunctionPass(&ID) {}
  virtual bool runOnFunction(Function &F);
  virtual void getAnalysisUsage(AnalysisUsage &AU) const {
    AU.addRequiredID(PromoteMemoryToRegisterID);
  }
};
char SpeculativeExecution::ID;

bool SpeculativeExecution::runOnFunction(Function &F)
{
  bool MadeChange;
  unsigned it = 0;
  do {
    MadeChange = false;
    DEBUG(errs() << "SpeculativelyExecute iteration #" << it++ << "\n");
    SmallVector<Instruction*, 16> Speculate;
    for (Function::iterator I=F.begin(); I != F.end();) {
      BasicBlock *BB = &*I;
      BasicBlock *Pred = I->getUniquePredecessor();
      if (I != F.begin()) {
        if (SimplifyCFG(I++)) {
          MadeChange = true;
          continue;
        }
      } else {
        ++I;
      }
      if (!Pred)
        continue;
      // Determine which instructions can be hoisted
      Speculate.clear();
      for (BasicBlock::iterator J=BB->begin(), JE=BB->end(); J != JE; ++J) {
        // The instruction must be safe to execute speculatively
        if (!J->isSafeToSpeculativelyExecute())
          continue;
        // All operands must be available in parent, since this BB has only
        // one predecessor checking that the operand is not in the current
        // BB is sufficient, otherwise dominance properties would need to be
        // checked.
        bool safe = true;
        for (User::op_iterator OI=J->op_begin(), OE=J->op_end();OI != OE;++OI){
          if (Instruction *I = dyn_cast<Instruction>(OI)) {
            if (I->getParent() == BB) {
              DEBUG(errs() << "Can't speculatively execute " << 
                    *J << " due to " << *I << "\n");
              safe = false;
              break;
            }
          }
        }
        if (!safe)
          continue;
        Speculate.push_back(J);
      }
      // Hoist instructions to predecessor
      for (SmallVector<Instruction*, 16>::iterator J=Speculate.begin(), JE=Speculate.end();
           J != JE; ++J) {
        DEBUG(errs() << "Moving " << *(*J) << " to predecessor\n");
        (*J)->moveBefore(Pred->getTerminator());
        MadeChange = true;
      }
    }
  } while (MadeChange);
  return MadeChange;
}

static void SpeculativelyExecute(Function &F)
{
  FunctionPassManager *PM = new FunctionPassManager(F.getParent());
  PM->add(new TargetData(F.getParent()));
  PM->add(createCFGSimplificationPass());
  PM->add(createPromoteMemoryToRegisterPass());
  PM->add(new SpeculativeExecution());
  PM->add(createConstantPropagationPass());
  PM->add(createInstructionCombiningPass());
  PM->add(createJumpThreadingPass());
  PM->add(createScalarReplAggregatesPass());
  PM->add(new SpeculativeExecution());
  PM->add(createReassociatePass());
  PM->add(createInstructionCombiningPass());
  PM->add(createGVNPass());
  PM->add(createSCCPPass());
  PM->add(createInstructionCombiningPass());
  PM->add(createDeadStoreEliminationPass());
  PM->add(createAggressiveDCEPass());
  PM->add(new SpeculativeExecution());
  PM->add(createInstructionCombiningPass());
  PM->doInitialization();
  PM->run(F);
  PM->doFinalization();
}


class LogicalCompiler {
public:
  LogicalNode *compile(Function &F)
  {
    GV = F.getParent()->getGlobalVariable("__clambc_match_counts");
    if (!GV) {
      printDiagnostic("__clambc_match_counts is not declared for logical"
                      " signature bytecode", F.getParent(), true);
      return 0;
    }
    // Speculatively execute all instructions where it is safe to do so.
    // This simplifies the function, making it more suitable for
    // converting to a logical expression.
    SpeculativelyExecute(F);
    if (F.begin() != F.end())
      DEBUG(errs() << "Trigger function has more than 1 basic block:\n";
            F.dump());

    bool valid = processBB(&F.getEntryBlock());
    if (!valid) {
      printDiagnostic("Unable to compile to logical signature", &F);
      return 0;
    }
    return LogicalNode::getAnd(LogicalNode::getOr(allNodes, exitNodesOr),
                               LogicalNode::getAnd(allNodes, exitNodesAnd));
  }
private:
  typedef DenseMap<const Value*, LogicalNode*> LogicalMap;
  LogicalNodes allNodes;
  LogicalMap Map;
  std::vector<LogicalNode*> Stack;
  std::vector<LogicalNode*> exitNodesOr;
  std::vector<LogicalNode*> exitNodesAnd;
  SmallPtrSet<BasicBlock*, 10> Visiting;
  GlobalVariable *GV;
  bool processLoad(LoadInst &LI)
  {
    Value *V = LI.getOperand(0);
    ConstantExpr *CE = dyn_cast<ConstantExpr>(V);
    if (!CE || CE->getOpcode() != Instruction::GetElementPtr ||
        CE->getOperand(0) != GV || CE->getNumOperands() != 3 ||
        !cast<ConstantInt>(CE->getOperand(1))->isZero()) {
      printDiagnostic("Logical signature: unsupported read", &LI);
      return false;
    }
    ConstantInt *CI = cast<ConstantInt>(CE->getOperand(2));
    Map[&LI] = LogicalNode::getSubSig(allNodes, CI->getValue().getZExtValue());
    return true;
  }

  bool processICmp(ICmpInst &IC)
  {
    Value *op0 = IC.getOperand(0);
    Value *op1 = IC.getOperand(1);
    if (isa<Constant>(op0))
      std::swap(op0, op1);
    ConstantInt *RHS = dyn_cast<ConstantInt>(op1);
    if (!RHS) {
      printDiagnostic("Logical signature: unsupported compare,"
                      " must compare to a constant", &IC);
      return false;
    }
    uint64_t v = RHS->getValue().getZExtValue();
    uint32_t rhs = (uint32_t)v;
    if (v != rhs) {
      printDiagnostic("Logical signature: constant needs more than 32-bits",
                      &IC);
      return false;
    }
    LogicalMap::iterator I = Map.find(op0);
    if (I == Map.end()) {
      printDiagnostic("Logical signature: must compare match count against"
                      " constant", &IC);
      return false;
    }
    LogicalNode *Node = 0;
    switch (IC.getPredicate()) {
    case CmpInst::ICMP_EQ:
      Node =  LogicalNode::getEQ(I->second, rhs);
      break;
    case CmpInst::ICMP_NE:
      /* a != b -> !(a == b)*/
      Node = LogicalNode::getNot(LogicalNode::getEQ(I->second, rhs));
      break;
    case CmpInst::ICMP_UGT:
      Node = LogicalNode::getGT(I->second, rhs);
      break;
    case CmpInst::ICMP_UGE:
      if (!rhs) {
        printDiagnostic("Logical signature: count >= 0 is always true"
                        ", probably a typo?", &IC);
        return false;
      }
      Node = LogicalNode::getGT(I->second, rhs-1);
      break;
    case CmpInst::ICMP_ULT:
      Node = LogicalNode::getLT(I->second, rhs);
      break;
    case CmpInst::ICMP_ULE:
      if (rhs == ~0u) {
        printDiagnostic("Logical signature: count <= ~0u is always true"
                        ", probably a type?", &IC);
        return false;
      }
      Node = LogicalNode::getLT(I->second, rhs+1);
      break;
    case CmpInst::ICMP_SGT:
    case CmpInst::ICMP_SGE:
    case CmpInst::ICMP_SLE:
    case CmpInst::ICMP_SLT:
      printDiagnostic("Logical signature: signed compares not supported"
                      ", please use unsigned compares!", &IC);
      return false;
    default:
      printDiagnostic("Logical signature: unsupported compare operator", &IC);
      return false;
    }
    Map[&IC] = Node;
    return true;
  }

  bool processBB(BasicBlock *BB)
  {
    bool valid = true;
    Visiting.insert(BB);
    for (BasicBlock::iterator I=BB->begin(), E=BB->end(); I != E; ++I) {
      if (isa<DbgInfoIntrinsic>(I))
        continue;
      if (isa<AllocaInst>(I))
        continue;
      switch (I->getOpcode()) {
      case Instruction::Load:
        valid &= processLoad(*cast<LoadInst>(I));
        break;
      case Instruction::ICmp:
        valid &= processICmp(*cast<ICmpInst>(I));
        break;
      case Instruction::Br:
        {
          BranchInst *BI = cast<BranchInst>(I);
          if (BI->isUnconditional()) {
            if (Visiting.count(BB)) {
              printDiagnostic("Logical signature: loop/recursion"
                              " not supported", BI);
              return false;
            }
            return processBB(BI->getSuccessor(0));
          }
          Value *V = BI->getCondition();
          LogicalMap::iterator J = Map.find(V);
          if (J == Map.end()) {
            printDiagnostic("Logical signature: Branch condition must be"
                            " logical expression", BI);
            return false;
          }
          LogicalNode *Node = J->second;
          Stack.push_back(Node);
          if (Visiting.count(BI->getSuccessor(0))) {
            printDiagnostic("Logical signature: loop/recursion"
                            " not supported", BI);
            return false;
          }
          valid &= processBB(BI->getSuccessor(0));
          Stack.pop_back();
          Node = LogicalNode::getNot(Node);
          Stack.push_back(Node);
          if (Visiting.count(BI->getSuccessor(1))) {
            printDiagnostic("Logical signature: loop/recursion"
                            " not supported", BI);
            return false;
          }
          valid &= processBB(BI->getSuccessor(1));
          assert(Stack.back() == Node);
          Stack.pop_back();
          break;
        }
      case Instruction::Select:
        {
          SelectInst *SI = cast<SelectInst>(I);
          LogicalMap::iterator CondNode = Map.find(SI->getCondition());
          LogicalMap::iterator TrueNode = Map.find(SI->getTrueValue());
          LogicalMap::iterator FalseNode = Map.find(SI->getFalseValue());
          if (CondNode == Map.end() || TrueNode == Map.end() || FalseNode ==
              Map.end()) {
            printDiagnostic("Logical signature: select operands must be logical"
                            " expressions", I);
            return false;
          }
          // select cond, trueval, falseval -> cond && trueval || !cond && falseval
          LogicalNode *N = LogicalNode::getAnd(CondNode->second,
                                               TrueNode->second);
          LogicalNode *NotCond = LogicalNode::getNot(CondNode->second);
          LogicalNode *N2 = LogicalNode::getAnd(NotCond, FalseNode->second);
          Map[I] = LogicalNode::getOr(N, N2);
          break;
        }
      case Instruction::Ret:
        {
          Value *V = I->getOperand(0);
          if (ConstantInt *CI = dyn_cast<ConstantInt>(V)) {
            LogicalNode *Node = LogicalNode::getAnd(allNodes, Stack);
            if (CI->isZero())
              exitNodesOr.push_back(LogicalNode::getNot(Node));
            else
              exitNodesAnd.push_back(Node);
            break;
          }
          LogicalMap::iterator J = Map.find(V);
          if (J == Map.end()) {
            printDiagnostic("Logical signature: return value must be logical"
                            " expression", I);
            return false;
          }
          LogicalNode *Node = J->second;
          Stack.push_back(Node);
          exitNodesOr.push_back(LogicalNode::getAnd(allNodes, Stack));
          Stack.pop_back();
          break;
        }
      case Instruction::Add:
        {
          LogicalMap::iterator J = Map.find(I->getOperand(0));
          if (J == Map.end()) {
            printDiagnostic("Logical signature: add operands must be logical"
                            " expressions", I);
            return false;
          }
          ConstantInt *CI = dyn_cast<ConstantInt>(I->getOperand(1));
          if (CI) {
            Map[I] = LogicalNode::getAdd(J->second, CI->getValue().getZExtValue());
          } else {
            LogicalMap::iterator J2 = Map.find(I->getOperand(1));
            if (J2 == Map.end()) {
              printDiagnostic("Logical signature: add operands must be "
                              "logical expressions", I);
              return false;
            }
            LogicalNode *N = LogicalNode::getAdd(J->second, J2->second);
            if (!N) {
              printDiagnostic("Logical signature: add operands mismatch,"
                              "only of counts, uniqueness, and constants",
                              I);
              return false;
            }
            if (!N->checkUniq()) {
              printDiagnostic("Logical signature: duplicate operands for add"
                              " not supported", I);
              return false;
            }
            Map[I] =N;
          }
          break;
        }
      case Instruction::And:
        {
          LogicalMap::iterator J1 = Map.find(I->getOperand(0));
          LogicalMap::iterator J2 = Map.find(I->getOperand(1));
          if (J1 == Map.end() || J2 == Map.end()) {
            printDiagnostic("Logical signature: and operands must be logical"
                            " expressions", I);
            return false;
          }
          Map[I] = LogicalNode::getAnd(J1->second, J2->second);
          break;
        }
      case Instruction::Or:
        {
          LogicalMap::iterator J1 = Map.find(I->getOperand(0));
          LogicalMap::iterator J2 = Map.find(I->getOperand(1));
          if (J1 == Map.end() || J2 == Map.end()) {
            printDiagnostic("Logical signature: or operands must be logical"
                            " expressions", I);
            return false;
          }
          Map[I] = LogicalNode::getOr(J1->second, J2->second);
          break;
        }
      case Instruction::Xor:
        {
          ConstantInt *CI = dyn_cast<ConstantInt>(I->getOperand(1));
          if (!CI || !CI->isOne()) {
            printDiagnostic("Logical signature: xor only supported for"
                            " negation", I);
            return false;
          }
          LogicalMap::iterator J1 = Map.find(I->getOperand(0));
          if (J1 == Map.end()) {
            printDiagnostic("Logical signature: xor operand must be logical"
                            " expressions", I);
            return false;
          }
          Map[I] = LogicalNode::getNot(J1->second);
          break;
        }
      case Instruction::ZExt:
        {
          LogicalMap::iterator J = Map.find(I->getOperand(0));
          if (J == Map.end()) {
            printDiagnostic("Logical signature: zext operand must be logical"
                            " expressions", I);
            return false;
          }
          ZExtInst *ZI = cast<ZExtInst>(I);
          unsigned from = ZI->getSrcTy()->getPrimitiveSizeInBits();
          unsigned to = ZI->getDestTy()->getPrimitiveSizeInBits();
          if (from != 1 || to != 32) {
            printDiagnostic("Logical signature: only support zero extend"
                            " from i1 to i32, but encountered "+Twine(from)+
                            " to "+Twine(to), I);
            return false;
          }
          Map[I] = LogicalNode::getUniqueSigs(J->second);
          break;
        }
      default:
        printDiagnostic("Logical signature: unsupported instruction", I);
        return false;
      }
    }
    Visiting.erase(BB);
    return valid;
  }
};

static std::string node2String(LogicalNode *node, unsigned &groups)
{
  switch (node->kind) {
  case LOG_SUBSIGNATURE:
    return Twine(node->op0).str();
  case LOG_AND:
  case LOG_OR:
    {
      groups++;
      std::string result("(");
      for (LogicalNode::const_iterator I=node->begin(),
           E=node->end(); I != E;) {
        result += node2String(*I, groups);
        ++I;
        if (I != E)
          result += node->kind == LOG_AND ? "&" : "|";
      }
      return result+")";
    }
  case LOG_EQ:
    if (node->op1 == ~0u)
      return ("("+node2String(node->front(), groups) + "=" + Twine(node->op0)+")").str();
    return ("("+node2String(node->front(), groups) + "=" + Twine(node->op0)+","+Twine(node->op1)+")").str();
  case LOG_GT:
    groups++;
    return ("("+node2String(node->front(), groups)+">"+Twine(node->op0)+")").str();
  case LOG_LT:
    groups++;
    return ("("+node2String(node->front(), groups)+"<"+Twine(node->op0)+")").str();
  case LOG_ADDUNIQ:
  case LOG_ADDSUM:
  case LOG_ADDBOTH:
    {
      if (node->size() == 1)
        return node2String(node->front(), groups);
      groups++;
      std::string result("(");
      for (LogicalNode::const_iterator I=node->begin(), E=node->end(); I != E;){
        result += node2String(*I, groups);
        ++I;
        if (I != E)
          result += "|";
      }
      return result+")";
    }
  default:
    assert(0 && "Invalid node kind");
    return "??";
  }
}

bool validateNDB(const char *S, Module *M, Value *Signatures)
{
  StringRef Pattern(S);
  bool valid = true;
  size_t offsetp = Pattern.find(':');
  if (offsetp == StringRef::npos)
    offsetp = 0;
  else {
    // Attempt to fully validate the anchor/offset.
    StringRef offset = Pattern.substr(0, offsetp);
    size_t floating = offset.find(",");
    if (floating != StringRef::npos) {
      unsigned R;
      StringRef floatO = offset.substr(floating+1);
      if (floatO.getAsInteger(10, R)) {
        printDiagnosticValue("Floating offset is not an integer in'"
                             +Twine(offset)+"'", M, Signatures);
        valid = false;
      } else {
        offset = offset.substr(0, floating);
      }
    }
    if (offset.empty()) {
      printDiagnosticValue("Offset is empty in pattern: '"+Twine(Pattern)+"'",
                           M, Signatures);
      valid = false;
    } else if (S[0] == '*') {
      if (S[1] != ':') {
        printDiagnosticValue("Offset ANY ('*') followed by garbage: '"
                             +Twine(offset)+"'", M, Signatures);
        valid = false;
      }
    } else if (S[0] >= '0' && S[0] <= '9') {
      unsigned R;
      if (offset.getAsInteger(10, R)) {
        printDiagnosticValue("Absolute offset is not an integer: '"
                             +Twine(offset)+"'", M, Signatures);
        valid = false;
      }
    } else if (!offset.equals("VI")) {
      size_t n1 = offset.find("+");
      size_t n2 = offset.find("-");
      if (n2 < n1)
        n1 = n2;
      if (n1 == StringRef::npos) {
        printDiagnosticValue("Pattern: unrecognized offset format: '"+
                             Twine(offset)+"'", M, Signatures);
        valid = false;
      } else {
        unsigned R;
        StringRef anchor = offset.substr(0, n1);
        StringRef delta = offset.substr(n1+1);
        if (delta.getAsInteger(10, R)) {
          printDiagnosticValue("Anchored offset is not an integer: '"+
                             Twine(offset)+"'", M, Signatures);
          valid = false;
        }
        if (!offset.startswith("EOF-") &&
            !anchor.equals("EP") &&
            !anchor.equals("SL")) {
          if (anchor[0] == 'S') {
            anchor = anchor.substr(1);
            if (anchor.getAsInteger(10, R)) {
              printDiagnosticValue("Section number in offset is not an integer:"
                                   "'"+Twine(offset)+"'", M, Signatures);
              valid = false;
            }
          } else {
            printDiagnosticValue("Unknown anchor '"+Twine(anchor)+
                                 "' in pattern '"+Twine(Pattern), M, Signatures);
            valid = false;
          }
        }
      }
    }
    Pattern = Pattern.substr(offsetp+1);
  }
  // This is not a comprehensive validation of the pattern, since
  // that is too complicated and has to be kept in sync with what libclamav
  // allows.
  for (unsigned i=0;i<Pattern.size();i++) {
    unsigned char c = Pattern[i];
    if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
        c == '?' || c == '*' || c == '{' || c == '}' ||
        c == '-' || c == '(' || c == ')' || c == '|' || c == '!' ||
        c == '[' || c == ']' || c == 'B' || c == 'L')
      continue;
    printDiagnosticValue("Pattern contains forbidden character '"+Twine(c)+"': "
                         +Twine(Pattern), M, Signatures);
    valid = false;
    break;
  }
  return valid;
}

static bool checkMinimum(llvm::Module *M, std::string s, unsigned min, int kind)
{
  const char *msgreq = NULL, *msgrec;
  unsigned min_required = 0, min_recommended = 0;
  StringRef ref(s);
  // Due to bb #1957 VI and $ sigs don't work properly in 0.96,
  // so using these sigs requires minimum functionality level
  if (ref.find('$') != StringRef::npos ||
      ref.find("VI") != StringRef::npos) {
    min_required = FUNC_LEVEL_096_dev;
    msgreq = "Logical signature use of VI/macros requires minimum "
      "functionality level of 0.96_dev";
  }

  if (kind >= BC_PDF) {
    min_required = FUNC_LEVEL_096_2;
    msgreq = "Using 0.96.2+ hook requires FUNC_LEVEL_096_2 at least";
  }

  if (kind >= BC_PE_ALL) {
    min_required = FUNC_LEVEL_096_2_dev;
    msgreq = "Using 0.96.3 hook requires FUNC_LEVEL_096_2_dev at least";
  }

  size_t pos = 0;
  while ((pos = ref.find_first_of("=><", pos)) != StringRef::npos) {
    pos++;
    if (pos >= 2 && ref[pos-2] != '>' && ref[pos-2] != '<' &&
        pos < ref.size() && ref[pos] != '0') {
      min_recommended = FUNC_LEVEL_096_2;
      msgrec = "Logical signature use of count comparison "
        "requires minimum functionality level of 0.96.2 (bb #2053)";
      break;
    }
  }
  if (min_recommended < FUNC_LEVEL_096_4) {
      min_recommended = FUNC_LEVEL_096_4;
      msgrec = "0.96.4 is minimum recommended engine version. Older versions have quadratic load time";
  }

  if (min_required && min < min_required) {
    printDiagnostic(msgreq, M);
    return false;
  }
  if (min_recommended && min < min_recommended) {
    printDiagnostic(msgrec, M);
  }
  return true;
}

bool ClamBCLogicalCompiler::compileLogicalSignature(Function &F, unsigned target,
                                                    unsigned min, unsigned max,
                                                    const std::string& icon1,
                                                    const std::string& icon2,
                                                    const std::string& container,
                                                    int kind)
{
  LogicalCompiler compiler;

  GlobalVariable *GV = F.getParent()->getGlobalVariable("Signatures");
  if (!GV->hasDefinitiveInitializer()) {
    printDiagnosticValue("Signatures declared but not initialized",
                         F.getParent(), GV);
    return false;
  }
  ConstantStruct *CS = cast<ConstantStruct>(GV->getInitializer());
  unsigned n = CS->getNumOperands();
  if (n&1) {
    printDiagnosticValue("Signatures initializer contains odd # of fields",
                         F.getParent(), GV, true);
    return false;
  }
  // remove the pointer field from Signatures
  std::vector<const Type*> newStruct;
  std::vector<Constant*> newInits;
  const StructType *STy = cast<StructType>(CS->getType());
  const Type* RTy1 = Type::getInt8Ty(GV->getContext());
  const Type* RTy2 = STy->getElementType(1);
  for (unsigned i=0;i<n;i+=2) {
    newStruct.push_back(RTy1);
    newStruct.push_back(RTy2);
    newInits.push_back(ConstantInt::get(RTy1, 0));
    newInits.push_back(CS->getOperand(i+1));
  }
  StructType *STy2 = StructType::get(GV->getContext(), newStruct);
  Constant *NS = ConstantStruct::get(STy2, newInits);
  GlobalVariable *NewGV =
    cast<GlobalVariable>(F.getParent()->getOrInsertGlobal("_Signatures_",
                                                         STy2));
  NewGV->setInitializer(NS);
  NewGV->setConstant(true);
  GV->uncheckedReplaceAllUsesWith(NewGV);
  GV->eraseFromParent();
  NewGV->setLinkage(GlobalValue::InternalLinkage);

  std::vector<std::string> SubSignatures;
  SubSignatures.resize(n/2);
  bool valid = true;
  for (unsigned i=0;i<n;i += 2) {
    Constant *C = CS->getOperand(i);
    unsigned id = 0;
    if (!isa<ConstantAggregateZero>(CS->getOperand(i+1))) {
      ConstantStruct *SS = cast<ConstantStruct>(CS->getOperand(i+1));
      id = cast<ConstantInt>(SS->getOperand(0))->getValue().getZExtValue();
      if (id > n/2 ) {
        printDiagnostic("Signature ID out of range ("+Twine(id)+" > "
                        +Twine(n/2)+")", F.getParent());
        return false;
      }
    }
    std::string String;
    if (!GetConstantStringInfo(C, String)) {
      printDiagnosticValue("Signature is not a static string",
                           F.getParent(), C);
      return false;
    }
    size_t offsetp = String.find(':');
    if (offsetp == StringRef::npos)
	offsetp = 0;
    std::transform(String.begin()+offsetp, String.end(), String.begin()+offsetp, ::tolower);
    valid = validateNDB(String.c_str(), F.getParent(), NewGV);
    SubSignatures[id] = String;
  }
  LogicalNode *node = compiler.compile(F);
  if (!node)
    return false;
  if (node->kind == LOG_TRUE) {
    printDiagnostic("Logical signature: expression is always true", &F);
    return false;
  }
  if (node->kind == LOG_FALSE) {
    printDiagnostic("Logical signature: expression is always false", &F);
    return false;
  }
  if (!valid)
    return false;
  unsigned groups = 0;
  LogicalSignature = virusnames;
  if (min || max || !icon1.empty() || !icon2.empty()) {
    if (!max)
      max = 255;/* for now it should be enough, we can always increase it later
                   */
    if (!min)
      min = FUNC_LEVEL_096_4;
    /* 0.96 is first to have bytecode support, but <0.96.4 has quadratic load
     * time */
    LogicalSignature = LogicalSignature+
      (";Engine:"+Twine(min)+"-"+Twine(max)+",").str();
  } else
    LogicalSignature = LogicalSignature + ";";
  std::string ndbsigs = node2String(node, groups);
  if (!icon1.empty())
    LogicalSignature = LogicalSignature+
      ("IconGroup1:"+Twine(icon1)+",").str();
  if (!icon2.empty())
    LogicalSignature = LogicalSignature+
      ("IconGroup2:"+Twine(icon2)+",").str();
  if (!container.empty())
      LogicalSignature = LogicalSignature+
       ("Container:"+Twine(container)+",").str();
  LogicalSignature = LogicalSignature+
    ("Target:"+Twine(target)).str();

  std::string rawattrs;
  GV = F.getParent()->getGlobalVariable("__ldb_rawattrs");
  if (GV && GV->hasDefinitiveInitializer() &&
      GetConstantStringInfo(GV->getInitializer(), rawattrs)) {
    GV->setLinkage(GlobalValue::InternalLinkage);
    for (unsigned i=0;i<rawattrs.length();i++) {
      unsigned char c = rawattrs[i];
      if (isalnum(c) || c == ':' || c == '-' || c == ',' || c == '_')
        continue;
      printDiagnostic("Invalid character in ldb attribute: "+rawattrs.substr(0,i+1),
                      F.getParent());
      return false;
    }
    LogicalSignature = LogicalSignature + "," + rawattrs;
  }
  LogicalSignature = LogicalSignature+";"+ndbsigs;



  if (groups > 64) {
    printDiagnostic(("Logical signature: a maximum of 64 subexpressions are "
                     "supported, but logical signature has "+Twine(groups)+
                     " groups").str(), &F);
    return false;
  }

  for (std::vector<std::string>::iterator I=SubSignatures.begin(),E=SubSignatures.end();
       I != E; ++I) {
    LogicalSignature += ";"+*I;
  }
  if (!checkMinimum(F.getParent(), LogicalSignature, min, kind))
    return false;

  F.setLinkage(GlobalValue::InternalLinkage);
  return true;
}

bool ClamBCLogicalCompiler::validateVirusName(const std::string& name,
                                              Module &M, bool Suffix)
{
  for (unsigned i=0;i<name.length();i++) {
    unsigned char c = name[i];
    if (Suffix && c == '.') {
      printDiagnostic("Character '.' is not allowed in virusname suffix: '"+
                      name.substr(0,i+1)+"'. Use - or _: "+name.substr(0, i+1), &M);
      return false;
    }
    if (isalnum(c) || c == '_' || c == '-' || c == '.')
      continue;
    printDiagnostic("Invalid character in virusname: "+name.substr(0, i+1), &M);
    return false;
  }
  return true;
}



static bool isUnpacker(unsigned kind)
{
  return kind == BC_PE_UNPACKER;
}

bool ClamBCLogicalCompiler::compileVirusNames(Module &M, unsigned kind)
{
  GlobalVariable *VPFX = M.getGlobalVariable("__clambc_virusname_prefix");
  if (!VPFX || !VPFX->hasDefinitiveInitializer()) {
    if (kind && kind != BC_STARTUP)
      printDiagnostic("Virusname must be declared for non-generic bytecodes",
                      &M);
    return false;
  }
  if (!GetConstantStringInfo(VPFX, virusnames)) {
    if (kind)
      printDiagnostic("Unable to determine virusname prefix string", &M);
    return false;
  }
  if (!validateVirusName(virusnames, M))
    return false;

  GlobalVariable *VNames = M.getGlobalVariable("__clambc_virusnames");
  StringSet<> virusNamesSet;
  std::string virusNamePrefix = virusnames;
  if (VNames && VNames->hasDefinitiveInitializer()) {
    // The virusnames in {} are only informative in the header (so you can
    // see what are the possible virusnames detected by a bytecode),
    // but the  bytecode has the names embedded in itself too, so
    // hand-editing the visible virusnames won't change anything.
    // The prefix isn't editable either.
    ConstantArray *CA = cast<ConstantArray>(VNames->getInitializer());
    bool Valid = true;
    std::vector<std::string> names;

    for (unsigned i=0;i<CA->getNumOperands();i++) {
      std::string virusnamepart;
      Constant *C = CA->getOperand(i);
      if (!GetConstantStringInfo(C, virusnamepart)) {
        printDiagnostic("Unable to determine virusname part string", &M);
        Valid = false;
      }
      if (virusnamepart.empty())
        continue;
      if (!validateVirusName(virusnamepart, M, true))
        Valid = false;
      virusNamesSet.insert(virusnamepart);
      names.push_back(virusnamepart);
    }
    std::sort(names.begin(), names.end());
    if (CA->getNumOperands())
      virusnames += ".{";
    else
      virusnames += "{";
    for (unsigned i=0;i<names.size();i++) {
      if (i)
        virusnames += ",";
      virusnames += names[i];
    }
    virusnames += "}";
    names.clear();
    if (!Valid)
      return false;
    VNames->setLinkage(GlobalValue::InternalLinkage);
  }
  VPFX->setLinkage(GlobalValue::InternalLinkage);
  if (!VPFX->use_empty()) {
    printDiagnostic("Virusname prefix should not be used in the bytecode!", &M);
  } else {
    VPFX->eraseFromParent();
  }

  // Check that the foundVirus() is only called with the declared virusnames.
  // This can come in 3 variants:
  // foundVirus("FULLPREFIX.FULLSUFFIX")
  // foundVirus("FULLSUFFIX")
  // foundVirus("")
  // The former is deprecated, but the compiler should actually transform all
  // calls to foundVirus to include the full virusname.
  Function *F = M.getFunction("setvirusname");
  if (!F || F->use_empty()) {
    // of course we can't check if a foundVirus call is ever reachable,
    // but no foundVirus calls is certainly a bad thing for non-unpacker
    // bytecodes.
    if (!isUnpacker(kind))
      printDiagnostic("Virusnames declared, but foundVirus was not called!", &M);
    // non-fatal
    return true;
  }
  bool Valid = true;
  for (Value::use_iterator I=F->use_begin(),E=F->use_end();
       I != E; ++I) {
    CallSite CS = CallSite::get(*I);
    if (!CS.getInstruction())
      continue;
    if (CS.getCalledFunction() != F) {
      printDiagnostic("setvirusname can only be directly called",
                      CS.getInstruction());
      Valid = false;
      continue;
    }
    assert(CS.arg_size() == 2 && "setvirusname has 2 args");
    std::string param;
    Value *V = CS.getArgument(0);
    if (!GetConstantStringInfo(V, param)) {
      printDiagnostic("Argument of foundVirus() must be a constant string",
                      CS.getInstruction());
      Valid = false;
      continue;
    }
    StringRef p(param);
    // Remove duplicate prefix
    if (p.startswith(virusNamePrefix))
      p = p.substr(virusNamePrefix.length());
    if (!p.empty() && !virusNamesSet.count(p)) {
      printDiagnostic(Twine("foundVirus called with an undeclared virusname: ",
                            p), CS.getInstruction());
      Valid = false;
      continue;
    }
    // Add prefix
    std::string fullname = p.empty() ? virusNamePrefix :
      virusNamePrefix + "." + p.str();
    IRBuilder<> builder(CS.getInstruction()->getParent());
    Value *C = builder.CreateGlobalStringPtr(fullname.c_str());

    const Type *I32Ty = Type::getInt32Ty(M.getContext());
    CS.setArgument(0, C);
    CS.setArgument(1, ConstantInt::get(I32Ty, fullname.size()));
  }
  return Valid;
}

bool ClamBCLogicalCompiler::runOnModule(Module &M)
{
  bool Valid = true;
  LogicalSignature = "";
  virusnames="";
  // Handle virusname
  unsigned kind = 0;
  GlobalVariable *GVKind = M.getGlobalVariable("__clambc_kind");
  if (GVKind && GVKind->hasDefinitiveInitializer()) {
    kind = cast<ConstantInt>(GVKind->getInitializer())->getValue().getZExtValue();
    assert(kind < 65536);
  }
  Function *F = M.getFunction("logical_trigger");
  // bytecode with a logical_trigger is always logical
  if (F && !kind) {
    kind = 256;
    GVKind->setLinkage(GlobalValue::ExternalLinkage);
    GVKind->setInitializer(ConstantInt::get(Type::getInt16Ty(GVKind->getContext()),
                                            kind));
    GVKind->setConstant(true);
  }
  if (!compileVirusNames(M, kind)) {
    if (!kind || kind == BC_STARTUP)
      return true;
    Valid = false;
  }
  if (Valid) {
    NamedMDNode *Node = M.getOrInsertNamedMetadata("clambc.virusnames");
    Value *S = MDString::get(M.getContext(), virusnames);
    MDNode *N = MDNode::get(M.getContext(),  &S, 1);
    Node->addOperand(N);
  }

  GlobalVariable *GV = M.getGlobalVariable("__FuncMin");
  unsigned funcmin = FUNC_LEVEL_096_4, funcmax = 0;
  if (GV && GV->hasDefinitiveInitializer()) {
    NamedMDNode *Node = M.getOrInsertNamedMetadata("clambc.funcmin");
    Value *C = GV->getInitializer();
    MDNode *N = MDNode::get(M.getContext(), &C, 1);
    Node->addOperand(N);
    GV->setLinkage(GlobalValue::InternalLinkage);
    funcmin = cast<ConstantInt>(C)->getZExtValue();
    if (funcmin < FUNC_LEVEL_096) {
      printDiagnostic("Minimum functionality level can't be set lower than "
                      "0.96", &M, GV);
      Valid = false;
    }
  }
  GV = M.getGlobalVariable("__FuncMax");
  if (GV && GV->hasDefinitiveInitializer()) {
    NamedMDNode *Node = M.getOrInsertNamedMetadata("clambc.funcmax");
    Value *C = GV->getInitializer();
    MDNode *N = MDNode::get(M.getContext(), &C, 1);
    Node->addOperand(N);
    GV->setLinkage(GlobalValue::InternalLinkage);
    funcmax = cast<ConstantInt>(C)->getZExtValue();
    if (funcmax < FUNC_LEVEL_096) {
      printDiagnostic("Maximum functionality level can't be set lower than "
                      "0.96", &M, GV);
      Valid = false;
    }
    if (funcmax < funcmin) {
      printDiagnostic("Maximum functionality level can't be lower than "
                      "minimum", &M, GV);
      Valid = false;
    }
  }
  if (F) {
    GV = M.getGlobalVariable("__Target");
    unsigned target = ~0u;
    if (!GV || !GV->hasDefinitiveInitializer()) {
      Valid = false;
      printDiagnostic("__Target not defined", &M, true);
    } else {
      target = cast<ConstantInt>(GV->getInitializer())->getValue().getZExtValue();
      GV->setLinkage(GlobalValue::InternalLinkage);
    }

    std::string icon1, icon2, container;
    GV = M.getGlobalVariable("__IconGroup1");
    if (GV && GV->hasDefinitiveInitializer() &&
        GetConstantStringInfo(GV->getInitializer(), icon1)) {
      if (!validateVirusName(icon1, M))
        Valid = false;
      GV->setLinkage(GlobalValue::InternalLinkage);
    }
    GV = M.getGlobalVariable("__IconGroup2");
    if (GV && GV->hasDefinitiveInitializer() &&
        GetConstantStringInfo(GV->getInitializer(), icon2)) {
      if (!validateVirusName(icon2, M))
        Valid = false;
      GV->setLinkage(GlobalValue::InternalLinkage);
    }
    GV = M.getGlobalVariable("__ldb_container");
    if (GV && GV->hasDefinitiveInitializer() &&
        GetConstantStringInfo(GV->getInitializer(), container)) {
	if (!StringRef(container).startswith("CL_TYPE_"))
	    Valid = false;
	GV->setLinkage(GlobalValue::InternalLinkage);
    }

    //errs() << "icon1:"<<icon1<<" icon2:"<<icon2 <<"\n";
    //TODO: validate that target is a valid target
    if (!compileLogicalSignature(*F, target, funcmin, funcmax, icon1, icon2,
				 container, kind)) {
      Valid = false;
    }
    NamedMDNode *Node = M.getOrInsertNamedMetadata("clambc.logicalsignature");
    Value *S = MDString::get(M.getContext(), LogicalSignature);
    MDNode *N = MDNode::get(M.getContext(),  &S, 1);
    Node->addOperand(N);
    if (F->use_empty())
      F->eraseFromParent();
  }
  if (!Valid) {
    errs() << "lsig not valid!\n";
    // diagnostic already printed
    exit(42);
  }
  return true;
}

}
const PassInfo *const ClamBCLogicalCompilerID = &X;

llvm::ModulePass *createClamBCLogicalCompiler()
{
  return new ClamBCLogicalCompiler();
}
