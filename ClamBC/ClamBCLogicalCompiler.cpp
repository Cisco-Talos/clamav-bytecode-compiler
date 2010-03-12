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
#include "clambc.h"
#include "ClamBCModule.h"
#include "ClamBCCommon.h"
#include "llvm/ADT/FoldingSet.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/Analysis/ConstantFolding.h"
#include "llvm/Analysis/DebugInfo.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/Config/config.h"
#include "llvm/DerivedTypes.h"
#include "llvm/IntrinsicInst.h"
#include "llvm/Module.h"
#include "llvm/ModuleProvider.h"
#include "llvm/Pass.h"
#include "llvm/PassManager.h"
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
  void compileLogicalSignature(Function &F, unsigned target);
  void validateVirusName(const std::string& name);
};
char ClamBCLogicalCompiler::ID = 0;
RegisterPass<ClamBCLogicalCompiler> X("clambc-lcompiler",
                                      "ClamAV logical compiler");
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
      return getFalse(V[0]->Set);
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
  FunctionPassManager *PM = new FunctionPassManager(new ExistingModuleProvider(F.getParent()));
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
    if (!GV)
      ClamBCModule::stop("__clambc_match_counts is not declared for logical signature bytecode");
    // Speculatively execute all instructions where it is safe to do so.
    // This simplifies the function, making it more suitable for
    // converting to a logical expression.
    SpeculativelyExecute(F);
    if (F.begin() != F.end())
      DEBUG(errs() << "Trigger function has more than 1 basic block:\n";
            F.dump());

    processBB(&F.getEntryBlock());
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
  void processLoad(LoadInst &LI)
  {
    Value *V = LI.getOperand(0);
    ConstantExpr *CE = dyn_cast<ConstantExpr>(V);
    if (!CE || CE->getOpcode() != Instruction::GetElementPtr ||
        CE->getOperand(0) != GV || CE->getNumOperands() != 3 ||
        !cast<ConstantInt>(CE->getOperand(1))->isZero()) {
      ClamBCModule::stop("Logical signature: unsupported load", 0, &LI);
    }
    ConstantInt *CI = cast<ConstantInt>(CE->getOperand(2));
    Map[&LI] = LogicalNode::getSubSig(allNodes, CI->getValue().getZExtValue());
  }

  void processICmp(ICmpInst &IC)
  {
    Value *op0 = IC.getOperand(0);
    Value *op1 = IC.getOperand(1);
    if (isa<Constant>(op0))
      std::swap(op0, op1);
    ConstantInt *RHS = dyn_cast<ConstantInt>(op1);
    if (!RHS)
      ClamBCModule::stop("Logical signature: unsupported compare, must compare to a constant", 0, &IC);
    uint64_t v = RHS->getValue().getZExtValue();
    uint32_t rhs = (uint32_t)v;
    if (v != rhs)
      ClamBCModule::stop("Logical signature: constant needs more than 32-bits", 0, &IC);
    LogicalMap::iterator I = Map.find(op0);
    if (I == Map.end())
      ClamBCModule::stop("Logical signature: must compare match count against constant", 0, &IC);
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
      if (!rhs)
        ClamBCModule::stop("Logical signature: count >= 0 is always true, probably a typo?", 0, &IC);
      Node = LogicalNode::getGT(I->second, rhs-1);
      break;
    case CmpInst::ICMP_ULT:
      Node = LogicalNode::getLT(I->second, rhs);
      break;
    case CmpInst::ICMP_ULE:
      if (rhs == ~0u)
        ClamBCModule::stop("Logical signature: count <= ~0u is always true, probably a type?", 0, &IC);
      Node = LogicalNode::getLT(I->second, rhs+1);
      break;
    case CmpInst::ICMP_SGT:
    case CmpInst::ICMP_SGE:
    case CmpInst::ICMP_SLE:
    case CmpInst::ICMP_SLT:
      ClamBCModule::stop("Logical signature: signed compares not supported, please use unsigned compares!", 0, &IC);
      break;
    default:
      ClamBCModule::stop("Logical signature: unsupported compare operator", 0, &IC);
    }
    Map[&IC] = Node;
  }

  void processBB(BasicBlock *BB)
  {
    Visiting.insert(BB);
    for (BasicBlock::iterator I=BB->begin(), E=BB->end(); I != E; ++I) {
      if (isa<DbgInfoIntrinsic>(I))
        continue;
      if (isa<AllocaInst>(I))
        continue;
      switch (I->getOpcode()) {
      case Instruction::Load:
        processLoad(*cast<LoadInst>(I));
        break;
      case Instruction::ICmp:
        processICmp(*cast<ICmpInst>(I));
        break;
      case Instruction::Br:
        {
          BranchInst *BI = cast<BranchInst>(I);
          if (BI->isUnconditional()) {
            if (Visiting.count(BB)) {
              ClamBCModule::stop("Logical signature: loop/recursion not supported", 0, BI);
            }
            processBB(BI->getSuccessor(0));
            return;
          }
          Value *V = BI->getCondition();
          LogicalMap::iterator J = Map.find(V);
          if (J == Map.end())
            ClamBCModule::stop("Logical signature: Branch condition must be logical expression", 0, BI);
          LogicalNode *Node = J->second;
          Stack.push_back(Node);
          if (Visiting.count(BI->getSuccessor(0)))
            ClamBCModule::stop("Logical signature: loop/recursion not supported", 0, BI);
          processBB(BI->getSuccessor(0));
          Stack.pop_back();
          Node = LogicalNode::getNot(Node);
          Stack.push_back(Node);
          if (Visiting.count(BI->getSuccessor(1)))
            ClamBCModule::stop("Logical signature: loop/recursion not supported", 0, BI);
          processBB(BI->getSuccessor(1));
          assert(Stack.back() == Node);
          Stack.pop_back();
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
          if (J == Map.end())
            ClamBCModule::stop("Logical signature: return value must be logical expression", 0, I);
          LogicalNode *Node = J->second;
          Stack.push_back(Node);
          exitNodesOr.push_back(LogicalNode::getAnd(allNodes, Stack));
          Stack.pop_back();
          break;
        }
      case Instruction::Add:
        {
          LogicalMap::iterator J = Map.find(I->getOperand(0));
          if (J == Map.end())
            ClamBCModule::stop("Logical signature: add operands must be logical expressions", 0, I);
          ConstantInt *CI = dyn_cast<ConstantInt>(I->getOperand(1));
          if (CI) {
            Map[I] = LogicalNode::getAdd(J->second, CI->getValue().getZExtValue());
          } else {
            LogicalMap::iterator J2 = Map.find(I->getOperand(1));
            if (J2 == Map.end())
              ClamBCModule::stop("Logical signature: add operands must be logical expressions", 0, I);
            LogicalNode *N = LogicalNode::getAdd(J->second, J2->second);
            if (!N)
              ClamBCModule::stop("Logical signature: add operands mismatch, only supported adding of counts, uniqueness, and constants\n", 0, I);
            if (!N->checkUniq()) {
              ClamBCModule::stop("Logical signature: duplicate operands for add not supported\n", 0, I);
            }
            Map[I] =N;
          }
          break;
        }
      case Instruction::And:
        {
          LogicalMap::iterator J1 = Map.find(I->getOperand(0));
          LogicalMap::iterator J2 = Map.find(I->getOperand(1));
          if (J1 == Map.end() || J2 == Map.end())
            ClamBCModule::stop("Logical signature: and operands must be logical expressions", 0, I);
          Map[I] = LogicalNode::getAnd(J1->second, J2->second);
          break;
        }
      case Instruction::Or:
        {
          LogicalMap::iterator J1 = Map.find(I->getOperand(0));
          LogicalMap::iterator J2 = Map.find(I->getOperand(1));
          if (J1 == Map.end() || J2 == Map.end())
            ClamBCModule::stop("Logical signature: or operands must be logical expressions", 0, I);
          Map[I] = LogicalNode::getOr(J1->second, J2->second);
          break;
        }
      case Instruction::Xor:
        {
          ConstantInt *CI = dyn_cast<ConstantInt>(I->getOperand(1));
          if (!CI || !CI->isOne())
            ClamBCModule::stop("Logical signature: xor only supported for negation", 0, I);
          LogicalMap::iterator J1 = Map.find(I->getOperand(0));
          if (J1 == Map.end())
            ClamBCModule::stop("Logical signature: xor operand must be logical expressions", 0, I);
          Map[I] = LogicalNode::getNot(J1->second);
          break;
        }
      case Instruction::ZExt:
        {
          LogicalMap::iterator J = Map.find(I->getOperand(0));
          if (J == Map.end())
            ClamBCModule::stop("Logical signature: zext operand must be logical expressions", 0, I);
          ZExtInst *ZI = cast<ZExtInst>(I);
          unsigned from = ZI->getSrcTy()->getPrimitiveSizeInBits();
          unsigned to = ZI->getDestTy()->getPrimitiveSizeInBits();
          if (from != 1 || to != 32) {
            ClamBCModule::stop("Logical signature: only support zero extend from i1 to i32, but encountered "+Twine(from)+" to "+Twine(to));
          }
          Map[I] = LogicalNode::getUniqueSigs(J->second);
          break;
        }
      default:
        ClamBCModule::stop("Logical signature: unsupported instruction", 0, I);
        break;
      }
    }
    Visiting.erase(BB);
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

void ClamBCLogicalCompiler::compileLogicalSignature(Function &F, unsigned target)
{
  LogicalCompiler compiler;
  LogicalNode *node = compiler.compile(F);
  if (node->kind == LOG_TRUE)
    ClamBCModule::stop("Logical signature: expression is always true", &F);
  if (node->kind == LOG_FALSE)
    ClamBCModule::stop("Logical signature: expression is always false", &F);
  unsigned groups = 0;
  LogicalSignature = (Twine(virusnames)+";Target:"+Twine(target)+";" + node2String(node, groups)).str();
  if (groups > 64) {
    ClamBCModule::stop("Logical signature: a maximum of 64 subexpressions are supported, but logical signature has "+Twine(groups)+" groups");
  }
  GlobalVariable *GV = F.getParent()->getGlobalVariable("Signatures");
  if (!GV->hasDefinitiveInitializer())
    return;//TODO:diagnose error
  ConstantStruct *CS = cast<ConstantStruct>(GV->getInitializer());
  unsigned n = CS->getNumOperands();
  if (n&1)
    return;//TODO:diagnose error
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
  for (unsigned i=0;i<n;i += 2) {
    Constant *C = CS->getOperand(i);
    unsigned id = 0;
    if (!isa<ConstantAggregateZero>(CS->getOperand(i+1))) {
      ConstantStruct *SS = cast<ConstantStruct>(CS->getOperand(i+1));
      id = cast<ConstantInt>(SS->getOperand(0))->getValue().getZExtValue();
      if (id > n/2)
        return;//TODO:diagnose error
    }
    std::string String;
    if (!GetConstantStringInfo(C, String))
      return;//TODO:diagnose error
    const char *s2 = String.c_str();
    const char *s = strchr(s2, ':');
    if (!s) s = s2;
    else {
      s++;
      //TODO: validate anchor
    }
    for (; *s; s++) {
      const char c = *s;
      if ((c >= '0' && c <= '9') || (c >= 'a' && c <='f'))
        continue;
      ClamBCModule::stop((Twine("pattern is not hexadecimal: ")+s).str());
      return;//TODO:diagnose error
    }
    SubSignatures[id] = String;
  }
  for (std::vector<std::string>::iterator I=SubSignatures.begin(),E=SubSignatures.end();
       I != E; ++I) {
    LogicalSignature += ";"+*I;
  }
  F.setLinkage(GlobalValue::InternalLinkage);
}

void ClamBCLogicalCompiler::validateVirusName(const std::string& name)
{
  for (unsigned i=0;i<name.length();i++) {
    unsigned char c = name[i];
    if (isalnum(c) || c == '_' || c == '-' || c == '.')
      continue;
    ClamBCModule::stop("Invalid character in virusname: "+name.substr(i, 1));
  }
}

bool ClamBCLogicalCompiler::runOnModule(Module &M)
{
  NamedMDNode *Node = M.getOrInsertNamedMetadata("clambc.logicalsignature");
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
  GlobalVariable *VPFX = M.getGlobalVariable("__clambc_virusname_prefix");
  if (!VPFX || !VPFX->hasDefinitiveInitializer()) {
    if (kind)
      ClamBCModule::stop("Virusname must be declared for non-generic bytecodes");
  } else {
    if (!GetConstantStringInfo(VPFX, virusnames))
      ClamBCModule::stop("Unable to determine virusname prefix string");
    validateVirusName(virusnames);
    GlobalVariable *VNames = M.getGlobalVariable("__clambc_virusnames");
    if (VNames && VNames->hasDefinitiveInitializer()) {
      // The virusnames in {} are only informative in the header (so you can
      // see what are the possible virusnames detected by a bytecode),
      // but the  bytecode has the names embedded in itself too, so
      // hand-editing the visible virusnames won't change anything.
      // Only the virusname prefix is hand/script-editable.
      ConstantArray *CA = cast<ConstantArray>(VNames->getInitializer());
      if (CA->getNumOperands())
        virusnames += ".{";
      else
        virusnames += "{";
      for (unsigned i=0;i<CA->getNumOperands();i++) {
        std::string virusnamepart;
        Constant *C = CA->getOperand(i);
        if (!GetConstantStringInfo(C, virusnamepart))
          ClamBCModule::stop("Unable to determine virusname part string");
        if (i)
          virusnames += ",";
        virusnames += virusnamepart;
      }
      virusnames += "}";
      VNames->setLinkage(GlobalValue::InternalLinkage);
    } else virusnames += "{}";
    VPFX->setLinkage(GlobalValue::InternalLinkage);
    if (!VPFX->use_empty()) {
      ClamBCModule::stop("Virusname prefix must not be used in the bytecode, because virusname prefix needs to be editable to solve virusname clashes!");
    }
    //TODO: check that foundVirus/setvirusname is called only with one of
    //these virusnames
  }
  if (F) {
    GlobalVariable *GV = M.getGlobalVariable("__Target");
    if (!GV || !GV->hasDefinitiveInitializer())
      ClamBCModule::stop("__Target not defined");
    unsigned target = cast<ConstantInt>(GV->getInitializer())->getValue().getZExtValue();
    GV->setLinkage(GlobalValue::InternalLinkage);
    //TODO: validate that target is a valid target
    compileLogicalSignature(*F, target);
  }
  Node->addElement(MDString::get(M.getContext(), LogicalSignature));
  return true;
}

}
const PassInfo *const ClamBCLogicalCompilerID = &X;

llvm::ModulePass *createClamBCLogicalCompiler()
{
  return new ClamBCLogicalCompiler();
}
