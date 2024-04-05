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

#include "clambc.h"
#include "bytecode_api.h"
#include "ClamBCDiagnostics.h"
#include "ClamBCCommon.h"
#include "ClamBCUtilities.h"

#include <llvm/Support/DataTypes.h>
#include <llvm/ADT/FoldingSet.h>
#include <llvm/ADT/SmallPtrSet.h>
#include <llvm/ADT/StringSet.h>
#include <llvm/Analysis/ConstantFolding.h>
#include <llvm/IR/DebugInfo.h>
#include <llvm/Analysis/ValueTracking.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/Module.h>
#include <llvm/Pass.h>
#include <llvm/IR/PassManager.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/PassPlugin.h>
#include <llvm/IR/ConstantRange.h>
#include <llvm/Support/Debug.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/Support/FormattedStream.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/Process.h>
#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Utils/Local.h>
#include <llvm/Transforms/IPO.h>
#include <llvm/IR/Type.h>
#include <llvm/Transforms/Utils.h>
#include <llvm/LinkAllPasses.h>

#define DEBUG_TYPE "lsigcompiler"

using namespace llvm;

namespace ClamBCLogicalCompiler
{

class ClamBCLogicalCompiler : public PassInfoMixin<ClamBCLogicalCompiler>
{
  public:
    ClamBCLogicalCompiler() {}

    virtual PreservedAnalyses run(Module &m, ModuleAnalysisManager &MAM);
    virtual void getAnalysisUsage(AnalysisUsage &AU) const
    {
        AU.setPreservesCFG();
        AU.addRequired<LoopInfoWrapperPass>();
    }

  private:
    std::string LogicalSignature;
    std::string virusnames;
    llvm::Module *pMod;

    bool compileLogicalSignature(Function &F, unsigned target, unsigned min,
                                 unsigned max, const std::string &icon1,
                                 const std::string &icon2,
                                 const std::string &container,
                                 int kind);
    bool validateVirusName(const std::string &name, Module &M, bool suffix = false);
    bool compileVirusNames(Module &M, unsigned kind);
};

enum LogicalKind {
    LOG_SUBSIGNATURE,
    LOG_AND,
    LOG_OR,
    LOG_EQ,
    LOG_GT,
    LOG_LT,
    LOG_ADDBOTH, /* checks both the sum of the individual matches, and the number of different subsignatures that matched */
    /* not actually supported by libclamav, will be folded */
    LOG_NOT,
    LOG_TRUE,
    LOG_FALSE,
    LOG_ADD,
    LOG_ADDSUM, /* sum up counts of (logical) subsignatures */
    LOG_ADDUNIQ /* sum up number of different subsignatures that matched */
};

// LogicalNodes are uniqued
class LogicalNode;
typedef FoldingSet<LogicalNode> LogicalNodes;
class LogicalNode : public FoldingSetNode
{
  private:
    LogicalNodes &Set;

  public:
    void Profile(FoldingSetNodeID &ID) const
    {
        ID.AddInteger(op0);
        ID.AddInteger(op1);
        ID.AddInteger(kind);
        for (std::vector<LogicalNode *>::const_iterator I = children.begin(), E = children.end();
             I != E; ++I) {
            ID.AddPointer(*I);
        }
    }

    static LogicalNode *getNode(const LogicalNode &N)
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

    static LogicalNode *getTrue(LogicalNodes &Set)
    {
        LogicalNode N(Set, LOG_TRUE);
        return getNode(N);
    }

    static LogicalNode *getFalse(LogicalNodes &Set)
    {
        LogicalNode N(Set, LOG_FALSE);
        return getNode(N);
    }

    static LogicalNode *getSubSig(LogicalNodes &Set, unsigned subsigid)
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
            case LOG_ADDSUM: {
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
        std::vector<LogicalNode *> nodes;
        // a in [min, max] -> a >= min && a <= max
        if (min) { // a >= 0 -> true
            // a >= min, min != 0 ->  a > min-1
            min--;
            nodes.push_back(getGT(Node, min));
        }
        if (++max) { // a <= ~0u -> true
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
            ConstantRange ltRange = ConstantRange::makeSatisfyingICmpRegion(CmpInst::ICMP_ULT, Cmp);

            ltRange      = ltRange.subtract(APInt(32, Node->op0));
            Node         = Node->children[0];
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
            ConstantRange ltRange = ConstantRange::makeSatisfyingICmpRegion(CmpInst::ICMP_UGT, Cmp);
            ltRange               = ltRange.subtract(APInt(32, Node->op0));
            Node                  = Node->children[0];
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
        std::vector<LogicalNode *> V;
        V.reserve(2);
        V.push_back(LHS);
        V.push_back(RHS);
        return getOr(V);
    }

    static LogicalNode *getAnd(LogicalNode *LHS, LogicalNode *RHS)
    {
        std::vector<LogicalNode *> V;
        V.reserve(2);
        V.push_back(LHS);
        V.push_back(RHS);
        return getAnd(V);
    }

    static LogicalNode *getNot(LogicalNode *Op)
    {
        std::vector<LogicalNode *> nodes;
        // 'Not' is not supported by libclamav, lower it
        switch (Op->kind) {
            case LOG_SUBSIGNATURE:
                // !a -> a == 0
                return getEQ(Op, 0);
            case LOG_AND:
                // DeMorgan's law: !(a && b) -> !a || !b
                for (std::vector<LogicalNode *>::iterator I = Op->children.begin(),
                                                          E = Op->children.end();
                     I != E; ++I) {
                    nodes.push_back(getNot(*I));
                }
                return getOr(nodes);
            case LOG_OR:
                // DeMorgan's law: !(a || b) -> !a && !b
                for (std::vector<LogicalNode *>::iterator I = Op->children.begin(),
                                                          E = Op->children.end();
                     I != E; ++I) {
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
                nodes.push_back(getGT(Op->children[0], Op->op0));
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

    /*Test for duplicates*/
    bool checkUniq()
    {
        LogicalSet nodes;
        for (const_iterator i = begin(), e = end(); i != e; i++) {
            const_iterator search = i;
            search++;
            if (e != std::find(search, e, *i)) {
                return false;
            }
        }
        return true;
    }

    static bool compare_lt(LogicalNode *LHS, LogicalNode *RHS)
    {
        if (LHS->kind != RHS->kind)
            return LHS->kind < RHS->kind;
        if (LHS->op0 != RHS->op0)
            return LHS->op0 < RHS->op0;
        if (LHS->op1 != RHS->op1)
            return LHS->op0 < RHS->op0;
        if (LHS->children.size() != RHS->children.size())
            return LHS->children.size() < RHS->children.size();
        for (const_iterator I = LHS->begin(), J = RHS->begin(), E = LHS->end(); I != E; ++I, ++J) {
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

    static LogicalNode *getAnd(LogicalNodes &Set, const std::vector<LogicalNode *> &V)
    {
        if (V.empty())
            return getTrue(Set);
        return getAnd(V);
    }

    static LogicalNode *getOr(LogicalNodes &Set, const std::vector<LogicalNode *> &V)
    {
        if (V.empty())
            return getTrue(Set);
        return getOr(V);
    }

    const uint32_t op0, op1;
    const enum LogicalKind kind;
    typedef std::vector<LogicalNode *>::const_iterator const_iterator;
    const_iterator begin() const
    {
        return children.begin();
    }
    const_iterator end() const
    {
        return children.end();
    }
    size_t size() const
    {
        return children.size();
    }
    LogicalNode *front() const
    {
        return children[0];
    }

  private:
    LogicalNode(LogicalNodes &Set, enum LogicalKind kind, uint32_t value = ~0u, uint32_t uniq = ~0u)
        : Set(Set), op0(value), op1(uniq), kind(kind) {}
    std::vector<LogicalNode *> children;
    typedef SmallPtrSet<LogicalNode *, 4> LogicalSet;

    static LogicalNode *getAnd(const std::vector<LogicalNode *> &V)
    {
        assert(!V.empty());
        LogicalNode N(V[0]->Set, LOG_AND);
        typedef DenseMap<LogicalNode *, SmallVector<LogicalNode *, 2>> LogicalMap;
        // There can be multiple addcounts/addmatchs with same subexpression
        // but different =X,Y modifier, so we need a map of vector.
        LogicalMap adds;
        LogicalSet others;

        std::vector<LogicalNode *> nodes(V);

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
                case LOG_EQ: {
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

        for (LogicalMap::iterator I = adds.begin(), E = adds.end();
             I != E; ++I) {
            std::vector<LogicalNode *> adduniq;
            std::vector<LogicalNode *> addsum;
            // all =X and =Y,Y with same subexpression is in this
            // vector, so separate them into addcounts, addmatch
            for (SmallVector<LogicalNode *, 2>::iterator J  = I->second.begin(),
                                                         JE = I->second.end();
                 J != JE; ++J) {
                LogicalNode *N = *J;
                if (N->op1 == ~0u) {
                    addsum.push_back(N);
                    continue;
                }
                assert(N->op1 == N->op0);
                adduniq.push_back(N);
            }

            for (std::vector<LogicalNode *>::iterator J  = addsum.begin(),
                                                      JE = addsum.end();
                 J != JE; ++J) {
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
            for (std::vector<LogicalNode *>::iterator J  = adduniq.begin(),
                                                      JE = adduniq.end();
                 J != JE; ++J) {
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

    static LogicalNode *getOr(const std::vector<LogicalNode *> &V)
    {
        assert(!V.empty());
        LogicalNode N(V[0]->Set, LOG_OR);
        LogicalSet nodes;
        for (std::vector<LogicalNode *>::const_iterator I = V.begin(), E = V.end();
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
static std::string node2String(LogicalNode *node, unsigned &groups);

class LogicalCompiler
{
  public:
    LogicalNode *compile(Function &F)
    {
        GV = F.getParent()->getGlobalVariable("__clambc_match_counts");
        if (!GV) {
            printDiagnostic("__clambc_match_counts is not declared for logical"
                            " signature bytecode",
                            F.getParent(), true);
            return 0;
        }

        for (auto i = F.begin(), e = F.end(); i != e; i++) {
            BasicBlock *pBB = llvm::cast<BasicBlock>(i);
            if (not processBB(pBB)) {
                printDiagnostic("Unable to compile to logical signature", &F);
                return nullptr;
            }
        }

        return LogicalNode::getAnd(LogicalNode::getOr(allNodes, exitNodesOr),
                                   LogicalNode::getAnd(allNodes, exitNodesAnd));
    }

  private:
    typedef DenseMap<const Value *, LogicalNode *> LogicalMap;
    LogicalNodes allNodes;
    LogicalMap Map;
    std::vector<LogicalNode *> Stack;
    std::vector<LogicalNode *> exitNodesOr;
    std::vector<LogicalNode *> exitNodesAnd;
    SmallPtrSet<BasicBlock *, 10> Visiting;
    GlobalVariable *GV;
    bool processLoad(LoadInst &LI)
    {
        Value *V         = LI.getOperand(0);
        ConstantExpr *CE = dyn_cast<ConstantExpr>(V);
        ConstantInt *CI  = nullptr;
        if (CE) {
            if (CE->getOpcode() != Instruction::GetElementPtr ||
                CE->getOperand(0) != GV || CE->getNumOperands() != 3 ||
                !cast<ConstantInt>(CE->getOperand(1))->isZero()) {
                printDiagnostic("Logical signature: unsupported read", &LI);
                return false;
            }
            CI = cast<ConstantInt>(CE->getOperand(2));
        } else {
            /* In this case, we are directly loading the global,
             * instead of using a getelementptr.
             * It is likely that this would have been changed by O3.
             */
            CI = ConstantInt::get(LI.getParent()->getParent()->getParent()->getContext(), APInt(64, 0));
        }
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
                            " must compare to a constant",
                            &IC);
            return false;
        }
        uint64_t v   = RHS->getValue().getZExtValue();
        uint32_t rhs = (uint32_t)v;
        if (v != rhs) {
            printDiagnostic("Logical signature: constant needs more than 32-bits",
                            &IC);
            return false;
        }
        LogicalMap::iterator I = Map.find(op0);
        if (I == Map.end()) {
            printDiagnostic("Logical signature: must compare match count against"
                            " constant",
                            &IC);
            return false;
        }
        LogicalNode *Node = 0;
        switch (IC.getPredicate()) {
            case CmpInst::ICMP_EQ:
                Node = LogicalNode::getEQ(I->second, rhs);
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
                                    ", probably a typo?",
                                    &IC);
                    return false;
                }
                Node = LogicalNode::getGT(I->second, rhs - 1);
                break;
            case CmpInst::ICMP_ULT:
                Node = LogicalNode::getLT(I->second, rhs);
                break;
            case CmpInst::ICMP_ULE:
                if (rhs == ~0u) {
                    printDiagnostic("Logical signature: count <= ~0u is always true"
                                    ", probably a type?",
                                    &IC);
                    return false;
                }
                Node = LogicalNode::getLT(I->second, rhs + 1);
                break;
            case CmpInst::ICMP_SGT:
            case CmpInst::ICMP_SGE:
            case CmpInst::ICMP_SLE:
            case CmpInst::ICMP_SLT:
                printDiagnostic("Logical signature: signed compares not supported"
                                ", please use unsigned compares!",
                                &IC);
                return false;
            default:
                printDiagnostic("Logical signature: unsupported compare operator", &IC);
                return false;
        }
        Map[&IC] = Node;
        return true;
    }

    class LogicalPHIHelper
    {
      public:
        LogicalPHIHelper(BranchInst *bi, bool isTrue)
        {
            pBranchInst  = bi;
            pBasicBlock  = bi->getParent();
            this->isTrue = isTrue;
        }

        LogicalPHIHelper(LogicalPHIHelper *lph)
        {
            this->pBasicBlock = lph->pBasicBlock;
            this->pBranchInst = lph->pBranchInst;
            this->isTrue      = lph->isTrue;
        }

        virtual ~LogicalPHIHelper() {}

        BranchInst *getBranchInst()
        {
            return pBranchInst;
        }

        BasicBlock *getBasicBlock()
        {
            return pBasicBlock;
        }

        bool getIsTrue()
        {
            return isTrue;
        }

        Value *getCondition()
        {
            if (pBranchInst->isConditional()) {
                return pBranchInst->getCondition();
            }
            return nullptr;
        }

      protected:
        BasicBlock *pBasicBlock;

        BranchInst *pBranchInst;

        bool isTrue;
    };

    /*Generate all paths from the 'curr' to 'end' and store them in routes.*/
    void populateRoutes(BasicBlock *curr, BasicBlock *end, std::vector<std::vector<LogicalPHIHelper *>> &routes, size_t idx)
    {

        if (curr == end) {
            return;
        }

        for (size_t i = 0; i < routes[idx].size(); i++) {
            if (routes[idx][i]->getBranchInst() == curr->getTerminator()) {
                return;
            }
        }

        if (BranchInst *bi = llvm::dyn_cast<BranchInst>(curr->getTerminator())) {
            if (bi->isConditional()) {
                // copy the route, so that there are separate paths for the true
                // and false condition.
                std::vector<LogicalPHIHelper *> route;
                for (size_t i = 0; i < routes[idx].size(); i++) {
                    route.push_back(new LogicalPHIHelper(routes[idx][i]));
                }
                routes.push_back(route);
                size_t falseIdx = routes.size() - 1;

                routes[idx].push_back(new LogicalPHIHelper(bi, true));
                routes[falseIdx].push_back(new LogicalPHIHelper(bi, false));

                populateRoutes(bi->getSuccessor(0), end, routes, idx);
                populateRoutes(bi->getSuccessor(1), end, routes, falseIdx);

            } else {
                routes[idx].push_back(new LogicalPHIHelper(bi, true));
                populateRoutes(bi->getSuccessor(0), end, routes, idx);
            }
        }
    }

    /* Find all routes from the entry BasicBlock that end with 'pBasicBlock' */
    std::vector<size_t> findRoute(BasicBlock *pBasicBlock, std::vector<std::vector<LogicalPHIHelper *>> &routes)
    {
        std::vector<size_t> ret;
        for (size_t i = 0; i < routes.size(); i++) {
            size_t lastIdx = routes[i].size() - 1;
            if (routes[i][lastIdx]->getBasicBlock() == pBasicBlock) {
                ret.push_back(i);
            }
        }
        return ret;
    }

    LogicalNode *getLogicalNode(std::vector<LogicalPHIHelper *> &route)
    {
        LogicalNode *ret = nullptr;

        for (size_t i = 0; i < route.size(); i++) {
            Value *vCond = route[i]->getCondition();
            if (vCond) {
                LogicalNode *ln = Map.find(vCond)->second;
                if (not route[i]->getIsTrue()) {
                    ln = LogicalNode::getNot(ln);
                }

                if (nullptr == ret) {
                    ret = ln;
                } else {
                    ret = LogicalNode::getAnd(ret, ln);
                }
            }
        }

        return ret;
    }

    /*
     * Our method for processing a phi node is to find all possible paths to a phi node
     * that could generate 'true' and Or them together.
     *
     * For example: Consider the following function.
     *
        ; Function Attrs: noinline norecurse nounwind readnone uwtable
        define dso_local zeroext i1 @logical_trigger() local_unnamed_addr #0 {
        entry:
          %0 = load i32, i32* getelementptr inbounds ([64 x i32], [64 x i32]* @__clambc_match_counts, i64 0, i64 0), align 16
          %cmp.i = icmp eq i32 %0, 0
          %1 = load i32, i32* getelementptr inbounds ([64 x i32], [64 x i32]* @__clambc_match_counts, i64 0, i64 1), align 4
          %cmp.i53 = icmp eq i32 %1, 0
          %or.cond = or i1 %cmp.i, %cmp.i53
          br i1 %or.cond, label %return, label %if.end

        if.end:                                           ; preds = %entry
          %2 = load i32, i32* getelementptr inbounds ([64 x i32], [64 x i32]* @__clambc_match_counts, i64 0, i64 2), align 8
          %cmp.i47 = icmp eq i32 %2, 0
          br i1 %cmp.i47, label %if.else, label %if.then5

        if.then5:                                         ; preds = %if.end
          %3 = load i32, i32* getelementptr inbounds ([64 x i32], [64 x i32]* @__clambc_match_counts, i64 0, i64 4), align 16
          %cmp.i41 = icmp eq i32 %3, 0
          br i1 %cmp.i41, label %if.end20, label %return

        if.else:                                          ; preds = %if.end
          %4 = load i32, i32* getelementptr inbounds ([64 x i32], [64 x i32]* @__clambc_match_counts, i64 0, i64 3), align 4
          %cmp.i35 = icmp eq i32 %4, 0
          br i1 %cmp.i35, label %return, label %if.then12

        if.then12:                                        ; preds = %if.else
          %5 = load i32, i32* getelementptr inbounds ([64 x i32], [64 x i32]* @__clambc_match_counts, i64 0, i64 4), align 16
          %cmp = icmp ne i32 %5, 2
          %6 = load i32, i32* getelementptr inbounds ([64 x i32], [64 x i32]* @__clambc_match_counts, i64 0, i64 5), align 4
          %cmp.i25 = icmp eq i32 %6, 0
          %or.cond1 = or i1 %cmp, %cmp.i25
          br i1 %or.cond1, label %if.end20, label %return

        if.end20:                                         ; preds = %if.then12, %if.then5
          br label %return

        return:                                           ; preds = %if.else, %if.then12, %if.then5, %entry, %if.end20
          %retval.0 = phi i1 [ true, %if.end20 ], [ false, %entry ], [ false, %if.then5 ], [ false, %if.then12 ], [ false, %if.else ]
          ret i1 %retval.0
        }


        The phi node is
        %retval.0 = phi i1 [ true, %if.end20 ], [ false, %entry ], [ false, %if.then5 ], [ false, %if.then12 ], [ false, %if.else ]

        This can only return true if the %return block is entered from the %if.end20 block.  There are two possible cases
        for that to happen, which will be OR'd together.

        The logical expression for this PHINode is
        (%or.cond1 AND (NOT %cmp.i35) AND %cmp.i47 AND (NOT %or.cond)) OR (%cmp.i41 AND (NOT %cmp.i47) AND (NOT %or.cond))
     *
     */
    void processPHI(PHINode *pn)
    {
        BasicBlock *phiBlock   = pn->getParent();
        BasicBlock *startBlock = llvm::cast<BasicBlock>(pn->getParent()->getParent()->begin());

        std::vector<std::vector<LogicalPHIHelper *>> routes;
        std::vector<LogicalPHIHelper *> route;
        routes.push_back(route);
        populateRoutes(startBlock, phiBlock, routes, 0);

        LogicalNode *ln = nullptr;

        for (size_t i = 0; i < pn->getNumIncomingValues(); i++) {
            Value *vIncoming = pn->getIncomingValue(i);
            ConstantInt *pci = llvm::dyn_cast<ConstantInt>(vIncoming);
            if (pci) {
                if (pci->isZero()) {
                    continue;
                }
            }
            std::vector<size_t> idxs = findRoute(pn->getIncomingBlock(i), routes);
            for (size_t j = 0; j < idxs.size(); j++) {
                size_t idx       = idxs[j];
                LogicalNode *tmp = getLogicalNode(routes[idx]);
                if (nullptr == pci) { // Then this isn't a constant
                    LogicalNode *l = Map.find(vIncoming)->second;
                    tmp            = LogicalNode::getAnd(tmp, l);
                }
                if (nullptr == ln) {
                    ln = tmp;
                } else {
                    ln = LogicalNode::getOr(ln, tmp);
                }
            }
        }
        Map[pn] = ln;

        for (size_t i = 0; i < routes.size(); i++) {
            for (size_t j = 0; j < routes[i].size(); j++) {
                delete (routes[i][j]);
            }
        }
    }

    bool processBB(BasicBlock *BB)
    {
        bool valid = true;
        Visiting.insert(BB);
        for (BasicBlock::iterator I = BB->begin(), E = BB->end(); I != E; ++I) {
            if (isa<DbgInfoIntrinsic>(I))
                continue;
            if (isa<AllocaInst>(I))
                continue;

            if (isa<PHINode>(I)) {
                PHINode *phiNode = llvm::cast<PHINode>(I);
                processPHI(phiNode);
                continue;
            }

            Instruction *pInst = llvm::cast<Instruction>(I);

            switch (I->getOpcode()) {
                case Instruction::Load:
                    valid &= processLoad(*cast<LoadInst>(I));
                    break;
                case Instruction::ICmp:
                    valid &= processICmp(*cast<ICmpInst>(I));
                    break;
                case Instruction::Br: {
                    BranchInst *BI = cast<BranchInst>(I);
                    if (BI->isUnconditional()) {
                        return true;
                    }
                    Value *V               = BI->getCondition();
                    LogicalMap::iterator J = Map.find(V);
                    if (J == Map.end()) {
                        printDiagnostic("Logical signature: Branch condition must be"
                                        " logical expression",
                                        BI);
                        return false;
                    }
                    LogicalNode *Node = J->second;
                    Stack.push_back(Node);
                    Stack.pop_back();
                    Node = LogicalNode::getNot(Node);
                    Stack.push_back(Node);
                    assert(Stack.back() == Node);
                    Stack.pop_back();
                    break;
                }
                case Instruction::Select: {
                    SelectInst *SI                 = cast<SelectInst>(I);
                    LogicalMap::iterator CondNode  = Map.find(SI->getCondition());
                    LogicalMap::iterator TrueNode  = Map.find(SI->getTrueValue());
                    LogicalMap::iterator FalseNode = Map.find(SI->getFalseValue());

                    /*O3 creates blocks that look like the following, which are legitimate blocks.
                     * This is essentially an AND of all the %cmp.i<number> instructions.
                     * Since the cmp instructions all have false at the end, comparisons will be skipped
                     * after one is found to be false, without having a bunch of branch instructions.
                     *
                     * We are going to handle these cases by only adding an 'and' or an 'or' if there is
                     * an actual logical operation, not for constants.
                     *

                    entry:
                      %0 = load i32, ptr @__clambc_match_counts, align 16
                      %cmp.i116.not = icmp eq i32 %0, 0
                      %1 = load i32, ptr getelementptr inbounds ([64 x i32], ptr @__clambc_match_counts, i64 0, i64 1), align 4
                      %cmp.i112.not = icmp eq i32 %1, 0
                      %or.cond = select i1 %cmp.i116.not, i1 %cmp.i112.not, i1 false
                      %2 = load i32, ptr getelementptr inbounds ([64 x i32], ptr @__clambc_match_counts, i64 0, i64 2), align 8
                      %cmp.i108.not = icmp eq i32 %2, 0
                      %or.cond1 = select i1 %or.cond, i1 %cmp.i108.not, i1 false
                      %3 = load i32, ptr getelementptr inbounds ([64 x i32], ptr @__clambc_match_counts, i64 0, i64 3), align 4
                      %cmp.i104.not = icmp eq i32 %3, 0


                      ....

                      br i1 %or.cond15, label %lor.rhs, label %lor.end

                    lor.rhs:                                          ; preds = %entry
                      %17 = load i32, ptr getelementptr inbounds ([64 x i32], ptr @__clambc_match_counts, i64 0, i64 17), align 4
                      %cmp.i = icmp ne i32 %17, 0
                      br label %lor.end

                    lor.end:                                          ; preds = %lor.rhs, %entry
                      %18 = phi i1 [ true, %entry ], [ %cmp.i, %lor.rhs ]
                      ret i1 %18

                     */
                    if (CondNode == Map.end() || (TrueNode == Map.end() && FalseNode == Map.end())) {
                        printDiagnostic("Logical signature: select condition must be logical"
                                        " expression",
                                        SI);
                        return false;
                    }

                    // select cond, trueval, falseval -> cond && trueval || !cond && falseval
                    LogicalNode *N       = nullptr;
                    LogicalNode *NotCond = nullptr;
                    LogicalNode *N2      = nullptr;

                    if (TrueNode != Map.end()) {
                        N = LogicalNode::getAnd(CondNode->second,
                                                TrueNode->second);
                    } else if (ConstantInt *pci = llvm::cast<ConstantInt>(SI->getTrueValue())) {
                        if (pci->isOne()) {
                            N = LogicalNode::getNode(*(CondNode->second));
                        } else if (not pci->isZero()) {
                            printDiagnostic("Logical signature: Select true value must either be"
                                            " a logical expression or a constant true/false integer.",
                                            SI);
                            return false;
                        }
                    } else {
                        printDiagnostic("Logical signature: Select true value must either be"
                                        " a logical expression or a constant true/false integer.",
                                        SI);
                        return false;
                    }

                    NotCond = LogicalNode::getNot(CondNode->second);
                    if (FalseNode != Map.end()) {
                        N2 = LogicalNode::getAnd(NotCond, FalseNode->second);
                    } else if (ConstantInt *pci = llvm::cast<ConstantInt>(SI->getFalseValue())) {
                        if (pci->isOne()) {
                            N2 = NotCond;
                        } else if (not pci->isZero()) {
                            printDiagnostic("Logical signature: Select false value must either be"
                                            " a logical expression or a constant true/false integer.",
                                            SI);
                            return false;
                        }
                    } else {
                        printDiagnostic("Logical signature: Select false value must either be"
                                        " a logical expression or a constant true/false integer.",
                                        SI);
                        return false;
                    }

                    LogicalNode *res = nullptr;
                    if (N && N2) {
                        res = LogicalNode::getOr(N, N2);
                    } else if (N) {
                        res = N;
                    } else if (N2) {
                        res = N2;
                    } else {
                        /*SHOULD be impossible, but will add a check just in case.*/
                        printDiagnostic("Logical signature: Malformed select statement.",
                                        SI);
                        return false;
                    }
                    Map[SI] = res;
                    break;
                }
                case Instruction::Ret: {
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
                                        " expression",
                                        llvm::cast<Instruction>(I));
                        return false;
                    }
                    LogicalNode *Node = J->second;
                    Stack.push_back(Node);
                    exitNodesOr.push_back(LogicalNode::getAnd(allNodes, Stack));
                    Stack.pop_back();
                    break;
                }
                case Instruction::Add: {
                    LogicalMap::iterator J = Map.find(I->getOperand(0));
                    if (J == Map.end()) {
                        printDiagnostic("Logical signature: add operands must be logical"
                                        " expressions",
                                        llvm::cast<Instruction>(I));
                        return false;
                    }
                    ConstantInt *CI = dyn_cast<ConstantInt>(I->getOperand(1));
                    if (CI) {
                        Map[pInst] = LogicalNode::getAdd(J->second, CI->getValue().getZExtValue());
                    } else {
                        LogicalMap::iterator J2 = Map.find(I->getOperand(1));
                        if (J2 == Map.end()) {
                            printDiagnostic("Logical signature: add operands must be "
                                            "logical expressions",
                                            pInst);
                            return false;
                        }
                        LogicalNode *N = LogicalNode::getAdd(J->second, J2->second);
                        if (!N) {
                            printDiagnostic("Logical signature: add operands mismatch,"
                                            "only of counts, uniqueness, and constants",
                                            pInst);
                            return false;
                        }
                        if (!N->checkUniq()) {
                            printDiagnostic("Logical signature: duplicate operands for add"
                                            " not supported",
                                            pInst);
                            return false;
                        }
                        Map[pInst] = N;
                    }
                    break;
                }
                case Instruction::And: {
                    LogicalMap::iterator J1 = Map.find(I->getOperand(0));
                    LogicalMap::iterator J2 = Map.find(I->getOperand(1));
                    if (J1 == Map.end() || J2 == Map.end()) {
                        printDiagnostic("Logical signature: and operands must be logical"
                                        " expressions",
                                        pInst);
                        return false;
                    }
                    Map[pInst] = LogicalNode::getAnd(J1->second, J2->second);
                    break;
                }
                case Instruction::Or: {
                    LogicalMap::iterator J1 = Map.find(I->getOperand(0));
                    LogicalMap::iterator J2 = Map.find(I->getOperand(1));
                    if (J1 == Map.end() || J2 == Map.end()) {
                        printDiagnostic("Logical signature: or operands must be logical"
                                        " expressions",
                                        pInst);
                        return false;
                    }
                    Map[pInst] = LogicalNode::getOr(J1->second, J2->second);
                    break;
                }
                case Instruction::Xor: {
                    ConstantInt *CI = dyn_cast<ConstantInt>(I->getOperand(1));
                    if (!CI || !CI->isOne()) {
                        printDiagnostic("Logical signature: xor only supported for"
                                        " negation",
                                        pInst);
                        return false;
                    }
                    LogicalMap::iterator J1 = Map.find(I->getOperand(0));
                    if (J1 == Map.end()) {
                        printDiagnostic("Logical signature: xor operand must be logical"
                                        " expressions",
                                        pInst);
                        return false;
                    }
                    Map[pInst] = LogicalNode::getNot(J1->second);
                    break;
                }
                case Instruction::ZExt: {
                    LogicalMap::iterator J = Map.find(I->getOperand(0));
                    if (J == Map.end()) {
                        printDiagnostic("Logical signature: zext operand must be logical"
                                        " expressions",
                                        pInst);
                        return false;
                    }
                    ZExtInst *ZI  = cast<ZExtInst>(I);
                    unsigned from = ZI->getSrcTy()->getPrimitiveSizeInBits();
                    unsigned to   = ZI->getDestTy()->getPrimitiveSizeInBits();
                    if (from != 1 || to != 32) {
                        printDiagnostic("Logical signature: only support zero extend"
                                        " from i1 to i32, but encountered " +
                                            Twine(from) +
                                            " to " + Twine(to),
                                        pInst);
                        return false;
                    }
                    Map[pInst] = LogicalNode::getUniqueSigs(J->second);
                    break;
                }
                default:
                    printDiagnostic("Logical signature: unsupported instruction", pInst);
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
        case LOG_OR: {
            groups++;
            std::string result("(");
            for (LogicalNode::const_iterator I = node->begin(),
                                             E = node->end();
                 I != E;) {
                result += node2String(*I, groups);
                ++I;
                if (I != E)
                    result += node->kind == LOG_AND ? "&" : "|";
            }
            return result + ")";
        }
        case LOG_EQ:
            if (node->op1 == ~0u)
                return ("(" + node2String(node->front(), groups) + "=" + Twine(node->op0) + ")").str();
            return ("(" + node2String(node->front(), groups) + "=" + Twine(node->op0) + "," + Twine(node->op1) + ")").str();
        case LOG_GT:
            groups++;
            return ("(" + node2String(node->front(), groups) + ">" + Twine(node->op0) + ")").str();
        case LOG_LT:
            groups++;
            return ("(" + node2String(node->front(), groups) + "<" + Twine(node->op0) + ")").str();
        case LOG_ADDUNIQ:
        case LOG_ADDSUM:
        case LOG_ADDBOTH: {
            if (node->size() == 1)
                return node2String(node->front(), groups);
            groups++;
            std::string result("(");
            for (LogicalNode::const_iterator I = node->begin(), E = node->end(); I != E;) {
                result += node2String(*I, groups);
                ++I;
                if (I != E)
                    result += "|";
            }
            return result + ")";
        }
        default:
            assert(0 && "Invalid node kind");
            return "??";
    }
}

bool validateNDB(const char *S, Module *M, Value *Signatures)
{
    StringRef Pattern(S);
    bool valid     = true;
    size_t offsetp = Pattern.find(':');
    if (offsetp == StringRef::npos)
        offsetp = 0;
    else {
        // Attempt to fully validate the anchor/offset.
        StringRef offset = Pattern.substr(0, offsetp);
        size_t floating  = offset.find(",");
        if (floating != StringRef::npos) {
            unsigned R;
            StringRef floatO = offset.substr(floating + 1);
            if (floatO.getAsInteger(10, R)) {
                printDiagnosticValue("Floating offset is not an integer in'" + Twine(offset) + "'", M, Signatures);
                valid = false;
            } else {
                offset = offset.substr(0, floating);
            }
        }
        if (offset.empty()) {
            printDiagnosticValue("Offset is empty in pattern: '" + Twine(Pattern) + "'",
                                 M, Signatures);
            valid = false;
        } else if (S[0] == '*') {
            if (S[1] != ':') {
                printDiagnosticValue("Offset ANY ('*') followed by garbage: '" + Twine(offset) + "'", M, Signatures);
                valid = false;
            }
        } else if (S[0] >= '0' && S[0] <= '9') {
            unsigned R;
            if (offset.getAsInteger(10, R)) {
                printDiagnosticValue("Absolute offset is not an integer: '" + Twine(offset) + "'", M, Signatures);
                valid = false;
            }
        } else if (!offset.equals("VI")) {
            size_t n1 = offset.find("+");
            size_t n2 = offset.find("-");
            if (n2 < n1)
                n1 = n2;
            if (n1 == StringRef::npos) {
                printDiagnosticValue("Pattern: unrecognized offset format: '" +
                                         Twine(offset) + "'",
                                     M, Signatures);
                valid = false;
            } else {
                unsigned R;
                StringRef anchor = offset.substr(0, n1);
                StringRef delta  = offset.substr(n1 + 1);
                if (delta.getAsInteger(10, R)) {
                    printDiagnosticValue("Anchored offset is not an integer: '" +
                                             Twine(offset) + "'",
                                         M, Signatures);
                    valid = false;
                }
                if (!offset.startswith("EOF-") &&
                    !anchor.equals("EP") &&
                    !anchor.equals("SL")) {
                    if (anchor[0] == 'S') {
                        anchor = anchor.substr(1);
                        if (anchor.getAsInteger(10, R)) {
                            printDiagnosticValue("Section number in offset is not an integer:"
                                                 "'" +
                                                     Twine(offset) + "'",
                                                 M, Signatures);
                            valid = false;
                        }
                    } else {
                        printDiagnosticValue("Unknown anchor '" + Twine(anchor) +
                                                 "' in pattern '" + Twine(Pattern),
                                             M, Signatures);
                        valid = false;
                    }
                }
            }
        }
        Pattern = Pattern.substr(offsetp + 1);
    }
    // This is not a comprehensive validation of the pattern, since
    // that is too complicated and has to be kept in sync with what libclamav
    // allows.
    for (unsigned i = 0; i < Pattern.size(); i++) {
        unsigned char c = Pattern[i];
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
            c == '?' || c == '*' || c == '{' || c == '}' ||
            c == '-' || c == '(' || c == ')' || c == '|' || c == '!' ||
            c == '[' || c == ']' || c == 'B' || c == 'L')
            continue;
        printDiagnosticValue("Pattern contains forbidden character '" + Twine(c) + "': " + Twine(Pattern), M, Signatures);
        valid = false;
        break;
    }
    return valid;
}
static const char *json_api_funcs[] = {"json_is_active", "json_get_object", "json_get_type",
                                       "json_get_array_length", "json_get_array_idx",
                                       "json_get_string_length", "json_get_string",
                                       "json_get_boolean", "json_get_int"};
#define num_json_api_funcs 9
#define FUNCDEBUG 0
static bool hasJSONUsage(llvm::Module *M)
{
#if FUNCDEBUG
    bool found = false;
#endif
    Function *F = NULL;
    for (unsigned i = 0; i < num_json_api_funcs; ++i) {
        F = M->getFunction(json_api_funcs[i]);
        if (F && F->isDeclaration()) {
#if FUNCDEBUG
            llvm::outs() << "found " << json_api_funcs[i] << "!\n";
            found = true;
#else
            return true;
#endif
        }
    }

#if FUNCDEBUG
    if (found) return true;
#endif
    return false;
}

static bool checkMinimum(llvm::Module *M, std::string s, unsigned min, unsigned target, int kind)
{
    const char *msgreq = NULL, *msgrec = NULL, *tarreq = NULL;
    unsigned min_required = 0, min_recommended = 0, target_required = 0;
    StringRef ref(s);
    bool valid = true;
    // Due to bb #1957 VI and $ sigs don't work properly in 0.96,
    // so using these sigs requires minimum functionality level
    if (ref.find('$') != StringRef::npos ||
        ref.find("VI") != StringRef::npos) {
        min_required = FUNC_LEVEL_096_dev;
        msgreq       = "Logical signature use of VI/macros requires minimum "
                       "functionality level of FUNC_LEVEL_096_dev";
    }

    if (kind >= BC_PDF) {
        min_required = FUNC_LEVEL_096_2;
        msgreq       = "Using 0.96.2+ hook requires FUNC_LEVEL_096_2 at least";
    }

    if (kind >= BC_PE_ALL) {
        min_required = FUNC_LEVEL_096_2_dev;
        msgreq       = "Using 0.96.3 hook requires FUNC_LEVEL_096_2_dev at least";
    }

    size_t pos = 0;
    while ((pos = ref.find_first_of("=><", pos)) != StringRef::npos) {
        pos++;
        if (pos >= 2 && ref[pos - 2] != '>' && ref[pos - 2] != '<' &&
            pos < ref.size() && ref[pos] != '0') {
            min_recommended = FUNC_LEVEL_096_2;
            msgrec          = "Logical signature use of count comparison "
                              "requires minimum functionality level of FUNC_LEVEL_096_2 (bb #2053)";
            break;
        }
    }
    if (min_recommended < FUNC_LEVEL_096_4) {
        min_recommended = FUNC_LEVEL_096_4;
        msgrec          = "FUNC_LEVEL_096_4 is minimum recommended engine version. Older "
                          "versions have quadratic load time";
    }

    /*JSON CHECK*/
    if (hasJSONUsage(M)) {
        min_required = FUNC_LEVEL_098_5;
        msgreq       = "JSON reading API requires minimum functionality level "
                       "of FUNC_LEVEL_098_5";
    }
    /*JSON CHECK*/

    if (kind >= BC_PRECLASS) {
        min_required = FUNC_LEVEL_098_7;
        msgreq       = "Using 0.98.7 hook requires FUNC_LEVEL_098_7 at least";
    }

    if (target_required && (target != target_required)) {
        printDiagnostic(tarreq, M);
        valid = false;
    }
    if (min_required && min < min_required) {
        printDiagnostic(msgreq, M);
        valid = false;
    }
    if (min_recommended && min < min_recommended) {
        printWarning(msgrec, M);
    }

    if (valid)
        return true;
    else
        return false;
}

bool ClamBCLogicalCompiler::compileLogicalSignature(Function &F, unsigned target,
                                                    unsigned min, unsigned max,
                                                    const std::string &icon1,
                                                    const std::string &icon2,
                                                    const std::string &container,
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
    unsigned n         = CS->getNumOperands();
    if (n & 1) {
        printDiagnosticValue("Signatures initializer contains odd # of fields",
                             F.getParent(), GV, true);
        return false;
    }
    // remove the pointer field from Signatures
    std::vector<Type *> newStruct;
    std::vector<Constant *> newInits;
    StructType *STy   = cast<StructType>(CS->getType());
    IntegerType *RTy1 = Type::getInt8Ty(GV->getContext());
    Type *RTy2        = STy->getElementType(1);
    for (unsigned i = 0; i < n; i += 2) {
        newStruct.push_back(RTy1);
        newStruct.push_back(RTy2);
        newInits.push_back(ConstantInt::get(RTy1, 0));
        newInits.push_back(CS->getOperand(i + 1));
    }
    StructType *STy2 = StructType::get(GV->getContext(), newStruct);
    Constant *NS     = ConstantStruct::get(STy2, newInits);
    GlobalVariable *NewGV =
        cast<GlobalVariable>(F.getParent()->getOrInsertGlobal("_Signatures_",
                                                              STy2));
    NewGV->setInitializer(NS);
    NewGV->setConstant(true);
    GV->replaceAllUsesWith(NewGV);
    GV->eraseFromParent();
    NewGV->setLinkage(GlobalValue::InternalLinkage);

    std::vector<std::string> SubSignatures;
    SubSignatures.resize(n / 2);
    bool valid = true;
    for (unsigned i = 0; i < n; i += 2) {
        Constant *C = CS->getOperand(i);
        unsigned id = 0;
        if (!isa<ConstantAggregateZero>(CS->getOperand(i + 1))) {
            ConstantStruct *SS = cast<ConstantStruct>(CS->getOperand(i + 1));
            id                 = cast<ConstantInt>(SS->getOperand(0))->getValue().getZExtValue();
            if (id > n / 2) {
                printDiagnostic("Signature ID out of range (" + Twine(id) + " > " + Twine(n / 2) + ")", F.getParent());
                return false;
            }
        }
        llvm::StringRef strSR;
        std::string str;
        bool ret = getConstantStringInfo(C, strSR);
        str      = strSR.str();
        if (!ret) {
            printDiagnosticValue("Signature is not a static string",
                                 F.getParent(), C);
            return false;
        }
        size_t offsetp = str.find(':');
        if (offsetp == StringRef::npos)
            offsetp = 0;
        std::transform(str.begin() + offsetp, str.end(), str.begin() + offsetp, ::tolower);
        valid             = validateNDB(str.data(), F.getParent(), NewGV);
        SubSignatures[id] = str;
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
    unsigned groups  = 0;
    LogicalSignature = virusnames;
    if (min || max || !icon1.empty() || !icon2.empty()) {
        if (!max)
            max = 255; /* for now it should be enough, we can always increase it later
                        */
        if (!min)
            min = FUNC_LEVEL_096_4;
        /* 0.96 is first to have bytecode support, but <0.96.4 has quadratic load
         * time */
        LogicalSignature = LogicalSignature +
                           (";Engine:" + Twine(min) + "-" + Twine(max) + ",").str();
    } else
        LogicalSignature = LogicalSignature + ";";
    std::string ndbsigs = node2String(node, groups);
    if (!icon1.empty())
        LogicalSignature = LogicalSignature +
                           ("IconGroup1:" + Twine(icon1) + ",").str();
    if (!icon2.empty())
        LogicalSignature = LogicalSignature +
                           ("IconGroup2:" + Twine(icon2) + ",").str();
    if (!container.empty())
        LogicalSignature = LogicalSignature +
                           ("Container:" + Twine(container) + ",").str();
    LogicalSignature = LogicalSignature +
                       ("Target:" + Twine(target)).str();

    std::string rawattrs;
    llvm::StringRef sr;
    GV = F.getParent()->getGlobalVariable("__ldb_rawattrs");
    if (GV && GV->hasDefinitiveInitializer() &&
        getConstantStringInfo(GV->getInitializer(), sr)) {
        rawattrs = sr.str();
        GV->setLinkage(GlobalValue::InternalLinkage);
        for (unsigned i = 0; i < rawattrs.length(); i++) {
            unsigned char c = rawattrs[i];
            if (isalnum(c) || c == ':' || c == '-' || c == ',' || c == '_')
                continue;
            printDiagnostic("Invalid character in ldb attribute: " + rawattrs.substr(0, i + 1),
                            F.getParent());
            return false;
        }
        LogicalSignature = LogicalSignature + "," + rawattrs;
    }
    LogicalSignature = LogicalSignature + ";" + ndbsigs;

    if (groups > 64) {
        printDiagnostic(("Logical signature: a maximum of 64 subexpressions are "
                         "supported, but logical signature has " +
                         Twine(groups) +
                         " groups")
                            .str(),
                        &F);
        return false;
    }

    for (std::vector<std::string>::iterator I = SubSignatures.begin(), E = SubSignatures.end();
         I != E; ++I) {
        LogicalSignature += ";" + *I;
    }
    if (!checkMinimum(F.getParent(), LogicalSignature, min, target, kind))
        return false;

    F.setLinkage(GlobalValue::InternalLinkage);
    return true;
}

bool ClamBCLogicalCompiler::validateVirusName(const std::string &name,
                                              Module &M, bool Suffix)
{
    for (unsigned i = 0; i < name.length(); i++) {
        unsigned char c = name[i];
        if (Suffix && c == '.') {
            printDiagnostic("Character '.' is not allowed in virusname suffix: '" +
                                name.substr(0, i + 1) + "'. Use - or _: " + name.substr(0, i + 1),
                            &M);
            return false;
        }
        if (isalnum(c) || c == '_' || c == '-' || c == '.')
            continue;
        printDiagnostic("Invalid character in virusname: " + name.substr(0, i + 1), &M);
        return false;
    }
    return true;
}

static bool isUnpacker(unsigned kind)
{
    return kind == BC_PE_UNPACKER || kind == BC_ELF_UNPACKER || kind == BC_MACHO_UNPACKER;
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
    llvm::StringRef sr;
    if (!getConstantStringInfo(VPFX, sr)) {
        if (kind)
            printDiagnostic("Unable to determine virusname prefix string", &M);
        return false;
    }
    virusnames = sr;
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
        bool Valid        = true;
        std::vector<std::string> names;

        for (unsigned i = 0; i < CA->getNumOperands(); i++) {
            std::string virusnamepart;
            llvm::StringRef sr;
            Constant *C = CA->getOperand(i);
            if (!getConstantStringInfo(C, sr)) {
                printDiagnostic("Unable to determine virusname part string", &M);
                Valid = false;
            }
            virusnamepart = sr.str();
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
        for (unsigned i = 0; i < names.size(); i++) {
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
            printWarning("Virusnames declared, but foundVirus was not called!", &M);
        // non-fatal, should be if we could check if foundVirusVirus was reachable
        return true;
    }
    bool Valid = true;

    for (auto I : F->users()) {
        CallInst *pCallInst = llvm::cast<CallInst>(I);
        if (nullptr == pCallInst) {
            assert(0 && "NOT sure how this is possible");
            continue;
        }

        if (F != pCallInst->getCalledFunction()) {

            /*Not sure how this is possible, either*/
            printDiagnostic("setvirusname can only be directly called",
                            pCallInst);
            Valid = false;
            continue;
        }

        if (2 != pCallInst->arg_size()) {
            printDiagnostic("setvirusname has 2 args", pCallInst);
            Valid = false;
            continue;
        }

        std::string param;
        llvm::StringRef sr;
        Value *V = llvm::cast<Value>(pCallInst->arg_begin());
        if (nullptr == V) {
            printDiagnostic("Invalid argument passed to setvirusname", pCallInst);
            Valid = false;
            continue;
        }
        bool result = getConstantStringInfo(V, sr);
        param       = sr.str();
        if (!result) {
            printDiagnostic("Argument of foundVirus() must be a constant string",
                            pCallInst);
            Valid = false;
            continue;
        }
        StringRef p(param);
        // Remove duplicate prefix
        if (p.startswith(virusNamePrefix))
            p = p.substr(virusNamePrefix.length());
        if (!p.empty() && !virusNamesSet.count(p)) {
            printDiagnostic(Twine("foundVirus called with an undeclared virusname: ",
                                  p),
                            pCallInst);
            Valid = false;
            continue;
        }
        // Add prefix
        std::string fullname = p.empty() ? virusNamePrefix : virusNamePrefix + "." + p.str();
        IRBuilder<> builder(pCallInst->getParent());
        Value *C = builder.CreateGlobalStringPtr(fullname.c_str());

        IntegerType *I32Ty = Type::getInt32Ty(M.getContext());
        pCallInst->setArgOperand(0, C);
        pCallInst->setArgOperand(1, ConstantInt::get(I32Ty, fullname.size()));
    }
    return Valid;
}

PreservedAnalyses ClamBCLogicalCompiler::run(Module &M, ModuleAnalysisManager &MAM)
{
    bool Valid       = true;
    LogicalSignature = "";
    virusnames       = "";
    pMod             = &M;

    // Handle virusname
    unsigned kind          = 0;
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
        if (!kind || kind == BC_STARTUP) {
            return PreservedAnalyses::all();
        }
        Valid = false;
    }

    if (F) {
        FunctionAnalysisManager &fam = MAM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();
        LoopInfo *li                 = &fam.getResult<LoopAnalysis>(*F);
        if (functionHasLoop(F, *li)) {
            printDiagnostic("Logical signature: loop/recursion not supported", F);
            Valid = false;
        }

        if (functionRecurses(F)) {
            Valid = false;
            printDiagnostic("Logical signature: loop/recursion not supported", F);
        }
    }

    if (Valid) {
        NamedMDNode *Node = M.getOrInsertNamedMetadata("clambc.virusnames");
        MDString *S       = MDString::get(M.getContext(), llvm::StringRef(virusnames));
        MDNode *N         = MDNode::get(M.getContext(), S);
        Node->addOperand(N);
    }

    GlobalVariable *GV = nullptr;
    unsigned funcmin = FUNC_LEVEL_096_4, funcmax = 0;
    if (Valid) {
        GV = M.getGlobalVariable("__FuncMin");
        if (GV && GV->hasDefinitiveInitializer()) {
            NamedMDNode *Node = M.getOrInsertNamedMetadata("clambc.funcmin");
            Constant *C       = GV->getInitializer();

            MDNode *N = MDNode::get(M.getContext(), ConstantAsMetadata::get(C));
            Node->addOperand(N);
            GV->setLinkage(GlobalValue::InternalLinkage);
            funcmin = cast<ConstantInt>(C)->getZExtValue();
            if (funcmin < FUNC_LEVEL_096) {
                printDiagnostic("Minimum functionality level can't be set lower than "
                                "0.96",
                                &M, GV);
                Valid = false;
            }
        }
    }
    if (Valid) {
        GV = M.getGlobalVariable("__FuncMax");
        if (GV && GV->hasDefinitiveInitializer()) {
            NamedMDNode *Node = M.getOrInsertNamedMetadata("clambc.funcmax");
            Constant *C       = GV->getInitializer();
            MDNode *N         = MDNode::get(M.getContext(), ConstantAsMetadata::get(C));
            Node->addOperand(N);
            GV->setLinkage(GlobalValue::InternalLinkage);
            funcmax = cast<ConstantInt>(C)->getZExtValue();
            if (funcmax < FUNC_LEVEL_096) {
                printDiagnostic("Maximum functionality level can't be set lower than "
                                "0.96",
                                &M, GV);
                Valid = false;
            }
            if (funcmax < funcmin) {
                printDiagnostic("Maximum functionality level can't be lower than "
                                "minimum",
                                &M, GV);
                Valid = false;
            }
        }
    }
    if (Valid) {
        if (F) {
            GV              = M.getGlobalVariable("__Target");
            unsigned target = ~0u;
            if (!GV || !GV->hasDefinitiveInitializer()) {
                Valid = false;
                printDiagnostic("__Target not defined", &M, true);
            } else {
                target = cast<ConstantInt>(GV->getInitializer())->getValue().getZExtValue();
                GV->setLinkage(GlobalValue::InternalLinkage);
            }

            std::string icon1, icon2, container;
            llvm::StringRef icon1SR, icon2SR, containerSR;

            GV = M.getGlobalVariable("__IconGroup1");
            if (GV) {
                bool res = getConstantStringInfo(GV->getInitializer(), icon1SR);
                icon1    = icon1SR;
                if (GV->hasDefinitiveInitializer() && res) {
                    icon1 = icon1SR.str();
                    if (!validateVirusName(icon1, M)) {
                        Valid = false;
                    }
                    GV->setLinkage(GlobalValue::InternalLinkage);
                }
            }

            GV = M.getGlobalVariable("__IconGroup2");
            if (GV) {
                bool res = getConstantStringInfo(GV->getInitializer(), icon2SR);
                icon2    = icon2SR.str();
                if (GV->hasDefinitiveInitializer() && res) {
                    if (!validateVirusName(icon2, M)) {
                        Valid = false;
                    }
                    GV->setLinkage(GlobalValue::InternalLinkage);
                }
            }

            GV = M.getGlobalVariable("__ldb_container");
            if (GV) {
                bool ret  = getConstantStringInfo(GV->getInitializer(), containerSR);
                container = containerSR.str();
                if (GV->hasDefinitiveInitializer() && ret) {
                    if (!StringRef(container).startswith("CL_TYPE_")) {
                        Valid = false;
                    }
                    GV->setLinkage(GlobalValue::InternalLinkage);
                }
            }

            if (!compileLogicalSignature(*F, target, funcmin, funcmax, icon1, icon2,
                                         container, kind)) {
                Valid = false;
            }
            NamedMDNode *Node = M.getOrInsertNamedMetadata("clambc.logicalsignature");
            MDString *S       = MDString::get(M.getContext(), LogicalSignature);
            MDNode *N         = MDNode::get(M.getContext(), S);
            Node->addOperand(N);
            if (F->use_empty())
                F->eraseFromParent();
        }
    }
    if (!Valid) {
        errs() << "lsig not valid!\n";
        // diagnostic already printed
        exit(42);
    }
    return PreservedAnalyses::none();
}

// This part is the new way of registering your pass
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo()
{
    return {
        LLVM_PLUGIN_API_VERSION, "ClamBCLogicalCompiler", "v0.1",
        [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &FPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                    if (Name == "clambc-lcompiler") {
                        FPM.addPass(ClamBCLogicalCompiler());
                        return true;
                    }
                    return false;
                });
        }};
}

} // namespace ClamBCLogicalCompiler
