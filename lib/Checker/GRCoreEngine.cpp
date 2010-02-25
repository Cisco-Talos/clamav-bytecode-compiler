//==- GRCoreEngine.cpp - Path-Sensitive Dataflow Engine ------------*- C++ -*-//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
//  This file defines a generic engine for intraprocedural, path-sensitive,
//  dataflow analysis via graph reachability engine.
//
//===----------------------------------------------------------------------===//

#include "clang/Checker/PathSensitive/GRCoreEngine.h"
#include "clang/Checker/PathSensitive/GRExprEngine.h"
#include "clang/AST/Expr.h"
#include "llvm/Support/Casting.h"
#include "llvm/ADT/DenseMap.h"
#include <vector>
#include <queue>

using llvm::cast;
using llvm::isa;
using namespace clang;

//===----------------------------------------------------------------------===//
// Worklist classes for exploration of reachable states.
//===----------------------------------------------------------------------===//

namespace {
class DFS : public GRWorkList {
  llvm::SmallVector<GRWorkListUnit,20> Stack;
public:
  virtual bool hasWork() const {
    return !Stack.empty();
  }

  virtual void Enqueue(const GRWorkListUnit& U) {
    Stack.push_back(U);
  }

  virtual GRWorkListUnit Dequeue() {
    assert (!Stack.empty());
    const GRWorkListUnit& U = Stack.back();
    Stack.pop_back(); // This technically "invalidates" U, but we are fine.
    return U;
  }
};

class BFS : public GRWorkList {
  std::queue<GRWorkListUnit> Queue;
public:
  virtual bool hasWork() const {
    return !Queue.empty();
  }

  virtual void Enqueue(const GRWorkListUnit& U) {
    Queue.push(U);
  }

  virtual GRWorkListUnit Dequeue() {
    // Don't use const reference.  The subsequent pop_back() might make it
    // unsafe.
    GRWorkListUnit U = Queue.front();
    Queue.pop();
    return U;
  }
};

} // end anonymous namespace

// Place the dstor for GRWorkList here because it contains virtual member
// functions, and we the code for the dstor generated in one compilation unit.
GRWorkList::~GRWorkList() {}

GRWorkList *GRWorkList::MakeDFS() { return new DFS(); }
GRWorkList *GRWorkList::MakeBFS() { return new BFS(); }

namespace {
  class BFSBlockDFSContents : public GRWorkList {
    std::queue<GRWorkListUnit> Queue;
    llvm::SmallVector<GRWorkListUnit,20> Stack;
  public:
    virtual bool hasWork() const {
      return !Queue.empty() || !Stack.empty();
    }

    virtual void Enqueue(const GRWorkListUnit& U) {
      if (isa<BlockEntrance>(U.getNode()->getLocation()))
        Queue.push(U);
      else
        Stack.push_back(U);
    }

    virtual GRWorkListUnit Dequeue() {
      // Process all basic blocks to completion.
      if (!Stack.empty()) {
        const GRWorkListUnit& U = Stack.back();
        Stack.pop_back(); // This technically "invalidates" U, but we are fine.
        return U;
      }

      assert(!Queue.empty());
      // Don't use const reference.  The subsequent pop_back() might make it
      // unsafe.
      GRWorkListUnit U = Queue.front();
      Queue.pop();
      return U;
    }
  };
} // end anonymous namespace

GRWorkList* GRWorkList::MakeBFSBlockDFSContents() {
  return new BFSBlockDFSContents();
}

//===----------------------------------------------------------------------===//
// Core analysis engine.
//===----------------------------------------------------------------------===//
void GRCoreEngine::ProcessEndPath(GREndPathNodeBuilder& Builder) {
  SubEngine.ProcessEndPath(Builder);
}

void GRCoreEngine::ProcessStmt(CFGElement E, GRStmtNodeBuilder& Builder) {
  SubEngine.ProcessStmt(E, Builder);
}

bool GRCoreEngine::ProcessBlockEntrance(CFGBlock* Blk, const GRState* State,
                                        GRBlockCounter BC) {
  return SubEngine.ProcessBlockEntrance(Blk, State, BC);
}

void GRCoreEngine::ProcessBranch(Stmt* Condition, Stmt* Terminator,
                   GRBranchNodeBuilder& Builder) {
  SubEngine.ProcessBranch(Condition, Terminator, Builder);
}

void GRCoreEngine::ProcessIndirectGoto(GRIndirectGotoNodeBuilder& Builder) {
  SubEngine.ProcessIndirectGoto(Builder);
}

void GRCoreEngine::ProcessSwitch(GRSwitchNodeBuilder& Builder) {
  SubEngine.ProcessSwitch(Builder);
}

void GRCoreEngine::ProcessCallEnter(GRCallEnterNodeBuilder &Builder) {
  SubEngine.ProcessCallEnter(Builder);
}

void GRCoreEngine::ProcessCallExit(GRCallExitNodeBuilder &Builder) {
  SubEngine.ProcessCallExit(Builder);
}

/// ExecuteWorkList - Run the worklist algorithm for a maximum number of steps.
bool GRCoreEngine::ExecuteWorkList(const LocationContext *L, unsigned Steps) {

  if (G->num_roots() == 0) { // Initialize the analysis by constructing
    // the root if none exists.

    CFGBlock* Entry = &(L->getCFG()->getEntry());

    assert (Entry->empty() &&
            "Entry block must be empty.");

    assert (Entry->succ_size() == 1 &&
            "Entry block must have 1 successor.");

    // Get the solitary successor.
    CFGBlock* Succ = *(Entry->succ_begin());

    // Construct an edge representing the
    // starting location in the function.
    BlockEdge StartLoc(Entry, Succ, L);

    // Set the current block counter to being empty.
    WList->setBlockCounter(BCounterFactory.GetEmptyCounter());

    // Generate the root.
    GenerateNode(StartLoc, getInitialState(L), 0);
  }

  while (Steps && WList->hasWork()) {
    --Steps;
    const GRWorkListUnit& WU = WList->Dequeue();

    // Set the current block counter.
    WList->setBlockCounter(WU.getBlockCounter());

    // Retrieve the node.
    ExplodedNode* Node = WU.getNode();

    // Dispatch on the location type.
    switch (Node->getLocation().getKind()) {
      case ProgramPoint::BlockEdgeKind:
        HandleBlockEdge(cast<BlockEdge>(Node->getLocation()), Node);
        break;

      case ProgramPoint::BlockEntranceKind:
        HandleBlockEntrance(cast<BlockEntrance>(Node->getLocation()), Node);
        break;

      case ProgramPoint::BlockExitKind:
        assert (false && "BlockExit location never occur in forward analysis.");
        break;

      case ProgramPoint::CallEnterKind:
        HandleCallEnter(cast<CallEnter>(Node->getLocation()), WU.getBlock(), 
                        WU.getIndex(), Node);
        break;

      case ProgramPoint::CallExitKind:
        HandleCallExit(cast<CallExit>(Node->getLocation()), Node);
        break;

      default:
        assert(isa<PostStmt>(Node->getLocation()));
        HandlePostStmt(cast<PostStmt>(Node->getLocation()), WU.getBlock(),
                       WU.getIndex(), Node);
        break;
    }
  }

  return WList->hasWork();
}

void GRCoreEngine::HandleCallEnter(const CallEnter &L, const CFGBlock *Block,
                                   unsigned Index, ExplodedNode *Pred) {
  GRCallEnterNodeBuilder Builder(*this, Pred, L.getCallExpr(), L.getCallee(), 
                                 Block, Index);
  ProcessCallEnter(Builder);
}

void GRCoreEngine::HandleCallExit(const CallExit &L, ExplodedNode *Pred) {
  GRCallExitNodeBuilder Builder(*this, Pred);
  ProcessCallExit(Builder);
}

void GRCoreEngine::HandleBlockEdge(const BlockEdge& L, ExplodedNode* Pred) {

  CFGBlock* Blk = L.getDst();

  // Check if we are entering the EXIT block.
  if (Blk == &(L.getLocationContext()->getCFG()->getExit())) {

    assert (L.getLocationContext()->getCFG()->getExit().size() == 0
            && "EXIT block cannot contain Stmts.");

    // Process the final state transition.
    GREndPathNodeBuilder Builder(Blk, Pred, this);
    ProcessEndPath(Builder);

    // This path is done. Don't enqueue any more nodes.
    return;
  }

  // FIXME: Should we allow ProcessBlockEntrance to also manipulate state?

  if (ProcessBlockEntrance(Blk, Pred->State, WList->getBlockCounter()))
    GenerateNode(BlockEntrance(Blk, Pred->getLocationContext()), Pred->State, Pred);
}

void GRCoreEngine::HandleBlockEntrance(const BlockEntrance& L,
                                       ExplodedNode* Pred) {

  // Increment the block counter.
  GRBlockCounter Counter = WList->getBlockCounter();
  Counter = BCounterFactory.IncrementCount(Counter, L.getBlock()->getBlockID());
  WList->setBlockCounter(Counter);

  // Process the entrance of the block.
  if (CFGElement E = L.getFirstElement()) {
    GRStmtNodeBuilder Builder(L.getBlock(), 0, Pred, this,
                              SubEngine.getStateManager());
    ProcessStmt(E, Builder);
  }
  else
    HandleBlockExit(L.getBlock(), Pred);
}

void GRCoreEngine::HandleBlockExit(CFGBlock * B, ExplodedNode* Pred) {

  if (Stmt* Term = B->getTerminator()) {
    switch (Term->getStmtClass()) {
      default:
        assert(false && "Analysis for this terminator not implemented.");
        break;

      case Stmt::BinaryOperatorClass: // '&&' and '||'
        HandleBranch(cast<BinaryOperator>(Term)->getLHS(), Term, B, Pred);
        return;

      case Stmt::ConditionalOperatorClass:
        HandleBranch(cast<ConditionalOperator>(Term)->getCond(), Term, B, Pred);
        return;

        // FIXME: Use constant-folding in CFG construction to simplify this
        // case.

      case Stmt::ChooseExprClass:
        HandleBranch(cast<ChooseExpr>(Term)->getCond(), Term, B, Pred);
        return;

      case Stmt::DoStmtClass:
        HandleBranch(cast<DoStmt>(Term)->getCond(), Term, B, Pred);
        return;

      case Stmt::ForStmtClass:
        HandleBranch(cast<ForStmt>(Term)->getCond(), Term, B, Pred);
        return;

      case Stmt::ContinueStmtClass:
      case Stmt::BreakStmtClass:
      case Stmt::GotoStmtClass:
        break;

      case Stmt::IfStmtClass:
        HandleBranch(cast<IfStmt>(Term)->getCond(), Term, B, Pred);
        return;

      case Stmt::IndirectGotoStmtClass: {
        // Only 1 successor: the indirect goto dispatch block.
        assert (B->succ_size() == 1);

        GRIndirectGotoNodeBuilder
           builder(Pred, B, cast<IndirectGotoStmt>(Term)->getTarget(),
                   *(B->succ_begin()), this);

        ProcessIndirectGoto(builder);
        return;
      }

      case Stmt::ObjCForCollectionStmtClass: {
        // In the case of ObjCForCollectionStmt, it appears twice in a CFG:
        //
        //  (1) inside a basic block, which represents the binding of the
        //      'element' variable to a value.
        //  (2) in a terminator, which represents the branch.
        //
        // For (1), subengines will bind a value (i.e., 0 or 1) indicating
        // whether or not collection contains any more elements.  We cannot
        // just test to see if the element is nil because a container can
        // contain nil elements.
        HandleBranch(Term, Term, B, Pred);
        return;
      }

      case Stmt::SwitchStmtClass: {
        GRSwitchNodeBuilder builder(Pred, B, cast<SwitchStmt>(Term)->getCond(),
                                    this);

        ProcessSwitch(builder);
        return;
      }

      case Stmt::WhileStmtClass:
        HandleBranch(cast<WhileStmt>(Term)->getCond(), Term, B, Pred);
        return;
    }
  }

  assert (B->succ_size() == 1 &&
          "Blocks with no terminator should have at most 1 successor.");

  GenerateNode(BlockEdge(B, *(B->succ_begin()), Pred->getLocationContext()),
               Pred->State, Pred);
}

void GRCoreEngine::HandleBranch(Stmt* Cond, Stmt* Term, CFGBlock * B,
                                ExplodedNode* Pred) {
  assert (B->succ_size() == 2);

  GRBranchNodeBuilder Builder(B, *(B->succ_begin()), *(B->succ_begin()+1),
                              Pred, this);

  ProcessBranch(Cond, Term, Builder);
}

void GRCoreEngine::HandlePostStmt(const PostStmt& L, CFGBlock* B,
                                  unsigned StmtIdx, ExplodedNode* Pred) {

  assert (!B->empty());

  if (StmtIdx == B->size())
    HandleBlockExit(B, Pred);
  else {
    GRStmtNodeBuilder Builder(B, StmtIdx, Pred, this,
                              SubEngine.getStateManager());
    ProcessStmt((*B)[StmtIdx], Builder);
  }
}

/// GenerateNode - Utility method to generate nodes, hook up successors,
///  and add nodes to the worklist.
void GRCoreEngine::GenerateNode(const ProgramPoint& Loc,
                                const GRState* State, ExplodedNode* Pred) {

  bool IsNew;
  ExplodedNode* Node = G->getNode(Loc, State, &IsNew);

  if (Pred)
    Node->addPredecessor(Pred, *G);  // Link 'Node' with its predecessor.
  else {
    assert (IsNew);
    G->addRoot(Node);  // 'Node' has no predecessor.  Make it a root.
  }

  // Only add 'Node' to the worklist if it was freshly generated.
  if (IsNew) WList->Enqueue(Node);
}

GRStmtNodeBuilder::GRStmtNodeBuilder(CFGBlock* b, unsigned idx,
                                     ExplodedNode* N, GRCoreEngine* e,
                                     GRStateManager &mgr)
  : Eng(*e), B(*b), Idx(idx), Pred(N), LastNode(N), Mgr(mgr), Auditor(0),
    PurgingDeadSymbols(false), BuildSinks(false), HasGeneratedNode(false),
    PointKind(ProgramPoint::PostStmtKind), Tag(0) {
  Deferred.insert(N);
  CleanedState = getLastNode()->getState();
}

GRStmtNodeBuilder::~GRStmtNodeBuilder() {
  for (DeferredTy::iterator I=Deferred.begin(), E=Deferred.end(); I!=E; ++I)
    if (!(*I)->isSink())
      GenerateAutoTransition(*I);
}

void GRStmtNodeBuilder::GenerateAutoTransition(ExplodedNode* N) {
  assert (!N->isSink());

  // Check if this node entered a callee.
  if (isa<CallEnter>(N->getLocation())) {
    // Still use the index of the CallExpr. It's needed to create the callee
    // StackFrameContext.
    Eng.WList->Enqueue(N, B, Idx);
    return;
  }

  PostStmt Loc(getStmt(), N->getLocationContext());

  if (Loc == N->getLocation()) {
    // Note: 'N' should be a fresh node because otherwise it shouldn't be
    // a member of Deferred.
    Eng.WList->Enqueue(N, B, Idx+1);
    return;
  }

  bool IsNew;
  ExplodedNode* Succ = Eng.G->getNode(Loc, N->State, &IsNew);
  Succ->addPredecessor(N, *Eng.G);

  if (IsNew)
    Eng.WList->Enqueue(Succ, B, Idx+1);
}

static ProgramPoint GetProgramPoint(const Stmt *S, ProgramPoint::Kind K,
                                    const LocationContext *LC, const void *tag){
  switch (K) {
    default:
      assert(false && "Unhandled ProgramPoint kind");    
    case ProgramPoint::PreStmtKind:
      return PreStmt(S, LC, tag);
    case ProgramPoint::PostStmtKind:
      return PostStmt(S, LC, tag);
    case ProgramPoint::PreLoadKind:
      return PreLoad(S, LC, tag);
    case ProgramPoint::PostLoadKind:
      return PostLoad(S, LC, tag);
    case ProgramPoint::PreStoreKind:
      return PreStore(S, LC, tag);
    case ProgramPoint::PostStoreKind:
      return PostStore(S, LC, tag);
    case ProgramPoint::PostLValueKind:
      return PostLValue(S, LC, tag);
    case ProgramPoint::PostPurgeDeadSymbolsKind:
      return PostPurgeDeadSymbols(S, LC, tag);
  }
}

ExplodedNode*
GRStmtNodeBuilder::generateNodeInternal(const Stmt* S, const GRState* state,
                                        ExplodedNode* Pred,
                                        ProgramPoint::Kind K,
                                        const void *tag) {
  
  const ProgramPoint &L = GetProgramPoint(S, K, Pred->getLocationContext(),tag);
  return generateNodeInternal(L, state, Pred);
}

ExplodedNode*
GRStmtNodeBuilder::generateNodeInternal(const ProgramPoint &Loc,
                                        const GRState* State,
                                        ExplodedNode* Pred) {
  bool IsNew;
  ExplodedNode* N = Eng.G->getNode(Loc, State, &IsNew);
  N->addPredecessor(Pred, *Eng.G);
  Deferred.erase(Pred);

  if (IsNew) {
    Deferred.insert(N);
    LastNode = N;
    return N;
  }

  LastNode = NULL;
  return NULL;
}

ExplodedNode* GRBranchNodeBuilder::generateNode(const GRState* State,
                                                bool branch) {

  // If the branch has been marked infeasible we should not generate a node.
  if (!isFeasible(branch))
    return NULL;

  bool IsNew;

  ExplodedNode* Succ =
    Eng.G->getNode(BlockEdge(Src,branch ? DstT:DstF,Pred->getLocationContext()),
                   State, &IsNew);

  Succ->addPredecessor(Pred, *Eng.G);

  if (branch)
    GeneratedTrue = true;
  else
    GeneratedFalse = true;

  if (IsNew) {
    Deferred.push_back(Succ);
    return Succ;
  }

  return NULL;
}

GRBranchNodeBuilder::~GRBranchNodeBuilder() {
  if (!GeneratedTrue) generateNode(Pred->State, true);
  if (!GeneratedFalse) generateNode(Pred->State, false);

  for (DeferredTy::iterator I=Deferred.begin(), E=Deferred.end(); I!=E; ++I)
    if (!(*I)->isSink()) Eng.WList->Enqueue(*I);
}


ExplodedNode*
GRIndirectGotoNodeBuilder::generateNode(const iterator& I, const GRState* St,
                                        bool isSink) {
  bool IsNew;

  ExplodedNode* Succ = Eng.G->getNode(BlockEdge(Src, I.getBlock(),
                                      Pred->getLocationContext()), St, &IsNew);

  Succ->addPredecessor(Pred, *Eng.G);

  if (IsNew) {

    if (isSink)
      Succ->markAsSink();
    else
      Eng.WList->Enqueue(Succ);

    return Succ;
  }

  return NULL;
}


ExplodedNode*
GRSwitchNodeBuilder::generateCaseStmtNode(const iterator& I, const GRState* St){

  bool IsNew;

  ExplodedNode* Succ = Eng.G->getNode(BlockEdge(Src, I.getBlock(),
                                       Pred->getLocationContext()), St, &IsNew);
  Succ->addPredecessor(Pred, *Eng.G);

  if (IsNew) {
    Eng.WList->Enqueue(Succ);
    return Succ;
  }

  return NULL;
}


ExplodedNode*
GRSwitchNodeBuilder::generateDefaultCaseNode(const GRState* St, bool isSink) {

  // Get the block for the default case.
  assert (Src->succ_rbegin() != Src->succ_rend());
  CFGBlock* DefaultBlock = *Src->succ_rbegin();

  bool IsNew;

  ExplodedNode* Succ = Eng.G->getNode(BlockEdge(Src, DefaultBlock,
                                       Pred->getLocationContext()), St, &IsNew);
  Succ->addPredecessor(Pred, *Eng.G);

  if (IsNew) {
    if (isSink)
      Succ->markAsSink();
    else
      Eng.WList->Enqueue(Succ);

    return Succ;
  }

  return NULL;
}

GREndPathNodeBuilder::~GREndPathNodeBuilder() {
  // Auto-generate an EOP node if one has not been generated.
  if (!HasGeneratedNode) generateNode(Pred->State);
}

ExplodedNode*
GREndPathNodeBuilder::generateNode(const GRState* State, const void *tag,
                                   ExplodedNode* P) {
  HasGeneratedNode = true;
  bool IsNew;

  ExplodedNode* Node = Eng.G->getNode(BlockEntrance(&B,
                               Pred->getLocationContext(), tag), State, &IsNew);

  Node->addPredecessor(P ? P : Pred, *Eng.G);

  if (IsNew) {
    Eng.G->addEndOfPath(Node);
    return Node;
  }

  return NULL;
}

void GREndPathNodeBuilder::GenerateCallExitNode(const GRState *state) {
  HasGeneratedNode = true;
  // Create a CallExit node and enqueue it.
  const StackFrameContext *LocCtx
                         = cast<StackFrameContext>(Pred->getLocationContext());
  const Stmt *CE = LocCtx->getCallSite();

  // Use the the callee location context.
  CallExit Loc(CE, LocCtx);

  bool isNew;
  ExplodedNode *Node = Eng.G->getNode(Loc, state, &isNew);
  Node->addPredecessor(Pred, *Eng.G);

  if (isNew)
    Eng.WList->Enqueue(Node);
}
                                                

void GRCallEnterNodeBuilder::GenerateNode(const GRState *state,
                                          const LocationContext *LocCtx) {
  // Get the callee entry block.
  const CFGBlock *Entry = &(LocCtx->getCFG()->getEntry());
  assert(Entry->empty());
  assert(Entry->succ_size() == 1);

  // Get the solitary successor.
  const CFGBlock *SuccB = *(Entry->succ_begin());

  // Construct an edge representing the starting location in the callee.
  BlockEdge Loc(Entry, SuccB, LocCtx);

  bool isNew;
  ExplodedNode *Node = Eng.G->getNode(Loc, state, &isNew);
  Node->addPredecessor(const_cast<ExplodedNode*>(Pred), *Eng.G);

  if (isNew)
    Eng.WList->Enqueue(Node);
}

void GRCallExitNodeBuilder::GenerateNode() {
  // Get the callee's location context.
  const StackFrameContext *LocCtx 
                         = cast<StackFrameContext>(Pred->getLocationContext());

  PostStmt Loc(LocCtx->getCallSite(), LocCtx->getParent());
  bool isNew;
  ExplodedNode *Node = Eng.G->getNode(Loc, Pred->getState(), &isNew);
  Node->addPredecessor(const_cast<ExplodedNode*>(Pred), *Eng.G);
  if (isNew)
    Eng.WList->Enqueue(Node, *const_cast<CFGBlock*>(LocCtx->getCallSiteBlock()),
                       LocCtx->getIndex() + 1);
}
