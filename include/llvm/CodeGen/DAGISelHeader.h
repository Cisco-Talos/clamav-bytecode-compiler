//==-llvm/CodeGen/DAGISelHeader.h - Common DAG ISel definitions  -*- C++ -*-==//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file provides definitions of the common, target-independent methods and 
// data, which is used by SelectionDAG-based instruction selectors.
//
// *** NOTE: This file is #included into the middle of the target
// instruction selector class.  These functions are really methods.
// This is a little awkward, but it allows this code to be shared
// by all the targets while still being able to call into
// target-specific code without using a virtual function call.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_CODEGEN_DAGISEL_HEADER_H
#define LLVM_CODEGEN_DAGISEL_HEADER_H

/// ISelPosition - Node iterator marking the current position of
/// instruction selection as it procedes through the topologically-sorted
/// node list.
SelectionDAG::allnodes_iterator ISelPosition;

/// ISelUpdater - helper class to handle updates of the 
/// instruciton selection graph.
class VISIBILITY_HIDDEN ISelUpdater : public SelectionDAG::DAGUpdateListener {
  SelectionDAG::allnodes_iterator &ISelPosition;
public:
  explicit ISelUpdater(SelectionDAG::allnodes_iterator &isp)
    : ISelPosition(isp) {}
  
  /// NodeDeleted - Handle nodes deleted from the graph. If the
  /// node being deleted is the current ISelPosition node, update
  /// ISelPosition.
  ///
  virtual void NodeDeleted(SDNode *N, SDNode *E) {
    if (ISelPosition == SelectionDAG::allnodes_iterator(N))
      ++ISelPosition;
  }

  /// NodeUpdated - Ignore updates for now.
  virtual void NodeUpdated(SDNode *N) {}
};

/// ReplaceUses - replace all uses of the old node F with the use
/// of the new node T.
DISABLE_INLINE void ReplaceUses(SDValue F, SDValue T) {
  ISelUpdater ISU(ISelPosition);
  CurDAG->ReplaceAllUsesOfValueWith(F, T, &ISU);
}

/// ReplaceUses - replace all uses of the old nodes F with the use
/// of the new nodes T.
DISABLE_INLINE void ReplaceUses(const SDValue *F, const SDValue *T,
                                unsigned Num) {
  ISelUpdater ISU(ISelPosition);
  CurDAG->ReplaceAllUsesOfValuesWith(F, T, Num, &ISU);
}

/// ReplaceUses - replace all uses of the old node F with the use
/// of the new node T.
DISABLE_INLINE void ReplaceUses(SDNode *F, SDNode *T) {
  ISelUpdater ISU(ISelPosition);
  CurDAG->ReplaceAllUsesWith(F, T, &ISU);
}

/// SelectRoot - Top level entry to DAG instruction selector.
/// Selects instructions starting at the root of the current DAG.
void SelectRoot(SelectionDAG &DAG) {
  SelectRootInit();

  // Create a dummy node (which is not added to allnodes), that adds
  // a reference to the root node, preventing it from being deleted,
  // and tracking any changes of the root.
  HandleSDNode Dummy(CurDAG->getRoot());
  ISelPosition = SelectionDAG::allnodes_iterator(CurDAG->getRoot().getNode());
  ++ISelPosition;

  // The AllNodes list is now topological-sorted. Visit the
  // nodes by starting at the end of the list (the root of the
  // graph) and preceding back toward the beginning (the entry
  // node).
  while (ISelPosition != CurDAG->allnodes_begin()) {
    SDNode *Node = --ISelPosition;
    // Skip dead nodes. DAGCombiner is expected to eliminate all dead nodes,
    // but there are currently some corner cases that it misses. Also, this
    // makes it theoretically possible to disable the DAGCombiner.
    if (Node->use_empty())
      continue;

    SDNode *ResNode = Select(Node);
    
    // If node should not be replaced, continue with the next one.
    if (ResNode == Node)
      continue;
    // Replace node.
    if (ResNode)
      ReplaceUses(Node, ResNode);

    // If after the replacement this node is not used any more,
    // remove this dead node.
    if (Node->use_empty()) { // Don't delete EntryToken, etc.
      ISelUpdater ISU(ISelPosition);
      CurDAG->RemoveDeadNode(Node, &ISU);
    }
  }

  CurDAG->setRoot(Dummy.getValue());
}


#endif /* LLVM_CODEGEN_DAGISEL_HEADER_H */
