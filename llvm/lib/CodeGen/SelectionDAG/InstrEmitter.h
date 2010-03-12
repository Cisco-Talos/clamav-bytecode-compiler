//===---- InstrEmitter.h - Emit MachineInstrs for the SelectionDAG class ---==//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This declares the Emit routines for the SelectionDAG class, which creates
// MachineInstrs based on the decisions of the SelectionDAG instruction
// selection.
//
//===----------------------------------------------------------------------===//

#ifndef INSTREMITTER_H
#define INSTREMITTER_H

#include "llvm/CodeGen/SelectionDAG.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/ADT/DenseMap.h"

namespace llvm {

class TargetInstrDesc;

class InstrEmitter {
  MachineFunction *MF;
  MachineRegisterInfo *MRI;
  const TargetMachine *TM;
  const TargetInstrInfo *TII;
  const TargetRegisterInfo *TRI;
  const TargetLowering *TLI;

  MachineBasicBlock *MBB;
  MachineBasicBlock::iterator InsertPos;

  /// EmitCopyFromReg - Generate machine code for an CopyFromReg node or an
  /// implicit physical register output.
  void EmitCopyFromReg(SDNode *Node, unsigned ResNo,
                       bool IsClone, bool IsCloned,
                       unsigned SrcReg,
                       DenseMap<SDValue, unsigned> &VRBaseMap);

  /// getDstOfCopyToRegUse - If the only use of the specified result number of
  /// node is a CopyToReg, return its destination register. Return 0 otherwise.
  unsigned getDstOfOnlyCopyToRegUse(SDNode *Node,
                                    unsigned ResNo) const;

  void CreateVirtualRegisters(SDNode *Node, MachineInstr *MI,
                              const TargetInstrDesc &II,
                              bool IsClone, bool IsCloned,
                              DenseMap<SDValue, unsigned> &VRBaseMap);

  /// getVR - Return the virtual register corresponding to the specified result
  /// of the specified node.
  unsigned getVR(SDValue Op,
                 DenseMap<SDValue, unsigned> &VRBaseMap);

  /// AddRegisterOperand - Add the specified register as an operand to the
  /// specified machine instr. Insert register copies if the register is
  /// not in the required register class.
  void AddRegisterOperand(MachineInstr *MI, SDValue Op,
                          unsigned IIOpNum,
                          const TargetInstrDesc *II,
                          DenseMap<SDValue, unsigned> &VRBaseMap);

  /// AddOperand - Add the specified operand to the specified machine instr.  II
  /// specifies the instruction information for the node, and IIOpNum is the
  /// operand number (in the II) that we are adding. IIOpNum and II are used for
  /// assertions only.
  void AddOperand(MachineInstr *MI, SDValue Op,
                  unsigned IIOpNum,
                  const TargetInstrDesc *II,
                  DenseMap<SDValue, unsigned> &VRBaseMap);

  /// EmitSubregNode - Generate machine code for subreg nodes.
  ///
  void EmitSubregNode(SDNode *Node, DenseMap<SDValue, unsigned> &VRBaseMap);

  /// EmitCopyToRegClassNode - Generate machine code for COPY_TO_REGCLASS nodes.
  /// COPY_TO_REGCLASS is just a normal copy, except that the destination
  /// register is constrained to be in a particular register class.
  ///
  void EmitCopyToRegClassNode(SDNode *Node,
                              DenseMap<SDValue, unsigned> &VRBaseMap);

public:
  /// CountResults - The results of target nodes have register or immediate
  /// operands first, then an optional chain, and optional flag operands
  /// (which do not go into the machine instrs.)
  static unsigned CountResults(SDNode *Node);

  /// CountOperands - The inputs to target nodes have any actual inputs first,
  /// followed by an optional chain operand, then flag operands.  Compute
  /// the number of actual operands that will go into the resulting
  /// MachineInstr.
  static unsigned CountOperands(SDNode *Node);

  /// EmitNode - Generate machine code for a node and needed dependencies.
  ///
  void EmitNode(SDNode *Node, bool IsClone, bool IsCloned,
                DenseMap<SDValue, unsigned> &VRBaseMap,
                DenseMap<MachineBasicBlock*, MachineBasicBlock*> *EM);

  /// getBlock - Return the current basic block.
  MachineBasicBlock *getBlock() { return MBB; }

  /// getInsertPos - Return the current insertion position.
  MachineBasicBlock::iterator getInsertPos() { return InsertPos; }

  /// InstrEmitter - Construct an InstrEmitter and set it to start inserting
  /// at the given position in the given block.
  InstrEmitter(MachineBasicBlock *mbb, MachineBasicBlock::iterator insertpos);
};

}

#endif
