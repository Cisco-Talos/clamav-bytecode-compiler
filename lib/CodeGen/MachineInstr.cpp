//===-- lib/CodeGen/MachineInstr.cpp --------------------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// Methods common to all machine instructions.
//
//===----------------------------------------------------------------------===//

#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/Constants.h"
#include "llvm/Function.h"
#include "llvm/InlineAsm.h"
#include "llvm/Type.h"
#include "llvm/Value.h"
#include "llvm/Assembly/Writer.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineMemOperand.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/CodeGen/PseudoSourceValue.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/Target/TargetInstrInfo.h"
#include "llvm/Target/TargetInstrDesc.h"
#include "llvm/Target/TargetRegisterInfo.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Analysis/DebugInfo.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/LeakDetector.h"
#include "llvm/Support/MathExtras.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/ADT/FoldingSet.h"
using namespace llvm;

//===----------------------------------------------------------------------===//
// MachineOperand Implementation
//===----------------------------------------------------------------------===//

/// AddRegOperandToRegInfo - Add this register operand to the specified
/// MachineRegisterInfo.  If it is null, then the next/prev fields should be
/// explicitly nulled out.
void MachineOperand::AddRegOperandToRegInfo(MachineRegisterInfo *RegInfo) {
  assert(isReg() && "Can only add reg operand to use lists");
  
  // If the reginfo pointer is null, just explicitly null out or next/prev
  // pointers, to ensure they are not garbage.
  if (RegInfo == 0) {
    Contents.Reg.Prev = 0;
    Contents.Reg.Next = 0;
    return;
  }
  
  // Otherwise, add this operand to the head of the registers use/def list.
  MachineOperand **Head = &RegInfo->getRegUseDefListHead(getReg());
  
  // For SSA values, we prefer to keep the definition at the start of the list.
  // we do this by skipping over the definition if it is at the head of the
  // list.
  if (*Head && (*Head)->isDef())
    Head = &(*Head)->Contents.Reg.Next;
  
  Contents.Reg.Next = *Head;
  if (Contents.Reg.Next) {
    assert(getReg() == Contents.Reg.Next->getReg() &&
           "Different regs on the same list!");
    Contents.Reg.Next->Contents.Reg.Prev = &Contents.Reg.Next;
  }
  
  Contents.Reg.Prev = Head;
  *Head = this;
}

/// RemoveRegOperandFromRegInfo - Remove this register operand from the
/// MachineRegisterInfo it is linked with.
void MachineOperand::RemoveRegOperandFromRegInfo() {
  assert(isOnRegUseList() && "Reg operand is not on a use list");
  // Unlink this from the doubly linked list of operands.
  MachineOperand *NextOp = Contents.Reg.Next;
  *Contents.Reg.Prev = NextOp; 
  if (NextOp) {
    assert(NextOp->getReg() == getReg() && "Corrupt reg use/def chain!");
    NextOp->Contents.Reg.Prev = Contents.Reg.Prev;
  }
  Contents.Reg.Prev = 0;
  Contents.Reg.Next = 0;
}

void MachineOperand::setReg(unsigned Reg) {
  if (getReg() == Reg) return; // No change.
  
  // Otherwise, we have to change the register.  If this operand is embedded
  // into a machine function, we need to update the old and new register's
  // use/def lists.
  if (MachineInstr *MI = getParent())
    if (MachineBasicBlock *MBB = MI->getParent())
      if (MachineFunction *MF = MBB->getParent()) {
        RemoveRegOperandFromRegInfo();
        Contents.Reg.RegNo = Reg;
        AddRegOperandToRegInfo(&MF->getRegInfo());
        return;
      }
        
  // Otherwise, just change the register, no problem.  :)
  Contents.Reg.RegNo = Reg;
}

/// ChangeToImmediate - Replace this operand with a new immediate operand of
/// the specified value.  If an operand is known to be an immediate already,
/// the setImm method should be used.
void MachineOperand::ChangeToImmediate(int64_t ImmVal) {
  // If this operand is currently a register operand, and if this is in a
  // function, deregister the operand from the register's use/def list.
  if (isReg() && getParent() && getParent()->getParent() &&
      getParent()->getParent()->getParent())
    RemoveRegOperandFromRegInfo();
  
  OpKind = MO_Immediate;
  Contents.ImmVal = ImmVal;
}

/// ChangeToRegister - Replace this operand with a new register operand of
/// the specified value.  If an operand is known to be an register already,
/// the setReg method should be used.
void MachineOperand::ChangeToRegister(unsigned Reg, bool isDef, bool isImp,
                                      bool isKill, bool isDead, bool isUndef) {
  // If this operand is already a register operand, use setReg to update the 
  // register's use/def lists.
  if (isReg()) {
    assert(!isEarlyClobber());
    setReg(Reg);
  } else {
    // Otherwise, change this to a register and set the reg#.
    OpKind = MO_Register;
    Contents.Reg.RegNo = Reg;

    // If this operand is embedded in a function, add the operand to the
    // register's use/def list.
    if (MachineInstr *MI = getParent())
      if (MachineBasicBlock *MBB = MI->getParent())
        if (MachineFunction *MF = MBB->getParent())
          AddRegOperandToRegInfo(&MF->getRegInfo());
  }

  IsDef = isDef;
  IsImp = isImp;
  IsKill = isKill;
  IsDead = isDead;
  IsUndef = isUndef;
  IsEarlyClobber = false;
  SubReg = 0;
}

/// isIdenticalTo - Return true if this operand is identical to the specified
/// operand.
bool MachineOperand::isIdenticalTo(const MachineOperand &Other) const {
  if (getType() != Other.getType() ||
      getTargetFlags() != Other.getTargetFlags())
    return false;
  
  switch (getType()) {
  default: llvm_unreachable("Unrecognized operand type");
  case MachineOperand::MO_Register:
    return getReg() == Other.getReg() && isDef() == Other.isDef() &&
           getSubReg() == Other.getSubReg();
  case MachineOperand::MO_Immediate:
    return getImm() == Other.getImm();
  case MachineOperand::MO_FPImmediate:
    return getFPImm() == Other.getFPImm();
  case MachineOperand::MO_MachineBasicBlock:
    return getMBB() == Other.getMBB();
  case MachineOperand::MO_FrameIndex:
    return getIndex() == Other.getIndex();
  case MachineOperand::MO_ConstantPoolIndex:
    return getIndex() == Other.getIndex() && getOffset() == Other.getOffset();
  case MachineOperand::MO_JumpTableIndex:
    return getIndex() == Other.getIndex();
  case MachineOperand::MO_GlobalAddress:
    return getGlobal() == Other.getGlobal() && getOffset() == Other.getOffset();
  case MachineOperand::MO_ExternalSymbol:
    return !strcmp(getSymbolName(), Other.getSymbolName()) &&
           getOffset() == Other.getOffset();
  case MachineOperand::MO_BlockAddress:
    return getBlockAddress() == Other.getBlockAddress();
  }
}

/// print - Print the specified machine operand.
///
void MachineOperand::print(raw_ostream &OS, const TargetMachine *TM) const {
  // If the instruction is embedded into a basic block, we can find the
  // target info for the instruction.
  if (!TM)
    if (const MachineInstr *MI = getParent())
      if (const MachineBasicBlock *MBB = MI->getParent())
        if (const MachineFunction *MF = MBB->getParent())
          TM = &MF->getTarget();

  switch (getType()) {
  case MachineOperand::MO_Register:
    if (getReg() == 0 || TargetRegisterInfo::isVirtualRegister(getReg())) {
      OS << "%reg" << getReg();
    } else {
      if (TM)
        OS << "%" << TM->getRegisterInfo()->get(getReg()).Name;
      else
        OS << "%physreg" << getReg();
    }

    if (getSubReg() != 0)
      OS << ':' << getSubReg();

    if (isDef() || isKill() || isDead() || isImplicit() || isUndef() ||
        isEarlyClobber()) {
      OS << '<';
      bool NeedComma = false;
      if (isDef()) {
        if (NeedComma) OS << ',';
        if (isEarlyClobber())
          OS << "earlyclobber,";
        if (isImplicit())
          OS << "imp-";
        OS << "def";
        NeedComma = true;
      } else if (isImplicit()) {
          OS << "imp-use";
          NeedComma = true;
      }

      if (isKill() || isDead() || isUndef()) {
        if (NeedComma) OS << ',';
        if (isKill())  OS << "kill";
        if (isDead())  OS << "dead";
        if (isUndef()) {
          if (isKill() || isDead())
            OS << ',';
          OS << "undef";
        }
      }
      OS << '>';
    }
    break;
  case MachineOperand::MO_Immediate:
    OS << getImm();
    break;
  case MachineOperand::MO_FPImmediate:
    if (getFPImm()->getType()->isFloatTy())
      OS << getFPImm()->getValueAPF().convertToFloat();
    else
      OS << getFPImm()->getValueAPF().convertToDouble();
    break;
  case MachineOperand::MO_MachineBasicBlock:
    OS << "<BB#" << getMBB()->getNumber() << ">";
    break;
  case MachineOperand::MO_FrameIndex:
    OS << "<fi#" << getIndex() << '>';
    break;
  case MachineOperand::MO_ConstantPoolIndex:
    OS << "<cp#" << getIndex();
    if (getOffset()) OS << "+" << getOffset();
    OS << '>';
    break;
  case MachineOperand::MO_JumpTableIndex:
    OS << "<jt#" << getIndex() << '>';
    break;
  case MachineOperand::MO_GlobalAddress:
    OS << "<ga:";
    WriteAsOperand(OS, getGlobal(), /*PrintType=*/false);
    if (getOffset()) OS << "+" << getOffset();
    OS << '>';
    break;
  case MachineOperand::MO_ExternalSymbol:
    OS << "<es:" << getSymbolName();
    if (getOffset()) OS << "+" << getOffset();
    OS << '>';
    break;
  case MachineOperand::MO_BlockAddress:
    OS << "<";
    WriteAsOperand(OS, getBlockAddress(), /*PrintType=*/false);
    OS << '>';
    break;
  default:
    llvm_unreachable("Unrecognized operand type");
  }
  
  if (unsigned TF = getTargetFlags())
    OS << "[TF=" << TF << ']';
}

//===----------------------------------------------------------------------===//
// MachineMemOperand Implementation
//===----------------------------------------------------------------------===//

MachineMemOperand::MachineMemOperand(const Value *v, unsigned int f,
                                     int64_t o, uint64_t s, unsigned int a)
  : Offset(o), Size(s), V(v),
    Flags((f & 7) | ((Log2_32(a) + 1) << 3)) {
  assert(getBaseAlignment() == a && "Alignment is not a power of 2!");
  assert((isLoad() || isStore()) && "Not a load/store!");
}

/// Profile - Gather unique data for the object.
///
void MachineMemOperand::Profile(FoldingSetNodeID &ID) const {
  ID.AddInteger(Offset);
  ID.AddInteger(Size);
  ID.AddPointer(V);
  ID.AddInteger(Flags);
}

void MachineMemOperand::refineAlignment(const MachineMemOperand *MMO) {
  // The Value and Offset may differ due to CSE. But the flags and size
  // should be the same.
  assert(MMO->getFlags() == getFlags() && "Flags mismatch!");
  assert(MMO->getSize() == getSize() && "Size mismatch!");

  if (MMO->getBaseAlignment() >= getBaseAlignment()) {
    // Update the alignment value.
    Flags = (Flags & 7) | ((Log2_32(MMO->getBaseAlignment()) + 1) << 3);
    // Also update the base and offset, because the new alignment may
    // not be applicable with the old ones.
    V = MMO->getValue();
    Offset = MMO->getOffset();
  }
}

/// getAlignment - Return the minimum known alignment in bytes of the
/// actual memory reference.
uint64_t MachineMemOperand::getAlignment() const {
  return MinAlign(getBaseAlignment(), getOffset());
}

raw_ostream &llvm::operator<<(raw_ostream &OS, const MachineMemOperand &MMO) {
  assert((MMO.isLoad() || MMO.isStore()) &&
         "SV has to be a load, store or both.");
  
  if (MMO.isVolatile())
    OS << "Volatile ";

  if (MMO.isLoad())
    OS << "LD";
  if (MMO.isStore())
    OS << "ST";
  OS << MMO.getSize();
  
  // Print the address information.
  OS << "[";
  if (!MMO.getValue())
    OS << "<unknown>";
  else
    WriteAsOperand(OS, MMO.getValue(), /*PrintType=*/false);

  // If the alignment of the memory reference itself differs from the alignment
  // of the base pointer, print the base alignment explicitly, next to the base
  // pointer.
  if (MMO.getBaseAlignment() != MMO.getAlignment())
    OS << "(align=" << MMO.getBaseAlignment() << ")";

  if (MMO.getOffset() != 0)
    OS << "+" << MMO.getOffset();
  OS << "]";

  // Print the alignment of the reference.
  if (MMO.getBaseAlignment() != MMO.getAlignment() ||
      MMO.getBaseAlignment() != MMO.getSize())
    OS << "(align=" << MMO.getAlignment() << ")";

  return OS;
}

//===----------------------------------------------------------------------===//
// MachineInstr Implementation
//===----------------------------------------------------------------------===//

/// MachineInstr ctor - This constructor creates a dummy MachineInstr with
/// TID NULL and no operands.
MachineInstr::MachineInstr()
  : TID(0), NumImplicitOps(0), AsmPrinterFlags(0), MemRefs(0), MemRefsEnd(0),
    Parent(0), debugLoc(DebugLoc::getUnknownLoc()) {
  // Make sure that we get added to a machine basicblock
  LeakDetector::addGarbageObject(this);
}

void MachineInstr::addImplicitDefUseOperands() {
  if (TID->ImplicitDefs)
    for (const unsigned *ImpDefs = TID->ImplicitDefs; *ImpDefs; ++ImpDefs)
      addOperand(MachineOperand::CreateReg(*ImpDefs, true, true));
  if (TID->ImplicitUses)
    for (const unsigned *ImpUses = TID->ImplicitUses; *ImpUses; ++ImpUses)
      addOperand(MachineOperand::CreateReg(*ImpUses, false, true));
}

/// MachineInstr ctor - This constructor create a MachineInstr and add the
/// implicit operands. It reserves space for number of operands specified by
/// TargetInstrDesc or the numOperands if it is not zero. (for
/// instructions with variable number of operands).
MachineInstr::MachineInstr(const TargetInstrDesc &tid, bool NoImp)
  : TID(&tid), NumImplicitOps(0), AsmPrinterFlags(0),
    MemRefs(0), MemRefsEnd(0), Parent(0),
    debugLoc(DebugLoc::getUnknownLoc()) {
  if (!NoImp && TID->getImplicitDefs())
    for (const unsigned *ImpDefs = TID->getImplicitDefs(); *ImpDefs; ++ImpDefs)
      NumImplicitOps++;
  if (!NoImp && TID->getImplicitUses())
    for (const unsigned *ImpUses = TID->getImplicitUses(); *ImpUses; ++ImpUses)
      NumImplicitOps++;
  Operands.reserve(NumImplicitOps + TID->getNumOperands());
  if (!NoImp)
    addImplicitDefUseOperands();
  // Make sure that we get added to a machine basicblock
  LeakDetector::addGarbageObject(this);
}

/// MachineInstr ctor - As above, but with a DebugLoc.
MachineInstr::MachineInstr(const TargetInstrDesc &tid, const DebugLoc dl,
                           bool NoImp)
  : TID(&tid), NumImplicitOps(0), AsmPrinterFlags(0), MemRefs(0), MemRefsEnd(0),
    Parent(0), debugLoc(dl) {
  if (!NoImp && TID->getImplicitDefs())
    for (const unsigned *ImpDefs = TID->getImplicitDefs(); *ImpDefs; ++ImpDefs)
      NumImplicitOps++;
  if (!NoImp && TID->getImplicitUses())
    for (const unsigned *ImpUses = TID->getImplicitUses(); *ImpUses; ++ImpUses)
      NumImplicitOps++;
  Operands.reserve(NumImplicitOps + TID->getNumOperands());
  if (!NoImp)
    addImplicitDefUseOperands();
  // Make sure that we get added to a machine basicblock
  LeakDetector::addGarbageObject(this);
}

/// MachineInstr ctor - Work exactly the same as the ctor two above, except
/// that the MachineInstr is created and added to the end of the specified 
/// basic block.
///
MachineInstr::MachineInstr(MachineBasicBlock *MBB, const TargetInstrDesc &tid)
  : TID(&tid), NumImplicitOps(0), AsmPrinterFlags(0),
    MemRefs(0), MemRefsEnd(0), Parent(0), 
    debugLoc(DebugLoc::getUnknownLoc()) {
  assert(MBB && "Cannot use inserting ctor with null basic block!");
  if (TID->ImplicitDefs)
    for (const unsigned *ImpDefs = TID->getImplicitDefs(); *ImpDefs; ++ImpDefs)
      NumImplicitOps++;
  if (TID->ImplicitUses)
    for (const unsigned *ImpUses = TID->getImplicitUses(); *ImpUses; ++ImpUses)
      NumImplicitOps++;
  Operands.reserve(NumImplicitOps + TID->getNumOperands());
  addImplicitDefUseOperands();
  // Make sure that we get added to a machine basicblock
  LeakDetector::addGarbageObject(this);
  MBB->push_back(this);  // Add instruction to end of basic block!
}

/// MachineInstr ctor - As above, but with a DebugLoc.
///
MachineInstr::MachineInstr(MachineBasicBlock *MBB, const DebugLoc dl,
                           const TargetInstrDesc &tid)
  : TID(&tid), NumImplicitOps(0), AsmPrinterFlags(0), MemRefs(0), MemRefsEnd(0),
    Parent(0), debugLoc(dl) {
  assert(MBB && "Cannot use inserting ctor with null basic block!");
  if (TID->ImplicitDefs)
    for (const unsigned *ImpDefs = TID->getImplicitDefs(); *ImpDefs; ++ImpDefs)
      NumImplicitOps++;
  if (TID->ImplicitUses)
    for (const unsigned *ImpUses = TID->getImplicitUses(); *ImpUses; ++ImpUses)
      NumImplicitOps++;
  Operands.reserve(NumImplicitOps + TID->getNumOperands());
  addImplicitDefUseOperands();
  // Make sure that we get added to a machine basicblock
  LeakDetector::addGarbageObject(this);
  MBB->push_back(this);  // Add instruction to end of basic block!
}

/// MachineInstr ctor - Copies MachineInstr arg exactly
///
MachineInstr::MachineInstr(MachineFunction &MF, const MachineInstr &MI)
  : TID(&MI.getDesc()), NumImplicitOps(0), AsmPrinterFlags(0),
    MemRefs(MI.MemRefs), MemRefsEnd(MI.MemRefsEnd),
    Parent(0), debugLoc(MI.getDebugLoc()) {
  Operands.reserve(MI.getNumOperands());

  // Add operands
  for (unsigned i = 0; i != MI.getNumOperands(); ++i)
    addOperand(MI.getOperand(i));
  NumImplicitOps = MI.NumImplicitOps;

  // Set parent to null.
  Parent = 0;

  LeakDetector::addGarbageObject(this);
}

MachineInstr::~MachineInstr() {
  LeakDetector::removeGarbageObject(this);
#ifndef NDEBUG
  for (unsigned i = 0, e = Operands.size(); i != e; ++i) {
    assert(Operands[i].ParentMI == this && "ParentMI mismatch!");
    assert((!Operands[i].isReg() || !Operands[i].isOnRegUseList()) &&
           "Reg operand def/use list corrupted");
  }
#endif
}

/// getRegInfo - If this instruction is embedded into a MachineFunction,
/// return the MachineRegisterInfo object for the current function, otherwise
/// return null.
MachineRegisterInfo *MachineInstr::getRegInfo() {
  if (MachineBasicBlock *MBB = getParent())
    return &MBB->getParent()->getRegInfo();
  return 0;
}

/// RemoveRegOperandsFromUseLists - Unlink all of the register operands in
/// this instruction from their respective use lists.  This requires that the
/// operands already be on their use lists.
void MachineInstr::RemoveRegOperandsFromUseLists() {
  for (unsigned i = 0, e = Operands.size(); i != e; ++i) {
    if (Operands[i].isReg())
      Operands[i].RemoveRegOperandFromRegInfo();
  }
}

/// AddRegOperandsToUseLists - Add all of the register operands in
/// this instruction from their respective use lists.  This requires that the
/// operands not be on their use lists yet.
void MachineInstr::AddRegOperandsToUseLists(MachineRegisterInfo &RegInfo) {
  for (unsigned i = 0, e = Operands.size(); i != e; ++i) {
    if (Operands[i].isReg())
      Operands[i].AddRegOperandToRegInfo(&RegInfo);
  }
}


/// addOperand - Add the specified operand to the instruction.  If it is an
/// implicit operand, it is added to the end of the operand list.  If it is
/// an explicit operand it is added at the end of the explicit operand list
/// (before the first implicit operand). 
void MachineInstr::addOperand(const MachineOperand &Op) {
  bool isImpReg = Op.isReg() && Op.isImplicit();
  assert((isImpReg || !OperandsComplete()) &&
         "Trying to add an operand to a machine instr that is already done!");

  MachineRegisterInfo *RegInfo = getRegInfo();

  // If we are adding the operand to the end of the list, our job is simpler.
  // This is true most of the time, so this is a reasonable optimization.
  if (isImpReg || NumImplicitOps == 0) {
    // We can only do this optimization if we know that the operand list won't
    // reallocate.
    if (Operands.empty() || Operands.size()+1 <= Operands.capacity()) {
      Operands.push_back(Op);
    
      // Set the parent of the operand.
      Operands.back().ParentMI = this;
  
      // If the operand is a register, update the operand's use list.
      if (Op.isReg()) {
        Operands.back().AddRegOperandToRegInfo(RegInfo);
        // If the register operand is flagged as early, mark the operand as such
        unsigned OpNo = Operands.size() - 1;
        if (TID->getOperandConstraint(OpNo, TOI::EARLY_CLOBBER) != -1)
          Operands[OpNo].setIsEarlyClobber(true);
      }
      return;
    }
  }
  
  // Otherwise, we have to insert a real operand before any implicit ones.
  unsigned OpNo = Operands.size()-NumImplicitOps;

  // If this instruction isn't embedded into a function, then we don't need to
  // update any operand lists.
  if (RegInfo == 0) {
    // Simple insertion, no reginfo update needed for other register operands.
    Operands.insert(Operands.begin()+OpNo, Op);
    Operands[OpNo].ParentMI = this;

    // Do explicitly set the reginfo for this operand though, to ensure the
    // next/prev fields are properly nulled out.
    if (Operands[OpNo].isReg()) {
      Operands[OpNo].AddRegOperandToRegInfo(0);
      // If the register operand is flagged as early, mark the operand as such
      if (TID->getOperandConstraint(OpNo, TOI::EARLY_CLOBBER) != -1)
        Operands[OpNo].setIsEarlyClobber(true);
    }

  } else if (Operands.size()+1 <= Operands.capacity()) {
    // Otherwise, we have to remove register operands from their register use
    // list, add the operand, then add the register operands back to their use
    // list.  This also must handle the case when the operand list reallocates
    // to somewhere else.
  
    // If insertion of this operand won't cause reallocation of the operand
    // list, just remove the implicit operands, add the operand, then re-add all
    // the rest of the operands.
    for (unsigned i = OpNo, e = Operands.size(); i != e; ++i) {
      assert(Operands[i].isReg() && "Should only be an implicit reg!");
      Operands[i].RemoveRegOperandFromRegInfo();
    }
    
    // Add the operand.  If it is a register, add it to the reg list.
    Operands.insert(Operands.begin()+OpNo, Op);
    Operands[OpNo].ParentMI = this;

    if (Operands[OpNo].isReg()) {
      Operands[OpNo].AddRegOperandToRegInfo(RegInfo);
      // If the register operand is flagged as early, mark the operand as such
      if (TID->getOperandConstraint(OpNo, TOI::EARLY_CLOBBER) != -1)
        Operands[OpNo].setIsEarlyClobber(true);
    }
    
    // Re-add all the implicit ops.
    for (unsigned i = OpNo+1, e = Operands.size(); i != e; ++i) {
      assert(Operands[i].isReg() && "Should only be an implicit reg!");
      Operands[i].AddRegOperandToRegInfo(RegInfo);
    }
  } else {
    // Otherwise, we will be reallocating the operand list.  Remove all reg
    // operands from their list, then readd them after the operand list is
    // reallocated.
    RemoveRegOperandsFromUseLists();
    
    Operands.insert(Operands.begin()+OpNo, Op);
    Operands[OpNo].ParentMI = this;
  
    // Re-add all the operands.
    AddRegOperandsToUseLists(*RegInfo);

      // If the register operand is flagged as early, mark the operand as such
    if (Operands[OpNo].isReg()
        && TID->getOperandConstraint(OpNo, TOI::EARLY_CLOBBER) != -1)
      Operands[OpNo].setIsEarlyClobber(true);
  }
}

/// RemoveOperand - Erase an operand  from an instruction, leaving it with one
/// fewer operand than it started with.
///
void MachineInstr::RemoveOperand(unsigned OpNo) {
  assert(OpNo < Operands.size() && "Invalid operand number");
  
  // Special case removing the last one.
  if (OpNo == Operands.size()-1) {
    // If needed, remove from the reg def/use list.
    if (Operands.back().isReg() && Operands.back().isOnRegUseList())
      Operands.back().RemoveRegOperandFromRegInfo();
    
    Operands.pop_back();
    return;
  }

  // Otherwise, we are removing an interior operand.  If we have reginfo to
  // update, remove all operands that will be shifted down from their reg lists,
  // move everything down, then re-add them.
  MachineRegisterInfo *RegInfo = getRegInfo();
  if (RegInfo) {
    for (unsigned i = OpNo, e = Operands.size(); i != e; ++i) {
      if (Operands[i].isReg())
        Operands[i].RemoveRegOperandFromRegInfo();
    }
  }
  
  Operands.erase(Operands.begin()+OpNo);

  if (RegInfo) {
    for (unsigned i = OpNo, e = Operands.size(); i != e; ++i) {
      if (Operands[i].isReg())
        Operands[i].AddRegOperandToRegInfo(RegInfo);
    }
  }
}

/// addMemOperand - Add a MachineMemOperand to the machine instruction.
/// This function should be used only occasionally. The setMemRefs function
/// is the primary method for setting up a MachineInstr's MemRefs list.
void MachineInstr::addMemOperand(MachineFunction &MF,
                                 MachineMemOperand *MO) {
  mmo_iterator OldMemRefs = MemRefs;
  mmo_iterator OldMemRefsEnd = MemRefsEnd;

  size_t NewNum = (MemRefsEnd - MemRefs) + 1;
  mmo_iterator NewMemRefs = MF.allocateMemRefsArray(NewNum);
  mmo_iterator NewMemRefsEnd = NewMemRefs + NewNum;

  std::copy(OldMemRefs, OldMemRefsEnd, NewMemRefs);
  NewMemRefs[NewNum - 1] = MO;

  MemRefs = NewMemRefs;
  MemRefsEnd = NewMemRefsEnd;
}

/// removeFromParent - This method unlinks 'this' from the containing basic
/// block, and returns it, but does not delete it.
MachineInstr *MachineInstr::removeFromParent() {
  assert(getParent() && "Not embedded in a basic block!");
  getParent()->remove(this);
  return this;
}


/// eraseFromParent - This method unlinks 'this' from the containing basic
/// block, and deletes it.
void MachineInstr::eraseFromParent() {
  assert(getParent() && "Not embedded in a basic block!");
  getParent()->erase(this);
}


/// OperandComplete - Return true if it's illegal to add a new operand
///
bool MachineInstr::OperandsComplete() const {
  unsigned short NumOperands = TID->getNumOperands();
  if (!TID->isVariadic() && getNumOperands()-NumImplicitOps >= NumOperands)
    return true;  // Broken: we have all the operands of this instruction!
  return false;
}

/// getNumExplicitOperands - Returns the number of non-implicit operands.
///
unsigned MachineInstr::getNumExplicitOperands() const {
  unsigned NumOperands = TID->getNumOperands();
  if (!TID->isVariadic())
    return NumOperands;

  for (unsigned i = NumOperands, e = getNumOperands(); i != e; ++i) {
    const MachineOperand &MO = getOperand(i);
    if (!MO.isReg() || !MO.isImplicit())
      NumOperands++;
  }
  return NumOperands;
}


/// isLabel - Returns true if the MachineInstr represents a label.
///
bool MachineInstr::isLabel() const {
  return getOpcode() == TargetInstrInfo::DBG_LABEL ||
         getOpcode() == TargetInstrInfo::EH_LABEL ||
         getOpcode() == TargetInstrInfo::GC_LABEL;
}

/// isDebugLabel - Returns true if the MachineInstr represents a debug label.
///
bool MachineInstr::isDebugLabel() const {
  return getOpcode() == TargetInstrInfo::DBG_LABEL;
}

/// findRegisterUseOperandIdx() - Returns the MachineOperand that is a use of
/// the specific register or -1 if it is not found. It further tightens
/// the search criteria to a use that kills the register if isKill is true.
int MachineInstr::findRegisterUseOperandIdx(unsigned Reg, bool isKill,
                                          const TargetRegisterInfo *TRI) const {
  for (unsigned i = 0, e = getNumOperands(); i != e; ++i) {
    const MachineOperand &MO = getOperand(i);
    if (!MO.isReg() || !MO.isUse())
      continue;
    unsigned MOReg = MO.getReg();
    if (!MOReg)
      continue;
    if (MOReg == Reg ||
        (TRI &&
         TargetRegisterInfo::isPhysicalRegister(MOReg) &&
         TargetRegisterInfo::isPhysicalRegister(Reg) &&
         TRI->isSubRegister(MOReg, Reg)))
      if (!isKill || MO.isKill())
        return i;
  }
  return -1;
}
  
/// findRegisterDefOperandIdx() - Returns the operand index that is a def of
/// the specified register or -1 if it is not found. If isDead is true, defs
/// that are not dead are skipped. If TargetRegisterInfo is non-null, then it
/// also checks if there is a def of a super-register.
int MachineInstr::findRegisterDefOperandIdx(unsigned Reg, bool isDead,
                                          const TargetRegisterInfo *TRI) const {
  for (unsigned i = 0, e = getNumOperands(); i != e; ++i) {
    const MachineOperand &MO = getOperand(i);
    if (!MO.isReg() || !MO.isDef())
      continue;
    unsigned MOReg = MO.getReg();
    if (MOReg == Reg ||
        (TRI &&
         TargetRegisterInfo::isPhysicalRegister(MOReg) &&
         TargetRegisterInfo::isPhysicalRegister(Reg) &&
         TRI->isSubRegister(MOReg, Reg)))
      if (!isDead || MO.isDead())
        return i;
  }
  return -1;
}

/// findFirstPredOperandIdx() - Find the index of the first operand in the
/// operand list that is used to represent the predicate. It returns -1 if
/// none is found.
int MachineInstr::findFirstPredOperandIdx() const {
  const TargetInstrDesc &TID = getDesc();
  if (TID.isPredicable()) {
    for (unsigned i = 0, e = getNumOperands(); i != e; ++i)
      if (TID.OpInfo[i].isPredicate())
        return i;
  }

  return -1;
}
  
/// isRegTiedToUseOperand - Given the index of a register def operand,
/// check if the register def is tied to a source operand, due to either
/// two-address elimination or inline assembly constraints. Returns the
/// first tied use operand index by reference is UseOpIdx is not null.
bool MachineInstr::
isRegTiedToUseOperand(unsigned DefOpIdx, unsigned *UseOpIdx) const {
  if (getOpcode() == TargetInstrInfo::INLINEASM) {
    assert(DefOpIdx >= 2);
    const MachineOperand &MO = getOperand(DefOpIdx);
    if (!MO.isReg() || !MO.isDef() || MO.getReg() == 0)
      return false;
    // Determine the actual operand index that corresponds to this index.
    unsigned DefNo = 0;
    unsigned DefPart = 0;
    for (unsigned i = 1, e = getNumOperands(); i < e; ) {
      const MachineOperand &FMO = getOperand(i);
      // After the normal asm operands there may be additional imp-def regs.
      if (!FMO.isImm())
        return false;
      // Skip over this def.
      unsigned NumOps = InlineAsm::getNumOperandRegisters(FMO.getImm());
      unsigned PrevDef = i + 1;
      i = PrevDef + NumOps;
      if (i > DefOpIdx) {
        DefPart = DefOpIdx - PrevDef;
        break;
      }
      ++DefNo;
    }
    for (unsigned i = 1, e = getNumOperands(); i != e; ++i) {
      const MachineOperand &FMO = getOperand(i);
      if (!FMO.isImm())
        continue;
      if (i+1 >= e || !getOperand(i+1).isReg() || !getOperand(i+1).isUse())
        continue;
      unsigned Idx;
      if (InlineAsm::isUseOperandTiedToDef(FMO.getImm(), Idx) &&
          Idx == DefNo) {
        if (UseOpIdx)
          *UseOpIdx = (unsigned)i + 1 + DefPart;
        return true;
      }
    }
    return false;
  }

  assert(getOperand(DefOpIdx).isDef() && "DefOpIdx is not a def!");
  const TargetInstrDesc &TID = getDesc();
  for (unsigned i = 0, e = TID.getNumOperands(); i != e; ++i) {
    const MachineOperand &MO = getOperand(i);
    if (MO.isReg() && MO.isUse() &&
        TID.getOperandConstraint(i, TOI::TIED_TO) == (int)DefOpIdx) {
      if (UseOpIdx)
        *UseOpIdx = (unsigned)i;
      return true;
    }
  }
  return false;
}

/// isRegTiedToDefOperand - Return true if the operand of the specified index
/// is a register use and it is tied to an def operand. It also returns the def
/// operand index by reference.
bool MachineInstr::
isRegTiedToDefOperand(unsigned UseOpIdx, unsigned *DefOpIdx) const {
  if (getOpcode() == TargetInstrInfo::INLINEASM) {
    const MachineOperand &MO = getOperand(UseOpIdx);
    if (!MO.isReg() || !MO.isUse() || MO.getReg() == 0)
      return false;

    // Find the flag operand corresponding to UseOpIdx
    unsigned FlagIdx, NumOps=0;
    for (FlagIdx = 1; FlagIdx < UseOpIdx; FlagIdx += NumOps+1) {
      const MachineOperand &UFMO = getOperand(FlagIdx);
      // After the normal asm operands there may be additional imp-def regs.
      if (!UFMO.isImm())
        return false;
      NumOps = InlineAsm::getNumOperandRegisters(UFMO.getImm());
      assert(NumOps < getNumOperands() && "Invalid inline asm flag");
      if (UseOpIdx < FlagIdx+NumOps+1)
        break;
    }
    if (FlagIdx >= UseOpIdx)
      return false;
    const MachineOperand &UFMO = getOperand(FlagIdx);
    unsigned DefNo;
    if (InlineAsm::isUseOperandTiedToDef(UFMO.getImm(), DefNo)) {
      if (!DefOpIdx)
        return true;

      unsigned DefIdx = 1;
      // Remember to adjust the index. First operand is asm string, then there
      // is a flag for each.
      while (DefNo) {
        const MachineOperand &FMO = getOperand(DefIdx);
        assert(FMO.isImm());
        // Skip over this def.
        DefIdx += InlineAsm::getNumOperandRegisters(FMO.getImm()) + 1;
        --DefNo;
      }
      *DefOpIdx = DefIdx + UseOpIdx - FlagIdx;
      return true;
    }
    return false;
  }

  const TargetInstrDesc &TID = getDesc();
  if (UseOpIdx >= TID.getNumOperands())
    return false;
  const MachineOperand &MO = getOperand(UseOpIdx);
  if (!MO.isReg() || !MO.isUse())
    return false;
  int DefIdx = TID.getOperandConstraint(UseOpIdx, TOI::TIED_TO);
  if (DefIdx == -1)
    return false;
  if (DefOpIdx)
    *DefOpIdx = (unsigned)DefIdx;
  return true;
}

/// copyKillDeadInfo - Copies kill / dead operand properties from MI.
///
void MachineInstr::copyKillDeadInfo(const MachineInstr *MI) {
  for (unsigned i = 0, e = MI->getNumOperands(); i != e; ++i) {
    const MachineOperand &MO = MI->getOperand(i);
    if (!MO.isReg() || (!MO.isKill() && !MO.isDead()))
      continue;
    for (unsigned j = 0, ee = getNumOperands(); j != ee; ++j) {
      MachineOperand &MOp = getOperand(j);
      if (!MOp.isIdenticalTo(MO))
        continue;
      if (MO.isKill())
        MOp.setIsKill();
      else
        MOp.setIsDead();
      break;
    }
  }
}

/// copyPredicates - Copies predicate operand(s) from MI.
void MachineInstr::copyPredicates(const MachineInstr *MI) {
  const TargetInstrDesc &TID = MI->getDesc();
  if (!TID.isPredicable())
    return;
  for (unsigned i = 0, e = MI->getNumOperands(); i != e; ++i) {
    if (TID.OpInfo[i].isPredicate()) {
      // Predicated operands must be last operands.
      addOperand(MI->getOperand(i));
    }
  }
}

/// isSafeToMove - Return true if it is safe to move this instruction. If
/// SawStore is set to true, it means that there is a store (or call) between
/// the instruction's location and its intended destination.
bool MachineInstr::isSafeToMove(const TargetInstrInfo *TII,
                                bool &SawStore,
                                AliasAnalysis *AA) const {
  // Ignore stuff that we obviously can't move.
  if (TID->mayStore() || TID->isCall()) {
    SawStore = true;
    return false;
  }
  if (TID->isTerminator() || TID->hasUnmodeledSideEffects())
    return false;

  // See if this instruction does a load.  If so, we have to guarantee that the
  // loaded value doesn't change between the load and the its intended
  // destination. The check for isInvariantLoad gives the targe the chance to
  // classify the load as always returning a constant, e.g. a constant pool
  // load.
  if (TID->mayLoad() && !isInvariantLoad(AA))
    // Otherwise, this is a real load.  If there is a store between the load and
    // end of block, or if the load is volatile, we can't move it.
    return !SawStore && !hasVolatileMemoryRef();

  return true;
}

/// isSafeToReMat - Return true if it's safe to rematerialize the specified
/// instruction which defined the specified register instead of copying it.
bool MachineInstr::isSafeToReMat(const TargetInstrInfo *TII,
                                 unsigned DstReg,
                                 AliasAnalysis *AA) const {
  bool SawStore = false;
  if (!TII->isTriviallyReMaterializable(this, AA) ||
      !isSafeToMove(TII, SawStore, AA))
    return false;
  for (unsigned i = 0, e = getNumOperands(); i != e; ++i) {
    const MachineOperand &MO = getOperand(i);
    if (!MO.isReg())
      continue;
    // FIXME: For now, do not remat any instruction with register operands.
    // Later on, we can loosen the restriction is the register operands have
    // not been modified between the def and use. Note, this is different from
    // MachineSink because the code is no longer in two-address form (at least
    // partially).
    if (MO.isUse())
      return false;
    else if (!MO.isDead() && MO.getReg() != DstReg)
      return false;
  }
  return true;
}

/// hasVolatileMemoryRef - Return true if this instruction may have a
/// volatile memory reference, or if the information describing the
/// memory reference is not available. Return false if it is known to
/// have no volatile memory references.
bool MachineInstr::hasVolatileMemoryRef() const {
  // An instruction known never to access memory won't have a volatile access.
  if (!TID->mayStore() &&
      !TID->mayLoad() &&
      !TID->isCall() &&
      !TID->hasUnmodeledSideEffects())
    return false;

  // Otherwise, if the instruction has no memory reference information,
  // conservatively assume it wasn't preserved.
  if (memoperands_empty())
    return true;
  
  // Check the memory reference information for volatile references.
  for (mmo_iterator I = memoperands_begin(), E = memoperands_end(); I != E; ++I)
    if ((*I)->isVolatile())
      return true;

  return false;
}

/// isInvariantLoad - Return true if this instruction is loading from a
/// location whose value is invariant across the function.  For example,
/// loading a value from the constant pool or from from the argument area
/// of a function if it does not change.  This should only return true of
/// *all* loads the instruction does are invariant (if it does multiple loads).
bool MachineInstr::isInvariantLoad(AliasAnalysis *AA) const {
  // If the instruction doesn't load at all, it isn't an invariant load.
  if (!TID->mayLoad())
    return false;

  // If the instruction has lost its memoperands, conservatively assume that
  // it may not be an invariant load.
  if (memoperands_empty())
    return false;

  const MachineFrameInfo *MFI = getParent()->getParent()->getFrameInfo();

  for (mmo_iterator I = memoperands_begin(),
       E = memoperands_end(); I != E; ++I) {
    if ((*I)->isVolatile()) return false;
    if ((*I)->isStore()) return false;

    if (const Value *V = (*I)->getValue()) {
      // A load from a constant PseudoSourceValue is invariant.
      if (const PseudoSourceValue *PSV = dyn_cast<PseudoSourceValue>(V))
        if (PSV->isConstant(MFI))
          continue;
      // If we have an AliasAnalysis, ask it whether the memory is constant.
      if (AA && AA->pointsToConstantMemory(V))
        continue;
    }

    // Otherwise assume conservatively.
    return false;
  }

  // Everything checks out.
  return true;
}

/// isConstantValuePHI - If the specified instruction is a PHI that always
/// merges together the same virtual register, return the register, otherwise
/// return 0.
unsigned MachineInstr::isConstantValuePHI() const {
  if (getOpcode() != TargetInstrInfo::PHI)
    return 0;
  assert(getNumOperands() >= 3 &&
         "It's illegal to have a PHI without source operands");

  unsigned Reg = getOperand(1).getReg();
  for (unsigned i = 3, e = getNumOperands(); i < e; i += 2)
    if (getOperand(i).getReg() != Reg)
      return 0;
  return Reg;
}

void MachineInstr::dump() const {
  errs() << "  " << *this;
}

void MachineInstr::print(raw_ostream &OS, const TargetMachine *TM) const {
  // We can be a bit tidier if we know the TargetMachine and/or MachineFunction.
  const MachineFunction *MF = 0;
  if (const MachineBasicBlock *MBB = getParent()) {
    MF = MBB->getParent();
    if (!TM && MF)
      TM = &MF->getTarget();
  }

  // Print explicitly defined operands on the left of an assignment syntax.
  unsigned StartOp = 0, e = getNumOperands();
  for (; StartOp < e && getOperand(StartOp).isReg() &&
         getOperand(StartOp).isDef() &&
         !getOperand(StartOp).isImplicit();
       ++StartOp) {
    if (StartOp != 0) OS << ", ";
    getOperand(StartOp).print(OS, TM);
  }

  if (StartOp != 0)
    OS << " = ";

  // Print the opcode name.
  OS << getDesc().getName();

  // Print the rest of the operands.
  bool OmittedAnyCallClobbers = false;
  bool FirstOp = true;
  for (unsigned i = StartOp, e = getNumOperands(); i != e; ++i) {
    const MachineOperand &MO = getOperand(i);

    // Omit call-clobbered registers which aren't used anywhere. This makes
    // call instructions much less noisy on targets where calls clobber lots
    // of registers. Don't rely on MO.isDead() because we may be called before
    // LiveVariables is run, or we may be looking at a non-allocatable reg.
    if (MF && getDesc().isCall() &&
        MO.isReg() && MO.isImplicit() && MO.isDef()) {
      unsigned Reg = MO.getReg();
      if (Reg != 0 && TargetRegisterInfo::isPhysicalRegister(Reg)) {
        const MachineRegisterInfo &MRI = MF->getRegInfo();
        if (MRI.use_empty(Reg) && !MRI.isLiveOut(Reg)) {
          bool HasAliasLive = false;
          for (const unsigned *Alias = TM->getRegisterInfo()->getAliasSet(Reg);
               unsigned AliasReg = *Alias; ++Alias)
            if (!MRI.use_empty(AliasReg) || MRI.isLiveOut(AliasReg)) {
              HasAliasLive = true;
              break;
            }
          if (!HasAliasLive) {
            OmittedAnyCallClobbers = true;
            continue;
          }
        }
      }
    }

    if (FirstOp) FirstOp = false; else OS << ",";
    OS << " ";
    MO.print(OS, TM);
  }

  // Briefly indicate whether any call clobbers were omitted.
  if (OmittedAnyCallClobbers) {
    if (!FirstOp) OS << ",";
    OS << " ...";
  }

  bool HaveSemi = false;
  if (!memoperands_empty()) {
    if (!HaveSemi) OS << ";"; HaveSemi = true;

    OS << " mem:";
    for (mmo_iterator i = memoperands_begin(), e = memoperands_end();
         i != e; ++i) {
      OS << **i;
      if (next(i) != e)
        OS << " ";
    }
  }

  if (!debugLoc.isUnknown() && MF) {
    if (!HaveSemi) OS << ";";

    // TODO: print InlinedAtLoc information

    DebugLocTuple DLT = MF->getDebugLocTuple(debugLoc);
    DIScope Scope(DLT.Scope);
    OS << " dbg:";
    // Omit the directory, since it's usually long and uninteresting.
    if (!Scope.isNull())
      OS << Scope.getFilename();
    else
      OS << "<unknown>";
    OS << ':' << DLT.Line;
    if (DLT.Col != 0)
      OS << ':' << DLT.Col;
  }

  OS << "\n";
}

bool MachineInstr::addRegisterKilled(unsigned IncomingReg,
                                     const TargetRegisterInfo *RegInfo,
                                     bool AddIfNotFound) {
  bool isPhysReg = TargetRegisterInfo::isPhysicalRegister(IncomingReg);
  bool hasAliases = isPhysReg && RegInfo->getAliasSet(IncomingReg);
  bool Found = false;
  SmallVector<unsigned,4> DeadOps;
  for (unsigned i = 0, e = getNumOperands(); i != e; ++i) {
    MachineOperand &MO = getOperand(i);
    if (!MO.isReg() || !MO.isUse() || MO.isUndef())
      continue;
    unsigned Reg = MO.getReg();
    if (!Reg)
      continue;

    if (Reg == IncomingReg) {
      if (!Found) {
        if (MO.isKill())
          // The register is already marked kill.
          return true;
        if (isPhysReg && isRegTiedToDefOperand(i))
          // Two-address uses of physregs must not be marked kill.
          return true;
        MO.setIsKill();
        Found = true;
      }
    } else if (hasAliases && MO.isKill() &&
               TargetRegisterInfo::isPhysicalRegister(Reg)) {
      // A super-register kill already exists.
      if (RegInfo->isSuperRegister(IncomingReg, Reg))
        return true;
      if (RegInfo->isSubRegister(IncomingReg, Reg))
        DeadOps.push_back(i);
    }
  }

  // Trim unneeded kill operands.
  while (!DeadOps.empty()) {
    unsigned OpIdx = DeadOps.back();
    if (getOperand(OpIdx).isImplicit())
      RemoveOperand(OpIdx);
    else
      getOperand(OpIdx).setIsKill(false);
    DeadOps.pop_back();
  }

  // If not found, this means an alias of one of the operands is killed. Add a
  // new implicit operand if required.
  if (!Found && AddIfNotFound) {
    addOperand(MachineOperand::CreateReg(IncomingReg,
                                         false /*IsDef*/,
                                         true  /*IsImp*/,
                                         true  /*IsKill*/));
    return true;
  }
  return Found;
}

bool MachineInstr::addRegisterDead(unsigned IncomingReg,
                                   const TargetRegisterInfo *RegInfo,
                                   bool AddIfNotFound) {
  bool isPhysReg = TargetRegisterInfo::isPhysicalRegister(IncomingReg);
  bool hasAliases = isPhysReg && RegInfo->getAliasSet(IncomingReg);
  bool Found = false;
  SmallVector<unsigned,4> DeadOps;
  for (unsigned i = 0, e = getNumOperands(); i != e; ++i) {
    MachineOperand &MO = getOperand(i);
    if (!MO.isReg() || !MO.isDef())
      continue;
    unsigned Reg = MO.getReg();
    if (!Reg)
      continue;

    if (Reg == IncomingReg) {
      if (!Found) {
        if (MO.isDead())
          // The register is already marked dead.
          return true;
        MO.setIsDead();
        Found = true;
      }
    } else if (hasAliases && MO.isDead() &&
               TargetRegisterInfo::isPhysicalRegister(Reg)) {
      // There exists a super-register that's marked dead.
      if (RegInfo->isSuperRegister(IncomingReg, Reg))
        return true;
      if (RegInfo->getSubRegisters(IncomingReg) &&
          RegInfo->getSuperRegisters(Reg) &&
          RegInfo->isSubRegister(IncomingReg, Reg))
        DeadOps.push_back(i);
    }
  }

  // Trim unneeded dead operands.
  while (!DeadOps.empty()) {
    unsigned OpIdx = DeadOps.back();
    if (getOperand(OpIdx).isImplicit())
      RemoveOperand(OpIdx);
    else
      getOperand(OpIdx).setIsDead(false);
    DeadOps.pop_back();
  }

  // If not found, this means an alias of one of the operands is dead. Add a
  // new implicit operand if required.
  if (Found || !AddIfNotFound)
    return Found;
    
  addOperand(MachineOperand::CreateReg(IncomingReg,
                                       true  /*IsDef*/,
                                       true  /*IsImp*/,
                                       false /*IsKill*/,
                                       true  /*IsDead*/));
  return true;
}
