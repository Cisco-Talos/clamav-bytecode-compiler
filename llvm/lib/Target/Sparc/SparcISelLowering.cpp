//===-- SparcISelLowering.cpp - Sparc DAG Lowering Implementation ---------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements the interfaces that Sparc uses to lower LLVM code into a
// selection DAG.
//
//===----------------------------------------------------------------------===//

#include "SparcISelLowering.h"
#include "SparcTargetMachine.h"
#include "llvm/Function.h"
#include "llvm/CodeGen/CallingConvLower.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/CodeGen/SelectionDAG.h"
#include "llvm/CodeGen/TargetLoweringObjectFileImpl.h"
#include "llvm/ADT/VectorExtras.h"
#include "llvm/Support/ErrorHandling.h"
using namespace llvm;


//===----------------------------------------------------------------------===//
// Calling Convention Implementation
//===----------------------------------------------------------------------===//

#include "SparcGenCallingConv.inc"

SDValue
SparcTargetLowering::LowerReturn(SDValue Chain,
                                 CallingConv::ID CallConv, bool isVarArg,
                                 const SmallVectorImpl<ISD::OutputArg> &Outs,
                                 DebugLoc dl, SelectionDAG &DAG) {

  // CCValAssign - represent the assignment of the return value to locations.
  SmallVector<CCValAssign, 16> RVLocs;

  // CCState - Info about the registers and stack slot.
  CCState CCInfo(CallConv, isVarArg, DAG.getTarget(),
                 RVLocs, *DAG.getContext());

  // Analize return values.
  CCInfo.AnalyzeReturn(Outs, RetCC_Sparc32);

  // If this is the first return lowered for this function, add the regs to the
  // liveout set for the function.
  if (DAG.getMachineFunction().getRegInfo().liveout_empty()) {
    for (unsigned i = 0; i != RVLocs.size(); ++i)
      if (RVLocs[i].isRegLoc())
        DAG.getMachineFunction().getRegInfo().addLiveOut(RVLocs[i].getLocReg());
  }

  SDValue Flag;

  // Copy the result values into the output registers.
  for (unsigned i = 0; i != RVLocs.size(); ++i) {
    CCValAssign &VA = RVLocs[i];
    assert(VA.isRegLoc() && "Can only return in registers!");

    Chain = DAG.getCopyToReg(Chain, dl, VA.getLocReg(), 
                             Outs[i].Val, Flag);

    // Guarantee that all emitted copies are stuck together with flags.
    Flag = Chain.getValue(1);
  }

  if (Flag.getNode())
    return DAG.getNode(SPISD::RET_FLAG, dl, MVT::Other, Chain, Flag);
  return DAG.getNode(SPISD::RET_FLAG, dl, MVT::Other, Chain);
}

/// LowerFormalArguments - V8 uses a very simple ABI, where all values are
/// passed in either one or two GPRs, including FP values.  TODO: we should
/// pass FP values in FP registers for fastcc functions.
SDValue
SparcTargetLowering::LowerFormalArguments(SDValue Chain,
                                          CallingConv::ID CallConv, bool isVarArg,
                                          const SmallVectorImpl<ISD::InputArg>
                                            &Ins,
                                          DebugLoc dl, SelectionDAG &DAG,
                                          SmallVectorImpl<SDValue> &InVals) {

  MachineFunction &MF = DAG.getMachineFunction();
  MachineRegisterInfo &RegInfo = MF.getRegInfo();

  // Assign locations to all of the incoming arguments.
  SmallVector<CCValAssign, 16> ArgLocs;
  CCState CCInfo(CallConv, isVarArg, getTargetMachine(),
                 ArgLocs, *DAG.getContext());
  CCInfo.AnalyzeFormalArguments(Ins, CC_Sparc32);

  static const unsigned ArgRegs[] = {
    SP::I0, SP::I1, SP::I2, SP::I3, SP::I4, SP::I5
  };
  const unsigned *CurArgReg = ArgRegs, *ArgRegEnd = ArgRegs+6;
  unsigned ArgOffset = 68;

  for (unsigned i = 0, e = ArgLocs.size(); i != e; ++i) {
    SDValue ArgValue;
    CCValAssign &VA = ArgLocs[i];
    // FIXME: We ignore the register assignments of AnalyzeFormalArguments
    // because it doesn't know how to split a double into two i32 registers.
    EVT ObjectVT = VA.getValVT();
    switch (ObjectVT.getSimpleVT().SimpleTy) {
    default: llvm_unreachable("Unhandled argument type!");
    case MVT::i1:
    case MVT::i8:
    case MVT::i16:
    case MVT::i32:
      if (!Ins[i].Used) {                  // Argument is dead.
        if (CurArgReg < ArgRegEnd) ++CurArgReg;
        InVals.push_back(DAG.getUNDEF(ObjectVT));
      } else if (CurArgReg < ArgRegEnd) {  // Lives in an incoming GPR
        unsigned VReg = RegInfo.createVirtualRegister(&SP::IntRegsRegClass);
        MF.getRegInfo().addLiveIn(*CurArgReg++, VReg);
        SDValue Arg = DAG.getCopyFromReg(Chain, dl, VReg, MVT::i32);
        if (ObjectVT != MVT::i32) {
          unsigned AssertOp = ISD::AssertSext;
          Arg = DAG.getNode(AssertOp, dl, MVT::i32, Arg,
                            DAG.getValueType(ObjectVT));
          Arg = DAG.getNode(ISD::TRUNCATE, dl, ObjectVT, Arg);
        }
        InVals.push_back(Arg);
      } else {
        int FrameIdx = MF.getFrameInfo()->CreateFixedObject(4, ArgOffset,
                                                            true, false);
        SDValue FIPtr = DAG.getFrameIndex(FrameIdx, MVT::i32);
        SDValue Load;
        if (ObjectVT == MVT::i32) {
          Load = DAG.getLoad(MVT::i32, dl, Chain, FIPtr, NULL, 0,
                             false, false, 0);
        } else {
          ISD::LoadExtType LoadOp = ISD::SEXTLOAD;

          // Sparc is big endian, so add an offset based on the ObjectVT.
          unsigned Offset = 4-std::max(1U, ObjectVT.getSizeInBits()/8);
          FIPtr = DAG.getNode(ISD::ADD, dl, MVT::i32, FIPtr,
                              DAG.getConstant(Offset, MVT::i32));
          Load = DAG.getExtLoad(LoadOp, dl, MVT::i32, Chain, FIPtr,
                                NULL, 0, ObjectVT, false, false, 0);
          Load = DAG.getNode(ISD::TRUNCATE, dl, ObjectVT, Load);
        }
        InVals.push_back(Load);
      }

      ArgOffset += 4;
      break;
    case MVT::f32:
      if (!Ins[i].Used) {                  // Argument is dead.
        if (CurArgReg < ArgRegEnd) ++CurArgReg;
        InVals.push_back(DAG.getUNDEF(ObjectVT));
      } else if (CurArgReg < ArgRegEnd) {  // Lives in an incoming GPR
        // FP value is passed in an integer register.
        unsigned VReg = RegInfo.createVirtualRegister(&SP::IntRegsRegClass);
        MF.getRegInfo().addLiveIn(*CurArgReg++, VReg);
        SDValue Arg = DAG.getCopyFromReg(Chain, dl, VReg, MVT::i32);

        Arg = DAG.getNode(ISD::BIT_CONVERT, dl, MVT::f32, Arg);
        InVals.push_back(Arg);
      } else {
        int FrameIdx = MF.getFrameInfo()->CreateFixedObject(4, ArgOffset,
                                                            true, false);
        SDValue FIPtr = DAG.getFrameIndex(FrameIdx, MVT::i32);
        SDValue Load = DAG.getLoad(MVT::f32, dl, Chain, FIPtr, NULL, 0,
                                   false, false, 0);
        InVals.push_back(Load);
      }
      ArgOffset += 4;
      break;

    case MVT::i64:
    case MVT::f64:
      if (!Ins[i].Used) {                // Argument is dead.
        if (CurArgReg < ArgRegEnd) ++CurArgReg;
        if (CurArgReg < ArgRegEnd) ++CurArgReg;
        InVals.push_back(DAG.getUNDEF(ObjectVT));
      } else {
        SDValue HiVal;
        if (CurArgReg < ArgRegEnd) {  // Lives in an incoming GPR
          unsigned VRegHi = RegInfo.createVirtualRegister(&SP::IntRegsRegClass);
          MF.getRegInfo().addLiveIn(*CurArgReg++, VRegHi);
          HiVal = DAG.getCopyFromReg(Chain, dl, VRegHi, MVT::i32);
        } else {
          int FrameIdx = MF.getFrameInfo()->CreateFixedObject(4, ArgOffset,
                                                              true, false);
          SDValue FIPtr = DAG.getFrameIndex(FrameIdx, MVT::i32);
          HiVal = DAG.getLoad(MVT::i32, dl, Chain, FIPtr, NULL, 0,
                              false, false, 0);
        }

        SDValue LoVal;
        if (CurArgReg < ArgRegEnd) {  // Lives in an incoming GPR
          unsigned VRegLo = RegInfo.createVirtualRegister(&SP::IntRegsRegClass);
          MF.getRegInfo().addLiveIn(*CurArgReg++, VRegLo);
          LoVal = DAG.getCopyFromReg(Chain, dl, VRegLo, MVT::i32);
        } else {
          int FrameIdx = MF.getFrameInfo()->CreateFixedObject(4, ArgOffset+4,
                                                              true, false);
          SDValue FIPtr = DAG.getFrameIndex(FrameIdx, MVT::i32);
          LoVal = DAG.getLoad(MVT::i32, dl, Chain, FIPtr, NULL, 0,
                              false, false, 0);
        }

        // Compose the two halves together into an i64 unit.
        SDValue WholeValue =
          DAG.getNode(ISD::BUILD_PAIR, dl, MVT::i64, LoVal, HiVal);

        // If we want a double, do a bit convert.
        if (ObjectVT == MVT::f64)
          WholeValue = DAG.getNode(ISD::BIT_CONVERT, dl, MVT::f64, WholeValue);

        InVals.push_back(WholeValue);
      }
      ArgOffset += 8;
      break;
    }
  }

  // Store remaining ArgRegs to the stack if this is a varargs function.
  if (isVarArg) {
    // Remember the vararg offset for the va_start implementation.
    VarArgsFrameOffset = ArgOffset;

    std::vector<SDValue> OutChains;

    for (; CurArgReg != ArgRegEnd; ++CurArgReg) {
      unsigned VReg = RegInfo.createVirtualRegister(&SP::IntRegsRegClass);
      MF.getRegInfo().addLiveIn(*CurArgReg, VReg);
      SDValue Arg = DAG.getCopyFromReg(DAG.getRoot(), dl, VReg, MVT::i32);

      int FrameIdx = MF.getFrameInfo()->CreateFixedObject(4, ArgOffset,
                                                          true, false);
      SDValue FIPtr = DAG.getFrameIndex(FrameIdx, MVT::i32);

      OutChains.push_back(DAG.getStore(DAG.getRoot(), dl, Arg, FIPtr, NULL, 0,
                                       false, false, 0));
      ArgOffset += 4;
    }

    if (!OutChains.empty()) {
      OutChains.push_back(Chain);
      Chain = DAG.getNode(ISD::TokenFactor, dl, MVT::Other,
                          &OutChains[0], OutChains.size());
    }
  }

  return Chain;
}

SDValue
SparcTargetLowering::LowerCall(SDValue Chain, SDValue Callee,
                               CallingConv::ID CallConv, bool isVarArg,
                               bool &isTailCall,
                               const SmallVectorImpl<ISD::OutputArg> &Outs,
                               const SmallVectorImpl<ISD::InputArg> &Ins,
                               DebugLoc dl, SelectionDAG &DAG,
                               SmallVectorImpl<SDValue> &InVals) {
  // Sparc target does not yet support tail call optimization.
  isTailCall = false;

#if 0
  // Analyze operands of the call, assigning locations to each operand.
  SmallVector<CCValAssign, 16> ArgLocs;
  CCState CCInfo(CallConv, isVarArg, DAG.getTarget(), ArgLocs);
  CCInfo.AnalyzeCallOperands(Outs, CC_Sparc32);

  // Get the size of the outgoing arguments stack space requirement.
  unsigned ArgsSize = CCInfo.getNextStackOffset();
  // FIXME: We can't use this until f64 is known to take two GPRs.
#else
  (void)CC_Sparc32;

  // Count the size of the outgoing arguments.
  unsigned ArgsSize = 0;
  for (unsigned i = 0, e = Outs.size(); i != e; ++i) {
    switch (Outs[i].Val.getValueType().getSimpleVT().SimpleTy) {
      default: llvm_unreachable("Unknown value type!");
      case MVT::i1:
      case MVT::i8:
      case MVT::i16:
      case MVT::i32:
      case MVT::f32:
        ArgsSize += 4;
        break;
      case MVT::i64:
      case MVT::f64:
        ArgsSize += 8;
        break;
    }
  }
  if (ArgsSize > 4*6)
    ArgsSize -= 4*6;    // Space for first 6 arguments is prereserved.
  else
    ArgsSize = 0;
#endif

  // Keep stack frames 8-byte aligned.
  ArgsSize = (ArgsSize+7) & ~7;

  Chain = DAG.getCALLSEQ_START(Chain, DAG.getIntPtrConstant(ArgsSize, true));

  SmallVector<std::pair<unsigned, SDValue>, 8> RegsToPass;
  SmallVector<SDValue, 8> MemOpChains;

#if 0
  // Walk the register/memloc assignments, inserting copies/loads.
  for (unsigned i = 0, e = ArgLocs.size(); i != e; ++i) {
    CCValAssign &VA = ArgLocs[i];
    SDValue Arg = Outs[i].Val;

    // Promote the value if needed.
    switch (VA.getLocInfo()) {
    default: llvm_unreachable("Unknown loc info!");
    case CCValAssign::Full: break;
    case CCValAssign::SExt:
      Arg = DAG.getNode(ISD::SIGN_EXTEND, VA.getLocVT(), Arg);
      break;
    case CCValAssign::ZExt:
      Arg = DAG.getNode(ISD::ZERO_EXTEND, VA.getLocVT(), Arg);
      break;
    case CCValAssign::AExt:
      Arg = DAG.getNode(ISD::ANY_EXTEND, VA.getLocVT(), Arg);
      break;
    }

    // Arguments that can be passed on register must be kept at
    // RegsToPass vector
    if (VA.isRegLoc()) {
      RegsToPass.push_back(std::make_pair(VA.getLocReg(), Arg));
      continue;
    }

    assert(VA.isMemLoc());

    // Create a store off the stack pointer for this argument.
    SDValue StackPtr = DAG.getRegister(SP::O6, MVT::i32);
    // FIXME: VERIFY THAT 68 IS RIGHT.
    SDValue PtrOff = DAG.getIntPtrConstant(VA.getLocMemOffset()+68);
    PtrOff = DAG.getNode(ISD::ADD, MVT::i32, StackPtr, PtrOff);
    MemOpChains.push_back(DAG.getStore(Chain, Arg, PtrOff, NULL, 0,
                                       false, false, 0));
  }

#else
  static const unsigned ArgRegs[] = {
    SP::I0, SP::I1, SP::I2, SP::I3, SP::I4, SP::I5
  };
  unsigned ArgOffset = 68;

  for (unsigned i = 0, e = Outs.size(); i != e; ++i) {
    SDValue Val = Outs[i].Val;
    EVT ObjectVT = Val.getValueType();
    SDValue ValToStore(0, 0);
    unsigned ObjSize;
    switch (ObjectVT.getSimpleVT().SimpleTy) {
    default: llvm_unreachable("Unhandled argument type!");
    case MVT::i32:
      ObjSize = 4;

      if (RegsToPass.size() >= 6) {
        ValToStore = Val;
      } else {
        RegsToPass.push_back(std::make_pair(ArgRegs[RegsToPass.size()], Val));
      }
      break;
    case MVT::f32:
      ObjSize = 4;
      if (RegsToPass.size() >= 6) {
        ValToStore = Val;
      } else {
        // Convert this to a FP value in an int reg.
        Val = DAG.getNode(ISD::BIT_CONVERT, dl, MVT::i32, Val);
        RegsToPass.push_back(std::make_pair(ArgRegs[RegsToPass.size()], Val));
      }
      break;
    case MVT::f64: {
      ObjSize = 8;
      if (RegsToPass.size() >= 6) {
        ValToStore = Val;    // Whole thing is passed in memory.
        break;
      }

      // Break into top and bottom parts by storing to the stack and loading
      // out the parts as integers.  Top part goes in a reg.
      SDValue StackPtr = DAG.CreateStackTemporary(MVT::f64, MVT::i32);
      SDValue Store = DAG.getStore(DAG.getEntryNode(), dl, 
                                   Val, StackPtr, NULL, 0,
                                   false, false, 0);
      // Sparc is big-endian, so the high part comes first.
      SDValue Hi = DAG.getLoad(MVT::i32, dl, Store, StackPtr, NULL, 0,
                               false, false, 0);
      // Increment the pointer to the other half.
      StackPtr = DAG.getNode(ISD::ADD, dl, StackPtr.getValueType(), StackPtr,
                             DAG.getIntPtrConstant(4));
      // Load the low part.
      SDValue Lo = DAG.getLoad(MVT::i32, dl, Store, StackPtr, NULL, 0,
                               false, false, 0);

      RegsToPass.push_back(std::make_pair(ArgRegs[RegsToPass.size()], Hi));

      if (RegsToPass.size() >= 6) {
        ValToStore = Lo;
        ArgOffset += 4;
        ObjSize = 4;
      } else {
        RegsToPass.push_back(std::make_pair(ArgRegs[RegsToPass.size()], Lo));
      }
      break;
    }
    case MVT::i64: {
      ObjSize = 8;
      if (RegsToPass.size() >= 6) {
        ValToStore = Val;    // Whole thing is passed in memory.
        break;
      }

      // Split the value into top and bottom part.  Top part goes in a reg.
      SDValue Hi = DAG.getNode(ISD::EXTRACT_ELEMENT, dl, MVT::i32, Val,
                                 DAG.getConstant(1, MVT::i32));
      SDValue Lo = DAG.getNode(ISD::EXTRACT_ELEMENT, dl, MVT::i32, Val,
                                 DAG.getConstant(0, MVT::i32));
      RegsToPass.push_back(std::make_pair(ArgRegs[RegsToPass.size()], Hi));

      if (RegsToPass.size() >= 6) {
        ValToStore = Lo;
        ArgOffset += 4;
        ObjSize = 4;
      } else {
        RegsToPass.push_back(std::make_pair(ArgRegs[RegsToPass.size()], Lo));
      }
      break;
    }
    }

    if (ValToStore.getNode()) {
      SDValue StackPtr = DAG.getRegister(SP::O6, MVT::i32);
      SDValue PtrOff = DAG.getConstant(ArgOffset, MVT::i32);
      PtrOff = DAG.getNode(ISD::ADD, dl, MVT::i32, StackPtr, PtrOff);
      MemOpChains.push_back(DAG.getStore(Chain, dl, ValToStore, 
                                         PtrOff, NULL, 0,
                                         false, false, 0));
    }
    ArgOffset += ObjSize;
  }
#endif

  // Emit all stores, make sure the occur before any copies into physregs.
  if (!MemOpChains.empty())
    Chain = DAG.getNode(ISD::TokenFactor, dl, MVT::Other,
                        &MemOpChains[0], MemOpChains.size());

  // Build a sequence of copy-to-reg nodes chained together with token
  // chain and flag operands which copy the outgoing args into registers.
  // The InFlag in necessary since all emited instructions must be
  // stuck together.
  SDValue InFlag;
  for (unsigned i = 0, e = RegsToPass.size(); i != e; ++i) {
    unsigned Reg = RegsToPass[i].first;
    // Remap I0->I7 -> O0->O7.
    if (Reg >= SP::I0 && Reg <= SP::I7)
      Reg = Reg-SP::I0+SP::O0;

    Chain = DAG.getCopyToReg(Chain, dl, Reg, RegsToPass[i].second, InFlag);
    InFlag = Chain.getValue(1);
  }

  // If the callee is a GlobalAddress node (quite common, every direct call is)
  // turn it into a TargetGlobalAddress node so that legalize doesn't hack it.
  // Likewise ExternalSymbol -> TargetExternalSymbol.
  if (GlobalAddressSDNode *G = dyn_cast<GlobalAddressSDNode>(Callee))
    Callee = DAG.getTargetGlobalAddress(G->getGlobal(), MVT::i32);
  else if (ExternalSymbolSDNode *E = dyn_cast<ExternalSymbolSDNode>(Callee))
    Callee = DAG.getTargetExternalSymbol(E->getSymbol(), MVT::i32);

  std::vector<EVT> NodeTys;
  NodeTys.push_back(MVT::Other);   // Returns a chain
  NodeTys.push_back(MVT::Flag);    // Returns a flag for retval copy to use.
  SDValue Ops[] = { Chain, Callee, InFlag };
  Chain = DAG.getNode(SPISD::CALL, dl, NodeTys, Ops, InFlag.getNode() ? 3 : 2);
  InFlag = Chain.getValue(1);

  Chain = DAG.getCALLSEQ_END(Chain, DAG.getIntPtrConstant(ArgsSize, true),
                             DAG.getIntPtrConstant(0, true), InFlag);
  InFlag = Chain.getValue(1);

  // Assign locations to each value returned by this call.
  SmallVector<CCValAssign, 16> RVLocs;
  CCState RVInfo(CallConv, isVarArg, DAG.getTarget(),
                 RVLocs, *DAG.getContext());

  RVInfo.AnalyzeCallResult(Ins, RetCC_Sparc32);

  // Copy all of the result registers out of their specified physreg.
  for (unsigned i = 0; i != RVLocs.size(); ++i) {
    unsigned Reg = RVLocs[i].getLocReg();

    // Remap I0->I7 -> O0->O7.
    if (Reg >= SP::I0 && Reg <= SP::I7)
      Reg = Reg-SP::I0+SP::O0;

    Chain = DAG.getCopyFromReg(Chain, dl, Reg,
                               RVLocs[i].getValVT(), InFlag).getValue(1);
    InFlag = Chain.getValue(2);
    InVals.push_back(Chain.getValue(0));
  }

  return Chain;
}



//===----------------------------------------------------------------------===//
// TargetLowering Implementation
//===----------------------------------------------------------------------===//

/// IntCondCCodeToICC - Convert a DAG integer condition code to a SPARC ICC
/// condition.
static SPCC::CondCodes IntCondCCodeToICC(ISD::CondCode CC) {
  switch (CC) {
  default: llvm_unreachable("Unknown integer condition code!");
  case ISD::SETEQ:  return SPCC::ICC_E;
  case ISD::SETNE:  return SPCC::ICC_NE;
  case ISD::SETLT:  return SPCC::ICC_L;
  case ISD::SETGT:  return SPCC::ICC_G;
  case ISD::SETLE:  return SPCC::ICC_LE;
  case ISD::SETGE:  return SPCC::ICC_GE;
  case ISD::SETULT: return SPCC::ICC_CS;
  case ISD::SETULE: return SPCC::ICC_LEU;
  case ISD::SETUGT: return SPCC::ICC_GU;
  case ISD::SETUGE: return SPCC::ICC_CC;
  }
}

/// FPCondCCodeToFCC - Convert a DAG floatingp oint condition code to a SPARC
/// FCC condition.
static SPCC::CondCodes FPCondCCodeToFCC(ISD::CondCode CC) {
  switch (CC) {
  default: llvm_unreachable("Unknown fp condition code!");
  case ISD::SETEQ:
  case ISD::SETOEQ: return SPCC::FCC_E;
  case ISD::SETNE:
  case ISD::SETUNE: return SPCC::FCC_NE;
  case ISD::SETLT:
  case ISD::SETOLT: return SPCC::FCC_L;
  case ISD::SETGT:
  case ISD::SETOGT: return SPCC::FCC_G;
  case ISD::SETLE:
  case ISD::SETOLE: return SPCC::FCC_LE;
  case ISD::SETGE:
  case ISD::SETOGE: return SPCC::FCC_GE;
  case ISD::SETULT: return SPCC::FCC_UL;
  case ISD::SETULE: return SPCC::FCC_ULE;
  case ISD::SETUGT: return SPCC::FCC_UG;
  case ISD::SETUGE: return SPCC::FCC_UGE;
  case ISD::SETUO:  return SPCC::FCC_U;
  case ISD::SETO:   return SPCC::FCC_O;
  case ISD::SETONE: return SPCC::FCC_LG;
  case ISD::SETUEQ: return SPCC::FCC_UE;
  }
}

SparcTargetLowering::SparcTargetLowering(TargetMachine &TM)
  : TargetLowering(TM, new TargetLoweringObjectFileELF()) {

  // Set up the register classes.
  addRegisterClass(MVT::i32, SP::IntRegsRegisterClass);
  addRegisterClass(MVT::f32, SP::FPRegsRegisterClass);
  addRegisterClass(MVT::f64, SP::DFPRegsRegisterClass);

  // Turn FP extload into load/fextend
  setLoadExtAction(ISD::EXTLOAD, MVT::f32, Expand);
  // Sparc doesn't have i1 sign extending load
  setLoadExtAction(ISD::SEXTLOAD, MVT::i1, Promote);
  // Turn FP truncstore into trunc + store.
  setTruncStoreAction(MVT::f64, MVT::f32, Expand);

  // Custom legalize GlobalAddress nodes into LO/HI parts.
  setOperationAction(ISD::GlobalAddress, MVT::i32, Custom);
  setOperationAction(ISD::GlobalTLSAddress, MVT::i32, Custom);
  setOperationAction(ISD::ConstantPool , MVT::i32, Custom);

  // Sparc doesn't have sext_inreg, replace them with shl/sra
  setOperationAction(ISD::SIGN_EXTEND_INREG, MVT::i16, Expand);
  setOperationAction(ISD::SIGN_EXTEND_INREG, MVT::i8 , Expand);
  setOperationAction(ISD::SIGN_EXTEND_INREG, MVT::i1 , Expand);

  // Sparc has no REM or DIVREM operations.
  setOperationAction(ISD::UREM, MVT::i32, Expand);
  setOperationAction(ISD::SREM, MVT::i32, Expand);
  setOperationAction(ISD::SDIVREM, MVT::i32, Expand);
  setOperationAction(ISD::UDIVREM, MVT::i32, Expand);

  // Custom expand fp<->sint
  setOperationAction(ISD::FP_TO_SINT, MVT::i32, Custom);
  setOperationAction(ISD::SINT_TO_FP, MVT::i32, Custom);

  // Expand fp<->uint
  setOperationAction(ISD::FP_TO_UINT, MVT::i32, Expand);
  setOperationAction(ISD::UINT_TO_FP, MVT::i32, Expand);

  setOperationAction(ISD::BIT_CONVERT, MVT::f32, Expand);
  setOperationAction(ISD::BIT_CONVERT, MVT::i32, Expand);

  // Sparc has no select or setcc: expand to SELECT_CC.
  setOperationAction(ISD::SELECT, MVT::i32, Expand);
  setOperationAction(ISD::SELECT, MVT::f32, Expand);
  setOperationAction(ISD::SELECT, MVT::f64, Expand);
  setOperationAction(ISD::SETCC, MVT::i32, Expand);
  setOperationAction(ISD::SETCC, MVT::f32, Expand);
  setOperationAction(ISD::SETCC, MVT::f64, Expand);

  // Sparc doesn't have BRCOND either, it has BR_CC.
  setOperationAction(ISD::BRCOND, MVT::Other, Expand);
  setOperationAction(ISD::BRIND, MVT::Other, Expand);
  setOperationAction(ISD::BR_JT, MVT::Other, Expand);
  setOperationAction(ISD::BR_CC, MVT::i32, Custom);
  setOperationAction(ISD::BR_CC, MVT::f32, Custom);
  setOperationAction(ISD::BR_CC, MVT::f64, Custom);

  setOperationAction(ISD::SELECT_CC, MVT::i32, Custom);
  setOperationAction(ISD::SELECT_CC, MVT::f32, Custom);
  setOperationAction(ISD::SELECT_CC, MVT::f64, Custom);

  // SPARC has no intrinsics for these particular operations.
  setOperationAction(ISD::MEMBARRIER, MVT::Other, Expand);

  setOperationAction(ISD::FSIN , MVT::f64, Expand);
  setOperationAction(ISD::FCOS , MVT::f64, Expand);
  setOperationAction(ISD::FREM , MVT::f64, Expand);
  setOperationAction(ISD::FSIN , MVT::f32, Expand);
  setOperationAction(ISD::FCOS , MVT::f32, Expand);
  setOperationAction(ISD::FREM , MVT::f32, Expand);
  setOperationAction(ISD::CTPOP, MVT::i32, Expand);
  setOperationAction(ISD::CTTZ , MVT::i32, Expand);
  setOperationAction(ISD::CTLZ , MVT::i32, Expand);
  setOperationAction(ISD::ROTL , MVT::i32, Expand);
  setOperationAction(ISD::ROTR , MVT::i32, Expand);
  setOperationAction(ISD::BSWAP, MVT::i32, Expand);
  setOperationAction(ISD::FCOPYSIGN, MVT::f64, Expand);
  setOperationAction(ISD::FCOPYSIGN, MVT::f32, Expand);
  setOperationAction(ISD::FPOW , MVT::f64, Expand);
  setOperationAction(ISD::FPOW , MVT::f32, Expand);

  setOperationAction(ISD::SHL_PARTS, MVT::i32, Expand);
  setOperationAction(ISD::SRA_PARTS, MVT::i32, Expand);
  setOperationAction(ISD::SRL_PARTS, MVT::i32, Expand);

  // FIXME: Sparc provides these multiplies, but we don't have them yet.
  setOperationAction(ISD::UMUL_LOHI, MVT::i32, Expand);
  setOperationAction(ISD::SMUL_LOHI, MVT::i32, Expand);

  setOperationAction(ISD::EH_LABEL, MVT::Other, Expand);

  // VASTART needs to be custom lowered to use the VarArgsFrameIndex.
  setOperationAction(ISD::VASTART           , MVT::Other, Custom);
  // VAARG needs to be lowered to not do unaligned accesses for doubles.
  setOperationAction(ISD::VAARG             , MVT::Other, Custom);

  // Use the default implementation.
  setOperationAction(ISD::VACOPY            , MVT::Other, Expand);
  setOperationAction(ISD::VAEND             , MVT::Other, Expand);
  setOperationAction(ISD::STACKSAVE         , MVT::Other, Expand);
  setOperationAction(ISD::STACKRESTORE      , MVT::Other, Expand);
  setOperationAction(ISD::DYNAMIC_STACKALLOC, MVT::i32  , Custom);

  // No debug info support yet.
  setOperationAction(ISD::EH_LABEL, MVT::Other, Expand);

  setStackPointerRegisterToSaveRestore(SP::O6);

  if (TM.getSubtarget<SparcSubtarget>().isV9())
    setOperationAction(ISD::CTPOP, MVT::i32, Legal);

  computeRegisterProperties();
}

const char *SparcTargetLowering::getTargetNodeName(unsigned Opcode) const {
  switch (Opcode) {
  default: return 0;
  case SPISD::CMPICC:     return "SPISD::CMPICC";
  case SPISD::CMPFCC:     return "SPISD::CMPFCC";
  case SPISD::BRICC:      return "SPISD::BRICC";
  case SPISD::BRFCC:      return "SPISD::BRFCC";
  case SPISD::SELECT_ICC: return "SPISD::SELECT_ICC";
  case SPISD::SELECT_FCC: return "SPISD::SELECT_FCC";
  case SPISD::Hi:         return "SPISD::Hi";
  case SPISD::Lo:         return "SPISD::Lo";
  case SPISD::FTOI:       return "SPISD::FTOI";
  case SPISD::ITOF:       return "SPISD::ITOF";
  case SPISD::CALL:       return "SPISD::CALL";
  case SPISD::RET_FLAG:   return "SPISD::RET_FLAG";
  }
}

/// isMaskedValueZeroForTargetNode - Return true if 'Op & Mask' is known to
/// be zero. Op is expected to be a target specific node. Used by DAG
/// combiner.
void SparcTargetLowering::computeMaskedBitsForTargetNode(const SDValue Op,
                                                         const APInt &Mask,
                                                         APInt &KnownZero,
                                                         APInt &KnownOne,
                                                         const SelectionDAG &DAG,
                                                         unsigned Depth) const {
  APInt KnownZero2, KnownOne2;
  KnownZero = KnownOne = APInt(Mask.getBitWidth(), 0);   // Don't know anything.

  switch (Op.getOpcode()) {
  default: break;
  case SPISD::SELECT_ICC:
  case SPISD::SELECT_FCC:
    DAG.ComputeMaskedBits(Op.getOperand(1), Mask, KnownZero, KnownOne,
                          Depth+1);
    DAG.ComputeMaskedBits(Op.getOperand(0), Mask, KnownZero2, KnownOne2,
                          Depth+1);
    assert((KnownZero & KnownOne) == 0 && "Bits known to be one AND zero?");
    assert((KnownZero2 & KnownOne2) == 0 && "Bits known to be one AND zero?");

    // Only known if known in both the LHS and RHS.
    KnownOne &= KnownOne2;
    KnownZero &= KnownZero2;
    break;
  }
}

// Look at LHS/RHS/CC and see if they are a lowered setcc instruction.  If so
// set LHS/RHS and SPCC to the LHS/RHS of the setcc and SPCC to the condition.
static void LookThroughSetCC(SDValue &LHS, SDValue &RHS,
                             ISD::CondCode CC, unsigned &SPCC) {
  if (isa<ConstantSDNode>(RHS) &&
      cast<ConstantSDNode>(RHS)->getZExtValue() == 0 &&
      CC == ISD::SETNE &&
      ((LHS.getOpcode() == SPISD::SELECT_ICC &&
        LHS.getOperand(3).getOpcode() == SPISD::CMPICC) ||
       (LHS.getOpcode() == SPISD::SELECT_FCC &&
        LHS.getOperand(3).getOpcode() == SPISD::CMPFCC)) &&
      isa<ConstantSDNode>(LHS.getOperand(0)) &&
      isa<ConstantSDNode>(LHS.getOperand(1)) &&
      cast<ConstantSDNode>(LHS.getOperand(0))->getZExtValue() == 1 &&
      cast<ConstantSDNode>(LHS.getOperand(1))->getZExtValue() == 0) {
    SDValue CMPCC = LHS.getOperand(3);
    SPCC = cast<ConstantSDNode>(LHS.getOperand(2))->getZExtValue();
    LHS = CMPCC.getOperand(0);
    RHS = CMPCC.getOperand(1);
  }
}

SDValue SparcTargetLowering::LowerGlobalAddress(SDValue Op, 
                                                SelectionDAG &DAG) {
  GlobalValue *GV = cast<GlobalAddressSDNode>(Op)->getGlobal();
  // FIXME there isn't really any debug info here
  DebugLoc dl = Op.getDebugLoc();
  SDValue GA = DAG.getTargetGlobalAddress(GV, MVT::i32);
  SDValue Hi = DAG.getNode(SPISD::Hi, dl, MVT::i32, GA);
  SDValue Lo = DAG.getNode(SPISD::Lo, dl, MVT::i32, GA);

  if (getTargetMachine().getRelocationModel() != Reloc::PIC_) 
    return DAG.getNode(ISD::ADD, dl, MVT::i32, Lo, Hi);
  
  SDValue GlobalBase = DAG.getNode(SPISD::GLOBAL_BASE_REG, dl,
                                   getPointerTy());
  SDValue RelAddr = DAG.getNode(ISD::ADD, dl, MVT::i32, Lo, Hi);
  SDValue AbsAddr = DAG.getNode(ISD::ADD, dl, MVT::i32, 
                                GlobalBase, RelAddr);
  return DAG.getLoad(getPointerTy(), dl, DAG.getEntryNode(), 
                     AbsAddr, NULL, 0, false, false, 0);
}

SDValue SparcTargetLowering::LowerConstantPool(SDValue Op,
                                               SelectionDAG &DAG) {
  ConstantPoolSDNode *N = cast<ConstantPoolSDNode>(Op);
  // FIXME there isn't really any debug info here
  DebugLoc dl = Op.getDebugLoc();
  Constant *C = N->getConstVal();
  SDValue CP = DAG.getTargetConstantPool(C, MVT::i32, N->getAlignment());
  SDValue Hi = DAG.getNode(SPISD::Hi, dl, MVT::i32, CP);
  SDValue Lo = DAG.getNode(SPISD::Lo, dl, MVT::i32, CP);
  if (getTargetMachine().getRelocationModel() != Reloc::PIC_) 
    return DAG.getNode(ISD::ADD, dl, MVT::i32, Lo, Hi);

  SDValue GlobalBase = DAG.getNode(SPISD::GLOBAL_BASE_REG, dl, 
                                   getPointerTy());
  SDValue RelAddr = DAG.getNode(ISD::ADD, dl, MVT::i32, Lo, Hi);
  SDValue AbsAddr = DAG.getNode(ISD::ADD, dl, MVT::i32,
                                GlobalBase, RelAddr);
  return DAG.getLoad(getPointerTy(), dl, DAG.getEntryNode(), 
                     AbsAddr, NULL, 0, false, false, 0);
}

static SDValue LowerFP_TO_SINT(SDValue Op, SelectionDAG &DAG) {
  DebugLoc dl = Op.getDebugLoc();
  // Convert the fp value to integer in an FP register.
  assert(Op.getValueType() == MVT::i32);
  Op = DAG.getNode(SPISD::FTOI, dl, MVT::f32, Op.getOperand(0));
  return DAG.getNode(ISD::BIT_CONVERT, dl, MVT::i32, Op);
}

static SDValue LowerSINT_TO_FP(SDValue Op, SelectionDAG &DAG) {
  DebugLoc dl = Op.getDebugLoc();
  assert(Op.getOperand(0).getValueType() == MVT::i32);
  SDValue Tmp = DAG.getNode(ISD::BIT_CONVERT, dl, MVT::f32, Op.getOperand(0));
  // Convert the int value to FP in an FP register.
  return DAG.getNode(SPISD::ITOF, dl, Op.getValueType(), Tmp);
}

static SDValue LowerBR_CC(SDValue Op, SelectionDAG &DAG) {
  SDValue Chain = Op.getOperand(0);
  ISD::CondCode CC = cast<CondCodeSDNode>(Op.getOperand(1))->get();
  SDValue LHS = Op.getOperand(2);
  SDValue RHS = Op.getOperand(3);
  SDValue Dest = Op.getOperand(4);
  DebugLoc dl = Op.getDebugLoc();
  unsigned Opc, SPCC = ~0U;

  // If this is a br_cc of a "setcc", and if the setcc got lowered into
  // an CMP[IF]CC/SELECT_[IF]CC pair, find the original compared values.
  LookThroughSetCC(LHS, RHS, CC, SPCC);

  // Get the condition flag.
  SDValue CompareFlag;
  if (LHS.getValueType() == MVT::i32) {
    std::vector<EVT> VTs;
    VTs.push_back(MVT::i32);
    VTs.push_back(MVT::Flag);
    SDValue Ops[2] = { LHS, RHS };
    CompareFlag = DAG.getNode(SPISD::CMPICC, dl, VTs, Ops, 2).getValue(1);
    if (SPCC == ~0U) SPCC = IntCondCCodeToICC(CC);
    Opc = SPISD::BRICC;
  } else {
    CompareFlag = DAG.getNode(SPISD::CMPFCC, dl, MVT::Flag, LHS, RHS);
    if (SPCC == ~0U) SPCC = FPCondCCodeToFCC(CC);
    Opc = SPISD::BRFCC;
  }
  return DAG.getNode(Opc, dl, MVT::Other, Chain, Dest,
                     DAG.getConstant(SPCC, MVT::i32), CompareFlag);
}

static SDValue LowerSELECT_CC(SDValue Op, SelectionDAG &DAG) {
  SDValue LHS = Op.getOperand(0);
  SDValue RHS = Op.getOperand(1);
  ISD::CondCode CC = cast<CondCodeSDNode>(Op.getOperand(4))->get();
  SDValue TrueVal = Op.getOperand(2);
  SDValue FalseVal = Op.getOperand(3);
  DebugLoc dl = Op.getDebugLoc();
  unsigned Opc, SPCC = ~0U;

  // If this is a select_cc of a "setcc", and if the setcc got lowered into
  // an CMP[IF]CC/SELECT_[IF]CC pair, find the original compared values.
  LookThroughSetCC(LHS, RHS, CC, SPCC);

  SDValue CompareFlag;
  if (LHS.getValueType() == MVT::i32) {
    std::vector<EVT> VTs;
    VTs.push_back(LHS.getValueType());   // subcc returns a value
    VTs.push_back(MVT::Flag);
    SDValue Ops[2] = { LHS, RHS };
    CompareFlag = DAG.getNode(SPISD::CMPICC, dl, VTs, Ops, 2).getValue(1);
    Opc = SPISD::SELECT_ICC;
    if (SPCC == ~0U) SPCC = IntCondCCodeToICC(CC);
  } else {
    CompareFlag = DAG.getNode(SPISD::CMPFCC, dl, MVT::Flag, LHS, RHS);
    Opc = SPISD::SELECT_FCC;
    if (SPCC == ~0U) SPCC = FPCondCCodeToFCC(CC);
  }
  return DAG.getNode(Opc, dl, TrueVal.getValueType(), TrueVal, FalseVal,
                     DAG.getConstant(SPCC, MVT::i32), CompareFlag);
}

static SDValue LowerVASTART(SDValue Op, SelectionDAG &DAG,
                              SparcTargetLowering &TLI) {
  // vastart just stores the address of the VarArgsFrameIndex slot into the
  // memory location argument.
  DebugLoc dl = Op.getDebugLoc();
  SDValue Offset = DAG.getNode(ISD::ADD, dl, MVT::i32,
                                 DAG.getRegister(SP::I6, MVT::i32),
                                 DAG.getConstant(TLI.getVarArgsFrameOffset(),
                                                 MVT::i32));
  const Value *SV = cast<SrcValueSDNode>(Op.getOperand(2))->getValue();
  return DAG.getStore(Op.getOperand(0), dl, Offset, Op.getOperand(1), SV, 0,
                      false, false, 0);
}

static SDValue LowerVAARG(SDValue Op, SelectionDAG &DAG) {
  SDNode *Node = Op.getNode();
  EVT VT = Node->getValueType(0);
  SDValue InChain = Node->getOperand(0);
  SDValue VAListPtr = Node->getOperand(1);
  const Value *SV = cast<SrcValueSDNode>(Node->getOperand(2))->getValue();
  DebugLoc dl = Node->getDebugLoc();
  SDValue VAList = DAG.getLoad(MVT::i32, dl, InChain, VAListPtr, SV, 0,
                               false, false, 0);
  // Increment the pointer, VAList, to the next vaarg
  SDValue NextPtr = DAG.getNode(ISD::ADD, dl, MVT::i32, VAList,
                                  DAG.getConstant(VT.getSizeInBits()/8,
                                                  MVT::i32));
  // Store the incremented VAList to the legalized pointer
  InChain = DAG.getStore(VAList.getValue(1), dl, NextPtr,
                         VAListPtr, SV, 0, false, false, 0);
  // Load the actual argument out of the pointer VAList, unless this is an
  // f64 load.
  if (VT != MVT::f64)
    return DAG.getLoad(VT, dl, InChain, VAList, NULL, 0, false, false, 0);

  // Otherwise, load it as i64, then do a bitconvert.
  SDValue V = DAG.getLoad(MVT::i64, dl, InChain, VAList, NULL, 0,
                          false, false, 0);

  // Bit-Convert the value to f64.
  SDValue Ops[2] = {
    DAG.getNode(ISD::BIT_CONVERT, dl, MVT::f64, V),
    V.getValue(1)
  };
  return DAG.getMergeValues(Ops, 2, dl);
}

static SDValue LowerDYNAMIC_STACKALLOC(SDValue Op, SelectionDAG &DAG) {
  SDValue Chain = Op.getOperand(0);  // Legalize the chain.
  SDValue Size  = Op.getOperand(1);  // Legalize the size.
  DebugLoc dl = Op.getDebugLoc();

  unsigned SPReg = SP::O6;
  SDValue SP = DAG.getCopyFromReg(Chain, dl, SPReg, MVT::i32);
  SDValue NewSP = DAG.getNode(ISD::SUB, dl, MVT::i32, SP, Size); // Value
  Chain = DAG.getCopyToReg(SP.getValue(1), dl, SPReg, NewSP);    // Output chain

  // The resultant pointer is actually 16 words from the bottom of the stack,
  // to provide a register spill area.
  SDValue NewVal = DAG.getNode(ISD::ADD, dl, MVT::i32, NewSP,
                                 DAG.getConstant(96, MVT::i32));
  SDValue Ops[2] = { NewVal, Chain };
  return DAG.getMergeValues(Ops, 2, dl);
}


SDValue SparcTargetLowering::
LowerOperation(SDValue Op, SelectionDAG &DAG) {
  switch (Op.getOpcode()) {
  default: llvm_unreachable("Should not custom lower this!");
  // Frame & Return address.  Currently unimplemented
  case ISD::RETURNADDR: return SDValue();
  case ISD::FRAMEADDR:  return SDValue();
  case ISD::GlobalTLSAddress:
    llvm_unreachable("TLS not implemented for Sparc.");
  case ISD::GlobalAddress:      return LowerGlobalAddress(Op, DAG);
  case ISD::ConstantPool:       return LowerConstantPool(Op, DAG);
  case ISD::FP_TO_SINT:         return LowerFP_TO_SINT(Op, DAG);
  case ISD::SINT_TO_FP:         return LowerSINT_TO_FP(Op, DAG);
  case ISD::BR_CC:              return LowerBR_CC(Op, DAG);
  case ISD::SELECT_CC:          return LowerSELECT_CC(Op, DAG);
  case ISD::VASTART:            return LowerVASTART(Op, DAG, *this);
  case ISD::VAARG:              return LowerVAARG(Op, DAG);
  case ISD::DYNAMIC_STACKALLOC: return LowerDYNAMIC_STACKALLOC(Op, DAG);
  }
}

MachineBasicBlock *
SparcTargetLowering::EmitInstrWithCustomInserter(MachineInstr *MI,
                                                 MachineBasicBlock *BB,
                   DenseMap<MachineBasicBlock*, MachineBasicBlock*> *EM) const {
  const TargetInstrInfo &TII = *getTargetMachine().getInstrInfo();
  unsigned BROpcode;
  unsigned CC;
  DebugLoc dl = MI->getDebugLoc();
  // Figure out the conditional branch opcode to use for this select_cc.
  switch (MI->getOpcode()) {
  default: llvm_unreachable("Unknown SELECT_CC!");
  case SP::SELECT_CC_Int_ICC:
  case SP::SELECT_CC_FP_ICC:
  case SP::SELECT_CC_DFP_ICC:
    BROpcode = SP::BCOND;
    break;
  case SP::SELECT_CC_Int_FCC:
  case SP::SELECT_CC_FP_FCC:
  case SP::SELECT_CC_DFP_FCC:
    BROpcode = SP::FBCOND;
    break;
  }

  CC = (SPCC::CondCodes)MI->getOperand(3).getImm();

  // To "insert" a SELECT_CC instruction, we actually have to insert the diamond
  // control-flow pattern.  The incoming instruction knows the destination vreg
  // to set, the condition code register to branch on, the true/false values to
  // select between, and a branch opcode to use.
  const BasicBlock *LLVM_BB = BB->getBasicBlock();
  MachineFunction::iterator It = BB;
  ++It;

  //  thisMBB:
  //  ...
  //   TrueVal = ...
  //   [f]bCC copy1MBB
  //   fallthrough --> copy0MBB
  MachineBasicBlock *thisMBB = BB;
  MachineFunction *F = BB->getParent();
  MachineBasicBlock *copy0MBB = F->CreateMachineBasicBlock(LLVM_BB);
  MachineBasicBlock *sinkMBB = F->CreateMachineBasicBlock(LLVM_BB);
  BuildMI(BB, dl, TII.get(BROpcode)).addMBB(sinkMBB).addImm(CC);
  F->insert(It, copy0MBB);
  F->insert(It, sinkMBB);
  // Update machine-CFG edges by first adding all successors of the current
  // block to the new block which will contain the Phi node for the select.
  // Also inform sdisel of the edge changes.
  for (MachineBasicBlock::succ_iterator I = BB->succ_begin(), 
         E = BB->succ_end(); I != E; ++I) {
    EM->insert(std::make_pair(*I, sinkMBB));
    sinkMBB->addSuccessor(*I);
  }
  // Next, remove all successors of the current block, and add the true
  // and fallthrough blocks as its successors.
  while (!BB->succ_empty())
    BB->removeSuccessor(BB->succ_begin());
  // Next, add the true and fallthrough blocks as its successors.
  BB->addSuccessor(copy0MBB);
  BB->addSuccessor(sinkMBB);

  //  copy0MBB:
  //   %FalseValue = ...
  //   # fallthrough to sinkMBB
  BB = copy0MBB;

  // Update machine-CFG edges
  BB->addSuccessor(sinkMBB);

  //  sinkMBB:
  //   %Result = phi [ %FalseValue, copy0MBB ], [ %TrueValue, thisMBB ]
  //  ...
  BB = sinkMBB;
  BuildMI(BB, dl, TII.get(SP::PHI), MI->getOperand(0).getReg())
    .addReg(MI->getOperand(2).getReg()).addMBB(copy0MBB)
    .addReg(MI->getOperand(1).getReg()).addMBB(thisMBB);

  F->DeleteMachineInstr(MI);   // The pseudo instruction is gone now.
  return BB;
}

//===----------------------------------------------------------------------===//
//                         Sparc Inline Assembly Support
//===----------------------------------------------------------------------===//

/// getConstraintType - Given a constraint letter, return the type of
/// constraint it is for this target.
SparcTargetLowering::ConstraintType
SparcTargetLowering::getConstraintType(const std::string &Constraint) const {
  if (Constraint.size() == 1) {
    switch (Constraint[0]) {
    default:  break;
    case 'r': return C_RegisterClass;
    }
  }

  return TargetLowering::getConstraintType(Constraint);
}

std::pair<unsigned, const TargetRegisterClass*>
SparcTargetLowering::getRegForInlineAsmConstraint(const std::string &Constraint,
                                                  EVT VT) const {
  if (Constraint.size() == 1) {
    switch (Constraint[0]) {
    case 'r':
      return std::make_pair(0U, SP::IntRegsRegisterClass);
    }
  }

  return TargetLowering::getRegForInlineAsmConstraint(Constraint, VT);
}

std::vector<unsigned> SparcTargetLowering::
getRegClassForInlineAsmConstraint(const std::string &Constraint,
                                  EVT VT) const {
  if (Constraint.size() != 1)
    return std::vector<unsigned>();

  switch (Constraint[0]) {
  default: break;
  case 'r':
    return make_vector<unsigned>(SP::L0, SP::L1, SP::L2, SP::L3,
                                 SP::L4, SP::L5, SP::L6, SP::L7,
                                 SP::I0, SP::I1, SP::I2, SP::I3,
                                 SP::I4, SP::I5,
                                 SP::O0, SP::O1, SP::O2, SP::O3,
                                 SP::O4, SP::O5, SP::O7, 0);
  }

  return std::vector<unsigned>();
}

bool
SparcTargetLowering::isOffsetFoldingLegal(const GlobalAddressSDNode *GA) const {
  // The Sparc target isn't yet aware of offsets.
  return false;
}

/// getFunctionAlignment - Return the Log2 alignment of this function.
unsigned SparcTargetLowering::getFunctionAlignment(const Function *) const {
  return 2;
}
