//===-- SelectionDAGBuilder.cpp - Selection-DAG building ------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This implements routines for translating from LLVM IR into SelectionDAG IR.
//
//===----------------------------------------------------------------------===//

#define DEBUG_TYPE "isel"
#include "SelectionDAGBuilder.h"
#include "FunctionLoweringInfo.h"
#include "llvm/ADT/BitVector.h"
#include "llvm/ADT/SmallSet.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Constants.h"
#include "llvm/CallingConv.h"
#include "llvm/DerivedTypes.h"
#include "llvm/Function.h"
#include "llvm/GlobalVariable.h"
#include "llvm/InlineAsm.h"
#include "llvm/Instructions.h"
#include "llvm/Intrinsics.h"
#include "llvm/IntrinsicInst.h"
#include "llvm/LLVMContext.h"
#include "llvm/Module.h"
#include "llvm/CodeGen/FastISel.h"
#include "llvm/CodeGen/GCStrategy.h"
#include "llvm/CodeGen/GCMetadata.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineJumpTableInfo.h"
#include "llvm/CodeGen/MachineModuleInfo.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/CodeGen/PseudoSourceValue.h"
#include "llvm/CodeGen/SelectionDAG.h"
#include "llvm/CodeGen/DwarfWriter.h"
#include "llvm/Analysis/DebugInfo.h"
#include "llvm/Target/TargetRegisterInfo.h"
#include "llvm/Target/TargetData.h"
#include "llvm/Target/TargetFrameInfo.h"
#include "llvm/Target/TargetInstrInfo.h"
#include "llvm/Target/TargetIntrinsicInfo.h"
#include "llvm/Target/TargetLowering.h"
#include "llvm/Target/TargetOptions.h"
#include "llvm/Support/Compiler.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/MathExtras.h"
#include "llvm/Support/raw_ostream.h"
#include <algorithm>
using namespace llvm;

/// LimitFloatPrecision - Generate low-precision inline sequences for
/// some float libcalls (6, 8 or 12 bits).
static unsigned LimitFloatPrecision;

static cl::opt<unsigned, true>
LimitFPPrecision("limit-float-precision",
                 cl::desc("Generate low-precision inline sequences "
                          "for some float libcalls"),
                 cl::location(LimitFloatPrecision),
                 cl::init(0));

namespace {
  /// RegsForValue - This struct represents the registers (physical or virtual)
  /// that a particular set of values is assigned, and the type information about
  /// the value. The most common situation is to represent one value at a time,
  /// but struct or array values are handled element-wise as multiple values.
  /// The splitting of aggregates is performed recursively, so that we never
  /// have aggregate-typed registers. The values at this point do not necessarily
  /// have legal types, so each value may require one or more registers of some
  /// legal type.
  ///
  struct RegsForValue {
    /// TLI - The TargetLowering object.
    ///
    const TargetLowering *TLI;

    /// ValueVTs - The value types of the values, which may not be legal, and
    /// may need be promoted or synthesized from one or more registers.
    ///
    SmallVector<EVT, 4> ValueVTs;

    /// RegVTs - The value types of the registers. This is the same size as
    /// ValueVTs and it records, for each value, what the type of the assigned
    /// register or registers are. (Individual values are never synthesized
    /// from more than one type of register.)
    ///
    /// With virtual registers, the contents of RegVTs is redundant with TLI's
    /// getRegisterType member function, however when with physical registers
    /// it is necessary to have a separate record of the types.
    ///
    SmallVector<EVT, 4> RegVTs;

    /// Regs - This list holds the registers assigned to the values.
    /// Each legal or promoted value requires one register, and each
    /// expanded value requires multiple registers.
    ///
    SmallVector<unsigned, 4> Regs;

    RegsForValue() : TLI(0) {}

    RegsForValue(const TargetLowering &tli,
                 const SmallVector<unsigned, 4> &regs,
                 EVT regvt, EVT valuevt)
      : TLI(&tli),  ValueVTs(1, valuevt), RegVTs(1, regvt), Regs(regs) {}
    RegsForValue(const TargetLowering &tli,
                 const SmallVector<unsigned, 4> &regs,
                 const SmallVector<EVT, 4> &regvts,
                 const SmallVector<EVT, 4> &valuevts)
      : TLI(&tli), ValueVTs(valuevts), RegVTs(regvts), Regs(regs) {}
    RegsForValue(LLVMContext &Context, const TargetLowering &tli,
                 unsigned Reg, const Type *Ty) : TLI(&tli) {
      ComputeValueVTs(tli, Ty, ValueVTs);

      for (unsigned Value = 0, e = ValueVTs.size(); Value != e; ++Value) {
        EVT ValueVT = ValueVTs[Value];
        unsigned NumRegs = TLI->getNumRegisters(Context, ValueVT);
        EVT RegisterVT = TLI->getRegisterType(Context, ValueVT);
        for (unsigned i = 0; i != NumRegs; ++i)
          Regs.push_back(Reg + i);
        RegVTs.push_back(RegisterVT);
        Reg += NumRegs;
      }
    }

    /// append - Add the specified values to this one.
    void append(const RegsForValue &RHS) {
      TLI = RHS.TLI;
      ValueVTs.append(RHS.ValueVTs.begin(), RHS.ValueVTs.end());
      RegVTs.append(RHS.RegVTs.begin(), RHS.RegVTs.end());
      Regs.append(RHS.Regs.begin(), RHS.Regs.end());
    }


    /// getCopyFromRegs - Emit a series of CopyFromReg nodes that copies from
    /// this value and returns the result as a ValueVTs value.  This uses
    /// Chain/Flag as the input and updates them for the output Chain/Flag.
    /// If the Flag pointer is NULL, no flag is used.
    SDValue getCopyFromRegs(SelectionDAG &DAG, DebugLoc dl,
                              SDValue &Chain, SDValue *Flag) const;

    /// getCopyToRegs - Emit a series of CopyToReg nodes that copies the
    /// specified value into the registers specified by this object.  This uses
    /// Chain/Flag as the input and updates them for the output Chain/Flag.
    /// If the Flag pointer is NULL, no flag is used.
    void getCopyToRegs(SDValue Val, SelectionDAG &DAG, DebugLoc dl,
                       SDValue &Chain, SDValue *Flag) const;

    /// AddInlineAsmOperands - Add this value to the specified inlineasm node
    /// operand list.  This adds the code marker, matching input operand index
    /// (if applicable), and includes the number of values added into it.
    void AddInlineAsmOperands(unsigned Code,
                              bool HasMatching, unsigned MatchingIdx,
                              SelectionDAG &DAG, std::vector<SDValue> &Ops) const;
  };
}

/// getCopyFromParts - Create a value that contains the specified legal parts
/// combined into the value they represent.  If the parts combine to a type
/// larger then ValueVT then AssertOp can be used to specify whether the extra
/// bits are known to be zero (ISD::AssertZext) or sign extended from ValueVT
/// (ISD::AssertSext).
static SDValue getCopyFromParts(SelectionDAG &DAG, DebugLoc dl,
                                const SDValue *Parts,
                                unsigned NumParts, EVT PartVT, EVT ValueVT,
                                ISD::NodeType AssertOp = ISD::DELETED_NODE) {
  assert(NumParts > 0 && "No parts to assemble!");
  const TargetLowering &TLI = DAG.getTargetLoweringInfo();
  SDValue Val = Parts[0];

  if (NumParts > 1) {
    // Assemble the value from multiple parts.
    if (!ValueVT.isVector() && ValueVT.isInteger()) {
      unsigned PartBits = PartVT.getSizeInBits();
      unsigned ValueBits = ValueVT.getSizeInBits();

      // Assemble the power of 2 part.
      unsigned RoundParts = NumParts & (NumParts - 1) ?
        1 << Log2_32(NumParts) : NumParts;
      unsigned RoundBits = PartBits * RoundParts;
      EVT RoundVT = RoundBits == ValueBits ?
        ValueVT : EVT::getIntegerVT(*DAG.getContext(), RoundBits);
      SDValue Lo, Hi;

      EVT HalfVT = EVT::getIntegerVT(*DAG.getContext(), RoundBits/2);

      if (RoundParts > 2) {
        Lo = getCopyFromParts(DAG, dl, Parts, RoundParts/2, PartVT, HalfVT);
        Hi = getCopyFromParts(DAG, dl, Parts+RoundParts/2, RoundParts/2,
                              PartVT, HalfVT);
      } else {
        Lo = DAG.getNode(ISD::BIT_CONVERT, dl, HalfVT, Parts[0]);
        Hi = DAG.getNode(ISD::BIT_CONVERT, dl, HalfVT, Parts[1]);
      }
      if (TLI.isBigEndian())
        std::swap(Lo, Hi);
      Val = DAG.getNode(ISD::BUILD_PAIR, dl, RoundVT, Lo, Hi);

      if (RoundParts < NumParts) {
        // Assemble the trailing non-power-of-2 part.
        unsigned OddParts = NumParts - RoundParts;
        EVT OddVT = EVT::getIntegerVT(*DAG.getContext(), OddParts * PartBits);
        Hi = getCopyFromParts(DAG, dl,
                              Parts+RoundParts, OddParts, PartVT, OddVT);

        // Combine the round and odd parts.
        Lo = Val;
        if (TLI.isBigEndian())
          std::swap(Lo, Hi);
        EVT TotalVT = EVT::getIntegerVT(*DAG.getContext(), NumParts * PartBits);
        Hi = DAG.getNode(ISD::ANY_EXTEND, dl, TotalVT, Hi);
        Hi = DAG.getNode(ISD::SHL, dl, TotalVT, Hi,
                         DAG.getConstant(Lo.getValueType().getSizeInBits(),
                                         TLI.getPointerTy()));
        Lo = DAG.getNode(ISD::ZERO_EXTEND, dl, TotalVT, Lo);
        Val = DAG.getNode(ISD::OR, dl, TotalVT, Lo, Hi);
      }
    } else if (ValueVT.isVector()) {
      // Handle a multi-element vector.
      EVT IntermediateVT, RegisterVT;
      unsigned NumIntermediates;
      unsigned NumRegs =
        TLI.getVectorTypeBreakdown(*DAG.getContext(), ValueVT, IntermediateVT, 
                                   NumIntermediates, RegisterVT);
      assert(NumRegs == NumParts && "Part count doesn't match vector breakdown!");
      NumParts = NumRegs; // Silence a compiler warning.
      assert(RegisterVT == PartVT && "Part type doesn't match vector breakdown!");
      assert(RegisterVT == Parts[0].getValueType() &&
             "Part type doesn't match part!");

      // Assemble the parts into intermediate operands.
      SmallVector<SDValue, 8> Ops(NumIntermediates);
      if (NumIntermediates == NumParts) {
        // If the register was not expanded, truncate or copy the value,
        // as appropriate.
        for (unsigned i = 0; i != NumParts; ++i)
          Ops[i] = getCopyFromParts(DAG, dl, &Parts[i], 1,
                                    PartVT, IntermediateVT);
      } else if (NumParts > 0) {
        // If the intermediate type was expanded, build the intermediate operands
        // from the parts.
        assert(NumParts % NumIntermediates == 0 &&
               "Must expand into a divisible number of parts!");
        unsigned Factor = NumParts / NumIntermediates;
        for (unsigned i = 0; i != NumIntermediates; ++i)
          Ops[i] = getCopyFromParts(DAG, dl, &Parts[i * Factor], Factor,
                                    PartVT, IntermediateVT);
      }

      // Build a vector with BUILD_VECTOR or CONCAT_VECTORS from the intermediate
      // operands.
      Val = DAG.getNode(IntermediateVT.isVector() ?
                        ISD::CONCAT_VECTORS : ISD::BUILD_VECTOR, dl,
                        ValueVT, &Ops[0], NumIntermediates);
    } else if (PartVT.isFloatingPoint()) {
      // FP split into multiple FP parts (for ppcf128)
      assert(ValueVT == EVT(MVT::ppcf128) && PartVT == EVT(MVT::f64) &&
             "Unexpected split");
      SDValue Lo, Hi;
      Lo = DAG.getNode(ISD::BIT_CONVERT, dl, EVT(MVT::f64), Parts[0]);
      Hi = DAG.getNode(ISD::BIT_CONVERT, dl, EVT(MVT::f64), Parts[1]);
      if (TLI.isBigEndian())
        std::swap(Lo, Hi);
      Val = DAG.getNode(ISD::BUILD_PAIR, dl, ValueVT, Lo, Hi);
    } else {
      // FP split into integer parts (soft fp)
      assert(ValueVT.isFloatingPoint() && PartVT.isInteger() &&
             !PartVT.isVector() && "Unexpected split");
      EVT IntVT = EVT::getIntegerVT(*DAG.getContext(), ValueVT.getSizeInBits());
      Val = getCopyFromParts(DAG, dl, Parts, NumParts, PartVT, IntVT);
    }
  }

  // There is now one part, held in Val.  Correct it to match ValueVT.
  PartVT = Val.getValueType();

  if (PartVT == ValueVT)
    return Val;

  if (PartVT.isVector()) {
    assert(ValueVT.isVector() && "Unknown vector conversion!");
    return DAG.getNode(ISD::BIT_CONVERT, dl, ValueVT, Val);
  }

  if (ValueVT.isVector()) {
    assert(ValueVT.getVectorElementType() == PartVT &&
           ValueVT.getVectorNumElements() == 1 &&
           "Only trivial scalar-to-vector conversions should get here!");
    return DAG.getNode(ISD::BUILD_VECTOR, dl, ValueVT, Val);
  }

  if (PartVT.isInteger() &&
      ValueVT.isInteger()) {
    if (ValueVT.bitsLT(PartVT)) {
      // For a truncate, see if we have any information to
      // indicate whether the truncated bits will always be
      // zero or sign-extension.
      if (AssertOp != ISD::DELETED_NODE)
        Val = DAG.getNode(AssertOp, dl, PartVT, Val,
                          DAG.getValueType(ValueVT));
      return DAG.getNode(ISD::TRUNCATE, dl, ValueVT, Val);
    } else {
      return DAG.getNode(ISD::ANY_EXTEND, dl, ValueVT, Val);
    }
  }

  if (PartVT.isFloatingPoint() && ValueVT.isFloatingPoint()) {
    if (ValueVT.bitsLT(Val.getValueType()))
      // FP_ROUND's are always exact here.
      return DAG.getNode(ISD::FP_ROUND, dl, ValueVT, Val,
                         DAG.getIntPtrConstant(1));
    return DAG.getNode(ISD::FP_EXTEND, dl, ValueVT, Val);
  }

  if (PartVT.getSizeInBits() == ValueVT.getSizeInBits())
    return DAG.getNode(ISD::BIT_CONVERT, dl, ValueVT, Val);

  llvm_unreachable("Unknown mismatch!");
  return SDValue();
}

/// getCopyToParts - Create a series of nodes that contain the specified value
/// split into legal parts.  If the parts contain more bits than Val, then, for
/// integers, ExtendKind can be used to specify how to generate the extra bits.
static void getCopyToParts(SelectionDAG &DAG, DebugLoc dl, SDValue Val,
                           SDValue *Parts, unsigned NumParts, EVT PartVT,
                           ISD::NodeType ExtendKind = ISD::ANY_EXTEND) {
  const TargetLowering &TLI = DAG.getTargetLoweringInfo();
  EVT PtrVT = TLI.getPointerTy();
  EVT ValueVT = Val.getValueType();
  unsigned PartBits = PartVT.getSizeInBits();
  unsigned OrigNumParts = NumParts;
  assert(TLI.isTypeLegal(PartVT) && "Copying to an illegal type!");

  if (!NumParts)
    return;

  if (!ValueVT.isVector()) {
    if (PartVT == ValueVT) {
      assert(NumParts == 1 && "No-op copy with multiple parts!");
      Parts[0] = Val;
      return;
    }

    if (NumParts * PartBits > ValueVT.getSizeInBits()) {
      // If the parts cover more bits than the value has, promote the value.
      if (PartVT.isFloatingPoint() && ValueVT.isFloatingPoint()) {
        assert(NumParts == 1 && "Do not know what to promote to!");
        Val = DAG.getNode(ISD::FP_EXTEND, dl, PartVT, Val);
      } else if (PartVT.isInteger() && ValueVT.isInteger()) {
        ValueVT = EVT::getIntegerVT(*DAG.getContext(), NumParts * PartBits);
        Val = DAG.getNode(ExtendKind, dl, ValueVT, Val);
      } else {
        llvm_unreachable("Unknown mismatch!");
      }
    } else if (PartBits == ValueVT.getSizeInBits()) {
      // Different types of the same size.
      assert(NumParts == 1 && PartVT != ValueVT);
      Val = DAG.getNode(ISD::BIT_CONVERT, dl, PartVT, Val);
    } else if (NumParts * PartBits < ValueVT.getSizeInBits()) {
      // If the parts cover less bits than value has, truncate the value.
      if (PartVT.isInteger() && ValueVT.isInteger()) {
        ValueVT = EVT::getIntegerVT(*DAG.getContext(), NumParts * PartBits);
        Val = DAG.getNode(ISD::TRUNCATE, dl, ValueVT, Val);
      } else {
        llvm_unreachable("Unknown mismatch!");
      }
    }

    // The value may have changed - recompute ValueVT.
    ValueVT = Val.getValueType();
    assert(NumParts * PartBits == ValueVT.getSizeInBits() &&
           "Failed to tile the value with PartVT!");

    if (NumParts == 1) {
      assert(PartVT == ValueVT && "Type conversion failed!");
      Parts[0] = Val;
      return;
    }

    // Expand the value into multiple parts.
    if (NumParts & (NumParts - 1)) {
      // The number of parts is not a power of 2.  Split off and copy the tail.
      assert(PartVT.isInteger() && ValueVT.isInteger() &&
             "Do not know what to expand to!");
      unsigned RoundParts = 1 << Log2_32(NumParts);
      unsigned RoundBits = RoundParts * PartBits;
      unsigned OddParts = NumParts - RoundParts;
      SDValue OddVal = DAG.getNode(ISD::SRL, dl, ValueVT, Val,
                                   DAG.getConstant(RoundBits,
                                                   TLI.getPointerTy()));
      getCopyToParts(DAG, dl, OddVal, Parts + RoundParts, OddParts, PartVT);
      if (TLI.isBigEndian())
        // The odd parts were reversed by getCopyToParts - unreverse them.
        std::reverse(Parts + RoundParts, Parts + NumParts);
      NumParts = RoundParts;
      ValueVT = EVT::getIntegerVT(*DAG.getContext(), NumParts * PartBits);
      Val = DAG.getNode(ISD::TRUNCATE, dl, ValueVT, Val);
    }

    // The number of parts is a power of 2.  Repeatedly bisect the value using
    // EXTRACT_ELEMENT.
    Parts[0] = DAG.getNode(ISD::BIT_CONVERT, dl,
                           EVT::getIntegerVT(*DAG.getContext(), ValueVT.getSizeInBits()),
                           Val);
    for (unsigned StepSize = NumParts; StepSize > 1; StepSize /= 2) {
      for (unsigned i = 0; i < NumParts; i += StepSize) {
        unsigned ThisBits = StepSize * PartBits / 2;
        EVT ThisVT = EVT::getIntegerVT(*DAG.getContext(), ThisBits);
        SDValue &Part0 = Parts[i];
        SDValue &Part1 = Parts[i+StepSize/2];

        Part1 = DAG.getNode(ISD::EXTRACT_ELEMENT, dl,
                            ThisVT, Part0,
                            DAG.getConstant(1, PtrVT));
        Part0 = DAG.getNode(ISD::EXTRACT_ELEMENT, dl,
                            ThisVT, Part0,
                            DAG.getConstant(0, PtrVT));

        if (ThisBits == PartBits && ThisVT != PartVT) {
          Part0 = DAG.getNode(ISD::BIT_CONVERT, dl,
                                                PartVT, Part0);
          Part1 = DAG.getNode(ISD::BIT_CONVERT, dl,
                                                PartVT, Part1);
        }
      }
    }

    if (TLI.isBigEndian())
      std::reverse(Parts, Parts + OrigNumParts);

    return;
  }

  // Vector ValueVT.
  if (NumParts == 1) {
    if (PartVT != ValueVT) {
      if (PartVT.getSizeInBits() == ValueVT.getSizeInBits()) {
        Val = DAG.getNode(ISD::BIT_CONVERT, dl, PartVT, Val);
      } else {
        assert(ValueVT.getVectorElementType() == PartVT &&
               ValueVT.getVectorNumElements() == 1 &&
               "Only trivial vector-to-scalar conversions should get here!");
        Val = DAG.getNode(ISD::EXTRACT_VECTOR_ELT, dl,
                          PartVT, Val,
                          DAG.getConstant(0, PtrVT));
      }
    }

    Parts[0] = Val;
    return;
  }

  // Handle a multi-element vector.
  EVT IntermediateVT, RegisterVT;
  unsigned NumIntermediates;
  unsigned NumRegs = TLI.getVectorTypeBreakdown(*DAG.getContext(), ValueVT,
                              IntermediateVT, NumIntermediates, RegisterVT);
  unsigned NumElements = ValueVT.getVectorNumElements();

  assert(NumRegs == NumParts && "Part count doesn't match vector breakdown!");
  NumParts = NumRegs; // Silence a compiler warning.
  assert(RegisterVT == PartVT && "Part type doesn't match vector breakdown!");

  // Split the vector into intermediate operands.
  SmallVector<SDValue, 8> Ops(NumIntermediates);
  for (unsigned i = 0; i != NumIntermediates; ++i)
    if (IntermediateVT.isVector())
      Ops[i] = DAG.getNode(ISD::EXTRACT_SUBVECTOR, dl,
                           IntermediateVT, Val,
                           DAG.getConstant(i * (NumElements / NumIntermediates),
                                           PtrVT));
    else
      Ops[i] = DAG.getNode(ISD::EXTRACT_VECTOR_ELT, dl,
                           IntermediateVT, Val,
                           DAG.getConstant(i, PtrVT));

  // Split the intermediate operands into legal parts.
  if (NumParts == NumIntermediates) {
    // If the register was not expanded, promote or copy the value,
    // as appropriate.
    for (unsigned i = 0; i != NumParts; ++i)
      getCopyToParts(DAG, dl, Ops[i], &Parts[i], 1, PartVT);
  } else if (NumParts > 0) {
    // If the intermediate type was expanded, split each the value into
    // legal parts.
    assert(NumParts % NumIntermediates == 0 &&
           "Must expand into a divisible number of parts!");
    unsigned Factor = NumParts / NumIntermediates;
    for (unsigned i = 0; i != NumIntermediates; ++i)
      getCopyToParts(DAG, dl, Ops[i], &Parts[i * Factor], Factor, PartVT);
  }
}


void SelectionDAGBuilder::init(GCFunctionInfo *gfi, AliasAnalysis &aa) {
  AA = &aa;
  GFI = gfi;
  TD = DAG.getTarget().getTargetData();
}

/// clear - Clear out the curret SelectionDAG and the associated
/// state and prepare this SelectionDAGBuilder object to be used
/// for a new block. This doesn't clear out information about
/// additional blocks that are needed to complete switch lowering
/// or PHI node updating; that information is cleared out as it is
/// consumed.
void SelectionDAGBuilder::clear() {
  NodeMap.clear();
  PendingLoads.clear();
  PendingExports.clear();
  EdgeMapping.clear();
  DAG.clear();
  CurDebugLoc = DebugLoc::getUnknownLoc();
  HasTailCall = false;
}

/// getRoot - Return the current virtual root of the Selection DAG,
/// flushing any PendingLoad items. This must be done before emitting
/// a store or any other node that may need to be ordered after any
/// prior load instructions.
///
SDValue SelectionDAGBuilder::getRoot() {
  if (PendingLoads.empty())
    return DAG.getRoot();

  if (PendingLoads.size() == 1) {
    SDValue Root = PendingLoads[0];
    DAG.setRoot(Root);
    PendingLoads.clear();
    return Root;
  }

  // Otherwise, we have to make a token factor node.
  SDValue Root = DAG.getNode(ISD::TokenFactor, getCurDebugLoc(), MVT::Other,
                               &PendingLoads[0], PendingLoads.size());
  PendingLoads.clear();
  DAG.setRoot(Root);
  return Root;
}

/// getControlRoot - Similar to getRoot, but instead of flushing all the
/// PendingLoad items, flush all the PendingExports items. It is necessary
/// to do this before emitting a terminator instruction.
///
SDValue SelectionDAGBuilder::getControlRoot() {
  SDValue Root = DAG.getRoot();

  if (PendingExports.empty())
    return Root;

  // Turn all of the CopyToReg chains into one factored node.
  if (Root.getOpcode() != ISD::EntryToken) {
    unsigned i = 0, e = PendingExports.size();
    for (; i != e; ++i) {
      assert(PendingExports[i].getNode()->getNumOperands() > 1);
      if (PendingExports[i].getNode()->getOperand(0) == Root)
        break;  // Don't add the root if we already indirectly depend on it.
    }

    if (i == e)
      PendingExports.push_back(Root);
  }

  Root = DAG.getNode(ISD::TokenFactor, getCurDebugLoc(), MVT::Other,
                     &PendingExports[0],
                     PendingExports.size());
  PendingExports.clear();
  DAG.setRoot(Root);
  return Root;
}

void SelectionDAGBuilder::visit(Instruction &I) {
  visit(I.getOpcode(), I);
}

void SelectionDAGBuilder::visit(unsigned Opcode, User &I) {
  // We're processing a new instruction.
  ++SDNodeOrder;

  // Note: this doesn't use InstVisitor, because it has to work with
  // ConstantExpr's in addition to instructions.
  switch (Opcode) {
  default: llvm_unreachable("Unknown instruction type encountered!");
    // Build the switch statement using the Instruction.def file.
#define HANDLE_INST(NUM, OPCODE, CLASS) \
  case Instruction::OPCODE: return visit##OPCODE((CLASS&)I);
#include "llvm/Instruction.def"
  }
}

SDValue SelectionDAGBuilder::getValue(const Value *V) {
  SDValue &N = NodeMap[V];
  if (N.getNode()) return N;

  if (Constant *C = const_cast<Constant*>(dyn_cast<Constant>(V))) {
    EVT VT = TLI.getValueType(V->getType(), true);

    if (ConstantInt *CI = dyn_cast<ConstantInt>(C))
      return N = DAG.getConstant(*CI, VT);

    if (GlobalValue *GV = dyn_cast<GlobalValue>(C))
      return N = DAG.getGlobalAddress(GV, VT);

    if (isa<ConstantPointerNull>(C))
      return N = DAG.getConstant(0, TLI.getPointerTy());

    if (ConstantFP *CFP = dyn_cast<ConstantFP>(C))
      return N = DAG.getConstantFP(*CFP, VT);

    if (isa<UndefValue>(C) && !V->getType()->isAggregateType())
      return N = DAG.getUNDEF(VT);

    if (ConstantExpr *CE = dyn_cast<ConstantExpr>(C)) {
      visit(CE->getOpcode(), *CE);
      SDValue N1 = NodeMap[V];
      assert(N1.getNode() && "visit didn't populate the ValueMap!");
      return N1;
    }

    if (isa<ConstantStruct>(C) || isa<ConstantArray>(C)) {
      SmallVector<SDValue, 4> Constants;
      for (User::const_op_iterator OI = C->op_begin(), OE = C->op_end();
           OI != OE; ++OI) {
        SDNode *Val = getValue(*OI).getNode();
        // If the operand is an empty aggregate, there are no values.
        if (!Val) continue;
        // Add each leaf value from the operand to the Constants list
        // to form a flattened list of all the values.
        for (unsigned i = 0, e = Val->getNumValues(); i != e; ++i)
          Constants.push_back(SDValue(Val, i));
      }

      SDValue Res = DAG.getMergeValues(&Constants[0], Constants.size(),
                                       getCurDebugLoc());
      if (DisableScheduling)
        DAG.AssignOrdering(Res.getNode(), SDNodeOrder);
      return Res;
    }

    if (isa<StructType>(C->getType()) || isa<ArrayType>(C->getType())) {
      assert((isa<ConstantAggregateZero>(C) || isa<UndefValue>(C)) &&
             "Unknown struct or array constant!");

      SmallVector<EVT, 4> ValueVTs;
      ComputeValueVTs(TLI, C->getType(), ValueVTs);
      unsigned NumElts = ValueVTs.size();
      if (NumElts == 0)
        return SDValue(); // empty struct
      SmallVector<SDValue, 4> Constants(NumElts);
      for (unsigned i = 0; i != NumElts; ++i) {
        EVT EltVT = ValueVTs[i];
        if (isa<UndefValue>(C))
          Constants[i] = DAG.getUNDEF(EltVT);
        else if (EltVT.isFloatingPoint())
          Constants[i] = DAG.getConstantFP(0, EltVT);
        else
          Constants[i] = DAG.getConstant(0, EltVT);
      }

      SDValue Res = DAG.getMergeValues(&Constants[0], NumElts,
                                       getCurDebugLoc());
      if (DisableScheduling)
        DAG.AssignOrdering(Res.getNode(), SDNodeOrder);
      return Res;
    }

    if (BlockAddress *BA = dyn_cast<BlockAddress>(C))
      return DAG.getBlockAddress(BA, VT);

    const VectorType *VecTy = cast<VectorType>(V->getType());
    unsigned NumElements = VecTy->getNumElements();

    // Now that we know the number and type of the elements, get that number of
    // elements into the Ops array based on what kind of constant it is.
    SmallVector<SDValue, 16> Ops;
    if (ConstantVector *CP = dyn_cast<ConstantVector>(C)) {
      for (unsigned i = 0; i != NumElements; ++i)
        Ops.push_back(getValue(CP->getOperand(i)));
    } else {
      assert(isa<ConstantAggregateZero>(C) && "Unknown vector constant!");
      EVT EltVT = TLI.getValueType(VecTy->getElementType());

      SDValue Op;
      if (EltVT.isFloatingPoint())
        Op = DAG.getConstantFP(0, EltVT);
      else
        Op = DAG.getConstant(0, EltVT);
      Ops.assign(NumElements, Op);
    }

    // Create a BUILD_VECTOR node.
    SDValue Res = DAG.getNode(ISD::BUILD_VECTOR, getCurDebugLoc(),
                              VT, &Ops[0], Ops.size());
    if (DisableScheduling)
      DAG.AssignOrdering(Res.getNode(), SDNodeOrder);

    return NodeMap[V] = Res;
  }

  // If this is a static alloca, generate it as the frameindex instead of
  // computation.
  if (const AllocaInst *AI = dyn_cast<AllocaInst>(V)) {
    DenseMap<const AllocaInst*, int>::iterator SI =
      FuncInfo.StaticAllocaMap.find(AI);
    if (SI != FuncInfo.StaticAllocaMap.end())
      return DAG.getFrameIndex(SI->second, TLI.getPointerTy());
  }

  unsigned InReg = FuncInfo.ValueMap[V];
  assert(InReg && "Value not in map!");

  RegsForValue RFV(*DAG.getContext(), TLI, InReg, V->getType());
  SDValue Chain = DAG.getEntryNode();
  SDValue Res = RFV.getCopyFromRegs(DAG, getCurDebugLoc(), Chain, NULL);
  if (DisableScheduling)
    DAG.AssignOrdering(Res.getNode(), SDNodeOrder);
  return Res;
}

/// Get the EVTs and ArgFlags collections that represent the return type
/// of the given function.  This does not require a DAG or a return value, and
/// is suitable for use before any DAGs for the function are constructed.
static void getReturnInfo(const Type* ReturnType,
                   Attributes attr, SmallVectorImpl<EVT> &OutVTs,
                   SmallVectorImpl<ISD::ArgFlagsTy> &OutFlags,
                   TargetLowering &TLI,
                   SmallVectorImpl<uint64_t> *Offsets = 0) {
  SmallVector<EVT, 4> ValueVTs;
  ComputeValueVTs(TLI, ReturnType, ValueVTs, Offsets);
  unsigned NumValues = ValueVTs.size();
  if ( NumValues == 0 ) return;

  for (unsigned j = 0, f = NumValues; j != f; ++j) {
    EVT VT = ValueVTs[j];
    ISD::NodeType ExtendKind = ISD::ANY_EXTEND;

    if (attr & Attribute::SExt)
      ExtendKind = ISD::SIGN_EXTEND;
    else if (attr & Attribute::ZExt)
      ExtendKind = ISD::ZERO_EXTEND;

    // FIXME: C calling convention requires the return type to be promoted to
    // at least 32-bit. But this is not necessary for non-C calling
    // conventions. The frontend should mark functions whose return values
    // require promoting with signext or zeroext attributes.
    if (ExtendKind != ISD::ANY_EXTEND && VT.isInteger()) {
      EVT MinVT = TLI.getRegisterType(ReturnType->getContext(), MVT::i32);
      if (VT.bitsLT(MinVT))
        VT = MinVT;
    }

    unsigned NumParts = TLI.getNumRegisters(ReturnType->getContext(), VT);
    EVT PartVT = TLI.getRegisterType(ReturnType->getContext(), VT);
    // 'inreg' on function refers to return value
    ISD::ArgFlagsTy Flags = ISD::ArgFlagsTy();
    if (attr & Attribute::InReg)
      Flags.setInReg();

    // Propagate extension type if any
    if (attr & Attribute::SExt)
      Flags.setSExt();
    else if (attr & Attribute::ZExt)
      Flags.setZExt();

    for (unsigned i = 0; i < NumParts; ++i) {
      OutVTs.push_back(PartVT);
      OutFlags.push_back(Flags);
    }
  }
}

void SelectionDAGBuilder::visitRet(ReturnInst &I) {
  SDValue Chain = getControlRoot();
  SmallVector<ISD::OutputArg, 8> Outs;
  FunctionLoweringInfo &FLI = DAG.getFunctionLoweringInfo();
  
  if (!FLI.CanLowerReturn) {
    unsigned DemoteReg = FLI.DemoteRegister;
    const Function *F = I.getParent()->getParent();

    // Emit a store of the return value through the virtual register.
    // Leave Outs empty so that LowerReturn won't try to load return
    // registers the usual way.
    SmallVector<EVT, 1> PtrValueVTs;
    ComputeValueVTs(TLI, PointerType::getUnqual(F->getReturnType()), 
                    PtrValueVTs);

    SDValue RetPtr = DAG.getRegister(DemoteReg, PtrValueVTs[0]);
    SDValue RetOp = getValue(I.getOperand(0));
  
    SmallVector<EVT, 4> ValueVTs;
    SmallVector<uint64_t, 4> Offsets;
    ComputeValueVTs(TLI, I.getOperand(0)->getType(), ValueVTs, &Offsets);
    unsigned NumValues = ValueVTs.size();

    SmallVector<SDValue, 4> Chains(NumValues);
    EVT PtrVT = PtrValueVTs[0];
    for (unsigned i = 0; i != NumValues; ++i) {
      SDValue Add = DAG.getNode(ISD::ADD, getCurDebugLoc(), PtrVT, RetPtr,
                                DAG.getConstant(Offsets[i], PtrVT));
      Chains[i] =
        DAG.getStore(Chain, getCurDebugLoc(),
                     SDValue(RetOp.getNode(), RetOp.getResNo() + i),
                     Add, NULL, Offsets[i], false, 0);

      if (DisableScheduling) {
        DAG.AssignOrdering(Add.getNode(), SDNodeOrder);
        DAG.AssignOrdering(Chains[i].getNode(), SDNodeOrder);
      }
    }

    Chain = DAG.getNode(ISD::TokenFactor, getCurDebugLoc(),
                        MVT::Other, &Chains[0], NumValues);

    if (DisableScheduling)
      DAG.AssignOrdering(Chain.getNode(), SDNodeOrder);
  } else {
    for (unsigned i = 0, e = I.getNumOperands(); i != e; ++i) {
      SmallVector<EVT, 4> ValueVTs;
      ComputeValueVTs(TLI, I.getOperand(i)->getType(), ValueVTs);
      unsigned NumValues = ValueVTs.size();
      if (NumValues == 0) continue;
  
      SDValue RetOp = getValue(I.getOperand(i));
      for (unsigned j = 0, f = NumValues; j != f; ++j) {
        EVT VT = ValueVTs[j];

        ISD::NodeType ExtendKind = ISD::ANY_EXTEND;

        const Function *F = I.getParent()->getParent();
        if (F->paramHasAttr(0, Attribute::SExt))
          ExtendKind = ISD::SIGN_EXTEND;
        else if (F->paramHasAttr(0, Attribute::ZExt))
          ExtendKind = ISD::ZERO_EXTEND;

        // FIXME: C calling convention requires the return type to be promoted to
        // at least 32-bit. But this is not necessary for non-C calling
        // conventions. The frontend should mark functions whose return values
        // require promoting with signext or zeroext attributes.
        if (ExtendKind != ISD::ANY_EXTEND && VT.isInteger()) {
          EVT MinVT = TLI.getRegisterType(*DAG.getContext(), MVT::i32);
          if (VT.bitsLT(MinVT))
            VT = MinVT;
        }

        unsigned NumParts = TLI.getNumRegisters(*DAG.getContext(), VT);
        EVT PartVT = TLI.getRegisterType(*DAG.getContext(), VT);
        SmallVector<SDValue, 4> Parts(NumParts);
        getCopyToParts(DAG, getCurDebugLoc(),
                       SDValue(RetOp.getNode(), RetOp.getResNo() + j),
                       &Parts[0], NumParts, PartVT, ExtendKind);

        // 'inreg' on function refers to return value
        ISD::ArgFlagsTy Flags = ISD::ArgFlagsTy();
        if (F->paramHasAttr(0, Attribute::InReg))
          Flags.setInReg();

        // Propagate extension type if any
        if (F->paramHasAttr(0, Attribute::SExt))
          Flags.setSExt();
        else if (F->paramHasAttr(0, Attribute::ZExt))
          Flags.setZExt();

        for (unsigned i = 0; i < NumParts; ++i)
          Outs.push_back(ISD::OutputArg(Flags, Parts[i], /*isfixed=*/true));
      }
    }
  }

  bool isVarArg = DAG.getMachineFunction().getFunction()->isVarArg();
  CallingConv::ID CallConv =
    DAG.getMachineFunction().getFunction()->getCallingConv();
  Chain = TLI.LowerReturn(Chain, CallConv, isVarArg,
                          Outs, getCurDebugLoc(), DAG);

  // Verify that the target's LowerReturn behaved as expected.
  assert(Chain.getNode() && Chain.getValueType() == MVT::Other &&
         "LowerReturn didn't return a valid chain!");

  // Update the DAG with the new chain value resulting from return lowering.
  DAG.setRoot(Chain);

  if (DisableScheduling)
    DAG.AssignOrdering(Chain.getNode(), SDNodeOrder);
}

/// CopyToExportRegsIfNeeded - If the given value has virtual registers
/// created for it, emit nodes to copy the value into the virtual
/// registers.
void SelectionDAGBuilder::CopyToExportRegsIfNeeded(Value *V) {
  if (!V->use_empty()) {
    DenseMap<const Value *, unsigned>::iterator VMI = FuncInfo.ValueMap.find(V);
    if (VMI != FuncInfo.ValueMap.end())
      CopyValueToVirtualRegister(V, VMI->second);
  }
}

/// ExportFromCurrentBlock - If this condition isn't known to be exported from
/// the current basic block, add it to ValueMap now so that we'll get a
/// CopyTo/FromReg.
void SelectionDAGBuilder::ExportFromCurrentBlock(Value *V) {
  // No need to export constants.
  if (!isa<Instruction>(V) && !isa<Argument>(V)) return;

  // Already exported?
  if (FuncInfo.isExportedInst(V)) return;

  unsigned Reg = FuncInfo.InitializeRegForValue(V);
  CopyValueToVirtualRegister(V, Reg);
}

bool SelectionDAGBuilder::isExportableFromCurrentBlock(Value *V,
                                                     const BasicBlock *FromBB) {
  // The operands of the setcc have to be in this block.  We don't know
  // how to export them from some other block.
  if (Instruction *VI = dyn_cast<Instruction>(V)) {
    // Can export from current BB.
    if (VI->getParent() == FromBB)
      return true;

    // Is already exported, noop.
    return FuncInfo.isExportedInst(V);
  }

  // If this is an argument, we can export it if the BB is the entry block or
  // if it is already exported.
  if (isa<Argument>(V)) {
    if (FromBB == &FromBB->getParent()->getEntryBlock())
      return true;

    // Otherwise, can only export this if it is already exported.
    return FuncInfo.isExportedInst(V);
  }

  // Otherwise, constants can always be exported.
  return true;
}

static bool InBlock(const Value *V, const BasicBlock *BB) {
  if (const Instruction *I = dyn_cast<Instruction>(V))
    return I->getParent() == BB;
  return true;
}

/// getFCmpCondCode - Return the ISD condition code corresponding to
/// the given LLVM IR floating-point condition code.  This includes
/// consideration of global floating-point math flags.
///
static ISD::CondCode getFCmpCondCode(FCmpInst::Predicate Pred) {
  ISD::CondCode FPC, FOC;
  switch (Pred) {
  case FCmpInst::FCMP_FALSE: FOC = FPC = ISD::SETFALSE; break;
  case FCmpInst::FCMP_OEQ:   FOC = ISD::SETEQ; FPC = ISD::SETOEQ; break;
  case FCmpInst::FCMP_OGT:   FOC = ISD::SETGT; FPC = ISD::SETOGT; break;
  case FCmpInst::FCMP_OGE:   FOC = ISD::SETGE; FPC = ISD::SETOGE; break;
  case FCmpInst::FCMP_OLT:   FOC = ISD::SETLT; FPC = ISD::SETOLT; break;
  case FCmpInst::FCMP_OLE:   FOC = ISD::SETLE; FPC = ISD::SETOLE; break;
  case FCmpInst::FCMP_ONE:   FOC = ISD::SETNE; FPC = ISD::SETONE; break;
  case FCmpInst::FCMP_ORD:   FOC = FPC = ISD::SETO;   break;
  case FCmpInst::FCMP_UNO:   FOC = FPC = ISD::SETUO;  break;
  case FCmpInst::FCMP_UEQ:   FOC = ISD::SETEQ; FPC = ISD::SETUEQ; break;
  case FCmpInst::FCMP_UGT:   FOC = ISD::SETGT; FPC = ISD::SETUGT; break;
  case FCmpInst::FCMP_UGE:   FOC = ISD::SETGE; FPC = ISD::SETUGE; break;
  case FCmpInst::FCMP_ULT:   FOC = ISD::SETLT; FPC = ISD::SETULT; break;
  case FCmpInst::FCMP_ULE:   FOC = ISD::SETLE; FPC = ISD::SETULE; break;
  case FCmpInst::FCMP_UNE:   FOC = ISD::SETNE; FPC = ISD::SETUNE; break;
  case FCmpInst::FCMP_TRUE:  FOC = FPC = ISD::SETTRUE; break;
  default:
    llvm_unreachable("Invalid FCmp predicate opcode!");
    FOC = FPC = ISD::SETFALSE;
    break;
  }
  if (FiniteOnlyFPMath())
    return FOC;
  else
    return FPC;
}

/// getICmpCondCode - Return the ISD condition code corresponding to
/// the given LLVM IR integer condition code.
///
static ISD::CondCode getICmpCondCode(ICmpInst::Predicate Pred) {
  switch (Pred) {
  case ICmpInst::ICMP_EQ:  return ISD::SETEQ;
  case ICmpInst::ICMP_NE:  return ISD::SETNE;
  case ICmpInst::ICMP_SLE: return ISD::SETLE;
  case ICmpInst::ICMP_ULE: return ISD::SETULE;
  case ICmpInst::ICMP_SGE: return ISD::SETGE;
  case ICmpInst::ICMP_UGE: return ISD::SETUGE;
  case ICmpInst::ICMP_SLT: return ISD::SETLT;
  case ICmpInst::ICMP_ULT: return ISD::SETULT;
  case ICmpInst::ICMP_SGT: return ISD::SETGT;
  case ICmpInst::ICMP_UGT: return ISD::SETUGT;
  default:
    llvm_unreachable("Invalid ICmp predicate opcode!");
    return ISD::SETNE;
  }
}

/// EmitBranchForMergedCondition - Helper method for FindMergedConditions.
/// This function emits a branch and is used at the leaves of an OR or an
/// AND operator tree.
///
void
SelectionDAGBuilder::EmitBranchForMergedCondition(Value *Cond,
                                                  MachineBasicBlock *TBB,
                                                  MachineBasicBlock *FBB,
                                                  MachineBasicBlock *CurBB) {
  const BasicBlock *BB = CurBB->getBasicBlock();

  // If the leaf of the tree is a comparison, merge the condition into
  // the caseblock.
  if (CmpInst *BOp = dyn_cast<CmpInst>(Cond)) {
    // The operands of the cmp have to be in this block.  We don't know
    // how to export them from some other block.  If this is the first block
    // of the sequence, no exporting is needed.
    if (CurBB == CurMBB ||
        (isExportableFromCurrentBlock(BOp->getOperand(0), BB) &&
         isExportableFromCurrentBlock(BOp->getOperand(1), BB))) {
      ISD::CondCode Condition;
      if (ICmpInst *IC = dyn_cast<ICmpInst>(Cond)) {
        Condition = getICmpCondCode(IC->getPredicate());
      } else if (FCmpInst *FC = dyn_cast<FCmpInst>(Cond)) {
        Condition = getFCmpCondCode(FC->getPredicate());
      } else {
        Condition = ISD::SETEQ; // silence warning.
        llvm_unreachable("Unknown compare instruction");
      }

      CaseBlock CB(Condition, BOp->getOperand(0),
                   BOp->getOperand(1), NULL, TBB, FBB, CurBB);
      SwitchCases.push_back(CB);
      return;
    }
  }

  // Create a CaseBlock record representing this branch.
  CaseBlock CB(ISD::SETEQ, Cond, ConstantInt::getTrue(*DAG.getContext()),
               NULL, TBB, FBB, CurBB);
  SwitchCases.push_back(CB);
}

/// FindMergedConditions - If Cond is an expression like
void SelectionDAGBuilder::FindMergedConditions(Value *Cond,
                                               MachineBasicBlock *TBB,
                                               MachineBasicBlock *FBB,
                                               MachineBasicBlock *CurBB,
                                               unsigned Opc) {
  // If this node is not part of the or/and tree, emit it as a branch.
  Instruction *BOp = dyn_cast<Instruction>(Cond);
  if (!BOp || !(isa<BinaryOperator>(BOp) || isa<CmpInst>(BOp)) ||
      (unsigned)BOp->getOpcode() != Opc || !BOp->hasOneUse() ||
      BOp->getParent() != CurBB->getBasicBlock() ||
      !InBlock(BOp->getOperand(0), CurBB->getBasicBlock()) ||
      !InBlock(BOp->getOperand(1), CurBB->getBasicBlock())) {
    EmitBranchForMergedCondition(Cond, TBB, FBB, CurBB);
    return;
  }

  //  Create TmpBB after CurBB.
  MachineFunction::iterator BBI = CurBB;
  MachineFunction &MF = DAG.getMachineFunction();
  MachineBasicBlock *TmpBB = MF.CreateMachineBasicBlock(CurBB->getBasicBlock());
  CurBB->getParent()->insert(++BBI, TmpBB);

  if (Opc == Instruction::Or) {
    // Codegen X | Y as:
    //   jmp_if_X TBB
    //   jmp TmpBB
    // TmpBB:
    //   jmp_if_Y TBB
    //   jmp FBB
    //

    // Emit the LHS condition.
    FindMergedConditions(BOp->getOperand(0), TBB, TmpBB, CurBB, Opc);

    // Emit the RHS condition into TmpBB.
    FindMergedConditions(BOp->getOperand(1), TBB, FBB, TmpBB, Opc);
  } else {
    assert(Opc == Instruction::And && "Unknown merge op!");
    // Codegen X & Y as:
    //   jmp_if_X TmpBB
    //   jmp FBB
    // TmpBB:
    //   jmp_if_Y TBB
    //   jmp FBB
    //
    //  This requires creation of TmpBB after CurBB.

    // Emit the LHS condition.
    FindMergedConditions(BOp->getOperand(0), TmpBB, FBB, CurBB, Opc);

    // Emit the RHS condition into TmpBB.
    FindMergedConditions(BOp->getOperand(1), TBB, FBB, TmpBB, Opc);
  }
}

/// If the set of cases should be emitted as a series of branches, return true.
/// If we should emit this as a bunch of and/or'd together conditions, return
/// false.
bool
SelectionDAGBuilder::ShouldEmitAsBranches(const std::vector<CaseBlock> &Cases){
  if (Cases.size() != 2) return true;

  // If this is two comparisons of the same values or'd or and'd together, they
  // will get folded into a single comparison, so don't emit two blocks.
  if ((Cases[0].CmpLHS == Cases[1].CmpLHS &&
       Cases[0].CmpRHS == Cases[1].CmpRHS) ||
      (Cases[0].CmpRHS == Cases[1].CmpLHS &&
       Cases[0].CmpLHS == Cases[1].CmpRHS)) {
    return false;
  }

  return true;
}

void SelectionDAGBuilder::visitBr(BranchInst &I) {
  // Update machine-CFG edges.
  MachineBasicBlock *Succ0MBB = FuncInfo.MBBMap[I.getSuccessor(0)];

  // Figure out which block is immediately after the current one.
  MachineBasicBlock *NextBlock = 0;
  MachineFunction::iterator BBI = CurMBB;
  if (++BBI != FuncInfo.MF->end())
    NextBlock = BBI;

  if (I.isUnconditional()) {
    // Update machine-CFG edges.
    CurMBB->addSuccessor(Succ0MBB);

    // If this is not a fall-through branch, emit the branch.
    if (Succ0MBB != NextBlock) {
      SDValue V = DAG.getNode(ISD::BR, getCurDebugLoc(),
                              MVT::Other, getControlRoot(),
                              DAG.getBasicBlock(Succ0MBB));
      DAG.setRoot(V);

      if (DisableScheduling)
        DAG.AssignOrdering(V.getNode(), SDNodeOrder);
    }

    return;
  }

  // If this condition is one of the special cases we handle, do special stuff
  // now.
  Value *CondVal = I.getCondition();
  MachineBasicBlock *Succ1MBB = FuncInfo.MBBMap[I.getSuccessor(1)];

  // If this is a series of conditions that are or'd or and'd together, emit
  // this as a sequence of branches instead of setcc's with and/or operations.
  // For example, instead of something like:
  //     cmp A, B
  //     C = seteq
  //     cmp D, E
  //     F = setle
  //     or C, F
  //     jnz foo
  // Emit:
  //     cmp A, B
  //     je foo
  //     cmp D, E
  //     jle foo
  //
  if (BinaryOperator *BOp = dyn_cast<BinaryOperator>(CondVal)) {
    if (BOp->hasOneUse() &&
        (BOp->getOpcode() == Instruction::And ||
         BOp->getOpcode() == Instruction::Or)) {
      FindMergedConditions(BOp, Succ0MBB, Succ1MBB, CurMBB, BOp->getOpcode());
      // If the compares in later blocks need to use values not currently
      // exported from this block, export them now.  This block should always
      // be the first entry.
      assert(SwitchCases[0].ThisBB == CurMBB && "Unexpected lowering!");

      // Allow some cases to be rejected.
      if (ShouldEmitAsBranches(SwitchCases)) {
        for (unsigned i = 1, e = SwitchCases.size(); i != e; ++i) {
          ExportFromCurrentBlock(SwitchCases[i].CmpLHS);
          ExportFromCurrentBlock(SwitchCases[i].CmpRHS);
        }

        // Emit the branch for this block.
        visitSwitchCase(SwitchCases[0]);
        SwitchCases.erase(SwitchCases.begin());
        return;
      }

      // Okay, we decided not to do this, remove any inserted MBB's and clear
      // SwitchCases.
      for (unsigned i = 1, e = SwitchCases.size(); i != e; ++i)
        FuncInfo.MF->erase(SwitchCases[i].ThisBB);

      SwitchCases.clear();
    }
  }

  // Create a CaseBlock record representing this branch.
  CaseBlock CB(ISD::SETEQ, CondVal, ConstantInt::getTrue(*DAG.getContext()),
               NULL, Succ0MBB, Succ1MBB, CurMBB);

  // Use visitSwitchCase to actually insert the fast branch sequence for this
  // cond branch.
  visitSwitchCase(CB);
}

/// visitSwitchCase - Emits the necessary code to represent a single node in
/// the binary search tree resulting from lowering a switch instruction.
void SelectionDAGBuilder::visitSwitchCase(CaseBlock &CB) {
  SDValue Cond;
  SDValue CondLHS = getValue(CB.CmpLHS);
  DebugLoc dl = getCurDebugLoc();

  // Build the setcc now.
  if (CB.CmpMHS == NULL) {
    // Fold "(X == true)" to X and "(X == false)" to !X to
    // handle common cases produced by branch lowering.
    if (CB.CmpRHS == ConstantInt::getTrue(*DAG.getContext()) &&
        CB.CC == ISD::SETEQ)
      Cond = CondLHS;
    else if (CB.CmpRHS == ConstantInt::getFalse(*DAG.getContext()) &&
             CB.CC == ISD::SETEQ) {
      SDValue True = DAG.getConstant(1, CondLHS.getValueType());
      Cond = DAG.getNode(ISD::XOR, dl, CondLHS.getValueType(), CondLHS, True);
    } else
      Cond = DAG.getSetCC(dl, MVT::i1, CondLHS, getValue(CB.CmpRHS), CB.CC);
  } else {
    assert(CB.CC == ISD::SETLE && "Can handle only LE ranges now");

    const APInt& Low = cast<ConstantInt>(CB.CmpLHS)->getValue();
    const APInt& High  = cast<ConstantInt>(CB.CmpRHS)->getValue();

    SDValue CmpOp = getValue(CB.CmpMHS);
    EVT VT = CmpOp.getValueType();

    if (cast<ConstantInt>(CB.CmpLHS)->isMinValue(true)) {
      Cond = DAG.getSetCC(dl, MVT::i1, CmpOp, DAG.getConstant(High, VT),
                          ISD::SETLE);
    } else {
      SDValue SUB = DAG.getNode(ISD::SUB, dl,
                                VT, CmpOp, DAG.getConstant(Low, VT));
      Cond = DAG.getSetCC(dl, MVT::i1, SUB,
                          DAG.getConstant(High-Low, VT), ISD::SETULE);
    }
  }

  if (DisableScheduling)
    DAG.AssignOrdering(Cond.getNode(), SDNodeOrder);

  // Update successor info
  CurMBB->addSuccessor(CB.TrueBB);
  CurMBB->addSuccessor(CB.FalseBB);

  // Set NextBlock to be the MBB immediately after the current one, if any.
  // This is used to avoid emitting unnecessary branches to the next block.
  MachineBasicBlock *NextBlock = 0;
  MachineFunction::iterator BBI = CurMBB;
  if (++BBI != FuncInfo.MF->end())
    NextBlock = BBI;

  // If the lhs block is the next block, invert the condition so that we can
  // fall through to the lhs instead of the rhs block.
  if (CB.TrueBB == NextBlock) {
    std::swap(CB.TrueBB, CB.FalseBB);
    SDValue True = DAG.getConstant(1, Cond.getValueType());
    Cond = DAG.getNode(ISD::XOR, dl, Cond.getValueType(), Cond, True);

    if (DisableScheduling)
      DAG.AssignOrdering(Cond.getNode(), SDNodeOrder);
  }

  SDValue BrCond = DAG.getNode(ISD::BRCOND, dl,
                               MVT::Other, getControlRoot(), Cond,
                               DAG.getBasicBlock(CB.TrueBB));

  if (DisableScheduling)
    DAG.AssignOrdering(BrCond.getNode(), SDNodeOrder);

  // If the branch was constant folded, fix up the CFG.
  if (BrCond.getOpcode() == ISD::BR) {
    CurMBB->removeSuccessor(CB.FalseBB);
  } else {
    // Otherwise, go ahead and insert the false branch.
    if (BrCond == getControlRoot())
      CurMBB->removeSuccessor(CB.TrueBB);

    if (CB.FalseBB != NextBlock) {
      BrCond = DAG.getNode(ISD::BR, dl, MVT::Other, BrCond,
                           DAG.getBasicBlock(CB.FalseBB));

      if (DisableScheduling)
        DAG.AssignOrdering(BrCond.getNode(), SDNodeOrder);
    }
  }

  DAG.setRoot(BrCond);
}

/// visitJumpTable - Emit JumpTable node in the current MBB
void SelectionDAGBuilder::visitJumpTable(JumpTable &JT) {
  // Emit the code for the jump table
  assert(JT.Reg != -1U && "Should lower JT Header first!");
  EVT PTy = TLI.getPointerTy();
  SDValue Index = DAG.getCopyFromReg(getControlRoot(), getCurDebugLoc(),
                                     JT.Reg, PTy);
  SDValue Table = DAG.getJumpTable(JT.JTI, PTy);
  SDValue BrJumpTable = DAG.getNode(ISD::BR_JT, getCurDebugLoc(),
                                    MVT::Other, Index.getValue(1),
                                    Table, Index);
  DAG.setRoot(BrJumpTable);

  if (DisableScheduling) {
    DAG.AssignOrdering(Index.getNode(), SDNodeOrder);
    DAG.AssignOrdering(Table.getNode(), SDNodeOrder);
    DAG.AssignOrdering(BrJumpTable.getNode(), SDNodeOrder);
  }
}

/// visitJumpTableHeader - This function emits necessary code to produce index
/// in the JumpTable from switch case.
void SelectionDAGBuilder::visitJumpTableHeader(JumpTable &JT,
                                               JumpTableHeader &JTH) {
  // Subtract the lowest switch case value from the value being switched on and
  // conditional branch to default mbb if the result is greater than the
  // difference between smallest and largest cases.
  SDValue SwitchOp = getValue(JTH.SValue);
  EVT VT = SwitchOp.getValueType();
  SDValue Sub = DAG.getNode(ISD::SUB, getCurDebugLoc(), VT, SwitchOp,
                            DAG.getConstant(JTH.First, VT));

  // The SDNode we just created, which holds the value being switched on minus
  // the the smallest case value, needs to be copied to a virtual register so it
  // can be used as an index into the jump table in a subsequent basic block.
  // This value may be smaller or larger than the target's pointer type, and
  // therefore require extension or truncating.
  SwitchOp = DAG.getZExtOrTrunc(Sub, getCurDebugLoc(), TLI.getPointerTy());

  unsigned JumpTableReg = FuncInfo.MakeReg(TLI.getPointerTy());
  SDValue CopyTo = DAG.getCopyToReg(getControlRoot(), getCurDebugLoc(),
                                    JumpTableReg, SwitchOp);
  JT.Reg = JumpTableReg;

  // Emit the range check for the jump table, and branch to the default block
  // for the switch statement if the value being switched on exceeds the largest
  // case in the switch.
  SDValue CMP = DAG.getSetCC(getCurDebugLoc(),
                             TLI.getSetCCResultType(Sub.getValueType()), Sub,
                             DAG.getConstant(JTH.Last-JTH.First,VT),
                             ISD::SETUGT);

  if (DisableScheduling) {
    DAG.AssignOrdering(Sub.getNode(), SDNodeOrder);
    DAG.AssignOrdering(SwitchOp.getNode(), SDNodeOrder);
    DAG.AssignOrdering(CopyTo.getNode(), SDNodeOrder);
    DAG.AssignOrdering(CMP.getNode(), SDNodeOrder);
  }

  // Set NextBlock to be the MBB immediately after the current one, if any.
  // This is used to avoid emitting unnecessary branches to the next block.
  MachineBasicBlock *NextBlock = 0;
  MachineFunction::iterator BBI = CurMBB;

  if (++BBI != FuncInfo.MF->end())
    NextBlock = BBI;

  SDValue BrCond = DAG.getNode(ISD::BRCOND, getCurDebugLoc(),
                               MVT::Other, CopyTo, CMP,
                               DAG.getBasicBlock(JT.Default));

  if (DisableScheduling)
    DAG.AssignOrdering(BrCond.getNode(), SDNodeOrder);

  if (JT.MBB != NextBlock) {
    BrCond = DAG.getNode(ISD::BR, getCurDebugLoc(), MVT::Other, BrCond,
                         DAG.getBasicBlock(JT.MBB));

    if (DisableScheduling)
      DAG.AssignOrdering(BrCond.getNode(), SDNodeOrder);
  }

  DAG.setRoot(BrCond);
}

/// visitBitTestHeader - This function emits necessary code to produce value
/// suitable for "bit tests"
void SelectionDAGBuilder::visitBitTestHeader(BitTestBlock &B) {
  // Subtract the minimum value
  SDValue SwitchOp = getValue(B.SValue);
  EVT VT = SwitchOp.getValueType();
  SDValue Sub = DAG.getNode(ISD::SUB, getCurDebugLoc(), VT, SwitchOp,
                            DAG.getConstant(B.First, VT));

  // Check range
  SDValue RangeCmp = DAG.getSetCC(getCurDebugLoc(),
                                  TLI.getSetCCResultType(Sub.getValueType()),
                                  Sub, DAG.getConstant(B.Range, VT),
                                  ISD::SETUGT);

  SDValue ShiftOp = DAG.getZExtOrTrunc(Sub, getCurDebugLoc(),
                                       TLI.getPointerTy());

  B.Reg = FuncInfo.MakeReg(TLI.getPointerTy());
  SDValue CopyTo = DAG.getCopyToReg(getControlRoot(), getCurDebugLoc(),
                                    B.Reg, ShiftOp);

  if (DisableScheduling) {
    DAG.AssignOrdering(Sub.getNode(), SDNodeOrder);
    DAG.AssignOrdering(RangeCmp.getNode(), SDNodeOrder);
    DAG.AssignOrdering(ShiftOp.getNode(), SDNodeOrder);
    DAG.AssignOrdering(CopyTo.getNode(), SDNodeOrder);
  }

  // Set NextBlock to be the MBB immediately after the current one, if any.
  // This is used to avoid emitting unnecessary branches to the next block.
  MachineBasicBlock *NextBlock = 0;
  MachineFunction::iterator BBI = CurMBB;
  if (++BBI != FuncInfo.MF->end())
    NextBlock = BBI;

  MachineBasicBlock* MBB = B.Cases[0].ThisBB;

  CurMBB->addSuccessor(B.Default);
  CurMBB->addSuccessor(MBB);

  SDValue BrRange = DAG.getNode(ISD::BRCOND, getCurDebugLoc(),
                                MVT::Other, CopyTo, RangeCmp,
                                DAG.getBasicBlock(B.Default));

  if (DisableScheduling)
    DAG.AssignOrdering(BrRange.getNode(), SDNodeOrder);

  if (MBB != NextBlock) {
    BrRange = DAG.getNode(ISD::BR, getCurDebugLoc(), MVT::Other, CopyTo,
                          DAG.getBasicBlock(MBB));

    if (DisableScheduling)
      DAG.AssignOrdering(BrRange.getNode(), SDNodeOrder);
  }

  DAG.setRoot(BrRange);
}

/// visitBitTestCase - this function produces one "bit test"
void SelectionDAGBuilder::visitBitTestCase(MachineBasicBlock* NextMBB,
                                           unsigned Reg,
                                           BitTestCase &B) {
  // Make desired shift
  SDValue ShiftOp = DAG.getCopyFromReg(getControlRoot(), getCurDebugLoc(), Reg,
                                       TLI.getPointerTy());
  SDValue SwitchVal = DAG.getNode(ISD::SHL, getCurDebugLoc(),
                                  TLI.getPointerTy(),
                                  DAG.getConstant(1, TLI.getPointerTy()),
                                  ShiftOp);

  // Emit bit tests and jumps
  SDValue AndOp = DAG.getNode(ISD::AND, getCurDebugLoc(),
                              TLI.getPointerTy(), SwitchVal,
                              DAG.getConstant(B.Mask, TLI.getPointerTy()));
  SDValue AndCmp = DAG.getSetCC(getCurDebugLoc(),
                                TLI.getSetCCResultType(AndOp.getValueType()),
                                AndOp, DAG.getConstant(0, TLI.getPointerTy()),
                                ISD::SETNE);

  if (DisableScheduling) {
    DAG.AssignOrdering(ShiftOp.getNode(), SDNodeOrder);
    DAG.AssignOrdering(SwitchVal.getNode(), SDNodeOrder);
    DAG.AssignOrdering(AndOp.getNode(), SDNodeOrder);
    DAG.AssignOrdering(AndCmp.getNode(), SDNodeOrder);
  }

  CurMBB->addSuccessor(B.TargetBB);
  CurMBB->addSuccessor(NextMBB);

  SDValue BrAnd = DAG.getNode(ISD::BRCOND, getCurDebugLoc(),
                              MVT::Other, getControlRoot(),
                              AndCmp, DAG.getBasicBlock(B.TargetBB));

  if (DisableScheduling)
    DAG.AssignOrdering(BrAnd.getNode(), SDNodeOrder);

  // Set NextBlock to be the MBB immediately after the current one, if any.
  // This is used to avoid emitting unnecessary branches to the next block.
  MachineBasicBlock *NextBlock = 0;
  MachineFunction::iterator BBI = CurMBB;
  if (++BBI != FuncInfo.MF->end())
    NextBlock = BBI;

  if (NextMBB != NextBlock) {
    BrAnd = DAG.getNode(ISD::BR, getCurDebugLoc(), MVT::Other, BrAnd,
                        DAG.getBasicBlock(NextMBB));

    if (DisableScheduling)
      DAG.AssignOrdering(BrAnd.getNode(), SDNodeOrder);
  }

  DAG.setRoot(BrAnd);
}

void SelectionDAGBuilder::visitInvoke(InvokeInst &I) {
  // Retrieve successors.
  MachineBasicBlock *Return = FuncInfo.MBBMap[I.getSuccessor(0)];
  MachineBasicBlock *LandingPad = FuncInfo.MBBMap[I.getSuccessor(1)];

  const Value *Callee(I.getCalledValue());
  if (isa<InlineAsm>(Callee))
    visitInlineAsm(&I);
  else
    LowerCallTo(&I, getValue(Callee), false, LandingPad);

  // If the value of the invoke is used outside of its defining block, make it
  // available as a virtual register.
  CopyToExportRegsIfNeeded(&I);

  // Update successor info
  CurMBB->addSuccessor(Return);
  CurMBB->addSuccessor(LandingPad);

  // Drop into normal successor.
  SDValue Branch = DAG.getNode(ISD::BR, getCurDebugLoc(),
                               MVT::Other, getControlRoot(),
                               DAG.getBasicBlock(Return));
  DAG.setRoot(Branch);

  if (DisableScheduling)
    DAG.AssignOrdering(Branch.getNode(), SDNodeOrder);
}

void SelectionDAGBuilder::visitUnwind(UnwindInst &I) {
}

/// handleSmallSwitchCaseRange - Emit a series of specific tests (suitable for
/// small case ranges).
bool SelectionDAGBuilder::handleSmallSwitchRange(CaseRec& CR,
                                                 CaseRecVector& WorkList,
                                                 Value* SV,
                                                 MachineBasicBlock* Default) {
  Case& BackCase  = *(CR.Range.second-1);

  // Size is the number of Cases represented by this range.
  size_t Size = CR.Range.second - CR.Range.first;
  if (Size > 3)
    return false;

  // Get the MachineFunction which holds the current MBB.  This is used when
  // inserting any additional MBBs necessary to represent the switch.
  MachineFunction *CurMF = FuncInfo.MF;

  // Figure out which block is immediately after the current one.
  MachineBasicBlock *NextBlock = 0;
  MachineFunction::iterator BBI = CR.CaseBB;

  if (++BBI != FuncInfo.MF->end())
    NextBlock = BBI;

  // TODO: If any two of the cases has the same destination, and if one value
  // is the same as the other, but has one bit unset that the other has set,
  // use bit manipulation to do two compares at once.  For example:
  // "if (X == 6 || X == 4)" -> "if ((X|2) == 6)"

  // Rearrange the case blocks so that the last one falls through if possible.
  if (NextBlock && Default != NextBlock && BackCase.BB != NextBlock) {
    // The last case block won't fall through into 'NextBlock' if we emit the
    // branches in this order.  See if rearranging a case value would help.
    for (CaseItr I = CR.Range.first, E = CR.Range.second-1; I != E; ++I) {
      if (I->BB == NextBlock) {
        std::swap(*I, BackCase);
        break;
      }
    }
  }

  // Create a CaseBlock record representing a conditional branch to
  // the Case's target mbb if the value being switched on SV is equal
  // to C.
  MachineBasicBlock *CurBlock = CR.CaseBB;
  for (CaseItr I = CR.Range.first, E = CR.Range.second; I != E; ++I) {
    MachineBasicBlock *FallThrough;
    if (I != E-1) {
      FallThrough = CurMF->CreateMachineBasicBlock(CurBlock->getBasicBlock());
      CurMF->insert(BBI, FallThrough);

      // Put SV in a virtual register to make it available from the new blocks.
      ExportFromCurrentBlock(SV);
    } else {
      // If the last case doesn't match, go to the default block.
      FallThrough = Default;
    }

    Value *RHS, *LHS, *MHS;
    ISD::CondCode CC;
    if (I->High == I->Low) {
      // This is just small small case range :) containing exactly 1 case
      CC = ISD::SETEQ;
      LHS = SV; RHS = I->High; MHS = NULL;
    } else {
      CC = ISD::SETLE;
      LHS = I->Low; MHS = SV; RHS = I->High;
    }
    CaseBlock CB(CC, LHS, RHS, MHS, I->BB, FallThrough, CurBlock);

    // If emitting the first comparison, just call visitSwitchCase to emit the
    // code into the current block.  Otherwise, push the CaseBlock onto the
    // vector to be later processed by SDISel, and insert the node's MBB
    // before the next MBB.
    if (CurBlock == CurMBB)
      visitSwitchCase(CB);
    else
      SwitchCases.push_back(CB);

    CurBlock = FallThrough;
  }

  return true;
}

static inline bool areJTsAllowed(const TargetLowering &TLI) {
  return !DisableJumpTables &&
          (TLI.isOperationLegalOrCustom(ISD::BR_JT, MVT::Other) ||
           TLI.isOperationLegalOrCustom(ISD::BRIND, MVT::Other));
}

static APInt ComputeRange(const APInt &First, const APInt &Last) {
  APInt LastExt(Last), FirstExt(First);
  uint32_t BitWidth = std::max(Last.getBitWidth(), First.getBitWidth()) + 1;
  LastExt.sext(BitWidth); FirstExt.sext(BitWidth);
  return (LastExt - FirstExt + 1ULL);
}

/// handleJTSwitchCase - Emit jumptable for current switch case range
bool SelectionDAGBuilder::handleJTSwitchCase(CaseRec& CR,
                                             CaseRecVector& WorkList,
                                             Value* SV,
                                             MachineBasicBlock* Default) {
  Case& FrontCase = *CR.Range.first;
  Case& BackCase  = *(CR.Range.second-1);

  const APInt &First = cast<ConstantInt>(FrontCase.Low)->getValue();
  const APInt &Last  = cast<ConstantInt>(BackCase.High)->getValue();

  APInt TSize(First.getBitWidth(), 0);
  for (CaseItr I = CR.Range.first, E = CR.Range.second;
       I!=E; ++I)
    TSize += I->size();

  if (!areJTsAllowed(TLI) || TSize.ult(APInt(First.getBitWidth(), 4)))
    return false;

  APInt Range = ComputeRange(First, Last);
  double Density = TSize.roundToDouble() / Range.roundToDouble();
  if (Density < 0.4)
    return false;

  DEBUG(errs() << "Lowering jump table\n"
               << "First entry: " << First << ". Last entry: " << Last << '\n'
               << "Range: " << Range
               << "Size: " << TSize << ". Density: " << Density << "\n\n");

  // Get the MachineFunction which holds the current MBB.  This is used when
  // inserting any additional MBBs necessary to represent the switch.
  MachineFunction *CurMF = FuncInfo.MF;

  // Figure out which block is immediately after the current one.
  MachineFunction::iterator BBI = CR.CaseBB;
  ++BBI;

  const BasicBlock *LLVMBB = CR.CaseBB->getBasicBlock();

  // Create a new basic block to hold the code for loading the address
  // of the jump table, and jumping to it.  Update successor information;
  // we will either branch to the default case for the switch, or the jump
  // table.
  MachineBasicBlock *JumpTableBB = CurMF->CreateMachineBasicBlock(LLVMBB);
  CurMF->insert(BBI, JumpTableBB);
  CR.CaseBB->addSuccessor(Default);
  CR.CaseBB->addSuccessor(JumpTableBB);

  // Build a vector of destination BBs, corresponding to each target
  // of the jump table. If the value of the jump table slot corresponds to
  // a case statement, push the case's BB onto the vector, otherwise, push
  // the default BB.
  std::vector<MachineBasicBlock*> DestBBs;
  APInt TEI = First;
  for (CaseItr I = CR.Range.first, E = CR.Range.second; I != E; ++TEI) {
    const APInt& Low = cast<ConstantInt>(I->Low)->getValue();
    const APInt& High = cast<ConstantInt>(I->High)->getValue();

    if (Low.sle(TEI) && TEI.sle(High)) {
      DestBBs.push_back(I->BB);
      if (TEI==High)
        ++I;
    } else {
      DestBBs.push_back(Default);
    }
  }

  // Update successor info. Add one edge to each unique successor.
  BitVector SuccsHandled(CR.CaseBB->getParent()->getNumBlockIDs());
  for (std::vector<MachineBasicBlock*>::iterator I = DestBBs.begin(),
         E = DestBBs.end(); I != E; ++I) {
    if (!SuccsHandled[(*I)->getNumber()]) {
      SuccsHandled[(*I)->getNumber()] = true;
      JumpTableBB->addSuccessor(*I);
    }
  }

  // Create a jump table index for this jump table, or return an existing
  // one.
  unsigned JTI = CurMF->getJumpTableInfo()->getJumpTableIndex(DestBBs);

  // Set the jump table information so that we can codegen it as a second
  // MachineBasicBlock
  JumpTable JT(-1U, JTI, JumpTableBB, Default);
  JumpTableHeader JTH(First, Last, SV, CR.CaseBB, (CR.CaseBB == CurMBB));
  if (CR.CaseBB == CurMBB)
    visitJumpTableHeader(JT, JTH);

  JTCases.push_back(JumpTableBlock(JTH, JT));

  return true;
}

/// handleBTSplitSwitchCase - emit comparison and split binary search tree into
/// 2 subtrees.
bool SelectionDAGBuilder::handleBTSplitSwitchCase(CaseRec& CR,
                                                  CaseRecVector& WorkList,
                                                  Value* SV,
                                                  MachineBasicBlock* Default) {
  // Get the MachineFunction which holds the current MBB.  This is used when
  // inserting any additional MBBs necessary to represent the switch.
  MachineFunction *CurMF = FuncInfo.MF;

  // Figure out which block is immediately after the current one.
  MachineFunction::iterator BBI = CR.CaseBB;
  ++BBI;

  Case& FrontCase = *CR.Range.first;
  Case& BackCase  = *(CR.Range.second-1);
  const BasicBlock *LLVMBB = CR.CaseBB->getBasicBlock();

  // Size is the number of Cases represented by this range.
  unsigned Size = CR.Range.second - CR.Range.first;

  const APInt &First = cast<ConstantInt>(FrontCase.Low)->getValue();
  const APInt &Last  = cast<ConstantInt>(BackCase.High)->getValue();
  double FMetric = 0;
  CaseItr Pivot = CR.Range.first + Size/2;

  // Select optimal pivot, maximizing sum density of LHS and RHS. This will
  // (heuristically) allow us to emit JumpTable's later.
  APInt TSize(First.getBitWidth(), 0);
  for (CaseItr I = CR.Range.first, E = CR.Range.second;
       I!=E; ++I)
    TSize += I->size();

  APInt LSize = FrontCase.size();
  APInt RSize = TSize-LSize;
  DEBUG(errs() << "Selecting best pivot: \n"
               << "First: " << First << ", Last: " << Last <<'\n'
               << "LSize: " << LSize << ", RSize: " << RSize << '\n');
  for (CaseItr I = CR.Range.first, J=I+1, E = CR.Range.second;
       J!=E; ++I, ++J) {
    const APInt &LEnd = cast<ConstantInt>(I->High)->getValue();
    const APInt &RBegin = cast<ConstantInt>(J->Low)->getValue();
    APInt Range = ComputeRange(LEnd, RBegin);
    assert((Range - 2ULL).isNonNegative() &&
           "Invalid case distance");
    double LDensity = (double)LSize.roundToDouble() / 
                           (LEnd - First + 1ULL).roundToDouble();
    double RDensity = (double)RSize.roundToDouble() /
                           (Last - RBegin + 1ULL).roundToDouble();
    double Metric = Range.logBase2()*(LDensity+RDensity);
    // Should always split in some non-trivial place
    DEBUG(errs() <<"=>Step\n"
                 << "LEnd: " << LEnd << ", RBegin: " << RBegin << '\n'
                 << "LDensity: " << LDensity
                 << ", RDensity: " << RDensity << '\n'
                 << "Metric: " << Metric << '\n');
    if (FMetric < Metric) {
      Pivot = J;
      FMetric = Metric;
      DEBUG(errs() << "Current metric set to: " << FMetric << '\n');
    }

    LSize += J->size();
    RSize -= J->size();
  }
  if (areJTsAllowed(TLI)) {
    // If our case is dense we *really* should handle it earlier!
    assert((FMetric > 0) && "Should handle dense range earlier!");
  } else {
    Pivot = CR.Range.first + Size/2;
  }

  CaseRange LHSR(CR.Range.first, Pivot);
  CaseRange RHSR(Pivot, CR.Range.second);
  Constant *C = Pivot->Low;
  MachineBasicBlock *FalseBB = 0, *TrueBB = 0;

  // We know that we branch to the LHS if the Value being switched on is
  // less than the Pivot value, C.  We use this to optimize our binary
  // tree a bit, by recognizing that if SV is greater than or equal to the
  // LHS's Case Value, and that Case Value is exactly one less than the
  // Pivot's Value, then we can branch directly to the LHS's Target,
  // rather than creating a leaf node for it.
  if ((LHSR.second - LHSR.first) == 1 &&
      LHSR.first->High == CR.GE &&
      cast<ConstantInt>(C)->getValue() ==
      (cast<ConstantInt>(CR.GE)->getValue() + 1LL)) {
    TrueBB = LHSR.first->BB;
  } else {
    TrueBB = CurMF->CreateMachineBasicBlock(LLVMBB);
    CurMF->insert(BBI, TrueBB);
    WorkList.push_back(CaseRec(TrueBB, C, CR.GE, LHSR));

    // Put SV in a virtual register to make it available from the new blocks.
    ExportFromCurrentBlock(SV);
  }

  // Similar to the optimization above, if the Value being switched on is
  // known to be less than the Constant CR.LT, and the current Case Value
  // is CR.LT - 1, then we can branch directly to the target block for
  // the current Case Value, rather than emitting a RHS leaf node for it.
  if ((RHSR.second - RHSR.first) == 1 && CR.LT &&
      cast<ConstantInt>(RHSR.first->Low)->getValue() ==
      (cast<ConstantInt>(CR.LT)->getValue() - 1LL)) {
    FalseBB = RHSR.first->BB;
  } else {
    FalseBB = CurMF->CreateMachineBasicBlock(LLVMBB);
    CurMF->insert(BBI, FalseBB);
    WorkList.push_back(CaseRec(FalseBB,CR.LT,C,RHSR));

    // Put SV in a virtual register to make it available from the new blocks.
    ExportFromCurrentBlock(SV);
  }

  // Create a CaseBlock record representing a conditional branch to
  // the LHS node if the value being switched on SV is less than C.
  // Otherwise, branch to LHS.
  CaseBlock CB(ISD::SETLT, SV, C, NULL, TrueBB, FalseBB, CR.CaseBB);

  if (CR.CaseBB == CurMBB)
    visitSwitchCase(CB);
  else
    SwitchCases.push_back(CB);

  return true;
}

/// handleBitTestsSwitchCase - if current case range has few destination and
/// range span less, than machine word bitwidth, encode case range into series
/// of masks and emit bit tests with these masks.
bool SelectionDAGBuilder::handleBitTestsSwitchCase(CaseRec& CR,
                                                   CaseRecVector& WorkList,
                                                   Value* SV,
                                                   MachineBasicBlock* Default){
  EVT PTy = TLI.getPointerTy();
  unsigned IntPtrBits = PTy.getSizeInBits();

  Case& FrontCase = *CR.Range.first;
  Case& BackCase  = *(CR.Range.second-1);

  // Get the MachineFunction which holds the current MBB.  This is used when
  // inserting any additional MBBs necessary to represent the switch.
  MachineFunction *CurMF = FuncInfo.MF;

  // If target does not have legal shift left, do not emit bit tests at all.
  if (!TLI.isOperationLegal(ISD::SHL, TLI.getPointerTy()))
    return false;

  size_t numCmps = 0;
  for (CaseItr I = CR.Range.first, E = CR.Range.second;
       I!=E; ++I) {
    // Single case counts one, case range - two.
    numCmps += (I->Low == I->High ? 1 : 2);
  }

  // Count unique destinations
  SmallSet<MachineBasicBlock*, 4> Dests;
  for (CaseItr I = CR.Range.first, E = CR.Range.second; I!=E; ++I) {
    Dests.insert(I->BB);
    if (Dests.size() > 3)
      // Don't bother the code below, if there are too much unique destinations
      return false;
  }
  DEBUG(errs() << "Total number of unique destinations: " << Dests.size() << '\n'
               << "Total number of comparisons: " << numCmps << '\n');

  // Compute span of values.
  const APInt& minValue = cast<ConstantInt>(FrontCase.Low)->getValue();
  const APInt& maxValue = cast<ConstantInt>(BackCase.High)->getValue();
  APInt cmpRange = maxValue - minValue;

  DEBUG(errs() << "Compare range: " << cmpRange << '\n'
               << "Low bound: " << minValue << '\n'
               << "High bound: " << maxValue << '\n');

  if (cmpRange.uge(APInt(cmpRange.getBitWidth(), IntPtrBits)) ||
      (!(Dests.size() == 1 && numCmps >= 3) &&
       !(Dests.size() == 2 && numCmps >= 5) &&
       !(Dests.size() >= 3 && numCmps >= 6)))
    return false;

  DEBUG(errs() << "Emitting bit tests\n");
  APInt lowBound = APInt::getNullValue(cmpRange.getBitWidth());

  // Optimize the case where all the case values fit in a
  // word without having to subtract minValue. In this case,
  // we can optimize away the subtraction.
  if (minValue.isNonNegative() &&
      maxValue.slt(APInt(maxValue.getBitWidth(), IntPtrBits))) {
    cmpRange = maxValue;
  } else {
    lowBound = minValue;
  }

  CaseBitsVector CasesBits;
  unsigned i, count = 0;

  for (CaseItr I = CR.Range.first, E = CR.Range.second; I!=E; ++I) {
    MachineBasicBlock* Dest = I->BB;
    for (i = 0; i < count; ++i)
      if (Dest == CasesBits[i].BB)
        break;

    if (i == count) {
      assert((count < 3) && "Too much destinations to test!");
      CasesBits.push_back(CaseBits(0, Dest, 0));
      count++;
    }

    const APInt& lowValue = cast<ConstantInt>(I->Low)->getValue();
    const APInt& highValue = cast<ConstantInt>(I->High)->getValue();

    uint64_t lo = (lowValue - lowBound).getZExtValue();
    uint64_t hi = (highValue - lowBound).getZExtValue();

    for (uint64_t j = lo; j <= hi; j++) {
      CasesBits[i].Mask |=  1ULL << j;
      CasesBits[i].Bits++;
    }

  }
  std::sort(CasesBits.begin(), CasesBits.end(), CaseBitsCmp());

  BitTestInfo BTC;

  // Figure out which block is immediately after the current one.
  MachineFunction::iterator BBI = CR.CaseBB;
  ++BBI;

  const BasicBlock *LLVMBB = CR.CaseBB->getBasicBlock();

  DEBUG(errs() << "Cases:\n");
  for (unsigned i = 0, e = CasesBits.size(); i!=e; ++i) {
    DEBUG(errs() << "Mask: " << CasesBits[i].Mask
                 << ", Bits: " << CasesBits[i].Bits
                 << ", BB: " << CasesBits[i].BB << '\n');

    MachineBasicBlock *CaseBB = CurMF->CreateMachineBasicBlock(LLVMBB);
    CurMF->insert(BBI, CaseBB);
    BTC.push_back(BitTestCase(CasesBits[i].Mask,
                              CaseBB,
                              CasesBits[i].BB));

    // Put SV in a virtual register to make it available from the new blocks.
    ExportFromCurrentBlock(SV);
  }

  BitTestBlock BTB(lowBound, cmpRange, SV,
                   -1U, (CR.CaseBB == CurMBB),
                   CR.CaseBB, Default, BTC);

  if (CR.CaseBB == CurMBB)
    visitBitTestHeader(BTB);

  BitTestCases.push_back(BTB);

  return true;
}

/// Clusterify - Transform simple list of Cases into list of CaseRange's
size_t SelectionDAGBuilder::Clusterify(CaseVector& Cases,
                                       const SwitchInst& SI) {
  size_t numCmps = 0;

  // Start with "simple" cases
  for (size_t i = 1; i < SI.getNumSuccessors(); ++i) {
    MachineBasicBlock *SMBB = FuncInfo.MBBMap[SI.getSuccessor(i)];
    Cases.push_back(Case(SI.getSuccessorValue(i),
                         SI.getSuccessorValue(i),
                         SMBB));
  }
  std::sort(Cases.begin(), Cases.end(), CaseCmp());

  // Merge case into clusters
  if (Cases.size() >= 2)
    // Must recompute end() each iteration because it may be
    // invalidated by erase if we hold on to it
    for (CaseItr I = Cases.begin(), J = ++(Cases.begin()); J != Cases.end(); ) {
      const APInt& nextValue = cast<ConstantInt>(J->Low)->getValue();
      const APInt& currentValue = cast<ConstantInt>(I->High)->getValue();
      MachineBasicBlock* nextBB = J->BB;
      MachineBasicBlock* currentBB = I->BB;

      // If the two neighboring cases go to the same destination, merge them
      // into a single case.
      if ((nextValue - currentValue == 1) && (currentBB == nextBB)) {
        I->High = J->High;
        J = Cases.erase(J);
      } else {
        I = J++;
      }
    }

  for (CaseItr I=Cases.begin(), E=Cases.end(); I!=E; ++I, ++numCmps) {
    if (I->Low != I->High)
      // A range counts double, since it requires two compares.
      ++numCmps;
  }

  return numCmps;
}

void SelectionDAGBuilder::visitSwitch(SwitchInst &SI) {
  // Figure out which block is immediately after the current one.
  MachineBasicBlock *NextBlock = 0;
  MachineBasicBlock *Default = FuncInfo.MBBMap[SI.getDefaultDest()];

  // If there is only the default destination, branch to it if it is not the
  // next basic block.  Otherwise, just fall through.
  if (SI.getNumOperands() == 2) {
    // Update machine-CFG edges.

    // If this is not a fall-through branch, emit the branch.
    CurMBB->addSuccessor(Default);
    if (Default != NextBlock) {
      SDValue Res = DAG.getNode(ISD::BR, getCurDebugLoc(),
                                MVT::Other, getControlRoot(),
                                DAG.getBasicBlock(Default));
      DAG.setRoot(Res);

      if (DisableScheduling)
        DAG.AssignOrdering(Res.getNode(), SDNodeOrder);
    }

    return;
  }

  // If there are any non-default case statements, create a vector of Cases
  // representing each one, and sort the vector so that we can efficiently
  // create a binary search tree from them.
  CaseVector Cases;
  size_t numCmps = Clusterify(Cases, SI);
  DEBUG(errs() << "Clusterify finished. Total clusters: " << Cases.size()
               << ". Total compares: " << numCmps << '\n');
  numCmps = 0;

  // Get the Value to be switched on and default basic blocks, which will be
  // inserted into CaseBlock records, representing basic blocks in the binary
  // search tree.
  Value *SV = SI.getOperand(0);

  // Push the initial CaseRec onto the worklist
  CaseRecVector WorkList;
  WorkList.push_back(CaseRec(CurMBB,0,0,CaseRange(Cases.begin(),Cases.end())));

  while (!WorkList.empty()) {
    // Grab a record representing a case range to process off the worklist
    CaseRec CR = WorkList.back();
    WorkList.pop_back();

    if (handleBitTestsSwitchCase(CR, WorkList, SV, Default))
      continue;

    // If the range has few cases (two or less) emit a series of specific
    // tests.
    if (handleSmallSwitchRange(CR, WorkList, SV, Default))
      continue;

    // If the switch has more than 5 blocks, and at least 40% dense, and the
    // target supports indirect branches, then emit a jump table rather than
    // lowering the switch to a binary tree of conditional branches.
    if (handleJTSwitchCase(CR, WorkList, SV, Default))
      continue;

    // Emit binary tree. We need to pick a pivot, and push left and right ranges
    // onto the worklist. Leafs are handled via handleSmallSwitchRange() call.
    handleBTSplitSwitchCase(CR, WorkList, SV, Default);
  }
}

void SelectionDAGBuilder::visitIndirectBr(IndirectBrInst &I) {
  // Update machine-CFG edges.
  for (unsigned i = 0, e = I.getNumSuccessors(); i != e; ++i)
    CurMBB->addSuccessor(FuncInfo.MBBMap[I.getSuccessor(i)]);

  SDValue Res = DAG.getNode(ISD::BRIND, getCurDebugLoc(),
                            MVT::Other, getControlRoot(),
                            getValue(I.getAddress()));
  DAG.setRoot(Res);

  if (DisableScheduling)
    DAG.AssignOrdering(Res.getNode(), SDNodeOrder);
}

void SelectionDAGBuilder::visitFSub(User &I) {
  // -0.0 - X --> fneg
  const Type *Ty = I.getType();
  if (isa<VectorType>(Ty)) {
    if (ConstantVector *CV = dyn_cast<ConstantVector>(I.getOperand(0))) {
      const VectorType *DestTy = cast<VectorType>(I.getType());
      const Type *ElTy = DestTy->getElementType();
      unsigned VL = DestTy->getNumElements();
      std::vector<Constant*> NZ(VL, ConstantFP::getNegativeZero(ElTy));
      Constant *CNZ = ConstantVector::get(&NZ[0], NZ.size());
      if (CV == CNZ) {
        SDValue Op2 = getValue(I.getOperand(1));
        SDValue Res = DAG.getNode(ISD::FNEG, getCurDebugLoc(),
                                  Op2.getValueType(), Op2); 
        setValue(&I, Res);

        if (DisableScheduling)
          DAG.AssignOrdering(Res.getNode(), SDNodeOrder);

        return;
      }
    }
  }

  if (ConstantFP *CFP = dyn_cast<ConstantFP>(I.getOperand(0)))
    if (CFP->isExactlyValue(ConstantFP::getNegativeZero(Ty)->getValueAPF())) {
      SDValue Op2 = getValue(I.getOperand(1));
      SDValue Res = DAG.getNode(ISD::FNEG, getCurDebugLoc(),
                                Op2.getValueType(), Op2);
      setValue(&I, Res);

      if (DisableScheduling)
        DAG.AssignOrdering(Res.getNode(), SDNodeOrder);

      return;
    }

  visitBinary(I, ISD::FSUB);
}

void SelectionDAGBuilder::visitBinary(User &I, unsigned OpCode) {
  SDValue Op1 = getValue(I.getOperand(0));
  SDValue Op2 = getValue(I.getOperand(1));
  SDValue Res = DAG.getNode(OpCode, getCurDebugLoc(),
                            Op1.getValueType(), Op1, Op2);
  setValue(&I, Res);

  if (DisableScheduling)
    DAG.AssignOrdering(Res.getNode(), SDNodeOrder);
}

void SelectionDAGBuilder::visitShift(User &I, unsigned Opcode) {
  SDValue Op1 = getValue(I.getOperand(0));
  SDValue Op2 = getValue(I.getOperand(1));
  if (!isa<VectorType>(I.getType()) &&
      Op2.getValueType() != TLI.getShiftAmountTy()) {
    // If the operand is smaller than the shift count type, promote it.
    EVT PTy = TLI.getPointerTy();
    EVT STy = TLI.getShiftAmountTy();
    if (STy.bitsGT(Op2.getValueType()))
      Op2 = DAG.getNode(ISD::ANY_EXTEND, getCurDebugLoc(),
                        TLI.getShiftAmountTy(), Op2);
    // If the operand is larger than the shift count type but the shift
    // count type has enough bits to represent any shift value, truncate
    // it now. This is a common case and it exposes the truncate to
    // optimization early.
    else if (STy.getSizeInBits() >=
             Log2_32_Ceil(Op2.getValueType().getSizeInBits()))
      Op2 = DAG.getNode(ISD::TRUNCATE, getCurDebugLoc(),
                        TLI.getShiftAmountTy(), Op2);
    // Otherwise we'll need to temporarily settle for some other
    // convenient type; type legalization will make adjustments as
    // needed.
    else if (PTy.bitsLT(Op2.getValueType()))
      Op2 = DAG.getNode(ISD::TRUNCATE, getCurDebugLoc(),
                        TLI.getPointerTy(), Op2);
    else if (PTy.bitsGT(Op2.getValueType()))
      Op2 = DAG.getNode(ISD::ANY_EXTEND, getCurDebugLoc(),
                        TLI.getPointerTy(), Op2);
  }

  SDValue Res = DAG.getNode(Opcode, getCurDebugLoc(),
                            Op1.getValueType(), Op1, Op2);
  setValue(&I, Res);

  if (DisableScheduling) {
    DAG.AssignOrdering(Op1.getNode(), SDNodeOrder);
    DAG.AssignOrdering(Op2.getNode(), SDNodeOrder);
    DAG.AssignOrdering(Res.getNode(), SDNodeOrder);
  }
}

void SelectionDAGBuilder::visitICmp(User &I) {
  ICmpInst::Predicate predicate = ICmpInst::BAD_ICMP_PREDICATE;
  if (ICmpInst *IC = dyn_cast<ICmpInst>(&I))
    predicate = IC->getPredicate();
  else if (ConstantExpr *IC = dyn_cast<ConstantExpr>(&I))
    predicate = ICmpInst::Predicate(IC->getPredicate());
  SDValue Op1 = getValue(I.getOperand(0));
  SDValue Op2 = getValue(I.getOperand(1));
  ISD::CondCode Opcode = getICmpCondCode(predicate);
  
  EVT DestVT = TLI.getValueType(I.getType());
  SDValue Res = DAG.getSetCC(getCurDebugLoc(), DestVT, Op1, Op2, Opcode);
  setValue(&I, Res);

  if (DisableScheduling)
    DAG.AssignOrdering(Res.getNode(), SDNodeOrder);
}

void SelectionDAGBuilder::visitFCmp(User &I) {
  FCmpInst::Predicate predicate = FCmpInst::BAD_FCMP_PREDICATE;
  if (FCmpInst *FC = dyn_cast<FCmpInst>(&I))
    predicate = FC->getPredicate();
  else if (ConstantExpr *FC = dyn_cast<ConstantExpr>(&I))
    predicate = FCmpInst::Predicate(FC->getPredicate());
  SDValue Op1 = getValue(I.getOperand(0));
  SDValue Op2 = getValue(I.getOperand(1));
  ISD::CondCode Condition = getFCmpCondCode(predicate);
  EVT DestVT = TLI.getValueType(I.getType());
  SDValue Res = DAG.getSetCC(getCurDebugLoc(), DestVT, Op1, Op2, Condition);
  setValue(&I, Res);

  if (DisableScheduling)
    DAG.AssignOrdering(Res.getNode(), SDNodeOrder);
}

void SelectionDAGBuilder::visitSelect(User &I) {
  SmallVector<EVT, 4> ValueVTs;
  ComputeValueVTs(TLI, I.getType(), ValueVTs);
  unsigned NumValues = ValueVTs.size();
  if (NumValues == 0) return;

  SmallVector<SDValue, 4> Values(NumValues);
  SDValue Cond     = getValue(I.getOperand(0));
  SDValue TrueVal  = getValue(I.getOperand(1));
  SDValue FalseVal = getValue(I.getOperand(2));

  for (unsigned i = 0; i != NumValues; ++i) {
    Values[i] = DAG.getNode(ISD::SELECT, getCurDebugLoc(),
                            TrueVal.getNode()->getValueType(i), Cond,
                            SDValue(TrueVal.getNode(),
                                    TrueVal.getResNo() + i),
                            SDValue(FalseVal.getNode(),
                                    FalseVal.getResNo() + i));

    if (DisableScheduling)
      DAG.AssignOrdering(Values[i].getNode(), SDNodeOrder);
  }

  SDValue Res = DAG.getNode(ISD::MERGE_VALUES, getCurDebugLoc(),
                            DAG.getVTList(&ValueVTs[0], NumValues),
                            &Values[0], NumValues);
  setValue(&I, Res);

  if (DisableScheduling)
    DAG.AssignOrdering(Res.getNode(), SDNodeOrder);
}

void SelectionDAGBuilder::visitTrunc(User &I) {
  // TruncInst cannot be a no-op cast because sizeof(src) > sizeof(dest).
  SDValue N = getValue(I.getOperand(0));
  EVT DestVT = TLI.getValueType(I.getType());
  SDValue Res = DAG.getNode(ISD::TRUNCATE, getCurDebugLoc(), DestVT, N);
  setValue(&I, Res);

  if (DisableScheduling)
    DAG.AssignOrdering(Res.getNode(), SDNodeOrder);
}

void SelectionDAGBuilder::visitZExt(User &I) {
  // ZExt cannot be a no-op cast because sizeof(src) < sizeof(dest).
  // ZExt also can't be a cast to bool for same reason. So, nothing much to do
  SDValue N = getValue(I.getOperand(0));
  EVT DestVT = TLI.getValueType(I.getType());
  SDValue Res = DAG.getNode(ISD::ZERO_EXTEND, getCurDebugLoc(), DestVT, N);
  setValue(&I, Res);

  if (DisableScheduling)
    DAG.AssignOrdering(Res.getNode(), SDNodeOrder);
}

void SelectionDAGBuilder::visitSExt(User &I) {
  // SExt cannot be a no-op cast because sizeof(src) < sizeof(dest).
  // SExt also can't be a cast to bool for same reason. So, nothing much to do
  SDValue N = getValue(I.getOperand(0));
  EVT DestVT = TLI.getValueType(I.getType());
  SDValue Res = DAG.getNode(ISD::SIGN_EXTEND, getCurDebugLoc(), DestVT, N);
  setValue(&I, Res);

  if (DisableScheduling)
    DAG.AssignOrdering(Res.getNode(), SDNodeOrder);
}

void SelectionDAGBuilder::visitFPTrunc(User &I) {
  // FPTrunc is never a no-op cast, no need to check
  SDValue N = getValue(I.getOperand(0));
  EVT DestVT = TLI.getValueType(I.getType());
  SDValue Res = DAG.getNode(ISD::FP_ROUND, getCurDebugLoc(),
                            DestVT, N, DAG.getIntPtrConstant(0));
  setValue(&I, Res);

  if (DisableScheduling)
    DAG.AssignOrdering(Res.getNode(), SDNodeOrder);
}

void SelectionDAGBuilder::visitFPExt(User &I){
  // FPTrunc is never a no-op cast, no need to check
  SDValue N = getValue(I.getOperand(0));
  EVT DestVT = TLI.getValueType(I.getType());
  SDValue Res = DAG.getNode(ISD::FP_EXTEND, getCurDebugLoc(), DestVT, N);
  setValue(&I, Res);

  if (DisableScheduling)
    DAG.AssignOrdering(Res.getNode(), SDNodeOrder);
}

void SelectionDAGBuilder::visitFPToUI(User &I) {
  // FPToUI is never a no-op cast, no need to check
  SDValue N = getValue(I.getOperand(0));
  EVT DestVT = TLI.getValueType(I.getType());
  SDValue Res = DAG.getNode(ISD::FP_TO_UINT, getCurDebugLoc(), DestVT, N);
  setValue(&I, Res);

  if (DisableScheduling)
    DAG.AssignOrdering(Res.getNode(), SDNodeOrder);
}

void SelectionDAGBuilder::visitFPToSI(User &I) {
  // FPToSI is never a no-op cast, no need to check
  SDValue N = getValue(I.getOperand(0));
  EVT DestVT = TLI.getValueType(I.getType());
  SDValue Res = DAG.getNode(ISD::FP_TO_SINT, getCurDebugLoc(), DestVT, N);
  setValue(&I, Res);

  if (DisableScheduling)
    DAG.AssignOrdering(Res.getNode(), SDNodeOrder);
}

void SelectionDAGBuilder::visitUIToFP(User &I) {
  // UIToFP is never a no-op cast, no need to check
  SDValue N = getValue(I.getOperand(0));
  EVT DestVT = TLI.getValueType(I.getType());
  SDValue Res = DAG.getNode(ISD::UINT_TO_FP, getCurDebugLoc(), DestVT, N);
  setValue(&I, Res);

  if (DisableScheduling)
    DAG.AssignOrdering(Res.getNode(), SDNodeOrder);
}

void SelectionDAGBuilder::visitSIToFP(User &I){
  // SIToFP is never a no-op cast, no need to check
  SDValue N = getValue(I.getOperand(0));
  EVT DestVT = TLI.getValueType(I.getType());
  SDValue Res = DAG.getNode(ISD::SINT_TO_FP, getCurDebugLoc(), DestVT, N);
  setValue(&I, Res);

  if (DisableScheduling)
    DAG.AssignOrdering(Res.getNode(), SDNodeOrder);
}

void SelectionDAGBuilder::visitPtrToInt(User &I) {
  // What to do depends on the size of the integer and the size of the pointer.
  // We can either truncate, zero extend, or no-op, accordingly.
  SDValue N = getValue(I.getOperand(0));
  EVT SrcVT = N.getValueType();
  EVT DestVT = TLI.getValueType(I.getType());
  SDValue Res = DAG.getZExtOrTrunc(N, getCurDebugLoc(), DestVT);
  setValue(&I, Res);

  if (DisableScheduling)
    DAG.AssignOrdering(Res.getNode(), SDNodeOrder);
}

void SelectionDAGBuilder::visitIntToPtr(User &I) {
  // What to do depends on the size of the integer and the size of the pointer.
  // We can either truncate, zero extend, or no-op, accordingly.
  SDValue N = getValue(I.getOperand(0));
  EVT SrcVT = N.getValueType();
  EVT DestVT = TLI.getValueType(I.getType());
  SDValue Res = DAG.getZExtOrTrunc(N, getCurDebugLoc(), DestVT);
  setValue(&I, Res);

  if (DisableScheduling)
    DAG.AssignOrdering(Res.getNode(), SDNodeOrder);
}

void SelectionDAGBuilder::visitBitCast(User &I) {
  SDValue N = getValue(I.getOperand(0));
  EVT DestVT = TLI.getValueType(I.getType());

  // BitCast assures us that source and destination are the same size so this is
  // either a BIT_CONVERT or a no-op.
  if (DestVT != N.getValueType()) {
    SDValue Res = DAG.getNode(ISD::BIT_CONVERT, getCurDebugLoc(),
                              DestVT, N); // convert types.
    setValue(&I, Res);

    if (DisableScheduling)
      DAG.AssignOrdering(Res.getNode(), SDNodeOrder);
  } else {
    setValue(&I, N);            // noop cast.
  }
}

void SelectionDAGBuilder::visitInsertElement(User &I) {
  SDValue InVec = getValue(I.getOperand(0));
  SDValue InVal = getValue(I.getOperand(1));
  SDValue InIdx = DAG.getNode(ISD::ZERO_EXTEND, getCurDebugLoc(),
                              TLI.getPointerTy(),
                              getValue(I.getOperand(2)));
  SDValue Res = DAG.getNode(ISD::INSERT_VECTOR_ELT, getCurDebugLoc(),
                            TLI.getValueType(I.getType()),
                            InVec, InVal, InIdx);
  setValue(&I, Res);

  if (DisableScheduling) {
    DAG.AssignOrdering(InIdx.getNode(), SDNodeOrder);
    DAG.AssignOrdering(Res.getNode(), SDNodeOrder);
  }
}

void SelectionDAGBuilder::visitExtractElement(User &I) {
  SDValue InVec = getValue(I.getOperand(0));
  SDValue InIdx = DAG.getNode(ISD::ZERO_EXTEND, getCurDebugLoc(),
                              TLI.getPointerTy(),
                              getValue(I.getOperand(1)));
  SDValue Res = DAG.getNode(ISD::EXTRACT_VECTOR_ELT, getCurDebugLoc(),
                            TLI.getValueType(I.getType()), InVec, InIdx);
  setValue(&I, Res);

  if (DisableScheduling) {
    DAG.AssignOrdering(InIdx.getNode(), SDNodeOrder);
    DAG.AssignOrdering(Res.getNode(), SDNodeOrder);
  }
}


// Utility for visitShuffleVector - Returns true if the mask is mask starting
// from SIndx and increasing to the element length (undefs are allowed).
static bool SequentialMask(SmallVectorImpl<int> &Mask, unsigned SIndx) {
  unsigned MaskNumElts = Mask.size();
  for (unsigned i = 0; i != MaskNumElts; ++i)
    if ((Mask[i] >= 0) && (Mask[i] != (int)(i + SIndx)))
      return false;
  return true;
}

void SelectionDAGBuilder::visitShuffleVector(User &I) {
  SmallVector<int, 8> Mask;
  SDValue Src1 = getValue(I.getOperand(0));
  SDValue Src2 = getValue(I.getOperand(1));

  // Convert the ConstantVector mask operand into an array of ints, with -1
  // representing undef values.
  SmallVector<Constant*, 8> MaskElts;
  cast<Constant>(I.getOperand(2))->getVectorElements(*DAG.getContext(), 
                                                     MaskElts);
  unsigned MaskNumElts = MaskElts.size();
  for (unsigned i = 0; i != MaskNumElts; ++i) {
    if (isa<UndefValue>(MaskElts[i]))
      Mask.push_back(-1);
    else
      Mask.push_back(cast<ConstantInt>(MaskElts[i])->getSExtValue());
  }
  
  EVT VT = TLI.getValueType(I.getType());
  EVT SrcVT = Src1.getValueType();
  unsigned SrcNumElts = SrcVT.getVectorNumElements();

  if (SrcNumElts == MaskNumElts) {
    SDValue Res = DAG.getVectorShuffle(VT, getCurDebugLoc(), Src1, Src2,
                                       &Mask[0]);
    setValue(&I, Res);

    if (DisableScheduling)
      DAG.AssignOrdering(Res.getNode(), SDNodeOrder);

    return;
  }

  // Normalize the shuffle vector since mask and vector length don't match.
  if (SrcNumElts < MaskNumElts && MaskNumElts % SrcNumElts == 0) {
    // Mask is longer than the source vectors and is a multiple of the source
    // vectors.  We can use concatenate vector to make the mask and vectors
    // lengths match.
    if (SrcNumElts*2 == MaskNumElts && SequentialMask(Mask, 0)) {
      // The shuffle is concatenating two vectors together.
      SDValue Res = DAG.getNode(ISD::CONCAT_VECTORS, getCurDebugLoc(),
                                VT, Src1, Src2);
      setValue(&I, Res);

      if (DisableScheduling)
        DAG.AssignOrdering(Res.getNode(), SDNodeOrder);

      return;
    }

    // Pad both vectors with undefs to make them the same length as the mask.
    unsigned NumConcat = MaskNumElts / SrcNumElts;
    bool Src1U = Src1.getOpcode() == ISD::UNDEF;
    bool Src2U = Src2.getOpcode() == ISD::UNDEF;
    SDValue UndefVal = DAG.getUNDEF(SrcVT);

    SmallVector<SDValue, 8> MOps1(NumConcat, UndefVal);
    SmallVector<SDValue, 8> MOps2(NumConcat, UndefVal);
    MOps1[0] = Src1;
    MOps2[0] = Src2;
    
    Src1 = Src1U ? DAG.getUNDEF(VT) : DAG.getNode(ISD::CONCAT_VECTORS, 
                                                  getCurDebugLoc(), VT, 
                                                  &MOps1[0], NumConcat);
    Src2 = Src2U ? DAG.getUNDEF(VT) : DAG.getNode(ISD::CONCAT_VECTORS,
                                                  getCurDebugLoc(), VT, 
                                                  &MOps2[0], NumConcat);

    // Readjust mask for new input vector length.
    SmallVector<int, 8> MappedOps;
    for (unsigned i = 0; i != MaskNumElts; ++i) {
      int Idx = Mask[i];
      if (Idx < (int)SrcNumElts)
        MappedOps.push_back(Idx);
      else
        MappedOps.push_back(Idx + MaskNumElts - SrcNumElts);
    }

    SDValue Res = DAG.getVectorShuffle(VT, getCurDebugLoc(), Src1, Src2, 
                                       &MappedOps[0]);
    setValue(&I, Res);

    if (DisableScheduling) {
      DAG.AssignOrdering(Src1.getNode(), SDNodeOrder);
      DAG.AssignOrdering(Src2.getNode(), SDNodeOrder);
      DAG.AssignOrdering(Res.getNode(), SDNodeOrder);
    }

    return;
  }

  if (SrcNumElts > MaskNumElts) {
    // Analyze the access pattern of the vector to see if we can extract
    // two subvectors and do the shuffle. The analysis is done by calculating
    // the range of elements the mask access on both vectors.
    int MinRange[2] = { SrcNumElts+1, SrcNumElts+1};
    int MaxRange[2] = {-1, -1};

    for (unsigned i = 0; i != MaskNumElts; ++i) {
      int Idx = Mask[i];
      int Input = 0;
      if (Idx < 0)
        continue;
      
      if (Idx >= (int)SrcNumElts) {
        Input = 1;
        Idx -= SrcNumElts;
      }
      if (Idx > MaxRange[Input])
        MaxRange[Input] = Idx;
      if (Idx < MinRange[Input])
        MinRange[Input] = Idx;
    }

    // Check if the access is smaller than the vector size and can we find
    // a reasonable extract index.
    int RangeUse[2] = { 2, 2 };  // 0 = Unused, 1 = Extract, 2 = Can not Extract.
    int StartIdx[2];  // StartIdx to extract from
    for (int Input=0; Input < 2; ++Input) {
      if (MinRange[Input] == (int)(SrcNumElts+1) && MaxRange[Input] == -1) {
        RangeUse[Input] = 0; // Unused
        StartIdx[Input] = 0;
      } else if (MaxRange[Input] - MinRange[Input] < (int)MaskNumElts) {
        // Fits within range but we should see if we can find a good
        // start index that is a multiple of the mask length.
        if (MaxRange[Input] < (int)MaskNumElts) {
          RangeUse[Input] = 1; // Extract from beginning of the vector
          StartIdx[Input] = 0;
        } else {
          StartIdx[Input] = (MinRange[Input]/MaskNumElts)*MaskNumElts;
          if (MaxRange[Input] - StartIdx[Input] < (int)MaskNumElts &&
              StartIdx[Input] + MaskNumElts < SrcNumElts)
            RangeUse[Input] = 1; // Extract from a multiple of the mask length.
        }
      }
    }

    if (RangeUse[0] == 0 && RangeUse[1] == 0) {
      SDValue Res = DAG.getUNDEF(VT);
      setValue(&I, Res);  // Vectors are not used.

      if (DisableScheduling)
        DAG.AssignOrdering(Res.getNode(), SDNodeOrder);

      return;
    }
    else if (RangeUse[0] < 2 && RangeUse[1] < 2) {
      // Extract appropriate subvector and generate a vector shuffle
      for (int Input=0; Input < 2; ++Input) {
        SDValue &Src = Input == 0 ? Src1 : Src2;
        if (RangeUse[Input] == 0)
          Src = DAG.getUNDEF(VT);
        else
          Src = DAG.getNode(ISD::EXTRACT_SUBVECTOR, getCurDebugLoc(), VT,
                            Src, DAG.getIntPtrConstant(StartIdx[Input]));

        if (DisableScheduling)
          DAG.AssignOrdering(Src.getNode(), SDNodeOrder);
      }

      // Calculate new mask.
      SmallVector<int, 8> MappedOps;
      for (unsigned i = 0; i != MaskNumElts; ++i) {
        int Idx = Mask[i];
        if (Idx < 0)
          MappedOps.push_back(Idx);
        else if (Idx < (int)SrcNumElts)
          MappedOps.push_back(Idx - StartIdx[0]);
        else
          MappedOps.push_back(Idx - SrcNumElts - StartIdx[1] + MaskNumElts);
      }

      SDValue Res = DAG.getVectorShuffle(VT, getCurDebugLoc(), Src1, Src2,
                                         &MappedOps[0]);
      setValue(&I, Res);

      if (DisableScheduling)
        DAG.AssignOrdering(Res.getNode(), SDNodeOrder);

      return;
    }
  }

  // We can't use either concat vectors or extract subvectors so fall back to
  // replacing the shuffle with extract and build vector.
  // to insert and build vector.
  EVT EltVT = VT.getVectorElementType();
  EVT PtrVT = TLI.getPointerTy();
  SmallVector<SDValue,8> Ops;
  for (unsigned i = 0; i != MaskNumElts; ++i) {
    if (Mask[i] < 0) {
      Ops.push_back(DAG.getUNDEF(EltVT));
    } else {
      int Idx = Mask[i];
      SDValue Res;

      if (Idx < (int)SrcNumElts)
        Res = DAG.getNode(ISD::EXTRACT_VECTOR_ELT, getCurDebugLoc(),
                          EltVT, Src1, DAG.getConstant(Idx, PtrVT));
      else
        Res = DAG.getNode(ISD::EXTRACT_VECTOR_ELT, getCurDebugLoc(),
                          EltVT, Src2,
                          DAG.getConstant(Idx - SrcNumElts, PtrVT));

      Ops.push_back(Res);

      if (DisableScheduling)
        DAG.AssignOrdering(Res.getNode(), SDNodeOrder);
    }
  }

  SDValue Res = DAG.getNode(ISD::BUILD_VECTOR, getCurDebugLoc(),
                            VT, &Ops[0], Ops.size());
  setValue(&I, Res);

  if (DisableScheduling)
    DAG.AssignOrdering(Res.getNode(), SDNodeOrder);
}

void SelectionDAGBuilder::visitInsertValue(InsertValueInst &I) {
  const Value *Op0 = I.getOperand(0);
  const Value *Op1 = I.getOperand(1);
  const Type *AggTy = I.getType();
  const Type *ValTy = Op1->getType();
  bool IntoUndef = isa<UndefValue>(Op0);
  bool FromUndef = isa<UndefValue>(Op1);

  unsigned LinearIndex = ComputeLinearIndex(TLI, AggTy,
                                            I.idx_begin(), I.idx_end());

  SmallVector<EVT, 4> AggValueVTs;
  ComputeValueVTs(TLI, AggTy, AggValueVTs);
  SmallVector<EVT, 4> ValValueVTs;
  ComputeValueVTs(TLI, ValTy, ValValueVTs);

  unsigned NumAggValues = AggValueVTs.size();
  unsigned NumValValues = ValValueVTs.size();
  SmallVector<SDValue, 4> Values(NumAggValues);

  SDValue Agg = getValue(Op0);
  SDValue Val = getValue(Op1);
  unsigned i = 0;
  // Copy the beginning value(s) from the original aggregate.
  for (; i != LinearIndex; ++i)
    Values[i] = IntoUndef ? DAG.getUNDEF(AggValueVTs[i]) :
                SDValue(Agg.getNode(), Agg.getResNo() + i);
  // Copy values from the inserted value(s).
  for (; i != LinearIndex + NumValValues; ++i)
    Values[i] = FromUndef ? DAG.getUNDEF(AggValueVTs[i]) :
                SDValue(Val.getNode(), Val.getResNo() + i - LinearIndex);
  // Copy remaining value(s) from the original aggregate.
  for (; i != NumAggValues; ++i)
    Values[i] = IntoUndef ? DAG.getUNDEF(AggValueVTs[i]) :
                SDValue(Agg.getNode(), Agg.getResNo() + i);

  SDValue Res = DAG.getNode(ISD::MERGE_VALUES, getCurDebugLoc(),
                            DAG.getVTList(&AggValueVTs[0], NumAggValues),
                            &Values[0], NumAggValues);
  setValue(&I, Res);

  if (DisableScheduling)
    DAG.AssignOrdering(Res.getNode(), SDNodeOrder);
}

void SelectionDAGBuilder::visitExtractValue(ExtractValueInst &I) {
  const Value *Op0 = I.getOperand(0);
  const Type *AggTy = Op0->getType();
  const Type *ValTy = I.getType();
  bool OutOfUndef = isa<UndefValue>(Op0);

  unsigned LinearIndex = ComputeLinearIndex(TLI, AggTy,
                                            I.idx_begin(), I.idx_end());

  SmallVector<EVT, 4> ValValueVTs;
  ComputeValueVTs(TLI, ValTy, ValValueVTs);

  unsigned NumValValues = ValValueVTs.size();
  SmallVector<SDValue, 4> Values(NumValValues);

  SDValue Agg = getValue(Op0);
  // Copy out the selected value(s).
  for (unsigned i = LinearIndex; i != LinearIndex + NumValValues; ++i)
    Values[i - LinearIndex] =
      OutOfUndef ?
        DAG.getUNDEF(Agg.getNode()->getValueType(Agg.getResNo() + i)) :
        SDValue(Agg.getNode(), Agg.getResNo() + i);

  SDValue Res = DAG.getNode(ISD::MERGE_VALUES, getCurDebugLoc(),
                            DAG.getVTList(&ValValueVTs[0], NumValValues),
                            &Values[0], NumValValues);
  setValue(&I, Res);

  if (DisableScheduling)
    DAG.AssignOrdering(Res.getNode(), SDNodeOrder);
}

void SelectionDAGBuilder::visitGetElementPtr(User &I) {
  SDValue N = getValue(I.getOperand(0));
  const Type *Ty = I.getOperand(0)->getType();

  for (GetElementPtrInst::op_iterator OI = I.op_begin()+1, E = I.op_end();
       OI != E; ++OI) {
    Value *Idx = *OI;
    if (const StructType *StTy = dyn_cast<StructType>(Ty)) {
      unsigned Field = cast<ConstantInt>(Idx)->getZExtValue();
      if (Field) {
        // N = N + Offset
        uint64_t Offset = TD->getStructLayout(StTy)->getElementOffset(Field);
        N = DAG.getNode(ISD::ADD, getCurDebugLoc(), N.getValueType(), N,
                        DAG.getIntPtrConstant(Offset));

        if (DisableScheduling)
          DAG.AssignOrdering(N.getNode(), SDNodeOrder);
      }

      Ty = StTy->getElementType(Field);
    } else {
      Ty = cast<SequentialType>(Ty)->getElementType();

      // If this is a constant subscript, handle it quickly.
      if (ConstantInt *CI = dyn_cast<ConstantInt>(Idx)) {
        if (CI->getZExtValue() == 0) continue;
        uint64_t Offs =
            TD->getTypeAllocSize(Ty)*cast<ConstantInt>(CI)->getSExtValue();
        SDValue OffsVal;
        EVT PTy = TLI.getPointerTy();
        unsigned PtrBits = PTy.getSizeInBits();
        if (PtrBits < 64)
          OffsVal = DAG.getNode(ISD::TRUNCATE, getCurDebugLoc(),
                                TLI.getPointerTy(),
                                DAG.getConstant(Offs, MVT::i64));
        else
          OffsVal = DAG.getIntPtrConstant(Offs);

        N = DAG.getNode(ISD::ADD, getCurDebugLoc(), N.getValueType(), N,
                        OffsVal);

        if (DisableScheduling) {
          DAG.AssignOrdering(OffsVal.getNode(), SDNodeOrder);
          DAG.AssignOrdering(N.getNode(), SDNodeOrder);
        }

        continue;
      }

      // N = N + Idx * ElementSize;
      APInt ElementSize = APInt(TLI.getPointerTy().getSizeInBits(),
                                TD->getTypeAllocSize(Ty));
      SDValue IdxN = getValue(Idx);

      // If the index is smaller or larger than intptr_t, truncate or extend
      // it.
      IdxN = DAG.getSExtOrTrunc(IdxN, getCurDebugLoc(), N.getValueType());

      // If this is a multiply by a power of two, turn it into a shl
      // immediately.  This is a very common case.
      if (ElementSize != 1) {
        if (ElementSize.isPowerOf2()) {
          unsigned Amt = ElementSize.logBase2();
          IdxN = DAG.getNode(ISD::SHL, getCurDebugLoc(),
                             N.getValueType(), IdxN,
                             DAG.getConstant(Amt, TLI.getPointerTy()));
        } else {
          SDValue Scale = DAG.getConstant(ElementSize, TLI.getPointerTy());
          IdxN = DAG.getNode(ISD::MUL, getCurDebugLoc(),
                             N.getValueType(), IdxN, Scale);
        }

        if (DisableScheduling)
          DAG.AssignOrdering(IdxN.getNode(), SDNodeOrder);
      }

      N = DAG.getNode(ISD::ADD, getCurDebugLoc(),
                      N.getValueType(), N, IdxN);

      if (DisableScheduling)
        DAG.AssignOrdering(N.getNode(), SDNodeOrder);
    }
  }

  setValue(&I, N);
}

void SelectionDAGBuilder::visitAlloca(AllocaInst &I) {
  // If this is a fixed sized alloca in the entry block of the function,
  // allocate it statically on the stack.
  if (FuncInfo.StaticAllocaMap.count(&I))
    return;   // getValue will auto-populate this.

  const Type *Ty = I.getAllocatedType();
  uint64_t TySize = TLI.getTargetData()->getTypeAllocSize(Ty);
  unsigned Align =
    std::max((unsigned)TLI.getTargetData()->getPrefTypeAlignment(Ty),
             I.getAlignment());

  SDValue AllocSize = getValue(I.getArraySize());
  
  AllocSize = DAG.getNode(ISD::MUL, getCurDebugLoc(), AllocSize.getValueType(),
                          AllocSize,
                          DAG.getConstant(TySize, AllocSize.getValueType()));
  
  if (DisableScheduling)
    DAG.AssignOrdering(AllocSize.getNode(), SDNodeOrder);
  
  EVT IntPtr = TLI.getPointerTy();
  AllocSize = DAG.getZExtOrTrunc(AllocSize, getCurDebugLoc(), IntPtr);

  if (DisableScheduling)
    DAG.AssignOrdering(AllocSize.getNode(), SDNodeOrder);
  
  // Handle alignment.  If the requested alignment is less than or equal to
  // the stack alignment, ignore it.  If the size is greater than or equal to
  // the stack alignment, we note this in the DYNAMIC_STACKALLOC node.
  unsigned StackAlign =
    TLI.getTargetMachine().getFrameInfo()->getStackAlignment();
  if (Align <= StackAlign)
    Align = 0;

  // Round the size of the allocation up to the stack alignment size
  // by add SA-1 to the size.
  AllocSize = DAG.getNode(ISD::ADD, getCurDebugLoc(),
                          AllocSize.getValueType(), AllocSize,
                          DAG.getIntPtrConstant(StackAlign-1));
  if (DisableScheduling)
    DAG.AssignOrdering(AllocSize.getNode(), SDNodeOrder);

  // Mask out the low bits for alignment purposes.
  AllocSize = DAG.getNode(ISD::AND, getCurDebugLoc(),
                          AllocSize.getValueType(), AllocSize,
                          DAG.getIntPtrConstant(~(uint64_t)(StackAlign-1)));
  if (DisableScheduling)
    DAG.AssignOrdering(AllocSize.getNode(), SDNodeOrder);

  SDValue Ops[] = { getRoot(), AllocSize, DAG.getIntPtrConstant(Align) };
  SDVTList VTs = DAG.getVTList(AllocSize.getValueType(), MVT::Other);
  SDValue DSA = DAG.getNode(ISD::DYNAMIC_STACKALLOC, getCurDebugLoc(),
                            VTs, Ops, 3);
  setValue(&I, DSA);
  DAG.setRoot(DSA.getValue(1));

  if (DisableScheduling)
    DAG.AssignOrdering(DSA.getNode(), SDNodeOrder);

  // Inform the Frame Information that we have just allocated a variable-sized
  // object.
  FuncInfo.MF->getFrameInfo()->CreateVariableSizedObject();
}

void SelectionDAGBuilder::visitLoad(LoadInst &I) {
  const Value *SV = I.getOperand(0);
  SDValue Ptr = getValue(SV);

  const Type *Ty = I.getType();
  bool isVolatile = I.isVolatile();
  unsigned Alignment = I.getAlignment();

  SmallVector<EVT, 4> ValueVTs;
  SmallVector<uint64_t, 4> Offsets;
  ComputeValueVTs(TLI, Ty, ValueVTs, &Offsets);
  unsigned NumValues = ValueVTs.size();
  if (NumValues == 0)
    return;

  SDValue Root;
  bool ConstantMemory = false;
  if (I.isVolatile())
    // Serialize volatile loads with other side effects.
    Root = getRoot();
  else if (AA->pointsToConstantMemory(SV)) {
    // Do not serialize (non-volatile) loads of constant memory with anything.
    Root = DAG.getEntryNode();
    ConstantMemory = true;
  } else {
    // Do not serialize non-volatile loads against each other.
    Root = DAG.getRoot();
  }

  SmallVector<SDValue, 4> Values(NumValues);
  SmallVector<SDValue, 4> Chains(NumValues);
  EVT PtrVT = Ptr.getValueType();
  for (unsigned i = 0; i != NumValues; ++i) {
    SDValue A = DAG.getNode(ISD::ADD, getCurDebugLoc(),
                            PtrVT, Ptr,
                            DAG.getConstant(Offsets[i], PtrVT));
    SDValue L = DAG.getLoad(ValueVTs[i], getCurDebugLoc(), Root,
                            A, SV, Offsets[i], isVolatile, Alignment);

    Values[i] = L;
    Chains[i] = L.getValue(1);

    if (DisableScheduling) {
      DAG.AssignOrdering(A.getNode(), SDNodeOrder);
      DAG.AssignOrdering(L.getNode(), SDNodeOrder);
    }
  }

  if (!ConstantMemory) {
    SDValue Chain = DAG.getNode(ISD::TokenFactor, getCurDebugLoc(),
                                MVT::Other, &Chains[0], NumValues);
    if (isVolatile)
      DAG.setRoot(Chain);
    else
      PendingLoads.push_back(Chain);

    if (DisableScheduling)
      DAG.AssignOrdering(Chain.getNode(), SDNodeOrder);
  }

  SDValue Res = DAG.getNode(ISD::MERGE_VALUES, getCurDebugLoc(),
                            DAG.getVTList(&ValueVTs[0], NumValues),
                            &Values[0], NumValues);
  setValue(&I, Res);

  if (DisableScheduling)
    DAG.AssignOrdering(Res.getNode(), SDNodeOrder);
}

void SelectionDAGBuilder::visitStore(StoreInst &I) {
  Value *SrcV = I.getOperand(0);
  Value *PtrV = I.getOperand(1);

  SmallVector<EVT, 4> ValueVTs;
  SmallVector<uint64_t, 4> Offsets;
  ComputeValueVTs(TLI, SrcV->getType(), ValueVTs, &Offsets);
  unsigned NumValues = ValueVTs.size();
  if (NumValues == 0)
    return;

  // Get the lowered operands. Note that we do this after
  // checking if NumResults is zero, because with zero results
  // the operands won't have values in the map.
  SDValue Src = getValue(SrcV);
  SDValue Ptr = getValue(PtrV);

  SDValue Root = getRoot();
  SmallVector<SDValue, 4> Chains(NumValues);
  EVT PtrVT = Ptr.getValueType();
  bool isVolatile = I.isVolatile();
  unsigned Alignment = I.getAlignment();

  for (unsigned i = 0; i != NumValues; ++i) {
    SDValue Add = DAG.getNode(ISD::ADD, getCurDebugLoc(), PtrVT, Ptr,
                              DAG.getConstant(Offsets[i], PtrVT));
    Chains[i] = DAG.getStore(Root, getCurDebugLoc(),
                             SDValue(Src.getNode(), Src.getResNo() + i),
                             Add, PtrV, Offsets[i], isVolatile, Alignment);

    if (DisableScheduling) {
      DAG.AssignOrdering(Add.getNode(), SDNodeOrder);
      DAG.AssignOrdering(Chains[i].getNode(), SDNodeOrder);
    }
  }

  SDValue Res = DAG.getNode(ISD::TokenFactor, getCurDebugLoc(),
                            MVT::Other, &Chains[0], NumValues);
  DAG.setRoot(Res);

  if (DisableScheduling)
    DAG.AssignOrdering(Res.getNode(), SDNodeOrder);
}

/// visitTargetIntrinsic - Lower a call of a target intrinsic to an INTRINSIC
/// node.
void SelectionDAGBuilder::visitTargetIntrinsic(CallInst &I,
                                               unsigned Intrinsic) {
  bool HasChain = !I.doesNotAccessMemory();
  bool OnlyLoad = HasChain && I.onlyReadsMemory();

  // Build the operand list.
  SmallVector<SDValue, 8> Ops;
  if (HasChain) {  // If this intrinsic has side-effects, chainify it.
    if (OnlyLoad) {
      // We don't need to serialize loads against other loads.
      Ops.push_back(DAG.getRoot());
    } else {
      Ops.push_back(getRoot());
    }
  }

  // Info is set by getTgtMemInstrinsic
  TargetLowering::IntrinsicInfo Info;
  bool IsTgtIntrinsic = TLI.getTgtMemIntrinsic(Info, I, Intrinsic);

  // Add the intrinsic ID as an integer operand if it's not a target intrinsic.
  if (!IsTgtIntrinsic)
    Ops.push_back(DAG.getConstant(Intrinsic, TLI.getPointerTy()));

  // Add all operands of the call to the operand list.
  for (unsigned i = 1, e = I.getNumOperands(); i != e; ++i) {
    SDValue Op = getValue(I.getOperand(i));
    assert(TLI.isTypeLegal(Op.getValueType()) &&
           "Intrinsic uses a non-legal type?");
    Ops.push_back(Op);
  }

  SmallVector<EVT, 4> ValueVTs;
  ComputeValueVTs(TLI, I.getType(), ValueVTs);
#ifndef NDEBUG
  for (unsigned Val = 0, E = ValueVTs.size(); Val != E; ++Val) {
    assert(TLI.isTypeLegal(ValueVTs[Val]) &&
           "Intrinsic uses a non-legal type?");
  }
#endif // NDEBUG

  if (HasChain)
    ValueVTs.push_back(MVT::Other);

  SDVTList VTs = DAG.getVTList(ValueVTs.data(), ValueVTs.size());

  // Create the node.
  SDValue Result;
  if (IsTgtIntrinsic) {
    // This is target intrinsic that touches memory
    Result = DAG.getMemIntrinsicNode(Info.opc, getCurDebugLoc(),
                                     VTs, &Ops[0], Ops.size(),
                                     Info.memVT, Info.ptrVal, Info.offset,
                                     Info.align, Info.vol,
                                     Info.readMem, Info.writeMem);
  } else if (!HasChain) {
    Result = DAG.getNode(ISD::INTRINSIC_WO_CHAIN, getCurDebugLoc(),
                         VTs, &Ops[0], Ops.size());
  } else if (I.getType() != Type::getVoidTy(*DAG.getContext())) {
    Result = DAG.getNode(ISD::INTRINSIC_W_CHAIN, getCurDebugLoc(),
                         VTs, &Ops[0], Ops.size());
  } else {
    Result = DAG.getNode(ISD::INTRINSIC_VOID, getCurDebugLoc(),
                         VTs, &Ops[0], Ops.size());
  }

  if (DisableScheduling)
    DAG.AssignOrdering(Result.getNode(), SDNodeOrder);

  if (HasChain) {
    SDValue Chain = Result.getValue(Result.getNode()->getNumValues()-1);
    if (OnlyLoad)
      PendingLoads.push_back(Chain);
    else
      DAG.setRoot(Chain);
  }

  if (I.getType() != Type::getVoidTy(*DAG.getContext())) {
    if (const VectorType *PTy = dyn_cast<VectorType>(I.getType())) {
      EVT VT = TLI.getValueType(PTy);
      Result = DAG.getNode(ISD::BIT_CONVERT, getCurDebugLoc(), VT, Result);

      if (DisableScheduling)
        DAG.AssignOrdering(Result.getNode(), SDNodeOrder);
    }

    setValue(&I, Result);
  }
}

/// GetSignificand - Get the significand and build it into a floating-point
/// number with exponent of 1:
///
///   Op = (Op & 0x007fffff) | 0x3f800000;
///
/// where Op is the hexidecimal representation of floating point value.
static SDValue
GetSignificand(SelectionDAG &DAG, SDValue Op, DebugLoc dl, unsigned Order) {
  SDValue t1 = DAG.getNode(ISD::AND, dl, MVT::i32, Op,
                           DAG.getConstant(0x007fffff, MVT::i32));
  SDValue t2 = DAG.getNode(ISD::OR, dl, MVT::i32, t1,
                           DAG.getConstant(0x3f800000, MVT::i32));
  SDValue Res = DAG.getNode(ISD::BIT_CONVERT, dl, MVT::f32, t2);

  if (DisableScheduling) {
    DAG.AssignOrdering(t1.getNode(), Order);
    DAG.AssignOrdering(t2.getNode(), Order);
    DAG.AssignOrdering(Res.getNode(), Order);
  }

  return Res;
}

/// GetExponent - Get the exponent:
///
///   (float)(int)(((Op & 0x7f800000) >> 23) - 127);
///
/// where Op is the hexidecimal representation of floating point value.
static SDValue
GetExponent(SelectionDAG &DAG, SDValue Op, const TargetLowering &TLI,
            DebugLoc dl, unsigned Order) {
  SDValue t0 = DAG.getNode(ISD::AND, dl, MVT::i32, Op,
                           DAG.getConstant(0x7f800000, MVT::i32));
  SDValue t1 = DAG.getNode(ISD::SRL, dl, MVT::i32, t0,
                           DAG.getConstant(23, TLI.getPointerTy()));
  SDValue t2 = DAG.getNode(ISD::SUB, dl, MVT::i32, t1,
                           DAG.getConstant(127, MVT::i32));
  SDValue Res = DAG.getNode(ISD::SINT_TO_FP, dl, MVT::f32, t2);

  if (DisableScheduling) {
    DAG.AssignOrdering(t0.getNode(), Order);
    DAG.AssignOrdering(t1.getNode(), Order);
    DAG.AssignOrdering(t2.getNode(), Order);
    DAG.AssignOrdering(Res.getNode(), Order);
  }

  return Res;
}

/// getF32Constant - Get 32-bit floating point constant.
static SDValue
getF32Constant(SelectionDAG &DAG, unsigned Flt) {
  return DAG.getConstantFP(APFloat(APInt(32, Flt)), MVT::f32);
}

/// Inlined utility function to implement binary input atomic intrinsics for
/// visitIntrinsicCall: I is a call instruction
///                     Op is the associated NodeType for I
const char *
SelectionDAGBuilder::implVisitBinaryAtomic(CallInst& I, ISD::NodeType Op) {
  SDValue Root = getRoot();
  SDValue L =
    DAG.getAtomic(Op, getCurDebugLoc(),
                  getValue(I.getOperand(2)).getValueType().getSimpleVT(),
                  Root,
                  getValue(I.getOperand(1)),
                  getValue(I.getOperand(2)),
                  I.getOperand(1));
  setValue(&I, L);
  DAG.setRoot(L.getValue(1));

  if (DisableScheduling)
    DAG.AssignOrdering(L.getNode(), SDNodeOrder);

  return 0;
}

// implVisitAluOverflow - Lower arithmetic overflow instrinsics.
const char *
SelectionDAGBuilder::implVisitAluOverflow(CallInst &I, ISD::NodeType Op) {
  SDValue Op1 = getValue(I.getOperand(1));
  SDValue Op2 = getValue(I.getOperand(2));

  SDVTList VTs = DAG.getVTList(Op1.getValueType(), MVT::i1);
  SDValue Result = DAG.getNode(Op, getCurDebugLoc(), VTs, Op1, Op2);

  setValue(&I, Result);

  if (DisableScheduling)
    DAG.AssignOrdering(Result.getNode(), SDNodeOrder);

  return 0;
}

/// visitExp - Lower an exp intrinsic. Handles the special sequences for
/// limited-precision mode.
void
SelectionDAGBuilder::visitExp(CallInst &I) {
  SDValue result;
  DebugLoc dl = getCurDebugLoc();

  if (getValue(I.getOperand(1)).getValueType() == MVT::f32 &&
      LimitFloatPrecision > 0 && LimitFloatPrecision <= 18) {
    SDValue Op = getValue(I.getOperand(1));

    // Put the exponent in the right bit position for later addition to the
    // final result:
    //
    //   #define LOG2OFe 1.4426950f
    //   IntegerPartOfX = ((int32_t)(X * LOG2OFe));
    SDValue t0 = DAG.getNode(ISD::FMUL, dl, MVT::f32, Op,
                             getF32Constant(DAG, 0x3fb8aa3b));
    SDValue IntegerPartOfX = DAG.getNode(ISD::FP_TO_SINT, dl, MVT::i32, t0);

    //   FractionalPartOfX = (X * LOG2OFe) - (float)IntegerPartOfX;
    SDValue t1 = DAG.getNode(ISD::SINT_TO_FP, dl, MVT::f32, IntegerPartOfX);
    SDValue X = DAG.getNode(ISD::FSUB, dl, MVT::f32, t0, t1);

    if (DisableScheduling) {
      DAG.AssignOrdering(t0.getNode(), SDNodeOrder);
      DAG.AssignOrdering(IntegerPartOfX.getNode(), SDNodeOrder);
      DAG.AssignOrdering(t1.getNode(), SDNodeOrder);
      DAG.AssignOrdering(X.getNode(), SDNodeOrder);
    }

    //   IntegerPartOfX <<= 23;
    IntegerPartOfX = DAG.getNode(ISD::SHL, dl, MVT::i32, IntegerPartOfX,
                                 DAG.getConstant(23, TLI.getPointerTy()));

    if (DisableScheduling)
      DAG.AssignOrdering(IntegerPartOfX.getNode(), SDNodeOrder);

    if (LimitFloatPrecision <= 6) {
      // For floating-point precision of 6:
      //
      //   TwoToFractionalPartOfX =
      //     0.997535578f +
      //       (0.735607626f + 0.252464424f * x) * x;
      //
      // error 0.0144103317, which is 6 bits
      SDValue t2 = DAG.getNode(ISD::FMUL, dl, MVT::f32, X,
                               getF32Constant(DAG, 0x3e814304));
      SDValue t3 = DAG.getNode(ISD::FADD, dl, MVT::f32, t2,
                               getF32Constant(DAG, 0x3f3c50c8));
      SDValue t4 = DAG.getNode(ISD::FMUL, dl, MVT::f32, t3, X);
      SDValue t5 = DAG.getNode(ISD::FADD, dl, MVT::f32, t4,
                               getF32Constant(DAG, 0x3f7f5e7e));
      SDValue TwoToFracPartOfX = DAG.getNode(ISD::BIT_CONVERT, dl,MVT::i32, t5);

      // Add the exponent into the result in integer domain.
      SDValue t6 = DAG.getNode(ISD::ADD, dl, MVT::i32,
                               TwoToFracPartOfX, IntegerPartOfX);

      result = DAG.getNode(ISD::BIT_CONVERT, dl, MVT::f32, t6);

      if (DisableScheduling) {
        DAG.AssignOrdering(t2.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t3.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t4.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t5.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t6.getNode(), SDNodeOrder);
        DAG.AssignOrdering(TwoToFracPartOfX.getNode(), SDNodeOrder);
        DAG.AssignOrdering(result.getNode(), SDNodeOrder);
      }
    } else if (LimitFloatPrecision > 6 && LimitFloatPrecision <= 12) {
      // For floating-point precision of 12:
      //
      //   TwoToFractionalPartOfX =
      //     0.999892986f +
      //       (0.696457318f +
      //         (0.224338339f + 0.792043434e-1f * x) * x) * x;
      //
      // 0.000107046256 error, which is 13 to 14 bits
      SDValue t2 = DAG.getNode(ISD::FMUL, dl, MVT::f32, X,
                               getF32Constant(DAG, 0x3da235e3));
      SDValue t3 = DAG.getNode(ISD::FADD, dl, MVT::f32, t2,
                               getF32Constant(DAG, 0x3e65b8f3));
      SDValue t4 = DAG.getNode(ISD::FMUL, dl, MVT::f32, t3, X);
      SDValue t5 = DAG.getNode(ISD::FADD, dl, MVT::f32, t4,
                               getF32Constant(DAG, 0x3f324b07));
      SDValue t6 = DAG.getNode(ISD::FMUL, dl, MVT::f32, t5, X);
      SDValue t7 = DAG.getNode(ISD::FADD, dl, MVT::f32, t6,
                               getF32Constant(DAG, 0x3f7ff8fd));
      SDValue TwoToFracPartOfX = DAG.getNode(ISD::BIT_CONVERT, dl,MVT::i32, t7);

      // Add the exponent into the result in integer domain.
      SDValue t8 = DAG.getNode(ISD::ADD, dl, MVT::i32,
                               TwoToFracPartOfX, IntegerPartOfX);

      result = DAG.getNode(ISD::BIT_CONVERT, dl, MVT::f32, t8);

      if (DisableScheduling) {
        DAG.AssignOrdering(t2.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t3.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t4.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t5.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t6.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t7.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t8.getNode(), SDNodeOrder);
        DAG.AssignOrdering(TwoToFracPartOfX.getNode(), SDNodeOrder);
        DAG.AssignOrdering(result.getNode(), SDNodeOrder);
      }
    } else { // LimitFloatPrecision > 12 && LimitFloatPrecision <= 18
      // For floating-point precision of 18:
      //
      //   TwoToFractionalPartOfX =
      //     0.999999982f +
      //       (0.693148872f +
      //         (0.240227044f +
      //           (0.554906021e-1f +
      //             (0.961591928e-2f +
      //               (0.136028312e-2f + 0.157059148e-3f *x)*x)*x)*x)*x)*x;
      //
      // error 2.47208000*10^(-7), which is better than 18 bits
      SDValue t2 = DAG.getNode(ISD::FMUL, dl, MVT::f32, X,
                               getF32Constant(DAG, 0x3924b03e));
      SDValue t3 = DAG.getNode(ISD::FADD, dl, MVT::f32, t2,
                               getF32Constant(DAG, 0x3ab24b87));
      SDValue t4 = DAG.getNode(ISD::FMUL, dl, MVT::f32, t3, X);
      SDValue t5 = DAG.getNode(ISD::FADD, dl, MVT::f32, t4,
                               getF32Constant(DAG, 0x3c1d8c17));
      SDValue t6 = DAG.getNode(ISD::FMUL, dl, MVT::f32, t5, X);
      SDValue t7 = DAG.getNode(ISD::FADD, dl, MVT::f32, t6,
                               getF32Constant(DAG, 0x3d634a1d));
      SDValue t8 = DAG.getNode(ISD::FMUL, dl, MVT::f32, t7, X);
      SDValue t9 = DAG.getNode(ISD::FADD, dl, MVT::f32, t8,
                               getF32Constant(DAG, 0x3e75fe14));
      SDValue t10 = DAG.getNode(ISD::FMUL, dl, MVT::f32, t9, X);
      SDValue t11 = DAG.getNode(ISD::FADD, dl, MVT::f32, t10,
                                getF32Constant(DAG, 0x3f317234));
      SDValue t12 = DAG.getNode(ISD::FMUL, dl, MVT::f32, t11, X);
      SDValue t13 = DAG.getNode(ISD::FADD, dl, MVT::f32, t12,
                                getF32Constant(DAG, 0x3f800000));
      SDValue TwoToFracPartOfX = DAG.getNode(ISD::BIT_CONVERT, dl,
                                             MVT::i32, t13);

      // Add the exponent into the result in integer domain.
      SDValue t14 = DAG.getNode(ISD::ADD, dl, MVT::i32,
                                TwoToFracPartOfX, IntegerPartOfX);

      result = DAG.getNode(ISD::BIT_CONVERT, dl, MVT::f32, t14);

      if (DisableScheduling) {
        DAG.AssignOrdering(t2.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t3.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t4.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t5.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t6.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t7.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t8.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t9.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t10.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t11.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t12.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t13.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t14.getNode(), SDNodeOrder);
        DAG.AssignOrdering(TwoToFracPartOfX.getNode(), SDNodeOrder);
        DAG.AssignOrdering(result.getNode(), SDNodeOrder);
      }
    }
  } else {
    // No special expansion.
    result = DAG.getNode(ISD::FEXP, dl,
                         getValue(I.getOperand(1)).getValueType(),
                         getValue(I.getOperand(1)));
    if (DisableScheduling)
      DAG.AssignOrdering(result.getNode(), SDNodeOrder);
  }

  setValue(&I, result);
}

/// visitLog - Lower a log intrinsic. Handles the special sequences for
/// limited-precision mode.
void
SelectionDAGBuilder::visitLog(CallInst &I) {
  SDValue result;
  DebugLoc dl = getCurDebugLoc();

  if (getValue(I.getOperand(1)).getValueType() == MVT::f32 &&
      LimitFloatPrecision > 0 && LimitFloatPrecision <= 18) {
    SDValue Op = getValue(I.getOperand(1));
    SDValue Op1 = DAG.getNode(ISD::BIT_CONVERT, dl, MVT::i32, Op);

    if (DisableScheduling)
      DAG.AssignOrdering(Op1.getNode(), SDNodeOrder);

    // Scale the exponent by log(2) [0.69314718f].
    SDValue Exp = GetExponent(DAG, Op1, TLI, dl, SDNodeOrder);
    SDValue LogOfExponent = DAG.getNode(ISD::FMUL, dl, MVT::f32, Exp,
                                        getF32Constant(DAG, 0x3f317218));

    if (DisableScheduling)
      DAG.AssignOrdering(LogOfExponent.getNode(), SDNodeOrder);

    // Get the significand and build it into a floating-point number with
    // exponent of 1.
    SDValue X = GetSignificand(DAG, Op1, dl, SDNodeOrder);

    if (LimitFloatPrecision <= 6) {
      // For floating-point precision of 6:
      //
      //   LogofMantissa =
      //     -1.1609546f +
      //       (1.4034025f - 0.23903021f * x) * x;
      //
      // error 0.0034276066, which is better than 8 bits
      SDValue t0 = DAG.getNode(ISD::FMUL, dl, MVT::f32, X,
                               getF32Constant(DAG, 0xbe74c456));
      SDValue t1 = DAG.getNode(ISD::FADD, dl, MVT::f32, t0,
                               getF32Constant(DAG, 0x3fb3a2b1));
      SDValue t2 = DAG.getNode(ISD::FMUL, dl, MVT::f32, t1, X);
      SDValue LogOfMantissa = DAG.getNode(ISD::FSUB, dl, MVT::f32, t2,
                                          getF32Constant(DAG, 0x3f949a29));

      result = DAG.getNode(ISD::FADD, dl,
                           MVT::f32, LogOfExponent, LogOfMantissa);

      if (DisableScheduling) {
        DAG.AssignOrdering(t0.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t1.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t2.getNode(), SDNodeOrder);
        DAG.AssignOrdering(LogOfMantissa.getNode(), SDNodeOrder);
        DAG.AssignOrdering(result.getNode(), SDNodeOrder);
      }
    } else if (LimitFloatPrecision > 6 && LimitFloatPrecision <= 12) {
      // For floating-point precision of 12:
      //
      //   LogOfMantissa =
      //     -1.7417939f +
      //       (2.8212026f +
      //         (-1.4699568f +
      //           (0.44717955f - 0.56570851e-1f * x) * x) * x) * x;
      //
      // error 0.000061011436, which is 14 bits
      SDValue t0 = DAG.getNode(ISD::FMUL, dl, MVT::f32, X,
                               getF32Constant(DAG, 0xbd67b6d6));
      SDValue t1 = DAG.getNode(ISD::FADD, dl, MVT::f32, t0,
                               getF32Constant(DAG, 0x3ee4f4b8));
      SDValue t2 = DAG.getNode(ISD::FMUL, dl, MVT::f32, t1, X);
      SDValue t3 = DAG.getNode(ISD::FSUB, dl, MVT::f32, t2,
                               getF32Constant(DAG, 0x3fbc278b));
      SDValue t4 = DAG.getNode(ISD::FMUL, dl, MVT::f32, t3, X);
      SDValue t5 = DAG.getNode(ISD::FADD, dl, MVT::f32, t4,
                               getF32Constant(DAG, 0x40348e95));
      SDValue t6 = DAG.getNode(ISD::FMUL, dl, MVT::f32, t5, X);
      SDValue LogOfMantissa = DAG.getNode(ISD::FSUB, dl, MVT::f32, t6,
                                          getF32Constant(DAG, 0x3fdef31a));

      result = DAG.getNode(ISD::FADD, dl,
                           MVT::f32, LogOfExponent, LogOfMantissa);

      if (DisableScheduling) {
        DAG.AssignOrdering(t0.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t1.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t2.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t3.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t4.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t5.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t6.getNode(), SDNodeOrder);
        DAG.AssignOrdering(LogOfMantissa.getNode(), SDNodeOrder);
        DAG.AssignOrdering(result.getNode(), SDNodeOrder);
      }
    } else { // LimitFloatPrecision > 12 && LimitFloatPrecision <= 18
      // For floating-point precision of 18:
      //
      //   LogOfMantissa =
      //     -2.1072184f +
      //       (4.2372794f +
      //         (-3.7029485f +
      //           (2.2781945f +
      //             (-0.87823314f +
      //               (0.19073739f - 0.17809712e-1f * x) * x) * x) * x) * x)*x;
      //
      // error 0.0000023660568, which is better than 18 bits
      SDValue t0 = DAG.getNode(ISD::FMUL, dl, MVT::f32, X,
                               getF32Constant(DAG, 0xbc91e5ac));
      SDValue t1 = DAG.getNode(ISD::FADD, dl, MVT::f32, t0,
                               getF32Constant(DAG, 0x3e4350aa));
      SDValue t2 = DAG.getNode(ISD::FMUL, dl, MVT::f32, t1, X);
      SDValue t3 = DAG.getNode(ISD::FSUB, dl, MVT::f32, t2,
                               getF32Constant(DAG, 0x3f60d3e3));
      SDValue t4 = DAG.getNode(ISD::FMUL, dl, MVT::f32, t3, X);
      SDValue t5 = DAG.getNode(ISD::FADD, dl, MVT::f32, t4,
                               getF32Constant(DAG, 0x4011cdf0));
      SDValue t6 = DAG.getNode(ISD::FMUL, dl, MVT::f32, t5, X);
      SDValue t7 = DAG.getNode(ISD::FSUB, dl, MVT::f32, t6,
                               getF32Constant(DAG, 0x406cfd1c));
      SDValue t8 = DAG.getNode(ISD::FMUL, dl, MVT::f32, t7, X);
      SDValue t9 = DAG.getNode(ISD::FADD, dl, MVT::f32, t8,
                               getF32Constant(DAG, 0x408797cb));
      SDValue t10 = DAG.getNode(ISD::FMUL, dl, MVT::f32, t9, X);
      SDValue LogOfMantissa = DAG.getNode(ISD::FSUB, dl, MVT::f32, t10,
                                          getF32Constant(DAG, 0x4006dcab));

      result = DAG.getNode(ISD::FADD, dl,
                           MVT::f32, LogOfExponent, LogOfMantissa);

      if (DisableScheduling) {
        DAG.AssignOrdering(t0.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t1.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t2.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t3.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t4.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t5.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t6.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t7.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t8.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t9.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t10.getNode(), SDNodeOrder);
        DAG.AssignOrdering(LogOfMantissa.getNode(), SDNodeOrder);
        DAG.AssignOrdering(result.getNode(), SDNodeOrder);
      }
    }
  } else {
    // No special expansion.
    result = DAG.getNode(ISD::FLOG, dl,
                         getValue(I.getOperand(1)).getValueType(),
                         getValue(I.getOperand(1)));

    if (DisableScheduling)
      DAG.AssignOrdering(result.getNode(), SDNodeOrder);
  }

  setValue(&I, result);
}

/// visitLog2 - Lower a log2 intrinsic. Handles the special sequences for
/// limited-precision mode.
void
SelectionDAGBuilder::visitLog2(CallInst &I) {
  SDValue result;
  DebugLoc dl = getCurDebugLoc();

  if (getValue(I.getOperand(1)).getValueType() == MVT::f32 &&
      LimitFloatPrecision > 0 && LimitFloatPrecision <= 18) {
    SDValue Op = getValue(I.getOperand(1));
    SDValue Op1 = DAG.getNode(ISD::BIT_CONVERT, dl, MVT::i32, Op);

    if (DisableScheduling)
      DAG.AssignOrdering(Op1.getNode(), SDNodeOrder);

    // Get the exponent.
    SDValue LogOfExponent = GetExponent(DAG, Op1, TLI, dl, SDNodeOrder);

    if (DisableScheduling)
      DAG.AssignOrdering(LogOfExponent.getNode(), SDNodeOrder);

    // Get the significand and build it into a floating-point number with
    // exponent of 1.
    SDValue X = GetSignificand(DAG, Op1, dl, SDNodeOrder);

    // Different possible minimax approximations of significand in
    // floating-point for various degrees of accuracy over [1,2].
    if (LimitFloatPrecision <= 6) {
      // For floating-point precision of 6:
      //
      //   Log2ofMantissa = -1.6749035f + (2.0246817f - .34484768f * x) * x;
      //
      // error 0.0049451742, which is more than 7 bits
      SDValue t0 = DAG.getNode(ISD::FMUL, dl, MVT::f32, X,
                               getF32Constant(DAG, 0xbeb08fe0));
      SDValue t1 = DAG.getNode(ISD::FADD, dl, MVT::f32, t0,
                               getF32Constant(DAG, 0x40019463));
      SDValue t2 = DAG.getNode(ISD::FMUL, dl, MVT::f32, t1, X);
      SDValue Log2ofMantissa = DAG.getNode(ISD::FSUB, dl, MVT::f32, t2,
                                           getF32Constant(DAG, 0x3fd6633d));

      result = DAG.getNode(ISD::FADD, dl,
                           MVT::f32, LogOfExponent, Log2ofMantissa);

      if (DisableScheduling) {
        DAG.AssignOrdering(t0.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t1.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t2.getNode(), SDNodeOrder);
        DAG.AssignOrdering(Log2ofMantissa.getNode(), SDNodeOrder);
        DAG.AssignOrdering(result.getNode(), SDNodeOrder);
      }
    } else if (LimitFloatPrecision > 6 && LimitFloatPrecision <= 12) {
      // For floating-point precision of 12:
      //
      //   Log2ofMantissa =
      //     -2.51285454f +
      //       (4.07009056f +
      //         (-2.12067489f +
      //           (.645142248f - 0.816157886e-1f * x) * x) * x) * x;
      //
      // error 0.0000876136000, which is better than 13 bits
      SDValue t0 = DAG.getNode(ISD::FMUL, dl, MVT::f32, X,
                               getF32Constant(DAG, 0xbda7262e));
      SDValue t1 = DAG.getNode(ISD::FADD, dl, MVT::f32, t0,
                               getF32Constant(DAG, 0x3f25280b));
      SDValue t2 = DAG.getNode(ISD::FMUL, dl, MVT::f32, t1, X);
      SDValue t3 = DAG.getNode(ISD::FSUB, dl, MVT::f32, t2,
                               getF32Constant(DAG, 0x4007b923));
      SDValue t4 = DAG.getNode(ISD::FMUL, dl, MVT::f32, t3, X);
      SDValue t5 = DAG.getNode(ISD::FADD, dl, MVT::f32, t4,
                               getF32Constant(DAG, 0x40823e2f));
      SDValue t6 = DAG.getNode(ISD::FMUL, dl, MVT::f32, t5, X);
      SDValue Log2ofMantissa = DAG.getNode(ISD::FSUB, dl, MVT::f32, t6,
                                           getF32Constant(DAG, 0x4020d29c));

      result = DAG.getNode(ISD::FADD, dl,
                           MVT::f32, LogOfExponent, Log2ofMantissa);

      if (DisableScheduling) {
        DAG.AssignOrdering(t0.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t1.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t2.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t3.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t4.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t5.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t6.getNode(), SDNodeOrder);
        DAG.AssignOrdering(Log2ofMantissa.getNode(), SDNodeOrder);
        DAG.AssignOrdering(result.getNode(), SDNodeOrder);
      }
    } else { // LimitFloatPrecision > 12 && LimitFloatPrecision <= 18
      // For floating-point precision of 18:
      //
      //   Log2ofMantissa =
      //     -3.0400495f +
      //       (6.1129976f +
      //         (-5.3420409f +
      //           (3.2865683f +
      //             (-1.2669343f +
      //               (0.27515199f -
      //                 0.25691327e-1f * x) * x) * x) * x) * x) * x;
      //
      // error 0.0000018516, which is better than 18 bits
      SDValue t0 = DAG.getNode(ISD::FMUL, dl, MVT::f32, X,
                               getF32Constant(DAG, 0xbcd2769e));
      SDValue t1 = DAG.getNode(ISD::FADD, dl, MVT::f32, t0,
                               getF32Constant(DAG, 0x3e8ce0b9));
      SDValue t2 = DAG.getNode(ISD::FMUL, dl, MVT::f32, t1, X);
      SDValue t3 = DAG.getNode(ISD::FSUB, dl, MVT::f32, t2,
                               getF32Constant(DAG, 0x3fa22ae7));
      SDValue t4 = DAG.getNode(ISD::FMUL, dl, MVT::f32, t3, X);
      SDValue t5 = DAG.getNode(ISD::FADD, dl, MVT::f32, t4,
                               getF32Constant(DAG, 0x40525723));
      SDValue t6 = DAG.getNode(ISD::FMUL, dl, MVT::f32, t5, X);
      SDValue t7 = DAG.getNode(ISD::FSUB, dl, MVT::f32, t6,
                               getF32Constant(DAG, 0x40aaf200));
      SDValue t8 = DAG.getNode(ISD::FMUL, dl, MVT::f32, t7, X);
      SDValue t9 = DAG.getNode(ISD::FADD, dl, MVT::f32, t8,
                               getF32Constant(DAG, 0x40c39dad));
      SDValue t10 = DAG.getNode(ISD::FMUL, dl, MVT::f32, t9, X);
      SDValue Log2ofMantissa = DAG.getNode(ISD::FSUB, dl, MVT::f32, t10,
                                           getF32Constant(DAG, 0x4042902c));

      result = DAG.getNode(ISD::FADD, dl,
                           MVT::f32, LogOfExponent, Log2ofMantissa);

      if (DisableScheduling) {
        DAG.AssignOrdering(t0.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t1.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t2.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t3.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t4.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t5.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t6.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t7.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t8.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t9.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t10.getNode(), SDNodeOrder);
        DAG.AssignOrdering(Log2ofMantissa.getNode(), SDNodeOrder);
        DAG.AssignOrdering(result.getNode(), SDNodeOrder);
      }
    }
  } else {
    // No special expansion.
    result = DAG.getNode(ISD::FLOG2, dl,
                         getValue(I.getOperand(1)).getValueType(),
                         getValue(I.getOperand(1)));

    if (DisableScheduling)
      DAG.AssignOrdering(result.getNode(), SDNodeOrder);
  }

  setValue(&I, result);
}

/// visitLog10 - Lower a log10 intrinsic. Handles the special sequences for
/// limited-precision mode.
void
SelectionDAGBuilder::visitLog10(CallInst &I) {
  SDValue result;
  DebugLoc dl = getCurDebugLoc();

  if (getValue(I.getOperand(1)).getValueType() == MVT::f32 &&
      LimitFloatPrecision > 0 && LimitFloatPrecision <= 18) {
    SDValue Op = getValue(I.getOperand(1));
    SDValue Op1 = DAG.getNode(ISD::BIT_CONVERT, dl, MVT::i32, Op);

    if (DisableScheduling)
      DAG.AssignOrdering(Op1.getNode(), SDNodeOrder);

    // Scale the exponent by log10(2) [0.30102999f].
    SDValue Exp = GetExponent(DAG, Op1, TLI, dl, SDNodeOrder);
    SDValue LogOfExponent = DAG.getNode(ISD::FMUL, dl, MVT::f32, Exp,
                                        getF32Constant(DAG, 0x3e9a209a));

    if (DisableScheduling)
      DAG.AssignOrdering(LogOfExponent.getNode(), SDNodeOrder);

    // Get the significand and build it into a floating-point number with
    // exponent of 1.
    SDValue X = GetSignificand(DAG, Op1, dl, SDNodeOrder);

    if (LimitFloatPrecision <= 6) {
      // For floating-point precision of 6:
      //
      //   Log10ofMantissa =
      //     -0.50419619f +
      //       (0.60948995f - 0.10380950f * x) * x;
      //
      // error 0.0014886165, which is 6 bits
      SDValue t0 = DAG.getNode(ISD::FMUL, dl, MVT::f32, X,
                               getF32Constant(DAG, 0xbdd49a13));
      SDValue t1 = DAG.getNode(ISD::FADD, dl, MVT::f32, t0,
                               getF32Constant(DAG, 0x3f1c0789));
      SDValue t2 = DAG.getNode(ISD::FMUL, dl, MVT::f32, t1, X);
      SDValue Log10ofMantissa = DAG.getNode(ISD::FSUB, dl, MVT::f32, t2,
                                            getF32Constant(DAG, 0x3f011300));

      result = DAG.getNode(ISD::FADD, dl,
                           MVT::f32, LogOfExponent, Log10ofMantissa);

      if (DisableScheduling) {
        DAG.AssignOrdering(t0.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t1.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t2.getNode(), SDNodeOrder);
        DAG.AssignOrdering(Log10ofMantissa.getNode(), SDNodeOrder);
        DAG.AssignOrdering(result.getNode(), SDNodeOrder);
      }
    } else if (LimitFloatPrecision > 6 && LimitFloatPrecision <= 12) {
      // For floating-point precision of 12:
      //
      //   Log10ofMantissa =
      //     -0.64831180f +
      //       (0.91751397f +
      //         (-0.31664806f + 0.47637168e-1f * x) * x) * x;
      //
      // error 0.00019228036, which is better than 12 bits
      SDValue t0 = DAG.getNode(ISD::FMUL, dl, MVT::f32, X,
                               getF32Constant(DAG, 0x3d431f31));
      SDValue t1 = DAG.getNode(ISD::FSUB, dl, MVT::f32, t0,
                               getF32Constant(DAG, 0x3ea21fb2));
      SDValue t2 = DAG.getNode(ISD::FMUL, dl, MVT::f32, t1, X);
      SDValue t3 = DAG.getNode(ISD::FADD, dl, MVT::f32, t2,
                               getF32Constant(DAG, 0x3f6ae232));
      SDValue t4 = DAG.getNode(ISD::FMUL, dl, MVT::f32, t3, X);
      SDValue Log10ofMantissa = DAG.getNode(ISD::FSUB, dl, MVT::f32, t4,
                                            getF32Constant(DAG, 0x3f25f7c3));

      result = DAG.getNode(ISD::FADD, dl,
                           MVT::f32, LogOfExponent, Log10ofMantissa);

      if (DisableScheduling) {
        DAG.AssignOrdering(t0.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t1.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t2.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t3.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t4.getNode(), SDNodeOrder);
        DAG.AssignOrdering(Log10ofMantissa.getNode(), SDNodeOrder);
        DAG.AssignOrdering(result.getNode(), SDNodeOrder);
      }
    } else { // LimitFloatPrecision > 12 && LimitFloatPrecision <= 18
      // For floating-point precision of 18:
      //
      //   Log10ofMantissa =
      //     -0.84299375f +
      //       (1.5327582f +
      //         (-1.0688956f +
      //           (0.49102474f +
      //             (-0.12539807f + 0.13508273e-1f * x) * x) * x) * x) * x;
      //
      // error 0.0000037995730, which is better than 18 bits
      SDValue t0 = DAG.getNode(ISD::FMUL, dl, MVT::f32, X,
                               getF32Constant(DAG, 0x3c5d51ce));
      SDValue t1 = DAG.getNode(ISD::FSUB, dl, MVT::f32, t0,
                               getF32Constant(DAG, 0x3e00685a));
      SDValue t2 = DAG.getNode(ISD::FMUL, dl, MVT::f32, t1, X);
      SDValue t3 = DAG.getNode(ISD::FADD, dl, MVT::f32, t2,
                               getF32Constant(DAG, 0x3efb6798));
      SDValue t4 = DAG.getNode(ISD::FMUL, dl, MVT::f32, t3, X);
      SDValue t5 = DAG.getNode(ISD::FSUB, dl, MVT::f32, t4,
                               getF32Constant(DAG, 0x3f88d192));
      SDValue t6 = DAG.getNode(ISD::FMUL, dl, MVT::f32, t5, X);
      SDValue t7 = DAG.getNode(ISD::FADD, dl, MVT::f32, t6,
                               getF32Constant(DAG, 0x3fc4316c));
      SDValue t8 = DAG.getNode(ISD::FMUL, dl, MVT::f32, t7, X);
      SDValue Log10ofMantissa = DAG.getNode(ISD::FSUB, dl, MVT::f32, t8,
                                            getF32Constant(DAG, 0x3f57ce70));

      result = DAG.getNode(ISD::FADD, dl,
                           MVT::f32, LogOfExponent, Log10ofMantissa);

      if (DisableScheduling) {
        DAG.AssignOrdering(t0.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t1.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t2.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t3.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t4.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t5.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t6.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t7.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t8.getNode(), SDNodeOrder);
        DAG.AssignOrdering(Log10ofMantissa.getNode(), SDNodeOrder);
        DAG.AssignOrdering(result.getNode(), SDNodeOrder);
      }
    }
  } else {
    // No special expansion.
    result = DAG.getNode(ISD::FLOG10, dl,
                         getValue(I.getOperand(1)).getValueType(),
                         getValue(I.getOperand(1)));

    if (DisableScheduling)
      DAG.AssignOrdering(result.getNode(), SDNodeOrder);
  }

  setValue(&I, result);
}

/// visitExp2 - Lower an exp2 intrinsic. Handles the special sequences for
/// limited-precision mode.
void
SelectionDAGBuilder::visitExp2(CallInst &I) {
  SDValue result;
  DebugLoc dl = getCurDebugLoc();

  if (getValue(I.getOperand(1)).getValueType() == MVT::f32 &&
      LimitFloatPrecision > 0 && LimitFloatPrecision <= 18) {
    SDValue Op = getValue(I.getOperand(1));

    SDValue IntegerPartOfX = DAG.getNode(ISD::FP_TO_SINT, dl, MVT::i32, Op);

    if (DisableScheduling)
      DAG.AssignOrdering(IntegerPartOfX.getNode(), SDNodeOrder);

    //   FractionalPartOfX = x - (float)IntegerPartOfX;
    SDValue t1 = DAG.getNode(ISD::SINT_TO_FP, dl, MVT::f32, IntegerPartOfX);
    SDValue X = DAG.getNode(ISD::FSUB, dl, MVT::f32, Op, t1);

    //   IntegerPartOfX <<= 23;
    IntegerPartOfX = DAG.getNode(ISD::SHL, dl, MVT::i32, IntegerPartOfX,
                                 DAG.getConstant(23, TLI.getPointerTy()));

    if (DisableScheduling) {
      DAG.AssignOrdering(t1.getNode(), SDNodeOrder);
      DAG.AssignOrdering(X.getNode(), SDNodeOrder);
      DAG.AssignOrdering(IntegerPartOfX.getNode(), SDNodeOrder);
    }

    if (LimitFloatPrecision <= 6) {
      // For floating-point precision of 6:
      //
      //   TwoToFractionalPartOfX =
      //     0.997535578f +
      //       (0.735607626f + 0.252464424f * x) * x;
      //
      // error 0.0144103317, which is 6 bits
      SDValue t2 = DAG.getNode(ISD::FMUL, dl, MVT::f32, X,
                               getF32Constant(DAG, 0x3e814304));
      SDValue t3 = DAG.getNode(ISD::FADD, dl, MVT::f32, t2,
                               getF32Constant(DAG, 0x3f3c50c8));
      SDValue t4 = DAG.getNode(ISD::FMUL, dl, MVT::f32, t3, X);
      SDValue t5 = DAG.getNode(ISD::FADD, dl, MVT::f32, t4,
                               getF32Constant(DAG, 0x3f7f5e7e));
      SDValue t6 = DAG.getNode(ISD::BIT_CONVERT, dl, MVT::i32, t5);
      SDValue TwoToFractionalPartOfX =
        DAG.getNode(ISD::ADD, dl, MVT::i32, t6, IntegerPartOfX);

      result = DAG.getNode(ISD::BIT_CONVERT, dl,
                           MVT::f32, TwoToFractionalPartOfX);

      if (DisableScheduling) {
        DAG.AssignOrdering(t2.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t3.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t4.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t5.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t6.getNode(), SDNodeOrder);
        DAG.AssignOrdering(TwoToFractionalPartOfX.getNode(), SDNodeOrder);
        DAG.AssignOrdering(result.getNode(), SDNodeOrder);
      }
    } else if (LimitFloatPrecision > 6 && LimitFloatPrecision <= 12) {
      // For floating-point precision of 12:
      //
      //   TwoToFractionalPartOfX =
      //     0.999892986f +
      //       (0.696457318f +
      //         (0.224338339f + 0.792043434e-1f * x) * x) * x;
      //
      // error 0.000107046256, which is 13 to 14 bits
      SDValue t2 = DAG.getNode(ISD::FMUL, dl, MVT::f32, X,
                               getF32Constant(DAG, 0x3da235e3));
      SDValue t3 = DAG.getNode(ISD::FADD, dl, MVT::f32, t2,
                               getF32Constant(DAG, 0x3e65b8f3));
      SDValue t4 = DAG.getNode(ISD::FMUL, dl, MVT::f32, t3, X);
      SDValue t5 = DAG.getNode(ISD::FADD, dl, MVT::f32, t4,
                               getF32Constant(DAG, 0x3f324b07));
      SDValue t6 = DAG.getNode(ISD::FMUL, dl, MVT::f32, t5, X);
      SDValue t7 = DAG.getNode(ISD::FADD, dl, MVT::f32, t6,
                               getF32Constant(DAG, 0x3f7ff8fd));
      SDValue t8 = DAG.getNode(ISD::BIT_CONVERT, dl, MVT::i32, t7);
      SDValue TwoToFractionalPartOfX =
        DAG.getNode(ISD::ADD, dl, MVT::i32, t8, IntegerPartOfX);

      result = DAG.getNode(ISD::BIT_CONVERT, dl,
                           MVT::f32, TwoToFractionalPartOfX);

      if (DisableScheduling) {
        DAG.AssignOrdering(t2.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t3.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t4.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t5.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t6.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t7.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t8.getNode(), SDNodeOrder);
        DAG.AssignOrdering(TwoToFractionalPartOfX.getNode(), SDNodeOrder);
        DAG.AssignOrdering(result.getNode(), SDNodeOrder);
      }
    } else { // LimitFloatPrecision > 12 && LimitFloatPrecision <= 18
      // For floating-point precision of 18:
      //
      //   TwoToFractionalPartOfX =
      //     0.999999982f +
      //       (0.693148872f +
      //         (0.240227044f +
      //           (0.554906021e-1f +
      //             (0.961591928e-2f +
      //               (0.136028312e-2f + 0.157059148e-3f *x)*x)*x)*x)*x)*x;
      // error 2.47208000*10^(-7), which is better than 18 bits
      SDValue t2 = DAG.getNode(ISD::FMUL, dl, MVT::f32, X,
                               getF32Constant(DAG, 0x3924b03e));
      SDValue t3 = DAG.getNode(ISD::FADD, dl, MVT::f32, t2,
                               getF32Constant(DAG, 0x3ab24b87));
      SDValue t4 = DAG.getNode(ISD::FMUL, dl, MVT::f32, t3, X);
      SDValue t5 = DAG.getNode(ISD::FADD, dl, MVT::f32, t4,
                               getF32Constant(DAG, 0x3c1d8c17));
      SDValue t6 = DAG.getNode(ISD::FMUL, dl, MVT::f32, t5, X);
      SDValue t7 = DAG.getNode(ISD::FADD, dl, MVT::f32, t6,
                               getF32Constant(DAG, 0x3d634a1d));
      SDValue t8 = DAG.getNode(ISD::FMUL, dl, MVT::f32, t7, X);
      SDValue t9 = DAG.getNode(ISD::FADD, dl, MVT::f32, t8,
                               getF32Constant(DAG, 0x3e75fe14));
      SDValue t10 = DAG.getNode(ISD::FMUL, dl, MVT::f32, t9, X);
      SDValue t11 = DAG.getNode(ISD::FADD, dl, MVT::f32, t10,
                                getF32Constant(DAG, 0x3f317234));
      SDValue t12 = DAG.getNode(ISD::FMUL, dl, MVT::f32, t11, X);
      SDValue t13 = DAG.getNode(ISD::FADD, dl, MVT::f32, t12,
                                getF32Constant(DAG, 0x3f800000));
      SDValue t14 = DAG.getNode(ISD::BIT_CONVERT, dl, MVT::i32, t13);
      SDValue TwoToFractionalPartOfX =
        DAG.getNode(ISD::ADD, dl, MVT::i32, t14, IntegerPartOfX);

      result = DAG.getNode(ISD::BIT_CONVERT, dl,
                           MVT::f32, TwoToFractionalPartOfX);

      if (DisableScheduling) {
        DAG.AssignOrdering(t2.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t3.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t4.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t5.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t6.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t7.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t8.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t9.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t10.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t11.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t12.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t13.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t14.getNode(), SDNodeOrder);
        DAG.AssignOrdering(TwoToFractionalPartOfX.getNode(), SDNodeOrder);
        DAG.AssignOrdering(result.getNode(), SDNodeOrder);
      }
    }
  } else {
    // No special expansion.
    result = DAG.getNode(ISD::FEXP2, dl,
                         getValue(I.getOperand(1)).getValueType(),
                         getValue(I.getOperand(1)));

    if (DisableScheduling)
      DAG.AssignOrdering(result.getNode(), SDNodeOrder);
  }

  setValue(&I, result);
}

/// visitPow - Lower a pow intrinsic. Handles the special sequences for
/// limited-precision mode with x == 10.0f.
void
SelectionDAGBuilder::visitPow(CallInst &I) {
  SDValue result;
  Value *Val = I.getOperand(1);
  DebugLoc dl = getCurDebugLoc();
  bool IsExp10 = false;

  if (getValue(Val).getValueType() == MVT::f32 &&
      getValue(I.getOperand(2)).getValueType() == MVT::f32 &&
      LimitFloatPrecision > 0 && LimitFloatPrecision <= 18) {
    if (Constant *C = const_cast<Constant*>(dyn_cast<Constant>(Val))) {
      if (ConstantFP *CFP = dyn_cast<ConstantFP>(C)) {
        APFloat Ten(10.0f);
        IsExp10 = CFP->getValueAPF().bitwiseIsEqual(Ten);
      }
    }
  }

  if (IsExp10 && LimitFloatPrecision > 0 && LimitFloatPrecision <= 18) {
    SDValue Op = getValue(I.getOperand(2));

    // Put the exponent in the right bit position for later addition to the
    // final result:
    //
    //   #define LOG2OF10 3.3219281f
    //   IntegerPartOfX = (int32_t)(x * LOG2OF10);
    SDValue t0 = DAG.getNode(ISD::FMUL, dl, MVT::f32, Op,
                             getF32Constant(DAG, 0x40549a78));
    SDValue IntegerPartOfX = DAG.getNode(ISD::FP_TO_SINT, dl, MVT::i32, t0);

    //   FractionalPartOfX = x - (float)IntegerPartOfX;
    SDValue t1 = DAG.getNode(ISD::SINT_TO_FP, dl, MVT::f32, IntegerPartOfX);
    SDValue X = DAG.getNode(ISD::FSUB, dl, MVT::f32, t0, t1);

    if (DisableScheduling) {
      DAG.AssignOrdering(t0.getNode(), SDNodeOrder);
      DAG.AssignOrdering(t1.getNode(), SDNodeOrder);
      DAG.AssignOrdering(IntegerPartOfX.getNode(), SDNodeOrder);
      DAG.AssignOrdering(X.getNode(), SDNodeOrder);
    }

    //   IntegerPartOfX <<= 23;
    IntegerPartOfX = DAG.getNode(ISD::SHL, dl, MVT::i32, IntegerPartOfX,
                                 DAG.getConstant(23, TLI.getPointerTy()));

    if (DisableScheduling)
      DAG.AssignOrdering(IntegerPartOfX.getNode(), SDNodeOrder);

    if (LimitFloatPrecision <= 6) {
      // For floating-point precision of 6:
      //
      //   twoToFractionalPartOfX =
      //     0.997535578f +
      //       (0.735607626f + 0.252464424f * x) * x;
      //
      // error 0.0144103317, which is 6 bits
      SDValue t2 = DAG.getNode(ISD::FMUL, dl, MVT::f32, X,
                               getF32Constant(DAG, 0x3e814304));
      SDValue t3 = DAG.getNode(ISD::FADD, dl, MVT::f32, t2,
                               getF32Constant(DAG, 0x3f3c50c8));
      SDValue t4 = DAG.getNode(ISD::FMUL, dl, MVT::f32, t3, X);
      SDValue t5 = DAG.getNode(ISD::FADD, dl, MVT::f32, t4,
                               getF32Constant(DAG, 0x3f7f5e7e));
      SDValue t6 = DAG.getNode(ISD::BIT_CONVERT, dl, MVT::i32, t5);
      SDValue TwoToFractionalPartOfX =
        DAG.getNode(ISD::ADD, dl, MVT::i32, t6, IntegerPartOfX);

      result = DAG.getNode(ISD::BIT_CONVERT, dl,
                           MVT::f32, TwoToFractionalPartOfX);

      if (DisableScheduling) {
        DAG.AssignOrdering(t2.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t3.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t4.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t5.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t6.getNode(), SDNodeOrder);
        DAG.AssignOrdering(TwoToFractionalPartOfX.getNode(), SDNodeOrder);
        DAG.AssignOrdering(result.getNode(), SDNodeOrder);
      }
    } else if (LimitFloatPrecision > 6 && LimitFloatPrecision <= 12) {
      // For floating-point precision of 12:
      //
      //   TwoToFractionalPartOfX =
      //     0.999892986f +
      //       (0.696457318f +
      //         (0.224338339f + 0.792043434e-1f * x) * x) * x;
      //
      // error 0.000107046256, which is 13 to 14 bits
      SDValue t2 = DAG.getNode(ISD::FMUL, dl, MVT::f32, X,
                               getF32Constant(DAG, 0x3da235e3));
      SDValue t3 = DAG.getNode(ISD::FADD, dl, MVT::f32, t2,
                               getF32Constant(DAG, 0x3e65b8f3));
      SDValue t4 = DAG.getNode(ISD::FMUL, dl, MVT::f32, t3, X);
      SDValue t5 = DAG.getNode(ISD::FADD, dl, MVT::f32, t4,
                               getF32Constant(DAG, 0x3f324b07));
      SDValue t6 = DAG.getNode(ISD::FMUL, dl, MVT::f32, t5, X);
      SDValue t7 = DAG.getNode(ISD::FADD, dl, MVT::f32, t6,
                               getF32Constant(DAG, 0x3f7ff8fd));
      SDValue t8 = DAG.getNode(ISD::BIT_CONVERT, dl, MVT::i32, t7);
      SDValue TwoToFractionalPartOfX =
        DAG.getNode(ISD::ADD, dl, MVT::i32, t8, IntegerPartOfX);

      result = DAG.getNode(ISD::BIT_CONVERT, dl,
                           MVT::f32, TwoToFractionalPartOfX);

      if (DisableScheduling) {
        DAG.AssignOrdering(t2.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t3.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t4.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t5.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t6.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t7.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t8.getNode(), SDNodeOrder);
        DAG.AssignOrdering(TwoToFractionalPartOfX.getNode(), SDNodeOrder);
        DAG.AssignOrdering(result.getNode(), SDNodeOrder);
      }
    } else { // LimitFloatPrecision > 12 && LimitFloatPrecision <= 18
      // For floating-point precision of 18:
      //
      //   TwoToFractionalPartOfX =
      //     0.999999982f +
      //       (0.693148872f +
      //         (0.240227044f +
      //           (0.554906021e-1f +
      //             (0.961591928e-2f +
      //               (0.136028312e-2f + 0.157059148e-3f *x)*x)*x)*x)*x)*x;
      // error 2.47208000*10^(-7), which is better than 18 bits
      SDValue t2 = DAG.getNode(ISD::FMUL, dl, MVT::f32, X,
                               getF32Constant(DAG, 0x3924b03e));
      SDValue t3 = DAG.getNode(ISD::FADD, dl, MVT::f32, t2,
                               getF32Constant(DAG, 0x3ab24b87));
      SDValue t4 = DAG.getNode(ISD::FMUL, dl, MVT::f32, t3, X);
      SDValue t5 = DAG.getNode(ISD::FADD, dl, MVT::f32, t4,
                               getF32Constant(DAG, 0x3c1d8c17));
      SDValue t6 = DAG.getNode(ISD::FMUL, dl, MVT::f32, t5, X);
      SDValue t7 = DAG.getNode(ISD::FADD, dl, MVT::f32, t6,
                               getF32Constant(DAG, 0x3d634a1d));
      SDValue t8 = DAG.getNode(ISD::FMUL, dl, MVT::f32, t7, X);
      SDValue t9 = DAG.getNode(ISD::FADD, dl, MVT::f32, t8,
                               getF32Constant(DAG, 0x3e75fe14));
      SDValue t10 = DAG.getNode(ISD::FMUL, dl, MVT::f32, t9, X);
      SDValue t11 = DAG.getNode(ISD::FADD, dl, MVT::f32, t10,
                                getF32Constant(DAG, 0x3f317234));
      SDValue t12 = DAG.getNode(ISD::FMUL, dl, MVT::f32, t11, X);
      SDValue t13 = DAG.getNode(ISD::FADD, dl, MVT::f32, t12,
                                getF32Constant(DAG, 0x3f800000));
      SDValue t14 = DAG.getNode(ISD::BIT_CONVERT, dl, MVT::i32, t13);
      SDValue TwoToFractionalPartOfX =
        DAG.getNode(ISD::ADD, dl, MVT::i32, t14, IntegerPartOfX);

      result = DAG.getNode(ISD::BIT_CONVERT, dl,
                           MVT::f32, TwoToFractionalPartOfX);

      if (DisableScheduling) {
        DAG.AssignOrdering(t2.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t3.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t4.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t5.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t6.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t7.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t8.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t9.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t10.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t11.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t12.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t13.getNode(), SDNodeOrder);
        DAG.AssignOrdering(t14.getNode(), SDNodeOrder);
        DAG.AssignOrdering(TwoToFractionalPartOfX.getNode(), SDNodeOrder);
        DAG.AssignOrdering(result.getNode(), SDNodeOrder);
      }
    }
  } else {
    // No special expansion.
    result = DAG.getNode(ISD::FPOW, dl,
                         getValue(I.getOperand(1)).getValueType(),
                         getValue(I.getOperand(1)),
                         getValue(I.getOperand(2)));

    if (DisableScheduling)
      DAG.AssignOrdering(result.getNode(), SDNodeOrder);
  }

  setValue(&I, result);
}

/// visitIntrinsicCall - Lower the call to the specified intrinsic function.  If
/// we want to emit this as a call to a named external function, return the name
/// otherwise lower it and return null.
const char *
SelectionDAGBuilder::visitIntrinsicCall(CallInst &I, unsigned Intrinsic) {
  DebugLoc dl = getCurDebugLoc();
  switch (Intrinsic) {
  default:
    // By default, turn this into a target intrinsic node.
    visitTargetIntrinsic(I, Intrinsic);
    return 0;
  case Intrinsic::vastart:  visitVAStart(I); return 0;
  case Intrinsic::vaend:    visitVAEnd(I); return 0;
  case Intrinsic::vacopy:   visitVACopy(I); return 0;
  case Intrinsic::returnaddress:
    setValue(&I, DAG.getNode(ISD::RETURNADDR, dl, TLI.getPointerTy(),
                             getValue(I.getOperand(1))));
    return 0;
  case Intrinsic::frameaddress:
    setValue(&I, DAG.getNode(ISD::FRAMEADDR, dl, TLI.getPointerTy(),
                             getValue(I.getOperand(1))));
    return 0;
  case Intrinsic::setjmp:
    return "_setjmp"+!TLI.usesUnderscoreSetJmp();
    break;
  case Intrinsic::longjmp:
    return "_longjmp"+!TLI.usesUnderscoreLongJmp();
    break;
  case Intrinsic::memcpy: {
    SDValue Op1 = getValue(I.getOperand(1));
    SDValue Op2 = getValue(I.getOperand(2));
    SDValue Op3 = getValue(I.getOperand(3));
    unsigned Align = cast<ConstantInt>(I.getOperand(4))->getZExtValue();
    DAG.setRoot(DAG.getMemcpy(getRoot(), dl, Op1, Op2, Op3, Align, false,
                              I.getOperand(1), 0, I.getOperand(2), 0));
    return 0;
  }
  case Intrinsic::memset: {
    SDValue Op1 = getValue(I.getOperand(1));
    SDValue Op2 = getValue(I.getOperand(2));
    SDValue Op3 = getValue(I.getOperand(3));
    unsigned Align = cast<ConstantInt>(I.getOperand(4))->getZExtValue();
    DAG.setRoot(DAG.getMemset(getRoot(), dl, Op1, Op2, Op3, Align,
                              I.getOperand(1), 0));
    return 0;
  }
  case Intrinsic::memmove: {
    SDValue Op1 = getValue(I.getOperand(1));
    SDValue Op2 = getValue(I.getOperand(2));
    SDValue Op3 = getValue(I.getOperand(3));
    unsigned Align = cast<ConstantInt>(I.getOperand(4))->getZExtValue();

    // If the source and destination are known to not be aliases, we can
    // lower memmove as memcpy.
    uint64_t Size = -1ULL;
    if (ConstantSDNode *C = dyn_cast<ConstantSDNode>(Op3))
      Size = C->getZExtValue();
    if (AA->alias(I.getOperand(1), Size, I.getOperand(2), Size) ==
        AliasAnalysis::NoAlias) {
      DAG.setRoot(DAG.getMemcpy(getRoot(), dl, Op1, Op2, Op3, Align, false,
                                I.getOperand(1), 0, I.getOperand(2), 0));
      return 0;
    }

    DAG.setRoot(DAG.getMemmove(getRoot(), dl, Op1, Op2, Op3, Align,
                               I.getOperand(1), 0, I.getOperand(2), 0));
    return 0;
  }
  case Intrinsic::dbg_stoppoint: 
  case Intrinsic::dbg_region_start:
  case Intrinsic::dbg_region_end:
  case Intrinsic::dbg_func_start:
    // FIXME - Remove this instructions once the dust settles.
    return 0;
  case Intrinsic::dbg_declare: {
    if (OptLevel != CodeGenOpt::None) 
      // FIXME: Variable debug info is not supported here.
      return 0;
    DwarfWriter *DW = DAG.getDwarfWriter();
    if (!DW)
      return 0;
    DbgDeclareInst &DI = cast<DbgDeclareInst>(I);
    if (!isValidDebugInfoIntrinsic(DI, CodeGenOpt::None))
      return 0;

    MDNode *Variable = DI.getVariable();
    Value *Address = DI.getAddress();
    if (BitCastInst *BCI = dyn_cast<BitCastInst>(Address))
      Address = BCI->getOperand(0);
    AllocaInst *AI = dyn_cast<AllocaInst>(Address);
    // Don't handle byval struct arguments or VLAs, for example.
    if (!AI)
      return 0;
    DenseMap<const AllocaInst*, int>::iterator SI =
      FuncInfo.StaticAllocaMap.find(AI);
    if (SI == FuncInfo.StaticAllocaMap.end()) 
      return 0; // VLAs.
    int FI = SI->second;

    MachineModuleInfo *MMI = DAG.getMachineModuleInfo();
    if (MMI) {
      MetadataContext &TheMetadata = 
        DI.getParent()->getContext().getMetadata();
      unsigned MDDbgKind = TheMetadata.getMDKind("dbg");
      MDNode *Dbg = TheMetadata.getMD(MDDbgKind, &DI);
      MMI->setVariableDbgInfo(Variable, FI, Dbg);
    }
    return 0;
  }
  case Intrinsic::eh_exception: {
    // Insert the EXCEPTIONADDR instruction.
    assert(CurMBB->isLandingPad() &&"Call to eh.exception not in landing pad!");
    SDVTList VTs = DAG.getVTList(TLI.getPointerTy(), MVT::Other);
    SDValue Ops[1];
    Ops[0] = DAG.getRoot();
    SDValue Op = DAG.getNode(ISD::EXCEPTIONADDR, dl, VTs, Ops, 1);
    setValue(&I, Op);
    DAG.setRoot(Op.getValue(1));
    return 0;
  }

  case Intrinsic::eh_selector: {
    MachineModuleInfo *MMI = DAG.getMachineModuleInfo();

    if (CurMBB->isLandingPad())
      AddCatchInfo(I, MMI, CurMBB);
    else {
#ifndef NDEBUG
      FuncInfo.CatchInfoLost.insert(&I);
#endif
      // FIXME: Mark exception selector register as live in.  Hack for PR1508.
      unsigned Reg = TLI.getExceptionSelectorRegister();
      if (Reg) CurMBB->addLiveIn(Reg);
    }

    // Insert the EHSELECTION instruction.
    SDVTList VTs = DAG.getVTList(TLI.getPointerTy(), MVT::Other);
    SDValue Ops[2];
    Ops[0] = getValue(I.getOperand(1));
    Ops[1] = getRoot();
    SDValue Op = DAG.getNode(ISD::EHSELECTION, dl, VTs, Ops, 2);

    DAG.setRoot(Op.getValue(1));

    setValue(&I, DAG.getSExtOrTrunc(Op, dl, MVT::i32));
    return 0;
  }

  case Intrinsic::eh_typeid_for: {
    MachineModuleInfo *MMI = DAG.getMachineModuleInfo();

    if (MMI) {
      // Find the type id for the given typeinfo.
      GlobalVariable *GV = ExtractTypeInfo(I.getOperand(1));

      unsigned TypeID = MMI->getTypeIDFor(GV);
      setValue(&I, DAG.getConstant(TypeID, MVT::i32));
    } else {
      // Return something different to eh_selector.
      setValue(&I, DAG.getConstant(1, MVT::i32));
    }

    return 0;
  }

  case Intrinsic::eh_return_i32:
  case Intrinsic::eh_return_i64:
    if (MachineModuleInfo *MMI = DAG.getMachineModuleInfo()) {
      MMI->setCallsEHReturn(true);
      DAG.setRoot(DAG.getNode(ISD::EH_RETURN, dl,
                              MVT::Other,
                              getControlRoot(),
                              getValue(I.getOperand(1)),
                              getValue(I.getOperand(2))));
    } else {
      setValue(&I, DAG.getConstant(0, TLI.getPointerTy()));
    }

    return 0;
  case Intrinsic::eh_unwind_init:
    if (MachineModuleInfo *MMI = DAG.getMachineModuleInfo()) {
      MMI->setCallsUnwindInit(true);
    }

    return 0;

  case Intrinsic::eh_dwarf_cfa: {
    EVT VT = getValue(I.getOperand(1)).getValueType();
    SDValue CfaArg = DAG.getSExtOrTrunc(getValue(I.getOperand(1)), dl,
                                        TLI.getPointerTy());

    SDValue Offset = DAG.getNode(ISD::ADD, dl,
                                 TLI.getPointerTy(),
                                 DAG.getNode(ISD::FRAME_TO_ARGS_OFFSET, dl,
                                             TLI.getPointerTy()),
                                 CfaArg);
    setValue(&I, DAG.getNode(ISD::ADD, dl,
                             TLI.getPointerTy(),
                             DAG.getNode(ISD::FRAMEADDR, dl,
                                         TLI.getPointerTy(),
                                         DAG.getConstant(0,
                                                         TLI.getPointerTy())),
                             Offset));
    return 0;
  }
  case Intrinsic::convertff:
  case Intrinsic::convertfsi:
  case Intrinsic::convertfui:
  case Intrinsic::convertsif:
  case Intrinsic::convertuif:
  case Intrinsic::convertss:
  case Intrinsic::convertsu:
  case Intrinsic::convertus:
  case Intrinsic::convertuu: {
    ISD::CvtCode Code = ISD::CVT_INVALID;
    switch (Intrinsic) {
    case Intrinsic::convertff:  Code = ISD::CVT_FF; break;
    case Intrinsic::convertfsi: Code = ISD::CVT_FS; break;
    case Intrinsic::convertfui: Code = ISD::CVT_FU; break;
    case Intrinsic::convertsif: Code = ISD::CVT_SF; break;
    case Intrinsic::convertuif: Code = ISD::CVT_UF; break;
    case Intrinsic::convertss:  Code = ISD::CVT_SS; break;
    case Intrinsic::convertsu:  Code = ISD::CVT_SU; break;
    case Intrinsic::convertus:  Code = ISD::CVT_US; break;
    case Intrinsic::convertuu:  Code = ISD::CVT_UU; break;
    }
    EVT DestVT = TLI.getValueType(I.getType());
    Value* Op1 = I.getOperand(1);
    setValue(&I, DAG.getConvertRndSat(DestVT, getCurDebugLoc(), getValue(Op1),
                                DAG.getValueType(DestVT),
                                DAG.getValueType(getValue(Op1).getValueType()),
                                getValue(I.getOperand(2)),
                                getValue(I.getOperand(3)),
                                Code));
    return 0;
  }

  case Intrinsic::sqrt:
    setValue(&I, DAG.getNode(ISD::FSQRT, dl,
                             getValue(I.getOperand(1)).getValueType(),
                             getValue(I.getOperand(1))));
    return 0;
  case Intrinsic::powi:
    setValue(&I, DAG.getNode(ISD::FPOWI, dl,
                             getValue(I.getOperand(1)).getValueType(),
                             getValue(I.getOperand(1)),
                             getValue(I.getOperand(2))));
    return 0;
  case Intrinsic::sin:
    setValue(&I, DAG.getNode(ISD::FSIN, dl,
                             getValue(I.getOperand(1)).getValueType(),
                             getValue(I.getOperand(1))));
    return 0;
  case Intrinsic::cos:
    setValue(&I, DAG.getNode(ISD::FCOS, dl,
                             getValue(I.getOperand(1)).getValueType(),
                             getValue(I.getOperand(1))));
    return 0;
  case Intrinsic::log:
    visitLog(I);
    return 0;
  case Intrinsic::log2:
    visitLog2(I);
    return 0;
  case Intrinsic::log10:
    visitLog10(I);
    return 0;
  case Intrinsic::exp:
    visitExp(I);
    return 0;
  case Intrinsic::exp2:
    visitExp2(I);
    return 0;
  case Intrinsic::pow:
    visitPow(I);
    return 0;
  case Intrinsic::pcmarker: {
    SDValue Tmp = getValue(I.getOperand(1));
    DAG.setRoot(DAG.getNode(ISD::PCMARKER, dl, MVT::Other, getRoot(), Tmp));
    return 0;
  }
  case Intrinsic::readcyclecounter: {
    SDValue Op = getRoot();
    SDValue Tmp = DAG.getNode(ISD::READCYCLECOUNTER, dl,
                              DAG.getVTList(MVT::i64, MVT::Other),
                              &Op, 1);
    setValue(&I, Tmp);
    DAG.setRoot(Tmp.getValue(1));
    return 0;
  }
  case Intrinsic::bswap:
    setValue(&I, DAG.getNode(ISD::BSWAP, dl,
                             getValue(I.getOperand(1)).getValueType(),
                             getValue(I.getOperand(1))));
    return 0;
  case Intrinsic::cttz: {
    SDValue Arg = getValue(I.getOperand(1));
    EVT Ty = Arg.getValueType();
    SDValue result = DAG.getNode(ISD::CTTZ, dl, Ty, Arg);
    setValue(&I, result);
    return 0;
  }
  case Intrinsic::ctlz: {
    SDValue Arg = getValue(I.getOperand(1));
    EVT Ty = Arg.getValueType();
    SDValue result = DAG.getNode(ISD::CTLZ, dl, Ty, Arg);
    setValue(&I, result);
    return 0;
  }
  case Intrinsic::ctpop: {
    SDValue Arg = getValue(I.getOperand(1));
    EVT Ty = Arg.getValueType();
    SDValue result = DAG.getNode(ISD::CTPOP, dl, Ty, Arg);
    setValue(&I, result);
    return 0;
  }
  case Intrinsic::stacksave: {
    SDValue Op = getRoot();
    SDValue Tmp = DAG.getNode(ISD::STACKSAVE, dl,
              DAG.getVTList(TLI.getPointerTy(), MVT::Other), &Op, 1);
    setValue(&I, Tmp);
    DAG.setRoot(Tmp.getValue(1));
    return 0;
  }
  case Intrinsic::stackrestore: {
    SDValue Tmp = getValue(I.getOperand(1));
    DAG.setRoot(DAG.getNode(ISD::STACKRESTORE, dl, MVT::Other, getRoot(), Tmp));
    return 0;
  }
  case Intrinsic::stackprotector: {
    // Emit code into the DAG to store the stack guard onto the stack.
    MachineFunction &MF = DAG.getMachineFunction();
    MachineFrameInfo *MFI = MF.getFrameInfo();
    EVT PtrTy = TLI.getPointerTy();

    SDValue Src = getValue(I.getOperand(1));   // The guard's value.
    AllocaInst *Slot = cast<AllocaInst>(I.getOperand(2));

    int FI = FuncInfo.StaticAllocaMap[Slot];
    MFI->setStackProtectorIndex(FI);

    SDValue FIN = DAG.getFrameIndex(FI, PtrTy);

    // Store the stack protector onto the stack.
    SDValue Result = DAG.getStore(getRoot(), getCurDebugLoc(), Src, FIN,
                                  PseudoSourceValue::getFixedStack(FI),
                                  0, true);
    setValue(&I, Result);
    DAG.setRoot(Result);
    return 0;
  }
  case Intrinsic::objectsize: {
    // If we don't know by now, we're never going to know.
    ConstantInt *CI = dyn_cast<ConstantInt>(I.getOperand(2));

    assert(CI && "Non-constant type in __builtin_object_size?");

    SDValue Arg = getValue(I.getOperand(0));
    EVT Ty = Arg.getValueType();

    if (CI->getZExtValue() < 2)
      setValue(&I, DAG.getConstant(-1ULL, Ty));
    else
      setValue(&I, DAG.getConstant(0, Ty));
    return 0;
  }
  case Intrinsic::var_annotation:
    // Discard annotate attributes
    return 0;

  case Intrinsic::init_trampoline: {
    const Function *F = cast<Function>(I.getOperand(2)->stripPointerCasts());

    SDValue Ops[6];
    Ops[0] = getRoot();
    Ops[1] = getValue(I.getOperand(1));
    Ops[2] = getValue(I.getOperand(2));
    Ops[3] = getValue(I.getOperand(3));
    Ops[4] = DAG.getSrcValue(I.getOperand(1));
    Ops[5] = DAG.getSrcValue(F);

    SDValue Tmp = DAG.getNode(ISD::TRAMPOLINE, dl,
                              DAG.getVTList(TLI.getPointerTy(), MVT::Other),
                              Ops, 6);

    setValue(&I, Tmp);
    DAG.setRoot(Tmp.getValue(1));
    return 0;
  }

  case Intrinsic::gcroot:
    if (GFI) {
      Value *Alloca = I.getOperand(1);
      Constant *TypeMap = cast<Constant>(I.getOperand(2));

      FrameIndexSDNode *FI = cast<FrameIndexSDNode>(getValue(Alloca).getNode());
      GFI->addStackRoot(FI->getIndex(), TypeMap);
    }
    return 0;

  case Intrinsic::gcread:
  case Intrinsic::gcwrite:
    llvm_unreachable("GC failed to lower gcread/gcwrite intrinsics!");
    return 0;

  case Intrinsic::flt_rounds: {
    setValue(&I, DAG.getNode(ISD::FLT_ROUNDS_, dl, MVT::i32));
    return 0;
  }

  case Intrinsic::trap: {
    DAG.setRoot(DAG.getNode(ISD::TRAP, dl,MVT::Other, getRoot()));
    return 0;
  }

  case Intrinsic::uadd_with_overflow:
    return implVisitAluOverflow(I, ISD::UADDO);
  case Intrinsic::sadd_with_overflow:
    return implVisitAluOverflow(I, ISD::SADDO);
  case Intrinsic::usub_with_overflow:
    return implVisitAluOverflow(I, ISD::USUBO);
  case Intrinsic::ssub_with_overflow:
    return implVisitAluOverflow(I, ISD::SSUBO);
  case Intrinsic::umul_with_overflow:
    return implVisitAluOverflow(I, ISD::UMULO);
  case Intrinsic::smul_with_overflow:
    return implVisitAluOverflow(I, ISD::SMULO);

  case Intrinsic::prefetch: {
    SDValue Ops[4];
    Ops[0] = getRoot();
    Ops[1] = getValue(I.getOperand(1));
    Ops[2] = getValue(I.getOperand(2));
    Ops[3] = getValue(I.getOperand(3));
    DAG.setRoot(DAG.getNode(ISD::PREFETCH, dl, MVT::Other, &Ops[0], 4));
    return 0;
  }

  case Intrinsic::memory_barrier: {
    SDValue Ops[6];
    Ops[0] = getRoot();
    for (int x = 1; x < 6; ++x)
      Ops[x] = getValue(I.getOperand(x));

    DAG.setRoot(DAG.getNode(ISD::MEMBARRIER, dl, MVT::Other, &Ops[0], 6));
    return 0;
  }
  case Intrinsic::atomic_cmp_swap: {
    SDValue Root = getRoot();
    SDValue L =
      DAG.getAtomic(ISD::ATOMIC_CMP_SWAP, getCurDebugLoc(),
                    getValue(I.getOperand(2)).getValueType().getSimpleVT(),
                    Root,
                    getValue(I.getOperand(1)),
                    getValue(I.getOperand(2)),
                    getValue(I.getOperand(3)),
                    I.getOperand(1));
    setValue(&I, L);
    DAG.setRoot(L.getValue(1));
    return 0;
  }
  case Intrinsic::atomic_load_add:
    return implVisitBinaryAtomic(I, ISD::ATOMIC_LOAD_ADD);
  case Intrinsic::atomic_load_sub:
    return implVisitBinaryAtomic(I, ISD::ATOMIC_LOAD_SUB);
  case Intrinsic::atomic_load_or:
    return implVisitBinaryAtomic(I, ISD::ATOMIC_LOAD_OR);
  case Intrinsic::atomic_load_xor:
    return implVisitBinaryAtomic(I, ISD::ATOMIC_LOAD_XOR);
  case Intrinsic::atomic_load_and:
    return implVisitBinaryAtomic(I, ISD::ATOMIC_LOAD_AND);
  case Intrinsic::atomic_load_nand:
    return implVisitBinaryAtomic(I, ISD::ATOMIC_LOAD_NAND);
  case Intrinsic::atomic_load_max:
    return implVisitBinaryAtomic(I, ISD::ATOMIC_LOAD_MAX);
  case Intrinsic::atomic_load_min:
    return implVisitBinaryAtomic(I, ISD::ATOMIC_LOAD_MIN);
  case Intrinsic::atomic_load_umin:
    return implVisitBinaryAtomic(I, ISD::ATOMIC_LOAD_UMIN);
  case Intrinsic::atomic_load_umax:
    return implVisitBinaryAtomic(I, ISD::ATOMIC_LOAD_UMAX);
  case Intrinsic::atomic_swap:
    return implVisitBinaryAtomic(I, ISD::ATOMIC_SWAP);

  case Intrinsic::invariant_start:
  case Intrinsic::lifetime_start:
    // Discard region information.
    setValue(&I, DAG.getUNDEF(TLI.getPointerTy()));
    return 0;
  case Intrinsic::invariant_end:
  case Intrinsic::lifetime_end:
    // Discard region information.
    return 0;
  }
}

/// Test if the given instruction is in a position to be optimized
/// with a tail-call. This roughly means that it's in a block with
/// a return and there's nothing that needs to be scheduled
/// between it and the return.
///
/// This function only tests target-independent requirements.
/// For target-dependent requirements, a target should override
/// TargetLowering::IsEligibleForTailCallOptimization.
///
static bool
isInTailCallPosition(const Instruction *I, Attributes CalleeRetAttr,
                     const TargetLowering &TLI) {
  const BasicBlock *ExitBB = I->getParent();
  const TerminatorInst *Term = ExitBB->getTerminator();
  const ReturnInst *Ret = dyn_cast<ReturnInst>(Term);
  const Function *F = ExitBB->getParent();

  // The block must end in a return statement or an unreachable.
  if (!Ret && !isa<UnreachableInst>(Term)) return false;

  // If I will have a chain, make sure no other instruction that will have a
  // chain interposes between I and the return.
  if (I->mayHaveSideEffects() || I->mayReadFromMemory() ||
      !I->isSafeToSpeculativelyExecute())
    for (BasicBlock::const_iterator BBI = prior(prior(ExitBB->end())); ;
         --BBI) {
      if (&*BBI == I)
        break;
      if (BBI->mayHaveSideEffects() || BBI->mayReadFromMemory() ||
          !BBI->isSafeToSpeculativelyExecute())
        return false;
    }

  // If the block ends with a void return or unreachable, it doesn't matter
  // what the call's return type is.
  if (!Ret || Ret->getNumOperands() == 0) return true;

  // If the return value is undef, it doesn't matter what the call's
  // return type is.
  if (isa<UndefValue>(Ret->getOperand(0))) return true;

  // Conservatively require the attributes of the call to match those of
  // the return. Ignore noalias because it doesn't affect the call sequence.
  unsigned CallerRetAttr = F->getAttributes().getRetAttributes();
  if ((CalleeRetAttr ^ CallerRetAttr) & ~Attribute::NoAlias)
    return false;

  // Otherwise, make sure the unmodified return value of I is the return value.
  for (const Instruction *U = dyn_cast<Instruction>(Ret->getOperand(0)); ;
       U = dyn_cast<Instruction>(U->getOperand(0))) {
    if (!U)
      return false;
    if (!U->hasOneUse())
      return false;
    if (U == I)
      break;
    // Check for a truly no-op truncate.
    if (isa<TruncInst>(U) &&
        TLI.isTruncateFree(U->getOperand(0)->getType(), U->getType()))
      continue;
    // Check for a truly no-op bitcast.
    if (isa<BitCastInst>(U) &&
        (U->getOperand(0)->getType() == U->getType() ||
         (isa<PointerType>(U->getOperand(0)->getType()) &&
          isa<PointerType>(U->getType()))))
      continue;
    // Otherwise it's not a true no-op.
    return false;
  }

  return true;
}

void SelectionDAGBuilder::LowerCallTo(CallSite CS, SDValue Callee,
                                      bool isTailCall,
                                      MachineBasicBlock *LandingPad) {
  const PointerType *PT = cast<PointerType>(CS.getCalledValue()->getType());
  const FunctionType *FTy = cast<FunctionType>(PT->getElementType());
  const Type *RetTy = FTy->getReturnType();
  MachineModuleInfo *MMI = DAG.getMachineModuleInfo();
  unsigned BeginLabel = 0, EndLabel = 0;

  TargetLowering::ArgListTy Args;
  TargetLowering::ArgListEntry Entry;
  Args.reserve(CS.arg_size());

  // Check whether the function can return without sret-demotion.
  SmallVector<EVT, 4> OutVTs;
  SmallVector<ISD::ArgFlagsTy, 4> OutsFlags;
  SmallVector<uint64_t, 4> Offsets;
  getReturnInfo(RetTy, CS.getAttributes().getRetAttributes(), 
    OutVTs, OutsFlags, TLI, &Offsets);
  

  bool CanLowerReturn = TLI.CanLowerReturn(CS.getCallingConv(), 
                        FTy->isVarArg(), OutVTs, OutsFlags, DAG);

  SDValue DemoteStackSlot;

  if (!CanLowerReturn) {
    uint64_t TySize = TLI.getTargetData()->getTypeAllocSize(
                      FTy->getReturnType());
    unsigned Align  = TLI.getTargetData()->getPrefTypeAlignment(
                      FTy->getReturnType());
    MachineFunction &MF = DAG.getMachineFunction();
    int SSFI = MF.getFrameInfo()->CreateStackObject(TySize, Align, false);
    const Type *StackSlotPtrType = PointerType::getUnqual(FTy->getReturnType());

    DemoteStackSlot = DAG.getFrameIndex(SSFI, TLI.getPointerTy());
    Entry.Node = DemoteStackSlot;
    Entry.Ty = StackSlotPtrType;
    Entry.isSExt = false;
    Entry.isZExt = false;
    Entry.isInReg = false;
    Entry.isSRet = true;
    Entry.isNest = false;
    Entry.isByVal = false;
    Entry.Alignment = Align;
    Args.push_back(Entry);
    RetTy = Type::getVoidTy(FTy->getContext());
  }

  for (CallSite::arg_iterator i = CS.arg_begin(), e = CS.arg_end();
       i != e; ++i) {
    SDValue ArgNode = getValue(*i);
    Entry.Node = ArgNode; Entry.Ty = (*i)->getType();

    unsigned attrInd = i - CS.arg_begin() + 1;
    Entry.isSExt  = CS.paramHasAttr(attrInd, Attribute::SExt);
    Entry.isZExt  = CS.paramHasAttr(attrInd, Attribute::ZExt);
    Entry.isInReg = CS.paramHasAttr(attrInd, Attribute::InReg);
    Entry.isSRet  = CS.paramHasAttr(attrInd, Attribute::StructRet);
    Entry.isNest  = CS.paramHasAttr(attrInd, Attribute::Nest);
    Entry.isByVal = CS.paramHasAttr(attrInd, Attribute::ByVal);
    Entry.Alignment = CS.getParamAlignment(attrInd);
    Args.push_back(Entry);
  }

  if (LandingPad && MMI) {
    // Insert a label before the invoke call to mark the try range.  This can be
    // used to detect deletion of the invoke via the MachineModuleInfo.
    BeginLabel = MMI->NextLabelID();

    // Both PendingLoads and PendingExports must be flushed here;
    // this call might not return.
    (void)getRoot();
    DAG.setRoot(DAG.getLabel(ISD::EH_LABEL, getCurDebugLoc(),
                             getControlRoot(), BeginLabel));
  }

  // Check if target-independent constraints permit a tail call here.
  // Target-dependent constraints are checked within TLI.LowerCallTo.
  if (isTailCall &&
      !isInTailCallPosition(CS.getInstruction(),
                            CS.getAttributes().getRetAttributes(),
                            TLI))
    isTailCall = false;

  std::pair<SDValue,SDValue> Result =
    TLI.LowerCallTo(getRoot(), RetTy,
                    CS.paramHasAttr(0, Attribute::SExt),
                    CS.paramHasAttr(0, Attribute::ZExt), FTy->isVarArg(),
                    CS.paramHasAttr(0, Attribute::InReg), FTy->getNumParams(),
                    CS.getCallingConv(),
                    isTailCall,
                    !CS.getInstruction()->use_empty(),
                    Callee, Args, DAG, getCurDebugLoc());
  assert((isTailCall || Result.second.getNode()) &&
         "Non-null chain expected with non-tail call!");
  assert((Result.second.getNode() || !Result.first.getNode()) &&
         "Null value expected with tail call!");
  if (Result.first.getNode())
    setValue(CS.getInstruction(), Result.first);
  else if (!CanLowerReturn && Result.second.getNode()) {
    // The instruction result is the result of loading from the
    // hidden sret parameter.
    SmallVector<EVT, 1> PVTs;
    const Type *PtrRetTy = PointerType::getUnqual(FTy->getReturnType());

    ComputeValueVTs(TLI, PtrRetTy, PVTs);
    assert(PVTs.size() == 1 && "Pointers should fit in one register");
    EVT PtrVT = PVTs[0];
    unsigned NumValues = OutVTs.size();
    SmallVector<SDValue, 4> Values(NumValues);
    SmallVector<SDValue, 4> Chains(NumValues);

    for (unsigned i = 0; i < NumValues; ++i) {
      SDValue L = DAG.getLoad(OutVTs[i], getCurDebugLoc(), Result.second,
        DAG.getNode(ISD::ADD, getCurDebugLoc(), PtrVT, DemoteStackSlot,
        DAG.getConstant(Offsets[i], PtrVT)),
        NULL, Offsets[i], false, 1);
      Values[i] = L;
      Chains[i] = L.getValue(1);
    }
    SDValue Chain = DAG.getNode(ISD::TokenFactor, getCurDebugLoc(),
                                MVT::Other, &Chains[0], NumValues);
    PendingLoads.push_back(Chain);

    setValue(CS.getInstruction(), DAG.getNode(ISD::MERGE_VALUES,
             getCurDebugLoc(), DAG.getVTList(&OutVTs[0], NumValues),
             &Values[0], NumValues));
  }
  // As a special case, a null chain means that a tail call has
  // been emitted and the DAG root is already updated.
  if (Result.second.getNode())
    DAG.setRoot(Result.second);
  else
    HasTailCall = true;

  if (LandingPad && MMI) {
    // Insert a label at the end of the invoke call to mark the try range.  This
    // can be used to detect deletion of the invoke via the MachineModuleInfo.
    EndLabel = MMI->NextLabelID();
    DAG.setRoot(DAG.getLabel(ISD::EH_LABEL, getCurDebugLoc(),
                             getRoot(), EndLabel));

    // Inform MachineModuleInfo of range.
    MMI->addInvoke(LandingPad, BeginLabel, EndLabel);
  }
}


void SelectionDAGBuilder::visitCall(CallInst &I) {
  const char *RenameFn = 0;
  if (Function *F = I.getCalledFunction()) {
    if (F->isDeclaration()) {
      const TargetIntrinsicInfo *II = TLI.getTargetMachine().getIntrinsicInfo();
      if (II) {
        if (unsigned IID = II->getIntrinsicID(F)) {
          RenameFn = visitIntrinsicCall(I, IID);
          if (!RenameFn)
            return;
        }
      }
      if (unsigned IID = F->getIntrinsicID()) {
        RenameFn = visitIntrinsicCall(I, IID);
        if (!RenameFn)
          return;
      }
    }

    // Check for well-known libc/libm calls.  If the function is internal, it
    // can't be a library call.
    if (!F->hasLocalLinkage() && F->hasName()) {
      StringRef Name = F->getName();
      if (Name == "copysign" || Name == "copysignf") {
        if (I.getNumOperands() == 3 &&   // Basic sanity checks.
            I.getOperand(1)->getType()->isFloatingPoint() &&
            I.getType() == I.getOperand(1)->getType() &&
            I.getType() == I.getOperand(2)->getType()) {
          SDValue LHS = getValue(I.getOperand(1));
          SDValue RHS = getValue(I.getOperand(2));
          setValue(&I, DAG.getNode(ISD::FCOPYSIGN, getCurDebugLoc(),
                                   LHS.getValueType(), LHS, RHS));
          return;
        }
      } else if (Name == "fabs" || Name == "fabsf" || Name == "fabsl") {
        if (I.getNumOperands() == 2 &&   // Basic sanity checks.
            I.getOperand(1)->getType()->isFloatingPoint() &&
            I.getType() == I.getOperand(1)->getType()) {
          SDValue Tmp = getValue(I.getOperand(1));
          setValue(&I, DAG.getNode(ISD::FABS, getCurDebugLoc(),
                                   Tmp.getValueType(), Tmp));
          return;
        }
      } else if (Name == "sin" || Name == "sinf" || Name == "sinl") {
        if (I.getNumOperands() == 2 &&   // Basic sanity checks.
            I.getOperand(1)->getType()->isFloatingPoint() &&
            I.getType() == I.getOperand(1)->getType() &&
            I.onlyReadsMemory()) {
          SDValue Tmp = getValue(I.getOperand(1));
          setValue(&I, DAG.getNode(ISD::FSIN, getCurDebugLoc(),
                                   Tmp.getValueType(), Tmp));
          return;
        }
      } else if (Name == "cos" || Name == "cosf" || Name == "cosl") {
        if (I.getNumOperands() == 2 &&   // Basic sanity checks.
            I.getOperand(1)->getType()->isFloatingPoint() &&
            I.getType() == I.getOperand(1)->getType() &&
            I.onlyReadsMemory()) {
          SDValue Tmp = getValue(I.getOperand(1));
          setValue(&I, DAG.getNode(ISD::FCOS, getCurDebugLoc(),
                                   Tmp.getValueType(), Tmp));
          return;
        }
      } else if (Name == "sqrt" || Name == "sqrtf" || Name == "sqrtl") {
        if (I.getNumOperands() == 2 &&   // Basic sanity checks.
            I.getOperand(1)->getType()->isFloatingPoint() &&
            I.getType() == I.getOperand(1)->getType() &&
            I.onlyReadsMemory()) {
          SDValue Tmp = getValue(I.getOperand(1));
          setValue(&I, DAG.getNode(ISD::FSQRT, getCurDebugLoc(),
                                   Tmp.getValueType(), Tmp));
          return;
        }
      }
    }
  } else if (isa<InlineAsm>(I.getOperand(0))) {
    visitInlineAsm(&I);
    return;
  }

  SDValue Callee;
  if (!RenameFn)
    Callee = getValue(I.getOperand(0));
  else
    Callee = DAG.getExternalSymbol(RenameFn, TLI.getPointerTy());

  // Check if we can potentially perform a tail call. More detailed
  // checking is be done within LowerCallTo, after more information
  // about the call is known.
  bool isTailCall = PerformTailCallOpt && I.isTailCall();

  LowerCallTo(&I, Callee, isTailCall);
}


/// getCopyFromRegs - Emit a series of CopyFromReg nodes that copies from
/// this value and returns the result as a ValueVT value.  This uses
/// Chain/Flag as the input and updates them for the output Chain/Flag.
/// If the Flag pointer is NULL, no flag is used.
SDValue RegsForValue::getCopyFromRegs(SelectionDAG &DAG, DebugLoc dl,
                                      SDValue &Chain,
                                      SDValue *Flag) const {
  // Assemble the legal parts into the final values.
  SmallVector<SDValue, 4> Values(ValueVTs.size());
  SmallVector<SDValue, 8> Parts;
  for (unsigned Value = 0, Part = 0, e = ValueVTs.size(); Value != e; ++Value) {
    // Copy the legal parts from the registers.
    EVT ValueVT = ValueVTs[Value];
    unsigned NumRegs = TLI->getNumRegisters(*DAG.getContext(), ValueVT);
    EVT RegisterVT = RegVTs[Value];

    Parts.resize(NumRegs);
    for (unsigned i = 0; i != NumRegs; ++i) {
      SDValue P;
      if (Flag == 0)
        P = DAG.getCopyFromReg(Chain, dl, Regs[Part+i], RegisterVT);
      else {
        P = DAG.getCopyFromReg(Chain, dl, Regs[Part+i], RegisterVT, *Flag);
        *Flag = P.getValue(2);
      }
      Chain = P.getValue(1);

      // If the source register was virtual and if we know something about it,
      // add an assert node.
      if (TargetRegisterInfo::isVirtualRegister(Regs[Part+i]) &&
          RegisterVT.isInteger() && !RegisterVT.isVector()) {
        unsigned SlotNo = Regs[Part+i]-TargetRegisterInfo::FirstVirtualRegister;
        FunctionLoweringInfo &FLI = DAG.getFunctionLoweringInfo();
        if (FLI.LiveOutRegInfo.size() > SlotNo) {
          FunctionLoweringInfo::LiveOutInfo &LOI = FLI.LiveOutRegInfo[SlotNo];

          unsigned RegSize = RegisterVT.getSizeInBits();
          unsigned NumSignBits = LOI.NumSignBits;
          unsigned NumZeroBits = LOI.KnownZero.countLeadingOnes();

          // FIXME: We capture more information than the dag can represent.  For
          // now, just use the tightest assertzext/assertsext possible.
          bool isSExt = true;
          EVT FromVT(MVT::Other);
          if (NumSignBits == RegSize)
            isSExt = true, FromVT = MVT::i1;   // ASSERT SEXT 1
          else if (NumZeroBits >= RegSize-1)
            isSExt = false, FromVT = MVT::i1;  // ASSERT ZEXT 1
          else if (NumSignBits > RegSize-8)
            isSExt = true, FromVT = MVT::i8;   // ASSERT SEXT 8
          else if (NumZeroBits >= RegSize-8)
            isSExt = false, FromVT = MVT::i8;  // ASSERT ZEXT 8
          else if (NumSignBits > RegSize-16)
            isSExt = true, FromVT = MVT::i16;  // ASSERT SEXT 16
          else if (NumZeroBits >= RegSize-16)
            isSExt = false, FromVT = MVT::i16; // ASSERT ZEXT 16
          else if (NumSignBits > RegSize-32)
            isSExt = true, FromVT = MVT::i32;  // ASSERT SEXT 32
          else if (NumZeroBits >= RegSize-32)
            isSExt = false, FromVT = MVT::i32; // ASSERT ZEXT 32

          if (FromVT != MVT::Other) {
            P = DAG.getNode(isSExt ? ISD::AssertSext : ISD::AssertZext, dl,
                            RegisterVT, P, DAG.getValueType(FromVT));

          }
        }
      }

      Parts[i] = P;
    }

    Values[Value] = getCopyFromParts(DAG, dl, Parts.begin(),
                                     NumRegs, RegisterVT, ValueVT);
    Part += NumRegs;
    Parts.clear();
  }

  return DAG.getNode(ISD::MERGE_VALUES, dl,
                     DAG.getVTList(&ValueVTs[0], ValueVTs.size()),
                     &Values[0], ValueVTs.size());
}

/// getCopyToRegs - Emit a series of CopyToReg nodes that copies the
/// specified value into the registers specified by this object.  This uses
/// Chain/Flag as the input and updates them for the output Chain/Flag.
/// If the Flag pointer is NULL, no flag is used.
void RegsForValue::getCopyToRegs(SDValue Val, SelectionDAG &DAG, DebugLoc dl,
                                 SDValue &Chain, SDValue *Flag) const {
  // Get the list of the values's legal parts.
  unsigned NumRegs = Regs.size();
  SmallVector<SDValue, 8> Parts(NumRegs);
  for (unsigned Value = 0, Part = 0, e = ValueVTs.size(); Value != e; ++Value) {
    EVT ValueVT = ValueVTs[Value];
    unsigned NumParts = TLI->getNumRegisters(*DAG.getContext(), ValueVT);
    EVT RegisterVT = RegVTs[Value];

    getCopyToParts(DAG, dl, Val.getValue(Val.getResNo() + Value),
                   &Parts[Part], NumParts, RegisterVT);
    Part += NumParts;
  }

  // Copy the parts into the registers.
  SmallVector<SDValue, 8> Chains(NumRegs);
  for (unsigned i = 0; i != NumRegs; ++i) {
    SDValue Part;
    if (Flag == 0)
      Part = DAG.getCopyToReg(Chain, dl, Regs[i], Parts[i]);
    else {
      Part = DAG.getCopyToReg(Chain, dl, Regs[i], Parts[i], *Flag);
      *Flag = Part.getValue(1);
    }
    Chains[i] = Part.getValue(0);
  }

  if (NumRegs == 1 || Flag)
    // If NumRegs > 1 && Flag is used then the use of the last CopyToReg is
    // flagged to it. That is the CopyToReg nodes and the user are considered
    // a single scheduling unit. If we create a TokenFactor and return it as
    // chain, then the TokenFactor is both a predecessor (operand) of the
    // user as well as a successor (the TF operands are flagged to the user).
    // c1, f1 = CopyToReg
    // c2, f2 = CopyToReg
    // c3     = TokenFactor c1, c2
    // ...
    //        = op c3, ..., f2
    Chain = Chains[NumRegs-1];
  else
    Chain = DAG.getNode(ISD::TokenFactor, dl, MVT::Other, &Chains[0], NumRegs);
}

/// AddInlineAsmOperands - Add this value to the specified inlineasm node
/// operand list.  This adds the code marker and includes the number of
/// values added into it.
void RegsForValue::AddInlineAsmOperands(unsigned Code,
                                        bool HasMatching,unsigned MatchingIdx,
                                        SelectionDAG &DAG,
                                        std::vector<SDValue> &Ops) const {
  EVT IntPtrTy = DAG.getTargetLoweringInfo().getPointerTy();
  assert(Regs.size() < (1 << 13) && "Too many inline asm outputs!");
  unsigned Flag = Code | (Regs.size() << 3);
  if (HasMatching)
    Flag |= 0x80000000 | (MatchingIdx << 16);
  Ops.push_back(DAG.getTargetConstant(Flag, IntPtrTy));
  for (unsigned Value = 0, Reg = 0, e = ValueVTs.size(); Value != e; ++Value) {
    unsigned NumRegs = TLI->getNumRegisters(*DAG.getContext(), ValueVTs[Value]);
    EVT RegisterVT = RegVTs[Value];
    for (unsigned i = 0; i != NumRegs; ++i) {
      assert(Reg < Regs.size() && "Mismatch in # registers expected");
      Ops.push_back(DAG.getRegister(Regs[Reg++], RegisterVT));
    }
  }
}

/// isAllocatableRegister - If the specified register is safe to allocate,
/// i.e. it isn't a stack pointer or some other special register, return the
/// register class for the register.  Otherwise, return null.
static const TargetRegisterClass *
isAllocatableRegister(unsigned Reg, MachineFunction &MF,
                      const TargetLowering &TLI,
                      const TargetRegisterInfo *TRI) {
  EVT FoundVT = MVT::Other;
  const TargetRegisterClass *FoundRC = 0;
  for (TargetRegisterInfo::regclass_iterator RCI = TRI->regclass_begin(),
       E = TRI->regclass_end(); RCI != E; ++RCI) {
    EVT ThisVT = MVT::Other;

    const TargetRegisterClass *RC = *RCI;
    // If none of the the value types for this register class are valid, we
    // can't use it.  For example, 64-bit reg classes on 32-bit targets.
    for (TargetRegisterClass::vt_iterator I = RC->vt_begin(), E = RC->vt_end();
         I != E; ++I) {
      if (TLI.isTypeLegal(*I)) {
        // If we have already found this register in a different register class,
        // choose the one with the largest VT specified.  For example, on
        // PowerPC, we favor f64 register classes over f32.
        if (FoundVT == MVT::Other || FoundVT.bitsLT(*I)) {
          ThisVT = *I;
          break;
        }
      }
    }

    if (ThisVT == MVT::Other) continue;

    // NOTE: This isn't ideal.  In particular, this might allocate the
    // frame pointer in functions that need it (due to them not being taken
    // out of allocation, because a variable sized allocation hasn't been seen
    // yet).  This is a slight code pessimization, but should still work.
    for (TargetRegisterClass::iterator I = RC->allocation_order_begin(MF),
         E = RC->allocation_order_end(MF); I != E; ++I)
      if (*I == Reg) {
        // We found a matching register class.  Keep looking at others in case
        // we find one with larger registers that this physreg is also in.
        FoundRC = RC;
        FoundVT = ThisVT;
        break;
      }
  }
  return FoundRC;
}


namespace llvm {
/// AsmOperandInfo - This contains information for each constraint that we are
/// lowering.
class VISIBILITY_HIDDEN SDISelAsmOperandInfo :
    public TargetLowering::AsmOperandInfo {
public:
  /// CallOperand - If this is the result output operand or a clobber
  /// this is null, otherwise it is the incoming operand to the CallInst.
  /// This gets modified as the asm is processed.
  SDValue CallOperand;

  /// AssignedRegs - If this is a register or register class operand, this
  /// contains the set of register corresponding to the operand.
  RegsForValue AssignedRegs;

  explicit SDISelAsmOperandInfo(const InlineAsm::ConstraintInfo &info)
    : TargetLowering::AsmOperandInfo(info), CallOperand(0,0) {
  }

  /// MarkAllocatedRegs - Once AssignedRegs is set, mark the assigned registers
  /// busy in OutputRegs/InputRegs.
  void MarkAllocatedRegs(bool isOutReg, bool isInReg,
                         std::set<unsigned> &OutputRegs,
                         std::set<unsigned> &InputRegs,
                         const TargetRegisterInfo &TRI) const {
    if (isOutReg) {
      for (unsigned i = 0, e = AssignedRegs.Regs.size(); i != e; ++i)
        MarkRegAndAliases(AssignedRegs.Regs[i], OutputRegs, TRI);
    }
    if (isInReg) {
      for (unsigned i = 0, e = AssignedRegs.Regs.size(); i != e; ++i)
        MarkRegAndAliases(AssignedRegs.Regs[i], InputRegs, TRI);
    }
  }

  /// getCallOperandValEVT - Return the EVT of the Value* that this operand
  /// corresponds to.  If there is no Value* for this operand, it returns
  /// MVT::Other.
  EVT getCallOperandValEVT(LLVMContext &Context, 
                           const TargetLowering &TLI,
                           const TargetData *TD) const {
    if (CallOperandVal == 0) return MVT::Other;

    if (isa<BasicBlock>(CallOperandVal))
      return TLI.getPointerTy();

    const llvm::Type *OpTy = CallOperandVal->getType();

    // If this is an indirect operand, the operand is a pointer to the
    // accessed type.
    if (isIndirect)
      OpTy = cast<PointerType>(OpTy)->getElementType();

    // If OpTy is not a single value, it may be a struct/union that we
    // can tile with integers.
    if (!OpTy->isSingleValueType() && OpTy->isSized()) {
      unsigned BitSize = TD->getTypeSizeInBits(OpTy);
      switch (BitSize) {
      default: break;
      case 1:
      case 8:
      case 16:
      case 32:
      case 64:
      case 128:
        OpTy = IntegerType::get(Context, BitSize);
        break;
      }
    }

    return TLI.getValueType(OpTy, true);
  }

private:
  /// MarkRegAndAliases - Mark the specified register and all aliases in the
  /// specified set.
  static void MarkRegAndAliases(unsigned Reg, std::set<unsigned> &Regs,
                                const TargetRegisterInfo &TRI) {
    assert(TargetRegisterInfo::isPhysicalRegister(Reg) && "Isn't a physreg");
    Regs.insert(Reg);
    if (const unsigned *Aliases = TRI.getAliasSet(Reg))
      for (; *Aliases; ++Aliases)
        Regs.insert(*Aliases);
  }
};
} // end llvm namespace.


/// GetRegistersForValue - Assign registers (virtual or physical) for the
/// specified operand.  We prefer to assign virtual registers, to allow the
/// register allocator to handle the assignment process.  However, if the asm
/// uses features that we can't model on machineinstrs, we have SDISel do the
/// allocation.  This produces generally horrible, but correct, code.
///
///   OpInfo describes the operand.
///   Input and OutputRegs are the set of already allocated physical registers.
///
void SelectionDAGBuilder::
GetRegistersForValue(SDISelAsmOperandInfo &OpInfo,
                     std::set<unsigned> &OutputRegs,
                     std::set<unsigned> &InputRegs) {
  LLVMContext &Context = FuncInfo.Fn->getContext();

  // Compute whether this value requires an input register, an output register,
  // or both.
  bool isOutReg = false;
  bool isInReg = false;
  switch (OpInfo.Type) {
  case InlineAsm::isOutput:
    isOutReg = true;

    // If there is an input constraint that matches this, we need to reserve
    // the input register so no other inputs allocate to it.
    isInReg = OpInfo.hasMatchingInput();
    break;
  case InlineAsm::isInput:
    isInReg = true;
    isOutReg = false;
    break;
  case InlineAsm::isClobber:
    isOutReg = true;
    isInReg = true;
    break;
  }


  MachineFunction &MF = DAG.getMachineFunction();
  SmallVector<unsigned, 4> Regs;

  // If this is a constraint for a single physreg, or a constraint for a
  // register class, find it.
  std::pair<unsigned, const TargetRegisterClass*> PhysReg =
    TLI.getRegForInlineAsmConstraint(OpInfo.ConstraintCode,
                                     OpInfo.ConstraintVT);

  unsigned NumRegs = 1;
  if (OpInfo.ConstraintVT != MVT::Other) {
    // If this is a FP input in an integer register (or visa versa) insert a bit
    // cast of the input value.  More generally, handle any case where the input
    // value disagrees with the register class we plan to stick this in.
    if (OpInfo.Type == InlineAsm::isInput &&
        PhysReg.second && !PhysReg.second->hasType(OpInfo.ConstraintVT)) {
      // Try to convert to the first EVT that the reg class contains.  If the
      // types are identical size, use a bitcast to convert (e.g. two differing
      // vector types).
      EVT RegVT = *PhysReg.second->vt_begin();
      if (RegVT.getSizeInBits() == OpInfo.ConstraintVT.getSizeInBits()) {
        OpInfo.CallOperand = DAG.getNode(ISD::BIT_CONVERT, getCurDebugLoc(),
                                         RegVT, OpInfo.CallOperand);
        OpInfo.ConstraintVT = RegVT;
      } else if (RegVT.isInteger() && OpInfo.ConstraintVT.isFloatingPoint()) {
        // If the input is a FP value and we want it in FP registers, do a
        // bitcast to the corresponding integer type.  This turns an f64 value
        // into i64, which can be passed with two i32 values on a 32-bit
        // machine.
        RegVT = EVT::getIntegerVT(Context, 
                                  OpInfo.ConstraintVT.getSizeInBits());
        OpInfo.CallOperand = DAG.getNode(ISD::BIT_CONVERT, getCurDebugLoc(),
                                         RegVT, OpInfo.CallOperand);
        OpInfo.ConstraintVT = RegVT;
      }
    }

    NumRegs = TLI.getNumRegisters(Context, OpInfo.ConstraintVT);
  }

  EVT RegVT;
  EVT ValueVT = OpInfo.ConstraintVT;

  // If this is a constraint for a specific physical register, like {r17},
  // assign it now.
  if (unsigned AssignedReg = PhysReg.first) {
    const TargetRegisterClass *RC = PhysReg.second;
    if (OpInfo.ConstraintVT == MVT::Other)
      ValueVT = *RC->vt_begin();

    // Get the actual register value type.  This is important, because the user
    // may have asked for (e.g.) the AX register in i32 type.  We need to
    // remember that AX is actually i16 to get the right extension.
    RegVT = *RC->vt_begin();

    // This is a explicit reference to a physical register.
    Regs.push_back(AssignedReg);

    // If this is an expanded reference, add the rest of the regs to Regs.
    if (NumRegs != 1) {
      TargetRegisterClass::iterator I = RC->begin();
      for (; *I != AssignedReg; ++I)
        assert(I != RC->end() && "Didn't find reg!");

      // Already added the first reg.
      --NumRegs; ++I;
      for (; NumRegs; --NumRegs, ++I) {
        assert(I != RC->end() && "Ran out of registers to allocate!");
        Regs.push_back(*I);
      }
    }
    OpInfo.AssignedRegs = RegsForValue(TLI, Regs, RegVT, ValueVT);
    const TargetRegisterInfo *TRI = DAG.getTarget().getRegisterInfo();
    OpInfo.MarkAllocatedRegs(isOutReg, isInReg, OutputRegs, InputRegs, *TRI);
    return;
  }

  // Otherwise, if this was a reference to an LLVM register class, create vregs
  // for this reference.
  if (const TargetRegisterClass *RC = PhysReg.second) {
    RegVT = *RC->vt_begin();
    if (OpInfo.ConstraintVT == MVT::Other)
      ValueVT = RegVT;

    // Create the appropriate number of virtual registers.
    MachineRegisterInfo &RegInfo = MF.getRegInfo();
    for (; NumRegs; --NumRegs)
      Regs.push_back(RegInfo.createVirtualRegister(RC));

    OpInfo.AssignedRegs = RegsForValue(TLI, Regs, RegVT, ValueVT);
    return;
  }
  
  // This is a reference to a register class that doesn't directly correspond
  // to an LLVM register class.  Allocate NumRegs consecutive, available,
  // registers from the class.
  std::vector<unsigned> RegClassRegs
    = TLI.getRegClassForInlineAsmConstraint(OpInfo.ConstraintCode,
                                            OpInfo.ConstraintVT);

  const TargetRegisterInfo *TRI = DAG.getTarget().getRegisterInfo();
  unsigned NumAllocated = 0;
  for (unsigned i = 0, e = RegClassRegs.size(); i != e; ++i) {
    unsigned Reg = RegClassRegs[i];
    // See if this register is available.
    if ((isOutReg && OutputRegs.count(Reg)) ||   // Already used.
        (isInReg  && InputRegs.count(Reg))) {    // Already used.
      // Make sure we find consecutive registers.
      NumAllocated = 0;
      continue;
    }

    // Check to see if this register is allocatable (i.e. don't give out the
    // stack pointer).
    const TargetRegisterClass *RC = isAllocatableRegister(Reg, MF, TLI, TRI);
    if (!RC) {        // Couldn't allocate this register.
      // Reset NumAllocated to make sure we return consecutive registers.
      NumAllocated = 0;
      continue;
    }

    // Okay, this register is good, we can use it.
    ++NumAllocated;

    // If we allocated enough consecutive registers, succeed.
    if (NumAllocated == NumRegs) {
      unsigned RegStart = (i-NumAllocated)+1;
      unsigned RegEnd   = i+1;
      // Mark all of the allocated registers used.
      for (unsigned i = RegStart; i != RegEnd; ++i)
        Regs.push_back(RegClassRegs[i]);

      OpInfo.AssignedRegs = RegsForValue(TLI, Regs, *RC->vt_begin(),
                                         OpInfo.ConstraintVT);
      OpInfo.MarkAllocatedRegs(isOutReg, isInReg, OutputRegs, InputRegs, *TRI);
      return;
    }
  }

  // Otherwise, we couldn't allocate enough registers for this.
}

/// hasInlineAsmMemConstraint - Return true if the inline asm instruction being
/// processed uses a memory 'm' constraint.
static bool
hasInlineAsmMemConstraint(std::vector<InlineAsm::ConstraintInfo> &CInfos,
                          const TargetLowering &TLI) {
  for (unsigned i = 0, e = CInfos.size(); i != e; ++i) {
    InlineAsm::ConstraintInfo &CI = CInfos[i];
    for (unsigned j = 0, ee = CI.Codes.size(); j != ee; ++j) {
      TargetLowering::ConstraintType CType = TLI.getConstraintType(CI.Codes[j]);
      if (CType == TargetLowering::C_Memory)
        return true;
    }
    
    // Indirect operand accesses access memory.
    if (CI.isIndirect)
      return true;
  }

  return false;
}

/// visitInlineAsm - Handle a call to an InlineAsm object.
///
void SelectionDAGBuilder::visitInlineAsm(CallSite CS) {
  InlineAsm *IA = cast<InlineAsm>(CS.getCalledValue());

  /// ConstraintOperands - Information about all of the constraints.
  std::vector<SDISelAsmOperandInfo> ConstraintOperands;

  std::set<unsigned> OutputRegs, InputRegs;

  // Do a prepass over the constraints, canonicalizing them, and building up the
  // ConstraintOperands list.
  std::vector<InlineAsm::ConstraintInfo>
    ConstraintInfos = IA->ParseConstraints();

  bool hasMemory = hasInlineAsmMemConstraint(ConstraintInfos, TLI);
  
  SDValue Chain, Flag;
  
  // We won't need to flush pending loads if this asm doesn't touch
  // memory and is nonvolatile.
  if (hasMemory || IA->hasSideEffects())
    Chain = getRoot();
  else
    Chain = DAG.getRoot();

  unsigned ArgNo = 0;   // ArgNo - The argument of the CallInst.
  unsigned ResNo = 0;   // ResNo - The result number of the next output.
  for (unsigned i = 0, e = ConstraintInfos.size(); i != e; ++i) {
    ConstraintOperands.push_back(SDISelAsmOperandInfo(ConstraintInfos[i]));
    SDISelAsmOperandInfo &OpInfo = ConstraintOperands.back();

    EVT OpVT = MVT::Other;

    // Compute the value type for each operand.
    switch (OpInfo.Type) {
    case InlineAsm::isOutput:
      // Indirect outputs just consume an argument.
      if (OpInfo.isIndirect) {
        OpInfo.CallOperandVal = CS.getArgument(ArgNo++);
        break;
      }

      // The return value of the call is this value.  As such, there is no
      // corresponding argument.
      assert(CS.getType() != Type::getVoidTy(*DAG.getContext()) &&
             "Bad inline asm!");
      if (const StructType *STy = dyn_cast<StructType>(CS.getType())) {
        OpVT = TLI.getValueType(STy->getElementType(ResNo));
      } else {
        assert(ResNo == 0 && "Asm only has one result!");
        OpVT = TLI.getValueType(CS.getType());
      }
      ++ResNo;
      break;
    case InlineAsm::isInput:
      OpInfo.CallOperandVal = CS.getArgument(ArgNo++);
      break;
    case InlineAsm::isClobber:
      // Nothing to do.
      break;
    }

    // If this is an input or an indirect output, process the call argument.
    // BasicBlocks are labels, currently appearing only in asm's.
    if (OpInfo.CallOperandVal) {
      // Strip bitcasts, if any.  This mostly comes up for functions.
      OpInfo.CallOperandVal = OpInfo.CallOperandVal->stripPointerCasts();

      if (BasicBlock *BB = dyn_cast<BasicBlock>(OpInfo.CallOperandVal)) {
        OpInfo.CallOperand = DAG.getBasicBlock(FuncInfo.MBBMap[BB]);
      } else {
        OpInfo.CallOperand = getValue(OpInfo.CallOperandVal);
      }

      OpVT = OpInfo.getCallOperandValEVT(*DAG.getContext(), TLI, TD);
    }

    OpInfo.ConstraintVT = OpVT;
  }

  // Second pass over the constraints: compute which constraint option to use
  // and assign registers to constraints that want a specific physreg.
  for (unsigned i = 0, e = ConstraintInfos.size(); i != e; ++i) {
    SDISelAsmOperandInfo &OpInfo = ConstraintOperands[i];

    // If this is an output operand with a matching input operand, look up the
    // matching input. If their types mismatch, e.g. one is an integer, the
    // other is floating point, or their sizes are different, flag it as an
    // error.
    if (OpInfo.hasMatchingInput()) {
      SDISelAsmOperandInfo &Input = ConstraintOperands[OpInfo.MatchingInput];
      if (OpInfo.ConstraintVT != Input.ConstraintVT) {
        if ((OpInfo.ConstraintVT.isInteger() !=
             Input.ConstraintVT.isInteger()) ||
            (OpInfo.ConstraintVT.getSizeInBits() !=
             Input.ConstraintVT.getSizeInBits())) {
          llvm_report_error("Unsupported asm: input constraint"
                            " with a matching output constraint of incompatible"
                            " type!");
        }
        Input.ConstraintVT = OpInfo.ConstraintVT;
      }
    }

    // Compute the constraint code and ConstraintType to use.
    TLI.ComputeConstraintToUse(OpInfo, OpInfo.CallOperand, hasMemory, &DAG);

    // If this is a memory input, and if the operand is not indirect, do what we
    // need to to provide an address for the memory input.
    if (OpInfo.ConstraintType == TargetLowering::C_Memory &&
        !OpInfo.isIndirect) {
      assert(OpInfo.Type == InlineAsm::isInput &&
             "Can only indirectify direct input operands!");

      // Memory operands really want the address of the value.  If we don't have
      // an indirect input, put it in the constpool if we can, otherwise spill
      // it to a stack slot.

      // If the operand is a float, integer, or vector constant, spill to a
      // constant pool entry to get its address.
      Value *OpVal = OpInfo.CallOperandVal;
      if (isa<ConstantFP>(OpVal) || isa<ConstantInt>(OpVal) ||
          isa<ConstantVector>(OpVal)) {
        OpInfo.CallOperand = DAG.getConstantPool(cast<Constant>(OpVal),
                                                 TLI.getPointerTy());
      } else {
        // Otherwise, create a stack slot and emit a store to it before the
        // asm.
        const Type *Ty = OpVal->getType();
        uint64_t TySize = TLI.getTargetData()->getTypeAllocSize(Ty);
        unsigned Align  = TLI.getTargetData()->getPrefTypeAlignment(Ty);
        MachineFunction &MF = DAG.getMachineFunction();
        int SSFI = MF.getFrameInfo()->CreateStackObject(TySize, Align, false);
        SDValue StackSlot = DAG.getFrameIndex(SSFI, TLI.getPointerTy());
        Chain = DAG.getStore(Chain, getCurDebugLoc(),
                             OpInfo.CallOperand, StackSlot, NULL, 0);
        OpInfo.CallOperand = StackSlot;
      }

      // There is no longer a Value* corresponding to this operand.
      OpInfo.CallOperandVal = 0;
      // It is now an indirect operand.
      OpInfo.isIndirect = true;
    }

    // If this constraint is for a specific register, allocate it before
    // anything else.
    if (OpInfo.ConstraintType == TargetLowering::C_Register)
      GetRegistersForValue(OpInfo, OutputRegs, InputRegs);
  }
  ConstraintInfos.clear();


  // Second pass - Loop over all of the operands, assigning virtual or physregs
  // to register class operands.
  for (unsigned i = 0, e = ConstraintOperands.size(); i != e; ++i) {
    SDISelAsmOperandInfo &OpInfo = ConstraintOperands[i];

    // C_Register operands have already been allocated, Other/Memory don't need
    // to be.
    if (OpInfo.ConstraintType == TargetLowering::C_RegisterClass)
      GetRegistersForValue(OpInfo, OutputRegs, InputRegs);
  }

  // AsmNodeOperands - The operands for the ISD::INLINEASM node.
  std::vector<SDValue> AsmNodeOperands;
  AsmNodeOperands.push_back(SDValue());  // reserve space for input chain
  AsmNodeOperands.push_back(
          DAG.getTargetExternalSymbol(IA->getAsmString().c_str(), MVT::Other));


  // Loop over all of the inputs, copying the operand values into the
  // appropriate registers and processing the output regs.
  RegsForValue RetValRegs;

  // IndirectStoresToEmit - The set of stores to emit after the inline asm node.
  std::vector<std::pair<RegsForValue, Value*> > IndirectStoresToEmit;

  for (unsigned i = 0, e = ConstraintOperands.size(); i != e; ++i) {
    SDISelAsmOperandInfo &OpInfo = ConstraintOperands[i];

    switch (OpInfo.Type) {
    case InlineAsm::isOutput: {
      if (OpInfo.ConstraintType != TargetLowering::C_RegisterClass &&
          OpInfo.ConstraintType != TargetLowering::C_Register) {
        // Memory output, or 'other' output (e.g. 'X' constraint).
        assert(OpInfo.isIndirect && "Memory output must be indirect operand");

        // Add information to the INLINEASM node to know about this output.
        unsigned ResOpType = 4/*MEM*/ | (1<<3);
        AsmNodeOperands.push_back(DAG.getTargetConstant(ResOpType,
                                                        TLI.getPointerTy()));
        AsmNodeOperands.push_back(OpInfo.CallOperand);
        break;
      }

      // Otherwise, this is a register or register class output.

      // Copy the output from the appropriate register.  Find a register that
      // we can use.
      if (OpInfo.AssignedRegs.Regs.empty()) {
        llvm_report_error("Couldn't allocate output reg for"
                          " constraint '" + OpInfo.ConstraintCode + "'!");
      }

      // If this is an indirect operand, store through the pointer after the
      // asm.
      if (OpInfo.isIndirect) {
        IndirectStoresToEmit.push_back(std::make_pair(OpInfo.AssignedRegs,
                                                      OpInfo.CallOperandVal));
      } else {
        // This is the result value of the call.
        assert(CS.getType() != Type::getVoidTy(*DAG.getContext()) &&
               "Bad inline asm!");
        // Concatenate this output onto the outputs list.
        RetValRegs.append(OpInfo.AssignedRegs);
      }

      // Add information to the INLINEASM node to know that this register is
      // set.
      OpInfo.AssignedRegs.AddInlineAsmOperands(OpInfo.isEarlyClobber ?
                                               6 /* EARLYCLOBBER REGDEF */ :
                                               2 /* REGDEF */ ,
                                               false,
                                               0,
                                               DAG, AsmNodeOperands);
      break;
    }
    case InlineAsm::isInput: {
      SDValue InOperandVal = OpInfo.CallOperand;

      if (OpInfo.isMatchingInputConstraint()) {   // Matching constraint?
        // If this is required to match an output register we have already set,
        // just use its register.
        unsigned OperandNo = OpInfo.getMatchedOperand();

        // Scan until we find the definition we already emitted of this operand.
        // When we find it, create a RegsForValue operand.
        unsigned CurOp = 2;  // The first operand.
        for (; OperandNo; --OperandNo) {
          // Advance to the next operand.
          unsigned OpFlag =
            cast<ConstantSDNode>(AsmNodeOperands[CurOp])->getZExtValue();
          assert(((OpFlag & 7) == 2 /*REGDEF*/ ||
                  (OpFlag & 7) == 6 /*EARLYCLOBBER REGDEF*/ ||
                  (OpFlag & 7) == 4 /*MEM*/) &&
                 "Skipped past definitions?");
          CurOp += InlineAsm::getNumOperandRegisters(OpFlag)+1;
        }

        unsigned OpFlag =
          cast<ConstantSDNode>(AsmNodeOperands[CurOp])->getZExtValue();
        if ((OpFlag & 7) == 2 /*REGDEF*/
            || (OpFlag & 7) == 6 /* EARLYCLOBBER REGDEF */) {
          // Add (OpFlag&0xffff)>>3 registers to MatchedRegs.
          if (OpInfo.isIndirect) {
            llvm_report_error("Don't know how to handle tied indirect "
                              "register inputs yet!");
          }
          RegsForValue MatchedRegs;
          MatchedRegs.TLI = &TLI;
          MatchedRegs.ValueVTs.push_back(InOperandVal.getValueType());
          EVT RegVT = AsmNodeOperands[CurOp+1].getValueType();
          MatchedRegs.RegVTs.push_back(RegVT);
          MachineRegisterInfo &RegInfo = DAG.getMachineFunction().getRegInfo();
          for (unsigned i = 0, e = InlineAsm::getNumOperandRegisters(OpFlag);
               i != e; ++i)
            MatchedRegs.Regs.
              push_back(RegInfo.createVirtualRegister(TLI.getRegClassFor(RegVT)));

          // Use the produced MatchedRegs object to
          MatchedRegs.getCopyToRegs(InOperandVal, DAG, getCurDebugLoc(),
                                    Chain, &Flag);
          MatchedRegs.AddInlineAsmOperands(1 /*REGUSE*/,
                                           true, OpInfo.getMatchedOperand(),
                                           DAG, AsmNodeOperands);
          break;
        } else {
          assert(((OpFlag & 7) == 4) && "Unknown matching constraint!");
          assert((InlineAsm::getNumOperandRegisters(OpFlag)) == 1 &&
                 "Unexpected number of operands");
          // Add information to the INLINEASM node to know about this input.
          // See InlineAsm.h isUseOperandTiedToDef.
          OpFlag |= 0x80000000 | (OpInfo.getMatchedOperand() << 16);
          AsmNodeOperands.push_back(DAG.getTargetConstant(OpFlag,
                                                          TLI.getPointerTy()));
          AsmNodeOperands.push_back(AsmNodeOperands[CurOp+1]);
          break;
        }
      }

      if (OpInfo.ConstraintType == TargetLowering::C_Other) {
        assert(!OpInfo.isIndirect &&
               "Don't know how to handle indirect other inputs yet!");

        std::vector<SDValue> Ops;
        TLI.LowerAsmOperandForConstraint(InOperandVal, OpInfo.ConstraintCode[0],
                                         hasMemory, Ops, DAG);
        if (Ops.empty()) {
          llvm_report_error("Invalid operand for inline asm"
                            " constraint '" + OpInfo.ConstraintCode + "'!");
        }

        // Add information to the INLINEASM node to know about this input.
        unsigned ResOpType = 3 /*IMM*/ | (Ops.size() << 3);
        AsmNodeOperands.push_back(DAG.getTargetConstant(ResOpType,
                                                        TLI.getPointerTy()));
        AsmNodeOperands.insert(AsmNodeOperands.end(), Ops.begin(), Ops.end());
        break;
      } else if (OpInfo.ConstraintType == TargetLowering::C_Memory) {
        assert(OpInfo.isIndirect && "Operand must be indirect to be a mem!");
        assert(InOperandVal.getValueType() == TLI.getPointerTy() &&
               "Memory operands expect pointer values");

        // Add information to the INLINEASM node to know about this input.
        unsigned ResOpType = 4/*MEM*/ | (1<<3);
        AsmNodeOperands.push_back(DAG.getTargetConstant(ResOpType,
                                                        TLI.getPointerTy()));
        AsmNodeOperands.push_back(InOperandVal);
        break;
      }

      assert((OpInfo.ConstraintType == TargetLowering::C_RegisterClass ||
              OpInfo.ConstraintType == TargetLowering::C_Register) &&
             "Unknown constraint type!");
      assert(!OpInfo.isIndirect &&
             "Don't know how to handle indirect register inputs yet!");

      // Copy the input into the appropriate registers.
      if (OpInfo.AssignedRegs.Regs.empty()) {
        llvm_report_error("Couldn't allocate input reg for"
                          " constraint '"+ OpInfo.ConstraintCode +"'!");
      }

      OpInfo.AssignedRegs.getCopyToRegs(InOperandVal, DAG, getCurDebugLoc(),
                                        Chain, &Flag);

      OpInfo.AssignedRegs.AddInlineAsmOperands(1/*REGUSE*/, false, 0,
                                               DAG, AsmNodeOperands);
      break;
    }
    case InlineAsm::isClobber: {
      // Add the clobbered value to the operand list, so that the register
      // allocator is aware that the physreg got clobbered.
      if (!OpInfo.AssignedRegs.Regs.empty())
        OpInfo.AssignedRegs.AddInlineAsmOperands(6 /* EARLYCLOBBER REGDEF */,
                                                 false, 0, DAG,AsmNodeOperands);
      break;
    }
    }
  }

  // Finish up input operands.
  AsmNodeOperands[0] = Chain;
  if (Flag.getNode()) AsmNodeOperands.push_back(Flag);

  Chain = DAG.getNode(ISD::INLINEASM, getCurDebugLoc(),
                      DAG.getVTList(MVT::Other, MVT::Flag),
                      &AsmNodeOperands[0], AsmNodeOperands.size());
  Flag = Chain.getValue(1);

  // If this asm returns a register value, copy the result from that register
  // and set it as the value of the call.
  if (!RetValRegs.Regs.empty()) {
    SDValue Val = RetValRegs.getCopyFromRegs(DAG, getCurDebugLoc(),
                                             Chain, &Flag);

    // FIXME: Why don't we do this for inline asms with MRVs?
    if (CS.getType()->isSingleValueType() && CS.getType()->isSized()) {
      EVT ResultType = TLI.getValueType(CS.getType());

      // If any of the results of the inline asm is a vector, it may have the
      // wrong width/num elts.  This can happen for register classes that can
      // contain multiple different value types.  The preg or vreg allocated may
      // not have the same VT as was expected.  Convert it to the right type
      // with bit_convert.
      if (ResultType != Val.getValueType() && Val.getValueType().isVector()) {
        Val = DAG.getNode(ISD::BIT_CONVERT, getCurDebugLoc(),
                          ResultType, Val);

      } else if (ResultType != Val.getValueType() &&
                 ResultType.isInteger() && Val.getValueType().isInteger()) {
        // If a result value was tied to an input value, the computed result may
        // have a wider width than the expected result.  Extract the relevant
        // portion.
        Val = DAG.getNode(ISD::TRUNCATE, getCurDebugLoc(), ResultType, Val);
      }

      assert(ResultType == Val.getValueType() && "Asm result value mismatch!");
    }

    setValue(CS.getInstruction(), Val);
    // Don't need to use this as a chain in this case.
    if (!IA->hasSideEffects() && !hasMemory && IndirectStoresToEmit.empty())
      return;
  }

  std::vector<std::pair<SDValue, Value*> > StoresToEmit;

  // Process indirect outputs, first output all of the flagged copies out of
  // physregs.
  for (unsigned i = 0, e = IndirectStoresToEmit.size(); i != e; ++i) {
    RegsForValue &OutRegs = IndirectStoresToEmit[i].first;
    Value *Ptr = IndirectStoresToEmit[i].second;
    SDValue OutVal = OutRegs.getCopyFromRegs(DAG, getCurDebugLoc(),
                                             Chain, &Flag);
    StoresToEmit.push_back(std::make_pair(OutVal, Ptr));

  }

  // Emit the non-flagged stores from the physregs.
  SmallVector<SDValue, 8> OutChains;
  for (unsigned i = 0, e = StoresToEmit.size(); i != e; ++i)
    OutChains.push_back(DAG.getStore(Chain, getCurDebugLoc(),
                                    StoresToEmit[i].first,
                                    getValue(StoresToEmit[i].second),
                                    StoresToEmit[i].second, 0));
  if (!OutChains.empty())
    Chain = DAG.getNode(ISD::TokenFactor, getCurDebugLoc(), MVT::Other,
                        &OutChains[0], OutChains.size());
  DAG.setRoot(Chain);
}

void SelectionDAGBuilder::visitVAStart(CallInst &I) {
  DAG.setRoot(DAG.getNode(ISD::VASTART, getCurDebugLoc(),
                          MVT::Other, getRoot(),
                          getValue(I.getOperand(1)),
                          DAG.getSrcValue(I.getOperand(1))));
}

void SelectionDAGBuilder::visitVAArg(VAArgInst &I) {
  SDValue V = DAG.getVAArg(TLI.getValueType(I.getType()), getCurDebugLoc(),
                           getRoot(), getValue(I.getOperand(0)),
                           DAG.getSrcValue(I.getOperand(0)));
  setValue(&I, V);
  DAG.setRoot(V.getValue(1));
}

void SelectionDAGBuilder::visitVAEnd(CallInst &I) {
  DAG.setRoot(DAG.getNode(ISD::VAEND, getCurDebugLoc(),
                          MVT::Other, getRoot(),
                          getValue(I.getOperand(1)),
                          DAG.getSrcValue(I.getOperand(1))));
}

void SelectionDAGBuilder::visitVACopy(CallInst &I) {
  DAG.setRoot(DAG.getNode(ISD::VACOPY, getCurDebugLoc(),
                          MVT::Other, getRoot(),
                          getValue(I.getOperand(1)),
                          getValue(I.getOperand(2)),
                          DAG.getSrcValue(I.getOperand(1)),
                          DAG.getSrcValue(I.getOperand(2))));
}

/// TargetLowering::LowerCallTo - This is the default LowerCallTo
/// implementation, which just calls LowerCall.
/// FIXME: When all targets are
/// migrated to using LowerCall, this hook should be integrated into SDISel.
std::pair<SDValue, SDValue>
TargetLowering::LowerCallTo(SDValue Chain, const Type *RetTy,
                            bool RetSExt, bool RetZExt, bool isVarArg,
                            bool isInreg, unsigned NumFixedArgs,
                            CallingConv::ID CallConv, bool isTailCall,
                            bool isReturnValueUsed,
                            SDValue Callee,
                            ArgListTy &Args, SelectionDAG &DAG, DebugLoc dl) {

  assert((!isTailCall || PerformTailCallOpt) &&
         "isTailCall set when tail-call optimizations are disabled!");

  // Handle all of the outgoing arguments.
  SmallVector<ISD::OutputArg, 32> Outs;
  for (unsigned i = 0, e = Args.size(); i != e; ++i) {
    SmallVector<EVT, 4> ValueVTs;
    ComputeValueVTs(*this, Args[i].Ty, ValueVTs);
    for (unsigned Value = 0, NumValues = ValueVTs.size();
         Value != NumValues; ++Value) {
      EVT VT = ValueVTs[Value];
      const Type *ArgTy = VT.getTypeForEVT(RetTy->getContext());
      SDValue Op = SDValue(Args[i].Node.getNode(),
                           Args[i].Node.getResNo() + Value);
      ISD::ArgFlagsTy Flags;
      unsigned OriginalAlignment =
        getTargetData()->getABITypeAlignment(ArgTy);

      if (Args[i].isZExt)
        Flags.setZExt();
      if (Args[i].isSExt)
        Flags.setSExt();
      if (Args[i].isInReg)
        Flags.setInReg();
      if (Args[i].isSRet)
        Flags.setSRet();
      if (Args[i].isByVal) {
        Flags.setByVal();
        const PointerType *Ty = cast<PointerType>(Args[i].Ty);
        const Type *ElementTy = Ty->getElementType();
        unsigned FrameAlign = getByValTypeAlignment(ElementTy);
        unsigned FrameSize  = getTargetData()->getTypeAllocSize(ElementTy);
        // For ByVal, alignment should come from FE.  BE will guess if this
        // info is not there but there are cases it cannot get right.
        if (Args[i].Alignment)
          FrameAlign = Args[i].Alignment;
        Flags.setByValAlign(FrameAlign);
        Flags.setByValSize(FrameSize);
      }
      if (Args[i].isNest)
        Flags.setNest();
      Flags.setOrigAlign(OriginalAlignment);

      EVT PartVT = getRegisterType(RetTy->getContext(), VT);
      unsigned NumParts = getNumRegisters(RetTy->getContext(), VT);
      SmallVector<SDValue, 4> Parts(NumParts);
      ISD::NodeType ExtendKind = ISD::ANY_EXTEND;

      if (Args[i].isSExt)
        ExtendKind = ISD::SIGN_EXTEND;
      else if (Args[i].isZExt)
        ExtendKind = ISD::ZERO_EXTEND;

      getCopyToParts(DAG, dl, Op, &Parts[0], NumParts, PartVT, ExtendKind);

      for (unsigned j = 0; j != NumParts; ++j) {
        // if it isn't first piece, alignment must be 1
        ISD::OutputArg MyFlags(Flags, Parts[j], i < NumFixedArgs);
        if (NumParts > 1 && j == 0)
          MyFlags.Flags.setSplit();
        else if (j != 0)
          MyFlags.Flags.setOrigAlign(1);

        Outs.push_back(MyFlags);
      }
    }
  }

  // Handle the incoming return values from the call.
  SmallVector<ISD::InputArg, 32> Ins;
  SmallVector<EVT, 4> RetTys;
  ComputeValueVTs(*this, RetTy, RetTys);
  for (unsigned I = 0, E = RetTys.size(); I != E; ++I) {
    EVT VT = RetTys[I];
    EVT RegisterVT = getRegisterType(RetTy->getContext(), VT);
    unsigned NumRegs = getNumRegisters(RetTy->getContext(), VT);
    for (unsigned i = 0; i != NumRegs; ++i) {
      ISD::InputArg MyFlags;
      MyFlags.VT = RegisterVT;
      MyFlags.Used = isReturnValueUsed;
      if (RetSExt)
        MyFlags.Flags.setSExt();
      if (RetZExt)
        MyFlags.Flags.setZExt();
      if (isInreg)
        MyFlags.Flags.setInReg();
      Ins.push_back(MyFlags);
    }
  }

  // Check if target-dependent constraints permit a tail call here.
  // Target-independent constraints should be checked by the caller.
  if (isTailCall &&
      !IsEligibleForTailCallOptimization(Callee, CallConv, isVarArg, Ins, DAG))
    isTailCall = false;

  SmallVector<SDValue, 4> InVals;
  Chain = LowerCall(Chain, Callee, CallConv, isVarArg, isTailCall,
                    Outs, Ins, dl, DAG, InVals);

  // Verify that the target's LowerCall behaved as expected.
  assert(Chain.getNode() && Chain.getValueType() == MVT::Other &&
         "LowerCall didn't return a valid chain!");
  assert((!isTailCall || InVals.empty()) &&
         "LowerCall emitted a return value for a tail call!");
  assert((isTailCall || InVals.size() == Ins.size()) &&
         "LowerCall didn't emit the correct number of values!");
  DEBUG(for (unsigned i = 0, e = Ins.size(); i != e; ++i) {
          assert(InVals[i].getNode() &&
                 "LowerCall emitted a null value!");
          assert(Ins[i].VT == InVals[i].getValueType() &&
                 "LowerCall emitted a value with the wrong type!");
        });

  // For a tail call, the return value is merely live-out and there aren't
  // any nodes in the DAG representing it. Return a special value to
  // indicate that a tail call has been emitted and no more Instructions
  // should be processed in the current block.
  if (isTailCall) {
    DAG.setRoot(Chain);
    return std::make_pair(SDValue(), SDValue());
  }

  // Collect the legal value parts into potentially illegal values
  // that correspond to the original function's return values.
  ISD::NodeType AssertOp = ISD::DELETED_NODE;
  if (RetSExt)
    AssertOp = ISD::AssertSext;
  else if (RetZExt)
    AssertOp = ISD::AssertZext;
  SmallVector<SDValue, 4> ReturnValues;
  unsigned CurReg = 0;
  for (unsigned I = 0, E = RetTys.size(); I != E; ++I) {
    EVT VT = RetTys[I];
    EVT RegisterVT = getRegisterType(RetTy->getContext(), VT);
    unsigned NumRegs = getNumRegisters(RetTy->getContext(), VT);

    SDValue ReturnValue =
      getCopyFromParts(DAG, dl, &InVals[CurReg], NumRegs, RegisterVT, VT,
                       AssertOp);
    ReturnValues.push_back(ReturnValue);
    CurReg += NumRegs;
  }

  // For a function returning void, there is no return value. We can't create
  // such a node, so we just return a null return value in that case. In
  // that case, nothing will actualy look at the value.
  if (ReturnValues.empty())
    return std::make_pair(SDValue(), Chain);

  SDValue Res = DAG.getNode(ISD::MERGE_VALUES, dl,
                            DAG.getVTList(&RetTys[0], RetTys.size()),
                            &ReturnValues[0], ReturnValues.size());

  return std::make_pair(Res, Chain);
}

void TargetLowering::LowerOperationWrapper(SDNode *N,
                                           SmallVectorImpl<SDValue> &Results,
                                           SelectionDAG &DAG) {
  SDValue Res = LowerOperation(SDValue(N, 0), DAG);
  if (Res.getNode())
    Results.push_back(Res);
}

SDValue TargetLowering::LowerOperation(SDValue Op, SelectionDAG &DAG) {
  llvm_unreachable("LowerOperation not implemented for this target!");
  return SDValue();
}


void SelectionDAGBuilder::CopyValueToVirtualRegister(Value *V, unsigned Reg) {
  SDValue Op = getValue(V);
  assert((Op.getOpcode() != ISD::CopyFromReg ||
          cast<RegisterSDNode>(Op.getOperand(1))->getReg() != Reg) &&
         "Copy from a reg to the same reg!");
  assert(!TargetRegisterInfo::isPhysicalRegister(Reg) && "Is a physreg");

  RegsForValue RFV(V->getContext(), TLI, Reg, V->getType());
  SDValue Chain = DAG.getEntryNode();
  RFV.getCopyToRegs(Op, DAG, getCurDebugLoc(), Chain, 0);
  PendingExports.push_back(Chain);
}

#include "llvm/CodeGen/SelectionDAGISel.h"

void SelectionDAGISel::LowerArguments(BasicBlock *LLVMBB) {
  // If this is the entry block, emit arguments.
  Function &F = *LLVMBB->getParent();
  SelectionDAG &DAG = SDB->DAG;
  SDValue OldRoot = DAG.getRoot();
  DebugLoc dl = SDB->getCurDebugLoc();
  const TargetData *TD = TLI.getTargetData();
  SmallVector<ISD::InputArg, 16> Ins;

  // Check whether the function can return without sret-demotion.
  SmallVector<EVT, 4> OutVTs;
  SmallVector<ISD::ArgFlagsTy, 4> OutsFlags;
  getReturnInfo(F.getReturnType(), F.getAttributes().getRetAttributes(), 
                OutVTs, OutsFlags, TLI);
  FunctionLoweringInfo &FLI = DAG.getFunctionLoweringInfo();

  FLI.CanLowerReturn = TLI.CanLowerReturn(F.getCallingConv(), F.isVarArg(), 
    OutVTs, OutsFlags, DAG);
  if (!FLI.CanLowerReturn) {
    // Put in an sret pointer parameter before all the other parameters.
    SmallVector<EVT, 1> ValueVTs;
    ComputeValueVTs(TLI, PointerType::getUnqual(F.getReturnType()), ValueVTs);

    // NOTE: Assuming that a pointer will never break down to more than one VT
    // or one register.
    ISD::ArgFlagsTy Flags;
    Flags.setSRet();
    EVT RegisterVT = TLI.getRegisterType(*CurDAG->getContext(), ValueVTs[0]);
    ISD::InputArg RetArg(Flags, RegisterVT, true);
    Ins.push_back(RetArg);
  }

  // Set up the incoming argument description vector.
  unsigned Idx = 1;
  for (Function::arg_iterator I = F.arg_begin(), E = F.arg_end();
       I != E; ++I, ++Idx) {
    SmallVector<EVT, 4> ValueVTs;
    ComputeValueVTs(TLI, I->getType(), ValueVTs);
    bool isArgValueUsed = !I->use_empty();
    for (unsigned Value = 0, NumValues = ValueVTs.size();
         Value != NumValues; ++Value) {
      EVT VT = ValueVTs[Value];
      const Type *ArgTy = VT.getTypeForEVT(*DAG.getContext());
      ISD::ArgFlagsTy Flags;
      unsigned OriginalAlignment =
        TD->getABITypeAlignment(ArgTy);

      if (F.paramHasAttr(Idx, Attribute::ZExt))
        Flags.setZExt();
      if (F.paramHasAttr(Idx, Attribute::SExt))
        Flags.setSExt();
      if (F.paramHasAttr(Idx, Attribute::InReg))
        Flags.setInReg();
      if (F.paramHasAttr(Idx, Attribute::StructRet))
        Flags.setSRet();
      if (F.paramHasAttr(Idx, Attribute::ByVal)) {
        Flags.setByVal();
        const PointerType *Ty = cast<PointerType>(I->getType());
        const Type *ElementTy = Ty->getElementType();
        unsigned FrameAlign = TLI.getByValTypeAlignment(ElementTy);
        unsigned FrameSize  = TD->getTypeAllocSize(ElementTy);
        // For ByVal, alignment should be passed from FE.  BE will guess if
        // this info is not there but there are cases it cannot get right.
        if (F.getParamAlignment(Idx))
          FrameAlign = F.getParamAlignment(Idx);
        Flags.setByValAlign(FrameAlign);
        Flags.setByValSize(FrameSize);
      }
      if (F.paramHasAttr(Idx, Attribute::Nest))
        Flags.setNest();
      Flags.setOrigAlign(OriginalAlignment);

      EVT RegisterVT = TLI.getRegisterType(*CurDAG->getContext(), VT);
      unsigned NumRegs = TLI.getNumRegisters(*CurDAG->getContext(), VT);
      for (unsigned i = 0; i != NumRegs; ++i) {
        ISD::InputArg MyFlags(Flags, RegisterVT, isArgValueUsed);
        if (NumRegs > 1 && i == 0)
          MyFlags.Flags.setSplit();
        // if it isn't first piece, alignment must be 1
        else if (i > 0)
          MyFlags.Flags.setOrigAlign(1);
        Ins.push_back(MyFlags);
      }
    }
  }

  // Call the target to set up the argument values.
  SmallVector<SDValue, 8> InVals;
  SDValue NewRoot = TLI.LowerFormalArguments(DAG.getRoot(), F.getCallingConv(),
                                             F.isVarArg(), Ins,
                                             dl, DAG, InVals);

  // Verify that the target's LowerFormalArguments behaved as expected.
  assert(NewRoot.getNode() && NewRoot.getValueType() == MVT::Other &&
         "LowerFormalArguments didn't return a valid chain!");
  assert(InVals.size() == Ins.size() &&
         "LowerFormalArguments didn't emit the correct number of values!");
  DEBUG(for (unsigned i = 0, e = Ins.size(); i != e; ++i) {
          assert(InVals[i].getNode() &&
                 "LowerFormalArguments emitted a null value!");
          assert(Ins[i].VT == InVals[i].getValueType() &&
                 "LowerFormalArguments emitted a value with the wrong type!");
        });

  // Update the DAG with the new chain value resulting from argument lowering.
  DAG.setRoot(NewRoot);

  // Set up the argument values.
  unsigned i = 0;
  Idx = 1;
  if (!FLI.CanLowerReturn) {
    // Create a virtual register for the sret pointer, and put in a copy
    // from the sret argument into it.
    SmallVector<EVT, 1> ValueVTs;
    ComputeValueVTs(TLI, PointerType::getUnqual(F.getReturnType()), ValueVTs);
    EVT VT = ValueVTs[0];
    EVT RegVT = TLI.getRegisterType(*CurDAG->getContext(), VT);
    ISD::NodeType AssertOp = ISD::DELETED_NODE;
    SDValue ArgValue = getCopyFromParts(DAG, dl, &InVals[0], 1, RegVT,
                                        VT, AssertOp);

    MachineFunction& MF = SDB->DAG.getMachineFunction();
    MachineRegisterInfo& RegInfo = MF.getRegInfo();
    unsigned SRetReg = RegInfo.createVirtualRegister(TLI.getRegClassFor(RegVT));
    FLI.DemoteRegister = SRetReg;
    NewRoot = SDB->DAG.getCopyToReg(NewRoot, SDB->getCurDebugLoc(), SRetReg, ArgValue);
    DAG.setRoot(NewRoot);
    
    // i indexes lowered arguments.  Bump it past the hidden sret argument.
    // Idx indexes LLVM arguments.  Don't touch it.
    ++i;
  }
  for (Function::arg_iterator I = F.arg_begin(), E = F.arg_end(); I != E;
      ++I, ++Idx) {
    SmallVector<SDValue, 4> ArgValues;
    SmallVector<EVT, 4> ValueVTs;
    ComputeValueVTs(TLI, I->getType(), ValueVTs);
    unsigned NumValues = ValueVTs.size();
    for (unsigned Value = 0; Value != NumValues; ++Value) {
      EVT VT = ValueVTs[Value];
      EVT PartVT = TLI.getRegisterType(*CurDAG->getContext(), VT);
      unsigned NumParts = TLI.getNumRegisters(*CurDAG->getContext(), VT);

      if (!I->use_empty()) {
        ISD::NodeType AssertOp = ISD::DELETED_NODE;
        if (F.paramHasAttr(Idx, Attribute::SExt))
          AssertOp = ISD::AssertSext;
        else if (F.paramHasAttr(Idx, Attribute::ZExt))
          AssertOp = ISD::AssertZext;

        ArgValues.push_back(getCopyFromParts(DAG, dl, &InVals[i], NumParts,
                                             PartVT, VT, AssertOp));
      }
      i += NumParts;
    }
    if (!I->use_empty()) {
      SDB->setValue(I, DAG.getMergeValues(&ArgValues[0], NumValues,
                                          SDB->getCurDebugLoc()));
      // If this argument is live outside of the entry block, insert a copy from
      // whereever we got it to the vreg that other BB's will reference it as.
      SDB->CopyToExportRegsIfNeeded(I);
    }
  }
  assert(i == InVals.size() && "Argument register count mismatch!");

  // Finally, if the target has anything special to do, allow it to do so.
  // FIXME: this should insert code into the DAG!
  EmitFunctionEntryCode(F, SDB->DAG.getMachineFunction());
}

/// Handle PHI nodes in successor blocks.  Emit code into the SelectionDAG to
/// ensure constants are generated when needed.  Remember the virtual registers
/// that need to be added to the Machine PHI nodes as input.  We cannot just
/// directly add them, because expansion might result in multiple MBB's for one
/// BB.  As such, the start of the BB might correspond to a different MBB than
/// the end.
///
void
SelectionDAGISel::HandlePHINodesInSuccessorBlocks(BasicBlock *LLVMBB) {
  TerminatorInst *TI = LLVMBB->getTerminator();

  SmallPtrSet<MachineBasicBlock *, 4> SuccsHandled;

  // Check successor nodes' PHI nodes that expect a constant to be available
  // from this block.
  for (unsigned succ = 0, e = TI->getNumSuccessors(); succ != e; ++succ) {
    BasicBlock *SuccBB = TI->getSuccessor(succ);
    if (!isa<PHINode>(SuccBB->begin())) continue;
    MachineBasicBlock *SuccMBB = FuncInfo->MBBMap[SuccBB];

    // If this terminator has multiple identical successors (common for
    // switches), only handle each succ once.
    if (!SuccsHandled.insert(SuccMBB)) continue;

    MachineBasicBlock::iterator MBBI = SuccMBB->begin();
    PHINode *PN;

    // At this point we know that there is a 1-1 correspondence between LLVM PHI
    // nodes and Machine PHI nodes, but the incoming operands have not been
    // emitted yet.
    for (BasicBlock::iterator I = SuccBB->begin();
         (PN = dyn_cast<PHINode>(I)); ++I) {
      // Ignore dead phi's.
      if (PN->use_empty()) continue;

      unsigned Reg;
      Value *PHIOp = PN->getIncomingValueForBlock(LLVMBB);

      if (Constant *C = dyn_cast<Constant>(PHIOp)) {
        unsigned &RegOut = SDB->ConstantsOut[C];
        if (RegOut == 0) {
          RegOut = FuncInfo->CreateRegForValue(C);
          SDB->CopyValueToVirtualRegister(C, RegOut);
        }
        Reg = RegOut;
      } else {
        Reg = FuncInfo->ValueMap[PHIOp];
        if (Reg == 0) {
          assert(isa<AllocaInst>(PHIOp) &&
                 FuncInfo->StaticAllocaMap.count(cast<AllocaInst>(PHIOp)) &&
                 "Didn't codegen value into a register!??");
          Reg = FuncInfo->CreateRegForValue(PHIOp);
          SDB->CopyValueToVirtualRegister(PHIOp, Reg);
        }
      }

      // Remember that this register needs to added to the machine PHI node as
      // the input for this MBB.
      SmallVector<EVT, 4> ValueVTs;
      ComputeValueVTs(TLI, PN->getType(), ValueVTs);
      for (unsigned vti = 0, vte = ValueVTs.size(); vti != vte; ++vti) {
        EVT VT = ValueVTs[vti];
        unsigned NumRegisters = TLI.getNumRegisters(*CurDAG->getContext(), VT);
        for (unsigned i = 0, e = NumRegisters; i != e; ++i)
          SDB->PHINodesToUpdate.push_back(std::make_pair(MBBI++, Reg+i));
        Reg += NumRegisters;
      }
    }
  }
  SDB->ConstantsOut.clear();
}

/// This is the Fast-ISel version of HandlePHINodesInSuccessorBlocks. It only
/// supports legal types, and it emits MachineInstrs directly instead of
/// creating SelectionDAG nodes.
///
bool
SelectionDAGISel::HandlePHINodesInSuccessorBlocksFast(BasicBlock *LLVMBB,
                                                      FastISel *F) {
  TerminatorInst *TI = LLVMBB->getTerminator();

  SmallPtrSet<MachineBasicBlock *, 4> SuccsHandled;
  unsigned OrigNumPHINodesToUpdate = SDB->PHINodesToUpdate.size();

  // Check successor nodes' PHI nodes that expect a constant to be available
  // from this block.
  for (unsigned succ = 0, e = TI->getNumSuccessors(); succ != e; ++succ) {
    BasicBlock *SuccBB = TI->getSuccessor(succ);
    if (!isa<PHINode>(SuccBB->begin())) continue;
    MachineBasicBlock *SuccMBB = FuncInfo->MBBMap[SuccBB];

    // If this terminator has multiple identical successors (common for
    // switches), only handle each succ once.
    if (!SuccsHandled.insert(SuccMBB)) continue;

    MachineBasicBlock::iterator MBBI = SuccMBB->begin();
    PHINode *PN;

    // At this point we know that there is a 1-1 correspondence between LLVM PHI
    // nodes and Machine PHI nodes, but the incoming operands have not been
    // emitted yet.
    for (BasicBlock::iterator I = SuccBB->begin();
         (PN = dyn_cast<PHINode>(I)); ++I) {
      // Ignore dead phi's.
      if (PN->use_empty()) continue;

      // Only handle legal types. Two interesting things to note here. First,
      // by bailing out early, we may leave behind some dead instructions,
      // since SelectionDAG's HandlePHINodesInSuccessorBlocks will insert its
      // own moves. Second, this check is necessary becuase FastISel doesn't
      // use CreateRegForValue to create registers, so it always creates
      // exactly one register for each non-void instruction.
      EVT VT = TLI.getValueType(PN->getType(), /*AllowUnknown=*/true);
      if (VT == MVT::Other || !TLI.isTypeLegal(VT)) {
        // Promote MVT::i1.
        if (VT == MVT::i1)
          VT = TLI.getTypeToTransformTo(*CurDAG->getContext(), VT);
        else {
          SDB->PHINodesToUpdate.resize(OrigNumPHINodesToUpdate);
          return false;
        }
      }

      Value *PHIOp = PN->getIncomingValueForBlock(LLVMBB);

      unsigned Reg = F->getRegForValue(PHIOp);
      if (Reg == 0) {
        SDB->PHINodesToUpdate.resize(OrigNumPHINodesToUpdate);
        return false;
      }
      SDB->PHINodesToUpdate.push_back(std::make_pair(MBBI++, Reg));
    }
  }

  return true;
}
