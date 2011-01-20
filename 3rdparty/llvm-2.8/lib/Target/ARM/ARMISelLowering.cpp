//===-- ARMISelLowering.cpp - ARM DAG Lowering Implementation -------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines the interfaces that ARM uses to lower LLVM code into a
// selection DAG.
//
//===----------------------------------------------------------------------===//

#define DEBUG_TYPE "arm-isel"
#include "ARM.h"
#include "ARMAddressingModes.h"
#include "ARMConstantPoolValue.h"
#include "ARMISelLowering.h"
#include "ARMMachineFunctionInfo.h"
#include "ARMPerfectShuffle.h"
#include "ARMRegisterInfo.h"
#include "ARMSubtarget.h"
#include "ARMTargetMachine.h"
#include "ARMTargetObjectFile.h"
#include "llvm/CallingConv.h"
#include "llvm/Constants.h"
#include "llvm/Function.h"
#include "llvm/GlobalValue.h"
#include "llvm/Instruction.h"
#include "llvm/Intrinsics.h"
#include "llvm/Type.h"
#include "llvm/CodeGen/CallingConvLower.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/CodeGen/PseudoSourceValue.h"
#include "llvm/CodeGen/SelectionDAG.h"
#include "llvm/MC/MCSectionMachO.h"
#include "llvm/Target/TargetOptions.h"
#include "llvm/ADT/VectorExtras.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/MathExtras.h"
#include "llvm/Support/raw_ostream.h"
#include <sstream>
using namespace llvm;

STATISTIC(NumTailCalls, "Number of tail calls");

// This option should go away when tail calls fully work.
static cl::opt<bool>
EnableARMTailCalls("arm-tail-calls", cl::Hidden,
  cl::desc("Generate tail calls (TEMPORARY OPTION)."),
  cl::init(false));

// This option should go away when Machine LICM is smart enough to hoist a 
// reg-to-reg VDUP.
static cl::opt<bool>
EnableARMVDUPsplat("arm-vdup-splat", cl::Hidden,
  cl::desc("Generate VDUP for integer constant splats (TEMPORARY OPTION)."),
  cl::init(false));

static cl::opt<bool>
EnableARMLongCalls("arm-long-calls", cl::Hidden,
  cl::desc("Generate calls via indirect call instructions"),
  cl::init(false));

static cl::opt<bool>
ARMInterworking("arm-interworking", cl::Hidden,
  cl::desc("Enable / disable ARM interworking (for debugging only)"),
  cl::init(true));

static cl::opt<bool>
EnableARMCodePlacement("arm-code-placement", cl::Hidden,
  cl::desc("Enable code placement pass for ARM"),
  cl::init(false));

static bool CC_ARM_APCS_Custom_f64(unsigned &ValNo, EVT &ValVT, EVT &LocVT,
                                   CCValAssign::LocInfo &LocInfo,
                                   ISD::ArgFlagsTy &ArgFlags,
                                   CCState &State);
static bool CC_ARM_AAPCS_Custom_f64(unsigned &ValNo, EVT &ValVT, EVT &LocVT,
                                    CCValAssign::LocInfo &LocInfo,
                                    ISD::ArgFlagsTy &ArgFlags,
                                    CCState &State);
static bool RetCC_ARM_APCS_Custom_f64(unsigned &ValNo, EVT &ValVT, EVT &LocVT,
                                      CCValAssign::LocInfo &LocInfo,
                                      ISD::ArgFlagsTy &ArgFlags,
                                      CCState &State);
static bool RetCC_ARM_AAPCS_Custom_f64(unsigned &ValNo, EVT &ValVT, EVT &LocVT,
                                       CCValAssign::LocInfo &LocInfo,
                                       ISD::ArgFlagsTy &ArgFlags,
                                       CCState &State);

void ARMTargetLowering::addTypeForNEON(EVT VT, EVT PromotedLdStVT,
                                       EVT PromotedBitwiseVT) {
  if (VT != PromotedLdStVT) {
    setOperationAction(ISD::LOAD, VT.getSimpleVT(), Promote);
    AddPromotedToType (ISD::LOAD, VT.getSimpleVT(),
                       PromotedLdStVT.getSimpleVT());

    setOperationAction(ISD::STORE, VT.getSimpleVT(), Promote);
    AddPromotedToType (ISD::STORE, VT.getSimpleVT(),
                       PromotedLdStVT.getSimpleVT());
  }

  EVT ElemTy = VT.getVectorElementType();
  if (ElemTy != MVT::i64 && ElemTy != MVT::f64)
    setOperationAction(ISD::VSETCC, VT.getSimpleVT(), Custom);
  if (ElemTy == MVT::i8 || ElemTy == MVT::i16)
    setOperationAction(ISD::EXTRACT_VECTOR_ELT, VT.getSimpleVT(), Custom);
  if (ElemTy != MVT::i32) {
    setOperationAction(ISD::SINT_TO_FP, VT.getSimpleVT(), Expand);
    setOperationAction(ISD::UINT_TO_FP, VT.getSimpleVT(), Expand);
    setOperationAction(ISD::FP_TO_SINT, VT.getSimpleVT(), Expand);
    setOperationAction(ISD::FP_TO_UINT, VT.getSimpleVT(), Expand);
  }
  setOperationAction(ISD::BUILD_VECTOR, VT.getSimpleVT(), Custom);
  setOperationAction(ISD::VECTOR_SHUFFLE, VT.getSimpleVT(), Custom);
  setOperationAction(ISD::CONCAT_VECTORS, VT.getSimpleVT(), Legal);
  setOperationAction(ISD::EXTRACT_SUBVECTOR, VT.getSimpleVT(), Expand);
  setOperationAction(ISD::SELECT, VT.getSimpleVT(), Expand);
  setOperationAction(ISD::SELECT_CC, VT.getSimpleVT(), Expand);
  if (VT.isInteger()) {
    setOperationAction(ISD::SHL, VT.getSimpleVT(), Custom);
    setOperationAction(ISD::SRA, VT.getSimpleVT(), Custom);
    setOperationAction(ISD::SRL, VT.getSimpleVT(), Custom);
    setLoadExtAction(ISD::SEXTLOAD, VT.getSimpleVT(), Expand);
    setLoadExtAction(ISD::ZEXTLOAD, VT.getSimpleVT(), Expand);
  }
  setLoadExtAction(ISD::EXTLOAD, VT.getSimpleVT(), Expand);

  // Promote all bit-wise operations.
  if (VT.isInteger() && VT != PromotedBitwiseVT) {
    setOperationAction(ISD::AND, VT.getSimpleVT(), Promote);
    AddPromotedToType (ISD::AND, VT.getSimpleVT(),
                       PromotedBitwiseVT.getSimpleVT());
    setOperationAction(ISD::OR,  VT.getSimpleVT(), Promote);
    AddPromotedToType (ISD::OR,  VT.getSimpleVT(),
                       PromotedBitwiseVT.getSimpleVT());
    setOperationAction(ISD::XOR, VT.getSimpleVT(), Promote);
    AddPromotedToType (ISD::XOR, VT.getSimpleVT(),
                       PromotedBitwiseVT.getSimpleVT());
  }

  // Neon does not support vector divide/remainder operations.
  setOperationAction(ISD::SDIV, VT.getSimpleVT(), Expand);
  setOperationAction(ISD::UDIV, VT.getSimpleVT(), Expand);
  setOperationAction(ISD::FDIV, VT.getSimpleVT(), Expand);
  setOperationAction(ISD::SREM, VT.getSimpleVT(), Expand);
  setOperationAction(ISD::UREM, VT.getSimpleVT(), Expand);
  setOperationAction(ISD::FREM, VT.getSimpleVT(), Expand);
}

void ARMTargetLowering::addDRTypeForNEON(EVT VT) {
  addRegisterClass(VT, ARM::DPRRegisterClass);
  addTypeForNEON(VT, MVT::f64, MVT::v2i32);
}

void ARMTargetLowering::addQRTypeForNEON(EVT VT) {
  addRegisterClass(VT, ARM::QPRRegisterClass);
  addTypeForNEON(VT, MVT::v2f64, MVT::v4i32);
}

static TargetLoweringObjectFile *createTLOF(TargetMachine &TM) {
  if (TM.getSubtarget<ARMSubtarget>().isTargetDarwin())
    return new TargetLoweringObjectFileMachO();

  return new ARMElfTargetObjectFile();
}

ARMTargetLowering::ARMTargetLowering(TargetMachine &TM)
    : TargetLowering(TM, createTLOF(TM)) {
  Subtarget = &TM.getSubtarget<ARMSubtarget>();
  RegInfo = TM.getRegisterInfo();

  if (Subtarget->isTargetDarwin()) {
    // Uses VFP for Thumb libfuncs if available.
    if (Subtarget->isThumb() && Subtarget->hasVFP2()) {
      // Single-precision floating-point arithmetic.
      setLibcallName(RTLIB::ADD_F32, "__addsf3vfp");
      setLibcallName(RTLIB::SUB_F32, "__subsf3vfp");
      setLibcallName(RTLIB::MUL_F32, "__mulsf3vfp");
      setLibcallName(RTLIB::DIV_F32, "__divsf3vfp");

      // Double-precision floating-point arithmetic.
      setLibcallName(RTLIB::ADD_F64, "__adddf3vfp");
      setLibcallName(RTLIB::SUB_F64, "__subdf3vfp");
      setLibcallName(RTLIB::MUL_F64, "__muldf3vfp");
      setLibcallName(RTLIB::DIV_F64, "__divdf3vfp");

      // Single-precision comparisons.
      setLibcallName(RTLIB::OEQ_F32, "__eqsf2vfp");
      setLibcallName(RTLIB::UNE_F32, "__nesf2vfp");
      setLibcallName(RTLIB::OLT_F32, "__ltsf2vfp");
      setLibcallName(RTLIB::OLE_F32, "__lesf2vfp");
      setLibcallName(RTLIB::OGE_F32, "__gesf2vfp");
      setLibcallName(RTLIB::OGT_F32, "__gtsf2vfp");
      setLibcallName(RTLIB::UO_F32,  "__unordsf2vfp");
      setLibcallName(RTLIB::O_F32,   "__unordsf2vfp");

      setCmpLibcallCC(RTLIB::OEQ_F32, ISD::SETNE);
      setCmpLibcallCC(RTLIB::UNE_F32, ISD::SETNE);
      setCmpLibcallCC(RTLIB::OLT_F32, ISD::SETNE);
      setCmpLibcallCC(RTLIB::OLE_F32, ISD::SETNE);
      setCmpLibcallCC(RTLIB::OGE_F32, ISD::SETNE);
      setCmpLibcallCC(RTLIB::OGT_F32, ISD::SETNE);
      setCmpLibcallCC(RTLIB::UO_F32,  ISD::SETNE);
      setCmpLibcallCC(RTLIB::O_F32,   ISD::SETEQ);

      // Double-precision comparisons.
      setLibcallName(RTLIB::OEQ_F64, "__eqdf2vfp");
      setLibcallName(RTLIB::UNE_F64, "__nedf2vfp");
      setLibcallName(RTLIB::OLT_F64, "__ltdf2vfp");
      setLibcallName(RTLIB::OLE_F64, "__ledf2vfp");
      setLibcallName(RTLIB::OGE_F64, "__gedf2vfp");
      setLibcallName(RTLIB::OGT_F64, "__gtdf2vfp");
      setLibcallName(RTLIB::UO_F64,  "__unorddf2vfp");
      setLibcallName(RTLIB::O_F64,   "__unorddf2vfp");

      setCmpLibcallCC(RTLIB::OEQ_F64, ISD::SETNE);
      setCmpLibcallCC(RTLIB::UNE_F64, ISD::SETNE);
      setCmpLibcallCC(RTLIB::OLT_F64, ISD::SETNE);
      setCmpLibcallCC(RTLIB::OLE_F64, ISD::SETNE);
      setCmpLibcallCC(RTLIB::OGE_F64, ISD::SETNE);
      setCmpLibcallCC(RTLIB::OGT_F64, ISD::SETNE);
      setCmpLibcallCC(RTLIB::UO_F64,  ISD::SETNE);
      setCmpLibcallCC(RTLIB::O_F64,   ISD::SETEQ);

      // Floating-point to integer conversions.
      // i64 conversions are done via library routines even when generating VFP
      // instructions, so use the same ones.
      setLibcallName(RTLIB::FPTOSINT_F64_I32, "__fixdfsivfp");
      setLibcallName(RTLIB::FPTOUINT_F64_I32, "__fixunsdfsivfp");
      setLibcallName(RTLIB::FPTOSINT_F32_I32, "__fixsfsivfp");
      setLibcallName(RTLIB::FPTOUINT_F32_I32, "__fixunssfsivfp");

      // Conversions between floating types.
      setLibcallName(RTLIB::FPROUND_F64_F32, "__truncdfsf2vfp");
      setLibcallName(RTLIB::FPEXT_F32_F64,   "__extendsfdf2vfp");

      // Integer to floating-point conversions.
      // i64 conversions are done via library routines even when generating VFP
      // instructions, so use the same ones.
      // FIXME: There appears to be some naming inconsistency in ARM libgcc:
      // e.g., __floatunsidf vs. __floatunssidfvfp.
      setLibcallName(RTLIB::SINTTOFP_I32_F64, "__floatsidfvfp");
      setLibcallName(RTLIB::UINTTOFP_I32_F64, "__floatunssidfvfp");
      setLibcallName(RTLIB::SINTTOFP_I32_F32, "__floatsisfvfp");
      setLibcallName(RTLIB::UINTTOFP_I32_F32, "__floatunssisfvfp");
    }
  }

  // These libcalls are not available in 32-bit.
  setLibcallName(RTLIB::SHL_I128, 0);
  setLibcallName(RTLIB::SRL_I128, 0);
  setLibcallName(RTLIB::SRA_I128, 0);

  // Libcalls should use the AAPCS base standard ABI, even if hard float
  // is in effect, as per the ARM RTABI specification, section 4.1.2.
  if (Subtarget->isAAPCS_ABI()) {
    for (int i = 0; i < RTLIB::UNKNOWN_LIBCALL; ++i) {
      setLibcallCallingConv(static_cast<RTLIB::Libcall>(i),
                            CallingConv::ARM_AAPCS);
    }
  }

  if (Subtarget->isThumb1Only())
    addRegisterClass(MVT::i32, ARM::tGPRRegisterClass);
  else
    addRegisterClass(MVT::i32, ARM::GPRRegisterClass);
  if (!UseSoftFloat && Subtarget->hasVFP2() && !Subtarget->isThumb1Only()) {
    addRegisterClass(MVT::f32, ARM::SPRRegisterClass);
    if (!Subtarget->isFPOnlySP())
      addRegisterClass(MVT::f64, ARM::DPRRegisterClass);

    setTruncStoreAction(MVT::f64, MVT::f32, Expand);
  }

  if (Subtarget->hasNEON()) {
    addDRTypeForNEON(MVT::v2f32);
    addDRTypeForNEON(MVT::v8i8);
    addDRTypeForNEON(MVT::v4i16);
    addDRTypeForNEON(MVT::v2i32);
    addDRTypeForNEON(MVT::v1i64);

    addQRTypeForNEON(MVT::v4f32);
    addQRTypeForNEON(MVT::v2f64);
    addQRTypeForNEON(MVT::v16i8);
    addQRTypeForNEON(MVT::v8i16);
    addQRTypeForNEON(MVT::v4i32);
    addQRTypeForNEON(MVT::v2i64);

    // v2f64 is legal so that QR subregs can be extracted as f64 elements, but
    // neither Neon nor VFP support any arithmetic operations on it.
    setOperationAction(ISD::FADD, MVT::v2f64, Expand);
    setOperationAction(ISD::FSUB, MVT::v2f64, Expand);
    setOperationAction(ISD::FMUL, MVT::v2f64, Expand);
    setOperationAction(ISD::FDIV, MVT::v2f64, Expand);
    setOperationAction(ISD::FREM, MVT::v2f64, Expand);
    setOperationAction(ISD::FCOPYSIGN, MVT::v2f64, Expand);
    setOperationAction(ISD::VSETCC, MVT::v2f64, Expand);
    setOperationAction(ISD::FNEG, MVT::v2f64, Expand);
    setOperationAction(ISD::FABS, MVT::v2f64, Expand);
    setOperationAction(ISD::FSQRT, MVT::v2f64, Expand);
    setOperationAction(ISD::FSIN, MVT::v2f64, Expand);
    setOperationAction(ISD::FCOS, MVT::v2f64, Expand);
    setOperationAction(ISD::FPOWI, MVT::v2f64, Expand);
    setOperationAction(ISD::FPOW, MVT::v2f64, Expand);
    setOperationAction(ISD::FLOG, MVT::v2f64, Expand);
    setOperationAction(ISD::FLOG2, MVT::v2f64, Expand);
    setOperationAction(ISD::FLOG10, MVT::v2f64, Expand);
    setOperationAction(ISD::FEXP, MVT::v2f64, Expand);
    setOperationAction(ISD::FEXP2, MVT::v2f64, Expand);
    setOperationAction(ISD::FCEIL, MVT::v2f64, Expand);
    setOperationAction(ISD::FTRUNC, MVT::v2f64, Expand);
    setOperationAction(ISD::FRINT, MVT::v2f64, Expand);
    setOperationAction(ISD::FNEARBYINT, MVT::v2f64, Expand);
    setOperationAction(ISD::FFLOOR, MVT::v2f64, Expand);

    setTruncStoreAction(MVT::v2f64, MVT::v2f32, Expand);

    // Neon does not support some operations on v1i64 and v2i64 types.
    setOperationAction(ISD::MUL, MVT::v1i64, Expand);
    // Custom handling for some quad-vector types to detect VMULL.
    setOperationAction(ISD::MUL, MVT::v8i16, Custom);
    setOperationAction(ISD::MUL, MVT::v4i32, Custom);
    setOperationAction(ISD::MUL, MVT::v2i64, Custom);
    setOperationAction(ISD::VSETCC, MVT::v1i64, Expand);
    setOperationAction(ISD::VSETCC, MVT::v2i64, Expand);

    setTargetDAGCombine(ISD::INTRINSIC_WO_CHAIN);
    setTargetDAGCombine(ISD::SHL);
    setTargetDAGCombine(ISD::SRL);
    setTargetDAGCombine(ISD::SRA);
    setTargetDAGCombine(ISD::SIGN_EXTEND);
    setTargetDAGCombine(ISD::ZERO_EXTEND);
    setTargetDAGCombine(ISD::ANY_EXTEND);
    setTargetDAGCombine(ISD::SELECT_CC);
  }

  computeRegisterProperties();

  // ARM does not have f32 extending load.
  setLoadExtAction(ISD::EXTLOAD, MVT::f32, Expand);

  // ARM does not have i1 sign extending load.
  setLoadExtAction(ISD::SEXTLOAD, MVT::i1, Promote);

  // ARM supports all 4 flavors of integer indexed load / store.
  if (!Subtarget->isThumb1Only()) {
    for (unsigned im = (unsigned)ISD::PRE_INC;
         im != (unsigned)ISD::LAST_INDEXED_MODE; ++im) {
      setIndexedLoadAction(im,  MVT::i1,  Legal);
      setIndexedLoadAction(im,  MVT::i8,  Legal);
      setIndexedLoadAction(im,  MVT::i16, Legal);
      setIndexedLoadAction(im,  MVT::i32, Legal);
      setIndexedStoreAction(im, MVT::i1,  Legal);
      setIndexedStoreAction(im, MVT::i8,  Legal);
      setIndexedStoreAction(im, MVT::i16, Legal);
      setIndexedStoreAction(im, MVT::i32, Legal);
    }
  }

  // i64 operation support.
  if (Subtarget->isThumb1Only()) {
    setOperationAction(ISD::MUL,     MVT::i64, Expand);
    setOperationAction(ISD::MULHU,   MVT::i32, Expand);
    setOperationAction(ISD::MULHS,   MVT::i32, Expand);
    setOperationAction(ISD::UMUL_LOHI, MVT::i32, Expand);
    setOperationAction(ISD::SMUL_LOHI, MVT::i32, Expand);
  } else {
    setOperationAction(ISD::MUL,     MVT::i64, Expand);
    setOperationAction(ISD::MULHU,   MVT::i32, Expand);
    if (!Subtarget->hasV6Ops())
      setOperationAction(ISD::MULHS, MVT::i32, Expand);
  }
  setOperationAction(ISD::SHL_PARTS, MVT::i32, Custom);
  setOperationAction(ISD::SRA_PARTS, MVT::i32, Custom);
  setOperationAction(ISD::SRL_PARTS, MVT::i32, Custom);
  setOperationAction(ISD::SRL,       MVT::i64, Custom);
  setOperationAction(ISD::SRA,       MVT::i64, Custom);

  // ARM does not have ROTL.
  setOperationAction(ISD::ROTL,  MVT::i32, Expand);
  setOperationAction(ISD::CTTZ,  MVT::i32, Custom);
  setOperationAction(ISD::CTPOP, MVT::i32, Expand);
  if (!Subtarget->hasV5TOps() || Subtarget->isThumb1Only())
    setOperationAction(ISD::CTLZ, MVT::i32, Expand);

  // Only ARMv6 has BSWAP.
  if (!Subtarget->hasV6Ops())
    setOperationAction(ISD::BSWAP, MVT::i32, Expand);

  // These are expanded into libcalls.
  if (!Subtarget->hasDivide()) {
    // v7M has a hardware divider
    setOperationAction(ISD::SDIV,  MVT::i32, Expand);
    setOperationAction(ISD::UDIV,  MVT::i32, Expand);
  }
  setOperationAction(ISD::SREM,  MVT::i32, Expand);
  setOperationAction(ISD::UREM,  MVT::i32, Expand);
  setOperationAction(ISD::SDIVREM, MVT::i32, Expand);
  setOperationAction(ISD::UDIVREM, MVT::i32, Expand);

  setOperationAction(ISD::GlobalAddress, MVT::i32,   Custom);
  setOperationAction(ISD::ConstantPool,  MVT::i32,   Custom);
  setOperationAction(ISD::GLOBAL_OFFSET_TABLE, MVT::i32, Custom);
  setOperationAction(ISD::GlobalTLSAddress, MVT::i32, Custom);
  setOperationAction(ISD::BlockAddress, MVT::i32, Custom);

  setOperationAction(ISD::TRAP, MVT::Other, Legal);

  // Use the default implementation.
  setOperationAction(ISD::VASTART,            MVT::Other, Custom);
  setOperationAction(ISD::VAARG,              MVT::Other, Expand);
  setOperationAction(ISD::VACOPY,             MVT::Other, Expand);
  setOperationAction(ISD::VAEND,              MVT::Other, Expand);
  setOperationAction(ISD::STACKSAVE,          MVT::Other, Expand);
  setOperationAction(ISD::STACKRESTORE,       MVT::Other, Expand);
  setOperationAction(ISD::EHSELECTION,        MVT::i32,   Expand);
  // FIXME: Shouldn't need this, since no register is used, but the legalizer
  // doesn't yet know how to not do that for SjLj.
  setExceptionSelectorRegister(ARM::R0);
  setOperationAction(ISD::DYNAMIC_STACKALLOC, MVT::i32, Expand);
  // ARMv6 Thumb1 (except for CPUs that support dmb / dsb) and earlier use
  // the default expansion.
  if (Subtarget->hasDataBarrier() ||
      (Subtarget->hasV6Ops() && !Subtarget->isThumb1Only())) {
    // membarrier needs custom lowering; the rest are legal and handled
    // normally.
    setOperationAction(ISD::MEMBARRIER, MVT::Other, Custom);
  } else {
    // Set them all for expansion, which will force libcalls.
    setOperationAction(ISD::MEMBARRIER, MVT::Other, Expand);
    setOperationAction(ISD::ATOMIC_CMP_SWAP,  MVT::i8,  Expand);
    setOperationAction(ISD::ATOMIC_CMP_SWAP,  MVT::i16, Expand);
    setOperationAction(ISD::ATOMIC_CMP_SWAP,  MVT::i32, Expand);
    setOperationAction(ISD::ATOMIC_SWAP,      MVT::i8,  Expand);
    setOperationAction(ISD::ATOMIC_SWAP,      MVT::i16, Expand);
    setOperationAction(ISD::ATOMIC_SWAP,      MVT::i32, Expand);
    setOperationAction(ISD::ATOMIC_LOAD_ADD,  MVT::i8,  Expand);
    setOperationAction(ISD::ATOMIC_LOAD_ADD,  MVT::i16, Expand);
    setOperationAction(ISD::ATOMIC_LOAD_ADD,  MVT::i32, Expand);
    setOperationAction(ISD::ATOMIC_LOAD_SUB,  MVT::i8,  Expand);
    setOperationAction(ISD::ATOMIC_LOAD_SUB,  MVT::i16, Expand);
    setOperationAction(ISD::ATOMIC_LOAD_SUB,  MVT::i32, Expand);
    setOperationAction(ISD::ATOMIC_LOAD_AND,  MVT::i8,  Expand);
    setOperationAction(ISD::ATOMIC_LOAD_AND,  MVT::i16, Expand);
    setOperationAction(ISD::ATOMIC_LOAD_AND,  MVT::i32, Expand);
    setOperationAction(ISD::ATOMIC_LOAD_OR,   MVT::i8,  Expand);
    setOperationAction(ISD::ATOMIC_LOAD_OR,   MVT::i16, Expand);
    setOperationAction(ISD::ATOMIC_LOAD_OR,   MVT::i32, Expand);
    setOperationAction(ISD::ATOMIC_LOAD_XOR,  MVT::i8,  Expand);
    setOperationAction(ISD::ATOMIC_LOAD_XOR,  MVT::i16, Expand);
    setOperationAction(ISD::ATOMIC_LOAD_XOR,  MVT::i32, Expand);
    setOperationAction(ISD::ATOMIC_LOAD_NAND, MVT::i8,  Expand);
    setOperationAction(ISD::ATOMIC_LOAD_NAND, MVT::i16, Expand);
    setOperationAction(ISD::ATOMIC_LOAD_NAND, MVT::i32, Expand);
    // Since the libcalls include locking, fold in the fences
    setShouldFoldAtomicFences(true);
  }
  // 64-bit versions are always libcalls (for now)
  setOperationAction(ISD::ATOMIC_CMP_SWAP,  MVT::i64, Expand);
  setOperationAction(ISD::ATOMIC_SWAP,      MVT::i64, Expand);
  setOperationAction(ISD::ATOMIC_LOAD_ADD,  MVT::i64, Expand);
  setOperationAction(ISD::ATOMIC_LOAD_SUB,  MVT::i64, Expand);
  setOperationAction(ISD::ATOMIC_LOAD_AND,  MVT::i64, Expand);
  setOperationAction(ISD::ATOMIC_LOAD_OR,   MVT::i64, Expand);
  setOperationAction(ISD::ATOMIC_LOAD_XOR,  MVT::i64, Expand);
  setOperationAction(ISD::ATOMIC_LOAD_NAND, MVT::i64, Expand);

  // Requires SXTB/SXTH, available on v6 and up in both ARM and Thumb modes.
  if (!Subtarget->hasV6Ops()) {
    setOperationAction(ISD::SIGN_EXTEND_INREG, MVT::i16, Expand);
    setOperationAction(ISD::SIGN_EXTEND_INREG, MVT::i8,  Expand);
  }
  setOperationAction(ISD::SIGN_EXTEND_INREG, MVT::i1, Expand);

  if (!UseSoftFloat && Subtarget->hasVFP2() && !Subtarget->isThumb1Only()) {
    // Turn f64->i64 into VMOVRRD, i64 -> f64 to VMOVDRR
    // iff target supports vfp2.
    setOperationAction(ISD::BIT_CONVERT, MVT::i64, Custom);
    setOperationAction(ISD::FLT_ROUNDS_, MVT::i32, Custom);
  }

  // We want to custom lower some of our intrinsics.
  setOperationAction(ISD::INTRINSIC_WO_CHAIN, MVT::Other, Custom);
  if (Subtarget->isTargetDarwin()) {
    setOperationAction(ISD::EH_SJLJ_SETJMP, MVT::i32, Custom);
    setOperationAction(ISD::EH_SJLJ_LONGJMP, MVT::Other, Custom);
  }

  setOperationAction(ISD::SETCC,     MVT::i32, Expand);
  setOperationAction(ISD::SETCC,     MVT::f32, Expand);
  setOperationAction(ISD::SETCC,     MVT::f64, Expand);
  setOperationAction(ISD::SELECT,    MVT::i32, Custom);
  setOperationAction(ISD::SELECT,    MVT::f32, Custom);
  setOperationAction(ISD::SELECT,    MVT::f64, Custom);
  setOperationAction(ISD::SELECT_CC, MVT::i32, Custom);
  setOperationAction(ISD::SELECT_CC, MVT::f32, Custom);
  setOperationAction(ISD::SELECT_CC, MVT::f64, Custom);

  setOperationAction(ISD::BRCOND,    MVT::Other, Expand);
  setOperationAction(ISD::BR_CC,     MVT::i32,   Custom);
  setOperationAction(ISD::BR_CC,     MVT::f32,   Custom);
  setOperationAction(ISD::BR_CC,     MVT::f64,   Custom);
  setOperationAction(ISD::BR_JT,     MVT::Other, Custom);

  // We don't support sin/cos/fmod/copysign/pow
  setOperationAction(ISD::FSIN,      MVT::f64, Expand);
  setOperationAction(ISD::FSIN,      MVT::f32, Expand);
  setOperationAction(ISD::FCOS,      MVT::f32, Expand);
  setOperationAction(ISD::FCOS,      MVT::f64, Expand);
  setOperationAction(ISD::FREM,      MVT::f64, Expand);
  setOperationAction(ISD::FREM,      MVT::f32, Expand);
  if (!UseSoftFloat && Subtarget->hasVFP2() && !Subtarget->isThumb1Only()) {
    setOperationAction(ISD::FCOPYSIGN, MVT::f64, Custom);
    setOperationAction(ISD::FCOPYSIGN, MVT::f32, Custom);
  }
  setOperationAction(ISD::FPOW,      MVT::f64, Expand);
  setOperationAction(ISD::FPOW,      MVT::f32, Expand);

  // Various VFP goodness
  if (!UseSoftFloat && !Subtarget->isThumb1Only()) {
    // int <-> fp are custom expanded into bit_convert + ARMISD ops.
    if (Subtarget->hasVFP2()) {
      setOperationAction(ISD::SINT_TO_FP, MVT::i32, Custom);
      setOperationAction(ISD::UINT_TO_FP, MVT::i32, Custom);
      setOperationAction(ISD::FP_TO_UINT, MVT::i32, Custom);
      setOperationAction(ISD::FP_TO_SINT, MVT::i32, Custom);
    }
    // Special handling for half-precision FP.
    if (!Subtarget->hasFP16()) {
      setOperationAction(ISD::FP16_TO_FP32, MVT::f32, Expand);
      setOperationAction(ISD::FP32_TO_FP16, MVT::i32, Expand);
    }
  }

  // We have target-specific dag combine patterns for the following nodes:
  // ARMISD::VMOVRRD  - No need to call setTargetDAGCombine
  setTargetDAGCombine(ISD::ADD);
  setTargetDAGCombine(ISD::SUB);
  setTargetDAGCombine(ISD::MUL);

  if (Subtarget->hasV6T2Ops())
    setTargetDAGCombine(ISD::OR);

  setStackPointerRegisterToSaveRestore(ARM::SP);

  if (UseSoftFloat || Subtarget->isThumb1Only() || !Subtarget->hasVFP2())
    setSchedulingPreference(Sched::RegPressure);
  else
    setSchedulingPreference(Sched::Hybrid);

  maxStoresPerMemcpy = 1;   //// temporary - rewrite interface to use type

  // On ARM arguments smaller than 4 bytes are extended, so all arguments
  // are at least 4 bytes aligned.
  setMinStackArgumentAlignment(4);

  if (EnableARMCodePlacement)
    benefitFromCodePlacementOpt = true;
}

std::pair<const TargetRegisterClass*, uint8_t>
ARMTargetLowering::findRepresentativeClass(EVT VT) const{
  const TargetRegisterClass *RRC = 0;
  uint8_t Cost = 1;
  switch (VT.getSimpleVT().SimpleTy) {
  default:
    return TargetLowering::findRepresentativeClass(VT);
  // Use DPR as representative register class for all floating point
  // and vector types. Since there are 32 SPR registers and 32 DPR registers so
  // the cost is 1 for both f32 and f64.
  case MVT::f32: case MVT::f64: case MVT::v8i8: case MVT::v4i16:
  case MVT::v2i32: case MVT::v1i64: case MVT::v2f32:
    RRC = ARM::DPRRegisterClass;
    break;
  case MVT::v16i8: case MVT::v8i16: case MVT::v4i32: case MVT::v2i64:
  case MVT::v4f32: case MVT::v2f64:
    RRC = ARM::DPRRegisterClass;
    Cost = 2;
    break;
  case MVT::v4i64:
    RRC = ARM::DPRRegisterClass;
    Cost = 4;
    break;
  case MVT::v8i64:
    RRC = ARM::DPRRegisterClass;
    Cost = 8;
    break;
  }
  return std::make_pair(RRC, Cost);
}

const char *ARMTargetLowering::getTargetNodeName(unsigned Opcode) const {
  switch (Opcode) {
  default: return 0;
  case ARMISD::Wrapper:       return "ARMISD::Wrapper";
  case ARMISD::WrapperJT:     return "ARMISD::WrapperJT";
  case ARMISD::CALL:          return "ARMISD::CALL";
  case ARMISD::CALL_PRED:     return "ARMISD::CALL_PRED";
  case ARMISD::CALL_NOLINK:   return "ARMISD::CALL_NOLINK";
  case ARMISD::tCALL:         return "ARMISD::tCALL";
  case ARMISD::BRCOND:        return "ARMISD::BRCOND";
  case ARMISD::BR_JT:         return "ARMISD::BR_JT";
  case ARMISD::BR2_JT:        return "ARMISD::BR2_JT";
  case ARMISD::RET_FLAG:      return "ARMISD::RET_FLAG";
  case ARMISD::PIC_ADD:       return "ARMISD::PIC_ADD";
  case ARMISD::AND:           return "ARMISD::AND";
  case ARMISD::CMP:           return "ARMISD::CMP";
  case ARMISD::CMPZ:          return "ARMISD::CMPZ";
  case ARMISD::CMPFP:         return "ARMISD::CMPFP";
  case ARMISD::CMPFPw0:       return "ARMISD::CMPFPw0";
  case ARMISD::BCC_i64:       return "ARMISD::BCC_i64";
  case ARMISD::FMSTAT:        return "ARMISD::FMSTAT";
  case ARMISD::CMOV:          return "ARMISD::CMOV";
  case ARMISD::CNEG:          return "ARMISD::CNEG";

  case ARMISD::RBIT:          return "ARMISD::RBIT";

  case ARMISD::FTOSI:         return "ARMISD::FTOSI";
  case ARMISD::FTOUI:         return "ARMISD::FTOUI";
  case ARMISD::SITOF:         return "ARMISD::SITOF";
  case ARMISD::UITOF:         return "ARMISD::UITOF";

  case ARMISD::SRL_FLAG:      return "ARMISD::SRL_FLAG";
  case ARMISD::SRA_FLAG:      return "ARMISD::SRA_FLAG";
  case ARMISD::RRX:           return "ARMISD::RRX";

  case ARMISD::VMOVRRD:         return "ARMISD::VMOVRRD";
  case ARMISD::VMOVDRR:         return "ARMISD::VMOVDRR";

  case ARMISD::EH_SJLJ_SETJMP: return "ARMISD::EH_SJLJ_SETJMP";
  case ARMISD::EH_SJLJ_LONGJMP:return "ARMISD::EH_SJLJ_LONGJMP";

  case ARMISD::TC_RETURN:     return "ARMISD::TC_RETURN";
  
  case ARMISD::THREAD_POINTER:return "ARMISD::THREAD_POINTER";

  case ARMISD::DYN_ALLOC:     return "ARMISD::DYN_ALLOC";

  case ARMISD::MEMBARRIER:    return "ARMISD::MEMBARRIER";
  case ARMISD::SYNCBARRIER:   return "ARMISD::SYNCBARRIER";

  case ARMISD::VCEQ:          return "ARMISD::VCEQ";
  case ARMISD::VCGE:          return "ARMISD::VCGE";
  case ARMISD::VCGEU:         return "ARMISD::VCGEU";
  case ARMISD::VCGT:          return "ARMISD::VCGT";
  case ARMISD::VCGTU:         return "ARMISD::VCGTU";
  case ARMISD::VTST:          return "ARMISD::VTST";

  case ARMISD::VSHL:          return "ARMISD::VSHL";
  case ARMISD::VSHRs:         return "ARMISD::VSHRs";
  case ARMISD::VSHRu:         return "ARMISD::VSHRu";
  case ARMISD::VSHLLs:        return "ARMISD::VSHLLs";
  case ARMISD::VSHLLu:        return "ARMISD::VSHLLu";
  case ARMISD::VSHLLi:        return "ARMISD::VSHLLi";
  case ARMISD::VSHRN:         return "ARMISD::VSHRN";
  case ARMISD::VRSHRs:        return "ARMISD::VRSHRs";
  case ARMISD::VRSHRu:        return "ARMISD::VRSHRu";
  case ARMISD::VRSHRN:        return "ARMISD::VRSHRN";
  case ARMISD::VQSHLs:        return "ARMISD::VQSHLs";
  case ARMISD::VQSHLu:        return "ARMISD::VQSHLu";
  case ARMISD::VQSHLsu:       return "ARMISD::VQSHLsu";
  case ARMISD::VQSHRNs:       return "ARMISD::VQSHRNs";
  case ARMISD::VQSHRNu:       return "ARMISD::VQSHRNu";
  case ARMISD::VQSHRNsu:      return "ARMISD::VQSHRNsu";
  case ARMISD::VQRSHRNs:      return "ARMISD::VQRSHRNs";
  case ARMISD::VQRSHRNu:      return "ARMISD::VQRSHRNu";
  case ARMISD::VQRSHRNsu:     return "ARMISD::VQRSHRNsu";
  case ARMISD::VGETLANEu:     return "ARMISD::VGETLANEu";
  case ARMISD::VGETLANEs:     return "ARMISD::VGETLANEs";
  case ARMISD::VMOVIMM:       return "ARMISD::VMOVIMM";
  case ARMISD::VMVNIMM:       return "ARMISD::VMVNIMM";
  case ARMISD::VDUP:          return "ARMISD::VDUP";
  case ARMISD::VDUPLANE:      return "ARMISD::VDUPLANE";
  case ARMISD::VEXT:          return "ARMISD::VEXT";
  case ARMISD::VREV64:        return "ARMISD::VREV64";
  case ARMISD::VREV32:        return "ARMISD::VREV32";
  case ARMISD::VREV16:        return "ARMISD::VREV16";
  case ARMISD::VZIP:          return "ARMISD::VZIP";
  case ARMISD::VUZP:          return "ARMISD::VUZP";
  case ARMISD::VTRN:          return "ARMISD::VTRN";
  case ARMISD::VMULLs:        return "ARMISD::VMULLs";
  case ARMISD::VMULLu:        return "ARMISD::VMULLu";
  case ARMISD::BUILD_VECTOR:  return "ARMISD::BUILD_VECTOR";
  case ARMISD::FMAX:          return "ARMISD::FMAX";
  case ARMISD::FMIN:          return "ARMISD::FMIN";
  case ARMISD::BFI:           return "ARMISD::BFI";
  }
}

/// getRegClassFor - Return the register class that should be used for the
/// specified value type.
TargetRegisterClass *ARMTargetLowering::getRegClassFor(EVT VT) const {
  // Map v4i64 to QQ registers but do not make the type legal. Similarly map
  // v8i64 to QQQQ registers. v4i64 and v8i64 are only used for REG_SEQUENCE to
  // load / store 4 to 8 consecutive D registers.
  if (Subtarget->hasNEON()) {
    if (VT == MVT::v4i64)
      return ARM::QQPRRegisterClass;
    else if (VT == MVT::v8i64)
      return ARM::QQQQPRRegisterClass;
  }
  return TargetLowering::getRegClassFor(VT);
}

// Create a fast isel object.
FastISel *
ARMTargetLowering::createFastISel(FunctionLoweringInfo &funcInfo) const {
  return ARM::createFastISel(funcInfo);
}

/// getFunctionAlignment - Return the Log2 alignment of this function.
unsigned ARMTargetLowering::getFunctionAlignment(const Function *F) const {
  return getTargetMachine().getSubtarget<ARMSubtarget>().isThumb() ? 1 : 2;
}

/// getMaximalGlobalOffset - Returns the maximal possible offset which can
/// be used for loads / stores from the global.
unsigned ARMTargetLowering::getMaximalGlobalOffset() const {
  return (Subtarget->isThumb1Only() ? 127 : 4095);
}

Sched::Preference ARMTargetLowering::getSchedulingPreference(SDNode *N) const {
  unsigned NumVals = N->getNumValues();
  if (!NumVals)
    return Sched::RegPressure;

  for (unsigned i = 0; i != NumVals; ++i) {
    EVT VT = N->getValueType(i);
    if (VT.isFloatingPoint() || VT.isVector())
      return Sched::Latency;
  }

  if (!N->isMachineOpcode())
    return Sched::RegPressure;

  // Load are scheduled for latency even if there instruction itinerary
  // is not available.
  const TargetInstrInfo *TII = getTargetMachine().getInstrInfo();
  const TargetInstrDesc &TID = TII->get(N->getMachineOpcode());
  if (TID.mayLoad())
    return Sched::Latency;

  const InstrItineraryData &Itins = getTargetMachine().getInstrItineraryData();
  if (!Itins.isEmpty() && Itins.getStageLatency(TID.getSchedClass()) > 2)
    return Sched::Latency;
  return Sched::RegPressure;
}

unsigned
ARMTargetLowering::getRegPressureLimit(const TargetRegisterClass *RC,
                                       MachineFunction &MF) const {
  switch (RC->getID()) {
  default:
    return 0;
  case ARM::tGPRRegClassID:
    return RegInfo->hasFP(MF) ? 4 : 5;
  case ARM::GPRRegClassID: {
    unsigned FP = RegInfo->hasFP(MF) ? 1 : 0;
    return 10 - FP - (Subtarget->isR9Reserved() ? 1 : 0);
  }
  case ARM::SPRRegClassID:  // Currently not used as 'rep' register class.
  case ARM::DPRRegClassID:
    return 32 - 10;
  }
}

//===----------------------------------------------------------------------===//
// Lowering Code
//===----------------------------------------------------------------------===//

/// IntCCToARMCC - Convert a DAG integer condition code to an ARM CC
static ARMCC::CondCodes IntCCToARMCC(ISD::CondCode CC) {
  switch (CC) {
  default: llvm_unreachable("Unknown condition code!");
  case ISD::SETNE:  return ARMCC::NE;
  case ISD::SETEQ:  return ARMCC::EQ;
  case ISD::SETGT:  return ARMCC::GT;
  case ISD::SETGE:  return ARMCC::GE;
  case ISD::SETLT:  return ARMCC::LT;
  case ISD::SETLE:  return ARMCC::LE;
  case ISD::SETUGT: return ARMCC::HI;
  case ISD::SETUGE: return ARMCC::HS;
  case ISD::SETULT: return ARMCC::LO;
  case ISD::SETULE: return ARMCC::LS;
  }
}

/// FPCCToARMCC - Convert a DAG fp condition code to an ARM CC.
static void FPCCToARMCC(ISD::CondCode CC, ARMCC::CondCodes &CondCode,
                        ARMCC::CondCodes &CondCode2) {
  CondCode2 = ARMCC::AL;
  switch (CC) {
  default: llvm_unreachable("Unknown FP condition!");
  case ISD::SETEQ:
  case ISD::SETOEQ: CondCode = ARMCC::EQ; break;
  case ISD::SETGT:
  case ISD::SETOGT: CondCode = ARMCC::GT; break;
  case ISD::SETGE:
  case ISD::SETOGE: CondCode = ARMCC::GE; break;
  case ISD::SETOLT: CondCode = ARMCC::MI; break;
  case ISD::SETOLE: CondCode = ARMCC::LS; break;
  case ISD::SETONE: CondCode = ARMCC::MI; CondCode2 = ARMCC::GT; break;
  case ISD::SETO:   CondCode = ARMCC::VC; break;
  case ISD::SETUO:  CondCode = ARMCC::VS; break;
  case ISD::SETUEQ: CondCode = ARMCC::EQ; CondCode2 = ARMCC::VS; break;
  case ISD::SETUGT: CondCode = ARMCC::HI; break;
  case ISD::SETUGE: CondCode = ARMCC::PL; break;
  case ISD::SETLT:
  case ISD::SETULT: CondCode = ARMCC::LT; break;
  case ISD::SETLE:
  case ISD::SETULE: CondCode = ARMCC::LE; break;
  case ISD::SETNE:
  case ISD::SETUNE: CondCode = ARMCC::NE; break;
  }
}

//===----------------------------------------------------------------------===//
//                      Calling Convention Implementation
//===----------------------------------------------------------------------===//

#include "ARMGenCallingConv.inc"

// APCS f64 is in register pairs, possibly split to stack
static bool f64AssignAPCS(unsigned &ValNo, EVT &ValVT, EVT &LocVT,
                          CCValAssign::LocInfo &LocInfo,
                          CCState &State, bool CanFail) {
  static const unsigned RegList[] = { ARM::R0, ARM::R1, ARM::R2, ARM::R3 };

  // Try to get the first register.
  if (unsigned Reg = State.AllocateReg(RegList, 4))
    State.addLoc(CCValAssign::getCustomReg(ValNo, ValVT, Reg, LocVT, LocInfo));
  else {
    // For the 2nd half of a v2f64, do not fail.
    if (CanFail)
      return false;

    // Put the whole thing on the stack.
    State.addLoc(CCValAssign::getCustomMem(ValNo, ValVT,
                                           State.AllocateStack(8, 4),
                                           LocVT, LocInfo));
    return true;
  }

  // Try to get the second register.
  if (unsigned Reg = State.AllocateReg(RegList, 4))
    State.addLoc(CCValAssign::getCustomReg(ValNo, ValVT, Reg, LocVT, LocInfo));
  else
    State.addLoc(CCValAssign::getCustomMem(ValNo, ValVT,
                                           State.AllocateStack(4, 4),
                                           LocVT, LocInfo));
  return true;
}

static bool CC_ARM_APCS_Custom_f64(unsigned &ValNo, EVT &ValVT, EVT &LocVT,
                                   CCValAssign::LocInfo &LocInfo,
                                   ISD::ArgFlagsTy &ArgFlags,
                                   CCState &State) {
  if (!f64AssignAPCS(ValNo, ValVT, LocVT, LocInfo, State, true))
    return false;
  if (LocVT == MVT::v2f64 &&
      !f64AssignAPCS(ValNo, ValVT, LocVT, LocInfo, State, false))
    return false;
  return true;  // we handled it
}

// AAPCS f64 is in aligned register pairs
static bool f64AssignAAPCS(unsigned &ValNo, EVT &ValVT, EVT &LocVT,
                           CCValAssign::LocInfo &LocInfo,
                           CCState &State, bool CanFail) {
  static const unsigned HiRegList[] = { ARM::R0, ARM::R2 };
  static const unsigned LoRegList[] = { ARM::R1, ARM::R3 };
  static const unsigned ShadowRegList[] = { ARM::R0, ARM::R1 };

  unsigned Reg = State.AllocateReg(HiRegList, ShadowRegList, 2);
  if (Reg == 0) {
    // For the 2nd half of a v2f64, do not just fail.
    if (CanFail)
      return false;

    // Put the whole thing on the stack.
    State.addLoc(CCValAssign::getCustomMem(ValNo, ValVT,
                                           State.AllocateStack(8, 8),
                                           LocVT, LocInfo));
    return true;
  }

  unsigned i;
  for (i = 0; i < 2; ++i)
    if (HiRegList[i] == Reg)
      break;

  unsigned T = State.AllocateReg(LoRegList[i]);
  (void)T;
  assert(T == LoRegList[i] && "Could not allocate register");

  State.addLoc(CCValAssign::getCustomReg(ValNo, ValVT, Reg, LocVT, LocInfo));
  State.addLoc(CCValAssign::getCustomReg(ValNo, ValVT, LoRegList[i],
                                         LocVT, LocInfo));
  return true;
}

static bool CC_ARM_AAPCS_Custom_f64(unsigned &ValNo, EVT &ValVT, EVT &LocVT,
                                    CCValAssign::LocInfo &LocInfo,
                                    ISD::ArgFlagsTy &ArgFlags,
                                    CCState &State) {
  if (!f64AssignAAPCS(ValNo, ValVT, LocVT, LocInfo, State, true))
    return false;
  if (LocVT == MVT::v2f64 &&
      !f64AssignAAPCS(ValNo, ValVT, LocVT, LocInfo, State, false))
    return false;
  return true;  // we handled it
}

static bool f64RetAssign(unsigned &ValNo, EVT &ValVT, EVT &LocVT,
                         CCValAssign::LocInfo &LocInfo, CCState &State) {
  static const unsigned HiRegList[] = { ARM::R0, ARM::R2 };
  static const unsigned LoRegList[] = { ARM::R1, ARM::R3 };

  unsigned Reg = State.AllocateReg(HiRegList, LoRegList, 2);
  if (Reg == 0)
    return false; // we didn't handle it

  unsigned i;
  for (i = 0; i < 2; ++i)
    if (HiRegList[i] == Reg)
      break;

  State.addLoc(CCValAssign::getCustomReg(ValNo, ValVT, Reg, LocVT, LocInfo));
  State.addLoc(CCValAssign::getCustomReg(ValNo, ValVT, LoRegList[i],
                                         LocVT, LocInfo));
  return true;
}

static bool RetCC_ARM_APCS_Custom_f64(unsigned &ValNo, EVT &ValVT, EVT &LocVT,
                                      CCValAssign::LocInfo &LocInfo,
                                      ISD::ArgFlagsTy &ArgFlags,
                                      CCState &State) {
  if (!f64RetAssign(ValNo, ValVT, LocVT, LocInfo, State))
    return false;
  if (LocVT == MVT::v2f64 && !f64RetAssign(ValNo, ValVT, LocVT, LocInfo, State))
    return false;
  return true;  // we handled it
}

static bool RetCC_ARM_AAPCS_Custom_f64(unsigned &ValNo, EVT &ValVT, EVT &LocVT,
                                       CCValAssign::LocInfo &LocInfo,
                                       ISD::ArgFlagsTy &ArgFlags,
                                       CCState &State) {
  return RetCC_ARM_APCS_Custom_f64(ValNo, ValVT, LocVT, LocInfo, ArgFlags,
                                   State);
}

/// CCAssignFnForNode - Selects the correct CCAssignFn for a the
/// given CallingConvention value.
CCAssignFn *ARMTargetLowering::CCAssignFnForNode(CallingConv::ID CC,
                                                 bool Return,
                                                 bool isVarArg) const {
  switch (CC) {
  default:
    llvm_unreachable("Unsupported calling convention");
  case CallingConv::C:
  case CallingConv::Fast:
    // Use target triple & subtarget features to do actual dispatch.
    if (Subtarget->isAAPCS_ABI()) {
      if (Subtarget->hasVFP2() &&
          FloatABIType == FloatABI::Hard && !isVarArg)
        return (Return ? RetCC_ARM_AAPCS_VFP: CC_ARM_AAPCS_VFP);
      else
        return (Return ? RetCC_ARM_AAPCS: CC_ARM_AAPCS);
    } else
        return (Return ? RetCC_ARM_APCS: CC_ARM_APCS);
  case CallingConv::ARM_AAPCS_VFP:
    return (Return ? RetCC_ARM_AAPCS_VFP: CC_ARM_AAPCS_VFP);
  case CallingConv::ARM_AAPCS:
    return (Return ? RetCC_ARM_AAPCS: CC_ARM_AAPCS);
  case CallingConv::ARM_APCS:
    return (Return ? RetCC_ARM_APCS: CC_ARM_APCS);
  }
}

/// LowerCallResult - Lower the result values of a call into the
/// appropriate copies out of appropriate physical registers.
SDValue
ARMTargetLowering::LowerCallResult(SDValue Chain, SDValue InFlag,
                                   CallingConv::ID CallConv, bool isVarArg,
                                   const SmallVectorImpl<ISD::InputArg> &Ins,
                                   DebugLoc dl, SelectionDAG &DAG,
                                   SmallVectorImpl<SDValue> &InVals) const {

  // Assign locations to each value returned by this call.
  SmallVector<CCValAssign, 16> RVLocs;
  CCState CCInfo(CallConv, isVarArg, getTargetMachine(),
                 RVLocs, *DAG.getContext());
  CCInfo.AnalyzeCallResult(Ins,
                           CCAssignFnForNode(CallConv, /* Return*/ true,
                                             isVarArg));

  // Copy all of the result registers out of their specified physreg.
  for (unsigned i = 0; i != RVLocs.size(); ++i) {
    CCValAssign VA = RVLocs[i];

    SDValue Val;
    if (VA.needsCustom()) {
      // Handle f64 or half of a v2f64.
      SDValue Lo = DAG.getCopyFromReg(Chain, dl, VA.getLocReg(), MVT::i32,
                                      InFlag);
      Chain = Lo.getValue(1);
      InFlag = Lo.getValue(2);
      VA = RVLocs[++i]; // skip ahead to next loc
      SDValue Hi = DAG.getCopyFromReg(Chain, dl, VA.getLocReg(), MVT::i32,
                                      InFlag);
      Chain = Hi.getValue(1);
      InFlag = Hi.getValue(2);
      Val = DAG.getNode(ARMISD::VMOVDRR, dl, MVT::f64, Lo, Hi);

      if (VA.getLocVT() == MVT::v2f64) {
        SDValue Vec = DAG.getNode(ISD::UNDEF, dl, MVT::v2f64);
        Vec = DAG.getNode(ISD::INSERT_VECTOR_ELT, dl, MVT::v2f64, Vec, Val,
                          DAG.getConstant(0, MVT::i32));

        VA = RVLocs[++i]; // skip ahead to next loc
        Lo = DAG.getCopyFromReg(Chain, dl, VA.getLocReg(), MVT::i32, InFlag);
        Chain = Lo.getValue(1);
        InFlag = Lo.getValue(2);
        VA = RVLocs[++i]; // skip ahead to next loc
        Hi = DAG.getCopyFromReg(Chain, dl, VA.getLocReg(), MVT::i32, InFlag);
        Chain = Hi.getValue(1);
        InFlag = Hi.getValue(2);
        Val = DAG.getNode(ARMISD::VMOVDRR, dl, MVT::f64, Lo, Hi);
        Val = DAG.getNode(ISD::INSERT_VECTOR_ELT, dl, MVT::v2f64, Vec, Val,
                          DAG.getConstant(1, MVT::i32));
      }
    } else {
      Val = DAG.getCopyFromReg(Chain, dl, VA.getLocReg(), VA.getLocVT(),
                               InFlag);
      Chain = Val.getValue(1);
      InFlag = Val.getValue(2);
    }

    switch (VA.getLocInfo()) {
    default: llvm_unreachable("Unknown loc info!");
    case CCValAssign::Full: break;
    case CCValAssign::BCvt:
      Val = DAG.getNode(ISD::BIT_CONVERT, dl, VA.getValVT(), Val);
      break;
    }

    InVals.push_back(Val);
  }

  return Chain;
}

/// CreateCopyOfByValArgument - Make a copy of an aggregate at address specified
/// by "Src" to address "Dst" of size "Size".  Alignment information is
/// specified by the specific parameter attribute.  The copy will be passed as
/// a byval function parameter.
/// Sometimes what we are copying is the end of a larger object, the part that
/// does not fit in registers.
static SDValue
CreateCopyOfByValArgument(SDValue Src, SDValue Dst, SDValue Chain,
                          ISD::ArgFlagsTy Flags, SelectionDAG &DAG,
                          DebugLoc dl) {
  SDValue SizeNode = DAG.getConstant(Flags.getByValSize(), MVT::i32);
  return DAG.getMemcpy(Chain, dl, Dst, Src, SizeNode, Flags.getByValAlign(),
                       /*isVolatile=*/false, /*AlwaysInline=*/false,
                       NULL, 0, NULL, 0);
}

/// LowerMemOpCallTo - Store the argument to the stack.
SDValue
ARMTargetLowering::LowerMemOpCallTo(SDValue Chain,
                                    SDValue StackPtr, SDValue Arg,
                                    DebugLoc dl, SelectionDAG &DAG,
                                    const CCValAssign &VA,
                                    ISD::ArgFlagsTy Flags) const {
  unsigned LocMemOffset = VA.getLocMemOffset();
  SDValue PtrOff = DAG.getIntPtrConstant(LocMemOffset);
  PtrOff = DAG.getNode(ISD::ADD, dl, getPointerTy(), StackPtr, PtrOff);
  if (Flags.isByVal()) {
    return CreateCopyOfByValArgument(Arg, PtrOff, Chain, Flags, DAG, dl);
  }
  return DAG.getStore(Chain, dl, Arg, PtrOff,
                      PseudoSourceValue::getStack(), LocMemOffset,
                      false, false, 0);
}

void ARMTargetLowering::PassF64ArgInRegs(DebugLoc dl, SelectionDAG &DAG,
                                         SDValue Chain, SDValue &Arg,
                                         RegsToPassVector &RegsToPass,
                                         CCValAssign &VA, CCValAssign &NextVA,
                                         SDValue &StackPtr,
                                         SmallVector<SDValue, 8> &MemOpChains,
                                         ISD::ArgFlagsTy Flags) const {

  SDValue fmrrd = DAG.getNode(ARMISD::VMOVRRD, dl,
                              DAG.getVTList(MVT::i32, MVT::i32), Arg);
  RegsToPass.push_back(std::make_pair(VA.getLocReg(), fmrrd));

  if (NextVA.isRegLoc())
    RegsToPass.push_back(std::make_pair(NextVA.getLocReg(), fmrrd.getValue(1)));
  else {
    assert(NextVA.isMemLoc());
    if (StackPtr.getNode() == 0)
      StackPtr = DAG.getCopyFromReg(Chain, dl, ARM::SP, getPointerTy());

    MemOpChains.push_back(LowerMemOpCallTo(Chain, StackPtr, fmrrd.getValue(1),
                                           dl, DAG, NextVA,
                                           Flags));
  }
}

/// LowerCall - Lowering a call into a callseq_start <-
/// ARMISD:CALL <- callseq_end chain. Also add input and output parameter
/// nodes.
SDValue
ARMTargetLowering::LowerCall(SDValue Chain, SDValue Callee,
                             CallingConv::ID CallConv, bool isVarArg,
                             bool &isTailCall,
                             const SmallVectorImpl<ISD::OutputArg> &Outs,
                             const SmallVectorImpl<SDValue> &OutVals,
                             const SmallVectorImpl<ISD::InputArg> &Ins,
                             DebugLoc dl, SelectionDAG &DAG,
                             SmallVectorImpl<SDValue> &InVals) const {
  MachineFunction &MF = DAG.getMachineFunction();
  bool IsStructRet    = (Outs.empty()) ? false : Outs[0].Flags.isSRet();
  bool IsSibCall = false;
  // Temporarily disable tail calls so things don't break.
  if (!EnableARMTailCalls)
    isTailCall = false;
  if (isTailCall) {
    // Check if it's really possible to do a tail call.
    isTailCall = IsEligibleForTailCallOptimization(Callee, CallConv,
                    isVarArg, IsStructRet, MF.getFunction()->hasStructRetAttr(),
                                                   Outs, OutVals, Ins, DAG);
    // We don't support GuaranteedTailCallOpt for ARM, only automatically
    // detected sibcalls.
    if (isTailCall) {
      ++NumTailCalls;
      IsSibCall = true;
    }
  }

  // Analyze operands of the call, assigning locations to each operand.
  SmallVector<CCValAssign, 16> ArgLocs;
  CCState CCInfo(CallConv, isVarArg, getTargetMachine(), ArgLocs,
                 *DAG.getContext());
  CCInfo.AnalyzeCallOperands(Outs,
                             CCAssignFnForNode(CallConv, /* Return*/ false,
                                               isVarArg));

  // Get a count of how many bytes are to be pushed on the stack.
  unsigned NumBytes = CCInfo.getNextStackOffset();

  // For tail calls, memory operands are available in our caller's stack.
  if (IsSibCall)
    NumBytes = 0;

  // Adjust the stack pointer for the new arguments...
  // These operations are automatically eliminated by the prolog/epilog pass
  if (!IsSibCall)
    Chain = DAG.getCALLSEQ_START(Chain, DAG.getIntPtrConstant(NumBytes, true));

  SDValue StackPtr = DAG.getCopyFromReg(Chain, dl, ARM::SP, getPointerTy());

  RegsToPassVector RegsToPass;
  SmallVector<SDValue, 8> MemOpChains;

  // Walk the register/memloc assignments, inserting copies/loads.  In the case
  // of tail call optimization, arguments are handled later.
  for (unsigned i = 0, realArgIdx = 0, e = ArgLocs.size();
       i != e;
       ++i, ++realArgIdx) {
    CCValAssign &VA = ArgLocs[i];
    SDValue Arg = OutVals[realArgIdx];
    ISD::ArgFlagsTy Flags = Outs[realArgIdx].Flags;

    // Promote the value if needed.
    switch (VA.getLocInfo()) {
    default: llvm_unreachable("Unknown loc info!");
    case CCValAssign::Full: break;
    case CCValAssign::SExt:
      Arg = DAG.getNode(ISD::SIGN_EXTEND, dl, VA.getLocVT(), Arg);
      break;
    case CCValAssign::ZExt:
      Arg = DAG.getNode(ISD::ZERO_EXTEND, dl, VA.getLocVT(), Arg);
      break;
    case CCValAssign::AExt:
      Arg = DAG.getNode(ISD::ANY_EXTEND, dl, VA.getLocVT(), Arg);
      break;
    case CCValAssign::BCvt:
      Arg = DAG.getNode(ISD::BIT_CONVERT, dl, VA.getLocVT(), Arg);
      break;
    }

    // f64 and v2f64 might be passed in i32 pairs and must be split into pieces
    if (VA.needsCustom()) {
      if (VA.getLocVT() == MVT::v2f64) {
        SDValue Op0 = DAG.getNode(ISD::EXTRACT_VECTOR_ELT, dl, MVT::f64, Arg,
                                  DAG.getConstant(0, MVT::i32));
        SDValue Op1 = DAG.getNode(ISD::EXTRACT_VECTOR_ELT, dl, MVT::f64, Arg,
                                  DAG.getConstant(1, MVT::i32));

        PassF64ArgInRegs(dl, DAG, Chain, Op0, RegsToPass,
                         VA, ArgLocs[++i], StackPtr, MemOpChains, Flags);

        VA = ArgLocs[++i]; // skip ahead to next loc
        if (VA.isRegLoc()) {
          PassF64ArgInRegs(dl, DAG, Chain, Op1, RegsToPass,
                           VA, ArgLocs[++i], StackPtr, MemOpChains, Flags);
        } else {
          assert(VA.isMemLoc());

          MemOpChains.push_back(LowerMemOpCallTo(Chain, StackPtr, Op1,
                                                 dl, DAG, VA, Flags));
        }
      } else {
        PassF64ArgInRegs(dl, DAG, Chain, Arg, RegsToPass, VA, ArgLocs[++i],
                         StackPtr, MemOpChains, Flags);
      }
    } else if (VA.isRegLoc()) {
      RegsToPass.push_back(std::make_pair(VA.getLocReg(), Arg));
    } else if (!IsSibCall) {
      assert(VA.isMemLoc());

      MemOpChains.push_back(LowerMemOpCallTo(Chain, StackPtr, Arg,
                                             dl, DAG, VA, Flags));
    }
  }

  if (!MemOpChains.empty())
    Chain = DAG.getNode(ISD::TokenFactor, dl, MVT::Other,
                        &MemOpChains[0], MemOpChains.size());

  // Build a sequence of copy-to-reg nodes chained together with token chain
  // and flag operands which copy the outgoing args into the appropriate regs.
  SDValue InFlag;
  // Tail call byval lowering might overwrite argument registers so in case of
  // tail call optimization the copies to registers are lowered later.
  if (!isTailCall)
    for (unsigned i = 0, e = RegsToPass.size(); i != e; ++i) {
      Chain = DAG.getCopyToReg(Chain, dl, RegsToPass[i].first,
                               RegsToPass[i].second, InFlag);
      InFlag = Chain.getValue(1);
    }

  // For tail calls lower the arguments to the 'real' stack slot.
  if (isTailCall) {
    // Force all the incoming stack arguments to be loaded from the stack
    // before any new outgoing arguments are stored to the stack, because the
    // outgoing stack slots may alias the incoming argument stack slots, and
    // the alias isn't otherwise explicit. This is slightly more conservative
    // than necessary, because it means that each store effectively depends
    // on every argument instead of just those arguments it would clobber.

    // Do not flag preceeding copytoreg stuff together with the following stuff.
    InFlag = SDValue();
    for (unsigned i = 0, e = RegsToPass.size(); i != e; ++i) {
      Chain = DAG.getCopyToReg(Chain, dl, RegsToPass[i].first,
                               RegsToPass[i].second, InFlag);
      InFlag = Chain.getValue(1);
    }
    InFlag =SDValue();
  }

  // If the callee is a GlobalAddress/ExternalSymbol node (quite common, every
  // direct call is) turn it into a TargetGlobalAddress/TargetExternalSymbol
  // node so that legalize doesn't hack it.
  bool isDirect = false;
  bool isARMFunc = false;
  bool isLocalARMFunc = false;
  ARMFunctionInfo *AFI = MF.getInfo<ARMFunctionInfo>();

  if (EnableARMLongCalls) {
    assert (getTargetMachine().getRelocationModel() == Reloc::Static
            && "long-calls with non-static relocation model!");
    // Handle a global address or an external symbol. If it's not one of
    // those, the target's already in a register, so we don't need to do
    // anything extra.
    if (GlobalAddressSDNode *G = dyn_cast<GlobalAddressSDNode>(Callee)) {
      const GlobalValue *GV = G->getGlobal();
      // Create a constant pool entry for the callee address
      unsigned ARMPCLabelIndex = AFI->createConstPoolEntryUId();
      ARMConstantPoolValue *CPV = new ARMConstantPoolValue(GV,
                                                           ARMPCLabelIndex,
                                                           ARMCP::CPValue, 0);
      // Get the address of the callee into a register
      SDValue CPAddr = DAG.getTargetConstantPool(CPV, getPointerTy(), 4);
      CPAddr = DAG.getNode(ARMISD::Wrapper, dl, MVT::i32, CPAddr);
      Callee = DAG.getLoad(getPointerTy(), dl,
                           DAG.getEntryNode(), CPAddr,
                           PseudoSourceValue::getConstantPool(), 0,
                           false, false, 0);
    } else if (ExternalSymbolSDNode *S=dyn_cast<ExternalSymbolSDNode>(Callee)) {
      const char *Sym = S->getSymbol();

      // Create a constant pool entry for the callee address
      unsigned ARMPCLabelIndex = AFI->createConstPoolEntryUId();
      ARMConstantPoolValue *CPV = new ARMConstantPoolValue(*DAG.getContext(),
                                                       Sym, ARMPCLabelIndex, 0);
      // Get the address of the callee into a register
      SDValue CPAddr = DAG.getTargetConstantPool(CPV, getPointerTy(), 4);
      CPAddr = DAG.getNode(ARMISD::Wrapper, dl, MVT::i32, CPAddr);
      Callee = DAG.getLoad(getPointerTy(), dl,
                           DAG.getEntryNode(), CPAddr,
                           PseudoSourceValue::getConstantPool(), 0,
                           false, false, 0);
    }
  } else if (GlobalAddressSDNode *G = dyn_cast<GlobalAddressSDNode>(Callee)) {
    const GlobalValue *GV = G->getGlobal();
    isDirect = true;
    bool isExt = GV->isDeclaration() || GV->isWeakForLinker();
    bool isStub = (isExt && Subtarget->isTargetDarwin()) &&
                   getTargetMachine().getRelocationModel() != Reloc::Static;
    isARMFunc = !Subtarget->isThumb() || isStub;
    // ARM call to a local ARM function is predicable.
    isLocalARMFunc = !Subtarget->isThumb() && (!isExt || !ARMInterworking);
    // tBX takes a register source operand.
    if (isARMFunc && Subtarget->isThumb1Only() && !Subtarget->hasV5TOps()) {
      unsigned ARMPCLabelIndex = AFI->createConstPoolEntryUId();
      ARMConstantPoolValue *CPV = new ARMConstantPoolValue(GV,
                                                           ARMPCLabelIndex,
                                                           ARMCP::CPValue, 4);
      SDValue CPAddr = DAG.getTargetConstantPool(CPV, getPointerTy(), 4);
      CPAddr = DAG.getNode(ARMISD::Wrapper, dl, MVT::i32, CPAddr);
      Callee = DAG.getLoad(getPointerTy(), dl,
                           DAG.getEntryNode(), CPAddr,
                           PseudoSourceValue::getConstantPool(), 0,
                           false, false, 0);
      SDValue PICLabel = DAG.getConstant(ARMPCLabelIndex, MVT::i32);
      Callee = DAG.getNode(ARMISD::PIC_ADD, dl,
                           getPointerTy(), Callee, PICLabel);
    } else
      Callee = DAG.getTargetGlobalAddress(GV, dl, getPointerTy());
  } else if (ExternalSymbolSDNode *S = dyn_cast<ExternalSymbolSDNode>(Callee)) {
    isDirect = true;
    bool isStub = Subtarget->isTargetDarwin() &&
                  getTargetMachine().getRelocationModel() != Reloc::Static;
    isARMFunc = !Subtarget->isThumb() || isStub;
    // tBX takes a register source operand.
    const char *Sym = S->getSymbol();
    if (isARMFunc && Subtarget->isThumb1Only() && !Subtarget->hasV5TOps()) {
      unsigned ARMPCLabelIndex = AFI->createConstPoolEntryUId();
      ARMConstantPoolValue *CPV = new ARMConstantPoolValue(*DAG.getContext(),
                                                       Sym, ARMPCLabelIndex, 4);
      SDValue CPAddr = DAG.getTargetConstantPool(CPV, getPointerTy(), 4);
      CPAddr = DAG.getNode(ARMISD::Wrapper, dl, MVT::i32, CPAddr);
      Callee = DAG.getLoad(getPointerTy(), dl,
                           DAG.getEntryNode(), CPAddr,
                           PseudoSourceValue::getConstantPool(), 0,
                           false, false, 0);
      SDValue PICLabel = DAG.getConstant(ARMPCLabelIndex, MVT::i32);
      Callee = DAG.getNode(ARMISD::PIC_ADD, dl,
                           getPointerTy(), Callee, PICLabel);
    } else
      Callee = DAG.getTargetExternalSymbol(Sym, getPointerTy());
  }

  // FIXME: handle tail calls differently.
  unsigned CallOpc;
  if (Subtarget->isThumb()) {
    if ((!isDirect || isARMFunc) && !Subtarget->hasV5TOps())
      CallOpc = ARMISD::CALL_NOLINK;
    else
      CallOpc = isARMFunc ? ARMISD::CALL : ARMISD::tCALL;
  } else {
    CallOpc = (isDirect || Subtarget->hasV5TOps())
      ? (isLocalARMFunc ? ARMISD::CALL_PRED : ARMISD::CALL)
      : ARMISD::CALL_NOLINK;
  }

  std::vector<SDValue> Ops;
  Ops.push_back(Chain);
  Ops.push_back(Callee);

  // Add argument registers to the end of the list so that they are known live
  // into the call.
  for (unsigned i = 0, e = RegsToPass.size(); i != e; ++i)
    Ops.push_back(DAG.getRegister(RegsToPass[i].first,
                                  RegsToPass[i].second.getValueType()));

  if (InFlag.getNode())
    Ops.push_back(InFlag);

  SDVTList NodeTys = DAG.getVTList(MVT::Other, MVT::Flag);
  if (isTailCall)
    return DAG.getNode(ARMISD::TC_RETURN, dl, NodeTys, &Ops[0], Ops.size());

  // Returns a chain and a flag for retval copy to use.
  Chain = DAG.getNode(CallOpc, dl, NodeTys, &Ops[0], Ops.size());
  InFlag = Chain.getValue(1);

  Chain = DAG.getCALLSEQ_END(Chain, DAG.getIntPtrConstant(NumBytes, true),
                             DAG.getIntPtrConstant(0, true), InFlag);
  if (!Ins.empty())
    InFlag = Chain.getValue(1);

  // Handle result values, copying them out of physregs into vregs that we
  // return.
  return LowerCallResult(Chain, InFlag, CallConv, isVarArg, Ins,
                         dl, DAG, InVals);
}

/// MatchingStackOffset - Return true if the given stack call argument is
/// already available in the same position (relatively) of the caller's
/// incoming argument stack.
static
bool MatchingStackOffset(SDValue Arg, unsigned Offset, ISD::ArgFlagsTy Flags,
                         MachineFrameInfo *MFI, const MachineRegisterInfo *MRI,
                         const ARMInstrInfo *TII) {
  unsigned Bytes = Arg.getValueType().getSizeInBits() / 8;
  int FI = INT_MAX;
  if (Arg.getOpcode() == ISD::CopyFromReg) {
    unsigned VR = cast<RegisterSDNode>(Arg.getOperand(1))->getReg();
    if (!VR || TargetRegisterInfo::isPhysicalRegister(VR))
      return false;
    MachineInstr *Def = MRI->getVRegDef(VR);
    if (!Def)
      return false;
    if (!Flags.isByVal()) {
      if (!TII->isLoadFromStackSlot(Def, FI))
        return false;
    } else {
      return false;
    }
  } else if (LoadSDNode *Ld = dyn_cast<LoadSDNode>(Arg)) {
    if (Flags.isByVal())
      // ByVal argument is passed in as a pointer but it's now being
      // dereferenced. e.g.
      // define @foo(%struct.X* %A) {
      //   tail call @bar(%struct.X* byval %A)
      // }
      return false;
    SDValue Ptr = Ld->getBasePtr();
    FrameIndexSDNode *FINode = dyn_cast<FrameIndexSDNode>(Ptr);
    if (!FINode)
      return false;
    FI = FINode->getIndex();
  } else
    return false;

  assert(FI != INT_MAX);
  if (!MFI->isFixedObjectIndex(FI))
    return false;
  return Offset == MFI->getObjectOffset(FI) && Bytes == MFI->getObjectSize(FI);
}

/// IsEligibleForTailCallOptimization - Check whether the call is eligible
/// for tail call optimization. Targets which want to do tail call
/// optimization should implement this function.
bool
ARMTargetLowering::IsEligibleForTailCallOptimization(SDValue Callee,
                                                     CallingConv::ID CalleeCC,
                                                     bool isVarArg,
                                                     bool isCalleeStructRet,
                                                     bool isCallerStructRet,
                                    const SmallVectorImpl<ISD::OutputArg> &Outs,
                                    const SmallVectorImpl<SDValue> &OutVals,
                                    const SmallVectorImpl<ISD::InputArg> &Ins,
                                                     SelectionDAG& DAG) const {
  const Function *CallerF = DAG.getMachineFunction().getFunction();
  CallingConv::ID CallerCC = CallerF->getCallingConv();
  bool CCMatch = CallerCC == CalleeCC;

  // Look for obvious safe cases to perform tail call optimization that do not
  // require ABI changes. This is what gcc calls sibcall.

  // Do not sibcall optimize vararg calls unless the call site is not passing
  // any arguments.
  if (isVarArg && !Outs.empty())
    return false;

  // Also avoid sibcall optimization if either caller or callee uses struct
  // return semantics.
  if (isCalleeStructRet || isCallerStructRet)
    return false;

  // FIXME: Completely disable sibcall for Thumb1 since Thumb1RegisterInfo::
  // emitEpilogue is not ready for them.
  // Doing this is tricky, since the LDM/POP instruction on Thumb doesn't take
  // LR.  This means if we need to reload LR, it takes an extra instructions,
  // which outweighs the value of the tail call; but here we don't know yet
  // whether LR is going to be used.  Probably the right approach is to
  // generate the tail call here and turn it back into CALL/RET in 
  // emitEpilogue if LR is used.
  if (Subtarget->isThumb1Only())
    return false;

  // For the moment, we can only do this to functions defined in this
  // compilation, or to indirect calls.  A Thumb B to an ARM function,
  // or vice versa, is not easily fixed up in the linker unlike BL.
  // (We could do this by loading the address of the callee into a register;
  // that is an extra instruction over the direct call and burns a register
  // as well, so is not likely to be a win.)

  // It might be safe to remove this restriction on non-Darwin.

  // Thumb1 PIC calls to external symbols use BX, so they can be tail calls,
  // but we need to make sure there are enough registers; the only valid
  // registers are the 4 used for parameters.  We don't currently do this
  // case.
  if (isa<ExternalSymbolSDNode>(Callee))
      return false;

  if (GlobalAddressSDNode *G = dyn_cast<GlobalAddressSDNode>(Callee)) {
    const GlobalValue *GV = G->getGlobal();
    if (GV->isDeclaration() || GV->isWeakForLinker())
      return false;
  }

  // If the calling conventions do not match, then we'd better make sure the
  // results are returned in the same way as what the caller expects.
  if (!CCMatch) {
    SmallVector<CCValAssign, 16> RVLocs1;
    CCState CCInfo1(CalleeCC, false, getTargetMachine(),
                    RVLocs1, *DAG.getContext());
    CCInfo1.AnalyzeCallResult(Ins, CCAssignFnForNode(CalleeCC, true, isVarArg));

    SmallVector<CCValAssign, 16> RVLocs2;
    CCState CCInfo2(CallerCC, false, getTargetMachine(),
                    RVLocs2, *DAG.getContext());
    CCInfo2.AnalyzeCallResult(Ins, CCAssignFnForNode(CallerCC, true, isVarArg));

    if (RVLocs1.size() != RVLocs2.size())
      return false;
    for (unsigned i = 0, e = RVLocs1.size(); i != e; ++i) {
      if (RVLocs1[i].isRegLoc() != RVLocs2[i].isRegLoc())
        return false;
      if (RVLocs1[i].getLocInfo() != RVLocs2[i].getLocInfo())
        return false;
      if (RVLocs1[i].isRegLoc()) {
        if (RVLocs1[i].getLocReg() != RVLocs2[i].getLocReg())
          return false;
      } else {
        if (RVLocs1[i].getLocMemOffset() != RVLocs2[i].getLocMemOffset())
          return false;
      }
    }
  }

  // If the callee takes no arguments then go on to check the results of the
  // call.
  if (!Outs.empty()) {
    // Check if stack adjustment is needed. For now, do not do this if any
    // argument is passed on the stack.
    SmallVector<CCValAssign, 16> ArgLocs;
    CCState CCInfo(CalleeCC, isVarArg, getTargetMachine(),
                   ArgLocs, *DAG.getContext());
    CCInfo.AnalyzeCallOperands(Outs,
                               CCAssignFnForNode(CalleeCC, false, isVarArg));
    if (CCInfo.getNextStackOffset()) {
      MachineFunction &MF = DAG.getMachineFunction();

      // Check if the arguments are already laid out in the right way as
      // the caller's fixed stack objects.
      MachineFrameInfo *MFI = MF.getFrameInfo();
      const MachineRegisterInfo *MRI = &MF.getRegInfo();
      const ARMInstrInfo *TII =
        ((ARMTargetMachine&)getTargetMachine()).getInstrInfo();
      for (unsigned i = 0, realArgIdx = 0, e = ArgLocs.size();
           i != e;
           ++i, ++realArgIdx) {
        CCValAssign &VA = ArgLocs[i];
        EVT RegVT = VA.getLocVT();
        SDValue Arg = OutVals[realArgIdx];
        ISD::ArgFlagsTy Flags = Outs[realArgIdx].Flags;
        if (VA.getLocInfo() == CCValAssign::Indirect)
          return false;
        if (VA.needsCustom()) {
          // f64 and vector types are split into multiple registers or
          // register/stack-slot combinations.  The types will not match
          // the registers; give up on memory f64 refs until we figure
          // out what to do about this.
          if (!VA.isRegLoc())
            return false;
          if (!ArgLocs[++i].isRegLoc())
            return false; 
          if (RegVT == MVT::v2f64) {
            if (!ArgLocs[++i].isRegLoc())
              return false;
            if (!ArgLocs[++i].isRegLoc())
              return false;
          }
        } else if (!VA.isRegLoc()) {
          if (!MatchingStackOffset(Arg, VA.getLocMemOffset(), Flags,
                                   MFI, MRI, TII))
            return false;
        }
      }
    }
  }

  return true;
}

SDValue
ARMTargetLowering::LowerReturn(SDValue Chain,
                               CallingConv::ID CallConv, bool isVarArg,
                               const SmallVectorImpl<ISD::OutputArg> &Outs,
                               const SmallVectorImpl<SDValue> &OutVals,
                               DebugLoc dl, SelectionDAG &DAG) const {

  // CCValAssign - represent the assignment of the return value to a location.
  SmallVector<CCValAssign, 16> RVLocs;

  // CCState - Info about the registers and stack slots.
  CCState CCInfo(CallConv, isVarArg, getTargetMachine(), RVLocs,
                 *DAG.getContext());

  // Analyze outgoing return values.
  CCInfo.AnalyzeReturn(Outs, CCAssignFnForNode(CallConv, /* Return */ true,
                                               isVarArg));

  // If this is the first return lowered for this function, add
  // the regs to the liveout set for the function.
  if (DAG.getMachineFunction().getRegInfo().liveout_empty()) {
    for (unsigned i = 0; i != RVLocs.size(); ++i)
      if (RVLocs[i].isRegLoc())
        DAG.getMachineFunction().getRegInfo().addLiveOut(RVLocs[i].getLocReg());
  }

  SDValue Flag;

  // Copy the result values into the output registers.
  for (unsigned i = 0, realRVLocIdx = 0;
       i != RVLocs.size();
       ++i, ++realRVLocIdx) {
    CCValAssign &VA = RVLocs[i];
    assert(VA.isRegLoc() && "Can only return in registers!");

    SDValue Arg = OutVals[realRVLocIdx];

    switch (VA.getLocInfo()) {
    default: llvm_unreachable("Unknown loc info!");
    case CCValAssign::Full: break;
    case CCValAssign::BCvt:
      Arg = DAG.getNode(ISD::BIT_CONVERT, dl, VA.getLocVT(), Arg);
      break;
    }

    if (VA.needsCustom()) {
      if (VA.getLocVT() == MVT::v2f64) {
        // Extract the first half and return it in two registers.
        SDValue Half = DAG.getNode(ISD::EXTRACT_VECTOR_ELT, dl, MVT::f64, Arg,
                                   DAG.getConstant(0, MVT::i32));
        SDValue HalfGPRs = DAG.getNode(ARMISD::VMOVRRD, dl,
                                       DAG.getVTList(MVT::i32, MVT::i32), Half);

        Chain = DAG.getCopyToReg(Chain, dl, VA.getLocReg(), HalfGPRs, Flag);
        Flag = Chain.getValue(1);
        VA = RVLocs[++i]; // skip ahead to next loc
        Chain = DAG.getCopyToReg(Chain, dl, VA.getLocReg(),
                                 HalfGPRs.getValue(1), Flag);
        Flag = Chain.getValue(1);
        VA = RVLocs[++i]; // skip ahead to next loc

        // Extract the 2nd half and fall through to handle it as an f64 value.
        Arg = DAG.getNode(ISD::EXTRACT_VECTOR_ELT, dl, MVT::f64, Arg,
                          DAG.getConstant(1, MVT::i32));
      }
      // Legalize ret f64 -> ret 2 x i32.  We always have fmrrd if f64 is
      // available.
      SDValue fmrrd = DAG.getNode(ARMISD::VMOVRRD, dl,
                                  DAG.getVTList(MVT::i32, MVT::i32), &Arg, 1);
      Chain = DAG.getCopyToReg(Chain, dl, VA.getLocReg(), fmrrd, Flag);
      Flag = Chain.getValue(1);
      VA = RVLocs[++i]; // skip ahead to next loc
      Chain = DAG.getCopyToReg(Chain, dl, VA.getLocReg(), fmrrd.getValue(1),
                               Flag);
    } else
      Chain = DAG.getCopyToReg(Chain, dl, VA.getLocReg(), Arg, Flag);

    // Guarantee that all emitted copies are
    // stuck together, avoiding something bad.
    Flag = Chain.getValue(1);
  }

  SDValue result;
  if (Flag.getNode())
    result = DAG.getNode(ARMISD::RET_FLAG, dl, MVT::Other, Chain, Flag);
  else // Return Void
    result = DAG.getNode(ARMISD::RET_FLAG, dl, MVT::Other, Chain);

  return result;
}

// ConstantPool, JumpTable, GlobalAddress, and ExternalSymbol are lowered as
// their target counterpart wrapped in the ARMISD::Wrapper node. Suppose N is
// one of the above mentioned nodes. It has to be wrapped because otherwise
// Select(N) returns N. So the raw TargetGlobalAddress nodes, etc. can only
// be used to form addressing mode. These wrapped nodes will be selected
// into MOVi.
static SDValue LowerConstantPool(SDValue Op, SelectionDAG &DAG) {
  EVT PtrVT = Op.getValueType();
  // FIXME there is no actual debug info here
  DebugLoc dl = Op.getDebugLoc();
  ConstantPoolSDNode *CP = cast<ConstantPoolSDNode>(Op);
  SDValue Res;
  if (CP->isMachineConstantPoolEntry())
    Res = DAG.getTargetConstantPool(CP->getMachineCPVal(), PtrVT,
                                    CP->getAlignment());
  else
    Res = DAG.getTargetConstantPool(CP->getConstVal(), PtrVT,
                                    CP->getAlignment());
  return DAG.getNode(ARMISD::Wrapper, dl, MVT::i32, Res);
}

unsigned ARMTargetLowering::getJumpTableEncoding() const {
  return MachineJumpTableInfo::EK_Inline;
}

SDValue ARMTargetLowering::LowerBlockAddress(SDValue Op,
                                             SelectionDAG &DAG) const {
  MachineFunction &MF = DAG.getMachineFunction();
  ARMFunctionInfo *AFI = MF.getInfo<ARMFunctionInfo>();
  unsigned ARMPCLabelIndex = 0;
  DebugLoc DL = Op.getDebugLoc();
  EVT PtrVT = getPointerTy();
  const BlockAddress *BA = cast<BlockAddressSDNode>(Op)->getBlockAddress();
  Reloc::Model RelocM = getTargetMachine().getRelocationModel();
  SDValue CPAddr;
  if (RelocM == Reloc::Static) {
    CPAddr = DAG.getTargetConstantPool(BA, PtrVT, 4);
  } else {
    unsigned PCAdj = Subtarget->isThumb() ? 4 : 8;
    ARMPCLabelIndex = AFI->createConstPoolEntryUId();
    ARMConstantPoolValue *CPV = new ARMConstantPoolValue(BA, ARMPCLabelIndex,
                                                         ARMCP::CPBlockAddress,
                                                         PCAdj);
    CPAddr = DAG.getTargetConstantPool(CPV, PtrVT, 4);
  }
  CPAddr = DAG.getNode(ARMISD::Wrapper, DL, PtrVT, CPAddr);
  SDValue Result = DAG.getLoad(PtrVT, DL, DAG.getEntryNode(), CPAddr,
                               PseudoSourceValue::getConstantPool(), 0,
                               false, false, 0);
  if (RelocM == Reloc::Static)
    return Result;
  SDValue PICLabel = DAG.getConstant(ARMPCLabelIndex, MVT::i32);
  return DAG.getNode(ARMISD::PIC_ADD, DL, PtrVT, Result, PICLabel);
}

// Lower ISD::GlobalTLSAddress using the "general dynamic" model
SDValue
ARMTargetLowering::LowerToTLSGeneralDynamicModel(GlobalAddressSDNode *GA,
                                                 SelectionDAG &DAG) const {
  DebugLoc dl = GA->getDebugLoc();
  EVT PtrVT = getPointerTy();
  unsigned char PCAdj = Subtarget->isThumb() ? 4 : 8;
  MachineFunction &MF = DAG.getMachineFunction();
  ARMFunctionInfo *AFI = MF.getInfo<ARMFunctionInfo>();
  unsigned ARMPCLabelIndex = AFI->createConstPoolEntryUId();
  ARMConstantPoolValue *CPV =
    new ARMConstantPoolValue(GA->getGlobal(), ARMPCLabelIndex,
                             ARMCP::CPValue, PCAdj, "tlsgd", true);
  SDValue Argument = DAG.getTargetConstantPool(CPV, PtrVT, 4);
  Argument = DAG.getNode(ARMISD::Wrapper, dl, MVT::i32, Argument);
  Argument = DAG.getLoad(PtrVT, dl, DAG.getEntryNode(), Argument,
                         PseudoSourceValue::getConstantPool(), 0,
                         false, false, 0);
  SDValue Chain = Argument.getValue(1);

  SDValue PICLabel = DAG.getConstant(ARMPCLabelIndex, MVT::i32);
  Argument = DAG.getNode(ARMISD::PIC_ADD, dl, PtrVT, Argument, PICLabel);

  // call __tls_get_addr.
  ArgListTy Args;
  ArgListEntry Entry;
  Entry.Node = Argument;
  Entry.Ty = (const Type *) Type::getInt32Ty(*DAG.getContext());
  Args.push_back(Entry);
  // FIXME: is there useful debug info available here?
  std::pair<SDValue, SDValue> CallResult =
    LowerCallTo(Chain, (const Type *) Type::getInt32Ty(*DAG.getContext()),
                false, false, false, false,
                0, CallingConv::C, false, /*isReturnValueUsed=*/true,
                DAG.getExternalSymbol("__tls_get_addr", PtrVT), Args, DAG, dl);
  return CallResult.first;
}

// Lower ISD::GlobalTLSAddress using the "initial exec" or
// "local exec" model.
SDValue
ARMTargetLowering::LowerToTLSExecModels(GlobalAddressSDNode *GA,
                                        SelectionDAG &DAG) const {
  const GlobalValue *GV = GA->getGlobal();
  DebugLoc dl = GA->getDebugLoc();
  SDValue Offset;
  SDValue Chain = DAG.getEntryNode();
  EVT PtrVT = getPointerTy();
  // Get the Thread Pointer
  SDValue ThreadPointer = DAG.getNode(ARMISD::THREAD_POINTER, dl, PtrVT);

  if (GV->isDeclaration()) {
    MachineFunction &MF = DAG.getMachineFunction();
    ARMFunctionInfo *AFI = MF.getInfo<ARMFunctionInfo>();
    unsigned ARMPCLabelIndex = AFI->createConstPoolEntryUId();
    // Initial exec model.
    unsigned char PCAdj = Subtarget->isThumb() ? 4 : 8;
    ARMConstantPoolValue *CPV =
      new ARMConstantPoolValue(GA->getGlobal(), ARMPCLabelIndex,
                               ARMCP::CPValue, PCAdj, "gottpoff", true);
    Offset = DAG.getTargetConstantPool(CPV, PtrVT, 4);
    Offset = DAG.getNode(ARMISD::Wrapper, dl, MVT::i32, Offset);
    Offset = DAG.getLoad(PtrVT, dl, Chain, Offset,
                         PseudoSourceValue::getConstantPool(), 0,
                         false, false, 0);
    Chain = Offset.getValue(1);

    SDValue PICLabel = DAG.getConstant(ARMPCLabelIndex, MVT::i32);
    Offset = DAG.getNode(ARMISD::PIC_ADD, dl, PtrVT, Offset, PICLabel);

    Offset = DAG.getLoad(PtrVT, dl, Chain, Offset,
                         PseudoSourceValue::getConstantPool(), 0,
                         false, false, 0);
  } else {
    // local exec model
    ARMConstantPoolValue *CPV = new ARMConstantPoolValue(GV, "tpoff");
    Offset = DAG.getTargetConstantPool(CPV, PtrVT, 4);
    Offset = DAG.getNode(ARMISD::Wrapper, dl, MVT::i32, Offset);
    Offset = DAG.getLoad(PtrVT, dl, Chain, Offset,
                         PseudoSourceValue::getConstantPool(), 0,
                         false, false, 0);
  }

  // The address of the thread local variable is the add of the thread
  // pointer with the offset of the variable.
  return DAG.getNode(ISD::ADD, dl, PtrVT, ThreadPointer, Offset);
}

SDValue
ARMTargetLowering::LowerGlobalTLSAddress(SDValue Op, SelectionDAG &DAG) const {
  // TODO: implement the "local dynamic" model
  assert(Subtarget->isTargetELF() &&
         "TLS not implemented for non-ELF targets");
  GlobalAddressSDNode *GA = cast<GlobalAddressSDNode>(Op);
  // If the relocation model is PIC, use the "General Dynamic" TLS Model,
  // otherwise use the "Local Exec" TLS Model
  if (getTargetMachine().getRelocationModel() == Reloc::PIC_)
    return LowerToTLSGeneralDynamicModel(GA, DAG);
  else
    return LowerToTLSExecModels(GA, DAG);
}

SDValue ARMTargetLowering::LowerGlobalAddressELF(SDValue Op,
                                                 SelectionDAG &DAG) const {
  EVT PtrVT = getPointerTy();
  DebugLoc dl = Op.getDebugLoc();
  const GlobalValue *GV = cast<GlobalAddressSDNode>(Op)->getGlobal();
  Reloc::Model RelocM = getTargetMachine().getRelocationModel();
  if (RelocM == Reloc::PIC_) {
    bool UseGOTOFF = GV->hasLocalLinkage() || GV->hasHiddenVisibility();
    ARMConstantPoolValue *CPV =
      new ARMConstantPoolValue(GV, UseGOTOFF ? "GOTOFF" : "GOT");
    SDValue CPAddr = DAG.getTargetConstantPool(CPV, PtrVT, 4);
    CPAddr = DAG.getNode(ARMISD::Wrapper, dl, MVT::i32, CPAddr);
    SDValue Result = DAG.getLoad(PtrVT, dl, DAG.getEntryNode(),
                                 CPAddr,
                                 PseudoSourceValue::getConstantPool(), 0,
                                 false, false, 0);
    SDValue Chain = Result.getValue(1);
    SDValue GOT = DAG.getGLOBAL_OFFSET_TABLE(PtrVT);
    Result = DAG.getNode(ISD::ADD, dl, PtrVT, Result, GOT);
    if (!UseGOTOFF)
      Result = DAG.getLoad(PtrVT, dl, Chain, Result,
                           PseudoSourceValue::getGOT(), 0,
                           false, false, 0);
    return Result;
  } else {
    // If we have T2 ops, we can materialize the address directly via movt/movw
    // pair. This is always cheaper.
    if (Subtarget->useMovt()) {
      return DAG.getNode(ARMISD::Wrapper, dl, PtrVT,
                         DAG.getTargetGlobalAddress(GV, dl, PtrVT));
    } else {
      SDValue CPAddr = DAG.getTargetConstantPool(GV, PtrVT, 4);
      CPAddr = DAG.getNode(ARMISD::Wrapper, dl, MVT::i32, CPAddr);
      return DAG.getLoad(PtrVT, dl, DAG.getEntryNode(), CPAddr,
                         PseudoSourceValue::getConstantPool(), 0,
                         false, false, 0);
    }
  }
}

SDValue ARMTargetLowering::LowerGlobalAddressDarwin(SDValue Op,
                                                    SelectionDAG &DAG) const {
  MachineFunction &MF = DAG.getMachineFunction();
  ARMFunctionInfo *AFI = MF.getInfo<ARMFunctionInfo>();
  unsigned ARMPCLabelIndex = 0;
  EVT PtrVT = getPointerTy();
  DebugLoc dl = Op.getDebugLoc();
  const GlobalValue *GV = cast<GlobalAddressSDNode>(Op)->getGlobal();
  Reloc::Model RelocM = getTargetMachine().getRelocationModel();
  SDValue CPAddr;
  if (RelocM == Reloc::Static)
    CPAddr = DAG.getTargetConstantPool(GV, PtrVT, 4);
  else {
    ARMPCLabelIndex = AFI->createConstPoolEntryUId();
    unsigned PCAdj = (RelocM != Reloc::PIC_) ? 0 : (Subtarget->isThumb()?4:8);
    ARMConstantPoolValue *CPV =
      new ARMConstantPoolValue(GV, ARMPCLabelIndex, ARMCP::CPValue, PCAdj);
    CPAddr = DAG.getTargetConstantPool(CPV, PtrVT, 4);
  }
  CPAddr = DAG.getNode(ARMISD::Wrapper, dl, MVT::i32, CPAddr);

  SDValue Result = DAG.getLoad(PtrVT, dl, DAG.getEntryNode(), CPAddr,
                               PseudoSourceValue::getConstantPool(), 0,
                               false, false, 0);
  SDValue Chain = Result.getValue(1);

  if (RelocM == Reloc::PIC_) {
    SDValue PICLabel = DAG.getConstant(ARMPCLabelIndex, MVT::i32);
    Result = DAG.getNode(ARMISD::PIC_ADD, dl, PtrVT, Result, PICLabel);
  }

  if (Subtarget->GVIsIndirectSymbol(GV, RelocM))
    Result = DAG.getLoad(PtrVT, dl, Chain, Result,
                         PseudoSourceValue::getGOT(), 0,
                         false, false, 0);

  return Result;
}

SDValue ARMTargetLowering::LowerGLOBAL_OFFSET_TABLE(SDValue Op,
                                                    SelectionDAG &DAG) const {
  assert(Subtarget->isTargetELF() &&
         "GLOBAL OFFSET TABLE not implemented for non-ELF targets");
  MachineFunction &MF = DAG.getMachineFunction();
  ARMFunctionInfo *AFI = MF.getInfo<ARMFunctionInfo>();
  unsigned ARMPCLabelIndex = AFI->createConstPoolEntryUId();
  EVT PtrVT = getPointerTy();
  DebugLoc dl = Op.getDebugLoc();
  unsigned PCAdj = Subtarget->isThumb() ? 4 : 8;
  ARMConstantPoolValue *CPV = new ARMConstantPoolValue(*DAG.getContext(),
                                                       "_GLOBAL_OFFSET_TABLE_",
                                                       ARMPCLabelIndex, PCAdj);
  SDValue CPAddr = DAG.getTargetConstantPool(CPV, PtrVT, 4);
  CPAddr = DAG.getNode(ARMISD::Wrapper, dl, MVT::i32, CPAddr);
  SDValue Result = DAG.getLoad(PtrVT, dl, DAG.getEntryNode(), CPAddr,
                               PseudoSourceValue::getConstantPool(), 0,
                               false, false, 0);
  SDValue PICLabel = DAG.getConstant(ARMPCLabelIndex, MVT::i32);
  return DAG.getNode(ARMISD::PIC_ADD, dl, PtrVT, Result, PICLabel);
}

SDValue
ARMTargetLowering::LowerEH_SJLJ_SETJMP(SDValue Op, SelectionDAG &DAG) const {
  DebugLoc dl = Op.getDebugLoc();
  SDValue Val = DAG.getConstant(0, MVT::i32);
  return DAG.getNode(ARMISD::EH_SJLJ_SETJMP, dl, MVT::i32, Op.getOperand(0),
                     Op.getOperand(1), Val);
}

SDValue
ARMTargetLowering::LowerEH_SJLJ_LONGJMP(SDValue Op, SelectionDAG &DAG) const {
  DebugLoc dl = Op.getDebugLoc();
  return DAG.getNode(ARMISD::EH_SJLJ_LONGJMP, dl, MVT::Other, Op.getOperand(0),
                     Op.getOperand(1), DAG.getConstant(0, MVT::i32));
}

SDValue
ARMTargetLowering::LowerINTRINSIC_WO_CHAIN(SDValue Op, SelectionDAG &DAG,
                                          const ARMSubtarget *Subtarget) const {
  unsigned IntNo = cast<ConstantSDNode>(Op.getOperand(0))->getZExtValue();
  DebugLoc dl = Op.getDebugLoc();
  switch (IntNo) {
  default: return SDValue();    // Don't custom lower most intrinsics.
  case Intrinsic::arm_thread_pointer: {
    EVT PtrVT = DAG.getTargetLoweringInfo().getPointerTy();
    return DAG.getNode(ARMISD::THREAD_POINTER, dl, PtrVT);
  }
  case Intrinsic::eh_sjlj_lsda: {
    MachineFunction &MF = DAG.getMachineFunction();
    ARMFunctionInfo *AFI = MF.getInfo<ARMFunctionInfo>();
    unsigned ARMPCLabelIndex = AFI->createConstPoolEntryUId();
    EVT PtrVT = getPointerTy();
    DebugLoc dl = Op.getDebugLoc();
    Reloc::Model RelocM = getTargetMachine().getRelocationModel();
    SDValue CPAddr;
    unsigned PCAdj = (RelocM != Reloc::PIC_)
      ? 0 : (Subtarget->isThumb() ? 4 : 8);
    ARMConstantPoolValue *CPV =
      new ARMConstantPoolValue(MF.getFunction(), ARMPCLabelIndex,
                               ARMCP::CPLSDA, PCAdj);
    CPAddr = DAG.getTargetConstantPool(CPV, PtrVT, 4);
    CPAddr = DAG.getNode(ARMISD::Wrapper, dl, MVT::i32, CPAddr);
    SDValue Result =
      DAG.getLoad(PtrVT, dl, DAG.getEntryNode(), CPAddr,
                  PseudoSourceValue::getConstantPool(), 0,
                  false, false, 0);

    if (RelocM == Reloc::PIC_) {
      SDValue PICLabel = DAG.getConstant(ARMPCLabelIndex, MVT::i32);
      Result = DAG.getNode(ARMISD::PIC_ADD, dl, PtrVT, Result, PICLabel);
    }
    return Result;
  }
  }
}

static SDValue LowerMEMBARRIER(SDValue Op, SelectionDAG &DAG,
                               const ARMSubtarget *Subtarget) {
  DebugLoc dl = Op.getDebugLoc();
  SDValue Op5 = Op.getOperand(5);
  unsigned isDeviceBarrier = cast<ConstantSDNode>(Op5)->getZExtValue();
  // Some subtargets which have dmb and dsb instructions can handle barriers
  // directly. Some ARMv6 cpus can support them with the help of mcr
  // instruction. Thumb1 and pre-v6 ARM mode use a libcall instead and should
  // never get here.
  unsigned Opc = isDeviceBarrier ? ARMISD::SYNCBARRIER : ARMISD::MEMBARRIER;
  if (Subtarget->hasDataBarrier())
    return DAG.getNode(Opc, dl, MVT::Other, Op.getOperand(0));
  else {
    assert(Subtarget->hasV6Ops() && !Subtarget->isThumb1Only() &&
           "Unexpected ISD::MEMBARRIER encountered. Should be libcall!");
    return DAG.getNode(Opc, dl, MVT::Other, Op.getOperand(0),
                       DAG.getConstant(0, MVT::i32));
  }
}

static SDValue LowerVASTART(SDValue Op, SelectionDAG &DAG) {
  MachineFunction &MF = DAG.getMachineFunction();
  ARMFunctionInfo *FuncInfo = MF.getInfo<ARMFunctionInfo>();

  // vastart just stores the address of the VarArgsFrameIndex slot into the
  // memory location argument.
  DebugLoc dl = Op.getDebugLoc();
  EVT PtrVT = DAG.getTargetLoweringInfo().getPointerTy();
  SDValue FR = DAG.getFrameIndex(FuncInfo->getVarArgsFrameIndex(), PtrVT);
  const Value *SV = cast<SrcValueSDNode>(Op.getOperand(2))->getValue();
  return DAG.getStore(Op.getOperand(0), dl, FR, Op.getOperand(1), SV, 0,
                      false, false, 0);
}

SDValue
ARMTargetLowering::GetF64FormalArgument(CCValAssign &VA, CCValAssign &NextVA,
                                        SDValue &Root, SelectionDAG &DAG,
                                        DebugLoc dl) const {
  MachineFunction &MF = DAG.getMachineFunction();
  ARMFunctionInfo *AFI = MF.getInfo<ARMFunctionInfo>();

  TargetRegisterClass *RC;
  if (AFI->isThumb1OnlyFunction())
    RC = ARM::tGPRRegisterClass;
  else
    RC = ARM::GPRRegisterClass;

  // Transform the arguments stored in physical registers into virtual ones.
  unsigned Reg = MF.addLiveIn(VA.getLocReg(), RC); 
  SDValue ArgValue = DAG.getCopyFromReg(Root, dl, Reg, MVT::i32);

  SDValue ArgValue2;
  if (NextVA.isMemLoc()) {
    MachineFrameInfo *MFI = MF.getFrameInfo();
    int FI = MFI->CreateFixedObject(4, NextVA.getLocMemOffset(), true);

    // Create load node to retrieve arguments from the stack.
    SDValue FIN = DAG.getFrameIndex(FI, getPointerTy());
    ArgValue2 = DAG.getLoad(MVT::i32, dl, Root, FIN,
                            PseudoSourceValue::getFixedStack(FI), 0,
                            false, false, 0);
  } else {
    Reg = MF.addLiveIn(NextVA.getLocReg(), RC);
    ArgValue2 = DAG.getCopyFromReg(Root, dl, Reg, MVT::i32);
  }

  return DAG.getNode(ARMISD::VMOVDRR, dl, MVT::f64, ArgValue, ArgValue2);
}

SDValue
ARMTargetLowering::LowerFormalArguments(SDValue Chain,
                                        CallingConv::ID CallConv, bool isVarArg,
                                        const SmallVectorImpl<ISD::InputArg>
                                          &Ins,
                                        DebugLoc dl, SelectionDAG &DAG,
                                        SmallVectorImpl<SDValue> &InVals)
                                          const {

  MachineFunction &MF = DAG.getMachineFunction();
  MachineFrameInfo *MFI = MF.getFrameInfo();

  ARMFunctionInfo *AFI = MF.getInfo<ARMFunctionInfo>();

  // Assign locations to all of the incoming arguments.
  SmallVector<CCValAssign, 16> ArgLocs;
  CCState CCInfo(CallConv, isVarArg, getTargetMachine(), ArgLocs,
                 *DAG.getContext());
  CCInfo.AnalyzeFormalArguments(Ins,
                                CCAssignFnForNode(CallConv, /* Return*/ false,
                                                  isVarArg));

  SmallVector<SDValue, 16> ArgValues;

  for (unsigned i = 0, e = ArgLocs.size(); i != e; ++i) {
    CCValAssign &VA = ArgLocs[i];

    // Arguments stored in registers.
    if (VA.isRegLoc()) {
      EVT RegVT = VA.getLocVT();

      SDValue ArgValue;
      if (VA.needsCustom()) {
        // f64 and vector types are split up into multiple registers or
        // combinations of registers and stack slots.
        if (VA.getLocVT() == MVT::v2f64) {
          SDValue ArgValue1 = GetF64FormalArgument(VA, ArgLocs[++i],
                                                   Chain, DAG, dl);
          VA = ArgLocs[++i]; // skip ahead to next loc
          SDValue ArgValue2;
          if (VA.isMemLoc()) {
            int FI = MFI->CreateFixedObject(8, VA.getLocMemOffset(), true);
            SDValue FIN = DAG.getFrameIndex(FI, getPointerTy());
            ArgValue2 = DAG.getLoad(MVT::f64, dl, Chain, FIN,
                                    PseudoSourceValue::getFixedStack(FI), 0,
                                    false, false, 0);
          } else {
            ArgValue2 = GetF64FormalArgument(VA, ArgLocs[++i],
                                             Chain, DAG, dl);
          }
          ArgValue = DAG.getNode(ISD::UNDEF, dl, MVT::v2f64);
          ArgValue = DAG.getNode(ISD::INSERT_VECTOR_ELT, dl, MVT::v2f64,
                                 ArgValue, ArgValue1, DAG.getIntPtrConstant(0));
          ArgValue = DAG.getNode(ISD::INSERT_VECTOR_ELT, dl, MVT::v2f64,
                                 ArgValue, ArgValue2, DAG.getIntPtrConstant(1));
        } else
          ArgValue = GetF64FormalArgument(VA, ArgLocs[++i], Chain, DAG, dl);

      } else {
        TargetRegisterClass *RC;

        if (RegVT == MVT::f32)
          RC = ARM::SPRRegisterClass;
        else if (RegVT == MVT::f64)
          RC = ARM::DPRRegisterClass;
        else if (RegVT == MVT::v2f64)
          RC = ARM::QPRRegisterClass;
        else if (RegVT == MVT::i32)
          RC = (AFI->isThumb1OnlyFunction() ?
                ARM::tGPRRegisterClass : ARM::GPRRegisterClass);
        else
          llvm_unreachable("RegVT not supported by FORMAL_ARGUMENTS Lowering");

        // Transform the arguments in physical registers into virtual ones.
        unsigned Reg = MF.addLiveIn(VA.getLocReg(), RC);
        ArgValue = DAG.getCopyFromReg(Chain, dl, Reg, RegVT);
      }

      // If this is an 8 or 16-bit value, it is really passed promoted
      // to 32 bits.  Insert an assert[sz]ext to capture this, then
      // truncate to the right size.
      switch (VA.getLocInfo()) {
      default: llvm_unreachable("Unknown loc info!");
      case CCValAssign::Full: break;
      case CCValAssign::BCvt:
        ArgValue = DAG.getNode(ISD::BIT_CONVERT, dl, VA.getValVT(), ArgValue);
        break;
      case CCValAssign::SExt:
        ArgValue = DAG.getNode(ISD::AssertSext, dl, RegVT, ArgValue,
                               DAG.getValueType(VA.getValVT()));
        ArgValue = DAG.getNode(ISD::TRUNCATE, dl, VA.getValVT(), ArgValue);
        break;
      case CCValAssign::ZExt:
        ArgValue = DAG.getNode(ISD::AssertZext, dl, RegVT, ArgValue,
                               DAG.getValueType(VA.getValVT()));
        ArgValue = DAG.getNode(ISD::TRUNCATE, dl, VA.getValVT(), ArgValue);
        break;
      }

      InVals.push_back(ArgValue);

    } else { // VA.isRegLoc()

      // sanity check
      assert(VA.isMemLoc());
      assert(VA.getValVT() != MVT::i64 && "i64 should already be lowered");

      unsigned ArgSize = VA.getLocVT().getSizeInBits()/8;
      int FI = MFI->CreateFixedObject(ArgSize, VA.getLocMemOffset(), true);

      // Create load nodes to retrieve arguments from the stack.
      SDValue FIN = DAG.getFrameIndex(FI, getPointerTy());
      InVals.push_back(DAG.getLoad(VA.getValVT(), dl, Chain, FIN,
                                   PseudoSourceValue::getFixedStack(FI), 0,
                                   false, false, 0));
    }
  }

  // varargs
  if (isVarArg) {
    static const unsigned GPRArgRegs[] = {
      ARM::R0, ARM::R1, ARM::R2, ARM::R3
    };

    unsigned NumGPRs = CCInfo.getFirstUnallocated
      (GPRArgRegs, sizeof(GPRArgRegs) / sizeof(GPRArgRegs[0]));

    unsigned Align = MF.getTarget().getFrameInfo()->getStackAlignment();
    unsigned VARegSize = (4 - NumGPRs) * 4;
    unsigned VARegSaveSize = (VARegSize + Align - 1) & ~(Align - 1);
    unsigned ArgOffset = CCInfo.getNextStackOffset();
    if (VARegSaveSize) {
      // If this function is vararg, store any remaining integer argument regs
      // to their spots on the stack so that they may be loaded by deferencing
      // the result of va_next.
      AFI->setVarArgsRegSaveSize(VARegSaveSize);
      AFI->setVarArgsFrameIndex(
        MFI->CreateFixedObject(VARegSaveSize,
                               ArgOffset + VARegSaveSize - VARegSize,
                               true));
      SDValue FIN = DAG.getFrameIndex(AFI->getVarArgsFrameIndex(),
                                      getPointerTy());

      SmallVector<SDValue, 4> MemOps;
      for (; NumGPRs < 4; ++NumGPRs) {
        TargetRegisterClass *RC;
        if (AFI->isThumb1OnlyFunction())
          RC = ARM::tGPRRegisterClass;
        else
          RC = ARM::GPRRegisterClass;

        unsigned VReg = MF.addLiveIn(GPRArgRegs[NumGPRs], RC);
        SDValue Val = DAG.getCopyFromReg(Chain, dl, VReg, MVT::i32);
        SDValue Store =
          DAG.getStore(Val.getValue(1), dl, Val, FIN,
               PseudoSourceValue::getFixedStack(AFI->getVarArgsFrameIndex()),
               0, false, false, 0);
        MemOps.push_back(Store);
        FIN = DAG.getNode(ISD::ADD, dl, getPointerTy(), FIN,
                          DAG.getConstant(4, getPointerTy()));
      }
      if (!MemOps.empty())
        Chain = DAG.getNode(ISD::TokenFactor, dl, MVT::Other,
                            &MemOps[0], MemOps.size());
    } else
      // This will point to the next argument passed via stack.
      AFI->setVarArgsFrameIndex(MFI->CreateFixedObject(4, ArgOffset, true));
  }

  return Chain;
}

/// isFloatingPointZero - Return true if this is +0.0.
static bool isFloatingPointZero(SDValue Op) {
  if (ConstantFPSDNode *CFP = dyn_cast<ConstantFPSDNode>(Op))
    return CFP->getValueAPF().isPosZero();
  else if (ISD::isEXTLoad(Op.getNode()) || ISD::isNON_EXTLoad(Op.getNode())) {
    // Maybe this has already been legalized into the constant pool?
    if (Op.getOperand(1).getOpcode() == ARMISD::Wrapper) {
      SDValue WrapperOp = Op.getOperand(1).getOperand(0);
      if (ConstantPoolSDNode *CP = dyn_cast<ConstantPoolSDNode>(WrapperOp))
        if (const ConstantFP *CFP = dyn_cast<ConstantFP>(CP->getConstVal()))
          return CFP->getValueAPF().isPosZero();
    }
  }
  return false;
}

/// Returns appropriate ARM CMP (cmp) and corresponding condition code for
/// the given operands.
SDValue
ARMTargetLowering::getARMCmp(SDValue LHS, SDValue RHS, ISD::CondCode CC,
                             SDValue &ARMcc, SelectionDAG &DAG,
                             DebugLoc dl) const {
  if (ConstantSDNode *RHSC = dyn_cast<ConstantSDNode>(RHS.getNode())) {
    unsigned C = RHSC->getZExtValue();
    if (!isLegalICmpImmediate(C)) {
      // Constant does not fit, try adjusting it by one?
      switch (CC) {
      default: break;
      case ISD::SETLT:
      case ISD::SETGE:
        if (C != 0x80000000 && isLegalICmpImmediate(C-1)) {
          CC = (CC == ISD::SETLT) ? ISD::SETLE : ISD::SETGT;
          RHS = DAG.getConstant(C-1, MVT::i32);
        }
        break;
      case ISD::SETULT:
      case ISD::SETUGE:
        if (C != 0 && isLegalICmpImmediate(C-1)) {
          CC = (CC == ISD::SETULT) ? ISD::SETULE : ISD::SETUGT;
          RHS = DAG.getConstant(C-1, MVT::i32);
        }
        break;
      case ISD::SETLE:
      case ISD::SETGT:
        if (C != 0x7fffffff && isLegalICmpImmediate(C+1)) {
          CC = (CC == ISD::SETLE) ? ISD::SETLT : ISD::SETGE;
          RHS = DAG.getConstant(C+1, MVT::i32);
        }
        break;
      case ISD::SETULE:
      case ISD::SETUGT:
        if (C != 0xffffffff && isLegalICmpImmediate(C+1)) {
          CC = (CC == ISD::SETULE) ? ISD::SETULT : ISD::SETUGE;
          RHS = DAG.getConstant(C+1, MVT::i32);
        }
        break;
      }
    }
  }

  ARMCC::CondCodes CondCode = IntCCToARMCC(CC);
  ARMISD::NodeType CompareType;
  switch (CondCode) {
  default:
    CompareType = ARMISD::CMP;
    break;
  case ARMCC::EQ:
  case ARMCC::NE:
    // Uses only Z Flag
    CompareType = ARMISD::CMPZ;
    break;
  }
  ARMcc = DAG.getConstant(CondCode, MVT::i32);
  return DAG.getNode(CompareType, dl, MVT::Flag, LHS, RHS);
}

/// Returns a appropriate VFP CMP (fcmp{s|d}+fmstat) for the given operands.
SDValue
ARMTargetLowering::getVFPCmp(SDValue LHS, SDValue RHS, SelectionDAG &DAG,
                             DebugLoc dl) const {
  SDValue Cmp;
  if (!isFloatingPointZero(RHS))
    Cmp = DAG.getNode(ARMISD::CMPFP, dl, MVT::Flag, LHS, RHS);
  else
    Cmp = DAG.getNode(ARMISD::CMPFPw0, dl, MVT::Flag, LHS);
  return DAG.getNode(ARMISD::FMSTAT, dl, MVT::Flag, Cmp);
}

SDValue ARMTargetLowering::LowerSELECT(SDValue Op, SelectionDAG &DAG) const {
  SDValue Cond = Op.getOperand(0);
  SDValue SelectTrue = Op.getOperand(1);
  SDValue SelectFalse = Op.getOperand(2);
  DebugLoc dl = Op.getDebugLoc();

  // Convert:
  //
  //   (select (cmov 1, 0, cond), t, f) -> (cmov t, f, cond)
  //   (select (cmov 0, 1, cond), t, f) -> (cmov f, t, cond)
  //
  if (Cond.getOpcode() == ARMISD::CMOV && Cond.hasOneUse()) {
    const ConstantSDNode *CMOVTrue =
      dyn_cast<ConstantSDNode>(Cond.getOperand(0));
    const ConstantSDNode *CMOVFalse =
      dyn_cast<ConstantSDNode>(Cond.getOperand(1));

    if (CMOVTrue && CMOVFalse) {
      unsigned CMOVTrueVal = CMOVTrue->getZExtValue();
      unsigned CMOVFalseVal = CMOVFalse->getZExtValue();

      SDValue True;
      SDValue False;
      if (CMOVTrueVal == 1 && CMOVFalseVal == 0) {
        True = SelectTrue;
        False = SelectFalse;
      } else if (CMOVTrueVal == 0 && CMOVFalseVal == 1) {
        True = SelectFalse;
        False = SelectTrue;
      }

      if (True.getNode() && False.getNode()) {
        EVT VT = Cond.getValueType();
        SDValue ARMcc = Cond.getOperand(2);
        SDValue CCR = Cond.getOperand(3);
        SDValue Cmp = Cond.getOperand(4);
        return DAG.getNode(ARMISD::CMOV, dl, VT, True, False, ARMcc, CCR, Cmp);
      }
    }
  }

  return DAG.getSelectCC(dl, Cond,
                         DAG.getConstant(0, Cond.getValueType()),
                         SelectTrue, SelectFalse, ISD::SETNE);
}

SDValue ARMTargetLowering::LowerSELECT_CC(SDValue Op, SelectionDAG &DAG) const {
  EVT VT = Op.getValueType();
  SDValue LHS = Op.getOperand(0);
  SDValue RHS = Op.getOperand(1);
  ISD::CondCode CC = cast<CondCodeSDNode>(Op.getOperand(4))->get();
  SDValue TrueVal = Op.getOperand(2);
  SDValue FalseVal = Op.getOperand(3);
  DebugLoc dl = Op.getDebugLoc();

  if (LHS.getValueType() == MVT::i32) {
    SDValue ARMcc;
    SDValue CCR = DAG.getRegister(ARM::CPSR, MVT::i32);
    SDValue Cmp = getARMCmp(LHS, RHS, CC, ARMcc, DAG, dl);
    return DAG.getNode(ARMISD::CMOV, dl, VT, FalseVal, TrueVal, ARMcc, CCR,Cmp);
  }

  ARMCC::CondCodes CondCode, CondCode2;
  FPCCToARMCC(CC, CondCode, CondCode2);

  SDValue ARMcc = DAG.getConstant(CondCode, MVT::i32);
  SDValue Cmp = getVFPCmp(LHS, RHS, DAG, dl);
  SDValue CCR = DAG.getRegister(ARM::CPSR, MVT::i32);
  SDValue Result = DAG.getNode(ARMISD::CMOV, dl, VT, FalseVal, TrueVal,
                               ARMcc, CCR, Cmp);
  if (CondCode2 != ARMCC::AL) {
    SDValue ARMcc2 = DAG.getConstant(CondCode2, MVT::i32);
    // FIXME: Needs another CMP because flag can have but one use.
    SDValue Cmp2 = getVFPCmp(LHS, RHS, DAG, dl);
    Result = DAG.getNode(ARMISD::CMOV, dl, VT,
                         Result, TrueVal, ARMcc2, CCR, Cmp2);
  }
  return Result;
}

/// canChangeToInt - Given the fp compare operand, return true if it is suitable
/// to morph to an integer compare sequence.
static bool canChangeToInt(SDValue Op, bool &SeenZero,
                           const ARMSubtarget *Subtarget) {
  SDNode *N = Op.getNode();
  if (!N->hasOneUse())
    // Otherwise it requires moving the value from fp to integer registers.
    return false;
  if (!N->getNumValues())
    return false;
  EVT VT = Op.getValueType();
  if (VT != MVT::f32 && !Subtarget->isFPBrccSlow())
    // f32 case is generally profitable. f64 case only makes sense when vcmpe +
    // vmrs are very slow, e.g. cortex-a8.
    return false;

  if (isFloatingPointZero(Op)) {
    SeenZero = true;
    return true;
  }
  return ISD::isNormalLoad(N);
}

static SDValue bitcastf32Toi32(SDValue Op, SelectionDAG &DAG) {
  if (isFloatingPointZero(Op))
    return DAG.getConstant(0, MVT::i32);

  if (LoadSDNode *Ld = dyn_cast<LoadSDNode>(Op))
    return DAG.getLoad(MVT::i32, Op.getDebugLoc(),
                       Ld->getChain(), Ld->getBasePtr(),
                       Ld->getSrcValue(), Ld->getSrcValueOffset(),
                       Ld->isVolatile(), Ld->isNonTemporal(),
                       Ld->getAlignment());

  llvm_unreachable("Unknown VFP cmp argument!");
}

static void expandf64Toi32(SDValue Op, SelectionDAG &DAG,
                           SDValue &RetVal1, SDValue &RetVal2) {
  if (isFloatingPointZero(Op)) {
    RetVal1 = DAG.getConstant(0, MVT::i32);
    RetVal2 = DAG.getConstant(0, MVT::i32);
    return;
  }

  if (LoadSDNode *Ld = dyn_cast<LoadSDNode>(Op)) {
    SDValue Ptr = Ld->getBasePtr();
    RetVal1 = DAG.getLoad(MVT::i32, Op.getDebugLoc(),
                          Ld->getChain(), Ptr,
                          Ld->getSrcValue(), Ld->getSrcValueOffset(),
                          Ld->isVolatile(), Ld->isNonTemporal(),
                          Ld->getAlignment());

    EVT PtrType = Ptr.getValueType();
    unsigned NewAlign = MinAlign(Ld->getAlignment(), 4);
    SDValue NewPtr = DAG.getNode(ISD::ADD, Op.getDebugLoc(),
                                 PtrType, Ptr, DAG.getConstant(4, PtrType));
    RetVal2 = DAG.getLoad(MVT::i32, Op.getDebugLoc(),
                          Ld->getChain(), NewPtr,
                          Ld->getSrcValue(), Ld->getSrcValueOffset() + 4,
                          Ld->isVolatile(), Ld->isNonTemporal(),
                          NewAlign);
    return;
  }

  llvm_unreachable("Unknown VFP cmp argument!");
}

/// OptimizeVFPBrcond - With -enable-unsafe-fp-math, it's legal to optimize some
/// f32 and even f64 comparisons to integer ones.
SDValue
ARMTargetLowering::OptimizeVFPBrcond(SDValue Op, SelectionDAG &DAG) const {
  SDValue Chain = Op.getOperand(0);
  ISD::CondCode CC = cast<CondCodeSDNode>(Op.getOperand(1))->get();
  SDValue LHS = Op.getOperand(2);
  SDValue RHS = Op.getOperand(3);
  SDValue Dest = Op.getOperand(4);
  DebugLoc dl = Op.getDebugLoc();

  bool SeenZero = false;
  if (canChangeToInt(LHS, SeenZero, Subtarget) &&
      canChangeToInt(RHS, SeenZero, Subtarget) &&
      // If one of the operand is zero, it's safe to ignore the NaN case since
      // we only care about equality comparisons.
      (SeenZero || (DAG.isKnownNeverNaN(LHS) && DAG.isKnownNeverNaN(RHS)))) {
    // If unsafe fp math optimization is enabled and there are no othter uses of
    // the CMP operands, and the condition code is EQ oe NE, we can optimize it
    // to an integer comparison.
    if (CC == ISD::SETOEQ)
      CC = ISD::SETEQ;
    else if (CC == ISD::SETUNE)
      CC = ISD::SETNE;

    SDValue ARMcc;
    if (LHS.getValueType() == MVT::f32) {
      LHS = bitcastf32Toi32(LHS, DAG);
      RHS = bitcastf32Toi32(RHS, DAG);
      SDValue Cmp = getARMCmp(LHS, RHS, CC, ARMcc, DAG, dl);
      SDValue CCR = DAG.getRegister(ARM::CPSR, MVT::i32);
      return DAG.getNode(ARMISD::BRCOND, dl, MVT::Other,
                         Chain, Dest, ARMcc, CCR, Cmp);
    }

    SDValue LHS1, LHS2;
    SDValue RHS1, RHS2;
    expandf64Toi32(LHS, DAG, LHS1, LHS2);
    expandf64Toi32(RHS, DAG, RHS1, RHS2);
    ARMCC::CondCodes CondCode = IntCCToARMCC(CC);
    ARMcc = DAG.getConstant(CondCode, MVT::i32);
    SDVTList VTList = DAG.getVTList(MVT::Other, MVT::Flag);
    SDValue Ops[] = { Chain, ARMcc, LHS1, LHS2, RHS1, RHS2, Dest };
    return DAG.getNode(ARMISD::BCC_i64, dl, VTList, Ops, 7);
  }

  return SDValue();
}

SDValue ARMTargetLowering::LowerBR_CC(SDValue Op, SelectionDAG &DAG) const {
  SDValue Chain = Op.getOperand(0);
  ISD::CondCode CC = cast<CondCodeSDNode>(Op.getOperand(1))->get();
  SDValue LHS = Op.getOperand(2);
  SDValue RHS = Op.getOperand(3);
  SDValue Dest = Op.getOperand(4);
  DebugLoc dl = Op.getDebugLoc();

  if (LHS.getValueType() == MVT::i32) {
    SDValue ARMcc;
    SDValue Cmp = getARMCmp(LHS, RHS, CC, ARMcc, DAG, dl);
    SDValue CCR = DAG.getRegister(ARM::CPSR, MVT::i32);
    return DAG.getNode(ARMISD::BRCOND, dl, MVT::Other,
                       Chain, Dest, ARMcc, CCR, Cmp);
  }

  assert(LHS.getValueType() == MVT::f32 || LHS.getValueType() == MVT::f64);

  if (UnsafeFPMath &&
      (CC == ISD::SETEQ || CC == ISD::SETOEQ ||
       CC == ISD::SETNE || CC == ISD::SETUNE)) {
    SDValue Result = OptimizeVFPBrcond(Op, DAG);
    if (Result.getNode())
      return Result;
  }

  ARMCC::CondCodes CondCode, CondCode2;
  FPCCToARMCC(CC, CondCode, CondCode2);

  SDValue ARMcc = DAG.getConstant(CondCode, MVT::i32);
  SDValue Cmp = getVFPCmp(LHS, RHS, DAG, dl);
  SDValue CCR = DAG.getRegister(ARM::CPSR, MVT::i32);
  SDVTList VTList = DAG.getVTList(MVT::Other, MVT::Flag);
  SDValue Ops[] = { Chain, Dest, ARMcc, CCR, Cmp };
  SDValue Res = DAG.getNode(ARMISD::BRCOND, dl, VTList, Ops, 5);
  if (CondCode2 != ARMCC::AL) {
    ARMcc = DAG.getConstant(CondCode2, MVT::i32);
    SDValue Ops[] = { Res, Dest, ARMcc, CCR, Res.getValue(1) };
    Res = DAG.getNode(ARMISD::BRCOND, dl, VTList, Ops, 5);
  }
  return Res;
}

SDValue ARMTargetLowering::LowerBR_JT(SDValue Op, SelectionDAG &DAG) const {
  SDValue Chain = Op.getOperand(0);
  SDValue Table = Op.getOperand(1);
  SDValue Index = Op.getOperand(2);
  DebugLoc dl = Op.getDebugLoc();

  EVT PTy = getPointerTy();
  JumpTableSDNode *JT = cast<JumpTableSDNode>(Table);
  ARMFunctionInfo *AFI = DAG.getMachineFunction().getInfo<ARMFunctionInfo>();
  SDValue UId = DAG.getConstant(AFI->createJumpTableUId(), PTy);
  SDValue JTI = DAG.getTargetJumpTable(JT->getIndex(), PTy);
  Table = DAG.getNode(ARMISD::WrapperJT, dl, MVT::i32, JTI, UId);
  Index = DAG.getNode(ISD::MUL, dl, PTy, Index, DAG.getConstant(4, PTy));
  SDValue Addr = DAG.getNode(ISD::ADD, dl, PTy, Index, Table);
  if (Subtarget->isThumb2()) {
    // Thumb2 uses a two-level jump. That is, it jumps into the jump table
    // which does another jump to the destination. This also makes it easier
    // to translate it to TBB / TBH later.
    // FIXME: This might not work if the function is extremely large.
    return DAG.getNode(ARMISD::BR2_JT, dl, MVT::Other, Chain,
                       Addr, Op.getOperand(2), JTI, UId);
  }
  if (getTargetMachine().getRelocationModel() == Reloc::PIC_) {
    Addr = DAG.getLoad((EVT)MVT::i32, dl, Chain, Addr,
                       PseudoSourceValue::getJumpTable(), 0,
                       false, false, 0);
    Chain = Addr.getValue(1);
    Addr = DAG.getNode(ISD::ADD, dl, PTy, Addr, Table);
    return DAG.getNode(ARMISD::BR_JT, dl, MVT::Other, Chain, Addr, JTI, UId);
  } else {
    Addr = DAG.getLoad(PTy, dl, Chain, Addr,
                       PseudoSourceValue::getJumpTable(), 0, false, false, 0);
    Chain = Addr.getValue(1);
    return DAG.getNode(ARMISD::BR_JT, dl, MVT::Other, Chain, Addr, JTI, UId);
  }
}

static SDValue LowerFP_TO_INT(SDValue Op, SelectionDAG &DAG) {
  DebugLoc dl = Op.getDebugLoc();
  unsigned Opc;

  switch (Op.getOpcode()) {
  default:
    assert(0 && "Invalid opcode!");
  case ISD::FP_TO_SINT:
    Opc = ARMISD::FTOSI;
    break;
  case ISD::FP_TO_UINT:
    Opc = ARMISD::FTOUI;
    break;
  }
  Op = DAG.getNode(Opc, dl, MVT::f32, Op.getOperand(0));
  return DAG.getNode(ISD::BIT_CONVERT, dl, MVT::i32, Op);
}

static SDValue LowerINT_TO_FP(SDValue Op, SelectionDAG &DAG) {
  EVT VT = Op.getValueType();
  DebugLoc dl = Op.getDebugLoc();
  unsigned Opc;

  switch (Op.getOpcode()) {
  default:
    assert(0 && "Invalid opcode!");
  case ISD::SINT_TO_FP:
    Opc = ARMISD::SITOF;
    break;
  case ISD::UINT_TO_FP:
    Opc = ARMISD::UITOF;
    break;
  }

  Op = DAG.getNode(ISD::BIT_CONVERT, dl, MVT::f32, Op.getOperand(0));
  return DAG.getNode(Opc, dl, VT, Op);
}

SDValue ARMTargetLowering::LowerFCOPYSIGN(SDValue Op, SelectionDAG &DAG) const {
  // Implement fcopysign with a fabs and a conditional fneg.
  SDValue Tmp0 = Op.getOperand(0);
  SDValue Tmp1 = Op.getOperand(1);
  DebugLoc dl = Op.getDebugLoc();
  EVT VT = Op.getValueType();
  EVT SrcVT = Tmp1.getValueType();
  SDValue AbsVal = DAG.getNode(ISD::FABS, dl, VT, Tmp0);
  SDValue ARMcc = DAG.getConstant(ARMCC::LT, MVT::i32);
  SDValue FP0 = DAG.getConstantFP(0.0, SrcVT);
  SDValue Cmp = getVFPCmp(Tmp1, FP0, DAG, dl);
  SDValue CCR = DAG.getRegister(ARM::CPSR, MVT::i32);
  return DAG.getNode(ARMISD::CNEG, dl, VT, AbsVal, AbsVal, ARMcc, CCR, Cmp);
}

SDValue ARMTargetLowering::LowerRETURNADDR(SDValue Op, SelectionDAG &DAG) const{
  MachineFunction &MF = DAG.getMachineFunction();
  MachineFrameInfo *MFI = MF.getFrameInfo();
  MFI->setReturnAddressIsTaken(true);

  EVT VT = Op.getValueType();
  DebugLoc dl = Op.getDebugLoc();
  unsigned Depth = cast<ConstantSDNode>(Op.getOperand(0))->getZExtValue();
  if (Depth) {
    SDValue FrameAddr = LowerFRAMEADDR(Op, DAG);
    SDValue Offset = DAG.getConstant(4, MVT::i32);
    return DAG.getLoad(VT, dl, DAG.getEntryNode(),
                       DAG.getNode(ISD::ADD, dl, VT, FrameAddr, Offset),
                       NULL, 0, false, false, 0);
  }

  // Return LR, which contains the return address. Mark it an implicit live-in.
  unsigned Reg = MF.addLiveIn(ARM::LR, getRegClassFor(MVT::i32));
  return DAG.getCopyFromReg(DAG.getEntryNode(), dl, Reg, VT);
}

SDValue ARMTargetLowering::LowerFRAMEADDR(SDValue Op, SelectionDAG &DAG) const {
  MachineFrameInfo *MFI = DAG.getMachineFunction().getFrameInfo();
  MFI->setFrameAddressIsTaken(true);

  EVT VT = Op.getValueType();
  DebugLoc dl = Op.getDebugLoc();  // FIXME probably not meaningful
  unsigned Depth = cast<ConstantSDNode>(Op.getOperand(0))->getZExtValue();
  unsigned FrameReg = (Subtarget->isThumb() || Subtarget->isTargetDarwin())
    ? ARM::R7 : ARM::R11;
  SDValue FrameAddr = DAG.getCopyFromReg(DAG.getEntryNode(), dl, FrameReg, VT);
  while (Depth--)
    FrameAddr = DAG.getLoad(VT, dl, DAG.getEntryNode(), FrameAddr, NULL, 0,
                            false, false, 0);
  return FrameAddr;
}

/// ExpandBIT_CONVERT - If the target supports VFP, this function is called to
/// expand a bit convert where either the source or destination type is i64 to
/// use a VMOVDRR or VMOVRRD node.  This should not be done when the non-i64
/// operand type is illegal (e.g., v2f32 for a target that doesn't support
/// vectors), since the legalizer won't know what to do with that.
static SDValue ExpandBIT_CONVERT(SDNode *N, SelectionDAG &DAG) {
  const TargetLowering &TLI = DAG.getTargetLoweringInfo();
  DebugLoc dl = N->getDebugLoc();
  SDValue Op = N->getOperand(0);

  // This function is only supposed to be called for i64 types, either as the
  // source or destination of the bit convert.
  EVT SrcVT = Op.getValueType();
  EVT DstVT = N->getValueType(0);
  assert((SrcVT == MVT::i64 || DstVT == MVT::i64) &&
         "ExpandBIT_CONVERT called for non-i64 type");

  // Turn i64->f64 into VMOVDRR.
  if (SrcVT == MVT::i64 && TLI.isTypeLegal(DstVT)) {
    SDValue Lo = DAG.getNode(ISD::EXTRACT_ELEMENT, dl, MVT::i32, Op,
                             DAG.getConstant(0, MVT::i32));
    SDValue Hi = DAG.getNode(ISD::EXTRACT_ELEMENT, dl, MVT::i32, Op,
                             DAG.getConstant(1, MVT::i32));
    return DAG.getNode(ISD::BIT_CONVERT, dl, DstVT,
                       DAG.getNode(ARMISD::VMOVDRR, dl, MVT::f64, Lo, Hi));
  }

  // Turn f64->i64 into VMOVRRD.
  if (DstVT == MVT::i64 && TLI.isTypeLegal(SrcVT)) {
    SDValue Cvt = DAG.getNode(ARMISD::VMOVRRD, dl,
                              DAG.getVTList(MVT::i32, MVT::i32), &Op, 1);
    // Merge the pieces into a single i64 value.
    return DAG.getNode(ISD::BUILD_PAIR, dl, MVT::i64, Cvt, Cvt.getValue(1));
  }

  return SDValue();
}

/// getZeroVector - Returns a vector of specified type with all zero elements.
/// Zero vectors are used to represent vector negation and in those cases
/// will be implemented with the NEON VNEG instruction.  However, VNEG does
/// not support i64 elements, so sometimes the zero vectors will need to be
/// explicitly constructed.  Regardless, use a canonical VMOV to create the
/// zero vector.
static SDValue getZeroVector(EVT VT, SelectionDAG &DAG, DebugLoc dl) {
  assert(VT.isVector() && "Expected a vector type");
  // The canonical modified immediate encoding of a zero vector is....0!
  SDValue EncodedVal = DAG.getTargetConstant(0, MVT::i32);
  EVT VmovVT = VT.is128BitVector() ? MVT::v4i32 : MVT::v2i32;
  SDValue Vmov = DAG.getNode(ARMISD::VMOVIMM, dl, VmovVT, EncodedVal);
  return DAG.getNode(ISD::BIT_CONVERT, dl, VT, Vmov);
}

/// LowerShiftRightParts - Lower SRA_PARTS, which returns two
/// i32 values and take a 2 x i32 value to shift plus a shift amount.
SDValue ARMTargetLowering::LowerShiftRightParts(SDValue Op,
                                                SelectionDAG &DAG) const {
  assert(Op.getNumOperands() == 3 && "Not a double-shift!");
  EVT VT = Op.getValueType();
  unsigned VTBits = VT.getSizeInBits();
  DebugLoc dl = Op.getDebugLoc();
  SDValue ShOpLo = Op.getOperand(0);
  SDValue ShOpHi = Op.getOperand(1);
  SDValue ShAmt  = Op.getOperand(2);
  SDValue ARMcc;
  unsigned Opc = (Op.getOpcode() == ISD::SRA_PARTS) ? ISD::SRA : ISD::SRL;

  assert(Op.getOpcode() == ISD::SRA_PARTS || Op.getOpcode() == ISD::SRL_PARTS);

  SDValue RevShAmt = DAG.getNode(ISD::SUB, dl, MVT::i32,
                                 DAG.getConstant(VTBits, MVT::i32), ShAmt);
  SDValue Tmp1 = DAG.getNode(ISD::SRL, dl, VT, ShOpLo, ShAmt);
  SDValue ExtraShAmt = DAG.getNode(ISD::SUB, dl, MVT::i32, ShAmt,
                                   DAG.getConstant(VTBits, MVT::i32));
  SDValue Tmp2 = DAG.getNode(ISD::SHL, dl, VT, ShOpHi, RevShAmt);
  SDValue FalseVal = DAG.getNode(ISD::OR, dl, VT, Tmp1, Tmp2);
  SDValue TrueVal = DAG.getNode(Opc, dl, VT, ShOpHi, ExtraShAmt);

  SDValue CCR = DAG.getRegister(ARM::CPSR, MVT::i32);
  SDValue Cmp = getARMCmp(ExtraShAmt, DAG.getConstant(0, MVT::i32), ISD::SETGE,
                          ARMcc, DAG, dl);
  SDValue Hi = DAG.getNode(Opc, dl, VT, ShOpHi, ShAmt);
  SDValue Lo = DAG.getNode(ARMISD::CMOV, dl, VT, FalseVal, TrueVal, ARMcc,
                           CCR, Cmp);

  SDValue Ops[2] = { Lo, Hi };
  return DAG.getMergeValues(Ops, 2, dl);
}

/// LowerShiftLeftParts - Lower SHL_PARTS, which returns two
/// i32 values and take a 2 x i32 value to shift plus a shift amount.
SDValue ARMTargetLowering::LowerShiftLeftParts(SDValue Op,
                                               SelectionDAG &DAG) const {
  assert(Op.getNumOperands() == 3 && "Not a double-shift!");
  EVT VT = Op.getValueType();
  unsigned VTBits = VT.getSizeInBits();
  DebugLoc dl = Op.getDebugLoc();
  SDValue ShOpLo = Op.getOperand(0);
  SDValue ShOpHi = Op.getOperand(1);
  SDValue ShAmt  = Op.getOperand(2);
  SDValue ARMcc;

  assert(Op.getOpcode() == ISD::SHL_PARTS);
  SDValue RevShAmt = DAG.getNode(ISD::SUB, dl, MVT::i32,
                                 DAG.getConstant(VTBits, MVT::i32), ShAmt);
  SDValue Tmp1 = DAG.getNode(ISD::SRL, dl, VT, ShOpLo, RevShAmt);
  SDValue ExtraShAmt = DAG.getNode(ISD::SUB, dl, MVT::i32, ShAmt,
                                   DAG.getConstant(VTBits, MVT::i32));
  SDValue Tmp2 = DAG.getNode(ISD::SHL, dl, VT, ShOpHi, ShAmt);
  SDValue Tmp3 = DAG.getNode(ISD::SHL, dl, VT, ShOpLo, ExtraShAmt);

  SDValue FalseVal = DAG.getNode(ISD::OR, dl, VT, Tmp1, Tmp2);
  SDValue CCR = DAG.getRegister(ARM::CPSR, MVT::i32);
  SDValue Cmp = getARMCmp(ExtraShAmt, DAG.getConstant(0, MVT::i32), ISD::SETGE,
                          ARMcc, DAG, dl);
  SDValue Lo = DAG.getNode(ISD::SHL, dl, VT, ShOpLo, ShAmt);
  SDValue Hi = DAG.getNode(ARMISD::CMOV, dl, VT, FalseVal, Tmp3, ARMcc,
                           CCR, Cmp);

  SDValue Ops[2] = { Lo, Hi };
  return DAG.getMergeValues(Ops, 2, dl);
}

SDValue ARMTargetLowering::LowerFLT_ROUNDS_(SDValue Op, 
                                            SelectionDAG &DAG) const {
  // The rounding mode is in bits 23:22 of the FPSCR.
  // The ARM rounding mode value to FLT_ROUNDS mapping is 0->1, 1->2, 2->3, 3->0
  // The formula we use to implement this is (((FPSCR + 1 << 22) >> 22) & 3)
  // so that the shift + and get folded into a bitfield extract.
  DebugLoc dl = Op.getDebugLoc();
  SDValue FPSCR = DAG.getNode(ISD::INTRINSIC_WO_CHAIN, dl, MVT::i32,
                              DAG.getConstant(Intrinsic::arm_get_fpscr,
                                              MVT::i32));
  SDValue FltRounds = DAG.getNode(ISD::ADD, dl, MVT::i32, FPSCR, 
                                  DAG.getConstant(1U << 22, MVT::i32));
  SDValue RMODE = DAG.getNode(ISD::SRL, dl, MVT::i32, FltRounds,
                              DAG.getConstant(22, MVT::i32));
  return DAG.getNode(ISD::AND, dl, MVT::i32, RMODE, 
                     DAG.getConstant(3, MVT::i32));
}

static SDValue LowerCTTZ(SDNode *N, SelectionDAG &DAG,
                         const ARMSubtarget *ST) {
  EVT VT = N->getValueType(0);
  DebugLoc dl = N->getDebugLoc();

  if (!ST->hasV6T2Ops())
    return SDValue();

  SDValue rbit = DAG.getNode(ARMISD::RBIT, dl, VT, N->getOperand(0));
  return DAG.getNode(ISD::CTLZ, dl, VT, rbit);
}

static SDValue LowerShift(SDNode *N, SelectionDAG &DAG,
                          const ARMSubtarget *ST) {
  EVT VT = N->getValueType(0);
  DebugLoc dl = N->getDebugLoc();

  // Lower vector shifts on NEON to use VSHL.
  if (VT.isVector()) {
    assert(ST->hasNEON() && "unexpected vector shift");

    // Left shifts translate directly to the vshiftu intrinsic.
    if (N->getOpcode() == ISD::SHL)
      return DAG.getNode(ISD::INTRINSIC_WO_CHAIN, dl, VT,
                         DAG.getConstant(Intrinsic::arm_neon_vshiftu, MVT::i32),
                         N->getOperand(0), N->getOperand(1));

    assert((N->getOpcode() == ISD::SRA ||
            N->getOpcode() == ISD::SRL) && "unexpected vector shift opcode");

    // NEON uses the same intrinsics for both left and right shifts.  For
    // right shifts, the shift amounts are negative, so negate the vector of
    // shift amounts.
    EVT ShiftVT = N->getOperand(1).getValueType();
    SDValue NegatedCount = DAG.getNode(ISD::SUB, dl, ShiftVT,
                                       getZeroVector(ShiftVT, DAG, dl),
                                       N->getOperand(1));
    Intrinsic::ID vshiftInt = (N->getOpcode() == ISD::SRA ?
                               Intrinsic::arm_neon_vshifts :
                               Intrinsic::arm_neon_vshiftu);
    return DAG.getNode(ISD::INTRINSIC_WO_CHAIN, dl, VT,
                       DAG.getConstant(vshiftInt, MVT::i32),
                       N->getOperand(0), NegatedCount);
  }

  // We can get here for a node like i32 = ISD::SHL i32, i64
  if (VT != MVT::i64)
    return SDValue();

  assert((N->getOpcode() == ISD::SRL || N->getOpcode() == ISD::SRA) &&
         "Unknown shift to lower!");

  // We only lower SRA, SRL of 1 here, all others use generic lowering.
  if (!isa<ConstantSDNode>(N->getOperand(1)) ||
      cast<ConstantSDNode>(N->getOperand(1))->getZExtValue() != 1)
    return SDValue();

  // If we are in thumb mode, we don't have RRX.
  if (ST->isThumb1Only()) return SDValue();

  // Okay, we have a 64-bit SRA or SRL of 1.  Lower this to an RRX expr.
  SDValue Lo = DAG.getNode(ISD::EXTRACT_ELEMENT, dl, MVT::i32, N->getOperand(0),
                           DAG.getConstant(0, MVT::i32));
  SDValue Hi = DAG.getNode(ISD::EXTRACT_ELEMENT, dl, MVT::i32, N->getOperand(0),
                           DAG.getConstant(1, MVT::i32));

  // First, build a SRA_FLAG/SRL_FLAG op, which shifts the top part by one and
  // captures the result into a carry flag.
  unsigned Opc = N->getOpcode() == ISD::SRL ? ARMISD::SRL_FLAG:ARMISD::SRA_FLAG;
  Hi = DAG.getNode(Opc, dl, DAG.getVTList(MVT::i32, MVT::Flag), &Hi, 1);

  // The low part is an ARMISD::RRX operand, which shifts the carry in.
  Lo = DAG.getNode(ARMISD::RRX, dl, MVT::i32, Lo, Hi.getValue(1));

  // Merge the pieces into a single i64 value.
 return DAG.getNode(ISD::BUILD_PAIR, dl, MVT::i64, Lo, Hi);
}

static SDValue LowerVSETCC(SDValue Op, SelectionDAG &DAG) {
  SDValue TmpOp0, TmpOp1;
  bool Invert = false;
  bool Swap = false;
  unsigned Opc = 0;

  SDValue Op0 = Op.getOperand(0);
  SDValue Op1 = Op.getOperand(1);
  SDValue CC = Op.getOperand(2);
  EVT VT = Op.getValueType();
  ISD::CondCode SetCCOpcode = cast<CondCodeSDNode>(CC)->get();
  DebugLoc dl = Op.getDebugLoc();

  if (Op.getOperand(1).getValueType().isFloatingPoint()) {
    switch (SetCCOpcode) {
    default: llvm_unreachable("Illegal FP comparison"); break;
    case ISD::SETUNE:
    case ISD::SETNE:  Invert = true; // Fallthrough
    case ISD::SETOEQ:
    case ISD::SETEQ:  Opc = ARMISD::VCEQ; break;
    case ISD::SETOLT:
    case ISD::SETLT: Swap = true; // Fallthrough
    case ISD::SETOGT:
    case ISD::SETGT:  Opc = ARMISD::VCGT; break;
    case ISD::SETOLE:
    case ISD::SETLE:  Swap = true; // Fallthrough
    case ISD::SETOGE:
    case ISD::SETGE: Opc = ARMISD::VCGE; break;
    case ISD::SETUGE: Swap = true; // Fallthrough
    case ISD::SETULE: Invert = true; Opc = ARMISD::VCGT; break;
    case ISD::SETUGT: Swap = true; // Fallthrough
    case ISD::SETULT: Invert = true; Opc = ARMISD::VCGE; break;
    case ISD::SETUEQ: Invert = true; // Fallthrough
    case ISD::SETONE:
      // Expand this to (OLT | OGT).
      TmpOp0 = Op0;
      TmpOp1 = Op1;
      Opc = ISD::OR;
      Op0 = DAG.getNode(ARMISD::VCGT, dl, VT, TmpOp1, TmpOp0);
      Op1 = DAG.getNode(ARMISD::VCGT, dl, VT, TmpOp0, TmpOp1);
      break;
    case ISD::SETUO: Invert = true; // Fallthrough
    case ISD::SETO:
      // Expand this to (OLT | OGE).
      TmpOp0 = Op0;
      TmpOp1 = Op1;
      Opc = ISD::OR;
      Op0 = DAG.getNode(ARMISD::VCGT, dl, VT, TmpOp1, TmpOp0);
      Op1 = DAG.getNode(ARMISD::VCGE, dl, VT, TmpOp0, TmpOp1);
      break;
    }
  } else {
    // Integer comparisons.
    switch (SetCCOpcode) {
    default: llvm_unreachable("Illegal integer comparison"); break;
    case ISD::SETNE:  Invert = true;
    case ISD::SETEQ:  Opc = ARMISD::VCEQ; break;
    case ISD::SETLT:  Swap = true;
    case ISD::SETGT:  Opc = ARMISD::VCGT; break;
    case ISD::SETLE:  Swap = true;
    case ISD::SETGE:  Opc = ARMISD::VCGE; break;
    case ISD::SETULT: Swap = true;
    case ISD::SETUGT: Opc = ARMISD::VCGTU; break;
    case ISD::SETULE: Swap = true;
    case ISD::SETUGE: Opc = ARMISD::VCGEU; break;
    }

    // Detect VTST (Vector Test Bits) = icmp ne (and (op0, op1), zero).
    if (Opc == ARMISD::VCEQ) {

      SDValue AndOp;
      if (ISD::isBuildVectorAllZeros(Op1.getNode()))
        AndOp = Op0;
      else if (ISD::isBuildVectorAllZeros(Op0.getNode()))
        AndOp = Op1;

      // Ignore bitconvert.
      if (AndOp.getNode() && AndOp.getOpcode() == ISD::BIT_CONVERT)
        AndOp = AndOp.getOperand(0);

      if (AndOp.getNode() && AndOp.getOpcode() == ISD::AND) {
        Opc = ARMISD::VTST;
        Op0 = DAG.getNode(ISD::BIT_CONVERT, dl, VT, AndOp.getOperand(0));
        Op1 = DAG.getNode(ISD::BIT_CONVERT, dl, VT, AndOp.getOperand(1));
        Invert = !Invert;
      }
    }
  }

  if (Swap)
    std::swap(Op0, Op1);

  SDValue Result = DAG.getNode(Opc, dl, VT, Op0, Op1);

  if (Invert)
    Result = DAG.getNOT(dl, Result, VT);

  return Result;
}

/// isNEONModifiedImm - Check if the specified splat value corresponds to a
/// valid vector constant for a NEON instruction with a "modified immediate"
/// operand (e.g., VMOV).  If so, return the encoded value.
static SDValue isNEONModifiedImm(uint64_t SplatBits, uint64_t SplatUndef,
                                 unsigned SplatBitSize, SelectionDAG &DAG,
                                 EVT &VT, bool is128Bits, bool isVMOV) {
  unsigned OpCmode, Imm;

  // SplatBitSize is set to the smallest size that splats the vector, so a
  // zero vector will always have SplatBitSize == 8.  However, NEON modified
  // immediate instructions others than VMOV do not support the 8-bit encoding
  // of a zero vector, and the default encoding of zero is supposed to be the
  // 32-bit version.
  if (SplatBits == 0)
    SplatBitSize = 32;

  switch (SplatBitSize) {
  case 8:
    if (!isVMOV)
      return SDValue();
    // Any 1-byte value is OK.  Op=0, Cmode=1110.
    assert((SplatBits & ~0xff) == 0 && "one byte splat value is too big");
    OpCmode = 0xe;
    Imm = SplatBits;
    VT = is128Bits ? MVT::v16i8 : MVT::v8i8;
    break;

  case 16:
    // NEON's 16-bit VMOV supports splat values where only one byte is nonzero.
    VT = is128Bits ? MVT::v8i16 : MVT::v4i16;
    if ((SplatBits & ~0xff) == 0) {
      // Value = 0x00nn: Op=x, Cmode=100x.
      OpCmode = 0x8;
      Imm = SplatBits;
      break;
    }
    if ((SplatBits & ~0xff00) == 0) {
      // Value = 0xnn00: Op=x, Cmode=101x.
      OpCmode = 0xa;
      Imm = SplatBits >> 8;
      break;
    }
    return SDValue();

  case 32:
    // NEON's 32-bit VMOV supports splat values where:
    // * only one byte is nonzero, or
    // * the least significant byte is 0xff and the second byte is nonzero, or
    // * the least significant 2 bytes are 0xff and the third is nonzero.
    VT = is128Bits ? MVT::v4i32 : MVT::v2i32;
    if ((SplatBits & ~0xff) == 0) {
      // Value = 0x000000nn: Op=x, Cmode=000x.
      OpCmode = 0;
      Imm = SplatBits;
      break;
    }
    if ((SplatBits & ~0xff00) == 0) {
      // Value = 0x0000nn00: Op=x, Cmode=001x.
      OpCmode = 0x2;
      Imm = SplatBits >> 8;
      break;
    }
    if ((SplatBits & ~0xff0000) == 0) {
      // Value = 0x00nn0000: Op=x, Cmode=010x.
      OpCmode = 0x4;
      Imm = SplatBits >> 16;
      break;
    }
    if ((SplatBits & ~0xff000000) == 0) {
      // Value = 0xnn000000: Op=x, Cmode=011x.
      OpCmode = 0x6;
      Imm = SplatBits >> 24;
      break;
    }

    if ((SplatBits & ~0xffff) == 0 &&
        ((SplatBits | SplatUndef) & 0xff) == 0xff) {
      // Value = 0x0000nnff: Op=x, Cmode=1100.
      OpCmode = 0xc;
      Imm = SplatBits >> 8;
      SplatBits |= 0xff;
      break;
    }

    if ((SplatBits & ~0xffffff) == 0 &&
        ((SplatBits | SplatUndef) & 0xffff) == 0xffff) {
      // Value = 0x00nnffff: Op=x, Cmode=1101.
      OpCmode = 0xd;
      Imm = SplatBits >> 16;
      SplatBits |= 0xffff;
      break;
    }

    // Note: there are a few 32-bit splat values (specifically: 00ffff00,
    // ff000000, ff0000ff, and ffff00ff) that are valid for VMOV.I64 but not
    // VMOV.I32.  A (very) minor optimization would be to replicate the value
    // and fall through here to test for a valid 64-bit splat.  But, then the
    // caller would also need to check and handle the change in size.
    return SDValue();

  case 64: {
    if (!isVMOV)
      return SDValue();
    // NEON has a 64-bit VMOV splat where each byte is either 0 or 0xff.
    uint64_t BitMask = 0xff;
    uint64_t Val = 0;
    unsigned ImmMask = 1;
    Imm = 0;
    for (int ByteNum = 0; ByteNum < 8; ++ByteNum) {
      if (((SplatBits | SplatUndef) & BitMask) == BitMask) {
        Val |= BitMask;
        Imm |= ImmMask;
      } else if ((SplatBits & BitMask) != 0) {
        return SDValue();
      }
      BitMask <<= 8;
      ImmMask <<= 1;
    }
    // Op=1, Cmode=1110.
    OpCmode = 0x1e;
    SplatBits = Val;
    VT = is128Bits ? MVT::v2i64 : MVT::v1i64;
    break;
  }

  default:
    llvm_unreachable("unexpected size for isNEONModifiedImm");
    return SDValue();
  }

  unsigned EncodedVal = ARM_AM::createNEONModImm(OpCmode, Imm);
  return DAG.getTargetConstant(EncodedVal, MVT::i32);
}

static bool isVEXTMask(const SmallVectorImpl<int> &M, EVT VT,
                       bool &ReverseVEXT, unsigned &Imm) {
  unsigned NumElts = VT.getVectorNumElements();
  ReverseVEXT = false;

  // Assume that the first shuffle index is not UNDEF.  Fail if it is.
  if (M[0] < 0)
    return false;

  Imm = M[0];

  // If this is a VEXT shuffle, the immediate value is the index of the first
  // element.  The other shuffle indices must be the successive elements after
  // the first one.
  unsigned ExpectedElt = Imm;
  for (unsigned i = 1; i < NumElts; ++i) {
    // Increment the expected index.  If it wraps around, it may still be
    // a VEXT but the source vectors must be swapped.
    ExpectedElt += 1;
    if (ExpectedElt == NumElts * 2) {
      ExpectedElt = 0;
      ReverseVEXT = true;
    }

    if (M[i] < 0) continue; // ignore UNDEF indices
    if (ExpectedElt != static_cast<unsigned>(M[i]))
      return false;
  }

  // Adjust the index value if the source operands will be swapped.
  if (ReverseVEXT)
    Imm -= NumElts;

  return true;
}

/// isVREVMask - Check if a vector shuffle corresponds to a VREV
/// instruction with the specified blocksize.  (The order of the elements
/// within each block of the vector is reversed.)
static bool isVREVMask(const SmallVectorImpl<int> &M, EVT VT,
                       unsigned BlockSize) {
  assert((BlockSize==16 || BlockSize==32 || BlockSize==64) &&
         "Only possible block sizes for VREV are: 16, 32, 64");

  unsigned EltSz = VT.getVectorElementType().getSizeInBits();
  if (EltSz == 64)
    return false;

  unsigned NumElts = VT.getVectorNumElements();
  unsigned BlockElts = M[0] + 1;
  // If the first shuffle index is UNDEF, be optimistic.
  if (M[0] < 0)
    BlockElts = BlockSize / EltSz;

  if (BlockSize <= EltSz || BlockSize != BlockElts * EltSz)
    return false;

  for (unsigned i = 0; i < NumElts; ++i) {
    if (M[i] < 0) continue; // ignore UNDEF indices
    if ((unsigned) M[i] != (i - i%BlockElts) + (BlockElts - 1 - i%BlockElts))
      return false;
  }

  return true;
}

static bool isVTRNMask(const SmallVectorImpl<int> &M, EVT VT,
                       unsigned &WhichResult) {
  unsigned EltSz = VT.getVectorElementType().getSizeInBits();
  if (EltSz == 64)
    return false;

  unsigned NumElts = VT.getVectorNumElements();
  WhichResult = (M[0] == 0 ? 0 : 1);
  for (unsigned i = 0; i < NumElts; i += 2) {
    if ((M[i] >= 0 && (unsigned) M[i] != i + WhichResult) ||
        (M[i+1] >= 0 && (unsigned) M[i+1] != i + NumElts + WhichResult))
      return false;
  }
  return true;
}

/// isVTRN_v_undef_Mask - Special case of isVTRNMask for canonical form of
/// "vector_shuffle v, v", i.e., "vector_shuffle v, undef".
/// Mask is e.g., <0, 0, 2, 2> instead of <0, 4, 2, 6>.
static bool isVTRN_v_undef_Mask(const SmallVectorImpl<int> &M, EVT VT,
                                unsigned &WhichResult) {
  unsigned EltSz = VT.getVectorElementType().getSizeInBits();
  if (EltSz == 64)
    return false;

  unsigned NumElts = VT.getVectorNumElements();
  WhichResult = (M[0] == 0 ? 0 : 1);
  for (unsigned i = 0; i < NumElts; i += 2) {
    if ((M[i] >= 0 && (unsigned) M[i] != i + WhichResult) ||
        (M[i+1] >= 0 && (unsigned) M[i+1] != i + WhichResult))
      return false;
  }
  return true;
}

static bool isVUZPMask(const SmallVectorImpl<int> &M, EVT VT,
                       unsigned &WhichResult) {
  unsigned EltSz = VT.getVectorElementType().getSizeInBits();
  if (EltSz == 64)
    return false;

  unsigned NumElts = VT.getVectorNumElements();
  WhichResult = (M[0] == 0 ? 0 : 1);
  for (unsigned i = 0; i != NumElts; ++i) {
    if (M[i] < 0) continue; // ignore UNDEF indices
    if ((unsigned) M[i] != 2 * i + WhichResult)
      return false;
  }

  // VUZP.32 for 64-bit vectors is a pseudo-instruction alias for VTRN.32.
  if (VT.is64BitVector() && EltSz == 32)
    return false;

  return true;
}

/// isVUZP_v_undef_Mask - Special case of isVUZPMask for canonical form of
/// "vector_shuffle v, v", i.e., "vector_shuffle v, undef".
/// Mask is e.g., <0, 2, 0, 2> instead of <0, 2, 4, 6>,
static bool isVUZP_v_undef_Mask(const SmallVectorImpl<int> &M, EVT VT,
                                unsigned &WhichResult) {
  unsigned EltSz = VT.getVectorElementType().getSizeInBits();
  if (EltSz == 64)
    return false;

  unsigned Half = VT.getVectorNumElements() / 2;
  WhichResult = (M[0] == 0 ? 0 : 1);
  for (unsigned j = 0; j != 2; ++j) {
    unsigned Idx = WhichResult;
    for (unsigned i = 0; i != Half; ++i) {
      int MIdx = M[i + j * Half];
      if (MIdx >= 0 && (unsigned) MIdx != Idx)
        return false;
      Idx += 2;
    }
  }

  // VUZP.32 for 64-bit vectors is a pseudo-instruction alias for VTRN.32.
  if (VT.is64BitVector() && EltSz == 32)
    return false;

  return true;
}

static bool isVZIPMask(const SmallVectorImpl<int> &M, EVT VT,
                       unsigned &WhichResult) {
  unsigned EltSz = VT.getVectorElementType().getSizeInBits();
  if (EltSz == 64)
    return false;

  unsigned NumElts = VT.getVectorNumElements();
  WhichResult = (M[0] == 0 ? 0 : 1);
  unsigned Idx = WhichResult * NumElts / 2;
  for (unsigned i = 0; i != NumElts; i += 2) {
    if ((M[i] >= 0 && (unsigned) M[i] != Idx) ||
        (M[i+1] >= 0 && (unsigned) M[i+1] != Idx + NumElts))
      return false;
    Idx += 1;
  }

  // VZIP.32 for 64-bit vectors is a pseudo-instruction alias for VTRN.32.
  if (VT.is64BitVector() && EltSz == 32)
    return false;

  return true;
}

/// isVZIP_v_undef_Mask - Special case of isVZIPMask for canonical form of
/// "vector_shuffle v, v", i.e., "vector_shuffle v, undef".
/// Mask is e.g., <0, 0, 1, 1> instead of <0, 4, 1, 5>.
static bool isVZIP_v_undef_Mask(const SmallVectorImpl<int> &M, EVT VT,
                                unsigned &WhichResult) {
  unsigned EltSz = VT.getVectorElementType().getSizeInBits();
  if (EltSz == 64)
    return false;

  unsigned NumElts = VT.getVectorNumElements();
  WhichResult = (M[0] == 0 ? 0 : 1);
  unsigned Idx = WhichResult * NumElts / 2;
  for (unsigned i = 0; i != NumElts; i += 2) {
    if ((M[i] >= 0 && (unsigned) M[i] != Idx) ||
        (M[i+1] >= 0 && (unsigned) M[i+1] != Idx))
      return false;
    Idx += 1;
  }

  // VZIP.32 for 64-bit vectors is a pseudo-instruction alias for VTRN.32.
  if (VT.is64BitVector() && EltSz == 32)
    return false;

  return true;
}

// If N is an integer constant that can be moved into a register in one
// instruction, return an SDValue of such a constant (will become a MOV
// instruction).  Otherwise return null.
static SDValue IsSingleInstrConstant(SDValue N, SelectionDAG &DAG,
                                     const ARMSubtarget *ST, DebugLoc dl) {
  uint64_t Val;
  if (!isa<ConstantSDNode>(N))
    return SDValue();
  Val = cast<ConstantSDNode>(N)->getZExtValue();

  if (ST->isThumb1Only()) {
    if (Val <= 255 || ~Val <= 255)
      return DAG.getConstant(Val, MVT::i32);
  } else {
    if (ARM_AM::getSOImmVal(Val) != -1 || ARM_AM::getSOImmVal(~Val) != -1)
      return DAG.getConstant(Val, MVT::i32);
  }
  return SDValue();
}

// If this is a case we can't handle, return null and let the default
// expansion code take care of it.
static SDValue LowerBUILD_VECTOR(SDValue Op, SelectionDAG &DAG, 
                                 const ARMSubtarget *ST) {
  BuildVectorSDNode *BVN = cast<BuildVectorSDNode>(Op.getNode());
  DebugLoc dl = Op.getDebugLoc();
  EVT VT = Op.getValueType();

  APInt SplatBits, SplatUndef;
  unsigned SplatBitSize;
  bool HasAnyUndefs;
  if (BVN->isConstantSplat(SplatBits, SplatUndef, SplatBitSize, HasAnyUndefs)) {
    if (SplatBitSize <= 64) {
      // Check if an immediate VMOV works.
      EVT VmovVT;
      SDValue Val = isNEONModifiedImm(SplatBits.getZExtValue(),
                                      SplatUndef.getZExtValue(), SplatBitSize,
                                      DAG, VmovVT, VT.is128BitVector(), true);
      if (Val.getNode()) {
        SDValue Vmov = DAG.getNode(ARMISD::VMOVIMM, dl, VmovVT, Val);
        return DAG.getNode(ISD::BIT_CONVERT, dl, VT, Vmov);
      }

      // Try an immediate VMVN.
      uint64_t NegatedImm = (SplatBits.getZExtValue() ^
                             ((1LL << SplatBitSize) - 1));
      Val = isNEONModifiedImm(NegatedImm,
                                      SplatUndef.getZExtValue(), SplatBitSize,
                                      DAG, VmovVT, VT.is128BitVector(), false);
      if (Val.getNode()) {
        SDValue Vmov = DAG.getNode(ARMISD::VMVNIMM, dl, VmovVT, Val);
        return DAG.getNode(ISD::BIT_CONVERT, dl, VT, Vmov);
      }
    }
  }

  // Scan through the operands to see if only one value is used.
  unsigned NumElts = VT.getVectorNumElements();
  bool isOnlyLowElement = true;
  bool usesOnlyOneValue = true;
  bool isConstant = true;
  SDValue Value;
  for (unsigned i = 0; i < NumElts; ++i) {
    SDValue V = Op.getOperand(i);
    if (V.getOpcode() == ISD::UNDEF)
      continue;
    if (i > 0)
      isOnlyLowElement = false;
    if (!isa<ConstantFPSDNode>(V) && !isa<ConstantSDNode>(V))
      isConstant = false;

    if (!Value.getNode())
      Value = V;
    else if (V != Value)
      usesOnlyOneValue = false;
  }

  if (!Value.getNode())
    return DAG.getUNDEF(VT);

  if (isOnlyLowElement)
    return DAG.getNode(ISD::SCALAR_TO_VECTOR, dl, VT, Value);

  unsigned EltSize = VT.getVectorElementType().getSizeInBits();

  if (EnableARMVDUPsplat) {
    // Use VDUP for non-constant splats.  For f32 constant splats, reduce to
    // i32 and try again.
    if (usesOnlyOneValue && EltSize <= 32) {
      if (!isConstant)
        return DAG.getNode(ARMISD::VDUP, dl, VT, Value);
      if (VT.getVectorElementType().isFloatingPoint()) {
        SmallVector<SDValue, 8> Ops;
        for (unsigned i = 0; i < NumElts; ++i)
          Ops.push_back(DAG.getNode(ISD::BIT_CONVERT, dl, MVT::i32, 
                                    Op.getOperand(i)));
        SDValue Val = DAG.getNode(ISD::BUILD_VECTOR, dl, MVT::v4i32, &Ops[0],
                                  NumElts);
        return DAG.getNode(ISD::BIT_CONVERT, dl, VT, 
                           LowerBUILD_VECTOR(Val, DAG, ST));
      }
      SDValue Val = IsSingleInstrConstant(Value, DAG, ST, dl);
      if (Val.getNode())
        return DAG.getNode(ARMISD::VDUP, dl, VT, Val);
    }
  }

  // If all elements are constants and the case above didn't get hit, fall back
  // to the default expansion, which will generate a load from the constant
  // pool.
  if (isConstant)
    return SDValue();

  if (!EnableARMVDUPsplat) {
    // Use VDUP for non-constant splats.
    if (usesOnlyOneValue && EltSize <= 32)
      return DAG.getNode(ARMISD::VDUP, dl, VT, Value);
  }

  // Vectors with 32- or 64-bit elements can be built by directly assigning
  // the subregisters.  Lower it to an ARMISD::BUILD_VECTOR so the operands
  // will be legalized.
  if (EltSize >= 32) {
    // Do the expansion with floating-point types, since that is what the VFP
    // registers are defined to use, and since i64 is not legal.
    EVT EltVT = EVT::getFloatingPointVT(EltSize);
    EVT VecVT = EVT::getVectorVT(*DAG.getContext(), EltVT, NumElts);
    SmallVector<SDValue, 8> Ops;
    for (unsigned i = 0; i < NumElts; ++i)
      Ops.push_back(DAG.getNode(ISD::BIT_CONVERT, dl, EltVT, Op.getOperand(i)));
    SDValue Val = DAG.getNode(ARMISD::BUILD_VECTOR, dl, VecVT, &Ops[0],NumElts);
    return DAG.getNode(ISD::BIT_CONVERT, dl, VT, Val);
  }

  return SDValue();
}

/// isShuffleMaskLegal - Targets can use this to indicate that they only
/// support *some* VECTOR_SHUFFLE operations, those with specific masks.
/// By default, if a target supports the VECTOR_SHUFFLE node, all mask values
/// are assumed to be legal.
bool
ARMTargetLowering::isShuffleMaskLegal(const SmallVectorImpl<int> &M,
                                      EVT VT) const {
  if (VT.getVectorNumElements() == 4 &&
      (VT.is128BitVector() || VT.is64BitVector())) {
    unsigned PFIndexes[4];
    for (unsigned i = 0; i != 4; ++i) {
      if (M[i] < 0)
        PFIndexes[i] = 8;
      else
        PFIndexes[i] = M[i];
    }

    // Compute the index in the perfect shuffle table.
    unsigned PFTableIndex =
      PFIndexes[0]*9*9*9+PFIndexes[1]*9*9+PFIndexes[2]*9+PFIndexes[3];
    unsigned PFEntry = PerfectShuffleTable[PFTableIndex];
    unsigned Cost = (PFEntry >> 30);

    if (Cost <= 4)
      return true;
  }

  bool ReverseVEXT;
  unsigned Imm, WhichResult;

  unsigned EltSize = VT.getVectorElementType().getSizeInBits();
  return (EltSize >= 32 ||
          ShuffleVectorSDNode::isSplatMask(&M[0], VT) ||
          isVREVMask(M, VT, 64) ||
          isVREVMask(M, VT, 32) ||
          isVREVMask(M, VT, 16) ||
          isVEXTMask(M, VT, ReverseVEXT, Imm) ||
          isVTRNMask(M, VT, WhichResult) ||
          isVUZPMask(M, VT, WhichResult) ||
          isVZIPMask(M, VT, WhichResult) ||
          isVTRN_v_undef_Mask(M, VT, WhichResult) ||
          isVUZP_v_undef_Mask(M, VT, WhichResult) ||
          isVZIP_v_undef_Mask(M, VT, WhichResult));
}

/// GeneratePerfectShuffle - Given an entry in the perfect-shuffle table, emit
/// the specified operations to build the shuffle.
static SDValue GeneratePerfectShuffle(unsigned PFEntry, SDValue LHS,
                                      SDValue RHS, SelectionDAG &DAG,
                                      DebugLoc dl) {
  unsigned OpNum = (PFEntry >> 26) & 0x0F;
  unsigned LHSID = (PFEntry >> 13) & ((1 << 13)-1);
  unsigned RHSID = (PFEntry >>  0) & ((1 << 13)-1);

  enum {
    OP_COPY = 0, // Copy, used for things like <u,u,u,3> to say it is <0,1,2,3>
    OP_VREV,
    OP_VDUP0,
    OP_VDUP1,
    OP_VDUP2,
    OP_VDUP3,
    OP_VEXT1,
    OP_VEXT2,
    OP_VEXT3,
    OP_VUZPL, // VUZP, left result
    OP_VUZPR, // VUZP, right result
    OP_VZIPL, // VZIP, left result
    OP_VZIPR, // VZIP, right result
    OP_VTRNL, // VTRN, left result
    OP_VTRNR  // VTRN, right result
  };

  if (OpNum == OP_COPY) {
    if (LHSID == (1*9+2)*9+3) return LHS;
    assert(LHSID == ((4*9+5)*9+6)*9+7 && "Illegal OP_COPY!");
    return RHS;
  }

  SDValue OpLHS, OpRHS;
  OpLHS = GeneratePerfectShuffle(PerfectShuffleTable[LHSID], LHS, RHS, DAG, dl);
  OpRHS = GeneratePerfectShuffle(PerfectShuffleTable[RHSID], LHS, RHS, DAG, dl);
  EVT VT = OpLHS.getValueType();

  switch (OpNum) {
  default: llvm_unreachable("Unknown shuffle opcode!");
  case OP_VREV:
    return DAG.getNode(ARMISD::VREV64, dl, VT, OpLHS);
  case OP_VDUP0:
  case OP_VDUP1:
  case OP_VDUP2:
  case OP_VDUP3:
    return DAG.getNode(ARMISD::VDUPLANE, dl, VT,
                       OpLHS, DAG.getConstant(OpNum-OP_VDUP0, MVT::i32));
  case OP_VEXT1:
  case OP_VEXT2:
  case OP_VEXT3:
    return DAG.getNode(ARMISD::VEXT, dl, VT,
                       OpLHS, OpRHS,
                       DAG.getConstant(OpNum-OP_VEXT1+1, MVT::i32));
  case OP_VUZPL:
  case OP_VUZPR:
    return DAG.getNode(ARMISD::VUZP, dl, DAG.getVTList(VT, VT),
                       OpLHS, OpRHS).getValue(OpNum-OP_VUZPL);
  case OP_VZIPL:
  case OP_VZIPR:
    return DAG.getNode(ARMISD::VZIP, dl, DAG.getVTList(VT, VT),
                       OpLHS, OpRHS).getValue(OpNum-OP_VZIPL);
  case OP_VTRNL:
  case OP_VTRNR:
    return DAG.getNode(ARMISD::VTRN, dl, DAG.getVTList(VT, VT),
                       OpLHS, OpRHS).getValue(OpNum-OP_VTRNL);
  }
}

static SDValue LowerVECTOR_SHUFFLE(SDValue Op, SelectionDAG &DAG) {
  SDValue V1 = Op.getOperand(0);
  SDValue V2 = Op.getOperand(1);
  DebugLoc dl = Op.getDebugLoc();
  EVT VT = Op.getValueType();
  ShuffleVectorSDNode *SVN = cast<ShuffleVectorSDNode>(Op.getNode());
  SmallVector<int, 8> ShuffleMask;

  // Convert shuffles that are directly supported on NEON to target-specific
  // DAG nodes, instead of keeping them as shuffles and matching them again
  // during code selection.  This is more efficient and avoids the possibility
  // of inconsistencies between legalization and selection.
  // FIXME: floating-point vectors should be canonicalized to integer vectors
  // of the same time so that they get CSEd properly.
  SVN->getMask(ShuffleMask);

  unsigned EltSize = VT.getVectorElementType().getSizeInBits();
  if (EltSize <= 32) {
    if (ShuffleVectorSDNode::isSplatMask(&ShuffleMask[0], VT)) {
      int Lane = SVN->getSplatIndex();
      // If this is undef splat, generate it via "just" vdup, if possible.
      if (Lane == -1) Lane = 0;

      if (Lane == 0 && V1.getOpcode() == ISD::SCALAR_TO_VECTOR) {
        return DAG.getNode(ARMISD::VDUP, dl, VT, V1.getOperand(0));
      }
      return DAG.getNode(ARMISD::VDUPLANE, dl, VT, V1,
                         DAG.getConstant(Lane, MVT::i32));
    }

    bool ReverseVEXT;
    unsigned Imm;
    if (isVEXTMask(ShuffleMask, VT, ReverseVEXT, Imm)) {
      if (ReverseVEXT)
        std::swap(V1, V2);
      return DAG.getNode(ARMISD::VEXT, dl, VT, V1, V2,
                         DAG.getConstant(Imm, MVT::i32));
    }

    if (isVREVMask(ShuffleMask, VT, 64))
      return DAG.getNode(ARMISD::VREV64, dl, VT, V1);
    if (isVREVMask(ShuffleMask, VT, 32))
      return DAG.getNode(ARMISD::VREV32, dl, VT, V1);
    if (isVREVMask(ShuffleMask, VT, 16))
      return DAG.getNode(ARMISD::VREV16, dl, VT, V1);

    // Check for Neon shuffles that modify both input vectors in place.
    // If both results are used, i.e., if there are two shuffles with the same
    // source operands and with masks corresponding to both results of one of
    // these operations, DAG memoization will ensure that a single node is
    // used for both shuffles.
    unsigned WhichResult;
    if (isVTRNMask(ShuffleMask, VT, WhichResult))
      return DAG.getNode(ARMISD::VTRN, dl, DAG.getVTList(VT, VT),
                         V1, V2).getValue(WhichResult);
    if (isVUZPMask(ShuffleMask, VT, WhichResult))
      return DAG.getNode(ARMISD::VUZP, dl, DAG.getVTList(VT, VT),
                         V1, V2).getValue(WhichResult);
    if (isVZIPMask(ShuffleMask, VT, WhichResult))
      return DAG.getNode(ARMISD::VZIP, dl, DAG.getVTList(VT, VT),
                         V1, V2).getValue(WhichResult);

    if (isVTRN_v_undef_Mask(ShuffleMask, VT, WhichResult))
      return DAG.getNode(ARMISD::VTRN, dl, DAG.getVTList(VT, VT),
                         V1, V1).getValue(WhichResult);
    if (isVUZP_v_undef_Mask(ShuffleMask, VT, WhichResult))
      return DAG.getNode(ARMISD::VUZP, dl, DAG.getVTList(VT, VT),
                         V1, V1).getValue(WhichResult);
    if (isVZIP_v_undef_Mask(ShuffleMask, VT, WhichResult))
      return DAG.getNode(ARMISD::VZIP, dl, DAG.getVTList(VT, VT),
                         V1, V1).getValue(WhichResult);
  }

  // If the shuffle is not directly supported and it has 4 elements, use
  // the PerfectShuffle-generated table to synthesize it from other shuffles.
  unsigned NumElts = VT.getVectorNumElements();
  if (NumElts == 4) {
    unsigned PFIndexes[4];
    for (unsigned i = 0; i != 4; ++i) {
      if (ShuffleMask[i] < 0)
        PFIndexes[i] = 8;
      else
        PFIndexes[i] = ShuffleMask[i];
    }

    // Compute the index in the perfect shuffle table.
    unsigned PFTableIndex =
      PFIndexes[0]*9*9*9+PFIndexes[1]*9*9+PFIndexes[2]*9+PFIndexes[3];
    unsigned PFEntry = PerfectShuffleTable[PFTableIndex];
    unsigned Cost = (PFEntry >> 30);

    if (Cost <= 4)
      return GeneratePerfectShuffle(PFEntry, V1, V2, DAG, dl);
  }

  // Implement shuffles with 32- or 64-bit elements as ARMISD::BUILD_VECTORs.
  if (EltSize >= 32) {
    // Do the expansion with floating-point types, since that is what the VFP
    // registers are defined to use, and since i64 is not legal.
    EVT EltVT = EVT::getFloatingPointVT(EltSize);
    EVT VecVT = EVT::getVectorVT(*DAG.getContext(), EltVT, NumElts);
    V1 = DAG.getNode(ISD::BIT_CONVERT, dl, VecVT, V1);
    V2 = DAG.getNode(ISD::BIT_CONVERT, dl, VecVT, V2);
    SmallVector<SDValue, 8> Ops;
    for (unsigned i = 0; i < NumElts; ++i) {
      if (ShuffleMask[i] < 0)
        Ops.push_back(DAG.getUNDEF(EltVT));
      else
        Ops.push_back(DAG.getNode(ISD::EXTRACT_VECTOR_ELT, dl, EltVT,
                                  ShuffleMask[i] < (int)NumElts ? V1 : V2,
                                  DAG.getConstant(ShuffleMask[i] & (NumElts-1),
                                                  MVT::i32)));
    }
    SDValue Val = DAG.getNode(ARMISD::BUILD_VECTOR, dl, VecVT, &Ops[0],NumElts);
    return DAG.getNode(ISD::BIT_CONVERT, dl, VT, Val);
  }

  return SDValue();
}

static SDValue LowerEXTRACT_VECTOR_ELT(SDValue Op, SelectionDAG &DAG) {
  EVT VT = Op.getValueType();
  DebugLoc dl = Op.getDebugLoc();
  SDValue Vec = Op.getOperand(0);
  SDValue Lane = Op.getOperand(1);
  assert(VT == MVT::i32 &&
         Vec.getValueType().getVectorElementType().getSizeInBits() < 32 &&
         "unexpected type for custom-lowering vector extract");
  return DAG.getNode(ARMISD::VGETLANEu, dl, MVT::i32, Vec, Lane);
}

static SDValue LowerCONCAT_VECTORS(SDValue Op, SelectionDAG &DAG) {
  // The only time a CONCAT_VECTORS operation can have legal types is when
  // two 64-bit vectors are concatenated to a 128-bit vector.
  assert(Op.getValueType().is128BitVector() && Op.getNumOperands() == 2 &&
         "unexpected CONCAT_VECTORS");
  DebugLoc dl = Op.getDebugLoc();
  SDValue Val = DAG.getUNDEF(MVT::v2f64);
  SDValue Op0 = Op.getOperand(0);
  SDValue Op1 = Op.getOperand(1);
  if (Op0.getOpcode() != ISD::UNDEF)
    Val = DAG.getNode(ISD::INSERT_VECTOR_ELT, dl, MVT::v2f64, Val,
                      DAG.getNode(ISD::BIT_CONVERT, dl, MVT::f64, Op0),
                      DAG.getIntPtrConstant(0));
  if (Op1.getOpcode() != ISD::UNDEF)
    Val = DAG.getNode(ISD::INSERT_VECTOR_ELT, dl, MVT::v2f64, Val,
                      DAG.getNode(ISD::BIT_CONVERT, dl, MVT::f64, Op1),
                      DAG.getIntPtrConstant(1));
  return DAG.getNode(ISD::BIT_CONVERT, dl, Op.getValueType(), Val);
}

/// SkipExtension - For a node that is either a SIGN_EXTEND, ZERO_EXTEND, or
/// an extending load, return the unextended value.
static SDValue SkipExtension(SDNode *N, SelectionDAG &DAG) {
  if (N->getOpcode() == ISD::SIGN_EXTEND || N->getOpcode() == ISD::ZERO_EXTEND)
    return N->getOperand(0);
  LoadSDNode *LD = cast<LoadSDNode>(N);
  return DAG.getLoad(LD->getMemoryVT(), N->getDebugLoc(), LD->getChain(),
                     LD->getBasePtr(), LD->getSrcValue(),
                     LD->getSrcValueOffset(), LD->isVolatile(),
                     LD->isNonTemporal(), LD->getAlignment());
}

static SDValue LowerMUL(SDValue Op, SelectionDAG &DAG) {
  // Multiplications are only custom-lowered for 128-bit vectors so that
  // VMULL can be detected.  Otherwise v2i64 multiplications are not legal.
  EVT VT = Op.getValueType();
  assert(VT.is128BitVector() && "unexpected type for custom-lowering ISD::MUL");
  SDNode *N0 = Op.getOperand(0).getNode();
  SDNode *N1 = Op.getOperand(1).getNode();
  unsigned NewOpc = 0;
  if ((N0->getOpcode() == ISD::SIGN_EXTEND || ISD::isSEXTLoad(N0)) &&
      (N1->getOpcode() == ISD::SIGN_EXTEND || ISD::isSEXTLoad(N1))) {
    NewOpc = ARMISD::VMULLs;
  } else if ((N0->getOpcode() == ISD::ZERO_EXTEND || ISD::isZEXTLoad(N0)) &&
             (N1->getOpcode() == ISD::ZERO_EXTEND || ISD::isZEXTLoad(N1))) {
    NewOpc = ARMISD::VMULLu;
  } else if (VT.getSimpleVT().SimpleTy == MVT::v2i64) {
    // Fall through to expand this.  It is not legal.
    return SDValue();
  } else {
    // Other vector multiplications are legal.
    return Op;
  }

  // Legalize to a VMULL instruction.
  DebugLoc DL = Op.getDebugLoc();
  SDValue Op0 = SkipExtension(N0, DAG);
  SDValue Op1 = SkipExtension(N1, DAG);

  assert(Op0.getValueType().is64BitVector() &&
         Op1.getValueType().is64BitVector() &&
         "unexpected types for extended operands to VMULL");
  return DAG.getNode(NewOpc, DL, VT, Op0, Op1);
}

SDValue ARMTargetLowering::LowerOperation(SDValue Op, SelectionDAG &DAG) const {
  switch (Op.getOpcode()) {
  default: llvm_unreachable("Don't know how to custom lower this!");
  case ISD::ConstantPool:  return LowerConstantPool(Op, DAG);
  case ISD::BlockAddress:  return LowerBlockAddress(Op, DAG);
  case ISD::GlobalAddress:
    return Subtarget->isTargetDarwin() ? LowerGlobalAddressDarwin(Op, DAG) :
      LowerGlobalAddressELF(Op, DAG);
  case ISD::GlobalTLSAddress:   return LowerGlobalTLSAddress(Op, DAG);
  case ISD::SELECT:        return LowerSELECT(Op, DAG);
  case ISD::SELECT_CC:     return LowerSELECT_CC(Op, DAG);
  case ISD::BR_CC:         return LowerBR_CC(Op, DAG);
  case ISD::BR_JT:         return LowerBR_JT(Op, DAG);
  case ISD::VASTART:       return LowerVASTART(Op, DAG);
  case ISD::MEMBARRIER:    return LowerMEMBARRIER(Op, DAG, Subtarget);
  case ISD::SINT_TO_FP:
  case ISD::UINT_TO_FP:    return LowerINT_TO_FP(Op, DAG);
  case ISD::FP_TO_SINT:
  case ISD::FP_TO_UINT:    return LowerFP_TO_INT(Op, DAG);
  case ISD::FCOPYSIGN:     return LowerFCOPYSIGN(Op, DAG);
  case ISD::RETURNADDR:    return LowerRETURNADDR(Op, DAG);
  case ISD::FRAMEADDR:     return LowerFRAMEADDR(Op, DAG);
  case ISD::GLOBAL_OFFSET_TABLE: return LowerGLOBAL_OFFSET_TABLE(Op, DAG);
  case ISD::EH_SJLJ_SETJMP: return LowerEH_SJLJ_SETJMP(Op, DAG);
  case ISD::EH_SJLJ_LONGJMP: return LowerEH_SJLJ_LONGJMP(Op, DAG);
  case ISD::INTRINSIC_WO_CHAIN: return LowerINTRINSIC_WO_CHAIN(Op, DAG,
                                                               Subtarget);
  case ISD::BIT_CONVERT:   return ExpandBIT_CONVERT(Op.getNode(), DAG);
  case ISD::SHL:
  case ISD::SRL:
  case ISD::SRA:           return LowerShift(Op.getNode(), DAG, Subtarget);
  case ISD::SHL_PARTS:     return LowerShiftLeftParts(Op, DAG);
  case ISD::SRL_PARTS:
  case ISD::SRA_PARTS:     return LowerShiftRightParts(Op, DAG);
  case ISD::CTTZ:          return LowerCTTZ(Op.getNode(), DAG, Subtarget);
  case ISD::VSETCC:        return LowerVSETCC(Op, DAG);
  case ISD::BUILD_VECTOR:  return LowerBUILD_VECTOR(Op, DAG, Subtarget);
  case ISD::VECTOR_SHUFFLE: return LowerVECTOR_SHUFFLE(Op, DAG);
  case ISD::EXTRACT_VECTOR_ELT: return LowerEXTRACT_VECTOR_ELT(Op, DAG);
  case ISD::CONCAT_VECTORS: return LowerCONCAT_VECTORS(Op, DAG);
  case ISD::FLT_ROUNDS_:   return LowerFLT_ROUNDS_(Op, DAG);
  case ISD::MUL:           return LowerMUL(Op, DAG);
  }
  return SDValue();
}

/// ReplaceNodeResults - Replace the results of node with an illegal result
/// type with new values built out of custom code.
void ARMTargetLowering::ReplaceNodeResults(SDNode *N,
                                           SmallVectorImpl<SDValue>&Results,
                                           SelectionDAG &DAG) const {
  SDValue Res;
  switch (N->getOpcode()) {
  default:
    llvm_unreachable("Don't know how to custom expand this!");
    break;
  case ISD::BIT_CONVERT:
    Res = ExpandBIT_CONVERT(N, DAG);
    break;
  case ISD::SRL:
  case ISD::SRA:
    Res = LowerShift(N, DAG, Subtarget);
    break;
  }
  if (Res.getNode())
    Results.push_back(Res);
}

//===----------------------------------------------------------------------===//
//                           ARM Scheduler Hooks
//===----------------------------------------------------------------------===//

MachineBasicBlock *
ARMTargetLowering::EmitAtomicCmpSwap(MachineInstr *MI,
                                     MachineBasicBlock *BB,
                                     unsigned Size) const {
  unsigned dest    = MI->getOperand(0).getReg();
  unsigned ptr     = MI->getOperand(1).getReg();
  unsigned oldval  = MI->getOperand(2).getReg();
  unsigned newval  = MI->getOperand(3).getReg();
  unsigned scratch = BB->getParent()->getRegInfo()
    .createVirtualRegister(ARM::GPRRegisterClass);
  const TargetInstrInfo *TII = getTargetMachine().getInstrInfo();
  DebugLoc dl = MI->getDebugLoc();
  bool isThumb2 = Subtarget->isThumb2();

  unsigned ldrOpc, strOpc;
  switch (Size) {
  default: llvm_unreachable("unsupported size for AtomicCmpSwap!");
  case 1:
    ldrOpc = isThumb2 ? ARM::t2LDREXB : ARM::LDREXB;
    strOpc = isThumb2 ? ARM::t2LDREXB : ARM::STREXB;
    break;
  case 2:
    ldrOpc = isThumb2 ? ARM::t2LDREXH : ARM::LDREXH;
    strOpc = isThumb2 ? ARM::t2STREXH : ARM::STREXH;
    break;
  case 4:
    ldrOpc = isThumb2 ? ARM::t2LDREX : ARM::LDREX;
    strOpc = isThumb2 ? ARM::t2STREX : ARM::STREX;
    break;
  }

  MachineFunction *MF = BB->getParent();
  const BasicBlock *LLVM_BB = BB->getBasicBlock();
  MachineFunction::iterator It = BB;
  ++It; // insert the new blocks after the current block

  MachineBasicBlock *loop1MBB = MF->CreateMachineBasicBlock(LLVM_BB);
  MachineBasicBlock *loop2MBB = MF->CreateMachineBasicBlock(LLVM_BB);
  MachineBasicBlock *exitMBB = MF->CreateMachineBasicBlock(LLVM_BB);
  MF->insert(It, loop1MBB);
  MF->insert(It, loop2MBB);
  MF->insert(It, exitMBB);

  // Transfer the remainder of BB and its successor edges to exitMBB.
  exitMBB->splice(exitMBB->begin(), BB,
                  llvm::next(MachineBasicBlock::iterator(MI)),
                  BB->end());
  exitMBB->transferSuccessorsAndUpdatePHIs(BB);

  //  thisMBB:
  //   ...
  //   fallthrough --> loop1MBB
  BB->addSuccessor(loop1MBB);

  // loop1MBB:
  //   ldrex dest, [ptr]
  //   cmp dest, oldval
  //   bne exitMBB
  BB = loop1MBB;
  AddDefaultPred(BuildMI(BB, dl, TII->get(ldrOpc), dest).addReg(ptr));
  AddDefaultPred(BuildMI(BB, dl, TII->get(isThumb2 ? ARM::t2CMPrr : ARM::CMPrr))
                 .addReg(dest).addReg(oldval));
  BuildMI(BB, dl, TII->get(isThumb2 ? ARM::t2Bcc : ARM::Bcc))
    .addMBB(exitMBB).addImm(ARMCC::NE).addReg(ARM::CPSR);
  BB->addSuccessor(loop2MBB);
  BB->addSuccessor(exitMBB);

  // loop2MBB:
  //   strex scratch, newval, [ptr]
  //   cmp scratch, #0
  //   bne loop1MBB
  BB = loop2MBB;
  AddDefaultPred(BuildMI(BB, dl, TII->get(strOpc), scratch).addReg(newval)
                 .addReg(ptr));
  AddDefaultPred(BuildMI(BB, dl, TII->get(isThumb2 ? ARM::t2CMPri : ARM::CMPri))
                 .addReg(scratch).addImm(0));
  BuildMI(BB, dl, TII->get(isThumb2 ? ARM::t2Bcc : ARM::Bcc))
    .addMBB(loop1MBB).addImm(ARMCC::NE).addReg(ARM::CPSR);
  BB->addSuccessor(loop1MBB);
  BB->addSuccessor(exitMBB);

  //  exitMBB:
  //   ...
  BB = exitMBB;

  MI->eraseFromParent();   // The instruction is gone now.

  return BB;
}

MachineBasicBlock *
ARMTargetLowering::EmitAtomicBinary(MachineInstr *MI, MachineBasicBlock *BB,
                                    unsigned Size, unsigned BinOpcode) const {
  // This also handles ATOMIC_SWAP, indicated by BinOpcode==0.
  const TargetInstrInfo *TII = getTargetMachine().getInstrInfo();

  const BasicBlock *LLVM_BB = BB->getBasicBlock();
  MachineFunction *MF = BB->getParent();
  MachineFunction::iterator It = BB;
  ++It;

  unsigned dest = MI->getOperand(0).getReg();
  unsigned ptr = MI->getOperand(1).getReg();
  unsigned incr = MI->getOperand(2).getReg();
  DebugLoc dl = MI->getDebugLoc();

  bool isThumb2 = Subtarget->isThumb2();
  unsigned ldrOpc, strOpc;
  switch (Size) {
  default: llvm_unreachable("unsupported size for AtomicCmpSwap!");
  case 1:
    ldrOpc = isThumb2 ? ARM::t2LDREXB : ARM::LDREXB;
    strOpc = isThumb2 ? ARM::t2STREXB : ARM::STREXB;
    break;
  case 2:
    ldrOpc = isThumb2 ? ARM::t2LDREXH : ARM::LDREXH;
    strOpc = isThumb2 ? ARM::t2STREXH : ARM::STREXH;
    break;
  case 4:
    ldrOpc = isThumb2 ? ARM::t2LDREX : ARM::LDREX;
    strOpc = isThumb2 ? ARM::t2STREX : ARM::STREX;
    break;
  }

  MachineBasicBlock *loopMBB = MF->CreateMachineBasicBlock(LLVM_BB);
  MachineBasicBlock *exitMBB = MF->CreateMachineBasicBlock(LLVM_BB);
  MF->insert(It, loopMBB);
  MF->insert(It, exitMBB);

  // Transfer the remainder of BB and its successor edges to exitMBB.
  exitMBB->splice(exitMBB->begin(), BB,
                  llvm::next(MachineBasicBlock::iterator(MI)),
                  BB->end());
  exitMBB->transferSuccessorsAndUpdatePHIs(BB);

  MachineRegisterInfo &RegInfo = MF->getRegInfo();
  unsigned scratch = RegInfo.createVirtualRegister(ARM::GPRRegisterClass);
  unsigned scratch2 = (!BinOpcode) ? incr :
    RegInfo.createVirtualRegister(ARM::GPRRegisterClass);

  //  thisMBB:
  //   ...
  //   fallthrough --> loopMBB
  BB->addSuccessor(loopMBB);

  //  loopMBB:
  //   ldrex dest, ptr
  //   <binop> scratch2, dest, incr
  //   strex scratch, scratch2, ptr
  //   cmp scratch, #0
  //   bne- loopMBB
  //   fallthrough --> exitMBB
  BB = loopMBB;
  AddDefaultPred(BuildMI(BB, dl, TII->get(ldrOpc), dest).addReg(ptr));
  if (BinOpcode) {
    // operand order needs to go the other way for NAND
    if (BinOpcode == ARM::BICrr || BinOpcode == ARM::t2BICrr)
      AddDefaultPred(BuildMI(BB, dl, TII->get(BinOpcode), scratch2).
                     addReg(incr).addReg(dest)).addReg(0);
    else
      AddDefaultPred(BuildMI(BB, dl, TII->get(BinOpcode), scratch2).
                     addReg(dest).addReg(incr)).addReg(0);
  }

  AddDefaultPred(BuildMI(BB, dl, TII->get(strOpc), scratch).addReg(scratch2)
                 .addReg(ptr));
  AddDefaultPred(BuildMI(BB, dl, TII->get(isThumb2 ? ARM::t2CMPri : ARM::CMPri))
                 .addReg(scratch).addImm(0));
  BuildMI(BB, dl, TII->get(isThumb2 ? ARM::t2Bcc : ARM::Bcc))
    .addMBB(loopMBB).addImm(ARMCC::NE).addReg(ARM::CPSR);

  BB->addSuccessor(loopMBB);
  BB->addSuccessor(exitMBB);

  //  exitMBB:
  //   ...
  BB = exitMBB;

  MI->eraseFromParent();   // The instruction is gone now.

  return BB;
}

static
MachineBasicBlock *OtherSucc(MachineBasicBlock *MBB, MachineBasicBlock *Succ) {
  for (MachineBasicBlock::succ_iterator I = MBB->succ_begin(),
       E = MBB->succ_end(); I != E; ++I)
    if (*I != Succ)
      return *I;
  llvm_unreachable("Expecting a BB with two successors!");
}

MachineBasicBlock *
ARMTargetLowering::EmitInstrWithCustomInserter(MachineInstr *MI,
                                               MachineBasicBlock *BB) const {
  const TargetInstrInfo *TII = getTargetMachine().getInstrInfo();
  DebugLoc dl = MI->getDebugLoc();
  bool isThumb2 = Subtarget->isThumb2();
  switch (MI->getOpcode()) {
  default:
    MI->dump();
    llvm_unreachable("Unexpected instr type to insert");

  case ARM::ATOMIC_LOAD_ADD_I8:
     return EmitAtomicBinary(MI, BB, 1, isThumb2 ? ARM::t2ADDrr : ARM::ADDrr);
  case ARM::ATOMIC_LOAD_ADD_I16:
     return EmitAtomicBinary(MI, BB, 2, isThumb2 ? ARM::t2ADDrr : ARM::ADDrr);
  case ARM::ATOMIC_LOAD_ADD_I32:
     return EmitAtomicBinary(MI, BB, 4, isThumb2 ? ARM::t2ADDrr : ARM::ADDrr);

  case ARM::ATOMIC_LOAD_AND_I8:
     return EmitAtomicBinary(MI, BB, 1, isThumb2 ? ARM::t2ANDrr : ARM::ANDrr);
  case ARM::ATOMIC_LOAD_AND_I16:
     return EmitAtomicBinary(MI, BB, 2, isThumb2 ? ARM::t2ANDrr : ARM::ANDrr);
  case ARM::ATOMIC_LOAD_AND_I32:
     return EmitAtomicBinary(MI, BB, 4, isThumb2 ? ARM::t2ANDrr : ARM::ANDrr);

  case ARM::ATOMIC_LOAD_OR_I8:
     return EmitAtomicBinary(MI, BB, 1, isThumb2 ? ARM::t2ORRrr : ARM::ORRrr);
  case ARM::ATOMIC_LOAD_OR_I16:
     return EmitAtomicBinary(MI, BB, 2, isThumb2 ? ARM::t2ORRrr : ARM::ORRrr);
  case ARM::ATOMIC_LOAD_OR_I32:
     return EmitAtomicBinary(MI, BB, 4, isThumb2 ? ARM::t2ORRrr : ARM::ORRrr);

  case ARM::ATOMIC_LOAD_XOR_I8:
     return EmitAtomicBinary(MI, BB, 1, isThumb2 ? ARM::t2EORrr : ARM::EORrr);
  case ARM::ATOMIC_LOAD_XOR_I16:
     return EmitAtomicBinary(MI, BB, 2, isThumb2 ? ARM::t2EORrr : ARM::EORrr);
  case ARM::ATOMIC_LOAD_XOR_I32:
     return EmitAtomicBinary(MI, BB, 4, isThumb2 ? ARM::t2EORrr : ARM::EORrr);

  case ARM::ATOMIC_LOAD_NAND_I8:
     return EmitAtomicBinary(MI, BB, 1, isThumb2 ? ARM::t2BICrr : ARM::BICrr);
  case ARM::ATOMIC_LOAD_NAND_I16:
     return EmitAtomicBinary(MI, BB, 2, isThumb2 ? ARM::t2BICrr : ARM::BICrr);
  case ARM::ATOMIC_LOAD_NAND_I32:
     return EmitAtomicBinary(MI, BB, 4, isThumb2 ? ARM::t2BICrr : ARM::BICrr);

  case ARM::ATOMIC_LOAD_SUB_I8:
     return EmitAtomicBinary(MI, BB, 1, isThumb2 ? ARM::t2SUBrr : ARM::SUBrr);
  case ARM::ATOMIC_LOAD_SUB_I16:
     return EmitAtomicBinary(MI, BB, 2, isThumb2 ? ARM::t2SUBrr : ARM::SUBrr);
  case ARM::ATOMIC_LOAD_SUB_I32:
     return EmitAtomicBinary(MI, BB, 4, isThumb2 ? ARM::t2SUBrr : ARM::SUBrr);

  case ARM::ATOMIC_SWAP_I8:  return EmitAtomicBinary(MI, BB, 1, 0);
  case ARM::ATOMIC_SWAP_I16: return EmitAtomicBinary(MI, BB, 2, 0);
  case ARM::ATOMIC_SWAP_I32: return EmitAtomicBinary(MI, BB, 4, 0);

  case ARM::ATOMIC_CMP_SWAP_I8:  return EmitAtomicCmpSwap(MI, BB, 1);
  case ARM::ATOMIC_CMP_SWAP_I16: return EmitAtomicCmpSwap(MI, BB, 2);
  case ARM::ATOMIC_CMP_SWAP_I32: return EmitAtomicCmpSwap(MI, BB, 4);

  case ARM::tMOVCCr_pseudo: {
    // To "insert" a SELECT_CC instruction, we actually have to insert the
    // diamond control-flow pattern.  The incoming instruction knows the
    // destination vreg to set, the condition code register to branch on, the
    // true/false values to select between, and a branch opcode to use.
    const BasicBlock *LLVM_BB = BB->getBasicBlock();
    MachineFunction::iterator It = BB;
    ++It;

    //  thisMBB:
    //  ...
    //   TrueVal = ...
    //   cmpTY ccX, r1, r2
    //   bCC copy1MBB
    //   fallthrough --> copy0MBB
    MachineBasicBlock *thisMBB  = BB;
    MachineFunction *F = BB->getParent();
    MachineBasicBlock *copy0MBB = F->CreateMachineBasicBlock(LLVM_BB);
    MachineBasicBlock *sinkMBB  = F->CreateMachineBasicBlock(LLVM_BB);
    F->insert(It, copy0MBB);
    F->insert(It, sinkMBB);

    // Transfer the remainder of BB and its successor edges to sinkMBB.
    sinkMBB->splice(sinkMBB->begin(), BB,
                    llvm::next(MachineBasicBlock::iterator(MI)),
                    BB->end());
    sinkMBB->transferSuccessorsAndUpdatePHIs(BB);

    BB->addSuccessor(copy0MBB);
    BB->addSuccessor(sinkMBB);

    BuildMI(BB, dl, TII->get(ARM::tBcc)).addMBB(sinkMBB)
      .addImm(MI->getOperand(3).getImm()).addReg(MI->getOperand(4).getReg());

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
    BuildMI(*BB, BB->begin(), dl,
            TII->get(ARM::PHI), MI->getOperand(0).getReg())
      .addReg(MI->getOperand(1).getReg()).addMBB(copy0MBB)
      .addReg(MI->getOperand(2).getReg()).addMBB(thisMBB);

    MI->eraseFromParent();   // The pseudo instruction is gone now.
    return BB;
  }

  case ARM::BCCi64:
  case ARM::BCCZi64: {
    // Compare both parts that make up the double comparison separately for
    // equality.
    bool RHSisZero = MI->getOpcode() == ARM::BCCZi64;

    unsigned LHS1 = MI->getOperand(1).getReg();
    unsigned LHS2 = MI->getOperand(2).getReg();
    if (RHSisZero) {
      AddDefaultPred(BuildMI(BB, dl,
                             TII->get(isThumb2 ? ARM::t2CMPri : ARM::CMPri))
                     .addReg(LHS1).addImm(0));
      BuildMI(BB, dl, TII->get(isThumb2 ? ARM::t2CMPri : ARM::CMPri))
        .addReg(LHS2).addImm(0)
        .addImm(ARMCC::EQ).addReg(ARM::CPSR);
    } else {
      unsigned RHS1 = MI->getOperand(3).getReg();
      unsigned RHS2 = MI->getOperand(4).getReg();
      AddDefaultPred(BuildMI(BB, dl,
                             TII->get(isThumb2 ? ARM::t2CMPrr : ARM::CMPrr))
                     .addReg(LHS1).addReg(RHS1));
      BuildMI(BB, dl, TII->get(isThumb2 ? ARM::t2CMPrr : ARM::CMPrr))
        .addReg(LHS2).addReg(RHS2)
        .addImm(ARMCC::EQ).addReg(ARM::CPSR);
    }

    MachineBasicBlock *destMBB = MI->getOperand(RHSisZero ? 3 : 5).getMBB();
    MachineBasicBlock *exitMBB = OtherSucc(BB, destMBB);
    if (MI->getOperand(0).getImm() == ARMCC::NE)
      std::swap(destMBB, exitMBB);

    BuildMI(BB, dl, TII->get(isThumb2 ? ARM::t2Bcc : ARM::Bcc))
      .addMBB(destMBB).addImm(ARMCC::EQ).addReg(ARM::CPSR);
    BuildMI(BB, dl, TII->get(isThumb2 ? ARM::t2B : ARM::B))
      .addMBB(exitMBB);

    MI->eraseFromParent();   // The pseudo instruction is gone now.
    return BB;
  }
  }
}

//===----------------------------------------------------------------------===//
//                           ARM Optimization Hooks
//===----------------------------------------------------------------------===//

static
SDValue combineSelectAndUse(SDNode *N, SDValue Slct, SDValue OtherOp,
                            TargetLowering::DAGCombinerInfo &DCI) {
  SelectionDAG &DAG = DCI.DAG;
  const TargetLowering &TLI = DAG.getTargetLoweringInfo();
  EVT VT = N->getValueType(0);
  unsigned Opc = N->getOpcode();
  bool isSlctCC = Slct.getOpcode() == ISD::SELECT_CC;
  SDValue LHS = isSlctCC ? Slct.getOperand(2) : Slct.getOperand(1);
  SDValue RHS = isSlctCC ? Slct.getOperand(3) : Slct.getOperand(2);
  ISD::CondCode CC = ISD::SETCC_INVALID;

  if (isSlctCC) {
    CC = cast<CondCodeSDNode>(Slct.getOperand(4))->get();
  } else {
    SDValue CCOp = Slct.getOperand(0);
    if (CCOp.getOpcode() == ISD::SETCC)
      CC = cast<CondCodeSDNode>(CCOp.getOperand(2))->get();
  }

  bool DoXform = false;
  bool InvCC = false;
  assert ((Opc == ISD::ADD || (Opc == ISD::SUB && Slct == N->getOperand(1))) &&
          "Bad input!");

  if (LHS.getOpcode() == ISD::Constant &&
      cast<ConstantSDNode>(LHS)->isNullValue()) {
    DoXform = true;
  } else if (CC != ISD::SETCC_INVALID &&
             RHS.getOpcode() == ISD::Constant &&
             cast<ConstantSDNode>(RHS)->isNullValue()) {
    std::swap(LHS, RHS);
    SDValue Op0 = Slct.getOperand(0);
    EVT OpVT = isSlctCC ? Op0.getValueType() :
                          Op0.getOperand(0).getValueType();
    bool isInt = OpVT.isInteger();
    CC = ISD::getSetCCInverse(CC, isInt);

    if (!TLI.isCondCodeLegal(CC, OpVT))
      return SDValue();         // Inverse operator isn't legal.

    DoXform = true;
    InvCC = true;
  }

  if (DoXform) {
    SDValue Result = DAG.getNode(Opc, RHS.getDebugLoc(), VT, OtherOp, RHS);
    if (isSlctCC)
      return DAG.getSelectCC(N->getDebugLoc(), OtherOp, Result,
                             Slct.getOperand(0), Slct.getOperand(1), CC);
    SDValue CCOp = Slct.getOperand(0);
    if (InvCC)
      CCOp = DAG.getSetCC(Slct.getDebugLoc(), CCOp.getValueType(),
                          CCOp.getOperand(0), CCOp.getOperand(1), CC);
    return DAG.getNode(ISD::SELECT, N->getDebugLoc(), VT,
                       CCOp, OtherOp, Result);
  }
  return SDValue();
}

/// PerformADDCombineWithOperands - Try DAG combinations for an ADD with
/// operands N0 and N1.  This is a helper for PerformADDCombine that is
/// called with the default operands, and if that fails, with commuted
/// operands.
static SDValue PerformADDCombineWithOperands(SDNode *N, SDValue N0, SDValue N1,
                                         TargetLowering::DAGCombinerInfo &DCI) {
  // fold (add (select cc, 0, c), x) -> (select cc, x, (add, x, c))
  if (N0.getOpcode() == ISD::SELECT && N0.getNode()->hasOneUse()) {
    SDValue Result = combineSelectAndUse(N, N0, N1, DCI);
    if (Result.getNode()) return Result;
  }
  return SDValue();
}

/// PerformADDCombine - Target-specific dag combine xforms for ISD::ADD.
///
static SDValue PerformADDCombine(SDNode *N,
                                 TargetLowering::DAGCombinerInfo &DCI) {
  SDValue N0 = N->getOperand(0);
  SDValue N1 = N->getOperand(1);

  // First try with the default operand order.
  SDValue Result = PerformADDCombineWithOperands(N, N0, N1, DCI);
  if (Result.getNode())
    return Result;

  // If that didn't work, try again with the operands commuted.
  return PerformADDCombineWithOperands(N, N1, N0, DCI);
}

/// PerformSUBCombine - Target-specific dag combine xforms for ISD::SUB.
///
static SDValue PerformSUBCombine(SDNode *N,
                                 TargetLowering::DAGCombinerInfo &DCI) {
  SDValue N0 = N->getOperand(0);
  SDValue N1 = N->getOperand(1);

  // fold (sub x, (select cc, 0, c)) -> (select cc, x, (sub, x, c))
  if (N1.getOpcode() == ISD::SELECT && N1.getNode()->hasOneUse()) {
    SDValue Result = combineSelectAndUse(N, N1, N0, DCI);
    if (Result.getNode()) return Result;
  }

  return SDValue();
}

static SDValue PerformMULCombine(SDNode *N,
                                 TargetLowering::DAGCombinerInfo &DCI,
                                 const ARMSubtarget *Subtarget) {
  SelectionDAG &DAG = DCI.DAG;

  if (Subtarget->isThumb1Only())
    return SDValue();

  if (DAG.getMachineFunction().
      getFunction()->hasFnAttr(Attribute::OptimizeForSize))
    return SDValue();

  if (DCI.isBeforeLegalize() || DCI.isCalledByLegalizer())
    return SDValue();

  EVT VT = N->getValueType(0);
  if (VT != MVT::i32)
    return SDValue();

  ConstantSDNode *C = dyn_cast<ConstantSDNode>(N->getOperand(1));
  if (!C)
    return SDValue();

  uint64_t MulAmt = C->getZExtValue();
  unsigned ShiftAmt = CountTrailingZeros_64(MulAmt);
  ShiftAmt = ShiftAmt & (32 - 1);
  SDValue V = N->getOperand(0);
  DebugLoc DL = N->getDebugLoc();

  SDValue Res;
  MulAmt >>= ShiftAmt;
  if (isPowerOf2_32(MulAmt - 1)) {
    // (mul x, 2^N + 1) => (add (shl x, N), x)
    Res = DAG.getNode(ISD::ADD, DL, VT,
                      V, DAG.getNode(ISD::SHL, DL, VT,
                                     V, DAG.getConstant(Log2_32(MulAmt-1),
                                                        MVT::i32)));
  } else if (isPowerOf2_32(MulAmt + 1)) {
    // (mul x, 2^N - 1) => (sub (shl x, N), x)
    Res = DAG.getNode(ISD::SUB, DL, VT,
                      DAG.getNode(ISD::SHL, DL, VT,
                                  V, DAG.getConstant(Log2_32(MulAmt+1),
                                                     MVT::i32)),
                                                     V);
  } else
    return SDValue();

  if (ShiftAmt != 0)
    Res = DAG.getNode(ISD::SHL, DL, VT, Res,
                      DAG.getConstant(ShiftAmt, MVT::i32));

  // Do not add new nodes to DAG combiner worklist.
  DCI.CombineTo(N, Res, false);
  return SDValue();
}

/// PerformORCombine - Target-specific dag combine xforms for ISD::OR
static SDValue PerformORCombine(SDNode *N,
                                TargetLowering::DAGCombinerInfo &DCI,
                                const ARMSubtarget *Subtarget) {
  // Try to use the ARM/Thumb2 BFI (bitfield insert) instruction when
  // reasonable.

  // BFI is only available on V6T2+
  if (Subtarget->isThumb1Only() || !Subtarget->hasV6T2Ops())
    return SDValue();

  SelectionDAG &DAG = DCI.DAG;
  SDValue N0 = N->getOperand(0), N1 = N->getOperand(1);
  DebugLoc DL = N->getDebugLoc();
  // 1) or (and A, mask), val => ARMbfi A, val, mask
  //      iff (val & mask) == val
  //
  // 2) or (and A, mask), (and B, mask2) => ARMbfi A, (lsr B, amt), mask
  //  2a) iff isBitFieldInvertedMask(mask) && isBitFieldInvertedMask(~mask2)
  //          && CountPopulation_32(mask) == CountPopulation_32(~mask2)
  //  2b) iff isBitFieldInvertedMask(~mask) && isBitFieldInvertedMask(mask2)
  //          && CountPopulation_32(mask) == CountPopulation_32(~mask2)
  //  (i.e., copy a bitfield value into another bitfield of the same width)
  if (N0.getOpcode() != ISD::AND)
    return SDValue();

  EVT VT = N->getValueType(0);
  if (VT != MVT::i32)
    return SDValue();


  // The value and the mask need to be constants so we can verify this is
  // actually a bitfield set. If the mask is 0xffff, we can do better
  // via a movt instruction, so don't use BFI in that case.
  ConstantSDNode *C = dyn_cast<ConstantSDNode>(N0.getOperand(1));
  if (!C)
    return SDValue();
  unsigned Mask = C->getZExtValue();
  if (Mask == 0xffff)
    return SDValue();
  SDValue Res;
  // Case (1): or (and A, mask), val => ARMbfi A, val, mask
  if ((C = dyn_cast<ConstantSDNode>(N1))) {
    unsigned Val = C->getZExtValue();
    if (!ARM::isBitFieldInvertedMask(Mask) || (Val & ~Mask) != Val)
      return SDValue();
    Val >>= CountTrailingZeros_32(~Mask);

    Res = DAG.getNode(ARMISD::BFI, DL, VT, N0.getOperand(0),
                      DAG.getConstant(Val, MVT::i32),
                      DAG.getConstant(Mask, MVT::i32));

    // Do not add new nodes to DAG combiner worklist.
    DCI.CombineTo(N, Res, false);
  } else if (N1.getOpcode() == ISD::AND) {
    // case (2) or (and A, mask), (and B, mask2) => ARMbfi A, (lsr B, amt), mask
    C = dyn_cast<ConstantSDNode>(N1.getOperand(1));
    if (!C)
      return SDValue();
    unsigned Mask2 = C->getZExtValue();

    if (ARM::isBitFieldInvertedMask(Mask) &&
        ARM::isBitFieldInvertedMask(~Mask2) &&
        (CountPopulation_32(Mask) == CountPopulation_32(~Mask2))) {
      // The pack halfword instruction works better for masks that fit it,
      // so use that when it's available.
      if (Subtarget->hasT2ExtractPack() &&
          (Mask == 0xffff || Mask == 0xffff0000))
        return SDValue();
      // 2a
      unsigned lsb = CountTrailingZeros_32(Mask2);
      Res = DAG.getNode(ISD::SRL, DL, VT, N1.getOperand(0),
                        DAG.getConstant(lsb, MVT::i32));
      Res = DAG.getNode(ARMISD::BFI, DL, VT, N0.getOperand(0), Res,
                        DAG.getConstant(Mask, MVT::i32));
      // Do not add new nodes to DAG combiner worklist.
      DCI.CombineTo(N, Res, false);
    } else if (ARM::isBitFieldInvertedMask(~Mask) &&
               ARM::isBitFieldInvertedMask(Mask2) &&
               (CountPopulation_32(~Mask) == CountPopulation_32(Mask2))) {
      // The pack halfword instruction works better for masks that fit it,
      // so use that when it's available.
      if (Subtarget->hasT2ExtractPack() &&
          (Mask2 == 0xffff || Mask2 == 0xffff0000))
        return SDValue();
      // 2b
      unsigned lsb = CountTrailingZeros_32(Mask);
      Res = DAG.getNode(ISD::SRL, DL, VT, N0.getOperand(0),
                        DAG.getConstant(lsb, MVT::i32));
      Res = DAG.getNode(ARMISD::BFI, DL, VT, N1.getOperand(0), Res,
                                DAG.getConstant(Mask2, MVT::i32));
      // Do not add new nodes to DAG combiner worklist.
      DCI.CombineTo(N, Res, false);
    }
  }

  return SDValue();
}

/// PerformVMOVRRDCombine - Target-specific dag combine xforms for
/// ARMISD::VMOVRRD.
static SDValue PerformVMOVRRDCombine(SDNode *N,
                                   TargetLowering::DAGCombinerInfo &DCI) {
  // fmrrd(fmdrr x, y) -> x,y
  SDValue InDouble = N->getOperand(0);
  if (InDouble.getOpcode() == ARMISD::VMOVDRR)
    return DCI.CombineTo(N, InDouble.getOperand(0), InDouble.getOperand(1));
  return SDValue();
}

/// PerformVDUPLANECombine - Target-specific dag combine xforms for
/// ARMISD::VDUPLANE.
static SDValue PerformVDUPLANECombine(SDNode *N,
                                      TargetLowering::DAGCombinerInfo &DCI) {
  // If the source is already a VMOVIMM or VMVNIMM splat, the VDUPLANE is
  // redundant.
  SDValue Op = N->getOperand(0);
  EVT VT = N->getValueType(0);

  // Ignore bit_converts.
  while (Op.getOpcode() == ISD::BIT_CONVERT)
    Op = Op.getOperand(0);
  if (Op.getOpcode() != ARMISD::VMOVIMM && Op.getOpcode() != ARMISD::VMVNIMM)
    return SDValue();

  // Make sure the VMOV element size is not bigger than the VDUPLANE elements.
  unsigned EltSize = Op.getValueType().getVectorElementType().getSizeInBits();
  // The canonical VMOV for a zero vector uses a 32-bit element size.
  unsigned Imm = cast<ConstantSDNode>(Op.getOperand(0))->getZExtValue();
  unsigned EltBits;
  if (ARM_AM::decodeNEONModImm(Imm, EltBits) == 0)
    EltSize = 8;
  if (EltSize > VT.getVectorElementType().getSizeInBits())
    return SDValue();

  SDValue Res = DCI.DAG.getNode(ISD::BIT_CONVERT, N->getDebugLoc(), VT, Op);
  return DCI.CombineTo(N, Res, false);
}

/// getVShiftImm - Check if this is a valid build_vector for the immediate
/// operand of a vector shift operation, where all the elements of the
/// build_vector must have the same constant integer value.
static bool getVShiftImm(SDValue Op, unsigned ElementBits, int64_t &Cnt) {
  // Ignore bit_converts.
  while (Op.getOpcode() == ISD::BIT_CONVERT)
    Op = Op.getOperand(0);
  BuildVectorSDNode *BVN = dyn_cast<BuildVectorSDNode>(Op.getNode());
  APInt SplatBits, SplatUndef;
  unsigned SplatBitSize;
  bool HasAnyUndefs;
  if (! BVN || ! BVN->isConstantSplat(SplatBits, SplatUndef, SplatBitSize,
                                      HasAnyUndefs, ElementBits) ||
      SplatBitSize > ElementBits)
    return false;
  Cnt = SplatBits.getSExtValue();
  return true;
}

/// isVShiftLImm - Check if this is a valid build_vector for the immediate
/// operand of a vector shift left operation.  That value must be in the range:
///   0 <= Value < ElementBits for a left shift; or
///   0 <= Value <= ElementBits for a long left shift.
static bool isVShiftLImm(SDValue Op, EVT VT, bool isLong, int64_t &Cnt) {
  assert(VT.isVector() && "vector shift count is not a vector type");
  unsigned ElementBits = VT.getVectorElementType().getSizeInBits();
  if (! getVShiftImm(Op, ElementBits, Cnt))
    return false;
  return (Cnt >= 0 && (isLong ? Cnt-1 : Cnt) < ElementBits);
}

/// isVShiftRImm - Check if this is a valid build_vector for the immediate
/// operand of a vector shift right operation.  For a shift opcode, the value
/// is positive, but for an intrinsic the value count must be negative. The
/// absolute value must be in the range:
///   1 <= |Value| <= ElementBits for a right shift; or
///   1 <= |Value| <= ElementBits/2 for a narrow right shift.
static bool isVShiftRImm(SDValue Op, EVT VT, bool isNarrow, bool isIntrinsic,
                         int64_t &Cnt) {
  assert(VT.isVector() && "vector shift count is not a vector type");
  unsigned ElementBits = VT.getVectorElementType().getSizeInBits();
  if (! getVShiftImm(Op, ElementBits, Cnt))
    return false;
  if (isIntrinsic)
    Cnt = -Cnt;
  return (Cnt >= 1 && Cnt <= (isNarrow ? ElementBits/2 : ElementBits));
}

/// PerformIntrinsicCombine - ARM-specific DAG combining for intrinsics.
static SDValue PerformIntrinsicCombine(SDNode *N, SelectionDAG &DAG) {
  unsigned IntNo = cast<ConstantSDNode>(N->getOperand(0))->getZExtValue();
  switch (IntNo) {
  default:
    // Don't do anything for most intrinsics.
    break;

  // Vector shifts: check for immediate versions and lower them.
  // Note: This is done during DAG combining instead of DAG legalizing because
  // the build_vectors for 64-bit vector element shift counts are generally
  // not legal, and it is hard to see their values after they get legalized to
  // loads from a constant pool.
  case Intrinsic::arm_neon_vshifts:
  case Intrinsic::arm_neon_vshiftu:
  case Intrinsic::arm_neon_vshiftls:
  case Intrinsic::arm_neon_vshiftlu:
  case Intrinsic::arm_neon_vshiftn:
  case Intrinsic::arm_neon_vrshifts:
  case Intrinsic::arm_neon_vrshiftu:
  case Intrinsic::arm_neon_vrshiftn:
  case Intrinsic::arm_neon_vqshifts:
  case Intrinsic::arm_neon_vqshiftu:
  case Intrinsic::arm_neon_vqshiftsu:
  case Intrinsic::arm_neon_vqshiftns:
  case Intrinsic::arm_neon_vqshiftnu:
  case Intrinsic::arm_neon_vqshiftnsu:
  case Intrinsic::arm_neon_vqrshiftns:
  case Intrinsic::arm_neon_vqrshiftnu:
  case Intrinsic::arm_neon_vqrshiftnsu: {
    EVT VT = N->getOperand(1).getValueType();
    int64_t Cnt;
    unsigned VShiftOpc = 0;

    switch (IntNo) {
    case Intrinsic::arm_neon_vshifts:
    case Intrinsic::arm_neon_vshiftu:
      if (isVShiftLImm(N->getOperand(2), VT, false, Cnt)) {
        VShiftOpc = ARMISD::VSHL;
        break;
      }
      if (isVShiftRImm(N->getOperand(2), VT, false, true, Cnt)) {
        VShiftOpc = (IntNo == Intrinsic::arm_neon_vshifts ?
                     ARMISD::VSHRs : ARMISD::VSHRu);
        break;
      }
      return SDValue();

    case Intrinsic::arm_neon_vshiftls:
    case Intrinsic::arm_neon_vshiftlu:
      if (isVShiftLImm(N->getOperand(2), VT, true, Cnt))
        break;
      llvm_unreachable("invalid shift count for vshll intrinsic");

    case Intrinsic::arm_neon_vrshifts:
    case Intrinsic::arm_neon_vrshiftu:
      if (isVShiftRImm(N->getOperand(2), VT, false, true, Cnt))
        break;
      return SDValue();

    case Intrinsic::arm_neon_vqshifts:
    case Intrinsic::arm_neon_vqshiftu:
      if (isVShiftLImm(N->getOperand(2), VT, false, Cnt))
        break;
      return SDValue();

    case Intrinsic::arm_neon_vqshiftsu:
      if (isVShiftLImm(N->getOperand(2), VT, false, Cnt))
        break;
      llvm_unreachable("invalid shift count for vqshlu intrinsic");

    case Intrinsic::arm_neon_vshiftn:
    case Intrinsic::arm_neon_vrshiftn:
    case Intrinsic::arm_neon_vqshiftns:
    case Intrinsic::arm_neon_vqshiftnu:
    case Intrinsic::arm_neon_vqshiftnsu:
    case Intrinsic::arm_neon_vqrshiftns:
    case Intrinsic::arm_neon_vqrshiftnu:
    case Intrinsic::arm_neon_vqrshiftnsu:
      // Narrowing shifts require an immediate right shift.
      if (isVShiftRImm(N->getOperand(2), VT, true, true, Cnt))
        break;
      llvm_unreachable("invalid shift count for narrowing vector shift "
                       "intrinsic");

    default:
      llvm_unreachable("unhandled vector shift");
    }

    switch (IntNo) {
    case Intrinsic::arm_neon_vshifts:
    case Intrinsic::arm_neon_vshiftu:
      // Opcode already set above.
      break;
    case Intrinsic::arm_neon_vshiftls:
    case Intrinsic::arm_neon_vshiftlu:
      if (Cnt == VT.getVectorElementType().getSizeInBits())
        VShiftOpc = ARMISD::VSHLLi;
      else
        VShiftOpc = (IntNo == Intrinsic::arm_neon_vshiftls ?
                     ARMISD::VSHLLs : ARMISD::VSHLLu);
      break;
    case Intrinsic::arm_neon_vshiftn:
      VShiftOpc = ARMISD::VSHRN; break;
    case Intrinsic::arm_neon_vrshifts:
      VShiftOpc = ARMISD::VRSHRs; break;
    case Intrinsic::arm_neon_vrshiftu:
      VShiftOpc = ARMISD::VRSHRu; break;
    case Intrinsic::arm_neon_vrshiftn:
      VShiftOpc = ARMISD::VRSHRN; break;
    case Intrinsic::arm_neon_vqshifts:
      VShiftOpc = ARMISD::VQSHLs; break;
    case Intrinsic::arm_neon_vqshiftu:
      VShiftOpc = ARMISD::VQSHLu; break;
    case Intrinsic::arm_neon_vqshiftsu:
      VShiftOpc = ARMISD::VQSHLsu; break;
    case Intrinsic::arm_neon_vqshiftns:
      VShiftOpc = ARMISD::VQSHRNs; break;
    case Intrinsic::arm_neon_vqshiftnu:
      VShiftOpc = ARMISD::VQSHRNu; break;
    case Intrinsic::arm_neon_vqshiftnsu:
      VShiftOpc = ARMISD::VQSHRNsu; break;
    case Intrinsic::arm_neon_vqrshiftns:
      VShiftOpc = ARMISD::VQRSHRNs; break;
    case Intrinsic::arm_neon_vqrshiftnu:
      VShiftOpc = ARMISD::VQRSHRNu; break;
    case Intrinsic::arm_neon_vqrshiftnsu:
      VShiftOpc = ARMISD::VQRSHRNsu; break;
    }

    return DAG.getNode(VShiftOpc, N->getDebugLoc(), N->getValueType(0),
                       N->getOperand(1), DAG.getConstant(Cnt, MVT::i32));
  }

  case Intrinsic::arm_neon_vshiftins: {
    EVT VT = N->getOperand(1).getValueType();
    int64_t Cnt;
    unsigned VShiftOpc = 0;

    if (isVShiftLImm(N->getOperand(3), VT, false, Cnt))
      VShiftOpc = ARMISD::VSLI;
    else if (isVShiftRImm(N->getOperand(3), VT, false, true, Cnt))
      VShiftOpc = ARMISD::VSRI;
    else {
      llvm_unreachable("invalid shift count for vsli/vsri intrinsic");
    }

    return DAG.getNode(VShiftOpc, N->getDebugLoc(), N->getValueType(0),
                       N->getOperand(1), N->getOperand(2),
                       DAG.getConstant(Cnt, MVT::i32));
  }

  case Intrinsic::arm_neon_vqrshifts:
  case Intrinsic::arm_neon_vqrshiftu:
    // No immediate versions of these to check for.
    break;
  }

  return SDValue();
}

/// PerformShiftCombine - Checks for immediate versions of vector shifts and
/// lowers them.  As with the vector shift intrinsics, this is done during DAG
/// combining instead of DAG legalizing because the build_vectors for 64-bit
/// vector element shift counts are generally not legal, and it is hard to see
/// their values after they get legalized to loads from a constant pool.
static SDValue PerformShiftCombine(SDNode *N, SelectionDAG &DAG,
                                   const ARMSubtarget *ST) {
  EVT VT = N->getValueType(0);

  // Nothing to be done for scalar shifts.
  if (! VT.isVector())
    return SDValue();

  assert(ST->hasNEON() && "unexpected vector shift");
  int64_t Cnt;

  switch (N->getOpcode()) {
  default: llvm_unreachable("unexpected shift opcode");

  case ISD::SHL:
    if (isVShiftLImm(N->getOperand(1), VT, false, Cnt))
      return DAG.getNode(ARMISD::VSHL, N->getDebugLoc(), VT, N->getOperand(0),
                         DAG.getConstant(Cnt, MVT::i32));
    break;

  case ISD::SRA:
  case ISD::SRL:
    if (isVShiftRImm(N->getOperand(1), VT, false, false, Cnt)) {
      unsigned VShiftOpc = (N->getOpcode() == ISD::SRA ?
                            ARMISD::VSHRs : ARMISD::VSHRu);
      return DAG.getNode(VShiftOpc, N->getDebugLoc(), VT, N->getOperand(0),
                         DAG.getConstant(Cnt, MVT::i32));
    }
  }
  return SDValue();
}

/// PerformExtendCombine - Target-specific DAG combining for ISD::SIGN_EXTEND,
/// ISD::ZERO_EXTEND, and ISD::ANY_EXTEND.
static SDValue PerformExtendCombine(SDNode *N, SelectionDAG &DAG,
                                    const ARMSubtarget *ST) {
  SDValue N0 = N->getOperand(0);

  // Check for sign- and zero-extensions of vector extract operations of 8-
  // and 16-bit vector elements.  NEON supports these directly.  They are
  // handled during DAG combining because type legalization will promote them
  // to 32-bit types and it is messy to recognize the operations after that.
  if (ST->hasNEON() && N0.getOpcode() == ISD::EXTRACT_VECTOR_ELT) {
    SDValue Vec = N0.getOperand(0);
    SDValue Lane = N0.getOperand(1);
    EVT VT = N->getValueType(0);
    EVT EltVT = N0.getValueType();
    const TargetLowering &TLI = DAG.getTargetLoweringInfo();

    if (VT == MVT::i32 &&
        (EltVT == MVT::i8 || EltVT == MVT::i16) &&
        TLI.isTypeLegal(Vec.getValueType())) {

      unsigned Opc = 0;
      switch (N->getOpcode()) {
      default: llvm_unreachable("unexpected opcode");
      case ISD::SIGN_EXTEND:
        Opc = ARMISD::VGETLANEs;
        break;
      case ISD::ZERO_EXTEND:
      case ISD::ANY_EXTEND:
        Opc = ARMISD::VGETLANEu;
        break;
      }
      return DAG.getNode(Opc, N->getDebugLoc(), VT, Vec, Lane);
    }
  }

  return SDValue();
}

/// PerformSELECT_CCCombine - Target-specific DAG combining for ISD::SELECT_CC
/// to match f32 max/min patterns to use NEON vmax/vmin instructions.
static SDValue PerformSELECT_CCCombine(SDNode *N, SelectionDAG &DAG,
                                       const ARMSubtarget *ST) {
  // If the target supports NEON, try to use vmax/vmin instructions for f32
  // selects like "x < y ? x : y".  Unless the NoNaNsFPMath option is set,
  // be careful about NaNs:  NEON's vmax/vmin return NaN if either operand is
  // a NaN; only do the transformation when it matches that behavior.

  // For now only do this when using NEON for FP operations; if using VFP, it
  // is not obvious that the benefit outweighs the cost of switching to the
  // NEON pipeline.
  if (!ST->hasNEON() || !ST->useNEONForSinglePrecisionFP() ||
      N->getValueType(0) != MVT::f32)
    return SDValue();

  SDValue CondLHS = N->getOperand(0);
  SDValue CondRHS = N->getOperand(1);
  SDValue LHS = N->getOperand(2);
  SDValue RHS = N->getOperand(3);
  ISD::CondCode CC = cast<CondCodeSDNode>(N->getOperand(4))->get();

  unsigned Opcode = 0;
  bool IsReversed;
  if (DAG.isEqualTo(LHS, CondLHS) && DAG.isEqualTo(RHS, CondRHS)) {
    IsReversed = false; // x CC y ? x : y
  } else if (DAG.isEqualTo(LHS, CondRHS) && DAG.isEqualTo(RHS, CondLHS)) {
    IsReversed = true ; // x CC y ? y : x
  } else {
    return SDValue();
  }

  bool IsUnordered;
  switch (CC) {
  default: break;
  case ISD::SETOLT:
  case ISD::SETOLE:
  case ISD::SETLT:
  case ISD::SETLE:
  case ISD::SETULT:
  case ISD::SETULE:
    // If LHS is NaN, an ordered comparison will be false and the result will
    // be the RHS, but vmin(NaN, RHS) = NaN.  Avoid this by checking that LHS
    // != NaN.  Likewise, for unordered comparisons, check for RHS != NaN.
    IsUnordered = (CC == ISD::SETULT || CC == ISD::SETULE);
    if (!DAG.isKnownNeverNaN(IsUnordered ? RHS : LHS))
      break;
    // For less-than-or-equal comparisons, "+0 <= -0" will be true but vmin
    // will return -0, so vmin can only be used for unsafe math or if one of
    // the operands is known to be nonzero.
    if ((CC == ISD::SETLE || CC == ISD::SETOLE || CC == ISD::SETULE) &&
        !UnsafeFPMath &&
        !(DAG.isKnownNeverZero(LHS) || DAG.isKnownNeverZero(RHS)))
      break;
    Opcode = IsReversed ? ARMISD::FMAX : ARMISD::FMIN;
    break;

  case ISD::SETOGT:
  case ISD::SETOGE:
  case ISD::SETGT:
  case ISD::SETGE:
  case ISD::SETUGT:
  case ISD::SETUGE:
    // If LHS is NaN, an ordered comparison will be false and the result will
    // be the RHS, but vmax(NaN, RHS) = NaN.  Avoid this by checking that LHS
    // != NaN.  Likewise, for unordered comparisons, check for RHS != NaN.
    IsUnordered = (CC == ISD::SETUGT || CC == ISD::SETUGE);
    if (!DAG.isKnownNeverNaN(IsUnordered ? RHS : LHS))
      break;
    // For greater-than-or-equal comparisons, "-0 >= +0" will be true but vmax
    // will return +0, so vmax can only be used for unsafe math or if one of
    // the operands is known to be nonzero.
    if ((CC == ISD::SETGE || CC == ISD::SETOGE || CC == ISD::SETUGE) &&
        !UnsafeFPMath &&
        !(DAG.isKnownNeverZero(LHS) || DAG.isKnownNeverZero(RHS)))
      break;
    Opcode = IsReversed ? ARMISD::FMIN : ARMISD::FMAX;
    break;
  }

  if (!Opcode)
    return SDValue();
  return DAG.getNode(Opcode, N->getDebugLoc(), N->getValueType(0), LHS, RHS);
}

SDValue ARMTargetLowering::PerformDAGCombine(SDNode *N,
                                             DAGCombinerInfo &DCI) const {
  switch (N->getOpcode()) {
  default: break;
  case ISD::ADD:        return PerformADDCombine(N, DCI);
  case ISD::SUB:        return PerformSUBCombine(N, DCI);
  case ISD::MUL:        return PerformMULCombine(N, DCI, Subtarget);
  case ISD::OR:         return PerformORCombine(N, DCI, Subtarget);
  case ARMISD::VMOVRRD: return PerformVMOVRRDCombine(N, DCI);
  case ARMISD::VDUPLANE: return PerformVDUPLANECombine(N, DCI);
  case ISD::INTRINSIC_WO_CHAIN: return PerformIntrinsicCombine(N, DCI.DAG);
  case ISD::SHL:
  case ISD::SRA:
  case ISD::SRL:        return PerformShiftCombine(N, DCI.DAG, Subtarget);
  case ISD::SIGN_EXTEND:
  case ISD::ZERO_EXTEND:
  case ISD::ANY_EXTEND: return PerformExtendCombine(N, DCI.DAG, Subtarget);
  case ISD::SELECT_CC:  return PerformSELECT_CCCombine(N, DCI.DAG, Subtarget);
  }
  return SDValue();
}

bool ARMTargetLowering::allowsUnalignedMemoryAccesses(EVT VT) const {
  if (!Subtarget->hasV6Ops())
    // Pre-v6 does not support unaligned mem access.
    return false;

  // v6+ may or may not support unaligned mem access depending on the system
  // configuration.
  // FIXME: This is pretty conservative. Should we provide cmdline option to
  // control the behaviour?
  if (!Subtarget->isTargetDarwin())
    return false;

  switch (VT.getSimpleVT().SimpleTy) {
  default:
    return false;
  case MVT::i8:
  case MVT::i16:
  case MVT::i32:
    return true;
  // FIXME: VLD1 etc with standard alignment is legal.
  }
}

static bool isLegalT1AddressImmediate(int64_t V, EVT VT) {
  if (V < 0)
    return false;

  unsigned Scale = 1;
  switch (VT.getSimpleVT().SimpleTy) {
  default: return false;
  case MVT::i1:
  case MVT::i8:
    // Scale == 1;
    break;
  case MVT::i16:
    // Scale == 2;
    Scale = 2;
    break;
  case MVT::i32:
    // Scale == 4;
    Scale = 4;
    break;
  }

  if ((V & (Scale - 1)) != 0)
    return false;
  V /= Scale;
  return V == (V & ((1LL << 5) - 1));
}

static bool isLegalT2AddressImmediate(int64_t V, EVT VT,
                                      const ARMSubtarget *Subtarget) {
  bool isNeg = false;
  if (V < 0) {
    isNeg = true;
    V = - V;
  }

  switch (VT.getSimpleVT().SimpleTy) {
  default: return false;
  case MVT::i1:
  case MVT::i8:
  case MVT::i16:
  case MVT::i32:
    // + imm12 or - imm8
    if (isNeg)
      return V == (V & ((1LL << 8) - 1));
    return V == (V & ((1LL << 12) - 1));
  case MVT::f32:
  case MVT::f64:
    // Same as ARM mode. FIXME: NEON?
    if (!Subtarget->hasVFP2())
      return false;
    if ((V & 3) != 0)
      return false;
    V >>= 2;
    return V == (V & ((1LL << 8) - 1));
  }
}

/// isLegalAddressImmediate - Return true if the integer value can be used
/// as the offset of the target addressing mode for load / store of the
/// given type.
static bool isLegalAddressImmediate(int64_t V, EVT VT,
                                    const ARMSubtarget *Subtarget) {
  if (V == 0)
    return true;

  if (!VT.isSimple())
    return false;

  if (Subtarget->isThumb1Only())
    return isLegalT1AddressImmediate(V, VT);
  else if (Subtarget->isThumb2())
    return isLegalT2AddressImmediate(V, VT, Subtarget);

  // ARM mode.
  if (V < 0)
    V = - V;
  switch (VT.getSimpleVT().SimpleTy) {
  default: return false;
  case MVT::i1:
  case MVT::i8:
  case MVT::i32:
    // +- imm12
    return V == (V & ((1LL << 12) - 1));
  case MVT::i16:
    // +- imm8
    return V == (V & ((1LL << 8) - 1));
  case MVT::f32:
  case MVT::f64:
    if (!Subtarget->hasVFP2()) // FIXME: NEON?
      return false;
    if ((V & 3) != 0)
      return false;
    V >>= 2;
    return V == (V & ((1LL << 8) - 1));
  }
}

bool ARMTargetLowering::isLegalT2ScaledAddressingMode(const AddrMode &AM,
                                                      EVT VT) const {
  int Scale = AM.Scale;
  if (Scale < 0)
    return false;

  switch (VT.getSimpleVT().SimpleTy) {
  default: return false;
  case MVT::i1:
  case MVT::i8:
  case MVT::i16:
  case MVT::i32:
    if (Scale == 1)
      return true;
    // r + r << imm
    Scale = Scale & ~1;
    return Scale == 2 || Scale == 4 || Scale == 8;
  case MVT::i64:
    // r + r
    if (((unsigned)AM.HasBaseReg + Scale) <= 2)
      return true;
    return false;
  case MVT::isVoid:
    // Note, we allow "void" uses (basically, uses that aren't loads or
    // stores), because arm allows folding a scale into many arithmetic
    // operations.  This should be made more precise and revisited later.

    // Allow r << imm, but the imm has to be a multiple of two.
    if (Scale & 1) return false;
    return isPowerOf2_32(Scale);
  }
}

/// isLegalAddressingMode - Return true if the addressing mode represented
/// by AM is legal for this target, for a load/store of the specified type.
bool ARMTargetLowering::isLegalAddressingMode(const AddrMode &AM,
                                              const Type *Ty) const {
  EVT VT = getValueType(Ty, true);
  if (!isLegalAddressImmediate(AM.BaseOffs, VT, Subtarget))
    return false;

  // Can never fold addr of global into load/store.
  if (AM.BaseGV)
    return false;

  switch (AM.Scale) {
  case 0:  // no scale reg, must be "r+i" or "r", or "i".
    break;
  case 1:
    if (Subtarget->isThumb1Only())
      return false;
    // FALL THROUGH.
  default:
    // ARM doesn't support any R+R*scale+imm addr modes.
    if (AM.BaseOffs)
      return false;

    if (!VT.isSimple())
      return false;

    if (Subtarget->isThumb2())
      return isLegalT2ScaledAddressingMode(AM, VT);

    int Scale = AM.Scale;
    switch (VT.getSimpleVT().SimpleTy) {
    default: return false;
    case MVT::i1:
    case MVT::i8:
    case MVT::i32:
      if (Scale < 0) Scale = -Scale;
      if (Scale == 1)
        return true;
      // r + r << imm
      return isPowerOf2_32(Scale & ~1);
    case MVT::i16:
    case MVT::i64:
      // r + r
      if (((unsigned)AM.HasBaseReg + Scale) <= 2)
        return true;
      return false;

    case MVT::isVoid:
      // Note, we allow "void" uses (basically, uses that aren't loads or
      // stores), because arm allows folding a scale into many arithmetic
      // operations.  This should be made more precise and revisited later.

      // Allow r << imm, but the imm has to be a multiple of two.
      if (Scale & 1) return false;
      return isPowerOf2_32(Scale);
    }
    break;
  }
  return true;
}

/// isLegalICmpImmediate - Return true if the specified immediate is legal
/// icmp immediate, that is the target has icmp instructions which can compare
/// a register against the immediate without having to materialize the
/// immediate into a register.
bool ARMTargetLowering::isLegalICmpImmediate(int64_t Imm) const {
  if (!Subtarget->isThumb())
    return ARM_AM::getSOImmVal(Imm) != -1;
  if (Subtarget->isThumb2())
    return ARM_AM::getT2SOImmVal(Imm) != -1; 
  return Imm >= 0 && Imm <= 255;
}

static bool getARMIndexedAddressParts(SDNode *Ptr, EVT VT,
                                      bool isSEXTLoad, SDValue &Base,
                                      SDValue &Offset, bool &isInc,
                                      SelectionDAG &DAG) {
  if (Ptr->getOpcode() != ISD::ADD && Ptr->getOpcode() != ISD::SUB)
    return false;

  if (VT == MVT::i16 || ((VT == MVT::i8 || VT == MVT::i1) && isSEXTLoad)) {
    // AddressingMode 3
    Base = Ptr->getOperand(0);
    if (ConstantSDNode *RHS = dyn_cast<ConstantSDNode>(Ptr->getOperand(1))) {
      int RHSC = (int)RHS->getZExtValue();
      if (RHSC < 0 && RHSC > -256) {
        assert(Ptr->getOpcode() == ISD::ADD);
        isInc = false;
        Offset = DAG.getConstant(-RHSC, RHS->getValueType(0));
        return true;
      }
    }
    isInc = (Ptr->getOpcode() == ISD::ADD);
    Offset = Ptr->getOperand(1);
    return true;
  } else if (VT == MVT::i32 || VT == MVT::i8 || VT == MVT::i1) {
    // AddressingMode 2
    if (ConstantSDNode *RHS = dyn_cast<ConstantSDNode>(Ptr->getOperand(1))) {
      int RHSC = (int)RHS->getZExtValue();
      if (RHSC < 0 && RHSC > -0x1000) {
        assert(Ptr->getOpcode() == ISD::ADD);
        isInc = false;
        Offset = DAG.getConstant(-RHSC, RHS->getValueType(0));
        Base = Ptr->getOperand(0);
        return true;
      }
    }

    if (Ptr->getOpcode() == ISD::ADD) {
      isInc = true;
      ARM_AM::ShiftOpc ShOpcVal= ARM_AM::getShiftOpcForNode(Ptr->getOperand(0));
      if (ShOpcVal != ARM_AM::no_shift) {
        Base = Ptr->getOperand(1);
        Offset = Ptr->getOperand(0);
      } else {
        Base = Ptr->getOperand(0);
        Offset = Ptr->getOperand(1);
      }
      return true;
    }

    isInc = (Ptr->getOpcode() == ISD::ADD);
    Base = Ptr->getOperand(0);
    Offset = Ptr->getOperand(1);
    return true;
  }

  // FIXME: Use VLDM / VSTM to emulate indexed FP load / store.
  return false;
}

static bool getT2IndexedAddressParts(SDNode *Ptr, EVT VT,
                                     bool isSEXTLoad, SDValue &Base,
                                     SDValue &Offset, bool &isInc,
                                     SelectionDAG &DAG) {
  if (Ptr->getOpcode() != ISD::ADD && Ptr->getOpcode() != ISD::SUB)
    return false;

  Base = Ptr->getOperand(0);
  if (ConstantSDNode *RHS = dyn_cast<ConstantSDNode>(Ptr->getOperand(1))) {
    int RHSC = (int)RHS->getZExtValue();
    if (RHSC < 0 && RHSC > -0x100) { // 8 bits.
      assert(Ptr->getOpcode() == ISD::ADD);
      isInc = false;
      Offset = DAG.getConstant(-RHSC, RHS->getValueType(0));
      return true;
    } else if (RHSC > 0 && RHSC < 0x100) { // 8 bit, no zero.
      isInc = Ptr->getOpcode() == ISD::ADD;
      Offset = DAG.getConstant(RHSC, RHS->getValueType(0));
      return true;
    }
  }

  return false;
}

/// getPreIndexedAddressParts - returns true by value, base pointer and
/// offset pointer and addressing mode by reference if the node's address
/// can be legally represented as pre-indexed load / store address.
bool
ARMTargetLowering::getPreIndexedAddressParts(SDNode *N, SDValue &Base,
                                             SDValue &Offset,
                                             ISD::MemIndexedMode &AM,
                                             SelectionDAG &DAG) const {
  if (Subtarget->isThumb1Only())
    return false;

  EVT VT;
  SDValue Ptr;
  bool isSEXTLoad = false;
  if (LoadSDNode *LD = dyn_cast<LoadSDNode>(N)) {
    Ptr = LD->getBasePtr();
    VT  = LD->getMemoryVT();
    isSEXTLoad = LD->getExtensionType() == ISD::SEXTLOAD;
  } else if (StoreSDNode *ST = dyn_cast<StoreSDNode>(N)) {
    Ptr = ST->getBasePtr();
    VT  = ST->getMemoryVT();
  } else
    return false;

  bool isInc;
  bool isLegal = false;
  if (Subtarget->isThumb2())
    isLegal = getT2IndexedAddressParts(Ptr.getNode(), VT, isSEXTLoad, Base,
                                       Offset, isInc, DAG);
  else
    isLegal = getARMIndexedAddressParts(Ptr.getNode(), VT, isSEXTLoad, Base,
                                        Offset, isInc, DAG);
  if (!isLegal)
    return false;

  AM = isInc ? ISD::PRE_INC : ISD::PRE_DEC;
  return true;
}

/// getPostIndexedAddressParts - returns true by value, base pointer and
/// offset pointer and addressing mode by reference if this node can be
/// combined with a load / store to form a post-indexed load / store.
bool ARMTargetLowering::getPostIndexedAddressParts(SDNode *N, SDNode *Op,
                                                   SDValue &Base,
                                                   SDValue &Offset,
                                                   ISD::MemIndexedMode &AM,
                                                   SelectionDAG &DAG) const {
  if (Subtarget->isThumb1Only())
    return false;

  EVT VT;
  SDValue Ptr;
  bool isSEXTLoad = false;
  if (LoadSDNode *LD = dyn_cast<LoadSDNode>(N)) {
    VT  = LD->getMemoryVT();
    Ptr = LD->getBasePtr();
    isSEXTLoad = LD->getExtensionType() == ISD::SEXTLOAD;
  } else if (StoreSDNode *ST = dyn_cast<StoreSDNode>(N)) {
    VT  = ST->getMemoryVT();
    Ptr = ST->getBasePtr();
  } else
    return false;

  bool isInc;
  bool isLegal = false;
  if (Subtarget->isThumb2())
    isLegal = getT2IndexedAddressParts(Op, VT, isSEXTLoad, Base, Offset,
                                       isInc, DAG);
  else
    isLegal = getARMIndexedAddressParts(Op, VT, isSEXTLoad, Base, Offset,
                                        isInc, DAG);
  if (!isLegal)
    return false;

  if (Ptr != Base) {
    // Swap base ptr and offset to catch more post-index load / store when
    // it's legal. In Thumb2 mode, offset must be an immediate.
    if (Ptr == Offset && Op->getOpcode() == ISD::ADD &&
        !Subtarget->isThumb2())
      std::swap(Base, Offset);

    // Post-indexed load / store update the base pointer.
    if (Ptr != Base)
      return false;
  }

  AM = isInc ? ISD::POST_INC : ISD::POST_DEC;
  return true;
}

void ARMTargetLowering::computeMaskedBitsForTargetNode(const SDValue Op,
                                                       const APInt &Mask,
                                                       APInt &KnownZero,
                                                       APInt &KnownOne,
                                                       const SelectionDAG &DAG,
                                                       unsigned Depth) const {
  KnownZero = KnownOne = APInt(Mask.getBitWidth(), 0);
  switch (Op.getOpcode()) {
  default: break;
  case ARMISD::CMOV: {
    // Bits are known zero/one if known on the LHS and RHS.
    DAG.ComputeMaskedBits(Op.getOperand(0), Mask, KnownZero, KnownOne, Depth+1);
    if (KnownZero == 0 && KnownOne == 0) return;

    APInt KnownZeroRHS, KnownOneRHS;
    DAG.ComputeMaskedBits(Op.getOperand(1), Mask,
                          KnownZeroRHS, KnownOneRHS, Depth+1);
    KnownZero &= KnownZeroRHS;
    KnownOne  &= KnownOneRHS;
    return;
  }
  }
}

//===----------------------------------------------------------------------===//
//                           ARM Inline Assembly Support
//===----------------------------------------------------------------------===//

/// getConstraintType - Given a constraint letter, return the type of
/// constraint it is for this target.
ARMTargetLowering::ConstraintType
ARMTargetLowering::getConstraintType(const std::string &Constraint) const {
  if (Constraint.size() == 1) {
    switch (Constraint[0]) {
    default:  break;
    case 'l': return C_RegisterClass;
    case 'w': return C_RegisterClass;
    }
  }
  return TargetLowering::getConstraintType(Constraint);
}

std::pair<unsigned, const TargetRegisterClass*>
ARMTargetLowering::getRegForInlineAsmConstraint(const std::string &Constraint,
                                                EVT VT) const {
  if (Constraint.size() == 1) {
    // GCC ARM Constraint Letters
    switch (Constraint[0]) {
    case 'l':
      if (Subtarget->isThumb())
        return std::make_pair(0U, ARM::tGPRRegisterClass);
      else
        return std::make_pair(0U, ARM::GPRRegisterClass);
    case 'r':
      return std::make_pair(0U, ARM::GPRRegisterClass);
    case 'w':
      if (VT == MVT::f32)
        return std::make_pair(0U, ARM::SPRRegisterClass);
      if (VT.getSizeInBits() == 64)
        return std::make_pair(0U, ARM::DPRRegisterClass);
      if (VT.getSizeInBits() == 128)
        return std::make_pair(0U, ARM::QPRRegisterClass);
      break;
    }
  }
  if (StringRef("{cc}").equals_lower(Constraint))
    return std::make_pair(unsigned(ARM::CPSR), ARM::CCRRegisterClass);

  return TargetLowering::getRegForInlineAsmConstraint(Constraint, VT);
}

std::vector<unsigned> ARMTargetLowering::
getRegClassForInlineAsmConstraint(const std::string &Constraint,
                                  EVT VT) const {
  if (Constraint.size() != 1)
    return std::vector<unsigned>();

  switch (Constraint[0]) {      // GCC ARM Constraint Letters
  default: break;
  case 'l':
    return make_vector<unsigned>(ARM::R0, ARM::R1, ARM::R2, ARM::R3,
                                 ARM::R4, ARM::R5, ARM::R6, ARM::R7,
                                 0);
  case 'r':
    return make_vector<unsigned>(ARM::R0, ARM::R1, ARM::R2, ARM::R3,
                                 ARM::R4, ARM::R5, ARM::R6, ARM::R7,
                                 ARM::R8, ARM::R9, ARM::R10, ARM::R11,
                                 ARM::R12, ARM::LR, 0);
  case 'w':
    if (VT == MVT::f32)
      return make_vector<unsigned>(ARM::S0, ARM::S1, ARM::S2, ARM::S3,
                                   ARM::S4, ARM::S5, ARM::S6, ARM::S7,
                                   ARM::S8, ARM::S9, ARM::S10, ARM::S11,
                                   ARM::S12,ARM::S13,ARM::S14,ARM::S15,
                                   ARM::S16,ARM::S17,ARM::S18,ARM::S19,
                                   ARM::S20,ARM::S21,ARM::S22,ARM::S23,
                                   ARM::S24,ARM::S25,ARM::S26,ARM::S27,
                                   ARM::S28,ARM::S29,ARM::S30,ARM::S31, 0);
    if (VT.getSizeInBits() == 64)
      return make_vector<unsigned>(ARM::D0, ARM::D1, ARM::D2, ARM::D3,
                                   ARM::D4, ARM::D5, ARM::D6, ARM::D7,
                                   ARM::D8, ARM::D9, ARM::D10,ARM::D11,
                                   ARM::D12,ARM::D13,ARM::D14,ARM::D15, 0);
    if (VT.getSizeInBits() == 128)
      return make_vector<unsigned>(ARM::Q0, ARM::Q1, ARM::Q2, ARM::Q3,
                                   ARM::Q4, ARM::Q5, ARM::Q6, ARM::Q7, 0);
      break;
  }

  return std::vector<unsigned>();
}

/// LowerAsmOperandForConstraint - Lower the specified operand into the Ops
/// vector.  If it is invalid, don't add anything to Ops.
void ARMTargetLowering::LowerAsmOperandForConstraint(SDValue Op,
                                                     char Constraint,
                                                     std::vector<SDValue>&Ops,
                                                     SelectionDAG &DAG) const {
  SDValue Result(0, 0);

  switch (Constraint) {
  default: break;
  case 'I': case 'J': case 'K': case 'L':
  case 'M': case 'N': case 'O':
    ConstantSDNode *C = dyn_cast<ConstantSDNode>(Op);
    if (!C)
      return;

    int64_t CVal64 = C->getSExtValue();
    int CVal = (int) CVal64;
    // None of these constraints allow values larger than 32 bits.  Check
    // that the value fits in an int.
    if (CVal != CVal64)
      return;

    switch (Constraint) {
      case 'I':
        if (Subtarget->isThumb1Only()) {
          // This must be a constant between 0 and 255, for ADD
          // immediates.
          if (CVal >= 0 && CVal <= 255)
            break;
        } else if (Subtarget->isThumb2()) {
          // A constant that can be used as an immediate value in a
          // data-processing instruction.
          if (ARM_AM::getT2SOImmVal(CVal) != -1)
            break;
        } else {
          // A constant that can be used as an immediate value in a
          // data-processing instruction.
          if (ARM_AM::getSOImmVal(CVal) != -1)
            break;
        }
        return;

      case 'J':
        if (Subtarget->isThumb()) {  // FIXME thumb2
          // This must be a constant between -255 and -1, for negated ADD
          // immediates. This can be used in GCC with an "n" modifier that
          // prints the negated value, for use with SUB instructions. It is
          // not useful otherwise but is implemented for compatibility.
          if (CVal >= -255 && CVal <= -1)
            break;
        } else {
          // This must be a constant between -4095 and 4095. It is not clear
          // what this constraint is intended for. Implemented for
          // compatibility with GCC.
          if (CVal >= -4095 && CVal <= 4095)
            break;
        }
        return;

      case 'K':
        if (Subtarget->isThumb1Only()) {
          // A 32-bit value where only one byte has a nonzero value. Exclude
          // zero to match GCC. This constraint is used by GCC internally for
          // constants that can be loaded with a move/shift combination.
          // It is not useful otherwise but is implemented for compatibility.
          if (CVal != 0 && ARM_AM::isThumbImmShiftedVal(CVal))
            break;
        } else if (Subtarget->isThumb2()) {
          // A constant whose bitwise inverse can be used as an immediate
          // value in a data-processing instruction. This can be used in GCC
          // with a "B" modifier that prints the inverted value, for use with
          // BIC and MVN instructions. It is not useful otherwise but is
          // implemented for compatibility.
          if (ARM_AM::getT2SOImmVal(~CVal) != -1)
            break;
        } else {
          // A constant whose bitwise inverse can be used as an immediate
          // value in a data-processing instruction. This can be used in GCC
          // with a "B" modifier that prints the inverted value, for use with
          // BIC and MVN instructions. It is not useful otherwise but is
          // implemented for compatibility.
          if (ARM_AM::getSOImmVal(~CVal) != -1)
            break;
        }
        return;

      case 'L':
        if (Subtarget->isThumb1Only()) {
          // This must be a constant between -7 and 7,
          // for 3-operand ADD/SUB immediate instructions.
          if (CVal >= -7 && CVal < 7)
            break;
        } else if (Subtarget->isThumb2()) {
          // A constant whose negation can be used as an immediate value in a
          // data-processing instruction. This can be used in GCC with an "n"
          // modifier that prints the negated value, for use with SUB
          // instructions. It is not useful otherwise but is implemented for
          // compatibility.
          if (ARM_AM::getT2SOImmVal(-CVal) != -1)
            break;
        } else {
          // A constant whose negation can be used as an immediate value in a
          // data-processing instruction. This can be used in GCC with an "n"
          // modifier that prints the negated value, for use with SUB
          // instructions. It is not useful otherwise but is implemented for
          // compatibility.
          if (ARM_AM::getSOImmVal(-CVal) != -1)
            break;
        }
        return;

      case 'M':
        if (Subtarget->isThumb()) { // FIXME thumb2
          // This must be a multiple of 4 between 0 and 1020, for
          // ADD sp + immediate.
          if ((CVal >= 0 && CVal <= 1020) && ((CVal & 3) == 0))
            break;
        } else {
          // A power of two or a constant between 0 and 32.  This is used in
          // GCC for the shift amount on shifted register operands, but it is
          // useful in general for any shift amounts.
          if ((CVal >= 0 && CVal <= 32) || ((CVal & (CVal - 1)) == 0))
            break;
        }
        return;

      case 'N':
        if (Subtarget->isThumb()) {  // FIXME thumb2
          // This must be a constant between 0 and 31, for shift amounts.
          if (CVal >= 0 && CVal <= 31)
            break;
        }
        return;

      case 'O':
        if (Subtarget->isThumb()) {  // FIXME thumb2
          // This must be a multiple of 4 between -508 and 508, for
          // ADD/SUB sp = sp + immediate.
          if ((CVal >= -508 && CVal <= 508) && ((CVal & 3) == 0))
            break;
        }
        return;
    }
    Result = DAG.getTargetConstant(CVal, Op.getValueType());
    break;
  }

  if (Result.getNode()) {
    Ops.push_back(Result);
    return;
  }
  return TargetLowering::LowerAsmOperandForConstraint(Op, Constraint, Ops, DAG);
}

bool
ARMTargetLowering::isOffsetFoldingLegal(const GlobalAddressSDNode *GA) const {
  // The ARM target isn't yet aware of offsets.
  return false;
}

int ARM::getVFPf32Imm(const APFloat &FPImm) {
  APInt Imm = FPImm.bitcastToAPInt();
  uint32_t Sign = Imm.lshr(31).getZExtValue() & 1;
  int32_t Exp = (Imm.lshr(23).getSExtValue() & 0xff) - 127;  // -126 to 127
  int64_t Mantissa = Imm.getZExtValue() & 0x7fffff;  // 23 bits

  // We can handle 4 bits of mantissa.
  // mantissa = (16+UInt(e:f:g:h))/16.
  if (Mantissa & 0x7ffff)
    return -1;
  Mantissa >>= 19;
  if ((Mantissa & 0xf) != Mantissa)
    return -1;

  // We can handle 3 bits of exponent: exp == UInt(NOT(b):c:d)-3
  if (Exp < -3 || Exp > 4)
    return -1;
  Exp = ((Exp+3) & 0x7) ^ 4;

  return ((int)Sign << 7) | (Exp << 4) | Mantissa;
}

int ARM::getVFPf64Imm(const APFloat &FPImm) {
  APInt Imm = FPImm.bitcastToAPInt();
  uint64_t Sign = Imm.lshr(63).getZExtValue() & 1;
  int64_t Exp = (Imm.lshr(52).getSExtValue() & 0x7ff) - 1023;   // -1022 to 1023
  uint64_t Mantissa = Imm.getZExtValue() & 0xfffffffffffffLL;

  // We can handle 4 bits of mantissa.
  // mantissa = (16+UInt(e:f:g:h))/16.
  if (Mantissa & 0xffffffffffffLL)
    return -1;
  Mantissa >>= 48;
  if ((Mantissa & 0xf) != Mantissa)
    return -1;

  // We can handle 3 bits of exponent: exp == UInt(NOT(b):c:d)-3
  if (Exp < -3 || Exp > 4)
    return -1;
  Exp = ((Exp+3) & 0x7) ^ 4;

  return ((int)Sign << 7) | (Exp << 4) | Mantissa;
}

bool ARM::isBitFieldInvertedMask(unsigned v) {
  if (v == 0xffffffff)
    return 0;
  // there can be 1's on either or both "outsides", all the "inside"
  // bits must be 0's
  unsigned int lsb = 0, msb = 31;
  while (v & (1 << msb)) --msb;
  while (v & (1 << lsb)) ++lsb;
  for (unsigned int i = lsb; i <= msb; ++i) {
    if (v & (1 << i))
      return 0;
  }
  return 1;
}

/// isFPImmLegal - Returns true if the target can instruction select the
/// specified FP immediate natively. If false, the legalizer will
/// materialize the FP immediate as a load from a constant pool.
bool ARMTargetLowering::isFPImmLegal(const APFloat &Imm, EVT VT) const {
  if (!Subtarget->hasVFP3())
    return false;
  if (VT == MVT::f32)
    return ARM::getVFPf32Imm(Imm) != -1;
  if (VT == MVT::f64)
    return ARM::getVFPf64Imm(Imm) != -1;
  return false;
}
