//===-- LLVMTargetMachine.cpp - Implement the LLVMTargetMachine class -----===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements the LLVMTargetMachine class.
//
//===----------------------------------------------------------------------===//

#include "llvm/Target/TargetMachine.h"
#include "llvm/PassManager.h"
#include "llvm/Pass.h"
#include "llvm/Analysis/Verifier.h"
#include "llvm/Assembly/PrintModulePass.h"
#include "llvm/CodeGen/AsmPrinter.h"
#include "llvm/CodeGen/Passes.h"
#include "llvm/CodeGen/GCStrategy.h"
#include "llvm/CodeGen/MachineFunctionAnalysis.h"
#include "llvm/Target/TargetOptions.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCStreamer.h"
#include "llvm/Target/TargetData.h"
#include "llvm/Target/TargetRegistry.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/ADT/OwningPtr.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/FormattedStream.h"
using namespace llvm;

namespace llvm {
  bool EnableFastISel;
}

static cl::opt<bool> DisablePostRA("disable-post-ra", cl::Hidden,
    cl::desc("Disable Post Regalloc"));
static cl::opt<bool> DisableBranchFold("disable-branch-fold", cl::Hidden,
    cl::desc("Disable branch folding"));
static cl::opt<bool> DisableTailDuplicate("disable-tail-duplicate", cl::Hidden,
    cl::desc("Disable tail duplication"));
static cl::opt<bool> DisableEarlyTailDup("disable-early-taildup", cl::Hidden,
    cl::desc("Disable pre-register allocation tail duplication"));
static cl::opt<bool> DisableCodePlace("disable-code-place", cl::Hidden,
    cl::desc("Disable code placement"));
static cl::opt<bool> DisableSSC("disable-ssc", cl::Hidden,
    cl::desc("Disable Stack Slot Coloring"));
static cl::opt<bool> DisableMachineLICM("disable-machine-licm", cl::Hidden,
    cl::desc("Disable Machine LICM"));
static cl::opt<bool> DisableMachineSink("disable-machine-sink", cl::Hidden,
    cl::desc("Disable Machine Sinking"));
static cl::opt<bool> DisableLSR("disable-lsr", cl::Hidden,
    cl::desc("Disable Loop Strength Reduction Pass"));
static cl::opt<bool> DisableCGP("disable-cgp", cl::Hidden,
    cl::desc("Disable Codegen Prepare"));
static cl::opt<bool> PrintLSR("print-lsr-output", cl::Hidden,
    cl::desc("Print LLVM IR produced by the loop-reduce pass"));
static cl::opt<bool> PrintISelInput("print-isel-input", cl::Hidden,
    cl::desc("Print LLVM IR input to isel pass"));
static cl::opt<bool> PrintGCInfo("print-gc", cl::Hidden,
    cl::desc("Dump garbage collector data"));
static cl::opt<bool> VerifyMachineCode("verify-machineinstrs", cl::Hidden,
    cl::desc("Verify generated machine code"),
    cl::init(getenv("LLVM_VERIFY_MACHINEINSTRS")!=NULL));

static cl::opt<bool> EnableMachineCSE("enable-machine-cse", cl::Hidden,
    cl::desc("Enable Machine CSE"));

static cl::opt<cl::boolOrDefault>
AsmVerbose("asm-verbose", cl::desc("Add comments to directives."),
           cl::init(cl::BOU_UNSET));

static bool getVerboseAsm() {
  switch (AsmVerbose) {
  default:
  case cl::BOU_UNSET: return TargetMachine::getAsmVerbosityDefault();
  case cl::BOU_TRUE:  return true;
  case cl::BOU_FALSE: return false;
  }      
}

// Enable or disable FastISel. Both options are needed, because
// FastISel is enabled by default with -fast, and we wish to be
// able to enable or disable fast-isel independently from -O0.
static cl::opt<cl::boolOrDefault>
EnableFastISelOption("fast-isel", cl::Hidden,
  cl::desc("Enable the \"fast\" instruction selector"));

// Enable or disable an experimental optimization to split GEPs
// and run a special GVN pass which does not examine loads, in
// an effort to factor out redundancy implicit in complex GEPs.
static cl::opt<bool> EnableSplitGEPGVN("split-gep-gvn", cl::Hidden,
    cl::desc("Split GEPs and run no-load GVN"));

LLVMTargetMachine::LLVMTargetMachine(const Target &T,
                                     const std::string &TargetTriple)
  : TargetMachine(T) {
  AsmInfo = T.createAsmInfo(TargetTriple);
}

// Set the default code model for the JIT for a generic target.
// FIXME: Is small right here? or .is64Bit() ? Large : Small?
void
LLVMTargetMachine::setCodeModelForJIT() {
  setCodeModel(CodeModel::Small);
}

// Set the default code model for static compilation for a generic target.
void
LLVMTargetMachine::setCodeModelForStatic() {
  setCodeModel(CodeModel::Small);
}

bool LLVMTargetMachine::addPassesToEmitFile(PassManagerBase &PM,
                                            formatted_raw_ostream &Out,
                                            CodeGenFileType FileType,
                                            CodeGenOpt::Level OptLevel,
                                            bool DisableVerify) {
  // Add common CodeGen passes.
  if (addCommonCodeGenPasses(PM, OptLevel, DisableVerify))
    return true;

  OwningPtr<MCContext> Context(new MCContext());
  OwningPtr<MCStreamer> AsmStreamer;

  formatted_raw_ostream *LegacyOutput;
  switch (FileType) {
  default: return true;
  case CGFT_AssemblyFile: {
    const MCAsmInfo &MAI = *getMCAsmInfo();
    MCInstPrinter *InstPrinter =
      getTarget().createMCInstPrinter(MAI.getAssemblerDialect(), MAI, Out);
    AsmStreamer.reset(createAsmStreamer(*Context, Out, MAI,
                                        getTargetData()->isLittleEndian(),
                                        getVerboseAsm(), InstPrinter,
                                        /*codeemitter*/0));
    // Set the AsmPrinter's "O" to the output file.
    LegacyOutput = &Out;
    break;
  }
  case CGFT_ObjectFile: {
    // Create the code emitter for the target if it exists.  If not, .o file
    // emission fails.
    MCCodeEmitter *MCE = getTarget().createCodeEmitter(*this, *Context);
    if (MCE == 0)
      return true;
    
    AsmStreamer.reset(createMachOStreamer(*Context, Out, MCE));
    
    // Any output to the asmprinter's "O" stream is bad and needs to be fixed,
    // force it to come out stderr.
    // FIXME: this is horrible and leaks, eventually remove the raw_ostream from
    // asmprinter.
    LegacyOutput = new formatted_raw_ostream(errs());
    break;
  }
  case CGFT_Null:
    // The Null output is intended for use for performance analysis and testing,
    // not real users.
    AsmStreamer.reset(createNullStreamer(*Context));
    // Any output to the asmprinter's "O" stream is bad and needs to be fixed,
    // force it to come out stderr.
    // FIXME: this is horrible and leaks, eventually remove the raw_ostream from
    // asmprinter.
    LegacyOutput = new formatted_raw_ostream(errs());
    break;
  }
  
  // Create the AsmPrinter, which takes ownership of Context and AsmStreamer
  // if successful.
  FunctionPass *Printer =
    getTarget().createAsmPrinter(*LegacyOutput, *this, *Context, *AsmStreamer,
                                 getMCAsmInfo());
  if (Printer == 0)
    return true;
  
  // If successful, createAsmPrinter took ownership of AsmStreamer and Context.
  Context.take(); AsmStreamer.take();
  
  PM.add(Printer);
  
  // Make sure the code model is set.
  setCodeModelForStatic();
  PM.add(createGCInfoDeleter());
  return false;
}

/// addPassesToEmitMachineCode - Add passes to the specified pass manager to
/// get machine code emitted.  This uses a JITCodeEmitter object to handle
/// actually outputting the machine code and resolving things like the address
/// of functions.  This method should returns true if machine code emission is
/// not supported.
///
bool LLVMTargetMachine::addPassesToEmitMachineCode(PassManagerBase &PM,
                                                   JITCodeEmitter &JCE,
                                                   CodeGenOpt::Level OptLevel,
                                                   bool DisableVerify) {
  // Make sure the code model is set.
  setCodeModelForJIT();
  
  // Add common CodeGen passes.
  if (addCommonCodeGenPasses(PM, OptLevel, DisableVerify))
    return true;

  addCodeEmitter(PM, OptLevel, JCE);
  PM.add(createGCInfoDeleter());

  return false; // success!
}

static void printNoVerify(PassManagerBase &PM,
                           const char *Banner) {
  if (PrintMachineCode)
    PM.add(createMachineFunctionPrinterPass(dbgs(), Banner));
}

static void printAndVerify(PassManagerBase &PM,
                           const char *Banner,
                           bool allowDoubleDefs = false) {
  if (PrintMachineCode)
    PM.add(createMachineFunctionPrinterPass(dbgs(), Banner));

  if (VerifyMachineCode)
    PM.add(createMachineVerifierPass(allowDoubleDefs));
}

/// addCommonCodeGenPasses - Add standard LLVM codegen passes used for both
/// emitting to assembly files or machine code output.
///
bool LLVMTargetMachine::addCommonCodeGenPasses(PassManagerBase &PM,
                                               CodeGenOpt::Level OptLevel,
                                               bool DisableVerify) {
  // Standard LLVM-Level Passes.

  // Before running any passes, run the verifier to determine if the input
  // coming from the front-end and/or optimizer is valid.
  if (!DisableVerify)
    PM.add(createVerifierPass());

  // Optionally, tun split-GEPs and no-load GVN.
  if (EnableSplitGEPGVN) {
    PM.add(createGEPSplitterPass());
    PM.add(createGVNPass(/*NoLoads=*/true));
  }

  // Run loop strength reduction before anything else.
  if (OptLevel != CodeGenOpt::None && !DisableLSR) {
    PM.add(createLoopStrengthReducePass(getTargetLowering()));
    if (PrintLSR)
      PM.add(createPrintFunctionPass("\n\n*** Code after LSR ***\n", &dbgs()));
  }

  // Turn exception handling constructs into something the code generators can
  // handle.
  switch (getMCAsmInfo()->getExceptionHandlingType())
  {
  case ExceptionHandling::SjLj:
    // SjLj piggy-backs on dwarf for this bit. The cleanups done apply to both
    // Dwarf EH prepare needs to be run after SjLj prepare. Otherwise,
    // catch info can get misplaced when a selector ends up more than one block
    // removed from the parent invoke(s). This could happen when a landing
    // pad is shared by multiple invokes and is also a target of a normal
    // edge from elsewhere.
    PM.add(createSjLjEHPass(getTargetLowering()));
    PM.add(createDwarfEHPass(getTargetLowering(), OptLevel==CodeGenOpt::None));
    break;
  case ExceptionHandling::Dwarf:
    PM.add(createDwarfEHPass(getTargetLowering(), OptLevel==CodeGenOpt::None));
    break;
  case ExceptionHandling::None:
    PM.add(createLowerInvokePass(getTargetLowering()));
    break;
  }

  PM.add(createGCLoweringPass());

  // Make sure that no unreachable blocks are instruction selected.
  PM.add(createUnreachableBlockEliminationPass());

  if (OptLevel != CodeGenOpt::None && !DisableCGP)
    PM.add(createCodeGenPreparePass(getTargetLowering()));

  PM.add(createStackProtectorPass(getTargetLowering()));

  if (PrintISelInput)
    PM.add(createPrintFunctionPass("\n\n"
                                   "*** Final LLVM Code input to ISel ***\n",
                                   &dbgs()));

  // All passes which modify the LLVM IR are now complete; run the verifier
  // to ensure that the IR is valid.
  if (!DisableVerify)
    PM.add(createVerifierPass());

  // Standard Lower-Level Passes.

  // Set up a MachineFunction for the rest of CodeGen to work on.
  PM.add(new MachineFunctionAnalysis(*this, OptLevel));

  // Enable FastISel with -fast, but allow that to be overridden.
  if (EnableFastISelOption == cl::BOU_TRUE ||
      (OptLevel == CodeGenOpt::None && EnableFastISelOption != cl::BOU_FALSE))
    EnableFastISel = true;

  // Ask the target for an isel.
  if (addInstSelector(PM, OptLevel))
    return true;

  // Print the instruction selected machine code...
  printAndVerify(PM, "After Instruction Selection",
                 /* allowDoubleDefs= */ true);

  // Optimize PHIs before DCE: removing dead PHI cycles may make more
  // instructions dead.
  if (OptLevel != CodeGenOpt::None)
    PM.add(createOptimizePHIsPass());

  // Delete dead machine instructions regardless of optimization level.
  PM.add(createDeadMachineInstructionElimPass());
  printAndVerify(PM, "After codegen DCE pass",
                 /* allowDoubleDefs= */ true);

  if (OptLevel != CodeGenOpt::None) {
    PM.add(createOptimizeExtsPass());
    if (!DisableMachineLICM)
      PM.add(createMachineLICMPass());
    if (EnableMachineCSE)
      PM.add(createMachineCSEPass());
    if (!DisableMachineSink)
      PM.add(createMachineSinkingPass());
    printAndVerify(PM, "After MachineLICM and MachineSinking",
                   /* allowDoubleDefs= */ true);
  }

  // Pre-ra tail duplication.
  if (OptLevel != CodeGenOpt::None && !DisableEarlyTailDup) {
    PM.add(createTailDuplicatePass(true));
    printAndVerify(PM, "After Pre-RegAlloc TailDuplicate",
                   /* allowDoubleDefs= */ true);
  }

  // Run pre-ra passes.
  if (addPreRegAlloc(PM, OptLevel))
    printAndVerify(PM, "After PreRegAlloc passes",
                   /* allowDoubleDefs= */ true);

  // Perform register allocation.
  PM.add(createRegisterAllocator());
  printAndVerify(PM, "After Register Allocation");

  // Perform stack slot coloring.
  if (OptLevel != CodeGenOpt::None && !DisableSSC) {
    // FIXME: Re-enable coloring with register when it's capable of adding
    // kill markers.
    PM.add(createStackSlotColoringPass(false));
    printAndVerify(PM, "After StackSlotColoring");
  }

  // Run post-ra passes.
  if (addPostRegAlloc(PM, OptLevel))
    printAndVerify(PM, "After PostRegAlloc passes");

  PM.add(createLowerSubregsPass());
  printAndVerify(PM, "After LowerSubregs");

  // Insert prolog/epilog code.  Eliminate abstract frame index references...
  PM.add(createPrologEpilogCodeInserter());
  printAndVerify(PM, "After PrologEpilogCodeInserter");

  // Run pre-sched2 passes.
  if (addPreSched2(PM, OptLevel))
    printAndVerify(PM, "After PreSched2 passes");

  // Second pass scheduler.
  if (OptLevel != CodeGenOpt::None && !DisablePostRA) {
    PM.add(createPostRAScheduler(OptLevel));
    printAndVerify(PM, "After PostRAScheduler");
  }

  // Branch folding must be run after regalloc and prolog/epilog insertion.
  if (OptLevel != CodeGenOpt::None && !DisableBranchFold) {
    PM.add(createBranchFoldingPass(getEnableTailMergeDefault()));
    printNoVerify(PM, "After BranchFolding");
  }

  // Tail duplication.
  if (OptLevel != CodeGenOpt::None && !DisableTailDuplicate) {
    PM.add(createTailDuplicatePass(false));
    printNoVerify(PM, "After TailDuplicate");
  }

  PM.add(createGCMachineCodeAnalysisPass());

  if (PrintGCInfo)
    PM.add(createGCInfoPrinter(dbgs()));

  if (OptLevel != CodeGenOpt::None && !DisableCodePlace) {
    PM.add(createCodePlacementOptPass());
    printNoVerify(PM, "After CodePlacementOpt");
  }

  if (addPreEmitPass(PM, OptLevel))
    printNoVerify(PM, "After PreEmit passes");

  return false;
}
