//===--- Backend.cpp - Interface to LLVM backend technologies -------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "clang/Frontend/ASTConsumers.h"
#include "clang/AST/ASTConsumer.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/DeclGroup.h"
#include "clang/Basic/TargetInfo.h"
#include "clang/Basic/TargetOptions.h"
#include "clang/CodeGen/CodeGenOptions.h"
#include "clang/CodeGen/ModuleBuilder.h"
#include "llvm/Module.h"
#include "llvm/ModuleProvider.h"
#include "llvm/PassManager.h"
#include "llvm/ADT/OwningPtr.h"
#include "llvm/Assembly/PrintModulePass.h"
#include "llvm/Analysis/CallGraph.h"
#include "llvm/Analysis/Verifier.h"
#include "llvm/Bitcode/ReaderWriter.h"
#include "llvm/CodeGen/RegAllocRegistry.h"
#include "llvm/CodeGen/SchedulerRegistry.h"
#include "llvm/Support/FormattedStream.h"
#include "llvm/Support/StandardPasses.h"
#include "llvm/Support/Timer.h"
#include "llvm/Target/SubtargetFeature.h"
#include "llvm/Target/TargetData.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/Target/TargetRegistry.h"
using namespace clang;
using namespace llvm;

namespace {
  class BackendConsumer : public ASTConsumer {
    BackendAction Action;
    CodeGenOptions CodeGenOpts;
    TargetOptions TargetOpts;
    llvm::raw_ostream *AsmOutStream;
    llvm::formatted_raw_ostream FormattedOutStream;
    ASTContext *Context;

    Timer LLVMIRGeneration;
    Timer CodeGenerationTime;

    llvm::OwningPtr<CodeGenerator> Gen;

    llvm::Module *TheModule;
    llvm::TargetData *TheTargetData;

    mutable llvm::ModuleProvider *ModuleProvider;
    mutable FunctionPassManager *CodeGenPasses;
    mutable PassManager *PerModulePasses;
    mutable FunctionPassManager *PerFunctionPasses;

    FunctionPassManager *getCodeGenPasses() const;
    PassManager *getPerModulePasses() const;
    FunctionPassManager *getPerFunctionPasses() const;

    void CreatePasses();

    /// AddEmitPasses - Add passes necessary to emit assembly or LLVM
    /// IR.
    ///
    /// \return True on success. On failure \arg Error will be set to
    /// a user readable error message.
    bool AddEmitPasses(std::string &Error);

    void EmitAssembly();

  public:
    BackendConsumer(BackendAction action, Diagnostic &Diags,
                    const LangOptions &langopts, const CodeGenOptions &compopts,
                    const TargetOptions &targetopts, const std::string &infile,
                    llvm::raw_ostream* OS, LLVMContext& C) :
      Action(action),
      CodeGenOpts(compopts),
      TargetOpts(targetopts),
      AsmOutStream(OS),
      LLVMIRGeneration("LLVM IR Generation Time"),
      CodeGenerationTime("Code Generation Time"),
      Gen(CreateLLVMCodeGen(Diags, infile, compopts, C)),
      TheModule(0), TheTargetData(0), ModuleProvider(0),
      CodeGenPasses(0), PerModulePasses(0), PerFunctionPasses(0) {

      if (AsmOutStream)
        FormattedOutStream.setStream(*AsmOutStream,
                                     formatted_raw_ostream::PRESERVE_STREAM);

      // Enable -time-passes if -ftime-report is enabled.
      llvm::TimePassesIsEnabled = CodeGenOpts.TimePasses;
    }

    ~BackendConsumer() {
      delete TheTargetData;
      delete ModuleProvider;
      delete CodeGenPasses;
      delete PerModulePasses;
      delete PerFunctionPasses;
    }

    virtual void Initialize(ASTContext &Ctx) {
      Context = &Ctx;

      if (CodeGenOpts.TimePasses)
        LLVMIRGeneration.startTimer();

      Gen->Initialize(Ctx);

      TheModule = Gen->GetModule();
      ModuleProvider = new ExistingModuleProvider(TheModule);
      TheTargetData = new llvm::TargetData(Ctx.Target.getTargetDescription());

      if (CodeGenOpts.TimePasses)
        LLVMIRGeneration.stopTimer();
    }

    virtual void HandleTopLevelDecl(DeclGroupRef D) {
      PrettyStackTraceDecl CrashInfo(*D.begin(), SourceLocation(),
                                     Context->getSourceManager(),
                                     "LLVM IR generation of declaration");

      if (CodeGenOpts.TimePasses)
        LLVMIRGeneration.startTimer();

      Gen->HandleTopLevelDecl(D);

      if (CodeGenOpts.TimePasses)
        LLVMIRGeneration.stopTimer();
    }

    virtual void HandleTranslationUnit(ASTContext &C) {
      {
        PrettyStackTraceString CrashInfo("Per-file LLVM IR generation");
        if (CodeGenOpts.TimePasses)
          LLVMIRGeneration.startTimer();

        Gen->HandleTranslationUnit(C);

        if (CodeGenOpts.TimePasses)
          LLVMIRGeneration.stopTimer();
      }

      // EmitAssembly times and registers crash info itself.
      EmitAssembly();

      // Force a flush here in case we never get released.
      if (AsmOutStream)
        FormattedOutStream.flush();
    }

    virtual void HandleTagDeclDefinition(TagDecl *D) {
      PrettyStackTraceDecl CrashInfo(D, SourceLocation(),
                                     Context->getSourceManager(),
                                     "LLVM IR generation of declaration");
      Gen->HandleTagDeclDefinition(D);
    }

    virtual void CompleteTentativeDefinition(VarDecl *D) {
      Gen->CompleteTentativeDefinition(D);
    }
  };
}

FunctionPassManager *BackendConsumer::getCodeGenPasses() const {
  if (!CodeGenPasses) {
    CodeGenPasses = new FunctionPassManager(ModuleProvider);
    CodeGenPasses->add(new TargetData(*TheTargetData));
  }

  return CodeGenPasses;
}

PassManager *BackendConsumer::getPerModulePasses() const {
  if (!PerModulePasses) {
    PerModulePasses = new PassManager();
    PerModulePasses->add(new TargetData(*TheTargetData));
  }

  return PerModulePasses;
}

FunctionPassManager *BackendConsumer::getPerFunctionPasses() const {
  if (!PerFunctionPasses) {
    PerFunctionPasses = new FunctionPassManager(ModuleProvider);
    PerFunctionPasses->add(new TargetData(*TheTargetData));
  }

  return PerFunctionPasses;
}

bool BackendConsumer::AddEmitPasses(std::string &Error) {
  if (Action == Backend_EmitNothing)
    return true;

  if (Action == Backend_EmitBC) {
    getPerModulePasses()->add(createBitcodeWriterPass(FormattedOutStream));
  } else if (Action == Backend_EmitLL) {
    getPerModulePasses()->add(createPrintModulePass(&FormattedOutStream));
  } else {
    bool Fast = CodeGenOpts.OptimizationLevel == 0;

    // Create the TargetMachine for generating code.
    std::string Triple = TheModule->getTargetTriple();
    const llvm::Target *TheTarget = TargetRegistry::lookupTarget(Triple, Error);
    if (!TheTarget) {
      Error = std::string("Unable to get target machine: ") + Error;
      return false;
    }

    // FIXME: Expose these capabilities via actual APIs!!!! Aside from just
    // being gross, this is also totally broken if we ever care about
    // concurrency.
    std::vector<const char *> BackendArgs;
    BackendArgs.push_back("clang"); // Fake program name.
    if (CodeGenOpts.AsmVerbose)
      BackendArgs.push_back("-asm-verbose");
    if (!CodeGenOpts.CodeModel.empty()) {
      BackendArgs.push_back("-code-model");
      BackendArgs.push_back(CodeGenOpts.CodeModel.c_str());
    }
    if (!CodeGenOpts.DebugPass.empty()) {
      BackendArgs.push_back("-debug-pass");
      BackendArgs.push_back(CodeGenOpts.DebugPass.c_str());
    }
    if (CodeGenOpts.DisableFPElim)
      BackendArgs.push_back("-disable-fp-elim");
    if (!CodeGenOpts.LimitFloatPrecision.empty()) {
      BackendArgs.push_back("-limit-float-precision");
      BackendArgs.push_back(CodeGenOpts.LimitFloatPrecision.c_str());
    }
    if (CodeGenOpts.NoZeroInitializedInBSS)
      BackendArgs.push_back("-nozero-initialized-in-bss");
    BackendArgs.push_back("-relocation-model");
    BackendArgs.push_back(CodeGenOpts.RelocationModel.c_str());
    if (CodeGenOpts.TimePasses)
      BackendArgs.push_back("-time-passes");
    if (CodeGenOpts.UnwindTables)
      BackendArgs.push_back("-unwind-tables");
    BackendArgs.push_back(0);
    llvm::cl::ParseCommandLineOptions(BackendArgs.size() - 1,
                                      (char**) &BackendArgs[0]);

    std::string FeaturesStr;
    if (TargetOpts.CPU.size() || TargetOpts.Features.size()) {
      SubtargetFeatures Features;
      Features.setCPU(TargetOpts.CPU);
      for (std::vector<std::string>::iterator
             it = TargetOpts.Features.begin(),
             ie = TargetOpts.Features.end(); it != ie; ++it)
        Features.AddFeature(*it);
      FeaturesStr = Features.getString();
    }
    TargetMachine *TM = TheTarget->createTargetMachine(Triple, FeaturesStr);

    // Set register scheduler & allocation policy.
    RegisterScheduler::setDefault(createDefaultScheduler);
    RegisterRegAlloc::setDefault(Fast ? createLocalRegisterAllocator :
                                 createLinearScanRegisterAllocator);

    // From llvm-gcc:
    // If there are passes we have to run on the entire module, we do codegen
    // as a separate "pass" after that happens.
    // FIXME: This is disabled right now until bugs can be worked out.  Reenable
    // this for fast -O0 compiles!
    FunctionPassManager *PM = getCodeGenPasses();
    CodeGenOpt::Level OptLevel = CodeGenOpt::Default;

    switch (CodeGenOpts.OptimizationLevel) {
    default: break;
    case 0: OptLevel = CodeGenOpt::None; break;
    case 3: OptLevel = CodeGenOpt::Aggressive; break;
    }

    // Normal mode, emit a .s file by running the code generator.
    // Note, this also adds codegenerator level optimization passes.
    switch (TM->addPassesToEmitFile(*PM, FormattedOutStream,
                                    TargetMachine::AssemblyFile, OptLevel)) {
    default:
    case FileModel::Error:
      Error = "Unable to interface with target machine!\n";
      return false;
    case FileModel::AsmFile:
      break;
    }

    if (TM->addPassesToEmitFileFinish(*CodeGenPasses, (MachineCodeEmitter *)0,
                                      OptLevel)) {
      Error = "Unable to interface with target machine!\n";
      return false;
    }
  }

  return true;
}

void BackendConsumer::CreatePasses() {
  unsigned OptLevel = CodeGenOpts.OptimizationLevel;
  CodeGenOptions::InliningMethod Inlining = CodeGenOpts.Inlining;

  // Handle disabling of LLVM optimization, where we want to preserve the
  // internal module before any optimization.
  if (CodeGenOpts.DisableLLVMOpts) {
    OptLevel = 0;
    Inlining = CodeGenOpts.NoInlining;
  }

  // In -O0 if checking is disabled, we don't even have per-function passes.
  if (CodeGenOpts.VerifyModule)
    getPerFunctionPasses()->add(createVerifierPass());

  // Assume that standard function passes aren't run for -O0.
  if (OptLevel > 0)
    llvm::createStandardFunctionPasses(getPerFunctionPasses(), OptLevel);

  llvm::Pass *InliningPass = 0;
  switch (Inlining) {
  case CodeGenOptions::NoInlining: break;
  case CodeGenOptions::NormalInlining: {
    // Inline small functions
    unsigned Threshold = (CodeGenOpts.OptimizeSize || OptLevel < 3) ? 50 : 200;
    InliningPass = createFunctionInliningPass(Threshold);
    break;
  }
  case CodeGenOptions::OnlyAlwaysInlining:
    InliningPass = createAlwaysInlinerPass();         // Respect always_inline
    break;
  }

  // For now we always create per module passes.
  PassManager *PM = getPerModulePasses();
  llvm::createStandardModulePasses(PM, OptLevel, CodeGenOpts.OptimizeSize,
                                   CodeGenOpts.UnitAtATime,
                                   CodeGenOpts.UnrollLoops,
                                   CodeGenOpts.SimplifyLibCalls,
                                   /*HaveExceptions=*/true,
                                   InliningPass);
}

/// EmitAssembly - Handle interaction with LLVM backend to generate
/// actual machine code.
void BackendConsumer::EmitAssembly() {
  // Silently ignore if we weren't initialized for some reason.
  if (!TheModule || !TheTargetData)
    return;

  TimeRegion Region(CodeGenOpts.TimePasses ? &CodeGenerationTime : 0);

  // Make sure IR generation is happy with the module. This is
  // released by the module provider.
  Module *M = Gen->ReleaseModule();
  if (!M) {
    // The module has been released by IR gen on failures, do not
    // double free.
    ModuleProvider->releaseModule();
    TheModule = 0;
    return;
  }

  assert(TheModule == M && "Unexpected module change during IR generation");

  CreatePasses();

  std::string Error;
  if (!AddEmitPasses(Error)) {
    // FIXME: Don't fail this way.
    llvm::errs() << "ERROR: " << Error << "\n";
    ::exit(1);
  }

  // Run passes. For now we do all passes at once, but eventually we
  // would like to have the option of streaming code generation.

  if (PerFunctionPasses) {
    PrettyStackTraceString CrashInfo("Per-function optimization");

    PerFunctionPasses->doInitialization();
    for (Module::iterator I = M->begin(), E = M->end(); I != E; ++I)
      if (!I->isDeclaration())
        PerFunctionPasses->run(*I);
    PerFunctionPasses->doFinalization();
  }

  if (PerModulePasses) {
    PrettyStackTraceString CrashInfo("Per-module optimization passes");
    PerModulePasses->run(*M);
  }

  if (CodeGenPasses) {
    PrettyStackTraceString CrashInfo("Code generation");
    CodeGenPasses->doInitialization();
    for (Module::iterator I = M->begin(), E = M->end(); I != E; ++I)
      if (!I->isDeclaration())
        CodeGenPasses->run(*I);
    CodeGenPasses->doFinalization();
  }
}

ASTConsumer *clang::CreateBackendConsumer(BackendAction Action,
                                          Diagnostic &Diags,
                                          const LangOptions &LangOpts,
                                          const CodeGenOptions &CodeGenOpts,
                                          const TargetOptions &TargetOpts,
                                          const std::string& InFile,
                                          llvm::raw_ostream* OS,
                                          LLVMContext& C) {
  return new BackendConsumer(Action, Diags, LangOpts, CodeGenOpts,
                             TargetOpts, InFile, OS, C);
}
