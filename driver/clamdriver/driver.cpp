//
//  Driver for ClamAV bytecode compiler.
//
//     Based on Clang's driver, opt and llc, which has this license:
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "llvm/Config/config.h"
#include "llvm/LLVMContext.h"
#include "llvm/Module.h"
#include "llvm/PassManager.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/IRReader.h"
#include "llvm/Support/FormattedStream.h"
#include "llvm/Support/ManagedStatic.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/PrettyStackTrace.h"
#include "llvm/Support/StandardPasses.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/System/Errno.h"
#include "llvm/System/Path.h"
#include "llvm/System/Program.h"
#include "llvm/System/Signals.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/Target/TargetRegistry.h"
#include "llvm/Target/TargetData.h"
#include "../tools/clang/include/clang/Basic/Version.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Basic/TargetInfo.h"
#include "clang/Basic/Version.h"
#include "clang/Driver/Arg.h"
#include "clang/Driver/ArgList.h"
#include "clang/Driver/CC1Options.h"
#include "clang/Driver/DriverDiagnostic.h"
#include "clang/Driver/OptTable.h"
#include "clang/Frontend/CodeGenAction.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/CompilerInvocation.h"
#include "clang/Frontend/FrontendActions.h"
#include "clang/Frontend/FrontendDiagnostic.h"
#include "clang/Frontend/FrontendPluginRegistry.h"
#include "clang/Frontend/FrontendOptions.h"
#include "clang/Frontend/TextDiagnosticBuffer.h"
#include "clang/Frontend/TextDiagnosticPrinter.h"
#include "clang/Frontend/VerifyDiagnosticsClient.h"
#include "llvm/LLVMContext.h"
#include "llvm/ADT/OwningPtr.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/ManagedStatic.h"
#include "llvm/Support/PrettyStackTrace.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/System/DynamicLibrary.h"
#include "llvm/System/Host.h"
#include "llvm/System/Path.h"
#include "llvm/System/Signals.h"
#include "llvm/Target/TargetSelect.h"
#include "driver.h"
#include <cstdio>
#ifdef LLVM_ON_UNIX
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#endif
extern "C" {
#include "tar.h"
}
#include <fcntl.h>
#include <cstring>
#include <cerrno>

using namespace llvm;
using namespace clang;
llvm::sys::Path GetExecutablePath(const char *Argv0) {
  // This just needs to be some symbol in the binary; C++ doesn't
  // allow taking the address of ::main however.
  void *P = (void*) (intptr_t) GetExecutablePath;
  return llvm::sys::Path::GetMainExecutable(Argv0, P);
}

extern "C" const char* clambc_getversion(void);

static void printVersion(raw_ostream &Err, bool printVer = true)
{
  Err << "ClamAV bytecode compiler version " << clambc_getversion() << ", running on " << HOST_OS << "\n  "\
      << (LLVM_MULTITHREADED ? "multi-threaded" : "") << " build"
#if _DEBUG || _GLIBCXX_DEBUG
      << " with"
#endif
#ifdef _DEBUG
      << " assertions"
#endif
#if _DEBUG && _GLIBCXX_DEBUG
      << " with"
#endif
#ifdef _GLIBCXX_DEBUG
      << " expensive checks"
#endif
      << ", using: \n";
  if (printVer)
    cl::PrintVersionMessage();
}

static std::string getTmpDir()
{
  char *tmpstr;
  std::string tmpfix;

  if ((tmpstr = getenv("TMPDIR")))
    tmpfix = tmpstr;
  else if ((tmpstr = getenv("TMP")))
    tmpfix = tmpstr;
  else
    tmpfix = sys::Path::GetTemporaryDirectory().str();

  return tmpfix;
}

static int printICE(int Res, const char **Argv, raw_ostream &Err,
                    bool insidebugreport,
                    int argc, const char **argv, const sys::Path* orig_err)
{
  Err << "Program arguments:";
  while (*Argv) {
    Err << " " << Argv[0];
    Argv++;
  }
  Err << "\n";
  Err.changeColor(raw_ostream::RED, true);
  Err << "\nInternal compiler error: ";
#ifdef LLVM_ON_UNIX
  Err << strsignal(Res);
#else
  Err << " killed by signal " << Res;
#endif
  Err << "!\n";
  Err.resetColor();
  Err.changeColor(raw_ostream::SAVEDCOLOR, true);
  if (insidebugreport)
    return 2;

  std::string prefix, prepath, tmperr, tarpath;
  prefix = getTmpDir();
  if (prefix.empty()) {
      Err << "Cannot open locate location to store temporary files\n";
      return 117;
  }
  tmperr = prefix + "/bugreport-preprocessed";
  prepath = prefix + "/bugreport-tmperr";
  tarpath = prefix + "/bugreport.tar";

  sys::Path Tmp(prepath);
  sys::Path TmpErr(tmperr);
  sys::Path TmpOut(tarpath);
  std::string ErrMsg;
  ErrMsg.clear();
  if (Tmp.createTemporaryFileOnDisk(true, &ErrMsg) ||
      TmpErr.createTemporaryFileOnDisk(true, &ErrMsg) ||
      TmpOut.createTemporaryFileOnDisk(true, &ErrMsg)) {
    Err << "Unable to create temporary file for bugreport: " << ErrMsg << "\n\n";
    Err << "Please submit a bugreport at http://bugs.clamav.net\n" ;
    Err << "Please include the full sourcecode that caused this internal compiler error and the full error message!\n";
  } else {
    ErrMsg.clear();
    raw_fd_ostream TmpErrF(TmpErr.c_str(), ErrMsg);
    // Create version info for bugreport
    CompileFile(argc, argv, &Tmp, &TmpErr, TmpErrF, true, true);
    // Create preprocessed file for bugreport
    CompileFile(argc, argv, &Tmp, &TmpErr, TmpErrF, true);
    TmpErrF.close();
    int fd = open(TmpOut.c_str(), O_WRONLY);
    if (fd < 0) {
      Err << "Cannot open file " << TmpOut.str() << ": " << strerror(errno) << 
        "\n";
    } else {
      chdir(orig_err->getDirname().str().c_str());
      tar_addfile(fd, orig_err->getLast().str().c_str());
      chdir(Tmp.getDirname().str().c_str());
      tar_addfile(fd, Tmp.getLast().str().c_str());
      chdir(TmpErr.getDirname().str().c_str());
      tar_addfile(fd, TmpErr.getLast().str().c_str());
      close(fd);
    }

    Tmp.eraseFromDisk();
    TmpErr.eraseFromDisk();
    Err << "Please submit a bugreport at http://bugs.clamav.net\n" ;
    Err << "Please compress and attach this file to the bugreport: " << TmpOut.str() << "\n";
  }

  Err.resetColor();
  return 42;
}

static void printFile(const sys::Path *err)
{
  std::string ErrMsg;
  ErrMsg.clear();
  MemoryBuffer *buf = MemoryBuffer::getFile(err->c_str(), &ErrMsg);
  errs().write(buf->getBufferStart(), buf->getBufferSize());
  delete buf;
}

extern int cc1_main(const char **ArgBegin, const char **ArgEnd,
                    const char *Argv0, void *MainAddr);

static int compileInternal(const char *input, int optimize, int optsize,
                           const char *argv0,
                           raw_fd_ostream *fd, CompilerInstance &Clang)
{
  std::string ErrMsg;
  LLVMContext &Context = getGlobalContext();
  std::auto_ptr<Module> M;

  MemoryBuffer *Buffer = MemoryBuffer::getFileOrSTDIN(input, &ErrMsg);
  if (!Buffer) {
    errs() << "Could not open temp input file '" << input << "'\n";
    return 2;
  }
  M.reset(ParseBitcodeFile(Buffer, Context, &ErrMsg));
  delete Buffer;
  if (M.get() == 0) {
    errs() << "Cannot parse temp input file '" << input << "'" << ErrMsg << "\n";
    return 2;
  }

  // FIXME: Remove TargetData!
  //XXX  M->setTargetTriple("");
  //XXX  M->setDataLayout("");

  // TODO: let clang handle these
  PassManager Passes;
  FunctionPassManager *FPasses = NULL;
  if (optimize) {
    FPasses = new FunctionPassManager(M.get());
//    FPasses->add(new TargetData(M.get()));//XXX
    createStandardFunctionPasses(FPasses, optimize);
  }
//  Passes.add(new TargetData(M.get()));//XXX
  unsigned threshold = optsize ? 75 : optimize > 2 ? 275 : 225;
  createStandardModulePasses(&Passes, optimize,
                             optsize,
                             true,
                             optimize > 1 && !optsize,
                             false,
                             false,
                             optimize > 1 ?
                             createFunctionInliningPass(threshold) :
                             createAlwaysInlinerPass());
  if (optimize) {
    FPasses->doInitialization();
    for (Module::iterator I = M.get()->begin(), E = M.get()->end();
         I != E; ++I)
      FPasses->run(*I);
    Passes.add(createVerifierPass());
    Passes.run(*M.get());
  }

  std::string Err2;
  //TODO: directly construct our target
  const Target *TheTarget =
    TargetRegistry::lookupTarget("clambc-generic-generic", Err2);
  if (TheTarget == 0) {
    errs() << argv0 << ": error auto-selecting target for module '"
      << Err2 << "'.  Please use the -march option to explicitly "
      << "pick a target.\n";
    return 1;
  }
  std::auto_ptr<TargetMachine> 
    Target(TheTarget->createTargetMachine("clambc-generic-generic", ""));
  //TODO: send it to the -o specified on cmdline
  // Figure out where we are going to send the output...
  formatted_raw_ostream *Out2 =
    new formatted_raw_ostream(*fd, formatted_raw_ostream::DELETE_STREAM);
  if (Out2 == 0) return 2;

  CodeGenOpt::Level OLvl = CodeGenOpt::Default;
  switch (optimize) {
  case 0: OLvl = CodeGenOpt::None; break;
  case 3: OLvl = CodeGenOpt::Aggressive; break;
  default: break;
  }

  PassManager PM;
  PM.add(new TargetData(M.get()));//XXX
  if (Target->addPassesToEmitWholeFile(PM, *Out2, TargetMachine::CGFT_AssemblyFile, OLvl)) {
      errs() << argv0<< ": target does not support generation of this"
             << " file type!\n";
      if (Out2 != &fouts()) delete Out2;
      // And the Out file is empty and useless, so remove it now.
//      sys::Path(OutputFilename).eraseFromDisk();
      return 2;
  }
  PM.run(*M.get());
  delete Out2;
  return 0;
}

void LLVMErrorHandler(void *UserData, const std::string &Message) {
  Diagnostic &Diags = *static_cast<Diagnostic*>(UserData);

  Diags.Report(diag::err_fe_error_backend) << Message;

  // We cannot recover from llvm errors.
  exit(1);
}

static FrontendAction *CreateFrontendAction(CompilerInstance &CI) {
  using namespace clang::frontend;

  switch (CI.getFrontendOpts().ProgramAction) {
  default:
    llvm_unreachable("Invalid program action!");

  case EmitBC:                 return new EmitBCAction();
  case PrintPreprocessedInput: return new PrintPreprocessedAction();
  }
}

int re2c_main(int argc, char *argv[]);
static int CompileSubprocess(const char **argv, int argc, 
                             sys::Path &ResourceDir, bool bugreport,
                             bool versionOnly, sys::Path &apiMapPath)
{
  std::vector<char*> llvmArgs;
  char apim[] = "-clam-apimap";
  llvmArgs.push_back((char*)argv[0]);
  llvmArgs.push_back(apim);
  llvmArgs.push_back((char*)apiMapPath.c_str());

  // Split args into cc1 and LLVM args, separator is --
  int cc1_argc;
  for (cc1_argc=1;cc1_argc<argc;cc1_argc++) {
    if (StringRef(argv[cc1_argc]) == "--") {
      for (int i=cc1_argc+1;i<argc;i++) {
        llvmArgs.push_back((char*)argv[i]);
      }
      break;
    }
  }

  // Initialize CompilerInstance from commandline args
  CompilerInstance Clang;
  Clang.setLLVMContext(new llvm::LLVMContext);
  LLVMInitializeClamBCTargetInfo();
  LLVMInitializeClamBCTarget();

  TextDiagnosticBuffer DiagsBuffer;
  Diagnostic Diags(&DiagsBuffer);
  CompilerInvocation::CreateFromArgs(Clang.getInvocation(), argv+1,
                                     argv+cc1_argc, Diags);
  FrontendOptions &FrontendOpts = Clang.getInvocation().getFrontendOpts();
  // Handle --version
  if (FrontendOpts.ShowVersion || versionOnly) {
    printVersion(outs(), true);
    exit(0);
  }

  DiagnosticOptions &DiagOpts = Clang.getInvocation().getDiagnosticOpts();
  DiagOpts.ShowOptionNames = DiagOpts.ShowColors = 1;
  DiagOpts.MessageLength = 80;// we are writing to a file
  DiagOpts.Warnings.push_back("all");
  DiagOpts.Warnings.push_back("no-pointer-sign");

  Clang.createDiagnostics(argc-1, const_cast<char**>(argv+1));
  if (!Clang.hasDiagnostics())
    return 2;

  Clang.getInvocation().getHeaderSearchOpts().ResourceDir = ResourceDir.str();

  // Set default options
  LangOptions &LangOpts = Clang.getInvocation().getLangOpts();
  // This is a freestanding environment, without libc, etc.
  LangOpts.Freestanding = 1;
  HeaderSearchOptions &HeaderSearchOpts =
    Clang.getInvocation().getHeaderSearchOpts();
  HeaderSearchOpts.UseStandardIncludes = 0;
  if (bugreport)
    HeaderSearchOpts.Verbose = 1;

  if (FrontendOpts.ProgramAction != frontend::PrintPreprocessedInput)
    FrontendOpts.ProgramAction = frontend::EmitBC;
  if (bugreport)
    FrontendOpts.ProgramAction = frontend::PrintPreprocessedInput;

  // Don't bother freeing of memory on exit 
  FrontendOpts.DisableFree = 1;

  CodeGenOptions &Opts = Clang.getInvocation().getCodeGenOpts();
  Opts.Inlining = CodeGenOptions::OnlyAlwaysInlining;
  // always generate debug info, so that ClamBC backend can output sourcelevel
  // diagnostics.
  Opts.DebugInfo = true;
  // FIXME: once the verifier can work w/o targetdata, and targetdate opts set
  // DisableLLVMOpts to true!
  // This is needed to avoid target-specific optimizations
  Opts.DisableLLVMOpts = false;

  AnalyzerOptions &AOpts = Clang.getInvocation().getAnalyzerOpts();
  AOpts.AnalysisList.push_back(WarnDeadStores);
  AOpts.AnalysisList.push_back(WarnUninitVals);
  AOpts.AnalysisList.push_back(SecuritySyntacticChecks);
  AOpts.AnalysisList.push_back(WarnSizeofPointer);

  // Set triple
  Clang.getInvocation().getTargetOpts().Triple = "clambc-generic-generic";
  // Set default include
  Clang.getInvocation().getPreprocessorOpts().Includes.push_back("bytecode.h");

  // Set an LLVM error handler.
  llvm::llvm_install_error_handler(LLVMErrorHandler,
                                   static_cast<void*>(&Clang.getDiagnostics()));
  DiagsBuffer.FlushDiagnostics(Clang.getDiagnostics());
  // If there were any errors in processing arguments, exit now.
  if (Clang.getDiagnostics().getNumErrors())
    return 1;

  // Create the target instance.
  //TODO: directly create a clambc target
  Clang.setTarget(TargetInfo::CreateTargetInfo(Clang.getDiagnostics(),
                                               Clang.getTargetOpts()));
  if (!Clang.hasTarget())
    return 1;

  // Inform the target of the language options
  Clang.getTarget().setForcedLangOptions(Clang.getLangOpts());

  if (Clang.getHeaderSearchOpts().Verbose) {
    llvm::errs() << "clang -cc1 version " CLANG_VERSION_STRING
                 << " based upon " << PACKAGE_STRING
                 << " hosted on " << llvm::sys::getHostTriple() << "\n";
    // Convert the invocation back to argument strings.
    std::vector<std::string> InvocationArgs;
    Clang.getInvocation().toArgs(InvocationArgs);

    // Dump the converted arguments.
    llvm::SmallVector<const char*, 32> Invocation2Args;
    llvm::errs() << "invocation argv :";
    for (unsigned i = 0, e = InvocationArgs.size(); i != e; ++i) {
      Invocation2Args.push_back(InvocationArgs[i].c_str());
      llvm::errs() << " \"" << InvocationArgs[i] << '"';
    }
    llvm::errs() << "\n";
  }

  std::string Input = FrontendOpts.Inputs[0].second;
  if (Input == "-" && bugreport)
    return 2;
  raw_fd_ostream *fd = 0;
  if (FrontendOpts.ProgramAction == frontend::EmitBC) {
    // replace output file of compiler with a tempfile,
    // and save the final output filename.
    std::string FinalOutput = FrontendOpts.OutputFile;
    if (FinalOutput.empty()) {
      if (Input == "-")
        FinalOutput = "-";
      else {
        sys::Path P(sys::Path(Input).getBasename());
        P.appendSuffix("cbc");
        FinalOutput = P.str();
      }
    }
    llvm::raw_fd_ostream *tmpfd;
    std::string Err2;
    fd = Clang.createOutputFile(FinalOutput, Err2, false);
    if (!fd) {
      Clang.getDiagnostics().Report(clang::diag::err_drv_unable_to_make_temp) << Err2;
      return 1;
    }
    sys::Path P = sys::Path(FinalOutput);
    P.eraseSuffix();
    P.appendSuffix("tmp.bc");
    FrontendOpts.OutputFile = P.str();
    tmpfd = Clang.createOutputFile(P.str(), Err2, true);
    if (!tmpfd) {
      Clang.getDiagnostics().Report(clang::diag::err_drv_unable_to_make_temp) << Err2;
      return 1;
    }
    delete tmpfd;

    sys::RemoveFileOnSignal(sys::Path(FrontendOpts.OutputFile));
  }

  if (!FrontendOpts.Inputs.empty()) {
    char srcp[] = "-clambc-src";
    llvmArgs.push_back(srcp);
    llvmArgs.push_back(strdup(Input.c_str()));
  }

  // Parse LLVM commandline args
  cl::ParseCommandLineOptions(llvmArgs.size(), &llvmArgs[0]);

  std::string re2cpath = getTmpDir();
  if (re2cpath.empty()) {
    llvm::errs()<< "Failed to create temporary file for re2c-out!\n";
    return 2;
  }
  re2cpath += "/clambc-compiler-re2c-out";

  sys::Path TmpRe2C(re2cpath);
  if (!FrontendOpts.Inputs.empty()) {
    char re2c_args[] = "--no-generation-date";
    char re2c_o[] = "-o";
    char name[] = "";
    char *args[6] = {
      name,
      re2c_args,
      re2c_o,
      NULL,
      NULL,
      NULL
    };
    args[4] = strdup(Input.c_str());
    std::string ErrMsg("");
    if (TmpRe2C.createTemporaryFileOnDisk(true, &ErrMsg)) {
      Clang.getDiagnostics().Report(clang::diag::err_drv_unable_to_make_temp) <<
        ErrMsg;
      return 1;
    }
    sys::RemoveFileOnSignal(TmpRe2C);
    args[3] = strdup(TmpRe2C.str().c_str());
    int ret = re2c_main(5, args);
    if (ret) {
      Clang.getDiagnostics().Report(clang::diag::err_drv_command_failed) <<
        "re2c" << ret;
      return 1;
    }
    Input = TmpRe2C.str();
  }

  // Create a file manager object to provide access to and cache the
  // filesystem.
  Clang.createFileManager();

  // Create the source manager.
  Clang.createSourceManager();

  // Create the preprocessor.
  Clang.createPreprocessor();

  llvm::OwningPtr<FrontendAction> Act(CreateFrontendAction(Clang));

  if (Act && Act->BeginSourceFile(Clang, Input, false)) {
    Act->Execute();
    Act->EndSourceFile();
  }

  TmpRe2C.eraseFromDisk();// erase tempfile
  int ret = Clang.getDiagnostics().getNumErrors() != 0;
  if (ret)
    return ret;

  if (FrontendOpts.ProgramAction != frontend::EmitBC) {
    // stop processing if not compiling a final .cbc file
    return 0;
  }

  ret = compileInternal(FrontendOpts.OutputFile.c_str(), Opts.OptimizationLevel,
                        Opts.OptimizeSize, argv[0], fd, Clang);
  // Erase temp file, we need to do this here since OutputFile is a tempfile
  // only if action was EmitBC
  sys::Path(FrontendOpts.OutputFile).eraseFromDisk();
  return ret;
}

int CompileFile(int argc, const char **argv, const sys::Path* out,
                const sys::Path* err, raw_ostream &Err, bool bugreport,
                bool versionOnly)
{
  sys::PrintStackTraceOnErrorSignal();
  PrettyStackTraceProgram X(argc, argv);
  llvm_shutdown_obj Y;

  std::string ErrMsg;
  // Find API map file
  sys::Path ResourceDir(CompilerInvocation::GetResourcesPath(argv[0],
                                                             (void*)(intptr_t)GetExecutablePath));
  sys::Path apiMapPath(ResourceDir);
  apiMapPath.appendComponent("include");
  apiMapPath.appendComponent("bytecode_api_decl.c.h");
  if (!apiMapPath.exists()) {
    Err << "Cannot find ClamAV API map: " + apiMapPath.str() << "\n";
    return 2;
  }

  // Create tempfile for stderr, unless already specified
  sys::Path empty;
  const sys::Path* orig_err = err;
  if (!err) {
    std::string errpath = getTmpDir();
    if (errpath.empty()) {
      Err << "Failed to create temporary file for stderr!\n";
      return 2;
    }
    errpath += "/clambc-compiler-stderr";

    sys::Path *newerr = new sys::Path(errpath);
    ErrMsg.clear();
    if (newerr->createTemporaryFileOnDisk(true, &ErrMsg)) {
      Err << "Failed to create temporary file for stderr!\n";
      return 2;
    } else {
      err = newerr;
    }
  }

  // Run compiler in child process so that we can create a bugreport.tar
  // if it crashes.
  pid_t pid = fork();
  if (pid == -1) {
    Err << "fork() failed: " << sys::StrError() << "\n";
    return 2;
  }

  if (!pid) {
    // Child process
    if (out) {
      int fd = open(out->str().c_str(), O_WRONLY, O_CREAT);
      dup2(fd, fileno(stdout));
    }
    if (err) {
      // known issue with Ubuntu 64-bit headers
      int fd = open(err->str().c_str(), O_WRONLY, O_CREAT);
      dup2(fd, fileno(stderr));
    }

    _Exit(CompileSubprocess(argv, argc, ResourceDir, bugreport, versionOnly,
                           apiMapPath));
  }
  int Res = 0;
  while (waitpid(pid, &Res, 0) != pid) {
    if (errno == EINTR)
      continue;
    Err << "waitpid failed" << sys::StrError() << "\n";
    return 2;
  }
  if (WIFEXITED(Res))
    Res = WEXITSTATUS(Res);
  else if (WIFSIGNALED(Res))
    Res = -WTERMSIG(Res);
  if (!orig_err && err) {
    printFile(err);
  }
  if (Res < 0) {
    Res = printICE(-Res, argv, Err, bugreport, argc, argv, err);
  } else if (Res > 0) {
    Err << "\nCompiler exited with code " << Res << "!\n";
  }
  if (err != orig_err) {
    err->eraseFromDisk();
    delete err;
  }
  return Res;
}

