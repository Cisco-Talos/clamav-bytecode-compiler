//===-- ToolRunner.cpp ----------------------------------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements the interfaces described in the ToolRunner.h file.
//
//===----------------------------------------------------------------------===//

#define DEBUG_TYPE "toolrunner"
#include "ToolRunner.h"
#include "llvm/System/Program.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/FileUtilities.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Config/config.h"   // for HAVE_LINK_R
#include <fstream>
#include <sstream>
using namespace llvm;

namespace llvm {
  cl::opt<bool>
  SaveTemps("save-temps", cl::init(false), cl::desc("Save temporary files"));
}

namespace {
  cl::opt<std::string>
  RemoteClient("remote-client",
               cl::desc("Remote execution client (rsh/ssh)"));

  cl::opt<std::string>
  RemoteHost("remote-host",
             cl::desc("Remote execution (rsh/ssh) host"));

  cl::opt<std::string>
  RemotePort("remote-port",
             cl::desc("Remote execution (rsh/ssh) port"));

  cl::opt<std::string>
  RemoteUser("remote-user",
             cl::desc("Remote execution (rsh/ssh) user id"));

  cl::opt<std::string>
  RemoteExtra("remote-extra-options",
          cl::desc("Remote execution (rsh/ssh) extra options"));
}

ToolExecutionError::~ToolExecutionError() throw() { }

/// RunProgramWithTimeout - This function provides an alternate interface
/// to the sys::Program::ExecuteAndWait interface.
/// @see sys:Program::ExecuteAndWait
static int RunProgramWithTimeout(const sys::Path &ProgramPath,
                                 const char **Args,
                                 const sys::Path &StdInFile,
                                 const sys::Path &StdOutFile,
                                 const sys::Path &StdErrFile,
                                 unsigned NumSeconds = 0,
                                 unsigned MemoryLimit = 0) {
  const sys::Path* redirects[3];
  redirects[0] = &StdInFile;
  redirects[1] = &StdOutFile;
  redirects[2] = &StdErrFile;

#if 0 // For debug purposes
  {
    errs() << "RUN:";
    for (unsigned i = 0; Args[i]; ++i)
      errs() << " " << Args[i];
    errs() << "\n";
  }
#endif

  return
    sys::Program::ExecuteAndWait(ProgramPath, Args, 0, redirects,
                                 NumSeconds, MemoryLimit);
}

/// RunProgramRemotelyWithTimeout - This function runs the given program
/// remotely using the given remote client and the sys::Program::ExecuteAndWait.
/// Returns the remote program exit code or reports a remote client error if it
/// fails. Remote client is required to return 255 if it failed or program exit
/// code otherwise.
/// @see sys:Program::ExecuteAndWait
static int RunProgramRemotelyWithTimeout(const sys::Path &RemoteClientPath,
                                         const char **Args,
                                         const sys::Path &StdInFile,
                                         const sys::Path &StdOutFile,
                                         const sys::Path &StdErrFile,
                                         unsigned NumSeconds = 0,
                                         unsigned MemoryLimit = 0) {
  const sys::Path* redirects[3];
  redirects[0] = &StdInFile;
  redirects[1] = &StdOutFile;
  redirects[2] = &StdErrFile;

#if 0 // For debug purposes
  {
    errs() << "RUN:";
    for (unsigned i = 0; Args[i]; ++i)
      errs() << " " << Args[i];
    errs() << "\n";
  }
#endif

  // Run the program remotely with the remote client
  int ReturnCode = sys::Program::ExecuteAndWait(RemoteClientPath, Args,
                                 0, redirects, NumSeconds, MemoryLimit);

  // Has the remote client fail?
  if (255 == ReturnCode) {
    std::ostringstream OS;
    OS << "\nError running remote client:\n ";
    for (const char **Arg = Args; *Arg; ++Arg)
      OS << " " << *Arg;
    OS << "\n";

    // The error message is in the output file, let's print it out from there.
    std::ifstream ErrorFile(StdOutFile.c_str());
    if (ErrorFile) {
      std::copy(std::istreambuf_iterator<char>(ErrorFile),
                std::istreambuf_iterator<char>(),
                std::ostreambuf_iterator<char>(OS));
      ErrorFile.close();
    }

    throw ToolExecutionError(OS.str());
  }

  return ReturnCode;
}

static void ProcessFailure(sys::Path ProgPath, const char** Args) {
  std::ostringstream OS;
  OS << "\nError running tool:\n ";
  for (const char **Arg = Args; *Arg; ++Arg)
    OS << " " << *Arg;
  OS << "\n";

  // Rerun the compiler, capturing any error messages to print them.
  sys::Path ErrorFilename("bugpoint.program_error_messages");
  std::string ErrMsg;
  if (ErrorFilename.makeUnique(true, &ErrMsg)) {
    errs() << "Error making unique filename: " << ErrMsg << "\n";
    exit(1);
  }
  RunProgramWithTimeout(ProgPath, Args, sys::Path(""), ErrorFilename,
                        ErrorFilename); // FIXME: check return code ?

  // Print out the error messages generated by GCC if possible...
  std::ifstream ErrorFile(ErrorFilename.c_str());
  if (ErrorFile) {
    std::copy(std::istreambuf_iterator<char>(ErrorFile),
              std::istreambuf_iterator<char>(),
              std::ostreambuf_iterator<char>(OS));
    ErrorFile.close();
  }

  ErrorFilename.eraseFromDisk();
  throw ToolExecutionError(OS.str());
}

//===---------------------------------------------------------------------===//
// LLI Implementation of AbstractIntepreter interface
//
namespace {
  class LLI : public AbstractInterpreter {
    std::string LLIPath;          // The path to the LLI executable
    std::vector<std::string> ToolArgs; // Args to pass to LLI
  public:
    LLI(const std::string &Path, const std::vector<std::string> *Args)
      : LLIPath(Path) {
      ToolArgs.clear ();
      if (Args) { ToolArgs = *Args; }
    }

    virtual int ExecuteProgram(const std::string &Bitcode,
                               const std::vector<std::string> &Args,
                               const std::string &InputFile,
                               const std::string &OutputFile,
                               const std::vector<std::string> &GCCArgs,
                               const std::vector<std::string> &SharedLibs =
                               std::vector<std::string>(),
                               unsigned Timeout = 0,
                               unsigned MemoryLimit = 0);
  };
}

int LLI::ExecuteProgram(const std::string &Bitcode,
                        const std::vector<std::string> &Args,
                        const std::string &InputFile,
                        const std::string &OutputFile,
                        const std::vector<std::string> &GCCArgs,
                        const std::vector<std::string> &SharedLibs,
                        unsigned Timeout,
                        unsigned MemoryLimit) {
  std::vector<const char*> LLIArgs;
  LLIArgs.push_back(LLIPath.c_str());
  LLIArgs.push_back("-force-interpreter=true");

  for (std::vector<std::string>::const_iterator i = SharedLibs.begin(), e = SharedLibs.end(); i != e; ++i) {
    LLIArgs.push_back("-load");
    LLIArgs.push_back((*i).c_str());
  }

  // Add any extra LLI args.
  for (unsigned i = 0, e = ToolArgs.size(); i != e; ++i)
    LLIArgs.push_back(ToolArgs[i].c_str());

  LLIArgs.push_back(Bitcode.c_str());
  // Add optional parameters to the running program from Argv
  for (unsigned i=0, e = Args.size(); i != e; ++i)
    LLIArgs.push_back(Args[i].c_str());
  LLIArgs.push_back(0);

  outs() << "<lli>"; outs().flush();
  DEBUG(errs() << "\nAbout to run:\t";
        for (unsigned i=0, e = LLIArgs.size()-1; i != e; ++i)
          errs() << " " << LLIArgs[i];
        errs() << "\n";
        );
  return RunProgramWithTimeout(sys::Path(LLIPath), &LLIArgs[0],
      sys::Path(InputFile), sys::Path(OutputFile), sys::Path(OutputFile),
      Timeout, MemoryLimit);
}

// LLI create method - Try to find the LLI executable
AbstractInterpreter *AbstractInterpreter::createLLI(const char *Argv0,
                                                    std::string &Message,
                                     const std::vector<std::string> *ToolArgs) {
  std::string LLIPath =
    FindExecutable("lli", Argv0, (void *)(intptr_t)&createLLI).str();
  if (!LLIPath.empty()) {
    Message = "Found lli: " + LLIPath + "\n";
    return new LLI(LLIPath, ToolArgs);
  }

  Message = "Cannot find `lli' in executable directory or PATH!\n";
  return 0;
}

//===---------------------------------------------------------------------===//
// Custom execution command implementation of AbstractIntepreter interface
//
// Allows using a custom command for executing the bitcode, thus allows,
// for example, to invoke a cross compiler for code generation followed by 
// a simulator that executes the generated binary.
namespace {
  class CustomExecutor : public AbstractInterpreter {
    std::string ExecutionCommand;
    std::vector<std::string> ExecutorArgs;
  public:
    CustomExecutor(
      const std::string &ExecutionCmd, std::vector<std::string> ExecArgs) :
      ExecutionCommand(ExecutionCmd), ExecutorArgs(ExecArgs) {}

    virtual int ExecuteProgram(const std::string &Bitcode,
                               const std::vector<std::string> &Args,
                               const std::string &InputFile,
                               const std::string &OutputFile,
                               const std::vector<std::string> &GCCArgs,
                               const std::vector<std::string> &SharedLibs =
                               std::vector<std::string>(),
                               unsigned Timeout = 0,
                               unsigned MemoryLimit = 0);
  };
}

int CustomExecutor::ExecuteProgram(const std::string &Bitcode,
                        const std::vector<std::string> &Args,
                        const std::string &InputFile,
                        const std::string &OutputFile,
                        const std::vector<std::string> &GCCArgs,
                        const std::vector<std::string> &SharedLibs,
                        unsigned Timeout,
                        unsigned MemoryLimit) {

  std::vector<const char*> ProgramArgs;
  ProgramArgs.push_back(ExecutionCommand.c_str());

  for (std::size_t i = 0; i < ExecutorArgs.size(); ++i)
    ProgramArgs.push_back(ExecutorArgs.at(i).c_str());
  ProgramArgs.push_back(Bitcode.c_str());
  ProgramArgs.push_back(0);

  // Add optional parameters to the running program from Argv
  for (unsigned i=0, e = Args.size(); i != e; ++i)
    ProgramArgs.push_back(Args[i].c_str());

  return RunProgramWithTimeout(
    sys::Path(ExecutionCommand),
    &ProgramArgs[0], sys::Path(InputFile), sys::Path(OutputFile), 
    sys::Path(OutputFile), Timeout, MemoryLimit);
}

// Custom execution environment create method, takes the execution command
// as arguments
AbstractInterpreter *AbstractInterpreter::createCustom(
                    std::string &Message,
                    const std::string &ExecCommandLine) {

  std::string Command = "";
  std::vector<std::string> Args;
  std::string delimiters = " ";

  // Tokenize the ExecCommandLine to the command and the args to allow
  // defining a full command line as the command instead of just the
  // executed program. We cannot just pass the whole string after the command
  // as a single argument because then program sees only a single
  // command line argument (with spaces in it: "foo bar" instead 
  // of "foo" and "bar").

  // code borrowed from: 
  // http://oopweb.com/CPP/Documents/CPPHOWTO/Volume/C++Programming-HOWTO-7.html
  std::string::size_type lastPos = 
    ExecCommandLine.find_first_not_of(delimiters, 0);
  std::string::size_type pos = 
    ExecCommandLine.find_first_of(delimiters, lastPos);

  while (std::string::npos != pos || std::string::npos != lastPos) {
    std::string token = ExecCommandLine.substr(lastPos, pos - lastPos);
    if (Command == "")
       Command = token;
    else
       Args.push_back(token);
    // Skip delimiters.  Note the "not_of"
    lastPos = ExecCommandLine.find_first_not_of(delimiters, pos);
    // Find next "non-delimiter"
    pos = ExecCommandLine.find_first_of(delimiters, lastPos);
  }

  std::string CmdPath = sys::Program::FindProgramByName(Command).str();
  if (CmdPath.empty()) {
    Message = 
      std::string("Cannot find '") + Command + 
      "' in executable directory or PATH!\n";
    return 0;
  }

  Message = "Found command in: " + CmdPath + "\n";

  return new CustomExecutor(CmdPath, Args);
}

//===----------------------------------------------------------------------===//
// LLC Implementation of AbstractIntepreter interface
//
GCC::FileType LLC::OutputCode(const std::string &Bitcode, 
                              sys::Path &OutputAsmFile) {
  sys::Path uniqueFile(Bitcode+".llc.s");
  std::string ErrMsg;
  if (uniqueFile.makeUnique(true, &ErrMsg)) {
    errs() << "Error making unique filename: " << ErrMsg << "\n";
    exit(1);
  }
  OutputAsmFile = uniqueFile;
  std::vector<const char *> LLCArgs;
  LLCArgs.push_back (LLCPath.c_str());

  // Add any extra LLC args.
  for (unsigned i = 0, e = ToolArgs.size(); i != e; ++i)
    LLCArgs.push_back(ToolArgs[i].c_str());

  LLCArgs.push_back ("-o");
  LLCArgs.push_back (OutputAsmFile.c_str()); // Output to the Asm file
  LLCArgs.push_back (Bitcode.c_str());      // This is the input bitcode
  LLCArgs.push_back (0);

  outs() << "<llc>"; outs().flush();
  DEBUG(errs() << "\nAbout to run:\t";
        for (unsigned i=0, e = LLCArgs.size()-1; i != e; ++i)
          errs() << " " << LLCArgs[i];
        errs() << "\n";
        );
  if (RunProgramWithTimeout(sys::Path(LLCPath), &LLCArgs[0],
                            sys::Path(), sys::Path(), sys::Path()))
    ProcessFailure(sys::Path(LLCPath), &LLCArgs[0]);

  return GCC::AsmFile;                              
}

void LLC::compileProgram(const std::string &Bitcode) {
  sys::Path OutputAsmFile;
  OutputCode(Bitcode, OutputAsmFile);
  OutputAsmFile.eraseFromDisk();
}

int LLC::ExecuteProgram(const std::string &Bitcode,
                        const std::vector<std::string> &Args,
                        const std::string &InputFile,
                        const std::string &OutputFile,
                        const std::vector<std::string> &ArgsForGCC,
                        const std::vector<std::string> &SharedLibs,
                        unsigned Timeout,
                        unsigned MemoryLimit) {

  sys::Path OutputAsmFile;
  OutputCode(Bitcode, OutputAsmFile);
  FileRemover OutFileRemover(OutputAsmFile, !SaveTemps);

  std::vector<std::string> GCCArgs(ArgsForGCC);
  GCCArgs.insert(GCCArgs.end(), SharedLibs.begin(), SharedLibs.end());
  GCCArgs.insert(GCCArgs.end(), gccArgs.begin(), gccArgs.end());

  // Assuming LLC worked, compile the result with GCC and run it.
  return gcc->ExecuteProgram(OutputAsmFile.str(), Args, GCC::AsmFile,
                             InputFile, OutputFile, GCCArgs,
                             Timeout, MemoryLimit);
}

/// createLLC - Try to find the LLC executable
///
LLC *AbstractInterpreter::createLLC(const char *Argv0,
                                    std::string &Message,
                                    const std::vector<std::string> *Args,
                                    const std::vector<std::string> *GCCArgs) {
  std::string LLCPath =
    FindExecutable("llc", Argv0, (void *)(intptr_t)&createLLC).str();
  if (LLCPath.empty()) {
    Message = "Cannot find `llc' in executable directory or PATH!\n";
    return 0;
  }

  Message = "Found llc: " + LLCPath + "\n";
  GCC *gcc = GCC::create(Message, GCCArgs);
  if (!gcc) {
    errs() << Message << "\n";
    exit(1);
  }
  return new LLC(LLCPath, gcc, Args, GCCArgs);
}

//===---------------------------------------------------------------------===//
// JIT Implementation of AbstractIntepreter interface
//
namespace {
  class JIT : public AbstractInterpreter {
    std::string LLIPath;          // The path to the LLI executable
    std::vector<std::string> ToolArgs; // Args to pass to LLI
  public:
    JIT(const std::string &Path, const std::vector<std::string> *Args)
      : LLIPath(Path) {
      ToolArgs.clear ();
      if (Args) { ToolArgs = *Args; }
    }

    virtual int ExecuteProgram(const std::string &Bitcode,
                               const std::vector<std::string> &Args,
                               const std::string &InputFile,
                               const std::string &OutputFile,
                               const std::vector<std::string> &GCCArgs =
                                 std::vector<std::string>(),
                               const std::vector<std::string> &SharedLibs =
                                 std::vector<std::string>(), 
                               unsigned Timeout =0,
                               unsigned MemoryLimit =0);
  };
}

int JIT::ExecuteProgram(const std::string &Bitcode,
                        const std::vector<std::string> &Args,
                        const std::string &InputFile,
                        const std::string &OutputFile,
                        const std::vector<std::string> &GCCArgs,
                        const std::vector<std::string> &SharedLibs,
                        unsigned Timeout,
                        unsigned MemoryLimit) {
  // Construct a vector of parameters, incorporating those from the command-line
  std::vector<const char*> JITArgs;
  JITArgs.push_back(LLIPath.c_str());
  JITArgs.push_back("-force-interpreter=false");

  // Add any extra LLI args.
  for (unsigned i = 0, e = ToolArgs.size(); i != e; ++i)
    JITArgs.push_back(ToolArgs[i].c_str());

  for (unsigned i = 0, e = SharedLibs.size(); i != e; ++i) {
    JITArgs.push_back("-load");
    JITArgs.push_back(SharedLibs[i].c_str());
  }
  JITArgs.push_back(Bitcode.c_str());
  // Add optional parameters to the running program from Argv
  for (unsigned i=0, e = Args.size(); i != e; ++i)
    JITArgs.push_back(Args[i].c_str());
  JITArgs.push_back(0);

  outs() << "<jit>"; outs().flush();
  DEBUG(errs() << "\nAbout to run:\t";
        for (unsigned i=0, e = JITArgs.size()-1; i != e; ++i)
          errs() << " " << JITArgs[i];
        errs() << "\n";
        );
  DEBUG(errs() << "\nSending output to " << OutputFile << "\n");
  return RunProgramWithTimeout(sys::Path(LLIPath), &JITArgs[0],
      sys::Path(InputFile), sys::Path(OutputFile), sys::Path(OutputFile),
      Timeout, MemoryLimit);
}

/// createJIT - Try to find the LLI executable
///
AbstractInterpreter *AbstractInterpreter::createJIT(const char *Argv0,
                   std::string &Message, const std::vector<std::string> *Args) {
  std::string LLIPath =
    FindExecutable("lli", Argv0, (void *)(intptr_t)&createJIT).str();
  if (!LLIPath.empty()) {
    Message = "Found lli: " + LLIPath + "\n";
    return new JIT(LLIPath, Args);
  }

  Message = "Cannot find `lli' in executable directory or PATH!\n";
  return 0;
}

GCC::FileType CBE::OutputCode(const std::string &Bitcode,
                              sys::Path &OutputCFile) {
  sys::Path uniqueFile(Bitcode+".cbe.c");
  std::string ErrMsg;
  if (uniqueFile.makeUnique(true, &ErrMsg)) {
    errs() << "Error making unique filename: " << ErrMsg << "\n";
    exit(1);
  }
  OutputCFile = uniqueFile;
  std::vector<const char *> LLCArgs;
  LLCArgs.push_back (LLCPath.c_str());

  // Add any extra LLC args.
  for (unsigned i = 0, e = ToolArgs.size(); i != e; ++i)
    LLCArgs.push_back(ToolArgs[i].c_str());

  LLCArgs.push_back ("-o");
  LLCArgs.push_back (OutputCFile.c_str());   // Output to the C file
  LLCArgs.push_back ("-march=c");            // Output C language
  LLCArgs.push_back ("-f");                  // Overwrite as necessary...
  LLCArgs.push_back (Bitcode.c_str());      // This is the input bitcode
  LLCArgs.push_back (0);

  outs() << "<cbe>"; outs().flush();
  DEBUG(errs() << "\nAbout to run:\t";
        for (unsigned i=0, e = LLCArgs.size()-1; i != e; ++i)
          errs() << " " << LLCArgs[i];
        errs() << "\n";
        );
  if (RunProgramWithTimeout(LLCPath, &LLCArgs[0], sys::Path(), sys::Path(),
                            sys::Path()))
    ProcessFailure(LLCPath, &LLCArgs[0]);
  return GCC::CFile;
}

void CBE::compileProgram(const std::string &Bitcode) {
  sys::Path OutputCFile;
  OutputCode(Bitcode, OutputCFile);
  OutputCFile.eraseFromDisk();
}

int CBE::ExecuteProgram(const std::string &Bitcode,
                        const std::vector<std::string> &Args,
                        const std::string &InputFile,
                        const std::string &OutputFile,
                        const std::vector<std::string> &ArgsForGCC,
                        const std::vector<std::string> &SharedLibs,
                        unsigned Timeout,
                        unsigned MemoryLimit) {
  sys::Path OutputCFile;
  OutputCode(Bitcode, OutputCFile);

  FileRemover CFileRemove(OutputCFile, !SaveTemps);

  std::vector<std::string> GCCArgs(ArgsForGCC);
  GCCArgs.insert(GCCArgs.end(), SharedLibs.begin(), SharedLibs.end());

  return gcc->ExecuteProgram(OutputCFile.str(), Args, GCC::CFile,
                             InputFile, OutputFile, GCCArgs,
                             Timeout, MemoryLimit);
}

/// createCBE - Try to find the 'llc' executable
///
CBE *AbstractInterpreter::createCBE(const char *Argv0,
                                    std::string &Message,
                                    const std::vector<std::string> *Args,
                                    const std::vector<std::string> *GCCArgs) {
  sys::Path LLCPath =
    FindExecutable("llc", Argv0, (void *)(intptr_t)&createCBE);
  if (LLCPath.isEmpty()) {
    Message =
      "Cannot find `llc' in executable directory or PATH!\n";
    return 0;
  }

  Message = "Found llc: " + LLCPath.str() + "\n";
  GCC *gcc = GCC::create(Message, GCCArgs);
  if (!gcc) {
    errs() << Message << "\n";
    exit(1);
  }
  return new CBE(LLCPath, gcc, Args);
}

//===---------------------------------------------------------------------===//
// GCC abstraction
//

static bool
IsARMArchitecture(std::vector<std::string> Args)
{
  for (std::vector<std::string>::const_iterator
         I = Args.begin(), E = Args.end(); I != E; ++I) {
    StringRef S(*I);
    if (!S.equals_lower("-arch")) {
      ++I;
      if (I != E && !S.substr(0, strlen("arm")).equals_lower("arm")) {
        return true;
      }
    }
  }

  return false;
}

int GCC::ExecuteProgram(const std::string &ProgramFile,
                        const std::vector<std::string> &Args,
                        FileType fileType,
                        const std::string &InputFile,
                        const std::string &OutputFile,
                        const std::vector<std::string> &ArgsForGCC,
                        unsigned Timeout,
                        unsigned MemoryLimit) {
  std::vector<const char*> GCCArgs;

  GCCArgs.push_back(GCCPath.c_str());

  for (std::vector<std::string>::const_iterator
         I = gccArgs.begin(), E = gccArgs.end(); I != E; ++I)
    GCCArgs.push_back(I->c_str());

  // Specify -x explicitly in case the extension is wonky
  GCCArgs.push_back("-x");
  if (fileType == CFile) {
    GCCArgs.push_back("c");
    GCCArgs.push_back("-fno-strict-aliasing");
  } else {
    GCCArgs.push_back("assembler");

    // For ARM architectures we don't want this flag. bugpoint isn't
    // explicitly told what architecture it is working on, so we get
    // it from gcc flags
    if ((TargetTriple.getOS() == Triple::Darwin) &&
        !IsARMArchitecture(ArgsForGCC))
      GCCArgs.push_back("-force_cpusubtype_ALL");
  }
  GCCArgs.push_back(ProgramFile.c_str());  // Specify the input filename...
  GCCArgs.push_back("-x");
  GCCArgs.push_back("none");
  GCCArgs.push_back("-o");
  sys::Path OutputBinary (ProgramFile+".gcc.exe");
  std::string ErrMsg;
  if (OutputBinary.makeUnique(true, &ErrMsg)) {
    errs() << "Error making unique filename: " << ErrMsg << "\n";
    exit(1);
  }
  GCCArgs.push_back(OutputBinary.c_str()); // Output to the right file...

  // Add any arguments intended for GCC. We locate them here because this is
  // most likely -L and -l options that need to come before other libraries but
  // after the source. Other options won't be sensitive to placement on the
  // command line, so this should be safe.
  for (unsigned i = 0, e = ArgsForGCC.size(); i != e; ++i)
    GCCArgs.push_back(ArgsForGCC[i].c_str());

  GCCArgs.push_back("-lm");                // Hard-code the math library...
  GCCArgs.push_back("-O2");                // Optimize the program a bit...
#if defined (HAVE_LINK_R)
  GCCArgs.push_back("-Wl,-R.");            // Search this dir for .so files
#endif
  if (TargetTriple.getArch() == Triple::sparc)
    GCCArgs.push_back("-mcpu=v9");
  GCCArgs.push_back(0);                    // NULL terminator

  outs() << "<gcc>"; outs().flush();
  DEBUG(errs() << "\nAbout to run:\t";
        for (unsigned i=0, e = GCCArgs.size()-1; i != e; ++i)
          errs() << " " << GCCArgs[i];
        errs() << "\n";
        );
  if (RunProgramWithTimeout(GCCPath, &GCCArgs[0], sys::Path(), sys::Path(),
        sys::Path())) {
    ProcessFailure(GCCPath, &GCCArgs[0]);
    exit(1);
  }

  std::vector<const char*> ProgramArgs;

  if (RemoteClientPath.isEmpty())
    ProgramArgs.push_back(OutputBinary.c_str());
  else {
    ProgramArgs.push_back(RemoteClientPath.c_str());
    ProgramArgs.push_back(RemoteHost.c_str());
    if (!RemoteUser.empty()) {
      ProgramArgs.push_back("-l");
      ProgramArgs.push_back(RemoteUser.c_str());
    }
    if (!RemotePort.empty()) {
      ProgramArgs.push_back("-p");
      ProgramArgs.push_back(RemotePort.c_str());
    }
    if (!RemoteExtra.empty()) {
      ProgramArgs.push_back(RemoteExtra.c_str());
    }

    // Full path to the binary. We need to cd to the exec directory because
    // there is a dylib there that the exec expects to find in the CWD
    char* env_pwd = getenv("PWD");
    std::string Exec = "cd ";
    Exec += env_pwd;
    Exec += "; ./";
    Exec += OutputBinary.c_str();
    ProgramArgs.push_back(Exec.c_str());
  }

  // Add optional parameters to the running program from Argv
  for (unsigned i=0, e = Args.size(); i != e; ++i)
    ProgramArgs.push_back(Args[i].c_str());
  ProgramArgs.push_back(0);                // NULL terminator

  // Now that we have a binary, run it!
  outs() << "<program>"; outs().flush();
  DEBUG(errs() << "\nAbout to run:\t";
        for (unsigned i=0, e = ProgramArgs.size()-1; i != e; ++i)
          errs() << " " << ProgramArgs[i];
        errs() << "\n";
        );

  FileRemover OutputBinaryRemover(OutputBinary, !SaveTemps);

  if (RemoteClientPath.isEmpty()) {
    DEBUG(errs() << "<run locally>";);
    return RunProgramWithTimeout(OutputBinary, &ProgramArgs[0],
        sys::Path(InputFile), sys::Path(OutputFile), sys::Path(OutputFile),
        Timeout, MemoryLimit);
  } else {
    outs() << "<run remotely>"; outs().flush();
    return RunProgramRemotelyWithTimeout(sys::Path(RemoteClientPath),
        &ProgramArgs[0], sys::Path(InputFile), sys::Path(OutputFile),
        sys::Path(OutputFile), Timeout, MemoryLimit);
  }
}

int GCC::MakeSharedObject(const std::string &InputFile, FileType fileType,
                          std::string &OutputFile,
                          const std::vector<std::string> &ArgsForGCC) {
  sys::Path uniqueFilename(InputFile+LTDL_SHLIB_EXT);
  std::string ErrMsg;
  if (uniqueFilename.makeUnique(true, &ErrMsg)) {
    errs() << "Error making unique filename: " << ErrMsg << "\n";
    exit(1);
  }
  OutputFile = uniqueFilename.str();

  std::vector<const char*> GCCArgs;
  
  GCCArgs.push_back(GCCPath.c_str());

  for (std::vector<std::string>::const_iterator
         I = gccArgs.begin(), E = gccArgs.end(); I != E; ++I)
    GCCArgs.push_back(I->c_str());

  // Compile the C/asm file into a shared object
  GCCArgs.push_back("-x");
  GCCArgs.push_back(fileType == AsmFile ? "assembler" : "c");
  GCCArgs.push_back("-fno-strict-aliasing");
  GCCArgs.push_back(InputFile.c_str());   // Specify the input filename.
  GCCArgs.push_back("-x");
  GCCArgs.push_back("none");
  if (TargetTriple.getArch() == Triple::sparc)
    GCCArgs.push_back("-G");       // Compile a shared library, `-G' for Sparc
  else if (TargetTriple.getOS() == Triple::Darwin) {
    // link all source files into a single module in data segment, rather than
    // generating blocks. dynamic_lookup requires that you set 
    // MACOSX_DEPLOYMENT_TARGET=10.3 in your env.  FIXME: it would be better for
    // bugpoint to just pass that in the environment of GCC.
    GCCArgs.push_back("-single_module");
    GCCArgs.push_back("-dynamiclib");   // `-dynamiclib' for MacOS X/PowerPC
    GCCArgs.push_back("-undefined");
    GCCArgs.push_back("dynamic_lookup");
  } else
    GCCArgs.push_back("-shared");  // `-shared' for Linux/X86, maybe others

  if ((TargetTriple.getArch() == Triple::alpha) ||
      (TargetTriple.getArch() == Triple::x86_64))
    GCCArgs.push_back("-fPIC");   // Requires shared objs to contain PIC

  if (TargetTriple.getArch() == Triple::sparc)
    GCCArgs.push_back("-mcpu=v9");

  GCCArgs.push_back("-o");
  GCCArgs.push_back(OutputFile.c_str()); // Output to the right filename.
  GCCArgs.push_back("-O2");              // Optimize the program a bit.

  
  
  // Add any arguments intended for GCC. We locate them here because this is
  // most likely -L and -l options that need to come before other libraries but
  // after the source. Other options won't be sensitive to placement on the
  // command line, so this should be safe.
  for (unsigned i = 0, e = ArgsForGCC.size(); i != e; ++i)
    GCCArgs.push_back(ArgsForGCC[i].c_str());
  GCCArgs.push_back(0);                    // NULL terminator

  

  outs() << "<gcc>"; outs().flush();
  DEBUG(errs() << "\nAbout to run:\t";
        for (unsigned i=0, e = GCCArgs.size()-1; i != e; ++i)
          errs() << " " << GCCArgs[i];
        errs() << "\n";
        );
  if (RunProgramWithTimeout(GCCPath, &GCCArgs[0], sys::Path(), sys::Path(),
                            sys::Path())) {
    ProcessFailure(GCCPath, &GCCArgs[0]);
    return 1;
  }
  return 0;
}

/// create - Try to find the `gcc' executable
///
GCC *GCC::create(std::string &Message,
                 const std::vector<std::string> *Args) {
  sys::Path GCCPath = sys::Program::FindProgramByName("gcc");
  if (GCCPath.isEmpty()) {
    Message = "Cannot find `gcc' in executable directory or PATH!\n";
    return 0;
  }

  sys::Path RemoteClientPath;
  if (!RemoteClient.empty())
    RemoteClientPath = sys::Program::FindProgramByName(RemoteClient);

  Message = "Found gcc: " + GCCPath.str() + "\n";
  return new GCC(GCCPath, RemoteClientPath, Args);
}
