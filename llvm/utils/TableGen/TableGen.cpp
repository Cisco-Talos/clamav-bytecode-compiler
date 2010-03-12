//===- TableGen.cpp - Top-Level TableGen implementation -------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// TableGen is a tool which can be used to build up a description of something,
// then invoke one or more "tablegen backends" to emit information about the
// description in some predefined format.  In practice, this is used by the LLVM
// code generators to automate generation of a code generator through a
// high-level description of the target.
//
//===----------------------------------------------------------------------===//

#include "AsmMatcherEmitter.h"
#include "AsmWriterEmitter.h"
#include "CallingConvEmitter.h"
#include "ClangDiagnosticsEmitter.h"
#include "CodeEmitterGen.h"
#include "DAGISelEmitter.h"
#include "DisassemblerEmitter.h"
#include "FastISelEmitter.h"
#include "InstrEnumEmitter.h"
#include "InstrInfoEmitter.h"
#include "IntrinsicEmitter.h"
#include "LLVMCConfigurationEmitter.h"
#include "OptParserEmitter.h"
#include "Record.h"
#include "RegisterInfoEmitter.h"
#include "SubtargetEmitter.h"
#include "TGParser.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileUtilities.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/PrettyStackTrace.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/System/Signals.h"
#include <algorithm>
#include <cstdio>
using namespace llvm;

enum ActionType {
  PrintRecords,
  GenEmitter,
  GenRegisterEnums, GenRegister, GenRegisterHeader,
  GenInstrEnums, GenInstrs, GenAsmWriter, GenAsmMatcher,
  GenDisassembler,
  GenCallingConv,
  GenClangDiagsDefs,
  GenClangDiagGroups,
  GenDAGISel,
  GenFastISel,
  GenOptParserDefs, GenOptParserImpl,
  GenSubtarget,
  GenIntrinsic,
  GenTgtIntrinsic,
  GenLLVMCConf,
  PrintEnums
};

namespace {
  cl::opt<ActionType>
  Action(cl::desc("Action to perform:"),
         cl::values(clEnumValN(PrintRecords, "print-records",
                               "Print all records to stdout (default)"),
                    clEnumValN(GenEmitter, "gen-emitter",
                               "Generate machine code emitter"),
                    clEnumValN(GenRegisterEnums, "gen-register-enums",
                               "Generate enum values for registers"),
                    clEnumValN(GenRegister, "gen-register-desc",
                               "Generate a register info description"),
                    clEnumValN(GenRegisterHeader, "gen-register-desc-header",
                               "Generate a register info description header"),
                    clEnumValN(GenInstrEnums, "gen-instr-enums",
                               "Generate enum values for instructions"),
                    clEnumValN(GenInstrs, "gen-instr-desc",
                               "Generate instruction descriptions"),
                    clEnumValN(GenCallingConv, "gen-callingconv",
                               "Generate calling convention descriptions"),
                    clEnumValN(GenAsmWriter, "gen-asm-writer",
                               "Generate assembly writer"),
                    clEnumValN(GenDisassembler, "gen-disassembler",
                               "Generate disassembler"),
                    clEnumValN(GenAsmMatcher, "gen-asm-matcher",
                               "Generate assembly instruction matcher"),
                    clEnumValN(GenDAGISel, "gen-dag-isel",
                               "Generate a DAG instruction selector"),
                    clEnumValN(GenFastISel, "gen-fast-isel",
                               "Generate a \"fast\" instruction selector"),
                    clEnumValN(GenOptParserDefs, "gen-opt-parser-defs",
                               "Generate option definitions"),
                    clEnumValN(GenOptParserImpl, "gen-opt-parser-impl",
                               "Generate option parser implementation"),
                    clEnumValN(GenSubtarget, "gen-subtarget",
                               "Generate subtarget enumerations"),
                    clEnumValN(GenIntrinsic, "gen-intrinsic",
                               "Generate intrinsic information"),
                    clEnumValN(GenTgtIntrinsic, "gen-tgt-intrinsic",
                               "Generate target intrinsic information"),
                    clEnumValN(GenClangDiagsDefs, "gen-clang-diags-defs",
                               "Generate Clang diagnostics definitions"),
                    clEnumValN(GenClangDiagGroups, "gen-clang-diag-groups",
                               "Generate Clang diagnostic groups"),
                    clEnumValN(GenLLVMCConf, "gen-llvmc",
                               "Generate LLVMC configuration library"),
                    clEnumValN(PrintEnums, "print-enums",
                               "Print enum values for a class"),
                    clEnumValEnd));

  cl::opt<std::string>
  Class("class", cl::desc("Print Enum list for this class"),
        cl::value_desc("class name"));

  cl::opt<std::string>
  OutputFilename("o", cl::desc("Output filename"), cl::value_desc("filename"),
                 cl::init("-"));

  cl::opt<std::string>
  InputFilename(cl::Positional, cl::desc("<input file>"), cl::init("-"));

  cl::list<std::string>
  IncludeDirs("I", cl::desc("Directory of include files"),
              cl::value_desc("directory"), cl::Prefix);
  
  cl::opt<std::string>
  ClangComponent("clang-component",
                 cl::desc("Only use warnings from specified component"),
                 cl::value_desc("component"), cl::Hidden);
}


// FIXME: Eliminate globals from tblgen.
RecordKeeper llvm::Records;

static SourceMgr SrcMgr;

void llvm::PrintError(SMLoc ErrorLoc, const std::string &Msg) {
  SrcMgr.PrintMessage(ErrorLoc, Msg, "error");
}



/// ParseFile - this function begins the parsing of the specified tablegen
/// file.
static bool ParseFile(const std::string &Filename,
                      const std::vector<std::string> &IncludeDirs,
                      SourceMgr &SrcMgr) {
  std::string ErrorStr;
  MemoryBuffer *F = MemoryBuffer::getFileOrSTDIN(Filename.c_str(), &ErrorStr);
  if (F == 0) {
    errs() << "Could not open input file '" << Filename << "': " 
           << ErrorStr <<"\n";
    return true;
  }
  
  // Tell SrcMgr about this buffer, which is what TGParser will pick up.
  SrcMgr.AddNewSourceBuffer(F, SMLoc());

  // Record the location of the include directory so that the lexer can find
  // it later.
  SrcMgr.setIncludeDirs(IncludeDirs);
  
  TGParser Parser(SrcMgr);

  return Parser.ParseFile();
}

int main(int argc, char **argv) {
  sys::PrintStackTraceOnErrorSignal();
  PrettyStackTraceProgram X(argc, argv);
  cl::ParseCommandLineOptions(argc, argv);

  
  // Parse the input file.
  if (ParseFile(InputFilename, IncludeDirs, SrcMgr))
    return 1;

  raw_ostream *Out = &outs();
  if (OutputFilename != "-") {
    std::string Error;
    Out = new raw_fd_ostream(OutputFilename.c_str(), Error);

    if (!Error.empty()) {
      errs() << argv[0] << ": error opening " << OutputFilename 
             << ":" << Error << "\n";
      return 1;
    }

    // Make sure the file gets removed if *gasp* tablegen crashes...
    sys::RemoveFileOnSignal(sys::Path(OutputFilename));
  }

  try {
    switch (Action) {
    case PrintRecords:
      *Out << Records;           // No argument, dump all contents
      break;
    case GenEmitter:
      CodeEmitterGen(Records).run(*Out);
      break;

    case GenRegisterEnums:
      RegisterInfoEmitter(Records).runEnums(*Out);
      break;
    case GenRegister:
      RegisterInfoEmitter(Records).run(*Out);
      break;
    case GenRegisterHeader:
      RegisterInfoEmitter(Records).runHeader(*Out);
      break;
    case GenInstrEnums:
      InstrEnumEmitter(Records).run(*Out);
      break;
    case GenInstrs:
      InstrInfoEmitter(Records).run(*Out);
      break;
    case GenCallingConv:
      CallingConvEmitter(Records).run(*Out);
      break;
    case GenAsmWriter:
      AsmWriterEmitter(Records).run(*Out);
      break;
    case GenAsmMatcher:
      AsmMatcherEmitter(Records).run(*Out);
      break;
    case GenClangDiagsDefs:
      ClangDiagsDefsEmitter(Records, ClangComponent).run(*Out);
      break;
    case GenClangDiagGroups:
      ClangDiagGroupsEmitter(Records).run(*Out);
      break;
    case GenDisassembler:
      DisassemblerEmitter(Records).run(*Out);
      break;
    case GenOptParserDefs:
      OptParserEmitter(Records, true).run(*Out);
      break;
    case GenOptParserImpl:
      OptParserEmitter(Records, false).run(*Out);
      break;
    case GenDAGISel:
      DAGISelEmitter(Records).run(*Out);
      break;
    case GenFastISel:
      FastISelEmitter(Records).run(*Out);
      break;
    case GenSubtarget:
      SubtargetEmitter(Records).run(*Out);
      break;
    case GenIntrinsic:
      IntrinsicEmitter(Records).run(*Out);
      break;
    case GenTgtIntrinsic:
      IntrinsicEmitter(Records, true).run(*Out);
      break;
    case GenLLVMCConf:
      LLVMCConfigurationEmitter(Records).run(*Out);
      break;
    case PrintEnums:
    {
      std::vector<Record*> Recs = Records.getAllDerivedDefinitions(Class);
      for (unsigned i = 0, e = Recs.size(); i != e; ++i)
        *Out << Recs[i]->getName() << ", ";
      *Out << "\n";
      break;
    }
    default:
      assert(1 && "Invalid Action");
      return 1;
    }
    
    if (Out != &outs())
      delete Out;                               // Close the file
    return 0;
    
  } catch (const TGError &Error) {
    errs() << argv[0] << ": error:\n";
    PrintError(Error.getLoc(), Error.getMessage());
    
  } catch (const std::string &Error) {
    errs() << argv[0] << ": " << Error << "\n";
  } catch (const char *Error) {
    errs() << argv[0] << ": " << Error << "\n";
  } catch (...) {
    errs() << argv[0] << ": Unknown unexpected exception occurred.\n";
  }
  
  if (Out != &outs()) {
    delete Out;                             // Close the file
    std::remove(OutputFilename.c_str());    // Remove the file, it's broken
  }
  return 1;
}
