/*
 *  Compile LLVM bytecode to ClamAV bytecode.
 *
 *  Copyright (C) 2009-2010 Sourcefire, Inc.
 *
 *  Authors: Török Edvin
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */
#include "llvm/System/DataTypes.h"
#include "clambc.h"
#include "ClamBCModule.h"
#include "ClamBCCommon.h"
#include "ClamBCTargetMachine.h"
#include "llvm/Analysis/Verifier.h"
#include "llvm/Bitcode/ReaderWriter.h"
#include "llvm/Config/config.h"
#include "llvm/Pass.h"
#include "llvm/PassManager.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetRegistry.h"
#include "llvm/Transforms/IPO.h"
#include "llvm/Transforms/Scalar.h"
#include <cstring>
using namespace llvm;

extern "C" int ClamBCTargetMachineModule;
int ClamBCTargetMachineModule = 0;

// Register the target.
extern Target TheClamBCTarget;

static cl::opt<bool>
DumpIR("clambc-dumpir", cl::Hidden, cl::init(false),
       cl::desc("Dump LLVM IR just before writing out ClamBC"));

static cl::opt<std::string> ApiMap("clam-apimap", cl::desc("Load API map from file"),
                                   cl::value_desc("C file containing API map"),
                                   cl::init(""));


// Force static initialization.
extern "C" void LLVMInitializeClamBCTarget() {
  RegisterTargetMachine<ClamBCTargetMachine> X(TheClamBCTarget);
}

static bool loadAPIList(std::vector<std::string> &APIList)
{
  if (ApiMap == "")
    return true;

  std::string ErrorMessage;
  MemoryBuffer *Buffer =
    MemoryBuffer::getFile(ApiMap.c_str(), &ErrorMessage);

  if (!Buffer) {
    errs() << "Could not open input file '" << ApiMap << "': "
      << ErrorMessage << "\n";
    return false;
  }

  const char *start = Buffer->getBufferStart();
  const char *begin = strstr(start, clamav::apicall_begin);
  if (!begin) {
    errs() << "ERROR: " << clamav::apicall_begin << " not found in '" <<
      ApiMap << "'\n";
    return false;
  }
  const char *end = strstr(begin, clamav::apicall_end);
  if (!end) {
    errs() << "ERROR: " << clamav::apicall_end << " not found in '" <<
      ApiMap << "'\n";
    return false;
  }

  do {
    const char *funcname = strchr(begin, '"');
    if (!funcname) {
      break;
    }
    const char *funcend = strchr(++funcname, '"');
    if (!funcend) {
      errs() << "ERROR: Invalid line format in '" << ApiMap << "'\n";
      return false;
    }
    std::string Name(funcname, funcend-funcname);
    APIList.push_back(Name);
    begin = strchr(funcname , '\n');
  } while (begin && begin < end);

  delete Buffer;
  return true;
}


bool ClamBCTargetMachine::addPassesToEmitWholeFile(PassManager &PM,
                                                   formatted_raw_ostream &o,
                                                   CodeGenFileType FileType,
                                                   CodeGenOpt::Level OptLevel,
                                                   bool DisableVerify) {
  if (FileType != TargetMachine::CGFT_AssemblyFile) return true;

  std::vector<std::string> APIList;
  loadAPIList(APIList);
  ClamBCModule *module = new ClamBCModule(o, APIList);
  
  //  PM.add(createStripSymbolsPass(true));
  std::vector<const char*> exports;
  exports.push_back("entrypoint");
  exports.push_back("main");
  exports.push_back("logical_trigger");
  exports.push_back("__clambc_kind");
  exports.push_back("__Copyright");
  PM.add(createGlobalDCEPass());
  PM.add(createStripDeadPrototypesPass());
  PM.add(createDeadTypeEliminationPass());
  PM.add(createConstantMergePass());

  PM.add(createPromoteMemoryToRegisterPass());
  PM.add(createAlwaysInlinerPass());
  PM.add(createGlobalOptimizerPass());
  PM.add(createLowerSwitchPass());
  PM.add(createLowerInvokePass());
  PM.add(createSimplifyLibCallsPass());
  PM.add(createGlobalOptimizerPass());
  PM.add(createCFGSimplificationPass());
  PM.add(createIndVarSimplifyPass());
  PM.add(createConstantPropagationPass());
  PM.add(createClamBCLowering(false));
  PM.add(createClamBCVerifier(false));
  PM.add(createClamBCRTChecks());
  PM.add(createClamBCLowering(false));
  PM.add(createDeadCodeEliminationPass());
  if (DumpIR)
    PM.add(createBitcodeWriterPass(outs()));
  PM.add(createClamBCLogicalCompiler());
  PM.add(createInternalizePass(exports));
  PM.add(createGlobalDCEPass());
  PM.add(createInstructionCombiningPass());
  PM.add(createCFGSimplificationPass());
  PM.add(createClamBCTrace());
  PM.add(createClamBCLowering(true));
  PM.add(createDeadCodeEliminationPass());
  PM.add(createClamBCVerifier(false));
  PM.add(createVerifierPass());
  PM.add(createStripDebugDeclarePass());
  PM.add(createGEPSplitterPass());
  PM.add(module);
  PM.add(createVerifierPass());
  PM.add(createClamBCWriter(module));
  return false;
}
