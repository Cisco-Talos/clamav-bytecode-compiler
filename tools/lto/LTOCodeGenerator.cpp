//===-LTOCodeGenerator.cpp - LLVM Link Time Optimizer ---------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
// 
//===----------------------------------------------------------------------===//
//
// This file implements the Link Time Optimization library. This library is 
// intended to be used by linker to optimize code at link time.
//
//===----------------------------------------------------------------------===//

#include "LTOModule.h"
#include "LTOCodeGenerator.h"


#include "llvm/Constants.h"
#include "llvm/DerivedTypes.h"
#include "llvm/Linker.h"
#include "llvm/LLVMContext.h"
#include "llvm/Module.h"
#include "llvm/ModuleProvider.h"
#include "llvm/PassManager.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/Triple.h"
#include "llvm/Analysis/Passes.h"
#include "llvm/Analysis/LoopPass.h"
#include "llvm/Analysis/Verifier.h"
#include "llvm/Bitcode/ReaderWriter.h"
#include "llvm/CodeGen/FileWriters.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FormattedStream.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/StandardPasses.h"
#include "llvm/Support/SystemUtils.h"
#include "llvm/System/Host.h"
#include "llvm/System/Program.h"
#include "llvm/System/Signals.h"
#include "llvm/Target/Mangler.h"
#include "llvm/Target/SubtargetFeature.h"
#include "llvm/Target/TargetOptions.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/Target/TargetData.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/Target/TargetRegistry.h"
#include "llvm/Target/TargetSelect.h"
#include "llvm/Transforms/IPO.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/Config/config.h"
#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>


using namespace llvm;

static cl::opt<bool> DisableInline("disable-inlining",
  cl::desc("Do not run the inliner pass"));


const char* LTOCodeGenerator::getVersionString()
{
#ifdef LLVM_VERSION_INFO
    return PACKAGE_NAME " version " PACKAGE_VERSION ", " LLVM_VERSION_INFO;
#else
    return PACKAGE_NAME " version " PACKAGE_VERSION;
#endif
}


LTOCodeGenerator::LTOCodeGenerator() 
    : _context(getGlobalContext()),
      _linker("LinkTimeOptimizer", "ld-temp.o", _context), _target(NULL),
      _emitDwarfDebugInfo(false), _scopeRestrictionsDone(false),
      _codeModel(LTO_CODEGEN_PIC_MODEL_DYNAMIC),
      _nativeObjectFile(NULL), _assemblerPath(NULL)
{
    InitializeAllTargets();
    InitializeAllAsmPrinters();
}

LTOCodeGenerator::~LTOCodeGenerator()
{
    delete _target;
    delete _nativeObjectFile;
}



bool LTOCodeGenerator::addModule(LTOModule* mod, std::string& errMsg)
{
    return _linker.LinkInModule(mod->getLLVVMModule(), &errMsg);
}
    

bool LTOCodeGenerator::setDebugInfo(lto_debug_model debug, std::string& errMsg)
{
    switch (debug) {
        case LTO_DEBUG_MODEL_NONE:
            _emitDwarfDebugInfo = false;
            return false;
            
        case LTO_DEBUG_MODEL_DWARF:
            _emitDwarfDebugInfo = true;
            return false;
    }
    errMsg = "unknown debug format";
    return true;
}


bool LTOCodeGenerator::setCodePICModel(lto_codegen_model model, 
                                       std::string& errMsg)
{
    switch (model) {
        case LTO_CODEGEN_PIC_MODEL_STATIC:
        case LTO_CODEGEN_PIC_MODEL_DYNAMIC:
        case LTO_CODEGEN_PIC_MODEL_DYNAMIC_NO_PIC:
            _codeModel = model;
            return false;
    }
    errMsg = "unknown pic model";
    return true;
}

void LTOCodeGenerator::setAssemblerPath(const char* path)
{
    if ( _assemblerPath )
        delete _assemblerPath;
    _assemblerPath = new sys::Path(path);
}

void LTOCodeGenerator::addMustPreserveSymbol(const char* sym)
{
    _mustPreserveSymbols[sym] = 1;
}


bool LTOCodeGenerator::writeMergedModules(const char *path,
                                          std::string &errMsg) {
  if (determineTarget(errMsg))
    return true;

  // mark which symbols can not be internalized 
  applyScopeRestrictions();

  // create output file
  std::string ErrInfo;
  raw_fd_ostream Out(path, ErrInfo,
                     raw_fd_ostream::F_Binary);
  if (!ErrInfo.empty()) {
    errMsg = "could not open bitcode file for writing: ";
    errMsg += path;
    return true;
  }
    
  // write bitcode to it
  WriteBitcodeToFile(_linker.getModule(), Out);
  
  if (Out.has_error()) {
    errMsg = "could not write bitcode file: ";
    errMsg += path;
    return true;
  }
  
  return false;
}


const void* LTOCodeGenerator::compile(size_t* length, std::string& errMsg)
{
    // make unique temp .s file to put generated assembly code
    sys::Path uniqueAsmPath("lto-llvm.s");
    if ( uniqueAsmPath.createTemporaryFileOnDisk(true, &errMsg) )
        return NULL;
    sys::RemoveFileOnSignal(uniqueAsmPath);
       
    // generate assembly code
    bool genResult = false;
    {
      raw_fd_ostream asmFD(uniqueAsmPath.c_str(), errMsg);
      formatted_raw_ostream asmFile(asmFD);
      if (!errMsg.empty())
        return NULL;
      genResult = this->generateAssemblyCode(asmFile, errMsg);
    }
    if ( genResult ) {
        if ( uniqueAsmPath.exists() )
            uniqueAsmPath.eraseFromDisk();
        return NULL;
    }
    
    // make unique temp .o file to put generated object file
    sys::PathWithStatus uniqueObjPath("lto-llvm.o");
    if ( uniqueObjPath.createTemporaryFileOnDisk(true, &errMsg) ) {
        if ( uniqueAsmPath.exists() )
            uniqueAsmPath.eraseFromDisk();
        return NULL;
    }
    sys::RemoveFileOnSignal(uniqueObjPath);

    // assemble the assembly code
    const std::string& uniqueObjStr = uniqueObjPath.str();
    bool asmResult = this->assemble(uniqueAsmPath.str(), uniqueObjStr, errMsg);
    if ( !asmResult ) {
        // remove old buffer if compile() called twice
        delete _nativeObjectFile;
        
        // read .o file into memory buffer
        _nativeObjectFile = MemoryBuffer::getFile(uniqueObjStr.c_str(),&errMsg);
    }

    // remove temp files
    uniqueAsmPath.eraseFromDisk();
    uniqueObjPath.eraseFromDisk();

    // return buffer, unless error
    if ( _nativeObjectFile == NULL )
        return NULL;
    *length = _nativeObjectFile->getBufferSize();
    return _nativeObjectFile->getBufferStart();
}


bool LTOCodeGenerator::assemble(const std::string& asmPath, 
                                const std::string& objPath, std::string& errMsg)
{
    sys::Path tool;
    bool needsCompilerOptions = true;
    if ( _assemblerPath ) {
        tool = *_assemblerPath;
        needsCompilerOptions = false;
    } else {
        // find compiler driver
        tool = sys::Program::FindProgramByName("gcc");
        if ( tool.isEmpty() ) {
            errMsg = "can't locate gcc";
            return true;
        }
    }

    // build argument list
    std::vector<const char*> args;
    llvm::Triple targetTriple(_linker.getModule()->getTargetTriple());
    const char *arch = targetTriple.getArchNameForAssembler();

    args.push_back(tool.c_str());

    if (targetTriple.getOS() == Triple::Darwin) {
        // darwin specific command line options
        if (arch != NULL) {
            args.push_back("-arch");
            args.push_back(arch);
        }
        // add -static to assembler command line when code model requires
        if ( (_assemblerPath != NULL) && (_codeModel == LTO_CODEGEN_PIC_MODEL_STATIC) )
            args.push_back("-static");
    }
    if ( needsCompilerOptions ) {
        args.push_back("-c");
        args.push_back("-x");
        args.push_back("assembler");
    }
    args.push_back("-o");
    args.push_back(objPath.c_str());
    args.push_back(asmPath.c_str());
    args.push_back(0);

    // invoke assembler
    if ( sys::Program::ExecuteAndWait(tool, &args[0], 0, 0, 0, 0, &errMsg) ) {
        errMsg = "error in assembly";    
        return true;
    }
    return false; // success
}



bool LTOCodeGenerator::determineTarget(std::string& errMsg)
{
    if ( _target == NULL ) {
        std::string Triple = _linker.getModule()->getTargetTriple();
        if (Triple.empty())
          Triple = sys::getHostTriple();

        // create target machine from info for merged modules
        const Target *march = TargetRegistry::lookupTarget(Triple, errMsg);
        if ( march == NULL )
            return true;

        // The relocation model is actually a static member of TargetMachine
        // and needs to be set before the TargetMachine is instantiated.
        switch( _codeModel ) {
        case LTO_CODEGEN_PIC_MODEL_STATIC:
            TargetMachine::setRelocationModel(Reloc::Static);
            break;
        case LTO_CODEGEN_PIC_MODEL_DYNAMIC:
            TargetMachine::setRelocationModel(Reloc::PIC_);
            break;
        case LTO_CODEGEN_PIC_MODEL_DYNAMIC_NO_PIC:
            TargetMachine::setRelocationModel(Reloc::DynamicNoPIC);
            break;
        }

        // construct LTModule, hand over ownership of module and target
        const std::string FeatureStr =
            SubtargetFeatures::getDefaultSubtargetFeatures(llvm::Triple(Triple));
        _target = march->createTargetMachine(Triple, FeatureStr);
    }
    return false;
}

void LTOCodeGenerator::applyScopeRestrictions()
{
    if ( !_scopeRestrictionsDone ) {
        Module* mergedModule = _linker.getModule();

        // Start off with a verification pass.
        PassManager passes;
        passes.add(createVerifierPass());

        // mark which symbols can not be internalized 
        if ( !_mustPreserveSymbols.empty() ) {
            Mangler mangler(*mergedModule, 
                                _target->getMCAsmInfo()->getGlobalPrefix());
            std::vector<const char*> mustPreserveList;
            for (Module::iterator f = mergedModule->begin(), 
                                        e = mergedModule->end(); f != e; ++f) {
                if ( !f->isDeclaration() 
                  && _mustPreserveSymbols.count(mangler.getNameWithPrefix(f)) )
                  mustPreserveList.push_back(::strdup(f->getNameStr().c_str()));
            }
            for (Module::global_iterator v = mergedModule->global_begin(), 
                                 e = mergedModule->global_end(); v !=  e; ++v) {
                if ( !v->isDeclaration()
                  && _mustPreserveSymbols.count(mangler.getNameWithPrefix(v)) )
                  mustPreserveList.push_back(::strdup(v->getNameStr().c_str()));
            }
            passes.add(createInternalizePass(mustPreserveList));
        }
        // apply scope restrictions
        passes.run(*mergedModule);
        
        _scopeRestrictionsDone = true;
    }
}

/// Optimize merged modules using various IPO passes
bool LTOCodeGenerator::generateAssemblyCode(formatted_raw_ostream& out,
                                            std::string& errMsg)
{
    if ( this->determineTarget(errMsg) ) 
        return true;

    // mark which symbols can not be internalized 
    this->applyScopeRestrictions();

    Module* mergedModule = _linker.getModule();

    // If target supports exception handling then enable it now.
    switch (_target->getMCAsmInfo()->getExceptionHandlingType()) {
    case ExceptionHandling::Dwarf:
      llvm::DwarfExceptionHandling = true;
      break;
    case ExceptionHandling::SjLj:
      llvm::SjLjExceptionHandling = true;
      break;
    case ExceptionHandling::None:
      break;
    default:
      assert (0 && "Unknown exception handling model!");
    }

    // if options were requested, set them
    if ( !_codegenOptions.empty() )
        cl::ParseCommandLineOptions(_codegenOptions.size(), 
                                                (char**)&_codegenOptions[0]);

    // Instantiate the pass manager to organize the passes.
    PassManager passes;

    // Start off with a verification pass.
    passes.add(createVerifierPass());

    // Add an appropriate TargetData instance for this module...
    passes.add(new TargetData(*_target->getTargetData()));
    
    createStandardLTOPasses(&passes, /*Internalize=*/ false, !DisableInline,
                            /*VerifyEach=*/ false);

    // Make sure everything is still good.
    passes.add(createVerifierPass());

    FunctionPassManager* codeGenPasses =
            new FunctionPassManager(new ExistingModuleProvider(mergedModule));

    codeGenPasses->add(new TargetData(*_target->getTargetData()));

    ObjectCodeEmitter* oce = NULL;

    switch (_target->addPassesToEmitFile(*codeGenPasses, out,
                                         TargetMachine::AssemblyFile,
                                         CodeGenOpt::Aggressive)) {
        case FileModel::ElfFile:
            oce = AddELFWriter(*codeGenPasses, out, *_target);
            break;
        case FileModel::AsmFile:
            break;
        case FileModel::MachOFile:
        case FileModel::Error:
        case FileModel::None:
            errMsg = "target file type not supported";
            return true;
    }

    if (_target->addPassesToEmitFileFinish(*codeGenPasses, oce,
                                           CodeGenOpt::Aggressive)) {
        errMsg = "target does not support generation of this file type";
        return true;
    }

    // Run our queue of passes all at once now, efficiently.
    passes.run(*mergedModule);

    // Run the code generator, and write assembly file
    codeGenPasses->doInitialization();

    for (Module::iterator
           it = mergedModule->begin(), e = mergedModule->end(); it != e; ++it)
      if (!it->isDeclaration())
        codeGenPasses->run(*it);

    codeGenPasses->doFinalization();

    return false; // success
}


/// Optimize merged modules using various IPO passes
void LTOCodeGenerator::setCodeGenDebugOptions(const char* options)
{
    for (std::pair<StringRef, StringRef> o = getToken(options);
         !o.first.empty(); o = getToken(o.second)) {
        // ParseCommandLineOptions() expects argv[0] to be program name.
        // Lazily add that.
        if ( _codegenOptions.empty() ) 
            _codegenOptions.push_back("libLTO");
        _codegenOptions.push_back(strdup(o.first.str().c_str()));
    }
}
