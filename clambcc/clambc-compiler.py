#!/usr/bin/env python3

from optparse import OptionParser, Values
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from typing import Union


#These are the list of supported versions
CLANG_LLVM_KNOWN_VERSIONS = [16]

#This is the min clang/llvm version this has been tested with.
MIN_CLANG_LLVM_VERSION = 16
PREFERRED_CLANG_LLVM_VERSION = 16

CLANG_NAME = "clang"
LLVM_NAME = "opt"

CLANG_BINARY_ARG = "--clang-binary"
OPT_BINARY_ARG = "--opt-binary"

COMPILED_BYTECODE_FILE_EXTENSION = "cbc"
LINKED_BYTECODE_FILE_EXTENSION = "linked.ll"
OPTIMIZED_BYTECODE_FILE_EXTENSION = "optimized.ll"
OPEN_SOURCE_GENERATED_EXTENSION = "generated.c"
OPTIMIZED_TMP_BYTECODE_FILE_EXTENSION = "optimized.tmp.ll"

COMMON_WARNING_OPTIONS = [
    "-Wno-backslash-newline-escape",
    "-Wno-pointer-sign",
    "-Wno-return-type",
    "-Wno-incompatible-pointer-types",
    "-Wno-unused-value",
    "-Wno-shift-negative-value",
    "-Wno-implicit-function-declaration",
    "-Wno-incompatible-library-redeclaration",
    "-Wno-implicit-int",
    "-Wno-constant-conversion",
]

TMPDIR=".__clambc_tmp"

INCDIR = str(Path(__file__).parent / '..' / 'include')

# Check for libclambcc.so at a location relative to this script first.
FOUND_SHARED_OBJ = False

SHARED_OBJ_DIR = Path(__file__).parent / '..' / 'lib'
if (SHARED_OBJ_DIR / 'libClamBCCommon.so').exists():
    FOUND_SHARED_OBJ = True

elif 'LD_LIBRARY_PATH' in os.environ:
    # Use LD_LIBRARY_PATH to try to find it.
    ld_library_paths = os.environ['LD_LIBRARY_PATH'].strip(' :').split(':')
    for lib_path in ld_library_paths:
        if (Path(lib_path) / 'libClamBCCommon.so').exists():
            SHARED_OBJ_DIR = Path(lib_path)
            FOUND_SHARED_OBJ = True
            break

VERBOSE=False

#Set of build tools needed on the system.
class ClangLLVM():
    def getLinkFromOpt(self, opt) -> None:
        dirName = os.path.dirname(opt)
        baseName = re.sub("opt", "llvm-link", os.path.basename(opt))
        self.link = os.path.join(dirName, baseName)

    def __init__(self, clangBinary: str, optBinary: str) -> None:
        self.clang = clangBinary
        self.opt = optBinary
        self.link = None
        self.getLinkFromOpt(self.opt)

    def getClang(self) -> str:
        return self.clang

    def getOpt(self) -> str:
        return self.opt

    def getLLVMLink(self) -> str:
        return self.link

    def validate(self) -> bool:
        optVersion = findVersion(self.opt, "--version")
        clangVersion = findVersion(self.clang, "--version")
        llvmLinkVersion = findVersion(self.link, "--version")

        if optVersion == -1:
            print("error: unable to get version information for opt", file=sys.stderr)
            return False

        if optVersion != clangVersion:
            print("error: versions of opt and clang must match", file=sys.stderr)
            return False

        if optVersion != llvmLinkVersion:
            print("error: versions of opt and llvm-link must match", file=sys.stderr)
            return False

        return True


def run(cmd: list) -> int:
    cmd = ' '.join(cmd)
    if VERBOSE:
        print(cmd)

    ret = os.system(cmd)
    if ret:
        print (cmd)
        print (ret)
        sys.exit(1)

    return ret


def die(msg: str, exitStatus: int) -> None:
    print(msg, file=sys.stderr)
    sys.exit(exitStatus)


def dieNoInputFile():
    die("No input file", 1)

def getNameNewExtension(fName: str, newExtension: str) -> str:
    newName = fName
    idx = newName.rfind(".")
    if -1 != idx:
        newName = newName[0:idx]

    ret = f"{newName}.{newExtension}"
    return ret

def getOutfile(options: Values, args: list) -> str:
    ret = options.outfile

    if not ret:
        if (1 > len(args)):
            #How did we even get here?
            dieNoInputFile()
        fName = os.path.basename(args[0])
        ret = getNameNewExtension(fName, COMPILED_BYTECODE_FILE_EXTENSION)

    if os.path.isdir(ret):
        fName = os.path.basename(args[0])
        fName = getNameNewExtension(fName, COMPILED_BYTECODE_FILE_EXTENSION)
        ret = os.path.join(ret, fName)

    if None == ret:
        #HOW did we  get here???
        import pdb ; pdb.set_trace()

    return ret

def getIrFile(fileName: str, debugBuild: bool) -> str:
    if debugBuild:
        outFile = getNameNewExtension(os.path.basename(fileName), "debug.ll")
    else:
        outFile = getNameNewExtension(os.path.basename(fileName), "ll")
    outFile = os.path.join(TMPDIR, outFile)
    return outFile

#The 'noBytecodeOptions' is to be used if we are building a "normal" executable (for unit tests).
def compileFile(clangLLVM: ClangLLVM, fileName: str, debugBuild: bool, standardCompiler: bool, options: Values) -> int:
    '''
    Compile a `.bc` bytecode signature source file.
    Returns the exit status code for the call to `clang`.
    '''

    outFile = getIrFile(fileName, debugBuild)

    cmd = []
    cmd.append(clangLLVM.getClang())
    #cmd.append("-m32") # TODO: Put this back and resolve issues with it.
    cmd.append("-S")
    cmd.append("-fno-discard-value-names")
    cmd.append("-Wno-implicit-function-declaration")
    cmd.append("-fno-vectorize")
    cmd.append("--language=c")
    cmd.append("-emit-llvm")
    cmd.append("-Werror=unused-command-line-argument")
    cmd.append("-Xclang")
    cmd.append("-disable-O0-optnone")
    cmd.append("-Xclang -no-opaque-pointers")
    cmd.append(fileName)
    cmd.append("-o")
    cmd.append(outFile)
    cmd.append("-I")
    cmd.append(INCDIR)
    cmd.append("-include")
    cmd.append("bytecode.h")
    cmd.append("-D__CLAMBC__")

    if options.includes:
        for i in options.includes:
            cmd.append("-I")
            cmd.append(i)

    if options.defines:
        for d in options.defines:
            cmd.append('-D')
            cmd.append(d)

    if debugBuild:
        cmd.append('-g')

    if options.disableCommonWarnings:
        cmd += COMMON_WARNING_OPTIONS

    cmd += options.passthroughOptions

    return run(cmd)


def compileFiles(clangLLVM: ClangLLVM, args: list, debugBuild: bool, standardCompiler: bool, options: Values) -> int:
    for a in args:
        exitStat = compileFile(clangLLVM, a, debugBuild, standardCompiler, options)
        if exitStat:
            return exitStat

    return 0

def getLinkedFileName(outputFileName: str) -> str:
    idx = outputFileName.find(COMPILED_BYTECODE_FILE_EXTENSION)
    if -1 == idx:
        die("getLinkedFileName called with invalid input", 2)

    outFileNoExtension = os.path.join(TMPDIR, outputFileName[0:idx])
    return f"{outFileNoExtension}{LINKED_BYTECODE_FILE_EXTENSION}"

def getOptimizedFileName(outputFileName: str) -> str:
    idx = outputFileName.find(COMPILED_BYTECODE_FILE_EXTENSION)
    if -1 == idx:
        die("getOptimizedFileName called with invalid input", 2)

    outFileNoExtension = os.path.join(TMPDIR, outputFileName[0:idx])
    return f"{outFileNoExtension}{OPTIMIZED_BYTECODE_FILE_EXTENSION}"

def getInputSourceFileName(outputFileName: str) -> str:
    idx = outputFileName.find(COMPILED_BYTECODE_FILE_EXTENSION)
    if -1 == idx:
        die("getInputSourceFileName called with invalid input", 2)

    outFileNoExtension = os.path.join(TMPDIR, outputFileName[0:idx])
    return f"{outFileNoExtension}{OPEN_SOURCE_GENERATED_EXTENSION}"

#Takes as input the linked bitcode file from llvm-link.
def getOptimizedTmpFileName(linkedFile: str) -> str:
    idx = linkedFile.find(LINKED_BYTECODE_FILE_EXTENSION)
    if -1 == idx:
        die("getOptimizedTmpFileName called with invalid input", 2)

    return f"{linkedFile[0:idx]}{OPTIMIZED_TMP_BYTECODE_FILE_EXTENSION}"

def linkIRFiles(clangLLVM: ClangLLVM, linkedFile: str, irFiles: list) -> int:
    '''
    Given an output file name and list of IR files, link the IR files.
    Returns the exit status code for the call to `llvm-link`.
    '''
    cmd = []
    cmd.append(clangLLVM.getLLVMLink())
    cmd.append("-S")
    cmd.append("-o")
    cmd.append(linkedFile)
    cmd += irFiles

    # Allow pointers that are not opaque.
    #
    # LLVM has decided to make all pointers opaque.
    # With this, pointers will not have an associated type. So to get the type, users will have to find where a pointer
    # is allocated, and what is assigned to it, or look at the instructions where it is used.
    #
    # TODO: LLVM 16 has this flag to use the old behavior, but it will be removed in LLVM 18.
    # The next upgrade will need to remove this option, and to deal with converting to opaque pointers.
    #
    # For more information, see
    # - https://llvm.org/docs/OpaquePointers.html
    # - https://llvm.org/devmtg/2022-04-03/slides/keynote.Opaque.Pointers.Are.Coming.pdf
    cmd.append("-opaque-pointers=0")

    return run(cmd)


def linkFiles(clangLLVM: ClangLLVM, linkedFile: str, args: list, debugBuild: bool) -> int:
    '''
    Given an output file name and the compiler argument list, assemble a list of IR files and link the IR files.
    Returns the exit status code for the call to `llvm-link`.
    '''
    lst = []
    for f in args:
        ir = getIrFile(f, debugBuild)
        lst.append(ir)

    return linkIRFiles(clangLLVM, linkedFile, lst)


class IRFile():
    def __init__(self, files, globalValues):
        self.files = files
        self.globalValues = globalValues

    def getKeyFromFile(self, fileName):
        for k in self.files.keys():
            if self.files[k] == fileName:
                return k
        return None


#We don't make effort to remove unused global variables because
#they could have been removed by constant propagation, and still
#be necessary to understanding the original source.
def parseIR(fileName: str) -> IRFile:
    f = open(fileName)
    lines = f.readlines()
    f.close()

    dbgFiles = {}
    dbgGlobals = {}
    for i in range(0, len(lines)):
        line = lines[i].rstrip()

        m = re.search("^![0-9]", line)
        if not m:
            continue

        m = re.search('^(![0-9]*) = !DIFile\(filename: "([^"]*)", directory: "([^"]*)"', line)
        if m:
            key = m.group(1)
            filename = os.path.join(m.group(3), m.group(2))
            dbgFiles[key] = filename
            continue

        m = re.search("distinct !DIGlobalVariable.*file: (![^,]*),.* line: ([0-9]*)", line)
        if m:
            key = m.group(1)
            lineNumber = int(m.group(2))
            if not key in dbgGlobals.keys():
                dbgGlobals[key] = []
            dbgGlobals[key].append(lineNumber)
            continue

        m = re.search("distinct !DISubprogram.*file: (![^,]*),.* line: ([0-9]*)", line)
        if m:
            key = m.group(1)
            if not key in dbgGlobals.keys():
                dbgGlobals[key] = []
            dbgGlobals[key].append(int(m.group(2)))
            continue

    for k in dbgGlobals.keys():
        dbgGlobals[k] = sorted(dbgGlobals[k])

    return IRFile(dbgFiles, dbgGlobals)


def generateIgnoreList(optimized: IRFile, linked: IRFile) -> dict:

    ignore = {}
    for key in optimized.files.keys():
        val = 0
        linkedKey = linked.getKeyFromFile(optimized.files[key])
        if not linkedKey:
            print("HOW DID THIS HAPPEN?")
            import pdb ; pdb.set_trace()

        if not linkedKey in linked.globalValues.keys():
            continue
        for vLinked in linked.globalValues[linkedKey]:
            if not vLinked in optimized.globalValues.keys():
                continue
            if not vLinked in optimized.globalValues[key]:

                if not linkedKey in ignore.keys():
                    ignore[linkedKey] = []
                ignore[linkedKey].append(vLinked)

    return ignore


def getOutputString(linked: IRFile, ignore: IRFile) -> str:

    CLAM_BYTECODE_HEADERS = ['bytecode_api.h', 'bytecode_local.h']

    out = ""
    keys = linked.globalValues.keys()

    for iteration in range(0,2):

        for k in keys:

            #No reason to copy the file.
            if not k in linked.globalValues.keys():
                continue

            fileName = linked.files[k]

            if os.path.basename(fileName) in CLAM_BYTECODE_HEADERS:
                continue

            if ((0 == iteration) and (not fileName.endswith(".h"))):
                continue
            if ((1 == iteration) and (fileName.endswith(".h"))):
                continue

            if not os.path.isfile(fileName):
                continue

            f = open(fileName)
            lines = f.readlines()
            f.close()

            #Nothing to ignore in this file.
            if not k in ignore.keys():
                out += "".join(lines)
                continue

            ignoreLst = ignore[k]
            gvs = linked.globalValues[k]

            iIdx = 0
            gIdx = 0

            idx = 0
            ignoreIdx = ignoreLst[iIdx]

            while idx < len(lines):
                if (not ignoreIdx):
                    out += "".join(lines[idx:])
                    break
                else:
                    out += "".join(lines[idx:ignoreIdx-1])

                    found = False
                    while gIdx < len(gvs):
                        idx = gvs[gIdx]
                        gIdx += 1
                        if idx >= ignoreIdx:
                            #break
                            if not idx in ignoreLst:
                                found = True
                                idx -= 1 #subtract one because these line numbers start with 1 and not 0
                                break
                    if not found:
                        break

                    found = False
                    while iIdx < len(ignoreLst):
                        ignoreIdx = ignoreLst[iIdx]
                        iIdx += 1
                        if (ignoreIdx > idx):
                            found = True
                            break
                    if not found:
                        ignoreIdx = None

    return out


def createOptimizedTmpFile(clangLLVM: ClangLLVM, linkedFile: str) -> str:
    name = getOptimizedTmpFileName(linkedFile)

    cmd = []
    cmd.append(clangLLVM.getOpt())
    cmd.append("-S")
    cmd.append(linkedFile)
    cmd.append("-o")
    cmd.append(name)
    cmd.append("-internalize-public-api-list=entrypoint")
    cmd.append('--passes="internalize,globalopt"')

    ret = run(cmd)
    if None == ret:
        return None

    return name


def createInputSourceFile(clangLLVM: ClangLLVM, name: str, args: list, options: Values) -> int:
    res = compileFiles(clangLLVM, args, True, False, options)

    idx = name.find( OPEN_SOURCE_GENERATED_EXTENSION )
    if -1 == idx:
        die("createInputSourceFile called with invalid input", 2)

    if not res:
        linkedFile = f"{name[0:idx]}debug.{LINKED_BYTECODE_FILE_EXTENSION}"
        res = linkFiles(clangLLVM, linkedFile, args, True)

    if not res:
        optimizedTmpFile = createOptimizedTmpFile(clangLLVM, linkedFile)
        if None == optimizedTmpFile:
            res = -1

    if not res:
        optimized = parseIR(optimizedTmpFile)
        linked = parseIR(linkedFile)
        ignore = generateIgnoreList(optimized, linked)
        out = getOutputString(linked, ignore)

        f = open(name, "w")
        if f:
            f.write(out)
            f.close()
        else:
            res = -1

    return res

# These are a list of functions that we don't want to internalize, or else it will rip these out.
# We internalize everything else.
INTERNALIZE_API_LIST=[
    "_Z10entrypointv",
    "entrypoint",
    "__clambc_kind",
    "__clambc_virusname_prefix",
    "__clambc_virusnames",
    "__clambc_filesize",
    "__clambc_match_counts",
    "__clambc_match_offsets",
    "__clambc_pedata",
    "__Copyright",
]

OPTIMIZE_OPTIONS = [
    "-S",
    "--disable-loop-unrolling",
    "--disable-i2p-p2i-opt",
    "--disable-loop-unrolling",
    "--disable-promote-alloca-to-lds",
    "--disable-promote-alloca-to-vector",
    "--disable-simplify-libcalls",
    "--disable-tail-calls",
    "--vectorize-slp=false",
    "--vectorize-loops=false",
    "-internalize-public-api-list=\"%s\"" % ','.join(INTERNALIZE_API_LIST),
]

# TODO: Remove this when we properly handle opaque pointers.
OPTIMIZE_OPTIONS.append("-opaque-pointers=0")

OPTIMIZE_PASSES = [
    # Convert function parameters to use registers as much as possible.
    'function(mem2reg)',
    'verify',

    # Prevent undefined or poison values from being inserted into the function calls by the 'O3' pass.
    # This pass should probably be renamed, since the ABI is not really changed.
    # Undefined values cause issues with the ClamBCWriter, and with ClamAV's runtime.
    #
    # The first call to preserve 'clambc-preserve-abis' adds fake function calls using all parameters so that 'O3' does
    # not optimize out unused functions or parameters. After the 'O3' pass, we undo it.
    'clambc-preserve-abis',
    'verify',

    # Run Clang's '-O3' optimizations.
    'default<O3>',

    # Removes unused globals and unused variables.
    'globalopt',

    # Remove the fake function calls tha we added with the first call to 'clambc-preserve-abis'.
    'clambc-preserve-abis',
    'verify',

    # Remove calls to smin intrinsics.
    # Smin intrinsics are not supported by the ClamAV runtime, so this pass creates it's own smin functions, and replaces
    # calls to intrinsics with calls to the newly created functions.
    #
    # For more on smin intrinsics, see https://llvm.org/docs/LangRef.html#llvm-smin-intrinsic.
    'clambc-remove-unsupported-icmp-intrinsics',
    'verify',

    # Remove calls to llvm.usub.sat.i32 because they are not supported by our runtime.
    # Removal is handled by creating our own function with the same behavior.
    # Currently, this pass only removes i32, which may be an oversight.
    #
    # Developer note: I don't remember if I was unable to get clang to generate other intrinsics, or I just forgot to add them.
    # In either case, it would not be difficult to add by duplicating the code, and changing types from 32-bit to whatever
    # bitwidth is needed.
    #
    # For more information, see https://llvm.org/docs/LangRef.html#llvm-usub-sat-intrinsics.
    'clambc-remove-usub',
    'verify',

    # Remove llvm.fshl.i32, llvm.fshl.i16, and llvm.fshl.i8 because they are not handled by our runtime.
    # Removal is handled by creating our own function with the same behavior.
    #
    # Developer Note: 64-bit was omitted because I could not find a testcase that would have used it.
    # There is an outline in the code for how it would be added.
    #
    # For more on fshl intrinsics, see https://llvm.org/docs/LangRef.html#llvm-fshl-intrinsic.
    'clambc-remove-fshl',
    'verify',

    # Perform lowering pass.
    # In practice, this lowering pass changes index sizes from 64bit to 32bit in `GetElementPtr` instructions.
    # There are some other lowering pass cases that are not run, either with our current signature set or because of prior passes. 
    # For example, one of them lowers all `PtrToInt` instructions to point have a type of `i8`. 
    # However, `PtrToIntInst` is not allowed, so this code never executes.
    # It's possible some of these lowering pass cases were works-in-progress that were solved another way.
    'clambc-lowering-notfinal',
    'verify',

    # This is an LLVM built-in pass that converts switch operations to a series of branches (ifs).
    # This allows our runtime to get away with not implementing the switch instruction.
    # See: https://llvm.org/docs/Passes.html#lower-switch-lower-switchinsts-to-branches
    'lowerswitch',
    'verify',

    # Remove icmp (Integer Compare) sle (Signed Less than or Equal) instructions because they are not supported by our runtime.
    # Very simple pass to swap the operands of the icmp sle instructions and replace them with sge (Signed Greater than or Equal).
    #
    # For more information about icmp instructions, see https://llvm.org/docs/LangRef.html#icmp-instruction.
    'clambc-remove-icmp-sle',
    'verify',

    # Verify that all functions in an IR signature don't break any of the rules for the llvm runtime.
    # Rules include:
    # - no variadic functions
    # - no calls through function pointers
    # - no undefs or poison values
    'function(clambc-verifier)',
    'verify',

    # Remove freeze instructions because they are not handled by our runtime.
    # This pass replaces the freeze instructions with what it was passed, since the freeze instruction is to give a
    # guaranteed value for a specific type, which may otherwise return an undef or poison value.
    #
    # For more information on freeze instructions, see https://llvm.org/docs/LangRef.html#freeze-instruction.
    'clambc-remove-freeze-insts',
    'verify',

    # Perform lowering pass, again.
    'clambc-lowering-notfinal',
    'verify',

    # The ClamBCLogicalCompiler pass requires that 'setvirusname' is called with a string constant.
    # One of the passes in '-O3' creates a pointer, sets the value of the pointer to different constants based on the code,
    # and calls 'setvirusname' with that.
    # This pass moves the calls to 'setvirusname' to the blocks where the pointer would be set.
    'clambc-lcompiler-helper',
    'verify',

    # Replaces the 'logical_trigger' function with a logical expression signature.
    # For more information on the 'logical_trigger' function, see the documentation for writing bytecode signatures.
    'clambc-lcompiler',
    'verify',

    # This pass loops over all of the functions in the input module, looking for a main function. 
    # If a main function is found, all other functions and all global variables with initializers are marked as internal.
    #
    # We maintain a list of public API functions to NOT internalize. See `INTERNALIZE_API_LIST`, above.
    #
    # See: https://llvm.org/docs/Passes.html#internalize-internalize-global-symbols
    'internalize',
    'verify',

    # Create new functions that replace all pointer types with 'i8' pointer types.
    # This requires recalculating all offsets, as well as handling structure types.
    'clambc-rebuild',
    'verify',

    # This pass removes pointer phis, and replaces them with an index calculation to get the same offset.
    #
    # Note: This is only needed for 0.103 on Windows where we're using an older vendored version of LLVM for the runtime.
    #       This can be removed when 0.103 support is no longer required.
    'clambc-remove-pointer-phis',
    'verify',

    # Tracing is not currently working, and the option is hidden.
    #
    # Developer Note: It should really be removed from the driver until it is tested.
    # It was an option in the original version, and never finished in the upgrade.
    # I don't know how well it worked (or if it worked) in the first place.
    'clambc-trace',
    'verify',

    # Outlines endianness calls (i.e. the opposite of inlining).
    #
    # Developer Note: At one point, the big endian calls were being replaced with a constant, or inlined, and was causing
    # issues with one of the signatures in testing. I don't remember which signature was the problem, but I believe the
    # platform was Windows.
    # This was added as part of 0.105.
    #
    # TODO: The next time we upgrade, we should evaluate if this is still necessary.
    'clambc-outline-endianness-calls',
    'verify',

    # Extends all integer phi nodes to use 64-bit values.
    #
    # TODO: I don't remember what the reason was that I needed to add this. It should be re-evaluated for the next release.
    'clambc-extend-phis-to-64-bit',
    'verify',

    # Converts intrinsic calls to use the 32-bit version, instead of the 64-bit version.
    # This is due to the 32-bit intrinsics being hard-coded in `libclamav/c++/bytecode2llvm.cpp`.
    'clambc-convert-intrinsics-to-32Bit',
    'verify',

    # Removes unused globals and unused variables (again).
    # One of the passes above may have created new unused globals or variables.
    # Rather than find out which one and clean it up manually, we run this.
    'globalopt',

    # Converts structure and array 'GetElementPtrInst' to arrays of i8 pointers.
    # See:
    # - https://llvm.org/docs/LangRef.html#getelementptr-instruction
    # - https://llvm.org/docs/GetElementPtr.html
    #
    # Some of these are missed by ClamBCRebuild, and are handled here.
    # Additionally, the writer does not support 'GetElementPtrInst' instructions with more than 2 operands.
    # See visitGetElementPtrInst() in ClamBCWriter.cpp, currently on line 943.
    'clambc-prepare-geps-for-writer',
    'verify',

    # Convert the modified llvm bitcode to a ClamAV signature.
    'clambc-writer',
    'verify',
]

OPTIMIZE_LOADS=[
    f"--load {SHARED_OBJ_DIR}/libClamBCCommon.so",

    f"--load-pass-plugin {SHARED_OBJ_DIR}/libClamBCPreserveABIs.so",
    f"--load-pass-plugin {SHARED_OBJ_DIR}/libClamBCRemoveUnsupportedICMPIntrinsics.so",
    f"--load-pass-plugin {SHARED_OBJ_DIR}/libClamBCRemoveUSUB.so",
    f"--load-pass-plugin {SHARED_OBJ_DIR}/libClamBCRemoveFSHL.so",

    # TODO: libClamBCRemovePointerPHIs.so is required for ClamAV 0.103 support, but may be removed eventually.
    f"--load-pass-plugin {SHARED_OBJ_DIR}/libClamBCRemovePointerPHIs.so",

    f"--load-pass-plugin {SHARED_OBJ_DIR}/libClamBCLoweringNF.so",
    f"--load-pass-plugin {SHARED_OBJ_DIR}/libClamBCRemoveICMPSLE.so",
    f"--load-pass-plugin {SHARED_OBJ_DIR}/libClamBCVerifier.so",
    f"--load-pass-plugin {SHARED_OBJ_DIR}/libClamBCRemoveFreezeInsts.so",

    # libClamBCLoweringF.so is no longer being run. The NF (non-final) version is used twice, instead.
    # The F (final) version was left in due to an oversight.
    #
    # TODO: May be removed in the future.
    # f"--load-pass-plugin {SHARED_OBJ_DIR}/libClamBCLoweringF.so",

    f"--load-pass-plugin {SHARED_OBJ_DIR}/libClamBCLogicalCompilerHelper.so",
    f"--load-pass-plugin {SHARED_OBJ_DIR}/libClamBCLogicalCompiler.so",
    f"--load-pass-plugin {SHARED_OBJ_DIR}/libClamBCRebuild.so",
    f"--load-pass-plugin {SHARED_OBJ_DIR}/libClamBCTrace.so",
    f"--load-pass-plugin {SHARED_OBJ_DIR}/libClamBCOutlineEndiannessCalls.so",
    f"--load-pass-plugin {SHARED_OBJ_DIR}/libClamBCExtendPHIsTo64Bit.so",
    f"--load-pass-plugin {SHARED_OBJ_DIR}/libClamBCConvertIntrinsicsTo32Bit.so",
    f"--load-pass-plugin {SHARED_OBJ_DIR}/libClamBCPrepareGEPsForWriter.so",

    # This is an Analysis pass, used by 'clambc-writer'. There is no option to invoke is directly.
    #
    # This pass gathers all information about the signature. This pass:
    # 1. Does some validation (Developer Note: I know, shouldn't be done in an analysis pass).
    # 2. Generates maps of all global values (functions, global variables, constant expressions used to initialize
    #    global variables).
    # 3. Sorts functions in the file.
    # 4. Stores API Map of available functions that bytecode signatures can call in clamav.
    #    If functions are added to bytecode_api_decl.c.h, they also MUST be added to 'ClamBCAnalysis::populateAPIMap()'.
    f"--load-pass-plugin {SHARED_OBJ_DIR}/libClamBCAnalyzer.so",

    # This is an Analysis pass, used by 'clambc-writer'. There is no option to invoke is directly.
    #
    # This pass...
    # 1. Removes all PHI nodes.
    #    There are other places we change PHI nodes around, we should really consolidate them.
    #    Part of the reason for having to do it again, is because they could potentially be re-added by llvm passes that
    #    are run after previous clamav passes.
    # 2. Stores values in map to be used by the ClamBCWriter.
    f"--load-pass-plugin {SHARED_OBJ_DIR}/libClamBCRegAlloc.so",

    f"--load-pass-plugin {SHARED_OBJ_DIR}/libClamBCWriter.so",
]

def optimize(clangLLVM: ClangLLVM, inFile: str, outFile: str, sigFile: str, inputSourceFile: str, standardCompiler: bool) -> int:

    cmd = []
    cmd.append(clangLLVM.getOpt())
    cmd.append(inFile)
    cmd.append('-o')
    cmd.append(outFile)
    cmd += OPTIMIZE_OPTIONS
    cmd += OPTIMIZE_LOADS

    s = '--passes="'
    first = True
    for v in OPTIMIZE_PASSES:
        if first:
            first = False
        else:
            s += ','
        s += v
    s += '"'
    cmd.append(s)


    cmd.append(f'-clambc-writer-input-source={inputSourceFile}')
    cmd.append(f'-clambc-sigfile={sigFile}')

    return run(cmd)


#This is definitely hacky, but it's the only change I need to make for
#this to work
def fixFileSize(optimizedFile: str) -> None:
    f = open(optimizedFile)
    lines = f.readlines()
    f.close()

    changed = False

    for i in range(0, len(lines)):
        line = lines[i]
        m = re.search("^@__clambc_filesize.*constant", line)
        if m:
            line = re.sub(" constant ", " global ", line)
            lines[i] = line
            changed = True
            continue

        m = re.search("@CLAMBC_FILESIZE_PLACEHOLDER", line)
        if m:
            if re.search("^@CLAMBC_FILESIZE_PLACEHOLDER", line):
                #don't mess with the declaration
                continue

            line = re.sub("@CLAMBC_FILESIZE_PLACEHOLDER", "@__clambc_filesize", line)
            lines[i] = line
            changed = True

    if changed:
        f = open(optimizedFile, "w")
        f.write("".join(lines))
        f.close()


def findVersion(progName: str, versionOption: str) -> int:
    ret = -1
    try :
        sp = subprocess.Popen([progName, versionOption], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        err = sp.communicate()
        m = re.search("version\s*([0-9]*)\.", str(err))
        if m:
            ret = int(m.group(1))
    except FileNotFoundError:
        pass

    return ret


def genList(prog: str, maj: int) -> list:

    ret = [f"{prog}-{maj}"]
    for i in range(0, 10):
        ret.append(f"{prog}{maj}{9-i}")

    return ret


def findProgram(progName: str, versionOption: str, progVersion: int, strictVersion: bool) -> Union[str, None]:
    ret = None

    progList = []
    progList.extend(genList(progName, progVersion))

    if not strictVersion:
        for i in CLANG_LLVM_KNOWN_VERSIONS:
            if i == progVersion:
                continue
            progList.extend(genList(progName, i))

    for c in progList:
        try:
            subprocess.run([c, "-v"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return c
        except FileNotFoundError:
            pass

    version = findVersion(progName, versionOption)
    if  version == progVersion:
        return progName

    if not strictVersion:
        if version >= MIN_CLANG_LLVM_VERSION:
            return progName
    else:
        print(f"error: {progName} requested version not found", file=sys.stderr)

    return ret


def findClangLLVM(options: Values) -> ClangLLVM:
    cl = None

    if (((None == options.clangBinary) and (None != options.optBinary))
            or ((None != options.clangBinary) and (None == options.optBinary))):
        print(f"error: if '{CLANG_BINARY_ARG} is present, then {OPT_BINARY_ARG} must also be present", out=sys.stderr)
        sys.exit(1)


    if None != options.clangBinary:
        cl = ClangLLVM(options.clangBinary, options.optBinary)
    else:

        clangVersion = options.clangVersion
        llvmVersion = options.llvmVersion
        strictClang = True
        strictLLVM = True

        if None == clangVersion:
            clangVersion = PREFERRED_CLANG_LLVM_VERSION
            strictClang = False
        else:
            if not clangVersion.isnumeric():
                print(f"error: {clangVersion} must be passed an integer type")
                sys.exit(1)
            clangVersion = int(clangVersion)


        if None == options.llvmVersion:
            llvmVersion = PREFERRED_CLANG_LLVM_VERSION
            strictLLVM = False

        else:
            if not llvmVersion.isnumeric():
                print(f"error: {llvmVersion} must be passed an integer type")
                sys.exit(1)
            llvmVersion = int(llvmVersion)


        clang = findProgram(CLANG_NAME, "--version", clangVersion, strictClang)
        if None == clang:
            print(f"{CLANG_NAME} must be installed and in your path.", file=sys.stderr)

        opt = findProgram(LLVM_NAME, "--version", llvmVersion, strictLLVM)
        if None == opt:
            print(f"{LLVM_NAME} must be installed and in your path.", file=sys.stderr)

        if (clang and opt):
            cl = ClangLLVM(clang, opt)

    if cl:
        if not cl.validate():
            cl = None

    return cl


#The purpose of this class is to save off all the
#options we haven't added, and just assume that they are
#for the compiler, so that we don't have to support -Wall, -Werror, ...
class ClamBCCOptionParser(OptionParser):
    def __init__(self):
        OptionParser.__init__(self)
        self.passthrough = []

    def _process_short_opts(self, rargs, values):
        try:
            processing = rargs[0]
            OptionParser._process_short_opts(self, rargs, values)
        except Exception as e:
            self.passthrough.append(processing)

    def _process_long_opt(self, rargs, values):
        try:
            processing = rargs[0]
            OptionParser._process_long_opt(self, rargs, values)
        except Exception:
            self.passthrough.append(processing)

    def getPassthrough(self):
        return self.passthrough


def main():

    parser = ClamBCCOptionParser()
    parser.add_option("-V", "--version", dest="version", action="store_true", default=False)
    parser.add_option("-o", "--outfile", dest="outfile", default=None)
    parser.add_option("--save-tempfiles", dest="save", action="store_true", default=False)
    parser.add_option("-v", "--verbose", dest="verbose", action="store_true", default=False)

    parser.add_option("--clang-version", dest="clangVersion")
    parser.add_option("--llvm-version", dest="llvmVersion")

    parser.add_option(CLANG_BINARY_ARG, dest="clangBinary", help="Path to clang binary")
    parser.add_option(OPT_BINARY_ARG, dest="optBinary", help="Path to opt binary")

    parser.add_option("-I", action="append", dest="includes", default=None)
    parser.add_option("-D", action="append", dest="defines", default=None)
    parser.add_option("--disable-common-warnings", dest="disableCommonWarnings",
            action="store_true", default=True,
            help="{%s} (Found in some bytecode signatures)." % (' '.join(COMMON_WARNING_OPTIONS)))
    (options, args) = parser.parse_args()

    if options.version:
        print('ClamBC-Compiler @PACKAGE_VERSION@')
        sys.exit(0)


    clangLLVM = findClangLLVM(options)
    if None == clangLLVM:
        sys.exit(1)

    options.passthroughOptions = parser.getPassthrough()

    if not FOUND_SHARED_OBJ:
        die(f"Shared objects not found.  See instructions for building", 2)

    if 0 == len(args):
        dieNoInputFile()

    global VERBOSE
    VERBOSE = options.verbose

    outFile = getOutfile(options, args)
    outFile = os.path.basename(outFile)
    saveFiles = options.save

    createdDir = False

    if not os.path.isdir(TMPDIR):
        os.makedirs(TMPDIR)
        createdDir = True

    res = compileFiles(clangLLVM, args, False, False, options)

    if not res:
        linkedFile = getLinkedFileName(outFile)
        res = linkFiles(clangLLVM, linkedFile, args, False)

    if not res:
        inputSourceFile = getInputSourceFileName(outFile)
        res = createInputSourceFile(clangLLVM, inputSourceFile, args, options)

    if not res:
        optimizedFile = getOptimizedFileName(outFile)
        outFile = getOutfile(options, args)
        res = optimize(clangLLVM, linkedFile, optimizedFile, outFile, inputSourceFile, False)

    if ((not saveFiles) and createdDir):
        shutil.rmtree(TMPDIR)

    if res:
        if os.path.exists(outFile):
            os.remove(outFile)
        sys.exit(1)


if '__main__' == __name__:

    main()



