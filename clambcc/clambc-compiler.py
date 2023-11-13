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
        "-Wno-backslash-newline-escape"
      , "-Wno-pointer-sign"
      , "-Wno-return-type"
      , "-Wno-incompatible-pointer-types"
      , "-Wno-unused-value"
      , "-Wno-shift-negative-value"
      , "-Wno-implicit-function-declaration"
      , "-Wno-incompatible-library-redeclaration"
      , "-Wno-implicit-int"
      , "-Wno-constant-conversion"
      ]

TMPDIR=".__clambc_tmp"

INCDIR = str(Path(__file__).parent / '..' / 'include')

# Check for libclambcc.so at a location relative to this script first.
FOUND_SHARED_OBJ = False

SHARED_OBJ_DIR = Path(__file__).parent / '..' / 'lib'
if (SHARED_OBJ_DIR / 'libclambccommon.so').exists():
    SHARED_OBJ_FILE = SHARED_OBJ_DIR / 'libclambcc.so'
    FOUND_SHARED_OBJ = True

elif 'LD_LIBRARY_PATH' in os.environ:
    # Use LD_LIBRARY_PATH to try to find it.
    ld_library_paths = os.environ['LD_LIBRARY_PATH'].strip(' :').split(':')
    for lib_path in ld_library_paths:
        if (Path(lib_path) / 'libclambcc.so').exists():
            SHARED_OBJ_FILE = Path(lib_path) / 'libclambcc.so'
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
    #cmd.append("-m32") #TODO: Put this back and resolve issues with it.
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
        die("getLinkedFileName called with invalid input", 2)

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

    #TODO: Remove this in a future version, since it is a depracated option
    #      that will no longer be supported.  For a detailed explanation, see
    #      https://llvm.org/docs/OpaquePointers.html
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


INTERNALIZE_API_LIST=[ "_Z10entrypointv"
        , "entrypoint"
        , "__clambc_kind"
        , "__clambc_virusname_prefix"
        , "__clambc_virusnames"
        , "__clambc_filesize"
        , "__clambc_match_counts"
        , "__clambc_match_offsets"
        , "__clambc_pedata"
        , "__Copyright" 
        ]

OPTIMIZE_OPTIONS = ["-S"
        , "--disable-loop-unrolling"
        , " --disable-i2p-p2i-opt"
        , " --disable-loop-unrolling"
        , " --disable-promote-alloca-to-lds"
        , " --disable-promote-alloca-to-vector"
        , " --disable-simplify-libcalls"
        , " --disable-tail-calls"
        , " --vectorize-slp=false"
        , " --vectorize-loops=false"
        , " -internalize-public-api-list=\"%s\"" % ','.join(INTERNALIZE_API_LIST)
        ]

#TODO: Remove this when we properly handle opaque pointers.
OPTIMIZE_OPTIONS.append("-opaque-pointers=0")

OPTIMIZE_PASSES = ["function(mem2reg)"
        , 'verify'
#        , 'clambc-remove-undefs' #TODO: This was added because the optimizer in llvm-8 was replacing unused
                                  #      parameters with 'undef' values in the IR.  This was causing issues in
                                  #      the writer, not knowing what value to put in the signature.  The llvm-16
                                  #      optimizer no longer does this, so this value does not appear to still be
                                  #      needed.  I have already done work upgrading the pass to the new
                                  #      pass manager, so I want to leave it in place throughout the -rc phase
                                  #      in case someone comes up with a testcase that re-introduces this bug.
#        , 'verify'
        , 'clambc-preserve-abis'
        , 'verify'
        , 'default<O3>'
        , 'globalopt'
        , 'clambc-preserve-abis' #remove fake function calls because O3 has already run
        , 'verify'
        , 'clambc-remove-unsupported-icmp-intrinsics'
        , 'verify'
        , 'clambc-remove-usub'
        , 'verify'
        , 'clambc-remove-fshl'
        , 'verify'
        , 'clambc-lowering-notfinal' # perform lowering pass
        , 'verify'
        , 'lowerswitch'
        , 'verify'
        , 'clambc-remove-icmp-sle'
        , 'verify'
        , 'function(clambc-verifier)'
        , 'verify'
        , 'clambc-remove-freeze-insts'
        , 'verify'
        , 'clambc-lowering-notfinal'  # perform lowering pass
        , 'verify'
        , 'clambc-lcompiler-helper' #compile the logical_trigger function to a
        , 'verify'
        , 'clambc-lcompiler' #compile the logical_trigger function to a
        , 'verify'
        , 'internalize'
        , 'verify'
        , 'clambc-rebuild'
        , 'verify'
        , 'clambc-trace'
        , 'verify'
        , 'clambc-outline-endianness-calls'
        , 'verify'
#        , 'clambc-change-malloc-arg-size' #TODO: This was added because the legacy llvm runtime
                                           #      had issues with 32-bit phi nodes being used in
                                           #      calls to malloc.  I already did the work to
                                           #      update it to the new pass manager, but it appears
                                           #      to no longer be necessary.  I will remove it
                                           #      after the -rc phase if nobody has a testcase
                                           #      that requires it.
#        , 'verify'
        , 'clambc-extend-phis-to-64-bit'
        , 'verify'
        , 'clambc-convert-intrinsics-to-32Bit'
        , 'verify'
        , 'globalopt'
        , 'clambc-prepare-geps-for-writer'
        , 'verify'
        , 'clambc-writer'
        , 'verify'
]

OPTIMIZE_LOADS=[ f"--load {SHARED_OBJ_DIR}/libclambccommon.so"
#        , f"--load-pass-plugin {SHARED_OBJ_DIR}/libclambcremoveundefs.so"          #Not needed, since clambc-remove-undefs is not being used.
        , f"--load-pass-plugin {SHARED_OBJ_DIR}/libclambcpreserveabis.so"
        , f"--load-pass-plugin {SHARED_OBJ_DIR}/libclambcremoveunsupportedicmpintrinsics.so"
        , f"--load-pass-plugin {SHARED_OBJ_DIR}/libclambcremoveusub.so"
        , f"--load-pass-plugin {SHARED_OBJ_DIR}/libclambcremovefshl.so"
#        , f"--load-pass-plugin {SHARED_OBJ_DIR}/libclambcremovepointerphis.so"    #Not needed, since clambc-remove-pointer-phis is not being used.
        , f"--load-pass-plugin {SHARED_OBJ_DIR}/libclambcloweringnf.so"
        , f"--load-pass-plugin {SHARED_OBJ_DIR}/libclambcremoveicmpsle.so"
        , f"--load-pass-plugin {SHARED_OBJ_DIR}/libclambcverifier.so"
        , f"--load-pass-plugin {SHARED_OBJ_DIR}/libclambcremovefreezeinsts.so"
        , f"--load-pass-plugin {SHARED_OBJ_DIR}/libclambcloweringf.so"
        , f"--load-pass-plugin {SHARED_OBJ_DIR}/libclambclogicalcompilerhelper.so"
        , f"--load-pass-plugin {SHARED_OBJ_DIR}/libclambclogicalcompiler.so"
        , f"--load-pass-plugin {SHARED_OBJ_DIR}/libclambcrebuild.so"
        , f"--load-pass-plugin {SHARED_OBJ_DIR}/libclambctrace.so"
        , f"--load-pass-plugin {SHARED_OBJ_DIR}/libclambcoutlineendiannesscalls.so"
        , f"--load-pass-plugin {SHARED_OBJ_DIR}/libclambcchangemallocargsize.so"
        , f"--load-pass-plugin {SHARED_OBJ_DIR}/libclambcextendphisto64bit.so"
        , f"--load-pass-plugin {SHARED_OBJ_DIR}/libclambcconvertintrinsicsto32bit.so"
        , f"--load-pass-plugin {SHARED_OBJ_DIR}/libclambcpreparegepsforwriter.so"
        , f"--load-pass-plugin {SHARED_OBJ_DIR}/libclambcanalyzer.so"
        , f"--load-pass-plugin {SHARED_OBJ_DIR}/libclambcregalloc.so"
        , f"--load-pass-plugin {SHARED_OBJ_DIR}/libclambcwriter.so"
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
        die(f"libclambcc.so not found.  See instructions for building", 2)

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



