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
#consider changing this to start at 8 and go up to 99.  That will cover us
#from having to update this when new versions come out.
CLANG_LLVM_KNOWN_VERSIONS = [8, 9, 10, 11, 12]

#This is the min clang/llvm version this has been tested with.
MIN_CLANG_LLVM_VERSION = 8
PREFERRED_CLANG_LLVM_VERSION = 8

CLANG_NAME = "clang"
LLVM_NAME = "opt"

CLANG_BINARY_ARG = "--clang-binary"
OPT_BINARY_ARG = "--opt-binary"

COMPILED_BYTECODE_FILE_EXTENSION = "cbc"
LINKED_BYTECODE_FILE_EXTENSION = "linked.ll"
OPTIMIZED_BYTECODE_FILE_EXTENSION = "optimized.ll"
OPEN_SOURCE_GENERATED_EXTENSION = "generated.c"
OPTIMIZED_TMP_BYTECODE_FILE_EXTENSION = "optimized.tmp.ll"


COMMON_WARNING_OPTIONS = "-Wno-backslash-newline-escape \
  -Wno-pointer-sign \
  -Wno-return-type \
  -Wno-incompatible-pointer-types \
  -Wno-unused-value \
  -Wno-shift-negative-value \
  -Wno-implicit-function-declaration \
  -Wno-incompatible-library-redeclaration \
  -Wno-implicit-int \
  -Wno-constant-conversion \
"

TMPDIR=".__clambc_tmp"

INCDIR = Path(__file__).parent / '..' / 'include'

# Check for libclambcc.so at a location relative to this script first.
FOUND_SHARED_OBJ = False

SHARED_OBJ_DIR = Path(__file__).parent / '..' / 'lib'
if (SHARED_OBJ_DIR / 'libclambcc.so').exists():
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


def run(cmd: str) -> int:
    if VERBOSE:
        print(cmd)
    return os.system(cmd)


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

    includePaths = ""
    if options.includes:
        for i in options.includes:
            includePaths += f"-I{i} "

    defines = ""
    if options.defines:
        for d in options.defines:
            defines += f"-D{d} "

    cmd = f"{clangLLVM.getClang()} \
            -S \
            -fno-discard-value-names \
            --language=c \
            -emit-llvm \
            -Werror=unused-command-line-argument \
            -Xclang \
            -disable-O0-optnone \
            -o {outFile} \
            {fileName} \
            "

    cmd += f" \
            {includePaths} \
            {defines} \
            "

    if debugBuild:
        cmd += " -g \
                "

    if (not standardCompiler):
        cmd += f" -I {INCDIR} \
                 -include bytecode.h \
                 -D__CLAMBC__ \
                 "

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
    inFiles = " ".join(irFiles)
    cmd = f"{clangLLVM.getLLVMLink()} -S -o {linkedFile} {inFiles}"

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

    cmd = f"{clangLLVM.getOpt()} \
            -S \
            {linkedFile} \
            -o {name} \
            -internalize -internalize-public-api-list=entrypoint \
            -globalopt \
            "

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


def optimize(clangLLVM: ClangLLVM, inFile: str, outFile: str, sigFile: str, inputSourceFile: str, standardCompiler: bool) -> int:

    internalizeAPIList = "_Z10entrypointv,entrypoint,__clambc_kind,__clambc_virusname_prefix,__clambc_virusnames,__clambc_filesize,__clambc_match_counts,__clambc_match_offsets,__clambc_pedata,__Copyright"
    if standardCompiler:
        internalizeAPIList += ",main"

    #TODO: Modify ClamBCRemoveUndefs to not require mem2reg to be run before it.
    cmd = (f'{clangLLVM.getOpt()} '
          f' -S'
          f' -verify-each'
          f' -load "{SHARED_OBJ_FILE}"'
          f' {inFile}'
          f' -o {outFile}'
          f' -mem2reg'
          f' -clambc-remove-undefs' #add pointer bounds checking.
          f' -clambc-preserve-abis' #add fake function calls that use all of
                                   #the arguments so that O3 doesn't change
                                   #the argument lists
          f' -O3'
          f' -clambc-preserve-abis' #remove fake function calls because O3 has already run
          f' -clambc-remove-pointer-phis'
          f' -dce'
          f' -disable-loop-vectorization'
          f' -disable-slp-vectorization'
          f' -globaldce'
          f' -strip-dead-prototypes'
          f' -constmerge'
          f' -mem2reg'
          f' -always-inline'
          f' -globalopt'
          f' -lowerswitch'
          f' -lowerinvoke'
          f' -globalopt'
          f' -simplifycfg'
          f' -indvars'
          f' -constprop'
          f' -clambc-lowering-notfinal' # perform lowering pass
          f' -lowerswitch'
          f' -clambc-verifier'
          f' -clambc-lowering-notfinal'  # perform lowering pass
          f' -dce'
          f' -simplifycfg'
          f' -mem2reg'
          f' -clambc-lcompiler' #compile the logical_trigger function to a
                               #logical signature.
          f' -internalize -internalize-public-api-list="{internalizeAPIList}"'
          f' -globaldce'
          f' -instcombine'
          f' -clambc-rebuild'
          f' -verify'
          f' -simplifycfg'
          f' -dce'
          f' -lowerswitch'
          f' -clambc-verifier'
          f' -verify'
          f' -strip-debug-declare'
          f' -clambc-gepsplitter-placeholder'
          f' -clambc-lowering-final'
          f' -clambc-trace'
          f' -dce'
          f' -clambc-module'
          f' -verify'
          f' -globalopt'
          f' -remove-selects'
          f' -clambc-outline-endianness-calls' #outline the endianness calls
                                              #because otherwise the call
                                              #is replaced with a constant
                                              #that is based on where the
                                              #signature was compiled, and
                                              #won't always be accurate.
          f' -clambc-change-malloc-arg-size'   #make sure we always use the
                                              #64-bit malloc.
          f' -globalopt'
          f' -clambc-extend-phis-to-64bit' #make all integer phi nodes 64-bit
                                          #because the llvm runtime inserts a
                                          #cast after phi nodes without
                                          #verifying that there is not
                                          #another phi node after it.
          f' -clambc-prepare-geps-for-writer' #format gep indexes to not not
                                             #have more than 2, because
                                             #otherwise the writer gets
                                             #unhappy.
          f' -globalopt'
          f' -clambc-convert-intrinsics'   #convert all memset intrinsics to
                                          #the 32-bit instead of the 64-bit
                                          #intrinsic
          f' -clambc-writer'               #write the bytecode
          f' -clambc-writer-input-source={inputSourceFile}'
          f' -clambc-sigfile={sigFile}'
          )

    if standardCompiler:
        cmd += f" -clambc-standard-compiler"

    return run(cmd)


def genExe(clangLLVM: ClangLLVM, optimizedFile: str, outputFile: str) -> int:
    cmd = f"{clangLLVM.getClang} {optimizedFile} -o {outputFile}"
    return run(cmd)


#This is definitely hacky, but I *think* it's the only change I need to make for
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

#    parser.add_option("--generate-exe", dest="genexe", action="store_true",
#            default=False, help="This is if you want to build a correctly formatted bytecode \
#                    signature as an executable for debugging (NOT IMPLEMENTED)")
    parser.add_option("-I", action="append", dest="includes", default=None)
    parser.add_option("-D", action="append", dest="defines", default=None)
    parser.add_option("--disable-common-warnings", dest="disableCommonWarnings",
            action="store_true", default=False,
            help=f"{COMMON_WARNING_OPTIONS} (Found in some bytecode signatures).")
#    parser.add_option("--standard-compiler", dest="standardCompiler", action="store_true", default=False,
#            help="This is if you want to build a normal c program as an executable to test the compiler.")
    (options, args) = parser.parse_args()

    if options.version:
        #TODO: determine the version by calling into libclambcc.so
        print('ClamBC-Compiler 0.103.1')
        sys.exit(0)


    clangLLVM = findClangLLVM(options)
    if None == clangLLVM:
        sys.exit(1)

    options.genexe = False
    options.standardCompiler = False

    options.passthroughOptions = " ".join(parser.getPassthrough())

    if not FOUND_SHARED_OBJ:
        die(f"libclambcc.so not found.  See instructions for building", 2)

    if 0 == len(args):
        dieNoInputFile()

    global VERBOSE
    VERBOSE = options.verbose

    outFile = getOutfile(options, args)
    outFile = os.path.basename(outFile)
    saveFiles = options.save
    bCompiler = options.standardCompiler
    buildExecutable = bCompiler or options.genexe

    createdDir = False

    #Add the compiled bytecode file extension, so that all the get<Blahblahblah>Name functions can find it
    if bCompiler:
        idx = outFile.find(COMPILED_BYTECODE_FILE_EXTENSION)
        if -1 == idx:
            outFile += f".{COMPILED_BYTECODE_FILE_EXTENSION}"

    if not os.path.isdir(TMPDIR):
        os.makedirs(TMPDIR)
        createdDir = True

#    if options.genexe:
#        inFile = os.path.join(os.path.dirname(__file__), 'clambc-compiler-main.c')
#        args.append(inFile)
#
    res = compileFiles(clangLLVM, args, False, bCompiler, options)

    if not res:
        linkedFile = getLinkedFileName(outFile)
        res = linkFiles(clangLLVM, linkedFile, args, False)

    if not res:
        inputSourceFile = getInputSourceFileName(outFile)
        if bCompiler:
            f = open(inputSourceFile, "w")
            f.close()
        else:
            res = createInputSourceFile(clangLLVM, inputSourceFile, args, options)

    if not res:
        optimizedFile = getOptimizedFileName(outFile)
        outFile = getOutfile(options, args)
        res = optimize(clangLLVM, linkedFile, optimizedFile, outFile, inputSourceFile, bCompiler)

    if not res:
        if options.genexe:

            #Add the 'main' and all the stuff that clam provides (TODO: make this configurable by the user)
            mainFile = os.path.join(os.path.dirname(__file__), 'clambc-compiler-main.c')
            res = compileFile(clangLLVM, mainFile, False, False, options)
            if res:
                print("Build FAILED")
                import pdb ; pdb.set_trace()

            if not res:
                mainIRFile = getIrFile(mainFile, False)

                fixFileSize(optimizedFile)
                fixFileSize(mainIRFile)

                res = linkIRFiles(clangLLVM, optimizedFile, [optimizedFile, mainIRFile])

            bCompiler = True

    if not res:
        if bCompiler:
            res = genExe(clangLLVM, optimizedFile, outFile)

    if ((not saveFiles) and createdDir):
        shutil.rmtree(TMPDIR)

    if res:
        if os.path.exists(outFile):
            os.remove(outFile)
        sys.exit(1)


if '__main__' == __name__:

    main()
