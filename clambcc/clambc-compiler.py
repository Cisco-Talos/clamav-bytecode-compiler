#!/usr/bin/env python3

import sys
import os
import shutil
import re
import subprocess

from optparse import OptionParser

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
"

TMPDIR=".__clambc_tmp"
CLANG_VERSION=8

INCDIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "include")
SHARED_OBJ_DIR = os.path.join( os.path.dirname( os.path.realpath(__file__) ) , "..", "lib")
SHARED_OBJ_FILE = os.path.join( SHARED_OBJ_DIR, "libclambcc.so")

VERBOSE=False

def run(cmd):
    if VERBOSE:
        print (cmd)
    return os.system(cmd)


def die(msg, exitStatus):
    print (msg, file=sys.stderr)
    sys.exit(exitStatus)


def dieNoInputFile():
    die("No input file", 1)

def getNameNewExtension(fName, newExtension):
    idx = fName.rfind(".")
    if -1 == idx:
        ret = "%s.%s" % (fName, newExtension)
    else:
        ret = "%s.%s" % (fName[0:idx], newExtension)

    return ret

def getOutfile(options, args):
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

def getIrFile(fileName, debugBuild):
    if debugBuild:
        outFile = getNameNewExtension(os.path.basename(fileName), "debug.ll")
    else:
        outFile = getNameNewExtension(os.path.basename(fileName), "ll")
    outFile = os.path.join(TMPDIR, outFile)
    return outFile

#The 'noBytecodeOptions' is to be used if we are building a "normal" executable (for unit tests).
def compileFile(fileName, debugBuild, standardCompiler, options):

    outFile = getIrFile(fileName, debugBuild)

    includePaths = ""
    if options.includes:
        for i in options.includes:
            includePaths += f"-I{i} "

    defines = ""
    if options.defines:
        for d in options.defines:
            defines += f"-D{d} "

    cmd = f"clang-{CLANG_VERSION} \
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


def compileFiles(args, debugBuild, standardCompiler, options):
    for a in args:
        exitStat = compileFile(a, debugBuild, standardCompiler, options)
        if exitStat:
            return exitStat

    return 0

def getLinkedFileName(outputFileName):
    idx = outputFileName.find(COMPILED_BYTECODE_FILE_EXTENSION)
    if -1 == idx:
        die("getLinkedFileName called with invalid input", 2)

    return ("%s%s" % (os.path.join(TMPDIR, outputFileName[0:idx]), LINKED_BYTECODE_FILE_EXTENSION))

def getOptimizedFileName(outputFileName):
    idx = outputFileName.find(COMPILED_BYTECODE_FILE_EXTENSION)
    if -1 == idx:
        die("getOptimizedFileName called with invalid input", 2)

    return ("%s%s" % (os.path.join(TMPDIR, outputFileName[0:idx]), OPTIMIZED_BYTECODE_FILE_EXTENSION))

def getInputSourceFileName(outputFileName):
    idx = outputFileName.find(COMPILED_BYTECODE_FILE_EXTENSION)
    if -1 == idx:
        die("getInputSourceFileName called with invalid input", 2)

    return ("%s%s" % (os.path.join(TMPDIR, outputFileName[0:idx]), OPEN_SOURCE_GENERATED_EXTENSION))

#Takes as input the linked bitcode file from llvm-link.
def getOptimizedTmpFileName(linkedFile):
    idx = linkedFile.find(LINKED_BYTECODE_FILE_EXTENSION)
    if -1 == idx:
        die("getLinkedFileName called with invalid input", 2)

    return ("%s%s" % (linkedFile[0:idx], OPTIMIZED_TMP_BYTECODE_FILE_EXTENSION ))

def linkIRFiles(linkedFile, irFiles):
    inFiles = " ".join(irFiles)
    cmd = f"llvm-link-{CLANG_VERSION} -S -o {linkedFile} {inFiles}"

    return run(cmd)


def linkFiles(linkedFile, args, debugBuild):

#    #Begin WORKAROUND
#    print ("TEMPORARILY REMOVING SUPPORT FOR LLVM-LINK.  Just want to see if the signatures work as expected.")
#    cmd = f"cp {getIrFile(args[0])} {linkedFile}"
#    run(cmd)
#    return
#    #End WORKAROUND


    lst = []
    for f in args:
        ir = getIrFile(f, debugBuild)
        lst.append(ir)

    return linkIRFiles(linkedFile, lst)



#####BEGIN


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
def parseIR(fileName):
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



def generateIgnoreList(optimized, linked):

    ignore = {}
    for key in optimized.files.keys():
        val = 0
        linkedKey = linked.getKeyFromFile(optimized.files[key])
        if not linkedKey:
            print ("HOW DID THIS HAPPEN?")
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


def getOutputString(linked, ignore):

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


def createOptimizedTmpFile(linkedFile):
    name = getOptimizedTmpFileName (linkedFile)

    cmd = f"opt-{CLANG_VERSION} \
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


def createInputSourceFile(name, args, options):
    res = compileFiles(args, True, False, options)

    idx = name.find( OPEN_SOURCE_GENERATED_EXTENSION )
    if -1 == idx:
        die("createInputSourceFile called with invalid input", 2)

    if not res:
        linkedFile = f"{name[0:idx]}debug.{LINKED_BYTECODE_FILE_EXTENSION}"
        res = linkFiles(linkedFile, args, True)

    if not res:
        optimizedTmpFile = createOptimizedTmpFile(linkedFile)
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


def optimize(inFile, outFile, sigFile, inputSourceFile, standardCompiler):

    internalizeAPIList = "_Z10entrypointv,entrypoint,__clambc_kind,__clambc_virusname_prefix,__clambc_virusnames,__clambc_filesize,__clambc_match_counts,__clambc_match_offsets,__clambc_pedata"
    if standardCompiler:
        internalizeAPIList += ",main"

    #TODO: Modify ClamBCRemoveUndefs to not require mem2reg to be run before it.
    cmd = f'opt-{CLANG_VERSION} \
            -S \
            -verify-each \
            -load "{SHARED_OBJ_FILE}" \
            {inFile} \
            -o {outFile} \
            -mem2reg \
            -clambc-remove-undefs \
            -O3 \
            -clambc-remove-pointer-phis \
            -dce \
            -disable-loop-vectorization \
            -disable-slp-vectorization \
            -globaldce \
            -strip-dead-prototypes \
            -constmerge \
            -mem2reg \
            -always-inline \
            -globalopt \
            -lowerswitch \
            -lowerinvoke  \
            -globalopt \
            -simplifycfg \
            -indvars \
            -constprop \
            -clambc-lowering-notfinal \
            -lowerswitch \
            -clambc-verifier \
            -clambc-lowering-notfinal \
            -dce \
            -simplifycfg \
            -mem2reg \
            -clambc-lcompiler \
            -internalize -internalize-public-api-list="{internalizeAPIList}" \
            -globaldce \
            -instcombine \
            -clambc-rebuild \
            -verify \
            -simplifycfg \
            -dce \
            -lowerswitch  \
            -clambc-verifier \
            -verify \
            -strip-debug-declare \
            -clambc-gepsplitter-placeholder \
            -clambc-lowering-final \
            -clambc-trace \
            -dce \
            -clambc-module \
            -verify \
            -globalopt \
            -remove-selects \
            -clambc-outline-endianness-calls \
            -clambc-change-malloc-arg-size \
            -globalopt \
            -clambc-prepare-geps-for-writer \
            -globalopt \
            -clambc-convert-intrinsics \
            -clambc-writer \
            -clambc-writer-input-source={inputSourceFile} \
            -clambc-sigfile={sigFile} \
            '

    if standardCompiler:
        cmd += f"-clambc-standard-compiler \
                "
    return run(cmd)


def genExe(optimizedFile, outputFile):
    cmd = f"clang-{CLANG_VERSION} {optimizedFile} -o {outputFile}"
    return run(cmd)





#This is definitely hacky, but I *think* it's the only change I need to make for
#this to work
def fixFileSize(optimizedFile) :
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



def verifyClangInstallation():
    exes = ["clang", "opt"]
    for exe in exes:
        try:
            exe = f"{exe}-{CLANG_VERSION}"
            subprocess.run([exe, "-v"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except FileNotFoundError:
            print (f"{exe} must be installed and in your path.", file=sys.stderr)
            return 1

    return 0



#The purpose of this class is to save off all the
#options we haven't added, and just assume that they are
#for the compiler, so that we don't have to support -Wall, -Werror, ...
class ClamBCCOptionParser (OptionParser):
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

    if verifyClangInstallation():
        sys.exit(-1)

    parser = ClamBCCOptionParser()
    parser.add_option("-o", "--outfile", dest="outfile", default=None)
    parser.add_option("--save-tempfiles", dest="save", action="store_true", default=False)
    parser.add_option("-v", "--verbose", dest="verbose", action="store_true", default=False)
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

    options.genexe = False
    options.standardCompiler = False

    options.passthroughOptions = " ".join(parser.getPassthrough())

    if not os.path.isfile(SHARED_OBJ_FILE ):
        die(f"{SHARED_OBJ_FILE} not found.  See instructions for building", 2)

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
    res = compileFiles(args, False, bCompiler, options)

    if not res:
        linkedFile = getLinkedFileName(outFile)
        res = linkFiles(linkedFile, args, False)

    if not res:
        inputSourceFile = getInputSourceFileName(outFile)
        if bCompiler:
            f = open(inputSourceFile, "w")
            f.close()
        else:
            res = createInputSourceFile(inputSourceFile, args, options)

    if not res:
        optimizedFile = getOptimizedFileName(outFile)
        outFile = getOutfile(options, args)
        res = optimize(linkedFile, optimizedFile, outFile, inputSourceFile, bCompiler)

    if not res:
        if options.genexe:

            #Add the 'main' and all the stuff that clam provides (TODO: make this configurable by the user)
            mainFile = os.path.join(os.path.dirname(__file__), 'clambc-compiler-main.c')
            res = compileFile(mainFile, False, False, options)
            if res:
                print ("Build FAILED")
                import pdb ; pdb.set_trace()

            if not res:
                mainIRFile = getIrFile(mainFile, False)

                fixFileSize(optimizedFile)
                fixFileSize(mainIRFile)

                res = linkIRFiles(optimizedFile, [optimizedFile, mainIRFile])

            bCompiler = True

    if not res:
        if bCompiler:
            res = genExe(optimizedFile, outFile)

    if ((not saveFiles) and createdDir):
        shutil.rmtree(TMPDIR)

    if res:
        sys.exit(1)


if '__main__' == __name__:

    main()



