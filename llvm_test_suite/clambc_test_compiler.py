#!/usr/bin/python3

import sys, os

COMPILER = '/usr/bin/clang-16'
OPTIMIZER = '/usr/bin/opt-16'
LLCOMPILER = '/usr/bin/llc-16'



INSTALL_DIR='/home/aragusa/Clang-16-Upgrade/install/lib'

#Add loads here
LOADS = "--load %s/libclambccommon.so " % INSTALL_DIR
LOADS += "--load-pass-plugin %s/libclambcrebuild.so" % INSTALL_DIR

#Add passes here
PASSES = 'default<O3>'
PASSES += ',clambc-rebuild'


def getIRGenCommand(args, inFile, irFile):
    cmd = f"{COMPILER} %s " % (" ".join(args))
    cmd += " -S -fno-discard-value-names "
    cmd += " -fno-vectorize "
    cmd += "--language=c "
    cmd += "-emit-llvm "
    cmd += "-Werror=unused-command-line-argument "
    cmd += "-Xclang -disable-O0-optnone "
    cmd += " -I /home/aragusa/clamav-bytecode-compiler-upstream/build/install/bin/../include "
    cmd += "-include bytecode.h "
    cmd += "-D__CLAMBC__"" "
    cmd += inFile
    cmd += " -o "
    cmd += irFile

    cmd = f"{COMPILER} %s " % (" ".join(args))
    cmd += " -S -fno-discard-value-names "
    cmd += " -fno-vectorize "
    cmd += "--language=c "
    cmd += "-emit-llvm "
    cmd += "-Werror=unused-command-line-argument "
    cmd += "-Xclang -disable-O0-optnone "
    cmd += inFile
    cmd += " -o "
    cmd += irFile






    return cmd

def getTransformCommand(inFile, outFile):
    cmd = OPTIMIZER + " -S "
    cmd +=" --disable-loop-unrolling "
    cmd +=" --disable-i2p-p2i-opt "
    cmd +=" --disable-loop-unrolling "
    cmd +=" --disable-promote-alloca-to-lds "
    cmd +=" --disable-promote-alloca-to-vector "
    cmd +=" --disable-simplify-libcalls "
    cmd +=" --disable-tail-calls "
    cmd +=" --vectorize-slp=false "
    cmd +=" --vectorize-loops=false "

    cmd +=  LOADS

    cmd +=' -passes=\"%s\" ' % PASSES

    cmd += inFile
    cmd += " -o "
    cmd += outFile
    return cmd

def getLoweringCommand(transformed, outFile):
    cmd = f"{LLCOMPILER} --filetype=obj {transformed} -o {outFile}"
    return cmd


def runBuildCommands(args, inFile, outFile):

    irFile = os.path.basename(inFile[:-1])
    transformed = irFile + "t.ll"
    irFile += "ll"
    cmd = getIRGenCommand(args, inFile, irFile)
    print (cmd)

    ret = os.system(cmd)
    if ret:
        return ret

    cmd = getTransformCommand(irFile, transformed)
    print (cmd)
    ret = os.system(cmd)
    if ret:
        return ret

    cmd = getLoweringCommand(transformed, outFile)
    print (cmd)
    print (cmd)
    ret = os.system(cmd)
    if ret:
        return ret

    print ("Success")
    return 0

changeIt = False
outFile = ''
outArgs = []
inFile = ''

ret = 0

i = 1
while i < len(sys.argv):
    arg = sys.argv[i]
    if '-o' == arg:
        nextArg = sys.argv[i+1]
        if nextArg.endswith(".o"):
            changeIt = True
            outFile = nextArg
            i += 1
    elif '-c' == arg:
        i += 1
        inFile = sys.argv[i]
    else:
        outArgs.append(arg)
    i += 1



if (changeIt):
    ret = runBuildCommands(outArgs, inFile, outFile)

else:

    s = " ".join(sys.argv[1:])
    cmd = f'{COMPILER} {s}'
    ret = os.system(cmd)

    f = open("/home/aragusa/wtfisthis.txt", "a")
    f.write(cmd)
    f.write("\n")
    #f.write(f"clang exit status in python = '{ret}'\n")
    f.close()




if (256 == ret):
    ret = 1

sys.exit(ret)


