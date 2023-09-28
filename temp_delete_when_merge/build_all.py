#!/usr/bin/python3

import os

os.system("rm -f *.ll")

SIG_DIR='sigs'

COMPILE_CMD = """clang-16    \
	-S    \
	-fno-discard-value-names    \
	-fno-vectorize    \
	--language=c    \
	-emit-llvm    \
	-Werror=unused-command-line-argument    \
	-Xclang    \
	-disable-O0-optnone    \
	%s    \
	-o    \
	%s    \
	-I    \
	/home/aragusa/clamav-bytecode-compiler-upstream/build/install/bin/../include    \
	-include    \
	bytecode.h    \
	-D__CLAMBC__"""

OPTIONS_STR='--disable-loop-unrolling'
OPTIONS_STR+=" --disable-i2p-p2i-opt"
OPTIONS_STR+=" --disable-loop-unrolling"
OPTIONS_STR+=" --disable-promote-alloca-to-lds"
OPTIONS_STR+=" --disable-promote-alloca-to-vector"
OPTIONS_STR+=" --disable-simplify-libcalls"
OPTIONS_STR+=" --disable-tail-calls"
#OPTIONS_STR+=" --polly-vectorizer=none"
#OPTIONS_STR+=" --loop-vectorize"
OPTIONS_STR+=" --vectorize-slp=false"
OPTIONS_STR+=" --vectorize-loops=false"
#OPTIONS_STR+=" --disable-loop-vectorization"




PASS_STR = "function(mem2reg)"
PASS_STR+=','
PASS_STR+='clambc-remove-undefs'
PASS_STR+=','
PASS_STR+='clambc-preserve-abis'
PASS_STR+=',default<O3>'
#PASS_STR+=',default<O0>'
PASS_STR+=',clambc-preserve-abis' #remove fake function calls because O3 has already run
PASS_STR+=',function(clambc-remove-pointer-phis)'
PASS_STR+=',clambc-lowering-notfinal' # perform lowering pass
PASS_STR+=',lowerswitch'

PASS_STR+=',function(clambc-verifier)'
PASS_STR+=',clambc-remove-freeze-insts'



#print ("TODO: Put verifier back")

#PASS_STR+=',clambc-lowering-notfinal'  # perform lowering pass
#PASS_STR+=',clambc-lcompiler' #compile the logical_trigger function to a

INSTALL_DIR=os.path.join(os.getcwd(), "..")
LOAD_STR = "--load %s/install/lib/libclambccommon.so " % INSTALL_DIR
LOAD_STR += "--load-pass-plugin %s/install/lib/libclambcremoveundefs.so  " % INSTALL_DIR
LOAD_STR += "--load-pass-plugin %s/install/lib/libclambcpreserveabis.so  " % INSTALL_DIR
LOAD_STR += "--load-pass-plugin %s/install/lib/libclambcanalyzer.so  " % INSTALL_DIR
LOAD_STR += "--load-pass-plugin %s/install/lib/libclambcremovepointerphis.so  " % INSTALL_DIR
LOAD_STR += "--load-pass-plugin %s/install/lib/libclambcloweringf.so  " % INSTALL_DIR
LOAD_STR += "--load-pass-plugin %s/install/lib/libclambcloweringnf.so  " % INSTALL_DIR
LOAD_STR += "--load-pass-plugin %s/install/lib/libclambcverifier.so  " % INSTALL_DIR
LOAD_STR += "--load-pass-plugin %s/install/lib/libclambclogicalcompiler.so  " % INSTALL_DIR
LOAD_STR += "--load-pass-plugin %s/install/lib/libclambcremovefreezeinsts.so  " % INSTALL_DIR
#LOAD_STR += "--load-pass-plugin %s/install/lib/libclambcrebuild.so" % INSTALL_DIR

#OPT_CMD = 'opt-16 -S %s --passes=\"-mem2reg\" --passes=\"%s\" %s ' % (LOAD_STR, PASS_STR, OPTIONS_STR)
OPT_CMD = 'opt-16 -S %s --passes=\"%s\" %s ' % (LOAD_STR, PASS_STR, OPTIONS_STR)


"""
#This is to find undefs.
print ("Take this part out, used to find undefs")
#PASS_STR = 'default<O3>'
OPTIONS_STR = ''
OPTIONS_STR+=" --vectorize-slp=false"
OPTIONS_STR+=" --vectorize-loops=false"
OPT_CMD = 'opt-16 -S %s --passes=\"%s\" %s ' % (LOAD_STR, PASS_STR, OPTIONS_STR)
"""



OPT_CMD += "%s -o %s"






def run(cmd):
    return os.system(cmd)


def compileFile(d, name):
    llFile = name[:-1] + "ll"

    cmd = COMPILE_CMD % (os.path.join(d,name), llFile)
    if (run(cmd)):
        return

    cmd = OPT_CMD % (llFile, llFile + ".optimized.ll")
    print (cmd)

    return run(cmd)


if '__main__' == __name__:
    for s in os.listdir(SIG_DIR):
        if (compileFile(SIG_DIR, s)):
            print (f"Failed on {s}")
            break
#        os.system("rm -f *.ll")




