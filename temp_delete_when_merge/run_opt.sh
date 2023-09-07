#!/bin/bash


#might be useful
#https://stackoverflow.com/questions/67206238/how-to-define-and-read-cli-arguments-for-an-llvm-pass-with-the-new-pass-manager

OPTIONS_STR='--disable-loop-unrolling'
OPTIONS_STR="$OPTIONS_STR --disable-i2p-p2i-opt"
OPTIONS_STR="$OPTIONS_STR --disable-loop-unrolling"
OPTIONS_STR="$OPTIONS_STR --disable-promote-alloca-to-lds"
OPTIONS_STR="$OPTIONS_STR --disable-promote-alloca-to-vector"
OPTIONS_STR="$OPTIONS_STR --disable-simplify-libcalls"
OPTIONS_STR="$OPTIONS_STR --disable-tail-calls"









PASS_STR='clambc-remove-undefs'
PASS_STR=$PASS_STR,'clambc-preserve-abis'
PASS_STR=$PASS_STR,'default<O3>'
PASS_STR=$PASS_STR,'clambc-preserve-abis' #remove fake function calls because O3 has already run
PASS_STR=$PASS_STR,'function(clambc-remove-pointer-phis)'
#PASS_STR=$PASS_STR,'dce'
#PASS_STR=$PASS_STR,'globaldce'
#PASS_STR=$PASS_STR,'strip-dead-prototypes'
#PASS_STR=$PASS_STR,'constmerge'
#PASS_STR=$PASS_STR,'mem2reg'
#PASS_STR=$PASS_STR,'always-inline'
#PASS_STR=$PASS_STR,'globalopt'
#PASS_STR=$PASS_STR,'lowerswitch'
#PASS_STR=$PASS_STR,'lowerinvoke'
#PASS_STR=$PASS_STR,'globalopt'
#PASS_STR=$PASS_STR,'simplifycfg'
#PASS_STR=$PASS_STR,'indvars'
#PASS_STR=$PASS_STR,'constprop' #figure this out later
PASS_STR=$PASS_STR,'clambc-lowering-notfinal' # perform lowering pass
PASS_STR=$PASS_STR,'lowerswitch'
PASS_STR=$PASS_STR,'function(clambc-verifier)'
PASS_STR=$PASS_STR,'clambc-lowering-notfinal'  # perform lowering pass
#PASS_STR=$PASS_STR,'dce'
#PASS_STR=$PASS_STR,'simplifycfg'
#PASS_STR=$PASS_STR,'mem2reg'
#PASS_STR=$PASS_STR,'clambc-lcompiler' #compile the logical_trigger function to a
#                               #logical signature.
#PASS_STR=$PASS_STR,'internalize -internalize-public-api-list="{internalizeAPIList}"'
#PASS_STR=$PASS_STR,'globaldce'
#PASS_STR=$PASS_STR,'instcombine'
#PASS_STR=$PASS_STR,'clambc-rebuild'
#PASS_STR=$PASS_STR,'verify'
#PASS_STR=$PASS_STR,'simplifycfg'
#PASS_STR=$PASS_STR,'dce'
#PASS_STR=$PASS_STR,'lowerswitch'
#PASS_STR=$PASS_STR,'clambc-verifier'
#PASS_STR=$PASS_STR,'verify'
#PASS_STR=$PASS_STR,'strip-debug-declare'
#PASS_STR=$PASS_STR,'clambc-lowering-final'
#PASS_STR=$PASS_STR,'clambc-trace'
#PASS_STR=$PASS_STR,'dce'
#PASS_STR=$PASS_STR,'clambc-module'
#PASS_STR=$PASS_STR,'verify'
#PASS_STR=$PASS_STR,'globalopt'
#PASS_STR=$PASS_STR,'remove-selects'
#PASS_STR=$PASS_STR,'clambc-outline-endianness-calls' #outline the endianness calls
#                                              #because otherwise the call
#                                              #is replaced with a constant
#                                              #that is based on where the
#                                              #signature was compiled, and
#                                              #won't always be accurate.
#PASS_STR=$PASS_STR,'clambc-change-malloc-arg-size'   #make sure we always use the
#                                              #64-bit malloc.
#PASS_STR=$PASS_STR,'globalopt'
#PASS_STR=$PASS_STR,'clambc-extend-phis-to-64bit' #make all integer phi nodes 64-bit
#                                          #because the llvm runtime inserts a
#                                          #cast after phi nodes without
#                                          #verifying that there is not
#                                          #another phi node after it.
#PASS_STR=$PASS_STR,'clambc-prepare-geps-for-writer' #format gep indexes to not not
#                                             #have more than 2, because
#                                             #otherwise the writer gets
#                                             #unhappy.
#PASS_STR=$PASS_STR,'globalopt'
#PASS_STR=$PASS_STR,'clambc-convert-intrinsics'   #convert all memset intrinsics to
#                                          #the 32-bit instead of the 64-bit
#                                          #intrinsic
#PASS_STR=$PASS_STR,'clambc-writer'               #write the bytecode
#PASS_STR=$PASS_STR,'clambc-writer-input-source={inputSourceFile}'
#PASS_STR=$PASS_STR,'clambc-sigfile={sigFile}'
#


#clang-16 -S \
#    -fno-discard-value-names \
#    --language=c \
#    -emit-llvm \
#    -Werror=unused-command-line-argument \
#    -Xclang \
#    -disable-O0-optnone \
#    -o test.ll \
#    ../../testing/BC.Img.Exploit.CVE_2017_3124-6335443-1.c \
#    -I ../../../build/install/bin/../include \
#    -include bytecode.h \
##    -D__CLAMBC__                  


clang-16 -S -fno-discard-value-names -emit-llvm -O0 -Xclang -disable-O0-optnone ../temp_delete_when_merge/testing/test.c



#opt-16 -S --load-pass-plugin libclambcc/libclambcc.so --passes="my-module-pass,my-function-pass" test.ll -o test.t.ll





INSTALL_DIR="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

clang-16 -S -fno-discard-value-names -emit-llvm -O0 -Xclang -disable-O0-optnone $INSTALL_DIR/testing/test.c

#opt-16 -S \
#    --load $INSTALL_DIR/install/lib/libclambccommon.so \
#    --load-pass-plugin $INSTALL_DIR/install/lib/libclambcremoveundefs.so \
#    --load-pass-plugin $INSTALL_DIR/install/lib/libclambcpreserveabis.so \
#    --load-pass-plugin $INSTALL_DIR/install/lib/libclambcanalyzer.so \
#    --load-pass-plugin $INSTALL_DIR/install/lib/libclambcremovepointerphis.so \
#    --load-pass-plugin $INSTALL_DIR/install/lib/libclambcloweringf.so \
#    --load-pass-plugin $INSTALL_DIR/install/lib/libclambcloweringnf.so \
#    --load-pass-plugin $INSTALL_DIR/install/lib/libclambcverifier.so \
#    --passes="-mem2reg"\
#    --passes="clambc-remove-undefs,clambc-preserve-abis,default<O3>,clambc-preserve-abis,function(clambc-remove-pointer-phis),dce,clambc-lowering-notfinal,clambc-lowering-final,function(clambc-verifier)" \
#    test.ll -o test.t.ll




#opt-16 -S \
#    --load $INSTALL_DIR/install/lib/libclambccommon.so \
#    --load-pass-plugin $INSTALL_DIR/install/lib/libclambcremoveundefs.so \
#    --load-pass-plugin $INSTALL_DIR/install/lib/libclambcpreserveabis.so \
#    --load-pass-plugin $INSTALL_DIR/install/lib/libclambcanalyzer.so \
#    --load-pass-plugin $INSTALL_DIR/install/lib/libclambcremovepointerphis.so \
#    --load-pass-plugin $INSTALL_DIR/install/lib/libclambcverifier.so \
#    --passes="-mem2reg"\
#    --passes="clambc-remove-undefs,clambc-preserve-abis,default<O3>,clambc-preserve-abis,function(clambc-remove-pointer-phis),dce,function(clambc-verifier)" \
#    test.ll -o test.t.ll
#



opt-16 -S \
    --load $INSTALL_DIR/install/lib/libclambccommon.so \
    --load-pass-plugin $INSTALL_DIR/install/lib/libclambcremoveundefs.so \
    --load-pass-plugin $INSTALL_DIR/install/lib/libclambcpreserveabis.so \
    --load-pass-plugin $INSTALL_DIR/install/lib/libclambcanalyzer.so \
    --load-pass-plugin $INSTALL_DIR/install/lib/libclambcremovepointerphis.so \
    --load-pass-plugin $INSTALL_DIR/install/lib/libclambcloweringf.so \
    --load-pass-plugin $INSTALL_DIR/install/lib/libclambcloweringnf.so \
    --load-pass-plugin $INSTALL_DIR/install/lib/libclambcverifier.so \
    --passes="-mem2reg"\
    --passes="$PASS_STR" \
    $OPTIONS_STR \
    test.ll -o test.t.ll



#There are warnings about not being able to load libclambccommon.so, but I 
#can add print statements to functions in that library and have them print, so ???
#opt-16 -S \
#    --load libclambcc/Common/libclambccommon.so \
#    --load-pass-plugin libclambcc/ClamBCRemoveUndefs/libclambcremoveundefs.so \
#    --load-pass-plugin libclambcc/ClamBCPreserveABIs/libclambcpreserveabis.so \
#    --load-pass-plugin libclambcc/ClamBCAnalyzer/libclambcanalyzer.so \
#    --load-pass-plugin libclambcc/ClamBCRemovePointerPHIs/libclambcremovepointerphis.so \
#    --passes="-mem2reg"\
#    --passes="clambc-remove-undefs,clambc-preserve-abis,default<O3>,clambc-preserve-abis" \
#    test.ll -o test.t.ll

opt-16 -S \
    --load libclambcc/Common/libclambccommon.so \
    --load-pass-plugin libclambcc/ClamBCRemoveUndefs/libclambcremoveundefs.so \
    --load-pass-plugin libclambcc/ClamBCPreserveABIs/libclambcpreserveabis.so \
    --load-pass-plugin libclambcc/ClamBCAnalyzer/libclambcanalyzer.so \
    --load-pass-plugin libclambcc/ClamBCRemovePointerPHIs/libclambcremovepointerphis.so \
    --passes="-mem2reg"\
    --passes="clambc-remove-undefs,clambc-preserve-abis,default<O3>,clambc-preserve-abis,function(clambc-remove-pointer-phis)" \
    test.ll -o test.t.ll



