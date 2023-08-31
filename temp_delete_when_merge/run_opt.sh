#!/bin/bash


#might be useful
#https://stackoverflow.com/questions/67206238/how-to-define-and-read-cli-arguments-for-an-llvm-pass-with-the-new-pass-manager



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

#opt-16 -S --load-pass-plugin libclambcc/libclambcc.so --passes=my-module-pass test.ll -o test.t.ll
#opt-16 -S --load-pass-plugin libclambcc/libclambcc.so --passes=my-function-pass test.ll -o test.t.ll



#opt-16 -S --load-pass-plugin libclambcc/libclambcc.so --load-pass-plugin ./libclambcc/MyModulePass/libclambcc_mymodulepass.so --passes=my-module-pass test.ll -o test.t.ll



#opt-16 -S \
#    --load-pass-plugin libclambcc/libclambcc.so \
#    --load-pass-plugin libclambcc/MyModulePass/libclambcc_mymodulepass.so \
#    --passes="my-module-pass,my-function-pass" test.ll -o test.t.ll
#



#Function Passes and Module Passes can't be mixed.  If we are going to have to 
#mix them, we need a wrapper to wrap the function pass in a module pass.



#opt-16 -S \
#    --load-pass-plugin libclambcc/MyModulePass/libclambcc_mymodulepass.so \
#    --load-pass-plugin libclambcc/MyModulePass2/libclambcc_mymodulepass2.so \
#    --load-pass-plugin libclambcc/MyFunctionPass/libclambcc_myfunctionpass.so \
#    --passes="my-module-pass2,my-module-pass" test.ll -o test.t.ll
#
#
#opt-16 -S \
#    --load-pass-plugin libclambcc/MyModulePass/libclambcc_mymodulepass.so \
#    --load-pass-plugin libclambcc/MyModulePass2/libclambcc_mymodulepass2.so \
#    --load-pass-plugin libclambcc/MyFunctionPass/libclambcc_myfunctionpass.so \
#    --passes="my-function-pass" test.ll -o test.t.ll
#



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



