#!/bin/sh
HEADERS_DIR=clang/lib/Headers
make -C obj/tools/clang/lib/Headers
for i in examples/in/*.o0.c; do
    j=`basename $i`
    ./compile.sh -w $i -o examples/out/$j.cbc || echo $j
#-- -clambc-dumpir | obj/Release/bin/llvm-dis -o examples/out/$j.ll -f || echo $j
done
for i in examples/in/*.o1.c; do
    j=`basename $i`
    ./compile.sh -w $i -o examples/out/$j.cbc -O1 || echo $j
    #-- -clambc-dumpir | obj/Release/bin/llvm-dis -o examples/out/$j.ll -f || echo $j
done
