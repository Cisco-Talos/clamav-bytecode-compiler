#!/bin/sh
HEADERS_DIR=clang/lib/Headers
make -C obj/tools/clang/lib/Headers
for i in examples/in/*.o0.c; do
    j=`basename $i`
    rm examples/out/$j.cbc
    ./compile.sh -w $i -o examples/out/$j.cbc || echo "-O0 $j" >&2
    ./compile.sh -w $i -O1 -o /dev/null || echo "-O1 $j" >&2
    ./compile.sh -w $i -O2 -o /dev/null || echo "-O2 $j" >&2
#-- -clambc-dumpir | obj/Release/bin/llvm-dis -o examples/out/$j.ll -f || echo $j
done
for i in examples/in/*.o1.c; do
    j=`basename $i`
    rm examples/out/$j.cbc
    ./compile.sh -w $i -o examples/out/$j.cbc -O1 || echo "-O1 $j" >&2
    ./compile.sh -w $i -o /dev/null || echo "-O0 $j" >&2
    ./compile.sh -w $i -O2 -o /dev/null || echo "-O2 $j" >&2
    #-- -clambc-dumpir | obj/Release/bin/llvm-dis -o examples/out/$j.ll -f || echo $j
done
for i in examples/in/*.c; do
    j=`basename $i`
    rm examples/out/$j.cbc
    ./compile.sh -w $i -o examples/out/$j.cbc -O2 || echo "-O2 $j" >&2
#    ./compile.sh -w $i -O1 -o /dev/null || echo "-O1 $j" >&2
#    ./compile.sh -w $i -o /dev/null || echo "-O0 $j" >&2
    #-- -clambc-dumpir | obj/Release/bin/llvm-dis -o examples/out/$j.ll -f || echo $j
done
