#!/bin/bash -e
CLAMAV_PATH=../../clamav-devel/
CLAMAV_TEST=$CLAMAV_PATH/unit_tests/input/
HEADERS_DIR=clang/lib/Headers

# Sync libclamav -> compiler
cp -v $CLAMAV_PATH/libclamav/bcfeatures.h clang/lib/Headers/bcfeatures.h
cp -v $CLAMAV_PATH/libclamav/execs.h clang/lib/Headers/bytecode_execs.h.tmp
cp -v $CLAMAV_PATH/libclamav/pe.h clang/lib/Headers/bytecode_pe.h.tmp
cp -v $CLAMAV_PATH/libclamav/disasm-common.h clang/lib/Headers/bytecode_disasm.h.tmp
sed -i 's/#include "cltypes.h"//' clang/lib/Headers/bytecode_execs.h.tmp
sed -i 's/#include "hashtab.h"//' clang/lib/Headers/bytecode_execs.h.tmp
sed -i '/^#include .*/d' clang/lib/Headers/bytecode_pe.h.tmp
sed -i '/^.*int.* cli_.*/d' clang/lib/Headers/bytecode_pe.h.tmp
sed -i 's/#include <sys\/types.h>//' clang/lib/Headers/bytecode_execs.h.tmp
for i in clang/lib/Headers/bytecode_{pe,execs,disasm}.h.tmp; do
    sed -r -i '/^[/ ][*][ /]/d' $i
    sed -r -i '/^[/ ][*]$/d' $i
done

cat >header.tmp <<EOH
/*
 *  Copyright (C) 2009 Sourcefire, Inc.
 *  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
EOH
for i in clang/lib/Headers/bytecode_{pe,execs,disasm}.h; do
    cp header.tmp $i;
    cat $i.tmp >>$i;
    rm $i.tmp
done
rm header.tmp

make -C obj/tools/clang/lib/Headers

echo "Generating bytecode_api_decl.c.h, bytecode_api_impl.h and bytecode_hooks.h"
obj/Release/bin/ifacegen $HEADERS_DIR/bytecode_api.h \
-gen-api-c $HEADERS_DIR/bytecode_api_decl.c.h -gen-hooks-h bytecode_hooks.h -gen-impl-h bytecode_api_impl.h ||
{ echo "Failed to compile API header"; exit 1; }

make -C obj/tools/clang/lib/Headers

# Sync compiler -> libclamav
cp -v clang/lib/Headers/bytecode_api_decl.c.h $CLAMAV_PATH/libclamav/bytecode_api_decl.c
cp -v clang/lib/Headers/bytecode_api.h $CLAMAV_PATH/libclamav/bytecode_api.h
sed -ri 's/enum \{(.+)\};/static const unsigned \1;/g' $CLAMAV_PATH/libclamav/bytecode_api.h
cp -v bytecode_api_impl.h $CLAMAV_PATH/libclamav/bytecode_api_impl.h
cp -v bytecode_hooks.h $CLAMAV_PATH/libclamav/bytecode_hooks.h
cp -v ClamBC/clambc.h $CLAMAV_PATH/libclamav/clambc.h
sed -nri '1h;1!H;${;g;s/enum BytecodeKind.+\};//;p;}' $CLAMAV_PATH/libclamav/clambc.h

cp -v examples/out/apicalls2.o1.c.cbc $CLAMAV_TEST/apicalls2_7.cbc
cp -v examples/out/apicalls.o1.c.cbc $CLAMAV_TEST/apicalls_7.cbc
cp -v examples/out/arithmetic.o1.c.cbc $CLAMAV_TEST/arith_7.cbc
cp -v examples/out/retmagic.o1.c.cbc $CLAMAV_TEST/retmagic_7.cbc
cp -v examples/out/lsig.o1.c.cbc $CLAMAV_TEST/lsig_7.cbc
cp -v examples/out/inf.o1.c.cbc $CLAMAV_TEST/inf_7.cbc
cp -v examples/out/api_files.o1.c.cbc $CLAMAV_TEST/api_files_7.cbc
cp -v examples/out/api_extract.o1.c.cbc $CLAMAV_TEST/api_extract_7.cbc
cp -v examples/out/debug.o1.c.cbc $CLAMAV_TEST/debug_7.cbc
cp -v examples/out/testadt.o1.c.cbc $CLAMAV_TEST/testadt_7.cbc

./compile.sh -x c /dev/null -E -dD | grep ^\#define >docs/internals/predefines
./compile.sh -x c /dev/null -E -dD | grep ^typedef >docs/internals/typedefs
cp docs/internals/predefines docs/user/predefines
