#!/bin/sh
rm _bugpoint.bc
obj/Release+Checks/bin/clambc-compiler -emit-llvm-bc -o _bugpoint.bc $@
echo "exit 145" >_bugpoint.ref
obj/Release+Checks/bin/bugpoint _bugpoint.bc -run-custom -safe-run-custom -append-exit-code -exec-command=./clamexec.sh -output=_bugpoint.ref
