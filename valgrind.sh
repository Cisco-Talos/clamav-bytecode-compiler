#!/bin/sh
valgrind obj/Debug+Checks/bin/clang-cc -ffreestanding -nostdinc -triple clambc-generic-generic -g -S -include bytecode.h -clam-apimap clang/lib/Headers/bytecode_api_decl.c.h $@
