##===- lib/Target/CBackend/Makefile ------------------------*- Makefile -*-===##
#
#                     The LLVM Compiler Infrastructure
#
# This file is distributed under the University of Illinois Open Source
# License. See LICENSE.TXT for details.
#
##===----------------------------------------------------------------------===##

LEVEL = ../../..
LIBRARYNAME = LLVMClamBC
DIRS = TargetInfo
CPPFLAGS += -DCLAMBC_COMPILER
include $(LEVEL)/Makefile.common
#GIT_VERSION := $(shell cd $(LLVM_SRC_ROOT); git describe --always)
GIT_VERSION = clambc-0.98.5beta
.PHONY: $(ObjDir)/version.o
$(ObjDir)/version.o: version.c
	$(Echo) "Compiling $(<F) for $(BuildMode) build" $(PIC_FLAG)
	$(Verb) $(Compile.C) -DGIT_VERSION=\"$(GIT_VERSION)\" $< -o $@
