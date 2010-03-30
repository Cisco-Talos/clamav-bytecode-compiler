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
CXXFLAGS=-DCLAMBC_COMPILER
include $(LEVEL)/Makefile.common
GIT_VERSION := $(shell cd $(LLVM_SRC_ROOT); git describe --always)
.PHONY: version.h.tmp
all:: version.h
$(SOURCES): version.h
version.c: version.h
version.h: version.h.tmp
		$(Verb) cp version.h.tmp $@

version.h.tmp:
		$(Echo) "Updating version.h"
		$(Verb) rm -f $@;
		$(Verb) echo -n "#define GIT_VERSION \"" >version.h.tmp
		$(Verb) echo -n $(GIT_VERSION) >>version.h.tmp
		$(Verb) echo "\"" >>version.h.tmp
