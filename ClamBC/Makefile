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
.PHONY: version.h
all:: version.h
$(SOURCES): version.h
version.h:
		$(Echo) "Updating version.h"
		$(Verb) echo -n "#define GIT_VERSION \"" >version.h.tmp
		$(Verb) echo -n $(GIT_VERSION) >>version.h.tmp
		$(Verb) echo "\"" >>version.h.tmp
		$(Verb) mv version.h.tmp $@
