##===- tools/Makefile --------------------------------------*- Makefile -*-===##
#
#                     The LLVM Compiler Infrastructure
#
# This file is distributed under the University of Illinois Open Source
# License. See LICENSE.TXT for details.
#
##===----------------------------------------------------------------------===##

LEVEL := ..

# Build clang if present.
OPTIONAL_PARALLEL_DIRS := clang

# NOTE: The tools are organized into five groups of four consisting of one
# large and three small executables. This is done to minimize memory load
# in parallel builds.  Please retain this ordering.
DIRS := llvm-config
PARALLEL_DIRS := opt llvm-as llvm-dis \
                 llc llvm-ranlib llvm-ar llvm-nm \
                 llvm-ld llvm-prof llvm-link \
                 lli llvm-extract \
                 bugpoint llvm-bcanalyzer llvm-stub \
                 llvm-mc llvmc
                 

# Let users override the set of tools to build from the command line.
ifdef ONLY_TOOLS
  OPTIONAL_PARALLEL_DIRS :=
  PARALLEL_DIRS := $(ONLY_TOOLS)
endif

include $(LEVEL)/Makefile.config

# These libraries build as dynamic libraries (.dylib /.so), they can only be
# built if ENABLE_PIC is set.
ifeq ($(ENABLE_PIC),1)
  # No support for dynamic libraries on windows targets.
  ifneq ($(TARGET_OS), $(filter $(TARGET_OS), Cygwin MingW))
    PARALLEL_DIRS += edis
    
    # gold only builds if binutils is around.  It requires "lto" to build before
    # it so it is added to DIRS.
    ifdef BINUTILS_INCDIR
      PARALLEL_DIRS += gold
      DIRS += lto
    else
      PARALLEL_DIRS += lto
    endif
  endif
endif

# Only build edis if X86 target support is enabled.
ifeq ($(filter $(TARGETS_TO_BUILD), X86),)
  PARALLEL_DIRS := $(filter-out edis, $(PARALLEL_DIRS))
endif

include $(LEVEL)/Makefile.common
