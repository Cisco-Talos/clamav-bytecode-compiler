LEVEL=../../../
DIRS := re2c
include $(LEVEL)/Makefile.config
GIT_VERSION := $(shell cd $(LLVM_SRC_ROOT); git describe --always)
CXXFLAGS = -fno-rtti -DHOST_OS=\"$(HOST_OS)\"
LIBRARYNAME:=clamdriver
BUILD_ARCHIVE := 1
LINK_COMPONENTS := system support
NO_INSTALL = 1
CPPFLAGS+=-I$(LLVM_SRC_ROOT)/tools/clang/include -I$(LLVM_OBJ_ROOT)/tools/clang/include
include $(LEVEL)/Makefile.common
