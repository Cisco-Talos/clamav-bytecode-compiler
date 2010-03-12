LEVEL=../../../../
LIBRARYNAME := re2c
BUILD_ARCHIVE := 1
NO_INSTALL = 1
CPPFLAGS += -DHAVE_CONFIG_H
SOURCES := actions.cc code.cc dfa.cc main.cc mbo_getopt.cc substr.cc translate.cc parser.cc scanner.cc
all:: config.h
include $(LEVEL)/Makefile.common
config.h: configure config.h.in
	$<
$(SOURCES): config.h
