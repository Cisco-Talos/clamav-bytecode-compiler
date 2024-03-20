#!/bin/bash


SOURCE_FILE=analysis_test.c

echo "#include <stdio.h> " >> $SOURCE_FILE
echo " " >> $SOURCE_FILE
echo "int func2(int i){ " >> $SOURCE_FILE
echo "    return i/2; " >> $SOURCE_FILE
echo "} " >> $SOURCE_FILE
echo " " >> $SOURCE_FILE
echo "int func(int idx){ " >> $SOURCE_FILE
echo "    int tmp; " >> $SOURCE_FILE
echo " " >> $SOURCE_FILE
echo "    if (idx > 1){ " >> $SOURCE_FILE
echo "        tmp = func2(11); " >> $SOURCE_FILE
echo "    } else { " >> $SOURCE_FILE
echo "        tmp = func(idx-1); " >> $SOURCE_FILE
echo "    } " >> $SOURCE_FILE
echo " " >> $SOURCE_FILE
echo "    if (0 == tmp){ " >> $SOURCE_FILE
echo "        return 0; " >> $SOURCE_FILE
echo "    } " >> $SOURCE_FILE
echo "    return idx-1; " >> $SOURCE_FILE
echo "} " >> $SOURCE_FILE
echo " " >> $SOURCE_FILE
echo "int main(int argc, char ** argv){ " >> $SOURCE_FILE
echo " " >> $SOURCE_FILE
echo "    if (argc){ " >> $SOURCE_FILE
echo "        func(argc); " >> $SOURCE_FILE
echo "    } " >> $SOURCE_FILE
echo " " >> $SOURCE_FILE
echo " " >> $SOURCE_FILE
echo "    return 0; " >> $SOURCE_FILE
echo "} " >> $SOURCE_FILE
echo " " >> $SOURCE_FILE


clang-16    \
	-S    \
	-fno-discard-value-names    \
	--language=c    \
	-emit-llvm    \
	-Werror=unused-command-line-argument    \
	-Xclang    \
	-disable-O0-optnone    \
    $SOURCE_FILE
