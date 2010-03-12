#!/bin/sh
git remote update llvm-upstream
git remote update clang-upstream
cd ..
bytecode/taggy.sh

