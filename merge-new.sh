#!/bin/sh
git remote update llvm-upstream
git remote update clang-upstream
git merge -s subtree llvm-upstream/release
git merge -s subtree clang-upstream/release

