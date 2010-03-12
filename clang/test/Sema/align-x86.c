// RUN: %clang_cc1 -triple i386-apple-darwin9 -fsyntax-only -verify %s

// PR3433
double g1;
short chk1[__alignof__(g1) == 8 ? 1 : -1]; 
short chk2[__alignof__(double) == 8 ? 1 : -1];

long long g2;
short chk1[__alignof__(g2) == 8 ? 1 : -1]; 
short chk2[__alignof__(long long) == 8 ? 1 : -1];

_Complex double g3;
short chk1[__alignof__(g3) == 8 ? 1 : -1]; 
short chk2[__alignof__(_Complex double) == 8 ? 1 : -1];
