// RUN: %clang_cc1 -P -E %s | grep 'int f(void)'
// PR1820

#define f(x) h(x
#define h(x) x(void) 
extern int f(f));
