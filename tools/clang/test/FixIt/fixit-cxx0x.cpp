// RUN: %clang_cc1 -verify -std=c++0x %s
// RUN: cp %s %t
// RUN: %clang_cc1 -std=c++0x -fixit %t || true
// RUN: %clang_cc1 -Wall -pedantic -x c++ -std=c++0x %t

/* This is a test of the various code modification hints that only
   apply in C++0x. */
struct A {
  explicit operator int(); // expected-note{{conversion to integral type}}
};

void x() {
  switch(A()) { // expected-error{{explicit conversion to}}
  }
}

