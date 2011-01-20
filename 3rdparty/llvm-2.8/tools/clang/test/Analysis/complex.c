// RUN: %clang_cc1 -analyze -analyzer-experimental-internal-checks -analyzer-check-objc-mem -analyzer-store=basic -analyzer-constraints=basic -verify -Wno-unreachable-code %s
// RUN: %clang_cc1 -analyze -analyzer-experimental-internal-checks -analyzer-check-objc-mem -analyzer-store=basic -analyzer-constraints=range -verify -Wno-unreachable-code %s
// RUN: %clang_cc1 -analyze -analyzer-experimental-internal-checks -analyzer-check-objc-mem -analyzer-store=region -analyzer-constraints=basic -verify -Wno-unreachable-code %s
// RUN: %clang_cc1 -analyze -analyzer-experimental-internal-checks -analyzer-check-objc-mem -analyzer-store=region -analyzer-constraints=range -verify -Wno-unreachable-code %s

#include <stdint.h>

void f1(int * p) {
  
  // This branch should be infeasible
  // because __imag__ p is 0.
  if (!p && __imag__ (intptr_t) p)
    *p = 1; // no-warning

  // If p != 0 then this branch is feasible; otherwise it is not.
  if (__real__ (intptr_t) p)
    *p = 1; // no-warning
    
  *p = 2; // expected-warning{{Dereference of null pointer}}
}
