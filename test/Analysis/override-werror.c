// RUN: %clang_cc1 -analyze -analyzer-experimental-internal-checks -analyzer-check-objc-mem -Werror %s -analyzer-store=basic -verify
// RUN: %clang_cc1 -analyze -analyzer-experimental-internal-checks -analyzer-check-objc-mem -Werror %s -analyzer-store=region -verify

// This test case illustrates that using '-analyze' overrides the effect of
// -Werror.  This allows basic warnings not to interfere with producing
// analyzer results.

char* f(int *p) { 
  return p; // expected-warning{{incompatible pointer types returning 'int *', expected 'char *'}}
}

void g(int *p) {
  if (!p) *p = 0; // expected-warning{{null}}  
}

