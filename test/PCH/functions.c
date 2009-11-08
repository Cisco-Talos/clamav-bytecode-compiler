// Test this without pch.
// RUN: clang-cc -include %S/functions.h -fsyntax-only -verify %s

// Test with pch.
// RUN: clang-cc -emit-pch -o %t %S/functions.h
// RUN: clang-cc -include-pch %t -fsyntax-only -verify %s 

int f0(int x0, int y0, ...) { return x0 + y0; }

float *test_f1(int val, double x, double y) {
  if (val > 5)
    return f1(x, y);
  else
    return f1(x); // expected-error{{too few arguments to function call}}
}

void test_g0(int *x, float * y) {
  g0(y); // expected-warning{{incompatible pointer types passing 'float *', expected 'int *'}}
  g0(x); 
}
