// RUN: %clang_cc1 -analyze -analyzer-store=region -analyzer-constraints=range -fblocks -analyzer-opt-analyze-nested-blocks -analyzer-check-objc-mem -analyzer-check-idempotent-operations -verify %s

// Basic tests

extern void test(int i);
extern void test_f(float f);

unsigned basic() {
  int x = 10, zero = 0, one = 1;

  // x op x
  x = x;        // expected-warning {{Assigned value is always the same as the existing value}}
  test(x - x);  // expected-warning {{Both operands to '-' always have the same value}}
  x -= x;       // expected-warning {{Both operands to '-=' always have the same value}}
  x = 10;       // no-warning
  test(x / x);  // expected-warning {{Both operands to '/' always have the same value}}
  x /= x;       // expected-warning {{Both operands to '/=' always have the same value}}
  x = 10;       // no-warning
  test(x & x);  // expected-warning {{Both operands to '&' always have the same value}}
  x &= x;       // expected-warning {{Both operands to '&=' always have the same value}}
  test(x | x);  // expected-warning {{Both operands to '|' always have the same value}}
  x |= x;       // expected-warning {{Both operands to '|=' always have the same value}}

  // x op 1
  test(x * one);  // expected-warning {{The right operand to '*' is always 1}}
  x *= one;       // expected-warning {{The right operand to '*=' is always 1}}
  test(x / one);  // expected-warning {{The right operand to '/' is always 1}}
  x /= one;       // expected-warning {{The right operand to '/=' is always 1}}

  // 1 op x
  test(one * x);   // expected-warning {{The left operand to '*' is always 1}}

  // x op 0
  test(x + zero);  // expected-warning {{The right operand to '+' is always 0}}
  test(x - zero);  // expected-warning {{The right operand to '-' is always 0}}
  test(x * zero);  // expected-warning {{The right operand to '*' is always 0}}
  test(x & zero);  // expected-warning {{The right operand to '&' is always 0}}
  test(x | zero);  // expected-warning {{The right operand to '|' is always 0}}
  test(x ^ zero);  // expected-warning {{The right operand to '^' is always 0}}
  test(x << zero); // expected-warning {{The right operand to '<<' is always 0}}
  test(x >> zero); // expected-warning {{The right operand to '>>' is always 0}}

  // 0 op x
  test(zero + x);  // expected-warning {{The left operand to '+' is always 0}}
  test(zero - x);  // expected-warning {{The left operand to '-' is always 0}}
  test(zero / x);  // expected-warning {{The left operand to '/' is always 0}}
  test(zero * x);  // expected-warning {{The left operand to '*' is always 0}}
  test(zero & x);  // expected-warning {{The left operand to '&' is always 0}}
  test(zero | x);  // expected-warning {{The left operand to '|' is always 0}}
  test(zero ^ x);  // expected-warning {{The left operand to '^' is always 0}}
  test(zero << x); // expected-warning {{The left operand to '<<' is always 0}}
  test(zero >> x); // expected-warning {{The left operand to '>>' is always 0}}

  // Overwrite the values so these aren't marked as Pseudoconstants
  x = 1;
  zero = 2;
  one = 3;

  return x + zero + one;
}

void floats(float x) {
  test_f(x * 1.0);  // no-warning
  test_f(x * 1.0F); // no-warning
}

// Ensure that we don't report false poitives in complex loops
void bailout() {
  int unused = 0, result = 4;
  result = result; // expected-warning {{Assigned value is always the same as the existing value}}

  for (unsigned bg = 0; bg < 1024; bg ++) {
    result = bg * result; // no-warning

    for (int i = 0; i < 256; i++) {
      unused *= i; // no-warning
    }
  }
}

// Relaxed liveness - check that we don't kill liveness at assignments
typedef unsigned uintptr_t;
void kill_at_assign() {
  short array[2];
  uintptr_t x = array; // expected-warning{{incompatible pointer to integer conversion}}
  short *p = x; // expected-warning{{incompatible integer to pointer conversion}}

  // The following branch should be infeasible.
  if (!(p = &array[0])) { // expected-warning{{Assigned value is always the same as the existing value}}
    p = 0;
    *p = 1; // no-warning
  }
}

// False positive tests

unsigned false1() {
  int a = 10;
  return a * (5 - 2 - 3); // no-warning
}

enum testenum { enum1 = 0, enum2 };
unsigned false2() {
  int a = 1234;
  return enum1 + a; // no-warning
}

// Self assignments of unused variables are common false positives
unsigned false3(int param, int param2) {
  param = param; // no-warning

  // if a self assigned variable is used later, then it should be reported still
  param2 = param2; // expected-warning{{Assigned value is always the same as the existing value}}

  unsigned nonparam = 5;

  nonparam = nonparam; // expected-warning{{Assigned value is always the same as the existing value}}

  return param2 + nonparam;
}

// Pseudo-constants (vars only read) and constants should not be reported
unsigned false4() {
  // Trivial constant
  const int height = 1;
  int c = 42;
  test(height * c); // no-warning

  // Pseudo-constant (never changes after decl)
  int width = height;

  return width * 10; // no-warning
}

// Block pseudoconstants
void false4a() {
  // Pseudo-constant
  __block int a = 1;
  int b = 10;
  __block int c = 0;
  b *= a; // no-warning

  ^{
    // Psuedoconstant block var
    test(b * c); // no-warning

    // Non-pseudoconstant block var
    int d = 0;
    test(b * d); // expected-warning{{The right operand to '*' is always 0}}
    d = 5;
    test(d);
  }();

  test(a + b);
}

// Static vars are common false positives
int false5() {
  static int test = 0;
  int a = 56;
  a *= test; // no-warning
  test++;
  return a;
}

// Non-local storage vars are considered false positives
int globalInt = 1;
int false6() {
  int localInt = 23;

  localInt /= globalInt;

  return localInt;
}

// Check that assignments filter out false positives correctly
int false7() {
  int zero = 0; // psuedo-constant
  int one = 1;

  int a = 55;
  a = a; // expected-warning{{Assigned value is always the same as the existing value}}
  a = enum1 * a; // no-warning

  int b = 123;
  b = b; // no-warning

  return a;
}
