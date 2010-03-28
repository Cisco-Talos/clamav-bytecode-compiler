// RUN: %clang_cc1 -fsyntax-only -Wunused-function -verify %s

void foo() {}
static void f2() {} 
static void f1() {f2();} // expected-warning{{unused}}

static int f0() { return 17; } // expected-warning{{unused}}
int x = sizeof(f0());

static void f3();
extern void f3() { } // expected-warning{{unused}}

// FIXME: This will trigger a warning when it should not.
// Update once PR6281 is fixed.
//inline static void f4();
//void f4() { }

static void __attribute__((used)) f5() {}
static void f6();
static void __attribute__((used)) f6();
static void f6() {};

static void f7(void);
void f8(void(*a0)(void));
void f9(void) { f8(f7); }
static void f7(void) {}

__attribute__((unused)) static void bar(void);
void bar(void) { }

