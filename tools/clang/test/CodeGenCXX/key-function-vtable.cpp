// RUN: %clang_cc1 %s -emit-llvm -o - | FileCheck %s

// Simple key function test
struct testa { virtual void a(); };
void testa::a() {}

// Simple key function test
struct testb { virtual void a() {} };
testb *testbvar = new testb;

// Key function with out-of-line inline definition
struct testc { virtual void a(); };
inline void testc::a() {}

// Functions with inline specifier are not key functions (PR5705)
struct testd { inline virtual void a(); };
void testd::a() {}

// Functions with inline specifier are not key functions (PR5705)
struct teste { inline virtual void a(); };
teste *testevar = new teste;

// Key functions with namespace (PR5711)
namespace {
  struct testf { virtual void a(); };
}
void testf::a() {}

// Key functions with namespace (PR5711)
namespace {
  struct testg { virtual void a(); };
}
testg *testgvar = new testg;

struct X0 { virtual ~X0(); };
struct X1 : X0 {
  virtual void f();
};

inline void X1::f() { }

void use_X1(X1 *x1) { x1->f(); }

// FIXME: The checks are extremely difficult to get right when the globals
// aren't alphabetized
// CHECK: @_ZTV2X1 = weak_odr constant
// CHECK: @_ZTV5testa = constant [3 x i8*] [i8* null
// CHECK: @_ZTV5testc = weak_odr constant [3 x i8*] [i8* null
// CHECK: @_ZTVN12_GLOBAL__N_15testgE = internal constant [3 x i8*] [i8* null
// CHECK: @_ZTV5teste = weak_odr constant [3 x i8*] [i8* null
// CHECK: @_ZTV5testb = weak_odr constant [3 x i8*] [i8* null
