// RUN: clang-cc %s -triple=x86_64-apple-darwin10 -emit-llvm -o - | FileCheck %s

namespace {
  struct A {
    virtual void f() { }
  };
}

void f() { A b; }

struct B {
  B();
  virtual void f();
};

B::B() { }

struct C {
  C();
  virtual void f() { } 
};

C::C() { } 

// B has a key function that is not defined in this translation unit so its vtable
// has external linkage.
// CHECK: @_ZTV1B = external constant

// C has no key function, so its vtable should have weak_odr linkage.
// CHECK: @_ZTV1C = weak_odr constant

// The A vtable should have internal linkage since it is inside an anonymous 
// namespace.
// CHECK: @_ZTVN12_GLOBAL__N_11AE = internal constant
