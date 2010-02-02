// RUN: %clang_cc1 -emit-llvm %s -o - -triple=x86_64-apple-darwin10 -O3 | FileCheck %s

struct A {
  virtual int f() { return 1; }
};

struct B : A {
  B() : i(f()) { }
  
  virtual int f() { return 2; }
  
  int i;
};

// CHECK: define i32 @_Z1fv() nounwind
int f() {
  B b;
  
  // CHECK: call i32 @_ZN1B1fEv
  return b.i;
}

