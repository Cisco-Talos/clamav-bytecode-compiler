// RUN: clang-cc -triple x86_64-apple-darwin -std=c++0x -S %s -o %t-64.s
// RUN: FileCheck -check-prefix LP64 --input-file=%t-64.s %s
// RUN: clang-cc -triple i386-apple-darwin -std=c++0x -S %s -o %t-32.s
// RUN: FileCheck -check-prefix LP32 --input-file=%t-32.s %s
// RUN: true

struct A {
  A(int);
};

struct B {
  B(A);
};

int main () {
  (B)10;
  B(10);
  static_cast<B>(10);
}

// CHECK-LP64: call     __ZN1AC1Ei
// CHECK-LP64: call     __ZN1BC1E1A
// CHECK-LP64: call     __ZN1AC1Ei
// CHECK-LP64: call     __ZN1BC1E1A
// CHECK-LP64: call     __ZN1AC1Ei
// CHECK-LP64: call     __ZN1BC1E1A

// CHECK-LP32: call     L__ZN1AC1Ei
// CHECK-LP32: call     L__ZN1BC1E1A
// CHECK-LP32: call     L__ZN1AC1Ei
// CHECK-LP32: call     L__ZN1BC1E1A
// CHECK-LP32: call     L__ZN1AC1Ei
// CHECK-LP32: call     L__ZN1BC1E1A
