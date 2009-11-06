// RUN: clang-cc -triple x86_64-apple-darwin -std=c++0x -emit-llvm %s -o %t-64.ll &&
// RUN: FileCheck -check-prefix LPLL64 --input-file=%t-64.ll %s &&
// RUN: true

extern "C" int printf(...);

struct A { 
  A(...) {
    printf("A::A(...)\n"); 
  } 
};

A a(1.34);

A b = 2.34;

int main()
{
  A c[3];
}

// CHECK-LPLL64: call void (%struct.A*, ...)
// CHECK-LPLL64: call void (%struct.A*, ...)
// CHECK-LPLL64: call void (%struct.A*, ...)
