// RUN: clang-cc -triple x86_64-apple-darwin -S %s -o %t-64.s &&
// RUN: FileCheck -check-prefix LP64 --input-file=%t-64.s %s &&
// RUN: clang-cc -triple i386-apple-darwin -S %s -o %t-32.s &&
// RUN: FileCheck -check-prefix LP32 --input-file=%t-32.s %s &&
// RUN: true

struct A {};

struct B 
{ 
  operator A&();
}; 


struct D : public B {
  operator A();
};

extern B f(); 
extern D d(); 

int main() {
	const A& rca = f();
	const A& rca2 = d();
}

// CHECK-LP64: call     __ZN1BcvR1AEv
// CHECK-LP64: call     __ZN1BcvR1AEv

// CHECK-LP32: call     L__ZN1BcvR1AEv
// CHECK-LP32: call     L__ZN1BcvR1AEv
