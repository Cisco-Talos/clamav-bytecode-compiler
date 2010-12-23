// RUN: %clang_cc1 %s -triple x86_64-apple-darwin10 -emit-llvm -o - | FileCheck %s

struct A {
  virtual ~A();
};

struct B : A { };

struct C {
  int i;
  B b;
};

// CHECK: _Z15test_value_initv
void test_value_init() {
  // This value initialization requires zero initialization of the 'B'
  // subobject followed by a call to its constructor.
  // PR5800

  // CHECK: store i32 17
  // CHECK: call void @llvm.memset.p0i8.i64
  // CHECK: call void @_ZN1BC1Ev
  C c = { 17 } ;
  // CHECK: call void @_ZN1CD1Ev
}

enum enum_type { negative_number = -1, magic_number = 42 };

class enum_holder
{
  enum_type m_enum;

public:
  enum_holder() : m_enum(magic_number) { }
};

struct enum_holder_and_int
{
  enum_holder e;
  int i;
};

// CHECK: _Z24test_enum_holder_and_intv()
void test_enum_holder_and_int() {
  // CHECK: alloca
  // CHECK-NEXT: bitcast
  // CHECK-NEXT: call void @llvm.memset
  // CHECK-NEXT: call void @_ZN19enum_holder_and_intC1Ev
  enum_holder_and_int();
  // CHECK-NEXT: ret void
}

// PR7834: don't crash.
namespace test1 {
  struct A {
    int A::*f;
    A();
    A(const A&);
    A &operator=(const A &);
  };

  struct B {
    A base;
  };

  void foo() {
    B();
  }
}

namespace ptrmem {
  struct S {
    int mem1;
    int S::*mem2;
  };

  // CHECK: define i32 @_ZN6ptrmem4testEPNS_1SE
  int test(S *s) {
    // CHECK: call void @llvm.memcpy.p0i8.p0i8.i64
    // CHECK: getelementptr
    // CHECK: ret
    return s->*S().mem2;
  }
}

namespace zeroinit {
  struct S { int i; };

  // CHECK: define i32 @_ZN8zeroinit4testEv()
  int test() {
    // CHECK: call void @llvm.memset.p0i8.i64
    // CHECK: getelementptr
    // CHECK: ret i32
    return S().i;
  }

  struct X0 {
    X0() { }
    int x;
  };

  struct X1 : X0 {
    int x1;
    void f();
  };

  // CHECK: define void @_ZN8zeroinit9testX0_X1Ev
  void testX0_X1() {
    // CHECK: call void @llvm.memset.p0i8.i64
    // CHECK-NEXT: call void @_ZN8zeroinit2X1C1Ev
    // CHECK-NEXT: call void @_ZN8zeroinit2X11fEv
    X1().f();
  }

  template<typename>
  struct X2 : X0 {
    int x2;
    void f();
  };

  template<typename>
  struct X3 : X2<int> { 
    X3() : X2<int>() { }
  };
  

  // CHECK: define void @_ZN8zeroinit9testX0_X3Ev
  void testX0_X3() {
    // CHECK-NOT: call void @llvm.memset
    // CHECK: call void @_ZN8zeroinit2X3IiEC1Ev
    // CHECK: call void @_ZN8zeroinit2X2IiE1fEv
    // CHECK-NEXT: ret void
    X3<int>().f();
  }

  // CHECK: define linkonce_odr void @_ZN8zeroinit2X3IiEC2Ev
  // CHECK: call void @llvm.memset.p0i8.i64
  // CHECK-NEXT: call void @_ZN8zeroinit2X2IiEC2Ev
  // CHECK-NEXT: ret void
}
