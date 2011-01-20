// RUN: %clang_cc1 %s -triple x86_64-apple-darwin10 -emit-llvm -o - -mconstructor-aliases -fexceptions | FileCheck %s

// CHECK: @_ZN5test01AD1Ev = alias {{.*}} @_ZN5test01AD2Ev
// CHECK: @_ZN5test11MD2Ev = alias {{.*}} @_ZN5test11AD2Ev
// CHECK: @_ZN5test11ND2Ev = alias {{.*}} @_ZN5test11AD2Ev
// CHECK: @_ZN5test11OD2Ev = alias {{.*}} @_ZN5test11AD2Ev
// CHECK: @_ZN5test11SD2Ev = alias bitcast {{.*}} @_ZN5test11AD2Ev

// CHECK: @_ZN5test312_GLOBAL__N_11DD1Ev = alias internal {{.*}} @_ZN5test312_GLOBAL__N_11DD2Ev
// CHECK: @_ZN5test312_GLOBAL__N_11DD2Ev = alias internal bitcast {{.*}} @_ZN5test312_GLOBAL__N_11CD2Ev
// CHECK: @_ZN5test312_GLOBAL__N_11CD1Ev = alias internal {{.*}} @_ZN5test312_GLOBAL__N_11CD2Ev

struct A {
  int a;
  
  ~A();
};

// Base with non-trivial destructor
struct B : A {
  ~B();
};

B::~B() { }

// Field with non-trivial destructor
struct C {
  A a;
  
  ~C();
};

C::~C() { }

namespace PR7526 {
  extern void foo();
  struct allocator {
    ~allocator() throw();
  };

  struct allocator_derived : allocator { };

  // CHECK: define void @_ZN6PR75269allocatorD2Ev
  // CHECK: call void @__cxa_call_unexpected
  allocator::~allocator() throw() { foo(); }

  // CHECK: define linkonce_odr void @_ZN6PR752617allocator_derivedD1Ev
  // CHECK-NOT: call void @__cxa_call_unexpected
  // CHECK:     }
  void foo() {
    allocator_derived ad;
  }
}

// PR5084
template<typename T>
class A1 {
  ~A1();
};

template<> A1<char>::~A1();

// PR5529
namespace PR5529 {
  struct A {
    ~A();
  };
  
  A::~A() { }
  struct B : A {
    virtual ~B();
  };
  
  B::~B()  {}
}

// FIXME: there's a known problem in the codegen here where, if one
// destructor throws, the remaining destructors aren't run.  Fix it,
// then make this code check for it.
namespace test0 {
  void foo();
  struct VBase { ~VBase(); };
  struct Base { ~Base(); };
  struct Member { ~Member(); };

  struct A : Base {
    Member M;
    ~A();
  };

  // The function-try-block won't suppress -mconstructor-aliases here.
  A::~A() try { } catch (int i) {}

// complete destructor alias tested above

// CHECK: define void @_ZN5test01AD2Ev
// CHECK: invoke void @_ZN5test06MemberD1Ev
// CHECK:   unwind label [[MEM_UNWIND:%[a-zA-Z0-9.]+]]
// CHECK: invoke void @_ZN5test04BaseD2Ev
// CHECK:   unwind label [[BASE_UNWIND:%[a-zA-Z0-9.]+]]

  struct B : Base, virtual VBase {
    Member M;
    ~B();
  };
  B::~B() try { } catch (int i) {}
  // It will suppress the delegation optimization here, though.

// CHECK: define void @_ZN5test01BD1Ev
// CHECK: invoke void @_ZN5test06MemberD1Ev
// CHECK:   unwind label [[MEM_UNWIND:%[a-zA-Z0-9.]+]]
// CHECK: invoke void @_ZN5test04BaseD2Ev
// CHECK:   unwind label [[BASE_UNWIND:%[a-zA-Z0-9.]+]]
// CHECK: invoke void @_ZN5test05VBaseD2Ev
// CHECK:   unwind label [[VBASE_UNWIND:%[a-zA-Z0-9.]+]]

// CHECK: define void @_ZN5test01BD2Ev
// CHECK: invoke void @_ZN5test06MemberD1Ev
// CHECK:   unwind label [[MEM_UNWIND:%[a-zA-Z0-9.]+]]
// CHECK: invoke void @_ZN5test04BaseD2Ev
// CHECK:   unwind label [[BASE_UNWIND:%[a-zA-Z0-9.]+]]
}

// Test base-class aliasing.
namespace test1 {
  struct A { ~A(); char ***m; }; // non-trivial destructor
  struct B { ~B(); }; // non-trivial destructor
  struct Empty { }; // trivial destructor, empty
  struct NonEmpty { int x; }; // trivial destructor, non-empty

  // There must be a definition in this translation unit for the alias
  // optimization to apply.
  A::~A() { delete m; }

  struct M : A { ~M(); };
  M::~M() {} // alias tested above

  struct N : A, Empty { ~N(); };
  N::~N() {} // alias tested above

  struct O : Empty, A { ~O(); };
  O::~O() {} // alias tested above

  struct P : NonEmpty, A { ~P(); };
  P::~P() {} // CHECK: define void @_ZN5test11PD2Ev

  struct Q : A, B { ~Q(); };
  Q::~Q() {} // CHECK: define void @_ZN5test11QD2Ev

  struct R : A { ~R(); };
  R::~R() { A a; } // CHECK: define void @_ZN5test11RD2Ev

  struct S : A { ~S(); int x; };
  S::~S() {} // alias tested above

  struct T : A { ~T(); B x; };
  T::~T() {} // CHECK: define void @_ZN5test11TD2Ev

  // The VTT parameter prevents this.  We could still make this work
  // for calling conventions that are safe against extra parameters.
  struct U : A, virtual B { ~U(); };
  U::~U() {} // CHECK: define void @_ZN5test11UD2Ev
}

// PR6471
namespace test2 {
  struct A { ~A(); char ***m; };
  struct B : A { ~B(); };

  B::~B() {}
  // CHECK: define void @_ZN5test21BD2Ev
  // CHECK: call void @_ZN5test21AD2Ev
}

// PR7142
namespace test3 {
  struct A { virtual ~A(); };
  struct B { virtual ~B(); };
  namespace { // internal linkage => deferred
    struct C : A, B {}; // ~B() in D requires a this-adjustment thunk
    struct D : C {};    // D::~D() is an alias to C::~C()
  }

  void test() {
    new D; // Force emission of D's vtable
  }

  // Checked at top of file:
  // @_ZN5test312_GLOBAL__N_11CD1Ev = alias internal {{.*}} @_ZN5test312_GLOBAL__N_11CD2Ev

  // More checks at end of file.

}

namespace test4 {
  struct A { ~A(); };

  // CHECK: define void @_ZN5test43fooEv()
  // CHECK: call void @_ZN5test41AD1Ev
  // CHECK: ret void
  void foo() {
    {
      A a;
      goto failure;
    }

  failure:
    return;
  }

  // CHECK: define void @_ZN5test43barEi(
  // CHECK:      [[X:%.*]] = alloca i32
  // CHECK-NEXT: [[A:%.*]] = alloca
  // CHECK:      br label
  // CHECK:      [[TMP:%.*]] = load i32* [[X]]
  // CHECK-NEXT: [[CMP:%.*]] = icmp ne i32 [[TMP]], 0
  // CHECK-NEXT: br i1
  // CHECK:      call void @_ZN5test41AD1Ev(
  // CHECK:      br label
  // CHECK:      [[TMP:%.*]] = load i32* [[X]]
  // CHECK:      [[TMP2:%.*]] = add nsw i32 [[TMP]], -1
  // CHECK:      store i32 [[TMP2]], i32* [[X]]
  // CHECK:      br label
  // CHECK:      ret void
  void bar(int x) {
    for (A a; x; ) {
      x--;
    }
  }
}

// PR7575
namespace test5 {
  struct A { ~A(); };

  // This is really unnecessarily verbose; we should be using phis,
  // even at -O0.

  // CHECK: define void @_ZN5test53fooEv()
  // CHECK:      [[ELEMS:%.*]] = alloca [5 x [[A:%.*]]], align
  // CHECK-NEXT: [[IVAR:%.*]] = alloca i64
  // CHECK:      [[ELEMSARRAY:%.*]] = bitcast [5 x [[A]]]* [[ELEMS]] to [[A]]
  // CHECK-NEXT: store i64 5, i64* [[IVAR]]
  // CHECK-NEXT: br label
  // CHECK:      [[I:%.*]] = load i64* [[IVAR]]
  // CHECK-NEXT: icmp ne i64 [[I]], 0
  // CHECK-NEXT: br i1
  // CHECK:      [[I:%.*]] = load i64* [[IVAR]]
  // CHECK-NEXT: [[I2:%.*]] = sub i64 [[I]], 1
  // CHECK-NEXT: getelementptr inbounds [[A]]* [[ELEMSARRAY]], i64 [[I2]]
  // CHECK-NEXT: call void @_ZN5test51AD1Ev(
  // CHECK-NEXT: br label
  // CHECK:      [[I:%.*]] = load i64* [[IVAR]]
  // CHECK-NEXT: [[I1:%.*]] = sub i64 [[I]], 1
  // CHECK-NEXT: store i64 [[I1]], i64* [[IVAR]]
  // CHECK-NEXT: br label
  // CHECK:      ret void
  void foo() {
    A elems[5];
  }
}

namespace test6 {
  void opaque();

  struct A { ~A(); };
  template <unsigned> struct B { B(); ~B(); int _; };
  struct C : B<0>, B<1>, virtual B<2>, virtual B<3> {
    A x, y, z;

    C();
    ~C();
  };

  C::C() { opaque(); }
  // CHECK: define void @_ZN5test61CC1Ev
  // CHECK:   call void @_ZN5test61BILj2EEC2Ev
  // CHECK:   invoke void @_ZN5test61BILj3EEC2Ev
  // CHECK:   invoke void @_ZN5test61BILj0EEC2Ev
  // CHECK:   invoke void @_ZN5test61BILj1EEC2Ev
  // CHECK:   invoke void @_ZN5test66opaqueEv
  // CHECK:   ret void
  // FIXME: way too much EH cleanup code follows

  C::~C() { opaque(); }
  // CHECK: define void @_ZN5test61CD1Ev
  // CHECK:   invoke void @_ZN5test61CD2Ev
  // CHECK:   invoke void @_ZN5test61BILj3EED2Ev
  // CHECK:   call void @_ZN5test61BILj2EED2Ev
  // CHECK:   ret void
  // CHECK:   invoke void @_ZN5test61BILj3EED2Ev
  // CHECK:   invoke void @_ZN5test61BILj2EED2Ev

  // CHECK: define void @_ZN5test61CD2Ev
  // CHECK:   invoke void @_ZN5test66opaqueEv
  // CHECK:   invoke void @_ZN5test61AD1Ev
  // CHECK:   invoke void @_ZN5test61AD1Ev
  // CHECK:   invoke void @_ZN5test61AD1Ev
  // CHECK:   invoke void @_ZN5test61BILj1EED2Ev
  // CHECK:   call void @_ZN5test61BILj0EED2Ev
  // CHECK:   ret void
  // CHECK:   invoke void @_ZN5test61AD1Ev
  // CHECK:   invoke void @_ZN5test61AD1Ev
  // CHECK:   invoke void @_ZN5test61AD1Ev
  // CHECK:   invoke void @_ZN5test61BILj1EED2Ev
  // CHECK:   invoke void @_ZN5test61BILj0EED2Ev
}

// Checks from test3:

  // CHECK: define internal void @_ZN5test312_GLOBAL__N_11DD0Ev(
  // CHECK: invoke void @_ZN5test312_GLOBAL__N_11DD1Ev(
  // CHECK: call void @_ZdlPv({{.*}}) nounwind
  // CHECK: ret void
  // CHECK: call i8* @llvm.eh.exception(
  // CHECK: call void @_ZdlPv({{.*}}) nounwind
  // CHECK: call void @_Unwind_Resume_or_Rethrow

  // Checked at top of file:
  // @_ZN5test312_GLOBAL__N_11DD1Ev = alias internal {{.*}} @_ZN5test312_GLOBAL__N_11DD2Ev
  // @_ZN5test312_GLOBAL__N_11DD2Ev = alias internal bitcast {{.*}} @_ZN5test312_GLOBAL__N_11CD2Ev

  // CHECK: define internal void @_ZThn8_N5test312_GLOBAL__N_11DD1Ev(
  // CHECK: getelementptr inbounds i8* {{.*}}, i64 -8
  // CHECK: call void @_ZN5test312_GLOBAL__N_11DD1Ev(
  // CHECK: ret void

  // CHECK: define internal void @_ZThn8_N5test312_GLOBAL__N_11DD0Ev(
  // CHECK: getelementptr inbounds i8* {{.*}}, i64 -8
  // CHECK: call void @_ZN5test312_GLOBAL__N_11DD0Ev(
  // CHECK: ret void

  // CHECK: define internal void @_ZN5test312_GLOBAL__N_11CD2Ev(
  // CHECK: invoke void @_ZN5test31BD2Ev(
  // CHECK: call void @_ZN5test31AD2Ev(
  // CHECK: ret void

  // CHECK: declare void @_ZN5test31BD2Ev(
  // CHECK: declare void @_ZN5test31AD2Ev(

  // CHECK: define internal void @_ZN5test312_GLOBAL__N_11CD0Ev(
  // CHECK: invoke void @_ZN5test312_GLOBAL__N_11CD1Ev(
  // CHECK: call void @_ZdlPv({{.*}}) nounwind
  // CHECK: ret void
  // CHECK: call i8* @llvm.eh.exception()
  // CHECK: call void @_ZdlPv({{.*}}) nounwind
  // CHECK: call void @_Unwind_Resume_or_Rethrow(

  // CHECK: define internal void @_ZThn8_N5test312_GLOBAL__N_11CD1Ev(
  // CHECK: getelementptr inbounds i8* {{.*}}, i64 -8
  // CHECK: call void @_ZN5test312_GLOBAL__N_11CD1Ev(
  // CHECK: ret void

  // CHECK: define internal void @_ZThn8_N5test312_GLOBAL__N_11CD0Ev(
  // CHECK: getelementptr inbounds i8* {{.*}}, i64 -8
  // CHECK: call void @_ZN5test312_GLOBAL__N_11CD0Ev(
  // CHECK: ret void
