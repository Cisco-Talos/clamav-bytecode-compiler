// RUN: %clang_cc1 -triple x86_64-apple-darwin10 %s -emit-llvm -o - | FileCheck %s

struct Member { int x; Member(); Member(int); Member(const Member &); };
struct VBase { int x; VBase(); VBase(int); VBase(const VBase &); };

struct ValueClass {
  ValueClass(int x, int y) : x(x), y(y) {}
  int x;
  int y;
}; // subject to ABI trickery



/* Test basic functionality. */
class A {
  A(struct Undeclared &);
  A(ValueClass);
  Member mem;
};

A::A(struct Undeclared &ref) : mem(0) {}

// Check that delegation works.
// CHECK: define void @_ZN1AC1ER10Undeclared(
// CHECK: call void @_ZN1AC2ER10Undeclared(

// CHECK: define void @_ZN1AC2ER10Undeclared(
// CHECK: call void @_ZN6MemberC1Ei(

A::A(ValueClass v) : mem(v.y - v.x) {}

// CHECK: define void @_ZN1AC1E10ValueClass(
// CHECK: call void @_ZN1AC2E10ValueClass(

// CHECK: define void @_ZN1AC2E10ValueClass(
// CHECK: call void @_ZN6MemberC1Ei(


/* Test that things work for inheritance. */
struct B : A {
  B(struct Undeclared &);
  Member mem;
};

B::B(struct Undeclared &ref) : A(ref), mem(1) {}

// CHECK: define void @_ZN1BC1ER10Undeclared(
// CHECK: call void @_ZN1BC2ER10Undeclared(

// CHECK: define void @_ZN1BC2ER10Undeclared(
// CHECK: call void @_ZN1AC2ER10Undeclared(
// CHECK: call void @_ZN6MemberC1Ei(



/* Test that the delegation optimization is disabled for classes with
   virtual bases (for now).  This is necessary because a vbase
   initializer could access one of the parameter variables by
   reference.  That's a solvable problem, but let's not solve it right
   now. */
struct C : virtual A {
  C(int);
  Member mem;
};
C::C(int x) : A(ValueClass(x, x+1)), mem(x * x) {}

// CHECK: define void @_ZN1CC1Ei(
// CHECK: call void @_ZN10ValueClassC1Eii(
// CHECK: call void @_ZN1AC2E10ValueClass(
// CHECK: call void @_ZN6MemberC1Ei(

// CHECK: define void @_ZN1CC2Ei(
// CHECK: call void @_ZN6MemberC1Ei(



/* Test that the delegation optimization is disabled for varargs
   constructors. */
struct D : A {
  D(int, ...);
  Member mem;
};

D::D(int x, ...) : A(ValueClass(x, x+1)), mem(x*x) {}

// CHECK: define void @_ZN1DC1Eiz(
// CHECK: call void @_ZN10ValueClassC1Eii(
// CHECK: call void @_ZN1AC2E10ValueClass(
// CHECK: call void @_ZN6MemberC1Ei(

// CHECK: define void @_ZN1DC2Eiz(
// CHECK: call void @_ZN10ValueClassC1Eii(
// CHECK: call void @_ZN1AC2E10ValueClass(
// CHECK: call void @_ZN6MemberC1Ei(
