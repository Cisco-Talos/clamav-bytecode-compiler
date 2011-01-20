// RUN: %clang_cc1 %s -triple=x86_64-apple-darwin10 -emit-llvm -o %t
// RUN: %clang_cc1 %s -triple=x86_64-apple-darwin10 -fhidden-weak-vtables -emit-llvm -o %t.hidden
// RUN: FileCheck --check-prefix=CHECK-1 %s < %t
// RUN: FileCheck --check-prefix=CHECK-2 %s < %t
// RUN: FileCheck --check-prefix=CHECK-2-HIDDEN %s < %t.hidden
// RUN: FileCheck --check-prefix=CHECK-3 %s < %t
// RUN: FileCheck --check-prefix=CHECK-4 %s < %t
// RUN: FileCheck --check-prefix=CHECK-5 %s < %t
// RUN: FileCheck --check-prefix=CHECK-5-HIDDEN %s < %t.hidden
// RUN: FileCheck --check-prefix=CHECK-6 %s < %t
// RUN: FileCheck --check-prefix=CHECK-6-HIDDEN %s < %t.hidden
// RUN: FileCheck --check-prefix=CHECK-7 %s < %t
// RUN: FileCheck --check-prefix=CHECK-8 %s < %t
// RUN: FileCheck --check-prefix=CHECK-9 %s < %t
// RUN: FileCheck --check-prefix=CHECK-10 %s < %t
// RUN: FileCheck --check-prefix=CHECK-11 %s < %t
// RUN: FileCheck --check-prefix=CHECK-12 %s < %t
// RUN: FileCheck --check-prefix=CHECK-13 %s < %t

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

struct D {
  virtual void f();
};

void D::f() { }

static struct : D { } e;

// The destructor is the key function.
template<typename T>
struct E {
  virtual ~E();
};

template<typename T> E<T>::~E() { }

// Anchor is the key function
template<>
struct E<char> {
  virtual void anchor();
};

void E<char>::anchor() { }

template struct E<short>;
extern template struct E<int>;

void use_E() {
  E<int> ei;
  (void)ei;
  E<long> el;
  (void)el;
}

// No key function
template<typename T>
struct F {
  virtual void foo() { }
};

// No key function
template<>
struct F<char> {
  virtual void foo() { }
};

template struct F<short>;
extern template struct F<int>;

void use_F() {
  F<char> fc;
  fc.foo();
  F<int> fi;
  fi.foo();
  F<long> fl;
  (void)fl;
}

// B has a key function that is not defined in this translation unit so its vtable
// has external linkage.
// CHECK-1: @_ZTV1B = external constant

// C has no key function, so its vtable should have weak_odr linkage
// and hidden visibility (rdar://problem/7523229).
// CHECK-2: @_ZTV1C = weak_odr constant
// CHECK-2: @_ZTS1C = weak_odr constant
// CHECK-2: @_ZTI1C = weak_odr constant
// CHECK-2-HIDDEN: @_ZTV1C = weak_odr hidden constant
// CHECK-2-HIDDEN: @_ZTS1C = weak_odr constant
// CHECK-2-HIDDEN: @_ZTI1C = weak_odr hidden constant

// D has a key function that is defined in this translation unit so its vtable is
// defined in the translation unit.
// CHECK-3: @_ZTV1D = constant
// CHECK-3: @_ZTS1D = constant
// CHECK-3: @_ZTI1D = constant

// E<char> is an explicit specialization with a key function defined
// in this translation unit, so its vtable should have external
// linkage.
// CHECK-4: @_ZTV1EIcE = constant
// CHECK-4: @_ZTS1EIcE = constant
// CHECK-4: @_ZTI1EIcE = constant

// E<short> is an explicit template instantiation with a key function
// defined in this translation unit, so its vtable should have
// weak_odr linkage.
// CHECK-5: @_ZTV1EIsE = weak_odr constant
// CHECK-5: @_ZTS1EIsE = weak_odr constant
// CHECK-5: @_ZTI1EIsE = weak_odr constant
// CHECK-5-HIDDEN: @_ZTV1EIsE = weak_odr constant
// CHECK-5-HIDDEN: @_ZTS1EIsE = weak_odr constant
// CHECK-5-HIDDEN: @_ZTI1EIsE = weak_odr constant

// F<short> is an explicit template instantiation without a key
// function, so its vtable should have weak_odr linkage
// CHECK-6: @_ZTV1FIsE = weak_odr constant
// CHECK-6: @_ZTS1FIsE = weak_odr constant
// CHECK-6: @_ZTI1FIsE = weak_odr constant
// CHECK-6-HIDDEN: @_ZTV1FIsE = weak_odr constant
// CHECK-6-HIDDEN: @_ZTS1FIsE = weak_odr constant
// CHECK-6-HIDDEN: @_ZTI1FIsE = weak_odr constant

// E<long> is an implicit template instantiation with a key function
// defined in this translation unit, so its vtable should have
// weak_odr linkage.
// CHECK-7: @_ZTV1EIlE = weak_odr constant
// CHECK-7: @_ZTS1EIlE = weak_odr constant
// CHECK-7: @_ZTI1EIlE = weak_odr constant

// F<long> is an implicit template instantiation with no key function,
// so its vtable should have weak_odr linkage.
// CHECK-8: @_ZTV1FIlE = weak_odr constant
// CHECK-8: @_ZTS1FIlE = weak_odr constant
// CHECK-8: @_ZTI1FIlE = weak_odr constant

// F<int> is an explicit template instantiation declaration without a
// key function, so its vtable should have external linkage.
// CHECK-9: @_ZTV1FIiE = external constant

// E<int> is an explicit template instantiation declaration. It has a
// key function that is not instantiated, so we should only reference
// its vtable, not define it.
// CHECK-10: @_ZTV1EIiE = external constant

// The anonymous struct for e has no linkage, so the vtable should have
// internal linkage.
// CHECK-11: @"_ZTV3$_0" = internal constant
// CHECK-11: @"_ZTS3$_0" = internal constant
// CHECK-11: @"_ZTI3$_0" = internal constant

// The A vtable should have internal linkage since it is inside an anonymous 
// namespace.
// CHECK-12: @_ZTVN12_GLOBAL__N_11AE = internal constant
// CHECK-12: @_ZTSN12_GLOBAL__N_11AE = internal constant
// CHECK-12: @_ZTIN12_GLOBAL__N_11AE = internal constant

// F<char> is an explicit specialization without a key function, so
// its vtable should have weak_odr linkage.
// CHECK-13: @_ZTV1FIcE = weak_odr constant
// CHECK-13: @_ZTS1FIcE = weak_odr constant
// CHECK-13: @_ZTI1FIcE = weak_odr constant

// RUN: FileCheck --check-prefix=CHECK-G %s < %t
//
// CHECK-G: @_ZTV1GIiE = weak_odr constant
template <typename T>
class G {
public:
  G() {}
  virtual void f0();
  virtual void f1();
};
template <>
void G<int>::f1() {}
template <typename T>
void G<T>::f0() {}
void G_f0()  { new G<int>(); }
