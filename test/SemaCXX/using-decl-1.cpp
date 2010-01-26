// RUN: %clang_cc1 -fsyntax-only -verify %s

extern "C" { void f(bool); }

namespace std {
  using ::f;
  inline void f() { return f(true); }
}

namespace M {
  void f(float);
}

namespace N {
  using M::f;
  void f(int) { } // expected-note{{previous}}
  
  void f(int) { } // expected-error{{redefinition}}
}

namespace N {
  void f(double);
  void f(long);
}

struct X0 {
  void operator()(int);
  void operator()(long);
};

struct X1 : X0 {
  // FIXME: give this operator() a 'float' parameter to test overloading
  // behavior. It currently fails.
  void operator()();
  using X0::operator();
  
  void test() {
    (*this)(1);
  }
};

struct A { void f(); };
struct B : A { };
class C : B { using B::f; };

// PR5751: Resolve overloaded functions through using decls.
namespace O {
  void f(int i);
  void f(double d);
}
namespace P {
  void f();
  void g(void (*ptr)(int));
  using O::f;
  void test() {
    f();
    f(1);
    void (*f_ptr1)(double) = f;
    void (*f_ptr2)() = f;
    g(f);
  }
}

// Make sure that ADL can find names brought in by using decls.
namespace test0 {
  namespace ns {
    class Foo {};
    
    namespace inner {
      void foo(char *); // expected-note {{no known conversion}} 
    }

    using inner::foo;
  }

  void test(ns::Foo *p) {
    foo(*p); // expected-error {{no matching function for call to 'foo'}}
  }
}

// Redeclarations!
namespace test1 {
  namespace ns0 { struct Foo {}; }
  namespace A { void foo(ns0::Foo *p, int y, int z); }
  namespace ns2 { using A::foo; }
  namespace ns1 { struct Bar : ns0::Foo {}; }
  namespace A { void foo(ns0::Foo *p, int y, int z = 0); } // expected-note {{candidate}}
  namespace ns1 { using A::foo; }
  namespace ns2 { struct Baz : ns1::Bar {}; }
  namespace A { void foo(ns0::Foo *p, int y = 0, int z); }

  void test(ns2::Baz *p) {
    foo(p, 0, 0); // okay!
    foo(p, 0); // should be fine!
    foo(p); // expected-error {{no matching function}}
  }
}
