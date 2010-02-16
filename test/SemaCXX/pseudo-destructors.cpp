// RUN: %clang_cc1 -fsyntax-only -verify %s
struct A {};

enum Foo { F };
typedef Foo Bar;

typedef int Integer;

void g();

namespace N {
  typedef Foo Wibble;
}

void f(A* a, Foo *f, int *i) {
  a->~A();
  a->A::~A();
  
  a->~foo(); // expected-error{{identifier 'foo' in pseudo-destructor expression does not name a type}}
  
  // FIXME: the diagnostic below isn't wonderful
  a->~Bar(); // expected-error{{does not name a type}}
  
  f->~Bar();
  f->~Foo();
  i->~Bar(); // expected-error{{does not match}}
  
  g().~Bar(); // expected-error{{non-scalar}}
  
  f->::~Bar();
  f->N::~Wibble(); // expected-error{{expected the class name after '~' to name a destructor}}
  
  f->::~Bar(17, 42); // expected-error{{cannot have any arguments}}
}

typedef int Integer;

void destroy_without_call(int *ip) {
  ip->~Integer; // expected-error{{called immediately}}
}

// PR5530
namespace N1 {
  class X0 { };
}

void test_X0(N1::X0 &x0) {
  x0.~X0();
}
