// RUN: clang-cc %s -verify -fsyntax-only
class A {
  void f() __attribute__((deprecated));
  void g(A* a);
  void h(A* a) __attribute__((deprecated));

  int b __attribute__((deprecated));
};

void A::g(A* a)
{
  f(); // expected-warning{{'f' is deprecated}}
  a->f(); // expected-warning{{'f' is deprecated}}
  
  (void)b; // expected-warning{{'b' is deprecated}}
  (void)a->b; // expected-warning{{'b' is deprecated}}
}

void A::h(A* a)
{
  f();
  a->f();
  
  (void)b;
  (void)a->b;
}

struct B {
  virtual void f() __attribute__((deprecated));
};

struct C : B {
  virtual void f();
};

void f(B* b, C *c) {
  b->f();
  b->B::f(); // expected-warning{{'f' is deprecated}}
  
  c->f();
  c->C::f();
  c->B::f(); // expected-warning{{'f' is deprecated}}
}
