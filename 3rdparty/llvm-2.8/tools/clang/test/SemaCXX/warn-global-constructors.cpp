// RUN: %clang_cc1 -fsyntax-only -Wglobal-constructors %s -verify

int opaque_int();

namespace test0 {
  // These should never require global constructors.
  int a;
  int b = 20;
  float c = 5.0f;

  // This global constructor is avoidable based on initialization order.
  int d = b; // expected-warning {{global constructor}}

  // These global constructors are unavoidable.
  int e = opaque_int(); // expected-warning {{global constructor}}
  int f = b; // expected-warning {{global constructor}}
}

namespace test1 {
  struct A { int x; };
  A a;
  A b = A();
  A c = { 10 };
  A d = { opaque_int() }; // expected-warning {{global constructor}}
  A e = A(A());
  A f = A(a); // expected-warning {{global constructor}}
  A g(a); // expected-warning {{global constructor}}
  A h((A())); // expected-warning {{global constructor}}
  A i((A(A()))); // expected-warning {{global constructor}}
}

namespace test2 {
  struct A { A(); };
  A a; // expected-warning {{global constructor}}
  A b[10]; // expected-warning {{global constructor}}
  A c[10][10]; // expected-warning {{global constructor}}

  A &d = a;
  A &e = b[5];
  A &f = c[5][7];
}

namespace test3 {
  struct A { ~A(); };
  A a; // expected-warning {{global destructor}}
  A b[10]; // expected-warning {{global destructor}}
  A c[10][10]; // expected-warning {{global destructor}}

  A &d = a;
  A &e = b[5];
  A &f = c[5][7];
}

namespace test4 {
  char a[] = "hello";
  char b[5] = "hello";
  char c[][5] = { "hello" };
}

namespace test5 {
  struct A { A(); };

  void f1() {
    static A a;
  }
  void f2() {
    static A& a = *new A;
  }
}

namespace test6 {
  struct A { ~A(); };

  void f1() {
    static A a; // expected-warning {{global destructor}}
  }
  void f2() {
    static A& a = *new A;
  }

}