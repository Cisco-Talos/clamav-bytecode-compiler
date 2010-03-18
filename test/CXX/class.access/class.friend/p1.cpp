// RUN: %clang_cc1 -fsyntax-only -faccess-control -verify %s

// C++'0x [class.friend] p1:
//   A friend of a class is a function or class that is given permission to use
//   the private and protected member names from the class. A class specifies
//   its friends, if any, by way of friend declarations. Such declarations give
//   special access rights to the friends, but they do not make the nominated
//   friends members of the befriending class.
//
// FIXME: Add tests for access control when implemented. Currently we only test
// for parsing.

struct S { static void f(); };
S* g() { return 0; }

struct X {
  friend struct S;
  friend S* g();
};

void test1() {
  S s;
  g()->f();
  S::f();
  X::g(); // expected-error{{no member named 'g' in 'X'}}
  X::S x_s; // expected-error{{no member named 'S' in 'X'}}
  X x;
  x.g(); // expected-error{{no member named 'g' in 'X'}}
}

// Test that we recurse through namespaces to find already declared names, but
// new names are declared within the enclosing namespace.
namespace N {
  struct X {
    friend struct S;
    friend S* g();

    friend struct S2;
    friend struct S2* g2();
  };

  struct S2 { static void f2(); };
  S2* g2() { return 0; }

  void test() {
    g()->f();
    S s;
    S::f();
    X::g(); // expected-error{{no member named 'g' in 'N::X'}}
    X::S x_s; // expected-error{{no member named 'S' in 'N::X'}}
    X x;
    x.g(); // expected-error{{no member named 'g' in 'N::X'}}

    g2();
    S2 s2;
    ::g2(); // expected-error{{no member named 'g2' in the global namespace}}
    ::S2 g_s2; // expected-error{{no member named 'S2' in the global namespace}}
    X::g2(); // expected-error{{no member named 'g2' in 'N::X'}}
    X::S2 x_s2; // expected-error{{no member named 'S2' in 'N::X'}}
    x.g2(); // expected-error{{no member named 'g2' in 'N::X'}}
  }
}

namespace test0 {
  class ClassFriend {
    void test();
  };

  class MemberFriend {
    void test();
  };

  void declared_test();

  class Class {
    static void member(); // expected-note 2 {{declared private here}}

    friend class ClassFriend;
    friend class UndeclaredClassFriend;

    friend void undeclared_test();
    friend void declared_test();
    friend void MemberFriend::test();
  };

  void declared_test() {
    Class::member();
  }

  void undeclared_test() {
    Class::member();
  }

  void unfriended_test() {
    Class::member(); // expected-error {{'member' is a private member of 'test0::Class'}}
  }

  void ClassFriend::test() {
    Class::member();
  }

  void MemberFriend::test() {
    Class::member();
  }

  class UndeclaredClassFriend {
    void test() {
      Class::member();
    }
  };

  class ClassNonFriend {
    void test() {
      Class::member(); // expected-error {{'member' is a private member of 'test0::Class'}}
    }
  };
}

// Make sure that friends have access to inherited protected members.
namespace test2 {
  struct X;

  class ilist_half_node {
    friend struct ilist_walker_bad;
    X *Prev;
  protected:
    X *getPrev() { return Prev; }
  };

  class ilist_node : private ilist_half_node { // expected-note {{declared private here}} expected-note {{constrained by private inheritance here}}
    friend struct ilist_walker;
    X *Next;
    X *getNext() { return Next; } // expected-note {{declared private here}}
  };

  struct X : ilist_node {};

  struct ilist_walker {
    static X *getPrev(X *N) { return N->getPrev(); }
    static X *getNext(X *N) { return N->getNext(); }
  };  

  struct ilist_walker_bad {
    static X *getPrev(X *N) { return N->getPrev(); } // \
    // expected-error {{'getPrev' is a private member of 'test2::ilist_half_node'}} \
    // expected-error {{cannot cast 'test2::X' to its private base class 'test2::ilist_half_node'}}

    static X *getNext(X *N) { return N->getNext(); } // \
    // expected-error {{'getNext' is a private member of 'test2::ilist_node'}}
  };  
}
