// RUN: %clang_cc1 -fsyntax-only -verify %s
namespace N {
  struct A {
    typedef int type;
  };

  struct B {
  };

  struct C {
    struct type { };
    int type; // expected-note 2{{referenced member 'type' is declared here}}
  };
}

int i;

typename N::A::type *ip1 = &i; // expected-warning{{'typename' occurs outside of a template}}
typename N::B::type *ip2 = &i; // expected-error{{no type named 'type' in 'N::B'}} \
// expected-warning{{'typename' occurs outside of a template}}
typename N::C::type *ip3 = &i; // expected-error{{typename specifier refers to non-type member 'type'}} \
// expected-warning{{'typename' occurs outside of a template}}

void test(double d) {
  typename N::A::type f(typename N::A::type(a)); // expected-warning{{parentheses were disambiguated as a function declarator}} \
  // expected-warning 2{{'typename' occurs outside of a template}}
  int five = f(5);
  
  using namespace N;
  for (typename A::type i = 0; i < 10; ++i) // expected-warning{{'typename' occurs outside of a template}}
    five += 1;

  const typename N::A::type f2(d); // expected-warning{{'typename' occurs outside of a template}}
}

namespace N {
  template<typename T>
  struct X {
    typedef typename T::type type; // expected-error {{no type named 'type' in 'N::B'}} \
    // expected-error {{no type named 'type' in 'B'}} \
    // FIXME: location info for error above isn't very good \
    // expected-error 2{{typename specifier refers to non-type member 'type'}} \
    // expected-error{{type 'int' cannot be used prior to '::' because it has no members}}
  };
}

N::X<N::A>::type *ip4 = &i;
N::X<N::B>::type *ip5 = &i; // expected-note{{in instantiation of template class 'N::X<N::B>' requested here}}
N::X<N::C>::type *ip6 = &i; // expected-note{{in instantiation of template class 'N::X<N::C>' requested here}}

N::X<int>::type fail1; // expected-note{{in instantiation of template class 'N::X<int>' requested here}}

template<typename T>
struct Y {
  typedef typename N::X<T>::type *type; // expected-note{{in instantiation of template class 'N::X<B>' requested here}} \
  // expected-note{{in instantiation of template class 'N::X<C>' requested here}}
};

struct A {
  typedef int type;
};

struct B {
};

struct C {
  struct type { };
  int type; // expected-note{{referenced member 'type' is declared here}}
};

::Y<A>::type ip7 = &i;
::Y<B>::type ip8 = &i; // expected-note{{in instantiation of template class 'Y<B>' requested here}}
::Y<C>::type ip9 = &i; // expected-note{{in instantiation of template class 'Y<C>' requested here}}
