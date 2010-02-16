// RUN: %clang_cc1 -fsyntax-only -verify %s

class X {};

void test() {
  X x;

  x.int; // expected-error{{expected unqualified-id}}
  x.~int(); // expected-error{{expected a class name}}
  x.operator; // expected-error{{missing type specifier after 'operator'}}
  x.operator typedef; // expected-error{{missing type specifier after 'operator'}}
}

void test2() {
  X *x;

  x->int; // expected-error{{expected unqualified-id}}
  x->~int(); // expected-error{{expected a class name}}
  x->operator; // expected-error{{missing type specifier after 'operator'}}
  x->operator typedef; // expected-error{{missing type specifier after 'operator'}}
}
