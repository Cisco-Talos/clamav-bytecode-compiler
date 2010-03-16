// RUN: %clang_cc1 -verify -fsyntax-only -Wshadow %s

namespace {
  int i; // expected-note {{previous declaration is here}}
}

namespace one {
namespace two {
  int j; // expected-note {{previous declaration is here}}
}
}

namespace xx {
  int m;
}
namespace yy {
  int m;
}

using namespace one::two;
using namespace xx;
using namespace yy;

void foo() {
  int i; // expected-warning {{declaration shadows a variable in namespace '<anonymous>'}}
  int j; // expected-warning {{declaration shadows a variable in namespace 'one::two'}}
  int m;
}

class A {
  static int data; // expected-note {{previous declaration}}
  int field; // expected-note {{previous declaration}}

  void test() {
    char *field; // expected-warning {{declaration shadows a field of 'A'}}
    char *data; // expected-warning {{declaration shadows a static data member of 'A'}}
  }
};
