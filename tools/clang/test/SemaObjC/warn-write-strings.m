// RUN: %clang_cc1 -verify -fsyntax-only -Wwrite-strings %s

// PR4804
char* x = "foo"; // expected-warning {{initializing 'char *' with an expression of type 'char const [4]' discards qualifiers}}
