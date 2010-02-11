// RUN: %clang_cc1 -triple i386-apple-darwin10 -fsyntax-only -verify %s

int a __attribute__((force_align_arg_pointer)); // expected-warning{{attribute only applies to function types}}

// It doesn't matter where the attribute is located.
void b(void) __attribute__((force_align_arg_pointer));
void __attribute__((force_align_arg_pointer)) c(void);

// Functions only have to be declared force_align_arg_pointer once.
void b(void) {}

// It doesn't matter which declaration has the attribute.
void d(void);
void __attribute__((force_align_arg_pointer)) d(void) {}

// Attribute is ignored on function pointer types.
void (__attribute__((force_align_arg_pointer)) *p)(); //expected-warning{{force_align_arg_pointer used on function pointer; attribute ignored}}

