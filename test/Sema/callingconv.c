// RUN: clang-cc %s -fsyntax-only -verify

void __attribute__((fastcall)) foo(float *a) { 
}

void __attribute__((stdcall)) bar(float *a) { 
}

void __attribute__((fastcall(1))) baz(float *a) { // expected-error {{attribute requires 0 argument(s)}}
}

void __attribute__((fastcall)) test0() { // expected-error {{function with no prototype cannot use 'fastcall' calling convention}}
}

void __attribute__((fastcall)) test1(void) {
}

void __attribute__((fastcall)) test2(int a, ...) { // expected-error {{variadic function cannot use 'fastcall' calling convention}}
}
