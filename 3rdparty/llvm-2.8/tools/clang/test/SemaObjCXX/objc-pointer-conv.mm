// RUN: %clang_cc1 -fsyntax-only -verify %s

typedef const void * VoidStar;

typedef struct __CFDictionary * CFMDRef;

void RandomFunc(CFMDRef theDict, const void *key, const void *value);

@interface Foo
- (void)_apply:(void (*)(const void *, const void *, void *))func context:(void *)context;
- (void)a:(id *)objects b:(id *)keys;
@end

@implementation Foo
- (void)_apply:(void (*)(const void *, const void *, void *))func context:(void *)context {
	id item;
	id obj;
    func(item, obj, context);
}

- (void)a:(id *)objects b:(id *)keys {
    VoidStar dict;
	id key;
    RandomFunc((CFMDRef)dict, key, objects[3]);
}
@end

@interface I
- (void) Meth : (I*) Arg; // expected-note{{passing argument to parameter 'Arg' here}}
@end

void Func (I* arg);  // expected-note {{candidate function not viable: no known conversion from 'I const *' to 'I *' for 1st argument}}

void foo(const I *p, I* sel) {
  [sel Meth : p];	// expected-error {{cannot initialize a parameter of type 'I *' with an lvalue of type 'I const *'}}
  Func(p);		// expected-error {{no matching function for call to 'Func'}}
}

@interface DerivedFromI : I
@end

void accept_derived(DerivedFromI*); // expected-note{{candidate function not viable: cannot convert from superclass 'I *' to subclass 'DerivedFromI *' for 1st argument}}

void test_base_to_derived(I* i) {
  accept_derived(i); // expected-error{{no matching function for call to 'accept_derived'}}
}
