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
- (void) Meth : (I*) Arg;
@end

void Func (I* arg);  // expected-note {{candidate function not viable: no known conversion from 'I const *' to 'I *' for 1st argument}}

void foo(const I *p, I* sel) {
  [sel Meth : p];	// expected-error {{incompatible type sending 'I const *', expected 'I *'}}
  Func(p);		// expected-error {{no matching function for call to 'Func'}}
}

