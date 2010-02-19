// RUN: %clang_cc1 -fsyntax-only -verify %s
@interface I1
- (void)method;
@end

@implementation I1
- (void)method {
  struct x { };
  [x method]; // expected-error{{invalid receiver to message expression}}
}
@end

typedef struct { int x; } ivar;

@interface I2 {
  id ivar;
}
- (void)method;
+ (void)method;
@end

@implementation I2
- (void)method {
  [ivar method];
}
+ (void)method {
  [ivar method]; // expected-error{{invalid receiver to message expression}}
}
@end
