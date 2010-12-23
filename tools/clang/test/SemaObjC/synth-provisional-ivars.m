// RUN: %clang_cc1 -fsyntax-only -fobjc-nonfragile-abi2 -verify %s

int bar;

@interface I
{
    int _bar;
}
@property int PROP;
@property int PROP1;
@property int PROP2;
@property int PROP3;
@property int PROP4;

@property int bar;
@property int bar1;

@end

@implementation I
- (int) Meth { return PROP; }	// expected-note {{'PROP' declared here}}

@dynamic PROP1;
- (int) Meth1 { return PROP1; }  // expected-error {{use of undeclared identifier 'PROP1'}}

- (int) Meth2 { return PROP2; }  // expected-error {{use of undeclared identifier 'PROP2'}}
@dynamic PROP2;

- (int) Meth3 { return PROP3; }  // expected-error {{use of undeclared identifier 'PROP3'}}
@synthesize PROP3=IVAR;

- (int) Meth4 { return PROP4; }
@synthesize PROP4=PROP4;

- (int) Meth5 { return bar; }  // expected-error {{use of undeclared identifier 'bar'}}
@synthesize bar = _bar;

- (int) Meth6 { return bar1; }

@end

@implementation I(CAT)
- (int) Meth { return PROP1; }  // expected-error {{use of undeclared identifier 'PROP1'}}
@end

@implementation I(r8251648)
- (int) Meth1: (int) bar {
  return bar; // expected-warning {{local declaration of 'bar' hides instance variable}}
}
@end
