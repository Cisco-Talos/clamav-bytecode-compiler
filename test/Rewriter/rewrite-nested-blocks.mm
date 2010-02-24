// RUN: %clang_cc1 -x objective-c++ -Wno-return-type -fblocks -fms-extensions -rewrite-objc %s -o %t-rw.cpp
// RUN: %clang_cc1 -fsyntax-only -Wno-address-of-temporary -D"SEL=void*" -D"__declspec(X)=" %t-rw.cpp
// radar 7682149


void f(void (^block)(void));

@interface X {
	int y;
}
- (void)foo;
@end

@implementation X
- (void)foo {
    f(^{
  f(^{
    f(^{
      y=42;
    });
  });
});

}
@end

