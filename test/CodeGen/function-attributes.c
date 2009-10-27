// RUN: clang-cc -triple i386-unknown-unknown -emit-llvm -o - %s | FileCheck %s
// CHECK: define signext i8 @f0(i32 %x) nounwind
// CHECK: define zeroext i8 @f1(i32 %x) nounwind
// CHECK: define void @f2(i8 signext %x) nounwind
// CHECK: define void @f3(i8 zeroext %x) nounwind
// CHECK: define signext i16 @f4(i32 %x) nounwind
// CHECK: define zeroext i16 @f5(i32 %x) nounwind
// CHECK: define void @f6(i16 signext %x) nounwind
// CHECK: define void @f7(i16 zeroext %x) nounwind

signed char f0(int x) { return x; }

unsigned char f1(int x) { return x; }

void f2(signed char x) { }

void f3(unsigned char x) { }

signed short f4(int x) { return x; }

unsigned short f5(int x) { return x; }

void f6(signed short x) { }

void f7(unsigned short x) { }

// CHECK: define void @f8() nounwind alwaysinline
void __attribute__((always_inline)) f8(void) { }

// CHECK: call void @f9_t() noreturn
void __attribute__((noreturn)) f9_t(void);
void f9(void) { f9_t(); }

// FIXME: We should be setting nounwind on calls.
// CHECK: call i32 @f10_t() readnone
int __attribute__((const)) f10_t(void);
int f10(void) { return f10_t(); }
int f11(void) {
 exit:
  return f10_t();
}
int f12(int arg) {
  return arg ? 0 : f10_t();
}

// CHECK: define void @f13() nounwind readnone
void f13(void) __attribute__((pure)) __attribute__((const));
void f13(void){}


// Ensure that these get inlined: rdar://6853279
// CHECK: define i32 @f14
// CHECK-NOT: @ai_
// CHECK: ret i32
static __inline__ __attribute__((always_inline))
int ai_1() {  return 4; }

static __inline__ __attribute__((always_inline))
struct {
  int a, b, c, d, e;
} ai_2() { while (1) {} }

int f14() {
  ai_2();
  return ai_1();
}
