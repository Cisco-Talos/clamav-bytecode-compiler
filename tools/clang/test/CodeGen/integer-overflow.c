// RUN: %clang_cc1 %s -emit-llvm -o - | FileCheck %s --check-prefix=DEFAULT
// RUN: %clang_cc1 %s -emit-llvm -o - -fwrapv | FileCheck %s --check-prefix=WRAPV
// RUN: %clang_cc1 %s -emit-llvm -o - -ftrapv | FileCheck %s --check-prefix=TRAPV


// Tests for signed integer overflow stuff.
// rdar://7432000 rdar://7221421
void test1() {
  // DEFAULT: define void @test1
  // WRAPV: define void @test1
  // TRAPV: define void @test1
  extern volatile int f11G, a, b;
  
  // DEFAULT: add nsw i32
  // WRAPV: add i32
  // TRAPV: llvm.sadd.with.overflow.i32
  f11G = a + b;
  
  // DEFAULT: sub nsw i32
  // WRAPV: sub i32
  // TRAPV: llvm.ssub.with.overflow.i32
  f11G = a - b;
  
  // DEFAULT: mul nsw i32
  // WRAPV: mul i32
  // TRAPV: llvm.smul.with.overflow.i32
  f11G = a * b;

  // DEFAULT: sub nsw i32 0, 
  // WRAPV: sub i32 0, 
  // TRAPV: llvm.ssub.with.overflow.i32(i32 0
  f11G = -a;
  
  // PR7426 - Overflow checking for increments.
  
  // DEFAULT: add nsw i32 {{.*}}, 1
  // WRAPV: add i32 {{.*}}, 1
  // TRAPV: llvm.sadd.with.overflow.i32({{.*}}, i32 1)
  ++a;
  
  // DEFAULT: add nsw i32 {{.*}}, -1
  // WRAPV: add i32 {{.*}}, -1
  // TRAPV: llvm.sadd.with.overflow.i32({{.*}}, i32 -1)
  --a;
}
