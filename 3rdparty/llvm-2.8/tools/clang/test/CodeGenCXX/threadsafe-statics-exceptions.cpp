// RUN: %clang_cc1 -emit-llvm -o - -fexceptions -triple x86_64-apple-darwin10 %s | FileCheck %s

struct X {
  X();
  ~X();
};

struct Y { };

// CHECK: define void @_Z1fv
void f() {
  // CHECK: call i32 @__cxa_guard_acquire(i64* @_ZGVZ1fvE1x)
  // CHECK: invoke void @_ZN1XC1Ev
  // CHECK: call void @__cxa_guard_release(i64* @_ZGVZ1fvE1x)
  // CHECK-NEXT: call i32 @__cxa_atexit
  // CHECK: br
  static X x;

  // CHECK: call i8* @__cxa_allocate_exception
  // CHECK: call void @__cxa_throw
  throw Y();

  // Finally, the landing pad.
  // CHECK: call i8* @llvm.eh.exception()
  // CHECK: call i32 (i8*, i8*, ...)* @llvm.eh.selector
  // CHECK: call void @__cxa_guard_abort(i64* @_ZGVZ1fvE1x)
  // CHECK: call void @_Unwind_Resume_or_Rethrow
  // CHECK: unreachable
}
