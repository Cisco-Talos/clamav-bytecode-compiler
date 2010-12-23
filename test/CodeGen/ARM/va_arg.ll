; RUN: llc < %s -mtriple=armv7-none-linux-gnueabi | FileCheck %s
; Test that we correctly align elements when using va_arg

; CHECK: test1:
; CHECK-NOT: bfc
; CHECK: add	r0, r0, #7
; CHECK: bfc	r0, #0, #3
; CHECK-NOT: bfc

define i64 @test1(i32 %i, ...) nounwind optsize {
entry:
  %g = alloca i8*, align 4
  %g1 = bitcast i8** %g to i8*
  call void @llvm.va_start(i8* %g1)
  %0 = va_arg i8** %g, i64
  call void @llvm.va_end(i8* %g1)
  ret i64 %0
}

; CHECK: test2:
; CHECK-NOT: bfc
; CHECK: add	r0, r0, #7
; CHECK: bfc	r0, #0, #3
; CHECK-NOT:	bfc
; CHECK: bx	lr

define double @test2(i32 %a, i32 %b, ...) nounwind optsize {
entry:
  %ap = alloca i8*, align 4                       ; <i8**> [#uses=3]
  %ap1 = bitcast i8** %ap to i8*                  ; <i8*> [#uses=2]
  call void @llvm.va_start(i8* %ap1)
  %0 = va_arg i8** %ap, i32                       ; <i32> [#uses=0]
  %1 = va_arg i8** %ap, double                    ; <double> [#uses=1]
  call void @llvm.va_end(i8* %ap1)
  ret double %1
}


declare void @llvm.va_start(i8*) nounwind

declare void @llvm.va_end(i8*) nounwind
