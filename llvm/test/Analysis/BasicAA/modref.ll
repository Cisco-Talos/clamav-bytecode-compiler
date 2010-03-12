; RUN: opt < %s -basicaa -gvn -dse -S | FileCheck %s
target datalayout = "E-p:64:64:64-a0:0:8-f32:32:32-f64:64:64-i1:8:8-i8:8:8-i16:16:16-i32:32:32-i64:32:64-v64:64:64-v128:128:128"

declare void @llvm.memset.i32(i8*, i8, i32, i32)
declare void @llvm.memset.i8(i8*, i8, i8, i32)
declare void @llvm.memcpy.i8(i8*, i8*, i8, i32)
declare void @llvm.memcpy.i32(i8*, i8*, i32, i32)
declare void @llvm.lifetime.end(i64, i8* nocapture)

declare void @external(i32*) 

define i32 @test0(i8* %P) {
  %A = alloca i32
  call void @external(i32* %A)
  
  store i32 0, i32* %A
  
  call void @llvm.memset.i32(i8* %P, i8 0, i32 42, i32 1)
  
  %B = load i32* %A
  ret i32 %B
  
; CHECK: @test0
; CHECK: ret i32 0
}

declare void @llvm.memcpy.i8(i8*, i8*, i8, i32)

define i8 @test1() {
; CHECK: @test1
  %A = alloca i8
  %B = alloca i8

  store i8 2, i8* %B  ;; Not written to by memcpy

  call void @llvm.memcpy.i8(i8* %A, i8* %B, i8 -1, i32 0)

  %C = load i8* %B
  ret i8 %C
; CHECK: ret i8 2
}

define i8 @test2(i8* %P) {
; CHECK: @test2
  %P2 = getelementptr i8* %P, i32 127
  store i8 1, i8* %P2  ;; Not dead across memset
  call void @llvm.memset.i8(i8* %P, i8 2, i8 127, i32 0)
  %A = load i8* %P2
  ret i8 %A
; CHECK: ret i8 1
}

define i8 @test2a(i8* %P) {
; CHECK: @test2
  %P2 = getelementptr i8* %P, i32 126
  
  ;; FIXME: DSE isn't zapping this dead store.
  store i8 1, i8* %P2  ;; Dead, clobbered by memset.
  
  call void @llvm.memset.i8(i8* %P, i8 2, i8 127, i32 0)
  %A = load i8* %P2
  ret i8 %A
; CHECK-NOT: load
; CHECK: ret i8 2
}

define void @test3(i8* %P, i8 %X) {
; CHECK: @test3
; CHECK-NOT: store
; CHECK-NOT: %Y
  %Y = add i8 %X, 1     ;; Dead, because the only use (the store) is dead.
  
  %P2 = getelementptr i8* %P, i32 2
  store i8 %Y, i8* %P2  ;; Not read by lifetime.end, should be removed.
; CHECK: store i8 2, i8* %P2
  call void @llvm.lifetime.end(i64 1, i8* %P)
  store i8 2, i8* %P2
; CHECK-NOT: store
  ret void
; CHECK: ret void
}

define void @test3a(i8* %P, i8 %X) {
; CHECK: @test3a
  %Y = add i8 %X, 1     ;; Dead, because the only use (the store) is dead.
  
  %P2 = getelementptr i8* %P, i32 2
  store i8 %Y, i8* %P2  ;; FIXME: Killed by llvm.lifetime.end, should be zapped.
; CHECK: store i8 %Y, i8* %P2
  call void @llvm.lifetime.end(i64 10, i8* %P)
  ret void
; CHECK: ret void
}

@G1 = external global i32
@G2 = external global [4000 x i32]

define i32 @test4(i8* %P) {
  %tmp = load i32* @G1
  call void @llvm.memset.i32(i8* bitcast ([4000 x i32]* @G2 to i8*), i8 0, i32 4000, i32 1)
  %tmp2 = load i32* @G1
  %sub = sub i32 %tmp2, %tmp
  ret i32 %sub
; CHECK: @test4
; CHECK: load i32* @G
; CHECK: memset.i32
; CHECK-NOT: load
; CHECK: sub i32 %tmp, %tmp
}

; Verify that basicaa is handling variable length memcpy, knowing it doesn't
; write to G1.
define i32 @test5(i8* %P, i32 %Len) {
  %tmp = load i32* @G1
  call void @llvm.memcpy.i32(i8* bitcast ([4000 x i32]* @G2 to i8*), i8* bitcast (i32* @G1 to i8*), i32 %Len, i32 1)
  %tmp2 = load i32* @G1
  %sub = sub i32 %tmp2, %tmp
  ret i32 %sub
; CHECK: @test5
; CHECK: load i32* @G
; CHECK: memcpy.i32
; CHECK-NOT: load
; CHECK: sub i32 %tmp, %tmp
}

