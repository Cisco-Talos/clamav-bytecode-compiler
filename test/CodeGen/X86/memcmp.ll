; RUN: llc %s -o - -march=x86-64 | FileCheck %s

; This tests codegen time inlining/optimization of memcmp
; rdar://6480398

@.str = private constant [6 x i8] c"fooxx\00", align 1 ; <[6 x i8]*> [#uses=1]

declare i32 @memcmp(...)

define void @memcmp2(i8* %X, i8* %Y, i32* nocapture %P) nounwind {
entry:
  %0 = tail call i32 (...)* @memcmp(i8* %X, i8* %Y, i32 2) nounwind ; <i32> [#uses=1]
  %1 = icmp eq i32 %0, 0                          ; <i1> [#uses=1]
  br i1 %1, label %return, label %bb

bb:                                               ; preds = %entry
  store i32 4, i32* %P, align 4
  ret void

return:                                           ; preds = %entry
  ret void
; CHECK: memcmp2:
; CHECK: movw    (%rsi), %ax
; CHECK: cmpw    %ax, (%rdi)
}

define void @memcmp2a(i8* %X, i32* nocapture %P) nounwind {
entry:
  %0 = tail call i32 (...)* @memcmp(i8* %X, i8* getelementptr inbounds ([6 x i8]* @.str, i32 0, i32 1), i32 2) nounwind ; <i32> [#uses=1]
  %1 = icmp eq i32 %0, 0                          ; <i1> [#uses=1]
  br i1 %1, label %return, label %bb

bb:                                               ; preds = %entry
  store i32 4, i32* %P, align 4
  ret void

return:                                           ; preds = %entry
  ret void
; CHECK: memcmp2a:
; CHECK: cmpw    $28527, (%rdi)
}


define void @memcmp4(i8* %X, i8* %Y, i32* nocapture %P) nounwind {
entry:
  %0 = tail call i32 (...)* @memcmp(i8* %X, i8* %Y, i32 4) nounwind ; <i32> [#uses=1]
  %1 = icmp eq i32 %0, 0                          ; <i1> [#uses=1]
  br i1 %1, label %return, label %bb

bb:                                               ; preds = %entry
  store i32 4, i32* %P, align 4
  ret void

return:                                           ; preds = %entry
  ret void
; CHECK: memcmp4:
; CHECK: movl    (%rsi), %eax
; CHECK: cmpl    %eax, (%rdi)
}

define void @memcmp4a(i8* %X, i32* nocapture %P) nounwind {
entry:
  %0 = tail call i32 (...)* @memcmp(i8* %X, i8* getelementptr inbounds ([6 x i8]* @.str, i32 0, i32 1), i32 4) nounwind ; <i32> [#uses=1]
  %1 = icmp eq i32 %0, 0                          ; <i1> [#uses=1]
  br i1 %1, label %return, label %bb

bb:                                               ; preds = %entry
  store i32 4, i32* %P, align 4
  ret void

return:                                           ; preds = %entry
  ret void
; CHECK: memcmp4a:
; CHECK: cmpl $2021158767, (%rdi)
}

