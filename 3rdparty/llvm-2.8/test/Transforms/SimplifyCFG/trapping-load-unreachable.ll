; RUN: opt < %s -simplifycfg -S | FileCheck %s
; PR2967

target datalayout =
"e-p:32:32:32-i1:8:8-i8:8:8-i16:16:16-i32:32:32-i64:32:64-f32:32:32"
target triple = "i386-pc-linux-gnu"

define void @test1(i32 %x) nounwind {
entry:
        %0 = icmp eq i32 %x, 0          ; <i1> [#uses=1]
        br i1 %0, label %bb, label %return

bb:             ; preds = %entry
        %1 = volatile load i32* null
        unreachable
        
        br label %return
return:         ; preds = %entry
        ret void
; CHECK: @test1
; CHECK: volatile load
}

; rdar://7958343
define void @test2() nounwind {
entry:
        store i32 4,i32* null
        ret void
        
; CHECK: @test2
; CHECK: call void @llvm.trap
; CHECK: unreachable
}

; PR7369
define void @test3() nounwind {
entry:
        volatile store i32 4, i32* null
        ret void

; CHECK: @test3
; CHECK: volatile store i32 4, i32* null
; CHECK: ret
}
