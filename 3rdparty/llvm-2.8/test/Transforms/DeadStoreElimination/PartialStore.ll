; RUN: opt < %s -dse -S | \
; RUN:    not grep {store i8}
; Ensure that the dead store is deleted in this case.  It is wholely
; overwritten by the second store.
target datalayout = "E-p:64:64:64-a0:0:8-f32:32:32-f64:64:64-i1:8:8-i8:8:8-i16:16:16-i32:32:32-i64:32:64-v64:64:64-v128:128:128"
define i32 @test() {
        %V = alloca i32         ; <i32*> [#uses=3]
        %V2 = bitcast i32* %V to i8*            ; <i8*> [#uses=1]
        store i8 0, i8* %V2
        store i32 1234567, i32* %V
        %X = load i32* %V               ; <i32> [#uses=1]
        ret i32 %X
}

