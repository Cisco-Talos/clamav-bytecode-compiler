; RUN: llc -march=x86 %s -o -
; RUN: llc -march=x86-64 %s -o -

; PR6497

; Chain and flag folding issues.
define i32 @test1() nounwind ssp {
entry:
  %tmp5.i = volatile load i32* undef              ; <i32> [#uses=1]
  %conv.i = zext i32 %tmp5.i to i64               ; <i64> [#uses=1]
  %tmp12.i = volatile load i32* undef             ; <i32> [#uses=1]
  %conv13.i = zext i32 %tmp12.i to i64            ; <i64> [#uses=1]
  %shl.i = shl i64 %conv13.i, 32                  ; <i64> [#uses=1]
  %or.i = or i64 %shl.i, %conv.i                  ; <i64> [#uses=1]
  %add16.i = add i64 %or.i, 256                   ; <i64> [#uses=1]
  %shr.i = lshr i64 %add16.i, 8                   ; <i64> [#uses=1]
  %conv19.i = trunc i64 %shr.i to i32             ; <i32> [#uses=1]
  volatile store i32 %conv19.i, i32* undef
  ret i32 undef
}
