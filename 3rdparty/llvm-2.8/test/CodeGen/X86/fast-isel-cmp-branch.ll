; RUN: llc -O0 -march=x86-64 -asm-verbose=false < %s | FileCheck %s
; rdar://8337108

; Fast-isel shouldn't try to look through the compare because it's in a
; different basic block, so its operands aren't necessarily exported
; for cross-block usage.

; CHECK: movb    %al, 7(%rsp)
; CHECK: callq   {{_?}}bar
; CHECK: movb    7(%rsp), %al

declare void @bar()

define void @foo(i32 %a, i32 %b) nounwind {
entry:
  %q = add i32 %a, 7
  %r = add i32 %b, 9
  %t = icmp ult i32 %q, %r
  invoke void @bar() to label %next unwind label %unw
next:
  br i1 %t, label %true, label %return
true:
  call void @bar()
  br label %return
return:
  ret void
unw:
  unreachable
}
