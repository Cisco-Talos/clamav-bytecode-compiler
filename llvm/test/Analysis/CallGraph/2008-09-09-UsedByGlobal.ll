; RUN: opt < %s -print-callgraph -disable-output |& \
; RUN:   grep {Calls function}

@a = global void ()* @f		; <void ()**> [#uses=0]

define internal void @f() {
	unreachable
}
