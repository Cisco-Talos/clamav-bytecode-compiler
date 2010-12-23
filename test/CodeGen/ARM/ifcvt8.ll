; RUN: llc < %s -march=arm -mtriple=arm-apple-darwin | \
; RUN:   grep ldmiane | count 1

	%struct.SString = type { i8*, i32, i32 }

declare void @abort()

define fastcc void @t(%struct.SString* %word, i8 signext  %c) {
entry:
	%tmp1 = icmp eq %struct.SString* %word, null		; <i1> [#uses=1]
	br i1 %tmp1, label %cond_true, label %cond_false

cond_true:		; preds = %entry
	tail call void @abort( )
	unreachable

cond_false:		; preds = %entry
	ret void
}
