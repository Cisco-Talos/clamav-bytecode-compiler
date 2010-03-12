; RUN: opt < %s -anders-aa -gvn -S \
; RUN: | not grep {ret i32 undef}

;; From PR 2160
declare void @f(i32*)

define i32 @g() {
entry:
      %tmp = alloca i32               ; <i32*> [#uses=2]
	call void @f( i32* %tmp )
	%tmp2 = load i32* %tmp          ; <i32> [#uses=1]
	ret i32 %tmp2
}

