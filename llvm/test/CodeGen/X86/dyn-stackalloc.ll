; RUN: llc < %s -march=x86 | not egrep {\\\$4294967289|-7}
; RUN: llc < %s -march=x86 | egrep {\\\$4294967280|-16}
; RUN: llc < %s -march=x86-64 | grep {\\-16}

define void @t() nounwind {
A:
	br label %entry

entry:
	%m1 = alloca i32, align 4
	%m2 = alloca [7 x i8], align 16
	call void @s( i32* %m1, [7 x i8]* %m2 )
	ret void
}

declare void @s(i32*, [7 x i8]*)
