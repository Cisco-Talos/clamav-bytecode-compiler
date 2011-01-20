; Test that the StrChrOptimizer works correctly
; RUN: opt < %s -simplify-libcalls -S | \
; RUN:   not grep {call.*@strchr}

; This transformation requires the pointer size, as it assumes that size_t is
; the size of a pointer.
target datalayout = "-p:64:64:64"

@hello = constant [14 x i8] c"hello world\5Cn\00"		; <[14 x i8]*> [#uses=1]
@null = constant [1 x i8] zeroinitializer		; <[1 x i8]*> [#uses=1]

declare i8* @strchr(i8*, i32)

declare i32 @puts(i8*)

define i32 @main() {
	%hello_p = getelementptr [14 x i8]* @hello, i32 0, i32 0		; <i8*> [#uses=2]
	%null_p = getelementptr [1 x i8]* @null, i32 0, i32 0		; <i8*> [#uses=1]
	%world = call i8* @strchr( i8* %hello_p, i32 119 )		; <i8*> [#uses=1]
	%ignore = call i8* @strchr( i8* %null_p, i32 119 )		; <i8*> [#uses=0]
	%len = call i32 @puts( i8* %world )		; <i32> [#uses=1]
	%index = add i32 %len, 112		; <i32> [#uses=2]
	%result = call i8* @strchr( i8* %hello_p, i32 %index )		; <i8*> [#uses=0]
	ret i32 %index
}

