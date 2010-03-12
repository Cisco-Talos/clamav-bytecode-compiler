; RUN: llc < %s -march=cellspu | FileCheck %s

; ModuleID = 'loads.bc'
target datalayout = "E-p:32:32:128-f64:64:128-f32:32:128-i64:32:128-i32:32:128-i16:16:128-i8:8:128-i1:8:128-a0:0:128-v128:128:128-s0:128:128"
target triple = "spu"

define <4 x float> @load_v4f32_1(<4 x float>* %a) nounwind readonly {
entry:
	%tmp1 = load <4 x float>* %a
	ret <4 x float> %tmp1
; CHECK:	lqd	$3, 0($3)
}

define <4 x float> @load_v4f32_2(<4 x float>* %a) nounwind readonly {
entry:
	%arrayidx = getelementptr <4 x float>* %a, i32 1
	%tmp1 = load <4 x float>* %arrayidx
	ret <4 x float> %tmp1
; CHECK:	lqd	$3, 16($3)
}
