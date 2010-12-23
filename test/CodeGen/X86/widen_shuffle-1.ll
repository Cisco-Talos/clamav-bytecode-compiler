; RUN: llc < %s -march=x86 -mattr=+sse42 -disable-mmx | FileCheck %s

; widening shuffle v3float and then a add
define void @shuf(<3 x float>* %dst.addr, <3 x float> %src1,<3 x float> %src2) nounwind {
entry:
; CHECK: shuf:
; CHECK: extractps
; CHECK: extractps
	%x = shufflevector <3 x float> %src1, <3 x float> %src2, <3 x i32> < i32 0, i32 1, i32 2>
	%val = fadd <3 x float> %x, %src2
	store <3 x float> %val, <3 x float>* %dst.addr
	ret void
}


; widening shuffle v3float with a different mask and then a add
define void @shuf2(<3 x float>* %dst.addr, <3 x float> %src1,<3 x float> %src2) nounwind {
entry:
; CHECK: shuf2:
; CHECK: extractps
; CHECK: extractps
	%x = shufflevector <3 x float> %src1, <3 x float> %src2, <3 x i32> < i32 0, i32 4, i32 2>
	%val = fadd <3 x float> %x, %src2
	store <3 x float> %val, <3 x float>* %dst.addr
	ret void
}

; Example of when widening a v3float operation causes the DAG to replace a node
; with the operation that we are currently widening, i.e. when replacing
; opA with opB, the DAG will produce new operations with opA.
define void @shuf3(<4 x float> %tmp10, <4 x float> %vecinit15, <4 x float>* %dst) nounwind {
entry:
; CHECK: pshufd
  %shuffle.i.i.i12 = shufflevector <4 x float> %tmp10, <4 x float> %vecinit15, <4 x i32> <i32 0, i32 1, i32 4, i32 5>
  %tmp25.i.i = shufflevector <4 x float> %shuffle.i.i.i12, <4 x float> undef, <3 x i32> <i32 0, i32 1, i32 2> 
  %tmp1.i.i = shufflevector <3 x float> %tmp25.i.i, <3 x float> zeroinitializer, <4 x i32> <i32 0, i32 1, i32 2, i32 3>
  %tmp3.i13 = shufflevector <4 x float> %tmp1.i.i, <4 x float> undef, <3 x i32> <i32 0, i32 1, i32 2> ; <<3 x float>>
  %tmp6.i14 = shufflevector <3 x float> %tmp3.i13, <3 x float> zeroinitializer, <4 x i32> <i32 0, i32 1, i32 2, i32 3>
  %tmp97.i = shufflevector <4 x float> %tmp6.i14, <4 x float> undef, <3 x i32> <i32 0, i32 1, i32 2>
  %tmp2.i18 = shufflevector <3 x float> %tmp97.i, <3 x float> undef, <4 x i32> <i32 0, i32 1, i32 2, i32 2>
  %t5 = bitcast <4 x float> %tmp2.i18 to <4 x i32>
  %shr.i.i19 = lshr <4 x i32> %t5, <i32 19, i32 19, i32 19, i32 19>
  %and.i.i20 = and <4 x i32> %shr.i.i19, <i32 4080, i32 4080, i32 4080, i32 4080> 
  %shuffle.i.i.i21 = shufflevector <4 x float> %tmp2.i18, <4 x float> undef, <4 x i32> <i32 2, i32 3, i32 2, i32 3>
  store <4 x float> %shuffle.i.i.i21, <4 x float>* %dst
  ret void
}

