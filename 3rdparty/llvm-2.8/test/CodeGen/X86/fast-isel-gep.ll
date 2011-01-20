; RUN: llc < %s -march=x86-64 -O0 | FileCheck %s --check-prefix=X64
; RUN: llc < %s -march=x86 -O0 | FileCheck %s --check-prefix=X32

; GEP indices are interpreted as signed integers, so they
; should be sign-extended to 64 bits on 64-bit targets.
; PR3181
define i32 @test1(i32 %t3, i32* %t1) nounwind {
       %t9 = getelementptr i32* %t1, i32 %t3           ; <i32*> [#uses=1]
       %t15 = load i32* %t9            ; <i32> [#uses=1]
       ret i32 %t15
; X32: test1:
; X32:  	movl	(%eax,%ecx,4), %eax
; X32:  	ret

; X64: test1:
; X64:  	movslq	%edi, %rax
; X64:  	movl	(%rsi,%rax,4), %eax
; X64:  	ret

}
define i32 @test2(i64 %t3, i32* %t1) nounwind {
       %t9 = getelementptr i32* %t1, i64 %t3           ; <i32*> [#uses=1]
       %t15 = load i32* %t9            ; <i32> [#uses=1]
       ret i32 %t15
; X32: test2:
; X32:  	movl	(%edx,%ecx,4), %eax
; X32:  	ret

; X64: test2:
; X64:  	movl	(%rsi,%rdi,4), %eax
; X64:  	ret
}



; PR4984
define i8 @test3(i8* %start) nounwind {
entry:
  %A = getelementptr i8* %start, i64 -2               ; <i8*> [#uses=1]
  %B = load i8* %A, align 1                       ; <i8> [#uses=1]
  ret i8 %B
  
  
; X32: test3:
; X32:  	movl	4(%esp), %eax
; X32:  	movb	-2(%eax), %al
; X32:  	ret

; X64: test3:
; X64:  	movb	-2(%rdi), %al
; X64:  	ret

}

define double @test4(i64 %x, double* %p) nounwind {
entry:
  %x.addr = alloca i64, align 8                   ; <i64*> [#uses=2]
  %p.addr = alloca double*, align 8               ; <double**> [#uses=2]
  store i64 %x, i64* %x.addr
  store double* %p, double** %p.addr
  %tmp = load i64* %x.addr                        ; <i64> [#uses=1]
  %add = add nsw i64 %tmp, 16                     ; <i64> [#uses=1]
  %tmp1 = load double** %p.addr                   ; <double*> [#uses=1]
  %arrayidx = getelementptr inbounds double* %tmp1, i64 %add ; <double*> [#uses=1]
  %tmp2 = load double* %arrayidx                  ; <double> [#uses=1]
  ret double %tmp2

; X32: test4:
; X32: 128(%e{{.*}},%e{{.*}},8)
; X64: test4:
; X64: 128(%r{{.*}},%r{{.*}},8)
}
