# RUN: llvm-mc -triple i386-unknown-unknown %s | FileCheck %s

# CHECK: TEST0:
# CHECK: .byte 0
TEST0:  
        .byte 0

# CHECK: TEST1:
# CHECK: .short 3
TEST1:  
        .short 3

# CHECK: TEST2:
# CHECK: .long 8
TEST2:  
        .long 8

# CHECK: TEST3:
# CHECK: .quad 9
TEST3:  
        .quad 9


# rdar://7997827
TEST4:
        .quad 0b0100
        .quad 4294967295
        .quad 4294967295+1
        .quad 4294967295LL+1
        .quad 0b10LL + 07ULL + 0x42AULL
# CHECK: TEST4
# CHECK: 	.quad	4
# CHECK: .quad	4294967295
# CHECK: 	.quad	4294967296
# CHECK: 	.quad	4294967296
# CHECK: 	.quad	1075


