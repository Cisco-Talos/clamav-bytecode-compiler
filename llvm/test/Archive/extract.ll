; This isn't really an assembly file, its just here to run the test.

; This test just makes sure that llvm-ar can extract bytecode members
; from various style archives.

; RUN: llvm-ar x %p/GNU.a very_long_bytecode_file_name.bc
; RUN: diff %p/very_long_bytecode_file_name.bc very_long_bytecode_file_name.bc >/dev/null 2>/dev/null

; RUN: llvm-ar x %p/MacOSX.a very_long_bytecode_file_name.bc
; RUN: diff %p/very_long_bytecode_file_name.bc very_long_bytecode_file_name.bc > /dev/null 2>/dev/null

; RUN: llvm-ar x %p/SVR4.a very_long_bytecode_file_name.bc
; RUN: diff %p/very_long_bytecode_file_name.bc very_long_bytecode_file_name.bc >/dev/null 2>/dev/null

; RUN: llvm-ar x %p/xpg4.a very_long_bytecode_file_name.bc
; RUN: diff %p/very_long_bytecode_file_name.bc very_long_bytecode_file_name.bc >/dev/null 2>/dev/null
