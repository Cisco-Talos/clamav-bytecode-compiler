// RUN: %llvmgcc -S %s -o - | llvm-as -o /dev/null

extern void start() __asm__("start");
extern void _start() __asm__("_start");
extern void __start() __asm__("__start");
void start() {}
void _start() {}
void __start() {}

