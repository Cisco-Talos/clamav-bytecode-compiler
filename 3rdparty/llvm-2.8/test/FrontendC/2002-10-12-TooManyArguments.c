// RUN: %llvmgcc -S %s -o - | llvm-as -o /dev/null


void foo() {}

void bar() {
  foo(1, 2, 3);  /* Too many arguments passed */
}
