// RUN: %llvmgcc -S %s -o - | llvm-as -o /dev/null



union foo { int X; };

int test(union foo* F) {
  {
    union foo { float X; } A;
  }
}
