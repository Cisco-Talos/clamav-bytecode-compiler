// RUN: %llvmgcc -S %s -o - | llvm-as -o /dev/null


typedef struct {
  unsigned long val;
} structty;

void bar(structty new_mask);
static void foo() {
  bar(({ structty mask; mask; }));
}

