// RUN: %llvmgxx -S %s -o - | llvm-as -o /dev/null

#include <string>

void bar();

void test() {
  try {
    bar();
  } catch (std::string) {}
}
