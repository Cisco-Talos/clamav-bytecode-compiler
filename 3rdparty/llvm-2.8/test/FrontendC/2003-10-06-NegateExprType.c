// RUN: %llvmgcc -S %s -o - | llvm-as -o /dev/null


extern int A[10];
void Func(int *B) { 
  B - &A[5]; 
}

