// RUN: %llvmgcc -S %s -o - | llvm-as -o /dev/null

void schedule_timeout(signed long timeout)
{
 switch (timeout)
 {
 case ((long)(~0UL>>1)): break;
 }
}
