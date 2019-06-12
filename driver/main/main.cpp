#include "../clamdriver/driver.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/CodeGen/RegAllocRegistry.h"
#include "llvm/CodeGen/SchedulerRegistry.h"

int main(int argc, char** argv)
{
    return CompileFile(argc, (const char**)argv, 0, 0, llvm::errs());
}

namespace llvm
{
// dummy def of these symbols, to allow linking w/o codegen/sdag.
MachinePassRegistry RegisterScheduler::Registry;
MachinePassRegistry RegisterRegAlloc::Registry;
ScheduleDAGSDNodes* createDefaultScheduler(SelectionDAGISel* IS,
                                           CodeGenOpt::Level OptLevel)
{
    return 0;
}
FunctionPass* createLinearScanRegisterAllocator()
{
    return 0;
}
FunctionPass* createLocalRegisterAllocator()
{
    return 0;
}
} // namespace llvm
