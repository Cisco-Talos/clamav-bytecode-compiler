#ifndef DRIVER_H
#define DRIVER_H
namespace llvm
{
namespace sys
{
class Path;
}
class raw_ostream;
} // namespace llvm
int CompileFile(int argc, const char** argv,
                const llvm::sys::Path* out, const llvm::sys::Path* err,
                llvm::raw_ostream& Err, bool bugreport = false,
                bool versiononly = false);
#endif
