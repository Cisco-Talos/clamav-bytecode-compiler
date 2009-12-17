//===- JITTest.cpp - Unit tests for the JIT -------------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "gtest/gtest.h"
#include "llvm/ADT/OwningPtr.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/Assembly/Parser.h"
#include "llvm/BasicBlock.h"
#include "llvm/Constant.h"
#include "llvm/Constants.h"
#include "llvm/DerivedTypes.h"
#include "llvm/ExecutionEngine/JIT.h"
#include "llvm/ExecutionEngine/JITMemoryManager.h"
#include "llvm/Function.h"
#include "llvm/GlobalValue.h"
#include "llvm/GlobalVariable.h"
#include "llvm/LLVMContext.h"
#include "llvm/Module.h"
#include "llvm/ModuleProvider.h"
#include "llvm/Support/IRBuilder.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/TypeBuilder.h"
#include "llvm/Target/TargetSelect.h"
#include "llvm/Type.h"

#include <vector>

using namespace llvm;

namespace {

Function *makeReturnGlobal(std::string Name, GlobalVariable *G, Module *M) {
  std::vector<const Type*> params;
  const FunctionType *FTy = FunctionType::get(G->getType()->getElementType(),
                                              params, false);
  Function *F = Function::Create(FTy, GlobalValue::ExternalLinkage, Name, M);
  BasicBlock *Entry = BasicBlock::Create(M->getContext(), "entry", F);
  IRBuilder<> builder(Entry);
  Value *Load = builder.CreateLoad(G);
  const Type *GTy = G->getType()->getElementType();
  Value *Add = builder.CreateAdd(Load, ConstantInt::get(GTy, 1LL));
  builder.CreateStore(Add, G);
  builder.CreateRet(Add);
  return F;
}

std::string DumpFunction(const Function *F) {
  std::string Result;
  raw_string_ostream(Result) << "" << *F;
  return Result;
}

class RecordingJITMemoryManager : public JITMemoryManager {
  const OwningPtr<JITMemoryManager> Base;
public:
  RecordingJITMemoryManager()
    : Base(JITMemoryManager::CreateDefaultMemManager()) {
    stubsAllocated = 0;
  }

  virtual void setMemoryWritable() { Base->setMemoryWritable(); }
  virtual void setMemoryExecutable() { Base->setMemoryExecutable(); }
  virtual void setPoisonMemory(bool poison) { Base->setPoisonMemory(poison); }
  virtual void AllocateGOT() { Base->AllocateGOT(); }
  virtual uint8_t *getGOTBase() const { return Base->getGOTBase(); }
  struct StartFunctionBodyCall {
    StartFunctionBodyCall(uint8_t *Result, const Function *F,
                          uintptr_t ActualSize, uintptr_t ActualSizeResult)
      : Result(Result), F(F), F_dump(DumpFunction(F)),
        ActualSize(ActualSize), ActualSizeResult(ActualSizeResult) {}
    uint8_t *Result;
    const Function *F;
    std::string F_dump;
    uintptr_t ActualSize;
    uintptr_t ActualSizeResult;
  };
  std::vector<StartFunctionBodyCall> startFunctionBodyCalls;
  virtual uint8_t *startFunctionBody(const Function *F,
                                     uintptr_t &ActualSize) {
    uintptr_t InitialActualSize = ActualSize;
    uint8_t *Result = Base->startFunctionBody(F, ActualSize);
    startFunctionBodyCalls.push_back(
      StartFunctionBodyCall(Result, F, InitialActualSize, ActualSize));
    return Result;
  }
  int stubsAllocated;
  virtual uint8_t *allocateStub(const GlobalValue* F, unsigned StubSize,
                                unsigned Alignment) {
    stubsAllocated++;
    return Base->allocateStub(F, StubSize, Alignment);
  }
  struct EndFunctionBodyCall {
    EndFunctionBodyCall(const Function *F, uint8_t *FunctionStart,
                        uint8_t *FunctionEnd)
      : F(F), F_dump(DumpFunction(F)),
        FunctionStart(FunctionStart), FunctionEnd(FunctionEnd) {}
    const Function *F;
    std::string F_dump;
    uint8_t *FunctionStart;
    uint8_t *FunctionEnd;
  };
  std::vector<EndFunctionBodyCall> endFunctionBodyCalls;
  virtual void endFunctionBody(const Function *F, uint8_t *FunctionStart,
                               uint8_t *FunctionEnd) {
    endFunctionBodyCalls.push_back(
      EndFunctionBodyCall(F, FunctionStart, FunctionEnd));
    Base->endFunctionBody(F, FunctionStart, FunctionEnd);
  }
  virtual uint8_t *allocateSpace(intptr_t Size, unsigned Alignment) {
    return Base->allocateSpace(Size, Alignment);
  }
  virtual uint8_t *allocateGlobal(uintptr_t Size, unsigned Alignment) {
    return Base->allocateGlobal(Size, Alignment);
  }
  struct DeallocateFunctionBodyCall {
    DeallocateFunctionBodyCall(const void *Body) : Body(Body) {}
    const void *Body;
  };
  std::vector<DeallocateFunctionBodyCall> deallocateFunctionBodyCalls;
  virtual void deallocateFunctionBody(void *Body) {
    deallocateFunctionBodyCalls.push_back(DeallocateFunctionBodyCall(Body));
    Base->deallocateFunctionBody(Body);
  }
  struct DeallocateExceptionTableCall {
    DeallocateExceptionTableCall(const void *ET) : ET(ET) {}
    const void *ET;
  };
  std::vector<DeallocateExceptionTableCall> deallocateExceptionTableCalls;
  virtual void deallocateExceptionTable(void *ET) {
    deallocateExceptionTableCalls.push_back(DeallocateExceptionTableCall(ET));
    Base->deallocateExceptionTable(ET);
  }
  struct StartExceptionTableCall {
    StartExceptionTableCall(uint8_t *Result, const Function *F,
                            uintptr_t ActualSize, uintptr_t ActualSizeResult)
      : Result(Result), F(F), F_dump(DumpFunction(F)),
        ActualSize(ActualSize), ActualSizeResult(ActualSizeResult) {}
    uint8_t *Result;
    const Function *F;
    std::string F_dump;
    uintptr_t ActualSize;
    uintptr_t ActualSizeResult;
  };
  std::vector<StartExceptionTableCall> startExceptionTableCalls;
  virtual uint8_t* startExceptionTable(const Function* F,
                                       uintptr_t &ActualSize) {
    uintptr_t InitialActualSize = ActualSize;
    uint8_t *Result = Base->startExceptionTable(F, ActualSize);
    startExceptionTableCalls.push_back(
      StartExceptionTableCall(Result, F, InitialActualSize, ActualSize));
    return Result;
  }
  struct EndExceptionTableCall {
    EndExceptionTableCall(const Function *F, uint8_t *TableStart,
                          uint8_t *TableEnd, uint8_t* FrameRegister)
      : F(F), F_dump(DumpFunction(F)),
        TableStart(TableStart), TableEnd(TableEnd),
        FrameRegister(FrameRegister) {}
    const Function *F;
    std::string F_dump;
    uint8_t *TableStart;
    uint8_t *TableEnd;
    uint8_t *FrameRegister;
  };
  std::vector<EndExceptionTableCall> endExceptionTableCalls;
  virtual void endExceptionTable(const Function *F, uint8_t *TableStart,
                                 uint8_t *TableEnd, uint8_t* FrameRegister) {
      endExceptionTableCalls.push_back(
          EndExceptionTableCall(F, TableStart, TableEnd, FrameRegister));
    return Base->endExceptionTable(F, TableStart, TableEnd, FrameRegister);
  }
};

class JITTest : public testing::Test {
 protected:
  virtual void SetUp() {
    M = new Module("<main>", Context);
    MP = new ExistingModuleProvider(M);
    RJMM = new RecordingJITMemoryManager;
    RJMM->setPoisonMemory(true);
    std::string Error;
    TheJIT.reset(EngineBuilder(MP).setEngineKind(EngineKind::JIT)
                 .setJITMemoryManager(RJMM)
                 .setErrorStr(&Error).create());
    ASSERT_TRUE(TheJIT.get() != NULL) << Error;
  }

  void LoadAssembly(const char *assembly) {
    SMDiagnostic Error;
    bool success = NULL != ParseAssemblyString(assembly, M, Error, Context);
    std::string errMsg;
    raw_string_ostream os(errMsg);
    Error.Print("", os);
    ASSERT_TRUE(success) << os.str();
  }

  LLVMContext Context;
  Module *M;  // Owned by MP.
  ModuleProvider *MP;  // Owned by ExecutionEngine.
  RecordingJITMemoryManager *RJMM;
  OwningPtr<ExecutionEngine> TheJIT;
};

// Regression test for a bug.  The JIT used to allocate globals inside the same
// memory block used for the function, and when the function code was freed,
// the global was left in the same place.  This test allocates a function
// that uses and global, deallocates it, and then makes sure that the global
// stays alive after that.
TEST(JIT, GlobalInFunction) {
  LLVMContext context;
  Module *M = new Module("<main>", context);
  ExistingModuleProvider *MP = new ExistingModuleProvider(M);

  JITMemoryManager *MemMgr = JITMemoryManager::CreateDefaultMemManager();
  // Tell the memory manager to poison freed memory so that accessing freed
  // memory is more easily tested.
  MemMgr->setPoisonMemory(true);
  std::string Error;
  OwningPtr<ExecutionEngine> JIT(EngineBuilder(MP)
                                 .setEngineKind(EngineKind::JIT)
                                 .setErrorStr(&Error)
                                 .setJITMemoryManager(MemMgr)
                                 // The next line enables the fix:
                                 .setAllocateGVsWithCode(false)
                                 .create());
  ASSERT_EQ(Error, "");

  // Create a global variable.
  const Type *GTy = Type::getInt32Ty(context);
  GlobalVariable *G = new GlobalVariable(
      *M,
      GTy,
      false,  // Not constant.
      GlobalValue::InternalLinkage,
      Constant::getNullValue(GTy),
      "myglobal");

  // Make a function that points to a global.
  Function *F1 = makeReturnGlobal("F1", G, M);

  // Get the pointer to the native code to force it to JIT the function and
  // allocate space for the global.
  void (*F1Ptr)() =
      reinterpret_cast<void(*)()>((intptr_t)JIT->getPointerToFunction(F1));

  // Since F1 was codegen'd, a pointer to G should be available.
  int32_t *GPtr = (int32_t*)JIT->getPointerToGlobalIfAvailable(G);
  ASSERT_NE((int32_t*)NULL, GPtr);
  EXPECT_EQ(0, *GPtr);

  // F1() should increment G.
  F1Ptr();
  EXPECT_EQ(1, *GPtr);

  // Make a second function identical to the first, referring to the same
  // global.
  Function *F2 = makeReturnGlobal("F2", G, M);
  void (*F2Ptr)() =
      reinterpret_cast<void(*)()>((intptr_t)JIT->getPointerToFunction(F2));

  // F2() should increment G.
  F2Ptr();
  EXPECT_EQ(2, *GPtr);

  // Deallocate F1.
  JIT->freeMachineCodeForFunction(F1);

  // F2() should *still* increment G.
  F2Ptr();
  EXPECT_EQ(3, *GPtr);
}

int PlusOne(int arg) {
  return arg + 1;
}

TEST_F(JITTest, FarCallToKnownFunction) {
  // x86-64 can only make direct calls to functions within 32 bits of
  // the current PC.  To call anything farther away, we have to load
  // the address into a register and call through the register.  The
  // current JIT does this by allocating a stub for any far call.
  // There was a bug in which the JIT tried to emit a direct call when
  // the target was already in the JIT's global mappings and lazy
  // compilation was disabled.

  Function *KnownFunction = Function::Create(
      TypeBuilder<int(int), false>::get(Context),
      GlobalValue::ExternalLinkage, "known", M);
  TheJIT->addGlobalMapping(KnownFunction, (void*)(intptr_t)PlusOne);

  // int test() { return known(7); }
  Function *TestFunction = Function::Create(
      TypeBuilder<int(), false>::get(Context),
      GlobalValue::ExternalLinkage, "test", M);
  BasicBlock *Entry = BasicBlock::Create(Context, "entry", TestFunction);
  IRBuilder<> Builder(Entry);
  Value *result = Builder.CreateCall(
      KnownFunction,
      ConstantInt::get(TypeBuilder<int, false>::get(Context), 7));
  Builder.CreateRet(result);

  TheJIT->DisableLazyCompilation(true);
  int (*TestFunctionPtr)() = reinterpret_cast<int(*)()>(
      (intptr_t)TheJIT->getPointerToFunction(TestFunction));
  // This used to crash in trying to call PlusOne().
  EXPECT_EQ(8, TestFunctionPtr());
}

// Test a function C which calls A and B which call each other.
TEST_F(JITTest, NonLazyCompilationStillNeedsStubs) {
  TheJIT->DisableLazyCompilation(true);

  const FunctionType *Func1Ty =
      cast<FunctionType>(TypeBuilder<void(void), false>::get(Context));
  std::vector<const Type*> arg_types;
  arg_types.push_back(Type::getInt1Ty(Context));
  const FunctionType *FuncTy = FunctionType::get(
      Type::getVoidTy(Context), arg_types, false);
  Function *Func1 = Function::Create(Func1Ty, Function::ExternalLinkage,
                                     "func1", M);
  Function *Func2 = Function::Create(FuncTy, Function::InternalLinkage,
                                     "func2", M);
  Function *Func3 = Function::Create(FuncTy, Function::InternalLinkage,
                                     "func3", M);
  BasicBlock *Block1 = BasicBlock::Create(Context, "block1", Func1);
  BasicBlock *Block2 = BasicBlock::Create(Context, "block2", Func2);
  BasicBlock *True2 = BasicBlock::Create(Context, "cond_true", Func2);
  BasicBlock *False2 = BasicBlock::Create(Context, "cond_false", Func2);
  BasicBlock *Block3 = BasicBlock::Create(Context, "block3", Func3);
  BasicBlock *True3 = BasicBlock::Create(Context, "cond_true", Func3);
  BasicBlock *False3 = BasicBlock::Create(Context, "cond_false", Func3);

  // Make Func1 call Func2(0) and Func3(0).
  IRBuilder<> Builder(Block1);
  Builder.CreateCall(Func2, ConstantInt::getTrue(Context));
  Builder.CreateCall(Func3, ConstantInt::getTrue(Context));
  Builder.CreateRetVoid();

  // void Func2(bool b) { if (b) { Func3(false); return; } return; }
  Builder.SetInsertPoint(Block2);
  Builder.CreateCondBr(Func2->arg_begin(), True2, False2);
  Builder.SetInsertPoint(True2);
  Builder.CreateCall(Func3, ConstantInt::getFalse(Context));
  Builder.CreateRetVoid();
  Builder.SetInsertPoint(False2);
  Builder.CreateRetVoid();

  // void Func3(bool b) { if (b) { Func2(false); return; } return; }
  Builder.SetInsertPoint(Block3);
  Builder.CreateCondBr(Func3->arg_begin(), True3, False3);
  Builder.SetInsertPoint(True3);
  Builder.CreateCall(Func2, ConstantInt::getFalse(Context));
  Builder.CreateRetVoid();
  Builder.SetInsertPoint(False3);
  Builder.CreateRetVoid();

  // Compile the function to native code
  void (*F1Ptr)() =
     reinterpret_cast<void(*)()>((intptr_t)TheJIT->getPointerToFunction(Func1));

  F1Ptr();
}

// Regression test for PR5162.  This used to trigger an AssertingVH inside the
// JIT's Function to stub mapping.
TEST_F(JITTest, NonLazyLeaksNoStubs) {
  TheJIT->DisableLazyCompilation(true);

  // Create two functions with a single basic block each.
  const FunctionType *FuncTy =
      cast<FunctionType>(TypeBuilder<int(), false>::get(Context));
  Function *Func1 = Function::Create(FuncTy, Function::ExternalLinkage,
                                     "func1", M);
  Function *Func2 = Function::Create(FuncTy, Function::InternalLinkage,
                                     "func2", M);
  BasicBlock *Block1 = BasicBlock::Create(Context, "block1", Func1);
  BasicBlock *Block2 = BasicBlock::Create(Context, "block2", Func2);

  // The first function calls the second and returns the result
  IRBuilder<> Builder(Block1);
  Value *Result = Builder.CreateCall(Func2);
  Builder.CreateRet(Result);

  // The second function just returns a constant
  Builder.SetInsertPoint(Block2);
  Builder.CreateRet(ConstantInt::get(TypeBuilder<int, false>::get(Context),42));

  // Compile the function to native code
  (void)TheJIT->getPointerToFunction(Func1);

  // Free the JIT state for the functions
  TheJIT->freeMachineCodeForFunction(Func1);
  TheJIT->freeMachineCodeForFunction(Func2);

  // Delete the first function (and show that is has no users)
  EXPECT_EQ(Func1->getNumUses(), 0u);
  Func1->eraseFromParent();

  // Delete the second function (and show that it has no users - it had one,
  // func1 but that's gone now)
  EXPECT_EQ(Func2->getNumUses(), 0u);
  Func2->eraseFromParent();
}

TEST_F(JITTest, ModuleDeletion) {
  TheJIT->DisableLazyCompilation(false);
  LoadAssembly("define void @main() { "
               "  call i32 @computeVal() "
               "  ret void "
               "} "
               " "
               "define internal i32 @computeVal()  { "
               "  ret i32 0 "
               "} ");
  Function *func = M->getFunction("main");
  TheJIT->getPointerToFunction(func);
  TheJIT->deleteModuleProvider(MP);

  SmallPtrSet<const void*, 2> FunctionsDeallocated;
  for (unsigned i = 0, e = RJMM->deallocateFunctionBodyCalls.size();
       i != e; ++i) {
    FunctionsDeallocated.insert(RJMM->deallocateFunctionBodyCalls[i].Body);
  }
  for (unsigned i = 0, e = RJMM->startFunctionBodyCalls.size(); i != e; ++i) {
    EXPECT_TRUE(FunctionsDeallocated.count(
                  RJMM->startFunctionBodyCalls[i].Result))
      << "Function leaked: \n" << RJMM->startFunctionBodyCalls[i].F_dump;
  }
  EXPECT_EQ(RJMM->startFunctionBodyCalls.size(),
            RJMM->deallocateFunctionBodyCalls.size());

  SmallPtrSet<const void*, 2> ExceptionTablesDeallocated;
  unsigned NumTablesDeallocated = 0;
  for (unsigned i = 0, e = RJMM->deallocateExceptionTableCalls.size();
       i != e; ++i) {
    ExceptionTablesDeallocated.insert(
        RJMM->deallocateExceptionTableCalls[i].ET);
    if (RJMM->deallocateExceptionTableCalls[i].ET != NULL) {
        // If JITEmitDebugInfo is off, we'll "deallocate" NULL, which doesn't
        // appear in startExceptionTableCalls.
        NumTablesDeallocated++;
    }
  }
  for (unsigned i = 0, e = RJMM->startExceptionTableCalls.size(); i != e; ++i) {
    EXPECT_TRUE(ExceptionTablesDeallocated.count(
                  RJMM->startExceptionTableCalls[i].Result))
      << "Function's exception table leaked: \n"
      << RJMM->startExceptionTableCalls[i].F_dump;
  }
  EXPECT_EQ(RJMM->startExceptionTableCalls.size(),
            NumTablesDeallocated);
}

// ARM and PPC still emit stubs for calls since the target may be too far away
// to call directly.  This #if can probably be removed when
// http://llvm.org/PR5201 is fixed.
#if !defined(__arm__) && !defined(__powerpc__) && !defined(__ppc__)
typedef int (*FooPtr) ();

TEST_F(JITTest, NoStubs) {
  LoadAssembly("define void @bar() {"
	       "entry: "
	       "ret void"
	       "}"
	       " "
	       "define i32 @foo() {"
	       "entry:"
	       "call void @bar()"
	       "ret i32 undef"
	       "}"
	       " "
	       "define i32 @main() {"
	       "entry:"
	       "%0 = call i32 @foo()"
	       "call void @bar()"
	       "ret i32 undef"
	       "}");
  Function *foo = M->getFunction("foo");
  uintptr_t tmp = (uintptr_t)(TheJIT->getPointerToFunction(foo));
  FooPtr ptr = (FooPtr)(tmp);

  (ptr)();

  // We should now allocate no more stubs, we have the code to foo
  // and the existing stub for bar.
  int stubsBefore = RJMM->stubsAllocated;
  Function *func = M->getFunction("main");
  TheJIT->getPointerToFunction(func);

  Function *bar = M->getFunction("bar");
  TheJIT->getPointerToFunction(bar);

  ASSERT_EQ(stubsBefore, RJMM->stubsAllocated);
}
#endif  // !ARM && !PPC

TEST_F(JITTest, FunctionPointersOutliveTheirCreator) {
  TheJIT->DisableLazyCompilation(true);
  LoadAssembly("define i8()* @get_foo_addr() { "
               "  ret i8()* @foo "
               "} "
               " "
               "define i8 @foo() { "
               "  ret i8 42 "
               "} ");
  Function *F_get_foo_addr = M->getFunction("get_foo_addr");

  typedef char(*fooT)();
  fooT (*get_foo_addr)() = reinterpret_cast<fooT(*)()>(
      (intptr_t)TheJIT->getPointerToFunction(F_get_foo_addr));
  fooT foo_addr = get_foo_addr();

  // Now free get_foo_addr.  This should not free the machine code for foo or
  // any call stub returned as foo's canonical address.
  TheJIT->freeMachineCodeForFunction(F_get_foo_addr);

  // Check by calling the reported address of foo.
  EXPECT_EQ(42, foo_addr());

  // The reported address should also be the same as the result of a subsequent
  // getPointerToFunction(foo).
#if 0
  // Fails until PR5126 is fixed:
  Function *F_foo = M->getFunction("foo");
  fooT foo = reinterpret_cast<fooT>(
      (intptr_t)TheJIT->getPointerToFunction(F_foo));
  EXPECT_EQ((intptr_t)foo, (intptr_t)foo_addr);
#endif
}

}  // anonymous namespace
// This variable is intentionally defined differently in the statically-compiled
// program from the IR input to the JIT to assert that the JIT doesn't use its
// definition.
extern "C" int32_t JITTest_AvailableExternallyGlobal;
int32_t JITTest_AvailableExternallyGlobal = 42;
namespace {

TEST_F(JITTest, AvailableExternallyGlobalIsntEmitted) {
  TheJIT->DisableLazyCompilation(true);
  LoadAssembly("@JITTest_AvailableExternallyGlobal = "
               "  available_externally global i32 7 "
               " "
               "define i32 @loader() { "
               "  %result = load i32* @JITTest_AvailableExternallyGlobal "
               "  ret i32 %result "
               "} ");
  Function *loaderIR = M->getFunction("loader");

  int32_t (*loader)() = reinterpret_cast<int32_t(*)()>(
    (intptr_t)TheJIT->getPointerToFunction(loaderIR));
  EXPECT_EQ(42, loader()) << "func should return 42 from the external global,"
                          << " not 7 from the IR version.";
}

}  // anonymous namespace
// This function is intentionally defined differently in the statically-compiled
// program from the IR input to the JIT to assert that the JIT doesn't use its
// definition.
extern "C" int32_t JITTest_AvailableExternallyFunction() {
  return 42;
}
namespace {

TEST_F(JITTest, AvailableExternallyFunctionIsntCompiled) {
  TheJIT->DisableLazyCompilation(true);
  LoadAssembly("define available_externally i32 "
               "    @JITTest_AvailableExternallyFunction() { "
               "  ret i32 7 "
               "} "
               " "
               "define i32 @func() { "
               "  %result = tail call i32 "
               "    @JITTest_AvailableExternallyFunction() "
               "  ret i32 %result "
               "} ");
  Function *funcIR = M->getFunction("func");

  int32_t (*func)() = reinterpret_cast<int32_t(*)()>(
    (intptr_t)TheJIT->getPointerToFunction(funcIR));
  EXPECT_EQ(42, func()) << "func should return 42 from the static version,"
                        << " not 7 from the IR version.";
}

// This code is copied from JITEventListenerTest, but it only runs once for all
// the tests in this directory.  Everything seems fine, but that's strange
// behavior.
class JITEnvironment : public testing::Environment {
  virtual void SetUp() {
    // Required to create a JIT.
    InitializeNativeTarget();
  }
};
testing::Environment* const jit_env =
  testing::AddGlobalTestEnvironment(new JITEnvironment);

}
