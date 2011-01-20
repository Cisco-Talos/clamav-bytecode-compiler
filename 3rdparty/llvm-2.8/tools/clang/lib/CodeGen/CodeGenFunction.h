//===-- CodeGenFunction.h - Per-Function state for LLVM CodeGen -*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This is the internal per-function state used for llvm translation.
//
//===----------------------------------------------------------------------===//

#ifndef CLANG_CODEGEN_CODEGENFUNCTION_H
#define CLANG_CODEGEN_CODEGENFUNCTION_H

#include "clang/AST/Type.h"
#include "clang/AST/ExprCXX.h"
#include "clang/AST/ExprObjC.h"
#include "clang/AST/CharUnits.h"
#include "clang/Basic/TargetInfo.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Support/ValueHandle.h"
#include "CodeGenModule.h"
#include "CGBlocks.h"
#include "CGBuilder.h"
#include "CGCall.h"
#include "CGCXX.h"
#include "CGValue.h"

namespace llvm {
  class BasicBlock;
  class LLVMContext;
  class MDNode;
  class Module;
  class SwitchInst;
  class Twine;
  class Value;
  class CallSite;
}

namespace clang {
  class APValue;
  class ASTContext;
  class CXXDestructorDecl;
  class CXXTryStmt;
  class Decl;
  class EnumConstantDecl;
  class FunctionDecl;
  class FunctionProtoType;
  class LabelStmt;
  class ObjCContainerDecl;
  class ObjCInterfaceDecl;
  class ObjCIvarDecl;
  class ObjCMethodDecl;
  class ObjCImplementationDecl;
  class ObjCPropertyImplDecl;
  class TargetInfo;
  class TargetCodeGenInfo;
  class VarDecl;
  class ObjCForCollectionStmt;
  class ObjCAtTryStmt;
  class ObjCAtThrowStmt;
  class ObjCAtSynchronizedStmt;

namespace CodeGen {
  class CodeGenTypes;
  class CGDebugInfo;
  class CGFunctionInfo;
  class CGRecordLayout;
  class CGBlockInfo;
  class CGCXXABI;

/// A branch fixup.  These are required when emitting a goto to a
/// label which hasn't been emitted yet.  The goto is optimistically
/// emitted as a branch to the basic block for the label, and (if it
/// occurs in a scope with non-trivial cleanups) a fixup is added to
/// the innermost cleanup.  When a (normal) cleanup is popped, any
/// unresolved fixups in that scope are threaded through the cleanup.
struct BranchFixup {
  /// The block containing the terminator which needs to be modified
  /// into a switch if this fixup is resolved into the current scope.
  /// If null, LatestBranch points directly to the destination.
  llvm::BasicBlock *OptimisticBranchBlock;

  /// The ultimate destination of the branch.
  ///
  /// This can be set to null to indicate that this fixup was
  /// successfully resolved.
  llvm::BasicBlock *Destination;

  /// The destination index value.
  unsigned DestinationIndex;

  /// The initial branch of the fixup.
  llvm::BranchInst *InitialBranch;
};

enum CleanupKind {
  EHCleanup = 0x1,
  NormalCleanup = 0x2,
  NormalAndEHCleanup = EHCleanup | NormalCleanup,

  InactiveCleanup = 0x4,
  InactiveEHCleanup = EHCleanup | InactiveCleanup,
  InactiveNormalCleanup = NormalCleanup | InactiveCleanup,
  InactiveNormalAndEHCleanup = NormalAndEHCleanup | InactiveCleanup
};

/// A stack of scopes which respond to exceptions, including cleanups
/// and catch blocks.
class EHScopeStack {
public:
  /// A saved depth on the scope stack.  This is necessary because
  /// pushing scopes onto the stack invalidates iterators.
  class stable_iterator {
    friend class EHScopeStack;

    /// Offset from StartOfData to EndOfBuffer.
    ptrdiff_t Size;

    stable_iterator(ptrdiff_t Size) : Size(Size) {}

  public:
    static stable_iterator invalid() { return stable_iterator(-1); }
    stable_iterator() : Size(-1) {}

    bool isValid() const { return Size >= 0; }

    /// Returns true if this scope encloses I.
    /// Returns false if I is invalid.
    /// This scope must be valid.
    bool encloses(stable_iterator I) const { return Size <= I.Size; }

    /// Returns true if this scope strictly encloses I: that is,
    /// if it encloses I and is not I.
    /// Returns false is I is invalid.
    /// This scope must be valid.
    bool strictlyEncloses(stable_iterator I) const { return Size < I.Size; }

    friend bool operator==(stable_iterator A, stable_iterator B) {
      return A.Size == B.Size;
    }
    friend bool operator!=(stable_iterator A, stable_iterator B) {
      return A.Size != B.Size;
    }
  };

  /// Information for lazily generating a cleanup.  Subclasses must be
  /// POD-like: cleanups will not be destructed, and they will be
  /// allocated on the cleanup stack and freely copied and moved
  /// around.
  ///
  /// Cleanup implementations should generally be declared in an
  /// anonymous namespace.
  class Cleanup {
  public:
    // Anchor the construction vtable.  We use the destructor because
    // gcc gives an obnoxious warning if there are virtual methods
    // with an accessible non-virtual destructor.  Unfortunately,
    // declaring this destructor makes it non-trivial, but there
    // doesn't seem to be any other way around this warning.
    //
    // This destructor will never be called.
    virtual ~Cleanup();

    /// Emit the cleanup.  For normal cleanups, this is run in the
    /// same EH context as when the cleanup was pushed, i.e. the
    /// immediately-enclosing context of the cleanup scope.  For
    /// EH cleanups, this is run in a terminate context.
    ///
    // \param IsForEHCleanup true if this is for an EH cleanup, false
    ///  if for a normal cleanup.
    virtual void Emit(CodeGenFunction &CGF, bool IsForEHCleanup) = 0;
  };

private:
  // The implementation for this class is in CGException.h and
  // CGException.cpp; the definition is here because it's used as a
  // member of CodeGenFunction.

  /// The start of the scope-stack buffer, i.e. the allocated pointer
  /// for the buffer.  All of these pointers are either simultaneously
  /// null or simultaneously valid.
  char *StartOfBuffer;

  /// The end of the buffer.
  char *EndOfBuffer;

  /// The first valid entry in the buffer.
  char *StartOfData;

  /// The innermost normal cleanup on the stack.
  stable_iterator InnermostNormalCleanup;

  /// The innermost EH cleanup on the stack.
  stable_iterator InnermostEHCleanup;

  /// The number of catches on the stack.
  unsigned CatchDepth;

  /// The current EH destination index.  Reset to FirstCatchIndex
  /// whenever the last EH cleanup is popped.
  unsigned NextEHDestIndex;
  enum { FirstEHDestIndex = 1 };

  /// The current set of branch fixups.  A branch fixup is a jump to
  /// an as-yet unemitted label, i.e. a label for which we don't yet
  /// know the EH stack depth.  Whenever we pop a cleanup, we have
  /// to thread all the current branch fixups through it.
  ///
  /// Fixups are recorded as the Use of the respective branch or
  /// switch statement.  The use points to the final destination.
  /// When popping out of a cleanup, these uses are threaded through
  /// the cleanup and adjusted to point to the new cleanup.
  ///
  /// Note that branches are allowed to jump into protected scopes
  /// in certain situations;  e.g. the following code is legal:
  ///     struct A { ~A(); }; // trivial ctor, non-trivial dtor
  ///     goto foo;
  ///     A a;
  ///    foo:
  ///     bar();
  llvm::SmallVector<BranchFixup, 8> BranchFixups;

  char *allocate(size_t Size);

  void *pushCleanup(CleanupKind K, size_t DataSize);

public:
  EHScopeStack() : StartOfBuffer(0), EndOfBuffer(0), StartOfData(0),
                   InnermostNormalCleanup(stable_end()),
                   InnermostEHCleanup(stable_end()),
                   CatchDepth(0), NextEHDestIndex(FirstEHDestIndex) {}
  ~EHScopeStack() { delete[] StartOfBuffer; }

  // Variadic templates would make this not terrible.

  /// Push a lazily-created cleanup on the stack.
  template <class T>
  void pushCleanup(CleanupKind Kind) {
    void *Buffer = pushCleanup(Kind, sizeof(T));
    Cleanup *Obj = new(Buffer) T();
    (void) Obj;
  }

  /// Push a lazily-created cleanup on the stack.
  template <class T, class A0>
  void pushCleanup(CleanupKind Kind, A0 a0) {
    void *Buffer = pushCleanup(Kind, sizeof(T));
    Cleanup *Obj = new(Buffer) T(a0);
    (void) Obj;
  }

  /// Push a lazily-created cleanup on the stack.
  template <class T, class A0, class A1>
  void pushCleanup(CleanupKind Kind, A0 a0, A1 a1) {
    void *Buffer = pushCleanup(Kind, sizeof(T));
    Cleanup *Obj = new(Buffer) T(a0, a1);
    (void) Obj;
  }

  /// Push a lazily-created cleanup on the stack.
  template <class T, class A0, class A1, class A2>
  void pushCleanup(CleanupKind Kind, A0 a0, A1 a1, A2 a2) {
    void *Buffer = pushCleanup(Kind, sizeof(T));
    Cleanup *Obj = new(Buffer) T(a0, a1, a2);
    (void) Obj;
  }

  /// Push a lazily-created cleanup on the stack.
  template <class T, class A0, class A1, class A2, class A3>
  void pushCleanup(CleanupKind Kind, A0 a0, A1 a1, A2 a2, A3 a3) {
    void *Buffer = pushCleanup(Kind, sizeof(T));
    Cleanup *Obj = new(Buffer) T(a0, a1, a2, a3);
    (void) Obj;
  }

  /// Push a lazily-created cleanup on the stack.
  template <class T, class A0, class A1, class A2, class A3, class A4>
  void pushCleanup(CleanupKind Kind, A0 a0, A1 a1, A2 a2, A3 a3, A4 a4) {
    void *Buffer = pushCleanup(Kind, sizeof(T));
    Cleanup *Obj = new(Buffer) T(a0, a1, a2, a3, a4);
    (void) Obj;
  }

  /// Pops a cleanup scope off the stack.  This should only be called
  /// by CodeGenFunction::PopCleanupBlock.
  void popCleanup();

  /// Push a set of catch handlers on the stack.  The catch is
  /// uninitialized and will need to have the given number of handlers
  /// set on it.
  class EHCatchScope *pushCatch(unsigned NumHandlers);

  /// Pops a catch scope off the stack.
  void popCatch();

  /// Push an exceptions filter on the stack.
  class EHFilterScope *pushFilter(unsigned NumFilters);

  /// Pops an exceptions filter off the stack.
  void popFilter();

  /// Push a terminate handler on the stack.
  void pushTerminate();

  /// Pops a terminate handler off the stack.
  void popTerminate();

  /// Determines whether the exception-scopes stack is empty.
  bool empty() const { return StartOfData == EndOfBuffer; }

  bool requiresLandingPad() const {
    return (CatchDepth || hasEHCleanups());
  }

  /// Determines whether there are any normal cleanups on the stack.
  bool hasNormalCleanups() const {
    return InnermostNormalCleanup != stable_end();
  }

  /// Returns the innermost normal cleanup on the stack, or
  /// stable_end() if there are no normal cleanups.
  stable_iterator getInnermostNormalCleanup() const {
    return InnermostNormalCleanup;
  }
  stable_iterator getInnermostActiveNormalCleanup() const; // CGException.h

  /// Determines whether there are any EH cleanups on the stack.
  bool hasEHCleanups() const {
    return InnermostEHCleanup != stable_end();
  }

  /// Returns the innermost EH cleanup on the stack, or stable_end()
  /// if there are no EH cleanups.
  stable_iterator getInnermostEHCleanup() const {
    return InnermostEHCleanup;
  }
  stable_iterator getInnermostActiveEHCleanup() const; // CGException.h

  /// An unstable reference to a scope-stack depth.  Invalidated by
  /// pushes but not pops.
  class iterator;

  /// Returns an iterator pointing to the innermost EH scope.
  iterator begin() const;

  /// Returns an iterator pointing to the outermost EH scope.
  iterator end() const;

  /// Create a stable reference to the top of the EH stack.  The
  /// returned reference is valid until that scope is popped off the
  /// stack.
  stable_iterator stable_begin() const {
    return stable_iterator(EndOfBuffer - StartOfData);
  }

  /// Create a stable reference to the bottom of the EH stack.
  static stable_iterator stable_end() {
    return stable_iterator(0);
  }

  /// Translates an iterator into a stable_iterator.
  stable_iterator stabilize(iterator it) const;

  /// Finds the nearest cleanup enclosing the given iterator.
  /// Returns stable_iterator::invalid() if there are no such cleanups.
  stable_iterator getEnclosingEHCleanup(iterator it) const;

  /// Turn a stable reference to a scope depth into a unstable pointer
  /// to the EH stack.
  iterator find(stable_iterator save) const;

  /// Removes the cleanup pointed to by the given stable_iterator.
  void removeCleanup(stable_iterator save);

  /// Add a branch fixup to the current cleanup scope.
  BranchFixup &addBranchFixup() {
    assert(hasNormalCleanups() && "adding fixup in scope without cleanups");
    BranchFixups.push_back(BranchFixup());
    return BranchFixups.back();
  }

  unsigned getNumBranchFixups() const { return BranchFixups.size(); }
  BranchFixup &getBranchFixup(unsigned I) {
    assert(I < getNumBranchFixups());
    return BranchFixups[I];
  }

  /// Pops lazily-removed fixups from the end of the list.  This
  /// should only be called by procedures which have just popped a
  /// cleanup or resolved one or more fixups.
  void popNullFixups();

  /// Clears the branch-fixups list.  This should only be called by
  /// CodeGenFunction::ResolveAllBranchFixups.
  void clearFixups() { BranchFixups.clear(); }

  /// Gets the next EH destination index.
  unsigned getNextEHDestIndex() { return NextEHDestIndex++; }
};

/// CodeGenFunction - This class organizes the per-function state that is used
/// while generating LLVM code.
class CodeGenFunction : public BlockFunction {
  CodeGenFunction(const CodeGenFunction&); // DO NOT IMPLEMENT
  void operator=(const CodeGenFunction&);  // DO NOT IMPLEMENT

  friend class CGCXXABI;
public:
  /// A jump destination is an abstract label, branching to which may
  /// require a jump out through normal cleanups.
  struct JumpDest {
    JumpDest() : Block(0), ScopeDepth(), Index(0) {}
    JumpDest(llvm::BasicBlock *Block,
             EHScopeStack::stable_iterator Depth,
             unsigned Index)
      : Block(Block), ScopeDepth(Depth), Index(Index) {}

    bool isValid() const { return Block != 0; }
    llvm::BasicBlock *getBlock() const { return Block; }
    EHScopeStack::stable_iterator getScopeDepth() const { return ScopeDepth; }
    unsigned getDestIndex() const { return Index; }
    
  private:
    llvm::BasicBlock *Block;
    EHScopeStack::stable_iterator ScopeDepth;
    unsigned Index;
  };

  /// An unwind destination is an abstract label, branching to which
  /// may require a jump out through EH cleanups.
  struct UnwindDest {
    UnwindDest() : Block(0), ScopeDepth(), Index(0) {}
    UnwindDest(llvm::BasicBlock *Block,
               EHScopeStack::stable_iterator Depth,
               unsigned Index)
      : Block(Block), ScopeDepth(Depth), Index(Index) {}

    bool isValid() const { return Block != 0; }
    llvm::BasicBlock *getBlock() const { return Block; }
    EHScopeStack::stable_iterator getScopeDepth() const { return ScopeDepth; }
    unsigned getDestIndex() const { return Index; }

  private:
    llvm::BasicBlock *Block;
    EHScopeStack::stable_iterator ScopeDepth;
    unsigned Index;
  };

  CodeGenModule &CGM;  // Per-module state.
  const TargetInfo &Target;

  typedef std::pair<llvm::Value *, llvm::Value *> ComplexPairTy;
  CGBuilderTy Builder;

  /// CurFuncDecl - Holds the Decl for the current function or ObjC method.
  /// This excludes BlockDecls.
  const Decl *CurFuncDecl;
  /// CurCodeDecl - This is the inner-most code context, which includes blocks.
  const Decl *CurCodeDecl;
  const CGFunctionInfo *CurFnInfo;
  QualType FnRetTy;
  llvm::Function *CurFn;

  /// CurGD - The GlobalDecl for the current function being compiled.
  GlobalDecl CurGD;

  /// ReturnBlock - Unified return block.
  JumpDest ReturnBlock;

  /// ReturnValue - The temporary alloca to hold the return value. This is null
  /// iff the function has no return value.
  llvm::Value *ReturnValue;

  /// RethrowBlock - Unified rethrow block.
  UnwindDest RethrowBlock;

  /// AllocaInsertPoint - This is an instruction in the entry block before which
  /// we prefer to insert allocas.
  llvm::AssertingVH<llvm::Instruction> AllocaInsertPt;

  // intptr_t, i32, i64
  const llvm::IntegerType *IntPtrTy, *Int32Ty, *Int64Ty;
  uint32_t LLVMPointerWidth;

  bool Exceptions;
  bool CatchUndefined;
  
  /// \brief A mapping from NRVO variables to the flags used to indicate
  /// when the NRVO has been applied to this variable.
  llvm::DenseMap<const VarDecl *, llvm::Value *> NRVOFlags;

  EHScopeStack EHStack;

  /// i32s containing the indexes of the cleanup destinations.
  llvm::AllocaInst *NormalCleanupDest;
  llvm::AllocaInst *EHCleanupDest;

  unsigned NextCleanupDestIndex;

  /// The exception slot.  All landing pads write the current
  /// exception pointer into this alloca.
  llvm::Value *ExceptionSlot;

  /// Emits a landing pad for the current EH stack.
  llvm::BasicBlock *EmitLandingPad();

  llvm::BasicBlock *getInvokeDestImpl();

public:
  /// ObjCEHValueStack - Stack of Objective-C exception values, used for
  /// rethrows.
  llvm::SmallVector<llvm::Value*, 8> ObjCEHValueStack;

  // A struct holding information about a finally block's IR
  // generation.  For now, doesn't actually hold anything.
  struct FinallyInfo {
  };

  FinallyInfo EnterFinallyBlock(const Stmt *Stmt,
                                llvm::Constant *BeginCatchFn,
                                llvm::Constant *EndCatchFn,
                                llvm::Constant *RethrowFn);
  void ExitFinallyBlock(FinallyInfo &FinallyInfo);

  /// PushDestructorCleanup - Push a cleanup to call the
  /// complete-object destructor of an object of the given type at the
  /// given address.  Does nothing if T is not a C++ class type with a
  /// non-trivial destructor.
  void PushDestructorCleanup(QualType T, llvm::Value *Addr);

  /// PushDestructorCleanup - Push a cleanup to call the
  /// complete-object variant of the given destructor on the object at
  /// the given address.
  void PushDestructorCleanup(const CXXDestructorDecl *Dtor,
                             llvm::Value *Addr);

  /// PopCleanupBlock - Will pop the cleanup entry on the stack and
  /// process all branch fixups.
  void PopCleanupBlock(bool FallThroughIsBranchThrough = false);

  void ActivateCleanup(EHScopeStack::stable_iterator Cleanup);

  /// \brief Enters a new scope for capturing cleanups, all of which
  /// will be executed once the scope is exited.
  class RunCleanupsScope {
    CodeGenFunction& CGF;
    EHScopeStack::stable_iterator CleanupStackDepth;
    bool OldDidCallStackSave;
    bool PerformCleanup;

    RunCleanupsScope(const RunCleanupsScope &); // DO NOT IMPLEMENT
    RunCleanupsScope &operator=(const RunCleanupsScope &); // DO NOT IMPLEMENT

  public:
    /// \brief Enter a new cleanup scope.
    explicit RunCleanupsScope(CodeGenFunction &CGF) 
      : CGF(CGF), PerformCleanup(true) 
    {
      CleanupStackDepth = CGF.EHStack.stable_begin();
      OldDidCallStackSave = CGF.DidCallStackSave;
    }

    /// \brief Exit this cleanup scope, emitting any accumulated
    /// cleanups.
    ~RunCleanupsScope() {
      if (PerformCleanup) {
        CGF.DidCallStackSave = OldDidCallStackSave;
        CGF.PopCleanupBlocks(CleanupStackDepth);
      }
    }

    /// \brief Determine whether this scope requires any cleanups.
    bool requiresCleanups() const {
      return CGF.EHStack.stable_begin() != CleanupStackDepth;
    }

    /// \brief Force the emission of cleanups now, instead of waiting
    /// until this object is destroyed.
    void ForceCleanup() {
      assert(PerformCleanup && "Already forced cleanup");
      CGF.DidCallStackSave = OldDidCallStackSave;
      CGF.PopCleanupBlocks(CleanupStackDepth);
      PerformCleanup = false;
    }
  };


  /// PopCleanupBlocks - Takes the old cleanup stack size and emits
  /// the cleanup blocks that have been added.
  void PopCleanupBlocks(EHScopeStack::stable_iterator OldCleanupStackSize);

  void ResolveAllBranchFixups(llvm::SwitchInst *Switch);
  void ResolveBranchFixups(llvm::BasicBlock *Target);

  /// The given basic block lies in the current EH scope, but may be a
  /// target of a potentially scope-crossing jump; get a stable handle
  /// to which we can perform this jump later.
  JumpDest getJumpDestInCurrentScope(llvm::BasicBlock *Target) {
    return JumpDest(Target,
                    EHStack.getInnermostNormalCleanup(),
                    NextCleanupDestIndex++);
  }

  /// The given basic block lies in the current EH scope, but may be a
  /// target of a potentially scope-crossing jump; get a stable handle
  /// to which we can perform this jump later.
  JumpDest getJumpDestInCurrentScope(const char *Name = 0) {
    return getJumpDestInCurrentScope(createBasicBlock(Name));
  }

  /// EmitBranchThroughCleanup - Emit a branch from the current insert
  /// block through the normal cleanup handling code (if any) and then
  /// on to \arg Dest.
  void EmitBranchThroughCleanup(JumpDest Dest);

  /// EmitBranchThroughEHCleanup - Emit a branch from the current
  /// insert block through the EH cleanup handling code (if any) and
  /// then on to \arg Dest.
  void EmitBranchThroughEHCleanup(UnwindDest Dest);

  /// getRethrowDest - Returns the unified outermost-scope rethrow
  /// destination.
  UnwindDest getRethrowDest();

  /// BeginConditionalBranch - Should be called before a conditional part of an
  /// expression is emitted. For example, before the RHS of the expression below
  /// is emitted:
  ///
  /// b && f(T());
  ///
  /// This is used to make sure that any temporaries created in the conditional
  /// branch are only destroyed if the branch is taken.
  void BeginConditionalBranch() {
    ++ConditionalBranchLevel;
  }

  /// EndConditionalBranch - Should be called after a conditional part of an
  /// expression has been emitted.
  void EndConditionalBranch() {
    assert(ConditionalBranchLevel != 0 &&
           "Conditional branch mismatch!");
    
    --ConditionalBranchLevel;
  }

private:
  CGDebugInfo *DebugInfo;

  /// IndirectBranch - The first time an indirect goto is seen we create a block
  /// with an indirect branch.  Every time we see the address of a label taken,
  /// we add the label to the indirect goto.  Every subsequent indirect goto is
  /// codegen'd as a jump to the IndirectBranch's basic block.
  llvm::IndirectBrInst *IndirectBranch;

  /// LocalDeclMap - This keeps track of the LLVM allocas or globals for local C
  /// decls.
  llvm::DenseMap<const Decl*, llvm::Value*> LocalDeclMap;

  /// LabelMap - This keeps track of the LLVM basic block for each C label.
  llvm::DenseMap<const LabelStmt*, JumpDest> LabelMap;

  // BreakContinueStack - This keeps track of where break and continue
  // statements should jump to.
  struct BreakContinue {
    BreakContinue(JumpDest Break, JumpDest Continue)
      : BreakBlock(Break), ContinueBlock(Continue) {}

    JumpDest BreakBlock;
    JumpDest ContinueBlock;
  };
  llvm::SmallVector<BreakContinue, 8> BreakContinueStack;

  /// SwitchInsn - This is nearest current switch instruction. It is null if if
  /// current context is not in a switch.
  llvm::SwitchInst *SwitchInsn;

  /// CaseRangeBlock - This block holds if condition check for last case
  /// statement range in current switch instruction.
  llvm::BasicBlock *CaseRangeBlock;

  // VLASizeMap - This keeps track of the associated size for each VLA type.
  // We track this by the size expression rather than the type itself because
  // in certain situations, like a const qualifier applied to an VLA typedef,
  // multiple VLA types can share the same size expression.
  // FIXME: Maybe this could be a stack of maps that is pushed/popped as we
  // enter/leave scopes.
  llvm::DenseMap<const Expr*, llvm::Value*> VLASizeMap;

  /// DidCallStackSave - Whether llvm.stacksave has been called. Used to avoid
  /// calling llvm.stacksave for multiple VLAs in the same scope.
  bool DidCallStackSave;

  /// A block containing a single 'unreachable' instruction.  Created
  /// lazily by getUnreachableBlock().
  llvm::BasicBlock *UnreachableBlock;

  /// CXXThisDecl - When generating code for a C++ member function,
  /// this will hold the implicit 'this' declaration.
  ImplicitParamDecl *CXXThisDecl;
  llvm::Value *CXXThisValue;

  /// CXXVTTDecl - When generating code for a base object constructor or
  /// base object destructor with virtual bases, this will hold the implicit
  /// VTT parameter.
  ImplicitParamDecl *CXXVTTDecl;
  llvm::Value *CXXVTTValue;
  
  /// ConditionalBranchLevel - Contains the nesting level of the current
  /// conditional branch. This is used so that we know if a temporary should be
  /// destroyed conditionally.
  unsigned ConditionalBranchLevel;


  /// ByrefValueInfoMap - For each __block variable, contains a pair of the LLVM
  /// type as well as the field number that contains the actual data.
  llvm::DenseMap<const ValueDecl *, std::pair<const llvm::Type *, 
                                              unsigned> > ByRefValueInfo;
  
  /// getByrefValueFieldNumber - Given a declaration, returns the LLVM field
  /// number that holds the value.
  unsigned getByRefValueLLVMField(const ValueDecl *VD) const;

  llvm::BasicBlock *TerminateLandingPad;
  llvm::BasicBlock *TerminateHandler;
  llvm::BasicBlock *TrapBB;

public:
  CodeGenFunction(CodeGenModule &cgm);

  CodeGenTypes &getTypes() const { return CGM.getTypes(); }
  ASTContext &getContext() const;
  CGDebugInfo *getDebugInfo() { return DebugInfo; }

  /// Returns a pointer to the function's exception object slot, which
  /// is assigned in every landing pad.
  llvm::Value *getExceptionSlot();

  llvm::Value *getNormalCleanupDestSlot();
  llvm::Value *getEHCleanupDestSlot();

  llvm::BasicBlock *getUnreachableBlock() {
    if (!UnreachableBlock) {
      UnreachableBlock = createBasicBlock("unreachable");
      new llvm::UnreachableInst(getLLVMContext(), UnreachableBlock);
    }
    return UnreachableBlock;
  }

  llvm::BasicBlock *getInvokeDest() {
    if (!EHStack.requiresLandingPad()) return 0;
    return getInvokeDestImpl();
  }

  llvm::LLVMContext &getLLVMContext() { return VMContext; }

  //===--------------------------------------------------------------------===//
  //                                  Objective-C
  //===--------------------------------------------------------------------===//

  void GenerateObjCMethod(const ObjCMethodDecl *OMD);

  void StartObjCMethod(const ObjCMethodDecl *MD,
                       const ObjCContainerDecl *CD);

  /// GenerateObjCGetter - Synthesize an Objective-C property getter function.
  void GenerateObjCGetter(ObjCImplementationDecl *IMP,
                          const ObjCPropertyImplDecl *PID);
  void GenerateObjCCtorDtorMethod(ObjCImplementationDecl *IMP,
                                  ObjCMethodDecl *MD, bool ctor);

  /// GenerateObjCSetter - Synthesize an Objective-C property setter function
  /// for the given property.
  void GenerateObjCSetter(ObjCImplementationDecl *IMP,
                          const ObjCPropertyImplDecl *PID);
  bool IndirectObjCSetterArg(const CGFunctionInfo &FI);
  bool IvarTypeWithAggrGCObjects(QualType Ty);

  //===--------------------------------------------------------------------===//
  //                                  Block Bits
  //===--------------------------------------------------------------------===//

  llvm::Value *BuildBlockLiteralTmp(const BlockExpr *);
  llvm::Constant *BuildDescriptorBlockDecl(const BlockExpr *,
                                           const CGBlockInfo &Info,
                                           const llvm::StructType *,
                                           llvm::Constant *BlockVarLayout,
                                           std::vector<HelperInfo> *);

  llvm::Function *GenerateBlockFunction(GlobalDecl GD,
                                        const BlockExpr *BExpr,
                                        CGBlockInfo &Info,
                                        const Decl *OuterFuncDecl,
                                        llvm::Constant *& BlockVarLayout,
                                  llvm::DenseMap<const Decl*, llvm::Value*> ldm);

  llvm::Value *LoadBlockStruct();

  void AllocateBlockCXXThisPointer(const CXXThisExpr *E);
  void AllocateBlockDecl(const BlockDeclRefExpr *E);
  llvm::Value *GetAddrOfBlockDecl(const BlockDeclRefExpr *E) {
    return GetAddrOfBlockDecl(E->getDecl(), E->isByRef());
  }
  llvm::Value *GetAddrOfBlockDecl(const ValueDecl *D, bool ByRef);
  const llvm::Type *BuildByRefType(const ValueDecl *D);

  void GenerateCode(GlobalDecl GD, llvm::Function *Fn);
  void StartFunction(GlobalDecl GD, QualType RetTy,
                     llvm::Function *Fn,
                     const FunctionArgList &Args,
                     SourceLocation StartLoc);

  void EmitConstructorBody(FunctionArgList &Args);
  void EmitDestructorBody(FunctionArgList &Args);
  void EmitFunctionBody(FunctionArgList &Args);

  /// EmitReturnBlock - Emit the unified return block, trying to avoid its
  /// emission when possible.
  void EmitReturnBlock();

  /// FinishFunction - Complete IR generation of the current function. It is
  /// legal to call this function even if there is no current insertion point.
  void FinishFunction(SourceLocation EndLoc=SourceLocation());

  /// GenerateThunk - Generate a thunk for the given method.
  void GenerateThunk(llvm::Function *Fn, GlobalDecl GD, const ThunkInfo &Thunk);
  
  void EmitCtorPrologue(const CXXConstructorDecl *CD, CXXCtorType Type,
                        FunctionArgList &Args);

  /// InitializeVTablePointer - Initialize the vtable pointer of the given
  /// subobject.
  ///
  void InitializeVTablePointer(BaseSubobject Base, 
                               const CXXRecordDecl *NearestVBase,
                               uint64_t OffsetFromNearestVBase,
                               llvm::Constant *VTable,
                               const CXXRecordDecl *VTableClass);

  typedef llvm::SmallPtrSet<const CXXRecordDecl *, 4> VisitedVirtualBasesSetTy;
  void InitializeVTablePointers(BaseSubobject Base, 
                                const CXXRecordDecl *NearestVBase,
                                uint64_t OffsetFromNearestVBase,
                                bool BaseIsNonVirtualPrimaryBase,
                                llvm::Constant *VTable,
                                const CXXRecordDecl *VTableClass,
                                VisitedVirtualBasesSetTy& VBases);

  void InitializeVTablePointers(const CXXRecordDecl *ClassDecl);


  /// EnterDtorCleanups - Enter the cleanups necessary to complete the
  /// given phase of destruction for a destructor.  The end result
  /// should call destructors on members and base classes in reverse
  /// order of their construction.
  void EnterDtorCleanups(const CXXDestructorDecl *Dtor, CXXDtorType Type);

  /// ShouldInstrumentFunction - Return true if the current function should be
  /// instrumented with __cyg_profile_func_* calls
  bool ShouldInstrumentFunction();

  /// EmitFunctionInstrumentation - Emit LLVM code to call the specified
  /// instrumentation function with the current function and the call site, if
  /// function instrumentation is enabled.
  void EmitFunctionInstrumentation(const char *Fn);

  /// EmitFunctionProlog - Emit the target specific LLVM code to load the
  /// arguments for the given function. This is also responsible for naming the
  /// LLVM function arguments.
  void EmitFunctionProlog(const CGFunctionInfo &FI,
                          llvm::Function *Fn,
                          const FunctionArgList &Args);

  /// EmitFunctionEpilog - Emit the target specific LLVM code to return the
  /// given temporary.
  void EmitFunctionEpilog(const CGFunctionInfo &FI);

  /// EmitStartEHSpec - Emit the start of the exception spec.
  void EmitStartEHSpec(const Decl *D);

  /// EmitEndEHSpec - Emit the end of the exception spec.
  void EmitEndEHSpec(const Decl *D);

  /// getTerminateLandingPad - Return a landing pad that just calls terminate.
  llvm::BasicBlock *getTerminateLandingPad();

  /// getTerminateHandler - Return a handler (not a landing pad, just
  /// a catch handler) that just calls terminate.  This is used when
  /// a terminate scope encloses a try.
  llvm::BasicBlock *getTerminateHandler();

  const llvm::Type *ConvertTypeForMem(QualType T);
  const llvm::Type *ConvertType(QualType T);
  const llvm::Type *ConvertType(const TypeDecl *T) {
    return ConvertType(getContext().getTypeDeclType(T));
  }

  /// LoadObjCSelf - Load the value of self. This function is only valid while
  /// generating code for an Objective-C method.
  llvm::Value *LoadObjCSelf();

  /// TypeOfSelfObject - Return type of object that this self represents.
  QualType TypeOfSelfObject();

  /// hasAggregateLLVMType - Return true if the specified AST type will map into
  /// an aggregate LLVM type or is void.
  static bool hasAggregateLLVMType(QualType T);

  /// createBasicBlock - Create an LLVM basic block.
  llvm::BasicBlock *createBasicBlock(const char *Name="",
                                     llvm::Function *Parent=0,
                                     llvm::BasicBlock *InsertBefore=0) {
#ifdef NDEBUG
    return llvm::BasicBlock::Create(VMContext, "", Parent, InsertBefore);
#else
    return llvm::BasicBlock::Create(VMContext, Name, Parent, InsertBefore);
#endif
  }

  /// getBasicBlockForLabel - Return the LLVM basicblock that the specified
  /// label maps to.
  JumpDest getJumpDestForLabel(const LabelStmt *S);

  /// SimplifyForwardingBlocks - If the given basic block is only a branch to
  /// another basic block, simplify it. This assumes that no other code could
  /// potentially reference the basic block.
  void SimplifyForwardingBlocks(llvm::BasicBlock *BB);

  /// EmitBlock - Emit the given block \arg BB and set it as the insert point,
  /// adding a fall-through branch from the current insert block if
  /// necessary. It is legal to call this function even if there is no current
  /// insertion point.
  ///
  /// IsFinished - If true, indicates that the caller has finished emitting
  /// branches to the given block and does not expect to emit code into it. This
  /// means the block can be ignored if it is unreachable.
  void EmitBlock(llvm::BasicBlock *BB, bool IsFinished=false);

  /// EmitBranch - Emit a branch to the specified basic block from the current
  /// insert block, taking care to avoid creation of branches from dummy
  /// blocks. It is legal to call this function even if there is no current
  /// insertion point.
  ///
  /// This function clears the current insertion point. The caller should follow
  /// calls to this function with calls to Emit*Block prior to generation new
  /// code.
  void EmitBranch(llvm::BasicBlock *Block);

  /// HaveInsertPoint - True if an insertion point is defined. If not, this
  /// indicates that the current code being emitted is unreachable.
  bool HaveInsertPoint() const {
    return Builder.GetInsertBlock() != 0;
  }

  /// EnsureInsertPoint - Ensure that an insertion point is defined so that
  /// emitted IR has a place to go. Note that by definition, if this function
  /// creates a block then that block is unreachable; callers may do better to
  /// detect when no insertion point is defined and simply skip IR generation.
  void EnsureInsertPoint() {
    if (!HaveInsertPoint())
      EmitBlock(createBasicBlock());
  }

  /// ErrorUnsupported - Print out an error that codegen doesn't support the
  /// specified stmt yet.
  void ErrorUnsupported(const Stmt *S, const char *Type,
                        bool OmitOnError=false);

  //===--------------------------------------------------------------------===//
  //                                  Helpers
  //===--------------------------------------------------------------------===//

  LValue MakeAddrLValue(llvm::Value *V, QualType T, unsigned Alignment = 0) {
    return LValue::MakeAddr(V, T, Alignment, getContext());
  }

  /// CreateTempAlloca - This creates a alloca and inserts it into the entry
  /// block. The caller is responsible for setting an appropriate alignment on
  /// the alloca.
  llvm::AllocaInst *CreateTempAlloca(const llvm::Type *Ty,
                                     const llvm::Twine &Name = "tmp");

  /// InitTempAlloca - Provide an initial value for the given alloca.
  void InitTempAlloca(llvm::AllocaInst *Alloca, llvm::Value *Value);

  /// CreateIRTemp - Create a temporary IR object of the given type, with
  /// appropriate alignment. This routine should only be used when an temporary
  /// value needs to be stored into an alloca (for example, to avoid explicit
  /// PHI construction), but the type is the IR type, not the type appropriate
  /// for storing in memory.
  llvm::AllocaInst *CreateIRTemp(QualType T, const llvm::Twine &Name = "tmp");

  /// CreateMemTemp - Create a temporary memory object of the given type, with
  /// appropriate alignment.
  llvm::AllocaInst *CreateMemTemp(QualType T, const llvm::Twine &Name = "tmp");

  /// EvaluateExprAsBool - Perform the usual unary conversions on the specified
  /// expression and compare the result against zero, returning an Int1Ty value.
  llvm::Value *EvaluateExprAsBool(const Expr *E);

  /// EmitAnyExpr - Emit code to compute the specified expression which can have
  /// any type.  The result is returned as an RValue struct.  If this is an
  /// aggregate expression, the aggloc/agglocvolatile arguments indicate where
  /// the result should be returned.
  ///
  /// \param IgnoreResult - True if the resulting value isn't used.
  RValue EmitAnyExpr(const Expr *E, llvm::Value *AggLoc = 0,
                     bool IsAggLocVolatile = false, bool IgnoreResult = false,
                     bool IsInitializer = false);

  // EmitVAListRef - Emit a "reference" to a va_list; this is either the address
  // or the value of the expression, depending on how va_list is defined.
  llvm::Value *EmitVAListRef(const Expr *E);

  /// EmitAnyExprToTemp - Similary to EmitAnyExpr(), however, the result will
  /// always be accessible even if no aggregate location is provided.
  RValue EmitAnyExprToTemp(const Expr *E, bool IsAggLocVolatile = false,
                           bool IsInitializer = false);

  /// EmitsAnyExprToMem - Emits the code necessary to evaluate an
  /// arbitrary expression into the given memory location.
  void EmitAnyExprToMem(const Expr *E, llvm::Value *Location,
                        bool IsLocationVolatile = false,
                        bool IsInitializer = false);

  /// EmitAggregateCopy - Emit an aggrate copy.
  ///
  /// \param isVolatile - True iff either the source or the destination is
  /// volatile.
  void EmitAggregateCopy(llvm::Value *DestPtr, llvm::Value *SrcPtr,
                         QualType EltTy, bool isVolatile=false);

  /// StartBlock - Start new block named N. If insert block is a dummy block
  /// then reuse it.
  void StartBlock(const char *N);

  /// GetAddrOfStaticLocalVar - Return the address of a static local variable.
  llvm::Constant *GetAddrOfStaticLocalVar(const VarDecl *BVD) {
    return cast<llvm::Constant>(GetAddrOfLocalVar(BVD));
  }

  /// GetAddrOfLocalVar - Return the address of a local variable.
  llvm::Value *GetAddrOfLocalVar(const VarDecl *VD) {
    llvm::Value *Res = LocalDeclMap[VD];
    assert(Res && "Invalid argument to GetAddrOfLocalVar(), no decl!");
    return Res;
  }

  /// getAccessedFieldNo - Given an encoded value and a result number, return
  /// the input field number being accessed.
  static unsigned getAccessedFieldNo(unsigned Idx, const llvm::Constant *Elts);

  llvm::BlockAddress *GetAddrOfLabel(const LabelStmt *L);
  llvm::BasicBlock *GetIndirectGotoBlock();

  /// EmitNullInitialization - Generate code to set a value of the given type to
  /// null, If the type contains data member pointers, they will be initialized
  /// to -1 in accordance with the Itanium C++ ABI.
  void EmitNullInitialization(llvm::Value *DestPtr, QualType Ty);

  // EmitVAArg - Generate code to get an argument from the passed in pointer
  // and update it accordingly. The return value is a pointer to the argument.
  // FIXME: We should be able to get rid of this method and use the va_arg
  // instruction in LLVM instead once it works well enough.
  llvm::Value *EmitVAArg(llvm::Value *VAListAddr, QualType Ty);

  /// EmitVLASize - Generate code for any VLA size expressions that might occur
  /// in a variably modified type. If Ty is a VLA, will return the value that
  /// corresponds to the size in bytes of the VLA type. Will return 0 otherwise.
  ///
  /// This function can be called with a null (unreachable) insert point.
  llvm::Value *EmitVLASize(QualType Ty);

  // GetVLASize - Returns an LLVM value that corresponds to the size in bytes
  // of a variable length array type.
  llvm::Value *GetVLASize(const VariableArrayType *);

  /// LoadCXXThis - Load the value of 'this'. This function is only valid while
  /// generating code for an C++ member function.
  llvm::Value *LoadCXXThis() {
    assert(CXXThisValue && "no 'this' value for this function");
    return CXXThisValue;
  }

  /// LoadCXXVTT - Load the VTT parameter to base constructors/destructors have
  /// virtual bases.
  llvm::Value *LoadCXXVTT() {
    assert(CXXVTTValue && "no VTT value for this function");
    return CXXVTTValue;
  }

  /// GetAddressOfBaseOfCompleteClass - Convert the given pointer to a
  /// complete class to the given direct base.
  llvm::Value *
  GetAddressOfDirectBaseInCompleteClass(llvm::Value *Value,
                                        const CXXRecordDecl *Derived,
                                        const CXXRecordDecl *Base,
                                        bool BaseIsVirtual);

  /// GetAddressOfBaseClass - This function will add the necessary delta to the
  /// load of 'this' and returns address of the base class.
  llvm::Value *GetAddressOfBaseClass(llvm::Value *Value, 
                                     const CXXRecordDecl *Derived,
                                     CastExpr::path_const_iterator PathBegin,
                                     CastExpr::path_const_iterator PathEnd,
                                     bool NullCheckValue);

  llvm::Value *GetAddressOfDerivedClass(llvm::Value *Value,
                                        const CXXRecordDecl *Derived,
                                        CastExpr::path_const_iterator PathBegin,
                                        CastExpr::path_const_iterator PathEnd,
                                        bool NullCheckValue);

  llvm::Value *GetVirtualBaseClassOffset(llvm::Value *This,
                                         const CXXRecordDecl *ClassDecl,
                                         const CXXRecordDecl *BaseClassDecl);
    
  void EmitDelegateCXXConstructorCall(const CXXConstructorDecl *Ctor,
                                      CXXCtorType CtorType,
                                      const FunctionArgList &Args);
  void EmitCXXConstructorCall(const CXXConstructorDecl *D, CXXCtorType Type,
                              bool ForVirtualBase, llvm::Value *This,
                              CallExpr::const_arg_iterator ArgBeg,
                              CallExpr::const_arg_iterator ArgEnd);

  void EmitCXXAggrConstructorCall(const CXXConstructorDecl *D,
                                  const ConstantArrayType *ArrayTy,
                                  llvm::Value *ArrayPtr,
                                  CallExpr::const_arg_iterator ArgBeg,
                                  CallExpr::const_arg_iterator ArgEnd,
                                  bool ZeroInitialization = false);
  
  void EmitCXXAggrConstructorCall(const CXXConstructorDecl *D,
                                  llvm::Value *NumElements,
                                  llvm::Value *ArrayPtr,
                                  CallExpr::const_arg_iterator ArgBeg,
                                  CallExpr::const_arg_iterator ArgEnd,
                                  bool ZeroInitialization = false);

  void EmitCXXAggrDestructorCall(const CXXDestructorDecl *D,
                                 const ArrayType *Array,
                                 llvm::Value *This);

  void EmitCXXAggrDestructorCall(const CXXDestructorDecl *D,
                                 llvm::Value *NumElements,
                                 llvm::Value *This);

  llvm::Function *GenerateCXXAggrDestructorHelper(const CXXDestructorDecl *D,
                                                  const ArrayType *Array,
                                                  llvm::Value *This);

  void EmitCXXDestructorCall(const CXXDestructorDecl *D, CXXDtorType Type,
                             bool ForVirtualBase, llvm::Value *This);
  
  void EmitNewArrayInitializer(const CXXNewExpr *E, llvm::Value *NewPtr,
                               llvm::Value *NumElements);

  void EmitCXXTemporary(const CXXTemporary *Temporary, llvm::Value *Ptr);

  llvm::Value *EmitCXXNewExpr(const CXXNewExpr *E);
  void EmitCXXDeleteExpr(const CXXDeleteExpr *E);

  void EmitDeleteCall(const FunctionDecl *DeleteFD, llvm::Value *Ptr,
                      QualType DeleteTy);

  llvm::Value* EmitCXXTypeidExpr(const CXXTypeidExpr *E);
  llvm::Value *EmitDynamicCast(llvm::Value *V, const CXXDynamicCastExpr *DCE);

  void EmitCheck(llvm::Value *, unsigned Size);

  llvm::Value *EmitScalarPrePostIncDec(const UnaryOperator *E, LValue LV,
                                       bool isInc, bool isPre);
  ComplexPairTy EmitComplexPrePostIncDec(const UnaryOperator *E, LValue LV,
                                         bool isInc, bool isPre);
  //===--------------------------------------------------------------------===//
  //                            Declaration Emission
  //===--------------------------------------------------------------------===//

  /// EmitDecl - Emit a declaration.
  ///
  /// This function can be called with a null (unreachable) insert point.
  void EmitDecl(const Decl &D);

  /// EmitBlockVarDecl - Emit a block variable declaration.
  ///
  /// This function can be called with a null (unreachable) insert point.
  void EmitBlockVarDecl(const VarDecl &D);

  typedef void SpecialInitFn(CodeGenFunction &Init, const VarDecl &D,
                             llvm::Value *Address);

  /// EmitLocalBlockVarDecl - Emit a local block variable declaration.
  ///
  /// This function can be called with a null (unreachable) insert point.
  void EmitLocalBlockVarDecl(const VarDecl &D, SpecialInitFn *SpecialInit = 0);

  void EmitStaticBlockVarDecl(const VarDecl &D,
                              llvm::GlobalValue::LinkageTypes Linkage);

  /// EmitParmDecl - Emit a ParmVarDecl or an ImplicitParamDecl.
  void EmitParmDecl(const VarDecl &D, llvm::Value *Arg);

  //===--------------------------------------------------------------------===//
  //                             Statement Emission
  //===--------------------------------------------------------------------===//

  /// EmitStopPoint - Emit a debug stoppoint if we are emitting debug info.
  void EmitStopPoint(const Stmt *S);

  /// EmitStmt - Emit the code for the statement \arg S. It is legal to call
  /// this function even if there is no current insertion point.
  ///
  /// This function may clear the current insertion point; callers should use
  /// EnsureInsertPoint if they wish to subsequently generate code without first
  /// calling EmitBlock, EmitBranch, or EmitStmt.
  void EmitStmt(const Stmt *S);

  /// EmitSimpleStmt - Try to emit a "simple" statement which does not
  /// necessarily require an insertion point or debug information; typically
  /// because the statement amounts to a jump or a container of other
  /// statements.
  ///
  /// \return True if the statement was handled.
  bool EmitSimpleStmt(const Stmt *S);

  RValue EmitCompoundStmt(const CompoundStmt &S, bool GetLast = false,
                          llvm::Value *AggLoc = 0, bool isAggVol = false);

  /// EmitLabel - Emit the block for the given label. It is legal to call this
  /// function even if there is no current insertion point.
  void EmitLabel(const LabelStmt &S); // helper for EmitLabelStmt.

  void EmitLabelStmt(const LabelStmt &S);
  void EmitGotoStmt(const GotoStmt &S);
  void EmitIndirectGotoStmt(const IndirectGotoStmt &S);
  void EmitIfStmt(const IfStmt &S);
  void EmitWhileStmt(const WhileStmt &S);
  void EmitDoStmt(const DoStmt &S);
  void EmitForStmt(const ForStmt &S);
  void EmitReturnStmt(const ReturnStmt &S);
  void EmitDeclStmt(const DeclStmt &S);
  void EmitBreakStmt(const BreakStmt &S);
  void EmitContinueStmt(const ContinueStmt &S);
  void EmitSwitchStmt(const SwitchStmt &S);
  void EmitDefaultStmt(const DefaultStmt &S);
  void EmitCaseStmt(const CaseStmt &S);
  void EmitCaseStmtRange(const CaseStmt &S);
  void EmitAsmStmt(const AsmStmt &S);

  void EmitObjCForCollectionStmt(const ObjCForCollectionStmt &S);
  void EmitObjCAtTryStmt(const ObjCAtTryStmt &S);
  void EmitObjCAtThrowStmt(const ObjCAtThrowStmt &S);
  void EmitObjCAtSynchronizedStmt(const ObjCAtSynchronizedStmt &S);

  llvm::Constant *getUnwindResumeOrRethrowFn();
  void EnterCXXTryStmt(const CXXTryStmt &S, bool IsFnTryBlock = false);
  void ExitCXXTryStmt(const CXXTryStmt &S, bool IsFnTryBlock = false);

  void EmitCXXTryStmt(const CXXTryStmt &S);
  
  //===--------------------------------------------------------------------===//
  //                         LValue Expression Emission
  //===--------------------------------------------------------------------===//

  /// GetUndefRValue - Get an appropriate 'undef' rvalue for the given type.
  RValue GetUndefRValue(QualType Ty);

  /// EmitUnsupportedRValue - Emit a dummy r-value using the type of E
  /// and issue an ErrorUnsupported style diagnostic (using the
  /// provided Name).
  RValue EmitUnsupportedRValue(const Expr *E,
                               const char *Name);

  /// EmitUnsupportedLValue - Emit a dummy l-value using the type of E and issue
  /// an ErrorUnsupported style diagnostic (using the provided Name).
  LValue EmitUnsupportedLValue(const Expr *E,
                               const char *Name);

  /// EmitLValue - Emit code to compute a designator that specifies the location
  /// of the expression.
  ///
  /// This can return one of two things: a simple address or a bitfield
  /// reference.  In either case, the LLVM Value* in the LValue structure is
  /// guaranteed to be an LLVM pointer type.
  ///
  /// If this returns a bitfield reference, nothing about the pointee type of
  /// the LLVM value is known: For example, it may not be a pointer to an
  /// integer.
  ///
  /// If this returns a normal address, and if the lvalue's C type is fixed
  /// size, this method guarantees that the returned pointer type will point to
  /// an LLVM type of the same size of the lvalue's type.  If the lvalue has a
  /// variable length type, this is not possible.
  ///
  LValue EmitLValue(const Expr *E);

  /// EmitCheckedLValue - Same as EmitLValue but additionally we generate
  /// checking code to guard against undefined behavior.  This is only
  /// suitable when we know that the address will be used to access the
  /// object.
  LValue EmitCheckedLValue(const Expr *E);

  /// EmitLoadOfScalar - Load a scalar value from an address, taking
  /// care to appropriately convert from the memory representation to
  /// the LLVM value representation.
  llvm::Value *EmitLoadOfScalar(llvm::Value *Addr, bool Volatile,
                                unsigned Alignment, QualType Ty);

  /// EmitStoreOfScalar - Store a scalar value to an address, taking
  /// care to appropriately convert from the memory representation to
  /// the LLVM value representation.
  void EmitStoreOfScalar(llvm::Value *Value, llvm::Value *Addr,
                         bool Volatile, unsigned Alignment, QualType Ty);

  /// EmitLoadOfLValue - Given an expression that represents a value lvalue,
  /// this method emits the address of the lvalue, then loads the result as an
  /// rvalue, returning the rvalue.
  RValue EmitLoadOfLValue(LValue V, QualType LVType);
  RValue EmitLoadOfExtVectorElementLValue(LValue V, QualType LVType);
  RValue EmitLoadOfBitfieldLValue(LValue LV, QualType ExprType);
  RValue EmitLoadOfPropertyRefLValue(LValue LV, QualType ExprType);
  RValue EmitLoadOfKVCRefLValue(LValue LV, QualType ExprType);


  /// EmitStoreThroughLValue - Store the specified rvalue into the specified
  /// lvalue, where both are guaranteed to the have the same type, and that type
  /// is 'Ty'.
  void EmitStoreThroughLValue(RValue Src, LValue Dst, QualType Ty);
  void EmitStoreThroughExtVectorComponentLValue(RValue Src, LValue Dst,
                                                QualType Ty);
  void EmitStoreThroughPropertyRefLValue(RValue Src, LValue Dst, QualType Ty);
  void EmitStoreThroughKVCRefLValue(RValue Src, LValue Dst, QualType Ty);

  /// EmitStoreThroughLValue - Store Src into Dst with same constraints as
  /// EmitStoreThroughLValue.
  ///
  /// \param Result [out] - If non-null, this will be set to a Value* for the
  /// bit-field contents after the store, appropriate for use as the result of
  /// an assignment to the bit-field.
  void EmitStoreThroughBitfieldLValue(RValue Src, LValue Dst, QualType Ty,
                                      llvm::Value **Result=0);

  // Note: only availabe for agg return types
  LValue EmitBinaryOperatorLValue(const BinaryOperator *E);
  LValue EmitCompoundAssignOperatorLValue(const CompoundAssignOperator *E);
  // Note: only available for agg return types
  LValue EmitCallExprLValue(const CallExpr *E);
  // Note: only available for agg return types
  LValue EmitVAArgExprLValue(const VAArgExpr *E);
  LValue EmitDeclRefLValue(const DeclRefExpr *E);
  LValue EmitStringLiteralLValue(const StringLiteral *E);
  LValue EmitObjCEncodeExprLValue(const ObjCEncodeExpr *E);
  LValue EmitPredefinedLValue(const PredefinedExpr *E);
  LValue EmitUnaryOpLValue(const UnaryOperator *E);
  LValue EmitArraySubscriptExpr(const ArraySubscriptExpr *E);
  LValue EmitExtVectorElementExpr(const ExtVectorElementExpr *E);
  LValue EmitMemberExpr(const MemberExpr *E);
  LValue EmitObjCIsaExpr(const ObjCIsaExpr *E);
  LValue EmitCompoundLiteralLValue(const CompoundLiteralExpr *E);
  LValue EmitConditionalOperatorLValue(const ConditionalOperator *E);
  LValue EmitCastLValue(const CastExpr *E);
  LValue EmitNullInitializationLValue(const CXXScalarValueInitExpr *E);
  
  llvm::Value *EmitIvarOffset(const ObjCInterfaceDecl *Interface,
                              const ObjCIvarDecl *Ivar);
  LValue EmitLValueForAnonRecordField(llvm::Value* Base,
                                      const FieldDecl* Field,
                                      unsigned CVRQualifiers);
  LValue EmitLValueForField(llvm::Value* Base, const FieldDecl* Field,
                            unsigned CVRQualifiers);
  
  /// EmitLValueForFieldInitialization - Like EmitLValueForField, except that
  /// if the Field is a reference, this will return the address of the reference
  /// and not the address of the value stored in the reference.
  LValue EmitLValueForFieldInitialization(llvm::Value* Base, 
                                          const FieldDecl* Field,
                                          unsigned CVRQualifiers);
  
  LValue EmitLValueForIvar(QualType ObjectTy,
                           llvm::Value* Base, const ObjCIvarDecl *Ivar,
                           unsigned CVRQualifiers);

  LValue EmitLValueForBitfield(llvm::Value* Base, const FieldDecl* Field,
                                unsigned CVRQualifiers);

  LValue EmitBlockDeclRefLValue(const BlockDeclRefExpr *E);

  LValue EmitCXXConstructLValue(const CXXConstructExpr *E);
  LValue EmitCXXBindTemporaryLValue(const CXXBindTemporaryExpr *E);
  LValue EmitCXXExprWithTemporariesLValue(const CXXExprWithTemporaries *E);
  LValue EmitCXXTypeidLValue(const CXXTypeidExpr *E);
  
  LValue EmitObjCMessageExprLValue(const ObjCMessageExpr *E);
  LValue EmitObjCIvarRefLValue(const ObjCIvarRefExpr *E);
  LValue EmitObjCPropertyRefLValue(const ObjCPropertyRefExpr *E);
  LValue EmitObjCKVCRefLValue(const ObjCImplicitSetterGetterRefExpr *E);
  LValue EmitObjCSuperExprLValue(const ObjCSuperExpr *E);
  LValue EmitStmtExprLValue(const StmtExpr *E);
  LValue EmitPointerToDataMemberBinaryExpr(const BinaryOperator *E);
  LValue EmitObjCSelectorLValue(const ObjCSelectorExpr *E);
  void   EmitDeclRefExprDbgValue(const DeclRefExpr *E, llvm::ConstantInt *Init);
  //===--------------------------------------------------------------------===//
  //                         Scalar Expression Emission
  //===--------------------------------------------------------------------===//

  /// EmitCall - Generate a call of the given function, expecting the given
  /// result type, and using the given argument list which specifies both the
  /// LLVM arguments and the types they were derived from.
  ///
  /// \param TargetDecl - If given, the decl of the function in a direct call;
  /// used to set attributes on the call (noreturn, etc.).
  RValue EmitCall(const CGFunctionInfo &FnInfo,
                  llvm::Value *Callee,
                  ReturnValueSlot ReturnValue,
                  const CallArgList &Args,
                  const Decl *TargetDecl = 0,
                  llvm::Instruction **callOrInvoke = 0);

  RValue EmitCall(QualType FnType, llvm::Value *Callee,
                  ReturnValueSlot ReturnValue,
                  CallExpr::const_arg_iterator ArgBeg,
                  CallExpr::const_arg_iterator ArgEnd,
                  const Decl *TargetDecl = 0);
  RValue EmitCallExpr(const CallExpr *E, 
                      ReturnValueSlot ReturnValue = ReturnValueSlot());

  llvm::CallSite EmitCallOrInvoke(llvm::Value *Callee,
                                  llvm::Value * const *ArgBegin,
                                  llvm::Value * const *ArgEnd,
                                  const llvm::Twine &Name = "");

  llvm::Value *BuildVirtualCall(const CXXMethodDecl *MD, llvm::Value *This,
                                const llvm::Type *Ty);
  llvm::Value *BuildVirtualCall(const CXXDestructorDecl *DD, CXXDtorType Type, 
                                llvm::Value *&This, const llvm::Type *Ty);

  RValue EmitCXXMemberCall(const CXXMethodDecl *MD,
                           llvm::Value *Callee,
                           ReturnValueSlot ReturnValue,
                           llvm::Value *This,
                           llvm::Value *VTT,
                           CallExpr::const_arg_iterator ArgBeg,
                           CallExpr::const_arg_iterator ArgEnd);
  RValue EmitCXXMemberCallExpr(const CXXMemberCallExpr *E,
                               ReturnValueSlot ReturnValue);
  RValue EmitCXXMemberPointerCallExpr(const CXXMemberCallExpr *E,
                                      ReturnValueSlot ReturnValue);

  RValue EmitCXXOperatorMemberCallExpr(const CXXOperatorCallExpr *E,
                                       const CXXMethodDecl *MD,
                                       ReturnValueSlot ReturnValue);

  
  RValue EmitBuiltinExpr(const FunctionDecl *FD,
                         unsigned BuiltinID, const CallExpr *E);

  RValue EmitBlockCallExpr(const CallExpr *E, ReturnValueSlot ReturnValue);

  /// EmitTargetBuiltinExpr - Emit the given builtin call. Returns 0 if the call
  /// is unhandled by the current target.
  llvm::Value *EmitTargetBuiltinExpr(unsigned BuiltinID, const CallExpr *E);

  llvm::Value *EmitARMBuiltinExpr(unsigned BuiltinID, const CallExpr *E);
  llvm::Value *EmitNeonCall(llvm::Function *F, 
                            llvm::SmallVectorImpl<llvm::Value*> &O,
                            const char *name, bool splat = false,
                            unsigned shift = 0, bool rightshift = false);
  llvm::Value *EmitNeonSplat(llvm::Value *V, llvm::Constant *Idx,
                             bool widen = false);
  llvm::Value *EmitNeonShiftVector(llvm::Value *V, const llvm::Type *Ty,
                                   bool negateForRightShift);
  
  llvm::Value *EmitX86BuiltinExpr(unsigned BuiltinID, const CallExpr *E);
  llvm::Value *EmitPPCBuiltinExpr(unsigned BuiltinID, const CallExpr *E);

  llvm::Value *EmitObjCProtocolExpr(const ObjCProtocolExpr *E);
  llvm::Value *EmitObjCStringLiteral(const ObjCStringLiteral *E);
  llvm::Value *EmitObjCSelectorExpr(const ObjCSelectorExpr *E);
  RValue EmitObjCMessageExpr(const ObjCMessageExpr *E,
                             ReturnValueSlot Return = ReturnValueSlot());
  RValue EmitObjCPropertyGet(const Expr *E,
                             ReturnValueSlot Return = ReturnValueSlot());
  RValue EmitObjCSuperPropertyGet(const Expr *Exp, const Selector &S,
                                  ReturnValueSlot Return = ReturnValueSlot());
  void EmitObjCPropertySet(const Expr *E, RValue Src);
  void EmitObjCSuperPropertySet(const Expr *E, const Selector &S, RValue Src);


  /// EmitReferenceBindingToExpr - Emits a reference binding to the passed in
  /// expression. Will emit a temporary variable if E is not an LValue.
  RValue EmitReferenceBindingToExpr(const Expr* E, 
                                    const NamedDecl *InitializedDecl);

  //===--------------------------------------------------------------------===//
  //                           Expression Emission
  //===--------------------------------------------------------------------===//

  // Expressions are broken into three classes: scalar, complex, aggregate.

  /// EmitScalarExpr - Emit the computation of the specified expression of LLVM
  /// scalar type, returning the result.
  llvm::Value *EmitScalarExpr(const Expr *E , bool IgnoreResultAssign = false);

  /// EmitScalarConversion - Emit a conversion from the specified type to the
  /// specified destination type, both of which are LLVM scalar types.
  llvm::Value *EmitScalarConversion(llvm::Value *Src, QualType SrcTy,
                                    QualType DstTy);

  /// EmitComplexToScalarConversion - Emit a conversion from the specified
  /// complex type to the specified destination type, where the destination type
  /// is an LLVM scalar type.
  llvm::Value *EmitComplexToScalarConversion(ComplexPairTy Src, QualType SrcTy,
                                             QualType DstTy);


  /// EmitAggExpr - Emit the computation of the specified expression of
  /// aggregate type.  The result is computed into DestPtr.  Note that if
  /// DestPtr is null, the value of the aggregate expression is not needed.
  void EmitAggExpr(const Expr *E, llvm::Value *DestPtr, bool VolatileDest,
                   bool IgnoreResult = false, bool IsInitializer = false,
                   bool RequiresGCollection = false);

  /// EmitAggExprToLValue - Emit the computation of the specified expression of
  /// aggregate type into a temporary LValue.
  LValue EmitAggExprToLValue(const Expr *E);

  /// EmitGCMemmoveCollectable - Emit special API for structs with object
  /// pointers.
  void EmitGCMemmoveCollectable(llvm::Value *DestPtr, llvm::Value *SrcPtr,
                                QualType Ty);

  /// EmitComplexExpr - Emit the computation of the specified expression of
  /// complex type, returning the result.
  ComplexPairTy EmitComplexExpr(const Expr *E, bool IgnoreReal = false,
                                bool IgnoreImag = false,
                                bool IgnoreRealAssign = false,
                                bool IgnoreImagAssign = false);

  /// EmitComplexExprIntoAddr - Emit the computation of the specified expression
  /// of complex type, storing into the specified Value*.
  void EmitComplexExprIntoAddr(const Expr *E, llvm::Value *DestAddr,
                               bool DestIsVolatile);

  /// StoreComplexToAddr - Store a complex number into the specified address.
  void StoreComplexToAddr(ComplexPairTy V, llvm::Value *DestAddr,
                          bool DestIsVolatile);
  /// LoadComplexFromAddr - Load a complex number from the specified address.
  ComplexPairTy LoadComplexFromAddr(llvm::Value *SrcAddr, bool SrcIsVolatile);

  /// CreateStaticBlockVarDecl - Create a zero-initialized LLVM global for a
  /// static block var decl.
  llvm::GlobalVariable *CreateStaticBlockVarDecl(const VarDecl &D,
                                                 const char *Separator,
                                       llvm::GlobalValue::LinkageTypes Linkage);
  
  /// AddInitializerToGlobalBlockVarDecl - Add the initializer for 'D' to the
  /// global variable that has already been created for it.  If the initializer
  /// has a different type than GV does, this may free GV and return a different
  /// one.  Otherwise it just returns GV.
  llvm::GlobalVariable *
  AddInitializerToGlobalBlockVarDecl(const VarDecl &D,
                                     llvm::GlobalVariable *GV);
  

  /// EmitStaticCXXBlockVarDeclInit - Create the initializer for a C++ runtime
  /// initialized static block var decl.
  void EmitStaticCXXBlockVarDeclInit(const VarDecl &D,
                                     llvm::GlobalVariable *GV);

  /// EmitCXXGlobalVarDeclInit - Create the initializer for a C++
  /// variable with global storage.
  void EmitCXXGlobalVarDeclInit(const VarDecl &D, llvm::Constant *DeclPtr);

  /// EmitCXXGlobalDtorRegistration - Emits a call to register the global ptr
  /// with the C++ runtime so that its destructor will be called at exit.
  void EmitCXXGlobalDtorRegistration(llvm::Constant *DtorFn,
                                     llvm::Constant *DeclPtr);

  /// GenerateCXXGlobalInitFunc - Generates code for initializing global
  /// variables.
  void GenerateCXXGlobalInitFunc(llvm::Function *Fn,
                                 llvm::Constant **Decls,
                                 unsigned NumDecls);

  /// GenerateCXXGlobalDtorFunc - Generates code for destroying global
  /// variables.
  void GenerateCXXGlobalDtorFunc(llvm::Function *Fn,
                                 const std::vector<std::pair<llvm::WeakVH,
                                   llvm::Constant*> > &DtorsAndObjects);

  void GenerateCXXGlobalVarDeclInitFunc(llvm::Function *Fn, const VarDecl *D);

  void EmitCXXConstructExpr(llvm::Value *Dest, const CXXConstructExpr *E);

  RValue EmitCXXExprWithTemporaries(const CXXExprWithTemporaries *E,
                                    llvm::Value *AggLoc = 0,
                                    bool IsAggLocVolatile = false,
                                    bool IsInitializer = false);

  void EmitCXXThrowExpr(const CXXThrowExpr *E);

  //===--------------------------------------------------------------------===//
  //                             Internal Helpers
  //===--------------------------------------------------------------------===//

  /// ContainsLabel - Return true if the statement contains a label in it.  If
  /// this statement is not executed normally, it not containing a label means
  /// that we can just remove the code.
  static bool ContainsLabel(const Stmt *S, bool IgnoreCaseStmts = false);

  /// ConstantFoldsToSimpleInteger - If the specified expression does not fold
  /// to a constant, or if it does but contains a label, return 0.  If it
  /// constant folds to 'true' and does not contain a label, return 1, if it
  /// constant folds to 'false' and does not contain a label, return -1.
  int ConstantFoldsToSimpleInteger(const Expr *Cond);

  /// EmitBranchOnBoolExpr - Emit a branch on a boolean condition (e.g. for an
  /// if statement) to the specified blocks.  Based on the condition, this might
  /// try to simplify the codegen of the conditional based on the branch.
  void EmitBranchOnBoolExpr(const Expr *Cond, llvm::BasicBlock *TrueBlock,
                            llvm::BasicBlock *FalseBlock);

  /// getTrapBB - Create a basic block that will call the trap intrinsic.  We'll
  /// generate a branch around the created basic block as necessary.
  llvm::BasicBlock *getTrapBB();
  
  /// EmitCallArg - Emit a single call argument.
  RValue EmitCallArg(const Expr *E, QualType ArgType);

  /// EmitDelegateCallArg - We are performing a delegate call; that
  /// is, the current function is delegating to another one.  Produce
  /// a r-value suitable for passing the given parameter.
  RValue EmitDelegateCallArg(const VarDecl *Param);

private:
  void EmitReturnOfRValue(RValue RV, QualType Ty);

  /// ExpandTypeFromArgs - Reconstruct a structure of type \arg Ty
  /// from function arguments into \arg Dst. See ABIArgInfo::Expand.
  ///
  /// \param AI - The first function argument of the expansion.
  /// \return The argument following the last expanded function
  /// argument.
  llvm::Function::arg_iterator
  ExpandTypeFromArgs(QualType Ty, LValue Dst,
                     llvm::Function::arg_iterator AI);

  /// ExpandTypeToArgs - Expand an RValue \arg Src, with the LLVM type for \arg
  /// Ty, into individual arguments on the provided vector \arg Args. See
  /// ABIArgInfo::Expand.
  void ExpandTypeToArgs(QualType Ty, RValue Src,
                        llvm::SmallVector<llvm::Value*, 16> &Args);

  llvm::Value* EmitAsmInput(const AsmStmt &S,
                            const TargetInfo::ConstraintInfo &Info,
                            const Expr *InputExpr, std::string &ConstraintStr);

  llvm::Value* EmitAsmInputLValue(const AsmStmt &S,
                                  const TargetInfo::ConstraintInfo &Info,
                                  LValue InputValue, QualType InputType,
                                  std::string &ConstraintStr);

  /// EmitCallArgs - Emit call arguments for a function.
  /// The CallArgTypeInfo parameter is used for iterating over the known
  /// argument types of the function being called.
  template<typename T>
  void EmitCallArgs(CallArgList& Args, const T* CallArgTypeInfo,
                    CallExpr::const_arg_iterator ArgBeg,
                    CallExpr::const_arg_iterator ArgEnd) {
      CallExpr::const_arg_iterator Arg = ArgBeg;

    // First, use the argument types that the type info knows about
    if (CallArgTypeInfo) {
      for (typename T::arg_type_iterator I = CallArgTypeInfo->arg_type_begin(),
           E = CallArgTypeInfo->arg_type_end(); I != E; ++I, ++Arg) {
        assert(Arg != ArgEnd && "Running over edge of argument list!");
        QualType ArgType = *I;

        assert(getContext().getCanonicalType(ArgType.getNonReferenceType()).
               getTypePtr() ==
               getContext().getCanonicalType(Arg->getType()).getTypePtr() &&
               "type mismatch in call argument!");

        Args.push_back(std::make_pair(EmitCallArg(*Arg, ArgType),
                                      ArgType));
      }

      // Either we've emitted all the call args, or we have a call to a
      // variadic function.
      assert((Arg == ArgEnd || CallArgTypeInfo->isVariadic()) &&
             "Extra arguments in non-variadic function!");

    }

    // If we still have any arguments, emit them using the type of the argument.
    for (; Arg != ArgEnd; ++Arg) {
      QualType ArgType = Arg->getType();
      Args.push_back(std::make_pair(EmitCallArg(*Arg, ArgType),
                                    ArgType));
    }
  }

  const TargetCodeGenInfo &getTargetHooks() const {
    return CGM.getTargetCodeGenInfo();
  }

  void EmitDeclMetadata();
};

/// CGBlockInfo - Information to generate a block literal.
class CGBlockInfo {
public:
  /// Name - The name of the block, kindof.
  const char *Name;
    
  /// DeclRefs - Variables from parent scopes that have been
  /// imported into this block.
  llvm::SmallVector<const BlockDeclRefExpr *, 8> DeclRefs;
    
  /// InnerBlocks - This block and the blocks it encloses.
  llvm::SmallPtrSet<const DeclContext *, 4> InnerBlocks;
    
  /// CXXThisRef - Non-null if 'this' was required somewhere, in
  /// which case this is that expression.
  const CXXThisExpr *CXXThisRef;
    
  /// NeedsObjCSelf - True if something in this block has an implicit
  /// reference to 'self'.
  bool NeedsObjCSelf;
    
  /// These are initialized by GenerateBlockFunction.
  bool BlockHasCopyDispose;
  CharUnits BlockSize;
  CharUnits BlockAlign;
  llvm::SmallVector<const Expr*, 8> BlockLayout;
    
  CGBlockInfo(const char *Name);
};
  
}  // end namespace CodeGen
}  // end namespace clang

#endif
