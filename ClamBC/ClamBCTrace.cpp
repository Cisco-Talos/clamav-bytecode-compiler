/*
 *  Compile LLVM bytecode to ClamAV bytecode.
 *
 *  Copyright (C) 2009-2010 Sourcefire, Inc.
 *
 *  Authors: Török Edvin
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */
#include "llvm/System/DataTypes.h"
#include "clambc.h"
#include "ClamBCModule.h"
#include "ClamBCCommon.h"
#include "llvm/ADT/FoldingSet.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/Analysis/ConstantFolding.h"
#include "llvm/Analysis/DebugInfo.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/Config/config.h"
#include "llvm/DerivedTypes.h"
#include "llvm/IntrinsicInst.h"
#include "llvm/Module.h"
#include "llvm/Pass.h"
#include "llvm/PassManager.h"
#include "llvm/System/Host.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/ConstantRange.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/InstIterator.h"
#include "llvm/Support/IRBuilder.h"
#include "llvm/Support/FormattedStream.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetData.h"
#include "llvm/System/Process.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Transforms/IPO.h"
#include "llvm/Type.h"
using namespace llvm;

static cl::opt<bool>
InsertTracing("clambc-trace", cl::Hidden, cl::init(false),
              cl::desc("Enable tracing of bytecode execution"));

namespace {
class ClamBCTrace : public ModulePass {
public:
  static char ID;
  ClamBCTrace() : ModulePass((intptr_t)&ID) {}
  virtual const char *getPassName() const { return "ClamAV Bytecode Execution Tracing"; }
  virtual bool runOnModule(Module &M);
};
char ClamBCTrace::ID;
}

  bool ClamBCTrace::runOnModule(Module &M) {
    if (!InsertTracing)
      return false;
    unsigned MDDbgKind = M.getContext().getMDKindID("dbg");
    DenseMap<MDNode*, unsigned> scopeIDs;
    unsigned scopeid = 0;
    IRBuilder<> builder(M.getContext());

    const Type *I32Ty = Type::getInt32Ty(M.getContext());
    std::vector<const Type*> args;
    args.push_back(PointerType::getUnqual(Type::getInt8Ty(M.getContext())));
    args.push_back(I32Ty);
    const FunctionType *FTy = FunctionType::get(I32Ty, args, false);
    Constant *trace_directory = M.getOrInsertFunction("trace_directory", FTy);
    Constant *trace_scope = M.getOrInsertFunction("trace_scope", FTy);
    Constant *trace_source = M.getOrInsertFunction("trace_source", FTy);
    Constant *trace_op = M.getOrInsertFunction("trace_op", FTy);
    Constant *trace_value = M.getOrInsertFunction("trace_value", FTy);
    Constant *trace_ptr = M.getOrInsertFunction("trace_ptr", FTy);
    assert (trace_scope && trace_source && trace_op && trace_value &&
            trace_directory && trace_ptr);
    if (!trace_directory->use_empty() || !trace_scope->use_empty()
        || !trace_source->use_empty() || !trace_op->use_empty() ||
        !trace_value->use_empty() || !trace_ptr->use_empty())
      ClamBCModule::stop("Tracing API can only be used by compiler!\n", &M);

    for (Module::iterator I=M.begin(),E=M.end(); I != E; ++I) {
      Function &F = *I;
      if (F.isDeclaration())
        continue;
      bool first = true;
      for (Function::iterator J=I->begin(),JE=I->end(); J != JE; ++J) {
        MDNode *Scope = 0;
        StringRef directory;
        Value *LastFile = 0;
        unsigned SrcLine = 0;
        BasicBlock::iterator BBIt = J->begin();
        while (BBIt != J->end()) {
          while (isa<AllocaInst>(BBIt) || isa<PHINode>(BBIt)) ++BBIt;
          MDNode *Dbg = BBIt->getMetadata(MDDbgKind);
          if (!Dbg) {
            ++BBIt;
            continue;
          }
          builder.SetInsertPoint(&*J, BBIt);
          Instruction *II = BBIt;
          ++BBIt;
          DILocation Loc(Dbg);
          StringRef file = Loc.getFilename();
          Value *File = builder.CreateGlobalStringPtr(file.str().c_str());
          MDNode *NewScope = Loc.getScope().getNode();

          if (NewScope != Scope) {
            Scope = NewScope;
            unsigned sid = scopeIDs[NewScope];
            if (!sid) {
              sid = ++scopeid;
              scopeIDs[NewScope] = sid;
            }
            DIScope scope(Loc.getScope());
            while (scope.isLexicalBlock()) {
              DILexicalBlock lex(scope.getNode());
              scope = lex.getContext();
            }
            Value *Scope = 0;
            if (scope.isSubprogram()) {
              DISubprogram sub(scope.getNode());
              StringRef name = sub.getDisplayName();
              if (name.empty()) name = sub.getName();
              Scope = builder.CreateGlobalStringPtr(name.str().c_str());
            } else {
              assert(scope.isCompileUnit());
              DICompileUnit unit(scope.getNode());
              Scope =
                builder.CreateGlobalStringPtr(unit.getFilename().str().c_str());
            }
            builder.CreateCall2(trace_scope, Scope,
                                ConstantInt::get(Type::getInt32Ty(M.getContext()), sid));
          }
          unsigned newLine = Loc.getLineNumber();
          if (File != LastFile || newLine != SrcLine) {
            LastFile = File;
            SrcLine = newLine;
            if (Loc.getDirectory() != directory) {
              directory = Loc.getDirectory();
              builder.CreateCall2(trace_directory,
                                  builder.CreateGlobalStringPtr(directory.str().c_str()),
                                  ConstantInt::get(Type::getInt32Ty(M.getContext()), 0));
            }
            builder.CreateCall2(trace_source, File,
                                ConstantInt::get(Type::getInt32Ty(M.getContext()), newLine));
          }
          if (first) {
            first = false;
            for (Function::arg_iterator AI=I->arg_begin(),AE=I->arg_end();
                 AI != AE; ++AI) {
              if (isa<IntegerType>(AI->getType())) {
#if 0
                Value *V = builder.CreateIntCast(AI, Type::getInt32Ty(M.getContext()), false);
                Value *ValueName = builder.CreateGlobalStringPtr(AI->getName().data());
                builder.CreateCall2(trace_value, ValueName, V);
#endif
              } else if (isa<PointerType>(AI->getType())) {
                Value *V = builder.CreatePointerCast(AI, 
                                                     PointerType::getUnqual(Type::getInt8Ty(M.getContext())));
                builder.CreateCall2(trace_ptr, V,
                                    ConstantInt::get(Type::getInt32Ty(M.getContext()),
                                                     0));
              }
            }
          }
          std::string op;
          raw_string_ostream opstr(op);
          opstr << *II;
          Value *Op = builder.CreateGlobalStringPtr(opstr.str().c_str());
          builder.CreateCall2(trace_op, Op,
                              ConstantInt::get(Type::getInt32Ty(M.getContext()),
                                               Loc.getColumnNumber()));
          //Value *ValueName = builder.CreateGlobalStringPtr(II->getName().data());
          if (isa<IntegerType>(II->getType())) {
#if 0
            builder.SetInsertPoint(&*J, BBIt);
            Value *V = builder.CreateIntCast(II, Type::getInt32Ty(M.getContext()), false);
            builder.CreateCall2(trace_value, ValueName, V);
#endif
          } else if (isa<PointerType>(II->getType())) {
            builder.SetInsertPoint(&*J, BBIt);
            Value *V = builder.CreatePointerCast(II, 
                                                 PointerType::getUnqual(Type::getInt8Ty(M.getContext())));
            builder.CreateCall2(trace_ptr, V,
                                ConstantInt::get(Type::getInt32Ty(M.getContext()),
                                                 0));
          }
        }
      }
    }
    return true;
  }

llvm::ModulePass *createClamBCTrace()
{
  return new ClamBCTrace();
}
