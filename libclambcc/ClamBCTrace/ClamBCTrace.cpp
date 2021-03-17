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
#include "clambc.h"
#include "ClamBCModule.h"
#include "ClamBCCommon.h"
#include "ClamBCUtilities.h"

#include <llvm/Support/DataTypes.h>
#include <llvm/ADT/FoldingSet.h>
#include <llvm/ADT/SmallPtrSet.h>
#include <llvm/Analysis/ConstantFolding.h>
#include <llvm/IR/DebugInfo.h>
#include <llvm/Analysis/ValueTracking.h>
//j#include "llvm/Config/config.h"
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/Module.h>
#include <llvm/Pass.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/Support/Host.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/IR/ConstantRange.h>
#include <llvm/Support/Debug.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/Support/FormattedStream.h>
#include <llvm/Support/raw_ostream.h>
//#include <llvm/Target/TargetData.h>
#include <llvm/Support/Process.h>
#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Utils/Local.h>
#include <llvm/Transforms/IPO.h>
#include <llvm/IR/Type.h>

using namespace llvm;

static cl::opt<bool>
    InsertTracing("clambc-trace", cl::Hidden, cl::init(false),
                  cl::desc("Enable tracing of bytecode execution"));

namespace
{
class ClamBCTrace : public ModulePass
{
  public:
    static char ID;
    ClamBCTrace()
        : ModulePass(ID) {}
    virtual llvm::StringRef getPassName() const
    {
        return "ClamAV Bytecode Execution Tracing";
    }
    virtual bool runOnModule(Module &M);
};
char ClamBCTrace::ID;
} // namespace

/*
declare i32 @trace_directory(i8*, i32)

declare i32 @trace_scope(i8*, i32)

declare i32 @trace_source(i8*, i32)

declare i32 @trace_op(i8*, i32)

declare i32 @trace_value(i8*, i32)

declare i32 @trace_ptr(i8*, i32)

*/

bool ClamBCTrace::runOnModule(Module &M)
{
    if (!InsertTracing)
        return false;
    unsigned MDDbgKind = M.getContext().getMDKindID("dbg");
    DenseMap<MDNode *, unsigned> scopeIDs;
    unsigned scopeid = 0;
    IRBuilder<> builder(M.getContext());

    Type *I32Ty = Type::getInt32Ty(M.getContext());
    std::vector<Type *> args;
    args.push_back(PointerType::getUnqual(Type::getInt8Ty(M.getContext())));
    args.push_back(I32Ty);
    FunctionType *FTy = FunctionType::get(I32Ty, args, false);
    /* llvm 10 replaces this with FunctionCallee.  */
    Constant *trace_directory = M.getOrInsertFunction("trace_directory", FTy);
    Constant *trace_scope     = M.getOrInsertFunction("trace_scope", FTy);
    Constant *trace_source    = M.getOrInsertFunction("trace_source", FTy);
    Constant *trace_op        = M.getOrInsertFunction("trace_op", FTy);
    Constant *trace_value     = M.getOrInsertFunction("trace_value", FTy);
    Constant *trace_ptr       = M.getOrInsertFunction("trace_ptr", FTy);
    assert(trace_scope && trace_source && trace_op && trace_value &&
           trace_directory && trace_ptr);
    if (!trace_directory->use_empty() || !trace_scope->use_empty() || !trace_source->use_empty() || !trace_op->use_empty() ||
        !trace_value->use_empty() || !trace_ptr->use_empty()) {
        ClamBCStop("Tracing API can only be used by compiler!\n", &M);
    }

    for (Module::iterator I = M.begin(), E = M.end(); I != E; ++I) {
        Function &F = *I;
        if (F.isDeclaration()) {
            continue;
        }
        bool first = true;
        for (Function::iterator J = I->begin(), JE = I->end(); J != JE; ++J) {
            MDNode *Scope = 0;
            StringRef directory;
            Value *LastFile           = 0;
            unsigned SrcLine          = 0;
            BasicBlock::iterator BBIt = J->begin();
            while (BBIt != J->end()) {
                while (isa<AllocaInst>(BBIt) || isa<PHINode>(BBIt)) ++BBIt;
                MDNode *Dbg = BBIt->getMetadata(MDDbgKind);
                if (!Dbg) {
                    ++BBIt;
                    continue;
                }
                builder.SetInsertPoint(&*J, BBIt);
                Instruction *II = llvm::cast<Instruction>(BBIt);
                ++BBIt;
                DILocation *Loc = II->getDebugLoc();
                StringRef file  = Loc->getFilename();
                Value *File     = builder.CreateGlobalStringPtr(file.str().c_str());
                /*just getting this to compile, so i can iterate the MDNode's in the Instruction, 
                 * and see which one i want.
                 */
                MDNode *NewScope = nullptr;

                if (NewScope != Scope) {
                    Scope        = NewScope;
                    unsigned sid = scopeIDs[NewScope];
                    if (!sid) {
                        sid                = ++scopeid;
                        scopeIDs[NewScope] = sid;
                    }
                    DIScope *scope = Loc->getScope();
                    while (llvm::isa<DILexicalBlock>(scope)) {
                        DILexicalBlock *lex = llvm::cast<DILexicalBlock>(scope);
                        //scope = lex->getContext();
                        /*aragusa: I have no idea if this is the right thing to do here.*/
                        scope = lex->getScope();
                    }

                    Value *Scope = 0;
                    if (llvm::isa<DISubprogram>(scope)) {
                        DISubprogram *sub = llvm::cast<DISubprogram>(scope);
                        //StringRef name = sub->getDisplayName();
                        //if (name.empty()) name = sub->getName();
                        StringRef name = sub->getName();
                        Scope          = builder.CreateGlobalStringPtr(name.str().c_str());
                    } else {
                        //assert(scope->isCompileUnit());
                        assert(llvm::isa<DICompileUnit>(scope) && "Not a DICompileUnit");
                        DICompileUnit *unit = llvm::cast<DICompileUnit>(scope);
                        Scope =
                            builder.CreateGlobalStringPtr(unit->getFilename().str().c_str());
                    }
                    std::vector<Value *> args = {
                        Scope, ConstantInt::get(Type::getInt32Ty(M.getContext()), sid)};
                    builder.CreateCall(trace_scope, args, "ClamBCTrace");
                }
                unsigned newLine = Loc->getLine();
                if (File != LastFile || newLine != SrcLine) {
                    LastFile = File;
                    SrcLine  = newLine;
                    if (Loc->getDirectory() != directory) {
                        directory                 = Loc->getDirectory();
                        std::vector<Value *> args = {
                            builder.CreateGlobalStringPtr(directory, "ClamBCTrace_gsp"), ConstantInt::get(Type::getInt32Ty(M.getContext()), 0)};
                        builder.CreateCall(trace_directory, args, "ClamBCTrace_dir");
                    }
                    std::vector<Value *> args = {
                        File, ConstantInt::get(Type::getInt32Ty(M.getContext()), newLine)};
                    builder.CreateCall(trace_source, args, "ClamBCTrace_lineno");
                }
                if (first) {
                    first = false;
                    for (Function::arg_iterator AI = I->arg_begin(), AE = I->arg_end();
                         AI != AE; ++AI) {
                        if (isa<IntegerType>(AI->getType())) {
#if 0
                Value *V = builder.CreateIntCast(AI, Type::getInt32Ty(M.getContext()), false);
                Value *ValueName = builder.CreateGlobalStringPtr(AI->getName().data());
                builder.CreateCall2(trace_value, ValueName, V);
#endif
                        } else if (isa<PointerType>(AI->getType())) {
                            Value *V                  = builder.CreatePointerCast(AI,
                                                                 PointerType::getUnqual(Type::getInt8Ty(M.getContext())));
                            std::vector<Value *> args = {
                                V, ConstantInt::get(Type::getInt32Ty(M.getContext()), 0)};
                            builder.CreateCall(trace_ptr, args, "ClamBCTrace_trace_ptr");
                        }
                    }
                }
                std::string op;
                raw_string_ostream opstr(op);
                opstr << *II;
                Value *Op                 = builder.CreateGlobalStringPtr(opstr.str().c_str());
                std::vector<Value *> args = {
                    Op, ConstantInt::get(Type::getInt32Ty(M.getContext()), Loc->getColumn())};
                builder.CreateCall(trace_op, args, "ClamBCTrace_trace_op");
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

                    std::vector<Value *> args = {
                        V, ConstantInt::get(Type::getInt32Ty(M.getContext()), 0)};
                    builder.CreateCall(trace_ptr, args, "ClamBCTrace_trace_ptr");
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
