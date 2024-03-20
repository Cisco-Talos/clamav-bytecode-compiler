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
#ifndef CLAMBC_MODULE_H
#define CLAMBC_MODULE_H

#include "clambc.h"

#include <llvm/ADT/DenseMap.h>
#include <llvm/ADT/DenseSet.h>
#include <llvm/ADT/StringMap.h>
#include <llvm/ADT/StringRef.h>
#include <llvm/ADT/Twine.h>
#include <llvm/Pass.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/Support/raw_ostream.h>

#include <vector>
#include <map>
#include <cstddef>

class ClamBCWriter;
class ClamBCRegAlloc;

namespace llvm
{
class Constant;
class ConstantExpr;
class DominatorTree;
class Function;
class FunctionPass;
class GlobalVariable;
class Instruction;
class MetadataBase;
class MetadataContext;
class Module;
class PassInfo;
class PHINode;
class Type;
class Twine;
class Value;
class formatted_raw_ostream;
} // namespace llvm

class ClamBCModule : public llvm::ModulePass
{
    typedef llvm::DenseMap<const llvm::Type *, unsigned> TypeMapTy;
    typedef llvm::DenseMap<const llvm::Function *, unsigned> FunctionMapTy;
    typedef llvm::DenseMap<const llvm::GlobalVariable *, unsigned> GlobalMapTy;
    typedef llvm::DenseMap<const llvm::ConstantExpr *, const llvm::GlobalVariable *> CEMapTy;
    typedef llvm::DenseMap<const llvm::MDNode *, unsigned> DbgMapTy;
    llvm::SmallVector<char, 4096> lineBuffer;
    std::vector<std::string> allLines;
    llvm::raw_svector_ostream Out;
    llvm::formatted_raw_ostream &OutReal;
    int lastLinePos;
    int maxLineLength;
    TypeMapTy typeIDs;
    std::vector<const llvm::Type *> extraTypes;
    FunctionMapTy functionIDs;
    llvm::StringMap<unsigned> apiMap;
    llvm::StringMap<unsigned> banMap;
    CEMapTy CEMap;
    GlobalMapTy globals;
    FunctionMapTy apiCalls;
    std::string LogicalSignature;
    std::string virusnames;
    llvm::StringMap<unsigned> globalsMap;
    unsigned kind;

    llvm::MetadataContext *TheMetadata;
    unsigned MDDbgKind;
    DbgMapTy dbgMap;
    bool anyDbgIds;
    char *copyright;
    unsigned startTID;

  public:
    static char ID;
    explicit ClamBCModule(llvm::formatted_raw_ostream &o,
                          const std::vector<std::string> &APIList);
    virtual llvm::StringRef getPassName() const
    {
        return "ClamAV Module: Bytecode Builder";
    }

    void writeGlobalMap(llvm::raw_ostream *Out);
    unsigned getDbgId(const llvm::MDNode *MB)
    {
        DbgMapTy::iterator I = dbgMap.find(MB);
        assert(I != dbgMap.end() && "Requested ID for non-existent Dbg MDNode");
        return I->second;
    }
    bool hasDbgIds() const
    {
        return anyDbgIds;
    }

    unsigned getGlobalID(const llvm::ConstantExpr *CE)
    {
        CEMapTy::iterator I = CEMap.find(CE);
        if (I == CEMap.end()) {
            CE->dump();
            assert(0 && "Requested ID for non-existent constant expr");
        }
        return getGlobalID(I->second);
    }
    unsigned getGlobalID(const llvm::GlobalVariable *GV)
    {
        GlobalMapTy::iterator I = globals.find(GV);
        assert(I != globals.end() && "Requested ID for non-existent global?");
        return I->second;
    }

    unsigned getExternalID(const llvm::Function *F)
    {
        FunctionMapTy::iterator I = apiCalls.find(F);
        assert(I != apiCalls.end() &&
               "Function ID requested for unknown external function");
        return I->second;
    }

    unsigned getFunctionID(const llvm::Function *F)
    {
        FunctionMapTy::iterator I = functionIDs.find(F);
        assert(I != functionIDs.end() &&
               "Function ID requested for unknown function");
        return I->second;
    }

    unsigned getTypeID(const llvm::Type *Ty)
    {
        TypeMapTy::iterator I = typeIDs.find(Ty);
        assert(I != typeIDs.end() && "Type ID requested for unknown type");
        return I->second;
    }

    virtual bool runOnModule(llvm::Module &M);
    virtual void getAnalysisUsage(llvm::AnalysisUsage &AU) const;

    void printNumber(uint64_t n, bool constant = false)
    {
        printNumber(Out, n, constant);
    }
    void printFixedNumber(uint64_t n, unsigned fixed)
    {
        printFixedNumber(Out, n, fixed);
    }
    void printOne(char c)
    {
        Out << c;
    }
    void printEOL();
    void finished(llvm::Module &M);
    void dumpTypes(llvm::raw_ostream &Out);

  private:
    void printModuleHeader(llvm::Module &M, unsigned startTID, unsigned maxLine);
    void printConstant(llvm::Module &M, llvm::Constant *C);
    void printGlobals(llvm::Module &M, uint16_t startTID);
    void compileLogicalSignature(llvm::Function &F, unsigned target);

    void describeType(llvm::raw_ostream &Out, const llvm::Type *Ty, llvm::Module *M);
    static void printNumber(llvm::raw_ostream &Out, uint64_t n,
                            bool constant = false);
    static void printFixedNumber(llvm::raw_ostream &Out, unsigned n,
                                 unsigned fixed);
    static void printConstData(llvm::raw_ostream &Out, const unsigned char *s,
                               size_t len);
    static void printString(llvm::raw_ostream &Out, const char *string, unsigned maxLength);
    void validateVirusName(const std::string &name);
};

class ClamBCRegAlloc : public llvm::FunctionPass
{
  public:
    static char ID;
    explicit ClamBCRegAlloc()
        : FunctionPass(ID) {}

    unsigned buildReverseMap(std::vector<const llvm::Value *> &);
    bool skipInstruction(const llvm::Instruction *I) const
    {
        return SkipMap.count(I);
    }

    unsigned getValueID(const llvm::Value *V) const
    {
        ValueIDMap::const_iterator I = ValueMap.find(V);
        if (I == ValueMap.end()) {
            DEBUGERR << "Error Value ID requested for unknown value (Printing below).\n";
            DEBUGERR << *V << "<END>\n";
            assert(0 && "Value ID requested for unknown value");
        }
        assert(I->second != ~0u &&
               "Value ID requested for unused/void instruction!");
        return I->second;
    }
    virtual bool runOnFunction(llvm::Function &F);
    virtual void getAnalysisUsage(llvm::AnalysisUsage &AU) const;
    void dump() const;
    void revdump() const;

  private:
    void handlePHI(llvm::PHINode *PN);
    typedef llvm::DenseMap<const llvm::Value *, unsigned> ValueIDMap;
    ValueIDMap ValueMap;
    std::vector<const llvm::Value *> RevValueMap;
    llvm::DenseSet<const llvm::Instruction *> SkipMap;
    llvm::DominatorTree *DT;
};

llvm::ModulePass *createClamBCWriter();
llvm::Pass *createClamBCRTChecks();
llvm::FunctionPass *createClamBCVerifier(bool final);
llvm::ModulePass *createClamBCLogicalCompiler();
llvm::ModulePass *createClamBCLowering(bool final);
llvm::ModulePass *createClamBCTrace();
llvm::ModulePass *createClamBCRebuild();
extern const llvm::PassInfo *const ClamBCRegAllocID;
#endif
