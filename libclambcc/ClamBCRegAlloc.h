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
#ifndef CLAMBC_REGALLOC_H
#define CLAMBC_REGALLOC_H

#include "clambc.h"

#include <llvm/ADT/DenseMap.h>
#include <llvm/ADT/DenseSet.h>
#include <llvm/ADT/StringMap.h>
#include <llvm/ADT/StringRef.h>
#include <llvm/ADT/Twine.h>
#include <llvm/Pass.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/Support/FormattedStream.h>
#include <llvm/IR/Dominators.h>
#include <llvm/Passes/PassPlugin.h>
#include <llvm/Passes/PassBuilder.h>

#include <vector>
#include <map>
#include <cstddef>

class ClamBCRegAllocAnalysis
{
  public:
    static char ID;
    explicit ClamBCRegAllocAnalysis() {}

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

    virtual void setDominatorTree(llvm::DominatorTree *dt)
    {
        DT = dt;
    }

  private:
    void handlePHI(llvm::PHINode *PN);
    typedef llvm::DenseMap<const llvm::Value *, unsigned> ValueIDMap;
    ValueIDMap ValueMap;
    std::vector<const llvm::Value *> RevValueMap;
    llvm::DenseSet<const llvm::Instruction *> SkipMap;
    llvm::DominatorTree *DT;
};

class ClamBCRegAllocAnalyzer : public llvm::AnalysisInfoMixin<ClamBCRegAllocAnalyzer>
{

  protected:
    ClamBCRegAllocAnalysis clamBCRegAllocAnalysis;

  public:
    ClamBCRegAllocAnalyzer() {}
    virtual ~ClamBCRegAllocAnalyzer() {}

    friend AnalysisInfoMixin<ClamBCRegAllocAnalyzer>;
    static llvm::AnalysisKey Key;
    typedef ClamBCRegAllocAnalysis Result;

    ClamBCRegAllocAnalysis &run(llvm::Function &F, llvm::FunctionAnalysisManager &fam)
    {

        llvm::DominatorTree &dt = fam.getResult<llvm::DominatorTreeAnalysis>(F);
        clamBCRegAllocAnalysis.setDominatorTree(&dt);
        clamBCRegAllocAnalysis.runOnFunction(F);
        clamBCRegAllocAnalysis.setDominatorTree(NULL);

        return clamBCRegAllocAnalysis;
    }
};

#endif // CLAMBC_REGALLOC_H
