/*
 *  Compile LLVM bytecode to ClamAV bytecode.
 *
 *  Copyright (C) 2009-2010 Sourcefire, Inc.
 *
 *  Authors: Andy Ragusa
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
#ifndef CLAMBC_ANALYZER_H_
#define CLAMBC_ANALYZER_H_

#include "clambc.h"

#include <llvm/ADT/DenseMap.h>
#include <llvm/ADT/DenseSet.h>
#include <llvm/ADT/StringMap.h>
#include <llvm/ADT/StringRef.h>
#include <llvm/ADT/Twine.h>
#include <llvm/Pass.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/Support/raw_ostream.h>

#include <llvm/Transforms/IPO/PassManagerBuilder.h>
#include <llvm/Passes/PassPlugin.h>
#include <llvm/Passes/PassBuilder.h>

#include <cstddef>
#include <vector>
#include <map>

class ClamBCAnalysis
{
  protected:
    typedef llvm::DenseMap<const llvm::Type *, unsigned> TypeMapTy;
    typedef llvm::DenseMap<const llvm::Function *, unsigned> FunctionMapTy;
    typedef llvm::DenseMap<const llvm::GlobalVariable *, unsigned> GlobalMapTy;
    typedef llvm::DenseMap<const llvm::ConstantExpr *, const llvm::GlobalVariable *> CEMapTy;
    typedef llvm::DenseMap<const llvm::MDNode *, unsigned> DbgMapTy;

    llvm::Module *pMod = nullptr;
    unsigned kind      = 0;
    std::string copyright;
    std::string logicalSignature;
    std::string virusnames;
    unsigned startTID = 0;
    TypeMapTy typeIDs;
    std::vector<const llvm::Type *> extraTypes;
    CEMapTy CEMap;
    FunctionMapTy functionIDs;
    DbgMapTy dbgMap;
    bool anyDbgIds = false;
    llvm::StringMap<unsigned> apiMap;
    llvm::StringMap<unsigned> globalsMap;
    GlobalMapTy globals;
    llvm::StringMap<unsigned> banMap;
    FunctionMapTy apiCalls;
    unsigned maxApi = 0;
    std::vector<const llvm::Function *> apis;
    unsigned maxGlobal = 0;
    std::vector<llvm::Constant *> globalInits;
    std::vector<const llvm::MDNode *> mds;

    virtual void printGlobals(uint16_t stid);

    /* TODO
     *
     * bytecode_api_decl.c.h
     *
     * Temporarily did this to populate the api map of the clamav functions that are allowed.  Previously,
     * there was c++ code that would parse the header file and read in the api's.  I am planning on having them
     * compiled into the module.
     *
     * bytecode_api_decl.c.h includes 5 potentially problematic files.
     * clamav-types.h => stored in the clamav build directory
     * type_desc.h => stored in clamav_checkout/libclamav
     * bytecode_api.h => stored in clamav install directory somewhere
     * bytecode_api_impl.h => stored in clamav_checkout/libclamav
     * bytecode_priv.h => stored in clamav_checkout/libclamav
     *
     * For NOW, we are just going to hardcode the api map.
     *
     * Eventually we will have clamav install api headers as part of the build, and just read those.
     */
    virtual void populateAPIMap();

  public:
    static char ID;
    explicit ClamBCAnalysis()
    {

        populateAPIMap();

        // Assign IDs to globals. Each global variable that is filled by libclamav
        // must be listed here.
        globalsMap["__clambc_match_counts"]  = GLOBAL_MATCH_COUNTS;
        globalsMap["__clambc_virusnames"]    = GLOBAL_VIRUSNAMES;
        globalsMap["__clambc_pedata"]        = GLOBAL_PEDATA;
        globalsMap["__clambc_filesize"]      = GLOBAL_FILESIZE;
        globalsMap["__clambc_match_offsets"] = GLOBAL_MATCH_OFFSETS;
    }

    ~ClamBCAnalysis() {}
    virtual void run(llvm::Module &m);

    virtual uint32_t getTypeID(const llvm::Type *const t)
    {
        TypeMapTy::iterator I = typeIDs.find(t);
        assert((I != typeIDs.end()) && "Type ID requested for unknown type");
        return I->second;
    }

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
        assert((I != CEMap.end()) && "Requested ID for non-existent constant expr");
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

    virtual const std::vector<const llvm::Type *> &getExtraTypes() const
    {
        return extraTypes;
    }

    virtual unsigned getKind() const
    {
        return kind;
    }

    virtual unsigned getStartTID() const
    {
        return startTID;
    }

    virtual std::string getCopyright() const
    {
        return copyright;
    }

    virtual const std::string &getLogicalSignature() const
    {
        return logicalSignature;
    }

    virtual const llvm::StringMap<unsigned> &getAPIMap() const
    {
        return apiMap;
    }

    virtual const llvm::StringMap<unsigned> &getBanMap() const
    {
        return banMap;
    }

    virtual unsigned getMaxApi() const
    {
        return maxApi;
    }

    virtual const FunctionMapTy &getApiCalls() const
    {
        return apiCalls;
    }

    virtual const std::vector<const llvm::Function *> &getApis() const
    {
        return apis;
    }

    virtual unsigned getMaxGlobal() const
    {
        return maxGlobal;
    }

    virtual const std::vector<llvm::Constant *> getGlobalInits() const
    {
        return globalInits;
    }

    virtual const std::vector<const llvm::MDNode *> &getMDs() const
    {
        return mds;
    }

    virtual unsigned getFunctionID(const llvm::Function *F)
    {
        FunctionMapTy::iterator I = functionIDs.find(F);
        assert(I != functionIDs.end() &&
               "Function ID requested for unknown function");
        return I->second;
    }

    virtual TypeMapTy getTypeIDs()
    {
        return typeIDs;
    }

    virtual const std::string &getVirusnames() const
    {
        return virusnames;
    }
};

class ClamBCAnalyzer : public llvm::AnalysisInfoMixin<ClamBCAnalyzer>
{
  protected:
    ClamBCAnalysis clamBCAnalysis;

  public:
    friend llvm::AnalysisInfoMixin<ClamBCAnalyzer>;
    static llvm::AnalysisKey Key;

    ClamBCAnalyzer()
        : clamBCAnalysis() {}
    virtual ~ClamBCAnalyzer() {}

    typedef ClamBCAnalysis Result;

    ClamBCAnalysis &run(llvm::Module &mod, llvm::ModuleAnalysisManager &mam)
    {
        clamBCAnalysis.run(mod);

        return clamBCAnalysis;
    }
};

#endif // CLAMBC_ANALYZER_H_
