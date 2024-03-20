/*
 *  Compile LLVM bytecode to ClamAV bytecode.
 *
 *  Copyright (C) 2009-2010 Sourcefire, Inc.
 *
 *  Authors: Török Edvin, Andy Ragusa
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
#include "ClamBCAnalyzer.h"

#include "ClamBCCommon.h"
#include "ClamBCUtilities.h"

#include <llvm/IR/Dominators.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/Intrinsics.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/Pass.h>
#include <llvm/IR/InstIterator.h>

#include <llvm/Analysis/ValueTracking.h>

using namespace llvm;

AnalysisKey ClamBCAnalyzer::Key;

static unsigned getSpecialIndex(StringRef Name)
{
    // Ensure main/entrypoint is sorted before any other function
    // Function ID 0 must be the entrypoint!
    if (Name.equals("entrypoint"))
        return 0;
    if (Name.equals("logical_trigger"))
        return 1;
    return ~0u;
}

static bool compare_lt_functions(Function *A, Function *B)
{
    // Sort functions: first special functions,
    // next sorted by parameter count ascending, next sorted by name.
    StringRef NA   = A->getName();
    StringRef NB   = B->getName();
    unsigned naidx = getSpecialIndex(NA);
    unsigned nbidx = getSpecialIndex(NB);
    if (naidx != ~0u || nbidx != ~0u)
        return naidx < nbidx;
    naidx = A->getFunctionType()->getNumParams();
    nbidx = B->getFunctionType()->getNumParams();
    if (naidx != nbidx)
        return naidx < nbidx;
    return NA.compare(NB) < 0;
}

void ClamBCAnalysis::run(Module &m)
{
    pMod = &m;

    // Determine bytecode kind, default is 0 (generic).
    kind                   = 0;
    GlobalVariable *GVKind = pMod->getGlobalVariable("__clambc_kind");
    if (GVKind && GVKind->hasDefinitiveInitializer()) {
        kind = cast<ConstantInt>(GVKind->getInitializer())->getValue().getZExtValue();
        // GVKind->setLinkage(GlobalValue::InternalLinkage);
        // Do not set the linkage type to internal, because the optimizer will remove it.
        if (kind >= 65536) {
            ClamBCStop("Bytecode kind cannot be higher than 64k\n", pMod);
        }
    }

    GlobalVariable *G = pMod->getGlobalVariable("__Copyright");
    if (G && G->hasDefinitiveInitializer()) {
        Constant *C = G->getInitializer();
        // std::string c;
        StringRef c;
        if (!getConstantStringInfo(C, c)) {
            ClamBCStop("Failed to extract copyright string\n", pMod);
        }
        copyright = c.str();
        // Do not set the linkage type to internal because the optimizer will remove it.
    }

    // Logical signature created by ClamBCLogicalCompiler.
    NamedMDNode *Node = pMod->getNamedMetadata("clambc.logicalsignature");
    logicalSignature  = Node ? cast<MDString>(Node->getOperand(0)->getOperand(0))->getString() : "";

    Node       = pMod->getNamedMetadata("clambc.virusnames");
    virusnames = Node ? cast<MDString>(Node->getOperand(0)->getOperand(0))->getString() : "";

    unsigned tid, fid;
    // unsigned cid;
    startTID = tid = clamav::initTypeIDs(typeIDs, pMod->getContext());
    // arrays of [2 x i8] .. [7 x i8] used for struct padding
    for (unsigned i = 1; i < 8; i++) {
        const Type *Ty = llvm::ArrayType::get(llvm::Type::getInt8Ty(pMod->getContext()),
                                              i);
        typeIDs[Ty]    = tid++;
        extraTypes.push_back(Ty);
    }

    std::vector<const Type *> types;
    fid = 1;
    for (Module::global_iterator I = pMod->global_begin(); I != pMod->global_end(); ++I) {
        GlobalVariable *gv = llvm::cast<GlobalVariable>(I);
        std::set<Instruction *> insts;
        std::set<GlobalVariable *> globs;
        std::set<ConstantExpr *> ces;
        getDependentValues(gv, insts, globs, ces);

        /*It is necessary to add these twice, because there is a condition we
         * can't use global idx 0 or 1 in the interpreter, since the size will
         * be incorrect in the interpreter.  Look at line 2011 of bytecode.c
         */
        for (size_t loop = 0; loop < 2; loop++) {
            for (auto J : ces) {
                ConstantExpr *CE = llvm::cast<ConstantExpr>(J);
                // ClamAV bytecode doesn't support arbitrary constant expressions for
                // globals, so introduce helper globals for nested constant expressions.
                if (CE->getOpcode() != Instruction::GetElementPtr) {
                    if (CE->getOpcode() == Instruction::BitCast) {
                        GlobalVariable *GV = new GlobalVariable(*pMod, CE->getType(), true,
                                                                GlobalValue::InternalLinkage,
                                                                CE, I->getName() + "_bc");
                        CEMap[CE]          = GV;
                        continue;
                    }
                    errs() << "UNSUPPORTED: " << *CE << "\n";
                    ClamBCStop("Unsupported constant expression", pMod);
                }
                ConstantInt *C0 = dyn_cast<ConstantInt>(CE->getOperand(1));
                ConstantInt *C1 = dyn_cast<ConstantInt>(CE->getOperand(2));
                uint64_t v      = C1->getValue().getZExtValue();
                if (!C0->isZero()) {
                    errs() << "UNSUPPORTED: " << *CE << "\n";
                    ClamBCStop("Unsupported constant expression, nonzero first"
                               " index",
                               pMod);
                }

                const DataLayout &dataLayout = pMod->getDataLayout();
                std::vector<Value *> indices;
                for (unsigned i = 1; i < CE->getNumOperands(); i++) {
                    indices.push_back(CE->getOperand(i));
                }
                Type *IP8Ty = PointerType::getUnqual(Type::getInt8Ty(CE->getContext()));
                Type *type  = getResultType(CE);

                uint64_t idx = dataLayout.getIndexedOffsetInType(type, indices);

                Value *Idxs[1];
                Idxs[0]     = ConstantInt::get(Type::getInt64Ty(CE->getContext()), idx);
                Constant *C = ConstantExpr::getPointerCast(CE->getOperand(0), IP8Ty);
                ConstantExpr *NewCE =
                    cast<ConstantExpr>(ConstantExpr::getGetElementPtr(C->getType(), C,
                                                                      Idxs));
                NewCE = cast<ConstantExpr>(ConstantExpr::getPointerCast(NewCE,
                                                                        CE->getType()));
                if (CE != NewCE) {
                    CE->replaceAllUsesWith(NewCE);
                }
                CE                 = NewCE;
                GlobalVariable *GV = new GlobalVariable(*pMod, CE->getType(), true,
                                                        GlobalValue::InternalLinkage,
                                                        CE,
                                                        I->getName() + "_" + Twine(v));
                CEMap[CE]          = GV;
            }
        }

        // Collect types of all globals.
        const Type *Ty = I->getType();
        Ty             = I->getValueType();
        if (!typeIDs.count(Ty)) {
            extraTypes.push_back(Ty);
            typeIDs[Ty] = tid++;
            types.push_back(Ty);
        }
    }

    // Sort functions.
    std::vector<Function *> functions;
    for (Module::iterator I = pMod->begin(), E = pMod->end(); I != E;) {
        Function *F = &*I;
        ++I;
        functions.push_back(F);
    }

    /*
     * Remove all functions and re-insert them sorted by number of arguments.
     * This is a requirement of the writer, but I have not verified that it is
     * still necessary.
     */
    for (size_t i = 0; i < functions.size(); i++) {
        functions[i]->removeFromParent();
    }

    std::sort(functions.begin(), functions.end(), compare_lt_functions);
    for (std::vector<Function *>::iterator I = functions.begin(),
                                           E = functions.end();
         I != E; ++I) {
        pMod->getFunctionList().push_back(*I);
    }

    Function *ep = pMod->getFunction("entrypoint");
    if (!ep) {
        ClamBCStop("Bytecode must define an entrypoint (with 0 parameters)!\n", pMod);
    }
    if (ep->getFunctionType()->getNumParams() != 0) {
        ClamBCStop("Bytecode must define an entrypoint with 0 parameters!\n", pMod);
    }

    unsigned dbgid     = 0;
    unsigned MDDbgKind = pMod->getContext().getMDKindID("dbg");
    for (Module::iterator I = pMod->begin(), E = pMod->end(); I != E; ++I) {
        Function &F = *I;
        if (F.isDeclaration()) {
            // Don't add prototypes of debug intrinsics
            if (F.getName().substr(0, 8).equals("llvm.dbg")) {
                continue;
            }
            if (F.isVarArg()) {
                if (!F.getFunctionType()->getNumParams()) {
                    ClamBCStop("Calling implicitly declared function '" +
                                   F.getName() +
                                   "' is not supported (did you forget to implement "
                                   "it, or called the wrong function?)",
                               &F);
                } else {
                    ClamBCStop("Vararg functions are not supported ('" +
                                   F.getName() + "')",
                               &F);
                }
            }
            assert(!F.isVarArg());
            // Add function type
            const FunctionType *FTy = F.getFunctionType();
            if (!typeIDs.count(FTy)) {
                extraTypes.push_back(FTy);
                typeIDs[FTy] = tid++;
                types.push_back(FTy);
            }
            continue;
        }
        functionIDs[&F] = fid++;
        for (Function::arg_iterator I = F.arg_begin(), E = F.arg_end(); I != E; ++I) {
            const Type *Ty = I->getType();
            if (typeIDs.count(Ty))
                continue;
            types.push_back(Ty);
            extraTypes.push_back(Ty);
            typeIDs[Ty] = tid++;
        }

        for (inst_iterator II = inst_begin(F), IE = inst_end(F); II != IE; ++II) {
            const Type *Ty;
            // Skip debug intrinsics, so we don't add llvm.dbg.* types
            if (isa<DbgInfoIntrinsic>(&*II)) {
                continue;
            }

            // Collect types of all instructions.
            if (const AllocaInst *AI = dyn_cast<AllocaInst>(&*II)) {
                Ty = AI->getAllocatedType();
            } else {
                Ty = II->getType();
            }

            if (const GetElementPtrInst *GEPI = dyn_cast<GetElementPtrInst>(&*II)) {
                const Type *GTy = GEPI->getPointerOperand()->getType();
                if (!typeIDs.count(GTy)) {
                    types.push_back(GTy);
                    extraTypes.push_back(GTy);
                    typeIDs[GTy] = tid++;
                }
            }

            /*
             * Collect types of all operands to each instruction.  Basic Blocks
             * don't have types, so they can be skipped.
             */
            for (size_t i = 0; i < II->getNumOperands(); i++) {
                Value *operand = II->getOperand(i);
                if (llvm::isa<BasicBlock>(operand)) {
                    continue;
                }
                Type *pt = operand->getType();
                if (0 == typeIDs.count(pt)) {
                    types.push_back(pt);
                    extraTypes.push_back(pt);
                    typeIDs[pt] = tid++;
                }
            }

            if (typeIDs.count(Ty)) {
                continue;
            }
            types.push_back(Ty);
            extraTypes.push_back(Ty);
            typeIDs[Ty] = tid++;
        }
    }

    // If a type references other types, add those to our typemap too.
    while (!types.empty()) {
        const Type *ty = types.back();
        types.pop_back();

        for (Type::subtype_iterator I = ty->subtype_begin(), E = ty->subtype_end();
             I != E; ++I) {

            const Type *STy = llvm::cast<Type>(*I);

            if (llvm::isa<StructType>(STy)) {
                const StructType *pst = llvm::cast<StructType>(STy);
                if (pst->isOpaque()) {
                    if (llvm::isa<PointerType>(ty)) {
                        continue;
                    }
                    DEBUGERR << *STy << "<END>\n";
                    ClamBCStop("Bytecode cannot use abstract types (only pointers to them)!", pMod);
                }
            }
            if (!typeIDs.count(STy)) {
                extraTypes.push_back(STy);
                typeIDs[STy] = tid++;
                types.push_back(STy);
            }
        }
    }

    if (tid >= 65536) {
        ClamBCStop("Attempted to use more than 64k types", pMod);
    }

    printGlobals(startTID);
}

void ClamBCAnalysis::printGlobals(uint16_t stid)
{
    llvm::Module &M = *pMod;
    // Describe types
    maxApi = 0;
    for (Module::iterator I = pMod->begin(), E = pMod->end(); I != E; ++I) {
        llvm::Function *pFunc = llvm::cast<llvm::Function>(I);
        // Skip dead declarations
        if (I->use_empty()) {
            continue;
        }

        StringRef Name = I->getName();

        // Forbid declaring functions with same name as API call
        if (!I->isDeclaration()) {
            if (apiMap.count(Name)) {
                ClamBCStop("Attempted to declare function that is part of ClamAV API: " + Name,
                           pFunc);
            }
            continue;
        }

        // Forbid the usage of specified functions
        StringMap<unsigned>::iterator K = banMap.find(Name);
        if (K != banMap.end()) {
            ClamBCStop("Usage of function '" + Name + "' is currently disabled", &M);
        }

        // Skip llvm.* intrinsics
        if (Name.substr(0, 5).equals("llvm.")) {
            continue;
        }
        if (Name.equals("__is_bigendian") || Name.equals("memcmp") || Name.equals("abort")) {
            continue;
        }
        StringMap<unsigned>::iterator J = apiMap.find(Name);
        if (J == apiMap.end()) {
            ClamBCStop("Call to unknown external function: " + Name, pFunc);
        }

        apiCalls[&*I] = J->second;
        apis.push_back(&*I);
        if (J->second > maxApi) {
            maxApi = J->second;
        }
    }

    // Collect the initializers for global variables, and their type
    unsigned int i = 1;
    maxGlobal      = 0;
    SmallPtrSet<GlobalVariable *, 1> specialGlobals;
    for (StringMap<unsigned>::iterator I = globalsMap.begin(),
                                       E = globalsMap.end();
         I != E; ++I) {
        if (GlobalVariable *GV = pMod->getGlobalVariable(I->getKey())) {
            specialGlobals.insert(GV);
            globals[GV] = I->getValue();
            if (I->getValue() > maxGlobal)
                maxGlobal = I->getValue();
        }
    }
    if (GlobalVariable *GV = pMod->getGlobalVariable("__clambc_kind")) {
        specialGlobals.insert(GV);
    }

    globalInits.push_back(0); // ConstantPointerNul placeholder
    for (Module::global_iterator I = pMod->global_begin(), E = pMod->global_end(); I != E; ++I) {
        GlobalVariable *pgv = llvm::cast<GlobalVariable>(I);
        if (specialGlobals.count(pgv)) {
            continue;
        }
        if (!pgv->isConstant()) {
            // Non-constant globals can introduce potential race conditions, we
            // don't want that.
            ClamBCStop("Attempting to declare non-constant global variable: " +
                           pgv->getName(),
                       &M);
        }
        if (!pgv->hasDefinitiveInitializer()) {
            ClamBCStop("Attempting to declare a global variable without initializer: " +
                           pgv->getName(),
                       &M);
        }
        if (pgv->isThreadLocal()) {
            ClamBCStop("Attempting to declare thread local global variable: " +
                           pgv->getName(),
                       &M);
        }
        if (pgv->hasSection()) {
            ClamBCStop("Attempting to declare section for global variable: " +
                           pgv->getName(),
                       &M);
        }
        Constant *C = pgv->getInitializer();
        if (C->use_empty()) {
            continue;
        }
        globalInits.push_back(C);
        globals[pgv] = i++;
        if (i >= 32768) {
            ClamBCStop("Attempted to use more than 32k global variables!", &M);
        }
    }

    if (anyDbgIds) {
        mds.resize(dbgMap.size());

        unsigned mdid = dbgMap.size();
        for (DbgMapTy::iterator I = dbgMap.begin(), E = dbgMap.end();
             I != E; ++I) {
            mds[I->second] = I->first;
        }
        unsigned mdnodes = mdid;
        for (unsigned i = 0; i < mdnodes; i++) {
            const MDNode *B = mds[i];
            std::vector<const MDNode *> nodes;
            nodes.push_back(cast<MDNode>(B));
            while (!nodes.empty()) {
                const MDNode *N = nodes.back();
                nodes.pop_back();
                for (unsigned i = 0; i < N->getNumOperands(); i++) {
                    if (MDNode *MD = dyn_cast_or_null<MDNode>(N->getOperand(i))) {
                        if (!dbgMap.count(MD)) {
                            mds.push_back(MD);
                            dbgMap[MD] = mdid++;
                            nodes.push_back(MD);
                        }
                    }
                }
            }
        }
    }
}

// need to use bytecode_api_decl.c.h
void ClamBCAnalysis::populateAPIMap()
{
    unsigned id                          = 1;
    apiMap["test1"]                      = id++;
    apiMap["read"]                       = id++;
    apiMap["write"]                      = id++;
    apiMap["seek"]                       = id++;
    apiMap["setvirusname"]               = id++;
    apiMap["debug_print_str"]            = id++;
    apiMap["debug_print_uint"]           = id++;
    apiMap["disasm_x86"]                 = id++;
    apiMap["trace_directory"]            = id++;
    apiMap["trace_scope"]                = id++;
    apiMap["trace_source"]               = id++;
    apiMap["trace_op"]                   = id++;
    apiMap["trace_value"]                = id++;
    apiMap["trace_ptr"]                  = id++;
    apiMap["pe_rawaddr"]                 = id++;
    apiMap["file_find"]                  = id++;
    apiMap["file_byteat"]                = id++;
    apiMap["malloc"]                     = id++;
    apiMap["test2"]                      = id++;
    apiMap["get_pe_section"]             = id++;
    apiMap["fill_buffer"]                = id++;
    apiMap["extract_new"]                = id++;
    apiMap["read_number"]                = id++;
    apiMap["hashset_new"]                = id++;
    apiMap["hashset_add"]                = id++;
    apiMap["hashset_remove"]             = id++;
    apiMap["hashset_contains"]           = id++;
    apiMap["hashset_done"]               = id++;
    apiMap["hashset_empty"]              = id++;
    apiMap["buffer_pipe_new"]            = id++;
    apiMap["buffer_pipe_new_fromfile"]   = id++;
    apiMap["buffer_pipe_read_avail"]     = id++;
    apiMap["buffer_pipe_read_get"]       = id++;
    apiMap["buffer_pipe_read_stopped"]   = id++;
    apiMap["buffer_pipe_write_avail"]    = id++;
    apiMap["buffer_pipe_write_get"]      = id++;
    apiMap["buffer_pipe_write_stopped"]  = id++;
    apiMap["buffer_pipe_done"]           = id++;
    apiMap["inflate_init"]               = id++;
    apiMap["inflate_process"]            = id++;
    apiMap["inflate_done"]               = id++;
    apiMap["bytecode_rt_error"]          = id++;
    apiMap["jsnorm_init"]                = id++;
    apiMap["jsnorm_process"]             = id++;
    apiMap["jsnorm_done"]                = id++;
    apiMap["ilog2"]                      = id++;
    apiMap["ipow"]                       = id++;
    apiMap["iexp"]                       = id++;
    apiMap["isin"]                       = id++;
    apiMap["icos"]                       = id++;
    apiMap["memstr"]                     = id++;
    apiMap["hex2ui"]                     = id++;
    apiMap["atoi"]                       = id++;
    apiMap["debug_print_str_start"]      = id++;
    apiMap["debug_print_str_nonl"]       = id++;
    apiMap["entropy_buffer"]             = id++;
    apiMap["map_new"]                    = id++;
    apiMap["map_addkey"]                 = id++;
    apiMap["map_setvalue"]               = id++;
    apiMap["map_remove"]                 = id++;
    apiMap["map_find"]                   = id++;
    apiMap["map_getvaluesize"]           = id++;
    apiMap["map_getvalue"]               = id++;
    apiMap["map_done"]                   = id++;
    apiMap["file_find_limit"]            = id++;
    apiMap["engine_functionality_level"] = id++;
    apiMap["engine_dconf_level"]         = id++;
    apiMap["engine_scan_options"]        = id++;
    apiMap["engine_db_options"]          = id++;
    apiMap["extract_set_container"]      = id++;
    apiMap["input_switch"]               = id++;
    apiMap["get_environment"]            = id++;
    apiMap["disable_bytecode_if"]        = id++;
    apiMap["disable_jit_if"]             = id++;
    apiMap["version_compare"]            = id++;
    apiMap["check_platform"]             = id++;
    apiMap["pdf_get_obj_num"]            = id++;
    apiMap["pdf_get_flags"]              = id++;
    apiMap["pdf_set_flags"]              = id++;
    apiMap["pdf_lookupobj"]              = id++;
    apiMap["pdf_getobjsize"]             = id++;
    apiMap["pdf_getobj"]                 = id++;
    apiMap["pdf_getobjid"]               = id++;
    apiMap["pdf_getobjflags"]            = id++;
    apiMap["pdf_setobjflags"]            = id++;
    apiMap["pdf_get_offset"]             = id++;
    apiMap["pdf_get_phase"]              = id++;
    apiMap["pdf_get_dumpedobjid"]        = id++;
    apiMap["matchicon"]                  = id++;
    apiMap["running_on_jit"]             = id++;
    apiMap["get_file_reliability"]       = id++;
    apiMap["json_is_active"]             = id++;
    apiMap["json_get_object"]            = id++;
    apiMap["json_get_type"]              = id++;
    apiMap["json_get_array_length"]      = id++;
    apiMap["json_get_array_idx"]         = id++;
    apiMap["json_get_string_length"]     = id++;
    apiMap["json_get_string"]            = id++;
    apiMap["json_get_boolean"]           = id++;
    apiMap["json_get_int"]               = id++;
    apiMap["engine_scan_options_ex"]     = id++;
    apiMap["lzma_init"]                  = id++;
    apiMap["lzma_process"]               = id++;
    apiMap["lzma_done"]                  = id++;
    apiMap["bzip2_init"]                 = id++;
    apiMap["bzip2_process"]              = id++;
    apiMap["bzip2_done"]                 = id++;
}

// This part is the new way of registering your pass
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo()
{
    return {
        LLVM_PLUGIN_API_VERSION, "ClamBCAnalysis", "v0.1",
        [](PassBuilder &PB) {
            PB.registerAnalysisRegistrationCallback(
                [](ModuleAnalysisManager &mam) {
                    mam.registerPass([]() { return ClamBCAnalyzer(); });
                });
        }};
}
