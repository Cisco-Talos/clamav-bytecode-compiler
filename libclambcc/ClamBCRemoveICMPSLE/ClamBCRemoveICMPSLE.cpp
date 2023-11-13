/*
 *  Compile LLVM bytecode to ClamAV bytecode.
 *
 *  Copyright (C) 2020-2023 Sourcefire, Inc.
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

#include "clambc.h"

#include <llvm/IR/Module.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Support/raw_ostream.h>

#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/PassPlugin.h>
#include <llvm/Analysis/FunctionPropertiesAnalysis.h>

#include <vector>

using namespace llvm;
using namespace std;

/* Modeled after CallGraphAnalysis */

namespace
{
struct ClamBCRemoveICMPSLE : public PassInfoMixin<ClamBCRemoveICMPSLE> {
  protected:
    Module *pMod  = nullptr;
    bool bChanged = false;

    virtual void gatherInstructions(Function *pFunc, std::vector<ICmpInst *> &insts)
    {
        for (auto i = pFunc->begin(), e = pFunc->end(); i != e; i++) {
            BasicBlock *pBB = llvm::cast<BasicBlock>(i);
            for (auto bbi = pBB->begin(), bbe = pBB->end(); bbi != bbe; bbi++) {
                ICmpInst *inst = llvm::dyn_cast<ICmpInst>(bbi);
                if (inst) {
                    if (CmpInst::ICMP_SLE == inst->getPredicate()) {
                        insts.push_back(inst);
                    }
                }
            }
        }
    }

    virtual void processFunction(Function *pFunc)
    {
        std::vector<ICmpInst *> insts;
        gatherInstructions(pFunc, insts);

        for (size_t i = 0; i < insts.size(); i++) {
            insts[i]->swapOperands();
        }
    }

  public:
    virtual ~ClamBCRemoveICMPSLE() {}

    PreservedAnalyses run(Module &m, ModuleAnalysisManager &MAM)
    {
        pMod = &m;
        for (auto i = pMod->begin(), e = pMod->end(); i != e; i++) {
            Function *pFunc = llvm::dyn_cast<Function>(i);
            if (pFunc) {
                if (pFunc->isDeclaration()) {
                    continue;
                }

                processFunction(pFunc);
            }
        }

        if (bChanged) {
            return PreservedAnalyses::none();
        }
        return PreservedAnalyses::all();
    }
}; // end of struct ClamBCRemoveICMPSLE

} // end of anonymous namespace

// This part is the new way of registering your pass
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo()
{
    return {
        LLVM_PLUGIN_API_VERSION, "ClamBCRemoveICMPSLE", "v0.1",
        [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &FPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                    if (Name == "clambc-remove-icmp-sle") {
                        FPM.addPass(ClamBCRemoveICMPSLE());
                        return true;
                    }
                    return false;
                });
        }};
}
