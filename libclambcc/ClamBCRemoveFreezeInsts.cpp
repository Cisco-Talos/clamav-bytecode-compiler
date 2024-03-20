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
#include "ClamBCUtilities.h"

#include <llvm/IR/Module.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Support/raw_ostream.h>

#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/PassPlugin.h>

#include <vector>

using namespace llvm;
using namespace std;

namespace
{
/*
 * Freeze Instructions are to guarantee sane behaviour in the case of undefs or poison values. The interpreter
 * has no notion of freeze instructions, so we are removing them.  The verifier will fail if there are undef or
 * poison values in the IR, so this is safe to do.
 */
struct ClamBCRemoveFreezeInsts : public PassInfoMixin<ClamBCRemoveFreezeInsts> {
  protected:
    Module *pMod  = nullptr;
    bool bChanged = false;

    virtual void gatherFreezeInsts(Function *pFunc, std::vector<FreezeInst *> &freezeInsts)
    {
        for (auto fi = pFunc->begin(), fe = pFunc->end(); fi != fe; fi++) {
            BasicBlock *pBB = llvm::cast<BasicBlock>(fi);
            for (auto bi = pBB->begin(), be = pBB->end(); bi != be; bi++) {
                if (FreezeInst *pfi = llvm::dyn_cast<FreezeInst>(bi)) {
                    freezeInsts.push_back(pfi);
                }
            }
        }
    }

    virtual void processFunction(Function *pFunc)
    {
        vector<FreezeInst *> freezeInsts;
        gatherFreezeInsts(pFunc, freezeInsts);

        for (size_t i = 0; i < freezeInsts.size(); i++) {
            bChanged = true;

            FreezeInst *pfi = freezeInsts[i];
            pfi->replaceAllUsesWith(pfi->getOperand(0));
            pfi->eraseFromParent();
        }
    }

  public:
    virtual ~ClamBCRemoveFreezeInsts() {}

    PreservedAnalyses run(Module &m, ModuleAnalysisManager &MAM)
    {
        pMod = &m;

        for (auto i = pMod->begin(), e = pMod->end(); i != e; i++) {
            Function *pFunc = llvm::cast<Function>(i);
            if (pFunc->isDeclaration()) {
                continue;
            }

            processFunction(pFunc);
        }

        if (bChanged) {
            return PreservedAnalyses::none();
        } else {
            return PreservedAnalyses::all();
        }
    }
}; // end of struct ClamBCRemoveFreezeInsts

} // end of anonymous namespace

// This part is the new way of registering your pass
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo()
{
    return {
        LLVM_PLUGIN_API_VERSION, "ClamBCRemoveFreezeInsts", "v0.1",
        [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &FPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                    if (Name == "clambc-remove-freeze-insts") {
                        FPM.addPass(ClamBCRemoveFreezeInsts());
                        return true;
                    }
                    return false;
                });
        }};
}
