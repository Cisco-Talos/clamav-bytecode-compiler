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
 *  along with this program; if not, write to the Free Softwaref
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */

#include "ClamBCLowering.h"

#include "clambc.h"

#include <llvm/Passes/PassPlugin.h>

using namespace llvm;

namespace ClamBCLowering
{

class ClamBCLoweringNF : public ClamBCLowering
{
  public:
    ClamBCLoweringNF() {}
    virtual ~ClamBCLoweringNF() {}

  protected:
    virtual bool isFinal()
    {
        return false;
    }
};

// This part is the new way of registering your pass
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo()
{
    return {
        LLVM_PLUGIN_API_VERSION, "ClamBCLowering", "v0.1",
        [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &FPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                    if (Name == "clambc-lowering-notfinal") {
                        FPM.addPass(ClamBCLoweringNF());
                        return true;
                    }
                    return false;
                });
        }};
}

} // namespace ClamBCLowering
