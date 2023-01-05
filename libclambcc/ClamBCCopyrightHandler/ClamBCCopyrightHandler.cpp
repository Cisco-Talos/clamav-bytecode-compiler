/*
 *  Compile LLVM bytecode to logical signatures.
 *
 *  Copyright (C) 2023 Sourcefire, Inc.
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

#include "ClamBCModule.h"
#include <llvm/Support/DataTypes.h>
#include "../Common/bytecode_api.h"
#include "clambc.h"
#include "ClamBCDiagnostics.h"
#include "ClamBCModule.h"
#include "ClamBCCommon.h"
#include "ClamBCUtilities.h"
#include "llvm/ADT/FoldingSet.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/Analysis/ConstantFolding.h"
#include <llvm/IR/DebugInfo.h>
#include "llvm/Analysis/ValueTracking.h"
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/Module.h>
#include <llvm/Pass.h>
//#include <llvm/IR/PassManager.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/CallSite.h>
#include <llvm/IR/ConstantRange.h>
#include "llvm/Support/Debug.h"
#include <llvm/IR/InstIterator.h>
#include "llvm/Support/FormattedStream.h"
#include "llvm/Support/raw_ostream.h"
#include <llvm/Support/Process.h>
#include "llvm/Transforms/Scalar.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Transforms/IPO.h"
#include <llvm/IR/Type.h>
//#include <llvm/IR/DataLayout.h>
#include <llvm/Transforms/Utils.h>
#include <llvm/LinkAllPasses.h>

#define DEBUG_TYPE "copyrighthandler"

using namespace llvm;

namespace
{

class ClamBCCopyrightHandler : public ModulePass
{
  public:
    static char ID;
    ClamBCCopyrightHandler()
        : ModulePass(ID) {}

    virtual bool runOnModule(Module &M);

  private:
    llvm::Module *pMod;
};

char ClamBCCopyrightHandler::ID = 0;
RegisterPass<ClamBCCopyrightHandler> X("clambc-copyright-handler",
                                       "ClamAV Copyright Handler");

bool ClamBCCopyrightHandler::runOnModule(Module &M)
{
    pMod      = &M;
    bool bRet = false;

    GlobalVariable *gCopyright = pMod->getGlobalVariable("__Copyright");
    std::string copyright;
    if (gCopyright && gCopyright->hasDefinitiveInitializer()) {
        Constant *C = gCopyright->getInitializer();
        StringRef c;
        if (!getConstantStringInfo(C, c)) {
            ClamBCStop("Failed to extract copyright string\n", pMod);
        }
        copyright = c.str();
    }

    if (copyright.length()) {
        NamedMDNode *Node = M.getOrInsertNamedMetadata("clambc.copyright");
        MDString *S       = MDString::get(M.getContext(), llvm::StringRef(copyright));
        MDNode *N         = MDNode::get(M.getContext(), S);
        Node->addOperand(N);
        bRet = true;
    }

    return bRet;
}

} // namespace
const PassInfo *const ClamBCCopyrightHandlerID = &X;

llvm::ModulePass *createClamBCCopyrightHandler()
{
    return new ClamBCCopyrightHandler();
}
