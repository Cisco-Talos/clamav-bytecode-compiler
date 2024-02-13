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
// #define DEBUG_TYPE "bclowering"

#include <llvm/Passes/PassBuilder.h>
#include <llvm/CodeGen/IntrinsicLowering.h>

namespace ClamBCLowering
{

class ClamBCLowering : public llvm::PassInfoMixin<ClamBCLowering>
{
  public:
    ClamBCLowering() {}

    virtual ~ClamBCLowering() {}

    virtual llvm::StringRef getPassName() const
    {
        return "ClamAV Bytecode Lowering";
    }
    virtual llvm::PreservedAnalyses run(llvm::Module &m, llvm::ModuleAnalysisManager &MAM);
    virtual void getAnalysisUsage(llvm::AnalysisUsage &AU) const
    {
    }

  protected:
    virtual bool isFinal()      = 0;
    llvm::LLVMContext *pContext = nullptr;
    llvm::Module *pMod          = nullptr;

  private:
    void lowerIntrinsics(llvm::IntrinsicLowering *IL, llvm::Function &F);
    void simplifyOperands(llvm::Function &F);
    void downsizeIntrinsics(llvm::Function &F);
    void splitGEPZArray(llvm::Function &F);
    void fixupBitCasts(llvm::Function &F);
    void fixupGEPs(llvm::Function &F);
    void fixupPtrToInts(llvm::Function &F);
};

} // namespace ClamBCLowering
