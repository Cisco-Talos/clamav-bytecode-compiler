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

#ifndef CLAMBCTARGETMACHINE_H
#define CLAMBCTARGETMACHINE_H

#include "llvm/Target/TargetMachine.h"
#include "llvm/Target/TargetData.h"

namespace llvm
{

struct ClamBCTargetMachine : public TargetMachine {
    ClamBCTargetMachine(const Target &T, const std::string &TT, const std::string &FS)
        : TargetMachine(T) {}

    virtual bool WantsWholeFile() const
    {
        return true;
    }
    virtual bool addPassesToEmitWholeFile(PassManager &PM,
                                          formatted_raw_ostream &Out,
                                          CodeGenFileType FileType,
                                          CodeGenOpt::Level OptLevel,
                                          bool DisableVerify = false);

    virtual const TargetData *getTargetData() const
    {
        return 0;
    }
};
} // namespace llvm
#endif
