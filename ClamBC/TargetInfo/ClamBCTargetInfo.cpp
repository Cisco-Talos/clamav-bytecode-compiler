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

#include "llvm/Module.h"
#include "llvm/Target/TargetRegistry.h"
using namespace llvm;
Target TheClamBCTarget;

static unsigned ClamBC_TripleMatchQuality(const std::string &TT)
{
    if (TT == "clambc-generic-generic")
        return 20;
    return 0;
}

extern "C" void LLVMInitializeClamBCTargetInfo()
{
    TargetRegistry::RegisterTarget(TheClamBCTarget, "clambc",
                                   "ClamAV bytecode backend",
                                   ClamBC_TripleMatchQuality, false);
}
