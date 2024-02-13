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

#include <llvm/ADT/DenseMap.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/Support/Compiler.h>

namespace clamav
{
static unsigned LLVM_ATTRIBUTE_USED initTypeIDs(llvm::DenseMap<const llvm::Type *, unsigned>
                                                    &typeIDs,
                                                llvm::LLVMContext &C)
{
    unsigned tid;
    // Void is typeid 0
    typeIDs[llvm::Type::getVoidTy(C)] = 0;

    // Type IDs 1 - 64 are i1 - i64.
    // Although we currently support only i1, i8, i16, i32, and i64 we reserve
    // typeIDs for arbitrary width integers.
    for (tid = 1; tid <= 64; tid++) {
        typeIDs[llvm::IntegerType::get(C, tid)] = tid;
    }

    // More reserved Type IDs:
    // 65 - i8*, 66 - i16*, 67 - i32*, 68 - i64*
    typeIDs[llvm::PointerType::getUnqual(llvm::Type::getInt8Ty(C))]  = tid++;
    typeIDs[llvm::PointerType::getUnqual(llvm::Type::getInt16Ty(C))] = tid++;
    typeIDs[llvm::PointerType::getUnqual(llvm::Type::getInt32Ty(C))] = tid++;
    typeIDs[llvm::PointerType::getUnqual(llvm::Type::getInt64Ty(C))] = tid++;
    return tid;
}

static LLVM_ATTRIBUTE_USED const char *apicall_begin = "/* Bytecode APIcalls BEGIN */";
static LLVM_ATTRIBUTE_USED const char *apicall_end   = "/* Bytecode APIcalls END */";
static LLVM_ATTRIBUTE_USED const char *globals_begin = "/* Bytecode globals BEGIN */";
static LLVM_ATTRIBUTE_USED const char *globals_end   = "/* Bytecode globals END */";
} // namespace clamav
