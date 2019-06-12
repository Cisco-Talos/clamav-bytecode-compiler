/*
 *  Compile LLVM bytecode to ClamAV bytecode.
 *
 *  Copyright (C) 2010 Sourcefire, Inc.
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
#ifndef CLAMBC_DIAGNOSTICS_H
#define CLAMBC_DIAGNOSTICS_H
#include <string>

namespace llvm
{
class Module;
class Function;
class Instruction;
class Value;
class Twine;
} // namespace llvm

// Print instruction location, falls back to printing function location,
// (and LLVM instruction if specified).
void printLocation(const llvm::Instruction *I, bool fallback);

// Print display name of value.
// Optionally print the location of declaration, and fallback to printing the
// full LLVM value.
// If fallback is not specified just the LLVM value's name is printed.
void printValue(const llvm::Value *V, bool printLocation = false,
                bool fallback = false);

// Prints a diagnostic error about the specified module.
void printDiagnostic(const llvm::Twine &Msg, const llvm::Module *F,
                     bool internal = false);

// Prints a diagnostic error about the specified function.
void printDiagnostic(const llvm::Twine &Msg, const llvm::Function *F,
                     bool internal = false);

// Prints a diagnostic error about the specified instruction.
void printDiagnostic(const llvm::Twine &Msg, const llvm::Instruction *I,
                     bool internal = false);

// Prints a diagnostic error about the specified value (can be an instruction).
void printDiagnosticValue(const llvm::Twine &Msg, const llvm::Module *M,
                          const llvm::Value *V,
                          bool internal = false);

// Prints a diagnostic warning about the specified module.
void printWarning(const llvm::Twine &Msg, const llvm::Module *F,
                  bool internal = false);

// Prints a diagnostic warning about the specified function.
void printWarning(const llvm::Twine &Msg, const llvm::Function *F,
                  bool internal = false);

// Prints a diagnostic warnini about the specified instruction.
void printWarning(const llvm::Twine &Msg, const llvm::Instruction *I,
                  bool internal = false);

// Prints a diagnostic warning about the specified value (can be an instruction).
void printWarningValue(const llvm::Twine &Msg, const llvm::Module *M,
                       const llvm::Value *V,
                       bool internal = false);

#endif
