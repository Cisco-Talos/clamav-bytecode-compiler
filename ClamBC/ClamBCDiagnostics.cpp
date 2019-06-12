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
#define DEBUGTYPE "clambcdiags"
#include "ClamBCDiagnostics.h"
#include "llvm/Analysis/DebugInfo.h"
#include "llvm/Instructions.h"
#include "llvm/Metadata.h"
#include "llvm/Module.h"
#include "llvm/System/Process.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/Debug.h"
using namespace llvm;

static inline void printSep(bool hasColors)
{
    if (hasColors)
        errs().resetColor();
    errs() << ":";
    if (hasColors)
        errs().changeColor(raw_ostream::SAVEDCOLOR, true);
}

// Print the main compile unit's source filename,
// falls back to printing the module identifier.
static void printLocation(const llvm::Module *M)
{
    NamedMDNode *ND = M->getNamedMetadata("llvm.dbg.gv");
    if (ND) {
        unsigned N = ND->getNumOperands();
        // Try to find main compile unit
        for (unsigned i = 0; i < N; i++) {
            DIGlobalVariable G(ND->getOperand(i));
            DICompileUnit CU(G.getCompileUnit());
            if (!CU.isMain())
                continue;
            errs() << /*CU.getDirectory() << "/" <<*/ CU.getFilename() << ": ";
            return;
        }
    }
    errs() << M->getModuleIdentifier() << ": ";
}

// Print source location of function, and display name,
// falls back to printing the module's location and the function's LLVM name.
static void printLocation(const llvm::Function *F)
{
    unsigned MDDebugKind = F->getParent()->getMDKindID("dbg");
    if (MDDebugKind) {
        // Try to find the function's name and location
        for (Function::const_iterator I = F->begin(), E = F->end();
             I != E; ++I) {
            if (const TerminatorInst *T = I->getTerminator()) {
                if (MDNode *N = T->getMetadata(MDDebugKind)) {
                    DILocation Loc(N);
                    DIScope Scope = Loc.getScope();
                    while (Scope.isLexicalBlock()) {
                        DILexicalBlock LB(Scope.getNode());
                        Scope = LB.getContext();
                    }
                    if (Scope.isSubprogram()) {
                        DISubprogram SP(Scope.getNode());
                        errs() << /*Loc.getDirectory() << "/" << */ Loc.getFilename()
                               << ": in function '"
                               << SP.getDisplayName()
                               << "': ";
                        return;
                    }
                }
            }
        }
    }
    // Fallback to printing module location and function name
    printLocation(F->getParent());
    errs() << "in function '" << F->getName() << "': ";
}

// Print instruction location, falls back to printing function location,
// (and LLVM instruction if specified).
void printLocation(const llvm::Instruction *I, bool fallback)
{
    const BasicBlock *BB          = I->getParent();
    bool approx                   = false;
    BasicBlock::const_iterator It = I;
    do {
        BasicBlock::const_iterator ItB = BB->begin();
        while (It != ItB) {
            if (MDNode *N = It->getMetadata("dbg")) {
                DILocation Loc(N);
                errs() << /*Loc.getDirectory() << "/" <<*/ Loc.getFilename()
                       << ":" << Loc.getLineNumber();
                if (unsigned Col = Loc.getColumnNumber()) {
                    errs() << ":" << Col;
                }
                if (approx)
                    errs() << "(?)";
                errs() << ": ";
                DIScope Scope = Loc.getScope();
                while (Scope.isLexicalBlock()) {
                    DILexicalBlock LB(Scope.getNode());
                    Scope = LB.getContext();
                }
                if (Scope.isSubprogram()) {
                    DISubprogram SP(Scope.getNode());
                    errs() << "in function '" << SP.getDisplayName() << "': ";
                }
                return;
            }
            approx = true;
            --It;
        }
        BB = BB->getUniquePredecessor();
        if (BB)
            It = BB->end();
    } while (BB);
    printLocation(I->getParent()->getParent());
    if (fallback)
        errs() << *I << ":\n";
}

// Print display name of value.
// Optionally print the location of declaration, and fallback to printing the
// full LLVM value.
// If fallback is not specified just the LLVM value's name is printed.
void printValue(const llvm::Value *V, bool printLocation, bool fallback)
{
    std::string DisplayName;
    std::string Type;
    unsigned Line;
    std::string File;
    std::string Dir;
    if (!getLocationInfo(V, DisplayName, Type, Line, File, Dir)) {
        if (fallback)
            errs() << *V << "\n: ";
        else
            errs() << V->getName() << ": ";
        return;
    }
    errs() << "'" << DisplayName << "' ";
    if (printLocation)
        errs() << " (" << File << ":" << Line << ")";
}

// Prints the location of the specified value.
// Falls backt to printing module's location.
void printLocation(const llvm::Module *M, const llvm::Value *V)
{
    std::string DisplayName;
    std::string Type;
    unsigned Line;
    std::string File;
    std::string Dir;
    if (!getLocationInfo(V, DisplayName, Type, Line, File, Dir)) {
        printLocation(M);
        return;
    }
    errs() << /*Dir << "/" <<*/ File << ":" << Line << ": ";
}

static void printMsg(const Twine &Msg, const llvm::Module *M,
                     const llvm::Function *F, const llvm::Instruction *I,
                     const llvm::Value *V, bool error, bool internal)
{
#ifdef CLAMBC_COMPILER
    bool hasColors = true;
#else
    bool hasColors = sys::Process::StandardErrHasColors();
#endif
    if (hasColors)
        errs().changeColor(raw_ostream::SAVEDCOLOR, true);
    if (I) {
        printLocation(I, false);
    } else if (V) {
        printLocation(M, V);
    } else if (F) {
        printLocation(F);
    } else if (M) {
        printLocation(M);
    }

    if (error) {
        if (hasColors)
            errs().changeColor(raw_ostream::RED, true);
        if (internal)
            errs() << "internal compiler error: ";
        else
            errs() << "error: ";
    } else {
        if (hasColors)
            errs().changeColor(raw_ostream::MAGENTA, true);
        if (internal)
            errs() << "internal compiler warning: ";
        else
            errs() << "warning: ";
    }

    if (hasColors) {
        errs().resetColor();
        errs().changeColor(raw_ostream::SAVEDCOLOR, true);
    }
    if (V)
        printValue(V, false, false);
    errs() << Msg << "\n";
    if (hasColors)
        errs().resetColor();
    if (I) {
        errs() << "\t at : " << *I << "\n";
        DEBUG(I->getParent()->dump());
    }
}

void printDiagnostic(const Twine &Msg, const llvm::Module *M, bool internal)
{
    printMsg(Msg, M, 0, 0, 0, true, internal);
}

void printDiagnostic(const Twine &Msg, const llvm::Function *F, bool internal)
{
    printMsg(Msg, F->getParent(), F, 0, 0, true, internal);
}

void printDiagnostic(const Twine &Msg, const llvm::Instruction *I,
                     bool internal)
{
    const Function *F = I->getParent()->getParent();
    printMsg(Msg, F->getParent(), F, I, 0, true, internal);
}

void printDiagnosticValue(const Twine &Msg, const llvm::Module *M,
                          const llvm::Value *V, bool internal)
{
    if (const Instruction *I = dyn_cast<Instruction>(V))
        printMsg(Msg, M, I->getParent()->getParent(), I, V, 0, internal);
    else if (const Argument *A = dyn_cast<Argument>(V))
        printMsg(Msg, M, A->getParent(), 0, A, 0, internal);
    else
        printMsg(Msg, M, 0, 0, V, true, internal);
}

void printWarning(const Twine &Msg, const llvm::Module *M, bool internal)
{
    printMsg(Msg, M, 0, 0, 0, false, internal);
}

void printWarning(const Twine &Msg, const llvm::Function *F, bool internal)
{
    printMsg(Msg, F->getParent(), F, 0, 0, false, internal);
}

void printWarning(const Twine &Msg, const llvm::Instruction *I,
                  bool internal)
{
    const Function *F = I->getParent()->getParent();
    printMsg(Msg, F->getParent(), F, I, 0, false, internal);
}

void printWarningValue(const Twine &Msg, const llvm::Module *M,
                       const llvm::Value *V, bool internal)
{
    if (const Instruction *I = dyn_cast<Instruction>(V))
        printMsg(Msg, M, I->getParent()->getParent(), I, V, 0, internal);
    else if (const Argument *A = dyn_cast<Argument>(V))
        printMsg(Msg, M, A->getParent(), 0, A, 0, internal);
    else
        printMsg(Msg, M, 0, 0, V, false, internal);
}
