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
#include "bytecode_api.h"
#include "clambc.h"
#include "ClamBCModule.h"
#include "ClamBCUtilities.h"

#include "ClamBCAnalyzer.h"
#include "ClamBCRegAlloc.h"

#include <llvm/Support/DataTypes.h>
#include <llvm/ADT/STLExtras.h>
#include <llvm/Analysis/ConstantFolding.h>
#include <llvm/IR/DebugInfo.h>
#include <llvm/IR/Dominators.h>
#include <llvm/Analysis/LoopInfo.h>
#include <llvm/Analysis/Passes.h>
#include <llvm/Analysis/ValueTracking.h>
#include <llvm/IR/Attributes.h>
#include <llvm/IR/CallingConv.h>
#include <llvm/CodeGen/IntrinsicLowering.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/Intrinsics.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/Module.h>
#include <llvm/Pass.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/PassPlugin.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/IR/GetElementPtrTypeIterator.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/InstVisitor.h>
#include <llvm/Support/FormattedStream.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Transforms/Scalar.h>

#include <llvm/Analysis/CallGraph.h>
#include <llvm/Support/MemoryBuffer.h>

#include <sstream>

extern "C" const char *clambc_getversion(void);

// There were some things that were in the previous Module, that may or may not be needed at this time.  There
// are ways to share data between passes, will do that if it is necessary.

using namespace llvm;

static cl::opt<std::string> MapFile("clambc-map", cl::desc("Write compilation map"),
                                    cl::value_desc("File to write the map to"),
                                    cl::init(""));
static cl::opt<bool>
    DumpDI("clambc-dumpdi", cl::Hidden, cl::init(false),
           cl::desc("Dump LLVM IR with debug info to standard output"));

static cl::opt<std::string> outFile("clambc-sigfile", cl::desc("Name of output file"),
                                    cl::value_desc("Name of output file"),
                                    cl::init(""));

/*This is necessary if multiple files are used, and put together with llmv-link*/
static cl::opt<std::string> inputSourceFile("clambc-writer-input-source", cl::desc("File containing source code of signature."),
                                            cl::value_desc("File containing source code of signature."),
                                            cl::init(""));

// checks whether the queried functionality level is between min and max.
// a min/max of 0 means no min/max.
static bool checkFunctionalityLevel(unsigned query, unsigned min, unsigned max)
{
    if (min && query < min)
        return false;
    if (max && query > max)
        return false;
    return true;
}

/*
 * This class will do the writing, the output formatting code is mostly stolen from the previous ClamBCModule.
 */
class ClamBCOutputWriter
{

  public:
    static ClamBCOutputWriter *createClamBCOutputWriter(llvm::StringRef srFileName,
                                                        llvm::Module *pMod,
                                                        ClamBCAnalysis *pAnalyzer)
    {
        std::error_code ec;
        raw_fd_ostream *rfo        = new raw_fd_ostream(srFileName, ec);
        formatted_raw_ostream *fro = new formatted_raw_ostream(*rfo);

        if (nullptr == fro) {
            assert(0 && "FIGURE OUT THE CORRECT WAY TO DIE");
            // ClamBCStop();
        }
        ClamBCOutputWriter *ret = new ClamBCOutputWriter(*fro, pMod, pAnalyzer);
        if (nullptr == ret) {
            assert(0 && "FIGURE OUT THE CORRECT WAY TO DIE");
            // ClamBCStop();
        }
        return ret;
    }

    ClamBCOutputWriter(llvm::formatted_raw_ostream &outStream, llvm::Module *pMod, ClamBCAnalysis *pAnalyzer)
        : Out(lineBuffer), OutReal(outStream), maxLineLength(0), lastLinePos(0), pMod(pMod), pAnalyzer(pAnalyzer)
    {
        printGlobals(pMod, pAnalyzer);
    }

    virtual ~ClamBCOutputWriter()
    {
        OutReal.flush();
        delete (&OutReal);
    }

    virtual void printEOL()
    {
        int diff;
        Out << "\n";
        diff        = lineBuffer.size() - lastLinePos;
        lastLinePos = lineBuffer.size();
        assert(diff > 0);
        if (diff > maxLineLength) {
            maxLineLength = diff;
        }
    }

    virtual void printOne(char c)
    {
        Out << c;
    }

    void printNumber(uint64_t n, bool constant)
    {
        printNumber(Out, n, constant);
    }

    void printFixedNumber(uint64_t n, unsigned fixed)
    {
        printFixedNumber(Out, n, fixed);
    }

    void printModuleHeader(Module &M, ClamBCAnalysis *pAnalyzer, unsigned maxLine)
    {
        NamedMDNode *MinFunc = M.getNamedMetadata("clambc.funcmin");
        NamedMDNode *MaxFunc = M.getNamedMetadata("clambc.funcmax");
        unsigned minfunc     = 0;
        unsigned maxfunc     = 0;
        if (MinFunc) {
            const MDOperand &op     = MinFunc->getOperand(0)->getOperand(0);
            ConstantAsMetadata *cas = llvm::cast<ConstantAsMetadata>(op);
            assert(llvm::isa<ConstantInt>(cas->getValue()) && "Then what is it?");
            ConstantInt *ci = llvm::cast<ConstantInt>(cas->getValue());

            minfunc = ci->getLimitedValue();
        }
        if (MaxFunc) {
            const MDOperand &op     = MaxFunc->getOperand(0)->getOperand(0);
            ConstantAsMetadata *cas = llvm::cast<ConstantAsMetadata>(op);
            assert(llvm::isa<ConstantInt>(cas->getValue()) && "Then what is it?");
            ConstantInt *ci = llvm::cast<ConstantInt>(cas->getValue());

            maxfunc = ci->getLimitedValue();
        }

        OutReal << "ClamBC";
        // Print functionality level
        // 0.96 only knows to skip based on bytecode format level, and has no min/max
        // verification.
        // So if this bytecode is supposed to load on 0.96 use 0.96's format,
        // otherwise use post 0.96 format.
        // In both cases we output the min/max functionality level fields (using 2
        // unused fields from 0.96).
        // 0.96 will ignore these and load it (but we already checked it should load
        // at least on 0.96 via bytecode format). Post 0.96 will check the fields and
        // load/skip based on that.
        // For post 0.96 we use a higher format, so 0.96 will not load it.
        if (checkFunctionalityLevel(FUNC_LEVEL_096, minfunc, maxfunc)) {
            printNumber(OutReal, BC_FORMAT_096, false);
        } else {
            printNumber(OutReal, BC_FORMAT_LEVEL, false);
        }

        // Bytecode compile timestamp
        time_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());

        // printNumber(now, false); //IT APPEARS THAT I NEED THIS???
        printNumber(OutReal, now, false);

        const char *user = getenv("SIGNDUSER");
        // fallback to $USER
        if (!user) {
            user = getenv("USER");
        }
        // Sigmaker name
        printString(OutReal, user, 64);
        // Target-exclude. TODO: allow override via a global variable.
        printNumber(OutReal, 0, false);

        printNumber(OutReal, pAnalyzer->getKind(), false);
        // functionality level min, max, unusued in 0.96!
        printNumber(OutReal, minfunc, false);
        printNumber(OutReal, maxfunc, false);

        // Some maximum (unused)
        printNumber(OutReal, 0, false);

        // Compiler version
        printString(OutReal, clambc_getversion(), 64);

        printNumber(OutReal, pAnalyzer->getExtraTypes().size() + pAnalyzer->getStartTID() - 64, false);
        unsigned count = 0;
        for (Module::iterator I = M.begin(), E = M.end(); I != E; ++I) {
            if (I->isDeclaration()) {
                continue;
            }
            count++;
        }
        printNumber(OutReal, count, false);

        // Print 2 magic number to ensure reader works properly
        printNumber(OutReal, 0x53e5493e9f3d1c30ull, false);
        printFixedNumber(OutReal, 42, 2);
        if (maxLine < 4096) {
            maxLine = 4096;
        }
        OutReal << ":" << maxLine << "\n";
        // first line must fit into 8k
        assert((OutReal.tell() < 8192) && "OutReal too big");
    }

    void describeType(llvm::raw_ostream &Out, const Type *Ty, Module *M, ClamBCAnalysis *pAnalyzer)
    {
        if (const FunctionType *FTy = dyn_cast<FunctionType>(Ty)) {
            printFixedNumber(Out, 1, 1);
            assert(!FTy->isVarArg());
            printNumber(Out, FTy->getNumParams() + 1, false);
            printNumber(Out, pAnalyzer->getTypeID(FTy->getReturnType()), false);
            for (FunctionType::param_iterator I = FTy->param_begin(), E = FTy->param_end();
                 I != E; ++I) {
                printNumber(Out, pAnalyzer->getTypeID(*I), false);
            }
            return;
        }

        if (const StructType *STy = dyn_cast<StructType>(Ty)) {
            // get field offsets and insert explicit padding
            std::vector<unsigned> elements;
            for (unsigned i = 0; i < STy->getNumElements(); i++) {
                Type *Ty = STy->getTypeAtIndex(i);
                if (isa<PointerType>(Ty)) {

                    // WriteTypeSymbolic(errs(), STy, M);
                    assert(0 && "Find replacement for WriteTypeSymbolic");

                    STy->dump();
                    ClamBCStop("Pointers inside structs are not supported\n", M);
                }
                unsigned abiAlign = M->getDataLayout().getABITypeAlignment(Ty);
                unsigned typeBits = M->getDataLayout().getTypeSizeInBits(Ty);

                if (Ty->isIntegerTy() && 8 * abiAlign < typeBits) {
                    Ty->dump();
                    errs() << 8 * abiAlign << " < " << typeBits << "\n";
                    // we've set up a targetdata where alignof(32) == 32, alignof(64) == 64,
                    // so that each type is maximally aligned on all architectures.
                    ClamBCStop("Internal error: ABI alignment less than typesize for integer!\n",
                               M);
                }
                elements.push_back(pAnalyzer->getTypeID(Ty));
            }

            printFixedNumber(Out, STy->isPacked() ? 2 : 3, 1);
            printNumber(Out, elements.size(), false);
            for (std::vector<unsigned>::iterator I = elements.begin(), E = elements.end();
                 I != E; ++I) {
                printNumber(Out, *I, false);
            }
            return;
        }

        if (const ArrayType *ATy = dyn_cast<ArrayType>(Ty)) {
            printFixedNumber(Out, 4, 1);
            printNumber(Out, ATy->getNumElements(), false);
            printNumber(Out, pAnalyzer->getTypeID(ATy->getElementType()), false);
            return;
        }

        if (const PointerType *PTy = dyn_cast<PointerType>(Ty)) {
            printFixedNumber(Out, 5, 1);
            const Type *ETy = PTy->getPointerElementType();
            // pointers to opaque types are treated as i8*
            int id = -1;
            if (llvm::isa<StructType>(ETy)) {
                const StructType *pst = llvm::cast<StructType>(ETy);
                if (pst->isOpaque()) {
                    id = 8;
                }
            }
            if (-1 == id) {
                id = pAnalyzer->getTypeID(ETy);
            }
            printNumber(Out, id, false);
            return;
        }

        ClamBCStop("Unsupported type ", M);
    }

    void printConstant(Module &M, Constant *C)
    {
        if (ConstantExpr *CE = dyn_cast<ConstantExpr>(C)) {
            ConstantExpr *VCE = dyn_cast<ConstantExpr>(CE->stripPointerCasts());
            if (!VCE)
                VCE = CE;
            GlobalVariable *GV =
                dyn_cast<GlobalVariable>(VCE->getOperand(0)->stripPointerCasts());
            if (VCE->getOpcode() == Instruction::GetElementPtr &&
                VCE->getNumOperands() == 2 && GV) {
                ConstantInt *C1 = dyn_cast<ConstantInt>(VCE->getOperand(1));
                uint64_t v      = C1->getValue().getZExtValue();
                printNumber(Out, v, true);
                printNumber(Out, pAnalyzer->getGlobalID(GV), true);
                return;
            }
            if (VCE->getNumOperands() == 3 && GV) {
                ConstantInt *C0 = dyn_cast<ConstantInt>(VCE->getOperand(1));
                ConstantInt *C1 = dyn_cast<ConstantInt>(VCE->getOperand(2));
                if (C0->isZero()) {
                    printNumber(Out, C1->getValue().getZExtValue(), true);
                    printNumber(Out, pAnalyzer->getGlobalID(GV), true);
                    return;
                }
            }
            if (CE->getOpcode() == Instruction::BitCast && GV) {
                printNumber(Out, 0, true);
                printNumber(Out, pAnalyzer->getGlobalID(GV), true);
                return;
            }
        }
        if (C->isNullValue()) {
            printNumber(Out, 0, true);
            return;
        }
        if (ConstantInt *CI = dyn_cast<ConstantInt>(C)) {
            uint64_t v = CI->getValue().getZExtValue();
            printNumber(Out, v, true);
            return;
        }
        assert(!isa<ConstantAggregateZero>(C) && "ConstantAggregateZero with non-null value?");
        assert(!isa<ConstantPointerNull>(C) && "ConstantPointerNull with non-null value?");
        if (isa<ConstantArray>(C) || isa<ConstantStruct>(C)) {
            assert(C->getNumOperands() && "[0xty] arrays are not supported!");
            for (User::op_iterator I = C->op_begin(), E = C->op_end(); I != E; ++I) {
                printConstant(M, cast<Constant>(*I));
            }
            return;
        }
        // TODO: better diagnostics here
        if (isa<ConstantFP>(C)) {
            ClamBCStop("Floating point constants are not supported!", &M);
        }
        if (isa<ConstantExpr>(C)) {
            C->dump();
            ClamBCStop("Global variable has runtime-computable constant expression"
                       " initializer",
                       &M);
        }

        if (isa<ConstantDataSequential>(C)) {
            ConstantDataSequential *cds = llvm::cast<ConstantDataSequential>(C);
            size_t cnt                  = cds->getNumElements();
            assert((0 < cnt) && "[0xty] arrays are not supported!");
            for (size_t i = 0; i < cnt; i++) {
                printConstant(M, cds->getElementAsConstant(i));
            }
            return;
        }

        ClamBCStop("Unsupported constant type", &M);
    }

    void printGlobals(llvm::Module *pMod, ClamBCAnalysis *pAnalyzer)
    {
        const std::string &ls = pAnalyzer->getLogicalSignature();
        if (ls.empty()) {
            Out << pAnalyzer->getVirusnames();
        } else {
            Out << ls;
        }
        printEOL();
        Out << "T";
        printFixedNumber(Out, pAnalyzer->getStartTID(), 2);
        unsigned tid                                = pAnalyzer->getStartTID();
        const std::vector<const Type *> &extraTypes = pAnalyzer->getExtraTypes();
        for (auto I = extraTypes.begin(), E = extraTypes.end(); I != E; ++I) {
            // assert(typeIDs[*I] == tid && "internal type ID mismatch");
            assert(pAnalyzer->getTypeID(*I) == tid && "internal type ID mismatch");
            describeType(Out, *I, pMod, pAnalyzer);
            tid++;
        }

        // External function calls
        printEOL();
        Out << "E";

        auto apiCalls = pAnalyzer->getApiCalls();
        auto apis     = pAnalyzer->getApis();
        printNumber(Out, pAnalyzer->getMaxApi(), false);
        printNumber(Out, apiCalls.size(), false);
        /*This assert should probably be in the analyzer.*/
        assert((apis.size() == apiCalls.size()) && "Number of apis don't match");

        for (std::vector<const Function *>::iterator I = apis.begin(), E = apis.end();
             I != E; ++I) {
            const Function *F = *I;
            // function api ID
            printNumber(Out, apiCalls[F], false);
            // function prototype
            printNumber(Out, pAnalyzer->getTypeID(F->getFunctionType()), false);
            // function name
            std::string Name(F->getName());
            printConstData(Out, (const unsigned char *)Name.c_str(), Name.size() + 1);
        }

        // Global constants
        printEOL();
        Out << "G";
        unsigned maxGlobal = pAnalyzer->getMaxGlobal();
        printNumber(Out, maxGlobal, false);

        const std::vector<Constant *> &globalInits = pAnalyzer->getGlobalInits();
        printNumber(Out, globalInits.size(), false);
        for (auto I = globalInits.begin(), E = globalInits.end(); I != E; ++I) {
            if (I == globalInits.begin()) {
                assert(!*I);
                printNumber(Out, 0, false);
                printNumber(Out, 0, true);
                printNumber(Out, 0, false);
                continue;
            }
            Constant *pConst = llvm::cast<Constant>(*I);
            // type of constant
            uint16_t id = pAnalyzer->getTypeID((*I)->getType());
            printNumber(Out, id, false);
            // value of constant
            printConstant(*pMod, pConst);
            printNumber(Out, 0, false);
        }

        if (pAnalyzer->hasDbgIds()) {

            /*Need to get debugging working.*/
            assert(0 && "Just want to see if any of them have debug ids");

            const std::vector<const MDNode *> &mds = pAnalyzer->getMDs();
            printEOL();
            Out << "D";

            unsigned size = mds.size();
            if (size > 32) {
                printNumber(Out, 32, false);
                size -= 32;
            } else {
                printNumber(Out, size, false);
            }
            unsigned cnt = 0, c = 0;
            for (auto I = mds.begin(), E = mds.end();
                 I != E; ++I) {
                if (const MDNode *N = dyn_cast<MDNode>(*I)) {
                    printNumber(Out, N->getNumOperands(), false);
                    errs() << c++ << ":";
                    for (unsigned i = 0; i < N->getNumOperands(); i++) {
                        Value *V            = nullptr;
                        const MDOperand &op = N->getOperand(i);
                        if (llvm::isa<ValueAsMetadata>(op)) {
                            assert(0 && "See if thius happens");
                            V = llvm::cast<ValueAsMetadata>(op)->getValue();
                        }

                        if (!V) {
                            printNumber(Out, 0, false);
                            printNumber(Out, ~0u, false);
                            //} else if (MDNode *MB = dyn_cast<MDNode>(V)) {
                        } else if (const MDNode *MB = dyn_cast<MDNode>(op.get())) {
                            printNumber(Out, 0, false);
                            printNumber(Out, pAnalyzer->getDbgId(MB), false);
                            errs() << pAnalyzer->getDbgId(MB) << ", ";
                            //} else if (MDString *MS = dyn_cast<MDString>(V)) {
                        } else if (MDString *MS = dyn_cast<MDString>(op.get())) {
                            printConstData(Out, (const unsigned char *)MS->getString().data(), MS->getLength());
                        } else {
                            ConstantInt *CI = cast<ConstantInt>(V);
                            printNumber(Out, CI->getBitWidth(), false);
                            printNumber(Out, CI->getZExtValue(), false);
                        }
                    }
                    errs() << "\n";
                }
                if (++cnt >= 32) {
                    printEOL();
                    Out << "D";
                    if (size > 32) {
                        printNumber(Out, 32, false);
                        size -= 32;
                    } else
                        printNumber(Out, size, false);
                    cnt = 0;
                }
            }
        }
    }

    void finished(llvm::Module *pMod, ClamBCAnalysis *pAnalyzer)
    {

        // maxline+1, 1 more for \0
        printModuleHeader(*pMod, pAnalyzer, maxLineLength + 1);
        OutReal << Out.str();

        // MemoryBuffer *MB  = nullptr;
        const char *start     = NULL;
        std::string copyright = pAnalyzer->getCopyright();
        if (copyright.length()) {
            start = copyright.c_str();
        } else {
            std::string SrcFile = inputSourceFile;
            if ("" == SrcFile) {
                SrcFile = pMod->getSourceFileName();
            }
            if (!SrcFile.empty()) {
                // std::string ErrStr;
                // MB = MemoryBuffer::getFile(SrcFile, &ErrStr);
                ErrorOr<std::unique_ptr<MemoryBuffer>> mbOrErr = MemoryBuffer::getFile(SrcFile);
                if (std::error_code ec = mbOrErr.getError()) {
                    ClamBCStop("Unable to (re)open input file: " + SrcFile, pMod);
                }
                // MB = mbOrErr.get();
                LLVMMemoryBufferRef mbr = wrap(mbOrErr.get().release());
                // mapped file is \0 terminated by getFile()
                start = unwrap(mbr)->getBufferStart();
                // start = MB->getBufferStart();
            }
        }
        if (!start) {
            ClamBCStop("Bytecode should either have source code or include copyright statement\n", pMod);
        }
        OutReal << "S";
        char c;
        unsigned linelength = 0;
        do {
            // skip whitespace at BOL
            do {
                c = *start++;
            } while (c == ' ' || c == '\t');
            while (c != '\n' && c) {
                // char b[3] = {0x60 | (c & 0xf), 0x60 | ((c >> 4) & 0xf), '\0'};
                char b[3];
                b[0] = 0x60 | (c & 0xf);
                b[1] = 0x60 | ((c >> 4) & 0xf);
                b[2] = 0;

                OutReal << b;
                c = *start++;
                linelength++;
            }
            if (c && linelength < 80) {
                OutReal << "S";
            } else if (linelength > 0) {
                OutReal << "\n";
                linelength = 0;
            }
        } while (c);
    }

    void dumpTypes(llvm::raw_ostream &OS)
    {
        // Print type IDs to debug.map
        auto typeIDs        = pAnalyzer->getTypeIDs();
        const Type **revmap = new const Type *[typeIDs.size()];
        for (auto I = typeIDs.begin(), E = typeIDs.end();
             I != E; ++I) {
            revmap[I->second] = I->first;
        }
        for (unsigned i = 65; i < typeIDs.size(); i++)
            OS << "type " << i << ": " << *revmap[i] << "\n";
        OS << "\n";
        delete[] revmap;
    }

  protected:
    llvm::raw_svector_ostream Out;
    llvm::formatted_raw_ostream &OutReal;
    llvm::SmallVector<char, 4096> lineBuffer;
    int maxLineLength         = 0;
    int lastLinePos           = 0;
    llvm::Module *pMod        = nullptr;
    ClamBCAnalysis *pAnalyzer = nullptr;

    void printFixedNumber(raw_ostream &Out, unsigned n, unsigned fixed)
    {
        char number[32];
        unsigned i = 0;
        while (fixed > 0) {
            number[i++] = 0x60 | (n & 0xf);
            n >>= 4;
            fixed--;
        }
        assert((n == 0) && "Fixed-width number cannot exceed width");
        number[i] = '\0';
        Out << number;
    }

    static void printNumber(raw_ostream &Out, uint64_t n, bool constant)
    {
        // llvm::errs() << "printNumber" << "::" << n << "::" << constant << "::";
        char number[32];
        unsigned i = 0;
        while (n > 0) {
            number[++i] = 0x60 | (n & 0xf);
            n >>= 4;
        }
        if (!constant) {
            number[0] = 0x60 | i;
        } else {
            number[0] = 0x40 | i;
        }
        number[++i] = '\0';
        // llvm::errs() << number << "<END>\n";
        Out << number;
    }

    static void printString(raw_ostream &Out, const char *string,
                            unsigned maxlength)
    {
        std::string str;
        if (string) {
            StringRef truncatedStr;
            truncatedStr = StringRef(string).substr(0, maxlength);
            str          = truncatedStr.str();
        }
        const char *cstr = str.c_str();
        // null terminated cstring
        printConstData(Out, (const unsigned char *)cstr, strlen(cstr) + 1);
    }

    static void printConstData(raw_ostream &Out, const unsigned char *s,
                               size_t len)
    {
        size_t i;

        Out << "|";
        printNumber(Out, len, false);
        for (i = 0; i < len; i++) {
            // char b[3] = {0x60 | (s[i] & 0xf), 0x60 | ((s[i] >> 4) & 0xf), '\0'};
            char b[3];
            b[0] = 0x60 | (s[i] & 0xf);
            b[1] = 0x60 | ((s[i] >> 4) & 0xf);
            b[2] = 0;
            Out << b;
        }
    }
};

class ClamBCWriter : public PassInfoMixin<ClamBCWriter>, public InstVisitor<ClamBCWriter>
{
    typedef DenseMap<const BasicBlock *, unsigned> BBIDMap;
    BBIDMap BBMap;

    const Module *TheModule = nullptr;
    unsigned opcodecvt[Instruction::OtherOpsEnd];
    raw_ostream *MapOut        = nullptr;
    FunctionPass *Dumper       = nullptr;
    ClamBCRegAllocAnalysis *RA = nullptr;
    unsigned fid, minflvl;
    MetadataContext *TheMetadata = nullptr;
    unsigned MDDbgKind;
    std::vector<unsigned> dbgInfo;
    bool anyDbg;

    llvm::Module *pMod                            = nullptr;
    ClamBCOutputWriter *pOutputWriter             = nullptr;
    ClamBCAnalysis *pAnalyzer                     = nullptr;
    ModuleAnalysisManager *pModuleAnalysisManager = nullptr;

  public:
    static char ID;
    explicit ClamBCWriter()
        : TheModule(0), MapOut(0), Dumper(0)
    {
        if (!MapFile.empty()) {
            std::error_code ec;
            std::error_condition ok;
            MapOut = new raw_fd_ostream(MapFile.c_str(), ec);
            if (ec != ok) {
                errs() << "error opening mapfile" << MapFile << ": " << ec.message() << "\n";
                MapOut = 0;
            }
        }
    }

    ~ClamBCWriter()
    {
        if (MapOut) {
            delete MapOut;
        }
    }
    virtual llvm::StringRef getPassName() const
    {
        return "ClamAV Bytecode Backend Writer";
    }

    void getAnalysisUsage(AnalysisUsage &AU) const
    {
        AU.addRequired<ClamBCRegAlloc>();
        AU.setPreservesAll();
    }

    virtual bool doInitialization(Module &M);

    PreservedAnalyses run(Module &m, ModuleAnalysisManager &mam)
    {
        doInitialization(m);
        pMod                   = &m;
        pModuleAnalysisManager = &mam;

        ClamBCAnalysis &analysis = mam.getResult<ClamBCAnalyzer>(m);
        pAnalyzer                = &analysis;
        pOutputWriter            = ClamBCOutputWriter::createClamBCOutputWriter(outFile, pMod, pAnalyzer);

        for (auto i = pMod->begin(), e = pMod->end(); i != e; i++) {
            if (llvm::isa<Function>(i)) {
                Function *pFunc = llvm::cast<Function>(i);
                if (not pFunc->isDeclaration()) {
                    runOnFunction(*pFunc);
                }
            }
        }

        doFinalization(m);
        return PreservedAnalyses::all();
    }

    void gatherGEPs(BasicBlock *pBB, std::vector<GetElementPtrInst *> &geps)
    {
        for (auto i = pBB->begin(), e = pBB->end(); i != e; i++) {
            if (llvm::isa<GetElementPtrInst>(i)) {

                GetElementPtrInst *pGEP = llvm::cast<GetElementPtrInst>(i);
                if (1 == pGEP->getNumIndices()) {
                    int iid = pAnalyzer->getTypeID(pGEP->getPointerOperand()->getType());
                    if (iid > 65) {
                        geps.push_back(pGEP);
                    }
                }
            }
        }
    }

    void gatherGEPs(Function *pFunc, std::vector<GetElementPtrInst *> &geps)
    {
        for (auto i = pFunc->begin(), e = pFunc->end(); i != e; i++) {
            BasicBlock *pBB = llvm::cast<BasicBlock>(i);
            gatherGEPs(pBB, geps);
        }
    }

    void fixGEPs(Function *pFunc)
    {
        std::vector<GetElementPtrInst *> geps;
        gatherGEPs(pFunc, geps);

        for (size_t i = 0; i < geps.size(); i++) {
            GetElementPtrInst *pGep = geps[i];

            assert(llvm::isa<PointerType>(pGep->getType()) && "ONLY POINTER TYPES ARE CURRENTLY SUPPORTED");

            Value *operand = pGep->getPointerOperand();

            PointerType *pDestType = Type::getInt8PtrTy(pMod->getContext());

            CastInst *ci = CastInst::CreatePointerCast(operand, pDestType, "ClamBCWriter_fixGEPs", pGep);

            Value *index = pGep->getOperand(1);

            assert(operand->getType()->isPointerTy() && "HOW COULD THIS HAPPEN?");

            Type *pType = operand->getType();
            pType       = pType->getPointerElementType();

            if (not pType->isIntegerTy()) {
                assert(0 && "ONLY INTEGER TYPES ARE CURRENTLY IMPLEMENTED");
            }

            unsigned multiplier = pType->getIntegerBitWidth() / 8;
            assert(multiplier && "HOW DID THIS END UP ZERO");

            Constant *cMultiplier = ConstantInt::get(index->getType(), multiplier);

            Value *newIndex = BinaryOperator::Create(Instruction::Mul, cMultiplier, index, "ClamBCWriter_fixGEPs", pGep);

            GetElementPtrInst *pNew = nullptr;

            if (pGep->isInBounds()) {
                Type *pt = ci->getType();
                if (llvm::isa<PointerType>(pt)) {
                    pt = pt->getPointerElementType();
                }
                pNew = GetElementPtrInst::Create(pt, ci, newIndex, "ClamBCWriter_fixGEPs", pGep);
            } else {
                assert(0 && "DON'T THINK THIS CAN HAPPEN");
            }

            assert(pNew && "HOW DID HTIS HAPPEN");

            ci = CastInst::CreatePointerCast(pNew, pGep->getType(), "ClamBCWriter_fixGEPs", pGep);

            pGep->replaceAllUsesWith(ci);
            pGep->eraseFromParent();
        }
    }

    bool runOnFunction(Function &F)
    {
        fixGEPs(&F);

        if ("" == F.getName()) {
            assert(0 && "Function created by ClamBCRebuild is not being deleted");
        }

        pMod = F.getParent();

        BBMap.clear();
        dbgInfo.clear();
        anyDbg = false;

        if (F.hasAvailableExternallyLinkage()) {
            return false;
        }
        fid++;

        // Removed, see note about getFunctionID at the top of the file.
        assert(pAnalyzer->getFunctionID(&F) == fid && "Function IDs don't match");

        FunctionAnalysisManager &fam = pModuleAnalysisManager->getResult<FunctionAnalysisManagerModuleProxy>(*pMod).getManager();

        RA = &fam.getResult<ClamBCRegAllocAnalyzer>(F);
        printFunction(F);
        if (Dumper) {
            Dumper->runOnFunction(F);
        }
        return false;
    }

    virtual bool doFinalization(Module &M)
    {
        printEOL();
        pOutputWriter->finished(pMod, pAnalyzer);
        if (MapOut) {
            pOutputWriter->dumpTypes(*MapOut);
            MapOut->flush();
        }
        if (Dumper) {
            delete Dumper;
        }

        delete (pOutputWriter);

        return false;
    }

  private:
    void printNumber(uint64_t c, bool constant)
    {
        pOutputWriter->printNumber(c, constant);
    }
    void printFixedNumber(unsigned c, unsigned fixed)
    {
        pOutputWriter->printFixedNumber(c, fixed);
    }
    void printEOL()
    {
        pOutputWriter->printEOL();
    }

    void stop(const std::string &Msg, const llvm::Function *F)
    {
        ClamBCStop(Msg, F);
    }
    void stop(const std::string &Msg, const llvm::Instruction *I)
    {
        ClamBCStop(Msg, I);
    }
    void printCount(Module &M, unsigned count, const std::string &What);
    void printType(const Type *Ty, const Function *F = 0, const Instruction *I = 0);
    void printFunction(Function &);
    void printMapping(const Value *V, unsigned id, bool newline = false);
    void printBasicBlock(BasicBlock *BB);

    static const AllocaInst *isDirectAlloca(const Value *V)
    {
        const AllocaInst *AI = dyn_cast<AllocaInst>(V);
        if (!AI) return 0;
        if (AI->isArrayAllocation())
            return 0;
        if (AI->getParent() != &AI->getParent()->getParent()->getEntryBlock())
            return 0;
        return AI;
    }

    static bool isInlineAsm(const Instruction &I)
    {
        if (isa<CallInst>(&I) && isa<InlineAsm>(I.getOperand(0))) {
            return true;
        }
        return false;
    }

    friend class InstVisitor<ClamBCWriter>;

    void visitGetElementPtrInst(GetElementPtrInst &GEP)
    {
        // Checking is done by the verifier!

        unsigned ops = GEP.getNumIndices();
        assert(ops && "GEP without indices?");
        if (ops > 15) {
            stop("Too many levels of pointer indexing, at most 15 is supported!",
                 &GEP);
        }

        switch (ops) {
            case 1:
                printFixedNumber(OP_BC_GEP1, 2);
                assert(!isa<GlobalVariable>(GEP.getOperand(0)) &&
                       !isa<ConstantExpr>(GEP.getOperand(0)) &&
                       "would hit libclamav interpreter bug");
                {
                    int iid = pAnalyzer->getTypeID(GEP.getPointerOperand()->getType());
                    if (iid > 65) {
                        DEBUGERR << GEP << "<END>\n";
                        DEBUGERR << *(GEP.getPointerOperand()) << "<END>\n";
                        DEBUGERR << *(GEP.getPointerOperand()->getType()) << "<END>\n";
                        DEBUGERR << iid << "<END>\n";
                        // stop("gep1 with type > 65 won't work on interpreter", &GEP);
                        assert(0 && "gep1 with type > 65 won't work on interpreter");
                    }
                }
                break;
            case 2:
                if (const ConstantInt *CI = dyn_cast<ConstantInt>(GEP.getOperand(1))) {
                    if (CI->isZero()) {
                        assert(!isa<GlobalVariable>(GEP.getOperand(0)) &&
                               !isa<ConstantExpr>(GEP.getOperand(0)) &&
                               "would hit libclamav interpreter bug");
                        printFixedNumber(OP_BC_GEPZ, 2);
                        printType(GEP.getPointerOperand()->getType(), 0, &GEP);
                        printOperand(GEP, GEP.getOperand(0));
                        printOperand(GEP, GEP.getOperand(2));
                        if (ConstantInt *CI = dyn_cast<ConstantInt>(GEP.getOperand(1))) {
                            if (!CI->isZero()) {
                                const PointerType *Ty = cast<PointerType>(GEP.getPointerOperand()->getType());
                                const ArrayType *ATy  = dyn_cast<ArrayType>(Ty->getPointerElementType());
                                if (ATy) {
                                    ClamBCStop("ATy", &GEP);
                                }
                            }
                        }
                        return;
                    }
                }
                // fall through
            default:
                DEBUGERR << GEP << "<END>\n";
                assert(0 && "GEPN");

                ClamBCStop("GEPN", &GEP);

                printFixedNumber(OP_BC_GEPN, 2);
                // If needed we could use DecomposeGEPExpression here.
                if (ops >= 16) {
                    ClamBCStop("GEP with more than 15 indices", &GEP);
                }
                printFixedNumber(ops, 1);
                break;
        }
        printType(GEP.getPointerOperand()->getType(), 0, &GEP);
        for (Instruction::op_iterator II = GEP.op_begin(), IE = GEP.op_end(); II != IE;
             ++II) {
            Value *V = *II;
            printOperand(GEP, V);
        }
    }

    void visitLoadInst(LoadInst &LI)
    {
        // Checking is done by the verifier!
        Value *V = LI.getPointerOperand();
        if (isa<AllocaInst>(V) || isa<GlobalVariable>(V)) {
            printFixedNumber(OP_BC_COPY, 2);
            printOperand(LI, V);
            printOperand(LI, &LI);
            return;
        }
        printFixedNumber(OP_BC_LOAD, 2);
        printOperand(LI, V);
    }

    void visitStoreInst(StoreInst &SI)
    {
        Value *V = SI.getPointerOperand();
        // checking is done by the verifier!
        if (isa<GetElementPtrInst>(V) ||
            isa<BitCastInst>(V)) {
            printFixedNumber(OP_BC_STORE, 2);
            printOperand(SI, SI.getOperand(0));
            printOperand(SI, V);
            return;
        }
        V = V->stripPointerCasts();
        if (isa<AllocaInst>(V) || isa<GlobalVariable>(V)) {
            printFixedNumber(OP_BC_COPY, 2);
            printOperand(SI, SI.getOperand(0));
            printOperand(SI, V);
            return;
        }
        // checking is done by the verifier!
        if (isa<GetElementPtrInst>(V)) {
            printFixedNumber(OP_BC_STORE, 2);
            printOperand(SI, SI.getOperand(0));
            printOperand(SI, V);
            return;
        }

        Function *pFunc = SI.getParent()->getParent();
        for (auto i = pFunc->arg_begin(), e = pFunc->arg_end(); i != e; i++) {
            Argument *pArg = llvm::cast<Argument>(i);
            if (pArg == V) {
                printFixedNumber(OP_BC_COPY, 2);
                printOperand(SI, SI.getOperand(0));
                printOperand(SI, V);
                return;
            }
        }

        printFixedNumber(OP_BC_STORE, 2);
        printOperand(SI, SI.getOperand(0));
        printOperand(SI, V);
        return;
    }

    void visitCastInst(CastInst &I)
    {
        if (BitCastInst *BCI = dyn_cast<BitCastInst>(&I)) {
            if (BCI->isLosslessCast()) {
                printFixedNumber(OP_BC_GEPZ, 2);
                printType(BCI->getOperand(0)->getType(), 0, BCI);
                printOperand(*BCI, BCI->getOperand(0));
                printNumber(0, true);
                printFixedNumber(4, 1);
                return;
            }
        }

        assert(!I.isLosslessCast());
        LLVMContext &C = I.getContext();
        if (isa<PtrToIntInst>(I) && I.getType() == Type::getInt64Ty(C)) {
            printFixedNumber(OP_BC_PTRTOINT64, 2);
            printOperand(I, I.getOperand(0));
            return;
        }
        HandleOpcodes(I);
    }

    void visitSelectInst(SelectInst &I)
    {
        HandleOpcodes(I);
    }

    void HandleOpcodes(Instruction &I, bool printTy = false)
    {
        unsigned Opc = I.getOpcode();
        assert(Opc < sizeof(opcodecvt) / sizeof(opcodecvt[0]));

        unsigned mapped = opcodecvt[Opc];
        unsigned n      = I.getNumOperands();
        assert(mapped < 256 && "At most 255 instruction types are supported!");
        assert(n < 16 && "At most 15 operands are supported!");

        if (!mapped)
            stop("Instruction is not mapped", &I);

        assert(operand_counts[mapped] == n && "Operand count mismatch");
        printFixedNumber(mapped, 2);
        for (Instruction::op_iterator II = I.op_begin(), IE = I.op_end(); II != IE;
             ++II) {
            Value *V = *II;
            if (printTy) {
                printType(V->getType());
            }
            printOperand(I, V);
        }
    }

    void printBasicBlockID(BasicBlock *BB)
    {
        unsigned bbid = BBMap[BB];
        assert(bbid && "Unknown basicblock?");
        printNumber(bbid, false);
    }

    void visitBranchInst(BranchInst &I)
    {
        if (I.isUnconditional()) {
            printFixedNumber(OP_BC_JMP, 2);
            printBasicBlockID(I.getSuccessor(0));
            return;
        }

        assert(I.getNumSuccessors() == 2);
        printFixedNumber(OP_BC_BRANCH, 2);
        printOperand(I, I.getCondition());
        printBasicBlockID(I.getSuccessor(0));
        printBasicBlockID(I.getSuccessor(1));
    }

    void visitSwitchInst(SwitchInst &I)
    {
        stop("ClamAV bytecode backend has not implemented switch statements, please lower ", &I);
    }

    void visitBinaryOperator(Instruction &I)
    {
        assert(!isa<PointerType>(I.getType()));
        if (I.getOpcode() == Instruction::Sub) {
            // sub ptrtoint, ptrtoint
            // TODO: push ptrtoinst through phi nodes!
            LLVMContext &C  = I.getContext();
            Instruction *LI = dyn_cast<Instruction>(I.getOperand(0));
            Instruction *RI = dyn_cast<Instruction>(I.getOperand(1));
            if (LI && RI) {
                PtrToIntInst *L = dyn_cast<PtrToIntInst>(LI);
                PtrToIntInst *R = dyn_cast<PtrToIntInst>(RI);
                if (L && R && I.getType() == Type::getInt32Ty(C)) {
                    printFixedNumber(OP_BC_PTRDIFF32, 2);
                    printOperand(I, L->getOperand(0));
                    printOperand(I, R->getOperand(0));
                    return;
                }
            }
        }
        HandleOpcodes(I);
    }
    void visitReturnInst(ReturnInst &I)
    {
        if (I.getNumOperands() == 0) {
            // special case ret of void
            printFixedNumber(OP_BC_RET_VOID, 2);
            return;
        }
        HandleOpcodes(I, true);
    }

    void visitUnreachableInst(UnreachableInst &I)
    {
        printFixedNumber(OP_BC_ABORT, 2);
        return;
    }

    void printOperand(Instruction &I, Value *V)
    {
        if (isa<UndefValue>(V)) {
            V = Constant::getNullValue(V->getType());
        }
        if (Constant *C = dyn_cast<Constant>(V)) {
            if (ConstantInt *CI = dyn_cast<ConstantInt>(C)) {
                if (CI->getBitWidth() > 64)
                    stop("Integers of more than 64-bits are not supported", &I);
                uint64_t v = CI->getValue().getZExtValue();
                printNumber(v, true);
                printFixedNumber((CI->getBitWidth() + 7) / 8, 1);
            } else {
                if (GlobalVariable *GV = dyn_cast<GlobalVariable>(C)) {
                    printNumber(pAnalyzer->getGlobalID(GV), true);
                    // a Constant of bitwidth 0 is a global variable
                    printFixedNumber(0, 1);
                } else if (ConstantExpr *CE = dyn_cast<ConstantExpr>(C)) {
                    if (CE->getOpcode() == Instruction::IntToPtr) {
                        stop("Cast of integer to pointer not supported", &I);
                    }
                    printNumber(pAnalyzer->getGlobalID(CE), true);
                    // a Constant of bitwidth 0 is a global variable
                    printFixedNumber(0, 1);
                } else if (isa<ConstantPointerNull>(C)) {
                    printNumber(0, true);
                    printFixedNumber(0, 1);
                } else {
                    DEBUGERR << I << "<END>\n";
                    DEBUGERR << *C << "<END>\n";
                    DEBUGERR << *(C->getType()) << "<END>\n";
                    assert(0 && "REMOVED THE CALL TO STOP, BECAUSE printLocation was crashing.");

                    stop("Unhandled constant type", &I);
                }
            }
        } else {
            printNumber(RA->getValueID(V), false);
        }
    }

    void visitICmpInst(ICmpInst &I)
    {
        enum bc_opcode opc;
        switch (I.getPredicate()) {
            case CmpInst::ICMP_EQ:
                opc = OP_BC_ICMP_EQ;
                break;
            case CmpInst::ICMP_NE:

                opc = OP_BC_ICMP_NE;
                break;
            case CmpInst::ICMP_UGT:
                opc = OP_BC_ICMP_UGT;
                break;
            case CmpInst::ICMP_UGE:
                opc = OP_BC_ICMP_UGE;
                break;
            case CmpInst::ICMP_ULT:
                opc = OP_BC_ICMP_ULT;
                break;
            case CmpInst::ICMP_ULE:
                opc = OP_BC_ICMP_ULE;
                break;
            case CmpInst::ICMP_SGT:
                opc = OP_BC_ICMP_SGT;
                break;
            case CmpInst::ICMP_SGE:
                opc = OP_BC_ICMP_SGE;
                break;
            case CmpInst::ICMP_SLE:
                opc = OP_BC_ICMP_SLE;
                if (minflvl < FUNC_LEVEL_098_5)
                    stop("Instruction opcode 29 (signed less than or equal to) is "
                         "not supported clamav JIT on functionality levels prior to "
                         "FUNC_LEVEL_098_5",
                         &I);
                break;
            case CmpInst::ICMP_SLT:
                opc = OP_BC_ICMP_SLT;
                break;
            default:
                stop("Unsupported icmp predicate", &I);
                return; // Removes uninitialized opc warning.
        }
        printFixedNumber(opc, 2);
        printType(I.getOperand(0)->getType());
        for (Instruction::op_iterator II = I.op_begin(), IE = I.op_end(); II != IE;
             ++II) {
            Value *V = *II;
            printOperand(I, V);
        }
    }

    void visitIntrinsic(unsigned iid, CallInst &CI)
    {
        /*
         * The current strategy is to make sure we don't have intrinsic calls
         * that are not supported by older runtimes inserted by any of the passes
         * we run.
         */
        unsigned numop = 0;
        if (isa<DbgInfoIntrinsic>(CI))
            return;
        switch (iid) {
            case Intrinsic::memset:
                assert(CI.getNumOperands() == 5);
                printFixedNumber(OP_BC_MEMSET, 2);
                numop = 3;
                break;
            case Intrinsic::memcpy:
                assert(CI.getNumOperands() == 5);
                printFixedNumber(OP_BC_MEMCPY, 2);
                numop = 3;
                break;
            case Intrinsic::memmove:
                assert(CI.getNumOperands() == 5);
                printFixedNumber(OP_BC_MEMMOVE, 2);
                numop = 3;
                break;
            case Intrinsic::bswap:
                assert(CI.getNumOperands() == 2);
                numop = 1;
                switch (CI.getType()->getPrimitiveSizeInBits()) {
                    case 16:
                        printFixedNumber(OP_BC_BSWAP16, 2);
                        break;
                    case 32:
                        printFixedNumber(OP_BC_BSWAP32, 2);
                        break;
                    case 64:
                        printFixedNumber(OP_BC_BSWAP64, 2);
                        break;
                    default:
                        stop("Unsupported bswap bitwidth", &CI);
                }
                break;
            default:
                stop("Unsupported intrinsic call ", &CI);
        }

        for (unsigned i = 0; i < numop; i++) {
            printOperand(CI, CI.getOperand(i));
        }
    }

    void visitCallInst(CallInst &CI)
    {
        Function *F = CI.getCalledFunction();
        if (!F) {
            stop("Indirect calls are not implemented yet!", &CI);
        }
        if (F->getCallingConv() != CI.getCallingConv()) {
            stop("Calling conventions don't match!", &CI);
        }
        if (F->isVarArg()) {
            stop("Calls to vararg functions are not supported!", &CI);
        }
        if (F->isDeclaration() && F->getName().equals("__is_bigendian")) {
            printFixedNumber(OP_BC_ISBIGENDIAN, 2);
            return;
        }
        if (F->isDeclaration() && F->getName().equals("abort")) {
            printFixedNumber(OP_BC_ABORT, 2);
            return;
        }

        unsigned iid = F->getIntrinsicID();
        if (iid != Intrinsic::not_intrinsic) {
            visitIntrinsic(iid, CI);
            return;
        }
        if (F->isDeclaration()) {
            if (F->getName().equals("memcmp")) {
                printFixedNumber(OP_BC_MEMCMP, 2);
                printOperand(CI, CI.getOperand(0));
                printOperand(CI, CI.getOperand(1));
                printOperand(CI, CI.getOperand(2));
                return;
            }
            unsigned id = pAnalyzer->getExternalID(F);
            printFixedNumber(OP_BC_CALL_API, 2);
            // API calls can have max 15 args
            printFixedNumber(F->arg_size(), 1);
            printNumber(id, false);
        } else {
            printFixedNumber(OP_BC_CALL_DIRECT, 2);
            if (F->arg_size() > 255) {
                stop("Calls can have max 15 parameters", &CI);
            }
            printFixedNumber(F->arg_size(), 1);
            printNumber(pAnalyzer->getFunctionID(F), false);
        }

        for (unsigned i = 0; i < CI.getNumOperands() - 1; i++) {
            printOperand(CI, CI.getOperand(i));
        }
    }

    void visitInstruction(Instruction &I)
    {
        stop("ClamAV bytecode backend does not know about ", &I);
    }
};

bool ClamBCWriter::doInitialization(Module &M)
{

    memset(opcodecvt, 0, sizeof(opcodecvt));

    opcodecvt[Instruction::Add]  = OP_BC_ADD;
    opcodecvt[Instruction::Sub]  = OP_BC_SUB;
    opcodecvt[Instruction::Mul]  = OP_BC_MUL;
    opcodecvt[Instruction::UDiv] = OP_BC_UDIV;
    opcodecvt[Instruction::SDiv] = OP_BC_SDIV;
    opcodecvt[Instruction::URem] = OP_BC_UREM;
    opcodecvt[Instruction::SRem] = OP_BC_SREM;

    opcodecvt[Instruction::Shl]  = OP_BC_SHL;
    opcodecvt[Instruction::LShr] = OP_BC_LSHR;
    opcodecvt[Instruction::AShr] = OP_BC_ASHR;
    opcodecvt[Instruction::And]  = OP_BC_AND;
    opcodecvt[Instruction::Or]   = OP_BC_OR;
    opcodecvt[Instruction::Xor]  = OP_BC_XOR;

    opcodecvt[Instruction::Trunc]  = OP_BC_TRUNC;
    opcodecvt[Instruction::SExt]   = OP_BC_SEXT;
    opcodecvt[Instruction::ZExt]   = OP_BC_ZEXT;
    opcodecvt[Instruction::Ret]    = OP_BC_RET;
    opcodecvt[Instruction::Select] = OP_BC_SELECT;
    TheModule                      = &M;

    if (DumpDI) {
        // TODO: Get debug info working.
        // Dumper = createDbgInfoPrinterPass();
    }
    fid       = 0;
    MDDbgKind = M.getContext().getMDKindID("dbg");

    return false;
}

void ClamBCWriter::printType(const Type *Ty, const Function *F, const Instruction *I)
{
    if (Ty->isIntegerTy()) {
        LLVMContext &C = Ty->getContext();
        if ((Ty != Type::getInt1Ty(C) && Ty != Type::getInt8Ty(C) &&
             Ty != Type::getInt16Ty(C) && Ty != Type::getInt32Ty(C) &&
             Ty != Type::getInt64Ty(C))) {
            stop("The ClamAV bytecode backend does not currently support"
                 "integer types of widths other than 1, 8, 16, 32, 64.",
                 I);
        }
    } else if (Ty->isFloatingPointTy()) {
        stop("The ClamAV bytecode backend does not support floating point"
             "types",
             I);
    }

    unsigned id = pAnalyzer->getTypeID(Ty);
    assert(id < 32768 && "At most 32k types are supported");
    printNumber(id, false);
}

void ClamBCWriter::printCount(Module &M, unsigned id, const std::string &What)
{
    if (id >= 65536) {
        std::string Msg("Attempted to use more than 64k " + What);
        ClamBCStop(Msg, &M);
    }
    printNumber(id, false);
}

void ClamBCWriter::printMapping(const Value *V, unsigned id, bool newline)
{
    if (!MapOut)
        return;
    *MapOut << "Value id " << id << ": " << *V << "\n";
}

void ClamBCWriter::printFunction(Function &F)
{
    if (F.hasStructRetAttr())
        stop("Functions with struct ret are not supported", &F);

    if (MapOut) {
        *MapOut << "Function " << (pAnalyzer->getFunctionID(&F) - 1) << ": " << F.getName() << "\n\n";
    }
    printEOL();
    pOutputWriter->printOne('A');
    printFixedNumber(F.arg_size(), 1);
    printType(F.getReturnType());
    pOutputWriter->printOne('L');

    unsigned id = 0;
    for (inst_iterator I = inst_begin(&F), E = inst_end(&F); I != E; ++I) {
        id++;
    }
    if (id >= 32768) /* upper 32k "operands" are globals */
        stop("Attempted to use more than 32k instructions", &F);

    std::vector<const Value *> reverseValueMap;
    id = RA->buildReverseMap(reverseValueMap);
    printCount(*F.getParent(), id - F.arg_size(), "values");
    /* We can't iterate directly on the densemap when writing bytecode, because:
     *  - iteration is non-deterministic, because DenseMaps are  sorted by pointer
     *      values that change each run
     *  - we need to write out types in order of increasing IDs, otherwise we'd
     *      have to write out the ID with the type */
    for (unsigned i = 0; i < id; i++) {
        const Type *Ty;
        const Value *V = reverseValueMap[i];
        assert(V && "Null Value in idmap?");
        if (const AllocaInst *AI = dyn_cast<AllocaInst>(V)) {
            if (AI->isArrayAllocation() && !isa<ArrayType>(AI->getAllocatedType()))
                stop("VLAs are not (yet) supported", AI);
            if (AI->isArrayAllocation())
                stop("Array allocs are not supported", AI);
            Ty = AI->getAllocatedType();
        } else {
            Ty = V->getType();
        }
        printMapping(V, i, isa<Argument>(V));
        printType(Ty, 0, dyn_cast<Instruction>(V));
        printFixedNumber(isa<AllocaInst>(V), 1);
    }

    pOutputWriter->printOne('F');
    unsigned instructions = 0;
    for (inst_iterator II = inst_begin(F), IE = inst_end(F); II != IE; ++II) {
        Instruction *pInst = &*II;
        if (isa<AllocaInst>(pInst) || isa<DbgInfoIntrinsic>(pInst)) {
            continue;
        }

        if (!pInst->isTerminator() && RA->skipInstruction(pInst)) {
            continue;
        }
        instructions++;
    }
    printNumber(instructions, false);

    id = 0; // entry BB gets ID 0, because it can have no predecessors
    for (Function::iterator BB = F.begin(), E = F.end(); BB != E; ++BB) {
        BBMap[&*BB] = id++;
    }
    printCount(*F.getParent(), id, "basic blocks");

    for (Function::iterator i = F.begin(), e = F.end(); i != e; ++i) {
        BasicBlock *pBB = llvm::cast<BasicBlock>(i);
        printBasicBlock(pBB);
    }

    pOutputWriter->printOne('E');
    if (anyDbg) {
        pOutputWriter->printOne('D');
        pOutputWriter->printOne('B');
        pOutputWriter->printOne('G');
        printNumber(dbgInfo.size(), false);
        for (std::vector<unsigned>::iterator I = dbgInfo.begin(), E = dbgInfo.end();
             I != E; ++I) {
            printNumber(*I, false);
        }
    }
}

void ClamBCWriter::printBasicBlock(BasicBlock *BB)
{
    printEOL();
    pOutputWriter->printOne('B');

    for (BasicBlock::iterator II = BB->begin(), E = --BB->end(); II != E;
         ++II) {
        Instruction *pInst = llvm::cast<Instruction>(II);

        if (isa<AllocaInst>(pInst) || isa<DbgInfoIntrinsic>(pInst)) {
            continue;
        }
        if (isInlineAsm(*pInst)) {
            stop("Inline assembly is not allowed", pInst);
        }
        if (RA->skipInstruction(pInst)) {
            continue;
        }
        const Type *Ty = pInst->getType();
        if (StoreInst *SI = dyn_cast<StoreInst>(pInst)) {
            printType(SI->getOperand(0)->getType());
        } else {
            printType(Ty);
        }
        if (Ty->getTypeID() != Type::VoidTyID) {
            printNumber(RA->getValueID(pInst), false);
        } else {
            printNumber(0, false);
        }
        visit(*pInst);
        if (pAnalyzer->hasDbgIds() && MDDbgKind) {
            MDNode *Dbg = pInst->getMetadata(MDDbgKind);
            if (Dbg) {
                dbgInfo.push_back(pAnalyzer->getDbgId(Dbg));
                anyDbg = true;
            } else {
                dbgInfo.push_back(~0u);
            }
        }
    }

    pOutputWriter->printOne('T');
    visit(*BB->getTerminator());
    if (pAnalyzer->hasDbgIds() && MDDbgKind) {
        MDNode *Dbg = BB->getTerminator()->getMetadata(MDDbgKind);
        if (Dbg) {
            dbgInfo.push_back(pAnalyzer->getDbgId(Dbg));
            anyDbg = true;
        } else {
            dbgInfo.push_back(~0u);
        }
    }
}

// This part is the new way of registering your pass
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo()
{
    return {
        LLVM_PLUGIN_API_VERSION, "ClamBCWriter", "v0.1",
        [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &FPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                    if (Name == "clambc-writer") {
                        FPM.addPass(ClamBCWriter());
                        return true;
                    }
                    return false;
                });
        }};
}
