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
// #include "llvm/Config/config.h"   //TODO: Is this needed?
#include "ClamBCCommon.h"
// #include "clang/Basic/Version.h"  //TODO: Is this needed?
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/StringMap.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/Support/ManagedStatic.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/PrettyStackTrace.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/Signals.h"
#include <cstring>
#include <map>
#include <ctime>
#include <set>
#include <filesystem>
using namespace llvm;

static cl::opt<std::string>
    InputFilename(cl::Positional, cl::desc("[input header]"), cl::init("-"));

static cl::opt<std::string>
    OutputFilename("gen-api-c", cl::desc("[output C file]"), cl::Required);

static cl::opt<std::string>
    OutputImplHeader("gen-impl-h", cl::desc("output bytecode_api_impl.h"),
                     cl::Required);

static cl::opt<std::string>
    OutputHooksHeader("gen-hooks-h", cl::desc("output bytecode_hooks.h"),
                      cl::Required);

namespace tok
{
enum kind {
    None = 0,
    BraceClose,
    BraceOpen,
    Comma,
    Const,
    End,
    Enum,
    Error,
    Equal,
    Extern,
    Number,
    Reserved,
    ReservedCXX,
    ReservedType,
    Int8,
    Int16,
    Int32,
    Int64,
    UInt8,
    UInt16,
    UInt32,
    UInt64,
    ParClose,
    ParOpen,
    Pointer,
    SemiColon,
    String,
    Struct,
    SquareBracketOpen,
    SquareBracketClose,
    Void
};
}

struct FunctionProto {
    const FunctionType *Ty;
    SmallVector<unsigned, 2> TypeFlags;
};

class Parser
{
  public:
    Parser(SourceMgr &SM, LLVMContext &C)
        : SrcMgr(SM), TokStart(0), LastTokStart(0), C(C)
    {
        memset(delimiters, tok::None, sizeof(delimiters));
        delimiters[(uint8_t)'('] = tok::ParOpen;
        delimiters[(uint8_t)')'] = tok::ParClose;
        delimiters[(uint8_t)'{'] = tok::BraceOpen;
        delimiters[(uint8_t)'}'] = tok::BraceClose;
        delimiters[(uint8_t)';'] = tok::SemiColon;
        delimiters[(uint8_t)'*'] = tok::Pointer;
        delimiters[(uint8_t)','] = tok::Comma;
        delimiters[(uint8_t)'['] = tok::SquareBracketOpen;
        delimiters[(uint8_t)']'] = tok::SquareBracketClose;
        delimiters[(uint8_t)'='] = tok::Equal;

        InitLangKeywords();

        keywords["const"]  = tok::Const;
        keywords["extern"] = tok::Extern;
        keywords["enum"]   = tok::Enum;
        // Supported types from C
        keywords["void"]   = tok::Void;
        keywords["struct"] = tok::Struct;

        // stdint.h types
        keywords["int8_t"]   = tok::Int8;
        keywords["int16_t"]  = tok::Int16;
        keywords["int32_t"]  = tok::Int32;
        keywords["int64_t"]  = tok::Int64;
        keywords["uint8_t"]  = tok::UInt8;
        keywords["uint16_t"] = tok::UInt16;
        keywords["uint32_t"] = tok::UInt32;
        keywords["uint64_t"] = tok::UInt64;

        // Diagnose unsupported types
        keywords["int"]        = tok::ReservedType;
        keywords["unsigned"]   = tok::ReservedType;
        keywords["long"]       = tok::ReservedType;
        keywords["short"]      = tok::ReservedType;
        keywords["double"]     = tok::ReservedType;
        keywords["float"]      = tok::ReservedType;
        keywords["signed"]     = tok::ReservedType;
        keywords["_Bool"]      = tok::ReservedType;
        keywords["_Complex"]   = tok::ReservedType;
        keywords["_Imaginary"] = tok::ReservedType;
        // stdbool.h
        keywords["bool"] = tok::ReservedType;

        // Macros to ignore
        ignoreMacros["EBOUNDS"] = 1;

        std::vector<const Type *> params;
        params.push_back(Type::getInt32Ty(C));
        params.push_back(Type::getInt32Ty(C));
        Api0Ty = FunctionType::get(Type::getInt32Ty(C), params, false);

        params.clear();
        params.push_back(PointerType::getUnqual(Type::getInt8Ty(C)));
        params.push_back(Type::getInt32Ty(C));
        Api1Ty = FunctionType::get(Type::getInt32Ty(C), params, false);

        params.clear();
        params.push_back(Type::getInt32Ty(C));
        Api2Ty = FunctionType::get(Type::getInt32Ty(C), params, false);

        Api3Ty = FunctionType::get(PointerType::getUnqual(Type::getInt8Ty(C)), params, false);
        params.clear();
        params.push_back(PointerType::getUnqual(Type::getInt8Ty(C)));
        params.push_back(Type::getInt32Ty(C));
        params.push_back(Type::getInt32Ty(C));
        params.push_back(Type::getInt32Ty(C));
        params.push_back(Type::getInt32Ty(C));
        Api4Ty = FunctionType::get(Type::getInt32Ty(C), params, false);

        params.clear();
        Api5Ty = FunctionType::get(Type::getInt32Ty(C), params, false);

        params.clear();
        params.push_back(Type::getInt32Ty(C));
        params.push_back(Type::getInt32Ty(C));

        Api6Ty = FunctionType::get(PointerType::getUnqual(Type::getInt8Ty(C)), params, false);

        params.clear();
        params.push_back(Type::getInt32Ty(C));
        params.push_back(Type::getInt32Ty(C));
        params.push_back(Type::getInt32Ty(C));
        Api7Ty = FunctionType::get(Type::getInt32Ty(C), params, false);

        params.clear();
        params.push_back(PointerType::getUnqual(Type::getInt8Ty(C)));
        params.push_back(Type::getInt32Ty(C));
        params.push_back(PointerType::getUnqual(Type::getInt8Ty(C)));
        params.push_back(Type::getInt32Ty(C));
        Api8Ty = FunctionType::get(Type::getInt32Ty(C), params, false);

        params.clear();
        params.push_back(PointerType::getUnqual(Type::getInt8Ty(C)));
        params.push_back(Type::getInt32Ty(C));
        params.push_back(Type::getInt32Ty(C));
        Api9Ty = FunctionType::get(Type::getInt32Ty(C), params, false);

        BufferID = 0;
    }

    bool parse();
    bool output(raw_ostream &Out, raw_ostream &OutImpl, raw_ostream &OutHooks);

  private:
    enum {
        ConstType  = 1 << 0,
        SignedType = 1 << 1
    };
    SourceMgr &SrcMgr;
    const unsigned char *TokStart;
    const unsigned char *LastTokStart;
    std::vector<const unsigned char *> Ifs;
    std::vector<std::vector<const unsigned char *>> Ifstack;
    StringMap<unsigned> ignoreMacros;
    LLVMContext &C;
    std::string CurString;
    int64_t CurNumber;
    unsigned TypeFlags;
    int BufferID;
    SmallVector<unsigned, 2> TypeFlagsList;
    std::map<std::string, tok::kind> keywords;
    DenseMap<const Type *, std::string> typeNames;
    tok::kind delimiters[256];
    std::vector<llvm::Type *> opaqueTypes;
    std::set<std::string> functionNames;
    std::set<std::string> globalNames;

    typedef std::vector<std::pair<std::string, struct FunctionProto>> FunctionListTy;
    typedef StringMap<const Type *> GlobalMapTy;
    GlobalMapTy globals;
    FunctionListTy functions;
    const FunctionType *Api0Ty;
    const FunctionType *Api1Ty;
    const FunctionType *Api2Ty;
    const FunctionType *Api3Ty;
    const FunctionType *Api4Ty;
    const FunctionType *Api5Ty;
    const FunctionType *Api6Ty;
    const FunctionType *Api7Ty;
    const FunctionType *Api8Ty;
    const FunctionType *Api9Ty;

    void outputTypename(raw_ostream &Out, const Type *Ty,
                        unsigned TypeFlag, bool after = false);
    void outputAPIcalls(raw_ostream &Out);
    void printApiCalls(raw_ostream &Out, const std::string &Type,
                       FunctionListTy &List, unsigned i);
    void outputHeader(raw_ostream &Out, const std::string HeaderName);

    void InitLangKeywords();
    tok::kind printError(const unsigned char *pos, const std::string &Msg)
    {
        SrcMgr.PrintMessage(SMLoc::getFromPointer((const char *)pos), Msg,
                            "error");
        return tok::Error;
    }

    int64_t LexNumber()
    {
        uint64_t n             = 0;
        const unsigned char *p = TokStart;
        bool negative          = false;
        if (*p == '-') {
            negative = true;
            p++;
        }
        while (isdigit(*p)) {
            n = n * 10 + (*p - '0');
            p++;
        }
        TokStart = p;
        if (negative) {
            n *= -1;
        }
        return n;
    }

    tok::kind LexIdentifier()
    {
        CurString              = "";
        const unsigned char *p = TokStart;
        for (p = TokStart; *p; p++) {
            const unsigned char c = *p;
            if (p == TokStart && isdigit(c)) {
                return printError(p, "Identifier cannot start with digit");
            }
            if (isspace(c) || delimiters[c] != tok::None)
                break;
            if (isalnum(c) || c == '_') {
                CurString += c;
                continue;
            }
            printError(p, "Unexpected character");
            return printError(TokStart, "while parsing identifier");
        }
        TokStart = p;
        return tok::String;
    }

    bool LexComment(const unsigned char *&p)
    {
        // Lex comment
        if (p[1] == '*') {
            // Look for */
            p += 2;
            while (p[0] && (p[0] != '*' || p[1] != '/')) p++;
            if (!*p) {
                printError(p, "EOF encountered while scanning for */");
                return false;
            }
            p += 2;
            return true;
        }

        if (p[1] == '/') {
            // Look for \n
            p += 2;
            while (p[0] && (p[0] != '\n')) p++;
            if (!*p)
                return true;
            p++;
            return true;
        }

        printError(p, "/* or // comment expected");
        return false;
    }

    tok::kind LexToken()
    {
        LastTokStart    = TokStart;
        tok::kind token = Lex();
        if (token == tok::Error || token == tok::End)
            return token;
        if (LastTokStart == TokStart)
            return printError(TokStart, "Lexer inflooping!");
        while (token == tok::String) {
            StringMap<unsigned>::iterator I = ignoreMacros.find(CurString);
            if (I != ignoreMacros.end()) {
                LastTokStart = TokStart;
                token        = Lex();
                if (token != tok::ParOpen)
                    return printError(LastTokStart, "expected ( after macro");
                for (unsigned i = 0; i < I->second; i++) {
                    Lex();
                    LastTokStart = TokStart;
                    token        = Lex();
                    if (i + 1 < I->second && token != tok::Comma)
                        return printError(LastTokStart, "expected , in macro arguments");
                }
                if (token != tok::ParClose)
                    return printError(LastTokStart, "expected ) after macro");
                token = Lex();
                continue;
            }
            break;
        }
        return token;
    }

    tok::kind Lex()
    {
        tok::kind kind;
        const unsigned char *p = TokStart;
        while (*p) {
            if (isspace(*p)) {
                p++;
                while (*p && isspace(*p)) p++;
                continue;
            }
            LastTokStart = p;
            TokStart     = p;
            if (*p == '/') {
                if (!LexComment(p))
                    return tok::Error;
                continue;
            }
            if (*p == '#') {
                if (!strncmp((const char *)p, "#ifdef ", 7)) {
                    Ifs.push_back(p);
                    TokStart        = p + 7;
                    tok::kind token = LexIdentifier();
                    if (token != tok::String)
                        return token;
                    if (CurString == "__CLAMBC__") {
                        p = TokStart;
                        continue;
                    }
                    return printError(p, "Only __CLAMBC__ and __has_feature #ifdef supported");
                }
                if (!strncmp((const char *)p, "#ifndef ", 8)) {
                    Ifs.push_back(p);
                    TokStart        = p + 8;
                    tok::kind token = LexIdentifier();
                    if (token != tok::String)
                        return token;
                    p = TokStart;
                    if (CurString == "__CLAMBC__") {
                        do {
                            p = (const unsigned char *)strchr((const char *)p + 1, '#');
                        } while (p && strncmp((const char *)p, "#endif", 6));
                        if (!p)
                            return printError(TokStart, "Missing #endif");
                        continue;
                    } else {
                        if (CurString.length() <= 2 ||
                            CurString.substr(CurString.length() - 2) != "_H")
                            return printError(p, "Only __CLAMBC__ and _H defines are supported");
                    }
                    continue;
                }

                if (!strncmp((const char *)p, "#define ", 8)) {
                    TokStart        = p + 8;
                    tok::kind token = LexIdentifier();
                    if (token != tok::String)
                        return token;
                    p = TokStart;
                    if (CurString.length() <= 2 ||
                        CurString.substr(CurString.length() - 2) != "_H")
                        return printError(p, "Only _H defines are supported");
                    continue;
                }

                if (!strncmp((const char *)p, "#endif", 6)) {
                    if (Ifs.empty())
                        return printError(p, "#endif without #if(def)");
                    Ifs.pop_back();
                    p += 6;
                    continue;
                }

                if (!strncmp((const char *)p, "#include \"", 10)) {
                    const unsigned char *includeName;
                    p += 10;
                    includeName = p;
                    while (*p && *p != '"') p++;
                    if (*p != '"')
                        return printError(includeName, "Unterminated string, expected \"");
                    std::string include((const char *)includeName, p - includeName);
                    p++;
                    if (include == "bcfeatures.h")
                        continue;
                    SMLoc Loc = SMLoc::getFromPointer((const char *)p);
                    Ifstack.push_back(Ifs);
                    Ifs.clear();
                    BufferID = SrcMgr.AddIncludeFile(include, Loc);
                    if (BufferID == -1)
                        return printError(includeName, "Include file not found: " + include);
                    p = (const unsigned char *)SrcMgr.getMemoryBuffer(BufferID)->getBufferStart();
                    continue;
                }
                return printError(TokStart, "Unexpected preprocessor directive");
            }

            // Check whether this is a delimiter
            kind = delimiters[*p];
            if (kind != tok::None) {
                TokStart = p + 1;
                return kind;
            }

            if (isdigit(*p) || *p == '-') {
                CurNumber = LexNumber();
                return tok::Number;
            }

            // Lex as identifier
            kind = LexIdentifier();
            if (kind != tok::String)
                return kind;

            // Check whether this is actually a keyword
            std::map<std::string, tok::kind>::const_iterator kw =
                keywords.find(CurString);
            if (kw != keywords.end()) {
                if (kw->second == tok::ReservedType)
                    return printError(p, "Using this type is not allowed (use a fixed-width integer type instead)!");
                if (kw->second == tok::Reserved)
                    return printError(p, "Using C/C99/GNUC/MSC keywords is not allowed!");
                if (kw->second == tok::ReservedCXX)
                    return printError(p, "Using C++/C++0x keywords is not allowed!");
                return kw->second;
            }

            // No, just an identifier
            return tok::String;
        }
        return tok::End;
    }

    std::map<std::string, llvm::Type *> namedTypes;

    llvm::Type *ParseType(tok::kind token, bool &Ok)
    {
        std::map<std::string, llvm::Type *>::iterator namedType;
        if (token == tok::End) {
            printError(TokStart, "Type name expected, but EOF encountered");
            Ok = false;
            return Type::getVoidTy(C);
        }
        switch (token) {
            case tok::Const:
                TypeFlags |= ConstType;
                token = LexToken();
                return ParseType(token, Ok);
            case tok::Struct:
                token = LexToken();
                if (token != tok::String) {
                    printError(LastTokStart, "Identifier expected after 'struct'");
                    Ok = false;
                    return Type::getVoidTy(C);
                }
                namedType = namedTypes.find(CurString);
                if (namedType == namedTypes.end()) {
                    // new struct type
                    llvm::Type *Ty = OpaqueType::get(C);
                    opaqueTypes.push_back(Ty);
                    namedTypes.insert(std::pair<std::string, llvm::Type *>(CurString, Ty));
                    return Ty;
                }
                return namedType->second;
            case tok::String:
                printError(LastTokStart, "Type name expected, but identifier found");
                Ok = false;
                return Type::getVoidTy(C);
            case tok::Int8:
                TypeFlags |= SignedType;
                /* Fall-through */
            case tok::UInt8:
                return Type::getInt8Ty(C);
            case tok::Int16:
                TypeFlags |= SignedType;
                /* Fall-through */
            case tok::UInt16:
                return Type::getInt16Ty(C);
            case tok::Int32:
                TypeFlags |= SignedType;
                /* Fall-through */
            case tok::UInt32:
                return Type::getInt32Ty(C);
            case tok::Int64:
                TypeFlags |= SignedType;
                /* Fall-through */
            case tok::UInt64:
                return Type::getInt64Ty(C);
            case tok::Void:
                return Type::getVoidTy(C);
            case tok::Extern:
                token = LexToken();
                return ParseType(token, Ok);
            default:
                printError(LastTokStart, "Type name expected");
                Ok = false;
                return Type::getVoidTy(C);
        }
    }

    tok::kind ParseTypeFully(Type &Ty, tok::kind token)
    {
        TypeFlags      = 0;
        bool Ok        = true;
        llvm::Type hTy = ParseType(token, Ok);
        if (!Ok)
            return tok::Error;
        Ty = hTy.get();

        do {
            tok::kind token = LexToken();
            switch (token) {
                case tok::Pointer:
                    if (Ty == Type::getVoidTy(C))
                        Ty = Type::getInt8Ty(C);
                    Ty = PointerType::getUnqual(Ty);
                    continue;
                default:
                    return token;
            }
        } while (1);
    }

    void printType(const Type *Ty)
    {
        for (std::map<std::string, llvm::Type *>::iterator I = namedTypes.begin(),
                                                           E = namedTypes.end();
             I != E; ++I) {
            if (I->second == Ty) {
                errs() << I->first;
                return;
            }
        }
        errs() << *Ty;
    }

    // returns size of type, and maximum alignment
    unsigned checkTypeSize(const Type *Ty, unsigned &MaxAlign)
    {
        // Accept just simple types: i8, i16, i32, i64,
        // arrays and structs consisting of these.
        if (Ty->isIntegerTy()) {
            unsigned s = Ty->getPrimitiveSizeInBits();
            if (s != 8 && s != 16 &&
                s != 32 && s != 64) {
                errs() << "Only 8,16,32, and 64-bit integers are supported in APIs: " << *Ty << "\n";
                return 0;
            }
            MaxAlign = s / 8;
            return s / 8;
        }
        if (isa<PointerType>(Ty)) {
            errs() << "Pointers to pointers are not allowed at this time in APIs: ";
            printType(Ty);
            errs() << "\n";
            return 0;
        }
        if (const ArrayType *ATy = dyn_cast<ArrayType>(Ty)) {
            // maxalign of array == maxalign of its element
            unsigned e = checkTypeSize(ATy->getElementType(), MaxAlign);
            if (!e) {
                errs() << "Element for array type ";
                printType(ATy);
                errs() << " is not allowed in APIs\n";
                return 0;
            }
            return ATy->getNumElements() * e;
        }
        if (const StructType *STy = dyn_cast<StructType>(Ty)) {
            // For non-packed structs check that all fields are aligned to the maximum
            // alignment, and that the struct is padded according to maximum padding
            // it could get.
            // This ensures that the C type matches the LLVM type even with a
            // different targetdata, basically its a check that a packed struct
            // would have same layout as a non-packed one.
            // This is a conservative check.
            unsigned size = 0, fields = 1;
            bool valid = true;
            MaxAlign   = 1;
            for (StructType::element_iterator I = STy->element_begin(), E = STy->element_end();
                 I != E; ++I) {
                unsigned M;
                unsigned s = checkTypeSize(*I, M);
                if (!s)
                    valid = false;
                if (!STy->isPacked()) {
                    // non-packed struct, need to consider alignment and padding
                    if (M > MaxAlign)
                        MaxAlign = M;
                    if (size & (M - 1)) {
                        errs() << "Field " << fields << " in ";
                        printType(STy);
                        errs() << " needs to be aligned to " << M << " bytes.\n";
                        errs() << "\tsuggestion: insert " << (size & (M - 1)) << " bytes of "
                                                                                 "padding via a dummy field\n";
                        size += (size & (M - 1));
                        valid = false;
                    }
                }
                size += s;
                fields++;
            }
            if (size & (MaxAlign - 1)) {
                errs() << "Struct ";
                printType(STy);
                errs() << " needs " << MaxAlign << " bytes of "
                                                   "alignment,\n\tand needs "
                       << (size & (MaxAlign - 1)) << " bytes of "
                                                     "padding at the end\n";
                valid = false;
            }
            if (!valid) {
                errs() << "Struct type ";
                printType(STy);
                errs() << " is not accepted in API calls\n";
                return 0;
            }
            return size;
        }
        errs() << "Unknown type ";
        printType(Ty);
        errs() << " is not accepted in API calls\n";
        return 0;
    }

    bool checkParam(const std::string &Func, unsigned param, const Type *Ty)
    {
        if (Ty->isIntegerTy())
            return true;
        const PointerType *PTy = dyn_cast<PointerType>(Ty);
        bool valid             = true;
        if (!PTy) {
            errs() << "Non-pointer/non-integer type in function parameter\n";
            valid = false;
        } else {
            unsigned A;
            if (!checkTypeSize(PTy->getElementType(), A))
                valid = false;
        }
        if (!valid) {
            errs() << "Function " << Func << " parameter " << param << " has unaccepted type!\n";
        }
        return valid;
    }

    // check that we are only passing pointers to struct with fixed size and field
    // offsets (i.e. padding/alignment is not platform dependent).
    bool checkFuncParams(const std::string &Func, const FunctionType *Ty)
    {
        bool valid = true;
        valid &= checkParam(Func, 0, Ty->getReturnType());
        for (unsigned i = 0; i < Ty->getNumParams(); i++) {
            valid &= checkParam(Func, i + 1, Ty->getParamType(i));
        }
        return valid;
    }

    bool ParseFunctionPrototype(Type *&Ty, tok::kind token)
    {
        bool ok = true;
        TypeFlagsList.clear();
        // Already parsed the return type
        Type *RetTy = Ty;
        TypeFlagsList.push_back(TypeFlags);
        // Check valid return type for LLVM
        if (!FunctionType::isValidReturnType(RetTy)) {
            printError(LastTokStart, "Invalid return type");
            ok = false;
        } else if (!isa<IntegerType>(Ty) && Ty != Type::getVoidTy(C)) {
            // special-case for malloc-like functions
            const PointerType *PTy = dyn_cast<PointerType>(Ty);
            if (!PTy || PTy->getElementType() != Type::getInt8Ty(C)) {
                // Check valid return type for clambc
                printError(LastTokStart, "Only integer and void return types are supported");
                ok = false;
            }
        }

        std::vector<const Type *> params;
        if (token != tok::ParOpen) {
            printError(LastTokStart, "( expected");
            return false;
        }
        do {
            token = LexToken();
            if (token == tok::ParClose) {
                if (params.size() == 0) {
                    printError(LastTokStart, "function prototypes must use (void) instead of ()");
                    ok = false;
                }
                break;
            }

            token = ParseTypeFully(Ty, token);
            if (token == tok::End) {
                printError(LastTokStart, "EOF encountered while parsing typename");
                return false;
            }
            if (token == tok::Error)
                return false;

            // Parse (void)
            if (Ty == Type::getVoidTy(C) && params.empty()) {
                if (token != tok::ParClose) {
                    printError(LastTokStart, ") expected");
                    return false;
                }
                break;
            }

            if (!FunctionType::isValidArgumentType(Ty)) {
                printError(LastTokStart, "Invalid argument type");
                ok = false;
            }

            if (!isa<IntegerType>(Ty) && !isa<PointerType>(Ty)) {
                printError(LastTokStart, "Only integer and pointer types are supported");
                ok = false;
            }
            params.push_back(Ty);
            TypeFlagsList.push_back(TypeFlags);

            if (params.size() > 5) {
                printError(LastTokStart, "At most 5 parameters supported for API calls");
                ok = false;
            }

            if (token == tok::String)
                token = LexToken(); // Skip parameter name
            if (token == tok::Comma)
                continue;
            if (token == tok::ParClose)
                break;
            if (token == tok::End) {
                printError(LastTokStart, "EOF encountered while parsing function prototype");
                return false;
            }
            printError(LastTokStart, ", or ) expected");
            return false;
        } while (1);

        token = LexToken();
        if (token != tok::SemiColon) {
            printError(LastTokStart, "; expected");
            return false;
        }

        if (ok) {
            Ty = FunctionType::get(RetTy, params, false);
            return true;
        }
        Ty = 0;
        return false;
    }

    bool ParseStructDecl(llvm::Type *STy)
    {
        Type *Ty;
        std::vector<const Type *> fields;

        tok::kind token = LexToken();
        while (token != tok::BraceClose) {
            const unsigned char *p = LastTokStart;
            token                  = ParseTypeFully(Ty, token);

            if (token == tok::Error) {
                printError(p, "Structure field expected");
                return false;
            }
            if (token == tok::End) {
                printError(p, "EOF encountered while parsing struct declaration");
                return false;
            }

            if (!StructType::isValidElementType(Ty)) {
                printError(LastTokStart, "Invalid structure field type");
                printError(p, "Structure field expected");
                return false;
            }

            if (token != tok::String) {
                printError(LastTokStart, "Structure field name expected");
                printError(p, "Structure field expected");
                return false;
            }

            token = LexToken();
            Ty    = parseOptionalArraySize(token, Ty);
            if (!Ty) {
                printError(p, "Structure field expected");
                return false;
            }
            fields.push_back(Ty);
            token = LexToken();
        }

        StructType *NewSTy = StructType::get(C, fields);
        cast<OpaqueType>(STy.get())->refineAbstractTypeTo(NewSTy);
        token = LexToken();
        if (token != tok::SemiColon) {
            printError(LastTokStart, "; expected");
            return false;
        }
        return true;
    }

    const Type *parseOptionalArraySize(tok::kind &token, Type *Ty)
    {
        std::vector<unsigned> dimensions;
        while (token != tok::SemiColon) {
            if (token != tok::SquareBracketOpen) {
                return 0; //don't print error here, let parent handle
            }
            token = Lex();
            if (token != tok::Number) {
                printError(LastTokStart, "Expected numeric array size");
                return 0;
            }
            int64_t numElements = CurNumber;
            if (numElements < 0) {
                // we parse as unsigned, if sign bit is set we can't interpret
                // as signed.
                printError(LastTokStart, "Array size too large");
                return 0;
            }
            if (numElements == 0) {
                printError(LastTokStart, "Expected non-zero array size");
                return 0;
            }
            token = LexToken();
            if (token != tok::SquareBracketClose) {
                printError(LastTokStart, "Expected ] after array size");
                return 0;
            }
            dimensions.push_back(numElements);
            token = LexToken();
        }
        while (!dimensions.empty()) {
            Ty = ArrayType::get(Ty, dimensions.back());
            dimensions.pop_back();
        }
        return Ty;
    }
};
// Map keywords types from TokenKinds.def to our token kinds
#define BOOLSUPPORT 2
#define KEYALL 1
#define KEYC99 1
#define KEYCXX 2
#define KEYCXX0X 2
#define KEYGNU 1
#define KEYMS 1
#define KEYALTIVEC 1

void Parser::InitLangKeywords()
{
    // Add all C/C99/C++/C++0x/GNUC/MSC keywords as reserved keywords
#define KEYWORD(NAME, FLAGS) keywords[#NAME] = ((FLAGS)&1) ? tok::Reserved : tok::ReservedCXX;
#include "clang/Basic/TokenKinds.def"
}

bool Parser::parse()
{
    llvm::PrettyStackTraceString CrashInfo("Parsing input");
    const char *start = SrcMgr.getMemoryBuffer(BufferID)->getBufferStart();
    tok::kind token;

    do {
        TokStart = (const unsigned char *)start;

        do {
            Type *Ty;
            bool Ok = true;

            token = LexToken();
            if (token == tok::End)
                break;

            while (token == tok::Enum) {
                token = LexToken();
                if (token == tok::String)
                    token = LexToken();
                if (token != tok::BraceOpen) {
                    token = printError(LastTokStart, "Expected { after enum");
                    break;
                }
                while (token != tok::BraceClose && token != tok::Error && token != tok::End) {
                    token = LexToken();
                }
                token = LexToken();
                if (token == tok::End) {
                    token = printError(LastTokStart, "EOF encountered, expected } after enum");
                    break;
                }
                if (token == tok::Error)
                    break;
                if (token != tok::SemiColon) {
                    token = printError(LastTokStart, "Expected ; after enum");
                    break;
                }
                token = LexToken();
            }

            TypeFlags       = 0;
            llvm::Type *hTy = ParseType(token, Ok);
            if (!Ok) {
                token = tok::Error;
                break;
            }

            Ty    = hTy.get();
            token = LexToken();
            if (token == tok::Pointer) {
                if (Ty == Type::getVoidTy(C))
                    Ty = Type::getInt8Ty(C);
                Ty    = PointerType::getUnqual(Ty);
                token = LexToken();
            }
            const unsigned char *MLastTokStart = LastTokStart;
            std::string Func;
            struct FunctionProto SFunc;
            Type *ATy;
            switch (token) {
                case tok::String:
                    Func  = CurString;
                    token = LexToken();
                    ATy   = parseOptionalArraySize(token, Ty);
                    if (ATy) {
                        Ty = ATy;
                        // This is a global variable
                        if (!StringRef(Func).startswith("__clambc_")) {
                            token = printError(MLastTokStart, "Global variable name must begin with __clambc_");
                            break;
                        }
                        if (globalNames.count(Func)) {
                            token = printError(MLastTokStart, "Global " + CurString + " already declared");
                            break;
                        }
                        globalNames.insert(Func);
                        unsigned A;
                        if (!checkTypeSize(Ty, A)) {
                            token = printError(MLastTokStart, "Global " + CurString + " has "
                                                                                      "unaccepted type in API");
                        }
                        globals[Func] = Ty;
                    } else {
                        // This is a function prototype
                        if (!ParseFunctionPrototype(Ty, token)) {
                            token = printError(MLastTokStart, "Function prototype expected");
                            break;
                        }
                        if (functionNames.count(Func)) {
                            token = printError(MLastTokStart, "Function " + Func + " already declared");
                            break;
                        }
                        if (StringRef(Func).startswith("__clambc_")) {
                            token = printError(MLastTokStart, "Function name cannot begin with __clambc_");
                            break;
                        }
                        SFunc.Ty        = cast<FunctionType>(Ty);
                        SFunc.TypeFlags = TypeFlagsList;
                        if (!checkFuncParams(Func, SFunc.Ty)) {
                            token = printError(MLastTokStart, "Function " + Func + " has "
                                                                                   "unaccepted parameters!");
                            break;
                        }
                        functionNames.insert(Func);
                        functions.push_back(std::pair<std::string, struct FunctionProto>(Func, SFunc));
                    }
                    break;
                case tok::BraceOpen:
                    // This is a struct declaration
                    if (!ParseStructDecl(hTy)) {
                        token = printError(MLastTokStart, "Structure type declaration expected");
                    }
                    break;
                default:
                    token = printError(MLastTokStart, "{ or identifier expected");
                    break;
            }
        } while (token != tok::Error && token != tok::End);

        if (token == tok::Error)
            break;
        while (!Ifs.empty()) {
            printError(Ifs.back(), "Unterminated #if");
            Ifs.pop_back();
        }
        SMLoc Loc = SrcMgr.getParentIncludeLoc(BufferID);
        BufferID  = SrcMgr.FindBufferContainingLoc(Loc);
        start     = Loc.getPointer();
        assert(BufferID != -1 || !Loc.isValid());
        if (BufferID != -1) {
            assert(!Ifstack.empty());
            Ifs = Ifstack.back();
            Ifstack.pop_back();
        }
    } while (BufferID != -1);
    return token == tok::End;
}

void Parser::printApiCalls(raw_ostream &Out, const std::string &Type,
                           FunctionListTy &List, unsigned i)
{
    Out << "const " << Type << " cli_apicalls" << i << "[] = {\n";
    for (FunctionListTy::iterator I = List.begin(), E = List.end();
         I != E;) {
        Out << "\t";
        //	if (i == 1 && I->second != Api1Ty) {
        Out << "(" << Type << ")";
        //	}
        Out << "cli_bcapi_" << I->first;
        ++I;
        if (I != E)
            Out << ",\n";
    }
    Out << "\n};\n";
}

void Parser::outputHeader(raw_ostream &Out, const std::string HeaderName)
{
    time_t rawtime;
    struct tm *tm;

    time(&rawtime);
    tm = gmtime(&rawtime);

    Out << "/*\n"
        << " *  ClamAV bytecode internal API\n";
    Out << " *  This is an automatically generated file!\n"
        << " *\n";
    Out << " *  Copyright (C) 2013-" << (1900 + tm->tm_year)
        << " Cisco Systems, Inc. and/or its affiliates. All rights reserved.\n"
        << " *  Copyright (C) 2009-2013 Sourcefire, Inc.\n"
        << " *\n"
        << " * Redistribution and use in source and binary forms, with or without\n"
        << " * modification, are permitted provided that the following conditions\n"
        << " * are met:\n"
        << " * 1. Redistributions of source code must retain the above copyright\n"
        << " *    notice, this list of conditions and the following disclaimer.\n"
        << " * 2. Redistributions in binary form must reproduce the above copyright\n"
        << " *    notice, this list of conditions and the following disclaimer in the\n"
        << " *    documentation and/or other materials provided with the distribution.\n"
        << " *\n"
        << " * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND\n"
        << " * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE\n"
        << " * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE\n"
        << " * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE\n"
        << " * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL\n"
        << " * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS\n"
        << " * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)\n"
        << " * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT\n"
        << " * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY\n"
        << " * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF\n"
        << " * SUCH DAMAGE\n"
        << " */\n";
    if (HeaderName.empty())
        Out << "#include \"clamav-types.h\"\n#include \"type_desc.h\"\n"
            << "#include \"bytecode_api.h\"\n"
            << "#include \"bytecode_api_impl.h\"\n"
            << "#include \"bytecode_priv.h\"\n"
            << "#include <stdlib.h>\n"
            << "\n";
    else
        Out << "#ifndef " << UppercaseString(HeaderName) << "_H\n"
            << "#define " << UppercaseString(HeaderName) << "_H\n\n";
}

void Parser::outputTypename(raw_ostream &Out, const Type *Ty, unsigned TypeFlag, bool after)
{
    if (after) {
        return;
    }
    if (TypeFlag & ConstType) {
        Out << "const ";
        TypeFlag &= ~ConstType;
    }
    if (const ArrayType *ATy = dyn_cast<ArrayType>(Ty)) {
        outputTypename(Out, ATy->getElementType(), TypeFlag);
        Out << "*";
        return;
    }
    if (const IntegerType *ITy = dyn_cast<IntegerType>(Ty)) {
        Out << (TypeFlag & SignedType ? "int" : "uint") << ITy->getBitWidth() << "_t";
        return;
    }
    if (isa<StructType>(Ty))
        Out << "struct ";
    DenseMap<const Type *, std::string>::iterator I = typeNames.find(Ty);
    if (I != typeNames.end()) {
        Out << I->second;
        return;
    }
    if (const PointerType *PTy = dyn_cast<PointerType>(Ty)) {
        outputTypename(Out, PTy->getElementType(), TypeFlag);
        Out << "*";
        return;
    }
    assert(0 && "Not reached");
}

void Parser::outputAPIcalls(raw_ostream &Out)
{
    for (FunctionListTy::iterator I = functions.begin(), E = functions.end();
         I != E; ++I) {
        const FunctionType *FTy = I->second.Ty;
        const Type *Ty          = FTy->getReturnType();
        outputTypename(Out, Ty, I->second.TypeFlags[0]);
        Out << " cli_bcapi_" << I->first << "(";
        Out << "struct cli_bc_ctx *ctx ";
        unsigned j = 1;
        for (FunctionType::param_iterator J  = FTy->param_begin(),
                                          JE = FTy->param_end();
             J != JE;) {
            Out << ", ";
            outputTypename(Out, *J, I->second.TypeFlags[j++]);
            ++J;
        }
        Out << ");\n";
    }
    Out << "\n";
}

bool Parser::output(raw_ostream &Out, raw_ostream &OutImpl, raw_ostream &OutHooks)
{
    for (std::map<std::string, Type *>::iterator I = namedTypes.begin(),
                                                 E = namedTypes.end();
         I != E; ++I) {
        typeNames[I->second] = I->first;
    }

    FunctionListTy apicalls[11];
    for (FunctionListTy::iterator I = functions.begin(), E = functions.end();
         I != E; ++I) {

        const FunctionType *FTy = I->second.Ty;
        if (FTy == Api0Ty) {
            apicalls[0].push_back(*I);
            continue;
        }

        if (FTy == Api1Ty) {
            apicalls[1].push_back(*I);
            continue;
        }

        if (FTy == Api2Ty) {
            apicalls[2].push_back(*I);
            continue;
        }

        if (FTy == Api3Ty) {
            apicalls[3].push_back(*I);
            continue;
        }

        if (FTy == Api4Ty) {
            apicalls[4].push_back(*I);
            continue;
        }

        if (FTy == Api5Ty) {
            apicalls[5].push_back(*I);
            continue;
        }

        if (FTy == Api6Ty) {
            apicalls[6].push_back(*I);
            continue;
        }

        if (FTy == Api7Ty) {
            apicalls[7].push_back(*I);
            continue;
        }

        if (FTy == Api8Ty) {
            apicalls[8].push_back(*I);
            continue;
        }

        if (FTy == Api9Ty) {
            apicalls[9].push_back(*I);
            continue;
        }

        if (FTy->getReturnType() == Type::getInt32Ty(C) &&
            isa<PointerType>(FTy->getParamType(0)) &&
            FTy->getParamType(1) == Type::getInt32Ty(C)) {

            apicalls[1].push_back(*I);
            continue;
        }

        errs() << "Function prototype for '" << I->first << "' doesn't match any of the known API call prototypes: ";
        errs() << *FTy << "\n";
        return false;
    }

    DenseMap<const Type *, unsigned> typeIDs;
    unsigned int tid      = clamav::initTypeIDs(typeIDs, C);
    unsigned int tidStart = tid;
    std::vector<const Type *> apiTypes;
    std::vector<const Type *> addTypes;

    for (FunctionListTy::iterator I = functions.begin(), E = functions.end();
         I != E; ++I) {

        addTypes.push_back(I->second.Ty);
    }
    for (GlobalMapTy::iterator I = globals.begin(), E = globals.end();
         I != E; ++I) {

        addTypes.push_back(I->second);
    }

    while (!addTypes.empty()) {
        const Type *Ty = addTypes.back();
        addTypes.pop_back();

        if (typeIDs.count(Ty))
            continue;
        apiTypes.push_back(Ty);
        typeIDs[Ty] = tid++;
        for (Type::subtype_iterator I = Ty->subtype_begin(), E = Ty->subtype_end();
             I != E; ++I) {
            if (isa<OpaqueType>(I->get()) && isa<PointerType>(Ty))
                continue;
            addTypes.push_back(*I);
        }
    }

    // Output file headers
    outputHeader(Out, "");
    outputHeader(OutImpl, "bytecode_api_impl");
    outputHeader(OutHooks, "bytecode_hooks");

    OutImpl << "struct cli_bc_bctx;\n";
    OutImpl << "struct cli_environment;\n";
    // output API calls
    outputAPIcalls(Out);
    outputAPIcalls(OutImpl);
    OutImpl << "#endif\n";

    // Output globals
    OutHooks << "struct cli_bc_hooks {\n";
    Out << "const struct cli_apiglobal cli_globals[] = {\n";
    Out << clamav::globals_begin << "\n";
    for (GlobalMapTy::iterator I = globals.begin(), E = globals.end();
         I != E;) {
        Out << "\t{\"" << I->getKey() << "\", GLOBAL" << UppercaseString(I->getKey().substr(8).str()) << ", "
            << typeIDs[I->getValue()]
            << ",\n\t ((char*)&((struct cli_bc_ctx*)0)->hooks."
            << I->getKey().substr(9).str()
            << " - (char*)NULL)}";
        OutHooks << "\t const ";
        outputTypename(OutHooks, I->getValue(), 0);
        // They are really pointers, so unless they are arrays (in which case they
        // are already pointers), we need to make them pointers.
        if (!isa<ArrayType>(I->getValue()))
            OutHooks << "*";
        OutHooks << " " << I->getKey().substr(9).str();
        outputTypename(OutHooks, I->getValue(), 0, true);
        OutHooks << ";\n";
        ++I;
        if (I != globals.end())
            Out << ",";
        Out << "\n";
    }
    OutHooks << "};\n#endif\n";
    Out << clamav::globals_end << "\n";
    Out << "};\n";
    Out << "const unsigned cli_apicall_maxglobal = _LAST_GLOBAL-1;\n";

    // Output types
    for (unsigned i = tidStart; i < tid; i++) {
        assert(typeIDs[apiTypes[i - tidStart]] == i);
        const Type *Ty = apiTypes[i - tidStart];

        Out << "static uint16_t cli_tmp" << (i - tidStart) << "[]={";
        for (Type::subtype_iterator I = Ty->subtype_begin(), E = Ty->subtype_end();
             I != E;) {
            int id = typeIDs[*I];
            if (!id)
                id = 8; //void* -> i8*
            Out << id;
            ++I;
            if (I != E)
                Out << ", ";
        }

        Out << "};\n";
    }
    Out << "\nconst struct cli_bc_type cli_apicall_types[]={\n";
    for (unsigned i = tidStart; i < tid; i++) {
        assert(typeIDs[apiTypes[i - tidStart]] == i);

        Out << "\t{";
        const Type *Ty = apiTypes[i - tidStart];
        if (isa<PointerType>(Ty))
            Out << "DPointerType";
        else if (isa<StructType>(Ty))
            Out << "DStructType";
        else if (isa<ArrayType>(Ty))
            Out << "DArrayType";
        else if (isa<FunctionType>(Ty)) {
            Out << "DFunctionType";
        } else {
            assert("Unhandled type!");
        }
        Out << ", cli_tmp" << (i - tidStart);

        Out << ", ";
        if (isa<PointerType>(Ty))
            Out << "1";
        else if (const StructType *STy = dyn_cast<const StructType>(Ty)) {
            Out << STy->getNumElements();
        } else if (const ArrayType *ATy = dyn_cast<const ArrayType>(Ty)) {
            Out << ATy->getNumElements();
        } else if (const FunctionType *FTy = dyn_cast<const FunctionType>(Ty)) {
            Out << (FTy->getNumParams() + 1);
        }
        Out << ", 0, 0}";
        if (i < tid - 1)
            Out << ",\n";
    }
    Out << "\n};\n";
    Out << "\nconst unsigned cli_apicall_maxtypes=sizeof(cli_apicall_types)/sizeof(cli_apicall_types[0]);\n";

    Out << "const struct cli_apicall cli_apicalls[]={\n";
    Out << clamav::apicall_begin << "\n";
    uint16_t api0 = 0, api1 = 0, api2 = 0, api3 = 0, api4 = 0, api5 = 0, api6 = 0, api7 = 0, api8 = 0, api9 = 0;
    for (FunctionListTy::iterator I = functions.begin(), E = functions.end();
         I != E;) {

        const FunctionType *FTy = I->second.Ty;
        unsigned tid            = typeIDs[FTy];
        assert(tid && "Type not in map?");
        Out << "\t{\"" << I->first << "\", " << (tid - tidStart) << ", ";
        if (FTy == Api0Ty) {
            Out << api0++ << ", 0";
        } else if (FTy == Api2Ty) {
            Out << api2++ << ", 2";
        } else if (FTy == Api3Ty) {
            Out << api3++ << ", 3";
        } else if (FTy == Api4Ty) {
            Out << api4++ << ", 4";
        } else if (FTy == Api5Ty) {
            Out << api5++ << ", 5";
        } else if (FTy == Api6Ty) {
            Out << api6++ << ", 6";
        } else if (FTy == Api7Ty) {
            Out << api7++ << ", 7";
        } else if (FTy == Api8Ty) {
            Out << api8++ << ", 8";
        } else if (FTy == Api9Ty) {
            Out << api9++ << ", 9";
        } else if (FTy == Api1Ty ||
                   (FTy->getNumParams() == 2 &&
                    FTy->getReturnType() == Type::getInt32Ty(C) &&
                    isa<PointerType>(FTy->getParamType(0)) &&
                    FTy->getParamType(1) == Type::getInt32Ty(C))) {
            Out << api1++ << ", 1";
        } else {
            errs() << "Unknown prototype: " << *FTy << " for function " << I->first << "\n"
                   << "known prototypes: "
                   << *Api0Ty << "\n"
                   << *Api1Ty << "\n"
                   << *Api2Ty << "\n"
                   << *Api3Ty << "\n"
                   << *Api4Ty << "\n"
                   << *Api5Ty << "\n"
                   << *Api6Ty << "\n"
                   << *Api7Ty << "\n"
                   << *Api8Ty << "\n"
                   << *Api9Ty << "\n";
            return false;
        }
        Out << "}";

        ++I;
        if (I != E)
            Out << ",\n";
    }
    Out << "\n"
        << clamav::apicall_end << "\n};\n";
    Out << "const unsigned cli_numapicalls=sizeof(cli_apicalls)/sizeof(cli_apicalls[0]);\n\n";

    printApiCalls(Out, "cli_apicall_int2", apicalls[0], 0);
    printApiCalls(Out, "cli_apicall_pointer", apicalls[1], 1);
    printApiCalls(Out, "cli_apicall_int1", apicalls[2], 2);
    printApiCalls(Out, "cli_apicall_malloclike", apicalls[3], 3);
    printApiCalls(Out, "cli_apicall_ptrbuffdata", apicalls[4], 4);
    printApiCalls(Out, "cli_apicall_allocobj", apicalls[5], 5);
    printApiCalls(Out, "cli_apicall_bufget", apicalls[6], 6);
    printApiCalls(Out, "cli_apicall_int3", apicalls[7], 7);
    printApiCalls(Out, "cli_apicall_2bufs", apicalls[8], 8);
    printApiCalls(Out, "cli_apicall_ptrbufid", apicalls[9], 9);
    Out << "const unsigned cli_apicall_maxapi = sizeof(cli_apicalls)/sizeof(cli_apicalls[0]);\n";
    return true;
}

static void VersionPrinter(void)
{
    outs() << "ClamAV bytecode interface generator:\n";
    outs() << "  Using LLVM version " << PACKAGE_VERSION << "\n  ";
#ifndef __OPTIMIZE__
    outs() << "DEBUG build";
#else
    outs() << "Optimized build";
#endif
#ifndef NDEBUG
    outs() << " with assertions";
#endif
    outs() << ".\n";
    outs() << "  Built " << __DATE__ << "(" << __TIME__ << ").\n";
    outs() << "\n";
}

std::string GetExecutablePath(const char *Argv0)
{
    // This just needs to be some symbol in the binary; C++ doesn't
    // allow taking the address of ::main however.
    void *P = (void *)(intptr_t)GetExecutablePath;
    return llvm::sys::fs::getMainExecutable(Argv0, P);
}

int main(int argc, char *argv[])
{
    // Print a stack trace if we signal out.
    sys::PrintStackTraceOnErrorSignal();
    PrettyStackTraceProgram X(argc, argv);

    llvm_shutdown_obj Y; // Call llvm_shutdown() on exit.
    cl::SetVersionPrinter(VersionPrinter);
    cl::ParseCommandLineOptions(argc, argv, "ClamAV bytecode interface generator\n");

    SourceMgr SrcMgr;
    auto Path = std::filesystem::path(GetExecutablePath(argv[0]));
    Path      = Path.parent_path() / ".." / "lib" / "clang" / LLVM_VERSION_STRING / "include";

    std::vector<std::string> IncludeDirs;
    IncludeDirs.push_back(Path.c_str());
    SrcMgr.setIncludeDirs(IncludeDirs);

    ErrorOr<std::unique_ptr<MemoryBuffer>> Buffer = MemoryBuffer::getFileOrSTDIN(InputFilename);

    if (std::error_code EC = Buffer.getError()) {
        errs() << "Could not open input file '" << InputFilename << "': "
               << EC.message() << "\n";
        return 1;
    }

    std::error_code EC;
    raw_ostream *Out = new raw_fd_ostream(OutputFilename, EC);
    if (EC) {
        errs() << EC.message() << '\n';
        delete Out;
        return 1;
    }
    // Make sure that the Out file gets unlinked from the disk if we get a
    // SIGINT
    sys::RemoveFileOnSignal(StringRef(OutputFilename));

    raw_ostream *OutImpl = new raw_fd_ostream(OutputImplHeader, EC);
    if (EC) {
        errs() << EC.message() << '\n';
        delete OutImpl;
        return 1;
    }
    // Make sure that the Out file gets unlinked from the disk if we get a
    // SIGINT
    sys::RemoveFileOnSignal(StringRef(OutputImplHeader));

    raw_ostream *OutHooks = new raw_fd_ostream(OutputHooksHeader, EC);
    if (EC) {
        errs() << EC.message() << '\n';
        delete OutHooks;
        return 1;
    }
    // Make sure that the Out file gets unlinked from the disk if we get a
    // SIGINT
    sys::RemoveFileOnSignal(StringRef(OutputHooksHeader));

    static LLVMContext TheContext;
    IRBuilder<> Builder(TheContext);
    SrcMgr.AddNewSourceBuffer(std::move(Buffer.get()), SMLoc());
    Parser parser(SrcMgr, TheContext);
    if (!parser.parse())
        return 1;
    if (!parser.output(*Out, *OutImpl, *OutHooks))
        return 1;

    delete Out;
    delete OutImpl;
    delete OutHooks;
    return 0;
}
