//===--- SemaChecking.cpp - Extra Semantic Checking -----------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
//  This file implements extra semantic analysis beyond what is enforced
//  by the C type system.
//
//===----------------------------------------------------------------------===//

#include "clang/Sema/Sema.h"
#include "clang/Sema/SemaInternal.h"
#include "clang/Sema/ScopeInfo.h"
#include "clang/Analysis/Analyses/FormatString.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/CharUnits.h"
#include "clang/AST/DeclCXX.h"
#include "clang/AST/DeclObjC.h"
#include "clang/AST/ExprCXX.h"
#include "clang/AST/ExprObjC.h"
#include "clang/AST/DeclObjC.h"
#include "clang/AST/StmtCXX.h"
#include "clang/AST/StmtObjC.h"
#include "clang/Lex/LiteralSupport.h"
#include "clang/Lex/Preprocessor.h"
#include "llvm/ADT/BitVector.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/Basic/TargetBuiltins.h"
#include "clang/Basic/TargetInfo.h"
#include <limits>
using namespace clang;
using namespace sema;

/// getLocationOfStringLiteralByte - Return a source location that points to the
/// specified byte of the specified string literal.
///
/// Strings are amazingly complex.  They can be formed from multiple tokens and
/// can have escape sequences in them in addition to the usual trigraph and
/// escaped newline business.  This routine handles this complexity.
///
SourceLocation Sema::getLocationOfStringLiteralByte(const StringLiteral *SL,
                                                    unsigned ByteNo) const {
  assert(!SL->isWide() && "This doesn't work for wide strings yet");

  // Loop over all of the tokens in this string until we find the one that
  // contains the byte we're looking for.
  unsigned TokNo = 0;
  while (1) {
    assert(TokNo < SL->getNumConcatenated() && "Invalid byte number!");
    SourceLocation StrTokLoc = SL->getStrTokenLoc(TokNo);

    // Get the spelling of the string so that we can get the data that makes up
    // the string literal, not the identifier for the macro it is potentially
    // expanded through.
    SourceLocation StrTokSpellingLoc = SourceMgr.getSpellingLoc(StrTokLoc);

    // Re-lex the token to get its length and original spelling.
    std::pair<FileID, unsigned> LocInfo =
      SourceMgr.getDecomposedLoc(StrTokSpellingLoc);
    bool Invalid = false;
    llvm::StringRef Buffer = SourceMgr.getBufferData(LocInfo.first, &Invalid);
    if (Invalid)
      return StrTokSpellingLoc;
      
    const char *StrData = Buffer.data()+LocInfo.second;

    // Create a langops struct and enable trigraphs.  This is sufficient for
    // relexing tokens.
    LangOptions LangOpts;
    LangOpts.Trigraphs = true;

    // Create a lexer starting at the beginning of this token.
    Lexer TheLexer(StrTokSpellingLoc, LangOpts, Buffer.begin(), StrData,
                   Buffer.end());
    Token TheTok;
    TheLexer.LexFromRawLexer(TheTok);

    // Use the StringLiteralParser to compute the length of the string in bytes.
    StringLiteralParser SLP(&TheTok, 1, PP, /*Complain=*/false);
    unsigned TokNumBytes = SLP.GetStringLength();

    // If the byte is in this token, return the location of the byte.
    if (ByteNo < TokNumBytes ||
        (ByteNo == TokNumBytes && TokNo == SL->getNumConcatenated())) {
      unsigned Offset =
        StringLiteralParser::getOffsetOfStringByte(TheTok, ByteNo, PP,
                                                   /*Complain=*/false);

      // Now that we know the offset of the token in the spelling, use the
      // preprocessor to get the offset in the original source.
      return PP.AdvanceToTokenCharacter(StrTokLoc, Offset);
    }

    // Move to the next string token.
    ++TokNo;
    ByteNo -= TokNumBytes;
  }
}

/// CheckablePrintfAttr - does a function call have a "printf" attribute
/// and arguments that merit checking?
bool Sema::CheckablePrintfAttr(const FormatAttr *Format, CallExpr *TheCall) {
  if (Format->getType() == "printf") return true;
  if (Format->getType() == "printf0") {
    // printf0 allows null "format" string; if so don't check format/args
    unsigned format_idx = Format->getFormatIdx() - 1;
    // Does the index refer to the implicit object argument?
    if (isa<CXXMemberCallExpr>(TheCall)) {
      if (format_idx == 0)
        return false;
      --format_idx;
    }
    if (format_idx < TheCall->getNumArgs()) {
      Expr *Format = TheCall->getArg(format_idx)->IgnoreParenCasts();
      if (!Format->isNullPointerConstant(Context,
                                         Expr::NPC_ValueDependentIsNull))
        return true;
    }
  }
  return false;
}

ExprResult
Sema::CheckBuiltinFunctionCall(unsigned BuiltinID, CallExpr *TheCall) {
  ExprResult TheCallResult(Owned(TheCall));

  switch (BuiltinID) {
  case Builtin::BI__builtin___CFStringMakeConstantString:
    assert(TheCall->getNumArgs() == 1 &&
           "Wrong # arguments to builtin CFStringMakeConstantString");
    if (CheckObjCString(TheCall->getArg(0)))
      return ExprError();
    break;
  case Builtin::BI__builtin_stdarg_start:
  case Builtin::BI__builtin_va_start:
    if (SemaBuiltinVAStart(TheCall))
      return ExprError();
    break;
  case Builtin::BI__builtin_isgreater:
  case Builtin::BI__builtin_isgreaterequal:
  case Builtin::BI__builtin_isless:
  case Builtin::BI__builtin_islessequal:
  case Builtin::BI__builtin_islessgreater:
  case Builtin::BI__builtin_isunordered:
    if (SemaBuiltinUnorderedCompare(TheCall))
      return ExprError();
    break;
  case Builtin::BI__builtin_fpclassify:
    if (SemaBuiltinFPClassification(TheCall, 6))
      return ExprError();
    break;
  case Builtin::BI__builtin_isfinite:
  case Builtin::BI__builtin_isinf:
  case Builtin::BI__builtin_isinf_sign:
  case Builtin::BI__builtin_isnan:
  case Builtin::BI__builtin_isnormal:
    if (SemaBuiltinFPClassification(TheCall, 1))
      return ExprError();
    break;
  case Builtin::BI__builtin_return_address:
  case Builtin::BI__builtin_frame_address: {
    llvm::APSInt Result;
    if (SemaBuiltinConstantArg(TheCall, 0, Result))
      return ExprError();
    break;
  }
  case Builtin::BI__builtin_eh_return_data_regno: {
    llvm::APSInt Result;
    if (SemaBuiltinConstantArg(TheCall, 0, Result))
      return ExprError();
    break;
  }
  case Builtin::BI__builtin_shufflevector:
    return SemaBuiltinShuffleVector(TheCall);
    // TheCall will be freed by the smart pointer here, but that's fine, since
    // SemaBuiltinShuffleVector guts it, but then doesn't release it.
  case Builtin::BI__builtin_prefetch:
    if (SemaBuiltinPrefetch(TheCall))
      return ExprError();
    break;
  case Builtin::BI__builtin_object_size:
    if (SemaBuiltinObjectSize(TheCall))
      return ExprError();
    break;
  case Builtin::BI__builtin_longjmp:
    if (SemaBuiltinLongjmp(TheCall))
      return ExprError();
    break;
  case Builtin::BI__sync_fetch_and_add:
  case Builtin::BI__sync_fetch_and_sub:
  case Builtin::BI__sync_fetch_and_or:
  case Builtin::BI__sync_fetch_and_and:
  case Builtin::BI__sync_fetch_and_xor:
  case Builtin::BI__sync_add_and_fetch:
  case Builtin::BI__sync_sub_and_fetch:
  case Builtin::BI__sync_and_and_fetch:
  case Builtin::BI__sync_or_and_fetch:
  case Builtin::BI__sync_xor_and_fetch:
  case Builtin::BI__sync_val_compare_and_swap:
  case Builtin::BI__sync_bool_compare_and_swap:
  case Builtin::BI__sync_lock_test_and_set:
  case Builtin::BI__sync_lock_release:
    return SemaBuiltinAtomicOverloaded(move(TheCallResult));
  }
  
  // Since the target specific builtins for each arch overlap, only check those
  // of the arch we are compiling for.
  if (BuiltinID >= Builtin::FirstTSBuiltin) {
    switch (Context.Target.getTriple().getArch()) {
      case llvm::Triple::arm:
      case llvm::Triple::thumb:
        if (CheckARMBuiltinFunctionCall(BuiltinID, TheCall))
          return ExprError();
        break;
      case llvm::Triple::x86:
      case llvm::Triple::x86_64:
        if (CheckX86BuiltinFunctionCall(BuiltinID, TheCall))
          return ExprError();
        break;
      default:
        break;
    }
  }

  return move(TheCallResult);
}

bool Sema::CheckX86BuiltinFunctionCall(unsigned BuiltinID, CallExpr *TheCall) {
  switch (BuiltinID) {
  case X86::BI__builtin_ia32_palignr128:
  case X86::BI__builtin_ia32_palignr: {
    llvm::APSInt Result;
    if (SemaBuiltinConstantArg(TheCall, 2, Result))
      return true;
    break;
  }
  }
  return false;
}

// Get the valid immediate range for the specified NEON type code.
static unsigned RFT(unsigned t, bool shift = false) {
  bool quad = t & 0x10;
  
  switch (t & 0x7) {
    case 0: // i8
      return shift ? 7 : (8 << (int)quad) - 1;
    case 1: // i16
      return shift ? 15 : (4 << (int)quad) - 1;
    case 2: // i32
      return shift ? 31 : (2 << (int)quad) - 1;
    case 3: // i64
      return shift ? 63 : (1 << (int)quad) - 1;
    case 4: // f32
      assert(!shift && "cannot shift float types!");
      return (2 << (int)quad) - 1;
    case 5: // poly8
      assert(!shift && "cannot shift polynomial types!");
      return (8 << (int)quad) - 1;
    case 6: // poly16
      assert(!shift && "cannot shift polynomial types!");
      return (4 << (int)quad) - 1;
    case 7: // float16
      assert(!shift && "cannot shift float types!");
      return (4 << (int)quad) - 1;
  }
  return 0;
}

bool Sema::CheckARMBuiltinFunctionCall(unsigned BuiltinID, CallExpr *TheCall) {
  llvm::APSInt Result;

  unsigned mask = 0;
  unsigned TV = 0;
  switch (BuiltinID) {
#define GET_NEON_OVERLOAD_CHECK
#include "clang/Basic/arm_neon.inc"
#undef GET_NEON_OVERLOAD_CHECK
  }
  
  // For NEON intrinsics which are overloaded on vector element type, validate
  // the immediate which specifies which variant to emit.
  if (mask) {
    unsigned ArgNo = TheCall->getNumArgs()-1;
    if (SemaBuiltinConstantArg(TheCall, ArgNo, Result))
      return true;
    
    TV = Result.getLimitedValue(32);
    if ((TV > 31) || (mask & (1 << TV)) == 0)
      return Diag(TheCall->getLocStart(), diag::err_invalid_neon_type_code)
        << TheCall->getArg(ArgNo)->getSourceRange();
  }
  
  // For NEON intrinsics which take an immediate value as part of the 
  // instruction, range check them here.
  unsigned i = 0, l = 0, u = 0;
  switch (BuiltinID) {
  default: return false;
  case ARM::BI__builtin_arm_ssat: i = 1; l = 1; u = 31; break;
  case ARM::BI__builtin_arm_usat: i = 1; u = 31; break;
  case ARM::BI__builtin_arm_vcvtr_f:
  case ARM::BI__builtin_arm_vcvtr_d: i = 1; u = 1; break;
#define GET_NEON_IMMEDIATE_CHECK
#include "clang/Basic/arm_neon.inc"
#undef GET_NEON_IMMEDIATE_CHECK
  };

  // Check that the immediate argument is actually a constant.
  if (SemaBuiltinConstantArg(TheCall, i, Result))
    return true;

  // Range check against the upper/lower values for this isntruction.
  unsigned Val = Result.getZExtValue();
  if (Val < l || Val > (u + l))
    return Diag(TheCall->getLocStart(), diag::err_argument_invalid_range)
      << l << u+l << TheCall->getArg(i)->getSourceRange();

  // FIXME: VFP Intrinsics should error if VFP not present.
  return false;
}

/// CheckFunctionCall - Check a direct function call for various correctness
/// and safety properties not strictly enforced by the C type system.
bool Sema::CheckFunctionCall(FunctionDecl *FDecl, CallExpr *TheCall) {
  // Get the IdentifierInfo* for the called function.
  IdentifierInfo *FnInfo = FDecl->getIdentifier();

  // None of the checks below are needed for functions that don't have
  // simple names (e.g., C++ conversion functions).
  if (!FnInfo)
    return false;

  // FIXME: This mechanism should be abstracted to be less fragile and
  // more efficient. For example, just map function ids to custom
  // handlers.

  // Printf checking.
  if (const FormatAttr *Format = FDecl->getAttr<FormatAttr>()) {
    const bool b = Format->getType() == "scanf";
    if (b || CheckablePrintfAttr(Format, TheCall)) {
      bool HasVAListArg = Format->getFirstArg() == 0;
      CheckPrintfScanfArguments(TheCall, HasVAListArg,
                                Format->getFormatIdx() - 1,
                                HasVAListArg ? 0 : Format->getFirstArg() - 1,
                                !b);
    }
  }

  specific_attr_iterator<NonNullAttr>
    i = FDecl->specific_attr_begin<NonNullAttr>(),
    e = FDecl->specific_attr_end<NonNullAttr>();

  for (; i != e; ++i)
    CheckNonNullArguments(*i, TheCall);

  return false;
}

bool Sema::CheckBlockCall(NamedDecl *NDecl, CallExpr *TheCall) {
  // Printf checking.
  const FormatAttr *Format = NDecl->getAttr<FormatAttr>();
  if (!Format)
    return false;

  const VarDecl *V = dyn_cast<VarDecl>(NDecl);
  if (!V)
    return false;

  QualType Ty = V->getType();
  if (!Ty->isBlockPointerType())
    return false;

  const bool b = Format->getType() == "scanf";
  if (!b && !CheckablePrintfAttr(Format, TheCall))
    return false;

  bool HasVAListArg = Format->getFirstArg() == 0;
  CheckPrintfScanfArguments(TheCall, HasVAListArg, Format->getFormatIdx() - 1,
                            HasVAListArg ? 0 : Format->getFirstArg() - 1, !b);

  return false;
}

/// SemaBuiltinAtomicOverloaded - We have a call to a function like
/// __sync_fetch_and_add, which is an overloaded function based on the pointer
/// type of its first argument.  The main ActOnCallExpr routines have already
/// promoted the types of arguments because all of these calls are prototyped as
/// void(...).
///
/// This function goes through and does final semantic checking for these
/// builtins,
ExprResult
Sema::SemaBuiltinAtomicOverloaded(ExprResult TheCallResult) {
  CallExpr *TheCall = (CallExpr *)TheCallResult.get();
  DeclRefExpr *DRE =cast<DeclRefExpr>(TheCall->getCallee()->IgnoreParenCasts());
  FunctionDecl *FDecl = cast<FunctionDecl>(DRE->getDecl());

  // Ensure that we have at least one argument to do type inference from.
  if (TheCall->getNumArgs() < 1) {
    Diag(TheCall->getLocEnd(), diag::err_typecheck_call_too_few_args_at_least)
      << 0 << 1 << TheCall->getNumArgs()
      << TheCall->getCallee()->getSourceRange();
    return ExprError();
  }

  // Inspect the first argument of the atomic builtin.  This should always be
  // a pointer type, whose element is an integral scalar or pointer type.
  // Because it is a pointer type, we don't have to worry about any implicit
  // casts here.
  // FIXME: We don't allow floating point scalars as input.
  Expr *FirstArg = TheCall->getArg(0);
  if (!FirstArg->getType()->isPointerType()) {
    Diag(DRE->getLocStart(), diag::err_atomic_builtin_must_be_pointer)
      << FirstArg->getType() << FirstArg->getSourceRange();
    return ExprError();
  }

  QualType ValType =
    FirstArg->getType()->getAs<PointerType>()->getPointeeType();
  if (!ValType->isIntegerType() && !ValType->isPointerType() &&
      !ValType->isBlockPointerType()) {
    Diag(DRE->getLocStart(), diag::err_atomic_builtin_must_be_pointer_intptr)
      << FirstArg->getType() << FirstArg->getSourceRange();
    return ExprError();
  }

  // The majority of builtins return a value, but a few have special return
  // types, so allow them to override appropriately below.
  QualType ResultType = ValType;

  // We need to figure out which concrete builtin this maps onto.  For example,
  // __sync_fetch_and_add with a 2 byte object turns into
  // __sync_fetch_and_add_2.
#define BUILTIN_ROW(x) \
  { Builtin::BI##x##_1, Builtin::BI##x##_2, Builtin::BI##x##_4, \
    Builtin::BI##x##_8, Builtin::BI##x##_16 }

  static const unsigned BuiltinIndices[][5] = {
    BUILTIN_ROW(__sync_fetch_and_add),
    BUILTIN_ROW(__sync_fetch_and_sub),
    BUILTIN_ROW(__sync_fetch_and_or),
    BUILTIN_ROW(__sync_fetch_and_and),
    BUILTIN_ROW(__sync_fetch_and_xor),

    BUILTIN_ROW(__sync_add_and_fetch),
    BUILTIN_ROW(__sync_sub_and_fetch),
    BUILTIN_ROW(__sync_and_and_fetch),
    BUILTIN_ROW(__sync_or_and_fetch),
    BUILTIN_ROW(__sync_xor_and_fetch),

    BUILTIN_ROW(__sync_val_compare_and_swap),
    BUILTIN_ROW(__sync_bool_compare_and_swap),
    BUILTIN_ROW(__sync_lock_test_and_set),
    BUILTIN_ROW(__sync_lock_release)
  };
#undef BUILTIN_ROW

  // Determine the index of the size.
  unsigned SizeIndex;
  switch (Context.getTypeSizeInChars(ValType).getQuantity()) {
  case 1: SizeIndex = 0; break;
  case 2: SizeIndex = 1; break;
  case 4: SizeIndex = 2; break;
  case 8: SizeIndex = 3; break;
  case 16: SizeIndex = 4; break;
  default:
    Diag(DRE->getLocStart(), diag::err_atomic_builtin_pointer_size)
      << FirstArg->getType() << FirstArg->getSourceRange();
    return ExprError();
  }

  // Each of these builtins has one pointer argument, followed by some number of
  // values (0, 1 or 2) followed by a potentially empty varags list of stuff
  // that we ignore.  Find out which row of BuiltinIndices to read from as well
  // as the number of fixed args.
  unsigned BuiltinID = FDecl->getBuiltinID();
  unsigned BuiltinIndex, NumFixed = 1;
  switch (BuiltinID) {
  default: assert(0 && "Unknown overloaded atomic builtin!");
  case Builtin::BI__sync_fetch_and_add: BuiltinIndex = 0; break;
  case Builtin::BI__sync_fetch_and_sub: BuiltinIndex = 1; break;
  case Builtin::BI__sync_fetch_and_or:  BuiltinIndex = 2; break;
  case Builtin::BI__sync_fetch_and_and: BuiltinIndex = 3; break;
  case Builtin::BI__sync_fetch_and_xor: BuiltinIndex = 4; break;

  case Builtin::BI__sync_add_and_fetch: BuiltinIndex = 5; break;
  case Builtin::BI__sync_sub_and_fetch: BuiltinIndex = 6; break;
  case Builtin::BI__sync_and_and_fetch: BuiltinIndex = 7; break;
  case Builtin::BI__sync_or_and_fetch:  BuiltinIndex = 8; break;
  case Builtin::BI__sync_xor_and_fetch: BuiltinIndex = 9; break;

  case Builtin::BI__sync_val_compare_and_swap:
    BuiltinIndex = 10;
    NumFixed = 2;
    break;
  case Builtin::BI__sync_bool_compare_and_swap:
    BuiltinIndex = 11;
    NumFixed = 2;
    ResultType = Context.BoolTy;
    break;
  case Builtin::BI__sync_lock_test_and_set: BuiltinIndex = 12; break;
  case Builtin::BI__sync_lock_release:
    BuiltinIndex = 13;
    NumFixed = 0;
    ResultType = Context.VoidTy;
    break;
  }

  // Now that we know how many fixed arguments we expect, first check that we
  // have at least that many.
  if (TheCall->getNumArgs() < 1+NumFixed) {
    Diag(TheCall->getLocEnd(), diag::err_typecheck_call_too_few_args_at_least)
      << 0 << 1+NumFixed << TheCall->getNumArgs()
      << TheCall->getCallee()->getSourceRange();
    return ExprError();
  }

  // Get the decl for the concrete builtin from this, we can tell what the
  // concrete integer type we should convert to is.
  unsigned NewBuiltinID = BuiltinIndices[BuiltinIndex][SizeIndex];
  const char *NewBuiltinName = Context.BuiltinInfo.GetName(NewBuiltinID);
  IdentifierInfo *NewBuiltinII = PP.getIdentifierInfo(NewBuiltinName);
  FunctionDecl *NewBuiltinDecl =
    cast<FunctionDecl>(LazilyCreateBuiltin(NewBuiltinII, NewBuiltinID,
                                           TUScope, false, DRE->getLocStart()));

  // The first argument --- the pointer --- has a fixed type; we
  // deduce the types of the rest of the arguments accordingly.  Walk
  // the remaining arguments, converting them to the deduced value type.
  for (unsigned i = 0; i != NumFixed; ++i) {
    Expr *Arg = TheCall->getArg(i+1);

    // If the argument is an implicit cast, then there was a promotion due to
    // "...", just remove it now.
    if (ImplicitCastExpr *ICE = dyn_cast<ImplicitCastExpr>(Arg)) {
      Arg = ICE->getSubExpr();
      ICE->setSubExpr(0);
      TheCall->setArg(i+1, Arg);
    }

    // GCC does an implicit conversion to the pointer or integer ValType.  This
    // can fail in some cases (1i -> int**), check for this error case now.
    CastKind Kind = CK_Unknown;
    CXXCastPath BasePath;
    if (CheckCastTypes(Arg->getSourceRange(), ValType, Arg, Kind, BasePath))
      return ExprError();

    // Okay, we have something that *can* be converted to the right type.  Check
    // to see if there is a potentially weird extension going on here.  This can
    // happen when you do an atomic operation on something like an char* and
    // pass in 42.  The 42 gets converted to char.  This is even more strange
    // for things like 45.123 -> char, etc.
    // FIXME: Do this check.
    ImpCastExprToType(Arg, ValType, Kind, VK_RValue, &BasePath);
    TheCall->setArg(i+1, Arg);
  }

  // Switch the DeclRefExpr to refer to the new decl.
  DRE->setDecl(NewBuiltinDecl);
  DRE->setType(NewBuiltinDecl->getType());

  // Set the callee in the CallExpr.
  // FIXME: This leaks the original parens and implicit casts.
  Expr *PromotedCall = DRE;
  UsualUnaryConversions(PromotedCall);
  TheCall->setCallee(PromotedCall);

  // Change the result type of the call to match the original value type. This
  // is arbitrary, but the codegen for these builtins ins design to handle it
  // gracefully.
  TheCall->setType(ResultType);

  return move(TheCallResult);
}


/// CheckObjCString - Checks that the argument to the builtin
/// CFString constructor is correct
/// FIXME: GCC currently emits the following warning:
/// "warning: input conversion stopped due to an input byte that does not
///           belong to the input codeset UTF-8"
/// Note: It might also make sense to do the UTF-16 conversion here (would
/// simplify the backend).
bool Sema::CheckObjCString(Expr *Arg) {
  Arg = Arg->IgnoreParenCasts();
  StringLiteral *Literal = dyn_cast<StringLiteral>(Arg);

  if (!Literal || Literal->isWide()) {
    Diag(Arg->getLocStart(), diag::err_cfstring_literal_not_string_constant)
      << Arg->getSourceRange();
    return true;
  }

  size_t NulPos = Literal->getString().find('\0');
  if (NulPos != llvm::StringRef::npos) {
    Diag(getLocationOfStringLiteralByte(Literal, NulPos),
         diag::warn_cfstring_literal_contains_nul_character)
      << Arg->getSourceRange();
  }

  return false;
}

/// SemaBuiltinVAStart - Check the arguments to __builtin_va_start for validity.
/// Emit an error and return true on failure, return false on success.
bool Sema::SemaBuiltinVAStart(CallExpr *TheCall) {
  Expr *Fn = TheCall->getCallee();
  if (TheCall->getNumArgs() > 2) {
    Diag(TheCall->getArg(2)->getLocStart(),
         diag::err_typecheck_call_too_many_args)
      << 0 /*function call*/ << 2 << TheCall->getNumArgs()
      << Fn->getSourceRange()
      << SourceRange(TheCall->getArg(2)->getLocStart(),
                     (*(TheCall->arg_end()-1))->getLocEnd());
    return true;
  }

  if (TheCall->getNumArgs() < 2) {
    return Diag(TheCall->getLocEnd(),
      diag::err_typecheck_call_too_few_args_at_least)
      << 0 /*function call*/ << 2 << TheCall->getNumArgs();
  }

  // Determine whether the current function is variadic or not.
  BlockScopeInfo *CurBlock = getCurBlock();
  bool isVariadic;
  if (CurBlock)
    isVariadic = CurBlock->TheDecl->isVariadic();
  else if (FunctionDecl *FD = getCurFunctionDecl())
    isVariadic = FD->isVariadic();
  else
    isVariadic = getCurMethodDecl()->isVariadic();

  if (!isVariadic) {
    Diag(Fn->getLocStart(), diag::err_va_start_used_in_non_variadic_function);
    return true;
  }

  // Verify that the second argument to the builtin is the last argument of the
  // current function or method.
  bool SecondArgIsLastNamedArgument = false;
  const Expr *Arg = TheCall->getArg(1)->IgnoreParenCasts();

  if (const DeclRefExpr *DR = dyn_cast<DeclRefExpr>(Arg)) {
    if (const ParmVarDecl *PV = dyn_cast<ParmVarDecl>(DR->getDecl())) {
      // FIXME: This isn't correct for methods (results in bogus warning).
      // Get the last formal in the current function.
      const ParmVarDecl *LastArg;
      if (CurBlock)
        LastArg = *(CurBlock->TheDecl->param_end()-1);
      else if (FunctionDecl *FD = getCurFunctionDecl())
        LastArg = *(FD->param_end()-1);
      else
        LastArg = *(getCurMethodDecl()->param_end()-1);
      SecondArgIsLastNamedArgument = PV == LastArg;
    }
  }

  if (!SecondArgIsLastNamedArgument)
    Diag(TheCall->getArg(1)->getLocStart(),
         diag::warn_second_parameter_of_va_start_not_last_named_argument);
  return false;
}

/// SemaBuiltinUnorderedCompare - Handle functions like __builtin_isgreater and
/// friends.  This is declared to take (...), so we have to check everything.
bool Sema::SemaBuiltinUnorderedCompare(CallExpr *TheCall) {
  if (TheCall->getNumArgs() < 2)
    return Diag(TheCall->getLocEnd(), diag::err_typecheck_call_too_few_args)
      << 0 << 2 << TheCall->getNumArgs()/*function call*/;
  if (TheCall->getNumArgs() > 2)
    return Diag(TheCall->getArg(2)->getLocStart(),
                diag::err_typecheck_call_too_many_args)
      << 0 /*function call*/ << 2 << TheCall->getNumArgs()
      << SourceRange(TheCall->getArg(2)->getLocStart(),
                     (*(TheCall->arg_end()-1))->getLocEnd());

  Expr *OrigArg0 = TheCall->getArg(0);
  Expr *OrigArg1 = TheCall->getArg(1);

  // Do standard promotions between the two arguments, returning their common
  // type.
  QualType Res = UsualArithmeticConversions(OrigArg0, OrigArg1, false);

  // Make sure any conversions are pushed back into the call; this is
  // type safe since unordered compare builtins are declared as "_Bool
  // foo(...)".
  TheCall->setArg(0, OrigArg0);
  TheCall->setArg(1, OrigArg1);

  if (OrigArg0->isTypeDependent() || OrigArg1->isTypeDependent())
    return false;

  // If the common type isn't a real floating type, then the arguments were
  // invalid for this operation.
  if (!Res->isRealFloatingType())
    return Diag(OrigArg0->getLocStart(),
                diag::err_typecheck_call_invalid_ordered_compare)
      << OrigArg0->getType() << OrigArg1->getType()
      << SourceRange(OrigArg0->getLocStart(), OrigArg1->getLocEnd());

  return false;
}

/// SemaBuiltinSemaBuiltinFPClassification - Handle functions like
/// __builtin_isnan and friends.  This is declared to take (...), so we have
/// to check everything. We expect the last argument to be a floating point
/// value.
bool Sema::SemaBuiltinFPClassification(CallExpr *TheCall, unsigned NumArgs) {
  if (TheCall->getNumArgs() < NumArgs)
    return Diag(TheCall->getLocEnd(), diag::err_typecheck_call_too_few_args)
      << 0 << NumArgs << TheCall->getNumArgs()/*function call*/;
  if (TheCall->getNumArgs() > NumArgs)
    return Diag(TheCall->getArg(NumArgs)->getLocStart(),
                diag::err_typecheck_call_too_many_args)
      << 0 /*function call*/ << NumArgs << TheCall->getNumArgs()
      << SourceRange(TheCall->getArg(NumArgs)->getLocStart(),
                     (*(TheCall->arg_end()-1))->getLocEnd());

  Expr *OrigArg = TheCall->getArg(NumArgs-1);

  if (OrigArg->isTypeDependent())
    return false;

  // This operation requires a non-_Complex floating-point number.
  if (!OrigArg->getType()->isRealFloatingType())
    return Diag(OrigArg->getLocStart(),
                diag::err_typecheck_call_invalid_unary_fp)
      << OrigArg->getType() << OrigArg->getSourceRange();

  // If this is an implicit conversion from float -> double, remove it.
  if (ImplicitCastExpr *Cast = dyn_cast<ImplicitCastExpr>(OrigArg)) {
    Expr *CastArg = Cast->getSubExpr();
    if (CastArg->getType()->isSpecificBuiltinType(BuiltinType::Float)) {
      assert(Cast->getType()->isSpecificBuiltinType(BuiltinType::Double) &&
             "promotion from float to double is the only expected cast here");
      Cast->setSubExpr(0);
      TheCall->setArg(NumArgs-1, CastArg);
      OrigArg = CastArg;
    }
  }
  
  return false;
}

/// SemaBuiltinShuffleVector - Handle __builtin_shufflevector.
// This is declared to take (...), so we have to check everything.
ExprResult Sema::SemaBuiltinShuffleVector(CallExpr *TheCall) {
  if (TheCall->getNumArgs() < 2)
    return ExprError(Diag(TheCall->getLocEnd(),
                          diag::err_typecheck_call_too_few_args_at_least)
      << 0 /*function call*/ << 2 << TheCall->getNumArgs()
      << TheCall->getSourceRange());

  // Determine which of the following types of shufflevector we're checking:
  // 1) unary, vector mask: (lhs, mask)
  // 2) binary, vector mask: (lhs, rhs, mask)
  // 3) binary, scalar mask: (lhs, rhs, index, ..., index)
  QualType resType = TheCall->getArg(0)->getType();
  unsigned numElements = 0;
  
  if (!TheCall->getArg(0)->isTypeDependent() &&
      !TheCall->getArg(1)->isTypeDependent()) {
    QualType LHSType = TheCall->getArg(0)->getType();
    QualType RHSType = TheCall->getArg(1)->getType();
    
    if (!LHSType->isVectorType() || !RHSType->isVectorType()) {
      Diag(TheCall->getLocStart(), diag::err_shufflevector_non_vector)
        << SourceRange(TheCall->getArg(0)->getLocStart(),
                       TheCall->getArg(1)->getLocEnd());
      return ExprError();
    }
    
    numElements = LHSType->getAs<VectorType>()->getNumElements();
    unsigned numResElements = TheCall->getNumArgs() - 2;

    // Check to see if we have a call with 2 vector arguments, the unary shuffle
    // with mask.  If so, verify that RHS is an integer vector type with the
    // same number of elts as lhs.
    if (TheCall->getNumArgs() == 2) {
      if (!RHSType->hasIntegerRepresentation() || 
          RHSType->getAs<VectorType>()->getNumElements() != numElements)
        Diag(TheCall->getLocStart(), diag::err_shufflevector_incompatible_vector)
          << SourceRange(TheCall->getArg(1)->getLocStart(),
                         TheCall->getArg(1)->getLocEnd());
      numResElements = numElements;
    }
    else if (!Context.hasSameUnqualifiedType(LHSType, RHSType)) {
      Diag(TheCall->getLocStart(), diag::err_shufflevector_incompatible_vector)
        << SourceRange(TheCall->getArg(0)->getLocStart(),
                       TheCall->getArg(1)->getLocEnd());
      return ExprError();
    } else if (numElements != numResElements) {
      QualType eltType = LHSType->getAs<VectorType>()->getElementType();
      resType = Context.getVectorType(eltType, numResElements,
                                      VectorType::NotAltiVec);
    }
  }

  for (unsigned i = 2; i < TheCall->getNumArgs(); i++) {
    if (TheCall->getArg(i)->isTypeDependent() ||
        TheCall->getArg(i)->isValueDependent())
      continue;

    llvm::APSInt Result(32);
    if (!TheCall->getArg(i)->isIntegerConstantExpr(Result, Context))
      return ExprError(Diag(TheCall->getLocStart(),
                  diag::err_shufflevector_nonconstant_argument)
                << TheCall->getArg(i)->getSourceRange());

    if (Result.getActiveBits() > 64 || Result.getZExtValue() >= numElements*2)
      return ExprError(Diag(TheCall->getLocStart(),
                  diag::err_shufflevector_argument_too_large)
               << TheCall->getArg(i)->getSourceRange());
  }

  llvm::SmallVector<Expr*, 32> exprs;

  for (unsigned i = 0, e = TheCall->getNumArgs(); i != e; i++) {
    exprs.push_back(TheCall->getArg(i));
    TheCall->setArg(i, 0);
  }

  return Owned(new (Context) ShuffleVectorExpr(Context, exprs.begin(),
                                            exprs.size(), resType,
                                            TheCall->getCallee()->getLocStart(),
                                            TheCall->getRParenLoc()));
}

/// SemaBuiltinPrefetch - Handle __builtin_prefetch.
// This is declared to take (const void*, ...) and can take two
// optional constant int args.
bool Sema::SemaBuiltinPrefetch(CallExpr *TheCall) {
  unsigned NumArgs = TheCall->getNumArgs();

  if (NumArgs > 3)
    return Diag(TheCall->getLocEnd(),
             diag::err_typecheck_call_too_many_args_at_most)
             << 0 /*function call*/ << 3 << NumArgs
             << TheCall->getSourceRange();

  // Argument 0 is checked for us and the remaining arguments must be
  // constant integers.
  for (unsigned i = 1; i != NumArgs; ++i) {
    Expr *Arg = TheCall->getArg(i);
    
    llvm::APSInt Result;
    if (SemaBuiltinConstantArg(TheCall, i, Result))
      return true;

    // FIXME: gcc issues a warning and rewrites these to 0. These
    // seems especially odd for the third argument since the default
    // is 3.
    if (i == 1) {
      if (Result.getLimitedValue() > 1)
        return Diag(TheCall->getLocStart(), diag::err_argument_invalid_range)
             << "0" << "1" << Arg->getSourceRange();
    } else {
      if (Result.getLimitedValue() > 3)
        return Diag(TheCall->getLocStart(), diag::err_argument_invalid_range)
            << "0" << "3" << Arg->getSourceRange();
    }
  }

  return false;
}

/// SemaBuiltinConstantArg - Handle a check if argument ArgNum of CallExpr
/// TheCall is a constant expression.
bool Sema::SemaBuiltinConstantArg(CallExpr *TheCall, int ArgNum,
                                  llvm::APSInt &Result) {
  Expr *Arg = TheCall->getArg(ArgNum);
  DeclRefExpr *DRE =cast<DeclRefExpr>(TheCall->getCallee()->IgnoreParenCasts());
  FunctionDecl *FDecl = cast<FunctionDecl>(DRE->getDecl());
  
  if (Arg->isTypeDependent() || Arg->isValueDependent()) return false;
  
  if (!Arg->isIntegerConstantExpr(Result, Context))
    return Diag(TheCall->getLocStart(), diag::err_constant_integer_arg_type)
                << FDecl->getDeclName() <<  Arg->getSourceRange();
  
  return false;
}

/// SemaBuiltinObjectSize - Handle __builtin_object_size(void *ptr,
/// int type). This simply type checks that type is one of the defined
/// constants (0-3).
// For compatability check 0-3, llvm only handles 0 and 2.
bool Sema::SemaBuiltinObjectSize(CallExpr *TheCall) {
  llvm::APSInt Result;
  
  // Check constant-ness first.
  if (SemaBuiltinConstantArg(TheCall, 1, Result))
    return true;

  Expr *Arg = TheCall->getArg(1);
  if (Result.getSExtValue() < 0 || Result.getSExtValue() > 3) {
    return Diag(TheCall->getLocStart(), diag::err_argument_invalid_range)
             << "0" << "3" << SourceRange(Arg->getLocStart(), Arg->getLocEnd());
  }

  return false;
}

/// SemaBuiltinLongjmp - Handle __builtin_longjmp(void *env[5], int val).
/// This checks that val is a constant 1.
bool Sema::SemaBuiltinLongjmp(CallExpr *TheCall) {
  Expr *Arg = TheCall->getArg(1);
  llvm::APSInt Result;

  // TODO: This is less than ideal. Overload this to take a value.
  if (SemaBuiltinConstantArg(TheCall, 1, Result))
    return true;
  
  if (Result != 1)
    return Diag(TheCall->getLocStart(), diag::err_builtin_longjmp_invalid_val)
             << SourceRange(Arg->getLocStart(), Arg->getLocEnd());

  return false;
}

// Handle i > 1 ? "x" : "y", recursivelly
bool Sema::SemaCheckStringLiteral(const Expr *E, const CallExpr *TheCall,
                                  bool HasVAListArg,
                                  unsigned format_idx, unsigned firstDataArg,
                                  bool isPrintf) {

  if (E->isTypeDependent() || E->isValueDependent())
    return false;

  switch (E->getStmtClass()) {
  case Stmt::ConditionalOperatorClass: {
    const ConditionalOperator *C = cast<ConditionalOperator>(E);
    return SemaCheckStringLiteral(C->getTrueExpr(), TheCall, HasVAListArg,
                                  format_idx, firstDataArg, isPrintf)
        && SemaCheckStringLiteral(C->getRHS(), TheCall, HasVAListArg,
                                  format_idx, firstDataArg, isPrintf);
  }

  case Stmt::ImplicitCastExprClass: {
    const ImplicitCastExpr *Expr = cast<ImplicitCastExpr>(E);
    return SemaCheckStringLiteral(Expr->getSubExpr(), TheCall, HasVAListArg,
                                  format_idx, firstDataArg, isPrintf);
  }

  case Stmt::ParenExprClass: {
    const ParenExpr *Expr = cast<ParenExpr>(E);
    return SemaCheckStringLiteral(Expr->getSubExpr(), TheCall, HasVAListArg,
                                  format_idx, firstDataArg, isPrintf);
  }

  case Stmt::DeclRefExprClass: {
    const DeclRefExpr *DR = cast<DeclRefExpr>(E);

    // As an exception, do not flag errors for variables binding to
    // const string literals.
    if (const VarDecl *VD = dyn_cast<VarDecl>(DR->getDecl())) {
      bool isConstant = false;
      QualType T = DR->getType();

      if (const ArrayType *AT = Context.getAsArrayType(T)) {
        isConstant = AT->getElementType().isConstant(Context);
      } else if (const PointerType *PT = T->getAs<PointerType>()) {
        isConstant = T.isConstant(Context) &&
                     PT->getPointeeType().isConstant(Context);
      }

      if (isConstant) {
        if (const Expr *Init = VD->getAnyInitializer())
          return SemaCheckStringLiteral(Init, TheCall,
                                        HasVAListArg, format_idx, firstDataArg,
                                        isPrintf);
      }

      // For vprintf* functions (i.e., HasVAListArg==true), we add a
      // special check to see if the format string is a function parameter
      // of the function calling the printf function.  If the function
      // has an attribute indicating it is a printf-like function, then we
      // should suppress warnings concerning non-literals being used in a call
      // to a vprintf function.  For example:
      //
      // void
      // logmessage(char const *fmt __attribute__ (format (printf, 1, 2)), ...){
      //      va_list ap;
      //      va_start(ap, fmt);
      //      vprintf(fmt, ap);  // Do NOT emit a warning about "fmt".
      //      ...
      //
      //
      //  FIXME: We don't have full attribute support yet, so just check to see
      //    if the argument is a DeclRefExpr that references a parameter.  We'll
      //    add proper support for checking the attribute later.
      if (HasVAListArg)
        if (isa<ParmVarDecl>(VD))
          return true;
    }

    return false;
  }

  case Stmt::CallExprClass: {
    const CallExpr *CE = cast<CallExpr>(E);
    if (const ImplicitCastExpr *ICE
          = dyn_cast<ImplicitCastExpr>(CE->getCallee())) {
      if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(ICE->getSubExpr())) {
        if (const FunctionDecl *FD = dyn_cast<FunctionDecl>(DRE->getDecl())) {
          if (const FormatArgAttr *FA = FD->getAttr<FormatArgAttr>()) {
            unsigned ArgIndex = FA->getFormatIdx();
            const Expr *Arg = CE->getArg(ArgIndex - 1);

            return SemaCheckStringLiteral(Arg, TheCall, HasVAListArg,
                                          format_idx, firstDataArg, isPrintf);
          }
        }
      }
    }

    return false;
  }
  case Stmt::ObjCStringLiteralClass:
  case Stmt::StringLiteralClass: {
    const StringLiteral *StrE = NULL;

    if (const ObjCStringLiteral *ObjCFExpr = dyn_cast<ObjCStringLiteral>(E))
      StrE = ObjCFExpr->getString();
    else
      StrE = cast<StringLiteral>(E);

    if (StrE) {
      CheckFormatString(StrE, E, TheCall, HasVAListArg, format_idx,
                        firstDataArg, isPrintf);
      return true;
    }

    return false;
  }

  default:
    return false;
  }
}

void
Sema::CheckNonNullArguments(const NonNullAttr *NonNull,
                            const CallExpr *TheCall) {
  for (NonNullAttr::args_iterator i = NonNull->args_begin(),
                                  e = NonNull->args_end();
       i != e; ++i) {
    const Expr *ArgExpr = TheCall->getArg(*i);
    if (ArgExpr->isNullPointerConstant(Context,
                                       Expr::NPC_ValueDependentIsNotNull))
      Diag(TheCall->getCallee()->getLocStart(), diag::warn_null_arg)
        << ArgExpr->getSourceRange();
  }
}

/// CheckPrintfScanfArguments - Check calls to printf and scanf (and similar
/// functions) for correct use of format strings.
void
Sema::CheckPrintfScanfArguments(const CallExpr *TheCall, bool HasVAListArg,
                                unsigned format_idx, unsigned firstDataArg,
                                bool isPrintf) {

  const Expr *Fn = TheCall->getCallee();

  // The way the format attribute works in GCC, the implicit this argument
  // of member functions is counted. However, it doesn't appear in our own
  // lists, so decrement format_idx in that case.
  if (isa<CXXMemberCallExpr>(TheCall)) {
    // Catch a format attribute mistakenly referring to the object argument.
    if (format_idx == 0)
      return;
    --format_idx;
    if(firstDataArg != 0)
      --firstDataArg;
  }

  // CHECK: printf/scanf-like function is called with no format string.
  if (format_idx >= TheCall->getNumArgs()) {
    Diag(TheCall->getRParenLoc(), diag::warn_missing_format_string)
      << Fn->getSourceRange();
    return;
  }

  const Expr *OrigFormatExpr = TheCall->getArg(format_idx)->IgnoreParenCasts();

  // CHECK: format string is not a string literal.
  //
  // Dynamically generated format strings are difficult to
  // automatically vet at compile time.  Requiring that format strings
  // are string literals: (1) permits the checking of format strings by
  // the compiler and thereby (2) can practically remove the source of
  // many format string exploits.

  // Format string can be either ObjC string (e.g. @"%d") or
  // C string (e.g. "%d")
  // ObjC string uses the same format specifiers as C string, so we can use
  // the same format string checking logic for both ObjC and C strings.
  if (SemaCheckStringLiteral(OrigFormatExpr, TheCall, HasVAListArg, format_idx,
                             firstDataArg, isPrintf))
    return;  // Literal format string found, check done!

  // If there are no arguments specified, warn with -Wformat-security, otherwise
  // warn only with -Wformat-nonliteral.
  if (TheCall->getNumArgs() == format_idx+1)
    Diag(TheCall->getArg(format_idx)->getLocStart(),
         diag::warn_format_nonliteral_noargs)
      << OrigFormatExpr->getSourceRange();
  else
    Diag(TheCall->getArg(format_idx)->getLocStart(),
         diag::warn_format_nonliteral)
           << OrigFormatExpr->getSourceRange();
}

namespace {
class CheckFormatHandler : public analyze_format_string::FormatStringHandler {
protected:
  Sema &S;
  const StringLiteral *FExpr;
  const Expr *OrigFormatExpr;
  const unsigned FirstDataArg;
  const unsigned NumDataArgs;
  const bool IsObjCLiteral;
  const char *Beg; // Start of format string.
  const bool HasVAListArg;
  const CallExpr *TheCall;
  unsigned FormatIdx;
  llvm::BitVector CoveredArgs;
  bool usesPositionalArgs;
  bool atFirstArg;
public:
  CheckFormatHandler(Sema &s, const StringLiteral *fexpr,
                     const Expr *origFormatExpr, unsigned firstDataArg,
                     unsigned numDataArgs, bool isObjCLiteral,
                     const char *beg, bool hasVAListArg,
                     const CallExpr *theCall, unsigned formatIdx)
    : S(s), FExpr(fexpr), OrigFormatExpr(origFormatExpr),
      FirstDataArg(firstDataArg),
      NumDataArgs(numDataArgs),
      IsObjCLiteral(isObjCLiteral), Beg(beg),
      HasVAListArg(hasVAListArg),
      TheCall(theCall), FormatIdx(formatIdx),
      usesPositionalArgs(false), atFirstArg(true) {
        CoveredArgs.resize(numDataArgs);
        CoveredArgs.reset();
      }

  void DoneProcessing();

  void HandleIncompleteSpecifier(const char *startSpecifier,
                                 unsigned specifierLen);
    
  virtual void HandleInvalidPosition(const char *startSpecifier,
                                     unsigned specifierLen,
                                     analyze_format_string::PositionContext p);

  virtual void HandleZeroPosition(const char *startPos, unsigned posLen);

  void HandleNullChar(const char *nullCharacter);

protected:
  bool HandleInvalidConversionSpecifier(unsigned argIndex, SourceLocation Loc,
                                        const char *startSpec,
                                        unsigned specifierLen,
                                        const char *csStart, unsigned csLen);
  
  SourceRange getFormatStringRange();
  CharSourceRange getSpecifierRange(const char *startSpecifier,
                                    unsigned specifierLen);
  SourceLocation getLocationOfByte(const char *x);

  const Expr *getDataArg(unsigned i) const;
  
  bool CheckNumArgs(const analyze_format_string::FormatSpecifier &FS,
                    const analyze_format_string::ConversionSpecifier &CS,
                    const char *startSpecifier, unsigned specifierLen,
                    unsigned argIndex);
};
}

SourceRange CheckFormatHandler::getFormatStringRange() {
  return OrigFormatExpr->getSourceRange();
}

CharSourceRange CheckFormatHandler::
getSpecifierRange(const char *startSpecifier, unsigned specifierLen) {
  SourceLocation Start = getLocationOfByte(startSpecifier);
  SourceLocation End   = getLocationOfByte(startSpecifier + specifierLen - 1);

  // Advance the end SourceLocation by one due to half-open ranges.
  End = End.getFileLocWithOffset(1);

  return CharSourceRange::getCharRange(Start, End);
}

SourceLocation CheckFormatHandler::getLocationOfByte(const char *x) {
  return S.getLocationOfStringLiteralByte(FExpr, x - Beg);
}

void CheckFormatHandler::HandleIncompleteSpecifier(const char *startSpecifier,
                                                   unsigned specifierLen){
  SourceLocation Loc = getLocationOfByte(startSpecifier);
  S.Diag(Loc, diag::warn_printf_incomplete_specifier)
    << getSpecifierRange(startSpecifier, specifierLen);
}

void
CheckFormatHandler::HandleInvalidPosition(const char *startPos, unsigned posLen,
                                     analyze_format_string::PositionContext p) {
  SourceLocation Loc = getLocationOfByte(startPos);
  S.Diag(Loc, diag::warn_format_invalid_positional_specifier)
    << (unsigned) p << getSpecifierRange(startPos, posLen);
}

void CheckFormatHandler::HandleZeroPosition(const char *startPos,
                                            unsigned posLen) {
  SourceLocation Loc = getLocationOfByte(startPos);
  S.Diag(Loc, diag::warn_format_zero_positional_specifier)
    << getSpecifierRange(startPos, posLen);
}

void CheckFormatHandler::HandleNullChar(const char *nullCharacter) {
  // The presence of a null character is likely an error.
  S.Diag(getLocationOfByte(nullCharacter),
         diag::warn_printf_format_string_contains_null_char)
    << getFormatStringRange();
}

const Expr *CheckFormatHandler::getDataArg(unsigned i) const {
  return TheCall->getArg(FirstDataArg + i);
}

void CheckFormatHandler::DoneProcessing() {
    // Does the number of data arguments exceed the number of
    // format conversions in the format string?
  if (!HasVAListArg) {
      // Find any arguments that weren't covered.
    CoveredArgs.flip();
    signed notCoveredArg = CoveredArgs.find_first();
    if (notCoveredArg >= 0) {
      assert((unsigned)notCoveredArg < NumDataArgs);
      S.Diag(getDataArg((unsigned) notCoveredArg)->getLocStart(),
             diag::warn_printf_data_arg_not_used)
      << getFormatStringRange();
    }
  }
}

bool
CheckFormatHandler::HandleInvalidConversionSpecifier(unsigned argIndex,
                                                     SourceLocation Loc,
                                                     const char *startSpec,
                                                     unsigned specifierLen,
                                                     const char *csStart,
                                                     unsigned csLen) {
  
  bool keepGoing = true;
  if (argIndex < NumDataArgs) {
    // Consider the argument coverered, even though the specifier doesn't
    // make sense.
    CoveredArgs.set(argIndex);
  }
  else {
    // If argIndex exceeds the number of data arguments we
    // don't issue a warning because that is just a cascade of warnings (and
    // they may have intended '%%' anyway). We don't want to continue processing
    // the format string after this point, however, as we will like just get
    // gibberish when trying to match arguments.
    keepGoing = false;
  }
  
  S.Diag(Loc, diag::warn_format_invalid_conversion)
    << llvm::StringRef(csStart, csLen)
    << getSpecifierRange(startSpec, specifierLen);
  
  return keepGoing;
}

bool
CheckFormatHandler::CheckNumArgs(
  const analyze_format_string::FormatSpecifier &FS,
  const analyze_format_string::ConversionSpecifier &CS,
  const char *startSpecifier, unsigned specifierLen, unsigned argIndex) {

  if (argIndex >= NumDataArgs) {
    if (FS.usesPositionalArg())  {
      S.Diag(getLocationOfByte(CS.getStart()),
             diag::warn_printf_positional_arg_exceeds_data_args)
      << (argIndex+1) << NumDataArgs
      << getSpecifierRange(startSpecifier, specifierLen);
    }
    else {
      S.Diag(getLocationOfByte(CS.getStart()),
             diag::warn_printf_insufficient_data_args)
      << getSpecifierRange(startSpecifier, specifierLen);
    }
    
    return false;
  }
  return true;
}

//===--- CHECK: Printf format string checking ------------------------------===//

namespace {
class CheckPrintfHandler : public CheckFormatHandler {
public:
  CheckPrintfHandler(Sema &s, const StringLiteral *fexpr,
                     const Expr *origFormatExpr, unsigned firstDataArg,
                     unsigned numDataArgs, bool isObjCLiteral,
                     const char *beg, bool hasVAListArg,
                     const CallExpr *theCall, unsigned formatIdx)
  : CheckFormatHandler(s, fexpr, origFormatExpr, firstDataArg,
                       numDataArgs, isObjCLiteral, beg, hasVAListArg,
                       theCall, formatIdx) {}
  
  
  bool HandleInvalidPrintfConversionSpecifier(
                                      const analyze_printf::PrintfSpecifier &FS,
                                      const char *startSpecifier,
                                      unsigned specifierLen);
  
  bool HandlePrintfSpecifier(const analyze_printf::PrintfSpecifier &FS,
                             const char *startSpecifier,
                             unsigned specifierLen);
  
  bool HandleAmount(const analyze_format_string::OptionalAmount &Amt, unsigned k,
                    const char *startSpecifier, unsigned specifierLen);
  void HandleInvalidAmount(const analyze_printf::PrintfSpecifier &FS,
                           const analyze_printf::OptionalAmount &Amt,
                           unsigned type,
                           const char *startSpecifier, unsigned specifierLen);
  void HandleFlag(const analyze_printf::PrintfSpecifier &FS,
                  const analyze_printf::OptionalFlag &flag,
                  const char *startSpecifier, unsigned specifierLen);
  void HandleIgnoredFlag(const analyze_printf::PrintfSpecifier &FS,
                         const analyze_printf::OptionalFlag &ignoredFlag,
                         const analyze_printf::OptionalFlag &flag,
                         const char *startSpecifier, unsigned specifierLen);
};  
}

bool CheckPrintfHandler::HandleInvalidPrintfConversionSpecifier(
                                      const analyze_printf::PrintfSpecifier &FS,
                                      const char *startSpecifier,
                                      unsigned specifierLen) {
  const analyze_printf::PrintfConversionSpecifier &CS =
    FS.getConversionSpecifier();
  
  return HandleInvalidConversionSpecifier(FS.getArgIndex(),
                                          getLocationOfByte(CS.getStart()),
                                          startSpecifier, specifierLen,
                                          CS.getStart(), CS.getLength());
}

bool CheckPrintfHandler::HandleAmount(
                               const analyze_format_string::OptionalAmount &Amt,
                               unsigned k, const char *startSpecifier,
                               unsigned specifierLen) {

  if (Amt.hasDataArgument()) {
    if (!HasVAListArg) {
      unsigned argIndex = Amt.getArgIndex();
      if (argIndex >= NumDataArgs) {
        S.Diag(getLocationOfByte(Amt.getStart()),
               diag::warn_printf_asterisk_missing_arg)
          << k << getSpecifierRange(startSpecifier, specifierLen);
        // Don't do any more checking.  We will just emit
        // spurious errors.
        return false;
      }

      // Type check the data argument.  It should be an 'int'.
      // Although not in conformance with C99, we also allow the argument to be
      // an 'unsigned int' as that is a reasonably safe case.  GCC also
      // doesn't emit a warning for that case.
      CoveredArgs.set(argIndex);
      const Expr *Arg = getDataArg(argIndex);
      QualType T = Arg->getType();

      const analyze_printf::ArgTypeResult &ATR = Amt.getArgType(S.Context);
      assert(ATR.isValid());

      if (!ATR.matchesType(S.Context, T)) {
        S.Diag(getLocationOfByte(Amt.getStart()),
               diag::warn_printf_asterisk_wrong_type)
          << k
          << ATR.getRepresentativeType(S.Context) << T
          << getSpecifierRange(startSpecifier, specifierLen)
          << Arg->getSourceRange();
        // Don't do any more checking.  We will just emit
        // spurious errors.
        return false;
      }
    }
  }
  return true;
}

void CheckPrintfHandler::HandleInvalidAmount(
                                      const analyze_printf::PrintfSpecifier &FS,
                                      const analyze_printf::OptionalAmount &Amt,
                                      unsigned type,
                                      const char *startSpecifier,
                                      unsigned specifierLen) {
  const analyze_printf::PrintfConversionSpecifier &CS =
    FS.getConversionSpecifier();
  switch (Amt.getHowSpecified()) {
  case analyze_printf::OptionalAmount::Constant:
    S.Diag(getLocationOfByte(Amt.getStart()),
        diag::warn_printf_nonsensical_optional_amount)
      << type
      << CS.toString()
      << getSpecifierRange(startSpecifier, specifierLen)
      << FixItHint::CreateRemoval(getSpecifierRange(Amt.getStart(),
          Amt.getConstantLength()));
    break;

  default:
    S.Diag(getLocationOfByte(Amt.getStart()),
        diag::warn_printf_nonsensical_optional_amount)
      << type
      << CS.toString()
      << getSpecifierRange(startSpecifier, specifierLen);
    break;
  }
}

void CheckPrintfHandler::HandleFlag(const analyze_printf::PrintfSpecifier &FS,
                                    const analyze_printf::OptionalFlag &flag,
                                    const char *startSpecifier,
                                    unsigned specifierLen) {
  // Warn about pointless flag with a fixit removal.
  const analyze_printf::PrintfConversionSpecifier &CS =
    FS.getConversionSpecifier();
  S.Diag(getLocationOfByte(flag.getPosition()),
      diag::warn_printf_nonsensical_flag)
    << flag.toString() << CS.toString()
    << getSpecifierRange(startSpecifier, specifierLen)
    << FixItHint::CreateRemoval(getSpecifierRange(flag.getPosition(), 1));
}

void CheckPrintfHandler::HandleIgnoredFlag(
                                const analyze_printf::PrintfSpecifier &FS,
                                const analyze_printf::OptionalFlag &ignoredFlag,
                                const analyze_printf::OptionalFlag &flag,
                                const char *startSpecifier,
                                unsigned specifierLen) {
  // Warn about ignored flag with a fixit removal.
  S.Diag(getLocationOfByte(ignoredFlag.getPosition()),
      diag::warn_printf_ignored_flag)
    << ignoredFlag.toString() << flag.toString()
    << getSpecifierRange(startSpecifier, specifierLen)
    << FixItHint::CreateRemoval(getSpecifierRange(
        ignoredFlag.getPosition(), 1));
}

bool
CheckPrintfHandler::HandlePrintfSpecifier(const analyze_printf::PrintfSpecifier
                                            &FS,
                                          const char *startSpecifier,
                                          unsigned specifierLen) {

  using namespace analyze_format_string;
  using namespace analyze_printf;  
  const PrintfConversionSpecifier &CS = FS.getConversionSpecifier();

  if (FS.consumesDataArgument()) {
    if (atFirstArg) {
        atFirstArg = false;
        usesPositionalArgs = FS.usesPositionalArg();
    }
    else if (usesPositionalArgs != FS.usesPositionalArg()) {
      // Cannot mix-and-match positional and non-positional arguments.
      S.Diag(getLocationOfByte(CS.getStart()),
             diag::warn_format_mix_positional_nonpositional_args)
        << getSpecifierRange(startSpecifier, specifierLen);
      return false;
    }
  }

  // First check if the field width, precision, and conversion specifier
  // have matching data arguments.
  if (!HandleAmount(FS.getFieldWidth(), /* field width */ 0,
                    startSpecifier, specifierLen)) {
    return false;
  }

  if (!HandleAmount(FS.getPrecision(), /* precision */ 1,
                    startSpecifier, specifierLen)) {
    return false;
  }

  if (!CS.consumesDataArgument()) {
    // FIXME: Technically specifying a precision or field width here
    // makes no sense.  Worth issuing a warning at some point.
    return true;
  }

  // Consume the argument.
  unsigned argIndex = FS.getArgIndex();
  if (argIndex < NumDataArgs) {
    // The check to see if the argIndex is valid will come later.
    // We set the bit here because we may exit early from this
    // function if we encounter some other error.
    CoveredArgs.set(argIndex);
  }

  // Check for using an Objective-C specific conversion specifier
  // in a non-ObjC literal.
  if (!IsObjCLiteral && CS.isObjCArg()) {
    return HandleInvalidPrintfConversionSpecifier(FS, startSpecifier,
                                                  specifierLen);
  }

  // Check for invalid use of field width
  if (!FS.hasValidFieldWidth()) {
    HandleInvalidAmount(FS, FS.getFieldWidth(), /* field width */ 0,
        startSpecifier, specifierLen);
  }

  // Check for invalid use of precision
  if (!FS.hasValidPrecision()) {
    HandleInvalidAmount(FS, FS.getPrecision(), /* precision */ 1,
        startSpecifier, specifierLen);
  }

  // Check each flag does not conflict with any other component.
  if (!FS.hasValidLeadingZeros())
    HandleFlag(FS, FS.hasLeadingZeros(), startSpecifier, specifierLen);
  if (!FS.hasValidPlusPrefix())
    HandleFlag(FS, FS.hasPlusPrefix(), startSpecifier, specifierLen);
  if (!FS.hasValidSpacePrefix())
    HandleFlag(FS, FS.hasSpacePrefix(), startSpecifier, specifierLen);
  if (!FS.hasValidAlternativeForm())
    HandleFlag(FS, FS.hasAlternativeForm(), startSpecifier, specifierLen);
  if (!FS.hasValidLeftJustified())
    HandleFlag(FS, FS.isLeftJustified(), startSpecifier, specifierLen);

  // Check that flags are not ignored by another flag
  if (FS.hasSpacePrefix() && FS.hasPlusPrefix()) // ' ' ignored by '+'
    HandleIgnoredFlag(FS, FS.hasSpacePrefix(), FS.hasPlusPrefix(),
        startSpecifier, specifierLen);
  if (FS.hasLeadingZeros() && FS.isLeftJustified()) // '0' ignored by '-'
    HandleIgnoredFlag(FS, FS.hasLeadingZeros(), FS.isLeftJustified(),
            startSpecifier, specifierLen);

  // Check the length modifier is valid with the given conversion specifier.
  const LengthModifier &LM = FS.getLengthModifier();
  if (!FS.hasValidLengthModifier())
    S.Diag(getLocationOfByte(LM.getStart()),
        diag::warn_format_nonsensical_length)
      << LM.toString() << CS.toString()
      << getSpecifierRange(startSpecifier, specifierLen)
      << FixItHint::CreateRemoval(getSpecifierRange(LM.getStart(),
          LM.getLength()));

  // Are we using '%n'?
  if (CS.getKind() == ConversionSpecifier::nArg) {
    // Issue a warning about this being a possible security issue.
    S.Diag(getLocationOfByte(CS.getStart()), diag::warn_printf_write_back)
      << getSpecifierRange(startSpecifier, specifierLen);
    // Continue checking the other format specifiers.
    return true;
  }

  // The remaining checks depend on the data arguments.
  if (HasVAListArg)
    return true;

  if (!CheckNumArgs(FS, CS, startSpecifier, specifierLen, argIndex))
    return false;

  // Now type check the data expression that matches the
  // format specifier.
  const Expr *Ex = getDataArg(argIndex);
  const analyze_printf::ArgTypeResult &ATR = FS.getArgType(S.Context);
  if (ATR.isValid() && !ATR.matchesType(S.Context, Ex->getType())) {
    // Check if we didn't match because of an implicit cast from a 'char'
    // or 'short' to an 'int'.  This is done because printf is a varargs
    // function.
    if (const ImplicitCastExpr *ICE = dyn_cast<ImplicitCastExpr>(Ex))
      if (ICE->getType() == S.Context.IntTy)
        if (ATR.matchesType(S.Context, ICE->getSubExpr()->getType()))
          return true;

    // We may be able to offer a FixItHint if it is a supported type.
    PrintfSpecifier fixedFS = FS;
    bool success = fixedFS.fixType(Ex->getType());

    if (success) {
      // Get the fix string from the fixed format specifier
      llvm::SmallString<128> buf;
      llvm::raw_svector_ostream os(buf);
      fixedFS.toString(os);

      // FIXME: getRepresentativeType() perhaps should return a string
      // instead of a QualType to better handle when the representative
      // type is 'wint_t' (which is defined in the system headers).
      S.Diag(getLocationOfByte(CS.getStart()),
          diag::warn_printf_conversion_argument_type_mismatch)
        << ATR.getRepresentativeType(S.Context) << Ex->getType()
        << getSpecifierRange(startSpecifier, specifierLen)
        << Ex->getSourceRange()
        << FixItHint::CreateReplacement(
            getSpecifierRange(startSpecifier, specifierLen),
            os.str());
    }
    else {
      S.Diag(getLocationOfByte(CS.getStart()),
             diag::warn_printf_conversion_argument_type_mismatch)
        << ATR.getRepresentativeType(S.Context) << Ex->getType()
        << getSpecifierRange(startSpecifier, specifierLen)
        << Ex->getSourceRange();
    }
  }

  return true;
}

//===--- CHECK: Scanf format string checking ------------------------------===//

namespace {  
class CheckScanfHandler : public CheckFormatHandler {
public:
  CheckScanfHandler(Sema &s, const StringLiteral *fexpr,
                    const Expr *origFormatExpr, unsigned firstDataArg,
                    unsigned numDataArgs, bool isObjCLiteral,
                    const char *beg, bool hasVAListArg,
                    const CallExpr *theCall, unsigned formatIdx)
  : CheckFormatHandler(s, fexpr, origFormatExpr, firstDataArg,
                       numDataArgs, isObjCLiteral, beg, hasVAListArg,
                       theCall, formatIdx) {}
  
  bool HandleScanfSpecifier(const analyze_scanf::ScanfSpecifier &FS,
                            const char *startSpecifier,
                            unsigned specifierLen);
  
  bool HandleInvalidScanfConversionSpecifier(
          const analyze_scanf::ScanfSpecifier &FS,
          const char *startSpecifier,
          unsigned specifierLen);

  void HandleIncompleteScanList(const char *start, const char *end);
};
}

void CheckScanfHandler::HandleIncompleteScanList(const char *start,
                                                 const char *end) {
  S.Diag(getLocationOfByte(end), diag::warn_scanf_scanlist_incomplete)
    << getSpecifierRange(start, end - start);
}

bool CheckScanfHandler::HandleInvalidScanfConversionSpecifier(
                                        const analyze_scanf::ScanfSpecifier &FS,
                                        const char *startSpecifier,
                                        unsigned specifierLen) {

  const analyze_scanf::ScanfConversionSpecifier &CS =
    FS.getConversionSpecifier();

  return HandleInvalidConversionSpecifier(FS.getArgIndex(),
                                          getLocationOfByte(CS.getStart()),
                                          startSpecifier, specifierLen,
                                          CS.getStart(), CS.getLength());
}

bool CheckScanfHandler::HandleScanfSpecifier(
                                       const analyze_scanf::ScanfSpecifier &FS,
                                       const char *startSpecifier,
                                       unsigned specifierLen) {
  
  using namespace analyze_scanf;
  using namespace analyze_format_string;  

  const ScanfConversionSpecifier &CS = FS.getConversionSpecifier();

  // Handle case where '%' and '*' don't consume an argument.  These shouldn't
  // be used to decide if we are using positional arguments consistently.
  if (FS.consumesDataArgument()) {
    if (atFirstArg) {
      atFirstArg = false;
      usesPositionalArgs = FS.usesPositionalArg();
    }
    else if (usesPositionalArgs != FS.usesPositionalArg()) {
      // Cannot mix-and-match positional and non-positional arguments.
      S.Diag(getLocationOfByte(CS.getStart()),
             diag::warn_format_mix_positional_nonpositional_args)
        << getSpecifierRange(startSpecifier, specifierLen);
      return false;
    }
  }
  
  // Check if the field with is non-zero.
  const OptionalAmount &Amt = FS.getFieldWidth();
  if (Amt.getHowSpecified() == OptionalAmount::Constant) {
    if (Amt.getConstantAmount() == 0) {
      const CharSourceRange &R = getSpecifierRange(Amt.getStart(),
                                                   Amt.getConstantLength());
      S.Diag(getLocationOfByte(Amt.getStart()),
             diag::warn_scanf_nonzero_width)
        << R << FixItHint::CreateRemoval(R);
    }
  }
  
  if (!FS.consumesDataArgument()) {
    // FIXME: Technically specifying a precision or field width here
    // makes no sense.  Worth issuing a warning at some point.
    return true;
  }
  
  // Consume the argument.
  unsigned argIndex = FS.getArgIndex();
  if (argIndex < NumDataArgs) {
      // The check to see if the argIndex is valid will come later.
      // We set the bit here because we may exit early from this
      // function if we encounter some other error.
    CoveredArgs.set(argIndex);
  }
  
  // Check the length modifier is valid with the given conversion specifier.
  const LengthModifier &LM = FS.getLengthModifier();
  if (!FS.hasValidLengthModifier()) {
    S.Diag(getLocationOfByte(LM.getStart()),
           diag::warn_format_nonsensical_length)
      << LM.toString() << CS.toString()
      << getSpecifierRange(startSpecifier, specifierLen)
      << FixItHint::CreateRemoval(getSpecifierRange(LM.getStart(),
                                                    LM.getLength()));
  }

  // The remaining checks depend on the data arguments.
  if (HasVAListArg)
    return true;
  
  if (!CheckNumArgs(FS, CS, startSpecifier, specifierLen, argIndex))
    return false;
  
  // FIXME: Check that the argument type matches the format specifier.
  
  return true;
}

void Sema::CheckFormatString(const StringLiteral *FExpr,
                             const Expr *OrigFormatExpr,
                             const CallExpr *TheCall, bool HasVAListArg,
                             unsigned format_idx, unsigned firstDataArg,
                             bool isPrintf) {
  
  // CHECK: is the format string a wide literal?
  if (FExpr->isWide()) {
    Diag(FExpr->getLocStart(),
         diag::warn_format_string_is_wide_literal)
    << OrigFormatExpr->getSourceRange();
    return;
  }
  
  // Str - The format string.  NOTE: this is NOT null-terminated!
  llvm::StringRef StrRef = FExpr->getString();
  const char *Str = StrRef.data();
  unsigned StrLen = StrRef.size();
  
  // CHECK: empty format string?
  if (StrLen == 0) {
    Diag(FExpr->getLocStart(), diag::warn_empty_format_string)
    << OrigFormatExpr->getSourceRange();
    return;
  }
  
  if (isPrintf) {
    CheckPrintfHandler H(*this, FExpr, OrigFormatExpr, firstDataArg,
                         TheCall->getNumArgs() - firstDataArg,
                         isa<ObjCStringLiteral>(OrigFormatExpr), Str,
                         HasVAListArg, TheCall, format_idx);
  
    if (!analyze_format_string::ParsePrintfString(H, Str, Str + StrLen))
      H.DoneProcessing();
  }
  else {
    CheckScanfHandler H(*this, FExpr, OrigFormatExpr, firstDataArg,
                        TheCall->getNumArgs() - firstDataArg,
                        isa<ObjCStringLiteral>(OrigFormatExpr), Str,
                        HasVAListArg, TheCall, format_idx);
    
    if (!analyze_format_string::ParseScanfString(H, Str, Str + StrLen))
      H.DoneProcessing();
  }
}

//===--- CHECK: Return Address of Stack Variable --------------------------===//

static DeclRefExpr* EvalVal(Expr *E);
static DeclRefExpr* EvalAddr(Expr* E);

/// CheckReturnStackAddr - Check if a return statement returns the address
///   of a stack variable.
void
Sema::CheckReturnStackAddr(Expr *RetValExp, QualType lhsType,
                           SourceLocation ReturnLoc) {

  // Perform checking for returned stack addresses.
  if (lhsType->isPointerType() || lhsType->isBlockPointerType()) {
    if (DeclRefExpr *DR = EvalAddr(RetValExp))
      Diag(DR->getLocStart(), diag::warn_ret_stack_addr)
       << DR->getDecl()->getDeclName() << RetValExp->getSourceRange();

    // Skip over implicit cast expressions when checking for block expressions.
    RetValExp = RetValExp->IgnoreParenCasts();

    if (BlockExpr *C = dyn_cast<BlockExpr>(RetValExp))
      if (C->hasBlockDeclRefExprs())
        Diag(C->getLocStart(), diag::err_ret_local_block)
          << C->getSourceRange();

    if (AddrLabelExpr *ALE = dyn_cast<AddrLabelExpr>(RetValExp))
      Diag(ALE->getLocStart(), diag::warn_ret_addr_label)
        << ALE->getSourceRange();

  } else if (lhsType->isReferenceType()) {
    // Perform checking for stack values returned by reference.
    // Check for a reference to the stack
    if (DeclRefExpr *DR = EvalVal(RetValExp))
      Diag(DR->getLocStart(), diag::warn_ret_stack_ref)
        << DR->getDecl()->getDeclName() << RetValExp->getSourceRange();
  }
}

/// EvalAddr - EvalAddr and EvalVal are mutually recursive functions that
///  check if the expression in a return statement evaluates to an address
///  to a location on the stack.  The recursion is used to traverse the
///  AST of the return expression, with recursion backtracking when we
///  encounter a subexpression that (1) clearly does not lead to the address
///  of a stack variable or (2) is something we cannot determine leads to
///  the address of a stack variable based on such local checking.
///
///  EvalAddr processes expressions that are pointers that are used as
///  references (and not L-values).  EvalVal handles all other values.
///  At the base case of the recursion is a check for a DeclRefExpr* in
///  the refers to a stack variable.
///
///  This implementation handles:
///
///   * pointer-to-pointer casts
///   * implicit conversions from array references to pointers
///   * taking the address of fields
///   * arbitrary interplay between "&" and "*" operators
///   * pointer arithmetic from an address of a stack variable
///   * taking the address of an array element where the array is on the stack
static DeclRefExpr* EvalAddr(Expr *E) {
  // We should only be called for evaluating pointer expressions.
  assert((E->getType()->isAnyPointerType() ||
          E->getType()->isBlockPointerType() ||
          E->getType()->isObjCQualifiedIdType()) &&
         "EvalAddr only works on pointers");

  // Our "symbolic interpreter" is just a dispatch off the currently
  // viewed AST node.  We then recursively traverse the AST by calling
  // EvalAddr and EvalVal appropriately.
  switch (E->getStmtClass()) {
  case Stmt::ParenExprClass:
    // Ignore parentheses.
    return EvalAddr(cast<ParenExpr>(E)->getSubExpr());

  case Stmt::UnaryOperatorClass: {
    // The only unary operator that make sense to handle here
    // is AddrOf.  All others don't make sense as pointers.
    UnaryOperator *U = cast<UnaryOperator>(E);

    if (U->getOpcode() == UO_AddrOf)
      return EvalVal(U->getSubExpr());
    else
      return NULL;
  }

  case Stmt::BinaryOperatorClass: {
    // Handle pointer arithmetic.  All other binary operators are not valid
    // in this context.
    BinaryOperator *B = cast<BinaryOperator>(E);
    BinaryOperatorKind op = B->getOpcode();

    if (op != BO_Add && op != BO_Sub)
      return NULL;

    Expr *Base = B->getLHS();

    // Determine which argument is the real pointer base.  It could be
    // the RHS argument instead of the LHS.
    if (!Base->getType()->isPointerType()) Base = B->getRHS();

    assert (Base->getType()->isPointerType());
    return EvalAddr(Base);
  }

  // For conditional operators we need to see if either the LHS or RHS are
  // valid DeclRefExpr*s.  If one of them is valid, we return it.
  case Stmt::ConditionalOperatorClass: {
    ConditionalOperator *C = cast<ConditionalOperator>(E);

    // Handle the GNU extension for missing LHS.
    if (Expr *lhsExpr = C->getLHS())
      if (DeclRefExpr* LHS = EvalAddr(lhsExpr))
        return LHS;

     return EvalAddr(C->getRHS());
  }

  // For casts, we need to handle conversions from arrays to
  // pointer values, and pointer-to-pointer conversions.
  case Stmt::ImplicitCastExprClass:
  case Stmt::CStyleCastExprClass:
  case Stmt::CXXFunctionalCastExprClass: {
    Expr* SubExpr = cast<CastExpr>(E)->getSubExpr();
    QualType T = SubExpr->getType();

    if (SubExpr->getType()->isPointerType() ||
        SubExpr->getType()->isBlockPointerType() ||
        SubExpr->getType()->isObjCQualifiedIdType())
      return EvalAddr(SubExpr);
    else if (T->isArrayType())
      return EvalVal(SubExpr);
    else
      return 0;
  }

  // C++ casts.  For dynamic casts, static casts, and const casts, we
  // are always converting from a pointer-to-pointer, so we just blow
  // through the cast.  In the case the dynamic cast doesn't fail (and
  // return NULL), we take the conservative route and report cases
  // where we return the address of a stack variable.  For Reinterpre
  // FIXME: The comment about is wrong; we're not always converting
  // from pointer to pointer. I'm guessing that this code should also
  // handle references to objects.
  case Stmt::CXXStaticCastExprClass:
  case Stmt::CXXDynamicCastExprClass:
  case Stmt::CXXConstCastExprClass:
  case Stmt::CXXReinterpretCastExprClass: {
      Expr *S = cast<CXXNamedCastExpr>(E)->getSubExpr();
      if (S->getType()->isPointerType() || S->getType()->isBlockPointerType())
        return EvalAddr(S);
      else
        return NULL;
  }

  // Everything else: we simply don't reason about them.
  default:
    return NULL;
  }
}


///  EvalVal - This function is complements EvalAddr in the mutual recursion.
///   See the comments for EvalAddr for more details.
static DeclRefExpr* EvalVal(Expr *E) {
do {
  // We should only be called for evaluating non-pointer expressions, or
  // expressions with a pointer type that are not used as references but instead
  // are l-values (e.g., DeclRefExpr with a pointer type).

  // Our "symbolic interpreter" is just a dispatch off the currently
  // viewed AST node.  We then recursively traverse the AST by calling
  // EvalAddr and EvalVal appropriately.
  switch (E->getStmtClass()) {
  case Stmt::ImplicitCastExprClass: {
    ImplicitCastExpr *IE = cast<ImplicitCastExpr>(E);
    if (IE->getValueKind() == VK_LValue) {
      E = IE->getSubExpr();
      continue;
    }
    return NULL;
  }

  case Stmt::DeclRefExprClass: {
    // DeclRefExpr: the base case.  When we hit a DeclRefExpr we are looking
    //  at code that refers to a variable's name.  We check if it has local
    //  storage within the function, and if so, return the expression.
    DeclRefExpr *DR = cast<DeclRefExpr>(E);

    if (VarDecl *V = dyn_cast<VarDecl>(DR->getDecl()))
      if (V->hasLocalStorage() && !V->getType()->isReferenceType()) return DR;

    return NULL;
  }

  case Stmt::ParenExprClass: {
    // Ignore parentheses.
    E = cast<ParenExpr>(E)->getSubExpr();
    continue;
  }

  case Stmt::UnaryOperatorClass: {
    // The only unary operator that make sense to handle here
    // is Deref.  All others don't resolve to a "name."  This includes
    // handling all sorts of rvalues passed to a unary operator.
    UnaryOperator *U = cast<UnaryOperator>(E);

    if (U->getOpcode() == UO_Deref)
      return EvalAddr(U->getSubExpr());

    return NULL;
  }

  case Stmt::ArraySubscriptExprClass: {
    // Array subscripts are potential references to data on the stack.  We
    // retrieve the DeclRefExpr* for the array variable if it indeed
    // has local storage.
    return EvalAddr(cast<ArraySubscriptExpr>(E)->getBase());
  }

  case Stmt::ConditionalOperatorClass: {
    // For conditional operators we need to see if either the LHS or RHS are
    // non-NULL DeclRefExpr's.  If one is non-NULL, we return it.
    ConditionalOperator *C = cast<ConditionalOperator>(E);

    // Handle the GNU extension for missing LHS.
    if (Expr *lhsExpr = C->getLHS())
      if (DeclRefExpr *LHS = EvalVal(lhsExpr))
        return LHS;

    return EvalVal(C->getRHS());
  }

  // Accesses to members are potential references to data on the stack.
  case Stmt::MemberExprClass: {
    MemberExpr *M = cast<MemberExpr>(E);

    // Check for indirect access.  We only want direct field accesses.
    if (M->isArrow())
      return NULL;

    // Check whether the member type is itself a reference, in which case
    // we're not going to refer to the member, but to what the member refers to.
    if (M->getMemberDecl()->getType()->isReferenceType())
      return NULL;

    return EvalVal(M->getBase());
  }

  // Everything else: we simply don't reason about them.
  default:
    return NULL;
  }
} while (true);
}

//===--- CHECK: Floating-Point comparisons (-Wfloat-equal) ---------------===//

/// Check for comparisons of floating point operands using != and ==.
/// Issue a warning if these are no self-comparisons, as they are not likely
/// to do what the programmer intended.
void Sema::CheckFloatComparison(SourceLocation loc, Expr* lex, Expr *rex) {
  bool EmitWarning = true;

  Expr* LeftExprSansParen = lex->IgnoreParens();
  Expr* RightExprSansParen = rex->IgnoreParens();

  // Special case: check for x == x (which is OK).
  // Do not emit warnings for such cases.
  if (DeclRefExpr* DRL = dyn_cast<DeclRefExpr>(LeftExprSansParen))
    if (DeclRefExpr* DRR = dyn_cast<DeclRefExpr>(RightExprSansParen))
      if (DRL->getDecl() == DRR->getDecl())
        EmitWarning = false;


  // Special case: check for comparisons against literals that can be exactly
  //  represented by APFloat.  In such cases, do not emit a warning.  This
  //  is a heuristic: often comparison against such literals are used to
  //  detect if a value in a variable has not changed.  This clearly can
  //  lead to false negatives.
  if (EmitWarning) {
    if (FloatingLiteral* FLL = dyn_cast<FloatingLiteral>(LeftExprSansParen)) {
      if (FLL->isExact())
        EmitWarning = false;
    } else
      if (FloatingLiteral* FLR = dyn_cast<FloatingLiteral>(RightExprSansParen)){
        if (FLR->isExact())
          EmitWarning = false;
    }
  }

  // Check for comparisons with builtin types.
  if (EmitWarning)
    if (CallExpr* CL = dyn_cast<CallExpr>(LeftExprSansParen))
      if (CL->isBuiltinCall(Context))
        EmitWarning = false;

  if (EmitWarning)
    if (CallExpr* CR = dyn_cast<CallExpr>(RightExprSansParen))
      if (CR->isBuiltinCall(Context))
        EmitWarning = false;

  // Emit the diagnostic.
  if (EmitWarning)
    Diag(loc, diag::warn_floatingpoint_eq)
      << lex->getSourceRange() << rex->getSourceRange();
}

//===--- CHECK: Integer mixed-sign comparisons (-Wsign-compare) --------===//
//===--- CHECK: Lossy implicit conversions (-Wconversion) --------------===//

namespace {

/// Structure recording the 'active' range of an integer-valued
/// expression.
struct IntRange {
  /// The number of bits active in the int.
  unsigned Width;

  /// True if the int is known not to have negative values.
  bool NonNegative;

  IntRange(unsigned Width, bool NonNegative)
    : Width(Width), NonNegative(NonNegative)
  {}

  // Returns the range of the bool type.
  static IntRange forBoolType() {
    return IntRange(1, true);
  }

  // Returns the range of an integral type.
  static IntRange forType(ASTContext &C, QualType T) {
    return forCanonicalType(C, T->getCanonicalTypeInternal().getTypePtr());
  }

  // Returns the range of an integeral type based on its canonical
  // representation.
  static IntRange forCanonicalType(ASTContext &C, const Type *T) {
    assert(T->isCanonicalUnqualified());

    if (const VectorType *VT = dyn_cast<VectorType>(T))
      T = VT->getElementType().getTypePtr();
    if (const ComplexType *CT = dyn_cast<ComplexType>(T))
      T = CT->getElementType().getTypePtr();

    if (const EnumType *ET = dyn_cast<EnumType>(T)) {
      EnumDecl *Enum = ET->getDecl();
      unsigned NumPositive = Enum->getNumPositiveBits();
      unsigned NumNegative = Enum->getNumNegativeBits();

      return IntRange(std::max(NumPositive, NumNegative), NumNegative == 0);
    }

    const BuiltinType *BT = cast<BuiltinType>(T);
    assert(BT->isInteger());

    return IntRange(C.getIntWidth(QualType(T, 0)), BT->isUnsignedInteger());
  }

  // Returns the supremum of two ranges: i.e. their conservative merge.
  static IntRange join(IntRange L, IntRange R) {
    return IntRange(std::max(L.Width, R.Width),
                    L.NonNegative && R.NonNegative);
  }

  // Returns the infinum of two ranges: i.e. their aggressive merge.
  static IntRange meet(IntRange L, IntRange R) {
    return IntRange(std::min(L.Width, R.Width),
                    L.NonNegative || R.NonNegative);
  }
};

IntRange GetValueRange(ASTContext &C, llvm::APSInt &value, unsigned MaxWidth) {
  if (value.isSigned() && value.isNegative())
    return IntRange(value.getMinSignedBits(), false);

  if (value.getBitWidth() > MaxWidth)
    value.trunc(MaxWidth);

  // isNonNegative() just checks the sign bit without considering
  // signedness.
  return IntRange(value.getActiveBits(), true);
}

IntRange GetValueRange(ASTContext &C, APValue &result, QualType Ty,
                       unsigned MaxWidth) {
  if (result.isInt())
    return GetValueRange(C, result.getInt(), MaxWidth);

  if (result.isVector()) {
    IntRange R = GetValueRange(C, result.getVectorElt(0), Ty, MaxWidth);
    for (unsigned i = 1, e = result.getVectorLength(); i != e; ++i) {
      IntRange El = GetValueRange(C, result.getVectorElt(i), Ty, MaxWidth);
      R = IntRange::join(R, El);
    }
    return R;
  }

  if (result.isComplexInt()) {
    IntRange R = GetValueRange(C, result.getComplexIntReal(), MaxWidth);
    IntRange I = GetValueRange(C, result.getComplexIntImag(), MaxWidth);
    return IntRange::join(R, I);
  }

  // This can happen with lossless casts to intptr_t of "based" lvalues.
  // Assume it might use arbitrary bits.
  // FIXME: The only reason we need to pass the type in here is to get
  // the sign right on this one case.  It would be nice if APValue
  // preserved this.
  assert(result.isLValue());
  return IntRange(MaxWidth, Ty->isUnsignedIntegerType());
}

/// Pseudo-evaluate the given integer expression, estimating the
/// range of values it might take.
///
/// \param MaxWidth - the width to which the value will be truncated
IntRange GetExprRange(ASTContext &C, Expr *E, unsigned MaxWidth) {
  E = E->IgnoreParens();

  // Try a full evaluation first.
  Expr::EvalResult result;
  if (E->Evaluate(result, C))
    return GetValueRange(C, result.Val, E->getType(), MaxWidth);

  // I think we only want to look through implicit casts here; if the
  // user has an explicit widening cast, we should treat the value as
  // being of the new, wider type.
  if (ImplicitCastExpr *CE = dyn_cast<ImplicitCastExpr>(E)) {
    if (CE->getCastKind() == CK_NoOp)
      return GetExprRange(C, CE->getSubExpr(), MaxWidth);

    IntRange OutputTypeRange = IntRange::forType(C, CE->getType());

    bool isIntegerCast = (CE->getCastKind() == CK_IntegralCast);
    if (!isIntegerCast && CE->getCastKind() == CK_Unknown)
      isIntegerCast = CE->getSubExpr()->getType()->isIntegerType();

    // Assume that non-integer casts can span the full range of the type.
    if (!isIntegerCast)
      return OutputTypeRange;

    IntRange SubRange
      = GetExprRange(C, CE->getSubExpr(),
                     std::min(MaxWidth, OutputTypeRange.Width));

    // Bail out if the subexpr's range is as wide as the cast type.
    if (SubRange.Width >= OutputTypeRange.Width)
      return OutputTypeRange;

    // Otherwise, we take the smaller width, and we're non-negative if
    // either the output type or the subexpr is.
    return IntRange(SubRange.Width,
                    SubRange.NonNegative || OutputTypeRange.NonNegative);
  }

  if (ConditionalOperator *CO = dyn_cast<ConditionalOperator>(E)) {
    // If we can fold the condition, just take that operand.
    bool CondResult;
    if (CO->getCond()->EvaluateAsBooleanCondition(CondResult, C))
      return GetExprRange(C, CondResult ? CO->getTrueExpr()
                                        : CO->getFalseExpr(),
                          MaxWidth);

    // Otherwise, conservatively merge.
    IntRange L = GetExprRange(C, CO->getTrueExpr(), MaxWidth);
    IntRange R = GetExprRange(C, CO->getFalseExpr(), MaxWidth);
    return IntRange::join(L, R);
  }

  if (BinaryOperator *BO = dyn_cast<BinaryOperator>(E)) {
    switch (BO->getOpcode()) {

    // Boolean-valued operations are single-bit and positive.
    case BO_LAnd:
    case BO_LOr:
    case BO_LT:
    case BO_GT:
    case BO_LE:
    case BO_GE:
    case BO_EQ:
    case BO_NE:
      return IntRange::forBoolType();

    // The type of these compound assignments is the type of the LHS,
    // so the RHS is not necessarily an integer.
    case BO_MulAssign:
    case BO_DivAssign:
    case BO_RemAssign:
    case BO_AddAssign:
    case BO_SubAssign:
      return IntRange::forType(C, E->getType());

    // Operations with opaque sources are black-listed.
    case BO_PtrMemD:
    case BO_PtrMemI:
      return IntRange::forType(C, E->getType());

    // Bitwise-and uses the *infinum* of the two source ranges.
    case BO_And:
    case BO_AndAssign:
      return IntRange::meet(GetExprRange(C, BO->getLHS(), MaxWidth),
                            GetExprRange(C, BO->getRHS(), MaxWidth));

    // Left shift gets black-listed based on a judgement call.
    case BO_Shl:
      // ...except that we want to treat '1 << (blah)' as logically
      // positive.  It's an important idiom.
      if (IntegerLiteral *I
            = dyn_cast<IntegerLiteral>(BO->getLHS()->IgnoreParenCasts())) {
        if (I->getValue() == 1) {
          IntRange R = IntRange::forType(C, E->getType());
          return IntRange(R.Width, /*NonNegative*/ true);
        }
      }
      // fallthrough

    case BO_ShlAssign:
      return IntRange::forType(C, E->getType());

    // Right shift by a constant can narrow its left argument.
    case BO_Shr:
    case BO_ShrAssign: {
      IntRange L = GetExprRange(C, BO->getLHS(), MaxWidth);

      // If the shift amount is a positive constant, drop the width by
      // that much.
      llvm::APSInt shift;
      if (BO->getRHS()->isIntegerConstantExpr(shift, C) &&
          shift.isNonNegative()) {
        unsigned zext = shift.getZExtValue();
        if (zext >= L.Width)
          L.Width = (L.NonNegative ? 0 : 1);
        else
          L.Width -= zext;
      }

      return L;
    }

    // Comma acts as its right operand.
    case BO_Comma:
      return GetExprRange(C, BO->getRHS(), MaxWidth);

    // Black-list pointer subtractions.
    case BO_Sub:
      if (BO->getLHS()->getType()->isPointerType())
        return IntRange::forType(C, E->getType());
      // fallthrough

    default:
      break;
    }

    // Treat every other operator as if it were closed on the
    // narrowest type that encompasses both operands.
    IntRange L = GetExprRange(C, BO->getLHS(), MaxWidth);
    IntRange R = GetExprRange(C, BO->getRHS(), MaxWidth);
    return IntRange::join(L, R);
  }

  if (UnaryOperator *UO = dyn_cast<UnaryOperator>(E)) {
    switch (UO->getOpcode()) {
    // Boolean-valued operations are white-listed.
    case UO_LNot:
      return IntRange::forBoolType();

    // Operations with opaque sources are black-listed.
    case UO_Deref:
    case UO_AddrOf: // should be impossible
      return IntRange::forType(C, E->getType());

    default:
      return GetExprRange(C, UO->getSubExpr(), MaxWidth);
    }
  }
  
  if (dyn_cast<OffsetOfExpr>(E)) {
    IntRange::forType(C, E->getType());
  }

  FieldDecl *BitField = E->getBitField();
  if (BitField) {
    llvm::APSInt BitWidthAP = BitField->getBitWidth()->EvaluateAsInt(C);
    unsigned BitWidth = BitWidthAP.getZExtValue();

    return IntRange(BitWidth, BitField->getType()->isUnsignedIntegerType());
  }

  return IntRange::forType(C, E->getType());
}

IntRange GetExprRange(ASTContext &C, Expr *E) {
  return GetExprRange(C, E, C.getIntWidth(E->getType()));
}

/// Checks whether the given value, which currently has the given
/// source semantics, has the same value when coerced through the
/// target semantics.
bool IsSameFloatAfterCast(const llvm::APFloat &value,
                          const llvm::fltSemantics &Src,
                          const llvm::fltSemantics &Tgt) {
  llvm::APFloat truncated = value;

  bool ignored;
  truncated.convert(Src, llvm::APFloat::rmNearestTiesToEven, &ignored);
  truncated.convert(Tgt, llvm::APFloat::rmNearestTiesToEven, &ignored);

  return truncated.bitwiseIsEqual(value);
}

/// Checks whether the given value, which currently has the given
/// source semantics, has the same value when coerced through the
/// target semantics.
///
/// The value might be a vector of floats (or a complex number).
bool IsSameFloatAfterCast(const APValue &value,
                          const llvm::fltSemantics &Src,
                          const llvm::fltSemantics &Tgt) {
  if (value.isFloat())
    return IsSameFloatAfterCast(value.getFloat(), Src, Tgt);

  if (value.isVector()) {
    for (unsigned i = 0, e = value.getVectorLength(); i != e; ++i)
      if (!IsSameFloatAfterCast(value.getVectorElt(i), Src, Tgt))
        return false;
    return true;
  }

  assert(value.isComplexFloat());
  return (IsSameFloatAfterCast(value.getComplexFloatReal(), Src, Tgt) &&
          IsSameFloatAfterCast(value.getComplexFloatImag(), Src, Tgt));
}

void AnalyzeImplicitConversions(Sema &S, Expr *E);

bool IsZero(Sema &S, Expr *E) {
  llvm::APSInt Value;
  return E->isIntegerConstantExpr(Value, S.Context) && Value == 0;
}

void CheckTrivialUnsignedComparison(Sema &S, BinaryOperator *E) {
  BinaryOperatorKind op = E->getOpcode();
  if (op == BO_LT && IsZero(S, E->getRHS())) {
    S.Diag(E->getOperatorLoc(), diag::warn_lunsigned_always_true_comparison)
      << "< 0" << "false"
      << E->getLHS()->getSourceRange() << E->getRHS()->getSourceRange();
  } else if (op == BO_GE && IsZero(S, E->getRHS())) {
    S.Diag(E->getOperatorLoc(), diag::warn_lunsigned_always_true_comparison)
      << ">= 0" << "true"
      << E->getLHS()->getSourceRange() << E->getRHS()->getSourceRange();
  } else if (op == BO_GT && IsZero(S, E->getLHS())) {
    S.Diag(E->getOperatorLoc(), diag::warn_runsigned_always_true_comparison)
      << "0 >" << "false" 
      << E->getLHS()->getSourceRange() << E->getRHS()->getSourceRange();
  } else if (op == BO_LE && IsZero(S, E->getLHS())) {
    S.Diag(E->getOperatorLoc(), diag::warn_runsigned_always_true_comparison)
      << "0 <=" << "true" 
      << E->getLHS()->getSourceRange() << E->getRHS()->getSourceRange();
  }
}

/// Analyze the operands of the given comparison.  Implements the
/// fallback case from AnalyzeComparison.
void AnalyzeImpConvsInComparison(Sema &S, BinaryOperator *E) {
  AnalyzeImplicitConversions(S, E->getLHS());
  AnalyzeImplicitConversions(S, E->getRHS());
}

/// \brief Implements -Wsign-compare.
///
/// \param lex the left-hand expression
/// \param rex the right-hand expression
/// \param OpLoc the location of the joining operator
/// \param BinOpc binary opcode or 0
void AnalyzeComparison(Sema &S, BinaryOperator *E) {
  // The type the comparison is being performed in.
  QualType T = E->getLHS()->getType();
  assert(S.Context.hasSameUnqualifiedType(T, E->getRHS()->getType())
         && "comparison with mismatched types");

  // We don't do anything special if this isn't an unsigned integral
  // comparison:  we're only interested in integral comparisons, and
  // signed comparisons only happen in cases we don't care to warn about.
  if (!T->hasUnsignedIntegerRepresentation())
    return AnalyzeImpConvsInComparison(S, E);

  Expr *lex = E->getLHS()->IgnoreParenImpCasts();
  Expr *rex = E->getRHS()->IgnoreParenImpCasts();

  // Check to see if one of the (unmodified) operands is of different
  // signedness.
  Expr *signedOperand, *unsignedOperand;
  if (lex->getType()->hasSignedIntegerRepresentation()) {
    assert(!rex->getType()->hasSignedIntegerRepresentation() &&
           "unsigned comparison between two signed integer expressions?");
    signedOperand = lex;
    unsignedOperand = rex;
  } else if (rex->getType()->hasSignedIntegerRepresentation()) {
    signedOperand = rex;
    unsignedOperand = lex;
  } else {
    CheckTrivialUnsignedComparison(S, E);
    return AnalyzeImpConvsInComparison(S, E);
  }

  // Otherwise, calculate the effective range of the signed operand.
  IntRange signedRange = GetExprRange(S.Context, signedOperand);

  // Go ahead and analyze implicit conversions in the operands.  Note
  // that we skip the implicit conversions on both sides.
  AnalyzeImplicitConversions(S, lex);
  AnalyzeImplicitConversions(S, rex);

  // If the signed range is non-negative, -Wsign-compare won't fire,
  // but we should still check for comparisons which are always true
  // or false.
  if (signedRange.NonNegative)
    return CheckTrivialUnsignedComparison(S, E);

  // For (in)equality comparisons, if the unsigned operand is a
  // constant which cannot collide with a overflowed signed operand,
  // then reinterpreting the signed operand as unsigned will not
  // change the result of the comparison.
  if (E->isEqualityOp()) {
    unsigned comparisonWidth = S.Context.getIntWidth(T);
    IntRange unsignedRange = GetExprRange(S.Context, unsignedOperand);

    // We should never be unable to prove that the unsigned operand is
    // non-negative.
    assert(unsignedRange.NonNegative && "unsigned range includes negative?");

    if (unsignedRange.Width < comparisonWidth)
      return;
  }

  S.Diag(E->getOperatorLoc(), diag::warn_mixed_sign_comparison)
    << lex->getType() << rex->getType()
    << lex->getSourceRange() << rex->getSourceRange();
}

/// Diagnose an implicit cast;  purely a helper for CheckImplicitConversion.
void DiagnoseImpCast(Sema &S, Expr *E, QualType T, unsigned diag) {
  S.Diag(E->getExprLoc(), diag) << E->getType() << T << E->getSourceRange();
}

void CheckImplicitConversion(Sema &S, Expr *E, QualType T,
                             bool *ICContext = 0) {
  if (E->isTypeDependent() || E->isValueDependent()) return;

  const Type *Source = S.Context.getCanonicalType(E->getType()).getTypePtr();
  const Type *Target = S.Context.getCanonicalType(T).getTypePtr();
  if (Source == Target) return;
  if (Target->isDependentType()) return;

  // Never diagnose implicit casts to bool.
  if (Target->isSpecificBuiltinType(BuiltinType::Bool))
    return;

  // Strip vector types.
  if (isa<VectorType>(Source)) {
    if (!isa<VectorType>(Target))
      return DiagnoseImpCast(S, E, T, diag::warn_impcast_vector_scalar);

    Source = cast<VectorType>(Source)->getElementType().getTypePtr();
    Target = cast<VectorType>(Target)->getElementType().getTypePtr();
  }

  // Strip complex types.
  if (isa<ComplexType>(Source)) {
    if (!isa<ComplexType>(Target))
      return DiagnoseImpCast(S, E, T, diag::warn_impcast_complex_scalar);

    Source = cast<ComplexType>(Source)->getElementType().getTypePtr();
    Target = cast<ComplexType>(Target)->getElementType().getTypePtr();
  }

  const BuiltinType *SourceBT = dyn_cast<BuiltinType>(Source);
  const BuiltinType *TargetBT = dyn_cast<BuiltinType>(Target);

  // If the source is floating point...
  if (SourceBT && SourceBT->isFloatingPoint()) {
    // ...and the target is floating point...
    if (TargetBT && TargetBT->isFloatingPoint()) {
      // ...then warn if we're dropping FP rank.

      // Builtin FP kinds are ordered by increasing FP rank.
      if (SourceBT->getKind() > TargetBT->getKind()) {
        // Don't warn about float constants that are precisely
        // representable in the target type.
        Expr::EvalResult result;
        if (E->Evaluate(result, S.Context)) {
          // Value might be a float, a float vector, or a float complex.
          if (IsSameFloatAfterCast(result.Val,
                   S.Context.getFloatTypeSemantics(QualType(TargetBT, 0)),
                   S.Context.getFloatTypeSemantics(QualType(SourceBT, 0))))
            return;
        }

        DiagnoseImpCast(S, E, T, diag::warn_impcast_float_precision);
      }
      return;
    }

    // If the target is integral, always warn.
    if ((TargetBT && TargetBT->isInteger()))
      // TODO: don't warn for integer values?
      DiagnoseImpCast(S, E, T, diag::warn_impcast_float_integer);

    return;
  }

  if (!Source->isIntegerType() || !Target->isIntegerType())
    return;

  IntRange SourceRange = GetExprRange(S.Context, E);
  IntRange TargetRange = IntRange::forCanonicalType(S.Context, Target);

  if (SourceRange.Width > TargetRange.Width) {
    // People want to build with -Wshorten-64-to-32 and not -Wconversion
    // and by god we'll let them.
    if (SourceRange.Width == 64 && TargetRange.Width == 32)
      return DiagnoseImpCast(S, E, T, diag::warn_impcast_integer_64_32);
    return DiagnoseImpCast(S, E, T, diag::warn_impcast_integer_precision);
  }

  if ((TargetRange.NonNegative && !SourceRange.NonNegative) ||
      (!TargetRange.NonNegative && SourceRange.NonNegative &&
       SourceRange.Width == TargetRange.Width)) {
    unsigned DiagID = diag::warn_impcast_integer_sign;

    // Traditionally, gcc has warned about this under -Wsign-compare.
    // We also want to warn about it in -Wconversion.
    // So if -Wconversion is off, use a completely identical diagnostic
    // in the sign-compare group.
    // The conditional-checking code will 
    if (ICContext) {
      DiagID = diag::warn_impcast_integer_sign_conditional;
      *ICContext = true;
    }

    return DiagnoseImpCast(S, E, T, DiagID);
  }

  return;
}

void CheckConditionalOperator(Sema &S, ConditionalOperator *E, QualType T);

void CheckConditionalOperand(Sema &S, Expr *E, QualType T,
                             bool &ICContext) {
  E = E->IgnoreParenImpCasts();

  if (isa<ConditionalOperator>(E))
    return CheckConditionalOperator(S, cast<ConditionalOperator>(E), T);

  AnalyzeImplicitConversions(S, E);
  if (E->getType() != T)
    return CheckImplicitConversion(S, E, T, &ICContext);
  return;
}

void CheckConditionalOperator(Sema &S, ConditionalOperator *E, QualType T) {
  AnalyzeImplicitConversions(S, E->getCond());

  bool Suspicious = false;
  CheckConditionalOperand(S, E->getTrueExpr(), T, Suspicious);
  CheckConditionalOperand(S, E->getFalseExpr(), T, Suspicious);

  // If -Wconversion would have warned about either of the candidates
  // for a signedness conversion to the context type...
  if (!Suspicious) return;

  // ...but it's currently ignored...
  if (S.Diags.getDiagnosticLevel(diag::warn_impcast_integer_sign_conditional))
    return;

  // ...and -Wsign-compare isn't...
  if (!S.Diags.getDiagnosticLevel(diag::warn_mixed_sign_conditional))
    return;

  // ...then check whether it would have warned about either of the
  // candidates for a signedness conversion to the condition type.
  if (E->getType() != T) {
    Suspicious = false;
    CheckImplicitConversion(S, E->getTrueExpr()->IgnoreParenImpCasts(),
                            E->getType(), &Suspicious);
    if (!Suspicious)
      CheckImplicitConversion(S, E->getFalseExpr()->IgnoreParenImpCasts(),
                              E->getType(), &Suspicious);
    if (!Suspicious)
      return;
  }

  // If so, emit a diagnostic under -Wsign-compare.
  Expr *lex = E->getTrueExpr()->IgnoreParenImpCasts();
  Expr *rex = E->getFalseExpr()->IgnoreParenImpCasts();
  S.Diag(E->getQuestionLoc(), diag::warn_mixed_sign_conditional)
    << lex->getType() << rex->getType()
    << lex->getSourceRange() << rex->getSourceRange();
}

/// AnalyzeImplicitConversions - Find and report any interesting
/// implicit conversions in the given expression.  There are a couple
/// of competing diagnostics here, -Wconversion and -Wsign-compare.
void AnalyzeImplicitConversions(Sema &S, Expr *OrigE) {
  QualType T = OrigE->getType();
  Expr *E = OrigE->IgnoreParenImpCasts();

  // For conditional operators, we analyze the arguments as if they
  // were being fed directly into the output.
  if (isa<ConditionalOperator>(E)) {
    ConditionalOperator *CO = cast<ConditionalOperator>(E);
    CheckConditionalOperator(S, CO, T);
    return;
  }

  // Go ahead and check any implicit conversions we might have skipped.
  // The non-canonical typecheck is just an optimization;
  // CheckImplicitConversion will filter out dead implicit conversions.
  if (E->getType() != T)
    CheckImplicitConversion(S, E, T);

  // Now continue drilling into this expression.

  // Skip past explicit casts.
  if (isa<ExplicitCastExpr>(E)) {
    E = cast<ExplicitCastExpr>(E)->getSubExpr()->IgnoreParenImpCasts();
    return AnalyzeImplicitConversions(S, E);
  }

  // Do a somewhat different check with comparison operators.
  if (isa<BinaryOperator>(E) && cast<BinaryOperator>(E)->isComparisonOp())
    return AnalyzeComparison(S, cast<BinaryOperator>(E));

  // These break the otherwise-useful invariant below.  Fortunately,
  // we don't really need to recurse into them, because any internal
  // expressions should have been analyzed already when they were
  // built into statements.
  if (isa<StmtExpr>(E)) return;

  // Don't descend into unevaluated contexts.
  if (isa<SizeOfAlignOfExpr>(E)) return;

  // Now just recurse over the expression's children.
  for (Stmt::child_iterator I = E->child_begin(), IE = E->child_end();
         I != IE; ++I)
    AnalyzeImplicitConversions(S, cast<Expr>(*I));
}

} // end anonymous namespace

/// Diagnoses "dangerous" implicit conversions within the given
/// expression (which is a full expression).  Implements -Wconversion
/// and -Wsign-compare.
void Sema::CheckImplicitConversions(Expr *E) {
  // Don't diagnose in unevaluated contexts.
  if (ExprEvalContexts.back().Context == Sema::Unevaluated)
    return;

  // Don't diagnose for value- or type-dependent expressions.
  if (E->isTypeDependent() || E->isValueDependent())
    return;

  AnalyzeImplicitConversions(*this, E);
}

/// CheckParmsForFunctionDef - Check that the parameters of the given
/// function are appropriate for the definition of a function. This
/// takes care of any checks that cannot be performed on the
/// declaration itself, e.g., that the types of each of the function
/// parameters are complete.
bool Sema::CheckParmsForFunctionDef(FunctionDecl *FD) {
  bool HasInvalidParm = false;
  for (unsigned p = 0, NumParams = FD->getNumParams(); p < NumParams; ++p) {
    ParmVarDecl *Param = FD->getParamDecl(p);

    // C99 6.7.5.3p4: the parameters in a parameter type list in a
    // function declarator that is part of a function definition of
    // that function shall not have incomplete type.
    //
    // This is also C++ [dcl.fct]p6.
    if (!Param->isInvalidDecl() &&
        RequireCompleteType(Param->getLocation(), Param->getType(),
                               diag::err_typecheck_decl_incomplete_type)) {
      Param->setInvalidDecl();
      HasInvalidParm = true;
    }

    // C99 6.9.1p5: If the declarator includes a parameter type list, the
    // declaration of each parameter shall include an identifier.
    if (Param->getIdentifier() == 0 &&
        !Param->isImplicit() &&
        !getLangOptions().CPlusPlus)
      Diag(Param->getLocation(), diag::err_parameter_name_omitted);

    // C99 6.7.5.3p12:
    //   If the function declarator is not part of a definition of that
    //   function, parameters may have incomplete type and may use the [*]
    //   notation in their sequences of declarator specifiers to specify
    //   variable length array types.
    QualType PType = Param->getOriginalType();
    if (const ArrayType *AT = Context.getAsArrayType(PType)) {
      if (AT->getSizeModifier() == ArrayType::Star) {
        // FIXME: This diagnosic should point the the '[*]' if source-location
        // information is added for it.
        Diag(Param->getLocation(), diag::err_array_star_in_function_definition);
      }
    }
  }

  return HasInvalidParm;
}

/// CheckCastAlign - Implements -Wcast-align, which warns when a
/// pointer cast increases the alignment requirements.
void Sema::CheckCastAlign(Expr *Op, QualType T, SourceRange TRange) {
  // This is actually a lot of work to potentially be doing on every
  // cast; don't do it if we're ignoring -Wcast_align (as is the default).
  if (getDiagnostics().getDiagnosticLevel(diag::warn_cast_align)
        == Diagnostic::Ignored)
    return;

  // Ignore dependent types.
  if (T->isDependentType() || Op->getType()->isDependentType())
    return;

  // Require that the destination be a pointer type.
  const PointerType *DestPtr = T->getAs<PointerType>();
  if (!DestPtr) return;

  // If the destination has alignment 1, we're done.
  QualType DestPointee = DestPtr->getPointeeType();
  if (DestPointee->isIncompleteType()) return;
  CharUnits DestAlign = Context.getTypeAlignInChars(DestPointee);
  if (DestAlign.isOne()) return;

  // Require that the source be a pointer type.
  const PointerType *SrcPtr = Op->getType()->getAs<PointerType>();
  if (!SrcPtr) return;
  QualType SrcPointee = SrcPtr->getPointeeType();

  // Whitelist casts from cv void*.  We already implicitly
  // whitelisted casts to cv void*, since they have alignment 1.
  // Also whitelist casts involving incomplete types, which implicitly
  // includes 'void'.
  if (SrcPointee->isIncompleteType()) return;

  CharUnits SrcAlign = Context.getTypeAlignInChars(SrcPointee);
  if (SrcAlign >= DestAlign) return;

  Diag(TRange.getBegin(), diag::warn_cast_align)
    << Op->getType() << T
    << static_cast<unsigned>(SrcAlign.getQuantity())
    << static_cast<unsigned>(DestAlign.getQuantity())
    << TRange << Op->getSourceRange();
}

