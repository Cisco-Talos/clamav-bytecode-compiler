//===--- TokenLexer.cpp - Lex from a token stream -------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements the TokenLexer interface.
//
//===----------------------------------------------------------------------===//

#include "clang/Lex/TokenLexer.h"
#include "MacroArgs.h"
#include "clang/Lex/MacroInfo.h"
#include "clang/Lex/Preprocessor.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/LexDiagnostic.h"
#include "llvm/ADT/SmallVector.h"
using namespace clang;


/// Create a TokenLexer for the specified macro with the specified actual
/// arguments.  Note that this ctor takes ownership of the ActualArgs pointer.
void TokenLexer::Init(Token &Tok, SourceLocation ILEnd, MacroArgs *Actuals) {
  // If the client is reusing a TokenLexer, make sure to free any memory
  // associated with it.
  destroy();

  Macro = PP.getMacroInfo(Tok.getIdentifierInfo());
  ActualArgs = Actuals;
  CurToken = 0;

  InstantiateLocStart = Tok.getLocation();
  InstantiateLocEnd = ILEnd;
  AtStartOfLine = Tok.isAtStartOfLine();
  HasLeadingSpace = Tok.hasLeadingSpace();
  Tokens = &*Macro->tokens_begin();
  OwnsTokens = false;
  DisableMacroExpansion = false;
  NumTokens = Macro->tokens_end()-Macro->tokens_begin();

  // If this is a function-like macro, expand the arguments and change
  // Tokens to point to the expanded tokens.
  if (Macro->isFunctionLike() && Macro->getNumArgs())
    ExpandFunctionArguments();

  // Mark the macro as currently disabled, so that it is not recursively
  // expanded.  The macro must be disabled only after argument pre-expansion of
  // function-like macro arguments occurs.
  Macro->DisableMacro();
}



/// Create a TokenLexer for the specified token stream.  This does not
/// take ownership of the specified token vector.
void TokenLexer::Init(const Token *TokArray, unsigned NumToks,
                      bool disableMacroExpansion, bool ownsTokens) {
  // If the client is reusing a TokenLexer, make sure to free any memory
  // associated with it.
  destroy();

  Macro = 0;
  ActualArgs = 0;
  Tokens = TokArray;
  OwnsTokens = ownsTokens;
  DisableMacroExpansion = disableMacroExpansion;
  NumTokens = NumToks;
  CurToken = 0;
  InstantiateLocStart = InstantiateLocEnd = SourceLocation();
  AtStartOfLine = false;
  HasLeadingSpace = false;

  // Set HasLeadingSpace/AtStartOfLine so that the first token will be
  // returned unmodified.
  if (NumToks != 0) {
    AtStartOfLine   = TokArray[0].isAtStartOfLine();
    HasLeadingSpace = TokArray[0].hasLeadingSpace();
  }
}


void TokenLexer::destroy() {
  // If this was a function-like macro that actually uses its arguments, delete
  // the expanded tokens.
  if (OwnsTokens) {
    delete [] Tokens;
    Tokens = 0;
    OwnsTokens = false;
  }

  // TokenLexer owns its formal arguments.
  if (ActualArgs) ActualArgs->destroy(PP);
}

/// Expand the arguments of a function-like macro so that we can quickly
/// return preexpanded tokens from Tokens.
void TokenLexer::ExpandFunctionArguments() {
  llvm::SmallVector<Token, 128> ResultToks;

  // Loop through 'Tokens', expanding them into ResultToks.  Keep
  // track of whether we change anything.  If not, no need to keep them.  If so,
  // we install the newly expanded sequence as the new 'Tokens' list.
  bool MadeChange = false;

  // NextTokGetsSpace - When this is true, the next token appended to the
  // output list will get a leading space, regardless of whether it had one to
  // begin with or not.  This is used for placemarker support.
  bool NextTokGetsSpace = false;

  for (unsigned i = 0, e = NumTokens; i != e; ++i) {
    // If we found the stringify operator, get the argument stringified.  The
    // preprocessor already verified that the following token is a macro name
    // when the #define was parsed.
    const Token &CurTok = Tokens[i];
    if (CurTok.is(tok::hash) || CurTok.is(tok::hashat)) {
      int ArgNo = Macro->getArgumentNum(Tokens[i+1].getIdentifierInfo());
      assert(ArgNo != -1 && "Token following # is not an argument?");

      Token Res;
      if (CurTok.is(tok::hash))  // Stringify
        Res = ActualArgs->getStringifiedArgument(ArgNo, PP);
      else {
        // 'charify': don't bother caching these.
        Res = MacroArgs::StringifyArgument(ActualArgs->getUnexpArgument(ArgNo),
                                           PP, true);
      }

      // The stringified/charified string leading space flag gets set to match
      // the #/#@ operator.
      if (CurTok.hasLeadingSpace() || NextTokGetsSpace)
        Res.setFlag(Token::LeadingSpace);

      ResultToks.push_back(Res);
      MadeChange = true;
      ++i;  // Skip arg name.
      NextTokGetsSpace = false;
      continue;
    }

    // Otherwise, if this is not an argument token, just add the token to the
    // output buffer.
    IdentifierInfo *II = CurTok.getIdentifierInfo();
    int ArgNo = II ? Macro->getArgumentNum(II) : -1;
    if (ArgNo == -1) {
      // This isn't an argument, just add it.
      ResultToks.push_back(CurTok);

      if (NextTokGetsSpace) {
        ResultToks.back().setFlag(Token::LeadingSpace);
        NextTokGetsSpace = false;
      }
      continue;
    }

    // An argument is expanded somehow, the result is different than the
    // input.
    MadeChange = true;

    // Otherwise, this is a use of the argument.  Find out if there is a paste
    // (##) operator before or after the argument.
    bool PasteBefore =
      !ResultToks.empty() && ResultToks.back().is(tok::hashhash);
    bool PasteAfter = i+1 != e && Tokens[i+1].is(tok::hashhash);

    // If it is not the LHS/RHS of a ## operator, we must pre-expand the
    // argument and substitute the expanded tokens into the result.  This is
    // C99 6.10.3.1p1.
    if (!PasteBefore && !PasteAfter) {
      const Token *ResultArgToks;

      // Only preexpand the argument if it could possibly need it.  This
      // avoids some work in common cases.
      const Token *ArgTok = ActualArgs->getUnexpArgument(ArgNo);
      if (ActualArgs->ArgNeedsPreexpansion(ArgTok, PP))
        ResultArgToks = &ActualArgs->getPreExpArgument(ArgNo, Macro, PP)[0];
      else
        ResultArgToks = ArgTok;  // Use non-preexpanded tokens.

      // If the arg token expanded into anything, append it.
      if (ResultArgToks->isNot(tok::eof)) {
        unsigned FirstResult = ResultToks.size();
        unsigned NumToks = MacroArgs::getArgLength(ResultArgToks);
        ResultToks.append(ResultArgToks, ResultArgToks+NumToks);

        // If any tokens were substituted from the argument, the whitespace
        // before the first token should match the whitespace of the arg
        // identifier.
        ResultToks[FirstResult].setFlagValue(Token::LeadingSpace,
                                             CurTok.hasLeadingSpace() ||
                                             NextTokGetsSpace);
        NextTokGetsSpace = false;
      } else {
        // If this is an empty argument, and if there was whitespace before the
        // formal token, make sure the next token gets whitespace before it.
        NextTokGetsSpace = CurTok.hasLeadingSpace();
      }
      continue;
    }

    // Okay, we have a token that is either the LHS or RHS of a paste (##)
    // argument.  It gets substituted as its non-pre-expanded tokens.
    const Token *ArgToks = ActualArgs->getUnexpArgument(ArgNo);
    unsigned NumToks = MacroArgs::getArgLength(ArgToks);
    if (NumToks) {  // Not an empty argument?
      // If this is the GNU ", ## __VA_ARG__" extension, and we just learned
      // that __VA_ARG__ expands to multiple tokens, avoid a pasting error when
      // the expander trys to paste ',' with the first token of the __VA_ARG__
      // expansion.
      if (PasteBefore && ResultToks.size() >= 2 &&
          ResultToks[ResultToks.size()-2].is(tok::comma) &&
          (unsigned)ArgNo == Macro->getNumArgs()-1 &&
          Macro->isVariadic()) {
        // Remove the paste operator, report use of the extension.
        PP.Diag(ResultToks.back().getLocation(), diag::ext_paste_comma);
        ResultToks.pop_back();
      }

      ResultToks.append(ArgToks, ArgToks+NumToks);

      // If this token (the macro argument) was supposed to get leading
      // whitespace, transfer this information onto the first token of the
      // expansion.
      //
      // Do not do this if the paste operator occurs before the macro argument,
      // as in "A ## MACROARG".  In valid code, the first token will get
      // smooshed onto the preceding one anyway (forming AMACROARG).  In
      // assembler-with-cpp mode, invalid pastes are allowed through: in this
      // case, we do not want the extra whitespace to be added.  For example,
      // we want ". ## foo" -> ".foo" not ". foo".
      if ((CurTok.hasLeadingSpace() || NextTokGetsSpace) &&
          !PasteBefore)
        ResultToks[ResultToks.size()-NumToks].setFlag(Token::LeadingSpace);

      NextTokGetsSpace = false;
      continue;
    }

    // If an empty argument is on the LHS or RHS of a paste, the standard (C99
    // 6.10.3.3p2,3) calls for a bunch of placemarker stuff to occur.  We
    // implement this by eating ## operators when a LHS or RHS expands to
    // empty.
    NextTokGetsSpace |= CurTok.hasLeadingSpace();
    if (PasteAfter) {
      // Discard the argument token and skip (don't copy to the expansion
      // buffer) the paste operator after it.
      NextTokGetsSpace |= Tokens[i+1].hasLeadingSpace();
      ++i;
      continue;
    }

    // If this is on the RHS of a paste operator, we've already copied the
    // paste operator to the ResultToks list.  Remove it.
    assert(PasteBefore && ResultToks.back().is(tok::hashhash));
    NextTokGetsSpace |= ResultToks.back().hasLeadingSpace();
    ResultToks.pop_back();

    // If this is the __VA_ARGS__ token, and if the argument wasn't provided,
    // and if the macro had at least one real argument, and if the token before
    // the ## was a comma, remove the comma.
    if ((unsigned)ArgNo == Macro->getNumArgs()-1 && // is __VA_ARGS__
        ActualArgs->isVarargsElidedUse() &&       // Argument elided.
        !ResultToks.empty() && ResultToks.back().is(tok::comma)) {
      // Never add a space, even if the comma, ##, or arg had a space.
      NextTokGetsSpace = false;
      // Remove the paste operator, report use of the extension.
      PP.Diag(ResultToks.back().getLocation(), diag::ext_paste_comma);
      ResultToks.pop_back();
    }
    continue;
  }

  // If anything changed, install this as the new Tokens list.
  if (MadeChange) {
    assert(!OwnsTokens && "This would leak if we already own the token list");
    // This is deleted in the dtor.
    NumTokens = ResultToks.size();
    llvm::BumpPtrAllocator &Alloc = PP.getPreprocessorAllocator();
    Token *Res =
      static_cast<Token *>(Alloc.Allocate(sizeof(Token)*ResultToks.size(),
                                          llvm::alignof<Token>()));
    if (NumTokens)
      memcpy(Res, &ResultToks[0], NumTokens*sizeof(Token));
    Tokens = Res;

    // The preprocessor bump pointer owns these tokens, not us.
    OwnsTokens = false;
  }
}

/// Lex - Lex and return a token from this macro stream.
///
void TokenLexer::Lex(Token &Tok) {
  // Lexing off the end of the macro, pop this macro off the expansion stack.
  if (isAtEnd()) {
    // If this is a macro (not a token stream), mark the macro enabled now
    // that it is no longer being expanded.
    if (Macro) Macro->EnableMacro();

    // Pop this context off the preprocessors lexer stack and get the next
    // token.  This will delete "this" so remember the PP instance var.
    Preprocessor &PPCache = PP;
    if (PP.HandleEndOfTokenLexer(Tok))
      return;

    // HandleEndOfTokenLexer may not return a token.  If it doesn't, lex
    // whatever is next.
    return PPCache.Lex(Tok);
  }

  // If this is the first token of the expanded result, we inherit spacing
  // properties later.
  bool isFirstToken = CurToken == 0;

  // Get the next token to return.
  Tok = Tokens[CurToken++];

  bool TokenIsFromPaste = false;

  // If this token is followed by a token paste (##) operator, paste the tokens!
  if (!isAtEnd() && Tokens[CurToken].is(tok::hashhash)) {
    // When handling the microsoft /##/ extension, the final token is
    // returned by PasteTokens, not the pasted token.
    if (PasteTokens(Tok))
      return;

    TokenIsFromPaste = true;
  }

  // The token's current location indicate where the token was lexed from.  We
  // need this information to compute the spelling of the token, but any
  // diagnostics for the expanded token should appear as if they came from
  // InstantiationLoc.  Pull this information together into a new SourceLocation
  // that captures all of this.
  if (InstantiateLocStart.isValid()) {   // Don't do this for token streams.
    SourceManager &SM = PP.getSourceManager();
    Tok.setLocation(SM.createInstantiationLoc(Tok.getLocation(),
                                              InstantiateLocStart,
                                              InstantiateLocEnd,
                                              Tok.getLength()));
  }

  // If this is the first token, set the lexical properties of the token to
  // match the lexical properties of the macro identifier.
  if (isFirstToken) {
    Tok.setFlagValue(Token::StartOfLine , AtStartOfLine);
    Tok.setFlagValue(Token::LeadingSpace, HasLeadingSpace);
  }

  // Handle recursive expansion!
  if (!Tok.isAnnotation() && Tok.getIdentifierInfo() != 0) {
    // Change the kind of this identifier to the appropriate token kind, e.g.
    // turning "for" into a keyword.
    IdentifierInfo *II = Tok.getIdentifierInfo();
    Tok.setKind(II->getTokenID());

    // If this identifier was poisoned and from a paste, emit an error.  This
    // won't be handled by Preprocessor::HandleIdentifier because this is coming
    // from a macro expansion.
    if (II->isPoisoned() && TokenIsFromPaste) {
      // We warn about __VA_ARGS__ with poisoning.
      if (II->isStr("__VA_ARGS__"))
        PP.Diag(Tok, diag::ext_pp_bad_vaargs_use);
      else
        PP.Diag(Tok, diag::err_pp_used_poisoned_id);
    }

    if (!DisableMacroExpansion && II->isHandleIdentifierCase())
      PP.HandleIdentifier(Tok);
  }

  // Otherwise, return a normal token.
}

/// PasteTokens - Tok is the LHS of a ## operator, and CurToken is the ##
/// operator.  Read the ## and RHS, and paste the LHS/RHS together.  If there
/// are more ## after it, chomp them iteratively.  Return the result as Tok.
/// If this returns true, the caller should immediately return the token.
bool TokenLexer::PasteTokens(Token &Tok) {
  llvm::SmallString<128> Buffer;
  const char *ResultTokStrPtr = 0;
  do {
    // Consume the ## operator.
    SourceLocation PasteOpLoc = Tokens[CurToken].getLocation();
    ++CurToken;
    assert(!isAtEnd() && "No token on the RHS of a paste operator!");

    // Get the RHS token.
    const Token &RHS = Tokens[CurToken];

    // Allocate space for the result token.  This is guaranteed to be enough for
    // the two tokens.
    Buffer.resize(Tok.getLength() + RHS.getLength());

    // Get the spelling of the LHS token in Buffer.
    const char *BufPtr = &Buffer[0];
    unsigned LHSLen = PP.getSpelling(Tok, BufPtr);
    if (BufPtr != &Buffer[0])   // Really, we want the chars in Buffer!
      memcpy(&Buffer[0], BufPtr, LHSLen);

    BufPtr = &Buffer[LHSLen];
    unsigned RHSLen = PP.getSpelling(RHS, BufPtr);
    if (BufPtr != &Buffer[LHSLen])   // Really, we want the chars in Buffer!
      memcpy(&Buffer[LHSLen], BufPtr, RHSLen);

    // Trim excess space.
    Buffer.resize(LHSLen+RHSLen);

    // Plop the pasted result (including the trailing newline and null) into a
    // scratch buffer where we can lex it.
    Token ResultTokTmp;
    ResultTokTmp.startToken();

    // Claim that the tmp token is a string_literal so that we can get the
    // character pointer back from CreateString in getLiteralData().
    ResultTokTmp.setKind(tok::string_literal);
    PP.CreateString(&Buffer[0], Buffer.size(), ResultTokTmp);
    SourceLocation ResultTokLoc = ResultTokTmp.getLocation();
    ResultTokStrPtr = ResultTokTmp.getLiteralData();

    // Lex the resultant pasted token into Result.
    Token Result;

    if (Tok.is(tok::identifier) && RHS.is(tok::identifier)) {
      // Common paste case: identifier+identifier = identifier.  Avoid creating
      // a lexer and other overhead.
      PP.IncrementPasteCounter(true);
      Result.startToken();
      Result.setKind(tok::identifier);
      Result.setLocation(ResultTokLoc);
      Result.setLength(LHSLen+RHSLen);
    } else {
      PP.IncrementPasteCounter(false);

      assert(ResultTokLoc.isFileID() &&
             "Should be a raw location into scratch buffer");
      SourceManager &SourceMgr = PP.getSourceManager();
      FileID LocFileID = SourceMgr.getFileID(ResultTokLoc);

      bool Invalid = false;
      const char *ScratchBufStart
        = SourceMgr.getBufferData(LocFileID, &Invalid).first;
      if (Invalid)
        return false;

      // Make a lexer to lex this string from.  Lex just this one token.
      // Make a lexer object so that we lex and expand the paste result.
      Lexer TL(SourceMgr.getLocForStartOfFile(LocFileID),
               PP.getLangOptions(), ScratchBufStart,
               ResultTokStrPtr, ResultTokStrPtr+LHSLen+RHSLen);

      // Lex a token in raw mode.  This way it won't look up identifiers
      // automatically, lexing off the end will return an eof token, and
      // warnings are disabled.  This returns true if the result token is the
      // entire buffer.
      bool isInvalid = !TL.LexFromRawLexer(Result);

      // If we got an EOF token, we didn't form even ONE token.  For example, we
      // did "/ ## /" to get "//".
      isInvalid |= Result.is(tok::eof);

      // If pasting the two tokens didn't form a full new token, this is an
      // error.  This occurs with "x ## +"  and other stuff.  Return with Tok
      // unmodified and with RHS as the next token to lex.
      if (isInvalid) {
        // Test for the Microsoft extension of /##/ turning into // here on the
        // error path.
        if (PP.getLangOptions().Microsoft && Tok.is(tok::slash) &&
            RHS.is(tok::slash)) {
          HandleMicrosoftCommentPaste(Tok);
          return true;
        }

        // Do not emit the warning when preprocessing assembler code.
        if (!PP.getLangOptions().AsmPreprocessor) {
          // Explicitly convert the token location to have proper instantiation
          // information so that the user knows where it came from.
          SourceManager &SM = PP.getSourceManager();
          SourceLocation Loc =
            SM.createInstantiationLoc(PasteOpLoc, InstantiateLocStart,
                                      InstantiateLocEnd, 2);
          PP.Diag(Loc, diag::err_pp_bad_paste)
            << std::string(Buffer.begin(), Buffer.end());
        }

        // Do not consume the RHS.
        --CurToken;
      }

      // Turn ## into 'unknown' to avoid # ## # from looking like a paste
      // operator.
      if (Result.is(tok::hashhash))
        Result.setKind(tok::unknown);
    }

    // Transfer properties of the LHS over the the Result.
    Result.setFlagValue(Token::StartOfLine , Tok.isAtStartOfLine());
    Result.setFlagValue(Token::LeadingSpace, Tok.hasLeadingSpace());

    // Finally, replace LHS with the result, consume the RHS, and iterate.
    ++CurToken;
    Tok = Result;
  } while (!isAtEnd() && Tokens[CurToken].is(tok::hashhash));

  // Now that we got the result token, it will be subject to expansion.  Since
  // token pasting re-lexes the result token in raw mode, identifier information
  // isn't looked up.  As such, if the result is an identifier, look up id info.
  if (Tok.is(tok::identifier)) {
    // Look up the identifier info for the token.  We disabled identifier lookup
    // by saying we're skipping contents, so we need to do this manually.
    PP.LookUpIdentifierInfo(Tok, ResultTokStrPtr);
  }
  return false;
}

/// isNextTokenLParen - If the next token lexed will pop this macro off the
/// expansion stack, return 2.  If the next unexpanded token is a '(', return
/// 1, otherwise return 0.
unsigned TokenLexer::isNextTokenLParen() const {
  // Out of tokens?
  if (isAtEnd())
    return 2;
  return Tokens[CurToken].is(tok::l_paren);
}


/// HandleMicrosoftCommentPaste - In microsoft compatibility mode, /##/ pastes
/// together to form a comment that comments out everything in the current
/// macro, other active macros, and anything left on the current physical
/// source line of the instantiated buffer.  Handle this by returning the
/// first token on the next line.
void TokenLexer::HandleMicrosoftCommentPaste(Token &Tok) {
  // We 'comment out' the rest of this macro by just ignoring the rest of the
  // tokens that have not been lexed yet, if any.

  // Since this must be a macro, mark the macro enabled now that it is no longer
  // being expanded.
  assert(Macro && "Token streams can't paste comments");
  Macro->EnableMacro();

  PP.HandleMicrosoftCommentPaste(Tok);
}
