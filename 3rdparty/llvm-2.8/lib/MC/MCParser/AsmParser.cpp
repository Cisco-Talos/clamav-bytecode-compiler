//===- AsmParser.cpp - Parser for Assembly Files --------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This class implements the parser for assembly files.
//
//===----------------------------------------------------------------------===//

#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/StringMap.h"
#include "llvm/ADT/StringSwitch.h"
#include "llvm/ADT/Twine.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCExpr.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCParser/AsmCond.h"
#include "llvm/MC/MCParser/AsmLexer.h"
#include "llvm/MC/MCParser/MCAsmParser.h"
#include "llvm/MC/MCParser/MCParsedAsmOperand.h"
#include "llvm/MC/MCSectionMachO.h"
#include "llvm/MC/MCStreamer.h"
#include "llvm/MC/MCSymbol.h"
#include "llvm/MC/MCDwarf.h"
#include "llvm/Support/Compiler.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetAsmParser.h"
#include <vector>
using namespace llvm;

namespace {

/// \brief Helper class for tracking macro definitions.
struct Macro {
  StringRef Name;
  StringRef Body;

public:
  Macro(StringRef N, StringRef B) : Name(N), Body(B) {}
};

/// \brief Helper class for storing information about an active macro
/// instantiation.
struct MacroInstantiation {
  /// The macro being instantiated.
  const Macro *TheMacro;

  /// The macro instantiation with substitutions.
  MemoryBuffer *Instantiation;

  /// The location of the instantiation.
  SMLoc InstantiationLoc;

  /// The location where parsing should resume upon instantiation completion.
  SMLoc ExitLoc;

public:
  MacroInstantiation(const Macro *M, SMLoc IL, SMLoc EL,
                     const std::vector<std::vector<AsmToken> > &A);
};

/// \brief The concrete assembly parser instance.
class AsmParser : public MCAsmParser {
  friend class GenericAsmParser;

  AsmParser(const AsmParser &);   // DO NOT IMPLEMENT
  void operator=(const AsmParser &);  // DO NOT IMPLEMENT
private:
  AsmLexer Lexer;
  MCContext &Ctx;
  MCStreamer &Out;
  SourceMgr &SrcMgr;
  MCAsmParserExtension *GenericParser;
  MCAsmParserExtension *PlatformParser;

  /// This is the current buffer index we're lexing from as managed by the
  /// SourceMgr object.
  int CurBuffer;

  AsmCond TheCondState;
  std::vector<AsmCond> TheCondStack;

  /// DirectiveMap - This is a table handlers for directives.  Each handler is
  /// invoked after the directive identifier is read and is responsible for
  /// parsing and validating the rest of the directive.  The handler is passed
  /// in the directive name and the location of the directive keyword.
  StringMap<std::pair<MCAsmParserExtension*, DirectiveHandler> > DirectiveMap;

  /// MacroMap - Map of currently defined macros.
  StringMap<Macro*> MacroMap;

  /// ActiveMacros - Stack of active macro instantiations.
  std::vector<MacroInstantiation*> ActiveMacros;

  /// Boolean tracking whether macro substitution is enabled.
  unsigned MacrosEnabled : 1;

public:
  AsmParser(const Target &T, SourceMgr &SM, MCContext &Ctx, MCStreamer &Out,
            const MCAsmInfo &MAI);
  ~AsmParser();

  virtual bool Run(bool NoInitialTextSection, bool NoFinalize = false);

  void AddDirectiveHandler(MCAsmParserExtension *Object,
                           StringRef Directive,
                           DirectiveHandler Handler) {
    DirectiveMap[Directive] = std::make_pair(Object, Handler);
  }

public:
  /// @name MCAsmParser Interface
  /// {

  virtual SourceMgr &getSourceManager() { return SrcMgr; }
  virtual MCAsmLexer &getLexer() { return Lexer; }
  virtual MCContext &getContext() { return Ctx; }
  virtual MCStreamer &getStreamer() { return Out; }

  virtual void Warning(SMLoc L, const Twine &Meg);
  virtual bool Error(SMLoc L, const Twine &Msg);

  const AsmToken &Lex();

  bool ParseExpression(const MCExpr *&Res);
  virtual bool ParseExpression(const MCExpr *&Res, SMLoc &EndLoc);
  virtual bool ParseParenExpression(const MCExpr *&Res, SMLoc &EndLoc);
  virtual bool ParseAbsoluteExpression(int64_t &Res);

  /// }

private:
  bool ParseStatement();

  bool HandleMacroEntry(StringRef Name, SMLoc NameLoc, const Macro *M);
  void HandleMacroExit();

  void PrintMacroInstantiations();
  void PrintMessage(SMLoc Loc, const std::string &Msg, const char *Type) const;
    
  /// EnterIncludeFile - Enter the specified file. This returns true on failure.
  bool EnterIncludeFile(const std::string &Filename);

  /// \brief Reset the current lexer position to that given by \arg Loc. The
  /// current token is not set; clients should ensure Lex() is called
  /// subsequently.
  void JumpToLoc(SMLoc Loc);

  void EatToEndOfStatement();

  /// \brief Parse up to the end of statement and a return the contents from the
  /// current token until the end of the statement; the current token on exit
  /// will be either the EndOfStatement or EOF.
  StringRef ParseStringToEndOfStatement();

  bool ParseAssignment(StringRef Name);

  bool ParsePrimaryExpr(const MCExpr *&Res, SMLoc &EndLoc);
  bool ParseBinOpRHS(unsigned Precedence, const MCExpr *&Res, SMLoc &EndLoc);
  bool ParseParenExpr(const MCExpr *&Res, SMLoc &EndLoc);

  /// ParseIdentifier - Parse an identifier or string (as a quoted identifier)
  /// and set \arg Res to the identifier contents.
  bool ParseIdentifier(StringRef &Res);
  
  // Directive Parsing.
  bool ParseDirectiveAscii(bool ZeroTerminated); // ".ascii", ".asciiz"
  bool ParseDirectiveValue(unsigned Size); // ".byte", ".long", ...
  bool ParseDirectiveFill(); // ".fill"
  bool ParseDirectiveSpace(); // ".space"
  bool ParseDirectiveSet(); // ".set"
  bool ParseDirectiveOrg(); // ".org"
  // ".align{,32}", ".p2align{,w,l}"
  bool ParseDirectiveAlign(bool IsPow2, unsigned ValueSize);

  /// ParseDirectiveSymbolAttribute - Parse a directive like ".globl" which
  /// accepts a single symbol (which should be a label or an external).
  bool ParseDirectiveSymbolAttribute(MCSymbolAttr Attr);
  bool ParseDirectiveELFType(); // ELF specific ".type"

  bool ParseDirectiveComm(bool IsLocal); // ".comm" and ".lcomm"

  bool ParseDirectiveAbort(); // ".abort"
  bool ParseDirectiveInclude(); // ".include"

  bool ParseDirectiveIf(SMLoc DirectiveLoc); // ".if"
  bool ParseDirectiveElseIf(SMLoc DirectiveLoc); // ".elseif"
  bool ParseDirectiveElse(SMLoc DirectiveLoc); // ".else"
  bool ParseDirectiveEndIf(SMLoc DirectiveLoc); // .endif

  /// ParseEscapedString - Parse the current token as a string which may include
  /// escaped characters and return the string contents.
  bool ParseEscapedString(std::string &Data);
};

/// \brief Generic implementations of directive handling, etc. which is shared
/// (or the default, at least) for all assembler parser.
class GenericAsmParser : public MCAsmParserExtension {
  template<bool (GenericAsmParser::*Handler)(StringRef, SMLoc)>
  void AddDirectiveHandler(StringRef Directive) {
    getParser().AddDirectiveHandler(this, Directive,
                                    HandleDirective<GenericAsmParser, Handler>);
  }

public:
  GenericAsmParser() {}

  AsmParser &getParser() {
    return (AsmParser&) this->MCAsmParserExtension::getParser();
  }

  virtual void Initialize(MCAsmParser &Parser) {
    // Call the base implementation.
    this->MCAsmParserExtension::Initialize(Parser);

    // Debugging directives.
    AddDirectiveHandler<&GenericAsmParser::ParseDirectiveFile>(".file");
    AddDirectiveHandler<&GenericAsmParser::ParseDirectiveLine>(".line");
    AddDirectiveHandler<&GenericAsmParser::ParseDirectiveLoc>(".loc");

    // Macro directives.
    AddDirectiveHandler<&GenericAsmParser::ParseDirectiveMacrosOnOff>(
      ".macros_on");
    AddDirectiveHandler<&GenericAsmParser::ParseDirectiveMacrosOnOff>(
      ".macros_off");
    AddDirectiveHandler<&GenericAsmParser::ParseDirectiveMacro>(".macro");
    AddDirectiveHandler<&GenericAsmParser::ParseDirectiveEndMacro>(".endm");
    AddDirectiveHandler<&GenericAsmParser::ParseDirectiveEndMacro>(".endmacro");
  }

  bool ParseDirectiveFile(StringRef, SMLoc DirectiveLoc);
  bool ParseDirectiveLine(StringRef, SMLoc DirectiveLoc);
  bool ParseDirectiveLoc(StringRef, SMLoc DirectiveLoc);

  bool ParseDirectiveMacrosOnOff(StringRef, SMLoc DirectiveLoc);
  bool ParseDirectiveMacro(StringRef, SMLoc DirectiveLoc);
  bool ParseDirectiveEndMacro(StringRef, SMLoc DirectiveLoc);
};

}

namespace llvm {

extern MCAsmParserExtension *createDarwinAsmParser();
extern MCAsmParserExtension *createELFAsmParser();

}

enum { DEFAULT_ADDRSPACE = 0 };

AsmParser::AsmParser(const Target &T, SourceMgr &_SM, MCContext &_Ctx,
                     MCStreamer &_Out, const MCAsmInfo &_MAI)
  : Lexer(_MAI), Ctx(_Ctx), Out(_Out), SrcMgr(_SM),
    GenericParser(new GenericAsmParser), PlatformParser(0),
    CurBuffer(0), MacrosEnabled(true) {
  Lexer.setBuffer(SrcMgr.getMemoryBuffer(CurBuffer));

  // Initialize the generic parser.
  GenericParser->Initialize(*this);

  // Initialize the platform / file format parser.
  //
  // FIXME: This is a hack, we need to (majorly) cleanup how these objects are
  // created.
  if (_MAI.hasSubsectionsViaSymbols()) {
    PlatformParser = createDarwinAsmParser();
    PlatformParser->Initialize(*this);
  } else {
    PlatformParser = createELFAsmParser();
    PlatformParser->Initialize(*this);
  }
}

AsmParser::~AsmParser() {
  assert(ActiveMacros.empty() && "Unexpected active macro instantiation!");

  // Destroy any macros.
  for (StringMap<Macro*>::iterator it = MacroMap.begin(),
         ie = MacroMap.end(); it != ie; ++it)
    delete it->getValue();

  delete PlatformParser;
  delete GenericParser;
}

void AsmParser::PrintMacroInstantiations() {
  // Print the active macro instantiation stack.
  for (std::vector<MacroInstantiation*>::const_reverse_iterator
         it = ActiveMacros.rbegin(), ie = ActiveMacros.rend(); it != ie; ++it)
    PrintMessage((*it)->InstantiationLoc, "while in macro instantiation",
                 "note");
}

void AsmParser::Warning(SMLoc L, const Twine &Msg) {
  PrintMessage(L, Msg.str(), "warning");
  PrintMacroInstantiations();
}

bool AsmParser::Error(SMLoc L, const Twine &Msg) {
  PrintMessage(L, Msg.str(), "error");
  PrintMacroInstantiations();
  return true;
}

void AsmParser::PrintMessage(SMLoc Loc, const std::string &Msg, 
                             const char *Type) const {
  SrcMgr.PrintMessage(Loc, Msg, Type);
}
                  
bool AsmParser::EnterIncludeFile(const std::string &Filename) {
  int NewBuf = SrcMgr.AddIncludeFile(Filename, Lexer.getLoc());
  if (NewBuf == -1)
    return true;
  
  CurBuffer = NewBuf;
  
  Lexer.setBuffer(SrcMgr.getMemoryBuffer(CurBuffer));
  
  return false;
}

void AsmParser::JumpToLoc(SMLoc Loc) {
  CurBuffer = SrcMgr.FindBufferContainingLoc(Loc);
  Lexer.setBuffer(SrcMgr.getMemoryBuffer(CurBuffer), Loc.getPointer());
}

const AsmToken &AsmParser::Lex() {
  const AsmToken *tok = &Lexer.Lex();
  
  if (tok->is(AsmToken::Eof)) {
    // If this is the end of an included file, pop the parent file off the
    // include stack.
    SMLoc ParentIncludeLoc = SrcMgr.getParentIncludeLoc(CurBuffer);
    if (ParentIncludeLoc != SMLoc()) {
      JumpToLoc(ParentIncludeLoc);
      tok = &Lexer.Lex();
    }
  }
    
  if (tok->is(AsmToken::Error))
    Error(Lexer.getErrLoc(), Lexer.getErr());
  
  return *tok;
}

bool AsmParser::Run(bool NoInitialTextSection, bool NoFinalize) {
  // Create the initial section, if requested.
  //
  // FIXME: Target hook & command line option for initial section.
  if (!NoInitialTextSection)
    Out.SwitchSection(Ctx.getMachOSection("__TEXT", "__text",
                                      MCSectionMachO::S_ATTR_PURE_INSTRUCTIONS,
                                      0, SectionKind::getText()));

  // Prime the lexer.
  Lex();
  
  bool HadError = false;
  
  AsmCond StartingCondState = TheCondState;

  // While we have input, parse each statement.
  while (Lexer.isNot(AsmToken::Eof)) {
    if (!ParseStatement()) continue;
  
    // We had an error, remember it and recover by skipping to the next line.
    HadError = true;
    EatToEndOfStatement();
  }

  if (TheCondState.TheCond != StartingCondState.TheCond ||
      TheCondState.Ignore != StartingCondState.Ignore)
    return TokError("unmatched .ifs or .elses");

  // Check to see there are no empty DwarfFile slots.
  const std::vector<MCDwarfFile *> &MCDwarfFiles =
    getContext().getMCDwarfFiles();
  for (unsigned i = 1; i < MCDwarfFiles.size(); i++) {
    if (!MCDwarfFiles[i]){
      TokError("unassigned file number: " + Twine(i) + " for .file directives");
      HadError = true;
    }
  }
  
  // Finalize the output stream if there are no errors and if the client wants
  // us to.
  if (!HadError && !NoFinalize)  
    Out.Finish();

  return HadError;
}

/// EatToEndOfStatement - Throw away the rest of the line for testing purposes.
void AsmParser::EatToEndOfStatement() {
  while (Lexer.isNot(AsmToken::EndOfStatement) &&
         Lexer.isNot(AsmToken::Eof))
    Lex();
  
  // Eat EOL.
  if (Lexer.is(AsmToken::EndOfStatement))
    Lex();
}

StringRef AsmParser::ParseStringToEndOfStatement() {
  const char *Start = getTok().getLoc().getPointer();

  while (Lexer.isNot(AsmToken::EndOfStatement) &&
         Lexer.isNot(AsmToken::Eof))
    Lex();

  const char *End = getTok().getLoc().getPointer();
  return StringRef(Start, End - Start);
}

/// ParseParenExpr - Parse a paren expression and return it.
/// NOTE: This assumes the leading '(' has already been consumed.
///
/// parenexpr ::= expr)
///
bool AsmParser::ParseParenExpr(const MCExpr *&Res, SMLoc &EndLoc) {
  if (ParseExpression(Res)) return true;
  if (Lexer.isNot(AsmToken::RParen))
    return TokError("expected ')' in parentheses expression");
  EndLoc = Lexer.getLoc();
  Lex();
  return false;
}

/// ParsePrimaryExpr - Parse a primary expression and return it.
///  primaryexpr ::= (parenexpr
///  primaryexpr ::= symbol
///  primaryexpr ::= number
///  primaryexpr ::= '.'
///  primaryexpr ::= ~,+,- primaryexpr
bool AsmParser::ParsePrimaryExpr(const MCExpr *&Res, SMLoc &EndLoc) {
  switch (Lexer.getKind()) {
  default:
    return TokError("unknown token in expression");
  case AsmToken::Exclaim:
    Lex(); // Eat the operator.
    if (ParsePrimaryExpr(Res, EndLoc))
      return true;
    Res = MCUnaryExpr::CreateLNot(Res, getContext());
    return false;
  case AsmToken::Dollar:
  case AsmToken::String:
  case AsmToken::Identifier: {
    EndLoc = Lexer.getLoc();

    StringRef Identifier;
    if (ParseIdentifier(Identifier))
      return false;

    // This is a symbol reference.
    std::pair<StringRef, StringRef> Split = Identifier.split('@');
    MCSymbol *Sym = getContext().GetOrCreateSymbol(Split.first);

    // Mark the symbol as used in an expression.
    Sym->setUsedInExpr(true);

    // Lookup the symbol variant if used.
    MCSymbolRefExpr::VariantKind Variant = MCSymbolRefExpr::VK_None;
    if (Split.first.size() != Identifier.size())
      Variant = MCSymbolRefExpr::getVariantKindForName(Split.second);

    // If this is an absolute variable reference, substitute it now to preserve
    // semantics in the face of reassignment.
    if (Sym->isVariable() && isa<MCConstantExpr>(Sym->getVariableValue())) {
      if (Variant)
        return Error(EndLoc, "unexpected modified on variable reference");

      Res = Sym->getVariableValue();
      return false;
    }

    // Otherwise create a symbol ref.
    Res = MCSymbolRefExpr::Create(Sym, Variant, getContext());
    return false;
  }
  case AsmToken::Integer: {
    SMLoc Loc = getTok().getLoc();
    int64_t IntVal = getTok().getIntVal();
    Res = MCConstantExpr::Create(IntVal, getContext());
    EndLoc = Lexer.getLoc();
    Lex(); // Eat token.
    // Look for 'b' or 'f' following an Integer as a directional label
    if (Lexer.getKind() == AsmToken::Identifier) {
      StringRef IDVal = getTok().getString();
      if (IDVal == "f" || IDVal == "b"){
        MCSymbol *Sym = Ctx.GetDirectionalLocalSymbol(IntVal,
                                                      IDVal == "f" ? 1 : 0);
        Res = MCSymbolRefExpr::Create(Sym, MCSymbolRefExpr::VK_None,
                                      getContext());
        if(IDVal == "b" && Sym->isUndefined())
          return Error(Loc, "invalid reference to undefined symbol");
        EndLoc = Lexer.getLoc();
        Lex(); // Eat identifier.
      }
    }
    return false;
  }
  case AsmToken::Dot: {
    // This is a '.' reference, which references the current PC.  Emit a
    // temporary label to the streamer and refer to it.
    MCSymbol *Sym = Ctx.CreateTempSymbol();
    Out.EmitLabel(Sym);
    Res = MCSymbolRefExpr::Create(Sym, MCSymbolRefExpr::VK_None, getContext());
    EndLoc = Lexer.getLoc();
    Lex(); // Eat identifier.
    return false;
  }
      
  case AsmToken::LParen:
    Lex(); // Eat the '('.
    return ParseParenExpr(Res, EndLoc);
  case AsmToken::Minus:
    Lex(); // Eat the operator.
    if (ParsePrimaryExpr(Res, EndLoc))
      return true;
    Res = MCUnaryExpr::CreateMinus(Res, getContext());
    return false;
  case AsmToken::Plus:
    Lex(); // Eat the operator.
    if (ParsePrimaryExpr(Res, EndLoc))
      return true;
    Res = MCUnaryExpr::CreatePlus(Res, getContext());
    return false;
  case AsmToken::Tilde:
    Lex(); // Eat the operator.
    if (ParsePrimaryExpr(Res, EndLoc))
      return true;
    Res = MCUnaryExpr::CreateNot(Res, getContext());
    return false;
  }
}

bool AsmParser::ParseExpression(const MCExpr *&Res) {
  SMLoc EndLoc;
  return ParseExpression(Res, EndLoc);
}

/// ParseExpression - Parse an expression and return it.
/// 
///  expr ::= expr +,- expr          -> lowest.
///  expr ::= expr |,^,&,! expr      -> middle.
///  expr ::= expr *,/,%,<<,>> expr  -> highest.
///  expr ::= primaryexpr
///
bool AsmParser::ParseExpression(const MCExpr *&Res, SMLoc &EndLoc) {
  // Parse the expression.
  Res = 0;
  if (ParsePrimaryExpr(Res, EndLoc) || ParseBinOpRHS(1, Res, EndLoc))
    return true;

  // Try to constant fold it up front, if possible.
  int64_t Value;
  if (Res->EvaluateAsAbsolute(Value))
    Res = MCConstantExpr::Create(Value, getContext());

  return false;
}

bool AsmParser::ParseParenExpression(const MCExpr *&Res, SMLoc &EndLoc) {
  Res = 0;
  return ParseParenExpr(Res, EndLoc) ||
         ParseBinOpRHS(1, Res, EndLoc);
}

bool AsmParser::ParseAbsoluteExpression(int64_t &Res) {
  const MCExpr *Expr;
  
  SMLoc StartLoc = Lexer.getLoc();
  if (ParseExpression(Expr))
    return true;

  if (!Expr->EvaluateAsAbsolute(Res))
    return Error(StartLoc, "expected absolute expression");

  return false;
}

static unsigned getBinOpPrecedence(AsmToken::TokenKind K, 
                                   MCBinaryExpr::Opcode &Kind) {
  switch (K) {
  default:
    return 0;    // not a binop.

    // Lowest Precedence: &&, ||
  case AsmToken::AmpAmp:
    Kind = MCBinaryExpr::LAnd;
    return 1;
  case AsmToken::PipePipe:
    Kind = MCBinaryExpr::LOr;
    return 1;

    // Low Precedence: +, -, ==, !=, <>, <, <=, >, >=
  case AsmToken::Plus:
    Kind = MCBinaryExpr::Add;
    return 2;
  case AsmToken::Minus:
    Kind = MCBinaryExpr::Sub;
    return 2;
  case AsmToken::EqualEqual:
    Kind = MCBinaryExpr::EQ;
    return 2;
  case AsmToken::ExclaimEqual:
  case AsmToken::LessGreater:
    Kind = MCBinaryExpr::NE;
    return 2;
  case AsmToken::Less:
    Kind = MCBinaryExpr::LT;
    return 2;
  case AsmToken::LessEqual:
    Kind = MCBinaryExpr::LTE;
    return 2;
  case AsmToken::Greater:
    Kind = MCBinaryExpr::GT;
    return 2;
  case AsmToken::GreaterEqual:
    Kind = MCBinaryExpr::GTE;
    return 2;

    // Intermediate Precedence: |, &, ^
    //
    // FIXME: gas seems to support '!' as an infix operator?
  case AsmToken::Pipe:
    Kind = MCBinaryExpr::Or;
    return 3;
  case AsmToken::Caret:
    Kind = MCBinaryExpr::Xor;
    return 3;
  case AsmToken::Amp:
    Kind = MCBinaryExpr::And;
    return 3;

    // Highest Precedence: *, /, %, <<, >>
  case AsmToken::Star:
    Kind = MCBinaryExpr::Mul;
    return 4;
  case AsmToken::Slash:
    Kind = MCBinaryExpr::Div;
    return 4;
  case AsmToken::Percent:
    Kind = MCBinaryExpr::Mod;
    return 4;
  case AsmToken::LessLess:
    Kind = MCBinaryExpr::Shl;
    return 4;
  case AsmToken::GreaterGreater:
    Kind = MCBinaryExpr::Shr;
    return 4;
  }
}


/// ParseBinOpRHS - Parse all binary operators with precedence >= 'Precedence'.
/// Res contains the LHS of the expression on input.
bool AsmParser::ParseBinOpRHS(unsigned Precedence, const MCExpr *&Res,
                              SMLoc &EndLoc) {
  while (1) {
    MCBinaryExpr::Opcode Kind = MCBinaryExpr::Add;
    unsigned TokPrec = getBinOpPrecedence(Lexer.getKind(), Kind);
    
    // If the next token is lower precedence than we are allowed to eat, return
    // successfully with what we ate already.
    if (TokPrec < Precedence)
      return false;
    
    Lex();
    
    // Eat the next primary expression.
    const MCExpr *RHS;
    if (ParsePrimaryExpr(RHS, EndLoc)) return true;
    
    // If BinOp binds less tightly with RHS than the operator after RHS, let
    // the pending operator take RHS as its LHS.
    MCBinaryExpr::Opcode Dummy;
    unsigned NextTokPrec = getBinOpPrecedence(Lexer.getKind(), Dummy);
    if (TokPrec < NextTokPrec) {
      if (ParseBinOpRHS(Precedence+1, RHS, EndLoc)) return true;
    }

    // Merge LHS and RHS according to operator.
    Res = MCBinaryExpr::Create(Kind, Res, RHS, getContext());
  }
}

  
  
  
/// ParseStatement:
///   ::= EndOfStatement
///   ::= Label* Directive ...Operands... EndOfStatement
///   ::= Label* Identifier OperandList* EndOfStatement
bool AsmParser::ParseStatement() {
  if (Lexer.is(AsmToken::EndOfStatement)) {
    Out.AddBlankLine();
    Lex();
    return false;
  }

  // Statements always start with an identifier.
  AsmToken ID = getTok();
  SMLoc IDLoc = ID.getLoc();
  StringRef IDVal;
  int64_t LocalLabelVal = -1;
  // GUESS allow an integer followed by a ':' as a directional local label
  if (Lexer.is(AsmToken::Integer)) {
    LocalLabelVal = getTok().getIntVal();
    if (LocalLabelVal < 0) {
      if (!TheCondState.Ignore)
        return TokError("unexpected token at start of statement");
      IDVal = "";
    }
    else {
      IDVal = getTok().getString();
      Lex(); // Consume the integer token to be used as an identifier token.
      if (Lexer.getKind() != AsmToken::Colon) {
        if (!TheCondState.Ignore)
          return TokError("unexpected token at start of statement");
      }
    }
  }
  else if (ParseIdentifier(IDVal)) {
    if (!TheCondState.Ignore)
      return TokError("unexpected token at start of statement");
    IDVal = "";
  }

  // Handle conditional assembly here before checking for skipping.  We
  // have to do this so that .endif isn't skipped in a ".if 0" block for
  // example.
  if (IDVal == ".if")
    return ParseDirectiveIf(IDLoc);
  if (IDVal == ".elseif")
    return ParseDirectiveElseIf(IDLoc);
  if (IDVal == ".else")
    return ParseDirectiveElse(IDLoc);
  if (IDVal == ".endif")
    return ParseDirectiveEndIf(IDLoc);
    
  // If we are in a ".if 0" block, ignore this statement.
  if (TheCondState.Ignore) {
    EatToEndOfStatement();
    return false;
  }
  
  // FIXME: Recurse on local labels?

  // See what kind of statement we have.
  switch (Lexer.getKind()) {
  case AsmToken::Colon: {
    // identifier ':'   -> Label.
    Lex();

    // Diagnose attempt to use a variable as a label.
    //
    // FIXME: Diagnostics. Note the location of the definition as a label.
    // FIXME: This doesn't diagnose assignment to a symbol which has been
    // implicitly marked as external.
    MCSymbol *Sym;
    if (LocalLabelVal == -1)
      Sym = getContext().GetOrCreateSymbol(IDVal);
    else
      Sym = Ctx.CreateDirectionalLocalSymbol(LocalLabelVal);
    if (!Sym->isUndefined() || Sym->isVariable())
      return Error(IDLoc, "invalid symbol redefinition");
    
    // Emit the label.
    Out.EmitLabel(Sym);
   
    // Consume any end of statement token, if present, to avoid spurious
    // AddBlankLine calls().
    if (Lexer.is(AsmToken::EndOfStatement)) {
      Lex();
      if (Lexer.is(AsmToken::Eof))
        return false;
    }

    return ParseStatement();
  }

  case AsmToken::Equal:
    // identifier '=' ... -> assignment statement
    Lex();

    return ParseAssignment(IDVal);

  default: // Normal instruction or directive.
    break;
  }

  // If macros are enabled, check to see if this is a macro instantiation.
  if (MacrosEnabled)
    if (const Macro *M = MacroMap.lookup(IDVal))
      return HandleMacroEntry(IDVal, IDLoc, M);

  // Otherwise, we have a normal instruction or directive.  
  if (IDVal[0] == '.') {
    // Assembler features
    if (IDVal == ".set")
      return ParseDirectiveSet();

    // Data directives

    if (IDVal == ".ascii")
      return ParseDirectiveAscii(false);
    if (IDVal == ".asciz")
      return ParseDirectiveAscii(true);

    if (IDVal == ".byte")
      return ParseDirectiveValue(1);
    if (IDVal == ".short")
      return ParseDirectiveValue(2);
    if (IDVal == ".long")
      return ParseDirectiveValue(4);
    if (IDVal == ".quad")
      return ParseDirectiveValue(8);

    if (IDVal == ".align") {
      bool IsPow2 = !getContext().getAsmInfo().getAlignmentIsInBytes();
      return ParseDirectiveAlign(IsPow2, /*ExprSize=*/1);
    }
    if (IDVal == ".align32") {
      bool IsPow2 = !getContext().getAsmInfo().getAlignmentIsInBytes();
      return ParseDirectiveAlign(IsPow2, /*ExprSize=*/4);
    }
    if (IDVal == ".balign")
      return ParseDirectiveAlign(/*IsPow2=*/false, /*ExprSize=*/1);
    if (IDVal == ".balignw")
      return ParseDirectiveAlign(/*IsPow2=*/false, /*ExprSize=*/2);
    if (IDVal == ".balignl")
      return ParseDirectiveAlign(/*IsPow2=*/false, /*ExprSize=*/4);
    if (IDVal == ".p2align")
      return ParseDirectiveAlign(/*IsPow2=*/true, /*ExprSize=*/1);
    if (IDVal == ".p2alignw")
      return ParseDirectiveAlign(/*IsPow2=*/true, /*ExprSize=*/2);
    if (IDVal == ".p2alignl")
      return ParseDirectiveAlign(/*IsPow2=*/true, /*ExprSize=*/4);

    if (IDVal == ".org")
      return ParseDirectiveOrg();

    if (IDVal == ".fill")
      return ParseDirectiveFill();
    if (IDVal == ".space")
      return ParseDirectiveSpace();

    // Symbol attribute directives

    if (IDVal == ".globl" || IDVal == ".global")
      return ParseDirectiveSymbolAttribute(MCSA_Global);
    if (IDVal == ".hidden")
      return ParseDirectiveSymbolAttribute(MCSA_Hidden);
    if (IDVal == ".indirect_symbol")
      return ParseDirectiveSymbolAttribute(MCSA_IndirectSymbol);
    if (IDVal == ".internal")
      return ParseDirectiveSymbolAttribute(MCSA_Internal);
    if (IDVal == ".lazy_reference")
      return ParseDirectiveSymbolAttribute(MCSA_LazyReference);
    if (IDVal == ".no_dead_strip")
      return ParseDirectiveSymbolAttribute(MCSA_NoDeadStrip);
    if (IDVal == ".private_extern")
      return ParseDirectiveSymbolAttribute(MCSA_PrivateExtern);
    if (IDVal == ".protected")
      return ParseDirectiveSymbolAttribute(MCSA_Protected);
    if (IDVal == ".reference")
      return ParseDirectiveSymbolAttribute(MCSA_Reference);
    if (IDVal == ".type")
      return ParseDirectiveELFType();
    if (IDVal == ".weak")
      return ParseDirectiveSymbolAttribute(MCSA_Weak);
    if (IDVal == ".weak_definition")
      return ParseDirectiveSymbolAttribute(MCSA_WeakDefinition);
    if (IDVal == ".weak_reference")
      return ParseDirectiveSymbolAttribute(MCSA_WeakReference);
    if (IDVal == ".weak_def_can_be_hidden")
      return ParseDirectiveSymbolAttribute(MCSA_WeakDefAutoPrivate);

    if (IDVal == ".comm")
      return ParseDirectiveComm(/*IsLocal=*/false);
    if (IDVal == ".lcomm")
      return ParseDirectiveComm(/*IsLocal=*/true);

    if (IDVal == ".abort")
      return ParseDirectiveAbort();
    if (IDVal == ".include")
      return ParseDirectiveInclude();

    // Look up the handler in the handler table.
    std::pair<MCAsmParserExtension*, DirectiveHandler> Handler =
      DirectiveMap.lookup(IDVal);
    if (Handler.first)
      return (*Handler.second)(Handler.first, IDVal, IDLoc);

    // Target hook for parsing target specific directives.
    if (!getTargetParser().ParseDirective(ID))
      return false;

    Warning(IDLoc, "ignoring directive for now");
    EatToEndOfStatement();
    return false;
  }

  // Canonicalize the opcode to lower case.
  SmallString<128> Opcode;
  for (unsigned i = 0, e = IDVal.size(); i != e; ++i)
    Opcode.push_back(tolower(IDVal[i]));
  
  SmallVector<MCParsedAsmOperand*, 8> ParsedOperands;
  bool HadError = getTargetParser().ParseInstruction(Opcode.str(), IDLoc,
                                                     ParsedOperands);
  if (!HadError && Lexer.isNot(AsmToken::EndOfStatement))
    HadError = TokError("unexpected token in argument list");

  // Dump the parsed representation, if requested.
  if (getShowParsedOperands()) {
    SmallString<256> Str;
    raw_svector_ostream OS(Str);
    OS << "parsed instruction: [";
    for (unsigned i = 0; i != ParsedOperands.size(); ++i) {
      if (i != 0)
        OS << ", ";
      ParsedOperands[i]->dump(OS);
    }
    OS << "]";

    PrintMessage(IDLoc, OS.str(), "note");
  }

  // If parsing succeeded, match the instruction.
  if (!HadError) {
    MCInst Inst;
    if (!getTargetParser().MatchInstruction(IDLoc, ParsedOperands, Inst)) {
      // Emit the instruction on success.
      Out.EmitInstruction(Inst);
    } else
      HadError = true;
  }

  // If there was no error, consume the end-of-statement token. Otherwise this
  // will be done by our caller.
  if (!HadError)
    Lex();

  // Free any parsed operands.
  for (unsigned i = 0, e = ParsedOperands.size(); i != e; ++i)
    delete ParsedOperands[i];

  return HadError;
}

MacroInstantiation::MacroInstantiation(const Macro *M, SMLoc IL, SMLoc EL,
                                   const std::vector<std::vector<AsmToken> > &A)
  : TheMacro(M), InstantiationLoc(IL), ExitLoc(EL)
{
  // Macro instantiation is lexical, unfortunately. We construct a new buffer
  // to hold the macro body with substitutions.
  SmallString<256> Buf;
  raw_svector_ostream OS(Buf);

  StringRef Body = M->Body;
  while (!Body.empty()) {
    // Scan for the next substitution.
    std::size_t End = Body.size(), Pos = 0;
    for (; Pos != End; ++Pos) {
      // Check for a substitution or escape.
      if (Body[Pos] != '$' || Pos + 1 == End)
        continue;

      char Next = Body[Pos + 1];
      if (Next == '$' || Next == 'n' || isdigit(Next))
        break;
    }

    // Add the prefix.
    OS << Body.slice(0, Pos);

    // Check if we reached the end.
    if (Pos == End)
      break;

    switch (Body[Pos+1]) {
       // $$ => $
    case '$':
      OS << '$';
      break;

      // $n => number of arguments
    case 'n':
      OS << A.size();
      break;

       // $[0-9] => argument
    default: {
      // Missing arguments are ignored.
      unsigned Index = Body[Pos+1] - '0';
      if (Index >= A.size())
        break;

      // Otherwise substitute with the token values, with spaces eliminated.
      for (std::vector<AsmToken>::const_iterator it = A[Index].begin(),
             ie = A[Index].end(); it != ie; ++it)
        OS << it->getString();
      break;
    }
    }

    // Update the scan point.
    Body = Body.substr(Pos + 2);
  }

  // We include the .endmacro in the buffer as our queue to exit the macro
  // instantiation.
  OS << ".endmacro\n";

  Instantiation = MemoryBuffer::getMemBufferCopy(OS.str(), "<instantiation>");
}

bool AsmParser::HandleMacroEntry(StringRef Name, SMLoc NameLoc,
                                 const Macro *M) {
  // Arbitrarily limit macro nesting depth, to match 'as'. We can eliminate
  // this, although we should protect against infinite loops.
  if (ActiveMacros.size() == 20)
    return TokError("macros cannot be nested more than 20 levels deep");

  // Parse the macro instantiation arguments.
  std::vector<std::vector<AsmToken> > MacroArguments;
  MacroArguments.push_back(std::vector<AsmToken>());
  unsigned ParenLevel = 0;
  for (;;) {
    if (Lexer.is(AsmToken::Eof))
      return TokError("unexpected token in macro instantiation");
    if (Lexer.is(AsmToken::EndOfStatement))
      break;

    // If we aren't inside parentheses and this is a comma, start a new token
    // list.
    if (ParenLevel == 0 && Lexer.is(AsmToken::Comma)) {
      MacroArguments.push_back(std::vector<AsmToken>());
    } else {
      // Adjust the current parentheses level.
      if (Lexer.is(AsmToken::LParen))
        ++ParenLevel;
      else if (Lexer.is(AsmToken::RParen) && ParenLevel)
        --ParenLevel;

      // Append the token to the current argument list.
      MacroArguments.back().push_back(getTok());
    }
    Lex();
  }

  // Create the macro instantiation object and add to the current macro
  // instantiation stack.
  MacroInstantiation *MI = new MacroInstantiation(M, NameLoc,
                                                  getTok().getLoc(),
                                                  MacroArguments);
  ActiveMacros.push_back(MI);

  // Jump to the macro instantiation and prime the lexer.
  CurBuffer = SrcMgr.AddNewSourceBuffer(MI->Instantiation, SMLoc());
  Lexer.setBuffer(SrcMgr.getMemoryBuffer(CurBuffer));
  Lex();

  return false;
}

void AsmParser::HandleMacroExit() {
  // Jump to the EndOfStatement we should return to, and consume it.
  JumpToLoc(ActiveMacros.back()->ExitLoc);
  Lex();

  // Pop the instantiation entry.
  delete ActiveMacros.back();
  ActiveMacros.pop_back();
}

bool AsmParser::ParseAssignment(StringRef Name) {
  // FIXME: Use better location, we should use proper tokens.
  SMLoc EqualLoc = Lexer.getLoc();

  const MCExpr *Value;
  if (ParseExpression(Value))
    return true;
  
  if (Lexer.isNot(AsmToken::EndOfStatement))
    return TokError("unexpected token in assignment");

  // Eat the end of statement marker.
  Lex();

  // Validate that the LHS is allowed to be a variable (either it has not been
  // used as a symbol, or it is an absolute symbol).
  MCSymbol *Sym = getContext().LookupSymbol(Name);
  if (Sym) {
    // Diagnose assignment to a label.
    //
    // FIXME: Diagnostics. Note the location of the definition as a label.
    // FIXME: Diagnose assignment to protected identifier (e.g., register name).
    if (Sym->isUndefined() && !Sym->isUsedInExpr())
      ; // Allow redefinitions of undefined symbols only used in directives.
    else if (!Sym->isUndefined() && !Sym->isAbsolute())
      return Error(EqualLoc, "redefinition of '" + Name + "'");
    else if (!Sym->isVariable())
      return Error(EqualLoc, "invalid assignment to '" + Name + "'");
    else if (!isa<MCConstantExpr>(Sym->getVariableValue()))
      return Error(EqualLoc, "invalid reassignment of non-absolute variable '" +
                   Name + "'");
  } else
    Sym = getContext().GetOrCreateSymbol(Name);

  // FIXME: Handle '.'.

  Sym->setUsedInExpr(true);

  // Do the assignment.
  Out.EmitAssignment(Sym, Value);

  return false;
}

/// ParseIdentifier:
///   ::= identifier
///   ::= string
bool AsmParser::ParseIdentifier(StringRef &Res) {
  // The assembler has relaxed rules for accepting identifiers, in particular we
  // allow things like '.globl $foo', which would normally be separate
  // tokens. At this level, we have already lexed so we cannot (currently)
  // handle this as a context dependent token, instead we detect adjacent tokens
  // and return the combined identifier.
  if (Lexer.is(AsmToken::Dollar)) {
    SMLoc DollarLoc = getLexer().getLoc();

    // Consume the dollar sign, and check for a following identifier.
    Lex();
    if (Lexer.isNot(AsmToken::Identifier))
      return true;

    // We have a '$' followed by an identifier, make sure they are adjacent.
    if (DollarLoc.getPointer() + 1 != getTok().getLoc().getPointer())
      return true;

    // Construct the joined identifier and consume the token.
    Res = StringRef(DollarLoc.getPointer(),
                    getTok().getIdentifier().size() + 1);
    Lex();
    return false;
  }

  if (Lexer.isNot(AsmToken::Identifier) &&
      Lexer.isNot(AsmToken::String))
    return true;

  Res = getTok().getIdentifier();

  Lex(); // Consume the identifier token.

  return false;
}

/// ParseDirectiveSet:
///   ::= .set identifier ',' expression
bool AsmParser::ParseDirectiveSet() {
  StringRef Name;

  if (ParseIdentifier(Name))
    return TokError("expected identifier after '.set' directive");
  
  if (getLexer().isNot(AsmToken::Comma))
    return TokError("unexpected token in '.set'");
  Lex();

  return ParseAssignment(Name);
}

bool AsmParser::ParseEscapedString(std::string &Data) {
  assert(getLexer().is(AsmToken::String) && "Unexpected current token!");

  Data = "";
  StringRef Str = getTok().getStringContents();
  for (unsigned i = 0, e = Str.size(); i != e; ++i) {
    if (Str[i] != '\\') {
      Data += Str[i];
      continue;
    }

    // Recognize escaped characters. Note that this escape semantics currently
    // loosely follows Darwin 'as'. Notably, it doesn't support hex escapes.
    ++i;
    if (i == e)
      return TokError("unexpected backslash at end of string");

    // Recognize octal sequences.
    if ((unsigned) (Str[i] - '0') <= 7) {
      // Consume up to three octal characters.
      unsigned Value = Str[i] - '0';

      if (i + 1 != e && ((unsigned) (Str[i + 1] - '0')) <= 7) {
        ++i;
        Value = Value * 8 + (Str[i] - '0');

        if (i + 1 != e && ((unsigned) (Str[i + 1] - '0')) <= 7) {
          ++i;
          Value = Value * 8 + (Str[i] - '0');
        }
      }

      if (Value > 255)
        return TokError("invalid octal escape sequence (out of range)");

      Data += (unsigned char) Value;
      continue;
    }

    // Otherwise recognize individual escapes.
    switch (Str[i]) {
    default:
      // Just reject invalid escape sequences for now.
      return TokError("invalid escape sequence (unrecognized character)");

    case 'b': Data += '\b'; break;
    case 'f': Data += '\f'; break;
    case 'n': Data += '\n'; break;
    case 'r': Data += '\r'; break;
    case 't': Data += '\t'; break;
    case '"': Data += '"'; break;
    case '\\': Data += '\\'; break;
    }
  }

  return false;
}

/// ParseDirectiveAscii:
///   ::= ( .ascii | .asciz ) [ "string" ( , "string" )* ]
bool AsmParser::ParseDirectiveAscii(bool ZeroTerminated) {
  if (getLexer().isNot(AsmToken::EndOfStatement)) {
    for (;;) {
      if (getLexer().isNot(AsmToken::String))
        return TokError("expected string in '.ascii' or '.asciz' directive");

      std::string Data;
      if (ParseEscapedString(Data))
        return true;

      getStreamer().EmitBytes(Data, DEFAULT_ADDRSPACE);
      if (ZeroTerminated)
        getStreamer().EmitBytes(StringRef("\0", 1), DEFAULT_ADDRSPACE);

      Lex();

      if (getLexer().is(AsmToken::EndOfStatement))
        break;

      if (getLexer().isNot(AsmToken::Comma))
        return TokError("unexpected token in '.ascii' or '.asciz' directive");
      Lex();
    }
  }

  Lex();
  return false;
}

/// ParseDirectiveValue
///  ::= (.byte | .short | ... ) [ expression (, expression)* ]
bool AsmParser::ParseDirectiveValue(unsigned Size) {
  if (getLexer().isNot(AsmToken::EndOfStatement)) {
    for (;;) {
      const MCExpr *Value;
      SMLoc ATTRIBUTE_UNUSED StartLoc = getLexer().getLoc();
      if (ParseExpression(Value))
        return true;

      // Special case constant expressions to match code generator.
      if (const MCConstantExpr *MCE = dyn_cast<MCConstantExpr>(Value))
        getStreamer().EmitIntValue(MCE->getValue(), Size, DEFAULT_ADDRSPACE);
      else
        getStreamer().EmitValue(Value, Size, DEFAULT_ADDRSPACE);

      if (getLexer().is(AsmToken::EndOfStatement))
        break;
      
      // FIXME: Improve diagnostic.
      if (getLexer().isNot(AsmToken::Comma))
        return TokError("unexpected token in directive");
      Lex();
    }
  }

  Lex();
  return false;
}

/// ParseDirectiveSpace
///  ::= .space expression [ , expression ]
bool AsmParser::ParseDirectiveSpace() {
  int64_t NumBytes;
  if (ParseAbsoluteExpression(NumBytes))
    return true;

  int64_t FillExpr = 0;
  if (getLexer().isNot(AsmToken::EndOfStatement)) {
    if (getLexer().isNot(AsmToken::Comma))
      return TokError("unexpected token in '.space' directive");
    Lex();
    
    if (ParseAbsoluteExpression(FillExpr))
      return true;

    if (getLexer().isNot(AsmToken::EndOfStatement))
      return TokError("unexpected token in '.space' directive");
  }

  Lex();

  if (NumBytes <= 0)
    return TokError("invalid number of bytes in '.space' directive");

  // FIXME: Sometimes the fill expr is 'nop' if it isn't supplied, instead of 0.
  getStreamer().EmitFill(NumBytes, FillExpr, DEFAULT_ADDRSPACE);

  return false;
}

/// ParseDirectiveFill
///  ::= .fill expression , expression , expression
bool AsmParser::ParseDirectiveFill() {
  int64_t NumValues;
  if (ParseAbsoluteExpression(NumValues))
    return true;

  if (getLexer().isNot(AsmToken::Comma))
    return TokError("unexpected token in '.fill' directive");
  Lex();
  
  int64_t FillSize;
  if (ParseAbsoluteExpression(FillSize))
    return true;

  if (getLexer().isNot(AsmToken::Comma))
    return TokError("unexpected token in '.fill' directive");
  Lex();
  
  int64_t FillExpr;
  if (ParseAbsoluteExpression(FillExpr))
    return true;

  if (getLexer().isNot(AsmToken::EndOfStatement))
    return TokError("unexpected token in '.fill' directive");
  
  Lex();

  if (FillSize != 1 && FillSize != 2 && FillSize != 4 && FillSize != 8)
    return TokError("invalid '.fill' size, expected 1, 2, 4, or 8");

  for (uint64_t i = 0, e = NumValues; i != e; ++i)
    getStreamer().EmitIntValue(FillExpr, FillSize, DEFAULT_ADDRSPACE);

  return false;
}

/// ParseDirectiveOrg
///  ::= .org expression [ , expression ]
bool AsmParser::ParseDirectiveOrg() {
  const MCExpr *Offset;
  if (ParseExpression(Offset))
    return true;

  // Parse optional fill expression.
  int64_t FillExpr = 0;
  if (getLexer().isNot(AsmToken::EndOfStatement)) {
    if (getLexer().isNot(AsmToken::Comma))
      return TokError("unexpected token in '.org' directive");
    Lex();
    
    if (ParseAbsoluteExpression(FillExpr))
      return true;

    if (getLexer().isNot(AsmToken::EndOfStatement))
      return TokError("unexpected token in '.org' directive");
  }

  Lex();

  // FIXME: Only limited forms of relocatable expressions are accepted here, it
  // has to be relative to the current section.
  getStreamer().EmitValueToOffset(Offset, FillExpr);

  return false;
}

/// ParseDirectiveAlign
///  ::= {.align, ...} expression [ , expression [ , expression ]]
bool AsmParser::ParseDirectiveAlign(bool IsPow2, unsigned ValueSize) {
  SMLoc AlignmentLoc = getLexer().getLoc();
  int64_t Alignment;
  if (ParseAbsoluteExpression(Alignment))
    return true;

  SMLoc MaxBytesLoc;
  bool HasFillExpr = false;
  int64_t FillExpr = 0;
  int64_t MaxBytesToFill = 0;
  if (getLexer().isNot(AsmToken::EndOfStatement)) {
    if (getLexer().isNot(AsmToken::Comma))
      return TokError("unexpected token in directive");
    Lex();

    // The fill expression can be omitted while specifying a maximum number of
    // alignment bytes, e.g:
    //  .align 3,,4
    if (getLexer().isNot(AsmToken::Comma)) {
      HasFillExpr = true;
      if (ParseAbsoluteExpression(FillExpr))
        return true;
    }

    if (getLexer().isNot(AsmToken::EndOfStatement)) {
      if (getLexer().isNot(AsmToken::Comma))
        return TokError("unexpected token in directive");
      Lex();

      MaxBytesLoc = getLexer().getLoc();
      if (ParseAbsoluteExpression(MaxBytesToFill))
        return true;
      
      if (getLexer().isNot(AsmToken::EndOfStatement))
        return TokError("unexpected token in directive");
    }
  }

  Lex();

  if (!HasFillExpr)
    FillExpr = 0;

  // Compute alignment in bytes.
  if (IsPow2) {
    // FIXME: Diagnose overflow.
    if (Alignment >= 32) {
      Error(AlignmentLoc, "invalid alignment value");
      Alignment = 31;
    }

    Alignment = 1ULL << Alignment;
  }

  // Diagnose non-sensical max bytes to align.
  if (MaxBytesLoc.isValid()) {
    if (MaxBytesToFill < 1) {
      Error(MaxBytesLoc, "alignment directive can never be satisfied in this "
            "many bytes, ignoring maximum bytes expression");
      MaxBytesToFill = 0;
    }

    if (MaxBytesToFill >= Alignment) {
      Warning(MaxBytesLoc, "maximum bytes expression exceeds alignment and "
              "has no effect");
      MaxBytesToFill = 0;
    }
  }

  // Check whether we should use optimal code alignment for this .align
  // directive.
  //
  // FIXME: This should be using a target hook.
  bool UseCodeAlign = false;
  if (const MCSectionMachO *S = dyn_cast<MCSectionMachO>(
        getStreamer().getCurrentSection()))
    UseCodeAlign = S->hasAttribute(MCSectionMachO::S_ATTR_PURE_INSTRUCTIONS);
  if ((!HasFillExpr || Lexer.getMAI().getTextAlignFillValue() == FillExpr) &&
      ValueSize == 1 && UseCodeAlign) {
    getStreamer().EmitCodeAlignment(Alignment, MaxBytesToFill);
  } else {
    // FIXME: Target specific behavior about how the "extra" bytes are filled.
    getStreamer().EmitValueToAlignment(Alignment, FillExpr, ValueSize,
                                       MaxBytesToFill);
  }

  return false;
}

/// ParseDirectiveSymbolAttribute
///  ::= { ".globl", ".weak", ... } [ identifier ( , identifier )* ]
bool AsmParser::ParseDirectiveSymbolAttribute(MCSymbolAttr Attr) {
  if (getLexer().isNot(AsmToken::EndOfStatement)) {
    for (;;) {
      StringRef Name;

      if (ParseIdentifier(Name))
        return TokError("expected identifier in directive");
      
      MCSymbol *Sym = getContext().GetOrCreateSymbol(Name);

      getStreamer().EmitSymbolAttribute(Sym, Attr);

      if (getLexer().is(AsmToken::EndOfStatement))
        break;

      if (getLexer().isNot(AsmToken::Comma))
        return TokError("unexpected token in directive");
      Lex();
    }
  }

  Lex();
  return false;  
}

/// ParseDirectiveELFType
///  ::= .type identifier , @attribute
bool AsmParser::ParseDirectiveELFType() {
  StringRef Name;
  if (ParseIdentifier(Name))
    return TokError("expected identifier in directive");

  // Handle the identifier as the key symbol.
  MCSymbol *Sym = getContext().GetOrCreateSymbol(Name);

  if (getLexer().isNot(AsmToken::Comma))
    return TokError("unexpected token in '.type' directive");
  Lex();

  if (getLexer().isNot(AsmToken::At))
    return TokError("expected '@' before type");
  Lex();

  StringRef Type;
  SMLoc TypeLoc;

  TypeLoc = getLexer().getLoc();
  if (ParseIdentifier(Type))
    return TokError("expected symbol type in directive");

  MCSymbolAttr Attr = StringSwitch<MCSymbolAttr>(Type)
    .Case("function", MCSA_ELF_TypeFunction)
    .Case("object", MCSA_ELF_TypeObject)
    .Case("tls_object", MCSA_ELF_TypeTLS)
    .Case("common", MCSA_ELF_TypeCommon)
    .Case("notype", MCSA_ELF_TypeNoType)
    .Default(MCSA_Invalid);

  if (Attr == MCSA_Invalid)
    return Error(TypeLoc, "unsupported attribute in '.type' directive");

  if (getLexer().isNot(AsmToken::EndOfStatement))
    return TokError("unexpected token in '.type' directive");

  Lex();

  getStreamer().EmitSymbolAttribute(Sym, Attr);

  return false;
}

/// ParseDirectiveComm
///  ::= ( .comm | .lcomm ) identifier , size_expression [ , align_expression ]
bool AsmParser::ParseDirectiveComm(bool IsLocal) {
  SMLoc IDLoc = getLexer().getLoc();
  StringRef Name;
  if (ParseIdentifier(Name))
    return TokError("expected identifier in directive");
  
  // Handle the identifier as the key symbol.
  MCSymbol *Sym = getContext().GetOrCreateSymbol(Name);

  if (getLexer().isNot(AsmToken::Comma))
    return TokError("unexpected token in directive");
  Lex();

  int64_t Size;
  SMLoc SizeLoc = getLexer().getLoc();
  if (ParseAbsoluteExpression(Size))
    return true;

  int64_t Pow2Alignment = 0;
  SMLoc Pow2AlignmentLoc;
  if (getLexer().is(AsmToken::Comma)) {
    Lex();
    Pow2AlignmentLoc = getLexer().getLoc();
    if (ParseAbsoluteExpression(Pow2Alignment))
      return true;
    
    // If this target takes alignments in bytes (not log) validate and convert.
    if (Lexer.getMAI().getAlignmentIsInBytes()) {
      if (!isPowerOf2_64(Pow2Alignment))
        return Error(Pow2AlignmentLoc, "alignment must be a power of 2");
      Pow2Alignment = Log2_64(Pow2Alignment);
    }
  }
  
  if (getLexer().isNot(AsmToken::EndOfStatement))
    return TokError("unexpected token in '.comm' or '.lcomm' directive");
  
  Lex();

  // NOTE: a size of zero for a .comm should create a undefined symbol
  // but a size of .lcomm creates a bss symbol of size zero.
  if (Size < 0)
    return Error(SizeLoc, "invalid '.comm' or '.lcomm' directive size, can't "
                 "be less than zero");

  // NOTE: The alignment in the directive is a power of 2 value, the assembler
  // may internally end up wanting an alignment in bytes.
  // FIXME: Diagnose overflow.
  if (Pow2Alignment < 0)
    return Error(Pow2AlignmentLoc, "invalid '.comm' or '.lcomm' directive "
                 "alignment, can't be less than zero");

  if (!Sym->isUndefined())
    return Error(IDLoc, "invalid symbol redefinition");

  // '.lcomm' is equivalent to '.zerofill'.
  // Create the Symbol as a common or local common with Size and Pow2Alignment
  if (IsLocal) {
    getStreamer().EmitZerofill(Ctx.getMachOSection(
                                 "__DATA", "__bss", MCSectionMachO::S_ZEROFILL,
                                 0, SectionKind::getBSS()),
                               Sym, Size, 1 << Pow2Alignment);
    return false;
  }

  getStreamer().EmitCommonSymbol(Sym, Size, 1 << Pow2Alignment);
  return false;
}

/// ParseDirectiveAbort
///  ::= .abort [... message ...]
bool AsmParser::ParseDirectiveAbort() {
  // FIXME: Use loc from directive.
  SMLoc Loc = getLexer().getLoc();

  StringRef Str = ParseStringToEndOfStatement();
  if (getLexer().isNot(AsmToken::EndOfStatement))
    return TokError("unexpected token in '.abort' directive");

  Lex();

  if (Str.empty())
    Error(Loc, ".abort detected. Assembly stopping.");
  else
    Error(Loc, ".abort '" + Str + "' detected. Assembly stopping.");
  // FIXME: Actually abort assembly here.

  return false;
}

/// ParseDirectiveInclude
///  ::= .include "filename"
bool AsmParser::ParseDirectiveInclude() {
  if (getLexer().isNot(AsmToken::String))
    return TokError("expected string in '.include' directive");
  
  std::string Filename = getTok().getString();
  SMLoc IncludeLoc = getLexer().getLoc();
  Lex();

  if (getLexer().isNot(AsmToken::EndOfStatement))
    return TokError("unexpected token in '.include' directive");
  
  // Strip the quotes.
  Filename = Filename.substr(1, Filename.size()-2);
  
  // Attempt to switch the lexer to the included file before consuming the end
  // of statement to avoid losing it when we switch.
  if (EnterIncludeFile(Filename)) {
    Error(IncludeLoc, "Could not find include file '" + Filename + "'");
    return true;
  }

  return false;
}

/// ParseDirectiveIf
/// ::= .if expression
bool AsmParser::ParseDirectiveIf(SMLoc DirectiveLoc) {
  TheCondStack.push_back(TheCondState);
  TheCondState.TheCond = AsmCond::IfCond;
  if(TheCondState.Ignore) {
    EatToEndOfStatement();
  }
  else {
    int64_t ExprValue;
    if (ParseAbsoluteExpression(ExprValue))
      return true;

    if (getLexer().isNot(AsmToken::EndOfStatement))
      return TokError("unexpected token in '.if' directive");
    
    Lex();

    TheCondState.CondMet = ExprValue;
    TheCondState.Ignore = !TheCondState.CondMet;
  }

  return false;
}

/// ParseDirectiveElseIf
/// ::= .elseif expression
bool AsmParser::ParseDirectiveElseIf(SMLoc DirectiveLoc) {
  if (TheCondState.TheCond != AsmCond::IfCond &&
      TheCondState.TheCond != AsmCond::ElseIfCond)
      Error(DirectiveLoc, "Encountered a .elseif that doesn't follow a .if or "
                          " an .elseif");
  TheCondState.TheCond = AsmCond::ElseIfCond;

  bool LastIgnoreState = false;
  if (!TheCondStack.empty())
      LastIgnoreState = TheCondStack.back().Ignore;
  if (LastIgnoreState || TheCondState.CondMet) {
    TheCondState.Ignore = true;
    EatToEndOfStatement();
  }
  else {
    int64_t ExprValue;
    if (ParseAbsoluteExpression(ExprValue))
      return true;

    if (getLexer().isNot(AsmToken::EndOfStatement))
      return TokError("unexpected token in '.elseif' directive");
    
    Lex();
    TheCondState.CondMet = ExprValue;
    TheCondState.Ignore = !TheCondState.CondMet;
  }

  return false;
}

/// ParseDirectiveElse
/// ::= .else
bool AsmParser::ParseDirectiveElse(SMLoc DirectiveLoc) {
  if (getLexer().isNot(AsmToken::EndOfStatement))
    return TokError("unexpected token in '.else' directive");
  
  Lex();

  if (TheCondState.TheCond != AsmCond::IfCond &&
      TheCondState.TheCond != AsmCond::ElseIfCond)
      Error(DirectiveLoc, "Encountered a .else that doesn't follow a .if or an "
                          ".elseif");
  TheCondState.TheCond = AsmCond::ElseCond;
  bool LastIgnoreState = false;
  if (!TheCondStack.empty())
    LastIgnoreState = TheCondStack.back().Ignore;
  if (LastIgnoreState || TheCondState.CondMet)
    TheCondState.Ignore = true;
  else
    TheCondState.Ignore = false;

  return false;
}

/// ParseDirectiveEndIf
/// ::= .endif
bool AsmParser::ParseDirectiveEndIf(SMLoc DirectiveLoc) {
  if (getLexer().isNot(AsmToken::EndOfStatement))
    return TokError("unexpected token in '.endif' directive");
  
  Lex();

  if ((TheCondState.TheCond == AsmCond::NoCond) ||
      TheCondStack.empty())
    Error(DirectiveLoc, "Encountered a .endif that doesn't follow a .if or "
                        ".else");
  if (!TheCondStack.empty()) {
    TheCondState = TheCondStack.back();
    TheCondStack.pop_back();
  }

  return false;
}

/// ParseDirectiveFile
/// ::= .file [number] string
bool GenericAsmParser::ParseDirectiveFile(StringRef, SMLoc DirectiveLoc) {
  // FIXME: I'm not sure what this is.
  int64_t FileNumber = -1;
  SMLoc FileNumberLoc = getLexer().getLoc();
  if (getLexer().is(AsmToken::Integer)) {
    FileNumber = getTok().getIntVal();
    Lex();

    if (FileNumber < 1)
      return TokError("file number less than one");
  }

  if (getLexer().isNot(AsmToken::String))
    return TokError("unexpected token in '.file' directive");

  StringRef Filename = getTok().getString();
  Filename = Filename.substr(1, Filename.size()-2);
  Lex();

  if (getLexer().isNot(AsmToken::EndOfStatement))
    return TokError("unexpected token in '.file' directive");

  if (FileNumber == -1)
    getStreamer().EmitFileDirective(Filename);
  else {
     if (getContext().GetDwarfFile(Filename, FileNumber) == 0)
	Error(FileNumberLoc, "file number already allocated");
    getStreamer().EmitDwarfFileDirective(FileNumber, Filename);
  }

  return false;
}

/// ParseDirectiveLine
/// ::= .line [number]
bool GenericAsmParser::ParseDirectiveLine(StringRef, SMLoc DirectiveLoc) {
  if (getLexer().isNot(AsmToken::EndOfStatement)) {
    if (getLexer().isNot(AsmToken::Integer))
      return TokError("unexpected token in '.line' directive");

    int64_t LineNumber = getTok().getIntVal();
    (void) LineNumber;
    Lex();

    // FIXME: Do something with the .line.
  }

  if (getLexer().isNot(AsmToken::EndOfStatement))
    return TokError("unexpected token in '.line' directive");

  return false;
}


/// ParseDirectiveLoc
/// ::= .loc FileNumber [LineNumber] [ColumnPos] [basic_block] [prologue_end]
///                                [epilogue_begin] [is_stmt VALUE] [isa VALUE]
/// The first number is a file number, must have been previously assigned with
/// a .file directive, the second number is the line number and optionally the
/// third number is a column position (zero if not specified).  The remaining
/// optional items are .loc sub-directives.
bool GenericAsmParser::ParseDirectiveLoc(StringRef, SMLoc DirectiveLoc) {

  if (getLexer().isNot(AsmToken::Integer))
    return TokError("unexpected token in '.loc' directive");
  int64_t FileNumber = getTok().getIntVal();
  if (FileNumber < 1)
    return TokError("file number less than one in '.loc' directive");
  if (!getContext().ValidateDwarfFileNumber(FileNumber))
    return TokError("unassigned file number in '.loc' directive");
  Lex();

  int64_t LineNumber = 0;
  if (getLexer().is(AsmToken::Integer)) {
    LineNumber = getTok().getIntVal();
    if (LineNumber < 1)
      return TokError("line number less than one in '.loc' directive");
    Lex();
  }

  int64_t ColumnPos = 0;
  if (getLexer().is(AsmToken::Integer)) {
    ColumnPos = getTok().getIntVal();
    if (ColumnPos < 0)
      return TokError("column position less than zero in '.loc' directive");
    Lex();
  }

  unsigned Flags = 0;
  unsigned Isa = 0;
  if (getLexer().isNot(AsmToken::EndOfStatement)) {
    for (;;) {
      if (getLexer().is(AsmToken::EndOfStatement))
        break;

      StringRef Name;
      SMLoc Loc = getTok().getLoc();
      if (getParser().ParseIdentifier(Name))
        return TokError("unexpected token in '.loc' directive");

      if (Name == "basic_block")
        Flags |= DWARF2_FLAG_BASIC_BLOCK;
      else if (Name == "prologue_end")
        Flags |= DWARF2_FLAG_PROLOGUE_END;
      else if (Name == "epilogue_begin")
        Flags |= DWARF2_FLAG_EPILOGUE_BEGIN;
      else if (Name == "is_stmt") {
        SMLoc Loc = getTok().getLoc();
        const MCExpr *Value;
        if (getParser().ParseExpression(Value))
          return true;
        // The expression must be the constant 0 or 1.
        if (const MCConstantExpr *MCE = dyn_cast<MCConstantExpr>(Value)) {
          int Value = MCE->getValue();
          if (Value == 0)
            Flags &= ~DWARF2_FLAG_IS_STMT;
          else if (Value == 1)
            Flags |= DWARF2_FLAG_IS_STMT;
          else
            return Error(Loc, "is_stmt value not 0 or 1");
	}
        else {
          return Error(Loc, "is_stmt value not the constant value of 0 or 1");
        }
      }
      else if (Name == "isa") {
        SMLoc Loc = getTok().getLoc();
        const MCExpr *Value;
        if (getParser().ParseExpression(Value))
          return true;
        // The expression must be a constant greater or equal to 0.
        if (const MCConstantExpr *MCE = dyn_cast<MCConstantExpr>(Value)) {
          int Value = MCE->getValue();
          if (Value < 0)
            return Error(Loc, "isa number less than zero");
          Isa = Value;
	}
        else {
          return Error(Loc, "isa number not a constant value");
        }
      }
      else {
        return Error(Loc, "unknown sub-directive in '.loc' directive");
      }

      if (getLexer().is(AsmToken::EndOfStatement))
        break;
    }
  }

  getContext().setCurrentDwarfLoc(FileNumber, LineNumber, ColumnPos, Flags,Isa);

  return false;
}

/// ParseDirectiveMacrosOnOff
/// ::= .macros_on
/// ::= .macros_off
bool GenericAsmParser::ParseDirectiveMacrosOnOff(StringRef Directive,
                                                 SMLoc DirectiveLoc) {
  if (getLexer().isNot(AsmToken::EndOfStatement))
    return Error(getLexer().getLoc(),
                 "unexpected token in '" + Directive + "' directive");

  getParser().MacrosEnabled = Directive == ".macros_on";

  return false;
}

/// ParseDirectiveMacro
/// ::= .macro name
bool GenericAsmParser::ParseDirectiveMacro(StringRef Directive,
                                           SMLoc DirectiveLoc) {
  StringRef Name;
  if (getParser().ParseIdentifier(Name))
    return TokError("expected identifier in directive");

  if (getLexer().isNot(AsmToken::EndOfStatement))
    return TokError("unexpected token in '.macro' directive");

  // Eat the end of statement.
  Lex();

  AsmToken EndToken, StartToken = getTok();

  // Lex the macro definition.
  for (;;) {
    // Check whether we have reached the end of the file.
    if (getLexer().is(AsmToken::Eof))
      return Error(DirectiveLoc, "no matching '.endmacro' in definition");

    // Otherwise, check whether we have reach the .endmacro.
    if (getLexer().is(AsmToken::Identifier) &&
        (getTok().getIdentifier() == ".endm" ||
         getTok().getIdentifier() == ".endmacro")) {
      EndToken = getTok();
      Lex();
      if (getLexer().isNot(AsmToken::EndOfStatement))
        return TokError("unexpected token in '" + EndToken.getIdentifier() +
                        "' directive");
      break;
    }

    // Otherwise, scan til the end of the statement.
    getParser().EatToEndOfStatement();
  }

  if (getParser().MacroMap.lookup(Name)) {
    return Error(DirectiveLoc, "macro '" + Name + "' is already defined");
  }

  const char *BodyStart = StartToken.getLoc().getPointer();
  const char *BodyEnd = EndToken.getLoc().getPointer();
  StringRef Body = StringRef(BodyStart, BodyEnd - BodyStart);
  getParser().MacroMap[Name] = new Macro(Name, Body);
  return false;
}

/// ParseDirectiveEndMacro
/// ::= .endm
/// ::= .endmacro
bool GenericAsmParser::ParseDirectiveEndMacro(StringRef Directive,
                                           SMLoc DirectiveLoc) {
  if (getLexer().isNot(AsmToken::EndOfStatement))
    return TokError("unexpected token in '" + Directive + "' directive");

  // If we are inside a macro instantiation, terminate the current
  // instantiation.
  if (!getParser().ActiveMacros.empty()) {
    getParser().HandleMacroExit();
    return false;
  }

  // Otherwise, this .endmacro is a stray entry in the file; well formed
  // .endmacro directives are handled during the macro definition parsing.
  return TokError("unexpected '" + Directive + "' in file, "
                  "no current macro definition");
}

/// \brief Create an MCAsmParser instance.
MCAsmParser *llvm::createMCAsmParser(const Target &T, SourceMgr &SM,
                                     MCContext &C, MCStreamer &Out,
                                     const MCAsmInfo &MAI) {
  return new AsmParser(T, SM, C, Out, MAI);
}
