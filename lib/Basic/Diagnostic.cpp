//===--- Diagnostic.cpp - C Language Family Diagnostic Handling -----------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
//  This file implements the Diagnostic-related interfaces.
//
//===----------------------------------------------------------------------===//

#include "clang/Basic/Diagnostic.h"

#include "clang/Lex/LexDiagnostic.h"
#include "clang/Parse/ParseDiagnostic.h"
#include "clang/AST/ASTDiagnostic.h"
#include "clang/Sema/SemaDiagnostic.h"
#include "clang/Frontend/FrontendDiagnostic.h"
#include "clang/Analysis/AnalysisDiagnostic.h"
#include "clang/Driver/DriverDiagnostic.h"

#include "clang/Basic/IdentifierTable.h"
#include "clang/Basic/SourceLocation.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/Support/raw_ostream.h"
#include <vector>
#include <map>
#include <cstring>
using namespace clang;

//===----------------------------------------------------------------------===//
// Builtin Diagnostic information
//===----------------------------------------------------------------------===//

// Diagnostic classes.
enum {
  CLASS_NOTE       = 0x01,
  CLASS_WARNING    = 0x02,
  CLASS_EXTENSION  = 0x03,
  CLASS_ERROR      = 0x04
};

struct StaticDiagInfoRec {
  unsigned short DiagID;
  unsigned Mapping : 3;
  unsigned Class : 3;
  bool SFINAE : 1;
  const char *Description;
  const char *OptionGroup;

  bool operator<(const StaticDiagInfoRec &RHS) const {
    return DiagID < RHS.DiagID;
  }
  bool operator>(const StaticDiagInfoRec &RHS) const {
    return DiagID > RHS.DiagID;
  }
};

static const StaticDiagInfoRec StaticDiagInfo[] = {
#define DIAG(ENUM,CLASS,DEFAULT_MAPPING,DESC,GROUP,SFINAE)    \
  { diag::ENUM, DEFAULT_MAPPING, CLASS, SFINAE, DESC, GROUP },
#include "clang/Basic/DiagnosticCommonKinds.inc"
#include "clang/Basic/DiagnosticDriverKinds.inc"
#include "clang/Basic/DiagnosticFrontendKinds.inc"
#include "clang/Basic/DiagnosticLexKinds.inc"
#include "clang/Basic/DiagnosticParseKinds.inc"
#include "clang/Basic/DiagnosticASTKinds.inc"
#include "clang/Basic/DiagnosticSemaKinds.inc"
#include "clang/Basic/DiagnosticAnalysisKinds.inc"
  { 0, 0, 0, 0, 0, 0}
};
#undef DIAG

/// GetDiagInfo - Return the StaticDiagInfoRec entry for the specified DiagID,
/// or null if the ID is invalid.
static const StaticDiagInfoRec *GetDiagInfo(unsigned DiagID) {
  unsigned NumDiagEntries = sizeof(StaticDiagInfo)/sizeof(StaticDiagInfo[0])-1;

  // If assertions are enabled, verify that the StaticDiagInfo array is sorted.
#ifndef NDEBUG
  static bool IsFirst = true;
  if (IsFirst) {
    for (unsigned i = 1; i != NumDiagEntries; ++i) {
      assert(StaticDiagInfo[i-1].DiagID != StaticDiagInfo[i].DiagID &&
             "Diag ID conflict, the enums at the start of clang::diag (in "
             "Diagnostic.h) probably need to be increased");

      assert(StaticDiagInfo[i-1] < StaticDiagInfo[i] &&
             "Improperly sorted diag info");
    }
    IsFirst = false;
  }
#endif

  // Search the diagnostic table with a binary search.
  StaticDiagInfoRec Find = { DiagID, 0, 0, 0, 0, 0 };

  const StaticDiagInfoRec *Found =
    std::lower_bound(StaticDiagInfo, StaticDiagInfo + NumDiagEntries, Find);
  if (Found == StaticDiagInfo + NumDiagEntries ||
      Found->DiagID != DiagID)
    return 0;

  return Found;
}

static unsigned GetDefaultDiagMapping(unsigned DiagID) {
  if (const StaticDiagInfoRec *Info = GetDiagInfo(DiagID))
    return Info->Mapping;
  return diag::MAP_FATAL;
}

/// getWarningOptionForDiag - Return the lowest-level warning option that
/// enables the specified diagnostic.  If there is no -Wfoo flag that controls
/// the diagnostic, this returns null.
const char *Diagnostic::getWarningOptionForDiag(unsigned DiagID) {
  if (const StaticDiagInfoRec *Info = GetDiagInfo(DiagID))
    return Info->OptionGroup;
  return 0;
}

bool Diagnostic::isBuiltinSFINAEDiag(unsigned DiagID) {
  if (const StaticDiagInfoRec *Info = GetDiagInfo(DiagID))
    return Info->SFINAE && Info->Class == CLASS_ERROR;
  return false;
}

/// getDiagClass - Return the class field of the diagnostic.
///
static unsigned getBuiltinDiagClass(unsigned DiagID) {
  if (const StaticDiagInfoRec *Info = GetDiagInfo(DiagID))
    return Info->Class;
  return ~0U;
}

//===----------------------------------------------------------------------===//
// Custom Diagnostic information
//===----------------------------------------------------------------------===//

namespace clang {
  namespace diag {
    class CustomDiagInfo {
      typedef std::pair<Diagnostic::Level, std::string> DiagDesc;
      std::vector<DiagDesc> DiagInfo;
      std::map<DiagDesc, unsigned> DiagIDs;
    public:

      /// getDescription - Return the description of the specified custom
      /// diagnostic.
      const char *getDescription(unsigned DiagID) const {
        assert(this && DiagID-DIAG_UPPER_LIMIT < DiagInfo.size() &&
               "Invalid diagnosic ID");
        return DiagInfo[DiagID-DIAG_UPPER_LIMIT].second.c_str();
      }

      /// getLevel - Return the level of the specified custom diagnostic.
      Diagnostic::Level getLevel(unsigned DiagID) const {
        assert(this && DiagID-DIAG_UPPER_LIMIT < DiagInfo.size() &&
               "Invalid diagnosic ID");
        return DiagInfo[DiagID-DIAG_UPPER_LIMIT].first;
      }

      unsigned getOrCreateDiagID(Diagnostic::Level L, llvm::StringRef Message,
                                 Diagnostic &Diags) {
        DiagDesc D(L, Message);
        // Check to see if it already exists.
        std::map<DiagDesc, unsigned>::iterator I = DiagIDs.lower_bound(D);
        if (I != DiagIDs.end() && I->first == D)
          return I->second;

        // If not, assign a new ID.
        unsigned ID = DiagInfo.size()+DIAG_UPPER_LIMIT;
        DiagIDs.insert(std::make_pair(D, ID));
        DiagInfo.push_back(D);
        return ID;
      }
    };

  } // end diag namespace
} // end clang namespace


//===----------------------------------------------------------------------===//
// Common Diagnostic implementation
//===----------------------------------------------------------------------===//

static void DummyArgToStringFn(Diagnostic::ArgumentKind AK, intptr_t QT,
                               const char *Modifier, unsigned ML,
                               const char *Argument, unsigned ArgLen,
                               const Diagnostic::ArgumentValue *PrevArgs,
                               unsigned NumPrevArgs,
                               llvm::SmallVectorImpl<char> &Output,
                               void *Cookie) {
  const char *Str = "<can't format argument>";
  Output.append(Str, Str+strlen(Str));
}


Diagnostic::Diagnostic(DiagnosticClient *client) : Client(client) {
  AllExtensionsSilenced = 0;
  IgnoreAllWarnings = false;
  WarningsAsErrors = false;
  SuppressSystemWarnings = false;
  SuppressAllDiagnostics = false;
  ExtBehavior = Ext_Ignore;

  ErrorOccurred = false;
  FatalErrorOccurred = false;
  NumDiagnostics = 0;

  NumErrors = 0;
  CustomDiagInfo = 0;
  CurDiagID = ~0U;
  LastDiagLevel = Ignored;

  ArgToStringFn = DummyArgToStringFn;
  ArgToStringCookie = 0;

  // Set all mappings to 'unset'.
  DiagMappings BlankDiags(diag::DIAG_UPPER_LIMIT/2, 0);
  DiagMappingsStack.push_back(BlankDiags);
}

Diagnostic::~Diagnostic() {
  delete CustomDiagInfo;
}


void Diagnostic::pushMappings() {
  // Avoids undefined behavior when the stack has to resize.
  DiagMappingsStack.reserve(DiagMappingsStack.size() + 1);
  DiagMappingsStack.push_back(DiagMappingsStack.back());
}

bool Diagnostic::popMappings() {
  if (DiagMappingsStack.size() == 1)
    return false;

  DiagMappingsStack.pop_back();
  return true;
}

/// getCustomDiagID - Return an ID for a diagnostic with the specified message
/// and level.  If this is the first request for this diagnosic, it is
/// registered and created, otherwise the existing ID is returned.
unsigned Diagnostic::getCustomDiagID(Level L, llvm::StringRef Message) {
  if (CustomDiagInfo == 0)
    CustomDiagInfo = new diag::CustomDiagInfo();
  return CustomDiagInfo->getOrCreateDiagID(L, Message, *this);
}


/// isBuiltinWarningOrExtension - Return true if the unmapped diagnostic
/// level of the specified diagnostic ID is a Warning or Extension.
/// This only works on builtin diagnostics, not custom ones, and is not legal to
/// call on NOTEs.
bool Diagnostic::isBuiltinWarningOrExtension(unsigned DiagID) {
  return DiagID < diag::DIAG_UPPER_LIMIT &&
         getBuiltinDiagClass(DiagID) != CLASS_ERROR;
}

/// \brief Determine whether the given built-in diagnostic ID is a
/// Note.
bool Diagnostic::isBuiltinNote(unsigned DiagID) {
  return DiagID < diag::DIAG_UPPER_LIMIT &&
    getBuiltinDiagClass(DiagID) == CLASS_NOTE;
}

/// isBuiltinExtensionDiag - Determine whether the given built-in diagnostic
/// ID is for an extension of some sort.
///
bool Diagnostic::isBuiltinExtensionDiag(unsigned DiagID) {
  return DiagID < diag::DIAG_UPPER_LIMIT &&
         getBuiltinDiagClass(DiagID) == CLASS_EXTENSION;
}


/// getDescription - Given a diagnostic ID, return a description of the
/// issue.
const char *Diagnostic::getDescription(unsigned DiagID) const {
  if (const StaticDiagInfoRec *Info = GetDiagInfo(DiagID))
    return Info->Description;
  return CustomDiagInfo->getDescription(DiagID);
}

/// getDiagnosticLevel - Based on the way the client configured the Diagnostic
/// object, classify the specified diagnostic ID into a Level, consumable by
/// the DiagnosticClient.
Diagnostic::Level Diagnostic::getDiagnosticLevel(unsigned DiagID) const {
  // Handle custom diagnostics, which cannot be mapped.
  if (DiagID >= diag::DIAG_UPPER_LIMIT)
    return CustomDiagInfo->getLevel(DiagID);

  unsigned DiagClass = getBuiltinDiagClass(DiagID);
  assert(DiagClass != CLASS_NOTE && "Cannot get diagnostic level of a note!");
  return getDiagnosticLevel(DiagID, DiagClass);
}

/// getDiagnosticLevel - Based on the way the client configured the Diagnostic
/// object, classify the specified diagnostic ID into a Level, consumable by
/// the DiagnosticClient.
Diagnostic::Level
Diagnostic::getDiagnosticLevel(unsigned DiagID, unsigned DiagClass) const {
  // Specific non-error diagnostics may be mapped to various levels from ignored
  // to error.  Errors can only be mapped to fatal.
  Diagnostic::Level Result = Diagnostic::Fatal;

  // Get the mapping information, if unset, compute it lazily.
  unsigned MappingInfo = getDiagnosticMappingInfo((diag::kind)DiagID);
  if (MappingInfo == 0) {
    MappingInfo = GetDefaultDiagMapping(DiagID);
    setDiagnosticMappingInternal(DiagID, MappingInfo, false);
  }

  switch (MappingInfo & 7) {
  default: assert(0 && "Unknown mapping!");
  case diag::MAP_IGNORE:
    // Ignore this, unless this is an extension diagnostic and we're mapping
    // them onto warnings or errors.
    if (!isBuiltinExtensionDiag(DiagID) ||  // Not an extension
        ExtBehavior == Ext_Ignore ||        // Extensions ignored anyway
        (MappingInfo & 8) != 0)             // User explicitly mapped it.
      return Diagnostic::Ignored;
    Result = Diagnostic::Warning;
    if (ExtBehavior == Ext_Error) Result = Diagnostic::Error;
    break;
  case diag::MAP_ERROR:
    Result = Diagnostic::Error;
    break;
  case diag::MAP_FATAL:
    Result = Diagnostic::Fatal;
    break;
  case diag::MAP_WARNING:
    // If warnings are globally mapped to ignore or error, do it.
    if (IgnoreAllWarnings)
      return Diagnostic::Ignored;

    Result = Diagnostic::Warning;

    // If this is an extension diagnostic and we're in -pedantic-error mode, and
    // if the user didn't explicitly map it, upgrade to an error.
    if (ExtBehavior == Ext_Error &&
        (MappingInfo & 8) == 0 &&
        isBuiltinExtensionDiag(DiagID))
      Result = Diagnostic::Error;

    if (WarningsAsErrors)
      Result = Diagnostic::Error;
    break;

  case diag::MAP_WARNING_NO_WERROR:
    // Diagnostics specified with -Wno-error=foo should be set to warnings, but
    // not be adjusted by -Werror or -pedantic-errors.
    Result = Diagnostic::Warning;

    // If warnings are globally mapped to ignore or error, do it.
    if (IgnoreAllWarnings)
      return Diagnostic::Ignored;

    break;
  }

  // Okay, we're about to return this as a "diagnostic to emit" one last check:
  // if this is any sort of extension warning, and if we're in an __extension__
  // block, silence it.
  if (AllExtensionsSilenced && isBuiltinExtensionDiag(DiagID))
    return Diagnostic::Ignored;

  return Result;
}

struct WarningOption {
  const char  *Name;
  const short *Members;
  const char  *SubGroups;
};

#define GET_DIAG_ARRAYS
#include "clang/Basic/DiagnosticGroups.inc"
#undef GET_DIAG_ARRAYS

// Second the table of options, sorted by name for fast binary lookup.
static const WarningOption OptionTable[] = {
#define GET_DIAG_TABLE
#include "clang/Basic/DiagnosticGroups.inc"
#undef GET_DIAG_TABLE
};
static const size_t OptionTableSize =
sizeof(OptionTable) / sizeof(OptionTable[0]);

static bool WarningOptionCompare(const WarningOption &LHS,
                                 const WarningOption &RHS) {
  return strcmp(LHS.Name, RHS.Name) < 0;
}

static void MapGroupMembers(const WarningOption *Group, diag::Mapping Mapping,
                            Diagnostic &Diags) {
  // Option exists, poke all the members of its diagnostic set.
  if (const short *Member = Group->Members) {
    for (; *Member != -1; ++Member)
      Diags.setDiagnosticMapping(*Member, Mapping);
  }

  // Enable/disable all subgroups along with this one.
  if (const char *SubGroups = Group->SubGroups) {
    for (; *SubGroups != (char)-1; ++SubGroups)
      MapGroupMembers(&OptionTable[(unsigned char)*SubGroups], Mapping, Diags);
  }
}

/// setDiagnosticGroupMapping - Change an entire diagnostic group (e.g.
/// "unknown-pragmas" to have the specified mapping.  This returns true and
/// ignores the request if "Group" was unknown, false otherwise.
bool Diagnostic::setDiagnosticGroupMapping(const char *Group,
                                           diag::Mapping Map) {

  WarningOption Key = { Group, 0, 0 };
  const WarningOption *Found =
  std::lower_bound(OptionTable, OptionTable + OptionTableSize, Key,
                   WarningOptionCompare);
  if (Found == OptionTable + OptionTableSize ||
      strcmp(Found->Name, Group) != 0)
    return true;  // Option not found.

  MapGroupMembers(Found, Map, *this);
  return false;
}


/// ProcessDiag - This is the method used to report a diagnostic that is
/// finally fully formed.
bool Diagnostic::ProcessDiag() {
  DiagnosticInfo Info(this);

  if (SuppressAllDiagnostics)
    return false;
  
  // Figure out the diagnostic level of this message.
  Diagnostic::Level DiagLevel;
  unsigned DiagID = Info.getID();

  // ShouldEmitInSystemHeader - True if this diagnostic should be produced even
  // in a system header.
  bool ShouldEmitInSystemHeader;

  if (DiagID >= diag::DIAG_UPPER_LIMIT) {
    // Handle custom diagnostics, which cannot be mapped.
    DiagLevel = CustomDiagInfo->getLevel(DiagID);

    // Custom diagnostics always are emitted in system headers.
    ShouldEmitInSystemHeader = true;
  } else {
    // Get the class of the diagnostic.  If this is a NOTE, map it onto whatever
    // the diagnostic level was for the previous diagnostic so that it is
    // filtered the same as the previous diagnostic.
    unsigned DiagClass = getBuiltinDiagClass(DiagID);
    if (DiagClass == CLASS_NOTE) {
      DiagLevel = Diagnostic::Note;
      ShouldEmitInSystemHeader = false;  // extra consideration is needed
    } else {
      // If this is not an error and we are in a system header, we ignore it.
      // Check the original Diag ID here, because we also want to ignore
      // extensions and warnings in -Werror and -pedantic-errors modes, which
      // *map* warnings/extensions to errors.
      ShouldEmitInSystemHeader = DiagClass == CLASS_ERROR;

      DiagLevel = getDiagnosticLevel(DiagID, DiagClass);
    }
  }

  if (DiagLevel != Diagnostic::Note) {
    // Record that a fatal error occurred only when we see a second
    // non-note diagnostic. This allows notes to be attached to the
    // fatal error, but suppresses any diagnostics that follow those
    // notes.
    if (LastDiagLevel == Diagnostic::Fatal)
      FatalErrorOccurred = true;

    LastDiagLevel = DiagLevel;
  }

  // If a fatal error has already been emitted, silence all subsequent
  // diagnostics.
  if (FatalErrorOccurred)
    return false;

  // If the client doesn't care about this message, don't issue it.  If this is
  // a note and the last real diagnostic was ignored, ignore it too.
  if (DiagLevel == Diagnostic::Ignored ||
      (DiagLevel == Diagnostic::Note && LastDiagLevel == Diagnostic::Ignored))
    return false;

  // If this diagnostic is in a system header and is not a clang error, suppress
  // it.
  if (SuppressSystemWarnings && !ShouldEmitInSystemHeader &&
      Info.getLocation().isValid() &&
      Info.getLocation().getSpellingLoc().isInSystemHeader() &&
      (DiagLevel != Diagnostic::Note || LastDiagLevel == Diagnostic::Ignored)) {
    LastDiagLevel = Diagnostic::Ignored;
    return false;
  }

  if (DiagLevel >= Diagnostic::Error) {
    ErrorOccurred = true;
    ++NumErrors;
  }

  // Finally, report it.
  Client->HandleDiagnostic(DiagLevel, Info);
  if (Client->IncludeInDiagnosticCounts()) ++NumDiagnostics;

  CurDiagID = ~0U;

  return true;
}


DiagnosticClient::~DiagnosticClient() {}


/// ModifierIs - Return true if the specified modifier matches specified string.
template <std::size_t StrLen>
static bool ModifierIs(const char *Modifier, unsigned ModifierLen,
                       const char (&Str)[StrLen]) {
  return StrLen-1 == ModifierLen && !memcmp(Modifier, Str, StrLen-1);
}

/// HandleSelectModifier - Handle the integer 'select' modifier.  This is used
/// like this:  %select{foo|bar|baz}2.  This means that the integer argument
/// "%2" has a value from 0-2.  If the value is 0, the diagnostic prints 'foo'.
/// If the value is 1, it prints 'bar'.  If it has the value 2, it prints 'baz'.
/// This is very useful for certain classes of variant diagnostics.
static void HandleSelectModifier(unsigned ValNo,
                                 const char *Argument, unsigned ArgumentLen,
                                 llvm::SmallVectorImpl<char> &OutStr) {
  const char *ArgumentEnd = Argument+ArgumentLen;

  // Skip over 'ValNo' |'s.
  while (ValNo) {
    const char *NextVal = std::find(Argument, ArgumentEnd, '|');
    assert(NextVal != ArgumentEnd && "Value for integer select modifier was"
           " larger than the number of options in the diagnostic string!");
    Argument = NextVal+1;  // Skip this string.
    --ValNo;
  }

  // Get the end of the value.  This is either the } or the |.
  const char *EndPtr = std::find(Argument, ArgumentEnd, '|');
  // Add the value to the output string.
  OutStr.append(Argument, EndPtr);
}

/// HandleIntegerSModifier - Handle the integer 's' modifier.  This adds the
/// letter 's' to the string if the value is not 1.  This is used in cases like
/// this:  "you idiot, you have %4 parameter%s4!".
static void HandleIntegerSModifier(unsigned ValNo,
                                   llvm::SmallVectorImpl<char> &OutStr) {
  if (ValNo != 1)
    OutStr.push_back('s');
}


/// PluralNumber - Parse an unsigned integer and advance Start.
static unsigned PluralNumber(const char *&Start, const char *End) {
  // Programming 101: Parse a decimal number :-)
  unsigned Val = 0;
  while (Start != End && *Start >= '0' && *Start <= '9') {
    Val *= 10;
    Val += *Start - '0';
    ++Start;
  }
  return Val;
}

/// TestPluralRange - Test if Val is in the parsed range. Modifies Start.
static bool TestPluralRange(unsigned Val, const char *&Start, const char *End) {
  if (*Start != '[') {
    unsigned Ref = PluralNumber(Start, End);
    return Ref == Val;
  }

  ++Start;
  unsigned Low = PluralNumber(Start, End);
  assert(*Start == ',' && "Bad plural expression syntax: expected ,");
  ++Start;
  unsigned High = PluralNumber(Start, End);
  assert(*Start == ']' && "Bad plural expression syntax: expected )");
  ++Start;
  return Low <= Val && Val <= High;
}

/// EvalPluralExpr - Actual expression evaluator for HandlePluralModifier.
static bool EvalPluralExpr(unsigned ValNo, const char *Start, const char *End) {
  // Empty condition?
  if (*Start == ':')
    return true;

  while (1) {
    char C = *Start;
    if (C == '%') {
      // Modulo expression
      ++Start;
      unsigned Arg = PluralNumber(Start, End);
      assert(*Start == '=' && "Bad plural expression syntax: expected =");
      ++Start;
      unsigned ValMod = ValNo % Arg;
      if (TestPluralRange(ValMod, Start, End))
        return true;
    } else {
      assert((C == '[' || (C >= '0' && C <= '9')) &&
             "Bad plural expression syntax: unexpected character");
      // Range expression
      if (TestPluralRange(ValNo, Start, End))
        return true;
    }

    // Scan for next or-expr part.
    Start = std::find(Start, End, ',');
    if (Start == End)
      break;
    ++Start;
  }
  return false;
}

/// HandlePluralModifier - Handle the integer 'plural' modifier. This is used
/// for complex plural forms, or in languages where all plurals are complex.
/// The syntax is: %plural{cond1:form1|cond2:form2|:form3}, where condn are
/// conditions that are tested in order, the form corresponding to the first
/// that applies being emitted. The empty condition is always true, making the
/// last form a default case.
/// Conditions are simple boolean expressions, where n is the number argument.
/// Here are the rules.
/// condition  := expression | empty
/// empty      :=                             -> always true
/// expression := numeric [',' expression]    -> logical or
/// numeric    := range                       -> true if n in range
///             | '%' number '=' range        -> true if n % number in range
/// range      := number
///             | '[' number ',' number ']'   -> ranges are inclusive both ends
///
/// Here are some examples from the GNU gettext manual written in this form:
/// English:
/// {1:form0|:form1}
/// Latvian:
/// {0:form2|%100=11,%10=0,%10=[2,9]:form1|:form0}
/// Gaeilge:
/// {1:form0|2:form1|:form2}
/// Romanian:
/// {1:form0|0,%100=[1,19]:form1|:form2}
/// Lithuanian:
/// {%10=0,%100=[10,19]:form2|%10=1:form0|:form1}
/// Russian (requires repeated form):
/// {%100=[11,14]:form2|%10=1:form0|%10=[2,4]:form1|:form2}
/// Slovak
/// {1:form0|[2,4]:form1|:form2}
/// Polish (requires repeated form):
/// {1:form0|%100=[10,20]:form2|%10=[2,4]:form1|:form2}
static void HandlePluralModifier(unsigned ValNo,
                                 const char *Argument, unsigned ArgumentLen,
                                 llvm::SmallVectorImpl<char> &OutStr) {
  const char *ArgumentEnd = Argument + ArgumentLen;
  while (1) {
    assert(Argument < ArgumentEnd && "Plural expression didn't match.");
    const char *ExprEnd = Argument;
    while (*ExprEnd != ':') {
      assert(ExprEnd != ArgumentEnd && "Plural missing expression end");
      ++ExprEnd;
    }
    if (EvalPluralExpr(ValNo, Argument, ExprEnd)) {
      Argument = ExprEnd + 1;
      ExprEnd = std::find(Argument, ArgumentEnd, '|');
      OutStr.append(Argument, ExprEnd);
      return;
    }
    Argument = std::find(Argument, ArgumentEnd - 1, '|') + 1;
  }
}


/// FormatDiagnostic - Format this diagnostic into a string, substituting the
/// formal arguments into the %0 slots.  The result is appended onto the Str
/// array.
void DiagnosticInfo::
FormatDiagnostic(llvm::SmallVectorImpl<char> &OutStr) const {
  const char *DiagStr = getDiags()->getDescription(getID());
  const char *DiagEnd = DiagStr+strlen(DiagStr);

  /// FormattedArgs - Keep track of all of the arguments formatted by
  /// ConvertArgToString and pass them into subsequent calls to
  /// ConvertArgToString, allowing the implementation to avoid redundancies in
  /// obvious cases.
  llvm::SmallVector<Diagnostic::ArgumentValue, 8> FormattedArgs;
  
  while (DiagStr != DiagEnd) {
    if (DiagStr[0] != '%') {
      // Append non-%0 substrings to Str if we have one.
      const char *StrEnd = std::find(DiagStr, DiagEnd, '%');
      OutStr.append(DiagStr, StrEnd);
      DiagStr = StrEnd;
      continue;
    } else if (DiagStr[1] == '%') {
      OutStr.push_back('%');  // %% -> %.
      DiagStr += 2;
      continue;
    }

    // Skip the %.
    ++DiagStr;

    // This must be a placeholder for a diagnostic argument.  The format for a
    // placeholder is one of "%0", "%modifier0", or "%modifier{arguments}0".
    // The digit is a number from 0-9 indicating which argument this comes from.
    // The modifier is a string of digits from the set [-a-z]+, arguments is a
    // brace enclosed string.
    const char *Modifier = 0, *Argument = 0;
    unsigned ModifierLen = 0, ArgumentLen = 0;

    // Check to see if we have a modifier.  If so eat it.
    if (!isdigit(DiagStr[0])) {
      Modifier = DiagStr;
      while (DiagStr[0] == '-' ||
             (DiagStr[0] >= 'a' && DiagStr[0] <= 'z'))
        ++DiagStr;
      ModifierLen = DiagStr-Modifier;

      // If we have an argument, get it next.
      if (DiagStr[0] == '{') {
        ++DiagStr; // Skip {.
        Argument = DiagStr;

        for (; DiagStr[0] != '}'; ++DiagStr)
          assert(DiagStr[0] && "Mismatched {}'s in diagnostic string!");
        ArgumentLen = DiagStr-Argument;
        ++DiagStr;  // Skip }.
      }
    }

    assert(isdigit(*DiagStr) && "Invalid format for argument in diagnostic");
    unsigned ArgNo = *DiagStr++ - '0';

    Diagnostic::ArgumentKind Kind = getArgKind(ArgNo);
    
    switch (Kind) {
    // ---- STRINGS ----
    case Diagnostic::ak_std_string: {
      const std::string &S = getArgStdStr(ArgNo);
      assert(ModifierLen == 0 && "No modifiers for strings yet");
      OutStr.append(S.begin(), S.end());
      break;
    }
    case Diagnostic::ak_c_string: {
      const char *S = getArgCStr(ArgNo);
      assert(ModifierLen == 0 && "No modifiers for strings yet");

      // Don't crash if get passed a null pointer by accident.
      if (!S)
        S = "(null)";

      OutStr.append(S, S + strlen(S));
      break;
    }
    // ---- INTEGERS ----
    case Diagnostic::ak_sint: {
      int Val = getArgSInt(ArgNo);

      if (ModifierIs(Modifier, ModifierLen, "select")) {
        HandleSelectModifier((unsigned)Val, Argument, ArgumentLen, OutStr);
      } else if (ModifierIs(Modifier, ModifierLen, "s")) {
        HandleIntegerSModifier(Val, OutStr);
      } else if (ModifierIs(Modifier, ModifierLen, "plural")) {
        HandlePluralModifier((unsigned)Val, Argument, ArgumentLen, OutStr);
      } else {
        assert(ModifierLen == 0 && "Unknown integer modifier");
        llvm::raw_svector_ostream(OutStr) << Val;
      }
      break;
    }
    case Diagnostic::ak_uint: {
      unsigned Val = getArgUInt(ArgNo);

      if (ModifierIs(Modifier, ModifierLen, "select")) {
        HandleSelectModifier(Val, Argument, ArgumentLen, OutStr);
      } else if (ModifierIs(Modifier, ModifierLen, "s")) {
        HandleIntegerSModifier(Val, OutStr);
      } else if (ModifierIs(Modifier, ModifierLen, "plural")) {
        HandlePluralModifier((unsigned)Val, Argument, ArgumentLen, OutStr);
      } else {
        assert(ModifierLen == 0 && "Unknown integer modifier");
        llvm::raw_svector_ostream(OutStr) << Val;
      }
      break;
    }
    // ---- NAMES and TYPES ----
    case Diagnostic::ak_identifierinfo: {
      const IdentifierInfo *II = getArgIdentifier(ArgNo);
      assert(ModifierLen == 0 && "No modifiers for strings yet");

      // Don't crash if get passed a null pointer by accident.
      if (!II) {
        const char *S = "(null)";
        OutStr.append(S, S + strlen(S));
        continue;
      }

      llvm::raw_svector_ostream(OutStr) << '\'' << II->getName() << '\'';
      break;
    }
    case Diagnostic::ak_qualtype:
    case Diagnostic::ak_declarationname:
    case Diagnostic::ak_nameddecl:
    case Diagnostic::ak_nestednamespec:
    case Diagnostic::ak_declcontext:
      getDiags()->ConvertArgToString(Kind, getRawArg(ArgNo),
                                     Modifier, ModifierLen,
                                     Argument, ArgumentLen,
                                     FormattedArgs.data(), FormattedArgs.size(),
                                     OutStr);
      break;
    }
    
    // Remember this argument info for subsequent formatting operations.  Turn
    // std::strings into a null terminated string to make it be the same case as
    // all the other ones.
    if (Kind != Diagnostic::ak_std_string)
      FormattedArgs.push_back(std::make_pair(Kind, getRawArg(ArgNo)));
    else
      FormattedArgs.push_back(std::make_pair(Diagnostic::ak_c_string,
                                        (intptr_t)getArgStdStr(ArgNo).c_str()));
    
  }
}

/// IncludeInDiagnosticCounts - This method (whose default implementation
///  returns true) indicates whether the diagnostics handled by this
///  DiagnosticClient should be included in the number of diagnostics
///  reported by Diagnostic.
bool DiagnosticClient::IncludeInDiagnosticCounts() const { return true; }
