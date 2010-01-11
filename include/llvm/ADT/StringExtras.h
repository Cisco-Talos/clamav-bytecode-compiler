//===-- llvm/ADT/StringExtras.h - Useful string functions -------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains some functions that are useful when dealing with strings.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_ADT_STRINGEXTRAS_H
#define LLVM_ADT_STRINGEXTRAS_H

#include "llvm/System/DataTypes.h"
#include "llvm/ADT/APFloat.h"
#include "llvm/ADT/StringRef.h"
#include <cctype>
#include <cstdio>
#include <string>

namespace llvm {
template<typename T> class SmallVectorImpl;

/// hexdigit - Return the (uppercase) hexadecimal character for the
/// given number \arg X (which should be less than 16).
static inline char hexdigit(unsigned X) {
  return X < 10 ? '0' + X : 'A' + X - 10;
}

/// utohex_buffer - Emit the specified number into the buffer specified by
/// BufferEnd, returning a pointer to the start of the string.  This can be used
/// like this: (note that the buffer must be large enough to handle any number):
///    char Buffer[40];
///    printf("0x%s", utohex_buffer(X, Buffer+40));
///
/// This should only be used with unsigned types.
///
template<typename IntTy>
static inline char *utohex_buffer(IntTy X, char *BufferEnd) {
  char *BufPtr = BufferEnd;
  *--BufPtr = 0;      // Null terminate buffer.
  if (X == 0) {
    *--BufPtr = '0';  // Handle special case.
    return BufPtr;
  }

  while (X) {
    unsigned char Mod = static_cast<unsigned char>(X) & 15;
    *--BufPtr = hexdigit(Mod);
    X >>= 4;
  }
  return BufPtr;
}

static inline std::string utohexstr(uint64_t X) {
  char Buffer[40];
  return utohex_buffer(X, Buffer+40);
}

static inline std::string utostr_32(uint32_t X, bool isNeg = false) {
  char Buffer[20];
  char *BufPtr = Buffer+19;

  *BufPtr = 0;                  // Null terminate buffer...
  if (X == 0) *--BufPtr = '0';  // Handle special case...

  while (X) {
    *--BufPtr = '0' + char(X % 10);
    X /= 10;
  }

  if (isNeg) *--BufPtr = '-';   // Add negative sign...

  return std::string(BufPtr);
}

static inline std::string utostr(uint64_t X, bool isNeg = false) {
  if (X == uint32_t(X))
    return utostr_32(uint32_t(X), isNeg);

  char Buffer[40];
  char *BufPtr = Buffer+39;

  *BufPtr = 0;                  // Null terminate buffer...
  if (X == 0) *--BufPtr = '0';  // Handle special case...

  while (X) {
    *--BufPtr = '0' + char(X % 10);
    X /= 10;
  }

  if (isNeg) *--BufPtr = '-';   // Add negative sign...
  return std::string(BufPtr);
}


static inline std::string itostr(int64_t X) {
  if (X < 0)
    return utostr(static_cast<uint64_t>(-X), true);
  else
    return utostr(static_cast<uint64_t>(X));
}

static inline std::string ftostr(double V) {
  char Buffer[200];
  sprintf(Buffer, "%20.6e", V);
  char *B = Buffer;
  while (*B == ' ') ++B;
  return B;
}

static inline std::string ftostr(const APFloat& V) {
  if (&V.getSemantics() == &APFloat::IEEEdouble)
    return ftostr(V.convertToDouble());
  else if (&V.getSemantics() == &APFloat::IEEEsingle)
    return ftostr((double)V.convertToFloat());
  return "<unknown format in ftostr>"; // error
}

static inline std::string LowercaseString(const std::string &S) {
  std::string result(S);
  for (unsigned i = 0; i < S.length(); ++i)
    if (isupper(result[i]))
      result[i] = char(tolower(result[i]));
  return result;
}

static inline std::string UppercaseString(const std::string &S) {
  std::string result(S);
  for (unsigned i = 0; i < S.length(); ++i)
    if (islower(result[i]))
      result[i] = char(toupper(result[i]));
  return result;
}

/// StringsEqualNoCase - Return true if the two strings are equal, ignoring
/// case.
static inline bool StringsEqualNoCase(const std::string &LHS,
                                      const std::string &RHS) {
  if (LHS.size() != RHS.size()) return false;
  for (unsigned i = 0, e = static_cast<unsigned>(LHS.size()); i != e; ++i)
    if (tolower(LHS[i]) != tolower(RHS[i])) return false;
  return true;
}

/// StringsEqualNoCase - Return true if the two strings are equal, ignoring
/// case.
static inline bool StringsEqualNoCase(const std::string &LHS,
                                      const char *RHS) {
  for (unsigned i = 0, e = static_cast<unsigned>(LHS.size()); i != e; ++i) {
    if (RHS[i] == 0) return false;  // RHS too short.
    if (tolower(LHS[i]) != tolower(RHS[i])) return false;
  }
  return RHS[LHS.size()] == 0;  // Not too long?
}
  
/// StringsEqualNoCase - Return true if the two null-terminated C strings are
///  equal, ignoring

static inline bool StringsEqualNoCase(const char *LHS, const char *RHS,
                                      unsigned len) {

  for (unsigned i = 0; i < len; ++i) {
    if (tolower(LHS[i]) != tolower(RHS[i]))
      return false;
    
    // If RHS[i] == 0 then LHS[i] == 0 or otherwise we would have returned
    // at the previous branch as tolower('\0') == '\0'.
    if (RHS[i] == 0)
      return true;
  }
  
  return true;
}

/// CStrInCStrNoCase - Portable version of strcasestr.  Locates the first
///  occurance of c-string 's2' in string 's1', ignoring case.  Returns
///  NULL if 's2' cannot be found.
static inline const char* CStrInCStrNoCase(const char *s1, const char *s2) {

  // Are either strings NULL or empty?
  if (!s1 || !s2 || s1[0] == '\0' || s2[0] == '\0')
    return 0;

  if (s1 == s2)
    return s1;

  const char *I1=s1, *I2=s2;

  while (*I1 != '\0' && *I2 != '\0' )
    if (tolower(*I1) != tolower(*I2)) { // No match.  Start over.
      ++s1; I1 = s1; I2 = s2;
    }
    else { // Character match.  Advance to the next character.
      ++I1; ++I2;
    }

  // If we exhausted all of the characters in 's2', then 's2' appears in 's1'.
  return *I2 == '\0' ? s1 : 0;
}

/// getToken - This function extracts one token from source, ignoring any
/// leading characters that appear in the Delimiters string, and ending the
/// token at any of the characters that appear in the Delimiters string.  If
/// there are no tokens in the source string, an empty string is returned.
/// The function returns a pair containing the extracted token and the
/// remaining tail string.
std::pair<StringRef, StringRef> getToken(StringRef Source,
                                         StringRef Delimiters = " \t\n\v\f\r");

/// SplitString - Split up the specified string according to the specified
/// delimiters, appending the result fragments to the output list.
void SplitString(StringRef Source,
                 SmallVectorImpl<StringRef> &OutFragments,
                 StringRef Delimiters = " \t\n\v\f\r");

/// HashString - Hash funtion for strings.
///
/// This is the Bernstein hash function.
//
// FIXME: Investigate whether a modified bernstein hash function performs
// better: http://eternallyconfuzzled.com/tuts/algorithms/jsw_tut_hashing.aspx
//   X*33+c -> X*33^c
static inline unsigned HashString(StringRef Str, unsigned Result = 0) {
  for (unsigned i = 0, e = Str.size(); i != e; ++i)
    Result = Result * 33 + Str[i];
  return Result;
}

} // End llvm namespace

#endif
