//===-- Regex.h - Regular Expression matcher implementation -*- C++ -*-----===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements a POSIX regular expression matcher.
//
//===----------------------------------------------------------------------===//

#include <string>

struct llvm_regex;

namespace llvm {
  class StringRef;
  template<typename T> class SmallVectorImpl;
  
  class Regex {
  public:
    enum {
      NoFlags=0,
      /// Compile for matching that ignores upper/lower case distinctions.
      IgnoreCase=1,
      /// Compile for newline-sensitive matching. With this flag '[^' bracket
      /// expressions and '.' never match newline. A ^ anchor matches the 
      /// null string after any newline in the string in addition to its normal 
      /// function, and the $ anchor matches the null string before any 
      /// newline in the string in addition to its normal function.
      Newline=2
    };

    /// Compiles the given POSIX Extended Regular Expression \arg Regex.
    /// This implementation supports regexes and matching strings with embedded
    /// NUL characters.
    Regex(const StringRef &Regex, unsigned Flags = NoFlags);
    ~Regex();

    /// isValid - returns the error encountered during regex compilation, or
    /// matching, if any.
    bool isValid(std::string &Error);

    /// getNumMatches - In a valid regex, return the number of parenthesized
    /// matches it contains.  The number filled in by match will include this
    /// many entries plus one for the whole regex (as element 0).
    unsigned getNumMatches() const;
    
    /// matches - Match the regex against a given \arg String.
    ///
    /// \param Matches - If given, on a succesful match this will be filled in
    /// with references to the matched group expressions (inside \arg String),
    /// the first group is always the entire pattern.
    ///
    /// This returns true on a successful match.
    bool match(const StringRef &String, SmallVectorImpl<StringRef> *Matches=0);
  private:
    struct llvm_regex *preg;
    int error;
  };
}
