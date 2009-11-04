//===--- InitPreprocessor.h - InitializePreprocessor function. --*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines the clang::InitializePreprocessor function.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_CLANG_FRONTEND_INIT_PREPROCESSOR_H_
#define LLVM_CLANG_FRONTEND_INIT_PREPROCESSOR_H_

#include <string>
#include <vector>

namespace clang {

class Preprocessor;
class LangOptions;

/// PreprocessorInitOptions - This class is used for passing the various
/// options used in preprocessor initialization to InitializePreprocessor().
class PreprocessorInitOptions {
  std::vector<std::pair<std::string, bool/*isUndef*/> > Macros;
  std::vector<std::pair<std::string, bool/*isPTH*/> > Includes;
  std::vector<std::string> MacroIncludes;

  unsigned UsePredefines : 1; /// Initialize the preprocessor with the compiler
                              /// and target specific predefines.

public:
  PreprocessorInitOptions() : UsePredefines(true) {}

  bool getUsePredefines() const { return UsePredefines; }
  void setUsePredefines(bool Value) {
    UsePredefines = Value;
  }

  void addMacroDef(const std::string &Name) {
    Macros.push_back(std::make_pair(Name, false));
  }
  void addMacroUndef(const std::string &Name) {
    Macros.push_back(std::make_pair(Name, true));
  }
  void addInclude(const std::string &Name, bool isPTH = false) {
    Includes.push_back(std::make_pair(Name, isPTH));
  }
  void addMacroInclude(const std::string &Name) {
    MacroIncludes.push_back(Name);
  }

  typedef std::vector<std::pair<std::string,
                                bool> >::const_iterator macro_iterator;
  macro_iterator macro_begin() const { return Macros.begin(); }
  macro_iterator macro_end() const { return Macros.end(); }

  typedef std::vector<std::pair<std::string,
                                bool> >::const_iterator include_iterator;
  include_iterator include_begin() const { return Includes.begin(); }
  include_iterator include_end() const { return Includes.end(); }

  typedef std::vector<std::string>::const_iterator imacro_iterator;
  imacro_iterator imacro_begin() const { return MacroIncludes.begin(); }
  imacro_iterator imacro_end() const { return MacroIncludes.end(); }
};

/// InitializePreprocessor - Initialize the preprocessor getting it and the
/// environment ready to process a single file. This returns true on error.
///
bool InitializePreprocessor(Preprocessor &PP,
                            const PreprocessorInitOptions& InitOptions);

} // end namespace clang

#endif
