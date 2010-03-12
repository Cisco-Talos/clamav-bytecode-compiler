//===----- ABIInfo.h - ABI information access & encapsulation ---*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef CLANG_CODEGEN_ABIINFO_H
#define CLANG_CODEGEN_ABIINFO_H

#include "clang/AST/Type.h"

#include <cassert>

namespace llvm {
  class Type;
  class Value;
  class LLVMContext;
}

namespace clang {
  class ASTContext;

  // FIXME: This is a layering issue if we want to move ABIInfo
  // down. Fortunately CGFunctionInfo has no real tie to CodeGen.
  namespace CodeGen {
    class CGFunctionInfo;
    class CodeGenFunction;
  }

  /* FIXME: All of this stuff should be part of the target interface
     somehow. It is currently here because it is not clear how to factor
     the targets to support this, since the Targets currently live in a
     layer below types n'stuff.
  */

  /// ABIArgInfo - Helper class to encapsulate information about how a
  /// specific C type should be passed to or returned from a function.
  class ABIArgInfo {
  public:
    enum Kind {
      Direct,    /// Pass the argument directly using the normal
                 /// converted LLVM type. Complex and structure types
                 /// are passed using first class aggregates.

      Extend,    /// Valid only for integer argument types. Same as 'direct'
                 /// but also emit a zero/sign extension attribute.

      Indirect,  /// Pass the argument indirectly via a hidden pointer
                 /// with the specified alignment (0 indicates default
                 /// alignment).

      Ignore,    /// Ignore the argument (treat as void). Useful for
                 /// void and empty structs.

      Coerce,    /// Only valid for aggregate return types, the argument
                 /// should be accessed by coercion to a provided type.

      Expand,    /// Only valid for aggregate argument types. The
                 /// structure should be expanded into consecutive
                 /// arguments for its constituent fields. Currently
                 /// expand is only allowed on structures whose fields
                 /// are all scalar types or are themselves expandable
                 /// types.

      KindFirst=Direct, KindLast=Expand
    };

  private:
    Kind TheKind;
    const llvm::Type *TypeData;
    unsigned UIntData;
    bool BoolData;

    ABIArgInfo(Kind K, const llvm::Type *TD=0,
               unsigned UI=0, bool B = false) 
      : TheKind(K), TypeData(TD), UIntData(UI), BoolData(B) {}

  public:
    ABIArgInfo() : TheKind(Direct), TypeData(0), UIntData(0) {}

    static ABIArgInfo getDirect() {
      return ABIArgInfo(Direct);
    }
    static ABIArgInfo getExtend() {
      return ABIArgInfo(Extend);
    }
    static ABIArgInfo getIgnore() {
      return ABIArgInfo(Ignore);
    }
    static ABIArgInfo getCoerce(const llvm::Type *T) {
      return ABIArgInfo(Coerce, T);
    }
    static ABIArgInfo getIndirect(unsigned Alignment, bool ByVal = true) {
      return ABIArgInfo(Indirect, 0, Alignment, ByVal);
    }
    static ABIArgInfo getExpand() {
      return ABIArgInfo(Expand);
    }

    Kind getKind() const { return TheKind; }
    bool isDirect() const { return TheKind == Direct; }
    bool isExtend() const { return TheKind == Extend; }
    bool isIgnore() const { return TheKind == Ignore; }
    bool isCoerce() const { return TheKind == Coerce; }
    bool isIndirect() const { return TheKind == Indirect; }
    bool isExpand() const { return TheKind == Expand; }

    // Coerce accessors
    const llvm::Type *getCoerceToType() const {
      assert(TheKind == Coerce && "Invalid kind!");
      return TypeData;
    }

    // Indirect accessors
    unsigned getIndirectAlign() const {
      assert(TheKind == Indirect && "Invalid kind!");
      return UIntData;
    }

    bool getIndirectByVal() const {
      assert(TheKind == Indirect && "Invalid kind!");
      return BoolData;
    }
    
    void dump() const;
  };

  /// ABIInfo - Target specific hooks for defining how a type should be
  /// passed or returned from functions.
  class ABIInfo {
  public:
    virtual ~ABIInfo();

    virtual void computeInfo(CodeGen::CGFunctionInfo &FI,
                             ASTContext &Ctx,
                             llvm::LLVMContext &VMContext) const = 0;

    /// EmitVAArg - Emit the target dependent code to load a value of
    /// \arg Ty from the va_list pointed to by \arg VAListAddr.

    // FIXME: This is a gaping layering violation if we wanted to drop
    // the ABI information any lower than CodeGen. Of course, for
    // VAArg handling it has to be at this level; there is no way to
    // abstract this out.
    virtual llvm::Value *EmitVAArg(llvm::Value *VAListAddr, QualType Ty,
                                   CodeGen::CodeGenFunction &CGF) const = 0;
  };
}  // end namespace clang

#endif
