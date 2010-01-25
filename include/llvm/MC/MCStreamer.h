//===- MCStreamer.h - High-level Streaming Machine Code Output --*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file declares the MCStreamer class.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_MC_MCSTREAMER_H
#define LLVM_MC_MCSTREAMER_H

#include "llvm/System/DataTypes.h"
#include "llvm/MC/MCDirectives.h"

namespace llvm {
  class MCAsmInfo;
  class MCCodeEmitter;
  class MCContext;
  class MCExpr;
  class MCInst;
  class MCInstPrinter;
  class MCSection;
  class MCSymbol;
  class StringRef;
  class Twine;
  class raw_ostream;
  class formatted_raw_ostream;

  /// MCStreamer - Streaming machine code generation interface.  This interface
  /// is intended to provide a programatic interface that is very similar to the
  /// level that an assembler .s file provides.  It has callbacks to emit bytes,
  /// handle directives, etc.  The implementation of this interface retains
  /// state to know what the current section is etc.
  ///
  /// There are multiple implementations of this interface: one for writing out
  /// a .s file, and implementations that write out .o files of various formats.
  ///
  class MCStreamer {
    MCContext &Context;

    MCStreamer(const MCStreamer&); // DO NOT IMPLEMENT
    MCStreamer &operator=(const MCStreamer&); // DO NOT IMPLEMENT

  protected:
    MCStreamer(MCContext &Ctx);

    /// CurSection - This is the current section code is being emitted to, it is
    /// kept up to date by SwitchSection.
    const MCSection *CurSection;

  public:
    virtual ~MCStreamer();

    MCContext &getContext() const { return Context; }

    /// @name Assembly File Formatting.
    /// @{

    /// AddComment - Add a comment that can be emitted to the generated .s
    /// file if applicable as a QoI issue to make the output of the compiler
    /// more readable.  This only affects the MCAsmStreamer, and only when
    /// verbose assembly output is enabled.
    ///
    /// If the comment includes embedded \n's, they will each get the comment
    /// prefix as appropriate.  The added comment should not end with a \n.
    virtual void AddComment(const Twine &T) {}
    
    /// GetCommentOS - Return a raw_ostream that comments can be written to.
    /// Unlike AddComment, you are required to terminate comments with \n if you
    /// use this method.
    virtual raw_ostream &GetCommentOS();
    
    /// AddBlankLine - Emit a blank line to a .s file to pretty it up.
    virtual void AddBlankLine() {}
    
    /// @}
    
    /// @name Symbol & Section Management
    /// @{
    
    /// getCurrentSection - Return the current seciton that the streamer is
    /// emitting code to.
    const MCSection *getCurrentSection() const { return CurSection; }

    /// SwitchSection - Set the current section where code is being emitted to
    /// @param Section.  This is required to update CurSection.
    ///
    /// This corresponds to assembler directives like .section, .text, etc.
    virtual void SwitchSection(const MCSection *Section) = 0;
    
    /// EmitLabel - Emit a label for @param Symbol into the current section.
    ///
    /// This corresponds to an assembler statement such as:
    ///   foo:
    ///
    /// @param Symbol - The symbol to emit. A given symbol should only be
    /// emitted as a label once, and symbols emitted as a label should never be
    /// used in an assignment.
    virtual void EmitLabel(MCSymbol *Symbol) = 0;

    /// EmitAssemblerFlag - Note in the output the specified @param Flag
    virtual void EmitAssemblerFlag(MCAssemblerFlag Flag) = 0;

    /// EmitAssignment - Emit an assignment of @param Value to @param Symbol.
    ///
    /// This corresponds to an assembler statement such as:
    ///  symbol = value
    ///
    /// The assignment generates no code, but has the side effect of binding the
    /// value in the current context. For the assembly streamer, this prints the
    /// binding into the .s file.
    ///
    /// @param Symbol - The symbol being assigned to.
    /// @param Value - The value for the symbol.
    virtual void EmitAssignment(MCSymbol *Symbol, const MCExpr *Value) = 0;

    /// EmitSymbolAttribute - Add the given @param Attribute to @param Symbol.
    virtual void EmitSymbolAttribute(MCSymbol *Symbol,
                                     MCSymbolAttr Attribute) = 0;

    /// EmitSymbolDesc - Set the @param DescValue for the @param Symbol.
    ///
    /// @param Symbol - The symbol to have its n_desc field set.
    /// @param DescValue - The value to set into the n_desc field.
    virtual void EmitSymbolDesc(MCSymbol *Symbol, unsigned DescValue) = 0;

    
    /// EmitELFSize - Emit an ELF .size directive.
    ///
    /// This corresponds to an assembler statement such as:
    ///  .size symbol, expression
    ///
    virtual void EmitELFSize(MCSymbol *Symbol, const MCExpr *Value) = 0;
    
    /// EmitCommonSymbol - Emit a common symbol.
    ///
    /// @param Symbol - The common symbol to emit.
    /// @param Size - The size of the common symbol.
    /// @param ByteAlignment - The alignment of the symbol if
    /// non-zero. This must be a power of 2.
    virtual void EmitCommonSymbol(MCSymbol *Symbol, uint64_t Size,
                                  unsigned ByteAlignment) = 0;

    /// EmitLocalCommonSymbol - Emit a local common (.lcomm) symbol.
    ///
    /// @param Symbol - The common symbol to emit.
    /// @param Size - The size of the common symbol.
    virtual void EmitLocalCommonSymbol(MCSymbol *Symbol, uint64_t Size) = 0;
    
    /// EmitZerofill - Emit a the zerofill section and an option symbol.
    ///
    /// @param Section - The zerofill section to create and or to put the symbol
    /// @param Symbol - The zerofill symbol to emit, if non-NULL.
    /// @param Size - The size of the zerofill symbol.
    /// @param ByteAlignment - The alignment of the zerofill symbol if
    /// non-zero. This must be a power of 2 on some targets.
    virtual void EmitZerofill(const MCSection *Section, MCSymbol *Symbol = 0,
                              unsigned Size = 0,unsigned ByteAlignment = 0) = 0;

    /// @}
    /// @name Generating Data
    /// @{

    /// EmitBytes - Emit the bytes in \arg Data into the output.
    ///
    /// This is used to implement assembler directives such as .byte, .ascii,
    /// etc.
    virtual void EmitBytes(StringRef Data, unsigned AddrSpace) = 0;

    /// EmitValue - Emit the expression @param Value into the output as a native
    /// integer of the given @param Size bytes.
    ///
    /// This is used to implement assembler directives such as .word, .quad,
    /// etc.
    ///
    /// @param Value - The value to emit.
    /// @param Size - The size of the integer (in bytes) to emit. This must
    /// match a native machine width.
    virtual void EmitValue(const MCExpr *Value, unsigned Size,
                           unsigned AddrSpace) = 0;

    /// EmitIntValue - Special case of EmitValue that avoids the client having
    /// to pass in a MCExpr for constant integers.
    virtual void EmitIntValue(uint64_t Value, unsigned Size,unsigned AddrSpace);
    
    /// EmitFill - Emit NumBytes bytes worth of the value specified by
    /// FillValue.  This implements directives such as '.space'.
    virtual void EmitFill(uint64_t NumBytes, uint8_t FillValue,
                          unsigned AddrSpace);
    
    /// EmitZeros - Emit NumBytes worth of zeros.  This is a convenience
    /// function that just wraps EmitFill.
    void EmitZeros(uint64_t NumBytes, unsigned AddrSpace) {
      EmitFill(NumBytes, 0, AddrSpace);
    }

    
    /// EmitValueToAlignment - Emit some number of copies of @param Value until
    /// the byte alignment @param ByteAlignment is reached.
    ///
    /// If the number of bytes need to emit for the alignment is not a multiple
    /// of @param ValueSize, then the contents of the emitted fill bytes is
    /// undefined.
    ///
    /// This used to implement the .align assembler directive.
    ///
    /// @param ByteAlignment - The alignment to reach. This must be a power of
    /// two on some targets.
    /// @param Value - The value to use when filling bytes.
    /// @param Size - The size of the integer (in bytes) to emit for @param
    /// Value. This must match a native machine width.
    /// @param MaxBytesToEmit - The maximum numbers of bytes to emit, or 0. If
    /// the alignment cannot be reached in this many bytes, no bytes are
    /// emitted.
    virtual void EmitValueToAlignment(unsigned ByteAlignment, int64_t Value = 0,
                                      unsigned ValueSize = 1,
                                      unsigned MaxBytesToEmit = 0) = 0;

    /// EmitValueToOffset - Emit some number of copies of @param Value until the
    /// byte offset @param Offset is reached.
    ///
    /// This is used to implement assembler directives such as .org.
    ///
    /// @param Offset - The offset to reach. This may be an expression, but the
    /// expression must be associated with the current section.
    /// @param Value - The value to use when filling bytes.
    virtual void EmitValueToOffset(const MCExpr *Offset,
                                   unsigned char Value = 0) = 0;
    
    /// @}

    /// EmitInstruction - Emit the given @param Instruction into the current
    /// section.
    virtual void EmitInstruction(const MCInst &Inst) = 0;

    /// Finish - Finish emission of machine code and flush any output.
    virtual void Finish() = 0;
  };

  /// createNullStreamer - Create a dummy machine code streamer, which does
  /// nothing. This is useful for timing the assembler front end.
  MCStreamer *createNullStreamer(MCContext &Ctx);

  /// createAsmStreamer - Create a machine code streamer which will print out
  /// assembly for the native target, suitable for compiling with a native
  /// assembler.
  MCStreamer *createAsmStreamer(MCContext &Ctx, formatted_raw_ostream &OS,
                                const MCAsmInfo &MAI, bool isLittleEndian,
                                bool isVerboseAsm,
                                MCInstPrinter *InstPrint = 0,
                                MCCodeEmitter *CE = 0);

  // FIXME: These two may end up getting rolled into a single
  // createObjectStreamer interface, which implements the assembler backend, and
  // is parameterized on an output object file writer.

  /// createMachOStream - Create a machine code streamer which will generative
  /// Mach-O format object files.
  MCStreamer *createMachOStreamer(MCContext &Ctx, raw_ostream &OS,
                                  MCCodeEmitter *CE = 0);

  /// createELFStreamer - Create a machine code streamer which will generative
  /// ELF format object files.
  MCStreamer *createELFStreamer(MCContext &Ctx, raw_ostream &OS);

} // end namespace llvm

#endif
