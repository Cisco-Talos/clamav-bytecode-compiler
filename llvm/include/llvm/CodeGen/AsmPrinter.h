//===-- llvm/CodeGen/AsmPrinter.h - AsmPrinter Framework --------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains a class to be used as the base class for target specific
// asm writers.  This class primarily handles common functionality used by
// all asm writers.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_CODEGEN_ASMPRINTER_H
#define LLVM_CODEGEN_ASMPRINTER_H

#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/Support/DebugLoc.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/ADT/DenseMap.h"

namespace llvm {
  class BlockAddress;
  class GCStrategy;
  class Constant;
  class ConstantArray;
  class ConstantFP;
  class ConstantInt;
  class ConstantStruct;
  class ConstantVector;
  class GCMetadataPrinter;
  class GlobalValue;
  class GlobalVariable;
  class MachineBasicBlock;
  class MachineFunction;
  class MachineInstr;
  class MachineLoopInfo;
  class MachineLoop;
  class MachineConstantPool;
  class MachineConstantPoolEntry;
  class MachineConstantPoolValue;
  class MachineJumpTableInfo;
  class MachineModuleInfo;
  class MCInst;
  class MCContext;
  class MCSection;
  class MCStreamer;
  class MCSymbol;
  class DwarfWriter;
  class Mangler;
  class MCAsmInfo;
  class TargetLoweringObjectFile;
  class Type;
  class formatted_raw_ostream;

  /// AsmPrinter - This class is intended to be used as a driving class for all
  /// asm writers.
  class AsmPrinter : public MachineFunctionPass {
    static char ID;

    /// FunctionNumber - This provides a unique ID for each function emitted in
    /// this translation unit.  It is autoincremented by SetupMachineFunction,
    /// and can be accessed with getFunctionNumber() and 
    /// IncrementFunctionNumber().
    ///
    unsigned FunctionNumber;

    // GCMetadataPrinters - The garbage collection metadata printer table.
    typedef DenseMap<GCStrategy*,GCMetadataPrinter*> gcp_map_type;
    typedef gcp_map_type::iterator gcp_iterator;
    gcp_map_type GCMetadataPrinters;

    /// If VerboseAsm is set, a pointer to the loop info for this
    /// function.
    ///
    MachineLoopInfo *LI;

  public:
    /// MMI - If available, this is a pointer to the current MachineModuleInfo.
    MachineModuleInfo *MMI;
    
  protected:
    /// DW - If available, this is a pointer to the current dwarf writer.
    DwarfWriter *DW;

  public:
    /// Flags to specify different kinds of comments to output in
    /// assembly code.  These flags carry semantic information not
    /// otherwise easily derivable from the IR text.
    ///
    enum CommentFlag {
      ReloadReuse = 0x1
    };

    /// Output stream on which we're printing assembly code.
    ///
    formatted_raw_ostream &O;

    /// Target machine description.
    ///
    TargetMachine &TM;
    
    /// getObjFileLowering - Return information about object file lowering.
    TargetLoweringObjectFile &getObjFileLowering() const;
    
    /// Target Asm Printer information.
    ///
    const MCAsmInfo *MAI;

    /// Target Register Information.
    ///
    const TargetRegisterInfo *TRI;

    /// OutContext - This is the context for the output file that we are
    /// streaming.  This owns all of the global MC-related objects for the
    /// generated translation unit.
    MCContext &OutContext;
    
    /// OutStreamer - This is the MCStreamer object for the file we are
    /// generating.  This contains the transient state for the current
    /// translation unit that we are generating (such as the current section
    /// etc).
    MCStreamer &OutStreamer;
    
    /// The current machine function.
    const MachineFunction *MF;

    /// Name-mangler for global names.
    ///
    Mangler *Mang;

    /// Cache of mangled name for current function. This is recalculated at the
    /// beginning of each call to runOnMachineFunction().
    ///
    std::string CurrentFnName;
    
    /// getCurrentSection() - Return the current section we are emitting to.
    const MCSection *getCurrentSection() const;
    

    /// VerboseAsm - Emit comments in assembly output if this is true.
    ///
    bool VerboseAsm;

    /// Private state for PrintSpecial()
    // Assign a unique ID to this machine instruction.
    mutable const MachineInstr *LastMI;
    mutable const Function *LastFn;
    mutable unsigned Counter;
    
    // Private state for processDebugLoc()
    mutable DebugLocTuple PrevDLT;

  protected:
    explicit AsmPrinter(formatted_raw_ostream &o, TargetMachine &TM,
                        const MCAsmInfo *T, bool V);
    
  public:
    virtual ~AsmPrinter();

    /// isVerbose - Return true if assembly output should contain comments.
    ///
    bool isVerbose() const { return VerboseAsm; }

    /// getFunctionNumber - Return a unique ID for the current function.
    ///
    unsigned getFunctionNumber() const { return FunctionNumber; }
    
  protected:
    /// getAnalysisUsage - Record analysis usage.
    /// 
    void getAnalysisUsage(AnalysisUsage &AU) const;
    
    /// doInitialization - Set up the AsmPrinter when we are working on a new
    /// module.  If your pass overrides this, it must make sure to explicitly
    /// call this implementation.
    bool doInitialization(Module &M);

    /// EmitStartOfAsmFile - This virtual method can be overridden by targets
    /// that want to emit something at the start of their file.
    virtual void EmitStartOfAsmFile(Module &) {}
    
    /// EmitEndOfAsmFile - This virtual method can be overridden by targets that
    /// want to emit something at the end of their file.
    virtual void EmitEndOfAsmFile(Module &) {}
    
    /// doFinalization - Shut down the asmprinter.  If you override this in your
    /// pass, you must make sure to call it explicitly.
    bool doFinalization(Module &M);
    
    /// PrintSpecial - Print information related to the specified machine instr
    /// that is independent of the operand, and may be independent of the instr
    /// itself.  This can be useful for portably encoding the comment character
    /// or other bits of target-specific knowledge into the asmstrings.  The
    /// syntax used is ${:comment}.  Targets can override this to add support
    /// for their own strange codes.
    virtual void PrintSpecial(const MachineInstr *MI, const char *Code) const;

    /// PrintAsmOperand - Print the specified operand of MI, an INLINEASM
    /// instruction, using the specified assembler variant.  Targets should
    /// override this to format as appropriate.  This method can return true if
    /// the operand is erroneous.
    virtual bool PrintAsmOperand(const MachineInstr *MI, unsigned OpNo,
                                 unsigned AsmVariant, const char *ExtraCode);
    
    /// PrintAsmMemoryOperand - Print the specified operand of MI, an INLINEASM
    /// instruction, using the specified assembler variant as an address.
    /// Targets should override this to format as appropriate.  This method can
    /// return true if the operand is erroneous.
    virtual bool PrintAsmMemoryOperand(const MachineInstr *MI, unsigned OpNo,
                                       unsigned AsmVariant, 
                                       const char *ExtraCode);
    
    /// PrintGlobalVariable - Emit the specified global variable and its
    /// initializer to the output stream.
    virtual void PrintGlobalVariable(const GlobalVariable *GV) = 0;

    /// SetupMachineFunction - This should be called when a new MachineFunction
    /// is being processed from runOnMachineFunction.
    void SetupMachineFunction(MachineFunction &MF);
    
    /// IncrementFunctionNumber - Increase Function Number.  AsmPrinters should
    /// not normally call this, as the counter is automatically bumped by
    /// SetupMachineFunction.
    void IncrementFunctionNumber() { FunctionNumber++; }
    
    /// EmitConstantPool - Print to the current output stream assembly
    /// representations of the constants in the constant pool MCP. This is
    /// used to print out constants which have been "spilled to memory" by
    /// the code generator.
    ///
    void EmitConstantPool(MachineConstantPool *MCP);

    /// EmitJumpTableInfo - Print assembly representations of the jump tables 
    /// used by the current function to the current output stream.  
    ///
    void EmitJumpTableInfo(MachineJumpTableInfo *MJTI, MachineFunction &MF);
    
    /// EmitSpecialLLVMGlobal - Check to see if the specified global is a
    /// special global used by LLVM.  If so, emit it and return true, otherwise
    /// do nothing and return false.
    bool EmitSpecialLLVMGlobal(const GlobalVariable *GV);

  public:
    //===------------------------------------------------------------------===//
    /// LEB 128 number encoding.

    /// PrintULEB128 - Print a series of hexidecimal values(separated by commas)
    /// representing an unsigned leb128 value.
    void PrintULEB128(unsigned Value) const;

    /// PrintSLEB128 - Print a series of hexidecimal values(separated by commas)
    /// representing a signed leb128 value.
    void PrintSLEB128(int Value) const;

    //===------------------------------------------------------------------===//
    // Emission and print routines
    //

    /// PrintHex - Print a value as a hexidecimal value.
    ///
    void PrintHex(int Value) const;

    /// EOL - Print a newline character to asm stream.  If a comment is present
    /// then it will be printed first.  Comments should not contain '\n'.
    void EOL() const;
    void EOL(const std::string &Comment) const;
    void EOL(const char* Comment) const;
    void EOL(const char *Comment, unsigned Encoding) const;

    /// EmitULEB128Bytes - Emit an assembler byte data directive to compose an
    /// unsigned leb128 value.
    void EmitULEB128Bytes(unsigned Value) const;
    
    /// EmitSLEB128Bytes - print an assembler byte data directive to compose a
    /// signed leb128 value.
    void EmitSLEB128Bytes(int Value) const;
    
    /// EmitInt8 - Emit a byte directive and value.
    ///
    void EmitInt8(int Value) const;

    /// EmitInt16 - Emit a short directive and value.
    ///
    void EmitInt16(int Value) const;

    /// EmitInt32 - Emit a long directive and value.
    ///
    void EmitInt32(int Value) const;

    /// EmitInt64 - Emit a long long directive and value.
    ///
    void EmitInt64(uint64_t Value) const;

    /// EmitString - Emit a string with quotes and a null terminator.
    /// Special characters are emitted properly.
    /// @verbatim (Eg. '\t') @endverbatim
    void EmitString(const StringRef String) const;
    void EmitString(const char *String, unsigned Size) const;

    /// EmitFile - Emit a .file directive.
    void EmitFile(unsigned Number, const std::string &Name) const;

    //===------------------------------------------------------------------===//

    /// EmitAlignment - Emit an alignment directive to the specified power of
    /// two boundary.  For example, if you pass in 3 here, you will get an 8
    /// byte alignment.  If a global value is specified, and if that global has
    /// an explicit alignment requested, it will unconditionally override the
    /// alignment request.  However, if ForcedAlignBits is specified, this value
    /// has final say: the ultimate alignment will be the max of ForcedAlignBits
    /// and the alignment computed with NumBits and the global.  If UseFillExpr
    /// is true, it also emits an optional second value FillValue which the
    /// assembler uses to fill gaps to match alignment for text sections if the
    /// has specified a non-zero fill value.
    ///
    /// The algorithm is:
    ///     Align = NumBits;
    ///     if (GV && GV->hasalignment) Align = GV->getalignment();
    ///     Align = std::max(Align, ForcedAlignBits);
    ///
    void EmitAlignment(unsigned NumBits, const GlobalValue *GV = 0,
                       unsigned ForcedAlignBits = 0,
                       bool UseFillExpr = true) const;

    /// printLabel - This method prints a local label used by debug and
    /// exception handling tables.
    void printLabel(const MachineInstr *MI) const;
    void printLabel(unsigned Id) const;

    /// printDeclare - This method prints a local variable declaration used by
    /// debug tables.
    void printDeclare(const MachineInstr *MI) const;

    /// EmitComments - Pretty-print comments for instructions
    void EmitComments(const MachineInstr &MI) const;
    /// EmitComments - Pretty-print comments for basic blocks
    void EmitComments(const MachineBasicBlock &MBB) const;

    /// GetMBBSymbol - Return the MCSymbol corresponding to the specified basic
    /// block label.
    MCSymbol *GetMBBSymbol(unsigned MBBID) const;
    
    /// GetBlockAddressSymbol - Return the MCSymbol used to satisfy BlockAddress
    /// uses of the specified basic block.
    MCSymbol *GetBlockAddressSymbol(const BlockAddress *BA,
                                    const char *Suffix = "") const;
    MCSymbol *GetBlockAddressSymbol(const Function *F,
                                    const BasicBlock *BB,
                                    const char *Suffix = "") const;

    /// EmitBasicBlockStart - This method prints the label for the specified
    /// MachineBasicBlock, an alignment (if present) and a comment describing
    /// it if appropriate.
    void EmitBasicBlockStart(const MachineBasicBlock *MBB) const;
  protected:
    /// EmitZeros - Emit a block of zeros.
    ///
    void EmitZeros(uint64_t NumZeros, unsigned AddrSpace = 0) const;

    /// EmitString - Emit a zero-byte-terminated string constant.
    ///
    virtual void EmitString(const ConstantArray *CVA) const;

    /// EmitConstantValueOnly - Print out the specified constant, without a
    /// storage class.  Only constants of first-class type are allowed here.
    void EmitConstantValueOnly(const Constant *CV);

    /// EmitGlobalConstant - Print a general LLVM constant to the .s file.
    void EmitGlobalConstant(const Constant* CV, unsigned AddrSpace = 0);

    virtual void EmitMachineConstantPoolValue(MachineConstantPoolValue *MCPV);

    /// processDebugLoc - Processes the debug information of each machine
    /// instruction's DebugLoc. 
    void processDebugLoc(const MachineInstr *MI, bool BeforePrintingInsn);
    
    /// printInlineAsm - This method formats and prints the specified machine
    /// instruction that is an inline asm.
    void printInlineAsm(const MachineInstr *MI) const;

    /// printImplicitDef - This method prints the specified machine instruction
    /// that is an implicit def.
    void printImplicitDef(const MachineInstr *MI) const;

    /// printKill - This method prints the specified kill machine instruction.
    void printKill(const MachineInstr *MI) const;

    /// printPICJumpTableSetLabel - This method prints a set label for the
    /// specified MachineBasicBlock for a jumptable entry.
    virtual void printPICJumpTableSetLabel(unsigned uid,
                                           const MachineBasicBlock *MBB) const;
    virtual void printPICJumpTableSetLabel(unsigned uid, unsigned uid2,
                                           const MachineBasicBlock *MBB) const;
    virtual void printPICJumpTableEntry(const MachineJumpTableInfo *MJTI,
                                        const MachineBasicBlock *MBB,
                                        unsigned uid) const;
    
    /// printDataDirective - This method prints the asm directive for the
    /// specified type.
    void printDataDirective(const Type *type, unsigned AddrSpace = 0);

    /// printVisibility - This prints visibility information about symbol, if
    /// this is suported by the target.
    void printVisibility(const std::string& Name, unsigned Visibility) const;

    /// printOffset - This is just convenient handler for printing offsets.
    void printOffset(int64_t Offset) const;
 
  private:
    void EmitLLVMUsedList(Constant *List);
    void EmitXXStructorList(Constant *List);
    void EmitGlobalConstantStruct(const ConstantStruct* CVS,
                                  unsigned AddrSpace);
    void EmitGlobalConstantArray(const ConstantArray* CVA, unsigned AddrSpace);
    void EmitGlobalConstantVector(const ConstantVector* CP);
    void EmitGlobalConstantFP(const ConstantFP* CFP, unsigned AddrSpace);
    void EmitGlobalConstantLargeInt(const ConstantInt* CI, unsigned AddrSpace);
    GCMetadataPrinter *GetOrCreateGCPrinter(GCStrategy *C);
  };
}

#endif
