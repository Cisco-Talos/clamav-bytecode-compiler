//===- CodeGenTarget.h - Target Class Wrapper -------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines wrappers for the Target class and related global
// functionality.  This makes it easier to access the data and provides a single
// place that needs to check it for validity.  All of these classes throw
// exceptions on error conditions.
//
//===----------------------------------------------------------------------===//

#ifndef CODEGEN_TARGET_H
#define CODEGEN_TARGET_H

#include "llvm/Support/raw_ostream.h"
#include "CodeGenRegisters.h"
#include "CodeGenInstruction.h"
#include <algorithm>
#include <map>

namespace llvm {

class Record;
class RecordKeeper;
struct CodeGenRegister;
class CodeGenTarget;

// SelectionDAG node properties.
//  SDNPMemOperand: indicates that a node touches memory and therefore must
//                  have an associated memory operand that describes the access.
enum SDNP {
  SDNPCommutative, 
  SDNPAssociative, 
  SDNPHasChain,
  SDNPOutFlag,
  SDNPInFlag,
  SDNPOptInFlag,
  SDNPMayLoad,
  SDNPMayStore,
  SDNPSideEffect,
  SDNPMemOperand
};

/// getValueType - Return the MVT::SimpleValueType that the specified TableGen
/// record corresponds to.
MVT::SimpleValueType getValueType(Record *Rec);

std::string getName(MVT::SimpleValueType T);
std::string getEnumName(MVT::SimpleValueType T);

/// getQualifiedName - Return the name of the specified record, with a
/// namespace qualifier if the record contains one.
std::string getQualifiedName(const Record *R);
  
/// CodeGenTarget - This class corresponds to the Target class in the .td files.
///
class CodeGenTarget {
  Record *TargetRec;

  mutable std::map<std::string, CodeGenInstruction> Instructions;
  mutable std::vector<CodeGenRegister> Registers;
  mutable std::vector<CodeGenRegisterClass> RegisterClasses;
  mutable std::vector<MVT::SimpleValueType> LegalValueTypes;
  void ReadRegisters() const;
  void ReadRegisterClasses() const;
  void ReadInstructions() const;
  void ReadLegalValueTypes() const;
public:
  CodeGenTarget();

  Record *getTargetRecord() const { return TargetRec; }
  const std::string &getName() const;

  /// getInstNamespace - Return the target-specific instruction namespace.
  ///
  std::string getInstNamespace() const;

  /// getInstructionSet - Return the InstructionSet object.
  ///
  Record *getInstructionSet() const;

  /// getAsmParser - Return the AssemblyParser definition for this target.
  ///
  Record *getAsmParser() const;

  /// getAsmWriter - Return the AssemblyWriter definition for this target.
  ///
  Record *getAsmWriter() const;

  const std::vector<CodeGenRegister> &getRegisters() const {
    if (Registers.empty()) ReadRegisters();
    return Registers;
  }

  const std::vector<CodeGenRegisterClass> &getRegisterClasses() const {
    if (RegisterClasses.empty()) ReadRegisterClasses();
    return RegisterClasses;
  }
  
  const CodeGenRegisterClass &getRegisterClass(Record *R) const {
    const std::vector<CodeGenRegisterClass> &RC = getRegisterClasses();
    for (unsigned i = 0, e = RC.size(); i != e; ++i)
      if (RC[i].TheDef == R)
        return RC[i];
    assert(0 && "Didn't find the register class");
    abort();
  }
  
  /// getRegisterClassForRegister - Find the register class that contains the
  /// specified physical register.  If the register is not in a register
  /// class, return null. If the register is in multiple classes, and the
  /// classes have a superset-subset relationship and the same set of
  /// types, return the superclass.  Otherwise return null.
  const CodeGenRegisterClass *getRegisterClassForRegister(Record *R) const {
    const std::vector<CodeGenRegisterClass> &RCs = getRegisterClasses();
    const CodeGenRegisterClass *FoundRC = 0;
    for (unsigned i = 0, e = RCs.size(); i != e; ++i) {
      const CodeGenRegisterClass &RC = RegisterClasses[i];
      for (unsigned ei = 0, ee = RC.Elements.size(); ei != ee; ++ei) {
        if (R != RC.Elements[ei])
          continue;

        // If a register's classes have different types, return null.
        if (FoundRC && RC.getValueTypes() != FoundRC->getValueTypes())
          return 0;

        // If this is the first class that contains the register,
        // make a note of it and go on to the next class.
        if (!FoundRC) {
          FoundRC = &RC;
          break;
        }

        std::vector<Record *> Elements(RC.Elements);
        std::vector<Record *> FoundElements(FoundRC->Elements);
        std::sort(Elements.begin(), Elements.end());
        std::sort(FoundElements.begin(), FoundElements.end());

        // Check to see if the previously found class that contains
        // the register is a subclass of the current class. If so,
        // prefer the superclass.
        if (std::includes(Elements.begin(), Elements.end(),
                          FoundElements.begin(), FoundElements.end())) {
          FoundRC = &RC;
          break;
        }

        // Check to see if the previously found class that contains
        // the register is a superclass of the current class. If so,
        // prefer the superclass.
        if (std::includes(FoundElements.begin(), FoundElements.end(),
                          Elements.begin(), Elements.end()))
          break;

        // Multiple classes, and neither is a superclass of the other.
        // Return null.
        return 0;
      }
    }
    return FoundRC;
  }

  /// getRegisterVTs - Find the union of all possible SimpleValueTypes for the
  /// specified physical register.
  std::vector<unsigned char> getRegisterVTs(Record *R) const;
  
  const std::vector<MVT::SimpleValueType> &getLegalValueTypes() const {
    if (LegalValueTypes.empty()) ReadLegalValueTypes();
    return LegalValueTypes;
  }
  
  /// isLegalValueType - Return true if the specified value type is natively
  /// supported by the target (i.e. there are registers that directly hold it).
  bool isLegalValueType(MVT::SimpleValueType VT) const {
    const std::vector<MVT::SimpleValueType> &LegalVTs = getLegalValueTypes();
    for (unsigned i = 0, e = LegalVTs.size(); i != e; ++i)
      if (LegalVTs[i] == VT) return true;
    return false;    
  }

  /// getInstructions - Return all of the instructions defined for this target.
  ///
  const std::map<std::string, CodeGenInstruction> &getInstructions() const {
    if (Instructions.empty()) ReadInstructions();
    return Instructions;
  }
  std::map<std::string, CodeGenInstruction> &getInstructions() {
    if (Instructions.empty()) ReadInstructions();
    return Instructions;
  }

  CodeGenInstruction &getInstruction(const std::string &Name) const {
    const std::map<std::string, CodeGenInstruction> &Insts = getInstructions();
    assert(Insts.count(Name) && "Not an instruction!");
    return const_cast<CodeGenInstruction&>(Insts.find(Name)->second);
  }

  typedef std::map<std::string,
                   CodeGenInstruction>::const_iterator inst_iterator;
  inst_iterator inst_begin() const { return getInstructions().begin(); }
  inst_iterator inst_end() const { return Instructions.end(); }

  /// getInstructionsByEnumValue - Return all of the instructions defined by the
  /// target, ordered by their enum value.
  void getInstructionsByEnumValue(std::vector<const CodeGenInstruction*>
                                                &NumberedInstructions);


  /// isLittleEndianEncoding - are instruction bit patterns defined as  [0..n]?
  ///
  bool isLittleEndianEncoding() const;
};

/// ComplexPattern - ComplexPattern info, corresponding to the ComplexPattern
/// tablegen class in TargetSelectionDAG.td
class ComplexPattern {
  MVT::SimpleValueType Ty;
  unsigned NumOperands;
  std::string SelectFunc;
  std::vector<Record*> RootNodes;
  unsigned Properties; // Node properties
public:
  ComplexPattern() : NumOperands(0) {}
  ComplexPattern(Record *R);

  MVT::SimpleValueType getValueType() const { return Ty; }
  unsigned getNumOperands() const { return NumOperands; }
  const std::string &getSelectFunc() const { return SelectFunc; }
  const std::vector<Record*> &getRootNodes() const {
    return RootNodes;
  }
  bool hasProperty(enum SDNP Prop) const { return Properties & (1 << Prop); }
};

} // End llvm namespace

#endif
