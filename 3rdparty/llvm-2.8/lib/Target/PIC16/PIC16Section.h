//===- PIC16Section.h - PIC16-specific section representation -*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file declares the PIC16Section class.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_PIC16SECTION_H
#define LLVM_PIC16SECTION_H

#include "llvm/MC/MCSection.h"
#include "llvm/GlobalVariable.h"
#include <vector>

namespace llvm {
  /// PIC16Section - Represents a physical section in PIC16 COFF.
  /// Contains data objects.
  ///
  class PIC16Section : public MCSection {
    /// PIC16 Sections does not really use the SectionKind class to
    /// to distinguish between various types of sections. PIC16 maintain
    /// its own Section Type info. See the PIC16SectionType enum in PIC16.h 
    /// for various section types.
    PIC16SectionType T;

    /// Name of the section to uniquely identify it.
    StringRef Name;

    /// User can specify an address at which a section should be placed. 
    /// Negative value here means user hasn't specified any. 
    StringRef Address; 

    /// Overlay information - Sections with same color can be overlaid on
    /// one another.
    int Color; 

    /// Total size of all data objects contained here.
    unsigned Size;
    
    PIC16Section(StringRef name, SectionKind K, StringRef addr, int color)
      : MCSection(SV_PIC16, K), Name(name), Address(addr),
        Color(color), Size(0) {
    }
    
  public:
    /// Return the name of the section.
    StringRef getName() const { return Name; }

    /// Return the Address of the section.
    StringRef getAddress() const { return Address; }

    /// Return the Color of the section.
    int getColor() const { return Color; }
    void setColor(int color) { Color = color; }

    /// Return the size of the section.
    unsigned getSize() const { return Size; }
    void setSize(unsigned size) { Size = size; }

    /// Conatined data objects.
    // FIXME: This vector is leaked because sections are allocated with a
    //        BumpPtrAllocator.
    std::vector<const GlobalVariable *>Items;

    /// Check section type. 
    bool isUDATA_Type() const { return T == UDATA; }
    bool isIDATA_Type() const { return T == IDATA; }
    bool isROMDATA_Type() const { return T == ROMDATA; }
    bool isUDATA_OVR_Type() const { return T == UDATA_OVR; }
    bool isUDATA_SHR_Type() const { return T == UDATA_SHR; }
    bool isCODE_Type() const { return T == CODE; }

    PIC16SectionType getType() const { return T; }

    /// This would be the only way to create a section. 
    static PIC16Section *Create(StringRef Name, PIC16SectionType Ty, 
                                StringRef Address, int Color, 
                                MCContext &Ctx);
    
    /// Override this as PIC16 has its own way of printing switching
    /// to a section.
    virtual void PrintSwitchToSection(const MCAsmInfo &MAI,
                                      raw_ostream &OS) const;

    static bool classof(const MCSection *S) {
      return S->getVariant() == SV_PIC16;
    }
    static bool classof(const PIC16Section *) { return true; }
  };

} // end namespace llvm

#endif
