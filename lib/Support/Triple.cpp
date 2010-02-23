//===--- Triple.cpp - Target triple helper class --------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "llvm/ADT/Triple.h"

#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/Twine.h"
#include <cassert>
#include <cstring>
using namespace llvm;

//

const char *Triple::getArchTypeName(ArchType Kind) {
  switch (Kind) {
  case InvalidArch: return "<invalid>";
  case UnknownArch: return "unknown";
    
  case alpha:   return "alpha";
  case arm:     return "arm";
  case bfin:    return "bfin";
  case cellspu: return "cellspu";
  case mips:    return "mips";
  case mipsel:  return "mipsel";
  case msp430:  return "msp430";
  case pic16:   return "pic16";
  case ppc64:   return "powerpc64";
  case ppc:     return "powerpc";
  case sparc:   return "sparc";
  case sparcv9: return "sparcv9";
  case systemz: return "s390x";
  case tce:     return "tce";
  case thumb:   return "thumb";
  case x86:     return "i386";
  case x86_64:  return "x86_64";
  case xcore:   return "xcore";
  case mblaze:  return "mblaze";
  }

  return "<invalid>";
}

const char *Triple::getArchTypePrefix(ArchType Kind) {
  switch (Kind) {
  default:
    return 0;

  case alpha:   return "alpha";

  case arm:
  case thumb:   return "arm";

  case bfin:    return "bfin";

  case cellspu: return "spu";

  case ppc64:
  case ppc:     return "ppc";

  case mblaze:  return "mblaze";

  case sparcv9:
  case sparc:   return "sparc";

  case x86:
  case x86_64:  return "x86";
  case xcore:   return "xcore";
  }
}

const char *Triple::getVendorTypeName(VendorType Kind) {
  switch (Kind) {
  case UnknownVendor: return "unknown";

  case Apple: return "apple";
  case PC: return "pc";
  }

  return "<invalid>";
}

const char *Triple::getOSTypeName(OSType Kind) {
  switch (Kind) {
  case UnknownOS: return "unknown";

  case AuroraUX: return "auroraux";
  case Cygwin: return "cygwin";
  case Darwin: return "darwin";
  case DragonFly: return "dragonfly";
  case FreeBSD: return "freebsd";
  case Linux: return "linux";
  case Lv2: return "lv2";
  case MinGW32: return "mingw32";
  case MinGW64: return "mingw64";
  case NetBSD: return "netbsd";
  case OpenBSD: return "openbsd";
  case Psp: return "psp";
  case Solaris: return "solaris";
  case Win32: return "win32";
  case Haiku: return "haiku";
  }

  return "<invalid>";
}

Triple::ArchType Triple::getArchTypeForLLVMName(StringRef Name) {
  if (Name == "alpha")
    return alpha;
  if (Name == "arm")
    return arm;
  if (Name == "bfin")
    return bfin;
  if (Name == "cellspu")
    return cellspu;
  if (Name == "mips")
    return mips;
  if (Name == "mipsel")
    return mipsel;
  if (Name == "msp430")
    return msp430;
  if (Name == "pic16")
    return pic16;
  if (Name == "ppc64")
    return ppc64;
  if (Name == "ppc")
    return ppc;
  if (Name == "mblaze")
    return mblaze;
  if (Name == "sparc")
    return sparc;
  if (Name == "sparcv9")
    return sparcv9;
  if (Name == "systemz")
    return systemz;
  if (Name == "tce")
    return tce;
  if (Name == "thumb")
    return thumb;
  if (Name == "x86")
    return x86;
  if (Name == "x86-64")
    return x86_64;
  if (Name == "xcore")
    return xcore;

  return UnknownArch;
}

Triple::ArchType Triple::getArchTypeForDarwinArchName(StringRef Str) {
  // See arch(3) and llvm-gcc's driver-driver.c. We don't implement support for
  // archs which Darwin doesn't use.

  // The matching this routine does is fairly pointless, since it is neither the
  // complete architecture list, nor a reasonable subset. The problem is that
  // historically the driver driver accepts this and also ties its -march=
  // handling to the architecture name, so we need to be careful before removing
  // support for it.

  // This code must be kept in sync with Clang's Darwin specific argument
  // translation.

  if (Str == "ppc" || Str == "ppc601" || Str == "ppc603" || Str == "ppc604" ||
      Str == "ppc604e" || Str == "ppc750" || Str == "ppc7400" ||
      Str == "ppc7450" || Str == "ppc970")
    return Triple::ppc;

  if (Str == "ppc64")
    return Triple::ppc64;

  if (Str == "i386" || Str == "i486" || Str == "i486SX" || Str == "pentium" ||
      Str == "i586" || Str == "pentpro" || Str == "i686" || Str == "pentIIm3" ||
      Str == "pentIIm5" || Str == "pentium4")
    return Triple::x86;

  if (Str == "x86_64")
    return Triple::x86_64;

  // This is derived from the driver driver.
  if (Str == "arm" || Str == "armv4t" || Str == "armv5" || Str == "xscale" ||
      Str == "armv6" || Str == "armv7")
    return Triple::arm;

  return Triple::UnknownArch;
}

// Returns architecture name that is unsderstood by the target assembler.
const char *Triple::getArchNameForAssembler() {
  if (getOS() != Triple::Darwin && getVendor() != Triple::Apple)
    return NULL;

  StringRef Str = getArchName();
  if (Str == "i386")
    return "i386";
  if (Str == "x86_64")
    return "x86_64";
  if (Str == "powerpc")
    return "ppc";
  if (Str == "powerpc64")
    return "ppc64";
  if (Str == "mblaze" || Str == "microblaze")
    return "mblaze";
  if (Str == "arm")
    return "arm";
  if (Str == "armv4t" || Str == "thumbv4t")
    return "armv4t";
  if (Str == "armv5" || Str == "armv5e" || Str == "thumbv5" || Str == "thumbv5e")
    return "armv5";
  if (Str == "armv6" || Str == "thumbv6")
    return "armv6";
  if (Str == "armv7" || Str == "thumbv7")
    return "armv7";
  return NULL;
}

//

void Triple::Parse() const {
  assert(!isInitialized() && "Invalid parse call.");

  StringRef ArchName = getArchName();
  StringRef VendorName = getVendorName();
  StringRef OSName = getOSName();

  if (ArchName.size() == 4 && ArchName[0] == 'i' && 
      ArchName[2] == '8' && ArchName[3] == '6' && 
      ArchName[1] - '3' < 6) // i[3-9]86
    Arch = x86;
  else if (ArchName == "amd64" || ArchName == "x86_64")
    Arch = x86_64;
  else if (ArchName == "bfin")
    Arch = bfin;
  else if (ArchName == "pic16")
    Arch = pic16;
  else if (ArchName == "powerpc")
    Arch = ppc;
  else if ((ArchName == "powerpc64") || (ArchName == "ppu"))
    Arch = ppc64;
  else if (ArchName == "mblaze")
    Arch = mblaze;
  else if (ArchName == "arm" ||
           ArchName.startswith("armv") ||
           ArchName == "xscale")
    Arch = arm;
  else if (ArchName == "thumb" ||
           ArchName.startswith("thumbv"))
    Arch = thumb;
  else if (ArchName.startswith("alpha"))
    Arch = alpha;
  else if (ArchName == "spu" || ArchName == "cellspu")
    Arch = cellspu;
  else if (ArchName == "msp430")
    Arch = msp430;
  else if (ArchName == "mips" || ArchName == "mipsallegrex")
    Arch = mips;
  else if (ArchName == "mipsel" || ArchName == "mipsallegrexel" ||
           ArchName == "psp")
    Arch = mipsel;
  else if (ArchName == "sparc")
    Arch = sparc;
  else if (ArchName == "sparcv9")
    Arch = sparcv9;
  else if (ArchName == "s390x")
    Arch = systemz;
  else if (ArchName == "tce")
    Arch = tce;
  else if (ArchName == "xcore")
    Arch = xcore;
  else
    Arch = UnknownArch;


  // Handle some exceptional cases where the OS / environment components are
  // stuck into the vendor field.
  if (StringRef(getTriple()).count('-') == 1) {
    StringRef VendorName = getVendorName();

    if (VendorName.startswith("mingw32")) { // 'i386-mingw32', etc.
      Vendor = PC;
      OS = MinGW32;
      return;
    }

    // arm-elf is another example, but we don't currently parse anything about
    // the environment.
  }

  if (VendorName == "apple")
    Vendor = Apple;
  else if (VendorName == "pc")
    Vendor = PC;
  else
    Vendor = UnknownVendor;

  if (OSName.startswith("auroraux"))
    OS = AuroraUX;
  else if (OSName.startswith("cygwin"))
    OS = Cygwin;
  else if (OSName.startswith("darwin"))
    OS = Darwin;
  else if (OSName.startswith("dragonfly"))
    OS = DragonFly;
  else if (OSName.startswith("freebsd"))
    OS = FreeBSD;
  else if (OSName.startswith("linux"))
    OS = Linux;
  else if (OSName.startswith("lv2"))
    OS = Lv2;
  else if (OSName.startswith("mingw32"))
    OS = MinGW32;
  else if (OSName.startswith("mingw64"))
    OS = MinGW64;
  else if (OSName.startswith("netbsd"))
    OS = NetBSD;
  else if (OSName.startswith("openbsd"))
    OS = OpenBSD;
  else if (OSName.startswith("psp"))
    OS = Psp;
  else if (OSName.startswith("solaris"))
    OS = Solaris;
  else if (OSName.startswith("win32"))
    OS = Win32;
  else if (OSName.startswith("haiku"))
  	OS = Haiku;
  else
    OS = UnknownOS;

  assert(isInitialized() && "Failed to initialize!");
}

StringRef Triple::getArchName() const {
  return StringRef(Data).split('-').first;           // Isolate first component
}

StringRef Triple::getVendorName() const {
  StringRef Tmp = StringRef(Data).split('-').second; // Strip first component
  return Tmp.split('-').first;                       // Isolate second component
}

StringRef Triple::getOSName() const {
  StringRef Tmp = StringRef(Data).split('-').second; // Strip first component
  Tmp = Tmp.split('-').second;                       // Strip second component
  return Tmp.split('-').first;                       // Isolate third component
}

StringRef Triple::getEnvironmentName() const {
  StringRef Tmp = StringRef(Data).split('-').second; // Strip first component
  Tmp = Tmp.split('-').second;                       // Strip second component
  return Tmp.split('-').second;                      // Strip third component
}

StringRef Triple::getOSAndEnvironmentName() const {
  StringRef Tmp = StringRef(Data).split('-').second; // Strip first component
  return Tmp.split('-').second;                      // Strip second component
}

static unsigned EatNumber(StringRef &Str) {
  assert(!Str.empty() && Str[0] >= '0' && Str[0] <= '9' && "Not a number");
  unsigned Result = Str[0]-'0';
  
  // Eat the digit.
  Str = Str.substr(1);
  
  // Handle "darwin11".
  if (Result == 1 && !Str.empty() && Str[0] >= '0' && Str[0] <= '9') {
    Result = Result*10 + (Str[0] - '0');
    // Eat the digit.
    Str = Str.substr(1);
  }
  
  return Result;
}

/// getDarwinNumber - Parse the 'darwin number' out of the specific target
/// triple.  For example, if we have darwin8.5 return 8,5,0.  If any entry is
/// not defined, return 0's.  This requires that the triple have an OSType of
/// darwin before it is called.
void Triple::getDarwinNumber(unsigned &Maj, unsigned &Min,
                             unsigned &Revision) const {
  assert(getOS() == Darwin && "Not a darwin target triple!");
  StringRef OSName = getOSName();
  assert(OSName.startswith("darwin") && "Unknown darwin target triple!");
  
  // Strip off "darwin".
  OSName = OSName.substr(6);
  
  Maj = Min = Revision = 0;

  if (OSName.empty() || OSName[0] < '0' || OSName[0] > '9')
    return;

  // The major version is the first digit.
  Maj = EatNumber(OSName);
  if (OSName.empty()) return;
  
  // Handle minor version: 10.4.9 -> darwin8.9.
  if (OSName[0] != '.')
    return;
  
  // Eat the '.'.
  OSName = OSName.substr(1);

  if (OSName.empty() || OSName[0] < '0' || OSName[0] > '9')
    return;
  
  Min = EatNumber(OSName);
  if (OSName.empty()) return;

  // Handle revision darwin8.9.1
  if (OSName[0] != '.')
    return;
  
  // Eat the '.'.
  OSName = OSName.substr(1);
  
  if (OSName.empty() || OSName[0] < '0' || OSName[0] > '9')
    return;

  Revision = EatNumber(OSName);
}

void Triple::setTriple(const Twine &Str) {
  Data = Str.str();
  Arch = InvalidArch;
}

void Triple::setArch(ArchType Kind) {
  setArchName(getArchTypeName(Kind));
}

void Triple::setVendor(VendorType Kind) {
  setVendorName(getVendorTypeName(Kind));
}

void Triple::setOS(OSType Kind) {
  setOSName(getOSTypeName(Kind));
}

void Triple::setArchName(StringRef Str) {
  // Work around a miscompilation bug for Twines in gcc 4.0.3.
  SmallString<64> Triple;
  Triple += Str;
  Triple += "-";
  Triple += getVendorName();
  Triple += "-";
  Triple += getOSAndEnvironmentName();
  setTriple(Triple.str());
}

void Triple::setVendorName(StringRef Str) {
  setTriple(getArchName() + "-" + Str + "-" + getOSAndEnvironmentName());
}

void Triple::setOSName(StringRef Str) {
  if (hasEnvironment())
    setTriple(getArchName() + "-" + getVendorName() + "-" + Str +
              "-" + getEnvironmentName());
  else
    setTriple(getArchName() + "-" + getVendorName() + "-" + Str);
}

void Triple::setEnvironmentName(StringRef Str) {
  setTriple(getArchName() + "-" + getVendorName() + "-" + getOSName() +
            "-" + Str);
}

void Triple::setOSAndEnvironmentName(StringRef Str) {
  setTriple(getArchName() + "-" + getVendorName() + "-" + Str);
}
