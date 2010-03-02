//===--- Tools.cpp - Tools Implementations ------------------------------*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "Tools.h"

#include "clang/Driver/Action.h"
#include "clang/Driver/Arg.h"
#include "clang/Driver/ArgList.h"
#include "clang/Driver/Driver.h"
#include "clang/Driver/DriverDiagnostic.h"
#include "clang/Driver/Compilation.h"
#include "clang/Driver/Job.h"
#include "clang/Driver/HostInfo.h"
#include "clang/Driver/Option.h"
#include "clang/Driver/Options.h"
#include "clang/Driver/ToolChain.h"
#include "clang/Driver/Util.h"

#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/StringSwitch.h"
#include "llvm/ADT/Twine.h"
#include "llvm/Support/Format.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/System/Host.h"
#include "llvm/System/Process.h"

#include "InputInfo.h"
#include "ToolChains.h"

using namespace clang::driver;
using namespace clang::driver::tools;

/// CheckPreprocessingOptions - Perform some validation of preprocessing
/// arguments that is shared with gcc.
static void CheckPreprocessingOptions(const Driver &D, const ArgList &Args) {
  if (Arg *A = Args.getLastArg(options::OPT_C, options::OPT_CC))
    if (!Args.hasArg(options::OPT_E))
      D.Diag(clang::diag::err_drv_argument_only_allowed_with)
        << A->getAsString(Args) << "-E";
}

/// CheckCodeGenerationOptions - Perform some validation of code generation
/// arguments that is shared with gcc.
static void CheckCodeGenerationOptions(const Driver &D, const ArgList &Args) {
  // In gcc, only ARM checks this, but it seems reasonable to check universally.
  if (Args.hasArg(options::OPT_static))
    if (const Arg *A = Args.getLastArg(options::OPT_dynamic,
                                       options::OPT_mdynamic_no_pic))
      D.Diag(clang::diag::err_drv_argument_not_allowed_with)
        << A->getAsString(Args) << "-static";
}

void Clang::AddPreprocessingOptions(const Driver &D,
                                    const ArgList &Args,
                                    ArgStringList &CmdArgs,
                                    const InputInfo &Output,
                                    const InputInfoList &Inputs) const {
  Arg *A;

  CheckPreprocessingOptions(D, Args);

  Args.AddLastArg(CmdArgs, options::OPT_C);
  Args.AddLastArg(CmdArgs, options::OPT_CC);

  // Handle dependency file generation.
  if ((A = Args.getLastArg(options::OPT_M)) ||
      (A = Args.getLastArg(options::OPT_MM)) ||
      (A = Args.getLastArg(options::OPT_MD)) ||
      (A = Args.getLastArg(options::OPT_MMD))) {
    // Determine the output location.
    const char *DepFile;
    if (Output.getType() == types::TY_Dependencies) {
      if (Output.isPipe())
        DepFile = "-";
      else
        DepFile = Output.getFilename();
    } else if (Arg *MF = Args.getLastArg(options::OPT_MF)) {
      DepFile = MF->getValue(Args);
    } else if (A->getOption().matches(options::OPT_M) ||
               A->getOption().matches(options::OPT_MM)) {
      DepFile = "-";
    } else {
      DepFile = darwin::CC1::getDependencyFileName(Args, Inputs);
    }
    CmdArgs.push_back("-dependency-file");
    CmdArgs.push_back(DepFile);

    // Add an -MT option if the user didn't specify their own.
    //
    // FIXME: This should use -MQ, when we support it.
    if (!Args.hasArg(options::OPT_MT) && !Args.hasArg(options::OPT_MQ)) {
      const char *DepTarget;

      // If user provided -o, that is the dependency target, except
      // when we are only generating a dependency file.
      Arg *OutputOpt = Args.getLastArg(options::OPT_o);
      if (OutputOpt && Output.getType() != types::TY_Dependencies) {
        DepTarget = OutputOpt->getValue(Args);
      } else {
        // Otherwise derive from the base input.
        //
        // FIXME: This should use the computed output file location.
        llvm::sys::Path P(Inputs[0].getBaseInput());

        P.eraseSuffix();
        P.appendSuffix("o");
        DepTarget = Args.MakeArgString(P.getLast());
      }

      CmdArgs.push_back("-MT");
      CmdArgs.push_back(DepTarget);
    }

    if (A->getOption().matches(options::OPT_M) ||
        A->getOption().matches(options::OPT_MD))
      CmdArgs.push_back("-sys-header-deps");
  }

  Args.AddLastArg(CmdArgs, options::OPT_MP);
  Args.AddAllArgs(CmdArgs, options::OPT_MT);

  // Add -i* options, and automatically translate to
  // -include-pch/-include-pth for transparent PCH support. It's
  // wonky, but we include looking for .gch so we can support seamless
  // replacement into a build system already set up to be generating
  // .gch files.
  for (arg_iterator it = Args.filtered_begin(options::OPT_clang_i_Group),
         ie = Args.filtered_end(); it != ie; ++it) {
    const Arg *A = it;

    if (A->getOption().matches(options::OPT_include)) {
      // Use PCH if the user requested it, except for C++ (for now).
      bool UsePCH = D.CCCUsePCH;
      if (types::isCXX(Inputs[0].getType()))
        UsePCH = false;

      bool FoundPTH = false;
      bool FoundPCH = false;
      llvm::sys::Path P(A->getValue(Args));
      if (UsePCH) {
        P.appendSuffix("pch");
        if (P.exists())
          FoundPCH = true;
        else
          P.eraseSuffix();
      }

      if (!FoundPCH) {
        P.appendSuffix("pth");
        if (P.exists())
          FoundPTH = true;
        else
          P.eraseSuffix();
      }

      if (!FoundPCH && !FoundPTH) {
        P.appendSuffix("gch");
        if (P.exists()) {
          FoundPCH = UsePCH;
          FoundPTH = !UsePCH;
        }
        else
          P.eraseSuffix();
      }

      if (FoundPCH || FoundPTH) {
        A->claim();
        if (UsePCH)
          CmdArgs.push_back("-include-pch");
        else
          CmdArgs.push_back("-include-pth");
        CmdArgs.push_back(Args.MakeArgString(P.str()));
        continue;
      }
    }

    // Not translated, render as usual.
    A->claim();
    A->render(Args, CmdArgs);
  }

  Args.AddAllArgs(CmdArgs, options::OPT_D, options::OPT_U);
  Args.AddAllArgs(CmdArgs, options::OPT_I_Group, options::OPT_F);

  // Add -Wp, and -Xassembler if using the preprocessor.

  // FIXME: There is a very unfortunate problem here, some troubled
  // souls abuse -Wp, to pass preprocessor options in gcc syntax. To
  // really support that we would have to parse and then translate
  // those options. :(
  Args.AddAllArgValues(CmdArgs, options::OPT_Wp_COMMA,
                       options::OPT_Xpreprocessor);

  // -I- is a deprecated GCC feature, reject it.
  if (Arg *A = Args.getLastArg(options::OPT_I_))
    D.Diag(clang::diag::err_drv_I_dash_not_supported) << A->getAsString(Args);
}

/// getARMTargetCPU - Get the (LLVM) name of the ARM cpu we are targetting.
//
// FIXME: tblgen this.
static const char *getARMTargetCPU(const ArgList &Args) {
  // FIXME: Warn on inconsistent use of -mcpu and -march.

  // If we have -mcpu=, use that.
  if (Arg *A = Args.getLastArg(options::OPT_mcpu_EQ))
    return A->getValue(Args);

  // Otherwise, if we have -march= choose the base CPU for that arch.
  if (Arg *A = Args.getLastArg(options::OPT_march_EQ)) {
    llvm::StringRef MArch = A->getValue(Args);

    if (MArch == "armv2" || MArch == "armv2a")
      return "arm2";
    if (MArch == "armv3")
      return "arm6";
    if (MArch == "armv3m")
      return "arm7m";
    if (MArch == "armv4" || MArch == "armv4t")
      return "arm7tdmi";
    if (MArch == "armv5" || MArch == "armv5t")
      return "arm10tdmi";
    if (MArch == "armv5e" || MArch == "armv5te")
      return "arm1026ejs";
    if (MArch == "armv5tej")
      return "arm926ej-s";
    if (MArch == "armv6" || MArch == "armv6k")
      return "arm1136jf-s";
    if (MArch == "armv6j")
      return "arm1136j-s";
    if (MArch == "armv6z" || MArch == "armv6zk")
      return "arm1176jzf-s";
    if (MArch == "armv6t2")
      return "arm1156t2-s";
    if (MArch == "armv7" || MArch == "armv7a" || MArch == "armv7-a")
      return "cortex-a8";
    if (MArch == "armv7r" || MArch == "armv7-r")
      return "cortex-r4";
    if (MArch == "armv7m" || MArch == "armv7-m")
      return "cortex-m3";
    if (MArch == "ep9312")
      return "ep9312";
    if (MArch == "iwmmxt")
      return "iwmmxt";
    if (MArch == "xscale")
      return "xscale";
  }

  // Otherwise return the most base CPU LLVM supports.
  return "arm7tdmi";
}

/// getLLVMArchSuffixForARM - Get the LLVM arch name to use for a particular
/// CPU.
//
// FIXME: This is redundant with -mcpu, why does LLVM use this.
// FIXME: tblgen this, or kill it!
static const char *getLLVMArchSuffixForARM(llvm::StringRef CPU) {
  if (CPU == "arm7tdmi" || CPU == "arm7tdmi-s" || CPU == "arm710t" ||
      CPU == "arm720t" || CPU == "arm9" || CPU == "arm9tdmi" ||
      CPU == "arm920" || CPU == "arm920t" || CPU == "arm922t" ||
      CPU == "arm940t" || CPU == "ep9312")
    return "v4t";

  if (CPU == "arm10tdmi" || CPU == "arm1020t")
    return "v5";

  if (CPU == "arm9e" || CPU == "arm926ej-s" || CPU == "arm946e-s" ||
      CPU == "arm966e-s" || CPU == "arm968e-s" || CPU == "arm10e" ||
      CPU == "arm1020e" || CPU == "arm1022e" || CPU == "xscale" ||
      CPU == "iwmmxt")
    return "v5e";

  if (CPU == "arm1136j-s" || CPU == "arm1136jf-s" || CPU == "arm1176jz-s" ||
      CPU == "arm1176jzf-s" || CPU == "mpcorenovfp" || CPU == "mpcore")
    return "v6";

  if (CPU == "arm1156t2-s" || CPU == "arm1156t2f-s")
    return "v6t2";

  if (CPU == "cortex-a8" || CPU == "cortex-a9")
    return "v7";

  return "";
}

/// getLLVMTriple - Get the LLVM triple to use for a particular toolchain, which
/// may depend on command line arguments.
static std::string getLLVMTriple(const ToolChain &TC, const ArgList &Args) {
  switch (TC.getTriple().getArch()) {
  default:
    return TC.getTripleString();

  case llvm::Triple::arm:
  case llvm::Triple::thumb: {
    // FIXME: Factor into subclasses.
    llvm::Triple Triple = TC.getTriple();

    // Thumb2 is the default for V7 on Darwin.
    //
    // FIXME: Thumb should just be another -target-feaure, not in the triple.
    llvm::StringRef Suffix = getLLVMArchSuffixForARM(getARMTargetCPU(Args));
    bool ThumbDefault =
      (Suffix == "v7" && TC.getTriple().getOS() == llvm::Triple::Darwin);
    std::string ArchName = "arm";
    if (Args.hasFlag(options::OPT_mthumb, options::OPT_mno_thumb, ThumbDefault))
      ArchName = "thumb";
    Triple.setArchName(ArchName + Suffix.str());

    return Triple.getTriple();
  }
  }
}

// FIXME: Move to target hook.
static bool isSignedCharDefault(const llvm::Triple &Triple) {
  switch (Triple.getArch()) {
  default:
    return true;

  case llvm::Triple::ppc:
  case llvm::Triple::ppc64:
    if (Triple.getOS() == llvm::Triple::Darwin)
      return true;
    return false;

  case llvm::Triple::systemz:
    return false;
  }
}

void Clang::AddARMTargetArgs(const ArgList &Args,
                             ArgStringList &CmdArgs) const {
  const Driver &D = getToolChain().getDriver();

  // Select the ABI to use.
  //
  // FIXME: Support -meabi.
  const char *ABIName = 0;
  if (Arg *A = Args.getLastArg(options::OPT_mabi_EQ)) {
    ABIName = A->getValue(Args);
  } else {
    // Select the default based on the platform.
    switch (getToolChain().getTriple().getOS()) {
      // FIXME: Is this right for non-Darwin and non-Linux?
    default:
      ABIName = "aapcs";
      break;

    case llvm::Triple::Darwin:
      ABIName = "apcs-gnu";
      break;

    case llvm::Triple::Linux:
      ABIName = "aapcs-linux";
      break;
    }
  }
  CmdArgs.push_back("-target-abi");
  CmdArgs.push_back(ABIName);

  // Set the CPU based on -march= and -mcpu=.
  CmdArgs.push_back("-target-cpu");
  CmdArgs.push_back(getARMTargetCPU(Args));

  // Select the float ABI as determined by -msoft-float, -mhard-float, and
  // -mfloat-abi=.
  llvm::StringRef FloatABI;
  if (Arg *A = Args.getLastArg(options::OPT_msoft_float,
                               options::OPT_mhard_float,
                               options::OPT_mfloat_abi_EQ)) {
    if (A->getOption().matches(options::OPT_msoft_float))
      FloatABI = "soft";
    else if (A->getOption().matches(options::OPT_mhard_float))
      FloatABI = "hard";
    else {
      FloatABI = A->getValue(Args);
      if (FloatABI != "soft" && FloatABI != "softfp" && FloatABI != "hard") {
        D.Diag(clang::diag::err_drv_invalid_mfloat_abi)
          << A->getAsString(Args);
        FloatABI = "soft";
      }
    }
  }

  // If unspecified, choose the default based on the platform.
  if (FloatABI.empty()) {
    // FIXME: This is wrong for non-Darwin, we don't have a mechanism yet for
    // distinguishing things like linux-eabi vs linux-elf.
    switch (getToolChain().getTriple().getOS()) {
    case llvm::Triple::Darwin: {
      // Darwin defaults to "softfp" for v6 and v7.
      //
      // FIXME: Factor out an ARM class so we can cache the arch somewhere.
      llvm::StringRef ArchName = getLLVMArchSuffixForARM(getARMTargetCPU(Args));
      if (ArchName.startswith("v6") || ArchName.startswith("v7"))
        FloatABI = "softfp";
      else
        FloatABI = "soft";
      break;
    }

    default:
      // Assume "soft", but warn the user we are guessing.
      FloatABI = "soft";
      D.Diag(clang::diag::warn_drv_assuming_mfloat_abi_is) << "soft";
      break;
    }
  }

  if (FloatABI == "soft") {
    // Floating point operations and argument passing are soft.
    //
    // FIXME: This changes CPP defines, we need -target-soft-float.
    CmdArgs.push_back("-msoft-float");
    CmdArgs.push_back("-mfloat-abi");
    CmdArgs.push_back("soft");
  } else if (FloatABI == "softfp") {
    // Floating point operations are hard, but argument passing is soft.
    CmdArgs.push_back("-mfloat-abi");
    CmdArgs.push_back("soft");
  } else {
    // Floating point operations and argument passing are hard.
    assert(FloatABI == "hard" && "Invalid float abi!");
    CmdArgs.push_back("-mfloat-abi");
    CmdArgs.push_back("hard");
  }

  // Set appropriate target features for floating point mode.
  //
  // FIXME: Note, this is a hack, the LLVM backend doesn't actually use these
  // yet (it uses the -mfloat-abi and -msoft-float options above), and it is
  // stripped out by the ARM target.

  // Use software floating point operations?
  if (FloatABI == "soft") {
    CmdArgs.push_back("-target-feature");
    CmdArgs.push_back("+soft-float");
  }

  // Use software floating point argument passing?
  if (FloatABI != "hard") {
    CmdArgs.push_back("-target-feature");
    CmdArgs.push_back("+soft-float-abi");
  }

  // Honor -mfpu=.
  //
  // FIXME: Centralize feature selection, defaulting shouldn't be also in the
  // frontend target.
  if (const Arg *A = Args.getLastArg(options::OPT_mfpu_EQ)) {
    llvm::StringRef FPU = A->getValue(Args);

    // Set the target features based on the FPU.
    if (FPU == "fpa" || FPU == "fpe2" || FPU == "fpe3" || FPU == "maverick") {
      // Disable any default FPU support.
      CmdArgs.push_back("-target-feature");
      CmdArgs.push_back("-vfp2");
      CmdArgs.push_back("-target-feature");
      CmdArgs.push_back("-vfp3");
      CmdArgs.push_back("-target-feature");
      CmdArgs.push_back("-neon");
    } else if (FPU == "vfp") {
      CmdArgs.push_back("-target-feature");
      CmdArgs.push_back("+vfp2");
    } else if (FPU == "vfp3") {
      CmdArgs.push_back("-target-feature");
      CmdArgs.push_back("+vfp3");
    } else if (FPU == "neon") {
      CmdArgs.push_back("-target-feature");
      CmdArgs.push_back("+neon");
    } else
      D.Diag(clang::diag::err_drv_clang_unsupported) << A->getAsString(Args);
  }
}

void Clang::AddMIPSTargetArgs(const ArgList &Args,
                             ArgStringList &CmdArgs) const {
  const Driver &D = getToolChain().getDriver();

  // Select the ABI to use.
  const char *ABIName = 0;
  if (Arg *A = Args.getLastArg(options::OPT_mabi_EQ)) {
    ABIName = A->getValue(Args);
  } else {
    ABIName = "o32";
  }

  CmdArgs.push_back("-target-abi");
  CmdArgs.push_back(ABIName);

  if (const Arg *A = Args.getLastArg(options::OPT_march_EQ)) {
    llvm::StringRef MArch = A->getValue(Args);
    CmdArgs.push_back("-target-cpu");

    if ((MArch == "r2000") || (MArch == "r3000"))
      CmdArgs.push_back("mips1");
    else if (MArch == "r6000")
      CmdArgs.push_back("mips2");
    else
      CmdArgs.push_back(MArch.str().c_str());
  }

  // Select the float ABI as determined by -msoft-float, -mhard-float, and
  llvm::StringRef FloatABI;
  if (Arg *A = Args.getLastArg(options::OPT_msoft_float,
                               options::OPT_mhard_float)) {
    if (A->getOption().matches(options::OPT_msoft_float))
      FloatABI = "soft";
    else if (A->getOption().matches(options::OPT_mhard_float))
      FloatABI = "hard";
  }

  // If unspecified, choose the default based on the platform.
  if (FloatABI.empty()) {
    switch (getToolChain().getTriple().getOS()) {
    default:
      // Assume "soft", but warn the user we are guessing.
      FloatABI = "soft";
      D.Diag(clang::diag::warn_drv_assuming_mfloat_abi_is) << "soft";
      break;
    }
  }

  if (FloatABI == "soft") {
    // Floating point operations and argument passing are soft.
    //
    // FIXME: This changes CPP defines, we need -target-soft-float.
    CmdArgs.push_back("-msoft-float");
  } else {
    assert(FloatABI == "hard" && "Invalid float abi!");
    CmdArgs.push_back("-mhard-float");
  }
}

void Clang::AddX86TargetArgs(const ArgList &Args,
                             ArgStringList &CmdArgs) const {
  if (!Args.hasFlag(options::OPT_mred_zone,
                    options::OPT_mno_red_zone,
                    true) ||
      Args.hasArg(options::OPT_mkernel) ||
      Args.hasArg(options::OPT_fapple_kext))
    CmdArgs.push_back("-disable-red-zone");

  if (Args.hasFlag(options::OPT_msoft_float,
                   options::OPT_mno_soft_float,
                   false))
    CmdArgs.push_back("-no-implicit-float");

  const char *CPUName = 0;
  if (const Arg *A = Args.getLastArg(options::OPT_march_EQ)) {
    if (llvm::StringRef(A->getValue(Args)) == "native") {
      // FIXME: Reject attempts to use -march=native unless the target matches
      // the host.
      //
      // FIXME: We should also incorporate the detected target features for use
      // with -native.
      std::string CPU = llvm::sys::getHostCPUName();
      if (!CPU.empty())
        CPUName = Args.MakeArgString(CPU);
    } else
      CPUName = A->getValue(Args);
  }

  // Select the default CPU if none was given (or detection failed).
  if (!CPUName) {
    // FIXME: Need target hooks.
    if (getToolChain().getOS().startswith("darwin")) {
      if (getToolChain().getArchName() == "x86_64")
        CPUName = "core2";
      else if (getToolChain().getArchName() == "i386")
        CPUName = "yonah";
    } else {
      if (getToolChain().getArchName() == "x86_64")
        CPUName = "x86-64";
      else if (getToolChain().getArchName() == "i386")
        CPUName = "pentium4";
    }
  }

  if (CPUName) {
    CmdArgs.push_back("-target-cpu");
    CmdArgs.push_back(CPUName);
  }

  for (arg_iterator it = Args.filtered_begin(options::OPT_m_x86_Features_Group),
         ie = Args.filtered_end(); it != ie; ++it) {
    llvm::StringRef Name = it->getOption().getName();
    it->claim();

    // Skip over "-m".
    assert(Name.startswith("-m") && "Invalid feature name.");
    Name = Name.substr(2);

    bool IsNegative = Name.startswith("no-");
    if (IsNegative)
      Name = Name.substr(3);

    CmdArgs.push_back("-target-feature");
    CmdArgs.push_back(Args.MakeArgString((IsNegative ? "-" : "+") + Name));
  }
}

static bool needsExceptions(const ArgList &Args,  types::ID InputType,
                            const llvm::Triple &Triple) {
  if (Arg *A = Args.getLastArg(options::OPT_fexceptions,
                               options::OPT_fno_exceptions)) {
    if (A->getOption().matches(options::OPT_fexceptions))
      return true;
    else
      return false;
  }
  switch (InputType) {
  case types::TY_CXX: case types::TY_CXXHeader:
  case types::TY_PP_CXX: case types::TY_PP_CXXHeader:
  case types::TY_ObjCXX: case types::TY_ObjCXXHeader:
  case types::TY_PP_ObjCXX: case types::TY_PP_ObjCXXHeader:
    return true;

  case types::TY_ObjC: case types::TY_ObjCHeader:
  case types::TY_PP_ObjC: case types::TY_PP_ObjCHeader:
    if (Args.hasArg(options::OPT_fobjc_nonfragile_abi))
      return true;
    if (Triple.getOS() != llvm::Triple::Darwin)
      return false;
    return (Triple.getDarwinMajorNumber() >= 9 &&
            Triple.getArch() == llvm::Triple::x86_64);

  default:
    return false;
  }
}

/// getEffectiveClangTriple - Get the "effective" target triple, which is the
/// triple for the target but with the OS version potentially modified for
/// Darwin's -mmacosx-version-min.
static std::string getEffectiveClangTriple(const Driver &D,
                                           const ToolChain &TC,
                                           const ArgList &Args) {
  llvm::Triple Triple(getLLVMTriple(TC, Args));

  // Handle -mmacosx-version-min and -miphoneos-version-min.
  if (Triple.getOS() != llvm::Triple::Darwin) {
    // Diagnose use of -mmacosx-version-min and -miphoneos-version-min on
    // non-Darwin.
    if (Arg *A = Args.getLastArg(options::OPT_mmacosx_version_min_EQ,
                                 options::OPT_miphoneos_version_min_EQ))
      D.Diag(clang::diag::err_drv_clang_unsupported) << A->getAsString(Args);
  } else {
    const toolchains::Darwin &DarwinTC(
      reinterpret_cast<const toolchains::Darwin&>(TC));
    unsigned Version[3];
    DarwinTC.getTargetVersion(Version);

    // Mangle the target version into the OS triple component.  For historical
    // reasons that make little sense, the version passed here is the "darwin"
    // version, which drops the 10 and offsets by 4. See inverse code when
    // setting the OS version preprocessor define.
    if (!DarwinTC.isTargetIPhoneOS()) {
      Version[0] = Version[1] + 4;
      Version[1] = Version[2];
      Version[2] = 0;
    } else {
      // Use the environment to communicate that we are targetting iPhoneOS.
      Triple.setEnvironmentName("iphoneos");
    }

    llvm::SmallString<16> Str;
    llvm::raw_svector_ostream(Str) << "darwin" << Version[0]
                                   << "." << Version[1] << "." << Version[2];
    Triple.setOSName(Str.str());
  }

  return Triple.getTriple();
}

void Clang::ConstructJob(Compilation &C, const JobAction &JA,
                         Job &Dest,
                         const InputInfo &Output,
                         const InputInfoList &Inputs,
                         const ArgList &Args,
                         const char *LinkingOutput) const {
  const Driver &D = getToolChain().getDriver();
  ArgStringList CmdArgs;

  assert(Inputs.size() == 1 && "Unable to handle multiple inputs.");

  // Invoke ourselves in -cc1 mode.
  //
  // FIXME: Implement custom jobs for internal actions.
  CmdArgs.push_back("-cc1");

  // Add the "effective" target triple.
  CmdArgs.push_back("-triple");
  std::string TripleStr = getEffectiveClangTriple(D, getToolChain(), Args);
  CmdArgs.push_back(Args.MakeArgString(TripleStr));

  // Select the appropriate action.
  if (isa<AnalyzeJobAction>(JA)) {
    assert(JA.getType() == types::TY_Plist && "Invalid output type.");
    CmdArgs.push_back("-analyze");
  } else if (isa<PreprocessJobAction>(JA)) {
    if (Output.getType() == types::TY_Dependencies)
      CmdArgs.push_back("-Eonly");
    else
      CmdArgs.push_back("-E");
  } else if (isa<AssembleJobAction>(JA)) {
    CmdArgs.push_back("-emit-obj");
  } else if (isa<PrecompileJobAction>(JA)) {
    // Use PCH if the user requested it, except for C++ (for now).
    bool UsePCH = D.CCCUsePCH;
    if (types::isCXX(Inputs[0].getType()))
      UsePCH = false;

    if (UsePCH)
      CmdArgs.push_back("-emit-pch");
    else
      CmdArgs.push_back("-emit-pth");
  } else {
    assert(isa<CompileJobAction>(JA) && "Invalid action for clang tool.");

    if (JA.getType() == types::TY_Nothing) {
      CmdArgs.push_back("-fsyntax-only");
    } else if (JA.getType() == types::TY_LLVMAsm) {
      CmdArgs.push_back("-emit-llvm");
    } else if (JA.getType() == types::TY_LLVMBC) {
      CmdArgs.push_back("-emit-llvm-bc");
    } else if (JA.getType() == types::TY_PP_Asm) {
      CmdArgs.push_back("-S");
    } else if (JA.getType() == types::TY_AST) {
      CmdArgs.push_back("-emit-pch");
    } else if (JA.getType() == types::TY_RewrittenObjC) {
      CmdArgs.push_back("-rewrite-objc");
    } else {
      assert(JA.getType() == types::TY_PP_Asm &&
             "Unexpected output type!");
    }
  }

  // The make clang go fast button.
  CmdArgs.push_back("-disable-free");

  // Disable the verification pass in -asserts builds.
#ifdef NDEBUG
  CmdArgs.push_back("-disable-llvm-verifier");
#endif

  // Set the main file name, so that debug info works even with
  // -save-temps.
  CmdArgs.push_back("-main-file-name");
  CmdArgs.push_back(darwin::CC1::getBaseInputName(Args, Inputs));

  // Some flags which affect the language (via preprocessor
  // defines). See darwin::CC1::AddCPPArgs.
  if (Args.hasArg(options::OPT_static))
    CmdArgs.push_back("-static-define");

  if (isa<AnalyzeJobAction>(JA)) {
    // Enable region store model by default.
    CmdArgs.push_back("-analyzer-store=region");

    // Treat blocks as analysis entry points.
    CmdArgs.push_back("-analyzer-opt-analyze-nested-blocks");

    // Add default argument set.
    if (!Args.hasArg(options::OPT__analyzer_no_default_checks)) {
      CmdArgs.push_back("-analyzer-check-dead-stores");
      CmdArgs.push_back("-analyzer-check-security-syntactic");
      CmdArgs.push_back("-analyzer-check-objc-mem");
      CmdArgs.push_back("-analyzer-eagerly-assume");
      CmdArgs.push_back("-analyzer-check-objc-methodsigs");
      // Do not enable the missing -dealloc check.
      // '-analyzer-check-objc-missing-dealloc',
      CmdArgs.push_back("-analyzer-check-objc-unused-ivars");
    }

    // Set the output format. The default is plist, for (lame) historical
    // reasons.
    CmdArgs.push_back("-analyzer-output");
    if (Arg *A = Args.getLastArg(options::OPT__analyzer_output))
      CmdArgs.push_back(A->getValue(Args));
    else
      CmdArgs.push_back("plist");

    // Add -Xanalyzer arguments when running as analyzer.
    Args.AddAllArgValues(CmdArgs, options::OPT_Xanalyzer);
  }

  CheckCodeGenerationOptions(D, Args);

  // Perform argument translation for LLVM backend. This
  // takes some care in reconciling with llvm-gcc. The
  // issue is that llvm-gcc translates these options based on
  // the values in cc1, whereas we are processing based on
  // the driver arguments.

  // This comes from the default translation the driver + cc1
  // would do to enable flag_pic.
  //
  // FIXME: Centralize this code.
  bool PICEnabled = (Args.hasArg(options::OPT_fPIC) ||
                     Args.hasArg(options::OPT_fpic) ||
                     Args.hasArg(options::OPT_fPIE) ||
                     Args.hasArg(options::OPT_fpie));
  bool PICDisabled = (Args.hasArg(options::OPT_mkernel) ||
                      Args.hasArg(options::OPT_static));
  const char *Model = getToolChain().GetForcedPicModel();
  if (!Model) {
    if (Args.hasArg(options::OPT_mdynamic_no_pic))
      Model = "dynamic-no-pic";
    else if (PICDisabled)
      Model = "static";
    else if (PICEnabled)
      Model = "pic";
    else
      Model = getToolChain().GetDefaultRelocationModel();
  }
  if (llvm::StringRef(Model) != "pic") {
    CmdArgs.push_back("-mrelocation-model");
    CmdArgs.push_back(Model);
  }

  // Infer the __PIC__ value.
  //
  // FIXME:  This isn't quite right on Darwin, which always sets
  // __PIC__=2.
  if (strcmp(Model, "pic") == 0 || strcmp(Model, "dynamic-no-pic") == 0) {
    CmdArgs.push_back("-pic-level");
    CmdArgs.push_back(Args.hasArg(options::OPT_fPIC) ? "2" : "1");
  }
  if (!Args.hasFlag(options::OPT_fmerge_all_constants,
                    options::OPT_fno_merge_all_constants))
    CmdArgs.push_back("-no-merge-all-constants");

  // LLVM Code Generator Options.

  // FIXME: Set --enable-unsafe-fp-math.
  if (Args.hasFlag(options::OPT_fno_omit_frame_pointer,
                   options::OPT_fomit_frame_pointer))
    CmdArgs.push_back("-mdisable-fp-elim");
  if (!Args.hasFlag(options::OPT_fzero_initialized_in_bss,
                    options::OPT_fno_zero_initialized_in_bss))
    CmdArgs.push_back("-mno-zero-initialized-in-bss");
  if (Args.hasArg(options::OPT_dA) || Args.hasArg(options::OPT_fverbose_asm))
    CmdArgs.push_back("-masm-verbose");
  if (Args.hasArg(options::OPT_fdebug_pass_structure)) {
    CmdArgs.push_back("-mdebug-pass");
    CmdArgs.push_back("Structure");
  }
  if (Args.hasArg(options::OPT_fdebug_pass_arguments)) {
    CmdArgs.push_back("-mdebug-pass");
    CmdArgs.push_back("Arguments");
  }

  // Enable -mconstructor-aliases except on darwin, where we have to
  // work around a linker bug;  see <rdar://problem/7651567>.
  if (getToolChain().getTriple().getOS() != llvm::Triple::Darwin)
    CmdArgs.push_back("-mconstructor-aliases");

  // This is a coarse approximation of what llvm-gcc actually does, both
  // -fasynchronous-unwind-tables and -fnon-call-exceptions interact in more
  // complicated ways.
  bool AsynchronousUnwindTables =
    Args.hasFlag(options::OPT_fasynchronous_unwind_tables,
                 options::OPT_fno_asynchronous_unwind_tables,
                 getToolChain().IsUnwindTablesDefault() &&
                 !Args.hasArg(options::OPT_mkernel));
  if (Args.hasFlag(options::OPT_funwind_tables, options::OPT_fno_unwind_tables,
                   AsynchronousUnwindTables))
    CmdArgs.push_back("-munwind-tables");

  if (Arg *A = Args.getLastArg(options::OPT_flimited_precision_EQ)) {
    CmdArgs.push_back("-mlimit-float-precision");
    CmdArgs.push_back(A->getValue(Args));
  }

  // FIXME: Handle -mtune=.
  (void) Args.hasArg(options::OPT_mtune_EQ);

  if (Arg *A = Args.getLastArg(options::OPT_mcmodel_EQ)) {
    CmdArgs.push_back("-mcode-model");
    CmdArgs.push_back(A->getValue(Args));
  }

  // Add target specific cpu and features flags.
  switch(getToolChain().getTriple().getArch()) {
  default:
    break;

  case llvm::Triple::arm:
  case llvm::Triple::thumb:
    AddARMTargetArgs(Args, CmdArgs);
    break;

  case llvm::Triple::mips:
  case llvm::Triple::mipsel:
    AddMIPSTargetArgs(Args, CmdArgs);
    break;

  case llvm::Triple::x86:
  case llvm::Triple::x86_64:
    AddX86TargetArgs(Args, CmdArgs);
    break;
  }

  // -fno-math-errno is default.
  if (Args.hasFlag(options::OPT_fmath_errno,
                   options::OPT_fno_math_errno,
                   false))
    CmdArgs.push_back("-fmath-errno");

  Arg *Unsupported;
  if ((Unsupported = Args.getLastArg(options::OPT_MG)) ||
      (Unsupported = Args.getLastArg(options::OPT_MQ)) ||
      (Unsupported = Args.getLastArg(options::OPT_iframework)) ||
      (Unsupported = Args.getLastArg(options::OPT_fshort_enums)))
    D.Diag(clang::diag::err_drv_clang_unsupported)
      << Unsupported->getOption().getName();

  Args.AddAllArgs(CmdArgs, options::OPT_v);
  Args.AddLastArg(CmdArgs, options::OPT_P);
  Args.AddLastArg(CmdArgs, options::OPT_print_ivar_layout);

  // Special case debug options to only pass -g to clang. This is
  // wrong.
  if (Args.hasArg(options::OPT_g_Group))
    CmdArgs.push_back("-g");

  Args.AddLastArg(CmdArgs, options::OPT_nostdinc);
  Args.AddLastArg(CmdArgs, options::OPT_nobuiltininc);

  // Pass the path to compiler resource files.
  CmdArgs.push_back("-resource-dir");
  CmdArgs.push_back(D.ResourceDir.c_str());

  // Add preprocessing options like -I, -D, etc. if we are using the
  // preprocessor.
  //
  // FIXME: Support -fpreprocessed
  types::ID InputType = Inputs[0].getType();
  if (types::getPreprocessedType(InputType) != types::TY_INVALID)
    AddPreprocessingOptions(D, Args, CmdArgs, Output, Inputs);

  // Manually translate -O to -O2 and -O4 to -O3; let clang reject
  // others.
  if (Arg *A = Args.getLastArg(options::OPT_O_Group)) {
    if (A->getOption().matches(options::OPT_O4))
      CmdArgs.push_back("-O3");
    else if (A->getValue(Args)[0] == '\0')
      CmdArgs.push_back("-O2");
    else
      A->render(Args, CmdArgs);
  }

  Args.AddAllArgs(CmdArgs, options::OPT_W_Group);
  Args.AddLastArg(CmdArgs, options::OPT_pedantic);
  Args.AddLastArg(CmdArgs, options::OPT_pedantic_errors);
  Args.AddLastArg(CmdArgs, options::OPT_w);

  // Handle -{std, ansi, trigraphs} -- take the last of -{std, ansi}
  // (-ansi is equivalent to -std=c89).
  //
  // If a std is supplied, only add -trigraphs if it follows the
  // option.
  if (Arg *Std = Args.getLastArg(options::OPT_std_EQ, options::OPT_ansi)) {
    if (Std->getOption().matches(options::OPT_ansi))
      if (types::isCXX(InputType))
        CmdArgs.push_back("-std=c++98");
      else
        CmdArgs.push_back("-std=c89");
    else
      Std->render(Args, CmdArgs);

    if (Arg *A = Args.getLastArg(options::OPT_trigraphs))
      if (A->getIndex() > Std->getIndex())
        A->render(Args, CmdArgs);
  } else {
    // Honor -std-default.
    //
    // FIXME: Clang doesn't correctly handle -std= when the input language
    // doesn't match. For the time being just ignore this for C++ inputs;
    // eventually we want to do all the standard defaulting here instead of
    // splitting it between the driver and clang -cc1.
    if (!types::isCXX(InputType))
        Args.AddAllArgsTranslated(CmdArgs, options::OPT_std_default_EQ,
                                  "-std=", /*Joined=*/true);
    Args.AddLastArg(CmdArgs, options::OPT_trigraphs);
  }

  if (Arg *A = Args.getLastArg(options::OPT_ftemplate_depth_)) {
    CmdArgs.push_back("-ftemplate-depth");
    CmdArgs.push_back(A->getValue(Args));
  }

  if (Args.hasArg(options::OPT__relocatable_pch))
    CmdArgs.push_back("-relocatable-pch");

  if (Arg *A = Args.getLastArg(options::OPT_fconstant_string_class_EQ)) {
    CmdArgs.push_back("-fconstant-string-class");
    CmdArgs.push_back(A->getValue(Args));
  }

  if (Arg *A = Args.getLastArg(options::OPT_ftabstop_EQ)) {
    CmdArgs.push_back("-ftabstop");
    CmdArgs.push_back(A->getValue(Args));
  }

  // Pass -fmessage-length=.
  CmdArgs.push_back("-fmessage-length");
  if (Arg *A = Args.getLastArg(options::OPT_fmessage_length_EQ)) {
    CmdArgs.push_back(A->getValue(Args));
  } else {
    // If -fmessage-length=N was not specified, determine whether this is a
    // terminal and, if so, implicitly define -fmessage-length appropriately.
    unsigned N = llvm::sys::Process::StandardErrColumns();
    CmdArgs.push_back(Args.MakeArgString(llvm::Twine(N)));
  }

  if (const Arg *A = Args.getLastArg(options::OPT_fvisibility_EQ)) {
    CmdArgs.push_back("-fvisibility");
    CmdArgs.push_back(A->getValue(Args));
  }

  // Forward -f (flag) options which we can pass directly.
  Args.AddLastArg(CmdArgs, options::OPT_fcatch_undefined_behavior);
  Args.AddLastArg(CmdArgs, options::OPT_femit_all_decls);
  Args.AddLastArg(CmdArgs, options::OPT_ffreestanding);
  Args.AddLastArg(CmdArgs, options::OPT_fheinous_gnu_extensions);
  Args.AddLastArg(CmdArgs, options::OPT_flax_vector_conversions);
  Args.AddLastArg(CmdArgs, options::OPT_fno_caret_diagnostics);
  Args.AddLastArg(CmdArgs, options::OPT_fno_show_column);
  Args.AddLastArg(CmdArgs, options::OPT_fobjc_gc_only);
  Args.AddLastArg(CmdArgs, options::OPT_fobjc_gc);
  Args.AddLastArg(CmdArgs, options::OPT_fobjc_sender_dependent_dispatch);
  Args.AddLastArg(CmdArgs, options::OPT_fdiagnostics_print_source_range_info);
  Args.AddLastArg(CmdArgs, options::OPT_ftime_report);
  Args.AddLastArg(CmdArgs, options::OPT_ftrapv);
  Args.AddLastArg(CmdArgs, options::OPT_fwritable_strings);

  Args.AddLastArg(CmdArgs, options::OPT_pthread);

  // -stack-protector=0 is default.
  unsigned StackProtectorLevel = 0;
  if (Arg *A = Args.getLastArg(options::OPT_fno_stack_protector,
                               options::OPT_fstack_protector_all,
                               options::OPT_fstack_protector)) {
    if (A->getOption().matches(options::OPT_fstack_protector))
      StackProtectorLevel = 1;
    else if (A->getOption().matches(options::OPT_fstack_protector_all))
      StackProtectorLevel = 2;
  } else
    StackProtectorLevel = getToolChain().GetDefaultStackProtectorLevel();
  if (StackProtectorLevel) {
    CmdArgs.push_back("-stack-protector");
    CmdArgs.push_back(Args.MakeArgString(llvm::Twine(StackProtectorLevel)));
  }

  // Forward -f options with positive and negative forms; we translate
  // these by hand.

  // -fbuiltin is default.
  if (!Args.hasFlag(options::OPT_fbuiltin, options::OPT_fno_builtin))
    CmdArgs.push_back("-fno-builtin");

  if (!Args.hasFlag(options::OPT_fassume_sane_operator_new,
                    options::OPT_fno_assume_sane_operator_new))
    CmdArgs.push_back("-fno-assume-sane-operator-new");

  // -fblocks=0 is default.
  if (Args.hasFlag(options::OPT_fblocks, options::OPT_fno_blocks,
                   getToolChain().IsBlocksDefault())) {
    CmdArgs.push_back("-fblocks");
  }

  // -fexceptions=0 is default.
  if (needsExceptions(Args, InputType, getToolChain().getTriple()))
    CmdArgs.push_back("-fexceptions");

  if (getToolChain().UseSjLjExceptions())
    CmdArgs.push_back("-fsjlj-exceptions");

  // -frtti is default.
  if (!Args.hasFlag(options::OPT_frtti, options::OPT_fno_rtti))
    CmdArgs.push_back("-fno-rtti");

  // -fsigned-char is default.
  if (!Args.hasFlag(options::OPT_fsigned_char, options::OPT_funsigned_char,
                    isSignedCharDefault(getToolChain().getTriple())))
    CmdArgs.push_back("-fno-signed-char");

  // -fthreadsafe-static is default.
  if (!Args.hasFlag(options::OPT_fthreadsafe_statics, 
                    options::OPT_fno_threadsafe_statics))
    CmdArgs.push_back("-fno-threadsafe-statics");

  // -fms-extensions=0 is default.
  if (Args.hasFlag(options::OPT_fms_extensions, options::OPT_fno_ms_extensions,
                   getToolChain().getTriple().getOS() == llvm::Triple::Win32))
    CmdArgs.push_back("-fms-extensions");

  // -fnext-runtime is default.
  if (!Args.hasFlag(options::OPT_fnext_runtime, options::OPT_fgnu_runtime,
                    getToolChain().getTriple().getOS() == llvm::Triple::Darwin))
    CmdArgs.push_back("-fgnu-runtime");

  // -fobjc-nonfragile-abi=0 is default.
  if (types::isObjC(InputType)) {
    if (Args.hasArg(options::OPT_fobjc_nonfragile_abi) ||
        getToolChain().IsObjCNonFragileABIDefault()) {
      CmdArgs.push_back("-fobjc-nonfragile-abi");
      
      // -fobjc-legacy-dispatch is only relevant with the nonfragile-abi, and
      // defaults to off.
      if (Args.hasFlag(options::OPT_fobjc_legacy_dispatch,
                       options::OPT_fno_objc_legacy_dispatch,
                       getToolChain().IsObjCLegacyDispatchDefault()))
        CmdArgs.push_back("-fobjc-legacy-dispatch");
    }
  }

  if (!Args.hasFlag(options::OPT_fassume_sane_operator_new,
                    options::OPT_fno_assume_sane_operator_new))
    CmdArgs.push_back("-fno-assume-sane-operator-new");

  // -fshort-wchar default varies depending on platform; only
  // pass if specified.
  if (Arg *A = Args.getLastArg(options::OPT_fshort_wchar)) {
    if (A->getOption().matches(options::OPT_fshort_wchar))
      CmdArgs.push_back("-fshort-wchar");
  }

  // -fno-pascal-strings is default, only pass non-default. If the tool chain
  // happened to translate to -mpascal-strings, we want to back translate here.
  //
  // FIXME: This is gross; that translation should be pulled from the
  // tool chain.
  if (Args.hasFlag(options::OPT_fpascal_strings,
                   options::OPT_fno_pascal_strings,
                   false) ||
      Args.hasFlag(options::OPT_mpascal_strings,
                   options::OPT_mno_pascal_strings,
                   false))
    CmdArgs.push_back("-fpascal-strings");

  // -fcommon is default, only pass non-default.
  if (!Args.hasFlag(options::OPT_fcommon, options::OPT_fno_common))
    CmdArgs.push_back("-fno-common");

  // -fsigned-bitfields is default, and clang doesn't yet support
  // --funsigned-bitfields.
  if (!Args.hasFlag(options::OPT_fsigned_bitfields,
                    options::OPT_funsigned_bitfields))
    D.Diag(clang::diag::warn_drv_clang_unsupported)
      << Args.getLastArg(options::OPT_funsigned_bitfields)->getAsString(Args);

  // -fdiagnostics-fixit-info is default, only pass non-default.
  if (!Args.hasFlag(options::OPT_fdiagnostics_fixit_info,
                    options::OPT_fno_diagnostics_fixit_info))
    CmdArgs.push_back("-fno-diagnostics-fixit-info");

  Args.AddLastArg(CmdArgs, options::OPT_fdiagnostics_binary);

  // Enable -fdiagnostics-show-option by default.
  if (Args.hasFlag(options::OPT_fdiagnostics_show_option,
                   options::OPT_fno_diagnostics_show_option))
    CmdArgs.push_back("-fdiagnostics-show-option");

  // Color diagnostics are the default, unless the terminal doesn't support
  // them.
  if (Args.hasFlag(options::OPT_fcolor_diagnostics,
                   options::OPT_fno_color_diagnostics) &&
      llvm::sys::Process::StandardErrHasColors())
    CmdArgs.push_back("-fcolor-diagnostics");

  if (!Args.hasFlag(options::OPT_fshow_source_location,
                    options::OPT_fno_show_source_location))
    CmdArgs.push_back("-fno-show-source-location");

  // -fdollars-in-identifiers default varies depending on platform and
  // language; only pass if specified.
  if (Arg *A = Args.getLastArg(options::OPT_fdollars_in_identifiers,
                               options::OPT_fno_dollars_in_identifiers)) {
    if (A->getOption().matches(options::OPT_fdollars_in_identifiers))
      CmdArgs.push_back("-fdollars-in-identifiers");
    else
      CmdArgs.push_back("-fno-dollars-in-identifiers");
  }

  // -funit-at-a-time is default, and we don't support -fno-unit-at-a-time for
  // practical purposes.
  if (Arg *A = Args.getLastArg(options::OPT_funit_at_a_time,
                               options::OPT_fno_unit_at_a_time)) {
    if (A->getOption().matches(options::OPT_fno_unit_at_a_time))
      D.Diag(clang::diag::warn_drv_clang_unsupported) << A->getAsString(Args);
  }

  // Default to -fno-builtin-str{cat,cpy} on Darwin for ARM.
  //
  // FIXME: This is disabled until clang -cc1 supports -fno-builtin-foo. PR4941.
#if 0
  if (getToolChain().getTriple().getOS() == llvm::Triple::Darwin &&
      (getToolChain().getTriple().getArch() == llvm::Triple::arm ||
       getToolChain().getTriple().getArch() == llvm::Triple::thumb)) {
    if (!Args.hasArg(options::OPT_fbuiltin_strcat))
      CmdArgs.push_back("-fno-builtin-strcat");
    if (!Args.hasArg(options::OPT_fbuiltin_strcpy))
      CmdArgs.push_back("-fno-builtin-strcpy");
  }
#endif

  if (Arg *A = Args.getLastArg(options::OPT_traditional,
                               options::OPT_traditional_cpp))
    D.Diag(clang::diag::err_drv_clang_unsupported) << A->getAsString(Args);

  Args.AddLastArg(CmdArgs, options::OPT_dM);
  Args.AddLastArg(CmdArgs, options::OPT_dD);

  Args.AddAllArgValues(CmdArgs, options::OPT_Xclang);
  Args.AddAllArgValues(CmdArgs, options::OPT_mllvm);

  if (Output.getType() == types::TY_Dependencies) {
    // Handled with other dependency code.
  } else if (Output.isPipe()) {
    CmdArgs.push_back("-o");
    CmdArgs.push_back("-");
  } else if (Output.isFilename()) {
    CmdArgs.push_back("-o");
    CmdArgs.push_back(Output.getFilename());
  } else {
    assert(Output.isNothing() && "Invalid output.");
  }

  for (InputInfoList::const_iterator
         it = Inputs.begin(), ie = Inputs.end(); it != ie; ++it) {
    const InputInfo &II = *it;
    CmdArgs.push_back("-x");
    CmdArgs.push_back(types::getTypeName(II.getType()));
    if (II.isPipe())
      CmdArgs.push_back("-");
    else if (II.isFilename())
      CmdArgs.push_back(II.getFilename());
    else
      II.getInputArg().renderAsInput(Args, CmdArgs);
  }

  Args.AddAllArgs(CmdArgs, options::OPT_undef);

  const char *Exec =
    Args.MakeArgString(getToolChain().GetProgramPath(C, "clang"));

  // Optionally embed the -cc1 level arguments into the debug info, for build
  // analysis.
  if (getToolChain().UseDwarfDebugFlags()) {
    llvm::SmallString<256> Flags;
    Flags += Exec;
    for (unsigned i = 0, e = CmdArgs.size(); i != e; ++i) {
      Flags += " ";
      Flags += CmdArgs[i];
    }
    CmdArgs.push_back("-dwarf-debug-flags");
    CmdArgs.push_back(Args.MakeArgString(Flags.str()));
  }

  Dest.addCommand(new Command(JA, *this, Exec, CmdArgs));

  // Explicitly warn that these options are unsupported, even though
  // we are allowing compilation to continue.
  for (arg_iterator it = Args.filtered_begin(options::OPT_pg),
         ie = Args.filtered_end(); it != ie; ++it) {
    it->claim();
    D.Diag(clang::diag::warn_drv_clang_unsupported) << it->getAsString(Args);
  }

  // Claim some arguments which clang supports automatically.

  // -fpch-preprocess is used with gcc to add a special marker in the
  // -output to include the PCH file. Clang's PTH solution is
  // -completely transparent, so we do not need to deal with it at
  // -all.
  Args.ClaimAllArgs(options::OPT_fpch_preprocess);

  // Claim some arguments which clang doesn't support, but we don't
  // care to warn the user about.
  Args.ClaimAllArgs(options::OPT_clang_ignored_f_Group);
  Args.ClaimAllArgs(options::OPT_clang_ignored_m_Group);
}

void gcc::Common::ConstructJob(Compilation &C, const JobAction &JA,
                               Job &Dest,
                               const InputInfo &Output,
                               const InputInfoList &Inputs,
                               const ArgList &Args,
                               const char *LinkingOutput) const {
  const Driver &D = getToolChain().getDriver();
  ArgStringList CmdArgs;

  for (ArgList::const_iterator
         it = Args.begin(), ie = Args.end(); it != ie; ++it) {
    Arg *A = *it;
    if (A->getOption().hasForwardToGCC()) {
      // It is unfortunate that we have to claim here, as this means
      // we will basically never report anything interesting for
      // platforms using a generic gcc, even if we are just using gcc
      // to get to the assembler.
      A->claim();
      A->render(Args, CmdArgs);
    }
  }

  RenderExtraToolArgs(JA, CmdArgs);

  // If using a driver driver, force the arch.
  const std::string &Arch = getToolChain().getArchName();
  if (getToolChain().getTriple().getOS() == llvm::Triple::Darwin) {
    CmdArgs.push_back("-arch");

    // FIXME: Remove these special cases.
    if (Arch == "powerpc")
      CmdArgs.push_back("ppc");
    else if (Arch == "powerpc64")
      CmdArgs.push_back("ppc64");
    else
      CmdArgs.push_back(Args.MakeArgString(Arch));
  }

  // Try to force gcc to match the tool chain we want, if we recognize
  // the arch.
  //
  // FIXME: The triple class should directly provide the information we want
  // here.
  if (Arch == "i386" || Arch == "powerpc")
    CmdArgs.push_back("-m32");
  else if (Arch == "x86_64" || Arch == "powerpc64")
    CmdArgs.push_back("-m64");

  if (Output.isPipe()) {
    CmdArgs.push_back("-o");
    CmdArgs.push_back("-");
  } else if (Output.isFilename()) {
    CmdArgs.push_back("-o");
    CmdArgs.push_back(Output.getFilename());
  } else {
    assert(Output.isNothing() && "Unexpected output");
    CmdArgs.push_back("-fsyntax-only");
  }


  // Only pass -x if gcc will understand it; otherwise hope gcc
  // understands the suffix correctly. The main use case this would go
  // wrong in is for linker inputs if they happened to have an odd
  // suffix; really the only way to get this to happen is a command
  // like '-x foobar a.c' which will treat a.c like a linker input.
  //
  // FIXME: For the linker case specifically, can we safely convert
  // inputs into '-Wl,' options?
  for (InputInfoList::const_iterator
         it = Inputs.begin(), ie = Inputs.end(); it != ie; ++it) {
    const InputInfo &II = *it;

    // Don't try to pass LLVM or AST inputs to a generic gcc.
    if (II.getType() == types::TY_LLVMBC)
      D.Diag(clang::diag::err_drv_no_linker_llvm_support)
        << getToolChain().getTripleString();
    else if (II.getType() == types::TY_AST)
      D.Diag(clang::diag::err_drv_no_ast_support)
        << getToolChain().getTripleString();

    if (types::canTypeBeUserSpecified(II.getType())) {
      CmdArgs.push_back("-x");
      CmdArgs.push_back(types::getTypeName(II.getType()));
    }

    if (II.isPipe())
      CmdArgs.push_back("-");
    else if (II.isFilename())
      CmdArgs.push_back(II.getFilename());
    else
      // Don't render as input, we need gcc to do the translations.
      II.getInputArg().render(Args, CmdArgs);
  }

  const char *GCCName = getToolChain().getDriver().CCCGenericGCCName.c_str();
  const char *Exec =
    Args.MakeArgString(getToolChain().GetProgramPath(C, GCCName));
  Dest.addCommand(new Command(JA, *this, Exec, CmdArgs));
}

void gcc::Preprocess::RenderExtraToolArgs(const JobAction &JA,
                                          ArgStringList &CmdArgs) const {
  CmdArgs.push_back("-E");
}

void gcc::Precompile::RenderExtraToolArgs(const JobAction &JA,
                                          ArgStringList &CmdArgs) const {
  // The type is good enough.
}

void gcc::Compile::RenderExtraToolArgs(const JobAction &JA,
                                       ArgStringList &CmdArgs) const {
  const Driver &D = getToolChain().getDriver();

  // If -flto, etc. are present then make sure not to force assembly output.
  if (JA.getType() == types::TY_LLVMBC)
    CmdArgs.push_back("-c");
  else {
    if (JA.getType() != types::TY_PP_Asm)
      D.Diag(clang::diag::err_drv_invalid_gcc_output_type)
        << getTypeName(JA.getType());
      
    CmdArgs.push_back("-S");
  }
}

void gcc::Assemble::RenderExtraToolArgs(const JobAction &JA,
                                        ArgStringList &CmdArgs) const {
  CmdArgs.push_back("-c");
}

void gcc::Link::RenderExtraToolArgs(const JobAction &JA,
                                    ArgStringList &CmdArgs) const {
  // The types are (hopefully) good enough.
}

const char *darwin::CC1::getCC1Name(types::ID Type) const {
  switch (Type) {
  default:
    assert(0 && "Unexpected type for Darwin CC1 tool.");
  case types::TY_Asm:
  case types::TY_C: case types::TY_CHeader:
  case types::TY_PP_C: case types::TY_PP_CHeader:
    return "cc1";
  case types::TY_ObjC: case types::TY_ObjCHeader:
  case types::TY_PP_ObjC: case types::TY_PP_ObjCHeader:
    return "cc1obj";
  case types::TY_CXX: case types::TY_CXXHeader:
  case types::TY_PP_CXX: case types::TY_PP_CXXHeader:
    return "cc1plus";
  case types::TY_ObjCXX: case types::TY_ObjCXXHeader:
  case types::TY_PP_ObjCXX: case types::TY_PP_ObjCXXHeader:
    return "cc1objplus";
  }
}

const char *darwin::CC1::getBaseInputName(const ArgList &Args,
                                          const InputInfoList &Inputs) {
  llvm::sys::Path P(Inputs[0].getBaseInput());
  return Args.MakeArgString(P.getLast());
}

const char *darwin::CC1::getBaseInputStem(const ArgList &Args,
                                          const InputInfoList &Inputs) {
  const char *Str = getBaseInputName(Args, Inputs);

  if (const char *End = strchr(Str, '.'))
    return Args.MakeArgString(std::string(Str, End));

  return Str;
}

const char *
darwin::CC1::getDependencyFileName(const ArgList &Args,
                                   const InputInfoList &Inputs) {
  // FIXME: Think about this more.
  std::string Res;

  if (Arg *OutputOpt = Args.getLastArg(options::OPT_o)) {
    std::string Str(OutputOpt->getValue(Args));

    Res = Str.substr(0, Str.rfind('.'));
  } else
    Res = darwin::CC1::getBaseInputStem(Args, Inputs);

  return Args.MakeArgString(Res + ".d");
}

void darwin::CC1::AddCC1Args(const ArgList &Args,
                             ArgStringList &CmdArgs) const {
  const Driver &D = getToolChain().getDriver();

  CheckCodeGenerationOptions(D, Args);

  // Derived from cc1 spec.
  if (!Args.hasArg(options::OPT_mkernel) && !Args.hasArg(options::OPT_static) &&
      !Args.hasArg(options::OPT_mdynamic_no_pic))
    CmdArgs.push_back("-fPIC");

  if (getToolChain().getTriple().getArch() == llvm::Triple::arm ||
      getToolChain().getTriple().getArch() == llvm::Triple::thumb) {
    if (!Args.hasArg(options::OPT_fbuiltin_strcat))
      CmdArgs.push_back("-fno-builtin-strcat");
    if (!Args.hasArg(options::OPT_fbuiltin_strcpy))
      CmdArgs.push_back("-fno-builtin-strcpy");
  }

  // gcc has some code here to deal with when no -mmacosx-version-min
  // and no -miphoneos-version-min is present, but this never happens
  // due to tool chain specific argument translation.

  if (Args.hasArg(options::OPT_g_Flag) &&
      !Args.hasArg(options::OPT_fno_eliminate_unused_debug_symbols))
    CmdArgs.push_back("-feliminate-unused-debug-symbols");
}

void darwin::CC1::AddCC1OptionsArgs(const ArgList &Args, ArgStringList &CmdArgs,
                                    const InputInfoList &Inputs,
                                    const ArgStringList &OutputArgs) const {
  const Driver &D = getToolChain().getDriver();

  // Derived from cc1_options spec.
  if (Args.hasArg(options::OPT_fast) ||
      Args.hasArg(options::OPT_fastf) ||
      Args.hasArg(options::OPT_fastcp))
    CmdArgs.push_back("-O3");

  if (Arg *A = Args.getLastArg(options::OPT_pg))
    if (Args.hasArg(options::OPT_fomit_frame_pointer))
      D.Diag(clang::diag::err_drv_argument_not_allowed_with)
        << A->getAsString(Args) << "-fomit-frame-pointer";

  AddCC1Args(Args, CmdArgs);

  if (!Args.hasArg(options::OPT_Q))
    CmdArgs.push_back("-quiet");

  CmdArgs.push_back("-dumpbase");
  CmdArgs.push_back(darwin::CC1::getBaseInputName(Args, Inputs));

  Args.AddAllArgs(CmdArgs, options::OPT_d_Group);

  Args.AddAllArgs(CmdArgs, options::OPT_m_Group);
  Args.AddAllArgs(CmdArgs, options::OPT_a_Group);

  // FIXME: The goal is to use the user provided -o if that is our
  // final output, otherwise to drive from the original input
  // name. Find a clean way to go about this.
  if ((Args.hasArg(options::OPT_c) || Args.hasArg(options::OPT_S)) &&
      Args.hasArg(options::OPT_o)) {
    Arg *OutputOpt = Args.getLastArg(options::OPT_o);
    CmdArgs.push_back("-auxbase-strip");
    CmdArgs.push_back(OutputOpt->getValue(Args));
  } else {
    CmdArgs.push_back("-auxbase");
    CmdArgs.push_back(darwin::CC1::getBaseInputStem(Args, Inputs));
  }

  Args.AddAllArgs(CmdArgs, options::OPT_g_Group);

  Args.AddAllArgs(CmdArgs, options::OPT_O);
  // FIXME: -Wall is getting some special treatment. Investigate.
  Args.AddAllArgs(CmdArgs, options::OPT_W_Group, options::OPT_pedantic_Group);
  Args.AddLastArg(CmdArgs, options::OPT_w);
  Args.AddAllArgs(CmdArgs, options::OPT_std_EQ, options::OPT_ansi,
                  options::OPT_trigraphs);
  if (!Args.getLastArg(options::OPT_std_EQ, options::OPT_ansi)) {
    // Honor -std-default.
    Args.AddAllArgsTranslated(CmdArgs, options::OPT_std_default_EQ,
                              "-std=", /*Joined=*/true);
  }

  if (Args.hasArg(options::OPT_v))
    CmdArgs.push_back("-version");
  if (Args.hasArg(options::OPT_pg))
    CmdArgs.push_back("-p");
  Args.AddLastArg(CmdArgs, options::OPT_p);

  // The driver treats -fsyntax-only specially.
  if (getToolChain().getTriple().getArch() == llvm::Triple::arm ||
      getToolChain().getTriple().getArch() == llvm::Triple::thumb) {
    // Removes -fbuiltin-str{cat,cpy}; these aren't recognized by cc1 but are
    // used to inhibit the default -fno-builtin-str{cat,cpy}.
    //
    // FIXME: Should we grow a better way to deal with "removing" args?
    for (arg_iterator it = Args.filtered_begin(options::OPT_f_Group,
                                               options::OPT_fsyntax_only),
           ie = Args.filtered_end(); it != ie; ++it) {
      if (!it->getOption().matches(options::OPT_fbuiltin_strcat) &&
          !it->getOption().matches(options::OPT_fbuiltin_strcpy)) {
        it->claim();
        it->render(Args, CmdArgs);
      }
    }
  } else
    Args.AddAllArgs(CmdArgs, options::OPT_f_Group, options::OPT_fsyntax_only);

  Args.AddAllArgs(CmdArgs, options::OPT_undef);
  if (Args.hasArg(options::OPT_Qn))
    CmdArgs.push_back("-fno-ident");

  // FIXME: This isn't correct.
  //Args.AddLastArg(CmdArgs, options::OPT__help)
  //Args.AddLastArg(CmdArgs, options::OPT__targetHelp)

  CmdArgs.append(OutputArgs.begin(), OutputArgs.end());

  // FIXME: Still don't get what is happening here. Investigate.
  Args.AddAllArgs(CmdArgs, options::OPT__param);

  if (Args.hasArg(options::OPT_fmudflap) ||
      Args.hasArg(options::OPT_fmudflapth)) {
    CmdArgs.push_back("-fno-builtin");
    CmdArgs.push_back("-fno-merge-constants");
  }

  if (Args.hasArg(options::OPT_coverage)) {
    CmdArgs.push_back("-fprofile-arcs");
    CmdArgs.push_back("-ftest-coverage");
  }

  if (types::isCXX(Inputs[0].getType()))
    CmdArgs.push_back("-D__private_extern__=extern");
}

void darwin::CC1::AddCPPOptionsArgs(const ArgList &Args, ArgStringList &CmdArgs,
                                    const InputInfoList &Inputs,
                                    const ArgStringList &OutputArgs) const {
  // Derived from cpp_options
  AddCPPUniqueOptionsArgs(Args, CmdArgs, Inputs);

  CmdArgs.append(OutputArgs.begin(), OutputArgs.end());

  AddCC1Args(Args, CmdArgs);

  // NOTE: The code below has some commonality with cpp_options, but
  // in classic gcc style ends up sending things in different
  // orders. This may be a good merge candidate once we drop pedantic
  // compatibility.

  Args.AddAllArgs(CmdArgs, options::OPT_m_Group);
  Args.AddAllArgs(CmdArgs, options::OPT_std_EQ, options::OPT_ansi,
                  options::OPT_trigraphs);
  if (!Args.getLastArg(options::OPT_std_EQ, options::OPT_ansi)) {
    // Honor -std-default.
    Args.AddAllArgsTranslated(CmdArgs, options::OPT_std_default_EQ,
                              "-std=", /*Joined=*/true);
  }
  Args.AddAllArgs(CmdArgs, options::OPT_W_Group, options::OPT_pedantic_Group);
  Args.AddLastArg(CmdArgs, options::OPT_w);

  // The driver treats -fsyntax-only specially.
  Args.AddAllArgs(CmdArgs, options::OPT_f_Group, options::OPT_fsyntax_only);

  if (Args.hasArg(options::OPT_g_Group) && !Args.hasArg(options::OPT_g0) &&
      !Args.hasArg(options::OPT_fno_working_directory))
    CmdArgs.push_back("-fworking-directory");

  Args.AddAllArgs(CmdArgs, options::OPT_O);
  Args.AddAllArgs(CmdArgs, options::OPT_undef);
  if (Args.hasArg(options::OPT_save_temps))
    CmdArgs.push_back("-fpch-preprocess");
}

void darwin::CC1::AddCPPUniqueOptionsArgs(const ArgList &Args,
                                          ArgStringList &CmdArgs,
                                          const InputInfoList &Inputs) const {
  const Driver &D = getToolChain().getDriver();

  CheckPreprocessingOptions(D, Args);

  // Derived from cpp_unique_options.
  // -{C,CC} only with -E is checked in CheckPreprocessingOptions().
  Args.AddLastArg(CmdArgs, options::OPT_C);
  Args.AddLastArg(CmdArgs, options::OPT_CC);
  if (!Args.hasArg(options::OPT_Q))
    CmdArgs.push_back("-quiet");
  Args.AddAllArgs(CmdArgs, options::OPT_nostdinc);
  Args.AddLastArg(CmdArgs, options::OPT_v);
  Args.AddAllArgs(CmdArgs, options::OPT_I_Group, options::OPT_F);
  Args.AddLastArg(CmdArgs, options::OPT_P);

  // FIXME: Handle %I properly.
  if (getToolChain().getArchName() == "x86_64") {
    CmdArgs.push_back("-imultilib");
    CmdArgs.push_back("x86_64");
  }

  if (Args.hasArg(options::OPT_MD)) {
    CmdArgs.push_back("-MD");
    CmdArgs.push_back(darwin::CC1::getDependencyFileName(Args, Inputs));
  }

  if (Args.hasArg(options::OPT_MMD)) {
    CmdArgs.push_back("-MMD");
    CmdArgs.push_back(darwin::CC1::getDependencyFileName(Args, Inputs));
  }

  Args.AddLastArg(CmdArgs, options::OPT_M);
  Args.AddLastArg(CmdArgs, options::OPT_MM);
  Args.AddAllArgs(CmdArgs, options::OPT_MF);
  Args.AddLastArg(CmdArgs, options::OPT_MG);
  Args.AddLastArg(CmdArgs, options::OPT_MP);
  Args.AddAllArgs(CmdArgs, options::OPT_MQ);
  Args.AddAllArgs(CmdArgs, options::OPT_MT);
  if (!Args.hasArg(options::OPT_M) && !Args.hasArg(options::OPT_MM) &&
      (Args.hasArg(options::OPT_MD) || Args.hasArg(options::OPT_MMD))) {
    if (Arg *OutputOpt = Args.getLastArg(options::OPT_o)) {
      CmdArgs.push_back("-MQ");
      CmdArgs.push_back(OutputOpt->getValue(Args));
    }
  }

  Args.AddLastArg(CmdArgs, options::OPT_remap);
  if (Args.hasArg(options::OPT_g3))
    CmdArgs.push_back("-dD");
  Args.AddLastArg(CmdArgs, options::OPT_H);

  AddCPPArgs(Args, CmdArgs);

  Args.AddAllArgs(CmdArgs, options::OPT_D, options::OPT_U, options::OPT_A);
  Args.AddAllArgs(CmdArgs, options::OPT_i_Group);

  for (InputInfoList::const_iterator
         it = Inputs.begin(), ie = Inputs.end(); it != ie; ++it) {
    const InputInfo &II = *it;

    if (II.isPipe())
      CmdArgs.push_back("-");
    else
      CmdArgs.push_back(II.getFilename());
  }

  Args.AddAllArgValues(CmdArgs, options::OPT_Wp_COMMA,
                       options::OPT_Xpreprocessor);

  if (Args.hasArg(options::OPT_fmudflap)) {
    CmdArgs.push_back("-D_MUDFLAP");
    CmdArgs.push_back("-include");
    CmdArgs.push_back("mf-runtime.h");
  }

  if (Args.hasArg(options::OPT_fmudflapth)) {
    CmdArgs.push_back("-D_MUDFLAP");
    CmdArgs.push_back("-D_MUDFLAPTH");
    CmdArgs.push_back("-include");
    CmdArgs.push_back("mf-runtime.h");
  }
}

void darwin::CC1::AddCPPArgs(const ArgList &Args,
                             ArgStringList &CmdArgs) const {
  // Derived from cpp spec.

  if (Args.hasArg(options::OPT_static)) {
    // The gcc spec is broken here, it refers to dynamic but
    // that has been translated. Start by being bug compatible.

    // if (!Args.hasArg(arglist.parser.dynamicOption))
    CmdArgs.push_back("-D__STATIC__");
  } else
    CmdArgs.push_back("-D__DYNAMIC__");

  if (Args.hasArg(options::OPT_pthread))
    CmdArgs.push_back("-D_REENTRANT");
}

void darwin::Preprocess::ConstructJob(Compilation &C, const JobAction &JA,
                                      Job &Dest, const InputInfo &Output,
                                      const InputInfoList &Inputs,
                                      const ArgList &Args,
                                      const char *LinkingOutput) const {
  ArgStringList CmdArgs;

  assert(Inputs.size() == 1 && "Unexpected number of inputs!");

  CmdArgs.push_back("-E");

  if (Args.hasArg(options::OPT_traditional) ||
      Args.hasArg(options::OPT_traditional_cpp))
    CmdArgs.push_back("-traditional-cpp");

  ArgStringList OutputArgs;
  if (Output.isFilename()) {
    OutputArgs.push_back("-o");
    OutputArgs.push_back(Output.getFilename());
  } else {
    assert(Output.isPipe() && "Unexpected CC1 output.");
  }

  if (Args.hasArg(options::OPT_E)) {
    AddCPPOptionsArgs(Args, CmdArgs, Inputs, OutputArgs);
  } else {
    AddCPPOptionsArgs(Args, CmdArgs, Inputs, ArgStringList());
    CmdArgs.append(OutputArgs.begin(), OutputArgs.end());
  }

  Args.AddAllArgs(CmdArgs, options::OPT_d_Group);

  const char *CC1Name = getCC1Name(Inputs[0].getType());
  const char *Exec =
    Args.MakeArgString(getToolChain().GetProgramPath(C, CC1Name));
  Dest.addCommand(new Command(JA, *this, Exec, CmdArgs));
}

void darwin::Compile::ConstructJob(Compilation &C, const JobAction &JA,
                                   Job &Dest, const InputInfo &Output,
                                   const InputInfoList &Inputs,
                                   const ArgList &Args,
                                   const char *LinkingOutput) const {
  const Driver &D = getToolChain().getDriver();
  ArgStringList CmdArgs;

  assert(Inputs.size() == 1 && "Unexpected number of inputs!");

  types::ID InputType = Inputs[0].getType();
  const Arg *A;
  if ((A = Args.getLastArg(options::OPT_traditional)))
    D.Diag(clang::diag::err_drv_argument_only_allowed_with)
      << A->getAsString(Args) << "-E";

  if (Output.getType() == types::TY_LLVMAsm)
    CmdArgs.push_back("-emit-llvm");
  else if (Output.getType() == types::TY_LLVMBC)
    CmdArgs.push_back("-emit-llvm-bc");
  else if (Output.getType() == types::TY_AST)
    D.Diag(clang::diag::err_drv_no_ast_support)
      << getToolChain().getTripleString();
  else if (JA.getType() != types::TY_PP_Asm &&
           JA.getType() != types::TY_PCH)
    D.Diag(clang::diag::err_drv_invalid_gcc_output_type)
      << getTypeName(JA.getType());

  ArgStringList OutputArgs;
  if (Output.getType() != types::TY_PCH) {
    OutputArgs.push_back("-o");
    if (Output.isPipe())
      OutputArgs.push_back("-");
    else if (Output.isNothing())
      OutputArgs.push_back("/dev/null");
    else
      OutputArgs.push_back(Output.getFilename());
  }

  // There is no need for this level of compatibility, but it makes
  // diffing easier.
  bool OutputArgsEarly = (Args.hasArg(options::OPT_fsyntax_only) ||
                          Args.hasArg(options::OPT_S));

  if (types::getPreprocessedType(InputType) != types::TY_INVALID) {
    AddCPPUniqueOptionsArgs(Args, CmdArgs, Inputs);
    if (OutputArgsEarly) {
      AddCC1OptionsArgs(Args, CmdArgs, Inputs, OutputArgs);
    } else {
      AddCC1OptionsArgs(Args, CmdArgs, Inputs, ArgStringList());
      CmdArgs.append(OutputArgs.begin(), OutputArgs.end());
    }
  } else {
    CmdArgs.push_back("-fpreprocessed");

    for (InputInfoList::const_iterator
           it = Inputs.begin(), ie = Inputs.end(); it != ie; ++it) {
      const InputInfo &II = *it;

      // Reject AST inputs.
      if (II.getType() == types::TY_AST) {
        D.Diag(clang::diag::err_drv_no_ast_support)
          << getToolChain().getTripleString();
        return;
      }

      if (II.isPipe())
        CmdArgs.push_back("-");
      else
        CmdArgs.push_back(II.getFilename());
    }

    if (OutputArgsEarly) {
      AddCC1OptionsArgs(Args, CmdArgs, Inputs, OutputArgs);
    } else {
      AddCC1OptionsArgs(Args, CmdArgs, Inputs, ArgStringList());
      CmdArgs.append(OutputArgs.begin(), OutputArgs.end());
    }
  }

  if (Output.getType() == types::TY_PCH) {
    assert(Output.isFilename() && "Invalid PCH output.");

    CmdArgs.push_back("-o");
    // NOTE: gcc uses a temp .s file for this, but there doesn't seem
    // to be a good reason.
    CmdArgs.push_back("/dev/null");

    CmdArgs.push_back("--output-pch=");
    CmdArgs.push_back(Output.getFilename());
  }

  const char *CC1Name = getCC1Name(Inputs[0].getType());
  const char *Exec =
    Args.MakeArgString(getToolChain().GetProgramPath(C, CC1Name));
  Dest.addCommand(new Command(JA, *this, Exec, CmdArgs));
}

void darwin::Assemble::ConstructJob(Compilation &C, const JobAction &JA,
                                    Job &Dest, const InputInfo &Output,
                                    const InputInfoList &Inputs,
                                    const ArgList &Args,
                                    const char *LinkingOutput) const {
  ArgStringList CmdArgs;

  assert(Inputs.size() == 1 && "Unexpected number of inputs.");
  const InputInfo &Input = Inputs[0];

  // Bit of a hack, this is only used for original inputs.
  //
  // FIXME: This is broken for preprocessed .s inputs.
  if (Input.isFilename() &&
      strcmp(Input.getFilename(), Input.getBaseInput()) == 0) {
    if (Args.hasArg(options::OPT_gstabs))
      CmdArgs.push_back("--gstabs");
    else if (Args.hasArg(options::OPT_g_Group))
      CmdArgs.push_back("--gdwarf2");
  }

  // Derived from asm spec.
  AddDarwinArch(Args, CmdArgs);

  if (!getDarwinToolChain().isTargetIPhoneOS() ||
      Args.hasArg(options::OPT_force__cpusubtype__ALL))
    CmdArgs.push_back("-force_cpusubtype_ALL");

  if (getToolChain().getTriple().getArch() != llvm::Triple::x86_64 &&
      (Args.hasArg(options::OPT_mkernel) ||
       Args.hasArg(options::OPT_static) ||
       Args.hasArg(options::OPT_fapple_kext)))
    CmdArgs.push_back("-static");

  Args.AddAllArgValues(CmdArgs, options::OPT_Wa_COMMA,
                       options::OPT_Xassembler);

  assert(Output.isFilename() && "Unexpected lipo output.");
  CmdArgs.push_back("-o");
  CmdArgs.push_back(Output.getFilename());

  if (Input.isPipe()) {
    CmdArgs.push_back("-");
  } else {
    assert(Input.isFilename() && "Invalid input.");
    CmdArgs.push_back(Input.getFilename());
  }

  // asm_final spec is empty.

  const char *Exec =
    Args.MakeArgString(getToolChain().GetProgramPath(C, "as"));
  Dest.addCommand(new Command(JA, *this, Exec, CmdArgs));
}

/// Helper routine for seeing if we should use dsymutil; this is a
/// gcc compatible hack, we should remove it and use the input
/// type information.
static bool isSourceSuffix(const char *Str) {
  // match: 'C', 'CPP', 'c', 'cc', 'cp', 'c++', 'cpp', 'cxx', 'm',
  // 'mm'.
  return llvm::StringSwitch<bool>(Str)
           .Case("C", true)
           .Case("c", true)
           .Case("m", true)
           .Case("cc", true)
           .Case("cp", true)
           .Case("mm", true)
           .Case("CPP", true)
           .Case("c++", true)
           .Case("cpp", true)
           .Case("cxx", true)
           .Default(false);
}

void darwin::DarwinTool::AddDarwinArch(const ArgList &Args,
                                       ArgStringList &CmdArgs) const {
  llvm::StringRef ArchName = getDarwinToolChain().getDarwinArchName(Args);

  // Derived from darwin_arch spec.
  CmdArgs.push_back("-arch");
  CmdArgs.push_back(Args.MakeArgString(ArchName));

  // FIXME: Is this needed anymore?
  if (ArchName == "arm")
    CmdArgs.push_back("-force_cpusubtype_ALL");
}

void darwin::Link::AddLinkArgs(const ArgList &Args,
                               ArgStringList &CmdArgs) const {
  const Driver &D = getToolChain().getDriver();

  // Derived from the "link" spec.
  Args.AddAllArgs(CmdArgs, options::OPT_static);
  if (!Args.hasArg(options::OPT_static))
    CmdArgs.push_back("-dynamic");
  if (Args.hasArg(options::OPT_fgnu_runtime)) {
    // FIXME: gcc replaces -lobjc in forward args with -lobjc-gnu
    // here. How do we wish to handle such things?
  }

  if (!Args.hasArg(options::OPT_dynamiclib)) {
    AddDarwinArch(Args, CmdArgs);
    // FIXME: Why do this only on this path?
    Args.AddLastArg(CmdArgs, options::OPT_force__cpusubtype__ALL);

    Args.AddLastArg(CmdArgs, options::OPT_bundle);
    Args.AddAllArgs(CmdArgs, options::OPT_bundle__loader);
    Args.AddAllArgs(CmdArgs, options::OPT_client__name);

    Arg *A;
    if ((A = Args.getLastArg(options::OPT_compatibility__version)) ||
        (A = Args.getLastArg(options::OPT_current__version)) ||
        (A = Args.getLastArg(options::OPT_install__name)))
      D.Diag(clang::diag::err_drv_argument_only_allowed_with)
        << A->getAsString(Args) << "-dynamiclib";

    Args.AddLastArg(CmdArgs, options::OPT_force__flat__namespace);
    Args.AddLastArg(CmdArgs, options::OPT_keep__private__externs);
    Args.AddLastArg(CmdArgs, options::OPT_private__bundle);
  } else {
    CmdArgs.push_back("-dylib");

    Arg *A;
    if ((A = Args.getLastArg(options::OPT_bundle)) ||
        (A = Args.getLastArg(options::OPT_bundle__loader)) ||
        (A = Args.getLastArg(options::OPT_client__name)) ||
        (A = Args.getLastArg(options::OPT_force__flat__namespace)) ||
        (A = Args.getLastArg(options::OPT_keep__private__externs)) ||
        (A = Args.getLastArg(options::OPT_private__bundle)))
      D.Diag(clang::diag::err_drv_argument_not_allowed_with)
        << A->getAsString(Args) << "-dynamiclib";

    Args.AddAllArgsTranslated(CmdArgs, options::OPT_compatibility__version,
                              "-dylib_compatibility_version");
    Args.AddAllArgsTranslated(CmdArgs, options::OPT_current__version,
                              "-dylib_current_version");

    AddDarwinArch(Args, CmdArgs);

    Args.AddAllArgsTranslated(CmdArgs, options::OPT_install__name,
                              "-dylib_install_name");
  }

  Args.AddLastArg(CmdArgs, options::OPT_all__load);
  Args.AddAllArgs(CmdArgs, options::OPT_allowable__client);
  Args.AddLastArg(CmdArgs, options::OPT_bind__at__load);
  if (getDarwinToolChain().isTargetIPhoneOS())
    Args.AddLastArg(CmdArgs, options::OPT_arch__errors__fatal);
  Args.AddLastArg(CmdArgs, options::OPT_dead__strip);
  Args.AddLastArg(CmdArgs, options::OPT_no__dead__strip__inits__and__terms);
  Args.AddAllArgs(CmdArgs, options::OPT_dylib__file);
  Args.AddLastArg(CmdArgs, options::OPT_dynamic);
  Args.AddAllArgs(CmdArgs, options::OPT_exported__symbols__list);
  Args.AddLastArg(CmdArgs, options::OPT_flat__namespace);
  Args.AddAllArgs(CmdArgs, options::OPT_headerpad__max__install__names);
  Args.AddAllArgs(CmdArgs, options::OPT_image__base);
  Args.AddAllArgs(CmdArgs, options::OPT_init);

  // Adding all arguments doesn't make sense here but this is what gcc does. One
  // of this should always be present thanks to argument translation.
  assert((Args.hasArg(options::OPT_mmacosx_version_min_EQ) ||
          Args.hasArg(options::OPT_miphoneos_version_min_EQ)) &&
         "Missing version argument (lost in translation)?");
  Args.AddAllArgsTranslated(CmdArgs, options::OPT_mmacosx_version_min_EQ,
                            "-macosx_version_min");
  Args.AddAllArgsTranslated(CmdArgs, options::OPT_miphoneos_version_min_EQ,
                            "-iphoneos_version_min");
  Args.AddLastArg(CmdArgs, options::OPT_nomultidefs);
  Args.AddLastArg(CmdArgs, options::OPT_multi__module);
  Args.AddLastArg(CmdArgs, options::OPT_single__module);
  Args.AddAllArgs(CmdArgs, options::OPT_multiply__defined);
  Args.AddAllArgs(CmdArgs, options::OPT_multiply__defined__unused);

  if (Args.hasArg(options::OPT_fpie))
    CmdArgs.push_back("-pie");

  Args.AddLastArg(CmdArgs, options::OPT_prebind);
  Args.AddLastArg(CmdArgs, options::OPT_noprebind);
  Args.AddLastArg(CmdArgs, options::OPT_nofixprebinding);
  Args.AddLastArg(CmdArgs, options::OPT_prebind__all__twolevel__modules);
  Args.AddLastArg(CmdArgs, options::OPT_read__only__relocs);
  Args.AddAllArgs(CmdArgs, options::OPT_sectcreate);
  Args.AddAllArgs(CmdArgs, options::OPT_sectorder);
  Args.AddAllArgs(CmdArgs, options::OPT_seg1addr);
  Args.AddAllArgs(CmdArgs, options::OPT_segprot);
  Args.AddAllArgs(CmdArgs, options::OPT_segaddr);
  Args.AddAllArgs(CmdArgs, options::OPT_segs__read__only__addr);
  Args.AddAllArgs(CmdArgs, options::OPT_segs__read__write__addr);
  Args.AddAllArgs(CmdArgs, options::OPT_seg__addr__table);
  Args.AddAllArgs(CmdArgs, options::OPT_seg__addr__table__filename);
  Args.AddAllArgs(CmdArgs, options::OPT_sub__library);
  Args.AddAllArgs(CmdArgs, options::OPT_sub__umbrella);

  Args.AddAllArgsTranslated(CmdArgs, options::OPT_isysroot, "-syslibroot");
  if (getDarwinToolChain().isTargetIPhoneOS()) {
    if (!Args.hasArg(options::OPT_isysroot)) {
      CmdArgs.push_back("-syslibroot");
      CmdArgs.push_back("/Developer/SDKs/Extra");
    }
  }

  Args.AddLastArg(CmdArgs, options::OPT_twolevel__namespace);
  Args.AddLastArg(CmdArgs, options::OPT_twolevel__namespace__hints);
  Args.AddAllArgs(CmdArgs, options::OPT_umbrella);
  Args.AddAllArgs(CmdArgs, options::OPT_undefined);
  Args.AddAllArgs(CmdArgs, options::OPT_unexported__symbols__list);
  Args.AddAllArgs(CmdArgs, options::OPT_weak__reference__mismatches);
  Args.AddLastArg(CmdArgs, options::OPT_X_Flag);
  Args.AddAllArgs(CmdArgs, options::OPT_y);
  Args.AddLastArg(CmdArgs, options::OPT_w);
  Args.AddAllArgs(CmdArgs, options::OPT_pagezero__size);
  Args.AddAllArgs(CmdArgs, options::OPT_segs__read__);
  Args.AddLastArg(CmdArgs, options::OPT_seglinkedit);
  Args.AddLastArg(CmdArgs, options::OPT_noseglinkedit);
  Args.AddAllArgs(CmdArgs, options::OPT_sectalign);
  Args.AddAllArgs(CmdArgs, options::OPT_sectobjectsymbols);
  Args.AddAllArgs(CmdArgs, options::OPT_segcreate);
  Args.AddLastArg(CmdArgs, options::OPT_whyload);
  Args.AddLastArg(CmdArgs, options::OPT_whatsloaded);
  Args.AddAllArgs(CmdArgs, options::OPT_dylinker__install__name);
  Args.AddLastArg(CmdArgs, options::OPT_dylinker);
  Args.AddLastArg(CmdArgs, options::OPT_Mach);
}

void darwin::Link::ConstructJob(Compilation &C, const JobAction &JA,
                                Job &Dest, const InputInfo &Output,
                                const InputInfoList &Inputs,
                                const ArgList &Args,
                                const char *LinkingOutput) const {
  assert(Output.getType() == types::TY_Image && "Invalid linker output type.");

  // The logic here is derived from gcc's behavior; most of which
  // comes from specs (starting with link_command). Consult gcc for
  // more information.
  ArgStringList CmdArgs;

  // I'm not sure why this particular decomposition exists in gcc, but
  // we follow suite for ease of comparison.
  AddLinkArgs(Args, CmdArgs);

  Args.AddAllArgs(CmdArgs, options::OPT_d_Flag);
  Args.AddAllArgs(CmdArgs, options::OPT_s);
  Args.AddAllArgs(CmdArgs, options::OPT_t);
  Args.AddAllArgs(CmdArgs, options::OPT_Z_Flag);
  Args.AddAllArgs(CmdArgs, options::OPT_u_Group);
  Args.AddAllArgs(CmdArgs, options::OPT_A);
  Args.AddLastArg(CmdArgs, options::OPT_e);
  Args.AddAllArgs(CmdArgs, options::OPT_m_Separate);
  Args.AddAllArgs(CmdArgs, options::OPT_r);

  CmdArgs.push_back("-o");
  CmdArgs.push_back(Output.getFilename());

  if (!Args.hasArg(options::OPT_A) &&
      !Args.hasArg(options::OPT_nostdlib) &&
      !Args.hasArg(options::OPT_nostartfiles)) {
    // Derived from startfile spec.
    if (Args.hasArg(options::OPT_dynamiclib)) {
      // Derived from darwin_dylib1 spec.
      if (getDarwinToolChain().isTargetIPhoneOS()) {
        if (getDarwinToolChain().isIPhoneOSVersionLT(3, 1))
          CmdArgs.push_back("-ldylib1.o");
      } else {
        if (getDarwinToolChain().isMacosxVersionLT(10, 5))
          CmdArgs.push_back("-ldylib1.o");
        else if (getDarwinToolChain().isMacosxVersionLT(10, 6))
          CmdArgs.push_back("-ldylib1.10.5.o");
      }
    } else {
      if (Args.hasArg(options::OPT_bundle)) {
        if (!Args.hasArg(options::OPT_static)) {
          // Derived from darwin_bundle1 spec.
          if (getDarwinToolChain().isTargetIPhoneOS()) {
            if (getDarwinToolChain().isIPhoneOSVersionLT(3, 1))
              CmdArgs.push_back("-lbundle1.o");
          } else {
            if (getDarwinToolChain().isMacosxVersionLT(10, 6))
              CmdArgs.push_back("-lbundle1.o");
          }
        }
      } else {
        if (Args.hasArg(options::OPT_pg)) {
          if (Args.hasArg(options::OPT_static) ||
              Args.hasArg(options::OPT_object) ||
              Args.hasArg(options::OPT_preload)) {
            CmdArgs.push_back("-lgcrt0.o");
          } else {
            CmdArgs.push_back("-lgcrt1.o");

            // darwin_crt2 spec is empty.
          }
        } else {
          if (Args.hasArg(options::OPT_static) ||
              Args.hasArg(options::OPT_object) ||
              Args.hasArg(options::OPT_preload)) {
            CmdArgs.push_back("-lcrt0.o");
          } else {
            // Derived from darwin_crt1 spec.
            if (getDarwinToolChain().isTargetIPhoneOS()) {
              if (getDarwinToolChain().isIPhoneOSVersionLT(3, 1))
                CmdArgs.push_back("-lcrt1.o");
              else
                CmdArgs.push_back("-lcrt1.3.1.o");
            } else {
              if (getDarwinToolChain().isMacosxVersionLT(10, 5))
                CmdArgs.push_back("-lcrt1.o");
              else if (getDarwinToolChain().isMacosxVersionLT(10, 6))
                CmdArgs.push_back("-lcrt1.10.5.o");
              else
                CmdArgs.push_back("-lcrt1.10.6.o");

              // darwin_crt2 spec is empty.
            }
          }
        }
      }
    }

    if (!getDarwinToolChain().isTargetIPhoneOS() &&
        Args.hasArg(options::OPT_shared_libgcc) &&
        getDarwinToolChain().isMacosxVersionLT(10, 5)) {
      const char *Str =
        Args.MakeArgString(getToolChain().GetFilePath(C, "crt3.o"));
      CmdArgs.push_back(Str);
    }
  }

  Args.AddAllArgs(CmdArgs, options::OPT_L);

  if (Args.hasArg(options::OPT_fopenmp))
    // This is more complicated in gcc...
    CmdArgs.push_back("-lgomp");

  getDarwinToolChain().AddLinkSearchPathArgs(Args, CmdArgs);

  for (InputInfoList::const_iterator
         it = Inputs.begin(), ie = Inputs.end(); it != ie; ++it) {
    const InputInfo &II = *it;
    if (II.isFilename())
      CmdArgs.push_back(II.getFilename());
    else
      II.getInputArg().renderAsInput(Args, CmdArgs);
  }

  if (LinkingOutput) {
    CmdArgs.push_back("-arch_multiple");
    CmdArgs.push_back("-final_output");
    CmdArgs.push_back(LinkingOutput);
  }

  if (Args.hasArg(options::OPT_fprofile_arcs) ||
      Args.hasArg(options::OPT_fprofile_generate) ||
      Args.hasArg(options::OPT_fcreate_profile) ||
      Args.hasArg(options::OPT_coverage))
    CmdArgs.push_back("-lgcov");

  if (Args.hasArg(options::OPT_fnested_functions))
    CmdArgs.push_back("-allow_stack_execute");

  if (!Args.hasArg(options::OPT_nostdlib) &&
      !Args.hasArg(options::OPT_nodefaultlibs)) {
    // FIXME: g++ is more complicated here, it tries to put -lstdc++
    // before -lm, for example.
    if (getToolChain().getDriver().CCCIsCXX)
      CmdArgs.push_back("-lstdc++");

    // link_ssp spec is empty.

    // Let the tool chain choose which runtime library to link.
    getDarwinToolChain().AddLinkRuntimeLibArgs(Args, CmdArgs);
  }

  if (!Args.hasArg(options::OPT_A) &&
      !Args.hasArg(options::OPT_nostdlib) &&
      !Args.hasArg(options::OPT_nostartfiles)) {
    // endfile_spec is empty.
  }

  Args.AddAllArgs(CmdArgs, options::OPT_T_Group);
  Args.AddAllArgs(CmdArgs, options::OPT_F);

  const char *Exec =
    Args.MakeArgString(getToolChain().GetProgramPath(C, "ld"));
  Dest.addCommand(new Command(JA, *this, Exec, CmdArgs));

  // Find the first non-empty base input (we want to ignore linker
  // inputs).
  const char *BaseInput = "";
  for (unsigned i = 0, e = Inputs.size(); i != e; ++i) {
    if (Inputs[i].getBaseInput()[0] != '\0') {
      BaseInput = Inputs[i].getBaseInput();
      break;
    }
  }

  // Run dsymutil if we are making an executable in a single step.
  //
  // FIXME: Currently we don't want to do this when we are part of a
  // universal build step, as this would end up creating stray temp
  // files.
  if (!LinkingOutput &&
      Args.getLastArg(options::OPT_g_Group) &&
      !Args.getLastArg(options::OPT_gstabs) &&
      !Args.getLastArg(options::OPT_g0)) {
    // FIXME: This is gross, but matches gcc. The test only considers
    // the suffix (not the -x type), and then only of the first
    // source input. Awesome.
    const char *Suffix = strrchr(BaseInput, '.');
    if (Suffix && isSourceSuffix(Suffix + 1)) {
      const char *Exec =
        Args.MakeArgString(getToolChain().GetProgramPath(C, "dsymutil"));
      ArgStringList CmdArgs;
      CmdArgs.push_back(Output.getFilename());
      C.getJobs().addCommand(new Command(JA, *this, Exec, CmdArgs));
    }
  }
}

void darwin::Lipo::ConstructJob(Compilation &C, const JobAction &JA,
                                Job &Dest, const InputInfo &Output,
                                const InputInfoList &Inputs,
                                const ArgList &Args,
                                const char *LinkingOutput) const {
  ArgStringList CmdArgs;

  CmdArgs.push_back("-create");
  assert(Output.isFilename() && "Unexpected lipo output.");

  CmdArgs.push_back("-output");
  CmdArgs.push_back(Output.getFilename());

  for (InputInfoList::const_iterator
         it = Inputs.begin(), ie = Inputs.end(); it != ie; ++it) {
    const InputInfo &II = *it;
    assert(II.isFilename() && "Unexpected lipo input.");
    CmdArgs.push_back(II.getFilename());
  }
  const char *Exec =
    Args.MakeArgString(getToolChain().GetProgramPath(C, "lipo"));
  Dest.addCommand(new Command(JA, *this, Exec, CmdArgs));
}

void auroraux::Assemble::ConstructJob(Compilation &C, const JobAction &JA,
                                      Job &Dest, const InputInfo &Output,
                                      const InputInfoList &Inputs,
                                      const ArgList &Args,
                                      const char *LinkingOutput) const {
  ArgStringList CmdArgs;

  Args.AddAllArgValues(CmdArgs, options::OPT_Wa_COMMA,
                       options::OPT_Xassembler);

  CmdArgs.push_back("-o");
  if (Output.isPipe())
    CmdArgs.push_back("-");
  else
    CmdArgs.push_back(Output.getFilename());

  for (InputInfoList::const_iterator
         it = Inputs.begin(), ie = Inputs.end(); it != ie; ++it) {
    const InputInfo &II = *it;
    if (II.isPipe())
      CmdArgs.push_back("-");
    else
      CmdArgs.push_back(II.getFilename());
  }

  const char *Exec =
    Args.MakeArgString(getToolChain().GetProgramPath(C, "gas"));
  Dest.addCommand(new Command(JA, *this, Exec, CmdArgs));
}

void auroraux::Link::ConstructJob(Compilation &C, const JobAction &JA,
                                  Job &Dest, const InputInfo &Output,
                                  const InputInfoList &Inputs,
                                  const ArgList &Args,
                                  const char *LinkingOutput) const {
  const Driver &D = getToolChain().getDriver();
  ArgStringList CmdArgs;

  if ((!Args.hasArg(options::OPT_nostdlib)) &&
      (!Args.hasArg(options::OPT_shared))) {
    CmdArgs.push_back("-e");
    CmdArgs.push_back("_start");
  }

  if (Args.hasArg(options::OPT_static)) {
    CmdArgs.push_back("-Bstatic");
    CmdArgs.push_back("-dn");
  } else {
//    CmdArgs.push_back("--eh-frame-hdr");
    CmdArgs.push_back("-Bdynamic");
    if (Args.hasArg(options::OPT_shared)) {
      CmdArgs.push_back("-shared");
    } else {
      CmdArgs.push_back("--dynamic-linker");
      CmdArgs.push_back("/lib/ld.so.1"); // 64Bit Path /lib/amd64/ld.so.1
    }
  }

  if (Output.isPipe()) {
    CmdArgs.push_back("-o");
    CmdArgs.push_back("-");
  } else if (Output.isFilename()) {
    CmdArgs.push_back("-o");
    CmdArgs.push_back(Output.getFilename());
  } else {
    assert(Output.isNothing() && "Invalid output.");
  }

  if (!Args.hasArg(options::OPT_nostdlib) &&
      !Args.hasArg(options::OPT_nostartfiles)) {
    if (!Args.hasArg(options::OPT_shared)) {
      CmdArgs.push_back(Args.MakeArgString(getToolChain().GetFilePath(C, "crt1.o")));
      CmdArgs.push_back(Args.MakeArgString(getToolChain().GetFilePath(C, "crti.o")));
      CmdArgs.push_back(Args.MakeArgString(getToolChain().GetFilePath(C, "crtbegin.o")));
    } else {
      CmdArgs.push_back(Args.MakeArgString(getToolChain().GetFilePath(C, "crti.o")));
    }
    CmdArgs.push_back(Args.MakeArgString(getToolChain().GetFilePath(C, "crtn.o")));
  }

  CmdArgs.push_back(Args.MakeArgString("-L/opt/gcc4/lib/gcc/"
                                       + getToolChain().getTripleString()
                                       + "/4.2.4"));

  Args.AddAllArgs(CmdArgs, options::OPT_L);
  Args.AddAllArgs(CmdArgs, options::OPT_T_Group);
  Args.AddAllArgs(CmdArgs, options::OPT_e);

  for (InputInfoList::const_iterator
         it = Inputs.begin(), ie = Inputs.end(); it != ie; ++it) {
    const InputInfo &II = *it;

    // Don't try to pass LLVM inputs to a generic gcc.
    if (II.getType() == types::TY_LLVMBC)
      D.Diag(clang::diag::err_drv_no_linker_llvm_support)
        << getToolChain().getTripleString();

    if (II.isPipe())
      CmdArgs.push_back("-");
    else if (II.isFilename())
      CmdArgs.push_back(II.getFilename());
    else
      II.getInputArg().renderAsInput(Args, CmdArgs);
  }

  if (!Args.hasArg(options::OPT_nostdlib) &&
      !Args.hasArg(options::OPT_nodefaultlibs)) {
    // FIXME: For some reason GCC passes -lgcc before adding
    // the default system libraries. Just mimic this for now.
    CmdArgs.push_back("-lgcc");

    if (Args.hasArg(options::OPT_pthread))
      CmdArgs.push_back("-pthread");
    if (!Args.hasArg(options::OPT_shared))
      CmdArgs.push_back("-lc");
    CmdArgs.push_back("-lgcc");
  }

  if (!Args.hasArg(options::OPT_nostdlib) &&
      !Args.hasArg(options::OPT_nostartfiles)) {
    if (!Args.hasArg(options::OPT_shared))
      CmdArgs.push_back(Args.MakeArgString(getToolChain().GetFilePath(C, "crtend.o")));
//    else
//      CmdArgs.push_back(Args.MakeArgString(getToolChain().GetFilePath(C, "crtendS.o")));
  }

  const char *Exec =
    Args.MakeArgString(getToolChain().GetProgramPath(C, "ld"));
  Dest.addCommand(new Command(JA, *this, Exec, CmdArgs));
}

void openbsd::Assemble::ConstructJob(Compilation &C, const JobAction &JA,
                                     Job &Dest, const InputInfo &Output,
                                     const InputInfoList &Inputs,
                                     const ArgList &Args,
                                     const char *LinkingOutput) const {
  ArgStringList CmdArgs;

  Args.AddAllArgValues(CmdArgs, options::OPT_Wa_COMMA,
                       options::OPT_Xassembler);

  CmdArgs.push_back("-o");
  if (Output.isPipe())
    CmdArgs.push_back("-");
  else
    CmdArgs.push_back(Output.getFilename());

  for (InputInfoList::const_iterator
         it = Inputs.begin(), ie = Inputs.end(); it != ie; ++it) {
    const InputInfo &II = *it;
    if (II.isPipe())
      CmdArgs.push_back("-");
    else
      CmdArgs.push_back(II.getFilename());
  }

  const char *Exec =
    Args.MakeArgString(getToolChain().GetProgramPath(C, "as"));
  Dest.addCommand(new Command(JA, *this, Exec, CmdArgs));
}

void openbsd::Link::ConstructJob(Compilation &C, const JobAction &JA,
                                 Job &Dest, const InputInfo &Output,
                                 const InputInfoList &Inputs,
                                 const ArgList &Args,
                                 const char *LinkingOutput) const {
  const Driver &D = getToolChain().getDriver();
  ArgStringList CmdArgs;

  if ((!Args.hasArg(options::OPT_nostdlib)) &&
      (!Args.hasArg(options::OPT_shared))) {
    CmdArgs.push_back("-e");
    CmdArgs.push_back("__start");
  }

  if (Args.hasArg(options::OPT_static)) {
    CmdArgs.push_back("-Bstatic");
  } else {
    CmdArgs.push_back("--eh-frame-hdr");
    CmdArgs.push_back("-Bdynamic");
    if (Args.hasArg(options::OPT_shared)) {
      CmdArgs.push_back("-shared");
    } else {
      CmdArgs.push_back("-dynamic-linker");
      CmdArgs.push_back("/usr/libexec/ld.so");
    }
  }

  if (Output.isPipe()) {
    CmdArgs.push_back("-o");
    CmdArgs.push_back("-");
  } else if (Output.isFilename()) {
    CmdArgs.push_back("-o");
    CmdArgs.push_back(Output.getFilename());
  } else {
    assert(Output.isNothing() && "Invalid output.");
  }

  if (!Args.hasArg(options::OPT_nostdlib) &&
      !Args.hasArg(options::OPT_nostartfiles)) {
    if (!Args.hasArg(options::OPT_shared)) {
      CmdArgs.push_back(Args.MakeArgString(getToolChain().GetFilePath(C, "crt0.o")));
      CmdArgs.push_back(Args.MakeArgString(getToolChain().GetFilePath(C, "crtbegin.o")));
    } else {
      CmdArgs.push_back(Args.MakeArgString(getToolChain().GetFilePath(C, "crtbeginS.o")));
    }
  }

  std::string Triple = getToolChain().getTripleString();
  if (Triple.substr(0, 6) == "x86_64")
    Triple.replace(0, 6, "amd64");
  CmdArgs.push_back(Args.MakeArgString("-L/usr/lib/gcc-lib/" + Triple +
                                       "/3.3.5"));

  Args.AddAllArgs(CmdArgs, options::OPT_L);
  Args.AddAllArgs(CmdArgs, options::OPT_T_Group);
  Args.AddAllArgs(CmdArgs, options::OPT_e);

  for (InputInfoList::const_iterator
         it = Inputs.begin(), ie = Inputs.end(); it != ie; ++it) {
    const InputInfo &II = *it;

    // Don't try to pass LLVM inputs to a generic gcc.
    if (II.getType() == types::TY_LLVMBC)
      D.Diag(clang::diag::err_drv_no_linker_llvm_support)
        << getToolChain().getTripleString();

    if (II.isPipe())
      CmdArgs.push_back("-");
    else if (II.isFilename())
      CmdArgs.push_back(II.getFilename());
    else
      II.getInputArg().renderAsInput(Args, CmdArgs);
  }

  if (!Args.hasArg(options::OPT_nostdlib) &&
      !Args.hasArg(options::OPT_nodefaultlibs)) {
    // FIXME: For some reason GCC passes -lgcc before adding
    // the default system libraries. Just mimic this for now.
    CmdArgs.push_back("-lgcc");

    if (Args.hasArg(options::OPT_pthread))
      CmdArgs.push_back("-pthread");
    if (!Args.hasArg(options::OPT_shared))
      CmdArgs.push_back("-lc");
    CmdArgs.push_back("-lgcc");
  }

  if (!Args.hasArg(options::OPT_nostdlib) &&
      !Args.hasArg(options::OPT_nostartfiles)) {
    if (!Args.hasArg(options::OPT_shared))
      CmdArgs.push_back(Args.MakeArgString(getToolChain().GetFilePath(C, "crtend.o")));
    else
      CmdArgs.push_back(Args.MakeArgString(getToolChain().GetFilePath(C, "crtendS.o")));
  }

  const char *Exec =
    Args.MakeArgString(getToolChain().GetProgramPath(C, "ld"));
  Dest.addCommand(new Command(JA, *this, Exec, CmdArgs));
}

void freebsd::Assemble::ConstructJob(Compilation &C, const JobAction &JA,
                                     Job &Dest, const InputInfo &Output,
                                     const InputInfoList &Inputs,
                                     const ArgList &Args,
                                     const char *LinkingOutput) const {
  ArgStringList CmdArgs;

  // When building 32-bit code on FreeBSD/amd64, we have to explicitly
  // instruct as in the base system to assemble 32-bit code.
  if (getToolChain().getArchName() == "i386")
    CmdArgs.push_back("--32");

  
  // Set byte order explicitly
  if (getToolChain().getArchName() == "mips")
    CmdArgs.push_back("-EB");
  else if (getToolChain().getArchName() == "mipsel")
    CmdArgs.push_back("-EL");

  Args.AddAllArgValues(CmdArgs, options::OPT_Wa_COMMA,
                       options::OPT_Xassembler);

  CmdArgs.push_back("-o");
  if (Output.isPipe())
    CmdArgs.push_back("-");
  else
    CmdArgs.push_back(Output.getFilename());

  for (InputInfoList::const_iterator
         it = Inputs.begin(), ie = Inputs.end(); it != ie; ++it) {
    const InputInfo &II = *it;
    if (II.isPipe())
      CmdArgs.push_back("-");
    else
      CmdArgs.push_back(II.getFilename());
  }

  const char *Exec =
    Args.MakeArgString(getToolChain().GetProgramPath(C, "as"));
  Dest.addCommand(new Command(JA, *this, Exec, CmdArgs));
}

void freebsd::Link::ConstructJob(Compilation &C, const JobAction &JA,
                                 Job &Dest, const InputInfo &Output,
                                 const InputInfoList &Inputs,
                                 const ArgList &Args,
                                 const char *LinkingOutput) const {
  const Driver &D = getToolChain().getDriver();
  ArgStringList CmdArgs;

  if (Args.hasArg(options::OPT_static)) {
    CmdArgs.push_back("-Bstatic");
  } else {
    CmdArgs.push_back("--eh-frame-hdr");
    if (Args.hasArg(options::OPT_shared)) {
      CmdArgs.push_back("-Bshareable");
    } else {
      CmdArgs.push_back("-dynamic-linker");
      CmdArgs.push_back("/libexec/ld-elf.so.1");
    }
  }

  // When building 32-bit code on FreeBSD/amd64, we have to explicitly
  // instruct ld in the base system to link 32-bit code.
  if (getToolChain().getArchName() == "i386") {
    CmdArgs.push_back("-m");
    CmdArgs.push_back("elf_i386_fbsd");
  }

  if (Output.isPipe()) {
    CmdArgs.push_back("-o");
    CmdArgs.push_back("-");
  } else if (Output.isFilename()) {
    CmdArgs.push_back("-o");
    CmdArgs.push_back(Output.getFilename());
  } else {
    assert(Output.isNothing() && "Invalid output.");
  }

  if (!Args.hasArg(options::OPT_nostdlib) &&
      !Args.hasArg(options::OPT_nostartfiles)) {
    if (!Args.hasArg(options::OPT_shared)) {
      CmdArgs.push_back(Args.MakeArgString(getToolChain().GetFilePath(C, "crt1.o")));
      CmdArgs.push_back(Args.MakeArgString(getToolChain().GetFilePath(C, "crti.o")));
      CmdArgs.push_back(Args.MakeArgString(getToolChain().GetFilePath(C, "crtbegin.o")));
    } else {
      CmdArgs.push_back(Args.MakeArgString(getToolChain().GetFilePath(C, "crti.o")));
      CmdArgs.push_back(Args.MakeArgString(getToolChain().GetFilePath(C, "crtbeginS.o")));
    }
  }

  Args.AddAllArgs(CmdArgs, options::OPT_L);
  Args.AddAllArgs(CmdArgs, options::OPT_T_Group);
  Args.AddAllArgs(CmdArgs, options::OPT_e);

  for (InputInfoList::const_iterator
         it = Inputs.begin(), ie = Inputs.end(); it != ie; ++it) {
    const InputInfo &II = *it;

    // Don't try to pass LLVM inputs to a generic gcc.
    if (II.getType() == types::TY_LLVMBC)
      D.Diag(clang::diag::err_drv_no_linker_llvm_support)
        << getToolChain().getTripleString();

    if (II.isPipe())
      CmdArgs.push_back("-");
    else if (II.isFilename())
      CmdArgs.push_back(II.getFilename());
    else
      II.getInputArg().renderAsInput(Args, CmdArgs);
  }

  if (!Args.hasArg(options::OPT_nostdlib) &&
      !Args.hasArg(options::OPT_nodefaultlibs)) {
    if (D.CCCIsCXX) {
      CmdArgs.push_back("-lstdc++");
      CmdArgs.push_back("-lm");
    }
    // FIXME: For some reason GCC passes -lgcc and -lgcc_s before adding
    // the default system libraries. Just mimic this for now.
    CmdArgs.push_back("-lgcc");
    if (Args.hasArg(options::OPT_static)) {
      CmdArgs.push_back("-lgcc_eh");
    } else {
      CmdArgs.push_back("--as-needed");
      CmdArgs.push_back("-lgcc_s");
      CmdArgs.push_back("--no-as-needed");
    }

    if (Args.hasArg(options::OPT_pthread))
      CmdArgs.push_back("-lpthread");
    CmdArgs.push_back("-lc");

    CmdArgs.push_back("-lgcc");
    if (Args.hasArg(options::OPT_static)) {
      CmdArgs.push_back("-lgcc_eh");
    } else {
      CmdArgs.push_back("--as-needed");
      CmdArgs.push_back("-lgcc_s");
      CmdArgs.push_back("--no-as-needed");
    }
  }

  if (!Args.hasArg(options::OPT_nostdlib) &&
      !Args.hasArg(options::OPT_nostartfiles)) {
    if (!Args.hasArg(options::OPT_shared))
      CmdArgs.push_back(Args.MakeArgString(getToolChain().GetFilePath(C, "crtend.o")));
    else
      CmdArgs.push_back(Args.MakeArgString(getToolChain().GetFilePath(C, "crtendS.o")));
    CmdArgs.push_back(Args.MakeArgString(getToolChain().GetFilePath(C, "crtn.o")));
  }

  const char *Exec =
    Args.MakeArgString(getToolChain().GetProgramPath(C, "ld"));
  Dest.addCommand(new Command(JA, *this, Exec, CmdArgs));
}

/// DragonFly Tools

// For now, DragonFly Assemble does just about the same as for
// FreeBSD, but this may change soon.
void dragonfly::Assemble::ConstructJob(Compilation &C, const JobAction &JA,
                                       Job &Dest, const InputInfo &Output,
                                       const InputInfoList &Inputs,
                                       const ArgList &Args,
                                       const char *LinkingOutput) const {
  ArgStringList CmdArgs;

  // When building 32-bit code on DragonFly/pc64, we have to explicitly
  // instruct as in the base system to assemble 32-bit code.
  if (getToolChain().getArchName() == "i386")
    CmdArgs.push_back("--32");

  Args.AddAllArgValues(CmdArgs, options::OPT_Wa_COMMA,
                       options::OPT_Xassembler);

  CmdArgs.push_back("-o");
  if (Output.isPipe())
    CmdArgs.push_back("-");
  else
    CmdArgs.push_back(Output.getFilename());

  for (InputInfoList::const_iterator
         it = Inputs.begin(), ie = Inputs.end(); it != ie; ++it) {
    const InputInfo &II = *it;
    if (II.isPipe())
      CmdArgs.push_back("-");
    else
      CmdArgs.push_back(II.getFilename());
  }

  const char *Exec =
    Args.MakeArgString(getToolChain().GetProgramPath(C, "as"));
  Dest.addCommand(new Command(JA, *this, Exec, CmdArgs));
}

void dragonfly::Link::ConstructJob(Compilation &C, const JobAction &JA,
                                 Job &Dest, const InputInfo &Output,
                                 const InputInfoList &Inputs,
                                 const ArgList &Args,
                                 const char *LinkingOutput) const {
  const Driver &D = getToolChain().getDriver();
  ArgStringList CmdArgs;

  if (Args.hasArg(options::OPT_static)) {
    CmdArgs.push_back("-Bstatic");
  } else {
    if (Args.hasArg(options::OPT_shared))
      CmdArgs.push_back("-Bshareable");
    else {
      CmdArgs.push_back("-dynamic-linker");
      CmdArgs.push_back("/usr/libexec/ld-elf.so.2");
    }
  }

  // When building 32-bit code on DragonFly/pc64, we have to explicitly
  // instruct ld in the base system to link 32-bit code.
  if (getToolChain().getArchName() == "i386") {
    CmdArgs.push_back("-m");
    CmdArgs.push_back("elf_i386");
  }

  if (Output.isPipe()) {
    CmdArgs.push_back("-o");
    CmdArgs.push_back("-");
  } else if (Output.isFilename()) {
    CmdArgs.push_back("-o");
    CmdArgs.push_back(Output.getFilename());
  } else {
    assert(Output.isNothing() && "Invalid output.");
  }

  if (!Args.hasArg(options::OPT_nostdlib) &&
      !Args.hasArg(options::OPT_nostartfiles)) {
    if (!Args.hasArg(options::OPT_shared)) {
      CmdArgs.push_back(Args.MakeArgString(getToolChain().GetFilePath(C, "crt1.o")));
      CmdArgs.push_back(Args.MakeArgString(getToolChain().GetFilePath(C, "crti.o")));
      CmdArgs.push_back(Args.MakeArgString(getToolChain().GetFilePath(C, "crtbegin.o")));
    } else {
      CmdArgs.push_back(Args.MakeArgString(getToolChain().GetFilePath(C, "crti.o")));
      CmdArgs.push_back(Args.MakeArgString(getToolChain().GetFilePath(C, "crtbeginS.o")));
    }
  }

  Args.AddAllArgs(CmdArgs, options::OPT_L);
  Args.AddAllArgs(CmdArgs, options::OPT_T_Group);
  Args.AddAllArgs(CmdArgs, options::OPT_e);

  for (InputInfoList::const_iterator
         it = Inputs.begin(), ie = Inputs.end(); it != ie; ++it) {
    const InputInfo &II = *it;

    // Don't try to pass LLVM inputs to a generic gcc.
    if (II.getType() == types::TY_LLVMBC)
      D.Diag(clang::diag::err_drv_no_linker_llvm_support)
        << getToolChain().getTripleString();

    if (II.isPipe())
      CmdArgs.push_back("-");
    else if (II.isFilename())
      CmdArgs.push_back(II.getFilename());
    else
      II.getInputArg().renderAsInput(Args, CmdArgs);
  }

  if (!Args.hasArg(options::OPT_nostdlib) &&
      !Args.hasArg(options::OPT_nodefaultlibs)) {
    // FIXME: GCC passes on -lgcc, -lgcc_pic and a whole lot of
    //         rpaths
    CmdArgs.push_back("-L/usr/lib/gcc41");

    if (!Args.hasArg(options::OPT_static)) {
      CmdArgs.push_back("-rpath");
      CmdArgs.push_back("/usr/lib/gcc41");

      CmdArgs.push_back("-rpath-link");
      CmdArgs.push_back("/usr/lib/gcc41");

      CmdArgs.push_back("-rpath");
      CmdArgs.push_back("/usr/lib");

      CmdArgs.push_back("-rpath-link");
      CmdArgs.push_back("/usr/lib");
    }

    if (Args.hasArg(options::OPT_shared)) {
      CmdArgs.push_back("-lgcc_pic");
    } else {
      CmdArgs.push_back("-lgcc");
    }


    if (Args.hasArg(options::OPT_pthread))
      CmdArgs.push_back("-lpthread");

    if (!Args.hasArg(options::OPT_nolibc)) {
      CmdArgs.push_back("-lc");
    }

    if (Args.hasArg(options::OPT_shared)) {
      CmdArgs.push_back("-lgcc_pic");
    } else {
      CmdArgs.push_back("-lgcc");
    }
  }

  if (!Args.hasArg(options::OPT_nostdlib) &&
      !Args.hasArg(options::OPT_nostartfiles)) {
    if (!Args.hasArg(options::OPT_shared))
      CmdArgs.push_back(Args.MakeArgString(getToolChain().GetFilePath(C, "crtend.o")));
    else
      CmdArgs.push_back(Args.MakeArgString(getToolChain().GetFilePath(C, "crtendS.o")));
    CmdArgs.push_back(Args.MakeArgString(getToolChain().GetFilePath(C, "crtn.o")));
  }

  const char *Exec =
    Args.MakeArgString(getToolChain().GetProgramPath(C, "ld"));
  Dest.addCommand(new Command(JA, *this, Exec, CmdArgs));
}
