//===--- ToolChains.cpp - ToolChain Implementations ---------------------*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "ToolChains.h"

#include "clang/Driver/Arg.h"
#include "clang/Driver/ArgList.h"
#include "clang/Driver/Compilation.h"
#include "clang/Driver/Driver.h"
#include "clang/Driver/DriverDiagnostic.h"
#include "clang/Driver/HostInfo.h"
#include "clang/Driver/OptTable.h"
#include "clang/Driver/Option.h"
#include "clang/Driver/Options.h"
#include "clang/Basic/Version.h"

#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/System/Path.h"

#include <cstdlib> // ::getenv

using namespace clang::driver;
using namespace clang::driver::toolchains;

/// Darwin - Darwin tool chain for i386 and x86_64.

Darwin::Darwin(const HostInfo &Host, const llvm::Triple& Triple)
  : ToolChain(Host, Triple), TargetInitialized(false)
{
  // Compute the initial Darwin version based on the host.
  bool HadExtra;
  std::string OSName = Triple.getOSName();
  if (!Driver::GetReleaseVersion(&OSName[6],
                                 DarwinVersion[0], DarwinVersion[1],
                                 DarwinVersion[2], HadExtra))
    getDriver().Diag(clang::diag::err_drv_invalid_darwin_version) << OSName;

  llvm::raw_string_ostream(MacosxVersionMin)
    << "10." << std::max(0, (int)DarwinVersion[0] - 4) << '.'
    << DarwinVersion[1];
}

types::ID Darwin::LookupTypeForExtension(const char *Ext) const {
  types::ID Ty = types::lookupTypeForExtension(Ext);

  // Darwin always preprocesses assembly files (unless -x is used explicitly).
  if (Ty == types::TY_PP_Asm)
    return types::TY_Asm;

  return Ty;
}

// FIXME: Can we tablegen this?
static const char *GetArmArchForMArch(llvm::StringRef Value) {
  if (Value == "armv6k")
    return "armv6";

  if (Value == "armv5tej")
    return "armv5";

  if (Value == "xscale")
    return "xscale";

  if (Value == "armv4t")
    return "armv4t";

  if (Value == "armv7" || Value == "armv7-a" || Value == "armv7-r" ||
      Value == "armv7-m" || Value == "armv7a" || Value == "armv7r" ||
      Value == "armv7m")
    return "armv7";

  return 0;
}

// FIXME: Can we tablegen this?
static const char *GetArmArchForMCpu(llvm::StringRef Value) {
  if (Value == "arm10tdmi" || Value == "arm1020t" || Value == "arm9e" ||
      Value == "arm946e-s" || Value == "arm966e-s" ||
      Value == "arm968e-s" || Value == "arm10e" ||
      Value == "arm1020e" || Value == "arm1022e" || Value == "arm926ej-s" ||
      Value == "arm1026ej-s")
    return "armv5";

  if (Value == "xscale")
    return "xscale";

  if (Value == "arm1136j-s" || Value == "arm1136jf-s" ||
      Value == "arm1176jz-s" || Value == "arm1176jzf-s")
    return "armv6";

  if (Value == "cortex-a8" || Value == "cortex-r4" || Value == "cortex-m3")
    return "armv7";

  return 0;
}

llvm::StringRef Darwin::getDarwinArchName(const ArgList &Args) const {
  switch (getTriple().getArch()) {
  default:
    return getArchName();

  case llvm::Triple::arm: {
    if (const Arg *A = Args.getLastArg(options::OPT_march_EQ))
      if (const char *Arch = GetArmArchForMArch(A->getValue(Args)))
        return Arch;

    if (const Arg *A = Args.getLastArg(options::OPT_mcpu_EQ))
      if (const char *Arch = GetArmArchForMCpu(A->getValue(Args)))
        return Arch;

    return "arm";
  }
  }
}

DarwinGCC::DarwinGCC(const HostInfo &Host, const llvm::Triple& Triple)
  : Darwin(Host, Triple)
{
  // We can only work with 4.2.1 currently.
  GCCVersion[0] = 4;
  GCCVersion[1] = 2;
  GCCVersion[2] = 1;

  // Set up the tool chain paths to match gcc.
  ToolChainDir = "i686-apple-darwin";
  ToolChainDir += llvm::utostr(DarwinVersion[0]);
  ToolChainDir += "/";
  ToolChainDir += llvm::utostr(GCCVersion[0]);
  ToolChainDir += '.';
  ToolChainDir += llvm::utostr(GCCVersion[1]);
  ToolChainDir += '.';
  ToolChainDir += llvm::utostr(GCCVersion[2]);

  // Try the next major version if that tool chain dir is invalid.
  std::string Tmp = "/usr/lib/gcc/" + ToolChainDir;
  if (!llvm::sys::Path(Tmp).exists()) {
    std::string Next = "i686-apple-darwin";
    Next += llvm::utostr(DarwinVersion[0] + 1);
    Next += "/";
    Next += llvm::utostr(GCCVersion[0]);
    Next += '.';
    Next += llvm::utostr(GCCVersion[1]);
    Next += '.';
    Next += llvm::utostr(GCCVersion[2]);

    // Use that if it exists, otherwise hope the user isn't linking.
    //
    // FIXME: Drop dependency on gcc's tool chain.
    Tmp = "/usr/lib/gcc/" + Next;
    if (llvm::sys::Path(Tmp).exists())
      ToolChainDir = Next;
  }

  std::string Path;
  if (getArchName() == "x86_64") {
    Path = getDriver().Dir;
    Path += "/../lib/gcc/";
    Path += ToolChainDir;
    Path += "/x86_64";
    getFilePaths().push_back(Path);

    Path = "/usr/lib/gcc/";
    Path += ToolChainDir;
    Path += "/x86_64";
    getFilePaths().push_back(Path);
  }

  Path = getDriver().Dir;
  Path += "/../lib/gcc/";
  Path += ToolChainDir;
  getFilePaths().push_back(Path);

  Path = "/usr/lib/gcc/";
  Path += ToolChainDir;
  getFilePaths().push_back(Path);

  Path = getDriver().Dir;
  Path += "/../libexec/gcc/";
  Path += ToolChainDir;
  getProgramPaths().push_back(Path);

  Path = "/usr/libexec/gcc/";
  Path += ToolChainDir;
  getProgramPaths().push_back(Path);

  getProgramPaths().push_back(getDriver().getInstalledDir());
  if (getDriver().getInstalledDir() != getDriver().Dir)
    getProgramPaths().push_back(getDriver().Dir);
}

Darwin::~Darwin() {
  // Free tool implementations.
  for (llvm::DenseMap<unsigned, Tool*>::iterator
         it = Tools.begin(), ie = Tools.end(); it != ie; ++it)
    delete it->second;
}

std::string Darwin::ComputeEffectiveClangTriple(const ArgList &Args) const {
  llvm::Triple Triple(ComputeLLVMTriple(Args));

  // If the target isn't initialized (e.g., an unknown Darwin platform, return
  // the default triple).
  if (!isTargetInitialized())
    return Triple.getTriple();
    
  unsigned Version[3];
  getTargetVersion(Version);

  // Mangle the target version into the OS triple component.  For historical
  // reasons that make little sense, the version passed here is the "darwin"
  // version, which drops the 10 and offsets by 4. See inverse code when
  // setting the OS version preprocessor define.
  if (!isTargetIPhoneOS()) {
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

  return Triple.getTriple();
}

Tool &Darwin::SelectTool(const Compilation &C, const JobAction &JA) const {
  Action::ActionClass Key;
  if (getDriver().ShouldUseClangCompiler(C, JA, getTriple()))
    Key = Action::AnalyzeJobClass;
  else
    Key = JA.getKind();

  // FIXME: This doesn't belong here, but ideally we will support static soon
  // anyway.
  bool HasStatic = (C.getArgs().hasArg(options::OPT_mkernel) ||
                    C.getArgs().hasArg(options::OPT_static) ||
                    C.getArgs().hasArg(options::OPT_fapple_kext));
  bool IsIADefault = IsIntegratedAssemblerDefault() && !HasStatic;
  bool UseIntegratedAs = C.getArgs().hasFlag(options::OPT_integrated_as,
                                             options::OPT_no_integrated_as,
                                             IsIADefault);

  Tool *&T = Tools[Key];
  if (!T) {
    switch (Key) {
    case Action::InputClass:
    case Action::BindArchClass:
      assert(0 && "Invalid tool kind.");
    case Action::PreprocessJobClass:
      T = new tools::darwin::Preprocess(*this); break;
    case Action::AnalyzeJobClass:
      T = new tools::Clang(*this); break;
    case Action::PrecompileJobClass:
    case Action::CompileJobClass:
      T = new tools::darwin::Compile(*this); break;
    case Action::AssembleJobClass: {
      if (UseIntegratedAs)
        T = new tools::ClangAs(*this);
      else
        T = new tools::darwin::Assemble(*this);
      break;
    }
    case Action::LinkJobClass:
      T = new tools::darwin::Link(*this); break;
    case Action::LipoJobClass:
      T = new tools::darwin::Lipo(*this); break;
    case Action::DsymutilJobClass:
      T = new tools::darwin::Dsymutil(*this); break;
    }
  }

  return *T;
}

void DarwinGCC::AddLinkSearchPathArgs(const ArgList &Args,
                                      ArgStringList &CmdArgs) const {
  std::string Tmp;

  // FIXME: Derive these correctly.
  if (getArchName() == "x86_64") {
    CmdArgs.push_back(Args.MakeArgString("-L/usr/lib/gcc/" + ToolChainDir +
                                         "/x86_64"));
    // Intentionally duplicated for (temporary) gcc bug compatibility.
    CmdArgs.push_back(Args.MakeArgString("-L/usr/lib/gcc/" + ToolChainDir +
                                         "/x86_64"));
  }

  CmdArgs.push_back(Args.MakeArgString("-L/usr/lib/" + ToolChainDir));

  Tmp = getDriver().Dir + "/../lib/gcc/" + ToolChainDir;
  if (llvm::sys::Path(Tmp).exists())
    CmdArgs.push_back(Args.MakeArgString("-L" + Tmp));
  Tmp = getDriver().Dir + "/../lib/gcc";
  if (llvm::sys::Path(Tmp).exists())
    CmdArgs.push_back(Args.MakeArgString("-L" + Tmp));
  CmdArgs.push_back(Args.MakeArgString("-L/usr/lib/gcc/" + ToolChainDir));
  // Intentionally duplicated for (temporary) gcc bug compatibility.
  CmdArgs.push_back(Args.MakeArgString("-L/usr/lib/gcc/" + ToolChainDir));
  Tmp = getDriver().Dir + "/../lib/" + ToolChainDir;
  if (llvm::sys::Path(Tmp).exists())
    CmdArgs.push_back(Args.MakeArgString("-L" + Tmp));
  Tmp = getDriver().Dir + "/../lib";
  if (llvm::sys::Path(Tmp).exists())
    CmdArgs.push_back(Args.MakeArgString("-L" + Tmp));
  CmdArgs.push_back(Args.MakeArgString("-L/usr/lib/gcc/" + ToolChainDir +
                                       "/../../../" + ToolChainDir));
  CmdArgs.push_back(Args.MakeArgString("-L/usr/lib/gcc/" + ToolChainDir +
                                       "/../../.."));
}

void DarwinGCC::AddLinkRuntimeLibArgs(const ArgList &Args,
                                      ArgStringList &CmdArgs) const {
  // Note that this routine is only used for targetting OS X.

  // Derived from libgcc and lib specs but refactored.
  if (Args.hasArg(options::OPT_static)) {
    CmdArgs.push_back("-lgcc_static");
  } else {
    if (Args.hasArg(options::OPT_static_libgcc)) {
      CmdArgs.push_back("-lgcc_eh");
    } else if (Args.hasArg(options::OPT_miphoneos_version_min_EQ)) {
      // Derived from darwin_iphoneos_libgcc spec.
      if (isTargetIPhoneOS()) {
        CmdArgs.push_back("-lgcc_s.1");
      } else {
        CmdArgs.push_back("-lgcc_s.10.5");
      }
    } else if (Args.hasArg(options::OPT_shared_libgcc) ||
               Args.hasFlag(options::OPT_fexceptions,
                            options::OPT_fno_exceptions) ||
               Args.hasArg(options::OPT_fgnu_runtime)) {
      // FIXME: This is probably broken on 10.3?
      if (isMacosxVersionLT(10, 5))
        CmdArgs.push_back("-lgcc_s.10.4");
      else if (isMacosxVersionLT(10, 6))
        CmdArgs.push_back("-lgcc_s.10.5");
    } else {
      if (isMacosxVersionLT(10, 3, 9))
        ; // Do nothing.
      else if (isMacosxVersionLT(10, 5))
        CmdArgs.push_back("-lgcc_s.10.4");
      else if (isMacosxVersionLT(10, 6))
        CmdArgs.push_back("-lgcc_s.10.5");
    }

    if (isTargetIPhoneOS() || isMacosxVersionLT(10, 6)) {
      CmdArgs.push_back("-lgcc");
      CmdArgs.push_back("-lSystem");
    } else {
      CmdArgs.push_back("-lSystem");
      CmdArgs.push_back("-lgcc");
    }
  }
}

DarwinClang::DarwinClang(const HostInfo &Host, const llvm::Triple& Triple)
  : Darwin(Host, Triple)
{
  // We expect 'as', 'ld', etc. to be adjacent to our install dir.
  getProgramPaths().push_back(getDriver().getInstalledDir());
  if (getDriver().getInstalledDir() != getDriver().Dir)
    getProgramPaths().push_back(getDriver().Dir);
}

void DarwinClang::AddLinkSearchPathArgs(const ArgList &Args,
                                       ArgStringList &CmdArgs) const {
  // The Clang toolchain uses explicit paths for internal libraries.

  // Unfortunately, we still might depend on a few of the libraries that are
  // only available in the gcc library directory (in particular
  // libstdc++.dylib). For now, hardcode the path to the known install location.
  llvm::sys::Path P(getDriver().Dir);
  P.eraseComponent(); // .../usr/bin -> ../usr
  P.appendComponent("lib");
  P.appendComponent("gcc");
  switch (getTriple().getArch()) {
  default:
    assert(0 && "Invalid Darwin arch!");
  case llvm::Triple::x86:
  case llvm::Triple::x86_64:
    P.appendComponent("i686-apple-darwin10");
    break;
  case llvm::Triple::arm:
  case llvm::Triple::thumb:
    P.appendComponent("arm-apple-darwin10");
    break;
  case llvm::Triple::ppc:
  case llvm::Triple::ppc64:
    P.appendComponent("powerpc-apple-darwin10");
    break;
  }
  P.appendComponent("4.2.1");

  // Determine the arch specific GCC subdirectory.
  const char *ArchSpecificDir = 0;
  switch (getTriple().getArch()) {
  default:
    break;
  case llvm::Triple::arm:
  case llvm::Triple::thumb: {
    std::string Triple = ComputeLLVMTriple(Args);
    llvm::StringRef TripleStr = Triple;
    if (TripleStr.startswith("armv5") || TripleStr.startswith("thumbv5"))
      ArchSpecificDir = "v5";
    else if (TripleStr.startswith("armv6") || TripleStr.startswith("thumbv6"))
      ArchSpecificDir = "v6";
    else if (TripleStr.startswith("armv7") || TripleStr.startswith("thumbv7"))
      ArchSpecificDir = "v7";
    break;
  }
  case llvm::Triple::ppc64:
    ArchSpecificDir = "ppc64";
    break;
  case llvm::Triple::x86_64:
    ArchSpecificDir = "x86_64";
    break;
  }

  if (ArchSpecificDir) {
    P.appendComponent(ArchSpecificDir);
    if (P.exists())
      CmdArgs.push_back(Args.MakeArgString("-L" + P.str()));
    P.eraseComponent();
  }

  if (P.exists())
    CmdArgs.push_back(Args.MakeArgString("-L" + P.str()));
}

void DarwinClang::AddLinkRuntimeLibArgs(const ArgList &Args,
                                        ArgStringList &CmdArgs) const {
  // Darwin doesn't support real static executables, don't link any runtime
  // libraries with -static.
  if (Args.hasArg(options::OPT_static))
    return;

  // Reject -static-libgcc for now, we can deal with this when and if someone
  // cares. This is useful in situations where someone wants to statically link
  // something like libstdc++, and needs its runtime support routines.
  if (const Arg *A = Args.getLastArg(options::OPT_static_libgcc)) {
    getDriver().Diag(clang::diag::err_drv_unsupported_opt)
      << A->getAsString(Args);
    return;
  }

  // Otherwise link libSystem, then the dynamic runtime library, and finally any
  // target specific static runtime library.
  CmdArgs.push_back("-lSystem");

  // Select the dynamic runtime library and the target specific static library.
  const char *DarwinStaticLib = 0;
  if (isTargetIPhoneOS()) {
    CmdArgs.push_back("-lgcc_s.1");

    // We may need some static functions for armv6/thumb which are required to
    // be in the same linkage unit as their caller.
    if (getDarwinArchName(Args) == "armv6")
      DarwinStaticLib = "libclang_rt.armv6.a";
  } else {
    // The dynamic runtime library was merged with libSystem for 10.6 and
    // beyond; only 10.4 and 10.5 need an additional runtime library.
    if (isMacosxVersionLT(10, 5))
      CmdArgs.push_back("-lgcc_s.10.4");
    else if (isMacosxVersionLT(10, 6))
      CmdArgs.push_back("-lgcc_s.10.5");

    // For OS X, we only need a static runtime library when targetting 10.4, to
    // provide versions of the static functions which were omitted from
    // 10.4.dylib.
    if (isMacosxVersionLT(10, 5))
      DarwinStaticLib = "libclang_rt.10.4.a";
  }

  /// Add the target specific static library, if needed.
  if (DarwinStaticLib) {
    llvm::sys::Path P(getDriver().ResourceDir);
    P.appendComponent("lib");
    P.appendComponent("darwin");
    P.appendComponent(DarwinStaticLib);

    // For now, allow missing resource libraries to support developers who may
    // not have compiler-rt checked out or integrated into their build.
    if (!P.exists())
      getDriver().Diag(clang::diag::warn_drv_missing_resource_library)
        << P.str();
    else
      CmdArgs.push_back(Args.MakeArgString(P.str()));
  }
}

void Darwin::AddDeploymentTarget(DerivedArgList &Args) const {
  const OptTable &Opts = getDriver().getOpts();

  Arg *OSXVersion = Args.getLastArg(options::OPT_mmacosx_version_min_EQ);
  Arg *iPhoneVersion = Args.getLastArg(options::OPT_miphoneos_version_min_EQ);
  if (OSXVersion && iPhoneVersion) {
    getDriver().Diag(clang::diag::err_drv_argument_not_allowed_with)
          << OSXVersion->getAsString(Args)
          << iPhoneVersion->getAsString(Args);
    iPhoneVersion = 0;
  } else if (!OSXVersion && !iPhoneVersion) {
    // If neither OS X nor iPhoneOS targets were specified, check for
    // environment defines.
    const char *OSXTarget = ::getenv("MACOSX_DEPLOYMENT_TARGET");
    const char *iPhoneOSTarget = ::getenv("IPHONEOS_DEPLOYMENT_TARGET");

    // Ignore empty strings.
    if (OSXTarget && OSXTarget[0] == '\0')
      OSXTarget = 0;
    if (iPhoneOSTarget && iPhoneOSTarget[0] == '\0')
      iPhoneOSTarget = 0;

    // Diagnose conflicting deployment targets, and choose default platform
    // based on the tool chain.
    //
    // FIXME: Don't hardcode default here.
    if (OSXTarget && iPhoneOSTarget) {
      // FIXME: We should see if we can get away with warning or erroring on
      // this. Perhaps put under -pedantic?
      if (getTriple().getArch() == llvm::Triple::arm ||
          getTriple().getArch() == llvm::Triple::thumb)
        OSXTarget = 0;
      else
        iPhoneOSTarget = 0;
    }

    if (OSXTarget) {
      const Option *O = Opts.getOption(options::OPT_mmacosx_version_min_EQ);
      OSXVersion = Args.MakeJoinedArg(0, O, OSXTarget);
      Args.append(OSXVersion);
    } else if (iPhoneOSTarget) {
      const Option *O = Opts.getOption(options::OPT_miphoneos_version_min_EQ);
      iPhoneVersion = Args.MakeJoinedArg(0, O, iPhoneOSTarget);
      Args.append(iPhoneVersion);
    } else {
      // Otherwise, assume we are targeting OS X.
      const Option *O = Opts.getOption(options::OPT_mmacosx_version_min_EQ);
      OSXVersion = Args.MakeJoinedArg(0, O, MacosxVersionMin);
      Args.append(OSXVersion);
    }
  }

  // Set the tool chain target information.
  unsigned Major, Minor, Micro;
  bool HadExtra;
  if (OSXVersion) {
    assert(!iPhoneVersion && "Unknown target platform!");
    if (!Driver::GetReleaseVersion(OSXVersion->getValue(Args), Major, Minor,
                                   Micro, HadExtra) || HadExtra ||
        Major != 10 || Minor >= 10 || Micro >= 10)
      getDriver().Diag(clang::diag::err_drv_invalid_version_number)
        << OSXVersion->getAsString(Args);
  } else {
    assert(iPhoneVersion && "Unknown target platform!");
    if (!Driver::GetReleaseVersion(iPhoneVersion->getValue(Args), Major, Minor,
                                   Micro, HadExtra) || HadExtra ||
        Major >= 10 || Minor >= 100 || Micro >= 100)
      getDriver().Diag(clang::diag::err_drv_invalid_version_number)
        << iPhoneVersion->getAsString(Args);
  }
  setTarget(iPhoneVersion, Major, Minor, Micro);
}

DerivedArgList *Darwin::TranslateArgs(const DerivedArgList &Args,
                                      const char *BoundArch) const {
  DerivedArgList *DAL = new DerivedArgList(Args.getBaseArgs());
  const OptTable &Opts = getDriver().getOpts();

  // FIXME: We really want to get out of the tool chain level argument
  // translation business, as it makes the driver functionality much
  // more opaque. For now, we follow gcc closely solely for the
  // purpose of easily achieving feature parity & testability. Once we
  // have something that works, we should reevaluate each translation
  // and try to push it down into tool specific logic.

  for (ArgList::const_iterator it = Args.begin(),
         ie = Args.end(); it != ie; ++it) {
    Arg *A = *it;

    if (A->getOption().matches(options::OPT_Xarch__)) {
      // FIXME: Canonicalize name.
      if (getArchName() != A->getValue(Args, 0))
        continue;

      unsigned Index = Args.getBaseArgs().MakeIndex(A->getValue(Args, 1));
      unsigned Prev = Index;
      Arg *XarchArg = Opts.ParseOneArg(Args, Index);

      // If the argument parsing failed or more than one argument was
      // consumed, the -Xarch_ argument's parameter tried to consume
      // extra arguments. Emit an error and ignore.
      //
      // We also want to disallow any options which would alter the
      // driver behavior; that isn't going to work in our model. We
      // use isDriverOption() as an approximation, although things
      // like -O4 are going to slip through.
      if (!XarchArg || Index > Prev + 1 ||
          XarchArg->getOption().isDriverOption()) {
       getDriver().Diag(clang::diag::err_drv_invalid_Xarch_argument)
          << A->getAsString(Args);
        continue;
      }

      XarchArg->setBaseArg(A);
      A = XarchArg;

      DAL->AddSynthesizedArg(A);
    }

    // Sob. These is strictly gcc compatible for the time being. Apple
    // gcc translates options twice, which means that self-expanding
    // options add duplicates.
    switch ((options::ID) A->getOption().getID()) {
    default:
      DAL->append(A);
      break;

    case options::OPT_mkernel:
    case options::OPT_fapple_kext:
      DAL->append(A);
      DAL->AddFlagArg(A, Opts.getOption(options::OPT_static));
      DAL->AddFlagArg(A, Opts.getOption(options::OPT_static));
      break;

    case options::OPT_dependency_file:
      DAL->AddSeparateArg(A, Opts.getOption(options::OPT_MF),
                          A->getValue(Args));
      break;

    case options::OPT_gfull:
      DAL->AddFlagArg(A, Opts.getOption(options::OPT_g_Flag));
      DAL->AddFlagArg(A,
               Opts.getOption(options::OPT_fno_eliminate_unused_debug_symbols));
      break;

    case options::OPT_gused:
      DAL->AddFlagArg(A, Opts.getOption(options::OPT_g_Flag));
      DAL->AddFlagArg(A,
             Opts.getOption(options::OPT_feliminate_unused_debug_symbols));
      break;

    case options::OPT_fterminated_vtables:
    case options::OPT_findirect_virtual_calls:
      DAL->AddFlagArg(A, Opts.getOption(options::OPT_fapple_kext));
      DAL->AddFlagArg(A, Opts.getOption(options::OPT_static));
      break;

    case options::OPT_shared:
      DAL->AddFlagArg(A, Opts.getOption(options::OPT_dynamiclib));
      break;

    case options::OPT_fconstant_cfstrings:
      DAL->AddFlagArg(A, Opts.getOption(options::OPT_mconstant_cfstrings));
      break;

    case options::OPT_fno_constant_cfstrings:
      DAL->AddFlagArg(A, Opts.getOption(options::OPT_mno_constant_cfstrings));
      break;

    case options::OPT_Wnonportable_cfstrings:
      DAL->AddFlagArg(A,
                      Opts.getOption(options::OPT_mwarn_nonportable_cfstrings));
      break;

    case options::OPT_Wno_nonportable_cfstrings:
      DAL->AddFlagArg(A,
                   Opts.getOption(options::OPT_mno_warn_nonportable_cfstrings));
      break;

    case options::OPT_fpascal_strings:
      DAL->AddFlagArg(A, Opts.getOption(options::OPT_mpascal_strings));
      break;

    case options::OPT_fno_pascal_strings:
      DAL->AddFlagArg(A, Opts.getOption(options::OPT_mno_pascal_strings));
      break;
    }
  }

  if (getTriple().getArch() == llvm::Triple::x86 ||
      getTriple().getArch() == llvm::Triple::x86_64)
    if (!Args.hasArgNoClaim(options::OPT_mtune_EQ))
      DAL->AddJoinedArg(0, Opts.getOption(options::OPT_mtune_EQ), "core2");

  // Add the arch options based on the particular spelling of -arch, to match
  // how the driver driver works.
  if (BoundArch) {
    llvm::StringRef Name = BoundArch;
    const Option *MCpu = Opts.getOption(options::OPT_mcpu_EQ);
    const Option *MArch = Opts.getOption(options::OPT_march_EQ);

    // This code must be kept in sync with LLVM's getArchTypeForDarwinArch,
    // which defines the list of which architectures we accept.
    if (Name == "ppc")
      ;
    else if (Name == "ppc601")
      DAL->AddJoinedArg(0, MCpu, "601");
    else if (Name == "ppc603")
      DAL->AddJoinedArg(0, MCpu, "603");
    else if (Name == "ppc604")
      DAL->AddJoinedArg(0, MCpu, "604");
    else if (Name == "ppc604e")
      DAL->AddJoinedArg(0, MCpu, "604e");
    else if (Name == "ppc750")
      DAL->AddJoinedArg(0, MCpu, "750");
    else if (Name == "ppc7400")
      DAL->AddJoinedArg(0, MCpu, "7400");
    else if (Name == "ppc7450")
      DAL->AddJoinedArg(0, MCpu, "7450");
    else if (Name == "ppc970")
      DAL->AddJoinedArg(0, MCpu, "970");

    else if (Name == "ppc64")
      DAL->AddFlagArg(0, Opts.getOption(options::OPT_m64));

    else if (Name == "i386")
      ;
    else if (Name == "i486")
      DAL->AddJoinedArg(0, MArch, "i486");
    else if (Name == "i586")
      DAL->AddJoinedArg(0, MArch, "i586");
    else if (Name == "i686")
      DAL->AddJoinedArg(0, MArch, "i686");
    else if (Name == "pentium")
      DAL->AddJoinedArg(0, MArch, "pentium");
    else if (Name == "pentium2")
      DAL->AddJoinedArg(0, MArch, "pentium2");
    else if (Name == "pentpro")
      DAL->AddJoinedArg(0, MArch, "pentiumpro");
    else if (Name == "pentIIm3")
      DAL->AddJoinedArg(0, MArch, "pentium2");

    else if (Name == "x86_64")
      DAL->AddFlagArg(0, Opts.getOption(options::OPT_m64));

    else if (Name == "arm")
      DAL->AddJoinedArg(0, MArch, "armv4t");
    else if (Name == "armv4t")
      DAL->AddJoinedArg(0, MArch, "armv4t");
    else if (Name == "armv5")
      DAL->AddJoinedArg(0, MArch, "armv5tej");
    else if (Name == "xscale")
      DAL->AddJoinedArg(0, MArch, "xscale");
    else if (Name == "armv6")
      DAL->AddJoinedArg(0, MArch, "armv6k");
    else if (Name == "armv7")
      DAL->AddJoinedArg(0, MArch, "armv7a");

    else
      llvm_unreachable("invalid Darwin arch");
  }

  // Add an explicit version min argument for the deployment target. We do this
  // after argument translation because -Xarch_ arguments may add a version min
  // argument.
  AddDeploymentTarget(*DAL);

  return DAL;
}

bool Darwin::IsUnwindTablesDefault() const {
  // FIXME: Gross; we should probably have some separate target
  // definition, possibly even reusing the one in clang.
  return getArchName() == "x86_64";
}

bool Darwin::UseDwarfDebugFlags() const {
  if (const char *S = ::getenv("RC_DEBUG_OPTIONS"))
    return S[0] != '\0';
  return false;
}

bool Darwin::UseSjLjExceptions() const {
  // Darwin uses SjLj exceptions on ARM.
  return (getTriple().getArch() == llvm::Triple::arm ||
          getTriple().getArch() == llvm::Triple::thumb);
}

const char *Darwin::GetDefaultRelocationModel() const {
  return "pic";
}

const char *Darwin::GetForcedPicModel() const {
  if (getArchName() == "x86_64")
    return "pic";
  return 0;
}

bool Darwin::SupportsObjCGC() const {
  // Garbage collection is supported everywhere except on iPhone OS.
  return !isTargetIPhoneOS();
}

std::string
Darwin_Generic_GCC::ComputeEffectiveClangTriple(const ArgList &Args) const {
  return ComputeLLVMTriple(Args);
}

/// Generic_GCC - A tool chain using the 'gcc' command to perform
/// all subcommands; this relies on gcc translating the majority of
/// command line options.

Generic_GCC::Generic_GCC(const HostInfo &Host, const llvm::Triple& Triple)
  : ToolChain(Host, Triple) {
  getProgramPaths().push_back(getDriver().getInstalledDir());
  if (getDriver().getInstalledDir() != getDriver().Dir.c_str())
    getProgramPaths().push_back(getDriver().Dir);
}

Generic_GCC::~Generic_GCC() {
  // Free tool implementations.
  for (llvm::DenseMap<unsigned, Tool*>::iterator
         it = Tools.begin(), ie = Tools.end(); it != ie; ++it)
    delete it->second;
}

Tool &Generic_GCC::SelectTool(const Compilation &C,
                              const JobAction &JA) const {
  Action::ActionClass Key;
  if (getDriver().ShouldUseClangCompiler(C, JA, getTriple()))
    Key = Action::AnalyzeJobClass;
  else
    Key = JA.getKind();

  Tool *&T = Tools[Key];
  if (!T) {
    switch (Key) {
    case Action::InputClass:
    case Action::BindArchClass:
      assert(0 && "Invalid tool kind.");
    case Action::PreprocessJobClass:
      T = new tools::gcc::Preprocess(*this); break;
    case Action::PrecompileJobClass:
      T = new tools::gcc::Precompile(*this); break;
    case Action::AnalyzeJobClass:
      T = new tools::Clang(*this); break;
    case Action::CompileJobClass:
      T = new tools::gcc::Compile(*this); break;
    case Action::AssembleJobClass:
      T = new tools::gcc::Assemble(*this); break;
    case Action::LinkJobClass:
      T = new tools::gcc::Link(*this); break;

      // This is a bit ungeneric, but the only platform using a driver
      // driver is Darwin.
    case Action::LipoJobClass:
      T = new tools::darwin::Lipo(*this); break;
    case Action::DsymutilJobClass:
      T = new tools::darwin::Dsymutil(*this); break;
    }
  }

  return *T;
}

bool Generic_GCC::IsUnwindTablesDefault() const {
  // FIXME: Gross; we should probably have some separate target
  // definition, possibly even reusing the one in clang.
  return getArchName() == "x86_64";
}

const char *Generic_GCC::GetDefaultRelocationModel() const {
  return "static";
}

const char *Generic_GCC::GetForcedPicModel() const {
  return 0;
}

/// TCEToolChain - A tool chain using the llvm bitcode tools to perform
/// all subcommands. See http://tce.cs.tut.fi for our peculiar target.
/// Currently does not support anything else but compilation.

TCEToolChain::TCEToolChain(const HostInfo &Host, const llvm::Triple& Triple)
  : ToolChain(Host, Triple) {
  // Path mangling to find libexec
  std::string Path(getDriver().Dir);

  Path += "/../libexec";
  getProgramPaths().push_back(Path);
}

TCEToolChain::~TCEToolChain() {
  for (llvm::DenseMap<unsigned, Tool*>::iterator
           it = Tools.begin(), ie = Tools.end(); it != ie; ++it)
      delete it->second;
}

bool TCEToolChain::IsMathErrnoDefault() const { 
  return true; 
}

bool TCEToolChain::IsUnwindTablesDefault() const {
  return false;
}

const char *TCEToolChain::GetDefaultRelocationModel() const {
  return "static";
}

const char *TCEToolChain::GetForcedPicModel() const {
  return 0;
}

Tool &TCEToolChain::SelectTool(const Compilation &C, 
                            const JobAction &JA) const {
  Action::ActionClass Key;
  Key = Action::AnalyzeJobClass;

  Tool *&T = Tools[Key];
  if (!T) {
    switch (Key) {
    case Action::PreprocessJobClass:
      T = new tools::gcc::Preprocess(*this); break;
    case Action::AnalyzeJobClass:
      T = new tools::Clang(*this); break;
    default:
     assert(false && "Unsupported action for TCE target.");
    }
  }
  return *T;
}

/// OpenBSD - OpenBSD tool chain which can call as(1) and ld(1) directly.

OpenBSD::OpenBSD(const HostInfo &Host, const llvm::Triple& Triple)
  : Generic_GCC(Host, Triple) {
  getFilePaths().push_back(getDriver().Dir + "/../lib");
  getFilePaths().push_back("/usr/lib");
}

Tool &OpenBSD::SelectTool(const Compilation &C, const JobAction &JA) const {
  Action::ActionClass Key;
  if (getDriver().ShouldUseClangCompiler(C, JA, getTriple()))
    Key = Action::AnalyzeJobClass;
  else
    Key = JA.getKind();

  Tool *&T = Tools[Key];
  if (!T) {
    switch (Key) {
    case Action::AssembleJobClass:
      T = new tools::openbsd::Assemble(*this); break;
    case Action::LinkJobClass:
      T = new tools::openbsd::Link(*this); break;
    default:
      T = &Generic_GCC::SelectTool(C, JA);
    }
  }

  return *T;
}

/// FreeBSD - FreeBSD tool chain which can call as(1) and ld(1) directly.

FreeBSD::FreeBSD(const HostInfo &Host, const llvm::Triple& Triple)
  : Generic_GCC(Host, Triple) {

  // Determine if we are compiling 32-bit code on an x86_64 platform.
  bool Lib32 = false;
  if (Triple.getArch() == llvm::Triple::x86 &&
      llvm::Triple(getDriver().DefaultHostTriple).getArch() ==
        llvm::Triple::x86_64)
    Lib32 = true;
    
  getProgramPaths().push_back(getDriver().Dir + "/../libexec");
  getProgramPaths().push_back("/usr/libexec");
  if (Lib32) {
    getFilePaths().push_back(getDriver().Dir + "/../lib32");
    getFilePaths().push_back("/usr/lib32");
  } else {
    getFilePaths().push_back(getDriver().Dir + "/../lib");
    getFilePaths().push_back("/usr/lib");
  }
}

Tool &FreeBSD::SelectTool(const Compilation &C, const JobAction &JA) const {
  Action::ActionClass Key;
  if (getDriver().ShouldUseClangCompiler(C, JA, getTriple()))
    Key = Action::AnalyzeJobClass;
  else
    Key = JA.getKind();

  Tool *&T = Tools[Key];
  if (!T) {
    switch (Key) {
    case Action::AssembleJobClass:
      T = new tools::freebsd::Assemble(*this); break;
    case Action::LinkJobClass:
      T = new tools::freebsd::Link(*this); break;
    default:
      T = &Generic_GCC::SelectTool(C, JA);
    }
  }

  return *T;
}

/// Minix - Minix tool chain which can call as(1) and ld(1) directly.

Minix::Minix(const HostInfo &Host, const llvm::Triple& Triple)
  : Generic_GCC(Host, Triple) {
  getFilePaths().push_back(getDriver().Dir + "/../lib");
  getFilePaths().push_back("/usr/lib");
  getFilePaths().push_back("/usr/gnu/lib");
  getFilePaths().push_back("/usr/gnu/lib/gcc/i686-pc-minix/4.4.3");
}

Tool &Minix::SelectTool(const Compilation &C, const JobAction &JA) const {
  Action::ActionClass Key;
  if (getDriver().ShouldUseClangCompiler(C, JA, getTriple()))
    Key = Action::AnalyzeJobClass;
  else
    Key = JA.getKind();

  Tool *&T = Tools[Key];
  if (!T) {
    switch (Key) {
    case Action::AssembleJobClass:
      T = new tools::minix::Assemble(*this); break;
    case Action::LinkJobClass:
      T = new tools::minix::Link(*this); break;
    default:
      T = &Generic_GCC::SelectTool(C, JA);
    }
  }

  return *T;
}

/// AuroraUX - AuroraUX tool chain which can call as(1) and ld(1) directly.

AuroraUX::AuroraUX(const HostInfo &Host, const llvm::Triple& Triple)
  : Generic_GCC(Host, Triple) {

  getProgramPaths().push_back(getDriver().getInstalledDir());
  if (getDriver().getInstalledDir() != getDriver().Dir.c_str())
    getProgramPaths().push_back(getDriver().Dir);

  getFilePaths().push_back(getDriver().Dir + "/../lib");
  getFilePaths().push_back("/usr/lib");
  getFilePaths().push_back("/usr/sfw/lib");
  getFilePaths().push_back("/opt/gcc4/lib");
  getFilePaths().push_back("/opt/gcc4/lib/gcc/i386-pc-solaris2.11/4.2.4");

}

Tool &AuroraUX::SelectTool(const Compilation &C, const JobAction &JA) const {
  Action::ActionClass Key;
  if (getDriver().ShouldUseClangCompiler(C, JA, getTriple()))
    Key = Action::AnalyzeJobClass;
  else
    Key = JA.getKind();

  Tool *&T = Tools[Key];
  if (!T) {
    switch (Key) {
    case Action::AssembleJobClass:
      T = new tools::auroraux::Assemble(*this); break;
    case Action::LinkJobClass:
      T = new tools::auroraux::Link(*this); break;
    default:
      T = &Generic_GCC::SelectTool(C, JA);
    }
  }

  return *T;
}


/// Linux toolchain (very bare-bones at the moment).

Linux::Linux(const HostInfo &Host, const llvm::Triple& Triple)
  : Generic_GCC(Host, Triple) {
  getFilePaths().push_back(getDriver().Dir +
                           "/../lib/clang/" CLANG_VERSION_STRING "/");
  getFilePaths().push_back("/lib/");
  getFilePaths().push_back("/usr/lib/");

  // Depending on the Linux distribution, any combination of lib{,32,64} is
  // possible. E.g. Debian uses lib and lib32 for mixed i386/x86-64 systems,
  // openSUSE uses lib and lib64 for the same purpose.
  getFilePaths().push_back("/lib32/");
  getFilePaths().push_back("/usr/lib32/");
  getFilePaths().push_back("/lib64/");
  getFilePaths().push_back("/usr/lib64/");

  // FIXME: Figure out some way to get gcc's libdir
  // (e.g. /usr/lib/gcc/i486-linux-gnu/4.3/ for Ubuntu 32-bit); we need
  // crtbegin.o/crtend.o/etc., and want static versions of various
  // libraries. If we had our own crtbegin.o/crtend.o/etc, we could probably
  // get away with using shared versions in /usr/lib, though.
  // We could fall back to the approach we used for includes (a massive
  // list), but that's messy at best.
}

Tool &Linux::SelectTool(const Compilation &C, const JobAction &JA) const {
  Action::ActionClass Key;
  if (getDriver().ShouldUseClangCompiler(C, JA, getTriple()))
    Key = Action::AnalyzeJobClass;
  else
    Key = JA.getKind();

  Tool *&T = Tools[Key];
  if (!T) {
    switch (Key) {
    case Action::AssembleJobClass:
      T = new tools::linuxtools::Assemble(*this); break;
    default:
      T = &Generic_GCC::SelectTool(C, JA);
    }
  }

  return *T;
}

/// DragonFly - DragonFly tool chain which can call as(1) and ld(1) directly.

DragonFly::DragonFly(const HostInfo &Host, const llvm::Triple& Triple)
  : Generic_GCC(Host, Triple) {

  // Path mangling to find libexec
  getProgramPaths().push_back(getDriver().getInstalledDir());
  if (getDriver().getInstalledDir() != getDriver().Dir.c_str())
    getProgramPaths().push_back(getDriver().Dir);

  getFilePaths().push_back(getDriver().Dir + "/../lib");
  getFilePaths().push_back("/usr/lib");
  getFilePaths().push_back("/usr/lib/gcc41");
}

Tool &DragonFly::SelectTool(const Compilation &C, const JobAction &JA) const {
  Action::ActionClass Key;
  if (getDriver().ShouldUseClangCompiler(C, JA, getTriple()))
    Key = Action::AnalyzeJobClass;
  else
    Key = JA.getKind();

  Tool *&T = Tools[Key];
  if (!T) {
    switch (Key) {
    case Action::AssembleJobClass:
      T = new tools::dragonfly::Assemble(*this); break;
    case Action::LinkJobClass:
      T = new tools::dragonfly::Link(*this); break;
    default:
      T = &Generic_GCC::SelectTool(C, JA);
    }
  }

  return *T;
}

Windows::Windows(const HostInfo &Host, const llvm::Triple& Triple)
  : ToolChain(Host, Triple) {
}

Tool &Windows::SelectTool(const Compilation &C, const JobAction &JA) const {
  Action::ActionClass Key;
  if (getDriver().ShouldUseClangCompiler(C, JA, getTriple()))
    Key = Action::AnalyzeJobClass;
  else
    Key = JA.getKind();

  Tool *&T = Tools[Key];
  if (!T) {
    switch (Key) {
    case Action::InputClass:
    case Action::BindArchClass:
    case Action::LipoJobClass:
    case Action::DsymutilJobClass:
      assert(0 && "Invalid tool kind.");
    case Action::PreprocessJobClass:
    case Action::PrecompileJobClass:
    case Action::AnalyzeJobClass:
    case Action::CompileJobClass:
      T = new tools::Clang(*this); break;
    case Action::AssembleJobClass:
      T = new tools::ClangAs(*this); break;
    case Action::LinkJobClass:
      T = new tools::visualstudio::Link(*this); break;
    }
  }

  return *T;
}

bool Windows::IsIntegratedAssemblerDefault() const {
  return true;
}

bool Windows::IsUnwindTablesDefault() const {
  // FIXME: Gross; we should probably have some separate target
  // definition, possibly even reusing the one in clang.
  return getArchName() == "x86_64";
}

const char *Windows::GetDefaultRelocationModel() const {
  return "static";
}

const char *Windows::GetForcedPicModel() const {
  if (getArchName() == "x86_64")
    return "pic";
  return 0;
}
