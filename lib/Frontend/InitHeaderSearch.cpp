//===--- InitHeaderSearch.cpp - Initialize header search paths ----------*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements the InitHeaderSearch class.
//
//===----------------------------------------------------------------------===//

#include "clang/Frontend/Utils.h"
#include "clang/Basic/FileManager.h"
#include "clang/Basic/LangOptions.h"
#include "clang/Frontend/HeaderSearchOptions.h"
#include "clang/Lex/HeaderSearch.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/Triple.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/System/Path.h"
#include "llvm/Config/config.h"
#include <cstdio>
#ifdef _MSC_VER
  #define WIN32_LEAN_AND_MEAN 1
  #include <windows.h>
#endif
using namespace clang;
using namespace clang::frontend;

namespace {

/// InitHeaderSearch - This class makes it easier to set the search paths of
///  a HeaderSearch object. InitHeaderSearch stores several search path lists
///  internally, which can be sent to a HeaderSearch object in one swoop.
class InitHeaderSearch {
  std::vector<DirectoryLookup> IncludeGroup[4];
  HeaderSearch& Headers;
  bool Verbose;
  std::string isysroot;

public:

  InitHeaderSearch(HeaderSearch &HS,
      bool verbose = false, const std::string &iSysroot = "")
    : Headers(HS), Verbose(verbose), isysroot(iSysroot) {}

  /// AddPath - Add the specified path to the specified group list.
  void AddPath(const llvm::StringRef &Path, IncludeDirGroup Group,
               bool isCXXAware, bool isUserSupplied,
               bool isFramework, bool IgnoreSysRoot = false);

  /// AddGnuCPlusPlusIncludePaths - Add the necessary paths to suport a gnu
  ///  libstdc++.
  void AddGnuCPlusPlusIncludePaths(const std::string &Base,
                                   const char *ArchDir,
                                   const char *Dir32,
                                   const char *Dir64,
                                   const llvm::Triple &triple);

  /// AddMinGWCPlusPlusIncludePaths - Add the necessary paths to suport a MinGW
  ///  libstdc++.
  void AddMinGWCPlusPlusIncludePaths(const std::string &Base,
                                     const char *Arch,
                                     const char *Version);

  /// AddDelimitedPaths - Add a list of paths delimited by the system PATH
  /// separator. The processing follows that of the CPATH variable for gcc.
  void AddDelimitedPaths(const char *String);

  // AddDefaultCIncludePaths - Add paths that should always be searched.
  void AddDefaultCIncludePaths(const llvm::Triple &triple);

  // AddDefaultCPlusPlusIncludePaths -  Add paths that should be searched when
  //  compiling c++.
  void AddDefaultCPlusPlusIncludePaths(const llvm::Triple &triple);

  /// AddDefaultSystemIncludePaths - Adds the default system include paths so
  ///  that e.g. stdio.h is found.
  void AddDefaultSystemIncludePaths(const LangOptions &Lang,
                                    const llvm::Triple &triple);

  /// Realize - Merges all search path lists into one list and send it to
  /// HeaderSearch.
  void Realize();
};

}

void InitHeaderSearch::AddPath(const llvm::StringRef &Path,
                               IncludeDirGroup Group, bool isCXXAware,
                               bool isUserSupplied, bool isFramework,
                               bool IgnoreSysRoot) {
  assert(!Path.empty() && "can't handle empty path here");
  FileManager &FM = Headers.getFileMgr();

  // Compute the actual path, taking into consideration -isysroot.
  llvm::SmallString<256> MappedPath;

  // Handle isysroot.
  if (Group == System && !IgnoreSysRoot) {
    // FIXME: Portability.  This should be a sys::Path interface, this doesn't
    // handle things like C:\ right, nor win32 \\network\device\blah.
    if (isysroot.size() != 1 || isysroot[0] != '/') // Add isysroot if present.
      MappedPath.append(isysroot.begin(), isysroot.end());
  }

  MappedPath.append(Path.begin(), Path.end());

  // Compute the DirectoryLookup type.
  SrcMgr::CharacteristicKind Type;
  if (Group == Quoted || Group == Angled)
    Type = SrcMgr::C_User;
  else if (isCXXAware)
    Type = SrcMgr::C_System;
  else
    Type = SrcMgr::C_ExternCSystem;


  // If the directory exists, add it.
  if (const DirectoryEntry *DE = FM.getDirectory(MappedPath.str())) {
    IncludeGroup[Group].push_back(DirectoryLookup(DE, Type, isUserSupplied,
                                                  isFramework));
    return;
  }

  // Check to see if this is an apple-style headermap (which are not allowed to
  // be frameworks).
  if (!isFramework) {
    if (const FileEntry *FE = FM.getFile(MappedPath.str())) {
      if (const HeaderMap *HM = Headers.CreateHeaderMap(FE)) {
        // It is a headermap, add it to the search path.
        IncludeGroup[Group].push_back(DirectoryLookup(HM, Type,isUserSupplied));
        return;
      }
    }
  }

  if (Verbose)
    llvm::errs() << "ignoring nonexistent directory \""
                 << MappedPath.str() << "\"\n";
}


void InitHeaderSearch::AddDelimitedPaths(const char *at) {
  if (*at == 0) // Empty string should not add '.' path.
    return;

  const char* delim = strchr(at, llvm::sys::PathSeparator);
  while (delim != 0) {
    if (delim-at == 0)
      AddPath(".", Angled, false, true, false);
    else
      AddPath(llvm::StringRef(at, delim-at), Angled, false, true, false);
    at = delim + 1;
    delim = strchr(at, llvm::sys::PathSeparator);
  }
  if (*at == 0)
    AddPath(".", Angled, false, true, false);
  else
    AddPath(at, Angled, false, true, false);
}

void InitHeaderSearch::AddGnuCPlusPlusIncludePaths(const std::string &Base,
                                                   const char *ArchDir,
                                                   const char *Dir32,
                                                   const char *Dir64,
                                                   const llvm::Triple &triple) {
  // Add the common dirs
  AddPath(Base, System, true, false, false);
  AddPath(Base + "/backward", System, true, false, false);

  // Add the multilib dirs
  llvm::Triple::ArchType arch = triple.getArch();
  bool is64bit = arch == llvm::Triple::ppc64 || arch == llvm::Triple::x86_64;
  if (is64bit)
    AddPath(Base + "/" + ArchDir + "/" + Dir64, System, true, false, false);
  else
    AddPath(Base + "/" + ArchDir + "/" + Dir32, System, true, false, false);
}

void InitHeaderSearch::AddMinGWCPlusPlusIncludePaths(const std::string &Base,
                                                     const char *Arch,
                                                     const char *Version) {
  std::string localBase = Base + "/" + Arch + "/" + Version + "/include";
  AddPath(localBase, System, true, false, false);
  AddPath(localBase + "/c++", System, true, false, false);
  AddPath(localBase + "/c++/backward", System, true, false, false);
}

  // FIXME: This probably should goto to some platform utils place.
#ifdef _MSC_VER
  // Read registry string.
bool getSystemRegistryString(const char *keyPath, const char *valueName,
                       char *value, size_t maxLength) {
  HKEY hRootKey = NULL;
  HKEY hKey = NULL;
  const char* subKey = NULL;
  DWORD valueType;
  DWORD valueSize = maxLength - 1;
  bool returnValue = false;
  if (strncmp(keyPath, "HKEY_CLASSES_ROOT\\", 18) == 0) {
    hRootKey = HKEY_CLASSES_ROOT;
    subKey = keyPath + 18;
  }
  else if (strncmp(keyPath, "HKEY_USERS\\", 11) == 0) {
    hRootKey = HKEY_USERS;
    subKey = keyPath + 11;
  }
  else if (strncmp(keyPath, "HKEY_LOCAL_MACHINE\\", 19) == 0) {
    hRootKey = HKEY_LOCAL_MACHINE;
    subKey = keyPath + 19;
  }
  else if (strncmp(keyPath, "HKEY_CURRENT_USER\\", 18) == 0) {
    hRootKey = HKEY_CURRENT_USER;
    subKey = keyPath + 18;
  }
  else
    return(false);
  long lResult = RegOpenKeyEx(hRootKey, subKey, 0, KEY_READ, &hKey);
  if (lResult == ERROR_SUCCESS) {
    lResult = RegQueryValueEx(hKey, valueName, NULL, &valueType,
      (LPBYTE)value, &valueSize);
    if (lResult == ERROR_SUCCESS)
      returnValue = true;
    RegCloseKey(hKey);
  }
  return(returnValue);
}
#else // _MSC_VER
  // Read registry string.
bool getSystemRegistryString(const char *, const char *, char *, size_t) {
  return(false);
}
#endif // _MSC_VER

  // Get Visual Studio installation directory.
bool getVisualStudioDir(std::string &path) {
  // Try the Windows registry first.
  char vs80IDEInstallDir[256];
  char vs90IDEInstallDir[256];
  const char* vsIDEInstallDir = NULL;
  bool has80 = getSystemRegistryString(
    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\VisualStudio\\8.0",
    "InstallDir", vs80IDEInstallDir, sizeof(vs80IDEInstallDir) - 1);
  bool has90 = getSystemRegistryString(
    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\VisualStudio\\9.0",
    "InstallDir", vs90IDEInstallDir, sizeof(vs90IDEInstallDir) - 1);
    // If we have both vc80 and vc90, pick version we were compiled with. 
  if (has80 && has90) {
    #ifdef _MSC_VER
      #if (_MSC_VER >= 1500)  // VC90
          vsIDEInstallDir = vs90IDEInstallDir;
      #elif (_MSC_VER == 1400) // VC80
          vsIDEInstallDir = vs80IDEInstallDir;
      #else
          vsIDEInstallDir = vs90IDEInstallDir;
      #endif
    #else
      vsIDEInstallDir = vs90IDEInstallDir;
    #endif
  }
  else if (has90)
    vsIDEInstallDir = vs90IDEInstallDir;
  else if (has80)
    vsIDEInstallDir = vs80IDEInstallDir;
  if (vsIDEInstallDir && *vsIDEInstallDir) {
    char *p = (char*)strstr(vsIDEInstallDir, "\\Common7\\IDE");
    if (p)
      *p = '\0';
    path = vsIDEInstallDir;
    return(true);
  }
  else {
    // Try the environment.
    const char* vs90comntools = getenv("VS90COMNTOOLS");
    const char* vs80comntools = getenv("VS80COMNTOOLS");
    const char* vscomntools = NULL;
      // If we have both vc80 and vc90, pick version we were compiled with. 
    if (vs90comntools && vs80comntools) {
      #if (_MSC_VER >= 1500)  // VC90
          vscomntools = vs90comntools;
      #elif (_MSC_VER == 1400) // VC80
          vscomntools = vs80comntools;
      #else
          vscomntools = vs90comntools;
      #endif
    }
    else if (vs90comntools)
      vscomntools = vs90comntools;
    else if (vs80comntools)
      vscomntools = vs80comntools;
    if (vscomntools && *vscomntools) {
      char *p = (char*)strstr(vscomntools, "\\Common7\\Tools");
      if (p)
        *p = '\0';
      path = vscomntools;
      return(true);
    }
    else
      return(false);
  }
  return(false);
}

void InitHeaderSearch::AddDefaultCIncludePaths(const llvm::Triple &triple) {
  // FIXME: temporary hack: hard-coded paths.
  llvm::StringRef CIncludeDirs(C_INCLUDE_DIRS);
  if (CIncludeDirs != "") {
    llvm::SmallVector<llvm::StringRef, 5> dirs;
    CIncludeDirs.split(dirs, ":");
    for (llvm::SmallVectorImpl<llvm::StringRef>::iterator i = dirs.begin();
         i != dirs.end();
         ++i) 
      AddPath(*i, System, false, false, false);
    return;
  }
  llvm::Triple::OSType os = triple.getOS();
  switch (os) {
  case llvm::Triple::Win32:
    {
      std::string VSDir;
      if (getVisualStudioDir(VSDir)) {
        AddPath(VSDir + "\\VC\\include", System, false, false, false);
        AddPath(VSDir + "\\VC\\PlatformSDK\\Include",
          System, false, false, false);
      }
      else {
          // Default install paths.
        AddPath("C:/Program Files/Microsoft Visual Studio 9.0/VC/include",
          System, false, false, false);
        AddPath(
        "C:/Program Files/Microsoft Visual Studio 9.0/VC/PlatformSDK/Include",
          System, false, false, false);
        AddPath("C:/Program Files/Microsoft Visual Studio 8/VC/include",
          System, false, false, false);
        AddPath(
        "C:/Program Files/Microsoft Visual Studio 8/VC/PlatformSDK/Include",
          System, false, false, false);
          // For some clang developers.
        AddPath("G:/Program Files/Microsoft Visual Studio 9.0/VC/include",
          System, false, false, false);
        AddPath(
        "G:/Program Files/Microsoft Visual Studio 9.0/VC/PlatformSDK/Include",
          System, false, false, false);
      }
    }
    break;
  case llvm::Triple::MinGW64:
  case llvm::Triple::MinGW32:
    AddPath("c:/mingw/include", System, true, false, false);
    break;
  default:
    break;
  }

  AddPath("/usr/local/include", System, false, false, false);
  AddPath("/usr/include", System, false, false, false);
}

void InitHeaderSearch::AddDefaultCPlusPlusIncludePaths(const llvm::Triple &triple) {
  llvm::Triple::OSType os = triple.getOS();
  llvm::StringRef CxxIncludeRoot(CXX_INCLUDE_ROOT);
  if (CxxIncludeRoot != "") {
    llvm::StringRef CxxIncludeArch(CXX_INCLUDE_ARCH);
    if (CxxIncludeArch == "")
      AddGnuCPlusPlusIncludePaths(CxxIncludeRoot, triple.str().c_str(),
                                  CXX_INCLUDE_32BIT_DIR, CXX_INCLUDE_64BIT_DIR, triple);
    else
      AddGnuCPlusPlusIncludePaths(CxxIncludeRoot, CXX_INCLUDE_ARCH,
                                  CXX_INCLUDE_32BIT_DIR, CXX_INCLUDE_64BIT_DIR, triple);
    return;
  }
  // FIXME: temporary hack: hard-coded paths.
  switch (os) {
  case llvm::Triple::Cygwin:
    AddPath("/lib/gcc/i686-pc-cygwin/3.4.4/include",
        System, true, false, false);
    AddPath("/lib/gcc/i686-pc-cygwin/3.4.4/include/c++",
        System, true, false, false);
    break;
  case llvm::Triple::MinGW64:
    // Try gcc 4.4.0
    AddMinGWCPlusPlusIncludePaths("c:/MinGW/lib/gcc", "mingw64", "4.4.0");
    // Try gcc 4.3.0
    AddMinGWCPlusPlusIncludePaths("c:/MinGW/lib/gcc", "mingw64", "4.3.0");
    // Fall through.
  case llvm::Triple::MinGW32:
    // Try gcc 4.4.0
    AddMinGWCPlusPlusIncludePaths("c:/MinGW/lib/gcc", "mingw32", "4.4.0");
    // Try gcc 4.3.0
    AddMinGWCPlusPlusIncludePaths("c:/MinGW/lib/gcc", "mingw32", "4.3.0");
    break;
  case llvm::Triple::Darwin:
    AddGnuCPlusPlusIncludePaths("/usr/include/c++/4.2.1",
                                "i686-apple-darwin10", "", "x86_64", triple);
    AddGnuCPlusPlusIncludePaths("/usr/include/c++/4.0.0",
                                "i686-apple-darwin8", "", "", triple);
    break;
  case llvm::Triple::Linux:
    // Ubuntu 7.10 - Gutsy Gibbon
    AddGnuCPlusPlusIncludePaths("/usr/include/c++/4.1.3",
                                "i486-linux-gnu", "", "", triple);
    // Ubuntu 9.04
    AddGnuCPlusPlusIncludePaths("/usr/include/c++/4.3.3",
                                "x86_64-linux-gnu","32", "", triple);
    // Ubuntu 9.10
    AddGnuCPlusPlusIncludePaths("/usr/include/c++/4.4.1",
                                "x86_64-linux-gnu", "32", "", triple);
    // Fedora 8
    AddGnuCPlusPlusIncludePaths("/usr/include/c++/4.1.2",
                                "i386-redhat-linux", "", "", triple);
    // Fedora 9
    AddGnuCPlusPlusIncludePaths("/usr/include/c++/4.3.0",
                                "i386-redhat-linux", "", "", triple);
    // Fedora 10
    AddGnuCPlusPlusIncludePaths("/usr/include/c++/4.3.2",
                                "i386-redhat-linux","", "", triple);
    // openSUSE 11.1 32 bit
    AddGnuCPlusPlusIncludePaths("/usr/include/c++/4.3",
                                "i586-suse-linux", "", "", triple);
    // openSUSE 11.1 64 bit
    AddGnuCPlusPlusIncludePaths("/usr/include/c++/4.3",
                                "x86_64-suse-linux", "32", "", triple);
    // openSUSE 11.2
    AddGnuCPlusPlusIncludePaths("/usr/include/c++/4.4",
                                "i586-suse-linux", "", "", triple);
    AddGnuCPlusPlusIncludePaths("/usr/include/c++/4.4",
                                "x86_64-suse-linux", "", "", triple);
    // Arch Linux 2008-06-24
    AddGnuCPlusPlusIncludePaths("/usr/include/c++/4.3.1",
                                "i686-pc-linux-gnu", "", "", triple);
    AddGnuCPlusPlusIncludePaths("/usr/include/c++/4.3.1",
                                "x86_64-unknown-linux-gnu", "", "", triple);
    // Gentoo x86 2009.1 stable
    AddGnuCPlusPlusIncludePaths(
      "/usr/lib/gcc/i686-pc-linux-gnu/4.3.4/include/g++-v4",
      "i686-pc-linux-gnu", "", "", triple);
    // Gentoo x86 2009.0 stable
    AddGnuCPlusPlusIncludePaths(
      "/usr/lib/gcc/i686-pc-linux-gnu/4.3.2/include/g++-v4",
      "i686-pc-linux-gnu", "", "", triple);
    // Gentoo x86 2008.0 stable
    AddGnuCPlusPlusIncludePaths(
      "/usr/lib/gcc/i686-pc-linux-gnu/4.1.2/include/g++-v4",
      "i686-pc-linux-gnu", "", "", triple);
    // Ubuntu 8.10
    AddGnuCPlusPlusIncludePaths("/usr/include/c++/4.3",
                                "i486-pc-linux-gnu", "", "", triple);
    // Ubuntu 9.04
    AddGnuCPlusPlusIncludePaths("/usr/include/c++/4.3",
                                "i486-linux-gnu","", "", triple);
    // Gentoo amd64 stable
    AddGnuCPlusPlusIncludePaths(
        "/usr/lib/gcc/x86_64-pc-linux-gnu/4.1.2/include/g++-v4",
        "i686-pc-linux-gnu", "", "", triple);
    // Exherbo (2009-10-26)
    AddGnuCPlusPlusIncludePaths("/usr/include/c++/4.4.2",
                                "x86_64-pc-linux-gnu", "32", "", triple);
    AddGnuCPlusPlusIncludePaths("/usr/include/c++/4.4.2",
                                "i686-pc-linux-gnu", "", "", triple);
    break;
  case llvm::Triple::FreeBSD:
    // DragonFly
    AddPath("/usr/include/c++/4.1", System, true, false, false);
    // FreeBSD
    AddPath("/usr/include/c++/4.2", System, true, false, false);
    break;
  case llvm::Triple::Solaris:
    // Solaris - Fall though..
  case llvm::Triple::AuroraUX:
    // AuroraUX
    AddGnuCPlusPlusIncludePaths("/opt/gcc4/include/c++/4.2.4",
                                "i386-pc-solaris2.11", "", "", triple);
    break;
  default:
    break;
  }
}

void InitHeaderSearch::AddDefaultSystemIncludePaths(const LangOptions &Lang,
                                                    const llvm::Triple &triple) {
  AddDefaultCIncludePaths(triple);

  // Add the default framework include paths on Darwin.
  if (triple.getOS() == llvm::Triple::Darwin) {
    AddPath("/System/Library/Frameworks", System, true, false, true);
    AddPath("/Library/Frameworks", System, true, false, true);
  }

  if (Lang.CPlusPlus)
    AddDefaultCPlusPlusIncludePaths(triple);
}

/// RemoveDuplicates - If there are duplicate directory entries in the specified
/// search list, remove the later (dead) ones.
static void RemoveDuplicates(std::vector<DirectoryLookup> &SearchList,
                             bool Verbose) {
  llvm::SmallPtrSet<const DirectoryEntry *, 8> SeenDirs;
  llvm::SmallPtrSet<const DirectoryEntry *, 8> SeenFrameworkDirs;
  llvm::SmallPtrSet<const HeaderMap *, 8> SeenHeaderMaps;
  for (unsigned i = 0; i != SearchList.size(); ++i) {
    unsigned DirToRemove = i;

    const DirectoryLookup &CurEntry = SearchList[i];

    if (CurEntry.isNormalDir()) {
      // If this isn't the first time we've seen this dir, remove it.
      if (SeenDirs.insert(CurEntry.getDir()))
        continue;
    } else if (CurEntry.isFramework()) {
      // If this isn't the first time we've seen this framework dir, remove it.
      if (SeenFrameworkDirs.insert(CurEntry.getFrameworkDir()))
        continue;
    } else {
      assert(CurEntry.isHeaderMap() && "Not a headermap or normal dir?");
      // If this isn't the first time we've seen this headermap, remove it.
      if (SeenHeaderMaps.insert(CurEntry.getHeaderMap()))
        continue;
    }

    // If we have a normal #include dir/framework/headermap that is shadowed
    // later in the chain by a system include location, we actually want to
    // ignore the user's request and drop the user dir... keeping the system
    // dir.  This is weird, but required to emulate GCC's search path correctly.
    //
    // Since dupes of system dirs are rare, just rescan to find the original
    // that we're nuking instead of using a DenseMap.
    if (CurEntry.getDirCharacteristic() != SrcMgr::C_User) {
      // Find the dir that this is the same of.
      unsigned FirstDir;
      for (FirstDir = 0; ; ++FirstDir) {
        assert(FirstDir != i && "Didn't find dupe?");

        const DirectoryLookup &SearchEntry = SearchList[FirstDir];

        // If these are different lookup types, then they can't be the dupe.
        if (SearchEntry.getLookupType() != CurEntry.getLookupType())
          continue;

        bool isSame;
        if (CurEntry.isNormalDir())
          isSame = SearchEntry.getDir() == CurEntry.getDir();
        else if (CurEntry.isFramework())
          isSame = SearchEntry.getFrameworkDir() == CurEntry.getFrameworkDir();
        else {
          assert(CurEntry.isHeaderMap() && "Not a headermap or normal dir?");
          isSame = SearchEntry.getHeaderMap() == CurEntry.getHeaderMap();
        }

        if (isSame)
          break;
      }

      // If the first dir in the search path is a non-system dir, zap it
      // instead of the system one.
      if (SearchList[FirstDir].getDirCharacteristic() == SrcMgr::C_User)
        DirToRemove = FirstDir;
    }

    if (Verbose) {
      fprintf(stderr, "ignoring duplicate directory \"%s\"\n",
              CurEntry.getName());
      if (DirToRemove != i)
        fprintf(stderr, "  as it is a non-system directory that duplicates"
                " a system directory\n");
    }

    // This is reached if the current entry is a duplicate.  Remove the
    // DirToRemove (usually the current dir).
    SearchList.erase(SearchList.begin()+DirToRemove);
    --i;
  }
}


void InitHeaderSearch::Realize() {
  // Concatenate ANGLE+SYSTEM+AFTER chains together into SearchList.
  std::vector<DirectoryLookup> SearchList;
  SearchList = IncludeGroup[Angled];
  SearchList.insert(SearchList.end(), IncludeGroup[System].begin(),
                    IncludeGroup[System].end());
  SearchList.insert(SearchList.end(), IncludeGroup[After].begin(),
                    IncludeGroup[After].end());
  RemoveDuplicates(SearchList, Verbose);
  RemoveDuplicates(IncludeGroup[Quoted], Verbose);

  // Prepend QUOTED list on the search list.
  SearchList.insert(SearchList.begin(), IncludeGroup[Quoted].begin(),
                    IncludeGroup[Quoted].end());


  bool DontSearchCurDir = false;  // TODO: set to true if -I- is set?
  Headers.SetSearchPaths(SearchList, IncludeGroup[Quoted].size(),
                         DontSearchCurDir);

  // If verbose, print the list of directories that will be searched.
  if (Verbose) {
    fprintf(stderr, "#include \"...\" search starts here:\n");
    unsigned QuotedIdx = IncludeGroup[Quoted].size();
    for (unsigned i = 0, e = SearchList.size(); i != e; ++i) {
      if (i == QuotedIdx)
        fprintf(stderr, "#include <...> search starts here:\n");
      const char *Name = SearchList[i].getName();
      const char *Suffix;
      if (SearchList[i].isNormalDir())
        Suffix = "";
      else if (SearchList[i].isFramework())
        Suffix = " (framework directory)";
      else {
        assert(SearchList[i].isHeaderMap() && "Unknown DirectoryLookup");
        Suffix = " (headermap)";
      }
      fprintf(stderr, " %s%s\n", Name, Suffix);
    }
    fprintf(stderr, "End of search list.\n");
  }
}

void clang::ApplyHeaderSearchOptions(HeaderSearch &HS,
                                     const HeaderSearchOptions &HSOpts,
                                     const LangOptions &Lang,
                                     const llvm::Triple &Triple) {
  InitHeaderSearch Init(HS, HSOpts.Verbose, HSOpts.Sysroot);

  // Add the user defined entries.
  for (unsigned i = 0, e = HSOpts.UserEntries.size(); i != e; ++i) {
    const HeaderSearchOptions::Entry &E = HSOpts.UserEntries[i];
    Init.AddPath(E.Path, E.Group, false, E.IsUserSupplied, E.IsFramework,
                 false);
  }

  // Add entries from CPATH and friends.
  Init.AddDelimitedPaths(HSOpts.EnvIncPath.c_str());
  if (Lang.CPlusPlus && Lang.ObjC1)
    Init.AddDelimitedPaths(HSOpts.ObjCXXEnvIncPath.c_str());
  else if (Lang.CPlusPlus)
    Init.AddDelimitedPaths(HSOpts.CXXEnvIncPath.c_str());
  else if (Lang.ObjC1)
    Init.AddDelimitedPaths(HSOpts.ObjCEnvIncPath.c_str());
  else
    Init.AddDelimitedPaths(HSOpts.CEnvIncPath.c_str());

  if (!HSOpts.BuiltinIncludePath.empty()) {
    // Ignore the sys root, we *always* look for clang headers relative to
    // supplied path.
    Init.AddPath(HSOpts.BuiltinIncludePath, System,
                 false, false, false, /*IgnoreSysRoot=*/ true);
  }

  if (HSOpts.UseStandardIncludes)
    Init.AddDefaultSystemIncludePaths(Lang, Triple);

  Init.Realize();
}
