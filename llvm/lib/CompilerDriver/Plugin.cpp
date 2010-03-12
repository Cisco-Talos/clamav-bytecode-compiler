//===--- Plugin.cpp - The LLVM Compiler Driver ------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open
// Source License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
//  Plugin support.
//
//===----------------------------------------------------------------------===//

#include "llvm/CompilerDriver/Plugin.h"
#include "llvm/Support/ManagedStatic.h"
#include "llvm/System/Mutex.h"
#include <algorithm>
#include <vector>

namespace {

  // Registry::Add<> does not do lifetime management (probably issues
  // with static constructor/destructor ordering), so we have to
  // implement it here.
  //
  // All this static registration/life-before-main model seems
  // unnecessary convoluted to me.

  static bool pluginListInitialized = false;
  typedef std::vector<const llvmc::BasePlugin*> PluginList;
  static PluginList Plugins;
  static llvm::ManagedStatic<llvm::sys::SmartMutex<true> > PluginMutex;

  struct ByPriority {
    bool operator()(const llvmc::BasePlugin* lhs,
                    const llvmc::BasePlugin* rhs) {
      return lhs->Priority() < rhs->Priority();
    }
  };
}

namespace llvmc {

  PluginLoader::PluginLoader() {
    llvm::sys::SmartScopedLock<true> Lock(*PluginMutex);
    if (!pluginListInitialized) {
      for (PluginRegistry::iterator B = PluginRegistry::begin(),
             E = PluginRegistry::end(); B != E; ++B)
        Plugins.push_back(B->instantiate());
      std::sort(Plugins.begin(), Plugins.end(), ByPriority());
    }
    pluginListInitialized = true;
  }

  PluginLoader::~PluginLoader() {
    llvm::sys::SmartScopedLock<true> Lock(*PluginMutex);
    if (pluginListInitialized) {
      for (PluginList::iterator B = Plugins.begin(), E = Plugins.end();
           B != E; ++B)
        delete (*B);
    }
    pluginListInitialized = false;
  }

  void PluginLoader::RunInitialization(LanguageMap& langMap,
                                       CompilationGraph& graph) const
  {
    llvm::sys::SmartScopedLock<true> Lock(*PluginMutex);
    for (PluginList::iterator B = Plugins.begin(), E = Plugins.end();
         B != E; ++B) {
      const BasePlugin* BP = *B;
      BP->PreprocessOptions();
      BP->PopulateLanguageMap(langMap);
      BP->PopulateCompilationGraph(graph);
    }
  }

}
