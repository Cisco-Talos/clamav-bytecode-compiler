//== Environment.cpp - Map from Stmt* to Locations/Values -------*- C++ -*--==//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
//  This file defined the Environment and EnvironmentManager classes.
//
//===----------------------------------------------------------------------===//
#include "clang/Analysis/PathSensitive/GRState.h"
#include "clang/Analysis/Analyses/LiveVariables.h"
#include "llvm/Support/Compiler.h"
#include "llvm/ADT/ImmutableMap.h"

using namespace clang;

SVal Environment::GetSVal(const Stmt *E, ValueManager& ValMgr) const {
  
  for (;;) {
    
    switch (E->getStmtClass()) {
        
      case Stmt::AddrLabelExprClass:        
        return ValMgr.makeLoc(cast<AddrLabelExpr>(E));
        
        // ParenExprs are no-ops.
        
      case Stmt::ParenExprClass:        
        E = cast<ParenExpr>(E)->getSubExpr();
        continue;
        
      case Stmt::CharacterLiteralClass: {
        const CharacterLiteral* C = cast<CharacterLiteral>(E);
        return ValMgr.makeIntVal(C->getValue(), C->getType());
      }
        
      case Stmt::IntegerLiteralClass: {
        return ValMgr.makeIntVal(cast<IntegerLiteral>(E));
      }
        
      // Casts where the source and target type are the same
      // are no-ops.  We blast through these to get the descendant
      // subexpression that has a value.
       
      case Stmt::ImplicitCastExprClass:
      case Stmt::CStyleCastExprClass: {
        const CastExpr* C = cast<CastExpr>(E);
        QualType CT = C->getType();
        
        if (CT->isVoidType())
          return UnknownVal();
        
        break;
      }
        
        // Handle all other Stmt* using a lookup.
        
      default:
        break;
    };
    
    break;
  }
  
  return LookupExpr(E);
}

SVal Environment::GetBlkExprSVal(const Stmt *E, ValueManager& ValMgr) const {
  
  while (1) {
    switch (E->getStmtClass()) {
      case Stmt::ParenExprClass:
        E = cast<ParenExpr>(E)->getSubExpr();
        continue;
        
      case Stmt::CharacterLiteralClass: {
        const CharacterLiteral* C = cast<CharacterLiteral>(E);
        return ValMgr.makeIntVal(C->getValue(), C->getType());
      }
        
      case Stmt::IntegerLiteralClass: {
        return ValMgr.makeIntVal(cast<IntegerLiteral>(E));
      }
        
      default:
        return LookupBlkExpr(E);
    }
  }
}

Environment EnvironmentManager::BindExpr(const Environment& Env, const Stmt* E,
                                         SVal V, bool isBlkExpr,
                                         bool Invalidate) {  
  assert (E);
  
  if (V.isUnknown()) {    
    if (Invalidate)
      return isBlkExpr ? RemoveBlkExpr(Env, E) : RemoveSubExpr(Env, E);
    else
      return Env;
  }

  return isBlkExpr ? AddBlkExpr(Env, E, V) : AddSubExpr(Env, E, V);
}

namespace {
class VISIBILITY_HIDDEN MarkLiveCallback : public SymbolVisitor {
  SymbolReaper &SymReaper;
public:
  MarkLiveCallback(SymbolReaper &symreaper) : SymReaper(symreaper) {}  
  bool VisitSymbol(SymbolRef sym) { SymReaper.markLive(sym); return true; }
};
} // end anonymous namespace

// RemoveDeadBindings:
//  - Remove subexpression bindings.
//  - Remove dead block expression bindings.
//  - Keep live block expression bindings:
//   - Mark their reachable symbols live in SymbolReaper, 
//     see ScanReachableSymbols.
//   - Mark the region in DRoots if the binding is a loc::MemRegionVal.

Environment 
EnvironmentManager::RemoveDeadBindings(Environment Env, Stmt* Loc,
                                       SymbolReaper& SymReaper,
                                       GRStateManager& StateMgr,
                                       const GRState *state,
                              llvm::SmallVectorImpl<const MemRegion*>& DRoots) {
  
  // Drop bindings for subexpressions.
  Env = RemoveSubExprBindings(Env);

  // Iterate over the block-expr bindings.
  for (Environment::beb_iterator I = Env.beb_begin(), E = Env.beb_end(); 
       I != E; ++I) {
    const Stmt *BlkExpr = I.getKey();

    if (SymReaper.isLive(Loc, BlkExpr)) {
      SVal X = I.getData();

      // If the block expr's value is a memory region, then mark that region.
      if (isa<loc::MemRegionVal>(X)) {
        const MemRegion* R = cast<loc::MemRegionVal>(X).getRegion();
        DRoots.push_back(R);
        // Mark the super region of the RX as live.
        // e.g.: int x; char *y = (char*) &x; if (*y) ... 
        // 'y' => element region. 'x' is its super region.
        // We only add one level super region for now.

        // FIXME: maybe multiple level of super regions should be added.
        if (const SubRegion *SR = dyn_cast<SubRegion>(R)) {
          DRoots.push_back(SR->getSuperRegion());
        }
      }

      // Mark all symbols in the block expr's value live.
      MarkLiveCallback cb(SymReaper);
      state->scanReachableSymbols(X, cb);
    } else {
      // The block expr is dead.
      SVal X = I.getData();

      // Do not misclean LogicalExpr or ConditionalOperator.  It is dead at the
      // beginning of itself, but we need its UndefinedVal to determine its
      // SVal.

      if (X.isUndef() && cast<UndefinedVal>(X).getData())
        continue;

      Env = RemoveBlkExpr(Env, BlkExpr);
    }
  }

  return Env;
}
