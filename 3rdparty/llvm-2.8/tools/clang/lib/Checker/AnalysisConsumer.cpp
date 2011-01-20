//===--- AnalysisConsumer.cpp - ASTConsumer for running Analyses ----------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// "Meta" ASTConsumer for running different source analyses.
//
//===----------------------------------------------------------------------===//

#include "clang/Checker/AnalysisConsumer.h"
#include "clang/AST/ASTConsumer.h"
#include "clang/AST/Decl.h"
#include "clang/AST/DeclCXX.h"
#include "clang/AST/DeclObjC.h"
#include "clang/AST/ParentMap.h"
#include "clang/Analysis/Analyses/LiveVariables.h"
#include "clang/Analysis/Analyses/UninitializedValues.h"
#include "clang/Analysis/CFG.h"
#include "clang/Checker/Checkers/LocalCheckers.h"
#include "clang/Checker/ManagerRegistry.h"
#include "clang/Checker/BugReporter/PathDiagnostic.h"
#include "clang/Checker/PathSensitive/AnalysisManager.h"
#include "clang/Checker/BugReporter/BugReporter.h"
#include "clang/Checker/PathSensitive/GRExprEngine.h"
#include "clang/Checker/PathSensitive/GRTransferFuncs.h"
#include "clang/Checker/PathDiagnosticClients.h"
#include "GRExprEngineExperimentalChecks.h"
#include "GRExprEngineInternalChecks.h"
#include "clang/Basic/FileManager.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Frontend/AnalyzerOptions.h"
#include "clang/Lex/Preprocessor.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/System/Path.h"
#include "llvm/System/Program.h"
#include "llvm/ADT/OwningPtr.h"

using namespace clang;

static ExplodedNode::Auditor* CreateUbiViz();

//===----------------------------------------------------------------------===//
// Special PathDiagnosticClients.
//===----------------------------------------------------------------------===//

static PathDiagnosticClient*
CreatePlistHTMLDiagnosticClient(const std::string& prefix,
                                const Preprocessor &PP) {
  llvm::sys::Path F(prefix);
  PathDiagnosticClient *PD = CreateHTMLDiagnosticClient(F.getDirname(), PP);
  return CreatePlistDiagnosticClient(prefix, PP, PD);
}

//===----------------------------------------------------------------------===//
// AnalysisConsumer declaration.
//===----------------------------------------------------------------------===//

namespace {

class AnalysisConsumer : public ASTConsumer {
public:
  typedef void (*CodeAction)(AnalysisConsumer &C, AnalysisManager &M, Decl *D);
  typedef void (*TUAction)(AnalysisConsumer &C, AnalysisManager &M,
                           TranslationUnitDecl &TU);

private:
  typedef std::vector<CodeAction> Actions;
  typedef std::vector<TUAction> TUActions;

  Actions FunctionActions;
  Actions ObjCMethodActions;
  Actions ObjCImplementationActions;
  Actions CXXMethodActions;
  TUActions TranslationUnitActions; // Remove this.

public:
  ASTContext* Ctx;
  const Preprocessor &PP;
  const std::string OutDir;
  AnalyzerOptions Opts;

  // PD is owned by AnalysisManager.
  PathDiagnosticClient *PD;

  StoreManagerCreator CreateStoreMgr;
  ConstraintManagerCreator CreateConstraintMgr;

  llvm::OwningPtr<AnalysisManager> Mgr;

  AnalysisConsumer(const Preprocessor& pp,
                   const std::string& outdir,
                   const AnalyzerOptions& opts)
    : Ctx(0), PP(pp), OutDir(outdir),
      Opts(opts), PD(0) {
    DigestAnalyzerOptions();
  }

  void DigestAnalyzerOptions() {
    // Create the PathDiagnosticClient.
    if (!OutDir.empty()) {
      switch (Opts.AnalysisDiagOpt) {
      default:
#define ANALYSIS_DIAGNOSTICS(NAME, CMDFLAG, DESC, CREATEFN, AUTOCREATE) \
        case PD_##NAME: PD = CREATEFN(OutDir, PP); break;
#include "clang/Frontend/Analyses.def"
      }
    }

    // Create the analyzer component creators.
    if (ManagerRegistry::StoreMgrCreator != 0) {
      CreateStoreMgr = ManagerRegistry::StoreMgrCreator;
    }
    else {
      switch (Opts.AnalysisStoreOpt) {
      default:
        assert(0 && "Unknown store manager.");
#define ANALYSIS_STORE(NAME, CMDFLAG, DESC, CREATEFN)           \
        case NAME##Model: CreateStoreMgr = CREATEFN; break;
#include "clang/Frontend/Analyses.def"
      }
    }

    if (ManagerRegistry::ConstraintMgrCreator != 0)
      CreateConstraintMgr = ManagerRegistry::ConstraintMgrCreator;
    else {
      switch (Opts.AnalysisConstraintsOpt) {
      default:
        assert(0 && "Unknown store manager.");
#define ANALYSIS_CONSTRAINTS(NAME, CMDFLAG, DESC, CREATEFN)     \
        case NAME##Model: CreateConstraintMgr = CREATEFN; break;
#include "clang/Frontend/Analyses.def"
      }
    }
  }

  void DisplayFunction(const Decl *D) {
    if (!Opts.AnalyzerDisplayProgress)
      return;

    SourceManager &SM = Mgr->getASTContext().getSourceManager();
    PresumedLoc Loc = SM.getPresumedLoc(D->getLocation());
    llvm::errs() << "ANALYZE: " << Loc.getFilename();

    if (isa<FunctionDecl>(D) || isa<ObjCMethodDecl>(D)) {
      const NamedDecl *ND = cast<NamedDecl>(D);
      llvm::errs() << ' ' << ND << '\n';
    }
    else if (isa<BlockDecl>(D)) {
      llvm::errs() << ' ' << "block(line:" << Loc.getLine() << ",col:"
                   << Loc.getColumn() << '\n';
    }
  }

  void addCodeAction(CodeAction action) {
    FunctionActions.push_back(action);
    ObjCMethodActions.push_back(action);
    CXXMethodActions.push_back(action);
  }

  void addTranslationUnitAction(TUAction action) {
    TranslationUnitActions.push_back(action);
  }

  void addObjCImplementationAction(CodeAction action) {
    ObjCImplementationActions.push_back(action);
  }

  virtual void Initialize(ASTContext &Context) {
    Ctx = &Context;
    Mgr.reset(new AnalysisManager(*Ctx, PP.getDiagnostics(),
                                  PP.getLangOptions(), PD,
                                  CreateStoreMgr, CreateConstraintMgr,
                                  /* Indexer */ 0, 
                                  Opts.MaxNodes, Opts.MaxLoop,
                                  Opts.VisualizeEGDot, Opts.VisualizeEGUbi,
                                  Opts.PurgeDead, Opts.EagerlyAssume,
                                  Opts.TrimGraph, Opts.InlineCall,
                                  Opts.UnoptimizedCFG));
  }

  virtual void HandleTranslationUnit(ASTContext &C);
  void HandleCode(Decl *D, Actions& actions);
};
} // end anonymous namespace

//===----------------------------------------------------------------------===//
// AnalysisConsumer implementation.
//===----------------------------------------------------------------------===//

void AnalysisConsumer::HandleTranslationUnit(ASTContext &C) {

  TranslationUnitDecl *TU = C.getTranslationUnitDecl();

  for (DeclContext::decl_iterator I = TU->decls_begin(), E = TU->decls_end();
       I != E; ++I) {
    Decl *D = *I;

    switch (D->getKind()) {
    case Decl::CXXConstructor:
    case Decl::CXXDestructor:
    case Decl::CXXConversion:
    case Decl::CXXMethod:
    case Decl::Function: {
      FunctionDecl* FD = cast<FunctionDecl>(D);
      
      if (FD->isThisDeclarationADefinition()) {
        if (!Opts.AnalyzeSpecificFunction.empty() &&
            FD->getDeclName().getAsString() != Opts.AnalyzeSpecificFunction)
          break;
        DisplayFunction(FD);
        HandleCode(FD, FunctionActions);
      }
      break;
    }

    case Decl::ObjCMethod: {
      ObjCMethodDecl* MD = cast<ObjCMethodDecl>(D);
      
      if (MD->isThisDeclarationADefinition()) {
        if (!Opts.AnalyzeSpecificFunction.empty() &&
            Opts.AnalyzeSpecificFunction != MD->getSelector().getAsString())
          break;
        DisplayFunction(MD);
        HandleCode(MD, ObjCMethodActions);
      }
      break;
    }

    case Decl::ObjCImplementation: {
      ObjCImplementationDecl* ID = cast<ObjCImplementationDecl>(*I);
      HandleCode(ID, ObjCImplementationActions);

      for (ObjCImplementationDecl::method_iterator MI = ID->meth_begin(), 
             ME = ID->meth_end(); MI != ME; ++MI) {
        if ((*MI)->isThisDeclarationADefinition()) {
          if (!Opts.AnalyzeSpecificFunction.empty() &&
             Opts.AnalyzeSpecificFunction != (*MI)->getSelector().getAsString())
            break;
          HandleCode(*MI, ObjCMethodActions);
        }
      }
      break;
    }

    default:
      break;
    }
  }

  for (TUActions::iterator I = TranslationUnitActions.begin(),
                           E = TranslationUnitActions.end(); I != E; ++I) {
    (*I)(*this, *Mgr, *TU);
  }

  // Explicitly destroy the PathDiagnosticClient.  This will flush its output.
  // FIXME: This should be replaced with something that doesn't rely on
  // side-effects in PathDiagnosticClient's destructor. This is required when
  // used with option -disable-free.
  Mgr.reset(NULL);
}

static void FindBlocks(DeclContext *D, llvm::SmallVectorImpl<Decl*> &WL) {
  if (BlockDecl *BD = dyn_cast<BlockDecl>(D))
    WL.push_back(BD);

  for (DeclContext::decl_iterator I = D->decls_begin(), E = D->decls_end();
       I!=E; ++I)
    if (DeclContext *DC = dyn_cast<DeclContext>(*I))
      FindBlocks(DC, WL);
}

void AnalysisConsumer::HandleCode(Decl *D, Actions& actions) {

  // Don't run the actions if an error has occured with parsing the file.
  Diagnostic &Diags = PP.getDiagnostics();
  if (Diags.hasErrorOccurred() || Diags.hasFatalErrorOccurred())
    return;

  // Don't run the actions on declarations in header files unless
  // otherwise specified.
  SourceManager &SM = Ctx->getSourceManager();
  SourceLocation SL = SM.getInstantiationLoc(D->getLocation());
  if (!Opts.AnalyzeAll && !SM.isFromMainFile(SL))
    return;

  // Clear the AnalysisManager of old AnalysisContexts.
  Mgr->ClearContexts();

  // Dispatch on the actions.
  llvm::SmallVector<Decl*, 10> WL;
  WL.push_back(D);

  if (D->hasBody() && Opts.AnalyzeNestedBlocks)
    FindBlocks(cast<DeclContext>(D), WL);

  for (Actions::iterator I = actions.begin(), E = actions.end(); I != E; ++I)
    for (llvm::SmallVectorImpl<Decl*>::iterator WI=WL.begin(), WE=WL.end();
         WI != WE; ++WI)
      (*I)(*this, *Mgr, *WI);
}

//===----------------------------------------------------------------------===//
// Analyses
//===----------------------------------------------------------------------===//

static void ActionWarnDeadStores(AnalysisConsumer &C, AnalysisManager& mgr,
                                 Decl *D) {
  if (LiveVariables *L = mgr.getLiveVariables(D)) {
    BugReporter BR(mgr);
    CheckDeadStores(*mgr.getCFG(D), *L, mgr.getParentMap(D), BR);
  }
}

static void ActionWarnUninitVals(AnalysisConsumer &C, AnalysisManager& mgr,
                                 Decl *D) {
  if (CFG* c = mgr.getCFG(D)) {
    CheckUninitializedValues(*c, mgr.getASTContext(), mgr.getDiagnostic());
  }
}


static void ActionGRExprEngine(AnalysisConsumer &C, AnalysisManager& mgr,
                               Decl *D,
                               GRTransferFuncs* tf) {

  llvm::OwningPtr<GRTransferFuncs> TF(tf);

  // Construct the analysis engine.  We first query for the LiveVariables
  // information to see if the CFG is valid.
  // FIXME: Inter-procedural analysis will need to handle invalid CFGs.
  if (!mgr.getLiveVariables(D))
    return;
  GRExprEngine Eng(mgr, TF.take());

  if (C.Opts.EnableExperimentalInternalChecks)
    RegisterExperimentalInternalChecks(Eng);

  RegisterAppleChecks(Eng, *D);

  if (C.Opts.EnableExperimentalChecks)
    RegisterExperimentalChecks(Eng);

  // Enable idempotent operation checking if it was explicitly turned on, or if
  // we are running experimental checks (i.e. everything)
  if (C.Opts.IdempotentOps || C.Opts.EnableExperimentalChecks
      || C.Opts.EnableExperimentalInternalChecks)
    RegisterIdempotentOperationChecker(Eng);

  // Set the graph auditor.
  llvm::OwningPtr<ExplodedNode::Auditor> Auditor;
  if (mgr.shouldVisualizeUbigraph()) {
    Auditor.reset(CreateUbiViz());
    ExplodedNode::SetAuditor(Auditor.get());
  }

  // Execute the worklist algorithm.
  Eng.ExecuteWorkList(mgr.getStackFrame(D, 0), mgr.getMaxNodes());

  // Release the auditor (if any) so that it doesn't monitor the graph
  // created BugReporter.
  ExplodedNode::SetAuditor(0);

  // Visualize the exploded graph.
  if (mgr.shouldVisualizeGraphviz())
    Eng.ViewGraph(mgr.shouldTrimGraph());

  // Display warnings.
  Eng.getBugReporter().FlushReports();
}

static void ActionObjCMemCheckerAux(AnalysisConsumer &C, AnalysisManager& mgr,
                                  Decl *D, bool GCEnabled) {

  GRTransferFuncs* TF = MakeCFRefCountTF(mgr.getASTContext(),
                                         GCEnabled,
                                         mgr.getLangOptions());

  ActionGRExprEngine(C, mgr, D, TF);
}

static void ActionObjCMemChecker(AnalysisConsumer &C, AnalysisManager& mgr,
                               Decl *D) {

 switch (mgr.getLangOptions().getGCMode()) {
 default:
   assert (false && "Invalid GC mode.");
 case LangOptions::NonGC:
   ActionObjCMemCheckerAux(C, mgr, D, false);
   break;

 case LangOptions::GCOnly:
   ActionObjCMemCheckerAux(C, mgr, D, true);
   break;

 case LangOptions::HybridGC:
   ActionObjCMemCheckerAux(C, mgr, D, false);
   ActionObjCMemCheckerAux(C, mgr, D, true);
   break;
 }
}

static void ActionDisplayLiveVariables(AnalysisConsumer &C,
                                       AnalysisManager& mgr, Decl *D) {
  if (LiveVariables* L = mgr.getLiveVariables(D)) {
    L->dumpBlockLiveness(mgr.getSourceManager());
  }
}

static void ActionCFGDump(AnalysisConsumer &C, AnalysisManager& mgr, Decl *D) {
  if (CFG *cfg = mgr.getCFG(D)) {
    cfg->dump(mgr.getLangOptions());
  }
}

static void ActionCFGView(AnalysisConsumer &C, AnalysisManager& mgr, Decl *D) {
  if (CFG *cfg = mgr.getCFG(D)) {
    cfg->viewCFG(mgr.getLangOptions());
  }
}

static void ActionSecuritySyntacticChecks(AnalysisConsumer &C,
                                          AnalysisManager &mgr, Decl *D) {
  BugReporter BR(mgr);
  CheckSecuritySyntaxOnly(D, BR);
}

static void ActionLLVMConventionChecker(AnalysisConsumer &C,
                                        AnalysisManager &mgr,
                                        TranslationUnitDecl &TU) {
  BugReporter BR(mgr);
  CheckLLVMConventions(TU, BR);
}

static void ActionWarnObjCDealloc(AnalysisConsumer &C, AnalysisManager& mgr,
                                  Decl *D) {
  if (mgr.getLangOptions().getGCMode() == LangOptions::GCOnly)
    return;
  BugReporter BR(mgr);
  CheckObjCDealloc(cast<ObjCImplementationDecl>(D), mgr.getLangOptions(), BR);
}

static void ActionWarnObjCUnusedIvars(AnalysisConsumer &C, AnalysisManager& mgr,
                                      Decl *D) {
  BugReporter BR(mgr);
  CheckObjCUnusedIvar(cast<ObjCImplementationDecl>(D), BR);
}

static void ActionWarnObjCMethSigs(AnalysisConsumer &C, AnalysisManager& mgr,
                                   Decl *D) {
  BugReporter BR(mgr);
  CheckObjCInstMethSignature(cast<ObjCImplementationDecl>(D), BR);
}

static void ActionWarnSizeofPointer(AnalysisConsumer &C, AnalysisManager &mgr,
                                    Decl *D) {
  BugReporter BR(mgr);
  CheckSizeofPointer(D, BR);
}

//===----------------------------------------------------------------------===//
// AnalysisConsumer creation.
//===----------------------------------------------------------------------===//

ASTConsumer* clang::CreateAnalysisConsumer(const Preprocessor& pp,
                                           const std::string& OutDir,
                                           const AnalyzerOptions& Opts) {
  llvm::OwningPtr<AnalysisConsumer> C(new AnalysisConsumer(pp, OutDir, Opts));

  for (unsigned i = 0; i < Opts.AnalysisList.size(); ++i)
    switch (Opts.AnalysisList[i]) {
#define ANALYSIS(NAME, CMD, DESC, SCOPE)\
    case NAME:\
      C->add ## SCOPE ## Action(&Action ## NAME);\
      break;
#include "clang/Frontend/Analyses.def"
    default: break;
    }

  // Last, disable the effects of '-Werror' when using the AnalysisConsumer.
  pp.getDiagnostics().setWarningsAsErrors(false);

  return C.take();
}

//===----------------------------------------------------------------------===//
// Ubigraph Visualization.  FIXME: Move to separate file.
//===----------------------------------------------------------------------===//

namespace {

class UbigraphViz : public ExplodedNode::Auditor {
  llvm::OwningPtr<llvm::raw_ostream> Out;
  llvm::sys::Path Dir, Filename;
  unsigned Cntr;

  typedef llvm::DenseMap<void*,unsigned> VMap;
  VMap M;

public:
  UbigraphViz(llvm::raw_ostream* out, llvm::sys::Path& dir,
              llvm::sys::Path& filename);

  ~UbigraphViz();

  virtual void AddEdge(ExplodedNode* Src, ExplodedNode* Dst);
};

} // end anonymous namespace

static ExplodedNode::Auditor* CreateUbiViz() {
  std::string ErrMsg;

  llvm::sys::Path Dir = llvm::sys::Path::GetTemporaryDirectory(&ErrMsg);
  if (!ErrMsg.empty())
    return 0;

  llvm::sys::Path Filename = Dir;
  Filename.appendComponent("llvm_ubi");
  Filename.makeUnique(true,&ErrMsg);

  if (!ErrMsg.empty())
    return 0;

  llvm::errs() << "Writing '" << Filename.str() << "'.\n";

  llvm::OwningPtr<llvm::raw_fd_ostream> Stream;
  Stream.reset(new llvm::raw_fd_ostream(Filename.c_str(), ErrMsg));

  if (!ErrMsg.empty())
    return 0;

  return new UbigraphViz(Stream.take(), Dir, Filename);
}

void UbigraphViz::AddEdge(ExplodedNode* Src, ExplodedNode* Dst) {

  assert (Src != Dst && "Self-edges are not allowed.");

  // Lookup the Src.  If it is a new node, it's a root.
  VMap::iterator SrcI= M.find(Src);
  unsigned SrcID;

  if (SrcI == M.end()) {
    M[Src] = SrcID = Cntr++;
    *Out << "('vertex', " << SrcID << ", ('color','#00ff00'))\n";
  }
  else
    SrcID = SrcI->second;

  // Lookup the Dst.
  VMap::iterator DstI= M.find(Dst);
  unsigned DstID;

  if (DstI == M.end()) {
    M[Dst] = DstID = Cntr++;
    *Out << "('vertex', " << DstID << ")\n";
  }
  else {
    // We have hit DstID before.  Change its style to reflect a cache hit.
    DstID = DstI->second;
    *Out << "('change_vertex_style', " << DstID << ", 1)\n";
  }

  // Add the edge.
  *Out << "('edge', " << SrcID << ", " << DstID
       << ", ('arrow','true'), ('oriented', 'true'))\n";
}

UbigraphViz::UbigraphViz(llvm::raw_ostream* out, llvm::sys::Path& dir,
                         llvm::sys::Path& filename)
  : Out(out), Dir(dir), Filename(filename), Cntr(0) {

  *Out << "('vertex_style_attribute', 0, ('shape', 'icosahedron'))\n";
  *Out << "('vertex_style', 1, 0, ('shape', 'sphere'), ('color', '#ffcc66'),"
          " ('size', '1.5'))\n";
}

UbigraphViz::~UbigraphViz() {
  Out.reset(0);
  llvm::errs() << "Running 'ubiviz' program... ";
  std::string ErrMsg;
  llvm::sys::Path Ubiviz = llvm::sys::Program::FindProgramByName("ubiviz");
  std::vector<const char*> args;
  args.push_back(Ubiviz.c_str());
  args.push_back(Filename.c_str());
  args.push_back(0);

  if (llvm::sys::Program::ExecuteAndWait(Ubiviz, &args[0],0,0,0,0,&ErrMsg)) {
    llvm::errs() << "Error viewing graph: " << ErrMsg << "\n";
  }

  // Delete the directory.
  Dir.eraseFromDisk(true);
}
