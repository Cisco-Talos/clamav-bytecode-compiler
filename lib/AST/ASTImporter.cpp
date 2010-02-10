//===--- ASTImporter.cpp - Importing ASTs from other Contexts ---*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
//  This file defines the ASTImporter class which imports AST nodes from one
//  context into another context.
//
//===----------------------------------------------------------------------===//
#include "clang/AST/ASTImporter.h"

#include "clang/AST/ASTContext.h"
#include "clang/AST/ASTDiagnostic.h"
#include "clang/AST/DeclObjC.h"
#include "clang/AST/DeclVisitor.h"
#include "clang/AST/TypeLoc.h"
#include "clang/AST/TypeVisitor.h"
#include "clang/Basic/FileManager.h"
#include "clang/Basic/SourceManager.h"
#include "llvm/Support/MemoryBuffer.h"

using namespace clang;

namespace {
  class ASTNodeImporter : public TypeVisitor<ASTNodeImporter, QualType>,
                          public DeclVisitor<ASTNodeImporter, Decl *> {
    ASTImporter &Importer;
    
  public:
    explicit ASTNodeImporter(ASTImporter &Importer) : Importer(Importer) { }
    
    using TypeVisitor<ASTNodeImporter, QualType>::Visit;
    using DeclVisitor<ASTNodeImporter, Decl *>::Visit;

    // Importing types
    QualType VisitType(Type *T);
    QualType VisitBuiltinType(BuiltinType *T);
    QualType VisitComplexType(ComplexType *T);
    QualType VisitPointerType(PointerType *T);
    QualType VisitBlockPointerType(BlockPointerType *T);
    QualType VisitLValueReferenceType(LValueReferenceType *T);
    QualType VisitRValueReferenceType(RValueReferenceType *T);
    QualType VisitMemberPointerType(MemberPointerType *T);
    QualType VisitConstantArrayType(ConstantArrayType *T);
    QualType VisitIncompleteArrayType(IncompleteArrayType *T);
    QualType VisitVariableArrayType(VariableArrayType *T);
    // FIXME: DependentSizedArrayType
    // FIXME: DependentSizedExtVectorType
    QualType VisitVectorType(VectorType *T);
    QualType VisitExtVectorType(ExtVectorType *T);
    QualType VisitFunctionNoProtoType(FunctionNoProtoType *T);
    QualType VisitFunctionProtoType(FunctionProtoType *T);
    // FIXME: UnresolvedUsingType
    QualType VisitTypedefType(TypedefType *T);
    QualType VisitTypeOfExprType(TypeOfExprType *T);
    // FIXME: DependentTypeOfExprType
    QualType VisitTypeOfType(TypeOfType *T);
    QualType VisitDecltypeType(DecltypeType *T);
    // FIXME: DependentDecltypeType
    QualType VisitRecordType(RecordType *T);
    QualType VisitEnumType(EnumType *T);
    QualType VisitElaboratedType(ElaboratedType *T);
    // FIXME: TemplateTypeParmType
    // FIXME: SubstTemplateTypeParmType
    // FIXME: TemplateSpecializationType
    QualType VisitQualifiedNameType(QualifiedNameType *T);
    // FIXME: TypenameType
    QualType VisitObjCInterfaceType(ObjCInterfaceType *T);
    QualType VisitObjCObjectPointerType(ObjCObjectPointerType *T);
                            
    // Importing declarations
    bool ImportDeclParts(NamedDecl *D, DeclContext *&DC, 
                         DeclContext *&LexicalDC, DeclarationName &Name, 
                         SourceLocation &Loc);                            
    bool ImportDeclParts(DeclaratorDecl *D, 
                         DeclContext *&DC, DeclContext *&LexicalDC,
                         DeclarationName &Name, SourceLocation &Loc, 
                         QualType &T);
    Decl *VisitDecl(Decl *D);
    Decl *VisitTypedefDecl(TypedefDecl *D);
    Decl *VisitFunctionDecl(FunctionDecl *D);
    Decl *VisitVarDecl(VarDecl *D);
    Decl *VisitParmVarDecl(ParmVarDecl *D);
  };
}

//----------------------------------------------------------------------------
// Import Types
//----------------------------------------------------------------------------

QualType ASTNodeImporter::VisitType(Type *T) {
  Importer.FromDiag(SourceLocation(), diag::err_unsupported_ast_node)
    << T->getTypeClassName();
  return QualType();
}

QualType ASTNodeImporter::VisitBuiltinType(BuiltinType *T) {
  switch (T->getKind()) {
  case BuiltinType::Void: return Importer.getToContext().VoidTy;
  case BuiltinType::Bool: return Importer.getToContext().BoolTy;
    
  case BuiltinType::Char_U:
    // The context we're importing from has an unsigned 'char'. If we're 
    // importing into a context with a signed 'char', translate to 
    // 'unsigned char' instead.
    if (Importer.getToContext().getLangOptions().CharIsSigned)
      return Importer.getToContext().UnsignedCharTy;
    
    return Importer.getToContext().CharTy;

  case BuiltinType::UChar: return Importer.getToContext().UnsignedCharTy;
    
  case BuiltinType::Char16:
    // FIXME: Make sure that the "to" context supports C++!
    return Importer.getToContext().Char16Ty;
    
  case BuiltinType::Char32: 
    // FIXME: Make sure that the "to" context supports C++!
    return Importer.getToContext().Char32Ty;

  case BuiltinType::UShort: return Importer.getToContext().UnsignedShortTy;
  case BuiltinType::UInt: return Importer.getToContext().UnsignedIntTy;
  case BuiltinType::ULong: return Importer.getToContext().UnsignedLongTy;
  case BuiltinType::ULongLong: 
    return Importer.getToContext().UnsignedLongLongTy;
  case BuiltinType::UInt128: return Importer.getToContext().UnsignedInt128Ty;
    
  case BuiltinType::Char_S:
    // The context we're importing from has an unsigned 'char'. If we're 
    // importing into a context with a signed 'char', translate to 
    // 'unsigned char' instead.
    if (!Importer.getToContext().getLangOptions().CharIsSigned)
      return Importer.getToContext().SignedCharTy;
    
    return Importer.getToContext().CharTy;

  case BuiltinType::SChar: return Importer.getToContext().SignedCharTy;
  case BuiltinType::WChar:
    // FIXME: If not in C++, shall we translate to the C equivalent of
    // wchar_t?
    return Importer.getToContext().WCharTy;
    
  case BuiltinType::Short : return Importer.getToContext().ShortTy;
  case BuiltinType::Int : return Importer.getToContext().IntTy;
  case BuiltinType::Long : return Importer.getToContext().LongTy;
  case BuiltinType::LongLong : return Importer.getToContext().LongLongTy;
  case BuiltinType::Int128 : return Importer.getToContext().Int128Ty;
  case BuiltinType::Float: return Importer.getToContext().FloatTy;
  case BuiltinType::Double: return Importer.getToContext().DoubleTy;
  case BuiltinType::LongDouble: return Importer.getToContext().LongDoubleTy;

  case BuiltinType::NullPtr:
    // FIXME: Make sure that the "to" context supports C++0x!
    return Importer.getToContext().NullPtrTy;
    
  case BuiltinType::Overload: return Importer.getToContext().OverloadTy;
  case BuiltinType::Dependent: return Importer.getToContext().DependentTy;
  case BuiltinType::UndeducedAuto: 
    // FIXME: Make sure that the "to" context supports C++0x!
    return Importer.getToContext().UndeducedAutoTy;

  case BuiltinType::ObjCId:
    // FIXME: Make sure that the "to" context supports Objective-C!
    return Importer.getToContext().ObjCBuiltinIdTy;
    
  case BuiltinType::ObjCClass:
    return Importer.getToContext().ObjCBuiltinClassTy;

  case BuiltinType::ObjCSel:
    return Importer.getToContext().ObjCBuiltinSelTy;
  }
  
  return QualType();
}

QualType ASTNodeImporter::VisitComplexType(ComplexType *T) {
  QualType ToElementType = Importer.Import(T->getElementType());
  if (ToElementType.isNull())
    return QualType();
  
  return Importer.getToContext().getComplexType(ToElementType);
}

QualType ASTNodeImporter::VisitPointerType(PointerType *T) {
  QualType ToPointeeType = Importer.Import(T->getPointeeType());
  if (ToPointeeType.isNull())
    return QualType();
  
  return Importer.getToContext().getPointerType(ToPointeeType);
}

QualType ASTNodeImporter::VisitBlockPointerType(BlockPointerType *T) {
  // FIXME: Check for blocks support in "to" context.
  QualType ToPointeeType = Importer.Import(T->getPointeeType());
  if (ToPointeeType.isNull())
    return QualType();
  
  return Importer.getToContext().getBlockPointerType(ToPointeeType);
}

QualType ASTNodeImporter::VisitLValueReferenceType(LValueReferenceType *T) {
  // FIXME: Check for C++ support in "to" context.
  QualType ToPointeeType = Importer.Import(T->getPointeeTypeAsWritten());
  if (ToPointeeType.isNull())
    return QualType();
  
  return Importer.getToContext().getLValueReferenceType(ToPointeeType);
}

QualType ASTNodeImporter::VisitRValueReferenceType(RValueReferenceType *T) {
  // FIXME: Check for C++0x support in "to" context.
  QualType ToPointeeType = Importer.Import(T->getPointeeTypeAsWritten());
  if (ToPointeeType.isNull())
    return QualType();
  
  return Importer.getToContext().getRValueReferenceType(ToPointeeType);  
}

QualType ASTNodeImporter::VisitMemberPointerType(MemberPointerType *T) {
  // FIXME: Check for C++ support in "to" context.
  QualType ToPointeeType = Importer.Import(T->getPointeeType());
  if (ToPointeeType.isNull())
    return QualType();
  
  QualType ClassType = Importer.Import(QualType(T->getClass(), 0));
  return Importer.getToContext().getMemberPointerType(ToPointeeType, 
                                                      ClassType.getTypePtr());
}

QualType ASTNodeImporter::VisitConstantArrayType(ConstantArrayType *T) {
  QualType ToElementType = Importer.Import(T->getElementType());
  if (ToElementType.isNull())
    return QualType();
  
  return Importer.getToContext().getConstantArrayType(ToElementType, 
                                                      T->getSize(),
                                                      T->getSizeModifier(),
                                               T->getIndexTypeCVRQualifiers());
}

QualType ASTNodeImporter::VisitIncompleteArrayType(IncompleteArrayType *T) {
  QualType ToElementType = Importer.Import(T->getElementType());
  if (ToElementType.isNull())
    return QualType();
  
  return Importer.getToContext().getIncompleteArrayType(ToElementType, 
                                                        T->getSizeModifier(),
                                                T->getIndexTypeCVRQualifiers());
}

QualType ASTNodeImporter::VisitVariableArrayType(VariableArrayType *T) {
  QualType ToElementType = Importer.Import(T->getElementType());
  if (ToElementType.isNull())
    return QualType();

  Expr *Size = Importer.Import(T->getSizeExpr());
  if (!Size)
    return QualType();
  
  SourceRange Brackets = Importer.Import(T->getBracketsRange());
  return Importer.getToContext().getVariableArrayType(ToElementType, Size,
                                                      T->getSizeModifier(),
                                                T->getIndexTypeCVRQualifiers(),
                                                      Brackets);
}

QualType ASTNodeImporter::VisitVectorType(VectorType *T) {
  QualType ToElementType = Importer.Import(T->getElementType());
  if (ToElementType.isNull())
    return QualType();
  
  return Importer.getToContext().getVectorType(ToElementType, 
                                               T->getNumElements(),
                                               T->isAltiVec(),
                                               T->isPixel());
}

QualType ASTNodeImporter::VisitExtVectorType(ExtVectorType *T) {
  QualType ToElementType = Importer.Import(T->getElementType());
  if (ToElementType.isNull())
    return QualType();
  
  return Importer.getToContext().getExtVectorType(ToElementType, 
                                                  T->getNumElements());
}

QualType ASTNodeImporter::VisitFunctionNoProtoType(FunctionNoProtoType *T) {
  // FIXME: What happens if we're importing a function without a prototype 
  // into C++? Should we make it variadic?
  QualType ToResultType = Importer.Import(T->getResultType());
  if (ToResultType.isNull())
    return QualType();
  
  return Importer.getToContext().getFunctionNoProtoType(ToResultType,
                                                        T->getNoReturnAttr(), 
                                                        T->getCallConv());
}

QualType ASTNodeImporter::VisitFunctionProtoType(FunctionProtoType *T) {
  QualType ToResultType = Importer.Import(T->getResultType());
  if (ToResultType.isNull())
    return QualType();
  
  // Import argument types
  llvm::SmallVector<QualType, 4> ArgTypes;
  for (FunctionProtoType::arg_type_iterator A = T->arg_type_begin(),
                                         AEnd = T->arg_type_end();
       A != AEnd; ++A) {
    QualType ArgType = Importer.Import(*A);
    if (ArgType.isNull())
      return QualType();
    ArgTypes.push_back(ArgType);
  }
  
  // Import exception types
  llvm::SmallVector<QualType, 4> ExceptionTypes;
  for (FunctionProtoType::exception_iterator E = T->exception_begin(),
                                          EEnd = T->exception_end();
       E != EEnd; ++E) {
    QualType ExceptionType = Importer.Import(*E);
    if (ExceptionType.isNull())
      return QualType();
    ExceptionTypes.push_back(ExceptionType);
  }
       
  return Importer.getToContext().getFunctionType(ToResultType, ArgTypes.data(),
                                                 ArgTypes.size(),
                                                 T->isVariadic(),
                                                 T->getTypeQuals(),
                                                 T->hasExceptionSpec(), 
                                                 T->hasAnyExceptionSpec(),
                                                 ExceptionTypes.size(),
                                                 ExceptionTypes.data(),
                                                 T->getNoReturnAttr(),
                                                 T->getCallConv());
}

QualType ASTNodeImporter::VisitTypedefType(TypedefType *T) {
  TypedefDecl *ToDecl
                 = dyn_cast_or_null<TypedefDecl>(Importer.Import(T->getDecl()));
  if (!ToDecl)
    return QualType();
  
  return Importer.getToContext().getTypeDeclType(ToDecl);
}

QualType ASTNodeImporter::VisitTypeOfExprType(TypeOfExprType *T) {
  Expr *ToExpr = Importer.Import(T->getUnderlyingExpr());
  if (!ToExpr)
    return QualType();
  
  return Importer.getToContext().getTypeOfExprType(ToExpr);
}

QualType ASTNodeImporter::VisitTypeOfType(TypeOfType *T) {
  QualType ToUnderlyingType = Importer.Import(T->getUnderlyingType());
  if (ToUnderlyingType.isNull())
    return QualType();
  
  return Importer.getToContext().getTypeOfType(ToUnderlyingType);
}

QualType ASTNodeImporter::VisitDecltypeType(DecltypeType *T) {
  Expr *ToExpr = Importer.Import(T->getUnderlyingExpr());
  if (!ToExpr)
    return QualType();
  
  return Importer.getToContext().getDecltypeType(ToExpr);
}

QualType ASTNodeImporter::VisitRecordType(RecordType *T) {
  RecordDecl *ToDecl
    = dyn_cast_or_null<RecordDecl>(Importer.Import(T->getDecl()));
  if (!ToDecl)
    return QualType();

  return Importer.getToContext().getTagDeclType(ToDecl);
}

QualType ASTNodeImporter::VisitEnumType(EnumType *T) {
  EnumDecl *ToDecl
    = dyn_cast_or_null<EnumDecl>(Importer.Import(T->getDecl()));
  if (!ToDecl)
    return QualType();

  return Importer.getToContext().getTagDeclType(ToDecl);
}

QualType ASTNodeImporter::VisitElaboratedType(ElaboratedType *T) {
  QualType ToUnderlyingType = Importer.Import(T->getUnderlyingType());
  if (ToUnderlyingType.isNull())
    return QualType();

  return Importer.getToContext().getElaboratedType(ToUnderlyingType,
                                                   T->getTagKind());
}

QualType ASTNodeImporter::VisitQualifiedNameType(QualifiedNameType *T) {
  NestedNameSpecifier *ToQualifier = Importer.Import(T->getQualifier());
  if (!ToQualifier)
    return QualType();

  QualType ToNamedType = Importer.Import(T->getNamedType());
  if (ToNamedType.isNull())
    return QualType();

  return Importer.getToContext().getQualifiedNameType(ToQualifier, ToNamedType);
}

QualType ASTNodeImporter::VisitObjCInterfaceType(ObjCInterfaceType *T) {
  ObjCInterfaceDecl *Class
    = dyn_cast_or_null<ObjCInterfaceDecl>(Importer.Import(T->getDecl()));
  if (!Class)
    return QualType();

  llvm::SmallVector<ObjCProtocolDecl *, 4> Protocols;
  for (ObjCInterfaceType::qual_iterator P = T->qual_begin(), 
                                     PEnd = T->qual_end();
       P != PEnd; ++P) {
    ObjCProtocolDecl *Protocol
      = dyn_cast_or_null<ObjCProtocolDecl>(Importer.Import(*P));
    if (!Protocol)
      return QualType();
    Protocols.push_back(Protocol);
  }

  return Importer.getToContext().getObjCInterfaceType(Class,
                                                      Protocols.data(),
                                                      Protocols.size());
}

QualType ASTNodeImporter::VisitObjCObjectPointerType(ObjCObjectPointerType *T) {
  QualType ToPointeeType = Importer.Import(T->getPointeeType());
  if (ToPointeeType.isNull())
    return QualType();

  llvm::SmallVector<ObjCProtocolDecl *, 4> Protocols;
  for (ObjCObjectPointerType::qual_iterator P = T->qual_begin(), 
                                         PEnd = T->qual_end();
       P != PEnd; ++P) {
    ObjCProtocolDecl *Protocol
      = dyn_cast_or_null<ObjCProtocolDecl>(Importer.Import(*P));
    if (!Protocol)
      return QualType();
    Protocols.push_back(Protocol);
  }

  return Importer.getToContext().getObjCObjectPointerType(ToPointeeType,
                                                          Protocols.data(),
                                                          Protocols.size());
}

//----------------------------------------------------------------------------
// Import Declarations
//----------------------------------------------------------------------------
bool ASTNodeImporter::ImportDeclParts(NamedDecl *D, DeclContext *&DC, 
                                      DeclContext *&LexicalDC, 
                                      DeclarationName &Name, 
                                      SourceLocation &Loc) {
  // Import the context of this declaration.
  DC = Importer.ImportContext(D->getDeclContext());
  if (!DC)
    return true;
  
  LexicalDC = DC;
  if (D->getDeclContext() != D->getLexicalDeclContext()) {
    LexicalDC = Importer.ImportContext(D->getLexicalDeclContext());
    if (!LexicalDC)
      return true;
  }
  
  // Import the name of this declaration.
  Name = Importer.Import(D->getDeclName());
  if (D->getDeclName() && !Name)
    return true;
  
  // Import the location of this declaration.
  Loc = Importer.Import(D->getLocation());
  return false;
}

bool ASTNodeImporter::ImportDeclParts(DeclaratorDecl *D, 
                                      DeclContext *&DC, 
                                      DeclContext *&LexicalDC,
                                      DeclarationName &Name, 
                                      SourceLocation &Loc,
                                      QualType &T) {
  if (ImportDeclParts(D, DC, LexicalDC, Name, Loc))
    return true;
  
  // Import the type of this declaration.
  T = Importer.Import(D->getType());
  if (T.isNull())
    return true;
  
  return false;
}

Decl *ASTNodeImporter::VisitDecl(Decl *D) {
  Importer.FromDiag(D->getLocation(), diag::err_unsupported_ast_node)
    << D->getDeclKindName();
  return 0;
}

Decl *ASTNodeImporter::VisitTypedefDecl(TypedefDecl *D) {
  // Import the major distinguishing characteristics of this typedef.
  DeclContext *DC, *LexicalDC;
  DeclarationName Name;
  SourceLocation Loc;
  if (ImportDeclParts(D, DC, LexicalDC, Name, Loc))
    return 0;
  
  // Import the underlying type of this typedef;
  QualType T = Importer.Import(D->getUnderlyingType());
  if (T.isNull())
    return 0;
  
  // If this typedef is not in block scope, determine whether we've
  // seen a typedef with the same name (that we can merge with) or any
  // other entity by that name (which name lookup could conflict with).
  if (!DC->isFunctionOrMethod()) {
    llvm::SmallVector<NamedDecl *, 4> ConflictingDecls;
    unsigned IDNS = Decl::IDNS_Ordinary;
    for (DeclContext::lookup_result Lookup = DC->lookup(Name);
         Lookup.first != Lookup.second; 
         ++Lookup.first) {
      if (!(*Lookup.first)->isInIdentifierNamespace(IDNS))
        continue;
      if (TypedefDecl *FoundTypedef = dyn_cast<TypedefDecl>(*Lookup.first)) {
        if (Importer.getToContext().typesAreCompatible(T, 
                                                       FoundTypedef->getUnderlyingType())) {
          Importer.getImportedDecls()[D] = FoundTypedef;
          return FoundTypedef;
        }
      }
      
      ConflictingDecls.push_back(*Lookup.first);
    }
    
    if (!ConflictingDecls.empty()) {
      Name = Importer.HandleNameConflict(Name, DC, IDNS,
                                         ConflictingDecls.data(), 
                                         ConflictingDecls.size());
      if (!Name)
        return 0;
    }
  }
  
  // Create the new typedef node.
  TypeSourceInfo *TInfo = Importer.Import(D->getTypeSourceInfo());
  TypedefDecl *ToTypedef = TypedefDecl::Create(Importer.getToContext(), DC,
                                               Loc, Name.getAsIdentifierInfo(),
                                               TInfo);
  ToTypedef->setLexicalDeclContext(LexicalDC);
  Importer.getImportedDecls()[D] = ToTypedef;
  LexicalDC->addDecl(ToTypedef);
  return ToTypedef;
}

Decl *ASTNodeImporter::VisitFunctionDecl(FunctionDecl *D) {
  // Import the major distinguishing characteristics of this function.
  DeclContext *DC, *LexicalDC;
  DeclarationName Name;
  QualType T;
  SourceLocation Loc;
  if (ImportDeclParts(D, DC, LexicalDC, Name, Loc, T))
    return 0;
  
  // Try to find a function in our own ("to") context with the same name, same
  // type, and in the same context as the function we're importing.
  if (!LexicalDC->isFunctionOrMethod()) {
    llvm::SmallVector<NamedDecl *, 4> ConflictingDecls;
    unsigned IDNS = Decl::IDNS_Ordinary;
    for (DeclContext::lookup_result Lookup = DC->lookup(Name);
         Lookup.first != Lookup.second; 
         ++Lookup.first) {
      if (!(*Lookup.first)->isInIdentifierNamespace(IDNS))
        continue;
    
      if (FunctionDecl *FoundFunction = dyn_cast<FunctionDecl>(*Lookup.first)) {
        if (isExternalLinkage(FoundFunction->getLinkage()) &&
            isExternalLinkage(D->getLinkage())) {
          if (Importer.getToContext().typesAreCompatible(T, 
                                                    FoundFunction->getType())) {
            // FIXME: Actually try to merge the body and other attributes.
            Importer.getImportedDecls()[D] = FoundFunction;
            return FoundFunction;
          }
        
          // FIXME: Check for overloading more carefully, e.g., by boosting
          // Sema::IsOverload out to the AST library.
          
          // Function overloading is okay in C++.
          if (Importer.getToContext().getLangOptions().CPlusPlus)
            continue;
          
          // Complain about inconsistent function types.
          Importer.ToDiag(Loc, diag::err_odr_function_type_inconsistent)
            << Name << T << FoundFunction->getType();
          Importer.ToDiag(FoundFunction->getLocation(), 
                          diag::note_odr_value_here)
            << FoundFunction->getType();
        }
      }
      
      ConflictingDecls.push_back(*Lookup.first);
    }
    
    if (!ConflictingDecls.empty()) {
      Name = Importer.HandleNameConflict(Name, DC, IDNS,
                                         ConflictingDecls.data(), 
                                         ConflictingDecls.size());
      if (!Name)
        return 0;
    }    
  }
  
  // Import the function parameters.
  llvm::SmallVector<ParmVarDecl *, 8> Parameters;
  for (FunctionDecl::param_iterator P = D->param_begin(), PEnd = D->param_end();
       P != PEnd; ++P) {
    ParmVarDecl *ToP = cast_or_null<ParmVarDecl>(Importer.Import(*P));
    if (!ToP)
      return 0;
    
    Parameters.push_back(ToP);
  }
  
  // Create the imported function.
  TypeSourceInfo *TInfo = Importer.Import(D->getTypeSourceInfo());
  FunctionDecl *ToFunction
    = FunctionDecl::Create(Importer.getToContext(), DC, Loc, 
                           Name, T, TInfo, D->getStorageClass(), 
                           D->isInlineSpecified(),
                           D->hasWrittenPrototype());
  ToFunction->setLexicalDeclContext(LexicalDC);
  Importer.getImportedDecls()[D] = ToFunction;
  LexicalDC->addDecl(ToFunction);

  // Set the parameters.
  for (unsigned I = 0, N = Parameters.size(); I != N; ++I) {
    Parameters[I]->setOwningFunction(ToFunction);
    ToFunction->addDecl(Parameters[I]);
  }
  ToFunction->setParams(Importer.getToContext(), 
                        Parameters.data(), Parameters.size());

  // FIXME: Other bits to merge?
  
  return ToFunction;
}

Decl *ASTNodeImporter::VisitVarDecl(VarDecl *D) {
  // Import the major distinguishing characteristics of a variable.
  DeclContext *DC, *LexicalDC;
  DeclarationName Name;
  QualType T;
  SourceLocation Loc;
  if (ImportDeclParts(D, DC, LexicalDC, Name, Loc, T))
    return 0;
  
  // Try to find a variable in our own ("to") context with the same name and
  // in the same context as the variable we're importing.
  if (D->isFileVarDecl()) {
    VarDecl *MergeWithVar = 0;
    llvm::SmallVector<NamedDecl *, 4> ConflictingDecls;
    unsigned IDNS = Decl::IDNS_Ordinary;
    for (DeclContext::lookup_result Lookup = DC->lookup(Name);
         Lookup.first != Lookup.second; 
         ++Lookup.first) {
      if (!(*Lookup.first)->isInIdentifierNamespace(IDNS))
        continue;
      
      if (VarDecl *FoundVar = dyn_cast<VarDecl>(*Lookup.first)) {
        // We have found a variable that we may need to merge with. Check it.
        if (isExternalLinkage(FoundVar->getLinkage()) &&
            isExternalLinkage(D->getLinkage())) {
          if (Importer.getToContext().typesAreCompatible(T, 
                                                         FoundVar->getType())) {
            MergeWithVar = FoundVar;
            break;
          }

          if (const IncompleteArrayType *FoundArray
                = Importer.getToContext().getAsIncompleteArrayType(
                                                        FoundVar->getType())) {
            if (const ConstantArrayType *TArray
                  = Importer.getToContext().getAsConstantArrayType(T)) {
              if (Importer.getToContext().typesAreCompatible(
                                               TArray->getElementType(), 
                                               FoundArray->getElementType())) {
                FoundVar->setType(T);
                MergeWithVar = FoundVar;
                break;
              }
            }
          } else if (const IncompleteArrayType *TArray
                        = Importer.getToContext().getAsIncompleteArrayType(T)) {
            if (const ConstantArrayType *FoundArray
                   = Importer.getToContext().getAsConstantArrayType(
                                                         FoundVar->getType())) {
              if (Importer.getToContext().typesAreCompatible(
                                               TArray->getElementType(), 
                                               FoundArray->getElementType())) {
                MergeWithVar = FoundVar;
                break;
              }
            }
          }

          Importer.ToDiag(Loc, diag::err_odr_variable_type_inconsistent)
            << Name << T << FoundVar->getType();
          Importer.ToDiag(FoundVar->getLocation(), diag::note_odr_value_here)
            << FoundVar->getType();
        }
      }
      
      ConflictingDecls.push_back(*Lookup.first);
    }

    if (MergeWithVar) {
      // An equivalent variable with external linkage has been found. Link 
      // the two declarations, then merge them.
      Importer.getImportedDecls()[D] = MergeWithVar;
      
      if (VarDecl *DDef = D->getDefinition()) {
        if (VarDecl *ExistingDef = MergeWithVar->getDefinition()) {
          Importer.ToDiag(ExistingDef->getLocation(), 
                          diag::err_odr_variable_multiple_def)
            << Name;
          Importer.FromDiag(DDef->getLocation(), diag::note_odr_defined_here);
        } else {
          Expr *Init = Importer.Import(DDef->getInit());
          MergeWithVar->setInit(Importer.getToContext(), Init);
        }
      }
      
      return MergeWithVar;
    }
    
    if (!ConflictingDecls.empty()) {
      Name = Importer.HandleNameConflict(Name, DC, IDNS,
                                         ConflictingDecls.data(), 
                                         ConflictingDecls.size());
      if (!Name)
        return 0;
    }
  }
    
  // Create the imported variable.
  TypeSourceInfo *TInfo = Importer.Import(D->getTypeSourceInfo());
  VarDecl *ToVar = VarDecl::Create(Importer.getToContext(), DC, Loc, 
                                   Name.getAsIdentifierInfo(), T, TInfo,
                                   D->getStorageClass());
  ToVar->setLexicalDeclContext(LexicalDC);
  Importer.getImportedDecls()[D] = ToVar;
  LexicalDC->addDecl(ToVar);

  // Merge the initializer.
  // FIXME: Can we really import any initializer? Alternatively, we could force
  // ourselves to import every declaration of a variable and then only use
  // getInit() here.
  ToVar->setInit(Importer.getToContext(),
                 Importer.Import(const_cast<Expr *>(D->getAnyInitializer())));

  // FIXME: Other bits to merge?
  
  return ToVar;
}

Decl *ASTNodeImporter::VisitParmVarDecl(ParmVarDecl *D) {
  // Parameters are created in the translation unit's context, then moved
  // into the function declaration's context afterward.
  DeclContext *DC = Importer.getToContext().getTranslationUnitDecl();
  
  // Import the name of this declaration.
  DeclarationName Name = Importer.Import(D->getDeclName());
  if (D->getDeclName() && !Name)
    return 0;
  
  // Import the location of this declaration.
  SourceLocation Loc = Importer.Import(D->getLocation());
  
  // Import the parameter's type.
  QualType T = Importer.Import(D->getType());
  if (T.isNull())
    return 0;
  
  // Create the imported parameter.
  TypeSourceInfo *TInfo = Importer.Import(D->getTypeSourceInfo());
  ParmVarDecl *ToParm = ParmVarDecl::Create(Importer.getToContext(), DC,
                                            Loc, Name.getAsIdentifierInfo(),
                                            T, TInfo, D->getStorageClass(),
                                            /*FIXME: Default argument*/ 0);
  Importer.getImportedDecls()[D] = ToParm;
  return ToParm;
}

ASTImporter::ASTImporter(ASTContext &ToContext, FileManager &ToFileManager,
                         Diagnostic &ToDiags,
                         ASTContext &FromContext, FileManager &FromFileManager,
                         Diagnostic &FromDiags)
  : ToContext(ToContext), FromContext(FromContext),
    ToFileManager(ToFileManager), FromFileManager(FromFileManager),
    ToDiags(ToDiags), FromDiags(FromDiags) { 
  ImportedDecls[FromContext.getTranslationUnitDecl()]
    = ToContext.getTranslationUnitDecl();
}

ASTImporter::~ASTImporter() { }

QualType ASTImporter::Import(QualType FromT) {
  if (FromT.isNull())
    return QualType();
  
  // Check whether we've already imported this type.  
  llvm::DenseMap<Type *, Type *>::iterator Pos
    = ImportedTypes.find(FromT.getTypePtr());
  if (Pos != ImportedTypes.end())
    return ToContext.getQualifiedType(Pos->second, FromT.getQualifiers());
  
  // Import the type
  ASTNodeImporter Importer(*this);
  QualType ToT = Importer.Visit(FromT.getTypePtr());
  if (ToT.isNull())
    return ToT;
  
  // Record the imported type.
  ImportedTypes[FromT.getTypePtr()] = ToT.getTypePtr();
  
  return ToContext.getQualifiedType(ToT, FromT.getQualifiers());
}

TypeSourceInfo *ASTImporter::Import(TypeSourceInfo *FromTSI) {
  if (!FromTSI)
    return FromTSI;

  // FIXME: For now we just create a "trivial" type source info based
  // on the type and a seingle location. Implement a real version of
  // this.
  QualType T = Import(FromTSI->getType());
  if (T.isNull())
    return 0;

  return ToContext.getTrivialTypeSourceInfo(T, 
                        FromTSI->getTypeLoc().getFullSourceRange().getBegin());
}

Decl *ASTImporter::Import(Decl *FromD) {
  if (!FromD)
    return 0;

  // Check whether we've already imported this declaration.  
  llvm::DenseMap<Decl *, Decl *>::iterator Pos = ImportedDecls.find(FromD);
  if (Pos != ImportedDecls.end())
    return Pos->second;
  
  // Import the type
  ASTNodeImporter Importer(*this);
  Decl *ToD = Importer.Visit(FromD);
  if (!ToD)
    return 0;
  
  // Record the imported declaration.
  ImportedDecls[FromD] = ToD;
  return ToD;
}

DeclContext *ASTImporter::ImportContext(DeclContext *FromDC) {
  if (!FromDC)
    return FromDC;

  return cast_or_null<DeclContext>(Import(cast<Decl>(FromDC)));
}

Expr *ASTImporter::Import(Expr *FromE) {
  if (!FromE)
    return 0;

  return cast_or_null<Expr>(Import(cast<Stmt>(FromE)));
}

Stmt *ASTImporter::Import(Stmt *FromS) {
  if (!FromS)
    return 0;

  // FIXME: Implement!
  return 0;
}

NestedNameSpecifier *ASTImporter::Import(NestedNameSpecifier *FromNNS) {
  if (!FromNNS)
    return 0;

  // FIXME: Implement!
  return 0;
}

SourceLocation ASTImporter::Import(SourceLocation FromLoc) {
  if (FromLoc.isInvalid())
    return SourceLocation();

  SourceManager &FromSM = FromContext.getSourceManager();
  
  // For now, map everything down to its spelling location, so that we
  // don't have to import macro instantiations.
  // FIXME: Import macro instantiations!
  FromLoc = FromSM.getSpellingLoc(FromLoc);
  std::pair<FileID, unsigned> Decomposed = FromSM.getDecomposedLoc(FromLoc);
  SourceManager &ToSM = ToContext.getSourceManager();
  return ToSM.getLocForStartOfFile(Import(Decomposed.first))
             .getFileLocWithOffset(Decomposed.second);
}

SourceRange ASTImporter::Import(SourceRange FromRange) {
  return SourceRange(Import(FromRange.getBegin()), Import(FromRange.getEnd()));
}

FileID ASTImporter::Import(FileID FromID) {
  llvm::DenseMap<unsigned, FileID>::iterator Pos
    = ImportedFileIDs.find(FromID.getHashValue());
  if (Pos != ImportedFileIDs.end())
    return Pos->second;
  
  SourceManager &FromSM = FromContext.getSourceManager();
  SourceManager &ToSM = ToContext.getSourceManager();
  const SrcMgr::SLocEntry &FromSLoc = FromSM.getSLocEntry(FromID);
  assert(FromSLoc.isFile() && "Cannot handle macro instantiations yet");
  
  // Include location of this file.
  SourceLocation ToIncludeLoc = Import(FromSLoc.getFile().getIncludeLoc());
  
  // Map the FileID for to the "to" source manager.
  FileID ToID;
  const SrcMgr::ContentCache *Cache = FromSLoc.getFile().getContentCache();
  if (Cache->Entry) {
    // FIXME: We probably want to use getVirtualFile(), so we don't hit the
    // disk again
    // FIXME: We definitely want to re-use the existing MemoryBuffer, rather
    // than mmap the files several times.
    const FileEntry *Entry = ToFileManager.getFile(Cache->Entry->getName());
    ToID = ToSM.createFileID(Entry, ToIncludeLoc, 
                             FromSLoc.getFile().getFileCharacteristic());
  } else {
    // FIXME: We want to re-use the existing MemoryBuffer!
    const llvm::MemoryBuffer *FromBuf = Cache->getBuffer();
    llvm::MemoryBuffer *ToBuf
      = llvm::MemoryBuffer::getMemBufferCopy(FromBuf->getBufferStart(),
                                             FromBuf->getBufferEnd(),
                                             FromBuf->getBufferIdentifier());
    ToID = ToSM.createFileIDForMemBuffer(ToBuf);
  }
  
  
  ImportedFileIDs[FromID.getHashValue()] = ToID;
  return ToID;
}

DeclarationName ASTImporter::Import(DeclarationName FromName) {
  if (!FromName)
    return DeclarationName();

  switch (FromName.getNameKind()) {
  case DeclarationName::Identifier:
    return Import(FromName.getAsIdentifierInfo());

  case DeclarationName::ObjCZeroArgSelector:
  case DeclarationName::ObjCOneArgSelector:
  case DeclarationName::ObjCMultiArgSelector:
    return Import(FromName.getObjCSelector());

  case DeclarationName::CXXConstructorName: {
    QualType T = Import(FromName.getCXXNameType());
    if (T.isNull())
      return DeclarationName();

    return ToContext.DeclarationNames.getCXXConstructorName(
                                               ToContext.getCanonicalType(T));
  }

  case DeclarationName::CXXDestructorName: {
    QualType T = Import(FromName.getCXXNameType());
    if (T.isNull())
      return DeclarationName();

    return ToContext.DeclarationNames.getCXXDestructorName(
                                               ToContext.getCanonicalType(T));
  }

  case DeclarationName::CXXConversionFunctionName: {
    QualType T = Import(FromName.getCXXNameType());
    if (T.isNull())
      return DeclarationName();

    return ToContext.DeclarationNames.getCXXConversionFunctionName(
                                               ToContext.getCanonicalType(T));
  }

  case DeclarationName::CXXOperatorName:
    return ToContext.DeclarationNames.getCXXOperatorName(
                                          FromName.getCXXOverloadedOperator());

  case DeclarationName::CXXLiteralOperatorName:
    return ToContext.DeclarationNames.getCXXLiteralOperatorName(
                                   Import(FromName.getCXXLiteralIdentifier()));

  case DeclarationName::CXXUsingDirective:
    // FIXME: STATICS!
    return DeclarationName::getUsingDirectiveName();
  }

  // Silence bogus GCC warning
  return DeclarationName();
}

IdentifierInfo *ASTImporter::Import(IdentifierInfo *FromId) {
  if (!FromId)
    return 0;

  return &ToContext.Idents.get(FromId->getName());
}

DeclarationName ASTImporter::HandleNameConflict(DeclarationName Name,
                                                DeclContext *DC,
                                                unsigned IDNS,
                                                NamedDecl **Decls,
                                                unsigned NumDecls) {
  return Name;
}

DiagnosticBuilder ASTImporter::ToDiag(SourceLocation Loc, unsigned DiagID) {
  return ToDiags.Report(FullSourceLoc(Loc, ToContext.getSourceManager()), 
                        DiagID);
}

DiagnosticBuilder ASTImporter::FromDiag(SourceLocation Loc, unsigned DiagID) {
  return FromDiags.Report(FullSourceLoc(Loc, FromContext.getSourceManager()), 
                          DiagID);
}
