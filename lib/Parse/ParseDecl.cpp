//===--- ParseDecl.cpp - Declaration Parsing ------------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
//  This file implements the Declaration portions of the Parser interfaces.
//
//===----------------------------------------------------------------------===//

#include "clang/Parse/Parser.h"
#include "clang/Parse/ParseDiagnostic.h"
#include "clang/Parse/Scope.h"
#include "clang/Parse/Template.h"
#include "RAIIObjectsForParser.h"
#include "llvm/ADT/SmallSet.h"
using namespace clang;

//===----------------------------------------------------------------------===//
// C99 6.7: Declarations.
//===----------------------------------------------------------------------===//

/// ParseTypeName
///       type-name: [C99 6.7.6]
///         specifier-qualifier-list abstract-declarator[opt]
///
/// Called type-id in C++.
Action::TypeResult Parser::ParseTypeName(SourceRange *Range) {
  // Parse the common declaration-specifiers piece.
  DeclSpec DS;
  ParseSpecifierQualifierList(DS);

  // Parse the abstract-declarator, if present.
  Declarator DeclaratorInfo(DS, Declarator::TypeNameContext);
  ParseDeclarator(DeclaratorInfo);
  if (Range)
    *Range = DeclaratorInfo.getSourceRange();

  if (DeclaratorInfo.isInvalidType())
    return true;

  return Actions.ActOnTypeName(CurScope, DeclaratorInfo);
}

/// ParseGNUAttributes - Parse a non-empty attributes list.
///
/// [GNU] attributes:
///         attribute
///         attributes attribute
///
/// [GNU]  attribute:
///          '__attribute__' '(' '(' attribute-list ')' ')'
///
/// [GNU]  attribute-list:
///          attrib
///          attribute_list ',' attrib
///
/// [GNU]  attrib:
///          empty
///          attrib-name
///          attrib-name '(' identifier ')'
///          attrib-name '(' identifier ',' nonempty-expr-list ')'
///          attrib-name '(' argument-expression-list [C99 6.5.2] ')'
///
/// [GNU]  attrib-name:
///          identifier
///          typespec
///          typequal
///          storageclass
///
/// FIXME: The GCC grammar/code for this construct implies we need two
/// token lookahead. Comment from gcc: "If they start with an identifier
/// which is followed by a comma or close parenthesis, then the arguments
/// start with that identifier; otherwise they are an expression list."
///
/// At the moment, I am not doing 2 token lookahead. I am also unaware of
/// any attributes that don't work (based on my limited testing). Most
/// attributes are very simple in practice. Until we find a bug, I don't see
/// a pressing need to implement the 2 token lookahead.

AttributeList *Parser::ParseGNUAttributes(SourceLocation *EndLoc) {
  assert(Tok.is(tok::kw___attribute) && "Not a GNU attribute list!");

  AttributeList *CurrAttr = 0;

  while (Tok.is(tok::kw___attribute)) {
    ConsumeToken();
    if (ExpectAndConsume(tok::l_paren, diag::err_expected_lparen_after,
                         "attribute")) {
      SkipUntil(tok::r_paren, true); // skip until ) or ;
      return CurrAttr;
    }
    if (ExpectAndConsume(tok::l_paren, diag::err_expected_lparen_after, "(")) {
      SkipUntil(tok::r_paren, true); // skip until ) or ;
      return CurrAttr;
    }
    // Parse the attribute-list. e.g. __attribute__(( weak, alias("__f") ))
    while (Tok.is(tok::identifier) || isDeclarationSpecifier() ||
           Tok.is(tok::comma)) {

      if (Tok.is(tok::comma)) {
        // allows for empty/non-empty attributes. ((__vector_size__(16),,,,))
        ConsumeToken();
        continue;
      }
      // we have an identifier or declaration specifier (const, int, etc.)
      IdentifierInfo *AttrName = Tok.getIdentifierInfo();
      SourceLocation AttrNameLoc = ConsumeToken();

      // check if we have a "parameterized" attribute
      if (Tok.is(tok::l_paren)) {
        ConsumeParen(); // ignore the left paren loc for now

        if (Tok.is(tok::identifier)) {
          IdentifierInfo *ParmName = Tok.getIdentifierInfo();
          SourceLocation ParmLoc = ConsumeToken();

          if (Tok.is(tok::r_paren)) {
            // __attribute__(( mode(byte) ))
            ConsumeParen(); // ignore the right paren loc for now
            CurrAttr = new AttributeList(AttrName, AttrNameLoc, 0, AttrNameLoc,
                                         ParmName, ParmLoc, 0, 0, CurrAttr);
          } else if (Tok.is(tok::comma)) {
            ConsumeToken();
            // __attribute__(( format(printf, 1, 2) ))
            ExprVector ArgExprs(Actions);
            bool ArgExprsOk = true;

            // now parse the non-empty comma separated list of expressions
            while (1) {
              OwningExprResult ArgExpr(ParseAssignmentExpression());
              if (ArgExpr.isInvalid()) {
                ArgExprsOk = false;
                SkipUntil(tok::r_paren);
                break;
              } else {
                ArgExprs.push_back(ArgExpr.release());
              }
              if (Tok.isNot(tok::comma))
                break;
              ConsumeToken(); // Eat the comma, move to the next argument
            }
            if (ArgExprsOk && Tok.is(tok::r_paren)) {
              ConsumeParen(); // ignore the right paren loc for now
              CurrAttr = new AttributeList(AttrName, AttrNameLoc, 0,
                                           AttrNameLoc, ParmName, ParmLoc,
                                           ArgExprs.take(), ArgExprs.size(),
                                           CurrAttr);
            }
          }
        } else { // not an identifier
          switch (Tok.getKind()) {
          case tok::r_paren:
          // parse a possibly empty comma separated list of expressions
            // __attribute__(( nonnull() ))
            ConsumeParen(); // ignore the right paren loc for now
            CurrAttr = new AttributeList(AttrName, AttrNameLoc, 0, AttrNameLoc,
                                         0, SourceLocation(), 0, 0, CurrAttr);
            break;
          case tok::kw_char:
          case tok::kw_wchar_t:
          case tok::kw_char16_t:
          case tok::kw_char32_t:
          case tok::kw_bool:
          case tok::kw_short:
          case tok::kw_int:
          case tok::kw_long:
          case tok::kw_signed:
          case tok::kw_unsigned:
          case tok::kw_float:
          case tok::kw_double:
          case tok::kw_void:
          case tok::kw_typeof:
            // If it's a builtin type name, eat it and expect a rparen
            // __attribute__(( vec_type_hint(char) ))
            ConsumeToken();
            CurrAttr = new AttributeList(AttrName, AttrNameLoc, 0, AttrNameLoc,
                                         0, SourceLocation(), 0, 0, CurrAttr);
            if (Tok.is(tok::r_paren))
              ConsumeParen();
            break;
          default:
            // __attribute__(( aligned(16) ))
            ExprVector ArgExprs(Actions);
            bool ArgExprsOk = true;

            // now parse the list of expressions
            while (1) {
              OwningExprResult ArgExpr(ParseAssignmentExpression());
              if (ArgExpr.isInvalid()) {
                ArgExprsOk = false;
                SkipUntil(tok::r_paren);
                break;
              } else {
                ArgExprs.push_back(ArgExpr.release());
              }
              if (Tok.isNot(tok::comma))
                break;
              ConsumeToken(); // Eat the comma, move to the next argument
            }
            // Match the ')'.
            if (ArgExprsOk && Tok.is(tok::r_paren)) {
              ConsumeParen(); // ignore the right paren loc for now
              CurrAttr = new AttributeList(AttrName, AttrNameLoc, 0,
                           AttrNameLoc, 0, SourceLocation(), ArgExprs.take(),
                           ArgExprs.size(),
                           CurrAttr);
            }
            break;
          }
        }
      } else {
        CurrAttr = new AttributeList(AttrName, AttrNameLoc, 0, AttrNameLoc,
                                     0, SourceLocation(), 0, 0, CurrAttr);
      }
    }
    if (ExpectAndConsume(tok::r_paren, diag::err_expected_rparen))
      SkipUntil(tok::r_paren, false);
    SourceLocation Loc = Tok.getLocation();
    if (ExpectAndConsume(tok::r_paren, diag::err_expected_rparen)) {
      SkipUntil(tok::r_paren, false);
    }
    if (EndLoc)
      *EndLoc = Loc;
  }
  return CurrAttr;
}

/// ParseMicrosoftDeclSpec - Parse an __declspec construct
///
/// [MS] decl-specifier:
///             __declspec ( extended-decl-modifier-seq )
///
/// [MS] extended-decl-modifier-seq:
///             extended-decl-modifier[opt]
///             extended-decl-modifier extended-decl-modifier-seq

AttributeList* Parser::ParseMicrosoftDeclSpec(AttributeList *CurrAttr) {
  assert(Tok.is(tok::kw___declspec) && "Not a declspec!");

  ConsumeToken();
  if (ExpectAndConsume(tok::l_paren, diag::err_expected_lparen_after,
                       "declspec")) {
    SkipUntil(tok::r_paren, true); // skip until ) or ;
    return CurrAttr;
  }
  while (Tok.getIdentifierInfo()) {
    IdentifierInfo *AttrName = Tok.getIdentifierInfo();
    SourceLocation AttrNameLoc = ConsumeToken();
    if (Tok.is(tok::l_paren)) {
      ConsumeParen();
      // FIXME: This doesn't parse __declspec(property(get=get_func_name))
      // correctly.
      OwningExprResult ArgExpr(ParseAssignmentExpression());
      if (!ArgExpr.isInvalid()) {
        ExprTy* ExprList = ArgExpr.take();
        CurrAttr = new AttributeList(AttrName, AttrNameLoc, 0, AttrNameLoc, 0,
                                     SourceLocation(), &ExprList, 1,
                                     CurrAttr, true);
      }
      if (ExpectAndConsume(tok::r_paren, diag::err_expected_rparen))
        SkipUntil(tok::r_paren, false);
    } else {
      CurrAttr = new AttributeList(AttrName, AttrNameLoc, 0, AttrNameLoc,
                                   0, SourceLocation(), 0, 0, CurrAttr, true);
    }
  }
  if (ExpectAndConsume(tok::r_paren, diag::err_expected_rparen))
    SkipUntil(tok::r_paren, false);
  return CurrAttr;
}

AttributeList* Parser::ParseMicrosoftTypeAttributes(AttributeList *CurrAttr) {
  // Treat these like attributes
  // FIXME: Allow Sema to distinguish between these and real attributes!
  while (Tok.is(tok::kw___fastcall) || Tok.is(tok::kw___stdcall) ||
         Tok.is(tok::kw___cdecl)    || Tok.is(tok::kw___ptr64) ||
         Tok.is(tok::kw___w64)) {
    IdentifierInfo *AttrName = Tok.getIdentifierInfo();
    SourceLocation AttrNameLoc = ConsumeToken();
    if (Tok.is(tok::kw___ptr64) || Tok.is(tok::kw___w64))
      // FIXME: Support these properly!
      continue;
    CurrAttr = new AttributeList(AttrName, AttrNameLoc, 0, AttrNameLoc, 0,
                                 SourceLocation(), 0, 0, CurrAttr, true);
  }
  return CurrAttr;
}

/// ParseDeclaration - Parse a full 'declaration', which consists of
/// declaration-specifiers, some number of declarators, and a semicolon.
/// 'Context' should be a Declarator::TheContext value.  This returns the
/// location of the semicolon in DeclEnd.
///
///       declaration: [C99 6.7]
///         block-declaration ->
///           simple-declaration
///           others                   [FIXME]
/// [C++]   template-declaration
/// [C++]   namespace-definition
/// [C++]   using-directive
/// [C++]   using-declaration
/// [C++0x] static_assert-declaration
///         others... [FIXME]
///
Parser::DeclGroupPtrTy Parser::ParseDeclaration(unsigned Context,
                                                SourceLocation &DeclEnd,
                                                CXX0XAttributeList Attr) {
  DeclPtrTy SingleDecl;
  switch (Tok.getKind()) {
  case tok::kw_template:
  case tok::kw_export:
    if (Attr.HasAttr)
      Diag(Attr.Range.getBegin(), diag::err_attributes_not_allowed)
        << Attr.Range;
    SingleDecl = ParseDeclarationStartingWithTemplate(Context, DeclEnd);
    break;
  case tok::kw_namespace:
    if (Attr.HasAttr)
      Diag(Attr.Range.getBegin(), diag::err_attributes_not_allowed)
        << Attr.Range;
    SingleDecl = ParseNamespace(Context, DeclEnd);
    break;
  case tok::kw_using:
    SingleDecl = ParseUsingDirectiveOrDeclaration(Context, DeclEnd, Attr);
    break;
  case tok::kw_static_assert:
    if (Attr.HasAttr)
      Diag(Attr.Range.getBegin(), diag::err_attributes_not_allowed)
        << Attr.Range;
    SingleDecl = ParseStaticAssertDeclaration(DeclEnd);
    break;
  default:
    return ParseSimpleDeclaration(Context, DeclEnd, Attr.AttrList);
  }
  
  // This routine returns a DeclGroup, if the thing we parsed only contains a
  // single decl, convert it now.
  return Actions.ConvertDeclToDeclGroup(SingleDecl);
}

///       simple-declaration: [C99 6.7: declaration] [C++ 7p1: dcl.dcl]
///         declaration-specifiers init-declarator-list[opt] ';'
///[C90/C++]init-declarator-list ';'                             [TODO]
/// [OMP]   threadprivate-directive                              [TODO]
///
/// If RequireSemi is false, this does not check for a ';' at the end of the
/// declaration.
Parser::DeclGroupPtrTy Parser::ParseSimpleDeclaration(unsigned Context,
                                                      SourceLocation &DeclEnd,
                                                      AttributeList *Attr) {
  // Parse the common declaration-specifiers piece.
  ParsingDeclSpec DS(*this);
  if (Attr)
    DS.AddAttributes(Attr);
  ParseDeclarationSpecifiers(DS, ParsedTemplateInfo(), AS_none,
                            getDeclSpecContextFromDeclaratorContext(Context));

  // C99 6.7.2.3p6: Handle "struct-or-union identifier;", "enum { X };"
  // declaration-specifiers init-declarator-list[opt] ';'
  if (Tok.is(tok::semi)) {
    ConsumeToken();
    DeclPtrTy TheDecl = Actions.ParsedFreeStandingDeclSpec(CurScope, DS);
    DS.complete(TheDecl);
    return Actions.ConvertDeclToDeclGroup(TheDecl);
  }

  DeclGroupPtrTy DG = ParseDeclGroup(DS, Context, /*FunctionDefs=*/ false,
                                     &DeclEnd);
  return DG;
}

/// ParseDeclGroup - Having concluded that this is either a function
/// definition or a group of object declarations, actually parse the
/// result.
Parser::DeclGroupPtrTy Parser::ParseDeclGroup(ParsingDeclSpec &DS,
                                              unsigned Context,
                                              bool AllowFunctionDefinitions,
                                              SourceLocation *DeclEnd) {
  // Parse the first declarator.
  ParsingDeclarator D(*this, DS, static_cast<Declarator::TheContext>(Context));
  ParseDeclarator(D);

  // Bail out if the first declarator didn't seem well-formed.
  if (!D.hasName() && !D.mayOmitIdentifier()) {
    // Skip until ; or }.
    SkipUntil(tok::r_brace, true, true);
    if (Tok.is(tok::semi))
      ConsumeToken();
    return DeclGroupPtrTy();
  }

  if (AllowFunctionDefinitions && D.isFunctionDeclarator()) {
    if (isDeclarationAfterDeclarator()) {
      // Fall though.  We have to check this first, though, because
      // __attribute__ might be the start of a function definition in
      // (extended) K&R C.
    } else if (isStartOfFunctionDefinition()) {
      if (DS.getStorageClassSpec() == DeclSpec::SCS_typedef) {
        Diag(Tok, diag::err_function_declared_typedef);

        // Recover by treating the 'typedef' as spurious.
        DS.ClearStorageClassSpecs();
      }

      DeclPtrTy TheDecl = ParseFunctionDefinition(D);
      return Actions.ConvertDeclToDeclGroup(TheDecl);
    } else {
      Diag(Tok, diag::err_expected_fn_body);
      SkipUntil(tok::semi);
      return DeclGroupPtrTy();
    }
  }

  llvm::SmallVector<DeclPtrTy, 8> DeclsInGroup;
  DeclPtrTy FirstDecl = ParseDeclarationAfterDeclarator(D);
  D.complete(FirstDecl);
  if (FirstDecl.get())
    DeclsInGroup.push_back(FirstDecl);

  // If we don't have a comma, it is either the end of the list (a ';') or an
  // error, bail out.
  while (Tok.is(tok::comma)) {
    // Consume the comma.
    ConsumeToken();

    // Parse the next declarator.
    D.clear();

    // Accept attributes in an init-declarator.  In the first declarator in a
    // declaration, these would be part of the declspec.  In subsequent
    // declarators, they become part of the declarator itself, so that they
    // don't apply to declarators after *this* one.  Examples:
    //    short __attribute__((common)) var;    -> declspec
    //    short var __attribute__((common));    -> declarator
    //    short x, __attribute__((common)) var;    -> declarator
    if (Tok.is(tok::kw___attribute)) {
      SourceLocation Loc;
      AttributeList *AttrList = ParseGNUAttributes(&Loc);
      D.AddAttributes(AttrList, Loc);
    }

    ParseDeclarator(D);

    DeclPtrTy ThisDecl = ParseDeclarationAfterDeclarator(D);
    D.complete(ThisDecl);
    if (ThisDecl.get())
      DeclsInGroup.push_back(ThisDecl);    
  }

  if (DeclEnd)
    *DeclEnd = Tok.getLocation();

  if (Context != Declarator::ForContext &&
      ExpectAndConsume(tok::semi,
                       Context == Declarator::FileContext
                         ? diag::err_invalid_token_after_toplevel_declarator
                         : diag::err_expected_semi_declaration)) {
    SkipUntil(tok::r_brace, true, true);
    if (Tok.is(tok::semi))
      ConsumeToken();
  }

  return Actions.FinalizeDeclaratorGroup(CurScope, DS,
                                         DeclsInGroup.data(),
                                         DeclsInGroup.size());
}

/// \brief Parse 'declaration' after parsing 'declaration-specifiers
/// declarator'. This method parses the remainder of the declaration
/// (including any attributes or initializer, among other things) and
/// finalizes the declaration.
///
///       init-declarator: [C99 6.7]
///         declarator
///         declarator '=' initializer
/// [GNU]   declarator simple-asm-expr[opt] attributes[opt]
/// [GNU]   declarator simple-asm-expr[opt] attributes[opt] '=' initializer
/// [C++]   declarator initializer[opt]
///
/// [C++] initializer:
/// [C++]   '=' initializer-clause
/// [C++]   '(' expression-list ')'
/// [C++0x] '=' 'default'                                                [TODO]
/// [C++0x] '=' 'delete'
///
/// According to the standard grammar, =default and =delete are function
/// definitions, but that definitely doesn't fit with the parser here.
///
Parser::DeclPtrTy Parser::ParseDeclarationAfterDeclarator(Declarator &D,
                                     const ParsedTemplateInfo &TemplateInfo) {
  // If a simple-asm-expr is present, parse it.
  if (Tok.is(tok::kw_asm)) {
    SourceLocation Loc;
    OwningExprResult AsmLabel(ParseSimpleAsm(&Loc));
    if (AsmLabel.isInvalid()) {
      SkipUntil(tok::semi, true, true);
      return DeclPtrTy();
    }

    D.setAsmLabel(AsmLabel.release());
    D.SetRangeEnd(Loc);
  }

  // If attributes are present, parse them.
  if (Tok.is(tok::kw___attribute)) {
    SourceLocation Loc;
    AttributeList *AttrList = ParseGNUAttributes(&Loc);
    D.AddAttributes(AttrList, Loc);
  }

  // Inform the current actions module that we just parsed this declarator.
  DeclPtrTy ThisDecl;
  switch (TemplateInfo.Kind) {
  case ParsedTemplateInfo::NonTemplate:
    ThisDecl = Actions.ActOnDeclarator(CurScope, D);
    break;
      
  case ParsedTemplateInfo::Template:
  case ParsedTemplateInfo::ExplicitSpecialization:
    ThisDecl = Actions.ActOnTemplateDeclarator(CurScope,
                             Action::MultiTemplateParamsArg(Actions,
                                          TemplateInfo.TemplateParams->data(),
                                          TemplateInfo.TemplateParams->size()),
                                               D);
    break;
      
  case ParsedTemplateInfo::ExplicitInstantiation: {
    Action::DeclResult ThisRes 
      = Actions.ActOnExplicitInstantiation(CurScope,
                                           TemplateInfo.ExternLoc,
                                           TemplateInfo.TemplateLoc,
                                           D);
    if (ThisRes.isInvalid()) {
      SkipUntil(tok::semi, true, true);
      return DeclPtrTy();
    }
    
    ThisDecl = ThisRes.get();
    break;
    }
  }

  // Parse declarator '=' initializer.
  if (Tok.is(tok::equal)) {
    ConsumeToken();
    if (getLang().CPlusPlus0x && Tok.is(tok::kw_delete)) {
      SourceLocation DelLoc = ConsumeToken();
      Actions.SetDeclDeleted(ThisDecl, DelLoc);
    } else {
      if (getLang().CPlusPlus && D.getCXXScopeSpec().isSet()) {
        EnterScope(0);
        Actions.ActOnCXXEnterDeclInitializer(CurScope, ThisDecl);
      }

      OwningExprResult Init(ParseInitializer());

      if (getLang().CPlusPlus && D.getCXXScopeSpec().isSet()) {
        Actions.ActOnCXXExitDeclInitializer(CurScope, ThisDecl);
        ExitScope();
      }

      if (Init.isInvalid()) {
        SkipUntil(tok::comma, true, true);
        Actions.ActOnInitializerError(ThisDecl);
      } else
        Actions.AddInitializerToDecl(ThisDecl, move(Init));
    }
  } else if (Tok.is(tok::l_paren)) {
    // Parse C++ direct initializer: '(' expression-list ')'
    SourceLocation LParenLoc = ConsumeParen();
    ExprVector Exprs(Actions);
    CommaLocsTy CommaLocs;

    if (getLang().CPlusPlus && D.getCXXScopeSpec().isSet()) {
      EnterScope(0);
      Actions.ActOnCXXEnterDeclInitializer(CurScope, ThisDecl);
    }

    if (ParseExpressionList(Exprs, CommaLocs)) {
      SkipUntil(tok::r_paren);

      if (getLang().CPlusPlus && D.getCXXScopeSpec().isSet()) {
        Actions.ActOnCXXExitDeclInitializer(CurScope, ThisDecl);
        ExitScope();
      }
    } else {
      // Match the ')'.
      SourceLocation RParenLoc = MatchRHSPunctuation(tok::r_paren, LParenLoc);

      assert(!Exprs.empty() && Exprs.size()-1 == CommaLocs.size() &&
             "Unexpected number of commas!");

      if (getLang().CPlusPlus && D.getCXXScopeSpec().isSet()) {
        Actions.ActOnCXXExitDeclInitializer(CurScope, ThisDecl);
        ExitScope();
      }

      Actions.AddCXXDirectInitializerToDecl(ThisDecl, LParenLoc,
                                            move_arg(Exprs),
                                            CommaLocs.data(), RParenLoc);
    }
  } else {
    bool TypeContainsUndeducedAuto =
      D.getDeclSpec().getTypeSpecType() == DeclSpec::TST_auto;
    Actions.ActOnUninitializedDecl(ThisDecl, TypeContainsUndeducedAuto);
  }

  return ThisDecl;
}

/// ParseSpecifierQualifierList
///        specifier-qualifier-list:
///          type-specifier specifier-qualifier-list[opt]
///          type-qualifier specifier-qualifier-list[opt]
/// [GNU]    attributes     specifier-qualifier-list[opt]
///
void Parser::ParseSpecifierQualifierList(DeclSpec &DS) {
  /// specifier-qualifier-list is a subset of declaration-specifiers.  Just
  /// parse declaration-specifiers and complain about extra stuff.
  ParseDeclarationSpecifiers(DS);

  // Validate declspec for type-name.
  unsigned Specs = DS.getParsedSpecifiers();
  if (Specs == DeclSpec::PQ_None && !DS.getNumProtocolQualifiers() &&
      !DS.getAttributes())
    Diag(Tok, diag::err_typename_requires_specqual);

  // Issue diagnostic and remove storage class if present.
  if (Specs & DeclSpec::PQ_StorageClassSpecifier) {
    if (DS.getStorageClassSpecLoc().isValid())
      Diag(DS.getStorageClassSpecLoc(),diag::err_typename_invalid_storageclass);
    else
      Diag(DS.getThreadSpecLoc(), diag::err_typename_invalid_storageclass);
    DS.ClearStorageClassSpecs();
  }

  // Issue diagnostic and remove function specfier if present.
  if (Specs & DeclSpec::PQ_FunctionSpecifier) {
    if (DS.isInlineSpecified())
      Diag(DS.getInlineSpecLoc(), diag::err_typename_invalid_functionspec);
    if (DS.isVirtualSpecified())
      Diag(DS.getVirtualSpecLoc(), diag::err_typename_invalid_functionspec);
    if (DS.isExplicitSpecified())
      Diag(DS.getExplicitSpecLoc(), diag::err_typename_invalid_functionspec);
    DS.ClearFunctionSpecs();
  }
}

/// isValidAfterIdentifierInDeclaratorAfterDeclSpec - Return true if the
/// specified token is valid after the identifier in a declarator which
/// immediately follows the declspec.  For example, these things are valid:
///
///      int x   [             4];         // direct-declarator
///      int x   (             int y);     // direct-declarator
///  int(int x   )                         // direct-declarator
///      int x   ;                         // simple-declaration
///      int x   =             17;         // init-declarator-list
///      int x   ,             y;          // init-declarator-list
///      int x   __asm__       ("foo");    // init-declarator-list
///      int x   :             4;          // struct-declarator
///      int x   {             5};         // C++'0x unified initializers
///
/// This is not, because 'x' does not immediately follow the declspec (though
/// ')' happens to be valid anyway).
///    int (x)
///
static bool isValidAfterIdentifierInDeclarator(const Token &T) {
  return T.is(tok::l_square) || T.is(tok::l_paren) || T.is(tok::r_paren) ||
         T.is(tok::semi) || T.is(tok::comma) || T.is(tok::equal) ||
         T.is(tok::kw_asm) || T.is(tok::l_brace) || T.is(tok::colon);
}


/// ParseImplicitInt - This method is called when we have an non-typename
/// identifier in a declspec (which normally terminates the decl spec) when
/// the declspec has no type specifier.  In this case, the declspec is either
/// malformed or is "implicit int" (in K&R and C89).
///
/// This method handles diagnosing this prettily and returns false if the
/// declspec is done being processed.  If it recovers and thinks there may be
/// other pieces of declspec after it, it returns true.
///
bool Parser::ParseImplicitInt(DeclSpec &DS, CXXScopeSpec *SS,
                              const ParsedTemplateInfo &TemplateInfo,
                              AccessSpecifier AS) {
  assert(Tok.is(tok::identifier) && "should have identifier");

  SourceLocation Loc = Tok.getLocation();
  // If we see an identifier that is not a type name, we normally would
  // parse it as the identifer being declared.  However, when a typename
  // is typo'd or the definition is not included, this will incorrectly
  // parse the typename as the identifier name and fall over misparsing
  // later parts of the diagnostic.
  //
  // As such, we try to do some look-ahead in cases where this would
  // otherwise be an "implicit-int" case to see if this is invalid.  For
  // example: "static foo_t x = 4;"  In this case, if we parsed foo_t as
  // an identifier with implicit int, we'd get a parse error because the
  // next token is obviously invalid for a type.  Parse these as a case
  // with an invalid type specifier.
  assert(!DS.hasTypeSpecifier() && "Type specifier checked above");

  // Since we know that this either implicit int (which is rare) or an
  // error, we'd do lookahead to try to do better recovery.
  if (isValidAfterIdentifierInDeclarator(NextToken())) {
    // If this token is valid for implicit int, e.g. "static x = 4", then
    // we just avoid eating the identifier, so it will be parsed as the
    // identifier in the declarator.
    return false;
  }

  // Otherwise, if we don't consume this token, we are going to emit an
  // error anyway.  Try to recover from various common problems.  Check
  // to see if this was a reference to a tag name without a tag specified.
  // This is a common problem in C (saying 'foo' instead of 'struct foo').
  //
  // C++ doesn't need this, and isTagName doesn't take SS.
  if (SS == 0) {
    const char *TagName = 0;
    tok::TokenKind TagKind = tok::unknown;

    switch (Actions.isTagName(*Tok.getIdentifierInfo(), CurScope)) {
      default: break;
      case DeclSpec::TST_enum:  TagName="enum"  ;TagKind=tok::kw_enum  ;break;
      case DeclSpec::TST_union: TagName="union" ;TagKind=tok::kw_union ;break;
      case DeclSpec::TST_struct:TagName="struct";TagKind=tok::kw_struct;break;
      case DeclSpec::TST_class: TagName="class" ;TagKind=tok::kw_class ;break;
    }

    if (TagName) {
      Diag(Loc, diag::err_use_of_tag_name_without_tag)
        << Tok.getIdentifierInfo() << TagName << getLang().CPlusPlus
        << CodeModificationHint::CreateInsertion(Tok.getLocation(),TagName);

      // Parse this as a tag as if the missing tag were present.
      if (TagKind == tok::kw_enum)
        ParseEnumSpecifier(Loc, DS, TemplateInfo, AS);
      else
        ParseClassSpecifier(TagKind, Loc, DS, TemplateInfo, AS);
      return true;
    }
  }

  // This is almost certainly an invalid type name. Let the action emit a 
  // diagnostic and attempt to recover.
  Action::TypeTy *T = 0;
  if (Actions.DiagnoseUnknownTypeName(*Tok.getIdentifierInfo(), Loc,
                                      CurScope, SS, T)) {
    // The action emitted a diagnostic, so we don't have to.
    if (T) {
      // The action has suggested that the type T could be used. Set that as
      // the type in the declaration specifiers, consume the would-be type
      // name token, and we're done.
      const char *PrevSpec;
      unsigned DiagID;
      DS.SetTypeSpecType(DeclSpec::TST_typename, Loc, PrevSpec, DiagID, T, 
                         false);
      DS.SetRangeEnd(Tok.getLocation());
      ConsumeToken();
      
      // There may be other declaration specifiers after this.
      return true;
    }
    
    // Fall through; the action had no suggestion for us.
  } else {
    // The action did not emit a diagnostic, so emit one now.
    SourceRange R;
    if (SS) R = SS->getRange();
    Diag(Loc, diag::err_unknown_typename) << Tok.getIdentifierInfo() << R;
  }

  // Mark this as an error.
  const char *PrevSpec;
  unsigned DiagID;
  DS.SetTypeSpecType(DeclSpec::TST_error, Loc, PrevSpec, DiagID);
  DS.SetRangeEnd(Tok.getLocation());
  ConsumeToken();

  // TODO: Could inject an invalid typedef decl in an enclosing scope to
  // avoid rippling error messages on subsequent uses of the same type,
  // could be useful if #include was forgotten.
  return false;
}

/// \brief Determine the declaration specifier context from the declarator
/// context.
///
/// \param Context the declarator context, which is one of the
/// Declarator::TheContext enumerator values.
Parser::DeclSpecContext 
Parser::getDeclSpecContextFromDeclaratorContext(unsigned Context) {
  if (Context == Declarator::MemberContext)
    return DSC_class;
  if (Context == Declarator::FileContext)
    return DSC_top_level;
  return DSC_normal;
}

/// ParseDeclarationSpecifiers
///       declaration-specifiers: [C99 6.7]
///         storage-class-specifier declaration-specifiers[opt]
///         type-specifier declaration-specifiers[opt]
/// [C99]   function-specifier declaration-specifiers[opt]
/// [GNU]   attributes declaration-specifiers[opt]
///
///       storage-class-specifier: [C99 6.7.1]
///         'typedef'
///         'extern'
///         'static'
///         'auto'
///         'register'
/// [C++]   'mutable'
/// [GNU]   '__thread'
///       function-specifier: [C99 6.7.4]
/// [C99]   'inline'
/// [C++]   'virtual'
/// [C++]   'explicit'
///       'friend': [C++ dcl.friend]
///       'constexpr': [C++0x dcl.constexpr]

///
void Parser::ParseDeclarationSpecifiers(DeclSpec &DS,
                                        const ParsedTemplateInfo &TemplateInfo,
                                        AccessSpecifier AS,
                                        DeclSpecContext DSContext) {
  if (Tok.is(tok::code_completion)) {
    Action::CodeCompletionContext CCC = Action::CCC_Namespace;
    if (TemplateInfo.Kind != ParsedTemplateInfo::NonTemplate)
      CCC = DSContext == DSC_class? Action::CCC_MemberTemplate 
                                  : Action::CCC_Template;
    else if (DSContext == DSC_class)
      CCC = Action::CCC_Class;
    else if (ObjCImpDecl)
      CCC = Action::CCC_ObjCImplementation;
    
    Actions.CodeCompleteOrdinaryName(CurScope, CCC);
    ConsumeToken();
  }
  
  DS.SetRangeStart(Tok.getLocation());
  while (1) {
    bool isInvalid = false;
    const char *PrevSpec = 0;
    unsigned DiagID = 0;

    SourceLocation Loc = Tok.getLocation();

    switch (Tok.getKind()) {
    default:
    DoneWithDeclSpec:
      // If this is not a declaration specifier token, we're done reading decl
      // specifiers.  First verify that DeclSpec's are consistent.
      DS.Finish(Diags, PP);
      return;

    case tok::coloncolon: // ::foo::bar
      // C++ scope specifier.  Annotate and loop, or bail out on error.
      if (TryAnnotateCXXScopeToken(true)) {
        if (!DS.hasTypeSpecifier())
          DS.SetTypeSpecError();
        goto DoneWithDeclSpec;
      }
      if (Tok.is(tok::coloncolon)) // ::new or ::delete
        goto DoneWithDeclSpec;
      continue;

    case tok::annot_cxxscope: {
      if (DS.hasTypeSpecifier())
        goto DoneWithDeclSpec;

      CXXScopeSpec SS;
      SS.setScopeRep(Tok.getAnnotationValue());
      SS.setRange(Tok.getAnnotationRange());

      // We are looking for a qualified typename.
      Token Next = NextToken();
      if (Next.is(tok::annot_template_id) &&
          static_cast<TemplateIdAnnotation *>(Next.getAnnotationValue())
            ->Kind == TNK_Type_template) {
        // We have a qualified template-id, e.g., N::A<int>

        // C++ [class.qual]p2:
        //   In a lookup in which the constructor is an acceptable lookup
        //   result and the nested-name-specifier nominates a class C:
        //
        //     - if the name specified after the
        //       nested-name-specifier, when looked up in C, is the
        //       injected-class-name of C (Clause 9), or
        //
        //     - if the name specified after the nested-name-specifier
        //       is the same as the identifier or the
        //       simple-template-id's template-name in the last
        //       component of the nested-name-specifier,
        //
        //   the name is instead considered to name the constructor of
        //   class C.
        // 
        // Thus, if the template-name is actually the constructor
        // name, then the code is ill-formed; this interpretation is
        // reinforced by the NAD status of core issue 635. 
        TemplateIdAnnotation *TemplateId
          = static_cast<TemplateIdAnnotation *>(Next.getAnnotationValue());
        if (DSContext == DSC_top_level && TemplateId->Name &&
            Actions.isCurrentClassName(*TemplateId->Name, CurScope, &SS)) {
          if (isConstructorDeclarator()) {
            // The user meant this to be an out-of-line constructor
            // definition, but template arguments are not allowed
            // there.  Just allow this as a constructor; we'll
            // complain about it later.
            goto DoneWithDeclSpec;
          }

          // The user meant this to name a type, but it actually names
          // a constructor with some extraneous template
          // arguments. Complain, then parse it as a type as the user
          // intended.
          Diag(TemplateId->TemplateNameLoc,
               diag::err_out_of_line_template_id_names_constructor)
            << TemplateId->Name;
        }

        DS.getTypeSpecScope() = SS;
        ConsumeToken(); // The C++ scope.
        assert(Tok.is(tok::annot_template_id) &&
               "ParseOptionalCXXScopeSpecifier not working");
        AnnotateTemplateIdTokenAsType(&SS);
        continue;
      }

      if (Next.is(tok::annot_typename)) {
        DS.getTypeSpecScope() = SS;
        ConsumeToken(); // The C++ scope.
        if (Tok.getAnnotationValue())
          isInvalid = DS.SetTypeSpecType(DeclSpec::TST_typename, Loc, 
                                         PrevSpec, DiagID, 
                                         Tok.getAnnotationValue());
        else
          DS.SetTypeSpecError();
        DS.SetRangeEnd(Tok.getAnnotationEndLoc());
        ConsumeToken(); // The typename
      }

      if (Next.isNot(tok::identifier))
        goto DoneWithDeclSpec;

      // If we're in a context where the identifier could be a class name,
      // check whether this is a constructor declaration.
      if (DSContext == DSC_top_level &&
          Actions.isCurrentClassName(*Next.getIdentifierInfo(), CurScope, 
                                     &SS)) {
        if (isConstructorDeclarator())
          goto DoneWithDeclSpec;

        // As noted in C++ [class.qual]p2 (cited above), when the name
        // of the class is qualified in a context where it could name
        // a constructor, its a constructor name. However, we've
        // looked at the declarator, and the user probably meant this
        // to be a type. Complain that it isn't supposed to be treated
        // as a type, then proceed to parse it as a type.
        Diag(Next.getLocation(), diag::err_out_of_line_type_names_constructor)
          << Next.getIdentifierInfo();
      }

      TypeTy *TypeRep = Actions.getTypeName(*Next.getIdentifierInfo(),
                                            Next.getLocation(), CurScope, &SS);

      // If the referenced identifier is not a type, then this declspec is
      // erroneous: We already checked about that it has no type specifier, and
      // C++ doesn't have implicit int.  Diagnose it as a typo w.r.t. to the
      // typename.
      if (TypeRep == 0) {
        ConsumeToken();   // Eat the scope spec so the identifier is current.
        if (ParseImplicitInt(DS, &SS, TemplateInfo, AS)) continue;
        goto DoneWithDeclSpec;
      }

      DS.getTypeSpecScope() = SS;
      ConsumeToken(); // The C++ scope.

      isInvalid = DS.SetTypeSpecType(DeclSpec::TST_typename, Loc, PrevSpec,
                                     DiagID, TypeRep);
      if (isInvalid)
        break;

      DS.SetRangeEnd(Tok.getLocation());
      ConsumeToken(); // The typename.

      continue;
    }

    case tok::annot_typename: {
      if (Tok.getAnnotationValue())
        isInvalid = DS.SetTypeSpecType(DeclSpec::TST_typename, Loc, PrevSpec,
                                       DiagID, Tok.getAnnotationValue());
      else
        DS.SetTypeSpecError();
      DS.SetRangeEnd(Tok.getAnnotationEndLoc());
      ConsumeToken(); // The typename

      // Objective-C supports syntax of the form 'id<proto1,proto2>' where 'id'
      // is a specific typedef and 'itf<proto1,proto2>' where 'itf' is an
      // Objective-C interface.  If we don't have Objective-C or a '<', this is
      // just a normal reference to a typedef name.
      if (!Tok.is(tok::less) || !getLang().ObjC1)
        continue;

      SourceLocation LAngleLoc, EndProtoLoc;
      llvm::SmallVector<DeclPtrTy, 8> ProtocolDecl;
      llvm::SmallVector<SourceLocation, 8> ProtocolLocs;
      ParseObjCProtocolReferences(ProtocolDecl, ProtocolLocs, false,
                                  LAngleLoc, EndProtoLoc);
      DS.setProtocolQualifiers(ProtocolDecl.data(), ProtocolDecl.size(),
                               ProtocolLocs.data(), LAngleLoc);

      DS.SetRangeEnd(EndProtoLoc);
      continue;
    }

      // typedef-name
    case tok::identifier: {
      // In C++, check to see if this is a scope specifier like foo::bar::, if
      // so handle it as such.  This is important for ctor parsing.
      if (getLang().CPlusPlus) {
        if (TryAnnotateCXXScopeToken(true)) {
          if (!DS.hasTypeSpecifier())
            DS.SetTypeSpecError();
          goto DoneWithDeclSpec;
        }
        if (!Tok.is(tok::identifier))
          continue;
      }

      // This identifier can only be a typedef name if we haven't already seen
      // a type-specifier.  Without this check we misparse:
      //  typedef int X; struct Y { short X; };  as 'short int'.
      if (DS.hasTypeSpecifier())
        goto DoneWithDeclSpec;

      // Check for need to substitute AltiVec keyword tokens.
      if (TryAltiVecToken(DS, Loc, PrevSpec, DiagID, isInvalid))
        break;

      // It has to be available as a typedef too!
      TypeTy *TypeRep = Actions.getTypeName(*Tok.getIdentifierInfo(),
                                            Tok.getLocation(), CurScope);

      // If this is not a typedef name, don't parse it as part of the declspec,
      // it must be an implicit int or an error.
      if (TypeRep == 0) {
        if (ParseImplicitInt(DS, 0, TemplateInfo, AS)) continue;
        goto DoneWithDeclSpec;
      }

      // If we're in a context where the identifier could be a class name,
      // check whether this is a constructor declaration.
      if (getLang().CPlusPlus && DSContext == DSC_class &&
          Actions.isCurrentClassName(*Tok.getIdentifierInfo(), CurScope) &&
          isConstructorDeclarator())
        goto DoneWithDeclSpec;

      isInvalid = DS.SetTypeSpecType(DeclSpec::TST_typename, Loc, PrevSpec,
                                     DiagID, TypeRep);
      if (isInvalid)
        break;

      DS.SetRangeEnd(Tok.getLocation());
      ConsumeToken(); // The identifier

      // Objective-C supports syntax of the form 'id<proto1,proto2>' where 'id'
      // is a specific typedef and 'itf<proto1,proto2>' where 'itf' is an
      // Objective-C interface.  If we don't have Objective-C or a '<', this is
      // just a normal reference to a typedef name.
      if (!Tok.is(tok::less) || !getLang().ObjC1)
        continue;

      SourceLocation LAngleLoc, EndProtoLoc;
      llvm::SmallVector<DeclPtrTy, 8> ProtocolDecl;
      llvm::SmallVector<SourceLocation, 8> ProtocolLocs;
      ParseObjCProtocolReferences(ProtocolDecl, ProtocolLocs, false,
                                  LAngleLoc, EndProtoLoc);
      DS.setProtocolQualifiers(ProtocolDecl.data(), ProtocolDecl.size(),
                               ProtocolLocs.data(), LAngleLoc);

      DS.SetRangeEnd(EndProtoLoc);

      // Need to support trailing type qualifiers (e.g. "id<p> const").
      // If a type specifier follows, it will be diagnosed elsewhere.
      continue;
    }

      // type-name
    case tok::annot_template_id: {
      TemplateIdAnnotation *TemplateId
        = static_cast<TemplateIdAnnotation *>(Tok.getAnnotationValue());
      if (TemplateId->Kind != TNK_Type_template) {
        // This template-id does not refer to a type name, so we're
        // done with the type-specifiers.
        goto DoneWithDeclSpec;
      }

      // If we're in a context where the template-id could be a
      // constructor name or specialization, check whether this is a
      // constructor declaration.
      if (getLang().CPlusPlus && DSContext == DSC_class &&
          Actions.isCurrentClassName(*TemplateId->Name, CurScope) &&
          isConstructorDeclarator())
        goto DoneWithDeclSpec;

      // Turn the template-id annotation token into a type annotation
      // token, then try again to parse it as a type-specifier.
      AnnotateTemplateIdTokenAsType();
      continue;
    }

    // GNU attributes support.
    case tok::kw___attribute:
      DS.AddAttributes(ParseGNUAttributes());
      continue;

    // Microsoft declspec support.
    case tok::kw___declspec:
      DS.AddAttributes(ParseMicrosoftDeclSpec());
      continue;

    // Microsoft single token adornments.
    case tok::kw___forceinline:
      // FIXME: Add handling here!
      break;

    case tok::kw___ptr64:
    case tok::kw___w64:
    case tok::kw___cdecl:
    case tok::kw___stdcall:
    case tok::kw___fastcall:
      DS.AddAttributes(ParseMicrosoftTypeAttributes());
      continue;

    // storage-class-specifier
    case tok::kw_typedef:
      isInvalid = DS.SetStorageClassSpec(DeclSpec::SCS_typedef, Loc, PrevSpec,
                                         DiagID);
      break;
    case tok::kw_extern:
      if (DS.isThreadSpecified())
        Diag(Tok, diag::ext_thread_before) << "extern";
      isInvalid = DS.SetStorageClassSpec(DeclSpec::SCS_extern, Loc, PrevSpec,
                                         DiagID);
      break;
    case tok::kw___private_extern__:
      isInvalid = DS.SetStorageClassSpec(DeclSpec::SCS_private_extern, Loc,
                                         PrevSpec, DiagID);
      break;
    case tok::kw_static:
      if (DS.isThreadSpecified())
        Diag(Tok, diag::ext_thread_before) << "static";
      isInvalid = DS.SetStorageClassSpec(DeclSpec::SCS_static, Loc, PrevSpec,
                                         DiagID);
      break;
    case tok::kw_auto:
      if (getLang().CPlusPlus0x)
        isInvalid = DS.SetTypeSpecType(DeclSpec::TST_auto, Loc, PrevSpec,
                                       DiagID);
      else
        isInvalid = DS.SetStorageClassSpec(DeclSpec::SCS_auto, Loc, PrevSpec,
                                           DiagID);
      break;
    case tok::kw_register:
      isInvalid = DS.SetStorageClassSpec(DeclSpec::SCS_register, Loc, PrevSpec,
                                         DiagID);
      break;
    case tok::kw_mutable:
      isInvalid = DS.SetStorageClassSpec(DeclSpec::SCS_mutable, Loc, PrevSpec,
                                         DiagID);
      break;
    case tok::kw___thread:
      isInvalid = DS.SetStorageClassSpecThread(Loc, PrevSpec, DiagID);
      break;

    // function-specifier
    case tok::kw_inline:
      isInvalid = DS.SetFunctionSpecInline(Loc, PrevSpec, DiagID);
      break;
    case tok::kw_virtual:
      isInvalid = DS.SetFunctionSpecVirtual(Loc, PrevSpec, DiagID);
      break;
    case tok::kw_explicit:
      isInvalid = DS.SetFunctionSpecExplicit(Loc, PrevSpec, DiagID);
      break;

    // friend
    case tok::kw_friend:
      if (DSContext == DSC_class)
        isInvalid = DS.SetFriendSpec(Loc, PrevSpec, DiagID);
      else {
        PrevSpec = ""; // not actually used by the diagnostic
        DiagID = diag::err_friend_invalid_in_context;
        isInvalid = true;
      }
      break;

    // constexpr
    case tok::kw_constexpr:
      isInvalid = DS.SetConstexprSpec(Loc, PrevSpec, DiagID);
      break;

    // type-specifier
    case tok::kw_short:
      isInvalid = DS.SetTypeSpecWidth(DeclSpec::TSW_short, Loc, PrevSpec,
                                      DiagID);
      break;
    case tok::kw_long:
      if (DS.getTypeSpecWidth() != DeclSpec::TSW_long)
        isInvalid = DS.SetTypeSpecWidth(DeclSpec::TSW_long, Loc, PrevSpec,
                                        DiagID);
      else
        isInvalid = DS.SetTypeSpecWidth(DeclSpec::TSW_longlong, Loc, PrevSpec,
                                        DiagID);
      break;
    case tok::kw_signed:
      isInvalid = DS.SetTypeSpecSign(DeclSpec::TSS_signed, Loc, PrevSpec,
                                     DiagID);
      break;
    case tok::kw_unsigned:
      isInvalid = DS.SetTypeSpecSign(DeclSpec::TSS_unsigned, Loc, PrevSpec,
                                     DiagID);
      break;
    case tok::kw__Complex:
      isInvalid = DS.SetTypeSpecComplex(DeclSpec::TSC_complex, Loc, PrevSpec,
                                        DiagID);
      break;
    case tok::kw__Imaginary:
      isInvalid = DS.SetTypeSpecComplex(DeclSpec::TSC_imaginary, Loc, PrevSpec,
                                        DiagID);
      break;
    case tok::kw_void:
      isInvalid = DS.SetTypeSpecType(DeclSpec::TST_void, Loc, PrevSpec,
                                     DiagID);
      break;
    case tok::kw_char:
      isInvalid = DS.SetTypeSpecType(DeclSpec::TST_char, Loc, PrevSpec,
                                     DiagID);
      break;
    case tok::kw_int:
      isInvalid = DS.SetTypeSpecType(DeclSpec::TST_int, Loc, PrevSpec,
                                     DiagID);
      break;
    case tok::kw_float:
      isInvalid = DS.SetTypeSpecType(DeclSpec::TST_float, Loc, PrevSpec,
                                     DiagID);
      break;
    case tok::kw_double:
      isInvalid = DS.SetTypeSpecType(DeclSpec::TST_double, Loc, PrevSpec,
                                     DiagID);
      break;
    case tok::kw_wchar_t:
      isInvalid = DS.SetTypeSpecType(DeclSpec::TST_wchar, Loc, PrevSpec,
                                     DiagID);
      break;
    case tok::kw_char16_t:
      isInvalid = DS.SetTypeSpecType(DeclSpec::TST_char16, Loc, PrevSpec,
                                     DiagID);
      break;
    case tok::kw_char32_t:
      isInvalid = DS.SetTypeSpecType(DeclSpec::TST_char32, Loc, PrevSpec,
                                     DiagID);
      break;
    case tok::kw_bool:
    case tok::kw__Bool:
      isInvalid = DS.SetTypeSpecType(DeclSpec::TST_bool, Loc, PrevSpec,
                                     DiagID);
      break;
    case tok::kw__Decimal32:
      isInvalid = DS.SetTypeSpecType(DeclSpec::TST_decimal32, Loc, PrevSpec,
                                     DiagID);
      break;
    case tok::kw__Decimal64:
      isInvalid = DS.SetTypeSpecType(DeclSpec::TST_decimal64, Loc, PrevSpec,
                                     DiagID);
      break;
    case tok::kw__Decimal128:
      isInvalid = DS.SetTypeSpecType(DeclSpec::TST_decimal128, Loc, PrevSpec,
                                     DiagID);
      break;
    case tok::kw___vector:
      isInvalid = DS.SetTypeAltiVecVector(true, Loc, PrevSpec, DiagID);
      break;
    case tok::kw___pixel:
      isInvalid = DS.SetTypeAltiVecPixel(true, Loc, PrevSpec, DiagID);
      break;

    // class-specifier:
    case tok::kw_class:
    case tok::kw_struct:
    case tok::kw_union: {
      tok::TokenKind Kind = Tok.getKind();
      ConsumeToken();
      ParseClassSpecifier(Kind, Loc, DS, TemplateInfo, AS);
      continue;
    }

    // enum-specifier:
    case tok::kw_enum:
      ConsumeToken();
      ParseEnumSpecifier(Loc, DS, TemplateInfo, AS);
      continue;

    // cv-qualifier:
    case tok::kw_const:
      isInvalid = DS.SetTypeQual(DeclSpec::TQ_const, Loc, PrevSpec, DiagID,
                                 getLang());
      break;
    case tok::kw_volatile:
      isInvalid = DS.SetTypeQual(DeclSpec::TQ_volatile, Loc, PrevSpec, DiagID,
                                 getLang());
      break;
    case tok::kw_restrict:
      isInvalid = DS.SetTypeQual(DeclSpec::TQ_restrict, Loc, PrevSpec, DiagID,
                                 getLang());
      break;

    // C++ typename-specifier:
    case tok::kw_typename:
      if (TryAnnotateTypeOrScopeToken()) {
        DS.SetTypeSpecError();
        goto DoneWithDeclSpec;
      }
      if (!Tok.is(tok::kw_typename))
        continue;
      break;

    // GNU typeof support.
    case tok::kw_typeof:
      ParseTypeofSpecifier(DS);
      continue;

    case tok::kw_decltype:
      ParseDecltypeSpecifier(DS);
      continue;

    case tok::less:
      // GCC ObjC supports types like "<SomeProtocol>" as a synonym for
      // "id<SomeProtocol>".  This is hopelessly old fashioned and dangerous,
      // but we support it.
      if (DS.hasTypeSpecifier() || !getLang().ObjC1)
        goto DoneWithDeclSpec;

      {
        SourceLocation LAngleLoc, EndProtoLoc;
        llvm::SmallVector<DeclPtrTy, 8> ProtocolDecl;
        llvm::SmallVector<SourceLocation, 8> ProtocolLocs;
        ParseObjCProtocolReferences(ProtocolDecl, ProtocolLocs, false,
                                    LAngleLoc, EndProtoLoc);
        DS.setProtocolQualifiers(ProtocolDecl.data(), ProtocolDecl.size(),
                                 ProtocolLocs.data(), LAngleLoc);
        DS.SetRangeEnd(EndProtoLoc);

        Diag(Loc, diag::warn_objc_protocol_qualifier_missing_id)
          << CodeModificationHint::CreateInsertion(Loc, "id")
          << SourceRange(Loc, EndProtoLoc);
        // Need to support trailing type qualifiers (e.g. "id<p> const").
        // If a type specifier follows, it will be diagnosed elsewhere.
        continue;
      }
    }
    // If the specifier wasn't legal, issue a diagnostic.
    if (isInvalid) {
      assert(PrevSpec && "Method did not return previous specifier!");
      assert(DiagID);
      Diag(Tok, DiagID) << PrevSpec;
    }
    DS.SetRangeEnd(Tok.getLocation());
    ConsumeToken();
  }
}

/// ParseOptionalTypeSpecifier - Try to parse a single type-specifier. We
/// primarily follow the C++ grammar with additions for C99 and GNU,
/// which together subsume the C grammar. Note that the C++
/// type-specifier also includes the C type-qualifier (for const,
/// volatile, and C99 restrict). Returns true if a type-specifier was
/// found (and parsed), false otherwise.
///
///       type-specifier: [C++ 7.1.5]
///         simple-type-specifier
///         class-specifier
///         enum-specifier
///         elaborated-type-specifier  [TODO]
///         cv-qualifier
///
///       cv-qualifier: [C++ 7.1.5.1]
///         'const'
///         'volatile'
/// [C99]   'restrict'
///
///       simple-type-specifier: [ C++ 7.1.5.2]
///         '::'[opt] nested-name-specifier[opt] type-name [TODO]
///         '::'[opt] nested-name-specifier 'template' template-id [TODO]
///         'char'
///         'wchar_t'
///         'bool'
///         'short'
///         'int'
///         'long'
///         'signed'
///         'unsigned'
///         'float'
///         'double'
///         'void'
/// [C99]   '_Bool'
/// [C99]   '_Complex'
/// [C99]   '_Imaginary'  // Removed in TC2?
/// [GNU]   '_Decimal32'
/// [GNU]   '_Decimal64'
/// [GNU]   '_Decimal128'
/// [GNU]   typeof-specifier
/// [OBJC]  class-name objc-protocol-refs[opt]    [TODO]
/// [OBJC]  typedef-name objc-protocol-refs[opt]  [TODO]
/// [C++0x] 'decltype' ( expression )
/// [AltiVec] '__vector'
bool Parser::ParseOptionalTypeSpecifier(DeclSpec &DS, bool& isInvalid,
                                        const char *&PrevSpec,
                                        unsigned &DiagID,
                                        const ParsedTemplateInfo &TemplateInfo,
                                        bool SuppressDeclarations) {
  SourceLocation Loc = Tok.getLocation();

  switch (Tok.getKind()) {
  case tok::identifier:   // foo::bar
    // Check for need to substitute AltiVec keyword tokens.
    if (TryAltiVecToken(DS, Loc, PrevSpec, DiagID, isInvalid))
      break;
    // Fall through.
  case tok::kw_typename:  // typename foo::bar
    // Annotate typenames and C++ scope specifiers.  If we get one, just
    // recurse to handle whatever we get.
    if (TryAnnotateTypeOrScopeToken())
      return true;
    if (Tok.is(tok::identifier))
      return false;
    return ParseOptionalTypeSpecifier(DS, isInvalid, PrevSpec, DiagID,
                                      TemplateInfo, SuppressDeclarations);
  case tok::coloncolon:   // ::foo::bar
    if (NextToken().is(tok::kw_new) ||    // ::new
        NextToken().is(tok::kw_delete))   // ::delete
      return false;

    // Annotate typenames and C++ scope specifiers.  If we get one, just
    // recurse to handle whatever we get.
    if (TryAnnotateTypeOrScopeToken())
      return true;
    return ParseOptionalTypeSpecifier(DS, isInvalid, PrevSpec, DiagID,
                                      TemplateInfo, SuppressDeclarations);

  // simple-type-specifier:
  case tok::annot_typename: {
    if (Tok.getAnnotationValue())
      isInvalid = DS.SetTypeSpecType(DeclSpec::TST_typename, Loc, PrevSpec,
                                     DiagID, Tok.getAnnotationValue());
    else
      DS.SetTypeSpecError();
    DS.SetRangeEnd(Tok.getAnnotationEndLoc());
    ConsumeToken(); // The typename

    // Objective-C supports syntax of the form 'id<proto1,proto2>' where 'id'
    // is a specific typedef and 'itf<proto1,proto2>' where 'itf' is an
    // Objective-C interface.  If we don't have Objective-C or a '<', this is
    // just a normal reference to a typedef name.
    if (!Tok.is(tok::less) || !getLang().ObjC1)
      return true;

    SourceLocation LAngleLoc, EndProtoLoc;
    llvm::SmallVector<DeclPtrTy, 8> ProtocolDecl;
    llvm::SmallVector<SourceLocation, 8> ProtocolLocs;
    ParseObjCProtocolReferences(ProtocolDecl, ProtocolLocs, false,
                                LAngleLoc, EndProtoLoc);
    DS.setProtocolQualifiers(ProtocolDecl.data(), ProtocolDecl.size(),
                             ProtocolLocs.data(), LAngleLoc);

    DS.SetRangeEnd(EndProtoLoc);
    return true;
  }

  case tok::kw_short:
    isInvalid = DS.SetTypeSpecWidth(DeclSpec::TSW_short, Loc, PrevSpec, DiagID);
    break;
  case tok::kw_long:
    if (DS.getTypeSpecWidth() != DeclSpec::TSW_long)
      isInvalid = DS.SetTypeSpecWidth(DeclSpec::TSW_long, Loc, PrevSpec,
                                      DiagID);
    else
      isInvalid = DS.SetTypeSpecWidth(DeclSpec::TSW_longlong, Loc, PrevSpec,
                                      DiagID);
    break;
  case tok::kw_signed:
    isInvalid = DS.SetTypeSpecSign(DeclSpec::TSS_signed, Loc, PrevSpec, DiagID);
    break;
  case tok::kw_unsigned:
    isInvalid = DS.SetTypeSpecSign(DeclSpec::TSS_unsigned, Loc, PrevSpec,
                                   DiagID);
    break;
  case tok::kw__Complex:
    isInvalid = DS.SetTypeSpecComplex(DeclSpec::TSC_complex, Loc, PrevSpec,
                                      DiagID);
    break;
  case tok::kw__Imaginary:
    isInvalid = DS.SetTypeSpecComplex(DeclSpec::TSC_imaginary, Loc, PrevSpec,
                                      DiagID);
    break;
  case tok::kw_void:
    isInvalid = DS.SetTypeSpecType(DeclSpec::TST_void, Loc, PrevSpec, DiagID);
    break;
  case tok::kw_char:
    isInvalid = DS.SetTypeSpecType(DeclSpec::TST_char, Loc, PrevSpec, DiagID);
    break;
  case tok::kw_int:
    isInvalid = DS.SetTypeSpecType(DeclSpec::TST_int, Loc, PrevSpec, DiagID);
    break;
  case tok::kw_float:
    isInvalid = DS.SetTypeSpecType(DeclSpec::TST_float, Loc, PrevSpec, DiagID);
    break;
  case tok::kw_double:
    isInvalid = DS.SetTypeSpecType(DeclSpec::TST_double, Loc, PrevSpec, DiagID);
    break;
  case tok::kw_wchar_t:
    isInvalid = DS.SetTypeSpecType(DeclSpec::TST_wchar, Loc, PrevSpec, DiagID);
    break;
  case tok::kw_char16_t:
    isInvalid = DS.SetTypeSpecType(DeclSpec::TST_char16, Loc, PrevSpec, DiagID);
    break;
  case tok::kw_char32_t:
    isInvalid = DS.SetTypeSpecType(DeclSpec::TST_char32, Loc, PrevSpec, DiagID);
    break;
  case tok::kw_bool:
  case tok::kw__Bool:
    isInvalid = DS.SetTypeSpecType(DeclSpec::TST_bool, Loc, PrevSpec, DiagID);
    break;
  case tok::kw__Decimal32:
    isInvalid = DS.SetTypeSpecType(DeclSpec::TST_decimal32, Loc, PrevSpec,
                                   DiagID);
    break;
  case tok::kw__Decimal64:
    isInvalid = DS.SetTypeSpecType(DeclSpec::TST_decimal64, Loc, PrevSpec,
                                   DiagID);
    break;
  case tok::kw__Decimal128:
    isInvalid = DS.SetTypeSpecType(DeclSpec::TST_decimal128, Loc, PrevSpec,
                                   DiagID);
    break;
  case tok::kw___vector:
    isInvalid = DS.SetTypeAltiVecVector(true, Loc, PrevSpec, DiagID);
    break;
  case tok::kw___pixel:
    isInvalid = DS.SetTypeAltiVecPixel(true, Loc, PrevSpec, DiagID);
    break;
  
  // class-specifier:
  case tok::kw_class:
  case tok::kw_struct:
  case tok::kw_union: {
    tok::TokenKind Kind = Tok.getKind();
    ConsumeToken();
    ParseClassSpecifier(Kind, Loc, DS, TemplateInfo, AS_none,
                        SuppressDeclarations);
    return true;
  }

  // enum-specifier:
  case tok::kw_enum:
    ConsumeToken();
    ParseEnumSpecifier(Loc, DS, TemplateInfo, AS_none);
    return true;

  // cv-qualifier:
  case tok::kw_const:
    isInvalid = DS.SetTypeQual(DeclSpec::TQ_const   , Loc, PrevSpec,
                               DiagID, getLang());
    break;
  case tok::kw_volatile:
    isInvalid = DS.SetTypeQual(DeclSpec::TQ_volatile, Loc, PrevSpec,
                               DiagID, getLang());
    break;
  case tok::kw_restrict:
    isInvalid = DS.SetTypeQual(DeclSpec::TQ_restrict, Loc, PrevSpec,
                               DiagID, getLang());
    break;

  // GNU typeof support.
  case tok::kw_typeof:
    ParseTypeofSpecifier(DS);
    return true;

  // C++0x decltype support.
  case tok::kw_decltype:
    ParseDecltypeSpecifier(DS);
    return true;

  // C++0x auto support.
  case tok::kw_auto:
    if (!getLang().CPlusPlus0x)
      return false;

    isInvalid = DS.SetTypeSpecType(DeclSpec::TST_auto, Loc, PrevSpec, DiagID);
    break;
  case tok::kw___ptr64:
  case tok::kw___w64:
  case tok::kw___cdecl:
  case tok::kw___stdcall:
  case tok::kw___fastcall:
    DS.AddAttributes(ParseMicrosoftTypeAttributes());
    return true;

  default:
    // Not a type-specifier; do nothing.
    return false;
  }

  // If the specifier combination wasn't legal, issue a diagnostic.
  if (isInvalid) {
    assert(PrevSpec && "Method did not return previous specifier!");
    // Pick between error or extwarn.
    Diag(Tok, DiagID) << PrevSpec;
  }
  DS.SetRangeEnd(Tok.getLocation());
  ConsumeToken(); // whatever we parsed above.
  return true;
}

/// ParseStructDeclaration - Parse a struct declaration without the terminating
/// semicolon.
///
///       struct-declaration:
///         specifier-qualifier-list struct-declarator-list
/// [GNU]   __extension__ struct-declaration
/// [GNU]   specifier-qualifier-list
///       struct-declarator-list:
///         struct-declarator
///         struct-declarator-list ',' struct-declarator
/// [GNU]   struct-declarator-list ',' attributes[opt] struct-declarator
///       struct-declarator:
///         declarator
/// [GNU]   declarator attributes[opt]
///         declarator[opt] ':' constant-expression
/// [GNU]   declarator[opt] ':' constant-expression attributes[opt]
///
void Parser::
ParseStructDeclaration(DeclSpec &DS, FieldCallback &Fields) {
  if (Tok.is(tok::kw___extension__)) {
    // __extension__ silences extension warnings in the subexpression.
    ExtensionRAIIObject O(Diags);  // Use RAII to do this.
    ConsumeToken();
    return ParseStructDeclaration(DS, Fields);
  }

  // Parse the common specifier-qualifiers-list piece.
  SourceLocation DSStart = Tok.getLocation();
  ParseSpecifierQualifierList(DS);

  // If there are no declarators, this is a free-standing declaration
  // specifier. Let the actions module cope with it.
  if (Tok.is(tok::semi)) {
    Actions.ParsedFreeStandingDeclSpec(CurScope, DS);
    return;
  }

  // Read struct-declarators until we find the semicolon.
  bool FirstDeclarator = true;
  while (1) {
    ParsingDeclRAIIObject PD(*this);
    FieldDeclarator DeclaratorInfo(DS);

    // Attributes are only allowed here on successive declarators.
    if (!FirstDeclarator && Tok.is(tok::kw___attribute)) {
      SourceLocation Loc;
      AttributeList *AttrList = ParseGNUAttributes(&Loc);
      DeclaratorInfo.D.AddAttributes(AttrList, Loc);
    }

    /// struct-declarator: declarator
    /// struct-declarator: declarator[opt] ':' constant-expression
    if (Tok.isNot(tok::colon)) {
      // Don't parse FOO:BAR as if it were a typo for FOO::BAR.
      ColonProtectionRAIIObject X(*this);
      ParseDeclarator(DeclaratorInfo.D);
    }

    if (Tok.is(tok::colon)) {
      ConsumeToken();
      OwningExprResult Res(ParseConstantExpression());
      if (Res.isInvalid())
        SkipUntil(tok::semi, true, true);
      else
        DeclaratorInfo.BitfieldSize = Res.release();
    }

    // If attributes exist after the declarator, parse them.
    if (Tok.is(tok::kw___attribute)) {
      SourceLocation Loc;
      AttributeList *AttrList = ParseGNUAttributes(&Loc);
      DeclaratorInfo.D.AddAttributes(AttrList, Loc);
    }

    // We're done with this declarator;  invoke the callback.
    DeclPtrTy D = Fields.invoke(DeclaratorInfo);
    PD.complete(D);

    // If we don't have a comma, it is either the end of the list (a ';')
    // or an error, bail out.
    if (Tok.isNot(tok::comma))
      return;

    // Consume the comma.
    ConsumeToken();

    FirstDeclarator = false;
  }
}

/// ParseStructUnionBody
///       struct-contents:
///         struct-declaration-list
/// [EXT]   empty
/// [GNU]   "struct-declaration-list" without terminatoring ';'
///       struct-declaration-list:
///         struct-declaration
///         struct-declaration-list struct-declaration
/// [OBC]   '@' 'defs' '(' class-name ')'
///
void Parser::ParseStructUnionBody(SourceLocation RecordLoc,
                                  unsigned TagType, DeclPtrTy TagDecl) {
  PrettyStackTraceActionsDecl CrashInfo(TagDecl, RecordLoc, Actions,
                                        PP.getSourceManager(),
                                        "parsing struct/union body");

  SourceLocation LBraceLoc = ConsumeBrace();

  ParseScope StructScope(this, Scope::ClassScope|Scope::DeclScope);
  Actions.ActOnTagStartDefinition(CurScope, TagDecl);

  // Empty structs are an extension in C (C99 6.7.2.1p7), but are allowed in
  // C++.
  if (Tok.is(tok::r_brace) && !getLang().CPlusPlus)
    Diag(Tok, diag::ext_empty_struct_union_enum)
      << DeclSpec::getSpecifierName((DeclSpec::TST)TagType);

  llvm::SmallVector<DeclPtrTy, 32> FieldDecls;

  // While we still have something to read, read the declarations in the struct.
  while (Tok.isNot(tok::r_brace) && Tok.isNot(tok::eof)) {
    // Each iteration of this loop reads one struct-declaration.

    // Check for extraneous top-level semicolon.
    if (Tok.is(tok::semi)) {
      Diag(Tok, diag::ext_extra_struct_semi)
        << CodeModificationHint::CreateRemoval(Tok.getLocation());
      ConsumeToken();
      continue;
    }

    // Parse all the comma separated declarators.
    DeclSpec DS;

    if (!Tok.is(tok::at)) {
      struct CFieldCallback : FieldCallback {
        Parser &P;
        DeclPtrTy TagDecl;
        llvm::SmallVectorImpl<DeclPtrTy> &FieldDecls;

        CFieldCallback(Parser &P, DeclPtrTy TagDecl,
                       llvm::SmallVectorImpl<DeclPtrTy> &FieldDecls) :
          P(P), TagDecl(TagDecl), FieldDecls(FieldDecls) {}

        virtual DeclPtrTy invoke(FieldDeclarator &FD) {
          // Install the declarator into the current TagDecl.
          DeclPtrTy Field = P.Actions.ActOnField(P.CurScope, TagDecl,
                              FD.D.getDeclSpec().getSourceRange().getBegin(),
                                                 FD.D, FD.BitfieldSize);
          FieldDecls.push_back(Field);
          return Field;
        }
      } Callback(*this, TagDecl, FieldDecls);

      ParseStructDeclaration(DS, Callback);
    } else { // Handle @defs
      ConsumeToken();
      if (!Tok.isObjCAtKeyword(tok::objc_defs)) {
        Diag(Tok, diag::err_unexpected_at);
        SkipUntil(tok::semi, true);
        continue;
      }
      ConsumeToken();
      ExpectAndConsume(tok::l_paren, diag::err_expected_lparen);
      if (!Tok.is(tok::identifier)) {
        Diag(Tok, diag::err_expected_ident);
        SkipUntil(tok::semi, true);
        continue;
      }
      llvm::SmallVector<DeclPtrTy, 16> Fields;
      Actions.ActOnDefs(CurScope, TagDecl, Tok.getLocation(),
                        Tok.getIdentifierInfo(), Fields);
      FieldDecls.insert(FieldDecls.end(), Fields.begin(), Fields.end());
      ConsumeToken();
      ExpectAndConsume(tok::r_paren, diag::err_expected_rparen);
    }

    if (Tok.is(tok::semi)) {
      ConsumeToken();
    } else if (Tok.is(tok::r_brace)) {
      ExpectAndConsume(tok::semi, diag::ext_expected_semi_decl_list);
      break;
    } else {
      ExpectAndConsume(tok::semi, diag::err_expected_semi_decl_list);
      // Skip to end of block or statement to avoid ext-warning on extra ';'.
      SkipUntil(tok::r_brace, true, true);
      // If we stopped at a ';', eat it.
      if (Tok.is(tok::semi)) ConsumeToken();
    }
  }

  SourceLocation RBraceLoc = MatchRHSPunctuation(tok::r_brace, LBraceLoc);

  llvm::OwningPtr<AttributeList> AttrList;
  // If attributes exist after struct contents, parse them.
  if (Tok.is(tok::kw___attribute))
    AttrList.reset(ParseGNUAttributes());

  Actions.ActOnFields(CurScope,
                      RecordLoc, TagDecl, FieldDecls.data(), FieldDecls.size(),
                      LBraceLoc, RBraceLoc,
                      AttrList.get());
  StructScope.Exit();
  Actions.ActOnTagFinishDefinition(CurScope, TagDecl, RBraceLoc);
}


/// ParseEnumSpecifier
///       enum-specifier: [C99 6.7.2.2]
///         'enum' identifier[opt] '{' enumerator-list '}'
///[C99/C++]'enum' identifier[opt] '{' enumerator-list ',' '}'
/// [GNU]   'enum' attributes[opt] identifier[opt] '{' enumerator-list ',' [opt]
///                                                 '}' attributes[opt]
///         'enum' identifier
/// [GNU]   'enum' attributes[opt] identifier
///
/// [C++] elaborated-type-specifier:
/// [C++]   'enum' '::'[opt] nested-name-specifier[opt] identifier
///
void Parser::ParseEnumSpecifier(SourceLocation StartLoc, DeclSpec &DS,
                                const ParsedTemplateInfo &TemplateInfo,
                                AccessSpecifier AS) {
  // Parse the tag portion of this.
  if (Tok.is(tok::code_completion)) {
    // Code completion for an enum name.
    Actions.CodeCompleteTag(CurScope, DeclSpec::TST_enum);
    ConsumeToken();
  }
  
  llvm::OwningPtr<AttributeList> Attr;
  // If attributes exist after tag, parse them.
  if (Tok.is(tok::kw___attribute))
    Attr.reset(ParseGNUAttributes());

  CXXScopeSpec SS;
  if (getLang().CPlusPlus) {
    if (ParseOptionalCXXScopeSpecifier(SS, 0, false))
      return;

    if (SS.isSet() && Tok.isNot(tok::identifier)) {
      Diag(Tok, diag::err_expected_ident);
      if (Tok.isNot(tok::l_brace)) {
        // Has no name and is not a definition.
        // Skip the rest of this declarator, up until the comma or semicolon.
        SkipUntil(tok::comma, true);
        return;
      }
    }
  }

  // Must have either 'enum name' or 'enum {...}'.
  if (Tok.isNot(tok::identifier) && Tok.isNot(tok::l_brace)) {
    Diag(Tok, diag::err_expected_ident_lbrace);

    // Skip the rest of this declarator, up until the comma or semicolon.
    SkipUntil(tok::comma, true);
    return;
  }

  // enums cannot be templates.
  if (TemplateInfo.Kind != ParsedTemplateInfo::NonTemplate) {
    Diag(Tok, diag::err_enum_template);

    // Skip the rest of this declarator, up until the comma or semicolon.
    SkipUntil(tok::comma, true);
    return;      
  }

  // If an identifier is present, consume and remember it.
  IdentifierInfo *Name = 0;
  SourceLocation NameLoc;
  if (Tok.is(tok::identifier)) {
    Name = Tok.getIdentifierInfo();
    NameLoc = ConsumeToken();
  }

  // There are three options here.  If we have 'enum foo;', then this is a
  // forward declaration.  If we have 'enum foo {...' then this is a
  // definition. Otherwise we have something like 'enum foo xyz', a reference.
  //
  // This is needed to handle stuff like this right (C99 6.7.2.3p11):
  // enum foo {..};  void bar() { enum foo; }    <- new foo in bar.
  // enum foo {..};  void bar() { enum foo x; }  <- use of old foo.
  //
  Action::TagUseKind TUK;
  if (Tok.is(tok::l_brace))
    TUK = Action::TUK_Definition;
  else if (Tok.is(tok::semi))
    TUK = Action::TUK_Declaration;
  else
    TUK = Action::TUK_Reference;
  bool Owned = false;
  bool IsDependent = false;
  DeclPtrTy TagDecl = Actions.ActOnTag(CurScope, DeclSpec::TST_enum, TUK,
                                       StartLoc, SS, Name, NameLoc, Attr.get(),
                                       AS,
                                       Action::MultiTemplateParamsArg(Actions),
                                       Owned, IsDependent);
  assert(!IsDependent && "didn't expect dependent enum");

  if (Tok.is(tok::l_brace))
    ParseEnumBody(StartLoc, TagDecl);

  // FIXME: The DeclSpec should keep the locations of both the keyword and the
  // name (if there is one).
  SourceLocation TSTLoc = NameLoc.isValid()? NameLoc : StartLoc;
  const char *PrevSpec = 0;
  unsigned DiagID;
  if (DS.SetTypeSpecType(DeclSpec::TST_enum, TSTLoc, PrevSpec, DiagID,
                         TagDecl.getAs<void>(), Owned))
    Diag(StartLoc, DiagID) << PrevSpec;
}

/// ParseEnumBody - Parse a {} enclosed enumerator-list.
///       enumerator-list:
///         enumerator
///         enumerator-list ',' enumerator
///       enumerator:
///         enumeration-constant
///         enumeration-constant '=' constant-expression
///       enumeration-constant:
///         identifier
///
void Parser::ParseEnumBody(SourceLocation StartLoc, DeclPtrTy EnumDecl) {
  // Enter the scope of the enum body and start the definition.
  ParseScope EnumScope(this, Scope::DeclScope);
  Actions.ActOnTagStartDefinition(CurScope, EnumDecl);

  SourceLocation LBraceLoc = ConsumeBrace();

  // C does not allow an empty enumerator-list, C++ does [dcl.enum].
  if (Tok.is(tok::r_brace) && !getLang().CPlusPlus)
    Diag(Tok, diag::ext_empty_struct_union_enum) << "enum";

  llvm::SmallVector<DeclPtrTy, 32> EnumConstantDecls;

  DeclPtrTy LastEnumConstDecl;

  // Parse the enumerator-list.
  while (Tok.is(tok::identifier)) {
    IdentifierInfo *Ident = Tok.getIdentifierInfo();
    SourceLocation IdentLoc = ConsumeToken();

    SourceLocation EqualLoc;
    OwningExprResult AssignedVal(Actions);
    if (Tok.is(tok::equal)) {
      EqualLoc = ConsumeToken();
      AssignedVal = ParseConstantExpression();
      if (AssignedVal.isInvalid())
        SkipUntil(tok::comma, tok::r_brace, true, true);
    }

    // Install the enumerator constant into EnumDecl.
    DeclPtrTy EnumConstDecl = Actions.ActOnEnumConstant(CurScope, EnumDecl,
                                                        LastEnumConstDecl,
                                                        IdentLoc, Ident,
                                                        EqualLoc,
                                                        AssignedVal.release());
    EnumConstantDecls.push_back(EnumConstDecl);
    LastEnumConstDecl = EnumConstDecl;

    if (Tok.isNot(tok::comma))
      break;
    SourceLocation CommaLoc = ConsumeToken();

    if (Tok.isNot(tok::identifier) &&
        !(getLang().C99 || getLang().CPlusPlus0x))
      Diag(CommaLoc, diag::ext_enumerator_list_comma)
        << getLang().CPlusPlus
        << CodeModificationHint::CreateRemoval(CommaLoc);
  }

  // Eat the }.
  SourceLocation RBraceLoc = MatchRHSPunctuation(tok::r_brace, LBraceLoc);

  llvm::OwningPtr<AttributeList> Attr;
  // If attributes exist after the identifier list, parse them.
  if (Tok.is(tok::kw___attribute))
    Attr.reset(ParseGNUAttributes()); // FIXME: where do they do?

  Actions.ActOnEnumBody(StartLoc, LBraceLoc, RBraceLoc, EnumDecl,
                        EnumConstantDecls.data(), EnumConstantDecls.size(),
                        CurScope, Attr.get());

  EnumScope.Exit();
  Actions.ActOnTagFinishDefinition(CurScope, EnumDecl, RBraceLoc);
}

/// isTypeSpecifierQualifier - Return true if the current token could be the
/// start of a type-qualifier-list.
bool Parser::isTypeQualifier() const {
  switch (Tok.getKind()) {
  default: return false;
    // type-qualifier
  case tok::kw_const:
  case tok::kw_volatile:
  case tok::kw_restrict:
    return true;
  }
}

/// isKnownToBeTypeSpecifier - Return true if we know that the specified token
/// is definitely a type-specifier.  Return false if it isn't part of a type
/// specifier or if we're not sure.
bool Parser::isKnownToBeTypeSpecifier(const Token &Tok) const {
  switch (Tok.getKind()) {
  default: return false;
    // type-specifiers
  case tok::kw_short:
  case tok::kw_long:
  case tok::kw_signed:
  case tok::kw_unsigned:
  case tok::kw__Complex:
  case tok::kw__Imaginary:
  case tok::kw_void:
  case tok::kw_char:
  case tok::kw_wchar_t:
  case tok::kw_char16_t:
  case tok::kw_char32_t:
  case tok::kw_int:
  case tok::kw_float:
  case tok::kw_double:
  case tok::kw_bool:
  case tok::kw__Bool:
  case tok::kw__Decimal32:
  case tok::kw__Decimal64:
  case tok::kw__Decimal128:
  case tok::kw___vector:
    
    // struct-or-union-specifier (C99) or class-specifier (C++)
  case tok::kw_class:
  case tok::kw_struct:
  case tok::kw_union:
    // enum-specifier
  case tok::kw_enum:
    
    // typedef-name
  case tok::annot_typename:
    return true;
  }
}

/// isTypeSpecifierQualifier - Return true if the current token could be the
/// start of a specifier-qualifier-list.
bool Parser::isTypeSpecifierQualifier() {
  switch (Tok.getKind()) {
  default: return false;

  case tok::identifier:   // foo::bar
    if (TryAltiVecVectorToken())
      return true;
    // Fall through.
  case tok::kw_typename:  // typename T::type
    // Annotate typenames and C++ scope specifiers.  If we get one, just
    // recurse to handle whatever we get.
    if (TryAnnotateTypeOrScopeToken())
      return true;
    if (Tok.is(tok::identifier))
      return false;
    return isTypeSpecifierQualifier();

  case tok::coloncolon:   // ::foo::bar
    if (NextToken().is(tok::kw_new) ||    // ::new
        NextToken().is(tok::kw_delete))   // ::delete
      return false;

    if (TryAnnotateTypeOrScopeToken())
      return true;
    return isTypeSpecifierQualifier();

    // GNU attributes support.
  case tok::kw___attribute:
    // GNU typeof support.
  case tok::kw_typeof:

    // type-specifiers
  case tok::kw_short:
  case tok::kw_long:
  case tok::kw_signed:
  case tok::kw_unsigned:
  case tok::kw__Complex:
  case tok::kw__Imaginary:
  case tok::kw_void:
  case tok::kw_char:
  case tok::kw_wchar_t:
  case tok::kw_char16_t:
  case tok::kw_char32_t:
  case tok::kw_int:
  case tok::kw_float:
  case tok::kw_double:
  case tok::kw_bool:
  case tok::kw__Bool:
  case tok::kw__Decimal32:
  case tok::kw__Decimal64:
  case tok::kw__Decimal128:
  case tok::kw___vector:

    // struct-or-union-specifier (C99) or class-specifier (C++)
  case tok::kw_class:
  case tok::kw_struct:
  case tok::kw_union:
    // enum-specifier
  case tok::kw_enum:

    // type-qualifier
  case tok::kw_const:
  case tok::kw_volatile:
  case tok::kw_restrict:

    // typedef-name
  case tok::annot_typename:
    return true;

    // GNU ObjC bizarre protocol extension: <proto1,proto2> with implicit 'id'.
  case tok::less:
    return getLang().ObjC1;

  case tok::kw___cdecl:
  case tok::kw___stdcall:
  case tok::kw___fastcall:
  case tok::kw___w64:
  case tok::kw___ptr64:
    return true;
  }
}

/// isDeclarationSpecifier() - Return true if the current token is part of a
/// declaration specifier.
bool Parser::isDeclarationSpecifier() {
  switch (Tok.getKind()) {
  default: return false;

  case tok::identifier:   // foo::bar
    // Unfortunate hack to support "Class.factoryMethod" notation.
    if (getLang().ObjC1 && NextToken().is(tok::period))
      return false;
    if (TryAltiVecVectorToken())
      return true;
    // Fall through.
  case tok::kw_typename: // typename T::type
    // Annotate typenames and C++ scope specifiers.  If we get one, just
    // recurse to handle whatever we get.
    if (TryAnnotateTypeOrScopeToken())
      return true;
    if (Tok.is(tok::identifier))
      return false;
    return isDeclarationSpecifier();

  case tok::coloncolon:   // ::foo::bar
    if (NextToken().is(tok::kw_new) ||    // ::new
        NextToken().is(tok::kw_delete))   // ::delete
      return false;

    // Annotate typenames and C++ scope specifiers.  If we get one, just
    // recurse to handle whatever we get.
    if (TryAnnotateTypeOrScopeToken())
      return true;
    return isDeclarationSpecifier();

    // storage-class-specifier
  case tok::kw_typedef:
  case tok::kw_extern:
  case tok::kw___private_extern__:
  case tok::kw_static:
  case tok::kw_auto:
  case tok::kw_register:
  case tok::kw___thread:

    // type-specifiers
  case tok::kw_short:
  case tok::kw_long:
  case tok::kw_signed:
  case tok::kw_unsigned:
  case tok::kw__Complex:
  case tok::kw__Imaginary:
  case tok::kw_void:
  case tok::kw_char:
  case tok::kw_wchar_t:
  case tok::kw_char16_t:
  case tok::kw_char32_t:

  case tok::kw_int:
  case tok::kw_float:
  case tok::kw_double:
  case tok::kw_bool:
  case tok::kw__Bool:
  case tok::kw__Decimal32:
  case tok::kw__Decimal64:
  case tok::kw__Decimal128:
  case tok::kw___vector:

    // struct-or-union-specifier (C99) or class-specifier (C++)
  case tok::kw_class:
  case tok::kw_struct:
  case tok::kw_union:
    // enum-specifier
  case tok::kw_enum:

    // type-qualifier
  case tok::kw_const:
  case tok::kw_volatile:
  case tok::kw_restrict:

    // function-specifier
  case tok::kw_inline:
  case tok::kw_virtual:
  case tok::kw_explicit:

    // typedef-name
  case tok::annot_typename:

    // GNU typeof support.
  case tok::kw_typeof:

    // GNU attributes.
  case tok::kw___attribute:
    return true;

    // GNU ObjC bizarre protocol extension: <proto1,proto2> with implicit 'id'.
  case tok::less:
    return getLang().ObjC1;

  case tok::kw___declspec:
  case tok::kw___cdecl:
  case tok::kw___stdcall:
  case tok::kw___fastcall:
  case tok::kw___w64:
  case tok::kw___ptr64:
  case tok::kw___forceinline:
    return true;
  }
}

bool Parser::isConstructorDeclarator() {
  TentativeParsingAction TPA(*this);

  // Parse the C++ scope specifier.
  CXXScopeSpec SS;
  if (ParseOptionalCXXScopeSpecifier(SS, 0, true)) {
    TPA.Revert();
    return false;
  }

  // Parse the constructor name.
  if (Tok.is(tok::identifier) || Tok.is(tok::annot_template_id)) {
    // We already know that we have a constructor name; just consume
    // the token.
    ConsumeToken();
  } else {
    TPA.Revert();
    return false;
  }

  // Current class name must be followed by a left parentheses.
  if (Tok.isNot(tok::l_paren)) {
    TPA.Revert();
    return false;
  }
  ConsumeParen();

  // A right parentheses or ellipsis signals that we have a constructor.
  if (Tok.is(tok::r_paren) || Tok.is(tok::ellipsis)) {
    TPA.Revert();
    return true;
  }

  // If we need to, enter the specified scope.
  DeclaratorScopeObj DeclScopeObj(*this, SS);
  if (SS.isSet() && Actions.ShouldEnterDeclaratorScope(CurScope, SS))
    DeclScopeObj.EnterDeclaratorScope();

  // Check whether the next token(s) are part of a declaration
  // specifier, in which case we have the start of a parameter and,
  // therefore, we know that this is a constructor.
  bool IsConstructor = isDeclarationSpecifier();
  TPA.Revert();
  return IsConstructor;
}

/// ParseTypeQualifierListOpt
///       type-qualifier-list: [C99 6.7.5]
///         type-qualifier
/// [GNU]   attributes                        [ only if AttributesAllowed=true ]
///         type-qualifier-list type-qualifier
/// [GNU]   type-qualifier-list attributes    [ only if AttributesAllowed=true ]
/// [C++0x] attribute-specifier[opt] is allowed before cv-qualifier-seq
///           if CXX0XAttributesAllowed = true
///
void Parser::ParseTypeQualifierListOpt(DeclSpec &DS, bool GNUAttributesAllowed,
                                       bool CXX0XAttributesAllowed) {
  if (getLang().CPlusPlus0x && isCXX0XAttributeSpecifier()) {
    SourceLocation Loc = Tok.getLocation();
    CXX0XAttributeList Attr = ParseCXX0XAttributes();
    if (CXX0XAttributesAllowed)
      DS.AddAttributes(Attr.AttrList);
    else
      Diag(Loc, diag::err_attributes_not_allowed);
  }
  
  while (1) {
    bool isInvalid = false;
    const char *PrevSpec = 0;
    unsigned DiagID = 0;
    SourceLocation Loc = Tok.getLocation();

    switch (Tok.getKind()) {
    case tok::kw_const:
      isInvalid = DS.SetTypeQual(DeclSpec::TQ_const   , Loc, PrevSpec, DiagID,
                                 getLang());
      break;
    case tok::kw_volatile:
      isInvalid = DS.SetTypeQual(DeclSpec::TQ_volatile, Loc, PrevSpec, DiagID,
                                 getLang());
      break;
    case tok::kw_restrict:
      isInvalid = DS.SetTypeQual(DeclSpec::TQ_restrict, Loc, PrevSpec, DiagID,
                                 getLang());
      break;
    case tok::kw___w64:
    case tok::kw___ptr64:
    case tok::kw___cdecl:
    case tok::kw___stdcall:
    case tok::kw___fastcall:
      if (GNUAttributesAllowed) {
        DS.AddAttributes(ParseMicrosoftTypeAttributes());
        continue;
      }
      goto DoneWithTypeQuals;
    case tok::kw___attribute:
      if (GNUAttributesAllowed) {
        DS.AddAttributes(ParseGNUAttributes());
        continue; // do *not* consume the next token!
      }
      // otherwise, FALL THROUGH!
    default:
      DoneWithTypeQuals:
      // If this is not a type-qualifier token, we're done reading type
      // qualifiers.  First verify that DeclSpec's are consistent.
      DS.Finish(Diags, PP);
      return;
    }

    // If the specifier combination wasn't legal, issue a diagnostic.
    if (isInvalid) {
      assert(PrevSpec && "Method did not return previous specifier!");
      Diag(Tok, DiagID) << PrevSpec;
    }
    ConsumeToken();
  }
}


/// ParseDeclarator - Parse and verify a newly-initialized declarator.
///
void Parser::ParseDeclarator(Declarator &D) {
  /// This implements the 'declarator' production in the C grammar, then checks
  /// for well-formedness and issues diagnostics.
  ParseDeclaratorInternal(D, &Parser::ParseDirectDeclarator);
}

/// ParseDeclaratorInternal - Parse a C or C++ declarator. The direct-declarator
/// is parsed by the function passed to it. Pass null, and the direct-declarator
/// isn't parsed at all, making this function effectively parse the C++
/// ptr-operator production.
///
///       declarator: [C99 6.7.5] [C++ 8p4, dcl.decl]
/// [C]     pointer[opt] direct-declarator
/// [C++]   direct-declarator
/// [C++]   ptr-operator declarator
///
///       pointer: [C99 6.7.5]
///         '*' type-qualifier-list[opt]
///         '*' type-qualifier-list[opt] pointer
///
///       ptr-operator:
///         '*' cv-qualifier-seq[opt]
///         '&'
/// [C++0x] '&&'
/// [GNU]   '&' restrict[opt] attributes[opt]
/// [GNU?]  '&&' restrict[opt] attributes[opt]
///         '::'[opt] nested-name-specifier '*' cv-qualifier-seq[opt]
void Parser::ParseDeclaratorInternal(Declarator &D,
                                     DirectDeclParseFunction DirectDeclParser) {
  if (Diags.hasAllExtensionsSilenced())
    D.setExtension();
  // C++ member pointers start with a '::' or a nested-name.
  // Member pointers get special handling, since there's no place for the
  // scope spec in the generic path below.
  if (getLang().CPlusPlus &&
      (Tok.is(tok::coloncolon) || Tok.is(tok::identifier) ||
       Tok.is(tok::annot_cxxscope))) {
    CXXScopeSpec SS;
    ParseOptionalCXXScopeSpecifier(SS, /*ObjectType=*/0, true); // ignore fail

    if (SS.isSet()) {
      if (Tok.isNot(tok::star)) {
        // The scope spec really belongs to the direct-declarator.
        D.getCXXScopeSpec() = SS;
        if (DirectDeclParser)
          (this->*DirectDeclParser)(D);
        return;
      }

      SourceLocation Loc = ConsumeToken();
      D.SetRangeEnd(Loc);
      DeclSpec DS;
      ParseTypeQualifierListOpt(DS);
      D.ExtendWithDeclSpec(DS);

      // Recurse to parse whatever is left.
      ParseDeclaratorInternal(D, DirectDeclParser);

      // Sema will have to catch (syntactically invalid) pointers into global
      // scope. It has to catch pointers into namespace scope anyway.
      D.AddTypeInfo(DeclaratorChunk::getMemberPointer(SS,DS.getTypeQualifiers(),
                                                      Loc, DS.TakeAttributes()),
                    /* Don't replace range end. */SourceLocation());
      return;
    }
  }

  tok::TokenKind Kind = Tok.getKind();
  // Not a pointer, C++ reference, or block.
  if (Kind != tok::star && Kind != tok::caret &&
      (Kind != tok::amp || !getLang().CPlusPlus) &&
      // We parse rvalue refs in C++03, because otherwise the errors are scary.
      (Kind != tok::ampamp || !getLang().CPlusPlus)) {
    if (DirectDeclParser)
      (this->*DirectDeclParser)(D);
    return;
  }

  // Otherwise, '*' -> pointer, '^' -> block, '&' -> lvalue reference,
  // '&&' -> rvalue reference
  SourceLocation Loc = ConsumeToken();  // Eat the *, ^, & or &&.
  D.SetRangeEnd(Loc);

  if (Kind == tok::star || Kind == tok::caret) {
    // Is a pointer.
    DeclSpec DS;

    ParseTypeQualifierListOpt(DS);
    D.ExtendWithDeclSpec(DS);

    // Recursively parse the declarator.
    ParseDeclaratorInternal(D, DirectDeclParser);
    if (Kind == tok::star)
      // Remember that we parsed a pointer type, and remember the type-quals.
      D.AddTypeInfo(DeclaratorChunk::getPointer(DS.getTypeQualifiers(), Loc,
                                                DS.TakeAttributes()),
                    SourceLocation());
    else
      // Remember that we parsed a Block type, and remember the type-quals.
      D.AddTypeInfo(DeclaratorChunk::getBlockPointer(DS.getTypeQualifiers(),
                                                     Loc, DS.TakeAttributes()),
                    SourceLocation());
  } else {
    // Is a reference
    DeclSpec DS;

    // Complain about rvalue references in C++03, but then go on and build
    // the declarator.
    if (Kind == tok::ampamp && !getLang().CPlusPlus0x)
      Diag(Loc, diag::err_rvalue_reference);

    // C++ 8.3.2p1: cv-qualified references are ill-formed except when the
    // cv-qualifiers are introduced through the use of a typedef or of a
    // template type argument, in which case the cv-qualifiers are ignored.
    //
    // [GNU] Retricted references are allowed.
    // [GNU] Attributes on references are allowed.
    // [C++0x] Attributes on references are not allowed.
    ParseTypeQualifierListOpt(DS, true, false);
    D.ExtendWithDeclSpec(DS);

    if (DS.getTypeQualifiers() != DeclSpec::TQ_unspecified) {
      if (DS.getTypeQualifiers() & DeclSpec::TQ_const)
        Diag(DS.getConstSpecLoc(),
             diag::err_invalid_reference_qualifier_application) << "const";
      if (DS.getTypeQualifiers() & DeclSpec::TQ_volatile)
        Diag(DS.getVolatileSpecLoc(),
             diag::err_invalid_reference_qualifier_application) << "volatile";
    }

    // Recursively parse the declarator.
    ParseDeclaratorInternal(D, DirectDeclParser);

    if (D.getNumTypeObjects() > 0) {
      // C++ [dcl.ref]p4: There shall be no references to references.
      DeclaratorChunk& InnerChunk = D.getTypeObject(D.getNumTypeObjects() - 1);
      if (InnerChunk.Kind == DeclaratorChunk::Reference) {
        if (const IdentifierInfo *II = D.getIdentifier())
          Diag(InnerChunk.Loc, diag::err_illegal_decl_reference_to_reference)
           << II;
        else
          Diag(InnerChunk.Loc, diag::err_illegal_decl_reference_to_reference)
            << "type name";

        // Once we've complained about the reference-to-reference, we
        // can go ahead and build the (technically ill-formed)
        // declarator: reference collapsing will take care of it.
      }
    }

    // Remember that we parsed a reference type. It doesn't have type-quals.
    D.AddTypeInfo(DeclaratorChunk::getReference(DS.getTypeQualifiers(), Loc,
                                                DS.TakeAttributes(),
                                                Kind == tok::amp),
                  SourceLocation());
  }
}

/// ParseDirectDeclarator
///       direct-declarator: [C99 6.7.5]
/// [C99]   identifier
///         '(' declarator ')'
/// [GNU]   '(' attributes declarator ')'
/// [C90]   direct-declarator '[' constant-expression[opt] ']'
/// [C99]   direct-declarator '[' type-qual-list[opt] assignment-expr[opt] ']'
/// [C99]   direct-declarator '[' 'static' type-qual-list[opt] assign-expr ']'
/// [C99]   direct-declarator '[' type-qual-list 'static' assignment-expr ']'
/// [C99]   direct-declarator '[' type-qual-list[opt] '*' ']'
///         direct-declarator '(' parameter-type-list ')'
///         direct-declarator '(' identifier-list[opt] ')'
/// [GNU]   direct-declarator '(' parameter-forward-declarations
///                    parameter-type-list[opt] ')'
/// [C++]   direct-declarator '(' parameter-declaration-clause ')'
///                    cv-qualifier-seq[opt] exception-specification[opt]
/// [C++]   declarator-id
///
///       declarator-id: [C++ 8]
///         id-expression
///         '::'[opt] nested-name-specifier[opt] type-name
///
///       id-expression: [C++ 5.1]
///         unqualified-id
///         qualified-id
///
///       unqualified-id: [C++ 5.1]
///         identifier
///         operator-function-id
///         conversion-function-id
///          '~' class-name
///         template-id
///
void Parser::ParseDirectDeclarator(Declarator &D) {
  DeclaratorScopeObj DeclScopeObj(*this, D.getCXXScopeSpec());

  if (getLang().CPlusPlus && D.mayHaveIdentifier()) {
    // ParseDeclaratorInternal might already have parsed the scope.
    bool afterCXXScope = D.getCXXScopeSpec().isSet();
    if (!afterCXXScope) {
      ParseOptionalCXXScopeSpecifier(D.getCXXScopeSpec(), /*ObjectType=*/0,
                                     true);
      afterCXXScope = D.getCXXScopeSpec().isSet();
    }

    if (afterCXXScope) {
      if (Actions.ShouldEnterDeclaratorScope(CurScope, D.getCXXScopeSpec()))
        // Change the declaration context for name lookup, until this function
        // is exited (and the declarator has been parsed).
        DeclScopeObj.EnterDeclaratorScope();
    } 
    
    if (Tok.is(tok::identifier) || Tok.is(tok::kw_operator) ||
        Tok.is(tok::annot_template_id) || Tok.is(tok::tilde)) {
      // We found something that indicates the start of an unqualified-id.
      // Parse that unqualified-id.
      bool AllowConstructorName
        = ((D.getCXXScopeSpec().isSet() && 
            D.getContext() == Declarator::FileContext) ||
           (!D.getCXXScopeSpec().isSet() &&
            D.getContext() == Declarator::MemberContext)) &&
        !D.getDeclSpec().hasTypeSpecifier();
      if (ParseUnqualifiedId(D.getCXXScopeSpec(), 
                             /*EnteringContext=*/true, 
                             /*AllowDestructorName=*/true, 
                             AllowConstructorName,
                             /*ObjectType=*/0,
                             D.getName())) {
        D.SetIdentifier(0, Tok.getLocation());
        D.setInvalidType(true);
      } else {
        // Parsed the unqualified-id; update range information and move along.
        if (D.getSourceRange().getBegin().isInvalid())
          D.SetRangeBegin(D.getName().getSourceRange().getBegin());
        D.SetRangeEnd(D.getName().getSourceRange().getEnd());
      }
      goto PastIdentifier;
    }
  } else if (Tok.is(tok::identifier) && D.mayHaveIdentifier()) {
    assert(!getLang().CPlusPlus &&
           "There's a C++-specific check for tok::identifier above");
    assert(Tok.getIdentifierInfo() && "Not an identifier?");
    D.SetIdentifier(Tok.getIdentifierInfo(), Tok.getLocation());
    ConsumeToken();
    goto PastIdentifier;
  }
    
  if (Tok.is(tok::l_paren)) {
    // direct-declarator: '(' declarator ')'
    // direct-declarator: '(' attributes declarator ')'
    // Example: 'char (*X)'   or 'int (*XX)(void)'
    ParseParenDeclarator(D);

    // If the declarator was parenthesized, we entered the declarator
    // scope when parsing the parenthesized declarator, then exited
    // the scope already. Re-enter the scope, if we need to.
    if (D.getCXXScopeSpec().isSet()) {
      if (Actions.ShouldEnterDeclaratorScope(CurScope, D.getCXXScopeSpec()))
        // Change the declaration context for name lookup, until this function
        // is exited (and the declarator has been parsed).
        DeclScopeObj.EnterDeclaratorScope();
    }
  } else if (D.mayOmitIdentifier()) {
    // This could be something simple like "int" (in which case the declarator
    // portion is empty), if an abstract-declarator is allowed.
    D.SetIdentifier(0, Tok.getLocation());
  } else {
    if (D.getContext() == Declarator::MemberContext)
      Diag(Tok, diag::err_expected_member_name_or_semi)
        << D.getDeclSpec().getSourceRange();
    else if (getLang().CPlusPlus)
      Diag(Tok, diag::err_expected_unqualified_id) << getLang().CPlusPlus;
    else
      Diag(Tok, diag::err_expected_ident_lparen);
    D.SetIdentifier(0, Tok.getLocation());
    D.setInvalidType(true);
  }

 PastIdentifier:
  assert(D.isPastIdentifier() &&
         "Haven't past the location of the identifier yet?");

  // Don't parse attributes unless we have an identifier.
  if (D.getIdentifier() && getLang().CPlusPlus0x
   && isCXX0XAttributeSpecifier(true)) {
    SourceLocation AttrEndLoc;
    CXX0XAttributeList Attr = ParseCXX0XAttributes();
    D.AddAttributes(Attr.AttrList, AttrEndLoc);
  }

  while (1) {
    if (Tok.is(tok::l_paren)) {
      // The paren may be part of a C++ direct initializer, eg. "int x(1);".
      // In such a case, check if we actually have a function declarator; if it
      // is not, the declarator has been fully parsed.
      if (getLang().CPlusPlus && D.mayBeFollowedByCXXDirectInit()) {
        // When not in file scope, warn for ambiguous function declarators, just
        // in case the author intended it as a variable definition.
        bool warnIfAmbiguous = D.getContext() != Declarator::FileContext;
        if (!isCXXFunctionDeclarator(warnIfAmbiguous))
          break;
      }
      ParseFunctionDeclarator(ConsumeParen(), D);
    } else if (Tok.is(tok::l_square)) {
      ParseBracketDeclarator(D);
    } else {
      break;
    }
  }
}

/// ParseParenDeclarator - We parsed the declarator D up to a paren.  This is
/// only called before the identifier, so these are most likely just grouping
/// parens for precedence.  If we find that these are actually function
/// parameter parens in an abstract-declarator, we call ParseFunctionDeclarator.
///
///       direct-declarator:
///         '(' declarator ')'
/// [GNU]   '(' attributes declarator ')'
///         direct-declarator '(' parameter-type-list ')'
///         direct-declarator '(' identifier-list[opt] ')'
/// [GNU]   direct-declarator '(' parameter-forward-declarations
///                    parameter-type-list[opt] ')'
///
void Parser::ParseParenDeclarator(Declarator &D) {
  SourceLocation StartLoc = ConsumeParen();
  assert(!D.isPastIdentifier() && "Should be called before passing identifier");

  // Eat any attributes before we look at whether this is a grouping or function
  // declarator paren.  If this is a grouping paren, the attribute applies to
  // the type being built up, for example:
  //     int (__attribute__(()) *x)(long y)
  // If this ends up not being a grouping paren, the attribute applies to the
  // first argument, for example:
  //     int (__attribute__(()) int x)
  // In either case, we need to eat any attributes to be able to determine what
  // sort of paren this is.
  //
  llvm::OwningPtr<AttributeList> AttrList;
  bool RequiresArg = false;
  if (Tok.is(tok::kw___attribute)) {
    AttrList.reset(ParseGNUAttributes());

    // We require that the argument list (if this is a non-grouping paren) be
    // present even if the attribute list was empty.
    RequiresArg = true;
  }
  // Eat any Microsoft extensions.
  if  (Tok.is(tok::kw___cdecl) || Tok.is(tok::kw___stdcall) ||
       Tok.is(tok::kw___fastcall) || Tok.is(tok::kw___w64) ||
       Tok.is(tok::kw___ptr64)) {
    AttrList.reset(ParseMicrosoftTypeAttributes(AttrList.take()));
  }

  // If we haven't past the identifier yet (or where the identifier would be
  // stored, if this is an abstract declarator), then this is probably just
  // grouping parens. However, if this could be an abstract-declarator, then
  // this could also be the start of function arguments (consider 'void()').
  bool isGrouping;

  if (!D.mayOmitIdentifier()) {
    // If this can't be an abstract-declarator, this *must* be a grouping
    // paren, because we haven't seen the identifier yet.
    isGrouping = true;
  } else if (Tok.is(tok::r_paren) ||           // 'int()' is a function.
             (getLang().CPlusPlus && Tok.is(tok::ellipsis)) || // C++ int(...)
             isDeclarationSpecifier()) {       // 'int(int)' is a function.
    // This handles C99 6.7.5.3p11: in "typedef int X; void foo(X)", X is
    // considered to be a type, not a K&R identifier-list.
    isGrouping = false;
  } else {
    // Otherwise, this is a grouping paren, e.g. 'int (*X)' or 'int(X)'.
    isGrouping = true;
  }

  // If this is a grouping paren, handle:
  // direct-declarator: '(' declarator ')'
  // direct-declarator: '(' attributes declarator ')'
  if (isGrouping) {
    bool hadGroupingParens = D.hasGroupingParens();
    D.setGroupingParens(true);
    if (AttrList)
      D.AddAttributes(AttrList.take(), SourceLocation());

    ParseDeclaratorInternal(D, &Parser::ParseDirectDeclarator);
    // Match the ')'.
    SourceLocation Loc = MatchRHSPunctuation(tok::r_paren, StartLoc);

    D.setGroupingParens(hadGroupingParens);
    D.SetRangeEnd(Loc);
    return;
  }

  // Okay, if this wasn't a grouping paren, it must be the start of a function
  // argument list.  Recognize that this declarator will never have an
  // identifier (and remember where it would have been), then call into
  // ParseFunctionDeclarator to handle of argument list.
  D.SetIdentifier(0, Tok.getLocation());

  ParseFunctionDeclarator(StartLoc, D, AttrList.take(), RequiresArg);
}

/// ParseFunctionDeclarator - We are after the identifier and have parsed the
/// declarator D up to a paren, which indicates that we are parsing function
/// arguments.
///
/// If AttrList is non-null, then the caller parsed those arguments immediately
/// after the open paren - they should be considered to be the first argument of
/// a parameter.  If RequiresArg is true, then the first argument of the
/// function is required to be present and required to not be an identifier
/// list.
///
/// This method also handles this portion of the grammar:
///       parameter-type-list: [C99 6.7.5]
///         parameter-list
///         parameter-list ',' '...'
/// [C++]   parameter-list '...'
///
///       parameter-list: [C99 6.7.5]
///         parameter-declaration
///         parameter-list ',' parameter-declaration
///
///       parameter-declaration: [C99 6.7.5]
///         declaration-specifiers declarator
/// [C++]   declaration-specifiers declarator '=' assignment-expression
/// [GNU]   declaration-specifiers declarator attributes
///         declaration-specifiers abstract-declarator[opt]
/// [C++]   declaration-specifiers abstract-declarator[opt]
///           '=' assignment-expression
/// [GNU]   declaration-specifiers abstract-declarator[opt] attributes
///
/// For C++, after the parameter-list, it also parses "cv-qualifier-seq[opt]"
/// and "exception-specification[opt]".
///
void Parser::ParseFunctionDeclarator(SourceLocation LParenLoc, Declarator &D,
                                     AttributeList *AttrList,
                                     bool RequiresArg) {
  // lparen is already consumed!
  assert(D.isPastIdentifier() && "Should not call before identifier!");

  // This parameter list may be empty.
  if (Tok.is(tok::r_paren)) {
    if (RequiresArg) {
      Diag(Tok, diag::err_argument_required_after_attribute);
      delete AttrList;
    }

    SourceLocation RParenLoc = ConsumeParen();  // Eat the closing ')'.
    SourceLocation EndLoc = RParenLoc;

    // cv-qualifier-seq[opt].
    DeclSpec DS;
    bool hasExceptionSpec = false;
    SourceLocation ThrowLoc;
    bool hasAnyExceptionSpec = false;
    llvm::SmallVector<TypeTy*, 2> Exceptions;
    llvm::SmallVector<SourceRange, 2> ExceptionRanges;
    if (getLang().CPlusPlus) {
      ParseTypeQualifierListOpt(DS, false /*no attributes*/);
      if (!DS.getSourceRange().getEnd().isInvalid())
        EndLoc = DS.getSourceRange().getEnd();

      // Parse exception-specification[opt].
      if (Tok.is(tok::kw_throw)) {
        hasExceptionSpec = true;
        ThrowLoc = Tok.getLocation();
        ParseExceptionSpecification(EndLoc, Exceptions, ExceptionRanges,
                                    hasAnyExceptionSpec);
        assert(Exceptions.size() == ExceptionRanges.size() &&
               "Produced different number of exception types and ranges.");
      }
    }

    // Remember that we parsed a function type, and remember the attributes.
    // int() -> no prototype, no '...'.
    D.AddTypeInfo(DeclaratorChunk::getFunction(/*prototype*/getLang().CPlusPlus,
                                               /*variadic*/ false,
                                               SourceLocation(),
                                               /*arglist*/ 0, 0,
                                               DS.getTypeQualifiers(),
                                               hasExceptionSpec, ThrowLoc,
                                               hasAnyExceptionSpec,
                                               Exceptions.data(),
                                               ExceptionRanges.data(),
                                               Exceptions.size(),
                                               LParenLoc, RParenLoc, D),
                  EndLoc);
    return;
  }

  // Alternatively, this parameter list may be an identifier list form for a
  // K&R-style function:  void foo(a,b,c)
  if (!getLang().CPlusPlus && Tok.is(tok::identifier)
      && !TryAltiVecVectorToken()) {
    if (TryAnnotateTypeOrScopeToken() || !Tok.is(tok::annot_typename)) {
      // K&R identifier lists can't have typedefs as identifiers, per
      // C99 6.7.5.3p11.
      if (RequiresArg) {
        Diag(Tok, diag::err_argument_required_after_attribute);
        delete AttrList;
      }
      // Identifier list.  Note that '(' identifier-list ')' is only allowed for
      // normal declarators, not for abstract-declarators.
      return ParseFunctionDeclaratorIdentifierList(LParenLoc, D);
    }
  }

  // Finally, a normal, non-empty parameter type list.

  // Build up an array of information about the parsed arguments.
  llvm::SmallVector<DeclaratorChunk::ParamInfo, 16> ParamInfo;

  // Enter function-declaration scope, limiting any declarators to the
  // function prototype scope, including parameter declarators.
  ParseScope PrototypeScope(this,
                            Scope::FunctionPrototypeScope|Scope::DeclScope);

  bool IsVariadic = false;
  SourceLocation EllipsisLoc;
  while (1) {
    if (Tok.is(tok::ellipsis)) {
      IsVariadic = true;
      EllipsisLoc = ConsumeToken();     // Consume the ellipsis.
      break;
    }

    SourceLocation DSStart = Tok.getLocation();

    // Parse the declaration-specifiers.
    // Just use the ParsingDeclaration "scope" of the declarator.
    DeclSpec DS;

    // If the caller parsed attributes for the first argument, add them now.
    if (AttrList) {
      DS.AddAttributes(AttrList);
      AttrList = 0;  // Only apply the attributes to the first parameter.
    }
    ParseDeclarationSpecifiers(DS);

    // Parse the declarator.  This is "PrototypeContext", because we must
    // accept either 'declarator' or 'abstract-declarator' here.
    Declarator ParmDecl(DS, Declarator::PrototypeContext);
    ParseDeclarator(ParmDecl);

    // Parse GNU attributes, if present.
    if (Tok.is(tok::kw___attribute)) {
      SourceLocation Loc;
      AttributeList *AttrList = ParseGNUAttributes(&Loc);
      ParmDecl.AddAttributes(AttrList, Loc);
    }

    // Remember this parsed parameter in ParamInfo.
    IdentifierInfo *ParmII = ParmDecl.getIdentifier();

    // DefArgToks is used when the parsing of default arguments needs
    // to be delayed.
    CachedTokens *DefArgToks = 0;

    // If no parameter was specified, verify that *something* was specified,
    // otherwise we have a missing type and identifier.
    if (DS.isEmpty() && ParmDecl.getIdentifier() == 0 &&
        ParmDecl.getNumTypeObjects() == 0) {
      // Completely missing, emit error.
      Diag(DSStart, diag::err_missing_param);
    } else {
      // Otherwise, we have something.  Add it and let semantic analysis try
      // to grok it and add the result to the ParamInfo we are building.

      // Inform the actions module about the parameter declarator, so it gets
      // added to the current scope.
      DeclPtrTy Param = Actions.ActOnParamDeclarator(CurScope, ParmDecl);

      // Parse the default argument, if any. We parse the default
      // arguments in all dialects; the semantic analysis in
      // ActOnParamDefaultArgument will reject the default argument in
      // C.
      if (Tok.is(tok::equal)) {
        SourceLocation EqualLoc = Tok.getLocation();

        // Parse the default argument
        if (D.getContext() == Declarator::MemberContext) {
          // If we're inside a class definition, cache the tokens
          // corresponding to the default argument. We'll actually parse
          // them when we see the end of the class definition.
          // FIXME: Templates will require something similar.
          // FIXME: Can we use a smart pointer for Toks?
          DefArgToks = new CachedTokens;

          if (!ConsumeAndStoreUntil(tok::comma, tok::r_paren, *DefArgToks,
                                    tok::semi, false)) {
            delete DefArgToks;
            DefArgToks = 0;
            Actions.ActOnParamDefaultArgumentError(Param);
          } else
            Actions.ActOnParamUnparsedDefaultArgument(Param, EqualLoc,
                                                (*DefArgToks)[1].getLocation());
        } else {
          // Consume the '='.
          ConsumeToken();

          OwningExprResult DefArgResult(ParseAssignmentExpression());
          if (DefArgResult.isInvalid()) {
            Actions.ActOnParamDefaultArgumentError(Param);
            SkipUntil(tok::comma, tok::r_paren, true, true);
          } else {
            // Inform the actions module about the default argument
            Actions.ActOnParamDefaultArgument(Param, EqualLoc,
                                              move(DefArgResult));
          }
        }
      }

      ParamInfo.push_back(DeclaratorChunk::ParamInfo(ParmII,
                                          ParmDecl.getIdentifierLoc(), Param,
                                          DefArgToks));
    }

    // If the next token is a comma, consume it and keep reading arguments.
    if (Tok.isNot(tok::comma)) {
      if (Tok.is(tok::ellipsis)) {
        IsVariadic = true;
        EllipsisLoc = ConsumeToken();     // Consume the ellipsis.
        
        if (!getLang().CPlusPlus) {
          // We have ellipsis without a preceding ',', which is ill-formed
          // in C. Complain and provide the fix.
          Diag(EllipsisLoc, diag::err_missing_comma_before_ellipsis)
            << CodeModificationHint::CreateInsertion(EllipsisLoc, ", ");
        }
      }
      
      break;
    }

    // Consume the comma.
    ConsumeToken();
  }

  // Leave prototype scope.
  PrototypeScope.Exit();

  // If we have the closing ')', eat it.
  SourceLocation RParenLoc = MatchRHSPunctuation(tok::r_paren, LParenLoc);
  SourceLocation EndLoc = RParenLoc;

  DeclSpec DS;
  bool hasExceptionSpec = false;
  SourceLocation ThrowLoc;
  bool hasAnyExceptionSpec = false;
  llvm::SmallVector<TypeTy*, 2> Exceptions;
  llvm::SmallVector<SourceRange, 2> ExceptionRanges;
  
  if (getLang().CPlusPlus) {
    // Parse cv-qualifier-seq[opt].
    ParseTypeQualifierListOpt(DS, false /*no attributes*/);
      if (!DS.getSourceRange().getEnd().isInvalid())
        EndLoc = DS.getSourceRange().getEnd();

    // Parse exception-specification[opt].
    if (Tok.is(tok::kw_throw)) {
      hasExceptionSpec = true;
      ThrowLoc = Tok.getLocation();
      ParseExceptionSpecification(EndLoc, Exceptions, ExceptionRanges,
                                  hasAnyExceptionSpec);
      assert(Exceptions.size() == ExceptionRanges.size() &&
             "Produced different number of exception types and ranges.");
    }
  }

  // Remember that we parsed a function type, and remember the attributes.
  D.AddTypeInfo(DeclaratorChunk::getFunction(/*proto*/true, IsVariadic,
                                             EllipsisLoc,
                                             ParamInfo.data(), ParamInfo.size(),
                                             DS.getTypeQualifiers(),
                                             hasExceptionSpec, ThrowLoc,
                                             hasAnyExceptionSpec,
                                             Exceptions.data(),
                                             ExceptionRanges.data(),
                                             Exceptions.size(),
                                             LParenLoc, RParenLoc, D),
                EndLoc);
}

/// ParseFunctionDeclaratorIdentifierList - While parsing a function declarator
/// we found a K&R-style identifier list instead of a type argument list.  The
/// current token is known to be the first identifier in the list.
///
///       identifier-list: [C99 6.7.5]
///         identifier
///         identifier-list ',' identifier
///
void Parser::ParseFunctionDeclaratorIdentifierList(SourceLocation LParenLoc,
                                                   Declarator &D) {
  // Build up an array of information about the parsed arguments.
  llvm::SmallVector<DeclaratorChunk::ParamInfo, 16> ParamInfo;
  llvm::SmallSet<const IdentifierInfo*, 16> ParamsSoFar;

  // If there was no identifier specified for the declarator, either we are in
  // an abstract-declarator, or we are in a parameter declarator which was found
  // to be abstract.  In abstract-declarators, identifier lists are not valid:
  // diagnose this.
  if (!D.getIdentifier())
    Diag(Tok, diag::ext_ident_list_in_param);

  // Tok is known to be the first identifier in the list.  Remember this
  // identifier in ParamInfo.
  ParamsSoFar.insert(Tok.getIdentifierInfo());
  ParamInfo.push_back(DeclaratorChunk::ParamInfo(Tok.getIdentifierInfo(),
                                                 Tok.getLocation(),
                                                 DeclPtrTy()));

  ConsumeToken();  // eat the first identifier.

  while (Tok.is(tok::comma)) {
    // Eat the comma.
    ConsumeToken();

    // If this isn't an identifier, report the error and skip until ')'.
    if (Tok.isNot(tok::identifier)) {
      Diag(Tok, diag::err_expected_ident);
      SkipUntil(tok::r_paren);
      return;
    }

    IdentifierInfo *ParmII = Tok.getIdentifierInfo();

    // Reject 'typedef int y; int test(x, y)', but continue parsing.
    if (Actions.getTypeName(*ParmII, Tok.getLocation(), CurScope))
      Diag(Tok, diag::err_unexpected_typedef_ident) << ParmII;

    // Verify that the argument identifier has not already been mentioned.
    if (!ParamsSoFar.insert(ParmII)) {
      Diag(Tok, diag::err_param_redefinition) << ParmII;
    } else {
      // Remember this identifier in ParamInfo.
      ParamInfo.push_back(DeclaratorChunk::ParamInfo(ParmII,
                                                     Tok.getLocation(),
                                                     DeclPtrTy()));
    }

    // Eat the identifier.
    ConsumeToken();
  }

  // If we have the closing ')', eat it and we're done.
  SourceLocation RLoc = MatchRHSPunctuation(tok::r_paren, LParenLoc);

  // Remember that we parsed a function type, and remember the attributes.  This
  // function type is always a K&R style function type, which is not varargs and
  // has no prototype.
  D.AddTypeInfo(DeclaratorChunk::getFunction(/*proto*/false, /*varargs*/false,
                                             SourceLocation(),
                                             &ParamInfo[0], ParamInfo.size(),
                                             /*TypeQuals*/0,
                                             /*exception*/false,
                                             SourceLocation(), false, 0, 0, 0,
                                             LParenLoc, RLoc, D),
                RLoc);
}

/// [C90]   direct-declarator '[' constant-expression[opt] ']'
/// [C99]   direct-declarator '[' type-qual-list[opt] assignment-expr[opt] ']'
/// [C99]   direct-declarator '[' 'static' type-qual-list[opt] assign-expr ']'
/// [C99]   direct-declarator '[' type-qual-list 'static' assignment-expr ']'
/// [C99]   direct-declarator '[' type-qual-list[opt] '*' ']'
void Parser::ParseBracketDeclarator(Declarator &D) {
  SourceLocation StartLoc = ConsumeBracket();

  // C array syntax has many features, but by-far the most common is [] and [4].
  // This code does a fast path to handle some of the most obvious cases.
  if (Tok.getKind() == tok::r_square) {
    SourceLocation EndLoc = MatchRHSPunctuation(tok::r_square, StartLoc);
    //FIXME: Use these
    CXX0XAttributeList Attr;
    if (getLang().CPlusPlus0x && isCXX0XAttributeSpecifier(true)) {
      Attr = ParseCXX0XAttributes();
    }
    
    // Remember that we parsed the empty array type.
    OwningExprResult NumElements(Actions);
    D.AddTypeInfo(DeclaratorChunk::getArray(0, false, false, 0,
                                            StartLoc, EndLoc),
                  EndLoc);
    return;
  } else if (Tok.getKind() == tok::numeric_constant &&
             GetLookAheadToken(1).is(tok::r_square)) {
    // [4] is very common.  Parse the numeric constant expression.
    OwningExprResult ExprRes(Actions.ActOnNumericConstant(Tok));
    ConsumeToken();

    SourceLocation EndLoc = MatchRHSPunctuation(tok::r_square, StartLoc);
    //FIXME: Use these
    CXX0XAttributeList Attr;
    if (getLang().CPlusPlus0x && isCXX0XAttributeSpecifier()) {
      Attr = ParseCXX0XAttributes();
    }

    // If there was an error parsing the assignment-expression, recover.
    if (ExprRes.isInvalid())
      ExprRes.release();  // Deallocate expr, just use [].

    // Remember that we parsed a array type, and remember its features.
    D.AddTypeInfo(DeclaratorChunk::getArray(0, false, 0, ExprRes.release(),
                                            StartLoc, EndLoc),
                  EndLoc);
    return;
  }

  // If valid, this location is the position where we read the 'static' keyword.
  SourceLocation StaticLoc;
  if (Tok.is(tok::kw_static))
    StaticLoc = ConsumeToken();

  // If there is a type-qualifier-list, read it now.
  // Type qualifiers in an array subscript are a C99 feature.
  DeclSpec DS;
  ParseTypeQualifierListOpt(DS, false /*no attributes*/);

  // If we haven't already read 'static', check to see if there is one after the
  // type-qualifier-list.
  if (!StaticLoc.isValid() && Tok.is(tok::kw_static))
    StaticLoc = ConsumeToken();

  // Handle "direct-declarator [ type-qual-list[opt] * ]".
  bool isStar = false;
  OwningExprResult NumElements(Actions);

  // Handle the case where we have '[*]' as the array size.  However, a leading
  // star could be the start of an expression, for example 'X[*p + 4]'.  Verify
  // the the token after the star is a ']'.  Since stars in arrays are
  // infrequent, use of lookahead is not costly here.
  if (Tok.is(tok::star) && GetLookAheadToken(1).is(tok::r_square)) {
    ConsumeToken();  // Eat the '*'.

    if (StaticLoc.isValid()) {
      Diag(StaticLoc, diag::err_unspecified_vla_size_with_static);
      StaticLoc = SourceLocation();  // Drop the static.
    }
    isStar = true;
  } else if (Tok.isNot(tok::r_square)) {
    // Note, in C89, this production uses the constant-expr production instead
    // of assignment-expr.  The only difference is that assignment-expr allows
    // things like '=' and '*='.  Sema rejects these in C89 mode because they
    // are not i-c-e's, so we don't need to distinguish between the two here.

    // Parse the constant-expression or assignment-expression now (depending
    // on dialect).
    if (getLang().CPlusPlus)
      NumElements = ParseConstantExpression();
    else
      NumElements = ParseAssignmentExpression();
  }

  // If there was an error parsing the assignment-expression, recover.
  if (NumElements.isInvalid()) {
    D.setInvalidType(true);
    // If the expression was invalid, skip it.
    SkipUntil(tok::r_square);
    return;
  }

  SourceLocation EndLoc = MatchRHSPunctuation(tok::r_square, StartLoc);

  //FIXME: Use these
  CXX0XAttributeList Attr;
  if (getLang().CPlusPlus0x && isCXX0XAttributeSpecifier()) {
    Attr = ParseCXX0XAttributes();
  }

  // Remember that we parsed a array type, and remember its features.
  D.AddTypeInfo(DeclaratorChunk::getArray(DS.getTypeQualifiers(),
                                          StaticLoc.isValid(), isStar,
                                          NumElements.release(),
                                          StartLoc, EndLoc),
                EndLoc);
}

/// [GNU]   typeof-specifier:
///           typeof ( expressions )
///           typeof ( type-name )
/// [GNU/C++] typeof unary-expression
///
void Parser::ParseTypeofSpecifier(DeclSpec &DS) {
  assert(Tok.is(tok::kw_typeof) && "Not a typeof specifier");
  Token OpTok = Tok;
  SourceLocation StartLoc = ConsumeToken();

  const bool hasParens = Tok.is(tok::l_paren);

  bool isCastExpr;
  TypeTy *CastTy;
  SourceRange CastRange;
  OwningExprResult Operand = ParseExprAfterTypeofSizeofAlignof(OpTok,
                                                               isCastExpr,
                                                               CastTy,
                                                               CastRange);
  if (hasParens)
    DS.setTypeofParensRange(CastRange);

  if (CastRange.getEnd().isInvalid())
    // FIXME: Not accurate, the range gets one token more than it should.
    DS.SetRangeEnd(Tok.getLocation());
  else
    DS.SetRangeEnd(CastRange.getEnd());

  if (isCastExpr) {
    if (!CastTy) {
      DS.SetTypeSpecError();
      return;
    }

    const char *PrevSpec = 0;
    unsigned DiagID;
    // Check for duplicate type specifiers (e.g. "int typeof(int)").
    if (DS.SetTypeSpecType(DeclSpec::TST_typeofType, StartLoc, PrevSpec,
                           DiagID, CastTy))
      Diag(StartLoc, DiagID) << PrevSpec;
    return;
  }

  // If we get here, the operand to the typeof was an expresion.
  if (Operand.isInvalid()) {
    DS.SetTypeSpecError();
    return;
  }

  const char *PrevSpec = 0;
  unsigned DiagID;
  // Check for duplicate type specifiers (e.g. "int typeof(int)").
  if (DS.SetTypeSpecType(DeclSpec::TST_typeofExpr, StartLoc, PrevSpec,
                         DiagID, Operand.release()))
    Diag(StartLoc, DiagID) << PrevSpec;
}


/// TryAltiVecVectorTokenOutOfLine - Out of line body that should only be called
/// from TryAltiVecVectorToken.
bool Parser::TryAltiVecVectorTokenOutOfLine() {
  Token Next = NextToken();
  switch (Next.getKind()) {
  default: return false;
  case tok::kw_short:
  case tok::kw_long:
  case tok::kw_signed:
  case tok::kw_unsigned:
  case tok::kw_void:
  case tok::kw_char:
  case tok::kw_int:
  case tok::kw_float:
  case tok::kw_double:
  case tok::kw_bool:
  case tok::kw___pixel:
    Tok.setKind(tok::kw___vector);
    return true;
  case tok::identifier:
    if (Next.getIdentifierInfo() == Ident_pixel) {
      Tok.setKind(tok::kw___vector);
      return true;
    }
    return false;
  }
}

bool Parser::TryAltiVecTokenOutOfLine(DeclSpec &DS, SourceLocation Loc,
                                      const char *&PrevSpec, unsigned &DiagID,
                                      bool &isInvalid) {
  if (Tok.getIdentifierInfo() == Ident_vector) {
    Token Next = NextToken();
    switch (Next.getKind()) {
    case tok::kw_short:
    case tok::kw_long:
    case tok::kw_signed:
    case tok::kw_unsigned:
    case tok::kw_void:
    case tok::kw_char:
    case tok::kw_int:
    case tok::kw_float:
    case tok::kw_double:
    case tok::kw_bool:
    case tok::kw___pixel:
      isInvalid = DS.SetTypeAltiVecVector(true, Loc, PrevSpec, DiagID);
      return true;
    case tok::identifier:
      if (Next.getIdentifierInfo() == Ident_pixel) {
        isInvalid = DS.SetTypeAltiVecVector(true, Loc, PrevSpec, DiagID);
        return true;
      }
      break;
    default:
      break;
    }
  } else if (Tok.getIdentifierInfo() == Ident_pixel &&
             DS.isTypeAltiVecVector()) {
    isInvalid = DS.SetTypeAltiVecPixel(true, Loc, PrevSpec, DiagID);
    return true;
  }
  return false;
}
  
