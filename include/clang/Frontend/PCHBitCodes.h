//===- PCHBitCodes.h - Enum values for the PCH bitcode format ---*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This header defines Bitcode enum values for Clang precompiled header files.
//
// The enum values defined in this file should be considered permanent.  If
// new features are added, they should have values added at the end of the
// respective lists.
//
//===----------------------------------------------------------------------===//
#ifndef LLVM_CLANG_FRONTEND_PCHBITCODES_H
#define LLVM_CLANG_FRONTEND_PCHBITCODES_H

#include "llvm/Bitcode/BitCodes.h"
#include "llvm/System/DataTypes.h"

namespace clang {
  namespace pch {
    /// \brief PCH major version number supported by this version of
    /// Clang.
    ///
    /// Whenever the PCH format changes in a way that makes it
    /// incompatible with previous versions (such that a reader
    /// designed for the previous version could not support reading
    /// the new version), this number should be increased.
    ///
    /// Version 3 of PCH files also requires that the version control branch and
    /// revision match exactly, since there is no backward compatibility of
    /// PCH files at this time.
    const unsigned VERSION_MAJOR = 3;

    /// \brief PCH minor version number supported by this version of
    /// Clang.
    ///
    /// Whenever the PCH format changes in a way that is still
    /// compatible with previous versions (such that a reader designed
    /// for the previous version could still support reading the new
    /// version by ignoring new kinds of subblocks), this number
    /// should be increased.
    const unsigned VERSION_MINOR = 0;

    /// \brief An ID number that refers to a declaration in a PCH file.
    ///
    /// The ID numbers of types are consecutive (in order of
    /// discovery) and start at 2. 0 is reserved for NULL, and 1 is
    /// reserved for the translation unit declaration.
    typedef uint32_t DeclID;

    /// \brief An ID number that refers to a type in a PCH file.
    ///
    /// The ID of a type is partitioned into two parts: the lower
    /// three bits are used to store the const/volatile/restrict
    /// qualifiers (as with QualType) and the upper bits provide a
    /// type index. The type index values are partitioned into two
    /// sets. The values below NUM_PREDEF_TYPE_IDs are predefined type
    /// IDs (based on the PREDEF_TYPE_*_ID constants), with 0 as a
    /// placeholder for "no type". Values from NUM_PREDEF_TYPE_IDs are
    /// other types that have serialized representations.
    typedef uint32_t TypeID;

    /// \brief An ID number that refers to an identifier in a PCH
    /// file.
    typedef uint32_t IdentID;

    typedef uint32_t SelectorID;

    /// \brief Describes the various kinds of blocks that occur within
    /// a PCH file.
    enum BlockIDs {
      /// \brief The PCH block, which acts as a container around the
      /// full PCH block.
      PCH_BLOCK_ID = llvm::bitc::FIRST_APPLICATION_BLOCKID,

      /// \brief The block containing information about the source
      /// manager.
      SOURCE_MANAGER_BLOCK_ID,

      /// \brief The block containing information about the
      /// preprocessor.
      PREPROCESSOR_BLOCK_ID,

      /// \brief The block containing the definitions of all of the
      /// types and decls used within the PCH file.
      DECLTYPES_BLOCK_ID
    };

    /// \brief Record types that occur within the PCH block itself.
    enum PCHRecordTypes {
      /// \brief Record code for the offsets of each type.
      ///
      /// The TYPE_OFFSET constant describes the record that occurs
      /// within the PCH block. The record itself is an array of offsets that
      /// point into the declarations and types block (identified by 
      /// DECLTYPES_BLOCK_ID). The index into the array is based on the ID
      /// of a type. For a given type ID @c T, the lower three bits of
      /// @c T are its qualifiers (const, volatile, restrict), as in
      /// the QualType class. The upper bits, after being shifted and
      /// subtracting NUM_PREDEF_TYPE_IDS, are used to index into the
      /// TYPE_OFFSET block to determine the offset of that type's
      /// corresponding record within the DECLTYPES_BLOCK_ID block.
      TYPE_OFFSET = 1,

      /// \brief Record code for the offsets of each decl.
      ///
      /// The DECL_OFFSET constant describes the record that occurs
      /// within the block identified by DECL_OFFSETS_BLOCK_ID within
      /// the PCH block. The record itself is an array of offsets that
      /// point into the declarations and types block (identified by
      /// DECLTYPES_BLOCK_ID). The declaration ID is an index into this
      /// record, after subtracting one to account for the use of
      /// declaration ID 0 for a NULL declaration pointer. Index 0 is
      /// reserved for the translation unit declaration.
      DECL_OFFSET = 2,

      /// \brief Record code for the language options table.
      ///
      /// The record with this code contains the contents of the
      /// LangOptions structure. We serialize the entire contents of
      /// the structure, and let the reader decide which options are
      /// actually important to check.
      LANGUAGE_OPTIONS = 3,

      /// \brief PCH metadata, including the PCH file version number
      /// and the target triple used to build the PCH file.
      METADATA = 4,

      /// \brief Record code for the table of offsets of each
      /// identifier ID.
      ///
      /// The offset table contains offsets into the blob stored in
      /// the IDENTIFIER_TABLE record. Each offset points to the
      /// NULL-terminated string that corresponds to that identifier.
      IDENTIFIER_OFFSET = 5,

      /// \brief Record code for the identifier table.
      ///
      /// The identifier table is a simple blob that contains
      /// NULL-terminated strings for all of the identifiers
      /// referenced by the PCH file. The IDENTIFIER_OFFSET table
      /// contains the mapping from identifier IDs to the characters
      /// in this blob. Note that the starting offsets of all of the
      /// identifiers are odd, so that, when the identifier offset
      /// table is loaded in, we can use the low bit to distinguish
      /// between offsets (for unresolved identifier IDs) and
      /// IdentifierInfo pointers (for already-resolved identifier
      /// IDs).
      IDENTIFIER_TABLE = 6,

      /// \brief Record code for the array of external definitions.
      ///
      /// The PCH file contains a list of all of the unnamed external
      /// definitions present within the parsed headers, stored as an
      /// array of declaration IDs. These external definitions will be
      /// reported to the AST consumer after the PCH file has been
      /// read, since their presence can affect the semantics of the
      /// program (e.g., for code generation).
      EXTERNAL_DEFINITIONS = 7,

      /// \brief Record code for the set of non-builtin, special
      /// types.
      ///
      /// This record contains the type IDs for the various type nodes
      /// that are constructed during semantic analysis (e.g.,
      /// __builtin_va_list). The SPECIAL_TYPE_* constants provide
      /// offsets into this record.
      SPECIAL_TYPES = 8,

      /// \brief Record code for the extra statistics we gather while
      /// generating a PCH file.
      STATISTICS = 9,

      /// \brief Record code for the array of tentative definitions.
      TENTATIVE_DEFINITIONS = 10,

      /// \brief Record code for the array of locally-scoped external
      /// declarations.
      LOCALLY_SCOPED_EXTERNAL_DECLS = 11,

      /// \brief Record code for the table of offsets into the
      /// Objective-C method pool.
      SELECTOR_OFFSETS = 12,

      /// \brief Record code for the Objective-C method pool,
      METHOD_POOL = 13,

      /// \brief The value of the next __COUNTER__ to dispense.
      /// [PP_COUNTER_VALUE, Val]
      PP_COUNTER_VALUE = 14,

      /// \brief Record code for the table of offsets into the block
      /// of source-location information.
      SOURCE_LOCATION_OFFSETS = 15,

      /// \brief Record code for the set of source location entries
      /// that need to be preloaded by the PCH reader.
      ///
      /// This set contains the source location entry for the
      /// predefines buffer and for any file entries that need to be
      /// preloaded.
      SOURCE_LOCATION_PRELOADS = 16,

      /// \brief Record code for the stat() cache.
      STAT_CACHE = 17,

      /// \brief Record code for the set of ext_vector type names.
      EXT_VECTOR_DECLS = 18,

      /// \brief Record code for the original file that was used to
      /// generate the precompiled header.
      ORIGINAL_FILE_NAME = 19,

      /// \brief Record code for the sorted array of source ranges where
      /// comments were encountered in the source code.
      COMMENT_RANGES = 20,
      
      /// \brief Record code for the version control branch and revision
      /// information of the compiler used to build this PCH file.
      VERSION_CONTROL_BRANCH_REVISION = 21,
      
      /// \brief Record code for the array of unused static functions.
      UNUSED_STATIC_FUNCS = 22
      
    };

    /// \brief Record types used within a source manager block.
    enum SourceManagerRecordTypes {
      /// \brief Describes a source location entry (SLocEntry) for a
      /// file.
      SM_SLOC_FILE_ENTRY = 1,
      /// \brief Describes a source location entry (SLocEntry) for a
      /// buffer.
      SM_SLOC_BUFFER_ENTRY = 2,
      /// \brief Describes a blob that contains the data for a buffer
      /// entry. This kind of record always directly follows a
      /// SM_SLOC_BUFFER_ENTRY record.
      SM_SLOC_BUFFER_BLOB = 3,
      /// \brief Describes a source location entry (SLocEntry) for a
      /// macro instantiation.
      SM_SLOC_INSTANTIATION_ENTRY = 4,
      /// \brief Describes the SourceManager's line table, with
      /// information about #line directives.
      SM_LINE_TABLE = 5,
      /// \brief Describes one header file info [isImport, DirInfo, NumIncludes]
      /// ControllingMacro is optional.
      SM_HEADER_FILE_INFO = 6
    };

    /// \brief Record types used within a preprocessor block.
    enum PreprocessorRecordTypes {
      // The macros in the PP section are a PP_MACRO_* instance followed by a
      // list of PP_TOKEN instances for each token in the definition.

      /// \brief An object-like macro definition.
      /// [PP_MACRO_OBJECT_LIKE, IdentInfoID, SLoc, IsUsed]
      PP_MACRO_OBJECT_LIKE = 1,

      /// \brief A function-like macro definition.
      /// [PP_MACRO_FUNCTION_LIKE, <ObjectLikeStuff>, IsC99Varargs, IsGNUVarars,
      ///  NumArgs, ArgIdentInfoID* ]
      PP_MACRO_FUNCTION_LIKE = 2,

      /// \brief Describes one token.
      /// [PP_TOKEN, SLoc, Length, IdentInfoID, Kind, Flags]
      PP_TOKEN = 3
    };

    /// \defgroup PCHAST Precompiled header AST constants
    ///
    /// The constants in this group describe various components of the
    /// abstract syntax tree within a precompiled header.
    ///
    /// @{

    /// \brief Predefined type IDs.
    ///
    /// These type IDs correspond to predefined types in the AST
    /// context, such as built-in types (int) and special place-holder
    /// types (the <overload> and <dependent> type markers). Such
    /// types are never actually serialized, since they will be built
    /// by the AST context when it is created.
    enum PredefinedTypeIDs {
      /// \brief The NULL type.
      PREDEF_TYPE_NULL_ID       = 0,
      /// \brief The void type.
      PREDEF_TYPE_VOID_ID       = 1,
      /// \brief The 'bool' or '_Bool' type.
      PREDEF_TYPE_BOOL_ID       = 2,
      /// \brief The 'char' type, when it is unsigned.
      PREDEF_TYPE_CHAR_U_ID     = 3,
      /// \brief The 'unsigned char' type.
      PREDEF_TYPE_UCHAR_ID      = 4,
      /// \brief The 'unsigned short' type.
      PREDEF_TYPE_USHORT_ID     = 5,
      /// \brief The 'unsigned int' type.
      PREDEF_TYPE_UINT_ID       = 6,
      /// \brief The 'unsigned long' type.
      PREDEF_TYPE_ULONG_ID      = 7,
      /// \brief The 'unsigned long long' type.
      PREDEF_TYPE_ULONGLONG_ID  = 8,
      /// \brief The 'char' type, when it is signed.
      PREDEF_TYPE_CHAR_S_ID     = 9,
      /// \brief The 'signed char' type.
      PREDEF_TYPE_SCHAR_ID      = 10,
      /// \brief The C++ 'wchar_t' type.
      PREDEF_TYPE_WCHAR_ID      = 11,
      /// \brief The (signed) 'short' type.
      PREDEF_TYPE_SHORT_ID      = 12,
      /// \brief The (signed) 'int' type.
      PREDEF_TYPE_INT_ID        = 13,
      /// \brief The (signed) 'long' type.
      PREDEF_TYPE_LONG_ID       = 14,
      /// \brief The (signed) 'long long' type.
      PREDEF_TYPE_LONGLONG_ID   = 15,
      /// \brief The 'float' type.
      PREDEF_TYPE_FLOAT_ID      = 16,
      /// \brief The 'double' type.
      PREDEF_TYPE_DOUBLE_ID     = 17,
      /// \brief The 'long double' type.
      PREDEF_TYPE_LONGDOUBLE_ID = 18,
      /// \brief The placeholder type for overloaded function sets.
      PREDEF_TYPE_OVERLOAD_ID   = 19,
      /// \brief The placeholder type for dependent types.
      PREDEF_TYPE_DEPENDENT_ID  = 20,
      /// \brief The '__uint128_t' type.
      PREDEF_TYPE_UINT128_ID    = 21,
      /// \brief The '__int128_t' type.
      PREDEF_TYPE_INT128_ID     = 22,
      /// \brief The type of 'nullptr'.
      PREDEF_TYPE_NULLPTR_ID    = 23,
      /// \brief The C++ 'char16_t' type.
      PREDEF_TYPE_CHAR16_ID     = 24,
      /// \brief The C++ 'char32_t' type.
      PREDEF_TYPE_CHAR32_ID     = 25,
      /// \brief The ObjC 'id' type.
      PREDEF_TYPE_OBJC_ID       = 26,
      /// \brief The ObjC 'Class' type.
      PREDEF_TYPE_OBJC_CLASS    = 27,
      /// \brief The ObjC 'SEL' type.
      PREDEF_TYPE_OBJC_SEL    = 28
    };

    /// \brief The number of predefined type IDs that are reserved for
    /// the PREDEF_TYPE_* constants.
    ///
    /// Type IDs for non-predefined types will start at
    /// NUM_PREDEF_TYPE_IDs.
    const unsigned NUM_PREDEF_TYPE_IDS = 100;

    /// \brief Record codes for each kind of type.
    ///
    /// These constants describe the type records that can occur within a
    /// block identified by DECLTYPES_BLOCK_ID in the PCH file. Each
    /// constant describes a record for a specific type class in the
    /// AST.
    enum TypeCode {
      /// \brief An ExtQualType record.
      TYPE_EXT_QUAL                 = 1,
      /// \brief A ComplexType record.
      TYPE_COMPLEX                  = 3,
      /// \brief A PointerType record.
      TYPE_POINTER                  = 4,
      /// \brief A BlockPointerType record.
      TYPE_BLOCK_POINTER            = 5,
      /// \brief An LValueReferenceType record.
      TYPE_LVALUE_REFERENCE         = 6,
      /// \brief An RValueReferenceType record.
      TYPE_RVALUE_REFERENCE         = 7,
      /// \brief A MemberPointerType record.
      TYPE_MEMBER_POINTER           = 8,
      /// \brief A ConstantArrayType record.
      TYPE_CONSTANT_ARRAY           = 9,
      /// \brief An IncompleteArrayType record.
      TYPE_INCOMPLETE_ARRAY         = 10,
      /// \brief A VariableArrayType record.
      TYPE_VARIABLE_ARRAY           = 11,
      /// \brief A VectorType record.
      TYPE_VECTOR                   = 12,
      /// \brief An ExtVectorType record.
      TYPE_EXT_VECTOR               = 13,
      /// \brief A FunctionNoProtoType record.
      TYPE_FUNCTION_NO_PROTO        = 14,
      /// \brief A FunctionProtoType record.
      TYPE_FUNCTION_PROTO           = 15,
      /// \brief A TypedefType record.
      TYPE_TYPEDEF                  = 16,
      /// \brief A TypeOfExprType record.
      TYPE_TYPEOF_EXPR              = 17,
      /// \brief A TypeOfType record.
      TYPE_TYPEOF                   = 18,
      /// \brief A RecordType record.
      TYPE_RECORD                   = 19,
      /// \brief An EnumType record.
      TYPE_ENUM                     = 20,
      /// \brief An ObjCInterfaceType record.
      TYPE_OBJC_INTERFACE           = 21,
      /// \brief An ObjCObjectPointerType record.
      TYPE_OBJC_OBJECT_POINTER      = 22,
      /// \brief a DecltypeType record.
      TYPE_DECLTYPE                 = 23,
      /// \brief An ElaboratedType record.
      TYPE_ELABORATED               = 24,
      /// \brief A SubstTemplateTypeParmType record.
      TYPE_SUBST_TEMPLATE_TYPE_PARM = 25,
      /// \brief An UnresolvedUsingType record.
      TYPE_UNRESOLVED_USING         = 26,
      /// \brief An InjectedClassNameType record.
      TYPE_INJECTED_CLASS_NAME      = 27
    };

    /// \brief The type IDs for special types constructed by semantic
    /// analysis.
    ///
    /// The constants in this enumeration are indices into the
    /// SPECIAL_TYPES record.
    enum SpecialTypeIDs {
      /// \brief __builtin_va_list
      SPECIAL_TYPE_BUILTIN_VA_LIST             = 0,
      /// \brief Objective-C "id" type
      SPECIAL_TYPE_OBJC_ID                     = 1,
      /// \brief Objective-C selector type
      SPECIAL_TYPE_OBJC_SELECTOR               = 2,
      /// \brief Objective-C Protocol type
      SPECIAL_TYPE_OBJC_PROTOCOL               = 3,
      /// \brief Objective-C Class type
      SPECIAL_TYPE_OBJC_CLASS                  = 4,
      /// \brief CFConstantString type
      SPECIAL_TYPE_CF_CONSTANT_STRING          = 5,
      /// \brief Objective-C fast enumeration state type
      SPECIAL_TYPE_OBJC_FAST_ENUMERATION_STATE = 6,
      /// \brief C FILE typedef type
      SPECIAL_TYPE_FILE                        = 7,
      /// \brief C jmp_buf typedef type
      SPECIAL_TYPE_jmp_buf                     = 8,
      /// \brief C sigjmp_buf typedef type
      SPECIAL_TYPE_sigjmp_buf                  = 9,
      /// \brief Objective-C "id" redefinition type
      SPECIAL_TYPE_OBJC_ID_REDEFINITION        = 10,
      /// \brief Objective-C "Class" redefinition type
      SPECIAL_TYPE_OBJC_CLASS_REDEFINITION     = 11,
      /// \brief Block descriptor type for Blocks CodeGen
      SPECIAL_TYPE_BLOCK_DESCRIPTOR            = 12,
      /// \brief Block extedned descriptor type for Blocks CodeGen
      SPECIAL_TYPE_BLOCK_EXTENDED_DESCRIPTOR   = 13,
      /// \brief Objective-C "SEL" redefinition type
      SPECIAL_TYPE_OBJC_SEL_REDEFINITION       = 14
    };

    /// \brief Record codes for each kind of declaration.
    ///
    /// These constants describe the declaration records that can occur within
    /// a declarations block (identified by DECLS_BLOCK_ID). Each
    /// constant describes a record for a specific declaration class
    /// in the AST.
    enum DeclCode {
      /// \brief Attributes attached to a declaration.
      DECL_ATTR = 50,
      /// \brief A TranslationUnitDecl record.
      DECL_TRANSLATION_UNIT,
      /// \brief A TypedefDecl record.
      DECL_TYPEDEF,
      /// \brief An EnumDecl record.
      DECL_ENUM,
      /// \brief A RecordDecl record.
      DECL_RECORD,
      /// \brief An EnumConstantDecl record.
      DECL_ENUM_CONSTANT,
      /// \brief A FunctionDecl record.
      DECL_FUNCTION,
      /// \brief A ObjCMethodDecl record.
      DECL_OBJC_METHOD,
      /// \brief A ObjCInterfaceDecl record.
      DECL_OBJC_INTERFACE,
      /// \brief A ObjCProtocolDecl record.
      DECL_OBJC_PROTOCOL,
      /// \brief A ObjCIvarDecl record.
      DECL_OBJC_IVAR,
      /// \brief A ObjCAtDefsFieldDecl record.
      DECL_OBJC_AT_DEFS_FIELD,
      /// \brief A ObjCClassDecl record.
      DECL_OBJC_CLASS,
      /// \brief A ObjCForwardProtocolDecl record.
      DECL_OBJC_FORWARD_PROTOCOL,
      /// \brief A ObjCCategoryDecl record.
      DECL_OBJC_CATEGORY,
      /// \brief A ObjCCategoryImplDecl record.
      DECL_OBJC_CATEGORY_IMPL,
      /// \brief A ObjCImplementationDecl record.
      DECL_OBJC_IMPLEMENTATION,
      /// \brief A ObjCCompatibleAliasDecl record.
      DECL_OBJC_COMPATIBLE_ALIAS,
      /// \brief A ObjCPropertyDecl record.
      DECL_OBJC_PROPERTY,
      /// \brief A ObjCPropertyImplDecl record.
      DECL_OBJC_PROPERTY_IMPL,
      /// \brief A FieldDecl record.
      DECL_FIELD,
      /// \brief A VarDecl record.
      DECL_VAR,
      /// \brief An ImplicitParamDecl record.
      DECL_IMPLICIT_PARAM,
      /// \brief A ParmVarDecl record.
      DECL_PARM_VAR,
      /// \brief A FileScopeAsmDecl record.
      DECL_FILE_SCOPE_ASM,
      /// \brief A BlockDecl record.
      DECL_BLOCK,
      /// \brief A record that stores the set of declarations that are
      /// lexically stored within a given DeclContext.
      ///
      /// The record itself is an array of declaration IDs, in the
      /// order in which those declarations were added to the
      /// declaration context. This data is used when iterating over
      /// the contents of a DeclContext, e.g., via
      /// DeclContext::decls_begin()/DeclContext::decls_end().
      DECL_CONTEXT_LEXICAL,
      /// \brief A record that stores the set of declarations that are
      /// visible from a given DeclContext.
      ///
      /// The record itself stores a set of mappings, each of which
      /// associates a declaration name with one or more declaration
      /// IDs. This data is used when performing qualified name lookup
      /// into a DeclContext via DeclContext::lookup.
      DECL_CONTEXT_VISIBLE,
      /// \brief A NamespaceDecl record.
      DECL_NAMESPACE
    };

    /// \brief Record codes for each kind of statement or expression.
    ///
    /// These constants describe the records that describe statements
    /// or expressions. These records  occur within type and declarations
    /// block, so they begin with record values of 100.  Each constant 
    /// describes a record for a specific statement or expression class in the
    /// AST.
    enum StmtCode {
      /// \brief A marker record that indicates that we are at the end
      /// of an expression.
      STMT_STOP = 100,
      /// \brief A NULL expression.
      STMT_NULL_PTR,
      /// \brief A NullStmt record.
      STMT_NULL,
      /// \brief A CompoundStmt record.
      STMT_COMPOUND,
      /// \brief A CaseStmt record.
      STMT_CASE,
      /// \brief A DefaultStmt record.
      STMT_DEFAULT,
      /// \brief A LabelStmt record.
      STMT_LABEL,
      /// \brief An IfStmt record.
      STMT_IF,
      /// \brief A SwitchStmt record.
      STMT_SWITCH,
      /// \brief A WhileStmt record.
      STMT_WHILE,
      /// \brief A DoStmt record.
      STMT_DO,
      /// \brief A ForStmt record.
      STMT_FOR,
      /// \brief A GotoStmt record.
      STMT_GOTO,
      /// \brief An IndirectGotoStmt record.
      STMT_INDIRECT_GOTO,
      /// \brief A ContinueStmt record.
      STMT_CONTINUE,
      /// \brief A BreakStmt record.
      STMT_BREAK,
      /// \brief A ReturnStmt record.
      STMT_RETURN,
      /// \brief A DeclStmt record.
      STMT_DECL,
      /// \brief An AsmStmt record.
      STMT_ASM,
      /// \brief A PredefinedExpr record.
      EXPR_PREDEFINED,
      /// \brief A DeclRefExpr record.
      EXPR_DECL_REF,
      /// \brief An IntegerLiteral record.
      EXPR_INTEGER_LITERAL,
      /// \brief A FloatingLiteral record.
      EXPR_FLOATING_LITERAL,
      /// \brief An ImaginaryLiteral record.
      EXPR_IMAGINARY_LITERAL,
      /// \brief A StringLiteral record.
      EXPR_STRING_LITERAL,
      /// \brief A CharacterLiteral record.
      EXPR_CHARACTER_LITERAL,
      /// \brief A ParenExpr record.
      EXPR_PAREN,
      /// \brief A UnaryOperator record.
      EXPR_UNARY_OPERATOR,
      /// \brief A SizefAlignOfExpr record.
      EXPR_SIZEOF_ALIGN_OF,
      /// \brief An ArraySubscriptExpr record.
      EXPR_ARRAY_SUBSCRIPT,
      /// \brief A CallExpr record.
      EXPR_CALL,
      /// \brief A MemberExpr record.
      EXPR_MEMBER,
      /// \brief A BinaryOperator record.
      EXPR_BINARY_OPERATOR,
      /// \brief A CompoundAssignOperator record.
      EXPR_COMPOUND_ASSIGN_OPERATOR,
      /// \brief A ConditionOperator record.
      EXPR_CONDITIONAL_OPERATOR,
      /// \brief An ImplicitCastExpr record.
      EXPR_IMPLICIT_CAST,
      /// \brief A CStyleCastExpr record.
      EXPR_CSTYLE_CAST,
      /// \brief A CompoundLiteralExpr record.
      EXPR_COMPOUND_LITERAL,
      /// \brief An ExtVectorElementExpr record.
      EXPR_EXT_VECTOR_ELEMENT,
      /// \brief An InitListExpr record.
      EXPR_INIT_LIST,
      /// \brief A DesignatedInitExpr record.
      EXPR_DESIGNATED_INIT,
      /// \brief An ImplicitValueInitExpr record.
      EXPR_IMPLICIT_VALUE_INIT,
      /// \brief A VAArgExpr record.
      EXPR_VA_ARG,
      /// \brief An AddrLabelExpr record.
      EXPR_ADDR_LABEL,
      /// \brief A StmtExpr record.
      EXPR_STMT,
      /// \brief A TypesCompatibleExpr record.
      EXPR_TYPES_COMPATIBLE,
      /// \brief A ChooseExpr record.
      EXPR_CHOOSE,
      /// \brief A GNUNullExpr record.
      EXPR_GNU_NULL,
      /// \brief A ShuffleVectorExpr record.
      EXPR_SHUFFLE_VECTOR,
      /// \brief BlockExpr
      EXPR_BLOCK,
      /// \brief A BlockDeclRef record.
      EXPR_BLOCK_DECL_REF,
      
      // Objective-C

      /// \brief An ObjCStringLiteral record.
      EXPR_OBJC_STRING_LITERAL,
      /// \brief An ObjCEncodeExpr record.
      EXPR_OBJC_ENCODE,
      /// \brief An ObjCSelectorExpr record.
      EXPR_OBJC_SELECTOR_EXPR,
      /// \brief An ObjCProtocolExpr record.
      EXPR_OBJC_PROTOCOL_EXPR,
      /// \brief An ObjCIvarRefExpr record.
      EXPR_OBJC_IVAR_REF_EXPR,
      /// \brief An ObjCPropertyRefExpr record.
      EXPR_OBJC_PROPERTY_REF_EXPR,
      /// \brief An ObjCImplicitSetterGetterRefExpr record.
      EXPR_OBJC_KVC_REF_EXPR,
      /// \brief An ObjCMessageExpr record.
      EXPR_OBJC_MESSAGE_EXPR,
      /// \brief An ObjCSuperExpr record.
      EXPR_OBJC_SUPER_EXPR,
      /// \brief An ObjCIsa Expr record.
      EXPR_OBJC_ISA,

      /// \brief An ObjCForCollectionStmt record.
      STMT_OBJC_FOR_COLLECTION,
      /// \brief An ObjCAtCatchStmt record.
      STMT_OBJC_CATCH,
      /// \brief An ObjCAtFinallyStmt record.
      STMT_OBJC_FINALLY,
      /// \brief An ObjCAtTryStmt record.
      STMT_OBJC_AT_TRY,
      /// \brief An ObjCAtSynchronizedStmt record.
      STMT_OBJC_AT_SYNCHRONIZED,
      /// \brief An ObjCAtThrowStmt record.
      STMT_OBJC_AT_THROW,

      // C++

      /// \brief A CXXOperatorCallExpr record.
      EXPR_CXX_OPERATOR_CALL,
      /// \brief A CXXConstructExpr record.
      EXPR_CXX_CONSTRUCT,
      // \brief A CXXStaticCastExpr record.
      EXPR_CXX_STATIC_CAST,
      // \brief A CXXDynamicCastExpr record.
      EXPR_CXX_DYNAMIC_CAST,
      // \brief A CXXReinterpretCastExpr record.
      EXPR_CXX_REINTERPRET_CAST,
      // \brief A CXXConstCastExpr record.
      EXPR_CXX_CONST_CAST,
      // \brief A CXXFunctionalCastExpr record.
      EXPR_CXX_FUNCTIONAL_CAST,
      // \brief A CXXBoolLiteralExpr record.
      EXPR_CXX_BOOL_LITERAL,
      // \brief A CXXNullPtrLiteralExpr record.
      EXPR_CXX_NULL_PTR_LITERAL
    };

    /// \brief The kinds of designators that can occur in a
    /// DesignatedInitExpr.
    enum DesignatorTypes {
      /// \brief Field designator where only the field name is known.
      DESIG_FIELD_NAME  = 0,
      /// \brief Field designator where the field has been resolved to
      /// a declaration.
      DESIG_FIELD_DECL  = 1,
      /// \brief Array designator.
      DESIG_ARRAY       = 2,
      /// \brief GNU array range designator.
      DESIG_ARRAY_RANGE = 3
    };

    /// @}
  }
} // end namespace clang

#endif
