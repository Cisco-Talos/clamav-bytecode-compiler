#===- cindex.py - Python Indexing Library Bindings -----------*- python -*--===#
#
#                     The LLVM Compiler Infrastructure
#
# This file is distributed under the University of Illinois Open Source
# License. See LICENSE.TXT for details.
#
#===------------------------------------------------------------------------===#

r"""
Clang Indexing Library Bindings
===============================

This module provides an interface to the Clang indexing library. It is a
low-level interface to the indexing library which attempts to match the Clang
API directly while also being "pythonic". Notable differences from the C API
are:

 * string results are returned as Python strings, not CXString objects.

 * null cursors are translated to None.

 * access to child cursors is done via iteration, not visitation.

The major indexing objects are:

  Index

    The top-level object which manages some global library state.

  TranslationUnit

    High-level object encapsulating the AST for a single translation unit. These
    can be loaded from .ast files or parsed on the fly.

  Cursor

    Generic object for representing a node in the AST.

  SourceRange, SourceLocation, and File

    Objects representing information about the input source.

Most object information is exposed using properties, when the underlying API
call is efficient.
"""

# TODO
# ====
#
# o API support for invalid translation units. Currently we can't even get the
#   diagnostics on failure because they refer to locations in an object that
#   will have been invalidated.
#
# o fix memory management issues (currently client must hold on to index and
#   translation unit, or risk crashes).
#
# o expose code completion APIs.
#
# o cleanup ctypes wrapping, would be nice to separate the ctypes details more
#   clearly, and hide from the external interface (i.e., help(cindex)).
#
# o implement additional SourceLocation, SourceRange, and File methods.

from ctypes import *

def get_cindex_library():
    # FIXME: It's probably not the case that the library is actually found in
    # this location. We need a better system of identifying and loading the
    # CIndex library. It could be on path or elsewhere, or versioned, etc.
    import platform
    name = platform.system()
    if name == 'Darwin':
        return cdll.LoadLibrary('libCIndex.dylib')
    elif name == 'Windows':
        return cdll.LoadLibrary('libCIndex.dll')
    else:
        return cdll.LoadLibrary('libCIndex.so')

# ctypes doesn't implicitly convert c_void_p to the appropriate wrapper
# object. This is a problem, because it means that from_parameter will see an
# integer and pass the wrong value on platforms where int != void*. Work around
# this by marshalling object arguments as void**.
c_object_p = POINTER(c_void_p)

lib = get_cindex_library()

### Structures and Utility Classes ###

class _CXString(Structure):
    """Helper for transforming CXString results."""

    _fields_ = [("spelling", c_char_p), ("free", c_int)]

    def __del__(self):
        _CXString_dispose(self)

    @staticmethod
    def from_result(res, fn, args):
        assert isinstance(res, _CXString)
        return _CXString_getCString(res)

class SourceLocation(Structure):
    """
    A SourceLocation represents a particular location within a source file.
    """
    _fields_ = [("ptr_data", c_void_p * 2), ("int_data", c_uint)]
    _data = None

    def _get_instantiation(self):
        if self._data is None:
            f, l, c, o = c_object_p(), c_uint(), c_uint(), c_uint()
            SourceLocation_loc(self, byref(f), byref(l), byref(c), byref(o))
            f = File(f) if f else None
            self._data = (f, int(l.value), int(c.value), int(c.value))
        return self._data

    @property
    def file(self):
        """Get the file represented by this source location."""
        return self._get_instantiation()[0]

    @property
    def line(self):
        """Get the line represented by this source location."""
        return self._get_instantiation()[1]

    @property
    def column(self):
        """Get the column represented by this source location."""
        return self._get_instantiation()[2]

    @property
    def offset(self):
        """Get the file offset represented by this source location."""
        return self._get_instantiation()[3]

    def __repr__(self):
        return "<SourceLocation file %r, line %r, column %r>" % (
            self.file.name if self.file else None, self.line, self.column)

class SourceRange(Structure):
    """
    A SourceRange describes a range of source locations within the source
    code.
    """
    _fields_ = [
        ("ptr_data", c_void_p * 2),
        ("begin_int_data", c_uint),
        ("end_int_data", c_uint)]

    # FIXME: Eliminate this and make normal constructor? Requires hiding ctypes
    # object.
    @staticmethod
    def from_locations(start, end):
        return SourceRange_getRange(start, end)

    @property
    def start(self):
        """
        Return a SourceLocation representing the first character within a
        source range.
        """
        return SourceRange_start(self)

    @property
    def end(self):
        """
        Return a SourceLocation representing the last character within a
        source range.
        """
        return SourceRange_end(self)

    def __repr__(self):
        return "<SourceRange start %r, end %r>" % (self.start, self.end)

class Diagnostic(object):
    """
    A Diagnostic is a single instance of a Clang diagnostic. It includes the
    diagnostic severity, the message, the location the diagnostic occurred, as
    well as additional source ranges and associated fix-it hints.
    """

    Ignored = 0
    Note    = 1
    Warning = 2
    Error   = 3
    Fatal   = 4

    def __init__(self, severity, location, spelling, ranges, fixits):
        self.severity = severity
        self.location = location
        self.spelling = spelling
        self.ranges = ranges
        self.fixits = fixits

    def __repr__(self):
        return "<Diagnostic severity %r, location %r, spelling %r>" % (
            self.severity, self.location, self.spelling)

class FixIt(object):
    """
    A FixIt represents a transformation to be applied to the source to
    "fix-it". The fix-it shouldbe applied by replacing the given source range
    with the given value.
    """

    def __init__(self, range, value):
        self.range = range
        self.value = value

    def __repr__(self):
        return "<FixIt range %r, value %r>" % (self.range, self.value)

### Cursor Kinds ###

class CursorKind(object):
    """
    A CursorKind describes the kind of entity that a cursor points to.
    """

    # The unique kind objects, indexed by id.
    _kinds = []
    _name_map = None

    def __init__(self, value):
        if value >= len(CursorKind._kinds):
            CursorKind._kinds += [None] * (value - len(CursorKind._kinds) + 1)
        if CursorKind._kinds[value] is not None:
            raise ValueError,'CursorKind already loaded'
        self.value = value
        CursorKind._kinds[value] = self
        CursorKind._name_map = None

    def from_param(self):
        return self.value

    @property
    def name(self):
        """Get the enumeration name of this cursor kind."""
        if self._name_map is None:
            self._name_map = {}
            for key,value in CursorKind.__dict__.items():
                if isinstance(value,CursorKind):
                    self._name_map[value] = key
        return self._name_map[self]

    @staticmethod
    def from_id(id):
        if id >= len(CursorKind._kinds) or CursorKind._kinds[id] is None:
            raise ValueError,'Unknown cursor kind'
        return CursorKind._kinds[id]

    @staticmethod
    def get_all_kinds():
        """Return all CursorKind enumeration instances."""
        return filter(None, CursorKind._kinds)

    def is_declaration(self):
        """Test if this is a declaration kind."""
        return CursorKind_is_decl(self)

    def is_reference(self):
        """Test if this is a reference kind."""
        return CursorKind_is_ref(self)

    def is_expression(self):
        """Test if this is an expression kind."""
        return CursorKind_is_expr(self)

    def is_statement(self):
        """Test if this is a statement kind."""
        return CursorKind_is_stmt(self)

    def is_invalid(self):
        """Test if this is an invalid kind."""
        return CursorKind_is_inv(self)

    def __repr__(self):
        return 'CursorKind.%s' % (self.name,)

# FIXME: Is there a nicer way to expose this enumeration? We could potentially
# represent the nested structure, or even build a class hierarchy. The main
# things we want for sure are (a) simple external access to kinds, (b) a place
# to hang a description and name, (c) easy to keep in sync with Index.h.

###
# Declaration Kinds

# A declaration whose specific kind is not exposed via this interface.
#
# Unexposed declarations have the same operations as any other kind of
# declaration; one can extract their location information, spelling, find their
# definitions, etc. However, the specific kind of the declaration is not
# reported.
CursorKind.UNEXPOSED_DECL = CursorKind(1)

# A C or C++ struct.
CursorKind.STRUCT_DECL = CursorKind(2)

# A C or C++ union.
CursorKind.UNION_DECL = CursorKind(3)

# A C++ class.
CursorKind.CLASS_DECL = CursorKind(4)

# An enumeration.
CursorKind.ENUM_DECL = CursorKind(5)

# A field (in C) or non-static data member (in C++) in a struct, union, or C++
# class.
CursorKind.FIELD_DECL = CursorKind(6)

# An enumerator constant.
CursorKind.ENUM_CONSTANT_DECL = CursorKind(7)

# A function.
CursorKind.FUNCTION_DECL = CursorKind(8)

# A variable.
CursorKind.VAR_DECL = CursorKind(9)

# A function or method parameter.
CursorKind.PARM_DECL = CursorKind(10)

# An Objective-C @interface.
CursorKind.OBJC_INTERFACE_DECL = CursorKind(11)

# An Objective-C @interface for a category.
CursorKind.OBJC_CATEGORY_DECL = CursorKind(12)

# An Objective-C @protocol declaration.
CursorKind.OBJC_PROTOCOL_DECL = CursorKind(13)

# An Objective-C @property declaration.
CursorKind.OBJC_PROPERTY_DECL = CursorKind(14)

# An Objective-C instance variable.
CursorKind.OBJC_IVAR_DECL = CursorKind(15)

# An Objective-C instance method.
CursorKind.OBJC_INSTANCE_METHOD_DECL = CursorKind(16)

# An Objective-C class method.
CursorKind.OBJC_CLASS_METHOD_DECL = CursorKind(17)

# An Objective-C @implementation.
CursorKind.OBJC_IMPLEMENTATION_DECL = CursorKind(18)

# An Objective-C @implementation for a category.
CursorKind.OBJC_CATEGORY_IMPL_DECL = CursorKind(19)

# A typedef.
CursorKind.TYPEDEF_DECL = CursorKind(20)

###
# Reference Kinds

CursorKind.OBJC_SUPER_CLASS_REF = CursorKind(40)
CursorKind.OBJC_PROTOCOL_REF = CursorKind(41)
CursorKind.OBJC_CLASS_REF = CursorKind(42)

# A reference to a type declaration.
#
# A type reference occurs anywhere where a type is named but not
# declared. For example, given:
#   typedef unsigned size_type;
#   size_type size;
#
# The typedef is a declaration of size_type (CXCursor_TypedefDecl),
# while the type of the variable "size" is referenced. The cursor
# referenced by the type of size is the typedef for size_type.
CursorKind.TYPE_REF = CursorKind(43)

###
# Invalid/Error Kinds

CursorKind.INVALID_FILE = CursorKind(70)
CursorKind.NO_DECL_FOUND = CursorKind(71)
CursorKind.NOT_IMPLEMENTED = CursorKind(72)

###
# Expression Kinds

# An expression whose specific kind is not exposed via this interface.
#
# Unexposed expressions have the same operations as any other kind of
# expression; one can extract their location information, spelling, children,
# etc. However, the specific kind of the expression is not reported.
CursorKind.UNEXPOSED_EXPR = CursorKind(100)

# An expression that refers to some value declaration, such as a function,
# varible, or enumerator.
CursorKind.DECL_REF_EXPR = CursorKind(101)

# An expression that refers to a member of a struct, union, class, Objective-C
# class, etc.
CursorKind.MEMBER_REF_EXPR = CursorKind(102)

# An expression that calls a function.
CursorKind.CALL_EXPR = CursorKind(103)

# An expression that sends a message to an Objective-C object or class.
CursorKind.OBJC_MESSAGE_EXPR = CursorKind(104)

# A statement whose specific kind is not exposed via this interface.
#
# Unexposed statements have the same operations as any other kind of statement;
# one can extract their location information, spelling, children, etc. However,
# the specific kind of the statement is not reported.
CursorKind.UNEXPOSED_STMT = CursorKind(200)

###
# Other Kinds

# Cursor that represents the translation unit itself.
#
# The translation unit cursor exists primarily to act as the root cursor for
# traversing the contents of a translation unit.
CursorKind.TRANSLATION_UNIT = CursorKind(300)

### Cursors ###

class Cursor(Structure):
    """
    The Cursor class represents a reference to an element within the AST. It
    acts as a kind of iterator.
    """
    _fields_ = [("_kind_id", c_int), ("data", c_void_p * 3)]

    def __eq__(self, other):
        return Cursor_eq(self, other)

    def __ne__(self, other):
        return not Cursor_eq(self, other)

    def is_definition(self):
        """
        Returns true if the declaration pointed at by the cursor is also a
        definition of that entity.
        """
        return Cursor_is_def(self)

    def get_definition(self):
        """
        If the cursor is a reference to a declaration or a declaration of
        some entity, return a cursor that points to the definition of that
        entity.
        """
        # TODO: Should probably check that this is either a reference or
        # declaration prior to issuing the lookup.
        return Cursor_def(self)

    def get_usr(self):
        """Return the Unified Symbol Resultion (USR) for the entity referenced
        by the given cursor (or None).

        A Unified Symbol Resolution (USR) is a string that identifies a
        particular entity (function, class, variable, etc.) within a
        program. USRs can be compared across translation units to determine,
        e.g., when references in one translation refer to an entity defined in
        another translation unit."""
        return Cursor_usr(self)

    @property
    def kind(self):
        """Return the kind of this cursor."""
        return CursorKind.from_id(self._kind_id)

    @property
    def spelling(self):
        """Return the spelling of the entity pointed at by the cursor."""
        if not self.kind.is_declaration():
            # FIXME: clang_getCursorSpelling should be fixed to not assert on
            # this, for consistency with clang_getCursorUSR.
            return None
        return Cursor_spelling(self)

    @property
    def location(self):
        """
        Return the source location (the starting character) of the entity
        pointed at by the cursor.
        """
        return Cursor_loc(self)

    @property
    def extent(self):
        """
        Return the source range (the range of text) occupied by the entity
        pointed at by the cursor.
        """
        return Cursor_extent(self)

    def get_children(self):
        """Return an iterator for accessing the children of this cursor."""

        # FIXME: Expose iteration from CIndex, PR6125.
        def visitor(child, parent, children):
            # FIXME: Document this assertion in API.
            # FIXME: There should just be an isNull method.
            assert child != Cursor_null()
            children.append(child)
            return 1 # continue
        children = []
        Cursor_visit(self, Cursor_visit_callback(visitor), children)
        return iter(children)

    @staticmethod
    def from_result(res, fn, args):
        assert isinstance(res, Cursor)
        # FIXME: There should just be an isNull method.
        if res == Cursor_null():
            return None
        return res

## CIndex Objects ##

# CIndex objects (derived from ClangObject) are essentially lightweight
# wrappers attached to some underlying object, which is exposed via CIndex as
# a void*.

class ClangObject(object):
    """
    A helper for Clang objects. This class helps act as an intermediary for
    the ctypes library and the Clang CIndex library.
    """
    def __init__(self, obj):
        assert isinstance(obj, c_object_p) and obj
        self.obj = self._as_parameter_ = obj

    def from_param(self):
        return self._as_parameter_


class _CXUnsavedFile(Structure):
    """Helper for passing unsaved file arguments."""
    _fields_ = [("name", c_char_p), ("contents", c_char_p), ('length', c_ulong)]

## Diagnostic Conversion ##

# Diagnostic objects are temporary, we must extract all the information from the
# diagnostic object when it is passed to the callback.

_clang_getDiagnosticSeverity = lib.clang_getDiagnosticSeverity
_clang_getDiagnosticSeverity.argtypes = [c_object_p]
_clang_getDiagnosticSeverity.restype = c_int

_clang_getDiagnosticLocation = lib.clang_getDiagnosticLocation
_clang_getDiagnosticLocation.argtypes = [c_object_p]
_clang_getDiagnosticLocation.restype = SourceLocation

_clang_getDiagnosticSpelling = lib.clang_getDiagnosticSpelling
_clang_getDiagnosticSpelling.argtypes = [c_object_p]
_clang_getDiagnosticSpelling.restype = _CXString
_clang_getDiagnosticSpelling.errcheck = _CXString.from_result

_clang_getDiagnosticRanges = lib.clang_getDiagnosticRanges
_clang_getDiagnosticRanges.argtypes = [c_object_p,
                                       POINTER(POINTER(SourceRange)),
                                       POINTER(c_uint)]
_clang_getDiagnosticRanges.restype = None

_clang_disposeDiagnosticRanges = lib.clang_disposeDiagnosticRanges
_clang_disposeDiagnosticRanges.argtypes = [POINTER(SourceRange), c_uint]
_clang_disposeDiagnosticRanges.restype = None

_clang_getDiagnosticNumFixIts = lib.clang_getDiagnosticNumFixIts
_clang_getDiagnosticNumFixIts.argtypes = [c_object_p]
_clang_getDiagnosticNumFixIts.restype = c_uint

_clang_getDiagnosticFixItKind = lib.clang_getDiagnosticFixItKind
_clang_getDiagnosticFixItKind.argtypes = [c_object_p, c_uint]
_clang_getDiagnosticFixItKind.restype = c_int

_clang_getDiagnosticFixItInsertion = lib.clang_getDiagnosticFixItInsertion
_clang_getDiagnosticFixItInsertion.argtypes = [c_object_p, c_uint,
                                               POINTER(SourceLocation)]
_clang_getDiagnosticFixItInsertion.restype = _CXString
_clang_getDiagnosticFixItInsertion.errcheck = _CXString.from_result

_clang_getDiagnosticFixItRemoval = lib.clang_getDiagnosticFixItRemoval
_clang_getDiagnosticFixItRemoval.argtypes = [c_object_p, c_uint,
                                             POINTER(SourceLocation)]
_clang_getDiagnosticFixItRemoval.restype = _CXString
_clang_getDiagnosticFixItRemoval.errcheck = _CXString.from_result

_clang_getDiagnosticFixItReplacement = lib.clang_getDiagnosticFixItReplacement
_clang_getDiagnosticFixItReplacement.argtypes = [c_object_p, c_uint,
                                                 POINTER(SourceRange)]
_clang_getDiagnosticFixItReplacement.restype = _CXString
_clang_getDiagnosticFixItReplacement.errcheck = _CXString.from_result

def _convert_fixit(diag_ptr, index):
    # We normalize all the fix-its to a single representation, this is more
    # convenient.
    #
    # FIXME: Push this back into API? It isn't exactly clear what the
    # SourceRange semantics are, we should make sure we can represent an empty
    # range.
    kind = _clang_getDiagnosticFixItKind(diag_ptr, index)
    range = None
    value = None
    if kind == 0: # insertion
        location = SourceLocation()
        value = _clang_getDiagnosticFixItInsertion(diag_ptr, index,
                                                   byref(location))
        range = SourceRange.from_locations(location, location)
    elif kind == 1: # removal
        range = _clang_getDiagnosticFixItRemoval(diag_ptr, index)
        value = ''
    else: # replacement
        assert kind == 2
        range = SourceRange()
        value = _clang_getDiagnosticFixItReplacement(diag_ptr, index,
                                                     byref(range))
    return FixIt(range, value)

def _convert_diag(diag_ptr, diag_list):
    severity = _clang_getDiagnosticSeverity(diag_ptr)
    loc = _clang_getDiagnosticLocation(diag_ptr)
    spelling = _clang_getDiagnosticSpelling(diag_ptr)

    # Diagnostic ranges.
    #
    # FIXME: Use getNum... based API?
    num_ranges = c_uint()
    ranges_array = POINTER(SourceRange)()
    _clang_getDiagnosticRanges(diag_ptr, byref(ranges_array), byref(num_ranges))

    # Copy the ranges array so we can dispose the original.
    ranges = [SourceRange.from_buffer_copy(ranges_array[i])
              for i in range(num_ranges.value)]
    _clang_disposeDiagnosticRanges(ranges_array, num_ranges)

    fixits = [_convert_fixit(diag_ptr, i)
              for i in range(_clang_getDiagnosticNumFixIts(diag_ptr))]

    diag_list.append(Diagnostic(severity, loc, spelling, ranges, fixits))

###

class Index(ClangObject):
    """
    The Index type provides the primary interface to the Clang CIndex library,
    primarily by providing an interface for reading and parsing translation
    units.
    """

    @staticmethod
    def create(excludeDecls=False):
        """
        Create a new Index.
        Parameters:
        excludeDecls -- Exclude local declarations from translation units.
        """
        return Index(Index_create(excludeDecls))

    def __del__(self):
        Index_dispose(self)

    def read(self, path):
        """Load the translation unit from the given AST file."""
        # FIXME: In theory, we could support streaming diagnostics. It's hard to
        # integrate this into the API cleanly, however. Resolve.
        diags = []
        ptr = TranslationUnit_read(self, path,
                                   Diagnostic_callback(_convert_diag), diags)
        return TranslationUnit(ptr) if ptr else None

    def parse(self, path, args = [], unsaved_files = []):
        """
        Load the translation unit from the given source code file by running
        clang and generating the AST before loading. Additional command line
        parameters can be passed to clang via the args parameter.

        In-memory contents for files can be provided by passing a list of pairs
        to as unsaved_files, the first item should be the filenames to be mapped
        and the second should be the contents to be substituted for the
        file. The contents may be passed as strings or file objects.
        """
        arg_array = 0
        if len(args):
            arg_array = (c_char_p * len(args))(* args)
        unsaved_files_array = 0
        if len(unsaved_files):
            unsaved_files_array = (_CXUnsavedFile * len(unsaved_files))()
            for i,(name,value) in enumerate(unsaved_files):
                if not isinstance(value, str):
                    # FIXME: It would be great to support an efficient version
                    # of this, one day.
                    value = value.read()
                    print value
                if not isinstance(value, str):
                    raise TypeError,'Unexpected unsaved file contents.'
                unsaved_files_array[i].name = name
                unsaved_files_array[i].contents = value
                unsaved_files_array[i].length = len(value)
        # FIXME: In theory, we could support streaming diagnostics. It's hard to
        # integrate this into the API cleanly, however. Resolve.
        diags = []
        ptr = TranslationUnit_parse(self, path, len(args), arg_array,
                                    len(unsaved_files), unsaved_files_array,
                                    Diagnostic_callback(_convert_diag), diags)
        return TranslationUnit(ptr, diags) if ptr else None


class TranslationUnit(ClangObject):
    """
    The TranslationUnit class represents a source code translation unit and
    provides read-only access to its top-level declarations.
    """

    def __init__(self, ptr, diagnostics):
        ClangObject.__init__(self, ptr)
        self.diagnostics = diagnostics

    def __del__(self):
        TranslationUnit_dispose(self)

    @property
    def cursor(self):
        """Retrieve the cursor that represents the given translation unit."""
        return TranslationUnit_cursor(self)

    @property
    def spelling(self):
        """Get the original translation unit source file name."""
        return TranslationUnit_spelling(self)

class File(ClangObject):
    """
    The File class represents a particular source file that is part of a
    translation unit.
    """

    @property
    def name(self):
        """Return the complete file and path name of the file."""
        return File_name(self)

    @property
    def time(self):
        """Return the last modification time of the file."""
        return File_time(self)

# Additional Functions and Types

# String Functions
_CXString_dispose = lib.clang_disposeString
_CXString_dispose.argtypes = [_CXString]

_CXString_getCString = lib.clang_getCString
_CXString_getCString.argtypes = [_CXString]
_CXString_getCString.restype = c_char_p

# Source Location Functions
SourceLocation_loc = lib.clang_getInstantiationLocation
SourceLocation_loc.argtypes = [SourceLocation, POINTER(c_object_p),
                               POINTER(c_uint), POINTER(c_uint),
                               POINTER(c_uint)]

# Source Range Functions
SourceRange_getRange = lib.clang_getRange
SourceRange_getRange.argtypes = [SourceLocation, SourceLocation]
SourceRange_getRange.restype = SourceRange

SourceRange_start = lib.clang_getRangeStart
SourceRange_start.argtypes = [SourceRange]
SourceRange_start.restype = SourceLocation

SourceRange_end = lib.clang_getRangeEnd
SourceRange_end.argtypes = [SourceRange]
SourceRange_end.restype = SourceLocation

# CursorKind Functions
CursorKind_is_decl = lib.clang_isDeclaration
CursorKind_is_decl.argtypes = [CursorKind]
CursorKind_is_decl.restype = bool

CursorKind_is_ref = lib.clang_isReference
CursorKind_is_ref.argtypes = [CursorKind]
CursorKind_is_ref.restype = bool

CursorKind_is_expr = lib.clang_isExpression
CursorKind_is_expr.argtypes = [CursorKind]
CursorKind_is_expr.restype = bool

CursorKind_is_stmt = lib.clang_isStatement
CursorKind_is_stmt.argtypes = [CursorKind]
CursorKind_is_stmt.restype = bool

CursorKind_is_inv = lib.clang_isInvalid
CursorKind_is_inv.argtypes = [CursorKind]
CursorKind_is_inv.restype = bool

# Cursor Functions
# TODO: Implement this function
Cursor_get = lib.clang_getCursor
Cursor_get.argtypes = [TranslationUnit, SourceLocation]
Cursor_get.restype = Cursor

Cursor_null = lib.clang_getNullCursor
Cursor_null.restype = Cursor

Cursor_usr = lib.clang_getCursorUSR
Cursor_usr.argtypes = [Cursor]
Cursor_usr.restype = _CXString
Cursor_usr.errcheck = _CXString.from_result

Cursor_is_def = lib.clang_isCursorDefinition
Cursor_is_def.argtypes = [Cursor]
Cursor_is_def.restype = bool

Cursor_def = lib.clang_getCursorDefinition
Cursor_def.argtypes = [Cursor]
Cursor_def.restype = Cursor
Cursor_def.errcheck = Cursor.from_result

Cursor_eq = lib.clang_equalCursors
Cursor_eq.argtypes = [Cursor, Cursor]
Cursor_eq.restype = c_uint

Cursor_spelling = lib.clang_getCursorSpelling
Cursor_spelling.argtypes = [Cursor]
Cursor_spelling.restype = _CXString
Cursor_spelling.errcheck = _CXString.from_result

Cursor_loc = lib.clang_getCursorLocation
Cursor_loc.argtypes = [Cursor]
Cursor_loc.restype = SourceLocation

Cursor_extent = lib.clang_getCursorExtent
Cursor_extent.argtypes = [Cursor]
Cursor_extent.restype = SourceRange

Cursor_ref = lib.clang_getCursorReferenced
Cursor_ref.argtypes = [Cursor]
Cursor_ref.restype = Cursor
Cursor_ref.errcheck = Cursor.from_result

Cursor_visit_callback = CFUNCTYPE(c_int, Cursor, Cursor, py_object)
Cursor_visit = lib.clang_visitChildren
Cursor_visit.argtypes = [Cursor, Cursor_visit_callback, py_object]
Cursor_visit.restype = c_uint

# Index Functions
Index_create = lib.clang_createIndex
Index_create.argtypes = [c_int]
Index_create.restype = c_object_p

Index_dispose = lib.clang_disposeIndex
Index_dispose.argtypes = [Index]

# Translation Unit Functions
Diagnostic_callback = CFUNCTYPE(None, c_object_p, py_object)

TranslationUnit_read = lib.clang_createTranslationUnit
TranslationUnit_read.argtypes = [Index, c_char_p,
                                 Diagnostic_callback, py_object]
TranslationUnit_read.restype = c_object_p

TranslationUnit_parse = lib.clang_createTranslationUnitFromSourceFile
TranslationUnit_parse.argtypes = [Index, c_char_p, c_int, c_void_p,
                                  c_int, c_void_p,
                                  Diagnostic_callback, py_object]
TranslationUnit_parse.restype = c_object_p

TranslationUnit_cursor = lib.clang_getTranslationUnitCursor
TranslationUnit_cursor.argtypes = [TranslationUnit]
TranslationUnit_cursor.restype = Cursor
TranslationUnit_cursor.errcheck = Cursor.from_result

TranslationUnit_spelling = lib.clang_getTranslationUnitSpelling
TranslationUnit_spelling.argtypes = [TranslationUnit]
TranslationUnit_spelling.restype = _CXString
TranslationUnit_spelling.errcheck = _CXString.from_result

TranslationUnit_dispose = lib.clang_disposeTranslationUnit
TranslationUnit_dispose.argtypes = [TranslationUnit]

# File Functions
File_name = lib.clang_getFileName
File_name.argtypes = [File]
File_name.restype = c_char_p

File_time = lib.clang_getFileTime
File_time.argtypes = [File]
File_time.restype = c_uint

###

__all__ = ['Index', 'TranslationUnit', 'Cursor', 'CursorKind',
           'Diagnostic', 'FixIt', 'SourceRange', 'SourceLocation', 'File']
