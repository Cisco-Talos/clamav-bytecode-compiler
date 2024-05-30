# Notable Changes

The ClamAV Bytecode Compiler releases adopt the version # for the latest
supported ClamAV release.
Multiple releases supporting the same ClamAV versions are hyphenated.

For example:
- 0.102.0 is the first release to support ClamAV 0.102.0 features.
- 0.102.0-2 supports the same, but with improvements to the compiler.

> _Note_: Changes should be grouped by release and use these icons:
> - Added: ➕
> - Changed: 🌌
> - Deprecated: 👇
> - Removed: ❌
> - Fixed: 🐛
> - Security: 🛡

> _Tip_: The bytecode signature programming API primarily consists of:
> - [bytecode_api.h](headers/bytecode_api.h)
> - [bytecode_local.h](headers/bytecode_local.h)

## `1.4.0`

➕ Upgrade bytecode compiler project to LLVM 16.
  - The bytecode compiler project now builds multiple shared object files,
    instead of just one with all of the passes.  This is due to running with
    the "new" pass manager, instead of running with the legacy pass manager,
    as before.  See https://llvm.org/docs/NewPassManager.html and
    https://blog.llvm.org/posts/2021-03-26-the-new-pass-manager/ for more details.
  - The bytecode compiler currently uses (deprecated) non-opaque pointers.
    Updating to all opaque pointers will be required for the next release.
    See https://llvm.org/docs/OpaquePointers.html for more information.

🌌 New Requirements:
  - LLVM 16
  - Clang 16

## `0.105.0`

➕ Complete overhaul of the bytecode compiler project.
  - The clamav compiler passes now build against a system-installed LLVM-
    library. This builds a single shared library (i.e. libclambcc.so).
  - The compiler application is now a Python script that uses Clang with the
    bytecode compiler library to run the compiler passes.

🐛 Fixed bug causing signatures with malloc to fail to run when using system
   installed llvm.

🐛 Fixed the peinfo.c example bytecode source.

❌ Removed vendored/modified LLVM/Clang 2.7-ish source.

🌌 Upgraded build system from Autotools -> CMake.

🌌 New Requirements:
  - LLVM 8
  - Clang 8
  - Python 3.6+

➕ Support for compiling bytecode signatures from multiple source file.

🐛 Many assorted bug fixes.

## `0.103.0`

🌌 Update `FunctionalityLevels` enum for 0.103.0.

➕ Support for bytecode features added in ClamAV 0.103.
  - Added decompression functions to the API.
    - LZMA decompression functions:
      ```c
      int32_t lzma_init(int32_t from, int32_t to);
      int32_t lzma_process(int32_t id);
      int32_t lzma_done(int32_t id);
      ```
    - Bzip2 decompression functions:
      ```c
      int32_t bzip2_init(int32_t from, int32_t to);
      int32_t bzip2_process(int32_t id);
      int32_t bzip2_done(int32_t id);
      ```

🐛 Fixed bytecode tracing.

🐛 Fixed issue with array accesses inside loops.

🐛 Other minor fixes.

## `0.102.0-2`

🐛 LLVM/Clang source compatibility fixes for newer versions of GCC and Clang.

## `0.102.0`

🌌 Update `FunctionalityLevels` enum for 0.102.0.

🌌 Renamed the `X86REGS` disassembly `enum` to deconflict with Debian headers.
  - This is a non-backwards compatible (breaking) change.
    Bytecode signature source using this enum must replace the `REG_` prefix
    with this prefix: `X86_REG_`.

➕ Support for bytecode features added in ClamAV 0.102.
  - Added runtime hooks to support these Mach-O and ELF unpackers:
    - Added the following macros:
      ```c
      ELF_UNPACKER_DECLARE
      MACHO_UNPACKER_DECLARE
      ```

➕ Support for bytecode features added in ClamAV 0.101.
  - Added function to check scan options to the API:
    ```c
    uint32_t engine_scan_options_ex(const uint8_t* option_name, uint32_t name_len);
    ```

🌌 Formatted the source with `clang-format`

🐛 LLVM/Clang source C++ 11 compatibility fixes from upstream project.

## `0.99.2`

🌌 Update `FunctionalityLevels` enum for 0.99.2.

🐛 Assorted bug fixes.

## `0.98.7`

🌌 Update `FunctionalityLevels` enum for 0.98.7.

➕ Added runtime hook for preclass.
  - Added the following macros:
    ```c
    PRECLASS_HOOK_DECLARE
    ```

## `0.98.5rc1`

🌌 Update `FunctionalityLevels` enum for 0.98.5.

🌌 Clean-up to API doxygen documentation.

🐛 Many assorted bug fixes.

➕ Support for bytecode features added in ClamAV 0.98.4.
  - Added APIs to read properties from scan metadata JSON:
    ```c
    int32_t json_is_active(void);
    int32_t json_get_object(const int8_t* name, int32_t name_len, int32_t objid);
    int32_t json_get_type(int32_t objid);
    int32_t json_get_array_length(int32_t objid);
    int32_t json_get_array_idx(int32_t idx, int32_t objid);
    int32_t json_get_string_length(int32_t objid);
    int32_t json_get_string(int8_t* str, int32_t str_len, int32_t objid);
    int32_t json_get_boolean(int32_t objid);
    int32_t json_get_int(int32_t objid);
    ```

## `0.98.1rc2`

🐛 A couple bug fixes.

## `0.98.1rc1`

🌌 Update `FunctionalityLevels` enum for 0.98.1.

🐛 Many assorted bug fixes.

➕ Minor API fixes and additions.
  - Add LDB Container support.
  - Added the following big endian conversion functions to the API:
    ```c
    static uint16_t force_inline be16_to_host(uint16_t v);
    static uint32_t force_inline be32_to_host(uint32_t v);
    static uint64_t force_inline be64_to_host(uint64_t v);
    ```
  - Added the following macros:
    ```c
    NULL
    CONTAINER(x)
    SIGNATURES_DEF_END
    ```

## `0.97.3a`

🐛 Many assorted bug fixes.

🌌 Significant clean-up to API doxygen documentation.

➕ Introduced `FunctionalityLevels` enum to match versions with ClamAV FLEVELs.

➕ Support for bytecode features added in ClamAV 0.96.1, 0.96.2, & 0.96.4
  - Added the following math functions to the API:
    ```c
    int32_t ilog2(uint32_t a, uint32_t b); /* 0.96.1 variant */
    static inline int32_t ilog2_compat(uint32_t a, uint32_t b); /* Old 0.96.0 compatible API; You should use the ilog2() 0.96.1 API */
    int32_t ipow(int32_t a, int32_t b, int32_t c);
    uint32_t iexp(int32_t a, int32_t b, int32_t c);
    int32_t isin(int32_t a, int32_t b, int32_t c);
    int32_t icos(int32_t a, int32_t b, int32_t c);
    ```
  - Added the following string functions to the API:
    ```c
    int32_t memstr(const uint8_t* haystack, int32_t haysize,
               const uint8_t* needle, int32_t needlesize);
    int32_t hex2ui(uint32_t hex1, uint32_t hex2);
    int32_t atoi(const uint8_t* str, int32_t size);
    uint32_t debug_print_str_start(const uint8_t *str, uint32_t len);
    uint32_t debug_print_str_nonl(const uint8_t *str, uint32_t len);
    uint32_t entropy_buffer(uint8_t* buffer, int32_t size);
    ```
  - Added the following data structures functions to the API:
    ```c
    int32_t map_new(int32_t keysize, int32_t valuesize);
    int32_t map_addkey(const uint8_t *key, int32_t ksize, int32_t id);
    int32_t map_setvalue(const uint8_t *value, int32_t vsize, int32_t id);
    int32_t map_remove(const uint8_t* key, int32_t ksize, int32_t id);
    int32_t map_find(const uint8_t* key, int32_t ksize, int32_t id);
    int32_t map_getvaluesize(int32_t id);
    uint8_t* map_getvalue(int32_t id, int32_t size);
    int32_t map_done(int32_t id);
    int32_t file_find_limit(const uint8_t *data, uint32_t len, int32_t maxpos);
    ```
  - Added the following engine-query functions to the API:
    ```c
    uint32_t engine_functionality_level(void);
    uint32_t engine_dconf_level(void);
    uint32_t engine_scan_options(void);
    uint32_t engine_db_options(void);
    ```
  - Added the following scan-control functions to the API:
    ```c
    int32_t extract_set_container(uint32_t container);
    int32_t input_switch(int32_t extracted_file);
    static force_inline uint32_t match_location(__Signature sig, uint32_t goback);
    static force_inline int32_t match_location_check(__Signature sig,
                                                     uint32_t goback,
                                                     const char *static_start,
                                                     uint32_t static_len)
    ```
  - Added the following assorted functions to the API:
    ```c
    uint32_t get_environment(struct cli_environment *env, uint32_t len);
    uint32_t disable_bytecode_if(const int8_t *reason, uint32_t len, uint32_t cond);
    uint32_t disable_jit_if(const int8_t* reason, uint32_t len, uint32_t cond);
    int32_t version_compare(const uint8_t* lhs, uint32_t lhs_len,
                            const uint8_t* rhs, uint32_t rhs_len);
    uint32_t check_platform(uint32_t a, uint32_t b, uint32_t c);
    static uint64_t force_inline le64_to_host(uint64_t v);
    int32_t running_on_jit(void);
    ```
  - Added PDF inspection functions to the API:
    ```c
    int32_t pdf_get_obj_num(void);
    int32_t pdf_get_flags(void);
    int32_t pdf_set_flags(int32_t flags);
    int32_t pdf_lookupobj(uint32_t id);
    uint32_t pdf_getobjsize(int32_t objidx);
    uint8_t *pdf_getobj(int32_t objidx, uint32_t amount);
    int32_t pdf_getobjid(int32_t objidx);
    int32_t pdf_getobjflags(int32_t objidx);
    int32_t pdf_setobjflags(int32_t objidx, int32_t flags);
    int32_t pdf_get_offset(int32_t objidx);
    int32_t pdf_get_phase(void);
    int32_t pdf_get_dumpedobjid(void);
    ```
  - Added PE parser features to the API:
    ```c
    static force_inline bool hasPEInfo(void);
    int32_t matchicon(const uint8_t* group1, int32_t group1_len,
                      const uint8_t* group2, int32_t group2_len);
    int32_t get_file_reliability(void);
    static force_inline bool hasPEInfo(void);
    static force_inline bool isPE64(void);
    static force_inline uint8_t getPEMajorLinkerVersion(void);
    static force_inline uint8_t getPEMinorLinkerVersion(void);
    static force_inline uint32_t getPESizeOfCode(void);
    static force_inline uint32_t getPESizeOfInitializedData(void);
    static force_inline uint32_t getPESizeOfUninitializedData(void);
    static force_inline uint32_t getPEBaseOfCode(void);
    static force_inline uint32_t getPEBaseOfData(void);
    static force_inline uint64_t getPEImageBase(void);
    static force_inline uint32_t getPESectionAlignment(void);
    static force_inline uint32_t getPEFileAlignment(void);
    static force_inline uint16_t getPEMajorOperatingSystemVersion(void);
    static force_inline uint16_t getPEMinorOperatingSystemVersion(void);
    static force_inline uint16_t getPEMajorImageVersion(void);
    static force_inline uint16_t getPEMinorImageVersion(void);
    static force_inline uint16_t getPEMajorSubsystemVersion(void);
    static force_inline uint16_t getPEMinorSubsystemVersion(void);
    static force_inline uint32_t getPEWin32VersionValue(void);
    static force_inline uint32_t getPESizeOfImage(void);
    static force_inline uint32_t getPESizeOfHeaders(void);
    static force_inline uint32_t getPECheckSum(void);
    static force_inline uint16_t getPESubsystem(void);
    static force_inline uint16_t getPEDllCharacteristics(void);
    static force_inline uint32_t getPESizeOfStackReserve(void);
    static force_inline uint32_t getPESizeOfStackCommit(void);
    static force_inline uint32_t getPESizeOfHeapReserve(void);
    static force_inline uint32_t getPESizeOfHeapCommit(void);
    static force_inline uint32_t getPELoaderFlags(void);
    static force_inline uint16_t getPEMachine();
    static force_inline uint32_t getPETimeDateStamp();
    static force_inline uint32_t getPEPointerToSymbolTable();
    static force_inline uint32_t getPENumberOfSymbols();
    static force_inline uint16_t getPESizeOfOptionalHeader();
    static force_inline uint16_t getPECharacteristics();
    static force_inline bool getPEisDLL();
    static force_inline uint32_t getPEDataDirRVA(unsigned n);
    static force_inline uint32_t getPEDataDirSize(unsigned n)
    static uint32_t getPELFANew(void);
    static force_inline int readPESectionName(unsigned char name[8], unsigned n);
    static force_inline uint32_t getImageBase(void);
    static uint32_t getSectionVirtualSize(unsigned i);
    static force_inline bool readRVA(uint32_t rva, void *buf, size_t bufsize);
    ```
  - Added following macros:
    ```c
    NEED_PE_INFO;       /* For use in PE hooks */
    PDF_HOOK_DECLARE;   /* Set signature to run on PDF files */
    BYTECODE_ABORT_HOOK /* Return code for bytecode entrypoint to exit early. */
    COPYRIGHT(c);       /* Define alternative copyright for signature, and
                           prevent source from being embedded into the bytecode. */
    ICONGROUP1(group);  /* Defines an alternative copyright for this bytecode. */
    ICONGROUP2(group);  /* Define IconGroup2 for logical signature. */
    FUNCTIONALITY_LEVEL_MIN(m); /*  Define minimum required ClamAV FLEVEL */
    LDB_ADDATTRIBUTES(x);
    ```

## `0.11`

> _Note_: This release predates the convention to adopt ClamAV version #'s.

➕ Additional feature support for ClamAV 0.96.0.
  - Added many functions to API:
    ```c
    /* memory access */
    int32_t fill_buffer(uint8_t* buffer, uint32_t len, uint32_t filled, uint32_t cur, uint32_t fill);
    int32_t extract_new(int32_t id);
    int32_t read_number(uint32_t radix);
    /* data structures */
    int32_t hashset_new(void);
    int32_t hashset_add(int32_t hs, uint32_t key);
    int32_t hashset_remove(int32_t hs, uint32_t key);
    int32_t hashset_contains(int32_t hs, uint32_t key);
    int32_t hashset_done(int32_t id);
    int32_t hashset_empty(int32_t id);
    int32_t  buffer_pipe_new(uint32_t size);
    int32_t  buffer_pipe_new_fromfile(uint32_t pos);
    uint32_t buffer_pipe_read_avail(int32_t id);
    uint8_t *buffer_pipe_read_get(int32_t id, uint32_t amount);
    int32_t  buffer_pipe_read_stopped(int32_t id, uint32_t amount);
    uint32_t buffer_pipe_write_avail(int32_t id);
    uint8_t *buffer_pipe_write_get(int32_t id, uint32_t size);
    int32_t  buffer_pipe_write_stopped(int32_t id, uint32_t amount);
    int32_t  buffer_pipe_done(int32_t id);
    /* decompression */
    int32_t inflate_init(int32_t from_buffer, int32_t to_buffer, int32_t windowBits);
    int32_t inflate_process(int32_t id);
    int32_t inflate_done(int32_t id);
    /* scan-control */
    int32_t bytecode_rt_error(int32_t locationid);
    /* javascript normalization */
    int32_t jsnorm_init(int32_t from_buffer);
    int32_t jsnorm_process(int32_t id);
    int32_t jsnorm_done(int32_t id);
    ```
  - Added following macros:
    ```c
    BUFFER_FILL(buf, cursor, need, limit);
    BUFFER_ENSURE(buf, cursor, need, limit);
    ```

🐛 Various bug fixes.

## `0.10`

> _Note_: This release predates the convention to adopt ClamAV version #'s.

➕ First public release, supporting ClamAV 0.96.0.
  - The bytecode API provides the following functions:
    ```c
    /* File/Memory access */
    int32_t read(uint8_t *data, int32_t size);
    int32_t write(uint8_t *data, int32_t size);
    int32_t seek(int32_t pos, uint32_t whence);
    int32_t file_find(const uint8_t* data, uint32_t len);
    int32_t file_byteat(uint32_t offset);
    void* malloc(uint32_t size);
    static void* memchr(const void* s, int c, size_t n);
    void* memset(void *src, int c, uint32_t n);
    void *memmove(void *dst, const void *src, uint32_t n);
    void *memcpy(void *restrict dst, const void *restrict src, uint32_t n);
    bool __is_bigendian(void);
    static uint32_t force_inline le32_to_host(uint32_t v);
    static uint16_t force_inline le16_to_host(uint16_t v);
    static uint32_t force_inline cli_readint32(const void* buff);
    static uint16_t force_inline cli_readint16(const void* buff);
    static void force_inline cli_writeint32(void* offset, uint32_t v);

    /* Set name of virus found */
    uint32_t setvirusname(const uint8_t *name, uint32_t len);
    static force_inline void foundVirus(const char *virusname);

    /* Debugging */
    uint32_t debug_print_str(const uint8_t *str, uint32_t len);
    uint32_t debug_print_uint(uint32_t a);
    static force_inline void __attribute__((overloadable)) debug(const char * str);
    static force_inline void __attribute__((overloadable)) debug(const uint8_t* str);
    static force_inline void __attribute__((overloadable)) debug(uint32_t a);

    /* Assembly */
    uint32_t disasm_x86(struct DISASM_RESULT* result, uint32_t len);
    static force_inline uint32_t DisassembleAt(struct DIS_fixed* result, uint32_t offset, uint32_t len);

    /* tracing API */
    uint32_t trace_directory(const uint8_t* directory, uint32_t dummy);
    uint32_t trace_scope(const uint8_t* newscope, uint32_t scopeid);
    uint32_t trace_source(const uint8_t* srcfile, uint32_t line);
    uint32_t trace_op(const uint8_t* opname, uint32_t column);
    uint32_t trace_value(const uint8_t* name, uint32_t v);
    uint32_t trace_ptr(const uint8_t* ptr, uint32_t dummy);

    /* PE parser utility */
    uint32_t pe_rawaddr(uint32_t rva);
    int32_t get_pe_section(struct cli_exe_section *section, uint32_t num);
    static uint32_t getVirtualEntryPoint(void);
    static uint32_t getLFANew(void);
    static uint32_t getSectionRVA(unsigned i);
    static force_inline bool hasExeInfo(void);
    static force_inline uint32_t getFilesize(void);
    static force_inline uint32_t getEntryPoint(void);
    static force_inline uint32_t getExeOffset(void);
    static force_inline uint16_t getNumberOfSections(void);
    ```
  - The bytecode API provides the following macros:
    ```c
    /* Signature structural macros */
    VIRUSNAME_PREFIX(name);  /* Declares the virusname prefix. */
    VIRUSNAMES(...);         /* Declares all the virusnames that this bytecode can report. */
    PE_HOOK_DECLARE;         /* Set signature to run on PE files */
    PE_UNPACKER_DECLARE;     /* Set signature to run as a PE unpacker */
    SIGNATURES_DECL_BEGIN;   /* Marks the beginning of the subsignature name declaration section */
    DECLARE_SIGNATURE(name); /* Declares a name for a subsignature */
    SIGNATURES_DECL_END;     /* Marks the end of the subsignature name declaration section */
    TARGET(tgt);             /* Defines the ClamAV file target. */
    SIGNATURES_DEF_BEGIN;    /* Marks the beginning of subsignature pattern definitions. */
    DEFINE_SIGNATURE(name, hex); /* Defines the pattern for a previously declared subsignature. */
    SIGNATURES_END;          /* Marks the end of the subsignature pattern definitions. */
    /* Regex utility macros */
    YYFILL(n);
    REGEX_SCANNER;
    REGEX_POS;
    REGEX_LOOP_BEGIN;
    REGEX_RESULT;
    RE2C_DEBUG_PRINT;
    DEBUG_PRINT_REGEX_MATCH;
    RE2C_FILLBUFFER(len);
    ```
