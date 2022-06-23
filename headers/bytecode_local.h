/*
 *  Copyright (C) 2009-2014 Cisco Systems, Inc.
 *  Copyright (C) 2009-2013 Sourcefire, Inc.
 *  All rights reserved.
 *  Authors: Török Edvin, Kevin Lin
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/** @file */
#define NULL (void *)0x0

#define force_inline inline __attribute__((always_inline))
#define overloadable_func __attribute__((overloadable))

/* DOXYGEN defined() must come first */
#if defined(DOXYGEN) || __has_feature(attribute_overloadable)
/* Yes, clang supports overloading functions in C! */
/**
\group_debug
 * @fn debug(const char * str)
 * Prints \p str to clamscan's --debug output.
 * @overload
 * @param[in] str null terminated string
 */
static force_inline void overloadable_func debug(const char *str)
{
    debug_print_str((const uint8_t *)str, 0);
}

/**
\group_debug
 * @fn debug(const uint8_t* str)
 * Prints \p str to clamscan's --debug output.
 * @overload
 * @param[in] str null terminated string
 */
static force_inline void overloadable_func debug(const uint8_t *str)
{
    debug_print_str((const uint8_t *)str, 0);
}

/**
\group_debug
 * @fn debug(uint32_t a)
 * Prints \p a integer to clamscan's --debug output.
 * @overload
 * @param[in] a integer
 */
static force_inline void overloadable_func debug(uint32_t a)
{
    debug_print_uint(a);
}

/**
\group_debug
 * debug is an overloaded function (yes clang supports that in C!), but it only
 * works on strings, and integers. Give an error on any other type.
 * @sa debug(const char * str),
 * @sa debug(const uint8_t* str),
 * @sa debug(uint32_t a)
 */
void debug(...) __attribute__((overloadable, unavailable));
#endif

/* Virusname definition handling */
/**
\group_config
 * Declares the virusname prefix.
 * @param[in] name the prefix common to all viruses reported by this bytecode
 */
#define VIRUSNAME_PREFIX(name) const char __clambc_virusname_prefix[] = name;
/**
\group_config
 * Declares all the virusnames that this bytecode can report.
 * @param[in] ... a comma-separated list of strings interpreted as virusnames
 */
#define VIRUSNAMES(...) const char *const __clambc_virusnames[] = {__VA_ARGS__};

/* Logical signature handling */

typedef struct signature {
    uint64_t id;
} __Signature;

/**
\group_config
 * Like \p PE_HOOK_DECLARE, but it is not run for packed files that pe.c can
 * unpack (only on the unpacked file).
 */
#define PE_UNPACKER_DECLARE const uint16_t __clambc_kind = BC_PE_UNPACKER;

/**
\group_config
 * Make the current bytecode a PDF hook.
 * @details Having a logical signature doesn't make sense here, since the logical
 * signature is evaluated AFTER these hooks run.
 * @details This hook is called several times, use pdf_get_phase() to find out in which
 * phase you got called.
 */
#define PDF_HOOK_DECLARE const uint16_t __clambc_kind = BC_PDF;

/**
 * entrypoint() return code that tells hook invoker that it should skip
 * executing, probably because it'd trigger a bug in it
 */
#define BYTECODE_ABORT_HOOK 0xcea5e

/**
\group_config
 * Make the current bytecode a PE hook.
 * @details Bytecode will be called once the logical signature trigger matches
 * (or always if there is none), and if you have access to all the PE information.
 * By default you only have access to execs.h information, and not to PE field
 * information (even for PE files).
 */
#define PE_HOOK_DECLARE const uint16_t __clambc_kind = BC_PE_ALL;

/**
\group_config
 * Make the current bytecode a PRECLASS hook.
 * @details Bytecode will be called once the logical signature trigger matches
 * (or always if there is none), and if you have access to all PRECLASS information.
 */
#define PRECLASS_HOOK_DECLARE const uint16_t __clambc_kind = BC_PRECLASS;

/**
\group_config
 * Like \p PE_UNPACKER_DECLARE, but for ELF files.
 */
#define ELF_UNPACKER_DECLARE const uint16_t __clambc_kind = BC_ELF_UNPACKER;

/**
\group_config
 * Like \p PE_UNPACKER_DECLARE, but for Mach-O files.
 */
#define MACHO_UNPACKER_DECLARE const uint16_t __clambc_kind = BC_MACHO_UNPACKER;

/**
\group_config
 * Marks the beginning of the subsignature name declaration section.
 */
#define SIGNATURES_DECL_BEGIN \
    struct __Signatures {
/**
\group_config
 * Declares a name for a subsignature.
 */
#define DECLARE_SIGNATURE(name) \
    const char *name##_sig;     \
    __Signature name;
/**
\group_config
 * Marks the end of the subsignature name declaration section.
 */
#define SIGNATURES_DECL_END \
    }                       \
    ;

/**
\group_config
 * Defines the ClamAV file target.
 * @param[in] tgt ClamAV signature type (0 - raw, 1 - PE, etc.)
 */
#define TARGET(tgt) const unsigned short __Target = (tgt);

/**
\group_config
 * Defines an alternative copyright for this bytecode.
 * @details This will also prevent the sourcecode from being embedded into the bytecode.
 */
#define COPYRIGHT(c) const char *const __Copyright = (c);

/**
\group_config
 * Define IconGroup1 for logical signature.
 * @details See logical signature documentation for what it is.
 */
#define ICONGROUP1(group) const char *const __IconGroup1 = (group);

/**
\group_config
 * Define IconGroup2 for logical signature.
 * @details See logical signature documentation for what it is.
 */
#define ICONGROUP2(group) const char *const __IconGroup2 = (group);

/**
\group_config
 * Define the minimum engine functionality level required for this
 * bytecode/logical signature.
 * @details Engines older than this will skip loading the bytecode.
 * You can use the #FunctionalityLevels enumeration here.
 */
#define FUNCTIONALITY_LEVEL_MIN(m) const unsigned short __FuncMin = (m);

/**
\group_config
 * Define the maximum engine functionality level required for this
 * bytecode/logical signature.
 * @details Engines newer than this will skip loading the bytecode.
 * You can use the #FunctionalityLevels enumeration here.
 */
#define FUNCTIONALITY_LEVEL_MAX(m) const unsigned short __FuncMax = (m);

#define LDB_ADDATTRIBUTES(x) const char *__ldb_rawattrs = (x);

#define CONTAINER(x) const char *__ldb_container = (x);

/**
\group_config
 * Marks the beginning of subsignature pattern definitions.
 * @sa SIGNATURES_DECL_BEGIN
 */
/* some other macro may use __COUNTER__, so we need to subtract its current\
 * value to obtain zero-based indices */
#define SIGNATURES_DEF_BEGIN                                                                             \
    static const unsigned __signature_bias = __COUNTER__ + 1;                                            \
    const struct __Signatures Signatures   = {/**                                                        \
                                        \group_config                                                  \
                                         * Defines the pattern for a previously declared subsignature. \
                                         * @sa DECLARE_SIGNATURE                                       \
                                         * @param name the name of a previously declared subsignature  \
                                         * @param hex the pattern for this subsignature                \
                                         */
#define DEFINE_SIGNATURE(name, hex) \
    .name##_sig = (hex),            \
    .name       = {__COUNTER__ - __signature_bias},
/**
 * Old macro used to mark the end of the subsignature pattern definitions.
 */
#define SIGNATURES_END \
    }                  \
    ;
/**
\group_config
 * Marks the end of the subsignature pattern definitions.\n
 * Alternative: SIGNATURES_END
 */
#define SIGNATURES_DEF_END \
    }                      \
    ;

/**
\group_engine
 * Returns how many times the specified signature matched.
 * @param[in] sig name of subsignature queried
 * @return number of times this subsignature matched in the entire file
 * @details This is a constant-time operation, the counts for all subsignatures are
 * already computed.
 */
static force_inline uint32_t count_match(__Signature sig)
{
    return __clambc_match_counts[sig.id];
}

/**
\group_engine
 * Returns whether the specified subsignature has matched at least once.
 * @param[in] sig name of subsignature queried
 * @return 1 if subsignature one or more times, 0 otherwise
 */
static force_inline uint32_t matches(__Signature sig)
{
    return __clambc_match_counts[sig.id] != 0;
}

/**
\group_engine
  * Returns the offset of the match.
  * @param[in] sig - Signature
  * @param[in] goback - max length of signature
  * @return offset of match
  */
static force_inline uint32_t match_location(__Signature sig, uint32_t goback)
{
    int32_t pos = __clambc_match_offsets[sig.id];
    if (engine_functionality_level() <= FUNC_LEVEL_096_1) {
        /* bug, it returns offset of last subsig, not offset of first */
        pos -= goback;
        if (pos <= 0) pos = 0;
    }
    return pos;
}

/**
\group_engine
  * Like match_location(), but also checks that the match starts with
  * the specified hex string.
  * @details It is recommended to use this for safety and compatibility with 0.96.1
  * @param[in] sig - signature
  * @param[in] goback - maximum length of signature (till start of last subsig)
  * @param[in] static_start - static string that sig must begin with
  * @param[in] static_len - static string that sig must begin with - length
  * @return >=0 - offset of match
  * @return -1 - no match
  */
static force_inline int32_t match_location_check(__Signature sig,
                                                 uint32_t goback,
                                                 const char *static_start,
                                                 uint32_t static_len)
{
    int32_t pos = match_location(sig, goback);
    if (seek(pos, SEEK_SET) != pos)
        return -1;
    int32_t cpos = file_find_limit((const uint8_t *)static_start, static_len, pos + goback);
    if (cpos == -1) {
        debug("Engine reported match, but we couldn't find it! Engine reported (after fixup):");
        debug(pos);
        return -1;
    }
    if (seek(cpos, SEEK_SET) != cpos)
        return -1;
    if (cpos != pos && engine_functionality_level() >= FUNC_LEVEL_096_1_dev) {
        debug("wrong match pos reported by engine, real match pos:");
        debug(cpos);
        debug("reported by engine:");
        debug(pos);
        debug("but goback fixed it up!");
    }
    return cpos;
}

/**
\group_scan
 * Sets the specified virusname as the virus detected by this bytecode.
 * @param[in] virusname the name of the virus, excluding the prefix, must be one of
 * the virusnames declared in \p VIRUSNAMES.
 * \sa VIRUSNAMES
 */
static force_inline overloadable_func void foundVirus(const char *virusname)
{
    setvirusname((const uint8_t *)virusname, 0);
}

#if defined(DOXYGEN) || __has_feature(attribute_overloadable)
/** Like foundVirus() but just use the prefix as virusname */
static force_inline void overloadable_func foundVirus(void)
{
    foundVirus("");
}
#endif

/**
\group_file
  * Returns the currently scanned file's size.
  * @return file size as 32-bit unsigned integer
  */
static force_inline uint32_t getFilesize(void)
{
    return __clambc_filesize[0];
}

union unaligned_32 {
    uint32_t una_u32;
    int32_t una_s32;
} __attribute__((packed));

union unaligned_16 {
    uint16_t una_u16;
    int16_t una_s16;
} __attribute__((packed));

/**
\group_env
 * Returns true if the bytecode is executing on a big-endian CPU.
 * @return true if executing on bigendian CPU, false otherwise
 *
 * @details This will be optimized away in libclamav, but it must be used when dealing
 * with endianess for portability reasons.\n
 * For example whenever you read a 32-bit integer from a file, it can be written
 * in little-endian convention (x86 CPU for example), or big-endian convention
 * (PowerPC CPU for example).\n
 * If the file always contains little-endian integers, then conversion might be
 * needed.\n
 * ClamAV bytecodes by their nature must only handle known-endian integers, if
 * endianness can change, then both situations must be taken into account (based
 * on a 1-byte field for example).
 */
bool __is_bigendian(void) __attribute__((const)) __attribute__((nothrow));

/**
\group_env
 * Converts the specified value if needed, knowing it is in little endian
 * order.
 * @param[in] v 32-bit integer as read from a file
 * @return integer converted to host's endianess
 */
static uint32_t force_inline le32_to_host(uint32_t v)
{
    /* calculate bswap always, so compiler can use a select,
     and doesn't need to create a branch.
     This will get optimized away at bytecode load time anyway */
    uint32_t swapped = __builtin_bswap32(v);
    return __is_bigendian() ? swapped : v;
}

/**
\group_env
 * Converts the specified value if needed, knowing it is in big endian
 * order.
 * @param[in] v 32-bit integer as read from a file
 * @return integer converted to host's endianess
 */
static uint32_t force_inline be32_to_host(uint32_t v)
{
    /* calculate bswap always, so compiler can use a select,
     and doesn't need to create a branch.
     This will get optimized away at bytecode load time anyway */
    uint32_t swapped = __builtin_bswap32(v);
    return __is_bigendian() ? v : swapped;
}

/**
\group_env
 * Converts the specified value if needed, knowing it is in little endian
 * order.
 * @param[in] v 64-bit integer as read from a file
 * @return integer converted to host's endianess
 */
static uint64_t force_inline le64_to_host(uint64_t v)
{
    uint64_t swapped = __builtin_bswap64(v);
    return __is_bigendian() ? swapped : v;
}

/**
\group_env
 * Converts the specified value if needed, knowing it is in big endian
 * order.
 * @param[in] v 64-bit integer as read from a file
 * @return integer converted to host's endianess
 */
static uint64_t force_inline be64_to_host(uint64_t v)
{
    uint64_t swapped = __builtin_bswap64(v);
    return __is_bigendian() ? v : swapped;
}

/**
\group_env
 * Converts the specified value if needed, knowing it is in little endian
 * order.
 * @param[in] v 16-bit integer as read from a file
 * @return integer converted to host's endianess
 */
static uint16_t force_inline le16_to_host(uint16_t v)
{
    uint16_t swapped = ((v & 0xff) << 8) | ((v >> 8) & 0xff);
    return __is_bigendian() ? swapped : v;
}

/**
\group_env
 * Converts the specified value if needed, knowing it is in big endian
 * order.
 * @param[in] v 16-bit integer as read from a file
 * @return integer converted to host's endianess
 */
static uint16_t force_inline be16_to_host(uint16_t v)
{
    uint16_t swapped = ((v & 0xff) << 8) | ((v >> 8) & 0xff);
    return __is_bigendian() ? v : swapped;
}

/**
\group_env
 * Reads from the specified buffer a 32-bit of little-endian integer.
 * @param[in] buff pointer to buffer
 * @return 32-bit little-endian integer converted to host endianness
 */
static uint32_t force_inline cli_readint32(const void *buff)
{
    uint32_t v = ((const union unaligned_32 *)buff)->una_s32;
    return le32_to_host(v);
}

/**
\group_env
 * Reads from the specified buffer a 16-bit of little-endian integer.
 * @param[in] buff pointer to buffer
 * @return 16-bit little-endian integer converted to host endianness
 */
static uint16_t force_inline cli_readint16(const void *buff)
{
    uint16_t v = ((const union unaligned_16 *)buff)->una_s16;
    return le16_to_host(v);
}

/**
\group_env
 * Writes the specified value into the specified buffer in little-endian order
 * @param[out] offset pointer to buffer to write to
 * @param[in] v value to write
 */
static void force_inline cli_writeint32(void *offset, uint32_t v)
{
    ((union unaligned_32 *)offset)->una_u32 = le32_to_host(v);
}

/* --------------------- PE helper functions ------------------------ */
/**
\group_pe
 * Returns whether the current file has executable information.
 * @return true if the file has exe info, false otherwise
 */
static force_inline bool hasExeInfo(void)
{
    return __clambc_pedata.offset != -1;
}

/**
\group_pe
 * Returns whether PE information is available
 * @return true if PE information is available (in PE hooks)
 */
static force_inline bool hasPEInfo(void)
{
    return (__clambc_kind == BC_PE_ALL ||
            __clambc_kind == BC_PE_UNPACKER);
}

#define NEED_PE_INFO                                                   \
    { /* only available in PE hooks */                                 \
        if (!hasPEInfo())                                              \
            __fail_missing_PE_HOOK_DECLARE__or__PE_UNPACKER_DECLARE(); \
    }

/**
\group_pe
 * Returns whether this is a PE32+ executable.
 * @return true if this is a PE32+ executable
 */
static force_inline bool isPE64(void)
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wimplicit-function-declaration"
    NEED_PE_INFO;
#pragma GCC diagnostic pop
    return le16_to_host(__clambc_pedata.opt64.Magic) == 0x020b;
}

/**
\group_pe
 * Returns MajorLinkerVersion for this PE file.
 * @return PE MajorLinkerVersion or 0 if not in PE hook
 */
static force_inline uint8_t getPEMajorLinkerVersion(void)
{
    return isPE64() ? __clambc_pedata.opt64.MajorLinkerVersion : __clambc_pedata.opt32.MajorLinkerVersion;
}

/**
\group_pe
 * Returns MinorLinkerVersion for this PE file.
 * @return PE MinorLinkerVersion or 0 if not in PE hook
 */
static force_inline uint8_t getPEMinorLinkerVersion(void)
{
    return isPE64() ? __clambc_pedata.opt64.MinorLinkerVersion : __clambc_pedata.opt32.MinorLinkerVersion;
}

/**
\group_pe
 * Return the PE SizeOfCode.
 * @return PE SizeOfCode or 0 if not in PE hook
 */
static force_inline uint32_t getPESizeOfCode(void)
{
    return le32_to_host(isPE64() ? __clambc_pedata.opt64.SizeOfCode : __clambc_pedata.opt32.SizeOfCode);
}

/**
\group_pe
 * Return the PE SizeofInitializedData.
 * @return PE SizeOfInitializeData or 0 if not in PE hook
 */
static force_inline uint32_t getPESizeOfInitializedData(void)
{
    return le32_to_host(isPE64() ? __clambc_pedata.opt64.SizeOfInitializedData : __clambc_pedata.opt32.SizeOfInitializedData);
}

/**
\group_pe
 * Return the PE SizeofUninitializedData.
 * @return PE SizeofUninitializedData or 0 if not in PE hook
 */
static force_inline uint32_t getPESizeOfUninitializedData(void)
{
    return le32_to_host(isPE64() ? __clambc_pedata.opt64.SizeOfUninitializedData : __clambc_pedata.opt32.SizeOfUninitializedData);
}

/**
\group_pe
 * Return the PE BaseOfCode.
 * @return PE BaseOfCode, or 0 if not in PE hook
 */
static force_inline uint32_t getPEBaseOfCode(void)
{
    return le32_to_host(isPE64() ? __clambc_pedata.opt64.BaseOfCode : __clambc_pedata.opt32.BaseOfCode);
}

/**
\group_pe
 * Return the PE BaseOfData.
 * @return PE BaseOfData, or 0 if not in PE hook
 */
static force_inline uint32_t getPEBaseOfData(void)
{
    return le32_to_host(isPE64() ? 0 : __clambc_pedata.opt32.BaseOfData);
}

/**
\group_pe
 * Return the PE ImageBase as 64-bit integer.
 * @return PE ImageBase as 64-bit int, or 0 if not in PE hook
 */
static force_inline uint64_t getPEImageBase(void)
{
    return le64_to_host(isPE64() ? __clambc_pedata.opt64.ImageBase : __clambc_pedata.opt32.ImageBase);
}

/**
\group_pe
 * Return the PE SectionAlignment.
 * @return PE SectionAlignment, or 0 if not in PE hook
 */
static force_inline uint32_t getPESectionAlignment(void)
{
    return le32_to_host(isPE64() ? __clambc_pedata.opt64.SectionAlignment : __clambc_pedata.opt32.SectionAlignment);
}

/**
\group_pe
 * Return the PE FileAlignment.
 * @return PE FileAlignment, or 0 if not in PE hook
 */
static force_inline uint32_t getPEFileAlignment(void)
{
    return le32_to_host(isPE64() ? __clambc_pedata.opt64.FileAlignment : __clambc_pedata.opt32.FileAlignment);
}

/**
\group_pe
 * Return the PE MajorOperatingSystemVersion.
 * @return PE MajorOperatingSystemVersion, or 0 if not in PE hook
 */
static force_inline uint16_t getPEMajorOperatingSystemVersion(void)
{
    return le16_to_host(isPE64() ? __clambc_pedata.opt64.MajorOperatingSystemVersion : __clambc_pedata.opt32.MajorOperatingSystemVersion);
}

/**
\group_pe
 * Return the PE MinorOperatingSystemVersion.
 * @return PE MinorOperatingSystemVersion, or 0 if not in PE hook
 */
static force_inline uint16_t getPEMinorOperatingSystemVersion(void)
{
    return le16_to_host(isPE64() ? __clambc_pedata.opt64.MinorOperatingSystemVersion : __clambc_pedata.opt32.MinorOperatingSystemVersion);
}

/**
\group_pe
 * Return the PE MajorImageVersion.
 * @return PE MajorImageVersion, or 0 if not in PE hook
 */
static force_inline uint16_t getPEMajorImageVersion(void)
{
    return le16_to_host(isPE64() ? __clambc_pedata.opt64.MajorImageVersion : __clambc_pedata.opt32.MajorImageVersion);
}

/**
\group_pe
 * Return the PE MinorImageVersion.
 * @return PE MinorrImageVersion, or 0 if not in PE hook */
static force_inline uint16_t getPEMinorImageVersion(void)
{
    return le16_to_host(isPE64() ? __clambc_pedata.opt64.MinorImageVersion : __clambc_pedata.opt32.MinorImageVersion);
}

/**
\group_pe
 * Return the PE MajorSubsystemVersion.
 * @return PE MajorSubsystemVersion or 0 if not in PE hook
 */
static force_inline uint16_t getPEMajorSubsystemVersion(void)
{
    return le16_to_host(isPE64() ? __clambc_pedata.opt64.MajorSubsystemVersion : __clambc_pedata.opt32.MajorSubsystemVersion);
}

/**
\group_pe
 * Return the PE MinorSubsystemVersion.
 * @return PE MinorSubsystemVersion, or 0 if not in PE hook
 */
static force_inline uint16_t getPEMinorSubsystemVersion(void)
{
    return le16_to_host(isPE64() ? __clambc_pedata.opt64.MinorSubsystemVersion : __clambc_pedata.opt32.MinorSubsystemVersion);
}

/**
\group_pe
 * Return the PE Win32VersionValue.
 * @return PE Win32VersionValue, or 0 if not in PE hook
 */
static force_inline uint32_t getPEWin32VersionValue(void)
{
    return le32_to_host(isPE64() ? __clambc_pedata.opt64.Win32VersionValue : __clambc_pedata.opt32.Win32VersionValue);
}

/**
\group_pe
 * Return the PE SizeOfImage.
 * @return PE SizeOfImage, or 0 if not in PE hook
 */
static force_inline uint32_t getPESizeOfImage(void)
{
    return le32_to_host(isPE64() ? __clambc_pedata.opt64.SizeOfImage : __clambc_pedata.opt32.SizeOfImage);
}

/**
\group_pe
 * Return the PE SizeOfHeaders.
 * @return PE SizeOfHeaders, or 0 if not in PE hook
 */
static force_inline uint32_t getPESizeOfHeaders(void)
{
    return le32_to_host(isPE64() ? __clambc_pedata.opt64.SizeOfHeaders : __clambc_pedata.opt32.SizeOfHeaders);
}

/**
\group_pe
 * Return the PE CheckSum.
 * @return PE CheckSum, or 0 if not in PE hook
 */
static force_inline uint32_t getPECheckSum(void)
{
    return le32_to_host(isPE64() ? __clambc_pedata.opt64.CheckSum : __clambc_pedata.opt32.CheckSum);
}

/**
\group_pe
 * Return the PE Subsystem.
 * @return PE subsystem, or 0 if not in PE hook
 */
static force_inline uint16_t getPESubsystem(void)
{
    return le16_to_host(isPE64() ? __clambc_pedata.opt64.Subsystem : __clambc_pedata.opt32.Subsystem);
}

/**
\group_pe
 * Return the PE DllCharacteristics.
 * @return PE DllCharacteristics, or 0 if not in PE hook
 */
static force_inline uint16_t getPEDllCharacteristics(void)
{
    return le16_to_host(isPE64() ? __clambc_pedata.opt64.DllCharacteristics : __clambc_pedata.opt32.DllCharacteristics);
}

/**
\group_pe
 * Return the PE SizeOfStackReserve.
 * @return PE SizeOfStackReserver, or 0 if not in PE hook
 */
static force_inline uint32_t getPESizeOfStackReserve(void)
{
    return le32_to_host(isPE64() ? __clambc_pedata.opt64.SizeOfStackReserve : __clambc_pedata.opt32.SizeOfStackReserve);
}

/**
\group_pe
 * Return the PE SizeOfStackCommit.
 * @return PE SizeOfStackCommit, or 0 if not in PE hook
 */
static force_inline uint32_t getPESizeOfStackCommit(void)
{
    return le32_to_host(isPE64() ? __clambc_pedata.opt64.SizeOfStackCommit : __clambc_pedata.opt32.SizeOfStackCommit);
}

/**
\group_pe
 * Return the PE SizeOfHeapReserve.
 * @return PE SizeOfHeapReserve, or 0 if not in PE hook
 */
static force_inline uint32_t getPESizeOfHeapReserve(void)
{
    return le32_to_host(isPE64() ? __clambc_pedata.opt64.SizeOfHeapReserve : __clambc_pedata.opt32.SizeOfHeapReserve);
}

/**
\group_pe
 * Return the PE SizeOfHeapCommit.
 * @return PE SizeOfHeapCommit, or 0 if not in PE hook
 */
static force_inline uint32_t getPESizeOfHeapCommit(void)
{
    return le32_to_host(isPE64() ? __clambc_pedata.opt64.SizeOfHeapCommit : __clambc_pedata.opt32.SizeOfHeapCommit);
}

/**
\group_pe
 * Return the PE LoaderFlags.
 * @return PE LoaderFlags or 0 if not in PE hook
 */
static force_inline uint32_t getPELoaderFlags(void)
{
    return le32_to_host(isPE64() ? __clambc_pedata.opt64.LoaderFlags : __clambc_pedata.opt32.LoaderFlags);
}

/**
\group_pe
 * Returns the CPU this executable runs on, see libclamav/pe.c for possible
 * values.
 * @return PE Machine or 0 if not in PE hook
 */
static force_inline uint16_t getPEMachine()
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wimplicit-function-declaration"
    NEED_PE_INFO;
#pragma GCC diagnostic pop
    return le16_to_host(__clambc_pedata.file_hdr.Machine);
}

/**
\group_pe
 * Returns the PE TimeDateStamp from headers
 * @return PE TimeDateStamp or 0 if not in PE hook
 */
static force_inline uint32_t getPETimeDateStamp()
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wimplicit-function-declaration"
    NEED_PE_INFO;
#pragma GCC diagnostic pop
    return le32_to_host(__clambc_pedata.file_hdr.TimeDateStamp);
}

/**
\group_pe
 * Returns pointer to the PE debug symbol table
 * @return PE PointerToSymbolTable or 0 if not in PE hook
 */
static force_inline uint32_t getPEPointerToSymbolTable()
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wimplicit-function-declaration"
    NEED_PE_INFO;
#pragma GCC diagnostic pop
    return le32_to_host(__clambc_pedata.file_hdr.PointerToSymbolTable);
}

/**
\group_pe
 * Returns the PE number of debug symbols
 * @return PE NumberOfSymbols or 0 if not in PE hook
 */
static force_inline uint32_t getPENumberOfSymbols()
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wimplicit-function-declaration"
    NEED_PE_INFO;
#pragma GCC diagnostic pop
    return le32_to_host(__clambc_pedata.file_hdr.NumberOfSymbols);
}

/**
\group_pe
 * Returns the size of PE optional header.
 * @return size of PE optional header, or 0 if not in PE hook
 */
static force_inline uint16_t getPESizeOfOptionalHeader()
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wimplicit-function-declaration"
    NEED_PE_INFO;
#pragma GCC diagnostic pop
    return le16_to_host(__clambc_pedata.file_hdr.SizeOfOptionalHeader);
}

/**
\group_pe
 * Returns PE characteristics.
 * @details For example you can use this to check whether it is a DLL (0x2000).
 * @return characteristic of PE file, or 0 if not in PE hook*/
static force_inline uint16_t getPECharacteristics()
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wimplicit-function-declaration"
    NEED_PE_INFO;
#pragma GCC diagnostic pop
    return le16_to_host(__clambc_pedata.file_hdr.Characteristics);
}

/**
\group_pe
 * Returns whether this is a DLL.
 * Use this only in a PE hook!
 * @return true - the file is a DLL
 * @return false - file is not a DLL
 */
static force_inline bool getPEisDLL()
{
    return getPECharacteristics() & 0x2000;
}

/**
\group_pe
 * Gets the virtual address of specified image data directory.
 * @param[in] n image directory requested
 * @return Virtual Address of requested image directory
 */
static force_inline uint32_t getPEDataDirRVA(unsigned n)
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wimplicit-function-declaration"
    NEED_PE_INFO;
#pragma GCC diagnostic pop
    const struct pe_image_data_dir *p   = &__clambc_pedata.opt64_dirs[n];
    const struct pe_image_data_dir *p32 = &__clambc_pedata.opt32_dirs[n];
    return n < 16 ? le32_to_host(isPE64() ? p->VirtualAddress : p32->VirtualAddress)
                  : 0;
}

/**
\group_pe
 * Gets the size of the specified image data directory.
 * @param[in] n image directory requested
 * @return Size of requested image directory
 */
static force_inline uint32_t getPEDataDirSize(unsigned n)
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wimplicit-function-declaration"
    NEED_PE_INFO;
#pragma GCC diagnostic pop
    return n < 16 ? le32_to_host(isPE64() ? __clambc_pedata.opt64_dirs[n].Size : __clambc_pedata.opt32_dirs[n].Size)
                  : 0;
}

/**
\group_pe
 * Returns the number of sections in this executable file.
 * @return number of sections as 16-bit unsigned integer
 */
static force_inline uint16_t getNumberOfSections(void)
{
    /* available in non-PE hooks too */
    return __clambc_pedata.nsections;
}

/**
\group_pe
 * Gets the offset to the PE header.
 * @return offset to the PE header, or 0 if not in PE hook
 */
static uint32_t getPELFANew(void)
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wimplicit-function-declaration"
    NEED_PE_INFO;
#pragma GCC diagnostic pop
    return le32_to_host(__clambc_pedata.e_lfanew);
}

/**
\group_pe
 * Read name of requested PE section.
 * @param[out] name name of PE section
 * @param[in] n PE section requested
 * @return 0 if successful,
 * @return <0 otherwise
 */
static force_inline int readPESectionName(unsigned char name[8], unsigned n)
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wimplicit-function-declaration"
    NEED_PE_INFO;
#pragma GCC diagnostic pop
    if (n >= getNumberOfSections())
        return -1;
    uint32_t at = getPELFANew() + sizeof(struct pe_image_file_hdr) + sizeof(struct pe_image_optional_hdr32);
    if (!isPE64()) {
        /* Seek to the end of the long header */
        at += getPESizeOfOptionalHeader() - sizeof(struct pe_image_optional_hdr32);
    } else {
        at += sizeof(struct pe_image_optional_hdr64) - sizeof(struct pe_image_optional_hdr32);
    }
    at += n * sizeof(struct pe_image_section_hdr);
    int32_t pos = seek(at, SEEK_SET);
    if (pos == -1)
        return -2;
    if (read(name, 8) != 8)
        return -3;
    seek(pos, SEEK_SET);
    return 0;
}

/**
\group_pe
 * Returns the offset of the EntryPoint in the executable file.
 * @return offset of EP as 32-bit unsigned integer
 */
static force_inline uint32_t getEntryPoint(void)
{
    /* available in non-PE hooks too */
    return __clambc_pedata.ep;
}

/**
\group_pe
 * Returns the offset of the executable in the file.
 * @return offset of embedded executable inside file
 */
static force_inline uint32_t getExeOffset(void)
{
    /* available in non-PE hooks too */
    return __clambc_pedata.offset;
}

/**
\group_pe
 * Returns the ImageBase with the correct endian conversion.
 * @details Only works if the bytecode is a PE hook (i.e. you invoked
 * PE_UNPACKER_DECLARE).
 * @return ImageBase of PE file, 0 - for non-PE hook
 */
static force_inline uint32_t getImageBase(void)
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wimplicit-function-declaration"
    NEED_PE_INFO;
#pragma GCC diagnostic pop
    return le32_to_host(__clambc_pedata.opt32.ImageBase);
}

/**
\group_pe
 * The address of the EntryPoint. Use this for matching EP against sections.
 * @return virtual address of EntryPoint, or 0 if not in PE hook
 */
static uint32_t getVirtualEntryPoint(void)
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wimplicit-function-declaration"
    NEED_PE_INFO;
#pragma GCC diagnostic pop
    return le32_to_host(isPE64() ? __clambc_pedata.opt64.AddressOfEntryPoint : __clambc_pedata.opt32.AddressOfEntryPoint);
}

/**
\group_pe
 * Return the RVA of the specified section.
 * @param i section index (from 0)
 * @return RVA of section, or -1 if invalid
 */
static uint32_t getSectionRVA(unsigned i)
{
    struct cli_exe_section section;
    if (get_pe_section(&section, i) == -1)
        return -1;
    return section.rva;
}

/**
\group_pe
 * Return the virtual size of the specified section.
 * @param i section index (from 0)
 * @return VSZ of section, or -1 if invalid
 */
static uint32_t getSectionVirtualSize(unsigned i)
{
    struct cli_exe_section section;
    if (get_pe_section(&section, i) == -1)
        return -1;
    return section.vsz;
}

/**
\group_pe
 * read the specified amount of bytes from the PE file, starting at the
 * address specified by RVA.
 * @param[in] rva the Relative Virtual Address you want to read from (will be
 * converted to file offset)
 * @param[out] buf destination buffer
 * @param[in] bufsize size of buffer
 * @return true on success (full read)
 * @return false on any failure
 */
static force_inline bool readRVA(uint32_t rva, void *buf, size_t bufsize)
{
    uint32_t off = pe_rawaddr(rva);
    if (off == PE_INVALID_RVA)
        return false;
    int32_t oldpos = seek(off, SEEK_SET);
    if (oldpos == -1)
        return false;
    if (read((uint8_t *)buf, bufsize) != bufsize) {
        return false;
    }
    seek(oldpos, SEEK_SET);
    return true;
}

#ifdef __cplusplus
#define restrict
#endif

/**
\group_string
 * Scan the first \p n bytes of the buffer \p s, for the character \p c.
 * @param[in] s buffer to scan
 * @param[in] c character to look for
 * @param[in] n size of buffer
 * @return a pointer to the first byte to match, or NULL if not found.
 */
static force_inline void *memchr(const void *s, int c, size_t n)
{
    unsigned char cc = c;
    const char *end, *p = (const char *)s;

    for (end = p + n; p < end; p++)
        if (*p == cc)
            return (void *)p;
    return (void *)0;
}

/* Provided by LLVM intrinsics */
/**
\group_string
 * [LLVM Intrinsic] Fills \p src location with \p c up to length \p n.
 * @param[out] src pointer to buffer
 * @param[in] c character to fill buffer with
 * @param[in] n length of buffer
 * @return \p src*/
void *memset(void *src, int c, uintptr_t n) __attribute__((nothrow)) __attribute__((__nonnull__((1))));

/**
\group_string
 * [LLVM Intrinsic] Copies data between overlapping buffers, from
 * \p src to \p dst to length \p n.
 * @param[out] dst destination buffer
 * @param[in] src source buffer
 * @param[in] n amount of bytes to copy
 * @return dst */
void *memmove(void *dst, const void *src, uintptr_t n)
    __attribute__((__nothrow__)) __attribute__((__nonnull__(1, 2)));

/**
\group_string
 * [LLVM Intrinsic] Copies data between two non-overlapping buffers,
 * from \p src to \p dst to length \p n.
 * @param[out] dst destination buffer
 * @param[in] src source buffer
 * @param[in] n amount of bytes to copy
 * @return dst */
void *memcpy(void *restrict dst, const void *restrict src, uintptr_t n)
    __attribute__((__nothrow__)) __attribute__((__nonnull__(1, 2)));

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wincompatible-library-redeclaration"
/**
\group_string
 * [LLVM Intrinsic] Compares two memory buffers, \p s1 and \p s2 to length \p n.
 * @param[in] s1 buffer one
 * @param[in] s2 buffer two
 * @param[in] n amount of bytes to copy
 * @return an integer less than, equal to, or greater than zero if the first
 * \p n bytes of \p s1 are found, respectively, to be less than, to match,
 * or be greater than the first \p n bytes of \p s2.*/
int memcmp(const void *s1, const void *s2, uint32_t n)
    __attribute__((__nothrow__)) __attribute__((__pure__)) __attribute__((__nonnull__(1, 2)));
#pragma GCC diagnostic pop

/**
\group_disasm
 * Disassembled memory operand: scale_reg*scale + add_reg + displacement.
 */
struct DIS_mem_arg {
    enum DIS_SIZE access_size; /**< size of access */
    enum X86REGS scale_reg;    /**< register used as scale */
    enum X86REGS add_reg;      /**< register used as displacemenet */
    uint8_t scale;             /**< scale as immediate number */
    int32_t displacement;      /**< displacement as immediate number */
};

/**
\group_disasm
 * Disassembled operand.
 */
struct DIS_arg {
    enum DIS_ACCESS access_type; /**< type of access */
    enum DIS_SIZE access_size;   /**< size of access */
    union {
        struct DIS_mem_arg mem; /**< memory operand - member of union 'u' */
        enum X86REGS reg;       /**< register operand - member of union 'u' */
        uint64_t other;         /**< other operand - member of union 'u' */
    } u;
};

/**
\group_disasm
 * Disassembled instruction.
 */
struct DIS_fixed {
    enum X86OPS x86_opcode;       /**< opcode of X86 instruction */
    enum DIS_SIZE operation_size; /**< size of operation */
    enum DIS_SIZE address_size;   /**< size of address */
    uint8_t segment;              /**< segment */
    struct DIS_arg arg[3];        /**< arguments */
};

/**
\group_disasm
 * Disassembles one X86 instruction starting at the specified offset.
 * @param[out] result disassembly result, memset to 0 on error
 * @param[in] offset start disassembling from this offset, in the current file
 * @param[in] len max amount of bytes to disassemble
 * @return offset where disassembly ended, -1 on error
 */
static force_inline uint32_t
DisassembleAt(struct DIS_fixed *result, uint32_t offset, uint32_t len)
{
    struct DISASM_RESULT res;
    unsigned i;
    memset(&res, 0, sizeof(struct DISASM_RESULT));
    seek(offset, SEEK_SET);
    offset                 = disasm_x86(&res, len < sizeof(res) ? len : sizeof(res));
    result->x86_opcode     = (enum X86OPS)cli_readint16(&res.real_op);
    result->operation_size = (enum DIS_SIZE)res.opsize;
    result->address_size   = (enum DIS_SIZE)res.adsize;
    result->segment        = res.segment;
    for (i = 0; i < 3; i++) {
        struct DIS_arg *arg = &result->arg[i];
        arg->access_type    = (enum DIS_ACCESS)res.arg[i][0];
        switch (result->arg[i].access_type) {
            case ACCESS_MEM:
                arg->u.mem.access_size  = (enum DIS_SIZE)res.arg[i][1];
                arg->u.mem.scale_reg    = (enum X86REGS)res.arg[i][2];
                arg->u.mem.add_reg      = (enum X86REGS)res.arg[i][3];
                arg->u.mem.scale        = res.arg[i][4];
                arg->u.mem.displacement = cli_readint32((const uint32_t *)&res.arg[i][6]);
                break;
            case ACCESS_REG:
                arg->u.reg = (enum X86REGS)res.arg[i][1];
                break;
            default: {
                uint64_t x   = cli_readint32((const uint32_t *)&res.arg[i][6]);
                arg->u.other = (x << 32) | cli_readint32((const uint32_t *)&res.arg[i][2]);
                break;
            }
        }
    }
    return offset;
}

// re2c macros
#define RE2C_BSIZE 1024
typedef struct {
    unsigned char *cur, *lim, *mrk, *ctx, *eof, *tok;
    int res;
    int32_t tokstart;
    unsigned char buffer[RE2C_BSIZE];
} regex_scanner_t;

#define YYCTYPE unsigned char
#define YYCURSOR re2c_scur
#define YYLIMIT re2c_slim
#define YYMARKER re2c_smrk
#define YYCONTEXT re2c_sctx
#define YYFILL(n)                  \
    {                              \
        RE2C_FILLBUFFER(n);        \
        if (re2c_sres <= 0) break; \
    }

#define REGEX_SCANNER                                                         \
    unsigned char *re2c_scur, *re2c_stok, *re2c_smrk, *re2c_sctx, *re2c_slim; \
    int re2c_sres;                                                            \
    int32_t re2c_stokstart;                                                   \
    unsigned char re2c_sbuffer[RE2C_BSIZE];                                   \
    re2c_scur = re2c_slim = re2c_smrk = re2c_sctx = &re2c_sbuffer[0];         \
    re2c_sres                                     = 0;                        \
    RE2C_FILLBUFFER(0);

#define REGEX_POS (-(re2c_slim - re2c_scur) + seek(0, SEEK_CUR))
#define REGEX_LOOP_BEGIN            \
    do {                            \
        re2c_stok      = re2c_scur; \
        re2c_stokstart = REGEX_POS; \
    } while (0);
#define REGEX_RESULT (re2c_sres)

#define RE2C_DEBUG_PRINT                       \
    do {                                       \
        char buf[81];                          \
        uint32_t here = seek(0, SEEK_CUR);     \
        uint32_t d    = re2c_slim - re2c_scur; \
        uint32_t end  = here - d;              \
        unsigned len  = end - re2c_stokstart;  \
        if (len > 80) {                        \
            unsigned skipped = len - 74;       \
            seek(re2c_stokstart, SEEK_SET);    \
            if (read(buf, 37) == 37)           \
                break;                         \
            memcpy(buf + 37, "[...]", 5);      \
            seek(end - 37, SEEK_SET);          \
            if (read(buf, 37) != 37)           \
                break;                         \
            buf[80] = '\0';                    \
        } else {                               \
            seek(re2c_stokstart, SEEK_SET);    \
            if (read(buf, len) != len)         \
                break;                         \
            buf[len] = '\0';                   \
        }                                      \
        buf[80] = '\0';                        \
        debug_print_str(buf, 0);               \
        seek(here, SEEK_SET);                  \
    } while (0)

#define DEBUG_PRINT_REGEX_MATCH RE2C_DEBUG_PRINT

#define BUFFER_FILL(buf, cursor, need, limit)                                   \
    do {                                                                        \
        (limit) = fill_buffer((buf), sizeof((buf)), (limit), (cursor), (need)); \
    } while (0);

#define BUFFER_ENSURE(buf, cursor, need, limit)   \
    do {                                          \
        if ((cursor) + (need) >= (limit)) {       \
            BUFFER_FILL(buf, cursor, need, limit) \
            (cursor) = 0;                         \
        }                                         \
    } while (0);

/* Move stok to offset 0, and fill rest of buffer, at least with 'len' bytes.
 *  Adjust the other pointers, which must be after the stok pointer!
 */
#define RE2C_FILLBUFFER(need)                                                                       \
    do {                                                                                            \
        uint32_t cursor = re2c_stok - &re2c_sbuffer[0];                                             \
        int32_t limit   = re2c_slim - &re2c_sbuffer[0];                                             \
        limit           = fill_buffer(re2c_sbuffer, sizeof(re2c_sbuffer), limit, (cursor), (need)); \
        if (!limit) {                                                                               \
            re2c_sres = 0;                                                                          \
        } else if (limit <= (need)) {                                                               \
            re2c_sres = -1;                                                                         \
        } else {                                                                                    \
            uint32_t curoff = re2c_scur - re2c_stok;                                                \
            uint32_t mrkoff = re2c_smrk - re2c_stok;                                                \
            uint32_t ctxoff = re2c_sctx - re2c_stok;                                                \
            re2c_slim       = &re2c_sbuffer[0] + limit;                                             \
            re2c_stok       = &re2c_sbuffer[0];                                                     \
            re2c_scur       = &re2c_sbuffer[0] + curoff;                                            \
            re2c_smrk       = &re2c_sbuffer[0] + mrkoff;                                            \
            re2c_sctx       = &re2c_sbuffer[0] + ctxoff;                                            \
            re2c_sres       = limit;                                                                \
        }                                                                                           \
    } while (0);

/**
 * ilog2_compat for 0.96 compatibility, you should use ilog2()
 * 0.96.1 API instead of this one!
 * @param a input
 * @param b input
 * @return 2^26*log2(a/b)
 */
static inline int32_t ilog2_compat(uint32_t a, uint32_t b)
{
    uint32_t c = a > b ? a : b;
    if (c < 2048) {
        // scale up a,b to [0, 4096]
        uint32_t scale = 2048 / c;
        a *= scale;
        b *= scale;
    } else {
        // scale down a,b to [0, 4096]
        uint32_t scale = (c + 2047) / 2048;
        a /= scale;
        b /= scale;
    }
    // log(a/b) = log(a*scale/(b*scale)) = log(a*scale) - log(b*scale)
    return ilog_table[a] - ilog_table[b];
}
