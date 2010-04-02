/*
 *  Copyright (C) 2009-2010 Sourcefire, Inc.
 *  All rights reserved.
 *  Authors: Török Edvin
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
#define force_inline inline __attribute__((always_inline))
#if __has_feature(attribute_overloadable)
/* Yes, clang supports overloading functions in C! */
static force_inline void __attribute__((overloadable)) debug(const char * str)
{
    debug_print_str((const uint8_t*)str, 0);
}
static force_inline void __attribute__((overloadable)) debug(const uint8_t* str)
{
    debug_print_str((const uint8_t*)str, 0);
}
static force_inline void __attribute__((overloadable)) debug(uint32_t a)
{
    debug_print_uint(a);
}
void debug(...) __attribute__((overloadable, unavailable));
#endif


/* Virusname definition handling */
/**
 * Declares the virusname prefix.
 * @param name the prefix common to all viruses reported by this bytecode
 * */
#define VIRUSNAME_PREFIX(name) const char __clambc_virusname_prefix[] = name;
/** Declares all the virusnames that this bytecode can report.
 * @param ... a comma-separated list of strings interpreted as virusnames  */
#define VIRUSNAMES(...) const char *const __clambc_virusnames[] = {__VA_ARGS__};

/* Logical signature handling */

typedef struct signature {
    uint64_t id;
} __Signature;

#define PE_UNPACKER_DECLARE const uint16_t __clambc_kind = BC_PE_UNPACKER;
/** Marks the beginning of the subsignature name declaration section */
#define SIGNATURES_DECL_BEGIN \
    struct __Signatures {
/** Declares a name for a subsignature */
#define DECLARE_SIGNATURE(name) \
    const char *name##_sig;\
    __Signature name;
/** Marks the end of the subsignature name declaration section */
#define SIGNATURES_DECL_END };

/** Defines the ClamAV file target.
 * @param tgt ClamAV signature type (0 - raw, 1 - PE, etc.) */
#define TARGET(tgt) const unsigned short __Target = (tgt);

/** Marks the beginning of subsignature pattern definitions. 
 * \sa SIGNATURES_DECL_BEGIN */
/* some other macro may use __COUNTER__, so we need to subtract its current\
 * value to obtain zero-based indices */
#define SIGNATURES_DEF_BEGIN \
    static const unsigned __signature_bias = __COUNTER__+1;\
const struct __Signatures Signatures = {\
/** Defines the pattern for a previously declared subsignature.
 * \sa DECLARE_SIGNATURE
 * @param name the name of a previously declared subsignature
 * @param hex the pattern for this subsignature
 * */
#define DEFINE_SIGNATURE(name, hex) \
    .name##_sig = (hex),\
    .name = {__COUNTER__ - __signature_bias},
/** Marks the end of the subsignature pattern definitions.*/
#define SIGNATURES_END };\

/** Returns how many times the specified signature matched.
 * @param sig name of subsignature queried
 * @return number of times this subsignature matched in the entire file
 *
 * This is a constant-time operation, the counts for all subsignatures are
 * already computed.*/
static force_inline uint32_t count_match(__Signature sig)\
{ return __clambc_match_counts[sig.id]; }\

/** Returns whether the specified subsignature has matched at least once.
 * @param sig name of subsignature queried
 * @return 1 if subsignature one or more times, 0 otherwise */
static force_inline uint32_t matches(__Signature sig)\
{ return __clambc_match_counts[sig.id]  != 0; }\

/** Sets the specified virusname as the virus detected by this bytecode.
 * @param virusname the name of the virus, excluding the prefix, must be one of
 * the virusnames declared in \p VIRUSNAMES.
 * \sa VIRUSNAMES */
static force_inline void foundVirus(const char *virusname)
{
    setvirusname((const uint8_t*)virusname, 0);
}

/** Returns the currently scanned file's size.
  * @return file size as 32-bit unsigned integer */
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
 * Returns true if the bytecode is executing on a big-endian CPU.
 * @return true if executing on bigendian CPU, false otherwise
 *
 * This will be optimized away in libclamav, but it must be used when dealing
 * with endianess for portability reasons.
 * For example whenever you read a 32-bit integer from a file, it can be written
 * in little-endian convention (x86 CPU for example), or big-endian convention
 * (PowerPC CPU for example).
 * If the file always contains little-endian integers, then conversion might be
 * needed.
 * ClamAV bytecodes by their nature must only handle known-endian integers, if
 * endianness can change, then both situations must be taken into account (based
 * on a 1-byte field for example).
 */
bool __is_bigendian(void) __attribute__((const)) __attribute__((nothrow));

/** Converts the specified value if needed, knowing it is in little endian
 * order.
 * @param[in] v 32-bit integer as read from a file
 * @return integer converted to host's endianess */
static uint32_t force_inline le32_to_host(uint32_t v)
{
    return __is_bigendian() ? __builtin_bswap32(v) : v;
}

/** Converts the specified value if needed, knowing it is in little endian
 * order.
 * @param[in] v 16-bit integer as read from a file
 * @return integer converted to host's endianess */
static uint16_t force_inline le16_to_host(uint16_t v)
{
    return __is_bigendian() ? ((v & 0xff) << 8) | ((v >> 8) & 0xff) : v;
}

/** Reads from the specified buffer a 32-bit of little-endian integer.
 * @param[in] buff pointer to buffer
 * @return 32-bit little-endian integer converted to host endianness */
static uint32_t force_inline cli_readint32(const void* buff)
{
    uint32_t v = ((const union unaligned_32 *)buff)->una_s32;
    return le32_to_host(v);
}

/** Reads from the specified buffer a 16-bit of little-endian integer.
 * @param[in] buff pointer to buffer
 * @return 16-bit little-endian integer converted to host endianness */
static uint16_t force_inline cli_readint16(const void* buff)
{
    uint16_t v = ((const union unaligned_16 *)buff)->una_s16;
    return le16_to_host(v);
}

/** Writes the specified value into the specified buffer in little-endian order
 * @param[out] offset pointer to buffer to write to
 * @param[in] v value to write*/
static void force_inline cli_writeint32(void* offset, uint32_t v)
{
    ((union unaligned_32 *)offset)->una_u32 = le32_to_host(v);
}

/* --------------------- PE helper functions ------------------------ */
/** Returns whether the current file has executable information.
 * @return true if the file has exe info, false otherwise */
static force_inline bool hasExeInfo(void)
{
    return __clambc_pedata.offset != -1;
}

static force_inline bool isPE64(void)
{
  return le16_to_host(__clambc_pedata.opt64.Magic) == 0x020b;
}

static force_inline uint8_t getPEMajorLinkerVersion(void)
{
  return isPE64() ?
    __clambc_pedata.opt64.MajorLinkerVersion :
    __clambc_pedata.opt32.MajorLinkerVersion;
}

static force_inline uint8_t getPEMinorLinkerVersion(void)
{
  return isPE64() ?
    __clambc_pedata.opt64.MajorLinkerVersion :
    __clambc_pedata.opt32.MajorLinkerVersion;
}

static force_inline uint32_t getPESizeOfCode(void)
{
  return le32_to_host(isPE64() ?
                      __clambc_pedata.opt64.SizeOfCode :
                      __clambc_pedata.opt32.SizeOfCode);
}

static force_inline uint32_t getPESizeOfInitializedData(void)
{
  return le32_to_host(isPE64() ?
                      __clambc_pedata.opt64.SizeOfInitializedData :
                      __clambc_pedata.opt32.SizeOfInitializedData);
}

static force_inline uint32_t getPESizeOfUninitializedData(void)
{
  return le32_to_host(isPE64() ?
                      __clambc_pedata.opt64.SizeOfUninitializedData :
                      __clambc_pedata.opt32.SizeOfUninitializedData);
}

static force_inline uint32_t getPEBaseOfCode(void)
{
  return le32_to_host(isPE64() ?
                      __clambc_pedata.opt64.BaseOfCode :
                      __clambc_pedata.opt32.BaseOfCode);
}

static force_inline uint32_t getPEBaseOfData(void)
{
  return le32_to_host(isPE64() ?
                      0 :
                      __clambc_pedata.opt32.BaseOfData);
}

static force_inline uint64_t getPEImageBase(void)
{
  return le32_to_host(isPE64() ?
                      __clambc_pedata.opt64.ImageBase :
                      __clambc_pedata.opt32.ImageBase);
}

static force_inline uint32_t getPESectionAlignment(void)
{
  return le32_to_host(isPE64() ?
                      __clambc_pedata.opt64.SectionAlignment :
                      __clambc_pedata.opt32.SectionAlignment);
}

static force_inline uint32_t getPEFileAlignment(void)
{
  return le32_to_host(isPE64() ?
                      __clambc_pedata.opt64.FileAlignment :
                      __clambc_pedata.opt32.FileAlignment);
}

static force_inline uint16_t getPEMajorOperatingSystemVersion(void)
{
  return le32_to_host(isPE64() ?
                      __clambc_pedata.opt64.MajorOperatingSystemVersion :
                      __clambc_pedata.opt32.MajorOperatingSystemVersion);
}

static force_inline uint16_t getPEMinorOperatingSystemVersion(void)
{
  return le32_to_host(isPE64() ?
                      __clambc_pedata.opt64.MinorOperatingSystemVersion :
                      __clambc_pedata.opt32.MinorOperatingSystemVersion);
}

static force_inline uint16_t getPEMajorImageVersion(void)
{
  return le32_to_host(isPE64() ?
                      __clambc_pedata.opt64.MajorImageVersion :
                      __clambc_pedata.opt32.MajorImageVersion);
}

static force_inline uint16_t getPEMinorImageVersion(void)
{
  return le32_to_host(isPE64() ?
                      __clambc_pedata.opt64.MinorImageVersion :
                      __clambc_pedata.opt32.MinorImageVersion);
}

static force_inline uint16_t getPEMajorSubsystemVersion(void)
{
  return le32_to_host(isPE64() ?
                      __clambc_pedata.opt64.MajorSubsystemVersion :
                      __clambc_pedata.opt32.MajorSubsystemVersion);
}

static force_inline uint16_t getPEMinorSubsystemVersion(void)
{
  return le32_to_host(isPE64() ?
                      __clambc_pedata.opt64.MinorSubsystemVersion :
                      __clambc_pedata.opt32.MinorSubsystemVersion);
}

static force_inline uint32_t getPEWin32VersionValue(void)
{
  return le32_to_host(isPE64() ?
                      __clambc_pedata.opt64.Win32VersionValue :
                      __clambc_pedata.opt32.Win32VersionValue);
}

static force_inline uint32_t getPESizeOfImage(void)
{
  return le32_to_host(isPE64() ?
                      __clambc_pedata.opt64.SizeOfImage :
                      __clambc_pedata.opt32.SizeOfImage);
}

static force_inline uint32_t getPESizeOfHeaders(void)
{
  return le32_to_host(isPE64() ?
                      __clambc_pedata.opt64.SizeOfHeaders :
                      __clambc_pedata.opt32.SizeOfHeaders);
}

static force_inline uint32_t getPECheckSum(void)
{
  return le32_to_host(isPE64() ?
                      __clambc_pedata.opt64.CheckSum :
                      __clambc_pedata.opt32.CheckSum);
}

static force_inline uint16_t getPESubsystem(void)
{
  return le32_to_host(isPE64() ?
                      __clambc_pedata.opt64.Subsystem :
                      __clambc_pedata.opt32.Subsystem);
}

static force_inline uint16_t getPEDllCharacteristics(void)
{
  return le32_to_host(isPE64() ?
                      __clambc_pedata.opt64.DllCharacteristics :
                      __clambc_pedata.opt32.DllCharacteristics);
}

static force_inline uint32_t getPESizeOfStackReserve(void)
{
  return le32_to_host(isPE64() ?
                      __clambc_pedata.opt64.SizeOfStackReserve :
                      __clambc_pedata.opt32.SizeOfStackReserve);
}

static force_inline uint32_t getPESizeOfStackCommit(void)
{
  return le32_to_host(isPE64() ?
                      __clambc_pedata.opt64.SizeOfStackCommit :
                      __clambc_pedata.opt32.SizeOfStackCommit);
}

static force_inline uint32_t getPESizeOfHeapReserve(void)
{
  return le32_to_host(isPE64() ?
                      __clambc_pedata.opt64.SizeOfHeapReserve :
                      __clambc_pedata.opt32.SizeOfHeapReserve);
}

static force_inline uint32_t getPESizeOfHeapCommit(void)
{
  return le32_to_host(isPE64() ?
                      __clambc_pedata.opt64.SizeOfHeapCommit :
                      __clambc_pedata.opt32.SizeOfHeapCommit);
}

static force_inline uint32_t getPELoaderFlags(void)
{
  return le32_to_host(isPE64() ?
                      __clambc_pedata.opt64.LoaderFlags :
                      __clambc_pedata.opt32.LoaderFlags);
}

/** Returns the offset of the EntryPoint in the executable file.
 * @return offset of EP as 32-bit unsigned integer */
static force_inline uint32_t getEntryPoint(void)
{
    return __clambc_pedata.ep;
}

/** Returns the offset of the executable in the file.
 * @return offset of embedded executable inside file. */
static force_inline uint32_t getExeOffset(void)
{
    return __clambc_pedata.offset;
}

/** Returns the number of sections in this executable file.
 * @return number of sections as 16-bit unsigned integer */
static force_inline uint16_t getNumberOfSections(void)
{
    return __clambc_pedata.nsections;
}


/** Returns the ImageBase with the correct endian conversion */
static force_inline uint32_t getImageBase(void)
{
  return le32_to_host(__clambc_pedata.opt32.ImageBase);
}

static uint32_t getVirtualEntryPoint(void)
{
    return le32_to_host(__clambc_pedata.opt32.AddressOfEntryPoint);
}

static uint32_t getLFANew(void)
{
    return le32_to_host(__clambc_pedata.e_lfanew);
}

static uint32_t getSectionRVA(unsigned i)
{
  struct cli_exe_section section;
  if (get_pe_section(&section, i) == -1)
    return -1;
  return section.rva;
}
#ifdef __cplusplus
#define restrict
#endif

/** Scan the first \p n bytes of the buffer \p s, for the character \p c.
  @param[in] s buffer to scan
  @param c character to look for
  @param n size of buffer
  @return a pointer to the first byte to match, or NULL if not found.
 */
static void* memchr(const void* s, int c, size_t n)
{
  unsigned char cc = c;
  const char *end, *p = s;

  for (end=p+n; p < end; p++)
    if (*p == cc)
      return p;
  return (void*)0;
}

/* Provided by LLVM intrinsics */
/** Fills the specified buffer to the specified value.
 * @param[out] src pointer to buffer
 * @param[in] c character to fill buffer with
 * @param[in] n length of buffer
 * @return \p src*/
void* memset(void *src, int c, uintptr_t n) __attribute__((nothrow)) __attribute__((__nonnull__((1))));

/** Copies data between two possibly overlapping buffers.
 * @param[out] dst destination buffer
 * @param[in] src source buffer
 * @param[in] n amount of bytes to copy
 * @return dst */
void *memmove (void *dst, const void *src, uintptr_t n)
    __attribute__ ((__nothrow__)) __attribute__ ((__nonnull__ (1, 2)));
/** Copies data between two non-overlapping buffers.
 * @param[out] dst destination buffer
 * @param[in] src source buffer
 * @param[in] n amount of bytes to copy
 * @return dst */
void *memcpy (void *restrict dst, const void *restrict src, uintptr_t n)
    __attribute__ ((__nothrow__)) __attribute__ ((__nonnull__ (1, 2)));

/** Compares two memory buffers.
 * @param[in] s1 buffer one
 * @param[in] s2 buffer two
 * @param[in] n amount of bytes to copy
 * @return an integer less than, equal to, or greater than zero if the first 
 * \p n bytes of \p s1 are found, respectively, to be less than, to match, 
 * or be greater than the first \p n bytes of \p s2.*/
int memcmp (const void *s1, const void *s2, uint32_t n)
    __attribute__ ((__nothrow__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1, 2)));

/** disassembled memory operand: scale_reg*scale + add_reg + displacement */
struct DIS_mem_arg {
    enum DIS_SIZE access_size;/**< size of access */
    enum X86REGS scale_reg;/**< register used as scale */
    enum X86REGS add_reg;/**< register used as displacemenet */
    uint8_t scale;/**< scale as immediate number */
    int32_t displacement;/**< displacement as immediate number */
};

/** disassembled operand */
struct DIS_arg {
    enum DIS_ACCESS access_type;/**< type of access */
    enum DIS_SIZE access_size;/**< size of access */
    union {
	struct DIS_mem_arg mem;/**< memory operand */
	enum X86REGS reg;/**< register operand */
	uint64_t other;/**< other operand */
    } u;
};

/** disassembled instruction */
struct DIS_fixed {
    enum X86OPS x86_opcode;/**< opcode of X86 instruction */
    enum DIS_SIZE operation_size;/**< size of operation */
    enum DIS_SIZE address_size;/**< size of address */
    uint8_t segment;/**< segment */
    struct DIS_arg arg[3];/** arguments */
};

/** Disassembles one X86 instruction starting at the specified offset.
 * @param[out] result disassembly result
 * @param[in] offset start disassembling from this offset, in the current file
 * @param[in] len max amount of bytes to disassemble
 * @return offset where disassembly ended*/
static force_inline uint32_t
DisassembleAt(struct DIS_fixed* result, uint32_t offset, uint32_t len)
{
    struct DISASM_RESULT res;
    unsigned i;
    seek(offset, SEEK_SET);
    offset = disasm_x86(&res, len);
    result->x86_opcode = (enum X86OPS) cli_readint16(&res.real_op);
    result->operation_size = (enum DIS_SIZE) res.opsize;
    result->address_size = (enum DIS_SIZE) res.adsize;
    result->segment = res.segment;
    for (i=0;i<3;i++) {
	struct DIS_arg *arg = &result->arg[i];
	arg->access_type = (enum DIS_ACCESS) res.arg[i][0];
	switch (result->arg[i].access_type) {
	    case ACCESS_MEM:
		arg->u.mem.access_size = (enum DIS_SIZE) res.arg[i][1];
		arg->u.mem.scale_reg = (enum X86REGS) res.arg[i][2];
		arg->u.mem.add_reg = (enum X86REGS) res.arg[i][3];
		arg->u.mem.scale = res.arg[i][4];
		arg->u.mem.displacement = cli_readint32((const uint32_t*)&res.arg[i][6]);
		break;
	    case ACCESS_REG:
		arg->u.reg = (enum X86REGS) res.arg[i][1];
		break;
	    default: {
		uint64_t x = cli_readint32((const uint32_t*)&res.arg[i][6]);
		arg->u.other = (x << 32) | cli_readint32((const uint32_t*)&res.arg[i][2]);
		break;
	    }
	}
    }
    return offset;
}

// re2c macros
#define RE2C_BSIZE 128
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
#define YYFILL(n) { \
  RE2C_FILLBUFFER(n);\
  if (re2c_sres <= 0) break;\
}

#define REGEX_SCANNER unsigned char *re2c_scur, *re2c_stok, *re2c_smrk, *re2c_sctx, *re2c_slim;\
  int re2c_sres; int32_t re2c_stokstart;\
  unsigned char re2c_sbuffer[RE2C_BSIZE];\
  re2c_scur = re2c_slim = re2c_smrk = re2c_sctx = &re2c_sbuffer[0];\
  re2c_sres = 0;\
  RE2C_FILLBUFFER(0);

#define REGEX_POS (-(re2c_slim - re2c_scur) + seek(0, SEEK_CUR))
#define REGEX_LOOP_BEGIN do { re2c_stok = re2c_scur; re2c_stokstart = REGEX_POS;} while (0);
#define REGEX_RESULT (re2c_sres)

#define RE2C_DEBUG_PRINT \
do {\
  char buf[81];\
  uint32_t here = seek(0, SEEK_CUR);\
  uint32_t d = re2c_slim - re2c_scur;\
  uint32_t end = here - d;\
  unsigned len = end - re2c_stokstart;\
  if (len > 80) {\
    unsigned skipped = len - 74;\
    seek(re2c_stokstart, SEEK_SET);\
    if (read(buf, 37) == 37)\
      break;\
    memcpy(buf+37, "[...]", 5);\
    seek(end-37, SEEK_SET);\
    if (read(buf, 37) != 37)\
      break;\
    buf[80] = '\0';\
  } else {\
    seek(re2c_stokstart, SEEK_SET);\
    if (read(buf, len) != len)\
      break;\
    buf[len] = '\0';\
  }\
  buf[80] = '\0';\
  debug_print_str(buf, 0);\
  seek(here, SEEK_SET);\
} while (0)

#define DEBUG_PRINT_REGEX_MATCH RE2C_DEBUG_PRINT

#define BUFFER_FILL(buf, cursor, need, limit) do {\
  (limit) = fill_buffer((buf), sizeof((buf)), (limit), (cursor), (need));\
} while (0);

#define BUFFER_ENSURE(buf, cursor, need, limit) do {\
  if ((cursor) + (need) >= (limit)) {\
    BUFFER_FILL(buf, cursor, need, limit)\
    (cursor) = 0;\
  }\
} while (0);

/* Move stok to offset 0, and fill rest of buffer, at least with 'len' bytes.
   Adjust the other pointers, which must be after the stok pointer!
*/
#define RE2C_FILLBUFFER(need) do {\
  uint32_t cursor = re2c_stok - &re2c_sbuffer[0];\
  int32_t limit = re2c_slim - &re2c_sbuffer[0];\
  limit = fill_buffer(re2c_sbuffer, sizeof(re2c_sbuffer), limit, (cursor), (need));\
  if (!limit) {\
    re2c_sres = 0;\
  } else if (limit <= (need)) {\
     re2c_sres = -1;\
  } else {\
    uint32_t curoff = re2c_scur - re2c_stok;\
    uint32_t mrkoff = re2c_smrk - re2c_stok;\
    uint32_t ctxoff = re2c_sctx - re2c_stok;\
    re2c_slim = &re2c_sbuffer[0] + limit;\
    re2c_stok = &re2c_sbuffer[0];\
    re2c_scur = &re2c_sbuffer[0] + curoff;\
    re2c_smrk = &re2c_sbuffer[0] + mrkoff;\
    re2c_sctx = &re2c_sbuffer[0] + ctxoff;\
    re2c_sres = limit;\
  }\
} while (0);
