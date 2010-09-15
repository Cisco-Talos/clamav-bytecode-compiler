//PE file format: http://kishorekumar.net/pecoff_v8.1.htm
VIRUSNAME_PREFIX("BC.ImportsParser")

//PE_HOOK_DECLARE
PE_UNPACKER_DECLARE

/* one pe_import_entry for each imported DLL */
struct pe_import_entry {
  uint32_t import_lookup_table_rva; /* rva of imported functions */
  uint32_t timestamp; /* ignore */
  uint32_t forwarder; /* ignore */
  uint32_t name_rva;/* rva of DLL we are importing from */
  uint32_t iat_rva;/* IAT */
};

/* pointed to by import_lookup_table_rva */
#define DLLNAME_MAX 64
#define FUNCNAME_MAX 128

static force_inline void lowercase_str(char *str, uint32_t len)
{
  uint32_t i;
  len--;
  // lowercase and zero terminate
  for (i=0;i<len;i++) {
    uint8_t c = str[i];
    if (!c)
      break;
    if (c >= 'A' && c <= 'Z')
      str[i] |= 0x20;
  }
  for(;i<len;i++)
    str[i] = 0;
  str[len] = 0;
}

// return false to stop parsing, all must be 'static force_inline' callbacks
typedef bool (*import_dllname_cb_t)(char *dllname, uint32_t len, void *arg);
typedef bool (*import_dllfunc_cb_t)(char *dllname, uint32_t len, char *funcname,
                                    uint32_t len2, void *arg);

typedef bool (*import_dllord_cb_t)(char* dllname, uint32_t len, uint16_t ordinal,
                                   void *arg);

static bool parse_PE_imports(import_dllname_cb_t dllname_cb,
                                import_dllfunc_cb_t dllfunc_cb,
                                import_dllord_cb_t dllord_cb,
                                void *arg)
{
  struct pe_import_entry imported_dll;
  char dllname[DLLNAME_MAX];

  /* PE data directory 1 is imports */
  uint32_t rva = getPEDataDirRVA(1);
  if (!rva || !getPEDataDirSize(1)) {
    debug("no imports");
    return false;
  }
  while (readRVA(rva, &imported_dll, sizeof(imported_dll))) {
    // get the name of the DLL we import from
    uint32_t dllname_rva = cli_readint32(&imported_dll.name_rva);
    if (!dllname_rva) {
      //end of imports signaled by NULL struct
      return true;
    }
    memset(dllname, 0, sizeof(dllname));
    if (dllname_rva < rva /* corrupt imports */ ||
        !readRVA(dllname_rva, &dllname, sizeof(dllname))) {
      debug("corrupt imports, invalid name RVA");
      return false;
    }
    lowercase_str(dllname, sizeof(dllname));

    if (!dllname_cb(dllname, sizeof(dllname), arg))
      return false;

    // parse imported functions
    if (dllfunc_cb || dllord_cb) {
      uint32_t import_table_rva =
        cli_readint32(&imported_dll.import_lookup_table_rva);
      // if no lookup table, use IAT they are supposed to be equal
      if (!import_table_rva)
        import_table_rva = cli_readint32(&imported_dll.iat_rva);
      while (import_table_rva) {
        uint32_t import_entry;
        if (!readRVA(import_table_rva, &import_entry, 4)) {
          debug("corrupted imports, invalid ILT/IAT");
          break;
        }
        // convert LE to host endianess
        import_entry = cli_readint32(&import_entry);
        if (!import_entry)
          break;// end of imports for this DLL
        if (import_entry & 0x80000000) {
          if (dllord_cb && !dllord_cb(dllname, sizeof(dllname),
                                      import_entry & 0xffff, arg))
            break;
        } else if (dllname_cb) {
          // import by name
          char funcname[FUNCNAME_MAX];
          if (readRVA(import_entry, &funcname, sizeof(funcname))) {
            if (!dllfunc_cb(dllname, sizeof(dllname), funcname+2,
                            sizeof(funcname)-2, arg))
              break;
          }
        }
        import_table_rva += 4;
      }
    }

    /* read next import directory entry */
    rva += sizeof(imported_dll);
  }
  //fully parsed
  return true;
}

struct pe_export_directory_table {
  uint32_t reserved;
  uint32_t timestamp;
  uint16_t majorver;
  uint16_t minorver;
  uint32_t name_rva;/* rva of DLL name */
  uint32_t ordinal_base;
  uint32_t address_table_entries;/* # of entries */
  uint32_t number_name_pointers;/* # of name pointers */
  uint32_t export_address_table_rva;
  uint32_t name_pointer_rva;
  uint32_t ordinal_table_rva;
};

static bool parse_PE_exports(import_dllname_cb_t dllname_cb,
                             import_dllfunc_cb_t dllfunc_cb,
                             void *arg)
{
  struct pe_export_directory_table exports;
  char dllname[DLLNAME_MAX];

  memset(dllname, 0, sizeof(dllname));

  /* PE data directory 0 is exports */
  uint32_t rva = getPEDataDirRVA(0);
  if (!rva || !getPEDataDirSize(0)) {
    debug("no exports");
    return false;
  }

  if (!readRVA(rva, &exports, sizeof(exports))) {
    debug("corrupt exports");
    return false;
  }
  //get current DLL name
  uint32_t dllname_rva = cli_readint32(&exports.name_rva);
  if (dllname_rva) {
    if (dllname_rva < rva /* corrupt exports */ ||
        !readRVA(dllname_rva, &dllname, sizeof(dllname))) {
      debug("corrupt exports, invalid name RVA");
    }

    if (dllname_cb && !dllname_cb(dllname, sizeof(dllname), arg))
      return false;
  }

  // parse named exports
  if (dllfunc_cb) {
    uint32_t i;
    uint32_t name_pointer_rva;
    uint32_t name_pointer_table =
      pe_rawaddr(cli_readint32(&exports.name_pointer_rva));
    exports.number_name_pointers = cli_readint32(&exports.number_name_pointers);
    for (i=0;i<exports.number_name_pointers;i++) {
      char funcname[FUNCNAME_MAX];
      if (seek(name_pointer_table + 4*i, SEEK_SET) == -1) {
        debug("corrupt exports, invalid name pointer rva");
        return false;
      }
      if (read(&name_pointer_rva, 4) != 4) {
        debug("corrupt exports, invalid name pointer");
        return false;
      }
      name_pointer_rva = cli_readint32(&name_pointer_rva);

      if (!readRVA(name_pointer_rva, &funcname, sizeof(funcname)))
        return false;
      dllfunc_cb(dllname, sizeof(dllname), funcname, sizeof(funcname), arg);
    }
  }
  //fully parsed
  return true;
}


static force_inline bool print_imported_dll(char *dllname, uint32_t len, void* foo)
{
  debug("--------------------------------------------------------");
  debug_print_str_start(dllname, len);
  debug_print_str_nonl(" imported\n", 10);
  debug("-------------- imported functions: ---------------------");
  return true;
}

static force_inline bool print_exported_dll(char *dllname, uint32_t len, void* foo)
{
  debug("--------------------------------------------------------");
  debug_print_str_start(dllname, len);
  debug_print_str_nonl(" exported\n", 10);
  debug("-------------- exported functions: ---------------------");
  return true;
}

static force_inline bool print_imported_func(char *dllname, uint32_t len,
                                             char *funcname, uint32_t len2,
                                             void *arg)
{
  debug_print_str_start(funcname, len2);
  debug_print_str_nonl("\n", 1);
  return true;
}

static force_inline bool print_imported_ord(char *dllname, uint32_t len,
                                            uint16_t ord, void* arg)
{
  debug_print_str_start("ordinal ", 8);
  debug_print_uint(ord);
  debug_print_str_nonl("\n", 1);
  return true;
}

int entrypoint(void)
{
  if (isPE64()) {
    debug("can't parse PE32+ yet");
    return 0;
  }
  parse_PE_imports(print_imported_dll, print_imported_func, print_imported_ord,
                   (void*)0);
  parse_PE_exports(print_exported_dll, print_imported_func, (void*)0);
  return 0;
}
