VIRUSNAME_PREFIX("BC.PDF")
VIRUSNAMES("JS.HighEntropy")
// Copyright (C) 2007-2008, 2010 Sourcefire, Inc.
// Author: Török Edvin
// Based on:
//  libclamav/pdf.c Author: Nigel Horne
//  snort-nrt/src/preprocessors/dispatchLib/pdfParse Author: Matt Olney 
//  PDF 1.7 ISO 32000-1 specification

TARGET(0)

//experimental, test out on git version first
FUNCTIONALITY_LEVEL_MIN(FUNC_LEVEL_096_dev)

SIGNATURES_DECL_BEGIN
DECLARE_SIGNATURE(PDF_header_good)
DECLARE_SIGNATURE(PDF_header_old)
DECLARE_SIGNATURE(PDF_header_accepted)
DECLARE_SIGNATURE(PDF_EOF)
DECLARE_SIGNATURE(PDF_EOF_startxref)
SIGNATURES_DECL_END

SIGNATURES_DEF_BEGIN
/* The usual PDF header, according to spec */
DEFINE_SIGNATURE(PDF_header_good, "0:255044462d312e")
/* Older readers also accept %!PS-Adobe-N.n PDF-M.m */
DEFINE_SIGNATURE(PDF_header_old, "0:252150532d41646f62652d??2e????5044462d")
/* However PDF readers also accepts %PDF anywhere in first 1024 bytes,
   don't validate the version here, since there are %PDF-1111, and %PDF-2.4 */
DEFINE_SIGNATURE(PDF_header_accepted, "0,1024:255044462d")
DEFINE_SIGNATURE(PDF_EOF,"EOF-1024,1019:2525454f46")
DEFINE_SIGNATURE(PDF_EOF_startxref,"EOF-1280,1266:737461727478726566")
SIGNATURES_END

/* only test code don't extract or detect anything */
#define TEST_ONLY 1

bool logical_trigger(void)
{
  return matches(Signatures.PDF_header_good) ||
    matches(Signatures.PDF_header_old) ||
    matches(Signatures.PDF_header_accepted);
}

/*!max:re2c */
#if RE2C_BSIZE < YYMAXFILL
#error RE2C_BSIZE must be greated than YYMAXFILL
#endif

static force_inline void javascript_filter(uint32_t *probTable,
                                           unsigned  *entropySize,
                                           const uint8_t* jsString, unsigned jsSize)
{
  unsigned i;
  if (jsSize < 3)
    return;
  jsSize -= 3;
  for (i=0; i<jsSize; i++)
  {
    if(memcmp(jsString+i, "var", 3) == 0)
    {
      i=i+3; //Don't include "var" in entropy check
      while(i<jsSize && jsString[i] != '\x3d')
      {
        if(jsString[i] == '\x20') {
          i++;
        }
        else if (jsString[i] == '\x3d') {
          i--;
        }  else if (i+6 < jsSize && jsString[i] == 'l' && jsString[i+1] == 'e' &&
                    jsString[i+2] == 'n' && jsString[i+3] == 'g' &&
                    jsString[i+4] == 't' && jsString[i+4] == 'h') {
          i += 6;
        }
        else if(i+6<jsSize && memcmp(jsString+i, "length", 6) == 0) { //Common in randomized strings
          i = i+6;
        }
        else {
          // add to entropy counter
          probTable[jsString[i]]++;
          (*entropySize)++;
          i++;
        }
      }
    }
  }
}

static force_inline void javascript_process(uint32_t *probTable, unsigned
                                            *entropySize)
{
  uint64_t entropy = 0;
  unsigned i;
  // entropy checks on short strings may be FP prone
  if (*entropySize < 256) {
    memset(probTable, 0, sizeof(*probTable));
    *entropySize = 0;
    return;
  }
  // Shannon entropy is equal to the sum of (prob * (log(prob) / log(2))) for each character.
  for (i=0; i<256; i++)
  {
    if (probTable[i] != 0)
    {
      // The probability that any one character is next in the string.
      // p = probTable[i][0] / (float)entropySize;
      // entropy = entropy + (-1 *(p * (log(p) / log(2))));
      uint32_t p = probTable[i];
      //TODO: converting to 64-bit leads to bogus results
      uint32_t i_log = ilog2(p, *entropySize);
      entropy += p*i_log/ *entropySize;
    }
  }
  debug("Entropy of X bytes is Y, y/(2^27)");
  debug(*entropySize);
  debug(entropy >> 27);
  debug(entropy - (entropy>>27));
  if ((*entropySize < 512 && entropy > 16*(1<<27)) ||
      (*entropySize >= 512 && entropy > 8*(1<<27)) ||
      (*entropySize >= 1024 && entropy > 4*(1<<27))) {
    debug("The variables in this JavaScript object have a high degree of entropy");
#ifndef TEST_ONLY
    foundVirus("JS.HighEntropy");
#endif
  }
  memset(probTable, 0, sizeof(*probTable));
  *entropySize = 0;
}

static force_inline void decode_js_text(uint32_t *probTable,
                                        unsigned *entropySize, unsigned pos)
{
  unsigned char buf[RE2C_BSIZE];
  unsigned back = seek(0, SEEK_CUR);
  unsigned paranthesis = 0;
  int filled = 0;
  unsigned i = 0;
  seek(pos, SEEK_SET);
  BUFFER_FILL(buf, 0, 1, filled);
  debug("decodejstext");
#ifndef TEST_ONLY
  extract_new(pos);
#endif

  //TODO: decode PDFEncoding and UTF16
  while (filled > 0) {
    for (i=0;i<filled;i++) {
      if (buf[i] == '(') paranthesis++;
      if (buf[i] == ')') {
        if (!--paranthesis)
          break;
      }
    }
    javascript_filter(probTable, entropySize, buf, i);
#ifndef TEST_ONLY
    write(buf, i);
#endif
    if (i < RE2C_BSIZE && buf[i] == ')' && !paranthesis)
      break;
    BUFFER_FILL(buf, 0, 1, filled);
  }
  seek(back, SEEK_SET);
  javascript_process(probTable, entropySize);
}

static void decode_js_hex(uint32_t *probTable, unsigned *entropySize,
                          unsigned pos)
{
  unsigned char buf[RE2C_BSIZE];
  unsigned back = seek(0, SEEK_CUR);
  seek(pos, SEEK_SET);
  debug("decodejshex");

#ifndef TEST_ONLY
  extract_new(pos);
#endif
  seek(back, SEEK_SET);
}

static void decode_js_indirect(uint32_t *probTable, unsigned *entropySize,
                               unsigned pos, int32_t jsobjs, int32_t extractobjs)
{
  unsigned char buf[RE2C_BSIZE];
  unsigned back = seek(0, SEEK_CUR);
  seek(pos, SEEK_SET);

  int32_t obj0 = read_number(10);
  int32_t obj1 = read_number(10);
  /* TODO: this is not right, obj1 can be max 99999 */
  int32_t objid = (obj0 << 4) | (obj1&0xf);
  debug("indirect JS object reference found at/to");
  debug(pos);
  debug(objid);

  hashset_add(jsobjs, objid);
  hashset_add(extractobjs, objid);

  seek(back, SEEK_SET);
}

static const int hex_chars[256] = {
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
     0, 1, 2, 3,  4, 5, 6, 7,  8, 9,-1,-1, -1,-1,-1,-1,
    -1,10,11,12, 13,14,15,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,10,11,12, 13,14,15,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
};

static inline int cli_hex2int(const char c)
{
	return hex_chars[(const unsigned char)c];
}

#define search(a,b,c) (memstr((a),(b),(c),sizeof((c))-1) != -1)
static force_inline void parseFilters(uint8_t *filters, unsigned size,
                                      bool *has_deflate, bool *has_asciihex,
                                      bool *has_ascii85)
{
  unsigned i,j;
  bool had_escapes_inpdfname = false;
  for (i=0,j=0;i<size;i++) {
    if (filters[i] == '/')
      had_escapes_inpdfname = false;
    if (filters[i] == '#' && i+1 < size) {
      filters[j++] = (cli_hex2int(filters[i+1]) << 4) | cli_hex2int(filters[i+2]);
      continue;
    }
    if (filters[i] == ' ' && had_escapes_inpdfname) {
      // /#4aava -> /Java#
      filters[j++] = '#';
    }
    if (j != i)
      filters[j] = filters[i];
    j++;
  }
  filters[j] = 0;
  if (!search(filters, j, "/Filter"))
    return;
  if (search(filters, j, "/FlateDecode")) {
    debug("found FlateDecode filter");
    *has_deflate = 1;
  }
  if (search(filters, j, "/ASCIIHexDecode")) {
    debug("found AsciiHexDecode filter");
    *has_asciihex = 1;
  }
  if (search(filters, j, "/ASCII85Decode")) {
    debug("found Ascii85Decode filter");
    *has_ascii85 = 1;
  }
  if (!*has_deflate && !*has_asciihex && !*has_ascii85) {
    debug("unhandled filter");
  }
}

static bool force_inline ascii85decode(int inbuf, int outbuf, unsigned avail)
{
  return false;
}

static bool force_inline asciihexdecode(int inbuf, int outbuf, unsigned avail)
{
  unsigned i,j;
  const uint8_t *in = buffer_pipe_read_get(inbuf, avail);
  if (!in)
    return false;

  unsigned outavail = buffer_pipe_write_avail(outbuf);
  uint8_t *out = buffer_pipe_write_get(outbuf, outavail);
  if (!out)
    return false;

  for (i=0,j=0;i<avail && j<outavail;i++) {
    if (in[i] == ' ')
      continue;
    if (in[i] == '>')
      break;
    if (i+1 >= avail)
      break;
    out[j++] = (cli_hex2int(in[i]) << 4) | cli_hex2int(in[i+1]);
    i++;
  }
  if (!i)
    return false;
  buffer_pipe_read_stopped(inbuf, i);
  seek(i, SEEK_CUR);
  buffer_pipe_write_stopped(outbuf, j);
  return true;
}

static force_inline void extract_obj(uint32_t *probTable, unsigned *entropySize, unsigned pos, unsigned jsnorm)
{
  char filters[1025];
  unsigned filtern;
  debug("extractobj");
  unsigned back = seek(0, SEEK_CUR);
  seek(pos, SEEK_SET);
  unsigned beginpos = pos;
  /* TODO: use state-machine here too,
     for now we just decode assuming deflate encoding!*/
  pos = file_find("stream", 6);
  if (pos == -1)
    return;
  seek(beginpos, SEEK_SET);
  if (beginpos + 1024 > pos) {
  filtern = pos-beginpos;
  } else {
  filtern = 1024;
  }
  read(filters, filtern);
  filters[filtern]=0;

  bool has_deflate=false, has_asciihex=false, has_ascii85=false;
  parseFilters(filters, filtern, &has_deflate, &has_asciihex,
               &has_ascii85);
  if (!has_deflate && !has_asciihex && !has_ascii85) {
    debug("not decodable");
    return;
  }
  debug("decoding");
#ifndef TEST_ONLY
  extract_new(beginpos);
#endif
  seek(pos, SEEK_SET);
  unsigned char c = file_byteat(pos+6);
  if (c == '\r')
    pos += 8;
  else
    pos += 7;
  unsigned endpos;
  do {
    endpos = file_find("endstream", 9);
    if (endpos == -1)
      break;
    c = file_byteat(endpos-1);
    if (seek(endpos+9, SEEK_SET) == -1)
      break;
  } while (c != '\n' && c != '\r');
  int32_t in = buffer_pipe_new_fromfile(pos);
  seek(pos, SEEK_SET);
  int32_t out = buffer_pipe_new(4096);

  int32_t asciiin = in;
  if (has_ascii85 || has_asciihex) {
    in = buffer_pipe_new(4096);
  }

  int32_t inf=0;
  if (has_deflate) {
    debug("trying to inflate X bytes");
    debug(endpos - pos);
    inf = inflate_init(in, out, 15);
    if (inf < 0)
      return -1;
  }
  do {
    uint32_t avail;
    if (has_ascii85 || has_asciihex) {
      avail = buffer_pipe_read_avail(asciiin);
      if (!avail) {
        has_ascii85 = has_asciihex = false;
      } else {
        if (has_ascii85)
          has_ascii85 = ascii85decode(asciiin, in, avail);
        else if (has_asciihex)
          has_asciihex = asciihexdecode(asciiin, in, avail);
      }
    }
    if (has_deflate) {
      do {
        inflate_process(inf);
        avail = buffer_pipe_read_avail(out);
        uint8_t *outdata = buffer_pipe_read_get(out, avail);
        if (outdata) {
          javascript_filter(probTable, entropySize, outdata, avail);
#ifndef TEST_ONLY
          write(outdata, avail);
#endif
        }
        buffer_pipe_read_stopped(out, avail);
      } while (avail);
    } else {
      avail = buffer_pipe_read_avail(in);
      uint8_t *outdata = buffer_pipe_read_get(in, avail);
      if (outdata) {
        javascript_filter(probTable, entropySize, outdata, avail);
#ifndef TEST_ONLY
        write(outdata, avail);
#endif
      }
      buffer_pipe_read_stopped(in, avail);
    }
  } while (has_ascii85 || has_asciihex);
  debug("done");
  seek(back, SEEK_SET);
  javascript_process(probTable, entropySize);
  debug("donejs");
}

static void force_inline handle_pdfobj(uint32_t *probTable,
                                       unsigned *entropySize,
                          unsigned jsobjs, unsigned extractobjs,
                          unsigned objpos, unsigned pos)
{
  unsigned char buf[128];
  unsigned back = seek(0, SEEK_CUR);
  seek(objpos, SEEK_SET);

  int32_t obj0 = read_number(10);
  int32_t obj1 = read_number(10);
  /* TODO: this is not right, obj1 can be max 99999 */
  int32_t objid = (obj0 << 4) | (obj1&0xf);
//  if (hashset_contains(extractobjs, objid)) {
// extract all objs for now
    extract_obj(probTable, entropySize, pos, hashset_contains(jsobjs, objid));
    hashset_remove(extractobjs, objid);
    hashset_remove(jsobjs, objid);
//  }
  seek(back, SEEK_SET);
}

enum Flags {
  BAD_PDF_VERSION=1,
  BAD_PDF_HEADERPOS,
  PDF_TRAILING_GARBAGE,
  PDF_MISSING_TRAILER,
  PDF_BADXREF
};

// Note that the seek() API really just sets an offset in a structure, it
// doesn't call fseek() or lseek() since we use fmap!
// So calling seek() is fast here!
// false when seek is out of bounds (and we had to seek to 0)
bool seekFromEOF(int32_t delta)
{
  uint32_t size = getFilesize();
  if (size > delta) {
    seek(-delta, SEEK_END);
    return true;
  } else {
    seek(0, SEEK_SET);
    return false;
  }
}

// Find last occurence of @data, starting from current file position
static force_inline int32_t find_last(const uint8_t* data, uint32_t len, int32_t stop_pos)
{
  int32_t pos, lastpos = -1;
  while ((pos = file_find(data, len)) != -1) {
    if (pos > stop_pos)
      break;
    lastpos = pos;
    if (seek(pos + len, SEEK_SET) == -1)
      break;
  }
  return lastpos;
}

// look for %%EOF
static force_inline int32_t find_xref(unsigned *flags)
{
  int32_t pos, delta, nread;
  char buf[4096];
  if (matches(Signatures.PDF_EOF)) {
    int32_t eofpos = match_location(Signatures.PDF_EOF);
    if (matches(Signatures.PDF_EOF_startxref)) {
      int32_t xrefpos = match_location(Signatures.PDF_EOF_startxref);
      if (xrefpos < eofpos)
        return xrefpos;
    }
  }
  debug("PDF has trailing garbage");
  *flags |= 1 << PDF_TRAILING_GARBAGE;
  delta = 4096;
  bool seekOK;
  int32_t foundEOF = -1;
  // find EOF scanning backward
  do {
    seekOK = seekFromEOF(delta);
    int32_t pos = seek(0, SEEK_CUR);
    nread = read(buf, 4096);
    while (nread > 5) {
      if (!memcmp(buf + nread - 3, "EOF", 3)) {
        nread -= 3;
        // Allow two %% optionally
        if (buf[nread-1] == '%')
          nread--;
        if (buf[nread-1] == '%')
          nread--;
        foundEOF = delta - nread;
        break;
      }
      nread -= 3;
    }
    delta += 4091;// overlapping reads of 5 bytes
  } while (seekOK && foundEOF == -1);
  if (foundEOF == -1) {
    debug("EOF not found in PDF");
    return -1;
  }

  // find startxref scanning backward
  delta += 4096;
  int32_t foundStartxref = -1;
  do {
    seekOK = seekFromEOF(delta);
    int32_t pos = seek(0, SEEK_CUR);
    nread = read(buf, 4096);
    while (nread > 9) {
      if (!memcmp(buf + nread - 9, "startxref", 9)) {
        nread -= 9;
        foundStartxref = pos + nread;
        break;
      }
      nread -= 9;
    }
    delta += 4087;// overlapping reads of 9 bytes
  } while (seekOK && foundStartxref == -1);
  if (foundStartxref == -1) {
    debug("startxref not found in PDF");
    return -1;
  }
  return foundStartxref;
}

static force_inline bool seek_toxref(unsigned *flags)
{
  int32_t pos = find_xref(flags);
  if (seek(pos+9, SEEK_SET) == -1)
    return false;
  debug(pos+9);
  int32_t xref = read_number(10);
  if (xref == -1 || seek(xref, SEEK_SET) == -1) {
    *flags |= PDF_BADXREF;
    debug("seek to xref failed (out of file)");
    debug(xref);
    return false;
  }
  return true;
}

// Check for PDF header and trailer, permissively
static force_inline void formatCheck(unsigned* flags)
{
  char verbuf[4];
  uint32_t pos = file_find("PDF-", 4);
  seek(pos+4, SEEK_SET);
  if (read(verbuf, 4) == 4) {
    // Check for PDF-1.[0-9]. Although 1.7 is highest number now, lets allow
    // till 1.9 for future versions.
    if (verbuf[1] != '.' || verbuf[0] != '1' ||
        verbuf[2] < '1' || verbuf[2] > '9') {
      *flags |= 1 << BAD_PDF_VERSION;
      debug("bad pdf version (not PDF-1.[0-9])");
    }
  }
  if (matches(Signatures.PDF_header_accepted) &&
      !matches(Signatures.PDF_header_good) &&
      !matches(Signatures.PDF_header_old)) {
    *flags |= 1 << BAD_PDF_HEADERPOS;
    debug("file doesn't start with PDF header");
  }

  // Look for trailer
  if (!seek_toxref(flags)) {
    *flags |= 1 << PDF_MISSING_TRAILER;
    debug("trailer not found in PDF");
    return;
  }
}

/* TODO: should be in API headers */
#define CL_SCAN_PDF			0x4000
int entrypoint(void)
{
  unsigned detectionFlags = 0;
  // use 0.96.1 API
/*  if (engine_functionality_level() < FUNC_LEVEL_096_dev)
    return 0;
  if (!(engine_scan_options() & CL_SCAN_PDF))
    return 0;*/

  formatCheck(&detectionFlags);

  seek(7, SEEK_SET);
  REGEX_SCANNER;
  int32_t jsnorm_objs, extract_objs;

  jsnorm_objs = hashset_new();
  extract_objs = hashset_new();
  unsigned i;
  uint32_t probTable[256];
  unsigned entropySize = 0;
  memset(probTable, 0, sizeof(probTable));
  for (;;) {
    REGEX_LOOP_BEGIN
  /*!re2c

    EOL = "\r" | "\n" | "\r\n";
    SKIPNOTEOL = [^\r\n]?;
    WS = [\000\t\r\h\n ];
    COMMENT = "%" SKIPNOTEOL EOL;
    WHITESPACE = (WS | COMMENT)+;
    POSNUMBER = [0-9]+;
    ANY = [^];

    DICT = "<<";

    NAME_CHAR_J = "J" | "#4"[aA];
    NAME_CHAR_S = ("S" | "#53");
    NAME_CHAR_a = ("a" | "#61");
    NAME_CHAR_c = ("c" | "#63");
    NAME_CHAR_i = ("i" | "#69");
    NAME_CHAR_p = ("p" | "#70");
    NAME_CHAR_r = ("r" | "#72");
    NAME_CHAR_t = ("t" | "#74");
    NAME_CHAR_v = ("v" | "#76");

    NAME_S = "/" NAME_CHAR_S;
    NAME_JS = "/" NAME_CHAR_J NAME_CHAR_S;
    NAME_JAVASCRIPT = "/" NAME_CHAR_J NAME_CHAR_a NAME_CHAR_v NAME_CHAR_a 
                      NAME_CHAR_S NAME_CHAR_c NAME_CHAR_r NAME_CHAR_i 
		      NAME_CHAR_p NAME_CHAR_t;

    S_JAVASCRIPT = NAME_S WHITESPACE? NAME_JAVASCRIPT WHITESPACE?;
    DIRECTJSOBJECT = DICT (WHITESPACE)? (S_JAVASCRIPT)? NAME_JS (WHITESPACE)?;
    DIRECTTEXTJS = DIRECTJSOBJECT "(";
    DIRECTHEXJS = DIRECTJSOBJECT "<";

    INDIRECTPDFOBJECT = POSNUMBER WHITESPACE POSNUMBER WHITESPACE "R";
    INDIRECTJSOBJECT = DICT WHITESPACE? S_JAVASCRIPT? NAME_JS WHITESPACE? INDIRECTPDFOBJECT;

    PDFOBJECT = POSNUMBER WHITESPACE POSNUMBER WHITESPACE "obj";
    INDIRECTJS = NAME_JS WHITESPACE? INDIRECTPDFOBJECT;

    PDFOBJECT {
        handle_pdfobj(probTable, &entropySize, jsnorm_objs, extract_objs, re2c_stokstart, REGEX_POS); continue;
    }

    DIRECTTEXTJS {
        debug("pdfjs text at:"); debug(REGEX_POS);
        decode_js_text(probTable, &entropySize, REGEX_POS); continue;
    }
    DIRECTHEXJS {
        debug("pdfjs hextext at:"); debug(REGEX_POS);
        decode_js_hex(probTable, &entropySize, REGEX_POS); continue;
    }
    INDIRECTJSOBJECT {
        decode_js_indirect(probTable, &entropySize, re2c_stokstart, jsnorm_objs, extract_objs); continue;
    }
    ANY { continue; }
  */
#if 0
#endif
  }
  /* TODO: loop over elements in the set, lookup in the pdfobj->offset map, and
   * extract 'em */
  return REGEX_RESULT;
}
