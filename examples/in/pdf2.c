VIRUSNAME_PREFIX("BC.PDF.JSExtract")
// Copyright (C) 2007-2008, 2010 Sourcefire, Inc.
// Author: Török Edvin
// Based on:
//  libclamav/pdf.c Author: Nigel Horne
//  snort-nrt/src/preprocessors/dispatchLib/pdfParse Author: Matt Olney 
//  PDF 1.7 ISO 32000-1 specification

VIRUSNAMES("")
TARGET(0)

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

struct javascript_data {
  uint64_t probTable[256][2];
  unsigned entropySize;
};

static force_inline void javascript_filter(struct javascript_data *js,
                              const uint8_t* jsString, unsigned jsSize)
{
  unsigned entropySize = 0;
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
        /*else if(memcmp(jsString+i, "length", 6) == 0) { //Common in randomized strings
          debug(jsString+i);
          debug(memcmp(jsString+i,"length",6));
          debug(memcmp(jsString+i,"lenXth",6));
          memcmp always returns 0 here with JIT... BUG!
          i = i+6;
        }*/
        else {
          // add to entropy counter
          js->probTable[jsString[i]][0]++;
          js->entropySize++;
          i++;
        }
      }
    }
  }
}

static force_inline void javascript_process(struct javascript_data *js)
{
  uint64_t entropy = 0;
  unsigned i;
  unsigned entropySize = js->entropySize;
  // Shannon entropy is equal to the sum of (prob * (log(prob) / log(2))) for each character.
  for (i=0; i<256; i++)
  {
    if (js->probTable[i][0] != 0)
    {
      // The probability that any one character is next in the string.
      // p = probTable[i][0] / (float)entropySize;
      // entropy = entropy + (-1 *(p * (log(p) / log(2))));
      uint32_t p = js->probTable[i][0];
      uint64_t i_log = ilog2(p, entropySize);
      entropy += p*i_log/entropySize;
    }
  }
  debug("Entropy of X bytes is Y, y/(2^27)");
  debug(entropySize);
  debug(entropy >> 27);
  debug(entropy - (entropy>>27));
  if (entropy > 4*(1<<27)) {
    debug("The variables in this JavaScript object have a high degree of entropy");
  }
  memset(js->probTable, 0, sizeof(js->probTable));
}

static force_inline void decode_js_text(struct javascript_data *js, unsigned pos)
{
  unsigned char buf[RE2C_BSIZE];
  unsigned back = seek(0, SEEK_CUR);
  unsigned paranthesis = 0;
  int filled = 0;
  unsigned i = 0;
  seek(pos, SEEK_SET);
  BUFFER_FILL(buf, 0, 1, filled);
  extract_new(pos);
  //TODO: decode PDFEncoding and UTF16
  while (filled > 0) {
    for (i=0;i<filled;i++) {
      if (buf[i] == '(') paranthesis++;
      if (buf[i] == ')') {
        if (!--paranthesis)
          break;
      }
    }
    javascript_filter(js, buf, i);
    write(buf, i);
    if (i < RE2C_BSIZE && buf[i] == ')' && !paranthesis)
      break;
    BUFFER_FILL(buf, 0, 1, filled);
  }
  seek(back, SEEK_SET);
  javascript_process(js);
}

static void decode_js_hex(struct javascript_data *js, unsigned pos)
{
  unsigned char buf[RE2C_BSIZE];
  unsigned back = seek(0, SEEK_CUR);
  seek(pos, SEEK_SET);
  extract_new(pos);
  seek(back, SEEK_SET);
}

static void decode_js_indirect(struct javascript_data *js, unsigned pos, int32_t jsobjs, int32_t extractobjs)
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

static force_inline void extract_obj(struct javascript_data *js, unsigned pos, unsigned jsnorm)
{
  unsigned back = seek(0, SEEK_CUR);
  seek(pos, SEEK_SET);
  extract_new(pos);
  /* TODO: use state-machine here too,
     for now we just decode assuming deflate encoding!*/
  pos = file_find("stream", 6);
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
  debug("trying to inflate X bytes");
  debug(endpos - pos);
  int32_t in = buffer_pipe_new_fromfile(pos);
  //TODO: buffers shouldn't depend on master seek pos!
  seek(pos, SEEK_SET);
  int32_t out = buffer_pipe_new(4096);
  int32_t inf = inflate_init(in, out, 15);
  if (inf < 0)
    return -1;
  uint32_t avail;
  do {
    inflate_process(inf);
    avail = buffer_pipe_read_avail(out);
    uint8_t *outdata = buffer_pipe_read_get(out, avail);
    if (outdata) {
      javascript_filter(js, outdata, avail);
      write(outdata, avail);
    }
    buffer_pipe_read_stopped(out, avail);
  } while (avail);
  seek(back, SEEK_SET);
  javascript_process(js);
}

static void force_inline handle_pdfobj(struct javascript_data *js,
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
  if (hashset_contains(extractobjs, objid)) {
    extract_obj(js, pos, hashset_contains(jsobjs, objid));
    hashset_remove(extractobjs, objid);
    hashset_remove(jsobjs, objid);
  }
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
    // common case for well formed PDFs
    // TODO: when we can query signature match positions, use that here
    seekFromEOF(1024);
    int32_t eofpos = find_last("%%EOF", 5, getFilesize());
    seek(eofpos - 256, SEEK_SET);
    if (matches(Signatures.PDF_EOF_startxref)) {
      return find_last("startxref", 9, eofpos);
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
    while (nread > 5) {
      if (!memcmp(buf + nread - 3, "startxref", 9)) {
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

int entrypoint(void)
{
  unsigned detectionFlags = 0;
  formatCheck(&detectionFlags);

  seek(7, SEEK_SET);
  REGEX_SCANNER;
  int32_t jsnorm_objs, extract_objs;

  jsnorm_objs = hashset_new();
  extract_objs = hashset_new();
  struct javascript_data jsdata;
  memset(&jsdata, 0, sizeof(jsdata));

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
        handle_pdfobj(&jsdata, jsnorm_objs, extract_objs, re2c_stokstart, REGEX_POS); continue;
    }

    DIRECTTEXTJS {
        debug("pdfjs text at:"); debug(REGEX_POS);
        decode_js_text(&jsdata, REGEX_POS); continue;
    }
    DIRECTHEXJS {
        debug("pdfjs hextext at:"); debug(REGEX_POS);
        decode_js_hex(&jsdata, REGEX_POS); continue;
    }
    INDIRECTJSOBJECT {
        decode_js_indirect(&jsdata, re2c_stokstart, jsnorm_objs, extract_objs); continue;
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
