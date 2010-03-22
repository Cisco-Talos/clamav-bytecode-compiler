VIRUSNAME_PREFIX("BC.PDF.JSExtract")
VIRUSNAMES("")
TARGET(0)

SIGNATURES_DECL_BEGIN
DECLARE_SIGNATURE(PDF_header)
SIGNATURES_DECL_END

SIGNATURES_DEF_BEGIN
/* %PDF-, don't validate the version, since there are %PDF-1111 for example */
DEFINE_SIGNATURE(PDF_header, "0:255044462d")
SIGNATURES_END

bool logical_trigger(void)
{
  return matches(Signatures.PDF_header);
  //&& matches(Signatures.PDF_eof);
}

/*!max:re2c */
#if RE2C_BSIZE < YYMAXFILL
#error RE2C_BSIZE must be greated than YYMAXFILL
#endif

static void decode_js_text(unsigned pos)
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
    write(buf, i);
    if (buf[i] == ')' && !paranthesis)
      break;
    BUFFER_FILL(buf, 0, 1, filled);
  }
  seek(back, SEEK_SET);
}

static void decode_js_hex(unsigned pos)
{
  unsigned char buf[RE2C_BSIZE];
  unsigned back = seek(0, SEEK_CUR);
  seek(pos, SEEK_SET);
  extract_new(pos);
  seek(back, SEEK_SET);
}

static void decode_js_indirect(unsigned pos, int32_t jsobjs, int32_t extractobjs)
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

static void extract_obj(unsigned pos, unsigned jsnorm)
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
  int32_t out = buffer_pipe_new(4096);
  int32_t inf = inflate_init(in, out, 15);
  if (inf < 0)
    return -1;
  uint32_t avail;
  do {
    inflate_process(inf);
    avail = buffer_pipe_read_avail(out);
    uint8_t *outdata = buffer_pipe_read_get(out, avail);
    write(outdata, avail);
    buffer_pipe_read_stopped(out, avail);
  } while (avail);
  seek(back, SEEK_SET);
}

static void handle_pdfobj(unsigned jsobjs, unsigned extractobjs,
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
    extract_obj(pos, hashset_contains(jsobjs, objid));
    hashset_remove(extractobjs, objid);
    hashset_remove(jsobjs, objid);
  }
  seek(back, SEEK_SET);
}

int entrypoint(void)
{
  seek(7, SEEK_SET);
  REGEX_SCANNER;
  int32_t jsnorm_objs, extract_objs;

  jsnorm_objs = hashset_new();
  extract_objs = hashset_new();

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
        handle_pdfobj(jsnorm_objs, extract_objs, re2c_stokstart, REGEX_POS); continue;
    }

    DIRECTTEXTJS {
        debug("pdfjs text at:"); debug(REGEX_POS);
        decode_js_text(REGEX_POS); continue;
    }
    DIRECTHEXJS {
        debug("pdfjs hextext at:"); debug(REGEX_POS);
        decode_js_hex(REGEX_POS); continue;
    }
    INDIRECTJSOBJECT {
        decode_js_indirect(re2c_stokstart, jsnorm_objs, extract_objs); continue;
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
