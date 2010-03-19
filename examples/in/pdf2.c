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

static void decode_js_indirect(unsigned pos)
{
  unsigned char buf[RE2C_BSIZE];
  unsigned back = seek(0, SEEK_CUR);
  seek(pos, SEEK_SET);
  extract_new(pos);
  seek(back, SEEK_SET);
}

static void handle_pdfobj(unsigned pos)
{
  unsigned char buf[128];
  unsigned back = seek(0, SEEK_CUR);
  seek(pos, SEEK_SET);

  int32_t obj0 = read_number(10);
  int32_t obj1 = read_number(10);
  debug("pdf obj");
  debug_print_uint(obj0);
  debug_print_uint(obj1);
  seek(back, SEEK_SET);
}

int entrypoint(void)
{
  seek(7, SEEK_SET);
  REGEX_SCANNER;

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
        handle_pdfobj(re2c_stokstart, REGEX_POS); continue;
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
        debug("indirectjs at:"); debug(REGEX_POS);
        decode_js_indirect(REGEX_POS); continue;
    }
    ANY { continue; }
  */
#if 0
#endif
  }
  return REGEX_RESULT;
}
