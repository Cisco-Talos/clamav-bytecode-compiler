VIRUSNAME_PREFIX("BC.PDF.JSExtract")
VIRUSNAMES("")
TARGET(0)

SIGNATURES_DECL_BEGIN
DECLARE_SIGNATURE(PDF_header)
DECLARE_SIGNATURE(PDF_eof)
SIGNATURES_DECL_END

SIGNATURES_DEF_BEGIN
/* %PDF-, don't validate the version, since there are %PDF-1111 for example */
DEFINE_SIGNATURE(PDF_header, "0:255044462d")
DEFINE_SIGNATURE(PDF_eof,"EOF-10,4:2525454f46")
SIGNATURES_END

bool logical_trigger(void)
{
  return matches(Signatures.PDF_header) && matches(Signatures.PDF_eof);
}

/*!max:re2c */
#if RE2C_BSIZE < YYMAXFILL
#error RE2C_BSIZE must be greated than YYMAXFILL
#endif

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

    DIRECTJSOBJECT { debug("pdfjs text at:"); DEBUG_PRINT_REGEX_MATCH; continue; }
    DIRECTHEXJS { debug("pdfjs hextext at:"); DEBUG_PRINT_REGEX_MATCH; continue; }
    INDIRECTJSOBJECT { debug("indirectjs at:"); DEBUG_PRINT_REGEX_MATCH; continue; }
    ANY { continue; }
  */
#if 0
    PDFOBJECT { debug("pdf obj at:"); DEBUG_PRINT_REGEX_MATCH; continue; }
#endif
  }
  return REGEX_RESULT;
}
