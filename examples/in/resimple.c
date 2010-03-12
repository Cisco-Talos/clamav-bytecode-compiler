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

    ANY = [^];

    ANY { continue; }
  */
  }
  return REGEX_RESULT;
}
