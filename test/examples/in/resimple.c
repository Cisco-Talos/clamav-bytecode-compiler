/*!max:re2c */
#if RE2C_BSIZE < YYMAXFILL
#error RE2C_BSIZE must be greated than YYMAXFILL
#endif

int entrypoint(void)
{
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
