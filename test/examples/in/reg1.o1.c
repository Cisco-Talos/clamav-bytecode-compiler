int entrypoint(void)
{
    REGEX_SCANNER;
    seek(0, SEEK_SET);
    for (;;) {
        REGEX_LOOP_BEGIN

          /* !re2c
             ANY = [^];

             "eval("[a-zA-Z_][a-zA-Z_0-9]*".unescape" {
                long pos = REGEX_POS;
                if (pos < 0)
                  continue;
                debug("unescape found at:");
                debug(pos);
             }
             ANY { continue; }
          */
    }
    return 0;
}
