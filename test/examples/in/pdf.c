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
DEFINE_SIGNATURE(PDF_eof,"EOF-5:2525454f46")
SIGNATURES_END

bool logical_trigger(void)
{
  return matches(Signatures.PDF_header) && matches(Signatures.PDF_eof);
}

// Skip current line until a \n, \r or \r\n is encountered
void pdf_skipeol()
{
  const unsigned char *p1, *p2;
  unsigned char buf[65];
  int n;
  buf[64] = '\0';
  while(1) {
    n = read(buf, sizeof(buf));
    if (n <= 0)
      break;
    p1 = memchr(buf, '\n', n);
    p2 = memchr(buf, '\r', n);
    if (p1 && p1 < p2) {
      seek(p1 - buf + 1-n, SEEK_CUR);
      return;
    }
    if (p2) {
      if (p2[1] == '\n')
        p2++;
      seek(p2 - buf + 1-n, SEEK_CUR);
      return;
    }
  }
}

// Skip whitespace.
// Whitespace in PDF is ascii 0,9,10,12,13,32.
// Consecutive whitespace is treated as a single character.
// Also comments are treated as a single whitespace character.
// Returns 1 if any whitespace was skipped, 0 otherwise.
int pdf_skipwhitespace(void)
{
  unsigned char buf[64];
  int i, n, seeked = 0;
  while ((n = read(buf, sizeof(buf))) > 0) {
    for (i=0;i<n;i++) {
      unsigned char c = buf[i];
      if (!c)
        continue;
      if ((c == 9) | (c == 10) | (c == 12) | (c == 13) | (c == 32))
        continue;
      if (c == '%') {
        seek(i+1-n, SEEK_CUR);
        pdf_skipeol();
        break;
      }
      /* not whitespace */
      seek(i-n, SEEK_CUR);
      return seeked || i >= 0;
    }
    seeked = 1;
  }
  return seeked;
}

typedef struct {
  unsigned id;
  unsigned generation;
  unsigned length;
  unsigned endoff;
} pdfobj_t;

/* skips a possibly repeated '0' */
void pdf_skip0(void)
{
  char buf[64];
  int n, i;
  while ((n = read(buf, sizeof(buf))) > 0) {
    for (i=0;i<n;i++) {
      if (buf[i] != '0') {
        seek(i-n, SEEK_CUR);
        return;
      }
    }
  }
}

int pdf_skipnumber()
{
  char buf[64];
  int n, i, seeked = 0;
  while ((n = read(buf, sizeof(buf))) > 0) {
    for (i=0;i<n;i++) {
      if (buf[i] < '0' || buf[i] > '9') {
        seek(i-n, SEEK_CUR);
        return seeked || i > 0;
      }
    }
    seeked = 1;
  }
  return seeked;
}

int pdf_findnextobj(pdfobj_t *obj)
{
  unsigned char c[2];
  int cc;
  int32_t start;
  int32_t off = file_find("obj", 3);
  if (off == -1)
    return -1;
  /* <number> := [0-9]+
     <whitespace> := ([\0\h\f\r\n ]|%[^\r\n]+)+
     <number><whitespace><number><whitespace>obj */
  if (!pdf_skipnumber())
    return -1;//TODO: look for numbers
  if (!pdf_skipwhitespace())
    return -1;
  if (!pdf_skipnumber())
    return -1;
  if (!pdf_skipwhitespace())
    return -1;
  if (seek(0, SEEK_CUR) != off)
    return -1;
  if (read(&c, 2) != 2)
    return -1;
  /* check that obj is followed by eol */
  if (c[0] == 'n')
    seek(-1, SEEK_CUR);
  else if (c[0] == '\r') {
    if (c[1] != '\n')
      seek(-1, SEEK_CUR);
  } else {
    seek(-2, SEEK_CUR);
    return -1;
  }
  start = seek(0, SEEK_CUR);

  while (1) {
    off = file_find("endobj", 6);
    if (off < 0)
      return -1;
    cc = file_byteat(off-1);
    if (cc == '\n') {
      if (file_byteat(off-2) == '\r')
        off -= 2;
      break;
    } else if (cc == '\r') {
      off--;
      break;
    }
    seek(off+7, SEEK_SET);
  }
  obj->endoff = off + 7;
  obj->length = off - start;
  seek(off, SEEK_SET);
  return 0;
}

void pdf_decodehex(pdfobj_t *obj)
{
  //TODO: just decode hex fiels and dump to file
}

void pdf_decodestring(pdfobj_t *obj)
{
  char buf[64];
  int n;
  unsigned char c;
  int paranthesis = 1;
  unsigned i;
  int off = seek(1, SEEK_CUR);
  c = file_byteat(off);
  if (c == 0xfe && file_byteat(off+1) == 0xff) {
    char out[32];
    unsigned j=0;
    do {
      /* utf16be encoding */
      /* TODO: better decoding? we now only decode ascii */
      n = read(buf, sizeof(buf));
      if (n <= 0)
        return;
      for (i=0;i<n;i+=2) {
        if (buf[i] == ')')
          return;
        out[j++] = buf[i+1];
      }
      write(out, j);
    } while (1);
    write("\n", 1);
  } else {
    while (1) {
    /* pdfdocencoding */
    /* TODO: really decode this */
    n = read(buf, sizeof(buf));
    for (i=0;i<n;i++) {
      if (buf[i] == '(')
        paranthesis++;
      if (buf[i] == ')') {
        if (!--paranthesis) {
          write(buf, i);
          return; 
        }
      }
    }
    write(buf, n);
    }
  }
}

int entrypoint(void)
{
  pdfobj_t obj;
  /* skip %PDF-1, note that not all pdfs have %PDF-1., some are missing the dot! */
  seek(7, SEEK_SET);
  /* PDF structure: Header, (Indirect Objects, Trailer)+ */
  pdf_skipeol();
  pdf_skipwhitespace();
  while (pdf_findnextobj(&obj) != -1) {
    int n, i;
    pdf_skipwhitespace();
    i = seek(0, SEEK_CUR);
    if (file_byteat(i) == '<' &&
        file_byteat(i+1) == '<') {
      int32_t off;
      unsigned char c;
      pdf_skipwhitespace();
      //TODO: look for /S/JavaScript too
      //TODO: look for names encoded using /#4a#53
      //TODO: find API with end limit
      off = file_find("/JS", 3);
      if (off > obj.endoff || off < 0) {
        break;// not a javascript object
      }
      seek(off, SEEK_SET);
      pdf_skipwhitespace();
      c = file_byteat(seek(0, SEEK_CUR));
      if (c == '(') {
        pdf_decodestring(&obj);
      } else if (c == '<') {
        pdf_decodehex(&obj);
      }
    }
    //TODO: API to extract more than one file
    // seek to next obj
    seek(obj.endoff, SEEK_SET);
  }
  return 0;
}
