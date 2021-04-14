/* test basic file operation APIs */
static const char file[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghij";
static const char notfile[] = "BCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghij";
int entrypoint(void)
{
  unsigned char buf[42];
  int8_t d;
  int16_t a;
  int32_t b;
  int64_t c;
  int16_t ar[3];
  int32_t br[3];
  int64_t cr[3];
  int i, sum = 0;
  /* test seek */
  if (seek(0, SEEK_CUR) != 0)
    return 0xbad1;
  if (seek(0, SEEK_SET) != 0)
    return 0xbad2;
  if (seek(0, SEEK_END) != __clambc_filesize[0])
    return 0xbad3;
  /* input testfile for this bytecode must have 42 bytes in size */
  if (__clambc_filesize[0] != 42)
    return 0xbad4;
  /* test seeks */
  for (i=0;i<42;i++) {
    if (seek(i, SEEK_SET) != i)
      return 0xbad5;
    if (seek(0, SEEK_CUR) != i)
      return 0xbad6;
  }
  if (seek(0, SEEK_SET) != 0)
    return 0xbad7;
  for (i=1;i<42;i++) {
    if (seek(1, SEEK_CUR) != i)
      return 0xbad8;
  }
  if (seek(1, SEEK_SET) != 1)
    return 0xbad9;
  if (seek(41, SEEK_CUR) != 42)
    return 0xbad10;
  for (i=0;i<42;i++) {
    if (seek(-i, SEEK_END) != 42-i)
      return 0xbad11;
  }

  memset(buf, 0x5a, sizeof(buf));
  /* test read + seek */
  if (seek(0, SEEK_SET) != 0)
    return 0xbad12;
  if (read(buf, 42) != sizeof(buf))
    return 0xbad13;
  sum = 0;
  for (i=0;i<42;i++)
    sum += buf[i];
  if (sum != 3591)
    return 0xbad14;
  if (buf[0] != 'A' || buf[41] != 'j')
    return 0xbad15;
  for (i=0;i<sizeof(buf);i++)
    if (buf[i] != 'A'+i)
      return 0xbad16;

  if (memcmp(buf, file, sizeof(file)-1))
    return 0xbad17;
  if (!memcmp(buf, notfile, sizeof(notfile)-1))
    return 0xbad18;

  /* bad seek mustn't modify position */
  if (seek(17, SEEK_SET) != 17)
    return 0xbad19;
  if (seek(43, SEEK_SET) != -1)
    return 0xbad20;
  if (seek(0, SEEK_CUR) != 17)
    return 0xbad21;
  if (seek(0, SEEK_SET) != 0)
    return 0xbad22;
  /* read little-endian data from file */
  if (read(&a, sizeof(a)) != sizeof(a))
    return 0xbad23;
  a = le16_to_host(a);
  if (a != 0x4241)
    return 0xbad24;
  if (read(&b, sizeof(b)) != sizeof(b))
    return 0xbad25;
  b = le32_to_host(b);
  if (b != 0x46454443)
    return 0xbad26;
  if (read(&c, sizeof(c)) != sizeof(c))
    return 0xbad27;
  debug("c0: ");
  debug(c);
  debug_print_str_nonl("\n",1);
  debug(c>>32);
  debug_print_str_nonl("\n",1);
  c = le64_to_host(c);
  if (c != 0x4e4d4c4b4a494847UL)
    return 0xbad28;

  if (seek(3, SEEK_SET) != 3)
    return 0xbad29;
  if (read(&d, sizeof(d)) != sizeof(d))
    return 0xbad30;
  if (d != 'D')
    return 0xbad31;
  if (file_find("UVW", 3) != 20)
    return 0xbad32;
  if (seek(0, SEEK_SET) != 0)
    return 0xbad33;
  if (file_find("UU", 2) != -1)
    return 0xbad34;
  if (file_byteat(0) != 'A' || file_byteat(1) != 'B')
    return 0xbad35;
  if (seek(3, SEEK_SET) != 3)
    return 0xbad36;
  if (file_find_limit("QR", 2, 17) != -1)
    return 0xbad37;
  if (file_find_limit("QR", 2, 18) != 16)
    return 0xbad38;
  if (seek(0, SEEK_SET) != 0)
    return 0xbad39;
  if (file_find_limit("UVW", 3, 20) != -1)
    return 0xbad40;
  return 0xf00d;
}

