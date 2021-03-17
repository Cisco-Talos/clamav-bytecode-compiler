/* test file extract API */
int entrypoint(void)
{
  unsigned char buf[4];
  /* fixme:compiler assumes LE here = {1, 2, 3, 4}; */
  uint32_t x, i;
  uint64_t y;
  *(uint32_t*)buf = le32_to_host(0x04030201);
  for (i=0;i<3;i++) {
    extract_new(i);
    if (write(buf, sizeof(buf)) != sizeof(buf))
      return 0xbad1;
    /* switch input to extracted file */
    if (input_switch(1) != 0)
      return 0xbad2;
    if (seek(0, SEEK_END) != 4)
      return 0xbad3;
    if (seek(0, SEEK_SET) != 0)
      return 0xbad4;
    x = 0x5a5a5a5a;
    if (read(&x, sizeof(x)) != sizeof(x))
      return 0xbad5;
    if (cli_readint32(&x) != 0x04030201)
      return 0xbad6;
    /* switch back to normal file */
    if (input_switch(0) != 0)
      return 0xbad7;
    if (seek(0, SEEK_SET) != 0)
      return 0xbad8;
    if (read(&x, sizeof(x)) != sizeof(x))
      return 0xbad9;
    x = le32_to_host(x);
    if (x != 0x44434241)
      return 0xbad10;
    /* write to extracted file again */
    if (write(buf, sizeof(buf)) != sizeof(buf))
      return 0xbad11;
    /* switch input to extracted file */
    if (input_switch(1) != 0)
      return 0xbad12;
    if (seek(0, SEEK_END) != 8)
      return 0xbad13;
    if (seek(0, SEEK_SET) != 0)
      return 0xbad14;
    if (read(&y, sizeof(y)) != sizeof(y))
      return 0xbad15;
    y = le64_to_host(y);
    if (y != 0x0403020104030201UL)
      return 0xbad16;
    if (input_switch(0) != 0)
      return 0xbad17;
  }
  return 0xf00d;
}
