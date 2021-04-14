int entrypoint()
{
  char buf[16] = {
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
  };
  char buf2[16];
  uint32_t x;
  memset(&buf2, 0, sizeof(buf2));
  if (cli_readint16(&buf) != 0x100)
    return 0xdead1;
  x = cli_readint32(&buf);
  if (x != 0x03020100)
    return 0xdead2;
  x = __builtin_bswap32(x);
  if (x != 0x00010203)
    return 0xdead3;
  cli_writeint32(&buf2, 0x12345678);
  if (cli_readint32(&buf2) != 0x12345678)
    return 0xdead4;
  if (buf2[0] != 0x78)
    return 0xdead5;
  return 0xbeef;
}
