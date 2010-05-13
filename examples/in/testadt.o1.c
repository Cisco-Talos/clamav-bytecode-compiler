/* test data structures */
int entrypoint(void)
{
  /* test set API */
  unsigned i;
  int m;
  int h = hashset_new();
  int s;
  uint8_t *x;

  if (h == -1)
    return 0xbad1;
  if (hashset_add(h, 0xf00))
    return 0xbad2;
  if (!hashset_contains(h, 0xf00))
    return 0xbad3;
  if (hashset_contains(h, 0xb00))
    return 0xbad4;
  if (hashset_add(h, 0xf00d))
    return 0xbad2;
  if (!hashset_contains(h, 0xf00d))
    return 0xbad3;
  if (hashset_contains(h, 0xb00d))
    return 0xbad4;
  if (hashset_remove(h, 0xf00))
    return 0xbad5;
  if (hashset_contains(h, 0xf00))
    return 0xbad6;
  if (!hashset_contains(h, 0xf00d))
    return 0xbad6;
  for (i=0;i<4096;i++)
    hashset_add(h, i);
  if (!hashset_contains(h, 42))
    return 0xbad7;
  if (hashset_done(h))
    return 0xbad8;
  for (i=0;i<4;i++) {
    h = hashset_new();
    if (h == -1)
      return 0xbad9;
    hashset_done(h);
  }
  h = hashset_new();
  if (hashset_add(h, 0xf00d))
    return 0xbad10;
  if (hashset_add(h, 0xf00d))
    return 0xbad10;
  /* don't call done, let bytecode engine do it automatically */
  if (hashset_add(-1, 0xf00) != -1)
    return 0xbad11;
  if (hashset_remove(-1, 0xf00) != -1)
    return 0xbad12;
  if (hashset_contains(-1, 0xf00) != -1)
    return 0xbad13;
  if (hashset_done(-1) != -1)
    return 0xbad14;
  if (hashset_add(1000, 0xf00) != -1)
    return 0xbad15;
  if (hashset_remove(1000, 0xf00) != -1)
    return 0xbad16;
  if (hashset_contains(1000, 0xf00) != -1)
    return 0xbad17;
  if (hashset_done(1000) != -1)
    return 0xbad18;

  /* test map API */
  if (map_new(0, 0) >= 0)
    return 0xbad19;
  m = map_new(8, 1);
  if (m == -1)
    return 0xbad20;
  if (map_addkey("12345678", 8, m) != 1)
    return 0xbad21;
  if (map_addkey("12345678", 8, m) != 0)
    return 0xbad22;
  if (map_addkey("1234", 4, m) >= 0)
    return 0xbad23;
  if (map_setvalue("ab", 2, m) >= 0)
    return 0xbad24;
  if (map_setvalue("a", 1, m) != 0)
    return 0xbad25;
  if (map_remove("12345678", 8, m) != 1)
    return 0xbad26;
  if (map_remove("12345678", 8, m) != 0)
    return 0xbad27;
  if (map_remove("1234", 4, m) >= 0)
    return 0xbad28;
  if (map_find("12345678", 8, m) != 0)
    return 0xbad29;
  if (map_addkey("abcd1234", 8, m) != 1)
    return 0xbad30;
  if (map_setvalue("b", 1, m) != 0)
    return 0xbad31;
  if (map_find("abcd1234", 8, m) != 1)
    return 0xbad32;
  if (map_find("1234", 4, m) >= 0)
    return 0xbad32;
  if (map_find("abcd1234", 8, m) != 1)
    return 0xbad33;
  s = map_getvaluesize(m);
  if (s != 1)
    return 0xbad34;
  x = map_getvalue(m, 1);
  if (!x || *x != 'b')
    return 0xbad35;
  if (map_done(m))
    return 0xbad36;

  /* test unsized value (values with different size) */
  m = map_new(8, 0);
  if (m == -1)
    return 0xbad37;
  if (map_addkey("12345678", 8, m) != 1)
    return 0xbad38;
  if (map_addkey("12345678", 8, m) != 0)
    return 0xbad39;
  if (map_addkey("1234", 4, m) >= 0)
    return 0xbad40;
  if (map_setvalue("ab", 2, m) != 0)
    return 0xbad41;
  if (map_setvalue("a", 1, m) != 0)
    return 0xbad42;
  if (map_setvalue("abc", 1, m) != 0)
    return 0xbad43;
  if (map_remove("12345678", 8, m) != 1)
    return 0xbad44;
  if (map_remove("12345678", 8, m) != 0)
    return 0xbad45;
  if (map_remove("1234", 4, m) >= 0)
    return 0xbad46;
  if (map_find("12345678", 8, m) != 0)
    return 0xbad47;
  if (map_addkey("abcd1234", 8, m) != 1)
    return 0xbad48;
  if (map_setvalue("bcde", 4, m) != 0)
    return 0xbad49;
  if (map_find("abcd1234", 8, m) != 1)
    return 0xbad50;
  if (map_find("1234", 4, m) >= 0)
    return 0xbad51;
  if (map_find("abcd1234", 8, m) != 1)
    return 0xbad52;
  s = map_getvaluesize(m);
  if (s != 4)
    return 0xbad53;
  x = map_getvalue(m, s);
  if (!x || memcmp(x, "bcde", 4))
    return 0xbad54;
  /* test invalid params */
  if (map_getvalue(m, 3)  || map_getvalue(m, 5))
    return 0xbad55;
  if (map_getvalue(-1, 4))
    return 0xbad56;
  if (map_addkey("abcd", 4, -1) >= 0)
    return 0xbad57;
  if (map_remove("abcd", 4, -1) >= 0)
    return 0xbad58;
  if (map_find("abcd", 4, -1) >= 0)
    return 0xbad59;
  if (map_setvalue("abcd", 4, -1) >= 0)
    return 0xbad60;
  /* don't call map_done, let bytecode engine do it */
  return 0xf00d;
}
