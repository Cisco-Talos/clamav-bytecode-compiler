int entrypoint(void)
{
  if (__is_bigendian())
    foundVirus("A");
  else
    foundVirus("B");
  //foundVirus(__is_bigendian()?"A":"B");
  return 0;
}
