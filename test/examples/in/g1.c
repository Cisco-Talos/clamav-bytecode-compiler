const int a[2] = {4, 5};
int entrypoint()
{
  return a[__is_bigendian()];
}
