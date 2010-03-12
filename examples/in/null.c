int entrypoint()
{
  const char *x = malloc(1024*1024*1024);
  if (x)
    return 0;
  return *x;
}
