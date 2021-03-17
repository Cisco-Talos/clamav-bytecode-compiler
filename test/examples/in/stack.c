static int bar();
static int foo(int a);
static int baz()
{
  return 5;
}
static int foobar()
{
  return bar(5) + 6;
}
static int foo(int a)
{
  if (a == 16)
    return foobar()+9;
  return baz();
}

static int bar()
{
  return foo(8)+4;
}

int entrypoint()
{
  return foo(16);
}
