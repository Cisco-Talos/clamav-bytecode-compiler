int foo(int a, int b)
{
    if (b > 5) {
	a += b;
	return a/b;
    }
    return a+b;
}
int entrypoint()
{
  return foo(4, 5);
}
