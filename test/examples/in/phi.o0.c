int foo(int a)
{
    int i, x=1;
    for (i=1;i<a;i++) {
	x *= i;
    }
    return x;
}
int entrypoint()
{
  return foo(5);
}
