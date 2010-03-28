int foo(unsigned a)
{
    int x=4;
    unsigned i;
    for (a=1;a<5;a++)
    for (i=0;i<a;i++)
      x*=x;
    if (a == 42)
	goto head2;
head:
    x++;
head2:
    if (a >= 5) {
	x += 3;
	goto head;
    } else if (a >= 2) {
	x += 9;
	goto head;
    }
    return x;
}
int entrypoint()
{
  int y;
  return foo(y);
}
