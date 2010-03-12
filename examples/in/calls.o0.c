int bar()
{
    return 4;
}
int foo()
{
    return bar();
}

int a1(int a)
{
    return a == 1;
}
int a2(int a, int b)
{
    return a == 2 && b == 3;
}
int a3(int a, int b, int c)
{
    return a == 4 && b == 5 && c == 6;
}
int a0(void)
{
    return a1(1) + a2(2, 3) + a3(4,5,6);
}
int j0(int j)
{
    return a1(j) + a2(j, j) + a3(j,j,j);
}
int entrypoint()
{
  return bar()+foo()+a0()+j0(5);
}
