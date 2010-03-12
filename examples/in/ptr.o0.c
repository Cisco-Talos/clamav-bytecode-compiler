unsigned foo() { return 1; }
int entrypoint()
{
    char x[2] = {6,7};
    unsigned idx = foo();
    if (idx < sizeof(x))
	x[idx] = 5;
    return x[1];
}
