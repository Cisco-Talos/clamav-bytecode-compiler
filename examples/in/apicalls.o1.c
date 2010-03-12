int entrypoint()
{
    return test1(0xf00dbeef, 0xbeeff00d) == 0x12345678 ? 0xf00d : 0xdead;
}

int foo1(uint8_t a)
{
    return a == 0x17 ? 0xf00d : 0xdead;
}

int foo2(uint16_t a)
{
    return a == 0x1728 ? 0xf00d : 0xdead;
}

int foo3(uint32_t a)
{
    return a == 0x172839 ? 0xf00d : 0xdead;
}

int foo4(uint64_t a)
{
    return a == 0x17283940516273 ? 0xf00d : 0xdead;
}

int foo5(uint8_t a, uint16_t b)
{
    return (a == 0x28 && b == 0x1234) ? 0xf00d : 0xdead;
}


