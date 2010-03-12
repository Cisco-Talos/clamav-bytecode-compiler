#define BUF 4096
uint32_t entrypoint(void)
{
    unsigned char buffer[BUF];

    int32_t size = seek(0, SEEK_END);
    if (size == -1)
	return 1;
    if (size < BUF)
	return 2;
    if (seek(-size, SEEK_END) == -1)
	return 3;

    if (read(buffer, size) != size)
	return 4;

    for (unsigned i=0;i<sizeof(buffer);i++) {
	if (buffer[i] == 'X')
	    return 0;
    }
    return 6;
}
