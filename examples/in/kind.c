VIRUSNAME_PREFIX("")
PE_UNPACKER_DECLARE
int entrypoint()
{
  return __clambc_pedata.opt32.ImageBase;
}
