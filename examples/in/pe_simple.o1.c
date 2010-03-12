VIRUSNAME_PREFIX("BC.Fake")
SIGNATURES_DECL_BEGIN
DECLARE_SIGNATURE(MZfromEOF)
SIGNATURES_DECL_END
TARGET(1)

SIGNATURES_DEF_BEGIN
DEFINE_SIGNATURE(MZfromEOF, "EOF-544:4d5a50000200000004000f00ffff0000")
SIGNATURES_END

bool logical_trigger(void)
{
  return matches(Signatures.MZfromEOF);
}

PE_UNPACKER_DECLARE
int entrypoint()
{
  uint32_t ep = getEntryPoint();
  debug_print_uint(ep);
  if (getFilesize() == 544) {
    foundVirus("");
  }
  return 0;
}
