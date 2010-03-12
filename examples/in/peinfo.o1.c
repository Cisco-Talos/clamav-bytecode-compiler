// a simple bytecode that looks for PE files of size 544, with 1 section */
VIRUSNAME_PREFIX("BC.544")
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
int entrypoint(void)
{
  if (getNumberOfSections() != 1)
    return 0;
  foundVirus("");
  return 0;
}
