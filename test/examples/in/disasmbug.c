VIRUSNAME_PREFIX("ClamAV-Test-File-detected-via-bytecode")
VIRUSNAMES("X")
TARGET(1)

/* This is all dummy stuff */
SIGNATURES_DECL_BEGIN
DECLARE_SIGNATURE(MZfromBOF)
DECLARE_SIGNATURE(MZfromEOF)
DECLARE_SIGNATURE(MZfromS0)
SIGNATURES_DECL_END

SIGNATURES_DEF_BEGIN
DEFINE_SIGNATURE(MZfromBOF,       "0:4d5a50000200000004000f00ffff0000")
DEFINE_SIGNATURE(MZfromEOF, "EOF-544:4d5a50000200000004000f00ffff0000")
DEFINE_SIGNATURE(MZfromS0,     "S0+0:4d5a50000200000004000f00ffff0000")
SIGNATURES_END

PE_UNPACKER_DECLARE

bool logical_trigger(void)
{
  return matches(Signatures.MZfromBOF) && matches(Signatures.MZfromEOF) && matches(Signatures.MZfromS0);
}
/* Dummy stuff ends here */

int entrypoint() {
        struct DIS_fixed disasm_data;
        uint32_t ep = getEntryPoint();
        uint32_t remaining_size = getFilesize() - ep;
        uint32_t current_offset = DisassembleAt(&disasm_data, ep, remaining_size);


        return 0;
}
