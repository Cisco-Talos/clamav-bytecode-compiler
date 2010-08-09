/* You are only allowed to set these virusnames as found */
VIRUSNAME_PREFIX("BC.Heuristic.Trojan.SusPacked")
VIRUSNAMES("")
TARGET(1)
ICONGROUP1("DOCUMENT")

SIGNATURES_DECL_BEGIN
DECLARE_SIGNATURE(ep0)
SIGNATURES_DECL_END

SIGNATURES_DEF_BEGIN
//DEFINE_SIGNATURE(ep0, "0:4d5a")
DEFINE_SIGNATURE(ep0,"EP+0:60be00??41008dbe00??feff57eb0b908a064688074701db75078b1e83eefc11db72edb80100000001db75078b1e83eefc11db11c001")
SIGNATURES_END


bool logical_trigger(void)
{
    return matches(Signatures.ep0);
}

int entrypoint(void)
{
    uint32_t ep = getEntryPoint();
    if (getNumberOfSections() < 1)
	return 0;
    uint32_t rva = getSectionRVA(0);
    uint32_t vsz = getSectionVirtualSize(0);
    if (ep >= rva && ep < rva+vsz) {
	debug_print_str_start("EP is in first section: ",24);
	debug_print_uint(ep);
	debug_print_str_nonl(" in [",5);
	debug_print_uint(rva);
	debug_print_str_nonl("-",1);
	debug_print_uint(rva+vsz);
	debug_print_str_nonl(")\n",2);

        if (matchicon("DOCUMENT", 8, "", 0) != 1) {
          debug("icon not matched");
          return 0;
        }
        foundVirus();
    }

    return 0;
}
