/* You are only allowed to set these virusnames as found */
VIRUSNAME_PREFIX("Test")
VIRUSNAMES("A", "B")
TARGET(1)

SIGNATURES_DECL_BEGIN
DECLARE_SIGNATURE(magic)
DECLARE_SIGNATURE(zero)
DECLARE_SIGNATURE(check)
DECLARE_SIGNATURE(fivetoten)
DECLARE_SIGNATURE(check2)
SIGNATURES_DECL_END

SIGNATURES_DEF_BEGIN
DEFINE_SIGNATURE(magic, "EP+0:aabb")
DEFINE_SIGNATURE(zero, "ffff")
DEFINE_SIGNATURE(fivetoten, "aaccee")
DEFINE_SIGNATURE(check, "f00d")
DEFINE_SIGNATURE(check2, "dead")
SIGNATURES_END

bool logical_trigger(void)
{
    unsigned sum_matches = count_match(Signatures.magic)+
	count_match(Signatures.zero) + count_match(Signatures.fivetoten);
    unsigned unique_matches = matches(Signatures.magic)+
	    matches(Signatures.zero)+ matches(Signatures.fivetoten);
    if (sum_matches == 42 && unique_matches == 2) {
	// The above 3 signatures have matched a total of 42 times, and at least
	// 2 of them have matched
	return true;
    }
    // If the check signature matches 10 times we still have a match
    if (count_match(Signatures.check) == 10)
	return true;
    // No match
    return false;
}

int entrypoint(void)
{
    unsigned count = count_match(Signatures.check2);
    if (count >= 2)
//	foundVirus(count == 2 ? "A" : "B");
      if (count == 2)
	foundVirus("A");
      else
        foundVirus("B");
    return 0;
}
