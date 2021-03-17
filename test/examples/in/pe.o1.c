VIRUSNAME_PREFIX("Trojan.Foo")
VIRUSNAMES("A","B")
SIGNATURES_DECL_BEGIN
DECLARE_SIGNATURE(magic)
DECLARE_SIGNATURE(zero)
DECLARE_SIGNATURE(check)
DECLARE_SIGNATURE(fivetoten)
SIGNATURES_DECL_END

TARGET(1)
SIGNATURES_DEF_BEGIN
DEFINE_SIGNATURE(magic, "aabb")
DEFINE_SIGNATURE(zero, "ffffffff")
DEFINE_SIGNATURE(fivetoten, "aaccee")
DEFINE_SIGNATURE(check, "f00d")
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
    if (matches(Signatures.check) == 10)
	return true;
    // No match
    return false;
}

uint32_t entrypoint(void)
{
    if (count_match(Signatures.check) == 2) {
	foundVirus("A");
    }
    if (!hasExeInfo())
	return 0;

    if (getNumberOfSections() > 4)
	return 0;
    foundVirus("B");
    return 0;
}
