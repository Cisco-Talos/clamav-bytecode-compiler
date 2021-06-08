VIRUSNAME_PREFIX("Clamav-Unit-Test-Signature.02")
VIRUSNAMES("")
TARGET(0)

FUNCTIONALITY_LEVEL_MIN(FUNC_LEVEL_096_4)

SIGNATURES_DECL_BEGIN
DECLARE_SIGNATURE(test_string)
SIGNATURES_DECL_END

SIGNATURES_DEF_BEGIN
/*   matches "CLAMAV-TEST-STRING-NOT-EICAR" */
DEFINE_SIGNATURE(test_string, "0:434c414d41562d544553542d535452494e472d4e4f542d4549434152")
SIGNATURES_DEF_END

bool logical_trigger()
{
    /***Will return true if signature matches ***/
    return matches(Signatures.test_string);
}

/***bytecode function that executes if the logical signature matched ***/
int entrypoint(void)
{
    foundVirus("");
    return 0;
}
