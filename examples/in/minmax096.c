VIRUSNAME_PREFIX("BC.testminmax")
TARGET(1)

/* Only load this on 0.96 */
FUNCTIONALITY_LEVEL_MIN(FUNC_LEVEL_096)
FUNCTIONALITY_LEVEL_MAX(FUNC_LEVEL_096)
PE_UNPACKER_DECLARE

int entrypoint()
{
  debug("bytecode executed!");
  return 0;
}
