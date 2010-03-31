VIRUSNAME_PREFIX("BC.PDF.JSNorm")
VIRUSNAMES("")
TARGET(0)

SIGNATURES_DECL_BEGIN
DECLARE_SIGNATURE(script_header)
DECLARE_SIGNATURE(eval_header)
SIGNATURES_DECL_END

SIGNATURES_DEF_BEGIN
DEFINE_SIGNATURE(script_header, "0:66756e6374696f6e20")
DEFINE_SIGNATURE(eval_header, "0:6576616c28")
SIGNATURES_END

bool logical_trigger(void)
{
  return matches(Signatures.script_header) || matches(Signatures.eval_header);
}

int entrypoint()
{
  int32_t in = buffer_pipe_new_fromfile(0);
  int32_t js = jsnorm_init(in);
  while (jsnorm_process(js) != -1) {
    debug("foo\n");
  }
  jsnorm_done(js);
  return 0;
}
