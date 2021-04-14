static const uint8_t input[] = {
  0x1f, 0x8b, 0x08, 0x08, 0xa0, 0x1a, 0xa5, 0x4b, 0x00, 0x03, 0x66, 0x6f,
  0x6f, 0x00, 0x2b, 0x49, 0x2d, 0x2e, 0x01, 0x00, 0x0c, 0x7e, 0x7f, 0xd8,
  0x04, 0x00, 0x00, 0x00 };
int entrypoint()
{
  uint32_t avail;
  uint8_t *input_b, *out_b;
  int32_t input_buf = buffer_pipe_new(4096);
  int32_t output_buf = buffer_pipe_new(4096);
  if (input_buf < 0 || output_buf < 0)
    return 0xdead1;
  avail = buffer_pipe_write_avail(input_buf);
  input_b = buffer_pipe_write_get(input_buf, avail);
  if (!input_b)
    return 0xdead0;
  memcpy(input_b, input, sizeof(input));
  buffer_pipe_write_stopped(input_buf, sizeof(input));

  int32_t id = inflate_init(input_buf, output_buf, 31);
  if (id < 0)
    return 0xdead2;
  inflate_process(id);
  avail = buffer_pipe_read_avail(output_buf);
  out_b = buffer_pipe_read_get(output_buf, avail);
  if (out_b && memcmp(out_b, "test", 4))
    return 0xdead3;
  inflate_done(id);
  return 0xbeef;
}
