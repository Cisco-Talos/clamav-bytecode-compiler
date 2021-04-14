/* test debug APIs */
int entrypoint(void)
{
  /* print a debug message, followed by newline */
  debug_print_str("bytecode started", 16);

  /* start a new debug message, don't end with newline yet */
  debug_print_str_start("Engine functionality level: ", 28);
  /* print an integer, no newline */
  debug_print_uint(engine_functionality_level());
  /* print a string without starting a new debug message, and without
   * terminating with newline */
  debug_print_str_nonl(", dconf functionality level: ", 28);
  debug_print_uint(engine_dconf_level());
  debug_print_str_nonl("\n", 1);
  debug_print_str_start("Engine scan options: ", 21);
  debug_print_uint(engine_scan_options());
  debug_print_str_nonl(", db options: ", 13);
  debug_print_uint(engine_db_options());
  debug_print_str_nonl("\n", 1);

  /* convenience wrapper to just print a string */
  debug("just print a string");
  /* convenience wrapper to just print an integer */
  debug(4);
  return 0xf00d;
}

