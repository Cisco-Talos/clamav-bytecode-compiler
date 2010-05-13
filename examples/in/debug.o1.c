/* test debug APIs */
int entrypoint(void)
{
  debug_print_str("bytecode started", 16);
  debug_print_str_start("Engine functionality level: ", 28);
  debug_print_uint(engine_functionality_level());
  debug_print_str_nonl(", dconf functionality level: ", 28);
  debug_print_uint(engine_dconf_level());
  debug_print_str_nonl("\n", 1);
  debug_print_str_start("Engine scan options: ", 21);
  debug_print_uint(engine_scan_options());
  debug_print_str_nonl(", db options: ", 13);
  debug_print_uint(engine_db_options());
  debug_print_str_nonl("\n", 1);
  return 0;
}

