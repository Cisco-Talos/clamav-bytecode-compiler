/*
 * Check that the 'include' options work.
 * RUN: echo "int x;\n" > %t1.inc
 * RUN: llvmc -include %t1.inc -fsyntax-only %s
 * XFAIL: vg_leak
 */

int f0(void) {
  return x;
}
