// RUN: %clang_cc1 -fsyntax-only -verify %s

int main(void) {
  const char ch = @encode(char *)[2];
  char c = @encode(char *)[2] + 4;
  return c;
}

