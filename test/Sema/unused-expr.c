// RUN: clang-cc -fsyntax-only -verify -fmath-errno=0 %s

int foo(int X, int Y);

double sqrt(double X);  // implicitly const because of -fno-math-errno!

void bar(volatile int *VP, int *P, int A,
         _Complex double C, volatile _Complex double VC) {
  
  VP == P;             // expected-warning {{expression result unused}}
  (void)A;
  (void)foo(1,2);      // no warning.
  
  A == foo(1, 2);      // expected-warning {{expression result unused}}

  foo(1,2)+foo(4,3);   // expected-warning {{expression result unused}}


  *P;                  // expected-warning {{expression result unused}}
  *VP;                 // no warning.
  P[4];                // expected-warning {{expression result unused}}
  VP[4];               // no warning.

  __real__ C;          // expected-warning {{expression result unused}}
  __real__ VC;
  
  // We know this can't change errno because of -fno-math-errno.
  sqrt(A);  // expected-warning {{ignoring return value of function declared with const attribute}}
}

extern void t1();
extern void t2();
void t3(int c) {
  c ? t1() : t2();
}

// This shouldn't warn: the expr at the end of the stmtexpr really is used.
int stmt_expr(int x, int y) {
  return ({int _a = x, _b = y; _a > _b ? _a : _b; });
}

void nowarn(unsigned char* a, unsigned char* b)
{
  unsigned char c = 1;
  *a |= c, *b += c;


  // PR4633
  int y, x;
  ((void)0), y = x;
}

void t4(int a) {
  int b = 0;

  if (a)
    b == 1; // expected-warning{{expression result unused}}
  else
    b == 2; // expected-warning{{expression result unused}}
    
  while (1)
    b == 3; // expected-warning{{expression result unused}}

  do
    b == 4; // expected-warning{{expression result unused}}
  while (1);
  
  for (;;)
    b == 5; // expected-warning{{expression result unused}}
    
  for (b == 1;;) {} // expected-warning{{expression result unused}}
  for (;b == 1;) {}
  for (;;b == 1) {} // expected-warning{{expression result unused}}
}

// rdar://7186119
int t5f(void) __attribute__((warn_unused_result));
void t5() {
  t5f();   // expected-warning {{ignoring return value of function declared with warn_unused_result}}
}
