// RUN: %clang_cc1 -fsyntax-only -verify %s

struct X1 { // has no implicit default constructor
   X1(int);
};

struct X2  : X1 {  // expected-note 2 {{'X2' declared here}}
   X2(int);
};

struct X3 : public X2 { // expected-error {{implicit default constructor for 'X3' must explicitly initialize the base class 'X2' which does not have a default constructor}}
};
X3 x3; // expected-note {{first required here}}


struct X4 { // expected-error {{must explicitly initialize the member 'x2'}} \
            // expected-error {{must explicitly initialize the reference member 'rx2'}}
  X2 x2; 	// expected-note {{member is declared here}}
  X2 & rx2; // expected-note {{declared at}}
};

X4 x4; // expected-note {{first required here}}


struct Y1 { // has no implicit default constructor
   Y1(int);
};

struct Y2  : Y1 { 
   Y2(int);
   Y2();
};

struct Y3 : public Y2 {
};
Y3 y3; 

struct Y4 {
  Y2 y2; 
};

Y4 y4;

// More tests


struct Z1 { // expected-error {{must explicitly initialize the reference member 'z'}} \
            // expected-error {{must explicitly initialize the const member 'c1'}}
  int& z;       // expected-note {{declared at}}
  const int c1; // expected-note {{declared at}}
  volatile int v1;
};

Z1 z1; // expected-note {{first required here}}

