// RUN: %clang_cc1 -faltivec -fsyntax-only -verify %s

// This is the same as the C version:

__vector char vv_c;
__vector signed char vv_sc;
__vector unsigned char vv_uc;
__vector short vv_s;
__vector signed  short vv_ss;
__vector unsigned  short vv_us;
__vector short int vv_si;
__vector signed short int vv_ssi;
__vector unsigned short int vv_usi;
__vector int vv_i;
__vector signed int vv_sint;
__vector unsigned int vv_ui;
__vector float vv_f;
__vector bool vv_b;
__vector __pixel vv_p;
__vector pixel vv__p;
__vector int vf__r();
void vf__a(__vector int a);
void vf__a2(int b, __vector int a);

vector char v_c;
vector signed char v_sc;
vector unsigned char v_uc;
vector short v_s;
vector signed  short v_ss;
vector unsigned  short v_us;
vector short int v_si;
vector signed short int v_ssi;
vector unsigned short int v_usi;
vector int v_i;
vector signed int v_sint;
vector unsigned int v_ui;
vector float v_f;
vector bool v_b;
vector __pixel v_p;
vector pixel v__p;
vector int f__r();
void f_a(vector int a);
void f_a2(int b, vector int a);

// These should have warnings.
__vector long vv_l;                 // expected-warning {{Use of 'long' with '__vector' is deprecated}}
__vector signed long vv_sl;         // expected-warning {{Use of 'long' with '__vector' is deprecated}}
__vector unsigned long vv_ul;       // expected-warning {{Use of 'long' with '__vector' is deprecated}}
__vector long int vv_li;            // expected-warning {{Use of 'long' with '__vector' is deprecated}}
__vector signed long int vv_sli;    // expected-warning {{Use of 'long' with '__vector' is deprecated}}
__vector unsigned long int vv_uli;  // expected-warning {{Use of 'long' with '__vector' is deprecated}}
vector long v_l;                    // expected-warning {{Use of 'long' with '__vector' is deprecated}}
vector signed long v_sl;            // expected-warning {{Use of 'long' with '__vector' is deprecated}}
vector unsigned long v_ul;          // expected-warning {{Use of 'long' with '__vector' is deprecated}}
vector long int v_li;               // expected-warning {{Use of 'long' with '__vector' is deprecated}}
vector signed long int v_sli;       // expected-warning {{Use of 'long' with '__vector' is deprecated}}
vector unsigned long int v_uli;     // expected-warning {{Use of 'long' with '__vector' is deprecated}}
__vector long double  vv_ld;        // expected-warning {{Use of 'long' with '__vector' is deprecated}} expected-error {{cannot use 'double' with '__vector'}}
vector long double  v_ld;           // expected-warning {{Use of 'long' with '__vector' is deprecated}} expected-error {{cannot use 'double' with '__vector'}}

// These should have errors.
__vector double vv_d1;               // expected-error {{cannot use 'double' with '__vector'}}
vector double v_d2;                  // expected-error {{cannot use 'double' with '__vector'}}
__vector long double  vv_ld3;        // expected-warning {{Use of 'long' with '__vector' is deprecated}} expected-error {{cannot use 'double' with '__vector'}}
vector long double  v_ld4;           // expected-warning {{Use of 'long' with '__vector' is deprecated}} expected-error {{cannot use 'double' with '__vector'}}

void f() {
  __vector unsigned int v = {0,0,0,0};
  __vector int v__cast = (__vector int)v;
  __vector int v_cast = (vector int)v;
  __vector char vb_cast = (vector char)v;

  // Check some casting between gcc and altivec vectors.
  #define gccvector __attribute__((vector_size(16)))
  gccvector unsigned int gccv = {0,0,0,0};
  gccvector unsigned int gccv1 = gccv;
  gccvector int gccv2 = (gccvector int)gccv;
  gccvector unsigned int gccv3 = v;
  __vector unsigned int av = gccv;
  __vector int avi = (__vector int)gccv;
  gccvector unsigned int gv = v;
  gccvector int gvi = (gccvector int)v;
  __attribute__((vector_size(8))) unsigned int gv8;
  gv8 = gccv;     // expected-error {{incompatible type assigning '__attribute__((__vector_size__(4 * sizeof(unsigned int)))) unsigned int', expected '__attribute__((__vector_size__(2 * sizeof(unsigned int)))) unsigned int'}}
  av = gv8;       // expected-error {{incompatible type assigning '__attribute__((__vector_size__(2 * sizeof(unsigned int)))) unsigned int', expected '__vector unsigned int'}}

  v = gccv;
  __vector unsigned int tv = gccv;
  gccv = v;
  gccvector unsigned int tgv = v;
}

// Now for the C++ version:

class vc__v {
  __vector int v;
  __vector int f__r();
  void f__a(__vector int a);
  void f__a2(int b, __vector int a);
};

class c_v {
  vector int v;
  vector int f__r();
  void f__a(vector int a);
  void f__a2(int b, vector int a);
};

