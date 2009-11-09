// RUN: clang-cc -fsyntax-only -verify %s

template<typename T, int N = 2> struct X; // expected-note{{template is declared here}}

X<int, 1> *x1;
X<int> *x2;

X<> *x3; // expected-error{{too few template arguments for class template 'X'}}

template<typename U = float, int M> struct X;

X<> *x4;

template<typename T = int> struct Z { };
template struct Z<>;

// PR4362
template<class T> struct a { };
template<> struct a<int> { static const bool v = true; };

template<class T, bool = a<T>::v> struct p { }; // expected-error {{no member named 'v'}}

template struct p<bool>; // expected-note {{in instantiation of default argument for 'p<bool>' required here}}
template struct p<int>;

// PR5187
template<typename T, typename U>
struct A;

template<typename T, typename U = T>
struct A;

template<typename T, typename U>
struct A {
  void f(A<T>);
};

template<typename T>
struct B { };

template<>
struct B<void> {
  typedef B<void*> type;
};

// Nested default arguments for template parameters.
template<typename T> struct X1 { };

template<typename T>
struct X2 {
  template<typename U = typename X1<T>::type> // expected-error{{no type named}}
  struct Inner1 { };
  
  template<T Value = X1<T>::value> // expected-error{{no member named 'value'}}
  struct NonType1 { };
  
  template<T Value>
  struct Inner2 { };
  
  template<typename U>
  struct Inner3 {
    template<typename X = T, typename V = U>
    struct VeryInner { };
    
    template<T Value1 = sizeof(T), T Value2 = sizeof(U), 
             T Value3 = Value1 + Value2>
    struct NonType2 { };
  };
};

X2<int> x2i;
X2<int>::Inner1<float> x2iif;

X2<int>::Inner1<> x2bad; // expected-note{{instantiation of default argument}}

X2<int>::NonType1<'a'> x2_nontype1;
X2<int>::NonType1<> x2_nontype1_bad; // expected-note{{instantiation of default argument}}

// Check multi-level substitution into template type arguments
X2<int>::Inner3<float>::VeryInner<> vi;
X2<char>::Inner3<int>::NonType2<> x2_deep_nontype;


template<typename T, typename U>
struct is_same { static const bool value = false; };

template<typename T>
struct is_same<T, T> { static const bool value = true; };

static int array1[is_same<__typeof__(vi), 
               X2<int>::Inner3<float>::VeryInner<int, float> >::value? 1 : -1];

static int array2[is_same<__typeof(x2_deep_nontype),
                     X2<char>::Inner3<int>::NonType2<sizeof(char), sizeof(int), 
                                    sizeof(char)+sizeof(int)> >::value? 1 : -1];
