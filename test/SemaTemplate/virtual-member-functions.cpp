// RUN: %clang_cc1 -fsyntax-only -verify %s

namespace PR5557 {
template <class T> struct A {
  A();
  virtual void anchor(); // expected-note{{instantiation}}
  virtual int a(T x);
};
template<class T> A<T>::A() {}
template<class T> void A<T>::anchor() { }

template<class T> int A<T>::a(T x) { 
  return *x; // expected-error{{requires pointer operand}}
}

void f(A<int> x) {
  x.anchor(); // expected-note{{in instantiation of member function 'PR5557::A<int>::anchor' requested here}}
}

template<typename T>
struct X {
  virtual void f();
};

template<>
void X<int>::f() { }
}

template<typename T>
struct Base {
  virtual ~Base() { 
    int *ptr = 0;
    T t = ptr; // expected-error{{cannot initialize}}
  }
};

template<typename T>
struct Derived : Base<T> {
  virtual void foo() { } // expected-note {{in instantiation of member function 'Base<int>::~Base' requested here}}
};

template struct Derived<int>;

template<typename T>
struct HasOutOfLineKey {
  HasOutOfLineKey() { } // expected-note{{in instantiation of member function 'HasOutOfLineKey<int>::f' requested here}}
  virtual T *f(float *fp);
};

template<typename T>
T *HasOutOfLineKey<T>::f(float *fp) {
  return fp; // expected-error{{cannot initialize return object of type 'int *' with an lvalue of type 'float *'}}
}

HasOutOfLineKey<int> out_of_line; // expected-note{{in instantiation of member function 'HasOutOfLineKey<int>::HasOutOfLineKey' requested here}}
