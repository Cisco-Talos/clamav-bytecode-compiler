// RUN: %clang_cc1 -fsyntax-only -verify %s

template<typename T, typename U>
struct X0 : T::template apply<U> { 
  X0(U u) : T::template apply<U>(u) { }
};

template<typename T, typename U>
struct X1 : T::apply<U> { }; // expected-error{{missing 'template' keyword prior to dependent template name 'T::apply'}}

template<typename T>
struct X2 : vector<T> { }; // expected-error{{unknown template name 'vector'}}

namespace PR6031 {
  template<typename T>
  struct A;

  template <class X>
  struct C { };

  template <class TT>
  struct II {
    typedef typename A<TT>::type type;
  };

  template <class TT>
  struct FI : II<TT>
  {
    C<typename FI::type> a;
  };

  template <class TT>
  struct FI2
  {
    C<typename FI2::type> a; // expected-error{{no type named 'type' in 'struct PR6031::FI2'}} \
        // expected-error{{C++ requires a type specifier for all declarations}}
  };

  template<typename T>
  struct Base {
    class Nested { };
    template<typename U> struct MemberTemplate { };
    int a;
  };

  template<typename T>
  struct HasDepBase : Base<T> {
    int foo() {
      class HasDepBase::Nested nested;
      typedef typename HasDepBase::template MemberTemplate<T>::type type;
      return HasDepBase::a;
    }
  };

  template<typename T>
  struct NoDepBase {
    int foo() {
      class NoDepBase::Nested nested; // expected-error{{'Nested' does not name a tag member in the specified scope}}
      typedef typename NoDepBase::template MemberTemplate<T>::type type; // expected-error{{'MemberTemplate' following the 'template' keyword does not refer to a template}} \
      // FIXME: expected-error{{unqualified-id}}
      return NoDepBase::a; // expected-error{{no member named 'a' in 'struct PR6031::NoDepBase'}}
    }
  };
}

namespace Ambig {
  template<typename T>
  struct Base1 {
    typedef int type; // expected-note{{member found by ambiguous name lookup}}
  };

  struct Base2 {
    typedef float type; // expected-note{{member found by ambiguous name lookup}}
  };

  template<typename T>
  struct Derived : Base1<T>, Base2 {
    typedef typename Derived::type type; // expected-error{{member 'type' found in multiple base classes of different types}}
    type *foo(float *fp) { return fp; }
  };

  Derived<int> di; // expected-note{{instantiation of}}
}

namespace PR6081 {
  template<typename T>
  struct A { };

  template<typename T>
  class B : public A<T> 
  {
  public:
    template< class X >
    void f0(const X & k)
    {
      this->template f1<int>()(k);
    }
  };

  template<typename T>
  class C
  {
  public:
    template< class X >
    void f0(const X & k)
    {
      this->template f1<int>()(k); // expected-error{{'f1' following the 'template' keyword does not refer to a template}} \
      // FIXME: expected-error{{unqualified-id}}
    }
  };
}

namespace PR6413 {
  template <typename T> class Base_A { };
  
  class Base_B { };
  
  template <typename T>
  class Derived
    : public virtual Base_A<T>
    , public virtual Base_B
  { };
}
