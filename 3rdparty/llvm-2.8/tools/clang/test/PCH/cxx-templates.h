// Header for PCH test cxx-templates.cpp

template <typename T1, typename T2>
struct S;

template <typename T1, typename T2>
struct S {
  S() { }
  static void templ();
};

template <typename T>
struct S<int, T> {
    static void partial();
};

template <>
struct S<int, float> {
    static void explicit_special();
};

template <int x>
int tmpl_f2() { return x; }

template <typename T, int y>
T templ_f(T x) {
  int z = templ_f<int, 5>(3);
  z = tmpl_f2<y+2>();
  T data[y];
  return x+y;
}

void govl(int);
void govl(char);

template <typename T>
struct Unresolv {
  void f() {
    govl(T());
  }
};

template <typename T>
struct Dep {
  typedef typename T::type Ty;
  void f() {
    Ty x = Ty();
    T::my_f();
    int y = T::template my_templf<int>(0);
    ovl(y);
  }
  
  void ovl(int);
  void ovl(float);
};

template<typename T, typename A1>
inline T make_a(const A1& a1) {
  T::depend_declref();
  return T(a1);
}

template <class T> class UseBase {
  void foo();
  typedef int bar;
};

template <class T> class UseA : public UseBase<T> {
  using UseBase<T>::foo;
  using typename UseBase<T>::bar; 
};

template <class T> class Sub : public UseBase<int> { };

template <class _Ret, class _Tp>
  class mem_fun_t
  {
  public:
    explicit
    mem_fun_t(_Ret (_Tp::*__pf)())
     {}

  private:
    _Ret (_Tp::*_M_f)();
  };

template<unsigned N>
bool isInt(int x);

template<> bool isInt<8>(int x) {
  try { ++x; } catch(...) { --x; }
  return true;
}

template<typename _CharT>
int __copy_streambufs_eof(_CharT);

class basic_streambuf 
{
  void m() { }
  friend int __copy_streambufs_eof<>(int);
};

// PR 7660
template<typename T> struct S_PR7660 { void g(void (*)(T)); };
 template<> void S_PR7660<int>::g(void(*)(int)) {}

// PR 7670
template<typename> class C_PR7670;
template<> class C_PR7670<int>;
template<> class C_PR7670<int>;

template <bool B>
struct S2 {
    static bool V;
};

extern template class S2<true>;

template <typename T>
struct S3 {
    void m();
};

template <typename T>
inline void S3<T>::m() { }

template <typename T>
struct S4 {
    void m() { }
};
extern template struct S4<int>;

void S4ImplicitInst() {
    S4<int> s;
    s.m();
}
