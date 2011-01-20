// Test is line- and column-sensitive. See run lines below.

template<typename T, T Value, template<typename U, U ValU> class X>
void f(X<T, Value> x);

template<typename T> class allocator;

template<typename T, typename Alloc = allocator<T> >
class vector {
  void clear();
};

template<typename T>
class vector<T*> { };

struct Z1 { };

template class vector<Z1>;

struct Z2 { };

template<>
class vector<Z2> {
  void clear();
};

template<typename T, typename U>
struct Y {
  using typename T::type;
  using U::operator Z2;
};

struct Z3 { };

const unsigned OneDimension = 1;
template<typename T, unsigned Dimensions = OneDimension>
struct array { };

template<template<typename, unsigned> class DataStructure = array>
struct storage { };

typedef unsigned Unsigned;

template<typename T, Unsigned Value>
struct value_c;

template class vector<int*>;

struct Z4 {
  template<typename T> T getAs();
};

void template_exprs() {
  f<Unsigned, OneDimension, array>(array<Unsigned, OneDimension>());
  Z4().getAs<Unsigned>();
}

// RUN: c-index-test -test-load-source all %s | FileCheck -check-prefix=CHECK-LOAD %s
// CHECK-LOAD: index-templates.cpp:4:6: FunctionTemplate=f:4:6 Extent=[3:1 - 4:22]
// CHECK-LOAD: index-templates.cpp:3:19: TemplateTypeParameter=T:3:19 (Definition) Extent=[3:19 - 3:20]
// CHECK-LOAD: index-templates.cpp:3:24: NonTypeTemplateParameter=Value:3:24 (Definition) Extent=[3:22 - 3:29]
// FIXME: Need the template type parameter here
// CHECK-LOAD: index-templates.cpp:3:66: TemplateTemplateParameter=X:3:66 (Definition) Extent=[3:31 - 3:67]
// CHECK-LOAD: index-templates.cpp:4:20: ParmDecl=x:4:20 (Definition) Extent=[4:8 - 4:21]
// CHECK-LOAD: index-templates.cpp:4:8: TemplateRef=X:3:66 Extent=[4:8 - 4:9]
// FIXME: Need the template type parameter here
// CHECK-LOAD: index-templates.cpp:4:13: DeclRefExpr=Value:3:24 Extent=[4:13 - 4:18]
// CHECK-LOAD: index-templates.cpp:6:28: ClassTemplate=allocator:6:28 Extent=[6:1 - 6:37]
// CHECK-LOAD: index-templates.cpp:6:19: TemplateTypeParameter=T:6:19 (Definition) Extent=[6:19 - 6:20]
// CHECK-LOAD: index-templates.cpp:9:7: ClassTemplate=vector:9:7 (Definition) Extent=[8:1 - 11:2]
// CHECK-LOAD: index-templates.cpp:8:19: TemplateTypeParameter=T:8:19 (Definition) Extent=[8:19 - 8:20]
// CHECK-LOAD: index-templates.cpp:8:31: TemplateTypeParameter=Alloc:8:31 (Definition) Extent=[8:31 - 8:36]
// CHECK-LOAD: index-templates.cpp:8:39: TemplateRef=allocator:6:28 Extent=[8:39 - 8:48]
// CHECK-LOAD: index-templates.cpp:10:8: CXXMethod=clear:10:8 Extent=[10:8 - 10:15]
// CHECK-LOAD: index-templates.cpp:14:7: ClassTemplatePartialSpecialization=vector:14:7 (Definition) [Specialization of vector:9:7] Extent=[13:1 - 14:21]
// CHECK-LOAD: index-templates.cpp:13:19: TemplateTypeParameter=T:13:19 (Definition) Extent=[13:19 - 13:20]
// CHECK-LOAD: index-templates.cpp:16:8: StructDecl=Z1:16:8 (Definition) Extent=[16:1 - 16:14]
// CHECK-LOAD: index-templates.cpp:18:16: ClassDecl=vector:18:16 (Definition) [Specialization of vector:9:7] Extent=[18:1 - 18:22]
// CHECK-LOAD: index-templates.cpp:18:23: TypeRef=struct Z1:16:8 Extent=[18:23 - 18:25]
// CHECK-LOAD-NOT: CXXMethod=clear
// CHECK-LOAD: index-templates.cpp:20:8: StructDecl=Z2:20:8 (Definition) Extent=[20:1 - 20:14]
// CHECK-LOAD: index-templates.cpp:23:7: ClassDecl=vector:23:7 (Definition) [Specialization of vector:9:7] Extent=[22:1 - 25:2]
// CHECK-LOAD: index-templates.cpp:23:14: TypeRef=struct Z2:20:8 Extent=[23:14 - 23:16]
// CHECK-LOAD: index-templates.cpp:24:8: CXXMethod=clear:24:8 Extent=[24:8 - 24:15]
// CHECK-LOAD: index-templates.cpp:28:8: ClassTemplate=Y:28:8 (Definition) Extent=[27:1 - 31:2]
// CHECK-LOAD: index-templates.cpp:27:19: TemplateTypeParameter=T:27:19 (Definition) Extent=[27:19 - 27:20]
// CHECK-LOAD: index-templates.cpp:27:31: TemplateTypeParameter=U:27:31 (Definition) Extent=[27:31 - 27:32]
// CHECK-LOAD: index-templates.cpp:29:21: UsingDeclaration=type:29:21 Extent=[29:3 - 29:25]
// CHECK-LOAD: index-templates.cpp:30:12: UsingDeclaration=operator Z2:30:12 Extent=[30:3 - 30:23]
// CHECK-LOAD: index-templates.cpp:30:21: TypeRef=struct Z2:20:8 Extent=[30:21 - 30:23]
// CHECK-LOAD: index-templates.cpp:35:16: VarDecl=OneDimension:35:16 (Definition) Extent=[35:7 - 35:32]
// CHECK-LOAD: index-templates.cpp:35:31: UnexposedExpr= Extent=[35:31 - 35:32]
// CHECK-LOAD: index-templates.cpp:35:31: UnexposedExpr= Extent=[35:31 - 35:32]
// CHECK-LOAD: index-templates.cpp:37:8: ClassTemplate=array:37:8 (Definition) Extent=[36:1 - 37:17]
// CHECK-LOAD: index-templates.cpp:36:19: TemplateTypeParameter=T:36:19 (Definition) Extent=[36:19 - 36:20]
// CHECK-LOAD: index-templates.cpp:36:31: NonTypeTemplateParameter=Dimensions:36:31 (Definition) Extent=[36:22 - 36:41]
// CHECK-LOAD: index-templates.cpp:36:44: DeclRefExpr=OneDimension:35:16 Extent=[36:44 - 36:56]
// CHECK-LOAD: index-templates.cpp:40:8: ClassTemplate=storage:40:8 (Definition) Extent=[39:1 - 40:19]
// CHECK-LOAD: index-templates.cpp:39:45: TemplateTemplateParameter=DataStructure:39:45 (Definition) Extent=[39:10 - 39:66]
// CHECK-LOAD: index-templates.cpp:39:19: TemplateTypeParameter=:39:19 (Definition) Extent=[39:19 - 39:27]
// CHECK-LOAD: index-templates.cpp:39:37: NonTypeTemplateParameter=:39:37 (Definition) Extent=[39:29 - 39:38]
// CHECK-LOAD: index-templates.cpp:39:61: TemplateRef=array:37:8 Extent=[39:61 - 39:66]
// CHECK-LOAD: index-templates.cpp:42:18: TypedefDecl=Unsigned:42:18 (Definition) Extent=[42:18 - 42:26]
// CHECK-LOAD: index-templates.cpp:45:8: ClassTemplate=value_c:45:8 Extent=[44:1 - 45:15]
// CHECK-LOAD: index-templates.cpp:44:19: TemplateTypeParameter=T:44:19 (Definition) Extent=[44:19 - 44:20]
// CHECK-LOAD: index-templates.cpp:44:31: NonTypeTemplateParameter=Value:44:31 (Definition) Extent=[44:22 - 44:36]
// CHECK-LOAD: index-templates.cpp:44:22: TypeRef=Unsigned:42:18 Extent=[44:22 - 44:30]
// CHECK-LOAD: index-templates.cpp:47:16: ClassDecl=vector:47:16 (Definition) [Specialization of vector:14:7] Extent=[47:1 - 47:22]
// CHECK-LOAD: index-templates.cpp:49:8: StructDecl=Z4:49:8 (Definition) Extent=[49:1 - 51:2]
// CHECK-LOAD: index-templates.cpp:50:26: FunctionTemplate=getAs:50:26 Extent=[50:3 - 50:33]
// CHECK-LOAD: index-templates.cpp:50:21: TemplateTypeParameter=T:50:21 (Definition) Extent=[50:21 - 50:22]
// CHECK-LOAD: index-templates.cpp:53:6: FunctionDecl=template_exprs:53:6 (Definition)
// CHECK-LOAD: <invalid loc>:0:0: UnexposedStmt=
// CHECK-LOAD: index-templates.cpp:54:3: CallExpr=f:4:6 Extent=[54:3 - 54:68]
// CHECK-LOAD: index-templates.cpp:54:3: UnexposedExpr=f:4:6 Extent=[54:3 - 54:35]
// CHECK-LOAD: index-templates.cpp:54:3: DeclRefExpr=f:4:6 Extent=[54:3 - 54:35]
// CHECK-LOAD: index-templates.cpp:54:5: TypeRef=Unsigned:42:18 Extent=[54:5 - 54:13]
// CHECK-LOAD: index-templates.cpp:54:15: DeclRefExpr=OneDimension:35:16 Extent=[54:15 - 54:27]
// CHECK-LOAD: index-templates.cpp:54:29: TemplateRef=array:37:8 Extent=[54:29 - 54:34]
// CHECK-LOAD: index-templates.cpp:55:8: MemberRefExpr=getAs:50:26 Extent=[55:3 - 55:23]
// CHECK-LOAD: index-templates.cpp:55:3: CallExpr= Extent=[55:3 - 55:7]
// CHECK-LOAD: index-templates.cpp:55:14: TypeRef=Unsigned:42:18 Extent=[55:14 - 55:22]

// RUN: c-index-test -test-load-source-usrs all %s | FileCheck -check-prefix=CHECK-USRS %s
// CHECK-USRS: index-templates.cpp c:@FT@>3#T#Nt0.0#t>2#T#Nt1.0f#>t0.22t0.0# Extent=[3:1 - 4:22]
// CHECK-USRS: index-templates.cpp c:index-templates.cpp@79 Extent=[3:19 - 3:20]
// CHECK-USRS: index-templates.cpp c:index-templates.cpp@82 Extent=[3:22 - 3:29]
// CHECK-USRS: index-templates.cpp c:index-templates.cpp@91 Extent=[3:31 - 3:67]
// CHECK-USRS: index-templates.cpp c:index-templates.cpp@136@FT@>3#T#Nt0.0#t>2#T#Nt1.0f#>t0.22t0.0#@x Extent=[4:8 - 4:21]
// CHECK-USRS: index-templates.cpp c:@CT>1#T@allocator Extent=[6:1 - 6:37]
// CHECK-USRS: index-templates.cpp c:index-templates.cpp@171 Extent=[6:19 - 6:20]
// CHECK-USRS: index-templates.cpp c:@CT>2#T#T@vector Extent=[8:1 - 11:2]
// CHECK-USRS: index-templates.cpp c:index-templates.cpp@210 Extent=[8:19 - 8:20]
// CHECK-USRS: index-templates.cpp c:index-templates.cpp@222 Extent=[8:31 - 8:36]
// CHECK-USRS: index-templates.cpp c:@CT>2#T#T@vector@F@clear# Extent=[10:8 - 10:15]
// CHECK-USRS: index-templates.cpp c:index-templates.cpp@280@CP>1#T@vector>#*t0.0#>@CT>1#T@allocator1*t0.0 Extent=[13:1 - 14:21]
// CHECK-USRS: index-templates.cpp c:index-templates.cpp@298 Extent=[13:19 - 13:20]
// CHECK-USRS: index-templates.cpp c:@S@Z1 Extent=[16:1 - 16:14]
// CHECK-USRS: index-templates.cpp c:@C@vector>#$@S@Z1#$@C@allocator>#$@S@Z1 Extent=[18:1 - 18:22]
// CHECK-USRS: index-templates.cpp c:@S@Z2 Extent=[20:1 - 20:14]
// CHECK-USRS: index-templates.cpp c:@C@vector>#$@S@Z2#$@C@allocator>#$@S@Z2 Extent=[22:1 - 25:2]
// CHECK-USRS: index-templates.cpp c:@C@vector>#$@S@Z2#$@C@allocator>#$@S@Z2@F@clear# Extent=[24:8 - 24:15]
// CHECK-USRS: index-templates.cpp c:@ST>2#T#T@Y Extent=[27:1 - 31:2]
// CHECK-USRS: index-templates.cpp c:index-templates.cpp@452 Extent=[27:19 - 27:20]
// CHECK-USRS: index-templates.cpp c:index-templates.cpp@464 Extent=[27:31 - 27:32]
// CHECK-USRS-NOT: type
// CHECK-USRS: index-templates.cpp c:@S@Z3 Extent=[33:1 - 33:14]
