// RUN: %clang_cc1 -triple x86_64-apple-darwin10 -fobjc-nonfragile-abi -fblocks -emit-pch -x objective-c %s -o %t.ast
// RUN: c-index-test -test-load-tu %t.ast all | FileCheck %s

@interface Foo 
{
  __attribute__((iboutlet)) id myoutlet;
}

- foo;
+ fooC;

@end

@interface Bar : Foo 
{
}

@end

@interface Foo (FooCat)
- (int) catMethodWithFloat:(float) fArg;
- (float) floatMethod;
@end

@protocol Proto
- pMethod;
@end

@protocol SubP <Proto>
- spMethod;
@end

@interface Baz : Bar <SubP>
{
    int _anIVar;
}

- (Foo *) bazMethod;

@end

enum {
  someEnum
};

int main (int argc, const char * argv[]) {
	Baz * bee;
	id a = [bee foo];
	id <SubP> c = [Foo fooC];
	id <Proto> d;
	d = c;
	[d pMethod];
	[bee catMethodWithFloat:[bee floatMethod]];
  main(someEnum, (const char **)bee);
}

// CHECK: c-index-api-loadTU-test.m:4:12: ObjCInterfaceDecl=Foo:4:12 Extent=[4:1 - 12:5]
// CHECK: c-index-api-loadTU-test.m:6:32: attribute(iboutlet)= Extent=[6:32 - 6:40]
// CHECK: c-index-api-loadTU-test.m:6:32: ObjCIvarDecl=myoutlet:6:32 (Definition) Extent=[6:32 - 6:40]
// CHECK: c-index-api-loadTU-test.m:6:29: TypeRef=id:0:0 Extent=[6:29 - 6:31]
// CHECK: c-index-api-loadTU-test.m:9:1: ObjCInstanceMethodDecl=foo:9:1 Extent=[9:1 - 9:7]
// CHECK: c-index-api-loadTU-test.m:10:1: ObjCClassMethodDecl=fooC:10:1 Extent=[10:1 - 10:8]
// CHECK: c-index-api-loadTU-test.m:14:12: ObjCInterfaceDecl=Bar:14:12 Extent=[14:1 - 18:5]
// CHECK: c-index-api-loadTU-test.m:14:18: ObjCSuperClassRef=Foo:4:12 Extent=[14:18 - 14:21]
// CHECK: c-index-api-loadTU-test.m:20:12: ObjCCategoryDecl=FooCat:20:12 Extent=[20:1 - 23:5]
// CHECK: c-index-api-loadTU-test.m:20:12: ObjCClassRef=Foo:4:12 Extent=[20:12 - 20:15]
// CHECK: c-index-api-loadTU-test.m:21:1: ObjCInstanceMethodDecl=catMethodWithFloat::21:1 Extent=[21:1 - 21:41]
// CHECK: c-index-api-loadTU-test.m:21:36: ParmDecl=fArg:21:36 (Definition) Extent=[21:29 - 21:40]
// CHECK: c-index-api-loadTU-test.m:22:1: ObjCInstanceMethodDecl=floatMethod:22:1 Extent=[22:1 - 22:23]
// CHECK: c-index-api-loadTU-test.m:25:1: ObjCProtocolDecl=Proto:25:1 (Definition) Extent=[25:1 - 27:5]
// CHECK: c-index-api-loadTU-test.m:26:1: ObjCInstanceMethodDecl=pMethod:26:1 Extent=[26:1 - 26:11]
// CHECK: c-index-api-loadTU-test.m:29:1: ObjCProtocolDecl=SubP:29:1 (Definition) Extent=[29:1 - 31:5]
// CHECK: c-index-api-loadTU-test.m:29:17: ObjCProtocolRef=Proto:25:1 Extent=[29:17 - 29:22]
// CHECK: c-index-api-loadTU-test.m:30:1: ObjCInstanceMethodDecl=spMethod:30:1 Extent=[30:1 - 30:12]
// CHECK: c-index-api-loadTU-test.m:33:12: ObjCInterfaceDecl=Baz:33:12 Extent=[33:1 - 40:5]
// CHECK: c-index-api-loadTU-test.m:33:18: ObjCSuperClassRef=Bar:14:12 Extent=[33:18 - 33:21]
// CHECK: c-index-api-loadTU-test.m:33:23: ObjCProtocolRef=SubP:29:1 Extent=[33:23 - 33:27]
// CHECK: c-index-api-loadTU-test.m:35:9: ObjCIvarDecl=_anIVar:35:9 (Definition) Extent=[35:9 - 35:16]
// CHECK: c-index-api-loadTU-test.m:38:1: ObjCInstanceMethodDecl=bazMethod:38:1 Extent=[38:1 - 38:21]
// CHECK: c-index-api-loadTU-test.m:42:1: EnumDecl=:42:1 (Definition) Extent=[42:1 - 44:2]
// CHECK: c-index-api-loadTU-test.m:43:3: EnumConstantDecl=someEnum:43:3 (Definition) Extent=[43:3 - 43:11]
// CHECK: c-index-api-loadTU-test.m:46:5: FunctionDecl=main:46:5 (Definition) Extent=[46:5 - 55:2]
// CHECK: c-index-api-loadTU-test.m:46:15: ParmDecl=argc:46:15 (Definition) Extent=[46:11 - 46:19]
// CHECK: c-index-api-loadTU-test.m:46:34: ParmDecl=argv:46:34 (Definition) Extent=[46:27 - 46:38]
// CHECK: c-index-api-loadTU-test.m:46:5: UnexposedStmt= Extent=[46:42 - 55:2]
// CHECK: c-index-api-loadTU-test.m:46:5: UnexposedStmt= Extent=[47:2 - 47:12]
// CHECK: c-index-api-loadTU-test.m:47:8: VarDecl=bee:47:8 (Definition) Extent=[47:2 - 47:11]
// CHECK: c-index-api-loadTU-test.m:47:2: ObjCClassRef=Baz:33:12 Extent=[47:2 - 47:5]
// CHECK: c-index-api-loadTU-test.m:47:8: UnexposedStmt= Extent=[48:2 - 48:19]
// CHECK: c-index-api-loadTU-test.m:48:5: VarDecl=a:48:5 (Definition) Extent=[48:2 - 48:18]
// CHECK: c-index-api-loadTU-test.m:48:2: TypeRef=id:0:0 Extent=[48:2 - 48:4]
// CHECK: c-index-api-loadTU-test.m:48:9: ObjCMessageExpr=foo:9:1 Extent=[48:9 - 48:18]
// CHECK: c-index-api-loadTU-test.m:48:10: DeclRefExpr=bee:47:8 Extent=[48:10 - 48:13]
// CHECK: c-index-api-loadTU-test.m:48:5: UnexposedStmt= Extent=[49:2 - 49:27]
// CHECK: c-index-api-loadTU-test.m:49:12: VarDecl=c:49:12 (Definition) Extent=[49:2 - 49:26]
// CHECK: c-index-api-loadTU-test.m:49:2: TypeRef=id:0:0 Extent=[49:2 - 49:4]
// CHECK: c-index-api-loadTU-test.m:49:6: ObjCProtocolRef=SubP:29:1 Extent=[49:6 - 49:10]
// CHECK: c-index-api-loadTU-test.m:49:16: UnexposedExpr=fooC:10:1 Extent=[49:16 - 49:26]
// CHECK: c-index-api-loadTU-test.m:49:16: ObjCMessageExpr=fooC:10:1 Extent=[49:16 - 49:26]
// CHECK: c-index-api-loadTU-test.m:49:12: UnexposedStmt= Extent=[50:2 - 50:15]
// CHECK: c-index-api-loadTU-test.m:50:13: VarDecl=d:50:13 (Definition) Extent=[50:2 - 50:14]
// CHECK: c-index-api-loadTU-test.m:50:2: TypeRef=id:0:0 Extent=[50:2 - 50:4]
// CHECK: c-index-api-loadTU-test.m:50:6: ObjCProtocolRef=Proto:25:1 Extent=[50:6 - 50:11]
// CHECK: c-index-api-loadTU-test.m:51:2: UnexposedExpr= Extent=[51:2 - 51:7]
// CHECK: c-index-api-loadTU-test.m:51:2: DeclRefExpr=d:50:13 Extent=[51:2 - 51:3]
// CHECK: c-index-api-loadTU-test.m:51:6: UnexposedExpr=c:49:12 Extent=[51:6 - 51:7]
// CHECK: c-index-api-loadTU-test.m:51:6: DeclRefExpr=c:49:12 Extent=[51:6 - 51:7]
// CHECK: c-index-api-loadTU-test.m:52:2: ObjCMessageExpr=pMethod:26:1 Extent=[52:2 - 52:13]
// CHECK: c-index-api-loadTU-test.m:52:3: DeclRefExpr=d:50:13 Extent=[52:3 - 52:4]
// CHECK: c-index-api-loadTU-test.m:53:2: ObjCMessageExpr=catMethodWithFloat::21:1 Extent=[53:2 - 53:44]
// CHECK: c-index-api-loadTU-test.m:53:3: DeclRefExpr=bee:47:8 Extent=[53:3 - 53:6]
// CHECK: c-index-api-loadTU-test.m:53:26: ObjCMessageExpr=floatMethod:22:1 Extent=[53:26 - 53:43]
// CHECK: c-index-api-loadTU-test.m:53:27: DeclRefExpr=bee:47:8 Extent=[53:27 - 53:30]
// CHECK: c-index-api-loadTU-test.m:54:3: CallExpr=main:46:5 Extent=[54:3 - 54:37]
// CHECK: c-index-api-loadTU-test.m:54:3: UnexposedExpr=main:46:5 Extent=[54:3 - 54:7]
// CHECK: c-index-api-loadTU-test.m:54:3: DeclRefExpr=main:46:5 Extent=[54:3 - 54:7]
// CHECK: c-index-api-loadTU-test.m:54:8: DeclRefExpr=someEnum:43:3 Extent=[54:8 - 54:16]
// CHECK: c-index-api-loadTU-test.m:54:18: UnexposedExpr=bee:47:8 Extent=[54:18 - 54:36]
// CHECK: c-index-api-loadTU-test.m:54:33: DeclRefExpr=bee:47:8 Extent=[54:33 - 54:36]

