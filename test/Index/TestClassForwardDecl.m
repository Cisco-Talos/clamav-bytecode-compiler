// RUN: %clang_cc1 -triple x86_64-apple-darwin10 -fobjc-nonfragile-abi -fblocks -emit-pch -x objective-c %s -o %t.ast
// RUN: c-index-test -test-file-scan %t.ast %s | FileCheck -check-prefix=scan %s
// RUN: c-index-test -test-load-tu %t.ast local | FileCheck -check-prefix=load %s

// This test checks how the @class resolves as a cursor when the @interface is implicitly defined.
// See TestClassDecl.m for the corresponding test case. (<rdar://problem/7383421>)

@class Foo;

void function(Foo * arg)
{
    // nothing here.
}

// CHECK-scan: [1:1 - 7:1] Invalid Cursor => NoDeclFound
// CHECK-scan: [8:1 - 8:7] UnexposedDecl=:8:1
// CHECK-scan: [8:8 - 8:10] ObjCClassRef=Foo:8:8
// CHECK-scan: [8:11 - 10:5] Invalid Cursor => NoDeclFound
// CHECK-scan: [10:6 - 10:14] FunctionDecl=function:10:6 (Definition)
// CHECK-scan: [10:15 - 10:17] ObjCClassRef=Foo:8:8
// CHECK-scan: [10:18 - 10:23] ParmDecl=arg:10:21 (Definition)
// CHECK-scan: [10:24 - 10:25] FunctionDecl=function:10:6 (Definition)
// CHECK-scan: [11:1 - 13:1] UnexposedStmt=















// CHECK-load: TestClassForwardDecl.m:10:6: FunctionDecl=function:10:6 (Definition)
// CHECK-load: TestClassForwardDecl.m:10:21: ParmDecl=arg:10:21

