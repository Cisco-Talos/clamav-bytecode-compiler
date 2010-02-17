// RUN: %clang_cc1 -emit-pch -o %t.1.ast %S/Inputs/property1.m
// RUN: %clang_cc1 -emit-pch -o %t.2.ast %S/Inputs/property2.m
// RUN: %clang_cc1 -ast-merge %t.1.ast -ast-merge %t.2.ast -fsyntax-only %s 2>&1 | FileCheck %s

// CHECK: property2.m:12:26: error: property 'Prop1' declared with incompatible types in different translation units ('int' vs. 'float')
// CHECK: property1.m:10:28: note: declared here with type 'float'
// CHECK: property2.m:12:26: error: instance method 'Prop1' has incompatible result types in different translation units ('int' vs. 'float')
// CHECK: property1.m:10:28: note: instance method 'Prop1' also declared here
// CHECK: 4 diagnostics generated.
