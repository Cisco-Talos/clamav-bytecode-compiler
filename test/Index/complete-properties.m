/* Note: the RUN lines are near the end of the file, since line/column
 matter for this test. */

@interface I1 
{
  id StoredProp3;
  int RandomIVar;
}
@property int Prop1;
@property float Prop2;
@end

@interface I2 : I1
@property id Prop3;
@end

@implementation I2
@synthesize Prop2, Prop1, Prop3 = StoredProp3;
@end

// RUN: c-index-test -code-completion-at=%s:18:13 %s | FileCheck -check-prefix=CHECK-CC1 %s
// CHECK-CC1: ObjCPropertyDecl:{TypedText Prop1}
// CHECK-CC1: ObjCPropertyDecl:{TypedText Prop2}
// CHECK-CC1: ObjCPropertyDecl:{TypedText Prop3}
// RUN: c-index-test -code-completion-at=%s:18:20 %s | FileCheck -check-prefix=CHECK-CC2 %s
// CHECK-CC2: ObjCPropertyDecl:{TypedText Prop1}
// CHECK-CC2-NEXT: ObjCPropertyDecl:{TypedText Prop3}
// RUN: c-index-test -code-completion-at=%s:18:35 %s | FileCheck -check-prefix=CHECK-CC3 %s
// CHECK-CC3: ObjCIvarDecl:{TypedText RandomIVar}
// CHECK-CC3: ObjCIvarDecl:{TypedText StoredProp3}
