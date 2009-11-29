// RUN: clang-cc -analyze -analyzer-experimental-internal-checks -checker-cfref -analyzer-store=region -analyzer-constraints=range -verify -fblocks %s -analyzer-eagerly-assume

// Delta-reduced header stuff (needed for test cases).
typedef signed char BOOL;
typedef unsigned int NSUInteger;
typedef struct _NSZone NSZone;
@class NSInvocation, NSMethodSignature, NSCoder, NSString, NSEnumerator;
@protocol NSObject  - (BOOL)isEqual:(id)object;
- (oneway void)release;
@end  @protocol NSCopying  - (id)copyWithZone:(NSZone *)zone;
@end  @protocol NSMutableCopying  - (id)mutableCopyWithZone:(NSZone *)zone;
@end  @protocol NSCoding  - (void)encodeWithCoder:(NSCoder *)aCoder;
@end    @interface NSObject <NSObject> {}
+ (id)alloc;
@end  typedef struct {}
NSFastEnumerationState;
@protocol NSFastEnumeration  - (NSUInteger)countByEnumeratingWithState:(NSFastEnumerationState *)state objects:(id *)stackbuf count:(NSUInteger)len;
@end      @interface NSArray : NSObject <NSCopying, NSMutableCopying, NSCoding, NSFastEnumeration>  - (NSUInteger)count;
@end    @interface NSMutableArray : NSArray  - (void)addObject:(id)anObject;
- (BOOL)isEqualToString:(NSString *)aString;
@end        @interface NSAutoreleasePool : NSObject {}
- (void)drain;
- (id)init;
@end

// This test case tests that (x != 0) is eagerly evaluated before stored to
// 'y'.  This test case complements recoverCastedSymbol (see below) because
// the symbolic expression is stored to 'y' (which is a short instead of an
// int).  recoverCastedSymbol() only recovers path-sensitivity when the
// symbolic expression is literally the branch condition.
//
void handle_assign_of_condition(int x) {
  // The cast to 'short' causes us to lose symbolic constraint.
  short y = (x != 0);
  char *p = 0;
  if (y) {
    // This should be infeasible.
    if (!(x != 0)) {
      *p = 1;  // no-warning
    }
  }
}

// From <rdar://problem/6619921>
//
// In this test case, 'needsAnArray' is a signed char.  The analyzer tracks
// a symbolic value for this variable, but in the branch condition it is
// promoted to 'int'.  Currently the analyzer doesn't reason well about
// promotions of symbolic values, so this test case tests the logic in
// 'recoverCastedSymbol()' (GRExprEngine.cpp) to test that we recover
// path-sensitivity and use the symbol for 'needsAnArray' in the branch
// condition.
//
void handle_symbolic_cast_in_condition(void) {
  NSAutoreleasePool* pool = [[NSAutoreleasePool alloc] init];

  BOOL needsAnArray = [@"aString" isEqualToString:@"anotherString"];
  NSMutableArray* array = needsAnArray ? [[NSMutableArray alloc] init] : 0;
  if(needsAnArray)
    [array release];

  [pool drain];
}

// From PR 3836 (http://llvm.org/bugs/show_bug.cgi?id=3836)
//
// In this test case, the double '!' works fine with our symbolic constraints,
// but we don't support comparing SymConstraint != SymConstraint.  By eagerly
// assuming the truth of !!a or !!b, we can compare these values directly.
//
void pr3836(int *a, int *b) {
  if (!!a != !!b) /* one of them is NULL */
    return;
  if (!a && !b) /* both are NULL */
    return;
      
  *a = 1; // no-warning
  *b = 1; // no-warning
}


//===---------------------------------------------------------------------===//
// <rdar://problem/7342806>
// This false positive occured because the symbolic constraint on a short was
// not maintained via sign extension.  The analyzer doesn't properly handle
// the sign extension, but now tracks the constraint.  This particular
// case relies on -analyzer-eagerly-assume because of the expression
// 'Flag1 != Count > 0'.
//===---------------------------------------------------------------------===//

void rdar7342806_aux(short x);

void rdar7342806() {
  extern short Count;
  extern short Flag1;

  short *Pointer = 0;
  short  Flag2   = !!Pointer;   // Flag2 is false (0).
  short  Ok      = 1;
  short  Which;

  if( Flag1 != Count > 0 )
    // Static analyzer skips this so either
    //   Flag1 is true and Count > 0
    // or
    //   Flag1 is false and Count <= 0
    Ok = 0;

  if( Flag1 != Flag2 )
    // Analyzer skips this so Flag1 and Flag2 have the
    // same value, both are false because Flag2 is false. And
    // from that we know Count must be <= 0.
    Ok = 0;

  for( Which = 0;
         Which < Count && Ok;
           Which++ )
    // This statement can only execute if Count > 0 which can only
    // happen when Flag1 and Flag2 are both true and Flag2 will only
    // be true when Pointer is not NULL.
    rdar7342806_aux(*Pointer); // no-warning
}
