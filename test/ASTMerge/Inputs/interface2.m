// Matches
@interface I1 {
  int ivar1;
}
@end

// Matches
@interface I2 : I1 {
  float ivar2;
}
@end

// Ivar mismatch
@interface I3 {
  int ivar1;
  float ivar2;
}
@end

// Superclass mismatch
@interface I4 : I1 {
}
@end

// Methods match
@interface I5
+ (float)bar;
- (int)foo;
@end

// Method mismatch
@interface I6
+ (float)foo;
@end

// Method mismatch
@interface I7
- (int)foo;
+ (int)bar:(float)x;
@end

// Method mismatch
@interface I8
- (int)foo;
+ (int)bar:(float)x, ...;
@end

// Matching protocol
@protocol P0
+ (int)foo;
- (int)bar:(float)x;
@end

// Protocol with mismatching method
@protocol P1
+ (int)foo;
- (int)bar:(double)x;
@end

// Interface with protocol
@interface I9 <P0>
+ (int)foo;
- (int)bar:(float)x;
@end

// Protocol with protocol
@protocol P2 <P0>
- (float)wibble:(int)a1 second:(int)a2;
@end
