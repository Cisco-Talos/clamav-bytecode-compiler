@interface I1 
@end

// Matching category
@interface I1 (Cat1)
- (int)method0;
@end

// Matching class extension
@interface I1 ()
- (int)method1;
@end

// Mismatched category
@interface I1 (Cat2)
- (int)method2;
@end

@interface I2
@end

// Mismatched class extension
@interface I2 ()
- (int)method3;
@end
