// RUN: clang-cc -rewrite-objc %s -o -

#include <stdarg.h>

@interface NSObject @end
@interface XX : NSObject @end

@implementation XX
- (void)encodeValuesOfObjCTypes:(const char *)types, ... {
   va_list ap;
   va_start(ap, types); 
   while (*types) ;
   va_end(ap);
}

@end

