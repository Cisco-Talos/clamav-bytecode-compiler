// RUN: %clang_cc1 -emit-llvm -o %t %s

typedef struct objc_class *Class;

typedef struct objc_object {
    Class isa;
} *id;

@interface I
+ (Class) class;
- (void)meth : (id)object : (id)src_object;
+ (unsigned char) isSubclassOfClass:(Class)aClass ;
@end

@implementation I
+ (Class) class {return 0;}
+ (unsigned char) isSubclassOfClass:(Class)aClass {return 0;}
- (void)meth : (id)object  : (id)src_object {
    [object->isa isSubclassOfClass:[I class]];

    [(*object).isa isSubclassOfClass:[I class]];

    object->isa = src_object->isa;
    (*src_object).isa = (*object).isa;
}
@end


// rdar 7470820
static Class MyClass;

Class Test(const void *inObject1) {
  if(((id)inObject1)->isa == MyClass)
   return ((id)inObject1)->isa;
  return (id)0;
}

// rdar 7609722
@interface Foo { 
@public 
  id isa; 
} 
+(id)method;
@end

id Test2() {
    if([Foo method]->isa)
      return (*[Foo method]).isa;
    return [Foo method]->isa;
}

// rdar 7709015
@interface Cat   {}
@end

@interface SuperCat : Cat {}
+(void)geneticallyAlterCat:(Cat *)cat;
@end

@implementation SuperCat
+ (void)geneticallyAlterCat:(Cat *)cat {
    Class dynamicSubclass;
    ((id)cat)->isa = dynamicSubclass;
}
@end
