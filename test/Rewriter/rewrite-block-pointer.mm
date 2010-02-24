// RUN: %clang_cc1 -x objective-c++ -Wno-return-type -fblocks -fms-extensions -rewrite-objc %s -o %t-rw.cpp
// RUN: %clang_cc1 -fsyntax-only -Wno-address-of-temporary -D"SEL=void*" -D"__declspec(X)=" %t-rw.cpp
// radar 7638400

typedef void * id;
void *sel_registerName(const char *);

@interface X
@end

void foo(void (^block)(int));

@implementation X
static void enumerateIt(void (^block)(id, id, char *)) {
      foo(^(int idx) { });
}
@end

// radar 7651312
void apply(void (^block)(int));

static void x(int (^cmp)(int, int)) {
	x(cmp);
}

static void y(int (^cmp)(int, int)) {
	apply(^(int sect) {
		x(cmp);
    });
}

// radar 7659483
void *_Block_copy(const void *aBlock);
void x(void (^block)(void)) {
        block = ((__typeof(block))_Block_copy((const void *)(block)));
}

// radar 7682149
@interface Y {
@private
    id _private;
}
- (void (^)(void))f;
@end

typedef void (^void_block_t)(void);

@interface YY {
    void_block_t __completion;
}
@property (copy) void_block_t f;
@end

@implementation Y
- (void (^)(void))f {
    return [_private f];
}

@end

