/* Test that all basic operations work properly */
int test_add(void);
int test_sub(void);
int test_mul(void);
int test_udiv(void);
int test_sdiv(void);
int test_rem(void);
int test_shl(void);
int test_lshr(void);
int test_ashr(void);
int test_and(void);
int test_or(void);
int test_xor(void);
int test_sext(void);
int test_zext(void);
int test_trunc(void);
int test_icmp(void);
int test_select(void);
int test_bswap(void);
int test_ifp(void);
int entrypoint(void)
{
   return test_add() + test_sub() + test_bswap() + test_ifp() + test_mul() +
     test_udiv() + test_sdiv()+ test_rem() + test_shl() + test_lshr()+
     test_ashr()+test_and()+test_or()+test_xor()+test_sext()+test_zext()+
     test_trunc()+test_icmp()+test_select();
}

#define fail(x) fail_real(x, __LINE__)
int fail_real(int x, int line)
{
   debug_print_str_start("failed arith test at line ",26);
   debug(line);
   debug_print_str_nonl("\n", 1);
   return 1/x;
}

uint32_t bs32(int32_t a)
{
  return __builtin_bswap32(a);
}

uint64_t bs64(int64_t a)
{
  return __builtin_bswap64(a);
}

int test_bswap(void)
{
  if (bs32(0xaa) != 0xaa000000)
    return fail(0);
  if (bs32(0x1234) != 0x34120000)
    return fail(0);
  if (bs64(0xaa) != 0xaa00000000000000UL)
    return fail(0);
  if (bs64(0x1234567890abcdefUL) != 0xefcdab9078563412UL)
    return fail(0);
  return 0x8;
}

int test_ifp(void)
{
  if (ilog2(1, 0) != 0x7fffffff)
    return fail(0);
  if (ilog2(1, 1) != 0)
    return fail(0);
  if (ilog2(2, 2) != 0)
    return fail(0);
  if (ilog2(2, 1) != 0x4000000)
    return fail(0);
  if (ilog2(1, 2) != -0x4000000)
    return fail(0);
  if (ilog2(4, 1) != 0x8000000)
    return fail(0);
  if (ilog2(8, 1) != 3*0x4000000)
    return fail(0);
  if (ilog2(3, 2) != 39256169)
    return fail(0);
  if (ilog2(5, 2) != 88713093)
    return fail(0);
  if (ilog2(1<<31,3) != 1974009751)
    return fail(0);
  if (ipow(0, 4, 1) != 0)
    return fail(0);
  if (ipow(1, 1, 1) != 1)
    return fail(0);
  if (ipow(2,10, 3) != 3*1024)
    return fail(0);
  if (iexp(0, 1, 1) != 1)
    return fail(0);
  if (iexp(1<<5, 3, 1<<16) != 2811605630)
    return fail(0);
  if (isin(1, 1, 1<<26) != 56470162)
    return fail(0);
  if (isin(1, 2, 1<<26) != 32173703)
    return fail(0);
  if (icos(1, 1, 1<<26) != 36259074)
    return fail(0);
  if (icos(1, 2, 1<<26) !=  58893569)
    return fail(0);
  return 0x80;
}

int8_t add_i8(int8_t a, int8_t b)
{
  return a + b;
}
int16_t add_i16(int16_t a, int16_t b)
{
  return a + b;
}
int32_t add_i32(int32_t a, int32_t b)
{
  return a + b;
}
int64_t add_i64(int64_t a, int64_t b)
{
  return a + b;
}

int test_add(void)
{
    if (add_i8(1, 1) != 2)
	return fail(0);
    if (add_i8(1, -1) != 0)
	return fail(0);
    if (add_i8(-1, -1) != -2)
	return fail(0);
    if (add_i8(255, 1) != 0)
	return fail(0);

    if (add_i16(1, 1) != 2)
	return fail(0);
    if (add_i16(1, -1) != 0)
	return fail(0);
    if (add_i16(-1, -1) != -2)
	return fail(0);
    if (add_i16(65535, 1) != 0)
	return fail(0);

    if (add_i32(1, 1) != 2)
	return fail(0);
    if (add_i32(1, -1) != 0)
	return fail(0);
    if (add_i32(-1, -1) != -2)
	return fail(0);
    if (add_i32(~0u, 1) != 0)
	return fail(0);

    if (add_i64(1, 1) != 2)
	return fail(0);
    if (add_i64(1, -1) != 0)
	return fail(0);
    if (add_i64(-1, -1) != -2)
	return fail(0);
    if (add_i64(~0ull, 1) != 0)
	return fail(0);
    return 0x1;
}

int8_t sub_i8(int8_t a, int8_t b)
{
  return a - b;
}
int16_t sub_i16(int16_t a, int16_t b)
{
  return a - b;
}
int32_t sub_i32(int32_t a, int32_t b)
{
  return a - b;
}
int64_t sub_i64(int64_t a, int64_t b)
{
  return a - b;
}

int test_sub(void)
{
    if (sub_i8(-1,1) != -2)
	return fail(0);
    if (sub_i8(1, -1) != 2)
	return fail(0);
    if (sub_i8(1, 1) != 0)
	return fail(0);

    if (sub_i16(-1,1) != -2)
	return fail(0);
    if (sub_i16(1, -1) != 2)
	return fail(0);
    if (sub_i16(1, 1) != 0)
	return fail(0);

    if (sub_i32(-1,1) != -2)
	return fail(0);
    if (sub_i32(1, -1) != 2)
	return fail(0);
    if (sub_i32(1, 1) != 0)
	return fail(0);

    if (sub_i64(-1,1) != -2)
	return fail(0);
    if (sub_i64(1, -1) != 2)
	return fail(0);
    if (sub_i64(1, 1) != 0)
	return fail(0);
    return 4;
}

int8_t mul_i8(int8_t a, int8_t b)
{
  return a * b;
}
int16_t mul_i16(int16_t a, int16_t b)
{
  return a * b;
}
int32_t mul_i32(int32_t a, int32_t b)
{
  return a * b;
}
int64_t mul_i64(int64_t a, int64_t b)
{
  return a * b;
}

int test_mul(void)
{
    if (mul_i8(-1, 1) != -1)
	return fail(0);
    if (mul_i8(-1, -1) != 1)
	return fail(0);
    if (mul_i8(1, 1) != 1)
	return fail(0);
    if (mul_i8(17, 35) != 83)
	return fail(0);

    if (mul_i16(-1, 1) != -1)
	return fail(0);
    if (mul_i16(-1, -1) != 1)
	return fail(0);
    if (mul_i16(1, 1) != 1)
	return fail(0);
    if (mul_i16(179, 871) != 24837)
	return fail(0);

    if (mul_i32(-1, 1) != -1)
	return fail(0);
    if (mul_i32(-1, -1) != 1)
	return fail(0);
    if (mul_i32(1, 1) != 1)
	return fail(0);
    if (mul_i32(179536, 871912) != 1920770176)
	return fail(0);

    if (mul_i64(-1, 1) != -1)
	return fail(0);
    if (mul_i64(-1, -1) != 1)
	return fail(0);
    if (mul_i64(1, 1) != 1)
	return fail(0);
    if (mul_i64(17953621789, 8719125119) != 8965922127819204963)
	return fail(0);
    return 0x10;
}

uint8_t udiv_i8(uint8_t a, uint8_t b)
{
  return a / b;
}
uint16_t udiv_i16(uint16_t a, uint16_t b)
{
  return a / b;
}
uint32_t udiv_i32(uint32_t a, uint32_t b)
{
  return a / b;
}
uint64_t udiv_i64(uint64_t a, uint64_t b)
{
  return a / b;
}

int test_udiv(void)
{
    if (udiv_i16(-534, 7) != 9286)
	return fail(0);
    return 0x40;
}

int8_t sdiv_i8(int8_t a, int8_t b)
{
  return a / b;
}
int16_t sdiv_i16(int16_t a, int16_t b)
{
  return a / b;
}
int32_t sdiv_i32(int32_t a, int32_t b)
{
  return a / b;
}
int64_t sdiv_i64(int64_t a, int64_t b)
{
  return a / b;
}

int test_sdiv(void)
{
    if (sdiv_i8(1, -1) != -1)
	return fail(0);
    if (sdiv_i8(-1,1) != -1)
	return fail(0);
    if (sdiv_i8(-1,-1) != 1)
	return fail(0);
    if (sdiv_i8(1,1) != 1)
	return fail(0);

    uint8_t a = 254;
    uint8_t b = 5;
    uint8_t c = add_i8(a,b);
    if (sdiv_i8(6, c) != 2)
	return fail(0);
    if (sdiv_i8(c, 2) != 1)
	return fail(0);

    if (sdiv_i16(-534, 7) != -76)
	return fail(0);
    return 0x100;
}

uint8_t urem_i8(uint8_t a, uint8_t b)
{
  return a % b;
}
uint16_t urem_i16(uint16_t a, uint16_t b)
{
  return a % b;
}
uint32_t urem_i32(uint32_t a, uint32_t b)
{
  return a % b;
}
uint64_t urem_i64(uint64_t a, uint64_t b)
{
  return a % b;
}
int8_t srem_i8(int8_t a, int8_t b)
{
  return a % b;
}
int16_t srem_i16(int16_t a, int16_t b)
{
  return a % b;
}
int32_t srem_i32(int32_t a, int32_t b)
{
  return a % b;
}
int64_t srem_i64(int64_t a, int64_t b)
{
  return a % b;
}

int test_rem(void)
{
    if (srem_i8(-1, 1) != 0)
	return fail(0);
    if (urem_i8(-1, 1) != 0)
	return fail(0);
    if (srem_i8(1, -1) != 0)
	return fail(0);
    if (srem_i16(-535,7) != -3)
	return fail(0);
    if (urem_i16(-535,7) != 6)
	return fail(0);
    return 0x400;
}

int8_t shl_i8(int8_t a, unsigned c)
{
  return a << c;
}
int16_t shl_i16(int16_t a, unsigned c)
{
  return a << c;
}
int32_t shl_i32(int32_t a, unsigned c)
{
  return a << c;
}
int64_t shl_i64(int64_t a, unsigned c)
{
  return a << c;
}

int test_shl(void)
{
    if (shl_i8(1, 1) != 2)
	return fail(0);
    if (shl_i8(1, 0) != 1)
	return fail(0);
    if (shl_i8(254, 2) != -8)
	return fail(0);
    if (shl_i16(0xfafe,2) != 0xffffebf8)
	return fail(0);
    return 0x1000;
}

int8_t lshr_i8(uint8_t a, unsigned c)
{
  return a >> c;
}
int16_t lshr_i16(uint16_t a, unsigned c)
{
  return a >> c;
}
int32_t lshr_i32(uint32_t a, unsigned c)
{
  return a >> c;
}
int64_t lshr_i64(uint64_t a, unsigned c)
{
  return a >> c;
}

int test_lshr(void)
{
    if (lshr_i8(0xfe, 1) != 0x7f)
	return fail(0);
    int8_t a = 254;
    int8_t b = 5;
    int8_t c = add_i8(a,b);
    if (lshr_i8(c, 1) != 1)
	return fail(0);
    return 0x4000;
}

int8_t ashr_i8(int8_t a, int8_t c)
{
 return a >> c;
}
int16_t ashr_i16(int16_t a, int16_t c)
{
 return a >> c;
}
int32_t ashr_i32(int32_t a, int32_t c)
{
 return a >> c;
}
int64_t ashr_i64(int64_t a, int64_t c)
{
 return a >> c;
}

int test_ashr(void)
{
    if (ashr_i8(0xfe, 1) != -1)
	return fail(0);
    if (ashr_i8(0x7e, 1) != 0x3f)
	return fail(0);
    return 0x10000;
}

int8_t and_i8(int8_t a, int8_t b)
{
  return a & b;
}
int16_t and_i16(int16_t a, int16_t b)
{
  return a & b;
}
int32_t and_i32(int32_t a, int32_t b)
{
  return a & b;
}
int64_t and_i64(int64_t a, int64_t b)
{
  return a & b;
}

int test_and(void)
{
    if (and_i8(0x5a, 0x0f) != 0xa)
	return fail(0);
    if (and_i16(0x5abc, 0xf000) != 0x5000)
	return fail(0);
    if (and_i32(0x5abc1234, 0x0f000000) != 0x0a000000)
	return fail(0);
    if (and_i64(0x5abc123456781234LL, 0x0f000000) != 0x06000000)
	return fail(0);
    return 0x40000;
}

int8_t or_i8(int8_t a, int8_t b)
{
  return a | b;
}
int16_t or_i16(int16_t a, int16_t b)
{
  return a | b;
}
int32_t or_i32(int32_t a, int32_t b)
{
  return a | b;
}
int64_t or_i64(int64_t a, int64_t b)
{
  return a | b;
}

int test_or(void)
{
    if (or_i8(0x5a, 0x0f) != 0x5f)
	return fail(0);
    if (or_i16(0x5abc, 0xf000) != (int16_t)0xfabc)
	return fail(0);
    if (or_i32(0x5abc1234, 0x0f000000) != 0x5fbc1234)
	return fail(0);
    if (or_i64(0x5abc123456781234LL, 0x0f000000) != 0x5abc12345f781234LL)
	return fail(0);
    return 0x100000;
}

int8_t xor_i8(int8_t a, int8_t b)
{
  return a ^ b;
}
int16_t xor_i16(int16_t a, int16_t b)
{
  return a ^ b;
}
int32_t xor_i32(int32_t a, int32_t b)
{
  return a ^ b;
}
int64_t xor_i64(int64_t a, int64_t b)
{
  return a ^ b;
}

int test_xor(void)
{
    if (xor_i8(0x5a, 0xf0) != (int8_t)0xaa)
	return fail(0);
    if (xor_i16(0x5a5a, 0xff00) != (int16_t)0xa55a)
	return fail(0);
    if (xor_i32(0x5a5a5a5a, 0xffffff00) != 0xa5a5a55a)
	return fail(0);
    if (xor_i64(0x5a5a5a5a5a5a5a5all, 0xffffffffffffff00ll) != 0xa5a5a5a5a5a5a55a)
	return fail(0);
    return 0x400000;
}

int16_t sext_i8to16(int8_t a)
{
  return a;
}
int32_t sext_i16to32(int16_t a)
{
  return a;
}
int64_t sext_i32to64(int32_t a)
{
  return a;
}

int test_sext(void)
{
    if (sext_i8to16(-4) != -4)
	return fail(0);
    if (sext_i16to32(-6) != -6)
	return fail(0);
    if (sext_i32to64(-6) != -6ll)
	return fail(0);
    return 0x1000000;
}

uint16_t zext_i8to16(uint8_t a)
{
  return a;
}
uint32_t zext_i16to32(uint16_t a)
{
  return a;
}
uint64_t zext_i32to64(uint32_t a)
{
  return a;
}

int test_zext(void)
{
  if (zext_i8to16(-4) != 0xfc)
      return fail(0);
  if (zext_i16to32(-4) != 0xfffc)
      return fail(0);
  if (zext_i32to64(-4) != 0xfffffffcll)
      return fail(0);
  return 0x4000000;
}

int8_t trunc_i16to8(int16_t a)
{
  return a;
}
int16_t trunc_i32to16(int32_t a)
{
  return a;
}
int32_t trunc_i64to32(int64_t a)
{
  return a;
}

int test_trunc(void)
{
    if (trunc_i16to8(0xfeed) != (int8_t)0xed)
	return fail(0);
    if (trunc_i32to16(0xdeadfeed) != (int16_t)0xfeed)
	return fail(0);
    if (trunc_i64to32(0xbeefdeadfeedbeefll) != 0xfeedbeef)
	return fail(0);
    return 0x10000000;
}

int test_icmp_(int a, int b, int c, unsigned d)
{
  int result = 0;
  if (a < b)
    result |= 1;
  if (b <= c)
    result |= 2;
  if (a > b)
    result |= 4;
  if (b >= c)
    result |= 8;
  if (a < d)
    result |= 16;
  if (b <= d)
    result |= 32;
  if (c >= d)
    result |= 64;
  if (a > d)
    result |= 128;
  if (a == b)
    result |= 256;
  if (b != c)
    result |= 512;
  return result;
}

int test_icmp(void)
{
    if (test_icmp_(-1,2,0,4) != 0x2a9)
	return fail(0);
    if (test_icmp_(-1,-1,1,-1) != 0x322)
	return fail(0);
    if (test_icmp_(-1,0,3,-2) != 0x2a3)
	return fail(0);
    if (test_icmp_(-1,0,3,0) != 0x2e3)
	return fail(0);
    if (test_icmp_(-1,0,0,-1) != 0x2b)
	return fail(0);
    return 0x40000000;
}

int test_select_(int a, int b, int c)
{
  return a ? b : c;
}

int test_select(void)
{
    if(test_select_(4, 5, 6) != 5)
	return fail(0);
    if(test_select_(0, 5, 6) != 6)
	return fail(0);
    return 0x80000000;
}

