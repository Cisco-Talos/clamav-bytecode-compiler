/*===---- smmintrin.h - SSE intrinsics -------------------------------------===
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
* THE SOFTWARE.
*
*===-----------------------------------------------------------------------===
*/

#ifndef _SMMINTRIN_H
#define _SMMINTRIN_H

#ifndef __SSE4_1__
#error "SSE4.1 instruction set not enabled"
#else

#include <tmmintrin.h>

/* Type defines.  */
typedef double __v2df __attribute__ ((__vector_size__ (16)));
typedef long long __v2di __attribute__ ((__vector_size__ (16)));

/* SSE4 Rounding macros. */
#define _MM_FROUND_TO_NEAREST_INT    0x00
#define _MM_FROUND_TO_NEG_INF        0x01
#define _MM_FROUND_TO_POS_INF        0x02
#define _MM_FROUND_TO_ZERO           0x03
#define _MM_FROUND_CUR_DIRECTION     0x04

#define _MM_FROUND_RAISE_EXC         0x00
#define _MM_FROUND_NO_EXC            0x08

#define _MM_FROUND_NINT      (_MM_FROUND_RAISE_EXC | _MM_FROUND_TO_NEAREST_INT)
#define _MM_FROUND_FLOOR     (_MM_FROUND_RAISE_EXC | _MM_FROUND_TO_NEG_INF)
#define _MM_FROUND_CEIL      (_MM_FROUND_RAISE_EXC | _MM_FROUND_TO_POS_INF)
#define _MM_FROUND_TRUNC     (_MM_FROUND_RAISE_EXC | _MM_FROUND_TO_ZERO)
#define _MM_FROUND_RINT      (_MM_FROUND_RAISE_EXC | _MM_FROUND_CUR_DIRECTION)
#define _MM_FROUND_NEARBYINT (_MM_FROUND_NO_EXC | _MM_FROUND_CUR_DIRECTION)

#define _mm_ceil_ps(X)       _mm_round_ps((X), _MM_FROUND_CEIL)
#define _mm_ceil_pd(X)       _mm_round_pd((X), _MM_FROUND_CEIL)
#define _mm_ceil_ss(X, Y)    _mm_round_ss((X), (Y), _MM_FROUND_CEIL)
#define _mm_ceil_sd(X, Y)    _mm_round_sd((X), (Y), _MM_FROUND_CEIL)

#define _mm_floor_ps(X)      _mm_round_ps((X), _MM_FROUND_FLOOR)
#define _mm_floor_pd(X)      _mm_round_pd((X), _MM_FROUND_FLOOR)
#define _mm_floor_ss(X, Y)   _mm_round_ss((X), (Y), _MM_FROUND_FLOOR)
#define _mm_floor_sd(X, Y)   _mm_round_sd((X), (Y), _MM_FROUND_FLOOR)

#define _mm_round_ps(X, Y)      __builtin_ia32_roundps((X), (Y))
#define _mm_round_ss(X, Y, M)   __builtin_ia32_roundss((X), (Y), (M))
#define _mm_round_pd(X, M)      __builtin_ia32_roundpd((X), (M))
#define _mm_round_sd(X, Y, M)   __builtin_ia32_roundsd((X), (Y), (M))

/* SSE4 Packed Blending Intrinsics.  */
static inline __m128d __attribute__((__always_inline__, __nodebug__))
_mm_blend_pd (__m128d __V1, __m128d __V2, const int __M)
{
  return (__m128d) __builtin_ia32_blendpd ((__v2df)__V1, (__v2df)__V2, __M);
}

static inline __m128 __attribute__((__always_inline__, __nodebug__))
_mm_blend_ps (__m128 __V1, __m128 __V2, const int __M)
{
  return (__m128) __builtin_ia32_blendps ((__v4sf)__V1, (__v4sf)__V2, __M);
}

static inline __m128d __attribute__((__always_inline__, __nodebug__))
_mm_blendv_pd (__m128d __V1, __m128d __V2, __m128d __M)
{
  return (__m128d) __builtin_ia32_blendvpd ((__v2df)__V1, (__v2df)__V2,
                                            (__v2df)__M);
}

static inline __m128 __attribute__((__always_inline__, __nodebug__))
_mm_blendv_ps (__m128 __V1, __m128 __V2, __m128 __M)
{
  return (__m128) __builtin_ia32_blendvps ((__v4sf)__V1, (__v4sf)__V2,
                                           (__v4sf)__M);
}

static inline __m128i __attribute__((__always_inline__, __nodebug__))
_mm_blendv_epi8 (__m128i __V1, __m128i __V2, __m128i __M)
{
  return (__m128i) __builtin_ia32_pblendvb128 ((__v16qi)__V1, (__v16qi)__V2,
                                               (__v16qi)__M);
}

static inline  __m128i __attribute__((__always_inline__, __nodebug__))
_mm_blend_epi16 (__m128i __V1, __m128i __V2, const int __M)
{
  return (__m128i) __builtin_ia32_pblendw128 ((__v8hi)__V1, (__v8hi)__V2, __M);
}

/* SSE4 Dword Multiply Instructions.  */
static inline  __m128i __attribute__((__always_inline__, __nodebug__))
_mm_mullo_epi32 (__m128i __V1, __m128i __V2)
{
  return (__m128i) __builtin_ia32_pmulld128((__v4si)__V1, (__v4si)__V2);
}

static inline  __m128i __attribute__((__always_inline__, __nodebug__))
_mm_mul_epi32 (__m128i __V1, __m128i __V2)
{
  return (__m128i) __builtin_ia32_pmuldq128 ((__v4si)__V1, (__v4si)__V2);
}

/* SSE4 Floating Point Dot Product Instructions.  */
#define _mm_dp_ps(X, Y, M) __builtin_ia32_dpps ((X), (Y), (M))
#define _mm_dp_pd(X, Y, M) __builtin_ia32_dppd ((X), (Y), (M))

/* SSE4 Streaming Load Hint Instruction.  */
static inline  __m128i __attribute__((__always_inline__, __nodebug__))
_mm_stream_load_si128 (__m128i *__V)
{
  return (__m128i) __builtin_ia32_movntdqa ((__v2di *) __V);
}

/* SSE4 Packed Integer Min/Max Instructions.  */
static inline  __m128i __attribute__((__always_inline__, __nodebug__))
_mm_min_epi8 (__m128i __V1, __m128i __V2)
{
  return (__m128i) __builtin_ia32_pminsb128 ((__v16qi) __V1, (__v16qi) __V2);
}

static inline  __m128i __attribute__((__always_inline__, __nodebug__))
_mm_max_epi8 (__m128i __V1, __m128i __V2)
{
  return (__m128i) __builtin_ia32_pmaxsb128 ((__v16qi) __V1, (__v16qi) __V2);
}

static inline  __m128i __attribute__((__always_inline__, __nodebug__))
_mm_min_epu16 (__m128i __V1, __m128i __V2)
{
  return (__m128i) __builtin_ia32_pminuw128 ((__v8hi) __V1, (__v8hi) __V2);
}

static inline  __m128i __attribute__((__always_inline__, __nodebug__))
_mm_max_epu16 (__m128i __V1, __m128i __V2)
{
  return (__m128i) __builtin_ia32_pmaxuw128 ((__v8hi) __V1, (__v8hi) __V2);
}

static inline  __m128i __attribute__((__always_inline__, __nodebug__))
_mm_min_epi32 (__m128i __V1, __m128i __V2)
{
  return (__m128i) __builtin_ia32_pminsd128 ((__v4si) __V1, (__v4si) __V2);
}

static inline  __m128i __attribute__((__always_inline__, __nodebug__))
_mm_max_epi32 (__m128i __V1, __m128i __V2)
{
  return (__m128i) __builtin_ia32_pmaxsd128 ((__v4si) __V1, (__v4si) __V2);
}

static inline  __m128i __attribute__((__always_inline__, __nodebug__))
_mm_min_epu32 (__m128i __V1, __m128i __V2)
{
  return (__m128i) __builtin_ia32_pminud128((__v4si) __V1, (__v4si) __V2);
}

static inline  __m128i __attribute__((__always_inline__, __nodebug__))
_mm_max_epu32 (__m128i __V1, __m128i __V2)
{
  return (__m128i) __builtin_ia32_pmaxud128((__v4si) __V1, (__v4si) __V2);
}

/* SSE4 Insertion and Extraction from XMM Register Instructions.  */
#define _mm_insert_ps(X, Y, N) __builtin_ia32_insertps128((X), (Y), (N))
#define _mm_extract_ps(X, N) (__extension__                      \
                              ({ union { int i; float f; } __t;  \
                                 __v4sf __a = (__v4sf)X;         \
                                 __t.f = __a[N];                 \
                                 __t.i;}))

/* Miscellaneous insert and extract macros.  */
/* Extract a single-precision float from X at index N into D.  */
#define _MM_EXTRACT_FLOAT(D, X, N) (__extension__ ({ __v4sf __a = (__v4sf)X; \
                                                    (D) = __a[N]; }))
                                                    
/* Or together 2 sets of indexes (X and Y) with the zeroing bits (Z) to create
   an index suitable for _mm_insert_ps.  */
#define _MM_MK_INSERTPS_NDX(X, Y, Z) (((X) << 6) | ((Y) << 4) | (Z))
                                           
/* Extract a float from X at index N into the first index of the return.  */
#define _MM_PICK_OUT_PS(X, N) _mm_insert_ps (_mm_setzero_ps(), (X),   \
                                             _MM_MK_INSERTPS_NDX((N), 0, 0x0e))
                                             
/* Insert int into packed integer array at index.  */
#define _mm_insert_epi8(X, I, N) (__extension__ ({ __v16qi __a = (__v16qi)X; \
                                                   __a[N] = I;               \
                                                   __a;}))
#define _mm_insert_epi32(X, I, N) (__extension__ ({ __v4si __a = (__v4si)X; \
                                                    __a[N] = I;             \
                                                    __a;}))
#ifdef __x86_64__
#define _mm_insert_epi64(X, I, N) (__extension__ ({ __v2di __a = (__v2di)X; \
                                                    __a[N] = I;             \
                                                    __a;}))
#endif /* __x86_64__ */

/* Extract int from packed integer array at index.  */
#define _mm_extract_epi8(X, N) (__extension__ ({ __v16qi __a = (__v16qi)X; \
                                                 __a[N];}))
#define _mm_extract_epi32(X, N) (__extension__ ({ __v4si __a = (__v4si)X; \
                                                  __a[N];}))
#ifdef __x86_64__
#define _mm_extract_epi64(X, N) (__extension__ ({ __v2di __a = (__v2di)X; \
                                                  __a[N];}))
#endif /* __x86_64 */

/* SSE4 128-bit Packed Integer Comparisons.  */
static inline int __attribute__((__always_inline__, __nodebug__))
_mm_testz_si128(__m128i __M, __m128i __V)
{
  return __builtin_ia32_ptestz128((__v2di)__M, (__v2di)__V);
}

static inline int __attribute__((__always_inline__, __nodebug__))
_mm_testc_si128(__m128i __M, __m128i __V)
{
  return __builtin_ia32_ptestc128((__v2di)__M, (__v2di)__V);
}

static inline int __attribute__((__always_inline__, __nodebug__))
_mm_testnzc_si128(__m128i __M, __m128i __V)
{
  return __builtin_ia32_ptestnzc128((__v2di)__M, (__v2di)__V);
}

#define _mm_test_all_ones(V) _mm_testc_si128((V), _mm_cmpeq_epi32((V), (V)))
#define _mm_test_mix_ones_zeros(M, V) _mm_testnzc_si128((M), (V))
#define _mm_test_all_zeros(M, V) _mm_testz_si128 ((V), (V))

/* SSE4 64-bit Packed Integer Comparisons.  */
static inline __m128i __attribute__((__always_inline__, __nodebug__))
_mm_cmpeq_epi64(__m128i __V1, __m128i __V2)
{
  return (__m128i) __builtin_ia32_pcmpeqq((__v2di)__V1, (__v2di)__V2);
}

/* SSE4 Packed Integer Sign-Extension.  */
static inline __m128i __attribute__((__always_inline__, __nodebug__))
_mm_cvtepi8_epi16(__m128i __V)
{
  return (__m128i) __builtin_ia32_pmovsxbw128((__v16qi) __V);
}

static inline __m128i __attribute__((__always_inline__, __nodebug__))
_mm_cvtepi8_epi32(__m128i __V)
{
  return (__m128i) __builtin_ia32_pmovsxbd128((__v16qi) __V);
}

static inline __m128i __attribute__((__always_inline__, __nodebug__))
_mm_cvtepi8_epi64(__m128i __V)
{
  return (__m128i) __builtin_ia32_pmovsxbq128((__v16qi) __V);
}

static inline __m128i __attribute__((__always_inline__, __nodebug__))
_mm_cvtepi16_epi32(__m128i __V)
{
  return (__m128i) __builtin_ia32_pmovsxwd128((__v8hi) __V); 
}

static inline __m128i __attribute__((__always_inline__, __nodebug__))
_mm_cvtepi16_epi64(__m128i __V)
{
  return (__m128i) __builtin_ia32_pmovsxwq128((__v8hi)__V);
}

static inline __m128i __attribute__((__always_inline__, __nodebug__))
_mm_cvtepi32_epi64(__m128i __V)
{
  return (__m128i) __builtin_ia32_pmovsxdq128((__v4si)__V);
}

/* SSE4 Packed Integer Zero-Extension.  */
static inline __m128i __attribute__((__always_inline__, __nodebug__))
_mm_cvtepu8_epi16(__m128i __V)
{
  return (__m128i) __builtin_ia32_pmovzxbw128((__v16qi) __V);
}

static inline __m128i __attribute__((__always_inline__, __nodebug__))
_mm_cvtepu8_epi32(__m128i __V)
{
  return (__m128i) __builtin_ia32_pmovzxbd128((__v16qi)__V);
}

static inline __m128i __attribute__((__always_inline__, __nodebug__))
_mm_cvtepu8_epi64(__m128i __V)
{
  return (__m128i) __builtin_ia32_pmovzxbq128((__v16qi)__V);
}

static inline __m128i __attribute__((__always_inline__, __nodebug__))
_mm_cvtepu16_epi32(__m128i __V)
{
  return (__m128i) __builtin_ia32_pmovzxwd128((__v8hi)__V);
}

static inline __m128i __attribute__((__always_inline__, __nodebug__))
_mm_cvtepu16_epi64(__m128i __V)
{
  return (__m128i) __builtin_ia32_pmovzxwq128((__v8hi)__V);
}

static inline __m128i __attribute__((__always_inline__, __nodebug__))
_mm_cvtepu32_epi64(__m128i __V)
{
  return (__m128i) __builtin_ia32_pmovzxdq128((__v4si)__V);
}

/* SSE4 Pack with Unsigned Saturation.  */
static inline __m128i __attribute__((__always_inline__, __nodebug__))
_mm_packus_epi32(__m128i __V1, __m128i __V2)
{
  return (__m128i) __builtin_ia32_packusdw128((__v4si)__V1, (__v4si)__V2);
}

/* SSE4 Multiple Packed Sums of Absolute Difference.  */
#define _mm_mpsadbw_epu8(X, Y, M) __builtin_ia32_mpsadbw128((X), (Y), (M))

#endif /* __SSE4_1__ */

#endif /* _SMMINTRIN_H */
