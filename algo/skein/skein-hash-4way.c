/* $Id: skein.c 254 2011-06-07 19:38:58Z tp $ */
/*
 * Skein implementation.
 *
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2007-2010  Projet RNRT SAPHIR
 * 
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 *
 * @author   Thomas Pornin <thomas.pornin@cryptolog.com>
 */

#if defined (__AVX2__)

#include <stddef.h>
#include <string.h>
#include "skein-hash-4way.h"

#ifdef __cplusplus
extern "C"{
#endif

#ifdef _MSC_VER
#pragma warning (disable: 4146)
#endif

/*
static const uint64_t IV256[] = {
   0xCCD044A12FDB3E13, 0xE83590301A79A9EB,
   0x55AEA0614F816E6F, 0x2A2767A4AE9B94DB,
   0xEC06025E74DD7683, 0xE7A436CDC4746251,
   0xC36FBAF9393AD185, 0x3EEDBA1833EDFC13
};

static const uint64_t IV512[] = {
   0x4903ADFF749C51CE, 0x0D95DE399746DF03,
   0x8FD1934127C79BCE, 0x9A255629FF352CB1,
   0x5DB62599DF6CA7B0, 0xEABE394CA9D5C3F4,
   0x991112C71A75B523, 0xAE18A40B660FCC33
};
*/
   
/*
 * M9_ ## s ## _ ## i  evaluates to s+i mod 9 (0 <= s <= 18, 0 <= i <= 7).
 */

#define M9_0_0    0
#define M9_0_1    1
#define M9_0_2    2
#define M9_0_3    3
#define M9_0_4    4
#define M9_0_5    5
#define M9_0_6    6
#define M9_0_7    7

#define M9_1_0    1
#define M9_1_1    2
#define M9_1_2    3
#define M9_1_3    4
#define M9_1_4    5
#define M9_1_5    6
#define M9_1_6    7
#define M9_1_7    8

#define M9_2_0    2
#define M9_2_1    3
#define M9_2_2    4
#define M9_2_3    5
#define M9_2_4    6
#define M9_2_5    7
#define M9_2_6    8
#define M9_2_7    0

#define M9_3_0    3
#define M9_3_1    4
#define M9_3_2    5
#define M9_3_3    6
#define M9_3_4    7
#define M9_3_5    8
#define M9_3_6    0
#define M9_3_7    1

#define M9_4_0    4
#define M9_4_1    5
#define M9_4_2    6
#define M9_4_3    7
#define M9_4_4    8
#define M9_4_5    0
#define M9_4_6    1
#define M9_4_7    2

#define M9_5_0    5
#define M9_5_1    6
#define M9_5_2    7
#define M9_5_3    8
#define M9_5_4    0
#define M9_5_5    1
#define M9_5_6    2
#define M9_5_7    3

#define M9_6_0    6
#define M9_6_1    7
#define M9_6_2    8
#define M9_6_3    0
#define M9_6_4    1
#define M9_6_5    2
#define M9_6_6    3
#define M9_6_7    4

#define M9_7_0    7
#define M9_7_1    8
#define M9_7_2    0
#define M9_7_3    1
#define M9_7_4    2
#define M9_7_5    3
#define M9_7_6    4
#define M9_7_7    5

#define M9_8_0    8
#define M9_8_1    0
#define M9_8_2    1
#define M9_8_3    2
#define M9_8_4    3
#define M9_8_5    4
#define M9_8_6    5
#define M9_8_7    6

#define M9_9_0    0
#define M9_9_1    1
#define M9_9_2    2
#define M9_9_3    3
#define M9_9_4    4
#define M9_9_5    5
#define M9_9_6    6
#define M9_9_7    7

#define M9_10_0   1
#define M9_10_1   2
#define M9_10_2   3
#define M9_10_3   4
#define M9_10_4   5
#define M9_10_5   6
#define M9_10_6   7
#define M9_10_7   8

#define M9_11_0   2
#define M9_11_1   3
#define M9_11_2   4
#define M9_11_3   5
#define M9_11_4   6
#define M9_11_5   7
#define M9_11_6   8
#define M9_11_7   0

#define M9_12_0   3
#define M9_12_1   4
#define M9_12_2   5
#define M9_12_3   6
#define M9_12_4   7
#define M9_12_5   8
#define M9_12_6   0
#define M9_12_7   1

#define M9_13_0   4
#define M9_13_1   5
#define M9_13_2   6
#define M9_13_3   7
#define M9_13_4   8
#define M9_13_5   0
#define M9_13_6   1
#define M9_13_7   2

#define M9_14_0   5
#define M9_14_1   6
#define M9_14_2   7
#define M9_14_3   8
#define M9_14_4   0
#define M9_14_5   1
#define M9_14_6   2
#define M9_14_7   3

#define M9_15_0   6
#define M9_15_1   7
#define M9_15_2   8
#define M9_15_3   0
#define M9_15_4   1
#define M9_15_5   2
#define M9_15_6   3
#define M9_15_7   4

#define M9_16_0   7
#define M9_16_1   8
#define M9_16_2   0
#define M9_16_3   1
#define M9_16_4   2
#define M9_16_5   3
#define M9_16_6   4
#define M9_16_7   5

#define M9_17_0   8
#define M9_17_1   0
#define M9_17_2   1
#define M9_17_3   2
#define M9_17_4   3
#define M9_17_5   4
#define M9_17_6   5
#define M9_17_7   6

#define M9_18_0   0
#define M9_18_1   1
#define M9_18_2   2
#define M9_18_3   3
#define M9_18_4   4
#define M9_18_5   5
#define M9_18_6   6
#define M9_18_7   7

/*
 * M3_ ## s ## _ ## i  evaluates to s+i mod 3 (0 <= s <= 18, 0 <= i <= 1).
 */

#define M3_0_0    0
#define M3_0_1    1
#define M3_1_0    1
#define M3_1_1    2
#define M3_2_0    2
#define M3_2_1    0
#define M3_3_0    0
#define M3_3_1    1
#define M3_4_0    1
#define M3_4_1    2
#define M3_5_0    2
#define M3_5_1    0
#define M3_6_0    0
#define M3_6_1    1
#define M3_7_0    1
#define M3_7_1    2
#define M3_8_0    2
#define M3_8_1    0
#define M3_9_0    0
#define M3_9_1    1
#define M3_10_0   1
#define M3_10_1   2
#define M3_11_0   2
#define M3_11_1   0
#define M3_12_0   0
#define M3_12_1   1
#define M3_13_0   1
#define M3_13_1   2
#define M3_14_0   2
#define M3_14_1   0
#define M3_15_0   0
#define M3_15_1   1
#define M3_16_0   1
#define M3_16_1   2
#define M3_17_0   2
#define M3_17_1   0
#define M3_18_0   0
#define M3_18_1   1

#define XCAT(x, y)     XCAT_(x, y)
#define XCAT_(x, y)    x ## y


#define SKBI(k, s, i)   XCAT(k, XCAT(XCAT(XCAT(M9_, s), _), i))
#define SKBT(t, s, v)   XCAT(t, XCAT(XCAT(XCAT(M3_, s), _), v))

#define READ_STATE_BIG(sc)   do { \
      h0 = (sc)->h0; \
      h1 = (sc)->h1; \
      h2 = (sc)->h2; \
      h3 = (sc)->h3; \
      h4 = (sc)->h4; \
      h5 = (sc)->h5; \
      h6 = (sc)->h6; \
      h7 = (sc)->h7; \
      bcount = sc->bcount; \
   } while (0)

#define WRITE_STATE_BIG(sc)   do { \
      (sc)->h0 = h0; \
      (sc)->h1 = h1; \
      (sc)->h2 = h2; \
      (sc)->h3 = h3; \
      (sc)->h4 = h4; \
      (sc)->h5 = h5; \
      (sc)->h6 = h6; \
      (sc)->h7 = h7; \
      sc->bcount = bcount; \
   } while (0)
   

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

#define TFBIG_KINIT_8WAY( k0, k1, k2, k3, k4, k5, k6, k7, k8, t0, t1, t2 ) \
do { \
  k8 = mm512_xor3( mm512_xor3( k0, k1, k2 ), mm512_xor3( k3, k4, k5 ), \
                   mm512_xor3( k6, k7, m512_const1_64( 0x1BD11BDAA9FC1A22) ));\
  t2 = t0 ^ t1; \
} while (0)

#define TFBIG_ADDKEY_8WAY(w0, w1, w2, w3, w4, w5, w6, w7, k, t, s) \
do { \
  w0 = _mm512_add_epi64( w0, SKBI(k,s,0) ); \
  w1 = _mm512_add_epi64( w1, SKBI(k,s,1) ); \
  w2 = _mm512_add_epi64( w2, SKBI(k,s,2) ); \
  w3 = _mm512_add_epi64( w3, SKBI(k,s,3) ); \
  w4 = _mm512_add_epi64( w4, SKBI(k,s,4) ); \
  w5 = _mm512_add_epi64( w5, _mm512_add_epi64( SKBI(k,s,5), \
                                         m512_const1_64( SKBT(t,s,0) ) ) ); \
  w6 = _mm512_add_epi64( w6, _mm512_add_epi64( SKBI(k,s,6), \
                                         m512_const1_64( SKBT(t,s,1) ) ) ); \
  w7 = _mm512_add_epi64( w7, _mm512_add_epi64( SKBI(k,s,7), \
                                         m512_const1_64( s ) ) ); \
} while (0)

#define TFBIG_MIX_8WAY(x0, x1, rc) \
do { \
     x0 = _mm512_add_epi64( x0, x1 ); \
     x1 = _mm512_xor_si512( mm512_rol_64( x1, rc ), x0 ); \
} while (0)

#define TFBIG_MIX8_8WAY(w0, w1, w2, w3, w4, w5, w6, w7, rc0, rc1, rc2, rc3)  do { \
      TFBIG_MIX_8WAY(w0, w1, rc0); \
      TFBIG_MIX_8WAY(w2, w3, rc1); \
      TFBIG_MIX_8WAY(w4, w5, rc2); \
      TFBIG_MIX_8WAY(w6, w7, rc3); \
   } while (0)

#define TFBIG_8WAY_4e(s)   do { \
      TFBIG_ADDKEY_8WAY(p0, p1, p2, p3, p4, p5, p6, p7, h, t, s); \
      TFBIG_MIX8_8WAY(p0, p1, p2, p3, p4, p5, p6, p7, 46, 36, 19, 37); \
      TFBIG_MIX8_8WAY(p2, p1, p4, p7, p6, p5, p0, p3, 33, 27, 14, 42); \
      TFBIG_MIX8_8WAY(p4, p1, p6, p3, p0, p5, p2, p7, 17, 49, 36, 39); \
      TFBIG_MIX8_8WAY(p6, p1, p0, p7, p2, p5, p4, p3, 44,  9, 54, 56); \
   } while (0)

#define TFBIG_8WAY_4o(s)   do { \
      TFBIG_ADDKEY_8WAY(p0, p1, p2, p3, p4, p5, p6, p7, h, t, s); \
      TFBIG_MIX8_8WAY(p0, p1, p2, p3, p4, p5, p6, p7, 39, 30, 34, 24); \
      TFBIG_MIX8_8WAY(p2, p1, p4, p7, p6, p5, p0, p3, 13, 50, 10, 17); \
      TFBIG_MIX8_8WAY(p4, p1, p6, p3, p0, p5, p2, p7, 25, 29, 39, 43); \
      TFBIG_MIX8_8WAY(p6, p1, p0, p7, p2, p5, p4, p3,  8, 35, 56, 22); \
   } while (0)

#define UBI_BIG_8WAY(etype, extra) \
do { \
  uint64_t t0, t1, t2; \
  __m512i h8; \
  __m512i m0 =  buf[0]; \
  __m512i m1 =  buf[1]; \
  __m512i m2 =  buf[2]; \
  __m512i m3 =  buf[3]; \
  __m512i m4 =  buf[4]; \
  __m512i m5 =  buf[5]; \
  __m512i m6 =  buf[6]; \
  __m512i m7 =  buf[7]; \
\
  __m512i p0 = m0; \
  __m512i p1 = m1; \
  __m512i p2 = m2; \
  __m512i p3 = m3; \
  __m512i p4 = m4; \
  __m512i p5 = m5; \
  __m512i p6 = m6; \
  __m512i p7 = m7; \
  t0 = (uint64_t)(bcount << 6) + (uint64_t)(extra); \
  t1 = (bcount >> 58) + ((uint64_t)(etype) << 55); \
  TFBIG_KINIT_8WAY(h0, h1, h2, h3, h4, h5, h6, h7, h8, t0, t1, t2); \
  TFBIG_8WAY_4e(0); \
  TFBIG_8WAY_4o(1); \
  TFBIG_8WAY_4e(2); \
  TFBIG_8WAY_4o(3); \
  TFBIG_8WAY_4e(4); \
  TFBIG_8WAY_4o(5); \
  TFBIG_8WAY_4e(6); \
  TFBIG_8WAY_4o(7); \
  TFBIG_8WAY_4e(8); \
  TFBIG_8WAY_4o(9); \
  TFBIG_8WAY_4e(10); \
  TFBIG_8WAY_4o(11); \
  TFBIG_8WAY_4e(12); \
  TFBIG_8WAY_4o(13); \
  TFBIG_8WAY_4e(14); \
  TFBIG_8WAY_4o(15); \
  TFBIG_8WAY_4e(16); \
  TFBIG_8WAY_4o(17); \
  TFBIG_ADDKEY_8WAY(p0, p1, p2, p3, p4, p5, p6, p7, h, t, 18); \
  h0 = _mm512_xor_si512( m0, p0 );\
  h1 = _mm512_xor_si512( m1, p1 );\
  h2 = _mm512_xor_si512( m2, p2 );\
  h3 = _mm512_xor_si512( m3, p3 );\
  h4 = _mm512_xor_si512( m4, p4 );\
  h5 = _mm512_xor_si512( m5, p5 );\
  h6 = _mm512_xor_si512( m6, p6 );\
  h7 = _mm512_xor_si512( m7, p7 );\
} while (0)

#define DECL_STATE_BIG_8WAY \
  __m512i h0, h1, h2, h3, h4, h5, h6, h7; \
  uint64_t bcount;


#endif // AVX512

#define TFBIG_KINIT_4WAY( k0, k1, k2, k3, k4, k5, k6, k7, k8, t0, t1, t2 ) \
do { \
  k8 = _mm256_xor_si256( _mm256_xor_si256( \
                            _mm256_xor_si256( _mm256_xor_si256( k0, k1 ), \
                                              _mm256_xor_si256( k2, k3 ) ), \
                            _mm256_xor_si256( _mm256_xor_si256( k4, k5 ), \
                                              _mm256_xor_si256( k6, k7 ) ) ), \
                         m256_const1_64( 0x1BD11BDAA9FC1A22) ); \
  t2 = t0 ^ t1; \
} while (0)

#define TFBIG_ADDKEY_4WAY(w0, w1, w2, w3, w4, w5, w6, w7, k, t, s) \
do { \
  w0 = _mm256_add_epi64( w0, SKBI(k,s,0) ); \
  w1 = _mm256_add_epi64( w1, SKBI(k,s,1) ); \
  w2 = _mm256_add_epi64( w2, SKBI(k,s,2) ); \
  w3 = _mm256_add_epi64( w3, SKBI(k,s,3) ); \
  w4 = _mm256_add_epi64( w4, SKBI(k,s,4) ); \
  w5 = _mm256_add_epi64( w5, _mm256_add_epi64( SKBI(k,s,5), \
                                         m256_const1_64( SKBT(t,s,0) ) ) ); \
  w6 = _mm256_add_epi64( w6, _mm256_add_epi64( SKBI(k,s,6), \
                                         m256_const1_64( SKBT(t,s,1) ) ) ); \
  w7 = _mm256_add_epi64( w7, _mm256_add_epi64( SKBI(k,s,7), \
                                         m256_const1_64( s ) ) ); \
} while (0)

#define TFBIG_MIX_4WAY(x0, x1, rc) \
do { \
     x0 = _mm256_add_epi64( x0, x1 ); \
     x1 = _mm256_xor_si256( mm256_rol_64( x1, rc ), x0 ); \
} while (0)

#define TFBIG_MIX8_4WAY(w0, w1, w2, w3, w4, w5, w6, w7, rc0, rc1, rc2, rc3)  do { \
      TFBIG_MIX_4WAY(w0, w1, rc0); \
      TFBIG_MIX_4WAY(w2, w3, rc1); \
      TFBIG_MIX_4WAY(w4, w5, rc2); \
      TFBIG_MIX_4WAY(w6, w7, rc3); \
   } while (0)

#define TFBIG_4WAY_4e(s)   do { \
      TFBIG_ADDKEY_4WAY(p0, p1, p2, p3, p4, p5, p6, p7, h, t, s); \
      TFBIG_MIX8_4WAY(p0, p1, p2, p3, p4, p5, p6, p7, 46, 36, 19, 37); \
      TFBIG_MIX8_4WAY(p2, p1, p4, p7, p6, p5, p0, p3, 33, 27, 14, 42); \
      TFBIG_MIX8_4WAY(p4, p1, p6, p3, p0, p5, p2, p7, 17, 49, 36, 39); \
      TFBIG_MIX8_4WAY(p6, p1, p0, p7, p2, p5, p4, p3, 44,  9, 54, 56); \
   } while (0)

#define TFBIG_4WAY_4o(s)   do { \
      TFBIG_ADDKEY_4WAY(p0, p1, p2, p3, p4, p5, p6, p7, h, t, s); \
      TFBIG_MIX8_4WAY(p0, p1, p2, p3, p4, p5, p6, p7, 39, 30, 34, 24); \
      TFBIG_MIX8_4WAY(p2, p1, p4, p7, p6, p5, p0, p3, 13, 50, 10, 17); \
      TFBIG_MIX8_4WAY(p4, p1, p6, p3, p0, p5, p2, p7, 25, 29, 39, 43); \
      TFBIG_MIX8_4WAY(p6, p1, p0, p7, p2, p5, p4, p3,  8, 35, 56, 22); \
   } while (0)

// scale buf offset by 4
#define UBI_BIG_4WAY(etype, extra) \
do { \
  uint64_t t0, t1, t2; \
  __m256i h8; \
  __m256i m0 =  buf[0]; \
  __m256i m1 =  buf[1]; \
  __m256i m2 =  buf[2]; \
  __m256i m3 =  buf[3]; \
  __m256i m4 =  buf[4]; \
  __m256i m5 =  buf[5]; \
  __m256i m6 =  buf[6]; \
  __m256i m7 =  buf[7]; \
\
  __m256i p0 = m0; \
  __m256i p1 = m1; \
  __m256i p2 = m2; \
  __m256i p3 = m3; \
  __m256i p4 = m4; \
  __m256i p5 = m5; \
  __m256i p6 = m6; \
  __m256i p7 = m7; \
  t0 = (uint64_t)(bcount << 6) + (uint64_t)(extra); \
  t1 = (bcount >> 58) + ((uint64_t)(etype) << 55); \
  TFBIG_KINIT_4WAY(h0, h1, h2, h3, h4, h5, h6, h7, h8, t0, t1, t2); \
  TFBIG_4WAY_4e(0); \
  TFBIG_4WAY_4o(1); \
  TFBIG_4WAY_4e(2); \
  TFBIG_4WAY_4o(3); \
  TFBIG_4WAY_4e(4); \
  TFBIG_4WAY_4o(5); \
  TFBIG_4WAY_4e(6); \
  TFBIG_4WAY_4o(7); \
  TFBIG_4WAY_4e(8); \
  TFBIG_4WAY_4o(9); \
  TFBIG_4WAY_4e(10); \
  TFBIG_4WAY_4o(11); \
  TFBIG_4WAY_4e(12); \
  TFBIG_4WAY_4o(13); \
  TFBIG_4WAY_4e(14); \
  TFBIG_4WAY_4o(15); \
  TFBIG_4WAY_4e(16); \
  TFBIG_4WAY_4o(17); \
  TFBIG_ADDKEY_4WAY(p0, p1, p2, p3, p4, p5, p6, p7, h, t, 18); \
  h0 = _mm256_xor_si256( m0, p0 );\
  h1 = _mm256_xor_si256( m1, p1 );\
  h2 = _mm256_xor_si256( m2, p2 );\
  h3 = _mm256_xor_si256( m3, p3 );\
  h4 = _mm256_xor_si256( m4, p4 );\
  h5 = _mm256_xor_si256( m5, p5 );\
  h6 = _mm256_xor_si256( m6, p6 );\
  h7 = _mm256_xor_si256( m7, p7 );\
} while (0)


#define DECL_STATE_BIG_4WAY \
  __m256i h0, h1, h2, h3, h4, h5, h6, h7; \
  uint64_t bcount;

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

void skein256_8way_init( skein256_8way_context *sc )
{
        sc->h0 = m512_const1_64( 0xCCD044A12FDB3E13 );
        sc->h1 = m512_const1_64( 0xE83590301A79A9EB );
        sc->h2 = m512_const1_64( 0x55AEA0614F816E6F );
        sc->h3 = m512_const1_64( 0x2A2767A4AE9B94DB );
        sc->h4 = m512_const1_64( 0xEC06025E74DD7683 );
        sc->h5 = m512_const1_64( 0xE7A436CDC4746251 );
        sc->h6 = m512_const1_64( 0xC36FBAF9393AD185 );
        sc->h7 = m512_const1_64( 0x3EEDBA1833EDFC13 );
        sc->bcount = 0;
        sc->ptr = 0;
}

void skein512_8way_init( skein512_8way_context *sc )
{
        sc->h0 = m512_const1_64( 0x4903ADFF749C51CE );
        sc->h1 = m512_const1_64( 0x0D95DE399746DF03 );
        sc->h2 = m512_const1_64( 0x8FD1934127C79BCE );
        sc->h3 = m512_const1_64( 0x9A255629FF352CB1 );
        sc->h4 = m512_const1_64( 0x5DB62599DF6CA7B0 );
        sc->h5 = m512_const1_64( 0xEABE394CA9D5C3F4 );
        sc->h6 = m512_const1_64( 0x991112C71A75B523 );
        sc->h7 = m512_const1_64( 0xAE18A40B660FCC33 );
        sc->bcount = 0;
        sc->ptr = 0;
}

static void
skein_big_core_8way( skein512_8way_context *sc, const void *data,
                     size_t len )
{
   __m512i *vdata = (__m512i*)data;
   __m512i *buf;
   size_t ptr;
   unsigned first;
   DECL_STATE_BIG_8WAY

   buf = sc->buf;
   ptr = sc->ptr;
   const int buf_size = 64;   // 64 * _m256i

   if ( len <= buf_size - ptr )
   {
       memcpy_512( buf + (ptr>>3), vdata, len>>3 );
       sc->ptr = ptr + len;
       return;
   }

   READ_STATE_BIG( sc );
   first = ( bcount == 0 ) << 7;
   do {
       size_t clen;

       if ( ptr == buf_size )
       {
            bcount ++;
            UBI_BIG_8WAY( 96 + first, 0 );
            first = 0;
            ptr = 0;
       }
       clen = buf_size - ptr;
       if ( clen > len )
            clen = len;
       memcpy_512( buf + (ptr>>3), vdata, clen>>3 );
       ptr += clen;
       vdata += (clen>>3);
       len -= clen;
   } while ( len > 0 );
   WRITE_STATE_BIG( sc );
   sc->ptr = ptr;
}

static void
skein_big_close_8way( skein512_8way_context *sc, unsigned ub, unsigned n,
                      void *dst, size_t out_len )
{
   __m512i *buf;
   size_t ptr;
   unsigned et;
   DECL_STATE_BIG_8WAY

   buf = sc->buf;
   ptr = sc->ptr;
        const int buf_size = 64;

   READ_STATE_BIG(sc);

   memset_zero_512( buf + (ptr>>3), (buf_size - ptr) >> 3 );
   et = 352 + ((bcount == 0) << 7);
   UBI_BIG_8WAY( et, ptr );

   memset_zero_512( buf, buf_size >> 3 );
   bcount = 0;
   UBI_BIG_8WAY( 510, 8 );

   buf[0] = h0;
   buf[1] = h1;
   buf[2] = h2;
   buf[3] = h3;
   buf[4] = h4;
   buf[5] = h5;
   buf[6] = h6;
   buf[7] = h7;

   memcpy_512( dst, buf, out_len >> 3 );
}

void skein512_8way_full( skein512_8way_context *sc, void *out, const void *data,
                     size_t len )
{
   __m512i h0, h1, h2, h3, h4, h5, h6, h7;
   __m512i *vdata = (__m512i*)data;
   __m512i *buf = sc->buf;
   size_t ptr = 0;
   unsigned first;
   uint64_t bcount = 0;
   const int buf_size = 64;   // 64 * _m256i

// Init

        h0 = m512_const1_64( 0x4903ADFF749C51CE );
        h1 = m512_const1_64( 0x0D95DE399746DF03 );
        h2 = m512_const1_64( 0x8FD1934127C79BCE );
        h3 = m512_const1_64( 0x9A255629FF352CB1 );
        h4 = m512_const1_64( 0x5DB62599DF6CA7B0 );
        h5 = m512_const1_64( 0xEABE394CA9D5C3F4 );
        h6 = m512_const1_64( 0x991112C71A75B523 );
        h7 = m512_const1_64( 0xAE18A40B660FCC33 );

// Update

   if ( len <= buf_size - ptr )
   {
       memcpy_512( buf + (ptr>>3), vdata, len>>3 );
       ptr += len;
   }
   else
   {
      first = ( bcount == 0 ) << 7;
      do {
         size_t clen;

         if ( ptr == buf_size )
         {
            bcount ++;
            UBI_BIG_8WAY( 96 + first, 0 );
            first = 0;
            ptr = 0;
         }
         clen = buf_size - ptr;
         if ( clen > len )
            clen = len;
         memcpy_512( buf + (ptr>>3), vdata, clen>>3 );
         ptr += clen;
         vdata += (clen>>3);
         len -= clen;
      } while ( len > 0 );
   }

// Close

   unsigned et;

   memset_zero_512( buf + (ptr>>3), (buf_size - ptr) >> 3 );
   et = 352 + ((bcount == 0) << 7);
   UBI_BIG_8WAY( et, ptr );

   memset_zero_512( buf, buf_size >> 3 );
   bcount = 0;
   UBI_BIG_8WAY( 510, 8 );

   casti_m512i( out, 0 ) = h0;
   casti_m512i( out, 1 ) = h1;
   casti_m512i( out, 2 ) = h2;
   casti_m512i( out, 3 ) = h3;
   casti_m512i( out, 4 ) = h4;
   casti_m512i( out, 5 ) = h5;
   casti_m512i( out, 6 ) = h6;
   casti_m512i( out, 7 ) = h7;
}

void
skein512_8way_prehash64( skein512_8way_context *sc, const void *data )
{
   __m512i *vdata = (__m512i*)data;
   __m512i *buf = sc->buf;
   buf[0] = vdata[0];
   buf[1] = vdata[1];
   buf[2] = vdata[2];
   buf[3] = vdata[3];
   buf[4] = vdata[4];
   buf[5] = vdata[5];
   buf[6] = vdata[6];
   buf[7] = vdata[7];
   register __m512i h0 = m512_const1_64( 0x4903ADFF749C51CE );
   register __m512i h1 = m512_const1_64( 0x0D95DE399746DF03 );
   register __m512i h2 = m512_const1_64( 0x8FD1934127C79BCE );
   register __m512i h3 = m512_const1_64( 0x9A255629FF352CB1 );
   register __m512i h4 = m512_const1_64( 0x5DB62599DF6CA7B0 );
   register __m512i h5 = m512_const1_64( 0xEABE394CA9D5C3F4 );
   register __m512i h6 = m512_const1_64( 0x991112C71A75B523 );
   register __m512i h7 = m512_const1_64( 0xAE18A40B660FCC33 );
   uint64_t bcount = 1;

   UBI_BIG_8WAY( 224, 0 );
   sc->h0 = h0;
   sc->h1 = h1;
   sc->h2 = h2;
   sc->h3 = h3;
   sc->h4 = h4;
   sc->h5 = h5;
   sc->h6 = h6;
   sc->h7 = h7;
}

void
skein512_8way_final16( skein512_8way_context *sc,  void *output,
                       const void *data )
{
   __m512i *in = (__m512i*)data;
   __m512i *buf = sc->buf;
   __m512i *out = (__m512i*)output;
   register __m512i h0 = sc->h0;
   register __m512i    h1 = sc->h1;
   register __m512i    h2 = sc->h2;
   register __m512i    h3 = sc->h3;
   register __m512i    h4 = sc->h4;
   register __m512i    h5 = sc->h5;
   register __m512i    h6 = sc->h6;
   register __m512i    h7 = sc->h7;

   const __m512i zero = m512_zero;
   buf[0] = in[0];
   buf[1] = in[1];
   buf[2] = zero;
   buf[3] = zero;
   buf[4] = zero;
   buf[5] = zero;
   buf[6] = zero;
   buf[7] = zero;

   uint64_t bcount = 1;
   UBI_BIG_8WAY( 352, 16 );

   buf[0] = zero;
   buf[1] = zero;

   bcount = 0;
   UBI_BIG_8WAY( 510, 8 );

   out[0] = h0;
   out[1] = h1;
   out[2] = h2;
   out[3] = h3;
   out[4] = h4;
   out[5] = h5;
   out[6] = h6;
   out[7] = h7;
}


void
skein256_8way_update(void *cc, const void *data, size_t len)
{
   skein_big_core_8way(cc, data, len);
}

void
skein256_8way_close(void *cc, void *dst)
{
        skein_big_close_8way(cc, 0, 0, dst, 32);
}

void
skein512_8way_update(void *cc, const void *data, size_t len)
{
   skein_big_core_8way(cc, data, len);
}

void
skein512_8way_close(void *cc, void *dst)
{
        skein_big_close_8way(cc, 0, 0, dst, 64);
}

#endif // AVX512


void skein256_4way_init( skein256_4way_context *sc )
{
        sc->h0 = m256_const1_64( 0xCCD044A12FDB3E13 );
        sc->h1 = m256_const1_64( 0xE83590301A79A9EB );
        sc->h2 = m256_const1_64( 0x55AEA0614F816E6F );
        sc->h3 = m256_const1_64( 0x2A2767A4AE9B94DB );
        sc->h4 = m256_const1_64( 0xEC06025E74DD7683 );
        sc->h5 = m256_const1_64( 0xE7A436CDC4746251 );
        sc->h6 = m256_const1_64( 0xC36FBAF9393AD185 );
        sc->h7 = m256_const1_64( 0x3EEDBA1833EDFC13 );
        sc->bcount = 0;
        sc->ptr = 0;
}

void skein512_4way_init( skein512_4way_context *sc )
{
        sc->h0 = m256_const1_64( 0x4903ADFF749C51CE );
        sc->h1 = m256_const1_64( 0x0D95DE399746DF03 );
        sc->h2 = m256_const1_64( 0x8FD1934127C79BCE );
        sc->h3 = m256_const1_64( 0x9A255629FF352CB1 );
        sc->h4 = m256_const1_64( 0x5DB62599DF6CA7B0 );
        sc->h5 = m256_const1_64( 0xEABE394CA9D5C3F4 );
        sc->h6 = m256_const1_64( 0x991112C71A75B523 );
        sc->h7 = m256_const1_64( 0xAE18A40B660FCC33 );
        sc->bcount = 0;
        sc->ptr = 0;
}

// Do not use for 128 bt data length
static void
skein_big_core_4way( skein512_4way_context *sc, const void *data,
                     size_t len )
{
   __m256i *vdata = (__m256i*)data;
   __m256i *buf;
   size_t ptr;
   unsigned first;
   DECL_STATE_BIG_4WAY

   buf = sc->buf;
   ptr = sc->ptr;
   const int buf_size = 64;   // 64 * _m256i

   if ( len <= buf_size - ptr )
   {
       memcpy_256( buf + (ptr>>3), vdata, len>>3 );
       sc->ptr = ptr + len;
       if ( ptr < buf_size ) return;
   }

   READ_STATE_BIG( sc );
   first = ( bcount == 0 ) << 7;
   do {
       size_t clen;

       if ( ptr == buf_size )
       {
            bcount ++;
            UBI_BIG_4WAY( 96 + first, 0 );
            first = 0;
            ptr = 0;
       }
       clen = buf_size - ptr;
       if ( clen > len )
            clen = len;
       len -= clen;
       if ( len == 0 ) break;
       memcpy_256( buf + (ptr>>3), vdata, clen>>3 );
       ptr += clen;
       vdata += (clen>>3);
       len -= clen;
   } while ( len > 0 );
   WRITE_STATE_BIG( sc );
   sc->ptr = ptr;
}

static void
skein_big_close_4way( skein512_4way_context *sc, unsigned ub, unsigned n,
                      void *dst, size_t out_len )
{
	__m256i *buf;
	size_t ptr;
	unsigned et;
	DECL_STATE_BIG_4WAY

	buf = sc->buf;
	ptr = sc->ptr;
        const int buf_size = 64;

	READ_STATE_BIG(sc);

   if ( ptr )
   {
      memset_zero_256( buf + (ptr>>3), (buf_size - ptr) >> 3 );
	   et = 352 + ((bcount == 0) << 7);
      UBI_BIG_4WAY( et, ptr );
   }

   memset_zero_256( buf, buf_size >> 3 );
   bcount = 0;
   UBI_BIG_4WAY( 510, 8 );

   buf[0] = h0;
   buf[1] = h1;
   buf[2] = h2;
   buf[3] = h3;
   buf[4] = h4;
   buf[5] = h5;
   buf[6] = h6;
   buf[7] = h7;

   memcpy_256( dst, buf, out_len >> 3 );
}

void
skein512_4way_full( skein512_4way_context *sc, void *out, const void *data,
                     size_t len )
{
   __m256i h0, h1, h2, h3, h4, h5, h6, h7;
   __m256i *vdata = (__m256i*)data;
   __m256i *buf = sc->buf;
   size_t ptr = 0;
   unsigned first;
   const int buf_size = 64;   // 64 * __m256i
   uint64_t bcount = 0;

   h0 = m256_const1_64( 0x4903ADFF749C51CE );
   h1 = m256_const1_64( 0x0D95DE399746DF03 );
   h2 = m256_const1_64( 0x8FD1934127C79BCE );
   h3 = m256_const1_64( 0x9A255629FF352CB1 );
   h4 = m256_const1_64( 0x5DB62599DF6CA7B0 );
   h5 = m256_const1_64( 0xEABE394CA9D5C3F4 );
   h6 = m256_const1_64( 0x991112C71A75B523 );
   h7 = m256_const1_64( 0xAE18A40B660FCC33 );

// Update     

   if ( len <= buf_size - ptr )
   {
       memcpy_256( buf + (ptr>>3), vdata, len>>3 );
       ptr += len;
   }
   else
   {
      first = ( bcount == 0 ) << 7;
      do {
         size_t clen;

         if ( ptr == buf_size )
         {
            bcount ++;
            UBI_BIG_4WAY( 96 + first, 0 );
            first = 0;
            ptr = 0;
         }
         clen = buf_size - ptr;
         if ( clen > len )
            clen = len;
         memcpy_256( buf + (ptr>>3), vdata, clen>>3 );
         ptr += clen;
         vdata += (clen>>3);
         len -= clen;
      } while ( len > 0 );
   }

// Close

   unsigned et;

   memset_zero_256( buf + (ptr>>3), (buf_size - ptr) >> 3 );
   et = 352 + ((bcount == 0) << 7);
   UBI_BIG_4WAY( et, ptr );

   memset_zero_256( buf, buf_size >> 3 );
   bcount = 0;
   UBI_BIG_4WAY( 510, 8 );

   casti_m256i( out, 0 ) = h0;
   casti_m256i( out, 1 ) = h1;
   casti_m256i( out, 2 ) = h2;
   casti_m256i( out, 3 ) = h3;
   casti_m256i( out, 4 ) = h4;
   casti_m256i( out, 5 ) = h5;
   casti_m256i( out, 6 ) = h6;
   casti_m256i( out, 7 ) = h7;
}

void
skein512_4way_prehash64( skein512_4way_context *sc, const void *data )
{
   __m256i *vdata = (__m256i*)data;
   __m256i *buf = sc->buf;
   buf[0] = vdata[0];
   buf[1] = vdata[1];
   buf[2] = vdata[2];
   buf[3] = vdata[3];
   buf[4] = vdata[4];
   buf[5] = vdata[5];
   buf[6] = vdata[6];
   buf[7] = vdata[7];
   register __m256i h0 = m256_const1_64( 0x4903ADFF749C51CE );
   register __m256i h1 = m256_const1_64( 0x0D95DE399746DF03 );
   register __m256i h2 = m256_const1_64( 0x8FD1934127C79BCE );
   register __m256i h3 = m256_const1_64( 0x9A255629FF352CB1 );
   register __m256i h4 = m256_const1_64( 0x5DB62599DF6CA7B0 );
   register __m256i h5 = m256_const1_64( 0xEABE394CA9D5C3F4 );
   register __m256i h6 = m256_const1_64( 0x991112C71A75B523 );
   register __m256i h7 = m256_const1_64( 0xAE18A40B660FCC33 );
   uint64_t bcount = 1;

   UBI_BIG_4WAY( 224, 0 );
   sc->h0 = h0;
   sc->h1 = h1;
   sc->h2 = h2;
   sc->h3 = h3;
   sc->h4 = h4;
   sc->h5 = h5;
   sc->h6 = h6;
   sc->h7 = h7;
}

void
skein512_4way_final16( skein512_4way_context *sc,  void *out, const void *data )
{
   __m256i *vdata = (__m256i*)data;
   __m256i *buf = sc->buf;
   register __m256i h0 = sc->h0;
   register __m256i    h1 = sc->h1;
   register __m256i    h2 = sc->h2;
   register __m256i    h3 = sc->h3;
   register __m256i    h4 = sc->h4;
   register __m256i    h5 = sc->h5;
   register __m256i    h6 = sc->h6;
   register __m256i    h7 = sc->h7;

   const __m256i zero = m256_zero;
   buf[0] = vdata[0];
   buf[1] = vdata[1];
   buf[2] = zero;
   buf[3] = zero;
   buf[4] = zero;
   buf[5] = zero;
   buf[6] = zero;
   buf[7] = zero;

   uint64_t bcount = 1;
   UBI_BIG_4WAY( 352, 16 );

   buf[0] = zero;
   buf[1] = zero;

   bcount = 0;
   UBI_BIG_4WAY( 510, 8 );

   casti_m256i( out, 0 ) = h0;
   casti_m256i( out, 1 ) = h1;
   casti_m256i( out, 2 ) = h2;
   casti_m256i( out, 3 ) = h3;
   casti_m256i( out, 4 ) = h4;
   casti_m256i( out, 5 ) = h5;
   casti_m256i( out, 6 ) = h6;
   casti_m256i( out, 7 ) = h7;
}

// Broken for 80 bytes, use prehash.
void
skein256_4way_update(void *cc, const void *data, size_t len)
{
	skein_big_core_4way(cc, data, len);
}

void
skein256_4way_close(void *cc, void *dst)
{
        skein_big_close_4way(cc, 0, 0, dst, 32);
}



// Do not use with 128 bit data
void
skein512_4way_update(void *cc, const void *data, size_t len)
{
	skein_big_core_4way(cc, data, len);
}

void
skein512_4way_close(void *cc, void *dst)
{
        skein_big_close_4way(cc, 0, 0, dst, 64);
}

#ifdef __cplusplus
}
#endif

#endif
