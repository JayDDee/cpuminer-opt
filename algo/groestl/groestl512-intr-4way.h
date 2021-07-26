/* groestl-intr-aes.h     Aug 2011
 *
 * Groestl implementation with intrinsics using ssse3, sse4.1, and aes
 * instructions.
 * Author: Günther A. Roland, Martin Schläffer, Krystian Matusiewicz
 *
 * This code is placed in the public domain
 */

#if !defined(GROESTL512_INTR_4WAY_H__)
#define GROESTL512_INTR_4WAY_H__ 1
      
#include "groestl512-hash-4way.h"

#if defined(__AVX2__) && defined(__VAES__)

static const __m128i round_const_p[] __attribute__ ((aligned (64))) =
{
   { 0x7060504030201000, 0xf0e0d0c0b0a09080 },
   { 0x7161514131211101, 0xf1e1d1c1b1a19181 }, 
   { 0x7262524232221202, 0xf2e2d2c2b2a29282 },
   { 0x7363534333231303, 0xf3e3d3c3b3a39383 },
   { 0x7464544434241404, 0xf4e4d4c4b4a49484 },
   { 0x7565554535251505, 0xf5e5d5c5b5a59585 },
   { 0x7666564636261606, 0xf6e6d6c6b6a69686 },
   { 0x7767574737271707, 0xf7e7d7c7b7a79787 },
   { 0x7868584838281808, 0xf8e8d8c8b8a89888 },
   { 0x7969594939291909, 0xf9e9d9c9b9a99989 },
   { 0x7a6a5a4a3a2a1a0a, 0xfaeadacabaaa9a8a },
   { 0x7b6b5b4b3b2b1b0b, 0xfbebdbcbbbab9b8b },
   { 0x7c6c5c4c3c2c1c0c, 0xfcecdcccbcac9c8c },
   { 0x7d6d5d4d3d2d1d0d, 0xfdedddcdbdad9d8d }
};

static const __m128i round_const_q[] __attribute__ ((aligned (64))) =
{
   { 0x8f9fafbfcfdfefff, 0x0f1f2f3f4f5f6f7f },
   { 0x8e9eaebecedeeefe, 0x0e1e2e3e4e5e6e7e },
   { 0x8d9dadbdcdddedfd, 0x0d1d2d3d4d5d6d7d },
   { 0x8c9cacbcccdcecfc, 0x0c1c2c3c4c5c6c7c },
   { 0x8b9babbbcbdbebfb, 0x0b1b2b3b4b5b6b7b },
   { 0x8a9aaabacadaeafa, 0x0a1a2a3a4a5a6a7a },
   { 0x8999a9b9c9d9e9f9, 0x0919293949596979 },
   { 0x8898a8b8c8d8e8f8, 0x0818283848586878 },
   { 0x8797a7b7c7d7e7f7, 0x0717273747576777 },
   { 0x8696a6b6c6d6e6f6, 0x0616263646566676 },
   { 0x8595a5b5c5d5e5f5, 0x0515253545556575 },
   { 0x8494a4b4c4d4e4f4, 0x0414243444546474 },
   { 0x8393a3b3c3d3e3f3, 0x0313233343536373 },
   { 0x8292a2b2c2d2e2f2, 0x0212223242526272 }
};

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

static const __m512i TRANSP_MASK = { 0x0d0509010c040800, 0x0f070b030e060a02,
                                     0x1d1519111c141810, 0x1f171b131e161a12,
                                     0x2d2529212c242820, 0x2f272b232e262a22,
                                     0x3d3539313c343830, 0x3f373b333e363a32 };

static const __m512i SUBSH_MASK0 = { 0x0b0e0104070a0d00, 0x0306090c0f020508,
                                     0x1b1e1114171a1d10, 0x1316191c1f121518,
                                     0x2b2e2124272a2d20, 0x2326292c2f222528,
                                     0x3b3e3134373a3d30, 0x3336393c3f323538 };

static const __m512i SUBSH_MASK1 = { 0x0c0f0205080b0e01, 0x04070a0d00030609,
                                     0x1c1f1215181b1e11, 0x14171a1d10131619,
                                     0x2c2f2225282b2e21, 0x24272a2d20232629,
                                     0x3c3f3235383b3e31, 0x34373a3d30333639 };

static const __m512i SUBSH_MASK2 = { 0x0d000306090c0f02, 0x05080b0e0104070a,
                                     0x1d101316191c1f12, 0x15181b1e1114171a,
                                     0x2d202326292c2f22, 0x25282b2e2124272a,
                                     0x3d303336393c3f32, 0x35383b3e3134373a };

static const __m512i SUBSH_MASK3 = { 0x0e0104070a0d0003, 0x06090c0f0205080b,
                                     0x1e1114171a1d1013, 0x16191c1f1215181b,
                                     0x2e2124272a2d2023, 0x26292c2f2225282b,
                                     0x3e3134373a3d3033, 0x36393c3f3235383b };

static const __m512i SUBSH_MASK4 = { 0x0f0205080b0e0104, 0x070a0d000306090c,
                                     0x1f1215181b1e1114, 0x171a1d101316191c,
                                     0x2f2225282b2e2124, 0x272a2d202326292c,
                                     0x3f3235383b3e3134, 0x373a3d303336393c };

static const __m512i SUBSH_MASK5 = { 0x000306090c0f0205, 0x080b0e0104070a0d,
                                     0x101316191c1f1215, 0x181b1e1114171a1d,
                                     0x202326292c2f2225, 0x282b2e2124272a2d,
                                     0x303336393c3f3235, 0x383b3e3134373a3d };

static const __m512i SUBSH_MASK6 = { 0x0104070a0d000306, 0x090c0f0205080b0e,
                                     0x1114171a1d101316, 0x191c1f1215181b1e,
                                     0x2124272a2d202326, 0x292c2f2225282b2e,
                                     0x3134373a3d303336, 0x393c3f3235383b3e };

static const __m512i SUBSH_MASK7 = { 0x06090c0f0205080b, 0x0e0104070a0d0003,
                                     0x16191c1f1215181b, 0x1e1114171a1d1013,
                                     0x26292c2f2225282b, 0x2e2124272a2d2023,
                                     0x36393c3f3235383b, 0x3e3134373a3d3033 };

#define tos(a)    #a
#define tostr(a)  tos(a)

/* xmm[i] will be multiplied by 2
 * xmm[j] will be lost
 * xmm[k] has to be all 0x1b */
#define MUL2(i, j, k){\
  j = _mm512_movm_epi8( _mm512_cmpgt_epi8_mask( m512_zero, i) );\
  i = _mm512_add_epi8(i, i);\
  i = mm512_xorand( i, j, k );\
} 

 /**/

/* Yet another implementation of MixBytes.
   This time we use the formulae (3) from the paper "Byte Slicing Groestl".
   Input: a0, ..., a7
   Output: b0, ..., b7 = MixBytes(a0,...,a7).
   but we use the relations:
   t_i = a_i + a_{i+3}
   x_i = t_i + t_{i+3}
   y_i = t_i + t+{i+2} + a_{i+6}
   z_i = 2*x_i
   w_i = z_i + y_{i+4}
   v_i = 2*w_i
   b_i = v_{i+3} + y_{i+4}
   We keep building b_i in registers xmm8..xmm15 by first building y_{i+4} there
   and then adding v_i computed in the meantime in registers xmm0..xmm7.
   We almost fit into 16 registers, need only 3 spills to memory.
   This implementation costs 7.7 c/b giving total speed on SNB: 10.7c/b.
   K. Matusiewicz, 2011/05/29 */
#define MixBytes( a0, a1, a2, a3, a4, a5, a6, a7, \
                  b0, b1, b2, b3, b4, b5, b6, b7) { \
  /* t_i = a_i + a_{i+1} */\
  b6 = a0; \
  b7 = a1; \
  a0 = _mm512_xor_si512( a0, a1 ); \
  b0 = a2; \
  a1 = _mm512_xor_si512( a1, a2 ); \
  b1 = a3; \
  TEMP2 = _mm512_xor_si512( a2, a3 ); \
  b2 = a4; \
  a3 = _mm512_xor_si512( a3, a4 ); \
  b3 = a5; \
  a4 = _mm512_xor_si512( a4, a5 );\
  b4 = a6; \
  a5 = _mm512_xor_si512( a5, a6 ); \
  b5 = a7; \
  a6 = _mm512_xor_si512( a6, a7 ); \
  a7 = _mm512_xor_si512( a7, b6 ); \
  \
  /* build y4 y5 y6 ... in regs xmm8, xmm9, xmm10 by adding t_i*/\
  TEMP0 = mm512_xor3( b0, a4, a6 ); \
  /* spill values y_4, y_5 to memory */\
  TEMP1 = mm512_xor3( b1, a5, a7 ); \
  b2 = mm512_xor3( b2, a6, a0 ); \
  /* save values t0, t1, t2 to xmm8, xmm9 and memory */\
  b0 = a0; \
  b3 = mm512_xor3( b3, a7, a1 ); \
  b1 = a1; \
  b6 = mm512_xor3( b6, a4, TEMP2 ); \
  b4 = mm512_xor3( b4, a0, TEMP2 ); \
  b7 = mm512_xor3( b7, a5, a3 ); \
  b5 = mm512_xor3( b5, a1, a3 ); \
  \
  /* compute x_i = t_i + t_{i+3} */\
  a0 = _mm512_xor_si512( a0, a3 ); \
  a1 = _mm512_xor_si512( a1, a4 ); \
  a2 = _mm512_xor_si512( TEMP2, a5 ); \
  a3 = _mm512_xor_si512( a3, a6 ); \
  a4 = _mm512_xor_si512( a4, a7 ); \
  a5 = _mm512_xor_si512( a5, b0 ); \
  a6 = _mm512_xor_si512( a6, b1 ); \
  a7 = _mm512_xor_si512( a7, TEMP2 ); \
  \
  /* compute z_i : double x_i using temp xmm8 and 1B xmm9 */\
  /* compute w_i : add y_{i+4} */\
  b1 = m512_const1_64( 0x1b1b1b1b1b1b1b1b ); \
  MUL2( a0, b0, b1 ); \
  a0 = _mm512_xor_si512( a0, TEMP0 ); \
  MUL2( a1, b0, b1 ); \
  a1 = _mm512_xor_si512( a1, TEMP1 ); \
  MUL2( a2, b0, b1 ); \
  a2 = _mm512_xor_si512( a2, b2 ); \
  MUL2( a3, b0, b1 ); \
  a3 = _mm512_xor_si512( a3, b3 ); \
  MUL2( a4, b0, b1 ); \
  a4 = _mm512_xor_si512( a4, b4 ); \
  MUL2( a5, b0, b1 ); \
  a5 = _mm512_xor_si512( a5, b5 ); \
  MUL2( a6, b0, b1 ); \
  a6 = _mm512_xor_si512( a6, b6 ); \
  MUL2( a7, b0, b1 ); \
  a7 = _mm512_xor_si512( a7, b7 ); \
  \
  /* compute v_i : double w_i      */\
  /* add to y_4 y_5 .. v3, v4, ... */\
  MUL2( a0, b0, b1 ); \
  b5 = _mm512_xor_si512( b5, a0 ); \
  MUL2( a1, b0, b1 ); \
  b6 = _mm512_xor_si512( b6, a1 ); \
  MUL2( a2, b0, b1 ); \
  b7 = _mm512_xor_si512( b7, a2 ); \
  MUL2( a5, b0, b1 ); \
  b2 = _mm512_xor_si512( b2, a5 ); \
  MUL2( a6, b0, b1 ); \
  b3 = _mm512_xor_si512( b3, a6 ); \
  MUL2( a7, b0, b1 ); \
  b4 = _mm512_xor_si512( b4, a7 ); \
  MUL2( a3, b0, b1 ); \
  MUL2( a4, b0, b1 ); \
  b0 = TEMP0;\
  b1 = TEMP1;\
  b0 = _mm512_xor_si512( b0, a3 ); \
  b1 = _mm512_xor_si512( b1, a4 ); \
}/*MixBytes*/

/* one round
 * a0-a7 = input rows
 * b0-b7 = output rows
 */
#define SUBMIX(a0, a1, a2, a3, a4, a5, a6, a7, b0, b1, b2, b3, b4, b5, b6, b7){\
  /* SubBytes */\
  b0 = _mm512_xor_si512( b0, b0 );\
  a0 = _mm512_aesenclast_epi128( a0, b0 );\
  a1 = _mm512_aesenclast_epi128( a1, b0 );\
  a2 = _mm512_aesenclast_epi128( a2, b0 );\
  a3 = _mm512_aesenclast_epi128( a3, b0 );\
  a4 = _mm512_aesenclast_epi128( a4, b0 );\
  a5 = _mm512_aesenclast_epi128( a5, b0 );\
  a6 = _mm512_aesenclast_epi128( a6, b0 );\
  a7 = _mm512_aesenclast_epi128( a7, b0 );\
  /* MixBytes */\
  MixBytes(a0, a1, a2, a3, a4, a5, a6, a7, b0, b1, b2, b3, b4, b5, b6, b7);\
}

#define ROUNDS_P(){\
  uint8_t round_counter = 0;\
  for ( round_counter = 0; round_counter < 14; round_counter += 2 ) \
  { \
    /* AddRoundConstant P1024 */\
    xmm8 = _mm512_xor_si512( xmm8, m512_const1_128( \
             casti_m128i( round_const_p, round_counter ) ) ); \
    /* ShiftBytes P1024 + pre-AESENCLAST */\
    xmm8  = _mm512_shuffle_epi8( xmm8,  SUBSH_MASK0 ); \
    xmm9  = _mm512_shuffle_epi8( xmm9,  SUBSH_MASK1 );\
    xmm10 = _mm512_shuffle_epi8( xmm10, SUBSH_MASK2 );\
    xmm11 = _mm512_shuffle_epi8( xmm11, SUBSH_MASK3 );\
    xmm12 = _mm512_shuffle_epi8( xmm12, SUBSH_MASK4 );\
    xmm13 = _mm512_shuffle_epi8( xmm13, SUBSH_MASK5 );\
    xmm14 = _mm512_shuffle_epi8( xmm14, SUBSH_MASK6 );\
    xmm15 = _mm512_shuffle_epi8( xmm15, SUBSH_MASK7 );\
    /* SubBytes + MixBytes */\
    SUBMIX(xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7);\
    \
     /* AddRoundConstant P1024 */\
    xmm0 = _mm512_xor_si512( xmm0, m512_const1_128( \
             casti_m128i( round_const_p, round_counter+1 ) ) ); \
    /* ShiftBytes P1024 + pre-AESENCLAST */\
    xmm0 = _mm512_shuffle_epi8( xmm0, SUBSH_MASK0 );\
    xmm1 = _mm512_shuffle_epi8( xmm1, SUBSH_MASK1 );\
    xmm2 = _mm512_shuffle_epi8( xmm2, SUBSH_MASK2 );\
    xmm3 = _mm512_shuffle_epi8( xmm3, SUBSH_MASK3 );\
    xmm4 = _mm512_shuffle_epi8( xmm4, SUBSH_MASK4 );\
    xmm5 = _mm512_shuffle_epi8( xmm5, SUBSH_MASK5 );\
    xmm6 = _mm512_shuffle_epi8( xmm6, SUBSH_MASK6 );\
    xmm7 = _mm512_shuffle_epi8( xmm7, SUBSH_MASK7 );\
    /* SubBytes + MixBytes */\
     SUBMIX(xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15);\
  }\
}

#define ROUNDS_Q(){\
  uint8_t round_counter = 0;\
  for ( round_counter = 0; round_counter < 14; round_counter += 2) \
  { \
    /* AddRoundConstant Q1024 */\
    xmm1 = m512_neg1;\
    xmm8  = _mm512_xor_si512( xmm8,  xmm1 );\
    xmm9  = _mm512_xor_si512( xmm9,  xmm1 );\
    xmm10 = _mm512_xor_si512( xmm10, xmm1 );\
    xmm11 = _mm512_xor_si512( xmm11, xmm1 );\
    xmm12 = _mm512_xor_si512( xmm12, xmm1 );\
    xmm13 = _mm512_xor_si512( xmm13, xmm1 );\
    xmm14 = _mm512_xor_si512( xmm14, xmm1 );\
    xmm15 = _mm512_xor_si512( xmm15, m512_const1_128( \
                 casti_m128i( round_const_q, round_counter ) ) ); \
    /* ShiftBytes Q1024 + pre-AESENCLAST */\
    xmm8  = _mm512_shuffle_epi8( xmm8,  SUBSH_MASK1 );\
    xmm9  = _mm512_shuffle_epi8( xmm9,  SUBSH_MASK3 );\
    xmm10 = _mm512_shuffle_epi8( xmm10, SUBSH_MASK5 );\
    xmm11 = _mm512_shuffle_epi8( xmm11, SUBSH_MASK7 );\
    xmm12 = _mm512_shuffle_epi8( xmm12, SUBSH_MASK0 );\
    xmm13 = _mm512_shuffle_epi8( xmm13, SUBSH_MASK2 );\
    xmm14 = _mm512_shuffle_epi8( xmm14, SUBSH_MASK4 );\
    xmm15 = _mm512_shuffle_epi8( xmm15, SUBSH_MASK6 );\
    /* SubBytes + MixBytes */\
    SUBMIX(xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7);\
    \
    /* AddRoundConstant Q1024 */\
    xmm9 = m512_neg1;\
    xmm0 = _mm512_xor_si512( xmm0, xmm9 );\
    xmm1 = _mm512_xor_si512( xmm1, xmm9 );\
    xmm2 = _mm512_xor_si512( xmm2, xmm9 );\
    xmm3 = _mm512_xor_si512( xmm3, xmm9 );\
    xmm4 = _mm512_xor_si512( xmm4, xmm9 );\
    xmm5 = _mm512_xor_si512( xmm5, xmm9 );\
    xmm6 = _mm512_xor_si512( xmm6, xmm9 );\
    xmm7 = _mm512_xor_si512( xmm7, m512_const1_128( \
             casti_m128i( round_const_q, round_counter+1 ) ) ); \
    /* ShiftBytes Q1024 + pre-AESENCLAST */\
    xmm0 = _mm512_shuffle_epi8( xmm0, SUBSH_MASK1 );\
    xmm1 = _mm512_shuffle_epi8( xmm1, SUBSH_MASK3 );\
    xmm2 = _mm512_shuffle_epi8( xmm2, SUBSH_MASK5 );\
    xmm3 = _mm512_shuffle_epi8( xmm3, SUBSH_MASK7 );\
    xmm4 = _mm512_shuffle_epi8( xmm4, SUBSH_MASK0 );\
    xmm5 = _mm512_shuffle_epi8( xmm5, SUBSH_MASK2 );\
    xmm6 = _mm512_shuffle_epi8( xmm6, SUBSH_MASK4 );\
    xmm7 = _mm512_shuffle_epi8( xmm7, SUBSH_MASK6 );\
    /* SubBytes + MixBytes */\
    SUBMIX(xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15);\
  }\
}

/* Matrix Transpose
 * input is a 1024-bit state with two columns in one xmm
 * output is a 1024-bit state with two rows in one xmm
 * inputs: i0-i7
 * outputs: i0-i7
 * clobbers: t0-t7
 */
#define Matrix_Transpose(i0, i1, i2, i3, i4, i5, i6, i7, t0, t1, t2, t3, t4, t5, t6, t7){\
  t0 = TRANSP_MASK;\
\
  i6 = _mm512_shuffle_epi8(i6, t0);\
  i0 = _mm512_shuffle_epi8(i0, t0);\
  i1 = _mm512_shuffle_epi8(i1, t0);\
  i2 = _mm512_shuffle_epi8(i2, t0);\
  i3 = _mm512_shuffle_epi8(i3, t0);\
  t1 = i2;\
  i4 = _mm512_shuffle_epi8(i4, t0);\
  i5 = _mm512_shuffle_epi8(i5, t0);\
  t2 = i4;\
  t3 = i6;\
  i7 = _mm512_shuffle_epi8(i7, t0);\
\
  /* continue with unpack using 4 temp registers */\
  t0 = i0;\
  t2 = _mm512_unpackhi_epi16(t2, i5);\
  i4 = _mm512_unpacklo_epi16(i4, i5);\
  t3 = _mm512_unpackhi_epi16(t3, i7);\
  i6 = _mm512_unpacklo_epi16(i6, i7);\
  t0 = _mm512_unpackhi_epi16(t0, i1);\
  t1 = _mm512_unpackhi_epi16(t1, i3);\
  i2 = _mm512_unpacklo_epi16(i2, i3);\
  i0 = _mm512_unpacklo_epi16(i0, i1);\
\
  /* shuffle with immediate */\
  t0 = _mm512_shuffle_epi32(t0, 216);\
  t1 = _mm512_shuffle_epi32(t1, 216);\
  t2 = _mm512_shuffle_epi32(t2, 216);\
  t3 = _mm512_shuffle_epi32(t3, 216);\
  i0 = _mm512_shuffle_epi32(i0, 216);\
  i2 = _mm512_shuffle_epi32(i2, 216);\
  i4 = _mm512_shuffle_epi32(i4, 216);\
  i6 = _mm512_shuffle_epi32(i6, 216);\
\
  /* continue with unpack */\
  t4 = i0;\
  i0 = _mm512_unpacklo_epi32(i0, i2);\
  t4 = _mm512_unpackhi_epi32(t4, i2);\
  t5 = t0;\
  t0 = _mm512_unpacklo_epi32(t0, t1);\
  t5 = _mm512_unpackhi_epi32(t5, t1);\
  t6 = i4;\
  i4 = _mm512_unpacklo_epi32(i4, i6);\
  t7 = t2;\
  t6 = _mm512_unpackhi_epi32(t6, i6);\
  i2 = t0;\
  t2 = _mm512_unpacklo_epi32(t2, t3);\
  i3 = t0;\
  t7 = _mm512_unpackhi_epi32(t7, t3);\
\
  /* there are now 2 rows in each xmm */\
  /* unpack to get 1 row of CV in each xmm */\
  i1 = i0;\
  i1 = _mm512_unpackhi_epi64(i1, i4);\
  i0 = _mm512_unpacklo_epi64(i0, i4);\
  i4 = t4;\
  i3 = _mm512_unpackhi_epi64(i3, t2);\
  i5 = t4;\
  i2 = _mm512_unpacklo_epi64(i2, t2);\
  i6 = t5;\
  i5 = _mm512_unpackhi_epi64(i5, t6);\
  i7 = t5;\
  i4 = _mm512_unpacklo_epi64(i4, t6);\
  i7 = _mm512_unpackhi_epi64(i7, t7);\
  i6 = _mm512_unpacklo_epi64(i6, t7);\
  /* transpose done */\
}/**/

/* Matrix Transpose Inverse
 * input is a 1024-bit state with two rows in one xmm
 * output is a 1024-bit state with two columns in one xmm
 * inputs: i0-i7
 * outputs: (i0, o0, i1, i3, o1, o2, i5, i7)
 * clobbers: t0-t4
 */
#define Matrix_Transpose_INV(i0, i1, i2, i3, i4, i5, i6, i7, o0, o1, o2, t0, t1, t2, t3, t4){\
  /*  transpose matrix to get output format */\
  o1 = i0;\
  i0 = _mm512_unpacklo_epi64(i0, i1);\
  o1 = _mm512_unpackhi_epi64(o1, i1);\
  t0 = i2;\
  i2 = _mm512_unpacklo_epi64(i2, i3);\
  t0 = _mm512_unpackhi_epi64(t0, i3);\
  t1 = i4;\
  i4 = _mm512_unpacklo_epi64(i4, i5);\
  t1 = _mm512_unpackhi_epi64(t1, i5);\
  t2 = i6;\
  o0 = TRANSP_MASK;\
  i6 = _mm512_unpacklo_epi64(i6, i7);\
  t2 = _mm512_unpackhi_epi64(t2, i7);\
  /* load transpose mask into a register, because it will be used 8 times */\
  i0 = _mm512_shuffle_epi8(i0, o0);\
  i2 = _mm512_shuffle_epi8(i2, o0);\
  i4 = _mm512_shuffle_epi8(i4, o0);\
  i6 = _mm512_shuffle_epi8(i6, o0);\
  o1 = _mm512_shuffle_epi8(o1, o0);\
  t0 = _mm512_shuffle_epi8(t0, o0);\
  t1 = _mm512_shuffle_epi8(t1, o0);\
  t2 = _mm512_shuffle_epi8(t2, o0);\
  /* continue with unpack using 4 temp registers */\
  t3 = i4;\
  o2 = o1;\
  o0 = i0;\
  t4 = t1;\
  \
  t3 = _mm512_unpackhi_epi16(t3, i6);\
  i4 = _mm512_unpacklo_epi16(i4, i6);\
  o0 = _mm512_unpackhi_epi16(o0, i2);\
  i0 = _mm512_unpacklo_epi16(i0, i2);\
  o2 = _mm512_unpackhi_epi16(o2, t0);\
  o1 = _mm512_unpacklo_epi16(o1, t0);\
  t4 = _mm512_unpackhi_epi16(t4, t2);\
  t1 = _mm512_unpacklo_epi16(t1, t2);\
  /* shuffle with immediate */\
  i4 = _mm512_shuffle_epi32(i4, 216);\
  t3 = _mm512_shuffle_epi32(t3, 216);\
  o1 = _mm512_shuffle_epi32(o1, 216);\
  o2 = _mm512_shuffle_epi32(o2, 216);\
  i0 = _mm512_shuffle_epi32(i0, 216);\
  o0 = _mm512_shuffle_epi32(o0, 216);\
  t1 = _mm512_shuffle_epi32(t1, 216);\
  t4 = _mm512_shuffle_epi32(t4, 216);\
  /* continue with unpack */\
  i1 = i0;\
  i3 = o0;\
  i5 = o1;\
  i7 = o2;\
  i0 = _mm512_unpacklo_epi32(i0, i4);\
  i1 = _mm512_unpackhi_epi32(i1, i4);\
  o0 = _mm512_unpacklo_epi32(o0, t3);\
  i3 = _mm512_unpackhi_epi32(i3, t3);\
  o1 = _mm512_unpacklo_epi32(o1, t1);\
  i5 = _mm512_unpackhi_epi32(i5, t1);\
  o2 = _mm512_unpacklo_epi32(o2, t4);\
  i7 = _mm512_unpackhi_epi32(i7, t4);\
  /* transpose done */\
}/**/


void INIT_4way( __m512i* chaining )
{
  static __m512i xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7;
  static __m512i xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15;

  /* load IV into registers xmm8 - xmm15 */
  xmm8 = chaining[0];
  xmm9 = chaining[1];
  xmm10 = chaining[2];
  xmm11 = chaining[3];
  xmm12 = chaining[4];
  xmm13 = chaining[5];
  xmm14 = chaining[6];
  xmm15 = chaining[7];

  /* transform chaining value from column ordering into row ordering */
  Matrix_Transpose(xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7);

  /* store transposed IV */
  chaining[0] = xmm8;
  chaining[1] = xmm9;
  chaining[2] = xmm10;
  chaining[3] = xmm11;
  chaining[4] = xmm12;
  chaining[5] = xmm13;
  chaining[6] = xmm14;
  chaining[7] = xmm15;
}

void TF1024_4way( __m512i* chaining, const __m512i* message )
{
  static __m512i xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7;
  static __m512i xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15;
  static __m512i QTEMP[8];
  static __m512i TEMP0;
  static __m512i TEMP1;
  static __m512i TEMP2;

  /* load message into registers xmm8 - xmm15 (Q = message) */
  xmm8 = message[0];
  xmm9 = message[1];
  xmm10 = message[2];
  xmm11 = message[3];
  xmm12 = message[4];
  xmm13 = message[5];
  xmm14 = message[6];
  xmm15 = message[7];

  /* transform message M from column ordering into row ordering */
  Matrix_Transpose(xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7);

  /* store message M (Q input) for later */
  QTEMP[0] = xmm8;
  QTEMP[1] = xmm9;
  QTEMP[2] = xmm10;
  QTEMP[3] = xmm11;
  QTEMP[4] = xmm12;
  QTEMP[5] = xmm13;
  QTEMP[6] = xmm14;
  QTEMP[7] = xmm15;

  /* xor CV to message to get P input */
  /* result: CV+M in xmm8...xmm15 */
  xmm8 = _mm512_xor_si512( xmm8,  (chaining[0]) );
  xmm9 = _mm512_xor_si512( xmm9,  (chaining[1]) );
  xmm10 = _mm512_xor_si512( xmm10, (chaining[2]) );
  xmm11 = _mm512_xor_si512( xmm11, (chaining[3]) );
  xmm12 = _mm512_xor_si512( xmm12, (chaining[4]) );
  xmm13 = _mm512_xor_si512( xmm13, (chaining[5]) );
  xmm14 = _mm512_xor_si512( xmm14, (chaining[6]) );
  xmm15 = _mm512_xor_si512( xmm15, (chaining[7]) );

  /* compute permutation P */
  /* result: P(CV+M) in xmm8...xmm15 */
  ROUNDS_P();

  /* xor CV to P output (feed-forward) */
  /* result: P(CV+M)+CV in xmm8...xmm15 */
  xmm8 = _mm512_xor_si512( xmm8,  (chaining[0]) );
  xmm9 = _mm512_xor_si512( xmm9,  (chaining[1]) );
  xmm10 = _mm512_xor_si512( xmm10, (chaining[2]) );
  xmm11 = _mm512_xor_si512( xmm11, (chaining[3]) );
  xmm12 = _mm512_xor_si512( xmm12, (chaining[4]) );
  xmm13 = _mm512_xor_si512( xmm13, (chaining[5]) );
  xmm14 = _mm512_xor_si512( xmm14, (chaining[6]) );
  xmm15 = _mm512_xor_si512( xmm15, (chaining[7]) );

  /* store P(CV+M)+CV */
  chaining[0] = xmm8;
  chaining[1] = xmm9;
  chaining[2] = xmm10;
  chaining[3] = xmm11;
  chaining[4] = xmm12;
  chaining[5] = xmm13;
  chaining[6] = xmm14;
  chaining[7] = xmm15;

  /* load message M (Q input) into xmm8-15 */
  xmm8 = QTEMP[0];
  xmm9 = QTEMP[1];
  xmm10 = QTEMP[2];
  xmm11 = QTEMP[3];
  xmm12 = QTEMP[4];
  xmm13 = QTEMP[5];
  xmm14 = QTEMP[6];
  xmm15 = QTEMP[7];

  /* compute permutation Q */
  /* result: Q(M) in xmm8...xmm15 */
  ROUNDS_Q();

  /* xor Q output */
  /* result: P(CV+M)+CV+Q(M) in xmm8...xmm15 */
  xmm8 = _mm512_xor_si512( xmm8,  (chaining[0]) );
  xmm9 = _mm512_xor_si512( xmm9,  (chaining[1]) );
  xmm10 = _mm512_xor_si512( xmm10, (chaining[2]) );
  xmm11 = _mm512_xor_si512( xmm11, (chaining[3]) );
  xmm12 = _mm512_xor_si512( xmm12, (chaining[4]) );
  xmm13 = _mm512_xor_si512( xmm13, (chaining[5]) );
  xmm14 = _mm512_xor_si512( xmm14, (chaining[6]) );
  xmm15 = _mm512_xor_si512( xmm15, (chaining[7]) );

  /* store CV */
  chaining[0] = xmm8;
  chaining[1] = xmm9;
  chaining[2] = xmm10;
  chaining[3] = xmm11;
  chaining[4] = xmm12;
  chaining[5] = xmm13;
  chaining[6] = xmm14;
  chaining[7] = xmm15;

  return;
}

void OF1024_4way( __m512i* chaining )
{
  static __m512i xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7;
  static __m512i xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15;
  static __m512i TEMP0;
  static __m512i TEMP1;
  static __m512i TEMP2;

  /* load CV into registers xmm8 - xmm15 */
  xmm8 = chaining[0];
  xmm9 = chaining[1];
  xmm10 = chaining[2];
  xmm11 = chaining[3];
  xmm12 = chaining[4];
  xmm13 = chaining[5];
  xmm14 = chaining[6];
  xmm15 = chaining[7];

  /* compute permutation P */
  /* result: P(CV) in xmm8...xmm15 */
  ROUNDS_P();

  /* xor CV to P output (feed-forward) */
  /* result: P(CV)+CV in xmm8...xmm15 */
  xmm8 = _mm512_xor_si512( xmm8,  (chaining[0]) );
  xmm9 = _mm512_xor_si512( xmm9,  (chaining[1]) );
  xmm10 = _mm512_xor_si512( xmm10, (chaining[2]) );
  xmm11 = _mm512_xor_si512( xmm11, (chaining[3]) );
  xmm12 = _mm512_xor_si512( xmm12, (chaining[4]) );
  xmm13 = _mm512_xor_si512( xmm13, (chaining[5]) );
  xmm14 = _mm512_xor_si512( xmm14, (chaining[6]) );
  xmm15 = _mm512_xor_si512( xmm15, (chaining[7]) );

  /* transpose CV back from row ordering to column ordering */
  /* result: final hash value in xmm0, xmm6, xmm13, xmm15 */
  Matrix_Transpose_INV(xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15, xmm4, xmm0, xmm6, xmm1, xmm2, xmm3, xmm5, xmm7);

  /* we only need to return the truncated half of the state */
  chaining[4] = xmm0;
  chaining[5] = xmm6;
  chaining[6] = xmm13;
  chaining[7] = xmm15;

  return;
}

#endif  // AVX512

// AVX2 + VAES

static const __m256i TRANSP_MASK_2WAY =
    { 0x0d0509010c040800, 0x0f070b030e060a02,
      0x1d1519111c141810, 0x1f171b131e161a12 };

static const __m256i SUBSH_MASK0_2WAY =
    { 0x0b0e0104070a0d00, 0x0306090c0f020508,
      0x1b1e1114171a1d10, 0x1316191c1f121518 };

static const __m256i SUBSH_MASK1_2WAY =
    { 0x0c0f0205080b0e01, 0x04070a0d00030609,
      0x1c1f1215181b1e11, 0x14171a1d10131619 };

static const __m256i SUBSH_MASK2_2WAY =
    { 0x0d000306090c0f02, 0x05080b0e0104070a,
      0x1d101316191c1f12, 0x15181b1e1114171a };

static const __m256i SUBSH_MASK3_2WAY =
    { 0x0e0104070a0d0003, 0x06090c0f0205080b,
      0x1e1114171a1d1013, 0x16191c1f1215181b };

static const __m256i SUBSH_MASK4_2WAY = 
    { 0x0f0205080b0e0104, 0x070a0d000306090c,
      0x1f1215181b1e1114, 0x171a1d101316191c };

static const __m256i SUBSH_MASK5_2WAY =
    { 0x000306090c0f0205, 0x080b0e0104070a0d,
      0x101316191c1f1215, 0x181b1e1114171a1d };

static const __m256i SUBSH_MASK6_2WAY =
    { 0x0104070a0d000306, 0x090c0f0205080b0e,
      0x1114171a1d101316, 0x191c1f1215181b1e };

static const __m256i SUBSH_MASK7_2WAY =
    { 0x06090c0f0205080b, 0x0e0104070a0d0003,
      0x16191c1f1215181b, 0x1e1114171a1d1013 };

#define tos(a)    #a
#define tostr(a)  tos(a)

/* xmm[i] will be multiplied by 2
 * xmm[j] will be lost
 * xmm[k] has to be all 0x1b */
#define MUL2_2WAY(i, j, k){\
  j = _mm256_cmpgt_epi8( m256_zero, i );\
  i = _mm256_add_epi8(i, i);\
  i = mm256_xorand( i, j, k );\
}

#define MixBytes_2way(a0, a1, a2, a3, a4, a5, a6, a7, b0, b1, b2, b3, b4, b5, b6, b7){\
  /* t_i = a_i + a_{i+1} */\
  b6 = a0;\
  b7 = a1;\
  a0 = _mm256_xor_si256(a0, a1);\
  b0 = a2;\
  a1 = _mm256_xor_si256(a1, a2);\
  b1 = a3;\
  a2 = _mm256_xor_si256(a2, a3);\
  b2 = a4;\
  a3 = _mm256_xor_si256(a3, a4);\
  b3 = a5;\
  a4 = _mm256_xor_si256(a4, a5);\
  b4 = a6;\
  a5 = _mm256_xor_si256(a5, a6);\
  b5 = a7;\
  a6 = _mm256_xor_si256(a6, a7);\
  a7 = _mm256_xor_si256(a7, b6);\
  \
  /* build y4 y5 y6 ... in regs xmm8, xmm9, xmm10 by adding t_i*/\
  b0 = _mm256_xor_si256(b0, a4);\
  b6 = _mm256_xor_si256(b6, a4);\
  b1 = _mm256_xor_si256(b1, a5);\
  b7 = _mm256_xor_si256(b7, a5);\
  b2 = _mm256_xor_si256(b2, a6);\
  b0 = _mm256_xor_si256(b0, a6);\
  /* spill values y_4, y_5 to memory */\
  TEMP0 = b0;\
  b3 = _mm256_xor_si256(b3, a7);\
  b1 = _mm256_xor_si256(b1, a7);\
  TEMP1 = b1;\
  b4 = _mm256_xor_si256(b4, a0);\
  b2 = _mm256_xor_si256(b2, a0);\
  /* save values t0, t1, t2 to xmm8, xmm9 and memory */\
  b0 = a0;\
  b5 = _mm256_xor_si256(b5, a1);\
  b3 = _mm256_xor_si256(b3, a1);\
  b1 = a1;\
  b6 = _mm256_xor_si256(b6, a2);\
  b4 = _mm256_xor_si256(b4, a2);\
  TEMP2 = a2;\
  b7 = _mm256_xor_si256(b7, a3);\
  b5 = _mm256_xor_si256(b5, a3);\
  \
  /* compute x_i = t_i + t_{i+3} */\
  a0 = _mm256_xor_si256(a0, a3);\
  a1 = _mm256_xor_si256(a1, a4);\
  a2 = _mm256_xor_si256(a2, a5);\
  a3 = _mm256_xor_si256(a3, a6);\
  a4 = _mm256_xor_si256(a4, a7);\
  a5 = _mm256_xor_si256(a5, b0);\
  a6 = _mm256_xor_si256(a6, b1);\
  a7 = _mm256_xor_si256(a7, TEMP2);\
  \
  /* compute z_i : double x_i using temp xmm8 and 1B xmm9 */\
  /* compute w_i : add y_{i+4} */\
  b1 = m256_const1_64( 0x1b1b1b1b1b1b1b1b );\
  MUL2_2WAY(a0, b0, b1);\
  a0 = _mm256_xor_si256(a0, TEMP0);\
  MUL2_2WAY(a1, b0, b1);\
  a1 = _mm256_xor_si256(a1, TEMP1);\
  MUL2_2WAY(a2, b0, b1);\
  a2 = _mm256_xor_si256(a2, b2);\
  MUL2_2WAY(a3, b0, b1);\
  a3 = _mm256_xor_si256(a3, b3);\
  MUL2_2WAY(a4, b0, b1);\
  a4 = _mm256_xor_si256(a4, b4);\
  MUL2_2WAY(a5, b0, b1);\
  a5 = _mm256_xor_si256(a5, b5);\
  MUL2_2WAY(a6, b0, b1);\
  a6 = _mm256_xor_si256(a6, b6);\
  MUL2_2WAY(a7, b0, b1);\
  a7 = _mm256_xor_si256(a7, b7);\
  \
  /* compute v_i : double w_i      */\
  /* add to y_4 y_5 .. v3, v4, ... */\
  MUL2_2WAY(a0, b0, b1);\
  b5 = _mm256_xor_si256(b5, a0);\
  MUL2_2WAY(a1, b0, b1);\
  b6 = _mm256_xor_si256(b6, a1);\
  MUL2_2WAY(a2, b0, b1);\
  b7 = _mm256_xor_si256(b7, a2);\
  MUL2_2WAY(a5, b0, b1);\
  b2 = _mm256_xor_si256(b2, a5);\
  MUL2_2WAY(a6, b0, b1);\
  b3 = _mm256_xor_si256(b3, a6);\
  MUL2_2WAY(a7, b0, b1);\
  b4 = _mm256_xor_si256(b4, a7);\
  MUL2_2WAY(a3, b0, b1);\
  MUL2_2WAY(a4, b0, b1);\
  b0 = TEMP0;\
  b1 = TEMP1;\
  b0 = _mm256_xor_si256(b0, a3);\
  b1 = _mm256_xor_si256(b1, a4);\
}/*MixBytes*/

/* one round
 * a0-a7 = input rows
 * b0-b7 = output rows
 */
#define SUBMIX_2WAY(a0, a1, a2, a3, a4, a5, a6, a7, b0, b1, b2, b3, b4, b5, b6, b7){\
  /* SubBytes */\
  b0 = _mm256_xor_si256( b0, b0 );\
  a0 = _mm256_aesenclast_epi128( a0, b0 );\
  a1 = _mm256_aesenclast_epi128( a1, b0 );\
  a2 = _mm256_aesenclast_epi128( a2, b0 );\
  a3 = _mm256_aesenclast_epi128( a3, b0 );\
  a4 = _mm256_aesenclast_epi128( a4, b0 );\
  a5 = _mm256_aesenclast_epi128( a5, b0 );\
  a6 = _mm256_aesenclast_epi128( a6, b0 );\
  a7 = _mm256_aesenclast_epi128( a7, b0 );\
  /* MixBytes */\
  MixBytes_2way(a0, a1, a2, a3, a4, a5, a6, a7, b0, b1, b2, b3, b4, b5, b6, b7);\
}

#define ROUNDS_P_2WAY(){\
  uint8_t round_counter = 0;\
  for ( round_counter = 0; round_counter < 14; round_counter += 2 ) \
  { \
    /* AddRoundConstant P1024 */\
    xmm8 = _mm256_xor_si256( xmm8, m256_const1_128( \
             casti_m128i( round_const_p, round_counter ) ) ); \
    /* ShiftBytes P1024 + pre-AESENCLAST */\
    xmm8  = _mm256_shuffle_epi8( xmm8,  SUBSH_MASK0_2WAY ); \
    xmm9  = _mm256_shuffle_epi8( xmm9,  SUBSH_MASK1_2WAY );\
    xmm10 = _mm256_shuffle_epi8( xmm10, SUBSH_MASK2_2WAY );\
    xmm11 = _mm256_shuffle_epi8( xmm11, SUBSH_MASK3_2WAY );\
    xmm12 = _mm256_shuffle_epi8( xmm12, SUBSH_MASK4_2WAY );\
    xmm13 = _mm256_shuffle_epi8( xmm13, SUBSH_MASK5_2WAY );\
    xmm14 = _mm256_shuffle_epi8( xmm14, SUBSH_MASK6_2WAY );\
    xmm15 = _mm256_shuffle_epi8( xmm15, SUBSH_MASK7_2WAY );\
    /* SubBytes + MixBytes */\
    SUBMIX_2WAY(xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7);\
    \
     /* AddRoundConstant P1024 */\
    xmm0 = _mm256_xor_si256( xmm0, m256_const1_128( \
             casti_m128i( round_const_p, round_counter+1 ) ) ); \
    /* ShiftBytes P1024 + pre-AESENCLAST */\
    xmm0 = _mm256_shuffle_epi8( xmm0, SUBSH_MASK0_2WAY );\
    xmm1 = _mm256_shuffle_epi8( xmm1, SUBSH_MASK1_2WAY );\
    xmm2 = _mm256_shuffle_epi8( xmm2, SUBSH_MASK2_2WAY );\
    xmm3 = _mm256_shuffle_epi8( xmm3, SUBSH_MASK3_2WAY );\
    xmm4 = _mm256_shuffle_epi8( xmm4, SUBSH_MASK4_2WAY );\
    xmm5 = _mm256_shuffle_epi8( xmm5, SUBSH_MASK5_2WAY );\
    xmm6 = _mm256_shuffle_epi8( xmm6, SUBSH_MASK6_2WAY );\
    xmm7 = _mm256_shuffle_epi8( xmm7, SUBSH_MASK7_2WAY );\
    /* SubBytes + MixBytes */\
     SUBMIX_2WAY(xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15);\
  }\
}

#define ROUNDS_Q_2WAY(){\
  uint8_t round_counter = 0;\
  for ( round_counter = 0; round_counter < 14; round_counter += 2) \
  { \
    /* AddRoundConstant Q1024 */\
    xmm1 = m256_neg1;\
    xmm8  = _mm256_xor_si256( xmm8,  xmm1 );\
    xmm9  = _mm256_xor_si256( xmm9,  xmm1 );\
    xmm10 = _mm256_xor_si256( xmm10, xmm1 );\
    xmm11 = _mm256_xor_si256( xmm11, xmm1 );\
    xmm12 = _mm256_xor_si256( xmm12, xmm1 );\
    xmm13 = _mm256_xor_si256( xmm13, xmm1 );\
    xmm14 = _mm256_xor_si256( xmm14, xmm1 );\
    xmm15 = _mm256_xor_si256( xmm15, m256_const1_128( \
                 casti_m128i( round_const_q, round_counter ) ) ); \
    /* ShiftBytes Q1024 + pre-AESENCLAST */\
    xmm8  = _mm256_shuffle_epi8( xmm8,  SUBSH_MASK1_2WAY );\
    xmm9  = _mm256_shuffle_epi8( xmm9,  SUBSH_MASK3_2WAY );\
    xmm10 = _mm256_shuffle_epi8( xmm10, SUBSH_MASK5_2WAY );\
    xmm11 = _mm256_shuffle_epi8( xmm11, SUBSH_MASK7_2WAY );\
    xmm12 = _mm256_shuffle_epi8( xmm12, SUBSH_MASK0_2WAY );\
    xmm13 = _mm256_shuffle_epi8( xmm13, SUBSH_MASK2_2WAY );\
    xmm14 = _mm256_shuffle_epi8( xmm14, SUBSH_MASK4_2WAY );\
    xmm15 = _mm256_shuffle_epi8( xmm15, SUBSH_MASK6_2WAY );\
    /* SubBytes + MixBytes */\
    SUBMIX_2WAY(xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7);\
    \
    /* AddRoundConstant Q1024 */\
    xmm9 = m256_neg1;\
    xmm0 = _mm256_xor_si256( xmm0, xmm9 );\
    xmm1 = _mm256_xor_si256( xmm1, xmm9 );\
    xmm2 = _mm256_xor_si256( xmm2, xmm9 );\
    xmm3 = _mm256_xor_si256( xmm3, xmm9 );\
    xmm4 = _mm256_xor_si256( xmm4, xmm9 );\
    xmm5 = _mm256_xor_si256( xmm5, xmm9 );\
    xmm6 = _mm256_xor_si256( xmm6, xmm9 );\
    xmm7 = _mm256_xor_si256( xmm7, m256_const1_128( \
             casti_m128i( round_const_q, round_counter+1 ) ) ); \
    /* ShiftBytes Q1024 + pre-AESENCLAST */\
    xmm0 = _mm256_shuffle_epi8( xmm0, SUBSH_MASK1_2WAY );\
    xmm1 = _mm256_shuffle_epi8( xmm1, SUBSH_MASK3_2WAY );\
    xmm2 = _mm256_shuffle_epi8( xmm2, SUBSH_MASK5_2WAY );\
    xmm3 = _mm256_shuffle_epi8( xmm3, SUBSH_MASK7_2WAY );\
    xmm4 = _mm256_shuffle_epi8( xmm4, SUBSH_MASK0_2WAY );\
    xmm5 = _mm256_shuffle_epi8( xmm5, SUBSH_MASK2_2WAY );\
    xmm6 = _mm256_shuffle_epi8( xmm6, SUBSH_MASK4_2WAY );\
    xmm7 = _mm256_shuffle_epi8( xmm7, SUBSH_MASK6_2WAY );\
    /* SubBytes + MixBytes */\
    SUBMIX_2WAY(xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15);\
  }\
}

#define Matrix_Transpose_2way(i0, i1, i2, i3, i4, i5, i6, i7, t0, t1, t2, t3, t4, t5, t6, t7){\
  t0 = TRANSP_MASK_2WAY;\
\
  i6 = _mm256_shuffle_epi8(i6, t0);\
  i0 = _mm256_shuffle_epi8(i0, t0);\
  i1 = _mm256_shuffle_epi8(i1, t0);\
  i2 = _mm256_shuffle_epi8(i2, t0);\
  i3 = _mm256_shuffle_epi8(i3, t0);\
  t1 = i2;\
  i4 = _mm256_shuffle_epi8(i4, t0);\
  i5 = _mm256_shuffle_epi8(i5, t0);\
  t2 = i4;\
  t3 = i6;\
  i7 = _mm256_shuffle_epi8(i7, t0);\
\
  /* continue with unpack using 4 temp registers */\
  t0 = i0;\
  t2 = _mm256_unpackhi_epi16(t2, i5);\
  i4 = _mm256_unpacklo_epi16(i4, i5);\
  t3 = _mm256_unpackhi_epi16(t3, i7);\
  i6 = _mm256_unpacklo_epi16(i6, i7);\
  t0 = _mm256_unpackhi_epi16(t0, i1);\
  t1 = _mm256_unpackhi_epi16(t1, i3);\
  i2 = _mm256_unpacklo_epi16(i2, i3);\
  i0 = _mm256_unpacklo_epi16(i0, i1);\
\
  /* shuffle with immediate */\
  t0 = _mm256_shuffle_epi32(t0, 216);\
  t1 = _mm256_shuffle_epi32(t1, 216);\
  t2 = _mm256_shuffle_epi32(t2, 216);\
  t3 = _mm256_shuffle_epi32(t3, 216);\
  i0 = _mm256_shuffle_epi32(i0, 216);\
  i2 = _mm256_shuffle_epi32(i2, 216);\
  i4 = _mm256_shuffle_epi32(i4, 216);\
  i6 = _mm256_shuffle_epi32(i6, 216);\
\
  /* continue with unpack */\
  t4 = i0;\
  i0 = _mm256_unpacklo_epi32(i0, i2);\
  t4 = _mm256_unpackhi_epi32(t4, i2);\
  t5 = t0;\
  t0 = _mm256_unpacklo_epi32(t0, t1);\
  t5 = _mm256_unpackhi_epi32(t5, t1);\
  t6 = i4;\
  i4 = _mm256_unpacklo_epi32(i4, i6);\
  t7 = t2;\
  t6 = _mm256_unpackhi_epi32(t6, i6);\
  i2 = t0;\
  t2 = _mm256_unpacklo_epi32(t2, t3);\
  i3 = t0;\
  t7 = _mm256_unpackhi_epi32(t7, t3);\
\
  /* there are now 2 rows in each xmm */\
  /* unpack to get 1 row of CV in each xmm */\
  i1 = i0;\
  i1 = _mm256_unpackhi_epi64(i1, i4);\
  i0 = _mm256_unpacklo_epi64(i0, i4);\
  i4 = t4;\
  i3 = _mm256_unpackhi_epi64(i3, t2);\
  i5 = t4;\
  i2 = _mm256_unpacklo_epi64(i2, t2);\
  i6 = t5;\
  i5 = _mm256_unpackhi_epi64(i5, t6);\
  i7 = t5;\
  i4 = _mm256_unpacklo_epi64(i4, t6);\
  i7 = _mm256_unpackhi_epi64(i7, t7);\
  i6 = _mm256_unpacklo_epi64(i6, t7);\
  /* transpose done */\
}/**/

#define Matrix_Transpose_INV_2way(i0, i1, i2, i3, i4, i5, i6, i7, o0, o1, o2, t0, t1, t2, t3, t4){\
  /*  transpose matrix to get output format */\
  o1 = i0;\
  i0 = _mm256_unpacklo_epi64(i0, i1);\
  o1 = _mm256_unpackhi_epi64(o1, i1);\
  t0 = i2;\
  i2 = _mm256_unpacklo_epi64(i2, i3);\
  t0 = _mm256_unpackhi_epi64(t0, i3);\
  t1 = i4;\
  i4 = _mm256_unpacklo_epi64(i4, i5);\
  t1 = _mm256_unpackhi_epi64(t1, i5);\
  t2 = i6;\
  o0 = TRANSP_MASK_2WAY;\
  i6 = _mm256_unpacklo_epi64(i6, i7);\
  t2 = _mm256_unpackhi_epi64(t2, i7);\
  /* load transpose mask into a register, because it will be used 8 times */\
  i0 = _mm256_shuffle_epi8(i0, o0);\
  i2 = _mm256_shuffle_epi8(i2, o0);\
  i4 = _mm256_shuffle_epi8(i4, o0);\
  i6 = _mm256_shuffle_epi8(i6, o0);\
  o1 = _mm256_shuffle_epi8(o1, o0);\
  t0 = _mm256_shuffle_epi8(t0, o0);\
  t1 = _mm256_shuffle_epi8(t1, o0);\
  t2 = _mm256_shuffle_epi8(t2, o0);\
  /* continue with unpack using 4 temp registers */\
  t3 = i4;\
  o2 = o1;\
  o0 = i0;\
  t4 = t1;\
  \
  t3 = _mm256_unpackhi_epi16(t3, i6);\
  i4 = _mm256_unpacklo_epi16(i4, i6);\
  o0 = _mm256_unpackhi_epi16(o0, i2);\
  i0 = _mm256_unpacklo_epi16(i0, i2);\
  o2 = _mm256_unpackhi_epi16(o2, t0);\
  o1 = _mm256_unpacklo_epi16(o1, t0);\
  t4 = _mm256_unpackhi_epi16(t4, t2);\
  t1 = _mm256_unpacklo_epi16(t1, t2);\
  /* shuffle with immediate */\
  i4 = _mm256_shuffle_epi32(i4, 216);\
  t3 = _mm256_shuffle_epi32(t3, 216);\
  o1 = _mm256_shuffle_epi32(o1, 216);\
  o2 = _mm256_shuffle_epi32(o2, 216);\
  i0 = _mm256_shuffle_epi32(i0, 216);\
  o0 = _mm256_shuffle_epi32(o0, 216);\
  t1 = _mm256_shuffle_epi32(t1, 216);\
  t4 = _mm256_shuffle_epi32(t4, 216);\
  /* continue with unpack */\
  i1 = i0;\
  i3 = o0;\
  i5 = o1;\
  i7 = o2;\
  i0 = _mm256_unpacklo_epi32(i0, i4);\
  i1 = _mm256_unpackhi_epi32(i1, i4);\
  o0 = _mm256_unpacklo_epi32(o0, t3);\
  i3 = _mm256_unpackhi_epi32(i3, t3);\
  o1 = _mm256_unpacklo_epi32(o1, t1);\
  i5 = _mm256_unpackhi_epi32(i5, t1);\
  o2 = _mm256_unpacklo_epi32(o2, t4);\
  i7 = _mm256_unpackhi_epi32(i7, t4);\
  /* transpose done */\
}/**/

void INIT_2way( __m256i *chaining )
{
  static __m256i xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7;
  static __m256i xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15;

  /* load IV into registers xmm8 - xmm15 */
  xmm8 = chaining[0];
  xmm9 = chaining[1];
  xmm10 = chaining[2];
  xmm11 = chaining[3];
  xmm12 = chaining[4];
  xmm13 = chaining[5];
  xmm14 = chaining[6];
  xmm15 = chaining[7];

  /* transform chaining value from column ordering into row ordering */
  Matrix_Transpose_2way(xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7);

  /* store transposed IV */
  chaining[0] = xmm8;
  chaining[1] = xmm9;
  chaining[2] = xmm10;
  chaining[3] = xmm11;
  chaining[4] = xmm12;
  chaining[5] = xmm13;
  chaining[6] = xmm14;
  chaining[7] = xmm15;
}

void TF1024_2way( __m256i *chaining, const __m256i *message )
{
  static __m256i xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7;
  static __m256i xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15;
  static __m256i QTEMP[8];
  static __m256i TEMP0;
  static __m256i TEMP1;
  static __m256i TEMP2;

  /* load message into registers xmm8 - xmm15 (Q = message) */
  xmm8 = message[0];
  xmm9 = message[1];
  xmm10 = message[2];
  xmm11 = message[3];
  xmm12 = message[4];
  xmm13 = message[5];
  xmm14 = message[6];
  xmm15 = message[7];

  /* transform message M from column ordering into row ordering */
  Matrix_Transpose_2way(xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7);

  /* store message M (Q input) for later */
  QTEMP[0] = xmm8;
  QTEMP[1] = xmm9;
  QTEMP[2] = xmm10;
  QTEMP[3] = xmm11;
  QTEMP[4] = xmm12;
  QTEMP[5] = xmm13;
  QTEMP[6] = xmm14;
  QTEMP[7] = xmm15;

  /* xor CV to message to get P input */
  /* result: CV+M in xmm8...xmm15 */
  xmm8 = _mm256_xor_si256( xmm8,  (chaining[0]) );
  xmm9 = _mm256_xor_si256( xmm9,  (chaining[1]) );
  xmm10 = _mm256_xor_si256( xmm10, (chaining[2]) );
  xmm11 = _mm256_xor_si256( xmm11, (chaining[3]) );
  xmm12 = _mm256_xor_si256( xmm12, (chaining[4]) );
  xmm13 = _mm256_xor_si256( xmm13, (chaining[5]) );
  xmm14 = _mm256_xor_si256( xmm14, (chaining[6]) );
  xmm15 = _mm256_xor_si256( xmm15, (chaining[7]) );

  /* compute permutation P */
  /* result: P(CV+M) in xmm8...xmm15 */
  ROUNDS_P_2WAY();

  /* xor CV to P output (feed-forward) */
  /* result: P(CV+M)+CV in xmm8...xmm15 */
  xmm8 = _mm256_xor_si256( xmm8,  (chaining[0]) );
  xmm9 = _mm256_xor_si256( xmm9,  (chaining[1]) );
  xmm10 = _mm256_xor_si256( xmm10, (chaining[2]) );
  xmm11 = _mm256_xor_si256( xmm11, (chaining[3]) );
  xmm12 = _mm256_xor_si256( xmm12, (chaining[4]) );
  xmm13 = _mm256_xor_si256( xmm13, (chaining[5]) );
  xmm14 = _mm256_xor_si256( xmm14, (chaining[6]) );
  xmm15 = _mm256_xor_si256( xmm15, (chaining[7]) );

  /* store P(CV+M)+CV */
  chaining[0] = xmm8;
  chaining[1] = xmm9;
  chaining[2] = xmm10;
  chaining[3] = xmm11;
  chaining[4] = xmm12;
  chaining[5] = xmm13;
  chaining[6] = xmm14;
  chaining[7] = xmm15;

  /* load message M (Q input) into xmm8-15 */
  xmm8 = QTEMP[0];
  xmm9 = QTEMP[1];
  xmm10 = QTEMP[2];
  xmm11 = QTEMP[3];
  xmm12 = QTEMP[4];
  xmm13 = QTEMP[5];
  xmm14 = QTEMP[6];
  xmm15 = QTEMP[7];

  /* compute permutation Q */
  /* result: Q(M) in xmm8...xmm15 */
  ROUNDS_Q_2WAY();

  /* xor Q output */
  /* result: P(CV+M)+CV+Q(M) in xmm8...xmm15 */
  xmm8 = _mm256_xor_si256( xmm8,  (chaining[0]) );
  xmm9 = _mm256_xor_si256( xmm9,  (chaining[1]) );
  xmm10 = _mm256_xor_si256( xmm10, (chaining[2]) );
  xmm11 = _mm256_xor_si256( xmm11, (chaining[3]) );
  xmm12 = _mm256_xor_si256( xmm12, (chaining[4]) );
  xmm13 = _mm256_xor_si256( xmm13, (chaining[5]) );
  xmm14 = _mm256_xor_si256( xmm14, (chaining[6]) );
  xmm15 = _mm256_xor_si256( xmm15, (chaining[7]) );

  /* store CV */
  chaining[0] = xmm8;
  chaining[1] = xmm9;
  chaining[2] = xmm10;
  chaining[3] = xmm11;
  chaining[4] = xmm12;
  chaining[5] = xmm13;
  chaining[6] = xmm14;
  chaining[7] = xmm15;

  return;
}

void OF1024_2way( __m256i* chaining )
{
  static __m256i xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7;
  static __m256i xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15;
  static __m256i TEMP0;
  static __m256i TEMP1;
  static __m256i TEMP2;

  /* load CV into registers xmm8 - xmm15 */
  xmm8 = chaining[0];
  xmm9 = chaining[1];
  xmm10 = chaining[2];
  xmm11 = chaining[3];
  xmm12 = chaining[4];
  xmm13 = chaining[5];
  xmm14 = chaining[6];
  xmm15 = chaining[7];

  /* compute permutation P */
  /* result: P(CV) in xmm8...xmm15 */
  ROUNDS_P_2WAY();

  /* xor CV to P output (feed-forward) */
  /* result: P(CV)+CV in xmm8...xmm15 */
  xmm8 = _mm256_xor_si256( xmm8,  (chaining[0]) );
  xmm9 = _mm256_xor_si256( xmm9,  (chaining[1]) );
  xmm10 = _mm256_xor_si256( xmm10, (chaining[2]) );
  xmm11 = _mm256_xor_si256( xmm11, (chaining[3]) );
  xmm12 = _mm256_xor_si256( xmm12, (chaining[4]) );
  xmm13 = _mm256_xor_si256( xmm13, (chaining[5]) );
  xmm14 = _mm256_xor_si256( xmm14, (chaining[6]) );
  xmm15 = _mm256_xor_si256( xmm15, (chaining[7]) );

  /* transpose CV back from row ordering to column ordering */
  /* result: final hash value in xmm0, xmm6, xmm13, xmm15 */
  Matrix_Transpose_INV_2way(xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15, xmm4, xmm0, xmm6, xmm1, xmm2, xmm3, xmm5, xmm7);

  /* we only need to return the truncated half of the state */
  chaining[4] = xmm0;
  chaining[5] = xmm6;
  chaining[6] = xmm13;
  chaining[7] = xmm15;

  return;
}



#endif  // VAES
#endif  // GROESTL512_INTR_4WAY_H__
