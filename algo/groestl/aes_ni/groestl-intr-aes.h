#if !defined GROESTL_INTR_AES_H__
#define GROESTL_INTR_AES_H__

/* groestl-intr-aes.h     Aug 2011
 *
 * Groestl implementation with intrinsics using ssse3, sse4.1, and aes
 * instructions.
 * Author: Günther A. Roland, Martin Schläffer, Krystian Matusiewicz
 *
 * This code is placed in the public domain
 */

#include "hash-groestl.h"

static const v128u64_t round_const_p[] __attribute__ ((aligned (64))) =
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

static const v128u64_t round_const_q[] __attribute__ ((aligned (64))) =
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

static const v128u64_t TRANSP_MASK = { 0x0d0509010c040800, 0x0f070b030e060a02 };
static const v128u64_t SUBSH_MASK0 = { 0x0b0e0104070a0d00, 0x0306090c0f020508 };
static const v128u64_t SUBSH_MASK1 = { 0x0c0f0205080b0e01, 0x04070a0d00030609 };
static const v128u64_t SUBSH_MASK2 = { 0x0d000306090c0f02, 0x05080b0e0104070a };
static const v128u64_t SUBSH_MASK3 = { 0x0e0104070a0d0003, 0x06090c0f0205080b };
static const v128u64_t SUBSH_MASK4 = { 0x0f0205080b0e0104, 0x070a0d000306090c };
static const v128u64_t SUBSH_MASK5 = { 0x000306090c0f0205, 0x080b0e0104070a0d };
static const v128u64_t SUBSH_MASK6 = { 0x0104070a0d000306, 0x090c0f0205080b0e };
static const v128u64_t SUBSH_MASK7 = { 0x06090c0f0205080b, 0x0e0104070a0d0003 };

#if defined(__ARM_NEON)

static const v128u32_t gr_mask __attribute__ ((aligned (16))) =
   { 0x03020100, 0x0b0a0908, 0x07060504, 0x0f0e0d0c };

#define gr_shuffle32(v)       vqtbl1q_u8( v, gr_mask ) 

#else

#define gr_shuffle32(v)       _mm_shuffle_epi32( v, 0xd8 )

#endif

#define tos(a)    #a
#define tostr(a)  tos(a)

/* xmm[i] will be multiplied by 2
 * xmm[j] will be lost
 * xmm[k] has to be all 0x1b */
#define MUL2(i, j, k){\
  j = v128_cmpgt8( v128_zero, i);\
  i = v128_add8(i, i);\
  i = v128_xorand(i, j, k );\
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

#if defined(VL256)

#define MixBytes(a0, a1, a2, a3, a4, a5, a6, a7, b0, b1, b2, b3, b4, b5, b6, b7){\
  /* t_i = a_i + a_{i+1} */\
  b6 = a0;\
  b7 = a1;\
  a0 = v128_xor(a0, a1);\
  b0 = a2;\
  a1 = v128_xor(a1, a2);\
  b1 = a3;\
  TEMP2 = v128_xor(a2, a3);\
  b2 = a4;\
  a3 = v128_xor(a3, a4);\
  b3 = a5;\
  a4 = v128_xor(a4, a5);\
  b4 = a6;\
  a5 = v128_xor(a5, a6);\
  b5 = a7;\
  a6 = v128_xor(a6, a7);\
  a7 = v128_xor(a7, b6);\
   \
  /* build y4 y5 y6 ... in regs xmm8, xmm9, xmm10 by adding t_i*/\
  TEMP0 = v128_xor3( b0, a4, a6 ); \
  /* spill values y_4, y_5 to memory */\
  TEMP1 = v128_xor3( b1, a5, a7 );\
  b2 = v128_xor3( b2, a6, a0 ); \
  /* save values t0, t1, t2 to xmm8, xmm9 and memory */\
  b0 = a0;\
  b3 = v128_xor3( b3, a7, a1 ); \
  b1 = a1;\
  b6 = v128_xor3( b6, a4, TEMP2 ); \
  b4 = v128_xor3( b4, a0, TEMP2 ); \
  b7 = v128_xor3( b7, a5, a3 ); \
  b5 = v128_xor3( b5, a1, a3 ); \
  \
  /* compute x_i = t_i + t_{i+3} */\
  a0 = v128_xor(a0, a3);\
  a1 = v128_xor(a1, a4);\
  a2 = v128_xor(TEMP2, a5);\
  a3 = v128_xor(a3, a6);\
  a4 = v128_xor(a4, a7);\
  a5 = v128_xor(a5, b0);\
  a6 = v128_xor(a6, b1);\
  a7 = v128_xor(a7, TEMP2);\
  \
  /* compute z_i : double x_i using temp xmm8 and 1B xmm9 */\
  /* compute w_i : add y_{i+4} */\
  b1 = v128_64( 0x1b1b1b1b1b1b1b1b );\
  MUL2(a0, b0, b1);\
  a0 = v128_xor(a0, TEMP0);\
  MUL2(a1, b0, b1);\
  a1 = v128_xor(a1, TEMP1);\
  MUL2(a2, b0, b1);\
  a2 = v128_xor(a2, b2);\
  MUL2(a3, b0, b1);\
  a3 = v128_xor(a3, b3);\
  MUL2(a4, b0, b1);\
  a4 = v128_xor(a4, b4);\
  MUL2(a5, b0, b1);\
  a5 = v128_xor(a5, b5);\
  MUL2(a6, b0, b1);\
  a6 = v128_xor(a6, b6);\
  MUL2(a7, b0, b1);\
  a7 = v128_xor(a7, b7);\
  \
  /* compute v_i : double w_i      */\
  /* add to y_4 y_5 .. v3, v4, ... */\
  MUL2(a0, b0, b1);\
  b5 = v128_xor(b5, a0);\
  MUL2(a1, b0, b1);\
  b6 = v128_xor(b6, a1);\
  MUL2(a2, b0, b1);\
  b7 = v128_xor(b7, a2);\
  MUL2(a5, b0, b1);\
  b2 = v128_xor(b2, a5);\
  MUL2(a6, b0, b1);\
  b3 = v128_xor(b3, a6);\
  MUL2(a7, b0, b1);\
  b4 = v128_xor(b4, a7);\
  MUL2(a3, b0, b1);\
  MUL2(a4, b0, b1);\
  b0 = TEMP0;\
  b1 = TEMP1;\
  b0 = v128_xor(b0, a3);\
  b1 = v128_xor(b1, a4);\
}/*MixBytes*/

#else

#define MixBytes(a0, a1, a2, a3, a4, a5, a6, a7, b0, b1, b2, b3, b4, b5, b6, b7){\
  /* t_i = a_i + a_{i+1} */\
  b6 = a0;\
  b7 = a1;\
  a0 = v128_xor(a0, a1);\
  b0 = a2;\
  a1 = v128_xor(a1, a2);\
  b1 = a3;\
  a2 = v128_xor(a2, a3);\
  b2 = a4;\
  a3 = v128_xor(a3, a4);\
  b3 = a5;\
  a4 = v128_xor(a4, a5);\
  b4 = a6;\
  a5 = v128_xor(a5, a6);\
  b5 = a7;\
  a6 = v128_xor(a6, a7);\
  a7 = v128_xor(a7, b6);\
   \
  /* build y4 y5 y6 ... in regs xmm8, xmm9, xmm10 by adding t_i*/\
  b0 = v128_xor(b0, a4);\
  b6 = v128_xor(b6, a4);\
  b1 = v128_xor(b1, a5);\
  b7 = v128_xor(b7, a5);\
  b2 = v128_xor(b2, a6);\
  b0 = v128_xor(b0, a6);\
  /* spill values y_4, y_5 to memory */\
  TEMP0 = b0;\
  b3 = v128_xor(b3, a7);\
  b1 = v128_xor(b1, a7);\
  TEMP1 = b1;\
  b4 = v128_xor(b4, a0);\
  b2 = v128_xor(b2, a0);\
  /* save values t0, t1, t2 to xmm8, xmm9 and memory */\
  b0 = a0;\
  b5 = v128_xor(b5, a1);\
  b3 = v128_xor(b3, a1);\
  b1 = a1;\
  b6 = v128_xor(b6, a2);\
  b4 = v128_xor(b4, a2);\
  TEMP2 = a2;\
  b7 = v128_xor(b7, a3);\
  b5 = v128_xor(b5, a3);\
  \
  /* compute x_i = t_i + t_{i+3} */\
  a0 = v128_xor(a0, a3);\
  a1 = v128_xor(a1, a4);\
  a2 = v128_xor(a2, a5);\
  a3 = v128_xor(a3, a6);\
  a4 = v128_xor(a4, a7);\
  a5 = v128_xor(a5, b0);\
  a6 = v128_xor(a6, b1);\
  a7 = v128_xor(a7, TEMP2);\
  \
  /* compute z_i : double x_i using temp xmm8 and 1B xmm9 */\
  /* compute w_i : add y_{i+4} */\
  b1 = v128_64( 0x1b1b1b1b1b1b1b1b );\
  MUL2(a0, b0, b1);\
  a0 = v128_xor(a0, TEMP0);\
  MUL2(a1, b0, b1);\
  a1 = v128_xor(a1, TEMP1);\
  MUL2(a2, b0, b1);\
  a2 = v128_xor(a2, b2);\
  MUL2(a3, b0, b1);\
  a3 = v128_xor(a3, b3);\
  MUL2(a4, b0, b1);\
  a4 = v128_xor(a4, b4);\
  MUL2(a5, b0, b1);\
  a5 = v128_xor(a5, b5);\
  MUL2(a6, b0, b1);\
  a6 = v128_xor(a6, b6);\
  MUL2(a7, b0, b1);\
  a7 = v128_xor(a7, b7);\
  \
  /* compute v_i : double w_i      */\
  /* add to y_4 y_5 .. v3, v4, ... */\
  MUL2(a0, b0, b1);\
  b5 = v128_xor(b5, a0);\
  MUL2(a1, b0, b1);\
  b6 = v128_xor(b6, a1);\
  MUL2(a2, b0, b1);\
  b7 = v128_xor(b7, a2);\
  MUL2(a5, b0, b1);\
  b2 = v128_xor(b2, a5);\
  MUL2(a6, b0, b1);\
  b3 = v128_xor(b3, a6);\
  MUL2(a7, b0, b1);\
  b4 = v128_xor(b4, a7);\
  MUL2(a3, b0, b1);\
  MUL2(a4, b0, b1);\
  b0 = TEMP0;\
  b1 = TEMP1;\
  b0 = v128_xor(b0, a3);\
  b1 = v128_xor(b1, a4);\
}/*MixBytes*/

#endif


/* one round
 * a0-a7 = input rows
 * b0-b7 = output rows
 */
#define SUBMIX(a0, a1, a2, a3, a4, a5, a6, a7, b0, b1, b2, b3, b4, b5, b6, b7){\
  /* SubBytes */\
  a0 = v128_aesenclast_nokey( a0 ); \
  a1 = v128_aesenclast_nokey( a1 ); \
  a2 = v128_aesenclast_nokey( a2 ); \
  a3 = v128_aesenclast_nokey( a3 ); \
  a4 = v128_aesenclast_nokey( a4 ); \
  a5 = v128_aesenclast_nokey( a5 ); \
  a6 = v128_aesenclast_nokey( a6 ); \
  a7 = v128_aesenclast_nokey( a7 ); \
  /* MixBytes */\
  MixBytes( a0, a1, a2, a3, a4, a5, a6, a7, b0, b1, b2, b3, b4, b5, b6, b7 ); \
}

#define ROUNDS_P(){\
  u8 round_counter = 0;\
  for(round_counter = 0; round_counter < 14; round_counter+=2) {\
    /* AddRoundConstant P1024 */\
    xmm8 = v128_xor( xmm8, \
             casti_v128( round_const_p, round_counter ) ); \
     /* ShiftBytes P1024 + pre-AESENCLAST */\
    xmm8  = v128_shuffle8( xmm8,  SUBSH_MASK0 ); \
    xmm9  = v128_shuffle8( xmm9,  SUBSH_MASK1 ); \
    xmm10 = v128_shuffle8( xmm10, SUBSH_MASK2 ); \
    xmm11 = v128_shuffle8( xmm11, SUBSH_MASK3 ); \
    xmm12 = v128_shuffle8( xmm12, SUBSH_MASK4 ); \
    xmm13 = v128_shuffle8( xmm13, SUBSH_MASK5 ); \
    xmm14 = v128_shuffle8( xmm14, SUBSH_MASK6 ); \
    xmm15 = v128_shuffle8( xmm15, SUBSH_MASK7 ); \
     /* SubBytes + MixBytes */\
    SUBMIX( xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15, \
            xmm0, xmm1, xmm2,  xmm3,  xmm4,  xmm5,  xmm6,  xmm7 ); \
    /* AddRoundConstant P1024 */\
    xmm0 = v128_xor( xmm0, \
             casti_v128( round_const_p, round_counter+1 ) ); \
    xmm0 = v128_shuffle8( xmm0, SUBSH_MASK0 ); \
    xmm1 = v128_shuffle8( xmm1, SUBSH_MASK1 ); \
    xmm2 = v128_shuffle8( xmm2, SUBSH_MASK2 ); \
    xmm3 = v128_shuffle8( xmm3, SUBSH_MASK3 ); \
    xmm4 = v128_shuffle8( xmm4, SUBSH_MASK4 ); \
    xmm5 = v128_shuffle8( xmm5, SUBSH_MASK5 ); \
    xmm6 = v128_shuffle8( xmm6, SUBSH_MASK6 ); \
    xmm7 = v128_shuffle8( xmm7, SUBSH_MASK7 ); \
    SUBMIX( xmm0, xmm1, xmm2,  xmm3,  xmm4,  xmm5,  xmm6,  xmm7, \
            xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15 ); \
  }\
}

#define ROUNDS_Q(){\
  u8 round_counter = 0;\
  for(round_counter = 0; round_counter < 14; round_counter+=2) {\
    /* AddRoundConstant Q1024 */\
    xmm1 = v128_neg1;\
    xmm8  = v128_xor( xmm8,  xmm1 ); \
    xmm9  = v128_xor( xmm9,  xmm1 ); \
    xmm10 = v128_xor( xmm10, xmm1 ); \
    xmm11 = v128_xor( xmm11, xmm1 ); \
    xmm12 = v128_xor( xmm12, xmm1 ); \
    xmm13 = v128_xor( xmm13, xmm1 ); \
    xmm14 = v128_xor( xmm14, xmm1 ); \
    xmm15 = v128_xor( xmm15, \
              casti_v128( round_const_q, round_counter ) ); \
    /* ShiftBytes Q1024 + pre-AESENCLAST */\
    xmm8  = v128_shuffle8( xmm8,  SUBSH_MASK1 ); \
    xmm9  = v128_shuffle8( xmm9,  SUBSH_MASK3 ); \
    xmm10 = v128_shuffle8( xmm10, SUBSH_MASK5 ); \
    xmm11 = v128_shuffle8( xmm11, SUBSH_MASK7 ); \
    xmm12 = v128_shuffle8( xmm12, SUBSH_MASK0 ); \
    xmm13 = v128_shuffle8( xmm13, SUBSH_MASK2 ); \
    xmm14 = v128_shuffle8( xmm14, SUBSH_MASK4 ); \
    xmm15 = v128_shuffle8( xmm15, SUBSH_MASK6 ); \
    /* SubBytes + MixBytes */\
    SUBMIX( xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15, \
            xmm0, xmm1, xmm2,  xmm3,  xmm4,  xmm5,  xmm6 , xmm7 ); \
    \
    /* AddRoundConstant Q1024 */\
    xmm9 = v128_neg1;\
    xmm0 = v128_xor( xmm0, xmm9 ); \
    xmm1 = v128_xor( xmm1, xmm9 ); \
    xmm2 = v128_xor( xmm2, xmm9 ); \
    xmm3 = v128_xor( xmm3, xmm9 ); \
    xmm4 = v128_xor( xmm4, xmm9 ); \
    xmm5 = v128_xor( xmm5, xmm9 ); \
    xmm6 = v128_xor( xmm6, xmm9 ); \
    xmm7 = v128_xor( xmm7, \
             casti_v128( round_const_q, round_counter+1 ) ); \
    /* ShiftBytes Q1024 + pre-AESENCLAST */\
    xmm0 = v128_shuffle8( xmm0, SUBSH_MASK1 ); \
    xmm1 = v128_shuffle8( xmm1, SUBSH_MASK3 ); \
    xmm2 = v128_shuffle8( xmm2, SUBSH_MASK5 ); \
    xmm3 = v128_shuffle8( xmm3, SUBSH_MASK7 ); \
    xmm4 = v128_shuffle8( xmm4, SUBSH_MASK0 ); \
    xmm5 = v128_shuffle8( xmm5, SUBSH_MASK2 ); \
    xmm6 = v128_shuffle8( xmm6, SUBSH_MASK4 ); \
    xmm7 = v128_shuffle8( xmm7, SUBSH_MASK6 ); \
    /* SubBytes + MixBytes */\
    SUBMIX( xmm0,  xmm1, xmm2,  xmm3,  xmm4,  xmm5,  xmm6,  xmm7, \
            xmm8,  xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15 ); \
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
  t0 = TRANSP_MASK; \
\
  i6 = v128_shuffle8(i6, t0);\
  i0 = v128_shuffle8(i0, t0);\
  i1 = v128_shuffle8(i1, t0);\
  i2 = v128_shuffle8(i2, t0);\
  i3 = v128_shuffle8(i3, t0);\
  t1 = i2;\
  i4 = v128_shuffle8(i4, t0);\
  i5 = v128_shuffle8(i5, t0);\
  t2 = i4;\
  t3 = i6;\
  i7 = v128_shuffle8(i7, t0);\
\
  /* continue with unpack using 4 temp registers */\
  t0 = i0;\
  t2 = v128_unpackhi16(t2, i5);\
  i4 = v128_unpacklo16(i4, i5);\
  t3 = v128_unpackhi16(t3, i7);\
  i6 = v128_unpacklo16(i6, i7);\
  t0 = v128_unpackhi16(t0, i1);\
  t1 = v128_unpackhi16(t1, i3);\
  i2 = v128_unpacklo16(i2, i3);\
  i0 = v128_unpacklo16(i0, i1);\
  /* shuffle with immediate */\
  t0 = gr_shuffle32( t0 ); \
  t1 = gr_shuffle32( t1 ); \
  t2 = gr_shuffle32( t2 ); \
  t3 = gr_shuffle32( t3 ); \
  i0 = gr_shuffle32( i0 ); \
  i2 = gr_shuffle32( i2 ); \
  i4 = gr_shuffle32( i4 ); \
  i6 = gr_shuffle32( i6 ); \
  /* continue with unpack */\
  t4 = i0;\
  i0 = v128_unpacklo32(i0, i2);\
  t4 = v128_unpackhi32(t4, i2);\
  t5 = t0;\
  t0 = v128_unpacklo32(t0, t1);\
  t5 = v128_unpackhi32(t5, t1);\
  t6 = i4;\
  i4 = v128_unpacklo32(i4, i6);\
  t7 = t2;\
  t6 = v128_unpackhi32(t6, i6);\
  i2 = t0;\
  t2 = v128_unpacklo32(t2, t3);\
  i3 = t0;\
  t7 = v128_unpackhi32(t7, t3);\
\
  /* there are now 2 rows in each xmm */\
  /* unpack to get 1 row of CV in each xmm */\
  i1 = i0;\
  i1 = v128_unpackhi64(i1, i4);\
  i0 = v128_unpacklo64(i0, i4);\
  i4 = t4;\
  i3 = v128_unpackhi64(i3, t2);\
  i5 = t4;\
  i2 = v128_unpacklo64(i2, t2);\
  i6 = t5;\
  i5 = v128_unpackhi64(i5, t6);\
  i7 = t5;\
  i4 = v128_unpacklo64(i4, t6);\
  i7 = v128_unpackhi64(i7, t7);\
  i6 = v128_unpacklo64(i6, t7);\
  /* transpose done */\
}/**/

/* Matrix Transpose Inverse
 * input is a 1024-bit state with two rows in one xmm
 * output is a 1024-bit state with two columns in one xmm
 * inputs: i0-i7
 * outputs: (i0, o0, i1, i3, o1, o2, i5, i7)
 * clobbers: t0-t4
 */
#define Matrix_Transpose_INV( i0, i1, i2, i3, i4, i5, i6, i7, \
                              o0, o1, o2, t0, t1, t2, t3, t4 ) \
{ \
  /*  transpose matrix to get output format */\
  o1 = i0; \
  i0 = v128_unpacklo64( i0, i1 ); \
  o1 = v128_unpackhi64( o1, i1 ); \
  t0 = i2; \
  i2 = v128_unpacklo64( i2, i3 ); \
  t0 = v128_unpackhi64( t0, i3 ); \
  t1 = i4; \
  i4 = v128_unpacklo64( i4, i5 ); \
  t1 = v128_unpackhi64( t1, i5 ); \
  t2 = i6; \
  o0 = TRANSP_MASK; \
  i6 = v128_unpacklo64( i6, i7 ); \
  t2 = v128_unpackhi64( t2, i7 ); \
  /* load transpose mask into a register, because it will be used 8 times */\
  i0 = v128_shuffle8( i0, o0 ); \
  i2 = v128_shuffle8( i2, o0 ); \
  i4 = v128_shuffle8( i4, o0 ); \
  i6 = v128_shuffle8( i6, o0 ); \
  o1 = v128_shuffle8( o1, o0 ); \
  t0 = v128_shuffle8( t0, o0 ); \
  t1 = v128_shuffle8( t1, o0 ); \
  t2 = v128_shuffle8( t2, o0 ); \
  /* continue with unpack using 4 temp registers */\
  t3 = i4; \
  o2 = o1; \
  o0 = i0; \
  t4 = t1; \
  \
  t3 = v128_unpackhi16( t3, i6 ); \
  i4 = v128_unpacklo16( i4, i6 ); \
  o0 = v128_unpackhi16( o0, i2 ); \
  i0 = v128_unpacklo16( i0, i2 ); \
  o2 = v128_unpackhi16( o2, t0 ); \
  o1 = v128_unpacklo16( o1, t0 ); \
  t4 = v128_unpackhi16( t4, t2 ); \
  t1 = v128_unpacklo16( t1, t2 ); \
  /* shuffle with immediate */\
  i4 = gr_shuffle32( i4 ); \
  t3 = gr_shuffle32( t3 ); \
  o1 = gr_shuffle32( o1 ); \
  o2 = gr_shuffle32( o2 ); \
  i0 = gr_shuffle32( i0 ); \
  o0 = gr_shuffle32( o0 ); \
  t1 = gr_shuffle32( t1 ); \
  t4 = gr_shuffle32( t4 ); \
  /* continue with unpack */\
  i1 = i0; \
  i3 = o0; \
  i5 = o1; \
  i7 = o2; \
  i0 = v128_unpacklo32( i0, i4 ); \
  i1 = v128_unpackhi32( i1, i4 ); \
  o0 = v128_unpacklo32( o0, t3 ); \
  i3 = v128_unpackhi32( i3, t3 ); \
  o1 = v128_unpacklo32( o1, t1 ); \
  i5 = v128_unpackhi32( i5, t1 ); \
  o2 = v128_unpacklo32( o2, t4 ); \
  i7 = v128_unpackhi32( i7, t4 ); \
  /* transpose done */\
}/**/

#if 0
// not used
void INIT( v128_t* chaining )
{
  static v128_t xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7;
  static v128_t xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15;

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
#endif

void TF1024( v128_t* chaining, const v128_t* message )
{
  static v128_t xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7;
  static v128_t xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15;
  static v128_t QTEMP[8];
  static v128_t TEMP0;
  static v128_t TEMP1;
  static v128_t TEMP2;

#ifdef IACA_TRACE
  IACA_START;
#endif

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
  xmm8 = v128_xor(xmm8,  (chaining[0]));
  xmm9 = v128_xor(xmm9,  (chaining[1]));
  xmm10 = v128_xor(xmm10, (chaining[2]));
  xmm11 = v128_xor(xmm11, (chaining[3]));
  xmm12 = v128_xor(xmm12, (chaining[4]));
  xmm13 = v128_xor(xmm13, (chaining[5]));
  xmm14 = v128_xor(xmm14, (chaining[6]));
  xmm15 = v128_xor(xmm15, (chaining[7]));

  /* compute permutation P */
  /* result: P(CV+M) in xmm8...xmm15 */
  ROUNDS_P();

  /* xor CV to P output (feed-forward) */
  /* result: P(CV+M)+CV in xmm8...xmm15 */
  xmm8 = v128_xor(xmm8,  (chaining[0]));
  xmm9 = v128_xor(xmm9,  (chaining[1]));
  xmm10 = v128_xor(xmm10, (chaining[2]));
  xmm11 = v128_xor(xmm11, (chaining[3]));
  xmm12 = v128_xor(xmm12, (chaining[4]));
  xmm13 = v128_xor(xmm13, (chaining[5]));
  xmm14 = v128_xor(xmm14, (chaining[6]));
  xmm15 = v128_xor(xmm15, (chaining[7]));

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
  xmm8 = v128_xor(xmm8,  (chaining[0]));
  xmm9 = v128_xor(xmm9,  (chaining[1]));
  xmm10 = v128_xor(xmm10, (chaining[2]));
  xmm11 = v128_xor(xmm11, (chaining[3]));
  xmm12 = v128_xor(xmm12, (chaining[4]));
  xmm13 = v128_xor(xmm13, (chaining[5]));
  xmm14 = v128_xor(xmm14, (chaining[6]));
  xmm15 = v128_xor(xmm15, (chaining[7]));

  /* store CV */
  chaining[0] = xmm8;
  chaining[1] = xmm9;
  chaining[2] = xmm10;
  chaining[3] = xmm11;
  chaining[4] = xmm12;
  chaining[5] = xmm13;
  chaining[6] = xmm14;
  chaining[7] = xmm15;

#ifdef IACA_TRACE
  IACA_END;
#endif

  return;
}

void OF1024( v128_t* chaining )
{
  static v128_t xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7;
  static v128_t xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15;
  static v128_t TEMP0;
  static v128_t TEMP1;
  static v128_t TEMP2;

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
  xmm8 = v128_xor(xmm8,  (chaining[0]));
  xmm9 = v128_xor(xmm9,  (chaining[1]));
  xmm10 = v128_xor(xmm10, (chaining[2]));
  xmm11 = v128_xor(xmm11, (chaining[3]));
  xmm12 = v128_xor(xmm12, (chaining[4]));
  xmm13 = v128_xor(xmm13, (chaining[5]));
  xmm14 = v128_xor(xmm14, (chaining[6]));
  xmm15 = v128_xor(xmm15, (chaining[7]));

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

#endif
