/* groestl-intr-aes.h     Aug 2011
 *
 * Groestl implementation with intrinsics using ssse3, sse4.1, and aes
 * instructions.
 * Author: Günther A. Roland, Martin Schläffer, Krystian Matusiewicz
 *
 * This code is placed in the public domain
 */


#if !defined(GROESTL256_INTR_4WAY_H__)
#define GROESTL256_INTR_4WAY_H__ 1
      
#include "groestl256-hash-4way.h"

#if defined(__VAES__)

/* global constants  */
__m512i ROUND_CONST_Lx;
__m512i ROUND_CONST_L0[ROUNDS512];
__m512i ROUND_CONST_L7[ROUNDS512];
//__m512i ROUND_CONST_P[ROUNDS1024];
//__m512i ROUND_CONST_Q[ROUNDS1024];
__m512i TRANSP_MASK;
__m512i SUBSH_MASK[8];
__m512i ALL_1B;
__m512i ALL_FF;

#define tos(a)    #a
#define tostr(a)  tos(a)

/* xmm[i] will be multiplied by 2
 * xmm[j] will be lost
 * xmm[k] has to be all 0x1b */
#define MUL2(i, j, k){\
  j = _mm512_xor_si512(j, j);\
  j = _mm512_movm_epi8( _mm512_cmpgt_epi8_mask(j, i) );\
  i = _mm512_add_epi8(i, i);\
  j = _mm512_and_si512(j, k);\
  i = _mm512_xor_si512(i, j);\
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
#define MixBytes(a0, a1, a2, a3, a4, a5, a6, a7, b0, b1, b2, b3, b4, b5, b6, b7){\
  /* t_i = a_i + a_{i+1} */\
  b6 = a0;\
  b7 = a1;\
  a0 = _mm512_xor_si512(a0, a1);\
  b0 = a2;\
  a1 = _mm512_xor_si512(a1, a2);\
  b1 = a3;\
  a2 = _mm512_xor_si512(a2, a3);\
  b2 = a4;\
  a3 = _mm512_xor_si512(a3, a4);\
  b3 = a5;\
  a4 = _mm512_xor_si512(a4, a5);\
  b4 = a6;\
  a5 = _mm512_xor_si512(a5, a6);\
  b5 = a7;\
  a6 = _mm512_xor_si512(a6, a7);\
  a7 = _mm512_xor_si512(a7, b6);\
  \
  /* build y4 y5 y6 ... in regs xmm8, xmm9, xmm10 by adding t_i*/\
  b0 = _mm512_xor_si512(b0, a4);\
  b6 = _mm512_xor_si512(b6, a4);\
  b1 = _mm512_xor_si512(b1, a5);\
  b7 = _mm512_xor_si512(b7, a5);\
  b2 = _mm512_xor_si512(b2, a6);\
  b0 = _mm512_xor_si512(b0, a6);\
  /* spill values y_4, y_5 to memory */\
  TEMP0 = b0;\
  b3 = _mm512_xor_si512(b3, a7);\
  b1 = _mm512_xor_si512(b1, a7);\
  TEMP1 = b1;\
  b4 = _mm512_xor_si512(b4, a0);\
  b2 = _mm512_xor_si512(b2, a0);\
  /* save values t0, t1, t2 to xmm8, xmm9 and memory */\
  b0 = a0;\
  b5 = _mm512_xor_si512(b5, a1);\
  b3 = _mm512_xor_si512(b3, a1);\
  b1 = a1;\
  b6 = _mm512_xor_si512(b6, a2);\
  b4 = _mm512_xor_si512(b4, a2);\
  TEMP2 = a2;\
  b7 = _mm512_xor_si512(b7, a3);\
  b5 = _mm512_xor_si512(b5, a3);\
  \
  /* compute x_i = t_i + t_{i+3} */\
  a0 = _mm512_xor_si512(a0, a3);\
  a1 = _mm512_xor_si512(a1, a4);\
  a2 = _mm512_xor_si512(a2, a5);\
  a3 = _mm512_xor_si512(a3, a6);\
  a4 = _mm512_xor_si512(a4, a7);\
  a5 = _mm512_xor_si512(a5, b0);\
  a6 = _mm512_xor_si512(a6, b1);\
  a7 = _mm512_xor_si512(a7, TEMP2);\
  \
  /* compute z_i : double x_i using temp xmm8 and 1B xmm9 */\
  /* compute w_i : add y_{i+4} */\
  b1 = m512_const1_64( 0x1b1b1b1b1b1b1b1b );\
  MUL2(a0, b0, b1);\
  a0 = _mm512_xor_si512(a0, TEMP0);\
  MUL2(a1, b0, b1);\
  a1 = _mm512_xor_si512(a1, TEMP1);\
  MUL2(a2, b0, b1);\
  a2 = _mm512_xor_si512(a2, b2);\
  MUL2(a3, b0, b1);\
  a3 = _mm512_xor_si512(a3, b3);\
  MUL2(a4, b0, b1);\
  a4 = _mm512_xor_si512(a4, b4);\
  MUL2(a5, b0, b1);\
  a5 = _mm512_xor_si512(a5, b5);\
  MUL2(a6, b0, b1);\
  a6 = _mm512_xor_si512(a6, b6);\
  MUL2(a7, b0, b1);\
  a7 = _mm512_xor_si512(a7, b7);\
  \
  /* compute v_i : double w_i      */\
  /* add to y_4 y_5 .. v3, v4, ... */\
  MUL2(a0, b0, b1);\
  b5 = _mm512_xor_si512(b5, a0);\
  MUL2(a1, b0, b1);\
  b6 = _mm512_xor_si512(b6, a1);\
  MUL2(a2, b0, b1);\
  b7 = _mm512_xor_si512(b7, a2);\
  MUL2(a5, b0, b1);\
  b2 = _mm512_xor_si512(b2, a5);\
  MUL2(a6, b0, b1);\
  b3 = _mm512_xor_si512(b3, a6);\
  MUL2(a7, b0, b1);\
  b4 = _mm512_xor_si512(b4, a7);\
  MUL2(a3, b0, b1);\
  MUL2(a4, b0, b1);\
  b0 = TEMP0;\
  b1 = TEMP1;\
  b0 = _mm512_xor_si512(b0, a3);\
  b1 = _mm512_xor_si512(b1, a4);\
}/*MixBytes*/

// calculate the round constants seperately and load at startup

#define SET_CONSTANTS(){\
  ALL_1B = _mm512_set1_epi32( 0x1b1b1b1b );\
  TRANSP_MASK   = _mm512_set_epi32( \
                         0x3f373b33, 0x3e363a32, 0x3d353931, 0x3c343830, \
                         0x2f272b23, 0x2e262a22, 0x2d252921, 0x2c242820, \
                         0x1f171b13, 0x1e161a12, 0x1d151911, 0x1c141810, \
                         0x0f070b03, 0x0e060a02, 0x0d050901, 0x0c040800 ); \
  SUBSH_MASK[0] = _mm512_set_epi32( \
                         0x33363a3d, 0x38323539, 0x3c3f3134, 0x373b3e30, \
                         0x23262a2d, 0x28222529, 0x2c2f2124, 0x272b2e20, \
                         0x13161a1d, 0x18121519, 0x1c1f1114, 0x171b1e10, \
                         0x03060a0d, 0x08020509, 0x0c0f0104, 0x070b0e00 ); \
  SUBSH_MASK[1] = _mm512_set_epi32( \
                         0x34373c3f, 0x3a33363b, 0x3e393235, 0x303d3831, \
                         0x24272c2f, 0x2a23262b, 0x2e292225, 0x202d2821, \
                         0x14171c1f, 0x1a13161b, 0x1e191215, 0x101d1801, \
                         0x04070c0f, 0x0a03060b, 0x0e090205, 0x000d0801 );\
  SUBSH_MASK[2] = _mm512_set_epi32( \
                         0x35303e39, 0x3c34373d, 0x383b3336, 0x313f3a32, \
                         0x25202e29, 0x2c24272d, 0x282b2326, 0x212f2a22, \
                         0x15101e19, 0x1c14171d, 0x181b1316, 0x111f1a12, \
                         0x05000e09, 0x0c04070d, 0x080b0306, 0x010f0a02 );\
  SUBSH_MASK[3] = _mm512_set_epi32( \
                         0x3631383b, 0x3e35303f, 0x3a3d3437, 0x32393c33, \
                         0x2621282b, 0x2e25202f, 0x2a2d2427, 0x22292c23, \
                         0x1611181b, 0x1e15101f, 0x1a1d1417, 0x12191c13, \
                         0x0601080b, 0x0e05000f, 0x0a0d0407, 0x02090c03 );\
  SUBSH_MASK[4] = _mm512_set_epi32( \
                         0x3732393c, 0x3f363138, 0x3b3e3530, 0x333a3d34, \
                         0x2722292c, 0x2f262128, 0x2b2e2520, 0x232a2d24, \
                         0x1712191c, 0x1f161118, 0x1b1e1510, 0x131a1d14, \
                         0x0702090c, 0x0f060108, 0x0b0e0500, 0x030a0d04 );\
  SUBSH_MASK[5] = _mm512_set_epi32( \
                         0x30333b3e, 0x3937323a, 0x3d383631, 0x343c3f35, \
                         0x20232b2e, 0x2927222a, 0x2d282621, 0x242c2f25, \
                         0x10131b1e, 0x1917121a, 0x1d181611, 0x141c1f15, \
                         0x00030b0e, 0x0907020a, 0x0d080601, 0x040c0f05 );\
  SUBSH_MASK[6] = _mm512_set_epi32( \
                         0x31343d38, 0x3b30333c, 0x3f3a3732, 0x353e3936, \
                         0x21242d28, 0x2b20232c, 0x2f2a2722, 0x252e2926, \
                         0x11141d18, 0x1b10131c, 0x1f1a1712, 0x151e1916, \
                         0x01040d08, 0x0b00030c, 0x0f0a0702, 0x050e0906 );\
  SUBSH_MASK[7] = _mm512_set_epi32( \
                         0x32353f3a, 0x3d31343e, 0x393c3033, 0x36383b37, \
                         0x22252f2a, 0x2d21242e, 0x292c2023, 0x26282b27, \
                         0x12151f1a, 0x1d11141e, 0x191c1013, 0x16181b17, \
                         0x02050f0a, 0x0d01040e, 0x090c0003, 0x06080b07 );\
  for ( i = 0; i < ROUNDS512; i++ ) \
  {\
    ROUND_CONST_L0[i] = _mm512_set4_epi32( 0xffffffff, 0xffffffff, \
          0x70605040 ^ ( i * 0x01010101 ), 0x30201000 ^ ( i * 0x01010101 ) ); \
    ROUND_CONST_L7[i] = _mm512_set4_epi32( 0x8f9fafbf ^ ( i * 0x01010101 ), \
          0xcfdfefff ^ ( i * 0x01010101 ), 0x00000000, 0x00000000 ); \
  }\
  ROUND_CONST_Lx = _mm512_set4_epi32( 0xffffffff, 0xffffffff, \
                                      0x00000000, 0x00000000 ); \
}while(0);\

#define ROUND(i, a0, a1, a2, a3, a4, a5, a6, a7, b0, b1, b2, b3, b4, b5, b6, b7){\
  /* AddRoundConstant */\
  b1 = ROUND_CONST_Lx;\
  a0 = _mm512_xor_si512( a0, (ROUND_CONST_L0[i]) );\
  a1 = _mm512_xor_si512( a1, b1 );\
  a2 = _mm512_xor_si512( a2, b1 );\
  a3 = _mm512_xor_si512( a3, b1 );\
  a4 = _mm512_xor_si512( a4, b1 );\
  a5 = _mm512_xor_si512( a5, b1 );\
  a6 = _mm512_xor_si512( a6, b1 );\
  a7 = _mm512_xor_si512( a7, (ROUND_CONST_L7[i]) );\
  \
  /* ShiftBytes + SubBytes (interleaved) */\
  b0 = _mm512_xor_si512( b0, b0 );\
  a0 = _mm512_shuffle_epi8( a0, (SUBSH_MASK[0]) );\
  a0 = _mm512_aesenclast_epi128(a0, b0 );\
  a1 = _mm512_shuffle_epi8( a1, (SUBSH_MASK[1]) );\
  a1 = _mm512_aesenclast_epi128(a1, b0 );\
  a2 = _mm512_shuffle_epi8( a2, (SUBSH_MASK[2]) );\
  a2 = _mm512_aesenclast_epi128(a2, b0 );\
  a3 = _mm512_shuffle_epi8( a3, (SUBSH_MASK[3]) );\
  a3 = _mm512_aesenclast_epi128(a3, b0 );\
  a4 = _mm512_shuffle_epi8( a4, (SUBSH_MASK[4]) );\
  a4 = _mm512_aesenclast_epi128(a4, b0 );\
  a5 = _mm512_shuffle_epi8( a5, (SUBSH_MASK[5]) );\
  a5 = _mm512_aesenclast_epi128(a5, b0 );\
  a6 = _mm512_shuffle_epi8( a6, (SUBSH_MASK[6]) );\
  a6 = _mm512_aesenclast_epi128(a6, b0 );\
  a7 = _mm512_shuffle_epi8( a7, (SUBSH_MASK[7]) );\
  a7 = _mm512_aesenclast_epi128( a7, b0 );\
  \
  /* MixBytes */\
  MixBytes(a0, a1, a2, a3, a4, a5, a6, a7, b0, b1, b2, b3, b4, b5, b6, b7);\
\
}

/* 10 rounds, P and Q in parallel */
#define ROUNDS_P_Q(){\
  ROUND(0, xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7);\
  ROUND(1, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15);\
  ROUND(2, xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7);\
  ROUND(3, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15);\
  ROUND(4, xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7);\
  ROUND(5, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15);\
  ROUND(6, xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7);\
  ROUND(7, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15);\
  ROUND(8, xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7);\
  ROUND(9, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15);\
}

/* Matrix Transpose Step 1
 * input is a 512-bit state with two columns in one xmm
 * output is a 512-bit state with two rows in one xmm
 * inputs: i0-i3
 * outputs: i0, o1-o3
 * clobbers: t0
 */
#define Matrix_Transpose_A(i0, i1, i2, i3, o1, o2, o3, t0){\
  t0 = TRANSP_MASK;\
  \
  i0 = _mm512_shuffle_epi8( i0, t0 );\
  i1 = _mm512_shuffle_epi8( i1, t0 );\
  i2 = _mm512_shuffle_epi8( i2, t0 );\
  i3 = _mm512_shuffle_epi8( i3, t0 );\
  \
  o1 = i0;\
  t0 = i2;\
  \
  i0 = _mm512_unpacklo_epi16( i0, i1 );\
  o1 = _mm512_unpackhi_epi16( o1, i1 );\
  i2 = _mm512_unpacklo_epi16( i2, i3 );\
  t0 = _mm512_unpackhi_epi16( t0, i3 );\
  \
  i0 = _mm512_shuffle_epi32( i0, 216 );\
  o1 = _mm512_shuffle_epi32( o1, 216 );\
  i2 = _mm512_shuffle_epi32( i2, 216 );\
  t0 = _mm512_shuffle_epi32( t0, 216 );\
  \
  o2 = i0;\
  o3 = o1;\
  \
  i0 = _mm512_unpacklo_epi32( i0, i2 );\
  o1 = _mm512_unpacklo_epi32( o1, t0 );\
  o2 = _mm512_unpackhi_epi32( o2, i2 );\
  o3 = _mm512_unpackhi_epi32( o3, t0 );\
}/**/

/* Matrix Transpose Step 2
 * input are two 512-bit states with two rows in one xmm
 * output are two 512-bit states with one row of each state in one xmm
 * inputs: i0-i3 = P, i4-i7 = Q
 * outputs: (i0, o1-o7) = (P|Q)
 * possible reassignments: (output reg = input reg)
 * * i1 -> o3-7
 * * i2 -> o5-7
 * * i3 -> o7
 * * i4 -> o3-7
 * * i5 -> o6-7
 */
#define Matrix_Transpose_B(i0, i1, i2, i3, i4, i5, i6, i7, o1, o2, o3, o4, o5, o6, o7){\
  o1 = i0;\
  o2 = i1;\
  i0 = _mm512_unpacklo_epi64( i0, i4 );\
  o1 = _mm512_unpackhi_epi64( o1, i4 );\
  o3 = i1;\
  o4 = i2;\
  o2 = _mm512_unpacklo_epi64( o2, i5 );\
  o3 = _mm512_unpackhi_epi64( o3, i5 );\
  o5 = i2;\
  o6 = i3;\
  o4 = _mm512_unpacklo_epi64( o4, i6 );\
  o5 = _mm512_unpackhi_epi64( o5, i6 );\
  o7 = i3;\
  o6 = _mm512_unpacklo_epi64( o6, i7 );\
  o7 = _mm512_unpackhi_epi64( o7, i7 );\
}/**/

/* Matrix Transpose Inverse Step 2
 * input are two 512-bit states with one row of each state in one xmm
 * output are two 512-bit states with two rows in one xmm
 * inputs: i0-i7 = (P|Q)
 * outputs: (i0, i2, i4, i6) = P, (o0-o3) = Q
 */
#define Matrix_Transpose_B_INV(i0, i1, i2, i3, i4, i5, i6, i7, o0, o1, o2, o3){\
  o0 = i0;\
  i0 = _mm512_unpacklo_epi64( i0, i1 );\
  o0 = _mm512_unpackhi_epi64( o0, i1 );\
  o1 = i2;\
  i2 = _mm512_unpacklo_epi64( i2, i3 );\
  o1 = _mm512_unpackhi_epi64( o1, i3 );\
  o2 = i4;\
  i4 = _mm512_unpacklo_epi64( i4, i5 );\
  o2 = _mm512_unpackhi_epi64( o2, i5 );\
  o3 = i6;\
  i6 = _mm512_unpacklo_epi64( i6, i7 );\
  o3 = _mm512_unpackhi_epi64( o3, i7 );\
}/**/


/* Matrix Transpose Output Step 2
 * input is one 512-bit state with two rows in one xmm
 * output is one 512-bit state with one row in the low 64-bits of one xmm
 * inputs: i0,i2,i4,i6 = S
 * outputs: (i0-7) = (0|S)
 */
#define Matrix_Transpose_O_B(i0, i1, i2, i3, i4, i5, i6, i7, t0){\
  t0 = _mm512_xor_si512( t0, t0 );\
  i1 = i0;\
  i3 = i2;\
  i5 = i4;\
  i7 = i6;\
  i0 = _mm512_unpacklo_epi64( i0, t0 );\
  i1 = _mm512_unpackhi_epi64( i1, t0 );\
  i2 = _mm512_unpacklo_epi64( i2, t0 );\
  i3 = _mm512_unpackhi_epi64( i3, t0 );\
  i4 = _mm512_unpacklo_epi64( i4, t0 );\
  i5 = _mm512_unpackhi_epi64( i5, t0 );\
  i6 = _mm512_unpacklo_epi64( i6, t0 );\
  i7 = _mm512_unpackhi_epi64( i7, t0 );\
}/**/

/* Matrix Transpose Output Inverse Step 2
 * input is one 512-bit state with one row in the low 64-bits of one xmm
 * output is one 512-bit state with two rows in one xmm
 * inputs: i0-i7 = (0|S)
 * outputs: (i0, i2, i4, i6) = S
 */
#define Matrix_Transpose_O_B_INV(i0, i1, i2, i3, i4, i5, i6, i7){\
  i0 = _mm512_unpacklo_epi64( i0, i1 );\
  i2 = _mm512_unpacklo_epi64( i2, i3 );\
  i4 = _mm512_unpacklo_epi64( i4, i5 );\
  i6 = _mm512_unpacklo_epi64( i6, i7 );\
}/**/



void INIT256_4way( __m512i* chaining )
{
  static __m512i xmm0, xmm2, xmm6, xmm7;
  static __m512i xmm12, xmm13, xmm14, xmm15;

  /* load IV into registers xmm12 - xmm15 */
  xmm12 = chaining[0];
  xmm13 = chaining[1];
  xmm14 = chaining[2];
  xmm15 = chaining[3];

  /* transform chaining value from column ordering into row ordering */
  /* we put two rows (64 bit) of the IV into one 128-bit XMM register */
  Matrix_Transpose_A(xmm12, xmm13, xmm14, xmm15, xmm2, xmm6, xmm7, xmm0);

  /* store transposed IV */
  chaining[0] = xmm12;
  chaining[1] = xmm2;
  chaining[2] = xmm6;
  chaining[3] = xmm7;
}

void TF512_4way( __m512i* chaining, __m512i* message )
{
  static __m512i xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7;
  static __m512i xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15;
  static __m512i TEMP0;
  static __m512i TEMP1;
  static __m512i TEMP2;

  /* load message into registers xmm12 - xmm15 */
  xmm12 = message[0];
  xmm13 = message[1];
  xmm14 = message[2];
  xmm15 = message[3];

  /* transform message M from column ordering into row ordering */
  /* we first put two rows (64 bit) of the message into one 128-bit xmm register */
  Matrix_Transpose_A(xmm12, xmm13, xmm14, xmm15, xmm2, xmm6, xmm7, xmm0);

  /* load previous chaining value */
  /* we first put two rows (64 bit) of the CV into one 128-bit xmm register */
  xmm8 = chaining[0];
  xmm0 = chaining[1];
  xmm4 = chaining[2];
  xmm5 = chaining[3];

  /* xor message to CV get input of P */
  /* result: CV+M in xmm8, xmm0, xmm4, xmm5 */
  xmm8 = _mm512_xor_si512( xmm8, xmm12 );
  xmm0 = _mm512_xor_si512( xmm0, xmm2 );
  xmm4 = _mm512_xor_si512( xmm4, xmm6 );
  xmm5 = _mm512_xor_si512( xmm5, xmm7 );

  /* there are now 2 rows of the Groestl state (P and Q) in each xmm register */
  /* unpack to get 1 row of P (64 bit) and Q (64 bit) into one xmm register */
  /* result: the 8 rows of P and Q in xmm8 - xmm12 */
  Matrix_Transpose_B(xmm8, xmm0, xmm4, xmm5, xmm12, xmm2, xmm6, xmm7, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15);

  /* compute the two permutations P and Q in parallel */
  ROUNDS_P_Q();

  /* unpack again to get two rows of P or two rows of Q in one xmm register */
  Matrix_Transpose_B_INV(xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15, xmm0, xmm1, xmm2, xmm3);

  /* xor output of P and Q */
  /* result: P(CV+M)+Q(M) in xmm0...xmm3 */
  xmm0 = _mm512_xor_si512( xmm0, xmm8 );
  xmm1 = _mm512_xor_si512( xmm1, xmm10 );
  xmm2 = _mm512_xor_si512( xmm2, xmm12 );
  xmm3 = _mm512_xor_si512( xmm3, xmm14 );

  /* xor CV (feed-forward) */
  /* result: P(CV+M)+Q(M)+CV in xmm0...xmm3 */
  xmm0 = _mm512_xor_si512( xmm0, (chaining[0]) );
  xmm1 = _mm512_xor_si512( xmm1, (chaining[1]) );
  xmm2 = _mm512_xor_si512( xmm2, (chaining[2]) );
  xmm3 = _mm512_xor_si512( xmm3, (chaining[3]) );

  /* store CV */
  chaining[0] = xmm0;
  chaining[1] = xmm1;
  chaining[2] = xmm2;
  chaining[3] = xmm3;

  return;
}

void OF512_4way( __m512i* chaining )
{
  static __m512i xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7;
  static __m512i xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15;
  static __m512i TEMP0;
  static __m512i TEMP1;
  static __m512i TEMP2;

  /* load CV into registers xmm8, xmm10, xmm12, xmm14 */
  xmm8 = chaining[0];
  xmm10 = chaining[1];
  xmm12 = chaining[2];
  xmm14 = chaining[3];

  /* there are now 2 rows of the CV in one xmm register */
  /* unpack to get 1 row of P (64 bit) into one half of an xmm register */
  /* result: the 8 input rows of P in xmm8 - xmm15 */
  Matrix_Transpose_O_B(xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15, xmm0);

  /* compute the permutation P */
  /* result: the output of P(CV) in xmm8 - xmm15 */
  ROUNDS_P_Q();

  /* unpack again to get two rows of P in one xmm register */
  /* result: P(CV) in xmm8, xmm10, xmm12, xmm14 */
  Matrix_Transpose_O_B_INV(xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15);

  /* xor CV to P output (feed-forward) */
  /* result: P(CV)+CV in xmm8, xmm10, xmm12, xmm14 */
  xmm8  = _mm512_xor_si512( xmm8,  (chaining[0]) );
  xmm10 = _mm512_xor_si512( xmm10, (chaining[1]) );
  xmm12 = _mm512_xor_si512( xmm12, (chaining[2]) );
  xmm14 = _mm512_xor_si512( xmm14, (chaining[3]) );

  /* transform state back from row ordering into column ordering */
  /* result: final hash value in xmm9, xmm11 */
  Matrix_Transpose_A(xmm8, xmm10, xmm12, xmm14, xmm4, xmm9, xmm11, xmm0);

  /* we only need to return the truncated half of the state */
  chaining[2] = xmm9;
  chaining[3] = xmm11;
}

#endif  // VAES
#endif  // GROESTL512_INTR_4WAY_H__
