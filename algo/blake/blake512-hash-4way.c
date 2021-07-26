/* $Id: blake.c 252 2011-06-07 17:55:14Z tp $ */
/*
 * BLAKE implementation.
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
#include <limits.h>

#include "blake-hash-4way.h"

#ifdef __cplusplus
extern "C"{
#endif

#ifdef _MSC_VER
#pragma warning (disable: 4146)
#endif

// Blake-512 common
   
/*
static const sph_u64 IV512[8] = {
	SPH_C64(0x6A09E667F3BCC908), SPH_C64(0xBB67AE8584CAA73B),
	SPH_C64(0x3C6EF372FE94F82B), SPH_C64(0xA54FF53A5F1D36F1),
	SPH_C64(0x510E527FADE682D1), SPH_C64(0x9B05688C2B3E6C1F),
	SPH_C64(0x1F83D9ABFB41BD6B), SPH_C64(0x5BE0CD19137E2179)
};

static const sph_u64 salt_zero_big[4] = { 0, 0, 0, 0 };

static const unsigned sigma[16][16] = {
	{  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
	{ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
	{ 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
	{  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
	{  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
	{  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
	{ 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
	{ 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
	{  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
	{ 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 },
	{  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
	{ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
	{ 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
	{  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
	{  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
	{  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 }
};

static const sph_u64 CB[16] = {
   SPH_C64(0x243F6A8885A308D3), SPH_C64(0x13198A2E03707344),
   SPH_C64(0xA4093822299F31D0), SPH_C64(0x082EFA98EC4E6C89),
   SPH_C64(0x452821E638D01377), SPH_C64(0xBE5466CF34E90C6C),
   SPH_C64(0xC0AC29B7C97C50DD), SPH_C64(0x3F84D5B5B5470917),
   SPH_C64(0x9216D5D98979FB1B), SPH_C64(0xD1310BA698DFB5AC),
   SPH_C64(0x2FFD72DBD01ADFB7), SPH_C64(0xB8E1AFED6A267E96),
   SPH_C64(0xBA7C9045F12C7F99), SPH_C64(0x24A19947B3916CF7),
   SPH_C64(0x0801F2E2858EFC16), SPH_C64(0x636920D871574E69)

*/

#define Z00   0
#define Z01   1
#define Z02   2
#define Z03   3
#define Z04   4
#define Z05   5
#define Z06   6
#define Z07   7
#define Z08   8
#define Z09   9
#define Z0A   A
#define Z0B   B
#define Z0C   C
#define Z0D   D
#define Z0E   E
#define Z0F   F

#define Z10   E
#define Z11   A
#define Z12   4
#define Z13   8
#define Z14   9
#define Z15   F
#define Z16   D
#define Z17   6
#define Z18   1
#define Z19   C
#define Z1A   0
#define Z1B   2
#define Z1C   B
#define Z1D   7
#define Z1E   5
#define Z1F   3

#define Z20   B
#define Z21   8
#define Z22   C
#define Z23   0
#define Z24   5
#define Z25   2
#define Z26   F
#define Z27   D
#define Z28   A
#define Z29   E
#define Z2A   3
#define Z2B   6
#define Z2C   7
#define Z2D   1
#define Z2E   9
#define Z2F   4

#define Z30   7
#define Z31   9
#define Z32   3
#define Z33   1
#define Z34   D
#define Z35   C
#define Z36   B
#define Z37   E
#define Z38   2
#define Z39   6
#define Z3A   5
#define Z3B   A
#define Z3C   4
#define Z3D   0
#define Z3E   F
#define Z3F   8

#define Z40   9
#define Z41   0
#define Z42   5
#define Z43   7
#define Z44   2
#define Z45   4
#define Z46   A
#define Z47   F
#define Z48   E
#define Z49   1
#define Z4A   B
#define Z4B   C
#define Z4C   6
#define Z4D   8
#define Z4E   3
#define Z4F   D

#define Z50   2
#define Z51   C
#define Z52   6
#define Z53   A
#define Z54   0
#define Z55   B
#define Z56   8
#define Z57   3
#define Z58   4
#define Z59   D
#define Z5A   7
#define Z5B   5
#define Z5C   F
#define Z5D   E
#define Z5E   1
#define Z5F   9

#define Z60   C
#define Z61   5
#define Z62   1
#define Z63   F
#define Z64   E
#define Z65   D
#define Z66   4
#define Z67   A
#define Z68   0
#define Z69   7
#define Z6A   6
#define Z6B   3
#define Z6C   9
#define Z6D   2
#define Z6E   8
#define Z6F   B

#define Z70   D
#define Z71   B
#define Z72   7
#define Z73   E
#define Z74   C
#define Z75   1
#define Z76   3
#define Z77   9
#define Z78   5
#define Z79   0
#define Z7A   F
#define Z7B   4
#define Z7C   8
#define Z7D   6
#define Z7E   2
#define Z7F   A

#define Z80   6
#define Z81   F
#define Z82   E
#define Z83   9
#define Z84   B
#define Z85   3
#define Z86   0
#define Z87   8
#define Z88   C
#define Z89   2
#define Z8A   D
#define Z8B   7
#define Z8C   1
#define Z8D   4
#define Z8E   A
#define Z8F   5

#define Z90   A
#define Z91   2
#define Z92   8
#define Z93   4
#define Z94   7
#define Z95   6
#define Z96   1
#define Z97   5
#define Z98   F
#define Z99   B
#define Z9A   9
#define Z9B   E
#define Z9C   3
#define Z9D   C
#define Z9E   D
#define Z9F   0

#define Mx(r, i)    Mx_(Z ## r ## i)
#define Mx_(n)      Mx__(n)
#define Mx__(n)     M ## n

#define CBx(r, i)   CBx_(Z ## r ## i)
#define CBx_(n)     CBx__(n)
#define CBx__(n)    CB ## n

#define CB0   0x243F6A8885A308D3
#define CB1   0x13198A2E03707344
#define CB2   0xA4093822299F31D0
#define CB3   0x082EFA98EC4E6C89
#define CB4   0x452821E638D01377
#define CB5   0xBE5466CF34E90C6C
#define CB6   0xC0AC29B7C97C50DD
#define CB7   0x3F84D5B5B5470917
#define CB8   0x9216D5D98979FB1B
#define CB9   0xD1310BA698DFB5AC
#define CBA   0x2FFD72DBD01ADFB7
#define CBB   0xB8E1AFED6A267E96
#define CBC   0xBA7C9045F12C7F99
#define CBD   0x24A19947B3916CF7
#define CBE   0x0801F2E2858EFC16
#define CBF   0x636920D871574E69

#define READ_STATE64(state)   do { \
      H0 = (state)->H[0]; \
      H1 = (state)->H[1]; \
      H2 = (state)->H[2]; \
      H3 = (state)->H[3]; \
      H4 = (state)->H[4]; \
      H5 = (state)->H[5]; \
      H6 = (state)->H[6]; \
      H7 = (state)->H[7]; \
      T0 = (state)->T0; \
      T1 = (state)->T1; \
   } while (0)

#define WRITE_STATE64(state)   do { \
      (state)->H[0] = H0; \
      (state)->H[1] = H1; \
      (state)->H[2] = H2; \
      (state)->H[3] = H3; \
      (state)->H[4] = H4; \
      (state)->H[5] = H5; \
      (state)->H[6] = H6; \
      (state)->H[7] = H7; \
      (state)->T0 = T0; \
      (state)->T1 = T1; \
   } while (0)

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

// Blake-512 8 way AVX512

#define GB_8WAY(m0, m1, c0, c1, a, b, c, d)   do { \
   a = _mm512_add_epi64( _mm512_add_epi64( _mm512_xor_si512( \
                 _mm512_set1_epi64( c1 ), m0 ), b ), a ); \
   d = mm512_ror_64( _mm512_xor_si512( d, a ), 32 ); \
   c = _mm512_add_epi64( c, d ); \
   b = mm512_ror_64( _mm512_xor_si512( b, c ), 25 ); \
   a = _mm512_add_epi64( _mm512_add_epi64( _mm512_xor_si512( \
                 _mm512_set1_epi64( c0 ), m1 ), b ), a ); \
   d = mm512_ror_64( _mm512_xor_si512( d, a ), 16 ); \
   c = _mm512_add_epi64( c, d ); \
   b = mm512_ror_64( _mm512_xor_si512( b, c ), 11 ); \
} while (0)

#define ROUND_B_8WAY(r)   do { \
   GB_8WAY(Mx(r, 0), Mx(r, 1), CBx(r, 0), CBx(r, 1), V0, V4, V8, VC); \
   GB_8WAY(Mx(r, 2), Mx(r, 3), CBx(r, 2), CBx(r, 3), V1, V5, V9, VD); \
   GB_8WAY(Mx(r, 4), Mx(r, 5), CBx(r, 4), CBx(r, 5), V2, V6, VA, VE); \
   GB_8WAY(Mx(r, 6), Mx(r, 7), CBx(r, 6), CBx(r, 7), V3, V7, VB, VF); \
   GB_8WAY(Mx(r, 8), Mx(r, 9), CBx(r, 8), CBx(r, 9), V0, V5, VA, VF); \
   GB_8WAY(Mx(r, A), Mx(r, B), CBx(r, A), CBx(r, B), V1, V6, VB, VC); \
   GB_8WAY(Mx(r, C), Mx(r, D), CBx(r, C), CBx(r, D), V2, V7, V8, VD); \
   GB_8WAY(Mx(r, E), Mx(r, F), CBx(r, E), CBx(r, F), V3, V4, V9, VE); \
   } while (0)

#define DECL_STATE64_8WAY \
   __m512i H0, H1, H2, H3, H4, H5, H6, H7; \
   uint64_t T0, T1;

#define COMPRESS64_8WAY( buf )   do \
{ \
  __m512i M0, M1, M2, M3, M4, M5, M6, M7; \
  __m512i M8, M9, MA, MB, MC, MD, ME, MF; \
  __m512i V0, V1, V2, V3, V4, V5, V6, V7; \
  __m512i V8, V9, VA, VB, VC, VD, VE, VF; \
  __m512i shuf_bswap64; \
  V0 = H0; \
  V1 = H1; \
  V2 = H2; \
  V3 = H3; \
  V4 = H4; \
  V5 = H5; \
  V6 = H6; \
  V7 = H7; \
  V8 = m512_const1_64( CB0 );  \
  V9 = m512_const1_64( CB1 );  \
  VA = m512_const1_64( CB2 );  \
  VB = m512_const1_64( CB3 );  \
  VC = _mm512_xor_si512( _mm512_set1_epi64( T0 ), \
                         m512_const1_64( CB4 ) );  \
  VD = _mm512_xor_si512( _mm512_set1_epi64( T0 ), \
                         m512_const1_64( CB5 ) );  \
  VE = _mm512_xor_si512( _mm512_set1_epi64( T1 ), \
                         m512_const1_64( CB6 ) );  \
  VF = _mm512_xor_si512( _mm512_set1_epi64( T1 ), \
                         m512_const1_64( CB7 ) );  \
  shuf_bswap64 = m512_const_64( 0x38393a3b3c3d3e3f, 0x3031323334353637, \
                                0x28292a2b2c2d2e2f, 0x2021222324252627, \
                                0x18191a1b1c1d1e1f, 0x1011121314151617, \
                                0x08090a0b0c0d0e0f, 0x0001020304050607 ); \
  M0 = _mm512_shuffle_epi8( *(buf+ 0), shuf_bswap64 ); \
  M1 = _mm512_shuffle_epi8( *(buf+ 1), shuf_bswap64 ); \
  M2 = _mm512_shuffle_epi8( *(buf+ 2), shuf_bswap64 ); \
  M3 = _mm512_shuffle_epi8( *(buf+ 3), shuf_bswap64 ); \
  M4 = _mm512_shuffle_epi8( *(buf+ 4), shuf_bswap64 ); \
  M5 = _mm512_shuffle_epi8( *(buf+ 5), shuf_bswap64 ); \
  M6 = _mm512_shuffle_epi8( *(buf+ 6), shuf_bswap64 ); \
  M7 = _mm512_shuffle_epi8( *(buf+ 7), shuf_bswap64 ); \
  M8 = _mm512_shuffle_epi8( *(buf+ 8), shuf_bswap64 ); \
  M9 = _mm512_shuffle_epi8( *(buf+ 9), shuf_bswap64 ); \
  MA = _mm512_shuffle_epi8( *(buf+10), shuf_bswap64 ); \
  MB = _mm512_shuffle_epi8( *(buf+11), shuf_bswap64 ); \
  MC = _mm512_shuffle_epi8( *(buf+12), shuf_bswap64 ); \
  MD = _mm512_shuffle_epi8( *(buf+13), shuf_bswap64 ); \
  ME = _mm512_shuffle_epi8( *(buf+14), shuf_bswap64 ); \
  MF = _mm512_shuffle_epi8( *(buf+15), shuf_bswap64 ); \
  ROUND_B_8WAY(0); \
  ROUND_B_8WAY(1); \
  ROUND_B_8WAY(2); \
  ROUND_B_8WAY(3); \
  ROUND_B_8WAY(4); \
  ROUND_B_8WAY(5); \
  ROUND_B_8WAY(6); \
  ROUND_B_8WAY(7); \
  ROUND_B_8WAY(8); \
  ROUND_B_8WAY(9); \
  ROUND_B_8WAY(0); \
  ROUND_B_8WAY(1); \
  ROUND_B_8WAY(2); \
  ROUND_B_8WAY(3); \
  ROUND_B_8WAY(4); \
  ROUND_B_8WAY(5); \
  H0 = mm512_xor3( V8, V0, H0 ); \
  H1 = mm512_xor3( V9, V1, H1 ); \
  H2 = mm512_xor3( VA, V2, H2 ); \
  H3 = mm512_xor3( VB, V3, H3 ); \
  H4 = mm512_xor3( VC, V4, H4 ); \
  H5 = mm512_xor3( VD, V5, H5 ); \
  H6 = mm512_xor3( VE, V6, H6 ); \
  H7 = mm512_xor3( VF, V7, H7 ); \
} while (0)

void blake512_8way_compress( blake_8way_big_context *sc )
{ 
  __m512i M0, M1, M2, M3, M4, M5, M6, M7;
  __m512i M8, M9, MA, MB, MC, MD, ME, MF;
  __m512i V0, V1, V2, V3, V4, V5, V6, V7;
  __m512i V8, V9, VA, VB, VC, VD, VE, VF;
  __m512i shuf_bswap64;

  V0 = sc->H[0];
  V1 = sc->H[1];
  V2 = sc->H[2];
  V3 = sc->H[3];
  V4 = sc->H[4];
  V5 = sc->H[5];
  V6 = sc->H[6];
  V7 = sc->H[7];
  V8 = m512_const1_64( CB0 );
  V9 = m512_const1_64( CB1 );
  VA = m512_const1_64( CB2 );
  VB = m512_const1_64( CB3 );
  VC = _mm512_xor_si512( _mm512_set1_epi64( sc->T0 ),
                            m512_const1_64( CB4 ) );
  VD = _mm512_xor_si512( _mm512_set1_epi64( sc->T0 ),
                            m512_const1_64( CB5 ) );
  VE = _mm512_xor_si512( _mm512_set1_epi64( sc->T1 ),
                            m512_const1_64( CB6 ) );
  VF = _mm512_xor_si512( _mm512_set1_epi64( sc->T1 ),
                            m512_const1_64( CB7 ) );

  shuf_bswap64 = m512_const_64( 0x38393a3b3c3d3e3f, 0x3031323334353637,
                                0x28292a2b2c2d2e2f, 0x2021222324252627,
                                0x18191a1b1c1d1e1f, 0x1011121314151617,
                                0x08090a0b0c0d0e0f, 0x0001020304050607 );

  M0 = _mm512_shuffle_epi8( sc->buf[ 0], shuf_bswap64 );
  M1 = _mm512_shuffle_epi8( sc->buf[ 1], shuf_bswap64 );
  M2 = _mm512_shuffle_epi8( sc->buf[ 2], shuf_bswap64 );
  M3 = _mm512_shuffle_epi8( sc->buf[ 3], shuf_bswap64 );
  M4 = _mm512_shuffle_epi8( sc->buf[ 4], shuf_bswap64 );
  M5 = _mm512_shuffle_epi8( sc->buf[ 5], shuf_bswap64 );
  M6 = _mm512_shuffle_epi8( sc->buf[ 6], shuf_bswap64 );
  M7 = _mm512_shuffle_epi8( sc->buf[ 7], shuf_bswap64 );
  M8 = _mm512_shuffle_epi8( sc->buf[ 8], shuf_bswap64 );
  M9 = _mm512_shuffle_epi8( sc->buf[ 9], shuf_bswap64 );
  MA = _mm512_shuffle_epi8( sc->buf[10], shuf_bswap64 );
  MB = _mm512_shuffle_epi8( sc->buf[11], shuf_bswap64 );
  MC = _mm512_shuffle_epi8( sc->buf[12], shuf_bswap64 );
  MD = _mm512_shuffle_epi8( sc->buf[13], shuf_bswap64 );
  ME = _mm512_shuffle_epi8( sc->buf[14], shuf_bswap64 );
  MF = _mm512_shuffle_epi8( sc->buf[15], shuf_bswap64 );

  ROUND_B_8WAY(0);
  ROUND_B_8WAY(1);
  ROUND_B_8WAY(2);
  ROUND_B_8WAY(3);
  ROUND_B_8WAY(4);
  ROUND_B_8WAY(5);
  ROUND_B_8WAY(6);
  ROUND_B_8WAY(7);
  ROUND_B_8WAY(8);
  ROUND_B_8WAY(9);
  ROUND_B_8WAY(0);
  ROUND_B_8WAY(1);
  ROUND_B_8WAY(2);
  ROUND_B_8WAY(3);
  ROUND_B_8WAY(4);
  ROUND_B_8WAY(5);

  sc->H[0] = mm512_xor3( V8, V0, sc->H[0] );
  sc->H[1] = mm512_xor3( V9, V1, sc->H[1] );
  sc->H[2] = mm512_xor3( VA, V2, sc->H[2] );
  sc->H[3] = mm512_xor3( VB, V3, sc->H[3] );
  sc->H[4] = mm512_xor3( VC, V4, sc->H[4] );
  sc->H[5] = mm512_xor3( VD, V5, sc->H[5] );
  sc->H[6] = mm512_xor3( VE, V6, sc->H[6] );
  sc->H[7] = mm512_xor3( VF, V7, sc->H[7] );
}

void blake512_8way_init( blake_8way_big_context *sc )
{
   casti_m512i( sc->H, 0 ) = m512_const1_64( 0x6A09E667F3BCC908 );
   casti_m512i( sc->H, 1 ) = m512_const1_64( 0xBB67AE8584CAA73B );
   casti_m512i( sc->H, 2 ) = m512_const1_64( 0x3C6EF372FE94F82B );
   casti_m512i( sc->H, 3 ) = m512_const1_64( 0xA54FF53A5F1D36F1 );
   casti_m512i( sc->H, 4 ) = m512_const1_64( 0x510E527FADE682D1 );
   casti_m512i( sc->H, 5 ) = m512_const1_64( 0x9B05688C2B3E6C1F );
   casti_m512i( sc->H, 6 ) = m512_const1_64( 0x1F83D9ABFB41BD6B );
   casti_m512i( sc->H, 7 ) = m512_const1_64( 0x5BE0CD19137E2179 );

   sc->T0 = sc->T1 = 0;
   sc->ptr = 0;
}

static void
blake64_8way( blake_8way_big_context *sc, const void *data, size_t len )
{
   __m512i *vdata = (__m512i*)data;
   __m512i *buf;
   size_t ptr;
   DECL_STATE64_8WAY

   const int buf_size = 128;  //  sizeof/8

// 64, 80 bytes: 1st pass copy data. 2nd pass copy padding and compress.   
// 128 bytes: 1st pass copy data, compress. 2nd pass copy padding, compress.
   
   buf = sc->buf;
   ptr = sc->ptr;
   if ( len < (buf_size - ptr) )
   {
      memcpy_512( buf + (ptr>>3), vdata, len>>3 );
      ptr += len;
      sc->ptr = ptr;
      return;
   }

   READ_STATE64(sc);
   while ( len > 0 )
   {
      size_t clen;

      clen = buf_size - ptr;
      if ( clen > len )
      clen = len;
      memcpy_512( buf + (ptr>>3), vdata, clen>>3 );
      ptr += clen;
      vdata = vdata + (clen>>3);
      len -= clen;
      if ( ptr == buf_size )
      {
         if ( ( T0 = T0 + 1024 ) < 1024 )
            T1 = T1 + 1;
         COMPRESS64_8WAY( buf );
         ptr = 0;
      }
   }
   WRITE_STATE64(sc);
   sc->ptr = ptr;

   }

static void
blake64_8way_close( blake_8way_big_context *sc, void *dst )
{
   __m512i buf[16];
   size_t ptr;
   unsigned bit_len;
   uint64_t th, tl;

   ptr = sc->ptr;
   bit_len = ((unsigned)ptr << 3);
   buf[ptr>>3] = m512_const1_64( 0x80 );
   tl = sc->T0 + bit_len;
   th = sc->T1;
   if (ptr == 0 )
   {
   sc->T0 = 0xFFFFFFFFFFFFFC00ULL;
   sc->T1 = 0xFFFFFFFFFFFFFFFFULL;
   }
   else if ( sc->T0 == 0 )
   {
   sc->T0 = 0xFFFFFFFFFFFFFC00ULL + bit_len;
   sc->T1 = sc->T1 - 1;
   }
   else
   {
        sc->T0 -= 1024 - bit_len;
   }
   if ( ptr <= 104 )
   {
       memset_zero_512( buf + (ptr>>3) + 1, (104-ptr) >> 3 );
       buf[104>>3] = _mm512_or_si512( buf[104>>3],
                                 m512_const1_64( 0x0100000000000000ULL ) );
       buf[112>>3] = m512_const1_64( bswap_64( th ) );
       buf[120>>3] = m512_const1_64( bswap_64( tl ) );

       blake64_8way( sc, buf + (ptr>>3), 128 - ptr );
   }
   else
  {
       memset_zero_512( buf + (ptr>>3) + 1, (120 - ptr) >> 3 );

       blake64_8way( sc, buf + (ptr>>3), 128 - ptr );
       sc->T0 = 0xFFFFFFFFFFFFFC00ULL;
       sc->T1 = 0xFFFFFFFFFFFFFFFFULL;
       memset_zero_512( buf, 112>>3 );
       buf[104>>3] = m512_const1_64( 0x0100000000000000ULL );
       buf[112>>3] = m512_const1_64( bswap_64( th ) );
       buf[120>>3] = m512_const1_64( bswap_64( tl ) );

       blake64_8way( sc, buf, 128 );
   }
   mm512_block_bswap_64( (__m512i*)dst, sc->H );
}

// init, update & close
void blake512_8way_full( blake_8way_big_context *sc, void * dst, 
                        const void *data, size_t len )
{
   
// init

   casti_m512i( sc->H, 0 ) = m512_const1_64( 0x6A09E667F3BCC908 );
   casti_m512i( sc->H, 1 ) = m512_const1_64( 0xBB67AE8584CAA73B );
   casti_m512i( sc->H, 2 ) = m512_const1_64( 0x3C6EF372FE94F82B );
   casti_m512i( sc->H, 3 ) = m512_const1_64( 0xA54FF53A5F1D36F1 );
   casti_m512i( sc->H, 4 ) = m512_const1_64( 0x510E527FADE682D1 );
   casti_m512i( sc->H, 5 ) = m512_const1_64( 0x9B05688C2B3E6C1F );
   casti_m512i( sc->H, 6 ) = m512_const1_64( 0x1F83D9ABFB41BD6B );
   casti_m512i( sc->H, 7 ) = m512_const1_64( 0x5BE0CD19137E2179 );

   sc->T0 = sc->T1 = 0;
   sc->ptr = 0;

// update

   memcpy_512( sc->buf, (__m512i*)data, len>>3 );
   sc->ptr = len;
   if ( len == 128 )
   {
      if ( ( sc->T0 = sc->T0 + 1024 ) < 1024 )
            sc->T1 = sc->T1 + 1;
      blake512_8way_compress( sc );
      sc->ptr = 0;
   }

// close

   size_t ptr64 = sc->ptr >> 3;
   unsigned bit_len;
   uint64_t th, tl;

   bit_len = sc->ptr << 3;
   sc->buf[ptr64] = m512_const1_64( 0x80 );
   tl = sc->T0 + bit_len;
   th = sc->T1;

   if ( ptr64 == 0 )
   {
   sc->T0 = 0xFFFFFFFFFFFFFC00ULL;
   sc->T1 = 0xFFFFFFFFFFFFFFFFULL;
   }
   else if ( sc->T0 == 0 )
   {
   sc->T0 = 0xFFFFFFFFFFFFFC00ULL + bit_len;
   sc->T1 = sc->T1 - 1;
   }
   else
      sc->T0 -= 1024 - bit_len;

   memset_zero_512( sc->buf + ptr64 + 1, 13 - ptr64 );
   sc->buf[13] = m512_const1_64( 0x0100000000000000ULL );
   sc->buf[14] = m512_const1_64( bswap_64( th ) );
   sc->buf[15] = m512_const1_64( bswap_64( tl ) );

   if ( ( sc->T0 = sc->T0 + 1024 ) < 1024 )
       sc->T1 = sc->T1 + 1;

   blake512_8way_compress( sc );
   
   mm512_block_bswap_64( (__m512i*)dst, sc->H );
}
   
void
blake512_8way_update(void *cc, const void *data, size_t len)
{
   blake64_8way(cc, data, len);
}

void
blake512_8way_close(void *cc, void *dst)
{
   blake64_8way_close(cc, dst);
}

#endif  // AVX512

// Blake-512 4 way

#define GB_4WAY(m0, m1, c0, c1, a, b, c, d)   do { \
   a = _mm256_add_epi64( _mm256_add_epi64( _mm256_xor_si256( \
                 _mm256_set1_epi64x( c1 ), m0 ), b ), a ); \
   d = mm256_ror_64( _mm256_xor_si256( d, a ), 32 ); \
   c = _mm256_add_epi64( c, d ); \
   b = mm256_ror_64( _mm256_xor_si256( b, c ), 25 ); \
   a = _mm256_add_epi64( _mm256_add_epi64( _mm256_xor_si256( \
                 _mm256_set1_epi64x( c0 ), m1 ), b ), a ); \
   d = mm256_ror_64( _mm256_xor_si256( d, a ), 16 ); \
   c = _mm256_add_epi64( c, d ); \
   b = mm256_ror_64( _mm256_xor_si256( b, c ), 11 ); \
} while (0)

#define ROUND_B_4WAY(r)   do { \
	GB_4WAY(Mx(r, 0), Mx(r, 1), CBx(r, 0), CBx(r, 1), V0, V4, V8, VC); \
	GB_4WAY(Mx(r, 2), Mx(r, 3), CBx(r, 2), CBx(r, 3), V1, V5, V9, VD); \
	GB_4WAY(Mx(r, 4), Mx(r, 5), CBx(r, 4), CBx(r, 5), V2, V6, VA, VE); \
	GB_4WAY(Mx(r, 6), Mx(r, 7), CBx(r, 6), CBx(r, 7), V3, V7, VB, VF); \
	GB_4WAY(Mx(r, 8), Mx(r, 9), CBx(r, 8), CBx(r, 9), V0, V5, VA, VF); \
	GB_4WAY(Mx(r, A), Mx(r, B), CBx(r, A), CBx(r, B), V1, V6, VB, VC); \
	GB_4WAY(Mx(r, C), Mx(r, D), CBx(r, C), CBx(r, D), V2, V7, V8, VD); \
	GB_4WAY(Mx(r, E), Mx(r, F), CBx(r, E), CBx(r, F), V3, V4, V9, VE); \
	} while (0)

#define DECL_STATE64_4WAY \
	__m256i H0, H1, H2, H3, H4, H5, H6, H7; \
	uint64_t T0, T1;

#define COMPRESS64_4WAY   do \
{ \
  __m256i M0, M1, M2, M3, M4, M5, M6, M7; \
  __m256i M8, M9, MA, MB, MC, MD, ME, MF; \
  __m256i V0, V1, V2, V3, V4, V5, V6, V7; \
  __m256i V8, V9, VA, VB, VC, VD, VE, VF; \
  __m256i shuf_bswap64; \
  V0 = H0; \
  V1 = H1; \
  V2 = H2; \
  V3 = H3; \
  V4 = H4; \
  V5 = H5; \
  V6 = H6; \
  V7 = H7; \
  V8 = m256_const1_64( CB0 );  \
  V9 = m256_const1_64( CB1 );  \
  VA = m256_const1_64( CB2 );  \
  VB = m256_const1_64( CB3 );  \
  VC = _mm256_xor_si256( _mm256_set1_epi64x( T0 ), \
                         m256_const1_64( CB4 ) );  \
  VD = _mm256_xor_si256( _mm256_set1_epi64x( T0 ), \
                         m256_const1_64( CB5 ) );  \
  VE = _mm256_xor_si256( _mm256_set1_epi64x( T1 ), \
                         m256_const1_64( CB6 ) );  \
  VF = _mm256_xor_si256( _mm256_set1_epi64x( T1 ), \
                         m256_const1_64( CB7 ) );  \
  shuf_bswap64 = m256_const_64( 0x18191a1b1c1d1e1f, 0x1011121314151617, \
                                0x08090a0b0c0d0e0f, 0x0001020304050607 ); \
  M0 = _mm256_shuffle_epi8( *(buf+ 0), shuf_bswap64 ); \
  M1 = _mm256_shuffle_epi8( *(buf+ 1), shuf_bswap64 ); \
  M2 = _mm256_shuffle_epi8( *(buf+ 2), shuf_bswap64 ); \
  M3 = _mm256_shuffle_epi8( *(buf+ 3), shuf_bswap64 ); \
  M4 = _mm256_shuffle_epi8( *(buf+ 4), shuf_bswap64 ); \
  M5 = _mm256_shuffle_epi8( *(buf+ 5), shuf_bswap64 ); \
  M6 = _mm256_shuffle_epi8( *(buf+ 6), shuf_bswap64 ); \
  M7 = _mm256_shuffle_epi8( *(buf+ 7), shuf_bswap64 ); \
  M8 = _mm256_shuffle_epi8( *(buf+ 8), shuf_bswap64 ); \
  M9 = _mm256_shuffle_epi8( *(buf+ 9), shuf_bswap64 ); \
  MA = _mm256_shuffle_epi8( *(buf+10), shuf_bswap64 ); \
  MB = _mm256_shuffle_epi8( *(buf+11), shuf_bswap64 ); \
  MC = _mm256_shuffle_epi8( *(buf+12), shuf_bswap64 ); \
  MD = _mm256_shuffle_epi8( *(buf+13), shuf_bswap64 ); \
  ME = _mm256_shuffle_epi8( *(buf+14), shuf_bswap64 ); \
  MF = _mm256_shuffle_epi8( *(buf+15), shuf_bswap64 ); \
  ROUND_B_4WAY(0); \
  ROUND_B_4WAY(1); \
  ROUND_B_4WAY(2); \
  ROUND_B_4WAY(3); \
  ROUND_B_4WAY(4); \
  ROUND_B_4WAY(5); \
  ROUND_B_4WAY(6); \
  ROUND_B_4WAY(7); \
  ROUND_B_4WAY(8); \
  ROUND_B_4WAY(9); \
  ROUND_B_4WAY(0); \
  ROUND_B_4WAY(1); \
  ROUND_B_4WAY(2); \
  ROUND_B_4WAY(3); \
  ROUND_B_4WAY(4); \
  ROUND_B_4WAY(5); \
  H0 = mm256_xor3( V8, V0, H0 ); \
  H1 = mm256_xor3( V9, V1, H1 ); \
  H2 = mm256_xor3( VA, V2, H2 ); \
  H3 = mm256_xor3( VB, V3, H3 ); \
  H4 = mm256_xor3( VC, V4, H4 ); \
  H5 = mm256_xor3( VD, V5, H5 ); \
  H6 = mm256_xor3( VE, V6, H6 ); \
  H7 = mm256_xor3( VF, V7, H7 ); \
} while (0)


void blake512_4way_compress( blake_4way_big_context *sc )
{
  __m256i M0, M1, M2, M3, M4, M5, M6, M7;
  __m256i M8, M9, MA, MB, MC, MD, ME, MF;
  __m256i V0, V1, V2, V3, V4, V5, V6, V7;
  __m256i V8, V9, VA, VB, VC, VD, VE, VF;
  __m256i shuf_bswap64;

  V0 = sc->H[0];
  V1 = sc->H[1];
  V2 = sc->H[2];
  V3 = sc->H[3];
  V4 = sc->H[4];
  V5 = sc->H[5];
  V6 = sc->H[6];
  V7 = sc->H[7];
  V8 = m256_const1_64( CB0 );
  V9 = m256_const1_64( CB1 );
  VA = m256_const1_64( CB2 );
  VB = m256_const1_64( CB3 );
  VC = _mm256_xor_si256( _mm256_set1_epi64x( sc->T0 ),
                             m256_const1_64( CB4 ) );
  VD = _mm256_xor_si256( _mm256_set1_epi64x( sc->T0 ),
                             m256_const1_64( CB5 ) );
  VE = _mm256_xor_si256( _mm256_set1_epi64x( sc->T1 ),
                             m256_const1_64( CB6 ) );
  VF = _mm256_xor_si256( _mm256_set1_epi64x( sc->T1 ),
                             m256_const1_64( CB7 ) );
  shuf_bswap64 = m256_const_64( 0x18191a1b1c1d1e1f, 0x1011121314151617,
                                0x08090a0b0c0d0e0f, 0x0001020304050607 );

  M0 = _mm256_shuffle_epi8( sc->buf[ 0], shuf_bswap64 );
  M1 = _mm256_shuffle_epi8( sc->buf[ 1], shuf_bswap64 );
  M2 = _mm256_shuffle_epi8( sc->buf[ 2], shuf_bswap64 );
  M3 = _mm256_shuffle_epi8( sc->buf[ 3], shuf_bswap64 );
  M4 = _mm256_shuffle_epi8( sc->buf[ 4], shuf_bswap64 );
  M5 = _mm256_shuffle_epi8( sc->buf[ 5], shuf_bswap64 );
  M6 = _mm256_shuffle_epi8( sc->buf[ 6], shuf_bswap64 );
  M7 = _mm256_shuffle_epi8( sc->buf[ 7], shuf_bswap64 );
  M8 = _mm256_shuffle_epi8( sc->buf[ 8], shuf_bswap64 );
  M9 = _mm256_shuffle_epi8( sc->buf[ 9], shuf_bswap64 );
  MA = _mm256_shuffle_epi8( sc->buf[10], shuf_bswap64 );
  MB = _mm256_shuffle_epi8( sc->buf[11], shuf_bswap64 );
  MC = _mm256_shuffle_epi8( sc->buf[12], shuf_bswap64 );
  MD = _mm256_shuffle_epi8( sc->buf[13], shuf_bswap64 );
  ME = _mm256_shuffle_epi8( sc->buf[14], shuf_bswap64 );
  MF = _mm256_shuffle_epi8( sc->buf[15], shuf_bswap64 );

  ROUND_B_4WAY(0);
  ROUND_B_4WAY(1);
  ROUND_B_4WAY(2);
  ROUND_B_4WAY(3);
  ROUND_B_4WAY(4);
  ROUND_B_4WAY(5);
  ROUND_B_4WAY(6);
  ROUND_B_4WAY(7);
  ROUND_B_4WAY(8);
  ROUND_B_4WAY(9);
  ROUND_B_4WAY(0);
  ROUND_B_4WAY(1);
  ROUND_B_4WAY(2);
  ROUND_B_4WAY(3);
  ROUND_B_4WAY(4);
  ROUND_B_4WAY(5);

  sc->H[0] = mm256_xor3( V8, V0, sc->H[0] );
  sc->H[1] = mm256_xor3( V9, V1, sc->H[1] );
  sc->H[2] = mm256_xor3( VA, V2, sc->H[2] );
  sc->H[3] = mm256_xor3( VB, V3, sc->H[3] );
  sc->H[4] = mm256_xor3( VC, V4, sc->H[4] );
  sc->H[5] = mm256_xor3( VD, V5, sc->H[5] );
  sc->H[6] = mm256_xor3( VE, V6, sc->H[6] );
  sc->H[7] = mm256_xor3( VF, V7, sc->H[7] );
}

void blake512_4way_init( blake_4way_big_context *sc )
{
   casti_m256i( sc->H, 0 ) = m256_const1_64( 0x6A09E667F3BCC908 );
   casti_m256i( sc->H, 1 ) = m256_const1_64( 0xBB67AE8584CAA73B );
   casti_m256i( sc->H, 2 ) = m256_const1_64( 0x3C6EF372FE94F82B );
   casti_m256i( sc->H, 3 ) = m256_const1_64( 0xA54FF53A5F1D36F1 );
   casti_m256i( sc->H, 4 ) = m256_const1_64( 0x510E527FADE682D1 );
   casti_m256i( sc->H, 5 ) = m256_const1_64( 0x9B05688C2B3E6C1F );
   casti_m256i( sc->H, 6 ) = m256_const1_64( 0x1F83D9ABFB41BD6B );
   casti_m256i( sc->H, 7 ) = m256_const1_64( 0x5BE0CD19137E2179 );

   sc->T0 = sc->T1 = 0;
   sc->ptr = 0;
}

static void
blake64_4way( blake_4way_big_context *sc, const void *data, size_t len)
{
   __m256i *vdata = (__m256i*)data;
   __m256i *buf;
   size_t ptr;
   DECL_STATE64_4WAY

   const int buf_size = 128;  //  sizeof/8 

   buf = sc->buf;
   ptr = sc->ptr;
   if ( len < (buf_size - ptr) )
   {
   	memcpy_256( buf + (ptr>>3), vdata, len>>3 );
	   ptr += len;
	   sc->ptr = ptr;
	   return;
   }

   READ_STATE64(sc);
   while ( len > 0 )
   {
   	size_t clen;

	   clen = buf_size - ptr;
	   if ( clen > len )
		   clen = len;
   	memcpy_256( buf + (ptr>>3), vdata, clen>>3 );
	   ptr += clen;
	   vdata = vdata + (clen>>3);
	   len -= clen;
	   if ( ptr == buf_size )
      {
		   if ( (T0 = T0 + 1024 ) < 1024 )
			   T1 = SPH_T64(T1 + 1);
	   	COMPRESS64_4WAY;
		   ptr = 0;
	   }
   }
   WRITE_STATE64(sc);
   sc->ptr = ptr;
}

static void
blake64_4way_close( blake_4way_big_context *sc, void *dst )
{
   __m256i buf[16];
   size_t ptr;
   unsigned bit_len;
   uint64_t th, tl;

   ptr = sc->ptr;
   bit_len = ((unsigned)ptr << 3);
   buf[ptr>>3] = m256_const1_64( 0x80 );
   tl = sc->T0 + bit_len;
   th = sc->T1;
   if (ptr == 0 )
   {
	sc->T0 = 0xFFFFFFFFFFFFFC00ULL;
	sc->T1 = 0xFFFFFFFFFFFFFFFFULL;
   }
   else if ( sc->T0 == 0 )
   {
	sc->T0 = 0xFFFFFFFFFFFFFC00ULL + bit_len;
	sc->T1 = sc->T1 - 1;
   } 
   else
   {
        sc->T0 -= 1024 - bit_len;
   }

   if ( ptr <= 104 )
   {
       memset_zero_256( buf + (ptr>>3) + 1, (104-ptr) >> 3 );
       buf[104>>3] = _mm256_or_si256( buf[104>>3],
                                 m256_const1_64( 0x0100000000000000ULL ) );
       buf[112>>3] = m256_const1_64( bswap_64( th ) );
       buf[120>>3] = m256_const1_64( bswap_64( tl ) );

       blake64_4way( sc, buf + (ptr>>3), 128 - ptr );
   }
   else
   {
       memset_zero_256( buf + (ptr>>3) + 1, (120 - ptr) >> 3 );

       blake64_4way( sc, buf + (ptr>>3), 128 - ptr );
       sc->T0 = SPH_C64(0xFFFFFFFFFFFFFC00ULL);
       sc->T1 = SPH_C64(0xFFFFFFFFFFFFFFFFULL);
       memset_zero_256( buf, 112>>3 ); 
       buf[104>>3] = m256_const1_64( 0x0100000000000000ULL );
       buf[112>>3] = m256_const1_64( bswap_64( th ) );
       buf[120>>3] = m256_const1_64( bswap_64( tl ) );

       blake64_4way( sc, buf, 128 );
   }
   mm256_block_bswap_64( (__m256i*)dst, sc->H );
}

// init, update & close
void blake512_4way_full( blake_4way_big_context *sc, void * dst,
                         const void *data, size_t len )
{

// init

   casti_m256i( sc->H, 0 ) = m256_const1_64( 0x6A09E667F3BCC908 );
   casti_m256i( sc->H, 1 ) = m256_const1_64( 0xBB67AE8584CAA73B );
   casti_m256i( sc->H, 2 ) = m256_const1_64( 0x3C6EF372FE94F82B );
   casti_m256i( sc->H, 3 ) = m256_const1_64( 0xA54FF53A5F1D36F1 );
   casti_m256i( sc->H, 4 ) = m256_const1_64( 0x510E527FADE682D1 );
   casti_m256i( sc->H, 5 ) = m256_const1_64( 0x9B05688C2B3E6C1F );
   casti_m256i( sc->H, 6 ) = m256_const1_64( 0x1F83D9ABFB41BD6B );
   casti_m256i( sc->H, 7 ) = m256_const1_64( 0x5BE0CD19137E2179 );

   sc->T0 = sc->T1 = 0;
   sc->ptr = 0;

// update

   memcpy_256( sc->buf, (__m256i*)data, len>>3 );
   sc->ptr += len;
   if ( len == 128 )
   {
      if ( ( sc->T0 = sc->T0 + 1024 ) < 1024 )
         sc->T1 =  sc->T1 + 1;
      blake512_4way_compress( sc );
      sc->ptr = 0;
   }

// close

   size_t ptr64 = sc->ptr >> 3;
   unsigned bit_len;
   uint64_t th, tl;

   bit_len = sc->ptr << 3;
   sc->buf[ptr64] = m256_const1_64( 0x80 );
   tl = sc->T0 + bit_len;
   th = sc->T1;
   if ( sc->ptr == 0 )
   {
      sc->T0 = 0xFFFFFFFFFFFFFC00ULL;
      sc->T1 = 0xFFFFFFFFFFFFFFFFULL;
   }
   else if ( sc->T0 == 0 )
   {
      sc->T0 = 0xFFFFFFFFFFFFFC00ULL + bit_len;
      sc->T1 = sc->T1 - 1;
   }
   else
        sc->T0 -= 1024 - bit_len;

   memset_zero_256( sc->buf + ptr64 + 1, 13 - ptr64 );
   sc->buf[13] = m256_const1_64( 0x0100000000000000ULL );
   sc->buf[14] = m256_const1_64( bswap_64( th ) );
   sc->buf[15] = m256_const1_64( bswap_64( tl ) );

   if ( ( sc->T0 = sc->T0 + 1024 ) < 1024 )
       sc->T1 = sc->T1 + 1;

   blake512_4way_compress( sc );

   mm256_block_bswap_64( (__m256i*)dst, sc->H );
}

void
blake512_4way_update(void *cc, const void *data, size_t len)
{
	blake64_4way(cc, data, len);
}

void
blake512_4way_close(void *cc, void *dst)
{
   blake64_4way_close( cc, dst );
}

#ifdef __cplusplus
}
#endif

#endif
