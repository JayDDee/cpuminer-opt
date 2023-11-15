/* $Id: blake.c 252 2011-06-07 17:55:14Z tp $ */
/*
 * BLAKE implementation.
 *
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2007-2010  Projet RNRT SAPHIR
 *               2016-2022  JayDDee246@gmail.com
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

//#if defined (__SSE4_2__)

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>

#include "blake256-hash.h"

// Blake-256

static const uint32_t IV256[8] =
{
	0x6A09E667, 0xBB67AE85,	0x3C6EF372, 0xA54FF53A,
	0x510E527F, 0x9B05688C,	0x1F83D9AB, 0x5BE0CD19
};

#if 0

// Blake-256 4 & 8 way, Blake-512 4 way

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

#endif

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

// Blake-256 4 & 8 way

#define CSx(r, i)   CSx_(Z ## r ## i)
#define CSx_(n)     CSx__(n)
#define CSx__(n)    CS ## n

#define CS0   0x243F6A88
#define CS1   0x85A308D3
#define CS2   0x13198A2E
#define CS3   0x03707344
#define CS4   0xA4093822
#define CS5   0x299F31D0
#define CS6   0x082EFA98
#define CS7   0xEC4E6C89
#define CS8   0x452821E6
#define CS9   0x38D01377
#define CSA   0xBE5466CF
#define CSB   0x34E90C6C
#define CSC   0xC0AC29B7
#define CSD   0xC97C50DD
#define CSE   0x3F84D5B5
#define CSF   0xB5470917

/////////////////////////////////////////
//
// Blake-256 1 way SIMD
// Only used for prehash, otherwise 4x32 is used with SSE2.

#define BLAKE256_ROUND( r ) \
{ \
   V0 = v128_add32( V0, v128_add32( V1, \
                           v128_set32( CSx( r, 7 ) ^ Mx( r, 6 ), \
                                       CSx( r, 5 ) ^ Mx( r, 4 ), \
                                       CSx( r, 3 ) ^ Mx( r, 2 ), \
                                       CSx( r, 1 ) ^ Mx( r, 0 ) ) ) ); \
   V3 = v128_ror32( v128_xor( V3, V0 ), 16 ); \
   V2 = v128_add32( V2, V3 ); \
   V1 = v128_ror32( v128_xor( V1, V2 ), 12 ); \
   V0 = v128_add32( V0, v128_add32( V1, \
                           v128_set32( CSx( r, 6 ) ^ Mx( r, 7 ), \
                                       CSx( r, 4 ) ^ Mx( r, 5 ), \
                                       CSx( r, 2 ) ^ Mx( r, 3 ), \
                                       CSx( r, 0 ) ^ Mx( r, 1 ) ) ) ); \
   V3 = v128_ror32( v128_xor( V3, V0 ), 8 ); \
   V2 = v128_add32( V2, V3 ); \
   V1 = v128_ror32( v128_xor( V1, V2 ), 7 ); \
   V0 = v128_shufll32( V0 ); \
   V3 = v128_swap64( V3 ); \
   V2 = v128_shuflr32( V2 ); \
   V0 = v128_add32( V0, v128_add32( V1, \
                           v128_set32( CSx( r, D ) ^ Mx( r, C ), \
                                       CSx( r, B ) ^ Mx( r, A ), \
                                       CSx( r, 9 ) ^ Mx( r, 8 ), \
                                       CSx( r, F ) ^ Mx( r, E ) ) ) ); \
   V3 = v128_ror32( v128_xor( V3, V0 ), 16 ); \
   V2 = v128_add32( V2, V3 ); \
   V1 = v128_ror32( v128_xor( V1, V2 ), 12 ); \
   V0 = v128_add32( V0, v128_add32( V1, \
                           v128_set32( CSx( r, C ) ^ Mx( r, D ), \
                                       CSx( r, A ) ^ Mx( r, B ), \
                                       CSx( r, 8 ) ^ Mx( r, 9 ), \
                                       CSx( r, E ) ^ Mx( r, F ) ) ) ); \
   V3 = v128_ror32( v128_xor( V3, V0 ), 8 ); \
   V2 = v128_add32( V2, V3 ); \
   V1 = v128_ror32( v128_xor( V1, V2 ), 7 ); \
   V0 = v128_shuflr32( V0 ); \
   V3 = v128_swap64( V3 ); \
   V2 = v128_shufll32( V2 ); \
}

// Default is 14 rounds, blakecoin & vanilla are 8.
void blake256_transform_le( uint32_t *H, const uint32_t *buf,
                            const uint32_t T0, const uint32_t T1, int rounds )
{
   v128_t V0, V1, V2, V3;
   uint32_t M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, MA, MB, MC, MD, ME, MF;
   V0 = casti_v128( H, 0 );
   V1 = casti_v128( H, 1 );
   V2 = v128_set32( 0x03707344, 0x13198A2E, 0x85A308D3, 0x243F6A88 );
   V3 = v128_set32( T1 ^ 0xEC4E6C89, T1 ^ 0x082EFA98,
                    T0 ^ 0x299F31D0, T0 ^ 0xA4093822 );
   M0 = buf[ 0];
   M1 = buf[ 1];
   M2 = buf[ 2];
   M3 = buf[ 3];
   M4 = buf[ 4];
   M5 = buf[ 5];
   M6 = buf[ 6];
   M7 = buf[ 7];
   M8 = buf[ 8];
   M9 = buf[ 9];
   MA = buf[10];
   MB = buf[11];
   MC = buf[12];
   MD = buf[13];
   ME = buf[14];
   MF = buf[15];
   BLAKE256_ROUND( 0 );
   BLAKE256_ROUND( 1 );
   BLAKE256_ROUND( 2 );
   BLAKE256_ROUND( 3 );
   BLAKE256_ROUND( 4 );
   BLAKE256_ROUND( 5 );
   BLAKE256_ROUND( 6 );
   BLAKE256_ROUND( 7 );
   if ( rounds > 8 )     // 14
   {
      BLAKE256_ROUND( 8 );
      BLAKE256_ROUND( 9 );
      BLAKE256_ROUND( 0 );
      BLAKE256_ROUND( 1 );
      BLAKE256_ROUND( 2 );
      BLAKE256_ROUND( 3 );
   }
   casti_v128( H, 0 ) = v128_xor( casti_v128( H, 0 ), v128_xor( V0, V2 ) );
   casti_v128( H, 1 ) = v128_xor( casti_v128( H, 1 ), v128_xor( V1, V3 ) );
}

////////////////////////////////////////////
//
//    Blake-256 4 way SSE2, NEON

#define GS_4X32( m0, m1, c0, c1, a, b, c, d ) \
{ \
   a = v128_add32( v128_add32( a, b ), v128_xor( v128_32( c1 ), m0 ) ); \
   d = v128_ror32( v128_xor( d, a ), 16 ); \
   c = v128_add32( c, d ); \
   b = v128_ror32( v128_xor( b, c ), 12 ); \
   a = v128_add32( v128_add32( a, b ), v128_xor( v128_32( c0 ), m1 ) ); \
   d = v128_ror32( v128_xor( d, a ), 8 ); \
   c = v128_add32( c, d ); \
   b = v128_ror32( v128_xor( b, c ), 7 ); \
}

#define ROUND_S_4X32(r) \
{ \
	GS_4X32(Mx(r, 0), Mx(r, 1), CSx(r, 0), CSx(r, 1), V0, V4, V8, VC); \
	GS_4X32(Mx(r, 2), Mx(r, 3), CSx(r, 2), CSx(r, 3), V1, V5, V9, VD); \
	GS_4X32(Mx(r, 4), Mx(r, 5), CSx(r, 4), CSx(r, 5), V2, V6, VA, VE); \
	GS_4X32(Mx(r, 6), Mx(r, 7), CSx(r, 6), CSx(r, 7), V3, V7, VB, VF); \
	GS_4X32(Mx(r, 8), Mx(r, 9), CSx(r, 8), CSx(r, 9), V0, V5, VA, VF); \
	GS_4X32(Mx(r, A), Mx(r, B), CSx(r, A), CSx(r, B), V1, V6, VB, VC); \
	GS_4X32(Mx(r, C), Mx(r, D), CSx(r, C), CSx(r, D), V2, V7, V8, VD); \
	GS_4X32(Mx(r, E), Mx(r, F), CSx(r, E), CSx(r, F), V3, V4, V9, VE); \
}

#define DECL_STATE32_4X32 \
	v128_t H0, H1, H2, H3, H4, H5, H6, H7; \
        uint32_t T0, T1;

#define READ_STATE32_4X32(state)   do { \
		H0 = casti_v128( state->H, 0 ); \
		H1 = casti_v128( state->H, 1 ); \
		H2 = casti_v128( state->H, 2 ); \
		H3 = casti_v128( state->H, 3 ); \
		H4 = casti_v128( state->H, 4 ); \
		H5 = casti_v128( state->H, 5 ); \
		H6 = casti_v128( state->H, 6 ); \
		H7 = casti_v128( state->H, 7 ); \
		T0 = (state)->T0; \
		T1 = (state)->T1; \
	} while (0)

#define WRITE_STATE32_4X32(state)   do { \
		casti_v128( state->H, 0 ) = H0; \
		casti_v128( state->H, 1 ) = H1; \
		casti_v128( state->H, 2 ) = H2; \
		casti_v128( state->H, 3 ) = H3; \
		casti_v128( state->H, 4 ) = H4; \
		casti_v128( state->H, 5 ) = H5; \
		casti_v128( state->H, 6 ) = H6; \
		casti_v128( state->H, 7 ) = H7; \
		(state)->T0 = T0; \
		(state)->T1 = T1; \
	} while (0)


#if defined(__SSSE3__)

#define BLAKE256_4X32_BLOCK_BSWAP32 \
{ \
   v128_t shuf_bswap32 = v128_set64( 0x0c0d0e0f08090a0b, \
                                     0x0405060700010203 ); \
   M0 = _mm_shuffle_epi8( buf[ 0], shuf_bswap32 ); \
   M1 = _mm_shuffle_epi8( buf[ 1], shuf_bswap32 ); \
   M2 = _mm_shuffle_epi8( buf[ 2], shuf_bswap32 ); \
   M3 = _mm_shuffle_epi8( buf[ 3], shuf_bswap32 ); \
   M4 = _mm_shuffle_epi8( buf[ 4], shuf_bswap32 ); \
   M5 = _mm_shuffle_epi8( buf[ 5], shuf_bswap32 ); \
   M6 = _mm_shuffle_epi8( buf[ 6], shuf_bswap32 ); \
   M7 = _mm_shuffle_epi8( buf[ 7], shuf_bswap32 ); \
   M8 = _mm_shuffle_epi8( buf[ 8], shuf_bswap32 ); \
   M9 = _mm_shuffle_epi8( buf[ 9], shuf_bswap32 ); \
   MA = _mm_shuffle_epi8( buf[10], shuf_bswap32 ); \
   MB = _mm_shuffle_epi8( buf[11], shuf_bswap32 ); \
   MC = _mm_shuffle_epi8( buf[12], shuf_bswap32 ); \
   MD = _mm_shuffle_epi8( buf[13], shuf_bswap32 ); \
   ME = _mm_shuffle_epi8( buf[14], shuf_bswap32 ); \
   MF = _mm_shuffle_epi8( buf[15], shuf_bswap32 ); \
}

#else  // SSE2

#define BLAKE256_4X32_BLOCK_BSWAP32 \
{ \
   M0 = v128_bswap32( buf[0] ); \
   M1 = v128_bswap32( buf[1] ); \
   M2 = v128_bswap32( buf[2] ); \
   M3 = v128_bswap32( buf[3] ); \
   M4 = v128_bswap32( buf[4] ); \
   M5 = v128_bswap32( buf[5] ); \
   M6 = v128_bswap32( buf[6] ); \
   M7 = v128_bswap32( buf[7] ); \
   M8 = v128_bswap32( buf[8] ); \
   M9 = v128_bswap32( buf[9] ); \
   MA = v128_bswap32( buf[10] ); \
   MB = v128_bswap32( buf[11] ); \
   MC = v128_bswap32( buf[12] ); \
   MD = v128_bswap32( buf[13] ); \
   ME = v128_bswap32( buf[14] ); \
   MF = v128_bswap32( buf[15] ); \
}

#endif  // SSSE3 else SSE2

#define COMPRESS32_4X32( rounds ) \
{ \
   v128_t M0, M1, M2, M3, M4, M5, M6, M7; \
   v128_t M8, M9, MA, MB, MC, MD, ME, MF; \
   v128_t V0, V1, V2, V3, V4, V5, V6, V7; \
   v128_t V8, V9, VA, VB, VC, VD, VE, VF; \
   V0 = H0; \
   V1 = H1; \
   V2 = H2; \
   V3 = H3; \
   V4 = H4; \
   V5 = H5; \
   V6 = H6; \
   V7 = H7; \
   V8 = v128_32( 0x243F6A88 ); \
   V9 = v128_32( 0x85A308D3 ); \
   VA = v128_32( 0x13198A2E ); \
   VB = v128_32( 0x03707344 ); \
   VC = v128_32( 0xA4093822 ^ T0 ); \
   VD = v128_32( 0x299F31D0 ^ T0 ); \
   VE = v128_32( 0x082EFA98 ^ T1 ); \
   VF = v128_32( 0xEC4E6C89 ^ T1 ); \
   BLAKE256_4X32_BLOCK_BSWAP32; \
   ROUND_S_4X32(0); \
   ROUND_S_4X32(1); \
   ROUND_S_4X32(2); \
   ROUND_S_4X32(3); \
   ROUND_S_4X32(4); \
   ROUND_S_4X32(5); \
   ROUND_S_4X32(6); \
   ROUND_S_4X32(7); \
   if (rounds == 14) \
   { \
      ROUND_S_4X32(8); \
      ROUND_S_4X32(9); \
      ROUND_S_4X32(0); \
      ROUND_S_4X32(1); \
      ROUND_S_4X32(2); \
      ROUND_S_4X32(3); \
   } \
   H0 = v128_xor( v128_xor( V8, V0 ), H0 ); \
   H1 = v128_xor( v128_xor( V9, V1 ), H1 ); \
   H2 = v128_xor( v128_xor( VA, V2 ), H2 ); \
   H3 = v128_xor( v128_xor( VB, V3 ), H3 ); \
   H4 = v128_xor( v128_xor( VC, V4 ), H4 ); \
   H5 = v128_xor( v128_xor( VD, V5 ), H5 ); \
   H6 = v128_xor( v128_xor( VE, V6 ), H6 ); \
   H7 = v128_xor( v128_xor( VF, V7 ), H7 ); \
}

#define G256_4X32_ALT( a, b, c, d, m0, m1 ) \
{ \
   a = v128_add32( v128_add32( a, b ), m0 ); \
   d = v128_ror32( v128_xor( d, a ), 16 ); \
   c = v128_add32( c, d ); \
   b = v128_ror32( v128_xor( b, c ), 12 ); \
   a = v128_add32( v128_add32( a, b ), m1 ); \
   d = v128_ror32( v128_xor( d, a ),  8 ); \
   c = v128_add32( c, d ); \
   b = v128_ror32( v128_xor( b, c ),  7 ); \
}

// Message expansion optimized to ignore padding M[5..12,14] for each round.
#define ROUND_S_4X32_0 \
{ \
   G256_4X32_ALT( V0, V4, V8, VC, v128_xor( M0, v128_32( CS1 ) ), \
                                  v128_xor( M1, v128_32( CS0 ) ) ); \
   G256_4X32_ALT( V1, V5, V9, VD, v128_xor( M2, v128_32( CS3 ) ), \
                                  v128_xor( M3, v128_32( CS2 ) ) ); \
   G256_4X32_ALT( V2, V6, VA, VE, v128_xor( M4, v128_32( CS5 ) ), \
                                                v128_32( CS4 )   ); \
   G256_4X32_ALT( V3, V7, VB, VF,               v128_32( CS7 )  , \
                                                v128_32( CS6 )   ); \
   G256_4X32_ALT( V0, V5, VA, VF,               v128_32( CS9 )  , \
                                                v128_32( CS8 )   ); \
   G256_4X32_ALT( V1, V6, VB, VC,               v128_32( CSB )  , \
                                                v128_32( CSA )   ); \
   G256_4X32_ALT( V2, V7, V8, VD,               v128_32( CSD )  , \
                                  v128_xor( MD, v128_32( CSC ) ) ); \
   G256_4X32_ALT( V3, V4, V9, VE,               v128_32( CSF )  , \
                                  v128_xor( MF, v128_32( CSE ) ) ); \
}

#define ROUND_S_4X32_1 \
{ \
   G256_4X32_ALT( V0, V4, V8, VC,               v128_32( CSA )  , \
                                                v128_32( CSE )   ); \
   G256_4X32_ALT( V1, V5, V9, VD, v128_xor( M4, v128_32( CS8 ) ), \
                                                v128_32( CS4 )   ); \
   G256_4X32_ALT( V2, V6, VA, VE,               v128_32( CSF )  , \
                                  v128_xor( MF, v128_32( CS9 ) ) ); \
   G256_4X32_ALT( V3, V7, VB, VF, v128_xor( MD, v128_32( CS6 ) ), \
                                                v128_32( CSD )   ); \
   G256_4X32_ALT( V0, V5, VA, VF, v128_xor( M1, v128_32( CSC ) ), \
                                                v128_32( CS1 )   ); \
   G256_4X32_ALT( V1, V6, VB, VC, v128_xor( M0, v128_32( CS2 ) ), \
                                  v128_xor( M2, v128_32( CS0 ) ) ); \
   G256_4X32_ALT( V2, V7, V8, VD,               v128_32( CS7 )  , \
                                                v128_32( CSB )   ); \
   G256_4X32_ALT( V3, V4, V9, VE,               v128_32( CS3 )  , \
                                  v128_xor( M3, v128_32( CS5 ) ) ); \
}

#define ROUND_S_4X32_2 \
{ \
   G256_4X32_ALT( V0, V4, V8, VC,               v128_32( CS8 )  , \
                                                v128_32( CSB )   ); \
   G256_4X32_ALT( V1, V5, V9, VD,               v128_32( CS0 )  , \
                                  v128_xor( M0, v128_32( CSC ) ) ); \
   G256_4X32_ALT( V2, V6, VA, VE,               v128_32( CS2 )  , \
                                  v128_xor( M2, v128_32( CS5 ) ) ); \
   G256_4X32_ALT( V3, V7, VB, VF, v128_xor( MF, v128_32( CSD ) ), \
                                  v128_xor( MD, v128_32( CSF ) ) ); \
   G256_4X32_ALT( V0, V5, VA, VF,               v128_32( CSE )  , \
                                                v128_32( CSA )   ); \
   G256_4X32_ALT( V1, V6, VB, VC, v128_xor( M3, v128_32( CS6 ) ), \
                                                v128_32( CS3 )   ); \
   G256_4X32_ALT( V2, V7, V8, VD,               v128_32( CS1 )  , \
                                  v128_xor( M1, v128_32( CS7 ) ) ); \
   G256_4X32_ALT( V3, V4, V9, VE,               v128_32( CS4 )  , \
                                  v128_xor( M4, v128_32( CS9 ) ) ); \
}

#define ROUND_S_4X32_3 \
{ \
   G256_4X32_ALT( V0, V4, V8, VC,               v128_32( CS9 )  , \
                                                v128_32( CS7 )   ); \
   G256_4X32_ALT( V1, V5, V9, VD, \
                                  v128_xor( M3, v128_32( CS1 ) ), \
                                  v128_xor( M1, v128_32( CS3 ) ) ); \
   G256_4X32_ALT( V2, V6, VA, VE, v128_xor( MD, v128_32( CSC ) ), \
                                                v128_32( CSD )   ); \
   G256_4X32_ALT( V3, V7, VB, VF,               v128_32( CSE )  , \
                                                v128_32( CSB )   ); \
   G256_4X32_ALT( V0, V5, VA, VF, \
                                  v128_xor( M2, v128_32( CS6 ) ), \
                                                v128_32( CS2 )   ); \
   G256_4X32_ALT( V1, V6, VB, VC,               v128_32( CSA )  , \
                                                v128_32( CS5 )   ); \
   G256_4X32_ALT( V2, V7, V8, VD, v128_xor( M4, v128_32( CS0 ) ), \
                                  v128_xor( M0, v128_32( CS4 ) ) ); \
   G256_4X32_ALT( V3, V4, V9, VE, \
                                  v128_xor( MF, v128_32( CS8 ) ), \
                                                v128_32( CSF )   ); \
}

#define ROUND_S_4X32_4 \
{ \
   G256_4X32_ALT( V0, V4, V8, VC,               v128_32( CS0 )  , \
                                  v128_xor( M0, v128_32( CS9 ) ) ); \
   G256_4X32_ALT( V1, V5, V9, VD,               v128_32( CS7 )  , \
                                                v128_32( CS5 )   ); \
   G256_4X32_ALT( V2, V6, VA, VE, v128_xor( M2, v128_32( CS4 ) ), \
                                  v128_xor( M4, v128_32( CS2 ) )  ); \
   G256_4X32_ALT( V3, V7, VB, VF,               v128_32( CSF )  , \
                                  v128_xor( MF, v128_32(  CSA ) ) ); \
   G256_4X32_ALT( V0, V5, VA, VF,               v128_32( CS1 )  , \
                                  v128_xor( M1, v128_32( CSE ) ) ); \
   G256_4X32_ALT( V1, V6, VB, VC,               v128_32( CSC )  , \
                                                v128_32( CSB )   ); \
   G256_4X32_ALT( V2, V7, V8, VD,               v128_32( CS8 )  , \
                                                v128_32( CS6 )   ); \
   G256_4X32_ALT( V3, V4, V9, VE, v128_xor( M3, v128_32( CSD ) ), \
                                  v128_xor( MD, v128_32( CS3 ) ) ); \
}
#define ROUND_S_4X32_5 \
{ \
   G256_4X32_ALT( V0, V4, V8, VC, v128_xor( M2, v128_32( CSC ) ), \
                                                v128_32( CS2 )   ); \
   G256_4X32_ALT( V1, V5, V9, VD,               v128_32( CSA )  , \
                                                v128_32( CS6 )   ); \
   G256_4X32_ALT( V2, V6, VA, VE, \
                                  v128_xor( M0, v128_32( CSB ) ), \
                                                v128_32( CS0 )   ); \
   G256_4X32_ALT( V3, V7, VB, VF,               v128_32( CS3 )  , \
                                  v128_xor( M3, v128_32( CS8 ) ) ); \
   G256_4X32_ALT( V0, V5, VA, VF, v128_xor( M4, v128_32( CSD ) ), \
                                  v128_xor( MD, v128_32( CS4 ) ) ); \
   G256_4X32_ALT( V1, V6, VB, VC,               v128_32( CS5 )  , \
                                                v128_32( CS7 )   ); \
   G256_4X32_ALT( V2, V7, V8, VD, \
                                  v128_xor( MF, v128_32( CSE ) ), \
                                                v128_32( CSF )   ); \
   G256_4X32_ALT( V3, V4, V9, VE, \
                                  v128_xor( M1, v128_32( CS9 ) ), \
                                                v128_32( CS1 )   ); \
} 
#define ROUND_S_4X32_6 \
{ \
   G256_4X32_ALT( V0, V4, V8, VC,               v128_32( CS5 )  , \
                                                v128_32( CSC )   ); \
   G256_4X32_ALT( V1, V5, V9, VD, v128_xor( M1, v128_32( CSF ) ), \
                                  v128_xor( MF, v128_32( CS1 ) ) ); \
   G256_4X32_ALT( V2, V6, VA, VE,               v128_32( CSD )  , \
                                  v128_xor( MD, v128_32( CSE ) ) );\
   G256_4X32_ALT( V3, V7, VB, VF, v128_xor( M4, v128_32( CSA ) ), \
                                                v128_32( CS4 )   ); \
   G256_4X32_ALT( V0, V5, VA, VF, v128_xor( M0, v128_32( CS7 ) ), \
                                                v128_32( CS0 )   ); \
   G256_4X32_ALT( V1, V6, VB, VC,               v128_32( CS3 )  , \
                                  v128_xor( M3, v128_32( CS6 ) ) ); \
   G256_4X32_ALT( V2, V7, V8, VD,               v128_32( CS2 )  , \
                                  v128_xor( M2, v128_32( CS9 ) ) ); \
   G256_4X32_ALT( V3, V4, V9, VE,               v128_32( CSB )  , \
                                                v128_32( CS8 )   ); \
}

#define ROUND_S_4X32_7 \
{ \
   G256_4X32_ALT( V0, V4, V8, VC, v128_xor( MD, v128_32( CSB ) ), \
                                                v128_32( CSD )   ); \
   G256_4X32_ALT( V1, V5, V9, VD,               v128_32( CSE )  , \
                                                v128_32( CS7 )   ); \
   G256_4X32_ALT( V2, V6, VA, VE,               v128_32( CS1 )  , \
                                  v128_xor( M1, v128_32( CSC ) ) ); \
   G256_4X32_ALT( V3, V7, VB, VF, v128_xor( M3, v128_32( CS9 ) ), \
                                                v128_32( CS3 )   ); \
   G256_4X32_ALT( V0, V5, VA, VF,               v128_32( CS0 )  , \
                                  v128_xor( M0, v128_32( CS5 ) ) ); \
   G256_4X32_ALT( V1, V6, VB, VC, v128_xor( MF, v128_32( CS4 ) ), \
                                  v128_xor( M4, v128_32( CSF ) ) ); \
   G256_4X32_ALT( V2, V7, V8, VD,               v128_32( CS6 )  , \
                                                v128_32( CS8 )   ); \
   G256_4X32_ALT( V3, V4, V9, VE, v128_xor( M2, v128_32( CSA ) ), \
                                                v128_32( CS2 )   ); \
}

#define ROUND_S_4X32_8 \
{ \
   G256_4X32_ALT( V0, V4, V8, VC,               v128_32( CSF   ), \
                                  v128_xor( MF, v128_32( CS6 ) ) ); \
   G256_4X32_ALT( V1, V5, V9, VD,               v128_32( CS9 )  , \
                                                v128_32( CSE )   ); \
   G256_4X32_ALT( V2, V6, VA, VE,               v128_32( CS3 )  , \
                                  v128_xor( M3, v128_32( CSB ) ) ); \
   G256_4X32_ALT( V3, V7, VB, VF, v128_xor( M0, v128_32( CS8 ) ), \
                                                v128_32( CS0 )   ); \
   G256_4X32_ALT( V0, V5, VA, VF,               v128_32( CS2 )  , \
                                  v128_xor( M2, v128_32( CSC ) ) ); \
   G256_4X32_ALT( V1, V6, VB, VC, \
                                  v128_xor( MD, v128_32( CS7 ) ), \
                                                v128_32( CSD )   ); \
   G256_4X32_ALT( V2, V7, V8, VD, v128_xor( M1, v128_32( CS4 ) ), \
                                  v128_xor( M4, v128_32( CS1 ) ) ); \
   G256_4X32_ALT( V3, V4, V9, VE,               v128_32( CS5 )  , \
                                                v128_32( CSA )   ); \
}

#define ROUND_S_4X32_9 \
{ \
   G256_4X32_ALT( V0, V4, V8, VC,               v128_32( CS2 )  , \
                                  v128_xor( M2, v128_32( CSA ) ) ); \
   G256_4X32_ALT( V1, V5, V9, VD,               v128_32( CS4 )  , \
                                  v128_xor( M4, v128_32( CS8 ) ) ); \
   G256_4X32_ALT( V2, V6, VA, VE,               v128_32( CS6 )  , \
                                                v128_32( CS7 )    ); \
   G256_4X32_ALT( V3, V7, VB, VF, v128_xor( M1, v128_32( CS5 ) ), \
                                                v128_32( CS1 )   ); \
   G256_4X32_ALT( V0, V5, VA, VF, v128_xor( MF, v128_32( CSB ) ), \
                                                v128_32( CSF )   ); \
   G256_4X32_ALT( V1, V6, VB, VC,               v128_32( CSE )  , \
                                                v128_32( CS9 )   ); \
   G256_4X32_ALT( V2, V7, V8, VD, v128_xor( M3, v128_32( CSC ) ), \
                                                v128_32( CS3 )   ); \
   G256_4X32_ALT( V3, V4, V9, VE, v128_xor( MD, v128_32( CS0 ) ), \
                                  v128_xor( M0, v128_32( CSD ) ) ); \
}

void blake256_4x32_round0_prehash_le( void *midstate, const void *midhash,
                                      void *data )
{
   v128_t *M = (v128_t*)data;
   v128_t *V = (v128_t*)midstate;
   const v128_t *H = (const v128_t*)midhash;

   V[ 0] = H[0];
   V[ 1] = H[1];
   V[ 2] = H[2];
   V[ 3] = H[3];
   V[ 4] = H[4];
   V[ 5] = H[5];
   V[ 6] = H[6];
   V[ 7] = H[7];
   V[ 8] = v128_32( CS0 );
   V[ 9] = v128_32( CS1 );
   V[10] = v128_32( CS2 );
   V[11] = v128_32( CS3 );
   V[12] = v128_32( CS4 ^ 0x280 );
   V[13] = v128_32( CS5 ^ 0x280 );
   V[14] = v128_32( CS6 );
   V[15] = v128_32( CS7 );

// M[ 0:3 ] contain new message data including unique nonces in M[ 3].
// M[ 5:12,14 ] are always zero and not needed or used.
// M[ 4], M[13], M[15] are constant and are initialized here.
// M[ 5] is a special case, used as a cache for (M[13] ^ CSC).

   M[ 4] = v128_32( 0x80000000 );
   M[13] = v128_32( 1 );
   M[15] = v128_32( 80*8 );

   M[ 5] = v128_xor( M[13], v128_32( CSC ) );

   // G0
   GS_4X32( M[ 0], M[ 1], CS0, CS1, V[ 0], V[ 4], V[ 8], V[12] );

   // G1
   V[ 1] = v128_add32( v128_add32( V[ 1], V[ 5] ),
                       v128_xor( v128_32( CS3 ), M[ 2] ) );
   V[13] = v128_ror32( v128_xor( V[13], V[ 1] ), 16 );
   V[ 9] = v128_add32( V[ 9], V[13] );
   V[ 5] = v128_ror32( v128_xor( V[ 5], V[ 9] ), 12 );
   V[ 1] = v128_add32( V[ 1], V[ 5] );

   // G2
   // GS_4X32( M[ 4], M[ 5], CS4, CS5, V[ 2], V[ 6], V[10], V[14] );
   V[ 2] = v128_add32( v128_add32( V[ 2], V[ 6] ),
                       v128_xor( v128_32( CS5 ), M[ 4] ) );
   V[14] = v128_ror32( v128_xor( V[14], V[ 2] ), 16 );
   V[10] = v128_add32( V[10], V[14] );
   V[ 6] = v128_ror32( v128_xor( V[ 6], V[10] ), 12 );
   V[ 2] = v128_add32( v128_add32( V[ 2], V[ 6] ), v128_32( CS4 ) );
   V[14] = v128_ror32( v128_xor( V[14], V[ 2] ), 8 );
   V[10] = v128_add32( V[10], V[14] );
   V[ 6] = v128_ror32( v128_xor( V[ 6], V[10] ), 7 );

   // G3
   // GS_4X32( M[ 6], M[ 7], CS6, CS7, V[ 3], V[ 7], V[11], V[15] );
   V[ 3] = v128_add32( v128_add32( V[ 3], V[ 7] ), v128_32( CS7 ) );
   V[15] = v128_ror32( v128_xor( V[15], V[ 3] ), 16 );
   V[11] = v128_add32( V[11], V[15] );
   V[ 7] = v128_ror32( v128_xor( V[ 7], V[11] ), 12 );
   V[ 3] = v128_add32( v128_add32( V[ 3], V[ 7] ), v128_32( CS6 ) );
   V[15] = v128_ror32( v128_xor( V[15], V[ 3] ), 8 );
   V[11] = v128_add32( V[11], V[15] );
   V[ 7] = v128_ror32( v128_xor( V[ 7], V[11] ), 7 );

   // G4
   V[ 0] = v128_add32( V[ 0], v128_32( CS9 ) );

   // G5
   // GS_4X32( M[10], M[11], CSA, CSB, V1, V6, VB, VC );

   // G6
   V[ 2] = v128_add32( v128_add32( V[ 2], V[ 7] ), v128_32( CSD ) );

   // G7
   V[ 3] = v128_add32( v128_add32( V[ 3], V[ 4] ), v128_32( CSF ) );
   V[14] = v128_ror32( v128_xor( V[14], V[ 3] ), 16 );
   V[ 3] = v128_add32( V[ 3], v128_xor( v128_32( CSE ), M[15] ) );
}

void blake256_4x32_final_rounds_le( void *final_hash, const void *midstate,
                     const void *midhash, const void *data, const int rounds )
{
   v128_t *H = (v128_t*)final_hash;
   const v128_t *h = (const v128_t*)midhash;
   v128_t V0, V1, V2, V3, V4, V5, V6, V7;
   v128_t V8, V9, VA, VB, VC, VD, VE, VF;
   v128_t M0, M1, M2, M3, M4, MD, MF;
   v128_t MDxorCSC;

   V0 = v128_load( (v128_t*)midstate +  0 );
   V1 = v128_load( (v128_t*)midstate +  1 );
   V2 = v128_load( (v128_t*)midstate +  2 );
   V3 = v128_load( (v128_t*)midstate +  3 );
   V4 = v128_load( (v128_t*)midstate +  4 );
   V5 = v128_load( (v128_t*)midstate +  5 );
   V6 = v128_load( (v128_t*)midstate +  6 );
   V7 = v128_load( (v128_t*)midstate +  7 );
   V8 = v128_load( (v128_t*)midstate +  8 );
   V9 = v128_load( (v128_t*)midstate +  9 );
   VA = v128_load( (v128_t*)midstate + 10 );
   VB = v128_load( (v128_t*)midstate + 11 );
   VC = v128_load( (v128_t*)midstate + 12 );
   VD = v128_load( (v128_t*)midstate + 13 );
   VE = v128_load( (v128_t*)midstate + 14 );
   VF = v128_load( (v128_t*)midstate + 15 );

   M0 = v128_load( (v128_t*)data +  0 );
   M1 = v128_load( (v128_t*)data +  1 );
   M2 = v128_load( (v128_t*)data +  2 );
   M3 = v128_load( (v128_t*)data +  3 );
   M4 = v128_load( (v128_t*)data +  4 );
   // M5 to MC & ME zero padding & optimised out.
   MD = v128_load( (v128_t*)data + 13 );
   MF = v128_load( (v128_t*)data + 15 );
   // precalculated MD^CSC, used in round0 G6.
   MDxorCSC = v128_load( (v128_t*)data +  5 );

   // Finish round 0 with nonce in M3
   // G1
   V1 = v128_add32( V1,
                         v128_xor( v128_32( CS2 ), M3 ) );
   VD = v128_ror32( v128_xor( VD, V1 ), 8 );
   V9 = v128_add32( V9, VD );
   V5 = v128_ror32( v128_xor( V5, V9 ), 7 );

   // G4
   V0 = v128_add32( V0, V5 );
   VF = v128_ror32( v128_xor( VF, V0 ), 16 );
   VA = v128_add32( VA, VF );
   V5 = v128_ror32( v128_xor( V5, VA ), 12 );
   V0 = v128_add32( V0, v128_add32( V5, v128_32( CS8 ) ) );
   VF = v128_ror32( v128_xor( VF, V0 ), 8 );
   VA = v128_add32( VA, VF );
   V5 = v128_ror32( v128_xor( V5, VA ), 7 );

   // G5
   // GS_4X32( MA, MB, CSA, CSB, V1, V6, VB, VC );
   V1 = v128_add32( v128_add32( V1, V6 ), v128_32( CSB ) );
   VC = v128_ror32( v128_xor( VC, V1 ), 16 );
   VB = v128_add32( VB, VC );
   V6 = v128_ror32( v128_xor( V6, VB ), 12 );
   V1 = v128_add32( v128_add32( V1, V6 ), v128_32( CSA ) );
   VC = v128_ror32( v128_xor( VC, V1 ), 8 );
   VB = v128_add32( VB, VC );
   V6 = v128_ror32( v128_xor( V6, VB ), 7 );

   // G6
   VD = v128_ror32( v128_xor( VD, V2 ), 16 );
   V8 = v128_add32( V8, VD );
   V7 = v128_ror32( v128_xor( V7, V8 ), 12 );
   V2 = v128_add32( V2, v128_add32( V7, MDxorCSC ) );
   VD = v128_ror32( v128_xor( VD, V2 ), 8 );
   V8 = v128_add32( V8, VD );
   V7 = v128_ror32( v128_xor( V7, V8 ), 7 );

   // G7
   V9 = v128_add32( V9, VE );
   V4 = v128_ror32( v128_xor( V4, V9 ), 12 );
   V3 = v128_add32( V3, V4 );
   VE = v128_ror32( v128_xor( VE, V3 ), 8 );
   V9 = v128_add32( V9, VE );
   V4 = v128_ror32( v128_xor( V4, V9 ), 7 );

   // Remaining rounds
   ROUND_S_4X32_1;
   ROUND_S_4X32_2;
   ROUND_S_4X32_3;
   ROUND_S_4X32_4;
   ROUND_S_4X32_5;
   ROUND_S_4X32_6;
   ROUND_S_4X32_7;
   if ( rounds > 8 )
   {
      ROUND_S_4X32_8;
      ROUND_S_4X32_9;
      ROUND_S_4X32_0;
      ROUND_S_4X32_1;
      ROUND_S_4X32_2;
      ROUND_S_4X32_3;
   }

#if defined(__SSSE3__)

   const v128_t shuf_bswap32 =
                      v128_set64( 0x0c0d0e0f08090a0b, 0x0405060700010203 );

   H[0] = _mm_shuffle_epi8( v128_xor3( V8, V0, h[0] ), shuf_bswap32 );
   H[1] = _mm_shuffle_epi8( v128_xor3( V9, V1, h[1] ), shuf_bswap32 );
   H[2] = _mm_shuffle_epi8( v128_xor3( VA, V2, h[2] ), shuf_bswap32 );
   H[3] = _mm_shuffle_epi8( v128_xor3( VB, V3, h[3] ), shuf_bswap32 );
   H[4] = _mm_shuffle_epi8( v128_xor3( VC, V4, h[4] ), shuf_bswap32 );
   H[5] = _mm_shuffle_epi8( v128_xor3( VD, V5, h[5] ), shuf_bswap32 );
   H[6] = _mm_shuffle_epi8( v128_xor3( VE, V6, h[6] ), shuf_bswap32 );
   H[7] = _mm_shuffle_epi8( v128_xor3( VF, V7, h[7] ), shuf_bswap32 );

#else

   H[0] = v128_bswap32( v128_xor3( V8, V0, h[0] ) );
   H[1] = v128_bswap32( v128_xor3( V9, V1, h[1] ) );
   H[2] = v128_bswap32( v128_xor3( VA, V2, h[2] ) );
   H[3] = v128_bswap32( v128_xor3( VB, V3, h[3] ) );
   H[4] = v128_bswap32( v128_xor3( VC, V4, h[4] ) );
   H[5] = v128_bswap32( v128_xor3( VD, V5, h[5] ) );
   H[6] = v128_bswap32( v128_xor3( VE, V6, h[6] ) );
   H[7] = v128_bswap32( v128_xor3( VF, V7, h[7] ) );

#endif
}

#if defined (__AVX2__)

/////////////////////////////////
//
//      Blake-256 8 way

#define GS_8WAY( m0, m1, c0, c1, a, b, c, d ) \
{ \
   a = _mm256_add_epi32( _mm256_add_epi32( a, b ), \
                         _mm256_xor_si256( v256_32( c1 ), m0 ) ); \
   d = mm256_ror_32( _mm256_xor_si256( d, a ), 16 ); \
   c = _mm256_add_epi32( c, d ); \
   b = mm256_ror_32( _mm256_xor_si256( b, c ), 12 ); \
   a = _mm256_add_epi32( _mm256_add_epi32( a, b ), \
                         _mm256_xor_si256( v256_32( c0 ), m1 ) ); \
   d = mm256_ror_32( _mm256_xor_si256( d, a ), 8 ); \
   c = _mm256_add_epi32( c, d ); \
   b = mm256_ror_32( _mm256_xor_si256( b, c ), 7 ); \
}

#define ROUND_S_8WAY(r) \
{ \
        GS_8WAY(Mx(r, 0), Mx(r, 1), CSx(r, 0), CSx(r, 1), V0, V4, V8, VC); \
        GS_8WAY(Mx(r, 2), Mx(r, 3), CSx(r, 2), CSx(r, 3), V1, V5, V9, VD); \
        GS_8WAY(Mx(r, 4), Mx(r, 5), CSx(r, 4), CSx(r, 5), V2, V6, VA, VE); \
        GS_8WAY(Mx(r, 6), Mx(r, 7), CSx(r, 6), CSx(r, 7), V3, V7, VB, VF); \
        GS_8WAY(Mx(r, 8), Mx(r, 9), CSx(r, 8), CSx(r, 9), V0, V5, VA, VF); \
        GS_8WAY(Mx(r, A), Mx(r, B), CSx(r, A), CSx(r, B), V1, V6, VB, VC); \
        GS_8WAY(Mx(r, C), Mx(r, D), CSx(r, C), CSx(r, D), V2, V7, V8, VD); \
        GS_8WAY(Mx(r, E), Mx(r, F), CSx(r, E), CSx(r, F), V3, V4, V9, VE); \
}

// Short cut message expansion when the message data is known to be zero.
// M[ 5:12, 14 ] are zero padded for the second block of 80 byte data.

#define G256_8WAY_ALT( a, b, c, d, m0, m1 ) \
{ \
   a = _mm256_add_epi32( _mm256_add_epi32( a, b ), m0 ); \
   d = mm256_ror_32( _mm256_xor_si256( d, a ), 16 ); \
   c = _mm256_add_epi32( c, d ); \
   b = mm256_ror_32( _mm256_xor_si256( b, c ), 12 ); \
   a = _mm256_add_epi32( _mm256_add_epi32( a, b ), m1 ); \
   d = mm256_ror_32( _mm256_xor_si256( d, a ), 8 ); \
   c = _mm256_add_epi32( c, d ); \
   b = mm256_ror_32( _mm256_xor_si256( b, c ), 7 ); \
}

// Message expansion optimized for each round.
#define ROUND256_8WAY_0 \
{ \
   G256_8WAY_ALT( V0, V4, V8, VC, \
                  _mm256_xor_si256( M0, v256_32( CS1 ) ), \
                  _mm256_xor_si256( M1, v256_32( CS0 ) ) ); \
   G256_8WAY_ALT( V1, V5, V9, VD, \
                  _mm256_xor_si256( M2, v256_32( CS3 ) ), \
                  _mm256_xor_si256( M3, v256_32( CS2 ) ) ); \
   G256_8WAY_ALT( V2, V6, VA, VE, \
                  _mm256_xor_si256( M4, v256_32( CS5 ) ), \
                                        v256_32( CS4 )   ); \
   G256_8WAY_ALT( V3, V7, VB, VF,       v256_32( CS7 )  , \
                                        v256_32( CS6 )   ); \
   G256_8WAY_ALT( V0, V5, VA, VF,       v256_32( CS9 )  , \
                                        v256_32( CS8 )   ); \
   G256_8WAY_ALT( V1, V6, VB, VC,       v256_32( CSB )  , \
                                        v256_32( CSA )   ); \
   G256_8WAY_ALT( V2, V7, V8, VD,       v256_32( CSD )  , \
                  _mm256_xor_si256( MD, v256_32( CSC ) ) ); \
   G256_8WAY_ALT( V3, V4, V9, VE,       v256_32( CSF )  , \
                  _mm256_xor_si256( MF, v256_32( CSE ) ) ); \
}

#define ROUND256_8WAY_1 \
{ \
   G256_8WAY_ALT( V0, V4, V8, VC,       v256_32( CSA )  , \
                                        v256_32( CSE )   ); \
   G256_8WAY_ALT( V1, V5, V9, VD, \
                  _mm256_xor_si256( M4, v256_32( CS8 ) ), \
                                        v256_32( CS4 )   ); \
   G256_8WAY_ALT( V2, V6, VA, VE,       v256_32( CSF )  , \
                  _mm256_xor_si256( MF, v256_32( CS9 ) ) ); \
   G256_8WAY_ALT( V3, V7, VB, VF, \
                  _mm256_xor_si256( MD, v256_32( CS6 ) ), \
                                        v256_32( CSD )   ); \
   G256_8WAY_ALT( V0, V5, VA, VF, \
                  _mm256_xor_si256( M1, v256_32( CSC ) ), \
                                        v256_32( CS1 )   ); \
   G256_8WAY_ALT( V1, V6, VB, VC, \
                  _mm256_xor_si256( M0, v256_32( CS2 ) ), \
                  _mm256_xor_si256( M2, v256_32( CS0 ) ) ); \
   G256_8WAY_ALT( V2, V7, V8, VD,       v256_32( CS7 )  , \
                                        v256_32( CSB )   ); \
   G256_8WAY_ALT( V3, V4, V9, VE,       v256_32( CS3 )  , \
                  _mm256_xor_si256( M3, v256_32( CS5 ) ) ); \
}

#define ROUND256_8WAY_2 \
{ \
   G256_8WAY_ALT( V0, V4, V8, VC,       v256_32( CS8 )  , \
                                        v256_32( CSB )   ); \
   G256_8WAY_ALT( V1, V5, V9, VD,       v256_32( CS0 )  , \
                  _mm256_xor_si256( M0, v256_32( CSC ) ) ); \
   G256_8WAY_ALT( V2, V6, VA, VE,       v256_32( CS2 )  , \
                  _mm256_xor_si256( M2, v256_32( CS5 ) ) ); \
   G256_8WAY_ALT( V3, V7, VB, VF, \
                  _mm256_xor_si256( MF, v256_32( CSD ) ), \
                  _mm256_xor_si256( MD, v256_32( CSF ) ) ); \
   G256_8WAY_ALT( V0, V5, VA, VF,       v256_32( CSE )  , \
                                        v256_32( CSA )   ); \
   G256_8WAY_ALT( V1, V6, VB, VC, \
                  _mm256_xor_si256( M3, v256_32( CS6 ) ), \
                                        v256_32( CS3 )   ); \
   G256_8WAY_ALT( V2, V7, V8, VD,       v256_32( CS1 )  , \
                  _mm256_xor_si256( M1, v256_32( CS7 ) ) ); \
   G256_8WAY_ALT( V3, V4, V9, VE,       v256_32( CS4 )  , \
                  _mm256_xor_si256( M4, v256_32( CS9 ) ) ); \
}

#define ROUND256_8WAY_3 \
{ \
   G256_8WAY_ALT( V0, V4, V8, VC,       v256_32( CS9 )  , \
                                        v256_32( CS7 )   ); \
   G256_8WAY_ALT( V1, V5, V9, VD, \
                  _mm256_xor_si256( M3, v256_32( CS1 ) ), \
                  _mm256_xor_si256( M1, v256_32( CS3 ) ) ); \
   G256_8WAY_ALT( V2, V6, VA, VE, \
                  _mm256_xor_si256( MD, v256_32( CSC ) ), \
                                        v256_32( CSD )   ); \
   G256_8WAY_ALT( V3, V7, VB, VF,       v256_32( CSE )  , \
                                        v256_32( CSB )   ); \
   G256_8WAY_ALT( V0, V5, VA, VF, \
                  _mm256_xor_si256( M2, v256_32( CS6 ) ), \
                                        v256_32( CS2 )   ); \
   G256_8WAY_ALT( V1, V6, VB, VC,       v256_32( CSA )  , \
                                        v256_32( CS5 )   ); \
   G256_8WAY_ALT( V2, V7, V8, VD, \
                  _mm256_xor_si256( M4, v256_32( CS0 ) ), \
                  _mm256_xor_si256( M0, v256_32( CS4 ) ) ); \
   G256_8WAY_ALT( V3, V4, V9, VE, \
                  _mm256_xor_si256( MF, v256_32( CS8 ) ), \
                                        v256_32( CSF )   ); \
}

#define ROUND256_8WAY_4 \
{ \
   G256_8WAY_ALT( V0, V4, V8, VC,       v256_32( CS0 )  , \
                  _mm256_xor_si256( M0, v256_32( CS9 ) ) ); \
   G256_8WAY_ALT( V1, V5, V9, VD,       v256_32( CS7 )  , \
                                        v256_32( CS5 )   ); \
   G256_8WAY_ALT( V2, V6, VA, VE, \
                  _mm256_xor_si256( M2, v256_32( CS4 ) ), \
                  _mm256_xor_si256( M4, v256_32( CS2 ) )  ); \
   G256_8WAY_ALT( V3, V7, VB, VF,       v256_32( CSF )  , \
                  _mm256_xor_si256( MF, v256_32( CSA ) ) ); \
   G256_8WAY_ALT( V0, V5, VA, VF,       v256_32( CS1 )  , \
                  _mm256_xor_si256( M1, v256_32( CSE ) ) ); \
   G256_8WAY_ALT( V1, V6, VB, VC,       v256_32( CSC )  , \
                                        v256_32( CSB )   ); \
   G256_8WAY_ALT( V2, V7, V8, VD,       v256_32( CS8 )  , \
                                        v256_32( CS6 )   ); \
   G256_8WAY_ALT( V3, V4, V9, VE, \
                  _mm256_xor_si256( M3, v256_32( CSD ) ), \
                  _mm256_xor_si256( MD, v256_32( CS3 ) ) ); \
}

#define ROUND256_8WAY_5 \
{ \
   G256_8WAY_ALT( V0, V4, V8, VC, \
                  _mm256_xor_si256( M2, v256_32( CSC ) ), \
                                        v256_32( CS2 )   ); \
   G256_8WAY_ALT( V1, V5, V9, VD,       v256_32( CSA )  , \
                                        v256_32( CS6 )   ); \
   G256_8WAY_ALT( V2, V6, VA, VE, \
                  _mm256_xor_si256( M0, v256_32( CSB ) ), \
                                        v256_32( CS0 )   ); \
   G256_8WAY_ALT( V3, V7, VB, VF,       v256_32( CS3 )  , \
                  _mm256_xor_si256( M3, v256_32( CS8 ) ) ); \
   G256_8WAY_ALT( V0, V5, VA, VF, \
                  _mm256_xor_si256( M4, v256_32( CSD ) ), \
                  _mm256_xor_si256( MD, v256_32( CS4 ) ) ); \
   G256_8WAY_ALT( V1, V6, VB, VC,       v256_32( CS5 )  , \
                                        v256_32( CS7 )   ); \
   G256_8WAY_ALT( V2, V7, V8, VD, \
                  _mm256_xor_si256( MF, v256_32( CSE ) ), \
                                        v256_32( CSF )   ); \
   G256_8WAY_ALT( V3, V4, V9, VE, \
                  _mm256_xor_si256( M1, v256_32( CS9 ) ), \
                                        v256_32( CS1 )   ); \
}

#define ROUND256_8WAY_6 \
{ \
   G256_8WAY_ALT( V0, V4, V8, VC,       v256_32( CS5 )  , \
                                        v256_32( CSC )   ); \
   G256_8WAY_ALT( V1, V5, V9, VD, \
                  _mm256_xor_si256( M1, v256_32( CSF ) ), \
                  _mm256_xor_si256( MF, v256_32( CS1 ) ) ); \
   G256_8WAY_ALT( V2, V6, VA, VE,       v256_32( CSD )  , \
                  _mm256_xor_si256( MD, v256_32( CSE ) ) );\
   G256_8WAY_ALT( V3, V7, VB, VF, \
                  _mm256_xor_si256( M4, v256_32( CSA ) ), \
                                        v256_32( CS4 )   ); \
   G256_8WAY_ALT( V0, V5, VA, VF, \
                  _mm256_xor_si256( M0, v256_32( CS7 ) ), \
                                        v256_32( CS0 )   ); \
   G256_8WAY_ALT( V1, V6, VB, VC,       v256_32( CS3 )  , \
                  _mm256_xor_si256( M3, v256_32( CS6 ) ) ); \
   G256_8WAY_ALT( V2, V7, V8, VD,       v256_32( CS2 )  , \
                  _mm256_xor_si256( M2, v256_32( CS9 ) ) ); \
   G256_8WAY_ALT( V3, V4, V9, VE,       v256_32( CSB )  , \
                                        v256_32( CS8 )   ); \
}

#define ROUND256_8WAY_7 \
{ \
   G256_8WAY_ALT( V0, V4, V8, VC, \
                  _mm256_xor_si256( MD, v256_32( CSB ) ), \
                                        v256_32( CSD )   ); \
   G256_8WAY_ALT( V1, V5, V9, VD,       v256_32( CSE )  , \
                                        v256_32( CS7 )   ); \
   G256_8WAY_ALT( V2, V6, VA, VE,       v256_32( CS1 )  , \
                  _mm256_xor_si256( M1, v256_32( CSC ) ) ); \
   G256_8WAY_ALT( V3, V7, VB, VF, \
                  _mm256_xor_si256( M3, v256_32( CS9 ) ), \
                                        v256_32( CS3 )   ); \
   G256_8WAY_ALT( V0, V5, VA, VF,       v256_32( CS0 )  , \
                  _mm256_xor_si256( M0, v256_32( CS5 ) ) ); \
   G256_8WAY_ALT( V1, V6, VB, VC, \
                  _mm256_xor_si256( MF, v256_32( CS4 ) ), \
                  _mm256_xor_si256( M4, v256_32( CSF ) ) ); \
   G256_8WAY_ALT( V2, V7, V8, VD,       v256_32( CS6 )  , \
                                        v256_32( CS8 )   ); \
   G256_8WAY_ALT( V3, V4, V9, VE, \
                  _mm256_xor_si256( M2, v256_32( CSA ) ), \
                                        v256_32( CS2 )   ); \
}

#define ROUND256_8WAY_8 \
{ \
   G256_8WAY_ALT( V0, V4, V8, VC,       v256_32( CSF   ), \
                  _mm256_xor_si256( MF, v256_32( CS6 ) ) ); \
   G256_8WAY_ALT( V1, V5, V9, VD,       v256_32( CS9 )  , \
                                        v256_32( CSE )   ); \
   G256_8WAY_ALT( V2, V6, VA, VE,       v256_32( CS3 )  , \
                  _mm256_xor_si256( M3, v256_32( CSB ) ) ); \
   G256_8WAY_ALT( V3, V7, VB, VF, \
                  _mm256_xor_si256( M0, v256_32( CS8 ) ), \
                                        v256_32( CS0 )   ); \
   G256_8WAY_ALT( V0, V5, VA, VF,       v256_32( CS2 )  , \
                  _mm256_xor_si256( M2, v256_32( CSC ) ) ); \
   G256_8WAY_ALT( V1, V6, VB, VC, \
                  _mm256_xor_si256( MD, v256_32( CS7 ) ), \
                                        v256_32( CSD )   ); \
   G256_8WAY_ALT( V2, V7, V8, VD, \
                  _mm256_xor_si256( M1, v256_32( CS4 ) ), \
                  _mm256_xor_si256( M4, v256_32( CS1 ) ) ); \
   G256_8WAY_ALT( V3, V4, V9, VE,       v256_32( CS5 )  , \
                                        v256_32( CSA )   ); \
}

#define ROUND256_8WAY_9 \
{ \
   G256_8WAY_ALT( V0, V4, V8, VC,       v256_32( CS2 )  , \
                  _mm256_xor_si256( M2, v256_32( CSA ) ) ); \
   G256_8WAY_ALT( V1, V5, V9, VD,       v256_32( CS4 )  , \
                  _mm256_xor_si256( M4, v256_32( CS8 ) ) ); \
   G256_8WAY_ALT( V2, V6, VA, VE,       v256_32( CS6 )  , \
                                        v256_32( CS7 )    ); \
   G256_8WAY_ALT( V3, V7, VB, VF, \
                  _mm256_xor_si256( M1, v256_32( CS5 ) ), \
                                        v256_32( CS1 )   ); \
   G256_8WAY_ALT( V0, V5, VA, VF, \
                  _mm256_xor_si256( MF, v256_32( CSB ) ), \
                                        v256_32( CSF )   ); \
   G256_8WAY_ALT( V1, V6, VB, VC,       v256_32( CSE )  , \
                                        v256_32( CS9 )   ); \
   G256_8WAY_ALT( V2, V7, V8, VD, \
                  _mm256_xor_si256( M3, v256_32( CSC ) ), \
                                        v256_32( CS3 )   ); \
   G256_8WAY_ALT( V3, V4, V9, VE, \
                  _mm256_xor_si256( MD, v256_32( CS0 ) ), \
                  _mm256_xor_si256( M0, v256_32( CSD ) ) ); \
}

#define DECL_STATE32_8WAY \
   __m256i H0, H1, H2, H3, H4, H5, H6, H7; \
   uint32_t T0, T1;

#define READ_STATE32_8WAY(state) \
do { \
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

#define WRITE_STATE32_8WAY(state) \
do { \
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

#define COMPRESS32_8WAY( rounds ) \
{ \
   __m256i M0, M1, M2, M3, M4, M5, M6, M7; \
   __m256i M8, M9, MA, MB, MC, MD, ME, MF; \
   __m256i V0, V1, V2, V3, V4, V5, V6, V7; \
   __m256i V8, V9, VA, VB, VC, VD, VE, VF; \
   V0 = H0; \
   V1 = H1; \
   V2 = H2; \
   V3 = H3; \
   V4 = H4; \
   V5 = H5; \
   V6 = H6; \
   V7 = H7; \
   V8 = v256_64( 0x243F6A88243F6A88 ); \
   V9 = v256_64( 0x85A308D385A308D3 ); \
   VA = v256_64( 0x13198A2E13198A2E ); \
   VB = v256_64( 0x0370734403707344 ); \
   VC = v256_32( T0 ^ 0xA4093822 ); \
   VD = v256_32( T0 ^ 0x299F31D0 ); \
   VE = v256_32( T1 ^ 0x082EFA98 ); \
   VF = v256_32( T1 ^ 0xEC4E6C89 ); \
   const __m256i shuf_bswap32 = mm256_set2_64( \
                               0x0c0d0e0f08090a0b, 0x0405060700010203 ); \
   M0 = _mm256_shuffle_epi8( * buf    , shuf_bswap32 ); \
   M1 = _mm256_shuffle_epi8( *(buf+ 1), shuf_bswap32 ); \
   M2 = _mm256_shuffle_epi8( *(buf+ 2), shuf_bswap32 ); \
   M3 = _mm256_shuffle_epi8( *(buf+ 3), shuf_bswap32 ); \
   M4 = _mm256_shuffle_epi8( *(buf+ 4), shuf_bswap32 ); \
   M5 = _mm256_shuffle_epi8( *(buf+ 5), shuf_bswap32 ); \
   M6 = _mm256_shuffle_epi8( *(buf+ 6), shuf_bswap32 ); \
   M7 = _mm256_shuffle_epi8( *(buf+ 7), shuf_bswap32 ); \
   M8 = _mm256_shuffle_epi8( *(buf+ 8), shuf_bswap32 ); \
   M9 = _mm256_shuffle_epi8( *(buf+ 9), shuf_bswap32 ); \
   MA = _mm256_shuffle_epi8( *(buf+10), shuf_bswap32 ); \
   MB = _mm256_shuffle_epi8( *(buf+11), shuf_bswap32 ); \
   MC = _mm256_shuffle_epi8( *(buf+12), shuf_bswap32 ); \
   MD = _mm256_shuffle_epi8( *(buf+13), shuf_bswap32 ); \
   ME = _mm256_shuffle_epi8( *(buf+14), shuf_bswap32 ); \
   MF = _mm256_shuffle_epi8( *(buf+15), shuf_bswap32 ); \
   ROUND_S_8WAY(0); \
   ROUND_S_8WAY(1); \
   ROUND_S_8WAY(2); \
   ROUND_S_8WAY(3); \
   ROUND_S_8WAY(4); \
   ROUND_S_8WAY(5); \
   ROUND_S_8WAY(6); \
   ROUND_S_8WAY(7); \
   if (rounds > 8) \
   { \
      ROUND_S_8WAY(8); \
      ROUND_S_8WAY(9); \
      ROUND_S_8WAY(0); \
      ROUND_S_8WAY(1); \
      ROUND_S_8WAY(2); \
      ROUND_S_8WAY(3); \
   } \
   H0 = mm256_xor3( V8, V0, H0 ); \
   H1 = mm256_xor3( V9, V1, H1 ); \
   H2 = mm256_xor3( VA, V2, H2 ); \
   H3 = mm256_xor3( VB, V3, H3 ); \
   H4 = mm256_xor3( VC, V4, H4 ); \
   H5 = mm256_xor3( VD, V5, H5 ); \
   H6 = mm256_xor3( VE, V6, H6 ); \
   H7 = mm256_xor3( VF, V7, H7 ); \
}

#define COMPRESS32_8WAY_LE( rounds ) \
{ \
   __m256i M0, M1, M2, M3, M4, M5, M6, M7; \
   __m256i M8, M9, MA, MB, MC, MD, ME, MF; \
   __m256i V0, V1, V2, V3, V4, V5, V6, V7; \
   __m256i V8, V9, VA, VB, VC, VD, VE, VF; \
   V0 = H0; \
   V1 = H1; \
   V2 = H2; \
   V3 = H3; \
   V4 = H4; \
   V5 = H5; \
   V6 = H6; \
   V7 = H7; \
   V8 = v256_64( 0x243F6A88243F6A88 ); \
   V9 = v256_64( 0x85A308D385A308D3 ); \
   VA = v256_64( 0x13198A2E13198A2E ); \
   VB = v256_64( 0x0370734403707344 ); \
   VC = v256_32( T0 ^ 0xA4093822 ); \
   VD = v256_32( T0 ^ 0x299F31D0 ); \
   VE = v256_32( T1 ^ 0x082EFA98 ); \
   VF = v256_32( T1 ^ 0xEC4E6C89 ); \
   M0 = buf[ 0]; \
   M1 = buf[ 1]; \
   M2 = buf[ 2]; \
   M3 = buf[ 3]; \
   M4 = buf[ 4]; \
   M5 = buf[ 5]; \
   M6 = buf[ 6]; \
   M7 = buf[ 7]; \
   M8 = buf[ 8]; \
   M9 = buf[ 9]; \
   MA = buf[10]; \
   MB = buf[11]; \
   MC = buf[12]; \
   MD = buf[13]; \
   ME = buf[14]; \
   MF = buf[15]; \
   ROUND_S_8WAY(0); \
   ROUND_S_8WAY(1); \
   ROUND_S_8WAY(2); \
   ROUND_S_8WAY(3); \
   ROUND_S_8WAY(4); \
   ROUND_S_8WAY(5); \
   ROUND_S_8WAY(6); \
   ROUND_S_8WAY(7); \
   if (rounds > 8) \
   { \
      ROUND_S_8WAY(8); \
      ROUND_S_8WAY(9); \
      ROUND_S_8WAY(0); \
      ROUND_S_8WAY(1); \
      ROUND_S_8WAY(2); \
      ROUND_S_8WAY(3); \
   } \
   H0 = mm256_xor3( V8, V0, H0 ); \
   H1 = mm256_xor3( V9, V1, H1 ); \
   H2 = mm256_xor3( VA, V2, H2 ); \
   H3 = mm256_xor3( VB, V3, H3 ); \
   H4 = mm256_xor3( VC, V4, H4 ); \
   H5 = mm256_xor3( VD, V5, H5 ); \
   H6 = mm256_xor3( VE, V6, H6 ); \
   H7 = mm256_xor3( VF, V7, H7 ); \
}

void blake256_8way_round0_prehash_le( void *midstate, const void *midhash,
                                      void *data )
{
   __m256i *M = (__m256i*)data;
   __m256i *V = (__m256i*)midstate;
   const __m256i *H = (const __m256i*)midhash;

   V[ 0] = H[0];
   V[ 1] = H[1];
   V[ 2] = H[2];
   V[ 3] = H[3];
   V[ 4] = H[4];
   V[ 5] = H[5];
   V[ 6] = H[6];
   V[ 7] = H[7];
   V[ 8] = v256_32( CS0 );
   V[ 9] = v256_32( CS1 );
   V[10] = v256_32( CS2 );
   V[11] = v256_32( CS3 );
   V[12] = v256_32( CS4 ^ 0x280 );
   V[13] = v256_32( CS5 ^ 0x280 );
   V[14] = v256_32( CS6 );
   V[15] = v256_32( CS7 );

// M[ 0:3 ] contain new message data including unique nonces in M[ 3].
// M[ 5:12, 14 ] are always zero and not needed or used.
// M[ 4], M[13], M[15] are constant and are initialized here.
// M[ 5] is a special case, used as a cache for (M[13] ^ CSC).

   M[ 4] = v256_32( 0x80000000 );
   M[13] = v256_32( 1 );
   M[15] = v256_32( 80*8 );

   M[ 5] =_mm256_xor_si256( M[13], v256_32( CSC ) );

   // G0   
   GS_8WAY( M[ 0], M[ 1], CS0, CS1, V[ 0], V[ 4], V[ 8], V[12] );

   // G1   
   V[ 1] = _mm256_add_epi32( _mm256_add_epi32( V[ 1], V[ 5] ),
                         _mm256_xor_si256( v256_32( CS3 ), M[ 2] ) );
   V[13] = mm256_ror_32( _mm256_xor_si256( V[13], V[ 1] ), 16 );
   V[ 9] = _mm256_add_epi32( V[ 9], V[13] );
   V[ 5] = mm256_ror_32( _mm256_xor_si256( V[ 5], V[ 9] ), 12 );
   V[ 1] = _mm256_add_epi32( V[ 1], V[ 5] );

   // G2
   // GS_8WAY( M[ 4], M[ 5], CS4, CS5, V[ 2], V[ 6], V[10], V[14] );
   V[ 2] = _mm256_add_epi32( _mm256_add_epi32( V[ 2], V[ 6] ),
                       _mm256_xor_si256( v256_32( CS5 ), M[ 4] ) );
   V[14] = mm256_ror_32( _mm256_xor_si256( V[14], V[ 2] ), 16 );
   V[10] = _mm256_add_epi32( V[10], V[14] );
   V[ 6] = mm256_ror_32( _mm256_xor_si256( V[ 6], V[10] ), 12 );
   V[ 2] = _mm256_add_epi32( _mm256_add_epi32( V[ 2], V[ 6] ),
                             v256_32( CS4 ) );
   V[14] = mm256_ror_32( _mm256_xor_si256( V[14], V[ 2] ), 8 );
   V[10] = _mm256_add_epi32( V[10], V[14] );
   V[ 6] = mm256_ror_32( _mm256_xor_si256( V[ 6], V[10] ), 7 );

   // G3
   // GS_8WAY( M[ 6], M[ 7], CS6, CS7, V[ 3], V[ 7], V[11], V[15] );
   V[ 3] = _mm256_add_epi32( _mm256_add_epi32( V[ 3], V[ 7] ),
                             v256_32( CS7 ) );
   V[15] = mm256_ror_32( _mm256_xor_si256( V[15], V[ 3] ), 16 );
   V[11] = _mm256_add_epi32( V[11], V[15] );
   V[ 7] = mm256_ror_32( _mm256_xor_si256( V[ 7], V[11] ), 12 );
   V[ 3] = _mm256_add_epi32( _mm256_add_epi32( V[ 3], V[ 7] ),
                             v256_32( CS6 ) );
   V[15] = mm256_ror_32( _mm256_xor_si256( V[15], V[ 3] ), 8 );
   V[11] = _mm256_add_epi32( V[11], V[15] );
   V[ 7] = mm256_ror_32( _mm256_xor_si256( V[ 7], V[11] ), 7 );

   // G4   
   V[ 0] = _mm256_add_epi32( V[ 0], v256_32( CS9 ) );

   // G5
   // GS_8WAY( M[10], M[11], CSA, CSB, V1, V6, VB, VC );

   // G6   
   V[ 2] = _mm256_add_epi32( _mm256_add_epi32( V[ 2], V[ 7] ),
                             v256_32( CSD ) );

   // G7   
   V[ 3] = _mm256_add_epi32( _mm256_add_epi32( V[ 3], V[ 4] ),
                             v256_32( CSF ) );
   V[14] = mm256_ror_32( _mm256_xor_si256( V[14], V[ 3] ), 16 );
   V[ 3] = _mm256_add_epi32( V[ 3],
                         _mm256_xor_si256( v256_32( CSE ), M[15] ) );
}

void blake256_8way_final_rounds_le( void *final_hash, const void *midstate,
                     const void *midhash, const void *data, const int rounds )
{
   __m256i *H = (__m256i*)final_hash;
   const __m256i *h = (const __m256i*)midhash;
   __m256i V0, V1, V2, V3, V4, V5, V6, V7;
   __m256i V8, V9, VA, VB, VC, VD, VE, VF;
   __m256i M0, M1, M2, M3, M4, MD, MF;
   __m256i MDxorCSC;

   V0 = _mm256_load_si256( (__m256i*)midstate +  0 );
   V1 = _mm256_load_si256( (__m256i*)midstate +  1 );
   V2 = _mm256_load_si256( (__m256i*)midstate +  2 );
   V3 = _mm256_load_si256( (__m256i*)midstate +  3 );
   V4 = _mm256_load_si256( (__m256i*)midstate +  4 );
   V5 = _mm256_load_si256( (__m256i*)midstate +  5 );
   V6 = _mm256_load_si256( (__m256i*)midstate +  6 );
   V7 = _mm256_load_si256( (__m256i*)midstate +  7 );
   V8 = _mm256_load_si256( (__m256i*)midstate +  8 );
   V9 = _mm256_load_si256( (__m256i*)midstate +  9 );
   VA = _mm256_load_si256( (__m256i*)midstate + 10 );
   VB = _mm256_load_si256( (__m256i*)midstate + 11 );
   VC = _mm256_load_si256( (__m256i*)midstate + 12 );
   VD = _mm256_load_si256( (__m256i*)midstate + 13 );
   VE = _mm256_load_si256( (__m256i*)midstate + 14 );
   VF = _mm256_load_si256( (__m256i*)midstate + 15 );

   M0 = _mm256_load_si256( (__m256i*)data +  0 );
   M1 = _mm256_load_si256( (__m256i*)data +  1 );
   M2 = _mm256_load_si256( (__m256i*)data +  2 );
   M3 = _mm256_load_si256( (__m256i*)data +  3 );
   M4 = _mm256_load_si256( (__m256i*)data +  4 );
   // M5 to MC & ME zero padding & optimised out.
   MD = _mm256_load_si256( (__m256i*)data + 13 );
   MF = _mm256_load_si256( (__m256i*)data + 15 );
   // precalculated MD^CSC, used in round0 G6.
   MDxorCSC = _mm256_load_si256( (__m256i*)data +  5 );
   
   // Finish round 0 with nonce in M3 
   // G1   
   V1 = _mm256_add_epi32( V1,
                         _mm256_xor_si256( v256_32( CS2 ), M3 ) );
   VD = mm256_ror_32( _mm256_xor_si256( VD, V1 ), 8 );
   V9 = _mm256_add_epi32( V9, VD );
   V5 = mm256_ror_32( _mm256_xor_si256( V5, V9 ), 7 );

   // G4
   V0 = _mm256_add_epi32( V0, V5 );
   VF = mm256_ror_32( _mm256_xor_si256( VF, V0 ), 16 );
   VA = _mm256_add_epi32( VA, VF );
   V5 = mm256_ror_32( _mm256_xor_si256( V5, VA ), 12 );
   V0 = _mm256_add_epi32( V0, _mm256_add_epi32( V5,
                             v256_32( CS8 ) ) );
   VF = mm256_ror_32( _mm256_xor_si256( VF, V0 ), 8 );
   VA = _mm256_add_epi32( VA, VF );
   V5 = mm256_ror_32( _mm256_xor_si256( V5, VA ), 7 );

   // G5
   // GS_8WAY( MA, MB, CSA, CSB, V1, V6, VB, VC );
   V1 = _mm256_add_epi32( _mm256_add_epi32( V1, V6 ),
                          v256_32( CSB ) );
   VC = mm256_ror_32( _mm256_xor_si256( VC, V1 ), 16 );
   VB = _mm256_add_epi32( VB, VC );
   V6 = mm256_ror_32( _mm256_xor_si256( V6, VB ), 12 );
   V1 = _mm256_add_epi32( _mm256_add_epi32( V1, V6 ),
                         v256_32( CSA ) );
   VC = mm256_ror_32( _mm256_xor_si256( VC, V1 ), 8 );
   VB = _mm256_add_epi32( VB, VC );
   V6 = mm256_ror_32( _mm256_xor_si256( V6, VB ), 7 );

   // G6
   VD = mm256_ror_32( _mm256_xor_si256( VD, V2 ), 16 );
   V8 = _mm256_add_epi32( V8, VD );
   V7 = mm256_ror_32( _mm256_xor_si256( V7, V8 ), 12 );
   V2 = _mm256_add_epi32( V2, _mm256_add_epi32( V7, MDxorCSC ) );
   VD = mm256_ror_32( _mm256_xor_si256( VD, V2 ), 8 );
   V8 = _mm256_add_epi32( V8, VD );
   V7 = mm256_ror_32( _mm256_xor_si256( V7, V8 ), 7 );

   // G7
   V9 = _mm256_add_epi32( V9, VE );
   V4 = mm256_ror_32( _mm256_xor_si256( V4, V9 ), 12 );
   V3 = _mm256_add_epi32( V3, V4 );
   VE = mm256_ror_32( _mm256_xor_si256( VE, V3 ), 8 );
   V9 = _mm256_add_epi32( V9, VE );
   V4 = mm256_ror_32( _mm256_xor_si256( V4, V9 ), 7 );

   // Remaining rounds   
   ROUND256_8WAY_1;
   ROUND256_8WAY_2;
   ROUND256_8WAY_3;
   ROUND256_8WAY_4;
   ROUND256_8WAY_5;
   ROUND256_8WAY_6;
   ROUND256_8WAY_7;
   if ( rounds > 8 )
   {
      ROUND256_8WAY_8;
      ROUND256_8WAY_9;
      ROUND256_8WAY_0;
      ROUND256_8WAY_1;
      ROUND256_8WAY_2;
      ROUND256_8WAY_3;
   }

   const __m256i shuf_bswap32 =
                  mm256_set2_64( 0x0c0d0e0f08090a0b, 0x0405060700010203 );

   H[0] = _mm256_shuffle_epi8( mm256_xor3( V8, V0, h[0] ), shuf_bswap32 );
   H[1] = _mm256_shuffle_epi8( mm256_xor3( V9, V1, h[1] ), shuf_bswap32 );
   H[2] = _mm256_shuffle_epi8( mm256_xor3( VA, V2, h[2] ), shuf_bswap32 );
   H[3] = _mm256_shuffle_epi8( mm256_xor3( VB, V3, h[3] ), shuf_bswap32 );
   H[4] = _mm256_shuffle_epi8( mm256_xor3( VC, V4, h[4] ), shuf_bswap32 );
   H[5] = _mm256_shuffle_epi8( mm256_xor3( VD, V5, h[5] ), shuf_bswap32 );
   H[6] = _mm256_shuffle_epi8( mm256_xor3( VE, V6, h[6] ), shuf_bswap32 );
   H[7] = _mm256_shuffle_epi8( mm256_xor3( VF, V7, h[7] ), shuf_bswap32 );
}

#endif

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

///////////////////////////////////////
//
//   Blake-256 16 way AVX512

// Generic with full inline message expansion
#define GS_16WAY( m0, m1, c0, c1, a, b, c, d ) \
{ \
   a = _mm512_add_epi32( _mm512_add_epi32( a, b ), \
                         _mm512_xor_si512( v512_32( c1 ), m0 ) ); \
   d = mm512_ror_32( _mm512_xor_si512( d, a ), 16 ); \
   c = _mm512_add_epi32( c, d ); \
   b = mm512_ror_32( _mm512_xor_si512( b, c ), 12 ); \
   a = _mm512_add_epi32( _mm512_add_epi32( a, b ), \
                         _mm512_xor_si512( v512_32( c0 ), m1 ) ); \
   d = mm512_ror_32( _mm512_xor_si512( d, a ), 8 ); \
   c = _mm512_add_epi32( c, d ); \
   b = mm512_ror_32( _mm512_xor_si512( b, c ), 7 ); \
}

#define ROUND_S_16WAY(r) \
{ \
        GS_16WAY(Mx(r, 0), Mx(r, 1), CSx(r, 0), CSx(r, 1), V0, V4, V8, VC); \
        GS_16WAY(Mx(r, 2), Mx(r, 3), CSx(r, 2), CSx(r, 3), V1, V5, V9, VD); \
        GS_16WAY(Mx(r, 4), Mx(r, 5), CSx(r, 4), CSx(r, 5), V2, V6, VA, VE); \
        GS_16WAY(Mx(r, 6), Mx(r, 7), CSx(r, 6), CSx(r, 7), V3, V7, VB, VF); \
        GS_16WAY(Mx(r, 8), Mx(r, 9), CSx(r, 8), CSx(r, 9), V0, V5, VA, VF); \
        GS_16WAY(Mx(r, A), Mx(r, B), CSx(r, A), CSx(r, B), V1, V6, VB, VC); \
        GS_16WAY(Mx(r, C), Mx(r, D), CSx(r, C), CSx(r, D), V2, V7, V8, VD); \
        GS_16WAY(Mx(r, E), Mx(r, F), CSx(r, E), CSx(r, F), V3, V4, V9, VE); \
}

// Short cut message expansion when the message data is known to be zero.
// M[ 5:12, 14 ] are zero padded for the second block of 80 byte data.

#define G256_16WAY_ALT( a, b, c, d, m0, m1 ) \
{ \
   a = _mm512_add_epi32( _mm512_add_epi32( a, b ), m0 ); \
   d = mm512_ror_32( _mm512_xor_si512( d, a ), 16 ); \
   c = _mm512_add_epi32( c, d ); \
   b = mm512_ror_32( _mm512_xor_si512( b, c ), 12 ); \
   a = _mm512_add_epi32( _mm512_add_epi32( a, b ), m1 ); \
   d = mm512_ror_32( _mm512_xor_si512( d, a ), 8 ); \
   c = _mm512_add_epi32( c, d ); \
   b = mm512_ror_32( _mm512_xor_si512( b, c ), 7 ); \
}

// Message expansion optimized for each round.
#define ROUND256_16WAY_0 \
{ \
   G256_16WAY_ALT( V0, V4, V8, VC, \
                   _mm512_xor_si512( M0, v512_32( CS1 ) ), \
                   _mm512_xor_si512( M1, v512_32( CS0 ) ) ); \
   G256_16WAY_ALT( V1, V5, V9, VD, \
                   _mm512_xor_si512( M2, v512_32( CS3 ) ), \
                   _mm512_xor_si512( M3, v512_32( CS2 ) ) ); \
   G256_16WAY_ALT( V2, V6, VA, VE, \
                   _mm512_xor_si512( M4, v512_32( CS5 ) ), \
                                         v512_32( CS4 )   ); \
   G256_16WAY_ALT( V3, V7, VB, VF,       v512_32( CS7 )  , \
                                         v512_32( CS6 )   ); \
   G256_16WAY_ALT( V0, V5, VA, VF,       v512_32( CS9 )  , \
                                         v512_32( CS8 )   ); \
   G256_16WAY_ALT( V1, V6, VB, VC,       v512_32( CSB )  , \
                                         v512_32( CSA )   ); \
   G256_16WAY_ALT( V2, V7, V8, VD,       v512_32( CSD )  , \
                   _mm512_xor_si512( MD, v512_32( CSC ) ) ); \
   G256_16WAY_ALT( V3, V4, V9, VE,       v512_32( CSF )  , \
                   _mm512_xor_si512( MF, v512_32( CSE ) ) ); \
}

#define ROUND256_16WAY_1 \
{ \
   G256_16WAY_ALT( V0, V4, V8, VC,       v512_32( CSA )  , \
                                         v512_32( CSE )   ); \
   G256_16WAY_ALT( V1, V5, V9, VD, \
                   _mm512_xor_si512( M4, v512_32( CS8 ) ), \
                                         v512_32( CS4 )   ); \
   G256_16WAY_ALT( V2, V6, VA, VE,       v512_32( CSF )  , \
                   _mm512_xor_si512( MF, v512_32( CS9 ) ) ); \
   G256_16WAY_ALT( V3, V7, VB, VF, \
                   _mm512_xor_si512( MD, v512_32( CS6 ) ), \
                                         v512_32( CSD )   ); \
   G256_16WAY_ALT( V0, V5, VA, VF, \
                   _mm512_xor_si512( M1, v512_32( CSC ) ), \
                                         v512_32( CS1 )   ); \
   G256_16WAY_ALT( V1, V6, VB, VC, \
                   _mm512_xor_si512( M0, v512_32( CS2 ) ), \
                   _mm512_xor_si512( M2, v512_32( CS0 ) ) ); \
   G256_16WAY_ALT( V2, V7, V8, VD,       v512_32( CS7 )  , \
                                         v512_32( CSB )   ); \
   G256_16WAY_ALT( V3, V4, V9, VE,       v512_32( CS3 )  , \
                   _mm512_xor_si512( M3, v512_32( CS5 ) ) ); \
}

#define ROUND256_16WAY_2 \
{ \
   G256_16WAY_ALT( V0, V4, V8, VC,       v512_32( CS8 )  , \
                                         v512_32( CSB )   ); \
   G256_16WAY_ALT( V1, V5, V9, VD,       v512_32( CS0 )  , \
                   _mm512_xor_si512( M0, v512_32( CSC ) ) ); \
   G256_16WAY_ALT( V2, V6, VA, VE,       v512_32( CS2 )  , \
                   _mm512_xor_si512( M2, v512_32( CS5 ) ) ); \
   G256_16WAY_ALT( V3, V7, VB, VF, \
                   _mm512_xor_si512( MF, v512_32( CSD ) ), \
                   _mm512_xor_si512( MD, v512_32( CSF ) ) ); \
   G256_16WAY_ALT( V0, V5, VA, VF,       v512_32( CSE )  , \
                                         v512_32( CSA )   ); \
   G256_16WAY_ALT( V1, V6, VB, VC, \
                   _mm512_xor_si512( M3, v512_32( CS6 ) ), \
                                         v512_32( CS3 )   ); \
   G256_16WAY_ALT( V2, V7, V8, VD,       v512_32( CS1 )  , \
                   _mm512_xor_si512( M1, v512_32( CS7 ) ) ); \
   G256_16WAY_ALT( V3, V4, V9, VE,       v512_32( CS4 )  , \
                   _mm512_xor_si512( M4, v512_32( CS9 ) ) ); \
}

#define ROUND256_16WAY_3 \
{ \
   G256_16WAY_ALT( V0, V4, V8, VC,       v512_32( CS9 )  , \
                                         v512_32( CS7 )   ); \
   G256_16WAY_ALT( V1, V5, V9, VD, \
                   _mm512_xor_si512( M3, v512_32( CS1 ) ), \
                   _mm512_xor_si512( M1, v512_32( CS3 ) ) ); \
   G256_16WAY_ALT( V2, V6, VA, VE, \
                   _mm512_xor_si512( MD, v512_32( CSC ) ), \
                                         v512_32( CSD )   ); \
   G256_16WAY_ALT( V3, V7, VB, VF,       v512_32( CSE )  , \
                                         v512_32( CSB )   ); \
   G256_16WAY_ALT( V0, V5, VA, VF, \
                   _mm512_xor_si512( M2, v512_32( CS6 ) ), \
                                         v512_32( CS2 )   ); \
   G256_16WAY_ALT( V1, V6, VB, VC,       v512_32( CSA )  , \
                                         v512_32( CS5 )   ); \
   G256_16WAY_ALT( V2, V7, V8, VD, \
                   _mm512_xor_si512( M4, v512_32( CS0 ) ), \
                   _mm512_xor_si512( M0, v512_32( CS4 ) ) ); \
   G256_16WAY_ALT( V3, V4, V9, VE, \
                   _mm512_xor_si512( MF, v512_32( CS8 ) ), \
                                         v512_32( CSF )   ); \
}

#define ROUND256_16WAY_4 \
{ \
   G256_16WAY_ALT( V0, V4, V8, VC,       v512_32( CS0 )  , \
                   _mm512_xor_si512( M0, v512_32( CS9 ) ) ); \
   G256_16WAY_ALT( V1, V5, V9, VD,       v512_32( CS7 )  , \
                                         v512_32( CS5 )   ); \
   G256_16WAY_ALT( V2, V6, VA, VE, \
                   _mm512_xor_si512( M2, v512_32( CS4 ) ), \
                   _mm512_xor_si512( M4, v512_32( CS2 ) )  ); \
   G256_16WAY_ALT( V3, V7, VB, VF,       v512_32( CSF )  , \
                   _mm512_xor_si512( MF, v512_32( CSA ) ) ); \
   G256_16WAY_ALT( V0, V5, VA, VF,       v512_32( CS1 )  , \
                   _mm512_xor_si512( M1, v512_32( CSE ) ) ); \
   G256_16WAY_ALT( V1, V6, VB, VC,       v512_32( CSC )  , \
                                         v512_32( CSB )   ); \
   G256_16WAY_ALT( V2, V7, V8, VD,       v512_32( CS8 )  , \
                                         v512_32( CS6 )   ); \
   G256_16WAY_ALT( V3, V4, V9, VE, \
                   _mm512_xor_si512( M3, v512_32( CSD ) ), \
                   _mm512_xor_si512( MD, v512_32( CS3 ) ) ); \
}

#define ROUND256_16WAY_5 \
{ \
   G256_16WAY_ALT( V0, V4, V8, VC, \
                   _mm512_xor_si512( M2, v512_32( CSC ) ), \
                                         v512_32( CS2 )   ); \
   G256_16WAY_ALT( V1, V5, V9, VD,       v512_32( CSA )  , \
                                         v512_32( CS6 )   ); \
   G256_16WAY_ALT( V2, V6, VA, VE, \
                   _mm512_xor_si512( M0, v512_32( CSB ) ), \
                                         v512_32( CS0 )   ); \
   G256_16WAY_ALT( V3, V7, VB, VF,       v512_32( CS3 )  , \
                   _mm512_xor_si512( M3, v512_32( CS8 ) ) ); \
   G256_16WAY_ALT( V0, V5, VA, VF, \
                   _mm512_xor_si512( M4, v512_32( CSD ) ), \
                   _mm512_xor_si512( MD, v512_32( CS4 ) ) ); \
   G256_16WAY_ALT( V1, V6, VB, VC,       v512_32( CS5 )  , \
                                         v512_32( CS7 )   ); \
   G256_16WAY_ALT( V2, V7, V8, VD, \
                   _mm512_xor_si512( MF, v512_32( CSE ) ), \
                                         v512_32( CSF )   ); \
   G256_16WAY_ALT( V3, V4, V9, VE, \
                   _mm512_xor_si512( M1, v512_32( CS9 ) ), \
                                         v512_32( CS1 )   ); \
}

#define ROUND256_16WAY_6 \
{ \
   G256_16WAY_ALT( V0, V4, V8, VC,       v512_32( CS5 )  , \
                                         v512_32( CSC )   ); \
   G256_16WAY_ALT( V1, V5, V9, VD, \
                   _mm512_xor_si512( M1, v512_32( CSF ) ), \
                   _mm512_xor_si512( MF, v512_32( CS1 ) ) ); \
   G256_16WAY_ALT( V2, V6, VA, VE,       v512_32( CSD )  , \
                   _mm512_xor_si512( MD, v512_32( CSE ) ) );\
   G256_16WAY_ALT( V3, V7, VB, VF, \
                   _mm512_xor_si512( M4, v512_32( CSA ) ), \
                                         v512_32( CS4 )   ); \
   G256_16WAY_ALT( V0, V5, VA, VF, \
                   _mm512_xor_si512( M0, v512_32( CS7 ) ), \
                                         v512_32( CS0 )   ); \
   G256_16WAY_ALT( V1, V6, VB, VC,       v512_32( CS3 )  , \
                   _mm512_xor_si512( M3, v512_32( CS6 ) ) ); \
   G256_16WAY_ALT( V2, V7, V8, VD,       v512_32( CS2 )  , \
                   _mm512_xor_si512( M2, v512_32( CS9 ) ) ); \
   G256_16WAY_ALT( V3, V4, V9, VE,       v512_32( CSB )  , \
                                         v512_32( CS8 )   ); \
}

#define ROUND256_16WAY_7 \
{ \
   G256_16WAY_ALT( V0, V4, V8, VC, \
                   _mm512_xor_si512( MD, v512_32( CSB ) ), \
                                         v512_32( CSD )   ); \
   G256_16WAY_ALT( V1, V5, V9, VD,       v512_32( CSE )  , \
                                         v512_32( CS7 )   ); \
   G256_16WAY_ALT( V2, V6, VA, VE,       v512_32( CS1 )  , \
                   _mm512_xor_si512( M1, v512_32( CSC ) ) ); \
   G256_16WAY_ALT( V3, V7, VB, VF, \
                   _mm512_xor_si512( M3, v512_32( CS9 ) ), \
                                         v512_32( CS3 )   ); \
   G256_16WAY_ALT( V0, V5, VA, VF,       v512_32( CS0 )  , \
                   _mm512_xor_si512( M0, v512_32( CS5 ) ) ); \
   G256_16WAY_ALT( V1, V6, VB, VC, \
                   _mm512_xor_si512( MF, v512_32( CS4 ) ), \
                   _mm512_xor_si512( M4, v512_32( CSF ) ) ); \
   G256_16WAY_ALT( V2, V7, V8, VD,       v512_32( CS6 )  , \
                                         v512_32( CS8 )   ); \
   G256_16WAY_ALT( V3, V4, V9, VE, \
                   _mm512_xor_si512( M2, v512_32( CSA ) ), \
                                         v512_32( CS2 )   ); \
}

#define ROUND256_16WAY_8 \
{ \
   G256_16WAY_ALT( V0, V4, V8, VC,       v512_32( CSF   ), \
                   _mm512_xor_si512( MF, v512_32( CS6 ) ) ); \
   G256_16WAY_ALT( V1, V5, V9, VD,       v512_32( CS9 )  , \
                                         v512_32( CSE )   ); \
   G256_16WAY_ALT( V2, V6, VA, VE,       v512_32( CS3 )  , \
                   _mm512_xor_si512( M3, v512_32( CSB ) ) ); \
   G256_16WAY_ALT( V3, V7, VB, VF, \
                   _mm512_xor_si512( M0, v512_32( CS8 ) ), \
                                         v512_32( CS0 )   ); \
   G256_16WAY_ALT( V0, V5, VA, VF,       v512_32( CS2 )  , \
                   _mm512_xor_si512( M2, v512_32( CSC ) ) ); \
   G256_16WAY_ALT( V1, V6, VB, VC, \
                   _mm512_xor_si512( MD, v512_32( CS7 ) ), \
                                         v512_32( CSD )   ); \
   G256_16WAY_ALT( V2, V7, V8, VD, \
                   _mm512_xor_si512( M1, v512_32( CS4 ) ), \
                   _mm512_xor_si512( M4, v512_32( CS1 ) ) ); \
   G256_16WAY_ALT( V3, V4, V9, VE,       v512_32( CS5 )  , \
                                         v512_32( CSA )   ); \
}

#define ROUND256_16WAY_9 \
{ \
   G256_16WAY_ALT( V0, V4, V8, VC,       v512_32( CS2 )  , \
                   _mm512_xor_si512( M2, v512_32( CSA ) ) ); \
   G256_16WAY_ALT( V1, V5, V9, VD,       v512_32( CS4 )  , \
                   _mm512_xor_si512( M4, v512_32( CS8 ) ) ); \
   G256_16WAY_ALT( V2, V6, VA, VE,       v512_32( CS6 )  , \
                                         v512_32( CS7 )    ); \
   G256_16WAY_ALT( V3, V7, VB, VF, \
                   _mm512_xor_si512( M1, v512_32( CS5 ) ), \
                                         v512_32( CS1 )   ); \
   G256_16WAY_ALT( V0, V5, VA, VF, \
                   _mm512_xor_si512( MF, v512_32( CSB ) ), \
                                         v512_32( CSF )   ); \
   G256_16WAY_ALT( V1, V6, VB, VC,       v512_32( CSE )  , \
                                         v512_32( CS9 )   ); \
   G256_16WAY_ALT( V2, V7, V8, VD, \
                   _mm512_xor_si512( M3, v512_32( CSC ) ), \
                                         v512_32( CS3 )   ); \
   G256_16WAY_ALT( V3, V4, V9, VE, \
                   _mm512_xor_si512( MD, v512_32( CS0 ) ), \
                   _mm512_xor_si512( M0, v512_32( CSD ) ) ); \
}

#define DECL_STATE32_16WAY \
   __m512i H0, H1, H2, H3, H4, H5, H6, H7; \
   uint32_t T0, T1;

#define READ_STATE32_16WAY(state) \
do { \
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

#define WRITE_STATE32_16WAY(state) \
do { \
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

#define COMPRESS32_16WAY( rounds ) \
{ \
   __m512i M0, M1, M2, M3, M4, M5, M6, M7; \
   __m512i M8, M9, MA, MB, MC, MD, ME, MF; \
   __m512i V0, V1, V2, V3, V4, V5, V6, V7; \
   __m512i V8, V9, VA, VB, VC, VD, VE, VF; \
   const __m512i shuf_bswap32 = mm512_bcast_m128( v128_set64( \
                                 0x0c0d0e0f08090a0b, 0x0405060700010203 ) ); \
   V0 = H0; \
   V1 = H1; \
   V2 = H2; \
   V3 = H3; \
   V4 = H4; \
   V5 = H5; \
   V6 = H6; \
   V7 = H7; \
   V8 = v512_64( 0x243F6A88243F6A88 ); \
   V9 = v512_64( 0x85A308D385A308D3 ); \
   VA = v512_64( 0x13198A2E13198A2E ); \
   VB = v512_64( 0x0370734403707344 ); \
   VC = v512_32( T0 ^ 0xA4093822 ); \
   VD = v512_32( T0 ^ 0x299F31D0 ); \
   VE = v512_32( T1 ^ 0x082EFA98 ); \
   VF = v512_32( T1 ^ 0xEC4E6C89 ); \
   M0 = _mm512_shuffle_epi8( * buf    , shuf_bswap32 ); \
   M1 = _mm512_shuffle_epi8( *(buf+ 1), shuf_bswap32 ); \
   M2 = _mm512_shuffle_epi8( *(buf+ 2), shuf_bswap32 ); \
   M3 = _mm512_shuffle_epi8( *(buf+ 3), shuf_bswap32 ); \
   M4 = _mm512_shuffle_epi8( *(buf+ 4), shuf_bswap32 ); \
   M5 = _mm512_shuffle_epi8( *(buf+ 5), shuf_bswap32 ); \
   M6 = _mm512_shuffle_epi8( *(buf+ 6), shuf_bswap32 ); \
   M7 = _mm512_shuffle_epi8( *(buf+ 7), shuf_bswap32 ); \
   M8 = _mm512_shuffle_epi8( *(buf+ 8), shuf_bswap32 ); \
   M9 = _mm512_shuffle_epi8( *(buf+ 9), shuf_bswap32 ); \
   MA = _mm512_shuffle_epi8( *(buf+10), shuf_bswap32 ); \
   MB = _mm512_shuffle_epi8( *(buf+11), shuf_bswap32 ); \
   MC = _mm512_shuffle_epi8( *(buf+12), shuf_bswap32 ); \
   MD = _mm512_shuffle_epi8( *(buf+13), shuf_bswap32 ); \
   ME = _mm512_shuffle_epi8( *(buf+14), shuf_bswap32 ); \
   MF = _mm512_shuffle_epi8( *(buf+15), shuf_bswap32 ); \
   ROUND_S_16WAY(0); \
   ROUND_S_16WAY(1); \
   ROUND_S_16WAY(2); \
   ROUND_S_16WAY(3); \
   ROUND_S_16WAY(4); \
   ROUND_S_16WAY(5); \
   ROUND_S_16WAY(6); \
   ROUND_S_16WAY(7); \
   if (rounds == 14) \
   { \
      ROUND_S_16WAY(8); \
      ROUND_S_16WAY(9); \
      ROUND_S_16WAY(0); \
      ROUND_S_16WAY(1); \
      ROUND_S_16WAY(2); \
      ROUND_S_16WAY(3); \
   } \
   H0 = mm512_xor3( V8, V0, H0 ); \
   H1 = mm512_xor3( V9, V1, H1 ); \
   H2 = mm512_xor3( VA, V2, H2 ); \
   H3 = mm512_xor3( VB, V3, H3 ); \
   H4 = mm512_xor3( VC, V4, H4 ); \
   H5 = mm512_xor3( VD, V5, H5 ); \
   H6 = mm512_xor3( VE, V6, H6 ); \
   H7 = mm512_xor3( VF, V7, H7 ); \
}

#define COMPRESS32_16WAY_LE( rounds ) \
{ \
   __m512i M0, M1, M2, M3, M4, M5, M6, M7; \
   __m512i M8, M9, MA, MB, MC, MD, ME, MF; \
   __m512i V0, V1, V2, V3, V4, V5, V6, V7; \
   __m512i V8, V9, VA, VB, VC, VD, VE, VF; \
   V0 = H0; \
   V1 = H1; \
   V2 = H2; \
   V3 = H3; \
   V4 = H4; \
   V5 = H5; \
   V6 = H6; \
   V7 = H7; \
   V8 = v512_64( 0x243F6A88243F6A88 ); \
   V9 = v512_64( 0x85A308D385A308D3 ); \
   VA = v512_64( 0x13198A2E13198A2E ); \
   VB = v512_64( 0x0370734403707344 ); \
   VC = v512_32( T0 ^ 0xA4093822 ); \
   VD = v512_32( T0 ^ 0x299F31D0 ); \
   VE = v512_32( T1 ^ 0x082EFA98 ); \
   VF = v512_32( T1 ^ 0xEC4E6C89 ); \
   M0 = buf[ 0]; \
   M1 = buf[ 1]; \
   M2 = buf[ 2]; \
   M3 = buf[ 3]; \
   M4 = buf[ 4]; \
   M5 = buf[ 5]; \
   M6 = buf[ 6]; \
   M7 = buf[ 7]; \
   M8 = buf[ 8]; \
   M9 = buf[ 9]; \
   MA = buf[10]; \
   MB = buf[11]; \
   MC = buf[12]; \
   MD = buf[13]; \
   ME = buf[14]; \
   MF = buf[15]; \
   ROUND_S_16WAY(0); \
   ROUND_S_16WAY(1); \
   ROUND_S_16WAY(2); \
   ROUND_S_16WAY(3); \
   ROUND_S_16WAY(4); \
   ROUND_S_16WAY(5); \
   ROUND_S_16WAY(6); \
   ROUND_S_16WAY(7); \
   if (rounds == 14) \
   { \
      ROUND_S_16WAY(8); \
      ROUND_S_16WAY(9); \
      ROUND_S_16WAY(0); \
      ROUND_S_16WAY(1); \
      ROUND_S_16WAY(2); \
      ROUND_S_16WAY(3); \
   } \
   H0 = mm512_xor3( V8, V0, H0 ); \
   H1 = mm512_xor3( V9, V1, H1 ); \
   H2 = mm512_xor3( VA, V2, H2 ); \
   H3 = mm512_xor3( VB, V3, H3 ); \
   H4 = mm512_xor3( VC, V4, H4 ); \
   H5 = mm512_xor3( VD, V5, H5 ); \
   H6 = mm512_xor3( VE, V6, H6 ); \
   H7 = mm512_xor3( VF, V7, H7 ); \
}

// Blake-256 prehash of the second block is split onto 2 parts. The first part
// is constant for every nonce and only needs to be run once per job. The
// second part is run for each nonce using the precalculated midstate and the
// hash from the first block.
void blake256_16way_round0_prehash_le( void *midstate, const void *midhash,
                                       void *data )
{
   __m512i *M = (__m512i*)data;
   __m512i *V = (__m512i*)midstate;
   const __m512i *H = (const __m512i*)midhash;

   V[ 0] = H[0];
   V[ 1] = H[1];
   V[ 2] = H[2];
   V[ 3] = H[3];
   V[ 4] = H[4];
   V[ 5] = H[5];
   V[ 6] = H[6];
   V[ 7] = H[7];
   V[ 8] = v512_32( CS0 );
   V[ 9] = v512_32( CS1 );
   V[10] = v512_32( CS2 );
   V[11] = v512_32( CS3 );
   V[12] = v512_32( CS4 ^ 0x280 );
   V[13] = v512_32( CS5 ^ 0x280 );
   V[14] = v512_32( CS6 );
   V[15] = v512_32( CS7 );

// M[ 0:3 ] contain new message data including unique nonces in M[ 3].   
// M[ 5:12, 14 ] are always zero and not needed or used, except M[5] as noted.
// M[ 4], M[ 13], M[15] are constant and are initialized here.
// M[ 5] is a special case, used as a cache for (M[13] ^ CSC).
   
   M[ 4] = v512_32( 0x80000000 );
   M[13] = v512_32( 1 );
   M[15] = v512_32( 80*8 );

   M[ 5] =_mm512_xor_si512( M[13], v512_32( CSC ) );

   // G0   
   GS_16WAY( M[ 0], M[ 1], CS0, CS1, V[ 0], V[ 4], V[ 8], V[12] );

   // G1   
   // GS_16WAY( M[ 2], M[ 3], CS2, CS3, V1, V5, V9, VD );
   V[ 1] = _mm512_add_epi32( _mm512_add_epi32( V[ 1], V[ 5] ),
                         _mm512_xor_si512( v512_32( CS3 ), M[ 2] ) );
   V[13] = mm512_ror_32( _mm512_xor_si512( V[13], V[ 1] ), 16 );
   V[ 9] = _mm512_add_epi32( V[ 9], V[13] );
   V[ 5] = mm512_ror_32( _mm512_xor_si512( V[ 5], V[ 9] ), 12 );
   V[ 1] = _mm512_add_epi32( V[ 1], V[ 5] );

   // G2
   // GS_16WAY( M[ 4], M[ 5], CS4, CS5, V[ 2], V[ 6], V[10], V[14] );
   V[ 2] = _mm512_add_epi32( _mm512_add_epi32( V[ 2], V[ 6] ),
                       _mm512_xor_si512( v512_32( CS5 ), M[ 4] ) );
   V[14] = mm512_ror_32( _mm512_xor_si512( V[14], V[ 2] ), 16 );
   V[10] = _mm512_add_epi32( V[10], V[14] );
   V[ 6] = mm512_ror_32( _mm512_xor_si512( V[ 6], V[10] ), 12 );
   V[ 2] = _mm512_add_epi32( _mm512_add_epi32( V[ 2], V[ 6] ),
                             v512_32( CS4 ) );
   V[14] = mm512_ror_32( _mm512_xor_si512( V[14], V[ 2] ), 8 );
   V[10] = _mm512_add_epi32( V[10], V[14] ); \
   V[ 6] = mm512_ror_32( _mm512_xor_si512( V[ 6], V[10] ), 7 );

   // G3
   // GS_16WAY( M[ 6], M[ 7], CS6, CS7, V[ 3], V[ 7], V[11], V[15] );
   V[ 3] = _mm512_add_epi32( _mm512_add_epi32( V[ 3], V[ 7] ),
                             v512_32( CS7 ) );
   V[15] = mm512_ror_32( _mm512_xor_si512( V[15], V[ 3] ), 16 );
   V[11] = _mm512_add_epi32( V[11], V[15] );
   V[ 7] = mm512_ror_32( _mm512_xor_si512( V[ 7], V[11] ), 12 );
   V[ 3] = _mm512_add_epi32( _mm512_add_epi32( V[ 3], V[ 7] ),
                             v512_32( CS6 ) );
   V[15] = mm512_ror_32( _mm512_xor_si512( V[15], V[ 3] ), 8 );
   V[11] = _mm512_add_epi32( V[11], V[15] ); \
   V[ 7] = mm512_ror_32( _mm512_xor_si512( V[ 7], V[11] ), 7 );

   // G4   
   // GS_16WAY( M[ 8], M[ 9], CS8, CS9, V0, V5, VA, VF );
   V[ 0] = _mm512_add_epi32( V[ 0], v512_32( CS9 ) ); 
   
   // G5
   // GS_16WAY( M[10], M[11], CSA, CSB, V1, V6, VB, VC );

   // G6   
   // GS_16WAY( M[12], M[13], CSC, CSD, V2, V7, V8, VD );
   V[ 2] = _mm512_add_epi32( _mm512_add_epi32( V[ 2], V[ 7] ),
                             v512_32( CSD ) );
   // G7   
   // GS_16WAY( M[14], M[15], CSE, CSF, V3, V4, V9, VE );
   V[ 3] = _mm512_add_epi32( _mm512_add_epi32( V[ 3], V[ 4] ),
                             v512_32( CSF ) );
   V[14] = mm512_ror_32( _mm512_xor_si512( V[14], V[ 3] ), 16 );
   V[ 3] = _mm512_add_epi32( V[ 3],
                         _mm512_xor_si512( v512_32( CSE ), M[15] ) );
}

// Dfault is 14 rounds, blakecoin & vanilla are 8.
void blake256_16way_final_rounds_le( void *final_hash, const void *midstate,
                     const void *midhash, const void *data, const int rounds )
{
   __m512i *H = (__m512i*)final_hash;
   const __m512i *h = (const __m512i*)midhash;
   __m512i V0, V1, V2, V3, V4, V5, V6, V7;
   __m512i V8, V9, VA, VB, VC, VD, VE, VF;
   __m512i M0, M1, M2, M3, M4, MD, MF;
   __m512i MDxorCSC;

   V0 = _mm512_load_si512( (__m512i*)midstate +  0 );
   V1 = _mm512_load_si512( (__m512i*)midstate +  1 );
   V2 = _mm512_load_si512( (__m512i*)midstate +  2 );
   V3 = _mm512_load_si512( (__m512i*)midstate +  3 );
   V4 = _mm512_load_si512( (__m512i*)midstate +  4 );
   V5 = _mm512_load_si512( (__m512i*)midstate +  5 );
   V6 = _mm512_load_si512( (__m512i*)midstate +  6 );
   V7 = _mm512_load_si512( (__m512i*)midstate +  7 );
   V8 = _mm512_load_si512( (__m512i*)midstate +  8 );
   V9 = _mm512_load_si512( (__m512i*)midstate +  9 );
   VA = _mm512_load_si512( (__m512i*)midstate + 10 );
   VB = _mm512_load_si512( (__m512i*)midstate + 11 );
   VC = _mm512_load_si512( (__m512i*)midstate + 12 );
   VD = _mm512_load_si512( (__m512i*)midstate + 13 );
   VE = _mm512_load_si512( (__m512i*)midstate + 14 );
   VF = _mm512_load_si512( (__m512i*)midstate + 15 );

   M0 = _mm512_load_si512( (__m512i*)data +  0 ); 
   M1 = _mm512_load_si512( (__m512i*)data +  1 ); 
   M2 = _mm512_load_si512( (__m512i*)data +  2 ); 
   M3 = _mm512_load_si512( (__m512i*)data +  3 ); 
   M4 = _mm512_load_si512( (__m512i*)data +  4 ); 
   // M5 to MC & ME are zero padding and optimised out
   MD = _mm512_load_si512( (__m512i*)data + 13 ); 
   MF = _mm512_load_si512( (__m512i*)data + 15 ); 
   // cache for precalculated MD^CSC, used in round0 G6.
   MDxorCSC = _mm512_load_si512( (__m512i*)data +  5 );

   // Finish round 0 with the nonce (M3) now available
   // G0   
   // GS_16WAY( M0, M1, CS0, CS1, V0, V4, V8, VC );

   // G1   
   // GS_16WAY( M2, M3, CS2, CS3, V1, V5, V9, VD );
   V1 = _mm512_add_epi32( V1, 
                         _mm512_xor_si512( v512_32( CS2 ), M3 ) );
   VD = mm512_ror_32( _mm512_xor_si512( VD, V1 ), 8 );
   V9 = _mm512_add_epi32( V9, VD );
   V5 = mm512_ror_32( _mm512_xor_si512( V5, V9 ), 7 );
   
   // G2,G3   
   // GS_16WAY( M4, M5, CS4, CS5, V2, V6, VA, VE );
   // GS_16WAY( M6, M7, CS6, CS7, V3, V7, VB, VF );

   // G4
   // GS_16WAY( M8, M9, CS8, CS9, V0, V5, VA, VF );
   V0 = _mm512_add_epi32( V0, V5 );
   VF = mm512_ror_32( _mm512_xor_si512( VF, V0 ), 16 );
   VA = _mm512_add_epi32( VA, VF );
   V5 = mm512_ror_32( _mm512_xor_si512( V5, VA ), 12 );
   V0 = _mm512_add_epi32( V0, _mm512_add_epi32( V5,
                             v512_32( CS8 ) ) );
   VF = mm512_ror_32( _mm512_xor_si512( VF, V0 ), 8 );
   VA = _mm512_add_epi32( VA, VF );
   V5 = mm512_ror_32( _mm512_xor_si512( V5, VA ), 7 );

   // G5
   // GS_16WAY( MA, MB, CSA, CSB, V1, V6, VB, VC );
   V1 = _mm512_add_epi32( _mm512_add_epi32( V1, V6 ),
                          v512_32( CSB ) );
   VC = mm512_ror_32( _mm512_xor_si512( VC, V1 ), 16 );
   VB = _mm512_add_epi32( VB, VC );
   V6 = mm512_ror_32( _mm512_xor_si512( V6, VB ), 12 );
   V1 = _mm512_add_epi32( _mm512_add_epi32( V1, V6 ),
                         v512_32( CSA ) );
   VC = mm512_ror_32( _mm512_xor_si512( VC, V1 ), 8 );
   VB = _mm512_add_epi32( VB, VC );
   V6 = mm512_ror_32( _mm512_xor_si512( V6, VB ), 7 );

   // G6
   // GS_16WAY( MC, MD, CSC, CSD, V2, V7, V8, VD );
   VD = mm512_ror_32( _mm512_xor_si512( VD, V2 ), 16 );
   V8 = _mm512_add_epi32( V8, VD );
   V7 = mm512_ror_32( _mm512_xor_si512( V7, V8 ), 12 );
   V2 = _mm512_add_epi32( V2, _mm512_add_epi32( V7, MDxorCSC ) );
   VD = mm512_ror_32( _mm512_xor_si512( VD, V2 ), 8 );
   V8 = _mm512_add_epi32( V8, VD );
   V7 = mm512_ror_32( _mm512_xor_si512( V7, V8 ), 7 );

   // G7
   // GS_16WAY( ME, MF, CSE, CSF, V3, V4, V9, VE );
   V9 = _mm512_add_epi32( V9, VE );
   V4 = mm512_ror_32( _mm512_xor_si512( V4, V9 ), 12 );
   V3 = _mm512_add_epi32( V3, V4 );
   VE = mm512_ror_32( _mm512_xor_si512( VE, V3 ), 8 );
   V9 = _mm512_add_epi32( V9, VE );
   V4 = mm512_ror_32( _mm512_xor_si512( V4, V9 ), 7 );

   // Remaining rounds, optimised   
   ROUND256_16WAY_1;
   ROUND256_16WAY_2;
   ROUND256_16WAY_3;
   ROUND256_16WAY_4;
   ROUND256_16WAY_5;
   ROUND256_16WAY_6;
   ROUND256_16WAY_7;
   if ( rounds > 8 )
   {
      ROUND256_16WAY_8;
      ROUND256_16WAY_9;
      ROUND256_16WAY_0;
      ROUND256_16WAY_1;
      ROUND256_16WAY_2;
      ROUND256_16WAY_3;
   }

   // Byte swap final hash
   const __m512i shuf_bswap32 =  mm512_bcast_m128( v128_set64( 
                                 0x0c0d0e0f08090a0b, 0x0405060700010203 ) );
   H[0] = _mm512_shuffle_epi8( mm512_xor3( V8, V0, h[0] ), shuf_bswap32 );
   H[1] = _mm512_shuffle_epi8( mm512_xor3( V9, V1, h[1] ), shuf_bswap32 );
   H[2] = _mm512_shuffle_epi8( mm512_xor3( VA, V2, h[2] ), shuf_bswap32 );
   H[3] = _mm512_shuffle_epi8( mm512_xor3( VB, V3, h[3] ), shuf_bswap32 );
   H[4] = _mm512_shuffle_epi8( mm512_xor3( VC, V4, h[4] ), shuf_bswap32 );
   H[5] = _mm512_shuffle_epi8( mm512_xor3( VD, V5, h[5] ), shuf_bswap32 );
   H[6] = _mm512_shuffle_epi8( mm512_xor3( VE, V6, h[6] ), shuf_bswap32 );
   H[7] = _mm512_shuffle_epi8( mm512_xor3( VF, V7, h[7] ), shuf_bswap32 );
}

#endif

// Blake-256 4 way

static const uint32_t salt_zero_4x32_small[4] = { 0, 0, 0, 0 };

static void
blake32_4x32_init( blake_4x32_small_context *ctx, const uint32_t *iv,
                   const uint32_t *salt, int rounds )
{
   casti_v128( ctx->H, 0 ) = v128_64( 0x6A09E6676A09E667 );
   casti_v128( ctx->H, 1 ) = v128_64( 0xBB67AE85BB67AE85 );
   casti_v128( ctx->H, 2 ) = v128_64( 0x3C6EF3723C6EF372 );
   casti_v128( ctx->H, 3 ) = v128_64( 0xA54FF53AA54FF53A );
   casti_v128( ctx->H, 4 ) = v128_64( 0x510E527F510E527F );
   casti_v128( ctx->H, 5 ) = v128_64( 0x9B05688C9B05688C );
   casti_v128( ctx->H, 6 ) = v128_64( 0x1F83D9AB1F83D9AB );
   casti_v128( ctx->H, 7 ) = v128_64( 0x5BE0CD195BE0CD19 );
   ctx->T0 = ctx->T1 = 0;
   ctx->ptr = 0;
   ctx->rounds = rounds;
}

static void
blake32_4x32( blake_4x32_small_context *ctx, const void *data,
              size_t len )
{
   v128_t *buf = (v128_t*)ctx->buf;
   size_t  bptr = ctx->ptr<<2;
   size_t  vptr = ctx->ptr >> 2;
   size_t  blen = len << 2;
   DECL_STATE32_4X32;

   if ( blen < (sizeof ctx->buf) - bptr )
   {
      memcpy( buf + vptr, data, (sizeof ctx->buf) - bptr );
      bptr += blen;
      ctx->ptr = bptr>>2;
      return;
   }

   READ_STATE32_4X32( ctx );
   while ( blen > 0 )
   {
      size_t clen = ( sizeof ctx->buf ) - bptr;

      if ( clen > blen )
         clen = blen;
      memcpy( buf + vptr, data, clen );
      bptr += clen;
      data = (const unsigned char *)data + clen;
      blen -= clen;
      if ( bptr == ( sizeof ctx->buf ) )
      {
         if ( ( T0 = T0 + 512 ) < 512 )
            T1 = T1 + 1;
         COMPRESS32_4X32( ctx->rounds );
	 bptr = 0;
      }
   }
   WRITE_STATE32_4X32( ctx );
   ctx->ptr = bptr>>2;
}

static void
blake32_4x32_close( blake_4x32_small_context *ctx, unsigned ub, unsigned n,
               void *dst, size_t out_size_w32 )
{
   v128_t buf[16] __attribute__ ((aligned (64)));
   size_t   ptr     = ctx->ptr;
   size_t   vptr    = ctx->ptr>>2;
   unsigned bit_len = ( (unsigned)ptr << 3 );
   uint32_t tl      = ctx->T0 + bit_len;
   uint32_t th      = ctx->T1;

   if ( ptr == 0 )
   {
      ctx->T0 = 0xFFFFFE00UL;
      ctx->T1 = 0xFFFFFFFFUL;
   }
   else if ( ctx->T0 == 0 )
   {
      ctx->T0 = 0xFFFFFE00UL + bit_len;
      ctx->T1 = ctx->T1 - 1;
   } 
   else
      ctx->T0 -= 512 - bit_len;

   buf[vptr] = v128_64( 0x0000008000000080 );

   if ( vptr < 12 )
   {
      v128_memset_zero( buf + vptr + 1, 13 - vptr  );
      buf[ 13 ] = v128_or( buf[ 13 ], v128_64( 0x0100000001000000ULL ) );
      buf[ 14 ] = v128_32( bswap_32( th ) );
      buf[ 15 ] = v128_32( bswap_32( tl ) );
      blake32_4x32( ctx, buf + vptr, 64 - ptr );
   }
   else
   {
      v128_memset_zero( buf + vptr + 1, (60-ptr) >> 2 );
      blake32_4x32( ctx, buf + vptr, 64 - ptr );
      ctx->T0 = 0xFFFFFE00UL;
      ctx->T1 = 0xFFFFFFFFUL;
      v128_memset_zero( buf, 56>>2 );
      buf[ 13 ] = v128_or( buf[ 13 ], v128_64( 0x0100000001000000ULL ) );
      buf[ 14 ] = v128_32( bswap_32( th ) );
      buf[ 15 ] = v128_32( bswap_32( tl ) );
      blake32_4x32( ctx, buf, 64 );
   }

   v128_block_bswap32_256( (v128_t*)dst, (v128_t*)ctx->H );
}

#if defined (__AVX2__)

// Blake-256 8 way

static const uint32_t salt_zero_8way_small[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };

static void
blake32_8way_init( blake_8way_small_context *sc, const uint32_t *iv,
                   const uint32_t *salt, int rounds )
{
   casti_m256i( sc->H, 0 ) = v256_64( 0x6A09E6676A09E667 );
   casti_m256i( sc->H, 1 ) = v256_64( 0xBB67AE85BB67AE85 );
   casti_m256i( sc->H, 2 ) = v256_64( 0x3C6EF3723C6EF372 );
   casti_m256i( sc->H, 3 ) = v256_64( 0xA54FF53AA54FF53A );
   casti_m256i( sc->H, 4 ) = v256_64( 0x510E527F510E527F );
   casti_m256i( sc->H, 5 ) = v256_64( 0x9B05688C9B05688C );
   casti_m256i( sc->H, 6 ) = v256_64( 0x1F83D9AB1F83D9AB );
   casti_m256i( sc->H, 7 ) = v256_64( 0x5BE0CD195BE0CD19 );
   sc->T0 = sc->T1 = 0;
   sc->ptr = 0;
   sc->rounds = rounds;
}

static void
blake32_8way( blake_8way_small_context *sc, const void *data, size_t len )
{
   __m256i *vdata = (__m256i*)data;
   __m256i *buf;
   size_t ptr;
   const int buf_size = 64;   // number of elements, sizeof/4
   DECL_STATE32_8WAY
   buf = sc->buf;
   ptr = sc->ptr;
   if ( len < buf_size - ptr )
   {
        memcpy_256( buf + (ptr>>2), vdata, len>>2 );
        ptr += len;
        sc->ptr = ptr;
        return;
   }

   READ_STATE32_8WAY(sc);
   while ( len > 0 )
   {
      size_t clen;

      clen = buf_size - ptr;
      if (clen > len)
           clen = len;
      memcpy_256( buf + (ptr>>2), vdata, clen>>2 );
      ptr += clen;
      vdata += (clen>>2);
      len -= clen;
      if ( ptr == buf_size )
      {
          if ( ( T0 = T0 + 512 ) < 512 )
                T1 = T1 + 1;
          COMPRESS32_8WAY( sc->rounds );
          ptr = 0;
      }
   }
   WRITE_STATE32_8WAY(sc);
   sc->ptr = ptr;
}

static void
blake32_8way_close( blake_8way_small_context *sc, unsigned ub, unsigned n,
                    void *dst, size_t out_size_w32 )
{
   __m256i buf[16];
   size_t ptr;
   unsigned bit_len;
   uint32_t th, tl;

   ptr = sc->ptr;
   bit_len = ((unsigned)ptr << 3);
   buf[ptr>>2] = v256_64( 0x0000008000000080ULL );
   tl = sc->T0 + bit_len;
   th = sc->T1;

   if ( ptr == 0 )
   {
        sc->T0 = 0xFFFFFE00UL;
        sc->T1 = 0xFFFFFFFFUL;
   }
   else if ( sc->T0 == 0 )
   {
        sc->T0 = 0xFFFFFE00UL + bit_len;
        sc->T1 = sc->T1 - 1;
   }
   else
        sc->T0 -= 512 - bit_len;

   if ( ptr <= 52 )
   {
       memset_zero_256( buf + (ptr>>2) + 1, (52 - ptr) >> 2 );
       if ( out_size_w32 == 8 )
           buf[52>>2] = _mm256_or_si256( buf[52>>2],
                                v256_64( 0x0100000001000000ULL ) );
       *(buf+(56>>2)) = v256_32( bswap_32( th ) );
       *(buf+(60>>2)) = v256_32( bswap_32( tl ) );
       blake32_8way( sc, buf + (ptr>>2), 64 - ptr );
   }
   else
   {
       memset_zero_256( buf + (ptr>>2) + 1, (60-ptr) >> 2 );
       blake32_8way( sc, buf + (ptr>>2), 64 - ptr );
       sc->T0 = 0xFFFFFE00UL;
       sc->T1 = 0xFFFFFFFFUL;
       memset_zero_256( buf, 56>>2 );
       if ( out_size_w32 == 8 )
           buf[52>>2] = v256_64( 0x0100000001000000ULL );
       *(buf+(56>>2)) = v256_32( bswap_32( th ) );
       *(buf+(60>>2)) = v256_32( bswap_32( tl ) );
       blake32_8way( sc, buf, 64 );
   }
   mm256_block_bswap32_256( (__m256i*)dst, (__m256i*)sc->H );
}

static void
blake32_8way_le( blake_8way_small_context *sc, const void *data, size_t len )
{
   __m256i *vdata = (__m256i*)data;
   __m256i *buf;
   size_t ptr;
   const int buf_size = 64;   // number of elements, sizeof/4
   DECL_STATE32_8WAY
   buf = sc->buf;
   ptr = sc->ptr;
   if ( len < buf_size - ptr )
   {
        memcpy_256( buf + (ptr>>2), vdata, len>>2 );
        ptr += len;
        sc->ptr = ptr;
        return;
   }

   READ_STATE32_8WAY(sc);
   while ( len > 0 )
   {
      size_t clen;

      clen = buf_size - ptr;
      if (clen > len)
           clen = len;
      memcpy_256( buf + (ptr>>2), vdata, clen>>2 );
      ptr += clen;
      vdata += (clen>>2);
      len -= clen;
      if ( ptr == buf_size )
      {
          if ( ( T0 = T0 + 512 ) < 512 )
                T1 = T1 + 1;
          COMPRESS32_8WAY_LE( sc->rounds );
          ptr = 0;
      }
   }
   WRITE_STATE32_8WAY(sc);
   sc->ptr = ptr;
}

static void
blake32_8way_close_le( blake_8way_small_context *sc, unsigned ub, unsigned n,
                       void *dst, size_t out_size_w32 )
{
   __m256i buf[16];
   size_t ptr;
   unsigned bit_len;
   uint32_t th, tl;

   ptr = sc->ptr;
   bit_len = ((unsigned)ptr << 3);
   buf[ptr>>2] = v256_32( 0x80000000 );
   tl = sc->T0 + bit_len;
   th = sc->T1;

   if ( ptr == 0 )
   {
        sc->T0 = 0xFFFFFE00UL;
        sc->T1 = 0xFFFFFFFFUL;
   }
   else if ( sc->T0 == 0 )
   {
        sc->T0 = 0xFFFFFE00UL + bit_len;
        sc->T1 = sc->T1 - 1;
   }
   else
        sc->T0 -= 512 - bit_len;

   if ( ptr <= 52 )
   {
       memset_zero_256( buf + (ptr>>2) + 1, (52 - ptr) >> 2 );
       if ( out_size_w32 == 8 )
           buf[52>>2] = _mm256_or_si256( buf[52>>2], v256_32( 1 ) );
       *(buf+(56>>2)) = v256_32( th );
       *(buf+(60>>2)) = v256_32( tl );
       blake32_8way_le( sc, buf + (ptr>>2), 64 - ptr );
   }
   else
   {
       memset_zero_256( buf + (ptr>>2) + 1, (60-ptr) >> 2 );
       blake32_8way_le( sc, buf + (ptr>>2), 64 - ptr );
       sc->T0 = 0xFFFFFE00UL;
       sc->T1 = 0xFFFFFFFFUL;
       memset_zero_256( buf, 56>>2 );
       if ( out_size_w32 == 8 )
           buf[52>>2] = v256_32( 1 );
       *(buf+(56>>2)) = v256_32( th );
       *(buf+(60>>2)) = v256_32( tl );
       blake32_8way_le( sc, buf, 64 );
   }
   mm256_block_bswap32_256( (__m256i*)dst, (__m256i*)sc->H );
}

#endif


#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

//Blake-256 16 way AVX512

static void
blake32_16way_init( blake_16way_small_context *sc, const uint32_t *iv,
                   const uint32_t *salt, int rounds )
{
   casti_m512i( sc->H, 0 ) = v512_64( 0x6A09E6676A09E667 );
   casti_m512i( sc->H, 1 ) = v512_64( 0xBB67AE85BB67AE85 );
   casti_m512i( sc->H, 2 ) = v512_64( 0x3C6EF3723C6EF372 );
   casti_m512i( sc->H, 3 ) = v512_64( 0xA54FF53AA54FF53A );
   casti_m512i( sc->H, 4 ) = v512_64( 0x510E527F510E527F );
   casti_m512i( sc->H, 5 ) = v512_64( 0x9B05688C9B05688C );
   casti_m512i( sc->H, 6 ) = v512_64( 0x1F83D9AB1F83D9AB );
   casti_m512i( sc->H, 7 ) = v512_64( 0x5BE0CD195BE0CD19 );
   sc->T0 = sc->T1 = 0;
   sc->ptr = 0;
   sc->rounds = rounds;
}

static void
blake32_16way( blake_16way_small_context *sc, const void *data, size_t len )
{
   __m512i *vdata = (__m512i*)data;
   __m512i *buf;
   size_t ptr;
   const int buf_size = 64;   // number of elements, sizeof/4
   DECL_STATE32_16WAY
   buf = sc->buf;
   ptr = sc->ptr;
   if ( len < buf_size - ptr )
   {
        memcpy_512( buf + (ptr>>2), vdata, len>>2 );
        ptr += len;
        sc->ptr = ptr;
        return;
   }
   READ_STATE32_16WAY(sc);
   while ( len > 0 )
   {
      size_t clen;

      clen = buf_size - ptr;
      if (clen > len)
           clen = len;
      memcpy_512( buf + (ptr>>2), vdata, clen>>2 );
      ptr += clen;
      vdata += (clen>>2);
      len -= clen;
      if ( ptr == buf_size )
      {
          if ( ( T0 = T0 + 512 ) < 512 )
                T1 = T1 + 1;
          COMPRESS32_16WAY( sc->rounds );
          ptr = 0;
      }
   }
   WRITE_STATE32_16WAY(sc);
   sc->ptr = ptr;
}
static void
blake32_16way_close( blake_16way_small_context *sc, unsigned ub, unsigned n,
                    void *dst, size_t out_size_w32 )
{
   __m512i buf[16];
   size_t ptr;
   unsigned bit_len;
   uint32_t th, tl;

   ptr = sc->ptr;
   bit_len = ((unsigned)ptr << 3);
   buf[ptr>>2] = v512_64( 0x0000008000000080ULL );
   tl = sc->T0 + bit_len;
   th = sc->T1;

   if ( ptr == 0 )
   {
        sc->T0 = 0xFFFFFE00UL;
        sc->T1 = 0xFFFFFFFFUL;
   }
   else if ( sc->T0 == 0 )
   {
        sc->T0 = 0xFFFFFE00UL + bit_len;
        sc->T1 = sc->T1 - 1;
   }
   else
        sc->T0 -= 512 - bit_len;

   if ( ptr <= 52 )
   {
       memset_zero_512( buf + (ptr>>2) + 1, (52 - ptr) >> 2 );
       if ( out_size_w32 == 8 )
           buf[52>>2] = _mm512_or_si512( buf[52>>2],
                                v512_64( 0x0100000001000000ULL ) );
       buf[56>>2] = v512_32( bswap_32( th ) );
       buf[60>>2] = v512_32( bswap_32( tl ) );
       blake32_16way( sc, buf + (ptr>>2), 64 - ptr );
   }
   else
   {
       memset_zero_512( buf + (ptr>>2) + 1, (60-ptr) >> 2 );
       blake32_16way( sc, buf + (ptr>>2), 64 - ptr );
       sc->T0 = 0xFFFFFE00UL;
       sc->T1 = 0xFFFFFFFFUL;
       memset_zero_512( buf, 56>>2 );
       if ( out_size_w32 == 8 )
          buf[52>>2] = v512_64( 0x0100000001000000ULL );
       buf[56>>2] = v512_32( bswap_32( th ) );
       buf[60>>2] = v512_32( bswap_32( tl ) );
       blake32_16way( sc, buf, 64 );
   }
   mm512_block_bswap32_256( (__m512i*)dst, (__m512i*)sc->H );
}

static void
blake32_16way_le( blake_16way_small_context *sc, const void *data, size_t len )
{
   __m512i *vdata = (__m512i*)data;
   __m512i *buf;
   size_t ptr;
   const int buf_size = 64;   // number of elements, sizeof/4
   DECL_STATE32_16WAY
   buf = sc->buf;
   ptr = sc->ptr;

   // only if calling update with 80
   if ( len < buf_size - ptr )
   {
        memcpy_512( buf + (ptr>>2), vdata, len>>2 );
        ptr += len;
        sc->ptr = ptr;
        return;
   }
   READ_STATE32_16WAY(sc);
   while ( len > 0 )
   {
      size_t clen;

      clen = buf_size - ptr;
      if (clen > len)
           clen = len;
      memcpy_512( buf + (ptr>>2), vdata, clen>>2 );
      ptr += clen;
      vdata += (clen>>2);
      len -= clen;
      if ( ptr == buf_size )
      {
          if ( ( T0 = T0 + 512 ) < 512 )
                T1 = T1 + 1;
          COMPRESS32_16WAY_LE( sc->rounds );
          ptr = 0;
      }
   }
   WRITE_STATE32_16WAY(sc);
   sc->ptr = ptr;
}

static void
blake32_16way_close_le( blake_16way_small_context *sc, unsigned ub, unsigned n,
                    void *dst, size_t out_size_w32 )
{
   __m512i buf[16];
   size_t ptr;
   unsigned bit_len;
   uint32_t th, tl;

   ptr = sc->ptr;
   bit_len = ((unsigned)ptr << 3);
   buf[ptr>>2] = v512_32( 0x80000000 );
   tl = sc->T0 + bit_len;
   th = sc->T1;

   if ( ptr == 0 )
   {
        sc->T0 = 0xFFFFFE00UL;
        sc->T1 = 0xFFFFFFFFUL;
   }
   else if ( sc->T0 == 0 )
   {
        sc->T0 = 0xFFFFFE00UL + bit_len;
        sc->T1 = sc->T1 - 1;
   }
   else
        sc->T0 -= 512 - bit_len;

   if ( ptr <= 52 )
   {
       memset_zero_512( buf + (ptr>>2) + 1, (52 - ptr) >> 2 );
       buf[52>>2] = _mm512_or_si512( buf[52>>2], v512_32( 1 ) );
       buf[56>>2] = v512_32( th );
       buf[60>>2] = v512_32( tl );
       blake32_16way_le( sc, buf + (ptr>>2), 64 - ptr );
   }
   else
   {
       memset_zero_512( buf + (ptr>>2) + 1, (60-ptr) >> 2 );
       blake32_16way_le( sc, buf + (ptr>>2), 64 - ptr );
       sc->T0 = 0xFFFFFE00UL;
       sc->T1 = 0xFFFFFFFFUL;
       memset_zero_512( buf, 56>>2 );
       buf[52>>2] = v512_32( 1 );
       buf[56>>2] = v512_32( th );
       buf[60>>2] = v512_32( tl );
       blake32_16way_le( sc, buf, 64 );
   }
   mm512_block_bswap32_256( (__m512i*)dst, (__m512i*)sc->H );
}

void
blake256_16way_init(void *cc)
{
   blake32_16way_init( cc, IV256, salt_zero_8way_small, 14 );
}

void
blake256_16way_update(void *cc, const void *data, size_t len)
{
        blake32_16way(cc, data, len);
}

void
blake256_16way_close(void *cc, void *dst)
{
        blake32_16way_close(cc, 0, 0, dst, 8);
}

void
blake256_16way_update_le(void *cc, const void *data, size_t len)
{
   blake32_16way_le(cc, data, len);
}

void
blake256_16way_close_le(void *cc, void *dst)
{
    blake32_16way_close_le(cc, 0, 0, dst, 8);
}

void blake256r14_16way_init(void *cc)
{
   blake32_16way_init( cc, IV256, salt_zero_8way_small, 14 );
}

void
blake256r14_16way_update(void *cc, const void *data, size_t len)
{
   blake32_16way(cc, data, len);
}

void
blake256r14_16way_close(void *cc, void *dst)
{
   blake32_16way_close(cc, 0, 0, dst, 8);
}

void blake256r8_16way_init(void *cc)
{
   blake32_16way_init( cc, IV256, salt_zero_8way_small, 8 );
}

void
blake256r8_16way_update(void *cc, const void *data, size_t len)
{
   blake32_16way(cc, data, len);
}

void
blake256r8_16way_close(void *cc, void *dst)
{
   blake32_16way_close(cc, 0, 0, dst, 8);
}

#endif // AVX512

// Blake-256 4 way

// default 14 rounds, backward copatibility
void
blake256_4x32_init(void *ctx)
{
   blake32_4x32_init( ctx, IV256, salt_zero_4x32_small, 14 );
}

void
blake256_4x32_update(void *ctx, const void *data, size_t len)
{
	blake32_4x32(ctx, data, len);
}

void
blake256_4x32_close(void *ctx, void *dst)
{
        blake32_4x32_close(ctx, 0, 0, dst, 8);
}

#if defined(__AVX2__)

// Blake-256 8 way

void
blake256_8way_init(void *cc)
{
   blake32_8way_init( cc, IV256, salt_zero_8way_small, 14 );
}

void
blake256_8way_update(void *cc, const void *data, size_t len)
{
        blake32_8way(cc, data, len);
}

void
blake256_8way_close(void *cc, void *dst)
{
        blake32_8way_close(cc, 0, 0, dst, 8);
}

void
blake256_8way_update_le(void *cc, const void *data, size_t len)
{
        blake32_8way_le(cc, data, len);
}

void
blake256_8way_close_le(void *cc, void *dst)
{
        blake32_8way_close_le(cc, 0, 0, dst, 8);
}

#endif

// 14 rounds Blake, Decred
void blake256r14_4x32_init(void *cc)
{
   blake32_4x32_init( cc, IV256, salt_zero_4x32_small, 14 );
}

void
blake256r14_4x32_update(void *cc, const void *data, size_t len)
{
   blake32_4x32(cc, data, len);
}

void
blake256r14_4x32_close(void *cc, void *dst)
{
   blake32_4x32_close(cc, 0, 0, dst, 8);
}

#if defined(__AVX2__)

void blake256r14_8way_init(void *cc)
{
   blake32_8way_init( cc, IV256, salt_zero_8way_small, 14 );
}

void
blake256r14_8way_update(void *cc, const void *data, size_t len)
{
   blake32_8way(cc, data, len);
}

void
blake256r14_8way_close(void *cc, void *dst)
{
   blake32_8way_close(cc, 0, 0, dst, 8);
}

#endif

// 8 rounds Blakecoin, Vanilla
void blake256r8_4x32_init(void *cc)
{
   blake32_4x32_init( cc, IV256, salt_zero_4x32_small, 8 );
}

void
blake256r8_4x32_update(void *cc, const void *data, size_t len)
{
   blake32_4x32(cc, data, len);
}

void
blake256r8_4x32_close(void *cc, void *dst)
{
   blake32_4x32_close(cc, 0, 0, dst, 8);
}

#if defined (__AVX2__)

void blake256r8_8way_init(void *cc)
{
   blake32_8way_init( cc, IV256, salt_zero_8way_small, 8 );
}

void
blake256r8_8way_update(void *cc, const void *data, size_t len)
{
   blake32_8way(cc, data, len);
}

void
blake256r8_8way_close(void *cc, void *dst)
{
   blake32_8way_close(cc, 0, 0, dst, 8);
}

#endif
