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

#if SPH_SMALL_FOOTPRINT && !defined SPH_SMALL_FOOTPRINT_BLAKE
#define SPH_SMALL_FOOTPRINT_BLAKE   1
#endif

#if SPH_64 && (SPH_SMALL_FOOTPRINT_BLAKE || !SPH_64_TRUE)
#define SPH_COMPACT_BLAKE_64   1
#endif

#ifdef _MSC_VER
#pragma warning (disable: 4146)
#endif


// Blake-512

static const sph_u64 IV512[8] = {
	SPH_C64(0x6A09E667F3BCC908), SPH_C64(0xBB67AE8584CAA73B),
	SPH_C64(0x3C6EF372FE94F82B), SPH_C64(0xA54FF53A5F1D36F1),
	SPH_C64(0x510E527FADE682D1), SPH_C64(0x9B05688C2B3E6C1F),
	SPH_C64(0x1F83D9ABFB41BD6B), SPH_C64(0x5BE0CD19137E2179)
};


#if SPH_COMPACT_BLAKE_32 || SPH_COMPACT_BLAKE_64

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

// Blake-512 4 way

#define CBx(r, i)   CBx_(Z ## r ## i)
#define CBx_(n)     CBx__(n)
#define CBx__(n)    CB ## n

#define CB0   SPH_C64(0x243F6A8885A308D3)
#define CB1   SPH_C64(0x13198A2E03707344)
#define CB2   SPH_C64(0xA4093822299F31D0)
#define CB3   SPH_C64(0x082EFA98EC4E6C89)
#define CB4   SPH_C64(0x452821E638D01377)
#define CB5   SPH_C64(0xBE5466CF34E90C6C)
#define CB6   SPH_C64(0xC0AC29B7C97C50DD)
#define CB7   SPH_C64(0x3F84D5B5B5470917)
#define CB8   SPH_C64(0x9216D5D98979FB1B)
#define CB9   SPH_C64(0xD1310BA698DFB5AC)
#define CBA   SPH_C64(0x2FFD72DBD01ADFB7)
#define CBB   SPH_C64(0xB8E1AFED6A267E96)
#define CBC   SPH_C64(0xBA7C9045F12C7F99)
#define CBD   SPH_C64(0x24A19947B3916CF7)
#define CBE   SPH_C64(0x0801F2E2858EFC16)
#define CBF   SPH_C64(0x636920D871574E69)

#if SPH_COMPACT_BLAKE_64
// not used
static const sph_u64 CB[16] = {
	SPH_C64(0x243F6A8885A308D3), SPH_C64(0x13198A2E03707344),
	SPH_C64(0xA4093822299F31D0), SPH_C64(0x082EFA98EC4E6C89),
	SPH_C64(0x452821E638D01377), SPH_C64(0xBE5466CF34E90C6C),
	SPH_C64(0xC0AC29B7C97C50DD), SPH_C64(0x3F84D5B5B5470917),
	SPH_C64(0x9216D5D98979FB1B), SPH_C64(0xD1310BA698DFB5AC),
	SPH_C64(0x2FFD72DBD01ADFB7), SPH_C64(0xB8E1AFED6A267E96),
	SPH_C64(0xBA7C9045F12C7F99), SPH_C64(0x24A19947B3916CF7),
	SPH_C64(0x0801F2E2858EFC16), SPH_C64(0x636920D871574E69)
};

#endif


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

#if SPH_COMPACT_BLAKE_64
// not used
#define ROUND_B_4WAY(r)   do { \
	GB_4WAY(M[sigma[r][0x0]], M[sigma[r][0x1]], \
		CB[sigma[r][0x0]], CB[sigma[r][0x1]], V0, V4, V8, VC); \
	GB_4WAY(M[sigma[r][0x2]], M[sigma[r][0x3]], \
		CB[sigma[r][0x2]], CB[sigma[r][0x3]], V1, V5, V9, VD); \
	GB_4WAY(M[sigma[r][0x4]], M[sigma[r][0x5]], \
		CB[sigma[r][0x4]], CB[sigma[r][0x5]], V2, V6, VA, VE); \
	GB_4WAY(M[sigma[r][0x6]], M[sigma[r][0x7]], \
		CB[sigma[r][0x6]], CB[sigma[r][0x7]], V3, V7, VB, VF); \
	GB_4WAY(M[sigma[r][0x8]], M[sigma[r][0x9]], \
		CB[sigma[r][0x8]], CB[sigma[r][0x9]], V0, V5, VA, VF); \
	GB_4WAY(M[sigma[r][0xA]], M[sigma[r][0xB]], \
		CB[sigma[r][0xA]], CB[sigma[r][0xB]], V1, V6, VB, VC); \
	GB_4WAY(M[sigma[r][0xC]], M[sigma[r][0xD]], \
		CB[sigma[r][0xC]], CB[sigma[r][0xD]], V2, V7, V8, VD); \
	GB_4WAY(M[sigma[r][0xE]], M[sigma[r][0xF]], \
		CB[sigma[r][0xE]], CB[sigma[r][0xF]], V3, V4, V9, VE); \
} while (0)

#else
//current_impl
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

#endif


// Blake-512 4 way

#define DECL_STATE64_4WAY \
	__m256i H0, H1, H2, H3, H4, H5, H6, H7; \
        __m256i S0, S1, S2, S3; \
	sph_u64 T0, T1;

#define READ_STATE64_4WAY(state)   do { \
		H0 = (state)->H[0]; \
		H1 = (state)->H[1]; \
		H2 = (state)->H[2]; \
		H3 = (state)->H[3]; \
		H4 = (state)->H[4]; \
		H5 = (state)->H[5]; \
		H6 = (state)->H[6]; \
		H7 = (state)->H[7]; \
		S0 = (state)->S[0]; \
		S1 = (state)->S[1]; \
		S2 = (state)->S[2]; \
		S3 = (state)->S[3]; \
		T0 = (state)->T0; \
		T1 = (state)->T1; \
	} while (0)

#define WRITE_STATE64_4WAY(state)   do { \
		(state)->H[0] = H0; \
		(state)->H[1] = H1; \
		(state)->H[2] = H2; \
		(state)->H[3] = H3; \
		(state)->H[4] = H4; \
		(state)->H[5] = H5; \
		(state)->H[6] = H6; \
		(state)->H[7] = H7; \
		(state)->S[0] = S0; \
		(state)->S[1] = S1; \
		(state)->S[2] = S2; \
		(state)->S[3] = S3; \
		(state)->T0 = T0; \
		(state)->T1 = T1; \
	} while (0)

#if SPH_COMPACT_BLAKE_64

// not used
#define COMPRESS64_4WAY   do { \
	__m256i M[16]; \
	__m256i V0, V1, V2, V3, V4, V5, V6, V7; \
	__m256i V8, V9, VA, VB, VC, VD, VE, VF; \
	unsigned r; \
	V0 = H0; \
	V1 = H1; \
	V2 = H2; \
	V3 = H3; \
	V4 = H4; \
	V5 = H5; \
	V6 = H6; \
	V7 = H7; \
   V8 = _mm256_xor_si256( S0, _mm256_set_epi64x( CB0, CB0, CB0, CB0 ) ); \
   V9 = _mm256_xor_si256( S1, _mm256_set_epi64x( CB1, CB1, CB1, CB1 ) ); \
   VA = _mm256_xor_si256( S2, _mm256_set_epi64x( CB2, CB2, CB2, CB2 ) ); \
   VB = _mm256_xor_si256( S3, _mm256_set_epi64x( CB3, CB3, CB3, CB3 ) ); \
   VC = _mm256_xor_si256( _mm256_set_epi64x( T0, T0, T0, T0 ), \
                          _mm256_set_epi64x( CB4, CB4, CB4, CB4 ) ); \
   VD = _mm256_xor_si256( _mm256_set_epi64x( T0, T0, T0, T0 ), \
                          _mm256_set_epi64x( CB5, CB5, CB5, CB5 ) ); \
   VE = _mm256_xor_si256( _mm256_set_epi64x( T1, T1, T1, T1 ), \
                          _mm256_set_epi64x( CB6, CB6, CB6, CB6 ) ); \
   VF = _mm256_xor_si256( _mm256_set_epi64x( T1, T1, T1, T1 ), \
                          _mm256_set_epi64x( CB7, CB7, CB7, CB7 ) ); \
	M[0x0] = mm256_bswap_64( *(buf+0) ); \
	M[0x1] = mm256_bswap_64( *(buf+1) ); \
	M[0x2] = mm256_bswap_64( *(buf+2) ); \
	M[0x3] = mm256_bswap_64( *(buf+3) ); \
	M[0x4] = mm256_bswap_64( *(buf+4) ); \
	M[0x5] = mm256_bswap_64( *(buf+5) ); \
	M[0x6] = mm256_bswap_64( *(buf+6) ); \
	M[0x7] = mm256_bswap_64( *(buf+7) ); \
	M[0x8] = mm256_bswap_64( *(buf+8) ); \
	M[0x9] = mm256_bswap_64( *(buf+9) ); \
	M[0xA] = mm256_bswap_64( *(buf+10) ); \
	M[0xB] = mm256_bswap_64( *(buf+11) ); \
	M[0xC] = mm256_bswap_64( *(buf+12) ); \
	M[0xD] = mm256_bswap_64( *(buf+13) ); \
	M[0xE] = mm256_bswap_64( *(buf+14) ); \
	M[0xF] = mm256_bswap_64( *(buf+15) ); \
	for (r = 0; r < 16; r ++) \
		ROUND_B_4WAY(r); \
        H0 = _mm256_xor_si256( _mm256_xor_si256( \
                    _mm256_xor_si256( S0, V0 ), V8 ), H0 ); \
        H1 = _mm256_xor_si256( _mm256_xor_si256( \
                    _mm256_xor_si256( S1, V1 ), V9 ), H1 ); \
        H2 = _mm256_xor_si256( _mm256_xor_si256( \
                    _mm256_xor_si256( S2, V2 ), VA ), H2 ); \
        H3 = _mm256_xor_si256( _mm256_xor_si256( \
                    _mm256_xor_si256( S3, V3 ), VB ), H3 ); \
        H4 = _mm256_xor_si256( _mm256_xor_si256( \
                    _mm256_xor_si256( S0, V4 ), VC ), H4 ); \
        H5 = _mm256_xor_si256( _mm256_xor_si256( \
                    _mm256_xor_si256( S1, V5 ), VD ), H5 ); \
        H6 = _mm256_xor_si256( _mm256_xor_si256( \
                    _mm256_xor_si256( S2, V6 ), VE ), H6 ); \
        H7 = _mm256_xor_si256( _mm256_xor_si256( \
                    _mm256_xor_si256( S3, V7 ), VF ), H7 ); \
	} while (0)

#else

//current impl

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
  V8 = _mm256_xor_si256( S0, m256_const1_64( CB0 ) );  \
  V9 = _mm256_xor_si256( S1, m256_const1_64( CB1 ) );  \
  VA = _mm256_xor_si256( S2, m256_const1_64( CB2 ) );  \
  VB = _mm256_xor_si256( S3, m256_const1_64( CB3 ) );  \
  VC = _mm256_xor_si256( _mm256_set1_epi64x( T0 ), \
                         m256_const1_64( CB4 ) );  \
  VD = _mm256_xor_si256( _mm256_set1_epi64x( T0 ), \
                         m256_const1_64( CB5 ) );  \
  VE = _mm256_xor_si256( _mm256_set1_epi64x( T1 ), \
                         m256_const1_64( CB6 ) );  \
  VF = _mm256_xor_si256( _mm256_set1_epi64x( T1 ), \
                         m256_const1_64( CB7 ) );  \
  shuf_bswap64 = m256_const_64( 0x08090a0b0c0d0e0f, 0x0001020304050607, \
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
  H0 = mm256_xor4( V8, V0, S0, H0 ); \
  H1 = mm256_xor4( V9, V1, S1, H1 ); \
  H2 = mm256_xor4( VA, V2, S2, H2 ); \
  H3 = mm256_xor4( VB, V3, S3, H3 ); \
  H4 = mm256_xor4( VC, V4, S0, H4 ); \
  H5 = mm256_xor4( VD, V5, S1, H5 ); \
  H6 = mm256_xor4( VE, V6, S2, H6 ); \
  H7 = mm256_xor4( VF, V7, S3, H7 ); \
} while (0)

#endif

static const sph_u64 salt_zero_big[4] = { 0, 0, 0, 0 };

static void
blake64_4way_init( blake_4way_big_context *sc, const sph_u64 *iv,
              const sph_u64 *salt )
{
   __m256i zero = m256_zero;
   casti_m256i( sc->H, 0 ) = m256_const1_64( 0x6A09E667F3BCC908 );
   casti_m256i( sc->H, 1 ) = m256_const1_64( 0xBB67AE8584CAA73B );
   casti_m256i( sc->H, 2 ) = m256_const1_64( 0x3C6EF372FE94F82B );
   casti_m256i( sc->H, 3 ) = m256_const1_64( 0xA54FF53A5F1D36F1 );
   casti_m256i( sc->H, 4 ) = m256_const1_64( 0x510E527FADE682D1 );
   casti_m256i( sc->H, 5 ) = m256_const1_64( 0x9B05688C2B3E6C1F );
   casti_m256i( sc->H, 6 ) = m256_const1_64( 0x1F83D9ABFB41BD6B );
   casti_m256i( sc->H, 7 ) = m256_const1_64( 0x5BE0CD19137E2179 );

   casti_m256i( sc->S, 0 ) = zero;
   casti_m256i( sc->S, 1 ) = zero;
   casti_m256i( sc->S, 2 ) = zero;
   casti_m256i( sc->S, 3 ) = zero;

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

   READ_STATE64_4WAY(sc);
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
	if (ptr == buf_size )
        {
		if ((T0 = SPH_T64(T0 + 1024)) < 1024)
			T1 = SPH_T64(T1 + 1);
		COMPRESS64_4WAY;
		ptr = 0;
	}
   }
   WRITE_STATE64_4WAY(sc);
   sc->ptr = ptr;
}

static void
blake64_4way_close( blake_4way_big_context *sc,
	unsigned ub, unsigned n, void *dst, size_t out_size_w64)
{
   __m256i buf[16];
   size_t ptr;
   unsigned bit_len;
   uint64_t z, zz;
   sph_u64 th, tl;

   ptr = sc->ptr;
   bit_len = ((unsigned)ptr << 3);
   z = 0x80 >> n;
   zz = ((ub & -z) | z) & 0xFF;
   buf[ptr>>3] = _mm256_set_epi64x( zz, zz, zz, zz );
   tl = sc->T0 + bit_len;
   th = sc->T1;
   if (ptr == 0 )
   {
	sc->T0 = SPH_C64(0xFFFFFFFFFFFFFC00ULL);
	sc->T1 = SPH_C64(0xFFFFFFFFFFFFFFFFULL);
   }
   else if ( sc->T0 == 0 )
   {
	sc->T0 = SPH_C64(0xFFFFFFFFFFFFFC00ULL) + bit_len;
	sc->T1 = SPH_T64(sc->T1 - 1);
   } 
   else
   {
        sc->T0 -= 1024 - bit_len;
   }
   if ( ptr <= 104 )
   {
       memset_zero_256( buf + (ptr>>3) + 1, (104-ptr) >> 3 );
       if ( out_size_w64 == 8 )
          buf[(104>>3)] = _mm256_or_si256( buf[(104>>3)],
                                 m256_const1_64( 0x0100000000000000ULL ) );
       *(buf+(112>>3)) = _mm256_set1_epi64x( bswap_64( th ) );
       *(buf+(120>>3)) = _mm256_set1_epi64x( bswap_64( tl ) );

       blake64_4way( sc, buf + (ptr>>3), 128 - ptr );
   }
   else
  {
       memset_zero_256( buf + (ptr>>3) + 1, (120 - ptr) >> 3 );

       blake64_4way( sc, buf + (ptr>>3), 128 - ptr );
       sc->T0 = SPH_C64(0xFFFFFFFFFFFFFC00ULL);
       sc->T1 = SPH_C64(0xFFFFFFFFFFFFFFFFULL);
       memset_zero_256( buf, 112>>3 ); 
       if ( out_size_w64 == 8 )
           buf[104>>3] = m256_const1_64( 0x0100000000000000ULL );
       *(buf+(112>>3)) = _mm256_set1_epi64x( bswap_64( th ) );
       *(buf+(120>>3)) = _mm256_set1_epi64x( bswap_64( tl ) );

       blake64_4way( sc, buf, 128 );
   }
   mm256_block_bswap_64( (__m256i*)dst, sc->H );
}

void
blake512_4way_init(void *cc)
{
	blake64_4way_init(cc, IV512, salt_zero_big);
}

void
blake512_4way(void *cc, const void *data, size_t len)
{
	blake64_4way(cc, data, len);
}

void
blake512_4way_close(void *cc, void *dst)
{
	blake512_4way_addbits_and_close(cc, 0, 0, dst);
}

void
blake512_4way_addbits_and_close(void *cc, unsigned ub, unsigned n, void *dst)
{
	blake64_4way_close(cc, ub, n, dst, 8);
}

#ifdef __cplusplus
}
#endif

#endif
