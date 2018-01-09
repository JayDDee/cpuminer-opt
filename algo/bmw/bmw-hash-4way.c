/* $Id: bmw.c 227 2010-06-16 17:28:38Z tp $ */
/*
 * BMW implementation.
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

#include <stddef.h>
#include <string.h>
#include <limits.h>
#include "bmw-hash-4way.h"

#if defined(__AVX2__)

#ifdef __cplusplus
extern "C"{
#endif

//#include "sph_bmw.h"

//#if SPH_SMALL_FOOTPRINT && !defined SPH_SMALL_FOOTPRINT_BMW
#define SPH_SMALL_FOOTPRINT_BMW   1
//#endif

#ifdef _MSC_VER
#pragma warning (disable: 4146)
#endif

//#undef SPH_ROTL64
//#define SPH_ROTL64(x,n)  (((x) << (n)) | ((x) >> (64 - (n))))
//#define SPH_ROTL64(x,n)  mm256_rotl_64(x,n)

static const sph_u32 IV256[] = {
	SPH_C32(0x40414243), SPH_C32(0x44454647),
	SPH_C32(0x48494A4B), SPH_C32(0x4C4D4E4F),
	SPH_C32(0x50515253), SPH_C32(0x54555657),
	SPH_C32(0x58595A5B), SPH_C32(0x5C5D5E5F),
	SPH_C32(0x60616263), SPH_C32(0x64656667),
	SPH_C32(0x68696A6B), SPH_C32(0x6C6D6E6F),
	SPH_C32(0x70717273), SPH_C32(0x74757677),
	SPH_C32(0x78797A7B), SPH_C32(0x7C7D7E7F)
};

#if SPH_64

static const sph_u64 IV512[] = {
	SPH_C64(0x8081828384858687), SPH_C64(0x88898A8B8C8D8E8F),
	SPH_C64(0x9091929394959697), SPH_C64(0x98999A9B9C9D9E9F),
	SPH_C64(0xA0A1A2A3A4A5A6A7), SPH_C64(0xA8A9AAABACADAEAF),
	SPH_C64(0xB0B1B2B3B4B5B6B7), SPH_C64(0xB8B9BABBBCBDBEBF),
	SPH_C64(0xC0C1C2C3C4C5C6C7), SPH_C64(0xC8C9CACBCCCDCECF),
	SPH_C64(0xD0D1D2D3D4D5D6D7), SPH_C64(0xD8D9DADBDCDDDEDF),
	SPH_C64(0xE0E1E2E3E4E5E6E7), SPH_C64(0xE8E9EAEBECEDEEEF),
	SPH_C64(0xF0F1F2F3F4F5F6F7), SPH_C64(0xF8F9FAFBFCFDFEFF)
};

#endif

#define XCAT(x, y)    XCAT_(x, y)
#define XCAT_(x, y)   x ## y

#define LPAR   (

/*
#define ss0(x)    (((x) >> 1) ^ SPH_T32((x) << 3) \
                  ^ SPH_ROTL32(x,  4) ^ SPH_ROTL32(x, 19))
#define ss1(x)    (((x) >> 1) ^ SPH_T32((x) << 2) \
                  ^ SPH_ROTL32(x,  8) ^ SPH_ROTL32(x, 23))
#define ss2(x)    (((x) >> 2) ^ SPH_T32((x) << 1) \
                  ^ SPH_ROTL32(x, 12) ^ SPH_ROTL32(x, 25))
#define ss3(x)    (((x) >> 2) ^ SPH_T32((x) << 2) \
                  ^ SPH_ROTL32(x, 15) ^ SPH_ROTL32(x, 29))
#define ss4(x)    (((x) >> 1) ^ (x))
#define ss5(x)    (((x) >> 2) ^ (x))
#define rs1(x)    SPH_ROTL32(x,  3)
#define rs2(x)    SPH_ROTL32(x,  7)
#define rs3(x)    SPH_ROTL32(x, 13)
#define rs4(x)    SPH_ROTL32(x, 16)
#define rs5(x)    SPH_ROTL32(x, 19)
#define rs6(x)    SPH_ROTL32(x, 23)
#define rs7(x)    SPH_ROTL32(x, 27)

#define Ks(j)   SPH_T32((sph_u32)(j) * SPH_C32(0x05555555))

#define add_elt_s(mf, hf, j0m, j1m, j3m, j4m, j7m, j10m, j11m, j16) \
	(SPH_T32(SPH_ROTL32(mf(j0m), j1m) + SPH_ROTL32(mf(j3m), j4m) \
		- SPH_ROTL32(mf(j10m), j11m) + Ks(j16)) ^ hf(j7m))

#define expand1s_inner(qf, mf, hf, i16, \
		i0, i1, i2, i3, i4, i5, i6, i7, i8, \
		i9, i10, i11, i12, i13, i14, i15, \
		i0m, i1m, i3m, i4m, i7m, i10m, i11m) \
	SPH_T32(ss1(qf(i0)) + ss2(qf(i1)) + ss3(qf(i2)) + ss0(qf(i3)) \
		+ ss1(qf(i4)) + ss2(qf(i5)) + ss3(qf(i6)) + ss0(qf(i7)) \
		+ ss1(qf(i8)) + ss2(qf(i9)) + ss3(qf(i10)) + ss0(qf(i11)) \
		+ ss1(qf(i12)) + ss2(qf(i13)) + ss3(qf(i14)) + ss0(qf(i15)) \
		+ add_elt_s(mf, hf, i0m, i1m, i3m, i4m, i7m, i10m, i11m, i16))

#define expand1s(qf, mf, hf, i16) \
	expand1s_(qf, mf, hf, i16, I16_ ## i16, M16_ ## i16)
#define expand1s_(qf, mf, hf, i16, ix, iy) \
	expand1s_inner LPAR qf, mf, hf, i16, ix, iy)

#define expand2s_inner(qf, mf, hf, i16, \
		i0, i1, i2, i3, i4, i5, i6, i7, i8, \
		i9, i10, i11, i12, i13, i14, i15, \
		i0m, i1m, i3m, i4m, i7m, i10m, i11m) \
	SPH_T32(qf(i0) + rs1(qf(i1)) + qf(i2) + rs2(qf(i3)) \
		+ qf(i4) + rs3(qf(i5)) + qf(i6) + rs4(qf(i7)) \
		+ qf(i8) + rs5(qf(i9)) + qf(i10) + rs6(qf(i11)) \
		+ qf(i12) + rs7(qf(i13)) + ss4(qf(i14)) + ss5(qf(i15)) \
		+ add_elt_s(mf, hf, i0m, i1m, i3m, i4m, i7m, i10m, i11m, i16))

#define expand2s(qf, mf, hf, i16) \
	expand2s_(qf, mf, hf, i16, I16_ ## i16, M16_ ## i16)
#define expand2s_(qf, mf, hf, i16, ix, iy) \
	expand2s_inner LPAR qf, mf, hf, i16, ix, iy)
*/
#if SPH_64

#define sb0(x) \
   _mm256_xor_si256( _mm256_xor_si256( _mm256_srli_epi64( (x), 1), \
                                       _mm256_slli_epi64( (x), 3) ), \
                     _mm256_xor_si256( mm256_rotl_64( (x), 4), \
                                       mm256_rotl_64( (x), 37) ) )

#define sb1(x) \
   _mm256_xor_si256( _mm256_xor_si256( _mm256_srli_epi64( (x), 1), \
                                       _mm256_slli_epi64( (x), 2) ), \
                     _mm256_xor_si256( mm256_rotl_64( (x), 13), \
                                       mm256_rotl_64( (x), 43) ) )

#define sb2(x) \
   _mm256_xor_si256( _mm256_xor_si256( _mm256_srli_epi64( (x), 2), \
                                       _mm256_slli_epi64( (x), 1) ), \
                     _mm256_xor_si256( mm256_rotl_64( (x), 19), \
                                       mm256_rotl_64( (x), 53) ) )

#define sb3(x) \
   _mm256_xor_si256( _mm256_xor_si256( _mm256_srli_epi64( (x), 2), \
                                       _mm256_slli_epi64( (x), 2) ), \
                     _mm256_xor_si256( mm256_rotl_64( (x), 28), \
                                       mm256_rotl_64( (x), 59) ) )

#define sb4(x) \
  _mm256_xor_si256( (x), _mm256_srli_epi64( (x), 1 ) )

#define sb5(x) \
  _mm256_xor_si256( (x), _mm256_srli_epi64( (x), 2 ) )

#define rb1(x)    mm256_rotl_64( x,  5 ) 
#define rb2(x)    mm256_rotl_64( x, 11 ) 
#define rb3(x)    mm256_rotl_64( x, 27 ) 
#define rb4(x)    mm256_rotl_64( x, 32 ) 
#define rb5(x)    mm256_rotl_64( x, 37 ) 
#define rb6(x)    mm256_rotl_64( x, 43 ) 
#define rb7(x)    mm256_rotl_64( x, 53 ) 

#define rol_off( M, j, off ) \
   mm256_rotl_64( M[ ( (j) + (off) ) & 15 ] , \
                   ( ( (j) + (off) ) & 15 ) + 1 )

#define add_elt_b( M, H, j ) \
   _mm256_xor_si256( \
      _mm256_add_epi64( \
            _mm256_sub_epi64( _mm256_add_epi64( rol_off( M, j, 0 ), \
                                                rol_off( M, j, 3 ) ), \
                             rol_off( M, j, 10 ) ), \
            _mm256_set1_epi64x( ( (j) + 16 ) * 0x0555555555555555ULL ) ), \
       H[ ( (j)+7 ) & 15 ] )
          
#define expand1b( qt, M, H, i ) \
   _mm256_add_epi64( \
      _mm256_add_epi64( \
         _mm256_add_epi64( \
             _mm256_add_epi64( \
                _mm256_add_epi64( sb1( qt[ (i)-16 ] ), \
                                  sb2( qt[ (i)-15 ] ) ), \
                _mm256_add_epi64( sb3( qt[ (i)-14 ] ), \
                                  sb0( qt[ (i)-13 ] ) ) ), \
             _mm256_add_epi64( \
                _mm256_add_epi64( sb1( qt[ (i)-12 ] ), \
                                  sb2( qt[ (i)-11 ] ) ), \
                _mm256_add_epi64( sb3( qt[ (i)-10 ] ), \
                                  sb0( qt[ (i)- 9 ] ) ) ) ), \
         _mm256_add_epi64( \
             _mm256_add_epi64( \
                _mm256_add_epi64( sb1( qt[ (i)- 8 ] ), \
                                  sb2( qt[ (i)- 7 ] ) ), \
                _mm256_add_epi64( sb3( qt[ (i)- 6 ] ), \
                                  sb0( qt[ (i)- 5 ] ) ) ), \
             _mm256_add_epi64( \
                _mm256_add_epi64( sb1( qt[ (i)- 4 ] ), \
                                  sb2( qt[ (i)- 3 ] ) ), \
                _mm256_add_epi64( sb3( qt[ (i)- 2 ] ), \
                                  sb0( qt[ (i)- 1 ] ) ) ) ) ), \
      add_elt_b( M, H, (i)-16 ) )

#define expand2b( qt, M, H, i) \
   _mm256_add_epi64( \
      _mm256_add_epi64( \
         _mm256_add_epi64( \
             _mm256_add_epi64( \
                _mm256_add_epi64( qt[ (i)-16 ], rb1( qt[ (i)-15 ] ) ), \
                _mm256_add_epi64( qt[ (i)-14 ], rb2( qt[ (i)-13 ] ) ) ), \
             _mm256_add_epi64( \
                _mm256_add_epi64( qt[ (i)-12 ], rb3( qt[ (i)-11 ] ) ), \
                _mm256_add_epi64( qt[ (i)-10 ], rb4( qt[ (i)- 9 ] ) ) ) ), \
         _mm256_add_epi64( \
             _mm256_add_epi64( \
                _mm256_add_epi64( qt[ (i)- 8 ], rb5( qt[ (i)- 7 ] ) ), \
                _mm256_add_epi64( qt[ (i)- 6 ], rb6( qt[ (i)- 5 ] ) ) ), \
             _mm256_add_epi64( \
                _mm256_add_epi64( qt[ (i)- 4 ], rb7( qt[ (i)- 3 ] ) ), \
                _mm256_add_epi64( sb4( qt[ (i)- 2 ] ), \
                                  sb5( qt[ (i)- 1 ] ) ) ) ) ), \
      add_elt_b( M, H, (i)-16 ) )

#endif

/*
#define MAKE_W( i0, op01, i1, op12, i2, op23, i3, op34, i4) \
        ((M(i0) ^ H(i0)) op01 (M(i1) ^ H(i1)) op12 (M(i2) ^ H(i2)) \
        op23 (M(i3) ^ H(i3)) op34 (M(i4) ^ H(i4)))
*/

/*
#define Ws0    MAKE_W(SPH_T32,  5, -,  7, +, 10, +, 13, +, 14)
#define Ws1    MAKE_W(SPH_T32,  6, -,  8, +, 11, +, 14, -, 15)
#define Ws2    MAKE_W(SPH_T32,  0, +,  7, +,  9, -, 12, +, 15)
#define Ws3    MAKE_W(SPH_T32,  0, -,  1, +,  8, -, 10, +, 13)
#define Ws4    MAKE_W(SPH_T32,  1, +,  2, +,  9, -, 11, -, 14)
#define Ws5    MAKE_W(SPH_T32,  3, -,  2, +, 10, -, 12, +, 15)
#define Ws6    MAKE_W(SPH_T32,  4, -,  0, -,  3, -, 11, +, 13)
#define Ws7    MAKE_W(SPH_T32,  1, -,  4, -,  5, -, 12, -, 14)
#define Ws8    MAKE_W(SPH_T32,  2, -,  5, -,  6, +, 13, -, 15)
#define Ws9    MAKE_W(SPH_T32,  0, -,  3, +,  6, -,  7, +, 14)
#define Ws10   MAKE_W(SPH_T32,  8, -,  1, -,  4, -,  7, +, 15)
#define Ws11   MAKE_W(SPH_T32,  8, -,  0, -,  2, -,  5, +,  9)
#define Ws12   MAKE_W(SPH_T32,  1, +,  3, -,  6, -,  9, +, 10)
#define Ws13   MAKE_W(SPH_T32,  2, +,  4, +,  7, +, 10, +, 11)
#define Ws14   MAKE_W(SPH_T32,  3, -,  5, +,  8, -, 11, -, 12)
#define Ws15   MAKE_W(SPH_T32, 12, -,  4, -,  6, -,  9, +, 13)

#if SPH_SMALL_FOOTPRINT_BMW

#define MAKE_Qas   do { \
		unsigned u; \
		sph_u32 Ws[16]; \
		Ws[ 0] = Ws0; \
		Ws[ 1] = Ws1; \
		Ws[ 2] = Ws2; \
		Ws[ 3] = Ws3; \
		Ws[ 4] = Ws4; \
		Ws[ 5] = Ws5; \
		Ws[ 6] = Ws6; \
		Ws[ 7] = Ws7; \
		Ws[ 8] = Ws8; \
		Ws[ 9] = Ws9; \
		Ws[10] = Ws10; \
		Ws[11] = Ws11; \
		Ws[12] = Ws12; \
		Ws[13] = Ws13; \
		Ws[14] = Ws14; \
		Ws[15] = Ws15; \
		for (u = 0; u < 15; u += 5) { \
			qt[u + 0] = SPH_T32(ss0(Ws[u + 0]) + H(u + 1)); \
			qt[u + 1] = SPH_T32(ss1(Ws[u + 1]) + H(u + 2)); \
			qt[u + 2] = SPH_T32(ss2(Ws[u + 2]) + H(u + 3)); \
			qt[u + 3] = SPH_T32(ss3(Ws[u + 3]) + H(u + 4)); \
			qt[u + 4] = SPH_T32(ss4(Ws[u + 4]) + H(u + 5)); \
		} \
		qt[15] = SPH_T32(ss0(Ws[15]) + H(0)); \
	} while (0)

#define MAKE_Qbs   do { \
		qt[16] = expand1s(Qs, M, H, 16); \
		qt[17] = expand1s(Qs, M, H, 17); \
		qt[18] = expand2s(Qs, M, H, 18); \
		qt[19] = expand2s(Qs, M, H, 19); \
		qt[20] = expand2s(Qs, M, H, 20); \
		qt[21] = expand2s(Qs, M, H, 21); \
		qt[22] = expand2s(Qs, M, H, 22); \
		qt[23] = expand2s(Qs, M, H, 23); \
		qt[24] = expand2s(Qs, M, H, 24); \
		qt[25] = expand2s(Qs, M, H, 25); \
		qt[26] = expand2s(Qs, M, H, 26); \
		qt[27] = expand2s(Qs, M, H, 27); \
		qt[28] = expand2s(Qs, M, H, 28); \
		qt[29] = expand2s(Qs, M, H, 29); \
		qt[30] = expand2s(Qs, M, H, 30); \
		qt[31] = expand2s(Qs, M, H, 31); \
	} while (0)

#else

#define MAKE_Qas   do { \
		qt[ 0] = SPH_T32(ss0(Ws0 ) + H( 1)); \
		qt[ 1] = SPH_T32(ss1(Ws1 ) + H( 2)); \
		qt[ 2] = SPH_T32(ss2(Ws2 ) + H( 3)); \
		qt[ 3] = SPH_T32(ss3(Ws3 ) + H( 4)); \
		qt[ 4] = SPH_T32(ss4(Ws4 ) + H( 5)); \
		qt[ 5] = SPH_T32(ss0(Ws5 ) + H( 6)); \
		qt[ 6] = SPH_T32(ss1(Ws6 ) + H( 7)); \
		qt[ 7] = SPH_T32(ss2(Ws7 ) + H( 8)); \
		qt[ 8] = SPH_T32(ss3(Ws8 ) + H( 9)); \
		qt[ 9] = SPH_T32(ss4(Ws9 ) + H(10)); \
		qt[10] = SPH_T32(ss0(Ws10) + H(11)); \
		qt[11] = SPH_T32(ss1(Ws11) + H(12)); \
		qt[12] = SPH_T32(ss2(Ws12) + H(13)); \
		qt[13] = SPH_T32(ss3(Ws13) + H(14)); \
		qt[14] = SPH_T32(ss4(Ws14) + H(15)); \
		qt[15] = SPH_T32(ss0(Ws15) + H( 0)); \
	} while (0)

#define MAKE_Qbs   do { \
		qt[16] = expand1s(Qs, M, H, 16); \
		qt[17] = expand1s(Qs, M, H, 17); \
		qt[18] = expand2s(Qs, M, H, 18); \
		qt[19] = expand2s(Qs, M, H, 19); \
		qt[20] = expand2s(Qs, M, H, 20); \
		qt[21] = expand2s(Qs, M, H, 21); \
		qt[22] = expand2s(Qs, M, H, 22); \
		qt[23] = expand2s(Qs, M, H, 23); \
		qt[24] = expand2s(Qs, M, H, 24); \
		qt[25] = expand2s(Qs, M, H, 25); \
		qt[26] = expand2s(Qs, M, H, 26); \
		qt[27] = expand2s(Qs, M, H, 27); \
		qt[28] = expand2s(Qs, M, H, 28); \
		qt[29] = expand2s(Qs, M, H, 29); \
		qt[30] = expand2s(Qs, M, H, 30); \
		qt[31] = expand2s(Qs, M, H, 31); \
	} while (0)

#endif

#define MAKE_Qs   do { \
		MAKE_Qas; \
		MAKE_Qbs; \
	} while (0)

#define Qs(j)   (qt[j])
*/
#if SPH_64

#define Wb0 \
   _mm256_add_epi64( \
       _mm256_add_epi64( \
          _mm256_add_epi64( \
             _mm256_sub_epi64( _mm256_xor_si256( M[ 5], H[ 5] ), \
                               _mm256_xor_si256( M[ 7], H[ 7] ) ), \
             _mm256_xor_si256( M[10], H[10] ) ), \
          _mm256_xor_si256( M[13], H[13] ) ), \
       _mm256_xor_si256( M[14], H[14] ) )

#define Wb1 \
   _mm256_sub_epi64( \
       _mm256_add_epi64( \
          _mm256_add_epi64( \
             _mm256_sub_epi64( _mm256_xor_si256( M[ 6], H[ 6] ), \
                               _mm256_xor_si256( M[ 8], H[ 8] ) ), \
             _mm256_xor_si256( M[11], H[11] ) ), \
          _mm256_xor_si256( M[14], H[14] ) ), \
       _mm256_xor_si256( M[15], H[15] ) )

#define Wb2 \
   _mm256_add_epi64( \
       _mm256_sub_epi64( \
          _mm256_add_epi64( \
             _mm256_add_epi64( _mm256_xor_si256( M[ 0], H[ 0] ), \
                               _mm256_xor_si256( M[ 7], H[ 7] ) ), \
             _mm256_xor_si256( M[ 9], H[ 9] ) ), \
          _mm256_xor_si256( M[12], H[12] ) ), \
       _mm256_xor_si256( M[15], H[15] ) )

#define Wb3 \
   _mm256_add_epi64( \
       _mm256_sub_epi64( \
          _mm256_add_epi64( \
             _mm256_sub_epi64( _mm256_xor_si256( M[ 0], H[ 0] ), \
                               _mm256_xor_si256( M[ 1], H[ 1] ) ), \
             _mm256_xor_si256( M[ 8], H[ 8] ) ), \
          _mm256_xor_si256( M[10], H[10] ) ), \
       _mm256_xor_si256( M[13], H[13] ) )

#define Wb4 \
   _mm256_sub_epi64( \
       _mm256_sub_epi64( \
          _mm256_add_epi64( \
             _mm256_add_epi64( _mm256_xor_si256( M[ 1], H[ 1] ), \
                               _mm256_xor_si256( M[ 2], H[ 2] ) ), \
             _mm256_xor_si256( M[ 9], H[ 9] ) ), \
          _mm256_xor_si256( M[11], H[11] ) ), \
       _mm256_xor_si256( M[14], H[14] ) )

#define Wb5 \
   _mm256_add_epi64( \
       _mm256_sub_epi64( \
          _mm256_add_epi64( \
             _mm256_sub_epi64( _mm256_xor_si256( M[ 3], H[ 3] ), \
                               _mm256_xor_si256( M[ 2], H[ 2] ) ), \
             _mm256_xor_si256( M[10], H[10] ) ), \
          _mm256_xor_si256( M[12], H[12] ) ), \
       _mm256_xor_si256( M[15], H[15] ) )

#define Wb6 \
   _mm256_add_epi64( \
       _mm256_sub_epi64( \
          _mm256_sub_epi64( \
             _mm256_sub_epi64( _mm256_xor_si256( M[ 4], H[ 4] ), \
                               _mm256_xor_si256( M[ 0], H[ 0] ) ), \
             _mm256_xor_si256( M[ 3], H[ 3] ) ), \
          _mm256_xor_si256( M[11], H[11] ) ), \
       _mm256_xor_si256( M[13], H[13] ) )

#define Wb7 \
   _mm256_sub_epi64( \
       _mm256_sub_epi64( \
          _mm256_sub_epi64( \
             _mm256_sub_epi64( _mm256_xor_si256( M[ 1], H[ 1] ), \
                               _mm256_xor_si256( M[ 4], H[ 4] ) ), \
             _mm256_xor_si256( M[ 5], H[ 5] ) ), \
          _mm256_xor_si256( M[12], H[12] ) ), \
       _mm256_xor_si256( M[14], H[14] ) )

#define Wb8 \
   _mm256_sub_epi64( \
       _mm256_add_epi64( \
          _mm256_sub_epi64( \
             _mm256_sub_epi64( _mm256_xor_si256( M[ 2], H[ 2] ), \
                               _mm256_xor_si256( M[ 5], H[ 5] ) ), \
             _mm256_xor_si256( M[ 6], H[ 6] ) ), \
          _mm256_xor_si256( M[13], H[13] ) ), \
       _mm256_xor_si256( M[15], H[15] ) )

#define Wb9 \
   _mm256_add_epi64( \
       _mm256_sub_epi64( \
          _mm256_add_epi64( \
             _mm256_sub_epi64( _mm256_xor_si256( M[ 0], H[ 0] ), \
                               _mm256_xor_si256( M[ 3], H[ 3] ) ), \
             _mm256_xor_si256( M[ 6], H[ 6] ) ), \
          _mm256_xor_si256( M[ 7], H[ 7] ) ), \
       _mm256_xor_si256( M[14], H[14] ) )

#define Wb10 \
   _mm256_add_epi64( \
       _mm256_sub_epi64( \
          _mm256_sub_epi64( \
             _mm256_sub_epi64( _mm256_xor_si256( M[ 8], H[ 8] ), \
                               _mm256_xor_si256( M[ 1], H[ 1] ) ), \
             _mm256_xor_si256( M[ 4], H[ 4] ) ), \
          _mm256_xor_si256( M[ 7], H[ 7] ) ), \
       _mm256_xor_si256( M[15], H[15] ) )

#define Wb11 \
   _mm256_add_epi64( \
       _mm256_sub_epi64( \
          _mm256_sub_epi64( \
             _mm256_sub_epi64( _mm256_xor_si256( M[ 8], H[ 8] ), \
                               _mm256_xor_si256( M[ 0], H[ 0] ) ), \
             _mm256_xor_si256( M[ 2], H[ 2] ) ), \
          _mm256_xor_si256( M[ 5], H[ 5] ) ), \
       _mm256_xor_si256( M[ 9], H[ 9] ) )

#define Wb12 \
   _mm256_add_epi64( \
       _mm256_sub_epi64( \
          _mm256_sub_epi64( \
             _mm256_add_epi64( _mm256_xor_si256( M[ 1], H[ 1] ), \
                               _mm256_xor_si256( M[ 3], H[ 3] ) ), \
             _mm256_xor_si256( M[ 6], H[ 6] ) ), \
          _mm256_xor_si256( M[ 9], H[ 9] ) ), \
       _mm256_xor_si256( M[10], H[10] ) )

#define Wb13 \
   _mm256_add_epi64( \
       _mm256_add_epi64( \
          _mm256_add_epi64( \
             _mm256_add_epi64( _mm256_xor_si256( M[ 2], H[ 2] ), \
                               _mm256_xor_si256( M[ 4], H[ 4] ) ), \
             _mm256_xor_si256( M[ 7], H[ 7] ) ), \
          _mm256_xor_si256( M[10], H[10] ) ), \
       _mm256_xor_si256( M[11], H[11] ) )

#define Wb14 \
   _mm256_sub_epi64( \
       _mm256_sub_epi64( \
          _mm256_add_epi64( \
             _mm256_sub_epi64( _mm256_xor_si256( M[ 3], H[ 3] ), \
                               _mm256_xor_si256( M[ 5], H[ 5] ) ), \
             _mm256_xor_si256( M[ 8], H[ 8] ) ), \
          _mm256_xor_si256( M[11], H[11] ) ), \
       _mm256_xor_si256( M[12], H[12] ) )

#define Wb15 \
   _mm256_add_epi64( \
       _mm256_sub_epi64( \
          _mm256_sub_epi64( \
             _mm256_sub_epi64( _mm256_xor_si256( M[12], H[12] ), \
                               _mm256_xor_si256( M[ 4], H[4] ) ), \
             _mm256_xor_si256( M[ 6], H[ 6] ) ), \
          _mm256_xor_si256( M[ 9], H[ 9] ) ), \
       _mm256_xor_si256( M[13], H[13] ) )

void compress_big( const __m256i *M, const __m256i H[16], __m256i dH[16] )
{
   __m256i qt[32], xl, xh; \

   qt[ 0] = sb0( Wb0 ) + H[ 1]; 
   qt[ 1] = sb1( Wb1 ) + H[ 2]; 
   qt[ 2] = sb2( Wb2 ) + H[ 3]; 
   qt[ 3] = sb3( Wb3 ) + H[ 4]; 
   qt[ 4] = sb4( Wb4 ) + H[ 5]; 
   qt[ 5] = sb0( Wb5 ) + H[ 6]; 
   qt[ 6] = sb1( Wb6 ) + H[ 7]; 
   qt[ 7] = sb2( Wb7 ) + H[ 8]; 
   qt[ 8] = sb3( Wb8 ) + H[ 9]; 
   qt[ 9] = sb4( Wb9 ) + H[10]; 
   qt[10] = sb0( Wb10) + H[11]; 
   qt[11] = sb1( Wb11) + H[12]; 
   qt[12] = sb2( Wb12) + H[13]; 
   qt[13] = sb3( Wb13) + H[14];
   qt[14] = sb4( Wb14) + H[15]; 
   qt[15] = sb0( Wb15) + H[ 0]; 
   qt[16] = expand1b( qt, M, H, 16 ); 
   qt[17] = expand1b( qt, M, H, 17 ); 
   qt[18] = expand2b( qt, M, H, 18 ); 
   qt[19] = expand2b( qt, M, H, 19 ); 
   qt[20] = expand2b( qt, M, H, 20 ); 
   qt[21] = expand2b( qt, M, H, 21 ); 
   qt[22] = expand2b( qt, M, H, 22 ); 
   qt[23] = expand2b( qt, M, H, 23 ); 
   qt[24] = expand2b( qt, M, H, 24 ); 
   qt[25] = expand2b( qt, M, H, 25 ); 
   qt[26] = expand2b( qt, M, H, 26 ); 
   qt[27] = expand2b( qt, M, H, 27 ); 
   qt[28] = expand2b( qt, M, H, 28 ); 
   qt[29] = expand2b( qt, M, H, 29 ); 
   qt[30] = expand2b( qt, M, H, 30 ); 
   qt[31] = expand2b( qt, M, H, 31 ); 
   xl = _mm256_xor_si256( 
              _mm256_xor_si256( _mm256_xor_si256( qt[16], qt[17] ), 
                                _mm256_xor_si256( qt[18], qt[19] ) ), 
              _mm256_xor_si256( _mm256_xor_si256( qt[20], qt[21] ), 
                                _mm256_xor_si256( qt[22], qt[23] ) ) ); 
   xh = _mm256_xor_si256( xl, 
             _mm256_xor_si256( 
                 _mm256_xor_si256( _mm256_xor_si256( qt[24], qt[25] ),
                                   _mm256_xor_si256( qt[26], qt[27] ) ),
                 _mm256_xor_si256( _mm256_xor_si256( qt[28], qt[29] ),
                                   _mm256_xor_si256( qt[30], qt[31] ) )));
   dH[ 0] = _mm256_add_epi64(
                 _mm256_xor_si256( M[0],
                      _mm256_xor_si256( _mm256_slli_epi64( xh, 5 ),
                                        _mm256_srli_epi64( qt[16], 5 ) ) ),
                 _mm256_xor_si256( _mm256_xor_si256( xl, qt[24] ), qt[ 0] ));
   dH[ 1] = _mm256_add_epi64(
                 _mm256_xor_si256( M[1],
                      _mm256_xor_si256( _mm256_srli_epi64( xh, 7 ),
                                        _mm256_slli_epi64( qt[17], 8 ) ) ),
                 _mm256_xor_si256( _mm256_xor_si256( xl, qt[25] ), qt[ 1] ));
   dH[ 2] = _mm256_add_epi64(
                 _mm256_xor_si256( M[2],
                      _mm256_xor_si256( _mm256_srli_epi64( xh, 5 ),
                                        _mm256_slli_epi64( qt[18], 5 ) ) ),
                 _mm256_xor_si256( _mm256_xor_si256( xl, qt[26] ), qt[ 2] ));
   dH[ 3] = _mm256_add_epi64(
                 _mm256_xor_si256( M[3],
                      _mm256_xor_si256( _mm256_srli_epi64( xh, 1 ),
                                        _mm256_slli_epi64( qt[19], 5 ) ) ),
                 _mm256_xor_si256( _mm256_xor_si256( xl, qt[27] ), qt[ 3] ));
   dH[ 4] = _mm256_add_epi64(
                 _mm256_xor_si256( M[4],
                      _mm256_xor_si256( _mm256_srli_epi64( xh, 3 ),
                                        _mm256_slli_epi64( qt[20], 0 ) ) ),
                 _mm256_xor_si256( _mm256_xor_si256( xl, qt[28] ), qt[ 4] ));
   dH[ 5] = _mm256_add_epi64(
                 _mm256_xor_si256( M[5],
                      _mm256_xor_si256( _mm256_slli_epi64( xh, 6 ),
                                        _mm256_srli_epi64( qt[21], 6 ) ) ),
                 _mm256_xor_si256( _mm256_xor_si256( xl, qt[29] ), qt[ 5] ));
   dH[ 6] = _mm256_add_epi64(
                 _mm256_xor_si256( M[6],
                      _mm256_xor_si256( _mm256_srli_epi64( xh, 4 ),
                                        _mm256_slli_epi64( qt[22], 6 ) ) ),
                 _mm256_xor_si256( _mm256_xor_si256( xl, qt[30] ), qt[ 6] ));
   dH[ 7] = _mm256_add_epi64(
                 _mm256_xor_si256( M[7],
                      _mm256_xor_si256( _mm256_srli_epi64( xh, 11 ),
                                        _mm256_slli_epi64( qt[23], 2 ) ) ),
                 _mm256_xor_si256( _mm256_xor_si256( xl, qt[31] ), qt[ 7] ));
   dH[ 8] = _mm256_add_epi64( _mm256_add_epi64(
                 mm256_rotl_64( dH[4], 9 ),
                 _mm256_xor_si256( _mm256_xor_si256( xh, qt[24] ), M[ 8] )),
                 _mm256_xor_si256( _mm256_slli_epi64( xl, 8 ),
                                   _mm256_xor_si256( qt[23], qt[ 8] ) ) );
   dH[ 9] = _mm256_add_epi64( _mm256_add_epi64(
                 mm256_rotl_64( dH[5], 10 ),
                 _mm256_xor_si256( _mm256_xor_si256( xh, qt[25] ), M[ 9] )),
                 _mm256_xor_si256( _mm256_srli_epi64( xl, 6 ),
                                   _mm256_xor_si256( qt[16], qt[ 9] ) ) );
   dH[10] = _mm256_add_epi64( _mm256_add_epi64(
                 mm256_rotl_64( dH[6], 11 ),
                 _mm256_xor_si256( _mm256_xor_si256( xh, qt[26] ), M[10] )),
                 _mm256_xor_si256( _mm256_slli_epi64( xl, 6 ),
                                   _mm256_xor_si256( qt[17], qt[10] ) ) );
   dH[11] = _mm256_add_epi64( _mm256_add_epi64(
                 mm256_rotl_64( dH[7], 12 ),
                 _mm256_xor_si256( _mm256_xor_si256( xh, qt[27] ), M[11] )),
                 _mm256_xor_si256( _mm256_slli_epi64( xl, 4 ),
                                   _mm256_xor_si256( qt[18], qt[11] ) ) );
   dH[12] = _mm256_add_epi64( _mm256_add_epi64(
                 mm256_rotl_64( dH[0], 13 ),
                 _mm256_xor_si256( _mm256_xor_si256( xh, qt[28] ), M[12] )),
                 _mm256_xor_si256( _mm256_srli_epi64( xl, 3 ),
                                   _mm256_xor_si256( qt[19], qt[12] ) ) );
   dH[13] = _mm256_add_epi64( _mm256_add_epi64(
                 mm256_rotl_64( dH[1], 14 ),
                 _mm256_xor_si256( _mm256_xor_si256( xh, qt[29] ), M[13] )),
                 _mm256_xor_si256( _mm256_srli_epi64( xl, 4 ),
                                   _mm256_xor_si256( qt[20], qt[13] ) ) );
   dH[14] = _mm256_add_epi64( _mm256_add_epi64(
                 mm256_rotl_64( dH[2], 15 ),
                 _mm256_xor_si256( _mm256_xor_si256( xh, qt[30] ), M[14] )),
                 _mm256_xor_si256( _mm256_srli_epi64( xl, 7 ),
                                   _mm256_xor_si256( qt[21], qt[14] ) ) );
   dH[15] = _mm256_add_epi64( _mm256_add_epi64(
                 mm256_rotl_64( dH[3], 16 ),
                 _mm256_xor_si256( _mm256_xor_si256( xh, qt[31] ), M[15] )),
                 _mm256_xor_si256( _mm256_srli_epi64( xl, 2 ),
                                   _mm256_xor_si256( qt[22], qt[15] ) ) );
} 

#endif  // 64

//#define FOLDs   FOLD(sph_u32, MAKE_Qs, SPH_ROTL32, M, Qs, dH)


/*
static void
compress_small(const unsigned char *data, const sph_u32 h[16], sph_u32 dh[16])
{
#define M(x)    sph_dec32le_aligned(data + 4 * (x))
#define H(x)    (h[x])
#define dH(x)   (dh[x])

	FOLDs;

#undef M
#undef H
#undef dH
}

static const sph_u32 final_s[16] = {
	SPH_C32(0xaaaaaaa0), SPH_C32(0xaaaaaaa1), SPH_C32(0xaaaaaaa2),
	SPH_C32(0xaaaaaaa3), SPH_C32(0xaaaaaaa4), SPH_C32(0xaaaaaaa5),
	SPH_C32(0xaaaaaaa6), SPH_C32(0xaaaaaaa7), SPH_C32(0xaaaaaaa8),
	SPH_C32(0xaaaaaaa9), SPH_C32(0xaaaaaaaa), SPH_C32(0xaaaaaaab),
	SPH_C32(0xaaaaaaac), SPH_C32(0xaaaaaaad), SPH_C32(0xaaaaaaae),
	SPH_C32(0xaaaaaaaf)
};

static void
bmw32_4way_init(bmw_4way_small_context *sc, const sph_u32 *iv)
{
	memcpy(sc->H, iv, sizeof sc->H);
	sc->ptr = 0;
#if SPH_64
	sc->bit_count = 0;
#else
	sc->bit_count_high = 0;
	sc->bit_count_low = 0;
#endif
}

static void
bmw32_4way(bmw_4way_small_context *sc, const void *data, size_t len)
{
	unsigned char *buf;
	size_t ptr;
	sph_u32 htmp[16];
	sph_u32 *h1, *h2;
#if !SPH_64
	sph_u32 tmp;
#endif

#if SPH_64
	sc->bit_count += (sph_u64)len << 3;
#else
	tmp = sc->bit_count_low;
	sc->bit_count_low = SPH_T32(tmp + ((sph_u32)len << 3));
	if (sc->bit_count_low < tmp)
		sc->bit_count_high ++;
	sc->bit_count_high += len >> 29;
#endif
	buf = sc->buf;
	ptr = sc->ptr;
	h1 = sc->H;
	h2 = htmp;
	while (len > 0) {
		size_t clen;

		clen = (sizeof sc->buf) - ptr;
		if (clen > len)
			clen = len;
		memcpy(buf + ptr, data, clen);
		data = (const unsigned char *)data + clen;
		len -= clen;
		ptr += clen;
		if (ptr == sizeof sc->buf) {
			sph_u32 *ht;

			compress_small(buf, h1, h2);
			ht = h1;
			h1 = h2;
			h2 = ht;
			ptr = 0;
		}
	}
	sc->ptr = ptr;
	if (h1 != sc->H)
		memcpy(sc->H, h1, sizeof sc->H);
}

static void
bmw32_4way_close(bmw_4way_small_context *sc, unsigned ub, unsigned n,
	void *dst, size_t out_size_w32)
{
	unsigned char *buf, *out;
	size_t ptr, u, v;
	unsigned z;
	sph_u32 h1[16], h2[16], *h;

	buf = sc->buf;
	ptr = sc->ptr;
	z = 0x80 >> n;
	buf[ptr ++] = ((ub & -z) | z) & 0xFF;
	h = sc->H;
	if (ptr > (sizeof sc->buf) - 8) {
		memset(buf + ptr, 0, (sizeof sc->buf) - ptr);
		compress_small(buf, h, h1);
		ptr = 0;
		h = h1;
	}
	memset(buf + ptr, 0, (sizeof sc->buf) - 8 - ptr);
#if SPH_64
	sph_enc64le_aligned(buf + (sizeof sc->buf) - 8,
		SPH_T64(sc->bit_count + n));
#else
	sph_enc32le_aligned(buf + (sizeof sc->buf) - 8,
		sc->bit_count_low + n);
	sph_enc32le_aligned(buf + (sizeof sc->buf) - 4,
		SPH_T32(sc->bit_count_high));
#endif
	compress_small(buf, h, h2);
	for (u = 0; u < 16; u ++)
		sph_enc32le_aligned(buf + 4 * u, h2[u]);
	compress_small(buf, final_s, h1);
	out = dst;
	for (u = 0, v = 16 - out_size_w32; u < out_size_w32; u ++, v ++)
		sph_enc32le(out + 4 * u, h1[v]);
}
*/
#if SPH_64

static const __m256i final_b[16] =
{
   { 0xaaaaaaaaaaaaaaa0, 0xaaaaaaaaaaaaaaa0,
     0xaaaaaaaaaaaaaaa0, 0xaaaaaaaaaaaaaaa0 },
   { 0xaaaaaaaaaaaaaaa1, 0xaaaaaaaaaaaaaaa1,
     0xaaaaaaaaaaaaaaa1, 0xaaaaaaaaaaaaaaa1 },
   { 0xaaaaaaaaaaaaaaa2, 0xaaaaaaaaaaaaaaa2,
     0xaaaaaaaaaaaaaaa2, 0xaaaaaaaaaaaaaaa2 },
   { 0xaaaaaaaaaaaaaaa3, 0xaaaaaaaaaaaaaaa3,
     0xaaaaaaaaaaaaaaa3, 0xaaaaaaaaaaaaaaa3 },
   { 0xaaaaaaaaaaaaaaa4, 0xaaaaaaaaaaaaaaa4,
     0xaaaaaaaaaaaaaaa4, 0xaaaaaaaaaaaaaaa4 },
   { 0xaaaaaaaaaaaaaaa5, 0xaaaaaaaaaaaaaaa5,
     0xaaaaaaaaaaaaaaa5, 0xaaaaaaaaaaaaaaa5 },
   { 0xaaaaaaaaaaaaaaa6, 0xaaaaaaaaaaaaaaa6,
     0xaaaaaaaaaaaaaaa6, 0xaaaaaaaaaaaaaaa6 },
   { 0xaaaaaaaaaaaaaaa7, 0xaaaaaaaaaaaaaaa7,
     0xaaaaaaaaaaaaaaa7, 0xaaaaaaaaaaaaaaa7 },
   { 0xaaaaaaaaaaaaaaa8, 0xaaaaaaaaaaaaaaa8,
     0xaaaaaaaaaaaaaaa8, 0xaaaaaaaaaaaaaaa8 },
   { 0xaaaaaaaaaaaaaaa9, 0xaaaaaaaaaaaaaaa9,
     0xaaaaaaaaaaaaaaa9, 0xaaaaaaaaaaaaaaa9 },
   { 0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa,
     0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa },
   { 0xaaaaaaaaaaaaaaab, 0xaaaaaaaaaaaaaaab,
     0xaaaaaaaaaaaaaaab, 0xaaaaaaaaaaaaaaab },
   { 0xaaaaaaaaaaaaaaac, 0xaaaaaaaaaaaaaaac,
     0xaaaaaaaaaaaaaaac, 0xaaaaaaaaaaaaaaac },
   { 0xaaaaaaaaaaaaaaad, 0xaaaaaaaaaaaaaaad,
     0xaaaaaaaaaaaaaaad, 0xaaaaaaaaaaaaaaad },
   { 0xaaaaaaaaaaaaaaae, 0xaaaaaaaaaaaaaaae,
     0xaaaaaaaaaaaaaaae, 0xaaaaaaaaaaaaaaae },
   { 0xaaaaaaaaaaaaaaaf, 0xaaaaaaaaaaaaaaaf,
     0xaaaaaaaaaaaaaaaf, 0xaaaaaaaaaaaaaaaf }
};

static void
bmw64_4way_init( bmw_4way_big_context *sc, const sph_u64 *iv )
{
   for ( int i = 0; i < 16; i++ )
      sc->H[i] = _mm256_set1_epi64x( iv[i] );
   sc->ptr = 0;
   sc->bit_count = 0;
}

static void
bmw64_4way( bmw_4way_big_context *sc, const void *data, size_t len )
{
   __m256i *vdata = (__m256i*)data;
   __m256i *buf;
   __m256i htmp[16];
   __m256i *h1, *h2;
   size_t ptr;
   const int buf_size = 128;  // bytes of one lane, compatible with len

   sc->bit_count += (sph_u64)len << 3;
   buf = sc->buf;
   ptr = sc->ptr;
   h1 = sc->H;
   h2 = htmp;
   while ( len > 0 )
   {
      size_t clen;
      clen = buf_size - ptr;
      if ( clen > len )
         clen = len;
      memcpy_256( buf + (ptr>>3), vdata, clen >> 3 );
      vdata = vdata + (clen>>3);
      len -= clen;
      ptr += clen;
      if ( ptr == buf_size )
      {
         __m256i *ht;
         compress_big( buf, h1, h2 );
         ht = h1;
         h1 = h2;
         h2 = ht;
         ptr = 0;
      }
   }
   sc->ptr = ptr;
   if ( h1 != sc->H )
        memcpy_256( sc->H, h1, 16 );
}

static void
bmw64_4way_close(bmw_4way_big_context *sc, unsigned ub, unsigned n,
	void *dst, size_t out_size_w64)
{
   __m256i *buf;
   __m256i h1[16], h2[16], *h;
   size_t ptr, u, v;
   unsigned z;
   const int buf_size = 128;  // bytes of one lane, compatible with len

   buf = sc->buf;
   ptr = sc->ptr;
   z = 0x80 >> n;
   buf[ ptr>>3 ] = _mm256_set1_epi64x( z );
   ptr += 8;
   h = sc->H;

   if (  ptr > (buf_size - 8) )
   {
      memset_zero_256( buf + (ptr>>3), (buf_size - ptr) >> 3 );
      compress_big( buf, h, h1 );
      ptr = 0;
      h = h1;
   }
   memset_zero_256( buf + (ptr>>3), (buf_size - 8 - ptr) >> 3 );
   buf[ (buf_size - 8) >> 3 ] = _mm256_set1_epi64x( sc->bit_count + n );
   compress_big( buf, h, h2 );
   for ( u = 0; u < 16; u ++ )
      buf[u] = h2[u];
   compress_big( buf, final_b, h1 );
   for (u = 0, v = 16 - out_size_w64; u < out_size_w64; u ++, v ++)
      casti_m256i(dst,u) = h1[v];
}

#endif

void
bmw256_4way_init(void *cc)
{
//	bmw32_4way_init(cc, IV256);
}

void
bmw256_4way(void *cc, const void *data, size_t len)
{
//	bmw32_4way(cc, data, len);
}

void
bmw256_4way_close(void *cc, void *dst)
{
//	bmw256_4way_addbits_and_close(cc, 0, 0, dst);
}

void
bmw256_4way_addbits_and_close(void *cc, unsigned ub, unsigned n, void *dst)
{
//	bmw32_4way_close(cc, ub, n, dst, 8);
}

#if SPH_64

void
bmw512_4way_init(void *cc)
{
	bmw64_4way_init(cc, IV512);
}

void
bmw512_4way(void *cc, const void *data, size_t len)
{
	bmw64_4way(cc, data, len);
}

void
bmw512_4way_close(void *cc, void *dst)
{
	bmw512_4way_addbits_and_close(cc, 0, 0, dst);
}

void
bmw512_4way_addbits_and_close(void *cc, unsigned ub, unsigned n, void *dst)
{
	bmw64_4way_close(cc, ub, n, dst, 8);
}

#endif

#ifdef __cplusplus
}
#endif

#endif
