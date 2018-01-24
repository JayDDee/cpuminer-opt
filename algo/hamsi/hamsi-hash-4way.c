/* $Id: hamsi.c 251 2010-10-19 14:31:51Z tp $ */
/*
 * Hamsi implementation.
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

#include "hamsi-hash-4way.h"

#if defined(__AVX__)

#ifdef __cplusplus
extern "C"{
#endif

/*
 * The SPH_HAMSI_EXPAND_* define how many input bits we handle in one
 * table lookup during message expansion (1 to 8, inclusive). If we note
 * w the number of bits per message word (w=32 for Hamsi-224/256, w=64
 * for Hamsi-384/512), r the size of a "row" in 32-bit words (r=8 for
 * Hamsi-224/256, r=16 for Hamsi-384/512), and n the expansion level,
 * then we will get t tables (where t=ceil(w/n)) of individual size
 * 2^n*r*4 (in bytes). The last table may be shorter (e.g. with w=32 and
 * n=5, there are 7 tables, but the last one uses only two bits on
 * input, not five).
 *
 * Also, we read t rows of r words from RAM. Words in a given row are
 * concatenated in RAM in that order, so most of the cost is about
 * reading the first row word; comparatively, cache misses are thus
 * less expensive with Hamsi-512 (r=16) than with Hamsi-256 (r=8).
 *
 * When n=1, tables are "special" in that we omit the first entry of
 * each table (which always contains 0), so that total table size is
 * halved.
 *
 * We thus have the following (size1 is the cumulative table size of
 * Hamsi-224/256; size2 is for Hamsi-384/512; similarly, t1 and t2
 * are for Hamsi-224/256 and Hamsi-384/512, respectively).
 *
 *   n      size1      size2    t1    t2
 * ---------------------------------------
 *   1       1024       4096    32    64
 *   2       2048       8192    16    32
 *   3       2688      10880    11    22
 *   4       4096      16384     8    16
 *   5       6272      25600     7    13
 *   6      10368      41984     6    11
 *   7      16896      73856     5    10
 *   8      32768     131072     4     8
 *
 * So there is a trade-off: a lower n makes the tables fit better in
 * L1 cache, but increases the number of memory accesses. The optimal
 * value depends on the amount of available L1 cache and the relative
 * impact of a cache miss.
 *
 * Experimentally, in ideal benchmark conditions (which are not necessarily
 * realistic with regards to L1 cache contention), it seems that n=8 is
 * the best value on "big" architectures (those with 32 kB or more of L1
 * cache), while n=4 is better on "small" architectures. This was tested
 * on an Intel Core2 Q6600 (both 32-bit and 64-bit mode), a PowerPC G3
 * (32 kB L1 cache, hence "big"), and a MIPS-compatible Broadcom BCM3302
 * (8 kB L1 cache).
 *
 * Note: with n=1, the 32 tables (actually implemented as one big table)
 * are read entirely and sequentially, regardless of the input data,
 * thus avoiding any data-dependent table access pattern.
 */

// Hard coded
//#define SPH_HAMSI_EXPAND_BIG    1

/*
#if !defined SPH_HAMSI_EXPAND_SMALL
#if SPH_SMALL_FOOTPRINT_HAMSI
#define SPH_HAMSI_EXPAND_SMALL  4
#else
#define SPH_HAMSI_EXPAND_SMALL  8
#endif
#endif

#if !defined SPH_HAMSI_EXPAND_BIG
#define SPH_HAMSI_EXPAND_BIG    8
#endif
*/

#ifdef _MSC_VER
#pragma warning (disable: 4146)
#endif

#include "hamsi-helper-4way.c"

static const sph_u32 IV512[] = {
	SPH_C32(0x73746565), SPH_C32(0x6c706172), SPH_C32(0x6b204172),
	SPH_C32(0x656e6265), SPH_C32(0x72672031), SPH_C32(0x302c2062),
	SPH_C32(0x75732032), SPH_C32(0x3434362c), SPH_C32(0x20422d33),
	SPH_C32(0x30303120), SPH_C32(0x4c657576), SPH_C32(0x656e2d48),
	SPH_C32(0x65766572), SPH_C32(0x6c65652c), SPH_C32(0x2042656c),
	SPH_C32(0x6769756d)
};

static const sph_u32 alpha_n[] = {
	SPH_C32(0xff00f0f0), SPH_C32(0xccccaaaa), SPH_C32(0xf0f0cccc),
	SPH_C32(0xff00aaaa), SPH_C32(0xccccaaaa), SPH_C32(0xf0f0ff00),
	SPH_C32(0xaaaacccc), SPH_C32(0xf0f0ff00), SPH_C32(0xf0f0cccc),
	SPH_C32(0xaaaaff00), SPH_C32(0xccccff00), SPH_C32(0xaaaaf0f0),
	SPH_C32(0xaaaaf0f0), SPH_C32(0xff00cccc), SPH_C32(0xccccf0f0),
	SPH_C32(0xff00aaaa), SPH_C32(0xccccaaaa), SPH_C32(0xff00f0f0),
	SPH_C32(0xff00aaaa), SPH_C32(0xf0f0cccc), SPH_C32(0xf0f0ff00),
	SPH_C32(0xccccaaaa), SPH_C32(0xf0f0ff00), SPH_C32(0xaaaacccc),
	SPH_C32(0xaaaaff00), SPH_C32(0xf0f0cccc), SPH_C32(0xaaaaf0f0),
	SPH_C32(0xccccff00), SPH_C32(0xff00cccc), SPH_C32(0xaaaaf0f0),
	SPH_C32(0xff00aaaa), SPH_C32(0xccccf0f0)
};

static const sph_u32 alpha_f[] = {
	SPH_C32(0xcaf9639c), SPH_C32(0x0ff0f9c0), SPH_C32(0x639c0ff0),
	SPH_C32(0xcaf9f9c0), SPH_C32(0x0ff0f9c0), SPH_C32(0x639ccaf9),
	SPH_C32(0xf9c00ff0), SPH_C32(0x639ccaf9), SPH_C32(0x639c0ff0),
	SPH_C32(0xf9c0caf9), SPH_C32(0x0ff0caf9), SPH_C32(0xf9c0639c),
	SPH_C32(0xf9c0639c), SPH_C32(0xcaf90ff0), SPH_C32(0x0ff0639c),
	SPH_C32(0xcaf9f9c0), SPH_C32(0x0ff0f9c0), SPH_C32(0xcaf9639c),
	SPH_C32(0xcaf9f9c0), SPH_C32(0x639c0ff0), SPH_C32(0x639ccaf9),
	SPH_C32(0x0ff0f9c0), SPH_C32(0x639ccaf9), SPH_C32(0xf9c00ff0),
	SPH_C32(0xf9c0caf9), SPH_C32(0x639c0ff0), SPH_C32(0xf9c0639c),
	SPH_C32(0x0ff0caf9), SPH_C32(0xcaf90ff0), SPH_C32(0xf9c0639c),
	SPH_C32(0xcaf9f9c0), SPH_C32(0x0ff0639c)
};

/*
#define s0   m0
#define s1   m1
#define s2   c0
#define s3   c1
#define s4   c2
#define s5   c3
#define s6   m2
#define s7   m3
#define s8   m4
#define s9   m5
#define sA   c4
#define sB   c5
#define sC   c6
#define sD   c7
#define sE   m6
#define sF   m7
*/

#define SBOX( a, b, c, d ) \
do { \
  __m128i t; \
  t = a; \
  a = _mm_xor_si128( d, _mm_and_si128( a, c ) ); \
  c = _mm_xor_si128( a, _mm_xor_si128( c, b ) ); \
  d = _mm_xor_si128( b, _mm_or_si128( d, t ) ); \
  t = _mm_xor_si128( t, c ); \
  b = d; \
  d = _mm_xor_si128( a, _mm_or_si128( d, t ) ); \
  a = _mm_and_si128( a, b ); \
  t = _mm_xor_si128( t, a ); \
  b = _mm_xor_si128( t, _mm_xor_si128( b, d ) ); \
  a = c; \
  c = b; \
  b = d; \
  d = mm_not( t ); \
} while (0)

#define L( a, b, c, d ) \
do { \
   a = mm_rotl_32( a, 13 ); \
   c = mm_rotl_32( c,  3 ); \
   b = _mm_xor_si128( b, _mm_xor_si128( a, c ) ); \
   d = _mm_xor_si128( d, _mm_xor_si128( c, _mm_slli_epi32( a, 3 ) ) ); \
   b = mm_rotl_32( b, 1 ); \
   d = mm_rotl_32( d, 7 ); \
   a = _mm_xor_si128( a, _mm_xor_si128( b, d ) ); \
   c = _mm_xor_si128( c, _mm_xor_si128( d, _mm_slli_epi32( b, 7 ) ) ); \
   a = mm_rotl_32( a,  5 ); \
   c = mm_rotl_32( c, 22 ); \
} while (0)

#define DECL_STATE_BIG \
   __m128i c0, c1, c2, c3, c4, c5, c6, c7; \
   __m128i c8, c9, cA, cB, cC, cD, cE, cF;

#define READ_STATE_BIG(sc)   do { \
		c0 = sc->h[0x0]; \
		c1 = sc->h[0x1]; \
		c2 = sc->h[0x2]; \
		c3 = sc->h[0x3]; \
		c4 = sc->h[0x4]; \
		c5 = sc->h[0x5]; \
		c6 = sc->h[0x6]; \
		c7 = sc->h[0x7]; \
		c8 = sc->h[0x8]; \
		c9 = sc->h[0x9]; \
		cA = sc->h[0xA]; \
		cB = sc->h[0xB]; \
		cC = sc->h[0xC]; \
		cD = sc->h[0xD]; \
		cE = sc->h[0xE]; \
		cF = sc->h[0xF]; \
	} while (0)

#define WRITE_STATE_BIG(sc)   do { \
		sc->h[0x0] = c0; \
		sc->h[0x1] = c1; \
		sc->h[0x2] = c2; \
		sc->h[0x3] = c3; \
		sc->h[0x4] = c4; \
		sc->h[0x5] = c5; \
		sc->h[0x6] = c6; \
		sc->h[0x7] = c7; \
		sc->h[0x8] = c8; \
		sc->h[0x9] = c9; \
		sc->h[0xA] = cA; \
		sc->h[0xB] = cB; \
		sc->h[0xC] = cC; \
		sc->h[0xD] = cD; \
		sc->h[0xE] = cE; \
		sc->h[0xF] = cF; \
	} while (0)

#define s00   m0
#define s01   m1
#define s02   c0
#define s03   c1
#define s04   m2
#define s05   m3
#define s06   c2
#define s07   c3
#define s08   c4
#define s09   c5
#define s0A   m4
#define s0B   m5
#define s0C   c6
#define s0D   c7
#define s0E   m6
#define s0F   m7
#define s10   m8
#define s11   m9
#define s12   c8
#define s13   c9
#define s14   mA
#define s15   mB
#define s16   cA
#define s17   cB
#define s18   cC
#define s19   cD
#define s1A   mC
#define s1B   mD
#define s1C   cE
#define s1D   cF
#define s1E   mE
#define s1F   mF

#define ROUND_BIG(rc, alpha) \
do { \
   s00 = _mm_xor_si128( s00, _mm_set1_epi32( alpha[ 0x00 ] ) ); \
   s01 = _mm_xor_si128( s01, _mm_xor_si128( _mm_set1_epi32( alpha[ 0x01 ] ), \
                                            _mm_set1_epi32( rc ) ) ); \
   s02 = _mm_xor_si128( s02, _mm_set1_epi32( alpha[ 0x02 ] ) ); \
   s03 = _mm_xor_si128( s03, _mm_set1_epi32( alpha[ 0x03 ] ) ); \
   s04 = _mm_xor_si128( s04, _mm_set1_epi32( alpha[ 0x04 ] ) ); \
   s05 = _mm_xor_si128( s05, _mm_set1_epi32( alpha[ 0x05 ] ) ); \
   s06 = _mm_xor_si128( s06, _mm_set1_epi32( alpha[ 0x06 ] ) ); \
   s07 = _mm_xor_si128( s07, _mm_set1_epi32( alpha[ 0x07 ] ) ); \
   s08 = _mm_xor_si128( s08, _mm_set1_epi32( alpha[ 0x08 ] ) ); \
   s09 = _mm_xor_si128( s09, _mm_set1_epi32( alpha[ 0x09 ] ) ); \
   s0A = _mm_xor_si128( s0A, _mm_set1_epi32( alpha[ 0x0A ] ) ); \
   s0B = _mm_xor_si128( s0B, _mm_set1_epi32( alpha[ 0x0B ] ) ); \
   s0C = _mm_xor_si128( s0C, _mm_set1_epi32( alpha[ 0x0C ] ) ); \
   s0D = _mm_xor_si128( s0D, _mm_set1_epi32( alpha[ 0x0D ] ) ); \
   s0E = _mm_xor_si128( s0E, _mm_set1_epi32( alpha[ 0x0E ] ) ); \
   s0F = _mm_xor_si128( s0F, _mm_set1_epi32( alpha[ 0x0F ] ) ); \
   s10 = _mm_xor_si128( s10, _mm_set1_epi32( alpha[ 0x10 ] ) ); \
   s11 = _mm_xor_si128( s11, _mm_set1_epi32( alpha[ 0x11 ] ) ); \
   s12 = _mm_xor_si128( s12, _mm_set1_epi32( alpha[ 0x12 ] ) ); \
   s13 = _mm_xor_si128( s13, _mm_set1_epi32( alpha[ 0x13 ] ) ); \
   s14 = _mm_xor_si128( s14, _mm_set1_epi32( alpha[ 0x14 ] ) ); \
   s15 = _mm_xor_si128( s15, _mm_set1_epi32( alpha[ 0x15 ] ) ); \
   s16 = _mm_xor_si128( s16, _mm_set1_epi32( alpha[ 0x16 ] ) ); \
   s17 = _mm_xor_si128( s17, _mm_set1_epi32( alpha[ 0x17 ] ) ); \
   s18 = _mm_xor_si128( s18, _mm_set1_epi32( alpha[ 0x18 ] ) ); \
   s19 = _mm_xor_si128( s19, _mm_set1_epi32( alpha[ 0x19 ] ) ); \
   s1A = _mm_xor_si128( s1A, _mm_set1_epi32( alpha[ 0x1A ] ) ); \
   s1B = _mm_xor_si128( s1B, _mm_set1_epi32( alpha[ 0x1B ] ) ); \
   s1C = _mm_xor_si128( s1C, _mm_set1_epi32( alpha[ 0x1C ] ) ); \
   s1D = _mm_xor_si128( s1D, _mm_set1_epi32( alpha[ 0x1D ] ) ); \
   s1E = _mm_xor_si128( s1E, _mm_set1_epi32( alpha[ 0x1E ] ) ); \
   s1F = _mm_xor_si128( s1F, _mm_set1_epi32( alpha[ 0x1F ] ) ); \
   SBOX( s00, s08, s10, s18); \
   SBOX( s01, s09, s11, s19); \
   SBOX( s02, s0A, s12, s1A); \
   SBOX( s03, s0B, s13, s1B); \
   SBOX( s04, s0C, s14, s1C); \
   SBOX( s05, s0D, s15, s1D); \
   SBOX( s06, s0E, s16, s1E); \
   SBOX( s07, s0F, s17, s1F); \
   L( s00, s09, s12, s1B ); \
   L( s01, s0A, s13, s1C ); \
   L( s02, s0B, s14, s1D ); \
   L( s03, s0C, s15, s1E ); \
   L( s04, s0D, s16, s1F ); \
   L( s05, s0E, s17, s18 ); \
   L( s06, s0F, s10, s19 ); \
   L( s07, s08, s11, s1A ); \
   L( s00, s02, s05, s07 ); \
   L( s10, s13, s15, s16 ); \
   L( s09, s0B, s0C, s0E ); \
   L( s19, s1A, s1C, s1F ); \
} while (0)

#define P_BIG   do { \
		ROUND_BIG(0, alpha_n); \
		ROUND_BIG(1, alpha_n); \
		ROUND_BIG(2, alpha_n); \
		ROUND_BIG(3, alpha_n); \
		ROUND_BIG(4, alpha_n); \
		ROUND_BIG(5, alpha_n); \
	} while (0)

#define PF_BIG   do { \
		ROUND_BIG(0, alpha_f); \
		ROUND_BIG(1, alpha_f); \
		ROUND_BIG(2, alpha_f); \
		ROUND_BIG(3, alpha_f); \
		ROUND_BIG(4, alpha_f); \
		ROUND_BIG(5, alpha_f); \
		ROUND_BIG(6, alpha_f); \
		ROUND_BIG(7, alpha_f); \
		ROUND_BIG(8, alpha_f); \
		ROUND_BIG(9, alpha_f); \
		ROUND_BIG(10, alpha_f); \
		ROUND_BIG(11, alpha_f); \
	} while (0)

#define T_BIG \
do { /* order is important */ \
   cF = _mm_xor_si128( sc->h[ 0xF ], s17 ); \
   cE = _mm_xor_si128( sc->h[ 0xE ], s16 ); \
   cD = _mm_xor_si128( sc->h[ 0xD ], s15 ); \
   cC = _mm_xor_si128( sc->h[ 0xC ], s14 ); \
   cB = _mm_xor_si128( sc->h[ 0xB ], s13 ); \
   cA = _mm_xor_si128( sc->h[ 0xA ], s12 ); \
   c9 = _mm_xor_si128( sc->h[ 0x9 ], s11 ); \
   c8 = _mm_xor_si128( sc->h[ 0x8 ], s10 ); \
   c7 = _mm_xor_si128( sc->h[ 0x7 ], s07 ); \
   c6 = _mm_xor_si128( sc->h[ 0x6 ], s06 ); \
   c5 = _mm_xor_si128( sc->h[ 0x5 ], s05 ); \
   c4 = _mm_xor_si128( sc->h[ 0x4 ], s04 ); \
   c3 = _mm_xor_si128( sc->h[ 0x3 ], s03 ); \
   c2 = _mm_xor_si128( sc->h[ 0x2 ], s02 ); \
   c1 = _mm_xor_si128( sc->h[ 0x1 ], s01 ); \
   c0 = _mm_xor_si128( sc->h[ 0x0 ], s00 ); \
} while (0)

void hamsi_big( hamsi_4way_big_context *sc, __m128i *buf, size_t num )
{
   DECL_STATE_BIG
   sph_u32 tmp;

   tmp = SPH_T32( (sph_u32)num << 6 );
   sc->count_low = SPH_T32( sc->count_low + tmp );
   sc->count_high += (sph_u32)( (num >> 13) >> 13 );
   if ( sc->count_low < tmp )
      sc->count_high++;

   READ_STATE_BIG( sc );

   while ( num-- > 0 )
   {
      __m128i m0, m1, m2, m3, m4, m5, m6, m7;
      __m128i m8, m9, mA, mB, mC, mD, mE, mF;

      INPUT_BIG;
      P_BIG;
      T_BIG;

// Strange kluge. Without the following WRITE_STATE the hash is bad.
// SPH doesn't do it.
      WRITE_STATE_BIG( sc );
      buf += 2;
   }
   WRITE_STATE_BIG( sc );
}

void hamsi_big_final( hamsi_4way_big_context *sc, __m128i *buf )
{
   __m128i m0, m1, m2, m3, m4, m5, m6, m7;
   __m128i m8, m9, mA, mB, mC, mD, mE, mF;
   DECL_STATE_BIG

   READ_STATE_BIG( sc );
   INPUT_BIG;
   PF_BIG;
   T_BIG;
   WRITE_STATE_BIG( sc );
}

void hamsi_big_init( hamsi_4way_big_context *sc, const sph_u32 *iv )
{
   sc->partial_len = 0;
   sc->count_high = sc->count_low = 0;
   for ( int i = 0; i < 16; i ++ )
      sc->h[i] = _mm_set1_epi32( iv[i] );
}

void hamsi_big_core( hamsi_4way_big_context *sc, const void *data, size_t len )
{
   __m128i *vdata = (__m128i*)data;

   if ( sc->partial_len != 0 )
   {
      size_t mlen;

      mlen = 8 - sc->partial_len;
      if ( len < mlen )
      {
         memcpy_128( sc->partial + (sc->partial_len >> 2), data, len>>2 );
         sc->partial_len += len;
         return;
      }
      else
      {
         memcpy_128( sc->partial + (sc->partial_len >> 2), data, mlen>>2 );
         len -= mlen;
         vdata += mlen>>2;
         hamsi_big( sc, sc->partial, 1 );
         sc->partial_len = 0;
      }
   }

   hamsi_big( sc, vdata, len>>3 );
   vdata += ( (len& ~(size_t)7) >> 2 );
   len &= (size_t)7;
   memcpy_128( sc->partial, vdata, len>>2 );
}

void hamsi_big_close( hamsi_4way_big_context *sc, void *dst,
                      size_t out_size_w32 )
{
   __m128i pad[2];
   size_t ptr, u;
   __m128i *out = (__m128i*)dst;

   ptr = sc->partial_len;

   pad[0] = mm_byteswap_32( _mm_set1_epi32( sc->count_high ) );      
   pad[1] = mm_byteswap_32( _mm_set1_epi32( sc->count_low + (ptr << 3) ) );

   sc->partial[ ptr>>2 ] = _mm_set1_epi32( 0x80UL );

   if ( ptr < 8 )
      memset_zero_128( sc->partial + (ptr>>2) + 1, (8-ptr) >> 2 );

   hamsi_big( sc, sc->partial, 1 );
   hamsi_big_final( sc, pad );

   for ( u = 0; u < 16; u ++ )
      out[u] = mm_byteswap_32( sc->h[u] );
}

void hamsi512_4way_init( void *cc )
{
	hamsi_big_init( cc, IV512 );
}

void hamsi512_4way( void *cc, const void *data, size_t len )
{
	hamsi_big_core( cc, data, len );
}

void hamsi512_4way_close( void *cc, void *dst )
{
	hamsi_big_close( cc, dst, 16 );
}

#ifdef __cplusplus
}
#endif

#endif
