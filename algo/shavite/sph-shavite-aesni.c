/* $Id: shavite.c 227 2010-06-16 17:28:38Z tp $ */
/*
 * SHAvite-3 implementation.
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
#include <stdio.h>
#include <stddef.h>
#include <string.h>

#if defined(__AES__)

#include "sph_shavite.h"
#include "simd-utils.h"

#ifdef __cplusplus
extern "C"{
#endif

#if SPH_SMALL_FOOTPRINT && !defined SPH_SMALL_FOOTPRINT_SHAVITE
#define SPH_SMALL_FOOTPRINT_SHAVITE   1
#endif

#ifdef _MSC_VER
#pragma warning (disable: 4146)
#endif

#define C32   SPH_C32

static const sph_u32 IV512[] = {
	C32(0x72FCCDD8), C32(0x79CA4727), C32(0x128A077B), C32(0x40D55AEC),
	C32(0xD1901A06), C32(0x430AE307), C32(0xB29F5CD1), C32(0xDF07FBFC),
	C32(0x8E45D73D), C32(0x681AB538), C32(0xBDE86578), C32(0xDD577E47),
	C32(0xE275EADE), C32(0x502D9FCD), C32(0xB9357178), C32(0x022A4B9A)
};

// Partially rotate elements in two 128 bit vectors a & b as one 256 bit vector
// and return the rotated 128 bit vector a.
// a[3:0] = { b[0], a[3], a[2], a[1] }
#if defined(__SSSE3__)

#define mm128_ror256hi_1x32( a, b )  _mm_alignr_epi8( b, a, 4 )

#else  // SSE2

#define mm128_ror256hi_1x32( a, b ) \
   _mm_or_si128( _mm_srli_si128( a,  4 ), \
                 _mm_slli_si128( b, 12 ) )

#endif

#if defined(__AVX2__)
// 2 way version of above
// a[7:0] = { b[4], a[7], a[6], a[5], b[0], a[3], a[2], a[1] }

#define mm256_ror2x256hi_1x32( a, b ) \
   _mm256_blend_epi32( mm256_ror256_1x32( a ), \
                       mm256_rol256_3x32( b ), 0x88 )

#endif

static void
c512( sph_shavite_big_context *sc, const void *msg )
{
   const __m128i zero = _mm_setzero_si128();
   __m128i p0, p1, p2, p3, x;
   __m128i k00, k01, k02, k03, k10, k11, k12, k13;
   __m128i *m = (__m128i*)msg;
   __m128i *h = (__m128i*)sc->h;
   int r;

   p0 = h[0];
   p1 = h[1];
   p2 = h[2];
   p3 = h[3];   

   // round

//  working proof of concept   
/*
   __m512i K = m512_const1_128( m[0] );
   __m512i X = _mm512_xor_si512( m512_const1_128( p1 ), K );
   X = _mm512_aesenc_epi128( X, m512_zero );
   k00 = _mm512_castsi512_si128( K );
   x = _mm512_castsi512_si128( X );
*/

   k00 = m[0];
   x = _mm_xor_si128( p1, k00 );
   x = _mm_aesenc_si128( x, zero );

   k01 = m[1];
   x = _mm_xor_si128( x, k01 );
   x = _mm_aesenc_si128( x, zero );
   k02 = m[2];
   x = _mm_xor_si128( x, k02 );
   x = _mm_aesenc_si128( x, zero );
   k03 = m[3];
   x = _mm_xor_si128( x, k03 );
   x = _mm_aesenc_si128( x, zero );

   p0 = _mm_xor_si128( p0, x );

   k10 = m[4];
   x = _mm_xor_si128( p3, k10 );
   x = _mm_aesenc_si128( x, zero );
   k11 = m[5];
   x = _mm_xor_si128( x, k11 );
   x = _mm_aesenc_si128( x, zero );
   k12 = m[6];
   x = _mm_xor_si128( x, k12 );
   x = _mm_aesenc_si128( x, zero );
   k13 = m[7];
   x = _mm_xor_si128( x, k13 );
   x = _mm_aesenc_si128( x, zero );

   p2 = _mm_xor_si128( p2, x );

   for ( r = 0; r < 3; r ++ )
   {
      // round 1, 5, 9
      k00 = mm128_ror_1x32( _mm_aesenc_si128( k00, zero ) );
      k00 = _mm_xor_si128( k00, k13 ); 

      if ( r == 0 )
         k00 = _mm_xor_si128( k00, _mm_set_epi32(
                  ~sc->count3, sc->count2, sc->count1, sc->count0 ) ); 

      x = _mm_xor_si128( p0, k00 );
      x = _mm_aesenc_si128( x, zero );
      k01 = mm128_ror_1x32( _mm_aesenc_si128( k01, zero ) );
      k01 = _mm_xor_si128( k01, k00 );

      if ( r == 1 )
         k01 = _mm_xor_si128( k01, _mm_set_epi32(
                  ~sc->count0, sc->count1, sc->count2, sc->count3 ) );

      x = _mm_xor_si128( x, k01 );
      x = _mm_aesenc_si128( x, zero );
      k02 = mm128_ror_1x32( _mm_aesenc_si128( k02, zero ) );
      k02 = _mm_xor_si128( k02, k01 );
      x = _mm_xor_si128( x, k02 );
      x = _mm_aesenc_si128( x, zero );
      k03 = mm128_ror_1x32( _mm_aesenc_si128( k03, zero ) );
      k03 = _mm_xor_si128( k03, k02 );
      x = _mm_xor_si128( x, k03 );
      x = _mm_aesenc_si128( x, zero );

      p3 = _mm_xor_si128( p3, x );

      k10 = mm128_ror_1x32( _mm_aesenc_si128( k10, zero ) );
      k10 = _mm_xor_si128( k10, k03 );

      x = _mm_xor_si128( p2, k10 );
      x = _mm_aesenc_si128( x, zero );
      k11 = mm128_ror_1x32( _mm_aesenc_si128( k11, zero ) );
      k11 = _mm_xor_si128( k11, k10 );
      x = _mm_xor_si128( x, k11 );
      x = _mm_aesenc_si128( x, zero );
      k12 = mm128_ror_1x32( _mm_aesenc_si128( k12, zero ) );
      k12 = _mm_xor_si128( k12, k11 );
      x = _mm_xor_si128( x, k12 );
      x = _mm_aesenc_si128( x, zero );
      k13 = mm128_ror_1x32( _mm_aesenc_si128( k13, zero ) );
      k13 = _mm_xor_si128( k13, k12 );

      if ( r == 2 )
         k13 = _mm_xor_si128( k13, _mm_set_epi32(
                  ~sc->count1, sc->count0, sc->count3, sc->count2 ) );

      x = _mm_xor_si128( x, k13 );
      x = _mm_aesenc_si128( x, zero );
      p1 = _mm_xor_si128( p1, x );

      // round 2, 6, 10

      k00 = _mm_xor_si128( k00, mm128_ror256hi_1x32( k12, k13 ) );
      x = _mm_xor_si128( p3, k00 );
      x = _mm_aesenc_si128( x, zero );
      k01 = _mm_xor_si128( k01, mm128_ror256hi_1x32( k13, k00 ) );
      x = _mm_xor_si128( x, k01 );
      x = _mm_aesenc_si128( x, zero );
      k02 = _mm_xor_si128( k02, mm128_ror256hi_1x32( k00, k01 ) );
      x = _mm_xor_si128( x, k02 );
      x = _mm_aesenc_si128( x, zero );
      k03 = _mm_xor_si128( k03, mm128_ror256hi_1x32( k01, k02 ) );
      x = _mm_xor_si128( x, k03 );
      x = _mm_aesenc_si128( x, zero );

      p2 = _mm_xor_si128( p2, x );

      k10 = _mm_xor_si128( k10, mm128_ror256hi_1x32( k02, k03 ) );
      x = _mm_xor_si128( p1, k10 );
      x = _mm_aesenc_si128( x, zero );
      k11 = _mm_xor_si128( k11, mm128_ror256hi_1x32( k03, k10 ) );
      x = _mm_xor_si128( x, k11 );
      x = _mm_aesenc_si128( x, zero );
      k12 = _mm_xor_si128( k12, mm128_ror256hi_1x32( k10, k11 ) );
      x = _mm_xor_si128( x, k12 );
      x = _mm_aesenc_si128( x, zero );
      k13 = _mm_xor_si128( k13, mm128_ror256hi_1x32( k11, k12 ) );
      x = _mm_xor_si128( x, k13 );
      x = _mm_aesenc_si128( x, zero );

      p0 = _mm_xor_si128( p0, x );

      // round 3, 7, 11

      k00 = mm128_ror_1x32( _mm_aesenc_si128( k00, zero ) );
      k00 = _mm_xor_si128( k00, k13 );
      x = _mm_xor_si128( p2, k00 );
      x = _mm_aesenc_si128( x, zero );
      k01 = mm128_ror_1x32( _mm_aesenc_si128( k01, zero ) );
      k01 = _mm_xor_si128( k01, k00 );
      x = _mm_xor_si128( x, k01 );
      x = _mm_aesenc_si128( x, zero );
      k02 = mm128_ror_1x32( _mm_aesenc_si128( k02, zero ) );
      k02 = _mm_xor_si128( k02, k01 );
      x = _mm_xor_si128( x, k02 );
      x = _mm_aesenc_si128( x, zero );
      k03 = mm128_ror_1x32( _mm_aesenc_si128( k03, zero ) );
      k03 = _mm_xor_si128( k03, k02 );
      x = _mm_xor_si128( x, k03 );
      x = _mm_aesenc_si128( x, zero );

      p1 = _mm_xor_si128( p1, x );

      k10 = mm128_ror_1x32( _mm_aesenc_si128( k10, zero ) );
      k10 = _mm_xor_si128( k10, k03 );
      x = _mm_xor_si128( p0, k10 );
      x = _mm_aesenc_si128( x, zero );
      k11 = mm128_ror_1x32( _mm_aesenc_si128( k11, zero ) );
      k11 = _mm_xor_si128( k11, k10 );
      x = _mm_xor_si128( x, k11 );
      x = _mm_aesenc_si128( x, zero );
      k12 = mm128_ror_1x32( _mm_aesenc_si128( k12, zero ) );
      k12 = _mm_xor_si128( k12, k11 );
      x = _mm_xor_si128( x, k12 );
      x = _mm_aesenc_si128( x, zero );
      k13 = mm128_ror_1x32( _mm_aesenc_si128( k13, zero ) );
      k13 = _mm_xor_si128( k13, k12 );
      x = _mm_xor_si128( x, k13 );
      x = _mm_aesenc_si128( x, zero );

      p3 = _mm_xor_si128( p3, x );

      // round 4, 8, 12

      k00 = _mm_xor_si128( k00, mm128_ror256hi_1x32( k12, k13 ) );
      x = _mm_xor_si128( p1, k00 );
      x = _mm_aesenc_si128( x, zero );
      k01 = _mm_xor_si128( k01, mm128_ror256hi_1x32( k13, k00 ) );
      x = _mm_xor_si128( x, k01 );
      x = _mm_aesenc_si128( x, zero );
      k02 = _mm_xor_si128( k02, mm128_ror256hi_1x32( k00, k01 ) );
      x = _mm_xor_si128( x, k02 );
      x = _mm_aesenc_si128( x, zero );
      k03 = _mm_xor_si128( k03, mm128_ror256hi_1x32( k01, k02 ) );
      x = _mm_xor_si128( x, k03 );
      x = _mm_aesenc_si128( x, zero );

      p0 = _mm_xor_si128( p0, x );

      k10 = _mm_xor_si128( k10, mm128_ror256hi_1x32( k02, k03 ) );
      x = _mm_xor_si128( p3, k10 );
      x = _mm_aesenc_si128( x, zero );
      k11 = _mm_xor_si128( k11, mm128_ror256hi_1x32( k03, k10 ) );
      x = _mm_xor_si128( x, k11 );
      x = _mm_aesenc_si128( x, zero );
      k12 = _mm_xor_si128( k12, mm128_ror256hi_1x32( k10, k11 ) );
      x = _mm_xor_si128( x, k12 );
      x = _mm_aesenc_si128( x, zero );
      k13 = _mm_xor_si128( k13, mm128_ror256hi_1x32( k11, k12 ) );
      x = _mm_xor_si128( x, k13 );
      x = _mm_aesenc_si128( x, zero );

      p2 = _mm_xor_si128( p2, x );
   }

   // round 13

   k00 = mm128_ror_1x32( _mm_aesenc_si128( k00, zero ) );
   k00 = _mm_xor_si128( k00, k13 );
   x = _mm_xor_si128( p0, k00 );
   x = _mm_aesenc_si128( x, zero );
   k01 = mm128_ror_1x32( _mm_aesenc_si128( k01, zero ) ); 
   k01 = _mm_xor_si128( k01, k00 );
   x = _mm_xor_si128( x, k01 );
   x = _mm_aesenc_si128( x, zero );
   k02 = mm128_ror_1x32( _mm_aesenc_si128( k02, zero ) );
   k02 = _mm_xor_si128( k02, k01 );
   x = _mm_xor_si128( x, k02 );
   x = _mm_aesenc_si128( x, zero );
   k03 = mm128_ror_1x32( _mm_aesenc_si128( k03, zero ) );
   k03 = _mm_xor_si128( k03, k02 );
   x = _mm_xor_si128( x, k03 );
   x = _mm_aesenc_si128( x, zero );

   p3 = _mm_xor_si128( p3, x );

   k10 = mm128_ror_1x32( _mm_aesenc_si128( k10, zero ) );
   k10 = _mm_xor_si128( k10, k03 );
   x = _mm_xor_si128( p2, k10 );
   x = _mm_aesenc_si128( x, zero );
   k11 = mm128_ror_1x32( _mm_aesenc_si128( k11, zero ) );
   k11 = _mm_xor_si128( k11, k10 );
   x = _mm_xor_si128( x, k11 );
   x = _mm_aesenc_si128( x, zero );
   k12 = mm128_ror_1x32( _mm_aesenc_si128( k12, zero ) );
   k12 = _mm_xor_si128( k12, _mm_xor_si128( k11, _mm_set_epi32(
               ~sc->count2, sc->count3, sc->count0, sc->count1 ) ) );
   x = _mm_xor_si128( x, k12 );
   x = _mm_aesenc_si128( x, zero );
   k13 = mm128_ror_1x32( _mm_aesenc_si128( k13, zero ) );
   k13 = _mm_xor_si128( k13, k12 );
   x = _mm_xor_si128( x, k13 );
   x = _mm_aesenc_si128( x, zero );

   p1 = _mm_xor_si128( p1, x );

   h[0] = _mm_xor_si128( h[0], p2 );
   h[1] = _mm_xor_si128( h[1], p3 );
   h[2] = _mm_xor_si128( h[2], p0 );
   h[3] = _mm_xor_si128( h[3], p1 );
}


static void
shavite_big_aesni_init( sph_shavite_big_context *sc, const sph_u32 *iv )
{
	memcpy( sc->h, iv, sizeof sc->h );
	sc->ptr    = 0;
	sc->count0 = 0;
	sc->count1 = 0;
	sc->count2 = 0;
	sc->count3 = 0;
}

static void
shavite_big_aesni_core( sph_shavite_big_context *sc, const void *data,
                        size_t len )
{
	unsigned char *buf;
	size_t ptr;

	buf = sc->buf;
	ptr = sc->ptr;
	while (len > 0) {
		size_t clen;

		clen = (sizeof sc->buf) - ptr;
		if (clen > len)
			clen = len;
		memcpy(buf + ptr, data, clen);
		data = (const unsigned char *)data + clen;
		ptr += clen;
		len -= clen;
		if (ptr == sizeof sc->buf) {
			if ((sc->count0 = SPH_T32(sc->count0 + 1024)) == 0) {
				sc->count1 = SPH_T32(sc->count1 + 1);
				if (sc->count1 == 0) {
					sc->count2 = SPH_T32(sc->count2 + 1);
					if (sc->count2 == 0) {
						sc->count3 = SPH_T32(
							sc->count3 + 1);
					}
				}
			}
			c512(sc, buf);
			ptr = 0;
		}
	}
	sc->ptr = ptr;
}

static void
shavite_big_aesni_close( sph_shavite_big_context *sc, unsigned ub, unsigned n,
                         void *dst, size_t out_size_w32 )
{
	unsigned char *buf;
	size_t ptr, u;
	unsigned z;
	sph_u32 count0, count1, count2, count3;

	buf = sc->buf;
	ptr = sc->ptr;
	count0 = (sc->count0 += SPH_T32(ptr << 3) + n);
	count1 = sc->count1;
	count2 = sc->count2;
	count3 = sc->count3;


	
	z = 0x80 >> n;
	z = ((ub & -z) | z) & 0xFF;
	if (ptr == 0 && n == 0) {
		buf[0] = 0x80;
		memset(buf + 1, 0, 109);
		sc->count0 = sc->count1 = sc->count2 = sc->count3 = 0;
	} else if (ptr < 110) {
		buf[ptr ++] = z;
		memset(buf + ptr, 0, 110 - ptr);
	} else {
		buf[ptr ++] = z;
		memset(buf + ptr, 0, 128 - ptr);
		c512(sc, buf);
		memset(buf, 0, 110);
		sc->count0 = sc->count1 = sc->count2 = sc->count3 = 0;
	}

	sph_enc32le(buf + 110, count0);
	sph_enc32le(buf + 114, count1);
	sph_enc32le(buf + 118, count2);
	sph_enc32le(buf + 122, count3);
	buf[126] = (unsigned char) (out_size_w32 << 5);
	buf[127] = (unsigned char) (out_size_w32 >> 3);
	c512(sc, buf);
	for (u = 0; u < out_size_w32; u ++)
		sph_enc32le((unsigned char *)dst + (u << 2), sc->h[u]);
}

void
sph_shavite512_aesni_init(void *cc)
{
	shavite_big_aesni_init(cc, IV512);
}

void
sph_shavite512_aesni(void *cc, const void *data, size_t len)
{
	shavite_big_aesni_core(cc, data, len);
}

void
sph_shavite512_aesni_close(void *cc, void *dst)
{
	shavite_big_aesni_close(cc, 0, 0, dst, 16);
}

void
sph_shavite512_aesni_addbits_and_close( void *cc, unsigned ub, unsigned n,
                                        void *dst)
{
	shavite_big_aesni_close(cc, ub, n, dst, 16);
}

#ifdef __cplusplus
}
#endif

#endif
