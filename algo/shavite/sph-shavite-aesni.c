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

#if ( defined(__AES__) && defined(__SSSE3__) ) || ( defined(__ARM_NEON) && defined(__ARM_FEATURE_AES) )

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

static const sph_u32 IV512[] =
{
	0x72FCCDD8, 0x79CA4727, 0x128A077B, 0x40D55AEC,
	0xD1901A06, 0x430AE307, 0xB29F5CD1, 0xDF07FBFC,
	0x8E45D73D, 0x681AB538, 0xBDE86578, 0xDD577E47,
	0xE275EADE, 0x502D9FCD, 0xB9357178, 0x022A4B9A
};

static void
c512( sph_shavite_big_context *sc, const void *msg )
{
   v128_t p0, p1, p2, p3, x;
   v128_t k00, k01, k02, k03, k10, k11, k12, k13;
   v128_t *m = (v128_t*)msg;
   v128_t *h = (v128_t*)sc->h;
   int r;

   p0 = h[0];
   p1 = h[1];
   p2 = h[2];
   p3 = h[3];   

   k00 = m[0];
   k01 = m[1];
   k02 = m[2];
   k03 = m[3];
   k10 = m[4];
   k11 = m[5];
   k12 = m[6];
   k13 = m[7];

   // round 0
   
   x = v128_xoraesenc( p1, k00 );
   x = v128_xoraesenc( x, k01 );
   x = v128_xoraesenc( x, k02 );
   p0 = v128_xoraesencxor( x, k03, p0 );

   x = v128_xoraesenc( p3, k10 );
   x = v128_xoraesenc( x, k11 );
   x = v128_xoraesenc( x, k12 );
   p2 = v128_xoraesencxor( x, k13, p2 );

   for ( r = 0; r < 3; r ++ )
   {
      // round 1, 5, 9
      k00 = v128_shuflr32( v128_aesenc_nokey( k00 ) );
      k00 = v128_xor( k00, k13 ); 

      if ( r == 0 )
         k00 = v128_xor( k00, v128_set32(
                  ~sc->count3, sc->count2, sc->count1, sc->count0 ) ); 
      x = v128_xoraesenc( p0, k00 );

      k01 = v128_shuflr32( v128_aesenc_nokey( k01 ) );
      k01 = v128_xor( k01, k00 );

      if ( r == 1 )
         k01 = v128_xor( k01, v128_set32(
                  ~sc->count0, sc->count1, sc->count2, sc->count3 ) );
      x = v128_xoraesenc( x, k01 );

      k02 = v128_shuflr32( v128_aesenc_nokey( k02 ) );
      k02 = v128_xor( k02, k01 );
      x = v128_xoraesenc( x, k02 );

      k03 = v128_shuflr32( v128_aesenc_nokey( k03 ) );
      k03 = v128_xor( k03, k02 );
      p3 = v128_xoraesencxor( x, k03, p3 );

      k10 = v128_shuflr32( v128_aesenc_nokey( k10 ) );
      k10 = v128_xor( k10, k03 );
      x = v128_xoraesenc( p2, k10 );

      k11 = v128_shuflr32( v128_aesenc_nokey( k11 ) );
      k11 = v128_xor( k11, k10 );
      x = v128_xoraesenc( x, k11 );

      k12 = v128_shuflr32( v128_aesenc_nokey( k12 ) );
      k12 = v128_xor( k12, k11 );
      x = v128_xoraesenc( x, k12 );

      k13 = v128_shuflr32( v128_aesenc_nokey( k13 ) );
      k13 = v128_xor( k13, k12 );

      if ( r == 2 )
         k13 = v128_xor( k13, v128_set32(
                  ~sc->count1, sc->count0, sc->count3, sc->count2 ) );
      p1 = v128_xoraesencxor( x, k13, p1 );

      // round 2, 6, 10

      k00 = v128_xor( k00, v128_alignr8( k13, k12, 4 ) );
      x = v128_xoraesenc( p3, k00 );

      k01 = v128_xor( k01, v128_alignr8( k00, k13, 4 ) );
      x = v128_xoraesenc( x, k01 );

      k02 = v128_xor( k02, v128_alignr8( k01, k00, 4 ) );
      x = v128_xoraesenc( x, k02 );

      k03 = v128_xor( k03, v128_alignr8( k02, k01, 4 ) );
      p2 = v128_xoraesencxor( x, k03, p2 );

      k10 = v128_xor( k10, v128_alignr8( k03, k02, 4 ) );
      x = v128_xoraesenc( p1, k10 );

      k11 = v128_xor( k11, v128_alignr8( k10, k03, 4 ) );
      x = v128_xoraesenc( x, k11 );

      k12 = v128_xor( k12, v128_alignr8( k11, k10, 4 ) );
      x = v128_xoraesenc( x, k12 );

      k13 = v128_xor( k13, v128_alignr8( k12, k11, 4 ) );
      p0 = v128_xoraesencxor( x, k13, p0 );

      // round 3, 7, 11

      k00 = v128_shuflr32( v128_aesenc_nokey( k00 ) );
      k00 = v128_xor( k00, k13 );
      x = v128_xoraesenc( p2, k00 );

      k01 = v128_shuflr32( v128_aesenc_nokey( k01 ) );
      k01 = v128_xor( k01, k00 );
      x = v128_xoraesenc( x, k01 );

      k02 = v128_shuflr32( v128_aesenc_nokey( k02 ) );
      k02 = v128_xor( k02, k01 );
      x = v128_xoraesenc( x, k02 );

      k03 = v128_shuflr32( v128_aesenc_nokey( k03 ) );
      k03 = v128_xor( k03, k02 );
      p1 = v128_xoraesencxor( x, k03, p1 );

      k10 = v128_shuflr32( v128_aesenc_nokey( k10 ) );
      k10 = v128_xor( k10, k03 );
      x = v128_xoraesenc( p0, k10 );

      k11 = v128_shuflr32( v128_aesenc_nokey( k11 ) );
      k11 = v128_xor( k11, k10 );
      x = v128_xoraesenc( x, k11 );

      k12 = v128_shuflr32( v128_aesenc_nokey( k12 ) );
      k12 = v128_xor( k12, k11 );
      x = v128_xoraesenc( x, k12 );

      k13 = v128_shuflr32( v128_aesenc_nokey( k13 ) );
      k13 = v128_xor( k13, k12 );
      p3 = v128_xoraesencxor( x, k13, p3 );

      // round 4, 8, 12

      k00 = v128_xor( k00, v128_alignr8( k13, k12, 4 ) );
      x = v128_xoraesenc( p1, k00 );

      k01 = v128_xor( k01, v128_alignr8( k00, k13, 4 ) );
      x = v128_xoraesenc( x, k01 );

      k02 = v128_xor( k02, v128_alignr8( k01, k00, 4 ) );
      x = v128_xoraesenc( x, k02 );

      k03 = v128_xor( k03, v128_alignr8( k02, k01, 4 ) );
      p0 = v128_xoraesencxor( x, k03, p0 );

      k10 = v128_xor( k10, v128_alignr8( k03, k02, 4 ) );
      x = v128_xoraesenc( p3, k10 );

      k11 = v128_xor( k11, v128_alignr8( k10, k03, 4 ) );
      x = v128_xoraesenc( x, k11 );

      k12 = v128_xor( k12, v128_alignr8( k11, k10, 4 ) );
      x = v128_xoraesenc( x, k12 );

      k13 = v128_xor( k13, v128_alignr8( k12, k11, 4 ) );
      p2 = v128_xoraesencxor( x, k13, p2 );
   }

   // round 13

   k00 = v128_shuflr32( v128_aesenc_nokey( k00 ) );
   k00 = v128_xor( k00, k13 );
   x = v128_xoraesenc( p0, k00 );

   k01 = v128_shuflr32( v128_aesenc_nokey( k01 ) ); 
   k01 = v128_xor( k01, k00 );
   x = v128_xoraesenc( x, k01 );

   k02 = v128_shuflr32( v128_aesenc_nokey( k02 ) );
   k02 = v128_xor( k02, k01 );
   x = v128_xoraesenc( x, k02 );

   k03 = v128_shuflr32( v128_aesenc_nokey( k03 ) );
   k03 = v128_xor( k03, k02 );
   p3 = v128_xoraesencxor( x, k03, p3 );

   k10 = v128_shuflr32( v128_aesenc_nokey( k10 ) );
   k10 = v128_xor( k10, k03 );
   x = v128_xoraesenc( p2, k10 );

   k11 = v128_shuflr32( v128_aesenc_nokey( k11 ) );
   k11 = v128_xor( k11, k10 );
   x = v128_xoraesenc( x, k11 );

   k12 = v128_shuflr32( v128_aesenc_nokey( k12 ) );
   k12 = v128_xor( k12, v128_xor( k11, v128_set32(
               ~sc->count2, sc->count3, sc->count0, sc->count1 ) ) );
   x = v128_xoraesenc( x, k12 );

   k13 = v128_shuflr32( v128_aesenc_nokey( k13 ) );
   k13 = v128_xor( k13, k12 );
   p1 = v128_xoraesencxor( x, k13, p1 );

   h[0] = v128_xor( h[0], p2 );
   h[1] = v128_xor( h[1], p3 );
   h[2] = v128_xor( h[2], p0 );
   h[3] = v128_xor( h[3], p1 );
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
