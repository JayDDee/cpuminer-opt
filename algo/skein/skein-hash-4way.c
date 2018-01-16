/* $Id: skein.c 254 2011-06-07 19:38:58Z tp $ */
/*
 * Skein implementation.
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
#include "skein-hash-4way.h"


#ifdef __cplusplus
extern "C"{
#endif

#ifdef _MSC_VER
#pragma warning (disable: 4146)
#endif

/*
 * M9_ ## s ## _ ## i  evaluates to s+i mod 9 (0 <= s <= 18, 0 <= i <= 7).
 */

#define M9_0_0    0
#define M9_0_1    1
#define M9_0_2    2
#define M9_0_3    3
#define M9_0_4    4
#define M9_0_5    5
#define M9_0_6    6
#define M9_0_7    7

#define M9_1_0    1
#define M9_1_1    2
#define M9_1_2    3
#define M9_1_3    4
#define M9_1_4    5
#define M9_1_5    6
#define M9_1_6    7
#define M9_1_7    8

#define M9_2_0    2
#define M9_2_1    3
#define M9_2_2    4
#define M9_2_3    5
#define M9_2_4    6
#define M9_2_5    7
#define M9_2_6    8
#define M9_2_7    0

#define M9_3_0    3
#define M9_3_1    4
#define M9_3_2    5
#define M9_3_3    6
#define M9_3_4    7
#define M9_3_5    8
#define M9_3_6    0
#define M9_3_7    1

#define M9_4_0    4
#define M9_4_1    5
#define M9_4_2    6
#define M9_4_3    7
#define M9_4_4    8
#define M9_4_5    0
#define M9_4_6    1
#define M9_4_7    2

#define M9_5_0    5
#define M9_5_1    6
#define M9_5_2    7
#define M9_5_3    8
#define M9_5_4    0
#define M9_5_5    1
#define M9_5_6    2
#define M9_5_7    3

#define M9_6_0    6
#define M9_6_1    7
#define M9_6_2    8
#define M9_6_3    0
#define M9_6_4    1
#define M9_6_5    2
#define M9_6_6    3
#define M9_6_7    4

#define M9_7_0    7
#define M9_7_1    8
#define M9_7_2    0
#define M9_7_3    1
#define M9_7_4    2
#define M9_7_5    3
#define M9_7_6    4
#define M9_7_7    5

#define M9_8_0    8
#define M9_8_1    0
#define M9_8_2    1
#define M9_8_3    2
#define M9_8_4    3
#define M9_8_5    4
#define M9_8_6    5
#define M9_8_7    6

#define M9_9_0    0
#define M9_9_1    1
#define M9_9_2    2
#define M9_9_3    3
#define M9_9_4    4
#define M9_9_5    5
#define M9_9_6    6
#define M9_9_7    7

#define M9_10_0   1
#define M9_10_1   2
#define M9_10_2   3
#define M9_10_3   4
#define M9_10_4   5
#define M9_10_5   6
#define M9_10_6   7
#define M9_10_7   8

#define M9_11_0   2
#define M9_11_1   3
#define M9_11_2   4
#define M9_11_3   5
#define M9_11_4   6
#define M9_11_5   7
#define M9_11_6   8
#define M9_11_7   0

#define M9_12_0   3
#define M9_12_1   4
#define M9_12_2   5
#define M9_12_3   6
#define M9_12_4   7
#define M9_12_5   8
#define M9_12_6   0
#define M9_12_7   1

#define M9_13_0   4
#define M9_13_1   5
#define M9_13_2   6
#define M9_13_3   7
#define M9_13_4   8
#define M9_13_5   0
#define M9_13_6   1
#define M9_13_7   2

#define M9_14_0   5
#define M9_14_1   6
#define M9_14_2   7
#define M9_14_3   8
#define M9_14_4   0
#define M9_14_5   1
#define M9_14_6   2
#define M9_14_7   3

#define M9_15_0   6
#define M9_15_1   7
#define M9_15_2   8
#define M9_15_3   0
#define M9_15_4   1
#define M9_15_5   2
#define M9_15_6   3
#define M9_15_7   4

#define M9_16_0   7
#define M9_16_1   8
#define M9_16_2   0
#define M9_16_3   1
#define M9_16_4   2
#define M9_16_5   3
#define M9_16_6   4
#define M9_16_7   5

#define M9_17_0   8
#define M9_17_1   0
#define M9_17_2   1
#define M9_17_3   2
#define M9_17_4   3
#define M9_17_5   4
#define M9_17_6   5
#define M9_17_7   6

#define M9_18_0   0
#define M9_18_1   1
#define M9_18_2   2
#define M9_18_3   3
#define M9_18_4   4
#define M9_18_5   5
#define M9_18_6   6
#define M9_18_7   7

/*
 * M3_ ## s ## _ ## i  evaluates to s+i mod 3 (0 <= s <= 18, 0 <= i <= 1).
 */

#define M3_0_0    0
#define M3_0_1    1
#define M3_1_0    1
#define M3_1_1    2
#define M3_2_0    2
#define M3_2_1    0
#define M3_3_0    0
#define M3_3_1    1
#define M3_4_0    1
#define M3_4_1    2
#define M3_5_0    2
#define M3_5_1    0
#define M3_6_0    0
#define M3_6_1    1
#define M3_7_0    1
#define M3_7_1    2
#define M3_8_0    2
#define M3_8_1    0
#define M3_9_0    0
#define M3_9_1    1
#define M3_10_0   1
#define M3_10_1   2
#define M3_11_0   2
#define M3_11_1   0
#define M3_12_0   0
#define M3_12_1   1
#define M3_13_0   1
#define M3_13_1   2
#define M3_14_0   2
#define M3_14_1   0
#define M3_15_0   0
#define M3_15_1   1
#define M3_16_0   1
#define M3_16_1   2
#define M3_17_0   2
#define M3_17_1   0
#define M3_18_0   0
#define M3_18_1   1

#define XCAT(x, y)     XCAT_(x, y)
#define XCAT_(x, y)    x ## y


#define SKBI(k, s, i)   XCAT(k, XCAT(XCAT(XCAT(M9_, s), _), i))
#define SKBT(t, s, v)   XCAT(t, XCAT(XCAT(XCAT(M3_, s), _), v))

// AVX2 all scalar vars are now vectors representing 4 nonces in parallel

#define TFBIG_KINIT_4WAY( k0, k1, k2, k3, k4, k5, k6, k7, k8, t0, t1, t2 ) \
do { \
  k8 = _mm256_xor_si256( _mm256_xor_si256( \
                            _mm256_xor_si256( _mm256_xor_si256( k0, k1 ), \
                                              _mm256_xor_si256( k2, k3 ) ), \
                            _mm256_xor_si256( _mm256_xor_si256( k4, k5 ), \
                                              _mm256_xor_si256( k6, k7 ) ) ), \
                         _mm256_set_epi64x( SPH_C64(0x1BD11BDAA9FC1A22), \
                                            SPH_C64(0x1BD11BDAA9FC1A22), \
                                            SPH_C64(0x1BD11BDAA9FC1A22), \
                                            SPH_C64(0x1BD11BDAA9FC1A22) ) ); \
  t2 = t0 ^ t1; \
} while (0)

#define TFBIG_ADDKEY_4WAY(w0, w1, w2, w3, w4, w5, w6, w7, k, t, s) \
do { \
  w0 = _mm256_add_epi64( w0, SKBI(k,s,0) ); \
  w1 = _mm256_add_epi64( w1, SKBI(k,s,1) ); \
  w2 = _mm256_add_epi64( w2, SKBI(k,s,2) ); \
  w3 = _mm256_add_epi64( w3, SKBI(k,s,3) ); \
  w4 = _mm256_add_epi64( w4, SKBI(k,s,4) ); \
  w5 = _mm256_add_epi64( w5, _mm256_add_epi64( SKBI(k,s,5), \
                           _mm256_set_epi64x( SKBT(t,s,0), SKBT(t,s,0), \
                                              SKBT(t,s,0), SKBT(t,s,0) ) ) ); \
  w6 = _mm256_add_epi64( w6, _mm256_add_epi64( SKBI(k,s,6), \
                           _mm256_set_epi64x( SKBT(t,s,1), SKBT(t,s,1), \
                                              SKBT(t,s,1), SKBT(t,s,1) ) ) ); \
  w7 = _mm256_add_epi64( w7, _mm256_add_epi64( SKBI(k,s,7), \
                                      _mm256_set_epi64x( s, s, s, s ) ) ); \
} while (0)


#define TFBIG_MIX_4WAY(x0, x1, rc) \
do { \
     x0 = _mm256_add_epi64( x0, x1 ); \
     x1 = _mm256_xor_si256( mm256_rotl_64( x1, rc ), x0 ); \
} while (0)
 

// typeless
#define TFBIG_MIX8(w0, w1, w2, w3, w4, w5, w6, w7, rc0, rc1, rc2, rc3)  do { \
		TFBIG_MIX_4WAY(w0, w1, rc0); \
		TFBIG_MIX_4WAY(w2, w3, rc1); \
		TFBIG_MIX_4WAY(w4, w5, rc2); \
		TFBIG_MIX_4WAY(w6, w7, rc3); \
	} while (0)


#define TFBIG_4e(s)   do { \
		TFBIG_ADDKEY_4WAY(p0, p1, p2, p3, p4, p5, p6, p7, h, t, s); \
		TFBIG_MIX8(p0, p1, p2, p3, p4, p5, p6, p7, 46, 36, 19, 37); \
		TFBIG_MIX8(p2, p1, p4, p7, p6, p5, p0, p3, 33, 27, 14, 42); \
		TFBIG_MIX8(p4, p1, p6, p3, p0, p5, p2, p7, 17, 49, 36, 39); \
		TFBIG_MIX8(p6, p1, p0, p7, p2, p5, p4, p3, 44,  9, 54, 56); \
	} while (0)

#define TFBIG_4o(s)   do { \
		TFBIG_ADDKEY_4WAY(p0, p1, p2, p3, p4, p5, p6, p7, h, t, s); \
		TFBIG_MIX8(p0, p1, p2, p3, p4, p5, p6, p7, 39, 30, 34, 24); \
		TFBIG_MIX8(p2, p1, p4, p7, p6, p5, p0, p3, 13, 50, 10, 17); \
		TFBIG_MIX8(p4, p1, p6, p3, p0, p5, p2, p7, 25, 29, 39, 43); \
		TFBIG_MIX8(p6, p1, p0, p7, p2, p5, p4, p3,  8, 35, 56, 22); \
	} while (0)


// scale buf offset by 4
#define UBI_BIG_4WAY(etype, extra) \
do { \
  sph_u64 t0, t1, t2; \
  __m256i h8; \
  __m256i m0 =  buf[0]; \
  __m256i m1 =  buf[1]; \
  __m256i m2 =  buf[2]; \
  __m256i m3 =  buf[3]; \
  __m256i m4 =  buf[4]; \
  __m256i m5 =  buf[5]; \
  __m256i m6 =  buf[6]; \
  __m256i m7 =  buf[7]; \
\
  __m256i p0 = m0; \
  __m256i p1 = m1; \
  __m256i p2 = m2; \
  __m256i p3 = m3; \
  __m256i p4 = m4; \
  __m256i p5 = m5; \
  __m256i p6 = m6; \
  __m256i p7 = m7; \
  t0 = SPH_T64(bcount << 6) + (sph_u64)(extra); \
  t1 = (bcount >> 58) + ((sph_u64)(etype) << 55); \
  TFBIG_KINIT_4WAY(h0, h1, h2, h3, h4, h5, h6, h7, h8, t0, t1, t2); \
  TFBIG_4e(0); \
  TFBIG_4o(1); \
  TFBIG_4e(2); \
  TFBIG_4o(3); \
  TFBIG_4e(4); \
  TFBIG_4o(5); \
  TFBIG_4e(6); \
  TFBIG_4o(7); \
  TFBIG_4e(8); \
  TFBIG_4o(9); \
  TFBIG_4e(10); \
  TFBIG_4o(11); \
  TFBIG_4e(12); \
  TFBIG_4o(13); \
  TFBIG_4e(14); \
  TFBIG_4o(15); \
  TFBIG_4e(16); \
  TFBIG_4o(17); \
  TFBIG_ADDKEY_4WAY(p0, p1, p2, p3, p4, p5, p6, p7, h, t, 18); \
  h0 = _mm256_xor_si256( m0, p0 );\
  h1 = _mm256_xor_si256( m1, p1 );\
  h2 = _mm256_xor_si256( m2, p2 );\
  h3 = _mm256_xor_si256( m3, p3 );\
  h4 = _mm256_xor_si256( m4, p4 );\
  h5 = _mm256_xor_si256( m5, p5 );\
  h6 = _mm256_xor_si256( m6, p6 );\
  h7 = _mm256_xor_si256( m7, p7 );\
} while (0)


#define DECL_STATE_BIG_4WAY \
  __m256i h0, h1, h2, h3, h4, h5, h6, h7; \
  sph_u64 bcount;

#define READ_STATE_BIG(sc)   do { \
		h0 = (sc)->h0; \
		h1 = (sc)->h1; \
		h2 = (sc)->h2; \
		h3 = (sc)->h3; \
		h4 = (sc)->h4; \
		h5 = (sc)->h5; \
		h6 = (sc)->h6; \
		h7 = (sc)->h7; \
		bcount = sc->bcount; \
	} while (0)

#define WRITE_STATE_BIG(sc)   do { \
		(sc)->h0 = h0; \
		(sc)->h1 = h1; \
		(sc)->h2 = h2; \
		(sc)->h3 = h3; \
		(sc)->h4 = h4; \
		(sc)->h5 = h5; \
		(sc)->h6 = h6; \
		(sc)->h7 = h7; \
		sc->bcount = bcount; \
	} while (0)


static void
skein_big_init_4way( skein512_4way_context *sc, const sph_u64 *iv )
{
        sc->h0 = _mm256_set_epi64x( iv[0], iv[0],iv[0],iv[0] );
        sc->h1 = _mm256_set_epi64x( iv[1], iv[1],iv[1],iv[1] );
        sc->h2 = _mm256_set_epi64x( iv[2], iv[2],iv[2],iv[2] );
        sc->h3 = _mm256_set_epi64x( iv[3], iv[3],iv[3],iv[3] );
        sc->h4 = _mm256_set_epi64x( iv[4], iv[4],iv[4],iv[4] );
        sc->h5 = _mm256_set_epi64x( iv[5], iv[5],iv[5],iv[5] );
        sc->h6 = _mm256_set_epi64x( iv[6], iv[6],iv[6],iv[6] );
        sc->h7 = _mm256_set_epi64x( iv[7], iv[7],iv[7],iv[7] );
        sc->bcount = 0;
        sc->ptr = 0;
}

static void
skein_big_core_4way( skein512_4way_context *sc, const void *data,
                     size_t len )
{
   __m256i *vdata = (__m256i*)data;
   __m256i *buf;
   size_t ptr;
   unsigned first;
   DECL_STATE_BIG_4WAY

   buf = sc->buf;
   ptr = sc->ptr;
   const int buf_size = 64;   // 64 * _m256i

   if ( len <= buf_size - ptr )
   {
       memcpy_256( buf + (ptr>>3), vdata, len>>3 );
       sc->ptr = ptr + len;
       return;
   }

   READ_STATE_BIG( sc );
   first = ( bcount == 0 ) << 7;
   do {
       size_t clen;

       if ( ptr == buf_size )
       {
            bcount ++;
            UBI_BIG_4WAY( 96 + first, 0 );
            first = 0;
            ptr = 0;
       }
       clen = buf_size - ptr;
       if ( clen > len )
            clen = len;
       memcpy_256( buf + (ptr>>3), vdata, clen>>3 );
       ptr += clen;
       vdata += (clen>>3);
       len -= clen;
   } while ( len > 0 );
   WRITE_STATE_BIG( sc );
   sc->ptr = ptr;
}

static void
skein_big_close_4way( skein512_4way_context *sc, unsigned ub, unsigned n,
                      void *dst, size_t out_len )
{
	__m256i *buf;
	size_t ptr;
	unsigned et;
	DECL_STATE_BIG_4WAY

	buf = sc->buf;
	ptr = sc->ptr;
        const int buf_size = 64;

	/*
	 * At that point, if ptr == 0, then the message was empty;
	 * otherwise, there is between 1 and 64 bytes (inclusive) which
	 * are yet to be processed. Either way, we complete the buffer
	 * to a full block with zeros (the Skein specification mandates
	 * that an empty message is padded so that there is at least
	 * one block to process).
	 *
	 * Once this block has been processed, we do it again, with
	 * a block full of zeros, for the output (that block contains
	 * the encoding of "0", over 8 bytes, then padded with zeros).
	 */

	READ_STATE_BIG(sc);

        memset_zero_256( buf + (ptr>>3), (buf_size - ptr) >> 3 );
	et = 352 + ((bcount == 0) << 7);
        UBI_BIG_4WAY( et, ptr );

        memset_zero_256( buf, buf_size >> 3 );
        bcount = 0;
        UBI_BIG_4WAY( 510, 8 );

        buf[0] = h0;
        buf[1] = h1;
        buf[2] = h2;
        buf[3] = h3;
        buf[4] = h4;
        buf[5] = h5;
        buf[6] = h6;
        buf[7] = h7;

        memcpy_256( dst, buf, out_len >> 3 );
}

static const sph_u64 IV256[] = {
	SPH_C64(0xCCD044A12FDB3E13), SPH_C64(0xE83590301A79A9EB),
	SPH_C64(0x55AEA0614F816E6F), SPH_C64(0x2A2767A4AE9B94DB),
	SPH_C64(0xEC06025E74DD7683), SPH_C64(0xE7A436CDC4746251),
	SPH_C64(0xC36FBAF9393AD185), SPH_C64(0x3EEDBA1833EDFC13)
};

static const sph_u64 IV512[] = {
	SPH_C64(0x4903ADFF749C51CE), SPH_C64(0x0D95DE399746DF03),
	SPH_C64(0x8FD1934127C79BCE), SPH_C64(0x9A255629FF352CB1),
	SPH_C64(0x5DB62599DF6CA7B0), SPH_C64(0xEABE394CA9D5C3F4),
	SPH_C64(0x991112C71A75B523), SPH_C64(0xAE18A40B660FCC33)
};


void
skein256_4way_init(void *cc)
{
	skein_big_init_4way(cc, IV256);
}

void
skein256_4way(void *cc, const void *data, size_t len)
{
	skein_big_core_4way(cc, data, len);
}

void
skein256_4way_close(void *cc, void *dst)
{
        skein_big_close_4way(cc, 0, 0, dst, 32);
}

void
skein512_4way_init(void *cc)
{
	skein_big_init_4way(cc, IV512);
}

void
skein512_4way(void *cc, const void *data, size_t len)
{
	skein_big_core_4way(cc, data, len);
}

void
skein512_4way_close(void *cc, void *dst)
{
        skein_big_close_4way(cc, 0, 0, dst, 64);
}

#ifdef __cplusplus
}
#endif

#endif
