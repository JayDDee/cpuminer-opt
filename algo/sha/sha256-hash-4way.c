/* $Id: sha2big.c 216 2010-06-08 09:46:57Z tp $ */
/*
 * SHA-384 / SHA-512 implementation.
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

#if defined(__SSE2__)

#include <stddef.h>
#include <string.h>
#include "sha-hash-4way.h"

// SHA-256 32 bit

/*
static const sph_u32 H256[8] = {
        SPH_C32(0x6A09E667), SPH_C32(0xBB67AE85),
        SPH_C32(0x3C6EF372), SPH_C32(0xA54FF53A),
        SPH_C32(0x510E527F), SPH_C32(0x9B05688C),
        SPH_C32(0x1F83D9AB), SPH_C32(0x5BE0CD19)
};
*/

static const sph_u32 K256[64] = {
        SPH_C32(0x428A2F98), SPH_C32(0x71374491),
        SPH_C32(0xB5C0FBCF), SPH_C32(0xE9B5DBA5),
        SPH_C32(0x3956C25B), SPH_C32(0x59F111F1),
        SPH_C32(0x923F82A4), SPH_C32(0xAB1C5ED5),
        SPH_C32(0xD807AA98), SPH_C32(0x12835B01),
        SPH_C32(0x243185BE), SPH_C32(0x550C7DC3),
        SPH_C32(0x72BE5D74), SPH_C32(0x80DEB1FE),
        SPH_C32(0x9BDC06A7), SPH_C32(0xC19BF174),
        SPH_C32(0xE49B69C1), SPH_C32(0xEFBE4786),
        SPH_C32(0x0FC19DC6), SPH_C32(0x240CA1CC),
        SPH_C32(0x2DE92C6F), SPH_C32(0x4A7484AA),
        SPH_C32(0x5CB0A9DC), SPH_C32(0x76F988DA),
        SPH_C32(0x983E5152), SPH_C32(0xA831C66D),
        SPH_C32(0xB00327C8), SPH_C32(0xBF597FC7),
        SPH_C32(0xC6E00BF3), SPH_C32(0xD5A79147),
        SPH_C32(0x06CA6351), SPH_C32(0x14292967),
        SPH_C32(0x27B70A85), SPH_C32(0x2E1B2138),
        SPH_C32(0x4D2C6DFC), SPH_C32(0x53380D13),
        SPH_C32(0x650A7354), SPH_C32(0x766A0ABB),
        SPH_C32(0x81C2C92E), SPH_C32(0x92722C85),
        SPH_C32(0xA2BFE8A1), SPH_C32(0xA81A664B),
        SPH_C32(0xC24B8B70), SPH_C32(0xC76C51A3),
        SPH_C32(0xD192E819), SPH_C32(0xD6990624),
        SPH_C32(0xF40E3585), SPH_C32(0x106AA070),
        SPH_C32(0x19A4C116), SPH_C32(0x1E376C08),
        SPH_C32(0x2748774C), SPH_C32(0x34B0BCB5),
        SPH_C32(0x391C0CB3), SPH_C32(0x4ED8AA4A),
        SPH_C32(0x5B9CCA4F), SPH_C32(0x682E6FF3),
        SPH_C32(0x748F82EE), SPH_C32(0x78A5636F),
        SPH_C32(0x84C87814), SPH_C32(0x8CC70208),
        SPH_C32(0x90BEFFFA), SPH_C32(0xA4506CEB),
        SPH_C32(0xBEF9A3F7), SPH_C32(0xC67178F2)
};

// SHA-256 4 way

#define SHA2s_MEXP( a, b, c, d ) \
  mm128_add4_32( SSG2_1( W[a] ), W[b], SSG2_0( W[c] ), W[d] );

#define CHs(X, Y, Z) \
   _mm_xor_si128( _mm_and_si128( _mm_xor_si128( Y, Z ), X ), Z ) 

#define MAJs(X, Y, Z) \
   _mm_or_si128( _mm_and_si128( X, Y ), \
                    _mm_and_si128( _mm_or_si128( X, Y ), Z ) )

#define BSG2_0(x) \
   _mm_xor_si128( _mm_xor_si128( \
        mm128_ror_32(x,  2), mm128_ror_32(x, 13) ), mm128_ror_32( x, 22) )

#define BSG2_1(x) \
   _mm_xor_si128( _mm_xor_si128( \
        mm128_ror_32(x,  6), mm128_ror_32(x, 11) ), mm128_ror_32( x, 25) )

#define SSG2_0(x) \
   _mm_xor_si128( _mm_xor_si128( \
        mm128_ror_32(x,  7), mm128_ror_32(x, 18) ), _mm_srli_epi32(x, 3) ) 

#define SSG2_1(x) \
   _mm_xor_si128( _mm_xor_si128( \
        mm128_ror_32(x, 17), mm128_ror_32(x, 19) ), _mm_srli_epi32(x, 10) )

#define SHA2s_4WAY_STEP(A, B, C, D, E, F, G, H, i, j) \
do { \
  __m128i T1, T2; \
  __m128i K = _mm_set1_epi32( K256[( (j)+(i) )] ); \
  T1 = _mm_add_epi32( H, mm128_add4_32( BSG2_1(E), CHs(E, F, G), \
                                        K, W[i] ) ); \
  T2 = _mm_add_epi32( BSG2_0(A), MAJs(A, B, C) ); \
  D  = _mm_add_epi32( D,  T1 ); \
  H  = _mm_add_epi32( T1, T2 ); \
} while (0)

static void
sha256_4way_round( sha256_4way_context *ctx, __m128i *in, __m128i r[8] )
{
   register  __m128i A, B, C, D, E, F, G, H;
   __m128i W[16];

   mm128_block_bswap_32( W, in );
   mm128_block_bswap_32( W+8, in+8 );

   if ( ctx->initialized )
   {
      A = r[0];
      B = r[1];
      C = r[2];
      D = r[3];
      E = r[4];
      F = r[5];
      G = r[6];
      H = r[7];
   }
   else
   {
      A = m128_const1_64( 0x6A09E6676A09E667 );
      B = m128_const1_64( 0xBB67AE85BB67AE85 );
      C = m128_const1_64( 0x3C6EF3723C6EF372 );
      D = m128_const1_64( 0xA54FF53AA54FF53A );
      E = m128_const1_64( 0x510E527F510E527F );
      F = m128_const1_64( 0x9B05688C9B05688C );
      G = m128_const1_64( 0x1F83D9AB1F83D9AB );
      H = m128_const1_64( 0x5BE0CD195BE0CD19 );
   }

   SHA2s_4WAY_STEP( A, B, C, D, E, F, G, H,  0, 0 );
   SHA2s_4WAY_STEP( H, A, B, C, D, E, F, G,  1, 0 );
   SHA2s_4WAY_STEP( G, H, A, B, C, D, E, F,  2, 0 );
   SHA2s_4WAY_STEP( F, G, H, A, B, C, D, E,  3, 0 );
   SHA2s_4WAY_STEP( E, F, G, H, A, B, C, D,  4, 0 );
   SHA2s_4WAY_STEP( D, E, F, G, H, A, B, C,  5, 0 );
   SHA2s_4WAY_STEP( C, D, E, F, G, H, A, B,  6, 0 );
   SHA2s_4WAY_STEP( B, C, D, E, F, G, H, A,  7, 0 );
   SHA2s_4WAY_STEP( A, B, C, D, E, F, G, H,  8, 0 );
   SHA2s_4WAY_STEP( H, A, B, C, D, E, F, G,  9, 0 );
   SHA2s_4WAY_STEP( G, H, A, B, C, D, E, F, 10, 0 );
   SHA2s_4WAY_STEP( F, G, H, A, B, C, D, E, 11, 0 );
   SHA2s_4WAY_STEP( E, F, G, H, A, B, C, D, 12, 0 );
   SHA2s_4WAY_STEP( D, E, F, G, H, A, B, C, 13, 0 );
   SHA2s_4WAY_STEP( C, D, E, F, G, H, A, B, 14, 0 );
   SHA2s_4WAY_STEP( B, C, D, E, F, G, H, A, 15, 0 );

   for ( int j = 16; j < 64; j += 16 )
   {
      W[ 0] = SHA2s_MEXP( 14,  9,  1,  0 );
      W[ 1] = SHA2s_MEXP( 15, 10,  2,  1 );
      W[ 2] = SHA2s_MEXP(  0, 11,  3,  2 );
      W[ 3] = SHA2s_MEXP(  1, 12,  4,  3 );
      W[ 4] = SHA2s_MEXP(  2, 13,  5,  4 );
      W[ 5] = SHA2s_MEXP(  3, 14,  6,  5 );
      W[ 6] = SHA2s_MEXP(  4, 15,  7,  6 );
      W[ 7] = SHA2s_MEXP(  5,  0,  8,  7 );
      W[ 8] = SHA2s_MEXP(  6,  1,  9,  8 );
      W[ 9] = SHA2s_MEXP(  7,  2, 10,  9 );
      W[10] = SHA2s_MEXP(  8,  3, 11, 10 );
      W[11] = SHA2s_MEXP(  9,  4, 12, 11 );
      W[12] = SHA2s_MEXP( 10,  5, 13, 12 );
      W[13] = SHA2s_MEXP( 11,  6, 14, 13 );
      W[14] = SHA2s_MEXP( 12,  7, 15, 14 );
      W[15] = SHA2s_MEXP( 13,  8,  0, 15 );

      SHA2s_4WAY_STEP( A, B, C, D, E, F, G, H,  0, j );
      SHA2s_4WAY_STEP( H, A, B, C, D, E, F, G,  1, j );
      SHA2s_4WAY_STEP( G, H, A, B, C, D, E, F,  2, j );
      SHA2s_4WAY_STEP( F, G, H, A, B, C, D, E,  3, j );
      SHA2s_4WAY_STEP( E, F, G, H, A, B, C, D,  4, j );
      SHA2s_4WAY_STEP( D, E, F, G, H, A, B, C,  5, j );
      SHA2s_4WAY_STEP( C, D, E, F, G, H, A, B,  6, j );
      SHA2s_4WAY_STEP( B, C, D, E, F, G, H, A,  7, j );
      SHA2s_4WAY_STEP( A, B, C, D, E, F, G, H,  8, j );
      SHA2s_4WAY_STEP( H, A, B, C, D, E, F, G,  9, j );
      SHA2s_4WAY_STEP( G, H, A, B, C, D, E, F, 10, j );
      SHA2s_4WAY_STEP( F, G, H, A, B, C, D, E, 11, j );
      SHA2s_4WAY_STEP( E, F, G, H, A, B, C, D, 12, j );
      SHA2s_4WAY_STEP( D, E, F, G, H, A, B, C, 13, j );
      SHA2s_4WAY_STEP( C, D, E, F, G, H, A, B, 14, j );
      SHA2s_4WAY_STEP( B, C, D, E, F, G, H, A, 15, j );
   }

   if ( ctx->initialized )
   {
      r[0] = _mm_add_epi32( r[0], A );
      r[1] = _mm_add_epi32( r[1], B );
      r[2] = _mm_add_epi32( r[2], C );
      r[3] = _mm_add_epi32( r[3], D );
      r[4] = _mm_add_epi32( r[4], E );
      r[5] = _mm_add_epi32( r[5], F );
      r[6] = _mm_add_epi32( r[6], G );
      r[7] = _mm_add_epi32( r[7], H );
   }
   else
   {
      ctx->initialized = true;
      r[0] = _mm_add_epi32( A, m128_const1_64( 0x6A09E6676A09E667 ) );
      r[1] = _mm_add_epi32( B, m128_const1_64( 0xBB67AE85BB67AE85 ) );
      r[2] = _mm_add_epi32( C, m128_const1_64( 0x3C6EF3723C6EF372 ) );
      r[3] = _mm_add_epi32( D, m128_const1_64( 0xA54FF53AA54FF53A ) );
      r[4] = _mm_add_epi32( E, m128_const1_64( 0x510E527F510E527F ) );
      r[5] = _mm_add_epi32( F, m128_const1_64( 0x9B05688C9B05688C ) );
      r[6] = _mm_add_epi32( G, m128_const1_64( 0x1F83D9AB1F83D9AB ) );
      r[7] = _mm_add_epi32( H, m128_const1_64( 0x5BE0CD195BE0CD19 ) );
   }
}

void sha256_4way_init( sha256_4way_context *sc )
{
   sc->initialized = false;
   sc->count_high = sc->count_low = 0;
/*
   sc->val[0] = _mm_set1_epi32( H256[0] );
   sc->val[1] = _mm_set1_epi32( H256[1] );
   sc->val[2] = _mm_set1_epi32( H256[2] );
   sc->val[3] = _mm_set1_epi32( H256[3] );
   sc->val[4] = _mm_set1_epi32( H256[4] );
   sc->val[5] = _mm_set1_epi32( H256[5] );
   sc->val[6] = _mm_set1_epi32( H256[6] );
   sc->val[7] = _mm_set1_epi32( H256[7] );
*/
}

void sha256_4way( sha256_4way_context *sc, const void *data, size_t len )
{
   __m128i *vdata = (__m128i*)data;
   size_t ptr;
   const int buf_size = 64;

   ptr = (unsigned)sc->count_low & (buf_size - 1U);
   while ( len > 0 )
   {
      size_t clen;
      uint32_t clow, clow2;

      clen = buf_size - ptr;
      if ( clen > len )
         clen = len;
      memcpy_128( sc->buf + (ptr>>2), vdata, clen>>2 );
      vdata = vdata + (clen>>2);
      ptr += clen;
      len -= clen;
      if ( ptr == buf_size )
      {
         sha256_4way_round( sc, sc->buf, sc->val );
         ptr = 0;
      }
      clow = sc->count_low;
      clow2 = SPH_T32( clow + clen );
      sc->count_low = clow2;
      if ( clow2 < clow )
         sc->count_high++;
   }
}

void sha256_4way_close( sha256_4way_context *sc, void *dst )
{
    unsigned ptr;
    uint32_t low, high;
    const int buf_size = 64;
    const int pad = buf_size - 8;

    ptr = (unsigned)sc->count_low & (buf_size - 1U);
    sc->buf[ ptr>>2 ] = m128_const1_64( 0x0000008000000080 );
    ptr += 4;

    if ( ptr > pad )
    {
         memset_zero_128( sc->buf + (ptr>>2), (buf_size - ptr) >> 2 );
         sha256_4way_round( sc, sc->buf, sc->val );
         memset_zero_128( sc->buf, pad >> 2 );
    }
    else
         memset_zero_128( sc->buf + (ptr>>2), (pad - ptr) >> 2 );

    low = sc->count_low;
    high = (sc->count_high << 3) | (low >> 29);
    low = low << 3;

    sc->buf[ pad >> 2 ] =
                 mm128_bswap_32( _mm_set1_epi32( high ) );
    sc->buf[ ( pad+4 ) >> 2 ] =
                 mm128_bswap_32( _mm_set1_epi32( low ) );
    sha256_4way_round( sc, sc->buf, sc->val );

    mm128_block_bswap_32( dst, sc->val );
}

#if defined(__AVX2__)

// SHA-256 8 way

#define CHx(X, Y, Z) \
   _mm256_xor_si256( _mm256_and_si256( _mm256_xor_si256( Y, Z ), X ), Z ) 

#define MAJx(X, Y, Z) \
   _mm256_or_si256( _mm256_and_si256( X, Y ), \
                    _mm256_and_si256( _mm256_or_si256( X, Y ), Z ) )

#define BSG2_0x(x) \
   _mm256_xor_si256( _mm256_xor_si256( \
       mm256_ror_32(x,  2), mm256_ror_32(x, 13) ), mm256_ror_32( x, 22) )

#define BSG2_1x(x) \
   _mm256_xor_si256( _mm256_xor_si256( \
       mm256_ror_32(x,  6), mm256_ror_32(x, 11) ), mm256_ror_32( x, 25) )

#define SSG2_0x(x) \
   _mm256_xor_si256( _mm256_xor_si256( \
       mm256_ror_32(x,  7), mm256_ror_32(x, 18) ), _mm256_srli_epi32(x, 3) ) 

#define SSG2_1x(x) \
   _mm256_xor_si256( _mm256_xor_si256( \
       mm256_ror_32(x, 17), mm256_ror_32(x, 19) ), _mm256_srli_epi32(x, 10) )

#define SHA2x_MEXP( a, b, c, d ) \
     mm256_add4_32( SSG2_1x( W[a] ), W[b], SSG2_0x( W[c] ), W[d] );

#define SHA2s_8WAY_STEP(A, B, C, D, E, F, G, H, i, j) \
do { \
  __m256i T1, T2; \
  __m256i K = _mm256_set1_epi32( K256[( (j)+(i) )] ); \
  T1 = _mm256_add_epi32( H, mm256_add4_32( BSG2_1x(E), CHx(E, F, G), \
                                           K, W[i] ) ); \
  T2 = _mm256_add_epi32( BSG2_0x(A), MAJx(A, B, C) ); \
  D  = _mm256_add_epi32( D,  T1 ); \
  H  = _mm256_add_epi32( T1, T2 ); \
} while (0)

static void
sha256_8way_round( sha256_8way_context *ctx,  __m256i *in, __m256i r[8] )
{
   register  __m256i A, B, C, D, E, F, G, H;
   __m256i W[16];

   mm256_block_bswap_32( W  , in   );
   mm256_block_bswap_32( W+8, in+8 );

   if ( ctx->initialized )
   {
      A = r[0];
      B = r[1];
      C = r[2];
      D = r[3];
      E = r[4];
      F = r[5];
      G = r[6];
      H = r[7];
   }
   else
   {
      A = m256_const1_64( 0x6A09E6676A09E667 );
      B = m256_const1_64( 0xBB67AE85BB67AE85 );
      C = m256_const1_64( 0x3C6EF3723C6EF372 );
      D = m256_const1_64( 0xA54FF53AA54FF53A );
      E = m256_const1_64( 0x510E527F510E527F );
      F = m256_const1_64( 0x9B05688C9B05688C );
      G = m256_const1_64( 0x1F83D9AB1F83D9AB );
      H = m256_const1_64( 0x5BE0CD195BE0CD19 );
   }

   SHA2s_8WAY_STEP( A, B, C, D, E, F, G, H,  0, 0 );
   SHA2s_8WAY_STEP( H, A, B, C, D, E, F, G,  1, 0 );
   SHA2s_8WAY_STEP( G, H, A, B, C, D, E, F,  2, 0 );
   SHA2s_8WAY_STEP( F, G, H, A, B, C, D, E,  3, 0 );
   SHA2s_8WAY_STEP( E, F, G, H, A, B, C, D,  4, 0 );
   SHA2s_8WAY_STEP( D, E, F, G, H, A, B, C,  5, 0 );
   SHA2s_8WAY_STEP( C, D, E, F, G, H, A, B,  6, 0 );
   SHA2s_8WAY_STEP( B, C, D, E, F, G, H, A,  7, 0 );
   SHA2s_8WAY_STEP( A, B, C, D, E, F, G, H,  8, 0 );
   SHA2s_8WAY_STEP( H, A, B, C, D, E, F, G,  9, 0 );
   SHA2s_8WAY_STEP( G, H, A, B, C, D, E, F, 10, 0 );
   SHA2s_8WAY_STEP( F, G, H, A, B, C, D, E, 11, 0 );
   SHA2s_8WAY_STEP( E, F, G, H, A, B, C, D, 12, 0 );
   SHA2s_8WAY_STEP( D, E, F, G, H, A, B, C, 13, 0 );
   SHA2s_8WAY_STEP( C, D, E, F, G, H, A, B, 14, 0 );
   SHA2s_8WAY_STEP( B, C, D, E, F, G, H, A, 15, 0 );

   for ( int j = 16; j < 64; j += 16 )
   {
      W[ 0] = SHA2x_MEXP( 14,  9,  1,  0 );
      W[ 1] = SHA2x_MEXP( 15, 10,  2,  1 );
      W[ 2] = SHA2x_MEXP(  0, 11,  3,  2 );
      W[ 3] = SHA2x_MEXP(  1, 12,  4,  3 );
      W[ 4] = SHA2x_MEXP(  2, 13,  5,  4 );
      W[ 5] = SHA2x_MEXP(  3, 14,  6,  5 );
      W[ 6] = SHA2x_MEXP(  4, 15,  7,  6 );
      W[ 7] = SHA2x_MEXP(  5,  0,  8,  7 );
      W[ 8] = SHA2x_MEXP(  6,  1,  9,  8 );
      W[ 9] = SHA2x_MEXP(  7,  2, 10,  9 );
      W[10] = SHA2x_MEXP(  8,  3, 11, 10 );
      W[11] = SHA2x_MEXP(  9,  4, 12, 11 );
      W[12] = SHA2x_MEXP( 10,  5, 13, 12 );
      W[13] = SHA2x_MEXP( 11,  6, 14, 13 );
      W[14] = SHA2x_MEXP( 12,  7, 15, 14 );
      W[15] = SHA2x_MEXP( 13,  8,  0, 15 );

      SHA2s_8WAY_STEP( A, B, C, D, E, F, G, H,  0, j );
      SHA2s_8WAY_STEP( H, A, B, C, D, E, F, G,  1, j );
      SHA2s_8WAY_STEP( G, H, A, B, C, D, E, F,  2, j );
      SHA2s_8WAY_STEP( F, G, H, A, B, C, D, E,  3, j );
      SHA2s_8WAY_STEP( E, F, G, H, A, B, C, D,  4, j );
      SHA2s_8WAY_STEP( D, E, F, G, H, A, B, C,  5, j );
      SHA2s_8WAY_STEP( C, D, E, F, G, H, A, B,  6, j );
      SHA2s_8WAY_STEP( B, C, D, E, F, G, H, A,  7, j );
      SHA2s_8WAY_STEP( A, B, C, D, E, F, G, H,  8, j );
      SHA2s_8WAY_STEP( H, A, B, C, D, E, F, G,  9, j );
      SHA2s_8WAY_STEP( G, H, A, B, C, D, E, F, 10, j );
      SHA2s_8WAY_STEP( F, G, H, A, B, C, D, E, 11, j );
      SHA2s_8WAY_STEP( E, F, G, H, A, B, C, D, 12, j );
      SHA2s_8WAY_STEP( D, E, F, G, H, A, B, C, 13, j );
      SHA2s_8WAY_STEP( C, D, E, F, G, H, A, B, 14, j );
      SHA2s_8WAY_STEP( B, C, D, E, F, G, H, A, 15, j );
   }

   if ( ctx->initialized )
   {
      r[0] = _mm256_add_epi32( r[0], A );
      r[1] = _mm256_add_epi32( r[1], B );
      r[2] = _mm256_add_epi32( r[2], C );
      r[3] = _mm256_add_epi32( r[3], D );
      r[4] = _mm256_add_epi32( r[4], E );
      r[5] = _mm256_add_epi32( r[5], F );
      r[6] = _mm256_add_epi32( r[6], G );
      r[7] = _mm256_add_epi32( r[7], H );
   }
   else
   {
      ctx->initialized = true;
      r[0] = _mm256_add_epi32( A, m256_const1_64( 0x6A09E6676A09E667 ) );
      r[1] = _mm256_add_epi32( B, m256_const1_64( 0xBB67AE85BB67AE85 ) );
      r[2] = _mm256_add_epi32( C, m256_const1_64( 0x3C6EF3723C6EF372 ) );
      r[3] = _mm256_add_epi32( D, m256_const1_64( 0xA54FF53AA54FF53A ) );
      r[4] = _mm256_add_epi32( E, m256_const1_64( 0x510E527F510E527F ) );
      r[5] = _mm256_add_epi32( F, m256_const1_64( 0x9B05688C9B05688C ) );
      r[6] = _mm256_add_epi32( G, m256_const1_64( 0x1F83D9AB1F83D9AB ) );
      r[7] = _mm256_add_epi32( H, m256_const1_64( 0x5BE0CD195BE0CD19 ) );
   }
}

void sha256_8way_init( sha256_8way_context *sc )
{
   sc->initialized = false;
   sc->count_high = sc->count_low = 0;
/*
   sc->val[0] = _mm256_set1_epi32( H256[0] );
   sc->val[1] = _mm256_set1_epi32( H256[1] );
   sc->val[2] = _mm256_set1_epi32( H256[2] );
   sc->val[3] = _mm256_set1_epi32( H256[3] );
   sc->val[4] = _mm256_set1_epi32( H256[4] );
   sc->val[5] = _mm256_set1_epi32( H256[5] );
   sc->val[6] = _mm256_set1_epi32( H256[6] );
   sc->val[7] = _mm256_set1_epi32( H256[7] );
*/
}

void sha256_8way( sha256_8way_context *sc, const void *data, size_t len )
{
   __m256i *vdata = (__m256i*)data;
   size_t ptr;
   const int buf_size = 64;

   ptr = (unsigned)sc->count_low & (buf_size - 1U);
   while ( len > 0 )
   {
      size_t clen;
      uint32_t clow, clow2;

      clen = buf_size - ptr;
      if ( clen > len )
         clen = len;
      memcpy_256( sc->buf + (ptr>>2), vdata, clen>>2 );
      vdata = vdata + (clen>>2);
      ptr += clen;
      len -= clen;
      if ( ptr == buf_size )
      {
         sha256_8way_round( sc, sc->buf, sc->val );
         ptr = 0;
      }
      clow = sc->count_low;
      clow2 = SPH_T32( clow + clen );
      sc->count_low = clow2;
      if ( clow2 < clow )
         sc->count_high++;
   }
}

void sha256_8way_close( sha256_8way_context *sc, void *dst )
{
    unsigned ptr;
    uint32_t low, high;
    const int buf_size = 64;
    const int pad = buf_size - 8;

    ptr = (unsigned)sc->count_low & (buf_size - 1U);
    sc->buf[ ptr>>2 ] = m256_const1_64( 0x0000008000000080 );
    ptr += 4;

    if ( ptr > pad )
    {
         memset_zero_256( sc->buf + (ptr>>2), (buf_size - ptr) >> 2 );
         sha256_8way_round( sc, sc->buf, sc->val );
         memset_zero_256( sc->buf, pad >> 2 );
    }
    else
         memset_zero_256( sc->buf + (ptr>>2), (pad - ptr) >> 2 );

    low = sc->count_low;
    high = (sc->count_high << 3) | (low >> 29);
    low = low << 3;

    sc->buf[ pad >> 2 ] =
                 mm256_bswap_32( _mm256_set1_epi32( high ) );
    sc->buf[ ( pad+4 ) >> 2 ] =
                 mm256_bswap_32( _mm256_set1_epi32( low ) );

    sha256_8way_round( sc, sc->buf, sc->val );

    mm256_block_bswap_32( dst, sc->val );
}

#endif  // __AVX2__
#endif  // __SSE2__
