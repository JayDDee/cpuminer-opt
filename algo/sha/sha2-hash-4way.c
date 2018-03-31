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

#if defined(__SSE4_2__)

#include <stddef.h>
#include <string.h>

#include "sha2-hash-4way.h"

#include <stdio.h>

// SHA-256 32 bit

static const sph_u32 H256[8] = {
        SPH_C32(0x6A09E667), SPH_C32(0xBB67AE85),
        SPH_C32(0x3C6EF372), SPH_C32(0xA54FF53A),
        SPH_C32(0x510E527F), SPH_C32(0x9B05688C),
        SPH_C32(0x1F83D9AB), SPH_C32(0x5BE0CD19)
};

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
     _mm_add_epi32( _mm_add_epi32( _mm_add_epi32( \
                    SSG2_1( W[a] ), W[b] ), SSG2_0( W[c] ) ), W[d] );

#define CHs(X, Y, Z) \
   _mm_xor_si128( _mm_and_si128( _mm_xor_si128( Y, Z ), X ), Z ) 

#define MAJs(X, Y, Z) \
   _mm_or_si128( _mm_and_si128( X, Y ), \
                    _mm_and_si128( _mm_or_si128( X, Y ), Z ) )

#define BSG2_0(x) \
   _mm_xor_si128( _mm_xor_si128( \
        mm_ror_32(x,  2), mm_ror_32(x, 13) ), mm_ror_32( x, 22) )

#define BSG2_1(x) \
   _mm_xor_si128( _mm_xor_si128( \
        mm_ror_32(x,  6), mm_ror_32(x, 11) ), mm_ror_32( x, 25) )

#define SSG2_0(x) \
   _mm_xor_si128( _mm_xor_si128( \
        mm_ror_32(x,  7), mm_ror_32(x, 18) ), _mm_srli_epi32(x, 3) ) 

#define SSG2_1(x) \
   _mm_xor_si128( _mm_xor_si128( \
        mm_ror_32(x, 17), mm_ror_32(x, 19) ), _mm_srli_epi32(x, 10) )

#define SHA2s_4WAY_STEP(A, B, C, D, E, F, G, H, i, j) \
do { \
  register __m128i T1, T2; \
  T1 = _mm_add_epi32( _mm_add_epi32( _mm_add_epi32( \
       _mm_add_epi32( H, BSG2_1(E) ), CHs(E, F, G) ), \
                          _mm_set1_epi32( K256[( (j)+(i) )] ) ), W[i] ); \
  T2 = _mm_add_epi32( BSG2_0(A), MAJs(A, B, C) ); \
  D  = _mm_add_epi32( D,  T1 ); \
  H  = _mm_add_epi32( T1, T2 ); \
} while (0)

static void
sha256_4way_round( __m128i *in, __m128i r[8] )
{
   register  __m128i A, B, C, D, E, F, G, H;
   __m128i W[16];

   W[ 0] = mm_bswap_32( in[ 0] );
   W[ 1] = mm_bswap_32( in[ 1] );
   W[ 2] = mm_bswap_32( in[ 2] );
   W[ 3] = mm_bswap_32( in[ 3] );
   W[ 4] = mm_bswap_32( in[ 4] );
   W[ 5] = mm_bswap_32( in[ 5] );
   W[ 6] = mm_bswap_32( in[ 6] );
   W[ 7] = mm_bswap_32( in[ 7] );
   W[ 8] = mm_bswap_32( in[ 8] );
   W[ 9] = mm_bswap_32( in[ 9] );
   W[10] = mm_bswap_32( in[10] );
   W[11] = mm_bswap_32( in[11] );
   W[12] = mm_bswap_32( in[12] );
   W[13] = mm_bswap_32( in[13] );
   W[14] = mm_bswap_32( in[14] );
   W[15] = mm_bswap_32( in[15] );

   A = r[0];
   B = r[1];
   C = r[2];
   D = r[3];
   E = r[4];
   F = r[5];
   G = r[6];
   H = r[7];

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

   r[0] = _mm_add_epi32( r[0], A );
   r[1] = _mm_add_epi32( r[1], B );
   r[2] = _mm_add_epi32( r[2], C );
   r[3] = _mm_add_epi32( r[3], D );
   r[4] = _mm_add_epi32( r[4], E );
   r[5] = _mm_add_epi32( r[5], F );
   r[6] = _mm_add_epi32( r[6], G );
   r[7] = _mm_add_epi32( r[7], H );
}

void sha256_4way_init( sha256_4way_context *sc )
{
   sc->count_high = sc->count_low = 0;
   sc->val[0] = _mm_set1_epi32( H256[0] );
   sc->val[1] = _mm_set1_epi32( H256[1] );
   sc->val[2] = _mm_set1_epi32( H256[2] );
   sc->val[3] = _mm_set1_epi32( H256[3] );
   sc->val[4] = _mm_set1_epi32( H256[4] );
   sc->val[5] = _mm_set1_epi32( H256[5] );
   sc->val[6] = _mm_set1_epi32( H256[6] );
   sc->val[7] = _mm_set1_epi32( H256[7] );
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
         sha256_4way_round( sc->buf, sc->val );
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
    unsigned ptr, u;
    uint32_t low, high;
    const int buf_size = 64;
    const int pad = buf_size - 8;

    ptr = (unsigned)sc->count_low & (buf_size - 1U);
    sc->buf[ ptr>>2 ] = _mm_set1_epi32( 0x80 );
    ptr += 4;

    if ( ptr > pad )
    {
         memset_zero_128( sc->buf + (ptr>>2), (buf_size - ptr) >> 2 );
         sha256_4way_round( sc->buf, sc->val );
         memset_zero_128( sc->buf, pad >> 2 );
    }
    else
         memset_zero_128( sc->buf + (ptr>>2), (pad - ptr) >> 2 );

    low = sc->count_low;
    high = (sc->count_high << 3) | (low >> 29);
    low = low << 3;

    sc->buf[ pad >> 2 ] =
                 mm_bswap_32( _mm_set1_epi32( high ) );
    sc->buf[ ( pad+4 ) >> 2 ] =
                 mm_bswap_32( _mm_set1_epi32( low ) );
    sha256_4way_round( sc->buf, sc->val );

    for ( u = 0; u < 8; u ++ )
       ((__m128i*)dst)[u] = mm_bswap_32( sc->val[u] );
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
     _mm256_add_epi32( _mm256_add_epi32( _mm256_add_epi32( \
                    SSG2_1x( W[a] ), W[b] ), SSG2_0x( W[c] ) ), W[d] );

#define SHA2s_8WAY_STEP(A, B, C, D, E, F, G, H, i, j) \
do { \
  register __m256i T1, T2; \
  T1 = _mm256_add_epi32( _mm256_add_epi32( _mm256_add_epi32( \
       _mm256_add_epi32( H, BSG2_1x(E) ), CHx(E, F, G) ), \
                          _mm256_set1_epi32( K256[( (j)+(i) )] ) ), W[i] ); \
  T2 = _mm256_add_epi32( BSG2_0x(A), MAJx(A, B, C) ); \
  D  = _mm256_add_epi32( D,  T1 ); \
  H  = _mm256_add_epi32( T1, T2 ); \
} while (0)

static void
sha256_8way_round( __m256i *in, __m256i r[8] )
{
   register  __m256i A, B, C, D, E, F, G, H;
   __m256i W[16];

   W[ 0] = mm256_bswap_32( in[ 0] );
   W[ 1] = mm256_bswap_32( in[ 1] );
   W[ 2] = mm256_bswap_32( in[ 2] );
   W[ 3] = mm256_bswap_32( in[ 3] );
   W[ 4] = mm256_bswap_32( in[ 4] );
   W[ 5] = mm256_bswap_32( in[ 5] );
   W[ 6] = mm256_bswap_32( in[ 6] );
   W[ 7] = mm256_bswap_32( in[ 7] );
   W[ 8] = mm256_bswap_32( in[ 8] );
   W[ 9] = mm256_bswap_32( in[ 9] );
   W[10] = mm256_bswap_32( in[10] );
   W[11] = mm256_bswap_32( in[11] );
   W[12] = mm256_bswap_32( in[12] );
   W[13] = mm256_bswap_32( in[13] );
   W[14] = mm256_bswap_32( in[14] );
   W[15] = mm256_bswap_32( in[15] );

   A = r[0];
   B = r[1];
   C = r[2];
   D = r[3];
   E = r[4];
   F = r[5];
   G = r[6];
   H = r[7];

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

   r[0] = _mm256_add_epi32( r[0], A );
   r[1] = _mm256_add_epi32( r[1], B );
   r[2] = _mm256_add_epi32( r[2], C );
   r[3] = _mm256_add_epi32( r[3], D );
   r[4] = _mm256_add_epi32( r[4], E );
   r[5] = _mm256_add_epi32( r[5], F );
   r[6] = _mm256_add_epi32( r[6], G );
   r[7] = _mm256_add_epi32( r[7], H );
}


void sha256_8way_init( sha256_8way_context *sc )
{
   sc->count_high = sc->count_low = 0;
   sc->val[0] = _mm256_set1_epi32( H256[0] );
   sc->val[1] = _mm256_set1_epi32( H256[1] );
   sc->val[2] = _mm256_set1_epi32( H256[2] );
   sc->val[3] = _mm256_set1_epi32( H256[3] );
   sc->val[4] = _mm256_set1_epi32( H256[4] );
   sc->val[5] = _mm256_set1_epi32( H256[5] );
   sc->val[6] = _mm256_set1_epi32( H256[6] );
   sc->val[7] = _mm256_set1_epi32( H256[7] );
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
         sha256_8way_round( sc->buf, sc->val );
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
    unsigned ptr, u;
    uint32_t low, high;
    const int buf_size = 64;
    const int pad = buf_size - 8;

    ptr = (unsigned)sc->count_low & (buf_size - 1U);
    sc->buf[ ptr>>2 ] = _mm256_set1_epi32( 0x80 );
    ptr += 4;

    if ( ptr > pad )
    {
         memset_zero_256( sc->buf + (ptr>>2), (buf_size - ptr) >> 2 );
         sha256_8way_round( sc->buf, sc->val );
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

    sha256_8way_round( sc->buf, sc->val );

    for ( u = 0; u < 8; u ++ )
       ((__m256i*)dst)[u] = mm256_bswap_32( sc->val[u] );
}


// SHA-512 4 way 64 bit

static const sph_u64 H512[8] = {
        SPH_C64(0x6A09E667F3BCC908), SPH_C64(0xBB67AE8584CAA73B),
        SPH_C64(0x3C6EF372FE94F82B), SPH_C64(0xA54FF53A5F1D36F1),
        SPH_C64(0x510E527FADE682D1), SPH_C64(0x9B05688C2B3E6C1F),
        SPH_C64(0x1F83D9ABFB41BD6B), SPH_C64(0x5BE0CD19137E2179)
};

static const sph_u64 K512[80] = {
	SPH_C64(0x428A2F98D728AE22), SPH_C64(0x7137449123EF65CD),
	SPH_C64(0xB5C0FBCFEC4D3B2F), SPH_C64(0xE9B5DBA58189DBBC),
	SPH_C64(0x3956C25BF348B538), SPH_C64(0x59F111F1B605D019),
	SPH_C64(0x923F82A4AF194F9B), SPH_C64(0xAB1C5ED5DA6D8118),
	SPH_C64(0xD807AA98A3030242), SPH_C64(0x12835B0145706FBE),
	SPH_C64(0x243185BE4EE4B28C), SPH_C64(0x550C7DC3D5FFB4E2),
	SPH_C64(0x72BE5D74F27B896F), SPH_C64(0x80DEB1FE3B1696B1),
	SPH_C64(0x9BDC06A725C71235), SPH_C64(0xC19BF174CF692694),
	SPH_C64(0xE49B69C19EF14AD2), SPH_C64(0xEFBE4786384F25E3),
	SPH_C64(0x0FC19DC68B8CD5B5), SPH_C64(0x240CA1CC77AC9C65),
	SPH_C64(0x2DE92C6F592B0275), SPH_C64(0x4A7484AA6EA6E483),
	SPH_C64(0x5CB0A9DCBD41FBD4), SPH_C64(0x76F988DA831153B5),
	SPH_C64(0x983E5152EE66DFAB), SPH_C64(0xA831C66D2DB43210),
	SPH_C64(0xB00327C898FB213F), SPH_C64(0xBF597FC7BEEF0EE4),
	SPH_C64(0xC6E00BF33DA88FC2), SPH_C64(0xD5A79147930AA725),
	SPH_C64(0x06CA6351E003826F), SPH_C64(0x142929670A0E6E70),
	SPH_C64(0x27B70A8546D22FFC), SPH_C64(0x2E1B21385C26C926),
	SPH_C64(0x4D2C6DFC5AC42AED), SPH_C64(0x53380D139D95B3DF),
	SPH_C64(0x650A73548BAF63DE), SPH_C64(0x766A0ABB3C77B2A8),
	SPH_C64(0x81C2C92E47EDAEE6), SPH_C64(0x92722C851482353B),
	SPH_C64(0xA2BFE8A14CF10364), SPH_C64(0xA81A664BBC423001),
	SPH_C64(0xC24B8B70D0F89791), SPH_C64(0xC76C51A30654BE30),
	SPH_C64(0xD192E819D6EF5218), SPH_C64(0xD69906245565A910),
	SPH_C64(0xF40E35855771202A), SPH_C64(0x106AA07032BBD1B8),
	SPH_C64(0x19A4C116B8D2D0C8), SPH_C64(0x1E376C085141AB53),
	SPH_C64(0x2748774CDF8EEB99), SPH_C64(0x34B0BCB5E19B48A8),
	SPH_C64(0x391C0CB3C5C95A63), SPH_C64(0x4ED8AA4AE3418ACB),
	SPH_C64(0x5B9CCA4F7763E373), SPH_C64(0x682E6FF3D6B2B8A3),
	SPH_C64(0x748F82EE5DEFB2FC), SPH_C64(0x78A5636F43172F60),
	SPH_C64(0x84C87814A1F0AB72), SPH_C64(0x8CC702081A6439EC),
	SPH_C64(0x90BEFFFA23631E28), SPH_C64(0xA4506CEBDE82BDE9),
	SPH_C64(0xBEF9A3F7B2C67915), SPH_C64(0xC67178F2E372532B),
	SPH_C64(0xCA273ECEEA26619C), SPH_C64(0xD186B8C721C0C207),
	SPH_C64(0xEADA7DD6CDE0EB1E), SPH_C64(0xF57D4F7FEE6ED178),
	SPH_C64(0x06F067AA72176FBA), SPH_C64(0x0A637DC5A2C898A6),
	SPH_C64(0x113F9804BEF90DAE), SPH_C64(0x1B710B35131C471B),
	SPH_C64(0x28DB77F523047D84), SPH_C64(0x32CAAB7B40C72493),
	SPH_C64(0x3C9EBE0A15C9BEBC), SPH_C64(0x431D67C49C100D4C),
	SPH_C64(0x4CC5D4BECB3E42B6), SPH_C64(0x597F299CFC657E2A),
	SPH_C64(0x5FCB6FAB3AD6FAEC), SPH_C64(0x6C44198C4A475817)
};

#define CH(X, Y, Z) \
   _mm256_xor_si256( _mm256_and_si256( _mm256_xor_si256( Y, Z ), X ), Z ) 

#define MAJ(X, Y, Z) \
   _mm256_or_si256( _mm256_and_si256( X, Y ), \
                    _mm256_and_si256( _mm256_or_si256( X, Y ), Z ) )

#define BSG5_0(x) \
   _mm256_xor_si256( _mm256_xor_si256( \
        mm256_ror_64(x, 28), mm256_ror_64(x, 34) ), mm256_ror_64(x, 39) )

#define BSG5_1(x) \
   _mm256_xor_si256( _mm256_xor_si256( \
        mm256_ror_64(x, 14), mm256_ror_64(x, 18) ), mm256_ror_64(x, 41) )

#define SSG5_0(x) \
   _mm256_xor_si256( _mm256_xor_si256( \
        mm256_ror_64(x,  1), mm256_ror_64(x,  8) ), _mm256_srli_epi64(x, 7) ) 

#define SSG5_1(x) \
   _mm256_xor_si256( _mm256_xor_si256( \
        mm256_ror_64(x, 19), mm256_ror_64(x, 61) ), _mm256_srli_epi64(x, 6) )

#define SHA3_4WAY_STEP(A, B, C, D, E, F, G, H, i) \
do { \
  register __m256i T1, T2; \
  T1 = _mm256_add_epi64( _mm256_add_epi64( _mm256_add_epi64( \
       _mm256_add_epi64( H, BSG5_1(E) ), CH(E, F, G) ), \
                         _mm256_set1_epi64x( K512[i] ) ), W[i] ); \
  T2 = _mm256_add_epi64( BSG5_0(A), MAJ(A, B, C) ); \
  D  = _mm256_add_epi64( D, T1 ); \
  H  = _mm256_add_epi64( T1, T2 ); \
} while (0)

static void
sha512_4way_round( __m256i *in, __m256i r[8] )
{
   int i;
   register __m256i A, B, C, D, E, F, G, H;
   __m256i W[80];

   for ( i = 0; i < 16; i++ )
      W[i] = mm256_bswap_64( in[i] );
   for ( i = 16; i < 80; i++ )
      W[i] = _mm256_add_epi64( _mm256_add_epi64( _mm256_add_epi64(
           SSG5_1( W[ i-2 ] ), W[ i-7 ] ), SSG5_0( W[ i-15 ] ) ), W[ i-16 ] );

   A = r[0];
   B = r[1];
   C = r[2];
   D = r[3];
   E = r[4];
   F = r[5];
   G = r[6];
   H = r[7];

   for ( i = 0; i < 80; i += 8 )
   {
      SHA3_4WAY_STEP( A, B, C, D, E, F, G, H, i + 0 );
      SHA3_4WAY_STEP( H, A, B, C, D, E, F, G, i + 1 );
      SHA3_4WAY_STEP( G, H, A, B, C, D, E, F, i + 2 );
      SHA3_4WAY_STEP( F, G, H, A, B, C, D, E, i + 3 );
      SHA3_4WAY_STEP( E, F, G, H, A, B, C, D, i + 4 );
      SHA3_4WAY_STEP( D, E, F, G, H, A, B, C, i + 5 );
      SHA3_4WAY_STEP( C, D, E, F, G, H, A, B, i + 6 );
      SHA3_4WAY_STEP( B, C, D, E, F, G, H, A, i + 7 );
   }

   r[0] = _mm256_add_epi64( r[0], A );
   r[1] = _mm256_add_epi64( r[1], B );
   r[2] = _mm256_add_epi64( r[2], C );
   r[3] = _mm256_add_epi64( r[3], D );
   r[4] = _mm256_add_epi64( r[4], E );
   r[5] = _mm256_add_epi64( r[5], F );
   r[6] = _mm256_add_epi64( r[6], G );
   r[7] = _mm256_add_epi64( r[7], H );
}

void sha512_4way_init( sha512_4way_context *sc )
{
   sc->count = 0;
   sc->val[0] = _mm256_set1_epi64x( H512[0] );
   sc->val[1] = _mm256_set1_epi64x( H512[1] );
   sc->val[2] = _mm256_set1_epi64x( H512[2] );
   sc->val[3] = _mm256_set1_epi64x( H512[3] );
   sc->val[4] = _mm256_set1_epi64x( H512[4] );
   sc->val[5] = _mm256_set1_epi64x( H512[5] );
   sc->val[6] = _mm256_set1_epi64x( H512[6] );
   sc->val[7] = _mm256_set1_epi64x( H512[7] );
}

void sha512_4way( sha512_4way_context *sc, const void *data, size_t len )
{
   __m256i *vdata = (__m256i*)data;
   size_t ptr;
   const int buf_size = 128;

   ptr = (unsigned)sc->count & (buf_size - 1U);
   while ( len > 0 )
   {
      size_t clen;
      clen = buf_size - ptr;
      if ( clen > len )
         clen = len;
      memcpy_256( sc->buf + (ptr>>3), vdata, clen>>3 );
      vdata = vdata + (clen>>3);
      ptr += clen;
      len -= clen;
      if ( ptr == buf_size )
      {
         sha512_4way_round( sc->buf, sc->val );
         ptr = 0;
      }
      sc->count += clen;
   }
}

void sha512_4way_close( sha512_4way_context *sc, void *dst )
{
    unsigned ptr, u;
    const int buf_size = 128;
    const int pad = buf_size - 16;

    ptr = (unsigned)sc->count & (buf_size - 1U);
    sc->buf[ ptr>>3 ] = _mm256_set1_epi64x( 0x80 );
    ptr += 8;
    if ( ptr > pad )
    {
         memset_zero_256( sc->buf + (ptr>>3), (buf_size - ptr) >> 3 );
         sha512_4way_round( sc->buf, sc->val );
         memset_zero_256( sc->buf, pad >> 3 );
    }
    else
         memset_zero_256( sc->buf + (ptr>>3), (pad - ptr) >> 3 );

    sc->buf[ pad >> 3 ] =
                 mm256_bswap_64( _mm256_set1_epi64x( sc->count >> 61 ) );
    sc->buf[ ( pad+8 ) >> 3 ] = 
                 mm256_bswap_64( _mm256_set1_epi64x( sc->count << 3 ) );
    sha512_4way_round( sc->buf, sc->val );

    for ( u = 0; u < 8; u ++ )
       ((__m256i*)dst)[u] = mm256_bswap_64( sc->val[u] );
}

#endif  // __AVX2__
#endif  // __SSE4_2__
