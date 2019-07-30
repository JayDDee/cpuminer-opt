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

#if defined(__AVX2__)

#include <stddef.h>
#include <string.h>
#include "sha-hash-4way.h"

// SHA-512 4 way 64 bit

/*
static const sph_u64 H512[8] = {
        SPH_C64(0x6A09E667F3BCC908), SPH_C64(0xBB67AE8584CAA73B),
        SPH_C64(0x3C6EF372FE94F82B), SPH_C64(0xA54FF53A5F1D36F1),
        SPH_C64(0x510E527FADE682D1), SPH_C64(0x9B05688C2B3E6C1F),
        SPH_C64(0x1F83D9ABFB41BD6B), SPH_C64(0x5BE0CD19137E2179)
};
*/

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

// Interleave SSG0 & SSG1 for better throughput.
// return ssg0(w0) + ssg1(w1)
static inline __m256i ssg512_add( __m256i w0, __m256i w1 )
{
   __m256i w0a, w1a, w0b, w1b;
   w0a = mm256_ror_64( w0, 1 );
   w1a = mm256_ror_64( w1,19 );
   w0b = mm256_ror_64( w0, 8 );
   w1b = mm256_ror_64( w1,61 );
   w0a = _mm256_xor_si256( w0a, w0b );
   w1a = _mm256_xor_si256( w1a, w1b );
   w0b = _mm256_srli_epi64( w0, 7 );
   w1b = _mm256_srli_epi64( w1, 6 );
   w0a = _mm256_xor_si256( w0a, w0b );
   w1a = _mm256_xor_si256( w1a, w1b );
   return _mm256_add_epi64( w0a, w1a );
}


#define SSG512x2_0( w0, w1, i ) do \
{ \
   __m256i X0a, X1a, X0b, X1b; \
  X0a = mm256_ror_64( W[i-15], 1 ); \
  X1a = mm256_ror_64( W[i-14], 1 ); \
  X0b = mm256_ror_64( W[i-15], 8 ); \
  X1b = mm256_ror_64( W[i-14], 8 ); \
  X0a = _mm256_xor_si256( X0a, X0b ); \
  X1a = _mm256_xor_si256( X1a, X1b ); \
  X0b = _mm256_srli_epi64( W[i-15], 7 ); \
  X1b = _mm256_srli_epi64( W[i-14], 7 ); \
  w0  = _mm256_xor_si256( X0a, X0b ); \
  w1  = _mm256_xor_si256( X1a, X1b ); \
} while(0)

#define SSG512x2_1( w0, w1, i ) do \
{ \
   __m256i X0a, X1a, X0b, X1b; \
  X0a = mm256_ror_64( W[i-2],19 ); \
  X1a = mm256_ror_64( W[i-1],19 ); \
  X0b = mm256_ror_64( W[i-2],61 ); \
  X1b = mm256_ror_64( W[i-1],61 ); \
  X0a = _mm256_xor_si256( X0a, X0b ); \
  X1a = _mm256_xor_si256( X1a, X1b ); \
  X0b = _mm256_srli_epi64( W[i-2], 6 ); \
  X1b = _mm256_srli_epi64( W[i-1], 6 ); \
  w0  = _mm256_xor_si256( X0a, X0b ); \
  w1  = _mm256_xor_si256( X1a, X1b ); \
} while(0)

#define SHA3_4WAY_STEP(A, B, C, D, E, F, G, H, i) \
do { \
  __m256i T1, T2; \
  __m256i K = _mm256_set1_epi64x( K512[ i ] ); \
  T1 = _mm256_add_epi64( H, mm256_add4_64( BSG5_1(E), CH(E, F, G), \
                                           K, W[i] ) ); \
  T2 = _mm256_add_epi64( BSG5_0(A), MAJ(A, B, C) ); \
  D  = _mm256_add_epi64( D, T1 ); \
  H  = _mm256_add_epi64( T1, T2 ); \
} while (0)


static void
sha512_4way_round( sha512_4way_context *ctx,  __m256i *in, __m256i r[8] )
{
   int i;
   register __m256i A, B, C, D, E, F, G, H;
   __m256i W[80];

   mm256_block_bswap_64( W  , in );
   mm256_block_bswap_64( W+8, in+8 );

   for ( i = 16; i < 80; i++ )
      W[i] = _mm256_add_epi64( ssg512_add( W[i-15], W[i-2] ),
                               _mm256_add_epi64( W[ i- 7 ], W[ i-16 ] ) );

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
      A = m256_const1_64( 0x6A09E667F3BCC908 );
      B = m256_const1_64( 0xBB67AE8584CAA73B );
      C = m256_const1_64( 0x3C6EF372FE94F82B );
      D = m256_const1_64( 0xA54FF53A5F1D36F1 );
      E = m256_const1_64( 0x510E527FADE682D1 );
      F = m256_const1_64( 0x9B05688C2B3E6C1F );
      G = m256_const1_64( 0x1F83D9ABFB41BD6B );
      H = m256_const1_64( 0x5BE0CD19137E2179 );
   }

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

   if ( ctx->initialized )
   {
      r[0] = _mm256_add_epi64( r[0], A );
      r[1] = _mm256_add_epi64( r[1], B );
      r[2] = _mm256_add_epi64( r[2], C );
      r[3] = _mm256_add_epi64( r[3], D );
      r[4] = _mm256_add_epi64( r[4], E );
      r[5] = _mm256_add_epi64( r[5], F );
      r[6] = _mm256_add_epi64( r[6], G );
      r[7] = _mm256_add_epi64( r[7], H );
   }
   else
   {
      ctx->initialized = true;
      r[0] = _mm256_add_epi64( A, m256_const1_64( 0x6A09E667F3BCC908 ) );
      r[1] = _mm256_add_epi64( B, m256_const1_64( 0xBB67AE8584CAA73B ) );
      r[2] = _mm256_add_epi64( C, m256_const1_64( 0x3C6EF372FE94F82B ) );
      r[3] = _mm256_add_epi64( D, m256_const1_64( 0xA54FF53A5F1D36F1 ) );
      r[4] = _mm256_add_epi64( E, m256_const1_64( 0x510E527FADE682D1 ) );
      r[5] = _mm256_add_epi64( F, m256_const1_64( 0x9B05688C2B3E6C1F ) );
      r[6] = _mm256_add_epi64( G, m256_const1_64( 0x1F83D9ABFB41BD6B ) );
      r[7] = _mm256_add_epi64( H, m256_const1_64( 0x5BE0CD19137E2179 ) );
   }
}

void sha512_4way_init( sha512_4way_context *sc )
{
   sc->initialized = false;
   sc->count = 0;
/*
   sc->val[0] = _mm256_set1_epi64x( H512[0] );
   sc->val[1] = _mm256_set1_epi64x( H512[1] );
   sc->val[2] = _mm256_set1_epi64x( H512[2] );
   sc->val[3] = _mm256_set1_epi64x( H512[3] );
   sc->val[4] = _mm256_set1_epi64x( H512[4] );
   sc->val[5] = _mm256_set1_epi64x( H512[5] );
   sc->val[6] = _mm256_set1_epi64x( H512[6] );
   sc->val[7] = _mm256_set1_epi64x( H512[7] );
*/
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
         sha512_4way_round( sc, sc->buf, sc->val );
         ptr = 0;
      }
      sc->count += clen;
   }
}

void sha512_4way_close( sha512_4way_context *sc, void *dst )
{
    unsigned ptr;
    const int buf_size = 128;
    const int pad = buf_size - 16;

    ptr = (unsigned)sc->count & (buf_size - 1U);
    sc->buf[ ptr>>3 ] = m256_const1_64( 0x80 );
    ptr += 8;
    if ( ptr > pad )
    {
         memset_zero_256( sc->buf + (ptr>>3), (buf_size - ptr) >> 3 );
         sha512_4way_round( sc, sc->buf, sc->val );
         memset_zero_256( sc->buf, pad >> 3 );
    }
    else
         memset_zero_256( sc->buf + (ptr>>3), (pad - ptr) >> 3 );

    sc->buf[ pad >> 3 ] =
                 mm256_bswap_64( _mm256_set1_epi64x( sc->count >> 61 ) );
    sc->buf[ ( pad+8 ) >> 3 ] = 
                 mm256_bswap_64( _mm256_set1_epi64x( sc->count << 3 ) );
    sha512_4way_round( sc, sc->buf, sc->val );

    mm256_block_bswap_64( dst, sc->val );
}

#endif  // __AVX2__
