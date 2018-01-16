/* ====================================================================
 * Copyright (c) 2014 - 2017 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

#include <string.h>
#include "sm3-hash-4way.h"

#ifdef __AVX__

void sm3_4way_init( sm3_4way_ctx_t *ctx )
{
	ctx->digest[0] = _mm_set1_epi32( 0x7380166F );
	ctx->digest[1] = _mm_set1_epi32( 0x4914B2B9 );
	ctx->digest[2] = _mm_set1_epi32( 0x172442D7 );
	ctx->digest[3] = _mm_set1_epi32( 0xDA8A0600 );
	ctx->digest[4] = _mm_set1_epi32( 0xA96F30BC );
	ctx->digest[5] = _mm_set1_epi32( 0x163138AA );
	ctx->digest[6] = _mm_set1_epi32( 0xE38DEE4D );
	ctx->digest[7] = _mm_set1_epi32( 0xB0FB0E4E );
	ctx->nblocks = 0;
	ctx->num = 0;
}

void sm3_4way( void *cc, const void *data, size_t len )
{
   sm3_4way_ctx_t *ctx = (sm3_4way_ctx_t*)cc;
   __m128i *block = (__m128i*)ctx->block;
   __m128i *vdata = (__m128i*)data;

   if ( ctx->num )
   {
      unsigned int left = SM3_BLOCK_SIZE - ctx->num;
      if ( len < left )
      {
         memcpy_128( block + (ctx->num >> 2), vdata , len>>2 ); 
         ctx->num += len;
         return;
      }
      else
      {
         memcpy_128( block + (ctx->num >> 2), vdata , left>>2 );
         sm3_4way_compress( ctx->digest, block );
         ctx->nblocks++;
         vdata += left>>2;
         len -= left;
      }
   }
   while ( len >= SM3_BLOCK_SIZE )
   {
      sm3_4way_compress( ctx->digest, vdata );
      ctx->nblocks++;
      vdata += SM3_BLOCK_SIZE>>2;
      len -= SM3_BLOCK_SIZE;
   }
   ctx->num = len;
   if ( len )
      memcpy_128( block, vdata, len>>2 );
}

void sm3_4way_close( void *cc, void *dst )
{
   sm3_4way_ctx_t *ctx = (sm3_4way_ctx_t*)cc;
   __m128i *hash = (__m128i*)dst;
   __m128i *count = (__m128i*)(ctx->block + ( (SM3_BLOCK_SIZE - 8) >> 2 ) );
   __m128i *block = (__m128i*)ctx->block;
   int i;

   block[ctx->num] = _mm_set1_epi32( 0x80 );

   if ( ctx->num + 8 <= SM3_BLOCK_SIZE )
   {
      memset_zero_128( block + (ctx->num >> 2) + 1, 
                      ( SM3_BLOCK_SIZE - ctx->num - 8 ) >> 2 ); 
   }
   else
   {
      memset_zero_128( block + (ctx->num >> 2) + 1, 
                             ( SM3_BLOCK_SIZE - (ctx->num >> 2) - 1 ) );
      sm3_4way_compress( ctx->digest, block );
      memset_zero_128( block, ( SM3_BLOCK_SIZE - 8 ) >> 2 );
   }

   count[0] = mm_byteswap_32(
                  _mm_set1_epi32( ctx->nblocks >> 23 ) );
   count[1] = mm_byteswap_32( _mm_set1_epi32( ( ctx->nblocks << 9 ) +
                                              ( ctx->num     << 3 ) ) );
   sm3_4way_compress( ctx->digest, block );

   for ( i = 0; i < 8 ; i++ )
     hash[i] = mm_byteswap_32( ctx->digest[i] );
}

#define P0(x) _mm_xor_si128( x, _mm_xor_si128( mm_rotl_32( x,  9 ), \
                                               mm_rotl_32( x, 17 ) ) ) 
#define P1(x) _mm_xor_si128( x, _mm_xor_si128( mm_rotl_32( x, 15 ), \
                                               mm_rotl_32( x, 23 ) ) ) 

#define FF0(x,y,z) _mm_xor_si128( x, _mm_xor_si128( y, z ) )
#define FF1(x,y,z) _mm_or_si128( _mm_or_si128( _mm_and_si128( x, y ), \
                                               _mm_and_si128( x, z ) ), \
                                               _mm_and_si128( y, z ) )

#define GG0(x,y,z) FF0(x,y,z)
#define GG1(x,y,z) _mm_or_si128( _mm_and_si128( x, y ), \
                                 _mm_andnot_si128( x, z ) )


void sm3_4way_compress( __m128i *digest, __m128i *block )
{
   __m128i W[68], W1[64];
   __m128i A = digest[ 0 ];
   __m128i B = digest[ 1 ];
   __m128i C = digest[ 2 ];
   __m128i D = digest[ 3 ];
   __m128i E = digest[ 4 ];
   __m128i F = digest[ 5 ];
   __m128i G = digest[ 6 ];
   __m128i H = digest[ 7 ];
   __m128i SS1, SS2, TT1, TT2, T;
   int j;

   for ( j = 0; j < 16; j++ )
      W[j] = mm_byteswap_32( block[j] );

   for ( j = 16; j < 68; j++ )
      W[j] = _mm_xor_si128( P1( _mm_xor_si128( _mm_xor_si128( W[ j-16 ],
                                                              W[ j-9 ] ),
                                               mm_rotl_32( W[ j-3 ], 15 ) ) ),
                            _mm_xor_si128( mm_rotl_32( W[ j-13 ], 7 ),
                                           W[ j-6 ] ) );

   for( j = 0; j < 64; j++ )
       W1[j] = _mm_xor_si128( W[j], W[j+4] );

   T = _mm_set1_epi32( 0x79CC4519UL );
   for( j =0; j < 16; j++ )
   {
      SS1 = mm_rotl_32( _mm_add_epi32( _mm_add_epi32( mm_rotl_32( A, 12 ), E ),
                                      mm_rotl_32( T, j ) ), 7 );
      SS2 = _mm_xor_si128( SS1, mm_rotl_32( A, 12 ) );
      TT1 = _mm_add_epi32( _mm_add_epi32( _mm_add_epi32( FF0( A, B, C ), D ),
                                          SS2 ), W1[j] );
      TT2 = _mm_add_epi32( _mm_add_epi32( _mm_add_epi32( GG0( E, F, G ), H ),
                                          SS1 ), W[j] );
      D = C;
      C = mm_rotl_32( B, 9 );
      B = A;
      A = TT1;
      H = G;
      G = mm_rotl_32( F, 19 );
      F = E;
      E = P0( TT2 );
   }

   T = _mm_set1_epi32( 0x7A879D8AUL );
   for( j =16; j < 64; j++ )
   {
      SS1 = mm_rotl_32( _mm_add_epi32( _mm_add_epi32( mm_rotl_32( A, 12 ), E ),
                                      mm_rotl_32( T, j&31 ) ), 7 );
      SS2 = _mm_xor_si128( SS1, mm_rotl_32( A, 12 ) );
      TT1 = _mm_add_epi32( _mm_add_epi32( _mm_add_epi32( FF1( A, B, C ), D ), 
                                          SS2 ), W1[j] );
      TT2 = _mm_add_epi32( _mm_add_epi32( _mm_add_epi32( GG1( E, F, G ), H ),
                                          SS1 ), W[j] );
      D = C;
      C = mm_rotl_32( B, 9 );
      B = A;
      A = TT1;
      H = G;
      G = mm_rotl_32( F, 19 );
      F = E;
      E = P0( TT2 );
   }

   digest[0] = _mm_xor_si128( digest[0], A );
   digest[1] = _mm_xor_si128( digest[1], B );
   digest[2] = _mm_xor_si128( digest[2], C );
   digest[3] = _mm_xor_si128( digest[3], D );
   digest[4] = _mm_xor_si128( digest[4], E );
   digest[5] = _mm_xor_si128( digest[5], F );
   digest[6] = _mm_xor_si128( digest[6], G );
   digest[7] = _mm_xor_si128( digest[7], H );
}

#endif

