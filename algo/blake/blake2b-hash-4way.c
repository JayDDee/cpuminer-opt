/*
 * Copyright 2009 Colin Percival, 2014 savale
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file was originally written by Colin Percival as part of the Tarsnap
 * online backup system.
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "blake2b-hash-4way.h"

#if defined(__AVX2__)

static const uint8_t sigma[12][16] =
{
      { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
      { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
      { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
      { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
      { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
      { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
      { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
      { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
      { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
      { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
      { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
      { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 }
};


#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

#define B2B8W_G(a, b, c, d, x, y) \
{ \
   v[a] = _mm512_add_epi64( _mm512_add_epi64( v[a], v[b] ), x ); \
   v[d] = mm512_ror_64( _mm512_xor_si512( v[d], v[a] ), 32 ); \
   v[c] = _mm512_add_epi64( v[c], v[d] ); \
   v[b] = mm512_ror_64( _mm512_xor_si512( v[b], v[c] ), 24 ); \
   v[a] = _mm512_add_epi64( _mm512_add_epi64( v[a], v[b] ), y ); \
   v[d] = mm512_ror_64( _mm512_xor_si512( v[d], v[a] ), 16 ); \
   v[c] = _mm512_add_epi64( v[c], v[d] ); \
   v[b] = mm512_ror_64( _mm512_xor_si512( v[b], v[c] ), 63 ); \
}

static void blake2b_8way_compress( blake2b_8way_ctx *ctx, int last )
{  
   __m512i v[16], m[16];

   v[ 0] = ctx->h[0];
   v[ 1] = ctx->h[1];
   v[ 2] = ctx->h[2];
   v[ 3] = ctx->h[3];
   v[ 4] = ctx->h[4];
   v[ 5] = ctx->h[5];
   v[ 6] = ctx->h[6];
   v[ 7] = ctx->h[7];
   v[ 8] = m512_const1_64( 0x6A09E667F3BCC908 );
   v[ 9] = m512_const1_64( 0xBB67AE8584CAA73B );
   v[10] = m512_const1_64( 0x3C6EF372FE94F82B );
   v[11] = m512_const1_64( 0xA54FF53A5F1D36F1 );
   v[12] = m512_const1_64( 0x510E527FADE682D1 );
   v[13] = m512_const1_64( 0x9B05688C2B3E6C1F );
   v[14] = m512_const1_64( 0x1F83D9ABFB41BD6B );
   v[15] = m512_const1_64( 0x5BE0CD19137E2179 );

   v[12] = _mm512_xor_si512( v[12], _mm512_set1_epi64( ctx->t[0] ) );
   v[13] = _mm512_xor_si512( v[13], _mm512_set1_epi64( ctx->t[1] ) );

   if ( last )
      v[14] = mm512_not( v[14] );

   m[ 0] = ctx->b[ 0];
   m[ 1] = ctx->b[ 1];
   m[ 2] = ctx->b[ 2];
   m[ 3] = ctx->b[ 3];
   m[ 4] = ctx->b[ 4];
   m[ 5] = ctx->b[ 5];
   m[ 6] = ctx->b[ 6];
   m[ 7] = ctx->b[ 7];
   m[ 8] = ctx->b[ 8];
   m[ 9] = ctx->b[ 9];
   m[10] = ctx->b[10];
   m[11] = ctx->b[11];
   m[12] = ctx->b[12];
   m[13] = ctx->b[13];
   m[14] = ctx->b[14];
   m[15] = ctx->b[15];

   for ( int i = 0; i < 12; i++ )
   {
      B2B8W_G( 0, 4,  8, 12, m[ sigma[i][ 0] ], m[ sigma[i][ 1] ] );
      B2B8W_G( 1, 5,  9, 13, m[ sigma[i][ 2] ], m[ sigma[i][ 3] ] );
      B2B8W_G( 2, 6, 10, 14, m[ sigma[i][ 4] ], m[ sigma[i][ 5] ] );
      B2B8W_G( 3, 7, 11, 15, m[ sigma[i][ 6] ], m[ sigma[i][ 7] ] );
      B2B8W_G( 0, 5, 10, 15, m[ sigma[i][ 8] ], m[ sigma[i][ 9] ] );
      B2B8W_G( 1, 6, 11, 12, m[ sigma[i][10] ], m[ sigma[i][11] ] );
      B2B8W_G( 2, 7,  8, 13, m[ sigma[i][12] ], m[ sigma[i][13] ] );
      B2B8W_G( 3, 4,  9, 14, m[ sigma[i][14] ], m[ sigma[i][15] ] );
   }

   ctx->h[0] = mm512_xor3( ctx->h[0], v[0], v[ 8] );
   ctx->h[1] = mm512_xor3( ctx->h[1], v[1], v[ 9] );
   ctx->h[2] = mm512_xor3( ctx->h[2], v[2], v[10] );
   ctx->h[3] = mm512_xor3( ctx->h[3], v[3], v[11] );
   ctx->h[4] = mm512_xor3( ctx->h[4], v[4], v[12] );
   ctx->h[5] = mm512_xor3( ctx->h[5], v[5], v[13] );
   ctx->h[6] = mm512_xor3( ctx->h[6], v[6], v[14] );
   ctx->h[7] = mm512_xor3( ctx->h[7], v[7], v[15] );
}

int blake2b_8way_init( blake2b_8way_ctx *ctx )
{
   size_t i;

   ctx->h[0] = m512_const1_64( 0x6A09E667F3BCC908 );
   ctx->h[1] = m512_const1_64( 0xBB67AE8584CAA73B );
   ctx->h[2] = m512_const1_64( 0x3C6EF372FE94F82B );
   ctx->h[3] = m512_const1_64( 0xA54FF53A5F1D36F1 );
   ctx->h[4] = m512_const1_64( 0x510E527FADE682D1 );
   ctx->h[5] = m512_const1_64( 0x9B05688C2B3E6C1F );
   ctx->h[6] = m512_const1_64( 0x1F83D9ABFB41BD6B );
   ctx->h[7] = m512_const1_64( 0x5BE0CD19137E2179 );

   ctx->h[0] = _mm512_xor_si512( ctx->h[0], m512_const1_64( 0x01010020 ) );

   ctx->t[0] = 0;
   ctx->t[1] = 0;
   ctx->c = 0;
   ctx->outlen = 32;

   for ( i = 0; i < 16; i++ )
     ctx->b[i] = m512_zero;

   return 0;
}


void blake2b_8way_update( blake2b_8way_ctx *ctx, const void *input,
                          size_t inlen )
{
   __m512i* in =(__m512i*)input;

   size_t i, c;
   c = ctx->c >> 3;

   for ( i = 0; i < (inlen >> 3); i++ )
   {
      if ( ctx->c == 128 )
      {
         ctx->t[0] += ctx->c;
         if ( ctx->t[0] < ctx->c )
            ctx->t[1]++;
         blake2b_8way_compress( ctx, 0 );
         ctx->c = 0;
      }
      ctx->b[ c++ ] = in[i];
      ctx->c += 8;
   }
}

void blake2b_8way_final( blake2b_8way_ctx *ctx, void *out )
{
   size_t c;
   c = ctx->c >> 3;

   ctx->t[0] += ctx->c;
   if ( ctx->t[0] < ctx->c )
      ctx->t[1]++;

   while ( ctx->c < 128 )
   {
      ctx->b[c++] = m512_zero;
      ctx->c += 8;
   }

   blake2b_8way_compress( ctx, 1 );           // final block flag = 1

   casti_m512i( out, 0 ) = ctx->h[0];
   casti_m512i( out, 1 ) = ctx->h[1];
   casti_m512i( out, 2 ) = ctx->h[2];
   casti_m512i( out, 3 ) = ctx->h[3];
}

#endif   // AVX512

// AVX2

// G Mixing function.

#define B2B_G(a, b, c, d, x, y) \
{ \
   v[a] = _mm256_add_epi64( _mm256_add_epi64( v[a], v[b] ), x ); \
	v[d] = mm256_ror_64( _mm256_xor_si256( v[d], v[a] ), 32 ); \
	v[c] = _mm256_add_epi64( v[c], v[d] ); \
	v[b] = mm256_ror_64( _mm256_xor_si256( v[b], v[c] ), 24 ); \
	v[a] = _mm256_add_epi64( _mm256_add_epi64( v[a], v[b] ), y ); \
	v[d] = mm256_ror_64( _mm256_xor_si256( v[d], v[a] ), 16 ); \
	v[c] = _mm256_add_epi64( v[c], v[d] ); \
	v[b] = mm256_ror_64( _mm256_xor_si256( v[b], v[c] ), 63 ); \
}

// Initialization Vector.
/*
static const uint64_t blake2b_iv[8] = {
	0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
	0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
	0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
	0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179
};
*/

static void blake2b_4way_compress( blake2b_4way_ctx *ctx, int last )
{
	__m256i v[16], m[16];

   v[ 0] = ctx->h[0];
   v[ 1] = ctx->h[1];
   v[ 2] = ctx->h[2];
   v[ 3] = ctx->h[3];
   v[ 4] = ctx->h[4];
   v[ 5] = ctx->h[5];
   v[ 6] = ctx->h[6];
   v[ 7] = ctx->h[7];
   v[ 8] = m256_const1_64( 0x6A09E667F3BCC908 );
   v[ 9] = m256_const1_64( 0xBB67AE8584CAA73B );
   v[10] = m256_const1_64( 0x3C6EF372FE94F82B );
   v[11] = m256_const1_64( 0xA54FF53A5F1D36F1 );
   v[12] = m256_const1_64( 0x510E527FADE682D1 );
   v[13] = m256_const1_64( 0x9B05688C2B3E6C1F );
   v[14] = m256_const1_64( 0x1F83D9ABFB41BD6B );
   v[15] = m256_const1_64( 0x5BE0CD19137E2179 );

   v[12] = _mm256_xor_si256( v[12], _mm256_set1_epi64x( ctx->t[0] ) );
   v[13] = _mm256_xor_si256( v[13], _mm256_set1_epi64x( ctx->t[1] ) );

   if ( last )   
		v[14] = mm256_not( v[14] );

   m[ 0] = ctx->b[ 0];
   m[ 1] = ctx->b[ 1];
   m[ 2] = ctx->b[ 2];
   m[ 3] = ctx->b[ 3];
   m[ 4] = ctx->b[ 4];
   m[ 5] = ctx->b[ 5];
   m[ 6] = ctx->b[ 6];
   m[ 7] = ctx->b[ 7];
   m[ 8] = ctx->b[ 8];
   m[ 9] = ctx->b[ 9];
   m[10] = ctx->b[10];
   m[11] = ctx->b[11];
   m[12] = ctx->b[12];
   m[13] = ctx->b[13];
   m[14] = ctx->b[14];
   m[15] = ctx->b[15];
   
	for ( int i = 0; i < 12; i++ )
   { 
		B2B_G( 0, 4,  8, 12, m[ sigma[i][ 0] ], m[ sigma[i][ 1] ] );
		B2B_G( 1, 5,  9, 13, m[ sigma[i][ 2] ], m[ sigma[i][ 3] ] );
		B2B_G( 2, 6, 10, 14, m[ sigma[i][ 4] ], m[ sigma[i][ 5] ] );
		B2B_G( 3, 7, 11, 15, m[ sigma[i][ 6] ], m[ sigma[i][ 7] ] );
		B2B_G( 0, 5, 10, 15, m[ sigma[i][ 8] ], m[ sigma[i][ 9] ] );
		B2B_G( 1, 6, 11, 12, m[ sigma[i][10] ], m[ sigma[i][11] ] );
		B2B_G( 2, 7,  8, 13, m[ sigma[i][12] ], m[ sigma[i][13] ] );
		B2B_G( 3, 4,  9, 14, m[ sigma[i][14] ], m[ sigma[i][15] ] );
	}

   ctx->h[0] = _mm256_xor_si256( _mm256_xor_si256( ctx->h[0], v[0] ), v[ 8] );
   ctx->h[1] = _mm256_xor_si256( _mm256_xor_si256( ctx->h[1], v[1] ), v[ 9] );
   ctx->h[2] = _mm256_xor_si256( _mm256_xor_si256( ctx->h[2], v[2] ), v[10] );
   ctx->h[3] = _mm256_xor_si256( _mm256_xor_si256( ctx->h[3], v[3] ), v[11] );
   ctx->h[4] = _mm256_xor_si256( _mm256_xor_si256( ctx->h[4], v[4] ), v[12] );
   ctx->h[5] = _mm256_xor_si256( _mm256_xor_si256( ctx->h[5], v[5] ), v[13] );
   ctx->h[6] = _mm256_xor_si256( _mm256_xor_si256( ctx->h[6], v[6] ), v[14] );
   ctx->h[7] = _mm256_xor_si256( _mm256_xor_si256( ctx->h[7], v[7] ), v[15] );
}

int blake2b_4way_init( blake2b_4way_ctx *ctx ) 
{
	size_t i;

   ctx->h[0] = m256_const1_64( 0x6A09E667F3BCC908 );
   ctx->h[1] = m256_const1_64( 0xBB67AE8584CAA73B );
   ctx->h[2] = m256_const1_64( 0x3C6EF372FE94F82B );
   ctx->h[3] = m256_const1_64( 0xA54FF53A5F1D36F1 );
   ctx->h[4] = m256_const1_64( 0x510E527FADE682D1 );
   ctx->h[5] = m256_const1_64( 0x9B05688C2B3E6C1F );
   ctx->h[6] = m256_const1_64( 0x1F83D9ABFB41BD6B );
   ctx->h[7] = m256_const1_64( 0x5BE0CD19137E2179 );

   ctx->h[0] = _mm256_xor_si256( ctx->h[0], m256_const1_64( 0x01010020 ) );

	ctx->t[0] = 0;
	ctx->t[1] = 0;
	ctx->c = 0;
	ctx->outlen = 32;

   for ( i = 0; i < 16; i++ )
     ctx->b[i] = m256_zero;

	return 0;
}

void blake2b_4way_update( blake2b_4way_ctx *ctx, const void *input,
                          size_t inlen ) 
{
   __m256i* in =(__m256i*)input;

	size_t i, c;
   c = ctx->c >> 3; 

	for ( i = 0; i < (inlen >> 3); i++ )
   {
		if ( ctx->c == 128 )
      { 
			ctx->t[0] += ctx->c;
			if ( ctx->t[0] < ctx->c )
				ctx->t[1]++;
			blake2b_4way_compress( ctx, 0 );
			ctx->c = 0;
		}
      ctx->b[ c++ ] = in[i];
      ctx->c += 8;
   }
}

void blake2b_4way_final( blake2b_4way_ctx *ctx, void *out )
{
	size_t c;
   c = ctx->c >> 3;

	ctx->t[0] += ctx->c;
	if ( ctx->t[0] < ctx->c )
		ctx->t[1]++;

	while ( ctx->c < 128 )
   {
      ctx->b[c++] = m256_zero;
      ctx->c += 8;
   }

   blake2b_4way_compress( ctx, 1 );           // final block flag = 1

   casti_m256i( out, 0 ) = ctx->h[0];
   casti_m256i( out, 1 ) = ctx->h[1];
   casti_m256i( out, 2 ) = ctx->h[2];
   casti_m256i( out, 3 ) = ctx->h[3];
}

#endif  // AVX2
