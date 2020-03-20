/*-
 * Copyright 2005,2007,2009 Colin Percival
 * Copywright 2020 JayDDee246@gmail.com
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
 */

#include <sys/types.h>
#include <stdint.h>
#include <string.h>
#include "hmac-sha256-hash-4way.h"
#include "compat.h"

// HMAC 4-way SSE2

/**
 * HMAC_SHA256_Buf(K, Klen, in, len, digest):
 * Compute the HMAC-SHA256 of ${len} bytes from ${in} using the key ${K} of
 * length ${Klen}, and write the result to ${digest}.
 */
void
hmac_sha256_4way_full( void *digest, const void *K, size_t Klen,
                       const void *in, size_t len )
{
   hmac_sha256_4way_context ctx;
   hmac_sha256_4way_init( &ctx, K, Klen );
   hmac_sha256_4way_update( &ctx, in, len );
   hmac_sha256_4way_close( &ctx, digest );
}

/* Initialize an HMAC-SHA256 operation with the given key. */
void
hmac_sha256_4way_init( hmac_sha256_4way_context *ctx, const void *_K,
                       size_t Klen )
{
	unsigned char pad[64*4] __attribute__ ((aligned (64)));
	unsigned char khash[32*4] __attribute__ ((aligned (64)));
	const unsigned char * K = _K;
	size_t i;

	/* If Klen > 64, the key is really SHA256(K). */
	if ( Klen > 64 )
   {
		sha256_4way_init( &ctx->ictx );
		sha256_4way_update( &ctx->ictx, K, Klen );
		sha256_4way_close( &ctx->ictx, khash );
		K = khash;
		Klen = 32;
	}

	/* Inner SHA256 operation is SHA256(K xor [block of 0x36] || data). */
   sha256_4way_init( &ctx->ictx );
	memset( pad, 0x36, 64*4 );

   for ( i = 0; i < Klen; i++ )
		casti_m128i( pad, i ) = _mm_xor_si128( casti_m128i( pad, i ),
                                             casti_m128i( K, i ) );

   sha256_4way_update( &ctx->ictx, pad, 64 );

	/* Outer SHA256 operation is SHA256(K xor [block of 0x5c] || hash). */
	sha256_4way_init( &ctx->octx );
	memset( pad, 0x5c, 64*4 );
	for ( i = 0; i < Klen/4; i++ )
		casti_m128i( pad, i ) = _mm_xor_si128( casti_m128i( pad, i ),
                                             casti_m128i( K, i ) );
	sha256_4way_update( &ctx->octx, pad, 64 );
}

/* Add bytes to the HMAC-SHA256 operation. */
void
hmac_sha256_4way_update( hmac_sha256_4way_context *ctx, const void *in,
                         size_t len )
{
	/* Feed data to the inner SHA256 operation. */
	sha256_4way_update( &ctx->ictx, in, len );
}

/* Finish an HMAC-SHA256 operation. */
void
hmac_sha256_4way_close( hmac_sha256_4way_context *ctx, void *digest )
{
	unsigned char ihash[32*4] __attribute__ ((aligned (64)));

	/* Finish the inner SHA256 operation. */
	sha256_4way_close( &ctx->ictx, ihash );

	/* Feed the inner hash to the outer SHA256 operation. */
	sha256_4way_update( &ctx->octx, ihash, 32 );

	/* Finish the outer SHA256 operation. */
	sha256_4way_close( &ctx->octx, digest );
}

/**
 * PBKDF2_SHA256(passwd, passwdlen, salt, saltlen, c, buf, dkLen):
 * Compute PBKDF2(passwd, salt, c, dkLen) using HMAC-SHA256 as the PRF, and
 * write the output to buf.  The value dkLen must be at most 32 * (2^32 - 1).
 */
void
pbkdf2_sha256_4way( uint8_t *buf, size_t dkLen,
                    const uint8_t *passwd, size_t passwdlen,
                    const uint8_t *salt, size_t saltlen, uint64_t c )
{
	hmac_sha256_4way_context PShctx, hctx;
	uint8_t _ALIGN(128) T[32*4];
	uint8_t _ALIGN(128) U[32*4];
   __m128i ivec;
   size_t i, clen;
	uint64_t j;
	int k;

	/* Compute HMAC state after processing P and S. */
	hmac_sha256_4way_init( &PShctx, passwd, passwdlen );
	hmac_sha256_4way_update( &PShctx, salt, saltlen );

	/* Iterate through the blocks. */
	for ( i = 0; i * 32 < dkLen; i++ )
   {
		/* Generate INT(i + 1). */
      ivec = _mm_set1_epi32( bswap_32( i+1 ) ); 

		/* Compute U_1 = PRF(P, S || INT(i)). */
		memcpy( &hctx, &PShctx, sizeof(hmac_sha256_4way_context) );
		hmac_sha256_4way_update( &hctx, &ivec, 4 );
		hmac_sha256_4way_close( &hctx, U );

		/* T_i = U_1 ... */
		memcpy( T, U, 32*4 );

		for ( j = 2; j <= c; j++ )
      {
			/* Compute U_j. */
			hmac_sha256_4way_init( &hctx, passwd, passwdlen );
			hmac_sha256_4way_update( &hctx, U, 32 );
			hmac_sha256_4way_close( &hctx, U );

			/* ... xor U_j ... */
			for ( k = 0; k < 8; k++ )
				casti_m128i( T, k ) = _mm_xor_si128( casti_m128i( T, k ),
                                                 casti_m128i( U, k ) );
		}

		/* Copy as many bytes as necessary into buf. */
		clen = dkLen - i * 32;
		if ( clen > 32 )
			clen = 32;
		memcpy( &buf[ i*32*4 ], T, clen*4 );
	}
}

#if defined(__AVX2__)

// HMAC 8-way AVX2

void
hmac_sha256_8way_full( void *digest, const void *K, size_t Klen,
                       const void *in, size_t len )
{
   hmac_sha256_8way_context ctx;
   hmac_sha256_8way_init( &ctx, K, Klen );
   hmac_sha256_8way_update( &ctx, in, len );
   hmac_sha256_8way_close( &ctx, digest );
}

/* Initialize an HMAC-SHA256 operation with the given key. */
void
hmac_sha256_8way_init( hmac_sha256_8way_context *ctx, const void *_K,
                       size_t Klen )
{
   unsigned char pad[64*8] __attribute__ ((aligned (128)));
   unsigned char khash[32*8] __attribute__ ((aligned (128)));
   const unsigned char * K = _K;
   size_t i;

   /* If Klen > 64, the key is really SHA256(K). */
   if ( Klen > 64 )
   {
      sha256_8way_init( &ctx->ictx );
      sha256_8way_update( &ctx->ictx, K, Klen );
      sha256_8way_close( &ctx->ictx, khash );
      K = khash;
      Klen = 32;
   }

   /* Inner SHA256 operation is SHA256(K xor [block of 0x36] || data). */
   sha256_8way_init( &ctx->ictx );
   memset( pad, 0x36, 64*8);

   for ( i = 0; i < Klen/4; i++ )
      casti_m256i( pad, i ) = _mm256_xor_si256( casti_m256i( pad, i ),
                                                casti_m256i( K, i ) );

   sha256_8way_update( &ctx->ictx, pad, 64 );

   /* Outer SHA256 operation is SHA256(K xor [block of 0x5c] || hash). */
   sha256_8way_init( &ctx->octx );
   memset( pad, 0x5c, 64*8 );
   for ( i = 0; i < Klen/4; i++ )
      casti_m256i( pad, i ) = _mm256_xor_si256( casti_m256i( pad, i ),
                                                casti_m256i( K, i ) );
   sha256_8way_update( &ctx->octx, pad, 64 );
}

void
hmac_sha256_8way_update( hmac_sha256_8way_context *ctx, const void *in,
                         size_t len )
{
   /* Feed data to the inner SHA256 operation. */
   sha256_8way_update( &ctx->ictx, in, len );
}

/* Finish an HMAC-SHA256 operation. */
void
hmac_sha256_8way_close( hmac_sha256_8way_context *ctx, void *digest )
{
   unsigned char ihash[32*8] __attribute__ ((aligned (128)));

   /* Finish the inner SHA256 operation. */
   sha256_8way_close( &ctx->ictx, ihash );

   /* Feed the inner hash to the outer SHA256 operation. */
   sha256_8way_update( &ctx->octx, ihash, 32 );

   /* Finish the outer SHA256 operation. */
   sha256_8way_close( &ctx->octx, digest );
}

/**
 * PBKDF2_SHA256(passwd, passwdlen, salt, saltlen, c, buf, dkLen):
 * Compute PBKDF2(passwd, salt, c, dkLen) using HMAC-SHA256 as the PRF, and
 * write the output to buf.  The value dkLen must be at most 32 * (2^32 - 1).
 */
void
pbkdf2_sha256_8way( uint8_t *buf, size_t dkLen, const uint8_t *passwd,
                    size_t passwdlen, const uint8_t *salt, size_t saltlen,
                    uint64_t c )
{
   hmac_sha256_8way_context PShctx, hctx;
   uint8_t _ALIGN(128) T[32*8];
   uint8_t _ALIGN(128) U[32*8];
   size_t i, clen;
   uint64_t j;
   int k;

   /* Compute HMAC state after processing P and S. */
   hmac_sha256_8way_init( &PShctx, passwd, passwdlen );

// saltlen can be odd number of bytes
   hmac_sha256_8way_update( &PShctx, salt, saltlen );

   /* Iterate through the blocks. */
   for ( i = 0; i * 32 < dkLen; i++ )
   {
      __m256i ivec = _mm256_set1_epi32( bswap_32( i+1 ) );

      /* Compute U_1 = PRF(P, S || INT(i)). */
      memcpy( &hctx, &PShctx, sizeof(hmac_sha256_8way_context) );
      hmac_sha256_8way_update( &hctx, &ivec, 4 );
      hmac_sha256_8way_close( &hctx, U );

      /* T_i = U_1 ... */
      memcpy( T, U, 32*8 );

      for ( j = 2; j <= c; j++ )
      {
         /* Compute U_j. */
         hmac_sha256_8way_init( &hctx, passwd, passwdlen );
         hmac_sha256_8way_update( &hctx, U, 32 );
         hmac_sha256_8way_close( &hctx, U );

         /* ... xor U_j ... */
         for ( k = 0; k < 8; k++ )
            casti_m256i( T, k ) = _mm256_xor_si256( casti_m256i( T, k ),
                                                    casti_m256i( U, k ) );
      }

      /* Copy as many bytes as necessary into buf. */
      clen = dkLen - i * 32;
      if ( clen > 32 )
         clen = 32;
      memcpy( &buf[ i*32*8 ], T, clen*8 );
   }
}

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

// HMAC 16-way AVX512

void
hmac_sha256_16way_full( void *digest, const void *K, size_t Klen,
                        const void *in, size_t len )
{
   hmac_sha256_16way_context ctx;
   hmac_sha256_16way_init( &ctx, K, Klen );
   hmac_sha256_16way_update( &ctx, in, len );
   hmac_sha256_16way_close( &ctx, digest );
}

void
hmac_sha256_16way_init( hmac_sha256_16way_context *ctx, const void *_K,
                       size_t Klen )
{
   unsigned char pad[64*16] __attribute__ ((aligned (128)));
   unsigned char khash[32*16] __attribute__ ((aligned (128)));
   const unsigned char * K = _K;
   size_t i;

   /* If Klen > 64, the key is really SHA256(K). */
   if ( Klen > 64 )
   {
      sha256_16way_init( &ctx->ictx );
      sha256_16way_update( &ctx->ictx, K, Klen );
      sha256_16way_close( &ctx->ictx, khash );
      K = khash;
      Klen = 32;
   }

   /* Inner SHA256 operation is SHA256(K xor [block of 0x36] || data). */
   sha256_16way_init( &ctx->ictx );
   memset( pad, 0x36, 64*16 );

   for ( i = 0; i < Klen; i++ )
      casti_m512i( pad, i ) = _mm512_xor_si512( casti_m512i( pad, i ),
                                                casti_m512i( K, i ) );
   sha256_16way_update( &ctx->ictx, pad, 64 );

   /* Outer SHA256 operation is SHA256(K xor [block of 0x5c] || hash). */
   sha256_16way_init( &ctx->octx );
   memset( pad, 0x5c, 64*16 );
   for ( i = 0; i < Klen/4; i++ )
      casti_m512i( pad, i ) = _mm512_xor_si512( casti_m512i( pad, i ),
                                             casti_m512i( K, i ) );
   sha256_16way_update( &ctx->octx, pad, 64 );
}
   
void
hmac_sha256_16way_update( hmac_sha256_16way_context *ctx, const void *in,
                         size_t len )
{
   /* Feed data to the inner SHA256 operation. */
   sha256_16way_update( &ctx->ictx, in, len );
}

/* Finish an HMAC-SHA256 operation. */
void
hmac_sha256_16way_close( hmac_sha256_16way_context *ctx, void *digest )
{
   unsigned char ihash[32*16] __attribute__ ((aligned (128)));

   /* Finish the inner SHA256 operation. */
   sha256_16way_close( &ctx->ictx, ihash );

   /* Feed the inner hash to the outer SHA256 operation. */
   sha256_16way_update( &ctx->octx, ihash, 32 );

   /* Finish the outer SHA256 operation. */
   sha256_16way_close( &ctx->octx, digest );
}

/**
 * PBKDF2_SHA256(passwd, passwdlen, salt, saltlen, c, buf, dkLen):
 * Compute PBKDF2(passwd, salt, c, dkLen) using HMAC-SHA256 as the PRF, and
 * write the output to buf.  The value dkLen must be at most 32 * (2^32 - 1).
 */
void
pbkdf2_sha256_16way( uint8_t *buf, size_t dkLen,
                     const uint8_t *passwd, size_t passwdlen,
                     const uint8_t *salt, size_t saltlen, uint64_t c )
{
   hmac_sha256_16way_context PShctx, hctx;
   uint8_t _ALIGN(128) T[32*16];
   uint8_t _ALIGN(128) U[32*16];
   __m512i ivec;
   size_t i, clen;
   uint64_t j;
   int k;

   /* Compute HMAC state after processing P and S. */
   hmac_sha256_16way_init( &PShctx, passwd, passwdlen );
   hmac_sha256_16way_update( &PShctx, salt, saltlen );

   /* Iterate through the blocks. */
   for ( i = 0; i * 32 < dkLen; i++ )
   {
      /* Generate INT(i + 1). */
      ivec = _mm512_set1_epi32( bswap_32( i+1 ) );

      /* Compute U_1 = PRF(P, S || INT(i)). */
      memcpy( &hctx, &PShctx, sizeof(hmac_sha256_16way_context) );
      hmac_sha256_16way_update( &hctx, &ivec, 4 );
      hmac_sha256_16way_close( &hctx, U );

      /* T_i = U_1 ... */
      memcpy( T, U, 32*16 );

      for ( j = 2; j <= c; j++ )
      {
         /* Compute U_j. */
         hmac_sha256_16way_init( &hctx, passwd, passwdlen );
         hmac_sha256_16way_update( &hctx, U, 32 );
         hmac_sha256_16way_close( &hctx, U );

         /* ... xor U_j ... */
         for ( k = 0; k < 8; k++ )
            casti_m512i( T, k ) = _mm512_xor_si512( casti_m512i( T, k ),
                                                    casti_m512i( U, k ) );
      }

      /* Copy as many bytes as necessary into buf. */
      clen = dkLen - i * 32;
      if ( clen > 32 )
         clen = 32;
      memcpy( &buf[ i*32*16 ], T, clen*16 );
   }
}

#endif  // AVX512
#endif  // AVX2

