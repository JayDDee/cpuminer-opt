/*-
 * Copyright 2009 Colin Percival
 * Copyright 2013-2018 Alexander Peslyak
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
 *
 * This is a proof-of-work focused fork of yescrypt, including reference and
 * cut-down implementation of the obsolete yescrypt 0.5 (based off its first
 * submission to PHC back in 2014) and a new proof-of-work specific variation
 * known as yespower 1.0.  The former is intended as an upgrade for
 * cryptocurrencies that already use yescrypt 0.5 and the latter may be used
 * as a further upgrade (hard fork) by those and other cryptocurrencies.  The
 * version of algorithm to use is requested through parameters, allowing for
 * both algorithms to co-exist in client and miner implementations (such as in
 * preparation for a hard-fork).
 *
 * This is the reference implementation.  Its purpose is to provide a simple
 * human- and machine-readable specification that implementations intended
 * for actual use should be tested against.  It is deliberately mostly not
 * optimized, and it is not meant to be used in production.  Instead, use
 * yespower-opt.c.
 */
/*
#warning "This reference implementation is deliberately mostly not optimized. Use yespower-opt.c instead unless you're testing (against) the reference implementation on purpose."
*/
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "algo/sha/hmac-sha256-hash-4way.h"
//#include "sysendian.h"

#include "yespower.h"


#if defined(__AVX2__)


static void blkcpy_8way( __m256i *dst, const __m256i *src, size_t count )
{
	do {
		*dst++ = *src++;
	} while (--count);
}

static void blkxor_8way( __m256i *dst, const __m256i *src, size_t count )
{
	do {
		*dst++ ^= *src++;
	} while (--count);
}

/**
 * salsa20(B):
 * Apply the Salsa20 core to the provided block.
 */
static void salsa20_8way( __m256i B[16], uint32_t rounds )
{
	__m256i x[16];
	size_t i;

	/* SIMD unshuffle */
	for ( i = 0; i < 16; i++ )
		x[i * 5 % 16] = B[i];

	for ( i = 0; i < rounds; i += 2 )
   {
#define R( a, b, c ) mm256_rol_32( _mm256_add_epi32( a, b ), c )
      /* Operate on columns */

      x[ 4] = _mm256_xor_si256( x[ 4], R( x[ 0], x[12],  7 ) );
      x[ 8] = _mm256_xor_si256( x[ 8], R( x[ 4], x[ 0],  9 ) );
      x[12] = _mm256_xor_si256( x[12], R( x[ 8], x[ 4], 13 ) );
      x[ 0] = _mm256_xor_si256( x[ 0], R( x[12], x[ 8], 18 ) );

      x[ 9] = _mm256_xor_si256( x[ 9], R( x[ 5], x[ 1],  7 ) );
      x[13] = _mm256_xor_si256( x[13], R( x[ 9], x[ 5],  9 ) );
      x[ 1] = _mm256_xor_si256( x[ 1], R( x[13], x[ 9], 13 ) );
      x[ 5] = _mm256_xor_si256( x[ 5], R( x[ 1], x[13], 18 ) );

      x[14] = _mm256_xor_si256( x[14], R( x[10], x[ 6],  7 ) );
      x[ 2] = _mm256_xor_si256( x[ 2], R( x[14], x[10],  9 ) );
      x[ 6] = _mm256_xor_si256( x[ 6], R( x[ 2], x[14], 13 ) );
      x[10] = _mm256_xor_si256( x[10], R( x[ 6], x[ 2], 18 ) );

      x[ 3] = _mm256_xor_si256( x[ 3], R( x[15], x[11],  7 ) );
      x[ 7] = _mm256_xor_si256( x[ 7], R( x[ 3], x[15],  9 ) );
      x[11] = _mm256_xor_si256( x[11], R( x[ 7], x[ 3], 13 ) );
      x[15] = _mm256_xor_si256( x[15], R( x[11], x[ 7], 18 ) );

		/* Operate on rows */

      x[ 1] = _mm256_xor_si256( x[ 1], R( x[ 0], x[ 3],  7 ) );
      x[ 2] = _mm256_xor_si256( x[ 2], R( x[ 1], x[ 0],  9 ) );
      x[ 3] = _mm256_xor_si256( x[ 3], R( x[ 2], x[ 1], 13 ) );
      x[ 0] = _mm256_xor_si256( x[ 0], R( x[ 3], x[ 2], 18 ) );

      x[ 6] = _mm256_xor_si256( x[ 6], R( x[ 5], x[ 4],  7 ) );
      x[ 7] = _mm256_xor_si256( x[ 7], R( x[ 6], x[ 5],  9 ) );
      x[ 4] = _mm256_xor_si256( x[ 4], R( x[ 7], x[ 6], 13 ) );
      x[ 5] = _mm256_xor_si256( x[ 5], R( x[ 4], x[ 7], 18 ) );

      x[11] = _mm256_xor_si256( x[11], R( x[10], x[ 9],  7 ) );
      x[ 8] = _mm256_xor_si256( x[ 8], R( x[11], x[10],  9 ) );
      x[ 9] = _mm256_xor_si256( x[ 9], R( x[ 8], x[11], 13 ) );
      x[10] = _mm256_xor_si256( x[10], R( x[ 9], x[ 8], 18 ) );

      x[12] = _mm256_xor_si256( x[12], R( x[15], x[14],  7 ) );
      x[13] = _mm256_xor_si256( x[13], R( x[12], x[15],  9 ) );
      x[14] = _mm256_xor_si256( x[14], R( x[13], x[12], 13 ) );
      x[15] = _mm256_xor_si256( x[15], R( x[14], x[13], 18 ) );

#undef R
	}

	/* SIMD shuffle */
	for (i = 0; i < 16; i++)
		B[i] = _mm256_add_epi32( B[i], x[i * 5 % 16] );
}

/**
 * blockmix_salsa(B):
 * Compute B = BlockMix_{salsa20, 1}(B).  The input B must be 128 bytes in
 * length.
 */
static void blockmix_salsa_8way( __m256i *B, uint32_t rounds )
{
	__m256i X[16];
	size_t i;

	/* 1: X <-- B_{2r - 1} */
	blkcpy_8way( X, &B[16], 16 );

	/* 2: for i = 0 to 2r - 1 do */
	for ( i = 0; i < 2; i++ )
   {
		/* 3: X <-- H(X xor B_i) */
		blkxor_8way( X, &B[i * 16], 16 );
		salsa20_8way( X, rounds );

		/* 4: Y_i <-- X */
		/* 6: B' <-- (Y_0, Y_2 ... Y_{2r-2}, Y_1, Y_3 ... Y_{2r-1}) */
		blkcpy_8way( &B[i * 16], X, 16 );
	}
}

/*
 * These are tunable, but they must meet certain constraints and are part of
 * what defines a yespower version.
 */
#define PWXsimple 2
#define PWXgather 4
/* Version 0.5 */
#define PWXrounds_0_5 6
#define Swidth_0_5 8
/* Version 1.0 */
#define PWXrounds_1_0 3
#define Swidth_1_0 11

/* Derived values.  Not tunable on their own. */
#define PWXbytes (PWXgather * PWXsimple * 8)
#define PWXwords (PWXbytes / sizeof(uint32_t))
#define rmin ((PWXbytes + 127) / 128)

/* Runtime derived values.  Not tunable on their own. */
#define Swidth_to_Sbytes1(Swidth) ((1 << Swidth) * PWXsimple * 8)
#define Swidth_to_Smask(Swidth) (((1 << Swidth) - 1) * PWXsimple * 8)

typedef struct {
   __m256i (*S0)[2], (*S1)[2], (*S2)[2];
   __m256i *S;
	yespower_version_t version;
	uint32_t salsa20_rounds;
	uint32_t PWXrounds, Swidth, Sbytes, Smask;
	size_t w;
} pwxform_8way_ctx_t __attribute__ ((aligned (128)));

/**
 * pwxform(B):
 * Transform the provided block using the provided S-boxes.
 */
static void pwxform_8way( __m256i *B, pwxform_8way_ctx_t *ctx )
{
	__m256i (*X)[PWXsimple][2] = (__m256i (*)[PWXsimple][2])B;
	__m256i (*S0)[2] = ctx->S0, (*S1)[2] = ctx->S1, (*S2)[2] = ctx->S2;
	__m256i Smask = _mm256_set1_epi32( ctx->Smask );
	size_t w = ctx->w;
	size_t i, j, k;

	/* 1: for i = 0 to PWXrounds - 1 do */
	for ( i = 0; i < ctx->PWXrounds; i++ )
   {
		/* 2: for j = 0 to PWXgather - 1 do */
		for ( j = 0; j < PWXgather; j++ )
      {
// Are these pointers or data?
         __m256i xl = X[j][0][0];
			__m256i xh = X[j][0][1];
			__m256i (*p0)[2], (*p1)[2];

			// 3: p0 <-- (lo(B_{j,0}) & Smask) / (PWXsimple * 8) 

// playing with pointers
/*
         p0 = S0 + (xl & Smask) / sizeof(*S0);
			// 4: p1 <-- (hi(B_{j,0}) & Smask) / (PWXsimple * 8) 
			p1 = S1 + (xh & Smask) / sizeof(*S1);
*/
			/* 5: for k = 0 to PWXsimple - 1 do */
			for ( k = 0; k < PWXsimple; k++ )
         {

// shift from 32 bit data to 64 bit data
            __m256i x0, x1, s00, s01, s10, s11;
            __m128i *p0k = (__m128i*)p0[k];
            __m128i *p1k = (__m128i*)p1[k];


           s00 = _mm256_add_epi64( _mm256_cvtepu32_epi64( p0k[0] ),
                _mm256_slli_epi64( _mm256_cvtepu32_epi64( p0k[2] ), 32 ) );
           s01 = _mm256_add_epi64( _mm256_cvtepu32_epi64( p0k[1] ),
                _mm256_slli_epi64( _mm256_cvtepu32_epi64( p0k[3] ), 32 ) );
           s10 = _mm256_add_epi64( _mm256_cvtepu32_epi64( p1k[0] ),
                _mm256_slli_epi64( _mm256_cvtepu32_epi64( p1k[2] ), 32 ) );
           s11 = _mm256_add_epi64( _mm256_cvtepu32_epi64( p1k[1] ),
                _mm256_slli_epi64( _mm256_cvtepu32_epi64( p1k[3] ), 32 ) );

            __m128i *xx = (__m128i*)X[j][k];
            x0 = _mm256_mul_epu32( _mm256_cvtepu32_epi64( xx[0] ),
                                   _mm256_cvtepu32_epi64( xx[2] ) );
            x1 = _mm256_mul_epu32( _mm256_cvtepu32_epi64( xx[1] ),
                                   _mm256_cvtepu32_epi64( xx[3] ) );

            x0 = _mm256_add_epi64( x0, s00 );
            x1 = _mm256_add_epi64( x1, s01 );
            
            x0 = _mm256_xor_si256( x0, s10 );
            x1 = _mm256_xor_si256( x1, s11 );

            X[j][k][0] = x0; 
            X[j][k][1] = x1;                        
			}

			if ( ctx->version != YESPOWER_0_5 &&
			    ( i == 0 || j < PWXgather / 2 ) )
         {
				if ( j & 1 )
            {
					for ( k = 0; k < PWXsimple; k++ )
               {
						S1[w][0] = X[j][k][0];
						S1[w][1] = X[j][k][1];
						w++;
					}
				}
            else
            {
					for ( k = 0; k < PWXsimple; k++ )
               {
						S0[w + k][0] = X[j][k][0];
						S0[w + k][1] = X[j][k][1];
					}
				}
			}
		}
	}

	if ( ctx->version != YESPOWER_0_5 )
   {
		/* 14: (S0, S1, S2) <-- (S2, S0, S1) */
		ctx->S0 = S2;
		ctx->S1 = S0;
		ctx->S2 = S1;
		/* 15: w <-- w mod 2^Swidth */
		ctx->w = w & ( ( 1 << ctx->Swidth ) * PWXsimple - 1 );
	}
}

/**
 * blockmix_pwxform(B, ctx, r):
 * Compute B = BlockMix_pwxform{salsa20, ctx, r}(B).  The input B must be
 * 128r bytes in length.
 */
static void blockmix_pwxform_8way( uint32_t *B, pwxform_8way_ctx_t *ctx,
                                   size_t r )
{
	__m256i X[PWXwords];
	size_t r1, i;

	/* Convert 128-byte blocks to PWXbytes blocks */
	/* 1: r_1 <-- 128r / PWXbytes */
	r1 = 128 * r / PWXbytes;

	/* 2: X <-- B'_{r_1 - 1} */
	blkcpy_8way( X, &B[ (r1 - 1) * PWXwords ], PWXwords );

	/* 3: for i = 0 to r_1 - 1 do */
	for ( i = 0; i < r1; i++ )
   {
		/* 4: if r_1 > 1 */
		if ( r1 > 1 )
      {
			/* 5: X <-- X xor B'_i */
			blkxor_8way( X, &B[ i * PWXwords ], PWXwords );
		}

		/* 7: X <-- pwxform(X) */
		pwxform_8way( X, ctx );

		/* 8: B'_i <-- X */
		blkcpy_8way( &B[ i * PWXwords ], X, PWXwords );
	}

	/* 10: i <-- floor((r_1 - 1) * PWXbytes / 64) */
	i = ( r1 - 1 ) * PWXbytes / 64;

	/* 11: B_i <-- H(B_i) */
	salsa20_8way( &B[i * 16], ctx->salsa20_rounds );

#if 1 /* No-op with our current pwxform settings, but do it to make sure */
	/* 12: for i = i + 1 to 2r - 1 do */
	for ( i++; i < 2 * r; i++ )
   {
		/* 13: B_i <-- H(B_i xor B_{i-1}) */
		blkxor_8way( &B[i * 16], &B[ (i - 1) * 16 ], 16 );
		salsa20_8way( &B[i * 16], ctx->salsa20_rounds );
	}
#endif
}

// This looks a lot like data dependent addressing

/**
 * integerify(B, r):
 * Return the result of parsing B_{2r-1} as a little-endian integer.
 */
static __m256i integerify8( const __m256i *B, size_t r )
{
/*
 * Our 32-bit words are in host byte order.  Also, they are SIMD-shuffled, but
 * we only care about the least significant 32 bits anyway.
 */
	const __m256i *X = &B[ (2 * r - 1) * 16 ];
	return X[0];
}

/**
 * p2floor(x):
 * Largest power of 2 not greater than argument.
 */
static uint32_t p2floor8( uint32_t x )
{
	uint32_t y;
	while ( ( y = x & (x - 1) ) )
		x = y;
	return x;
}

/**
 * wrap(x, i):
 * Wrap x to the range 0 to i-1.
 */
static uint32_t wrap8( uint32_t x, uint32_t i )
{
	uint32_t n = p2floor( i );
	return ( x & (n - 1) ) + (i - n);
}

/**
 * smix1(B, r, N, V, X, ctx):
 * Compute first loop of B = SMix_r(B, N).  The input B must be 128r bytes in
 * length; the temporary storage V must be 128rN bytes in length; the temporary
 * storage X must be 128r bytes in length.
 */
static void smix1_8way( __m256i *B, size_t r, uint32_t N,
                        __m256i *V, __m256i *X, pwxform_8way_ctx_t *ctx )
{
	size_t s = 32 * r;
	uint32_t i, j;
	size_t k;

	/* 1: X <-- B */
	for ( k = 0; k < 2 * r; k++ )
		for ( i = 0; i < 16; i++ )
			X[ k * 16 + i ] = B[ k * 16 + ( i * 5 % 16 ) ];

	if ( ctx->version != YESPOWER_0_5 )
   {
		for ( k = 1; k < r; k++ )
      {
			blkcpy_8way( &X[k * 32], &X[ (k - 1) * 32 ], 32 );
			blockmix_pwxform_8way( &X[k * 32], ctx, 1 );
		}
	}

	/* 2: for i = 0 to N - 1 do */
	for ( i = 0; i < N; i++ )
   {
		/* 3: V_i <-- X */
		blkcpy_8way( &V[i * s], X, s );

		if ( i > 1 )
      {

// is j int or vector? Integrify has data dependent addressing?

         /* j <-- Wrap(Integerify(X), i) */
//			j = wrap8( integerify8( X, r ), i );

			/* X <-- X xor V_j */
			blkxor_8way( X, &V[j * s], s );
		}

		/* 4: X <-- H(X) */
		if ( V != ctx->S )
			blockmix_pwxform_8way( X, ctx, r );
		else
			blockmix_salsa_8way( X, ctx->salsa20_rounds );
	}

	/* B' <-- X */
	for ( k = 0; k < 2 * r; k++ )
		for ( i = 0; i < 16; i++ )
			B[ k * 16 + ( i * 5 % 16 ) ] = X[ k * 16 + i ];
}

/**
 * smix2(B, r, N, Nloop, V, X, ctx):
 * Compute second loop of B = SMix_r(B, N).  The input B must be 128r bytes in
 * length; the temporary storage V must be 128rN bytes in length; the temporary
 * storage X must be 128r bytes in length.  The value N must be a power of 2
 * greater than 1.
 */
static void smix2_8way( __m256i *B, size_t r, uint32_t N, uint32_t Nloop,
                        __m256i *V, __m256i *X, pwxform_8way_ctx_t *ctx )
{
	size_t s = 32 * r;
	uint32_t i, j;
	size_t k;

	/* X <-- B */
	for ( k = 0; k < 2 * r; k++ )
		for ( i = 0; i < 16; i++ )
			X[ k * 16 + i ] = B[ k * 16 + ( i * 5 % 16 ) ];

	/* 6: for i = 0 to N - 1 do */
	for ( i = 0; i < Nloop; i++ )
   {
		/* 7: j <-- Integerify(X) mod N */
//		j = integerify8(X, r) & (N - 1);

		/* 8.1: X <-- X xor V_j */
		blkxor_8way( X, &V[j * s], s );
		/* V_j <-- X */
		if ( Nloop != 2 )
			blkcpy_8way( &V[j * s], X, s );

		/* 8.2: X <-- H(X) */
		blockmix_pwxform_8way( X, ctx, r );
	}

	/* 10: B' <-- X */
	for ( k = 0; k < 2 * r; k++ )
		for ( i = 0; i < 16; i++ )
			B[ k * 16 + ( i * 5 % 16 ) ] = X[ k * 16 + i ];
}

/**
 * smix(B, r, N, p, t, V, X, ctx):
 * Compute B = SMix_r(B, N).  The input B must be 128rp bytes in length; the
 * temporary storage V must be 128rN bytes in length; the temporary storage
 * X must be 128r bytes in length.  The value N must be a power of 2 and at
 * least 16.
 */
static void smix_8way( __m256i *B, size_t r, uint32_t N,
                       __m256i *V, __m256i *X, pwxform_8way_ctx_t *ctx)
{
	uint32_t Nloop_all = (N + 2) / 3; /* 1/3, round up */
	uint32_t Nloop_rw = Nloop_all;

	Nloop_all++; Nloop_all &= ~(uint32_t)1; /* round up to even */

   if ( ctx->version == YESPOWER_0_5 )
		Nloop_rw &= ~(uint32_t)1; /* round down to even */
	else
		Nloop_rw++; Nloop_rw &= ~(uint32_t)1; /* round up to even */

	smix1_8way( B, 1, ctx->Sbytes / 128, ctx->S, X, ctx );
	smix1_8way( B, r, N, V, X, ctx );
	smix2_8way( B, r, N, Nloop_rw /* must be > 2 */, V, X, ctx );
	smix2_8way( B, r, N, Nloop_all - Nloop_rw /* 0 or 2 */, V, X, ctx );
}

/**
 * yespower(local, src, srclen, params, dst):
 * Compute yespower(src[0 .. srclen - 1], N, r), to be checked for "< target".
 *
 * Return 0 on success; or -1 on error.
 */
int yespower_8way( yespower_local_t *local, const __m256i *src, size_t srclen,
              const yespower_params_t *params, yespower_8way_binary_t *dst,
              int thrid )
{
	yespower_version_t version = params->version;
	uint32_t N = params->N;
	uint32_t r = params->r;
	const uint8_t *pers = params->pers;
	size_t perslen = params->perslen;
	int retval = -1;
	size_t B_size, V_size;
	uint32_t *B, *V, *X, *S;
	pwxform_8way_ctx_t ctx;
	__m256i sha256[8];

	/* Sanity-check parameters */
	if ( (version != YESPOWER_0_5 && version != YESPOWER_1_0 ) ||
	    N < 1024 || N > 512 * 1024 || r < 8 || r > 32 ||
	    (N & (N - 1)) != 0 || r < rmin ||
	    (!pers && perslen) )
   {
		errno = EINVAL;
		return -1;
	}

	/* Allocate memory */
	B_size = (size_t)128 * r;
	V_size = B_size * N;
	if ((V = malloc(V_size)) == NULL)
		return -1;
	if ((B = malloc(B_size)) == NULL)
		goto free_V;
	if ((X = malloc(B_size)) == NULL)
		goto free_B;
	ctx.version = version;
	if (version == YESPOWER_0_5) {
		ctx.salsa20_rounds = 8;
		ctx.PWXrounds = PWXrounds_0_5;
		ctx.Swidth = Swidth_0_5;
		ctx.Sbytes = 2 * Swidth_to_Sbytes1(ctx.Swidth);
	} else {
		ctx.salsa20_rounds = 2;
		ctx.PWXrounds = PWXrounds_1_0;
		ctx.Swidth = Swidth_1_0;
		ctx.Sbytes = 3 * Swidth_to_Sbytes1(ctx.Swidth);
	}
	if ((S = malloc(ctx.Sbytes)) == NULL)
		goto free_X;
	ctx.S = S;
	ctx.S0 = (__m256i (*)[2])S;
	ctx.S1 = ctx.S0 + (1 << ctx.Swidth) * PWXsimple;
	ctx.S2 = ctx.S1 + (1 << ctx.Swidth) * PWXsimple;
	ctx.Smask = Swidth_to_Smask(ctx.Swidth);
	ctx.w = 0;

   // do prehash
	sha256_8way_full( sha256, src, srclen );


  // need flexible size, use malloc;
   __m256i vpers[128];

	if ( version != YESPOWER_0_5 && perslen )
      for ( int i = 0; i < perslen/4 + 1; i++ )
         vpers[i] = _mm256_set1_epi32( pers[i] );

	/* 1: (B_0 ... B_{p-1}) <-- PBKDF2(P, S, 1, p * MFLen) */
	pbkdf2_sha256_8way( B, B_size, sha256, sizeof(sha256), vpers, perslen, 1 );

	blkcpy_8way( sha256, B, sizeof(sha256) / sizeof(sha256[0] ) );

	/* 3: B_i <-- MF(B_i, N) */
	smix_8way( B, r, N, V, X, &ctx );

	if ( version == YESPOWER_0_5 )
   {
		/* 5: DK <-- PBKDF2(P, B, 1, dkLen) */
		pbkdf2_sha256_8way( dst, sizeof(*dst), sha256, sizeof(sha256),
                          B, B_size, 1 );

		if ( pers )
      {
			hmac_sha256_8way_full( dst, sizeof(*dst), vpers, perslen, sha256 );
			sha256_8way_full( dst, sha256, sizeof(sha256) );
		}
	}
   else
		hmac_sha256_8way_full( dst, B + B_size - 64, 64, sha256, sizeof(sha256) );

	/* Success! */
	retval = 1;

	/* Free memory */
	free(S);
free_X:
	free(X);
free_B:
	free(B);
free_V:
	free(V);

	return retval;
}

int yespower_8way_tls( const __m256i *src, size_t srclen,
    const yespower_params_t *params, yespower_8way_binary_t *dst, int trhid )
{
/* The reference implementation doesn't use thread-local storage */
	return yespower_8way( NULL, src, srclen, params, dst, trhid );
}

int yespower_init_local8( yespower_local_t *local )
{
/* The reference implementation doesn't use the local structure */
	local->base = local->aligned = NULL;
	local->base_size = local->aligned_size = 0;
	return 0;
}

int yespower_free_local8( yespower_local_t *local )
{
/* The reference implementation frees its memory in yespower() */
	(void)local; /* unused */
	return 0;
}

int yespower_8way_hash( const char *input, char *output, uint32_t len,
                        int thrid )
{
   return yespower_8way_tls( input, len, &yespower_params,
           (yespower_binary_t*)output, thrid );
}

int scanhash_yespower_8way( struct work *work, uint32_t max_nonce,
                            uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t _ALIGN(128) hash[8*8];
   uint32_t _ALIGN(128) vdata[20*8];
   uint32_t _ALIGN(128) endiandata[20];
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce;
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;

   for ( int k = 0; k < 19; k++ )
      be32enc( &endiandata[k], pdata[k] );
   endiandata[19] = n;

// do sha256 prehash
   SHA256_Init( &sha256_prehash_ctx );
   SHA256_Update( &sha256_prehash_ctx, endiandata, 64 );

   do {
      if ( yespower_hash( vdata, hash, 80, thr_id ) )
      if unlikely( valid_hash( hash, ptarget ) && !opt_benchmark )
      {
          be32enc( pdata+19, n );
          submit_solution( work, hash, mythr );
      }
      endiandata[19] = ++n;
   } while ( n < last_nonce && !work_restart[thr_id].restart );
   *hashes_done = n - first_nonce;
   pdata[19] = n;
   return 0;
}

#endif  // AVX2
