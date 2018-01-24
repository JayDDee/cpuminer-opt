/* CubeHash 16/32 is recommended for SHA-3 "normal", 16/1 for "formal" */
#define CUBEHASH_ROUNDS	16
#define CUBEHASH_BLOCKBYTES 32
#define OPTIMIZE_SSE2
#if defined(OPTIMIZE_SSE2)
#include <emmintrin.h>
#endif
#ifdef __AVX2__
#include <immintrin.h>
#endif
#include "cubehash_sse2.h"
#include "algo/sha/sha3-defs.h"
#include <stdbool.h>
#include <unistd.h>
#include <memory.h>
#include "avxdefs.h"

static void transform( cubehashParam *sp )
{
    int r;
    const int rounds = sp->rounds;

#ifdef __AVX2__

    __m256i x0, x1, x2, x3, y0, y1;

    x0 = _mm256_load_si256( (__m256i*)sp->x     );
    x1 = _mm256_load_si256( (__m256i*)sp->x + 1 );   
    x2 = _mm256_load_si256( (__m256i*)sp->x + 2 );
    x3 = _mm256_load_si256( (__m256i*)sp->x + 3 );

    for ( r = 0; r < rounds; ++r )
    { 
        x2 = _mm256_add_epi32( x0, x2 );
        x3 = _mm256_add_epi32( x1, x3 );
        y0 = x1;
        y1 = x0;
        x0 = _mm256_xor_si256( _mm256_slli_epi32( y0, 7 ),
                               _mm256_srli_epi32( y0, 25 ) );
        x1 = _mm256_xor_si256( _mm256_slli_epi32( y1, 7 ),
                               _mm256_srli_epi32( y1, 25 ) );
        x0 = _mm256_xor_si256( x0, x2 );
        x1 = _mm256_xor_si256( x1, x3 );
        x2 = _mm256_shuffle_epi32( x2, 0x4e );
        x3 = _mm256_shuffle_epi32( x3, 0x4e );
        x2 = _mm256_add_epi32( x0, x2 );
        x3 = _mm256_add_epi32( x1, x3 );
        y0 = _mm256_permute2f128_si256( x0, x0, 1 );
        y1 = _mm256_permute2f128_si256( x1, x1, 1 );
        x0 = _mm256_xor_si256( _mm256_slli_epi32( y0, 11 ),
                               _mm256_srli_epi32( y0, 21 ) );
        x1 = _mm256_xor_si256( _mm256_slli_epi32( y1, 11 ), 
                               _mm256_srli_epi32( y1, 21 ) );
        x0 = _mm256_xor_si256( x0, x2 );
        x1 = _mm256_xor_si256( x1, x3 );
        x2 = _mm256_shuffle_epi32( x2, 0xb1 );
        x3 = _mm256_shuffle_epi32( x3, 0xb1 );
    }

    _mm256_store_si256( (__m256i*)sp->x,     x0 );
    _mm256_store_si256( (__m256i*)sp->x + 1, x1 );
    _mm256_store_si256( (__m256i*)sp->x + 2, x2 );
    _mm256_store_si256( (__m256i*)sp->x + 3, x3 );

#else
    __m128i x0, x1, x2, x3, x4, x5, x6, x7, y0, y1, y2, y3;

    x0 = _mm_load_si128( (__m128i*)sp->x     );
    x1 = _mm_load_si128( (__m128i*)sp->x + 1 );
    x2 = _mm_load_si128( (__m128i*)sp->x + 2 );
    x3 = _mm_load_si128( (__m128i*)sp->x + 3 );
    x4 = _mm_load_si128( (__m128i*)sp->x + 4 );
    x5 = _mm_load_si128( (__m128i*)sp->x + 5 );
    x6 = _mm_load_si128( (__m128i*)sp->x + 6 );
    x7 = _mm_load_si128( (__m128i*)sp->x + 7 );

    for (r = 0; r < rounds; ++r) {
	x4 = _mm_add_epi32(x0, x4);
	x5 = _mm_add_epi32(x1, x5);
	x6 = _mm_add_epi32(x2, x6);
	x7 = _mm_add_epi32(x3, x7);
	y0 = x2;
	y1 = x3;
	y2 = x0;
	y3 = x1;
	x0 = _mm_xor_si128(_mm_slli_epi32(y0, 7), _mm_srli_epi32(y0, 25));
	x1 = _mm_xor_si128(_mm_slli_epi32(y1, 7), _mm_srli_epi32(y1, 25));
	x2 = _mm_xor_si128(_mm_slli_epi32(y2, 7), _mm_srli_epi32(y2, 25));
	x3 = _mm_xor_si128(_mm_slli_epi32(y3, 7), _mm_srli_epi32(y3, 25));
	x0 = _mm_xor_si128(x0, x4);
	x1 = _mm_xor_si128(x1, x5);
	x2 = _mm_xor_si128(x2, x6);
	x3 = _mm_xor_si128(x3, x7);
	x4 = _mm_shuffle_epi32(x4, 0x4e);
	x5 = _mm_shuffle_epi32(x5, 0x4e);
	x6 = _mm_shuffle_epi32(x6, 0x4e);
	x7 = _mm_shuffle_epi32(x7, 0x4e);
	x4 = _mm_add_epi32(x0, x4);
	x5 = _mm_add_epi32(x1, x5);
	x6 = _mm_add_epi32(x2, x6);
	x7 = _mm_add_epi32(x3, x7);
	y0 = x1;
	y1 = x0;
	y2 = x3;
	y3 = x2;
	x0 = _mm_xor_si128(_mm_slli_epi32(y0, 11), _mm_srli_epi32(y0, 21));
	x1 = _mm_xor_si128(_mm_slli_epi32(y1, 11), _mm_srli_epi32(y1, 21));
	x2 = _mm_xor_si128(_mm_slli_epi32(y2, 11), _mm_srli_epi32(y2, 21));
	x3 = _mm_xor_si128(_mm_slli_epi32(y3, 11), _mm_srli_epi32(y3, 21));
	x0 = _mm_xor_si128(x0, x4);
	x1 = _mm_xor_si128(x1, x5);
	x2 = _mm_xor_si128(x2, x6);
	x3 = _mm_xor_si128(x3, x7);
	x4 = _mm_shuffle_epi32(x4, 0xb1);
	x5 = _mm_shuffle_epi32(x5, 0xb1);
	x6 = _mm_shuffle_epi32(x6, 0xb1);
	x7 = _mm_shuffle_epi32(x7, 0xb1);
    }

    _mm_store_si128( (__m128i*)sp->x,     x0 );
    _mm_store_si128( (__m128i*)sp->x + 1, x1 );
    _mm_store_si128( (__m128i*)sp->x + 2, x2 );
    _mm_store_si128( (__m128i*)sp->x + 3, x3 );
    _mm_store_si128( (__m128i*)sp->x + 4, x4 );
    _mm_store_si128( (__m128i*)sp->x + 5, x5 );
    _mm_store_si128( (__m128i*)sp->x + 6, x6 );
    _mm_store_si128( (__m128i*)sp->x + 7, x7 );

#endif
}  // transform

// Ccubehash context initializing is very expensive.
// Cache the intial value for faster reinitializing.
cubehashParam cube_ctx_cache __attribute__ ((aligned (64)));

int cubehashReinit( cubehashParam *sp )
{
   memcpy( sp, &cube_ctx_cache, sizeof(cubehashParam) );
   return SUCCESS;

}

// Initialize the cache then copy to sp.
int cubehashInit(cubehashParam *sp, int hashbitlen, int rounds, int blockbytes)
{
    int i;

    if ( hashbitlen < 8 ) return BAD_HASHBITLEN;
    if ( hashbitlen > 512 ) return BAD_HASHBITLEN;
    if ( hashbitlen != 8 * (hashbitlen / 8) ) return BAD_HASHBITLEN;

    /* Sanity checks */
    if ( rounds <= 0 || rounds > 32 )
       rounds = CUBEHASH_ROUNDS;
    if ( blockbytes <= 0 || blockbytes >= 256)
       blockbytes = CUBEHASH_BLOCKBYTES;

    // all sizes of __m128i
    cube_ctx_cache.hashlen   = hashbitlen/128;
    cube_ctx_cache.blocksize = blockbytes/16;
    cube_ctx_cache.rounds    = rounds;
    cube_ctx_cache.pos       = 0;

    for ( i = 0; i < 8; ++i )
       cube_ctx_cache.x[i] = _mm_setzero_si128();;

    cube_ctx_cache.x[0] = _mm_set_epi32( 0, rounds, blockbytes,
                                         hashbitlen / 8 );

    for ( i = 0; i < 10; ++i )
       transform( &cube_ctx_cache );

    memcpy( sp, &cube_ctx_cache, sizeof(cubehashParam) );
    return SUCCESS;
}

int cubehashUpdate( cubehashParam *sp, const byte *data, size_t size )
{
    const int len = size / 16;
    const __m128i* in = (__m128i*)data;
    int i;

    // It is assumed data is aligned to 256 bits and is a multiple of 128 bits.
    // Current usage sata is either 64 or 80 bytes.

    for ( i = 0; i < len; i++ )
    {
        sp->x[ sp->pos ] = _mm_xor_si128( sp->x[ sp->pos ], in[i] );
        sp->pos++;
        if ( sp->pos == sp->blocksize )
        {
           transform( sp );
           sp->pos = 0;
        }
    }

    return SUCCESS;
}

int cubehashDigest( cubehashParam *sp, byte *digest )
{
    __m128i* hash = (__m128i*)digest;
    int i;

    // pos is zero for 64 byte data, 1 for 80 byte data.
    sp->x[ sp->pos ] = _mm_xor_si128( sp->x[ sp->pos ],
                                      _mm_set_epi8( 0,0,0,0, 0,0,0,0,
                                                    0,0,0,0, 0,0,0,0x80 ) );
    transform( sp );

    sp->x[7] = _mm_xor_si128( sp->x[7], _mm_set_epi32( 1,0,0,0 ) );
    transform( sp );
    transform( sp );
    transform( sp );
    transform( sp );
    transform( sp );
    transform( sp );
    transform( sp );
    transform( sp );
    transform( sp );
    transform( sp );

    for ( i = 0; i < sp->hashlen; i++ )
       hash[i] = sp->x[i];

    return SUCCESS;
}

int cubehashUpdateDigest( cubehashParam *sp, byte *digest,
                          const byte *data, size_t size )
{
    const int len = size / 16;
    const __m128i* in = (__m128i*)data;
    __m128i* hash = (__m128i*)digest;
    int i;

    // It is assumed data is aligned to 256 bits and is a multiple of 128 bits.
    // Current usage sata is either 64 or 80 bytes.

    for ( i = 0; i < len; i++ )
    {
        sp->x[ sp->pos ] = _mm_xor_si128( sp->x[ sp->pos ], in[i] );
        sp->pos++;
        if ( sp->pos == sp->blocksize )
        {
           transform( sp );
           sp->pos = 0;
        }
    }

    // pos is zero for 64 byte data, 1 for 80 byte data.
    sp->x[ sp->pos ] = _mm_xor_si128( sp->x[ sp->pos ],
                                      _mm_set_epi8( 0,0,0,0, 0,0,0,0,
                                                    0,0,0,0, 0,0,0,0x80 ) );
    transform( sp );

    sp->x[7] = _mm_xor_si128( sp->x[7], _mm_set_epi32( 1,0,0,0 ) );
    transform( sp );
    transform( sp );
    transform( sp );
    transform( sp );
    transform( sp );
    transform( sp );
    transform( sp );
    transform( sp );
    transform( sp );
    transform( sp );

    for ( i = 0; i < sp->hashlen; i++ )
       hash[i] = sp->x[i];

    return SUCCESS;
}

