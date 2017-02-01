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
#include "algo/sha3/sha3-defs.h"

//enum { SUCCESS = 0, FAIL = 1, BAD_HASHBITLEN = 2 };

//#if defined(OPTIMIZE_SSE2)

static void transform( cubehashParam *sp )
{
    int r;
    const int rounds = sp->rounds;

#ifdef __AVX2__

    __m256i x0, x1, x2, x3, y0, y1;

    x0 = _mm256_load_si256( 0 + sp->x );
    x1 = _mm256_load_si256( 2 + sp->x );   
    x2 = _mm256_load_si256( 4 + sp->x );
    x3 = _mm256_load_si256( 6 + sp->x );

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

    _mm256_store_si256( 0 + sp->x, x0 );
    _mm256_store_si256( 2 + sp->x, x1 );
    _mm256_store_si256( 4 + sp->x, x2 );
    _mm256_store_si256( 6 + sp->x, x3 );

#else
    __m128i x0, x1, x2, x3, x4, x5, x6, x7, y0, y1, y2, y3;

    x0 = _mm_load_si128(0 + sp->x);
    x1 = _mm_load_si128(1 + sp->x);
    x2 = _mm_load_si128(2 + sp->x);
    x3 = _mm_load_si128(3 + sp->x);
    x4 = _mm_load_si128(4 + sp->x);
    x5 = _mm_load_si128(5 + sp->x);
    x6 = _mm_load_si128(6 + sp->x);
    x7 = _mm_load_si128(7 + sp->x);

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

    _mm_store_si128(0 + sp->x, x0);
    _mm_store_si128(1 + sp->x, x1);
    _mm_store_si128(2 + sp->x, x2);
    _mm_store_si128(3 + sp->x, x3);
    _mm_store_si128(4 + sp->x, x4);
    _mm_store_si128(5 + sp->x, x5);
    _mm_store_si128(6 + sp->x, x6);
    _mm_store_si128(7 + sp->x, x7);

#endif
}  // transform

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

    sp->hashbitlen = hashbitlen;
    sp->rounds = rounds;
    sp->blockbytes = blockbytes;
    for ( i = 0; i < 8; ++i )
         sp->x[i] = _mm_set_epi32(0, 0, 0, 0);
    sp->x[0] = _mm_set_epi32(0, sp->rounds, sp->blockbytes, hashbitlen / 8);
    for ( i = 0; i < 10; ++i )
         transform(sp);
    sp->pos = 0;
    return SUCCESS;
}

int
cubehashReset(cubehashParam *sp)
{
    return cubehashInit(sp, sp->hashbitlen, sp->rounds, sp->blockbytes);
}

int cubehashUpdate( cubehashParam *sp, const byte *data, size_t size )
{
    uint64_t databitlen = 8 * size;

    /* caller promises us that previous data had integral number of bytes */
    /* so sp->pos is a multiple of 8 */

    while ( databitlen >= 8 )
    {
	( (unsigned char *)sp->x )[sp->pos/8] ^= *data;
	data += 1;
	databitlen -= 8;
	sp->pos += 8;
	if ( sp->pos == 8 * sp->blockbytes )
        {
	    transform( sp );
	    sp->pos = 0;
	}
    }
    if ( databitlen > 0 )
    {
	( (unsigned char *)sp->x )[sp->pos/8] ^= *data;
	sp->pos += databitlen;
    }
    return SUCCESS;
}

int cubehashDigest( cubehashParam *sp, byte *digest )
{
    int i;

    ( (unsigned char *)sp->x )[sp->pos/8] ^= ( 128 >> (sp->pos % 8) );
    transform(sp);

    sp->x[7] = _mm_xor_si128(sp->x[7], _mm_set_epi32(1, 0, 0, 0));
    transform(sp);
    transform(sp);
    transform(sp);
    transform(sp);
    transform(sp);
    transform(sp);
    transform(sp);
    transform(sp);
    transform(sp);
    transform(sp);

    for ( i = 0; i < sp->hashbitlen / 8; ++i )
	digest[i] = ((unsigned char *) sp->x)[i];

    return SUCCESS;
}

int cubehashUpdateDigest( cubehashParam *sp, byte *digest,
                          const byte *data, size_t size )
{
    uint64_t databitlen = 8 * size;
    int hashlen128 = sp->hashbitlen/128;
    int i;

    /* caller promises us that previous data had integral number of bytes */
    /* so sp->pos is a multiple of 8 */

    while ( databitlen >= 8 )
    {
        ( (unsigned char *)sp->x )[sp->pos/8] ^= *data;
        data += 1;
        databitlen -= 8;
        sp->pos += 8;
        if ( sp->pos == 8 * sp->blockbytes )
        {
            transform(sp);
            sp->pos = 0;
        }
    }
    if ( databitlen > 0 )
    {
        ( (unsigned char *)sp->x )[sp->pos/8] ^= *data;
        sp->pos += databitlen;
    }

    ( (unsigned char *)sp->x )[sp->pos/8] ^= ( 128 >> (sp->pos % 8) );
    transform( sp );

    sp->x[7] = _mm_xor_si128( sp->x[7], _mm_set_epi32(1,0,0,0) );
    transform(sp);
    transform(sp);
    transform(sp);
    transform(sp);
    transform(sp);
    transform(sp);
    transform(sp);
    transform(sp);
    transform(sp);
    transform(sp);

    for ( i = 0; i < hashlen128; i++ )
       ( (__m128i*)digest )[i] = ( (__m128i*)sp->x )[i];

    return SUCCESS;
}

