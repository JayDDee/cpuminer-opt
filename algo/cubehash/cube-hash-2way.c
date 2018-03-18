#if defined(__AVX2__)

#include <stdbool.h>
#include <unistd.h>
#include <memory.h>
#include "cube-hash-2way.h"

// 2x128

static void transform_2way( cube_2way_context *sp )
{
    int r;
    const int rounds = sp->rounds;

    __m256i x0, x1, x2, x3, x4, x5, x6, x7, y0, y1, y2, y3;

    x0 = _mm256_load_si256( (__m256i*)sp->h     );
    x1 = _mm256_load_si256( (__m256i*)sp->h + 1 );
    x2 = _mm256_load_si256( (__m256i*)sp->h + 2 );
    x3 = _mm256_load_si256( (__m256i*)sp->h + 3 );
    x4 = _mm256_load_si256( (__m256i*)sp->h + 4 );
    x5 = _mm256_load_si256( (__m256i*)sp->h + 5 );
    x6 = _mm256_load_si256( (__m256i*)sp->h + 6 );
    x7 = _mm256_load_si256( (__m256i*)sp->h + 7 );

    for ( r = 0; r < rounds; ++r )
    {
        x4 = _mm256_add_epi32( x0, x4 );
        x5 = _mm256_add_epi32( x1, x5 );
        x6 = _mm256_add_epi32( x2, x6 );
        x7 = _mm256_add_epi32( x3, x7 );
        y0 = x2;
        y1 = x3;
        y2 = x0;
        y3 = x1;
        x0 = _mm256_xor_si256( _mm256_slli_epi32( y0,  7 ),
                               _mm256_srli_epi32( y0, 25 ) );
        x1 = _mm256_xor_si256( _mm256_slli_epi32( y1,  7 ),
                               _mm256_srli_epi32( y1, 25 ) );
        x2 = _mm256_xor_si256( _mm256_slli_epi32( y2,  7 ),
                               _mm256_srli_epi32( y2, 25 ) );
        x3 = _mm256_xor_si256( _mm256_slli_epi32( y3,  7 ),
                               _mm256_srli_epi32( y3, 25 ) );
        x0 = _mm256_xor_si256( x0, x4 );
        x1 = _mm256_xor_si256( x1, x5 );
        x2 = _mm256_xor_si256( x2, x6 );
        x3 = _mm256_xor_si256( x3, x7 );
        x4 = mm256_swap128_64( x4 );
        x5 = mm256_swap128_64( x5 );
        x6 = mm256_swap128_64( x6 );
        x7 = mm256_swap128_64( x7 );
        x4 = _mm256_add_epi32( x0, x4 );
        x5 = _mm256_add_epi32( x1, x5 );
        x6 = _mm256_add_epi32( x2, x6 );
        x7 = _mm256_add_epi32( x3, x7 );
        y0 = x1;
        y1 = x0;
        y2 = x3;
        y3 = x2;
        x0 = _mm256_xor_si256( _mm256_slli_epi32( y0, 11 ),
                               _mm256_srli_epi32( y0, 21 ) );
        x1 = _mm256_xor_si256( _mm256_slli_epi32( y1, 11 ),
                               _mm256_srli_epi32( y1, 21 ) );
        x2 = _mm256_xor_si256( _mm256_slli_epi32( y2, 11 ),
                               _mm256_srli_epi32( y2, 21 ) );
        x3 = _mm256_xor_si256( _mm256_slli_epi32( y3, 11 ),
                               _mm256_srli_epi32( y3, 21 ) );
        x0 = _mm256_xor_si256( x0, x4 );
        x1 = _mm256_xor_si256( x1, x5 );
        x2 = _mm256_xor_si256( x2, x6 );
        x3 = _mm256_xor_si256( x3, x7 );
        x4 = mm256_swap64_32( x4 );
        x5 = mm256_swap64_32( x5 );
        x6 = mm256_swap64_32( x6 );
        x7 = mm256_swap64_32( x7 );
    }

    _mm256_store_si256( (__m256i*)sp->h,     x0 );
    _mm256_store_si256( (__m256i*)sp->h + 1, x1 );
    _mm256_store_si256( (__m256i*)sp->h + 2, x2 );
    _mm256_store_si256( (__m256i*)sp->h + 3, x3 );
    _mm256_store_si256( (__m256i*)sp->h + 4, x4 );
    _mm256_store_si256( (__m256i*)sp->h + 5, x5 );
    _mm256_store_si256( (__m256i*)sp->h + 6, x6 );
    _mm256_store_si256( (__m256i*)sp->h + 7, x7 );

}

cube_2way_context cube_2way_ctx_cache __attribute__ ((aligned (64)));

int cube_2way_reinit( cube_2way_context *sp )
{
   memcpy( sp, &cube_2way_ctx_cache, sizeof(cube_2way_context) );
   return 0;

}

int cube_2way_init( cube_2way_context *sp, int hashbitlen, int rounds,
                       int blockbytes )
{
    int i;

    // all sizes of __m128i
    cube_2way_ctx_cache.hashlen   = hashbitlen/128;
    cube_2way_ctx_cache.blocksize = blockbytes/16;
    cube_2way_ctx_cache.rounds    = rounds;
    cube_2way_ctx_cache.pos       = 0;

    for ( i = 0; i < 8; ++i )
       cube_2way_ctx_cache.h[i] = m256_zero;

    cube_2way_ctx_cache.h[0] = _mm256_set_epi32(
                                   0, rounds, blockbytes, hashbitlen / 8,
                                   0, rounds, blockbytes, hashbitlen / 8 );

    for ( i = 0; i < 10; ++i )
       transform_2way( &cube_2way_ctx_cache );

    memcpy( sp, &cube_2way_ctx_cache, sizeof(cube_2way_context) );
    return 0;
}


int cube_2way_update( cube_2way_context *sp, const void *data, size_t size )
{
    const int len = size / 16;
    const __m256i *in = (__m256i*)data;
    int i;

    // It is assumed data is aligned to 256 bits and is a multiple of 128 bits.
    // Current usage sata is either 64 or 80 bytes.

    for ( i = 0; i < len; i++ )
    {
        sp->h[ sp->pos ] = _mm256_xor_si256( sp->h[ sp->pos ], in[i] );
        sp->pos++;
        if ( sp->pos == sp->blocksize )
        {
           transform_2way( sp );
           sp->pos = 0;
        }
    }

    return 0;
}

int cube_2way_close( cube_2way_context *sp, void *output )
{
    __m256i *hash = (__m256i*)output;
    int i;

    // pos is zero for 64 byte data, 1 for 80 byte data.
    sp->h[ sp->pos ] = _mm256_xor_si256( sp->h[ sp->pos ],
                    _mm256_set_epi8( 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0x80,
                                     0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0x80 ) );
    transform_2way( sp );

    sp->h[7] = _mm256_xor_si256( sp->h[7], _mm256_set_epi32( 1,0,0,0,
                                                             1,0,0,0 ) );
    for ( i = 0; i < 10; ++i )
       transform_2way( &cube_2way_ctx_cache );

    for ( i = 0; i < sp->hashlen; i++ )
       hash[i] = sp->h[i];

    return 0;
}

int cube_2way_update_close( cube_2way_context *sp, void *output,
                               const void *data, size_t size )
{
    const int len = size / 16;
    const __m256i *in = (__m256i*)data;
    __m256i *hash = (__m256i*)output;
    int i;

    for ( i = 0; i < len; i++ )
    {
        sp->h[ sp->pos ] = _mm256_xor_si256( sp->h[ sp->pos ], in[i] );
        sp->pos++;
        if ( sp->pos == sp->blocksize )
        {
           transform_2way( sp );
           sp->pos = 0;
        }
    }

    // pos is zero for 64 byte data, 1 for 80 byte data.
    sp->h[ sp->pos ] = _mm256_xor_si256( sp->h[ sp->pos ],
                    _mm256_set_epi8( 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0x80,
                                     0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0x80 ) );
    transform_2way( sp );

    sp->h[7] = _mm256_xor_si256( sp->h[7], _mm256_set_epi32( 1,0,0,0,
                                                             1,0,0,0 ) );
    for ( i = 0; i < 10; ++i )
       transform_2way( &cube_2way_ctx_cache );

    for ( i = 0; i < sp->hashlen; i++ )
       hash[i] = sp->h[i];

    return 0;
}

#endif
