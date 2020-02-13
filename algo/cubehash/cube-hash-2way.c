#if defined(__AVX2__)

#include <stdbool.h>
#include <unistd.h>
#include <memory.h>
#include "cube-hash-2way.h"

// 2x128


// The result of hashing 10 rounds of initial data which consists of params
// zero padded.
static const uint64_t IV256[] =
{
0xCCD6F29FEA2BD4B4, 0x35481EAE63117E71, 0xE5D94E6322512D5B, 0xF4CC12BE7E624131,
0x42AF2070C2D0B696, 0x3361DA8CD0720C35, 0x8EF8AD8328CCECA4, 0x40E5FBAB4680AC00,
0x6107FBD5D89041C3, 0xF0B266796C859D41, 0x5FA2560309392549, 0x93CB628565C892FD,
0x9E4B4E602AF2B5AE, 0x85254725774ABFDD, 0x4AB6AAD615815AEB, 0xD6032C0A9CDAF8AF
};

static const uint64_t IV512[] =
{
0x50F494D42AEA2A61, 0x4167D83E2D538B8B, 0xC701CF8C3FEE2313, 0x50AC5695CC39968E,
0xA647A8B34D42C787, 0x825B453797CF0BEF, 0xF22090C4EEF864D2, 0xA23911AED0E5CD33,
0x148FE485FCD398D9, 0xB64445321B017BEF, 0x2FF5781C6A536159, 0x0DBADEA991FA7934,
0xA5A70E75D65C8A2B, 0xBC796576B1C62456, 0xE7989AF11921C8F7, 0xD43E3B447795D246
};

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

// 4 way 128 is handy to avoid reinterleaving in many algos.
// If reinterleaving is necessary it may be more efficient to use
// 2 way 256. The same transform code should work for both.

static void transform_4way( cube_4way_context *sp )
{
    int r;
    const int rounds = sp->rounds;

    __m512i x0, x1, x2, x3, x4, x5, x6, x7, y0, y1;

    x0 = _mm512_load_si512( (__m512i*)sp->h     );
    x1 = _mm512_load_si512( (__m512i*)sp->h + 1 );
    x2 = _mm512_load_si512( (__m512i*)sp->h + 2 );
    x3 = _mm512_load_si512( (__m512i*)sp->h + 3 );
    x4 = _mm512_load_si512( (__m512i*)sp->h + 4 );
    x5 = _mm512_load_si512( (__m512i*)sp->h + 5 );
    x6 = _mm512_load_si512( (__m512i*)sp->h + 6 );
    x7 = _mm512_load_si512( (__m512i*)sp->h + 7 );

    for ( r = 0; r < rounds; ++r )
    {
        x4 = _mm512_add_epi32( x0, x4 );
        x5 = _mm512_add_epi32( x1, x5 );
        x6 = _mm512_add_epi32( x2, x6 );
        x7 = _mm512_add_epi32( x3, x7 );
        y0 = x0;
        y1 = x1;
        x0 = mm512_rol_32( x2, 7 );
        x1 = mm512_rol_32( x3, 7 );
        x2 = mm512_rol_32( y0, 7 );
        x3 = mm512_rol_32( y1, 7 );
        x0 = _mm512_xor_si512( x0, x4 );
        x1 = _mm512_xor_si512( x1, x5 );
        x2 = _mm512_xor_si512( x2, x6 );
        x3 = _mm512_xor_si512( x3, x7 );
        x4 = mm512_swap128_64( x4 );
        x5 = mm512_swap128_64( x5 );
        x6 = mm512_swap128_64( x6 );
        x7 = mm512_swap128_64( x7 );
        x4 = _mm512_add_epi32( x0, x4 );
        x5 = _mm512_add_epi32( x1, x5 );
        x6 = _mm512_add_epi32( x2, x6 );
        x7 = _mm512_add_epi32( x3, x7 );
        y0 = x0;
        y1 = x2;
        x0 = mm512_rol_32( x1, 11 );
        x1 = mm512_rol_32( y0, 11 );
        x2 = mm512_rol_32( x3, 11 );
        x3 = mm512_rol_32( y1, 11 );
        x0 = _mm512_xor_si512( x0, x4 );
        x1 = _mm512_xor_si512( x1, x5 );
        x2 = _mm512_xor_si512( x2, x6 );
        x3 = _mm512_xor_si512( x3, x7 );
        x4 = mm512_swap64_32( x4 );
        x5 = mm512_swap64_32( x5 );
        x6 = mm512_swap64_32( x6 );
        x7 = mm512_swap64_32( x7 );
    }

    _mm512_store_si512( (__m512i*)sp->h,     x0 );
    _mm512_store_si512( (__m512i*)sp->h + 1, x1 );
    _mm512_store_si512( (__m512i*)sp->h + 2, x2 );
    _mm512_store_si512( (__m512i*)sp->h + 3, x3 );
    _mm512_store_si512( (__m512i*)sp->h + 4, x4 );
    _mm512_store_si512( (__m512i*)sp->h + 5, x5 );
    _mm512_store_si512( (__m512i*)sp->h + 6, x6 );
    _mm512_store_si512( (__m512i*)sp->h + 7, x7 );
}

int cube_4way_init( cube_4way_context *sp, int hashbitlen, int rounds,
                    int blockbytes )
{
    __m512i *h = (__m512i*)sp->h;
    __m128i *iv = (__m128i*)( hashbitlen == 512 ? (__m128i*)IV512
                                                : (__m128i*)IV256 );
    sp->hashlen   = hashbitlen/128;
    sp->blocksize = blockbytes/16;
    sp->rounds    = rounds;
    sp->pos       = 0;

    h[ 0] = m512_const1_128( iv[0] );
    h[ 1] = m512_const1_128( iv[1] );
    h[ 2] = m512_const1_128( iv[2] );
    h[ 3] = m512_const1_128( iv[3] );
    h[ 4] = m512_const1_128( iv[4] );
    h[ 5] = m512_const1_128( iv[5] );
    h[ 6] = m512_const1_128( iv[6] );
    h[ 7] = m512_const1_128( iv[7] );
    h[ 0] = m512_const1_128( iv[0] );
    h[ 1] = m512_const1_128( iv[1] );
    h[ 2] = m512_const1_128( iv[2] );
    h[ 3] = m512_const1_128( iv[3] );
    h[ 4] = m512_const1_128( iv[4] );
    h[ 5] = m512_const1_128( iv[5] );
    h[ 6] = m512_const1_128( iv[6] );
    h[ 7] = m512_const1_128( iv[7] );

    return 0;
}

int cube_4way_update( cube_4way_context *sp, const void *data, size_t size )
{
    const int len = size >> 4;
    const __m512i *in = (__m512i*)data;
    int i;

    for ( i = 0; i < len; i++ )
    {
        sp->h[ sp->pos ] = _mm512_xor_si512( sp->h[ sp->pos ], in[i] );
        sp->pos++;
        if ( sp->pos == sp->blocksize )
        {
           transform_4way( sp );
           sp->pos = 0;
        }
    }
    return 0;
}

int cube_4way_close( cube_4way_context *sp, void *output )
{
    __m512i *hash = (__m512i*)output;
    int i;

    // pos is zero for 64 byte data, 1 for 80 byte data.
    sp->h[ sp->pos ] = _mm512_xor_si512( sp->h[ sp->pos ],
                                 m512_const2_64( 0, 0x0000000000000080 ) );
    transform_4way( sp );

    sp->h[7] = _mm512_xor_si512( sp->h[7],
                                 m512_const2_64( 0x0000000100000000, 0 ) );

    for ( i = 0; i < 10; ++i ) 
       transform_4way( sp );

    memcpy( hash, sp->h, sp->hashlen<<6 );
    return 0;
}

int cube_4way_full( cube_4way_context *sp, void *output,  int hashbitlen, 
                    const void *data, size_t size )
{
    __m512i *h = (__m512i*)sp->h;
    __m128i *iv = (__m128i*)( hashbitlen == 512 ? (__m128i*)IV512
                                                : (__m128i*)IV256 );
    sp->hashlen   = hashbitlen/128;
    sp->blocksize = 32/16;
    sp->rounds    = 16;
    sp->pos       = 0;

    h[ 0] = m512_const1_128( iv[0] );
    h[ 1] = m512_const1_128( iv[1] );
    h[ 2] = m512_const1_128( iv[2] );
    h[ 3] = m512_const1_128( iv[3] );
    h[ 4] = m512_const1_128( iv[4] );
    h[ 5] = m512_const1_128( iv[5] );
    h[ 6] = m512_const1_128( iv[6] );
    h[ 7] = m512_const1_128( iv[7] );

    const int len = size >> 4;
    const __m512i *in = (__m512i*)data;
    __m512i *hash = (__m512i*)output;
    int i;

    for ( i = 0; i < len; i++ )
    {
        sp->h[ sp->pos ] = _mm512_xor_si512( sp->h[ sp->pos ], in[i] );
        sp->pos++;
        if ( sp->pos == sp->blocksize )
        {
           transform_4way( sp );
           sp->pos = 0;
        }
    }

    // pos is zero for 64 byte data, 1 for 80 byte data.
    sp->h[ sp->pos ] = _mm512_xor_si512( sp->h[ sp->pos ],
                                    m512_const2_64( 0, 0x0000000000000080 ) );
    transform_4way( sp );

    sp->h[7] = _mm512_xor_si512( sp->h[7],
                                    m512_const2_64( 0x0000000100000000, 0 ) );

    for ( i = 0; i < 10; ++i )
       transform_4way( sp );

    memcpy( hash, sp->h, sp->hashlen<<6);
    return 0;
}


int cube_4way_update_close( cube_4way_context *sp, void *output,
                               const void *data, size_t size )
{
    const int len = size >> 4;
    const __m512i *in = (__m512i*)data;
    __m512i *hash = (__m512i*)output;
    int i;

    for ( i = 0; i < len; i++ )
    {
        sp->h[ sp->pos ] = _mm512_xor_si512( sp->h[ sp->pos ], in[i] );
        sp->pos++;
        if ( sp->pos == sp->blocksize )
        {
           transform_4way( sp );
           sp->pos = 0;
        }
    }

    // pos is zero for 64 byte data, 1 for 80 byte data.
    sp->h[ sp->pos ] = _mm512_xor_si512( sp->h[ sp->pos ],
                                    m512_const2_64( 0, 0x0000000000000080 ) );
    transform_4way( sp );

    sp->h[7] = _mm512_xor_si512( sp->h[7],
                                    m512_const2_64( 0x0000000100000000, 0 ) );

    for ( i = 0; i < 10; ++i )
       transform_4way( sp );

    memcpy( hash, sp->h, sp->hashlen<<6);
    return 0;
}


#endif // AVX512

// 2 way 128 

static void transform_2way( cube_2way_context *sp )
{
    int r;
    const int rounds = sp->rounds;

    __m256i x0, x1, x2, x3, x4, x5, x6, x7, y0, y1;

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
        y0 = x0;
        y1 = x1;
        x0 = mm256_rol_32( x2, 7 );
        x1 = mm256_rol_32( x3, 7 );
        x2 = mm256_rol_32( y0, 7 );
        x3 = mm256_rol_32( y1, 7 );
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
        y0 = x0;
        y1 = x2;
        x0 = mm256_rol_32( x1, 11 );
        x1 = mm256_rol_32( y0, 11 );
        x2 = mm256_rol_32( x3, 11 );
        x3 = mm256_rol_32( y1, 11 );
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

int cube_2way_init( cube_2way_context *sp, int hashbitlen, int rounds,
                    int blockbytes )
{
    __m256i *h = (__m256i*)sp->h;
    __m128i *iv = (__m128i*)( hashbitlen == 512 ? (__m128i*)IV512
                                                : (__m128i*)IV256 );
    sp->hashlen   = hashbitlen/128;
    sp->blocksize = blockbytes/16;
    sp->rounds    = rounds;
    sp->pos       = 0;

    h[ 0] = m256_const1_128( iv[0] );
    h[ 1] = m256_const1_128( iv[1] );
    h[ 2] = m256_const1_128( iv[2] );
    h[ 3] = m256_const1_128( iv[3] );
    h[ 4] = m256_const1_128( iv[4] );
    h[ 5] = m256_const1_128( iv[5] );
    h[ 6] = m256_const1_128( iv[6] );
    h[ 7] = m256_const1_128( iv[7] );
    h[ 0] = m256_const1_128( iv[0] );
    h[ 1] = m256_const1_128( iv[1] );
    h[ 2] = m256_const1_128( iv[2] );
    h[ 3] = m256_const1_128( iv[3] );
    h[ 4] = m256_const1_128( iv[4] );
    h[ 5] = m256_const1_128( iv[5] );
    h[ 6] = m256_const1_128( iv[6] );
    h[ 7] = m256_const1_128( iv[7] );
    
    return 0;
}


int cube_2way_update( cube_2way_context *sp, const void *data, size_t size )
{
    const int len = size >> 4;
    const __m256i *in = (__m256i*)data;
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
    return 0;
}

int cube_2way_close( cube_2way_context *sp, void *output )
{
    __m256i *hash = (__m256i*)output;
    int i;

    // pos is zero for 64 byte data, 1 for 80 byte data.
    sp->h[ sp->pos ] = _mm256_xor_si256( sp->h[ sp->pos ],
                                   m256_const2_64( 0, 0x0000000000000080 ) );
    transform_2way( sp );

    sp->h[7] = _mm256_xor_si256( sp->h[7],
                                   m256_const2_64( 0x0000000100000000, 0 ) );

    for ( i = 0; i < 10; ++i )           transform_2way( sp );

    memcpy( hash, sp->h, sp->hashlen<<5 );
    return 0;
}

int cube_2way_update_close( cube_2way_context *sp, void *output,
                               const void *data, size_t size )
{
    const int len = size >> 4;
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
                                    m256_const2_64( 0, 0x0000000000000080 ) );
    transform_2way( sp );

    sp->h[7] = _mm256_xor_si256( sp->h[7],
                                    m256_const2_64( 0x0000000100000000, 0 ) );

    for ( i = 0; i < 10; ++i )    transform_2way( sp );

    memcpy( hash, sp->h, sp->hashlen<<5 );
    return 0;
}

int cube_2way_full( cube_2way_context *sp, void *output, int hashbitlen,
                               const void *data, size_t size )
{
    __m256i *h = (__m256i*)sp->h;
    __m128i *iv = (__m128i*)( hashbitlen == 512 ? (__m128i*)IV512
                                                : (__m128i*)IV256 );
    sp->hashlen   = hashbitlen/128;
    sp->blocksize = 32/16;
    sp->rounds    = 16;
    sp->pos       = 0;

    h[ 0] = m256_const1_128( iv[0] );
    h[ 1] = m256_const1_128( iv[1] );
    h[ 2] = m256_const1_128( iv[2] );
    h[ 3] = m256_const1_128( iv[3] );
    h[ 4] = m256_const1_128( iv[4] );
    h[ 5] = m256_const1_128( iv[5] );
    h[ 6] = m256_const1_128( iv[6] );
    h[ 7] = m256_const1_128( iv[7] );

    const int len = size >> 4;
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
                                    m256_const2_64( 0, 0x0000000000000080 ) );
    transform_2way( sp );

    sp->h[7] = _mm256_xor_si256( sp->h[7],
                                    m256_const2_64( 0x0000000100000000, 0 ) );

    for ( i = 0; i < 10; ++i )    transform_2way( sp );

    memcpy( hash, sp->h, sp->hashlen<<5 );
    return 0;
}

#endif
