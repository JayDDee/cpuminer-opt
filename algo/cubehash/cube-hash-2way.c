#if defined(__AVX2__)

#include <stdbool.h>
#include <unistd.h>
#include <memory.h>
#include "cube-hash-2way.h"

// 2x128

/*
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
*/

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
        x4 = mm256_swap64_128( x4 );
        x5 = mm256_swap64_128( x5 );
        x6 = mm256_swap64_128( x6 );
        x7 = mm256_swap64_128( x7 );
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
        x4 = mm256_swap32_64( x4 );
        x5 = mm256_swap32_64( x5 );
        x6 = mm256_swap32_64( x6 );
        x7 = mm256_swap32_64( x7 );
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
    __m128i* h = (__m128i*)sp->h;
    sp->hashlen   = hashbitlen/128;
    sp->blocksize = blockbytes/16;
    sp->rounds    = rounds;
    sp->pos       = 0;

    if ( hashbitlen == 512 )
    {

       h[ 0] = m128_const_64( 0x4167D83E2D538B8B, 0x50F494D42AEA2A61 );
       h[ 2] = m128_const_64( 0x50AC5695CC39968E, 0xC701CF8C3FEE2313 );
       h[ 4] = m128_const_64( 0x825B453797CF0BEF, 0xA647A8B34D42C787 );
       h[ 6] = m128_const_64( 0xA23911AED0E5CD33, 0xF22090C4EEF864D2 );
       h[ 8] = m128_const_64( 0xB64445321B017BEF, 0x148FE485FCD398D9 );
       h[10] = m128_const_64( 0x0DBADEA991FA7934, 0x2FF5781C6A536159 );
       h[12] = m128_const_64( 0xBC796576B1C62456, 0xA5A70E75D65C8A2B );
       h[14] = m128_const_64( 0xD43E3B447795D246, 0xE7989AF11921C8F7 );
       h[1] = h[ 0];  h[ 3] = h[ 2]; h[ 5] = h[ 4]; h[ 7] = h[ 6];
       h[9] = h[ 8];  h[11] = h[10]; h[13] = h[12]; h[15] = h[14];
    }
    else
    {
       h[ 0] = m128_const_64( 0x35481EAE63117E71, 0xCCD6F29FEA2BD4B4 );
       h[ 2] = m128_const_64( 0xF4CC12BE7E624131, 0xE5D94E6322512D5B );
       h[ 4] = m128_const_64( 0x3361DA8CD0720C35, 0x42AF2070C2D0B696 );
       h[ 6] = m128_const_64( 0x40E5FBAB4680AC00, 0x8EF8AD8328CCECA4 );
       h[ 8] = m128_const_64( 0xF0B266796C859D41, 0x6107FBD5D89041C3 );
       h[10] = m128_const_64( 0x93CB628565C892FD, 0x5FA2560309392549 );
       h[12] = m128_const_64( 0x85254725774ABFDD, 0x9E4B4E602AF2B5AE );
       h[14] = m128_const_64( 0xD6032C0A9CDAF8AF, 0x4AB6AAD615815AEB );
       h[1] = h[ 0];  h[ 3] = h[ 2]; h[ 5] = h[ 4]; h[ 7] = h[ 6];
       h[9] = h[ 8];  h[11] = h[10]; h[13] = h[12]; h[15] = h[14];
    }
    
    return 0;
}


int cube_2way_update( cube_2way_context *sp, const void *data, size_t size )
{
    const int len = size >> 4;
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
                                _mm256_set_epi32( 0,0,0,0x80,  0,0,0,0x80 ) );
    transform_2way( sp );

    sp->h[7] = _mm256_xor_si256( sp->h[7],
		                 _mm256_set_epi32( 1,0,0,0,  1,0,0,0 ) );

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
                    _mm256_set_epi32( 0,0,0,0x80,  0,0,0,0x80 ) );
    transform_2way( sp );

    sp->h[7] = _mm256_xor_si256( sp->h[7], _mm256_set_epi32( 1,0,0,0,
                                                             1,0,0,0 ) );

    for ( i = 0; i < 10; ++i )            transform_2way( sp );

    memcpy( hash, sp->h, sp->hashlen<<5 );
    return 0;
}

#endif
