/* CubeHash 16/32 is recommended for SHA-3 "normal", 16/1 for "formal" */
#define CUBEHASH_ROUNDS	16
#define CUBEHASH_BLOCKBYTES 32
#include "cubehash_sse2.h"
#include <stdbool.h>
#include <unistd.h>
#include <memory.h>
#include "simd-utils.h"
#include <stdio.h>

static void transform( cubehashParam *sp )
{
    int r;
    const int rounds = sp->rounds;

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

    register __m512i x0, x1;

    x0 = _mm512_load_si512( (__m512i*)sp->x     );
    x1 = _mm512_load_si512( (__m512i*)sp->x + 1 );

    for ( r = 0; r < rounds; ++r )
    { 
        x1 = _mm512_add_epi32( x0, x1 );
        x0 = mm512_swap_256( x0 );
        x0 = mm512_rol_32( x0, 7 );
        x0 = _mm512_xor_si512( x0, x1 );
        x1 = mm512_swap128_64( x1 );
        x1 = _mm512_add_epi32( x0, x1 );
        x0 = mm512_swap256_128( x0 );
        x0 = mm512_rol_32( x0, 11 );
        x0 = _mm512_xor_si512( x0, x1 );
        x1 = mm512_swap64_32( x1 );
    }

    _mm512_store_si512( (__m512i*)sp->x,     x0 );
    _mm512_store_si512( (__m512i*)sp->x + 1, x1 );

#elif defined(__AVX2__)

    register __m256i x0, x1, x2, x3, y0, y1;

    x0 = _mm256_load_si256( (__m256i*)sp->x     );
    x1 = _mm256_load_si256( (__m256i*)sp->x + 1 );   
    x2 = _mm256_load_si256( (__m256i*)sp->x + 2 );
    x3 = _mm256_load_si256( (__m256i*)sp->x + 3 );

    for ( r = 0; r < rounds; ++r )
    { 
        x2 = _mm256_add_epi32( x0, x2 );
        x3 = _mm256_add_epi32( x1, x3 );
        y0 = mm256_rol_32( x1, 7 );
        y1 = mm256_rol_32( x0, 7 );
        x0 = _mm256_xor_si256( y0, x2 );
        x1 = _mm256_xor_si256( y1, x3 );
        x2 = mm256_swap128_64( x2 );
        x3 = mm256_swap128_64( x3 );
        x2 = _mm256_add_epi32( x0, x2 );
        x3 = _mm256_add_epi32( x1, x3 );
        x0 = mm256_swap_128( x0 );
        x1 = mm256_swap_128( x1 );
        x0 = mm256_rol_32( x0, 11 );
        x1 = mm256_rol_32( x1, 11 );
        x0 = _mm256_xor_si256( x0, x2 );
        x1 = _mm256_xor_si256( x1, x3 );
        x2 = mm256_swap64_32( x2 );
        x3 = mm256_swap64_32( x3 );
    }

    _mm256_store_si256( (__m256i*)sp->x,     x0 );
    _mm256_store_si256( (__m256i*)sp->x + 1, x1 );
    _mm256_store_si256( (__m256i*)sp->x + 2, x2 );
    _mm256_store_si256( (__m256i*)sp->x + 3, x3 );

#else   // AVX, SSE2, NEON

    v128_t x0, x1, x2, x3, x4, x5, x6, x7, y0, y1, y2, y3;

    x0 = casti_v128( sp->x, 0 );
    x1 = casti_v128( sp->x, 1 );
    x2 = casti_v128( sp->x, 2 );
    x3 = casti_v128( sp->x, 3 );
    x4 = casti_v128( sp->x, 4 );
    x5 = casti_v128( sp->x, 5 );
    x6 = casti_v128( sp->x, 6 );
    x7 = casti_v128( sp->x, 7 );

    for ( r = 0; r < rounds; ++r )
    {
       x4 = v128_add32( x0, x4 );
       x5 = v128_add32( x1, x5 );
       x6 = v128_add32( x2, x6 );
       x7 = v128_add32( x3, x7 );
       y0 = x2;
       y1 = x3;
       y2 = x0;
       y3 = x1;
       x0 = v128_rol32( y0, 7 );
       x1 = v128_rol32( y1, 7 );
       x2 = v128_rol32( y2, 7 );
       x3 = v128_rol32( y3, 7 );
       x0 = v128_xor( x0, x4 );
       x1 = v128_xor( x1, x5 );
       x2 = v128_xor( x2, x6 );
       x3 = v128_xor( x3, x7 );
       x4 = v128_swap64( x4 );
       x5 = v128_swap64( x5 );
       x6 = v128_swap64( x6 );
       x7 = v128_swap64( x7 );
       x4 = v128_add32( x0, x4 );
       x5 = v128_add32( x1, x5 );
       x6 = v128_add32( x2, x6 );
       x7 = v128_add32( x3, x7 );
       y0 = x1;
       y1 = x0;
       y2 = x3;
       y3 = x2;
       x0 = v128_rol32( y0, 11 );
       x1 = v128_rol32( y1, 11 );
       x2 = v128_rol32( y2, 11 );
       x3 = v128_rol32( y3, 11 );
	    x0 = v128_xor( x0, x4 );
	    x1 = v128_xor( x1, x5 );
	    x2 = v128_xor( x2, x6 );
	    x3 = v128_xor( x3, x7 );
	    x4 = v128_swap64_32( x4 );
	    x5 = v128_swap64_32( x5 );
	    x6 = v128_swap64_32( x6 );
	    x7 = v128_swap64_32( x7 );
    }

    casti_v128( sp->x, 0 ) = x0;
    casti_v128( sp->x, 1 ) = x1;
    casti_v128( sp->x, 2 ) = x2;
    casti_v128( sp->x, 3 ) = x3;
    casti_v128( sp->x, 4 ) = x4;
    casti_v128( sp->x, 5 ) = x5;
    casti_v128( sp->x, 6 ) = x6;
    casti_v128( sp->x, 7 ) = x7;

#endif
}  // transform

/*
// The result of hashing 10 rounds of initial data which is params and
// mostly zeros.
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

int cubehashInit(cubehashParam *sp, int hashbitlen, int rounds, int blockbytes)
{
    v128_t *x = (v128_t*)sp->x;
    sp->hashlen   = hashbitlen/128;
    sp->blocksize = blockbytes/16;
    sp->rounds    = rounds;
    sp->pos       = 0;

    if ( hashbitlen == 512 )
    {

       x[0] = v128_set64( 0x4167D83E2D538B8B, 0x50F494D42AEA2A61 );
       x[1] = v128_set64( 0x50AC5695CC39968E, 0xC701CF8C3FEE2313 );
       x[2] = v128_set64( 0x825B453797CF0BEF, 0xA647A8B34D42C787 );
       x[3] = v128_set64( 0xA23911AED0E5CD33, 0xF22090C4EEF864D2 );
       x[4] = v128_set64( 0xB64445321B017BEF, 0x148FE485FCD398D9 );
       x[5] = v128_set64( 0x0DBADEA991FA7934, 0x2FF5781C6A536159 );
       x[6] = v128_set64( 0xBC796576B1C62456, 0xA5A70E75D65C8A2B );
       x[7] = v128_set64( 0xD43E3B447795D246, 0xE7989AF11921C8F7 );
    }
    else
    {
       x[0] = v128_set64( 0x35481EAE63117E71, 0xCCD6F29FEA2BD4B4 );
       x[1] = v128_set64( 0xF4CC12BE7E624131, 0xE5D94E6322512D5B );
       x[2] = v128_set64( 0x3361DA8CD0720C35, 0x42AF2070C2D0B696 );
       x[3] = v128_set64( 0x40E5FBAB4680AC00, 0x8EF8AD8328CCECA4 );
       x[4] = v128_set64( 0xF0B266796C859D41, 0x6107FBD5D89041C3 );
       x[5] = v128_set64( 0x93CB628565C892FD, 0x5FA2560309392549 );
       x[6] = v128_set64( 0x85254725774ABFDD, 0x9E4B4E602AF2B5AE );
       x[7] = v128_set64( 0xD6032C0A9CDAF8AF, 0x4AB6AAD615815AEB );
    }   

    return 0;
}

int cubehashUpdate( cubehashParam *sp, const void *data, size_t size )
{
    const int len = size / 16;
    const v128_t* in = (v128_t*)data;
    int i;

    // It is assumed data is aligned to 256 bits and is a multiple of 128 bits.
    // Current usage sata is either 64 or 80 bytes.

    for ( i = 0; i < len; i++ )
    {
        sp->x[ sp->pos ] = v128_xor( sp->x[ sp->pos ], in[i] );
        sp->pos++;
        if ( sp->pos == sp->blocksize )
        {
           transform( sp );
           sp->pos = 0;
        }
    }

    return 0;
}

int cubehashDigest( cubehashParam *sp, void *digest )
{
    v128_t* hash = (v128_t*)digest;
    int i;

    // pos is zero for 64 byte data, 1 for 80 byte data.
    sp->x[ sp->pos ] = v128_xor( sp->x[ sp->pos ],
                                      v128_set64( 0, 0x80 ) );
    transform( sp );

    sp->x[7] = v128_xor( sp->x[7], v128_set64( 0x100000000, 0 ) );
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

    return 0;
}

int cubehashUpdateDigest( cubehashParam *sp, void *digest,
                          const void *data, size_t size )
{
    const int len = size / 16;
    const v128_t* in = (v128_t*)data;
    v128_t* hash = (v128_t*)digest;
    int i;

    // It is assumed data is aligned to 256 bits and is a multiple of 128 bits.
    // Current usage sata is either 64 or 80 bytes.

    for ( i = 0; i < len; i++ )
    {
        sp->x[ sp->pos ] = v128_xor( sp->x[ sp->pos ], in[i] );
        sp->pos++;
        if ( sp->pos == sp->blocksize )
        {
           transform( sp );
           sp->pos = 0;
        }
    }

    // pos is zero for 64 byte data, 1 for 80 byte data.
    sp->x[ sp->pos ] = v128_xor( sp->x[ sp->pos ],
                                      v128_set64( 0, 0x80 ) );
    transform( sp );

    sp->x[7] = v128_xor( sp->x[7], v128_set64( 0x100000000, 0 ) );

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

    return 0;
}

int cubehash_full( cubehashParam *sp, void *digest, int hashbitlen,
                          const void *data, size_t size )
{
    v128_t *x = (v128_t*)sp->x;
    sp->hashlen   = hashbitlen/128;
    sp->blocksize = 32/16;
    sp->rounds    = 16;
    sp->pos       = 0;

    if ( hashbitlen == 512 )
    {

       x[0] = v128_set64( 0x4167D83E2D538B8B, 0x50F494D42AEA2A61 );
       x[1] = v128_set64( 0x50AC5695CC39968E, 0xC701CF8C3FEE2313 );
       x[2] = v128_set64( 0x825B453797CF0BEF, 0xA647A8B34D42C787 );
       x[3] = v128_set64( 0xA23911AED0E5CD33, 0xF22090C4EEF864D2 );
       x[4] = v128_set64( 0xB64445321B017BEF, 0x148FE485FCD398D9 );
       x[5] = v128_set64( 0x0DBADEA991FA7934, 0x2FF5781C6A536159 );
       x[6] = v128_set64( 0xBC796576B1C62456, 0xA5A70E75D65C8A2B );
       x[7] = v128_set64( 0xD43E3B447795D246, 0xE7989AF11921C8F7 );
    }
    else
    {
       x[0] = v128_set64( 0x35481EAE63117E71, 0xCCD6F29FEA2BD4B4 );
       x[1] = v128_set64( 0xF4CC12BE7E624131, 0xE5D94E6322512D5B );
       x[2] = v128_set64( 0x3361DA8CD0720C35, 0x42AF2070C2D0B696 );
       x[3] = v128_set64( 0x40E5FBAB4680AC00, 0x8EF8AD8328CCECA4 );
       x[4] = v128_set64( 0xF0B266796C859D41, 0x6107FBD5D89041C3 );
       x[5] = v128_set64( 0x93CB628565C892FD, 0x5FA2560309392549 );
       x[6] = v128_set64( 0x85254725774ABFDD, 0x9E4B4E602AF2B5AE );
       x[7] = v128_set64( 0xD6032C0A9CDAF8AF, 0x4AB6AAD615815AEB );
    }

    const int len = size / 16;
    const v128_t* in = (v128_t*)data;
    v128_t* hash = (v128_t*)digest;
    int i;

    // It is assumed data is aligned to 256 bits and is a multiple of 128 bits.
    // Current usage data is either 64 or 80 bytes.

    for ( i = 0; i < len; i++ )
    {
        sp->x[ sp->pos ] = v128_xor( sp->x[ sp->pos ], in[i] );
        sp->pos++;
        if ( sp->pos == sp->blocksize )
        {
           transform( sp );
           sp->pos = 0;
        }
    }

    // pos is zero for 64 byte data, 1 for 80 byte data.
    sp->x[ sp->pos ] = v128_xor( sp->x[ sp->pos ],
                                      v128_set64( 0, 0x80 ) );
    transform( sp );

    sp->x[7] = v128_xor( sp->x[7], v128_set64( 0x100000000, 0 ) );

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

    return 0;
}

