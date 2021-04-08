#if defined(__AVX2__)

// sha3-4way.c
// 19-Nov-11  Markku-Juhani O. Saarinen <mjos@iki.fi>
// vectorization by JayDDee 2021-03-27
//
// Revised 07-Aug-15 to match with official release of FIPS PUB 202 "SHA3"
// Revised 03-Sep-15 for portability + OpenSSL - style API

#include "sha3-4way.h"

// constants
static const uint64_t keccakf_rndc[24] = {
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
        0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
        0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
        0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
        0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
        0x8000000000008080, 0x0000000080000001, 0x8000000080008008
    };

void sha3_4way_keccakf( __m256i st[25] )
{
   int i, j, r;
   __m256i t, bc[5];

   for ( r = 0; r < KECCAKF_ROUNDS; r++ )
   {
      // Theta
      bc[0] = _mm256_xor_si256( st[0],
                           mm256_xor4( st[5], st[10], st[15], st[20] ) );
      bc[1] = _mm256_xor_si256( st[1],
                           mm256_xor4( st[6], st[11], st[16], st[21] ) );
      bc[2] = _mm256_xor_si256( st[2],
                           mm256_xor4( st[7], st[12], st[17], st[22] ) );
      bc[3] = _mm256_xor_si256( st[3],
                           mm256_xor4( st[8], st[13], st[18], st[23] ) );
      bc[4] = _mm256_xor_si256( st[4],
                           mm256_xor4( st[9], st[14], st[19], st[24] ) );

      for ( i = 0; i < 5; i++ )
      {
         t = _mm256_xor_si256( bc[ (i+4) % 5 ],
                               mm256_rol_64( bc[ (i+1) % 5 ], 1 ) );
         st[ i    ]  = _mm256_xor_si256( st[ i    ],  t );
         st[ i+5  ]  = _mm256_xor_si256( st[ i+ 5 ],  t );
         st[ i+10 ]  = _mm256_xor_si256( st[ i+10 ],  t );
         st[ i+15 ]  = _mm256_xor_si256( st[ i+15 ],  t );
         st[ i+20 ]  = _mm256_xor_si256( st[ i+20 ],  t );
      }

      // Rho Pi
#define RHO_PI( i, c ) \
   bc[0] = st[ i ]; \
   st[ i ] = mm256_rol_64( t, c ); \
   t = bc[0]

      t = st[1];

      RHO_PI( 10,  1 );
      RHO_PI(  7,  3 );
      RHO_PI( 11,  6 );
      RHO_PI( 17, 10 );
      RHO_PI( 18, 15 );
      RHO_PI(  3, 21 );
      RHO_PI(  5, 28 );
      RHO_PI( 16, 36 );
      RHO_PI(  8, 45 );
      RHO_PI( 21, 55 );
      RHO_PI( 24,  2 );
      RHO_PI(  4, 14 );
      RHO_PI( 15, 27 );
      RHO_PI( 23, 41 );
      RHO_PI( 19, 56 );
      RHO_PI( 13,  8 );
      RHO_PI( 12, 25 );
      RHO_PI(  2, 43 );
      RHO_PI( 20, 62 );
      RHO_PI( 14, 18 );
      RHO_PI( 22, 39 );
      RHO_PI(  9, 61 );
      RHO_PI(  6, 20 );
      RHO_PI(  1, 44 );

#undef RHO_PI        

      //  Chi
      for ( j = 0; j < 25; j += 5 )
      {
         memcpy( bc, &st[ j ], 5*32 );
         st[ j   ] = _mm256_xor_si256( st[ j   ],
                                       _mm256_andnot_si256( bc[1], bc[2] ) );
         st[ j+1 ] = _mm256_xor_si256( st[ j+1 ],
                                       _mm256_andnot_si256( bc[2], bc[3] ) );
         st[ j+2 ] = _mm256_xor_si256( st[ j+2 ],
                                       _mm256_andnot_si256( bc[3], bc[4] ) );
         st[ j+3 ] = _mm256_xor_si256( st[ j+3 ],
                                       _mm256_andnot_si256( bc[4], bc[0] ) );
         st[ j+4 ] = _mm256_xor_si256( st[ j+4 ],
                                       _mm256_andnot_si256( bc[0], bc[1] ) );
      }

      //  Iota
      st[0] = _mm256_xor_si256( st[0],
                                _mm256_set1_epi64x( keccakf_rndc[ r ] ) );
   }
}

int sha3_4way_init( sha3_4way_ctx_t *c, int mdlen )
{
    for ( int i = 0; i < 25; i++ )  c->st[ i ] = m256_zero;
    c->mdlen = mdlen;
    c->rsiz = 200 - 2 * mdlen;
    c->pt = 0;
    return 1;
}

int sha3_4way_update( sha3_4way_ctx_t *c, const void *data, size_t len )
{
    size_t i;
    int j =  c->pt;
    const int rsiz = c->rsiz / 8;
    const int l = len / 8;

    for ( i = 0; i < l; i++ )
    {
        c->st[ j ] = _mm256_xor_si256( c->st[ j ],
                                       ( (const __m256i*)data )[i] );
        j++;
        if ( j >= rsiz )
        {
            sha3_4way_keccakf( c->st );
            j = 0;
        }
    }
    c->pt = j;

    return 1;
}

int sha3_4way_final( void *md, sha3_4way_ctx_t *c )
{
    c->st[ c->pt ] = _mm256_xor_si256( c->st[ c->pt ],
                                       m256_const1_64( 6 ) );
    c->st[ c->rsiz / 8 - 1 ] =
                       _mm256_xor_si256( c->st[ c->rsiz / 8 - 1 ],
                                         m256_const1_64( 0x8000000000000000 ) );
    sha3_4way_keccakf( c->st );
    memcpy( md, c->st, c->mdlen * 4 );
    return 1;
}

void *sha3_4way( const void *in, size_t inlen, void *md, int mdlen )
{
    sha3_4way_ctx_t ctx;
    sha3_4way_init( &ctx, mdlen);
    sha3_4way_update( &ctx, in, inlen );
    sha3_4way_final( md, &ctx );
    return md;
}

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

void sha3_8way_keccakf( __m512i st[25] )
{
    int i, j, r;
    __m512i t, bc[5];

    // actual iteration
    for ( r = 0; r < KECCAKF_ROUNDS; r++ )
    {

        // Theta
        for ( i = 0; i < 5; i++ )
           bc[i] = _mm512_xor_si512( st[i], 
              mm512_xor4( st[ i+5 ], st[ i+10 ], st[ i+15 ], st[i+20 ] ) );

        for ( i = 0; i < 5; i++ )
        {
            t = _mm512_xor_si512( bc[(i + 4) % 5],
                                  _mm512_rol_epi64( bc[(i + 1) % 5], 1 ) );
            for ( j = 0; j < 25; j += 5 )
                st[j + i]  = _mm512_xor_si512( st[j + i],  t );
        }

        // Rho Pi
#define RHO_PI( i, c ) \
   bc[0] = st[ i ]; \
   st[ i ] = _mm512_rol_epi64( t, c ); \
   t = bc[0]

        t = st[1];

        RHO_PI( 10,  1 );        
        RHO_PI(  7,  3 );
        RHO_PI( 11,  6 );
        RHO_PI( 17, 10 );
        RHO_PI( 18, 15 );
        RHO_PI(  3, 21 );
        RHO_PI(  5, 28 );
        RHO_PI( 16, 36 );
        RHO_PI(  8, 45 );
        RHO_PI( 21, 55 );
        RHO_PI( 24,  2 );
        RHO_PI(  4, 14 );
        RHO_PI( 15, 27 );
        RHO_PI( 23, 41 );
        RHO_PI( 19, 56 );
        RHO_PI( 13,  8 );
        RHO_PI( 12, 25 );
        RHO_PI(  2, 43 );
        RHO_PI( 20, 62 );
        RHO_PI( 14, 18 );
        RHO_PI( 22, 39 );
        RHO_PI(  9, 61 );
        RHO_PI(  6, 20 );
        RHO_PI(  1, 44 );

#undef RHO_PI        

        //  Chi
        for ( j = 0; j < 25; j += 5 )
        {
            for ( i = 0; i < 5; i++ )
                bc[i] = st[j + i];
            for ( i = 0; i < 5; i++ )
                st[ j+i ] = _mm512_xor_si512(  st[ j+i ],  _mm512_andnot_si512(
                                         bc[ (i+1) % 5 ], bc[ (i+2) % 5 ] ) );
        }

        //  Iota
        st[0] = _mm512_xor_si512( st[0], _mm512_set1_epi64( keccakf_rndc[r] ) );
    }
}

// Initialize the context for SHA3

int sha3_8way_init( sha3_8way_ctx_t *c, int mdlen )
{
    for ( int i = 0; i < 25; i++ )  c->st[ i ] = m512_zero;
    c->mdlen = mdlen;
    c->rsiz = 200 - 2 * mdlen;
    c->pt = 0;
    return 1;
}

// update state with more data

int sha3_8way_update( sha3_8way_ctx_t *c, const void *data, size_t len )
{
    size_t i;
    int j =  c->pt;
    const int rsiz = c->rsiz / 8;
    const int l = len / 8;

    for ( i = 0; i < l; i++ )
    {
        c->st[ j ] = _mm512_xor_si512( c->st[ j ],
                                        ( (const __m512i*)data )[i] );
        j++;
        if ( j >= rsiz )
        {
            sha3_8way_keccakf( c->st );
            j = 0;
        }
    }
    c->pt = j;

    return 1;
}

// finalize and output a hash

int sha3_8way_final( void *md, sha3_8way_ctx_t *c )
{
    c->st[ c->pt ] =
                       _mm512_xor_si512( c->st[ c->pt ],
                                         m512_const1_64( 6 ) );
    c->st[ c->rsiz / 8 - 1 ] =
                       _mm512_xor_si512( c->st[ c->rsiz / 8 - 1 ],
                                         m512_const1_64( 0x8000000000000000 ) );
    sha3_8way_keccakf( c->st );
    memcpy( md, c->st, c->mdlen * 8 );
    return 1;
}

// compute a SHA-3 hash (md) of given byte length from "in"

void *sha3_8way( const void *in, size_t inlen, void *md, int mdlen )
{
    sha3_8way_ctx_t sha3;
    sha3_8way_init( &sha3, mdlen);
    sha3_8way_update( &sha3, in, inlen );
    sha3_8way_final( md, &sha3 );
    return md;
}

#endif  // AVX512
#endif  // AVX2
