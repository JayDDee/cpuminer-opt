#include <stddef.h>
#include <string.h>
#include "sha256-hash.h"
#include "compat.h"

static const uint32_t sha256_iv[8]  __attribute__ ((aligned (32))) =
{
   0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
   0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};


static const uint32_t K256[64] =
{
   0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
   0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
   0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
   0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
   0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
   0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
   0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
   0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
   0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
   0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
   0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
   0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
   0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
   0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
   0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
   0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
};

#if defined(__SSE2__) || defined(__ARM_NEON)
// SHA-256 4 way SSE2

#define CHs(X, Y, Z) \
   v128_xor( v128_and( v128_xor( Y, Z ), X ), Z ) 

#define MAJs(X, Y, Z) \
  v128_xor( Y, v128_and( X_xor_Y = v128_xor( X, Y ), Y_xor_Z ) )

#define BSG2_0(x) \
   v128_xor( v128_xor( \
        v128_ror32(x,  2), v128_ror32(x, 13) ), v128_ror32( x, 22) )

#define BSG2_1(x) \
   v128_xor( v128_xor( \
        v128_ror32(x,  6), v128_ror32(x, 11) ), v128_ror32( x, 25) )

#define SSG2_0(x) \
   v128_xor( v128_xor( \
        v128_ror32(x,  7), v128_ror32(x, 18) ), v128_sr32(x, 3) ) 

#define SSG2_1(x) \
   v128_xor( v128_xor( \
        v128_ror32(x, 17), v128_ror32(x, 19) ), v128_sr32(x, 10) )

#define SHA256_4X32_MEXP( a, b, c, d ) \
  v128_add4_32( SSG2_1( a ), b, SSG2_0( c ), d );

#define SHA256_4X32_MSG_EXPANSION( W ) \
   W[ 0] = SHA256_4X32_MEXP( W[14], W[ 9], W[ 1], W[ 0] ); \
   W[ 1] = SHA256_4X32_MEXP( W[15], W[10], W[ 2], W[ 1] ); \
   W[ 2] = SHA256_4X32_MEXP( W[ 0], W[11], W[ 3], W[ 2] ); \
   W[ 3] = SHA256_4X32_MEXP( W[ 1], W[12], W[ 4], W[ 3] ); \
   W[ 4] = SHA256_4X32_MEXP( W[ 2], W[13], W[ 5], W[ 4] ); \
   W[ 5] = SHA256_4X32_MEXP( W[ 3], W[14], W[ 6], W[ 5] ); \
   W[ 6] = SHA256_4X32_MEXP( W[ 4], W[15], W[ 7], W[ 6] ); \
   W[ 7] = SHA256_4X32_MEXP( W[ 5], W[ 0], W[ 8], W[ 7] ); \
   W[ 8] = SHA256_4X32_MEXP( W[ 6], W[ 1], W[ 9], W[ 8] ); \
   W[ 9] = SHA256_4X32_MEXP( W[ 7], W[ 2], W[10], W[ 9] ); \
   W[10] = SHA256_4X32_MEXP( W[ 8], W[ 3], W[11], W[10] ); \
   W[11] = SHA256_4X32_MEXP( W[ 9], W[ 4], W[12], W[11] ); \
   W[12] = SHA256_4X32_MEXP( W[10], W[ 5], W[13], W[12] ); \
   W[13] = SHA256_4X32_MEXP( W[11], W[ 6], W[14], W[13] ); \
   W[14] = SHA256_4X32_MEXP( W[12], W[ 7], W[15], W[14] ); \
   W[15] = SHA256_4X32_MEXP( W[13], W[ 8], W[ 0], W[15] );

#define SHA256_4X32_ROUND(A, B, C, D, E, F, G, H, i, j) \
{ \
  v128_t T1, T2; \
  v128_t K = v128_32( K256[( (j)+(i) )] ); \
  T1 = v128_add32( H, v128_add4_32( BSG2_1(E), CHs(E, F, G), \
                                        K, W[i] ) ); \
  T2 = v128_add32( BSG2_0(A), MAJs(A, B, C) ); \
  Y_xor_Z = X_xor_Y; \
  D  = v128_add32( D,  T1 ); \
  H  = v128_add32( T1, T2 ); \
}

#define SHA256_4X32_ROUND_NOMSG( A, B, C, D, E, F, G, H, i, j ) \
{ \
   v128_t T1 = v128_add4_32( H, BSG2_1(E), CHs(E, F, G), \
                                             v128_32( K256[(i)+(j)] ) ); \
   v128_t T2 = v128_add32( BSG2_0(A), MAJs(A, B, C) ); \
   Y_xor_Z = X_xor_Y; \
   D  = v128_add32( D,  T1 ); \
   H  = v128_add32( T1, T2 ); \
}

#define SHA256_4X32_16ROUNDS( A, B, C, D, E, F, G, H, j ) \
{ \
   v128_t X_xor_Y, Y_xor_Z = v128_xor( B, C ); \
   SHA256_4X32_ROUND( A, B, C, D, E, F, G, H,  0, j ); \
   SHA256_4X32_ROUND( H, A, B, C, D, E, F, G,  1, j ); \
   SHA256_4X32_ROUND( G, H, A, B, C, D, E, F,  2, j ); \
   SHA256_4X32_ROUND( F, G, H, A, B, C, D, E,  3, j ); \
   SHA256_4X32_ROUND( E, F, G, H, A, B, C, D,  4, j ); \
   SHA256_4X32_ROUND( D, E, F, G, H, A, B, C,  5, j ); \
   SHA256_4X32_ROUND( C, D, E, F, G, H, A, B,  6, j ); \
   SHA256_4X32_ROUND( B, C, D, E, F, G, H, A,  7, j ); \
   SHA256_4X32_ROUND( A, B, C, D, E, F, G, H,  8, j ); \
   SHA256_4X32_ROUND( H, A, B, C, D, E, F, G,  9, j ); \
   SHA256_4X32_ROUND( G, H, A, B, C, D, E, F, 10, j ); \
   SHA256_4X32_ROUND( F, G, H, A, B, C, D, E, 11, j ); \
   SHA256_4X32_ROUND( E, F, G, H, A, B, C, D, 12, j ); \
   SHA256_4X32_ROUND( D, E, F, G, H, A, B, C, 13, j ); \
   SHA256_4X32_ROUND( C, D, E, F, G, H, A, B, 14, j ); \
   SHA256_4X32_ROUND( B, C, D, E, F, G, H, A, 15, j ); \
}

// LE data, no need to byte swap
static inline void SHA256_4X32_TRANSFORM( v128_t *out, v128_t *W,
                                          const v128_t *in )
{
   v128_t A, B, C, D, E, F, G, H;

   A = in[0];
   B = in[1];
   C = in[2];
   D = in[3];
   E = in[4];
   F = in[5];
   G = in[6];
   H = in[7];

   SHA256_4X32_16ROUNDS( A, B, C, D, E, F, G, H, 0 );
   SHA256_4X32_MSG_EXPANSION( W );
   SHA256_4X32_16ROUNDS( A, B, C, D, E, F, G, H, 16 );
   SHA256_4X32_MSG_EXPANSION( W );
   SHA256_4X32_16ROUNDS( A, B, C, D, E, F, G, H, 32 );
   SHA256_4X32_MSG_EXPANSION( W );
   SHA256_4X32_16ROUNDS( A, B, C, D, E, F, G, H, 48 );
   
   out[0] = v128_add32( in[0], A );
   out[1] = v128_add32( in[1], B );
   out[2] = v128_add32( in[2], C );
   out[3] = v128_add32( in[3], D );
   out[4] = v128_add32( in[4], E );
   out[5] = v128_add32( in[5], F );
   out[6] = v128_add32( in[6], G );
   out[7] = v128_add32( in[7], H );
}

// LE data, no need to byte swap
void sha256_4x32_transform_le( v128_t *state_out, const v128_t *data,
                               const v128_t *state_in )
{
   v128_t W[16];
   v128_memcpy( W, data, 16 );
   SHA256_4X32_TRANSFORM( state_out, W, state_in );
}

// BE data, need to byte swap input data
void sha256_4x32_transform_be( v128_t *state_out, const v128_t *data,
                               const v128_t *state_in )
{
   v128_t W[16];
   v128_block_bswap32( W, data );
   v128_block_bswap32( W+8, data+8 );
   SHA256_4X32_TRANSFORM( state_out, W, state_in );
}

void sha256_4x32_prehash_3rounds( v128_t *state_mid, v128_t *X,
                                  const v128_t *W, const v128_t *state_in )
{
   v128_t A, B, C, D, E, F, G, H, T1;

   X[ 0] = v128_add32( SSG2_0( W[ 1] ), W[ 0] );
   X[ 1] = v128_add32( v128_add32( SSG2_1( W[15] ), SSG2_0( W[ 2] ) ), W[ 1] );
   X[ 2] = v128_add32( SSG2_1( X[ 0] ), W[ 2] );
   X[ 3] = v128_add32( SSG2_1( X[ 1] ), SSG2_0( W[ 4] ) );
   X[ 4] = SSG2_0( W[15] );
   X[ 5] = v128_add32( SSG2_0( X[ 0] ), W[15] );
   // W[0] for round 32
   X[ 6] = v128_add32( SSG2_0( X[ 1] ), X[ 0] );

   A = v128_load( state_in     );
   B = v128_load( state_in + 1 );
   C = v128_load( state_in + 2 );
   D = v128_load( state_in + 3 );
   E = v128_load( state_in + 4 );
   F = v128_load( state_in + 5 );
   G = v128_load( state_in + 6 );
   H = v128_load( state_in + 7 );

   v128_t X_xor_Y, Y_xor_Z = v128_xor( B, C );

   SHA256_4X32_ROUND( A, B, C, D, E, F, G, H,  0, 0 );
   SHA256_4X32_ROUND( H, A, B, C, D, E, F, G,  1, 0 );
   SHA256_4X32_ROUND( G, H, A, B, C, D, E, F,  2, 0 );

   // round 3 part 1, avoid nonces W[3]
   T1 = v128_add4_32( E, BSG2_1(B), CHs(B, C, D), v128_32( K256[3] ) );
   A = v128_add32( A, T1 );
   E = v128_add32( T1, v128_add32( BSG2_0(F), MAJs(F, G, H) ) );

   v128_store( state_mid    , A );
   v128_store( state_mid + 1, B );
   v128_store( state_mid + 2, C );
   v128_store( state_mid + 3, D );
   v128_store( state_mid + 4, E );
   v128_store( state_mid + 5, F );
   v128_store( state_mid + 6, G );
   v128_store( state_mid + 7, H );
}

void sha256_4x32_final_rounds( v128_t *state_out, const v128_t *data,
          const v128_t *state_in, const v128_t *state_mid, const v128_t *X )
{
   v128_t A, B, C, D, E, F, G, H;
   v128_t W[16];

   v128_memcpy( W, data, 16 );

   A = v128_load( state_mid     );
   B = v128_load( state_mid + 1 );
   C = v128_load( state_mid + 2 );
   D = v128_load( state_mid + 3 );
   E = v128_load( state_mid + 4 );
   F = v128_load( state_mid + 5 );
   G = v128_load( state_mid + 6 );
   H = v128_load( state_mid + 7 );

   v128_t X_xor_Y, Y_xor_Z = v128_xor( F, G );

   // round 3 part 2, add nonces  
   A = v128_add32( A, W[3] );
   E = v128_add32( E, W[3] );

   SHA256_4X32_ROUND(       E, F, G, H, A, B, C, D,  4, 0 );
   SHA256_4X32_ROUND_NOMSG( D, E, F, G, H, A, B, C,  5, 0 );
   SHA256_4X32_ROUND_NOMSG( C, D, E, F, G, H, A, B,  6, 0 );
   SHA256_4X32_ROUND_NOMSG( B, C, D, E, F, G, H, A,  7, 0 );
   SHA256_4X32_ROUND_NOMSG( A, B, C, D, E, F, G, H,  8, 0 );
   SHA256_4X32_ROUND_NOMSG( H, A, B, C, D, E, F, G,  9, 0 );
   SHA256_4X32_ROUND_NOMSG( G, H, A, B, C, D, E, F, 10, 0 );
   SHA256_4X32_ROUND_NOMSG( F, G, H, A, B, C, D, E, 11, 0 );
   SHA256_4X32_ROUND_NOMSG( E, F, G, H, A, B, C, D, 12, 0 );
   SHA256_4X32_ROUND_NOMSG( D, E, F, G, H, A, B, C, 13, 0 );
   SHA256_4X32_ROUND_NOMSG( C, D, E, F, G, H, A, B, 14, 0 );
   SHA256_4X32_ROUND(       B, C, D, E, F, G, H, A, 15, 0 );

   W[ 0] = X[ 0];
   W[ 1] = X[ 1];
   W[ 2] = v128_add32( X[ 2], SSG2_0( W[ 3] ) );
   W[ 3] = v128_add32( X[ 3], W[ 3] );
   W[ 4] = v128_add32( W[ 4], SSG2_1( W[ 2] ) );
   W[ 5] = SSG2_1( W[ 3] );
   W[ 6] = v128_add32( W[15], SSG2_1( W[ 4] ) );
   W[ 7] = v128_add32( X[ 0], SSG2_1( W[ 5] ) );
   W[ 8] = v128_add32( X[ 1], SSG2_1( W[ 6] ) );
   W[ 9] = v128_add32( SSG2_1( W[ 7] ), W[ 2] );
   W[10] = v128_add32( SSG2_1( W[ 8] ), W[ 3] );
   W[11] = v128_add32( SSG2_1( W[ 9] ), W[ 4] );
   W[12] = v128_add32( SSG2_1( W[10] ), W[ 5] );
   W[13] = v128_add32( SSG2_1( W[11] ), W[ 6] );
   W[14] = v128_add32( X[ 4], v128_add32( SSG2_1( W[12] ), W[ 7] ) );
   W[15] = v128_add32( X[ 5], v128_add32( SSG2_1( W[13] ), W[ 8] ) );

   SHA256_4X32_16ROUNDS( A, B, C, D, E, F, G, H, 16 );

   W[ 0] = v128_add32( X[ 6], v128_add32( SSG2_1( W[14] ), W[ 9] ) );
   W[ 1] = SHA256_4X32_MEXP( W[15], W[10], W[ 2], W[ 1] );
   W[ 2] = SHA256_4X32_MEXP( W[ 0], W[11], W[ 3], W[ 2] );
   W[ 3] = SHA256_4X32_MEXP( W[ 1], W[12], W[ 4], W[ 3] );
   W[ 4] = SHA256_4X32_MEXP( W[ 2], W[13], W[ 5], W[ 4] );
   W[ 5] = SHA256_4X32_MEXP( W[ 3], W[14], W[ 6], W[ 5] );
   W[ 6] = SHA256_4X32_MEXP( W[ 4], W[15], W[ 7], W[ 6] );
   W[ 7] = SHA256_4X32_MEXP( W[ 5], W[ 0], W[ 8], W[ 7] );
   W[ 8] = SHA256_4X32_MEXP( W[ 6], W[ 1], W[ 9], W[ 8] );
   W[ 9] = SHA256_4X32_MEXP( W[ 7], W[ 2], W[10], W[ 9] );
   W[10] = SHA256_4X32_MEXP( W[ 8], W[ 3], W[11], W[10] );
   W[11] = SHA256_4X32_MEXP( W[ 9], W[ 4], W[12], W[11] );
   W[12] = SHA256_4X32_MEXP( W[10], W[ 5], W[13], W[12] );
   W[13] = SHA256_4X32_MEXP( W[11], W[ 6], W[14], W[13] );
   W[14] = SHA256_4X32_MEXP( W[12], W[ 7], W[15], W[14] );
   W[15] = SHA256_4X32_MEXP( W[13], W[ 8], W[ 0], W[15] );

   SHA256_4X32_16ROUNDS( A, B, C, D, E, F, G, H, 32 );
   SHA256_4X32_MSG_EXPANSION( W );
   SHA256_4X32_16ROUNDS( A, B, C, D, E, F, G, H, 48 );

   A = v128_add32( A, v128_load( state_in     ) );
   B = v128_add32( B, v128_load( state_in + 1 ) );
   C = v128_add32( C, v128_load( state_in + 2 ) );
   D = v128_add32( D, v128_load( state_in + 3 ) );
   E = v128_add32( E, v128_load( state_in + 4 ) );
   F = v128_add32( F, v128_load( state_in + 5 ) );
   G = v128_add32( G, v128_load( state_in + 6 ) );
   H = v128_add32( H, v128_load( state_in + 7 ) );

   v128_store( state_out    ,  A );
   v128_store( state_out + 1,  B );
   v128_store( state_out + 2,  C );
   v128_store( state_out + 3,  D );
   v128_store( state_out + 4,  E );
   v128_store( state_out + 5,  F );
   v128_store( state_out + 6,  G );
   v128_store( state_out + 7,  H );
}

void sha256_4x32_init( sha256_4x32_context *sc )
{
   sc->count_high = sc->count_low = 0;
   sc->val[0] = v128_32( sha256_iv[0] );
   sc->val[1] = v128_32( sha256_iv[1] );
   sc->val[2] = v128_32( sha256_iv[2] );
   sc->val[3] = v128_32( sha256_iv[3] );
   sc->val[4] = v128_32( sha256_iv[4] );
   sc->val[5] = v128_32( sha256_iv[5] );
   sc->val[6] = v128_32( sha256_iv[6] );
   sc->val[7] = v128_32( sha256_iv[7] );
}

void sha256_4x32_update( sha256_4x32_context *sc, const void *data, size_t len )
{
   v128_t *vdata = (v128_t*)data;
   size_t ptr;
   const int buf_size = 64;

   ptr = (unsigned)sc->count_low & (buf_size - 1U);
   while ( len > 0 )
   {
      size_t clen;
      uint32_t clow, clow2;

      clen = buf_size - ptr;
      if ( clen > len )
         clen = len;
      v128_memcpy( sc->buf + (ptr>>2), vdata, clen>>2 );
      vdata = vdata + (clen>>2);
      ptr += clen;
      len -= clen;
      if ( ptr == buf_size )
      {
         sha256_4x32_transform_be( sc->val, sc->buf, sc->val );
         ptr = 0;
      }
      clow = sc->count_low;
      clow2 = clow + clen;
      sc->count_low = clow2;
      if ( clow2 < clow )
         sc->count_high++;
   }
}

void sha256_4x32_close( sha256_4x32_context *sc, void *dst )
{
    unsigned ptr;
    uint32_t low, high;
    const int buf_size = 64;
    const int pad = buf_size - 8;

    ptr = (unsigned)sc->count_low & (buf_size - 1U);
    sc->buf[ ptr>>2 ] = v128_64( 0x0000008000000080 );
    ptr += 4;

    if ( ptr > pad )
    {
         v128_memset_zero( sc->buf + (ptr>>2), (buf_size - ptr) >> 2 );
         sha256_4x32_transform_be( sc->val, sc->buf, sc->val );
         v128_memset_zero( sc->buf, pad >> 2 );
    }
    else
         v128_memset_zero( sc->buf + (ptr>>2), (pad - ptr) >> 2 );

    low = sc->count_low;
    high = (sc->count_high << 3) | (low >> 29);
    low = low << 3;

    sc->buf[  pad     >> 2 ] = v128_32( bswap_32( high ) );
    sc->buf[( pad+4 ) >> 2 ] = v128_32( bswap_32( low ) );
    sha256_4x32_transform_be( sc->val, sc->buf, sc->val );

    v128_block_bswap32( dst, sc->val );
}

void sha256_4x32_full( void *dst, const void *data, size_t len )
{
   sha256_4x32_context ctx;
   sha256_4x32_init( &ctx );
   sha256_4x32_update( &ctx, data, len );
   sha256_4x32_close( &ctx, dst );
}

#endif  // SSE2 || NEON

#if defined(__AVX2__)

// SHA-256 8 way

#define BSG2_0x(x) \
   mm256_xor3( mm256_ror_32( x,  2 ), \
               mm256_ror_32( x, 13 ), \
               mm256_ror_32( x, 22 ) )

#define BSG2_1x(x) \
   mm256_xor3( mm256_ror_32( x,  6 ), \
               mm256_ror_32( x, 11 ), \
               mm256_ror_32( x, 25 ) )

#define SSG2_0x(x) \
   mm256_xor3( mm256_ror_32( x,  7 ), \
               mm256_ror_32( x, 18 ), \
               _mm256_srli_epi32( x, 3 ) ) 

#define SSG2_1x(x) \
   mm256_xor3( mm256_ror_32( x, 17 ), \
               mm256_ror_32( x, 19 ), \
               _mm256_srli_epi32( x, 10 ) )

#define SHA256_8WAY_MEXP( a, b, c, d ) \
     mm256_add4_32( SSG2_1x( a ), b, SSG2_0x( c ), d );

#define SHA256_8WAY_MEXP_16ROUNDS( W ) \
      W[ 0] = SHA256_8WAY_MEXP( W[14], W[ 9], W[ 1], W[ 0] ); \
      W[ 1] = SHA256_8WAY_MEXP( W[15], W[10], W[ 2], W[ 1] ); \
      W[ 2] = SHA256_8WAY_MEXP( W[ 0], W[11], W[ 3], W[ 2] ); \
      W[ 3] = SHA256_8WAY_MEXP( W[ 1], W[12], W[ 4], W[ 3] ); \
      W[ 4] = SHA256_8WAY_MEXP( W[ 2], W[13], W[ 5], W[ 4] ); \
      W[ 5] = SHA256_8WAY_MEXP( W[ 3], W[14], W[ 6], W[ 5] ); \
      W[ 6] = SHA256_8WAY_MEXP( W[ 4], W[15], W[ 7], W[ 6] ); \
      W[ 7] = SHA256_8WAY_MEXP( W[ 5], W[ 0], W[ 8], W[ 7] ); \
      W[ 8] = SHA256_8WAY_MEXP( W[ 6], W[ 1], W[ 9], W[ 8] ); \
      W[ 9] = SHA256_8WAY_MEXP( W[ 7], W[ 2], W[10], W[ 9] ); \
      W[10] = SHA256_8WAY_MEXP( W[ 8], W[ 3], W[11], W[10] ); \
      W[11] = SHA256_8WAY_MEXP( W[ 9], W[ 4], W[12], W[11] ); \
      W[12] = SHA256_8WAY_MEXP( W[10], W[ 5], W[13], W[12] ); \
      W[13] = SHA256_8WAY_MEXP( W[11], W[ 6], W[14], W[13] ); \
      W[14] = SHA256_8WAY_MEXP( W[12], W[ 7], W[15], W[14] ); \
      W[15] = SHA256_8WAY_MEXP( W[13], W[ 8], W[ 0], W[15] ); 

#define CHx(X, Y, Z) \
   _mm256_xor_si256( _mm256_and_si256( _mm256_xor_si256( Y, Z ), X ), Z ) 

// Use saved X_xor_Y from previous round, now called Y_xor_Z,
// and save new X_xor_Y, for next round.
#define MAJx(X, Y, Z) \
  _mm256_xor_si256( Y, _mm256_and_si256( X_xor_Y = _mm256_xor_si256( X, Y ), \
                                         Y_xor_Z ) )

#define SHA256_8WAY_ROUND_NOMSG( A, B, C, D, E, F, G, H, i, j ) \
{ \
   H = mm256_add4_32( H, BSG2_1x(E), CHx(E, F, G), \
                              v256_32( K256[(i)+(j)] ) ); \
   __m256i T = _mm256_add_epi32( BSG2_0x(A), MAJx(A, B, C) ); \
   Y_xor_Z = X_xor_Y; \
   D  = _mm256_add_epi32( D, H ); \
   H  = _mm256_add_epi32( H, T ); \
}

#define SHA256_8WAY_ROUND( A, B, C, D, E, F, G, H, i, j ) \
{ \
  __m256i T1 = _mm256_add_epi32( v256_32( K256[(j)+(i)] ), W[i] ); \
  H = _mm256_add_epi32( H, BSG2_1x( E ) ); \
  __m256i T2 = BSG2_0x( A ); \
  T1 = _mm256_add_epi32( T1, CHx( E, F, G ) ); \
  T2 = _mm256_add_epi32( T2, MAJx( A, B, C ) ); \
  H = _mm256_add_epi32( H, T1 ); \
  Y_xor_Z = X_xor_Y; \
  D  = _mm256_add_epi32( D,  H ); \
  H  = _mm256_add_epi32( H, T2 ); \
}

// read Y_xor_Z, update X_xor_Y
#define MAJ_2step(X, Y, Z, X_xor_Y, Y_xor_Z ) \
  _mm256_xor_si256( Y, _mm256_and_si256( X_xor_Y = _mm256_xor_si256( X, Y ), \
                                         Y_xor_Z ) )

// start with toc initialized to y^z, toc = B ^ C for first ound.
// First round reads toc as Y_xor_Z and saves X_xor_Y as tic.
// Second round reads tic as Y_xor_Z and saves X_xor_Y as toc.

#define SHA256_8WAY_2ROUNDS( A, B, C, D, E, F, G, H, i0, i1, j ) \
{ \
  __m256i T1 = _mm256_add_epi32( v256_32( K256[ (j)+(i0) ] ), \
                                 W[ i0 ] ); \
  H = _mm256_add_epi32( H, BSG2_1x( E ) ); \
  __m256i T2 = BSG2_0x( A ); \
  T1 = _mm256_add_epi32( T1, CHx( E, F, G ) ); \
  T2 = _mm256_add_epi32( T2, MAJ_2step( A, B, C, tic, toc ) ); \
  H = _mm256_add_epi32( H, T1 ); \
  D  = _mm256_add_epi32( D,  H ); \
  H  = _mm256_add_epi32( H, T2 ); \
\
  T1 = _mm256_add_epi32( v256_32( K256[ (j)+(i1) ] ), \
                                 W[ (i1) ] ); \
  G = _mm256_add_epi32( G, BSG2_1x( D ) ); \
  T2 = BSG2_0x( H ); \
  T1 = _mm256_add_epi32( T1, CHx( D, E, F ) ); \
  T2 = _mm256_add_epi32( T2, MAJ_2step( H, A, B, toc, tic ) ); \
  G = _mm256_add_epi32( G, T1 ); \
  C  = _mm256_add_epi32( C,  G ); \
  G  = _mm256_add_epi32( G, T2 ); \
}

#define SHA256_8WAY_16ROUNDS( A, B, C, D, E, F, G, H, j ) \
{ \
   __m256i tic, toc = _mm256_xor_si256( B, C ); \
   SHA256_8WAY_2ROUNDS( A, B, C, D, E, F, G, H,  0,  1, j ); \
   SHA256_8WAY_2ROUNDS( G, H, A, B, C, D, E, F,  2,  3, j ); \
   SHA256_8WAY_2ROUNDS( E, F, G, H, A, B, C, D,  4,  5, j ); \
   SHA256_8WAY_2ROUNDS( C, D, E, F, G, H, A, B,  6,  7, j ); \
   SHA256_8WAY_2ROUNDS( A, B, C, D, E, F, G, H,  8,  9, j ); \
   SHA256_8WAY_2ROUNDS( G, H, A, B, C, D, E, F, 10, 11, j ); \
   SHA256_8WAY_2ROUNDS( E, F, G, H, A, B, C, D, 12, 13, j ); \
   SHA256_8WAY_2ROUNDS( C, D, E, F, G, H, A, B, 14, 15, j ); \
}

static inline void SHA256_8WAY_TRANSFORM( __m256i *out, __m256i *W,
                                          const  __m256i *in ) \
{
   __m256i A, B, C, D, E, F, G, H;

   A = _mm256_load_si256( in   );
   B = _mm256_load_si256( in+1 );
   C = _mm256_load_si256( in+2 );
   D = _mm256_load_si256( in+3 );
   E = _mm256_load_si256( in+4 );
   F = _mm256_load_si256( in+5 );
   G = _mm256_load_si256( in+6 );
   H = _mm256_load_si256( in+7 );

   SHA256_8WAY_16ROUNDS( A, B, C, D, E, F, G, H, 0 );

   for ( int j = 16; j < 64; j += 16 )
   {
      SHA256_8WAY_MEXP_16ROUNDS( W );
      SHA256_8WAY_16ROUNDS( A, B, C, D, E, F, G, H, j );
   }

   out[0] = _mm256_add_epi32( in[0], A );
   out[1] = _mm256_add_epi32( in[1], B );
   out[2] = _mm256_add_epi32( in[2], C );
   out[3] = _mm256_add_epi32( in[3], D );
   out[4] = _mm256_add_epi32( in[4], E );
   out[5] = _mm256_add_epi32( in[5], F );
   out[6] = _mm256_add_epi32( in[6], G );
   out[7] = _mm256_add_epi32( in[7], H );
}

// accepts LE input data
void sha256_8x32_transform_le( __m256i *state_out, const __m256i *data,
                               const __m256i *state_in )
{
   __m256i W[16];
   memcpy_256( W, data, 16 );
   SHA256_8WAY_TRANSFORM( state_out, W, state_in );
}

// Accepts BE input data, need to bswap
void sha256_8x32_transform_be( __m256i *state_out, const __m256i *data,
                               const __m256i *state_in )
{
   __m256i W[16];
   mm256_block_bswap_32( W  , data   );
   mm256_block_bswap_32( W+8, data+8 );
   SHA256_8WAY_TRANSFORM( state_out, W, state_in );
}

// Aggressive prehashing, LE byte order
void sha256_8x32_prehash_3rounds( __m256i *state_mid, __m256i *X,
                                  const __m256i *W, const __m256i *state_in )
{
   __m256i A, B, C, D, E, F, G, H, T1;

   X[ 0] = _mm256_add_epi32( SSG2_0x( W[ 1] ), W[ 0] );
   X[ 1] = _mm256_add_epi32( _mm256_add_epi32( SSG2_1x( W[15] ),
                             SSG2_0x( W[ 2] ) ), W[ 1] );
   X[ 2] = _mm256_add_epi32( SSG2_1x( X[ 0] ), W[ 2] );
   X[ 3] = _mm256_add_epi32( SSG2_1x( X[ 1] ), SSG2_0x( W[ 4] ) );
   X[ 4] = SSG2_0x( W[15] );
   X[ 5] = _mm256_add_epi32( SSG2_0x( X[ 0] ), W[15] );
   // W[0] for round 32
   X[ 6] = _mm256_add_epi32( SSG2_0x( X[ 1] ), X[ 0] );
   
   A = _mm256_load_si256( state_in     );
   B = _mm256_load_si256( state_in + 1 );
   C = _mm256_load_si256( state_in + 2 );
   D = _mm256_load_si256( state_in + 3 );
   E = _mm256_load_si256( state_in + 4 );
   F = _mm256_load_si256( state_in + 5 );
   G = _mm256_load_si256( state_in + 6 );
   H = _mm256_load_si256( state_in + 7 );

   __m256i X_xor_Y, Y_xor_Z = _mm256_xor_si256( B, C );

   SHA256_8WAY_ROUND( A, B, C, D, E, F, G, H,  0, 0 );
   SHA256_8WAY_ROUND( H, A, B, C, D, E, F, G,  1, 0 );
   SHA256_8WAY_ROUND( G, H, A, B, C, D, E, F,  2, 0 );

   // round 3 part 1, avoid nonces W[3]
   T1 = mm256_add4_32( E, BSG2_1x(B), CHx(B, C, D),
                       v256_32( K256[3] ) );
   A = _mm256_add_epi32( A, T1 );
   E = _mm256_add_epi32( T1, _mm256_add_epi32( BSG2_0x(F),
                                               MAJx(F, G, H) ) );
   
   _mm256_store_si256( state_mid    , A );
   _mm256_store_si256( state_mid + 1, B );
   _mm256_store_si256( state_mid + 2, C );
   _mm256_store_si256( state_mid + 3, D );
   _mm256_store_si256( state_mid + 4, E );
   _mm256_store_si256( state_mid + 5, F );
   _mm256_store_si256( state_mid + 6, G );
   _mm256_store_si256( state_mid + 7, H );
}

void sha256_8x32_final_rounds( __m256i *state_out, const __m256i *data,
          const __m256i *state_in, const __m256i *state_mid, const __m256i *X )
{
   __m256i A, B, C, D, E, F, G, H;
   __m256i W[16];

   memcpy_256( W, data, 16 );

   A = _mm256_load_si256( state_mid     );
   B = _mm256_load_si256( state_mid + 1 );
   C = _mm256_load_si256( state_mid + 2 );
   D = _mm256_load_si256( state_mid + 3 );
   E = _mm256_load_si256( state_mid + 4 );
   F = _mm256_load_si256( state_mid + 5 );
   G = _mm256_load_si256( state_mid + 6 );
   H = _mm256_load_si256( state_mid + 7 );

   __m256i X_xor_Y, Y_xor_Z = _mm256_xor_si256( F, G );

   // round 3 part 2, add nonces  
   A = _mm256_add_epi32( A, W[3] );
   E = _mm256_add_epi32( E, W[3] );
   
   SHA256_8WAY_ROUND(       E, F, G, H, A, B, C, D,  4, 0 );
   SHA256_8WAY_ROUND_NOMSG( D, E, F, G, H, A, B, C,  5, 0 );
   SHA256_8WAY_ROUND_NOMSG( C, D, E, F, G, H, A, B,  6, 0 );
   SHA256_8WAY_ROUND_NOMSG( B, C, D, E, F, G, H, A,  7, 0 );
   SHA256_8WAY_ROUND_NOMSG( A, B, C, D, E, F, G, H,  8, 0 );
   SHA256_8WAY_ROUND_NOMSG( H, A, B, C, D, E, F, G,  9, 0 );
   SHA256_8WAY_ROUND_NOMSG( G, H, A, B, C, D, E, F, 10, 0 );
   SHA256_8WAY_ROUND_NOMSG( F, G, H, A, B, C, D, E, 11, 0 );
   SHA256_8WAY_ROUND_NOMSG( E, F, G, H, A, B, C, D, 12, 0 );
   SHA256_8WAY_ROUND_NOMSG( D, E, F, G, H, A, B, C, 13, 0 );
   SHA256_8WAY_ROUND_NOMSG( C, D, E, F, G, H, A, B, 14, 0 );
   SHA256_8WAY_ROUND(       B, C, D, E, F, G, H, A, 15, 0 );

   W[ 0] = X[ 0];
   W[ 1] = X[ 1];
   W[ 2] = _mm256_add_epi32( X[ 2], SSG2_0x( W[ 3] ) );
   W[ 3] = _mm256_add_epi32( X[ 3], W[ 3] );
   W[ 4] = _mm256_add_epi32( W[ 4], SSG2_1x( W[ 2] ) );
   W[ 5] = SSG2_1x( W[ 3] );
   W[ 6] = _mm256_add_epi32( W[15], SSG2_1x( W[ 4] ) );
   W[ 7] = _mm256_add_epi32( X[ 0], SSG2_1x( W[ 5] ) );
   W[ 8] = _mm256_add_epi32( X[ 1], SSG2_1x( W[ 6] ) );
   W[ 9] = _mm256_add_epi32( SSG2_1x( W[ 7] ), W[ 2] );
   W[10] = _mm256_add_epi32( SSG2_1x( W[ 8] ), W[ 3] );
   W[11] = _mm256_add_epi32( SSG2_1x( W[ 9] ), W[ 4] );
   W[12] = _mm256_add_epi32( SSG2_1x( W[10] ), W[ 5] );
   W[13] = _mm256_add_epi32( SSG2_1x( W[11] ), W[ 6] );
   W[14] = _mm256_add_epi32( X[ 4], _mm256_add_epi32( SSG2_1x( W[12] ),
                                                      W[ 7] ) );
   W[15] = _mm256_add_epi32( X[ 5], _mm256_add_epi32( SSG2_1x( W[13] ),
                                                      W[ 8] ) );

   SHA256_8WAY_16ROUNDS( A, B, C, D, E, F, G, H, 16 );

   W[ 0] = _mm256_add_epi32( X[ 6], _mm256_add_epi32( SSG2_1x( W[14] ),
                                                      W[ 9] ) );
   W[ 1] = SHA256_8WAY_MEXP( W[15], W[10], W[ 2], W[ 1] );
   W[ 2] = SHA256_8WAY_MEXP( W[ 0], W[11], W[ 3], W[ 2] );
   W[ 3] = SHA256_8WAY_MEXP( W[ 1], W[12], W[ 4], W[ 3] );
   W[ 4] = SHA256_8WAY_MEXP( W[ 2], W[13], W[ 5], W[ 4] );
   W[ 5] = SHA256_8WAY_MEXP( W[ 3], W[14], W[ 6], W[ 5] );
   W[ 6] = SHA256_8WAY_MEXP( W[ 4], W[15], W[ 7], W[ 6] );
   W[ 7] = SHA256_8WAY_MEXP( W[ 5], W[ 0], W[ 8], W[ 7] );
   W[ 8] = SHA256_8WAY_MEXP( W[ 6], W[ 1], W[ 9], W[ 8] );
   W[ 9] = SHA256_8WAY_MEXP( W[ 7], W[ 2], W[10], W[ 9] );
   W[10] = SHA256_8WAY_MEXP( W[ 8], W[ 3], W[11], W[10] );
   W[11] = SHA256_8WAY_MEXP( W[ 9], W[ 4], W[12], W[11] );
   W[12] = SHA256_8WAY_MEXP( W[10], W[ 5], W[13], W[12] );
   W[13] = SHA256_8WAY_MEXP( W[11], W[ 6], W[14], W[13] );
   W[14] = SHA256_8WAY_MEXP( W[12], W[ 7], W[15], W[14] );
   W[15] = SHA256_8WAY_MEXP( W[13], W[ 8], W[ 0], W[15] ); 

   SHA256_8WAY_16ROUNDS( A, B, C, D, E, F, G, H, 32 );

   SHA256_8WAY_MEXP_16ROUNDS( W );
   SHA256_8WAY_16ROUNDS( A, B, C, D, E, F, G, H, 48 );
   
   A = _mm256_add_epi32( A, _mm256_load_si256( state_in     ) );
   B = _mm256_add_epi32( B, _mm256_load_si256( state_in + 1 ) );
   C = _mm256_add_epi32( C, _mm256_load_si256( state_in + 2 ) );
   D = _mm256_add_epi32( D, _mm256_load_si256( state_in + 3 ) );
   E = _mm256_add_epi32( E, _mm256_load_si256( state_in + 4 ) );
   F = _mm256_add_epi32( F, _mm256_load_si256( state_in + 5 ) );
   G = _mm256_add_epi32( G, _mm256_load_si256( state_in + 6 ) );
   H = _mm256_add_epi32( H, _mm256_load_si256( state_in + 7 ) );

   _mm256_store_si256( state_out    ,  A );
   _mm256_store_si256( state_out + 1,  B );
   _mm256_store_si256( state_out + 2,  C );
   _mm256_store_si256( state_out + 3,  D );
   _mm256_store_si256( state_out + 4,  E );
   _mm256_store_si256( state_out + 5,  F );
   _mm256_store_si256( state_out + 6,  G );
   _mm256_store_si256( state_out + 7,  H );
}

int sha256_8x32_transform_le_short( __m256i *state_out, const __m256i *data,
                           const __m256i *state_in, const uint32_t *target )
{
   __m256i A, B, C, D, E, F, G, H, G57, H56;
   __m256i vmask, targ, hash;
   __m256i W[16];  memcpy_256( W, data, 16 );
   uint8_t flip, t6_mask, t7_mask;

   A = _mm256_load_si256( state_in   );
   B = _mm256_load_si256( state_in+1 );
   C = _mm256_load_si256( state_in+2 );
   D = _mm256_load_si256( state_in+3 );
   E = _mm256_load_si256( state_in+4 );
   F = _mm256_load_si256( state_in+5 );
   G = _mm256_load_si256( state_in+6 );
   H = _mm256_load_si256( state_in+7 );

   const __m256i istate6 = G;
   const __m256i istate7 = H;

   __m256i X_xor_Y, Y_xor_Z = _mm256_xor_si256( B, C );

   // rounds 0 to 16, ignore zero padding W[9..14]
   SHA256_8WAY_ROUND(       A, B, C, D, E, F, G, H,  0, 0 );
   SHA256_8WAY_ROUND(       H, A, B, C, D, E, F, G,  1, 0 );
   SHA256_8WAY_ROUND(       G, H, A, B, C, D, E, F,  2, 0 );
   SHA256_8WAY_ROUND(       F, G, H, A, B, C, D, E,  3, 0 );
   SHA256_8WAY_ROUND(       E, F, G, H, A, B, C, D,  4, 0 );
   SHA256_8WAY_ROUND(       D, E, F, G, H, A, B, C,  5, 0 );
   SHA256_8WAY_ROUND(       C, D, E, F, G, H, A, B,  6, 0 );
   SHA256_8WAY_ROUND(       B, C, D, E, F, G, H, A,  7, 0 );
   SHA256_8WAY_ROUND(       A, B, C, D, E, F, G, H,  8, 0 );
   SHA256_8WAY_ROUND_NOMSG( H, A, B, C, D, E, F, G,  9, 0 );
   SHA256_8WAY_ROUND_NOMSG( G, H, A, B, C, D, E, F, 10, 0 );
   SHA256_8WAY_ROUND_NOMSG( F, G, H, A, B, C, D, E, 11, 0 );
   SHA256_8WAY_ROUND_NOMSG( E, F, G, H, A, B, C, D, 12, 0 );
   SHA256_8WAY_ROUND_NOMSG( D, E, F, G, H, A, B, C, 13, 0 );
   SHA256_8WAY_ROUND_NOMSG( C, D, E, F, G, H, A, B, 14, 0 );
   SHA256_8WAY_ROUND(       B, C, D, E, F, G, H, A, 15, 0 );
  
   // rounds 16 ro 31
   SHA256_8WAY_MEXP_16ROUNDS( W );
   SHA256_8WAY_16ROUNDS( A, B, C, D, E, F, G, H, 16 );

   // rounds 32  to 47
   SHA256_8WAY_MEXP_16ROUNDS( W );
   SHA256_8WAY_16ROUNDS( A, B, C, D, E, F, G, H, 32 );

   // rounds 48 to 60 mexp
   W[ 0] = SHA256_8WAY_MEXP( W[14], W[ 9], W[ 1], W[ 0] );
   W[ 1] = SHA256_8WAY_MEXP( W[15], W[10], W[ 2], W[ 1] );
   W[ 2] = SHA256_8WAY_MEXP( W[ 0], W[11], W[ 3], W[ 2] );
   W[ 3] = SHA256_8WAY_MEXP( W[ 1], W[12], W[ 4], W[ 3] );
   W[ 4] = SHA256_8WAY_MEXP( W[ 2], W[13], W[ 5], W[ 4] );
   W[ 5] = SHA256_8WAY_MEXP( W[ 3], W[14], W[ 6], W[ 5] );
   W[ 6] = SHA256_8WAY_MEXP( W[ 4], W[15], W[ 7], W[ 6] );
   W[ 7] = SHA256_8WAY_MEXP( W[ 5], W[ 0], W[ 8], W[ 7] );
   W[ 8] = SHA256_8WAY_MEXP( W[ 6], W[ 1], W[ 9], W[ 8] );
   W[ 9] = SHA256_8WAY_MEXP( W[ 7], W[ 2], W[10], W[ 9] );
   W[10] = SHA256_8WAY_MEXP( W[ 8], W[ 3], W[11], W[10] );
   W[11] = SHA256_8WAY_MEXP( W[ 9], W[ 4], W[12], W[11] );
   W[12] = SHA256_8WAY_MEXP( W[10], W[ 5], W[13], W[12] );

   Y_xor_Z = _mm256_xor_si256( B, C );

   // Rounds 48 to 55
   SHA256_8WAY_ROUND( A, B, C, D, E, F, G, H,  0, 48 );
   SHA256_8WAY_ROUND( H, A, B, C, D, E, F, G,  1, 48 );
   SHA256_8WAY_ROUND( G, H, A, B, C, D, E, F,  2, 48 );
   SHA256_8WAY_ROUND( F, G, H, A, B, C, D, E,  3, 48 );
   SHA256_8WAY_ROUND( E, F, G, H, A, B, C, D,  4, 48 );
   SHA256_8WAY_ROUND( D, E, F, G, H, A, B, C,  5, 48 );
   SHA256_8WAY_ROUND( C, D, E, F, G, H, A, B,  6, 48 );
   SHA256_8WAY_ROUND( B, C, D, E, F, G, H, A,  7, 48 );

   // Round 56
   H = _mm256_add_epi32( v256_32( K256[56] ),
                 mm256_add4_32( BSG2_1x( E ), CHx( E, F, G ), W[ 8], H ) );
   D = _mm256_add_epi32( D, H );
   H56 = _mm256_add_epi32( H, _mm256_add_epi32( BSG2_0x( A ),
                                                   MAJx( A, B, C ) ) );
   Y_xor_Z = X_xor_Y; 
   
   // Rounds 57 to 60 part 1
   G = _mm256_add_epi32( v256_32( K256[57] ),
                 mm256_add4_32( BSG2_1x( D ), CHx( D, E, F ), W[ 9], G ) );
   C = _mm256_add_epi32( C, G );
   G57 = _mm256_add_epi32( G, MAJx( H56, A, B ) );
   
   F = _mm256_add_epi32( v256_32( K256[58] ),
                 mm256_add4_32( BSG2_1x( C ), CHx( C, D, E ), W[10], F ) );
   B = _mm256_add_epi32( B, F );

   E = _mm256_add_epi32( v256_32( K256[59] ),
                 mm256_add4_32( BSG2_1x( B ), CHx( B, C, D ), W[11], E ) );
   A = _mm256_add_epi32( A, E );

   D = _mm256_add_epi32( v256_32( K256[60] ),
                 mm256_add4_32( BSG2_1x( A ), CHx( A, B, C ), W[12], D ) );
   H = _mm256_add_epi32( H56, D );

   // Got H, test it.
   hash = mm256_bswap_32( _mm256_add_epi32( H, istate7 ) );
   targ = v256_32( target[7] );
   // A simple unsigned LE test is complicated by the lack of a cmple
   // instruction, and lack of unsigned compares in AVX2.
   flip = ( (int)target[7] < 0 ? -1 : 0 ) ^ mm256_movmask_32( hash );
   if ( likely( 0xff == ( t7_mask = ( flip ^
                    mm256_movmask_32( _mm256_cmpgt_epi32( hash, targ ) ) ) )))
      return 0;
   t6_mask = mm256_movmask_32( vmask =_mm256_cmpeq_epi32( hash, targ ) );

   // Round 57 part 2
   G57 = _mm256_add_epi32( G57, BSG2_0x( H56 ) );
   Y_xor_Z = X_xor_Y;

   // Round 61 part 1
   W[13] = SHA256_8WAY_MEXP( W[11], W[ 6], W[14], W[13] );
   C = _mm256_add_epi32( v256_32( K256[61] ),
                 mm256_add4_32( BSG2_1x( H ), CHx( H, A, B ), W[13], C ) );
   G = _mm256_add_epi32( G57, C );

   if ( t6_mask == (0xff & ~t7_mask ) )
   { 
      // Testing H was inconclusive: hash7 == target7, need to test G
      targ = _mm256_and_si256( vmask, v256_32( target[6] ) );
      hash = mm256_bswap_32( _mm256_add_epi32( G, istate6 ) );
      flip = ( (int)target[6] < 0 ? -1 : 0 ) ^ mm256_movmask_32( hash );
      if ( likely( 0 != ( t6_mask & ( flip ^
                   mm256_movmask_32( _mm256_cmpgt_epi32( hash, targ ) ) ) ) ))
         return 0;
   }

   // Rounds 58 to 61 part 2
   F = _mm256_add_epi32( F, _mm256_add_epi32( BSG2_0x( G57 ),
                                                 MAJx( G57, H, A ) ) );
   Y_xor_Z = X_xor_Y;

   E = _mm256_add_epi32( E, _mm256_add_epi32( BSG2_0x( F ),
                                                 MAJx( F, G57, H ) ) );
   Y_xor_Z = X_xor_Y;

   D = _mm256_add_epi32( D, _mm256_add_epi32( BSG2_0x( E ),
                                                 MAJx( E, F, G57 ) ) );
   Y_xor_Z = X_xor_Y;

   C = _mm256_add_epi32( C, _mm256_add_epi32( BSG2_0x( D ),
                                                 MAJx( D, E, F ) ) );
   Y_xor_Z = X_xor_Y;

   // Rounds 62 & 63
   W[14] = SHA256_8WAY_MEXP( W[12], W[ 7], W[15], W[14] );
   W[15] = SHA256_8WAY_MEXP( W[13], W[ 8], W[ 0], W[15] );

   SHA256_8WAY_ROUND( C, D, E, F, G, H, A, B, 14, 48 );
   SHA256_8WAY_ROUND( B, C, D, E, F, G, H, A, 15, 48 );

   state_out[0] = _mm256_add_epi32( state_in[0], A );
   state_out[1] = _mm256_add_epi32( state_in[1], B );
   state_out[2] = _mm256_add_epi32( state_in[2], C );
   state_out[3] = _mm256_add_epi32( state_in[3], D );
   state_out[4] = _mm256_add_epi32( state_in[4], E );
   state_out[5] = _mm256_add_epi32( state_in[5], F );
   state_out[6] = _mm256_add_epi32( state_in[6], G );
   state_out[7] = _mm256_add_epi32( state_in[7], H );

   return 1;
}

void sha256_8x32_init( sha256_8x32_context *sc )
{
   sc->count_high = sc->count_low = 0;
   sc->val[0] = v256_32( sha256_iv[0] );
   sc->val[1] = v256_32( sha256_iv[1] );
   sc->val[2] = v256_32( sha256_iv[2] );
   sc->val[3] = v256_32( sha256_iv[3] );
   sc->val[4] = v256_32( sha256_iv[4] );
   sc->val[5] = v256_32( sha256_iv[5] );
   sc->val[6] = v256_32( sha256_iv[6] );
   sc->val[7] = v256_32( sha256_iv[7] );
}

// need to handle odd byte length for yespower.
// Assume only last update is odd.

void sha256_8x32_update( sha256_8x32_context *sc, const void *data, size_t len )
{
   __m256i *vdata = (__m256i*)data;
   size_t ptr;
   const int buf_size = 64;

   ptr = (unsigned)sc->count_low & (buf_size - 1U);
   while ( len > 0 )
   {
      size_t clen;
      uint32_t clow, clow2;

      clen = buf_size - ptr;
      if ( clen > len )
         clen = len;
      memcpy_256( sc->buf + (ptr>>2), vdata, clen>>2 );
      vdata = vdata + (clen>>2);
      ptr += clen;
      len -= clen;
      if ( ptr == buf_size )
      {
         sha256_8x32_transform_be( sc->val, sc->buf, sc->val );
         ptr = 0;
      }
      clow = sc->count_low;
      clow2 = clow + clen;
      sc->count_low = clow2;
      if ( clow2 < clow )
         sc->count_high++;
   }
}

void sha256_8x32_close( sha256_8x32_context *sc, void *dst )
{
    unsigned ptr;
    uint32_t low, high;
    const int buf_size = 64;
    const int pad = buf_size - 8;

    ptr = (unsigned)sc->count_low & (buf_size - 1U);
    sc->buf[ ptr>>2 ] = v256_64( 0x0000008000000080 );
    ptr += 4;

    if ( ptr > pad )
    {
         memset_zero_256( sc->buf + (ptr>>2), (buf_size - ptr) >> 2 );
         sha256_8x32_transform_be( sc->val, sc->buf, sc->val );
         memset_zero_256( sc->buf, pad >> 2 );
    }
    else
         memset_zero_256( sc->buf + (ptr>>2), (pad - ptr) >> 2 );

    low = sc->count_low;
    high = (sc->count_high << 3) | (low >> 29);
    low = low << 3;

    sc->buf[   pad     >> 2 ] = v256_32( bswap_32( high ) );
    sc->buf[ ( pad+4 ) >> 2 ] = v256_32( bswap_32( low ) );

    sha256_8x32_transform_be( sc->val, sc->buf, sc->val );

    mm256_block_bswap_32( dst, sc->val );
}

void sha256_8x32_full( void *dst, const void *data, size_t len )
{
   sha256_8x32_context ctx;
   sha256_8x32_init( &ctx );
   sha256_8x32_update( &ctx, data, len );
   sha256_8x32_close( &ctx, dst );
}

#if defined(SIMD512)

// SHA-256 16 way

#define CHx16(X, Y, Z)    _mm512_ternarylogic_epi32( X, Y, Z, 0xca )

#define MAJx16(X, Y, Z)   _mm512_ternarylogic_epi32( X, Y, Z, 0xe8 )

#define BSG2_0x16(x)      mm512_xor3( _mm512_ror_epi32( x,  2 ), \
                                      _mm512_ror_epi32( x, 13 ), \
                                      _mm512_ror_epi32( x, 22 ) )

#define BSG2_1x16(x)      mm512_xor3( _mm512_ror_epi32( x,  6 ), \
                                      _mm512_ror_epi32( x, 11 ), \
                                      _mm512_ror_epi32( x, 25 ) )

#define SSG2_0x16(x)      mm512_xor3( _mm512_ror_epi32(  x,  7 ), \
                                      _mm512_ror_epi32(  x, 18 ), \
                                      _mm512_srli_epi32( x,  3 ) )

#define SSG2_1x16(x)      mm512_xor3( _mm512_ror_epi32(  x, 17 ), \
                                      _mm512_ror_epi32(  x, 19 ), \
                                      _mm512_srli_epi32( x, 10 ) )

#define SHA256_16WAY_MEXP( a, b, c, d ) \
     mm512_add4_32( SSG2_1x16( a ), b, SSG2_0x16( c ), d );

#define SHA256_MEXP_16WAY_16ROUNDS( W ) \
   W[ 0] = SHA256_16WAY_MEXP( W[14], W[ 9], W[ 1], W[ 0] ); \
   W[ 1] = SHA256_16WAY_MEXP( W[15], W[10], W[ 2], W[ 1] ); \
   W[ 2] = SHA256_16WAY_MEXP( W[ 0], W[11], W[ 3], W[ 2] ); \
   W[ 3] = SHA256_16WAY_MEXP( W[ 1], W[12], W[ 4], W[ 3] ); \
   W[ 4] = SHA256_16WAY_MEXP( W[ 2], W[13], W[ 5], W[ 4] ); \
   W[ 5] = SHA256_16WAY_MEXP( W[ 3], W[14], W[ 6], W[ 5] ); \
   W[ 6] = SHA256_16WAY_MEXP( W[ 4], W[15], W[ 7], W[ 6] ); \
   W[ 7] = SHA256_16WAY_MEXP( W[ 5], W[ 0], W[ 8], W[ 7] ); \
   W[ 8] = SHA256_16WAY_MEXP( W[ 6], W[ 1], W[ 9], W[ 8] ); \
   W[ 9] = SHA256_16WAY_MEXP( W[ 7], W[ 2], W[10], W[ 9] ); \
   W[10] = SHA256_16WAY_MEXP( W[ 8], W[ 3], W[11], W[10] ); \
   W[11] = SHA256_16WAY_MEXP( W[ 9], W[ 4], W[12], W[11] ); \
   W[12] = SHA256_16WAY_MEXP( W[10], W[ 5], W[13], W[12] ); \
   W[13] = SHA256_16WAY_MEXP( W[11], W[ 6], W[14], W[13] ); \
   W[14] = SHA256_16WAY_MEXP( W[12], W[ 7], W[15], W[14] ); \
   W[15] = SHA256_16WAY_MEXP( W[13], W[ 8], W[ 0], W[15] );

#define SHA256_16WAY_ROUND( A, B, C, D, E, F, G, H, i, j ) \
{ \
  __m512i T1 = _mm512_add_epi32( v512_32( K256[(j)+(i)] ), W[i] ); \
  H = _mm512_add_epi32( H, BSG2_1x16( E ) ); \
  __m512i T2 = BSG2_0x16( A ); \
  T1 = _mm512_add_epi32( T1, CHx16( E, F, G ) ); \
  T2 = _mm512_add_epi32( T2, MAJx16( A, B, C ) ); \
  H = _mm512_add_epi32( H, T1 ); \
  D  = _mm512_add_epi32( D,  H ); \
  H  = _mm512_add_epi32( H, T2 ); \
}
   
#define SHA256_16WAY_ROUND_NOMSG( A, B, C, D, E, F, G, H, i, j ) \
{ \
   H = mm512_add4_32( H, BSG2_1x16(E), CHx16(E, F, G), \
                              v512_32( K256[(i)+(j)] ) ); \
   __m512i T = _mm512_add_epi32( BSG2_0x16(A), MAJx16(A, B, C) ); \
   D  = _mm512_add_epi32( D, H ); \
   H  = _mm512_add_epi32( H, T ); \
}

#define SHA256_16WAY_16ROUNDS( A, B, C, D, E, F, G, H, j ) \
   SHA256_16WAY_ROUND( A, B, C, D, E, F, G, H,  0, j ); \
   SHA256_16WAY_ROUND( H, A, B, C, D, E, F, G,  1, j ); \
   SHA256_16WAY_ROUND( G, H, A, B, C, D, E, F,  2, j ); \
   SHA256_16WAY_ROUND( F, G, H, A, B, C, D, E,  3, j ); \
   SHA256_16WAY_ROUND( E, F, G, H, A, B, C, D,  4, j ); \
   SHA256_16WAY_ROUND( D, E, F, G, H, A, B, C,  5, j ); \
   SHA256_16WAY_ROUND( C, D, E, F, G, H, A, B,  6, j ); \
   SHA256_16WAY_ROUND( B, C, D, E, F, G, H, A,  7, j ); \
   SHA256_16WAY_ROUND( A, B, C, D, E, F, G, H,  8, j ); \
   SHA256_16WAY_ROUND( H, A, B, C, D, E, F, G,  9, j ); \
   SHA256_16WAY_ROUND( G, H, A, B, C, D, E, F, 10, j ); \
   SHA256_16WAY_ROUND( F, G, H, A, B, C, D, E, 11, j ); \
   SHA256_16WAY_ROUND( E, F, G, H, A, B, C, D, 12, j ); \
   SHA256_16WAY_ROUND( D, E, F, G, H, A, B, C, 13, j ); \
   SHA256_16WAY_ROUND( C, D, E, F, G, H, A, B, 14, j ); \
   SHA256_16WAY_ROUND( B, C, D, E, F, G, H, A, 15, j );

static inline void SHA256_16WAY_TRANSFORM( __m512i *out, __m512i *W,
                                           const  __m512i *in ) \
{
   __m512i A, B, C, D, E, F, G, H;
   A = _mm512_load_si512( in   );
   B = _mm512_load_si512( in+1 );
   C = _mm512_load_si512( in+2 );
   D = _mm512_load_si512( in+3 );
   E = _mm512_load_si512( in+4 );
   F = _mm512_load_si512( in+5 );
   G = _mm512_load_si512( in+6 );
   H = _mm512_load_si512( in+7 );

   SHA256_16WAY_16ROUNDS( A, B, C, D, E, F, G, H,  0 );   
   SHA256_MEXP_16WAY_16ROUNDS( W );
   SHA256_16WAY_16ROUNDS( A, B, C, D, E, F, G, H, 16 );
   SHA256_MEXP_16WAY_16ROUNDS( W );
   SHA256_16WAY_16ROUNDS( A, B, C, D, E, F, G, H, 32 );
   SHA256_MEXP_16WAY_16ROUNDS( W );
   SHA256_16WAY_16ROUNDS( A, B, C, D, E, F, G, H, 48 );

   out[0] = _mm512_add_epi32( in[0], A );
   out[1] = _mm512_add_epi32( in[1], B );
   out[2] = _mm512_add_epi32( in[2], C );
   out[3] = _mm512_add_epi32( in[3], D );
   out[4] = _mm512_add_epi32( in[4], E );
   out[5] = _mm512_add_epi32( in[5], F );
   out[6] = _mm512_add_epi32( in[6], G );
   out[7] = _mm512_add_epi32( in[7], H );
}

// accepts LE input data
void sha256_16x32_transform_le( __m512i *state_out, const __m512i *data,
                                const __m512i *state_in )
{
   __m512i W[16];
   memcpy_512( W, data, 16 );
   SHA256_16WAY_TRANSFORM( state_out, W, state_in );
}

// Accepts BE input data, need to bswap
void sha256_16x32_transform_be( __m512i *state_out, const __m512i *data,
                                const __m512i *state_in )
{
   __m512i W[16];
   mm512_block_bswap_32( W  , data   );
   mm512_block_bswap_32( W+8, data+8 );
   SHA256_16WAY_TRANSFORM( state_out, W, state_in );
}
 
// Aggressive prehashing, LE byte order
void sha256_16x32_prehash_3rounds( __m512i *state_mid, __m512i *X, 
                                   const __m512i *W, const __m512i *state_in )
{
   __m512i A, B, C, D, E, F, G, H, T1;

   // rounds 16 to 32 mexp part 1
   X[ 0] = _mm512_add_epi32( SSG2_0x16( W[ 1] ), W[ 0] );
   X[ 1] = _mm512_add_epi32( _mm512_add_epi32( SSG2_1x16( W[15] ),
                             SSG2_0x16( W[ 2] ) ), W[ 1] );
   X[ 2] = _mm512_add_epi32( SSG2_1x16( X[ 0] ), W[ 2] );
   X[ 3] = _mm512_add_epi32( SSG2_1x16( X[ 1] ), SSG2_0x16( W[ 4] ) );         
   X[ 4] = SSG2_0x16( W[15] );
   X[ 5] = _mm512_add_epi32( SSG2_0x16( X[ 0] ), W[15] );

   // round 32 mexp part 1
   X[ 6] = _mm512_add_epi32( SSG2_0x16( X[ 1] ), X[ 0] );

   A = _mm512_load_si512( state_in     );
   B = _mm512_load_si512( state_in + 1 );
   C = _mm512_load_si512( state_in + 2 );
   D = _mm512_load_si512( state_in + 3 );
   E = _mm512_load_si512( state_in + 4 );
   F = _mm512_load_si512( state_in + 5 );
   G = _mm512_load_si512( state_in + 6 );
   H = _mm512_load_si512( state_in + 7 );

   // rounds 0 to 2
   SHA256_16WAY_ROUND( A, B, C, D, E, F, G, H,  0, 0 );
   SHA256_16WAY_ROUND( H, A, B, C, D, E, F, G,  1, 0 );
   SHA256_16WAY_ROUND( G, H, A, B, C, D, E, F,  2, 0 );

   // round 3 part 1, avoid nonces W[3]
   T1 = mm512_add4_32( E, BSG2_1x16(B), CHx16(B, C, D), 
                       v512_32( K256[3] ) );
   A = _mm512_add_epi32( A, T1 );
   E = _mm512_add_epi32( T1, _mm512_add_epi32( BSG2_0x16(F),
                                               MAJx16(F, G, H) ) ); 

   _mm512_store_si512( state_mid    , A );
   _mm512_store_si512( state_mid + 1, B );
   _mm512_store_si512( state_mid + 2, C );
   _mm512_store_si512( state_mid + 3, D );
   _mm512_store_si512( state_mid + 4, E );
   _mm512_store_si512( state_mid + 5, F );
   _mm512_store_si512( state_mid + 6, G );
   _mm512_store_si512( state_mid + 7, H );
}   

void sha256_16x32_final_rounds( __m512i *state_out, const __m512i *data,
          const __m512i *state_in, const __m512i *state_mid, const __m512i *X )
{
   __m512i A, B, C, D, E, F, G, H;
   __m512i W[16];

   memcpy_512( W, data, 16 );

   A = _mm512_load_si512( state_mid     );
   B = _mm512_load_si512( state_mid + 1 );
   C = _mm512_load_si512( state_mid + 2 );
   D = _mm512_load_si512( state_mid + 3 );
   E = _mm512_load_si512( state_mid + 4 );
   F = _mm512_load_si512( state_mid + 5 );
   G = _mm512_load_si512( state_mid + 6 );
   H = _mm512_load_si512( state_mid + 7 );

   // round 3 part 2, add nonces  
   A = _mm512_add_epi32( A, W[3] );
   E = _mm512_add_epi32( E, W[3] );

   // rounds 4 to 15, ignore zero padding W[5..14]
   SHA256_16WAY_ROUND      ( E, F, G, H, A, B, C, D,  4, 0 );   
   SHA256_16WAY_ROUND_NOMSG( D, E, F, G, H, A, B, C,  5, 0 );
   SHA256_16WAY_ROUND_NOMSG( C, D, E, F, G, H, A, B,  6, 0 );
   SHA256_16WAY_ROUND_NOMSG( B, C, D, E, F, G, H, A,  7, 0 );
   SHA256_16WAY_ROUND_NOMSG( A, B, C, D, E, F, G, H,  8, 0 );
   SHA256_16WAY_ROUND_NOMSG( H, A, B, C, D, E, F, G,  9, 0 );
   SHA256_16WAY_ROUND_NOMSG( G, H, A, B, C, D, E, F, 10, 0 );
   SHA256_16WAY_ROUND_NOMSG( F, G, H, A, B, C, D, E, 11, 0 );
   SHA256_16WAY_ROUND_NOMSG( E, F, G, H, A, B, C, D, 12, 0 );
   SHA256_16WAY_ROUND_NOMSG( D, E, F, G, H, A, B, C, 13, 0 );
   SHA256_16WAY_ROUND_NOMSG( C, D, E, F, G, H, A, B, 14, 0 );
   SHA256_16WAY_ROUND      ( B, C, D, E, F, G, H, A, 15, 0 );

   // rounds 16 to 31 mexp part 2, add nonces.
   W[ 0] = X[ 0];
   W[ 1] = X[ 1];
   W[ 2] = _mm512_add_epi32( X[ 2], SSG2_0x16( W[ 3] ) );
   W[ 3] = _mm512_add_epi32( X[ 3], W[ 3] );
   W[ 4] = _mm512_add_epi32( W[ 4], SSG2_1x16( W[ 2] ) );
   W[ 5] = SSG2_1x16( W[ 3] );
   W[ 6] = _mm512_add_epi32( W[15], SSG2_1x16( W[ 4] ) );
   W[ 7] = _mm512_add_epi32( X[ 0], SSG2_1x16( W[ 5] ) );
   W[ 8] = _mm512_add_epi32( X[ 1], SSG2_1x16( W[ 6] ) );
   W[ 9] = _mm512_add_epi32( SSG2_1x16( W[ 7] ), W[ 2] );
   W[10] = _mm512_add_epi32( SSG2_1x16( W[ 8] ), W[ 3] );
   W[11] = _mm512_add_epi32( SSG2_1x16( W[ 9] ), W[ 4] );
   W[12] = _mm512_add_epi32( SSG2_1x16( W[10] ), W[ 5] );
   W[13] = _mm512_add_epi32( SSG2_1x16( W[11] ), W[ 6] );
   W[14] = _mm512_add_epi32( X[ 4], _mm512_add_epi32( SSG2_1x16( W[12] ),
                                                      W[ 7] ) );
   W[15] = _mm512_add_epi32( X[ 5], _mm512_add_epi32( SSG2_1x16( W[13] ),
                                                      W[ 8] ) );

   SHA256_16WAY_16ROUNDS( A, B, C, D, E, F, G, H, 16 );

   // rounds 32 to 63   
   W[ 0] = _mm512_add_epi32( X[ 6], _mm512_add_epi32( SSG2_1x16( W[14] ),
                                                      W[ 9] ) ); 
   W[ 1] = SHA256_16WAY_MEXP( W[15], W[10], W[ 2], W[ 1] );
   W[ 2] = SHA256_16WAY_MEXP( W[ 0], W[11], W[ 3], W[ 2] );
   W[ 3] = SHA256_16WAY_MEXP( W[ 1], W[12], W[ 4], W[ 3] );
   W[ 4] = SHA256_16WAY_MEXP( W[ 2], W[13], W[ 5], W[ 4] );
   W[ 5] = SHA256_16WAY_MEXP( W[ 3], W[14], W[ 6], W[ 5] );
   W[ 6] = SHA256_16WAY_MEXP( W[ 4], W[15], W[ 7], W[ 6] );
   W[ 7] = SHA256_16WAY_MEXP( W[ 5], W[ 0], W[ 8], W[ 7] );
   W[ 8] = SHA256_16WAY_MEXP( W[ 6], W[ 1], W[ 9], W[ 8] );
   W[ 9] = SHA256_16WAY_MEXP( W[ 7], W[ 2], W[10], W[ 9] );
   W[10] = SHA256_16WAY_MEXP( W[ 8], W[ 3], W[11], W[10] );
   W[11] = SHA256_16WAY_MEXP( W[ 9], W[ 4], W[12], W[11] );
   W[12] = SHA256_16WAY_MEXP( W[10], W[ 5], W[13], W[12] );
   W[13] = SHA256_16WAY_MEXP( W[11], W[ 6], W[14], W[13] );
   W[14] = SHA256_16WAY_MEXP( W[12], W[ 7], W[15], W[14] );
   W[15] = SHA256_16WAY_MEXP( W[13], W[ 8], W[ 0], W[15] );

   SHA256_16WAY_16ROUNDS( A, B, C, D, E, F, G, H, 32 );
   SHA256_MEXP_16WAY_16ROUNDS( W );
   SHA256_16WAY_16ROUNDS( A, B, C, D, E, F, G, H, 48 );

   A = _mm512_add_epi32( A, _mm512_load_si512( state_in     ) );
   B = _mm512_add_epi32( B, _mm512_load_si512( state_in + 1 ) );
   C = _mm512_add_epi32( C, _mm512_load_si512( state_in + 2 ) );
   D = _mm512_add_epi32( D, _mm512_load_si512( state_in + 3 ) );
   E = _mm512_add_epi32( E, _mm512_load_si512( state_in + 4 ) );
   F = _mm512_add_epi32( F, _mm512_load_si512( state_in + 5 ) );
   G = _mm512_add_epi32( G, _mm512_load_si512( state_in + 6 ) );
   H = _mm512_add_epi32( H, _mm512_load_si512( state_in + 7 ) );
   
   _mm512_store_si512( state_out    ,  A );
   _mm512_store_si512( state_out + 1,  B );
   _mm512_store_si512( state_out + 2,  C );
   _mm512_store_si512( state_out + 3,  D );
   _mm512_store_si512( state_out + 4,  E );
   _mm512_store_si512( state_out + 5,  F );
   _mm512_store_si512( state_out + 6,  G );
   _mm512_store_si512( state_out + 7,  H );
}

// returns 0 if hash aborted early and invalid,
// returns 1 for completed hash with at least one valid candidate.
int sha256_16x32_transform_le_short( __m512i *state_out, const __m512i *data,
                              const __m512i *state_in, const uint32_t *target )
{
   __m512i A, B, C, D, E, F, G, H, hash, targ, G57, H56;
   __m512i W[16];      memcpy_512( W, data, 16 );
   __mmask16 mask;
   
   A = _mm512_load_si512( state_in   );
   B = _mm512_load_si512( state_in+1 );
   C = _mm512_load_si512( state_in+2 );
   D = _mm512_load_si512( state_in+3 );
   E = _mm512_load_si512( state_in+4 );
   F = _mm512_load_si512( state_in+5 );
   G = _mm512_load_si512( state_in+6 );
   H = _mm512_load_si512( state_in+7 );

   const __m512i istate6 = G;
   const __m512i istate7 = H;
   
   // rounds 0 to 8
   SHA256_16WAY_ROUND( A, B, C, D, E, F, G, H,  0, 0 );
   SHA256_16WAY_ROUND( H, A, B, C, D, E, F, G,  1, 0 );
   SHA256_16WAY_ROUND( G, H, A, B, C, D, E, F,  2, 0 );
   SHA256_16WAY_ROUND( F, G, H, A, B, C, D, E,  3, 0 );
   SHA256_16WAY_ROUND( E, F, G, H, A, B, C, D,  4, 0 );
   SHA256_16WAY_ROUND( D, E, F, G, H, A, B, C,  5, 0 );
   SHA256_16WAY_ROUND( C, D, E, F, G, H, A, B,  6, 0 );
   SHA256_16WAY_ROUND( B, C, D, E, F, G, H, A,  7, 0 );
   SHA256_16WAY_ROUND( A, B, C, D, E, F, G, H,  8, 0 );

   // rounds 9 to 14, ignore zero padding
   SHA256_16WAY_ROUND_NOMSG( H, A, B, C, D, E, F, G,  9, 0 );
   SHA256_16WAY_ROUND_NOMSG( G, H, A, B, C, D, E, F, 10, 0 );
   SHA256_16WAY_ROUND_NOMSG( F, G, H, A, B, C, D, E, 11, 0 );
   SHA256_16WAY_ROUND_NOMSG( E, F, G, H, A, B, C, D, 12, 0 );
   SHA256_16WAY_ROUND_NOMSG( D, E, F, G, H, A, B, C, 13, 0 );
   SHA256_16WAY_ROUND_NOMSG( C, D, E, F, G, H, A, B, 14, 0 );

   // round 15
   SHA256_16WAY_ROUND( B, C, D, E, F, G, H, A, 15, 0 );

   // rounds 16 to 31 mexp part 2
   W[ 0] = _mm512_add_epi32( SSG2_0x16( W[ 1] ), W[ 0] );
   W[ 1] = _mm512_add_epi32( _mm512_add_epi32( SSG2_1x16( W[15] ),
                             SSG2_0x16( W[ 2] ) ), W[ 1] );
   W[ 2] = _mm512_add_epi32( _mm512_add_epi32( SSG2_1x16( W[ 0] ),
                             SSG2_0x16( W[ 3] ) ), W[ 2] );
   W[ 3] = _mm512_add_epi32( _mm512_add_epi32( SSG2_1x16( W[ 1] ),
                             SSG2_0x16( W[ 4] ) ), W[ 3] );
   W[ 4] = _mm512_add_epi32( _mm512_add_epi32( SSG2_1x16( W[ 2] ),
                             SSG2_0x16( W[ 5] ) ), W[ 4] );
   W[ 5] = _mm512_add_epi32( _mm512_add_epi32( SSG2_1x16( W[ 3] ),
                             SSG2_0x16( W[ 6] ) ), W[ 5] );
   W[ 6] = SHA256_16WAY_MEXP( W[ 4], W[15], W[ 7], W[ 6] );
   W[ 7] = SHA256_16WAY_MEXP( W[ 5], W[ 0], W[ 8], W[ 7] );

   W[ 8] = _mm512_add_epi32( _mm512_add_epi32( SSG2_1x16( W[ 6] ),
                                               W[1] ), W[ 8] );
   W[ 9] = _mm512_add_epi32( SSG2_1x16( W[ 7] ), W[ 2] );
   W[10] = _mm512_add_epi32( SSG2_1x16( W[ 8] ), W[ 3] );
   W[11] = _mm512_add_epi32( SSG2_1x16( W[ 9] ), W[ 4] );
   W[12] = _mm512_add_epi32( SSG2_1x16( W[10] ), W[ 5] );
   W[13] = _mm512_add_epi32( SSG2_1x16( W[11] ), W[ 6] );
   W[14] = _mm512_add_epi32( _mm512_add_epi32( SSG2_1x16( W[12] ),
                             W[ 7] ), SSG2_0x16( W[15] ) );
   W[15] = SHA256_16WAY_MEXP( W[13], W[ 8], W[ 0], W[15] );
  
   // rounds 16 to 31
   SHA256_16WAY_16ROUNDS( A, B, C, D, E, F, G, H, 16 );

   // rounds 32 to 47
   SHA256_MEXP_16WAY_16ROUNDS( W );
   SHA256_16WAY_16ROUNDS( A, B, C, D, E, F, G, H, 32 );

   // rounds 48 to 60 mexp
   W[ 0] = SHA256_16WAY_MEXP( W[14], W[ 9], W[ 1], W[ 0] );
   W[ 1] = SHA256_16WAY_MEXP( W[15], W[10], W[ 2], W[ 1] );
   W[ 2] = SHA256_16WAY_MEXP( W[ 0], W[11], W[ 3], W[ 2] );
   W[ 3] = SHA256_16WAY_MEXP( W[ 1], W[12], W[ 4], W[ 3] );
   W[ 4] = SHA256_16WAY_MEXP( W[ 2], W[13], W[ 5], W[ 4] );
   W[ 5] = SHA256_16WAY_MEXP( W[ 3], W[14], W[ 6], W[ 5] );
   W[ 6] = SHA256_16WAY_MEXP( W[ 4], W[15], W[ 7], W[ 6] );
   W[ 7] = SHA256_16WAY_MEXP( W[ 5], W[ 0], W[ 8], W[ 7] );
   W[ 8] = SHA256_16WAY_MEXP( W[ 6], W[ 1], W[ 9], W[ 8] );
   W[ 9] = SHA256_16WAY_MEXP( W[ 7], W[ 2], W[10], W[ 9] );
   W[10] = SHA256_16WAY_MEXP( W[ 8], W[ 3], W[11], W[10] );
   W[11] = SHA256_16WAY_MEXP( W[ 9], W[ 4], W[12], W[11] );
   W[12] = SHA256_16WAY_MEXP( W[10], W[ 5], W[13], W[12] );
   
   // Rounds 48 to 55
   SHA256_16WAY_ROUND( A, B, C, D, E, F, G, H,  0, 48 );
   SHA256_16WAY_ROUND( H, A, B, C, D, E, F, G,  1, 48 );
   SHA256_16WAY_ROUND( G, H, A, B, C, D, E, F,  2, 48 );
   SHA256_16WAY_ROUND( F, G, H, A, B, C, D, E,  3, 48 );
   SHA256_16WAY_ROUND( E, F, G, H, A, B, C, D,  4, 48 );
   SHA256_16WAY_ROUND( D, E, F, G, H, A, B, C,  5, 48 );
   SHA256_16WAY_ROUND( C, D, E, F, G, H, A, B,  6, 48 );
   SHA256_16WAY_ROUND( B, C, D, E, F, G, H, A,  7, 48 );

   // Round 56
   H = _mm512_add_epi32( v512_32( K256[56] ),
                 mm512_add4_32( BSG2_1x16( E ), CHx16( E, F, G ), W[ 8], H ) );
   D = _mm512_add_epi32( D, H );
   H56 = _mm512_add_epi32( H, _mm512_add_epi32( BSG2_0x16( A ),
                                                   MAJx16( A, B, C ) ) );
   
   // Rounds 57 to 60 part 1
   G = _mm512_add_epi32( v512_32( K256[57] ),
                 mm512_add4_32( BSG2_1x16( D ), CHx16( D, E, F ), W[ 9], G ) );
   C = _mm512_add_epi32( C, G );
   G57 = _mm512_add_epi32( G, MAJx16( H56, A, B ) );
   
   F = _mm512_add_epi32( v512_32( K256[58] ),
                 mm512_add4_32( BSG2_1x16( C ), CHx16( C, D, E ), W[10], F ) );
   B = _mm512_add_epi32( B, F );
   
   E = _mm512_add_epi32( v512_32( K256[59] ),
                 mm512_add4_32( BSG2_1x16( B ), CHx16( B, C, D ), W[11], E ) );
   A = _mm512_add_epi32( A, E );

   D = _mm512_add_epi32( v512_32( K256[60] ),
                 mm512_add4_32( BSG2_1x16( A ), CHx16( A, B, C ), W[12], D ) );
   H = _mm512_add_epi32( H56, D );

   // got final H, test it against target[7]
   hash = mm512_bswap_32( _mm512_add_epi32( H , istate7 ) );
   targ = v512_32( target[7] );
   if ( likely( 0 == ( mask = _mm512_cmple_epu32_mask( hash, targ ) ) ))
      return 0;

   // Round 57 part 2
   G57 = _mm512_add_epi32( G57, BSG2_0x16( H56 ) );
   
   // Round 61 part 1
   W[13] = SHA256_16WAY_MEXP( W[11], W[ 6], W[14], W[13] );
   C = _mm512_add_epi32( v512_32( K256[61] ),
                 mm512_add4_32( BSG2_1x16( H ), CHx16( H, A, B ), W[13], C ) );
   G = _mm512_add_epi32( G57, C );

   // got final G, test it against target[6] if indicated.
   if ( mask == _mm512_cmpeq_epi32_mask( hash, targ ) )
   {
      hash = mm512_bswap_32( _mm512_add_epi32( G, istate6 ) );
      targ = v512_32( target[6] );
      if ( likely( 0 == _mm512_mask_cmple_epu32_mask( mask, hash, targ ) ))
          return 0;
   }

   // Round 58 to 61 part 2
   F = _mm512_add_epi32( F, _mm512_add_epi32( BSG2_0x16( G57 ),
                                                 MAJx16( G57, H, A ) ) );
   E = _mm512_add_epi32( E, _mm512_add_epi32( BSG2_0x16( F ),
                                                 MAJx16( F, G57, H ) ) );
   D = _mm512_add_epi32( D, _mm512_add_epi32( BSG2_0x16( E ),
                                                 MAJx16( E, F, G57 ) ) );
   C = _mm512_add_epi32( C, _mm512_add_epi32( BSG2_0x16( D ),
                                                 MAJx16( D, E, F ) ) );

   // Rounds 62, 63
   W[14] = SHA256_16WAY_MEXP( W[12], W[ 7], W[15], W[14] );
   W[15] = SHA256_16WAY_MEXP( W[13], W[ 8], W[ 0], W[15] );
   
   SHA256_16WAY_ROUND( C, D, E, F, G, H, A, B, 14, 48 );
   SHA256_16WAY_ROUND( B, C, D, E, F, G, H, A, 15, 48 );
   
   state_out[0] = _mm512_add_epi32( state_in[0], A );
   state_out[1] = _mm512_add_epi32( state_in[1], B );
   state_out[2] = _mm512_add_epi32( state_in[2], C );
   state_out[3] = _mm512_add_epi32( state_in[3], D );
   state_out[4] = _mm512_add_epi32( state_in[4], E );
   state_out[5] = _mm512_add_epi32( state_in[5], F );
   state_out[6] = _mm512_add_epi32( state_in[6], G );
   state_out[7] = _mm512_add_epi32( state_in[7], H );
   return 1;
}

void sha256_16x32_init( sha256_16x32_context *sc )
{
   sc->count_high = sc->count_low = 0;
   sc->val[0] = v512_32( sha256_iv[0] );
   sc->val[1] = v512_32( sha256_iv[1] );
   sc->val[2] = v512_32( sha256_iv[2] );
   sc->val[3] = v512_32( sha256_iv[3] );
   sc->val[4] = v512_32( sha256_iv[4] );
   sc->val[5] = v512_32( sha256_iv[5] );
   sc->val[6] = v512_32( sha256_iv[6] );
   sc->val[7] = v512_32( sha256_iv[7] );
}

void sha256_16x32_update( sha256_16x32_context *sc, const void *data,
                           size_t len )
{
   __m512i *vdata = (__m512i*)data;
   size_t ptr;
   const int buf_size = 64;

   ptr = (unsigned)sc->count_low & (buf_size - 1U);
   while ( len > 0 )
   {
      size_t clen;
      uint32_t clow, clow2;

      clen = buf_size - ptr;
      if ( clen > len )
         clen = len;
      memcpy_512( sc->buf + (ptr>>2), vdata, clen>>2 );
      vdata = vdata + (clen>>2);
      ptr += clen;
      len -= clen;
      if ( ptr == buf_size )
      {
         sha256_16x32_transform_be( sc->val, sc->buf, sc->val );
         ptr = 0;
      }
      clow = sc->count_low;
      clow2 = clow + clen;
      sc->count_low = clow2;
      if ( clow2 < clow )
         sc->count_high++;
   }
}

void sha256_16x32_close( sha256_16x32_context *sc, void *dst )
{
    unsigned ptr;
    uint32_t low, high;
    const int buf_size = 64;
    const int pad = buf_size - 8;

    ptr = (unsigned)sc->count_low & (buf_size - 1U);
    sc->buf[ ptr>>2 ] = v512_64( 0x0000008000000080 );
    ptr += 4;

    if ( ptr > pad )
    {
         memset_zero_512( sc->buf + (ptr>>2), (buf_size - ptr) >> 2 );
         sha256_16x32_transform_be( sc->val, sc->buf, sc->val );
         memset_zero_512( sc->buf, pad >> 2 );
    }
    else
         memset_zero_512( sc->buf + (ptr>>2), (pad - ptr) >> 2 );

    low = sc->count_low;
    high = (sc->count_high << 3) | (low >> 29);
    low = low << 3;

    sc->buf[   pad     >> 2 ] = v512_32( bswap_32( high ) );
    sc->buf[ ( pad+4 ) >> 2 ] = v512_32( bswap_32( low ) );

    sha256_16x32_transform_be( sc->val, sc->buf, sc->val );

    mm512_block_bswap_32( dst, sc->val );
}

void sha256_16x32_full( void *dst, const void *data, size_t len )
{
   sha256_16x32_context ctx;
   sha256_16x32_init( &ctx );
   sha256_16x32_update( &ctx, data, len );
   sha256_16x32_close( &ctx, dst );
}

#undef CH

#endif  // AVX512
#endif  // __AVX2__
