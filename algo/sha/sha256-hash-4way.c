
#if defined(__SSE2__)

#include <stddef.h>
#include <string.h>
#include "sha-hash-4way.h"
#include "compat.h"

/*
static const uint32_t H256[8] =
{
   0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
   0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};
*/

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

// SHA-256 4 way SSE2

#define CHs(X, Y, Z) \
   _mm_xor_si128( _mm_and_si128( _mm_xor_si128( Y, Z ), X ), Z ) 

#define MAJs(X, Y, Z) \
  _mm_xor_si128( Y, _mm_and_si128( X_xor_Y = _mm_xor_si128( X, Y ), \
                                   Y_xor_Z ) )

#define BSG2_0(x) \
   _mm_xor_si128( _mm_xor_si128( \
        mm128_ror_32(x,  2), mm128_ror_32(x, 13) ), mm128_ror_32( x, 22) )

#define BSG2_1(x) \
   _mm_xor_si128( _mm_xor_si128( \
        mm128_ror_32(x,  6), mm128_ror_32(x, 11) ), mm128_ror_32( x, 25) )

#define SSG2_0(x) \
   _mm_xor_si128( _mm_xor_si128( \
        mm128_ror_32(x,  7), mm128_ror_32(x, 18) ), _mm_srli_epi32(x, 3) ) 

#define SSG2_1(x) \
   _mm_xor_si128( _mm_xor_si128( \
        mm128_ror_32(x, 17), mm128_ror_32(x, 19) ), _mm_srli_epi32(x, 10) )

#define SHA2s_MEXP( a, b, c, d ) \
  mm128_add4_32( SSG2_1( a ), b, SSG2_0( c ), d );

#define SHA256x4_MSG_EXPANSION( W ) \
   W[ 0] = SHA2s_MEXP( W[14], W[ 9], W[ 1], W[ 0] ); \
   W[ 1] = SHA2s_MEXP( W[15], W[10], W[ 2], W[ 1] ); \
   W[ 2] = SHA2s_MEXP( W[ 0], W[11], W[ 3], W[ 2] ); \
   W[ 3] = SHA2s_MEXP( W[ 1], W[12], W[ 4], W[ 3] ); \
   W[ 4] = SHA2s_MEXP( W[ 2], W[13], W[ 5], W[ 4] ); \
   W[ 5] = SHA2s_MEXP( W[ 3], W[14], W[ 6], W[ 5] ); \
   W[ 6] = SHA2s_MEXP( W[ 4], W[15], W[ 7], W[ 6] ); \
   W[ 7] = SHA2s_MEXP( W[ 5], W[ 0], W[ 8], W[ 7] ); \
   W[ 8] = SHA2s_MEXP( W[ 6], W[ 1], W[ 9], W[ 8] ); \
   W[ 9] = SHA2s_MEXP( W[ 7], W[ 2], W[10], W[ 9] ); \
   W[10] = SHA2s_MEXP( W[ 8], W[ 3], W[11], W[10] ); \
   W[11] = SHA2s_MEXP( W[ 9], W[ 4], W[12], W[11] ); \
   W[12] = SHA2s_MEXP( W[10], W[ 5], W[13], W[12] ); \
   W[13] = SHA2s_MEXP( W[11], W[ 6], W[14], W[13] ); \
   W[14] = SHA2s_MEXP( W[12], W[ 7], W[15], W[14] ); \
   W[15] = SHA2s_MEXP( W[13], W[ 8], W[ 0], W[15] );

#define SHA2s_4WAY_STEP(A, B, C, D, E, F, G, H, i, j) \
do { \
  __m128i T1, T2; \
  __m128i K = _mm_set1_epi32( K256[( (j)+(i) )] ); \
  T1 = _mm_add_epi32( H, mm128_add4_32( BSG2_1(E), CHs(E, F, G), \
                                        K, W[i] ) ); \
  T2 = _mm_add_epi32( BSG2_0(A), MAJs(A, B, C) ); \
  Y_xor_Z = X_xor_Y; \
  D  = _mm_add_epi32( D,  T1 ); \
  H  = _mm_add_epi32( T1, T2 ); \
} while (0)

#define SHA256x4_16ROUNDS( A, B, C, D, E, F, G, H, j ) \
{ \
   __m128i X_xor_Y, Y_xor_Z = _mm_xor_si128( B, C ); \
   SHA2s_4WAY_STEP( A, B, C, D, E, F, G, H,  0, j ); \
   SHA2s_4WAY_STEP( H, A, B, C, D, E, F, G,  1, j ); \
   SHA2s_4WAY_STEP( G, H, A, B, C, D, E, F,  2, j ); \
   SHA2s_4WAY_STEP( F, G, H, A, B, C, D, E,  3, j ); \
   SHA2s_4WAY_STEP( E, F, G, H, A, B, C, D,  4, j ); \
   SHA2s_4WAY_STEP( D, E, F, G, H, A, B, C,  5, j ); \
   SHA2s_4WAY_STEP( C, D, E, F, G, H, A, B,  6, j ); \
   SHA2s_4WAY_STEP( B, C, D, E, F, G, H, A,  7, j ); \
   SHA2s_4WAY_STEP( A, B, C, D, E, F, G, H,  8, j ); \
   SHA2s_4WAY_STEP( H, A, B, C, D, E, F, G,  9, j ); \
   SHA2s_4WAY_STEP( G, H, A, B, C, D, E, F, 10, j ); \
   SHA2s_4WAY_STEP( F, G, H, A, B, C, D, E, 11, j ); \
   SHA2s_4WAY_STEP( E, F, G, H, A, B, C, D, 12, j ); \
   SHA2s_4WAY_STEP( D, E, F, G, H, A, B, C, 13, j ); \
   SHA2s_4WAY_STEP( C, D, E, F, G, H, A, B, 14, j ); \
   SHA2s_4WAY_STEP( B, C, D, E, F, G, H, A, 15, j ); \
}

// LE data, no need to byte swap
static inline void SHA256_4WAY_TRANSFORM( __m128i *out, __m128i *W,
                                          const __m128i *in )
{
   __m128i A, B, C, D, E, F, G, H;

   A = in[0];
   B = in[1];
   C = in[2];
   D = in[3];
   E = in[4];
   F = in[5];
   G = in[6];
   H = in[7];

   SHA256x4_16ROUNDS( A, B, C, D, E, F, G, H, 0 );
   SHA256x4_MSG_EXPANSION( W );
   SHA256x4_16ROUNDS( A, B, C, D, E, F, G, H, 16 );
   SHA256x4_MSG_EXPANSION( W );
   SHA256x4_16ROUNDS( A, B, C, D, E, F, G, H, 32 );
   SHA256x4_MSG_EXPANSION( W );
   SHA256x4_16ROUNDS( A, B, C, D, E, F, G, H, 48 );
   
   out[0] = _mm_add_epi32( in[0], A );
   out[1] = _mm_add_epi32( in[1], B );
   out[2] = _mm_add_epi32( in[2], C );
   out[3] = _mm_add_epi32( in[3], D );
   out[4] = _mm_add_epi32( in[4], E );
   out[5] = _mm_add_epi32( in[5], F );
   out[6] = _mm_add_epi32( in[6], G );
   out[7] = _mm_add_epi32( in[7], H );
}

// LE data, no need to byte swap
void sha256_4way_transform_le( __m128i *state_out, const __m128i *data,
                               const __m128i *state_in )
{
   __m128i W[16];
   memcpy_128( W, data, 16 );
   SHA256_4WAY_TRANSFORM( state_out, W, state_in );
}

// BE data, need to byte swap input data
void sha256_4way_transform_be( __m128i *state_out, const __m128i *data,
                               const __m128i *state_in )
{
   __m128i W[16];
   mm128_block_bswap_32( W, data );
   mm128_block_bswap_32( W+8, data+8 );
   SHA256_4WAY_TRANSFORM( state_out, W, state_in );
}

// prehash_3rounds & final_rounds are not working
void sha256_4way_prehash_3rounds( __m128i *state_mid, __m128i *X,
                                   const __m128i *W, const __m128i *state_in )
{
   __m128i A, B, C, D, E, F, G, H;

   // precalculate constant part msg expansion for second iteration.
   X[ 0] = SHA2s_MEXP( W[14], W[ 9], W[ 1], W[ 0] );
   X[ 1] = SHA2s_MEXP( W[15], W[10], W[ 2], W[ 1] );
   X[ 2] = _mm_add_epi32( _mm_add_epi32( SSG2_1( X[ 0] ), W[11] ),
                          W[ 2] );
   X[ 3] = _mm_add_epi32( _mm_add_epi32( SSG2_1( X[ 1] ), W[12] ),
                          SSG2_0( W[ 4] ) );
   X[ 4] = _mm_add_epi32( _mm_add_epi32( W[13], SSG2_0( W[ 5] ) ),
                          W[ 4] );
   X[ 5] = _mm_add_epi32( _mm_add_epi32( W[14], SSG2_0( W[ 6] ) ),
                          W[ 5] );
   X [6] = _mm_add_epi32( _mm_add_epi32( W[15], SSG2_0( W[ 7] ) ),
                          W[ 6] );
   X[ 7] = _mm_add_epi32( _mm_add_epi32( X[ 0], SSG2_0( W[ 8] ) ),
                          W[ 7] );
   X[ 8] = _mm_add_epi32( _mm_add_epi32( X[ 1], SSG2_0( W[ 9] ) ),
                          W[ 8] );
   X[ 9] = _mm_add_epi32( SSG2_0( W[10] ), W[ 9] );
   X[10] = _mm_add_epi32( SSG2_0( W[11] ), W[10] );
   X[11] = _mm_add_epi32( SSG2_0( W[12] ), W[11] );
   X[12] = _mm_add_epi32( SSG2_0( W[13] ), W[12] );
   X[13] = _mm_add_epi32( SSG2_0( W[14] ), W[13] );
   X[14] = _mm_add_epi32( SSG2_0( W[15] ), W[14] );
   X[15] = _mm_add_epi32( SSG2_0( X[ 0] ), W[15] );

   A = _mm_load_si128( state_in     );
   B = _mm_load_si128( state_in + 1 );
   C = _mm_load_si128( state_in + 2 );
   D = _mm_load_si128( state_in + 3 );
   E = _mm_load_si128( state_in + 4 );
   F = _mm_load_si128( state_in + 5 );
   G = _mm_load_si128( state_in + 6 );
   H = _mm_load_si128( state_in + 7 );

   __m128i X_xor_Y, Y_xor_Z = _mm_xor_si128( B, C );
   
   SHA2s_4WAY_STEP( A, B, C, D, E, F, G, H,  0, 0 );
   SHA2s_4WAY_STEP( H, A, B, C, D, E, F, G,  1, 0 );
   SHA2s_4WAY_STEP( G, H, A, B, C, D, E, F,  2, 0 );
   
   _mm_store_si128( state_mid    , A );
   _mm_store_si128( state_mid + 1, B );
   _mm_store_si128( state_mid + 2, C );
   _mm_store_si128( state_mid + 3, D );
   _mm_store_si128( state_mid + 4, E );
   _mm_store_si128( state_mid + 5, F );
   _mm_store_si128( state_mid + 6, G );
   _mm_store_si128( state_mid + 7, H );
}

void sha256_4way_final_rounds( __m128i *state_out, const __m128i *data,
          const __m128i *state_in, const __m128i *state_mid, const __m128i *X )
{
   __m128i A, B, C, D, E, F, G, H;
   __m128i W[16];

   memcpy_128( W, data, 16 );

   A = _mm_load_si128( state_mid     );
   B = _mm_load_si128( state_mid + 1 );
   C = _mm_load_si128( state_mid + 2 );
   D = _mm_load_si128( state_mid + 3 );
   E = _mm_load_si128( state_mid + 4 );
   F = _mm_load_si128( state_mid + 5 );
   G = _mm_load_si128( state_mid + 6 );
   H = _mm_load_si128( state_mid + 7 );

   __m128i X_xor_Y, Y_xor_Z = _mm_xor_si128( G, H );

   SHA2s_4WAY_STEP( F, G, H, A, B, C, D, E,  3, 0 );
   SHA2s_4WAY_STEP( E, F, G, H, A, B, C, D,  4, 0 );
   SHA2s_4WAY_STEP( D, E, F, G, H, A, B, C,  5, 0 );
   SHA2s_4WAY_STEP( C, D, E, F, G, H, A, B,  6, 0 );
   SHA2s_4WAY_STEP( B, C, D, E, F, G, H, A,  7, 0 );
   SHA2s_4WAY_STEP( A, B, C, D, E, F, G, H,  8, 0 );
   SHA2s_4WAY_STEP( H, A, B, C, D, E, F, G,  9, 0 );
   SHA2s_4WAY_STEP( G, H, A, B, C, D, E, F, 10, 0 );
   SHA2s_4WAY_STEP( F, G, H, A, B, C, D, E, 11, 0 );
   SHA2s_4WAY_STEP( E, F, G, H, A, B, C, D, 12, 0 );
   SHA2s_4WAY_STEP( D, E, F, G, H, A, B, C, 13, 0 );
   SHA2s_4WAY_STEP( C, D, E, F, G, H, A, B, 14, 0 );
   SHA2s_4WAY_STEP( B, C, D, E, F, G, H, A, 15, 0 );

   // update precalculated msg expansion with new nonce: W[3].
   W[ 0] = X[ 0];
   W[ 1] = X[ 1];
   W[ 2] = _mm_add_epi32( X[ 2], SSG2_0( W[ 3] ) );
   W[ 3] = _mm_add_epi32( X[ 3], W[ 3] );
   W[ 4] = _mm_add_epi32( X[ 4], SSG2_1( W[ 2] ) );
   W[ 5] = _mm_add_epi32( X[ 5], SSG2_1( W[ 3] ) );
   W[ 6] = _mm_add_epi32( X[ 6], SSG2_1( W[ 4] ) );
   W[ 7] = _mm_add_epi32( X[ 7], SSG2_1( W[ 5] ) );
   W[ 8] = _mm_add_epi32( X[ 8], SSG2_1( W[ 6] ) );
   W[ 9] = _mm_add_epi32( X[ 9], _mm_add_epi32( SSG2_1( W[ 7] ),
                                                W[ 2] ) );
   W[10] = _mm_add_epi32( X[10], _mm_add_epi32( SSG2_1( W[ 8] ),
                                                W[ 3] ) );
   W[11] = _mm_add_epi32( X[11], _mm_add_epi32( SSG2_1( W[ 9] ),
                                                W[ 4] ) );
   W[12] = _mm_add_epi32( X[12], _mm_add_epi32( SSG2_1( W[10] ),
                                                W[ 5] ) );
   W[13] = _mm_add_epi32( X[13], _mm_add_epi32( SSG2_1( W[11] ),
                                                W[ 6] ) );
   W[14] = _mm_add_epi32( X[14], _mm_add_epi32( SSG2_1( W[12] ),
                                                W[ 7] ) );
   W[15] = _mm_add_epi32( X[15], _mm_add_epi32( SSG2_1( W[13] ),
                                                W[ 8] ) );

   SHA256x4_16ROUNDS( A, B, C, D, E, F, G, H, 16 );
   SHA256x4_MSG_EXPANSION( W );
   SHA256x4_16ROUNDS( A, B, C, D, E, F, G, H, 32 );
   SHA256x4_MSG_EXPANSION( W );
   SHA256x4_16ROUNDS( A, B, C, D, E, F, G, H, 48 );

   A = _mm_add_epi32( A, _mm_load_si128( state_in     ) );
   B = _mm_add_epi32( B, _mm_load_si128( state_in + 1 ) );
   C = _mm_add_epi32( C, _mm_load_si128( state_in + 2 ) );
   D = _mm_add_epi32( D, _mm_load_si128( state_in + 3 ) );
   E = _mm_add_epi32( E, _mm_load_si128( state_in + 4 ) );
   F = _mm_add_epi32( F, _mm_load_si128( state_in + 5 ) );
   G = _mm_add_epi32( G, _mm_load_si128( state_in + 6 ) );
   H = _mm_add_epi32( H, _mm_load_si128( state_in + 7 ) );

   _mm_store_si128( state_out    ,  A );
   _mm_store_si128( state_out + 1,  B );
   _mm_store_si128( state_out + 2,  C );
   _mm_store_si128( state_out + 3,  D );
   _mm_store_si128( state_out + 4,  E );
   _mm_store_si128( state_out + 5,  F );
   _mm_store_si128( state_out + 6,  G );
   _mm_store_si128( state_out + 7,  H );
}

// Working correctly but still slower
int sha256_4way_transform_le_short( __m128i *state_out, const __m128i *data,
                            const __m128i *state_in, const uint32_t *target )
{
   __m128i A, B, C, D, E, F, G, H, T0, T1, T2;
   __m128i vmask, targ, hash;
   int t6_mask, flip;
   __m128i W[16];      memcpy_128( W, data, 16 );

   A = _mm_load_si128( state_in   );
   B = _mm_load_si128( state_in+1 );
   C = _mm_load_si128( state_in+2 );
   D = _mm_load_si128( state_in+3 );
   E = _mm_load_si128( state_in+4 );
   F = _mm_load_si128( state_in+5 );
   G = _mm_load_si128( state_in+6 );
   H = _mm_load_si128( state_in+7 );

   const __m128i IV7 = H;
   const __m128i IV6 = G;

   SHA256x4_16ROUNDS( A, B, C, D, E, F, G, H, 0 );
   SHA256x4_MSG_EXPANSION( W );
   SHA256x4_16ROUNDS( A, B, C, D, E, F, G, H, 16 );
   SHA256x4_MSG_EXPANSION( W );
   SHA256x4_16ROUNDS( A, B, C, D, E, F, G, H, 32 );

   W[ 0] = SHA2s_MEXP( W[14], W[ 9], W[ 1], W[ 0] );
   W[ 1] = SHA2s_MEXP( W[15], W[10], W[ 2], W[ 1] );
   W[ 2] = SHA2s_MEXP( W[ 0], W[11], W[ 3], W[ 2] );
   W[ 3] = SHA2s_MEXP( W[ 1], W[12], W[ 4], W[ 3] );
   W[ 4] = SHA2s_MEXP( W[ 2], W[13], W[ 5], W[ 4] );
   W[ 5] = SHA2s_MEXP( W[ 3], W[14], W[ 6], W[ 5] );
   W[ 6] = SHA2s_MEXP( W[ 4], W[15], W[ 7], W[ 6] );
   W[ 7] = SHA2s_MEXP( W[ 5], W[ 0], W[ 8], W[ 7] );
   W[ 8] = SHA2s_MEXP( W[ 6], W[ 1], W[ 9], W[ 8] );
   W[ 9] = SHA2s_MEXP( W[ 7], W[ 2], W[10], W[ 9] );
   W[10] = SHA2s_MEXP( W[ 8], W[ 3], W[11], W[10] );
   W[11] = SHA2s_MEXP( W[ 9], W[ 4], W[12], W[11] );
   W[12] = SHA2s_MEXP( W[10], W[ 5], W[13], W[12] );

   __m128i X_xor_Y, Y_xor_Z = _mm_xor_si128( B, C );
   
   SHA2s_4WAY_STEP( A, B, C, D, E, F, G, H,  0, 48 );
   SHA2s_4WAY_STEP( H, A, B, C, D, E, F, G,  1, 48 );
   SHA2s_4WAY_STEP( G, H, A, B, C, D, E, F,  2, 48 );
   SHA2s_4WAY_STEP( F, G, H, A, B, C, D, E,  3, 48 );
   SHA2s_4WAY_STEP( E, F, G, H, A, B, C, D,  4, 48 );
   SHA2s_4WAY_STEP( D, E, F, G, H, A, B, C,  5, 48 );
   SHA2s_4WAY_STEP( C, D, E, F, G, H, A, B,  6, 48 );
   SHA2s_4WAY_STEP( B, C, D, E, F, G, H, A,  7, 48 );
   SHA2s_4WAY_STEP( A, B, C, D, E, F, G, H,  8, 48 );
   SHA2s_4WAY_STEP( H, A, B, C, D, E, F, G,  9, 48 );

   T0 = _mm_add_epi32( _mm_set1_epi32( K256[58] ),
                   mm128_add4_32( BSG2_1( C ), CHs( C, D, E ), W[10], F ) );
   B = _mm_add_epi32( B, T0 );

   T1 = _mm_add_epi32( _mm_set1_epi32( K256[59] ),
                    mm128_add4_32( BSG2_1( B ), CHs( B, C, D ), W[11], E ) );
   A = _mm_add_epi32( A, T1 );

   T2 = _mm_add_epi32( _mm_set1_epi32( K256[60] ),
                    mm128_add4_32( BSG2_1( A ), CHs( A, B, C ), W[12], D ) );
   H = _mm_add_epi32( H, T2 );

   targ = _mm_set1_epi32( target[7] );
   hash = mm128_bswap_32( _mm_add_epi32( H, IV7 ) );

   flip = ( (int)target[7] < 0 ? 0xf : 0 ) ^ mm128_movmask_32( hash );

   if ( likely( 0xf == ( flip ^
                    mm128_movmask_32( _mm_cmpgt_epi32( hash, targ ) ) ) ))
   return 0;

   t6_mask = mm128_movmask_32( vmask =_mm_cmpeq_epi32( hash, targ ) );

   // round 58 part 2
   F = _mm_add_epi32( T0, _mm_add_epi32( BSG2_0( G ), MAJs( G, H, A ) ) );

   // round 61  part 1
   W[13] = SHA2s_MEXP( W[11], W[ 6], W[14], W[13] );
   T0 = _mm_add_epi32( _mm_set1_epi32( K256[61] ),
                 mm128_add4_32( BSG2_1( H ), CHs( H, A, B ), W[13], C ) );
   G = _mm_add_epi32( G, T0 );

   if ( t6_mask )
   {
      targ = _mm_and_si128( vmask, _mm_set1_epi32( target[6] ) );
      hash = mm128_bswap_32( _mm_add_epi32( G, IV6 ) );

      if ( ( 0 != ( t6_mask & mm128_movmask_32(
                                 _mm_cmpeq_epi32( hash, targ ) ) ) ))
         return 0;
      else
      {
         flip = ( (int)target[6] < 0 ? 0xf : 0 ) ^ mm128_movmask_32( hash );
         if ( 0 != ( t6_mask & ( flip ^ mm128_movmask_32(
                                       _mm_cmpgt_epi32( hash, targ ) ) ) ) )
            return 0;
          else if ( target[6] == 0x80000000 )
          {
             if ( 0 == ( t6_mask & mm128_movmask_32(
                   _mm_cmpgt_epi32( hash, _mm_xor_si128( hash, hash ) ) ) ) )
                return 0;
          }
       }
   }
   
   // rounds 59 to 61 part 2
   E = _mm_add_epi32( T1, _mm_add_epi32( BSG2_0( F ), MAJs( F, G, H ) ) );
   D = _mm_add_epi32( T2, _mm_add_epi32( BSG2_0( E ), MAJs( E, F, G ) ) );
   C = _mm_add_epi32( T0, _mm_add_epi32( BSG2_0( D ), MAJs( D, E, F ) ) );

   // rounds 62 & 63
   W[14] = SHA2s_MEXP( W[12], W[ 7], W[15], W[14] );
   W[15] = SHA2s_MEXP( W[13], W[ 8], W[ 0], W[15] );

   SHA2s_4WAY_STEP( C, D, E, F, G, H, A, B, 14, 48 );
   SHA2s_4WAY_STEP( B, C, D, E, F, G, H, A, 15, 48 );

   state_out[0] = _mm_add_epi32( state_in[0], A );
   state_out[1] = _mm_add_epi32( state_in[1], B );
   state_out[2] = _mm_add_epi32( state_in[2], C );
   state_out[3] = _mm_add_epi32( state_in[3], D );
   state_out[4] = _mm_add_epi32( state_in[4], E );
   state_out[5] = _mm_add_epi32( state_in[5], F );
   state_out[6] = _mm_add_epi32( state_in[6], G );
   state_out[7] = _mm_add_epi32( state_in[7], H );
return 1;
}


void sha256_4way_init( sha256_4way_context *sc )
{
   sc->count_high = sc->count_low = 0;
   sc->val[0] = _mm_set1_epi64x( 0x6A09E6676A09E667 );
   sc->val[1] = _mm_set1_epi64x( 0xBB67AE85BB67AE85 );
   sc->val[2] = _mm_set1_epi64x( 0x3C6EF3723C6EF372 );
   sc->val[3] = _mm_set1_epi64x( 0xA54FF53AA54FF53A );
   sc->val[4] = _mm_set1_epi64x( 0x510E527F510E527F );
   sc->val[5] = _mm_set1_epi64x( 0x9B05688C9B05688C );
   sc->val[6] = _mm_set1_epi64x( 0x1F83D9AB1F83D9AB );
   sc->val[7] = _mm_set1_epi64x( 0x5BE0CD195BE0CD19 );
}

void sha256_4way_update( sha256_4way_context *sc, const void *data, size_t len )
{
   __m128i *vdata = (__m128i*)data;
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
      memcpy_128( sc->buf + (ptr>>2), vdata, clen>>2 );
      vdata = vdata + (clen>>2);
      ptr += clen;
      len -= clen;
      if ( ptr == buf_size )
      {
         sha256_4way_transform_be( sc->val, sc->buf, sc->val );
         ptr = 0;
      }
      clow = sc->count_low;
      clow2 = clow + clen;
      sc->count_low = clow2;
      if ( clow2 < clow )
         sc->count_high++;
   }
}

void sha256_4way_close( sha256_4way_context *sc, void *dst )
{
    unsigned ptr;
    uint32_t low, high;
    const int buf_size = 64;
    const int pad = buf_size - 8;

    ptr = (unsigned)sc->count_low & (buf_size - 1U);
    sc->buf[ ptr>>2 ] = _mm_set1_epi64x( 0x0000008000000080 );
    ptr += 4;

    if ( ptr > pad )
    {
         memset_zero_128( sc->buf + (ptr>>2), (buf_size - ptr) >> 2 );
         sha256_4way_transform_be( sc->val, sc->buf, sc->val );
         memset_zero_128( sc->buf, pad >> 2 );
    }
    else
         memset_zero_128( sc->buf + (ptr>>2), (pad - ptr) >> 2 );

    low = sc->count_low;
    high = (sc->count_high << 3) | (low >> 29);
    low = low << 3;

    sc->buf[  pad     >> 2 ] = _mm_set1_epi32( bswap_32( high ) );
    sc->buf[( pad+4 ) >> 2 ] = _mm_set1_epi32( bswap_32( low ) );
    sha256_4way_transform_be( sc->val, sc->buf, sc->val );

    mm128_block_bswap_32( dst, sc->val );
}

void sha256_4way_full( void *dst, const void *data, size_t len )
{
   sha256_4way_context ctx;
   sha256_4way_init( &ctx );
   sha256_4way_update( &ctx, data, len );
   sha256_4way_close( &ctx, dst );
}

#if defined(__AVX2__)

// SHA-256 8 way

#define BSG2_0x(x) \
   _mm256_xor_si256( _mm256_xor_si256( mm256_ror_32( x,  2 ), \
                                       mm256_ror_32( x, 13 ) ), \
                                       mm256_ror_32( x, 22 ) )

#define BSG2_1x(x) \
   _mm256_xor_si256( _mm256_xor_si256( mm256_ror_32( x,  6 ), \
                                       mm256_ror_32( x, 11 ) ), \
                                       mm256_ror_32( x, 25 ) )

#define SSG2_0x(x) \
   _mm256_xor_si256( _mm256_xor_si256( mm256_ror_32( x,  7 ), \
                                       mm256_ror_32( x, 18 ) ), \
                                       _mm256_srli_epi32( x, 3 ) ) 

#define SSG2_1x(x) \
   _mm256_xor_si256( _mm256_xor_si256( mm256_ror_32( x, 17 ), \
                                       mm256_ror_32( x, 19 ) ), \
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


// With AVX512VL ternary logic optimizations are available.
// If not optimize by forwarding the result of X^Y in MAJ to the next round
// to avoid recalculating it as Y^Z. This optimization is not applicable
// when MAJ is optimized with ternary logic.

#if defined(__AVX512VL__)

#define CHx(X, Y, Z)    _mm256_ternarylogic_epi32( X, Y, Z, 0xca )

#define MAJx(X, Y, Z)   _mm256_ternarylogic_epi32( X, Y, Z, 0xe8 )

#define SHA256_8WAY_ROUND( A, B, C, D, E, F, G, H, i, j ) \
do { \
  __m256i T0 = _mm256_add_epi32( _mm256_set1_epi32( K256[ (j)+(i) ] ), \
                                 W[ i ] ); \
  __m256i T1 = BSG2_1x( E ); \
  __m256i T2 = BSG2_0x( A ); \
  T0 = _mm256_add_epi32( T0, CHx( E, F, G ) ); \
  T1 = _mm256_add_epi32( T1, H ); \
  T2 = _mm256_add_epi32( T2, MAJx( A, B, C ) ); \
  T1 = _mm256_add_epi32( T1, T0 ); \
  D  = _mm256_add_epi32( D,  T1 ); \
  H  = _mm256_add_epi32( T1, T2 ); \
} while (0)

#define SHA256_8WAY_16ROUNDS( A, B, C, D, E, F, G, H, j ) \
   SHA256_8WAY_ROUND( A, B, C, D, E, F, G, H,  0, j ); \
   SHA256_8WAY_ROUND( H, A, B, C, D, E, F, G,  1, j ); \
   SHA256_8WAY_ROUND( G, H, A, B, C, D, E, F,  2, j ); \
   SHA256_8WAY_ROUND( F, G, H, A, B, C, D, E,  3, j ); \
   SHA256_8WAY_ROUND( E, F, G, H, A, B, C, D,  4, j ); \
   SHA256_8WAY_ROUND( D, E, F, G, H, A, B, C,  5, j ); \
   SHA256_8WAY_ROUND( C, D, E, F, G, H, A, B,  6, j ); \
   SHA256_8WAY_ROUND( B, C, D, E, F, G, H, A,  7, j ); \
   SHA256_8WAY_ROUND( A, B, C, D, E, F, G, H,  8, j ); \
   SHA256_8WAY_ROUND( H, A, B, C, D, E, F, G,  9, j ); \
   SHA256_8WAY_ROUND( G, H, A, B, C, D, E, F, 10, j ); \
   SHA256_8WAY_ROUND( F, G, H, A, B, C, D, E, 11, j ); \
   SHA256_8WAY_ROUND( E, F, G, H, A, B, C, D, 12, j ); \
   SHA256_8WAY_ROUND( D, E, F, G, H, A, B, C, 13, j ); \
   SHA256_8WAY_ROUND( C, D, E, F, G, H, A, B, 14, j ); \
   SHA256_8WAY_ROUND( B, C, D, E, F, G, H, A, 15, j );

#else  // AVX2

#define CHx(X, Y, Z) \
   _mm256_xor_si256( _mm256_and_si256( _mm256_xor_si256( Y, Z ), X ), Z ) 

// Use saved X_xor_Y from previous round, now called Y_xor_Z,
// and save new X_xor_Y, for next round.
#define MAJx(X, Y, Z) \
  _mm256_xor_si256( Y, _mm256_and_si256( X_xor_Y = _mm256_xor_si256( X, Y ), \
                                         Y_xor_Z ) )

#define SHA256_8WAY_ROUND( A, B, C, D, E, F, G, H, i, j ) \
do { \
  __m256i T0 = _mm256_add_epi32( _mm256_set1_epi32( K256[(j)+(i)] ), W[i] ); \
  __m256i T1 = BSG2_1x( E ); \
  __m256i T2 = BSG2_0x( A ); \
  T0 = _mm256_add_epi32( T0, CHx( E, F, G ) ); \
  T1 = _mm256_add_epi32( T1, H ); \
  T2 = _mm256_add_epi32( T2, MAJx( A, B, C ) ); \
  T1 = _mm256_add_epi32( T1, T0 ); \
  Y_xor_Z = X_xor_Y; \
  D  = _mm256_add_epi32( D,  T1 ); \
  H  = _mm256_add_epi32( T1, T2 ); \
} while (0)


// read Y_xor_Z, update X_xor_Y
#define MAJ_2step(X, Y, Z, X_xor_Y, Y_xor_Z ) \
  _mm256_xor_si256( Y, _mm256_and_si256( X_xor_Y = _mm256_xor_si256( X, Y ), \
                                         Y_xor_Z ) )

// start with toc initialized to y^z:   toc = B ^ C
// First round reads toc as Y_xor_Z and saves X_xor_Y as tic.
// Second round reads tic as Y_xor_Z and saves X_xor_Y as toc.

#define SHA256_8WAY_2ROUNDS( A, B, C, D, E, F, G, H, i0, i1, j ) \
do { \
  __m256i T0 = _mm256_add_epi32( _mm256_set1_epi32( K256[ (j)+(i0) ] ), \
                                 W[ i0 ] ); \
  __m256i T1 = BSG2_1x( E ); \
  __m256i T2 = BSG2_0x( A ); \
  T0 = _mm256_add_epi32( T0, CHx( E, F, G ) ); \
  T1 = _mm256_add_epi32( T1, H ); \
  T2 = _mm256_add_epi32( T2, MAJ_2step( A, B, C, tic, toc ) ); \
  T1 = _mm256_add_epi32( T1, T0 ); \
  D  = _mm256_add_epi32( D,  T1 ); \
  H  = _mm256_add_epi32( T1, T2 ); \
\
  T0 = _mm256_add_epi32( _mm256_set1_epi32( K256[ (j)+(i1) ] ), \
                                 W[ (i1) ] ); \
  T1 = BSG2_1x( D ); \
  T2 = BSG2_0x( H ); \
  T0 = _mm256_add_epi32( T0, CHx( D, E, F ) ); \
  T1 = _mm256_add_epi32( T1, G ); \
  T2 = _mm256_add_epi32( T2, MAJ_2step( H, A, B, toc, tic ) ); \
  T1 = _mm256_add_epi32( T1, T0 ); \
  C  = _mm256_add_epi32( C,  T1 ); \
  G  = _mm256_add_epi32( T1, T2 ); \
} while (0)

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

#endif   // AVX512VL else AVX2

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
void sha256_8way_transform_le( __m256i *state_out, const __m256i *data,
                               const __m256i *state_in )
{
   __m256i W[16];
   memcpy_256( W, data, 16 );
   SHA256_8WAY_TRANSFORM( state_out, W, state_in );
}

// Accepts BE input data, need to bswap
void sha256_8way_transform_be( __m256i *state_out, const __m256i *data,
                               const __m256i *state_in )
{
   __m256i W[16];
   mm256_block_bswap_32( W  , data   );
   mm256_block_bswap_32( W+8, data+8 );
   SHA256_8WAY_TRANSFORM( state_out, W, state_in );
}

// Aggressive prehashing, LE byte order
void sha256_8way_prehash_3rounds( __m256i *state_mid, __m256i *X,
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

#if !defined(__AVX512VL__)
   __m256i X_xor_Y, Y_xor_Z = _mm256_xor_si256( B, C );
#endif

   SHA256_8WAY_ROUND( A, B, C, D, E, F, G, H,  0, 0 );
   SHA256_8WAY_ROUND( H, A, B, C, D, E, F, G,  1, 0 );
   SHA256_8WAY_ROUND( G, H, A, B, C, D, E, F,  2, 0 );

   // round 3 part 1, ignore nonces W[3]
   T1 = mm256_add4_32( E, BSG2_1x(B), CHx(B, C, D),
                       _mm256_set1_epi32( K256[3] ) );
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

void sha256_8way_final_rounds( __m256i *state_out, const __m256i *data,
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

#if !defined(__AVX512VL__)
   __m256i X_xor_Y, Y_xor_Z = _mm256_xor_si256( F, G );
#endif

   // round 3 part 2, inject nonces  
   A = _mm256_add_epi32( A, W[3] );
   E = _mm256_add_epi32( E, W[3] );
   
//   SHA256_8WAY_ROUND( F, G, H, A, B, C, D, E,  3, 0 );
   SHA256_8WAY_ROUND( E, F, G, H, A, B, C, D,  4, 0 );
   SHA256_8WAY_ROUND( D, E, F, G, H, A, B, C,  5, 0 );
   SHA256_8WAY_ROUND( C, D, E, F, G, H, A, B,  6, 0 );
   SHA256_8WAY_ROUND( B, C, D, E, F, G, H, A,  7, 0 );
   SHA256_8WAY_ROUND( A, B, C, D, E, F, G, H,  8, 0 );
   SHA256_8WAY_ROUND( H, A, B, C, D, E, F, G,  9, 0 );
   SHA256_8WAY_ROUND( G, H, A, B, C, D, E, F, 10, 0 );
   SHA256_8WAY_ROUND( F, G, H, A, B, C, D, E, 11, 0 );
   SHA256_8WAY_ROUND( E, F, G, H, A, B, C, D, 12, 0 );
   SHA256_8WAY_ROUND( D, E, F, G, H, A, B, C, 13, 0 );
   SHA256_8WAY_ROUND( C, D, E, F, G, H, A, B, 14, 0 );
   SHA256_8WAY_ROUND( B, C, D, E, F, G, H, A, 15, 0 );

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


// It's working with a high hit rate but performance is lower
int sha256_8way_transform_le_short( __m256i *state_out, const __m256i *data,
                           const __m256i *state_in, const uint32_t *target )
{
   __m256i A, B, C, D, E, F, G, H, T0, T1, T2;
   int flip;
   int t6_mask;
   __m256i vmask, targ, hash;
   __m256i W[16];  memcpy_256( W, data, 16 );
   const __m256i bswap_shuf = mm256_bcast_m128( _mm_set_epi64x(
                              0x0c0d0e0f08090a0b, 0x0405060700010203 ) );

   A = _mm256_load_si256( state_in   );
   B = _mm256_load_si256( state_in+1 );
   C = _mm256_load_si256( state_in+2 );
   D = _mm256_load_si256( state_in+3 );
   E = _mm256_load_si256( state_in+4 );
   F = _mm256_load_si256( state_in+5 );
   G = _mm256_load_si256( state_in+6 );
   H = _mm256_load_si256( state_in+7 );

   const __m256i IV7 = H;
   const __m256i IV6 = G;

   SHA256_8WAY_16ROUNDS( A, B, C, D, E, F, G, H, 0 );

   for ( int j = 16; j < 48; j += 16 )
   {
      SHA256_8WAY_MEXP_16ROUNDS( W );
      SHA256_8WAY_16ROUNDS( A, B, C, D, E, F, G, H, j );
   }

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

#if !defined(__AVX512VL__)
   __m256i X_xor_Y, Y_xor_Z = _mm256_xor_si256( B, C );
#endif

   SHA256_8WAY_ROUND( A, B, C, D, E, F, G, H,  0, 48 );
   SHA256_8WAY_ROUND( H, A, B, C, D, E, F, G,  1, 48 );
   SHA256_8WAY_ROUND( G, H, A, B, C, D, E, F,  2, 48 );
   SHA256_8WAY_ROUND( F, G, H, A, B, C, D, E,  3, 48 );
   SHA256_8WAY_ROUND( E, F, G, H, A, B, C, D,  4, 48 );
   SHA256_8WAY_ROUND( D, E, F, G, H, A, B, C,  5, 48 );
   SHA256_8WAY_ROUND( C, D, E, F, G, H, A, B,  6, 48 );
   SHA256_8WAY_ROUND( B, C, D, E, F, G, H, A,  7, 48 );
   SHA256_8WAY_ROUND( A, B, C, D, E, F, G, H,  8, 48 );
   SHA256_8WAY_ROUND( H, A, B, C, D, E, F, G,  9, 48 );

   // round 58 to 60 part 1
   T0 = _mm256_add_epi32( _mm256_set1_epi32( K256[58] ),
                 mm256_add4_32( BSG2_1x( C ), CHx( C, D, E ), W[10], F ) );
   B = _mm256_add_epi32( B, T0 );

   T1 = _mm256_add_epi32( _mm256_set1_epi32( K256[59] ),
                 mm256_add4_32( BSG2_1x( B ), CHx( B, C, D ), W[11], E ) );
   A = _mm256_add_epi32( A, T1 );

   T2 = _mm256_add_epi32( _mm256_set1_epi32( K256[60] ),
                 mm256_add4_32( BSG2_1x( A ), CHx( A, B, C ), W[12], D ) );
   H = _mm256_add_epi32( H, T2 );

   // Got H, test it.
   targ = _mm256_set1_epi32( target[7] );
   hash = _mm256_shuffle_epi8( _mm256_add_epi32( H, IV7 ), bswap_shuf );
   flip = ( (int)target[7] < 0 ? -1 : 0 ) ^ mm256_movmask_32( hash );
   if ( likely( 0xff == ( flip ^
                    mm256_movmask_32( _mm256_cmpgt_epi32( hash, targ ) ) ) ))
   return 0;

   t6_mask = mm256_movmask_32( vmask =_mm256_cmpeq_epi32( hash, targ ) );

   // round 58 part 2
   F = _mm256_add_epi32( T0, _mm256_add_epi32( BSG2_0x( G ),
                                               MAJx( G, H, A ) ) );
   // round 61 part 1
   W[13] = SHA256_8WAY_MEXP( W[11], W[ 6], W[14], W[13] );
   T0 = _mm256_add_epi32( _mm256_set1_epi32( K256[61] ),
                 mm256_add4_32( BSG2_1x( H ), CHx( H, A, B ), W[13], C ) );
   G = _mm256_add_epi32( G, T0 );

   if ( t6_mask )
   { 
      // Testing H inconclusive: hash7 == target7, need to test G
      targ = _mm256_and_si256( vmask, _mm256_set1_epi32( target[6] ) );
      hash = _mm256_shuffle_epi8( _mm256_add_epi32( G, IV6 ), bswap_shuf );

      if ( unlikely( 0 != ( t6_mask & mm256_movmask_32(
                                      _mm256_cmpeq_epi32( hash, targ ) ) ) ))
         return 0;
      else
      {
          flip = ( (int)target[6] < 0 ? -1 : 0 ) ^ mm256_movmask_32( hash );
          if ( likely( 0 != ( t6_mask & ( flip ^
                   mm256_movmask_32( _mm256_cmpgt_epi32( hash, targ ) ) ) ) ))
             return 0;
          else if ( likely( target[6] == 0x80000000 ))
          {
             if ( 0 == ( t6_mask & mm256_movmask_32( _mm256_cmpgt_epi32(
                                  hash, _mm256_xor_si256( hash, hash ) ) ) ) )
               return 0;
          }
       } 
   }

   // rounds 59 to 61 part 2
   E = _mm256_add_epi32( T1, _mm256_add_epi32( BSG2_0x( F ),
                                               MAJx( F, G, H ) ) );
   D = _mm256_add_epi32( T2, _mm256_add_epi32( BSG2_0x( E ),
                                               MAJx( E, F, G ) ) );
   C = _mm256_add_epi32( T0, _mm256_add_epi32( BSG2_0x( D ),
                                               MAJx( D, E, F ) ) );

   // rounds 62 & 63
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


void sha256_8way_init( sha256_8way_context *sc )
{
   sc->count_high = sc->count_low = 0;
   sc->val[0] = _mm256_set1_epi64x( 0x6A09E6676A09E667 );
   sc->val[1] = _mm256_set1_epi64x( 0xBB67AE85BB67AE85 );
   sc->val[2] = _mm256_set1_epi64x( 0x3C6EF3723C6EF372 );
   sc->val[3] = _mm256_set1_epi64x( 0xA54FF53AA54FF53A );
   sc->val[4] = _mm256_set1_epi64x( 0x510E527F510E527F );
   sc->val[5] = _mm256_set1_epi64x( 0x9B05688C9B05688C );
   sc->val[6] = _mm256_set1_epi64x( 0x1F83D9AB1F83D9AB );
   sc->val[7] = _mm256_set1_epi64x( 0x5BE0CD195BE0CD19 );
}

// need to handle odd byte length for yespower.
// Assume only last update is odd.

void sha256_8way_update( sha256_8way_context *sc, const void *data, size_t len )
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
         sha256_8way_transform_be( sc->val, sc->buf, sc->val );
         ptr = 0;
      }
      clow = sc->count_low;
      clow2 = clow + clen;
      sc->count_low = clow2;
      if ( clow2 < clow )
         sc->count_high++;
   }
}

void sha256_8way_close( sha256_8way_context *sc, void *dst )
{
    unsigned ptr;
    uint32_t low, high;
    const int buf_size = 64;
    const int pad = buf_size - 8;

    ptr = (unsigned)sc->count_low & (buf_size - 1U);
    sc->buf[ ptr>>2 ] = _mm256_set1_epi64x( 0x0000008000000080 );
    ptr += 4;

    if ( ptr > pad )
    {
         memset_zero_256( sc->buf + (ptr>>2), (buf_size - ptr) >> 2 );
         sha256_8way_transform_be( sc->val, sc->buf, sc->val );
         memset_zero_256( sc->buf, pad >> 2 );
    }
    else
         memset_zero_256( sc->buf + (ptr>>2), (pad - ptr) >> 2 );

    low = sc->count_low;
    high = (sc->count_high << 3) | (low >> 29);
    low = low << 3;

    sc->buf[   pad     >> 2 ] = _mm256_set1_epi32( bswap_32( high ) );
    sc->buf[ ( pad+4 ) >> 2 ] = _mm256_set1_epi32( bswap_32( low ) );

    sha256_8way_transform_be( sc->val, sc->buf, sc->val );

    mm256_block_bswap_32( dst, sc->val );
}

void sha256_8way_full( void *dst, const void *data, size_t len )
{
   sha256_8way_context ctx;
   sha256_8way_init( &ctx );
   sha256_8way_update( &ctx, data, len );
   sha256_8way_close( &ctx, dst );
}

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

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
do { \
  __m512i T0 = _mm512_add_epi32( _mm512_set1_epi32( K256[(j)+(i)] ), W[i] ); \
  __m512i T1 = BSG2_1x16( E ); \
  __m512i T2 = BSG2_0x16( A ); \
  T0 = _mm512_add_epi32( T0, CHx16( E, F, G ) ); \
  T1 = _mm512_add_epi32( T1, H ); \
  T2 = _mm512_add_epi32( T2, MAJx16( A, B, C ) ); \
  T1 = _mm512_add_epi32( T1, T0 ); \
  D  = _mm512_add_epi32( D,  T1 ); \
  H  = _mm512_add_epi32( T1, T2 ); \
} while (0)
   
/*
#define SHA256_16WAY_ROUND(A, B, C, D, E, F, G, H, i, j) \
do { \
  __m512i T1, T2; \
  __m512i K = _mm512_set1_epi32( K256[( (j)+(i) )] ); \
  T1 = _mm512_add_epi32( H, mm512_add4_32( BSG2_1x16(E), CHx16(E, F, G), \
                                           K, W[i] ) ); \
  T2 = _mm512_add_epi32( BSG2_0x16(A), MAJx16(A, B, C) ); \
  D  = _mm512_add_epi32( D,  T1 ); \
  H  = _mm512_add_epi32( T1, T2 ); \
} while (0)
*/

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
void sha256_16way_transform_le( __m512i *state_out, const __m512i *data,
                                const __m512i *state_in )
{
   __m512i W[16];
   memcpy_512( W, data, 16 );
   SHA256_16WAY_TRANSFORM( state_out, W, state_in );
}

// Accepts BE input data, need to bswap
void sha256_16way_transform_be( __m512i *state_out, const __m512i *data,
                                const __m512i *state_in )
{
   __m512i W[16];
   mm512_block_bswap_32( W  , data   );
   mm512_block_bswap_32( W+8, data+8 );
   SHA256_16WAY_TRANSFORM( state_out, W, state_in );
}
 
// Aggressive prehashing, LE byte order
void sha256_16way_prehash_3rounds( __m512i *state_mid, __m512i *X, 
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

   // round 3 part 1, ignore nonces W[3]
   T1 = mm512_add4_32( E, BSG2_1x16(B), CHx16(B, C, D), 
                       _mm512_set1_epi32( K256[3] ) );
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

void sha256_16way_final_rounds( __m512i *state_out, const __m512i *data,
          const __m512i *state_in, const __m512i *state_mid, const __m512i *X )
{
   __m512i A, B, C, D, E, F, G, H, T1, T2;
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

   // round 3 part 2, inject nonces  
   A = _mm512_add_epi32( A, W[3] );
   E = _mm512_add_epi32( E, W[3] );

   // round 4
   SHA256_16WAY_ROUND( E, F, G, H, A, B, C, D, 4, 0 );   

   // round 5
   T1 = mm512_add4_32( C, BSG2_1x16(H), CHx16(H, A, B), 
                       _mm512_set1_epi32( K256[5] ) ); 
   T2 = _mm512_add_epi32( BSG2_0x16(D), MAJx16(D, E, F) ); 
   G  = _mm512_add_epi32( G,  T1 );
   C  = _mm512_add_epi32( T1, T2 );

   // round 6
   T1 = mm512_add4_32( B, BSG2_1x16(G), CHx16(G, H, A),
                       _mm512_set1_epi32( K256[6] ) );
   T2 = _mm512_add_epi32( BSG2_0x16(C), MAJx16(C, D, E) );
   F  = _mm512_add_epi32( F,  T1 );
   B  = _mm512_add_epi32( T1, T2 );

   // round 7
   T1 = mm512_add4_32( A, BSG2_1x16(F), CHx16(F, G, H),
                       _mm512_set1_epi32( K256[7] ) );
   T2 = _mm512_add_epi32( BSG2_0x16(B), MAJx16(B, C, D) );
   E  = _mm512_add_epi32( E,  T1 );
   A  = _mm512_add_epi32( T1, T2 );

   // round 8
   T1 = mm512_add4_32( H, BSG2_1x16(E), CHx16(E, F, G),
                       _mm512_set1_epi32( K256[8] ) );
   T2 = _mm512_add_epi32( BSG2_0x16(A), MAJx16(A, B, C) );
   D  = _mm512_add_epi32( D,  T1 );
   H  = _mm512_add_epi32( T1, T2 );

   // round 9
   T1 = mm512_add4_32( G, BSG2_1x16(D), CHx16(D, E, F),
                       _mm512_set1_epi32( K256[9] ) );
   T2 = _mm512_add_epi32( BSG2_0x16(H), MAJx16(H, A, B) );
   C  = _mm512_add_epi32( C,  T1 );
   G  = _mm512_add_epi32( T1, T2 );
       
   // round 10
   T1 = mm512_add4_32( F, BSG2_1x16(C), CHx16(C, D, E),
                       _mm512_set1_epi32( K256[10] ) );
   T2 = _mm512_add_epi32( BSG2_0x16(G), MAJx16(G, H, A) );
   B  = _mm512_add_epi32( B,  T1 );
   F  = _mm512_add_epi32( T1, T2 );
       
   // round 11
   T1 = mm512_add4_32( E, BSG2_1x16(B), CHx16(B, C, D),
                       _mm512_set1_epi32( K256[11] ) );
   T2 = _mm512_add_epi32( BSG2_0x16(F), MAJx16(F, G, H) );
   A  = _mm512_add_epi32( A,  T1 );
   E  = _mm512_add_epi32( T1, T2 );

   // round 12
   T1 = mm512_add4_32( D, BSG2_1x16(A), CHx16(A, B, C),
                       _mm512_set1_epi32( K256[12] ) );
   T2 = _mm512_add_epi32( BSG2_0x16(E), MAJx16(E, F, G) );
   H  = _mm512_add_epi32( H,  T1 );
   D  = _mm512_add_epi32( T1, T2 );

   // round 13
   T1 = mm512_add4_32( C, BSG2_1x16(H), CHx16(H, A, B),
                       _mm512_set1_epi32( K256[13] ) );
   T2 = _mm512_add_epi32( BSG2_0x16(D), MAJx16(D, E, F) );
   G  = _mm512_add_epi32( G,  T1 );
   C  = _mm512_add_epi32( T1, T2 );
  
   // round 14
   T1 = mm512_add4_32( B, BSG2_1x16(G), CHx16(G, H, A),
                       _mm512_set1_epi32( K256[14] ) );
   T2 = _mm512_add_epi32( BSG2_0x16(C), MAJx16(C, D, E) );
   F  = _mm512_add_epi32( F,  T1 );
   B  = _mm512_add_epi32( T1, T2 );

   // round 15   
   SHA256_16WAY_ROUND( B, C, D, E, F, G, H, A, 15, 0 );

   // rounds 16 to 31 mexp part 2, inject nonces.
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
int sha256_16way_transform_le_short( __m512i *state_out, const __m512i *data,
                              const __m512i *state_in, const uint32_t *target )
{
   __m512i A, B, C, D, E, F, G, H, hash, targ;
   __m512i T0, T1, T2;
   __m512i W[16];      memcpy_512( W, data, 16 );
   __mmask16 t6_mask;
   const __m512i bswap_shuf = mm512_bcast_m128( _mm_set_epi64x(
                              0x0c0d0e0f08090a0b, 0x0405060700010203 ) ); 

   A = _mm512_load_si512( state_in   );
   B = _mm512_load_si512( state_in+1 );
   C = _mm512_load_si512( state_in+2 );
   D = _mm512_load_si512( state_in+3 );
   E = _mm512_load_si512( state_in+4 );
   F = _mm512_load_si512( state_in+5 );
   G = _mm512_load_si512( state_in+6 );
   H = _mm512_load_si512( state_in+7 );

   const __m512i IV6 = G;
   const __m512i IV7 = H; 

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
   T1 = mm512_add4_32( G, BSG2_1x16(D), CHx16(D, E, F),
                       _mm512_set1_epi32( K256[9] ) );
   T2 = _mm512_add_epi32( BSG2_0x16(H), MAJx16(H, A, B) );
   C  = _mm512_add_epi32( C,  T1 );
   G  = _mm512_add_epi32( T1, T2 );

   T1 = mm512_add4_32( F, BSG2_1x16(C), CHx16(C, D, E),
                       _mm512_set1_epi32( K256[10] ) );
   T2 = _mm512_add_epi32( BSG2_0x16(G), MAJx16(G, H, A) );
   B  = _mm512_add_epi32( B,  T1 );
   F  = _mm512_add_epi32( T1, T2 );

   T1 = mm512_add4_32( E, BSG2_1x16(B), CHx16(B, C, D),
                       _mm512_set1_epi32( K256[11] ) );
   T2 = _mm512_add_epi32( BSG2_0x16(F), MAJx16(F, G, H) );
   A  = _mm512_add_epi32( A,  T1 );
   E  = _mm512_add_epi32( T1, T2 );

   T1 = mm512_add4_32( D, BSG2_1x16(A), CHx16(A, B, C),
                       _mm512_set1_epi32( K256[12] ) );
   T2 = _mm512_add_epi32( BSG2_0x16(E), MAJx16(E, F, G) );
   H  = _mm512_add_epi32( H,  T1 );
   D  = _mm512_add_epi32( T1, T2 );

   T1 = mm512_add4_32( C, BSG2_1x16(H), CHx16(H, A, B),
                       _mm512_set1_epi32( K256[13] ) );
   T2 = _mm512_add_epi32( BSG2_0x16(D), MAJx16(D, E, F) );
   G  = _mm512_add_epi32( G,  T1 );
   C  = _mm512_add_epi32( T1, T2 );

   T1 = mm512_add4_32( B, BSG2_1x16(G), CHx16(G, H, A),
                       _mm512_set1_epi32( K256[14] ) );
   T2 = _mm512_add_epi32( BSG2_0x16(C), MAJx16(C, D, E) );
   F  = _mm512_add_epi32( F,  T1 );
   B  = _mm512_add_epi32( T1, T2 );

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
   
   // Rounds 48 to 57
   SHA256_16WAY_ROUND( A, B, C, D, E, F, G, H,  0, 48 );
   SHA256_16WAY_ROUND( H, A, B, C, D, E, F, G,  1, 48 );
   SHA256_16WAY_ROUND( G, H, A, B, C, D, E, F,  2, 48 );
   SHA256_16WAY_ROUND( F, G, H, A, B, C, D, E,  3, 48 );
   SHA256_16WAY_ROUND( E, F, G, H, A, B, C, D,  4, 48 );
   SHA256_16WAY_ROUND( D, E, F, G, H, A, B, C,  5, 48 );
   SHA256_16WAY_ROUND( C, D, E, F, G, H, A, B,  6, 48 );
   SHA256_16WAY_ROUND( B, C, D, E, F, G, H, A,  7, 48 );
   SHA256_16WAY_ROUND( A, B, C, D, E, F, G, H,  8, 48 );
   SHA256_16WAY_ROUND( H, A, B, C, D, E, F, G,  9, 48 );

   // rounds 58 to 60 part 1
   T0 = _mm512_add_epi32( _mm512_set1_epi32( K256[58] ),
                 mm512_add4_32( BSG2_1x16( C ), CHx16( C, D, E ), W[10], F ) );
   B = _mm512_add_epi32( B, T0 );
   
   T1 = _mm512_add_epi32( _mm512_set1_epi32( K256[59] ),
                 mm512_add4_32( BSG2_1x16( B ), CHx16( B, C, D ), W[11], E ) );
   A = _mm512_add_epi32( A, T1 );

   T2 = _mm512_add_epi32( _mm512_set1_epi32( K256[60] ),
                 mm512_add4_32( BSG2_1x16( A ), CHx16( A, B, C ), W[12], D ) );
   H = _mm512_add_epi32( H, T2 );

   // got H, test it against target[7]
   hash = _mm512_shuffle_epi8( _mm512_add_epi32( H , IV7 ), bswap_shuf ); 
   targ = _mm512_set1_epi32( target[7] );
   if ( likely( 0 == _mm512_cmple_epu32_mask( hash, targ ) ))
      return 0;
   t6_mask = _mm512_cmpeq_epi32_mask( hash, targ );

   // round 58 part 2
   F = _mm512_add_epi32( T0, _mm512_add_epi32( BSG2_0x16( G ),
                                               MAJx16( G, H, A ) ) );

   // round 61 part 1
   W[13] = SHA256_16WAY_MEXP( W[11], W[ 6], W[14], W[13] );
   T0 = _mm512_add_epi32( _mm512_set1_epi32( K256[61] ),
                 mm512_add4_32( BSG2_1x16( H ), CHx16( H, A, B ), W[13], C ) );
   G = _mm512_add_epi32( G, T0 );

   // got G, test it against target[6] if indicated
   if ( t6_mask != 0 )
   {
      hash = _mm512_shuffle_epi8( _mm512_add_epi32( G, IV6 ), bswap_shuf );
      targ = _mm512_set1_epi32( target[6] );
      if ( likely( 0 == _mm512_mask_cmple_epu32_mask( t6_mask,
                                                      hash, targ ) ))
          return 0;
   }

   // round 59 part 2
   E = _mm512_add_epi32( T1, _mm512_add_epi32( BSG2_0x16( F ),
                                                  MAJx16( F, G, H ) ) );
   
   // round 60 part 2
   D = _mm512_add_epi32( T2, _mm512_add_epi32( BSG2_0x16( E ),
                                                  MAJx16( E, F, G ) ) );
   
   // round 61 part 2
   C = _mm512_add_epi32( T0, _mm512_add_epi32( BSG2_0x16( D ),
                                                  MAJx16( D, E, F ) ) );

   // rounds 62, 63
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

void sha256_16way_init( sha256_16way_context *sc )
{
   sc->count_high = sc->count_low = 0;
   sc->val[0] = _mm512_set1_epi64( 0x6A09E6676A09E667 );
   sc->val[1] = _mm512_set1_epi64( 0xBB67AE85BB67AE85 );
   sc->val[2] = _mm512_set1_epi64( 0x3C6EF3723C6EF372 );
   sc->val[3] = _mm512_set1_epi64( 0xA54FF53AA54FF53A );
   sc->val[4] = _mm512_set1_epi64( 0x510E527F510E527F );
   sc->val[5] = _mm512_set1_epi64( 0x9B05688C9B05688C );
   sc->val[6] = _mm512_set1_epi64( 0x1F83D9AB1F83D9AB );
   sc->val[7] = _mm512_set1_epi64( 0x5BE0CD195BE0CD19 );
}

void sha256_16way_update( sha256_16way_context *sc, const void *data,
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
         sha256_16way_transform_be( sc->val, sc->buf, sc->val );
         ptr = 0;
      }
      clow = sc->count_low;
      clow2 = clow + clen;
      sc->count_low = clow2;
      if ( clow2 < clow )
         sc->count_high++;
   }
}

void sha256_16way_close( sha256_16way_context *sc, void *dst )
{
    unsigned ptr;
    uint32_t low, high;
    const int buf_size = 64;
    const int pad = buf_size - 8;

    ptr = (unsigned)sc->count_low & (buf_size - 1U);
    sc->buf[ ptr>>2 ] = _mm512_set1_epi64( 0x0000008000000080 );
    ptr += 4;

    if ( ptr > pad )
    {
         memset_zero_512( sc->buf + (ptr>>2), (buf_size - ptr) >> 2 );
         sha256_16way_transform_be( sc->val, sc->buf, sc->val );
         memset_zero_512( sc->buf, pad >> 2 );
    }
    else
         memset_zero_512( sc->buf + (ptr>>2), (pad - ptr) >> 2 );

    low = sc->count_low;
    high = (sc->count_high << 3) | (low >> 29);
    low = low << 3;

    sc->buf[   pad     >> 2 ] = _mm512_set1_epi32( bswap_32( high ) );
    sc->buf[ ( pad+4 ) >> 2 ] = _mm512_set1_epi32( bswap_32( low ) );

    sha256_16way_transform_be( sc->val, sc->buf, sc->val );

    mm512_block_bswap_32( dst, sc->val );
}

void sha256_16way_full( void *dst, const void *data, size_t len )
{
   sha256_16way_context ctx;
   sha256_16way_init( &ctx );
   sha256_16way_update( &ctx, data, len );
   sha256_16way_close( &ctx, dst );
}

#undef CH

#endif  // AVX512
#endif  // __AVX2__
#endif  // __SSE2__
