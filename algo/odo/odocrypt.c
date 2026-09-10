// Odocrypt (DigiByte) scalar core. Port of DigiByte Core src/crypto/odocrypt.cpp
// (forward path) + KeccakP-800-reference.cpp (12-round permute). MIT/X11.

#include "odocrypt.h"
#include <string.h>
#if defined(__AVX512F__)
#include <immintrin.h>
#endif

// ---------------------------------------------------------------------------
// OdoRandom — LCG (Knuth params) used to generate the per-epoch tables.
// ---------------------------------------------------------------------------

#define ODO_LCG_MUL  6364136223846793005ull
#define ODO_LCG_ADD  1442695040888963407ull

typedef struct
{
   uint64_t current;
   uint64_t multiplicand;
   uint64_t addend;
} OdoRandom;

static inline void rand_init( OdoRandom *r, uint32_t seed )
{
   r->current = seed;
   r->multiplicand = 1;
   r->addend = 0;
}

static inline uint32_t rand_next_int( OdoRandom *r )
{
   r->addend += r->multiplicand * ODO_LCG_ADD;
   r->multiplicand *= ODO_LCG_MUL;
   r->current = r->current * r->multiplicand + r->addend;
   return (uint32_t)( r->current >> 32 );
}

static inline uint64_t rand_next_long( OdoRandom *r )
{
   uint64_t hi = rand_next_int( r );
   return ( hi << 32 ) | rand_next_int( r );
}

static inline int rand_next( OdoRandom *r, int N )
{
   return (int)( ( (uint64_t)rand_next_int( r ) * (uint64_t)N ) >> 32 );
}

// Knuth shuffle producing a unique permutation of 0..sz-1 (one per element type).
#define DEFINE_PERM( NAME, TYPE )                                      \
static void NAME( OdoRandom *r, TYPE *arr, size_t sz )                 \
{                                                                      \
   for ( size_t i = 0; i < sz; i++ ) arr[i] = (TYPE)i;                 \
   for ( size_t i = 1; i < sz; i++ )                                   \
   {                                                                   \
      size_t j = (size_t)rand_next( r, (int)( i + 1 ) );              \
      TYPE t = arr[i]; arr[i] = arr[j]; arr[j] = t;                    \
   }                                                                   \
}
DEFINE_PERM( perm_u8,  uint8_t  )
DEFINE_PERM( perm_u16, uint16_t )
DEFINE_PERM( perm_int, int      )

// ---------------------------------------------------------------------------
// Table generation (epoch shapechange) — mirrors the OdoCrypt(key) constructor.
// ---------------------------------------------------------------------------

void odocrypt_init( OdoCrypt *c, uint32_t key )
{
   OdoRandom r;
   rand_init( &r, key );

   for ( int i = 0; i < ODO_SMALL_SBOX_COUNT; i++ )
      perm_u8( &r, c->Sbox1[i], 1 << ODO_SMALL_SBOX_WIDTH );
   for ( int i = 0; i < ODO_LARGE_SBOX_COUNT; i++ )
      perm_u16( &r, c->Sbox2[i], 1 << ODO_LARGE_SBOX_WIDTH );

   for ( int i = 0; i < 2; i++ )
   {
      OdoPbox *perm = &c->Permutation[i];
      for ( int j = 0; j < ODO_PBOX_SUBROUNDS; j++ )
         for ( int k = 0; k < ODO_STATE_SIZE / 2; k++ )
            perm->mask[j][k] = rand_next_long( &r );
      for ( int j = 0; j < ODO_PBOX_SUBROUNDS - 1; j++ )
         for ( int k = 0; k < ODO_STATE_SIZE / 2; k++ )
            perm->rotation[j][k] = rand_next( &r, 63 ) + 1;
   }

   // Rotations: distinct, non-zero, with odd sum.
   {
      int bits[ODO_WORD_BITS - 1];
      perm_int( &r, bits, ODO_WORD_BITS - 1 );
      int sum = 0;
      for ( int j = 0; j < ODO_ROTATION_COUNT - 1; j++ )
      {
         c->Rotations[j] = bits[j] + 1;
         sum += c->Rotations[j];
      }
      for ( int j = ODO_ROTATION_COUNT - 1; ; j++ )
         if ( ( bits[j] + 1 + sum ) % 2 )
         {
            c->Rotations[ODO_ROTATION_COUNT - 1] = bits[j] + 1;
            break;
         }
   }

   for ( int i = 0; i < ODO_ROUNDS; i++ )
      c->RoundKey[i] = (uint16_t)rand_next( &r, 1 << ODO_STATE_SIZE );

#if defined(__AVX512F__)
   // Widen the S-boxes to uint32 for AVX512 i64gather.
   for ( int i = 0; i < ODO_SMALL_SBOX_COUNT; i++ )
      for ( int k = 0; k < ( 1 << ODO_SMALL_SBOX_WIDTH ); k++ )
         c->Sbox1_w[i][k] = c->Sbox1[i][k];
   for ( int i = 0; i < ODO_LARGE_SBOX_COUNT; i++ )
      for ( int k = 0; k < ( 1 << ODO_LARGE_SBOX_WIDTH ); k++ )
         c->Sbox2_w[i][k] = c->Sbox2[i][k];
#endif
}

// ---------------------------------------------------------------------------
// Encrypt (forward SPN).
// ---------------------------------------------------------------------------

static inline uint64_t rot64( uint64_t x, int r )
{
   return r == 0 ? x : ( x << r ) ^ ( x >> ( 64 - r ) );
}

static void unpack_state( uint64_t state[ODO_STATE_SIZE], const char bytes[ODO_DIGEST_SIZE] )
{
   for ( int i = 0; i < ODO_STATE_SIZE; i++ )
   {
      uint64_t v = 0;
      for ( int j = 0; j < 8; j++ )
         v |= (uint64_t)(uint8_t)bytes[8 * i + j] << ( 8 * j );
      state[i] = v;
   }
}

static void pack_state( const uint64_t state[ODO_STATE_SIZE], char bytes[ODO_DIGEST_SIZE] )
{
   for ( int i = 0; i < ODO_STATE_SIZE; i++ )
      for ( int j = 0; j < 8; j++ )
         bytes[8 * i + j] = (char)( ( state[i] >> ( 8 * j ) ) & 0xff );
}

static void premix( uint64_t state[ODO_STATE_SIZE] )
{
   uint64_t total = 0;
   for ( int i = 0; i < ODO_STATE_SIZE; i++ ) total ^= state[i];
   total ^= total >> 32;
   for ( int i = 0; i < ODO_STATE_SIZE; i++ ) state[i] ^= total;
}

static void apply_sboxes( uint64_t state[ODO_STATE_SIZE],
                          const uint8_t  sbox1[ODO_SMALL_SBOX_COUNT][1 << ODO_SMALL_SBOX_WIDTH],
                          const uint16_t sbox2[ODO_LARGE_SBOX_COUNT][1 << ODO_LARGE_SBOX_WIDTH] )
{
   const uint64_t MASK1 = ( 1 << ODO_SMALL_SBOX_WIDTH ) - 1;
   const uint64_t MASK2 = ( 1 << ODO_LARGE_SBOX_WIDTH ) - 1;
   int smallIdx = 0;
   for ( int i = 0; i < ODO_STATE_SIZE; i++ )
   {
      uint64_t next = 0;
      int pos = 0, largeIdx = i;
      for ( int j = 0; j < ODO_SMALL_SBOX_COUNT / ODO_STATE_SIZE; j++ )
      {
         next |= (uint64_t)sbox1[smallIdx][( state[i] >> pos ) & MASK1] << pos;
         pos += ODO_SMALL_SBOX_WIDTH;
         next |= (uint64_t)sbox2[largeIdx][( state[i] >> pos ) & MASK2] << pos;
         pos += ODO_LARGE_SBOX_WIDTH;
         smallIdx++;
      }
      state[i] = next;
   }
}

static void apply_masked_swaps( uint64_t state[ODO_STATE_SIZE], const uint64_t mask[ODO_STATE_SIZE / 2] )
{
   for ( int i = 0; i < ODO_STATE_SIZE / 2; i++ )
   {
      uint64_t swp = mask[i] & ( state[2 * i] ^ state[2 * i + 1] );
      state[2 * i]     ^= swp;
      state[2 * i + 1] ^= swp;
   }
}

static void apply_word_shuffle( uint64_t state[ODO_STATE_SIZE], int m )
{
   uint64_t next[ODO_STATE_SIZE];
   for ( int i = 0; i < ODO_STATE_SIZE; i++ )
      next[( m * i ) % ODO_STATE_SIZE] = state[i];
   memcpy( state, next, sizeof next );
}

static void apply_pbox_rotations( uint64_t state[ODO_STATE_SIZE], const int rotation[ODO_STATE_SIZE / 2] )
{
   for ( int i = 0; i < ODO_STATE_SIZE / 2; i++ )
      state[2 * i] = rot64( state[2 * i], rotation[i] );   // only even words
}

static void apply_pbox( uint64_t state[ODO_STATE_SIZE], const OdoPbox *perm )
{
   for ( int i = 0; i < ODO_PBOX_SUBROUNDS - 1; i++ )
   {
      apply_masked_swaps( state, perm->mask[i] );
      apply_word_shuffle( state, ODO_PBOX_M );
      apply_pbox_rotations( state, perm->rotation[i] );
   }
   apply_masked_swaps( state, perm->mask[ODO_PBOX_SUBROUNDS - 1] );
}

static void apply_rotations( uint64_t state[ODO_STATE_SIZE], const int rotations[ODO_ROTATION_COUNT] )
{
   uint64_t next[ODO_STATE_SIZE];
   for ( int i = 0; i < ODO_STATE_SIZE; i++ )
      next[i] = state[( i + 1 ) % ODO_STATE_SIZE];
   for ( int i = 0; i < ODO_STATE_SIZE; i++ )
      for ( int j = 0; j < ODO_ROTATION_COUNT; j++ )
         next[i] ^= rot64( state[i], rotations[j] );
   memcpy( state, next, sizeof next );
}

static void apply_round_key( uint64_t state[ODO_STATE_SIZE], int roundKey )
{
   for ( int i = 0; i < ODO_STATE_SIZE; i++ )
      state[i] ^= ( roundKey >> i ) & 1;
}

void odocrypt_encrypt( const OdoCrypt *c, char out[ODO_DIGEST_SIZE],
                       const char in[ODO_DIGEST_SIZE] )
{
   uint64_t state[ODO_STATE_SIZE];
   unpack_state( state, in );
   premix( state );
   for ( int round = 0; round < ODO_ROUNDS; round++ )
   {
      apply_pbox( state, &c->Permutation[0] );
      apply_sboxes( state, c->Sbox1, c->Sbox2 );
      apply_pbox( state, &c->Permutation[1] );
      apply_rotations( state, c->Rotations );
      apply_round_key( state, c->RoundKey[round] );
   }
   pack_state( state, out );
}

// ---------------------------------------------------------------------------
// Keccak-p[800], 12 rounds (reference implementation, 25 x 32-bit lanes).
// ---------------------------------------------------------------------------

#define KIDX( x, y )  ( ( (x) % 5 ) + 5 * ( (y) % 5 ) )
#define ROL32( a, o ) ( (o) ? ( ( (uint32_t)(a) << (o) ) ^ ( (uint32_t)(a) >> ( 32 - (o) ) ) ) : (uint32_t)(a) )

static const uint32_t odo_keccak_rc[22] =
{
   0x00000001, 0x00008082, 0x0000808a, 0x80008000, 0x0000808b, 0x80000001,
   0x80008081, 0x00008009, 0x0000008a, 0x00000088, 0x80008009, 0x8000000a,
   0x8000808b, 0x0000008b, 0x00008089, 0x00008003, 0x00008002, 0x00000080,
   0x0000800a, 0x8000000a, 0x80008081, 0x00008080
};

static const unsigned int odo_keccak_rho[25] =
{
   0,  1, 30, 28, 27,  4, 12,  6, 23, 20,  3, 10, 11, 25,  7,
   9, 13, 15, 21,  8, 18,  2, 29, 24, 14
};

void odo_keccakp800_12( uint8_t s[100] )
{
   uint32_t A[25];
   for ( int i = 0; i < 25; i++ )
      A[i] = (uint32_t)s[4*i] | ( (uint32_t)s[4*i+1] << 8 )
           | ( (uint32_t)s[4*i+2] << 16 ) | ( (uint32_t)s[4*i+3] << 24 );

   for ( int round = 22 - 12; round < 22; round++ )
   {
      uint32_t C[5], D[5], B[25];
      // theta
      for ( int x = 0; x < 5; x++ )
         C[x] = A[KIDX(x,0)] ^ A[KIDX(x,1)] ^ A[KIDX(x,2)] ^ A[KIDX(x,3)] ^ A[KIDX(x,4)];
      for ( int x = 0; x < 5; x++ )
         D[x] = ROL32( C[(x+1)%5], 1 ) ^ C[(x+4)%5];
      for ( int x = 0; x < 5; x++ )
         for ( int y = 0; y < 5; y++ )
            A[KIDX(x,y)] ^= D[x];
      // rho
      for ( int i = 0; i < 25; i++ )
         A[i] = ROL32( A[i], odo_keccak_rho[i] );
      // pi
      for ( int x = 0; x < 5; x++ )
         for ( int y = 0; y < 5; y++ )
            B[KIDX( 0*x + 1*y, 2*x + 3*y )] = A[KIDX(x,y)];
      // chi
      for ( int y = 0; y < 5; y++ )
         for ( int x = 0; x < 5; x++ )
            A[KIDX(x,y)] = B[KIDX(x,y)] ^ ( ( ~B[KIDX(x+1,y)] ) & B[KIDX(x+2,y)] );
      // iota
      A[0] ^= odo_keccak_rc[round];
   }

   for ( int i = 0; i < 25; i++ )
   {
      s[4*i]   = (uint8_t)( A[i]       );
      s[4*i+1] = (uint8_t)( A[i] >> 8  );
      s[4*i+2] = (uint8_t)( A[i] >> 16 );
      s[4*i+3] = (uint8_t)( A[i] >> 24 );
   }
}

// ---------------------------------------------------------------------------
// AVX512 8-way encrypt: 8 independent 80-byte blocks in parallel. State is
// 10 words x 8 lanes (10 x __m512i). The pure-bitwise steps vectorize ~8x;
// the S-boxes use i64gather over the widened uint32 tables. Each lane's result
// is bit-identical to the scalar odocrypt_encrypt (validated against it).
// ---------------------------------------------------------------------------
#if defined(__AVX512F__)

#define ODO_V1(x)  _mm512_set1_epi64( (long long)(x) )
#define ODO_XOR    _mm512_xor_si512
#define ODO_AND    _mm512_and_si512
#define ODO_OR     _mm512_or_si512

static inline __m512i odo_rolv( __m512i x, int r )
{ return _mm512_rolv_epi64( x, ODO_V1( r ) ); }

static inline void premix8( __m512i s[10] )
{
   __m512i t = s[0];
   for ( int i = 1; i < 10; i++ ) t = ODO_XOR( t, s[i] );
   t = ODO_XOR( t, _mm512_srli_epi64( t, 32 ) );
   for ( int i = 0; i < 10; i++ ) s[i] = ODO_XOR( s[i], t );
}

static inline void mswaps8( __m512i s[10], const uint64_t m[ODO_STATE_SIZE/2] )
{
   for ( int i = 0; i < ODO_STATE_SIZE/2; i++ )
   {
      __m512i a = s[2*i], b = s[2*i+1];
      __m512i sw = ODO_AND( ODO_V1( m[i] ), ODO_XOR( a, b ) );
      s[2*i] = ODO_XOR( a, sw );
      s[2*i+1] = ODO_XOR( b, sw );
   }
}

static inline void wshuf8( __m512i s[10] )
{
   __m512i n[10];
   for ( int i = 0; i < 10; i++ ) n[( ODO_PBOX_M * i ) % 10] = s[i];
   for ( int i = 0; i < 10; i++ ) s[i] = n[i];
}

static inline void prot8( __m512i s[10], const int r[ODO_STATE_SIZE/2] )
{
   for ( int i = 0; i < ODO_STATE_SIZE/2; i++ )
      s[2*i] = odo_rolv( s[2*i], r[i] );
}

static inline void pbox8( __m512i s[10], const OdoPbox *p )
{
   for ( int i = 0; i < ODO_PBOX_SUBROUNDS - 1; i++ )
   {
      mswaps8( s, p->mask[i] );
      wshuf8( s );
      prot8( s, p->rotation[i] );
   }
   mswaps8( s, p->mask[ODO_PBOX_SUBROUNDS - 1] );
}

static inline void sboxes8( __m512i s[10], const OdoCrypt *c )
{
   for ( int i = 0; i < 10; i++ )
   {
      __m512i x = s[i], next = _mm512_setzero_si512();
      int pos = 0;
      for ( int j = 0; j < ODO_SMALL_SBOX_COUNT / ODO_STATE_SIZE; j++ )
      {
         int si = ( ODO_SMALL_SBOX_COUNT / ODO_STATE_SIZE ) * i + j;

         // 6-bit (small) S-box: in-register 64-entry table lookup (no gather).
         __m512i i1 = ODO_AND( _mm512_srlv_epi64( x, ODO_V1( pos ) ), ODO_V1( 63 ) );
#if defined(__AVX512VBMI__)
         __m512i tbl = _mm512_loadu_si512( (const void*)c->Sbox1[si] );  // 64 x u8
         __m512i v1  = ODO_AND( _mm512_permutexvar_epi8( i1, tbl ), ODO_V1( 0xFF ) );
#else
         __m512i v1  = _mm512_cvtepu32_epi64(
                          _mm512_i64gather_epi32( i1, (const int*)c->Sbox1_w[si], 4 ) );
#endif
         next = ODO_OR( next, _mm512_sllv_epi64( v1, ODO_V1( pos ) ) );
         pos += ODO_SMALL_SBOX_WIDTH;

         // 10-bit (large) S-box: 1024 entries -> gather.
         __m512i i2 = ODO_AND( _mm512_srlv_epi64( x, ODO_V1( pos ) ), ODO_V1( 1023 ) );
         __m512i v2 = _mm512_cvtepu32_epi64(
                         _mm512_i64gather_epi32( i2, (const int*)c->Sbox2_w[i], 4 ) );
         next = ODO_OR( next, _mm512_sllv_epi64( v2, ODO_V1( pos ) ) );
         pos += ODO_LARGE_SBOX_WIDTH;
      }
      s[i] = next;
   }
}

static inline void rot8( __m512i s[10], const int r[ODO_ROTATION_COUNT] )
{
   __m512i n[10];
   for ( int i = 0; i < 10; i++ ) n[i] = s[( i + 1 ) % 10];
   for ( int i = 0; i < 10; i++ )
      for ( int j = 0; j < ODO_ROTATION_COUNT; j++ )
         n[i] = ODO_XOR( n[i], odo_rolv( s[i], r[j] ) );
   for ( int i = 0; i < 10; i++ ) s[i] = n[i];
}

static inline void rkey8( __m512i s[10], int rk )
{
   for ( int i = 0; i < 10; i++ ) s[i] = ODO_XOR( s[i], ODO_V1( ( rk >> i ) & 1 ) );
}

static inline uint64_t odo_ld64( const unsigned char *p )
{ uint64_t v; memcpy( &v, p, 8 ); return v; }

void odocrypt_encrypt_8way( const OdoCrypt *c,
                            unsigned char out[8][ODO_DIGEST_SIZE],
                            const unsigned char in[8][ODO_DIGEST_SIZE] )
{
   __m512i s[10];
   for ( int i = 0; i < 10; i++ )
      s[i] = _mm512_set_epi64(
         odo_ld64( in[7] + 8*i ), odo_ld64( in[6] + 8*i ),
         odo_ld64( in[5] + 8*i ), odo_ld64( in[4] + 8*i ),
         odo_ld64( in[3] + 8*i ), odo_ld64( in[2] + 8*i ),
         odo_ld64( in[1] + 8*i ), odo_ld64( in[0] + 8*i ) );

   premix8( s );
   for ( int r = 0; r < ODO_ROUNDS; r++ )
   {
      pbox8( s, &c->Permutation[0] );
      sboxes8( s, c );
      pbox8( s, &c->Permutation[1] );
      rot8( s, c->Rotations );
      rkey8( s, c->RoundKey[r] );
   }

   for ( int i = 0; i < 10; i++ )
   {
      uint64_t t[8];
      _mm512_storeu_si512( t, s[i] );
      for ( int l = 0; l < 8; l++ ) memcpy( out[l] + 8*i, &t[l], 8 );
   }
}

#endif // __AVX512F__
