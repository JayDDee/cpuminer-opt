/* Lyra2RE, two lanes per AVX2 register.
 *
 * The sponge state is exactly 16 x 64-bit words, so a 256-bit register already
 * holds one lane with zero waste (LYRA_ROUND_AVX2, sponge.h) -- there is no
 * width left to exploit. This path wins a different way: it packs TWO words of
 * each of TWO lanes into one 256-bit register, giving the out-of-order engine
 * two independent dependency chains instead of one. The sponge is latency
 * bound rather than issue bound, so the second chain is close to free.
 *
 * Register layout, 8 x __m256i, mirroring the 128-bit 8-register form:
 *
 *    st[j] = [ lane0 word 2j, lane0 word 2j+1 | lane1 word 2j, lane1 word 2j+1 ]
 *              <------- low 128 bits ------->   <------ high 128 bits ------>
 *
 * Every op is either elementwise (add/xor/ror) or per-128-bit-lane
 * (_mm256_alignr_epi8), so the shipping 128-bit round drives both lanes
 * unchanged. That equivalence is not assumed: the round below was verified
 * bit-exact against LYRA_ROUND_AVX on each lane before this file was written.
 *
 * Matrix layout: the two lanes share one allocation, interleaved at 128-bit
 * granularity (intrlv_2x128), which is why every row offset carries a 2x.
 *
 * Kept in its own file on purpose: nothing existing calls these functions, so
 * the six lyra2 variants plus phi2, x22i and x25x that share lyra2.c and
 * sponge.c are bit-identical by construction rather than by re-testing.
 */
#include <stdint.h>
#include <string.h>
#include "miner.h"
#include "compat.h"
#include "lyra2.h"
#include "sponge.h"
#include "simd-utils.h"

#if defined(__AVX2__) && ( !defined(SIMD512) || defined(LYRA2_FORCE_2WAY_AVX2) )

/* 256-bit units per 12-word column block. Numerically the same as
 * BLOCK_LEN_128 because each unit now carries 2 words of each of 2 lanes. */
#define BLK_2W  ( BLOCK_LEN_INT64 / 2 )

#define G_2W( a, b, c, d ) \
   a = _mm256_add_epi64( a, b ); \
   d = mm256_ror_64( _mm256_xor_si256( d, a ), 32 ); \
   c = _mm256_add_epi64( c, d ); \
   b = mm256_ror_64( _mm256_xor_si256( b, c ), 24 ); \
   a = _mm256_add_epi64( a, b ); \
   d = mm256_ror_64( _mm256_xor_si256( d, a ), 16 ); \
   c = _mm256_add_epi64( c, d ); \
   b = mm256_ror_64( _mm256_xor_si256( b, c ), 63 );

/* v128_alignr64(x,y,1) is _mm_alignr_epi8(x,y,8); the 256-bit form is
 * per-128-bit-lane, which is exactly the 2-lane semantics wanted here. */
#define ALR_2W( x, y ) _mm256_alignr_epi8( x, y, 8 )

#define LYRA_ROUND_2WAY_AVX2( s0, s1, s2, s3, s4, s5, s6, s7 ) \
{ \
   __m256i t; \
   G_2W( s0, s2, s4, s6 ); \
   G_2W( s1, s3, s5, s7 ); \
   t =  ALR_2W( s7, s6 ); \
   s6 = ALR_2W( s6, s7 ); \
   s7 = t; \
   t =  ALR_2W( s2, s3 ); \
   s2 = ALR_2W( s3, s2 ); \
   s3 = t; \
   G_2W( s0, s2, s5, s6 ); \
   G_2W( s1, s3, s4, s7 ); \
   t =  ALR_2W( s6, s7 ); \
   s6 = ALR_2W( s7, s6 ); \
   s7 = t; \
   t =  ALR_2W( s3, s2 ); \
   s2 = ALR_2W( s2, s3 ); \
   s3 = t; \
}

#define LYRA_12_ROUNDS_2WAY_AVX2( s0, s1, s2, s3, s4, s5, s6, s7 ) \
   LYRA_ROUND_2WAY_AVX2( s0, s1, s2, s3, s4, s5, s6, s7 ) \
   LYRA_ROUND_2WAY_AVX2( s0, s1, s2, s3, s4, s5, s6, s7 ) \
   LYRA_ROUND_2WAY_AVX2( s0, s1, s2, s3, s4, s5, s6, s7 ) \
   LYRA_ROUND_2WAY_AVX2( s0, s1, s2, s3, s4, s5, s6, s7 ) \
   LYRA_ROUND_2WAY_AVX2( s0, s1, s2, s3, s4, s5, s6, s7 ) \
   LYRA_ROUND_2WAY_AVX2( s0, s1, s2, s3, s4, s5, s6, s7 ) \
   LYRA_ROUND_2WAY_AVX2( s0, s1, s2, s3, s4, s5, s6, s7 ) \
   LYRA_ROUND_2WAY_AVX2( s0, s1, s2, s3, s4, s5, s6, s7 ) \
   LYRA_ROUND_2WAY_AVX2( s0, s1, s2, s3, s4, s5, s6, s7 ) \
   LYRA_ROUND_2WAY_AVX2( s0, s1, s2, s3, s4, s5, s6, s7 ) \
   LYRA_ROUND_2WAY_AVX2( s0, s1, s2, s3, s4, s5, s6, s7 ) \
   LYRA_ROUND_2WAY_AVX2( s0, s1, s2, s3, s4, s5, s6, s7 )

#define LOAD_ST( S ) \
   __m256i st0 = _mm256_load_si256( (const __m256i*)(S)     ); \
   __m256i st1 = _mm256_load_si256( (const __m256i*)(S) + 1 ); \
   __m256i st2 = _mm256_load_si256( (const __m256i*)(S) + 2 ); \
   __m256i st3 = _mm256_load_si256( (const __m256i*)(S) + 3 ); \
   __m256i st4 = _mm256_load_si256( (const __m256i*)(S) + 4 ); \
   __m256i st5 = _mm256_load_si256( (const __m256i*)(S) + 5 ); \
   __m256i st6 = _mm256_load_si256( (const __m256i*)(S) + 6 ); \
   __m256i st7 = _mm256_load_si256( (const __m256i*)(S) + 7 );

#define STORE_ST( S ) \
   _mm256_store_si256( (__m256i*)(S)    , st0 ); \
   _mm256_store_si256( (__m256i*)(S) + 1, st1 ); \
   _mm256_store_si256( (__m256i*)(S) + 2, st2 ); \
   _mm256_store_si256( (__m256i*)(S) + 3, st3 ); \
   _mm256_store_si256( (__m256i*)(S) + 4, st4 ); \
   _mm256_store_si256( (__m256i*)(S) + 5, st5 ); \
   _mm256_store_si256( (__m256i*)(S) + 6, st6 ); \
   _mm256_store_si256( (__m256i*)(S) + 7, st7 );

/* Lane0 takes the low 128 bits, lane1 the high 128: the two lanes may be
 * reading DIFFERENT matrix rows, which is the whole difficulty of a 2-way
 * Lyra2 -- the Wandering phase derives rowa from each lane's own state. */
#define GATHER_IO( a, b ) _mm256_blend_epi32( a, b, 0xf0 )

#define SCATTER_IO( io, p0, p1 ) \
{ \
   _mm_store_si128( (__m128i*)(p0), _mm256_castsi256_si128( io ) ); \
   _mm_store_si128( (__m128i*)(p1) + 1, _mm256_extracti128_si256( io, 1 ) ); \
}

// ---------------------------------------------------------------- absorbs

static inline void absorb_blake2safe_2w( uint64_t *State, const uint64_t *In,
                                         const uint64_t nBlocks,
                                         const uint64_t block_len )
{
   __m256i st0, st1, st2, st3, st4, st5, st6, st7;

   st0 = st1 = st2 = st3 = _mm256_setzero_si256();
   /* Both halves take the same IV: two independent sponges sharing registers. */
   st4 = _mm256_set_epi64x( 0xbb67ae8584caa73bULL, 0x6a09e667f3bcc908ULL,
                            0xbb67ae8584caa73bULL, 0x6a09e667f3bcc908ULL );
   st5 = _mm256_set_epi64x( 0xa54ff53a5f1d36f1ULL, 0x3c6ef372fe94f82bULL,
                            0xa54ff53a5f1d36f1ULL, 0x3c6ef372fe94f82bULL );
   st6 = _mm256_set_epi64x( 0x9b05688c2b3e6c1fULL, 0x510e527fade682d1ULL,
                            0x9b05688c2b3e6c1fULL, 0x510e527fade682d1ULL );
   st7 = _mm256_set_epi64x( 0x5be0cd19137e2179ULL, 0x1f83d9abfb41bd6bULL,
                            0x5be0cd19137e2179ULL, 0x1f83d9abfb41bd6bULL );

   for ( uint64_t i = 0; i < nBlocks; i++ )
   {
      const __m256i *in = (const __m256i*)In;

      st0 = _mm256_xor_si256( st0, in[0] );
      st1 = _mm256_xor_si256( st1, in[1] );
      st2 = _mm256_xor_si256( st2, in[2] );
      st3 = _mm256_xor_si256( st3, in[3] );

      LYRA_12_ROUNDS_2WAY_AVX2( st0, st1, st2, st3, st4, st5, st6, st7 );

      /* x2 for the two interleaved lanes. Lyra2RE passes block_len in BYTES
       * while this is a word stride, so with nCols=8 the second block lands at
       * word 512 -- zeroed matrix, not the basil. That is what the scalar and
       * AVX-512 paths do, so it is consensus and must not be "fixed" here. */
      In += block_len * 2;
   }
   STORE_ST( State );
}

static inline void absorb_block_2w( uint64_t *State, const uint64_t *In0,
                                    const uint64_t *In1 )
{
   LOAD_ST( State );
   const __m256i *i0 = (const __m256i*)In0;
   const __m256i *i1 = (const __m256i*)In1;

   st0 = _mm256_xor_si256( st0, GATHER_IO( i0[0], i1[0] ) );
   st1 = _mm256_xor_si256( st1, GATHER_IO( i0[1], i1[1] ) );
   st2 = _mm256_xor_si256( st2, GATHER_IO( i0[2], i1[2] ) );
   st3 = _mm256_xor_si256( st3, GATHER_IO( i0[3], i1[3] ) );
   st4 = _mm256_xor_si256( st4, GATHER_IO( i0[4], i1[4] ) );
   st5 = _mm256_xor_si256( st5, GATHER_IO( i0[5], i1[5] ) );

   LYRA_12_ROUNDS_2WAY_AVX2( st0, st1, st2, st3, st4, st5, st6, st7 );

   STORE_ST( State );
}

// --------------------------------------------------------------- squeezes

static inline void squeeze_2w( uint64_t *State, unsigned char *Out,
                               unsigned int len )
{
   /* len is per lane; a 256-bit unit carries 128 bits of each lane. */
   const int units      = len / 16;
   const int fullBlocks = units / BLK_2W;
   __m256i *state = (__m256i*)State;
   __m256i *out   = (__m256i*)Out;

   for ( int i = 0; i < fullBlocks; i++ )
   {
      for ( int j = 0; j < BLK_2W; j++ ) out[j] = state[j];
      LYRA_ROUND_2WAY_AVX2( state[0], state[1], state[2], state[3],
                            state[4], state[5], state[6], state[7] );
      out += BLK_2W;
   }
   for ( int j = 0; j < units % BLK_2W; j++ ) out[j] = state[j];
}

static inline void reduced_squeeze_row0_2w( uint64_t *State, uint64_t *rowOut,
                                            uint64_t nCols )
{
   LOAD_ST( State );
   __m256i *out = (__m256i*)rowOut + ( ( nCols - 1 ) * BLK_2W );

   for ( uint64_t i = 0; i < nCols; i++ )
   {
      out[0] = st0;
      out[1] = st1;
      out[2] = st2;
      out[3] = st3;
      out[4] = st4;
      out[5] = st5;

      out -= BLK_2W;            // fills columns back to front

      LYRA_ROUND_2WAY_AVX2( st0, st1, st2, st3, st4, st5, st6, st7 );
   }
   STORE_ST( State );
}

// --------------------------------------------------------------- duplexes

static inline void reduced_duplex_row1_2w( uint64_t *State, uint64_t *rowIn,
                                           uint64_t *rowOut, uint64_t nCols )
{
   LOAD_ST( State );
   const __m256i *in = (const __m256i*)rowIn;
   __m256i *out = (__m256i*)rowOut + ( ( nCols - 1 ) * BLK_2W );

   for ( uint64_t i = 0; i < nCols; i++ )
   {
      st0 = _mm256_xor_si256( st0, in[0] );
      st1 = _mm256_xor_si256( st1, in[1] );
      st2 = _mm256_xor_si256( st2, in[2] );
      st3 = _mm256_xor_si256( st3, in[3] );
      st4 = _mm256_xor_si256( st4, in[4] );
      st5 = _mm256_xor_si256( st5, in[5] );

      LYRA_ROUND_2WAY_AVX2( st0, st1, st2, st3, st4, st5, st6, st7 );

      out[0] = _mm256_xor_si256( st0, in[0] );
      out[1] = _mm256_xor_si256( st1, in[1] );
      out[2] = _mm256_xor_si256( st2, in[2] );
      out[3] = _mm256_xor_si256( st3, in[3] );
      out[4] = _mm256_xor_si256( st4, in[4] );
      out[5] = _mm256_xor_si256( st5, in[5] );

      in  += BLK_2W;
      out -= BLK_2W;
   }
   STORE_ST( State );
}

/* Setup phase: rowa is deterministic and therefore the SAME for both lanes,
 * so there is a single rowInOut and no gather. rowInOut may alias rowOut, so
 * the inout read-modify-write must stay after the out store, exactly as the
 * scalar path orders it -- that ordering is consensus. */
static inline void reduced_duplex_row_setup_2w( uint64_t *State,
                       uint64_t *rowIn, uint64_t *rowInOut, uint64_t *rowOut,
                       uint64_t nCols )
{
   LOAD_ST( State );
   const __m256i *in = (const __m256i*)rowIn;
   __m256i *inout    = (__m256i*)rowInOut;
   __m256i *out      = (__m256i*)rowOut + ( ( nCols - 1 ) * BLK_2W );

   for ( uint64_t i = 0; i < nCols; i++ )
   {
      st0 = _mm256_xor_si256( st0, _mm256_add_epi64( in[0], inout[0] ) );
      st1 = _mm256_xor_si256( st1, _mm256_add_epi64( in[1], inout[1] ) );
      st2 = _mm256_xor_si256( st2, _mm256_add_epi64( in[2], inout[2] ) );
      st3 = _mm256_xor_si256( st3, _mm256_add_epi64( in[3], inout[3] ) );
      st4 = _mm256_xor_si256( st4, _mm256_add_epi64( in[4], inout[4] ) );
      st5 = _mm256_xor_si256( st5, _mm256_add_epi64( in[5], inout[5] ) );

      LYRA_ROUND_2WAY_AVX2( st0, st1, st2, st3, st4, st5, st6, st7 );

      out[0] = _mm256_xor_si256( st0, in[0] );
      out[1] = _mm256_xor_si256( st1, in[1] );
      out[2] = _mm256_xor_si256( st2, in[2] );
      out[3] = _mm256_xor_si256( st3, in[3] );
      out[4] = _mm256_xor_si256( st4, in[4] );
      out[5] = _mm256_xor_si256( st5, in[5] );

      /* M[row*][col] ^= rotW(rand): a one-word rotation across the block,
       * which alignr does inside each 128-bit lane. */
      inout[0] = _mm256_xor_si256( inout[0], ALR_2W( st0, st5 ) );
      inout[1] = _mm256_xor_si256( inout[1], ALR_2W( st1, st0 ) );
      inout[2] = _mm256_xor_si256( inout[2], ALR_2W( st2, st1 ) );
      inout[3] = _mm256_xor_si256( inout[3], ALR_2W( st3, st2 ) );
      inout[4] = _mm256_xor_si256( inout[4], ALR_2W( st4, st3 ) );
      inout[5] = _mm256_xor_si256( inout[5], ALR_2W( st5, st4 ) );

      in    += BLK_2W;
      inout += BLK_2W;
      out   -= BLK_2W;
   }
   STORE_ST( State );
}

/* Wandering phase. Each lane picks its own rowa, so inout is gathered from two
 * rows and scattered back to both. Two variants:
 *
 *   _cached  neither inout row is rowOut, so the gathered value stays valid
 *            across the out store.
 *   _reread  one inout row IS rowOut. The scalar path reads inout from memory
 *            after storing out, so when they alias it sees the updated bytes.
 *            Re-gathering after the store reproduces that; keeping the cached
 *            copy would not.
 */
static inline void reduced_duplex_row_2w_cached( uint64_t *State,
                     uint64_t *rowIn, uint64_t *rowInOut0, uint64_t *rowInOut1,
                     uint64_t *rowOut, uint64_t nCols )
{
   LOAD_ST( State );
   const __m256i *in = (const __m256i*)rowIn;
   __m256i *io0 = (__m256i*)rowInOut0;
   __m256i *io1 = (__m256i*)rowInOut1;
   __m256i *out = (__m256i*)rowOut;

   for ( uint64_t i = 0; i < nCols; i++ )
   {
      __m256i v0 = GATHER_IO( io0[0], io1[0] );
      __m256i v1 = GATHER_IO( io0[1], io1[1] );
      __m256i v2 = GATHER_IO( io0[2], io1[2] );
      __m256i v3 = GATHER_IO( io0[3], io1[3] );
      __m256i v4 = GATHER_IO( io0[4], io1[4] );
      __m256i v5 = GATHER_IO( io0[5], io1[5] );

      st0 = _mm256_xor_si256( st0, _mm256_add_epi64( in[0], v0 ) );
      st1 = _mm256_xor_si256( st1, _mm256_add_epi64( in[1], v1 ) );
      st2 = _mm256_xor_si256( st2, _mm256_add_epi64( in[2], v2 ) );
      st3 = _mm256_xor_si256( st3, _mm256_add_epi64( in[3], v3 ) );
      st4 = _mm256_xor_si256( st4, _mm256_add_epi64( in[4], v4 ) );
      st5 = _mm256_xor_si256( st5, _mm256_add_epi64( in[5], v5 ) );

      LYRA_ROUND_2WAY_AVX2( st0, st1, st2, st3, st4, st5, st6, st7 );

      out[0] = _mm256_xor_si256( out[0], st0 );
      out[1] = _mm256_xor_si256( out[1], st1 );
      out[2] = _mm256_xor_si256( out[2], st2 );
      out[3] = _mm256_xor_si256( out[3], st3 );
      out[4] = _mm256_xor_si256( out[4], st4 );
      out[5] = _mm256_xor_si256( out[5], st5 );

      v0 = _mm256_xor_si256( v0, ALR_2W( st0, st5 ) );
      v1 = _mm256_xor_si256( v1, ALR_2W( st1, st0 ) );
      v2 = _mm256_xor_si256( v2, ALR_2W( st2, st1 ) );
      v3 = _mm256_xor_si256( v3, ALR_2W( st3, st2 ) );
      v4 = _mm256_xor_si256( v4, ALR_2W( st4, st3 ) );
      v5 = _mm256_xor_si256( v5, ALR_2W( st5, st4 ) );

      SCATTER_IO( v0, io0    , io1     );
      SCATTER_IO( v1, io0 + 1, io1 + 1 );
      SCATTER_IO( v2, io0 + 2, io1 + 2 );
      SCATTER_IO( v3, io0 + 3, io1 + 3 );
      SCATTER_IO( v4, io0 + 4, io1 + 4 );
      SCATTER_IO( v5, io0 + 5, io1 + 5 );

      in  += BLK_2W;
      io0 += BLK_2W;
      io1 += BLK_2W;
      out += BLK_2W;
   }
   STORE_ST( State );
}

static inline void reduced_duplex_row_2w_reread( uint64_t *State,
                     uint64_t *rowIn, uint64_t *rowInOut0, uint64_t *rowInOut1,
                     uint64_t *rowOut, uint64_t nCols )
{
   LOAD_ST( State );
   const __m256i *in = (const __m256i*)rowIn;
   __m256i *io0 = (__m256i*)rowInOut0;
   __m256i *io1 = (__m256i*)rowInOut1;
   __m256i *out = (__m256i*)rowOut;

   for ( uint64_t i = 0; i < nCols; i++ )
   {
      st0 = _mm256_xor_si256( st0,
                 _mm256_add_epi64( in[0], GATHER_IO( io0[0], io1[0] ) ) );
      st1 = _mm256_xor_si256( st1,
                 _mm256_add_epi64( in[1], GATHER_IO( io0[1], io1[1] ) ) );
      st2 = _mm256_xor_si256( st2,
                 _mm256_add_epi64( in[2], GATHER_IO( io0[2], io1[2] ) ) );
      st3 = _mm256_xor_si256( st3,
                 _mm256_add_epi64( in[3], GATHER_IO( io0[3], io1[3] ) ) );
      st4 = _mm256_xor_si256( st4,
                 _mm256_add_epi64( in[4], GATHER_IO( io0[4], io1[4] ) ) );
      st5 = _mm256_xor_si256( st5,
                 _mm256_add_epi64( in[5], GATHER_IO( io0[5], io1[5] ) ) );

      LYRA_ROUND_2WAY_AVX2( st0, st1, st2, st3, st4, st5, st6, st7 );

      out[0] = _mm256_xor_si256( out[0], st0 );
      out[1] = _mm256_xor_si256( out[1], st1 );
      out[2] = _mm256_xor_si256( out[2], st2 );
      out[3] = _mm256_xor_si256( out[3], st3 );
      out[4] = _mm256_xor_si256( out[4], st4 );
      out[5] = _mm256_xor_si256( out[5], st5 );

      /* re-gather AFTER the out store: that is what aliasing demands */
      SCATTER_IO( _mm256_xor_si256( GATHER_IO( io0[0], io1[0] ),
                                    ALR_2W( st0, st5 ) ), io0    , io1     );
      SCATTER_IO( _mm256_xor_si256( GATHER_IO( io0[1], io1[1] ),
                                    ALR_2W( st1, st0 ) ), io0 + 1, io1 + 1 );
      SCATTER_IO( _mm256_xor_si256( GATHER_IO( io0[2], io1[2] ),
                                    ALR_2W( st2, st1 ) ), io0 + 2, io1 + 2 );
      SCATTER_IO( _mm256_xor_si256( GATHER_IO( io0[3], io1[3] ),
                                    ALR_2W( st3, st2 ) ), io0 + 3, io1 + 3 );
      SCATTER_IO( _mm256_xor_si256( GATHER_IO( io0[4], io1[4] ),
                                    ALR_2W( st4, st3 ) ), io0 + 4, io1 + 4 );
      SCATTER_IO( _mm256_xor_si256( GATHER_IO( io0[5], io1[5] ),
                                    ALR_2W( st5, st4 ) ), io0 + 5, io1 + 5 );

      in  += BLK_2W;
      io0 += BLK_2W;
      io1 += BLK_2W;
      out += BLK_2W;
   }
   STORE_ST( State );
}

static inline void reduced_duplex_row_2w( uint64_t *State, uint64_t *rowIn,
                     uint64_t *rowInOut0, uint64_t *rowInOut1,
                     uint64_t *rowOut, uint64_t nCols )
{
   if ( ( rowInOut0 == rowOut ) || ( rowInOut1 == rowOut ) )
      reduced_duplex_row_2w_reread( State, rowIn, rowInOut0, rowInOut1,
                                    rowOut, nCols );
   else
      reduced_duplex_row_2w_cached( State, rowIn, rowInOut0, rowInOut1,
                                    rowOut, nCols );
}

// ------------------------------------------------------------------ driver

int LYRA2RE_2WAY_AVX2( void *K, uint64_t kLen, const void *pwd,
                       const uint64_t pwdlen, const uint64_t timeCost,
                       const uint64_t nRows, const uint64_t nCols )
{
   uint64_t _ALIGN(64) state[32];        // 2 lanes x 16 words
   int64_t row = 2;
   int64_t prev = 1;
   int64_t rowa0 = 0, rowa1 = 0;
   int64_t tau, step = 1, window = 2, gap = 1, i;

   const int64_t ROW_LEN_INT64 = BLOCK_LEN_INT64 * nCols;
   const int64_t ROW_LEN_BYTES = ROW_LEN_INT64 * 8;
   const int64_t BLOCK_LEN = ( nCols == 4 ) ? BLOCK_LEN_BLAKE2_SAFE_INT64
                                            : BLOCK_LEN_BLAKE2_SAFE_BYTES;

   i = (int64_t)ROW_LEN_BYTES * nRows;

#if defined(ALLIUM_NO_LYRA2_TLS)

   uint64_t *wholeMatrix = mm_malloc( 2 * i, 64 );   // x2: both lanes
   if ( wholeMatrix == NULL ) return -1;

#else

   /* The matrix is per-thread state, not per-call state, so it is allocated
    * once per thread and reused. This is the tree's own pattern --
    * `l2v3_wholeMatrix`/`l2v2_wholeMatrix` (`lyra2-gate.c:41,90`) and
    * `allium_ctx` (`allium-4way.c:737`) are all `__thread` -- and it removes
    * one malloc/free pair per NONCE PAIR on the shipping AVX2 path.
    *
    * It grows rather than assuming allium's parameters, so the function stays
    * correct if any caller ever passes larger nRows/nCols. Never freed, which
    * matches `l2v3_wholeMatrix`: a miner's thread pool is fixed, and 12 KB per
    * thread is not worth an atexit hook. */
   static __thread uint64_t *tls_matrix = NULL;
   static __thread int64_t   tls_bytes  = 0;

   if ( tls_bytes < 2 * i )
   {
      if ( tls_matrix != NULL ) mm_free( tls_matrix );
      tls_matrix = mm_malloc( 2 * i, 64 );
      if ( tls_matrix == NULL ) { tls_bytes = 0; return -1; }
      tls_bytes = 2 * i;
   }
   uint64_t *wholeMatrix = tls_matrix;

#endif

   /* Still required every call: the absorb reads zeroed matrix beyond the
    * basil, which is consensus (see absorb_blake2safe_2w). The TLS matrix
    * removes the allocation, not the zeroing. */
   memset_zero_256( (__m256i*)wholeMatrix, ( 2 * i ) >> 5 );

   uint64_t *ptrWord = wholeMatrix;
   uint64_t *pw = (uint64_t*)pwd;

   int64_t nBlocksInput = ( ( pwdlen + pwdlen + 6 * sizeof(uint64_t) )
                              / BLOCK_LEN_BLAKE2_SAFE_BYTES ) + 1;

   uint64_t *ptr = wholeMatrix;

   /* pwd arrives already interleaved 2x128, so these are byte copies. */
   memcpy( ptr, pw, 2 * pwdlen );        // password, both lanes
   ptr += pwdlen >> 2;
   memcpy( ptr, pw, 2 * pwdlen );        // salt is the password again
   ptr += pwdlen >> 2;

   /* Basil, interleaved on the fly. At 128-bit granularity a lane's word pair
    * lands at [0,1] and its partner's at [2,3], hence the (0,2) (1,3) pairing
    * rather than the AVX-512 path's (0,4) (1,5). */
   ptr[ 0] = ptr[ 2] = kLen;
   ptr[ 1] = ptr[ 3] = pwdlen;
   ptr[ 4] = ptr[ 6] = pwdlen;           // saltlen
   ptr[ 5] = ptr[ 7] = timeCost;
   ptr[ 8] = ptr[10] = nRows;
   ptr[ 9] = ptr[11] = nCols;
   ptr[12] = ptr[14] = 0x80;
   ptr[13] = ptr[15] = 0x0100000000000000;

   absorb_blake2safe_2w( state, ptrWord, nBlocksInput, BLOCK_LEN );

   reduced_squeeze_row0_2w( state, &wholeMatrix[0], nCols );

   reduced_duplex_row1_2w( state, &wholeMatrix[0],
                                  &wholeMatrix[ 2 * ROW_LEN_INT64 ], nCols );
   do
   {
      reduced_duplex_row_setup_2w( state,
                            &wholeMatrix[ 2 * prev  * ROW_LEN_INT64 ],
                            &wholeMatrix[ 2 * rowa0 * ROW_LEN_INT64 ],
                            &wholeMatrix[ 2 * row   * ROW_LEN_INT64 ], nCols );

      rowa0 = ( rowa0 + step ) & ( window - 1 );
      prev = row;
      row++;

      if ( rowa0 == 0 )
      {
         step = window + gap;
         window *= 2;
         gap = -gap;
      }
   } while ( row < nRows );

   row = 0;
   for ( tau = 1; tau <= timeCost; tau++ )
   {
      step = ( ( tau & 1 ) == 0 ) ? -1 : ( nRows >> 1 ) - 1;
      do
      {
         /* Each lane's own word 0. In this layout register 0 holds
          * [L0w0, L0w1, L1w0, L1w1], so lane 1 reads state[2], not state[4]
          * as it would at 256-bit granularity. */
         rowa0 = state[ 0 ] & (unsigned int)( nRows - 1 );
         rowa1 = state[ 2 ] & (unsigned int)( nRows - 1 );

         reduced_duplex_row_2w( state,
                          &wholeMatrix[ 2 * prev  * ROW_LEN_INT64 ],
                          &wholeMatrix[ 2 * rowa0 * ROW_LEN_INT64 ],
                          &wholeMatrix[ 2 * rowa1 * ROW_LEN_INT64 ],
                          &wholeMatrix[ 2 * row   * ROW_LEN_INT64 ], nCols );
         prev = row;
         row = ( row + step ) & (unsigned int)( nRows - 1 );

      } while ( row != 0 );
   }

   absorb_block_2w( state, &wholeMatrix[ 2 * rowa0 * ROW_LEN_INT64 ],
                           &wholeMatrix[ 2 * rowa1 * ROW_LEN_INT64 ] );
   squeeze_2w( state, K, (unsigned int)kLen );

#if defined(ALLIUM_NO_LYRA2_TLS)
   mm_free( wholeMatrix );
#endif

   return 0;
}

#endif  // AVX2 && !AVX512
