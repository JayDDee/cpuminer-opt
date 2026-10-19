/* Lyra2RE, four lanes per AVX-512 register.
 *
 * This is the shipping 2-way geometry widened. The sponge state is
 * exactly 16 x 64-bit words, so a 512-bit register could hold one lane and
 * waste half of itself; instead it holds TWO words of each of FOUR lanes, one
 * lane per 128-bit sub-lane, giving the out-of-order engine four independent
 * dependency chains through a latency-bound kernel.
 *
 * Register layout, 8 x __m512i:
 *
 *   st[j] = [ L0 w2j, L0 w2j+1 | L1 w2j, L1 w2j+1 | L2 ... | L3 ... ]
 *             <-- sub-lane 0 -->  <-- sub-lane 1 -->
 *
 * Every op is elementwise (add/xor/ror) or per-128-bit-lane
 * (_mm512_alignr_epi8), so the shipping 128-bit round drives all four lanes
 * unchanged -- the same equivalence the 2-way relies on at 2 lanes, and it is
 * bit-exact against that round on all four lanes.
 *
 * Matrix layout: the four lanes share one allocation interleaved at 128-bit
 * granularity (intrlv_4x128), which is why every row offset carries a 4x.
 * That granularity is deliberate: cubehash on the 16-way path is ALREADY
 * 4x128, so Lyra2 -> cubehash -> Lyra2 now stays in one layout and the
 * conversions between them disappear.
 *
 * Per-lane matrix is 6 KB, so four lanes are 24 KB -- still inside a 32 KB
 * L1D, but four threads on one core are not.
 *
 * Kept in its own file on purpose: nothing existing calls these functions, so
 * the six lyra2 variants plus phi2, x22i and x25x that share lyra2.c and
 * sponge.c stay bit-identical by construction rather than by re-testing.
 */
#include <stdint.h>
#include <string.h>
#include "miner.h"
#include "compat.h"
#include "lyra2.h"
#include "sponge.h"
#include "simd-utils.h"

#if defined(SIMD512)

/* 512-bit units per 12-word column block. Numerically the same as the 2-way's
 * BLK_2W because each unit now carries 2 words of each of 4 lanes. */
#define BLK_4W  ( BLOCK_LEN_INT64 / 2 )

#define G_4W( a, b, c, d ) \
   a = _mm512_add_epi64( a, b ); \
   d = mm512_ror_64( _mm512_xor_si512( d, a ), 32 ); \
   c = _mm512_add_epi64( c, d ); \
   b = mm512_ror_64( _mm512_xor_si512( b, c ), 24 ); \
   a = _mm512_add_epi64( a, b ); \
   d = mm512_ror_64( _mm512_xor_si512( d, a ), 16 ); \
   c = _mm512_add_epi64( c, d ); \
   b = mm512_ror_64( _mm512_xor_si512( b, c ), 63 );

/* Per-128-bit-lane, which is exactly the 4-lane semantics wanted here.
 * _mm512_alignr_epi64 would rotate across the WHOLE register and is wrong. */
#define ALR_4W( x, y ) _mm512_alignr_epi8( x, y, 8 )

#define LYRA_ROUND_4WAY_AVX512( s0, s1, s2, s3, s4, s5, s6, s7 ) \
{ \
   __m512i t; \
   G_4W( s0, s2, s4, s6 ); \
   G_4W( s1, s3, s5, s7 ); \
   t =  ALR_4W( s7, s6 ); \
   s6 = ALR_4W( s6, s7 ); \
   s7 = t; \
   t =  ALR_4W( s2, s3 ); \
   s2 = ALR_4W( s3, s2 ); \
   s3 = t; \
   G_4W( s0, s2, s5, s6 ); \
   G_4W( s1, s3, s4, s7 ); \
   t =  ALR_4W( s6, s7 ); \
   s6 = ALR_4W( s7, s6 ); \
   s7 = t; \
   t =  ALR_4W( s3, s2 ); \
   s2 = ALR_4W( s2, s3 ); \
   s3 = t; \
}

#define LYRA_12_ROUNDS_4WAY_AVX512( s0, s1, s2, s3, s4, s5, s6, s7 ) \
   LYRA_ROUND_4WAY_AVX512( s0, s1, s2, s3, s4, s5, s6, s7 ) \
   LYRA_ROUND_4WAY_AVX512( s0, s1, s2, s3, s4, s5, s6, s7 ) \
   LYRA_ROUND_4WAY_AVX512( s0, s1, s2, s3, s4, s5, s6, s7 ) \
   LYRA_ROUND_4WAY_AVX512( s0, s1, s2, s3, s4, s5, s6, s7 ) \
   LYRA_ROUND_4WAY_AVX512( s0, s1, s2, s3, s4, s5, s6, s7 ) \
   LYRA_ROUND_4WAY_AVX512( s0, s1, s2, s3, s4, s5, s6, s7 ) \
   LYRA_ROUND_4WAY_AVX512( s0, s1, s2, s3, s4, s5, s6, s7 ) \
   LYRA_ROUND_4WAY_AVX512( s0, s1, s2, s3, s4, s5, s6, s7 ) \
   LYRA_ROUND_4WAY_AVX512( s0, s1, s2, s3, s4, s5, s6, s7 ) \
   LYRA_ROUND_4WAY_AVX512( s0, s1, s2, s3, s4, s5, s6, s7 ) \
   LYRA_ROUND_4WAY_AVX512( s0, s1, s2, s3, s4, s5, s6, s7 ) \
   LYRA_ROUND_4WAY_AVX512( s0, s1, s2, s3, s4, s5, s6, s7 )

#define LOAD_ST( S ) \
   __m512i st0 = _mm512_load_si512( (const __m512i*)(S)     ); \
   __m512i st1 = _mm512_load_si512( (const __m512i*)(S) + 1 ); \
   __m512i st2 = _mm512_load_si512( (const __m512i*)(S) + 2 ); \
   __m512i st3 = _mm512_load_si512( (const __m512i*)(S) + 3 ); \
   __m512i st4 = _mm512_load_si512( (const __m512i*)(S) + 4 ); \
   __m512i st5 = _mm512_load_si512( (const __m512i*)(S) + 5 ); \
   __m512i st6 = _mm512_load_si512( (const __m512i*)(S) + 6 ); \
   __m512i st7 = _mm512_load_si512( (const __m512i*)(S) + 7 );

#define STORE_ST( S ) \
   _mm512_store_si512( (__m512i*)(S)    , st0 ); \
   _mm512_store_si512( (__m512i*)(S) + 1, st1 ); \
   _mm512_store_si512( (__m512i*)(S) + 2, st2 ); \
   _mm512_store_si512( (__m512i*)(S) + 3, st3 ); \
   _mm512_store_si512( (__m512i*)(S) + 4, st4 ); \
   _mm512_store_si512( (__m512i*)(S) + 5, st5 ); \
   _mm512_store_si512( (__m512i*)(S) + 6, st6 ); \
   _mm512_store_si512( (__m512i*)(S) + 7, st7 );

/* Wandering-phase gather/scatter. Each lane derives its own rowa, so the four
 * lanes may be reading four DIFFERENT matrix rows -- the whole difficulty of an
 * n-way Lyra2. Lane i's 128 bits is taken from ITS row at ITS sub-lane offset.
 *
 * Four 128-bit loads read 64 bytes to build 64 bytes; blending four full
 * 512-bit loads would read 256 bytes for the same result, so the narrow loads
 * are the point, not a micro-optimisation. */
#if defined(LYRA2_4WAY_WIDE_IO)

/* Variant B: full-width loads with mask-blends, and masked full-width stores.
 *
 * This changes the load/store FORM only, not the line count: four lanes read
 * four different rows, so four distinct cache lines are touched either way and
 * reading 64 bytes instead of 16 from a line being filled anyway costs no
 * extra traffic. It was measured and does not recover the loss above, leaving
 * row divergence rather than uop shape as the cause. */
static inline __m512i gather_io( const __m512i *io0, const __m512i *io1,
                                 const __m512i *io2, const __m512i *io3 )
{
   __m512i v = _mm512_load_si512( io0 );          /* sub-lane 0 already correct */
   v = _mm512_mask_blend_epi64( 0x0c, v, _mm512_load_si512( io1 ) );
   v = _mm512_mask_blend_epi64( 0x30, v, _mm512_load_si512( io2 ) );
   v = _mm512_mask_blend_epi64( 0xc0, v, _mm512_load_si512( io3 ) );
   return v;
}

static inline void scatter_io( const __m512i v, __m512i *io0, __m512i *io1,
                               __m512i *io2, __m512i *io3 )
{
   /* Row offsets are multiples of 64 bytes and the matrix is 64-byte aligned,
    * so aligned masked stores are safe. */
   _mm512_mask_store_epi64( io0, 0x03, v );
   _mm512_mask_store_epi64( io1, 0x0c, v );
   _mm512_mask_store_epi64( io2, 0x30, v );
   _mm512_mask_store_epi64( io3, 0xc0, v );
}

#else

static inline __m512i gather_io( const __m512i *io0, const __m512i *io1,
                                 const __m512i *io2, const __m512i *io3 )
{
   __m512i v = _mm512_castsi128_si512(
                  _mm_load_si128( (const __m128i*)io0     ) );
   v = _mm512_inserti32x4( v, _mm_load_si128( (const __m128i*)io1 + 1 ), 1 );
   v = _mm512_inserti32x4( v, _mm_load_si128( (const __m128i*)io2 + 2 ), 2 );
   v = _mm512_inserti32x4( v, _mm_load_si128( (const __m128i*)io3 + 3 ), 3 );
   return v;
}

static inline void scatter_io( const __m512i v, __m512i *io0, __m512i *io1,
                               __m512i *io2, __m512i *io3 )
{
   _mm_store_si128( (__m128i*)io0    , _mm512_extracti32x4_epi32( v, 0 ) );
   _mm_store_si128( (__m128i*)io1 + 1, _mm512_extracti32x4_epi32( v, 1 ) );
   _mm_store_si128( (__m128i*)io2 + 2, _mm512_extracti32x4_epi32( v, 2 ) );
   _mm_store_si128( (__m128i*)io3 + 3, _mm512_extracti32x4_epi32( v, 3 ) );
}

#endif

// ---------------------------------------------------------------- absorbs

static inline void absorb_blake2safe_4w( uint64_t *State, const uint64_t *In,
                                         const uint64_t nBlocks,
                                         const uint64_t block_len )
{
   __m512i st0, st1, st2, st3, st4, st5, st6, st7;

   st0 = st1 = st2 = st3 = _mm512_setzero_si512();
   /* All four sub-lanes take the same IV: four independent sponges sharing
    * registers. */
   st4 = _mm512_set_epi64( 0xbb67ae8584caa73bULL, 0x6a09e667f3bcc908ULL,
                           0xbb67ae8584caa73bULL, 0x6a09e667f3bcc908ULL,
                           0xbb67ae8584caa73bULL, 0x6a09e667f3bcc908ULL,
                           0xbb67ae8584caa73bULL, 0x6a09e667f3bcc908ULL );
   st5 = _mm512_set_epi64( 0xa54ff53a5f1d36f1ULL, 0x3c6ef372fe94f82bULL,
                           0xa54ff53a5f1d36f1ULL, 0x3c6ef372fe94f82bULL,
                           0xa54ff53a5f1d36f1ULL, 0x3c6ef372fe94f82bULL,
                           0xa54ff53a5f1d36f1ULL, 0x3c6ef372fe94f82bULL );
   st6 = _mm512_set_epi64( 0x9b05688c2b3e6c1fULL, 0x510e527fade682d1ULL,
                           0x9b05688c2b3e6c1fULL, 0x510e527fade682d1ULL,
                           0x9b05688c2b3e6c1fULL, 0x510e527fade682d1ULL,
                           0x9b05688c2b3e6c1fULL, 0x510e527fade682d1ULL );
   st7 = _mm512_set_epi64( 0x5be0cd19137e2179ULL, 0x1f83d9abfb41bd6bULL,
                           0x5be0cd19137e2179ULL, 0x1f83d9abfb41bd6bULL,
                           0x5be0cd19137e2179ULL, 0x1f83d9abfb41bd6bULL,
                           0x5be0cd19137e2179ULL, 0x1f83d9abfb41bd6bULL );

   for ( uint64_t i = 0; i < nBlocks; i++ )
   {
      const __m512i *in = (const __m512i*)In;

      st0 = _mm512_xor_si512( st0, in[0] );
      st1 = _mm512_xor_si512( st1, in[1] );
      st2 = _mm512_xor_si512( st2, in[2] );
      st3 = _mm512_xor_si512( st3, in[3] );

      LYRA_12_ROUNDS_4WAY_AVX512( st0, st1, st2, st3, st4, st5, st6, st7 );

      /* x4 for the four interleaved lanes. Lyra2RE passes block_len in BYTES
       * while this is a word stride, so with nCols=8 the second block lands in
       * zeroed matrix rather than on the basil. The scalar and AVX-512 2-way
       * paths both do this, so it is CONSENSUS and must not be "fixed" here. */
      In += block_len * 4;
   }
   STORE_ST( State );
}

static inline void absorb_block_4w( uint64_t *State, const uint64_t *In0,
                                    const uint64_t *In1, const uint64_t *In2,
                                    const uint64_t *In3 )
{
   LOAD_ST( State );
   const __m512i *i0 = (const __m512i*)In0;
   const __m512i *i1 = (const __m512i*)In1;
   const __m512i *i2 = (const __m512i*)In2;
   const __m512i *i3 = (const __m512i*)In3;

   st0 = _mm512_xor_si512( st0, gather_io( i0    , i1    , i2    , i3     ) );
   st1 = _mm512_xor_si512( st1, gather_io( i0 + 1, i1 + 1, i2 + 1, i3 + 1 ) );
   st2 = _mm512_xor_si512( st2, gather_io( i0 + 2, i1 + 2, i2 + 2, i3 + 2 ) );
   st3 = _mm512_xor_si512( st3, gather_io( i0 + 3, i1 + 3, i2 + 3, i3 + 3 ) );
   st4 = _mm512_xor_si512( st4, gather_io( i0 + 4, i1 + 4, i2 + 4, i3 + 4 ) );
   st5 = _mm512_xor_si512( st5, gather_io( i0 + 5, i1 + 5, i2 + 5, i3 + 5 ) );

   LYRA_12_ROUNDS_4WAY_AVX512( st0, st1, st2, st3, st4, st5, st6, st7 );

   STORE_ST( State );
}

// --------------------------------------------------------------- squeezes

static inline void squeeze_4w( uint64_t *State, unsigned char *Out,
                               unsigned int len )
{
   /* len is per lane; a 512-bit unit carries 128 bits of each of 4 lanes. */
   const int units      = len / 16;
   const int fullBlocks = units / BLK_4W;
   __m512i *state = (__m512i*)State;
   __m512i *out   = (__m512i*)Out;

   for ( int i = 0; i < fullBlocks; i++ )
   {
      for ( int j = 0; j < BLK_4W; j++ ) out[j] = state[j];
      LYRA_ROUND_4WAY_AVX512( state[0], state[1], state[2], state[3],
                              state[4], state[5], state[6], state[7] );
      out += BLK_4W;
   }
   for ( int j = 0; j < units % BLK_4W; j++ ) out[j] = state[j];
}

static inline void reduced_squeeze_row0_4w( uint64_t *State, uint64_t *rowOut,
                                            uint64_t nCols )
{
   LOAD_ST( State );
   __m512i *out = (__m512i*)rowOut + ( ( nCols - 1 ) * BLK_4W );

   for ( uint64_t i = 0; i < nCols; i++ )
   {
      out[0] = st0;
      out[1] = st1;
      out[2] = st2;
      out[3] = st3;
      out[4] = st4;
      out[5] = st5;

      out -= BLK_4W;            // fills columns back to front

      LYRA_ROUND_4WAY_AVX512( st0, st1, st2, st3, st4, st5, st6, st7 );
   }
   STORE_ST( State );
}

// --------------------------------------------------------------- duplexes

static inline void reduced_duplex_row1_4w( uint64_t *State, uint64_t *rowIn,
                                           uint64_t *rowOut, uint64_t nCols )
{
   LOAD_ST( State );
   const __m512i *in = (const __m512i*)rowIn;
   __m512i *out = (__m512i*)rowOut + ( ( nCols - 1 ) * BLK_4W );

   for ( uint64_t i = 0; i < nCols; i++ )
   {
      st0 = _mm512_xor_si512( st0, in[0] );
      st1 = _mm512_xor_si512( st1, in[1] );
      st2 = _mm512_xor_si512( st2, in[2] );
      st3 = _mm512_xor_si512( st3, in[3] );
      st4 = _mm512_xor_si512( st4, in[4] );
      st5 = _mm512_xor_si512( st5, in[5] );

      LYRA_ROUND_4WAY_AVX512( st0, st1, st2, st3, st4, st5, st6, st7 );

      out[0] = _mm512_xor_si512( st0, in[0] );
      out[1] = _mm512_xor_si512( st1, in[1] );
      out[2] = _mm512_xor_si512( st2, in[2] );
      out[3] = _mm512_xor_si512( st3, in[3] );
      out[4] = _mm512_xor_si512( st4, in[4] );
      out[5] = _mm512_xor_si512( st5, in[5] );

      in  += BLK_4W;
      out -= BLK_4W;
   }
   STORE_ST( State );
}

/* Setup phase: rowa is deterministic and therefore the SAME for all four lanes,
 * so there is a single rowInOut and no gather -- full-width loads are correct
 * here. rowInOut may alias rowOut, so the inout read-modify-write must stay
 * after the out store, exactly as the scalar path orders it. That ordering is
 * consensus. */
static inline void reduced_duplex_row_setup_4w( uint64_t *State,
                       uint64_t *rowIn, uint64_t *rowInOut, uint64_t *rowOut,
                       uint64_t nCols )
{
   LOAD_ST( State );
   const __m512i *in = (const __m512i*)rowIn;
   __m512i *inout    = (__m512i*)rowInOut;
   __m512i *out      = (__m512i*)rowOut + ( ( nCols - 1 ) * BLK_4W );

   for ( uint64_t i = 0; i < nCols; i++ )
   {
      st0 = _mm512_xor_si512( st0, _mm512_add_epi64( in[0], inout[0] ) );
      st1 = _mm512_xor_si512( st1, _mm512_add_epi64( in[1], inout[1] ) );
      st2 = _mm512_xor_si512( st2, _mm512_add_epi64( in[2], inout[2] ) );
      st3 = _mm512_xor_si512( st3, _mm512_add_epi64( in[3], inout[3] ) );
      st4 = _mm512_xor_si512( st4, _mm512_add_epi64( in[4], inout[4] ) );
      st5 = _mm512_xor_si512( st5, _mm512_add_epi64( in[5], inout[5] ) );

      LYRA_ROUND_4WAY_AVX512( st0, st1, st2, st3, st4, st5, st6, st7 );

      out[0] = _mm512_xor_si512( st0, in[0] );
      out[1] = _mm512_xor_si512( st1, in[1] );
      out[2] = _mm512_xor_si512( st2, in[2] );
      out[3] = _mm512_xor_si512( st3, in[3] );
      out[4] = _mm512_xor_si512( st4, in[4] );
      out[5] = _mm512_xor_si512( st5, in[5] );

      /* M[row*][col] ^= rotW(rand): a one-word rotation across the block,
       * which alignr does inside each 128-bit lane. */
      inout[0] = _mm512_xor_si512( inout[0], ALR_4W( st0, st5 ) );
      inout[1] = _mm512_xor_si512( inout[1], ALR_4W( st1, st0 ) );
      inout[2] = _mm512_xor_si512( inout[2], ALR_4W( st2, st1 ) );
      inout[3] = _mm512_xor_si512( inout[3], ALR_4W( st3, st2 ) );
      inout[4] = _mm512_xor_si512( inout[4], ALR_4W( st4, st3 ) );
      inout[5] = _mm512_xor_si512( inout[5], ALR_4W( st5, st4 ) );

      in    += BLK_4W;
      inout += BLK_4W;
      out   -= BLK_4W;
   }
   STORE_ST( State );
}

/* Wandering phase. Each lane picks its own rowa, so inout is gathered from four
 * rows and scattered back to all four. Two variants, as in the 2-way:
 *
 *   _cached  no inout row is rowOut, so the gathered value stays valid across
 *            the out store.
 *   _reread  at least one inout row IS rowOut. The scalar path reads inout from
 *            memory AFTER storing out, so when they alias it sees the updated
 *            bytes. Re-gathering after the store reproduces that; keeping the
 *            cached copy would not.
 */
static inline void reduced_duplex_row_4w_cached( uint64_t *State,
                     uint64_t *rowIn, uint64_t *rowInOut0, uint64_t *rowInOut1,
                     uint64_t *rowInOut2, uint64_t *rowInOut3,
                     uint64_t *rowOut, uint64_t nCols )
{
   LOAD_ST( State );
   const __m512i *in = (const __m512i*)rowIn;
   __m512i *io0 = (__m512i*)rowInOut0;
   __m512i *io1 = (__m512i*)rowInOut1;
   __m512i *io2 = (__m512i*)rowInOut2;
   __m512i *io3 = (__m512i*)rowInOut3;
   __m512i *out = (__m512i*)rowOut;

   for ( uint64_t i = 0; i < nCols; i++ )
   {
      __m512i v0 = gather_io( io0    , io1    , io2    , io3     );
      __m512i v1 = gather_io( io0 + 1, io1 + 1, io2 + 1, io3 + 1 );
      __m512i v2 = gather_io( io0 + 2, io1 + 2, io2 + 2, io3 + 2 );
      __m512i v3 = gather_io( io0 + 3, io1 + 3, io2 + 3, io3 + 3 );
      __m512i v4 = gather_io( io0 + 4, io1 + 4, io2 + 4, io3 + 4 );
      __m512i v5 = gather_io( io0 + 5, io1 + 5, io2 + 5, io3 + 5 );

      st0 = _mm512_xor_si512( st0, _mm512_add_epi64( in[0], v0 ) );
      st1 = _mm512_xor_si512( st1, _mm512_add_epi64( in[1], v1 ) );
      st2 = _mm512_xor_si512( st2, _mm512_add_epi64( in[2], v2 ) );
      st3 = _mm512_xor_si512( st3, _mm512_add_epi64( in[3], v3 ) );
      st4 = _mm512_xor_si512( st4, _mm512_add_epi64( in[4], v4 ) );
      st5 = _mm512_xor_si512( st5, _mm512_add_epi64( in[5], v5 ) );

      LYRA_ROUND_4WAY_AVX512( st0, st1, st2, st3, st4, st5, st6, st7 );

      out[0] = _mm512_xor_si512( out[0], st0 );
      out[1] = _mm512_xor_si512( out[1], st1 );
      out[2] = _mm512_xor_si512( out[2], st2 );
      out[3] = _mm512_xor_si512( out[3], st3 );
      out[4] = _mm512_xor_si512( out[4], st4 );
      out[5] = _mm512_xor_si512( out[5], st5 );

      v0 = _mm512_xor_si512( v0, ALR_4W( st0, st5 ) );
      v1 = _mm512_xor_si512( v1, ALR_4W( st1, st0 ) );
      v2 = _mm512_xor_si512( v2, ALR_4W( st2, st1 ) );
      v3 = _mm512_xor_si512( v3, ALR_4W( st3, st2 ) );
      v4 = _mm512_xor_si512( v4, ALR_4W( st4, st3 ) );
      v5 = _mm512_xor_si512( v5, ALR_4W( st5, st4 ) );

      scatter_io( v0, io0    , io1    , io2    , io3     );
      scatter_io( v1, io0 + 1, io1 + 1, io2 + 1, io3 + 1 );
      scatter_io( v2, io0 + 2, io1 + 2, io2 + 2, io3 + 2 );
      scatter_io( v3, io0 + 3, io1 + 3, io2 + 3, io3 + 3 );
      scatter_io( v4, io0 + 4, io1 + 4, io2 + 4, io3 + 4 );
      scatter_io( v5, io0 + 5, io1 + 5, io2 + 5, io3 + 5 );

      in  += BLK_4W;
      io0 += BLK_4W;
      io1 += BLK_4W;
      io2 += BLK_4W;
      io3 += BLK_4W;
      out += BLK_4W;
   }
   STORE_ST( State );
}

static inline void reduced_duplex_row_4w_reread( uint64_t *State,
                     uint64_t *rowIn, uint64_t *rowInOut0, uint64_t *rowInOut1,
                     uint64_t *rowInOut2, uint64_t *rowInOut3,
                     uint64_t *rowOut, uint64_t nCols )
{
   LOAD_ST( State );
   const __m512i *in = (const __m512i*)rowIn;
   __m512i *io0 = (__m512i*)rowInOut0;
   __m512i *io1 = (__m512i*)rowInOut1;
   __m512i *io2 = (__m512i*)rowInOut2;
   __m512i *io3 = (__m512i*)rowInOut3;
   __m512i *out = (__m512i*)rowOut;

   for ( uint64_t i = 0; i < nCols; i++ )
   {
      st0 = _mm512_xor_si512( st0, _mm512_add_epi64( in[0],
               gather_io( io0    , io1    , io2    , io3     ) ) );
      st1 = _mm512_xor_si512( st1, _mm512_add_epi64( in[1],
               gather_io( io0 + 1, io1 + 1, io2 + 1, io3 + 1 ) ) );
      st2 = _mm512_xor_si512( st2, _mm512_add_epi64( in[2],
               gather_io( io0 + 2, io1 + 2, io2 + 2, io3 + 2 ) ) );
      st3 = _mm512_xor_si512( st3, _mm512_add_epi64( in[3],
               gather_io( io0 + 3, io1 + 3, io2 + 3, io3 + 3 ) ) );
      st4 = _mm512_xor_si512( st4, _mm512_add_epi64( in[4],
               gather_io( io0 + 4, io1 + 4, io2 + 4, io3 + 4 ) ) );
      st5 = _mm512_xor_si512( st5, _mm512_add_epi64( in[5],
               gather_io( io0 + 5, io1 + 5, io2 + 5, io3 + 5 ) ) );

      LYRA_ROUND_4WAY_AVX512( st0, st1, st2, st3, st4, st5, st6, st7 );

      out[0] = _mm512_xor_si512( out[0], st0 );
      out[1] = _mm512_xor_si512( out[1], st1 );
      out[2] = _mm512_xor_si512( out[2], st2 );
      out[3] = _mm512_xor_si512( out[3], st3 );
      out[4] = _mm512_xor_si512( out[4], st4 );
      out[5] = _mm512_xor_si512( out[5], st5 );

      /* re-gather AFTER the out store: that is what aliasing demands */
      scatter_io( _mm512_xor_si512( gather_io( io0, io1, io2, io3 ),
                     ALR_4W( st0, st5 ) ), io0, io1, io2, io3 );
      scatter_io( _mm512_xor_si512( gather_io( io0 + 1, io1 + 1, io2 + 1,
                     io3 + 1 ), ALR_4W( st1, st0 ) ),
                  io0 + 1, io1 + 1, io2 + 1, io3 + 1 );
      scatter_io( _mm512_xor_si512( gather_io( io0 + 2, io1 + 2, io2 + 2,
                     io3 + 2 ), ALR_4W( st2, st1 ) ),
                  io0 + 2, io1 + 2, io2 + 2, io3 + 2 );
      scatter_io( _mm512_xor_si512( gather_io( io0 + 3, io1 + 3, io2 + 3,
                     io3 + 3 ), ALR_4W( st3, st2 ) ),
                  io0 + 3, io1 + 3, io2 + 3, io3 + 3 );
      scatter_io( _mm512_xor_si512( gather_io( io0 + 4, io1 + 4, io2 + 4,
                     io3 + 4 ), ALR_4W( st4, st3 ) ),
                  io0 + 4, io1 + 4, io2 + 4, io3 + 4 );
      scatter_io( _mm512_xor_si512( gather_io( io0 + 5, io1 + 5, io2 + 5,
                     io3 + 5 ), ALR_4W( st5, st4 ) ),
                  io0 + 5, io1 + 5, io2 + 5, io3 + 5 );

      in  += BLK_4W;
      io0 += BLK_4W;
      io1 += BLK_4W;
      io2 += BLK_4W;
      io3 += BLK_4W;
      out += BLK_4W;
   }
   STORE_ST( State );
}

static inline void reduced_duplex_row_4w( uint64_t *State, uint64_t *rowIn,
                     uint64_t *rowInOut0, uint64_t *rowInOut1,
                     uint64_t *rowInOut2, uint64_t *rowInOut3,
                     uint64_t *rowOut, uint64_t nCols )
{
   if ( ( rowInOut0 == rowOut ) || ( rowInOut1 == rowOut )
     || ( rowInOut2 == rowOut ) || ( rowInOut3 == rowOut ) )
      reduced_duplex_row_4w_reread( State, rowIn, rowInOut0, rowInOut1,
                                    rowInOut2, rowInOut3, rowOut, nCols );
   else
      reduced_duplex_row_4w_cached( State, rowIn, rowInOut0, rowInOut1,
                                    rowInOut2, rowInOut3, rowOut, nCols );
}

// ------------------------------------------------------------------ driver

int LYRA2RE_4WAY_AVX512( void *K, uint64_t kLen, const void *pwd,
                         const uint64_t pwdlen, const uint64_t timeCost,
                         const uint64_t nRows, const uint64_t nCols )
{
   uint64_t _ALIGN(64) state[64];        // 4 lanes x 16 words
   int64_t row = 2;
   int64_t prev = 1;
   int64_t rowa0 = 0, rowa1 = 0, rowa2 = 0, rowa3 = 0;
   int64_t tau, step = 1, window = 2, gap = 1, i;

   const int64_t ROW_LEN_INT64 = BLOCK_LEN_INT64 * nCols;
   const int64_t ROW_LEN_BYTES = ROW_LEN_INT64 * 8;
   const int64_t BLOCK_LEN = ( nCols == 4 ) ? BLOCK_LEN_BLAKE2_SAFE_INT64
                                            : BLOCK_LEN_BLAKE2_SAFE_BYTES;

   i = (int64_t)ROW_LEN_BYTES * nRows;
   uint64_t *wholeMatrix = mm_malloc( 4 * i, 64 );   // x4: all four lanes
   if ( wholeMatrix == NULL ) return -1;

   memset_zero_512( (__m512i*)wholeMatrix, ( 4 * i ) >> 6 );

   uint64_t *ptrWord = wholeMatrix;
   uint64_t *pw = (uint64_t*)pwd;

   int64_t nBlocksInput = ( ( pwdlen + pwdlen + 6 * sizeof(uint64_t) )
                              / BLOCK_LEN_BLAKE2_SAFE_BYTES ) + 1;

   uint64_t *ptr = wholeMatrix;

   /* pwd arrives already interleaved 4x128, so these are byte copies. */
   memcpy( ptr, pw, 4 * pwdlen );        // password, all four lanes
   ptr += pwdlen >> 1;
   memcpy( ptr, pw, 4 * pwdlen );        // salt is the password again
   ptr += pwdlen >> 1;

   /* Basil, interleaved on the fly. At 128-bit granularity each lane's word
    * pair occupies its own 128-bit slot, so within every 8-word unit the same
    * pair repeats four times at stride 2. */
   ptr[ 0] = ptr[ 2] = ptr[ 4] = ptr[ 6] = kLen;
   ptr[ 1] = ptr[ 3] = ptr[ 5] = ptr[ 7] = pwdlen;
   ptr[ 8] = ptr[10] = ptr[12] = ptr[14] = pwdlen;      // saltlen
   ptr[ 9] = ptr[11] = ptr[13] = ptr[15] = timeCost;
   ptr[16] = ptr[18] = ptr[20] = ptr[22] = nRows;
   ptr[17] = ptr[19] = ptr[21] = ptr[23] = nCols;
   ptr[24] = ptr[26] = ptr[28] = ptr[30] = 0x80;
   ptr[25] = ptr[27] = ptr[29] = ptr[31] = 0x0100000000000000;

   absorb_blake2safe_4w( state, ptrWord, nBlocksInput, BLOCK_LEN );

   reduced_squeeze_row0_4w( state, &wholeMatrix[0], nCols );

   reduced_duplex_row1_4w( state, &wholeMatrix[0],
                                  &wholeMatrix[ 4 * ROW_LEN_INT64 ], nCols );
   do
   {
      reduced_duplex_row_setup_4w( state,
                            &wholeMatrix[ 4 * prev  * ROW_LEN_INT64 ],
                            &wholeMatrix[ 4 * rowa0 * ROW_LEN_INT64 ],
                            &wholeMatrix[ 4 * row   * ROW_LEN_INT64 ], nCols );

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
         /* Each lane's own word 0. Register 0 holds
          * [L0w0,L0w1 | L1w0,L1w1 | L2w0,L2w1 | L3w0,L3w1], so lane i reads
          * state[2i] -- not state[4i] as it would at 256-bit granularity. */
         rowa0 = state[ 0 ] & (unsigned int)( nRows - 1 );
         rowa1 = state[ 2 ] & (unsigned int)( nRows - 1 );
         rowa2 = state[ 4 ] & (unsigned int)( nRows - 1 );
         rowa3 = state[ 6 ] & (unsigned int)( nRows - 1 );

         reduced_duplex_row_4w( state,
                          &wholeMatrix[ 4 * prev  * ROW_LEN_INT64 ],
                          &wholeMatrix[ 4 * rowa0 * ROW_LEN_INT64 ],
                          &wholeMatrix[ 4 * rowa1 * ROW_LEN_INT64 ],
                          &wholeMatrix[ 4 * rowa2 * ROW_LEN_INT64 ],
                          &wholeMatrix[ 4 * rowa3 * ROW_LEN_INT64 ],
                          &wholeMatrix[ 4 * row   * ROW_LEN_INT64 ], nCols );
         prev = row;
         row = ( row + step ) & (unsigned int)( nRows - 1 );

      } while ( row != 0 );
   }

   absorb_block_4w( state, &wholeMatrix[ 4 * rowa0 * ROW_LEN_INT64 ],
                           &wholeMatrix[ 4 * rowa1 * ROW_LEN_INT64 ],
                           &wholeMatrix[ 4 * rowa2 * ROW_LEN_INT64 ],
                           &wholeMatrix[ 4 * rowa3 * ROW_LEN_INT64 ] );
   squeeze_4w( state, K, (unsigned int)kLen );

   mm_free( wholeMatrix );

   return 0;
}

#endif  // SIMD512
