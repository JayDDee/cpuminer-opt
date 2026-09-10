/*
 * sha256csm — Galleoncoin (GALE).
 *
 *    hash = SHA-256( SHA-256( header80 || 32 zero bytes ) )
 *
 * Double SHA-256, except the first hash's message is the 80-byte header
 * zero-extended to 112 bytes. Standard IV, 256-bit digest, nonce at W[3],
 * opt_target_factor 1.0. Same cost as sha256d: 112 bytes still spans two
 * blocks and the first is nonce-independent, so the midstate carries over.
 *
 * Versus sha256d, only three words of the second block change:
 * [4] 0x80000000 -> 0, [12] 0 -> 0x80000000, [15] 0x280 -> 0x380.
 *
 * Do NOT reuse the family's prehash_3rounds/final_rounds here. They are
 * specialised on W[12] == 0 -- true for sha256d and sha256dt, and exactly
 * what csm changes -- so they drop schedule terms that are non-zero for csm.
 * It fails silently: wrong digests, no compile error. Every path below uses
 * the generic transform_le instead.
 */

#include "algo-gate-api.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "sha256-hash.h"

// SHA256CSM_FORCE_SCALAR: test hook, exercises the scalar path on x86-64
// where __SSE2__ is baseline and the #else below is otherwise dead.
#if defined(SHA256CSM_FORCE_SCALAR)
  #define SHA256CSM_PATH  "scalar reference (forced)"
#elif defined(SIMD512)
  #define SHA256CSM_16X32 1
  #define SHA256CSM_PATH  "16x32 AVX-512"
#elif defined(__x86_64__) && defined(__SHA__)
  #define SHA256CSM_X86_SHA256 1
  #define SHA256CSM_PATH  "2-way x86 SHA-NI"
#elif defined(__ARM_NEON) && defined(__ARM_FEATURE_SHA2)
  #define SHA256CSM_NEON_SHA256 1
  #define SHA256CSM_PATH  "2-way NEON SHA2"
#elif defined(__AVX2__)
  #define SHA256CSM_8X32 1
  #define SHA256CSM_PATH  "8x32 AVX2"
#elif defined(__SSE2__) || defined(__ARM_NEON)
  #define SHA256CSM_4X32 1
  #define SHA256CSM_PATH  "4x32 SSE2/NEON"
#else
  #define SHA256CSM_PATH  "scalar reference"
#endif

static const uint32_t sha256csm_iv[8] __attribute__ ((aligned (32))) =
{
   0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
   0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

#define CSM_MSG1_BITS   (112*8)     // 0x380, the zero-extended header
#define CSM_MSG2_BITS   ( 32*8)     // 0x100, the intermediate digest

// Byte-oriented reference. Always compiled; the KAT and every width's
// differential are anchored on it.
void sha256csm_hash( void *output, const void *input )
{
   unsigned char _ALIGN(64) msg[112];
   uint32_t      _ALIGN(32) digest[8];

   memset( msg, 0, sizeof msg );
   memcpy( msg, input, 80 );

   sha256_full( digest, msg, 112 );
   sha256_full( output, digest, 32 );
}

// The scanhash block layout, one scalar nonce. Output words are in W order
// (big-endian numeric), matching sha256_transform_le.
static inline void sha256csm_hash_block( uint32_t *hash32,
                                         const uint32_t *mstate,
                                         const uint32_t *pdata, uint32_t nonce )
{
   uint32_t _ALIGN(64) block1[16];
   uint32_t _ALIGN(64) block2[16];

   block1[ 0] = pdata[16];
   block1[ 1] = pdata[17];
   block1[ 2] = pdata[18];
   block1[ 3] = nonce;
   memset( block1 + 4, 0, 32 );        // words 4..11, where sha256d pads
   block1[12] = 0x80000000;            // csm's padding bit
   block1[13] = 0;
   block1[14] = 0;
   block1[15] = CSM_MSG1_BITS;

   sha256_transform_le( block2, block1, mstate );

   block2[ 8] = 0x80000000;
   memset( block2 + 9, 0, 24 );
   block2[15] = CSM_MSG2_BITS;

   sha256_transform_le( hash32, block2, sha256csm_iv );
}

// ---------------------------------------------------------------------------
// Validation

static void sha256csm_log_mismatch( const char *what, const uint8_t *got,
                                    const uint8_t *expected )
{
   char g[65], e[65];
   for ( int i = 0; i < 32; i++ )
   {
      sprintf( g + i*2, "%02x", got[i] );
      sprintf( e + i*2, "%02x", expected[i] );
   }
   applog( LOG_ERR, "sha256csm %s FAILED (KAT mismatch)", what );
   applog( LOG_ERR, "  got:      %s", g );
   applog( LOG_ERR, "  expected: %s", e );
}

// Reference-derived vectors, not chain-derived: GALE is PIVX-based, so a
// block id is sha256d of the header and is not the PoW hash.
static const uint8_t sha256csm_kat0_input[80] =
{
   0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
   0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
   0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,
   0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f,
   0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f
};
static const uint8_t sha256csm_kat0_expected[32] =
{
   0x35,0xb2,0x28,0x6c,0x70,0x35,0x2d,0xb4,0x61,0xa3,0xc5,0x27,0x94,0x9c,0xa0,0xdb,
   0x70,0xdd,0xd7,0x3a,0xeb,0x07,0x01,0x08,0x72,0x00,0x00,0x47,0x51,0xc2,0x71,0x36
};

static const uint8_t sha256csm_kat1_input[80] = { 0 };
static const uint8_t sha256csm_kat1_expected[32] =
{
   0x7b,0x55,0x96,0x88,0xe6,0x6e,0xa7,0x8c,0x64,0xf5,0x08,0xe2,0xa6,0xcd,0x9c,0x3e,
   0xa6,0xbf,0x3b,0x06,0x94,0x8c,0x31,0x4b,0x55,0x8e,0x44,0x4f,0x7d,0x73,0x9d,0x78
};

// Anchors the byte-oriented reference. The 112-byte length is the whole
// algorithm, so a build that quietly hashed 80 bytes fails here.
bool sha256csm_kat_check( void )
{
   uint8_t hash[32];

   sha256csm_hash( hash, sha256csm_kat0_input );
   if ( memcmp( hash, sha256csm_kat0_expected, 32 ) != 0 )
   {
      sha256csm_log_mismatch( "counting header", hash,
                              sha256csm_kat0_expected );
      return false;
   }

   sha256csm_hash( hash, sha256csm_kat1_input );
   if ( memcmp( hash, sha256csm_kat1_expected, 32 ) != 0 )
   {
      sha256csm_log_mismatch( "zero header", hash, sha256csm_kat1_expected );
      return false;
   }
   return true;
}

// Catches a wrong padding word or bit count; the KAT above cannot, since it
// never touches the W-order block construction.
#define CSM_SELFTEST_LANES  16

static bool sha256csm_block_check( void )
{
   uint32_t _ALIGN(64) pdata[20];
   uint32_t _ALIGN(64) mstate[8];
   uint32_t _ALIGN(64) hash32[8];
   uint8_t  _ALIGN(64) header[80];
   uint8_t  _ALIGN(64) got[32], expected[32];

   // arbitrary but fixed W-order header; nonce word is overwritten per lane
   for ( int i = 0; i < 20; i++ )
      pdata[i] = 0x0f0e0d0cu * (uint32_t)( i + 1 ) ^ 0xa5a5a5a5u;

   sha256_transform_le( mstate, pdata, sha256csm_iv );

   for ( int lane = 0; lane < CSM_SELFTEST_LANES; lane++ )
   {
      const uint32_t nonce = 0x1234abcdu + (uint32_t)lane;

      pdata[19] = nonce;
      for ( int i = 0; i < 20; i++ )
         be32enc( (uint32_t*)header + i, pdata[i] );
      sha256csm_hash( expected, header );

      sha256csm_hash_block( hash32, mstate, pdata, nonce );
      for ( int i = 0; i < 8; i++ )
         be32enc( (uint32_t*)got + i, hash32[i] );

      if ( memcmp( got, expected, 32 ) != 0 )
      {
         sha256csm_log_mismatch( "scanhash block layout", got, expected );
         return false;
      }
   }
   return true;
}

// Each scanhash re-declares the same padding at its own width, so a typo in
// one vector path's buf[12] would only surface as pool rejects. Replicate the
// compiled path's block setup and diff every lane against the scalar.
static bool sha256csm_vector_check( void )
{
// Scalar scanhash calls sha256csm_hash_block directly, already anchored above.
#if !defined(SHA256CSM_FORCE_SCALAR)

   uint32_t _ALIGN(64) pdata[20];
   uint32_t _ALIGN(64) mstate[8];
   uint32_t _ALIGN(64) ref[8];
   uint8_t  _ALIGN(64) got[32], expected[32];
   const uint32_t n = 0x7f00beefu;
   int lanes = 0;

   for ( int i = 0; i < 20; i++ )
      pdata[i] = 0x1b2d3f41u * (uint32_t)( i + 3 ) ^ 0x5c5c5c5cu;

   sha256_transform_le( mstate, pdata, sha256csm_iv );

#if defined(SHA256CSM_16X32) || defined(SHA256CSM_8X32) \
 || defined(SHA256CSM_4X32)

   uint32_t _ALIGN(64) lane_hash[8];

  #if defined(SHA256CSM_16X32)
   #define CSM_VEC_T       __m512i
   #define csm_vec_bcast   v512_32
   #define csm_vec_zero    memset_zero_512
   #define csm_vec_xform   sha256_16x32_transform_le
   #define csm_vec_prehash sha256csm_16x32_prehash_3rounds
   #define csm_vec_final   sha256csm_16x32_final_rounds
   #define csm_vec_extr    extr_lane_16x32
   lanes = 16;
   __m512i noncev = _mm512_set_epi32( n+15, n+14, n+13, n+12, n+11, n+10,
                                      n+ 9, n+ 8, n+ 7, n+ 6, n+ 5, n+ 4,
                                      n+ 3, n+ 2, n+ 1, n );
  #elif defined(SHA256CSM_8X32)
   #define CSM_VEC_T       __m256i
   #define csm_vec_bcast   v256_32
   #define csm_vec_zero    memset_zero_256
   #define csm_vec_xform   sha256_8x32_transform_le
   #define csm_vec_prehash sha256csm_8x32_prehash_3rounds
   #define csm_vec_final   sha256csm_8x32_final_rounds
   #define csm_vec_extr    extr_lane_8x32
   lanes = 8;
   __m256i noncev = _mm256_set_epi32( n+7, n+6, n+5, n+4, n+3, n+2, n+1, n );
  #else
   #define CSM_VEC_T       v128_t
   #define csm_vec_bcast   v128_32
   #define csm_vec_zero    v128_memset_zero
   #define csm_vec_xform   sha256_4x32_transform_le
   #define csm_vec_prehash sha256csm_4x32_prehash_3rounds
   #define csm_vec_final   sha256csm_4x32_final_rounds
   #define csm_vec_extr    extr_lane_4x32
   lanes = 4;
   v128_t noncev = v128_set32( n+3, n+2, n+1, n );
  #endif

   CSM_VEC_T buf[16]    __attribute__ ((aligned (128)));
   CSM_VEC_T block[16]  __attribute__ ((aligned (128)));
   CSM_VEC_T hash32[8]  __attribute__ ((aligned (128)));
   CSM_VEC_T vmstate[8] __attribute__ ((aligned (128)));
   CSM_VEC_T istate[8]  __attribute__ ((aligned (128)));

   for ( int i = 0; i < 8; i++ )
   {
      vmstate[i] = csm_vec_bcast( mstate[i] );
      istate[i]  = csm_vec_bcast( sha256csm_iv[i] );
   }

   buf[0] = csm_vec_bcast( pdata[16] );
   buf[1] = csm_vec_bcast( pdata[17] );
   buf[2] = csm_vec_bcast( pdata[18] );
   buf[3] = noncev;
   csm_vec_zero( buf+4, 8 );
   buf[12] = csm_vec_bcast( 0x80000000 );
   csm_vec_zero( buf+13, 2 );
   buf[15] = csm_vec_bcast( CSM_MSG1_BITS );

   block[ 8] = csm_vec_bcast( 0x80000000 );
   csm_vec_zero( block+9, 6 );
   block[15] = csm_vec_bcast( CSM_MSG2_BITS );

   // Mirror whatever the compiled scanhash does, or this proves nothing.
   // All three SIMD widths now use the csm-specific prehash + final_rounds.
   CSM_VEC_T mstate2[8]  __attribute__ ((aligned (128)));
   CSM_VEC_T mexp_pre[8] __attribute__ ((aligned (128)));
   csm_vec_prehash( mstate2, mexp_pre, buf, vmstate );
   csm_vec_final( block, buf, vmstate, mstate2, mexp_pre );
   csm_vec_xform( hash32, block, istate );

  #if defined(SHA256CSM_4X32)
   // The 4x32 scanhash gates on sha256_4x32_transform_le_short, whose early
   // abort fails silently: a wrong "no lane can win" produces no digest at
   // all, so no digest comparison can see it. Assert both verdicts.
   {
      uint32_t permissive[8], impossible[8];
      CSM_VEC_T probe[8] __attribute__ ((aligned (128)));

      memset( permissive,  0xff, sizeof permissive  );
      memset( impossible,  0x00, sizeof impossible  );

      if ( !sha256_4x32_transform_le_short( probe, block, istate, permissive ) )
      {
         applog( LOG_ERR, "sha256csm short transform aborted on a target "
                          "no lane can lose to" );
         return false;
      }
      if ( memcmp( probe, hash32, 8 * sizeof(CSM_VEC_T) ) != 0 )
      {
         applog( LOG_ERR, "sha256csm short transform digest differs from the "
                          "full transform" );
         return false;
      }
      if ( sha256_4x32_transform_le_short( probe, block, istate, impossible ) )
      {
         applog( LOG_ERR, "sha256csm short transform completed on a target "
                          "no lane can win" );
         return false;
      }
   }
  #endif

   for ( int lane = 0; lane < lanes; lane++ )
   {
      csm_vec_extr( lane_hash, hash32, lane, 256 );
      sha256csm_hash_block( ref, mstate, pdata, n + (uint32_t)lane );
      for ( int i = 0; i < 8; i++ )
      {
         be32enc( (uint32_t*)got + i, lane_hash[i] );
         be32enc( (uint32_t*)expected + i, ref[i] );
      }
      if ( memcmp( got, expected, 32 ) != 0 )
      {
         sha256csm_log_mismatch( SHA256CSM_PATH " lane", got, expected );
         return false;
      }
   }

   #undef CSM_VEC_T
   #undef csm_vec_bcast
   #undef csm_vec_zero
   #undef csm_vec_xform
   #undef csm_vec_prehash
   #undef csm_vec_final
   #undef csm_vec_extr

#elif defined(SHA256CSM_X86_SHA256) || defined(SHA256CSM_NEON_SHA256)

   uint32_t _ALIGN(64) block1a[16], block1b[16];
   uint32_t _ALIGN(64) block2a[16], block2b[16];
   uint32_t _ALIGN(64) hasha[8], hashb[8];

   lanes = 2;

   memcpy( block1a, pdata + 16, 12 );
   memcpy( block1b, pdata + 16, 12 );
   block1a[ 3] = n;
   block1b[ 3] = n+1;
   memset( block1a + 4, 0, 32 );
   memset( block1b + 4, 0, 32 );
   block1a[12] = block1b[12] = 0x80000000;
   block1a[13] = block1b[13] = 0;
   block1a[14] = block1b[14] = 0;
   block1a[15] = block1b[15] = CSM_MSG1_BITS;

   block2a[ 8] = block2b[ 8] = 0x80000000;
   memset( block2a + 9, 0, 24 );
   memset( block2b + 9, 0, 24 );
   block2a[15] = block2b[15] = CSM_MSG2_BITS;

   sha256_2x_transform_le( block2a, block2b, block1a, block1b,
                           mstate, mstate );
   sha256_2x_transform_le( hasha, hashb, block2a, block2b,
                           sha256csm_iv, sha256csm_iv );

   for ( int lane = 0; lane < 2; lane++ )
   {
      const uint32_t *h = lane ? hashb : hasha;
      sha256csm_hash_block( ref, mstate, pdata, n + (uint32_t)lane );
      for ( int i = 0; i < 8; i++ )
      {
         be32enc( (uint32_t*)got + i, h[i] );
         be32enc( (uint32_t*)expected + i, ref[i] );
      }
      if ( memcmp( got, expected, 32 ) != 0 )
      {
         sha256csm_log_mismatch( SHA256CSM_PATH " lane", got, expected );
         return false;
      }
   }

#endif

   (void)lanes;
#endif   // !SHA256CSM_FORCE_SCALAR
   return true;
}

bool sha256csm_self_test( void )
{
   if ( !sha256csm_kat_check() )    return false;
   if ( !sha256csm_block_check() )  return false;
   if ( !sha256csm_vector_check() ) return false;
   applog( LOG_NOTICE, "sha256csm self-test PASSED [%s] "
                       "(reference KAT + %d-nonce block layout + lane diff)",
                       SHA256CSM_PATH, CSM_SELFTEST_LANES );
   return true;
}

// ---------------------------------------------------------------------------

#if defined(SHA256CSM_X86_SHA256)

int scanhash_sha256csm_x86_x2sha( struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t block1a[16] __attribute__ ((aligned (64)));
   uint32_t block1b[16] __attribute__ ((aligned (64)));
   uint32_t block2a[16] __attribute__ ((aligned (64)));
   uint32_t block2b[16] __attribute__ ((aligned (64)));
   uint32_t hasha[8]    __attribute__ ((aligned (32)));
   uint32_t hashb[8]    __attribute__ ((aligned (32)));
   uint32_t mstate[8]   __attribute__ ((aligned (32)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 2;
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;
   const bool bench = opt_benchmark;

   // hash first 64 byte block of data
   sha256_transform_le( mstate, pdata, sha256csm_iv );

   // fill & pad second block without nonce
   memcpy( block1a, pdata + 16, 12 );
   memcpy( block1b, pdata + 16, 12 );
   block1a[ 3] = block1b[ 3] = 0;
   memset( block1a + 4, 0, 32 );
   memset( block1b + 4, 0, 32 );
   block1a[12] = block1b[12] = 0x80000000;
   block1a[13] = block1b[13] = 0;
   block1a[14] = block1b[14] = 0;
   block1a[15] = block1b[15] = CSM_MSG1_BITS;

   // Pad third block
   block2a[ 8] = block2b[ 8] = 0x80000000;
   memset( block2a + 9, 0, 24 );
   memset( block2b + 9, 0, 24 );
   block2a[15] = block2b[15] = CSM_MSG2_BITS;

   do
   {
      // Insert nonce for second block
      block1a[3] = n;
      block1b[3] = n+1;
      sha256_2x_transform_le( block2a, block2b, block1a, block1b,
                                  mstate, mstate );

      sha256_2x_transform_le( hasha, hashb, block2a, block2b,
                                  sha256csm_iv, sha256csm_iv );

      if ( unlikely( bswap_32( hasha[7] ) <= ptarget[7] ) )
      {
          casti_v128( hasha, 0 ) = v128_bswap32( casti_v128( hasha, 0 ) );
          casti_v128( hasha, 1 ) = v128_bswap32( casti_v128( hasha, 1 ) );
          if ( likely( valid_hash( hasha, ptarget ) && !bench ) )
          {
             pdata[19] = n;
             submit_solution( work, hasha, mythr );
          }
      }
      if ( unlikely( bswap_32( hashb[7] ) <= ptarget[7] ) )
      {
         casti_v128( hashb, 0 ) = v128_bswap32( casti_v128( hashb, 0 ) );
         casti_v128( hashb, 1 ) = v128_bswap32( casti_v128( hashb, 1 ) );
         if ( likely( valid_hash( hashb, ptarget ) && !bench ) )
         {
            pdata[19] = n+1;
            submit_solution( work, hashb, mythr );
         }
      }
      n += 2;
   } while ( (n < last_nonce) && !work_restart[thr_id].restart );

   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

#elif defined(SHA256CSM_NEON_SHA256)

int scanhash_sha256csm_neon_x2sha( struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t block1a[16] __attribute__ ((aligned (64)));
   uint32_t block1b[16] __attribute__ ((aligned (64)));
   uint32_t block2a[16] __attribute__ ((aligned (64)));
   uint32_t block2b[16] __attribute__ ((aligned (64)));
   uint32_t hasha[8]    __attribute__ ((aligned (32)));
   uint32_t hashb[8]    __attribute__ ((aligned (32)));
   uint32_t mstate[8]   __attribute__ ((aligned (32)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 2;
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;
   const bool bench = opt_benchmark;

   sha256_neon_sha_transform_le( mstate, pdata, sha256csm_iv );

   memcpy( block1a, pdata + 16, 12 );
   memcpy( block1b, pdata + 16, 12 );
   block1a[ 3] = block1b[ 3] = 0;
   memset( block1a + 4, 0, 32 );
   memset( block1b + 4, 0, 32 );
   block1a[12] = block1b[12] = 0x80000000;
   block1a[13] = block1b[13] = 0;
   block1a[14] = block1b[14] = 0;
   block1a[15] = block1b[15] = CSM_MSG1_BITS;

   block2a[ 8] = block2b[ 8] = 0x80000000;
   memset( block2a + 9, 0, 24 );
   memset( block2b + 9, 0, 24 );
   block2a[15] = block2b[15] = CSM_MSG2_BITS;

   do
   {
      block1a[3] = n;
      block1b[3] = n+1;
      sha256_neon_x2sha_transform_le( block2a, block2b, block1a, block1b,
                                  mstate, mstate );

      sha256_neon_x2sha_transform_le( hasha, hashb, block2a, block2b,
                                  sha256csm_iv, sha256csm_iv );

      if ( unlikely( bswap_32( hasha[7] ) <= ptarget[7] ) )
      {
          casti_v128( hasha, 0 ) = v128_bswap32( casti_v128( hasha, 0 ) );
          casti_v128( hasha, 1 ) = v128_bswap32( casti_v128( hasha, 1 ) );
          if ( likely( valid_hash( hasha, ptarget ) && !bench ) )
          {
             pdata[19] = n;
             submit_solution( work, hasha, mythr );
          }
      }
      if ( unlikely( bswap_32( hashb[7] ) <= ptarget[7] ) )
      {
         casti_v128( hashb, 0 ) = v128_bswap32( casti_v128( hashb, 0 ) );
         casti_v128( hashb, 1 ) = v128_bswap32( casti_v128( hashb, 1 ) );
         if ( likely( valid_hash( hashb, ptarget ) && !bench ) )
         {
            pdata[19] = n+1;
            submit_solution( work, hashb, mythr );
         }
      }
      n += 2;
   } while ( (n < last_nonce) && !work_restart[thr_id].restart );

   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

#elif defined(SHA256CSM_16X32)

int scanhash_sha256csm_16x32( struct work *work, const uint32_t max_nonce,
                           uint64_t *hashes_done, struct thr_info *mythr )
{
   __m512i  block[16]    __attribute__ ((aligned (128)));
   __m512i  buf[16]      __attribute__ ((aligned (64)));
   __m512i  hash32[8]    __attribute__ ((aligned (64)));
   __m512i  mstate[8]    __attribute__ ((aligned (64)));
   __m512i  mstate2[8]   __attribute__ ((aligned (64)));
   __m512i  mexp_pre[8]  __attribute__ ((aligned (64)));
   __m512i  istate[8]    __attribute__ ((aligned (64)));
   uint32_t phash[8]     __attribute__ ((aligned (32)));
   uint32_t *pdata = work->data;
   const uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 16;
   const __m512i last_byte = v512_32( 0x80000000 );
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;
   const __m512i sixteen = v512_32( 16 );
   const bool bench = opt_benchmark;

   // prehash first block directly from pdata
   sha256_transform_le( phash, pdata, sha256csm_iv );

   for ( int i = 0; i < 8; i++ )
   {
      mstate[i] = v512_32( phash[i] );
      istate[i] = v512_32( sha256csm_iv[i] );
   }

   // second message block: data, nonce, then csm's padding at word 12
   buf[0] = v512_32( pdata[16] );
   buf[1] = v512_32( pdata[17] );
   buf[2] = v512_32( pdata[18] );
   buf[3] = _mm512_set_epi32( n+15, n+14, n+13, n+12, n+11, n+10, n+ 9, n+ 8,
                              n+ 7, n+ 6, n+ 5, n+ 4, n+ 3, n+ 2, n +1, n );
   memset_zero_512( buf+4, 8 );
   buf[12] = last_byte;
   memset_zero_512( buf+13, 2 );
   buf[15] = v512_32( CSM_MSG1_BITS );

   // padding for the second hash
   block[ 8] = last_byte;
   memset_zero_512( block+9, 6 );
   block[15] = v512_32( CSM_MSG2_BITS );

   // partially pre-expand & prehash the second message block, avoiding the
   // nonces. csm-specific: the shared helpers assume W[12] == 0.
   sha256csm_16x32_prehash_3rounds( mstate2, mexp_pre, buf, mstate );

   do
   {
      sha256csm_16x32_final_rounds( block, buf, mstate, mstate2, mexp_pre );
      if ( unlikely( sha256_16x32_transform_le_short(
                                  hash32, block, istate, ptarget ) ) )
      {
         for ( int lane = 0; lane < 16; lane++ )
         {
            extr_lane_16x32( phash, hash32, lane, 256 );
            casti_m256i( phash, 0 ) = mm256_bswap_32( casti_m256i( phash, 0 ) );
            if ( likely( valid_hash( phash, ptarget ) && !bench ) )
            {
              pdata[19] = n + lane;
              submit_solution( work, phash, mythr );
            }
         }
      }
      buf[3] = _mm512_add_epi32( buf[3], sixteen );
      n += 16;
   } while ( (n < last_nonce) && !work_restart[thr_id].restart );
   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

#elif defined(SHA256CSM_8X32)

int scanhash_sha256csm_8x32( struct work *work, const uint32_t max_nonce,
                           uint64_t *hashes_done, struct thr_info *mythr )
{
   __m256i  block[16]    __attribute__ ((aligned (64)));
   __m256i  buf[16]      __attribute__ ((aligned (32)));
   __m256i  hash32[8]    __attribute__ ((aligned (32)));
   __m256i  mstate[8]    __attribute__ ((aligned (32)));
   __m256i  mstate2[8]   __attribute__ ((aligned (32)));
   __m256i  mexp_pre[8]  __attribute__ ((aligned (32)));
   __m256i  istate[8]    __attribute__ ((aligned (32)));
   uint32_t phash[8]     __attribute__ ((aligned (32)));
   uint32_t *pdata = work->data;
   const uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 8;
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;
   const bool bench = opt_benchmark;
   const __m256i last_byte = v256_32( 0x80000000 );
   const __m256i eight = v256_32( 8 );

   sha256_transform_le( phash, pdata, sha256csm_iv );

   for ( int i = 0; i < 8; i++ )
   {
      mstate[i] = v256_32( phash[i] );
      istate[i] = v256_32( sha256csm_iv[i] );
   }

   buf[0] = v256_32( pdata[16] );
   buf[1] = v256_32( pdata[17] );
   buf[2] = v256_32( pdata[18] );
   buf[3] = _mm256_set_epi32( n+ 7, n+ 6, n+ 5, n+ 4, n+ 3, n+ 2, n+1, n );
   memset_zero_256( buf+4, 8 );
   buf[12] = last_byte;
   memset_zero_256( buf+13, 2 );
   buf[15] = v256_32( CSM_MSG1_BITS );

   block[ 8] = last_byte;
   memset_zero_256( block+9, 6 );
   block[15] = v256_32( CSM_MSG2_BITS );

   sha256csm_8x32_prehash_3rounds( mstate2, mexp_pre, buf, mstate );

   do
   {
      sha256csm_8x32_final_rounds( block, buf, mstate, mstate2, mexp_pre );
      if ( unlikely( sha256_8x32_transform_le_short( hash32, block,
                                                     istate, ptarget ) ) )
      {
         for ( int lane = 0; lane < 8; lane++ )
         {
            extr_lane_8x32( phash, hash32, lane, 256 );
            casti_m256i( phash, 0 ) = mm256_bswap_32( casti_m256i( phash, 0 ) );
            if ( likely( valid_hash( phash, ptarget ) && !bench ) )
            {
               pdata[19] = n + lane;
               submit_solution( work, phash, mythr );
            }
         }
      }
      buf[3] = _mm256_add_epi32( buf[3], eight );
      n += 8;
   } while ( (n < last_nonce) && !work_restart[thr_id].restart );
   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

#elif defined(SHA256CSM_4X32)

int scanhash_sha256csm_4x32( struct work *work, const uint32_t max_nonce,
                           uint64_t *hashes_done, struct thr_info *mythr )
{
   v128_t   block[16]    __attribute__ ((aligned (64)));
   v128_t   buf[16]      __attribute__ ((aligned (32)));
   v128_t   hash32[8]    __attribute__ ((aligned (32)));
   v128_t   mstate[8]    __attribute__ ((aligned (32)));
   v128_t   mstate2[8]   __attribute__ ((aligned (32)));
   v128_t   mexp_pre[8]  __attribute__ ((aligned (32)));
   v128_t   iv[8]        __attribute__ ((aligned (32)));
   uint32_t phash[8]     __attribute__ ((aligned (32)));
   uint32_t *hash32_d7 = (uint32_t*)&( hash32[7] );
   uint32_t *pdata = work->data;
   const uint32_t *ptarget = work->target;
   const uint32_t targ32_d7 = ptarget[7];
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 4;
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;
   const bool bench = opt_benchmark;
   const v128_t last_byte = v128_32( 0x80000000 );
   const v128_t four = v128_32( 4 );

   sha256_transform_le( phash, pdata, sha256csm_iv );

   for ( int i = 0; i < 8; i++ )
   {
      mstate[i] = v128_32( phash[i] );
      iv[i]     = v128_32( sha256csm_iv[i] );
   }

   buf[0] = v128_32( pdata[16] );
   buf[1] = v128_32( pdata[17] );
   buf[2] = v128_32( pdata[18] );
   buf[3] = v128_set32( n+3, n+2, n+1, n );
   v128_memset_zero( buf+4, 8 );
   buf[12] = last_byte;
   v128_memset_zero( buf+13, 2 );
   buf[15] = v128_32( CSM_MSG1_BITS );

   block[ 8] = last_byte;
   v128_memset_zero( block+9, 6 );
   block[15] = v128_32( CSM_MSG2_BITS );

   sha256csm_4x32_prehash_3rounds( mstate2, mexp_pre, buf, mstate );

   do
   {
      sha256csm_4x32_final_rounds( block, buf, mstate, mstate2, mexp_pre );
      if ( unlikely( sha256_4x32_transform_le_short( hash32, block, iv,
                                                     ptarget ) ) )
      for ( int lane = 0; lane < 4; lane++ )
      {
         if ( unlikely( bswap_32( hash32_d7[ lane ] ) <= targ32_d7 ) )
         {
            extr_lane_4x32( phash, hash32, lane, 256 );
            casti_v128( phash, 0 ) = v128_bswap32( casti_v128( phash, 0 ) );
            casti_v128( phash, 1 ) = v128_bswap32( casti_v128( phash, 1 ) );
            if ( likely( valid_hash( phash, ptarget ) && !bench ) )
            {
               pdata[19] = n + lane;
               submit_solution( work, phash, mythr );
            }
         }
      }
      buf[3] = v128_add32( buf[3], four );
      n += 4;
   } while ( (n < last_nonce) && !work_restart[thr_id].restart );
   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

#else

int scanhash_sha256csm_ref( struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t hash32[8]  __attribute__ ((aligned (32)));
   uint32_t mstate[8]  __attribute__ ((aligned (32)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 1;
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;
   const bool bench = opt_benchmark;

   // hash first 64 byte block of data
   sha256_transform_le( mstate, pdata, sha256csm_iv );

   do
   {
      sha256csm_hash_block( hash32, mstate, pdata, n );

      if ( unlikely( bswap_32( hash32[7] ) <= ptarget[7] ) )
      {
          casti_v128( hash32, 0 ) = v128_bswap32( casti_v128( hash32, 0 ) );
          casti_v128( hash32, 1 ) = v128_bswap32( casti_v128( hash32, 1 ) );
          if ( likely( valid_hash( hash32, ptarget ) && !bench ) )
          {
             pdata[19] = n;
             submit_solution( work, hash32, mythr );
          }
      }
      n += 1;
   } while ( (n < last_nonce) && !work_restart[thr_id].restart );

   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

#endif

bool register_sha256csm_algo( algo_gate_t* gate )
{
    if ( !sha256csm_self_test() ) return false;

    gate->optimizations = SSE2_OPT | AVX2_OPT | AVX512_OPT | NEON_OPT;
#if defined(SHA256CSM_16X32)
    gate->scanhash = (void*)&scanhash_sha256csm_16x32;
#elif defined(SHA256CSM_X86_SHA256)
    gate->optimizations = SSE2_OPT | SHA256_OPT;
    gate->scanhash = (void*)&scanhash_sha256csm_x86_x2sha;
#elif defined(SHA256CSM_NEON_SHA256)
    gate->optimizations = NEON_OPT | SHA256_OPT;
    gate->scanhash = (void*)&scanhash_sha256csm_neon_x2sha;
#elif defined(SHA256CSM_8X32)
    gate->scanhash = (void*)&scanhash_sha256csm_8x32;
#elif defined(SHA256CSM_4X32)
    gate->scanhash = (void*)&scanhash_sha256csm_4x32;
#else
    gate->scanhash = (void*)&scanhash_sha256csm_ref;
#endif
    return true;
}
