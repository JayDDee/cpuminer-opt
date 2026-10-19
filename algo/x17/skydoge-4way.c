#include "skydoge-gate.h"

#if defined(SKYDOGE_4WAY)

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "simd-utils.h"

// 4x64 cores for the lane-friendly hashes
#include "algo/blake/blake512-hash.h"
#include "algo/bmw/bmw-hash-4way.h"
#include "algo/skein/skein-hash-4way.h"
#include "algo/jh/jh-hash-4way.h"
#include "algo/keccak/keccak-hash-4way.h"
#include "algo/hamsi/hamsi-hash-4way.h"
#include "algo/sha/sha512-hash.h"
#include "algo/shabal/shabal-hash-4way.h"  // shabal512_4x32
#include "algo/sha/sha256-hash.h"          // sha256_4x32
#include "algo/haval/haval-hash-4way.h"    // haval256_4x32

// 2x128 cores for luffa/cubehash/shavite/simd (and, under VAES, groestl/echo)
#include "algo/luffa/luffa-hash-2way.h"
#include "algo/cubehash/cube-hash-2way.h"
#include "algo/shavite/shavite-hash-2way.h"
#include "algo/simd/simd-hash-2way.h"
#if defined(__VAES__)
  #include "algo/groestl/groestl512-hash-4way.h"
  #include "algo/echo/echo-hash-4way.h"
#endif

// scalar 1-way cores for the always-scalar tail (and non-VAES groestl/echo/group)
#include "algo/cubehash/cubehash_sse2.h"
#include "algo/shavite/sph_shavite.h"
#include "algo/shabal/sph_shabal.h"
#include "algo/whirlpool/sph_whirlpool.h"
#include "algo/sha/sph_sha2.h"
#include "algo/haval/sph-haval.h"
#if defined(__AES__) || defined(__ARM_FEATURE_AES)
  #include "algo/groestl/aes_ni/hash-groestl.h"
  #include "algo/echo/aes_ni/hash_api.h"
  #include "algo/fugue/fugue-aesni.h"
#else
  #include "algo/groestl/sph_groestl.h"
  #include "algo/echo/sph_echo.h"
  #include "algo/fugue/sph_fugue.h"
#endif

/*
 * SkyDoge 4-way (4x64), Phase 2b.2.
 *   - blake/skein/bmw/jh/keccak/hamsi/sha512 run 4-way (4x64);
 *   - luffa and the two simd stages run 2-way (2x128); groestl and the
 *     simd/echo/cubehash/shavite group run 2-way under VAES, else scalar;
 *   - fugue/shabal/whirlpool(x2)/sha256/haval stay scalar (deinterleaved per lane).
 * Bit-identical to the scalar path; guarded by skydoge_4way_self_test (the KAT).
 */

union skydoge_4x64_ctx
{
   bmw512_4x64_context     bmw;
   skein512_4x64_context   skein;
   jh512_4x64_context      jh;
   keccak512_4x64_context  keccak;
   hamsi512_4x64_context   hamsi;
   sha512_4x64_context     sha512;
   shabal512_4x32_context  shabal4;
   sha256_4x32_context     sha256_4;
   haval256_4x32_context   haval4;
   luffa_2way_context      luffa2;
   cube_2way_context       cube2;
   shavite512_2way_context shavite2;
   simd512_2way_context    simd2;
#if defined(__VAES__)
   groestl512_2way_context groestl2;
   echo_2way_context       echo2;
#endif
};

union skydoge_lane_ctx
{
   simd512_context         simd;
   cubehashParam           cube;
   sph_shavite512_context  shavite;
   sph_shabal512_context   shabal;
   sph_whirlpool_context   whirlpool;
   sph_sha256_context      sha256;
   sph_haval256_5_context  haval;
#if defined(__AES__) || defined(__ARM_FEATURE_AES)
   hashState_groestl       groestl;
   hashState_echo          echo;
   hashState_fugue         fugue;
#else
   sph_groestl512_context  groestl;
   sph_echo512_context     echo;
   sph_fugue512_context    fugue;
#endif
};

static inline void lane_groestl( union skydoge_lane_ctx *c, void *h )
{
#if defined(__AES__) || defined(__ARM_FEATURE_AES)
   groestl512_full( &c->groestl, (char*)h, (const char*)h, 512 );
#else
   sph_groestl512_init( &c->groestl );
   sph_groestl512( &c->groestl, h, 64 );
   sph_groestl512_close( &c->groestl, h );
#endif
}
static inline void lane_echo( union skydoge_lane_ctx *c, void *h )
{
#if defined(__AES__) || defined(__ARM_FEATURE_AES)
   echo_full( &c->echo, (BitSequence*)h, 512, (const BitSequence*)h, 64 );
#else
   sph_echo512_init( &c->echo );
   sph_echo512( &c->echo, h, 64 );
   sph_echo512_close( &c->echo, h );
#endif
}
static inline void lane_fugue( union skydoge_lane_ctx *c, void *h )
{
#if defined(__AES__) || defined(__ARM_FEATURE_AES)
   fugue512_full( &c->fugue, h, h, 64 );
#else
   sph_fugue512_full( &c->fugue, h, h, 64 );
#endif
}

// Blake-512 midstate (constant first block); the _le variants match the
// v128_swap64_32-prepped input format.
static __thread __m256i skydoge_4way_midstate[16] __attribute__ ((aligned (64)));
static __thread blake512_4x64_context skydoge_blake_ctx __attribute__ ((aligned (64)));

int skydoge_4x64_hash( void *output, const void *input, int thr_id )
{
   uint64_t vhash [8*4] __attribute__ ((aligned (64)));
   uint64_t vhashA[8*4] __attribute__ ((aligned (64)));
   uint64_t vhashB[8*4] __attribute__ ((aligned (64)));
   uint8_t  h0[64] __attribute__ ((aligned (64)));
   uint8_t  h1[64] __attribute__ ((aligned (64)));
   uint8_t  h2[64] __attribute__ ((aligned (64)));
   uint8_t  h3[64] __attribute__ ((aligned (64)));
   uint8_t *lane[4] = { h0, h1, h2, h3 };
   union skydoge_4x64_ctx ctx;
   union skydoge_lane_ctx sx;

   // 1-3: blake, skein, bmw (4x64)
   blake512_4x64_final_le( &skydoge_blake_ctx, vhash, casti_m256i( input, 9 ),
                           skydoge_4way_midstate );
   skein512_4x64_init( &ctx.skein );
   skein512_4x64_update( &ctx.skein, vhash, 64 );
   skein512_4x64_close( &ctx.skein, vhash );
   bmw512_4x64_init( &ctx.bmw );
   bmw512_4x64_update( &ctx.bmw, vhash, 64 );
   bmw512_4x64_close( &ctx.bmw, vhash );

   // 4: groestl (2x128 under VAES, else scalar)
#if defined(__VAES__)
   rintrlv_4x64_2x128( vhashA, vhashB, vhash, 512 );
   groestl512_2way_full( &ctx.groestl2, vhashA, vhashA, 64 );
   groestl512_2way_full( &ctx.groestl2, vhashB, vhashB, 64 );
   rintrlv_2x128_4x64( vhash, vhashA, vhashB, 512 );
#else
   dintrlv_4x64_512( h0, h1, h2, h3, vhash );
   for ( int l = 0; l < 4; l++ ) lane_groestl( &sx, lane[l] );
   intrlv_4x64_512( vhash, h0, h1, h2, h3 );
#endif

   // 5: jh (4x64)
   jh512_4x64_init( &ctx.jh );
   jh512_4x64_update( &ctx.jh, vhash, 64 );
   jh512_4x64_close( &ctx.jh, vhash );

   // 6: luffa (2x128)
   rintrlv_4x64_2x128( vhashA, vhashB, vhash, 512 );
   luffa512_2way_full( &ctx.luffa2, vhashA, vhashA, 64 );
   luffa512_2way_full( &ctx.luffa2, vhashB, vhashB, 64 );
   rintrlv_2x128_4x64( vhash, vhashA, vhashB, 512 );

   // 7: keccak (4x64)
   keccak512_4x64_init( &ctx.keccak );
   keccak512_4x64_update( &ctx.keccak, vhash, 64 );
   keccak512_4x64_close( &ctx.keccak, vhash );

   // 8-11: simd, echo, cubehash, shavite (2x128 under VAES, else scalar)
#if defined(__VAES__)
   rintrlv_4x64_2x128( vhashA, vhashB, vhash, 512 );
   simd512_2way_full( &ctx.simd2, vhashA, vhashA, 64 );
   simd512_2way_full( &ctx.simd2, vhashB, vhashB, 64 );
   echo_2way_full( &ctx.echo2, vhashA, 512, vhashA, 64 );
   echo_2way_full( &ctx.echo2, vhashB, 512, vhashB, 64 );
   cube_2way_full( &ctx.cube2, vhashA, 512, vhashA, 64 );
   cube_2way_full( &ctx.cube2, vhashB, 512, vhashB, 64 );
   shavite512_2way_full( &ctx.shavite2, vhashA, vhashA, 64 );
   shavite512_2way_full( &ctx.shavite2, vhashB, vhashB, 64 );
   rintrlv_2x128_4x64( vhash, vhashA, vhashB, 512 );
#else
   dintrlv_4x64_512( h0, h1, h2, h3, vhash );
   for ( int l = 0; l < 4; l++ )
   {
      simd512_ctx( &sx.simd, lane[l], lane[l], 64 );
      lane_echo( &sx, lane[l] );
      cubehash_full( &sx.cube, lane[l], 512, lane[l], 64 );
      sph_shavite512_init( &sx.shavite );
      sph_shavite512( &sx.shavite, lane[l], 64 );
      sph_shavite512_close( &sx.shavite, lane[l] );
   }
   intrlv_4x64_512( vhash, h0, h1, h2, h3 );
#endif

   // 12: hamsi (4x64)
   hamsi512_4x64_init( &ctx.hamsi );
   hamsi512_4x64_update( &ctx.hamsi, vhash, 64 );
   hamsi512_4x64_close( &ctx.hamsi, vhash );

   // 13: fugue (scalar)
   dintrlv_4x64_512( h0, h1, h2, h3, vhash );
   for ( int l = 0; l < 4; l++ ) lane_fugue( &sx, lane[l] );
   // 14: shabal (4x32)
   intrlv_4x32_512( vhash, h0, h1, h2, h3 );
   shabal512_4x32_init( &ctx.shabal4 );
   shabal512_4x32_update( &ctx.shabal4, vhash, 64 );
   shabal512_4x32_close( &ctx.shabal4, vhash );
   dintrlv_4x32_512( h0, h1, h2, h3, vhash );
   // 15: whirlpool (scalar)
   for ( int l = 0; l < 4; l++ )
   {
      sph_whirlpool_init( &sx.whirlpool );
      sph_whirlpool( &sx.whirlpool, lane[l], 64 );
      sph_whirlpool_close( &sx.whirlpool, lane[l] );
   }
   intrlv_4x64_512( vhash, h0, h1, h2, h3 );

   // 16: sha512 (4x64)
   sha512_4x64_init( &ctx.sha512 );
   sha512_4x64_update( &ctx.sha512, vhash, 64 );
   sha512_4x64_close( &ctx.sha512, vhash );

   // 17: simd (2x128) -> deinterleave to scalar for the tail
   rintrlv_4x64_2x128( vhashA, vhashB, vhash, 512 );
   simd512_2way_full( &ctx.simd2, vhashA, vhashA, 64 );
   simd512_2way_full( &ctx.simd2, vhashB, vhashB, 64 );
   dintrlv_2x128_512( h0, h1, vhashA );
   dintrlv_2x128_512( h2, h3, vhashB );

   // 18: whirlpool (scalar)
   for ( int l = 0; l < 4; l++ )
   {
      sph_whirlpool_init( &sx.whirlpool );
      sph_whirlpool( &sx.whirlpool, lane[l], 64 );
      sph_whirlpool_close( &sx.whirlpool, lane[l] );
   }
   // 19: sha256 (4x32) -> 32 bytes/lane; zero the high 32; 20: haval (4x32)
   intrlv_4x32_512( vhash, h0, h1, h2, h3 );
   sha256_4x32_init( &ctx.sha256_4 );
   sha256_4x32_update( &ctx.sha256_4, vhash, 64 );
   sha256_4x32_close( &ctx.sha256_4, vhashA );
   memset( (uint32_t*)vhashA + 32, 0, 32 * sizeof(uint32_t) ); // words 8..15, all 4 lanes
   haval256_4x32_init( &ctx.haval4 );
   haval256_4x32_update( &ctx.haval4, vhashA, 64 );
   haval256_4x32_close( &ctx.haval4, vhash );
   dintrlv_4x32( (uint8_t*)output,      (uint8_t*)output + 32,
                 (uint8_t*)output + 64, (uint8_t*)output + 96, vhash, 256 );
   return 1;
}

int scanhash_skydoge_4x64( struct work *work, uint32_t max_nonce,
                           uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t hash[8*4] __attribute__ ((aligned (64)));
   uint32_t vdata[20*4] __attribute__ ((aligned (64)));
   v128_t   edata[5] __attribute__ ((aligned (32)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 4;
   uint32_t n = first_nonce;
   __m256i  *noncev = (__m256i*)vdata + 9;
   const int thr_id = mythr->id;
   const uint32_t targ32 = ptarget[7];
   const bool bench = opt_benchmark;
   const __m256i four = _mm256_set_epi32( 0,4,0,4, 0,4,0,4 );

   edata[0] = v128_swap64_32( casti_v128u32( pdata, 0 ) );
   edata[1] = v128_swap64_32( casti_v128u32( pdata, 1 ) );
   edata[2] = v128_swap64_32( casti_v128u32( pdata, 2 ) );
   edata[3] = v128_swap64_32( casti_v128u32( pdata, 3 ) );
   edata[4] = v128_swap64_32( casti_v128u32( pdata, 4 ) );
   mm256_intrlv80_4x64( vdata, edata );
   *noncev = _mm256_add_epi32( *noncev, _mm256_set_epi32( 0,3,0,2, 0,1,0,0 ) );
   blake512_4x64_prehash_le( &skydoge_blake_ctx, skydoge_4way_midstate, vdata );

   do
   {
      skydoge_4x64_hash( hash, vdata, thr_id );
      for ( int lane = 0; lane < 4; lane++ )
      {
         uint32_t *lh = hash + ( lane << 3 );
         if ( unlikely( ( lh[7] <= targ32 ) && !bench ) )
            if ( likely( valid_hash( lh, ptarget ) ) )
            {
               pdata[19] = n + lane;
               submit_solution( work, lh, mythr );
            }
      }
      *noncev = _mm256_add_epi32( *noncev, four );
      n += 4;
   } while ( ( n < last_nonce ) && !work_restart[thr_id].restart );

   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

// Self-test = consensus anchor + differential conformance.
//   1. scalar(KAT) == pool-accepted digest  -> scalar path == consensus.
//   2. 4-way == scalar for many varied inputs across all lanes -> the 4-way path
//      is byte-identical to the reference (not just for the single KAT input).
// Hard-fails on any mismatch, so a non-conformant build refuses to mine.
bool skydoge_4way_self_test( void )
{
   uint8_t ref[32];

   // 1. Anchor the scalar reference to consensus.
   skydoge_hash( ref, skydoge_test_input, 0 );
   if ( memcmp( ref, skydoge_test_expected, 32 ) != 0 )
   {
      applog( LOG_ERR, "SkyDoge scalar reference KAT mismatch - cannot anchor" );
      return false;
   }

   // 2. Differential: 4-way vs scalar over KITERS varied headers x 4 lane nonces.
   const int KITERS = 64;
   uint32_t lcg = 0x9e3779b9u;
   for ( int it = 0; it < KITERS; it++ )
   {
      uint32_t pdata[20];
      for ( int i = 0; i < 20; i++ )
      {  lcg = lcg * 1664525u + 1013904223u;  pdata[i] = lcg;  }

      v128_t   edata[5]    __attribute__ ((aligned (32)));
      uint32_t vdata[20*4] __attribute__ ((aligned (64)));
      uint32_t vhash[8*4]  __attribute__ ((aligned (64)));
      for ( int k = 0; k < 5; k++ )
         edata[k] = v128_swap64_32( casti_v128u32( pdata, k ) );
      mm256_intrlv80_4x64( vdata, edata );
      __m256i *noncev = (__m256i*)vdata + 9;
      *noncev = _mm256_add_epi32( *noncev, _mm256_set_epi32( 0,3, 0,2, 0,1, 0,0 ) );
      blake512_4x64_prehash_le( &skydoge_blake_ctx, skydoge_4way_midstate, vdata );
      skydoge_4x64_hash( vhash, vdata, 0 );

      for ( int lane = 0; lane < 4; lane++ )
      {
         uint32_t eds[20];
         for ( int i = 0; i < 19; i++ ) be32enc( &eds[i], pdata[i] );
         be32enc( &eds[19], pdata[19] + lane );
         skydoge_hash( ref, eds, 0 );
         if ( memcmp( ref, (uint8_t*)vhash + lane * 32, 32 ) != 0 )
         {
            applog( LOG_ERR,
                    "SkyDoge 4-way differential FAILED: iter %d lane %d", it, lane );
            return false;
         }
      }
   }

   applog( LOG_NOTICE,
           "SkyDoge 4-way self-test PASSED (consensus KAT + %dx4 differential)",
           KITERS );
   return true;
}

#endif // SKYDOGE_4WAY
