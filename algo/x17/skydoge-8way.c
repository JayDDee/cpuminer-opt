#include "skydoge-gate.h"

#if defined(SKYDOGE_8WAY)

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "simd-utils.h"

// 8x64 cores
#include "algo/blake/blake512-hash.h"
#include "algo/bmw/bmw-hash-4way.h"
#include "algo/skein/skein-hash-4way.h"
#include "algo/jh/jh-hash-4way.h"
#include "algo/keccak/keccak-hash-4way.h"
#include "algo/hamsi/hamsi-hash-4way.h"
#include "algo/sha/sha512-hash.h"
#include "algo/shabal/shabal-hash-4way.h"  // shabal512_8x32
#include "algo/sha/sha256-hash.h"          // sha256_8x32
#include "algo/haval/haval-hash-4way.h"    // haval256_8x32

// 4x128 cores for the heavy hashes
#include "algo/luffa/luffa-hash-2way.h"   // luffa512_4way
#include "algo/cubehash/cube-hash-2way.h" // cube_4way_2buf
#include "algo/simd/simd-hash-2way.h"     // simd512_4way
#if defined(__VAES__)
  #include "algo/groestl/groestl512-hash-4way.h"
  #include "algo/shavite/shavite-hash-4way.h"
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
 * SkyDoge 8-way (8x64), Phase 2b.3. Same shape as the 4x64 path but 8 lanes:
 *   - blake/skein/bmw/jh/keccak/hamsi/sha512 run 8-way (8x64);
 *   - luffa and both simd stages run 4-way (4x128); groestl and the
 *     simd/echo/cubehash/shavite group run 4-way under VAES, scalar otherwise;
 *   - fugue/shabal/whirlpool(x2)/sha256/haval run per-lane (deinterleaved 1-way).
 * KAT-guarded (skydoge_8way_self_test); bit-identical to the scalar path.
 */

union skydoge_8x64_ctx
{
   bmw512_8x64_context     bmw;
   skein512_8x64_context   skein;
   jh512_8x64_context      jh;
   keccak512_8x64_context  keccak;
   hamsi512_8x64_context   hamsi;
   sha512_8x64_context     sha512;
   shabal512_8x32_context  shabal8;
   sha256_8x32_context     sha256_8;
   haval256_8x32_context   haval8;
   luffa_4way_context      luffa4;
   cube_4way_2buf_context  cube4;
   simd_4way_context       simd4;
#if defined(__VAES__)
   groestl512_4way_context groestl4;
   shavite512_4way_context shavite4;
   echo_4way_context       echo4;
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

static __thread __m512i skydoge_8way_midstate[16] __attribute__ ((aligned (64)));
static __thread blake512_8x64_context skydoge_blake8_ctx __attribute__ ((aligned (64)));

int skydoge_8x64_hash( void *output, const void *input, int thr_id )
{
   uint64_t vhash [8*8] __attribute__ ((aligned (128)));
   uint64_t vhashA[8*8] __attribute__ ((aligned (64)));
   uint64_t vhashB[8*8] __attribute__ ((aligned (64)));
   uint8_t  h[8][64]    __attribute__ ((aligned (64)));
   union skydoge_8x64_ctx ctx;
   union skydoge_lane_ctx sx;

   // 1-3: blake, skein, bmw (8x64)
   blake512_8x64_final_le( &skydoge_blake8_ctx, vhash, casti_m512i( input, 9 ),
                           skydoge_8way_midstate );
   skein512_8x64_init( &ctx.skein );
   skein512_8x64_update( &ctx.skein, vhash, 64 );
   skein512_8x64_close( &ctx.skein, vhash );
   bmw512_8x64_init( &ctx.bmw );
   bmw512_8x64_update( &ctx.bmw, vhash, 64 );
   bmw512_8x64_close( &ctx.bmw, vhash );

   // 4: groestl (4x128 under VAES, else scalar)
#if defined(__VAES__)
   rintrlv_8x64_4x128( vhashA, vhashB, vhash, 512 );
   groestl512_4way_full( &ctx.groestl4, vhashA, vhashA, 64 );
   groestl512_4way_full( &ctx.groestl4, vhashB, vhashB, 64 );
   rintrlv_4x128_8x64( vhash, vhashA, vhashB, 512 );
#else
   dintrlv_8x64_512( h[0],h[1],h[2],h[3],h[4],h[5],h[6],h[7], vhash );
   for ( int l = 0; l < 8; l++ ) lane_groestl( &sx, h[l] );
   intrlv_8x64_512( vhash, h[0],h[1],h[2],h[3],h[4],h[5],h[6],h[7] );
#endif

   // 5: jh (8x64)
   jh512_8x64_init( &ctx.jh );
   jh512_8x64_update( &ctx.jh, vhash, 64 );
   jh512_8x64_close( &ctx.jh, vhash );

   // 6: luffa (4x128)
   rintrlv_8x64_4x128( vhashA, vhashB, vhash, 512 );
   luffa512_4way_full( &ctx.luffa4, vhashA, vhashA, 64 );
   luffa512_4way_full( &ctx.luffa4, vhashB, vhashB, 64 );
   rintrlv_4x128_8x64( vhash, vhashA, vhashB, 512 );

   // 7: keccak (8x64)
   keccak512_8x64_init( &ctx.keccak );
   keccak512_8x64_update( &ctx.keccak, vhash, 64 );
   keccak512_8x64_close( &ctx.keccak, vhash );

   // 8-11: simd, echo, cubehash, shavite (4x128 under VAES, else scalar)
#if defined(__VAES__)
   rintrlv_8x64_4x128( vhashA, vhashB, vhash, 512 );
   simd512_4way_full( &ctx.simd4, vhashA, vhashA, 64 );
   simd512_4way_full( &ctx.simd4, vhashB, vhashB, 64 );
   echo_4way_full( &ctx.echo4, vhashA, 512, vhashA, 64 );
   echo_4way_full( &ctx.echo4, vhashB, 512, vhashB, 64 );
   cube_4way_2buf_full( &ctx.cube4, vhashA, vhashB, 512, vhashA, vhashB, 64 );
   shavite512_4way_full( &ctx.shavite4, vhashA, vhashA, 64 );
   shavite512_4way_full( &ctx.shavite4, vhashB, vhashB, 64 );
   rintrlv_4x128_8x64( vhash, vhashA, vhashB, 512 );
#else
   dintrlv_8x64_512( h[0],h[1],h[2],h[3],h[4],h[5],h[6],h[7], vhash );
   for ( int l = 0; l < 8; l++ )
   {
      simd512_ctx( &sx.simd, h[l], h[l], 64 );
      lane_echo( &sx, h[l] );
      cubehash_full( &sx.cube, h[l], 512, h[l], 64 );
      sph_shavite512_init( &sx.shavite );
      sph_shavite512( &sx.shavite, h[l], 64 );
      sph_shavite512_close( &sx.shavite, h[l] );
   }
   intrlv_8x64_512( vhash, h[0],h[1],h[2],h[3],h[4],h[5],h[6],h[7] );
#endif

   // 12: hamsi (8x64)
   hamsi512_8x64_init( &ctx.hamsi );
   hamsi512_8x64_update( &ctx.hamsi, vhash, 64 );
   hamsi512_8x64_close( &ctx.hamsi, vhash );

   // 13: fugue (scalar)
   dintrlv_8x64_512( h[0],h[1],h[2],h[3],h[4],h[5],h[6],h[7], vhash );
   for ( int l = 0; l < 8; l++ ) lane_fugue( &sx, h[l] );
   // 14: shabal (8x32)
   intrlv_8x32_512( vhash, h[0],h[1],h[2],h[3],h[4],h[5],h[6],h[7] );
   shabal512_8x32_init( &ctx.shabal8 );
   shabal512_8x32_update( &ctx.shabal8, vhash, 64 );
   shabal512_8x32_close( &ctx.shabal8, vhash );
   dintrlv_8x32_512( h[0],h[1],h[2],h[3],h[4],h[5],h[6],h[7], vhash );
   // 15: whirlpool (scalar)
   for ( int l = 0; l < 8; l++ )
   {
      sph_whirlpool_init( &sx.whirlpool );
      sph_whirlpool( &sx.whirlpool, h[l], 64 );
      sph_whirlpool_close( &sx.whirlpool, h[l] );
   }
   intrlv_8x64_512( vhash, h[0],h[1],h[2],h[3],h[4],h[5],h[6],h[7] );

   // 16: sha512 (8x64)
   sha512_8x64_init( &ctx.sha512 );
   sha512_8x64_update( &ctx.sha512, vhash, 64 );
   sha512_8x64_close( &ctx.sha512, vhash );

   // 17: simd (4x128) -> deinterleave to scalar for the tail
   rintrlv_8x64_4x128( vhashA, vhashB, vhash, 512 );
   simd512_4way_full( &ctx.simd4, vhashA, vhashA, 64 );
   simd512_4way_full( &ctx.simd4, vhashB, vhashB, 64 );
   dintrlv_4x128_512( h[0], h[1], h[2], h[3], vhashA );
   dintrlv_4x128_512( h[4], h[5], h[6], h[7], vhashB );

   // 18: whirlpool (scalar)
   for ( int l = 0; l < 8; l++ )
   {
      sph_whirlpool_init( &sx.whirlpool );
      sph_whirlpool( &sx.whirlpool, h[l], 64 );
      sph_whirlpool_close( &sx.whirlpool, h[l] );
   }
   // 19: sha256 (8x32) -> 32 bytes/lane; zero the high 32; 20: haval (8x32)
   intrlv_8x32_512( vhash, h[0],h[1],h[2],h[3],h[4],h[5],h[6],h[7] );
   sha256_8x32_init( &ctx.sha256_8 );
   sha256_8x32_update( &ctx.sha256_8, vhash, 64 );
   sha256_8x32_close( &ctx.sha256_8, vhashA );
   memset( (uint32_t*)vhashA + 64, 0, 64 * sizeof(uint32_t) ); // words 8..15, all 8 lanes
   haval256_8x32_init( &ctx.haval8 );
   haval256_8x32_update( &ctx.haval8, vhashA, 64 );
   haval256_8x32_close( &ctx.haval8, vhash );
   dintrlv_8x32_256( (uint8_t*)output,       (uint8_t*)output +  32,
                     (uint8_t*)output +  64, (uint8_t*)output +  96,
                     (uint8_t*)output + 128, (uint8_t*)output + 160,
                     (uint8_t*)output + 192, (uint8_t*)output + 224, vhash );
   return 1;
}

int scanhash_skydoge_8x64( struct work *work, uint32_t max_nonce,
                           uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t hash[8*8] __attribute__ ((aligned (128)));
   uint32_t vdata[20*8] __attribute__ ((aligned (64)));
   v128_t   edata[5] __attribute__ ((aligned (32)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 8;
   uint32_t n = first_nonce;
   __m512i  *noncev = (__m512i*)vdata + 9;
   const int thr_id = mythr->id;
   const uint32_t targ32 = ptarget[7];
   const bool bench = opt_benchmark;
   const __m512i eight = _mm512_set_epi32( 0,8, 0,8, 0,8, 0,8, 0,8, 0,8, 0,8, 0,8 );

   edata[0] = v128_swap64_32( casti_v128u32( pdata, 0 ) );
   edata[1] = v128_swap64_32( casti_v128u32( pdata, 1 ) );
   edata[2] = v128_swap64_32( casti_v128u32( pdata, 2 ) );
   edata[3] = v128_swap64_32( casti_v128u32( pdata, 3 ) );
   edata[4] = v128_swap64_32( casti_v128u32( pdata, 4 ) );
   mm512_intrlv80_8x64( vdata, edata );
   *noncev = _mm512_add_epi32( *noncev,
                _mm512_set_epi32( 0,7, 0,6, 0,5, 0,4, 0,3, 0,2, 0,1, 0,0 ) );
   blake512_8x64_prehash_le( &skydoge_blake8_ctx, skydoge_8way_midstate, vdata );

   do
   {
      skydoge_8x64_hash( hash, vdata, thr_id );
      for ( int lane = 0; lane < 8; lane++ )
      {
         uint32_t *lh = hash + ( lane << 3 );
         if ( unlikely( ( lh[7] <= targ32 ) && !bench ) )
            if ( likely( valid_hash( lh, ptarget ) ) )
            {
               pdata[19] = n + lane;
               submit_solution( work, lh, mythr );
            }
      }
      *noncev = _mm512_add_epi32( *noncev, eight );
      n += 8;
   } while ( ( n < last_nonce ) && !work_restart[thr_id].restart );

   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

// Self-test = consensus anchor + differential conformance.
//   1. scalar(KAT) == pool-accepted digest  -> scalar path == consensus.
//   2. 8-way == scalar for many varied inputs across all lanes -> the 8-way path
//      is byte-identical to the reference (not just for the single KAT input).
// Hard-fails on any mismatch, so a non-conformant build refuses to mine.
bool skydoge_8way_self_test( void )
{
   uint8_t ref[32];

   // 1. Anchor the scalar reference to consensus.
   skydoge_hash( ref, skydoge_test_input, 0 );
   if ( memcmp( ref, skydoge_test_expected, 32 ) != 0 )
   {
      applog( LOG_ERR, "SkyDoge scalar reference KAT mismatch - cannot anchor" );
      return false;
   }

   // 2. Differential: 8-way vs scalar over KITERS varied headers x 8 lane nonces.
   const int KITERS = 64;
   uint32_t lcg = 0x9e3779b9u;
   for ( int it = 0; it < KITERS; it++ )
   {
      uint32_t pdata[20];
      for ( int i = 0; i < 20; i++ )
      {  lcg = lcg * 1664525u + 1013904223u;  pdata[i] = lcg;  }

      v128_t   edata[5]   __attribute__ ((aligned (32)));
      uint32_t vdata[20*8] __attribute__ ((aligned (64)));
      uint32_t vhash[8*8]  __attribute__ ((aligned (128)));
      for ( int k = 0; k < 5; k++ )
         edata[k] = v128_swap64_32( casti_v128u32( pdata, k ) );
      mm512_intrlv80_8x64( vdata, edata );
      __m512i *noncev = (__m512i*)vdata + 9;
      *noncev = _mm512_add_epi32( *noncev,
                   _mm512_set_epi32( 0,7, 0,6, 0,5, 0,4, 0,3, 0,2, 0,1, 0,0 ) );
      blake512_8x64_prehash_le( &skydoge_blake8_ctx, skydoge_8way_midstate, vdata );
      skydoge_8x64_hash( vhash, vdata, 0 );

      for ( int lane = 0; lane < 8; lane++ )
      {
         uint32_t eds[20];
         for ( int i = 0; i < 19; i++ ) be32enc( &eds[i], pdata[i] );
         be32enc( &eds[19], pdata[19] + lane );
         skydoge_hash( ref, eds, 0 );
         if ( memcmp( ref, (uint8_t*)vhash + lane * 32, 32 ) != 0 )
         {
            applog( LOG_ERR,
                    "SkyDoge 8-way differential FAILED: iter %d lane %d", it, lane );
            return false;
         }
      }
   }

   applog( LOG_NOTICE,
           "SkyDoge 8-way self-test PASSED (consensus KAT + %dx8 differential)",
           KITERS );
   return true;
}

#endif // SKYDOGE_8WAY
