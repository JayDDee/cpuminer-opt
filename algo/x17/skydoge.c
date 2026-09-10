#include "skydoge-gate.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "algo/blake/blake512-hash.h"
#include "algo/bmw/sph_bmw.h"
#include "algo/skein/sph_skein.h"
#include "algo/jh/sph_jh.h"
#include "algo/keccak/sph_keccak.h"
#include "algo/luffa/luffa_for_sse2.h"
#include "algo/cubehash/cubehash_sse2.h"
#include "algo/shavite/sph_shavite.h"
#include "algo/simd/simd-hash-2way.h"
#include "algo/hamsi/sph_hamsi.h"
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
 * SkyDoge (`skydoge`) — fixed-order 20-step chained hash.
 *
 * Port of tpfuemp/yiimp-skydoge algos/skydoge.c. The chain (each round consumes
 * the previous 64-byte output; the first consumes the 80-byte header):
 *
 *   blake512, skein512, bmw512, groestl512, jh512, luffa512, keccak512, simd512,
 *   echo512, cubehash512, shavite512, hamsi512, fugue512, shabal512, whirlpool,
 *   sha512, simd512, whirlpool, sha256, haval256-5
 *
 * (simd and whirlpool each run twice.) Finalize: sha256 writes 32 bytes into
 * hashA; hashA[8..15] (the high 32 bytes) are zeroed; haval256-5 hashes the full
 * 64-byte hashA; the first 32 bytes of its output are the result.
 *
 * Phase 2: the heavy cores use this repo's optimized single-hash implementations
 * (AES-NI groestl/echo/fugue, SSE2 luffa/cubehash/simd, blake512) which are
 * bit-identical to the sph reference (as proven by the pool-confirmed x17 family
 * and guarded by the consensus KAT in skydoge_self_test). The rest stay sph.
 */

union _skydoge_ctx_overlay
{
   blake512_context        blake;
   sph_bmw512_context      bmw;
   sph_skein512_context    skein;
   sph_jh512_context       jh;
   sph_keccak512_context   keccak;
   hashState_luffa         luffa;
   cubehashParam           cube;
   sph_shavite512_context  shavite;
   simd512_context         simd;
   sph_hamsi512_context    hamsi;
   sph_shabal512_context   shabal;
   sph_whirlpool_context   whirlpool;
   sph_sha512_context      sha512;
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
typedef union _skydoge_ctx_overlay skydoge_ctx_overlay;

int skydoge_hash( void *output, const void *input, int thr_id )
{
   uint32_t _ALIGN(64) hash[16];
   uint32_t _ALIGN(64) hashA[16];
   skydoge_ctx_overlay ctx;

   blake512_full( &ctx.blake, hash, input, 80 );                       // 1

   sph_skein512_init( &ctx.skein );                                    // 2
   sph_skein512( &ctx.skein, hash, 64 );
   sph_skein512_close( &ctx.skein, hash );

   sph_bmw512_init( &ctx.bmw );                                        // 3
   sph_bmw512( &ctx.bmw, hash, 64 );
   sph_bmw512_close( &ctx.bmw, hash );

#if defined(__AES__) || defined(__ARM_FEATURE_AES)                     // 4
   groestl512_full( &ctx.groestl, (char*)hash, (const char*)hash, 512 );
#else
   sph_groestl512_init( &ctx.groestl );
   sph_groestl512( &ctx.groestl, hash, 64 );
   sph_groestl512_close( &ctx.groestl, hash );
#endif

   sph_jh512_init( &ctx.jh );                                          // 5
   sph_jh512( &ctx.jh, hash, 64 );
   sph_jh512_close( &ctx.jh, hash );

   luffa_full( &ctx.luffa, hash, 512, hash, 64 );                      // 6

   sph_keccak512_init( &ctx.keccak );                                  // 7
   sph_keccak512( &ctx.keccak, hash, 64 );
   sph_keccak512_close( &ctx.keccak, hash );

   simd512_ctx( &ctx.simd, hash, hash, 64 );                           // 8

#if defined(__AES__) || defined(__ARM_FEATURE_AES)                     // 9
   echo_full( &ctx.echo, (BitSequence*)hash, 512,
              (const BitSequence*)hash, 64 );
#else
   sph_echo512_init( &ctx.echo );
   sph_echo512( &ctx.echo, hash, 64 );
   sph_echo512_close( &ctx.echo, hash );
#endif

   cubehash_full( &ctx.cube, hash, 512, hash, 64 );// 10

   sph_shavite512_init( &ctx.shavite );                                // 11
   sph_shavite512( &ctx.shavite, hash, 64 );
   sph_shavite512_close( &ctx.shavite, hash );

   sph_hamsi512_init( &ctx.hamsi );                                    // 12
   sph_hamsi512( &ctx.hamsi, hash, 64 );
   sph_hamsi512_close( &ctx.hamsi, hash );

#if defined(__AES__) || defined(__ARM_FEATURE_AES)                     // 13
   fugue512_full( &ctx.fugue, hash, hash, 64 );
#else
   sph_fugue512_full( &ctx.fugue, hash, hash, 64 );
#endif

   sph_shabal512_init( &ctx.shabal );                                  // 14
   sph_shabal512( &ctx.shabal, hash, 64 );
   sph_shabal512_close( &ctx.shabal, hash );

   sph_whirlpool_init( &ctx.whirlpool );                               // 15
   sph_whirlpool( &ctx.whirlpool, hash, 64 );
   sph_whirlpool_close( &ctx.whirlpool, hash );

   sph_sha512_init( &ctx.sha512 );                                     // 16
   sph_sha512( &ctx.sha512, hash, 64 );
   sph_sha512_close( &ctx.sha512, hash );

   simd512_ctx( &ctx.simd, hash, hash, 64 );                           // 17

   sph_whirlpool_init( &ctx.whirlpool );                               // 18
   sph_whirlpool( &ctx.whirlpool, hash, 64 );
   sph_whirlpool_close( &ctx.whirlpool, hash );

   sph_sha256_init( &ctx.sha256 );                                     // 19
   sph_sha256( &ctx.sha256, hash, 64 );
   sph_sha256_close( &ctx.sha256, hashA );

   // Zero the high 32 bytes (uint32 indices 8..15) before the final haval.
   for ( int i = 8; i < 16; i++ )
      hashA[i] = 0;

   sph_haval256_5_init( &ctx.haval );                                  // 20
   sph_haval256_5( &ctx.haval, hashA, 64 );
   sph_haval256_5_close( &ctx.haval, hash );

   memcpy( output, hash, 32 );
   return 1;
}

// Known-answer self-test, taken from a REAL pool-accepted share (zpool.ca SkyDoge
// job 30b2, 2026-06-26). skydoge_test_input is the 80-byte header exactly as
// skydoge_hash receives it (the be32enc'd work->data words). skydoge_test_expected
// is the resulting 32-byte digest (little-endian words: hash[0]=0x0e05d672 ..
// hash[7]=0x0000001a), which the pool accepted, so it is consensus-correct. This
// also guards the Phase-2 optimized cores against any divergence from sph.
const uint8_t skydoge_test_input[80] =
{
   0x00,0x00,0x00,0x20, 0x2e,0x4c,0xf8,0x2c, 0x5a,0xc6,0x4f,0xf3, 0xc0,0xcc,0x0d,0x6d,
   0x8c,0x0d,0x0e,0xb5, 0x45,0x32,0x1b,0x2c, 0x85,0x9f,0x8a,0x78, 0xa4,0xd3,0x0e,0x01,
   0x00,0x00,0x00,0x00, 0xd2,0xe7,0x08,0x8b, 0xbd,0xf7,0x3f,0x0d, 0x6b,0xfa,0x2c,0xf9,
   0x22,0x48,0x32,0x36, 0xfb,0x65,0x99,0x4c, 0x22,0x10,0x73,0xe9, 0x85,0x0d,0x36,0xaf,
   0x3f,0xdf,0x1f,0xfd, 0x5c,0xdf,0x3e,0x6a, 0x3d,0x20,0x02,0x1c, 0xf0,0x02,0x51,0xaf
};

const uint8_t skydoge_test_expected[32] =
{
   0x72,0xd6,0x05,0x0e, 0x7d,0xfa,0x96,0x04, 0x80,0x1a,0x9d,0x73, 0xbc,0xd5,0x44,0xe0,
   0x7b,0xed,0xd5,0xd2, 0xc1,0x49,0xb4,0xd1, 0xf1,0x33,0xff,0xbc, 0x1a,0x00,0x00,0x00
};

bool skydoge_self_test( void )
{
   uint8_t hash[32];
   skydoge_hash( hash, skydoge_test_input, 0 );

   if ( memcmp( hash, skydoge_test_expected, 32 ) == 0 )
   {
      applog( LOG_NOTICE, "SkyDoge self-test PASSED (consensus KAT)" );
      return true;
   }

   char got[65], exp[65];
   for ( int i = 0; i < 32; i++ )
   {
      sprintf( got + i * 2, "%02x", hash[i] );
      sprintf( exp + i * 2, "%02x", skydoge_test_expected[i] );
   }
   applog( LOG_ERR, "SkyDoge self-test FAILED (consensus KAT mismatch)" );
   applog( LOG_ERR, "  got:      %s", got );
   applog( LOG_ERR, "  expected: %s", exp );
   return false;
}

#if !defined(SKYDOGE_8WAY) && !defined(SKYDOGE_4WAY)

int scanhash_skydoge( struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t _ALIGN(64) hash[8];
   uint32_t _ALIGN(64) edata[20];
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const int thr_id = mythr->id;
   uint32_t n = first_nonce;
   volatile uint8_t *restart = &( work_restart[thr_id].restart );
   const bool bench = opt_benchmark;

   for ( int i = 0; i < 19; i++ )
      be32enc( &edata[i], pdata[i] );

   do
   {
      be32enc( &edata[19], n );
      skydoge_hash( hash, edata, thr_id );

      if ( unlikely( valid_hash( hash, ptarget ) && !bench ) )
      {
         pdata[19] = n;
         submit_solution( work, hash, mythr );
      }
      n++;
   } while ( n < max_nonce && !(*restart) );

   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

#endif // scalar

bool register_skydoge_algo( algo_gate_t *gate )
{
#if defined(SKYDOGE_8WAY)
   if ( !skydoge_8way_self_test() )
   {
      applog( LOG_ERR, "SkyDoge 8-way self-test failed" );
      return false;
   }
   gate->scanhash      = (void*)&scanhash_skydoge_8x64;
   gate->hash          = (void*)&skydoge_8x64_hash;
#elif defined(SKYDOGE_4WAY)
   if ( !skydoge_4way_self_test() )
   {
      applog( LOG_ERR, "SkyDoge 4-way self-test failed" );
      return false;
   }
   gate->scanhash      = (void*)&scanhash_skydoge_4x64;
   gate->hash          = (void*)&skydoge_4x64_hash;
#else
   if ( !skydoge_self_test() )
   {
      applog( LOG_ERR, "SkyDoge self-test failed" );
      return false;
   }
   gate->scanhash      = (void*)&scanhash_skydoge;
   gate->hash          = (void*)&skydoge_hash;
#endif
   gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT | NEON_OPT;
   // Standard Bitcoin difficulty scale (0xffff base), like the other plain
   // 256-bit-output hash algos. (A 256.0 factor made targetdiff 256x too easy
   // -> pool rejected shares as "low difficulty".)
   opt_target_factor   = 1.0;
   return true;
}
