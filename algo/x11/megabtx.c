#include "megabtx-gate.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "algo/blake/sph_blake.h"
#include "algo/blake/blake512-hash.h"
#include "algo/bmw/sph_bmw.h"
#include "algo/jh/sph_jh.h"
#include "algo/keccak/sph_keccak.h"
#include "algo/skein/sph_skein.h"
#include "algo/luffa/sph_luffa.h"
#include "algo/luffa/luffa_for_sse2.h"
#include "algo/cubehash/cubehash_sse2.h"
#include "algo/shavite/sph_shavite.h"
#include "algo/simd/simd-hash-2way.h"
#include "algo/hamsi/sph_hamsi.h"
#include "algo/shabal/sph_shabal.h"
#include "algo/whirlpool/sph_whirlpool.h"
#include "algo/sha/sph_sha2.h"
#include "algo/gost/sph_gost.h"
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

#include "megabtx-kat.h"

union _megabtx_context_overlay
{
#if defined(__aarch64__)
        sph_blake512_context    blake;
        sph_luffa512_context    luffa;
#else
        blake512_context        blake;
        hashState_luffa         luffa;
#endif
#if defined(__AES__) || defined(__ARM_FEATURE_AES)
        hashState_groestl       groestl;
        hashState_echo          echo;
        hashState_fugue         fugue;
#else
        sph_groestl512_context  groestl;
        sph_echo512_context     echo;
        sph_fugue512_context    fugue;
#endif
        sph_bmw512_context      bmw;
        sph_jh512_context       jh;
        sph_keccak512_context   keccak;
        sph_skein512_context    skein;
        cubehashParam           cube;
        sph_shavite512_context  shavite;
        simd512_context         simd;
        sph_hamsi512_context    hamsi;
        sph_shabal512_context   shabal;
        sph_whirlpool_context   whirlpool;
        sph_sha512_context      sha512;
        sph_gost512_context     gost;
        sph_haval256_5_context  haval;
};
typedef union _megabtx_context_overlay megabtx_context_overlay;

/* Every step after slot 0 is 64 bytes in, 64 bytes out, in place. The contexts
 * share a union because each step is a self-contained init/update/close, so the
 * second hash of a pair never overlaps the first.
 */

static inline void mega_blake( megabtx_context_overlay *ctx, void *hash )
{
#if defined(__aarch64__)
   sph_blake512_init( &ctx->blake );
   sph_blake512( &ctx->blake, hash, 64 );
   sph_blake512_close( &ctx->blake, hash );
#else
   blake512_full( &ctx->blake, hash, hash, 64 );
#endif
}

static inline void mega_bmw( megabtx_context_overlay *ctx, void *hash )
{
   sph_bmw512_init( &ctx->bmw );
   sph_bmw512( &ctx->bmw, hash, 64 );
   sph_bmw512_close( &ctx->bmw, hash );
}

static inline void mega_groestl( megabtx_context_overlay *ctx, void *hash )
{
#if defined(__AES__) || defined(__ARM_FEATURE_AES)
   groestl512_full( &ctx->groestl, (char*)hash, (const char*)hash, 512 );
#else
   sph_groestl512_init( &ctx->groestl );
   sph_groestl512( &ctx->groestl, hash, 64 );
   sph_groestl512_close( &ctx->groestl, hash );
#endif
}

static inline void mega_jh( megabtx_context_overlay *ctx, void *hash )
{
   sph_jh512_init( &ctx->jh );
   sph_jh512( &ctx->jh, hash, 64 );
   sph_jh512_close( &ctx->jh, hash );
}

static inline void mega_keccak( megabtx_context_overlay *ctx, void *hash )
{
   sph_keccak512_init( &ctx->keccak );
   sph_keccak512( &ctx->keccak, hash, 64 );
   sph_keccak512_close( &ctx->keccak, hash );
}

static inline void mega_skein( megabtx_context_overlay *ctx, void *hash )
{
   sph_skein512_init( &ctx->skein );
   sph_skein512( &ctx->skein, hash, 64 );
   sph_skein512_close( &ctx->skein, hash );
}

static inline void mega_luffa( megabtx_context_overlay *ctx, void *hash )
{
#if defined(__aarch64__)
   sph_luffa512_init( &ctx->luffa );
   sph_luffa512( &ctx->luffa, hash, 64 );
   sph_luffa512_close( &ctx->luffa, hash );
#else
   luffa_full( &ctx->luffa, hash, 512, hash, 64 );
#endif
}

static inline void mega_cubehash( megabtx_context_overlay *ctx, void *hash )
{
   cubehash_full( &ctx->cube, hash, 512, hash, 64 );
}

static inline void mega_shavite( megabtx_context_overlay *ctx, void *hash )
{
   sph_shavite512_init( &ctx->shavite );
   sph_shavite512( &ctx->shavite, hash, 64 );
   sph_shavite512_close( &ctx->shavite, hash );
}

static inline void mega_simd( megabtx_context_overlay *ctx, void *hash )
{
   simd512_ctx( &ctx->simd, hash, hash, 64 );
}

static inline void mega_echo( megabtx_context_overlay *ctx, void *hash )
{
#if defined(__AES__) || defined(__ARM_FEATURE_AES)
   echo_full( &ctx->echo, (BitSequence *)hash, 512,
              (const BitSequence *)hash, 64 );
#else
   sph_echo512_init( &ctx->echo );
   sph_echo512( &ctx->echo, hash, 64 );
   sph_echo512_close( &ctx->echo, hash );
#endif
}

static inline void mega_hamsi( megabtx_context_overlay *ctx, void *hash )
{
   sph_hamsi512_init( &ctx->hamsi );
   sph_hamsi512( &ctx->hamsi, hash, 64 );
   sph_hamsi512_close( &ctx->hamsi, hash );
}

static inline void mega_fugue( megabtx_context_overlay *ctx, void *hash )
{
#if defined(__AES__) || defined(__ARM_FEATURE_AES)
   fugue512_full( &ctx->fugue, hash, hash, 64 );
#else
   sph_fugue512_full( &ctx->fugue, hash, hash, 64 );
#endif
}

static inline void mega_shabal( megabtx_context_overlay *ctx, void *hash )
{
   sph_shabal512_init( &ctx->shabal );
   sph_shabal512( &ctx->shabal, hash, 64 );
   sph_shabal512_close( &ctx->shabal, hash );
}

/* Plain sph_whirlpool -- the final 2003 Whirlpool, which is what the reference
 * links. This tree's own whirlpool/whirlpoolx algos call sph_whirlpool1
 * (Whirlpool-T) instead, so copying from them gives a different hash. */
static inline void mega_whirlpool( megabtx_context_overlay *ctx, void *hash )
{
   sph_whirlpool_init( &ctx->whirlpool );
   sph_whirlpool( &ctx->whirlpool, hash, 64 );
   sph_whirlpool_close( &ctx->whirlpool, hash );
}

static inline void mega_sha512( megabtx_context_overlay *ctx, void *hash )
{
   sph_sha512_init( &ctx->sha512 );
   sph_sha512( &ctx->sha512, hash, 64 );
   sph_sha512_close( &ctx->sha512, hash );
}

static inline void mega_gost( megabtx_context_overlay *ctx, void *hash )
{
   sph_gost512_init( &ctx->gost );
   sph_gost512( &ctx->gost, hash, 64 );
   sph_gost512_close( &ctx->gost, hash );
}

/* haval256_5 digests 256 bits, so this writes only the low 32 bytes of the
 * 64-byte buffer and the high 32 are left holding the tail of whatever wrote
 * the buffer immediately before (sha512 in case 16, gost512 in case 19). The
 * next slot hashes all 64. That is the reference's behaviour, not an oversight
 * here: zeroing the buffer, or hashing into a fresh one, changes every digest
 * from that slot on. */
static inline void mega_haval( megabtx_context_overlay *ctx, void *hash )
{
   sph_haval256_5_init( &ctx->haval );
   sph_haval256_5( &ctx->haval, hash, 64 );
   sph_haval256_5_close( &ctx->haval, hash );
}

/* mega-btx.h:111-342. Slot 0 is blake512 over the 80-byte header; slots 1-22
 * run the case body named by perm[i] over the previous slot's output. The three
 * groups own disjoint case ranges (1-7, 8-15, 16-22), so one switch covers all
 * three loops.
 */
void megabtx_hash_perm( void *output, const void *input, const int *perm )
{
   unsigned char hash[64] __attribute__((aligned(64)));
   megabtx_context_overlay ctx;
   int i;

#if defined(__aarch64__)
   sph_blake512_init( &ctx.blake );
   sph_blake512( &ctx.blake, input, 80 );
   sph_blake512_close( &ctx.blake, hash );
#else
   blake512_full( &ctx.blake, hash, input, 80 );
#endif

   for ( i = 1; i < MEGA_SLOTS; i++ )
   {
      switch ( perm[i] )
      {
         // group 1
         case  1: mega_echo     ( &ctx, hash ); mega_blake    ( &ctx, hash ); break;
         case  2: mega_simd     ( &ctx, hash ); mega_bmw      ( &ctx, hash ); break;
         case  3: mega_groestl  ( &ctx, hash );                               break;
         case  4: mega_whirlpool( &ctx, hash ); mega_jh       ( &ctx, hash ); break;
         case  5: mega_gost     ( &ctx, hash ); mega_keccak   ( &ctx, hash ); break;
         case  6: mega_fugue    ( &ctx, hash ); mega_skein    ( &ctx, hash ); break;
         case  7: mega_shavite  ( &ctx, hash ); mega_luffa    ( &ctx, hash ); break;
         // group 2
         case  8: mega_whirlpool( &ctx, hash ); mega_cubehash ( &ctx, hash ); break;
         case  9: mega_jh       ( &ctx, hash ); mega_shavite  ( &ctx, hash ); break;
         case 10: mega_blake    ( &ctx, hash ); mega_simd     ( &ctx, hash ); break;
         case 11: mega_shabal   ( &ctx, hash ); mega_echo     ( &ctx, hash ); break;
         case 12: mega_hamsi    ( &ctx, hash );                               break;
         case 13: mega_bmw      ( &ctx, hash ); mega_fugue    ( &ctx, hash ); break;
         case 14: mega_keccak   ( &ctx, hash ); mega_shabal   ( &ctx, hash ); break;
         case 15: mega_luffa    ( &ctx, hash ); mega_whirlpool( &ctx, hash ); break;
         // group 3
         case 16: mega_sha512   ( &ctx, hash ); mega_haval    ( &ctx, hash ); break;
         case 17: mega_skein    ( &ctx, hash ); mega_groestl  ( &ctx, hash ); break;
         case 18: mega_simd     ( &ctx, hash ); mega_hamsi    ( &ctx, hash ); break;
         case 19: mega_gost     ( &ctx, hash ); mega_haval    ( &ctx, hash ); break;
         case 20: mega_cubehash ( &ctx, hash ); mega_sha512   ( &ctx, hash ); break;
         case 21: mega_echo     ( &ctx, hash ); mega_shavite  ( &ctx, hash ); break;
         case 22: mega_luffa    ( &ctx, hash ); mega_shabal   ( &ctx, hash ); break;
         default: break;
      }
   }

   memcpy( output, hash, 32 );   // trim256(): the low 32 bytes
}

// Slot order is per-job state: it depends on nTime and nothing else.
static __thread uint32_t s_ntime = UINT32_MAX;
static __thread int      s_perm[ MEGA_SLOTS ];

int megabtx_hash( void *output, const void *input, int thr_id )
{
   const uint32_t ntime = ((const uint32_t*)input)[17];
   if ( unlikely( ntime != s_ntime ) )
   {
      mega_permutation( s_perm, ntime );
      s_ntime = ntime;
   }
   megabtx_hash_perm( output, input, s_perm );
   return 1;
}

int scanhash_megabtx( struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t edata[20] __attribute__((aligned(64)));
   uint32_t hash[8] __attribute__((aligned(64)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 1;
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;
   const bool bench = opt_benchmark;

   v128_bswap32_80( edata, pdata );

   /* edata is now the wire header, so edata[17] is nTime. Re-derive the order
    * whenever it changes -- new job, ntime roll, or block change. */
   if ( edata[17] != s_ntime )
   {
      mega_permutation( s_perm, edata[17] );
      s_ntime = edata[17];
   }

   do
   {
      edata[19] = n;
      megabtx_hash_perm( hash, edata, s_perm );
      if ( unlikely( valid_hash( hash, ptarget ) && !bench ) )
      {
         pdata[19] = bswap_32( n );
         submit_solution( work, hash, mythr );
      }
      n++;
   } while ( n < last_nonce && !work_restart[thr_id].restart );

   *hashes_done = n - first_nonce;
   pdata[19] = n;
   return 0;
}

/* Startup self-test over five real BTX mainnet headers, asserted two ways: the
 * digest must be exact, and it must also land under that block's own nBits
 * target -- the second is what ties this to consensus rather than to itself.
 * Always run with BTX constants, so megamec's registration covers the shared
 * code too. */
bool megabtx_kat( void )
{
   int perm[ MEGA_SLOTS ];
   uint32_t pdata[20]  __attribute__((aligned(64)));
   uint32_t edata[20]  __attribute__((aligned(64)));
   uint32_t digest[8]  __attribute__((aligned(64)));
   uint32_t target[8]  __attribute__((aligned(64)));
   int i, k, fails = 0;

   for ( i = 0; i < MEGABTX_NUM_KATS; i++ )
   {
      const struct megabtx_kat *v = &megabtx_kats[i];
      uint32_t ntime;

      memcpy( edata, v->header, 80 );
      memcpy( target, v->target, 32 );

      /* Reach the header the way scanhash does -- back into work->data's
       * byte-swapped word convention, then the same v128_bswap32_80, then nTime
       * from edata[17]. Reading v->header directly would leave that extraction
       * untested, and a wrong word index rejects every share while the KAT
       * still passes. */
      for ( k = 0; k < 20; k++ ) pdata[k] = bswap_32( edata[k] );
      v128_bswap32_80( edata, pdata );
      if ( memcmp( edata, v->header, 80 ) )
      {
         applog( LOG_ERR, "megabtx KAT FAILED (header word order): %s", v->name );
         fails++;
         continue;
      }
      ntime = edata[17];

      mega_permutation_ex( perm, ntime, MEGABTX_BASE_TIMESTAMP, MEGABTX_VAR_1 );
      megabtx_hash_perm( digest, edata, perm );

      if ( memcmp( digest, v->digest, 32 ) )
      {
         applog( LOG_ERR, "megabtx KAT FAILED (digest): %s", v->name );
         fails++;
      }
      else if ( !valid_hash( digest, target ) )
      {
         applog( LOG_ERR, "megabtx KAT FAILED (over target): %s", v->name );
         fails++;
      }
   }

   if ( fails )
   {
      applog( LOG_ERR, "megabtx: %d of %d known-answer tests failed",
              fails, MEGABTX_NUM_KATS );
      return false;
   }
   /* Path reported from inside this TU, so a build matrix shows what was
    * actually selected rather than what the flags implied. */
   applog( LOG_NOTICE,
           "megabtx: %d/%d known-answer tests passed (real BTX blocks); "
           "%s, blake %s, luffa %s, groestl/echo/fugue %s",
           MEGABTX_NUM_KATS, MEGABTX_NUM_KATS,
#if defined(MEGABTX_4WAY)
           "scanhash 4x64",
#else
           "scanhash 1-way",
#endif
#if defined(__aarch64__)
           "sph", "sph",
#else
           "blake512_full", "luffa_full",
#endif
#if defined(__AES__) || defined(__ARM_FEATURE_AES)
           "AES"
#else
           "sph"
#endif
         );
   return true;
}
