#include "soterg-gate.h"
#include "soterg-kat.h"
#include <string.h>
#include <stdio.h>

#include "algo/blake/sph_blake.h"
#include "algo/shabal/sph_shabal.h"
#include "algo/groestl/sph_groestl.h"
#include "algo/jh/sph_jh.h"
#include "algo/keccak/sph_keccak.h"
#include "algo/skein/sph_skein.h"
#include "algo/luffa/sph_luffa.h"
#include "algo/cubehash/sph_cubehash.h"
#include "algo/simd/sph_simd.h"
#include "algo/echo/sph_echo.h"
#include "algo/hamsi/sph_hamsi.h"
#include "algo/sha/sph_sha2.h"
#include "algo/keccak/keccak-gate.h"      // hard_coded_eb
#include "x16r-gate.h"                    // X16R_8WAY / X16R_4WAY

#if defined(__AES__) || defined(__ARM_FEATURE_AES)
  #include "algo/groestl/aes_ni/hash-groestl.h"
  #include "algo/echo/aes_ni/hash_api.h"
#endif

union soterg_context_overlay
{
   sph_blake512_context    blake;
   sph_shabal512_context   shabal;
   sph_jh512_context       jh;
   sph_keccak512_context   keccak;
   sph_skein512_context    skein;
   sph_luffa512_context    luffa;
   sph_cubehash512_context cube;
   sph_simd512_context     simd;
   sph_hamsi512_context    hamsi;
   sph_sha512_context      sha512;
   sph_sha256_context      sha256;
#if defined(__AES__) || defined(__ARM_FEATURE_AES)
   hashState_groestl       groestl;
   hashState_echo          echo;
#else
   sph_groestl512_context  groestl;
   sph_echo512_context     echo;
#endif
} __attribute__ ((aligned (64)));
typedef union soterg_context_overlay soterg_context_overlay;

static __thread char soterg_hash_order[ SOTERG_FUNC_COUNT + 1 ] = { 0 };

/* Order derivation. The seed is sha256d over the four bytes of the masked
 * time, then nibbles 48..63 of that digest are rejection-sampled down to
 * 0..11 -- this is not x16r's plain nibble walk. */
static uint8_t soterg_nibble( const uint8_t *h, int index )
{
   index = 63 - index;
   if ( index & 1 ) return h[ index >> 1 ] >> 4;
   return h[ index >> 1 ] & 0x0F;
}

static int soterg_select( const uint8_t *seed, int index )
{
   const int start = 48, mask = 0xF;
   int pos = start + ( index & mask );
   int nibble = soterg_nibble( seed, pos );

   if ( nibble < SOTERG_FUNC_COUNT ) return nibble;
   for ( int i = 1; i < 16; i++ )
   {
      pos = start + ( ( index + i ) & mask );
      nibble = soterg_nibble( seed, pos );
      if ( nibble < SOTERG_FUNC_COUNT ) return nibble;
   }
   return nibble % SOTERG_FUNC_COUNT;
}

/* soterg stage id -> x16r stage id, for the n-way path, which reuses x16r's
 * cascade. The two enums are NOT the same: SHABAL is 1 here and 13 there,
 * SIMD 8 vs 9, ECHO 9 vs 10, HAMSI 10 vs 11, SHA512 11 vs 15. x16r:
 *   BLAKE 0, BMW 1, GROESTL 2, JH 3, KECCAK 4, SKEIN 5, LUFFA 6, CUBEHASH 7,
 *   SHAVITE 8, SIMD 9, ECHO 10, HAMSI 11, FUGUE 12, SHABAL 13, WHIRLPOOL 14,
 *   SHA_512 15                                                              */
static const uint8_t soterg_to_x16r[ SOTERG_FUNC_COUNT ] =
   { 0, 13, 2, 3, 4, 5, 6, 7, 9, 10, 11, 15 };

void soterg_order_to_x16r_ids( const char *src, char *dst )
{
   for ( int i = 0; i < SOTERG_FUNC_COUNT; i++ )
   {
      const char e = src[i];
      const uint8_t id = e >= 'A' ? e - 'A' + 10 : e - '0';
      const uint8_t x = soterg_to_x16r[ id ];
      dst[i] = x < 10 ? '0' + x : 'A' + ( x - 10 );
   }
   dst[ SOTERG_FUNC_COUNT ] = 0;
}

void soterg_getAlgoString( uint32_t ntime, char *output )
{
   uint8_t seed[32], tmp[32];
   int32_t masked = (int32_t)( ntime & SOTERG_TIME_MASK );
   sph_sha256_context sha;

   sph_sha256_init( &sha );
   sph_sha256( &sha, &masked, sizeof masked );
   sph_sha256_close( &sha, tmp );
   sph_sha256_init( &sha );
   sph_sha256( &sha, tmp, 32 );
   sph_sha256_close( &sha, seed );

   for ( int i = 0; i < SOTERG_FUNC_COUNT; i++ )
   {
      int sel = soterg_select( seed, i );
      output[i] = sel < 10 ? '0' + sel : 'A' + ( sel - 10 );
   }
   output[ SOTERG_FUNC_COUNT ] = '\0';
}

int soterg_hash( void *output, const void *input, int thrid )
{
   uint32_t _ALIGN(64) hash[16];
   soterg_context_overlay ctx;
   const void *in = input;
   int size = 80;

   for ( int i = 0; i < SOTERG_FUNC_COUNT; i++ )
   {
      const char elem = soterg_hash_order[i];
      const uint8_t algo = elem >= 'A' ? elem - 'A' + 10 : elem - '0';

      switch ( algo )
      {
         case SOTERG_BLAKE:
            sph_blake512_init( &ctx.blake );
            sph_blake512( &ctx.blake, in, size );
            sph_blake512_close( &ctx.blake, hash );
         break;
         case SOTERG_SHABAL:
            sph_shabal512_init( &ctx.shabal );
            sph_shabal512( &ctx.shabal, in, size );
            sph_shabal512_close( &ctx.shabal, hash );
         break;
         case SOTERG_GROESTL:
#if defined(__AES__) || defined(__ARM_FEATURE_AES)
            groestl512_full( &ctx.groestl, hash, in, size<<3 );
#else
            sph_groestl512_init( &ctx.groestl );
            sph_groestl512( &ctx.groestl, in, size );
            sph_groestl512_close( &ctx.groestl, hash );
#endif
         break;
         case SOTERG_JH:
            sph_jh512_init( &ctx.jh );
            sph_jh512( &ctx.jh, in, size );
            sph_jh512_close( &ctx.jh, hash );
         break;
         case SOTERG_KECCAK:
            sph_keccak512_init( &ctx.keccak );
            sph_keccak512( &ctx.keccak, in, size );
            sph_keccak512_close( &ctx.keccak, hash );
         break;
         case SOTERG_SKEIN:
            sph_skein512_init( &ctx.skein );
            sph_skein512( &ctx.skein, in, size );
            sph_skein512_close( &ctx.skein, hash );
         break;
         case SOTERG_LUFFA:
            sph_luffa512_init( &ctx.luffa );
            sph_luffa512( &ctx.luffa, in, size );
            sph_luffa512_close( &ctx.luffa, hash );
         break;
         case SOTERG_CUBEHASH:
            sph_cubehash512_init( &ctx.cube );
            sph_cubehash512( &ctx.cube, in, size );
            sph_cubehash512_close( &ctx.cube, hash );
         break;
         case SOTERG_SIMD:
            sph_simd512_init( &ctx.simd );
            sph_simd512( &ctx.simd, in, size );
            sph_simd512_close( &ctx.simd, hash );
         break;
         case SOTERG_ECHO:
#if defined(__AES__) || defined(__ARM_FEATURE_AES)
            echo_full( &ctx.echo, (BitSequence*)hash, 512,
                       (const BitSequence*)in, size );
#else
            sph_echo512_init( &ctx.echo );
            sph_echo512( &ctx.echo, in, size );
            sph_echo512_close( &ctx.echo, hash );
#endif
         break;
         case SOTERG_HAMSI:
            sph_hamsi512_init( &ctx.hamsi );
            sph_hamsi512( &ctx.hamsi, in, size );
            sph_hamsi512_close( &ctx.hamsi, hash );
         break;
         case SOTERG_SHA512:
            sph_sha512_init( &ctx.sha512 );
            sph_sha512( &ctx.sha512, in, size );
            sph_sha512_close( &ctx.sha512, hash );
         break;
         default:
            return 0;
      }
      /* work_restart is a pointer, NULL until the miner threads are
       * allocated -- which happens AFTER algo registration. thrid < 0 means
       * "no restart check", used by the start-up self-test. */
      if ( thrid >= 0 && work_restart[thrid].restart ) return 0;
      in = (const void*) hash;
      size = 64;
   }
   memcpy( output, hash, 32 );      /* uint512::trim256() */
   return 1;
}

int scanhash_soterg( struct work *work, uint32_t max_nonce,
                     uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t _ALIGN(64) hash32[8];
   uint32_t _ALIGN(64) edata[20];
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const int thr_id = mythr->id;
   uint32_t nonce = first_nonce;
   volatile uint8_t *restart = &( work_restart[thr_id].restart );
   const bool bench = opt_benchmark;

   if ( bench ) ptarget[7] = 0x0cff;

   v128_bswap32_80( edata, pdata );

   /* Order depends on nTime only, so it is resolved once per job. */
   /* Keyed on the MASKED time: the order only changes when the 96-second
    * bucket does, so this avoids re-deriving and re-logging every job. */
   static __thread uint32_t s_masked = UINT32_MAX;
   uint32_t ntime = bswap_32( pdata[17] );
   uint32_t masked = ntime & SOTERG_TIME_MASK;
   if ( s_masked != masked )
   {
      soterg_getAlgoString( ntime, soterg_hash_order );
      s_masked = masked;
      if ( !opt_quiet && !thr_id )
         applog( LOG_INFO, "hash order %s (%08x, masked %08x)",
                 soterg_hash_order, ntime, ntime & SOTERG_TIME_MASK );
   }

   do
   {
      edata[19] = nonce;
      if ( soterg_hash( hash32, edata, thr_id ) )
      if ( unlikely( valid_hash( hash32, ptarget ) && !bench ) )
      {
         pdata[19] = bswap_32( nonce );
         submit_solution( work, hash32, mythr );
      }
      nonce++;
   } while ( nonce < max_nonce && !(*restart) );

   pdata[19] = nonce;
   *hashes_done = pdata[19] - first_nonce;
   return 0;
}

/* Startup gate: real mainnet headers, digest exact against the block's own
 * hash. Also exercises the n-way path, whose id translation and lane plumbing
 * the 1-way check cannot cover. */
static bool soterg_self_test( void )
{
   char saved[ SOTERG_FUNC_COUNT + 1 ];
   uint32_t hash32[8];
   uint32_t other[8];
   uint8_t bad[80];
   int pass = 0;

   memcpy( saved, soterg_hash_order, sizeof saved );

   for ( unsigned k = 0; k < SOTERG_KAT_COUNT; k++ )
   {
      soterg_getAlgoString( soterg_kat[k].ntime, soterg_hash_order );
      if ( !soterg_hash( hash32, soterg_kat[k].header, -1 ) )
      {
         applog( LOG_ERR, "soterg KAT %u: hash aborted", k );
         goto fail;
      }
      if ( memcmp( hash32, soterg_kat[k].digest, 32 ) != 0 )
      {
         applog( LOG_ERR, "soterg KAT %u (height %u, order %s): digest mismatch",
                 k, soterg_kat[k].height, soterg_hash_order );
         goto fail;
      }
      pass++;
   }

#if defined(X16R_8WAY) || defined(X16R_4WAY) || defined(X16R_2WAY)
   /* n-way: the same headers through x16r's interleaved cascade. prehash
    * byte-swaps and interleaves pdata into every lane, so each lane already
    * carries that block's own nonce and every lane must return its digest --
    * a wrong id map or a swapped lane fails here rather than on a pool.
    *
    * x16r's generic checks work_restart[thrid] itself, and work_restart is
    * still NULL during registration, so point it at a cleared static and
    * restore it before returning. */
   {
      struct work_restart *saved_restart = work_restart;
      static struct work_restart selftest_restart[1] = { { 0 } };
#if defined(X16R_8WAY)
      const int lanes = 8;
      uint32_t vdata[20*8] __attribute__ ((aligned (64)));
      uint32_t nhash[16*8] __attribute__ ((aligned (128)));
#elif defined(X16R_4WAY)
      const int lanes = 4;
      uint32_t vdata[20*4] __attribute__ ((aligned (64)));
      uint32_t nhash[16*4] __attribute__ ((aligned (64)));
#else
      const int lanes = 2;
      uint32_t vdata[20*2] __attribute__ ((aligned (64)));
      uint32_t nhash[16*2] __attribute__ ((aligned (64)));
#endif
      char xorder[ SOTERG_FUNC_COUNT + 1 ];
      /* aligned like work->data: the prehash paths use aligned 256/512-bit
       * loads on it (HAMSI's mm256_bswap32_intrlv80_4x64 does), so an
       * unaligned buffer segfaults on some first-stage functions and not
       * others. */
      uint32_t pdata[20] __attribute__ ((aligned (64)));
      int nlanes = 0, bad_lane = 0;

      if ( !work_restart ) work_restart = selftest_restart;

      for ( unsigned k = 0; k < SOTERG_KAT_COUNT && !bad_lane; k++ )
      {
         const uint32_t *hw = (const uint32_t*)soterg_kat[k].header;
         for ( int i = 0; i < 20; i++ ) pdata[i] = bswap_32( hw[i] );

         soterg_getAlgoString( soterg_kat[k].ntime, soterg_hash_order );
         soterg_order_to_x16r_ids( soterg_hash_order, xorder );
         memcpy( x16r_hash_order, xorder, sizeof xorder );

#if defined(X16R_8WAY)
         x16r_8way_prehash( vdata, pdata, x16r_hash_order );
         if ( !x16r_8way_hash_generic( nhash, vdata, 0, x16r_hash_order,
                                       SOTERG_FUNC_COUNT ) )
            bad_lane = 1;
#elif defined(X16R_4WAY)
         x16r_4way_prehash( vdata, pdata, x16r_hash_order );
         if ( !x16r_4way_hash_generic( nhash, vdata, 0, x16r_hash_order,
                                       SOTERG_FUNC_COUNT ) )
            bad_lane = 1;
#else
         x16r_2x64_prehash( vdata, pdata, x16r_hash_order );
         if ( !x16r_2x64_hash_generic( nhash, vdata, 0, x16r_hash_order,
                                       SOTERG_FUNC_COUNT ) )
            bad_lane = 1;
#endif
         for ( int l = 0; l < lanes && !bad_lane; l++ )
         {
            /* the generic emits 64 bytes per lane, so the stride is 16
             * uint32 -- x16rt reads (i<<3) only because it goes through
             * the x16r_8way_hash wrapper, which repacks to 32. */
            if ( memcmp( nhash + (l<<4), soterg_kat[k].digest, 32 ) != 0 )
            {
               applog( LOG_ERR, "soterg %d-way KAT %u lane %d: digest mismatch",
                       lanes, k, l );
               bad_lane = 1;
            }
            else nlanes++;
         }
      }

      work_restart = saved_restart;
      if ( bad_lane ) goto fail;
      applog( LOG_NOTICE, "soterg %d-way matches 1-way on %d/%d lanes",
              lanes, nlanes, lanes * SOTERG_KAT_COUNT );
   }
#endif

   /* Non-vacuity: one flipped nonce bit must change the digest. */
   memcpy( bad, soterg_kat[0].header, 80 );
   bad[79] ^= 1;
   soterg_getAlgoString( soterg_kat[0].ntime, soterg_hash_order );
   soterg_hash( other, bad, -1 );
   if ( memcmp( other, soterg_kat[0].digest, 32 ) == 0 )
   {
      applog( LOG_ERR, "soterg KAT is vacuous: altered header gave the same digest" );
      goto fail;
   }

   memcpy( soterg_hash_order, saved, sizeof saved );
   applog( LOG_NOTICE, "soterg self-test PASSED (%d real mainnet headers, "
           "height %u to %u)", pass, soterg_kat[0].height,
           soterg_kat[SOTERG_KAT_COUNT-1].height );
   return true;

fail:
   memcpy( soterg_hash_order, saved, sizeof saved );
   return false;
}

bool register_soterg_algo( algo_gate_t* gate )
{
   /* sph_keccak512's close() takes its padding byte from this global: 1 is
    * Keccak, 6 is SHA3. The cascade needs Keccak. It is keccak-gate.c's
    * default, but pin it rather than inherit whatever ran last. */
   hard_coded_eb = 1;

   if ( !soterg_self_test() ) return false;

#if defined(X16R_8WAY)
   gate->scanhash      = (void*)&scanhash_soterg_8way;
#elif defined(X16R_4WAY)
   gate->scanhash      = (void*)&scanhash_soterg_4way;
#elif defined(X16R_2WAY)
   gate->scanhash      = (void*)&scanhash_soterg_2x64;
#else
   gate->scanhash      = (void*)&scanhash_soterg;
#endif
   gate->hash          = (void*)&soterg_hash;
   gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT | AVX512_OPT | NEON_OPT;
   opt_target_factor   = 1.0;
   return true;
}
