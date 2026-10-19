/*
 * sha3t / sha3-256t — triple NIST SHA3-256 over the 80-byte header.
 * BitcoinIII (BC3), Fjarcode (FJAR).
 *
 *    hash = SHA3-256( SHA3-256( SHA3-256( header80 ) ) )
 *
 * Same primitive and padding as sha3d, one more iteration — but two consensus
 * differences the name similarity hides. Get either wrong and the KAT still
 * passes while every share is rejected:
 *
 *   1. sha3d overrides gen_merkle_root; sha3t keeps the DEFAULT sha256d one.
 *      (BC3 merkle roots recompute from their txids with sha256d, not sha3d.)
 *   2. SHA3 padding (0x06), not Keccak (0x01) — hard_coded_eb = 6, set in
 *      register_sha3t_algo before any hashing, self-test included.
 *
 * opt_target_factor stays 1.0: BC3 is Bitcoin with only the block hash swapped.
 */

#include "keccak-gate.h"
#include "sha3t-kat.h"

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include "sph_keccak.h"
#include "keccak-hash-4way.h"   // sha3_256_prepad80 / _prepad32

// Always compiled: the n-way self-tests use it as differential oracle even
// where the scalar scanhash below is compiled out.
void sha3t_hash( void *state, const void *input )
{
   uint32_t _ALIGN(64) buffer[16];
   sph_keccak256_context ctx_keccak;

   sph_keccak256_init( &ctx_keccak );
   sph_keccak256( &ctx_keccak, input, 80 );
   sph_keccak256_close( &ctx_keccak, buffer );

   sph_keccak256_init( &ctx_keccak );
   sph_keccak256( &ctx_keccak, buffer, 32 );
   sph_keccak256_close( &ctx_keccak, buffer );

   sph_keccak256_init( &ctx_keccak );
   sph_keccak256( &ctx_keccak, buffer, 32 );
   sph_keccak256_close( &ctx_keccak, state );
}

static void sha3t_log_mismatch( const char *what, const uint8_t *got,
                                const uint8_t *expected )
{
   char g[65], e[65];
   for ( int i = 0; i < 32; i++ )
   {
      sprintf( g + i*2, "%02x", got[i] );
      sprintf( e + i*2, "%02x", expected[i] );
   }
   applog( LOG_ERR, "sha3t %s FAILED (consensus KAT mismatch)", what );
   applog( LOG_ERR, "  got:      %s", g );
   applog( LOG_ERR, "  expected: %s", e );
}

// Anchor the scalar reference to consensus. Also called by the n-way
// self-tests, so a batched build is anchored before its differential runs.
bool sha3t_kat_check( void )
{
   uint8_t hash[32];

   sha3t_hash( hash, sha3t_kat0_input );
   if ( memcmp( hash, sha3t_kat0_expected, 32 ) != 0 )
   {
      sha3t_log_mismatch( "block 44172", hash, sha3t_kat0_expected );
      return false;
   }

   sha3t_hash( hash, sha3t_kat1_input );
   if ( memcmp( hash, sha3t_kat1_expected, 32 ) != 0 )
   {
      sha3t_log_mismatch( "block 39663", hash, sha3t_kat1_expected );
      return false;
   }
   return true;
}

#if !defined(SHA3T_8WAY) && !defined(SHA3T_4WAY) && !defined(SHA3T_2WAY)

// Scalar mining driver: the same three passes as sha3t_hash(), driven from a
// pre-padded state instead of init/update/close. Each message is a single rate
// block (80, 32, 32 against a 136 B rate), so the padded block is known up
// front: no buffer, no padding VLA, 2 NOT64s per pass instead of 6. The 1-way
// analogue of sha3t_{8,4,2}x64_prepad; the kernel itself is shared, not new.
// NOTE: SHA3 padding (0x06) is baked in and hard_coded_eb is ignored -- right
// for sha3t, wrong for keccak/sha3d. See keccak-hash-4way.h.
void sha3t_hash_prepad( void *state, const void *input )
{
   uint32_t _ALIGN(64) pass1[8];
   uint32_t _ALIGN(64) pass2[8];

   // Separate buffers: sha3_256_prepad32 happens to read src fully before
   // writing dst, but it does not promise to.
   sha3_256_prepad80( pass1, input );
   sha3_256_prepad32( pass2, pass1 );
   sha3_256_prepad32( state, pass2 );
}

#define SHA3T_1WAY_DIFF_ITERS 64

// Differential against sha3t_hash(), which reaches keccak through sph_keccak.c
// and so shares no code with this path. Fatal, like the batched widths' tests.
bool sha3t_1way_self_test( void )
{
   if ( !sha3t_kat_check() )
   {
      applog( LOG_ERR, "sha3t scalar reference KAT mismatch - cannot anchor" );
      return false;
   }

   uint32_t lcg = 0x9e3779b9u;
   for ( int it = 0; it < SHA3T_1WAY_DIFF_ITERS; it++ )
   {
      uint32_t _ALIGN(64) edata[20];
      uint32_t _ALIGN(64) ref[8];
      uint32_t _ALIGN(64) got[8];

      for ( int i = 0; i < 20; i++ )
      {
         lcg = lcg * 1664525u + 1013904223u;
         edata[i] = lcg;
      }

      sha3t_hash( ref, edata );
      sha3t_hash_prepad( got, edata );

      if ( memcmp( ref, got, 32 ) != 0 )
      {
         applog( LOG_ERR, "sha3t 1-way differential FAILED: iter %d", it );
         return false;
      }
   }

   // Name the live driver so two builds cannot log the same line.
   applog( LOG_NOTICE,
           "sha3t 1-way self-test PASSED (consensus KAT + %d differential), "
           "mining driver: %s",
           SHA3T_1WAY_DIFF_ITERS, SHA3T_SCALAR_HASH_NAME );
   return true;
}

int scanhash_sha3t( struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t _ALIGN(64) hash64[8];
   uint32_t _ALIGN(64) endiandata[20];
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   uint32_t n = pdata[19];
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce;
   const int thr_id = mythr->id;
   const bool bench = opt_benchmark;

   for ( int i = 0; i < 19; i++ )
      be32enc( &endiandata[i], pdata[i] );

   do {
      be32enc( &endiandata[19], n );
      SHA3T_SCALAR_HASH( hash64, endiandata );

      if ( unlikely( valid_hash( hash64, ptarget ) && !bench ) )
      {
         pdata[19] = n;
         submit_solution( work, hash64, mythr );
      }
      n++;
   } while ( likely( n < last_nonce && !work_restart[thr_id].restart ) );

   *hashes_done = n - first_nonce;
   pdata[19] = n;
   return 0;
}

#endif
