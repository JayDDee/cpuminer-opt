#include "curvehash-gate.h"
#include "curvehash-kat.h"
#include "curvehash-kernel.h"
#include "algo/sha/sha256-hash.h"
#include "secp256k1/include/secp256k1.h"

#include <string.h>

/* curvehash (Pulsar, PLSR) -- 8 rounds of "treat the SHA-256 digest as a
 * secp256k1 private key and hash the uncompressed public key". Consensus is
 * Pulsar's src/pulsar.cpp (Pulsar / GetCurvehashHash).
 *
 * ~2 kH/s/thread is correct, not a bug: the 8 scalar multiplications are the
 * whole cost. Coverage, not competitive mining -- see docs/algorithms/. */

/* ORACLE ONLY -- the hot path is curvehash_kg65(), from curvehash-kernel.c.
 * This is the pristine vendored public API, kept so the startup self-test can
 * differentially check the extracted kernel against untouched upstream. Shared
 * read-only: pubkey_create takes a const ctx and does not mutate it (only
 * context_randomize does). */
static secp256k1_context *curvehash_ctx = NULL;

bool curvehash_hash( void *output, const void *input )
{
   unsigned char pub[65];
   unsigned char *phash = (unsigned char*)output;

   sha256_full( phash, input, 80 );

   for ( int round = 0; round < 8; round++ )
   {
      /* Consensus asserts this is 1; phash == 0 or >= n is ~2^-128. Report it
       * so the caller skips the nonce, never fabricate a digest. */
      if ( unlikely( !curvehash_kg65( pub, phash ) ) )
         return false;

      sha256_full( phash, pub, 65 );
   }
   return true;
}

/* CURVEHASH_LANES nonces in lockstep, so each round's inversions batch.
 *
 * The 8 rounds are still strictly serial per lane -- round r+1's scalar is
 * SHA-256 of round r's point. The parallelism is purely across nonces, which
 * is the only axis this algorithm has.
 *
 * A lane whose scalar is invalid clears its bit in *active and stops being
 * hashed; its digest is meaningless and the caller must not test it. */
void curvehash_hash_batch( unsigned char out[][32], const unsigned char in[][80],
                           int lanes, uint32_t *active )
{
   unsigned char pub[CURVEHASH_MAX_LANES][65];
   uint32_t act = *active;
   int l, round;

   for ( l = 0; l < lanes; l++ )
      if ( act & ( 1u << l ) )
         sha256_full( out[l], in[l], 80 );

   for ( round = 0; round < 8; round++ )
   {
      curvehash_kg65_batch( pub, (const unsigned char (*)[32])out, lanes, &act );
      for ( l = 0; l < lanes; l++ )
         if ( act & ( 1u << l ) )
            sha256_full( out[l], pub[l], 65 );
   }

   *active = act;
}

/* Runtime differential: extracted kernel vs pristine vendored library.
 *
 * A KAT alone is not enough once the kernel is tuned. A k*G that is wrong for
 * *some* scalars still produces a well-formed 32-byte digest and still passes
 * a few fixed vectors -- the failure would surface only as pool rejects.
 * Checking random scalars against untouched upstream scales with the tuning,
 * and costs a few milliseconds once per process. */
static const char *curvehash_kernel_differential( int n )
{
   uint64_t s = 0x0123456789ABCDEFULL;

   for ( int i = 0; i < n; i++ )
   {
      unsigned char sec[32], from_kernel[65], from_vendored[65];
      secp256k1_pubkey pubkey;
      size_t publen = 65;
      int ok_kernel, ok_vendored;

      for ( int j = 0; j < 32; j += 8 )
      {
         uint64_t r;
         s ^= s >> 12; s ^= s << 25; s ^= s >> 27;
         r = s * 0x2545F4914F6CDD1DULL;
         for ( int b = 0; b < 8; b++ ) sec[j+b] = (unsigned char)( r >> (8*b) );
      }

      ok_kernel   = curvehash_kg65( from_kernel, sec );
      ok_vendored = secp256k1_ec_pubkey_create( curvehash_ctx, &pubkey, sec );

      if ( ok_kernel != ok_vendored )
         return "kernel vs vendored: disagree on scalar validity";
      if ( !ok_kernel )
         continue;

      secp256k1_ec_pubkey_serialize( curvehash_ctx, from_vendored, &publen,
                                     &pubkey, SECP256K1_EC_UNCOMPRESSED );
      if ( publen != 65 || memcmp( from_kernel, from_vendored, 65 ) )
         return "kernel vs vendored: point mismatch";
   }
   return NULL;
}

const char *curvehash_self_test( void )
{
   unsigned char out[32], hdr[80];

   for ( size_t i = 0; i < CURVEHASH_NUM_KATS; i++ )
   {
      if ( !curvehash_hash( out, curvehash_kats[i].header ) )
         return curvehash_kats[i].name;
      if ( memcmp( out, curvehash_kats[i].digest, 32 ) )
         return curvehash_kats[i].name;
   }

   /* Non-vacuity: without this, a KAT that hashed a constant would pass. */
   memcpy( hdr, curvehash_kats[0].header, 80 );
   hdr[40] ^= 0x01;
   if ( !curvehash_hash( out, hdr ) )
      return "non-vacuity (unexpected invalid seckey)";
   if ( !memcmp( out, curvehash_kats[0].digest, 32 ) )
      return "non-vacuity (flipped header gave the same digest)";

   /* The BATCH path is what scanhash actually runs. Without this the KAT would
    * cover only the one-nonce path and leave the shipped one untested. Giving
    * each lane a different vector also catches lane crossing: a bug that fed
    * lane 0's scalar to every lane would still pass a one-vector check. */
   {
      unsigned char hdrs[CURVEHASH_LANES][80], digs[CURVEHASH_LANES][32];
      uint32_t active = ( CURVEHASH_LANES >= 32 )
                      ? 0xffffffffu : ( ( 1u << CURVEHASH_LANES ) - 1 );
      int l;

      for ( l = 0; l < CURVEHASH_LANES; l++ )
         memcpy( hdrs[l], curvehash_kats[l % CURVEHASH_NUM_KATS].header, 80 );

      curvehash_hash_batch( digs, (const unsigned char (*)[80])hdrs,
                            CURVEHASH_LANES, &active );

      for ( l = 0; l < CURVEHASH_LANES; l++ )
      {
         if ( !( active & ( 1u << l ) ) )
            return "batch path (unexpected invalid seckey)";
         if ( memcmp( digs[l],
                      curvehash_kats[l % CURVEHASH_NUM_KATS].digest, 32 ) )
            return "batch path digest mismatch";
      }
   }

   return curvehash_kernel_differential( 32 );
}

int scanhash_curvehash( struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t _ALIGN(64) edata[20];
   unsigned char _ALIGN(64) hdr[CURVEHASH_LANES][80];
   unsigned char _ALIGN(64) dig[CURVEHASH_LANES][32];
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;
   const bool bench = opt_benchmark;
   volatile uint8_t *restart = &( work_restart[thr_id].restart );
   const uint32_t all_lanes = ( CURVEHASH_LANES >= 32 )
                            ? 0xffffffffu : ( ( 1u << CURVEHASH_LANES ) - 1 );
   /* Stop LANES short so n + l never runs past max_nonce. */
   const uint32_t last_nonce = max_nonce > (uint32_t)CURVEHASH_LANES
                             ? max_nonce - (uint32_t)CURVEHASH_LANES : 0;
   int l;

   /* Yields the LE wire header: work->data is stored word-swapped relative to
    * the wire (std_build_block_header), and sha256_full() hashes plain bytes.
    * Looks like a double swap, is not -- do not "fix" it. */
   v128_bswap32_80( edata, pdata );
   for ( l = 0; l < CURVEHASH_LANES; l++ )
      memcpy( hdr[l], edata, 80 );

   do
   {
      uint32_t active = all_lanes;

      /* Bytes 76..79 are the nonce, exactly where edata[19] sat. */
      for ( l = 0; l < CURVEHASH_LANES; l++ )
      {
         uint32_t nl = n + (uint32_t)l;
         memcpy( hdr[l] + 76, &nl, 4 );
      }

      curvehash_hash_batch( dig, (const unsigned char (*)[80])hdr,
                            CURVEHASH_LANES, &active );

      /* Test EVERY lane, and submit n + l, not n. */
      for ( l = 0; l < CURVEHASH_LANES; l++ )
      {
         if ( unlikely( !( active & ( 1u << l ) ) ) )
            continue;
         if ( unlikely( valid_hash( (uint32_t*)dig[l], ptarget ) && !bench ) )
         {
            be32enc( &pdata[19], n + (uint32_t)l );
            submit_solution( work, (uint32_t*)dig[l], mythr );
         }
      }
      n += CURVEHASH_LANES;
   } while ( likely( n < last_nonce && !( *restart ) ) );

   *hashes_done = n - first_nonce;
   pdata[19] = n;
   return 0;
}

bool register_curvehash_algo( algo_gate_t *gate )
{
   if ( !curvehash_kernel_init() )
   {
      applog( LOG_ERR, "curvehash: could not build the kernel gen table" );
      return false;
   }

   /* The oracle. Costs a second 64 KB table at startup and is not touched
    * again after the self-test -- cheap insurance for a tunable kernel. */
   if ( !curvehash_ctx )
      curvehash_ctx = secp256k1_context_create( SECP256K1_CONTEXT_SIGN );
   if ( !curvehash_ctx )
   {
      applog( LOG_ERR, "curvehash: could not create a secp256k1 context" );
      return false;
   }

   const char *failed = curvehash_self_test();
   if ( failed )
   {
      applog( LOG_ERR, "curvehash self-test failed: %s", failed );
      return false;
   }

   /* Which library config the KERNEL compiled to -- asked from inside its TU,
    * because the selection macros are invisible from here. */
   applog( LOG_DEBUG, "curvehash: extracted kernel, %s, %d lane(s)",
           curvehash_kernel_config(), CURVEHASH_LANES );

   gate->scanhash = (void*)&scanhash_curvehash;

   /* Nothing hand-vectorized here; sha256_full picks SHA-NI / ARMv8 SHA2 at
    * compile time and is ~1% of a hash, so nothing is claimed. */
   gate->optimizations = SSE2_OPT | NEON_OPT;

   /* Plain 256-bit output. Confirmed by two mainnet blocks whose digests sit
    * under the nBits target read as a LE uint256, as valid_hash does. */
   opt_target_factor = 1.0;

   return true;
}
