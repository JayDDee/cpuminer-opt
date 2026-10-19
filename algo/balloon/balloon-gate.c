#include "algo-gate-api.h"
#include "balloon.h"

/* Balloon (Mateable, MTBC).
 *
 * Stock header handling: 80 bytes, big-endian words, nonce at word 19, so the
 * default build_extraheader applies. The digest goes to valid_hash() as raw
 * little-endian uint32[8] with no byte reversal — confirmed against a share
 * the pool accepted, see docs/algorithms/balloon.md.                        */

int scanhash_balloon( struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t _ALIGN(64) hash[8];
   uint32_t _ALIGN(64) edata[20];
#if BALLOON_USE_2WAY
   uint32_t _ALIGN(64) hash1[8];
   uint32_t _ALIGN(64) edata1[20];
#endif
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const int thr_id = mythr->id;
   uint32_t n = first_nonce;
   volatile uint8_t *restart = &( work_restart[thr_id].restart );
   const bool bench = opt_benchmark;

   /* 224 KiB per thread, allocated on the first call and kept. It also holds
    * the index table, which is why it must never be shared between threads. */
   balloon_ctx *ctx = balloon_thread_ctx();
   if ( unlikely( !ctx ) )
   {
      applog( LOG_ERR, "balloon thr%d: could not allocate %u KiB of scratch",
              thr_id, (unsigned)( sizeof(balloon_ctx) >> 10 ) );
      return -1;
   }

   for ( int i = 0; i < 19; i++ )
      be32enc( &edata[i], pdata[i] );

#if BALLOON_USE_2WAY

   /* Two nonces per pass. They differ only at word 19, so they share the salt
    * and therefore the index table — which is what makes the pairing free.
    * `max_nonce - 1` so the pair can never step past the range.            */
   memcpy( edata1, edata, sizeof edata1 );
   const uint32_t last_nonce = max_nonce - 1;

   do
   {
      be32enc( &edata [19], n     );
      be32enc( &edata1[19], n + 1 );
      balloon_hash_header_2way( ctx, edata, edata1, hash, hash1 );

      /* Both lanes are candidates and both can submit. */
      if ( unlikely( valid_hash( hash, ptarget ) && !bench ) )
      {
         pdata[19] = n;
         submit_solution( work, hash, mythr );
      }
      if ( unlikely( valid_hash( hash1, ptarget ) && !bench ) )
      {
         pdata[19] = n + 1;
         submit_solution( work, hash1, mythr );
      }
      n += 2;
   } while ( n < last_nonce && !(*restart) );

#else

   do
   {
      be32enc( &edata[19], n );
      balloon_hash_header( ctx, edata, hash );

      if ( unlikely( valid_hash( hash, ptarget ) && !bench ) )
      {
         pdata[19] = n;
         submit_solution( work, hash, mythr );
      }
      n++;
   } while ( n < max_nonce && !(*restart) );

#endif

   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

/* The gate hands the thread id; the context is __thread, so it is implicit. */
static void balloon_gate_thread_free( int thr_id )
{
   (void)thr_id;
   balloon_thread_ctx_free();
}

bool register_balloon_algo( algo_gate_t *gate )
{
   const char *failed = balloon_self_test();
   if ( failed )
   {
      applog( LOG_ERR, "balloon self-test failed: %s", failed );
      return false;
   }

   gate->scanhash = (void*)&scanhash_balloon;
   gate->miner_thread_free = (void*)&balloon_gate_thread_free;

   /* Nothing here is hand-vectorized. Whether SHA-NI or ARMv8 SHA2 is used is
    * decided inside sha256_full at compile time, so it is not claimed here. */
   gate->optimizations = SSE2_OPT | NEON_OPT;

   /* Measured, not assumed: a pool-accepted share was found at nonce 128454
    * against an expected 429497 at factor 1. Factor 256 predicts 1678.      */
   opt_target_factor = 1.0;

   return true;
}
