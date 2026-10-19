#include <string.h>
#include <inttypes.h>

#include "miner.h"
#include "sha256-hash.h"
#include "sha256dv.h"

/*
 * SHA-256D Veil (sha256dv).
 *
 * Veil's SHA256Dv pool computes the block-header midstate (stage-1) itself
 * and hands the miner a pre-hashed midstate. The miner builds the 80-byte
 * "stage2" buffer, double-SHA-256s it and searches a 64-bit nonce split into
 * a low and high 32-bit word.
 *
 * Stage2 layout (matches the reference veil_sha256d_miner.py):
 *
 *   version_le  (4)
 *   midstate_be (32)
 *   merkle_le   (32)   = reversed merkle_be
 *   ntime_le    (4)
 *   nonce_lo_le (4)
 *   nonce_hi_le (4)
 *
 * The job's midstate/merkle/ntime/nonce_hi arrive over a bespoke Stratum
 * notify (see stratum_notify_sha256dv in util.c); the share is submitted with
 * a custom mining.submit carrying nonce_hi, ntime and nonce_lo (see
 * veil_sha256dv_build_stratum_request in cpu-miner.c).
 */
static inline void veil_sha256dv_build_stage2( uint8_t out[80],
                                               const struct work *work,
                                               uint32_t nonce_low,
                                               uint32_t nonce_high )
{
   uint8_t *p = out;

   // 1) VERSION (little-endian) from work->data[0] in host order
   le32enc( p, work->data[0] );
   p += 4;

   // 2) MIDSTATE (big-endian) - copy as is
   memcpy( p, work->veil_midstate_be, 32 );
   p += 32;

   // 3) MERKLE (little-endian) = reversed merkle_be
   for ( int i = 0; i < 32; i++ )
      p[i] = work->veil_merkle_be[31 - i];
   p += 32;

   // 4) NTIME (little-endian)
   le32enc( p, work->veil_ntime );
   p += 4;

   // 5) nonce_low (little-endian)
   le32enc( p, nonce_low );
   p += 4;

   // 6) nonce_high (little-endian)
   le32enc( p, nonce_high );
   p += 4;
}

// Silent equivalent of fulltest(): hash and target are 8 x uint32 LE,
// compared from the most significant word.
static inline bool veil_hash_meets_target( const uint32_t *hash,
                                           const uint32_t *target )
{
   for ( int i = 7; i >= 0; i-- )
   {
      if ( hash[i] > target[i] ) return false;
      if ( hash[i] < target[i] ) return true;
   }
   return true;
}

int scanhash_sha256dv( struct work *work, uint32_t max_nonce,
                       uint64_t *hashes_done, struct thr_info *mythr )
{
   const int thr_id = mythr->id;

   // Not a Veil SHA256Dv job, nothing to do.
   if ( !work->veil_sha256dv )
      return 0;

   uint8_t  stage2[80] __attribute__((aligned(64)));
   uint8_t  hash_be[32];
   uint32_t hash_le[8];

   // Per-thread nonce striping: base nonce_hi from the job, offset by thr_id.
   uint32_t nonce_hi = work->veil_nonce_hi + (uint32_t)thr_id;
   uint32_t nonce_lo = 0;

   const uint32_t *ptarget = work->target;
   *hashes_done = 0;

   while ( !work_restart[thr_id].restart )
   {
      veil_sha256dv_build_stage2( stage2, work, nonce_lo, nonce_hi );

      sha256_full( hash_be, stage2,  80 );
      sha256_full( hash_be, hash_be, 32 );

      for ( int i = 0; i < 8; i++ )
         hash_le[i] = be32dec( hash_be + i * 4 );

      if ( veil_hash_meets_target( hash_le, ptarget ) )
      {
         uint64_t nonce64 = ( (uint64_t)nonce_hi << 32 ) | nonce_lo;

         // Stash the winning nonce pair for submit.
         work->veil_nonce_lo = nonce_lo;
         work->veil_nonce_hi = nonce_hi;

         if ( !submit_solution( work, hash_be, mythr ) )
            applog( LOG_WARNING,
                    "SHA256Dv[%d]: submit_solution failed for job=%s (nonce64=%016"
                    PRIx64 ")",
                    thr_id, work->job_id ? work->job_id : "(null)", nonce64 );

         (*hashes_done)++;

         // Advance nonce_hi so this thread's next range does not overlap.
         work->veil_nonce_hi += (uint32_t)opt_n_threads;

         return 0;
      }

      nonce_lo++;
      if ( nonce_lo == 0 )
         nonce_hi += (uint32_t)opt_n_threads;

      (*hashes_done)++;

      if ( max_nonce && nonce_lo >= max_nonce )
      {
         // Range exhausted without a share: advance the stored base by
         // opt_n_threads (same as the found-share path) so the next call
         // scans a fresh range instead of rehashing this one. The per-thread
         // thr_id offset is re-applied at the top of the next call.
         work->veil_nonce_hi += (uint32_t)opt_n_threads;
         break;
      }
   }

   return 0;
}

bool register_sha256dv_algo( algo_gate_t *gate )
{
   gate->scanhash = (void*)&scanhash_sha256dv;
   return true;
}
