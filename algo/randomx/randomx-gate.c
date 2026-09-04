/* RandomX algo gate: scanhash, thread lifecycle, registration.
 *
 * The work item is not an 80-byte bitcoin header. It is the pool's ~76-byte
 * Monero hashing blob, held verbatim in work->data, with a 4-byte little-endian
 * nonce at byte offset 39. There is no ntime, nbits or merkle root, so
 * ntime_index / nbits_index / gen_merkle_root / build_extraheader do not apply
 * and are left unregistered.
 *
 * Share test: the last 8 bytes of the hash, little endian, must be strictly
 * less than the pool's 64-bit target. Spelled out byte-wise below so it is
 * correct on big endian and needs no alignment assumption. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "miner.h"
#include "algo-gate-api.h"
#include "randomx-gate.h"
#include "randomx-core.h"
#include "randomx/randomx.h"

/* --------------------------------------------------------------- helpers */

static inline uint64_t rx_hash_tail( const unsigned char *h )
{
   int i;
   uint64_t v = 0;
   for ( i = 7; i >= 0; i-- )
      v = ( v << 8 ) | h[24 + i];
   return v;
}

/* -------------------------------------------------------------- scanhash */

int scanhash_randomx( struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done, struct thr_info *mythr )
{
   const int thr_id = mythr->id;
   unsigned char blob[RX_BLOB_MAX] __attribute__ ((aligned (16)));
   unsigned char hash[32]          __attribute__ ((aligned (16)));
   const size_t  blob_len = work->rx_blob_len;
   const uint64_t target  = work->rx_target;
   uint32_t n, found_nonce = 0;
   bool found;
   randomx_vm *vm;
   uint64_t done = 0;
#ifndef RANDOMX_NO_BATCH
   uint32_t pending;
#endif

   if ( !work->rx_work || blob_len < RX_NONCE_OFFSET + 4 || !target )
   {
      /* No RandomX job yet (or a malformed one). Sleep rather than spin: the
       * miner loop calls us again as soon as g_work is refreshed. */
      usleep( 20000 );
      *hashes_done = 0;
      return 0;
   }

   memcpy( blob, work->data, blob_len );
   n = work->data[ RX_NONCE_WORD ];

   /* A rebuild is wanted or running: stand off WITHOUT taking the read lock.
    * Taking it here is what starves the rebuild's writer -- glibc rwlocks
    * prefer readers, and this loop re-acquires on every call. See the
    * rx_reseed_pending comment in randomx-vm.c. */
   if ( unlikely( rx_reseed_is_pending() ) )
   {
      usleep( 5000 );
      *hashes_done = 0;
      return 0;
   }

   /* Read lock for the whole call: a seed change rebuilds the cache and
    * dataset IN PLACE, and hashing across that produces valid-looking wrong
    * hashes. See randomx-vm.c. */
   rx_read_lock();

   vm = rx_vm_get( thr_id );
   if ( !vm )
   {
      rx_read_unlock();
      usleep( 20000 );
      *hashes_done = 0;
      return 0;
   }

   found = false;

#ifdef RANDOMX_NO_BATCH

   /* One-shot driver, kept compiled-in so the batched path can be A/B'd from a
    * single binary. Each call does getFinalResult and initScratchpad: two full
    * passes over the 2 MiB scratchpad per hash. */
   do
   {
      le32enc( blob + RX_NONCE_OFFSET, n );
      rx_core->calculate_hash( vm, blob, blob_len, hash );
      done++;

      if ( unlikely( rx_hash_tail( hash ) < target ) )
      {
         found = true;
         found_nonce = n;
         break;
      }
      n++;
   } while ( n < max_nonce && !work_restart[ thr_id ].restart );

#else /* batched */

   /* Batched driver: rx_core->calculate_hash_next() finalises the in-flight hash
    * and fills the scratchpad for the next input in one pass, instead of a
    * separate getFinalResult plus initScratchpad.
    *
    * THE TRAP: the digest _next() writes belongs to the input given to the
    * PREVIOUS _first()/_next() call, not to nextInput. `pending` is the nonce
    * whose hash is in flight. Pairing them wrongly submits a valid digest
    * against the wrong nonce -- the pool rejects everything while every offline
    * test of the primitive still passes. Hence the re-verify below.
    *
    * Abandoning a batch mid-flight is safe: _first() just recomputes tempHash
    * and re-inits the scratchpad, holding nothing that needs releasing. */
   le32enc( blob + RX_NONCE_OFFSET, n );
   rx_core->calculate_hash_first( vm, blob, blob_len );
   pending = n;

   for ( ;; )
   {
      const uint32_t next = pending + 1;
      const bool last = ( next >= max_nonce )
                        || work_restart[ thr_id ].restart;

      if ( last )
         rx_core->calculate_hash_last( vm, hash );        /* digest of pending */
      else
      {
         le32enc( blob + RX_NONCE_OFFSET, next );
         rx_core->calculate_hash_next( vm, blob, blob_len, hash );
      }                                                  /* digest of pending */
      done++;

      if ( unlikely( rx_hash_tail( hash ) < target ) )
      {
         found = true;
         found_nonce = pending;
         break;
      }

      if ( last )
      {
         n = next;
         break;
      }
      pending = next;
   }

#endif

   if ( found )
   {
      const uint64_t tail = rx_hash_tail( hash );

      /* Re-derive the winner one-shot before submitting: one extra hash per
       * share (~0.02%) turns a wrong nonce/digest pairing into a logged error
       * instead of a session of rejects. Re-hashes from work->data, not the
       * local copy, so it also catches a torn blob. */
      unsigned char verify_blob[RX_BLOB_MAX] __attribute__ ((aligned (16)));
      unsigned char verify_hash[32]          __attribute__ ((aligned (16)));

      memcpy( verify_blob, work->data, blob_len );
      le32enc( verify_blob + RX_NONCE_OFFSET, found_nonce );
      rx_core->calculate_hash( vm, verify_blob, blob_len, verify_hash );
      done++;

      if ( unlikely( memcmp( verify_hash, hash, 32 ) != 0 ) )
      {
         applog( LOG_ERR, "RandomX: share self-check FAILED for nonce %08x "
                          "-- not submitting. This is a driver bug, please "
                          "report it.", found_nonce );
         found = false;
         n = found_nonce + 1;
      }
      else
      {
         /* The bytes the pool echoes back: the winning nonce in the blob at
          * offset 39 (that is what build_stratum_request reads) and the hash
          * itself -- Monero submits the result, not a re-derived header. */
         le32enc( (unsigned char*)work->data + RX_NONCE_OFFSET, found_nonce );
         memcpy( work->rx_result, hash, 32 );

         /* Leave the scratch word ON the winning nonce: get_new_work's
          * `++(*nonceptr)` is what makes the next scan resume at n+1. Getting
          * this wrong re-finds and re-submits the same share every call. */
         n = found_nonce;
         work->sharediff = tail
            ? (double)( 0xFFFFFFFFFFFFFFFFULL / tail ) : 0.;
      }
   }

   work->data[ RX_NONCE_WORD ] = n;

   rx_read_unlock();

   *hashes_done = done;

   if ( found && !submit_solution( work, hash, mythr ) )
      applog( LOG_WARNING, "RandomX: failed to submit solution" );

   return 0;
}

/* ------------------------------------------------------- work / lifecycle */

/* Is this genuinely new work, or the same block template under a new job_id?
 *
 * The analogue of std_get_new_work's memcmp over work_cmp_size, written out
 * because the RandomX nonce lives INSIDE the blob (byte 39) rather than past
 * the compared region: a plain memcmp would differ as soon as scanhash advanced
 * the nonce, so every call would look like new work.
 *
 * job_id is not a usable proxy either -- pools rotate it every few seconds for
 * an unchanged template, and resetting the nonce on each rotation re-walks the
 * same range and gets the same shares rejected as duplicates.
 *
 * So: compare the blob with the nonce bytes excised, plus the seed, since a new
 * epoch is new work regardless of the blob. */
static bool rx_same_template( const struct work *work,
                              const struct work *g_work )
{
   const unsigned char *a = (const unsigned char*) work->data;
   const unsigned char *b = (const unsigned char*) g_work->data;
   const size_t tail = RX_NONCE_OFFSET + 4;

   if ( !work->rx_work || !work->job_id )
      return false;
   if ( work->rx_blob_len != g_work->rx_blob_len
        || work->rx_blob_len < tail )
      return false;
   if ( memcmp( work->rx_seed_hash, g_work->rx_seed_hash, 32 ) )
      return false;
   if ( memcmp( a, b, RX_NONCE_OFFSET ) )
      return false;
   return memcmp( a + tail, b + tail, work->rx_blob_len - tail ) == 0;
}

void rx_get_new_work( struct work *work, struct work *g_work,
                      int thr_id, uint32_t *end_nonce_ptr )
{
   uint32_t *nonceptr = work->data + RX_NONCE_WORD;

   if ( !rx_same_template( work, g_work ) || *nonceptr >= *end_nonce_ptr )
   {
      work_free( work );
      work_copy( work, g_work );
      /* Split the nonce space between threads, as the rest of the tree does.
       * RandomX is slow enough that a thread cannot exhaust a slice within a
       * job's lifetime, so no extranonce is needed. */
      *nonceptr      = 0xffffffffU / opt_n_threads * thr_id;
      *end_nonce_ptr = ( 0xffffffffU / opt_n_threads ) * ( thr_id + 1 ) - 0x20;
   }
   else
   {
      /* Same template: carry the nonce across, but re-copy everything else --
       * the job_id must be current or the pool answers "Invalid job id", and
       * the target moves under vardiff. */
      const uint32_t next = *nonceptr + 1;
      work_free( work );
      work_copy( work, g_work );
      work->data[ RX_NONCE_WORD ] = next;
   }
}

static bool rx_miner_thread_init( int thr_id )
{
   (void) thr_id;
   return true;      /* VMs are created lazily by rx_vm_get, under the lock */
}

static void rx_miner_thread_free( int thr_id )
{
   rx_vm_free( thr_id );
}

/* Reported to the startup thread-count auto-cap. The dataset and cache are
 * SHARED, not per-thread -- only each VM's scratchpad and the JIT code buffer
 * scale with -t. Reporting the dataset here would make the cap believe 8
 * threads need ~19 GB and refuse to start.
 *
 * The scratchpad size comes from the selected core: it is 2 MiB for rx/0 but
 * 1 MiB for rx/wow and 256 KiB for rx/arq, and hardcoding 2 MiB made the cap
 * over-reserve by 8x for the smallest variant. */
static size_t rx_get_workspace_size( void )
{
   return (size_t)rx_core->scratchpad_size() + 64 * 1024;
}

/* --------------------------------------------------------- registration */

bool register_randomx_algo( algo_gate_t *gate )
{
   gate->scanhash            = (void*)&scanhash_randomx;
   gate->get_new_work        = (void*)&rx_get_new_work;
   gate->miner_thread_init   = (void*)&rx_miner_thread_init;
   gate->miner_thread_free   = (void*)&rx_miner_thread_free;
   gate->build_stratum_request = (void*)&rx_build_stratum_request;
   gate->get_workspace_size  = (void*)&rx_get_workspace_size;

   /* Points the shared miner loop's nonce tracking at the scratch word past the
    * blob; see RX_NONCE_WORD. ntime_index / nbits_index stay at their defaults
    * because a Monero blob has neither and nothing on this path reads them. */
   gate->nonce_index = RX_NONCE_WORD;

   /* The vendored core picks JIT vs interpreter and hard vs soft AES at runtime
    * from rx_core->get_flags(), so it runs anywhere. This set is only what it
    * can use, for the startup banner. */
   gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT | NEON_OPT;

   /* This tree's difficulty convention (see pool_diff_to_internal in
    * cpu-miner.c): internal difficulty uses the bitcoin difficulty-1 base, so
    * expected hashes == internal_diff * 2**32, and opt_target_factor converts
    * internal to pool units.
    *
    * Monero difficulty IS the expected hash count, with no 2**32 in it, so one
    * pool unit is 2**-32 internal units. Left at 1.0, every share-derived
    * hashrate in the shared reporting code comes out 2**32 too high. It never
    * affects the target actually scanned against -- that is work->rx_target,
    * straight from the pool. */
   opt_target_factor = EXP32;

   if ( !rx_vm_pool_init( opt_n_threads > 0 ? opt_n_threads : 1 ) )
   {
      applog( LOG_ERR, "RandomX: could not allocate the VM table" );
      return false;
   }

   /* Order matters. The self-test's vectors are rx/0's, so it must run under
    * rx/0's argon salt -- i.e. before any variant is applied. It validates the
    * engine (argon2 fill, interpreter, JIT, both AES paths), all of which a
    * salt-only variant shares bit for bit. */
   if ( !rx_kat_selftest() )
   {
      applog( LOG_ERR, "RandomX self-test FAILED -- refusing to mine" );
      return false;
   }

   /* Now switch the core to this run's variant and verify it. Upstream
    * publishes vectors for rx/0 only, so a variant is checked either against
    * a real vector reconstructed from a share a pool accepted (rx/sfx has
    * one) or, until it has ever been accepted anywhere, against a
    * differential with rx/0 -- same key and input, different salt, therefore
    * a different digest. The weaker check still catches the failure that
    * matters: a variant whose salt never reached the core would otherwise
    * look healthy right up to 100% rejects. */
   if ( !rx_variant_select( opt_algo ) )
      return false;

   if ( opt_algo != ALGO_RANDOMX )
   {
      const rx_variant_t *v = rx_variant();
      if ( !( v->selftest ? v->selftest() : rx_variant_differs_from_rx0() ) )
      {
         applog( LOG_ERR, "RandomX %s self-test FAILED -- refusing to mine",
                 v->pool_algo );
         return false;
      }
   }

   return true;
}
