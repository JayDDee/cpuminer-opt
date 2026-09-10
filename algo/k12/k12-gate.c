#include "algo-gate-api.h"
#include "KangarooTwelve.h"
#include "algo/randomx/randomx-gate.h"

#include <stdint.h>
#include <string.h>
#include <unistd.h>

/*
 * KangarooTwelve as a standalone PoW (algo name "k12").
 *
 * Not a bitcoin-stratum algo. The chain is CryptoNote, so the work item is
 * the pool's 80-byte hashing blob held verbatim in work->data with a 4-byte
 * little-endian nonce at offset 39, and the share test is the hash's last 8
 * bytes as a little-endian uint64 against the pool's 64-bit target. That is
 * the same wire and the same work-item convention as the RandomX family, so
 * this gate reuses algo/randomx's Monero stratum instead of reimplementing it.
 *
 * Two things differ from RandomX and both are handled by predicates rather
 * than by copying the stratum: rx_algo_uses_monero_stratum() puts k12 in the
 * dialect set, and rx_algo_needs_seed() is false here because K12 has no
 * dataset and the pool sends no seed_hash field at all.
 *
 * hash = KangarooTwelve( blob, blob_len ) truncated to 32 bytes, no
 * customization string, over the raw blob with no byte swapping. The same
 * primitive hashes the seed inside panthera; see
 * algo/randomx/panthera-seed.c.
 */

void k12_hash( void *output, const void *input, size_t len )
{
   KangarooTwelve( (const unsigned char *)input, len,
                   (unsigned char *)output, 32, NULL, 0 );
}

/* Consensus is plain standard K12 over the blob; do not "fix" the padding.
 * The reference miner writes its domain byte at dlen + 1, which looks like an
 * off-by-one but is not: K12 absorbs M || C || right_encode(|C|), and
 * right_encode(0) for an empty customization string is a single zero byte, so
 * byte dlen is part of the encoding. Appending a further zero gives a
 * different digest that pools reject. */
/* Aeon's nonce field is EIGHT bytes at offset 39, not RandomX's four: the
 * pool's blob zeroes 39..46 and the reference miner increments a uint64 there.
 * Submitting 4 bytes is answered with "incorrect size of nonce". The counter
 * is 32-bit, so the high half is written as zero rather than left as found --
 * the hash must cover exactly the bytes the pool will re-hash. Byte-wise so it
 * is correct on a big-endian host and needs no alignment assumption. */
static inline void k12_put_nonce( unsigned char *blob, uint32_t n )
{
   blob[RX_NONCE_OFFSET    ] = (unsigned char)( n       );
   blob[RX_NONCE_OFFSET + 1] = (unsigned char)( n >>  8 );
   blob[RX_NONCE_OFFSET + 2] = (unsigned char)( n >> 16 );
   blob[RX_NONCE_OFFSET + 3] = (unsigned char)( n >> 24 );
   blob[RX_NONCE_OFFSET + 4] = 0;
   blob[RX_NONCE_OFFSET + 5] = 0;
   blob[RX_NONCE_OFFSET + 6] = 0;
   blob[RX_NONCE_OFFSET + 7] = 0;
}

/* Last 8 bytes, little endian. Spelled out byte-wise so it is correct on a big
 * endian host and needs no alignment assumption -- same as rx_hash_tail(). */
static inline uint64_t k12_hash_tail( const unsigned char *h )
{
   int i;
   uint64_t v = 0;
   for ( i = 7; i >= 0; i-- )
      v = ( v << 8 ) | h[24 + i];
   return v;
}

/* --benchmark has no pool and so never gets a job. K12 is a sponge: its cost
 * grows with input length, so a synthetic blob has to be a representative
 * length or the number means nothing. This dialect carries a CryptoNote
 * block-hashing blob, ~76 bytes; the banner states it so a benchmark is never
 * silently compared against a job of another size. */
#define K12_BENCH_BLOB_LEN 76

int scanhash_k12( struct work *work, uint32_t max_nonce,
                  uint64_t *hashes_done, struct thr_info *mythr )
{
   unsigned char blob[RX_BLOB_MAX] __attribute__ ((aligned (16)));
   unsigned char hash[32]          __attribute__ ((aligned (16)));
   size_t   blob_len = work->rx_blob_len;
   uint64_t target   = work->rx_target;
   uint32_t *nonceptr = work->data + RX_NONCE_WORD;
   uint32_t  n = *nonceptr;
   const uint32_t first_nonce = n;
   const int thr_id = mythr->id;

   if ( !work->rx_work || blob_len < RX_NONCE_OFFSET + 4 || !target )
   {
      if ( !opt_benchmark )
      {
         /* No job yet (or a malformed one). Sleep rather than spin; the miner
          * loop calls us again as soon as g_work is refreshed. */
         usleep( 20000 );
         *hashes_done = 0;
         return 0;
      }
      /* Hash a synthetic blob instead of idling. target 0 leaves every digest
       * above it, so the submit path -- which needs a real job_id and would
       * reach the pool -- is never entered. */
      blob_len = K12_BENCH_BLOB_LEN;
      target   = 0;
      if ( !thr_id )
      {
         static bool noted = false;
         if ( !noted )
         {
            applog( LOG_NOTICE, "k12: benchmarking a synthetic %d-byte blob "
                                "(no pool, so no job); a real job's rate "
                                "tracks its own blob length",
                    K12_BENCH_BLOB_LEN );
            noted = true;
         }
      }
   }

   memcpy( blob, work->data, blob_len );

   do
   {
      k12_put_nonce( blob, n );
      k12_hash( hash, blob, blob_len );

      if ( k12_hash_tail( hash ) < target )
      {
         const uint64_t tail = k12_hash_tail( hash );

         /* The submit contract of this dialect, which is NOT the bitcoin one:
          * the pool echoes the nonce bytes it finds in work->data at offset 39
          * (that is what rx_build_stratum_request reads) and CryptoNote
          * submits the digest itself rather than a re-derived header, so
          * work->rx_result must be set too. Omitting either yields a
          * well-formed submit the pool rejects. */
         k12_put_nonce( (unsigned char*)work->data, n );
         memcpy( work->rx_result, hash, 32 );
         work->sharediff = tail
            ? (double)( 0xFFFFFFFFFFFFFFFFULL / tail ) : 0.;

         /* Leave the scratch word ON the winning nonce: get_new_work's
          * `++(*nonceptr)` is what makes the next scan resume at n+1. */
         *nonceptr = n;
         *hashes_done = n - first_nonce + 1;
         if ( !submit_solution( work, hash, mythr ) )
            applog( LOG_WARNING, "k12: failed to submit solution" );
         return 0;
      }
      n++;
   } while ( n < max_nonce && !work_restart[thr_id].restart );

   *hashes_done = n - first_nonce;
   *nonceptr = n;
   return 0;
}

/* KangarooTwelve( "", 32 ), from the XKCP test vectors. Cheap, and it is the
 * only check that the vendored Keccak-p permutation was built correctly for
 * this target. It says nothing about the wire. */
static bool k12_self_test( void )
{
   static const uint8_t expected[32] =
   { 0x1a, 0xc2, 0xd4, 0x50, 0xfc, 0x3b, 0x42, 0x05,
     0xd1, 0x9d, 0xa7, 0xbf, 0xca, 0x1b, 0x37, 0x51,
     0x3c, 0x08, 0x03, 0x57, 0x7a, 0xc7, 0x16, 0x7f,
     0x06, 0xfe, 0x2c, 0xe1, 0xf0, 0xef, 0x39, 0xe5 };
   uint8_t hash[32];

   if ( KangarooTwelve( (const unsigned char *)"", 0, hash, 32, NULL, 0 ) )
   {
      applog( LOG_ERR, "k12: KangarooTwelve() returned an error" );
      return false;
   }
   if ( memcmp( hash, expected, 32 ) )
   {
      char got[65];
      bin2hex( got, hash, 32 );
      applog( LOG_ERR, "k12: self-test FAILED, got %s", got );
      return false;
   }
   return true;
}

bool register_k12_algo( algo_gate_t *gate )
{
   /* The dialect lives in algo/randomx, so --disable-randomx takes it away.
    * Refuse rather than silently fall back to the bitcoin stratum, which
    * would fail authorization against every k12 pool. */
   if ( !rx_stratum_available() )
   {
      applog( LOG_ERR, "k12 needs the Monero stratum dialect, which this "
                       "build omits (--disable-randomx)" );
      return false;
   }

   if ( !k12_self_test() ) return false;

   /* Only to publish the pool's algo string ("k12") for the login request --
    * no salt, no core, no RandomX banner. */
   if ( !rx_variant_select_plain( ALGO_K12 ) ) return false;

   gate->scanhash              = (void*)&scanhash_k12;
   gate->get_new_work          = (void*)&rx_get_new_work;
   gate->build_stratum_request = (void*)&rx_build_stratum_request;

   /* The nonce is at byte offset 39, which no uint32 index can alias, so the
    * shared miner loop tracks it in a scratch word past the blob. */
   gate->nonce_index = RX_NONCE_WORD;

   /* Reference C permutation only -- no n-way kernel, so no ISA gating. */
   gate->optimizations = 0;

   /* CryptoNote difficulty IS the expected hash count, with no 2**32 in it --
    * the same convention as RandomX; see register_randomx_algo. Confirmed on a
    * live pool: at a 180.00M target the two accepted shares reported 356.64M
    * and 265.78M, i.e. the right scale, not 2**32 off. */
   opt_target_factor = EXP32;

   return true;
}
