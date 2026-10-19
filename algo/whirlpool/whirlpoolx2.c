#include "algo-gate-api.h"
#include "whirlpoolx2-kat.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "sph_whirlpool.h"

/* whirlpoolx2 -- CapStash (CAP). Consensus: CapStash-Core
 * src/primitives/block.cpp CBlockHeader::GetPoWHash().
 *
 *    Whirlpool512( 80-byte header )  ->  out[i] = wh[i] ^ wh[i+32]  (i < 32)
 *
 * compared as a little-endian uint256. "x2" is that 512->256 fold, not a second
 * pass.
 *
 * Two things differ from `whirlpoolx` and both fail silently, so do not copy
 * from whirlpoolx.c: the primitive is plain sph_whirlpool (ISO/IEC 10118-3),
 * NOT the sph_whirlpool1 that whirlpool.c and whirlpoolx.c call, and the fold
 * offset is 32, not 16. whirlpoolx2_self_test() asserts both.
 */

void whirlpoolx2_hash( void *state, const void *input )
{
   sph_whirlpool_context ctx;
   uint32_t _ALIGN(64) wh[16];
   uint32_t *out = (uint32_t*)state;

   sph_whirlpool_init( &ctx );
   sph_whirlpool( &ctx, input, 80 );
   sph_whirlpool_close( &ctx, wh );

   /* XOR is bytewise, so folding 32-bit words gives the same bytes as
    * out[i] = wh[i] ^ wh[i+32] without a byte cast. */
   for ( int i = 0; i < 8; i++ )
      out[i] = wh[i] ^ wh[i + 8];
}

/* Per-job state. The nonce is at header bytes 76..79, i.e. in Whirlpool's
 * SECOND block, so everything derived from bytes 0..63 is job-constant:
 *
 *   h    the chaining state after block 1 (the midstate)
 *   keys the ten round keys, which depend only on h -- half a compression's
 *        work, hoisted out of the nonce loop
 *   blk  the padded second block; only bytes 12..15 (the nonce) change
 */
typedef struct
{
   sph_whirlpool_keys keys;
   sph_u64            h[8];
   unsigned char      blk[64] __attribute__ ((aligned (64)));
} whirlpoolx2_job;

static void whirlpoolx2_job_init( whirlpoolx2_job *job, const void *input )
{
   sph_whirlpool_context ctx;

   sph_whirlpool_init( &ctx );
   sph_whirlpool( &ctx, input, 64 );
   memcpy( job->h, ctx.state, sizeof job->h );

   sph_whirlpool_expand_keys( &job->keys, job->h );

   /* Whirlpool padding for an 80-byte message: the trailing 16 bytes, 0x80,
    * zeros, then the 256-bit big-endian bit length 640 (0x280). One block. */
   memset( job->blk, 0, 64 );
   memcpy( job->blk, (const unsigned char*)input + 64, 16 );
   job->blk[16] = 0x80;
   job->blk[62] = 0x02;
   job->blk[63] = 0x80;
}

/* The target screen needs only the digest's most significant 64-bit word, which
 * needs only two of the final round's eight state words. Sound because a
 * 256-bit value can be <= the target only if its most significant word is, so
 * no winning nonce is skipped; survivors are hashed in full and tested exactly. */
static inline sph_u64 whirlpoolx2_job_msw( whirlpoolx2_job *job,
                                           uint32_t nonce_be )
{
   memcpy( job->blk + 12, &nonce_be, 4 );
   return sph_whirlpool_keyed_fold32_msw( &job->keys, job->blk, job->h );
}

static inline void whirlpoolx2_job_hash( void *state, whirlpoolx2_job *job,
                                         uint32_t nonce_be )
{
   sph_u64 _ALIGN(64) st[8];
   uint32_t *out = (uint32_t*)state;
   const uint32_t *wh = (const uint32_t*)st;

   memcpy( job->blk + 12, &nonce_be, 4 );
   sph_whirlpool_compress_keyed( &job->keys, job->blk, job->h, st );

   /* sph_whirlpool_close() writes the state as LE64 words, which on a
    * little-endian host is this array's byte image, so the fold is the same. */
   for ( int i = 0; i < 8; i++ )
      out[i] = wh[i] ^ wh[i + 8];
}

const char *whirlpoolx2_self_test( void )
{
   uint32_t _ALIGN(64) dig[8];
   uint32_t _ALIGN(64) tgt[8];
   unsigned char hdr[80];

   memcpy( tgt, whirlpoolx2_kat_target, 32 );

   for ( size_t i = 0; i < WHIRLPOOLX2_NUM_KATS; i++ )
   {
      whirlpoolx2_job job;
      uint32_t nonce_be;

      whirlpoolx2_hash( dig, whirlpoolx2_kats[i].header );
      if ( memcmp( dig, whirlpoolx2_kats[i].digest, 32 ) )
         return whirlpoolx2_kats[i].name;

      /* Mined headers, so the digest must clear their own nBits. Checked with
       * the shipped comparator, which also pins opt_target_factor. */
      if ( !valid_hash( dig, tgt ) )
         return "genesis digest is above its own nBits target";

      /* The keyed path is what scanhash runs. Feed it the vector's own nonce. */
      whirlpoolx2_job_init( &job, whirlpoolx2_kats[i].header );
      memcpy( &nonce_be, whirlpoolx2_kats[i].header + 76, 4 );
      whirlpoolx2_job_hash( dig, &job, nonce_be );
      if ( memcmp( dig, whirlpoolx2_kats[i].digest, 32 ) )
         return "precomputed-key path disagrees with the KAT";
   }

   /* Non-vacuity, one flip per Whirlpool block: byte 40 (merkle root, so it
    * also catches stale per-job state) and byte 76 (nonce). */
   for ( int pos = 40; pos <= 76; pos += 36 )
   {
      whirlpoolx2_job job;
      uint32_t nonce_be;

      memcpy( hdr, whirlpoolx2_kats[0].header, 80 );
      hdr[pos] ^= 0x01;

      whirlpoolx2_hash( dig, hdr );
      if ( !memcmp( dig, whirlpoolx2_kats[0].digest, 32 ) )
         return "non-vacuity (flipped header gave the same digest)";

      whirlpoolx2_job_init( &job, hdr );
      memcpy( &nonce_be, hdr + 76, 4 );
      whirlpoolx2_job_hash( dig, &job, nonce_be );
      if ( !memcmp( dig, whirlpoolx2_kats[0].digest, 32 ) )
         return "non-vacuity (keyed path ignored a header change)";
   }

   /* Differential against the pristine one-shot core. Reused round keys and a
    * cached block can be right for one vector and wrong for the next nonce, so
    * a handful of fixed vectors would not cover this. */
   {
      whirlpoolx2_job job;
      uint32_t _ALIGN(64) ref[8];

      memcpy( hdr, whirlpoolx2_kats[0].header, 80 );
      whirlpoolx2_job_init( &job, hdr );

      for ( uint32_t k = 0; k < 512; k++ )
      {
         uint32_t n = k * 2654435761u;
         uint32_t nonce_be;

         be32enc( &nonce_be, n );
         memcpy( hdr + 76, &nonce_be, 4 );

         whirlpoolx2_hash( ref, hdr );
         whirlpoolx2_job_hash( dig, &job, nonce_be );
         if ( memcmp( dig, ref, 32 ) )
            return "keyed path differs from the one-shot core";

         /* Must be EXACTLY the digest's most significant word: anything else
          * silently skips winning nonces, which no pool can report because the
          * shares are never submitted. */
         if ( whirlpoolx2_job_msw( &job, nonce_be )
              != ( (const uint64_t*)ref )[3] )
            return "target pre-filter word != digest MSW";
      }
   }

   /* The KAT catches a wrong hash only if the KAT itself is right. These assert
    * the vectors discriminate both deltas, so regenerating whirlpoolx2-kat.h
    * with the wrong fold or primitive cannot yield a self-consistent build. */
   {
      sph_whirlpool_context ctx;
      uint32_t _ALIGN(64) wh[16];
      uint32_t _ALIGN(64) alt[8];

      sph_whirlpool_init( &ctx );
      sph_whirlpool( &ctx, whirlpoolx2_kats[0].header, 80 );
      sph_whirlpool_close( &ctx, wh );
      /* fold at 16 == whirlpoolx's offset */
      for ( int i = 0; i < 8; i++ ) alt[i] = wh[i] ^ wh[i + 4];
      if ( !memcmp( alt, whirlpoolx2_kats[0].digest, 32 ) )
         return "delta guard: the offset-16 fold matched (fold offset is 32)";

      sph_whirlpool1_init( &ctx );
      sph_whirlpool1( &ctx, whirlpoolx2_kats[0].header, 80 );
      sph_whirlpool1_close( &ctx, wh );
      for ( int i = 0; i < 8; i++ ) alt[i] = wh[i] ^ wh[i + 8];
      if ( !memcmp( alt, whirlpoolx2_kats[0].digest, 32 ) )
         return "delta guard: whirlpool1 matched (primitive is plain whirlpool)";
   }

   return NULL;
}

int scanhash_whirlpoolx2( struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t _ALIGN(64) endiandata[20];
   uint32_t _ALIGN(64) vhash[8];
   whirlpoolx2_job job;
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   uint32_t n = first_nonce - 1;
   const int thr_id = mythr->id;
   const bool bench = opt_benchmark;
   volatile uint8_t *restart = &( work_restart[thr_id].restart );

   for ( int i = 0; i < 19; i++ )
      be32enc( &endiandata[i], pdata[i] );

   /* Midstate, round keys and the padded second block: all job-constant. */
   whirlpoolx2_job_init( &job, endiandata );

   /* Most significant 64-bit word of the target, same little-endian order the
    * digest is compared in. Screening on it skips the last round's other six
    * state words for every nonce that cannot win. */
   const sph_u64 target_msw = ( (const sph_u64*)ptarget )[3];

   do {
      uint32_t nonce_be;

      be32enc( &nonce_be, ++n );

      if ( unlikely( whirlpoolx2_job_msw( &job, nonce_be ) <= target_msw ) )
      {
         whirlpoolx2_job_hash( vhash, &job, nonce_be );
         if ( valid_hash( vhash, ptarget ) && !bench )
         {
            pdata[19] = n;
            submit_solution( work, vhash, mythr );
         }
      }
   } while ( likely( n < max_nonce && !( *restart ) ) );

   *hashes_done = n - first_nonce + 1;
   pdata[19] = n;
   return 0;
}

bool register_whirlpoolx2_algo( algo_gate_t *gate )
{
   /* Builds the keyed path's table copy. Must precede the self-test, which is
    * also what verifies that copy against the pristine core. */
   sph_whirlpool_keyed_init();

   const char *failed = whirlpoolx2_self_test();
   if ( failed )
   {
      applog( LOG_ERR, "whirlpoolx2 self-test failed: %s", failed );
      return false;
   }

   applog( LOG_NOTICE, "whirlpoolx2 self-test PASSED [%s] (%d CapStash genesis "
                       "vectors under nBits 0x1d01fffe, precomputed-key path "
                       "vs the one-shot core over 512 nonces)",
                       sph_whirlpool_keyed_config(), WHIRLPOOLX2_NUM_KATS );

   gate->scanhash = (void*)&scanhash_whirlpoolx2;
   gate->hash     = (void*)&whirlpoolx2_hash;

   /* Table-driven scalar core, 1-way scan: nothing to claim. */
   gate->optimizations = EMPTY_SET;

   /* Compared directly against nBits as a little-endian uint256, no shift. */
   opt_target_factor = 1.0;

   return true;
}
