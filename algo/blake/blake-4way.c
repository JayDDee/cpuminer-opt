#include "blake-gate.h"

#if defined (BLAKE_4WAY)

#include "blake-hash-4way.h"
#include <string.h>
#include <stdint.h>
#include <memory.h>

blake256r14_4way_context blake_ctx;

void blakehash_4way(void *state, const void *input)
{
     uint32_t vhash[8*4] __attribute__ ((aligned (64)));
     blake256r14_4way_context ctx;
     memcpy( &ctx, &blake_ctx, sizeof ctx );
     blake256r14_4way( &ctx, input + (64<<2), 16 );
     blake256r14_4way_close( &ctx, vhash );
     mm_deinterleave_4x32( state, state+32, state+64, state+96, vhash, 256 );
}

int scanhash_blake_4way( int thr_id, struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done )
{
   uint32_t vdata[20*4] __attribute__ ((aligned (64)));
   uint32_t hash[8*4] __attribute__ ((aligned (32)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   uint32_t HTarget = ptarget[7];
   uint32_t _ALIGN(32) edata[20];
   uint32_t n = first_nonce;
   uint32_t *nonces = work->nonces;
   bool *found = work->nfound;
   int num_found = 0;

   if (opt_benchmark)
      HTarget = 0x7f;

   // we need big endian data...
   swab32_array( edata, pdata, 20 );

   mm_interleave_4x32( vdata, edata, edata, edata, edata, 640 );

   blake256r14_4way_init( &blake_ctx );
   blake256r14_4way( &blake_ctx, vdata, 64 );

   uint32_t *noncep = vdata + 76;   // 19*4
   do {
      found[0] = found[1] = found[2] = found[3] = false;
      be32enc( noncep,    n   );
      be32enc( noncep +1, n+1 );
      be32enc( noncep +2, n+2 );
      be32enc( noncep +3, n+3 );

      blakehash_4way( hash, vdata );

      if (  hash[7] <= HTarget && fulltest( hash, ptarget ) )
      {
          found[0] = true;
          num_found++;
          nonces[0] = n;
          pdata[19] = n;
          work_set_target_ratio( work, hash );
      }
      if ( (hash+8)[7] <= HTarget && fulltest( hash+8, ptarget ) )
      {
          found[1] = true;
          num_found++;
          nonces[1] = n+1;
          work_set_target_ratio( work, hash+8 );
      }
      if ( (hash+16)[7] <= HTarget && fulltest( hash+16, ptarget ) )
      {
           found[2] = true;
           num_found++;
           nonces[2] = n+2;
           work_set_target_ratio( work, hash+16 );
      }
      if ( (hash+24)[7] <= HTarget && fulltest( hash+24, ptarget ) )
      {
           found[3] = true;
           num_found++;
           nonces[3] = n+3;
           work_set_target_ratio( work, hash+24 );
      }
      n += 4;

   } while ( (num_found == 0) && (n < max_nonce) 
             && !work_restart[thr_id].restart );

   *hashes_done = n - first_nonce + 1;
   return num_found;
}

#endif

