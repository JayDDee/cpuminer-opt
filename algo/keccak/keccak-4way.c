#include "keccak-gate.h"

#ifdef KECCAK_4WAY

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "sph_keccak.h"
#include "keccak-hash-4way.h"

void keccakhash_4way(void *state, const void *input)
{
    keccak256_4way_context ctx;
    keccak256_4way_init( &ctx );
    keccak256_4way( &ctx, input, 80 );
    keccak256_4way_close( &ctx, state );
}

int scanhash_keccak_4way( int thr_id, struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done)
{
   uint32_t vdata[24*4] __attribute__ ((aligned (64)));
   uint32_t hash[8*4] __attribute__ ((aligned (32)));
   uint32_t *hash7 = &(hash[25]);   // 3*8+1
   uint32_t lane_hash[8];
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   uint32_t n = pdata[19];
   const uint32_t first_nonce = pdata[19];
//   const uint32_t Htarg = ptarget[7];
   uint32_t endiandata[20];
   uint32_t *nonces = work->nonces;
   int num_found = 0;
   uint32_t *noncep = vdata + 73;   // 9*8 + 1

   for ( int i=0; i < 19; i++ ) 
      be32enc( &endiandata[i], pdata[i] );

   uint64_t *edata = (uint64_t*)endiandata;
   mm256_interleave_4x64( (uint64_t*)vdata, edata, edata, edata, edata, 640 );

   do {
      be32enc( noncep,   n   );
      be32enc( noncep+2, n+1 );
      be32enc( noncep+4, n+2 );
      be32enc( noncep+6, n+3 );
	
      keccakhash_4way( hash, vdata );

      for ( int lane = 0; lane < 4; lane++ )
      if ( ( ( hash7[ lane<<1 ] & 0xFFFFFF00 ) == 0 ) )
      {
          mm256_extract_lane_4x64( lane_hash, hash, lane, 256 );
          if ( fulltest( lane_hash, ptarget ) )
          {
              pdata[19] = n + lane;
              nonces[ num_found++ ] = n + lane;
              work_set_target_ratio( work, lane_hash );
          }
      }
      n += 4;

   } while ( (num_found == 0) && (n < max_nonce-4)
                   && !work_restart[thr_id].restart);

   *hashes_done = n - first_nonce + 1;
   return num_found;
}

#endif
