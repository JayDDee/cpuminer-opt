#include "skein2-gate.h"
#include <string.h>
#include <stdint.h>
#include "skein-hash-4way.h"

#if defined(SKEIN2_4WAY)

void skein2hash_4way( void *output, const void *input )
{
   skein512_4way_context ctx;
   uint64_t hash[8*4] __attribute__ ((aligned (64)));

   skein512_4way_init( &ctx );
   skein512_4way( &ctx, input, 80 );
   skein512_4way_close( &ctx, hash );

   skein512_4way_init( &ctx );
   skein512_4way( &ctx, hash, 64 );
   skein512_4way_close( &ctx, output );
}

int scanhash_skein2_4way( int thr_id, struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done )
{
    uint32_t hash[8*4] __attribute__ ((aligned (64)));
    uint32_t *hash7 = &(hash[25]);
    uint32_t vdata[20*4] __attribute__ ((aligned (64)));
    uint32_t endiandata[20] __attribute__ ((aligned (64)));
    uint64_t *edata = (uint64_t*)endiandata;
    uint32_t *pdata = work->data;
    uint32_t *ptarget = work->target;
    const uint32_t Htarg = ptarget[7];
    const uint32_t first_nonce = pdata[19];
    uint32_t n = first_nonce;
    uint32_t *nonces = work->nonces;
    int num_found = 0;

    swab32_array( endiandata, pdata, 20 );

    mm256_interleave_4x64( vdata, edata, edata, edata, edata, 640 );

    uint32_t *noncep = vdata + 73;   // 9*8 + 1

    do 
    {
       be32enc( noncep,   n   );
       be32enc( noncep+2, n+1 );
       be32enc( noncep+4, n+2 );
       be32enc( noncep+6, n+3 );

       skein2hash( hash, vdata );

       for ( int lane = 0; lane < 4; lane++ )
       if ( hash7[ lane ] <= Htarg )
       {
          // deinterleave hash for lane
          uint32_t lane_hash[8];
          mm256_extract_lane_4x64( lane_hash, hash, lane, 256 );
          if ( fulltest( lane_hash, ptarget ) )
          {
             pdata[19] = n + lane;
             nonces[ num_found++ ] = n + lane;
             work_set_target_ratio( work, lane_hash );
          }
       }
       n += 4;
    } while ( (num_found == 0) && (n < max_nonce)
             &&  !work_restart[thr_id].restart );

    *hashes_done = n - first_nonce + 1;
    return num_found;
}

#endif
