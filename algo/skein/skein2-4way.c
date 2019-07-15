#include "skein2-gate.h"
#include <string.h>
#include <stdint.h>
#include "skein-hash-4way.h"

#if defined(SKEIN2_4WAY)

void skein2hash_4way( void *output, const void *input )
{
   skein512_4way_context ctx;
   uint64_t hash[16*4] __attribute__ ((aligned (64)));

   skein512_4way_init( &ctx );
   skein512_4way( &ctx, input, 80 );
   skein512_4way_close( &ctx, hash );

   skein512_4way_init( &ctx );
   skein512_4way( &ctx, hash, 64 );
   skein512_4way_close( &ctx, output );
}

int scanhash_skein2_4way( struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done, struct thr_info *mythr )
{
    uint32_t hash[16*4] __attribute__ ((aligned (64)));
    uint32_t vdata[20*4] __attribute__ ((aligned (64)));
    uint32_t lane_hash[8] __attribute__ ((aligned (64)));
    uint32_t *hash7 = &(hash[25]);
    uint32_t *pdata = work->data;
    uint32_t *ptarget = work->target;
    const uint32_t Htarg = ptarget[7];
    const uint32_t first_nonce = pdata[19];
    uint32_t n = first_nonce;
    __m256i  *noncev = (__m256i*)vdata + 9;   // aligned
    int thr_id = mythr->id;  // thr_id arg is deprecated

    mm256_bswap32_intrlv80_4x64( vdata, pdata );
    do 
    {
       *noncev = mm256_intrlv_blend_32( mm256_bswap_32(
                _mm256_set_epi32( n+3, 0, n+2, 0, n+1, 0, n, 0 ) ), *noncev );

       skein2hash_4way( hash, vdata );

       for ( int lane = 0; lane < 4; lane++ )
       if ( hash7[ lane<<1 ] <= Htarg )
       {
          extr_lane_4x64( lane_hash, hash, lane, 256 );
          if ( fulltest( lane_hash, ptarget ) && !opt_benchmark )
          {
             pdata[19] = n + lane;
             submit_lane_solution( work, lane_hash, mythr, lane );
          }
       }
       n += 4;
    } while ( (n < max_nonce) && !work_restart[thr_id].restart );

    *hashes_done = n - first_nonce + 1;
    return 0;
}

#endif
