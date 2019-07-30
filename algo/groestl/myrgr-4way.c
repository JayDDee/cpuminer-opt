#include "myrgr-gate.h"

#if defined(MYRGR_4WAY)

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "aes_ni/hash-groestl.h"
#include "algo/sha/sha-hash-4way.h"

typedef struct {
    hashState_groestl       groestl;
    sha256_4way_context     sha;
} myrgr_4way_ctx_holder;

myrgr_4way_ctx_holder myrgr_4way_ctx;

void init_myrgr_4way_ctx()
{
     init_groestl (&myrgr_4way_ctx.groestl, 64 );
     sha256_4way_init( &myrgr_4way_ctx.sha );
}

void myriad_4way_hash( void *output, const void *input )
{
     uint32_t hash0[20] __attribute__ ((aligned (64)));
     uint32_t hash1[20] __attribute__ ((aligned (64)));
     uint32_t hash2[20] __attribute__ ((aligned (64)));
     uint32_t hash3[20] __attribute__ ((aligned (64)));
     uint32_t vhash[16*4] __attribute__ ((aligned (64)));
     myrgr_4way_ctx_holder ctx;
     memcpy( &ctx, &myrgr_4way_ctx, sizeof(myrgr_4way_ctx) );

     dintrlv_4x32( hash0, hash1, hash2, hash3, input, 640 );

     update_and_final_groestl( &ctx.groestl, (char*)hash0, (char*)hash0, 640 );
     memcpy( &ctx.groestl, &myrgr_4way_ctx.groestl, sizeof(hashState_groestl) );
     update_and_final_groestl( &ctx.groestl, (char*)hash1, (char*)hash1, 640 );
     memcpy( &ctx.groestl, &myrgr_4way_ctx.groestl, sizeof(hashState_groestl) );
     update_and_final_groestl( &ctx.groestl, (char*)hash2, (char*)hash2, 640 );
     memcpy( &ctx.groestl, &myrgr_4way_ctx.groestl, sizeof(hashState_groestl) );
     update_and_final_groestl( &ctx.groestl, (char*)hash3, (char*)hash3, 640 );

     intrlv_4x32( vhash, hash0, hash1, hash2, hash3, 512 );

     sha256_4way( &ctx.sha, vhash, 64 );
     sha256_4way_close( &ctx.sha, output );
}

int scanhash_myriad_4way( struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t hash[8*4] __attribute__ ((aligned (64)));
   uint32_t vdata[20*4] __attribute__ ((aligned (64)));
   uint32_t lane_hash[8] __attribute__ ((aligned (64)));
   uint32_t *hash7 = &(hash[7<<2]);
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t Htarg = ptarget[7];
   const uint32_t first_nonce = pdata[19];
   uint32_t n = first_nonce;
   __m128i  *noncev = (__m128i*)vdata + 19;   // aligned
   int thr_id = mythr->id;  // thr_id arg is deprecated

   if ( opt_benchmark )
      ( (uint32_t*)ptarget )[7] = 0x0000ff;

   mm128_bswap32_intrlv80_4x32( vdata, pdata );
   do {
      *noncev = mm128_bswap_32( _mm_set_epi32( n+3,n+2,n+1,n ) );

      myriad_4way_hash( hash, vdata );
      pdata[19] = n;

      for ( int lane = 0; lane < 4; lane++ )
      if ( hash7[ lane ] <= Htarg )
      {
         extr_lane_4x32( lane_hash, hash, lane, 256 );
         if ( fulltest( lane_hash, ptarget ) && !opt_benchmark )
         {
            pdata[19] = n + lane;
            submit_lane_solution( work, lane_hash, mythr, lane );
         }
      }
      n += 4;
   } while ( (n < max_nonce-4) && !work_restart[thr_id].restart);

   *hashes_done = n - first_nonce + 1;
   return 0;
}

#endif
