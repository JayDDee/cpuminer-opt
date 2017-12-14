#include "whirlpool-gate.h"

#if defined(__AVX2__)

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "sph_whirlpool.h"
#include "whirlpool-hash-4way.h"

static __thread whirlpool_4way_context whirl_mid;

void whirlpool_hash_4way( void *state, const void *input )
{
     uint64_t hash0[8] __attribute__ ((aligned (64)));
     uint64_t hash1[8] __attribute__ ((aligned (64)));
     uint64_t hash2[8] __attribute__ ((aligned (64)));
     uint64_t hash3[8] __attribute__ ((aligned (64)));
     uint64_t vhash[8*4] __attribute__ ((aligned (64)));
     const int midlen = 64;
     const int tail   = 80 - midlen;
     whirlpool_4way_context ctx;

     memcpy( &ctx, &whirl_mid, sizeof whirl_mid );
     whirlpool1_4way( &ctx, input + (midlen<<2), tail );
     whirlpool1_4way_close( &ctx, vhash);

//     whirlpool1_4way_init( &ctx );
//     whirlpool1_4way( &ctx, input, 80 );
//     whirlpool1_4way_close( &ctx, vhash);

     whirlpool1_4way_init( &ctx );
     whirlpool1_4way( &ctx, vhash, 64 );
     whirlpool1_4way_close( &ctx, vhash);

     whirlpool1_4way_init( &ctx );
     whirlpool1_4way( &ctx, vhash, 64 );
     whirlpool1_4way_close( &ctx, vhash);

     whirlpool1_4way_init( &ctx );
     whirlpool1_4way( &ctx, vhash, 64 );
     whirlpool1_4way_close( &ctx, vhash);

     mm256_deinterleave_4x64( hash0, hash1, hash2, hash3, vhash, 512 );

     memcpy( state   , hash0, 32 );
     memcpy( state+32, hash1, 32 );
     memcpy( state+64, hash2, 32 );
     memcpy( state+96, hash3, 32 );
}

int scanhash_whirlpool_4way( int thr_id, struct work* work, uint32_t max_nonce,
                             uint64_t *hashes_done )
{
   uint32_t hash[4*8] __attribute__ ((aligned (64)));
   uint32_t vdata[20*4] __attribute__ ((aligned (64)));
   uint32_t _ALIGN(128) endiandata[20];
   uint32_t* pdata = work->data;
   uint32_t* ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   uint32_t n = first_nonce;
   uint32_t *nonces = work->nonces;
   bool *found = work->nfound;
   int num_found = 0;
   uint32_t *noncep0 = vdata + 73;   // 9*8 + 1
   uint32_t *noncep1 = vdata + 75;
   uint32_t *noncep2 = vdata + 77;
   uint32_t *noncep3 = vdata + 79;

   if (opt_benchmark)
      ((uint32_t*)ptarget)[7] = 0x0000ff;

    for (int i=0; i < 19; i++)
      be32enc(&endiandata[i], pdata[i]);

   uint64_t *edata = (uint64_t*)endiandata;
   mm256_interleave_4x64( (uint64_t*)vdata, edata, edata, edata, edata, 640 );

   // midstate
   whirlpool1_4way_init( &whirl_mid );
   whirlpool1_4way( &whirl_mid, vdata, 64 );

   do {
     const uint32_t Htarg = ptarget[7];
     found[0] = found[1] = found[2] = found[3] = false;
     be32enc( noncep0, n   );
     be32enc( noncep1, n+1 );
     be32enc( noncep2, n+2 );
     be32enc( noncep3, n+3 );

     whirlpool_hash_4way( hash, vdata );

     pdata[19] = n;
     if ( hash[7] <= Htarg && fulltest( hash, ptarget ) )
     {
         found[0] = true;
         num_found++;
         nonces[0] = n;
         work_set_target_ratio(work, hash);
     }
     if ( (hash+8)[7] <= Htarg && fulltest( hash+8, ptarget ) )
     {
         found[1] = true;
         num_found++;
         nonces[1] = n+1;
         work_set_target_ratio( work, hash+8 );
     }
     if ( (hash+16)[7] <= Htarg && fulltest( hash+16, ptarget ) )
     {
         found[2] = true;
         num_found++;
         nonces[2] = n+2;
         work_set_target_ratio( work, hash+16 );
     }
     if ( (hash+24)[7] <= Htarg && fulltest( hash+24, ptarget ) )
     {
         found[3] = true;
         num_found++;
         nonces[3] = n+3;
         work_set_target_ratio( work, hash+24 );
     }
     n += 4;

   } while ( ( num_found == 0 ) && ( n < max_nonce )
             && !work_restart[thr_id].restart );

   *hashes_done = n - first_nonce + 1;
	return num_found;
}

#endif
