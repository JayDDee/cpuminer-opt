#include "myrgr-gate.h"

#if defined(MYRGR_4WAY)

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "aes_ni/hash-groestl.h"
#include "algo/sha/sha2-hash-4way.h"

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

     mm_deinterleave_4x32( hash0, hash1, hash2, hash3, input, 640 );

     update_and_final_groestl( &ctx.groestl, (char*)hash0, (char*)hash0, 640 );
     memcpy( &ctx.groestl, &myrgr_4way_ctx.groestl, sizeof(hashState_groestl) );
     update_and_final_groestl( &ctx.groestl, (char*)hash1, (char*)hash1, 640 );
     memcpy( &ctx.groestl, &myrgr_4way_ctx.groestl, sizeof(hashState_groestl) );
     update_and_final_groestl( &ctx.groestl, (char*)hash2, (char*)hash2, 640 );
     memcpy( &ctx.groestl, &myrgr_4way_ctx.groestl, sizeof(hashState_groestl) );
     update_and_final_groestl( &ctx.groestl, (char*)hash3, (char*)hash3, 640 );

     mm_interleave_4x32( vhash, hash0, hash1, hash2, hash3, 512 );

     sha256_4way( &ctx.sha, vhash, 64 );
     sha256_4way_close( &ctx.sha, vhash );

     mm_deinterleave_4x32( output, output+32, output+64, output+96,
                           vhash, 256 );
}

int scanhash_myriad_4way( int thr_id, struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done )
{
   uint32_t hash[8*4] __attribute__ ((aligned (64)));
   uint32_t vdata[20*4] __attribute__ ((aligned (64)));
   uint32_t _ALIGN(64) edata[20];
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t Htarg = ptarget[7];
   const uint32_t first_nonce = pdata[19];
   uint32_t n = first_nonce;
   uint32_t *nonces = work->nonces;
   bool *found = work->nfound;
   int num_found = 0;
   uint32_t *noncep0 = vdata + 76; // 19*4
   uint32_t *noncep1 = vdata + 77;
   uint32_t *noncep2 = vdata + 78;
   uint32_t *noncep3 = vdata + 79;

/*
        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;

	uint32_t _ALIGN(64) endiandata[20];
	const uint32_t first_nonce = pdata[19];
	uint32_t nonce = first_nonce;
*/
   if ( opt_benchmark )
      ( (uint32_t*)ptarget )[7] = 0x0000ff;

   swab32_array( edata, pdata, 20 );
   mm_interleave_4x32( vdata, edata, edata, edata, edata, 640 );

   do {
      found[0] = found[1] = found[2] = found[3] = false;
      be32enc( noncep0, n   );
      be32enc( noncep1, n+1 );
      be32enc( noncep2, n+2 );
      be32enc( noncep3, n+3 );

      myriad_4way_hash( hash, vdata );
      pdata[19] = n;

      if ( hash[7] <= Htarg && fulltest( hash, ptarget ) )
      {
          found[0] = true;
          num_found++;
          nonces[0] = pdata[19] = n;
          work_set_target_ratio( work, hash );
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
   } while ( (num_found == 0) && (n < max_nonce-4)
                   && !work_restart[thr_id].restart);

   *hashes_done = n - first_nonce + 1;
   return num_found;
}

#endif
