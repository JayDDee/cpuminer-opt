#include "decred-gate.h"
#include "sph_blake.h"
#include "blake-hash-4way.h"
#include <string.h>
#include <stdint.h>
#include <memory.h>
#include <unistd.h>

#if defined (DECRED_4WAY)

static __thread blake256_4way_context blake_mid;
static __thread bool ctx_midstate_done = false;

void decred_hash_4way( void *state, const void *input )
{
     uint32_t hash0[16] __attribute__ ((aligned (64)));
     uint32_t hash1[16] __attribute__ ((aligned (64)));
     uint32_t hash2[16] __attribute__ ((aligned (64)));
     uint32_t hash3[16] __attribute__ ((aligned (64)));
     uint32_t vhash[16*4] __attribute__ ((aligned (64)));
     blake256_4way_context ctx __attribute__ ((aligned (64)));

     sph_blake256_context ctx2 __attribute__ ((aligned (64)));
     uint32_t hash[16] __attribute__ ((aligned (64)));
     uint32_t sin0[45], sin1[45], sin2[45], sin3[45];
     m128_deinterleave_4x32( sin0, sin1, sin2, sin3, (uint32_t*)input, 180*8 );

     void *tail = input + DECRED_MIDSTATE_LEN;
     int tail_len = 180 - DECRED_MIDSTATE_LEN; 
//     #define MIDSTATE_LEN 128
/*
        uint8_t *ending = (uint8_t*) input;
        ending += MIDSTATE_LEN;

     if ( !ctx_midstate_done )
     {
          blake256_4way_init( &blake_mid );
          blake256_4way( &blake_mid, input, DECRED_MIDSTATE_LEN );
          ctx_midstate_done = true;
     }
     memcpy( &ctx, &blake_mid, sizeof(blake_mid) );

     blake256_4way( &ctx, tail, tail_len );
     blake256_4way_close( &ctx, vhash );
*/


     sph_blake256_init( &ctx2 );
     sph_blake256( &ctx2, sin0, 180 );
     sph_blake256_close( &ctx2, hash );

     blake256_4way_init( &ctx );
     blake256_4way( &ctx, input, 180 );
     blake256_4way_close( &ctx, vhash );

     m128_deinterleave_4x32( hash0, hash1, hash2, hash3, vhash, 512 );
/*
        for ( int i = 0; i < 8; i++ )
          if ( hash[i] != hash0[i] )
            printf(" hash mismatch, i = %u\n",i);

printf("hash:  %08lx %08lx %08lx %08lx\n", *hash, *(hash+1),
                             *(hash+2), *(hash+3) );
printf("hash0: %08lx %08lx %08lx %08lx\n", *hash0, *(hash0+1),
                             *(hash0+2), *(hash0+3) );
printf("\n");
*/

//     memcpy( state,    hash0, 32 );
//     memcpy( state+32, hash1, 32 );
//     memcpy( state+64, hash1, 32 );
//     memcpy( state+96, hash1, 32 );

     memcpy( state, hash, 32 );

}

int scanhash_decred_4way( int thr_id, struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done)
{
   uint32_t vdata[45*4] __attribute__ ((aligned (64)));
   uint32_t hash[4*8] __attribute__ ((aligned (64)));
        uint32_t _ALIGN(64) endiandata[48];
//        uint32_t _ALIGN(64) hash32[8];
        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;
        const uint32_t first_nonce = pdata[DECRED_NONCE_INDEX];
        uint32_t n = first_nonce;
        const uint32_t HTarget = opt_benchmark ? 0x7f : ptarget[7];
   uint32_t *nonces = work->nonces;
   bool *found = work->nfound;
   int num_found = 0;

//        #define DCR_NONCE_OFT32 35

        ctx_midstate_done = false;

//        memcpy(endiandata, pdata, 180);

   m128_interleave_4x32( vdata, pdata, pdata, pdata, pdata, 180*8 );

   uint32_t *noncep = vdata + DECRED_NONCE_INDEX * 4;
   do {
      found[0] = found[1] = found[2] = found[3] = false;
      * noncep    = n;
      *(noncep+2) = n+1;
      *(noncep+4) = n+2;
      *(noncep+6) = n+3;

      decred_hash_4way( hash, vdata );

//                endiandata[DCR_NONCE_OFT32] = n;
//                decred_hash(hash32, endiandata);

      if ( hash[7] <= HTarget && fulltest( hash, ptarget ) )
      {
          work_set_target_ratio( work, hash );
          found[0] = true;
          num_found++;
          nonces[0] = n;
          pdata[DECRED_NONCE_INDEX] = n;
      }
/*      if ( (hash+8)[7] <= HTarget && fulltest( hash+8, ptarget ) )
      {
          work_set_target_ratio( work, hash+8 );
          found[1] = true;
          num_found++;
          nonces[1] = n;
      }
      if ( (hash+16)[7] <= HTarget && fulltest( hash+16, ptarget ) )
      {
          work_set_target_ratio( work, hash+16 );
          found[2] = true;
          num_found++;
          nonces[2] = n;
      }
      if ( (hash+24)[7] <= HTarget && fulltest( hash+24, ptarget ) )
      {
          work_set_target_ratio( work, hash+24 );
          found[3] = true;
          num_found++;
          nonces[3] = n;
      }
*/
      n += 4;
  } while ( (num_found == 0) && (n < max_nonce) 
            && !work_restart[thr_id].restart );

  *hashes_done = n - first_nonce + 1;
  return num_found;
}

#endif
