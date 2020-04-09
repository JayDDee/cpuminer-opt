#include "decred-gate.h"
#include "blake-hash-4way.h"
#include <string.h>
#include <stdint.h>
#include <memory.h>
#include <unistd.h>

#if defined (DECRED_4WAY)

static __thread blake256_4way_context blake_mid;

void decred_hash_4way( void *state, const void *input )
{
     uint32_t vhash[8*4] __attribute__ ((aligned (64)));
//     uint32_t hash0[8] __attribute__ ((aligned (32)));
//     uint32_t hash1[8] __attribute__ ((aligned (32)));
//     uint32_t hash2[8] __attribute__ ((aligned (32)));
//     uint32_t hash3[8] __attribute__ ((aligned (32)));
     const void *tail = input + ( DECRED_MIDSTATE_LEN << 2 );
     int tail_len = 180 - DECRED_MIDSTATE_LEN; 
     blake256_4way_context ctx __attribute__ ((aligned (64)));

     memcpy( &ctx, &blake_mid, sizeof(blake_mid) );
     blake256_4way_update( &ctx, tail, tail_len );
     blake256_4way_close( &ctx, vhash );
     dintrlv_4x32( state, state+32, state+64, state+96, vhash, 256 );
}

int scanhash_decred_4way( struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t vdata[48*4] __attribute__ ((aligned (64)));
   uint32_t hash[8*4] __attribute__ ((aligned (32)));
   uint32_t _ALIGN(64) edata[48];
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[DECRED_NONCE_INDEX];
   uint32_t n = first_nonce;
   const uint32_t HTarget = opt_benchmark ? 0x7f : ptarget[7];
   int thr_id = mythr->id;  // thr_id arg is deprecated

   // copy to buffer guaranteed to be aligned.
   memcpy( edata, pdata, 180 );

   // use the old way until  new way updated for size.
   mm128_intrlv_4x32x( vdata, edata, edata, edata, edata, 180*8 );

   blake256_4way_init( &blake_mid );
   blake256_4way_update( &blake_mid, vdata, DECRED_MIDSTATE_LEN );

   uint32_t *noncep = vdata + DECRED_NONCE_INDEX * 4;
   do {
      * noncep    = n;
      *(noncep+1) = n+1;
      *(noncep+2) = n+2;
      *(noncep+3) = n+3;

      decred_hash_4way( hash, vdata );

      for ( int i = 0; i < 4; i++ )
      if (  (hash+(i<<3))[7] <= HTarget )
      if ( fulltest( hash+(i<<3), ptarget ) && !opt_benchmark )
      {
          pdata[DECRED_NONCE_INDEX] = n+i;
          submit_solution( work, hash+(i<<3), mythr );
      }
      n += 4;
  } while ( (n < max_nonce) && !work_restart[thr_id].restart );

  *hashes_done = n - first_nonce + 1;
  return 0;
}

#endif
