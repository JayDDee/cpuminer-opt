#include "algo-gate-api.h"
#include "sph_blake.h"
#include "blake-hash-4way.h"
#include <string.h>
#include <stdint.h>
#include <memory.h>

#if defined (__AVX__)

void blakehash_4way(void *state, const void *input)
{
     uint32_t hash0[16] __attribute__ ((aligned (64)));
     uint32_t hash1[16] __attribute__ ((aligned (64)));
     uint32_t hash2[16] __attribute__ ((aligned (64)));
     uint32_t hash3[16] __attribute__ ((aligned (64)));
     uint32_t vhash[16*4] __attribute__ ((aligned (64)));
     blake256_4way_context ctx;

     blake256_4way_init( &ctx );
     blake256_4way( &ctx, input, 16 );
     blake256_4way_close( &ctx, vhash );

     m128_deinterleave_4x32( hash0, hash1, hash2, hash3, vhash, 512 );

     memcpy( state,    hash0, 32 );
     memcpy( state+32, hash1, 32 );
     memcpy( state+64, hash1, 32 );
     memcpy( state+96, hash1, 32 );
}

int scanhash_blake_4way( int thr_id, struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done )
{
   uint32_t vdata[20*4] __attribute__ ((aligned (64)));
   uint32_t hash[4*8] __attribute__ ((aligned (64)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
//   uint32_t HTarget = ptarget[7];
   uint32_t _ALIGN(32) endiandata[20];
   uint32_t n = first_nonce;
   uint32_t *nonces = work->nonces;
   bool *found = work->nfound;
   int num_found;

//   if (opt_benchmark)
//      HTarget = 0x7f;

   // we need big endian data...
   swab32_array( endiandata, pdata, 20 );

   m128_interleave_4x32( vdata, endiandata, endiandata, endiandata,
                         endiandata, 640 );

   uint32_t *noncep = vdata + 76;   // 19*4
   do {
      found[0] = found[1] = found[2] = found[3] = false;
      num_found = 0;
      be32enc( noncep,    n   );
      be32enc( noncep +2, n+1 );
      be32enc( noncep +4, n+2 );
      be32enc( noncep +6, n+3 );

      blakehash_4way( hash, vdata );

      if ( hash[7] == 0 )
      {
         if ( fulltest( hash, ptarget ) )
         {
             found[0] = true;
             num_found++;
             nonces[0] = n;
             pdata[19] = n;
         }
      }
      if ( (hash+8)[7] == 0 ) 
      {
         if ( fulltest( hash, ptarget ) ) 
         {
             found[1] = true;
             num_found++;
             nonces[1] = n+1;
         }
      }
      if ( (hash+16)[7] == 0 )
      {
          if ( fulltest( hash, ptarget ) )
          {
              found[2] = true;
              num_found++;
              nonces[2] = n+2;
          }
      }
      if ( (hash+24)[7] == 0 )
      {
         if ( fulltest( hash, ptarget ) )
         {
              found[3] = true;
              num_found++;
              nonces[3] = n+3;
         }
      }
 
      n += 4;
      *hashes_done = n - first_nonce + 1;

   } while ( (num_found == 0) && (n < max_nonce) 
             && !work_restart[thr_id].restart );

   *hashes_done = n - first_nonce + 1;
   return num_found;
}

#endif

