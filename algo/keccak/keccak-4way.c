#include "keccak-gate.h"

#ifdef KECCAK_4WAY

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "sph_keccak.h"
#include "keccak-hash-4way.h"

void keccakhash_4way(void *state, const void *input)
{
    uint64_t vhash[4*4] __attribute__ ((aligned (64)));
    keccak256_4way_context ctx;

    keccak256_4way_init( &ctx );
    keccak256_4way( &ctx, input, 80 );
    keccak256_4way_close( &ctx, vhash );

    mm256_deinterleave_4x64( state, state+32, state+64, state+96, vhash, 256 );
}

int scanhash_keccak_4way( int thr_id, struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done)
{
   uint32_t vdata[24*4] __attribute__ ((aligned (64)));
   uint32_t hash[8*4] __attribute__ ((aligned (32)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   uint32_t n = pdata[19];
   const uint32_t first_nonce = pdata[19];
//   const uint32_t Htarg = ptarget[7];
   uint32_t endiandata[20];
   uint32_t *nonces = work->nonces;
   bool *found = work->nfound;
   int num_found = 0;
   uint32_t *noncep0 = vdata + 73;   // 9*8 + 1
   uint32_t *noncep1 = vdata + 75;
   uint32_t *noncep2 = vdata + 77;
   uint32_t *noncep3 = vdata + 79;

   for ( int i=0; i < 19; i++ ) 
      be32enc( &endiandata[i], pdata[i] );

   uint64_t *edata = (uint64_t*)endiandata;
   mm256_interleave_4x64( (uint64_t*)vdata, edata, edata, edata, edata, 640 );

   do {
      found[0] = found[1] = found[2] = found[3] = false;
      be32enc( noncep0, n   );
      be32enc( noncep1, n+1 );
      be32enc( noncep2, n+2 );
      be32enc( noncep3, n+3 );
	
      keccakhash_4way( hash, vdata );

      if ( ( ( hash[7] & 0xFFFFFF00 ) == 0 )
         && fulltest( hash, ptarget) )
      {
          found[0] = true;
          num_found++;
          nonces[0] = n;
          pdata[19] = n;
      }
      if ( ( ( (hash+8)[7] & 0xFFFFFF00 ) == 0 )
         && fulltest( hash+8, ptarget) ) 
      {
          found[1] = true;
          num_found++;
          nonces[1] = n+1;
      }
      if ( ( ( (hash+16) [7] & 0xFFFFFF00 ) == 0 )
         && fulltest( hash+16, ptarget) )
      {
          found[2] = true;
          num_found++;
          nonces[2] = n+2;
      }
      if ( ( ( (hash+24)[7] & 0xFFFFFF00 ) == 0 )
         && fulltest( hash+24, ptarget) )
      {
          found[3] = true;
          num_found++;
          nonces[3] = n+3;
      }
      n += 4;

   } while ( (num_found == 0) && (n < max_nonce-4)
                   && !work_restart[thr_id].restart);

   *hashes_done = n - first_nonce + 1;
   return num_found;
}

#endif
