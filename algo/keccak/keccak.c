#include "keccak-gate.h"

#if !defined(KECCAK_8WAY) && !defined(KECCAK_4WAY)

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "sph_keccak.h"

void keccakhash(void *state, const void *input)
{
    sph_keccak256_context ctx_keccak;
    uint32_t hash[32];	
   
    sph_keccak256_init(&ctx_keccak);
    sph_keccak256 (&ctx_keccak,input, 80);
    sph_keccak256_close(&ctx_keccak, hash);

	memcpy(state, hash, 32);
}

int scanhash_keccak( struct work *work, uint32_t max_nonce,
                     uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t _ALIGN(64) hash64[8];
   uint32_t _ALIGN(64) endiandata[32];
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   uint32_t n = pdata[19];
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce;
   const int thr_id = mythr->id;

   for ( int i=0; i < 19; i++ )
      be32enc( &endiandata[i], pdata[i] );

   do {
      be32enc( &endiandata[19], n );
      keccakhash( hash64, endiandata );
      if ( valid_hash( hash64, ptarget ) && !opt_benchmark )
      {
         pdata[19] = n;
         submit_solution( work, hash64, mythr );
      }
      n++;
   } while ( n < last_nonce && !work_restart[thr_id].restart );

   *hashes_done = n - first_nonce;
   pdata[19] = n;
   return 0;
}

#endif
