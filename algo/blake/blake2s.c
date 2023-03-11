#include "blake2s-gate.h"

#if  !defined(BLAKE2S_16WAY) && !defined(BLAKE2S_8WAY) && !defined(BLAKE2S)

#include <string.h>
#include <stdint.h>

#include "sph-blake2s.h"

static __thread blake2s_state blake2s_ctx;

void blake2s_hash( void *output, const void *input )
{
   unsigned char _ALIGN(64) hash[BLAKE2S_OUTBYTES];
   blake2s_state ctx __attribute__ ((aligned (64)));
  
   memcpy( &ctx, &blake2s_ctx, sizeof ctx );
   blake2s_update( &ctx, input+64, 16 );
 
	blake2s_final( &ctx, hash, BLAKE2S_OUTBYTES );

	memcpy(output, hash, 32);
}

int scanhash_blake2s( struct work *work,
	uint32_t max_nonce, uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;

	uint32_t _ALIGN(64) hash64[8];
	uint32_t _ALIGN(64) endiandata[20];
   int thr_id = mythr->id;  

	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];

	uint32_t n = first_nonce;

   swab32_array( endiandata, pdata, 20 );

	// midstate
	blake2s_init( &blake2s_ctx, BLAKE2S_OUTBYTES );
	blake2s_update( &blake2s_ctx, (uint8_t*) endiandata, 64 );

	do {
		be32enc(&endiandata[19], n);
		blake2s_hash( hash64, endiandata );
      if (hash64[7] <= Htarg )
      if ( fulltest(hash64, ptarget) && !opt_benchmark )
      {
         pdata[19] = n;
         submit_solution( work, hash64, mythr );
      }
		n++;

	} while (n < max_nonce && !work_restart[thr_id].restart);

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;

	return 0;
}
#endif
