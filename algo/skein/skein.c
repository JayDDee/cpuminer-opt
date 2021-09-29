#include "algo-gate-api.h"

#if !defined(SKEIN_8WAY) && !defined(SKEIN_4WAY)

#include <string.h>
#include <stdint.h>
#include "sph_skein.h"
#include "algo/sha/sha256-hash.h"

void skeinhash(void *state, const void *input)
{
     uint32_t hash[16] __attribute__ ((aligned (64)));
     sph_skein512_context ctx_skein;

     sph_skein512_init( &ctx_skein );
     sph_skein512( &ctx_skein, input, 80 );
     sph_skein512_close( &ctx_skein, hash );

     sha256_full( hash, hash, 64 );

     memcpy(state, hash, 32);
}

int scanhash_skein( struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
	uint32_t hash64[8] __attribute__ ((aligned (64)));
	uint32_t endiandata[20] __attribute__ ((aligned (64)));
	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];
	uint32_t n = first_nonce;
   int thr_id = mythr->id;  // thr_id arg is deprecated

   swab32_array( endiandata, pdata, 20 );

	do {
		be32enc(&endiandata[19], n); 
		skeinhash(hash64, endiandata);
		if (hash64[7] < Htarg && fulltest(hash64, ptarget)) {
			*hashes_done = n - first_nonce + 1;
			pdata[19] = n;
			return true;
		}
		n++;

	} while (n < max_nonce && !work_restart[thr_id].restart);

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;

	return 0;
}
#endif
