#include "algo-gate-api.h"

#if !defined(BMW512_8WAY) && !defined(BMW512_4WAY)

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "sph_bmw.h"

void bmw512hash(void *state, const void *input)
{
    sph_bmw512_context ctx;
    uint32_t hash[32];	
   
    sph_bmw512_init( &ctx );
    sph_bmw512( &ctx,input, 80 );
    sph_bmw512_close( &ctx, hash );

    memcpy( state, hash, 32 );
}

int scanhash_bmw512( struct work *work, uint32_t max_nonce,
                     uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];
	//const uint32_t Htarg = ptarget[7];
   int thr_id = mythr->id;  // thr_id arg is deprecated

	uint32_t _ALIGN(32) hash64[8];
	uint32_t endiandata[32];

   for (int i=0; i < 19; i++) 
           be32enc(&endiandata[i], pdata[i]);

	do {
	
		pdata[19] = ++n;
		be32enc(&endiandata[19], n); 
		bmw512hash(hash64, endiandata);
        if (((hash64[7]&0xFFFFFF00)==0) && 
				fulltest(hash64, ptarget)) {
            *hashes_done = n - first_nonce + 1;
			return true;
		}
	} while (n < max_nonce && !work_restart[thr_id].restart);
	
	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}
#endif
