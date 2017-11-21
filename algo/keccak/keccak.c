#include "algo-gate-api.h"

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

int scanhash_keccak(int thr_id, struct work *work,
	uint32_t max_nonce, uint64_t *hashes_done)
{
        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;
	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];
	//const uint32_t Htarg = ptarget[7];

	uint32_t _ALIGN(32) hash64[8];
	uint32_t endiandata[32];

        for (int i=0; i < 19; i++) 
                be32enc(&endiandata[i], pdata[i]);

	do {
	
		pdata[19] = ++n;
		be32enc(&endiandata[19], n); 
		keccakhash(hash64, endiandata);
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

