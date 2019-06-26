#include "algo-gate-api.h"

#include <string.h>
#include <stdint.h>

#include "sph_bmw.h"

void bmwhash(void *output, const void *input)
{
/*
 	uint32_t hash[16];
	sph_bmw256_context ctx;

	sph_bmw256_init(&ctx);
	sph_bmw256(&ctx, input, 80);
	sph_bmw256_close(&ctx, hash);

	memcpy(output, hash, 32);
*/
}

int scanhash_bmw( struct work *work, uint32_t max_nonce,
                  uint64_t *hashes_done, struct thr_info *mythr )
{
        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;

 	uint32_t _ALIGN(64) hash64[8];
	uint32_t _ALIGN(64) endiandata[20];
   int thr_id = mythr->id;

	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];

	uint32_t n = first_nonce;

        for (int k = 0; k < 19; k++)
                be32enc(&endiandata[k], pdata[k]);

	do {
		be32enc(&endiandata[19], n);
		bmwhash(hash64, endiandata);
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

bool register_bmw256_algo( algo_gate_t* gate )
{
    algo_not_implemented();
    return false;
//    gate->scanhash = (void*)&scanhash_bmw;
//    gate->hash     = (void*)&bmwhash;
    return true;
};

