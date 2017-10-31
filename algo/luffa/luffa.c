#include "algo-gate-api.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "sph_luffa.h"

void luffahash(void *output, const void *input)
{
	unsigned char _ALIGN(128) hash[64];
	sph_luffa512_context ctx_luffa;

	sph_luffa512_init(&ctx_luffa);
	sph_luffa512 (&ctx_luffa, input, 80);
	sph_luffa512_close(&ctx_luffa, (void*) hash);

	memcpy(output, hash, 32);
}

int scanhash_luffa(int thr_id, struct work *work,
	uint32_t max_nonce, uint64_t *hashes_done)
{
        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;

	uint32_t _ALIGN(64) hash64[8];
	uint32_t _ALIGN(64) endiandata[20];

	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];

	uint32_t n = first_nonce;

        for (int i=0; i < 19; i++) 
                be32enc(&endiandata[i], pdata[i]);

	do {
		be32enc(&endiandata[19], n);
		luffahash(hash64, endiandata);
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

bool register_luffa_algo( algo_gate_t* gate )
{
    gate->scanhash = (void*)&scanhash_luffa;
    gate->hash     = (void*)&luffahash;
    return true;
};

