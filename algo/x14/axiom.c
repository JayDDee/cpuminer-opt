#include "algo-gate-api.h"

#include <string.h>
#include <stdint.h>

#include "algo/shabal/sph_shabal.h"

static __thread uint32_t _ALIGN(64) M[65536][8];

void axiomhash(void *output, const void *input)
{
	sph_shabal256_context ctx __attribute__ ((aligned (64)));
	const int N = 65536;

	sph_shabal256_init(&ctx);
	sph_shabal256(&ctx, input, 80);
	sph_shabal256_close(&ctx, M[0]);

	for(int i = 1; i < N; i++) {
		sph_shabal256_init(&ctx);
		sph_shabal256(&ctx, M[i-1], 32);
		sph_shabal256_close(&ctx, M[i]);
	}

	for(int b = 0; b < N; b++)
	{
		const int p = b > 0 ? b - 1 : 0xFFFF;
		const int q = M[p][0] % 0xFFFF;
		const int j = (b + q) % N;

		sph_shabal256_init(&ctx);
#if 0
		sph_shabal256(&ctx, M[p], 32);
		sph_shabal256(&ctx, M[j], 32);
#else
		uint8_t _ALIGN(64) hash[64];
		memcpy(hash, M[p], 32);
		memcpy(&hash[32], M[j], 32);
		sph_shabal256(&ctx, hash, 64);
#endif
		sph_shabal256_close(&ctx, M[b]);
	}
	memcpy(output, M[N-1], 32);
}

int scanhash_axiom( struct work *work,
	uint32_t max_nonce, uint64_t *hashes_done, struct thr_info *mythr )
{
        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;
	uint32_t _ALIGN(64) hash64[8];
	uint32_t _ALIGN(64) endiandata[20];
   int thr_id = mythr->id;  // thr_id arg is deprecated

	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];

	uint32_t n = first_nonce;

        for (int k = 0; k < 19; k++)
                be32enc(&endiandata[k], pdata[k]);

	do {
		be32enc(&endiandata[19], n);
		axiomhash(hash64, endiandata);
		if (hash64[7] < Htarg && fulltest(hash64, ptarget))
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

bool register_axiom_algo( algo_gate_t* gate )
{
    gate->scanhash  = (void*)&scanhash_axiom;
    gate->hash      = (void*)&axiomhash;
    return true;
}
