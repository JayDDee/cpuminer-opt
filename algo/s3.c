#include "miner.h"
#include "algo-gate-api.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "algo/skein/sph_skein.h"
#include "algo/shavite/sph_shavite.h"
#include "algo/simd/sph_simd.h"

void s3hash(void *output, const void *input)
{

 	sph_shavite512_context ctx_shavite;
	sph_simd512_context ctx_simd;
	sph_skein512_context ctx_skein;

	unsigned char _ALIGN(128) hash[64];

	sph_shavite512_init(&ctx_shavite);
	sph_shavite512(&ctx_shavite, input, 80);
	sph_shavite512_close(&ctx_shavite, (void*)hash);

	sph_simd512_init(&ctx_simd);
	sph_simd512(&ctx_simd, (const void*)hash, 64);
	sph_simd512_close(&ctx_simd, (void*)hash);

	sph_skein512_init(&ctx_skein);
	sph_skein512(&ctx_skein, (const void*)hash, 64);
	sph_skein512_close(&ctx_skein, (void*)hash);

	memcpy(output, hash, 32);

}

int scanhash_s3(int thr_id, struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done)
{
        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;
	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];
	const uint32_t Htarg = ptarget[7];

	uint32_t _ALIGN(32) hash64[8];
	uint32_t endiandata[32];


	uint64_t htmax[] = {
		0,
		0xF,
		0xFF,
		0xFFF,
		0xFFFF,
		0x10000000
	};
	uint32_t masks[] = {
		0xFFFFFFFF,
		0xFFFFFFF0,
		0xFFFFFF00,
		0xFFFFF000,
		0xFFFF0000,
		0
	};

	// we need bigendian data...
	for (int kk=0; kk < 32; kk++) {
		be32enc(&endiandata[kk], ((uint32_t*)pdata)[kk]);
	};
#ifdef DEBUG_ALGO
	printf("[%d] Htarg=%X\n", thr_id, Htarg);
#endif
	for (int m=0; m < 6; m++) {
		if (Htarg <= htmax[m]) {
			uint32_t mask = masks[m];
			do {
				pdata[19] = ++n;
				be32enc(&endiandata[19], n);
				s3hash(hash64, endiandata);
#ifndef DEBUG_ALGO
				if ((!(hash64[7] & mask)) && fulltest(hash64, ptarget)) {
					*hashes_done = n - first_nonce + 1;
					return true;
				}
#else
				if (!(n % 0x1000) && !thr_id) printf(".");
				if (!(hash64[7] & mask)) {
					printf("[%d]",thr_id);
					if (fulltest(hash64, ptarget)) {
						*hashes_done = n - first_nonce + 1;
						return true;
					}
				}
#endif
			} while (n < max_nonce && !work_restart[thr_id].restart);
			// see blake.c if else to understand the loop on htmax => mask
			break;
		}
	}

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}

bool register_s3_algo( algo_gate_t* gate )
{
    algo_not_tested();
    gate->scanhash = (void*)&scanhash_s3;
    gate->hash     = (void*)&s3hash;
//  gate->get_max64 = &s3_get_max64;
    return true;
};

