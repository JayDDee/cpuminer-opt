#include "algo-gate-api.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "algo/shavite/sph_shavite.h"
#include "algo/simd/sph_simd.h"
#include "algo/echo/sph_echo.h"

//#define DEBUG_ALGO

extern void freshhash(void* output, const void* input, uint32_t len)
{
	unsigned char hash[128]; // uint32_t hashA[16], hashB[16];
	#define hashA hash
	#define hashB hash+64

	sph_shavite512_context ctx_shavite;
	sph_simd512_context ctx_simd;
	sph_echo512_context ctx_echo;

	sph_shavite512_init(&ctx_shavite);
	sph_shavite512(&ctx_shavite, input, len);
	sph_shavite512_close(&ctx_shavite, hashA);

	sph_simd512_init(&ctx_simd);
	sph_simd512(&ctx_simd, hashA, 64);
	sph_simd512_close(&ctx_simd, hashB);

	sph_shavite512_init(&ctx_shavite);
	sph_shavite512(&ctx_shavite, hashB, 64);
	sph_shavite512_close(&ctx_shavite, hashA);

	sph_simd512_init(&ctx_simd);
	sph_simd512(&ctx_simd, hashA, 64);
	sph_simd512_close(&ctx_simd, hashB);

	sph_echo512_init(&ctx_echo);
	sph_echo512(&ctx_echo, hashB, 64);
	sph_echo512_close(&ctx_echo, hashA);

	memcpy(output, hash, 32);
}

int scanhash_fresh(int thr_id, struct work *work,
				uint32_t max_nonce, uint64_t *hashes_done)
{
        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;
	uint32_t len = 80;

	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];
	const uint32_t Htarg = ptarget[7];
#ifdef _MSC_VER
	uint32_t __declspec(align(32)) hash64[8];
#else
	uint32_t hash64[8] __attribute__((aligned(32)));
#endif
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
        for (int k = 0; k < 19; k++)
                be32enc(&endiandata[k], pdata[k]);

#ifdef DEBUG_ALGO
	if (Htarg != 0)
		printf("[%d] Htarg=%X\n", thr_id, Htarg);
#endif
	for (int m=0; m < 6; m++) {
		if (Htarg <= htmax[m]) {
			uint32_t mask = masks[m];
			do {
				pdata[19] = ++n;
				be32enc(&endiandata[19], n);
				freshhash(hash64, endiandata, len);
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

void fresh_set_target( struct work* work, double job_diff )
{
 work_set_target( work, job_diff / (256.0 * opt_diff_factor) );
}


bool register_fresh_algo( algo_gate_t* gate )
{
    algo_not_tested();
    gate->scanhash   = (void*)&scanhash_fresh;
    gate->hash       = (void*)&freshhash;
    gate->set_target = (void*)&fresh_set_target;
    gate->get_max64  = (void*)&get_max64_0x3ffff;
    return true;
};

