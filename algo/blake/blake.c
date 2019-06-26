#include "algo-gate-api.h"
#include "sph_blake.h"

#include <string.h>
#include <stdint.h>
#include <memory.h>

/* Move init out of loop, so init once externally,
 * and then use one single memcpy */
static __thread sph_blake256_context blake_mid;
static __thread bool ctx_midstate_done = false;

static void init_blake_hash(void)
{
	sph_blake256_init(&blake_mid);
	ctx_midstate_done = true;
}

void blakehash(void *state, const void *input)
{
	sph_blake256_context ctx;

	uint8_t hash[64] __attribute__ ((aligned (32)));
	uint8_t *ending = (uint8_t*) input;
	ending += 64;

	// do one memcopy to get a fresh context
	if (!ctx_midstate_done) {
		init_blake_hash();
		sph_blake256(&blake_mid, input, 64);
	}

	memcpy(&ctx, &blake_mid, sizeof(blake_mid));

	sph_blake256(&ctx, ending, 16);
	sph_blake256_close(&ctx, hash);

	memcpy(state, hash, 32);

}

int scanhash_blake( struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done, struct thr_info *mythr )
{
        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;
	const uint32_t first_nonce = pdata[19];
	uint32_t HTarget = ptarget[7];
	uint32_t _ALIGN(32) hash64[8];
	uint32_t _ALIGN(32) endiandata[20];
	uint32_t n = first_nonce;
   int thr_id = mythr->id;  // thr_id arg is deprecated

	ctx_midstate_done = false;

	if (opt_benchmark)
		HTarget = 0x7f;

	// we need big endian data...
        swab32_array( endiandata, pdata, 20 );

#ifdef DEBUG_ALGO
	applog(LOG_DEBUG,"[%d] Target=%08x %08x", thr_id, ptarget[6], ptarget[7]);
#endif

	do {
		be32enc(&endiandata[19], n);
		blakehash(hash64, endiandata);
#ifndef DEBUG_ALGO
		if (hash64[7] <= HTarget && fulltest(hash64, ptarget)) {
			*hashes_done = n - first_nonce + 1;
			return true;
		}
#else
		if (!(n % 0x1000) && !thr_id) printf(".");
		if (hash64[7] == 0) {
			printf("[%d]",thr_id);
			if (fulltest(hash64, ptarget)) {
				*hashes_done = n - first_nonce + 1;
				return true;
			}
		}
#endif
		n++; pdata[19] = n;

	} while (n < max_nonce && !work_restart[thr_id].restart);

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}

