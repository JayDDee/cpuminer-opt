/**
 * Blake2-B Implementation
 * tpruvot@github 2015-2016
 */

#include "blake2b-gate.h"

#if !defined(BLAKE2B_8WAY) && !defined(BLAKE2B_4WAY)

#include <string.h>
#include <stdint.h>
#include "algo/blake/sph_blake2b.h"

#define MIDLEN 76
#define A 64

void blake2b_hash(void *output, const void *input)
{
	uint8_t _ALIGN(A) hash[32];
	sph_blake2b_ctx ctx __attribute__ ((aligned (64)));

	sph_blake2b_init(&ctx, 32, NULL, 0);
	sph_blake2b_update(&ctx, input, 80);
	sph_blake2b_final(&ctx, hash);

	memcpy(output, hash, 32);
}

int scanhash_blake2b( struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done, struct thr_info *mythr )
{
	uint32_t _ALIGN(A) vhashcpu[8];
	uint32_t _ALIGN(A) endiandata[20];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;
   int thr_id = mythr->id;  // thr_id arg is deprecated

	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];

	uint32_t n = first_nonce;

	for (int i=0; i < 19; i++) {
		be32enc(&endiandata[i], pdata[i]);
	}

	do {
		be32enc(&endiandata[19], n);
		blake2b_hash(vhashcpu, endiandata);

		if (vhashcpu[7] <= Htarg && fulltest(vhashcpu, ptarget))
      {
			pdata[19] = n;
         submit_solution( work, vhashcpu, mythr );
      }
      n++;
	} while (n < max_nonce && !work_restart[thr_id].restart);
	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;

	return 0;
}

#endif
