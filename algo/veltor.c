#include "miner.h"
#include "algo-gate-api.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "algo/skein/sph_skein.h"
#include "algo/gost/sph_gost.h"
#include "algo/shavite/sph_shavite.h"
#include "algo/shabal/sph_shabal.h"

typedef struct {
     sph_gost512_context     gost;
     sph_shavite512_context  shavite;
     sph_skein512_context    skein;
     sph_shabal512_context   shabal;
} veltor_ctx_holder;

veltor_ctx_holder veltor_ctx;

void init_veltor_ctx()
{
     sph_gost512_init( &veltor_ctx.gost );
     sph_shavite512_init( &veltor_ctx.shavite );
     sph_skein512_init( &veltor_ctx.skein);
     sph_shabal512_init( &veltor_ctx.shabal);
}

void veltorhash(void *output, const void *input)
{
//	sph_skein512_context	ctx_skein;
//	sph_gost512_context 	ctx_gost;
//	sph_shabal512_context ctx_shabal;
//	sph_shavite512_context     ctx_shavite;

	//these uint512 in the c++ source of the client are backed by an array of uint32
	uint32_t _ALIGN(64) hashA[16], hashB[16];

     veltor_ctx_holder ctx;
     memcpy( &ctx, &veltor_ctx, sizeof(veltor_ctx) );

//	sph_skein512_init(&ctx_skein);
	sph_skein512(&ctx.skein, input, 80);
	sph_skein512_close(&ctx.skein, hashA);

//        sph_shavite512_init(&ctx_shavite);
        sph_shavite512(&ctx.shavite, hashA, 64);
        sph_shavite512_close(&ctx.shavite, hashB);

//        sph_shabal512_init(&ctx_shabal);
        sph_shabal512(&ctx.shabal, hashB, 64);
        sph_shabal512_close(&ctx.shabal, hashA);

//	sph_gost512_init(&ctx_gost);
	sph_gost512(&ctx.gost, hashA, 64);
	sph_gost512_close(&ctx.gost, hashB);

	memcpy(output, hashB, 32);
}

int scanhash_veltor(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t _ALIGN(128) hash[8];
	uint32_t _ALIGN(128) endiandata[20];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;

	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];
	uint32_t nonce = first_nonce;
	volatile uint8_t *restart = &(work_restart[thr_id].restart);

	if (opt_benchmark)
		ptarget[7] = 0x0cff;

	// we need bigendian data...
	for (int i=0; i < 19; i++) {
		be32enc(&endiandata[i], pdata[i]);
	}
	do {
		be32enc(&endiandata[19], nonce);
		veltorhash(hash, endiandata);

		if (hash[7] <= Htarg && fulltest(hash, ptarget)) {
			work_set_target_ratio(work, hash);
			pdata[19] = nonce;
			*hashes_done = pdata[19] - first_nonce;
			return 1;
		}
		nonce++;

	} while (nonce < max_nonce && !(*restart));

	pdata[19] = nonce;
	*hashes_done = pdata[19] - first_nonce + 1;
	return 0;
}

bool register_veltor_algo( algo_gate_t* gate )
{
    gate->optimizations = SSE2_OPT; 
    init_veltor_ctx();
    gate->scanhash  = (void*)&scanhash_veltor;
    gate->hash      = (void*)&veltorhash;
    gate->hash_alt  = (void*)&veltorhash;
    gate->get_max64 = (void*)&get_max64_0x3ffff;
}

