#include "miner.h"
#include "algo-gate-api.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#ifdef NO_AES_NI
  #include "sph_groestl.h"
#else
  #include "algo/groestl/aes_ni/hash-groestl.h"
#endif

typedef struct
{
#ifdef NO_AES_NI
    sph_groestl512_context groestl;
#else
    hashState_groestl groestl1, groestl2;
#endif

} groestl_ctx_holder;

static groestl_ctx_holder groestl_ctx;

void init_groestl_ctx()
{
#ifdef NO_AES_NI
    sph_groestl512_init( &groestl_ctx.groestl );
#else
    init_groestl( &groestl_ctx.groestl1, 64 );
    init_groestl( &groestl_ctx.groestl2, 64 );
#endif
}

void groestlhash( void *output, const void *input )
{
     uint32_t hash[16] __attribute__ ((aligned (64)));
     groestl_ctx_holder ctx __attribute__ ((aligned (64)));
     memcpy( &ctx, &groestl_ctx, sizeof(groestl_ctx) );

#ifdef NO_AES_NI
     sph_groestl512(&ctx.groestl, input, 80);
     sph_groestl512_close(&ctx.groestl, hash);

     sph_groestl512(&ctx.groestl, hash, 64);
     sph_groestl512_close(&ctx.groestl, hash);
#else
     update_and_final_groestl( &ctx.groestl1, (char*)hash,
                               (const char*)input, 640 );

     update_and_final_groestl( &ctx.groestl1, (char*)hash,
                               (const char*)hash, 512 );
#endif
     memcpy(output, hash, 32);
 }

int scanhash_groestl( int thr_id, struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done )
{
        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;
        uint32_t endiandata[20] __attribute__ ((aligned (64)));
	const uint32_t first_nonce = pdata[19];
	uint32_t nonce = first_nonce;

	if (opt_benchmark)
		((uint32_t*)ptarget)[7] = 0x0000ff;

        swab32_array( endiandata, pdata, 20 );

	do {
		const uint32_t Htarg = ptarget[7];
		uint32_t hash[8] __attribute__ ((aligned (64)));
		be32enc(&endiandata[19], nonce);
		groestlhash(hash, endiandata);

		if (hash[7] <= Htarg )
                   if ( fulltest(hash, ptarget))
                   {
			pdata[19] = nonce;
			*hashes_done = pdata[19] - first_nonce;
			return 1;
	           }
         
		nonce++;

	} while (nonce < max_nonce && !work_restart[thr_id].restart);

	pdata[19] = nonce;
	*hashes_done = pdata[19] - first_nonce + 1;
	return 0;
}

void groestl_set_target( struct work* work, double job_diff )
{
 work_set_target( work, job_diff / (256.0 * opt_diff_factor) );
}

bool register_groestl_algo( algo_gate_t* gate )
{
    init_groestl_ctx();
    gate->optimizations   = SSE2_OPT | AES_OPT;
    gate->scanhash        = (void*)&scanhash_groestl;
    gate->hash            = (void*)&groestlhash;
    gate->hash_alt        = (void*)&groestlhash;
    gate->set_target      = (void*)&groestl_set_target;
    gate->gen_merkle_root = (void*)&SHA256_gen_merkle_root;
    gate->get_max64       = (void*)&get_max64_0x3ffff;
    return true;
};

