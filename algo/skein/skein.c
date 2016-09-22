#include "miner.h"
#include "algo-gate-api.h"

#include <string.h>
#include <stdint.h>

#include <openssl/sha.h>

#include "sph_skein.h"

typedef struct {
        sph_skein512_context skein;
        SHA256_CTX           sha256;
} skein_ctx_holder;

skein_ctx_holder skein_ctx;

void init_skein_ctx()
{
        sph_skein512_init(&skein_ctx.skein);
        SHA256_Init(&skein_ctx.sha256);
}

void skeinhash(void *state, const void *input)
{
     skein_ctx_holder ctx;
     memcpy( &ctx, &skein_ctx, sizeof(skein_ctx) );
     uint32_t hash[16];
	
     sph_skein512(&ctx.skein, input, 80);
     sph_skein512_close(&ctx.skein, hash);

     SHA256_Update(&ctx.sha256, hash, 64);
     SHA256_Final((unsigned char*) hash, &ctx.sha256);

     memcpy(state, hash, 32);
}

int scanhash_skein(int thr_id, struct work *work,
	uint32_t max_nonce, uint64_t *hashes_done)
{
        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;
	uint32_t _ALIGN(64) hash64[8];
	uint32_t _ALIGN(64) endiandata[20];
	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];
	uint32_t n = first_nonce;
	
        swab32_array( endiandata, pdata, 20 );

	do {
		be32enc(&endiandata[19], n); 
		skeinhash(hash64, endiandata);
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

int64_t skein_get_max64() { return 0x7ffffLL; }

bool register_skein_algo( algo_gate_t* gate )
{
    init_skein_ctx();
    gate->scanhash  = (void*)&scanhash_skein;
    gate->hash      = (void*)&skeinhash;
    gate->get_max64 = (void*)&skein_get_max64;
    return true;
};

