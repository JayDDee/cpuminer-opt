#include "miner.h"
#include "algo-gate-api.h"

#include <string.h>
#include <stdint.h>

#include "sph_skein.h"

#if defined __SHA__
#include <openssl/sha.h>
#else
#include "algo/sha/sph_sha2.h"
#endif

typedef struct {
   sph_skein512_context skein;
#if defined __SHA__
   SHA256_CTX         sha256;
#else
   sph_sha256_context sha256;
#endif
} skein_ctx_holder;

skein_ctx_holder skein_ctx;

void init_skein_ctx()
{
   sph_skein512_init( &skein_ctx.skein );
#if defined __SHA__
   SHA256_Init( &skein_ctx.sha256 );
#else
   sph_sha256_init( &skein_ctx.sha256 );
#endif
}

void skeinhash(void *state, const void *input)
{
     skein_ctx_holder ctx __attribute__ ((aligned (64)));
     memcpy( &ctx, &skein_ctx, sizeof(skein_ctx) );
     uint32_t hash[16] __attribute__ ((aligned (64)));
	
     sph_skein512( &ctx.skein, input, 80 );
     sph_skein512_close( &ctx.skein, hash );

#if defined __SHA__
     SHA256_Update( &ctx.sha256, hash, 64 );
     SHA256_Final( (unsigned char*) hash, &ctx.sha256 );
#else
     sph_sha256( &ctx.sha256, hash, 64 );
     sph_sha256_close( &ctx.sha256, hash );
#endif

     memcpy(state, hash, 32);
}

int scanhash_skein(int thr_id, struct work *work,
	uint32_t max_nonce, uint64_t *hashes_done)
{
        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;
	uint32_t hash64[8] __attribute__ ((aligned (64)));
	uint32_t endiandata[20] __attribute__ ((aligned (64)));
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
    gate->optimizations = SSE2_OPT | SHA_OPT;
    gate->scanhash  = (void*)&scanhash_skein;
    gate->hash      = (void*)&skeinhash;
    gate->get_max64 = (void*)&skein_get_max64;
    return true;
};

