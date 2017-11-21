#include "algo-gate-api.h"
#include <string.h>
#include <stdint.h>
#include "sph_skein.h"
#include <openssl/sha.h>
#include "algo/sha/sph_sha2.h"

void skeinhash(void *state, const void *input)
{
     uint32_t hash[16] __attribute__ ((aligned (64)));
     sph_skein512_context ctx_skein;
#ifndef USE_SPH_SHA
     SHA256_CTX           ctx_sha256;
#else
     sph_sha256_context   ctx_sha256;
#endif

     sph_skein512_init( &ctx_skein );
     sph_skein512( &ctx_skein, input, 80 );
     sph_skein512_close( &ctx_skein, hash );

#ifndef USE_SPH_SHA
     SHA256_Init( &ctx_sha256 );
     SHA256_Update( &ctx_sha256, (unsigned char*)hash, 64 );
     SHA256_Final( (unsigned char*) hash, &ctx_sha256 );
#else
     sph_sha256_init( &ctx_sha256 );
     sph_sha256( &ctx_sha256, hash, 64 );
     sph_sha256_close( &ctx_sha256, hash );
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

