#include "veltor-gate.h"

#if !defined(VELTOR_8WAY) && !defined(VELTOR_4WAY)

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

veltor_ctx_holder veltor_ctx __attribute__ ((aligned (64)));
static __thread sph_skein512_context veltor_skein_mid
                               __attribute__ ((aligned (64)));

void init_veltor_ctx()
{
     sph_gost512_init( &veltor_ctx.gost );
     sph_shavite512_init( &veltor_ctx.shavite );
     sph_skein512_init( &veltor_ctx.skein);
     sph_shabal512_init( &veltor_ctx.shabal);
}

void veltor_skein512_midstate( const void* input )
{
    memcpy( &veltor_skein_mid, &veltor_ctx.skein, sizeof veltor_skein_mid );
    sph_skein512( &veltor_skein_mid, input, 64 );
}

void veltor_hash(void *output, const void *input)
{
	uint32_t _ALIGN(64) hashA[16], hashB[16];

        veltor_ctx_holder ctx __attribute__ ((aligned (64)));
        memcpy( &ctx, &veltor_ctx, sizeof(veltor_ctx) );

        const int midlen = 64;            // bytes
        const int tail   = 80 - midlen;   // 16

        memcpy( &ctx.skein, &veltor_skein_mid, sizeof veltor_skein_mid );
        sph_skein512( &ctx.skein, input + midlen, tail );

	sph_skein512_close(&ctx.skein, hashA);

        sph_shavite512(&ctx.shavite, hashA, 64);
        sph_shavite512_close(&ctx.shavite, hashB);

        sph_shabal512(&ctx.shabal, hashB, 64);
        sph_shabal512_close(&ctx.shabal, hashA);

	sph_gost512(&ctx.gost, hashA, 64);
	sph_gost512_close(&ctx.gost, hashB);

	memcpy(output, hashB, 32);
}

int scanhash_veltor( struct work *work, uint32_t max_nonce,
                     uint64_t *hashes_done, struct thr_info *mythr )
{
	uint32_t _ALIGN(128) hash[8];
	uint32_t _ALIGN(128) endiandata[20];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;
   int thr_id = mythr->id;  // thr_id arg is deprecated

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

        veltor_skein512_midstate( endiandata );

	do {
		be32enc(&endiandata[19], nonce);
		veltor_hash(hash, endiandata);

		if (hash[7] <= Htarg && fulltest(hash, ptarget))
      {
			pdata[19] = nonce;
         submit_solution( work, hash, mythr );
		}
		nonce++;

	} while (nonce < max_nonce && !(*restart));

	pdata[19] = nonce;
	*hashes_done = pdata[19] - first_nonce + 1;
	return 0;
}
#endif
