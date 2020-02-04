#include "polytimos-gate.h"

#if !defined(POLYTIMOS_8WAY) && !defined(POLYTIMOS_4WAY)

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "algo/skein/sph_skein.h"
#include "algo/echo/sph_echo.h"
#include "algo/fugue//sph_fugue.h"
#include "algo/luffa/luffa_for_sse2.h"
#include "algo/shabal/sph_shabal.h"
#include "algo/gost/sph_gost.h"
#ifdef __AES__
  #include "algo/echo/aes_ni/hash_api.h"
#endif

typedef struct {
	sph_skein512_context    skein;
   sph_shabal512_context   shabal;
#ifdef __AES__
   hashState_echo          echo;
#else
	sph_echo512_context		echo;
#endif
   hashState_luffa         luffa;
	sph_fugue512_context    fugue;
	sph_gost512_context     gost;
} poly_ctx_holder;

poly_ctx_holder poly_ctx;

void init_polytimos_ctx()
{
	sph_skein512_init(&poly_ctx.skein);
   sph_shabal512_init(&poly_ctx.shabal);
#ifdef __AES__
   init_echo( &poly_ctx.echo, 512 );
#else
   sph_echo512_init(&poly_ctx.echo);
#endif
   init_luffa( &poly_ctx.luffa, 512 );
   sph_fugue512_init(&poly_ctx.fugue);
   sph_gost512_init(&poly_ctx.gost);
}

void polytimos_hash(void *output, const void *input)
{
        uint32_t hashA[16] __attribute__ ((aligned (64)));
        poly_ctx_holder ctx __attribute__ ((aligned (64)));
        memcpy( &ctx, &poly_ctx, sizeof(poly_ctx) );

	sph_skein512(&ctx.skein, input, 80);
	sph_skein512_close(&ctx.skein, hashA);

	sph_shabal512(&ctx.shabal, hashA, 64);
	sph_shabal512_close(&ctx.shabal, hashA);

#ifdef __AES__
    update_final_echo ( &ctx.echo, (BitSequence *)hashA,
                             (const BitSequence *)hashA, 512 );
#else
	sph_echo512(&ctx.echo, hashA, 64);
	sph_echo512_close(&ctx.echo, hashA);
#endif

        update_and_final_luffa( &ctx.luffa, (BitSequence*)hashA,
                                (const BitSequence*)hashA, 64 );

	sph_fugue512(&ctx.fugue, hashA, 64);
	sph_fugue512_close(&ctx.fugue, hashA);

	sph_gost512(&ctx.gost, hashA, 64);
	sph_gost512_close(&ctx.gost, hashA);

	memcpy(output, hashA, 32);
}

int scanhash_polytimos( struct work *work, uint32_t max_nonce,
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
	do {
		be32enc(&endiandata[19], nonce);
		polytimos_hash(hash, endiandata);

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
