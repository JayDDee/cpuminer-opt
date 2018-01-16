#include "phi1612-gate.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "algo/gost/sph_gost.h"
#include "algo/echo/sph_echo.h"
#include "algo/fugue//sph_fugue.h"
#include "algo/cubehash/sse2/cubehash_sse2.h"
#include "algo/skein/sse2/skein.c"
#include "algo/jh/sph_jh.h"

#ifndef NO_AES_NI
  #include "algo/echo/aes_ni/hash_api.h"
#endif

typedef struct {
     sph_skein512_context    skein;
     sph_jh512_context       jh;
     cubehashParam           cube;
     sph_fugue512_context    fugue;
     sph_gost512_context     gost;
#ifdef NO_AES_NI
     sph_echo512_context     echo;
#else
     hashState_echo          echo;
#endif
} phi_ctx_holder;

phi_ctx_holder phi_ctx;
static __thread sph_skein512_context phi_skein_mid
                                           __attribute__ ((aligned (64)));

void init_phi1612_ctx()
{
     sph_skein512_init( &phi_ctx.skein );
     sph_jh512_init( &phi_ctx.jh );
     cubehashInit( &phi_ctx.cube, 512, 16, 32 );
     sph_fugue512_init( &phi_ctx.fugue );
     sph_gost512_init( &phi_ctx.gost );
#ifdef NO_AES_NI
     sph_echo512_init( &phi_ctx.echo );
#else
     init_echo( &phi_ctx.echo, 512 );
#endif
}

void phi_skein_midstate( const void* input )
{
    memcpy( &phi_skein_mid, &phi_ctx.skein, sizeof phi_skein_mid );
    sph_skein512( &phi_skein_mid, input, 64 );
}

void phi1612_hash(void *output, const void *input)
{
     unsigned char hash[128] __attribute__ ((aligned (64)));
     phi_ctx_holder ctx __attribute__ ((aligned (64)));

     memcpy( &ctx, &phi_ctx, sizeof(phi_ctx) );

     memcpy( &ctx.skein, &phi_skein_mid, sizeof phi_skein_mid );
     sph_skein512( &ctx.skein, input + 64, 16 );
     sph_skein512_close( &ctx.skein, hash );

//     sph_skein512( &ctx.skein, input, 80 );
//     sph_skein512_close( &ctx.skein, (void*)hash );

     sph_jh512( &ctx.jh, (const void*)hash, 64 );
     sph_jh512_close( &ctx.jh, (void*)hash );

     cubehashUpdateDigest( &ctx.cube, (byte*) hash, (const byte*)hash, 64 );

     sph_fugue512( &ctx.fugue, (const void*)hash, 64 );
     sph_fugue512_close( &ctx.fugue, (void*)hash );

     sph_gost512( &ctx.gost, hash, 64 );
     sph_gost512_close( &ctx.gost, hash );

#ifdef NO_AES_NI
     sph_echo512( &ctx.echo, hash, 64 );
     sph_echo512_close( &ctx.echo, hash );
#else
     update_final_echo ( &ctx.echo, (BitSequence *)hash,
                         (const BitSequence *)hash, 512 );
#endif

     memcpy(output, hash, 32);
}

int scanhash_phi1612( int thr_id, struct work *work, uint32_t max_nonce,
                  uint64_t *hashes_done )
{
        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;

	const uint32_t first_nonce = pdata[19];
	uint32_t _ALIGN(64) endiandata[20];
	uint32_t nonce = first_nonce;
	volatile uint8_t *restart = &(work_restart[thr_id].restart);

	if (opt_benchmark)
		((uint32_t*)ptarget)[7] = 0x0cff;

	for (int k = 0; k < 19; k++)
		be32enc(&endiandata[k], pdata[k]);

        phi_skein_midstate( endiandata );

	const uint32_t Htarg = ptarget[7];
	do {
		uint32_t hash[8];
		be32enc(&endiandata[19], nonce);
		phi1612_hash(hash, endiandata);

		if (hash[7] <= Htarg && fulltest(hash, ptarget)) {
			pdata[19] = nonce;
                        work_set_target_ratio( work, hash );
			*hashes_done = pdata[19] - first_nonce;
			return 1;
		}
		nonce++;

	} while (nonce < max_nonce && !(*restart));

	pdata[19] = nonce;
	*hashes_done = pdata[19] - first_nonce + 1;
	return 0;
}

