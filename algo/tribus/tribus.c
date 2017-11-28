#include "tribus-gate.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "algo/jh//sph_jh.h"
#include "algo/keccak/sph_keccak.h"

#ifdef NO_AES_NI
  #include "algo/echo/sph_echo.h"
#else
  #include "algo/echo/aes_ni/hash_api.h"
#endif

typedef struct {
    sph_jh512_context     jh;
    sph_keccak512_context keccak;
#ifdef NO_AES_NI
    sph_echo512_context   echo;
#else
    hashState_echo        echo;
#endif
} tribus_ctx_holder;

static __thread tribus_ctx_holder tribus_ctx;

bool tribus_thread_init()
{
   sph_jh512_init( &tribus_ctx.jh );
   sph_keccak512_init( &tribus_ctx.keccak );
#ifdef NO_AES_NI
   sph_echo512_init( &tribus_ctx.echo );
#else
   init_echo( &tribus_ctx.echo, 512 );
#endif
  return true;
}

void tribus_hash(void *state, const void *input)
{
     unsigned char hash[128] __attribute__ ((aligned (32)));
     tribus_ctx_holder ctx;
     memcpy( &ctx, &tribus_ctx, sizeof(tribus_ctx) );

     sph_jh512( &ctx.jh, input+64, 16 );
     sph_jh512_close( &ctx.jh, (void*) hash );

     sph_keccak512( &ctx.keccak, (const void*) hash, 64 );
     sph_keccak512_close( &ctx.keccak, (void*) hash );

#ifdef NO_AES_NI
     sph_echo512( &ctx.echo, hash, 64 );
     sph_echo512_close (&ctx.echo, hash );
#else
     update_final_echo( &ctx.echo, (BitSequence *) hash,
                        (const BitSequence *) hash, 512 );
#endif

     memcpy(state, hash, 32);
}

int scanhash_tribus(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t _ALIGN(128) hash32[8];
	uint32_t _ALIGN(128) endiandata[20];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;
	const uint32_t first_nonce = pdata[19];
	const uint32_t Htarg = ptarget[7];
	uint32_t n = pdata[19] - 1;

	uint64_t htmax[] = {
		0,
		0xF,
		0xFF,
		0xFFF,
		0xFFFF,
		0x10000000
	};
	uint32_t masks[] = {
		0xFFFFFFFF,
		0xFFFFFFF0,
		0xFFFFFF00,
		0xFFFFF000,
		0xFFFF0000,
		0
	};

	// we need bigendian data...
	for (int i=0; i < 19; i++) {
		be32enc(&endiandata[i], pdata[i]);
	}

        // precalc midstate
        sph_jh512_init( &tribus_ctx.jh );
        sph_jh512( &tribus_ctx.jh, endiandata, 64 );

#ifdef DEBUG_ALGO
	printf("[%d] Htarg=%X\n", thr_id, Htarg);
#endif
	for (int m=0; m < 6; m++) {
		if (Htarg <= htmax[m]) {
			uint32_t mask = masks[m];
			do {
				pdata[19] = ++n;
				be32enc(&endiandata[19], n);
				tribus_hash(hash32, endiandata);
#ifndef DEBUG_ALGO
				if ((!(hash32[7] & mask)) && fulltest(hash32, ptarget)) {
					work_set_target_ratio(work, hash32);
					*hashes_done = n - first_nonce + 1;
					return 1;
				}
#else
				if (!(n % 0x1000) && !thr_id) printf(".");
				if (!(hash32[7] & mask)) {
					printf("[%d]",thr_id);
					if (fulltest(hash32, ptarget)) {
						work_set_target_ratio(work, hash32);
						*hashes_done = n - first_nonce + 1;
						return 1;
					}
				}
#endif
			} while (n < max_nonce && !work_restart[thr_id].restart);
			// see blake.c if else to understand the loop on htmax => mask
			break;
		}
	}

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}


