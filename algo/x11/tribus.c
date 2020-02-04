#include "tribus-gate.h"

#if !defined(TRIBUS_8WAY) && !defined(TRIBUS_4WAY)

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "algo/jh//sph_jh.h"
#include "algo/keccak/sph_keccak.h"
#ifdef __AES__
  #include "algo/echo/aes_ni/hash_api.h"
#else
  #include "algo/echo/sph_echo.h"
#endif

typedef struct {
    sph_jh512_context     jh;
    sph_keccak512_context keccak;
#ifdef __AES__
    hashState_echo        echo;
#else
    sph_echo512_context   echo;
#endif
} tribus_ctx_holder;

static __thread tribus_ctx_holder tribus_ctx;

bool tribus_thread_init()
{
   sph_jh512_init( &tribus_ctx.jh );
   sph_keccak512_init( &tribus_ctx.keccak );
#ifdef __AES__
   init_echo( &tribus_ctx.echo, 512 );
#else
   sph_echo512_init( &tribus_ctx.echo );
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

#ifdef __AES__
     update_final_echo( &ctx.echo, (BitSequence *) hash,
                        (const BitSequence *) hash, 512 );
#else
     sph_echo512( &ctx.echo, hash, 64 );
     sph_echo512_close (&ctx.echo, hash );
#endif

     memcpy(state, hash, 32);
}

int scanhash_tribus( struct work *work, uint32_t max_nonce,
      uint64_t *hashes_done, struct thr_info *mythr )
{
	uint32_t _ALIGN(128) hash32[8];
	uint32_t _ALIGN(128) endiandata[20];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;
	const uint32_t first_nonce = pdata[19];
	const uint32_t Htarg = ptarget[7];
	uint32_t n = pdata[19] - 1;
   int thr_id = mythr->id;  // thr_id arg is deprecated

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

	for (int m=0; m < 6; m++) {
		if (Htarg <= htmax[m]) {
			uint32_t mask = masks[m];
			do {
				pdata[19] = ++n;
				be32enc(&endiandata[19], n);
				tribus_hash(hash32, endiandata);
				if ((!(hash32[7] & mask)) && fulltest(hash32, ptarget)) 
                submit_solution( work, hash32, mythr );
			} while (n < max_nonce && !work_restart[thr_id].restart);
			break;
		}
	}

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}

#endif
