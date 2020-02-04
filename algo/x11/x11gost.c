#include "x11gost-gate.h"

#if !defined(X11GOST_8WAY) && !defined(X11GOST_4WAY)

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "algo/blake/sph_blake.h"
#include "algo/bmw/sph_bmw.h"
#include "algo/gost/sph_gost.h"
#include "algo/jh/sph_jh.h"
#include "algo/keccak/sph_keccak.h"
#include "algo/skein/sph_skein.h"
#include "algo/shavite/sph_shavite.h"
#include "algo/luffa/luffa_for_sse2.h"
#include "algo/cubehash/cubehash_sse2.h"
#include "algo/simd/nist.h"

#if defined(__AES__)
  #include "algo/echo/aes_ni/hash_api.h"
  #include "algo/groestl/aes_ni/hash-groestl.h"
#else
  #include "algo/groestl/sph_groestl.h"
  #include "algo/echo/sph_echo.h"
#endif

typedef struct {
   sph_blake512_context blake;
   sph_bmw512_context bmw;
#if defined(__AES__)
   hashState_echo          echo;
   hashState_groestl       groestl;
#else
   sph_groestl512_context   groestl;
   sph_echo512_context      echo;
#endif
   sph_jh512_context       jh;
   sph_keccak512_context   keccak;
   sph_skein512_context    skein;
   hashState_luffa         luffa;
   cubehashParam           cube;
   sph_shavite512_context  shavite;
   hashState_sd            simd;
   sph_gost512_context     gost;
} x11gost_ctx_holder;

x11gost_ctx_holder x11gost_ctx;

void init_x11gost_ctx()
{
   sph_blake512_init( &x11gost_ctx.blake );
   sph_bmw512_init( &x11gost_ctx.bmw );
#if defined(__AES__)
   init_groestl( &x11gost_ctx.groestl, 64 );
   init_echo( &x11gost_ctx.echo, 512 );
#else
   sph_groestl512_init( &x11gost_ctx.groestl );
   sph_echo512_init( &x11gost_ctx.echo );
#endif
   sph_skein512_init( &x11gost_ctx.skein );
   sph_jh512_init( &x11gost_ctx.jh );
   sph_keccak512_init( &x11gost_ctx.keccak );
   sph_gost512_init( &x11gost_ctx.gost );
   sph_shavite512_init( &x11gost_ctx.shavite );
   init_luffa( &x11gost_ctx.luffa, 512 );
   cubehashInit( &x11gost_ctx.cube, 512, 16, 32 );
   init_sd( &x11gost_ctx.simd, 512 );
}

void x11gost_hash(void *output, const void *input)
{
    unsigned char hash[64] __attribute__((aligned(64)));
    x11gost_ctx_holder ctx;
    memcpy( &ctx, &x11gost_ctx, sizeof(x11gost_ctx) );

    sph_blake512( &ctx.blake, input, 80 );
    sph_blake512_close( &ctx.blake, hash );

    sph_bmw512( &ctx.bmw, (const void*) hash, 64 );
    sph_bmw512_close( &ctx.bmw, hash );

#if defined(__AES__)
    init_groestl( &ctx.groestl, 64 );
    update_and_final_groestl( &ctx.groestl, (char*)hash,
                                      (const char*)hash, 512 );
#else
    sph_groestl512_init( &ctx.groestl );
    sph_groestl512( &ctx.groestl, hash, 64 );
    sph_groestl512_close( &ctx.groestl, hash );
#endif

    sph_skein512( &ctx.skein, (const void*) hash, 64 );
    sph_skein512_close( &ctx.skein, hash );

    sph_jh512( &ctx.jh, (const void*) hash, 64 );
    sph_jh512_close( &ctx.jh, hash );

    sph_keccak512( &ctx.keccak, (const void*) hash, 64 );
    sph_keccak512_close( &ctx.keccak, hash );

    sph_gost512( &ctx.gost, hash, 64 );
    sph_gost512_close( &ctx.gost, hash );

    update_and_final_luffa( &ctx.luffa, (BitSequence*)hash,
                                  (const BitSequence*)hash, 64 );

    cubehashUpdateDigest( &ctx.cube, (byte*) hash,
                                (const byte*)hash, 64 );

    sph_shavite512( &ctx.shavite, hash, 64 );
    sph_shavite512_close( &ctx.shavite, hash );

    update_final_sd( &ctx.simd, (BitSequence *)hash,
                          (const BitSequence *)hash, 512 );

#if defined(__AES__)
     update_final_echo ( &ctx.echo, (BitSequence *)hash,
                         (const BitSequence *)hash, 512 );
#else
     sph_echo512(&ctx.echo, hash, 64);
     sph_echo512_close(&ctx.echo, hash);
#endif

     memcpy( output, hash, 32 );
}

int scanhash_x11gost( struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
	const uint32_t first_nonce = pdata[19];
	uint32_t _ALIGN(64) endiandata[20];
   int thr_id = mythr->id;  // thr_id arg is deprecated
	uint32_t nonce = first_nonce;
	volatile uint8_t *restart = &(work_restart[thr_id].restart);

	if (opt_benchmark)
		((uint32_t*)ptarget)[7] = 0x0cff;

	for (int k = 0; k < 19; k++)
		be32enc(&endiandata[k], pdata[k]);

	const uint32_t Htarg = ptarget[7];
	do {
		uint32_t hash[8];
		be32enc(&endiandata[19], nonce);
		x11gost_hash(hash, endiandata);

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
