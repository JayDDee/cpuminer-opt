#include "x11gost-gate.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "algo/groestl/sph_groestl.h"
#include "algo/gost/sph_gost.h"
#include "algo/shavite/sph_shavite.h"
#include "algo/echo/sph_echo.h"

#include "algo/luffa/sse2/luffa_for_sse2.h"
#include "algo/cubehash/sse2/cubehash_sse2.h"
#include "algo/simd/sse2/nist.h"
#include "algo/blake/sse2/blake.c"
#include "algo/keccak/sse2/keccak.c"
#include "algo/bmw/sse2/bmw.c"
#include "algo/skein/sse2/skein.c"
#include "algo/jh/sse2/jh_sse2_opt64.h"

#ifndef NO_AES_NI
  #include "algo/groestl/aes_ni/hash-groestl.h"
  #include "algo/echo/aes_ni/hash_api.h"
#endif

typedef struct {
     sph_gost512_context     gost;
     sph_shavite512_context  shavite;
     hashState_luffa         luffa;
     cubehashParam           cube;
     hashState_sd            simd;
#ifdef NO_AES_NI
     sph_groestl512_context  groestl;
     sph_echo512_context     echo;
#else
     hashState_echo          echo;
     hashState_groestl       groestl;
#endif
} x11gost_ctx_holder;

x11gost_ctx_holder x11gost_ctx;

void init_x11gost_ctx()
{
     sph_gost512_init( &x11gost_ctx.gost );
     sph_shavite512_init( &x11gost_ctx.shavite );
     init_luffa( &x11gost_ctx.luffa, 512 );
     cubehashInit( &x11gost_ctx.cube, 512, 16, 32 );
     init_sd( &x11gost_ctx.simd, 512 );
#ifdef NO_AES_NI
     sph_groestl512_init( &x11gost_ctx.groestl );
     sph_echo512_init( &x11gost_ctx.echo );
#else
     init_echo( &x11gost_ctx.echo, 512 );
     init_groestl( &x11gost_ctx.groestl, 64 );
#endif

}

void x11gost_hash(void *output, const void *input)
{
     unsigned char hash[128] __attribute__ ((aligned (64)));
     #define hashA hash
     #define hashB hash+64

     size_t hashptr;
     unsigned char hashbuf[128];
     sph_u64 hashctA;
     sph_u64 hashctB;

     x11gost_ctx_holder ctx __attribute__ ((aligned (64)));
     memcpy( &ctx, &x11gost_ctx, sizeof(x11gost_ctx) );

     DECL_BLK;
     BLK_I;
     BLK_W;
     BLK_C;

     DECL_BMW;
     BMW_I;
     BMW_U;
     #define M(x)    sph_dec64le_aligned(data + 8 * (x))
     #define H(x)    (h[x])
     #define dH(x)   (dh[x])
     BMW_C;
     #undef M
     #undef H
     #undef dH

#ifdef NO_AES_NI
     sph_groestl512 (&ctx.groestl, hash, 64);
     sph_groestl512_close(&ctx.groestl, hash);
#else
     update_and_final_groestl( &ctx.groestl, (char*)hash,
                               (const char*)hash, 512 );
#endif

     DECL_SKN;
     SKN_I;
     SKN_U;
     SKN_C;

     DECL_JH;
     JH_H;

     DECL_KEC;
     KEC_I;
     KEC_U;
     KEC_C;

     sph_gost512(&ctx.gost, hashA, 64);
     sph_gost512_close(&ctx.gost, hashB);

     update_and_final_luffa( &ctx.luffa, (BitSequence*)hashA,
                             (const BitSequence*)hashB, 64 );

     cubehashUpdateDigest( &ctx.cube, (byte*) hashB,
                           (const byte*)hashA, 64 );

     sph_shavite512(&ctx.shavite, hashB, 64);
     sph_shavite512_close(&ctx.shavite, hashA);

     update_final_sd( &ctx.simd, (BitSequence *)hashB,
                      (const BitSequence *)hashA, 512 );

#ifdef NO_AES_NI
     sph_echo512(&ctx.echo, hashB, 64);
     sph_echo512_close(&ctx.echo, hashA);
#else
     update_final_echo ( &ctx.echo, (BitSequence *)hashA,
                         (const BitSequence *)hashB, 512 );
#endif

     memcpy(output, hashA, 32);
}

int scanhash_x11gost( int thr_id, struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done)
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

	const uint32_t Htarg = ptarget[7];
	do {
		uint32_t hash[8];
		be32enc(&endiandata[19], nonce);
		x11gost_hash(hash, endiandata);

		if (hash[7] <= Htarg && fulltest(hash, ptarget)) {
			pdata[19] = nonce;
			*hashes_done = pdata[19] - first_nonce;
                        work_set_target_ratio( work, hash );
			return 1;
		}
		nonce++;

	} while (nonce < max_nonce && !(*restart));

	pdata[19] = nonce;
	*hashes_done = pdata[19] - first_nonce + 1;
	return 0;
}

