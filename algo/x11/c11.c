#include "c11-gate.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "algo/blake/sph_blake.h"
#include "algo/bmw/sph_bmw.h"
#include "algo/groestl/sph_groestl.h"
#include "algo/jh/sph_jh.h"
#include "algo/keccak/sph_keccak.h"
#include "algo/skein/sph_skein.h"
#include "algo/luffa/sph_luffa.h"
#include "algo/cubehash/sph_cubehash.h"
#include "algo/shavite/sph_shavite.h"
#include "algo/simd/sph_simd.h"
#include "algo/echo/sph_echo.h"

#ifndef NO_AES_NI
  #include "algo/groestl/aes_ni/hash-groestl.h"
  #include "algo/echo/aes_ni/hash_api.h"
#endif

#include "algo/luffa/sse2/luffa_for_sse2.h"
#include "algo/cubehash/sse2/cubehash_sse2.h"
#include "algo/simd/sse2/nist.h"
#include "algo/blake/sse2/blake.c"
#include "algo/keccak/sse2/keccak.c"
#include "algo/bmw/sse2/bmw.c"
#include "algo/skein/sse2/skein.c"
#include "algo/jh/sse2/jh_sse2_opt64.h"


typedef struct {
    sph_shavite512_context  shavite;
    sph_skein512_context     skein;
#ifdef NO_AES_NI
    sph_groestl512_context  groestl;
    sph_echo512_context     echo;
#else
     hashState_echo          echo;
     hashState_groestl       groestl;
#endif
     hashState_luffa         luffa;
     cubehashParam           cube;
     hashState_sd            simd;
} c11_ctx_holder;

c11_ctx_holder c11_ctx __attribute__ ((aligned (64)));

void init_c11_ctx()
{
     init_luffa( &c11_ctx.luffa, 512 );
     cubehashInit( &c11_ctx.cube, 512, 16, 32 );
     sph_shavite512_init( &c11_ctx.shavite );
     init_sd( &c11_ctx.simd, 512 );
#ifdef NO_AES_NI
     sph_groestl512_init( &c11_ctx.groestl );
     sph_echo512_init( &c11_ctx.echo );
#else
     init_echo( &c11_ctx.echo, 512 );
     init_groestl( &c11_ctx.groestl, 64 );
#endif
}

void c11_hash( void *output, const void *input )
{
        unsigned char hash[128] _ALIGN(64); // uint32_t hashA[16], hashB[16];
//	uint32_t _ALIGN(64) hash[16];

     c11_ctx_holder ctx __attribute__ ((aligned (64)));
     memcpy( &ctx, &c11_ctx, sizeof(c11_ctx) );

     size_t hashptr;
     unsigned char hashbuf[128];
     sph_u64 hashctA;
     sph_u64 hashctB;

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

     DECL_JH;
     JH_H;

     DECL_KEC;
     KEC_I;
     KEC_U;
     KEC_C;

     DECL_SKN;
     SKN_I;
     SKN_U;
     SKN_C;

     update_and_final_luffa( &ctx.luffa, (BitSequence*)hash+64,
                             (const BitSequence*)hash, 64 );

     cubehashUpdateDigest( &ctx.cube, (byte*)hash,
                           (const byte*)hash+64, 64 );

     sph_shavite512( &ctx.shavite, hash, 64);
     sph_shavite512_close( &ctx.shavite, hash+64);

     update_final_sd( &ctx.simd, (BitSequence *)hash,
                      (const BitSequence *)hash+64, 512 );

#ifdef NO_AES_NI
     sph_echo512 (&ctx.echo, hash, 64);
     sph_echo512_close(&ctx.echo, hash+64);
#else
     update_final_echo ( &ctx.echo, (BitSequence *)hash+64,
                         (const BitSequence *)hash, 512 );
#endif

        memcpy(output, hash+64, 32);
}

int scanhash_c11( int thr_id, struct work *work, uint32_t max_nonce,
                  uint64_t *hashes_done )
{
        uint32_t endiandata[20] __attribute__((aligned(64)));
        uint32_t hash[8] __attribute__((aligned(64)));
        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;
	const uint32_t first_nonce = pdata[19];
        const uint32_t Htarg = ptarget[7];
	uint32_t nonce = first_nonce;
	volatile uint8_t *restart = &(work_restart[thr_id].restart);

	if (opt_benchmark)
		((uint32_t*)ptarget)[7] = 0x0cff;

        swab32_array( endiandata, pdata, 20 );

	do
        {
		be32enc( &endiandata[19], nonce );
		c11_hash( hash, endiandata );
		if ( hash[7] <= Htarg && fulltest(hash, ptarget) )
                {
			pdata[19] = nonce;
			*hashes_done = pdata[19] - first_nonce;
                        work_set_target_ratio( work, hash );
 			return 1;
		}
		nonce++;
	} while ( nonce < max_nonce && !(*restart) );
	pdata[19] = nonce;
	*hashes_done = pdata[19] - first_nonce + 1;
	return 0;
}

