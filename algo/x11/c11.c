#include "miner.h"
#include "algo-gate-api.h"

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

c11_ctx_holder c11_ctx;

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
     init_groestl( &c11_ctx.groestl );
#endif
}

void c11hash( void *output, const void *input )
{
        unsigned char hash[128]; // uint32_t hashA[16], hashB[16];
//	uint32_t _ALIGN(64) hash[16];

     c11_ctx_holder ctx;
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
     update_groestl( &ctx.groestl, (char*)hash,512);
     final_groestl( &ctx.groestl, (char*)hash);
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

     update_luffa( &ctx.luffa, (const BitSequence*)hash,512);
     final_luffa( &ctx.luffa, (BitSequence*)hash+64);

     cubehashUpdate( &ctx.cube, (const byte*) hash+64,64);
     cubehashDigest( &ctx.cube, (byte*)hash);

     sph_shavite512( &ctx.shavite, hash, 64);
     sph_shavite512_close( &ctx.shavite, hash+64);

     update_sd( &ctx.simd, (const BitSequence *)hash+64,512);
     final_sd( &ctx.simd, (BitSequence *)hash);

#ifdef NO_AES_NI
     sph_echo512 (&ctx.echo, hash, 64);
     sph_echo512_close(&ctx.echo, hash+64);
#else
     update_echo ( &ctx.echo, (const BitSequence *) hash, 512);
     final_echo( &ctx.echo, (BitSequence *) hash+64 );
#endif

        memcpy(output, hash+64, 32);
}

void c11hash_alt( void *output, const void *input )
{
    unsigned char hash[128];
    sph_blake512_context     ctx_blake;
    sph_bmw512_context       ctx_bmw;
    sph_groestl512_context   ctx_groestl;
    sph_skein512_context     ctx_skein;
    sph_jh512_context        ctx_jh;
    sph_keccak512_context    ctx_keccak;
    sph_luffa512_context     ctx_luffa1;
    sph_cubehash512_context  ctx_cubehash1;
    sph_shavite512_context   ctx_shavite1;
    sph_simd512_context      ctx_simd1;
    sph_echo512_context      ctx_echo;


	sph_blake512_init(&ctx_blake);
	sph_blake512 (&ctx_blake, input, 80);
	sph_blake512_close (&ctx_blake, hash);

	sph_bmw512_init(&ctx_bmw);
	sph_bmw512 (&ctx_bmw, hash, 64);
	sph_bmw512_close(&ctx_bmw, hash);

	sph_groestl512_init(&ctx_groestl);
	sph_groestl512 (&ctx_groestl, hash, 64);
	sph_groestl512_close(&ctx_groestl, hash);

	sph_jh512_init(&ctx_jh);
	sph_jh512 (&ctx_jh, hash, 64);
	sph_jh512_close(&ctx_jh, hash);

	sph_keccak512_init(&ctx_keccak);
	sph_keccak512 (&ctx_keccak, hash, 64);
	sph_keccak512_close(&ctx_keccak, hash);

	sph_skein512_init(&ctx_skein);
	sph_skein512 (&ctx_skein, hash, 64);
	sph_skein512_close (&ctx_skein, hash);

	sph_luffa512_init (&ctx_luffa1);
	sph_luffa512 (&ctx_luffa1, hash, 64);
	sph_luffa512_close (&ctx_luffa1, hash);

	sph_cubehash512_init (&ctx_cubehash1);
	sph_cubehash512 (&ctx_cubehash1, hash, 64);
	sph_cubehash512_close(&ctx_cubehash1, hash);

	sph_shavite512_init (&ctx_shavite1);
	sph_shavite512 (&ctx_shavite1, hash, 64);
	sph_shavite512_close(&ctx_shavite1, hash);

	sph_simd512_init (&ctx_simd1);
	sph_simd512 (&ctx_simd1, hash, 64);
	sph_simd512_close(&ctx_simd1, hash);

	sph_echo512_init (&ctx_echo);
	sph_echo512 (&ctx_echo, hash, 64);
	sph_echo512_close(&ctx_echo, hash);

	memcpy(output, hash+64, 32);
}

int scanhash_c11( int thr_id, struct work *work, uint32_t max_nonce,
                  uint64_t *hashes_done )
{
        uint32_t endiandata[20] __attribute__((aligned(64)));
        uint32_t hash[8] __attribute__((aligned(32)));
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
		c11hash( hash, endiandata );
		if ( hash[7] <= Htarg && fulltest(hash, ptarget) )
                {
			pdata[19] = nonce;
			*hashes_done = pdata[19] - first_nonce;
			return 1;
		}
		nonce++;
	} while ( nonce < max_nonce && !(*restart) );
	pdata[19] = nonce;
	*hashes_done = pdata[19] - first_nonce + 1;
	return 0;
}

bool register_c11_algo( algo_gate_t* gate )
{
  gate->optimizations = SSE2_OPT | AES_OPT | AVX_OPT | AVX2_OPT;
  init_c11_ctx();
  gate->scanhash  = (void*)&scanhash_c11;
  gate->hash      = (void*)&c11hash;
  gate->hash_alt  = (void*)&c11hash_alt;
  gate->get_max64 = (void*)&get_max64_0x3ffff;
  return true;
};

