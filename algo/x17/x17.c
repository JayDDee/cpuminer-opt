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
#include "algo/shavite/sph_shavite.h"
#include "algo/luffa/sph_luffa.h"
#include "algo/cubehash/sph_cubehash.h"
#include "algo/simd/sph_simd.h"
#include "algo/echo/sph_echo.h"
#include "algo/hamsi/sph_hamsi.h"
#include "algo/fugue/sph_fugue.h"
#include "algo/shabal/sph_shabal.h"
#include "algo/whirlpool/sph_whirlpool.h"
#include "algo/sha3/sph_sha2.h"
#include "algo/haval/sph-haval.h"

#include "algo/luffa/sse2/luffa_for_sse2.h" 
#include "algo/cubehash/sse2/cubehash_sse2.h"
#include "algo/simd/sse2/nist.h"
#include "algo/blake/sse2/blake.c"
#include "algo/bmw/sse2/bmw.c"
#include "algo/keccak/sse2/keccak.c"
#include "algo/skein/sse2/skein.c"
#include "algo/jh/sse2/jh_sse2_opt64.h"

#ifndef NO_AES_NI
  #include "algo/echo/aes_ni/hash_api.h"
  #include "algo/groestl/aes_ni/hash-groestl.h"
#endif

typedef struct {
#ifdef NO_AES_NI
        sph_groestl512_context   groestl;
        sph_echo512_context      echo;
#else
        hashState_echo          echo;
        hashState_groestl       groestl;
#endif
        hashState_luffa         luffa;
        cubehashParam           cubehash;
        sph_shavite512_context  shavite;
        hashState_sd            simd;
        sph_hamsi512_context    hamsi;
        sph_fugue512_context    fugue;
        sph_shabal512_context   shabal;
        sph_whirlpool_context   whirlpool;
        sph_sha512_context      sha512;
        sph_haval256_5_context  haval;
} x17_ctx_holder;

x17_ctx_holder x17_ctx;

void init_x17_ctx()
{
#ifdef NO_AES_NI
        sph_groestl512_init(&x17_ctx.groestl );
        sph_echo512_init(&x17_ctx.echo);
#else
        init_echo( &x17_ctx.echo, 512 );
        init_groestl( &x17_ctx.groestl, 64 );
#endif
        init_luffa( &x17_ctx.luffa, 512 );
        cubehashInit( &x17_ctx.cubehash, 512, 16, 32 );
        sph_shavite512_init( &x17_ctx.shavite );
        init_sd( &x17_ctx.simd, 512 );
        sph_hamsi512_init( &x17_ctx.hamsi );
        sph_fugue512_init( &x17_ctx.fugue );
        sph_shabal512_init( &x17_ctx.shabal );
        sph_whirlpool_init( &x17_ctx.whirlpool );
        sph_sha512_init(&x17_ctx.sha512);
        sph_haval256_5_init(&x17_ctx.haval);
};

static void x17hash(void *output, const void *input)
{
	unsigned char hash[128]; // uint32_t hashA[16], hashB[16];
	#define hashB hash+64

        x17_ctx_holder ctx;
        memcpy( &ctx, &x17_ctx, sizeof(x17_ctx) );

        unsigned char hashbuf[128];
        size_t hashptr;
        sph_u64 hashctA;
        sph_u64 hashctB;

        //---blake1---
        
        DECL_BLK;
        BLK_I;
        BLK_W;
        BLK_C;

        //---bmw2---
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

        //---groestl----

#ifdef NO_AES_NI
        sph_groestl512(&ctx.groestl, hash, 64);
        sph_groestl512_close(&ctx.groestl, hash);
#else
        update_groestl( &ctx.groestl, (char*)hash,512);
        final_groestl( &ctx.groestl, (char*)hash);
#endif

        //---skein4---

        DECL_SKN;
        SKN_I;
        SKN_U;
        SKN_C;

        //---jh5------

        DECL_JH;
        JH_H;

        //---keccak6---

        DECL_KEC;
        KEC_I;
        KEC_U;
        KEC_C;

        //--- luffa7
        update_luffa( &ctx.luffa, (const BitSequence*)hash,64);
        final_luffa( &ctx.luffa, (BitSequence*)hashB);

        // 8 Cube
        cubehashUpdate( &ctx.cubehash, (const byte*) hashB,64);
        cubehashDigest( &ctx.cubehash, (byte*)hash);

        // 9 Shavite
        sph_shavite512( &ctx.shavite, hash, 64);
        sph_shavite512_close( &ctx.shavite, hashB);

        // 10 Simd
        update_sd( &ctx.simd, (const BitSequence *)hashB,512);
        final_sd( &ctx.simd, (BitSequence *)hash);

        //11---echo---

#ifdef NO_AES_NI
        sph_echo512(&ctx.echo, hash, 64);
        sph_echo512_close(&ctx.echo, hashB);
#else
        update_echo ( &ctx.echo, (const BitSequence *) hash, 512);
        final_echo( &ctx.echo, (BitSequence *) hashB);
#endif

        // X13 algos
        // 12 Hamsi
        sph_hamsi512(&ctx.hamsi, hashB, 64);
        sph_hamsi512_close(&ctx.hamsi, hash);

        // 13 Fugue
         sph_fugue512(&ctx.fugue, hash, 64);
        sph_fugue512_close(&ctx.fugue, hashB);

        // X14 Shabal
        sph_shabal512(&ctx.shabal, hashB, 64);
        sph_shabal512_close(&ctx.shabal, hash);
       
        // X15 Whirlpool
	sph_whirlpool(&ctx.whirlpool, hash, 64);
	sph_whirlpool_close(&ctx.whirlpool, hashB);

        sph_sha512(&ctx.sha512,(const void*) hashB, 64);
        sph_sha512_close(&ctx.sha512,(void*) hash);

        sph_haval256_5(&ctx.haval,(const void*) hash, 64);
        sph_haval256_5_close(&ctx.haval,hashB);


        asm volatile ("emms");
	memcpy(output, hashB, 32);
}

void x17hash_alt(void *output, const void *input)
{
        unsigned char hash[128]; // uint32_t hashA[16], hashB[16];
        #define hashB hash+64

        sph_blake512_context     ctx_blake;
        sph_bmw512_context       ctx_bmw;
        sph_groestl512_context   ctx_groestl;
        sph_jh512_context        ctx_jh;
        sph_keccak512_context    ctx_keccak;
        sph_skein512_context     ctx_skein;
        sph_luffa512_context     ctx_luffa;
        sph_cubehash512_context  ctx_cubehash;
        sph_shavite512_context   ctx_shavite;
        sph_simd512_context      ctx_simd;
        sph_echo512_context      ctx_echo;
        sph_hamsi512_context     ctx_hamsi;
        sph_fugue512_context     ctx_fugue;
        sph_shabal512_context    ctx_shabal;
        sph_whirlpool_context    ctx_whirlpool;
        sph_sha512_context       ctx_sha512;
        sph_haval256_5_context   ctx_haval;

        sph_blake512_init(&ctx_blake);
        sph_blake512(&ctx_blake, input, 80);
        sph_blake512_close(&ctx_blake, hash);

        sph_bmw512_init(&ctx_bmw);
        sph_bmw512(&ctx_bmw, hash, 64);
        sph_bmw512_close(&ctx_bmw, hashB);

        sph_groestl512_init(&ctx_groestl);
        sph_groestl512(&ctx_groestl, hashB, 64);
        sph_groestl512_close(&ctx_groestl, hash);

        sph_skein512_init(&ctx_skein);
        sph_skein512(&ctx_skein, hash, 64);
        sph_skein512_close(&ctx_skein, hashB);

        sph_jh512_init(&ctx_jh);
        sph_jh512(&ctx_jh, hashB, 64);
        sph_jh512_close(&ctx_jh, hash);

        sph_keccak512_init(&ctx_keccak);
        sph_keccak512(&ctx_keccak, hash, 64);
        sph_keccak512_close(&ctx_keccak, hashB);

        sph_luffa512_init(&ctx_luffa);
        sph_luffa512(&ctx_luffa, hashB, 64);
        sph_luffa512_close(&ctx_luffa, hash);

        sph_cubehash512_init(&ctx_cubehash);
        sph_cubehash512(&ctx_cubehash, hash, 64);
        sph_cubehash512_close(&ctx_cubehash, hashB);

        sph_shavite512_init(&ctx_shavite);
        sph_shavite512(&ctx_shavite, hashB, 64);
        sph_shavite512_close(&ctx_shavite, hash);

        sph_simd512_init(&ctx_simd);
        sph_simd512(&ctx_simd, hash, 64);
        sph_simd512_close(&ctx_simd, hashB);

        sph_echo512_init(&ctx_echo);
        sph_echo512(&ctx_echo, hashB, 64);
        sph_echo512_close(&ctx_echo, hash);

        sph_hamsi512_init(&ctx_hamsi);
        sph_hamsi512(&ctx_hamsi, hash, 64);
        sph_hamsi512_close(&ctx_hamsi, hashB);

        sph_fugue512_init(&ctx_fugue);
        sph_fugue512(&ctx_fugue, hashB, 64);
        sph_fugue512_close(&ctx_fugue, hash);

        sph_shabal512_init(&ctx_shabal);
        sph_shabal512(&ctx_shabal, hash, 64);
        sph_shabal512_close(&ctx_shabal, hashB);

        sph_whirlpool_init(&ctx_whirlpool);
        sph_whirlpool(&ctx_whirlpool, hashB, 64);
        sph_whirlpool_close(&ctx_whirlpool, hash);

        sph_sha512_init(&ctx_sha512);
        sph_sha512(&ctx_sha512,(const void*) hash, 64);
        sph_sha512_close(&ctx_sha512,(void*) hash);

        sph_haval256_5_init(&ctx_haval);
        sph_haval256_5(&ctx_haval,(const void*) hash, 64);
        sph_haval256_5_close(&ctx_haval,hash);

        memcpy(output, hash, 32);
}

int scanhash_x17(int thr_id, struct work *work,
                    uint32_t max_nonce, uint64_t *hashes_done)
{
        uint32_t endiandata[20] __attribute__((aligned(64)));
        uint32_t hash64[8] __attribute__((aligned(32)));
        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;
	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];
	const uint32_t Htarg = ptarget[7];

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
        swab32_array( endiandata, pdata, 20 );

#ifdef DEBUG_ALGO
	if (Htarg != 0)
		printf("[%d] Htarg=%X\n", thr_id, Htarg);
#endif
	for (int m=0; m < 6; m++) {
		if (Htarg <= htmax[m]) {
			uint32_t mask = masks[m];
			do {
				pdata[19] = ++n;
				be32enc(&endiandata[19], n);
				x17hash(hash64, endiandata);
#ifndef DEBUG_ALGO
				if (!(hash64[7] & mask))
                                {
                                  if ( fulltest(hash64, ptarget)) {
					*hashes_done = n - first_nonce + 1;
					return true;
                                    }
//                                    else
//                                    {
//                                      applog(LOG_INFO, "Result does not validate on CPU!");
//                                     }
                         	}
#else
				if (!(n % 0x1000) && !thr_id) printf(".");
				if (!(hash64[7] & mask)) {
					printf("[%d]",thr_id);
					if (fulltest(hash64, ptarget)) {
						*hashes_done = n - first_nonce + 1;
						return true;
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

bool register_x17_algo( algo_gate_t* gate )
{
  gate->optimizations = SSE2_OPT | AES_OPT | AVX_OPT | AVX2_OPT;
  init_x17_ctx();
  gate->scanhash = (void*)&scanhash_x17;
  gate->hash     = (void*)&x17hash;
  gate->hash_alt = (void*)&x17hash_alt;
  return true;
};

