#include "x13sm3-gate.h"

#if !defined(X13SM3_8WAY) && !defined(X13SM3_4WAY)

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "algo/blake/sph_blake.h"
#include "algo/bmw/sph_bmw.h"
#include "algo/jh/sph_jh.h"
#include "algo/keccak/sph_keccak.h"
#include "algo/sm3/sph_sm3.h"
#include "algo/skein/sph_skein.h"
#include "algo/shavite/sph_shavite.h"
#include "algo/hamsi/sph_hamsi.h"
#include "algo/fugue/sph_fugue.h"
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
   sm3_ctx_t               sm3;
   sph_hamsi512_context    hamsi;
   sph_fugue512_context    fugue;
} hsr_ctx_holder;

hsr_ctx_holder hsr_ctx;

void init_x13sm3_ctx()
{
   sph_blake512_init( &hsr_ctx.blake );
   sph_bmw512_init( &hsr_ctx.bmw );
#if defined(__AES__)
   init_groestl( &hsr_ctx.groestl, 64 );
   init_echo( &hsr_ctx.echo, 512 );
#else
   sph_groestl512_init( &hsr_ctx.groestl );
   sph_echo512_init( &hsr_ctx.echo );
#endif
   sph_skein512_init( &hsr_ctx.skein );
   sph_jh512_init( &hsr_ctx.jh );
   sph_keccak512_init( &hsr_ctx.keccak );
   init_luffa( &hsr_ctx.luffa,512 );
   cubehashInit( &hsr_ctx.cube,512,16,32 );
   sph_shavite512_init( &hsr_ctx.shavite );
   init_sd( &hsr_ctx.simd,512 );
   sm3_init( &hsr_ctx.sm3 );
   sph_hamsi512_init( &hsr_ctx.hamsi );
   sph_fugue512_init( &hsr_ctx.fugue );
};

void x13sm3_hash(void *output, const void *input)
{
    unsigned char hash[64] __attribute__((aligned(64)));
    hsr_ctx_holder ctx;
    memcpy( &ctx, &hsr_ctx, sizeof(hsr_ctx) );

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


        //--- luffa7
        update_and_final_luffa( &ctx.luffa, (BitSequence*)hash,
                                (const BitSequence*)hash, 64 );

        // 8 Cube
        cubehashUpdateDigest( &ctx.cube, (byte*) hash,
                              (const byte*)hash, 64 );

        // 9 Shavite
        sph_shavite512( &ctx.shavite, hash, 64);
        sph_shavite512_close( &ctx.shavite, hash);

        // 10 Simd
        update_final_sd( &ctx.simd, (BitSequence *)hash,
                         (const BitSequence *)hash, 512 );

        //11---echo---
#ifdef __AES__
        update_final_echo ( &ctx.echo, (BitSequence *)hash,
                            (const BitSequence *)hash, 512 );
#else
        sph_echo512(&ctx.echo, hash, 64);
        sph_echo512_close(&ctx.echo, hash);
#endif

        uint32_t sm3_hash[32] __attribute__ ((aligned (32)));
        memset(sm3_hash, 0, sizeof sm3_hash);

        sph_sm3(&ctx.sm3, hash, 64);
        sph_sm3_close(&ctx.sm3, sm3_hash);

        sph_hamsi512(&ctx.hamsi, sm3_hash, 64);
        sph_hamsi512_close(&ctx.hamsi, hash);

        sph_fugue512(&ctx.fugue, hash, 64);
        sph_fugue512_close(&ctx.fugue, hash);

        asm volatile ("emms");
	memcpy(output, hash, 32);
}

int scanhash_x13sm3( struct work *work, uint32_t max_nonce,
                     uint64_t *hashes_done, struct thr_info *mythr)
{
        uint32_t endiandata[20] __attribute__((aligned(64)));
        uint32_t hash64[8] __attribute__((aligned(64)));
        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;
	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];
   int thr_id = mythr->id;  // thr_id arg is deprecated
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

	for (int m=0; m < 6; m++) {
		if (Htarg <= htmax[m]) {
			uint32_t mask = masks[m];
			do {
				pdata[19] = ++n;
				be32enc(&endiandata[19], n);
				x13sm3_hash(hash64, endiandata);
				if ((!(hash64[7] & mask)) && fulltest(hash64, ptarget))
                submit_solution( work, hash64, mythr );
			} while (n < max_nonce && !work_restart[thr_id].restart);
			// see blake.c if else to understand the loop on htmax => mask
			break;
		}
	}

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}

#endif
