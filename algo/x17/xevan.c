#include "xevan-gate.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "algo/blake/sph_blake.h"
#include "algo/bmw/sph_bmw.h"
#include "algo/jh/sph_jh.h"
#include "algo/keccak/sph_keccak.h"
#include "algo/skein/sph_skein.h"
#include "algo/shavite/sph_shavite.h"
#include "algo/luffa/sse2/luffa_for_sse2.h"
#include "algo/hamsi/sph_hamsi.h"
#include "algo/fugue/sph_fugue.h"
#include "algo/shabal/sph_shabal.h"
#include "algo/whirlpool/sph_whirlpool.h"
#include "algo/sha/sph_sha2.h"
#include "algo/haval/sph-haval.h"
#include "algo/simd/sse2/nist.h"
#include "algo/cubehash/sse2/cubehash_sse2.h"
#include <openssl/sha.h>
#ifdef NO_AES_NI
  #include "algo/groestl/sph_groestl.h"
  #include "algo/echo/sph_echo.h"
#else
  #include "algo/groestl/aes_ni/hash-groestl.h"
  #include "algo/echo/aes_ni/hash_api.h"
#endif

typedef struct {
        sph_blake512_context    blake;
        sph_bmw512_context      bmw;
        sph_skein512_context    skein;
        sph_jh512_context       jh;
        sph_keccak512_context   keccak;
        hashState_luffa         luffa;
        cubehashParam           cubehash;
        sph_shavite512_context  shavite;
        hashState_sd            simd;
        sph_hamsi512_context    hamsi;
        sph_fugue512_context    fugue;
        sph_shabal512_context   shabal;
        sph_whirlpool_context   whirlpool;
#ifndef USE_SPH_SHA
        SHA512_CTX              sha512;
#else
        sph_sha512_context      sha512;
#endif
        sph_haval256_5_context  haval;
#ifdef NO_AES_NI
        sph_groestl512_context  groestl;
        sph_echo512_context     echo;
#else
        hashState_echo          echo;
        hashState_groestl       groestl;
#endif
} xevan_ctx_holder;

xevan_ctx_holder xevan_ctx __attribute__ ((aligned (64)));
static __thread sph_blake512_context xevan_blake_mid
                                        __attribute__ ((aligned (64)));

void init_xevan_ctx()
{
        sph_blake512_init(&xevan_ctx.blake);
        sph_bmw512_init(&xevan_ctx.bmw);
        sph_skein512_init(&xevan_ctx.skein);
        sph_jh512_init(&xevan_ctx.jh);
        sph_keccak512_init(&xevan_ctx.keccak);
        init_luffa( &xevan_ctx.luffa, 512 );
        cubehashInit( &xevan_ctx.cubehash, 512, 16, 32 );
        sph_shavite512_init( &xevan_ctx.shavite );
        init_sd( &xevan_ctx.simd, 512 );
        sph_hamsi512_init( &xevan_ctx.hamsi );
        sph_fugue512_init( &xevan_ctx.fugue );
        sph_shabal512_init( &xevan_ctx.shabal );
        sph_whirlpool_init( &xevan_ctx.whirlpool );
#ifndef USE_SPH_SHA
        SHA512_Init( &xevan_ctx.sha512 );
#else
        sph_sha512_init(&xevan_ctx.sha512);
#endif
        sph_haval256_5_init(&xevan_ctx.haval);
#ifdef NO_AES_NI
        sph_groestl512_init( &xevan_ctx.groestl );
        sph_echo512_init( &xevan_ctx.echo );
#else
        init_groestl( &xevan_ctx.groestl, 64 );
        init_echo( &xevan_ctx.echo, 512 );
#endif
};

void xevan_blake512_midstate( const void* input )
{
    memcpy( &xevan_blake_mid, &xevan_ctx.blake, sizeof xevan_blake_mid );
    sph_blake512( &xevan_blake_mid, input, 64 );
}

void xevan_hash(void *output, const void *input)
{
        uint32_t _ALIGN(64) hash[32]; // 128 bytes required
	const int dataLen = 128;
        xevan_ctx_holder ctx __attribute__ ((aligned (64)));
        memcpy( &ctx, &xevan_ctx, sizeof(xevan_ctx) );

        const int midlen = 64;            // bytes
        const int tail   = 80 - midlen;   // 16

        memcpy( &ctx.blake, &xevan_blake_mid, sizeof xevan_blake_mid );
        sph_blake512( &ctx.blake, input + midlen, tail );
	sph_blake512_close(&ctx.blake, hash);

	memset(&hash[16], 0, 64);

	sph_bmw512(&ctx.bmw, hash, dataLen);
	sph_bmw512_close(&ctx.bmw, hash);

#ifdef NO_AES_NI
	sph_groestl512(&ctx.groestl, hash, dataLen);
	sph_groestl512_close(&ctx.groestl, hash);
#else
        update_and_final_groestl( &ctx.groestl, (char*)hash, 
                                  (const char*)hash, dataLen*8 );
#endif

	sph_skein512(&ctx.skein, hash, dataLen);
	sph_skein512_close(&ctx.skein, hash);

	sph_jh512(&ctx.jh, hash, dataLen);
	sph_jh512_close(&ctx.jh, hash);

	sph_keccak512(&ctx.keccak, hash, dataLen);
	sph_keccak512_close(&ctx.keccak, hash);

        update_and_final_luffa( &ctx.luffa, (BitSequence*)hash,
                                (const BitSequence*)hash, dataLen );

        cubehashUpdateDigest( &ctx.cubehash, (byte*)hash,
                              (const byte*) hash, dataLen );

	sph_shavite512(&ctx.shavite, hash, dataLen);
	sph_shavite512_close(&ctx.shavite, hash);

        update_final_sd( &ctx.simd, (BitSequence *)hash,
                         (const BitSequence *)hash, dataLen*8 );

#ifdef NO_AES_NI
	sph_echo512(&ctx.echo, hash, dataLen);
	sph_echo512_close(&ctx.echo, hash);
#else
        update_final_echo( &ctx.echo, (BitSequence *) hash, 
                           (const BitSequence *) hash, dataLen*8 );
#endif

	sph_hamsi512(&ctx.hamsi, hash, dataLen);
	sph_hamsi512_close(&ctx.hamsi, hash);

	sph_fugue512(&ctx.fugue, hash, dataLen);
	sph_fugue512_close(&ctx.fugue, hash);

	sph_shabal512(&ctx.shabal, hash, dataLen);
	sph_shabal512_close(&ctx.shabal, hash);

	sph_whirlpool(&ctx.whirlpool, hash, dataLen);
	sph_whirlpool_close(&ctx.whirlpool, hash);

#ifndef USE_SPH_SHA
        SHA512_Update( &ctx.sha512, hash, dataLen );
        SHA512_Final( (unsigned char*) hash, &ctx.sha512 );
#else
	sph_sha512(&ctx.sha512,(const void*) hash, dataLen);
	sph_sha512_close(&ctx.sha512,(void*) hash);
#endif
	sph_haval256_5(&ctx.haval,(const void*) hash, dataLen);
	sph_haval256_5_close(&ctx.haval, hash);

	memset(&hash[8], 0, dataLen - 32);

        memcpy( &ctx, &xevan_ctx, sizeof(xevan_ctx) );

	sph_blake512(&ctx.blake, hash, dataLen);
	sph_blake512_close(&ctx.blake, hash);

	sph_bmw512(&ctx.bmw, hash, dataLen);
	sph_bmw512_close(&ctx.bmw, hash);

#ifdef NO_AES_NI
        sph_groestl512(&ctx.groestl, hash, dataLen);
        sph_groestl512_close(&ctx.groestl, hash);
#else
        update_and_final_groestl( &ctx.groestl, (char*)hash,
                                  (const BitSequence*)hash, dataLen*8 );
#endif

	sph_skein512(&ctx.skein, hash, dataLen);
	sph_skein512_close(&ctx.skein, hash);

	sph_jh512(&ctx.jh, hash, dataLen);
	sph_jh512_close(&ctx.jh, hash);

	sph_keccak512(&ctx.keccak, hash, dataLen);
	sph_keccak512_close(&ctx.keccak, hash);
        update_and_final_luffa( &ctx.luffa, (BitSequence*)hash,
                                (const BitSequence*)hash, dataLen );

        cubehashUpdateDigest( &ctx.cubehash, (byte*)hash,
                              (const byte*) hash, dataLen );

	sph_shavite512(&ctx.shavite, hash, dataLen);
	sph_shavite512_close(&ctx.shavite, hash);

        update_final_sd( &ctx.simd, (BitSequence *)hash,
                         (const BitSequence *)hash, dataLen*8 );

#ifdef NO_AES_NI
        sph_echo512(&ctx.echo, hash, dataLen);
        sph_echo512_close(&ctx.echo, hash);
#else
        update_final_echo( &ctx.echo, (BitSequence *) hash,
                           (const BitSequence *) hash, dataLen*8 );
#endif

	sph_hamsi512(&ctx.hamsi, hash, dataLen);
	sph_hamsi512_close(&ctx.hamsi, hash);

	sph_fugue512(&ctx.fugue, hash, dataLen);
	sph_fugue512_close(&ctx.fugue, hash);

	sph_shabal512(&ctx.shabal, hash, dataLen);
	sph_shabal512_close(&ctx.shabal, hash);

	sph_whirlpool(&ctx.whirlpool, hash, dataLen);
	sph_whirlpool_close(&ctx.whirlpool, hash);

#ifndef USE_SPH_SHA
        SHA512_Update( &ctx.sha512, hash, dataLen );
        SHA512_Final( (unsigned char*) hash, &ctx.sha512 );
#else
	sph_sha512(&ctx.sha512,(const void*) hash, dataLen);
	sph_sha512_close(&ctx.sha512,(void*) hash);
#endif
	sph_haval256_5(&ctx.haval,(const void*) hash, dataLen);
	sph_haval256_5_close(&ctx.haval, hash);

	memcpy(output, hash, 32);
}

int scanhash_xevan(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t _ALIGN(64) hash[8];
	uint32_t _ALIGN(64) endiandata[20];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;

	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];
	uint32_t nonce = first_nonce;
	volatile uint8_t *restart = &(work_restart[thr_id].restart);

	if (opt_benchmark)
		ptarget[7] = 0x0cff;

	for (int k=0; k < 19; k++)
		be32enc(&endiandata[k], pdata[k]);

        xevan_blake512_midstate( endiandata );

	do {
		be32enc(&endiandata[19], nonce);
		xevan_hash(hash, endiandata);

		if (hash[7] <= Htarg && fulltest(hash, ptarget)) {
			work_set_target_ratio(work, hash);
			pdata[19] = nonce;
			*hashes_done = pdata[19] - first_nonce;
			return 1;
		}
		nonce++;

	} while (nonce < max_nonce && !(*restart));

	pdata[19] = nonce;
	*hashes_done = pdata[19] - first_nonce + 1;
	return 0;
}

