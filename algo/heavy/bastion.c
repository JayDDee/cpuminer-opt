#include "algo-gate-api.h"

#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <stdlib.h>

#include "sph_hefty1.h"

#include "algo/luffa/sph_luffa.h"
#include "algo/fugue/sph_fugue.h"
#include "algo/skein/sph_skein.h"
#include "algo/whirlpool/sph_whirlpool.h"
#include "algo/shabal/sph_shabal.h"
#include "algo/echo/sph_echo.h"
#include "algo/hamsi/sph_hamsi.h"
#include "algo/luffa/sse2/luffa_for_sse2.h"
#include "algo/skein/sse2/skein.c"

#ifndef NO_AES_NI
  #include "algo/echo/aes_ni/hash_api.h"
#endif

void bastionhash(void *output, const void *input)
{
	unsigned char hash[64] __attribute__ ((aligned (64)));

#ifdef NO_AES_NI
        sph_echo512_context     ctx_echo;
#else
        hashState_echo          ctx_echo;
#endif
        hashState_luffa         ctx_luffa;
	sph_fugue512_context ctx_fugue;
	sph_whirlpool_context ctx_whirlpool;
	sph_shabal512_context ctx_shabal;
	sph_hamsi512_context ctx_hamsi;

        unsigned char hashbuf[128] __attribute__ ((aligned (16)));
        sph_u64 hashctA;
//        sph_u64 hashctB;
        size_t hashptr;

	HEFTY1(input, 80, hash);

        init_luffa( &ctx_luffa, 512 );
        update_and_final_luffa( &ctx_luffa, (BitSequence*)hash,
                                (const BitSequence*)hash, 64 );
//        update_luffa( &ctx_luffa, hash, 64 );
//        final_luffa( &ctx_luffa, hash );

	if (hash[0] & 0x8)
	{
		sph_fugue512_init(&ctx_fugue);
		sph_fugue512(&ctx_fugue, hash, 64);
		sph_fugue512_close(&ctx_fugue, hash);
	} else {
                DECL_SKN;
                SKN_I;
                SKN_U;
                SKN_C;
	}

	sph_whirlpool_init(&ctx_whirlpool);
	sph_whirlpool(&ctx_whirlpool, hash, 64);
	sph_whirlpool_close(&ctx_whirlpool, hash);

	sph_fugue512_init(&ctx_fugue);
	sph_fugue512(&ctx_fugue, hash, 64);
	sph_fugue512_close(&ctx_fugue, hash);

	if (hash[0] & 0x8)
	{
#ifdef NO_AES_NI
		sph_echo512_init(&ctx_echo);
		sph_echo512(&ctx_echo, hash, 64);
		sph_echo512_close(&ctx_echo, hash);
#else
                init_echo( &ctx_echo, 512 );
                update_final_echo ( &ctx_echo,(BitSequence*)hash,
                                    (const BitSequence*)hash, 512 );
//                update_echo ( &ctx_echo, hash, 512 );
//                final_echo( &ctx_echo,  hash );
#endif
	} else {
                init_luffa( &ctx_luffa, 512 );
                update_and_final_luffa( &ctx_luffa, (BitSequence*)hash,
                                        (const BitSequence*)hash, 64 );
//                update_luffa( &ctx_luffa, hash, 64 );
//                final_luffa( &ctx_luffa, hash );
	}

	sph_shabal512_init(&ctx_shabal);
	sph_shabal512(&ctx_shabal, hash, 64);
	sph_shabal512_close(&ctx_shabal, hash);

        DECL_SKN;
        SKN_I;
        SKN_U;
        SKN_C;

	if (hash[0] & 0x8)
	{
		sph_shabal512_init(&ctx_shabal);
		sph_shabal512(&ctx_shabal, hash, 64);
		sph_shabal512_close(&ctx_shabal, hash);
	} else {
		sph_whirlpool_init(&ctx_whirlpool);
		sph_whirlpool(&ctx_whirlpool, hash, 64);
		sph_whirlpool_close(&ctx_whirlpool, hash);
	}

	sph_shabal512_init(&ctx_shabal);
	sph_shabal512(&ctx_shabal, hash, 64);
	sph_shabal512_close(&ctx_shabal, hash);

	if (hash[0] & 0x8)
	{
		sph_hamsi512_init(&ctx_hamsi);
		sph_hamsi512(&ctx_hamsi, hash, 64);
		sph_hamsi512_close(&ctx_hamsi, hash);
	} else {
                init_luffa( &ctx_luffa, 512 );
                update_and_final_luffa( &ctx_luffa, (BitSequence*)hash,
                                        (const BitSequence*)hash, 64 );
//                update_luffa( &ctx_luffa, hash, 64 );
//                final_luffa( &ctx_luffa, hash );
	}

	memcpy(output, hash, 32);
}

int scanhash_bastion(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t _ALIGN(64) hash32[8];
	uint32_t _ALIGN(64) endiandata[20];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;

	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];

	uint32_t n = first_nonce;

	for (int i=0; i < 19; i++) 
		be32enc(&endiandata[i], pdata[i]);

	do {
		be32enc(&endiandata[19], n);
		bastionhash(hash32, endiandata);
		if (hash32[7] < Htarg && fulltest(hash32, ptarget)) {
			work_set_target_ratio(work, hash32);
			*hashes_done = n - first_nonce + 1;
			pdata[19] = n;
			return true;
		}
		n++;

	} while (n < max_nonce && !work_restart[thr_id].restart);

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;

	return 0;
}

bool register_bastion_algo( algo_gate_t* gate )
{
  gate->optimizations = SSE2_OPT | AES_OPT;
  gate->scanhash = (void*)&scanhash_bastion;
  gate->hash     = (void*)&bastionhash;
  return true;
};

