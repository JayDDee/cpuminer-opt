#include "miner.h"
#include "algo-gate-api.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

// Optimized luffa doesn't find blocks with qubit
#define LUFFA_SSE2_BROKEN

#include "algo/luffa/sph_luffa.h"
#include "algo/cubehash/sph_cubehash.h"
#include "algo/shavite/sph_shavite.h"
#include "algo/simd/sph_simd.h"
#include "algo/echo/sph_echo.h"

#include "algo/luffa/sse2/luffa_for_sse2.h" 
#include "algo/cubehash/sse2/cubehash_sse2.h" 
#include "algo/simd/sse2/nist.h"
#include "algo/shavite/sph_shavite.h"

#ifndef NO_AES_NI
#include "algo/echo/aes_ni/hash_api.h"
#endif

typedef struct
{
#ifdef LUFFA_SSE2_BROKEN
        sph_luffa512_context    luffa;
#else
         hashState_luffa         luffa;
#endif
        cubehashParam           cubehash;
        sph_shavite512_context  shavite;
        hashState_sd            simd;
#ifdef NO_AES_NI
        sph_echo512_context echo;
#else
        hashState_echo          echo;
#endif
} qubit_ctx_holder;

qubit_ctx_holder qubit_ctx;

void init_qubit_ctx()
{
#ifdef LUFFA_SSE2_BROKEN
        sph_luffa512_init(&qubit_ctx.luffa);
#else
        init_luffa(&qubit_ctx.luffa,512);
#endif
        cubehashInit(&qubit_ctx.cubehash,512,16,32);
        sph_shavite512_init(&qubit_ctx.shavite);
        init_sd(&qubit_ctx.simd,512);
#ifdef NO_AES_NI
        sph_echo512_init(&qubit_ctx.echo);
#else
        init_echo(&qubit_ctx.echo, 512);
#endif
};

void qubithash(void *output, const void *input)
{
        unsigned char hash[128]; // uint32_t hashA[16], hashB[16];
        #define hashB hash+64

        qubit_ctx_holder ctx;
        memcpy( &ctx, &qubit_ctx, sizeof(qubit_ctx) );

#ifdef LUFFA_SSE2_BROKEN
        sph_luffa512 (&ctx.luffa, input, 80);
        sph_luffa512_close(&ctx.luffa, (void*) hash);
#else
//        init_luffa(&qubit_ctx.luffa,512);
        update_luffa( &ctx.luffa, (const BitSequence*)input, 80 );
        final_luffa( &ctx.luffa, (BitSequence*)hash);
#endif

        cubehashUpdate( &ctx.cubehash, (const byte*) hash,64);
        cubehashDigest( &ctx.cubehash, (byte*)hash);

        sph_shavite512( &ctx.shavite, hash, 64);
        sph_shavite512_close( &ctx.shavite, hash);

        update_sd( &ctx.simd, (const BitSequence *)hash,512);
        final_sd( &ctx.simd, (BitSequence *)hash);

#ifdef NO_AES_NI
        sph_echo512 (&ctx.echo, (const void*) hash, 64);
        sph_echo512_close(&ctx.echo, (void*) hash);
#else
        update_echo ( &ctx.echo, (const BitSequence *) hash, 512);
        final_echo( &ctx.echo, (BitSequence *) hash);
#endif

        asm volatile ("emms");
        memcpy(output, hash, 32);
}

void qubithash_alt(void *output, const void *input)
{
        sph_luffa512_context ctx_luffa;
        sph_cubehash512_context ctx_cubehash;
        sph_shavite512_context ctx_shavite;
        sph_simd512_context ctx_simd;
        sph_echo512_context ctx_echo;

        uint8_t hash[64];

        sph_luffa512_init(&ctx_luffa);
        sph_luffa512 (&ctx_luffa, input, 80);
        sph_luffa512_close(&ctx_luffa, (void*) hash);

        sph_cubehash512_init(&ctx_cubehash);
        sph_cubehash512 (&ctx_cubehash, (const void*) hash, 64);
        sph_cubehash512_close(&ctx_cubehash, (void*) hash);

        sph_shavite512_init(&ctx_shavite);
        sph_shavite512 (&ctx_shavite, (const void*) hash, 64);
        sph_shavite512_close(&ctx_shavite, (void*) hash);

        sph_simd512_init(&ctx_simd);
        sph_simd512 (&ctx_simd, (const void*) hash, 64);
        sph_simd512_close(&ctx_simd, (void*) hash);

        sph_echo512_init(&ctx_echo);
        sph_echo512 (&ctx_echo, (const void*) hash, 64);
        sph_echo512_close(&ctx_echo, (void*) hash);

        memcpy(output, hash, 32);
}


int scanhash_qubit(int thr_id, struct work *work,
		uint32_t max_nonce, uint64_t *hashes_done)
{
        uint32_t endiandata[20] __attribute__((aligned(64)));
        uint32_t hash64[8] __attribute__((aligned(32)));
        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;
	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];
	const uint32_t Htarg = ptarget[7];

	uint64_t htmax[] = { 0, 0xF, 0xFF,  0xFFF, 0xFFFF, 0x10000000 };
	uint32_t masks[] =
          { 0xFFFFFFFF, 0xFFFFFFF0, 0xFFFFFF00, 0xFFFFF000, 0xFFFF0000, 0 };

	// we need bigendian data...
        swab32_array( endiandata, pdata, 20 );

#ifdef DEBUG_ALGO
	printf("[%d] Htarg=%X\n", thr_id, Htarg);
#endif
	for ( int m=0; m < 6; m++ )
        {
	    if ( Htarg <= htmax[m] )
            {
	        uint32_t mask = masks[m];
	        do
                {
	            pdata[19] = ++n;
		    be32enc(&endiandata[19], n);
		    qubithash(hash64, endiandata);
#ifndef DEBUG_ALGO
		    if (!(hash64[7] & mask))
                    {
                       if ( fulltest(hash64, ptarget) )
                       {
		          *hashes_done = n - first_nonce + 1;
		          return true;
                       }
//                       else
//                       {
//                          applog(LOG_INFO, "Result does not validate on CPU!");
//                       }
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
                } while ( n < max_nonce && !work_restart[thr_id].restart );
                // see blake.c if else to understand the loop on htmax => mask
            break;
          } 
        }

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}

bool register_qubit_algo( algo_gate_t* gate )
{
  gate->optimizations = SSE2_OPT | AES_OPT | AVX_OPT | AVX2_OPT;
  init_qubit_ctx();
  gate->scanhash = (void*)&scanhash_qubit;
  gate->hash     = (void*)&qubithash;
  gate->hash_alt = (void*)&qubithash_alt;
  return true;
};

