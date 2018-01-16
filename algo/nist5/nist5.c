#include "nist5-gate.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "algo/blake/sph_blake.h"
#include "algo/groestl/sph_groestl.h"
#include "algo/skein/sph_skein.h"
#include "algo/jh/sph_jh.h"
#include "algo/keccak/sph_keccak.h"

#include "algo/blake/sse2/blake.c"
#include "algo/keccak/sse2/keccak.c"
#include "algo/skein/sse2/skein.c"
#include "algo/jh/sse2/jh_sse2_opt64.h"

#ifndef NO_AES_NI
  #include "algo/groestl/aes_ni/hash-groestl.h"
#endif

typedef struct {
#ifdef NO_AES_NI
    sph_groestl512_context groestl;
#else
    hashState_groestl      groestl;
#endif
} nist5_ctx_holder;

nist5_ctx_holder nist5_ctx;

void init_nist5_ctx()
{
#ifdef NO_AES_NI
     sph_groestl512_init( &nist5_ctx.groestl );
#else
     init_groestl( &nist5_ctx.groestl, 64 );
#endif
}

void nist5hash(void *output, const void *input)
{
     size_t hashptr;
     unsigned char hashbuf[128];
     sph_u64 hashctA;
     sph_u64 hashctB;
     unsigned char hash[128] __attribute__ ((aligned (64))) ;
     #define hashA hash
     #define hashB hash+64

     nist5_ctx_holder ctx __attribute__ ((aligned (64)));
     memcpy( &ctx, &nist5_ctx, sizeof(nist5_ctx) );

     DECL_BLK;
     BLK_I;
     BLK_W;
     BLK_C;

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

     memcpy(output, hash, 32);
}

int scanhash_nist5(int thr_id, struct work *work,
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
	printf("[%d] Htarg=%X\n", thr_id, Htarg);
#endif
	for (int m=0; m < 6; m++) {
		if (Htarg <= htmax[m]) {
			uint32_t mask = masks[m];
			do {
				pdata[19] = ++n;
				be32enc(&endiandata[19], n);
				nist5hash(hash64, endiandata);
#ifndef DEBUG_ALGO
				if ((!(hash64[7] & mask)) && fulltest(hash64, ptarget)) {
					*hashes_done = n - first_nonce + 1;
					return true;
				}
#else
				if (!(n % 0x1000) && !thr_id) printf(".");
				if (!(hash64[7] & mask)) {
					printf("[%d]",thr_id);
					if (fulltest(hash64, ptarget)) {
                                                work_set_target_ratio( work, hash64 );
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
/*
bool register_nist5_algo( algo_gate_t* gate )
{
    gate->optimizations = SSE2_OPT | AES_OPT;
    init_nist5_ctx();
    gate->scanhash = (void*)&scanhash_nist5;
    gate->hash     = (void*)&nist5hash;
    return true;
};
*/
