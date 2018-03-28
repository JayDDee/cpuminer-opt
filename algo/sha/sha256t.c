#include "sha256t-gate.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "sph_sha2.h"
#include <openssl/sha.h>

#if !defined(SHA256T_4WAY)

#ifndef USE_SPH_SHA
 static __thread SHA256_CTX sha256t_ctx __attribute__ ((aligned (64)));
#else
 static __thread sph_sha256_context sha256t_ctx __attribute__ ((aligned (64)));
#endif

void sha256t_midstate( const void* input )
{
#ifndef USE_SPH_SHA
    SHA256_Init( &sha256t_ctx );
    SHA256_Update( &sha256t_ctx, input, 64 );
#else
    sph_sha256_init( &sha256t_ctx );
    sph_sha256( &sha256t_ctx, input, 64 );
#endif
}

void sha256t_hash( void* output, const void* input )
{
	uint32_t _ALIGN(64) hashA[16];
        const int midlen = 64;            // bytes
        const int tail   = 80 - midlen;   // 16

#ifndef USE_SPH_SHA 
        SHA256_CTX ctx_sha256 __attribute__ ((aligned (64)));
        memcpy( &ctx_sha256, &sha256t_ctx, sizeof sha256t_ctx );

        SHA256_Update( &ctx_sha256, input + midlen, tail );
        SHA256_Final( (unsigned char*)hashA, &ctx_sha256 );

        SHA256_Init( &ctx_sha256 );
        SHA256_Update( &ctx_sha256, hashA, 32 );
        SHA256_Final( (unsigned char*)hashA, &ctx_sha256 );

        SHA256_Init( &ctx_sha256 );
        SHA256_Update( &ctx_sha256, hashA, 32 );
        SHA256_Final( (unsigned char*)hashA, &ctx_sha256 );
#else
        sph_sha256_context ctx_sha256 __attribute__ ((aligned (64)));
        memcpy( &ctx_sha256, &sha256t_mid, sizeof sha256t_mid );

        sph_sha256( &ctx_sha256, input + midlen, tail );
	sph_sha256_close( &ctx_sha256, hashA );

        sph_sha256_init( &ctx_sha256 );
	sph_sha256( &ctx_sha256, hashA, 32 );
	sph_sha256_close( &ctx_sha256, hashA );

        sph_sha256_init( &ctx_sha256 );
	sph_sha256( &ctx_sha256, hashA, 32 );
	sph_sha256_close( &ctx_sha256, hashA );
#endif
	memcpy( output, hashA, 32 );
}

int scanhash_sha256t(int thr_id, struct work *work,
				uint32_t max_nonce, uint64_t *hashes_done)
{
        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;
	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];
	const uint32_t Htarg = ptarget[7];
#ifdef _MSC_VER
	uint32_t __declspec(align(32)) hash64[8];
#else
	uint32_t hash64[8] __attribute__((aligned(32)));
#endif
	uint32_t endiandata[32];

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
        for (int k = 0; k < 19; k++)
                be32enc(&endiandata[k], pdata[k]);

        sha256t_midstate( endiandata );

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
				sha256t_hash( hash64, endiandata );
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
#endif
