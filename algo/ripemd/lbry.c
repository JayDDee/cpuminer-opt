#include "lbry-gate.h"

#if !defined(LBRY_16WAY) && !defined(LBRY_8WAY) && !defined(LBRY_4WAY)

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "sph_ripemd.h"
#include "algo/sha/sha256-hash.h"

void lbry_hash(void* output, const void* input)
{
   sha256_context        ctx_sha256 __attribute__ ((aligned (64)));
   sph_sha512_context    ctx_sha512 __attribute__ ((aligned (64)));
   sph_ripemd160_context ctx_ripemd __attribute__ ((aligned (64)));
   uint32_t _ALIGN(64) hashA[16];
   uint32_t _ALIGN(64) hashB[16];
   uint32_t _ALIGN(64) hashC[16];

   sha256_full( hashA, input, 112 );
   sha256_full( hashA, hashA, 32 );

   sph_sha512_init( &ctx_sha512 );
   sph_sha512( &ctx_sha512, hashA, 32 );
   sph_sha512_close( &ctx_sha512, hashA );

   sph_ripemd160_init( &ctx_ripemd );
   sph_ripemd160 ( &ctx_ripemd, hashA, 32 );
   sph_ripemd160_close( &ctx_ripemd, hashB );

   sph_ripemd160_init( &ctx_ripemd );
   sph_ripemd160 ( &ctx_ripemd, hashA+8, 32 );
   sph_ripemd160_close( &ctx_ripemd, hashC );

   sha256_ctx_init( &ctx_sha256 );
   sha256_update( &ctx_sha256, hashB, 20 );
   sha256_update( &ctx_sha256, hashC, 20 );
   sha256_final( &ctx_sha256, hashA );

   sha256_full( hashA, hashA, 32 );
   
   memcpy( output, hashA, 32 );
}

int scanhash_lbry( struct work *work, uint32_t max_nonce,
                   uint64_t *hashes_done, struct thr_info *mythr)
{
  uint32_t *pdata = work->data;
  uint32_t *ptarget = work->target;
	uint32_t n = pdata[27] - 1;
	const uint32_t first_nonce = pdata[27];
	const uint32_t Htarg = ptarget[7];
   int thr_id = mythr->id;  // thr_id arg is deprecated

	uint32_t hash64[8] __attribute__((aligned(64)));
	uint32_t endiandata[32] __attribute__ ((aligned (64)));

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
        swab32_array( endiandata, pdata, 32 );

	for (int m=0; m < sizeof(masks); m++) {
		if (Htarg <= htmax[m]) {
			uint32_t mask = masks[m];
			do {
				pdata[27] = ++n;
				be32enc(&endiandata[27], n);
				lbry_hash(hash64, &endiandata);
				if ((!(hash64[7] & mask)) && fulltest(hash64, ptarget)) {
               pdata[27] = n;
               submit_solution( work, hash64, mythr );
				}
			} while ( (n < max_nonce -8) && !work_restart[thr_id].restart);
			break;
		}
	}

	*hashes_done = n - first_nonce + 1;
	pdata[27] = n;
	return 0;
}
#endif
