#include "nist5-gate.h"

#if !defined(NIST5_8WAY) && !defined(NIST5_4WAY)

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "algo/blake/sph_blake.h"
#include "algo/jh/sph_jh.h"
#include "algo/keccak/sph_keccak.h"
#include "algo/skein/sph_skein.h"
#if defined(__AES__)
  #include "algo/groestl/aes_ni/hash-groestl.h"
#else
  #include "algo/groestl/sph_groestl.h"
#endif

void nist5hash(void *output, const void *input)
{
   uint32_t hash[16] __attribute__((aligned(64)));
   sph_blake512_context    ctx_blake;
#if defined(__AES__)
   hashState_groestl       ctx_groestl;
#else
   sph_groestl512_context  ctx_groestl;
#endif
   sph_skein512_context    ctx_skein;
   sph_jh512_context       ctx_jh;
   sph_keccak512_context   ctx_keccak;

   sph_blake512_init( &ctx_blake );
   sph_blake512( &ctx_blake, input, 80 );
   sph_blake512_close( &ctx_blake, hash );

#if defined(__AES__)
   init_groestl( &ctx_groestl, 64 );
   update_and_final_groestl( &ctx_groestl, (char*)hash,
                                     (const char*)hash, 512 );
#else
   sph_groestl512_init( &ctx_groestl );
   sph_groestl512( &ctx_groestl, hash, 64 );
   sph_groestl512_close( &ctx_groestl, hash );
#endif

   sph_jh512_init( &ctx_jh );
   sph_jh512( &ctx_jh, hash, 64 );
   sph_jh512_close( &ctx_jh, hash );

   sph_keccak512_init( &ctx_keccak );
   sph_keccak512( &ctx_keccak, hash, 64 );
   sph_keccak512_close( &ctx_keccak, hash );

   sph_skein512_init( &ctx_skein );
   sph_skein512( &ctx_skein, hash, 64 );
   sph_skein512_close( &ctx_skein, hash );

   memcpy( output, hash, 32 );
}

int scanhash_nist5( struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done, struct thr_info *mythr)
{
   uint32_t endiandata[20] __attribute__((aligned(64)));
   uint32_t hash64[8] __attribute__((aligned(32)));
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
				nist5hash(hash64, endiandata);
				if ((!(hash64[7] & mask)) && fulltest(hash64, ptarget))
                submit_solution( work, hash64, mythr );
			} while (n < max_nonce && !work_restart[thr_id].restart);
			break;
		}
	}

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}
#endif
