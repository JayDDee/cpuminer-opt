#include "jha-gate.h"

#if !defined(JHA_8WAY) && !defined(JHA_4WAY)

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "algo/blake/sph_blake.h"
#include "algo/jh/sph_jh.h"
#include "algo/keccak/sph_keccak.h"
#include "algo/skein/sph_skein.h"
#ifdef __AES__
  #include "algo/groestl/aes_ni/hash-groestl.h"
#else
  #include "algo/groestl/sph_groestl.h"
#endif

static __thread sph_keccak512_context jha_kec_mid __attribute__ ((aligned (64)));

void jha_kec_midstate( const void* input )
{
    sph_keccak512_init( &jha_kec_mid );
    sph_keccak512( &jha_kec_mid, input, 64 );
}

void jha_hash(void *output, const void *input)
{
	uint8_t _ALIGN(128) hash[64];

#ifdef __AES__
   hashState_groestl      ctx_groestl;
#else
	sph_groestl512_context ctx_groestl;
#endif
   sph_blake512_context ctx_blake;
	sph_jh512_context ctx_jh;
	sph_keccak512_context ctx_keccak;
	sph_skein512_context ctx_skein;

        memcpy( &ctx_keccak, &jha_kec_mid, sizeof jha_kec_mid );
        sph_keccak512(&ctx_keccak, input+64, 16 );
	sph_keccak512_close(&ctx_keccak, hash );

	// Heavy & Light Pair Loop
	for (int round = 0; round < 3; round++)
	{
	   if (hash[0] & 0x01)
      {
#ifdef __AES__
         init_groestl( &ctx_groestl, 64 );
         update_and_final_groestl( &ctx_groestl, (char*)hash,
                                              (char*)hash, 512 );
#else
   		sph_groestl512_init(&ctx_groestl);
	   	sph_groestl512(&ctx_groestl, hash, 64 );
		   sph_groestl512_close(&ctx_groestl, hash );
#endif
      }
      else
      {
		   sph_skein512_init(&ctx_skein);
		   sph_skein512(&ctx_skein, hash, 64);
		   sph_skein512_close(&ctx_skein, hash );
	   }

	   if (hash[0] & 0x01)
      {
		   sph_blake512_init(&ctx_blake);
		   sph_blake512(&ctx_blake, hash, 64);
		   sph_blake512_close(&ctx_blake, hash );
	   }
      else
      {
		   sph_jh512_init(&ctx_jh);
		   sph_jh512(&ctx_jh, hash, 64 );
		   sph_jh512_close(&ctx_jh, hash );
	   }
	}

	memcpy(output, hash, 32);
}

int scanhash_jha( struct work *work, uint32_t max_nonce,
                  uint64_t *hashes_done, struct thr_info *mythr )
{
	uint32_t _ALIGN(128) hash32[8];
	uint32_t _ALIGN(128) endiandata[20];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;
	const uint32_t first_nonce = pdata[19];
	const uint32_t Htarg = ptarget[7];
   uint32_t n = pdata[19] - 1;
   int thr_id = mythr->id;  // thr_id arg is deprecated

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
	for (int i=0; i < 19; i++) {
		be32enc(&endiandata[i], pdata[i]);
	}

        jha_kec_midstate( endiandata );

	for (int m=0; m < 6; m++) {
		if (Htarg <= htmax[m]) {
			uint32_t mask = masks[m];
			do {
				pdata[19] = ++n;
				be32enc(&endiandata[19], n);
				jha_hash(hash32, endiandata);
				if ((!(hash32[7] & mask)) && fulltest(hash32, ptarget)) 
               submit_solution( work, hash32, mythr );
			} while (n < max_nonce && !work_restart[thr_id].restart);
			break;
		}
	}

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}

#endif
