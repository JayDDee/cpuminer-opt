#include "cpuminer-config.h"
#include "quark-gate.h"

#if !defined(QUARK_8WAY) && !defined(QUARK_4WAY)

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "algo/blake/sph_blake.h"
#include "algo/bmw/sph_bmw.h"
#include "algo/jh/sph_jh.h"
#include "algo/keccak/sph_keccak.h"
#include "algo/skein/sph_skein.h"
#if defined(__AES__)
  #include "algo/groestl/aes_ni/hash-groestl.h"
#else
  #include "algo/groestl/sph_groestl.h"
#endif

void quark_hash(void *state, const void *input)
{
   uint32_t hash[16] __attribute__((aligned(64)));
   sph_blake512_context    ctx_blake;
   sph_bmw512_context      ctx_bmw;
#if defined(__AES__)
   hashState_groestl       ctx_groestl;
#else
   sph_groestl512_context  ctx_groestl;
#endif
   sph_skein512_context    ctx_skein;
   sph_jh512_context       ctx_jh;
   sph_keccak512_context   ctx_keccak;
   uint32_t mask = 8;

   sph_blake512_init( &ctx_blake );
   sph_blake512( &ctx_blake, input, 80 );
   sph_blake512_close( &ctx_blake, hash );

   sph_bmw512_init( &ctx_bmw );
   sph_bmw512( &ctx_bmw, hash, 64 );
   sph_bmw512_close( &ctx_bmw, hash ); 

   if ( hash[0] & mask )
   {
#if defined(__AES__)
      init_groestl( &ctx_groestl, 64 );
      update_and_final_groestl( &ctx_groestl, (char*)hash,
                                        (const char*)hash, 512 );
#else
      sph_groestl512_init( &ctx_groestl );
      sph_groestl512( &ctx_groestl, hash, 64 );
      sph_groestl512_close( &ctx_groestl, hash );
#endif
   }
   else
   {
      sph_skein512_init( &ctx_skein );
      sph_skein512( &ctx_skein, hash, 64 );
      sph_skein512_close( &ctx_skein, hash );
   }

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

   if ( hash[0] & mask )
   {
      sph_blake512_init( &ctx_blake );
      sph_blake512( &ctx_blake, hash, 64 );
      sph_blake512_close( &ctx_blake, hash );
   }
   else
   {
      sph_bmw512_init( &ctx_bmw );
      sph_bmw512( &ctx_bmw, hash, 64 );
      sph_bmw512_close( &ctx_bmw, hash );
   }

   sph_keccak512_init( &ctx_keccak );
   sph_keccak512( &ctx_keccak, hash, 64 );
   sph_keccak512_close( &ctx_keccak, hash );

   sph_skein512_init( &ctx_skein );
   sph_skein512( &ctx_skein, hash, 64 );
   sph_skein512_close( &ctx_skein, hash );

   if ( hash[0] & mask )
   {
      sph_keccak512_init( &ctx_keccak );
      sph_keccak512( &ctx_keccak, hash, 64 );
      sph_keccak512_close( &ctx_keccak, hash );
   }
   else
   {
      sph_jh512_init( &ctx_jh );
      sph_jh512( &ctx_jh, hash, 64 );
      sph_jh512_close( &ctx_jh, hash );
   }

   memcpy(state, hash, 32);
}


int scanhash_quark( struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t endiandata[20] __attribute__((aligned(64)));
   uint32_t hash64[8] __attribute__((aligned(32)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];
   int thr_id = mythr->id;  // thr_id arg is deprecated

   swab32_array( endiandata, pdata, 20 );

	do {
		pdata[19] = ++n;
		be32enc(&endiandata[19], n); 
		quark_hash(hash64, &endiandata);
      if ((hash64[7]&0xFFFFFF00)==0)
      {
         if (fulltest(hash64, ptarget)) 
                submit_solution( work, hash64, mythr );
      }
	} while (n < max_nonce && !work_restart[thr_id].restart);
	
	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}
#endif
