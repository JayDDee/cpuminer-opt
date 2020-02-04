#include "groestl-gate.h"

#if !defined(GROESTL_8WAY) && !defined(GROESTLX16R_4WAY)

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#ifdef __AES__
  #include "algo/groestl/aes_ni/hash-groestl.h"
#else
  #include "sph_groestl.h"
#endif

typedef struct
{
#ifdef __AES__
    hashState_groestl groestl1, groestl2;
#else
    sph_groestl512_context groestl1, groestl2;
#endif

} groestl_ctx_holder;

static groestl_ctx_holder groestl_ctx;

void init_groestl_ctx()
{
#ifdef __AES__
    init_groestl( &groestl_ctx.groestl1, 64 );
    init_groestl( &groestl_ctx.groestl2, 64 );
#else
    sph_groestl512_init( &groestl_ctx.groestl1 );
    sph_groestl512_init( &groestl_ctx.groestl2 );
#endif
}

void groestlhash( void *output, const void *input )
{
     uint32_t hash[16] __attribute__ ((aligned (64)));
     groestl_ctx_holder ctx __attribute__ ((aligned (64)));
     memcpy( &ctx, &groestl_ctx, sizeof(groestl_ctx) );

#ifdef __AES__
     update_and_final_groestl( &ctx.groestl1, (char*)hash,
                               (const char*)input, 640 );

     update_and_final_groestl( &ctx.groestl2, (char*)hash,
                               (const char*)hash, 512 );
#else
     sph_groestl512(&ctx.groestl1, input, 80);
     sph_groestl512_close(&ctx.groestl1, hash);

     sph_groestl512(&ctx.groestl2, hash, 64);
     sph_groestl512_close(&ctx.groestl2, hash);
#endif
     memcpy(output, hash, 32);
 }

int scanhash_groestl( struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done, struct thr_info *mythr )
{
        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;
        uint32_t endiandata[20] __attribute__ ((aligned (64)));
	const uint32_t first_nonce = pdata[19];
	uint32_t nonce = first_nonce;
   int thr_id = mythr->id;  // thr_id arg is deprecated

	if (opt_benchmark)
		((uint32_t*)ptarget)[7] = 0x0000ff;

        swab32_array( endiandata, pdata, 20 );

	do {
		const uint32_t Htarg = ptarget[7];
		uint32_t hash[8] __attribute__ ((aligned (64)));
		be32enc(&endiandata[19], nonce);
		groestlhash(hash, endiandata);

		if (hash[7] <= Htarg )
      if ( fulltest(hash, ptarget) && !opt_benchmark )
      {
			pdata[19] = nonce;
         submit_solution( work, hash, mythr );
	   }
		nonce++;
	} while (nonce < max_nonce && !work_restart[thr_id].restart);

	pdata[19] = nonce;
	*hashes_done = pdata[19] - first_nonce + 1;
	return 0;
}
#endif
