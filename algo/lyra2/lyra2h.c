#include "lyra2-gate.h"

#if !( defined(LYRA2H_8WAY) || defined(LYRA2H_4WAY) )

#include <memory.h>
#include <mm_malloc.h>
#include "lyra2.h"
#include "algo/blake/sph_blake.h"

__thread uint64_t* lyra2h_matrix;

bool lyra2h_thread_init()
{
   lyra2h_matrix = _mm_malloc( LYRA2H_MATRIX_SIZE, 64 );
   return lyra2h_matrix;
}

static __thread sph_blake256_context lyra2h_blake_mid;

void lyra2h_midstate( const void* input )
{
       sph_blake256_init( &lyra2h_blake_mid );
       sph_blake256( &lyra2h_blake_mid, input, 64 );
}

void lyra2h_hash( void *state, const void *input )
{
        uint32_t _ALIGN(64) hash[16];

        sph_blake256_context ctx_blake __attribute__ ((aligned (64)));

        memcpy( &ctx_blake, &lyra2h_blake_mid, sizeof lyra2h_blake_mid );
        sph_blake256( &ctx_blake, input + 64, 16 );
        sph_blake256_close( &ctx_blake, hash );

        LYRA2Z( lyra2h_matrix, hash, 32, hash, 32, hash, 32, 16, 16, 16 );

    memcpy(state, hash, 32);
}

int scanhash_lyra2h( struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done, struct thr_info *mythr )
{
	uint32_t _ALIGN(64) hash[8];
	uint32_t _ALIGN(64) endiandata[20];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;
	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];
	uint32_t nonce = first_nonce;
   int thr_id = mythr->id;  // thr_id arg is deprecated

	if (opt_benchmark)
		ptarget[7] = 0x0000ff;

	for (int i=0; i < 19; i++) {
		be32enc(&endiandata[i], pdata[i]);
	}

   lyra2h_midstate( endiandata );
	do {
		be32enc(&endiandata[19], nonce);
                lyra2h_hash( hash, endiandata );

		if ( hash[7] <= Htarg )
      if ( fulltest( hash, ptarget ) && !opt_benchmark )
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
