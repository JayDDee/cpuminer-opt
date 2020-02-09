#include <memory.h>
#include <mm_malloc.h>
#include "lyra2-gate.h"

#if !( defined(LYRA2Z_16WAY) || defined(LYRA2Z_8WAY) || defined(LYRA2Z_4WAY) )

#include "lyra2.h"
#include "algo/blake/sph_blake.h"
#include "simd-utils.h"

__thread uint64_t* lyra2z_matrix;

bool lyra2z_thread_init()
{
//   const int64_t ROW_LEN_INT64 = BLOCK_LEN_INT64 * 8; // nCols
//   const int64_t ROW_LEN_BYTES = ROW_LEN_INT64 * 8;
//   int i = (int64_t)ROW_LEN_BYTES * 8; // nRows;
   const int i = BLOCK_LEN_INT64 * 8 * 8 * 8;
   lyra2z_matrix = _mm_malloc( i, 64 );
   return lyra2z_matrix;
}

static __thread sph_blake256_context lyra2z_blake_mid;

void lyra2z_midstate( const void* input )
{
       sph_blake256_init( &lyra2z_blake_mid );
       sph_blake256( &lyra2z_blake_mid, input, 64 );
}

// block 2050 new algo, blake plus new lyra parms. new input
// is power of 2 so normal lyra can be used
//void zcoin_hash(void *state, const void *input, uint32_t height)
void lyra2z_hash( void *state, const void *input )
{
        uint32_t _ALIGN(64) hash[16];

        sph_blake256_context ctx_blake __attribute__ ((aligned (64)));

        memcpy( &ctx_blake, &lyra2z_blake_mid, sizeof lyra2z_blake_mid );
        sph_blake256( &ctx_blake, input + 64, 16 );
        sph_blake256_close( &ctx_blake, hash );

        LYRA2Z( lyra2z_matrix, hash, 32, hash, 32, hash, 32, 8, 8, 8);

    memcpy(state, hash, 32);
}

int scanhash_lyra2z( struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done, struct thr_info *mythr )
{
	uint32_t _ALIGN(64) hash[8];
	uint32_t _ALIGN(64) endiandata[20];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;
	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];
	uint32_t nonce = first_nonce;
   int thr_id = mythr->id; 

	if (opt_benchmark)
		ptarget[7] = 0x0000ff;

	for (int i=0; i < 19; i++) {
		be32enc(&endiandata[i], pdata[i]);
	}

   lyra2z_midstate( endiandata );

	do {
		be32enc(&endiandata[19], nonce);
                lyra2z_hash( hash, endiandata );

      if ( valid_hash( hash, ptarget ) && !opt_benchmark )
      {
			pdata[19] = nonce;
			submit_solution( work, hash, mythr );
	   }
		nonce++;
	} while ( nonce < max_nonce && !work_restart[thr_id].restart );
	pdata[19] = nonce;
	*hashes_done = pdata[19] - first_nonce + 1;
	return 0;
}
#endif
