#include <memory.h>
#include <mm_malloc.h>
#include "miner.h"
#include "algo-gate-api.h"
#include "lyra2.h"
#include "algo/blake/sph_blake.h"
#include "avxdefs.h"

__thread uint64_t* zcoin_wholeMatrix;

static __thread sph_blake256_context zcoin_blake_mid;


void zcoin_midstate( const void* input )
{
       sph_blake256_init( &zcoin_blake_mid );
       sph_blake256( &zcoin_blake_mid, input, 64 );
}

// block 2050 new algo, blake plus new lyra parms. new input
// is power of 2 so normal lyra can be used
//void zcoin_hash(void *state, const void *input, uint32_t height)
void zcoin_hash(void *state, const void *input )
{
        uint32_t _ALIGN(64) hash[16];

        sph_blake256_context ctx_blake __attribute__ ((aligned (64)));

        memcpy( &ctx_blake, &zcoin_blake_mid, sizeof zcoin_blake_mid );
        sph_blake256( &ctx_blake, input + 64, 16 );
        sph_blake256_close( &ctx_blake, hash );

        LYRA2Z( zcoin_wholeMatrix, hash, 32, hash, 32, hash, 32, 8, 8, 8);

    memcpy(state, hash, 32);
}

int scanhash_zcoin( int thr_id, struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done )
{
	uint32_t _ALIGN(64) hash[8];
	uint32_t _ALIGN(64) endiandata[20];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;
	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];
	uint32_t nonce = first_nonce;

	if (opt_benchmark)
		ptarget[7] = 0x0000ff;

	for (int i=0; i < 19; i++) {
		be32enc(&endiandata[i], pdata[i]);
	}

        zcoin_midstate( endiandata );

	do {
		be32enc(&endiandata[19], nonce);
                zcoin_hash( hash, endiandata );

		if (hash[7] <= Htarg && fulltest(hash, ptarget)) {
			work_set_target_ratio(work, hash);
			pdata[19] = nonce;
			*hashes_done = pdata[19] - first_nonce;
			return 1;
		}
		nonce++;

	} while (nonce < max_nonce && !work_restart[thr_id].restart);

	pdata[19] = nonce;
	*hashes_done = pdata[19] - first_nonce + 1;
	return 0;
}

//int64_t get_max64_0xffffLL() { return 0xffffLL; };

void zcoin_set_target( struct work* work, double job_diff )
{
 work_set_target( work, job_diff / (256.0 * opt_diff_factor) );
}
/*
bool zcoin_get_work_height( struct work* work, struct stratum_ctx* sctx )
{
   work->height = sctx->bloc_height;
   return false;
}
*/

bool zcoin_thread_init()
{
   const int64_t ROW_LEN_INT64 = BLOCK_LEN_INT64 * 8; // nCols
   const int64_t ROW_LEN_BYTES = ROW_LEN_INT64 * 8;

   int i = (int64_t)ROW_LEN_BYTES * 8; // nRows;
   zcoin_wholeMatrix = _mm_malloc( i, 64 );

   if ( zcoin_wholeMatrix == NULL )
     return false;

#if defined (__AVX2__)
   memset_zero_m256i( (__m256i*)zcoin_wholeMatrix, i/32 );
#elif defined(__AVX__)
   memset_zero_m128i( (__m128i*)zcoin_wholeMatrix, i/16 );
#else
   memset( zcoin_wholeMatrix, 0, i );
#endif
   return true;
}

bool register_zcoin_algo( algo_gate_t* gate )
{
  gate->optimizations = SSE2_OPT | AES_OPT | AVX_OPT | AVX2_OPT;
  gate->miner_thread_init = (void*)&zcoin_thread_init;
  gate->scanhash   = (void*)&scanhash_zcoin;
  gate->hash       = (void*)&zcoin_hash;
  gate->get_max64  = (void*)&get_max64_0xffffLL;
  gate->set_target = (void*)&zcoin_set_target;
//  gate->prevent_dupes = (void*)&zcoin_get_work_height;
  return true;
};

