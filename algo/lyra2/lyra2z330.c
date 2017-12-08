#include <memory.h>
#include "algo-gate-api.h"
#include "lyra2.h"
#include "avxdefs.h"

__thread uint64_t* lyra2z330_wholeMatrix;

void lyra2z330_hash(void *state, const void *input, uint32_t height)
{
	uint32_t _ALIGN(256) hash[16];

        LYRA2Z( lyra2z330_wholeMatrix, hash, 32, input, 80, input, 80,
                 2, 330, 256 );

	memcpy(state, hash, 32);
}

int scanhash_lyra2z330( int thr_id, struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done )
{
	uint32_t hash[8] __attribute__ ((aligned (64))); 
	uint32_t endiandata[20] __attribute__ ((aligned (64)));
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

	do {
		be32enc(&endiandata[19], nonce);
		lyra2z330_hash( hash, endiandata, work->height );

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

void lyra2z330_set_target( struct work* work, double job_diff )
{
 work_set_target( work, job_diff / (256.0 * opt_diff_factor) );
}

bool lyra2z330_thread_init()
{
   const int64_t ROW_LEN_INT64 = BLOCK_LEN_INT64 * 256; // nCols
   const int64_t ROW_LEN_BYTES = ROW_LEN_INT64 * 8;

   int i = (int64_t)ROW_LEN_BYTES * 330; // nRows;
   lyra2z330_wholeMatrix = _mm_malloc( i, 64 );

   return lyra2z330_wholeMatrix;
}

bool register_lyra2z330_algo( algo_gate_t* gate )
{
  gate->optimizations = AVX_OPT | AVX2_OPT;
  gate->miner_thread_init = (void*)&lyra2z330_thread_init;
  gate->scanhash   = (void*)&scanhash_lyra2z330;
  gate->hash       = (void*)&lyra2z330_hash;
  gate->get_max64  = (void*)&get_max64_0xffffLL;
  gate->set_target = (void*)&lyra2z330_set_target;
  return true;
};

