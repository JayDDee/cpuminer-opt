#include <memory.h>
#include "miner.h"
#include "algo-gate-api.h"
#include "lyra2.h"

void zcoin_hash(void *state, const void *input, uint32_t height)
{

	uint32_t _ALIGN(256) hash[16];

//        LYRA2Z(hash, 32, input, 80, input, 80, 2, height, 256);
        LYRA2Z(hash, 32, input, 80, input, 80, 2, 8192, 256);

	memcpy(state, hash, 32);
}

//int scanhash_zcoin(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done, uint32_t height)
int scanhash_zcoin( int thr_id, struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done )
{
	uint32_t _ALIGN(128) hash[8];
	uint32_t _ALIGN(128) endiandata[20];
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
		zcoin_hash( hash, endiandata, work->height );

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

bool zcoin_get_work_height( struct work* work, struct stratum_ctx* sctx )
{
   work->height = sctx->bloc_height;
   return false;
}

bool register_zcoin_algo( algo_gate_t* gate )
{
  gate->optimizations = SSE2_OPT | AES_OPT | AVX_OPT | AVX2_OPT;
  gate->scanhash   = (void*)&scanhash_zcoin;
  gate->hash       = (void*)&zcoin_hash;
  gate->hash_alt   = (void*)&zcoin_hash;
  gate->get_max64  = (void*)&get_max64_0xffffLL;
  gate->set_target = (void*)&zcoin_set_target;
  gate->prevent_dupes = (void*)&zcoin_get_work_height;
  return true;
};

