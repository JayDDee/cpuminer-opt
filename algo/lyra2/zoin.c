#include <memory.h>
#include "miner.h"
#include "algo-gate-api.h"
#include "lyra2.h"

void zoin_hash(void *state, const void *input, uint32_t height)
{

	uint32_t _ALIGN(256) hash[16];

        LYRA2Z(hash, 32, input, 80, input, 80, 2, 330, 256);

	memcpy(state, hash, 32);
}

int scanhash_zoin( int thr_id, struct work *work, uint32_t max_nonce,
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
		zoin_hash( hash, endiandata, work->height );

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

void zoin_set_target( struct work* work, double job_diff )
{
 work_set_target( work, job_diff / (256.0 * opt_diff_factor) );
}

bool zoin_get_work_height( struct work* work, struct stratum_ctx* sctx )
{
   work->height = sctx->bloc_height;
   return false;
}

bool register_zoin_algo( algo_gate_t* gate )
{
  gate->optimizations = SSE2_OPT | AES_OPT | AVX_OPT | AVX2_OPT;
  gate->scanhash   = (void*)&scanhash_zoin;
  gate->hash       = (void*)&zoin_hash;
  gate->hash_alt   = (void*)&zoin_hash;
  gate->get_max64  = (void*)&get_max64_0xffffLL;
  gate->set_target = (void*)&zoin_set_target;
  gate->prevent_dupes = (void*)&zoin_get_work_height;
  return true;
};

