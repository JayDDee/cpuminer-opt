#include "miner.h"
#include "algo-gate-api.h"

#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <stdlib.h>

#include "yescrypt.h"

// segfaults, scanhash never returns


int scanhash_yescrypt(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t _ALIGN(64) vhash[8];
	uint32_t _ALIGN(64) endiandata[20];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;

	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];
	uint32_t n = first_nonce;

        for (int k = 0; k < 19; k++)
                be32enc(&endiandata[k], pdata[k]);

	do {
		be32enc(&endiandata[19], n);
		yescrypt_hash((char*) endiandata, (char*) vhash, 80);
		if (vhash[7] < Htarg && fulltest(vhash, ptarget)) {
			work_set_target_ratio( work, vhash );
			*hashes_done = n - first_nonce + 1;
			pdata[19] = n;
			return true;
		}
		n++;
	} while (n < max_nonce && !work_restart[thr_id].restart);

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;

	return 0;
}

int64_t yescrypt_get_max64 ()
{
  return 0x1ffLL;
}

bool register_yescrypt_algo ( algo_gate_t* gate )
{
   gate->scanhash   = (void*)&scanhash_yescrypt;
   gate->hash       = (void*)&yescrypt_hash;
   gate->set_target = (void*)&scrypt_set_target;
   gate->get_max64  = (void*)&yescrypt_get_max64;
   return true;
}

