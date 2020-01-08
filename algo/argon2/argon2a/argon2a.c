#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <openssl/sha.h>
#include "ar2/argon2.h"
#include "ar2/cores.h"
#include "ar2/ar2-scrypt-jane.h"
#include "algo-gate-api.h"

#define T_COSTS 2
#define M_COSTS 16
#define MASK 8
#define ZERO 0

inline void argon_call(void *out, void *in, void *salt, int type)
{
	argon2_context context;

	context.out = (uint8_t *)out;
	context.pwd = (uint8_t *)in;
	context.salt = (uint8_t*)salt;
	context.pwdlen = 0;
	context.allocate_cbk = NULL;
	context.free_cbk = NULL;

	ar2_argon2_core(&context, type);
}

void argon2hash(void *output, const void *input)
{
	uint32_t _ALIGN(64) hashA[8], hashB[8];

	my_scrypt((const unsigned char *)input, 80,
		(const unsigned char *)input, 80,
		(unsigned char *)hashA);

	argon_call(hashB, hashA, hashA, (hashA[0] & MASK) == ZERO);

	my_scrypt((const unsigned char *)hashB, 32,
		(const unsigned char *)hashB, 32,
		(unsigned char *)output);
}

int scanhash_argon2( struct work* work, uint32_t max_nonce,
                     uint64_t *hashes_done, struct thr_info *mythr )
{
	uint32_t _ALIGN(64) endiandata[20];
	uint32_t _ALIGN(64) hash[8];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;
   int thr_id = mythr->id;  // thr_id arg is deprecated

	const uint32_t first_nonce = pdata[19];
	const uint32_t Htarg = ptarget[7];
	uint32_t nonce = first_nonce;

        swab32_array( endiandata, pdata, 20 );

	do {
		be32enc(&endiandata[19], nonce);
		argon2hash(hash, endiandata);
		if (hash[7] <= Htarg && fulltest(hash, ptarget)) {
			pdata[19] = nonce;
         submit_solution( work, hash, mythr );
		}
		nonce++;
	} while (nonce < max_nonce && !work_restart[thr_id].restart);

	pdata[19] = nonce;
	*hashes_done = pdata[19] - first_nonce + 1;
	return 0;
}

bool register_argon2_algo( algo_gate_t* gate )
{
  gate->optimizations = SSE2_OPT | AVX_OPT | AVX2_OPT;
  gate->scanhash        = (void*)&scanhash_argon2;
  gate->hash            = (void*)&argon2hash;
  gate->gen_merkle_root = (void*)&SHA256_gen_merkle_root;
  opt_target_factor = 65536.0;

  return true;
};

