#include <memory.h>

#include "miner.h"
#include "algo-gate-api.h"

#include "algo/blake/sph_blake.h"
#include "algo/cubehash/sph_cubehash.h"
#include "algo/keccak/sph_keccak.h"
#include "algo/skein/sph_skein.h"
#include "algo/bmw/sph_bmw.h"

#include "algo/cubehash/sse2/cubehash_sse2.h" 

#include "lyra2.h"

typedef struct {
        cubehashParam           cube1;
        cubehashParam           cube2;
        sph_blake256_context     blake;
        sph_keccak256_context    keccak;
        sph_skein256_context     skein;
        sph_bmw256_context       bmw;

} lyra2v2_ctx_holder;

lyra2v2_ctx_holder lyra2v2_ctx;

void init_lyra2rev2_ctx()
{
        cubehashInit( &lyra2v2_ctx.cube1, 256, 16, 32 );
        cubehashInit( &lyra2v2_ctx.cube2, 256, 16, 32 );
        sph_blake256_init( &lyra2v2_ctx.blake );
        sph_keccak256_init( &lyra2v2_ctx.keccak );
        sph_skein256_init( &lyra2v2_ctx.skein );
        sph_bmw256_init( &lyra2v2_ctx.bmw );
}

void lyra2rev2_hash( void *state, const void *input )
{
        lyra2v2_ctx_holder ctx;
        memcpy( &ctx, &lyra2v2_ctx, sizeof(lyra2v2_ctx) );

	uint32_t _ALIGN(128) hashA[8], hashB[8];

	sph_blake256( &ctx.blake, input, 80 );
	sph_blake256_close( &ctx.blake, hashA );

	sph_keccak256( &ctx.keccak, hashA, 32 );
	sph_keccak256_close(&ctx.keccak, hashB);

        cubehashUpdate( &ctx.cube1, (const byte*) hashB,32 );
        cubehashDigest( &ctx.cube1, (byte*)hashA );

	LYRA2( hashA, 32, hashA, 32, hashA, 32, 1, 4, 4 );

	sph_skein256( &ctx.skein, hashA, 32 );
	sph_skein256_close( &ctx.skein, hashB );

        cubehashUpdate( &ctx.cube2, (const byte*) hashB,32 );
        cubehashDigest( &ctx.cube2, (byte*)hashA );

	sph_bmw256( &ctx.bmw, hashA, 32 );
	sph_bmw256_close( &ctx.bmw, hashB );

	memcpy( state, hashB, 32 );
}

int scanhash_lyra2rev2(int thr_id, struct work *work,
	uint32_t max_nonce, uint64_t *hashes_done)
{
        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;
	uint32_t _ALIGN(64) endiandata[20];
        uint32_t hash[8] __attribute__((aligned(32)));
	const uint32_t first_nonce = pdata[19];
	uint32_t nonce = first_nonce;
        const uint32_t Htarg = ptarget[7];

	if (opt_benchmark)
		((uint32_t*)ptarget)[7] = 0x0000ff;

        swab32_array( endiandata, pdata, 20 );

	do {
		be32enc(&endiandata[19], nonce);
		lyra2rev2_hash(hash, endiandata);

		if (hash[7] <= Htarg )
                {
                   if( fulltest(hash, ptarget) )
                   {
			pdata[19] = nonce;
			*hashes_done = pdata[19] - first_nonce;
		   	return 1;
		   }
                }
		nonce++;

	} while (nonce < max_nonce && !work_restart[thr_id].restart);

	pdata[19] = nonce;
	*hashes_done = pdata[19] - first_nonce + 1;
	return 0;
}

void lyra2rev2_set_target( struct work* work, double job_diff )
{
 work_set_target( work, job_diff / (256.0 * opt_diff_factor) );
}

bool register_lyra2rev2_algo( algo_gate_t* gate )
{
  init_lyra2rev2_ctx();
  gate->optimizations = SSE2_OPT | AES_OPT | AVX_OPT | AVX2_OPT;
  gate->scanhash   = (void*)&scanhash_lyra2rev2;
  gate->hash       = (void*)&lyra2rev2_hash;
  gate->hash_alt   = (void*)&lyra2rev2_hash;
  gate->set_target = (void*)&lyra2rev2_set_target;
  return true;
};

