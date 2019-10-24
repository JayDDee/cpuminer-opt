#include <memory.h>

#include "algo/blake/sph_blake.h"
#include "algo/groestl/sph_groestl.h"
#include "algo/skein/sph_skein.h"
#include "algo/keccak/sph_keccak.h"
#include "lyra2.h"
#include "algo-gate-api.h"
#include "simd-utils.h"
#if defined(__AES__)
  #include "algo/groestl/aes_ni/hash-groestl256.h"
#endif

//__thread uint64_t* lyra2re_wholeMatrix;

typedef struct {
        sph_blake256_context     blake;
        sph_keccak256_context    keccak;
        sph_skein256_context     skein;
#if defined(__AES__)
        hashState_groestl256     groestl;
#else
        sph_groestl256_context   groestl;
#endif
} lyra2re_ctx_holder;

lyra2re_ctx_holder lyra2re_ctx;
static __thread sph_blake256_context lyra2_blake_mid;

void init_lyra2re_ctx()
{
        sph_blake256_init(&lyra2re_ctx.blake);
        sph_keccak256_init(&lyra2re_ctx.keccak);
        sph_skein256_init(&lyra2re_ctx.skein);
#if defined(__AES__)
        init_groestl256( &lyra2re_ctx.groestl, 32 );
#else
        sph_groestl256_init(&lyra2re_ctx.groestl);
#endif
}

void lyra2_blake256_midstate( const void* input )
{
    memcpy( &lyra2_blake_mid, &lyra2re_ctx.blake, sizeof lyra2_blake_mid );
    sph_blake256( &lyra2_blake_mid, input, 64 );
}

void lyra2re_hash(void *state, const void *input)
{
        lyra2re_ctx_holder ctx __attribute__ ((aligned (64))) ;
        memcpy(&ctx, &lyra2re_ctx, sizeof(lyra2re_ctx));

	uint8_t _ALIGN(64) hash[32*8];
        #define hashA hash
        #define hashB hash+16

        const int midlen = 64;            // bytes
        const int tail   = 80 - midlen;   // 16

        memcpy( &ctx.blake, &lyra2_blake_mid, sizeof lyra2_blake_mid );
        sph_blake256( &ctx.blake, input + midlen, tail );

	sph_blake256_close(&ctx.blake, hashA);

	sph_keccak256(&ctx.keccak, hashA, 32);
	sph_keccak256_close(&ctx.keccak, hashB);

        LYRA2RE( hashA, 32, hashB, 32, hashB, 32, 1, 8, 8);
//	LYRA2RE( lyra2re_wholeMatrix, hashA, 32, hashB, 32, hashB, 32, 1, 8, 8);

	sph_skein256(&ctx.skein, hashA, 32);
	sph_skein256_close(&ctx.skein, hashB);

#if defined(__AES__)
        update_and_final_groestl256( &ctx.groestl, hashA, hashB, 256 );
#else
	sph_groestl256( &ctx.groestl, hashB, 32 );
	sph_groestl256_close( &ctx.groestl, hashA );
#endif

	memcpy(state, hashA, 32);
}

int scanhash_lyra2re( struct work *work, uint32_t max_nonce,
	              uint64_t *hashes_done, struct thr_info *mythr )
{
        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;
	uint32_t _ALIGN(64) endiandata[20];
        uint32_t hash[8] __attribute__((aligned(64)));
	const uint32_t first_nonce = pdata[19];
	uint32_t nonce = first_nonce;
        const uint32_t Htarg = ptarget[7];
   int thr_id = mythr->id;  // thr_id arg is deprecated

        swab32_array( endiandata, pdata, 20 );

        lyra2_blake256_midstate( endiandata );

	do {
		be32enc(&endiandata[19], nonce);
		lyra2re_hash(hash, endiandata);
		if ( hash[7] <= Htarg )
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

bool register_lyra2re_algo( algo_gate_t* gate )
{
  init_lyra2re_ctx();
  gate->optimizations = SSE2_OPT | AES_OPT | SSE42_OPT | AVX2_OPT;
  gate->scanhash   = (void*)&scanhash_lyra2re;
  gate->hash       = (void*)&lyra2re_hash;
  opt_target_factor = 128.0;
  return true;
};

