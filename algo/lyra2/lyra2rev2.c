#include "lyra2-gate.h"

#if !( defined(LYRA2REV2_16WAY) || defined(LYRA2REV2_8WAY) || defined(LYRA2REV2_4WAY) )

#include <memory.h>
#include "algo/blake/sph_blake.h"
#include "algo/cubehash/sph_cubehash.h"
#include "algo/keccak/sph_keccak.h"
#include "algo/skein/sph_skein.h"
#include "algo/bmw/sph_bmw.h"
#include "algo/cubehash/cubehash_sse2.h" 
//#include "lyra2.h"

typedef struct {
        cubehashParam           cube1;
        cubehashParam           cube2;
        sph_blake256_context     blake;
        sph_keccak256_context    keccak;
        sph_skein256_context     skein;
        sph_bmw256_context       bmw;

} lyra2v2_ctx_holder;

static lyra2v2_ctx_holder lyra2v2_ctx;
static __thread sph_blake256_context l2v2_blake_mid;

bool init_lyra2rev2_ctx()
{
        cubehashInit( &lyra2v2_ctx.cube1, 256, 16, 32 );
        cubehashInit( &lyra2v2_ctx.cube2, 256, 16, 32 );
        sph_blake256_init( &lyra2v2_ctx.blake );
        sph_keccak256_init( &lyra2v2_ctx.keccak );
        sph_skein256_init( &lyra2v2_ctx.skein );
        sph_bmw256_init( &lyra2v2_ctx.bmw );
        return true;
}

void l2v2_blake256_midstate( const void* input )
{
    memcpy( &l2v2_blake_mid, &lyra2v2_ctx.blake, sizeof l2v2_blake_mid );
    sph_blake256( &l2v2_blake_mid, input, 64 );
}

void lyra2rev2_hash( void *state, const void *input )
{
   lyra2v2_ctx_holder ctx __attribute__ ((aligned (64))); 
   memcpy( &ctx, &lyra2v2_ctx, sizeof(lyra2v2_ctx) );
   uint8_t hash[128] __attribute__ ((aligned (64)));
   #define hashA hash
   #define hashB hash+64
   const int midlen = 64;            // bytes
   const int tail   = 80 - midlen;   // 16

   memcpy( &ctx.blake, &l2v2_blake_mid, sizeof l2v2_blake_mid );
	sph_blake256( &ctx.blake, (uint8_t*)input + midlen, tail );
	sph_blake256_close( &ctx.blake, hashA );

	sph_keccak256( &ctx.keccak, hashA, 32 );
	sph_keccak256_close(&ctx.keccak, hashB);

   cubehashUpdateDigest( &ctx.cube1, (byte*) hashA,
                               (const byte*) hashB, 32 );

	LYRA2REV2( l2v2_wholeMatrix, hashA, 32, hashA, 32, hashA, 32, 1, 4, 4 );

	sph_skein256( &ctx.skein, hashA, 32 );
	sph_skein256_close( &ctx.skein, hashB );

   cubehashUpdateDigest( &ctx.cube2, (byte*) hashA, 
                               (const byte*) hashB, 32 );

	sph_bmw256( &ctx.bmw, hashA, 32 );
	sph_bmw256_close( &ctx.bmw, hashB );

	memcpy( state, hashB, 32 );
}

int scanhash_lyra2rev2( struct work *work,
	uint32_t max_nonce, uint64_t *hashes_done, struct thr_info *mythr)
{
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
	uint32_t endiandata[20] __attribute__ ((aligned (64)));
   uint32_t hash[8] __attribute__((aligned(64)));
	const uint32_t first_nonce = pdata[19];
	uint32_t nonce = first_nonce;
        const uint32_t Htarg = ptarget[7];
   int thr_id = mythr->id;  // thr_id arg is deprecated

	if (opt_benchmark)
		((uint32_t*)ptarget)[7] = 0x0000ff;

   swab32_array( endiandata, pdata, 20 );

   l2v2_blake256_midstate( endiandata );

	do {
		be32enc(&endiandata[19], nonce);
		lyra2rev2_hash(hash, endiandata);

		if (hash[7] <= Htarg )
      if( valid_hash( hash, ptarget ) && !opt_benchmark )
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
