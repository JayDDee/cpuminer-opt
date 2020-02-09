#include "lyra2-gate.h"

#if !( defined(LYRA2REV3_16WAY) || defined(LYRA2REV3_8WAY) || defined(LYRA2REV3_4WAY) )

#include <memory.h>
#include "algo/blake/sph_blake.h"
#include "algo/cubehash/sph_cubehash.h"
#include "algo/bmw/sph_bmw.h"
#include "algo/cubehash/cubehash_sse2.h" 
//#include "lyra2.h"

typedef struct {
        cubehashParam           cube;
        sph_blake256_context     blake;
        sph_bmw256_context       bmw;

} lyra2v3_ctx_holder;

static lyra2v3_ctx_holder lyra2v3_ctx;
static __thread sph_blake256_context l2v3_blake_mid;

bool init_lyra2rev3_ctx()
{
        cubehashInit( &lyra2v3_ctx.cube, 256, 16, 32 );
        sph_blake256_init( &lyra2v3_ctx.blake );
        sph_bmw256_init( &lyra2v3_ctx.bmw );
        return true;
}

void l2v3_blake256_midstate( const void* input )
{
    memcpy( &l2v3_blake_mid, &lyra2v3_ctx.blake, sizeof l2v3_blake_mid );
    sph_blake256( &l2v3_blake_mid, input, 64 );
}

void lyra2rev3_hash( void *state, const void *input )
{
   lyra2v3_ctx_holder ctx __attribute__ ((aligned (64))); 
   memcpy( &ctx, &lyra2v3_ctx, sizeof(lyra2v3_ctx) );
   uint8_t hash[128] __attribute__ ((aligned (64)));
   #define hashA hash
   #define hashB hash+64
   const int midlen = 64;            // bytes
   const int tail   = 80 - midlen;   // 16

   memcpy( &ctx.blake, &l2v3_blake_mid, sizeof l2v3_blake_mid );
   sph_blake256( &ctx.blake, (uint8_t*)input + midlen, tail );
   sph_blake256_close( &ctx.blake, hash );

   LYRA2REV3( l2v3_wholeMatrix, hash, 32, hash, 32, hash, 32, 1, 4, 4 );

   cubehashUpdateDigest( &ctx.cube, (byte*) hashA,
                         (const byte*) hash, 32 );

   LYRA2REV3( l2v3_wholeMatrix, hash, 32, hash, 32, hash, 32, 1, 4, 4 );

   sph_bmw256( &ctx.bmw, hash, 32 );
   sph_bmw256_close( &ctx.bmw, hash );

	memcpy( state, hash, 32 );
}

int scanhash_lyra2rev3( struct work *work,
	uint32_t max_nonce, uint64_t *hashes_done, struct thr_info *mythr )
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

   // need big endian data
   casti_m128i( endiandata, 0 ) = mm128_bswap_32( casti_m128i( pdata, 0 ) );
   casti_m128i( endiandata, 1 ) = mm128_bswap_32( casti_m128i( pdata, 1 ) );
   casti_m128i( endiandata, 2 ) = mm128_bswap_32( casti_m128i( pdata, 2 ) );
   casti_m128i( endiandata, 3 ) = mm128_bswap_32( casti_m128i( pdata, 3 ) );
   casti_m128i( endiandata, 4 ) = mm128_bswap_32( casti_m128i( pdata, 4 ) );
   l2v3_blake256_midstate( endiandata );
   do
   {
	be32enc(&endiandata[19], nonce);
	lyra2rev3_hash(hash, endiandata);

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
