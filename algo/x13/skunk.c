#include "skunk-gate.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "algo/gost/sph_gost.h"
#include "algo/skein/sph_skein.h"
#include "algo/fugue/sph_fugue.h"
#include "algo/cubehash/sse2/cubehash_sse2.h"

typedef struct {
    sph_skein512_context  skein;
    cubehashParam         cube;
    sph_fugue512_context  fugue;
    sph_gost512_context   gost;
} skunk_ctx_holder;

static __thread skunk_ctx_holder skunk_ctx;

void skunkhash( void *output, const void *input )
{
     unsigned char hash[128] __attribute__ ((aligned (64)));

     skunk_ctx_holder ctx __attribute__ ((aligned (64)));
     memcpy( &ctx, &skunk_ctx, sizeof(skunk_ctx) );

     sph_skein512( &ctx.skein, input+64, 16 );
     sph_skein512_close( &ctx.skein, (void*) hash );

     cubehashUpdateDigest( &ctx.cube, (byte*) hash, (const byte*)hash, 64 );

     sph_fugue512( &ctx.fugue, hash, 64 );
     sph_fugue512_close( &ctx.fugue, hash );

     sph_gost512( &ctx.gost, hash, 64 );
     sph_gost512_close( &ctx.gost, hash );

     memcpy(output, hash, 32);
}

int scanhash_skunk( int thr_id, struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done )
{
        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;

	const uint32_t first_nonce = pdata[19];
	uint32_t _ALIGN(64) endiandata[20];
	uint32_t nonce = first_nonce;
	volatile uint8_t *restart = &(work_restart[thr_id].restart);

	if ( opt_benchmark )
		((uint32_t*)ptarget)[7] = 0x0cff;

	for ( int k = 0; k < 19; k++ )
		be32enc( &endiandata[k], pdata[k] );

        // precalc midstate
        sph_skein512_init( &skunk_ctx.skein );
        sph_skein512( &skunk_ctx.skein, endiandata, 64 );

	const uint32_t Htarg = ptarget[7];
	do
        {
	   uint32_t hash[8];
	   be32enc( &endiandata[19], nonce );
	   skunkhash( hash, endiandata );

	   if ( hash[7] <= Htarg && fulltest( hash, ptarget ) )
           {
		pdata[19] = nonce;
		*hashes_done = pdata[19] - first_nonce;
                work_set_target_ratio( work, hash );
		return 1;
	   }
	   nonce++;
	} while ( nonce < max_nonce && !(*restart) );

	pdata[19] = nonce;
	*hashes_done = pdata[19] - first_nonce + 1;
	return 0;
}

bool skunk_thread_init()
{
   sph_skein512_init( &skunk_ctx.skein );
   cubehashInit( &skunk_ctx.cube, 512, 16, 32 );
   sph_fugue512_init( &skunk_ctx.fugue );
   sph_gost512_init( &skunk_ctx.gost );
   return true;
}
