#include "veltor-gate.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#if defined(__AVX2__) && defined(__AES__)

#include "algo/skein/skein-hash-4way.h"
#include "algo/shavite/sph_shavite.h"
#include "algo/shabal/shabal-hash-4way.h"
#include "algo/gost/sph_gost.h"

typedef struct {
    skein512_4way_context   skein;
    sph_shavite512_context  shavite;
    shabal512_4way_context  shabal;
    sph_gost512_context     gost;
} veltor_4way_ctx_holder;

veltor_4way_ctx_holder veltor_4way_ctx __attribute__ ((aligned (64)));

void init_veltor_4way_ctx()
{
     skein512_4way_init( &veltor_4way_ctx.skein );
     sph_shavite512_init( &veltor_4way_ctx.shavite );
     shabal512_4way_init( &veltor_4way_ctx.shabal );
     sph_gost512_init( &veltor_4way_ctx.gost );
}

void veltor_4way_hash( void *output, const void *input )
{
     uint64_t hash0[8] __attribute__ ((aligned (64)));
     uint64_t hash1[8] __attribute__ ((aligned (64)));
     uint64_t hash2[8] __attribute__ ((aligned (64)));
     uint64_t hash3[8] __attribute__ ((aligned (64)));
     uint64_t vhash[8*4] __attribute__ ((aligned (64)));
     veltor_4way_ctx_holder ctx __attribute__ ((aligned (64)));
     memcpy( &ctx, &veltor_4way_ctx, sizeof(veltor_4way_ctx) );

     skein512_4way( &ctx.skein, input, 80 );
     skein512_4way_close( &ctx.skein, vhash );
     mm256_deinterleave_4x64( hash0, hash1, hash2, hash3, vhash, 512 );

     sph_shavite512( &ctx.shavite, hash0, 64 );
     sph_shavite512_close( &ctx.shavite, hash0 );
     sph_shavite512_init( &ctx.shavite );
     sph_shavite512( &ctx.shavite, hash1, 64 );
     sph_shavite512_close( &ctx.shavite, hash1 );
     sph_shavite512_init( &ctx.shavite );
     sph_shavite512( &ctx.shavite, hash2, 64 );
     sph_shavite512_close( &ctx.shavite, hash2 );
     sph_shavite512_init( &ctx.shavite );
     sph_shavite512( &ctx.shavite, hash3, 64 );
     sph_shavite512_close( &ctx.shavite, hash3 );

     mm_interleave_4x32( vhash, hash0, hash1, hash2, hash3, 512 );
     shabal512_4way( &ctx.shabal, vhash, 64 );
     shabal512_4way_close( &ctx.shabal, vhash );
     mm_deinterleave_4x32( hash0, hash1, hash2, hash3, vhash, 512 );

     sph_gost512( &ctx.gost, hash0, 64 );
     sph_gost512_close( &ctx.gost, hash0 );
     sph_gost512_init( &ctx.gost );
     sph_gost512( &ctx.gost, hash1, 64 );
     sph_gost512_close( &ctx.gost, hash1 );
     sph_gost512_init( &ctx.gost );
     sph_gost512( &ctx.gost, hash2, 64 );
     sph_gost512_close( &ctx.gost, hash2 );
     sph_gost512_init( &ctx.gost );
     sph_gost512( &ctx.gost, hash3, 64 );
     sph_gost512_close( &ctx.gost, hash3 );

     memcpy( output,    hash0, 32 );
     memcpy( output+32, hash1, 32 );
     memcpy( output+64, hash2, 32 );
     memcpy( output+96, hash3, 32 );
}

int scanhash_veltor_4way( int thr_id, struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done )
{
     uint32_t hash[4*8] __attribute__ ((aligned (64)));
     uint32_t vdata[24*4] __attribute__ ((aligned (64)));
     uint32_t endiandata[20] __attribute__((aligned(64)));
     uint32_t *pdata = work->data;
     uint32_t *ptarget = work->target;
     const uint32_t Htarg = ptarget[7];
     const uint32_t first_nonce = pdata[19];
     uint32_t n = first_nonce;
     uint32_t *nonces = work->nonces;
     int num_found = 0;
     uint32_t *noncep = vdata + 73;   // 9*8 + 1
     volatile uint8_t *restart = &(work_restart[thr_id].restart);

     if ( opt_benchmark )
        ptarget[7] = 0x0cff;
     for ( int i=0; i < 19; i++ )
     {
        be32enc( &endiandata[i], pdata[i] );
     }

     uint64_t *edata = (uint64_t*)endiandata;
     mm256_interleave_4x64( (uint64_t*)vdata, edata, edata, edata, edata, 640 );
     do
     {
         be32enc( noncep,   n   );
         be32enc( noncep+2, n+1 );
         be32enc( noncep+4, n+2 );
         be32enc( noncep+6, n+3 );

         veltor_4way_hash( hash, vdata );
         pdata[19] = n;

         for ( int i = 0; i < 4; i++ )
         if ( (hash+(i<<3))[7] <= Htarg && fulltest( hash+(i<<3), ptarget ) )
         {
            pdata[19] = n+i;
            nonces[ num_found++ ] = n+i;
            work_set_target_ratio( work, hash+(i<<3) );
         }
         n += 4;
     } while ( ( num_found == 0 ) && ( n < max_nonce ) && !(*restart) );
     *hashes_done = n - first_nonce + 1;
     return num_found;
}

#endif
