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

     skein512_4way_update( &ctx.skein, input, 80 );
     skein512_4way_close( &ctx.skein, vhash );
     dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 512 );

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

     intrlv_4x32( vhash, hash0, hash1, hash2, hash3, 512 );
     shabal512_4way_update( &ctx.shabal, vhash, 64 );
     shabal512_4way_close( &ctx.shabal, vhash );
     dintrlv_4x32( hash0, hash1, hash2, hash3, vhash, 512 );

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

int scanhash_veltor_4way( struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done, struct thr_info *mythr )
{
     uint32_t hash[4*8] __attribute__ ((aligned (64)));
     uint32_t vdata[24*4] __attribute__ ((aligned (64)));
     uint32_t *pdata = work->data;
     uint32_t *ptarget = work->target;
     const uint32_t Htarg = ptarget[7];
     const uint32_t first_nonce = pdata[19];
     uint32_t n = first_nonce;
     __m256i  *noncev = (__m256i*)vdata + 9;   // aligned
     int thr_id = mythr->id;  // thr_id arg is deprecated
     volatile uint8_t *restart = &(work_restart[thr_id].restart);

     if ( opt_benchmark )
        ptarget[7] = 0x0cff;

     mm256_bswap32_intrlv80_4x64( vdata, pdata );

     do
     {
         *noncev = mm256_intrlv_blend_32( mm256_bswap_32(
                 _mm256_set_epi32( n+3, 0, n+2, 0, n+1, 0, n, 0 ) ), *noncev );

         veltor_4way_hash( hash, vdata );
         pdata[19] = n;

         for ( int i = 0; i < 4; i++ )
         if ( (hash+(i<<3))[7] <= Htarg && fulltest( hash+(i<<3), ptarget ) )
         {
            pdata[19] = n+i;
            submit_solution( work, hash+(i<<3), mythr );
         }
         n += 4;
     } while ( ( n < max_nonce ) && !(*restart) );
     *hashes_done = n - first_nonce + 1;
     return 0;
}

#endif
