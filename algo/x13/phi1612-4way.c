#include "phi1612-gate.h"

#if defined(PHI1612_4WAY)

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "algo/skein/skein-hash-4way.h"
#include "algo/jh/jh-hash-4way.h"
#include "algo/cubehash/cubehash_sse2.h"
#include "algo/fugue/sph_fugue.h"
#include "algo/gost/sph_gost.h"
#include "algo/echo/aes_ni/hash_api.h"

typedef struct {
    skein512_4way_context   skein;
    jh512_4way_context      jh;
    cubehashParam           cube;
    sph_fugue512_context    fugue;
    sph_gost512_context     gost;
    hashState_echo          echo;
} phi1612_4way_ctx_holder;

phi1612_4way_ctx_holder phi1612_4way_ctx __attribute__ ((aligned (64)));

void init_phi1612_4way_ctx()
{
     skein512_4way_init( &phi1612_4way_ctx.skein );
     jh512_4way_init( &phi1612_4way_ctx.jh );
     cubehashInit( &phi1612_4way_ctx.cube, 512, 16, 32 );
     sph_fugue512_init( &phi1612_4way_ctx.fugue );
     sph_gost512_init( &phi1612_4way_ctx.gost );
     init_echo( &phi1612_4way_ctx.echo, 512 );
};

void phi1612_4way_hash( void *state, const void *input )
{
     uint64_t hash0[8] __attribute__ ((aligned (64)));
     uint64_t hash1[8] __attribute__ ((aligned (64)));
     uint64_t hash2[8] __attribute__ ((aligned (64)));
     uint64_t hash3[8] __attribute__ ((aligned (64)));
     uint64_t vhash[8*4] __attribute__ ((aligned (64)));
     phi1612_4way_ctx_holder ctx;
     memcpy( &ctx, &phi1612_4way_ctx, sizeof(phi1612_4way_ctx) );

     // Skein parallel 4way
     skein512_4way( &ctx.skein, input, 80 );
     skein512_4way_close( &ctx.skein, vhash );

     // JH
     jh512_4way( &ctx.jh, vhash, 64 );
     jh512_4way_close( &ctx.jh, vhash );

     // Serial to the end
     dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 512 );

     // Cubehash
     cubehashUpdateDigest( &ctx.cube, (byte*)hash0, (const byte*) hash0, 64 );
     memcpy( &ctx.cube, &phi1612_4way_ctx.cube, sizeof(cubehashParam) );
     cubehashUpdateDigest( &ctx.cube, (byte*)hash1, (const byte*) hash1, 64 );
     memcpy( &ctx.cube, &phi1612_4way_ctx.cube, sizeof(cubehashParam) );
     cubehashUpdateDigest( &ctx.cube, (byte*)hash2, (const byte*) hash2, 64 );
     memcpy( &ctx.cube, &phi1612_4way_ctx.cube, sizeof(cubehashParam) );
     cubehashUpdateDigest( &ctx.cube, (byte*)hash3, (const byte*) hash3, 64 );

     // Fugue
     sph_fugue512( &ctx.fugue, hash0, 64 );
     sph_fugue512_close( &ctx.fugue, hash0 );
     sph_fugue512_init( &ctx.fugue );
     sph_fugue512( &ctx.fugue, hash1, 64 );
     sph_fugue512_close( &ctx.fugue, hash1 );
     sph_fugue512_init( &ctx.fugue );
     sph_fugue512( &ctx.fugue, hash2, 64 );
     sph_fugue512_close( &ctx.fugue, hash2 );
     sph_fugue512_init( &ctx.fugue );
     sph_fugue512( &ctx.fugue, hash3, 64 );
     sph_fugue512_close( &ctx.fugue, hash3 );

     // Gost
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

     // Echo
     update_final_echo( &ctx.echo, (BitSequence *)hash0,
                       (const BitSequence *) hash0, 512 );
     init_echo( &ctx.echo, 512 );
     update_final_echo( &ctx.echo, (BitSequence *)hash1,
                       (const BitSequence *) hash1, 512 );
     init_echo( &ctx.echo, 512 );
     update_final_echo( &ctx.echo, (BitSequence *)hash2,
                       (const BitSequence *) hash2, 512 );
     init_echo( &ctx.echo, 512 );
     update_final_echo( &ctx.echo, (BitSequence *)hash3,
                       (const BitSequence *) hash3, 512 );

     memcpy( state,    hash0, 32 );
     memcpy( state+32, hash1, 32 );
     memcpy( state+64, hash2, 32 );
     memcpy( state+96, hash3, 32 );
}

int scanhash_phi1612_4way( struct work *work, uint32_t max_nonce,
                  uint64_t *hashes_done, struct thr_info *mythr )
{
     uint32_t hash[4*8] __attribute__ ((aligned (64)));
     uint32_t vdata[24*4] __attribute__ ((aligned (64)));
     uint32_t *pdata = work->data;
     uint32_t *ptarget = work->target;
     const uint32_t first_nonce = pdata[19];
     uint32_t n = first_nonce;
     __m256i  *noncev = (__m256i*)vdata + 9;   // aligned
     int thr_id = mythr->id;  // thr_id arg is deprecated
     const uint32_t Htarg = ptarget[7];

     if ( opt_benchmark )
          ( (uint32_t*)ptarget )[7] = 0x0cff;
     mm256_bswap32_intrlv80_4x64( vdata, pdata );

     do {
           *noncev = mm256_intrlv_blend_32( mm256_bswap_32(
                 _mm256_set_epi32( n+3, 0, n+2, 0, n+1, 0, n, 0 ) ), *noncev );

        phi1612_4way_hash( hash, vdata );
        pdata[19] = n;

        for ( int i = 0; i < 4; i++ )
        if ( (hash+(i<<3))[7] <= Htarg )
        if ( fulltest( hash+(i<<3), ptarget ) && !opt_benchmark )
        {
           pdata[19] = n+i;
           submit_lane_solution( work, hash+(i<<3), mythr, i );
        }
        n += 4;
     } while ( ( n < max_nonce ) && !work_restart[thr_id].restart );
     *hashes_done = n - first_nonce + 1;
     return 0;
}

#endif
