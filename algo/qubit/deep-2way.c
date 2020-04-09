#include "deep-gate.h"

#if defined(DEEP_2WAY)

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "algo/luffa/luffa-hash-2way.h"
#include "algo/cubehash/cubehash_sse2.h" 
#include "algo/shavite/sph_shavite.h"
#include "algo/echo/aes_ni/hash_api.h"

typedef struct
{
        luffa_2way_context      luffa;
        cubehashParam           cube;
        sph_shavite512_context  shavite;
        hashState_echo          echo;
} deep_2way_ctx_holder;

deep_2way_ctx_holder deep_2way_ctx;

void init_deep_2way_ctx()
{
        luffa_2way_init( &deep_2way_ctx.luffa, 512 );
        cubehashInit(&deep_2way_ctx.cube,512,16,32);
        sph_shavite512_init(&deep_2way_ctx.shavite);
        init_echo(&deep_2way_ctx.echo, 512);
};

void deep_2way_hash( void *output, const void *input )
{
     uint64_t hash0[8] __attribute__ ((aligned (64)));
     uint64_t hash1[8] __attribute__ ((aligned (64)));
     uint64_t vhash[8*2] __attribute__ ((aligned (64)));
     deep_2way_ctx_holder ctx;

     memcpy( &ctx, &deep_2way_ctx, sizeof(deep_2way_ctx) );
     luffa_2way_update( &ctx.luffa, input + (64<<1), 16 );
     luffa_2way_close( &ctx.luffa, vhash );
     dintrlv_2x128( hash0, hash1, vhash, 512 );

     cubehashUpdateDigest( &ctx.cube, (byte*)hash0,
                           (const byte*) hash0, 64 );
     memcpy( &ctx.cube, &deep_2way_ctx.cube, sizeof(cubehashParam) );
     cubehashUpdateDigest( &ctx.cube, (byte*)hash1, (const byte*) hash1, 64 );

     sph_shavite512( &ctx.shavite, hash0, 64 );
     sph_shavite512_close( &ctx.shavite, hash0 );
     memcpy( &ctx.shavite, &deep_2way_ctx.shavite,
             sizeof(sph_shavite512_context) );
     sph_shavite512( &ctx.shavite, hash1, 64 );
     sph_shavite512_close( &ctx.shavite, hash1 );

     update_final_echo( &ctx.echo, (BitSequence *)hash0,
                       (const BitSequence *) hash0, 512 );
     memcpy( &ctx.echo, &deep_2way_ctx.echo, sizeof(hashState_echo) );
     update_final_echo( &ctx.echo, (BitSequence *)hash1,
                       (const BitSequence *) hash1, 512 );

     memcpy( output,    hash0, 32 );
     memcpy( output+32, hash1, 32 );
}

int scanhash_deep_2way( struct work *work,uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr )
{
     uint32_t hash[4*8] __attribute__ ((aligned (64)));
     uint32_t vdata[24*4] __attribute__ ((aligned (64)));
     uint32_t endiandata[20] __attribute__((aligned(64)));
     uint32_t *pdata = work->data;
     uint32_t *ptarget = work->target;
     uint32_t n = pdata[19];
     const uint32_t first_nonce = pdata[19];
     uint32_t *noncep = vdata + 32+3;   // 4*8 + 3
     int thr_id = mythr->id;  // thr_id arg is deprecated
     const uint32_t Htarg = ptarget[7];
     uint64_t htmax[] = {          0,        0xF,       0xFF,
                               0xFFF,     0xFFFF, 0x10000000  };
     uint32_t masks[] = { 0xFFFFFFFF, 0xFFFFFFF0, 0xFFFFFF00,
                          0xFFFFF000, 0xFFFF0000,          0  };

     casti_m256i( endiandata, 0 ) = mm256_bswap_32( casti_m256i( pdata, 0 ) );
     casti_m256i( endiandata, 1 ) = mm256_bswap_32( casti_m256i( pdata, 1 ) );
     casti_m128i( endiandata, 4 ) = mm128_bswap_32( casti_m128i( pdata, 4 ) );

     uint64_t *edata = (uint64_t*)endiandata;
     intrlv_2x128( (uint64_t*)vdata, edata, edata, 640 );

     luffa_2way_init( &deep_2way_ctx.luffa, 512 );
     luffa_2way_update( &deep_2way_ctx.luffa, vdata, 64 );

     for ( int m=0; m < 6; m++ ) if ( Htarg <= htmax[m] )
     {
        uint32_t mask = masks[m];
        do
        {
            be32enc( noncep,   n   );
            be32enc( noncep+4, n+1 );

            deep_2way_hash( hash, vdata );
            pdata[19] = n;

            if ( !( hash[7] & mask ) )
            if ( fulltest( hash, ptarget) && !opt_benchmark )
            {
                pdata[19] = n;
                submit_solution( work, hash, mythr );
            }
            if ( !( (hash+8)[7] & mask ) )
            if ( fulltest( hash+8, ptarget) && !opt_benchmark )
            {
               pdata[19] = n+1;
               submit_solution( work, hash+8, mythr );
            }
            n += 2;
         } while ( ( n < max_nonce ) && !work_restart[thr_id].restart );
         break;
     }
     *hashes_done = n - first_nonce + 1;
     return 0;
}

#endif
