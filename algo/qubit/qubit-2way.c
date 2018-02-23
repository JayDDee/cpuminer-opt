#include "qubit-gate.h"

#if defined(QUBIT_2WAY)

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "algo/luffa/luffa-hash-2way.h"
#include "algo/cubehash/sse2/cubehash_sse2.h" 
#include "algo/simd/simd-hash-2way.h"
#include "algo/shavite/sph_shavite.h"
#include "algo/echo/aes_ni/hash_api.h"

typedef struct
{
        luffa_2way_context      luffa;
        cubehashParam           cube;
        sph_shavite512_context  shavite;
        simd_2way_context       simd;
        hashState_echo          echo;
} qubit_2way_ctx_holder;

qubit_2way_ctx_holder qubit_2way_ctx;

void init_qubit_2way_ctx()
{
        cubehashInit(&qubit_2way_ctx.cube,512,16,32);
        sph_shavite512_init(&qubit_2way_ctx.shavite);
        simd_2way_init( &qubit_2way_ctx.simd, 512 );
        init_echo(&qubit_2way_ctx.echo, 512);
};

void qubit_2way_hash( void *output, const void *input )
{
     uint64_t hash0[8] __attribute__ ((aligned (64)));
     uint64_t hash1[8] __attribute__ ((aligned (64)));
     uint64_t vhash[8*2] __attribute__ ((aligned (64)));
     qubit_2way_ctx_holder ctx;

     memcpy( &ctx, &qubit_2way_ctx, sizeof(qubit_2way_ctx) );
     luffa_2way_update( &ctx.luffa, input + (64<<1), 16 );
     luffa_2way_close( &ctx.luffa, vhash );
     mm256_deinterleave_2x128( hash0, hash1, vhash, 512 );

     cubehashUpdateDigest( &ctx.cube, (byte*)hash0,
                           (const byte*) hash0, 64 );
     memcpy( &ctx.cube, &qubit_2way_ctx.cube, sizeof(cubehashParam) );
     cubehashUpdateDigest( &ctx.cube, (byte*)hash1, (const byte*) hash1, 64 );

     sph_shavite512( &ctx.shavite, hash0, 64 );
     sph_shavite512_close( &ctx.shavite, hash0 );
     memcpy( &ctx.shavite, &qubit_2way_ctx.shavite,
             sizeof(sph_shavite512_context) );
     sph_shavite512( &ctx.shavite, hash1, 64 );
     sph_shavite512_close( &ctx.shavite, hash1 );

     mm256_interleave_2x128( vhash, hash0, hash1, 512 );
     simd_2way_update_close( &ctx.simd, vhash, vhash, 512 );
     mm256_deinterleave_2x128( hash0, hash1, vhash, 512 );

     update_final_echo( &ctx.echo, (BitSequence *)hash0,
                       (const BitSequence *) hash0, 512 );
     memcpy( &ctx.echo, &qubit_2way_ctx.echo, sizeof(hashState_echo) );
     update_final_echo( &ctx.echo, (BitSequence *)hash1,
                       (const BitSequence *) hash1, 512 );

     memcpy( output,    hash0, 32 );
     memcpy( output+32, hash1, 32 );
}

int scanhash_qubit_2way( int thr_id, struct work *work,uint32_t max_nonce,
                         uint64_t *hashes_done )
{
     uint32_t hash[4*8] __attribute__ ((aligned (64)));
     uint32_t vdata[24*4] __attribute__ ((aligned (64)));
     uint32_t endiandata[20] __attribute__((aligned(64)));
     uint32_t *pdata = work->data;
     uint32_t *ptarget = work->target;
     uint32_t n = pdata[19];
     const uint32_t first_nonce = pdata[19];
     uint32_t *nonces = work->nonces;
     int num_found = 0;
     uint32_t *noncep = vdata + 32+3;   // 4*8 + 3
     const uint32_t Htarg = ptarget[7];
     uint64_t htmax[] = {          0,        0xF,       0xFF,
                               0xFFF,     0xFFFF, 0x10000000  };
     uint32_t masks[] = { 0xFFFFFFFF, 0xFFFFFFF0, 0xFFFFFF00,
                          0xFFFFF000, 0xFFFF0000,          0  };

     // big endian encode 0..18 uint32_t, 64 bits at a time
     swab32_array( endiandata, pdata, 20 );

     uint64_t *edata = (uint64_t*)endiandata;
     mm256_interleave_2x128( (uint64_t*)vdata, edata, edata, 640 );

     luffa_2way_init( &qubit_2way_ctx.luffa, 512 );
     luffa_2way_update( &qubit_2way_ctx.luffa, vdata, 64 );

     for ( int m=0; m < 6; m++ ) if ( Htarg <= htmax[m] )
     {
        uint32_t mask = masks[m];
        do
        {
            be32enc( noncep,   n   );
            be32enc( noncep+4, n+1 );
            qubit_2way_hash( hash, vdata );
            pdata[19] = n;


            if ( !( hash[7] & mask ) && fulltest( hash, ptarget) )
            {
               nonces[ num_found++ ] = n;
               work_set_target_ratio( work, hash );
            }
            if ( !( (hash+8)[7] & mask ) && fulltest( hash+8, ptarget) )
            {
               pdata[19] = n+1;
               nonces[ num_found++ ] = n+1;
               work_set_target_ratio( work, hash+8 );
            }
            n += 2;
         } while ( ( num_found == 0 ) && ( n < max_nonce )
                   && !work_restart[thr_id].restart );
         break;
     }
     *hashes_done = n - first_nonce + 1;
     return num_found;
}

#endif
