#include "qubit-gate.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "algo/luffa/luffa-hash-2way.h"
#include "algo/cubehash/cube-hash-2way.h"
#include "algo/cubehash/cubehash_sse2.h"
#include "algo/simd/simd-hash-2way.h"
#include "algo/shavite/sph_shavite.h"
#include "algo/echo/aes_ni/hash_api.h"
#if defined(__VAES__)
  #include "algo/shavite/shavite-hash-4way.h"
  #include "algo/echo/echo-hash-4way.h"
#endif

#if defined(QUBIT_4WAY)

typedef struct
{
    luffa_4way_context      luffa;
    cube_4way_context       cube;
    simd_4way_context       simd;
#if defined(__VAES__)
    shavite512_4way_context shavite;
    echo_4way_context       echo;
#else
    sph_shavite512_context  shavite;
    hashState_echo          echo;
#endif
} qubit_4way_ctx_holder;

qubit_4way_ctx_holder qubit_4way_ctx;

void init_qubit_4way_ctx()
{
    cube_4way_init( &qubit_4way_ctx.cube, 512, 16, 32 );
    simd_4way_init( &qubit_4way_ctx.simd, 512 );
#if defined(__VAES__)
    shavite512_4way_init( &qubit_4way_ctx.shavite );
    echo_4way_init( &qubit_4way_ctx.echo, 512 );
#else
    sph_shavite512_init( &qubit_4way_ctx.shavite );
    init_echo( &qubit_4way_ctx.echo, 512 );
#endif
};

void qubit_4way_hash( void *output, const void *input )
{
     uint32_t vhash[16*4] __attribute__ ((aligned (128)));
#if !defined(__VAES__)
     uint32_t hash0[16] __attribute__ ((aligned (64)));
     uint32_t hash1[16] __attribute__ ((aligned (64)));
     uint32_t hash2[16] __attribute__ ((aligned (64)));
     uint32_t hash3[16] __attribute__ ((aligned (64)));
#endif
     qubit_4way_ctx_holder ctx;

     memcpy( &ctx, &qubit_4way_ctx, sizeof(qubit_4way_ctx) );

     luffa_4way_update( &ctx.luffa, input + (64<<2), 16 );
     luffa_4way_close( &ctx.luffa, vhash );
     
     cube_4way_update_close( &ctx.cube, vhash, vhash, 64 );

#if defined(__VAES__)

     shavite512_4way_update_close( &ctx.shavite, vhash, vhash, 64 );

#else

     dintrlv_4x128_512( hash0, hash1, hash2, hash3, vhash );
     
     sph_shavite512( &ctx.shavite, hash0, 64 );
     sph_shavite512_close( &ctx.shavite, hash0 );
     memcpy( &ctx.shavite, &qubit_4way_ctx.shavite,
             sizeof(sph_shavite512_context) );
     sph_shavite512( &ctx.shavite, hash1, 64 );
     sph_shavite512_close( &ctx.shavite, hash1 );
     memcpy( &ctx.shavite, &qubit_4way_ctx.shavite,
             sizeof(sph_shavite512_context) );
     sph_shavite512( &ctx.shavite, hash2, 64 );
     sph_shavite512_close( &ctx.shavite, hash2 );
     memcpy( &ctx.shavite, &qubit_4way_ctx.shavite,
             sizeof(sph_shavite512_context) );
     sph_shavite512( &ctx.shavite, hash3, 64 );
     sph_shavite512_close( &ctx.shavite, hash3 );

     intrlv_4x128_512( vhash, hash0, hash1, hash2, hash3 );

#endif

     simd_4way_update_close( &ctx.simd, vhash, vhash, 512 );

#if defined(__VAES__)

     echo_4way_update_close( &ctx.echo, vhash, vhash, 512 );

     dintrlv_4x128( output, output+32, output+64, output+96, vhash, 256 );
    
#else

     dintrlv_4x128_512( hash0, hash1, hash2, hash3, vhash );

     update_final_echo( &ctx.echo, (BitSequence*)hash0,
                            (const BitSequence*)hash0, 512 );
     memcpy( &ctx.echo, &qubit_4way_ctx.echo, sizeof(hashState_echo) );
     update_final_echo( &ctx.echo, (BitSequence*)hash1,
                             (const BitSequence*)hash1, 512 );
     memcpy( &ctx.echo, &qubit_4way_ctx.echo, sizeof(hashState_echo) );
     update_final_echo( &ctx.echo, (BitSequence*)hash2,
                             (const BitSequence*)hash2, 512 );
     memcpy( &ctx.echo, &qubit_4way_ctx.echo, sizeof(hashState_echo) );
     update_final_echo( &ctx.echo, (BitSequence*)hash3,
                             (const BitSequence*)hash3, 512 );

     memcpy( output,    hash0, 32 );
     memcpy( output+32, hash1, 32 );
     memcpy( output+64, hash2, 32 );
     memcpy( output+96, hash3, 32 );
#endif
}

int scanhash_qubit_4way( struct work *work,uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr )
{
     uint32_t hash[8*4] __attribute__ ((aligned (128)));
     uint32_t vdata[24*4] __attribute__ ((aligned (64)));
     uint32_t *pdata = work->data;
     uint32_t *ptarget = work->target;
     uint32_t n = pdata[19];
     const uint32_t first_nonce = pdata[19];
     uint32_t *noncep = vdata + 64+3;   // 4*16 + 3
     int thr_id = mythr->id;
     const uint32_t Htarg = ptarget[7];

     mm512_bswap32_intrlv80_4x128( vdata, pdata );
     luffa_4way_init( &qubit_4way_ctx.luffa, 512 );
     luffa_4way_update( &qubit_4way_ctx.luffa, vdata, 64 );

     do
     {
        be32enc( noncep,    n   );
        be32enc( noncep+ 4, n+1 );
        be32enc( noncep+ 8, n+2 );
        be32enc( noncep+12, n+3 );

        qubit_4way_hash( hash, vdata );
        pdata[19] = n;

        for ( int lane = 0; lane < 4; lane++ )
        if ( unlikely( ( hash+(lane<<3) )[7] <= Htarg ) )
        if ( likely( fulltest( hash+(lane<<3), ptarget) && !opt_benchmark ) )
        {
           pdata[19] = n + lane;
           submit_solution( work, hash+(lane<<3), mythr );
        }
        n += 4;
     } while ( ( n < max_nonce-4 ) && !work_restart[thr_id].restart );
     *hashes_done = n - first_nonce;
     return 0;
}

#elif defined(QUBIT_2WAY)

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
     dintrlv_2x128( hash0, hash1, vhash, 512 );

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

     intrlv_2x128( vhash, hash0, hash1, 512 );
     simd_2way_update_close( &ctx.simd, vhash, vhash, 512 );
     dintrlv_2x128( hash0, hash1, vhash, 512 );

     update_final_echo( &ctx.echo, (BitSequence *)hash0,
                       (const BitSequence *) hash0, 512 );
     memcpy( &ctx.echo, &qubit_2way_ctx.echo, sizeof(hashState_echo) );
     update_final_echo( &ctx.echo, (BitSequence *)hash1,
                       (const BitSequence *) hash1, 512 );

     memcpy( output,    hash0, 32 );
     memcpy( output+32, hash1, 32 );
}

int scanhash_qubit_2way( struct work *work,uint32_t max_nonce,
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

     casti_m256i( endiandata, 0 ) = mm256_bswap_32( casti_m256i( pdata, 0 ) );
     casti_m256i( endiandata, 1 ) = mm256_bswap_32( casti_m256i( pdata, 1 ) );
     casti_m128i( endiandata, 4 ) = mm128_bswap_32( casti_m128i( pdata, 4 ) );

     uint64_t *edata = (uint64_t*)endiandata;
     intrlv_2x128( (uint64_t*)vdata, edata, edata, 640 );

     luffa_2way_init( &qubit_2way_ctx.luffa, 512 );
     luffa_2way_update( &qubit_2way_ctx.luffa, vdata, 64 );

     do
     {
         be32enc( noncep,   n   );
         be32enc( noncep+4, n+1 );
         qubit_2way_hash( hash, vdata );
         pdata[19] = n;

         if ( unlikely( hash[7] <= Htarg ) )
         if ( likely( fulltest( hash, ptarget) && !opt_benchmark ) )
         {
            pdata[19] = n;
            submit_solution( work, hash, mythr );
         }
         if ( unlikely( ( (hash+8))[7] <= Htarg ) )
         if ( likely( fulltest( hash+8, ptarget) && !opt_benchmark ) )
         {
            pdata[19] = n+1;
            submit_solution( work, hash+8, mythr );
         }
         n += 2;
     } while ( ( n < max_nonce ) && !work_restart[thr_id].restart );
     *hashes_done = n - first_nonce + 1;
     return 0;
}

#endif
