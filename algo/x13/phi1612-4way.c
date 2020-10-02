#include "phi1612-gate.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "algo/skein/skein-hash-4way.h"
#include "algo/jh/jh-hash-4way.h"
#include "algo/cubehash/cubehash_sse2.h"
#include "algo/cubehash/cube-hash-2way.h"
#include "algo/fugue/fugue-aesni.h"
#include "algo/gost/sph_gost.h"
#include "algo/echo/aes_ni/hash_api.h"
#if defined(__VAES__)
  #include "algo/echo/echo-hash-4way.h"
#endif

#if defined(PHI1612_8WAY)

typedef struct {
    skein512_8way_context   skein;
    jh512_8way_context      jh;
    cube_4way_context       cube;
    hashState_fugue         fugue;
    sph_gost512_context     gost;
#if defined(__VAES__)
    echo_4way_context       echo;
#else
    hashState_echo          echo;
#endif
} phi1612_8way_ctx_holder;

phi1612_8way_ctx_holder phi1612_8way_ctx __attribute__ ((aligned (64)));

void init_phi1612_8way_ctx()
{
     skein512_8way_init( &phi1612_8way_ctx.skein );
     jh512_8way_init( &phi1612_8way_ctx.jh );
     cube_4way_init( &phi1612_8way_ctx.cube, 512, 16, 32 );
     fugue512_Init( &phi1612_8way_ctx.fugue, 512 );
     sph_gost512_init( &phi1612_8way_ctx.gost );
#if defined(__VAES__)
     echo_4way_init( &phi1612_8way_ctx.echo, 512 );
#else
     init_echo( &phi1612_8way_ctx.echo, 512 );
#endif
};

void phi1612_8way_hash( void *state, const void *input )
{
     uint64_t vhash[8*8] __attribute__ ((aligned (128)));
     uint64_t hash0[8] __attribute__ ((aligned (64)));
     uint64_t hash1[8] __attribute__ ((aligned (64)));
     uint64_t hash2[8] __attribute__ ((aligned (64)));
     uint64_t hash3[8] __attribute__ ((aligned (64)));
     uint64_t hash4[8] __attribute__ ((aligned (64)));
     uint64_t hash5[8] __attribute__ ((aligned (64)));
     uint64_t hash6[8] __attribute__ ((aligned (64)));
     uint64_t hash7[8] __attribute__ ((aligned (64)));
     phi1612_8way_ctx_holder ctx;
     memcpy( &ctx, &phi1612_8way_ctx, sizeof(phi1612_8way_ctx) );

     // Skein parallel 4way
     skein512_8way_update( &ctx.skein, input, 80 );
     skein512_8way_close( &ctx.skein, vhash );

     // JH
     jh512_8way_update( &ctx.jh, vhash, 64 );
     jh512_8way_close( &ctx.jh, vhash );
     dintrlv_8x64_512( hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
                   vhash );

     // Cubehash
     intrlv_4x128_512( vhash, hash0, hash1, hash2, hash3 );
     cube_4way_update_close( &ctx.cube, vhash, vhash, 64 );
     dintrlv_4x128_512( hash0, hash1, hash2, hash3, vhash );
     intrlv_4x128_512( vhash, hash4, hash5, hash6, hash7 );
     cube_4way_init( &ctx.cube, 512, 16, 32 );
     cube_4way_update_close( &ctx.cube, vhash, vhash, 64 );
     dintrlv_4x128_512( hash4, hash5, hash6, hash7, vhash );

     // Fugue
     fugue512_full( &ctx.fugue, hash0, hash0, 64 );
     fugue512_full( &ctx.fugue, hash1, hash1, 64 );
     fugue512_full( &ctx.fugue, hash2, hash2, 64 );
     fugue512_full( &ctx.fugue, hash3, hash3, 64 );
     fugue512_full( &ctx.fugue, hash4, hash4, 64 );
     fugue512_full( &ctx.fugue, hash5, hash5, 64 );
     fugue512_full( &ctx.fugue, hash6, hash6, 64 );
     fugue512_full( &ctx.fugue, hash7, hash7, 64 );

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
     sph_gost512_init( &ctx.gost );
     sph_gost512( &ctx.gost, hash4, 64 );
     sph_gost512_close( &ctx.gost, hash4 );
     sph_gost512_init( &ctx.gost );
     sph_gost512( &ctx.gost, hash5, 64 );
     sph_gost512_close( &ctx.gost, hash5 );
     sph_gost512_init( &ctx.gost );
     sph_gost512( &ctx.gost, hash6, 64 );
     sph_gost512_close( &ctx.gost, hash6 );
     sph_gost512_init( &ctx.gost );
     sph_gost512( &ctx.gost, hash7, 64 );
     sph_gost512_close( &ctx.gost, hash7 );

     // Echo

#if defined(__VAES__)

     intrlv_4x128_512( vhash, hash0, hash1, hash2, hash3 );
     echo_4way_update_close( &ctx.echo, vhash, vhash, 512 );
     dintrlv_4x128_512( hash0, hash1, hash2, hash3, vhash );
     intrlv_4x128_512( vhash, hash4, hash5, hash6, hash7 );
     echo_4way_init( &ctx.echo, 512 );
     echo_4way_update_close( &ctx.echo, vhash, vhash, 512 );
     dintrlv_4x128_512( hash4, hash5, hash6, hash7, vhash );

#else

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
     init_echo( &ctx.echo, 512 );
     update_final_echo( &ctx.echo, (BitSequence *)hash4,
                       (const BitSequence *) hash4, 512 );
     init_echo( &ctx.echo, 512 );
     update_final_echo( &ctx.echo, (BitSequence *)hash5,
                       (const BitSequence *) hash5, 512 );
     init_echo( &ctx.echo, 512 );
     update_final_echo( &ctx.echo, (BitSequence *)hash6,
                       (const BitSequence *) hash6, 512 );
     init_echo( &ctx.echo, 512 );
     update_final_echo( &ctx.echo, (BitSequence *)hash7,
                       (const BitSequence *) hash7, 512 );

#endif

     memcpy( state,     hash0, 32 );
     memcpy( state+ 32, hash1, 32 );
     memcpy( state+ 64, hash2, 32 );
     memcpy( state+ 96, hash3, 32 );
     memcpy( state+128, hash4, 32 );
     memcpy( state+160, hash5, 32 );
     memcpy( state+192, hash6, 32 );
     memcpy( state+224, hash7, 32 );
}

int scanhash_phi1612_8way( struct work *work, uint32_t max_nonce,
                  uint64_t *hashes_done, struct thr_info *mythr )
{
     uint32_t hash[8*8] __attribute__ ((aligned (128)));
     uint32_t vdata[24*8] __attribute__ ((aligned (64)));
     uint32_t *pdata = work->data;
     uint32_t *ptarget = work->target;
     const uint32_t first_nonce = pdata[19];
     uint32_t n = first_nonce;
     __m512i  *noncev = (__m512i*)vdata + 9;   // aligned
     int thr_id = mythr->id;  
     const uint32_t Htarg = ptarget[7];

     if ( opt_benchmark )
          ( (uint32_t*)ptarget )[7] = 0x0cff;
     mm512_bswap32_intrlv80_8x64( vdata, pdata );

     do {
           *noncev = mm512_intrlv_blend_32( mm512_bswap_32(
               _mm512_set_epi32( n+7, 0, n+6, 0, n+5, 0, n+4, 0,
                                 n+3, 0, n+2, 0, n+1, 0, n,   0 ) ), *noncev );

        phi1612_8way_hash( hash, vdata );
        pdata[19] = n;

        for ( int i = 0; i < 8; i++ )
        if ( (hash+(i<<3))[7] <= Htarg )
        if ( fulltest( hash+(i<<3), ptarget ) && !opt_benchmark )
        {
           pdata[19] = n+i;
           submit_solution( work, hash+(i<<3), mythr );
        }
        n += 8;
     } while ( ( n < max_nonce-8 ) && !work_restart[thr_id].restart );
     *hashes_done = n - first_nonce;
     return 0;
}

#elif defined(PHI1612_4WAY)


typedef struct {
    skein512_4way_context   skein;
    jh512_4way_context      jh;
    cubehashParam           cube;
    hashState_fugue         fugue;
    sph_gost512_context     gost;
    hashState_echo          echo;
} phi1612_4way_ctx_holder;

phi1612_4way_ctx_holder phi1612_4way_ctx __attribute__ ((aligned (64)));

void init_phi1612_4way_ctx()
{
     skein512_4way_init( &phi1612_4way_ctx.skein );
     jh512_4way_init( &phi1612_4way_ctx.jh );
     cubehashInit( &phi1612_4way_ctx.cube, 512, 16, 32 );
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

// skein 4way is broken for 80 bytes
//     skein512_4way_update( &ctx.skein, input, 80 );
//     skein512_4way_close( &ctx.skein, vhash );
     skein512_4way_prehash64( &ctx.skein, input );
     skein512_4way_final16( &ctx.skein, vhash, input + (64*4) );

     // JH
     jh512_4way_update( &ctx.jh, vhash, 64 );
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
     fugue512_full( &ctx.fugue, hash0, hash0, 64 );
     fugue512_full( &ctx.fugue, hash1, hash1, 64 );
     fugue512_full( &ctx.fugue, hash2, hash2, 64 );
     fugue512_full( &ctx.fugue, hash3, hash3, 64 );

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
           submit_solution( work, hash+(i<<3), mythr );
        }
        n += 4;
     } while ( ( n < max_nonce ) && !work_restart[thr_id].restart );
     *hashes_done = n - first_nonce + 1;
     return 0;
}

#endif
