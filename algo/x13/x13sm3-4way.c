#include "x13sm3-gate.h"

#if defined(X13SM3_4WAY)

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "algo/blake/blake-hash-4way.h"
#include "algo/bmw/bmw-hash-4way.h"
#include "algo/groestl/aes_ni/hash-groestl.h"
#include "algo/skein/skein-hash-4way.h"
#include "algo/jh/jh-hash-4way.h"
#include "algo/keccak/keccak-hash-4way.h"
#include "algo/luffa/luffa-hash-2way.h"
#include "algo/cubehash/cubehash_sse2.h"
#include "algo/shavite/sph_shavite.h"
#include "algo/simd/simd-hash-2way.h"
#include "algo/echo/aes_ni/hash_api.h"
#include "algo/sm3/sm3-hash-4way.h"
#include "algo/hamsi/hamsi-hash-4way.h"
#include "algo/fugue/sph_fugue.h"

typedef struct {
    blake512_4way_context   blake;
    bmw512_4way_context     bmw;
    hashState_groestl       groestl;
    skein512_4way_context   skein;
    jh512_4way_context      jh;
    keccak512_4way_context  keccak;
    luffa_2way_context      luffa;
    cubehashParam           cube;
    sph_shavite512_context  shavite;
    simd_2way_context       simd;
    hashState_echo          echo;
    sm3_4way_ctx_t          sm3;
    hamsi512_4way_context   hamsi;
    sph_fugue512_context    fugue;
} x13sm3_4way_ctx_holder;

x13sm3_4way_ctx_holder x13sm3_4way_ctx __attribute__ ((aligned (64)));
static __thread blake512_4way_context x13sm3_ctx_mid;

void init_x13sm3_4way_ctx()
{
     blake512_4way_init( &x13sm3_4way_ctx.blake );
     bmw512_4way_init( &x13sm3_4way_ctx.bmw );
     init_groestl( &x13sm3_4way_ctx.groestl, 64 );
     skein512_4way_init( &x13sm3_4way_ctx.skein );
     jh512_4way_init( &x13sm3_4way_ctx.jh );
     keccak512_4way_init( &x13sm3_4way_ctx.keccak );
     luffa_2way_init( &x13sm3_4way_ctx.luffa, 512 );
     cubehashInit( &x13sm3_4way_ctx.cube, 512, 16, 32 );
     sph_shavite512_init( &x13sm3_4way_ctx.shavite );
     simd_2way_init( &x13sm3_4way_ctx.simd, 512 );
     init_echo( &x13sm3_4way_ctx.echo, 512 );
     sm3_4way_init( &x13sm3_4way_ctx.sm3 );
     hamsi512_4way_init( &x13sm3_4way_ctx.hamsi );
     sph_fugue512_init( &x13sm3_4way_ctx.fugue );
};

void x13sm3_4way_hash( void *state, const void *input )
{
     uint64_t hash0[8] __attribute__ ((aligned (64)));
     uint64_t hash1[8] __attribute__ ((aligned (64)));
     uint64_t hash2[8] __attribute__ ((aligned (64)));
     uint64_t hash3[8] __attribute__ ((aligned (64)));
     uint64_t vhash[8*4] __attribute__ ((aligned (64)));
     x13sm3_4way_ctx_holder ctx;
     memcpy( &ctx, &x13sm3_4way_ctx, sizeof(x13sm3_4way_ctx) );

     // Blake
     memcpy( &ctx.blake, &x13sm3_ctx_mid, sizeof(x13sm3_ctx_mid) );
     blake512_4way_update( &ctx.blake, input + (64<<2), 16 );
     blake512_4way_close( &ctx.blake, vhash );

     // Bmw
     bmw512_4way_update( &ctx.bmw, vhash, 64 );
     bmw512_4way_close( &ctx.bmw, vhash );

     // Serial
     dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 512 );

     // Groestl
     update_and_final_groestl( &ctx.groestl, (char*)hash0, (char*)hash0, 512 );
     reinit_groestl( &ctx.groestl );
     update_and_final_groestl( &ctx.groestl, (char*)hash1, (char*)hash1, 512 );
     reinit_groestl( &ctx.groestl );
     update_and_final_groestl( &ctx.groestl, (char*)hash2, (char*)hash2, 512 );
     reinit_groestl( &ctx.groestl );
     update_and_final_groestl( &ctx.groestl, (char*)hash3, (char*)hash3, 512 );

     // Parallel 4way
     intrlv_4x64( vhash, hash0, hash1, hash2, hash3, 512 );

     // Skein
     skein512_4way_update( &ctx.skein, vhash, 64 );
     skein512_4way_close( &ctx.skein, vhash );

     // JH
     jh512_4way_update( &ctx.jh, vhash, 64 );
     jh512_4way_close( &ctx.jh, vhash );

     // Keccak
     keccak512_4way_update( &ctx.keccak, vhash, 64 );
     keccak512_4way_close( &ctx.keccak, vhash );

     // Serial to the end
     dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 512 );

     // Luffa
     intrlv_2x128( vhash, hash0, hash1, 512 );
     luffa_2way_update_close( &ctx.luffa, vhash, vhash, 64 );
     dintrlv_2x128( hash0, hash1, vhash, 512 );
     intrlv_2x128( vhash, hash2, hash3, 512 );
     luffa_2way_init( &ctx.luffa, 512 );
     luffa_2way_update_close( &ctx.luffa, vhash, vhash, 64 );
     dintrlv_2x128( hash2, hash3, vhash, 512 );

     // Cubehash
     cubehashUpdateDigest( &ctx.cube, (byte*)hash0, (const byte*) hash0, 64 );
     memcpy( &ctx.cube, &x13sm3_4way_ctx.cube, sizeof(cubehashParam) );
     cubehashUpdateDigest( &ctx.cube, (byte*)hash1, (const byte*) hash1, 64 );
     memcpy( &ctx.cube, &x13sm3_4way_ctx.cube, sizeof(cubehashParam) );
     cubehashUpdateDigest( &ctx.cube, (byte*)hash2, (const byte*) hash2, 64 );
     memcpy( &ctx.cube, &x13sm3_4way_ctx.cube, sizeof(cubehashParam) );
     cubehashUpdateDigest( &ctx.cube, (byte*)hash3, (const byte*) hash3, 64 );

     // Shavite
     sph_shavite512( &ctx.shavite, hash0, 64 );
     sph_shavite512_close( &ctx.shavite, hash0 );
     memcpy( &ctx.shavite, &x13sm3_4way_ctx.shavite,
             sizeof(sph_shavite512_context) );
     sph_shavite512( &ctx.shavite, hash1, 64 );
     sph_shavite512_close( &ctx.shavite, hash1 );
     memcpy( &ctx.shavite, &x13sm3_4way_ctx.shavite,
             sizeof(sph_shavite512_context) );
     sph_shavite512( &ctx.shavite, hash2, 64 );
     sph_shavite512_close( &ctx.shavite, hash2 );
     memcpy( &ctx.shavite, &x13sm3_4way_ctx.shavite,
             sizeof(sph_shavite512_context) );
     sph_shavite512( &ctx.shavite, hash3, 64 );
     sph_shavite512_close( &ctx.shavite, hash3 );

     // Simd
     intrlv_2x128( vhash, hash0, hash1, 512 );
     simd_2way_update_close( &ctx.simd, vhash, vhash, 512 );
     dintrlv_2x128( hash0, hash1, vhash, 512 );
     intrlv_2x128( vhash, hash2, hash3, 512 );
     simd_2way_init( &ctx.simd, 512 );
     simd_2way_update_close( &ctx.simd, vhash, vhash, 512 );
     dintrlv_2x128( hash2, hash3, vhash, 512 );

     // Echo
     update_final_echo( &ctx.echo, (BitSequence *)hash0,
                       (const BitSequence *) hash0, 512 );
     memcpy( &ctx.echo, &x13sm3_4way_ctx.echo, sizeof(hashState_echo) );
     update_final_echo( &ctx.echo, (BitSequence *)hash1,
                       (const BitSequence *) hash1, 512 );
     memcpy( &ctx.echo, &x13sm3_4way_ctx.echo, sizeof(hashState_echo) );
     update_final_echo( &ctx.echo, (BitSequence *)hash2,
                       (const BitSequence *) hash2, 512 );
     memcpy( &ctx.echo, &x13sm3_4way_ctx.echo, sizeof(hashState_echo) );
     update_final_echo( &ctx.echo, (BitSequence *)hash3,
                       (const BitSequence *) hash3, 512 );

     intrlv_4x32( vhash, hash0, hash1, hash2, hash3, 512 );

     // SM3 parallel 32 bit
     uint32_t sm3_vhash[32*4] __attribute__ ((aligned (64)));
     memset( sm3_vhash, 0, sizeof sm3_vhash );
     uint32_t sm3_hash0[32] __attribute__ ((aligned (32)));
     memset( sm3_hash0, 0, sizeof sm3_hash0 );
     uint32_t sm3_hash1[32] __attribute__ ((aligned (32)));
     memset( sm3_hash1, 0, sizeof sm3_hash1 );
     uint32_t sm3_hash2[32] __attribute__ ((aligned (32)));
     memset( sm3_hash2, 0, sizeof sm3_hash2 );
     uint32_t sm3_hash3[32] __attribute__ ((aligned (32)));
     memset( sm3_hash3, 0, sizeof sm3_hash3 );

     sm3_4way_update( &ctx.sm3, vhash, 64 );
     sm3_4way_close( &ctx.sm3, sm3_vhash );
     dintrlv_4x32( hash0, hash1, hash2, hash3, sm3_vhash, 512 );

     // Hamsi parallel 4x32x2
     intrlv_4x64( vhash, hash0, hash1, hash2, hash3, 512 );
     hamsi512_4way_update( &ctx.hamsi, vhash, 64 );
     hamsi512_4way_close( &ctx.hamsi, vhash );
     dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 512 );

     // Fugue serial
     sph_fugue512( &ctx.fugue, hash0, 64 );
     sph_fugue512_close( &ctx.fugue, hash0 );
     memcpy( &ctx.fugue, &x13sm3_4way_ctx.fugue, sizeof(sph_fugue512_context) );
     sph_fugue512( &ctx.fugue, hash1, 64 );
     sph_fugue512_close( &ctx.fugue, hash1 );
     memcpy( &ctx.fugue, &x13sm3_4way_ctx.fugue, sizeof(sph_fugue512_context) );
     sph_fugue512( &ctx.fugue, hash2, 64 );
     sph_fugue512_close( &ctx.fugue, hash2 );
     memcpy( &ctx.fugue, &x13sm3_4way_ctx.fugue, sizeof(sph_fugue512_context) );
     sph_fugue512( &ctx.fugue, hash3, 64 );
     sph_fugue512_close( &ctx.fugue, hash3 );

     memcpy( state,    hash0, 32 );
     memcpy( state+32, hash1, 32 );
     memcpy( state+64, hash2, 32 );
     memcpy( state+96, hash3, 32 );
}

int scanhash_x13sm3_4way( struct work *work, uint32_t max_nonce,
                       uint64_t *hashes_done, struct thr_info *mythr )
{
     uint32_t hash[4*8] __attribute__ ((aligned (64)));
     uint32_t vdata[24*4] __attribute__ ((aligned (64)));
     uint32_t *pdata = work->data;
     uint32_t *ptarget = work->target;
     uint32_t n = pdata[19];
     const uint32_t first_nonce = pdata[19];
     __m256i  *noncev = (__m256i*)vdata + 9;   // aligned
     int thr_id = mythr->id;  // thr_id arg is deprecated
     const uint32_t Htarg = ptarget[7];
     uint64_t htmax[] = {          0,        0xF,       0xFF,
                               0xFFF,     0xFFFF, 0x10000000  };
     uint32_t masks[] = { 0xFFFFFFFF, 0xFFFFFFF0, 0xFFFFFF00,
                          0xFFFFF000, 0xFFFF0000,          0  };

     mm256_bswap32_intrlv80_4x64( vdata, pdata );

     blake512_4way_init( &x13sm3_ctx_mid );
     blake512_4way_update( &x13sm3_ctx_mid, vdata, 64 );

     for ( int m=0; m < 6; m++ )
       if ( Htarg <= htmax[m] )
       {
         uint32_t mask = masks[m];
         do
         {
           *noncev = mm256_intrlv_blend_32( mm256_bswap_32(
                 _mm256_set_epi32( n+3, 0, n+2, 0, n+1, 0, n, 0 ) ), *noncev );

            x13sm3_4way_hash( hash, vdata );
            pdata[19] = n;

            for ( int i = 0; i < 4; i++ )
            if ( ( ( (hash+(i<<3))[7] & mask ) == 0 ) )
            if ( fulltest( hash+(i<<3), ptarget ) && !opt_benchmark )
            {
               pdata[19] = n+i;
              submit_solution( work, hash+(i<<3), mythr );
            }
            n += 4;
         } while ( ( n < max_nonce ) && !work_restart[thr_id].restart );
         break;
       }

     *hashes_done = n - first_nonce + 1;
     return 0;
}

#endif
