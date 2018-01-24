#include "x15-gate.h"

#if defined(X15_4WAY)

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
#include "algo/luffa/sse2/luffa_for_sse2.h"
#include "algo/cubehash/sse2/cubehash_sse2.h"
#include "algo/shavite/sph_shavite.h"
#include "algo/simd/sse2/nist.h"
#include "algo/echo/aes_ni/hash_api.h"
#include "algo/echo/sph_echo.h"
#include "algo/hamsi/hamsi-hash-4way.h"
//#include "algo/hamsi/sph_hamsi.h"
#include "algo/fugue/sph_fugue.h"
#include "algo/shabal/shabal-hash-4way.h"
#include "algo/whirlpool/sph_whirlpool.h"

typedef struct {
    blake512_4way_context   blake;
    bmw512_4way_context     bmw;
    hashState_groestl       groestl;
    skein512_4way_context   skein;
    jh512_4way_context      jh;
    keccak512_4way_context  keccak;
    hashState_luffa         luffa;
    cubehashParam           cube;
    sph_shavite512_context  shavite;
    hashState_sd            simd;
    hashState_echo          echo;
    hamsi512_4way_context   hamsi;
//    sph_hamsi512_context    hamsi;
    sph_fugue512_context    fugue;
    shabal512_4way_context  shabal;
    sph_whirlpool_context   whirlpool;
} x15_4way_ctx_holder;

x15_4way_ctx_holder x15_4way_ctx __attribute__ ((aligned (64)));

void init_x15_4way_ctx()
{
     blake512_4way_init( &x15_4way_ctx.blake );
     bmw512_4way_init( &x15_4way_ctx.bmw );
     init_groestl( &x15_4way_ctx.groestl, 64 );
     skein512_4way_init( &x15_4way_ctx.skein );
     jh512_4way_init( &x15_4way_ctx.jh );
     keccak512_4way_init( &x15_4way_ctx.keccak );
     init_luffa( &x15_4way_ctx.luffa, 512 );
     cubehashInit( &x15_4way_ctx.cube, 512, 16, 32 );
     sph_shavite512_init( &x15_4way_ctx.shavite );
     init_sd( &x15_4way_ctx.simd, 512 );
     init_echo( &x15_4way_ctx.echo, 512 );
     hamsi512_4way_init( &x15_4way_ctx.hamsi );
//     sph_hamsi512_init( &x15_4way_ctx.hamsi );
     sph_fugue512_init( &x15_4way_ctx.fugue );
     shabal512_4way_init( &x15_4way_ctx.shabal );
     sph_whirlpool_init( &x15_4way_ctx.whirlpool );
};

void x15_4way_hash( void *state, const void *input )
{
     uint64_t hash0[8] __attribute__ ((aligned (64)));
     uint64_t hash1[8] __attribute__ ((aligned (64)));
     uint64_t hash2[8] __attribute__ ((aligned (64)));
     uint64_t hash3[8] __attribute__ ((aligned (64)));
     uint64_t vhash[8*4] __attribute__ ((aligned (64)));
     x15_4way_ctx_holder ctx;
     memcpy( &ctx, &x15_4way_ctx, sizeof(x15_4way_ctx) );

     // 1 Blake
     blake512_4way( &ctx.blake, input, 80 );
     blake512_4way_close( &ctx.blake, vhash );

     // 2 Bmw
     bmw512_4way( &ctx.bmw, vhash, 64 );
     bmw512_4way_close( &ctx.bmw, vhash );

     // Serial
     mm256_deinterleave_4x64( hash0, hash1, hash2, hash3, vhash, 512 );

     // 3 Groestl
     update_and_final_groestl( &ctx.groestl, (char*)hash0, (char*)hash0, 512 );
     memcpy( &ctx.groestl, &x15_4way_ctx.groestl, sizeof(hashState_groestl) );
     update_and_final_groestl( &ctx.groestl, (char*)hash1, (char*)hash1, 512 );
     memcpy( &ctx.groestl, &x15_4way_ctx.groestl, sizeof(hashState_groestl) );
     update_and_final_groestl( &ctx.groestl, (char*)hash2, (char*)hash2, 512 );
     memcpy( &ctx.groestl, &x15_4way_ctx.groestl, sizeof(hashState_groestl) );
     update_and_final_groestl( &ctx.groestl, (char*)hash3, (char*)hash3, 512 );

     // Parallel 4way
     mm256_interleave_4x64( vhash, hash0, hash1, hash2, hash3, 512 );

     // 4 Skein
     skein512_4way( &ctx.skein, vhash, 64 );
     skein512_4way_close( &ctx.skein, vhash );

     // 5 JH
     jh512_4way( &ctx.jh, vhash, 64 );
     jh512_4way_close( &ctx.jh, vhash );

     // 6 Keccak
     keccak512_4way( &ctx.keccak, vhash, 64 );
     keccak512_4way_close( &ctx.keccak, vhash );

     // Serial to the end
     mm256_deinterleave_4x64( hash0, hash1, hash2, hash3, vhash, 512 );

     // 7 Luffa
     update_and_final_luffa( &ctx.luffa, (BitSequence*)hash0,
                             (const BitSequence*)hash0, 64 );
     memcpy( &ctx.luffa, &x15_4way_ctx.luffa, sizeof(hashState_luffa) );
     update_and_final_luffa( &ctx.luffa, (BitSequence*)hash1,
                             (const BitSequence*)hash1, 64 );
     memcpy( &ctx.luffa, &x15_4way_ctx.luffa, sizeof(hashState_luffa) );
     update_and_final_luffa( &ctx.luffa, (BitSequence*)hash2,
                             (const BitSequence*)hash2, 64 );
     memcpy( &ctx.luffa, &x15_4way_ctx.luffa, sizeof(hashState_luffa) );
     update_and_final_luffa( &ctx.luffa, (BitSequence*)hash3,
                             (const BitSequence*)hash3, 64 );

     // 8 Cubehash
     cubehashUpdateDigest( &ctx.cube, (byte*)hash0, (const byte*) hash0, 64 );
     memcpy( &ctx.cube, &x15_4way_ctx.cube, sizeof(cubehashParam) );
     cubehashUpdateDigest( &ctx.cube, (byte*)hash1, (const byte*) hash1, 64 );
     memcpy( &ctx.cube, &x15_4way_ctx.cube, sizeof(cubehashParam) );
     cubehashUpdateDigest( &ctx.cube, (byte*)hash2, (const byte*) hash2, 64 );
     memcpy( &ctx.cube, &x15_4way_ctx.cube, sizeof(cubehashParam) );
     cubehashUpdateDigest( &ctx.cube, (byte*)hash3, (const byte*) hash3, 64 );

     // 9 Shavite
     sph_shavite512( &ctx.shavite, hash0, 64 );
     sph_shavite512_close( &ctx.shavite, hash0 );
     memcpy( &ctx.shavite, &x15_4way_ctx.shavite,
             sizeof(sph_shavite512_context) );
     sph_shavite512( &ctx.shavite, hash1, 64 );
     sph_shavite512_close( &ctx.shavite, hash1 );
     memcpy( &ctx.shavite, &x15_4way_ctx.shavite,
             sizeof(sph_shavite512_context) );
     sph_shavite512( &ctx.shavite, hash2, 64 );
     sph_shavite512_close( &ctx.shavite, hash2 );
     memcpy( &ctx.shavite, &x15_4way_ctx.shavite,
             sizeof(sph_shavite512_context) );
     sph_shavite512( &ctx.shavite, hash3, 64 );
     sph_shavite512_close( &ctx.shavite, hash3 );

     // 10 Simd
     update_final_sd( &ctx.simd, (BitSequence *)hash0,
                      (const BitSequence *)hash0, 512 );
     memcpy( &ctx.simd, &x15_4way_ctx.simd, sizeof(hashState_sd) );
     update_final_sd( &ctx.simd, (BitSequence *)hash1,
                      (const BitSequence *)hash1, 512 );
     memcpy( &ctx.simd, &x15_4way_ctx.simd, sizeof(hashState_sd) );
     update_final_sd( &ctx.simd, (BitSequence *)hash2,
                      (const BitSequence *)hash2, 512 );
     memcpy( &ctx.simd, &x15_4way_ctx.simd, sizeof(hashState_sd) );
     update_final_sd( &ctx.simd, (BitSequence *)hash3,
                      (const BitSequence *)hash3, 512 );

     // 11 Echo
     update_final_echo( &ctx.echo, (BitSequence *)hash0,
                       (const BitSequence *) hash0, 512 );
     memcpy( &ctx.echo, &x15_4way_ctx.echo, sizeof(hashState_echo) );
     update_final_echo( &ctx.echo, (BitSequence *)hash1,
                       (const BitSequence *) hash1, 512 );
     memcpy( &ctx.echo, &x15_4way_ctx.echo, sizeof(hashState_echo) );
     update_final_echo( &ctx.echo, (BitSequence *)hash2,
                       (const BitSequence *) hash2, 512 );
     memcpy( &ctx.echo, &x15_4way_ctx.echo, sizeof(hashState_echo) );
     update_final_echo( &ctx.echo, (BitSequence *)hash3,
                       (const BitSequence *) hash3, 512 );

     // 12 Hamsi parallel 4way 32 bit
     mm_interleave_4x32( vhash, hash0, hash1, hash2, hash3, 512 );
     hamsi512_4way( &ctx.hamsi, vhash, 64 );
     hamsi512_4way_close( &ctx.hamsi, vhash );
     mm_deinterleave_4x32( hash0, hash1, hash2, hash3, vhash, 512 );
/*
     // 12 Hamsi
     sph_hamsi512( &ctx.hamsi, hash0, 64 );
     sph_hamsi512_close( &ctx.hamsi, hash0 );
     memcpy( &ctx.hamsi, &x15_4way_ctx.hamsi, sizeof(sph_hamsi512_context) );
     sph_hamsi512( &ctx.hamsi, hash1, 64 );
     sph_hamsi512_close( &ctx.hamsi, hash1 );
     memcpy( &ctx.hamsi, &x15_4way_ctx.hamsi, sizeof(sph_hamsi512_context) );
     sph_hamsi512( &ctx.hamsi, hash2, 64 );
     sph_hamsi512_close( &ctx.hamsi, hash2 );
     memcpy( &ctx.hamsi, &x15_4way_ctx.hamsi, sizeof(sph_hamsi512_context) );
     sph_hamsi512( &ctx.hamsi, hash3, 64 );
     sph_hamsi512_close( &ctx.hamsi, hash3 );
*/
     // 13 Fugue
     sph_fugue512( &ctx.fugue, hash0, 64 );
     sph_fugue512_close( &ctx.fugue, hash0 );
     memcpy( &ctx.fugue, &x15_4way_ctx.fugue, sizeof(sph_fugue512_context) );
     sph_fugue512( &ctx.fugue, hash1, 64 );
     sph_fugue512_close( &ctx.fugue, hash1 );
     memcpy( &ctx.fugue, &x15_4way_ctx.fugue, sizeof(sph_fugue512_context) );
     sph_fugue512( &ctx.fugue, hash2, 64 );
     sph_fugue512_close( &ctx.fugue, hash2 );
     memcpy( &ctx.fugue, &x15_4way_ctx.fugue, sizeof(sph_fugue512_context) );
     sph_fugue512( &ctx.fugue, hash3, 64 );
     sph_fugue512_close( &ctx.fugue, hash3 );

     // 14 Shabal, parallel 32 bit
     mm_interleave_4x32( vhash, hash0, hash1, hash2, hash3, 512 );
     shabal512_4way( &ctx.shabal, vhash, 64 );
     shabal512_4way_close( &ctx.shabal, vhash );
     mm_deinterleave_4x32( hash0, hash1, hash2, hash3, vhash, 512 );
       
     // 15 Whirlpool
     sph_whirlpool( &ctx.whirlpool, hash0, 64 );
     sph_whirlpool_close( &ctx.whirlpool, hash0 );
     memcpy( &ctx.whirlpool, &x15_4way_ctx.whirlpool,
             sizeof(sph_whirlpool_context) );
     sph_whirlpool( &ctx.whirlpool, hash1, 64 );
     sph_whirlpool_close( &ctx.whirlpool, hash1 );
     memcpy( &ctx.whirlpool, &x15_4way_ctx.whirlpool, 
             sizeof(sph_whirlpool_context) );
     sph_whirlpool( &ctx.whirlpool, hash2, 64 );
     sph_whirlpool_close( &ctx.whirlpool, hash2 );
     memcpy( &ctx.whirlpool, &x15_4way_ctx.whirlpool, 
             sizeof(sph_whirlpool_context) );
     sph_whirlpool( &ctx.whirlpool, hash3, 64 );
     sph_whirlpool_close( &ctx.whirlpool, hash3 );

     memcpy( state,    hash0, 32 );
     memcpy( state+32, hash1, 32 );
     memcpy( state+64, hash2, 32 );
     memcpy( state+96, hash3, 32 );
}

int scanhash_x15_4way( int thr_id, struct work *work, uint32_t max_nonce,
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
     bool *found = work->nfound;
     int num_found = 0;
     uint32_t *noncep0 = vdata + 73;   // 9*8 + 1
     uint32_t *noncep1 = vdata + 75;
     uint32_t *noncep2 = vdata + 77;
     uint32_t *noncep3 = vdata + 79;
     const uint32_t Htarg = ptarget[7];
     uint64_t htmax[] = {          0,        0xF,       0xFF,
                               0xFFF,     0xFFFF, 0x10000000  };
     uint32_t masks[] = { 0xFFFFFFFF, 0xFFFFFFF0, 0xFFFFFF00,
                          0xFFFFF000, 0xFFFF0000,          0  };

     // big endian encode 0..18 uint32_t, 64 bits at a time
     swab32_array( endiandata, pdata, 20 );

     uint64_t *edata = (uint64_t*)endiandata;
     mm256_interleave_4x64( (uint64_t*)vdata, edata, edata, edata, edata, 640 );

     for ( int m=0; m < 6; m++ )
       if ( Htarg <= htmax[m] )
       {
         uint32_t mask = masks[m];
         do
         {
            found[0] = found[1] = found[2] = found[3] = false;
            be32enc( noncep0, n   );
            be32enc( noncep1, n+1 );
            be32enc( noncep2, n+2 );
            be32enc( noncep3, n+3 );

            x15_4way_hash( hash, vdata );
            pdata[19] = n;

            if ( ( hash[7] & mask ) == 0 && fulltest( hash, ptarget ) )
            {
               found[0] = true;
               num_found++;
               nonces[0] = n;
               work_set_target_ratio( work, hash );
            }
            if ( ( (hash+8)[7] & mask ) == 0 && fulltest( hash+8, ptarget ) )
            {
               found[1] = true;
               num_found++;
               nonces[1] = n+1;
               work_set_target_ratio( work, hash+8 );
            }
            if ( ( (hash+16)[7] & mask ) == 0 && fulltest( hash+16, ptarget ) )
            {
               found[2] = true;
               num_found++;
               nonces[2] = n+2;
               work_set_target_ratio( work, hash+16 );
            }
            if ( ( (hash+24)[7] & mask ) == 0 && fulltest( hash+24, ptarget ) )
            {
               found[3] = true;
               num_found++;
               nonces[3] = n+3;
               work_set_target_ratio( work, hash+24 );
            }
            n += 4;
         } while ( ( num_found == 0 ) && ( n < max_nonce )
                   && !work_restart[thr_id].restart );
         break;
       }

     *hashes_done = n - first_nonce + 1;
     return num_found;
}

#endif
