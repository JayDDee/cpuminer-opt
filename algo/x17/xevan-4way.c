#include "xevan-gate.h"

#if defined(XEVAN_4WAY)

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "algo/blake/blake-hash-4way.h"
#include "algo/bmw/bmw-hash-4way.h"
#include "algo/groestl/aes_ni/hash-groestl.h"
#include "algo/jh/jh-hash-4way.h"
#include "algo/keccak/keccak-hash-4way.h"
#include "algo/skein/skein-hash-4way.h"
#include "algo/shavite/sph_shavite.h"
#include "algo/luffa/sse2/luffa_for_sse2.h"
#include "algo/cubehash/sse2/cubehash_sse2.h"
#include "algo/simd/sse2/nist.h"
#include "algo/echo/aes_ni/hash_api.h"
#include "algo/hamsi/hamsi-hash-4way.h"
#include "algo/fugue/sph_fugue.h"
#include "algo/shabal/shabal-hash-4way.h"
#include "algo/whirlpool/sph_whirlpool.h"
#include "algo/sha/sha2-hash-4way.h"
#include "algo/haval/haval-hash-4way.h"

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
        sph_fugue512_context    fugue;
        shabal512_4way_context  shabal;
        sph_whirlpool_context   whirlpool;
        sha512_4way_context     sha512;
        haval256_5_4way_context haval;
} xevan_4way_ctx_holder;

xevan_4way_ctx_holder xevan_4way_ctx __attribute__ ((aligned (64)));
static __thread blake512_4way_context xevan_blake_4way_mid
                                        __attribute__ ((aligned (64)));

void init_xevan_4way_ctx()
{
        blake512_4way_init(&xevan_4way_ctx.blake);
        bmw512_4way_init( &xevan_4way_ctx.bmw );
        init_groestl( &xevan_4way_ctx.groestl, 64 );
        skein512_4way_init(&xevan_4way_ctx.skein);
        jh512_4way_init(&xevan_4way_ctx.jh);
        keccak512_4way_init(&xevan_4way_ctx.keccak);
        init_luffa( &xevan_4way_ctx.luffa, 512 );
        cubehashInit( &xevan_4way_ctx.cube, 512, 16, 32 );
        sph_shavite512_init( &xevan_4way_ctx.shavite );
        init_sd( &xevan_4way_ctx.simd, 512 );
        init_echo( &xevan_4way_ctx.echo, 512 );
        hamsi512_4way_init( &xevan_4way_ctx.hamsi );
        sph_fugue512_init( &xevan_4way_ctx.fugue );
        shabal512_4way_init( &xevan_4way_ctx.shabal );
        sph_whirlpool_init( &xevan_4way_ctx.whirlpool );
        sha512_4way_init( &xevan_4way_ctx.sha512 );
        haval256_5_4way_init( &xevan_4way_ctx.haval );
};

void xevan_4way_blake512_midstate( const void* input )
{
    memcpy( &xevan_blake_4way_mid, &xevan_4way_ctx.blake,
            sizeof(xevan_blake_4way_mid) );
    blake512_4way( &xevan_blake_4way_mid, input, 64 );
}

void xevan_4way_hash( void *output, const void *input )
{
     uint64_t hash0[16] __attribute__ ((aligned (64)));
     uint64_t hash1[16] __attribute__ ((aligned (64)));
     uint64_t hash2[16] __attribute__ ((aligned (64)));
     uint64_t hash3[16] __attribute__ ((aligned (64)));
     uint64_t vhash[16<<2] __attribute__ ((aligned (64)));
     uint64_t vhash32[16<<2] __attribute__ ((aligned (64)));
     const int dataLen = 128;
     const int midlen = 64;            // bytes
     const int tail   = 80 - midlen;   // 16
     xevan_4way_ctx_holder ctx __attribute__ ((aligned (64)));
     memcpy( &ctx, &xevan_4way_ctx, sizeof(xevan_4way_ctx) );

     // parallel way
     memcpy( &ctx.blake, &xevan_blake_4way_mid,
             sizeof(xevan_blake_4way_mid) );
     blake512_4way( &ctx.blake, input + (midlen<<2), tail );
     blake512_4way_close(&ctx.blake, vhash);
     memset( &vhash[8<<2], 0, 64<<2 );

     bmw512_4way( &ctx.bmw, vhash, dataLen );
     bmw512_4way_close( &ctx.bmw, vhash );

     // Serial
     mm256_deinterleave_4x64( hash0, hash1, hash2, hash3, vhash, dataLen<<3 );

     update_and_final_groestl( &ctx.groestl, (char*)hash0, (char*)hash0,
                               dataLen<<3 );
     memcpy( &ctx.groestl, &xevan_4way_ctx.groestl, sizeof(hashState_groestl) );
     update_and_final_groestl( &ctx.groestl, (char*)hash1, (char*)hash1,
                               dataLen<<3 );
     memcpy( &ctx.groestl, &xevan_4way_ctx.groestl, sizeof(hashState_groestl) );
     update_and_final_groestl( &ctx.groestl, (char*)hash2, (char*)hash2,
                               dataLen<<3 );
     memcpy( &ctx.groestl, &xevan_4way_ctx.groestl, sizeof(hashState_groestl) );
     update_and_final_groestl( &ctx.groestl, (char*)hash3, (char*)hash3,
                               dataLen<<3 );

     // Parallel 4way
     mm256_interleave_4x64( vhash, hash0, hash1, hash2, hash3, dataLen<<3 );

     skein512_4way( &ctx.skein, vhash, dataLen );
     skein512_4way_close( &ctx.skein, vhash );

     jh512_4way( &ctx.jh, vhash, dataLen );
     jh512_4way_close( &ctx.jh, vhash );

     keccak512_4way( &ctx.keccak, vhash, dataLen );
     keccak512_4way_close( &ctx.keccak, vhash );

     // Serial
     mm256_deinterleave_4x64( hash0, hash1, hash2, hash3, vhash, dataLen<<3 );

     update_and_final_luffa( &ctx.luffa, (BitSequence*)hash0,
                             (const BitSequence*)hash0, dataLen );
     memcpy( &ctx.luffa, &xevan_4way_ctx.luffa, sizeof(hashState_luffa) );
     update_and_final_luffa( &ctx.luffa, (BitSequence*)hash1,
                             (const BitSequence*)hash1, dataLen );
     memcpy( &ctx.luffa, &xevan_4way_ctx.luffa, sizeof(hashState_luffa) );
     update_and_final_luffa( &ctx.luffa, (BitSequence*)hash2,
                             (const BitSequence*)hash2, dataLen );
     memcpy( &ctx.luffa, &xevan_4way_ctx.luffa, sizeof(hashState_luffa) );
     update_and_final_luffa( &ctx.luffa, (BitSequence*)hash3,
                             (const BitSequence*)hash3, dataLen );

     cubehashUpdateDigest( &ctx.cube, (byte*)hash0, (const byte*) hash0,
                           dataLen );
     memcpy( &ctx.cube, &xevan_4way_ctx.cube, sizeof(cubehashParam) );
     cubehashUpdateDigest( &ctx.cube, (byte*)hash1, (const byte*) hash1,
                           dataLen );
     memcpy( &ctx.cube, &xevan_4way_ctx.cube, sizeof(cubehashParam) );
     cubehashUpdateDigest( &ctx.cube, (byte*)hash2, (const byte*) hash2,
                           dataLen );
     memcpy( &ctx.cube, &xevan_4way_ctx.cube, sizeof(cubehashParam) );
     cubehashUpdateDigest( &ctx.cube, (byte*)hash3, (const byte*) hash3,
                           dataLen );

     sph_shavite512( &ctx.shavite, hash0, dataLen );
     sph_shavite512_close( &ctx.shavite, hash0 );
     memcpy( &ctx.shavite, &xevan_4way_ctx.shavite,
             sizeof(sph_shavite512_context) );
     sph_shavite512( &ctx.shavite, hash1, dataLen );
     sph_shavite512_close( &ctx.shavite, hash1 );
     memcpy( &ctx.shavite, &xevan_4way_ctx.shavite,
             sizeof(sph_shavite512_context) );
     sph_shavite512( &ctx.shavite, hash2, dataLen );
     sph_shavite512_close( &ctx.shavite, hash2 );
     memcpy( &ctx.shavite, &xevan_4way_ctx.shavite,
             sizeof(sph_shavite512_context) );
     sph_shavite512( &ctx.shavite, hash3, dataLen );
     sph_shavite512_close( &ctx.shavite, hash3 );

     update_final_sd( &ctx.simd, (BitSequence *)hash0,
                      (const BitSequence *)hash0, dataLen<<3 );
     memcpy( &ctx.simd, &xevan_4way_ctx.simd, sizeof(hashState_sd) );
     update_final_sd( &ctx.simd, (BitSequence *)hash1,
                      (const BitSequence *)hash1, dataLen<<3  );
     memcpy( &ctx.simd, &xevan_4way_ctx.simd, sizeof(hashState_sd) );
     update_final_sd( &ctx.simd, (BitSequence *)hash2,
                      (const BitSequence *)hash2, dataLen<<3  );
     memcpy( &ctx.simd, &xevan_4way_ctx.simd, sizeof(hashState_sd) );
     update_final_sd( &ctx.simd, (BitSequence *)hash3,
                      (const BitSequence *)hash3, dataLen<<3  );

     update_final_echo( &ctx.echo, (BitSequence *)hash0,
                       (const BitSequence *) hash0, dataLen<<3 );
     memcpy( &ctx.echo, &xevan_4way_ctx.echo, sizeof(hashState_echo) );
     update_final_echo( &ctx.echo, (BitSequence *)hash1,
                       (const BitSequence *) hash1, dataLen<<3 );
     memcpy( &ctx.echo, &xevan_4way_ctx.echo, sizeof(hashState_echo) );
     update_final_echo( &ctx.echo, (BitSequence *)hash2,
                       (const BitSequence *) hash2, dataLen<<3 );
     memcpy( &ctx.echo, &xevan_4way_ctx.echo, sizeof(hashState_echo) );
     update_final_echo( &ctx.echo, (BitSequence *)hash3,
                       (const BitSequence *) hash3, dataLen<<3 );

     // Parallel 32 bit
     mm_interleave_4x32( vhash, hash0, hash1, hash2, hash3, dataLen<<3 );
     hamsi512_4way( &ctx.hamsi, vhash, dataLen );
     hamsi512_4way_close( &ctx.hamsi, vhash );
     mm_deinterleave_4x32( hash0, hash1, hash2, hash3, vhash, dataLen<<3 );

     sph_fugue512( &ctx.fugue, hash0, dataLen );
     sph_fugue512_close( &ctx.fugue, hash0 );
     memcpy( &ctx.fugue, &xevan_4way_ctx.fugue, sizeof(sph_fugue512_context) );
     sph_fugue512( &ctx.fugue, hash1, dataLen );
     sph_fugue512_close( &ctx.fugue, hash1 );
     memcpy( &ctx.fugue, &xevan_4way_ctx.fugue, sizeof(sph_fugue512_context) );
     sph_fugue512( &ctx.fugue, hash2, dataLen );
     sph_fugue512_close( &ctx.fugue, hash2 );
     memcpy( &ctx.fugue, &xevan_4way_ctx.fugue, sizeof(sph_fugue512_context) );
     sph_fugue512( &ctx.fugue, hash3, dataLen );
     sph_fugue512_close( &ctx.fugue, hash3 );

     // Parallel 4way 32 bit
     mm_interleave_4x32( vhash, hash0, hash1, hash2, hash3, dataLen<<3 );
     shabal512_4way( &ctx.shabal, vhash, dataLen );
     shabal512_4way_close( &ctx.shabal, vhash );
     mm_deinterleave_4x32( hash0, hash1, hash2, hash3, vhash, dataLen<<3 );

     // Serial
     sph_whirlpool( &ctx.whirlpool, hash0, dataLen );
     sph_whirlpool_close( &ctx.whirlpool, hash0 );
     memcpy( &ctx.whirlpool, &xevan_4way_ctx.whirlpool,
             sizeof(sph_whirlpool_context) );
     sph_whirlpool( &ctx.whirlpool, hash1, dataLen );
     sph_whirlpool_close( &ctx.whirlpool, hash1 );
     memcpy( &ctx.whirlpool, &xevan_4way_ctx.whirlpool,
             sizeof(sph_whirlpool_context) );
     sph_whirlpool( &ctx.whirlpool, hash2, dataLen );
     sph_whirlpool_close( &ctx.whirlpool, hash2 );
     memcpy( &ctx.whirlpool, &xevan_4way_ctx.whirlpool,
             sizeof(sph_whirlpool_context) );
     sph_whirlpool( &ctx.whirlpool, hash3, dataLen );
     sph_whirlpool_close( &ctx.whirlpool, hash3 );

     mm256_interleave_4x64( vhash, hash0, hash1, hash2, hash3, dataLen<<3 );
     sha512_4way( &ctx.sha512, vhash, dataLen );
     sha512_4way_close( &ctx.sha512, vhash );

     mm256_reinterleave_4x32( vhash32, vhash, dataLen<<3 );
     haval256_5_4way( &ctx.haval, vhash32, dataLen );
     haval256_5_4way_close( &ctx.haval, vhash );
     mm_deinterleave_4x32( hash0, hash1, hash2, hash3, vhash, dataLen<<3 );

     mm256_interleave_4x64( vhash, hash0, hash1, hash2, hash3, dataLen<<3 );
     memset( &vhash[ 4<<2 ], 0, (dataLen-32) << 2 );
     memcpy( &ctx, &xevan_4way_ctx, sizeof(xevan_4way_ctx) );

     blake512_4way( &ctx.blake, vhash, dataLen );
     blake512_4way_close(&ctx.blake, vhash);

     bmw512_4way( &ctx.bmw, vhash, dataLen );
     bmw512_4way_close( &ctx.bmw, vhash );

     mm256_deinterleave_4x64( hash0, hash1, hash2, hash3, vhash, dataLen<<3 );

     update_and_final_groestl( &ctx.groestl, (char*)hash0, (char*)hash0,
                               dataLen<<3 );
     memcpy( &ctx.groestl, &xevan_4way_ctx.groestl, sizeof(hashState_groestl) );
     update_and_final_groestl( &ctx.groestl, (char*)hash1, (char*)hash1,
                               dataLen<<3 );
     memcpy( &ctx.groestl, &xevan_4way_ctx.groestl, sizeof(hashState_groestl) );
     update_and_final_groestl( &ctx.groestl, (char*)hash2, (char*)hash2,
                               dataLen<<3 );
     memcpy( &ctx.groestl, &xevan_4way_ctx.groestl, sizeof(hashState_groestl) );
     update_and_final_groestl( &ctx.groestl, (char*)hash3, (char*)hash3,
                               dataLen<<3 );

     mm256_interleave_4x64( vhash, hash0, hash1, hash2, hash3, dataLen<<3 );

     skein512_4way( &ctx.skein, vhash, dataLen );
     skein512_4way_close( &ctx.skein, vhash );

     jh512_4way( &ctx.jh, vhash, dataLen );
     jh512_4way_close( &ctx.jh, vhash );

     keccak512_4way( &ctx.keccak, vhash, dataLen );
     keccak512_4way_close( &ctx.keccak, vhash );

     mm256_deinterleave_4x64( hash0, hash1, hash2, hash3, vhash, dataLen<<3 );

     update_and_final_luffa( &ctx.luffa, (BitSequence*)hash0,
                             (const BitSequence*)hash0, dataLen );
     memcpy( &ctx.luffa, &xevan_4way_ctx.luffa, sizeof(hashState_luffa) );
     update_and_final_luffa( &ctx.luffa, (BitSequence*)hash1,
                             (const BitSequence*)hash1, dataLen );
     memcpy( &ctx.luffa, &xevan_4way_ctx.luffa, sizeof(hashState_luffa) );
     update_and_final_luffa( &ctx.luffa, (BitSequence*)hash2,
                             (const BitSequence*)hash2, dataLen );
     memcpy( &ctx.luffa, &xevan_4way_ctx.luffa, sizeof(hashState_luffa) );
     update_and_final_luffa( &ctx.luffa, (BitSequence*)hash3,
                             (const BitSequence*)hash3, dataLen );

     cubehashUpdateDigest( &ctx.cube, (byte*)hash0, (const byte*) hash0,
                           dataLen );
     memcpy( &ctx.cube, &xevan_4way_ctx.cube, sizeof(cubehashParam) );
     cubehashUpdateDigest( &ctx.cube, (byte*)hash1, (const byte*) hash1,
                           dataLen );
     memcpy( &ctx.cube, &xevan_4way_ctx.cube, sizeof(cubehashParam) );
     cubehashUpdateDigest( &ctx.cube, (byte*)hash2, (const byte*) hash2,
                           dataLen );
     memcpy( &ctx.cube, &xevan_4way_ctx.cube, sizeof(cubehashParam) );
     cubehashUpdateDigest( &ctx.cube, (byte*)hash3, (const byte*) hash3,
                           dataLen );

     sph_shavite512( &ctx.shavite, hash0, dataLen );
     sph_shavite512_close( &ctx.shavite, hash0 );
     memcpy( &ctx.shavite, &xevan_4way_ctx.shavite,
             sizeof(sph_shavite512_context) );
     sph_shavite512( &ctx.shavite, hash1, dataLen );
     sph_shavite512_close( &ctx.shavite, hash1 );
     memcpy( &ctx.shavite, &xevan_4way_ctx.shavite,
             sizeof(sph_shavite512_context) );
     sph_shavite512( &ctx.shavite, hash2, dataLen );
     sph_shavite512_close( &ctx.shavite, hash2 );
     memcpy( &ctx.shavite, &xevan_4way_ctx.shavite,
             sizeof(sph_shavite512_context) );
     sph_shavite512( &ctx.shavite, hash3, dataLen );
     sph_shavite512_close( &ctx.shavite, hash3 );

     update_final_sd( &ctx.simd, (BitSequence *)hash0,
                      (const BitSequence *)hash0, dataLen<<3 );
     memcpy( &ctx.simd, &xevan_4way_ctx.simd, sizeof(hashState_sd) );
     update_final_sd( &ctx.simd, (BitSequence *)hash1,
                      (const BitSequence *)hash1, dataLen<<3  );
     memcpy( &ctx.simd, &xevan_4way_ctx.simd, sizeof(hashState_sd) );
     update_final_sd( &ctx.simd, (BitSequence *)hash2,
                      (const BitSequence *)hash2, dataLen<<3  );
     memcpy( &ctx.simd, &xevan_4way_ctx.simd, sizeof(hashState_sd) );
     update_final_sd( &ctx.simd, (BitSequence *)hash3,
                      (const BitSequence *)hash3, dataLen<<3  );

     update_final_echo( &ctx.echo, (BitSequence *)hash0,
                       (const BitSequence *) hash0, dataLen<<3 );
     memcpy( &ctx.echo, &xevan_4way_ctx.echo, sizeof(hashState_echo) );
     update_final_echo( &ctx.echo, (BitSequence *)hash1,
                       (const BitSequence *) hash1, dataLen<<3 );
     memcpy( &ctx.echo, &xevan_4way_ctx.echo, sizeof(hashState_echo) );
     update_final_echo( &ctx.echo, (BitSequence *)hash2,
                       (const BitSequence *) hash2, dataLen<<3 );
     memcpy( &ctx.echo, &xevan_4way_ctx.echo, sizeof(hashState_echo) );
     update_final_echo( &ctx.echo, (BitSequence *)hash3,
                       (const BitSequence *) hash3, dataLen<<3 );

     mm_interleave_4x32( vhash, hash0, hash1, hash2, hash3, dataLen<<3 );
     hamsi512_4way( &ctx.hamsi, vhash, dataLen );
     hamsi512_4way_close( &ctx.hamsi, vhash );
     mm_deinterleave_4x32( hash0, hash1, hash2, hash3, vhash, dataLen<<3 );

     sph_fugue512( &ctx.fugue, hash0, dataLen );
     sph_fugue512_close( &ctx.fugue, hash0 );
     memcpy( &ctx.fugue, &xevan_4way_ctx.fugue, sizeof(sph_fugue512_context) );
     sph_fugue512( &ctx.fugue, hash1, dataLen );
     sph_fugue512_close( &ctx.fugue, hash1 );
     memcpy( &ctx.fugue, &xevan_4way_ctx.fugue, sizeof(sph_fugue512_context) );
     sph_fugue512( &ctx.fugue, hash2, dataLen );
     sph_fugue512_close( &ctx.fugue, hash2 );
     memcpy( &ctx.fugue, &xevan_4way_ctx.fugue, sizeof(sph_fugue512_context) );
     sph_fugue512( &ctx.fugue, hash3, dataLen );
     sph_fugue512_close( &ctx.fugue, hash3 );

     mm_interleave_4x32( vhash, hash0, hash1, hash2, hash3, dataLen<<3 );
     shabal512_4way( &ctx.shabal, vhash, dataLen );
     shabal512_4way_close( &ctx.shabal, vhash );
     mm_deinterleave_4x32( hash0, hash1, hash2, hash3, vhash, dataLen<<3 );

     sph_whirlpool( &ctx.whirlpool, hash0, dataLen );
     sph_whirlpool_close( &ctx.whirlpool, hash0 );
     memcpy( &ctx.whirlpool, &xevan_4way_ctx.whirlpool,
             sizeof(sph_whirlpool_context) );
     sph_whirlpool( &ctx.whirlpool, hash1, dataLen );
     sph_whirlpool_close( &ctx.whirlpool, hash1 );
     memcpy( &ctx.whirlpool, &xevan_4way_ctx.whirlpool,
             sizeof(sph_whirlpool_context) );
     sph_whirlpool( &ctx.whirlpool, hash2, dataLen );
     sph_whirlpool_close( &ctx.whirlpool, hash2 );
     memcpy( &ctx.whirlpool, &xevan_4way_ctx.whirlpool,
             sizeof(sph_whirlpool_context) );
     sph_whirlpool( &ctx.whirlpool, hash3, dataLen );
     sph_whirlpool_close( &ctx.whirlpool, hash3 );

     mm256_interleave_4x64( vhash, hash0, hash1, hash2, hash3, dataLen<<3 );
     sha512_4way( &ctx.sha512, vhash, dataLen );
     sha512_4way_close( &ctx.sha512, vhash );

     mm256_reinterleave_4x32( vhash32, vhash, dataLen<<3 );
     haval256_5_4way( &ctx.haval, vhash32, dataLen );
     haval256_5_4way_close( &ctx.haval, vhash32 );

     mm_deinterleave_4x32( output, output+32, output+64, output+96,
                           vhash32, 256 );
}

int scanhash_xevan_4way( int thr_id, struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done )
{
   uint32_t hash[4*8] __attribute__ ((aligned (64)));
   uint32_t vdata[24*4] __attribute__ ((aligned (64)));
   uint32_t _ALIGN(64) endiandata[20];
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;

   const uint32_t Htarg = ptarget[7];
   const uint32_t first_nonce = pdata[19];
   uint32_t n = first_nonce;
   uint32_t *nonces = work->nonces;
   bool *found = work->nfound;
   int num_found = 0;
   uint32_t *noncep0 = vdata + 73;   // 9*8 + 1
   uint32_t *noncep1 = vdata + 75;
   uint32_t *noncep2 = vdata + 77;
   uint32_t *noncep3 = vdata + 79;

   if ( opt_benchmark )
      ptarget[7] = 0x0cff;

   for ( int k=0; k < 19; k++ )
      be32enc( &endiandata[k], pdata[k] );

   uint64_t *edata = (uint64_t*)endiandata;
   mm256_interleave_4x64( (uint64_t*)vdata, edata, edata, edata, edata, 640 );

   xevan_4way_blake512_midstate( vdata );

   do {
      found[0] = found[1] = found[2] = found[3] = false;
      be32enc( noncep0, n   );
      be32enc( noncep1, n+1 );
      be32enc( noncep2, n+2 );
      be32enc( noncep3, n+3 );

      xevan_4way_hash( hash, vdata );

      pdata[19] = n;

      if ( ( hash[7] <= Htarg ) && fulltest( hash, ptarget ) )
      {
         found[0] = true;
         num_found++;
         nonces[0] = n;
         work_set_target_ratio( work, hash );
      }
      if ( ( (hash+8)[7] <= Htarg ) && fulltest( hash+8, ptarget ) )
      {
         found[1] = true;
         num_found++;
         nonces[1] = n+1;
         work_set_target_ratio( work, hash+8 );
      }
      if ( ( (hash+16)[7] <= Htarg ) && fulltest( hash+16, ptarget ) )
      {
         found[2] = true;
         num_found++;
         nonces[2] = n+2;
         work_set_target_ratio( work, hash+16 );
      }
      if ( ( (hash+24)[7] <= Htarg ) && fulltest( hash+24, ptarget ) )
      {
         found[3] = true;
         num_found++;
         nonces[3] = n+3;
         work_set_target_ratio( work, hash+24 );
      }
      n += 4;
   } while ( ( num_found == 0 ) && ( n < max_nonce )
             && !work_restart[thr_id].restart );
   *hashes_done = n - first_nonce + 1;
   return num_found;
}

#endif
