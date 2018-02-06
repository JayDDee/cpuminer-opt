/**
 * x16r algo implementation
 *
 * Implementation by tpruvot@github Jan 2018
 * Optimized by JayDDee@github Jan 2018
 */
#include "x16r-gate.h"

#if defined (X16R_4WAY)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "algo/blake/blake-hash-4way.h"
#include "algo/bmw/bmw-hash-4way.h"
#include "algo/groestl/aes_ni/hash-groestl.h"
#include "algo/groestl/aes_ni/hash-groestl.h"
#include "algo/skein/skein-hash-4way.h"
#include "algo/jh/jh-hash-4way.h"
#include "algo/keccak/keccak-hash-4way.h"
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

static __thread uint32_t s_ntime = UINT32_MAX;
static __thread char hashOrder[X16R_HASH_FUNC_COUNT + 1] = { 0 };


typedef struct {
    blake512_4way_context   blake;
    bmw512_4way_context     bmw;
    hashState_echo          echo;
    hashState_groestl       groestl;
    skein512_4way_context   skein;
    jh512_4way_context      jh;
    keccak512_4way_context  keccak;
    hashState_luffa         luffa;
    cubehashParam           cube;
    sph_shavite512_context  shavite;
    hashState_sd            simd;
    hamsi512_4way_context   hamsi;
    sph_fugue512_context    fugue;
    shabal512_4way_context  shabal;
    sph_whirlpool_context   whirlpool;
    sha512_4way_context     sha512;
} x16r_4way_ctx_holder;

x16r_4way_ctx_holder x16r_4way_ctx __attribute__ ((aligned (64)));

// Cube needs one full init so fast reinits can be done in the hash loop.
void init_x16r_4way_ctx()
{
   cubehashInit( &x16r_4way_ctx.cube, 512, 16, 32 );
};


void x16r_4way_hash( void* output, const void* input )
{
   uint32_t hash0[24] __attribute__ ((aligned (64)));
   uint32_t hash1[24] __attribute__ ((aligned (64)));
   uint32_t hash2[24] __attribute__ ((aligned (64)));
   uint32_t hash3[24] __attribute__ ((aligned (64)));
   uint32_t vhash[24*4] __attribute__ ((aligned (64)));

   x16r_4way_ctx_holder ctx;
   
   void *in0 = (void*) hash0;
   void *in1 = (void*) hash1;
   void *in2 = (void*) hash2;
   void *in3 = (void*) hash3;

   int size = 80;

   mm256_deinterleave_4x64( hash0, hash1, hash2, hash3, input, 640 );
 
   if ( s_ntime == UINT32_MAX )
   {
      const uint8_t* tmp = (uint8_t*) in0;
      x16r_getAlgoString( &tmp[4], hashOrder );
   }

   // Input data is both 64 bit interleaved (input)
   // and deinterleaved in inp0-3.
   // If First function uses 64 bit data it is not required to interleave inp
   // first. It may use the inerleaved data dmost convenient, ie 4way 64 bit.
   // All other functions assume data is deinterleaved in hash0-3
   // All functions must exit with data deinterleaved in hash0-3.
   // Alias in0-3 points to either inp0-3 or hash0-3 according to
   // its hashOrder position. Size is also set accordingly.
   for ( int i = 0; i < 16; i++ )
   {
      const char elem = hashOrder[i];
      const uint8_t algo = elem >= 'A' ? elem - 'A' + 10 : elem - '0';

      switch ( algo )
      {
         case BLAKE:
            blake512_4way_init( &ctx.blake );
            if ( i == 0 )
               blake512_4way( &ctx.blake, input, size );
            else
            {
               mm256_interleave_4x64( vhash, in0, in1, in2, in3, size<<3 );
               blake512_4way( &ctx.blake, vhash, size );
            }
            blake512_4way_close( &ctx.blake, vhash );
            mm256_deinterleave_4x64( hash0, hash1, hash2, hash3, vhash, size<<3 );
         break;
         case BMW:
            bmw512_4way_init( &ctx.bmw );
            if ( i == 0 )
               bmw512_4way( &ctx.bmw, input, size );
            else
            {
               mm256_interleave_4x64( vhash, in0, in1, in2, in3, size<<3 );
               bmw512_4way( &ctx.bmw, vhash, size );
            }
            bmw512_4way_close( &ctx.bmw, vhash );
            mm256_deinterleave_4x64( hash0, hash1, hash2, hash3, vhash, size<<3 );
         break;
         case GROESTL:
               init_groestl( &ctx.groestl, 64 );
               update_and_final_groestl( &ctx.groestl, (char*)hash0,
                                                 (const char*)in0, size<<3 );
               init_groestl( &ctx.groestl, 64 );
               update_and_final_groestl( &ctx.groestl, (char*)hash1,
                                                 (const char*)in1, size<<3 );
               init_groestl( &ctx.groestl, 64 );
               update_and_final_groestl( &ctx.groestl, (char*)hash2,
                                                 (const char*)in2, size<<3 );
               init_groestl( &ctx.groestl, 64 );
               update_and_final_groestl( &ctx.groestl, (char*)hash3,
                                                 (const char*)in3, size<<3 );
         break;
         case SKEIN:
            skein512_4way_init( &ctx.skein );
            if ( i == 0 )
               skein512_4way( &ctx.skein, input, size );
            else
            {
               mm256_interleave_4x64( vhash, in0, in1, in2, in3, size<<3 );
               skein512_4way( &ctx.skein, vhash, size );
            }
            skein512_4way_close( &ctx.skein, vhash );
            mm256_deinterleave_4x64( hash0, hash1, hash2, hash3, vhash, size<<3 );
         break;
         case JH:
            jh512_4way_init( &ctx.jh );
            if ( i == 0 )
               jh512_4way( &ctx.jh, input, size );
            else
            {
               mm256_interleave_4x64( vhash, in0, in1, in2, in3, size<<3 );
               jh512_4way( &ctx.jh, vhash, size );
            }
            jh512_4way_close( &ctx.jh, vhash );
            mm256_deinterleave_4x64( hash0, hash1, hash2, hash3, vhash, size<<3 );
         break;
         case KECCAK:
            keccak512_4way_init( &ctx.keccak );
            if ( i == 0 )
               keccak512_4way( &ctx.keccak, input, size );
            else
            {
               mm256_interleave_4x64( vhash, in0, in1, in2, in3, size<<3 );
               keccak512_4way( &ctx.keccak, vhash, size );
            }
            keccak512_4way_close( &ctx.keccak, vhash );
            mm256_deinterleave_4x64( hash0, hash1, hash2, hash3, vhash, size<<3 );
         break;
         case LUFFA:
            init_luffa( &ctx.luffa, 512 );
            update_and_final_luffa( &ctx.luffa, (BitSequence*)hash0,
                                          (const BitSequence*)in0, size );
            init_luffa( &ctx.luffa, 512 );
            update_and_final_luffa( &ctx.luffa, (BitSequence*)hash1,
                                          (const BitSequence*)in1, size );
            init_luffa( &ctx.luffa, 512 );
            update_and_final_luffa( &ctx.luffa, (BitSequence*)hash2,
                                          (const BitSequence*)in2, size );
            init_luffa( &ctx.luffa, 512 );
            update_and_final_luffa( &ctx.luffa, (BitSequence*)hash3,
                                          (const BitSequence*)in3, size );
         break;
         case CUBEHASH:
            cubehashReinit( &ctx.cube );
            cubehashUpdateDigest( &ctx.cube, (byte*) hash0,
                                  (const byte*)in0, size );
            cubehashReinit( &ctx.cube );
            cubehashUpdateDigest( &ctx.cube, (byte*) hash1,
                                  (const byte*)in1, size );
            cubehashReinit( &ctx.cube );
            cubehashUpdateDigest( &ctx.cube, (byte*) hash2,
                                  (const byte*)in2, size );
            cubehashReinit( &ctx.cube );
            cubehashUpdateDigest( &ctx.cube, (byte*) hash3,
                                        (const byte*)in3, size );
         break;
         case SHAVITE:
            sph_shavite512_init( &ctx.shavite );
            sph_shavite512( &ctx.shavite, in0, size );
            sph_shavite512_close( &ctx.shavite, hash0 );
            sph_shavite512_init( &ctx.shavite );
            sph_shavite512( &ctx.shavite, in1, size );
            sph_shavite512_close( &ctx.shavite, hash1 );
            sph_shavite512_init( &ctx.shavite );
            sph_shavite512( &ctx.shavite, in2, size );
            sph_shavite512_close( &ctx.shavite, hash2 );
            sph_shavite512_init( &ctx.shavite );
            sph_shavite512( &ctx.shavite, in3, size );
            sph_shavite512_close( &ctx.shavite, hash3 );
         break;
         case SIMD:
             init_sd( &ctx.simd, 512 );
             update_final_sd( &ctx.simd, (BitSequence *)hash0,
                              (const BitSequence*)in0, size<<3 );
             init_sd( &ctx.simd, 512 );
             update_final_sd( &ctx.simd, (BitSequence *)hash1,
                              (const BitSequence*)in1, size<<3 );
             init_sd( &ctx.simd, 512 );
             update_final_sd( &ctx.simd, (BitSequence *)hash2,
                              (const BitSequence*)in2, size<<3 );
             init_sd( &ctx.simd, 512 );
             update_final_sd( &ctx.simd, (BitSequence *)hash3,
                              (const BitSequence*)in3, size<<3 );
         break;
         case ECHO:
             init_echo( &ctx.echo, 512 );
             update_final_echo ( &ctx.echo, (BitSequence *)hash0,
                                (const BitSequence*)in0, size<<3 );
             init_echo( &ctx.echo, 512 );
             update_final_echo ( &ctx.echo, (BitSequence *)hash1,
                                (const BitSequence*)in1, size<<3 );
             init_echo( &ctx.echo, 512 );
             update_final_echo ( &ctx.echo, (BitSequence *)hash2,
                                (const BitSequence*)in2, size<<3 );
             init_echo( &ctx.echo, 512 );
             update_final_echo ( &ctx.echo, (BitSequence *)hash3,
                                (const BitSequence*)in3, size<<3 );
         break;
         case HAMSI:
             mm_interleave_4x32( vhash, in0, in1, in2, in3, size<<3 );
             hamsi512_4way_init( &ctx.hamsi );
             hamsi512_4way( &ctx.hamsi, vhash, size );
             hamsi512_4way_close( &ctx.hamsi, vhash );
             mm_deinterleave_4x32( hash0, hash1, hash2, hash3, vhash, size<<3 );
         break;
         case FUGUE:
             sph_fugue512_init( &ctx.fugue );
             sph_fugue512( &ctx.fugue, in0, size );
             sph_fugue512_close( &ctx.fugue, hash0 );
             sph_fugue512_init( &ctx.fugue );
             sph_fugue512( &ctx.fugue, in1, size );
             sph_fugue512_close( &ctx.fugue, hash1 );
             sph_fugue512_init( &ctx.fugue );
             sph_fugue512( &ctx.fugue, in2, size );
             sph_fugue512_close( &ctx.fugue, hash2 );
             sph_fugue512_init( &ctx.fugue );
             sph_fugue512( &ctx.fugue, in3, size );
             sph_fugue512_close( &ctx.fugue, hash3 );
         break;
         case SHABAL:
             mm_interleave_4x32( vhash, in0, in1, in2, in3, size<<3 );
             shabal512_4way_init( &ctx.shabal );
             shabal512_4way( &ctx.shabal, vhash, size );
             shabal512_4way_close( &ctx.shabal, vhash );
             mm_deinterleave_4x32( hash0, hash1, hash2, hash3, vhash, size<<3 );
         break;
         case WHIRLPOOL:
             sph_whirlpool_init( &ctx.whirlpool );
             sph_whirlpool( &ctx.whirlpool, in0, size );
             sph_whirlpool_close( &ctx.whirlpool, hash0 );
             sph_whirlpool_init( &ctx.whirlpool );
             sph_whirlpool( &ctx.whirlpool, in1, size );
             sph_whirlpool_close( &ctx.whirlpool, hash1 );
             sph_whirlpool_init( &ctx.whirlpool );
             sph_whirlpool( &ctx.whirlpool, in2, size );
             sph_whirlpool_close( &ctx.whirlpool, hash2 );
             sph_whirlpool_init( &ctx.whirlpool );
             sph_whirlpool( &ctx.whirlpool, in3, size );
             sph_whirlpool_close( &ctx.whirlpool, hash3 );
         break;
         case SHA_512:
             mm256_interleave_4x64( vhash, in0, in1, in2, in3, size<<3 );
             sha512_4way_init( &ctx.sha512 );
             sha512_4way( &ctx.sha512, vhash, size );
             sha512_4way_close( &ctx.sha512, vhash );
             mm256_deinterleave_4x64( hash0, hash1, hash2, hash3, vhash, size<<3 );
         break;
      }
      size = 64;
   }
   memcpy( output,    hash0, 32 );
   memcpy( output+32, hash1, 32 );
   memcpy( output+64, hash2, 32 );
   memcpy( output+96, hash3, 32 );
}

int scanhash_x16r_4way( int thr_id, struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done )
{
   uint32_t hash[4*16] __attribute__ ((aligned (64)));
   uint32_t vdata[24*4] __attribute__ ((aligned (64)));
   uint32_t endiandata[20] __attribute__((aligned(64)));
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
   volatile uint8_t *restart = &(work_restart[thr_id].restart);

   for ( int k=0; k < 19; k++ )
      be32enc( &endiandata[k], pdata[k] );

   if ( s_ntime != pdata[17] )
   {
      uint32_t ntime = swab32(pdata[17]);
      x16r_getAlgoString( (const char*) (&endiandata[1]), hashOrder );
      s_ntime = ntime;
      if ( opt_debug && !thr_id )
              applog( LOG_DEBUG, "hash order %s (%08x)", hashOrder, ntime );
   }

   if ( opt_benchmark )
      ptarget[7] = 0x0cff;

   uint64_t *edata = (uint64_t*)endiandata;
   mm256_interleave_4x64( (uint64_t*)vdata, edata, edata, edata, edata, 640 );

   do
   {
      found[0] = found[1] = found[2] = found[3] = false;
      be32enc( noncep0, n   );
      be32enc( noncep1, n+1 );
      be32enc( noncep2, n+2 );
      be32enc( noncep3, n+3 );
      x16r_4way_hash( hash, vdata );
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
   } while ( ( num_found == 0 ) && ( n < max_nonce ) && !(*restart) );

   *hashes_done = n - first_nonce + 1;
   return num_found;
}

#endif
