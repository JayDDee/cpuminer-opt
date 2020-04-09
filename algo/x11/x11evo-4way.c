#include "cpuminer-config.h"
#include "x11evo-gate.h"

#if defined(X11EVO_4WAY)

#include <string.h>
#include <stdint.h>
#include <compat/portable_endian.h>
#include "algo/blake/blake-hash-4way.h"
#include "algo/bmw/bmw-hash-4way.h"
#include "algo/skein/skein-hash-4way.h"
#include "algo/jh/jh-hash-4way.h"
#include "algo/keccak/keccak-hash-4way.h"
#include "algo/shavite/sph_shavite.h"
#include "algo/groestl/aes_ni/hash-groestl.h"
#include "algo/echo/aes_ni/hash_api.h"
#include "algo/luffa/luffa-hash-2way.h"
#include "algo/cubehash/cubehash_sse2.h"
#include "algo/simd/simd-hash-2way.h"

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
} x11evo_4way_ctx_holder;

static x11evo_4way_ctx_holder x11evo_4way_ctx __attribute__ ((aligned (64)));

void init_x11evo_4way_ctx()
{
     blake512_4way_init( &x11evo_4way_ctx.blake );
     bmw512_4way_init( &x11evo_4way_ctx.bmw );
     init_groestl( &x11evo_4way_ctx.groestl, 64 );
     skein512_4way_init( &x11evo_4way_ctx.skein );
     jh512_4way_init( &x11evo_4way_ctx.jh );
     keccak512_4way_init( &x11evo_4way_ctx.keccak );
     luffa_2way_init( &x11evo_4way_ctx.luffa, 512 );
     cubehashInit( &x11evo_4way_ctx.cube, 512, 16, 32 );
     sph_shavite512_init( &x11evo_4way_ctx.shavite );
     simd_2way_init( &x11evo_4way_ctx.simd, 512 );
     init_echo( &x11evo_4way_ctx.echo, 512 );
}

static char hashOrder[X11EVO_FUNC_COUNT + 1] = { 0 };
static __thread uint32_t s_ntime = UINT32_MAX;

void x11evo_4way_hash( void *state, const void *input )
{
   uint32_t hash0[16] __attribute__ ((aligned (64)));
   uint32_t hash1[16] __attribute__ ((aligned (64)));
   uint32_t hash2[16] __attribute__ ((aligned (64)));
   uint32_t hash3[16] __attribute__ ((aligned (64)));
   uint32_t vhash[16*4] __attribute__ ((aligned (64)));
   x11evo_4way_ctx_holder ctx __attribute__ ((aligned (64)));
   memcpy( &ctx, &x11evo_4way_ctx, sizeof(x11evo_4way_ctx) );

   if ( s_seq == -1 )
   {
       uint32_t *data = (uint32_t*) input;
       const uint32_t ntime = data[17];
       evo_twisted_code( ntime, hashOrder );
    }

   int i;
   int len = strlen( hashOrder );
   for ( i = 0; i < len; i++ )
   {
      char elem = hashOrder[i];
      uint8_t idx;
      if ( elem >= 'A' )
         idx = elem - 'A' + 10;
      else
         idx = elem - '0';

//      int size = 64;

      switch ( idx )
      {
         case 0:
            blake512_4way_update( &ctx.blake, input, 80 );
            blake512_4way_close( &ctx.blake, vhash );
            dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 64<<3 );
         break;
         case 1:
            bmw512_4way_update( &ctx.bmw, vhash, 64 );
            bmw512_4way_close( &ctx.bmw, vhash );
            if ( i >= len-1 )
               dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 64<<3 );
         break;
         case 2:
            dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 64<<3 );
            update_and_final_groestl( &ctx.groestl, (char*)hash0,
                                                    (char*)hash0, 512 );
            reinit_groestl( &ctx.groestl );
            update_and_final_groestl( &ctx.groestl, (char*)hash1,
                                                    (char*)hash1, 512 );
            reinit_groestl( &ctx.groestl );
            update_and_final_groestl( &ctx.groestl, (char*)hash2,
                                                      (char*)hash2, 512 );
            reinit_groestl( &ctx.groestl );
            update_and_final_groestl( &ctx.groestl, (char*)hash3,
                                                      (char*)hash3, 512 );
            if ( i < len-1 )
               intrlv_4x64( vhash, hash0, hash1, hash2, hash3, 64<<3 );
         break;
         case 3:
            skein512_4way_update( &ctx.skein, vhash, 64 );
            skein512_4way_close( &ctx.skein, vhash );
            if ( i >= len-1 )
               dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 64<<3 );
         break;
         case 4:
            jh512_4way_update( &ctx.jh, vhash, 64 );
            jh512_4way_close( &ctx.jh, vhash );
            if ( i >= len-1 )
               dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 64<<3 );
         break;
         case 5:
            keccak512_4way_update( &ctx.keccak, vhash, 64 );
            keccak512_4way_close( &ctx.keccak, vhash );
            if ( i >= len-1 )
               dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 64<<3 );
         break;
         case 6:
            dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 64<<3 );
            intrlv_2x128( vhash, hash0, hash1, 64<<3 );
            luffa_2way_update_close( &ctx.luffa, vhash, vhash, 64 );
            dintrlv_2x128( hash0, hash1, vhash, 64<<3 );
            intrlv_2x128( vhash, hash2, hash3, 64<<3 );
            luffa_2way_init( &ctx.luffa, 512 );
            luffa_2way_update_close( &ctx.luffa, vhash, vhash, 64 );
            dintrlv_2x128( hash2, hash3, vhash, 64<<3 );
            if ( i < len-1 )
               intrlv_4x64( vhash, hash0, hash1, hash2, hash3, 64<<3 );
         break;
         case 7:
            dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 64<<3 );
            cubehashUpdateDigest( &ctx.cube, (byte*)hash0,
                                      (const byte*) hash0, 64 );
            memcpy( &ctx.cube, &x11evo_4way_ctx.cube, sizeof(cubehashParam) );
            cubehashUpdateDigest( &ctx.cube, (byte*)hash1,
                                      (const byte*) hash1, 64 );
            memcpy( &ctx.cube, &x11evo_4way_ctx.cube, sizeof(cubehashParam) );
            cubehashUpdateDigest( &ctx.cube, (byte*)hash2,
                                      (const byte*) hash2, 64 );
            memcpy( &ctx.cube, &x11evo_4way_ctx.cube, sizeof(cubehashParam) );
            cubehashUpdateDigest( &ctx.cube, (byte*)hash3,
                                      (const byte*) hash3, 64 );
            if ( i < len-1 )
               intrlv_4x64( vhash, hash0, hash1, hash2, hash3, 64<<3 );
         break;
         case 8:
            dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 64<<3 );
            sph_shavite512( &ctx.shavite, hash0, 64 );
            sph_shavite512_close( &ctx.shavite, hash0 );
            memcpy( &ctx.shavite, &x11evo_4way_ctx.shavite,
                    sizeof(sph_shavite512_context) );
            sph_shavite512( &ctx.shavite, hash1, 64 );
            sph_shavite512_close( &ctx.shavite, hash1 );
            memcpy( &ctx.shavite, &x11evo_4way_ctx.shavite,
                    sizeof(sph_shavite512_context) );
            sph_shavite512( &ctx.shavite, hash2, 64 );
            sph_shavite512_close( &ctx.shavite, hash2 );
            memcpy( &ctx.shavite, &x11evo_4way_ctx.shavite,
                    sizeof(sph_shavite512_context) );
            sph_shavite512( &ctx.shavite, hash3, 64 );
            sph_shavite512_close( &ctx.shavite, hash3 );
            if ( i < len-1 )
               intrlv_4x64( vhash, hash0, hash1, hash2, hash3, 64<<3 );
         break;
         case 9:
            dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 64<<3 );
            intrlv_2x128( vhash, hash0, hash1, 64<<3 );
            simd_2way_update_close( &ctx.simd, vhash, vhash, 64<<3 );
            dintrlv_2x128( hash0, hash1, vhash, 64<<3 );
            intrlv_2x128( vhash, hash2, hash3, 64<<3 );
            simd_2way_init( &ctx.simd, 512 );
            simd_2way_update_close( &ctx.simd, vhash, vhash, 64<<3 );
            dintrlv_2x128( hash2, hash3, vhash, 64<<3 );
            if ( i < len-1 )
               intrlv_4x64( vhash, hash0, hash1, hash2, hash3, 64<<3 );
         break;
         case 10:
            dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 64<<3 );
            update_final_echo( &ctx.echo, (BitSequence *)hash0,
                                   (const BitSequence *) hash0, 512 );
            memcpy( &ctx.echo, &x11evo_4way_ctx.echo, sizeof(hashState_echo) );
            update_final_echo( &ctx.echo, (BitSequence *)hash1,
                                   (const BitSequence *) hash1, 512 );
            memcpy( &ctx.echo, &x11evo_4way_ctx.echo, sizeof(hashState_echo) );
            update_final_echo( &ctx.echo, (BitSequence *)hash2,
                                   (const BitSequence *) hash2, 512 );
            memcpy( &ctx.echo, &x11evo_4way_ctx.echo, sizeof(hashState_echo) );
            update_final_echo( &ctx.echo, (BitSequence *)hash3,
                                   (const BitSequence *) hash3, 512 );
            if ( i < len-1 )
               intrlv_4x64( vhash, hash0, hash1, hash2, hash3, 64<<3 );
         break;
      }
   }

   memcpy( state,    hash0, 32 );
   memcpy( state+32, hash1, 32 );
   memcpy( state+64, hash2, 32 );
   memcpy( state+96, hash3, 32 );
}

//static const uint32_t diff1targ = 0x0000ffff;

int scanhash_x11evo_4way( struct work* work, uint32_t max_nonce,
                          uint64_t *hashes_done, struct thr_info *mythr )
{
     uint32_t hash[4*8] __attribute__ ((aligned (64)));
     uint32_t vdata[24*4] __attribute__ ((aligned (64)));
     uint32_t endiandata[20] __attribute__((aligned(64)));
     uint32_t *pdata = work->data;
     uint32_t *ptarget = work->target;
     uint32_t n = pdata[19];
     const uint32_t first_nonce = pdata[19];
     int thr_id = mythr->id;  // thr_id arg is deprecated
     uint32_t *noncep = vdata + 73;   // 9*8 + 1
     const uint32_t Htarg = ptarget[7];

     swab32_array( endiandata, pdata, 20 );

     int ntime = endiandata[17];
     if ( ntime != s_ntime  ||  s_seq == -1 )
     {
         evo_twisted_code( ntime, hashOrder );
         s_ntime = ntime;
     }

     uint32_t hmask = 0xFFFFFFFF;
     if ( Htarg  > 0 )
     {
        if ( Htarg <= 0xF )
            hmask = 0xFFFFFFF0;
        else if ( Htarg <= 0xFF )
            hmask = 0xFFFFFF00;
        else if ( Htarg <= 0xFFF )
            hmask = 0xFFFF000;
        else if ( Htarg <= 0xFFFF )
           hmask = 0xFFFF000;
      }

     uint64_t *edata = (uint64_t*)endiandata;
     intrlv_4x64( (uint64_t*)vdata, edata, edata, edata, edata, 640 );

     do
     {
         be32enc( noncep,   n   );
         be32enc( noncep+2, n+1 );
         be32enc( noncep+4, n+2 );
         be32enc( noncep+6, n+3 );

         x11evo_4way_hash( hash, vdata );
         pdata[19] = n;

         for ( int i = 0; i < 4; i++ )
         if ( ( ( (hash+(i<<3))[7] & hmask ) == 0 )
                 && fulltest( hash+(i<<3), ptarget ) && !opt_benchmark )
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
