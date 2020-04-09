#include "timetravel-gate.h"

#if defined(TIMETRAVEL_4WAY)

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

static __thread uint32_t s_ntime = UINT32_MAX;
static __thread int permutation[TT8_FUNC_COUNT] = { 0 };

typedef struct {
    blake512_4way_context   blake;
    bmw512_4way_context     bmw;
    hashState_groestl       groestl;
    skein512_4way_context   skein;
    jh512_4way_context      jh;
    keccak512_4way_context  keccak;
    luffa_2way_context      luffa;
    cubehashParam           cube;
} tt8_4way_ctx_holder;

tt8_4way_ctx_holder tt8_4way_ctx __attribute__ ((aligned (64)));

void init_tt8_4way_ctx()
{
    blake512_4way_init( &tt8_4way_ctx.blake );
    bmw512_4way_init( &tt8_4way_ctx.bmw );
    init_groestl( &tt8_4way_ctx.groestl, 64 );
    skein512_4way_init( &tt8_4way_ctx.skein );
    jh512_4way_init( &tt8_4way_ctx.jh );
    keccak512_4way_init( &tt8_4way_ctx.keccak );
    luffa_2way_init( &tt8_4way_ctx.luffa, 512 );
    cubehashInit( &tt8_4way_ctx.cube, 512, 16, 32 );
};

void timetravel_4way_hash(void *output, const void *input)
{
   uint64_t hash0[10] __attribute__ ((aligned (64)));
   uint64_t hash1[10] __attribute__ ((aligned (64)));
   uint64_t hash2[10] __attribute__ ((aligned (64)));
   uint64_t hash3[10] __attribute__ ((aligned (64)));
   uint64_t vhashX[10*4] __attribute__ ((aligned (64)));
   uint64_t vhashY[10*4] __attribute__ ((aligned (64)));
   uint64_t *vhashA, *vhashB;
   tt8_4way_ctx_holder ctx __attribute__ ((aligned (64)));
   uint32_t dataLen = 64;
   int i;

   memcpy( &ctx, &tt8_4way_ctx, sizeof(tt8_4way_ctx) );

   for ( i = 0; i < TT8_FUNC_COUNT; i++ )
   {
      if (i == 0)
      {
	 dataLen = 80;
         vhashA = (uint64_t*)input;
         vhashB = vhashX;
      }
      else
      {
         dataLen = 64;
         if ( i % 2 == 0 )
         {
           vhashA = vhashY;
           vhashB = vhashX;
         }
         else
         {
           vhashA = vhashX;
           vhashB = vhashY;
         }
      }

      switch ( permutation[i] )
      {
        case 0:
           blake512_4way_update( &ctx.blake, vhashA, dataLen );
           blake512_4way_close( &ctx.blake, vhashB );
           if ( i == 7 )
              dintrlv_4x64( hash0, hash1, hash2, hash3, vhashB, dataLen<<3 );
        break;
        case 1:
           bmw512_4way_update( &ctx.bmw, vhashA, dataLen );
           bmw512_4way_close( &ctx.bmw, vhashB );
           if ( i == 7 )
              dintrlv_4x64( hash0, hash1, hash2, hash3, vhashB, dataLen<<3 );
        break;
        case 2:
           dintrlv_4x64( hash0, hash1, hash2, hash3, vhashA, dataLen<<3 );
           update_and_final_groestl( &ctx.groestl, (char*)hash0,
                                                   (char*)hash0, dataLen<<3 );
           reinit_groestl( &ctx.groestl );
           update_and_final_groestl( &ctx.groestl, (char*)hash1,
                                                   (char*)hash1, dataLen<<3 );
           reinit_groestl( &ctx.groestl );     
           update_and_final_groestl( &ctx.groestl, (char*)hash2,
                                                   (char*)hash2, dataLen<<3 );
           reinit_groestl( &ctx.groestl );     
           update_and_final_groestl( &ctx.groestl, (char*)hash3,
                                                   (char*)hash3, dataLen<<3 );
           if ( i != 7 )
              intrlv_4x64( vhashB, hash0, hash1, hash2, hash3, dataLen<<3 );
        break;
        case 3:
           skein512_4way_update( &ctx.skein, vhashA, dataLen );
           skein512_4way_close( &ctx.skein, vhashB );
           if ( i == 7 )
              dintrlv_4x64( hash0, hash1, hash2, hash3, vhashB, dataLen<<3 );
        break;
        case 4:
           jh512_4way_update( &ctx.jh, vhashA, dataLen );
           jh512_4way_close( &ctx.jh, vhashB );
           if ( i == 7 )
              dintrlv_4x64( hash0, hash1, hash2, hash3, vhashB, dataLen<<3 );
        break;
        case 5:
           keccak512_4way_update( &ctx.keccak, vhashA, dataLen );
           keccak512_4way_close( &ctx.keccak, vhashB );
           if ( i == 7 )
              dintrlv_4x64( hash0, hash1, hash2, hash3, vhashB, dataLen<<3 );
        break;
        case 6:
           dintrlv_4x64( hash0, hash1, hash2, hash3, vhashA, dataLen<<3 );
           intrlv_2x128( vhashA, hash0, hash1, dataLen<<3 );
           luffa_2way_update_close( &ctx.luffa, vhashA, vhashA, dataLen );
           dintrlv_2x128( hash0, hash1, vhashA, dataLen<<3 );
           intrlv_2x128( vhashA, hash2, hash3, dataLen<<3 );
           luffa_2way_init( &ctx.luffa, 512 );
           luffa_2way_update_close( &ctx.luffa, vhashA, vhashA, dataLen );
           dintrlv_2x128( hash2, hash3, vhashA, dataLen<<3 );
           if ( i != 7 )           
              intrlv_4x64( vhashB, hash0, hash1, hash2, hash3, dataLen<<3 );
        break;
        case 7:
           dintrlv_4x64( hash0, hash1, hash2, hash3, vhashA, dataLen<<3 );
           cubehashUpdateDigest( &ctx.cube, (byte*)hash0,
                                      (const byte*)hash0, dataLen );
           memcpy( &ctx.cube, &tt8_4way_ctx.cube, sizeof(cubehashParam) );
           cubehashUpdateDigest( &ctx.cube, (byte*)hash1,
                                      (const byte*)hash1, dataLen );
           memcpy( &ctx.cube, &tt8_4way_ctx.cube, sizeof(cubehashParam) );
           cubehashUpdateDigest( &ctx.cube, (byte*)hash2,
                                      (const byte*)hash2, dataLen );
           memcpy( &ctx.cube, &tt8_4way_ctx.cube, sizeof(cubehashParam) );
           cubehashUpdateDigest( &ctx.cube, (byte*)hash3,
                                      (const byte*)hash3, dataLen );
           if ( i != 7 )           
              intrlv_4x64( vhashB, hash0, hash1, hash2, hash3, dataLen<<3 );
        break;
        default:
           applog(LOG_ERR,"SWERR: timetravel invalid permutation");
	break;
      }
   }

   memcpy( output,    hash0, 32 );
   memcpy( output+32, hash1, 32 );
   memcpy( output+64, hash2, 32 );
   memcpy( output+96, hash3, 32 );
}

int scanhash_timetravel_4way( struct work *work, uint32_t max_nonce,
                              uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t hash[4*8] __attribute__ ((aligned (64)));
   uint32_t vdata[24*4] __attribute__ ((aligned (64)));
   uint32_t endiandata[20] __attribute__((aligned(64)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   uint32_t n = pdata[19];
   const uint32_t first_nonce = pdata[19];
   uint32_t *noncep = vdata + 73;   // 9*8 + 1
   const uint32_t Htarg = ptarget[7];
   int thr_id = mythr->id;  // thr_id arg is deprecated
   volatile uint8_t *restart = &(work_restart[thr_id].restart);
   int i;

   if ( opt_benchmark )
	ptarget[7] = 0x0cff;

   for ( int k = 0; k < 19; k++ )
	be32enc( &endiandata[k], pdata[k] );

   const uint32_t timestamp = endiandata[17];
   if ( timestamp != s_ntime )
   {
      const int steps = ( timestamp - TT8_FUNC_BASE_TIMESTAMP )
                    % TT8_FUNC_COUNT_PERMUTATIONS;
      for ( i = 0; i < TT8_FUNC_COUNT; i++ )
         permutation[i] = i;
      for ( i = 0; i < steps; i++ )
         tt8_next_permutation( permutation, permutation + TT8_FUNC_COUNT );
      s_ntime = timestamp;
   }

   uint64_t *edata = (uint64_t*)endiandata;
   intrlv_4x64( (uint64_t*)vdata, edata, edata, edata, edata, 640 );

   do
   {
      be32enc( noncep,   n   );
      be32enc( noncep+2, n+1 );
      be32enc( noncep+4, n+2 );
      be32enc( noncep+6, n+3 );

      timetravel_4way_hash( hash, vdata );
      pdata[19] = n;

      for ( int i = 0; i < 4; i++ )
      if ( (hash+(i<<3))[7] <= Htarg && fulltest( hash+(i<<3), ptarget )
          && !opt_benchmark )
      {
          pdata[19] = n+i;
          submit_solution( work, hash+(i<<3), mythr );
      }
      n += 4;
   } while ( ( n < max_nonce ) && !(*restart) );

   *hashes_done = n - first_nonce + 1;
   return 0;
}

#endif
