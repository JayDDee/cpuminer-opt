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
#include "algo/luffa/sse2/luffa_for_sse2.h"
#include "algo/cubehash/sse2/cubehash_sse2.h"

static __thread uint32_t s_ntime = UINT32_MAX;
static __thread int permutation[TT8_FUNC_COUNT] = { 0 };

typedef struct {
    blake512_4way_context   blake;
    bmw512_4way_context     bmw;
    hashState_groestl       groestl;
    skein512_4way_context   skein;
    jh512_4way_context      jh;
    keccak512_4way_context  keccak;
    hashState_luffa         luffa;
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
    init_luffa( &tt8_4way_ctx.luffa, 512 );
    cubehashInit( &tt8_4way_ctx.cube, 512, 16, 32 );
};

void timetravel_4way_hash(void *output, const void *input)
{
   uint64_t hash0[8] __attribute__ ((aligned (64)));
   uint64_t hash1[8] __attribute__ ((aligned (64)));
   uint64_t hash2[8] __attribute__ ((aligned (64)));
   uint64_t hash3[8] __attribute__ ((aligned (64)));
   uint64_t vhashX[8*4] __attribute__ ((aligned (64)));
   uint64_t vhashY[8*4] __attribute__ ((aligned (64)));
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
           blake512_4way( &ctx.blake, vhashA, dataLen );
           blake512_4way_close( &ctx.blake, vhashB );
           if ( i == 7 )
              mm256_deinterleave_4x64( hash0, hash1, hash2, hash3,
                                       vhashB, dataLen<<3 );
        break;
        case 1:
           bmw512_4way( &ctx.bmw, vhashA, dataLen );
           bmw512_4way_close( &ctx.bmw, vhashB );
           if ( i == 7 )
              mm256_deinterleave_4x64( hash0, hash1, hash2, hash3,
                                       vhashB, dataLen<<3 );
        break;
        case 2:
           mm256_deinterleave_4x64( hash0, hash1, hash2, hash3,
                                    vhashA, dataLen<<3 );
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
              mm256_interleave_4x64( vhashB,
                                     hash0, hash1, hash2, hash3, dataLen<<3 );
        break;
        case 3:
           skein512_4way( &ctx.skein, vhashA, dataLen );
           skein512_4way_close( &ctx.skein, vhashB );
           if ( i == 7 )
              mm256_deinterleave_4x64( hash0, hash1, hash2, hash3,
                                       vhashB, dataLen<<3 );
        break;
        case 4:
           jh512_4way( &ctx.jh, vhashA, dataLen );
           jh512_4way_close( &ctx.jh, vhashB );
           if ( i == 7 )
              mm256_deinterleave_4x64( hash0, hash1, hash2, hash3,
                                       vhashB, dataLen<<3 );
        break;
        case 5:
           keccak512_4way( &ctx.keccak, vhashA, dataLen );
           keccak512_4way_close( &ctx.keccak, vhashB );
           if ( i == 7 )
              mm256_deinterleave_4x64( hash0, hash1, hash2, hash3,
                                       vhashB, dataLen<<3 );
        break;
        case 6:
           mm256_deinterleave_4x64( hash0, hash1, hash2, hash3,
                                    vhashA, dataLen<<3 );
           update_and_final_luffa( &ctx.luffa, (BitSequence*)hash0,
                                        (const BitSequence *)hash0, dataLen );
           memcpy( &ctx.luffa, &tt8_4way_ctx.luffa, sizeof(hashState_luffa) );
           update_and_final_luffa( &ctx.luffa, (BitSequence*)hash1,
                                         (const BitSequence*)hash1, dataLen );
           memcpy( &ctx.luffa, &tt8_4way_ctx.luffa, sizeof(hashState_luffa) );
           update_and_final_luffa( &ctx.luffa, (BitSequence*)hash2,
                                         (const BitSequence*)hash2, dataLen );
           memcpy( &ctx.luffa, &tt8_4way_ctx.luffa, sizeof(hashState_luffa) );
           update_and_final_luffa( &ctx.luffa, (BitSequence*)hash3,
                                         (const BitSequence*)hash3, dataLen );
           if ( i != 7 )           
              mm256_interleave_4x64( vhashB,
                                     hash0, hash1, hash2, hash3, dataLen<<3 );
        break;
        case 7:
           mm256_deinterleave_4x64( hash0, hash1, hash2, hash3,
                                    vhashA, dataLen<<3 );
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
              mm256_interleave_4x64( vhashB,
                                     hash0, hash1, hash2, hash3, dataLen<<3 );
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

int scanhash_timetravel_4way( int thr_id, struct work *work, uint32_t max_nonce,
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
   mm256_interleave_4x64( (uint64_t*)vdata, edata, edata, edata, edata, 640 );

   do
   {
      found[0] = found[1] = found[2] = found[3] = false;
      be32enc( noncep0, n   );
      be32enc( noncep1, n+1 );
      be32enc( noncep2, n+2 );
      be32enc( noncep3, n+3 );

      timetravel_4way_hash( hash, vdata );
      pdata[19] = n;

      if ( hash[7] <= Htarg && fulltest( hash, ptarget) )
      {
         found[0] = true;
         num_found++;
         nonces[0] = n;
         work_set_target_ratio( work, hash );
      }
      if ( (hash+8)[7] <= Htarg && fulltest( hash+8, ptarget) )
      {
         found[1] = true;
         num_found++;
         nonces[1] = n+1;
         work_set_target_ratio( work, hash+8 );
      }
      if ( (hash+16)[7] <= Htarg && fulltest( hash+16, ptarget) )
      {
         found[2] = true;
         num_found++;
         nonces[2] = n+2;
         work_set_target_ratio( work, hash+16 );
      }
      if ( (hash+24)[7] <= Htarg && fulltest( hash+24, ptarget) )
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
