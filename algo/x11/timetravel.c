#include "timetravel-gate.h"

#if !defined(TIMETRAVEL_8WAY) && !defined(TIMETRAVEL_4WAY)

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "algo/blake/sph_blake.h"
#include "algo/bmw/sph_bmw.h"
#include "algo/jh/sph_jh.h"
#include "algo/keccak/sph_keccak.h"
#include "algo/skein/sph_skein.h"
#include "algo/luffa/luffa_for_sse2.h"
#include "algo/cubehash/cubehash_sse2.h"
#ifdef __AES__
  #include "algo/groestl/aes_ni/hash-groestl.h"
#else
  #include "algo/groestl/sph_groestl.h"
#endif

static __thread uint32_t s_ntime = UINT32_MAX;
static __thread int permutation[TT8_FUNC_COUNT] = { 0 };

typedef struct {
        sph_blake512_context    blake;
        sph_bmw512_context      bmw;
        sph_skein512_context    skein;
        sph_jh512_context       jh;
        sph_keccak512_context   keccak;
        hashState_luffa         luffa;
        cubehashParam           cube;
#ifdef __AES__
        hashState_groestl       groestl;
#else
        sph_groestl512_context  groestl;
#endif
} tt_ctx_holder;

tt_ctx_holder tt_ctx __attribute__ ((aligned (64)));
__thread tt_ctx_holder tt_mid __attribute__ ((aligned (64)));

void init_tt8_ctx()
{
        sph_blake512_init( &tt_ctx.blake );
        sph_bmw512_init( &tt_ctx.bmw );
        sph_skein512_init( &tt_ctx.skein );
        sph_jh512_init( &tt_ctx.jh );
        sph_keccak512_init( &tt_ctx.keccak );
        init_luffa( &tt_ctx.luffa, 512 );
        cubehashInit( &tt_ctx.cube, 512, 16, 32 );
#ifdef __AES__
        init_groestl( &tt_ctx.groestl, 64 );
#else
        sph_groestl512_init( &tt_ctx.groestl );
#endif
};

void timetravel_hash(void *output, const void *input)
{
   uint32_t hash[ 16 * TT8_FUNC_COUNT ] __attribute__ ((aligned (64)));
   uint32_t *hashA, *hashB;
   tt_ctx_holder ctx __attribute__ ((aligned (64)));
   uint32_t dataLen = 64;
   uint32_t *work_data = (uint32_t *)input;
   int i;
   const int midlen = 64;            // bytes
   const int tail   = 80 - midlen;   // 16

   memcpy( &ctx, &tt_ctx, sizeof(tt_ctx) );

   for ( i = 0; i < TT8_FUNC_COUNT; i++ )
   {
        if (i == 0)
        {
	   dataLen = 80;
	   hashA = work_data;
	}
        else
        {
           dataLen = 64;
	   hashA = &hash[16 * (i - 1)];
	}
	hashB = &hash[16 * i];

    switch ( permutation[i] )
    {
      case 0:
        if ( i == 0 )
        {
           memcpy( &ctx.blake, &tt_mid.blake, sizeof tt_mid.blake );
           sph_blake512( &ctx.blake, input + midlen, tail );
           sph_blake512_close( &ctx.blake, hashB );
        }
        else
        {
           sph_blake512( &ctx.blake, hashA, dataLen );
           sph_blake512_close( &ctx.blake, hashB );
        }
        break;
     case 1:
        if ( i == 0 )
        {
           memcpy( &ctx.bmw, &tt_mid.bmw, sizeof tt_mid.bmw );
           sph_bmw512( &ctx.bmw, input + midlen, tail );
           sph_bmw512_close( &ctx.bmw, hashB );
        }
        else
        {          
           sph_bmw512( &ctx.bmw, hashA, dataLen );
           sph_bmw512_close( &ctx.bmw, hashB );
        }
        break;
     case 2:
#ifdef __AES__
           update_and_final_groestl( &ctx.groestl, (char*)hashB,
                                    (char*)hashA, dataLen*8 );
#else
        if ( i == 0 )
        {
           memcpy( &ctx.groestl, &tt_mid.groestl, sizeof tt_mid.groestl );
           sph_groestl512( &ctx.groestl, input + midlen, tail );
           sph_groestl512_close( &ctx.groestl, hashB );
        }
        else
        {
           sph_groestl512( &ctx.groestl, hashA, dataLen );
           sph_groestl512_close( &ctx.groestl, hashB );
        }
#endif
        break;
     case 3:
        if ( i == 0 )
        {
           memcpy( &ctx.skein, &tt_mid.skein, sizeof tt_mid.skein );
           sph_skein512( &ctx.skein, input + midlen, tail );
           sph_skein512_close( &ctx.skein, hashB );
        }
        else
        {
           sph_skein512( &ctx.skein, hashA, dataLen );
           sph_skein512_close( &ctx.skein, hashB );
        }
        break;
     case 4:
        if ( i == 0 )
        {
           memcpy( &ctx.jh, &tt_mid.jh, sizeof tt_mid.jh );
           sph_jh512( &ctx.jh, input + midlen, tail );
           sph_jh512_close( &ctx.jh, hashB );
        }
        else
        {
           sph_jh512( &ctx.jh, hashA, dataLen );
           sph_jh512_close( &ctx.jh, hashB);
        }
        break;
     case 5:
        if ( i == 0 )
        {
           memcpy( &ctx.keccak, &tt_mid.keccak, sizeof tt_mid.keccak );
           sph_keccak512( &ctx.keccak, input + midlen, tail );
           sph_keccak512_close( &ctx.keccak, hashB );
        }
        else
        {
           sph_keccak512( &ctx.keccak, hashA, dataLen );
           sph_keccak512_close( &ctx.keccak, hashB );
        }
        break;
     case 6:
        if ( i == 0 )
        {
           memcpy( &ctx.luffa, &tt_mid.luffa, sizeof tt_mid.luffa );
           update_and_final_luffa( &ctx.luffa, (BitSequence*)hashB,
                                   (const BitSequence *)input + 64, 16 );
        }
        else
        {
           update_and_final_luffa( &ctx.luffa, (BitSequence*)hashB,
                                   (const BitSequence *)hashA, dataLen );
        }
        break;
     case 7:
        if ( i == 0 )
        {
           memcpy( &ctx.cube, &tt_mid.cube, sizeof tt_mid.cube );
           cubehashUpdateDigest( &ctx.cube, (byte*)hashB,
                                 (const byte*)input + midlen, tail );
        }
        else
        {
           cubehashUpdateDigest( &ctx.cube, (byte*)hashB, (const byte*)hashA,
                                 dataLen );
        }
        break;
     default:
	break;
    }
  }

	memcpy(output, &hash[16 * (TT8_FUNC_COUNT - 1)], 32);
}

int scanhash_timetravel( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t _ALIGN(64) hash[8];
   uint32_t _ALIGN(64) endiandata[20];
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   int thr_id = mythr->id;  // thr_id arg is deprecated
   const uint32_t Htarg = ptarget[7];
   const uint32_t first_nonce = pdata[19];
   uint32_t nonce = first_nonce;
   volatile uint8_t *restart = &(work_restart[thr_id].restart);
   int i;

   if (opt_benchmark)
	ptarget[7] = 0x0cff;

   for (int k=0; k < 19; k++)
	be32enc(&endiandata[k], pdata[k]);

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

      // do midstate precalc for first function
      switch ( permutation[0] )
      {
         case 0:
           memcpy( &tt_mid.blake, &tt_ctx.blake, sizeof(tt_mid.blake) );
           sph_blake512( &tt_mid.blake, endiandata, 64 );
           break;
        case 1:
           memcpy( &tt_mid.bmw, &tt_ctx.bmw, sizeof(tt_mid.bmw) );
           sph_bmw512( &tt_mid.bmw, endiandata, 64 );
           break;
        case 2:
#ifndef __AES__
           memcpy( &tt_mid.groestl, &tt_ctx.groestl, sizeof(tt_mid.groestl ) );
           sph_groestl512( &tt_mid.groestl, endiandata, 64 );
#endif
           break;
        case 3:
           memcpy( &tt_mid.skein, &tt_ctx.skein, sizeof(tt_mid.skein ) );
           sph_skein512( &tt_mid.skein, endiandata, 64 );
           break;
        case 4:
           memcpy( &tt_mid.jh, &tt_ctx.jh, sizeof(tt_mid.jh ) );
           sph_jh512( &tt_mid.jh, endiandata, 64 );
           break;
         case 5:
           memcpy( &tt_mid.keccak, &tt_ctx.keccak, sizeof(tt_mid.keccak ) );
           sph_keccak512( &tt_mid.keccak, endiandata, 64 );
           break;
        case 6:
           memcpy( &tt_mid.luffa, &tt_ctx.luffa, sizeof(tt_mid.luffa ) );
           update_luffa( &tt_mid.luffa, (const BitSequence*)endiandata, 64 );
           break;
        case 7:
           memcpy( &tt_mid.cube, &tt_ctx.cube, sizeof(tt_mid.cube ) );
           cubehashUpdate( &tt_mid.cube, (const byte*)endiandata, 64 );
           break;
        default:
           break;
      }
   }

   do {
        be32enc( &endiandata[19], nonce );
        timetravel_hash( hash, endiandata );

        if ( hash[7] <= Htarg && fulltest( hash, ptarget) )
        {
              pdata[19] = nonce;
              submit_solution( work, hash, mythr );
        }
        nonce++;
        } while (nonce < max_nonce && !(*restart));

        pdata[19] = nonce;
        *hashes_done = pdata[19] - first_nonce + 1;
  return 0;
}

#endif
