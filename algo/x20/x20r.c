#include "x20r-gate.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "algo/blake/sph_blake.h"
#include "algo/bmw/sph_bmw.h"
#include "algo/jh/sph_jh.h"
#include "algo/keccak/sph_keccak.h"
#include "algo/skein/sph_skein.h"
#include "algo/shavite/sph_shavite.h"
#include "algo/hamsi/sph_hamsi.h"
#include "algo/fugue/sph_fugue.h"
#include "algo/shabal/sph_shabal.h"
#include "algo/whirlpool/sph_whirlpool.h"
#include "algo/haval/sph-haval.h"
#include "algo/radiogatun/sph_radiogatun.h"
#include "algo/panama/sph_panama.h"
#include "algo/gost/sph_gost.h"
#include "algo/sha/sph_sha2.h"
#if defined(__AES__)
  #include "algo/echo/aes_ni/hash_api.h"
  #include "algo/groestl/aes_ni/hash-groestl.h"
#else
  #include "algo/groestl/sph_groestl.h"
  #include "algo/echo/sph_echo.h"
#endif 
#include "algo/luffa/luffa_for_sse2.h"
#include "algo/cubehash/cubehash_sse2.h"
#include "algo/simd/nist.h"


static __thread uint32_t s_ntime = UINT32_MAX;
static __thread char hashOrder[X20R_HASH_FUNC_COUNT + 1] = { 0 };

union _x20r_context_overlay
{
    sph_blake512_context     blake;
    sph_bmw512_context       bmw;
#if defined(__AES__)
    hashState_groestl        groestl;
    hashState_echo           echo;
#else
    sph_groestl512_context   groestl;
    sph_echo512_context      echo;
#endif
    sph_skein512_context     skein;
    sph_jh512_context        jh;
    sph_keccak512_context    keccak;
    hashState_luffa          luffa;
    cubehashParam            cube;
    hashState_sd             simd;
    sph_shavite512_context   shavite;
    sph_hamsi512_context     hamsi;
    sph_fugue512_context     fugue;
    sph_shabal512_context    shabal;
    sph_whirlpool_context    whirlpool;
    sph_sha512_context       sha512;
    sph_haval256_5_context   haval;
    sph_gost512_context      gost;
    sph_radiogatun64_context radiogatun;
    sph_panama_context       panama;
};
typedef union _x20r_context_overlay x20r_context_overlay;

void x20r_hash(void* output, const void* input)
{
   uint32_t _ALIGN(128) hash[64/4];
   x20r_context_overlay ctx;
   void *in = (void*) input;
   int size = 80;

   if ( s_ntime == UINT32_MAX )
   {
	const uint8_t* in8 = (uint8_t*) input;
	x20_r_s_getAlgoString(&in8[4], hashOrder);
   }

   for (int i = 0; i < 20; i++)
   {
	const char elem = hashOrder[i];
	const uint8_t algo = elem >= 'A' ? elem - 'A' + 10 : elem - '0';

	switch ( algo )
       	{
	   case BLAKE:
		sph_blake512_init(&ctx.blake);
		sph_blake512(&ctx.blake, in, size);
		sph_blake512_close(&ctx.blake, hash);
		break;
	   case BMW:
		sph_bmw512_init(&ctx.bmw);
		sph_bmw512(&ctx.bmw, in, size);
		sph_bmw512_close(&ctx.bmw, hash);
		break;
	   case GROESTL:
#if defined(__AES__)
                init_groestl( &ctx.groestl, 64 );
                update_and_final_groestl( &ctx.groestl, (char*)hash,
                                         (const char*)in, size<<3 );
#else
                sph_groestl512_init(&ctx.groestl);
                sph_groestl512(&ctx.groestl, in, size);
                sph_groestl512_close(&ctx.groestl, hash);
#endif
                break;
           case SKEIN:
		sph_skein512_init(&ctx.skein);
		sph_skein512(&ctx.skein, in, size);
		sph_skein512_close(&ctx.skein, hash);
		break;
	   case JH:
		sph_jh512_init(&ctx.jh);
		sph_jh512(&ctx.jh, in, size);
		sph_jh512_close(&ctx.jh, hash);
		break;
	   case KECCAK:
		sph_keccak512_init(&ctx.keccak);
		sph_keccak512(&ctx.keccak, in, size);
		sph_keccak512_close(&ctx.keccak, hash);
		break;
	   case LUFFA:
                init_luffa( &ctx.luffa, 512 );
                update_and_final_luffa( &ctx.luffa, (BitSequence*)hash,
                                        (const BitSequence*)in, size );
		break;
           case CUBEHASH:
                cubehashInit( &ctx.cube, 512, 16, 32 );
                cubehashUpdateDigest( &ctx.cube, (byte*) hash,
                                      (const byte*)in, size );
		break;
	   case SHAVITE:
		sph_shavite512_init(&ctx.shavite);
		sph_shavite512(&ctx.shavite, in, size);
		sph_shavite512_close(&ctx.shavite, hash);
		break;
           case SIMD:
                init_sd( &ctx.simd, 512 );
                update_final_sd( &ctx.simd, (BitSequence *)hash,
                                 (const BitSequence *)in, size<<3 );
			break;
           case ECHO:
#if defined(__AES__)
                init_echo( &ctx.echo, 512 );
                update_final_echo ( &ctx.echo, (BitSequence *)hash,
                                    (const BitSequence *)in, size<<3 );
#else
	        sph_echo512_init(&ctx.echo);
	        sph_echo512(&ctx.echo, in, size);
	        sph_echo512_close(&ctx.echo, hash);
#endif
		break;
	   case HAMSI:
		sph_hamsi512_init(&ctx.hamsi);
		sph_hamsi512(&ctx.hamsi, in, size);
		sph_hamsi512_close(&ctx.hamsi, hash);
		break;
	   case FUGUE:
		sph_fugue512_init(&ctx.fugue);
		sph_fugue512(&ctx.fugue, in, size);
		sph_fugue512_close(&ctx.fugue, hash);
		break;
	   case SHABAL:
		sph_shabal512_init(&ctx.shabal);
		sph_shabal512(&ctx.shabal, in, size);
		sph_shabal512_close(&ctx.shabal, hash);
		break;
	   case WHIRLPOOL:
		sph_whirlpool_init(&ctx.whirlpool);
		sph_whirlpool(&ctx.whirlpool, in, size);
		sph_whirlpool_close(&ctx.whirlpool, hash);
		break;
	   case SHA_512:
                sph_sha512_Init( &ctx.sha512 );
                sph_sha512( &ctx.sha512, in, size );
                sph_sha512_close( &ctx.sha512, hash );
		break;
	   case HAVAL:
		sph_haval256_5_init(&ctx.haval);
		sph_haval256_5(&ctx.haval, in, size);
		sph_haval256_5_close(&ctx.haval, hash);
		memset(&hash[8], 0, 32);
		break;
	   case GOST:
		sph_gost512_init(&ctx.gost);
		sph_gost512(&ctx.gost, in, size);
		sph_gost512_close(&ctx.gost, hash);
		break;
	   case RADIOGATUN:
		sph_radiogatun64_init(&ctx.radiogatun);
		sph_radiogatun64(&ctx.radiogatun, in, size);
		sph_radiogatun64_close(&ctx.radiogatun, hash);
		memset(&hash[8], 0, 32);
		break;
	   case PANAMA:
		sph_panama_init(&ctx.panama);
		sph_panama(&ctx.panama, in, size);
		sph_panama_close(&ctx.panama, hash);
		memset(&hash[8], 0, 32);
		break;
	}
   in = (void*) hash;
   size = 64;
   }
   memcpy(output, hash, 32);
}

int scanhash_x20r( struct work *work, uint32_t max_nonce,
	           uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t _ALIGN(128) hash32[8];
   uint32_t _ALIGN(128) endiandata[20];
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t Htarg = ptarget[7];
   const uint32_t first_nonce = pdata[19];
   uint32_t nonce = first_nonce;
   int thr_id = mythr->id;
   volatile uint8_t *restart = &(work_restart[thr_id].restart);

   for (int k=0; k < 19; k++)
	be32enc( &endiandata[k], pdata[k] );

   if ( s_ntime != pdata[17] )
   {
	uint32_t ntime = swab32(pdata[17]);
	x20_r_s_getAlgoString( (const char*) (&endiandata[1]), hashOrder );
	s_ntime = ntime;
	if (opt_debug && !thr_id) applog(LOG_DEBUG, "hash order %s (%08x)", hashOrder, ntime);
   }

   if ( opt_benchmark )
	ptarget[7] = 0x0cff;

   do {
	be32enc( &endiandata[19], nonce );
	x20r_hash( hash32, endiandata );

	if ( hash32[7] <= Htarg && fulltest( hash32, ptarget ) )
  	{
        pdata[19] = nonce;
        submit_solution( work, hash32, mythr );
	}
	nonce++;

   } while (nonce < max_nonce && !(*restart));

   pdata[19] = nonce;
   *hashes_done = pdata[19] - first_nonce + 1;
   return 0;
}
