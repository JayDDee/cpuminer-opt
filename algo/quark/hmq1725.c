#include "hmq1725-gate.h"

#if !defined(HMQ1725_8WAY) && !defined(HMQ1725_4WAY)

#include <string.h>
#include <stdint.h>
#include "algo/blake/blake512-hash.h"
#include "algo/bmw/sph_bmw.h"
#if defined(__AES__) || defined(__ARM_FEATURE_AES)
  #include "algo/fugue/fugue-aesni.h"
#else
  #include "algo/fugue/sph_fugue.h"
#endif
#if defined(__AES__) || defined(__ARM_FEATURE_AES)
  #include "algo/groestl/aes_ni/hash-groestl.h"
  #include "algo/echo/aes_ni/hash_api.h"
#else
  #include "algo/groestl/sph_groestl.h"
  #include "algo/echo/sph_echo.h"
#endif
#include "algo/jh/sph_jh.h"
#include "algo/keccak/sph_keccak.h"
#include "algo/skein/sph_skein.h"
#include "algo/shavite/sph_shavite.h"
#include "algo/hamsi/sph_hamsi.h"
#include "algo/shabal/sph_shabal.h"
#include "algo/whirlpool/sph_whirlpool.h"
#include "algo/haval/sph-haval.h"
#include "algo/sha/sph_sha2.h"
#include "algo/luffa/luffa_for_sse2.h"
#include "algo/cubehash/cubehash_sse2.h"
#include "algo/simd/simd-hash-2way.h"

union _hmq1725_ctx_holder
{
   blake512_context        blake;
   sph_bmw512_context      bmw;
#if defined(__AES__) || defined(__ARM_FEATURE_AES)
   hashState_fugue         fugue;
#else
   sph_fugue512_context    fugue;
#endif
#if defined(__AES__) || defined(__ARM_FEATURE_AES)
   hashState_groestl       groestl;
   hashState_echo          echo;
#else
   sph_groestl512_context  groestl;
   sph_echo512_context     echo;
#endif
   sph_skein512_context    skein;
   sph_jh512_context       jh;
   sph_keccak512_context   keccak;
   hashState_luffa         luffa;
   cubehashParam           cube;
   sph_shavite512_context  shavite;
   simd512_context         simd;
   sph_hamsi512_context    hamsi;
   sph_shabal512_context   shabal;
   sph_whirlpool_context   whirlpool;
   sph_sha512_context      sha;
   sph_haval256_5_context  haval;
};
typedef union _hmq1725_ctx_holder hmq1725_ctx_holder;

extern void hmq1725hash(void *state, const void *input)
{
    const uint32_t mask = 24;
    uint32_t hashA[32] __attribute__((aligned(32)));
    uint32_t hashB[32] __attribute__((aligned(32)));
    hmq1725_ctx_holder ctx __attribute__ ((aligned (64)));

    sph_bmw512_init( &ctx.bmw );
    sph_bmw512( &ctx.bmw, input, 80 );
    sph_bmw512_close( &ctx.bmw, hashA );   //1

    sph_whirlpool_init( &ctx.whirlpool );
    sph_whirlpool( &ctx.whirlpool, hashA, 64 );    //0
    sph_whirlpool_close( &ctx.whirlpool, hashB );   //1

    if ( hashB[0] & mask )   //1
    {
#if defined(__AES__) || defined(__ARM_FEATURE_AES)
       groestl512_full( &ctx.groestl, hashA, hashB, 512 );
#else
       sph_groestl512_init( &ctx.groestl );
       sph_groestl512( &ctx.groestl, hashB, 64 ); //1
       sph_groestl512_close( &ctx.groestl, hashA ); //2
#endif
    }
    else
    {
      sph_skein512_init( &ctx.skein );
      sph_skein512( &ctx.skein, hashB, 64 ); //1
      sph_skein512_close( &ctx.skein, hashA ); //2
    }
	
    sph_jh512_init( &ctx.jh );
    sph_jh512( &ctx.jh, hashA, 64 ); //3
    sph_jh512_close( &ctx.jh, hashB ); //4

    sph_keccak512_init( &ctx.keccak );
    sph_keccak512( &ctx.keccak, hashB, 64 ); //2
    sph_keccak512_close( &ctx.keccak, hashA ); //3

    if ( hashA[0] & mask ) //4
    {
        blake512_init( &ctx.blake );
        blake512_update( &ctx.blake, hashA, 64 );
        blake512_close( &ctx.blake, hashB );
    }
    else
    {
        sph_bmw512_init( &ctx.bmw );
        sph_bmw512( &ctx.bmw, hashA, 64 ); //4
        sph_bmw512_close( &ctx.bmw, hashB );   //5
    }
    
    luffa_full( &ctx.luffa, hashA, 512, hashB, 64 );

    cubehash_full( &ctx.cube, hashB, 512, hashA, 64 );

    if ( hashB[0] & mask ) //7
    {
        sph_keccak512_init( &ctx.keccak );
        sph_keccak512( &ctx.keccak, hashB, 64 ); //
        sph_keccak512_close( &ctx.keccak, hashA ); //8
    }
    else
    {
        sph_jh512_init( &ctx.jh );
        sph_jh512( &ctx.jh, hashB, 64 ); //7
        sph_jh512_close( &ctx.jh, hashA ); //8
    }

    sph_shavite512_init( &ctx.shavite );
    sph_shavite512( &ctx.shavite, hashA, 64 ); //3
    sph_shavite512_close( &ctx.shavite, hashB ); //4

    simd512_ctx( &ctx.simd, hashA, hashB, 64 );

    if ( hashA[0] & mask ) //4
    {
        sph_whirlpool_init( &ctx.whirlpool );
        sph_whirlpool( &ctx.whirlpool, hashA, 64 ); //
        sph_whirlpool_close( &ctx.whirlpool, hashB ); //5
    }
    else
    {
        sph_haval256_5_init( &ctx.haval );
        sph_haval256_5( &ctx.haval, hashA, 64 ); //4
        sph_haval256_5_close( &ctx.haval, hashB );   //5
        memset(&hashB[8], 0, 32);
    }

#if defined(__AES__) || defined(__ARM_FEATURE_AES)
    echo_full( &ctx.echo, hashA, 512, hashB, 64 );
#else
    sph_echo512_init( &ctx.echo );
    sph_echo512( &ctx.echo, hashB, 64 ); //5
    sph_echo512_close( &ctx.echo, hashA ); //6
#endif

    blake512_init( &ctx.blake );
    blake512_update( &ctx.blake, hashA, 64 );
    blake512_close( &ctx.blake, hashB );

    if ( hashB[0] & mask ) //7
    {
       sph_shavite512_init( &ctx.shavite );
       sph_shavite512( &ctx.shavite, hashB, 64 ); //
       sph_shavite512_close( &ctx.shavite, hashA ); //8
    }
    else
       luffa_full( &ctx.luffa, hashA, 512, hashB, 64 );

    sph_hamsi512_init( &ctx.hamsi );
    sph_hamsi512( &ctx.hamsi, hashA, 64 ); //3
    sph_hamsi512_close( &ctx.hamsi, hashB ); //4

#if defined(__AES__) || defined(__ARM_FEATURE_AES)
    fugue512_full( &ctx.fugue, hashA, hashB, 64 );
#else
    sph_fugue512_init( &ctx.fugue );
    sph_fugue512( &ctx.fugue, hashB, 64 ); //2   ////
    sph_fugue512_close( &ctx.fugue, hashA ); //3 
#endif

    if ( hashA[0] & mask ) //4
    {
#if defined(__AES__) || defined(__ARM_FEATURE_AES)
       echo_full( &ctx.echo, hashB, 512, hashA, 64 );
#else
       sph_echo512_init( &ctx.echo );
       sph_echo512( &ctx.echo, hashA, 64 ); //
       sph_echo512_close( &ctx.echo, hashB ); //5
#endif
    }
    else
       simd512_ctx( &ctx.simd, hashB, hashA, 64 );

    sph_shabal512_init( &ctx.shabal );
    sph_shabal512( &ctx.shabal, hashB, 64 ); //5
    sph_shabal512_close( &ctx.shabal, hashA ); //6

    sph_whirlpool_init( &ctx.whirlpool );
    sph_whirlpool( &ctx.whirlpool, hashA, 64 ); //6
    sph_whirlpool_close( &ctx.whirlpool, hashB ); //7

    if ( hashB[0] & mask ) //7
    {
#if defined(__AES__) || defined(__ARM_FEATURE_AES)
       fugue512_full( &ctx.fugue, hashA, hashB, 64 );
#else
       sph_fugue512_init( &ctx.fugue );
       sph_fugue512( &ctx.fugue, hashB, 64 ); //
       sph_fugue512_close( &ctx.fugue, hashA ); //8
#endif
    }
    else
    {
       sph_sha512_init( &ctx.sha );
       sph_sha512( &ctx.sha, hashB, 64 );
       sph_sha512_close( &ctx.sha, hashA );
    }

#if defined(__AES__) || defined(__ARM_FEATURE_AES)
    groestl512_full( &ctx.groestl, hashB, hashA, 512 );
#else
    sph_groestl512_init( &ctx.groestl );
    sph_groestl512( &ctx.groestl, hashA, 64 ); //3
    sph_groestl512_close( &ctx.groestl, hashB ); //4
#endif

    sph_sha512_init( &ctx.sha );
    sph_sha512( &ctx.sha, hashB, 64 );
    sph_sha512_close( &ctx.sha, hashA );

    if ( hashA[0] & mask ) //4
    {
        sph_haval256_5_init( &ctx.haval );
        sph_haval256_5( &ctx.haval, hashA, 64 ); //
        sph_haval256_5_close( &ctx.haval, hashB ); //5
        memset( &hashB[8], 0, 32 );
    }
    else
    {
        sph_whirlpool_init( &ctx.whirlpool );
        sph_whirlpool( &ctx.whirlpool, hashA, 64 ); //4
        sph_whirlpool_close( &ctx.whirlpool, hashB );   //5
    }

    sph_bmw512_init( &ctx.bmw );
    sph_bmw512( &ctx.bmw, hashB, 64 ); //5
    sph_bmw512_close( &ctx.bmw, hashA ); //6

	memcpy( state, hashA, 32 );
}

int scanhash_hmq1725( struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t endiandata[20] __attribute__((aligned(32)));
   uint32_t hash64[8] __attribute__((aligned(32)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];
   int thr_id = mythr->id;  // thr_id arg is deprecated

	//we need bigendian data...
   for (int k = 0; k < 20; k++)
         be32enc(&endiandata[k], pdata[k]);

	if (ptarget[7]==0) {
		do {
			pdata[19] = ++n;
			be32enc(&endiandata[19], n); 
			hmq1725hash(hash64, endiandata);
			if (((hash64[7]&0xFFFFFFFF)==0) && 
					fulltest(hash64, ptarget)) 
            submit_solution( work, hash64, mythr );
		} while (n < max_nonce && !work_restart[thr_id].restart);	
	} 
	else if (ptarget[7]<=0xF) 
	{
		do {
			pdata[19] = ++n;
			be32enc(&endiandata[19], n); 
			hmq1725hash(hash64, endiandata);
			if (((hash64[7]&0xFFFFFFF0)==0) && 
					fulltest(hash64, ptarget)) 
            submit_solution( work, hash64, mythr );
		} while (n < max_nonce && !work_restart[thr_id].restart);	
	} 
	else if (ptarget[7]<=0xFF) 
	{
		do {
			pdata[19] = ++n;
			be32enc(&endiandata[19], n); 
			hmq1725hash(hash64, endiandata);
			if (((hash64[7]&0xFFFFFF00)==0) && 
					fulltest(hash64, ptarget)) 
            submit_solution( work, hash64, mythr );
		} while (n < max_nonce && !work_restart[thr_id].restart);	
	} 
	else if (ptarget[7]<=0xFFF) 
	{
		do {
			pdata[19] = ++n;
			be32enc(&endiandata[19], n); 
			hmq1725hash(hash64, endiandata);
			if (((hash64[7]&0xFFFFF000)==0) && 
					fulltest(hash64, ptarget)) 
            submit_solution( work, hash64, mythr );
		} while (n < max_nonce && !work_restart[thr_id].restart);	
	} 
	else if (ptarget[7]<=0xFFFF) 
	{
		do {
			pdata[19] = ++n;
			be32enc(&endiandata[19], n); 
			hmq1725hash(hash64, endiandata);
			if (((hash64[7]&0xFFFF0000)==0) && 
					fulltest(hash64, ptarget)) 
                submit_solution( work, hash64, mythr );
		} while (n < max_nonce && !work_restart[thr_id].restart);	
	} 
	else 
	{
		do {
			pdata[19] = ++n;
			be32enc(&endiandata[19], n); 
			hmq1725hash(hash64, endiandata);
			if (fulltest(hash64, ptarget)) 
                submit_solution( work, hash64, mythr );
		} while (n < max_nonce && !work_restart[thr_id].restart);	
	}
	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}
#endif
