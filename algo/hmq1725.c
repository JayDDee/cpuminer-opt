#include "algo-gate-api.h"
#include <string.h>
#include <stdint.h>
#include "algo/blake/sph_blake.h"
#include "algo/bmw/sph_bmw.h"
#include "algo/groestl/sph_groestl.h"
#include "algo/jh/sph_jh.h"
#include "algo/keccak/sph_keccak.h"
#include "algo/skein/sph_skein.h"
#include "algo/luffa/sph_luffa.h"
#include "algo/cubehash/sph_cubehash.h"
#include "algo/shavite/sph_shavite.h"
#include "algo/simd/sph_simd.h"
#include "algo/echo/sph_echo.h"
#include "algo/hamsi/sph_hamsi.h"
#include "algo/fugue/sph_fugue.h"
#include "algo/shabal/sph_shabal.h"
#include "algo/whirlpool/sph_whirlpool.h"
#include "algo/sha/sph_sha2.h"
#include "algo/haval/sph-haval.h"
#include <openssl/sha.h>
#ifndef NO_AES_NI
  #include "algo/groestl/aes_ni/hash-groestl.h"
  #include "algo/echo/aes_ni/hash_api.h"
#endif
#include "algo/luffa/sse2/luffa_for_sse2.h"
#include "algo/cubehash/sse2/cubehash_sse2.h"
#include "algo/simd/sse2/nist.h"
#include "algo/jh/sse2/jh_sse2_opt64.h"

typedef struct {
  sph_blake512_context    blake1, blake2;
  sph_bmw512_context      bmw1, bmw2, bmw3;
  sph_skein512_context    skein1, skein2;
  sph_jh512_context       jh1, jh2;
  sph_keccak512_context   keccak1, keccak2;
  hashState_luffa         luffa1, luffa2;
  cubehashParam           cube;
  sph_shavite512_context  shavite1, shavite2;
  hashState_sd            simd1, simd2;
  sph_hamsi512_context    hamsi1;
  sph_fugue512_context    fugue1, fugue2;
  sph_shabal512_context   shabal1;
  sph_whirlpool_context   whirlpool1, whirlpool2, whirlpool3, whirlpool4;
#ifndef USE_SPH_SHA
  SHA512_CTX              sha1, sha2;
#else
  sph_sha512_context      sha1, sha2;
#endif
  sph_haval256_5_context  haval1, haval2;
#ifdef NO_AES_NI
  sph_groestl512_context  groestl1, groestl2;
  sph_echo512_context     echo1, echo2;
#else
  hashState_echo          echo1, echo2;
  hashState_groestl       groestl1, groestl2;
#endif
} hmq1725_ctx_holder;

static hmq1725_ctx_holder hmq1725_ctx __attribute__ ((aligned (64)));
static __thread sph_bmw512_context hmq_bmw_mid __attribute__ ((aligned (64)));

void init_hmq1725_ctx()
{
    sph_blake512_init(&hmq1725_ctx.blake1);
    sph_blake512_init(&hmq1725_ctx.blake2);

    sph_bmw512_init(&hmq1725_ctx.bmw1);
    sph_bmw512_init(&hmq1725_ctx.bmw2);
    sph_bmw512_init(&hmq1725_ctx.bmw3);

    sph_skein512_init(&hmq1725_ctx.skein1);
    sph_skein512_init(&hmq1725_ctx.skein2);

    sph_jh512_init(&hmq1725_ctx.jh1);
    sph_jh512_init(&hmq1725_ctx.jh2);

    sph_keccak512_init(&hmq1725_ctx.keccak1);
    sph_keccak512_init(&hmq1725_ctx.keccak2);

    init_luffa( &hmq1725_ctx.luffa1, 512 );
    init_luffa( &hmq1725_ctx.luffa2, 512 );

    cubehashInit( &hmq1725_ctx.cube, 512, 16, 32 );

    sph_shavite512_init(&hmq1725_ctx.shavite1);
    sph_shavite512_init(&hmq1725_ctx.shavite2);

    init_sd( &hmq1725_ctx.simd1, 512 );
    init_sd( &hmq1725_ctx.simd2, 512 );

    sph_hamsi512_init(&hmq1725_ctx.hamsi1);

    sph_fugue512_init(&hmq1725_ctx.fugue1);
    sph_fugue512_init(&hmq1725_ctx.fugue2);

    sph_shabal512_init(&hmq1725_ctx.shabal1);

    sph_whirlpool_init(&hmq1725_ctx.whirlpool1);
    sph_whirlpool_init(&hmq1725_ctx.whirlpool2);
    sph_whirlpool_init(&hmq1725_ctx.whirlpool3);
    sph_whirlpool_init(&hmq1725_ctx.whirlpool4);

#ifndef USE_SPH_SHA
    SHA512_Init( &hmq1725_ctx.sha1 );
    SHA512_Init( &hmq1725_ctx.sha2 );
#else
    sph_sha512_init(&hmq1725_ctx.sha1);
    sph_sha512_init(&hmq1725_ctx.sha2);
#endif
    sph_haval256_5_init(&hmq1725_ctx.haval1);
    sph_haval256_5_init(&hmq1725_ctx.haval2);

#ifdef NO_AES_NI
     sph_groestl512_init( &hmq1725_ctx.groestl1 );
     sph_groestl512_init( &hmq1725_ctx.groestl2 );
     sph_echo512_init( &hmq1725_ctx.echo1 );
     sph_echo512_init( &hmq1725_ctx.echo2 );
#else
     init_echo( &hmq1725_ctx.echo1, 512 );
     init_echo( &hmq1725_ctx.echo2, 512 );
     init_groestl( &hmq1725_ctx.groestl1, 64 );
     init_groestl( &hmq1725_ctx.groestl2, 64 );
#endif
}

void hmq_bmw512_midstate( const void* input )
{
    memcpy( &hmq_bmw_mid, &hmq1725_ctx.bmw1, sizeof hmq_bmw_mid );
    sph_bmw512( &hmq_bmw_mid, input, 64 );
}

__thread hmq1725_ctx_holder h_ctx __attribute__ ((aligned (64)));

extern void hmq1725hash(void *state, const void *input)
{
    const uint32_t mask = 24;
    uint32_t hashA[32] __attribute__((aligned(64)));
    uint32_t hashB[32] __attribute__((aligned(64)));
    const int midlen = 64;            // bytes
    const int tail   = 80 - midlen;   // 16

    memcpy(&h_ctx, &hmq1725_ctx, sizeof(hmq1725_ctx));

    memcpy( &h_ctx.bmw1, &hmq_bmw_mid, sizeof hmq_bmw_mid );
    sph_bmw512( &h_ctx.bmw1, input + midlen, tail );
    sph_bmw512_close(&h_ctx.bmw1, hashA);   //1

    sph_whirlpool (&h_ctx.whirlpool1, hashA, 64);    //0
    sph_whirlpool_close(&h_ctx.whirlpool1, hashB);   //1

    if ( hashB[0] & mask )   //1
    {
#ifdef NO_AES_NI
     sph_groestl512 (&h_ctx.groestl1, hashB, 64); //1
     sph_groestl512_close(&h_ctx.groestl1, hashA); //2
#else
     update_and_final_groestl( &h_ctx.groestl1, (char*)hashA, 
                               (const char*)hashB, 512 );
#endif
    }
    else
    {
      sph_skein512 (&h_ctx.skein1, hashB, 64); //1
      sph_skein512_close(&h_ctx.skein1, hashA); //2
    }
	
    sph_jh512 (&h_ctx.jh1, hashA, 64); //3
    sph_jh512_close(&h_ctx.jh1, hashB); //4

    sph_keccak512 (&h_ctx.keccak1, hashB, 64); //2
    sph_keccak512_close(&h_ctx.keccak1, hashA); //3

    if ( hashA[0] & mask ) //4
    {
        sph_blake512 (&h_ctx.blake1, hashA, 64); //
        sph_blake512_close(&h_ctx.blake1, hashB); //5
    }
    else
    {
        sph_bmw512 (&h_ctx.bmw2, hashA, 64); //4
        sph_bmw512_close(&h_ctx.bmw2, hashB);   //5
    }
    
     update_and_final_luffa( &h_ctx.luffa1, (BitSequence*)hashA, 
                             (const BitSequence*)hashB, 64 );

     cubehashUpdateDigest( &h_ctx.cube, (BitSequence *)hashB,
                           (const BitSequence *)hashA, 64 );

    if ( hashB[0] & mask ) //7
    {
        sph_keccak512 (&h_ctx.keccak2, hashB, 64); //
        sph_keccak512_close(&h_ctx.keccak2, hashA); //8
    }
    else
    {
        sph_jh512 (&h_ctx.jh2, hashB, 64); //7
        sph_jh512_close(&h_ctx.jh2, hashA); //8
    }

    sph_shavite512 (&h_ctx.shavite1, hashA, 64); //3
    sph_shavite512_close(&h_ctx.shavite1, hashB); //4

    update_final_sd( &h_ctx.simd1, (BitSequence *)hashA,
                                   (const BitSequence *)hashB, 512 );

    if ( hashA[0] & mask ) //4
    {
        sph_whirlpool (&h_ctx.whirlpool2, hashA, 64); //
        sph_whirlpool_close(&h_ctx.whirlpool2, hashB); //5
    }
    else
    {
        sph_haval256_5 (&h_ctx.haval1, hashA, 64); //4
        sph_haval256_5_close(&h_ctx.haval1, hashB);   //5
	memset(&hashB[8], 0, 32);
    }

#ifdef NO_AES_NI
    sph_echo512 (&h_ctx.echo1, hashB, 64); //5
    sph_echo512_close(&h_ctx.echo1, hashA); //6
#else
    update_final_echo ( &h_ctx.echo1, (BitSequence *)hashA,
                        (const BitSequence *)hashB, 512 );
#endif

    sph_blake512 (&h_ctx.blake2, hashA, 64); //6
    sph_blake512_close(&h_ctx.blake2, hashB); //7

    if ( hashB[0] & mask ) //7
    {
        sph_shavite512 (&h_ctx.shavite2, hashB, 64); //
        sph_shavite512_close(&h_ctx.shavite2, hashA); //8
    }
    else
    {
     update_and_final_luffa( &h_ctx.luffa2, (BitSequence *)hashA,
                             (const BitSequence *)hashB, 64 );
    }

    sph_hamsi512 (&h_ctx.hamsi1, hashA, 64); //3
    sph_hamsi512_close(&h_ctx.hamsi1, hashB); //4

    sph_fugue512 (&h_ctx.fugue1, hashB, 64); //2   ////
    sph_fugue512_close(&h_ctx.fugue1, hashA); //3 

    if ( hashA[0] & mask ) //4
    {
#ifdef NO_AES_NI
     sph_echo512 (&h_ctx.echo2, hashA, 64); //
     sph_echo512_close(&h_ctx.echo2, hashB); //5
#else
     update_final_echo ( &h_ctx.echo2, (BitSequence *)hashB,
                         (const BitSequence *)hashA, 512 );
#endif
    }
    else
    {
     update_final_sd( &h_ctx.simd2, (BitSequence *)hashB,
                      (const BitSequence *)hashA, 512 );
    }

    sph_shabal512 (&h_ctx.shabal1, hashB, 64); //5
    sph_shabal512_close(&h_ctx.shabal1, hashA); //6

    sph_whirlpool (&h_ctx.whirlpool3, hashA, 64); //6
    sph_whirlpool_close(&h_ctx.whirlpool3, hashB); //7

    if ( hashB[0] & mask ) //7
    {
        sph_fugue512 (&h_ctx.fugue2, hashB, 64); //
        sph_fugue512_close(&h_ctx.fugue2, hashA); //8
    }
    else
    {
#ifndef USE_SPH_SHA
        SHA512_Update( &h_ctx.sha1, hashB, 64 );
        SHA512_Final( (unsigned char*) hashA, &h_ctx.sha1 );
#else
        sph_sha512 (&h_ctx.sha1, hashB, 64); //7
        sph_sha512_close(&h_ctx.sha1, hashA); //8
#endif
    }

#ifdef NO_AES_NI
    sph_groestl512 (&h_ctx.groestl2, hashA, 64); //3
    sph_groestl512_close(&h_ctx.groestl2, hashB); //4
#else
    update_and_final_groestl( &h_ctx.groestl2, (char*)hashB,
                               (const char*)hashA, 512 );
#endif

#ifndef USE_SPH_SHA
    SHA512_Update( &h_ctx.sha2, hashB, 64 );
    SHA512_Final( (unsigned char*) hashA, &h_ctx.sha2 );
#else
    sph_sha512 (&h_ctx.sha2, hashB, 64); //2 
    sph_sha512_close(&h_ctx.sha2, hashA); //3 
#endif

    if ( hashA[0] & mask ) //4
    {
        sph_haval256_5 (&h_ctx.haval2, hashA, 64); //
        sph_haval256_5_close(&h_ctx.haval2, hashB); //5
	memset(&hashB[8], 0, 32);
    }
    else
    {
        sph_whirlpool (&h_ctx.whirlpool4, hashA, 64); //4
        sph_whirlpool_close(&h_ctx.whirlpool4, hashB);   //5
    }

    sph_bmw512 (&h_ctx.bmw3, hashB, 64); //5
    sph_bmw512_close(&h_ctx.bmw3, hashA); //6

	memcpy(state, hashA, 32);
}

int scanhash_hmq1725( int thr_id, struct work *work, int32_t max_nonce,
                      uint64_t *hashes_done )
{
        uint32_t endiandata[32] __attribute__((aligned(64)));
        uint32_t hash64[8] __attribute__((aligned(64)));
        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;
	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];
	//const uint32_t Htarg = ptarget[7];

	//we need bigendian data...
        for (int k = 0; k < 32; k++)
                be32enc(&endiandata[k], pdata[k]);

        hmq_bmw512_midstate( endiandata );

//	if (opt_debug) 
//	{
//		applog(LOG_DEBUG, "Thr: %02d, firstN: %08x, maxN: %08x, ToDo: %d", thr_id, first_nonce, max_nonce, max_nonce-first_nonce);
//	}
	
	/* I'm to lazy to put the loop in an inline function... so dirty copy'n'paste.... */
	/* i know that i could set a variable, but i don't know how the compiler will optimize it, not that then the cpu needs to load the value *everytime* in a register */
	if (ptarget[7]==0) {
		do {
			pdata[19] = ++n;
			be32enc(&endiandata[19], n); 
			hmq1725hash(hash64, endiandata);
			if (((hash64[7]&0xFFFFFFFF)==0) && 
					fulltest(hash64, ptarget)) {
				*hashes_done = n - first_nonce + 1;
				return true;
			}
		} while (n < max_nonce && !work_restart[thr_id].restart);	
	} 
	else if (ptarget[7]<=0xF) 
	{
		do {
			pdata[19] = ++n;
			be32enc(&endiandata[19], n); 
			hmq1725hash(hash64, endiandata);
			if (((hash64[7]&0xFFFFFFF0)==0) && 
					fulltest(hash64, ptarget)) {
				*hashes_done = n - first_nonce + 1;
				return true;
			}
		} while (n < max_nonce && !work_restart[thr_id].restart);	
	} 
	else if (ptarget[7]<=0xFF) 
	{
		do {
			pdata[19] = ++n;
			be32enc(&endiandata[19], n); 
			hmq1725hash(hash64, endiandata);
			if (((hash64[7]&0xFFFFFF00)==0) && 
					fulltest(hash64, ptarget)) {
				*hashes_done = n - first_nonce + 1;
				return true;
			}
		} while (n < max_nonce && !work_restart[thr_id].restart);	
	} 
	else if (ptarget[7]<=0xFFF) 
	{
		do {
			pdata[19] = ++n;
			be32enc(&endiandata[19], n); 
			hmq1725hash(hash64, endiandata);
			if (((hash64[7]&0xFFFFF000)==0) && 
					fulltest(hash64, ptarget)) {
				*hashes_done = n - first_nonce + 1;
				return true;
			}
		} while (n < max_nonce && !work_restart[thr_id].restart);	

	} 
	else if (ptarget[7]<=0xFFFF) 
	{
		do {
			pdata[19] = ++n;
			be32enc(&endiandata[19], n); 
			hmq1725hash(hash64, endiandata);
			if (((hash64[7]&0xFFFF0000)==0) && 
					fulltest(hash64, ptarget)) {
				*hashes_done = n - first_nonce + 1;
				return true;
			}
		} while (n < max_nonce && !work_restart[thr_id].restart);	

	} 
	else 
	{
		do {
			pdata[19] = ++n;
			be32enc(&endiandata[19], n); 
			hmq1725hash(hash64, endiandata);
			if (fulltest(hash64, ptarget)) {
				*hashes_done = n - first_nonce + 1;
				return true;
			}
		} while (n < max_nonce && !work_restart[thr_id].restart);	
	}
	
	
	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}

bool register_hmq1725_algo( algo_gate_t* gate )
{
  init_hmq1725_ctx();
  gate->optimizations = SSE2_OPT | AES_OPT | AVX_OPT | AVX2_OPT | SHA_OPT;
  gate->set_target       = (void*)&scrypt_set_target;
  gate->scanhash         = (void*)&scanhash_hmq1725;
  gate->hash             = (void*)&hmq1725hash;
  return true;
};

