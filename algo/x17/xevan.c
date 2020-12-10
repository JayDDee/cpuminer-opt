#include "xevan-gate.h"

#if !defined(XEVAN_8WAY) && !defined(XEVAN_4WAY)

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "algo/blake/sph_blake.h"
#include "algo/bmw/sph_bmw.h"
#include "algo/jh/sph_jh.h"
#include "algo/keccak/sph_keccak.h"
#include "algo/skein/sph_skein.h"
#include "algo/shavite/sph_shavite.h"
#include "algo/luffa/luffa_for_sse2.h"
#include "algo/hamsi/sph_hamsi.h"
#include "algo/shabal/sph_shabal.h"
#include "algo/whirlpool/sph_whirlpool.h"
#include "algo/haval/sph-haval.h"
#include "algo/simd/nist.h"
#include "algo/cubehash/cubehash_sse2.h"
#include "algo/sha/sph_sha2.h"
#if defined(__AES__)
  #include "algo/groestl/aes_ni/hash-groestl.h"
  #include "algo/echo/aes_ni/hash_api.h"
  #include "algo/fugue/fugue-aesni.h"
#else
  #include "algo/groestl/sph_groestl.h"
  #include "algo/echo/sph_echo.h"
  #include "algo/fugue/sph_fugue.h"
#endif

typedef struct {
        sph_blake512_context    blake;
        sph_bmw512_context      bmw;
        sph_skein512_context    skein;
        sph_jh512_context       jh;
        sph_keccak512_context   keccak;
        hashState_luffa         luffa;
        cubehashParam           cubehash;
        sph_shavite512_context  shavite;
        hashState_sd            simd;
        sph_hamsi512_context    hamsi;
        sph_shabal512_context   shabal;
        sph_whirlpool_context   whirlpool;
        sph_sha512_context      sha512;
        sph_haval256_5_context  haval;
#if defined(__AES__)
        hashState_echo          echo;
        hashState_groestl       groestl;
        hashState_fugue         fugue;
#else
	sph_groestl512_context  groestl;
        sph_echo512_context     echo;
        sph_fugue512_context    fugue;
#endif
} xevan_ctx_holder;

xevan_ctx_holder xevan_ctx __attribute__ ((aligned (64)));

void init_xevan_ctx()
{
        sph_blake512_init(&xevan_ctx.blake);
        sph_bmw512_init(&xevan_ctx.bmw);
        sph_skein512_init(&xevan_ctx.skein);
        sph_jh512_init(&xevan_ctx.jh);
        sph_keccak512_init(&xevan_ctx.keccak);
        init_luffa( &xevan_ctx.luffa, 512 );
        cubehashInit( &xevan_ctx.cubehash, 512, 16, 32 );
        sph_shavite512_init( &xevan_ctx.shavite );
        init_sd( &xevan_ctx.simd, 512 );
        sph_hamsi512_init( &xevan_ctx.hamsi );
        sph_shabal512_init( &xevan_ctx.shabal );
        sph_whirlpool_init( &xevan_ctx.whirlpool );
        sph_sha512_init( &xevan_ctx.sha512 );
        sph_haval256_5_init(&xevan_ctx.haval);
#if defined(__AES__)
        init_groestl( &xevan_ctx.groestl, 64 );
        init_echo( &xevan_ctx.echo, 512 );
        fugue512_Init( &xevan_ctx.fugue, 512 );
#else
	sph_groestl512_init( &xevan_ctx.groestl );
        sph_echo512_init( &xevan_ctx.echo );
        sph_fugue512_init( &xevan_ctx.fugue );
#endif
};

int xevan_hash(void *output, const void *input, int thr_id )
{
   uint32_t _ALIGN(64) hash[32]; // 128 bytes required
	const int dataLen = 128;
   xevan_ctx_holder ctx __attribute__ ((aligned (64)));
   memcpy( &ctx, &xevan_ctx, sizeof(xevan_ctx) );

   sph_blake512( &ctx.blake, input, 80 );
   sph_blake512_close( &ctx.blake, hash );
   memset(&hash[16], 0, 64);

   sph_bmw512(&ctx.bmw, hash, dataLen);
   sph_bmw512_close(&ctx.bmw, hash);

#if defined(__AES__)
   update_and_final_groestl( &ctx.groestl, (char*)hash,
                                     (const char*)hash, dataLen*8 );
#else
   sph_groestl512(&ctx.groestl, hash, dataLen);
   sph_groestl512_close(&ctx.groestl, hash);
#endif

   sph_skein512(&ctx.skein, hash, dataLen);
   sph_skein512_close(&ctx.skein, hash);

   sph_jh512(&ctx.jh, hash, dataLen);
   sph_jh512_close(&ctx.jh, hash);

   sph_keccak512(&ctx.keccak, hash, dataLen);
   sph_keccak512_close(&ctx.keccak, hash);

   update_and_final_luffa( &ctx.luffa, (BitSequence*)hash,
                                 (const BitSequence*)hash, dataLen );

   cubehashUpdateDigest( &ctx.cubehash, (byte*)hash,
                                 (const byte*) hash, dataLen );

   sph_shavite512(&ctx.shavite, hash, dataLen);
   sph_shavite512_close(&ctx.shavite, hash);

   update_final_sd( &ctx.simd, (BitSequence *)hash,
                         (const BitSequence *)hash, dataLen*8 );

#if defined(__AES__)
   update_final_echo( &ctx.echo, (BitSequence *) hash,
                           (const BitSequence *) hash, dataLen*8 );
#else
   sph_echo512(&ctx.echo, hash, dataLen);
   sph_echo512_close(&ctx.echo, hash);
#endif

   sph_hamsi512(&ctx.hamsi, hash, dataLen);
   sph_hamsi512_close(&ctx.hamsi, hash);

#if defined(__AES__)
   fugue512_Update( &ctx.fugue, hash, dataLen*8 );
   fugue512_Final( &ctx.fugue, hash ); 
#else
   sph_fugue512(&ctx.fugue, hash, dataLen);
   sph_fugue512_close(&ctx.fugue, hash);
#endif

   sph_shabal512(&ctx.shabal, hash, dataLen);
   sph_shabal512_close(&ctx.shabal, hash);

   sph_whirlpool(&ctx.whirlpool, hash, dataLen);
   sph_whirlpool_close(&ctx.whirlpool, hash);

   sph_sha512( &ctx.sha512, hash, dataLen );
   sph_sha512_close( &ctx.sha512, hash );

   sph_haval256_5(&ctx.haval,(const void*) hash, dataLen);
   sph_haval256_5_close(&ctx.haval, hash);

   memset(&hash[8], 0, dataLen - 32);

   memcpy( &ctx, &xevan_ctx, sizeof(xevan_ctx) );

   sph_blake512(&ctx.blake, hash, dataLen);
   sph_blake512_close(&ctx.blake, hash);

   sph_bmw512(&ctx.bmw, hash, dataLen);
   sph_bmw512_close(&ctx.bmw, hash);

#if defined(__AES__)
   update_and_final_groestl( &ctx.groestl, (char*)hash,
                              (const BitSequence*)hash, dataLen*8 );
#else
   sph_groestl512(&ctx.groestl, hash, dataLen);
   sph_groestl512_close(&ctx.groestl, hash);
#endif

   sph_skein512(&ctx.skein, hash, dataLen);
   sph_skein512_close(&ctx.skein, hash);

   sph_jh512(&ctx.jh, hash, dataLen);
   sph_jh512_close(&ctx.jh, hash);

   sph_keccak512(&ctx.keccak, hash, dataLen);
   sph_keccak512_close(&ctx.keccak, hash);

   update_and_final_luffa( &ctx.luffa, (BitSequence*)hash,
                                 (const BitSequence*)hash, dataLen );

   cubehashUpdateDigest( &ctx.cubehash, (byte*)hash,
                                 (const byte*) hash, dataLen );

   sph_shavite512(&ctx.shavite, hash, dataLen);
   sph_shavite512_close(&ctx.shavite, hash);

   update_final_sd( &ctx.simd, (BitSequence *)hash,
                         (const BitSequence *)hash, dataLen*8 );

#if defined(__AES__)
   update_final_echo( &ctx.echo, (BitSequence *) hash,
                           (const BitSequence *) hash, dataLen*8 );
#else
   sph_echo512(&ctx.echo, hash, dataLen);
   sph_echo512_close(&ctx.echo, hash);
#endif

   sph_hamsi512(&ctx.hamsi, hash, dataLen);
   sph_hamsi512_close(&ctx.hamsi, hash);

#if defined(__AES__)
   fugue512_Update( &ctx.fugue, hash, dataLen*8 );
   fugue512_Final( &ctx.fugue, hash );   
#else
   sph_fugue512(&ctx.fugue, hash, dataLen);
   sph_fugue512_close(&ctx.fugue, hash);
#endif

   sph_shabal512(&ctx.shabal, hash, dataLen);
   sph_shabal512_close(&ctx.shabal, hash);

   sph_whirlpool(&ctx.whirlpool, hash, dataLen);
   sph_whirlpool_close(&ctx.whirlpool, hash);

   sph_sha512( &ctx.sha512, hash, dataLen );
   sph_sha512_close( &ctx.sha512, hash );

   sph_haval256_5(&ctx.haval,(const void*) hash, dataLen);
   sph_haval256_5_close(&ctx.haval, hash);

   memcpy(output, hash, 32);

   return 1;
}

#endif
