#include "sonoa-gate.h"

#if !defined(SONOA_8WAY) && !defined(SONOA_4WAY)

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "algo/blake/sph_blake.h"
#include "algo/bmw/sph_bmw.h"
#include "algo/groestl/sph_groestl.h"
#include "algo/jh/sph_jh.h"
#include "algo/keccak/sph_keccak.h"
#include "algo/skein/sph_skein.h"
#include "algo/shavite/sph_shavite.h"
#include "algo/hamsi/sph_hamsi.h"
#include "algo/shabal/sph_shabal.h"
#include "algo/whirlpool/sph_whirlpool.h"
#include "algo/haval/sph-haval.h"
#include "algo/luffa/luffa_for_sse2.h"
#include "algo/cubehash/cubehash_sse2.h"
#include "algo/simd/nist.h"
#include "algo/sha/sph_sha2.h"
#if defined(__AES__)
  #include "algo/echo/aes_ni/hash_api.h"
  #include "algo/groestl/aes_ni/hash-groestl.h"
  #include "algo/fugue/fugue-aesni.h"
#else
  #include "algo/groestl/sph_groestl.h"
  #include "algo/echo/sph_echo.h"
  #include "algo/fugue/sph_fugue.h"
#endif

typedef struct {
        sph_blake512_context    blake;
        sph_bmw512_context      bmw;
#if defined(__AES__)
        hashState_echo          echo;
        hashState_groestl       groestl;
        hashState_fugue         fugue;
#else
        sph_groestl512_context  groestl;
        sph_echo512_context     echo;
        sph_fugue512_context    fugue;
#endif
        sph_jh512_context       jh;
        sph_keccak512_context   keccak;
        sph_skein512_context    skein;
        hashState_luffa         luffa;
        cubehashParam           cubehash;
        sph_shavite512_context  shavite;
        hashState_sd            simd;
        sph_hamsi512_context    hamsi;
        sph_shabal512_context   shabal;
        sph_whirlpool_context   whirlpool;
        sph_sha512_context      sha512;
        sph_haval256_5_context  haval;
} sonoa_ctx_holder;

sonoa_ctx_holder sonoa_ctx __attribute__ ((aligned (64)));

void init_sonoa_ctx()
{
        sph_blake512_init( &sonoa_ctx.blake);
        sph_bmw512_init( &sonoa_ctx.bmw);
#if defined(__AES__)
        init_echo( &sonoa_ctx.echo, 512 );
        init_groestl( &sonoa_ctx.groestl, 64 );
        fugue512_Init( &sonoa_ctx.fugue, 512 );
#else
        sph_groestl512_init(&sonoa_ctx.groestl );
        sph_echo512_init( &sonoa_ctx.echo );
        sph_fugue512_init( &sonoa_ctx.fugue );
#endif
        sph_skein512_init( &sonoa_ctx.skein);
        sph_jh512_init( &sonoa_ctx.jh);
        sph_keccak512_init( &sonoa_ctx.keccak );
        init_luffa( &sonoa_ctx.luffa, 512 );
        cubehashInit( &sonoa_ctx.cubehash, 512, 16, 32 );
        sph_shavite512_init( &sonoa_ctx.shavite );
        init_sd( &sonoa_ctx.simd, 512 );
        sph_hamsi512_init( &sonoa_ctx.hamsi );
        sph_shabal512_init( &sonoa_ctx.shabal );
        sph_whirlpool_init( &sonoa_ctx.whirlpool );
        sph_sha512_init( &sonoa_ctx.sha512 );
        sph_haval256_5_init(&sonoa_ctx.haval);
};

int sonoa_hash( void *state, const void *input, int thr_id )
{
	uint8_t hash[128] __attribute__ ((aligned (64)));
   sonoa_ctx_holder ctx __attribute__ ((aligned (64)));
   memcpy( &ctx, &sonoa_ctx, sizeof(sonoa_ctx) );

   sph_blake512(&ctx.blake, input, 80);
	sph_blake512_close(&ctx.blake, hash);

	sph_bmw512(&ctx.bmw, hash, 64);
	sph_bmw512_close(&ctx.bmw, hash);

#if defined(__AES__)
   update_and_final_groestl( &ctx.groestl, (char*)hash,
                                     (const char*)hash, 512 );
#else
   sph_groestl512(&ctx.groestl, hash, 64);
   sph_groestl512_close(&ctx.groestl, hash);
#endif

   sph_skein512(&ctx.skein, hash, 64);
	sph_skein512_close(&ctx.skein, hash);

	sph_jh512(&ctx.jh, hash, 64);
	sph_jh512_close(&ctx.jh, hash);

	sph_keccak512(&ctx.keccak, hash, 64);
	sph_keccak512_close(&ctx.keccak, hash);

   update_and_final_luffa( &ctx.luffa, (BitSequence*)hash,
                                 (const BitSequence*)hash, 64 );

   cubehashUpdateDigest( &ctx.cubehash, (byte*) hash,
                                   (const byte*)hash, 64 );

	sph_shavite512(&ctx.shavite, hash, 64);
	sph_shavite512_close(&ctx.shavite, hash);

   update_final_sd( &ctx.simd, (BitSequence *)hash,
                         (const BitSequence *)hash, 512 );

#if defined(__AES__)
   update_final_echo ( &ctx.echo, (BitSequence *)hash,
                            (const BitSequence *)hash, 512 );
#else
   sph_echo512(&ctx.echo, hash, 64);
   sph_echo512_close(&ctx.echo, hash);
#endif

   if ( work_restart[thr_id].restart ) return 0;
//

   sph_bmw512_init( &ctx.bmw);
   sph_bmw512(&ctx.bmw, hash, 64);
   sph_bmw512_close(&ctx.bmw, hash);

#if defined(__AES__)
   init_groestl( &ctx.groestl, 64 );
   update_and_final_groestl( &ctx.groestl, (char*)hash,
                                     (const char*)hash, 512 );
#else
   sph_groestl512_init(&ctx.groestl );
   sph_groestl512(&ctx.groestl, hash, 64);
   sph_groestl512_close(&ctx.groestl, hash);
#endif

   sph_skein512_init( &ctx.skein);
   sph_skein512(&ctx.skein, hash, 64);
   sph_skein512_close(&ctx.skein, hash);

   sph_jh512_init( &ctx.jh);
   sph_jh512(&ctx.jh, hash, 64);
   sph_jh512_close(&ctx.jh, hash);

   sph_keccak512_init( &ctx.keccak );
   sph_keccak512(&ctx.keccak, hash, 64);
   sph_keccak512_close(&ctx.keccak, hash);

   init_luffa( &ctx.luffa, 512 );
   update_and_final_luffa( &ctx.luffa, (BitSequence*)hash,
                                 (const BitSequence*)hash, 64 );

   cubehashInit( &ctx.cubehash, 512, 16, 32 );
   cubehashUpdateDigest( &ctx.cubehash, (byte*) hash,
                                   (const byte*)hash, 64 );

   sph_shavite512_init( &ctx.shavite );
   sph_shavite512(&ctx.shavite, hash, 64);
   sph_shavite512_close(&ctx.shavite, hash);

   init_sd( &ctx.simd, 512 );
   update_final_sd( &ctx.simd, (BitSequence *)hash,
                         (const BitSequence *)hash, 512 );

#if defined(__AES__)
   init_echo( &ctx.echo, 512 );
   update_final_echo ( &ctx.echo, (BitSequence *)hash,
                            (const BitSequence *)hash, 512 );
#else
   sph_echo512_init( &ctx.echo );
   sph_echo512(&ctx.echo, hash, 64);
   sph_echo512_close(&ctx.echo, hash);
#endif

   sph_hamsi512(&ctx.hamsi, hash, 64);
   sph_hamsi512_close(&ctx.hamsi, hash);
	
   if ( work_restart[thr_id].restart ) return 0;
//

   sph_bmw512_init( &ctx.bmw);
   sph_bmw512(&ctx.bmw, hash, 64);
   sph_bmw512_close(&ctx.bmw, hash);

#if defined(__AES__)
   init_groestl( &ctx.groestl, 64 );
   update_and_final_groestl( &ctx.groestl, (char*)hash,
                                     (const char*)hash, 512 );
#else
   sph_groestl512_init(&ctx.groestl );
   sph_groestl512(&ctx.groestl, hash, 64);
   sph_groestl512_close(&ctx.groestl, hash);
#endif

   sph_skein512_init( &ctx.skein);
   sph_skein512(&ctx.skein, hash, 64);
   sph_skein512_close(&ctx.skein, hash);

   sph_jh512_init( &ctx.jh);
   sph_jh512(&ctx.jh, hash, 64);
   sph_jh512_close(&ctx.jh, hash);

   sph_keccak512_init( &ctx.keccak );
   sph_keccak512(&ctx.keccak, hash, 64);
   sph_keccak512_close(&ctx.keccak, hash);

   init_luffa( &ctx.luffa, 512 );
   update_and_final_luffa( &ctx.luffa, (BitSequence*)hash,
                                 (const BitSequence*)hash, 64 );

   cubehashInit( &ctx.cubehash, 512, 16, 32 );
   cubehashUpdateDigest( &ctx.cubehash, (byte*)hash,
                                  (const byte*)hash, 64 );

   sph_shavite512_init( &ctx.shavite );
   sph_shavite512(&ctx.shavite, hash, 64);
   sph_shavite512_close(&ctx.shavite, hash);

   init_sd( &ctx.simd, 512 );
   update_final_sd( &ctx.simd, (BitSequence *)hash,
                         (const BitSequence *)hash, 512 );

#if defined(__AES__)
   init_echo( &ctx.echo, 512 );
   update_final_echo ( &ctx.echo, (BitSequence *)hash,
                            (const BitSequence *)hash, 512 );
#else
   sph_echo512_init( &ctx.echo );
   sph_echo512(&ctx.echo, hash, 64);
   sph_echo512_close(&ctx.echo, hash);
#endif

   sph_hamsi512_init( &ctx.hamsi );
   sph_hamsi512(&ctx.hamsi, hash, 64);
   sph_hamsi512_close(&ctx.hamsi, hash);

#if defined(__AES__)
   fugue512_Update( &ctx.fugue, hash, 512 );
   fugue512_Final( &ctx.fugue, hash ); 
#else   
   sph_fugue512(&ctx.fugue, hash, 64);
   sph_fugue512_close(&ctx.fugue, hash);
#endif

   if ( work_restart[thr_id].restart ) return 0;
//

   sph_bmw512_init( &ctx.bmw);
   sph_bmw512(&ctx.bmw, hash, 64);
   sph_bmw512_close(&ctx.bmw, hash);

#if defined(__AES__)
   init_groestl( &ctx.groestl, 64 );
   update_and_final_groestl( &ctx.groestl, (char*)hash,
                                  (const char*)hash, 512 );
#else
   sph_groestl512_init(&ctx.groestl );
   sph_groestl512(&ctx.groestl, hash, 64);
   sph_groestl512_close(&ctx.groestl, hash);
#endif

   sph_skein512_init( &ctx.skein);
   sph_skein512(&ctx.skein, hash, 64);
   sph_skein512_close(&ctx.skein, hash);

   sph_jh512_init( &ctx.jh);
   sph_jh512(&ctx.jh, hash, 64);
   sph_jh512_close(&ctx.jh, hash);

   sph_keccak512_init( &ctx.keccak );
   sph_keccak512(&ctx.keccak, hash, 64);
   sph_keccak512_close(&ctx.keccak, hash);

   init_luffa( &ctx.luffa, 512 );
   update_and_final_luffa( &ctx.luffa, (BitSequence*)hash,
                                (const BitSequence*)hash, 64 );

   cubehashInit( &ctx.cubehash, 512, 16, 32 );
   cubehashUpdateDigest( &ctx.cubehash, (byte*) hash,
                              (const byte*)hash, 64 );

   sph_shavite512_init( &ctx.shavite );
   sph_shavite512(&ctx.shavite, hash, 64);
   sph_shavite512_close(&ctx.shavite, hash);

   init_sd( &ctx.simd, 512 );
   update_final_sd( &ctx.simd, (BitSequence *)hash,
                         (const BitSequence *)hash, 512 );

#if defined(__AES__)
   init_echo( &ctx.echo, 512 );
   update_final_echo ( &ctx.echo, (BitSequence *)hash,
                            (const BitSequence *)hash, 512 );
#else
   sph_echo512_init( &ctx.echo );
   sph_echo512(&ctx.echo, hash, 64);
   sph_echo512_close(&ctx.echo, hash);
#endif

   sph_hamsi512_init( &ctx.hamsi );
   sph_hamsi512(&ctx.hamsi, hash, 64);
   sph_hamsi512_close(&ctx.hamsi, hash);

#if defined(__AES__)
    fugue512_full( &ctx.fugue, hash, hash, 64 );
#else
    sph_fugue512_full( &ctx.fugue, hash, hash, 64 );
#endif

   sph_shabal512(&ctx.shabal, hash, 64);
   sph_shabal512_close(&ctx.shabal, hash);

   sph_hamsi512_init( &ctx.hamsi );
   sph_hamsi512(&ctx.hamsi, hash, 64);
   sph_hamsi512_close(&ctx.hamsi, hash);

#if defined(__AES__)
   init_echo( &ctx.echo, 512 );
   update_final_echo ( &ctx.echo, (BitSequence *)hash,
                            (const BitSequence *)hash, 512 );
#else
   sph_echo512_init( &ctx.echo );
   sph_echo512(&ctx.echo, hash, 64);
   sph_echo512_close(&ctx.echo, hash);
#endif

   sph_shavite512_init( &ctx.shavite );
   sph_shavite512(&ctx.shavite, hash, 64);
   sph_shavite512_close(&ctx.shavite, hash);

   if ( work_restart[thr_id].restart ) return 0;
//

   sph_bmw512_init( &ctx.bmw);
   sph_bmw512(&ctx.bmw, hash, 64);
   sph_bmw512_close(&ctx.bmw, hash);

   sph_shabal512_init( &ctx.shabal );
	sph_shabal512(&ctx.shabal, hash, 64);
   sph_shabal512_close(&ctx.shabal, hash);

#if defined(__AES__)
   init_groestl( &ctx.groestl, 64 );
   update_and_final_groestl( &ctx.groestl, (char*)hash,
                                  (const char*)hash, 512 );
#else
   sph_groestl512_init(&ctx.groestl );
   sph_groestl512(&ctx.groestl, hash, 64);
   sph_groestl512_close(&ctx.groestl, hash);
#endif

   sph_skein512_init( &ctx.skein);
   sph_skein512(&ctx.skein, hash, 64);
   sph_skein512_close(&ctx.skein, hash);

   sph_jh512_init( &ctx.jh);
   sph_jh512(&ctx.jh, hash, 64);
   sph_jh512_close(&ctx.jh, hash);

   sph_keccak512_init( &ctx.keccak );
   sph_keccak512(&ctx.keccak, hash, 64);
   sph_keccak512_close(&ctx.keccak, hash);

   init_luffa( &ctx.luffa, 512 );
   update_and_final_luffa( &ctx.luffa, (BitSequence*)hash,
                                (const BitSequence*)hash, 64 );

   cubehashInit( &ctx.cubehash, 512, 16, 32 );
   cubehashUpdateDigest( &ctx.cubehash, (byte*) hash,
                              (const byte*)hash, 64 );

   sph_shavite512_init( &ctx.shavite );
   sph_shavite512(&ctx.shavite, hash, 64);
   sph_shavite512_close(&ctx.shavite, hash);

   init_sd( &ctx.simd, 512 );
   update_final_sd( &ctx.simd, (BitSequence *)hash,
                         (const BitSequence *)hash, 512 );

#if defined(__AES__)
   init_echo( &ctx.echo, 512 );
   update_final_echo ( &ctx.echo, (BitSequence *)hash,
                            (const BitSequence *)hash, 512 );
#else
   sph_echo512_init( &ctx.echo );
   sph_echo512(&ctx.echo, hash, 64);
   sph_echo512_close(&ctx.echo, hash);
#endif

   sph_hamsi512_init( &ctx.hamsi );
   sph_hamsi512(&ctx.hamsi, hash, 64);
   sph_hamsi512_close(&ctx.hamsi, hash);

#if defined(__AES__)
    fugue512_full( &ctx.fugue, hash, hash, 64 );
#else
    sph_fugue512_full( &ctx.fugue, hash, hash, 64 );
#endif

   sph_shabal512_init( &ctx.shabal );
   sph_shabal512(&ctx.shabal, hash, 64);
   sph_shabal512_close(&ctx.shabal, hash);

   sph_whirlpool(&ctx.whirlpool, hash, 64);
   sph_whirlpool_close(&ctx.whirlpool, hash);

   if ( work_restart[thr_id].restart ) return 0;
//
   sph_bmw512_init( &ctx.bmw);
   sph_bmw512(&ctx.bmw, hash, 64);
   sph_bmw512_close(&ctx.bmw, hash);

#if defined(__AES__)
   init_groestl( &ctx.groestl, 64 );
   update_and_final_groestl( &ctx.groestl, (char*)hash,
                                  (const char*)hash, 512 );
#else
   sph_groestl512_init(&ctx.groestl );
   sph_groestl512(&ctx.groestl, hash, 64);
   sph_groestl512_close(&ctx.groestl, hash);
#endif

   sph_skein512_init( &ctx.skein);
   sph_skein512(&ctx.skein, hash, 64);
   sph_skein512_close(&ctx.skein, hash);

   sph_jh512_init( &ctx.jh);
   sph_jh512(&ctx.jh, hash, 64);
   sph_jh512_close(&ctx.jh, hash);

   sph_keccak512_init( &ctx.keccak );
   sph_keccak512(&ctx.keccak, hash, 64);
   sph_keccak512_close(&ctx.keccak, hash);

   init_luffa( &ctx.luffa, 512 );
   update_and_final_luffa( &ctx.luffa, (BitSequence*)hash,
                                (const BitSequence*)hash, 64 );

   cubehashInit( &ctx.cubehash, 512, 16, 32 );
   cubehashUpdateDigest( &ctx.cubehash, (byte*) hash,
                              (const byte*)hash, 64 );

   sph_shavite512_init( &ctx.shavite );
   sph_shavite512(&ctx.shavite, hash, 64);
   sph_shavite512_close(&ctx.shavite, hash);

   init_sd( &ctx.simd, 512 );
   update_final_sd( &ctx.simd, (BitSequence *)hash,
                         (const BitSequence *)hash, 512 );

#if defined(__AES__)
   init_echo( &ctx.echo, 512 );
   update_final_echo ( &ctx.echo, (BitSequence *)hash,
                            (const BitSequence *)hash, 512 );
#else
   sph_echo512_init( &ctx.echo );
   sph_echo512(&ctx.echo, hash, 64);
   sph_echo512_close(&ctx.echo, hash);
#endif

   sph_hamsi512_init( &ctx.hamsi );
   sph_hamsi512(&ctx.hamsi, hash, 64);
   sph_hamsi512_close(&ctx.hamsi, hash);

#if defined(__AES__)
    fugue512_full( &ctx.fugue, hash, hash, 64 );
#else
    sph_fugue512_full( &ctx.fugue, hash, hash, 64 );
#endif

   sph_shabal512_init( &ctx.shabal );
   sph_shabal512(&ctx.shabal, hash, 64);
   sph_shabal512_close(&ctx.shabal, hash);

   sph_whirlpool_init( &ctx.whirlpool );
   sph_whirlpool(&ctx.whirlpool, hash, 64);
   sph_whirlpool_close(&ctx.whirlpool, hash);

   sph_sha512( &ctx.sha512, hash, 64 );
   sph_sha512_close( &ctx.sha512, hash );

   sph_whirlpool_init( &ctx.whirlpool );
   sph_whirlpool(&ctx.whirlpool, hash, 64);
   sph_whirlpool_close(&ctx.whirlpool, hash);

   if ( work_restart[thr_id].restart ) return 0;
//

   sph_bmw512_init( &ctx.bmw);
   sph_bmw512(&ctx.bmw, hash, 64);
   sph_bmw512_close(&ctx.bmw, hash);

#if defined(__AES__)
   init_groestl( &ctx.groestl, 64 );
   update_and_final_groestl( &ctx.groestl, (char*)hash,
                                  (const char*)hash, 512 );
#else
   sph_groestl512_init(&ctx.groestl );
   sph_groestl512(&ctx.groestl, hash, 64);
   sph_groestl512_close(&ctx.groestl, hash);
#endif

   sph_skein512_init( &ctx.skein);
   sph_skein512(&ctx.skein, hash, 64);
   sph_skein512_close(&ctx.skein, hash);

   sph_jh512_init( &ctx.jh);
   sph_jh512(&ctx.jh, hash, 64);
   sph_jh512_close(&ctx.jh, hash);

   sph_keccak512_init( &ctx.keccak );
   sph_keccak512(&ctx.keccak, hash, 64);
   sph_keccak512_close(&ctx.keccak, hash);

   init_luffa( &ctx.luffa, 512 );
   update_and_final_luffa( &ctx.luffa, (BitSequence*)hash,
                                (const BitSequence*)hash, 64 );

   cubehashInit( &ctx.cubehash, 512, 16, 32 );
   cubehashUpdateDigest( &ctx.cubehash, (byte*) hash,
                              (const byte*)hash, 64 );

   sph_shavite512_init( &ctx.shavite );
   sph_shavite512(&ctx.shavite, hash, 64);
   sph_shavite512_close(&ctx.shavite, hash);

   init_sd( &ctx.simd, 512 );
   update_final_sd( &ctx.simd, (BitSequence *)hash,
                         (const BitSequence *)hash, 512 );

#if defined(__AES__)
   init_echo( &ctx.echo, 512 );
   update_final_echo ( &ctx.echo, (BitSequence *)hash,
                            (const BitSequence *)hash, 512 );
#else
   sph_echo512_init( &ctx.echo );
   sph_echo512(&ctx.echo, hash, 64);
   sph_echo512_close(&ctx.echo, hash);
#endif

   sph_hamsi512_init( &ctx.hamsi );
   sph_hamsi512(&ctx.hamsi, hash, 64);
   sph_hamsi512_close(&ctx.hamsi, hash);

#if defined(__AES__)
    fugue512_full( &ctx.fugue, hash, hash, 64 );
#else
    sph_fugue512_full( &ctx.fugue, hash, hash, 64 );
#endif

   sph_shabal512_init( &ctx.shabal );
   sph_shabal512(&ctx.shabal, hash, 64);
   sph_shabal512_close(&ctx.shabal, hash);

   sph_whirlpool_init( &ctx.whirlpool );
   sph_whirlpool(&ctx.whirlpool, hash, 64);
   sph_whirlpool_close(&ctx.whirlpool, hash);

   sph_sha512_init( &ctx.sha512 );
   sph_sha512( &ctx.sha512, hash, 64 );
   sph_sha512_close( &ctx.sha512, hash );

   sph_haval256_5(&ctx.haval,(const void*) hash, 64);
   sph_haval256_5_close(&ctx.haval, hash);

   memcpy(state, hash, 32);
   return 1;
}

#endif
