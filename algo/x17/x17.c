#include "x17-gate.h"

#if !defined(X17_8WAY) && !defined(X17_4WAY)

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
#include "algo/hamsi/sph_hamsi.h"
#include "algo/shabal/sph_shabal.h"
#include "algo/whirlpool/sph_whirlpool.h"
#include "algo/haval/sph-haval.h"
#include "algo/luffa/luffa_for_sse2.h" 
#include "algo/cubehash/cubehash_sse2.h"
#include "algo/simd/nist.h"
#include "algo/sha/sph_sha2.h"
#if defined(__AES__)
  #include "algo/fugue/fugue-aesni.h"
  #include "algo/echo/aes_ni/hash_api.h"
  #include "algo/groestl/aes_ni/hash-groestl.h"
#else
  #include "algo/groestl/sph_groestl.h"
  #include "algo/echo/sph_echo.h"
  #include "algo/fugue/sph_fugue.h"
#endif

union _x17_context_overlay
{
        sph_blake512_context blake;
        sph_bmw512_context bmw;
#if defined(__AES__)
        hashState_groestl       groestl;
        hashState_echo          echo;
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
        cubehashParam           cube;
        sph_shavite512_context  shavite;
        hashState_sd            simd;
        sph_hamsi512_context    hamsi;
        sph_shabal512_context   shabal;
        sph_whirlpool_context   whirlpool;
        sph_sha512_context      sha512;
        sph_haval256_5_context  haval;
};
typedef union _x17_context_overlay x17_context_overlay;

int x17_hash(void *output, const void *input, int thr_id )
{
//    unsigned char hash[64 * 4] __attribute__((aligned(64))) = {0};
    unsigned char hash[64] __attribute__((aligned(64)));
    x17_context_overlay ctx;

    sph_blake512_init(&ctx.blake);
    sph_blake512(&ctx.blake, input, 80);
    sph_blake512_close(&ctx.blake, hash);

    sph_bmw512_init(&ctx.bmw);
    sph_bmw512(&ctx.bmw, (const void*) hash, 64);
    sph_bmw512_close(&ctx.bmw, hash);

#if defined(__AES__)
    groestl512_full( &ctx.groestl, (char*)hash, (const char*)hash, 512 );
#else
    sph_groestl512_init( &ctx.groestl );
    sph_groestl512( &ctx.groestl, hash, 64 );
    sph_groestl512_close( &ctx.groestl, hash );
#endif

    sph_skein512_init(&ctx.skein);
    sph_skein512(&ctx.skein, (const void*) hash, 64);
    sph_skein512_close(&ctx.skein, hash);

    sph_jh512_init(&ctx.jh);
    sph_jh512(&ctx.jh, (const void*) hash, 64);
    sph_jh512_close(&ctx.jh, hash);

    sph_keccak512_init(&ctx.keccak);
    sph_keccak512(&ctx.keccak, (const void*) hash, 64);
    sph_keccak512_close(&ctx.keccak, hash);

    luffa_full( &ctx.luffa, (BitSequence*)hash, 512,
                            (const BitSequence*)hash, 64 );

    // 8 Cube
    cubehash_full( &ctx.cube, (byte*) hash, 512, (const byte*)hash, 64 );

    // 9 Shavite
    sph_shavite512_init( &ctx.shavite );
    sph_shavite512( &ctx.shavite, hash, 64);
    sph_shavite512_close( &ctx.shavite, hash);

    // 10 Simd
    simd_full( &ctx.simd, (BitSequence*)hash,
                          (const BitSequence*)hash, 512 );

    //11---echo---
#if defined(__AES__)
    echo_full( &ctx.echo, (BitSequence *)hash, 512,
                    (const BitSequence *)hash, 64 );
#else
    sph_echo512_init( &ctx.echo );
    sph_echo512( &ctx.echo, hash, 64 );
    sph_echo512_close( &ctx.echo, hash );
#endif

    // X13 algos
    // 12 Hamsi
    sph_hamsi512_init( &ctx.hamsi );
    sph_hamsi512( &ctx.hamsi, hash, 64 );
    sph_hamsi512_close( &ctx.hamsi, hash );

    // 13 Fugue
#if defined(__AES__)
    fugue512_full( &ctx.fugue, hash, hash, 64 );
#else
    sph_fugue512_full( &ctx.fugue, hash, hash, 64 );
#endif

    // X14 Shabal
    sph_shabal512_init( &ctx.shabal );
    sph_shabal512(&ctx.shabal, hash, 64);
    sph_shabal512_close( &ctx.shabal, hash );
       
    // X15 Whirlpool
    sph_whirlpool_init( &ctx.whirlpool );
    sph_whirlpool( &ctx.whirlpool, hash, 64 );
    sph_whirlpool_close( &ctx.whirlpool, hash );

    sph_sha512_init( &ctx.sha512 );
    sph_sha512( &ctx.sha512, hash, 64 );
    sph_sha512_close( &ctx.sha512, hash );

    sph_haval256_5_init(&ctx.haval);
    sph_haval256_5( &ctx.haval, (const void*)hash, 64 );
    sph_haval256_5_close( &ctx.haval, output );

    return 1;
}

#endif

