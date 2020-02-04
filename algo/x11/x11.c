#include "cpuminer-config.h"
#include "x11-gate.h"

#if !defined(X11_8WAY) && !defined(X11_4WAY)

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
#include "algo/cubehash/cubehash_sse2.h"
#include "algo/simd/nist.h"

#if defined(__AES__)
  #include "algo/echo/aes_ni/hash_api.h"
  #include "algo/groestl/aes_ni/hash-groestl.h"
#else
  #include "algo/groestl/sph_groestl.h"
  #include "algo/echo/sph_echo.h"
#endif

typedef struct {
   sph_blake512_context blake;
   sph_bmw512_context bmw;
#if defined(__AES__)
   hashState_echo          echo;
   hashState_groestl       groestl;
#else
   sph_groestl512_context   groestl;
   sph_echo512_context      echo;
#endif
   sph_jh512_context       jh;
   sph_keccak512_context   keccak;
   sph_skein512_context    skein;
   hashState_luffa         luffa;
   cubehashParam           cube;
   sph_shavite512_context  shavite;
   hashState_sd            simd;
} x11_ctx_holder;

x11_ctx_holder x11_ctx;

void init_x11_ctx()
{
   sph_blake512_init( &x11_ctx.blake );
   sph_bmw512_init( &x11_ctx.bmw );
#if defined(__AES__)
   init_groestl( &x11_ctx.groestl, 64 );
   init_echo( &x11_ctx.echo, 512 );
#else
   sph_groestl512_init( &x11_ctx.groestl );
   sph_echo512_init( &x11_ctx.echo );
#endif
   sph_skein512_init( &x11_ctx.skein );
   sph_jh512_init( &x11_ctx.jh );
   sph_keccak512_init( &x11_ctx.keccak );
   init_luffa( &x11_ctx.luffa, 512 );
   cubehashInit( &x11_ctx.cube, 512, 16, 32 );
   sph_shavite512_init( &x11_ctx.shavite );
   init_sd( &x11_ctx.simd, 512 );
}

void x11_hash( void *state, const void *input )
{
    unsigned char hash[64] __attribute__((aligned(64)));
    x11_ctx_holder ctx;
    memcpy( &ctx, &x11_ctx, sizeof(x11_ctx) );

    sph_blake512( &ctx.blake, input, 80 );
    sph_blake512_close( &ctx.blake, hash );

    sph_bmw512( &ctx.bmw, (const void*) hash, 64 );
    sph_bmw512_close( &ctx.bmw, hash );

#if defined(__AES__)
    init_groestl( &ctx.groestl, 64 );
    update_and_final_groestl( &ctx.groestl, (char*)hash,
                                      (const char*)hash, 512 );
#else
    sph_groestl512_init( &ctx.groestl );
    sph_groestl512( &ctx.groestl, hash, 64 );
    sph_groestl512_close( &ctx.groestl, hash );
#endif

    sph_skein512( &ctx.skein, (const void*) hash, 64 );
    sph_skein512_close( &ctx.skein, hash );

    sph_jh512( &ctx.jh, (const void*) hash, 64 );
    sph_jh512_close( &ctx.jh, hash );

    sph_keccak512( &ctx.keccak, (const void*) hash, 64 );
    sph_keccak512_close( &ctx.keccak, hash );

     update_luffa( &ctx.luffa, (const BitSequence*)hash, 64 );
     final_luffa( &ctx.luffa, (BitSequence*)hash );

     cubehashUpdate( &ctx.cube, (const byte*) hash, 64 );
     cubehashDigest( &ctx.cube, (byte*)hash );

     sph_shavite512( &ctx.shavite, hash, 64 );
     sph_shavite512_close( &ctx.shavite, hash );

     update_sd( &ctx.simd, (const BitSequence *)hash, 512 );
     final_sd( &ctx.simd, (BitSequence *)hash );

#if defined(__AES__)
    update_final_echo ( &ctx.echo, (BitSequence *)hash,
                            (const BitSequence *)hash, 512 );
#else
    sph_echo512( &ctx.echo, hash, 64 );
    sph_echo512_close( &ctx.echo, hash );
#endif

     memcpy( state, hash, 32 );
}

int scanhash_x11( struct work *work, uint32_t max_nonce,
                  uint64_t *hashes_done, struct thr_info *mythr )
{
        uint32_t endiandata[20] __attribute__((aligned(64)));
        uint32_t hash64[8] __attribute__((aligned(64)));
        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;
	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];
   int thr_id = mythr->id;
	const uint32_t Htarg = ptarget[7];
        uint64_t htmax[] = {
                0,
                0xF,
                0xFF,
                0xFFF,
                0xFFFF,
                0x10000000
        };
        uint32_t masks[] = {
                0xFFFFFFFF,
                0xFFFFFFF0,
                0xFFFFFF00,
                0xFFFFF000,
                0xFFFF0000,
                0
        };

        // big endian encode 0..18 uint32_t, 64 bits at a time
        swab32_array( endiandata, pdata, 20 );

        for (int m=0; m < 6; m++) 
          if (Htarg <= htmax[m])
          {
            uint32_t mask = masks[m];
            do
            {
              pdata[19] = ++n;
              be32enc( &endiandata[19], n );
              x11_hash( hash64, &endiandata );
              if ( ( hash64[7] & mask ) == 0 )
              {
                 if ( fulltest( hash64, ptarget ) )
                    submit_solution( work, hash64, mythr );
              }
            } while ( n < max_nonce && !work_restart[thr_id].restart );
          }

        *hashes_done = n - first_nonce + 1;
        pdata[19] = n;
        return 0;
}
#endif
