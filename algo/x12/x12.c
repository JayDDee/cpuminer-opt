#include "x12-gate.h"

#if !defined(X12_8WAY) && !defined(X12_4WAY)

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "algo/groestl/sph_groestl.h"
#include "algo/blake/sph_blake.h"
#include "algo/bmw/sph_bmw.h"
#include "algo/jh/sph_jh.h"
#include "algo/keccak/sph_keccak.h"
#include "algo/skein/sph_skein.h"
#include "algo/shavite/sph_shavite.h"
#include "algo/echo/sph_echo.h"
#include "algo/hamsi/sph_hamsi.h"
#include "algo/luffa/luffa_for_sse2.h" 
#include "algo/cubehash/cubehash_sse2.h"
#include "algo/simd/nist.h"
#if defined(__AES__)
  #include "algo/groestl/aes_ni/hash-groestl.h"
  #include "algo/echo/aes_ni/hash_api.h"
#endif

typedef struct {
   sph_blake512_context    blake;
   sph_bmw512_context      bmw;
   sph_skein512_context    skein;
   sph_jh512_context       jh;
   sph_keccak512_context   keccak;
#if defined(__AES__)
   hashState_groestl       groestl;
   hashState_echo          echo;
#else
   sph_groestl512_context   groestl;
   sph_echo512_context      echo;
#endif
   hashState_luffa          luffa;
   cubehashParam            cubehash;
   sph_shavite512_context   shavite;
   hashState_sd             simd;
   sph_hamsi512_context     hamsi;
} x12_ctx_holder;

x12_ctx_holder x12_ctx;

void init_x12_ctx()
{
        sph_blake512_init( &x12_ctx.blake );
        sph_bmw512_init( &x12_ctx.bmw );
        sph_skein512_init( &x12_ctx.skein);
        sph_jh512_init( &x12_ctx.jh);
        sph_keccak512_init( &x12_ctx.keccak);
#if defined(__AES__)
        init_echo( &x12_ctx.echo, 512 );
        init_groestl (&x12_ctx.groestl, 64 );
#else
        sph_groestl512_init(&x12_ctx.groestl);
        sph_echo512_init(&x12_ctx.echo);
#endif
        init_luffa( &x12_ctx.luffa, 512 );
        cubehashInit( &x12_ctx.cubehash, 512, 16, 32 );
        sph_shavite512_init( &x12_ctx.shavite );
        init_sd( &x12_ctx.simd, 512 );
        sph_hamsi512_init( &x12_ctx.hamsi );
};

void x12hash(void *output, const void *input)
{

	unsigned char hash[128] __attribute__ ((aligned (32)));
	#define hashB hash+64
      
   x12_ctx_holder ctx;
   memcpy( &ctx, &x12_ctx, sizeof(x12_ctx) );

   sph_blake512(&ctx.blake, input, 80);
   sph_blake512_close(&ctx.blake, hash);

   sph_bmw512(&ctx.bmw, hash, 64);
   sph_bmw512_close(&ctx.bmw, hash);

   update_and_final_luffa( &ctx.luffa, (BitSequence*)hashB,
                           (const BitSequence*)hash, 64 );

   cubehashUpdateDigest( &ctx.cubehash, (byte*) hash,
                         (const byte*)hashB, 64 );

   sph_shavite512( &ctx.shavite, hash, 64);
   sph_shavite512_close( &ctx.shavite, hashB);

   update_final_sd( &ctx.simd, (BitSequence *)hash,
                    (const BitSequence *)hashB, 512 );

#if defined(__AES__)
   update_final_echo ( &ctx.echo, (BitSequence *)hashB,
                            (const BitSequence *)hash, 512 );
#else
   sph_echo512(&ctx.echo, hash, 64);
   sph_echo512_close(&ctx.echo, hashB);
#endif

#if defined(__AES__)
   update_and_final_groestl( &ctx.groestl, (char*)hash,
                                  (const char*)hash, 512 );
#else
   sph_groestl512 (&ctx.groestl, hash, 64);
   sph_groestl512_close(&ctx.groestl, hash);
#endif

   sph_skein512(&ctx.skein, hash, 64);
   sph_skein512_close(&ctx.skein, hash);

   sph_jh512(&ctx.jh, hash, 64);
   sph_jh512_close(&ctx.jh, hash);

   sph_keccak512(&ctx.keccak, hash, 64);
   sph_keccak512_close(&ctx.keccak, hash);

	sph_hamsi512(&ctx.hamsi, hashB, 64);
	sph_hamsi512_close(&ctx.hamsi, hash);

	memcpy(output, hashB, 32);
}

int scanhash_x12( struct work *work, uint32_t max_nonce,
                               uint64_t *hashes_done, struct thr_info *mythr )
{
        uint32_t endiandata[20] __attribute__((aligned(64)));
        uint32_t hash64[8] __attribute__((aligned(64)));
        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;
	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];
   int thr_id = mythr->id;  // thr_id arg is deprecated
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

	// we need bigendian data...
        swab32_array( endiandata, pdata, 20 );

   for (int m=0; m < 6; m++) {
      if (Htarg <= htmax[m]) {
        uint32_t mask = masks[m];
	do {
	   pdata[19] = ++n;
	   be32enc(&endiandata[19], n);
	   x12hash(hash64, endiandata);
	   if (!(hash64[7] & mask))
      if ( fulltest(hash64, ptarget) )
         submit_solution( work, hash64, mythr );
	} while (n < max_nonce && !work_restart[thr_id].restart);
	break;
     }
  }

  *hashes_done = n - first_nonce + 1;
  pdata[19] = n;
  return 0;
}
#endif
