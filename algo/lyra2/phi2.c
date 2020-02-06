/**
 * Phi-2 algo Implementation
 */

#include "lyra2-gate.h"
#include "algo/skein/sph_skein.h"
#include "algo/jh/sph_jh.h"
#include "algo/gost/sph_gost.h"
#include "algo/cubehash/cubehash_sse2.h"
#ifdef __AES__
  #include "algo/echo/aes_ni/hash_api.h"
#else
  #include "algo/echo/sph_echo.h"
#endif

typedef struct {
     cubehashParam           cube;
     sph_jh512_context       jh;
#if  defined(__AES__)
     hashState_echo          echo1;
     hashState_echo          echo2;
#else
     sph_echo512_context     echo1;
     sph_echo512_context     echo2;
#endif
     sph_gost512_context     gost;
     sph_skein512_context    skein;
} phi2_ctx_holder;

phi2_ctx_holder phi2_ctx;

void init_phi2_ctx()
{
   cubehashInit( &phi2_ctx.cube, 512, 16, 32 );
   sph_jh512_init(&phi2_ctx.jh);
#if defined(__AES__)
   init_echo( &phi2_ctx.echo1, 512 );
   init_echo( &phi2_ctx.echo2, 512 );
#else
   sph_echo512_init(&phi2_ctx.echo1);
   sph_echo512_init(&phi2_ctx.echo2);
#endif
   sph_gost512_init(&phi2_ctx.gost);
   sph_skein512_init(&phi2_ctx.skein);
};

void phi2_hash(void *state, const void *input)
{
	unsigned char _ALIGN(128) hash[64];
	unsigned char _ALIGN(128) hashA[64];
	unsigned char _ALIGN(128) hashB[64];

  phi2_ctx_holder ctx __attribute__ ((aligned (64)));
  memcpy( &ctx, &phi2_ctx, sizeof(phi2_ctx) );

  cubehashUpdateDigest( &ctx.cube, (byte*)hashB, (const byte*)input,
                        phi2_has_roots ? 144 : 80 );

	LYRA2RE( &hashA[ 0], 32, &hashB[ 0], 32, &hashB[ 0], 32, 1, 8, 8 );
	LYRA2RE( &hashA[32], 32, &hashB[32], 32, &hashB[32], 32, 1, 8, 8 );

	sph_jh512( &ctx.jh, (const void*)hashA, 64 );
	sph_jh512_close( &ctx.jh, (void*)hash );

	if ( hash[0] & 1 )
  	{
      sph_gost512( &ctx.gost, (const void*)hash, 64 );
	   sph_gost512_close( &ctx.gost, (void*)hash );
	}
  	else
  	{
#if defined(__AES__)
      update_final_echo ( &ctx.echo1, (BitSequence *)hash,
                          (const BitSequence *)hash, 512 );
      update_final_echo ( &ctx.echo2, (BitSequence *)hash,
                          (const BitSequence *)hash, 512 );
#else
	   sph_echo512( &ctx.echo1, (const void*)hash, 64 );
	   sph_echo512_close( &ctx.echo1, (void*)hash );

	   sph_echo512( &ctx.echo2, (const void*)hash, 64 );
	   sph_echo512_close( &ctx.echo2, (void*)hash );
#endif
	}

	sph_skein512( &ctx.skein, (const void*)hash, 64 );
	sph_skein512_close( &ctx.skein, (void*)hash );

	for (int i=0; i<4; i++)
		((uint64_t*)hash)[i] ^= ((uint64_t*)hash)[i+4];

	memcpy(state, hash, 32);
}

int scanhash_phi2( struct work *work, uint32_t max_nonce,
	           uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t _ALIGN(128) hash[8];
   uint32_t _ALIGN(128) edata[36];
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;
   const bool bench = opt_benchmark;
   if( bench )   	ptarget[7] = 0x00ff;

   phi2_has_roots = false;

   for ( int i = 0; i < 36; i++ )
   {
	   be32enc( &edata[i], pdata[i] );
      if ( i >= 20 && pdata[i] ) phi2_has_roots = true;
   }

   do {
	edata[19] = n;
	phi2_hash( hash, edata );
   if ( valid_hash( hash, ptarget ) && !opt_benchmark )
  	{
       be32enc( pdata+19, n );
       submit_solution( work, hash, mythr );
   }
	n++;
   } while ( n < max_nonce && !work_restart[thr_id].restart );
   *hashes_done = n - first_nonce + 1;
   pdata[19] = n;
   return 0;
}
