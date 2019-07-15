/**
 * Phi-2 algo Implementation
 */

#include "lyra2-gate.h"

#if defined(PHI2_4WAY)

#include "algo/skein/skein-hash-4way.h"
#include "algo/jh/jh-hash-4way.h"
#include "algo/gost/sph_gost.h"
#include "algo/cubehash/cubehash_sse2.h"
#include "algo/echo/aes_ni/hash_api.h"

typedef struct {
     cubehashParam           cube;
     jh512_4way_context      jh;
     hashState_echo          echo;
//     hashState_echo          echo2;
     sph_gost512_context     gost;
     skein512_4way_context   skein;
} phi2_ctx_holder;
/*
phi2_ctx_holder phi2_ctx;

void init_phi2_ctx()
{
   cubehashInit( &phi2_ctx.cube, 512, 16, 32 );
   sph_jh512_init(&phi2_ctx.jh);
   init_echo( &phi2_ctx.echo1, 512 );
   init_echo( &phi2_ctx.echo2, 512 );
   sph_gost512_init(&phi2_ctx.gost);
   sph_skein512_init(&phi2_ctx.skein);
};
*/
void phi2_hash_4way( void *state, const void *input )
{
   uint32_t hash[4][16] __attribute__ ((aligned (64)));
   uint32_t hashA[4][16] __attribute__ ((aligned (64)));
   uint32_t hashB[4][16] __attribute__ ((aligned (64)));
   uint32_t vhash[4*16] __attribute__ ((aligned (64)));

//   unsigned char _ALIGN(128) hash[64];
//	unsigned char _ALIGN(128) hashA[64];
//	unsigned char _ALIGN(128) hashB[64];

   phi2_ctx_holder ctx __attribute__ ((aligned (64)));
//  memcpy( &ctx, &phi2_ctx, sizeof(phi2_ctx) );

   cubehashInit( &ctx.cube, 512, 16, 32 );
   cubehashUpdateDigest( &ctx.cube, (byte*)hashB[0], (const byte*)input,
                        phi2_has_roots ? 144 : 80 );
   cubehashInit( &ctx.cube, 512, 16, 32 );
   cubehashUpdateDigest( &ctx.cube, (byte*)hashB[1], (const byte*)input+144,
                        phi2_has_roots ? 144 : 80 );
   cubehashInit( &ctx.cube, 512, 16, 32 );
   cubehashUpdateDigest( &ctx.cube, (byte*)hashB[2], (const byte*)input+288,
                        phi2_has_roots ? 144 : 80 );
   cubehashInit( &ctx.cube, 512, 16, 32 );
   cubehashUpdateDigest( &ctx.cube, (byte*)hashB[3], (const byte*)input+432,
                        phi2_has_roots ? 144 : 80 );

	LYRA2RE( &hashA[0][0], 32, &hashB[0][0], 32, &hashB[0][0], 32, 1, 8, 8 );
	LYRA2RE( &hashA[0][8], 32, &hashB[0][8], 32, &hashB[0][8], 32, 1, 8, 8 );
   LYRA2RE( &hashA[1][0], 32, &hashB[1][0], 32, &hashB[1][0], 32, 1, 8, 8 );
   LYRA2RE( &hashA[1][8], 32, &hashB[1][8], 32, &hashB[1][8], 32, 1, 8, 8 );
   LYRA2RE( &hashA[2][0], 32, &hashB[2][0], 32, &hashB[2][0], 32, 1, 8, 8 );
   LYRA2RE( &hashA[2][8], 32, &hashB[2][8], 32, &hashB[2][8], 32, 1, 8, 8 );
   LYRA2RE( &hashA[3][0], 32, &hashB[3][0], 32, &hashB[3][0], 32, 1, 8, 8 );
   LYRA2RE( &hashA[3][8], 32, &hashB[3][8], 32, &hashB[3][8], 32, 1, 8, 8 );

   intrlv_4x64( vhash, hashA[0], hashA[1], hashA[2], hashA[3], 512 );

   jh512_4way_init( &ctx.jh );
   jh512_4way( &ctx.jh, vhash, 64 );
   jh512_4way_close( &ctx.jh, vhash );

   dintrlv_4x64( hash[0], hash[1], hash[2], hash[3], vhash, 512 );

   if ( hash[0][0] & 1 )
  	{
      sph_gost512_init( &ctx.gost );
      sph_gost512( &ctx.gost, (const void*)hash[0], 64 );
	   sph_gost512_close( &ctx.gost, (void*)hash[0] );
	}
  	else
  	{
      init_echo( &ctx.echo, 512 );
      update_final_echo ( &ctx.echo, (BitSequence *)hash[0],
                          (const BitSequence *)hash[0], 512 );
      init_echo( &ctx.echo, 512 );
      update_final_echo ( &ctx.echo, (BitSequence *)hash[0],
                          (const BitSequence *)hash[0], 512 );
	}

   if ( hash[1][0] & 1 )
   {
      sph_gost512_init( &ctx.gost );
      sph_gost512( &ctx.gost, (const void*)hash[1], 64 );
      sph_gost512_close( &ctx.gost, (void*)hash[1] );
   }
   else
   {
      init_echo( &ctx.echo, 512 );
      update_final_echo ( &ctx.echo, (BitSequence *)hash[1],
                          (const BitSequence *)hash[1], 512 );
      init_echo( &ctx.echo, 512 );
      update_final_echo ( &ctx.echo, (BitSequence *)hash[1],
                          (const BitSequence *)hash[1], 512 );
   }

   if ( hash[2][0] & 1 )
   {
      sph_gost512_init( &ctx.gost );
      sph_gost512( &ctx.gost, (const void*)hash[2], 64 );
      sph_gost512_close( &ctx.gost, (void*)hash[2] );
   }
   else
   {
      init_echo( &ctx.echo, 512 );
      update_final_echo ( &ctx.echo, (BitSequence *)hash[2],
                          (const BitSequence *)hash[2], 512 );
      init_echo( &ctx.echo, 512 );
      update_final_echo ( &ctx.echo, (BitSequence *)hash[2],
                          (const BitSequence *)hash[2], 512 );
   }

   if ( hash[3][0] & 1 )
   {
      sph_gost512_init( &ctx.gost );
      sph_gost512( &ctx.gost, (const void*)hash[3], 64 );
      sph_gost512_close( &ctx.gost, (void*)hash[3] );
   }
   else
   {
      init_echo( &ctx.echo, 512 );
      update_final_echo ( &ctx.echo, (BitSequence *)hash[3],
                          (const BitSequence *)hash[3], 512 );
      init_echo( &ctx.echo, 512 );
      update_final_echo ( &ctx.echo, (BitSequence *)hash[3],
                          (const BitSequence *)hash[3], 512 );
   }

   intrlv_4x64( vhash, hash[0], hash[1], hash[2], hash[3], 512 );
   
   skein512_4way_init( &ctx.skein );
	skein512_4way( &ctx.skein, vhash, 64 );
	skein512_4way_close( &ctx.skein, vhash );

   for (int i=0; i<4; i++)
   {
      ( (uint64_t*)vhash    )[i] ^= ( (uint64_t*)vhash    )[i+4];
      ( (uint64_t*)vhash+ 8 )[i] ^= ( (uint64_t*)vhash+ 8 )[i+4];
      ( (uint64_t*)vhash+16 )[i] ^= ( (uint64_t*)vhash+16 )[i+4];
      ( (uint64_t*)vhash+24 )[i] ^= ( (uint64_t*)vhash+24 )[i+4];
   }
//   for ( int i = 0; i < 4; i++ )
//      casti_m256i( vhash, i ) = _mm256_xor_si256( casti_m256i( vhash, i   ),
//                                                  casti_m256i( vhash, i+4 ) );

	memcpy( state, vhash, 128 );
}

int scanhash_phi2_4way( struct work *work, uint32_t max_nonce,
	                     uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t _ALIGN(128) hash[8];
   uint32_t _ALIGN(128) edata[36];
   uint32_t vdata[4][36] __attribute__ ((aligned (64)));
   uint32_t *hash7 = &(hash[25]);
   uint32_t lane_hash[8] __attribute__ ((aligned (32)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t Htarg = ptarget[7];
   const uint32_t first_nonce = pdata[19];
   uint32_t n = first_nonce;
   int thr_id = mythr->id;  // thr_id arg is deprecated

   if(opt_benchmark){
   	ptarget[7] = 0x00ff;
   }

// Data is not interleaved, but hash is.
// any non-zero data at index 20 or above sets roots true.
// Split up the operations, bswap first, then set roots.

   phi2_has_roots = false;
   for ( int i=0; i < 36; i++ )
   {
   be32enc(&edata[i], pdata[i]);
   if (i >= 20 && pdata[i]) phi2_has_roots = true;
   }
/*
   casti_m256i( vdata[0], 0 ) = mm256_bswap_32( casti_m256i( pdata, 0 ) );   
   casti_m256i( vdata[0], 1 ) = mm256_bswap_32( casti_m256i( pdata, 1 ) );
   casti_m256i( vdata[0], 2 ) = mm256_bswap_32( casti_m256i( pdata, 2 ) );
   casti_m256i( vdata[0], 3 ) = mm256_bswap_32( casti_m256i( pdata, 3 ) );
   casti_m128i( vdata[0], 8 ) = mm128_bswap_32( casti_m128i( pdata, 8 ) );
   phi2_has_roots = mm128_anybits1( casti_m128i( vdata[0], 5 ) ) ||
                    mm128_anybits1( casti_m128i( vdata[0], 6 ) ) ||
                    mm128_anybits1( casti_m128i( vdata[0], 7 ) ) ||
                    mm128_anybits1( casti_m128i( vdata[0], 8 ) );
*/   

   memcpy( vdata[0], edata, 144 );
   memcpy( vdata[1], edata, 144 );
   memcpy( vdata[2], edata, 144 );
   memcpy( vdata[3], edata, 144 );

   do {
      be32enc( &vdata[0][19], n );
      be32enc( &vdata[1][19], n+1 );
      be32enc( &vdata[2][19], n+2 );
      be32enc( &vdata[3][19], n+3 );

      phi2_hash_4way( hash, vdata );

      for ( int lane = 0; lane < 4; lane++ ) if (  hash7[ lane<<1 ] < Htarg )
      {
          extr_lane_4x64( lane_hash, hash, lane, 256 );
          if ( fulltest( lane_hash, ptarget ) && !opt_benchmark )
          {
              pdata[19] = n + lane;
              submit_lane_solution( work, lane_hash, mythr, lane );
          }
       }
       n += 4;
    } while ( ( n < max_nonce - 4 ) && !work_restart[thr_id].restart );
    *hashes_done = n - first_nonce + 1;
    return 0;
}
   
#endif  // PHI2_4WAY
