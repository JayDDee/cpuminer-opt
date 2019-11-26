#include "x22i-gate.h"

#if defined(X22I_4WAY)

#include "algo/blake/blake-hash-4way.h"
#include "algo/bmw/bmw-hash-4way.h"
#include "algo/skein/skein-hash-4way.h"
#include "algo/jh/jh-hash-4way.h"
#include "algo/keccak/keccak-hash-4way.h"
#include "algo/hamsi/hamsi-hash-4way.h"
#include "algo/shabal/shabal-hash-4way.h"
#include "algo/sha/sha-hash-4way.h"
#include "algo/haval/haval-hash-4way.h"
#include "algo/blake/blake2s-hash-4way.h"
#include "algo/echo/aes_ni/hash_api.h"
#include "algo/groestl/aes_ni/hash-groestl.h"
#include "algo/luffa/luffa_for_sse2.h"
#include "algo/cubehash/cubehash_sse2.h"
#include "algo/shavite/sph_shavite.h"
#include "algo/simd/nist.h"
#include "algo/fugue/sph_fugue.h"
#include "algo/whirlpool/sph_whirlpool.h"
#include "algo/tiger/sph_tiger.h"
#include "algo/lyra2/lyra2.h"
#include "algo/gost/sph_gost.h"
#include "algo/swifftx/swifftx.h"
#include "algo/panama/sph_panama.h"
#include "algo/lanehash/lane.h"

union _x25x_4way_ctx_overlay
{
    blake512_4way_context   blake;
    bmw512_4way_context     bmw;
    hashState_groestl       groestl;
    hashState_echo          echo;
    skein512_4way_context   skein;
    jh512_4way_context      jh;
    keccak512_4way_context  keccak;
    hashState_luffa         luffa;
    cubehashParam           cube;
    sph_shavite512_context  shavite;
    hashState_sd            simd;
    hamsi512_4way_context   hamsi;
    sph_fugue512_context    fugue;
    shabal512_4way_context  shabal;
    sph_whirlpool_context   whirlpool;
    sha512_4way_context     sha512;
    haval256_5_4way_context haval;
    sph_tiger_context       tiger;
    sph_gost512_context     gost;
    sha256_4way_context     sha256;
    sph_panama_context      panama;
     blake2s_4way_state           blake2s;
};
typedef union _x25x_4way_ctx_overlay x25x_4way_ctx_overlay;

void x25x_shuffle( void *hash )
{
   // Simple shuffle algorithm, instead of just reversing
   #define X25X_SHUFFLE_BLOCKS (24 * 64 / 2)
   #define X25X_SHUFFLE_ROUNDS 12

   static const uint16_t x25x_round_const[X25X_SHUFFLE_ROUNDS] =
   {
      0x142c, 0x5830, 0x678c, 0xe08c, 0x3c67, 0xd50d, 0xb1d8, 0xecb2,
      0xd7ee, 0x6783, 0xfa6c, 0x4b9c
   };

   uint16_t* block_pointer = (uint16_t*)hash;
   for ( int r = 0; r < X25X_SHUFFLE_ROUNDS; r++ )
   {
      for ( int i = 0; i < X25X_SHUFFLE_BLOCKS; i++ )
      {
         uint16_t block_value = block_pointer[ X25X_SHUFFLE_BLOCKS - i - 1 ];
         block_pointer[i] ^= block_pointer[ block_value % X25X_SHUFFLE_BLOCKS ]
                                + ( x25x_round_const[r] << (i % 16) );
      }
   }

   #undef X25X_SHUFFLE_BLOCKS
   #undef X25X_SHUFFLE_ROUNDS
}

void x25x_4way_hash( void *output, const void *input )
{
   unsigned char hash0[25][64] __attribute__((aligned(64))) = {0};
   unsigned char hash1[25][64] __attribute__((aligned(64))) = {0};
   unsigned char hash2[25][64] __attribute__((aligned(64))) = {0};
   unsigned char hash3[25][64] __attribute__((aligned(64))) = {0};
   uint64_t vhash[8*4] __attribute__ ((aligned (64)));
   unsigned char vhashA[24][64*4] __attribute__ ((aligned (64)));
   x25x_4way_ctx_overlay ctx __attribute__ ((aligned (64)));

   blake512_4way_init( &ctx.blake );
   blake512_4way( &ctx.blake, input, 80 );
   blake512_4way_close( &ctx.blake, vhash );
   dintrlv_4x64_512( &hash0[0], &hash1[0], &hash2[0], &hash3[0], vhash );

   bmw512_4way_init( &ctx.bmw );
   bmw512_4way( &ctx.bmw, vhash, 64 );
   bmw512_4way_close( &ctx.bmw, vhash );
   dintrlv_4x64_512( &hash0[1], &hash1[1], &hash2[1], &hash3[1], vhash );

   init_groestl( &ctx.groestl, 64 );
   update_and_final_groestl( &ctx.groestl, (char*)&hash0[2],
                                  (const char*)&hash0[1], 512 );
   init_groestl( &ctx.groestl, 64 );
   update_and_final_groestl( &ctx.groestl, (char*)&hash1[2],
                                  (const char*)&hash1[1], 512 );
   init_groestl( &ctx.groestl, 64 );
   update_and_final_groestl( &ctx.groestl, (char*)&hash2[2],
                                  (const char*)&hash2[1], 512 );
   init_groestl( &ctx.groestl, 64 );
   update_and_final_groestl( &ctx.groestl, (char*)&hash3[2],
                                  (const char*)&hash3[1], 512 );
   
   intrlv_4x64_512( vhash, &hash0[2], &hash1[2], &hash2[2], &hash3[2] );

   skein512_4way_init( &ctx.skein );
   skein512_4way( &ctx.skein, vhash, 64 );
   skein512_4way_close( &ctx.skein, vhash );
   dintrlv_4x64_512( &hash0[3], &hash1[3], &hash2[3], &hash3[3], vhash );

   jh512_4way_init( &ctx.jh );
   jh512_4way( &ctx.jh, vhash, 64 );
   jh512_4way_close( &ctx.jh, vhash );
   dintrlv_4x64_512( &hash0[4], &hash1[4], &hash2[4], &hash3[4], vhash );

   keccak512_4way_init( &ctx.keccak );
   keccak512_4way( &ctx.keccak, vhash, 64 );
   keccak512_4way_close( &ctx.keccak, vhash );
   dintrlv_4x64_512( &hash0[5], &hash1[5], &hash2[5], &hash3[5], vhash );
   
   init_luffa( &ctx.luffa, 512 );
   update_and_final_luffa( &ctx.luffa, (BitSequence*)&hash0[6],
                                (const BitSequence*)&hash0[5], 64 );
   init_luffa( &ctx.luffa, 512 );
   update_and_final_luffa( &ctx.luffa, (BitSequence*)&hash1[6],
                                (const BitSequence*)&hash1[5], 64 );
   init_luffa( &ctx.luffa, 512 );
   update_and_final_luffa( &ctx.luffa, (BitSequence*)&hash2[6],
                                (const BitSequence*)&hash2[5], 64 );
   init_luffa( &ctx.luffa, 512 );
   update_and_final_luffa( &ctx.luffa, (BitSequence*)&hash3[6],
                                (const BitSequence*)&hash3[5], 64 );

   cubehashInit( &ctx.cube, 512, 16, 32 );
   cubehashUpdateDigest( &ctx.cube, (byte*) &hash0[7],
                              (const byte*)&hash0[6], 64 );
   cubehashInit( &ctx.cube, 512, 16, 32 );
   cubehashUpdateDigest( &ctx.cube, (byte*) &hash1[7],
                              (const byte*)&hash1[6], 64 );
   cubehashInit( &ctx.cube, 512, 16, 32 );
   cubehashUpdateDigest( &ctx.cube, (byte*) &hash2[7],
                              (const byte*)&hash2[6], 64 );
   cubehashInit( &ctx.cube, 512, 16, 32 );
   cubehashUpdateDigest( &ctx.cube, (byte*) &hash3[7],
                              (const byte*)&hash3[6], 64 );

	sph_shavite512_init(&ctx.shavite);
	sph_shavite512(&ctx.shavite, (const void*) &hash0[7], 64);
	sph_shavite512_close(&ctx.shavite, &hash0[8]);
   sph_shavite512_init(&ctx.shavite);
   sph_shavite512(&ctx.shavite, (const void*) &hash1[7], 64);
   sph_shavite512_close(&ctx.shavite, &hash1[8]);
   sph_shavite512_init(&ctx.shavite);
   sph_shavite512(&ctx.shavite, (const void*) &hash2[7], 64);
   sph_shavite512_close(&ctx.shavite, &hash2[8]);
   sph_shavite512_init(&ctx.shavite);
   sph_shavite512(&ctx.shavite, (const void*) &hash3[7], 64);
   sph_shavite512_close(&ctx.shavite, &hash3[8]);

   init_sd( &ctx.simd, 512 );
   update_final_sd( &ctx.simd, (BitSequence*)&hash0[9],
                         (const BitSequence*)&hash0[8], 512 );
   init_sd( &ctx.simd, 512 );
   update_final_sd( &ctx.simd, (BitSequence*)&hash1[9],
                         (const BitSequence*)&hash1[8], 512 );
   init_sd( &ctx.simd, 512 );
   update_final_sd( &ctx.simd, (BitSequence*)&hash2[9],
                         (const BitSequence*)&hash2[8], 512 );
   init_sd( &ctx.simd, 512 );
   update_final_sd( &ctx.simd, (BitSequence*)&hash3[9],
                         (const BitSequence*)&hash3[8], 512 );

   init_echo( &ctx.echo, 512 );
   update_final_echo ( &ctx.echo, (BitSequence*)&hash0[10],
                            (const BitSequence*)&hash0[9], 512 );
   init_echo( &ctx.echo, 512 );
   update_final_echo ( &ctx.echo, (BitSequence*)&hash1[10],
                            (const BitSequence*)&hash1[9], 512 );
   init_echo( &ctx.echo, 512 );
   update_final_echo ( &ctx.echo, (BitSequence*)&hash2[10],
                            (const BitSequence*)&hash2[9], 512 );
   init_echo( &ctx.echo, 512 );
   update_final_echo ( &ctx.echo, (BitSequence*)&hash3[10],
                            (const BitSequence*)&hash3[9], 512 );

   intrlv_4x64_512( vhash, &hash0[10], &hash1[10], &hash2[10], &hash3[10] );

   hamsi512_4way_init( &ctx.hamsi );
   hamsi512_4way( &ctx.hamsi, vhash, 64 );
   hamsi512_4way_close( &ctx.hamsi, vhash );
   dintrlv_4x64_512( &hash0[11], &hash1[11], &hash2[11], &hash3[11], vhash );

	sph_fugue512_init(&ctx.fugue);
	sph_fugue512(&ctx.fugue, (const void*) &hash0[11], 64);
	sph_fugue512_close(&ctx.fugue, &hash0[12]);
   sph_fugue512_init(&ctx.fugue);
   sph_fugue512(&ctx.fugue, (const void*) &hash1[11], 64);
   sph_fugue512_close(&ctx.fugue, &hash1[12]);
   sph_fugue512_init(&ctx.fugue);
   sph_fugue512(&ctx.fugue, (const void*) &hash2[11], 64);
   sph_fugue512_close(&ctx.fugue, &hash2[12]);
   sph_fugue512_init(&ctx.fugue);
   sph_fugue512(&ctx.fugue, (const void*) &hash3[11], 64);
   sph_fugue512_close(&ctx.fugue, &hash3[12]);

   intrlv_4x32_512( vhash, &hash0[12], &hash1[12], &hash2[12], &hash3[12] );

   shabal512_4way_init( &ctx.shabal );
   shabal512_4way( &ctx.shabal, vhash, 64 );
   shabal512_4way_close( &ctx.shabal, vhash );
   dintrlv_4x32_512( &hash0[13], &hash1[13], &hash2[13], &hash3[13], vhash );

	sph_whirlpool_init(&ctx.whirlpool);
	sph_whirlpool (&ctx.whirlpool, (const void*) &hash0[13], 64);
	sph_whirlpool_close(&ctx.whirlpool, &hash0[14]);
   sph_whirlpool_init(&ctx.whirlpool);
   sph_whirlpool (&ctx.whirlpool, (const void*) &hash1[13], 64);
   sph_whirlpool_close(&ctx.whirlpool, &hash1[14]);
   sph_whirlpool_init(&ctx.whirlpool);
   sph_whirlpool (&ctx.whirlpool, (const void*) &hash2[13], 64);
   sph_whirlpool_close(&ctx.whirlpool, &hash2[14]);
   sph_whirlpool_init(&ctx.whirlpool);
   sph_whirlpool (&ctx.whirlpool, (const void*) &hash3[13], 64);
   sph_whirlpool_close(&ctx.whirlpool, &hash3[14]);

   intrlv_4x64_512( vhash, &hash0[14], &hash1[14], &hash2[14], &hash3[14] );

   sha512_4way_init( &ctx.sha512 );
   sha512_4way( &ctx.sha512, vhash, 64 );
   sha512_4way_close( &ctx.sha512, vhash );
   dintrlv_4x64_512( &hash0[15], &hash1[15], &hash2[15], &hash3[15], vhash );


   ComputeSingleSWIFFTX((unsigned char*)&hash0[12], (unsigned char*)&hash0[16]);
   ComputeSingleSWIFFTX((unsigned char*)&hash1[12], (unsigned char*)&hash1[16]);
   ComputeSingleSWIFFTX((unsigned char*)&hash2[12], (unsigned char*)&hash2[16]);
   ComputeSingleSWIFFTX((unsigned char*)&hash3[12], (unsigned char*)&hash3[16]);

   intrlv_4x32_512( &vhashA, &hash0[16], &hash1[16], &hash2[16], &hash3[16] );

   memset( vhash, 0, 64*4 );
   
   haval256_5_4way_init( &ctx.haval );
   haval256_5_4way( &ctx.haval, vhashA, 64 );
   haval256_5_4way_close( &ctx.haval, vhash );
   dintrlv_4x32_512( &hash0[17], &hash1[17], &hash2[17], &hash3[17], vhash );

	sph_tiger_init(&ctx.tiger);
	sph_tiger (&ctx.tiger, (const void*) &hash0[17], 64);
	sph_tiger_close(&ctx.tiger, (void*) &hash0[18]);
   sph_tiger_init(&ctx.tiger);
   sph_tiger (&ctx.tiger, (const void*) &hash1[17], 64);
   sph_tiger_close(&ctx.tiger, (void*) &hash1[18]);
   sph_tiger_init(&ctx.tiger);
   sph_tiger (&ctx.tiger, (const void*) &hash2[17], 64);
   sph_tiger_close(&ctx.tiger, (void*) &hash2[18]);
   sph_tiger_init(&ctx.tiger);
   sph_tiger (&ctx.tiger, (const void*) &hash3[17], 64);
   sph_tiger_close(&ctx.tiger, (void*) &hash3[18]);

	LYRA2RE( (void*)&hash0[19], 32, (const void*)&hash0[18], 32,
            (const void*)&hash0[18], 32, 1, 4, 4 );
   LYRA2RE( (void*)&hash1[19], 32, (const void*)&hash1[18], 32,
            (const void*)&hash1[18], 32, 1, 4, 4 );
   LYRA2RE( (void*)&hash2[19], 32, (const void*)&hash2[18], 32,
            (const void*)&hash2[18], 32, 1, 4, 4 );
   LYRA2RE( (void*)&hash3[19], 32, (const void*)&hash3[18], 32,
            (const void*)&hash3[18], 32, 1, 4, 4 );

	sph_gost512_init(&ctx.gost);
	sph_gost512 (&ctx.gost, (const void*) &hash0[19], 64);
	sph_gost512_close(&ctx.gost, (void*) &hash0[20]);
   sph_gost512_init(&ctx.gost);
   sph_gost512 (&ctx.gost, (const void*) &hash1[19], 64);
   sph_gost512_close(&ctx.gost, (void*) &hash1[20]);
   sph_gost512_init(&ctx.gost);
   sph_gost512 (&ctx.gost, (const void*) &hash2[19], 64);
   sph_gost512_close(&ctx.gost, (void*) &hash2[20]);
   sph_gost512_init(&ctx.gost);
   sph_gost512 (&ctx.gost, (const void*) &hash3[19], 64);
   sph_gost512_close(&ctx.gost, (void*) &hash3[20]);

   intrlv_4x32_512( vhashA, &hash0[20], &hash1[20], &hash2[20], &hash3[20] );
   memset( vhash, 0, 64*4 );

   sha256_4way_init( &ctx.sha256 );
   sha256_4way( &ctx.sha256, vhashA, 64 );
   sha256_4way_close( &ctx.sha256, vhash );
   dintrlv_4x32_512( &hash0[21], &hash1[21], &hash2[21], &hash3[21], vhash );

   sph_panama_init(&ctx.panama);
   sph_panama (&ctx.panama, (const void*) &hash0[21], 64 );
   sph_panama_close(&ctx.panama, (void*) &hash0[22]);
   sph_panama_init(&ctx.panama);
   sph_panama (&ctx.panama, (const void*) &hash1[21], 64 );
   sph_panama_close(&ctx.panama, (void*) &hash1[22]);
   sph_panama_init(&ctx.panama);
   sph_panama (&ctx.panama, (const void*) &hash2[21], 64 );
   sph_panama_close(&ctx.panama, (void*) &hash2[22]);
   sph_panama_init(&ctx.panama);
   sph_panama (&ctx.panama, (const void*) &hash3[21], 64 );
   sph_panama_close(&ctx.panama, (void*) &hash3[22]);

   laneHash(512, (const BitSequence*)&hash0[22], 512, (BitSequence*)&hash0[23]);
   laneHash(512, (const BitSequence*)&hash1[22], 512, (BitSequence*)&hash1[23]);
   laneHash(512, (const BitSequence*)&hash2[22], 512, (BitSequence*)&hash2[23]);
   laneHash(512, (const BitSequence*)&hash3[22], 512, (BitSequence*)&hash3[23]);

   x25x_shuffle( hash0 );
   x25x_shuffle( hash1 );
   x25x_shuffle( hash2 );
   x25x_shuffle( hash3 );

   intrlv_4x32_512( &vhashA[ 0], &hash0[ 0], &hash1[ 0], &hash2[ 0], &hash3[ 0] );
   intrlv_4x32_512( &vhashA[ 1], &hash0[ 1], &hash1[ 1], &hash2[ 1], &hash3[ 1] );
   intrlv_4x32_512( &vhashA[ 2], &hash0[ 2], &hash1[ 2], &hash2[ 2], &hash3[ 2] );
   intrlv_4x32_512( &vhashA[ 3], &hash0[ 3], &hash1[ 3], &hash2[ 3], &hash3[ 3] );
   intrlv_4x32_512( &vhashA[ 4], &hash0[ 4], &hash1[ 4], &hash2[ 4], &hash3[ 4] );
   intrlv_4x32_512( &vhashA[ 5], &hash0[ 5], &hash1[ 5], &hash2[ 5], &hash3[ 5] );
   intrlv_4x32_512( &vhashA[ 6], &hash0[ 6], &hash1[ 6], &hash2[ 6], &hash3[ 6] );
   intrlv_4x32_512( &vhashA[ 7], &hash0[ 7], &hash1[ 7], &hash2[ 7], &hash3[ 7] );
   intrlv_4x32_512( &vhashA[ 8], &hash0[ 8], &hash1[ 8], &hash2[ 8], &hash3[ 8] );
   intrlv_4x32_512( &vhashA[ 9], &hash0[ 9], &hash1[ 9], &hash2[ 9], &hash3[ 9] );
   intrlv_4x32_512( &vhashA[10], &hash0[10], &hash1[10], &hash2[10], &hash3[10] );
   intrlv_4x32_512( &vhashA[11], &hash0[11], &hash1[11], &hash2[11], &hash3[11] );
   intrlv_4x32_512( &vhashA[12], &hash0[12], &hash1[12], &hash2[12], &hash3[12] );
   intrlv_4x32_512( &vhashA[13], &hash0[13], &hash1[13], &hash2[13], &hash3[13] );
   intrlv_4x32_512( &vhashA[14], &hash0[14], &hash1[14], &hash2[14], &hash3[14] );
   intrlv_4x32_512( &vhashA[15], &hash0[15], &hash1[15], &hash2[15], &hash3[15] );
   intrlv_4x32_512( &vhashA[16], &hash0[16], &hash1[16], &hash2[16], &hash3[16] );
   intrlv_4x32_512( &vhashA[17], &hash0[17], &hash1[17], &hash2[17], &hash3[17] );
   intrlv_4x32_512( &vhashA[18], &hash0[18], &hash1[18], &hash2[18], &hash3[18] );
   intrlv_4x32_512( &vhashA[19], &hash0[19], &hash1[19], &hash2[19], &hash3[19] );
   intrlv_4x32_512( &vhashA[20], &hash0[20], &hash1[20], &hash2[20], &hash3[20] );
   intrlv_4x32_512( &vhashA[21], &hash0[21], &hash1[21], &hash2[21], &hash3[21] );
   intrlv_4x32_512( &vhashA[22], &hash0[22], &hash1[22], &hash2[22], &hash3[22] );
   intrlv_4x32_512( &vhashA[23], &hash0[23], &hash1[23], &hash2[23], &hash3[23] );

   blake2s_4way_init( &ctx.blake2s, 32 );
   blake2s_4way_full_blocks( &ctx.blake2s, vhash, vhashA, 64*24 );

   dintrlv_4x32( &hash0[24], &hash1[24], &hash2[24], &hash3[24], vhash, 256 );
     
	memcpy(output,    &hash0[24], 32);
   memcpy(output+32, &hash1[24], 32);
   memcpy(output+64, &hash2[24], 32);
   memcpy(output+96, &hash3[24], 32);
}

int scanhash_x25x_4way( struct work* work, uint32_t max_nonce,
                   uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t hash[4*16] __attribute__ ((aligned (64)));
   uint32_t vdata[24*4] __attribute__ ((aligned (64)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   __m256i  *noncev = (__m256i*)vdata + 9;   // aligned
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;
   const uint32_t Htarg = ptarget[7];

   if (opt_benchmark)
      ((uint32_t*)ptarget)[7] = 0x08ff;

   InitializeSWIFFTX();

   mm256_bswap32_intrlv80_4x64( vdata, pdata );
   do
   {
      *noncev = mm256_intrlv_blend_32( mm256_bswap_32(
              _mm256_set_epi32( n+3, 0, n+2, 0, n+1, 0, n, 0 ) ), *noncev );
      x25x_4way_hash( hash, vdata );

      for ( int i = 0; i < 4; i++ )
      if ( unlikely( (hash+(i<<3))[7] <= Htarg ) )
      if( likely( fulltest( hash+(i<<3), ptarget ) && !opt_benchmark ) )
      {
         pdata[19] = n+i;
         submit_lane_solution( work, hash+(i<<3), mythr, i );
      }
      n += 4;
   } while ( likely( ( n < max_nonce - 4 ) && !work_restart[thr_id].restart ) );

   *hashes_done = n - first_nonce + 1;
   return 0;
}

#endif
