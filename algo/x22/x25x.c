#include "x22i-gate.h"

#if !( defined(X25X_8WAY) || defined(X25X_4WAY) )

#include "algo/blake/sph_blake.h"
#include "algo/bmw/sph_bmw.h"
#if defined(__AES__)
  #include "algo/echo/aes_ni/hash_api.h"
  #include "algo/groestl/aes_ni/hash-groestl.h"
  #include "algo/fugue/fugue-aesni.h"
#else
  #include "algo/groestl/sph_groestl.h"
  #include "algo/echo/sph_echo.h"
  #include "algo/fugue/sph_fugue.h"
#endif
#include "algo/skein/sph_skein.h"
#include "algo/jh/sph_jh.h"
#include "algo/keccak/sph_keccak.h"
#include "algo/luffa/luffa_for_sse2.h"
#include "algo/cubehash/cubehash_sse2.h"
#include "algo/shavite/sph_shavite.h"
#include "algo/simd/nist.h"
#include "algo/hamsi/sph_hamsi.h"
#include "algo/shabal/sph_shabal.h"
#include "algo/whirlpool/sph_whirlpool.h"
#include "algo/sha/sha256-hash.h"
#include "algo/haval/sph-haval.h"
#include "algo/tiger/sph_tiger.h"
#include "algo/lyra2/lyra2.h"
#include "algo/gost/sph_gost.h"
#include "algo/swifftx/swifftx.h"
#include "algo/blake/sph-blake2s.h"
#include "algo/panama/sph_panama.h"
#include "algo/lanehash/lane.h"

union _x25x_context_overlay
{
        sph_blake512_context    blake;
        sph_bmw512_context      bmw;
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
        sph_tiger_context       tiger;
        sph_gost512_context     gost;
        sha256_context          sha256;
        sph_panama_context      panama;
        blake2s_state           blake2s;
};
typedef union _x25x_context_overlay x25x_context_overlay;

int x25x_hash( void *output, const void *input, int thrid )
{
   unsigned char hash[25][64] __attribute__((aligned(64))) = {0};
   x25x_context_overlay ctx;

   sph_blake512_init(&ctx.blake);
   sph_blake512(&ctx.blake, input, 80);
   sph_blake512_close(&ctx.blake, &hash[0] );

   sph_bmw512_init(&ctx.bmw);
   sph_bmw512(&ctx.bmw, (const void*) &hash[0], 64);
   sph_bmw512_close(&ctx.bmw, &hash[1]);

#if defined(__AES__)
   init_groestl( &ctx.groestl, 64 );
   update_and_final_groestl( &ctx.groestl, (char*)&hash[2],
                                  (const char*)&hash[1], 512 );
#else
   sph_groestl512_init( &ctx.groestl );
   sph_groestl512( &ctx.groestl, &hash[1], 64 );
   sph_groestl512_close( &ctx.groestl, &hash[2] );
#endif
   
   sph_skein512_init(&ctx.skein);
   sph_skein512(&ctx.skein, (const void*) &hash[2], 64);
   sph_skein512_close(&ctx.skein, &hash[3]);

   sph_jh512_init(&ctx.jh);
   sph_jh512(&ctx.jh, (const void*) &hash[3], 64);
   sph_jh512_close(&ctx.jh, &hash[4]);

   sph_keccak512_init(&ctx.keccak);
   sph_keccak512(&ctx.keccak, (const void*) &hash[4], 64);
   sph_keccak512_close(&ctx.keccak, &hash[5]);

   if ( work_restart[thrid].restart ) return 0;
   
   init_luffa( &ctx.luffa, 512 );
   update_and_final_luffa( &ctx.luffa, (BitSequence*)&hash[6],
                                (const BitSequence*)&hash[5], 64 );

   cubehashInit( &ctx.cube, 512, 16, 32 );
   cubehashUpdateDigest( &ctx.cube, (byte*) &hash[7],
                              (const byte*)&hash[6], 64 );

   sph_shavite512_init(&ctx.shavite);
   sph_shavite512(&ctx.shavite, (const void*) &hash[7], 64);
   sph_shavite512_close(&ctx.shavite, &hash[8]);

   init_sd( &ctx.simd, 512 );
   update_final_sd( &ctx.simd, (BitSequence*)&hash[9],
                         (const BitSequence*)&hash[8], 512 );

#if defined(__AES__)
   init_echo( &ctx.echo, 512 );
   update_final_echo ( &ctx.echo, (BitSequence*)&hash[10],
                            (const BitSequence*)&hash[9], 512 );
#else
   sph_echo512_init( &ctx.echo );
   sph_echo512( &ctx.echo, &hash[9], 64 );
   sph_echo512_close( &ctx.echo, &hash[10] );
#endif

   if ( work_restart[thrid].restart ) return 0;

   sph_hamsi512_init(&ctx.hamsi);
   sph_hamsi512(&ctx.hamsi, (const void*) &hash[10], 64);
   sph_hamsi512_close(&ctx.hamsi, &hash[11]);

#if defined(__AES__)
   fugue512_full( &ctx.fugue, &hash[12], &hash[11], 64 );
#else
   sph_fugue512_init(&ctx.fugue);
   sph_fugue512(&ctx.fugue, (const void*) &hash[11], 64);
   sph_fugue512_close(&ctx.fugue, &hash[12]);
#endif

   sph_shabal512_init(&ctx.shabal);
   sph_shabal512(&ctx.shabal, (const void*) &hash[12], 64);
   sph_shabal512_close(&ctx.shabal, &hash[13]);

   sph_whirlpool_init(&ctx.whirlpool);
   sph_whirlpool (&ctx.whirlpool, (const void*) &hash[13], 64);
   sph_whirlpool_close(&ctx.whirlpool, &hash[14]);

   sph_sha512_init( &ctx.sha512 );
   sph_sha512( &ctx.sha512, &hash[14], 64 );
   sph_sha512_close( &ctx.sha512, &hash[15] );

   ComputeSingleSWIFFTX((unsigned char*)&hash[12], (unsigned char*)&hash[16]);

   sph_haval256_5_init(&ctx.haval);
   sph_haval256_5(&ctx.haval,(const void*) &hash[16], 64);
   sph_haval256_5_close(&ctx.haval,&hash[17]);

   if ( work_restart[thrid].restart ) return 0;
   
   sph_tiger_init(&ctx.tiger);
   sph_tiger (&ctx.tiger, (const void*) &hash[17], 64);
   sph_tiger_close(&ctx.tiger, (void*) &hash[18]);

   LYRA2RE( (void*)&hash[19], 32, (const void*)&hash[18], 32,
            (const void*)&hash[18], 32, 1, 4, 4 );

   sph_gost512_init(&ctx.gost);
   sph_gost512 (&ctx.gost, (const void*) &hash[19], 64);
   sph_gost512_close(&ctx.gost, (void*) &hash[20]);

   sha256_full( &hash[21], &hash[20], 64 );

   sph_panama_init(&ctx.panama);
   sph_panama (&ctx.panama, (const void*) &hash[21], 64 );
   sph_panama_close(&ctx.panama, (void*) &hash[22]);

   laneHash(512, (const BitSequence*) &hash[22], 512, (BitSequence*) &hash[23]);

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

   blake2s_simple( (uint8_t*)&hash[24], (const void*)(&hash[0]), 64 * 24 );
   
	memcpy(output, &hash[24], 32);

   return 1;
}

int scanhash_x25x( struct work *work, uint32_t max_nonce,
             uint64_t *hashes_done, struct thr_info *mythr)
{
   uint32_t edata[20] __attribute__((aligned(64)));
   uint32_t hash64[8] __attribute__((aligned(64)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   uint32_t n = pdata[19];
   const uint32_t first_nonce = n;
   const int thr_id = mythr->id;
   const bool bench = opt_benchmark;

   if ( bench ) ptarget[7] = 0x08ff;

   mm128_bswap32_80( edata, pdata );

   InitializeSWIFFTX();

   do
   {
      edata[19] = n;
      if ( x25x_hash( hash64, edata, thr_id ) );
      if ( unlikely( valid_hash( hash64, ptarget ) && !bench ) )
      {
         pdata[19] = bswap_32( n );
         submit_solution( work, hash64, mythr );
      }
      n++;
   } while ( n < max_nonce && !work_restart[thr_id].restart );
   *hashes_done = n - first_nonce;
   pdata[19] = n;
   return 0;
}

#endif
