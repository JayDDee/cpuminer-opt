#include "tribus-gate.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "algo/jh/jh-hash-4way.h"
#include "algo/keccak/keccak-hash-4way.h"
#include "algo/echo/aes_ni/hash_api.h"
#if defined(__VAES__)
  #include "algo/echo/echo-hash-4way.h"
#endif

#if defined(TRIBUS_8WAY)

static __thread jh512_8way_context ctx_mid;

void tribus_hash_8way( void *state, const void *input )
{
     uint64_t vhash[8*8] __attribute__ ((aligned (128)));
     uint64_t hash0[8] __attribute__ ((aligned (64)));
     uint64_t hash1[8] __attribute__ ((aligned (64)));
     uint64_t hash2[8] __attribute__ ((aligned (64)));
     uint64_t hash3[8] __attribute__ ((aligned (64)));
     uint64_t hash4[8] __attribute__ ((aligned (64)));
     uint64_t hash5[8] __attribute__ ((aligned (64)));
     uint64_t hash6[8] __attribute__ ((aligned (64)));
     uint64_t hash7[8] __attribute__ ((aligned (64)));
     jh512_8way_context     ctx_jh;
     keccak512_8way_context ctx_keccak;
#if defined(__VAES__)
     echo_4way_context      ctx_echo;
#else
     hashState_echo         ctx_echo;
#endif

     memcpy( &ctx_jh, &ctx_mid, sizeof(ctx_mid) );
     jh512_8way_update( &ctx_jh, input + (64<<3), 16 );
     jh512_8way_close( &ctx_jh, vhash );

     keccak512_8way_init( &ctx_keccak );
     keccak512_8way_update( &ctx_keccak, vhash, 64 );
     keccak512_8way_close( &ctx_keccak, vhash );

#if defined(__VAES__)
     uint64_t vhashA[8*4] __attribute__ ((aligned (64)));
     uint64_t vhashB[8*4] __attribute__ ((aligned (64)));

     rintrlv_8x64_4x128( vhashA, vhashB, vhash, 512 );
     
     echo_4way_init( &ctx_echo, 512 );
     echo_4way_update_close( &ctx_echo, vhashA, vhashA, 512 );
     echo_4way_init( &ctx_echo, 512 );
     echo_4way_update_close( &ctx_echo, vhashB, vhashB, 512 );

     dintrlv_4x128_512( hash0, hash1, hash2, hash3, vhashA );
     dintrlv_4x128_512( hash4, hash5, hash6, hash7, vhashB );

#else

     dintrlv_8x64( hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
                   vhash, 512 );

     init_echo( &ctx_echo, 512 );
     update_final_echo( &ctx_echo, (BitSequence *) hash0,
                        (const BitSequence *) hash0, 512 );
     init_echo( &ctx_echo, 512 );
     update_final_echo( &ctx_echo, (BitSequence *) hash1,
                        (const BitSequence *) hash1, 512 );
     init_echo( &ctx_echo, 512 );
     update_final_echo( &ctx_echo, (BitSequence *) hash2,
                        (const BitSequence *) hash2, 512 );
     init_echo( &ctx_echo, 512 );
     update_final_echo( &ctx_echo, (BitSequence *) hash3,
                        (const BitSequence *) hash3, 512 );
     init_echo( &ctx_echo, 512 );
     update_final_echo( &ctx_echo, (BitSequence *) hash4,
                        (const BitSequence *) hash4, 512 );
     init_echo( &ctx_echo, 512 );
     update_final_echo( &ctx_echo, (BitSequence *) hash5,
                        (const BitSequence *) hash5, 512 );
     init_echo( &ctx_echo, 512 );
     update_final_echo( &ctx_echo, (BitSequence *) hash6,
                        (const BitSequence *) hash6, 512 );
     init_echo( &ctx_echo, 512 );
     update_final_echo( &ctx_echo, (BitSequence *) hash7,
                        (const BitSequence *) hash7, 512 );

#endif

     memcpy( state,       hash0, 32 );
     memcpy( state+32,    hash1, 32 );
     memcpy( state+64,    hash2, 32 );
     memcpy( state+96,    hash3, 32 );
     memcpy( state+128,   hash4, 32 );
     memcpy( state+160,   hash5, 32 );
     memcpy( state+192,   hash6, 32 );
     memcpy( state+224,   hash7, 32 );
}

int scanhash_tribus_8way( struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t hash[8*8] __attribute__ ((aligned (128)));
   uint32_t vdata[20*8] __attribute__ ((aligned (64)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t Htarg = ptarget[7];
   uint32_t n = pdata[19];
   __m512i  *noncev = (__m512i*)vdata + 9;   // aligned
   int thr_id = mythr->id;  

   mm512_bswap32_intrlv80_8x64( vdata, pdata );

   jh512_8way_init( &ctx_mid );
   jh512_8way_update( &ctx_mid, vdata, 64 );

   do {
     *noncev = mm512_intrlv_blend_32( mm512_bswap_32(
                _mm512_set_epi32( n+7, 0, n+6, 0, n+5, 0, n+4, 0,
                                  n+3, 0, n+2, 0, n+1, 0, n  , 0 ) ), *noncev );

     tribus_hash_8way( hash, vdata );
     pdata[19] = n;

     for ( int i = 0; i < 8; i++ )
     if ( (hash+(i<<3))[7] <= Htarg )
     if ( fulltest( hash+(i<<3), ptarget ) && !opt_benchmark )
     {
          pdata[19] = n+i;
          submit_solution( work, hash+(i<<3), mythr );
     }
     n += 8;
   } while ( ( n < max_nonce-8 )  && !work_restart[thr_id].restart);

   *hashes_done = n - first_nonce;
   return 0;
}

#elif defined(TRIBUS_4WAY)

static __thread jh512_4way_context ctx_mid;

void tribus_hash_4way( void *state, const void *input )
{
     uint64_t hash0[8] __attribute__ ((aligned (64)));
     uint64_t hash1[8] __attribute__ ((aligned (64)));
     uint64_t hash2[8] __attribute__ ((aligned (64)));
     uint64_t hash3[8] __attribute__ ((aligned (64)));
     uint64_t vhash[8*4] __attribute__ ((aligned (64)));
     jh512_4way_context     ctx_jh;
     keccak512_4way_context ctx_keccak;
     hashState_echo         ctx_echo;

     memcpy( &ctx_jh, &ctx_mid, sizeof(ctx_mid) );
     jh512_4way_update( &ctx_jh, input + (64<<2), 16 );
     jh512_4way_close( &ctx_jh, vhash );

     keccak512_4way_init( &ctx_keccak );
     keccak512_4way_update( &ctx_keccak, vhash, 64 );
     keccak512_4way_close( &ctx_keccak, vhash );

     dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 512 );

     // hash echo serially
     init_echo( &ctx_echo, 512 );
     update_final_echo( &ctx_echo, (BitSequence *) hash0,
                        (const BitSequence *) hash0, 512 );
     init_echo( &ctx_echo, 512 );
     update_final_echo( &ctx_echo, (BitSequence *) hash1,
                        (const BitSequence *) hash1, 512 );
     init_echo( &ctx_echo, 512 );
     update_final_echo( &ctx_echo, (BitSequence *) hash2,
                        (const BitSequence *) hash2, 512 );
     init_echo( &ctx_echo, 512 );
     update_final_echo( &ctx_echo, (BitSequence *) hash3,
                        (const BitSequence *) hash3, 512 );

     memcpy( state,       hash0, 32 );
     memcpy( state+32,    hash1, 32 );
     memcpy( state+64,    hash2, 32 );
     memcpy( state+96,    hash3, 32 );
}

int scanhash_tribus_4way( struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t hash[4*8] __attribute__ ((aligned (64)));
   uint32_t vdata[20*4] __attribute__ ((aligned (64)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t Htarg = ptarget[7];
   uint32_t n = pdata[19];
   __m256i  *noncev = (__m256i*)vdata + 9;   // aligned
   int thr_id = mythr->id;

   mm256_bswap32_intrlv80_4x64( vdata, pdata );

   jh512_4way_init( &ctx_mid );
   jh512_4way_update( &ctx_mid, vdata, 64 );

   do {
     *noncev = mm256_intrlv_blend_32( mm256_bswap_32(
                _mm256_set_epi32( n+3, 0, n+2, 0, n+1, 0, n, 0 ) ), *noncev );

     tribus_hash_4way( hash, vdata );

     pdata[19] = n;

     for ( int i = 0; i < 4; i++ )
     if ( (hash+(i<<3))[7] <= Htarg )
     if ( fulltest( hash+(i<<3), ptarget ) && !opt_benchmark )
     {
          pdata[19] = n+i;
          submit_solution( work, hash+(i<<3), mythr );
     }
     n += 4;
   } while ( ( n < max_nonce-4 )  && !work_restart[thr_id].restart);

   *hashes_done = n - first_nonce;
   return 0;
}

#endif
