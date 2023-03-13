#include "skein-gate.h"
#include <string.h>
#include <stdint.h>
#include "skein-hash-4way.h"
#include "algo/sha/sha-hash-4way.h"
#include "algo/sha/sha256-hash.h"

#if defined (SKEIN_8WAY)

static __thread skein512_8way_context skein512_8way_ctx
                                            __attribute__ ((aligned (64)));

void skeinhash_8way( void *state, const void *input )
{
     uint64_t vhash64[8*8] __attribute__ ((aligned (128)));
     skein512_8way_context ctx_skein;
     memcpy( &ctx_skein, &skein512_8way_ctx, sizeof( ctx_skein ) );
     uint32_t vhash32[16*8] __attribute__ ((aligned (128)));
     sha256_8way_context ctx_sha256;

     skein512_8way_final16( &ctx_skein, vhash64, input + (64*8) );
     rintrlv_8x64_8x32( vhash32, vhash64, 512 );

     sha256_8way_init( &ctx_sha256 );
     sha256_8way_update( &ctx_sha256, vhash32, 64 );
     sha256_8way_close( &ctx_sha256, state );
}

int scanhash_skein_8way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr )
{
    uint32_t vdata[20*8] __attribute__ ((aligned (128)));
    uint32_t hash[8*8] __attribute__ ((aligned (64)));
    uint32_t lane_hash[8] __attribute__ ((aligned (64)));
    uint32_t *hash_d7 = &(hash[7*8]);
    uint32_t *pdata = work->data;
    uint32_t *ptarget = work->target;
    const uint32_t targ_d7 = ptarget[7];
    const uint32_t first_nonce = pdata[19];
    const uint32_t last_nonce = max_nonce - 8;
    uint32_t n = first_nonce;
    __m512i  *noncev = (__m512i*)vdata + 9; 
    const int thr_id = mythr->id; 
    const bool bench = opt_benchmark;

   mm512_bswap32_intrlv80_8x64( vdata, pdata );
   *noncev = mm512_intrlv_blend_32(
                _mm512_set_epi32( n+7, 0, n+6, 0, n+5, 0, n+4, 0,
                                  n+3, 0, n+2, 0, n+1, 0, n  , 0 ), *noncev );
   skein512_8way_prehash64( &skein512_8way_ctx, vdata );
   do
   {
       skeinhash_8way( hash, vdata );

       for ( int lane = 0; lane < 8; lane++ )
       if ( unlikely( hash_d7[ lane ] <= targ_d7 ) && !bench )
       {
          extr_lane_8x32( lane_hash, hash, lane, 256 );
          if ( valid_hash( lane_hash, ptarget ) )
          {
             pdata[19] = bswap_32( n + lane );
             submit_solution( work, lane_hash, mythr );
          }
       }
       *noncev = _mm512_add_epi32( *noncev,
                                  m512_const1_64( 0x0000000800000000 ) );
       n += 8;
    } while ( likely( (n < last_nonce) && !work_restart[thr_id].restart ) );

    pdata[19] = n;
    *hashes_done = n - first_nonce;
    return 0;
}

#elif defined (SKEIN_4WAY)

static __thread skein512_4way_context skein512_4way_ctx
                                            __attribute__ ((aligned (64)));

void skeinhash_4way( void *state, const void *input )
{
     uint64_t vhash64[8*4] __attribute__ ((aligned (128)));
     skein512_4way_context ctx_skein;
     memcpy( &ctx_skein, &skein512_4way_ctx, sizeof( ctx_skein ) );
#if defined(__SHA__)
     uint32_t hash0[16] __attribute__ ((aligned (64)));
     uint32_t hash1[16] __attribute__ ((aligned (64)));
     uint32_t hash2[16] __attribute__ ((aligned (64)));
     uint32_t hash3[16] __attribute__ ((aligned (64)));
#else
     uint32_t vhash32[16*4] __attribute__ ((aligned (64)));
     sha256_4way_context ctx_sha256;
#endif

     skein512_4way_final16( &ctx_skein, vhash64, input + (64*4) );

#if defined(__SHA__)      

     dintrlv_4x64( hash0, hash1, hash2, hash3, vhash64, 512 );

     sha256_full( hash0, hash0, 64 );
     sha256_full( hash1, hash1, 64 );
     sha256_full( hash2, hash2, 64 );
     sha256_full( hash3, hash3, 64 );
    
     intrlv_4x32( state, hash0, hash1, hash2, hash3, 256 );

#else

     rintrlv_4x64_4x32( vhash32, vhash64, 512 );
     sha256_4way_init( &ctx_sha256 );
     sha256_4way_update( &ctx_sha256, vhash32, 64 );
     sha256_4way_close( &ctx_sha256, state );

#endif
}

int scanhash_skein_4way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr )
{
    uint32_t vdata[20*4] __attribute__ ((aligned (64)));
    uint32_t hash[8*4] __attribute__ ((aligned (64)));
    uint32_t lane_hash[8] __attribute__ ((aligned (32)));
    uint32_t *hash_d7 = &(hash[7<<2]);
    uint32_t *pdata = work->data;
    uint32_t *ptarget = work->target;
    const uint32_t targ_d7 = ptarget[7];
    const uint32_t first_nonce = pdata[19];
    const uint32_t last_nonce = max_nonce - 4;
    uint32_t n = first_nonce;
    __m256i  *noncev = (__m256i*)vdata + 9; 
    const int thr_id = mythr->id; 
    const bool bench = opt_benchmark;

   mm256_bswap32_intrlv80_4x64( vdata, pdata );
   skein512_4way_prehash64( &skein512_4way_ctx, vdata );

   *noncev = mm256_intrlv_blend_32(
                _mm256_set_epi32( n+3, 0, n+2, 0, n+1, 0, n, 0 ), *noncev );
   do
   {
       skeinhash_4way( hash, vdata );
       for ( int lane = 0; lane < 4; lane++ )
       if ( unlikely( ( hash_d7[ lane ] <= targ_d7 ) && !bench ) )
       {
          extr_lane_4x32( lane_hash, hash, lane, 256 );
          if ( valid_hash( lane_hash, ptarget ) )
          {
             pdata[19] = bswap_32( n + lane );
             submit_solution( work, lane_hash, mythr );
          }
       }
       *noncev = _mm256_add_epi32( *noncev,
                                  m256_const1_64( 0x0000000400000000 ) );
       n += 4;
    } while ( likely( (n < last_nonce) && !work_restart[thr_id].restart ) );

    pdata[19] = n;
    *hashes_done = n - first_nonce;
    return 0;
}

#endif
