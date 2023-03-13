#include "skein-gate.h"
#include <string.h>
#include <stdint.h>
#include "skein-hash-4way.h"

#if defined(SKEIN_8WAY)

 static __thread skein512_8way_context skein512_8way_ctx
                                             __attribute__ ((aligned (64)));

void skein2hash_8way( void *output, const void *input )
{
   uint64_t hash[16*8] __attribute__ ((aligned (128)));
   skein512_8way_context ctx;
   memcpy( &ctx, &skein512_8way_ctx, sizeof( ctx ) );

   skein512_8way_final16( &ctx, hash, input + (64*8) );
   skein512_8way_full( &ctx, output, hash, 64 );
}

int scanhash_skein2_8way( struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done, struct thr_info *mythr )
{
    uint64_t hash[8*8] __attribute__ ((aligned (128)));
    uint32_t vdata[20*8] __attribute__ ((aligned (64)));
    uint32_t lane_hash[8] __attribute__ ((aligned (64)));
    uint64_t *hashq3 = &(hash[3*8]);
    uint32_t *pdata = work->data;
    uint32_t *ptarget = work->target;
    const uint64_t targq3 = ((uint64_t*)ptarget)[3];
    const uint32_t first_nonce = pdata[19];
    const uint32_t last_nonce = max_nonce - 8;
    uint32_t n = first_nonce;
    __m512i  *noncev = (__m512i*)vdata + 9; 
    const int thr_id = mythr->id; 
    const bool bench = opt_benchmark;
    skein512_8way_context ctx;

    mm512_bswap32_intrlv80_8x64( vdata, pdata );
    *noncev = mm512_intrlv_blend_32(
                _mm512_set_epi32( n+7, 0, n+6, 0, n+5, 0, n+4, 0,
                                  n+3, 0, n+2, 0, n+1, 0, n  , 0 ), *noncev );
    skein512_8way_prehash64( &ctx, vdata );
    do
    {
       skein512_8way_final16( &ctx, hash, vdata + (16*8) );
       skein512_8way_full( &ctx, hash, hash, 64 );

       for ( int lane = 0; lane < 8; lane++ )
       if ( unlikely( hashq3[ lane ] <= targq3 && !bench ) )
       {
          extr_lane_8x64( lane_hash, hash, lane, 256 );
          if ( valid_hash( lane_hash, ptarget ) && !bench )
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

#elif defined(SKEIN_4WAY)

static __thread skein512_4way_context skein512_4way_ctx
                                           __attribute__ ((aligned (64)));

void skein2hash_4way( void *output, const void *input )
{
   skein512_4way_context ctx;
   memcpy( &ctx, &skein512_4way_ctx, sizeof( ctx ) ); 
   uint64_t hash[16*4] __attribute__ ((aligned (64)));

   skein512_4way_final16( &ctx, hash, input + (64*4) );
   skein512_4way_full( &ctx, output, hash, 64 );
}

int scanhash_skein2_4way( struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done, struct thr_info *mythr )
{
    uint64_t hash[8*4] __attribute__ ((aligned (64)));
    uint32_t vdata[20*4] __attribute__ ((aligned (64)));
    uint32_t lane_hash[8] __attribute__ ((aligned (64)));
    uint64_t *hash_q3 = &(hash[3*4]);
    uint32_t *pdata = work->data;
    uint32_t *ptarget = work->target;
    const uint64_t targ_q3 = ((uint64_t*)ptarget)[3];
    const uint32_t first_nonce = pdata[19];
    const uint32_t last_nonce = max_nonce - 4;
    uint32_t n = first_nonce;
    __m256i  *noncev = (__m256i*)vdata + 9; 
    const int thr_id = mythr->id;  
    const bool bench = opt_benchmark;
    skein512_4way_context ctx;

    mm256_bswap32_intrlv80_4x64( vdata, pdata );
    skein512_4way_prehash64( &ctx, vdata );
    *noncev = mm256_intrlv_blend_32(
                _mm256_set_epi32( n+3, 0, n+2, 0, n+1, 0, n, 0 ), *noncev );
    do 
    {
       skein512_4way_final16( &ctx, hash, vdata + (16*4) );
       skein512_4way_full( &ctx, hash, hash, 64 );

       for ( int lane = 0; lane < 4; lane++ )
       if ( hash_q3[ lane ] <= targ_q3 )
       {
          extr_lane_4x64( lane_hash, hash, lane, 256 );
          if ( valid_hash( lane_hash, ptarget ) && !bench )
          {
             pdata[19] = bswap_32( n + lane );
             submit_solution( work, lane_hash, mythr );
          }
       }
       *noncev = _mm256_add_epi32( *noncev,
                                  m256_const1_64( 0x0000000400000000 ) );
       n += 4;
    } while ( (n < last_nonce) && !work_restart[thr_id].restart );

    pdata[19] = n;
    *hashes_done = n - first_nonce;
    return 0;
}

#endif
