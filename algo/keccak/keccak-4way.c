#include "keccak-gate.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "sph_keccak.h"
#include "keccak-hash-4way.h"

#if defined(KECCAK_8WAY)

void keccakhash_8way(void *state, const void *input)
{
    keccak256_8way_context ctx;
    keccak256_8way_init( &ctx );
    keccak256_8way_update( &ctx, input, 80 );
    keccak256_8way_close( &ctx, state );
}

int scanhash_keccak_8way( struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t vdata[24*8] __attribute__ ((aligned (128)));
   uint32_t hash[16*8] __attribute__ ((aligned (64)));
   uint32_t lane_hash[8] __attribute__ ((aligned (64)));
   uint32_t *hash7 = &(hash[49]);   // 3*16+1
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   uint32_t n = pdata[19];
   const uint32_t first_nonce = pdata[19];
   __m512i  *noncev = (__m512i*)vdata + 9;   // aligned
   const uint32_t Htarg = ptarget[7];
   int thr_id = mythr->id;  

   mm512_bswap32_intrlv80_8x64( vdata, pdata );
   do {
       *noncev = mm512_intrlv_blend_32( mm512_bswap_32(
                _mm512_set_epi32( n+7, 0, n+6, 0, n+5, 0, n+4, 0,
                                  n+3, 0, n+2, 0, n+1, 0, n  , 0 ) ), *noncev );

      keccakhash_8way( hash, vdata );

      for ( int lane = 0; lane < 8; lane++ )
      if ( hash7[ lane<<1 ] <= Htarg ) 
      {
          extr_lane_8x64( lane_hash, hash, lane, 256 );
          if ( fulltest( lane_hash, ptarget ) && !opt_benchmark )
          {
              pdata[19] = n + lane;
              submit_lane_solution( work, lane_hash, mythr, lane );
          }
      }
      n += 8;

   } while ( (n < max_nonce-8) && !work_restart[thr_id].restart);

   *hashes_done = n - first_nonce + 1;
   return 0;
}

#elif defined(KECCAK_4WAY)

void keccakhash_4way(void *state, const void *input)
{
    keccak256_4way_context ctx;
    keccak256_4way_init( &ctx );
    keccak256_4way_update( &ctx, input, 80 );
    keccak256_4way_close( &ctx, state );
}

int scanhash_keccak_4way( struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t vdata[24*4] __attribute__ ((aligned (64)));
   uint32_t hash[16*4] __attribute__ ((aligned (32)));
   uint32_t lane_hash[8] __attribute__ ((aligned (32)));
   uint32_t *hash7 = &(hash[25]);   // 3*8+1
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   uint32_t n = pdata[19];
   const uint32_t first_nonce = pdata[19];
   __m256i  *noncev = (__m256i*)vdata + 9;   // aligned
   const uint32_t Htarg = ptarget[7];
   int thr_id = mythr->id;

   mm256_bswap32_intrlv80_4x64( vdata, pdata );
   do {
       *noncev = mm256_intrlv_blend_32( mm256_bswap_32(
                _mm256_set_epi32( n+3, 0, n+2, 0, n+1, 0, n, 0 ) ), *noncev );
	
      keccakhash_4way( hash, vdata );

      for ( int lane = 0; lane < 4; lane++ )
      if ( hash7[ lane<<1 ] <= Htarg )
      {
          extr_lane_4x64( lane_hash, hash, lane, 256 );
          if ( fulltest( lane_hash, ptarget ) && !opt_benchmark )
          {
              pdata[19] = n + lane;
              submit_lane_solution( work, lane_hash, mythr, lane );
          }
      }
      n += 4;

   } while ( (n < max_nonce-4) && !work_restart[thr_id].restart);

   *hashes_done = n - first_nonce + 1;
   return 0;
}

#endif
