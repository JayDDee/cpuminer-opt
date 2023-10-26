#include "algo-gate-api.h"
#include "blake2s-hash.h"
#include <string.h>
#include <stdint.h>

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)
  #define BLAKE2S_16WAY
#elif defined(__AVX2__)
  #define BLAKE2S_8WAY
#elif defined(__SSE2__) || defined(__ARM_NEON)
//  #define BLAKE2S_4WAY
#endif

#if defined(BLAKE2S_16WAY)

static __thread blake2s_16way_state blake2s_16w_ctx;

void blake2s_16way_hash( void *output, const void *input )
{
   blake2s_16way_state ctx;
   memcpy( &ctx, &blake2s_16w_ctx, sizeof ctx );
   blake2s_16way_update( &ctx, input + (64<<4), 16 );
   blake2s_16way_final( &ctx, output, 32 );
}

int scanhash_blake2s_16way( struct work *work, uint32_t max_nonce,
                            uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t vdata[20*16] __attribute__ ((aligned (128)));
   uint32_t hash[8*16] __attribute__ ((aligned (64)));
   uint32_t lane_hash[8] __attribute__ ((aligned (64)));
   uint32_t *hash7 = &(hash[7<<4]);
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t Htarg = ptarget[7];
   const uint32_t first_nonce = pdata[19];
   __m512i  *noncev = (__m512i*)vdata + 19;   // aligned
   uint32_t n = first_nonce;
   int thr_id = mythr->id;  

   mm512_bswap32_intrlv80_16x32( vdata, pdata );
   blake2s_16way_init( &blake2s_16w_ctx, 32 );
   blake2s_16way_update( &blake2s_16w_ctx, vdata, 64 );

   do {
      *noncev = mm512_bswap_32( _mm512_set_epi32(
	                  n+15, n+14, n+13, n+12, n+11, n+10, n+ 9, n+ 8,
	                  n+ 7, n+ 6, n+ 5, n+ 4, n+ 3, n+ 2, n+ 1, n ) );
      pdata[19] = n;

      blake2s_16way_hash( hash, vdata );

      for ( int lane = 0; lane < 16; lane++ )
      if ( unlikely( hash7[lane] <= Htarg ) )
      {
         extr_lane_16x32( lane_hash, hash, lane, 256 );
         if ( likely( fulltest( lane_hash, ptarget ) && !opt_benchmark ) )
         {
              pdata[19] = n + lane;
              submit_solution( work, lane_hash, mythr );
         }
      }
      n += 16;
   } while ( (n < max_nonce-16) && !work_restart[thr_id].restart );

   *hashes_done = n - first_nonce + 1;
   return 0;
}

#elif defined(BLAKE2S_8WAY)

static __thread blake2s_8way_state blake2s_8w_ctx;

void blake2s_8way_hash( void *output, const void *input )
{
   blake2s_8way_state ctx;
   memcpy( &ctx, &blake2s_8w_ctx, sizeof ctx );
   blake2s_8way_update( &ctx, input + (64<<3), 16 );
   blake2s_8way_final( &ctx, output, 32 );
}

int scanhash_blake2s_8way( struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t vdata[20*8] __attribute__ ((aligned (64)));
   uint32_t hash[8*8] __attribute__ ((aligned (32)));
   uint32_t lane_hash[8] __attribute__ ((aligned (32)));
   uint32_t *hash7 = &(hash[7<<3]);
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t Htarg = ptarget[7];
   const uint32_t first_nonce = pdata[19];
   __m256i  *noncev = (__m256i*)vdata + 19;   // aligned
   uint32_t n = first_nonce;
   int thr_id = mythr->id; 

   mm256_bswap32_intrlv80_8x32( vdata, pdata );
   blake2s_8way_init( &blake2s_8w_ctx, 32 );
   blake2s_8way_update( &blake2s_8w_ctx, vdata, 64 );

   do {
      *noncev = mm256_bswap_32( _mm256_set_epi32( n+7, n+6, n+5, n+4,
                                                  n+3, n+2, n+1, n ) );
      pdata[19] = n;

      blake2s_8way_hash( hash, vdata );

      for ( int lane = 0; lane < 8; lane++ )
      if ( unlikely( hash7[lane] <= Htarg ) )
      {
         extr_lane_8x32( lane_hash, hash, lane, 256 );
         if ( likely( fulltest( lane_hash, ptarget ) && !opt_benchmark ) )
         {
              pdata[19] = n + lane;
              submit_solution( work, lane_hash, mythr );
         }
      }
      n += 8;
   } while ( (n < max_nonce) && !work_restart[thr_id].restart );

   *hashes_done = n - first_nonce + 1;
   return 0;
}

#elif defined(BLAKE2S_4WAY)

static __thread blake2s_4way_state blake2s_4w_ctx;

void blake2s_4way_hash( void *output, const void *input )
{
   blake2s_4way_state ctx;
   memcpy( &ctx, &blake2s_4w_ctx, sizeof ctx );
   blake2s_4way_update( &ctx, input + (64<<2), 16 );
   blake2s_4way_final( &ctx, output, 32 );
}

int scanhash_blake2s_4way( struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t vdata[20*4] __attribute__ ((aligned (64)));
   uint32_t hash[8*4] __attribute__ ((aligned (32)));
   uint32_t lane_hash[8] __attribute__ ((aligned (32)));
   uint32_t *hash7 = &(hash[7<<2]);
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t Htarg = ptarget[7];
   const uint32_t first_nonce = pdata[19];
   v128_t  *noncev = (v128_t*)vdata + 19;   // aligned
   uint32_t n = first_nonce;
   int thr_id = mythr->id; 

   v128_bswap32_intrlv80_4x32( vdata, pdata );
   blake2s_4way_init( &blake2s_4w_ctx, 32 );
   blake2s_4way_update( &blake2s_4w_ctx, vdata, 64 );

   do {
      *noncev = v128_bswap32( v128_set32( n+3, n+2, n+1, n ) );
      pdata[19] = n;

      blake2s_4way_hash( hash, vdata );

      for ( int lane = 0; lane < 4; lane++ ) if ( hash7[lane] <= Htarg )
      {
         extr_lane_4x32( lane_hash, hash, lane, 256 );
         if ( fulltest( lane_hash, ptarget ) && !opt_benchmark )
         {
              pdata[19] = n + lane;
              submit_solution( work, lane_hash, mythr );
              }
      }
      n += 4;
   } while ( (n < max_nonce) && !work_restart[thr_id].restart );

   *hashes_done = n - first_nonce + 1;
   return 0;
}

#else

#include "sph-blake2s.h"

static __thread blake2s_state blake2s_ctx;

void blake2s_hash( void *output, const void *input )
{
   unsigned char _ALIGN(32) hash[32];
   blake2s_state ctx __attribute__ ((aligned (32)));

   memcpy( &ctx, &blake2s_ctx, sizeof ctx );
   blake2s_update( &ctx, input+64, 16 );
   blake2s_final( &ctx, hash, 32 );

   memcpy(output, hash, 32);
}

int scanhash_blake2s( struct work *work,uint32_t max_nonce,
                      uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t *pdata = work->data;
   const uint32_t *ptarget = work->target;
   uint32_t _ALIGN(32) hash32[8];
   uint32_t _ALIGN(32) endiandata[20];
   const int thr_id = mythr->id;
   const uint32_t first_nonce = pdata[19];
   uint32_t n = first_nonce;

   v128_bswap32_80( endiandata, pdata );

   // midstate
   blake2s_init( &blake2s_ctx, 32 );
   blake2s_update( &blake2s_ctx, (uint8_t*) endiandata, 64 );

   do
   {
      endiandata[19] = n;
      blake2s_hash( hash32, endiandata );
      if ( unlikely( valid_hash( hash32, ptarget ) ) && !opt_benchmark )
      {
         pdata[19] = bswap_32( n );
         submit_solution( work, hash32, mythr );
      }
      n++;
   } while (n < max_nonce && !work_restart[thr_id].restart);

   *hashes_done = n - first_nonce + 1;
   pdata[19] = n;

   return 0;
}

#endif

bool register_blake2s_algo( algo_gate_t* gate )
{
#if defined(BLAKE2S_16WAY)
  gate->scanhash  = (void*)&scanhash_blake2s_16way;
  gate->hash      = (void*)&blake2s_16way_hash;
#elif defined(BLAKE2S_8WAY)
  gate->scanhash  = (void*)&scanhash_blake2s_8way;
  gate->hash      = (void*)&blake2s_8way_hash;
#elif defined(BLAKE2S_4WAY)
  gate->scanhash  = (void*)&scanhash_blake2s_4way;
  gate->hash      = (void*)&blake2s_4way_hash;
#else
  gate->scanhash  = (void*)&scanhash_blake2s;
  gate->hash      = (void*)&blake2s_hash;
#endif
  gate->optimizations = SSE2_OPT | AVX2_OPT | AVX512_OPT | NEON_OPT;
  return true;
};

