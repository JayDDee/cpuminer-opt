#include "blake2s-gate.h"
#include "blake2s-hash-4way.h"
//#include "sph-blake2s.h"
#include <string.h>
#include <stdint.h>

#if defined(BLAKE2S_16WAY)

static __thread blake2s_16way_state blake2s_16w_ctx;

/*
static blake2s_16way_state blake2s_16w_ctx;
static uint32_t blake2s_16way_vdata[20*16] __attribute__ ((aligned (64)));
*/
/*
int blake2s_16way_prehash( struct work *work )
{
   uint32_t edata[20] __attribute__ ((aligned (64)));
   blake2s_state ctx;
   mm128_bswap32_80( edata, work->data );
   blake2s_init( &ctx, BLAKE2S_OUTBYTES );
   ctx.buflen = ctx.t[0] = 64;
   blake2s_compress( &ctx, (const uint8_t*)edata );

   blake2s_16way_init( &blake2s_16w_ctx, BLAKE2S_OUTBYTES );
   intrlv_16x32( blake2s_16w_ctx.h, ctx.h, ctx.h, ctx.h, ctx.h,
                                    ctx.h, ctx.h, ctx.h, ctx.h,
                                    ctx.h, ctx.h, ctx.h, ctx.h,
                                    ctx.h, ctx.h, ctx.h, ctx.h, 256 );
   intrlv_16x32( blake2s_16way_vdata, edata, edata, edata, edata,
                                      edata, edata, edata, edata,
                                      edata, edata, edata, edata,
                                      edata, edata, edata, edata, 640 );
   blake2s_16w_ctx.t[0] = 64;
   return 1;
}
*/
/*
int blake2s_16way_prehash( struct work *work )
{
   mm512_bswap32_intrlv80_16x32( blake2s_16way_vdata, work->data );
   blake2s_16way_init( &blake2s_16w_ctx, BLAKE2S_OUTBYTES );
   blake2s_16way_update( &blake2s_16w_ctx, blake2s_16way_vdata, 64 );
   return 1;
}
*/

void blake2s_16way_hash( void *output, const void *input )
{
   blake2s_16way_state ctx;
   memcpy( &ctx, &blake2s_16w_ctx, sizeof ctx );
   blake2s_16way_update( &ctx, input + (64<<4), 16 );
   blake2s_16way_final( &ctx, output, BLAKE2S_OUTBYTES );
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

/*   
//   pthread_rwlock_rdlock( &g_work_lock );
       memcpy( (__m512i*)vdata +16, (__m512i*)blake2s_16way_vdata +16, 3*4*16 );
//     casti_m512i( vdata, 16 ) = casti_m512i( blake2s_16way_vdata, 16 );
//     casti_m512i( vdata, 17 ) = casti_m512i( blake2s_16way_vdata, 17 );
//     casti_m512i( vdata, 18 ) = casti_m512i( blake2s_16way_vdata, 18 );
       
//   pthread_rwlock_unlock( &g_work_lock );
*/
/*
   uint32_t edata[20] __attribute__ ((aligned (64)));
   blake2s_state ctx;
   mm128_bswap32_80( edata, pdata );
   blake2s_init( &ctx, BLAKE2S_OUTBYTES );
   ctx.buflen = ctx.t[0] = 64;
   blake2s_compress( &ctx, (const uint8_t*)edata );

   blake2s_16way_init( &blake2s_16w_ctx, BLAKE2S_OUTBYTES );
   intrlv_16x32( blake2s_16w_ctx.h, ctx.h, ctx.h, ctx.h, ctx.h,
                                    ctx.h, ctx.h, ctx.h, ctx.h,
                                    ctx.h, ctx.h, ctx.h, ctx.h,
                                    ctx.h, ctx.h, ctx.h, ctx.h, 256 );
   intrlv_16x32( blake2s_16way_blake2s_16way_vdata, edata, edata, edata, edata,
                                      edata, edata, edata, edata,
                                      edata, edata, edata, edata,
                                      edata, edata, edata, edata, 640 );
   blake2s_16w_ctx.t[0] = 64;
*/
   
   mm512_bswap32_intrlv80_16x32( vdata, pdata );
   blake2s_16way_init( &blake2s_16w_ctx, BLAKE2S_OUTBYTES );
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

/*
static blake2s_8way_state blake2s_8w_ctx;
static uint32_t blake2s_8way_vdata[20*8] __attribute__ ((aligned (32)));

int blake2s_8way_prehash( struct work *work )
{
   uint32_t edata[20] __attribute__ ((aligned (64)));
   blake2s_state ctx;
   mm128_bswap32_80( edata, work->data );
   blake2s_init( &ctx, BLAKE2S_OUTBYTES );
   ctx.buflen = ctx.t[0] = 64;
   blake2s_compress( &ctx, (const uint8_t*)edata );

   blake2s_8way_init( &blake2s_8w_ctx, BLAKE2S_OUTBYTES );

   for ( int i = 0; i < 8; i++ )
      casti_m256i( blake2s_8w_ctx.h, i ) = _mm256_set1_epi32( ctx.h[i] );

   casti_m256i( blake2s_8way_vdata, 16 ) = _mm256_set1_epi32( edata[16] );
   casti_m256i( blake2s_8way_vdata, 17 ) = _mm256_set1_epi32( edata[17] );
   casti_m256i( blake2s_8way_vdata, 18 ) = _mm256_set1_epi32( edata[18] );

//   intrlv_8x32( blake2s_8w_ctx.h, ctx.h, ctx.h, ctx.h, ctx.h,
//                                  ctx.h, ctx.h, ctx.h, ctx.h, 256 );
//   intrlv_8x32( blake2s_8way_vdata, edata, edata, edata, edata,
//                                    edata, edata, edata, edata, 640 );
   blake2s_8w_ctx.t[0] = 64;
}
*/

void blake2s_8way_hash( void *output, const void *input )
{
   blake2s_8way_state ctx;
   memcpy( &ctx, &blake2s_8w_ctx, sizeof ctx );
   blake2s_8way_update( &ctx, input + (64<<3), 16 );
   blake2s_8way_final( &ctx, output, BLAKE2S_OUTBYTES );
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

/*   
//   pthread_rwlock_rdlock( &g_work_lock );
       memcpy( &vdata[16*8], &blake2s_8way_vdata[16*8], 3*4*8 );
//   pthread_rwlock_unlock( &g_work_lock );
*/
/*
   uint32_t edata[20] __attribute__ ((aligned (64)));
   blake2s_state ctx;
   mm128_bswap32_80( edata, pdata );
   blake2s_init( &ctx, BLAKE2S_OUTBYTES );
   ctx.buflen = ctx.t[0] = 64;
   blake2s_compress( &ctx, (const uint8_t*)edata );

   blake2s_8way_init( &blake2s_8w_ctx, BLAKE2S_OUTBYTES );
   for ( int i = 0; i < 8; i++ )
      casti_m256i( blake2s_8w_ctx.h, i ) = _mm256_set1_epi32( ctx.h[i] );

   casti_m256i( vdata, 16 ) = _mm256_set1_epi32( edata[16] );
   casti_m256i( vdata, 17 ) = _mm256_set1_epi32( edata[17] );
   casti_m256i( vdata, 18 ) = _mm256_set1_epi32( edata[18] );


//  intrlv_8x32( blake2s_8w_ctx.h, ctx.h, ctx.h, ctx.h, ctx.h,
//                                  ctx.h, ctx.h, ctx.h, ctx.h, 256 );
//   intrlv_8x32( vdata, edata, edata, edata, edata,
//                                    edata, edata, edata, edata, 640 );

   blake2s_8w_ctx.t[0] = 64;
*/
   
   mm256_bswap32_intrlv80_8x32( vdata, pdata );
   blake2s_8way_init( &blake2s_8w_ctx, BLAKE2S_OUTBYTES );
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
/*
static blake2s_4way_state blake2s_4w_ctx;
static uint32_t blake2s_4way_vdata[20*4] __attribute__ ((aligned (32)));

int blake2s_4way_prehash( struct work *work )
{
   uint32_t edata[20] __attribute__ ((aligned (64)));
   blake2s_state ctx;
   mm128_bswap32_80( edata, work->data );
   blake2s_init( &ctx, BLAKE2S_OUTBYTES );
   ctx.buflen = ctx.t[0] = 64;
   blake2s_compress( &ctx, (const uint8_t*)edata );

   blake2s_4way_init( &blake2s_4w_ctx, BLAKE2S_OUTBYTES );
   intrlv_4x32( blake2s_4w_ctx.h, ctx.h, ctx.h, ctx.h, ctx.h, 256 );
   intrlv_4x32( blake2s_4way_vdata, edata, edata, edata, edata, 640 );
   blake2s_4w_ctx.t[0] = 64;
}
*/
void blake2s_4way_hash( void *output, const void *input )
{
   blake2s_4way_state ctx;
   memcpy( &ctx, &blake2s_4w_ctx, sizeof ctx );
   blake2s_4way_update( &ctx, input + (64<<2), 16 );
   blake2s_4way_final( &ctx, output, BLAKE2S_OUTBYTES );
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
   __m128i  *noncev = (__m128i*)vdata + 19;   // aligned
   uint32_t n = first_nonce;
   int thr_id = mythr->id; 
/*
   pthread_rwlock_rdlock( &g_work_lock );
       memcpy( vdata, blake2s_4way_vdata, sizeof vdata );
   pthread_rwlock_unlock( &g_work_lock );
*/
   mm128_bswap32_intrlv80_4x32( vdata, pdata );
   blake2s_4way_init( &blake2s_4w_ctx, BLAKE2S_OUTBYTES );
   blake2s_4way_update( &blake2s_4w_ctx, vdata, 64 );
   
   do {
      *noncev = mm128_bswap_32( _mm_set_epi32( n+3, n+2, n+1, n ) );
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

#endif
