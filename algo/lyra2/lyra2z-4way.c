#include "lyra2-gate.h"
#include <memory.h>
#include "lyra2.h"
#include "algo/blake/blake256-hash.h"

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)
  #define LYRA2Z_16WAY 1
#elif defined(__AVX2__)
  #define LYRA2Z_8WAY 1
#elif defined(__SSE2__)
  #define LYRA2Z_4WAY 1
//#else
// NEON 1 way SIMD
#endif

#define LYRA2Z_MATRIX_SIZE  BLOCK_LEN_INT64 * 8 * 8 * 8

#if defined(LYRA2Z_16WAY)

__thread uint64_t* lyra2z_16way_matrix;

bool lyra2z_16way_thread_init()
{
 return ( lyra2z_16way_matrix = mm_malloc( 2*LYRA2Z_MATRIX_SIZE, 64 ) );
}

static void lyra2z_16way_hash( void *state, const void *midstate_vars,
                        const void *midhash, const void *block )
{
    uint32_t vhash[8*16] __attribute__ ((aligned (128)));
    uint32_t hash0[8] __attribute__ ((aligned (32)));
    uint32_t hash1[8] __attribute__ ((aligned (32)));
    uint32_t hash2[8] __attribute__ ((aligned (32)));
    uint32_t hash3[8] __attribute__ ((aligned (32)));
    uint32_t hash4[8] __attribute__ ((aligned (32)));
    uint32_t hash5[8] __attribute__ ((aligned (32)));
    uint32_t hash6[8] __attribute__ ((aligned (32)));
    uint32_t hash7[8] __attribute__ ((aligned (32)));
    uint32_t hash8[8] __attribute__ ((aligned (32)));
    uint32_t hash9[8] __attribute__ ((aligned (32)));
    uint32_t hash10[8] __attribute__ ((aligned (32)));
    uint32_t hash11[8] __attribute__ ((aligned (32)));
    uint32_t hash12[8] __attribute__ ((aligned (32)));
    uint32_t hash13[8] __attribute__ ((aligned (32)));
    uint32_t hash14[8] __attribute__ ((aligned (32)));
    uint32_t hash15[8] __attribute__ ((aligned (32)));

    blake256_16way_final_rounds_le( vhash, midstate_vars, midhash, block, 14 );

    dintrlv_16x32( hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
              hash8, hash9, hash10, hash11 ,hash12, hash13, hash14, hash15,
              vhash, 256 );

    intrlv_2x256( vhash, hash0, hash1, 256 );
    LYRA2Z_2WAY( lyra2z_16way_matrix, vhash, 32, vhash, 32, 8, 8, 8 );
    dintrlv_2x256( hash0, hash1, vhash, 256 );
    intrlv_2x256( vhash, hash2, hash3, 256 );
    LYRA2Z_2WAY( lyra2z_16way_matrix, vhash, 32, vhash, 32, 8, 8, 8 );
    dintrlv_2x256( hash2, hash3, vhash, 256 );
    intrlv_2x256( vhash, hash4, hash5, 256 );
    LYRA2Z_2WAY( lyra2z_16way_matrix, vhash, 32, vhash, 32, 8, 8, 8 );
    dintrlv_2x256( hash4, hash5, vhash, 256 );
    intrlv_2x256( vhash, hash6, hash7, 256 );
    LYRA2Z_2WAY( lyra2z_16way_matrix, vhash, 32, vhash, 32, 8, 8, 8 );
    dintrlv_2x256( hash6, hash7, vhash, 256 );
    intrlv_2x256( vhash, hash8, hash9, 256 );
    LYRA2Z_2WAY( lyra2z_16way_matrix, vhash, 32, vhash, 32, 8, 8, 8 );
    dintrlv_2x256( hash8, hash9, vhash, 256 );
    intrlv_2x256( vhash, hash10, hash11, 256 );
    LYRA2Z_2WAY( lyra2z_16way_matrix, vhash, 32, vhash, 32, 8, 8, 8 );
    dintrlv_2x256( hash10, hash11, vhash, 256 );
    intrlv_2x256( vhash, hash12, hash13, 256 );
    LYRA2Z_2WAY( lyra2z_16way_matrix, vhash, 32, vhash, 32, 8, 8, 8 );
    dintrlv_2x256( hash12, hash13, vhash, 256 );
    intrlv_2x256( vhash, hash14, hash15, 256 );
    LYRA2Z_2WAY( lyra2z_16way_matrix, vhash, 32, vhash, 32, 8, 8, 8 );
    dintrlv_2x256( hash14, hash15, vhash, 256 );
   
    memcpy( state,     hash0, 32 );
    memcpy( state+ 32, hash1, 32 );
    memcpy( state+ 64, hash2, 32 );
    memcpy( state+ 96, hash3, 32 );
    memcpy( state+128, hash4, 32 );
    memcpy( state+160, hash5, 32 );
    memcpy( state+192, hash6, 32 );
    memcpy( state+224, hash7, 32 );
    memcpy( state+256, hash8, 32 );
    memcpy( state+288, hash9, 32 );
    memcpy( state+320, hash10, 32 );
    memcpy( state+352, hash11, 32 );
    memcpy( state+384, hash12, 32 );
    memcpy( state+416, hash13, 32 );
    memcpy( state+448, hash14, 32 );
    memcpy( state+480, hash15, 32 );
}

int scanhash_lyra2z_16way( struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t hash[8*16] __attribute__ ((aligned (128)));
   uint32_t midstate_vars[16*16] __attribute__ ((aligned (64)));
   __m512i block0_hash[8] __attribute__ ((aligned (64)));
   __m512i block_buf[16] __attribute__ ((aligned (64)));
   uint32_t phash[8] __attribute__ ((aligned (64))) =
   {
      0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
      0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
   };
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   uint32_t n = first_nonce;
   const uint32_t last_nonce = max_nonce - 16;
   const int thr_id = mythr->id;
   const bool bench = opt_benchmark;
   const __m512i sixteen = _mm512_set1_epi32( 16 );

   if ( bench ) ( (uint32_t*)ptarget )[7] = 0x0000ff;

   // Prehash first block
   blake256_transform_le( phash, pdata, 512, 0, 14 );

   block0_hash[0] = _mm512_set1_epi32( phash[0] );
   block0_hash[1] = _mm512_set1_epi32( phash[1] );
   block0_hash[2] = _mm512_set1_epi32( phash[2] );
   block0_hash[3] = _mm512_set1_epi32( phash[3] );
   block0_hash[4] = _mm512_set1_epi32( phash[4] );
   block0_hash[5] = _mm512_set1_epi32( phash[5] );
   block0_hash[6] = _mm512_set1_epi32( phash[6] );
   block0_hash[7] = _mm512_set1_epi32( phash[7] );

   // Build vectored second block, interleave last 16 bytes of data using
   // unique nonces.
   block_buf[ 0] = _mm512_set1_epi32( pdata[16] );
   block_buf[ 1] = _mm512_set1_epi32( pdata[17] );
   block_buf[ 2] = _mm512_set1_epi32( pdata[18] );
   block_buf[ 3] =
             _mm512_set_epi32( n+15, n+14, n+13, n+12, n+11, n+10, n+ 9, n+ 8,
                               n+ 7, n+ 6, n+ 5, n+ 4, n+ 3, n+ 2, n +1, n );

   // Partialy prehash second block without touching nonces in block_buf[3].
   blake256_16way_round0_prehash_le( midstate_vars, block0_hash, block_buf );

   do {
     lyra2z_16way_hash( hash, midstate_vars, block0_hash, block_buf );

     for ( int lane = 0; lane < 16; lane++ )
     if ( unlikely( valid_hash( hash+(lane<<3), ptarget ) && !bench ) )
     {
        pdata[19] = n + lane;
        submit_solution( work, hash+(lane<<3), mythr );
     }
     block_buf[ 3] = _mm512_add_epi32( block_buf[ 3], sixteen );
     n += 16;
   } while ( likely( (n < last_nonce) && !work_restart[thr_id].restart) );
   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

#elif defined(LYRA2Z_8WAY)

__thread uint64_t* lyra2z_8way_matrix;

bool lyra2z_8way_thread_init()
{
 return ( lyra2z_8way_matrix = mm_malloc( LYRA2Z_MATRIX_SIZE, 64 ) );
}

static void lyra2z_8way_hash( void *state, const void *midstate_vars,
                       const void *midhash, const void *block )
{
     uint32_t hash0[8] __attribute__ ((aligned (64)));
     uint32_t hash1[8] __attribute__ ((aligned (32)));
     uint32_t hash2[8] __attribute__ ((aligned (32)));
     uint32_t hash3[8] __attribute__ ((aligned (32)));
     uint32_t hash4[8] __attribute__ ((aligned (32)));
     uint32_t hash5[8] __attribute__ ((aligned (32)));
     uint32_t hash6[8] __attribute__ ((aligned (32)));
     uint32_t hash7[8] __attribute__ ((aligned (32)));
     uint32_t vhash[8*8] __attribute__ ((aligned (64)));

     blake256_8way_final_rounds_le( vhash, midstate_vars, midhash, block, 14 );

     dintrlv_8x32( hash0, hash1, hash2, hash3,
                   hash4, hash5, hash6, hash7, vhash, 256 );

     LYRA2Z( lyra2z_8way_matrix, hash0, 32, hash0, 32, hash0, 32, 8, 8, 8 );
     LYRA2Z( lyra2z_8way_matrix, hash1, 32, hash1, 32, hash1, 32, 8, 8, 8 );
     LYRA2Z( lyra2z_8way_matrix, hash2, 32, hash2, 32, hash2, 32, 8, 8, 8 );
     LYRA2Z( lyra2z_8way_matrix, hash3, 32, hash3, 32, hash3, 32, 8, 8, 8 );
     LYRA2Z( lyra2z_8way_matrix, hash4, 32, hash4, 32, hash4, 32, 8, 8, 8 );
     LYRA2Z( lyra2z_8way_matrix, hash5, 32, hash5, 32, hash5, 32, 8, 8, 8 );
     LYRA2Z( lyra2z_8way_matrix, hash6, 32, hash6, 32, hash6, 32, 8, 8, 8 );
     LYRA2Z( lyra2z_8way_matrix, hash7, 32, hash7, 32, hash7, 32, 8, 8, 8 );

     memcpy( state,     hash0, 32 );
     memcpy( state+ 32, hash1, 32 );
     memcpy( state+ 64, hash2, 32 );
     memcpy( state+ 96, hash3, 32 );
     memcpy( state+128, hash4, 32 );
     memcpy( state+160, hash5, 32 );
     memcpy( state+192, hash6, 32 );
     memcpy( state+224, hash7, 32 );
}

int scanhash_lyra2z_8way( struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done, struct thr_info *mythr )
{
   uint64_t hash[4*8] __attribute__ ((aligned (64)));
   uint32_t midstate_vars[16*8] __attribute__ ((aligned (64)));
   __m256i block0_hash[8] __attribute__ ((aligned (64)));
   __m256i block_buf[16] __attribute__ ((aligned (64)));
   uint32_t phash[8] __attribute__ ((aligned (32))) =
   {
      0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
      0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
   };
   uint32_t *pdata = work->data;
   uint64_t *ptarget = (uint64_t*)work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 8;
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;
   const bool bench = opt_benchmark;
   const __m256i eight = _mm256_set1_epi32( 8 );

   // Prehash first block
   blake256_transform_le( phash, pdata, 512, 0, 14 );

   block0_hash[0] = _mm256_set1_epi32( phash[0] );
   block0_hash[1] = _mm256_set1_epi32( phash[1] );
   block0_hash[2] = _mm256_set1_epi32( phash[2] );
   block0_hash[3] = _mm256_set1_epi32( phash[3] );
   block0_hash[4] = _mm256_set1_epi32( phash[4] );
   block0_hash[5] = _mm256_set1_epi32( phash[5] );
   block0_hash[6] = _mm256_set1_epi32( phash[6] );
   block0_hash[7] = _mm256_set1_epi32( phash[7] );

   // Build vectored second block, interleave last 16 bytes of data using
   // unique nonces.
   block_buf[ 0] = _mm256_set1_epi32( pdata[16] );
   block_buf[ 1] = _mm256_set1_epi32( pdata[17] );
   block_buf[ 2] = _mm256_set1_epi32( pdata[18] );
   block_buf[ 3] =
            _mm256_set_epi32( n+ 7, n+ 6, n+ 5, n+ 4, n+ 3, n+ 2, n +1, n );

   // Partialy prehash second block without touching nonces
   blake256_8way_round0_prehash_le( midstate_vars, block0_hash, block_buf );

   do {
     lyra2z_8way_hash( hash, midstate_vars, block0_hash, block_buf );

     for ( int lane = 0; lane < 8; lane++ )
     {
        const uint64_t *lane_hash = hash + (lane<<2);
        if ( unlikely( valid_hash( lane_hash, ptarget ) && !bench ) )
        {
           pdata[19] = n + lane;
           submit_solution( work, lane_hash, mythr );
        }
     }
     n += 8;
     block_buf[ 3] = _mm256_add_epi32( block_buf[ 3], eight );
   } while ( likely( (n <= last_nonce) && !work_restart[thr_id].restart ) );
   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

#elif defined(LYRA2Z_4WAY)

//    SSE2 or NEON
    
__thread uint64_t* lyra2z_4way_matrix;

bool lyra2z_4way_thread_init()
{
 return ( lyra2z_4way_matrix = mm_malloc( LYRA2Z_MATRIX_SIZE, 64 ) );
}

static __thread blake256_4way_context l2z_4way_blake_mid;

void lyra2z_4way_midstate( const void* input )
{
       blake256_4way_init( &l2z_4way_blake_mid );
       blake256_4way_update( &l2z_4way_blake_mid, input, 64 );
}

void lyra2z_4way_hash( void *hash, const void *midstate_vars,
                               const void *midhash, const void *block )
{
     uint32_t hash0[8] __attribute__ ((aligned (64)));
     uint32_t hash1[8] __attribute__ ((aligned (64)));
     uint32_t hash2[8] __attribute__ ((aligned (64)));
     uint32_t hash3[8] __attribute__ ((aligned (64)));
     uint32_t vhash[8*4] __attribute__ ((aligned (64)));
//     blake256_4way_context ctx_blake __attribute__ ((aligned (64)));

     blake256_4way_final_rounds_le( vhash, midstate_vars, midhash, block, 14 );

/*
     memcpy( &ctx_blake, &l2z_4way_blake_mid, sizeof l2z_4way_blake_mid );
     blake256_4way_update( &ctx_blake, input + (64*4), 16 );
     blake256_4way_close( &ctx_blake, vhash );
*/

     dintrlv_4x32( hash0, hash1, hash2, hash3, vhash, 256 );

     LYRA2Z( lyra2z_4way_matrix, hash   , 32, hash0, 32, hash0, 32, 8, 8, 8 );
     LYRA2Z( lyra2z_4way_matrix, hash+32, 32, hash1, 32, hash1, 32, 8, 8, 8 );
     LYRA2Z( lyra2z_4way_matrix, hash+64, 32, hash2, 32, hash2, 32, 8, 8, 8 );
     LYRA2Z( lyra2z_4way_matrix, hash+96, 32, hash3, 32, hash3, 32, 8, 8, 8 );
}

int scanhash_lyra2z_4way( struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done, struct thr_info *mythr )
{
   uint64_t hash[4*4] __attribute__ ((aligned (64)));
   uint32_t midstate_vars[16*4] __attribute__ ((aligned (64)));
   v128_t block0_hash[8] __attribute__ ((aligned (64)));
   v128_t block_buf[16] __attribute__ ((aligned (64)));
   uint32_t phash[8] __attribute__ ((aligned (32))) =
   {
      0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
      0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
   };
   uint32_t *pdata = work->data;
   uint64_t *ptarget = (uint64_t*)work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 4;
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;
   const bool bench = opt_benchmark;
   const v128u32_t four = v128_32(4);

   // Prehash first block
   blake256_transform_le( phash, pdata, 512, 0, 14 );

   block0_hash[0] = v128_32( phash[0] );
   block0_hash[1] = v128_32( phash[1] );
   block0_hash[2] = v128_32( phash[2] );
   block0_hash[3] = v128_32( phash[3] );
   block0_hash[4] = v128_32( phash[4] );
   block0_hash[5] = v128_32( phash[5] );
   block0_hash[6] = v128_32( phash[6] );
   block0_hash[7] = v128_32( phash[7] );

   // Build vectored second block, interleave last 16 bytes of data using
   // unique nonces.
   block_buf[ 0] = v128_32( pdata[16] );
   block_buf[ 1] = v128_32( pdata[17] );
   block_buf[ 2] = v128_32( pdata[18] );
   block_buf[ 3] = v128_set32( n+3, n+2, n+1, n );
   block_buf[ 4] = v128_32( 0x80000000 );
   block_buf[13] = v128_32( 1 );
   block_buf[15] = v128_32( 640 );

   // Partialy prehash second block without touching nonces
   blake256_4way_round0_prehash_le( midstate_vars, block0_hash, block_buf );

   do {
      lyra2z_4way_hash( hash, midstate_vars, block0_hash, block_buf );
      for ( int lane = 0; lane < 4; lane++ )
      {
        const uint64_t *lane_hash = hash + (lane<<2);
        if ( unlikely( valid_hash( lane_hash, ptarget ) && !bench ) )
        {
           pdata[19] =  n + lane;
           submit_solution( work, lane_hash, mythr );
        }
      }
      block_buf[ 3] = v128_add32( block_buf[ 3], four );
      n += 4;
   } while ( likely( (n < last_nonce) && !work_restart[thr_id].restart ) );

   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

#else

// not used

__thread uint64_t* lyra2z_matrix;

bool lyra2z_thread_init()
{
   const int i = BLOCK_LEN_INT64 * 8 * 8 * 8;
   lyra2z_matrix = mm_malloc( i, 64 );
   return lyra2z_matrix;
}

static __thread blake256_context lyra2z_blake_mid;

void lyra2z_midstate( const void* input )
{
       blake256_init( &lyra2z_blake_mid );
       blake256_update( &lyra2z_blake_mid, input, 64 );
}

void lyra2z_hash( void *state, const void *input )
{
    uint32_t _ALIGN(32) hash[16];
    blake256_context ctx_blake __attribute__ ((aligned (64)));

    memcpy( &ctx_blake, &lyra2z_blake_mid, sizeof (blake256_context) );
    blake256_update( &ctx_blake, input + 64, 16 );
    blake256_close( &ctx_blake, hash );

    LYRA2Z( lyra2z_matrix, hash, 32, hash, 32, hash, 32, 8, 8, 8 );

    memcpy( state, hash, 32 );
}

int scanhash_lyra2z( struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t _ALIGN(64) hash[8];
   uint32_t _ALIGN(64) endiandata[20];
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   uint32_t nonce = first_nonce;
   int thr_id = mythr->id;

   if (opt_benchmark) ptarget[7] = 0x0000ff;

//   for ( int i = 0; i < 20; i++ ) endiandata[i] = bswap_32( pdata[i] );
   v128_bswap32_80( endiandata, pdata );

   lyra2z_midstate( endiandata );

   do {
      endiandata[19] = bswap_32( nonce );
      lyra2z_hash( hash, endiandata );
      if ( valid_hash( hash, ptarget ) && !opt_benchmark )
      {
         pdata[19] = nonce;
         submit_solution( work, hash, mythr );
      }
      nonce++;
   } while ( nonce < max_nonce && !work_restart[thr_id].restart );
   pdata[19] = nonce;
   *hashes_done = pdata[19] - first_nonce + 1;
   return 0;
}

#endif

bool register_lyra2z_algo( algo_gate_t* gate )
{
#if defined(LYRA2Z_16WAY)
  gate->miner_thread_init = (void*)&lyra2z_16way_thread_init;
  gate->scanhash          = (void*)&scanhash_lyra2z_16way;
//  gate->hash       = (void*)&lyra2z_16way_hash;
#elif defined(LYRA2Z_8WAY)
  gate->miner_thread_init = (void*)&lyra2z_8way_thread_init;
  gate->scanhash          = (void*)&scanhash_lyra2z_8way;
//  gate->hash       = (void*)&lyra2z_8way_hash;
#elif defined(LYRA2Z_4WAY)
  gate->miner_thread_init = (void*)&lyra2z_4way_thread_init;
  gate->scanhash          = (void*)&scanhash_lyra2z_4way;
  gate->hash              = (void*)&lyra2z_4way_hash;
#else
  gate->miner_thread_init = (void*)&lyra2z_thread_init;
  gate->scanhash          = (void*)&scanhash_lyra2z;
  gate->hash              = (void*)&lyra2z_hash;
#endif
  gate->optimizations = SSE2_OPT | AVX2_OPT | AVX512_OPT | NEON_OPT;
  opt_target_factor = 256.0;
  return true;
};

