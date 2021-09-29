#include "algo-gate-api.h"
#include "algo/sha/sha256-hash.h"
#include "Verthash.h"
#include "tiny_sha3/sha3-4way.h"

static verthash_info_t verthashInfo;

// Verthash data file hash in bytes for verification
// 0x48aa21d7afededb63976d48a8ff8ec29d5b02563af4a1110b056cd43e83155a5
static const uint8_t verthashDatFileHash_bytes[32] =
{ 0xa5, 0x55, 0x31, 0xe8, 0x43, 0xcd, 0x56, 0xb0,
  0x10, 0x11, 0x4a, 0xaf, 0x63, 0x25, 0xb0, 0xd5,
  0x29, 0xec, 0xf8, 0x8f, 0x8a, 0xd4, 0x76, 0x39,
  0xb6, 0xed, 0xed, 0xaf, 0xd7, 0x21, 0xaa, 0x48 };

#if defined(__AVX2__)

static __thread sha3_4way_ctx_t sha3_mid_ctxA;
static __thread sha3_4way_ctx_t sha3_mid_ctxB;

#else

static __thread sha3_ctx_t sha3_mid_ctx[8];

#endif

void verthash_sha3_512_prehash_72( const void *input )
{
#if defined(__AVX2__)
   
   __m256i vin[10];
   mm256_intrlv80_4x64( vin, input );

   sha3_4way_init( &sha3_mid_ctxA, 64 );
   sha3_4way_init( &sha3_mid_ctxB, 64 );

   vin[0] = _mm256_add_epi8( vin[0], _mm256_set_epi64x( 4,3,2,1 ) );
   sha3_4way_update( &sha3_mid_ctxA, vin, 72 );

   vin[0] = _mm256_add_epi8( vin[0], _mm256_set1_epi64x( 4 ) );
   sha3_4way_update( &sha3_mid_ctxB, vin, 72 );

#else

   char in[80] __attribute__ ((aligned (64)));
   memcpy( in, input, 80 );   
   for ( int i = 0; i < 8; i++ )
   {
      in[0] += 1;
      sha3_init( &sha3_mid_ctx[i], 64 );
      sha3_update( &sha3_mid_ctx[i], in, 72 );
   }

#endif
}

void verthash_sha3_512_final_8( void *hash, const uint64_t nonce )
{
#if defined(__AVX2__)

    __m256i vhashA[ 10 ] __attribute__ ((aligned (64)));
    __m256i vhashB[ 10 ] __attribute__ ((aligned (64)));

   sha3_4way_ctx_t ctx;
   const __m256i vnonce = _mm256_set1_epi64x( nonce );

   memcpy( &ctx, &sha3_mid_ctxA, sizeof ctx );
   sha3_4way_update( &ctx, &vnonce, 8 );
   sha3_4way_final( vhashA, &ctx );

   memcpy( &ctx, &sha3_mid_ctxB, sizeof ctx );
   sha3_4way_update( &ctx, &vnonce, 8 );
   sha3_4way_final( vhashB, &ctx );

   dintrlv_4x64( hash,     hash+64,  hash+128, hash+192, vhashA, 512 );
   dintrlv_4x64( hash+256, hash+320, hash+384, hash+448, vhashB, 512 );
   
#else

   for ( int i = 0; i < 8; i++ )
   {
      sha3_ctx_t ctx;
      memcpy( &ctx, &sha3_mid_ctx[i], sizeof ctx );
      sha3_update( &ctx, &nonce, 8 );
      sha3_final( hash + i*64, &ctx );
   }
   
#endif
}

int scanhash_verthash( struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t edata[20] __attribute__((aligned(64)));
   uint32_t hash[8] __attribute__((aligned(64)));
   uint32_t *pdata = work->data;
   const uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 1;
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;
   const bool bench = opt_benchmark;

   mm128_bswap32_80( edata, pdata );
   verthash_sha3_512_prehash_72( edata );

   do
   {
      edata[19] = n;
      verthash_hash( verthashInfo.data, verthashInfo.dataSize, 
                     edata,  hash );
      if ( valid_hash( hash, ptarget ) && !bench )
      {
         pdata[19] = bswap_32( n );
         submit_solution( work, hash, mythr );
      }
      n++;
   } while ( n < last_nonce && !work_restart[thr_id].restart );
   *hashes_done = n - first_nonce;
   pdata[19] = n;
   return 0;
}

static const char *default_verthash_data_file = "verthash.dat";

bool register_verthash_algo( algo_gate_t* gate )
{
  opt_target_factor = 256.0;
  gate->scanhash  = (void*)&scanhash_verthash;
  gate->optimizations = AVX2_OPT;
   
  const char *verthash_data_file = opt_data_file ? opt_data_file
                                                 : default_verthash_data_file;
  
   int vhLoadResult = verthash_info_init( &verthashInfo, verthash_data_file );
   if (vhLoadResult == 0) // No Error
   {
      if ( opt_verify )
      {
         uint8_t vhDataFileHash[32] = { 0 };

         applog( LOG_NOTICE, "Verifying Verthash data" );
         sha256_full( vhDataFileHash, verthashInfo.data,
                          verthashInfo.dataSize );
         if ( memcmp( vhDataFileHash, verthashDatFileHash_bytes,
                      sizeof(verthashDatFileHash_bytes) ) == 0 )
            applog( LOG_NOTICE, "Verthash data has been verified" );
         else
         {
            applog( LOG_ERR, "Verthash data verification has failed" );
            return false;
         }
      }
   }
   else
   {
      // Handle Verthash error codes
      if ( vhLoadResult == 1 )
      {
         applog( LOG_ERR, "Verthash data file not found: %s",
                 verthash_data_file );
         if ( !opt_data_file )
            applog( LOG_NOTICE, "Add '--verify' to create verthash.dat");
      }
      else if ( vhLoadResult == 2 )
         applog( LOG_ERR, "Failed to allocate memory for Verthash data" );
//       else // for debugging purposes
//          applog( LOG_ERR, "Verthash data initialization unknown error code: %d",
//                 vhLoadResult );
      return false;
   }

   printf("\n");
   return true;
}

