#include <memory.h>
#include "algo-gate-api.h"
#include "lyra2.h"
#include "simd-utils.h"

__thread uint64_t* lyra2z330_wholeMatrix;

void lyra2z330_hash(void *state, const void *input, uint32_t height)
{
	uint32_t _ALIGN(256) hash[16];

   LYRA2Z( lyra2z330_wholeMatrix, hash, 32, input, 80, input, 80,
                 2, 330, 256 );

	memcpy(state, hash, 32);
}

int scanhash_lyra2z330( struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t hash[8] __attribute__ ((aligned (128))); 
   uint32_t edata[20] __attribute__ ((aligned (64)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   uint32_t nonce = first_nonce;
   const int thr_id = mythr->id; 

   if (opt_benchmark)
	ptarget[7] = 0x0000ff;

   casti_m128i( edata, 0 ) = mm128_bswap_32( casti_m128i( pdata, 0 ) );
   casti_m128i( edata, 1 ) = mm128_bswap_32( casti_m128i( pdata, 1 ) );
   casti_m128i( edata, 2 ) = mm128_bswap_32( casti_m128i( pdata, 2 ) );
   casti_m128i( edata, 3 ) = mm128_bswap_32( casti_m128i( pdata, 3 ) );
   casti_m128i( edata, 4 ) = mm128_bswap_32( casti_m128i( pdata, 4 ) );
   
   do
   {
      edata[19] = nonce;

      LYRA2Z( lyra2z330_wholeMatrix, hash, 32, edata, 80, edata, 80,
                 2, 330, 256 );
      
//      lyra2z330_hash( hash, edata, work->height );
      if ( valid_hash( hash, ptarget ) && !opt_benchmark )
      {
         be32enc( pdata + 19, nonce );
         submit_solution( work, hash, mythr );
      }
      nonce++;
   } while ( nonce < max_nonce && !work_restart[thr_id].restart );
   pdata[19] = nonce;
   *hashes_done = nonce - first_nonce;
   return 0;
}

bool lyra2z330_thread_init()
{
   const int64_t ROW_LEN_INT64 = BLOCK_LEN_INT64 * 256; // nCols
   const int64_t ROW_LEN_BYTES = ROW_LEN_INT64 * 8;

   int i = (int64_t)ROW_LEN_BYTES * 330; // nRows;
   lyra2z330_wholeMatrix = _mm_malloc( i, 64 );

   return lyra2z330_wholeMatrix;
}

bool register_lyra2z330_algo( algo_gate_t* gate )
{
  gate->optimizations = SSE2_OPT | AVX2_OPT;
  gate->miner_thread_init = (void*)&lyra2z330_thread_init;
  gate->scanhash   = (void*)&scanhash_lyra2z330;
  gate->hash       = (void*)&lyra2z330_hash;
  opt_target_factor = 256.0;
  return true;
};

