#include "lyra2rev2-gate.h"

__thread uint64_t* l2v2_wholeMatrix;

void lyra2rev2_set_target( struct work* work, double job_diff )
{
 work_set_target( work, job_diff / (256.0 * opt_diff_factor) );
}

bool lyra2rev2_thread_init()
{
   const int64_t ROW_LEN_INT64 = BLOCK_LEN_INT64 * 4; // nCols
   const int64_t ROW_LEN_BYTES = ROW_LEN_INT64 * 8;

   int i = (int64_t)ROW_LEN_BYTES * 4; // nRows;
   l2v2_wholeMatrix = _mm_malloc( i, 64 );

   return l2v2_wholeMatrix;
}

bool register_lyra2rev2_algo( algo_gate_t* gate )
{
#if defined (LYRA2REV2_4WAY)
  init_lyra2rev2_4way_ctx();
  gate->scanhash  = (void*)&scanhash_lyra2rev2_4way;
  gate->hash      = (void*)&lyra2rev2_4way_hash;
#else
  init_lyra2rev2_ctx();
  gate->scanhash  = (void*)&scanhash_lyra2rev2;
  gate->hash      = (void*)&lyra2rev2_hash;
#endif
  gate->optimizations = SSE2_OPT | AES_OPT | AVX_OPT | AVX2_OPT;
  gate->miner_thread_init = (void*)&lyra2rev2_thread_init;
  gate->set_target        = (void*)&lyra2rev2_set_target;
  return true;
};


