#include "skunk-gate.h"

bool register_skunk_algo( algo_gate_t* gate )
{
   gate->optimizations = SSE2_OPT | AVX_OPT | AVX2_OPT;
#if defined (SKUNK_4WAY)
   gate->miner_thread_init = (void*)&skunk_4way_thread_init;
   gate->scanhash = (void*)&scanhash_skunk_4way;
   gate->hash     = (void*)&skunk_4way_hash;
//   init_skunk_4way_ctx();
#else
   gate->miner_thread_init = (void*)&skunk_thread_init;
   gate->scanhash = (void*)&scanhash_skunk;
   gate->hash     = (void*)&skunkhash;
#endif
   return true;
}

