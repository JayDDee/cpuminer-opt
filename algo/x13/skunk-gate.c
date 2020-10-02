#include "skunk-gate.h"

bool register_skunk_algo( algo_gate_t* gate )
{
   gate->optimizations = SSE2_OPT | AVX2_OPT | AVX512_OPT | AES_OPT;
#if defined (SKUNK_8WAY)
   gate->miner_thread_init = (void*)&skunk_8way_thread_init;
   gate->scanhash = (void*)&scanhash_skunk_8way;
   gate->hash     = (void*)&skunk_8way_hash;
#elif defined (SKUNK_4WAY)
   gate->miner_thread_init = (void*)&skunk_4way_thread_init;
   gate->scanhash = (void*)&scanhash_skunk_4way;
   gate->hash     = (void*)&skunk_4way_hash;
#else
   gate->miner_thread_init = (void*)&skunk_thread_init;
   gate->scanhash = (void*)&scanhash_skunk;
   gate->hash     = (void*)&skunkhash;
#endif
   return true;
}

