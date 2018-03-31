#include "allium-gate.h"

int64_t get_max64_0xFFFFLL() { return 0xFFFFLL; }

bool register_allium_algo( algo_gate_t* gate )
{
#if defined (ALLIUM_4WAY)
  gate->miner_thread_init = (void*)&init_allium_4way_ctx;
  gate->scanhash  = (void*)&scanhash_allium_4way;
  gate->hash      = (void*)&allium_4way_hash;
#else
  gate->miner_thread_init = (void*)&init_allium_ctx;
  gate->scanhash  = (void*)&scanhash_allium;
  gate->hash      = (void*)&allium_hash;
#endif
  gate->optimizations = SSE2_OPT | AES_OPT | SSE42_OPT | AVX2_OPT;
  gate->set_target        = (void*)&alt_set_target;
  gate->get_max64         = (void*)&get_max64_0xFFFFLL;
  return true;
};


