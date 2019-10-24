#include "tribus-gate.h"

bool register_tribus_algo( algo_gate_t* gate )
{
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT;
#if defined (TRIBUS_4WAY)
//  init_tribus_4way_ctx();
  gate->scanhash      = (void*)&scanhash_tribus_4way;
  gate->hash          = (void*)&tribus_hash_4way;
#else
  gate->miner_thread_init = (void*)&tribus_thread_init;
  gate->scanhash      = (void*)&scanhash_tribus;
  gate->hash          = (void*)&tribus_hash;
#endif
  return true;
};

