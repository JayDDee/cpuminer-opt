#include "tribus-gate.h"

bool register_tribus_algo( algo_gate_t* gate )
{
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT | AVX512_OPT | VAES_OPT;
#if defined (TRIBUS_8WAY)
  gate->scanhash      = (void*)&scanhash_tribus_8way;
  gate->hash          = (void*)&tribus_hash_8way;
#elif defined (TRIBUS_4WAY)
  gate->scanhash      = (void*)&scanhash_tribus_4way;
  gate->hash          = (void*)&tribus_hash_4way;
#else
  gate->miner_thread_init = (void*)&tribus_thread_init;
  gate->scanhash      = (void*)&scanhash_tribus;
  gate->hash          = (void*)&tribus_hash;
#endif
  return true;
};

