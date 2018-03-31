#include "blake2s-gate.h"


// changed to get_max64_0x3fffffLL in cpuminer-multi-decred
int64_t blake2s_get_max64 ()
{
   return 0x7ffffLL;
}

bool register_blake2s_algo( algo_gate_t* gate )
{
#if defined(BLAKE2S_8WAY)
  gate->scanhash  = (void*)&scanhash_blake2s_8way;
  gate->hash      = (void*)&blake2s_8way_hash;
#elif defined(BLAKE2S_4WAY)
  gate->scanhash  = (void*)&scanhash_blake2s_4way;
  gate->hash      = (void*)&blake2s_4way_hash;
#else
  gate->scanhash  = (void*)&scanhash_blake2s;
  gate->hash      = (void*)&blake2s_hash;
#endif
  gate->get_max64 = (void*)&blake2s_get_max64;
  gate->optimizations = SSE42_OPT | AVX2_OPT;
  return true;
};


