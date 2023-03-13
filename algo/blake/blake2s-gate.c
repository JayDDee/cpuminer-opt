#include "blake2s-gate.h"

bool register_blake2s_algo( algo_gate_t* gate )
{
#if defined(BLAKE2S_16WAY)
  gate->scanhash  = (void*)&scanhash_blake2s_16way;
  gate->hash      = (void*)&blake2s_16way_hash;
#elif defined(BLAKE2S_8WAY)
//#if defined(BLAKE2S_8WAY)
  gate->scanhash  = (void*)&scanhash_blake2s_8way;
  gate->hash      = (void*)&blake2s_8way_hash;
#elif defined(BLAKE2S_4WAY)
  gate->scanhash  = (void*)&scanhash_blake2s_4way;
  gate->hash      = (void*)&blake2s_4way_hash;
#else
  gate->scanhash  = (void*)&scanhash_blake2s;
  gate->hash      = (void*)&blake2s_hash;
#endif
  gate->optimizations = SSE2_OPT | AVX2_OPT | AVX512_OPT;
  return true;
};


