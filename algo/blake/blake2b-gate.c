#include "blake2b-gate.h"

bool register_blake2b_algo( algo_gate_t* gate )
{
#if defined(BLAKE2B_4WAY)
  gate->scanhash  = (void*)&scanhash_blake2b_4way;
  gate->hash      = (void*)&blake2b_4way_hash;
#else
  gate->scanhash  = (void*)&scanhash_blake2b;
  gate->hash      = (void*)&blake2b_hash;
#endif
  gate->optimizations =  AVX2_OPT;
  return true;
};


