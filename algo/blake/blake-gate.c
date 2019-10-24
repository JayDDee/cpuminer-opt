#include "blake-gate.h"

bool register_blake_algo( algo_gate_t* gate )
{
  gate->optimizations = AVX2_OPT;
#if defined(BLAKE_4WAY)
  four_way_not_tested();
  gate->scanhash  = (void*)&scanhash_blake_4way;
  gate->hash      = (void*)&blakehash_4way;
#else
  gate->scanhash  = (void*)&scanhash_blake;
  gate->hash      = (void*)&blakehash;
#endif
  return true;
}

