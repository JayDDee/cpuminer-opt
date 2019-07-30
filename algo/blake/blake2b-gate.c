#include "blake2b-gate.h"

/*
// changed to get_max64_0x3fffffLL in cpuminer-multi-decred
int64_t blake2s_get_max64 ()
{
   return 0x7ffffLL;
}
*/

bool register_blake2b_algo( algo_gate_t* gate )
{
#if defined(BLAKE2B_4WAY)
  gate->scanhash  = (void*)&scanhash_blake2b_4way;
  gate->hash      = (void*)&blake2b_4way_hash;
#else
  gate->scanhash  = (void*)&scanhash_blake2b;
  gate->hash      = (void*)&blake2b_hash;
#endif
//  gate->get_max64 = (void*)&blake2s_get_max64;
  gate->optimizations =  AVX2_OPT;
  return true;
};


