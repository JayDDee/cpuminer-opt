#include "blake-gate.h"

int64_t blake_get_max64 ()
{
  return 0x7ffffLL;
}

bool register_blake_algo( algo_gate_t* gate )
{
  gate->optimizations = AVX2_OPT;
  gate->get_max64 = (void*)&blake_get_max64;
//#if defined (__AVX2__) && defined (FOUR_WAY)
//   gate->optimizations = SSE2_OPT | AVX_OPT | AVX2_OPT;
//  gate->scanhash  = (void*)&scanhash_blake_8way;
//  gate->hash      = (void*)&blakehash_8way;
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

