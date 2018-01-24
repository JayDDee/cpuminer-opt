#include "x13sm3-gate.h"

bool register_x13sm3_algo( algo_gate_t* gate )
{
#if defined (X13SM3_4WAY)
  init_x13sm3_4way_ctx();
  gate->scanhash  = (void*)&scanhash_x13sm3_4way;
  gate->hash      = (void*)&x13sm3_4way_hash;
#else
  init_x13sm3_ctx();
  gate->scanhash  = (void*)&scanhash_x13sm3;
  gate->hash      = (void*)&x13sm3_hash;
#endif
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT;
  gate->get_max64 = (void*)&get_max64_0x3ffff;
  return true;
};

