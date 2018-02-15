#include "x12-gate.h"

bool register_x12_algo( algo_gate_t* gate )
{
#if defined (X12_4WAY)
  init_x12_4way_ctx();
  gate->scanhash  = (void*)&scanhash_x12_4way;
  gate->hash      = (void*)&x12_4way_hash;
#else
  init_x12_ctx();
  gate->scanhash  = (void*)&scanhash_x12;
  gate->hash      = (void*)&x12hash;
#endif
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT;
  gate->get_max64 = (void*)&get_max64_0x3ffff;
  return true;
};

