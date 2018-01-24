#include "x13-gate.h"

bool register_x13_algo( algo_gate_t* gate )
{
#if defined (X13_4WAY)
  init_x13_4way_ctx();
  gate->scanhash  = (void*)&scanhash_x13_4way;
  gate->hash      = (void*)&x13_4way_hash;
#else
  init_x13_ctx();
  gate->scanhash  = (void*)&scanhash_x13;
  gate->hash      = (void*)&x13hash;
#endif
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT;
  gate->get_max64 = (void*)&get_max64_0x3ffff;
  return true;
};

