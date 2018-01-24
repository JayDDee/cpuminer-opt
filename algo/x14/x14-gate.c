#include "x14-gate.h"

bool register_x14_algo( algo_gate_t* gate )
{
#if defined (X14_4WAY)
  init_x14_4way_ctx();
  gate->scanhash  = (void*)&scanhash_x14_4way;
  gate->hash      = (void*)&x14_4way_hash;
#else
  init_x14_ctx();
  gate->scanhash  = (void*)&scanhash_x14;
  gate->hash      = (void*)&x14hash;
#endif
  gate->optimizations = SSE2_OPT | AES_OPT | AVX_OPT | AVX2_OPT;
  gate->get_max64 = (void*)&get_max64_0x3ffff;
  return true;
};

