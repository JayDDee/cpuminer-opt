#include "x15-gate.h"

bool register_x15_algo( algo_gate_t* gate )
{
#if defined (X15_4WAY)
  init_x15_4way_ctx();
  gate->scanhash  = (void*)&scanhash_x15_4way;
  gate->hash      = (void*)&x15_4way_hash;
#else
  init_x15_ctx();
  gate->scanhash  = (void*)&scanhash_x15;
  gate->hash      = (void*)&x15hash;
#endif
  gate->optimizations = SSE2_OPT | AES_OPT | AVX_OPT | AVX2_OPT;
  return true;
};

