#include "deep-gate.h"

bool register_deep_algo( algo_gate_t* gate )
{
#if defined (DEEP_2WAY)
  init_deep_2way_ctx();
  gate->scanhash  = (void*)&scanhash_deep_2way;
  gate->hash      = (void*)&deep_2way_hash;
#else
  init_deep_ctx();
  gate->scanhash  = (void*)&scanhash_deep;
  gate->hash      = (void*)&deep_hash;
#endif
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT;
  return true;
};

