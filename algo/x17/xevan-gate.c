#include "xevan-gate.h"

bool register_xevan_algo( algo_gate_t* gate )
{
#if defined (XEVAN_4WAY)
//  init_xevan_4way_ctx();
  gate->scanhash  = (void*)&scanhash_xevan_4way;
  gate->hash      = (void*)&xevan_4way_hash;
#else
  init_xevan_ctx();
  gate->scanhash  = (void*)&scanhash_xevan;
  gate->hash      = (void*)&xevan_hash;
#endif
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT;
  opt_target_factor = 256.0;
  return true;
};

