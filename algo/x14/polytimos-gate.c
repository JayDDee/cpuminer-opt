#include "polytimos-gate.h"

bool register_polytimos_algo( algo_gate_t* gate )
{
  gate->optimizations = SSE2_OPT | AES_OPT | AVX_OPT | AVX2_OPT;
#ifdef POLYTIMOS_4WAY
  init_polytimos_4way_ctx();
  gate->scanhash  = (void*)&scanhash_polytimos_4way;
  gate->hash      = (void*)&polytimos_4way_hash;
#else
  init_polytimos_context();
  gate->scanhash  = (void*)&scanhash_polytimos;
  gate->hash      = (void*)&polytimos_hash;
#endif
  gate->get_max64 = (void*)&get_max64_0x3ffff;
  return true;
};

