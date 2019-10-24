#include "veltor-gate.h"

bool register_veltor_algo( algo_gate_t* gate )
{
#if defined (VELTOR_4WAY)
  init_veltor_4way_ctx();
  gate->scanhash  = (void*)&scanhash_veltor_4way;
  gate->hash      = (void*)&veltor_4way_hash;
#else
  init_veltor_ctx();
  gate->scanhash  = (void*)&scanhash_veltor;
  gate->hash      = (void*)&veltor_hash;
#endif
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT;
  return true;
};

