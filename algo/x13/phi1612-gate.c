#include "phi1612-gate.h"

bool register_phi1612_algo( algo_gate_t* gate )
{
#if defined(PHI1612_4WAY)
  init_phi1612_4way_ctx();
  gate->scanhash  = (void*)&scanhash_phi1612_4way;
  gate->hash      = (void*)&phi1612_4way_hash;
#else
  init_phi1612_ctx();
  gate->scanhash  = (void*)&scanhash_phi1612;
  gate->hash      = (void*)&phi1612_hash;
#endif
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT;
  gate->get_max64 = (void*)&get_max64_0x3ffff;
  return true;
};

