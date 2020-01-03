#include "phi1612-gate.h"

bool register_phi1612_algo( algo_gate_t* gate )
{
#if defined(PHI1612_8WAY)
  init_phi1612_8way_ctx();
  gate->scanhash  = (void*)&scanhash_phi1612_8way;
  gate->hash      = (void*)&phi1612_8way_hash;
#elif defined(PHI1612_4WAY)
  init_phi1612_4way_ctx();
  gate->scanhash  = (void*)&scanhash_phi1612_4way;
  gate->hash      = (void*)&phi1612_4way_hash;
#else
  init_phi1612_ctx();
  gate->scanhash  = (void*)&scanhash_phi1612;
  gate->hash      = (void*)&phi1612_hash;
#endif
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT | AVX512_OPT | VAES_OPT;
  return true;
};

