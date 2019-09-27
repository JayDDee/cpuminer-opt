#include "bmw512-gate.h"

int64_t bmw512_get_max64() { return 0x7ffffLL; }

bool register_bmw512_algo( algo_gate_t* gate )
{
  gate->optimizations = AVX2_OPT;
  gate->get_max64       = (void*)&bmw512_get_max64;
  opt_target_factor = 256.0;
#if defined (BMW512_4WAY)
  gate->scanhash  = (void*)&scanhash_bmw512_4way;
  gate->hash      = (void*)&bmw512hash_4way;
#else
  gate->scanhash        = (void*)&scanhash_bmw512;
  gate->hash            = (void*)&bmw512hash;
#endif
  return true;
};


