#include "bmw512-gate.h"

bool register_bmw512_algo( algo_gate_t* gate )
{
  gate->optimizations = AVX2_OPT | AVX512_OPT;
  opt_target_factor = 256.0;
#if defined (BMW512_8WAY)
  gate->scanhash  = (void*)&scanhash_bmw512_8way;
  gate->hash      = (void*)&bmw512hash_8way;
#elif defined (BMW512_4WAY)
  gate->scanhash  = (void*)&scanhash_bmw512_4way;
  gate->hash      = (void*)&bmw512hash_4way;
#else
  gate->scanhash        = (void*)&scanhash_bmw512;
  gate->hash            = (void*)&bmw512hash;
#endif
  return true;
};


