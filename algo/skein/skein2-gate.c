#include "skein2-gate.h"
#include <stdint.h>
#include "sph_skein.h"

bool register_skein2_algo( algo_gate_t* gate )
{
  gate->optimizations = AVX2_OPT;
#if defined (SKEIN2_4WAY)
  gate->scanhash  = (void*)&scanhash_skein2_4way;
  gate->hash      = (void*)&skein2hash_4way;
#else
  gate->scanhash  = (void*)&scanhash_skein2;
  gate->hash      = (void*)&skein2hash;
#endif
  return true;
};

