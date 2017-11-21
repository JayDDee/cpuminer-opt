#include "skein2-gate.h"
#include "algo-gate-api.h"
//#include <string.h>
#include <stdint.h>
#include "sph_skein.h"
//#include "skein-hash-avx2.h"

int64_t skein2_get_max64 ()
{
  return 0x7ffffLL;
}

bool register_skein2_algo( algo_gate_t* gate )
{
#if defined (FOUR_WAY) && defined (__AVX2__)
  gate->optimizations = SSE2_OPT | AVX2_OPT;
  gate->scanhash  = (void*)&scanhash_skein2_4way;
  gate->hash      = (void*)&skein2hash_4way;
#else
  gate->optimizations = SSE2_OPT;
  gate->scanhash  = (void*)&scanhash_skein2;
  gate->hash      = (void*)&skein2hash;
#endif
  gate->get_max64 = (void*)&skein2_get_max64;
  return true;
};

