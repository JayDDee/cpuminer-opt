#include "skein2-gate.h"
#include <stdint.h>
#include "sph_skein.h"

int64_t skein2_get_max64 ()
{
  return 0x7ffffLL;
}

bool register_skein2_algo( algo_gate_t* gate )
{
  gate->optimizations = AVX2_OPT;
#if defined (FOUR_WAY) && defined (__AVX2__)
  gate->scanhash  = (void*)&scanhash_skein2_4way;
  gate->hash      = (void*)&skein2hash_4way;
  four_way_not_tested();
#else
  gate->scanhash  = (void*)&scanhash_skein2;
  gate->hash      = (void*)&skein2hash;
#endif
  gate->get_max64 = (void*)&skein2_get_max64;
  return true;
};

