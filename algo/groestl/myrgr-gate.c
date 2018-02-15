#include "myrgr-gate.h"

bool register_myriad_algo( algo_gate_t* gate )
{
#if defined (MYRGR_4WAY)
  init_myrgr_4way_ctx();
  gate->scanhash  = (void*)&scanhash_myriad_4way;
  gate->hash      = (void*)&myriad_4way_hash;
#else
  init_myrgr_ctx();
  gate->scanhash  = (void*)&scanhash_myriad;
  gate->hash      = (void*)&myriad_hash;
#endif
  gate->optimizations = AES_OPT | AVX2_OPT;
  gate->get_max64 = (void*)&get_max64_0x3ffff;
  return true;
};

