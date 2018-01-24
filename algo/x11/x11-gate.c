#include "x11-gate.h"

bool register_x11_algo( algo_gate_t* gate )
{
#if defined (X11_4WAY)
  init_x11_4way_ctx();
  gate->scanhash  = (void*)&scanhash_x11_4way;
  gate->hash      = (void*)&x11_4way_hash;
#else
  init_x11_ctx();
  gate->scanhash  = (void*)&scanhash_x11;
  gate->hash      = (void*)&x11_hash;
#endif
  gate->optimizations = SSE2_OPT | AES_OPT | AVX_OPT | AVX2_OPT;
  gate->get_max64 = (void*)&get_max64_0x3ffff;
  return true;
};

