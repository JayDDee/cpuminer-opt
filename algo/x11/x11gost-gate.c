#include "x11gost-gate.h"

bool register_x11gost_algo( algo_gate_t* gate )
{
#if defined (X11GOST_4WAY)
  init_x11gost_4way_ctx();
  gate->scanhash  = (void*)&scanhash_x11gost_4way;
  gate->hash      = (void*)&x11gost_4way_hash;
#else
  init_x11gost_ctx();
  gate->scanhash  = (void*)&scanhash_x11gost;
  gate->hash      = (void*)&x11gost_hash;
#endif
  gate->optimizations = SSE2_OPT | AES_OPT | AVX_OPT | AVX2_OPT;
  gate->get_max64 = (void*)&get_max64_0x3ffff;
  return true;
};

