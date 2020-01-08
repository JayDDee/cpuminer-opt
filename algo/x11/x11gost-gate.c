#include "x11gost-gate.h"

bool register_x11gost_algo( algo_gate_t* gate )
{
#if defined (X11GOST_8WAY)
  init_x11gost_8way_ctx();
  gate->scanhash  = (void*)&scanhash_x11gost_8way;
  gate->hash      = (void*)&x11gost_8way_hash;
#elif defined (X11GOST_4WAY)
  init_x11gost_4way_ctx();
  gate->scanhash  = (void*)&scanhash_x11gost_4way;
  gate->hash      = (void*)&x11gost_4way_hash;
#else
  init_x11gost_ctx();
  gate->scanhash  = (void*)&scanhash_x11gost;
  gate->hash      = (void*)&x11gost_hash;
#endif
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT | AVX512_OPT | VAES_OPT;
  return true;
};

