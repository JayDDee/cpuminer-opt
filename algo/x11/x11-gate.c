#include "x11-gate.h"

bool register_x11_algo( algo_gate_t *gate )
{
#if defined (X11_8WAY)
  init_x11_8way_ctx();
  gate->scanhash  = (void*)&scanhash_x11_8way;
  gate->hash      = (void*)&x11_8way_hash;
#elif defined (X11_4WAY)
  init_x11_4way_ctx();
  gate->scanhash  = (void*)&scanhash_x11_4way;
  gate->hash      = (void*)&x11_4way_hash;
#else
  init_x11_ctx();
  gate->scanhash  = (void*)&scanhash_x11;
  gate->hash      = (void*)&x11_hash;
#endif
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT | AVX512_OPT | VAES_OPT ;
  return true;
};

