#include "x14-gate.h"

bool register_x14_algo( algo_gate_t* gate )
{
#if defined (X14_8WAY)
  init_x14_8way_ctx();
  gate->scanhash  = (void*)&scanhash_x14_8way;
  gate->hash      = (void*)&x14_8way_hash;
#elif defined (X14_4WAY)
  init_x14_4way_ctx();
  gate->scanhash  = (void*)&scanhash_x14_4way;
  gate->hash      = (void*)&x14_4way_hash;
#else
  init_x14_ctx();
  gate->scanhash  = (void*)&scanhash_x14;
  gate->hash      = (void*)&x14hash;
#endif
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT | AVX512_OPT | VAES_OPT;
  return true;
};

