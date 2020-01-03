#include "x13-gate.h"

bool register_x13_algo( algo_gate_t* gate )
{
#if defined (X13_8WAY)
  init_x13_8way_ctx();
  gate->scanhash  = (void*)&scanhash_x13_8way;
  gate->hash      = (void*)&x13_8way_hash;
#elif defined (X13_4WAY)
  init_x13_4way_ctx();
  gate->scanhash  = (void*)&scanhash_x13_4way;
  gate->hash      = (void*)&x13_4way_hash;
#else
  init_x13_ctx();
  gate->scanhash  = (void*)&scanhash_x13;
  gate->hash      = (void*)&x13hash;
#endif
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT | AVX512_OPT | VAES_OPT;
  return true;
};

