#include "c11-gate.h"

bool register_c11_algo( algo_gate_t* gate )
{
#if defined (C11_8WAY)
  init_c11_8way_ctx();
  gate->scanhash  = (void*)&scanhash_c11_8way;
  gate->hash      = (void*)&c11_8way_hash;
#elif defined (C11_4WAY)
  init_c11_4way_ctx();
  gate->scanhash  = (void*)&scanhash_c11_4way;
  gate->hash      = (void*)&c11_4way_hash;
#else
  init_c11_ctx();
  gate->scanhash  = (void*)&scanhash_c11;
  gate->hash      = (void*)&c11_hash;
#endif
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT | AVX512_OPT | VAES_OPT;
  return true;
};

