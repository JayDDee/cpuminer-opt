#include "xevan-gate.h"

bool register_xevan_algo( algo_gate_t* gate )
{
#if defined (XEVAN_8WAY)
  gate->scanhash  = (void*)&scanhash_8way_64in_32out;
  gate->hash      = (void*)&xevan_8way_hash;
#elif defined (XEVAN_4WAY)
  gate->scanhash  = (void*)&scanhash_4way_64in_32out;
  gate->hash      = (void*)&xevan_4way_hash;
#else
  init_xevan_ctx();
  gate->hash      = (void*)&xevan_hash;
#endif
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT | AVX512_OPT | VAES_OPT | VAES256_OPT;
  opt_target_factor = 256.0;
  return true;
};

