#include "sonoa-gate.h"

bool register_sonoa_algo( algo_gate_t* gate )
{
#if defined (SONOA_8WAY)
  gate->scanhash  = (void*)&scanhash_sonoa_8way;
//  gate->hash      = (void*)&sonoa_8way_hash;
#elif defined (SONOA_4WAY)
  gate->scanhash  = (void*)&scanhash_sonoa_4way;
//  gate->hash      = (void*)&sonoa_4way_hash;
#else
  init_sonoa_ctx();
  gate->scanhash  = (void*)&scanhash_sonoa;
//  gate->hash      = (void*)&sonoa_hash;
#endif
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT | AVX512_OPT | VAES_OPT;
  return true;
};

