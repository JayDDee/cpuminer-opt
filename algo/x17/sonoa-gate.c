#include "sonoa-gate.h"

bool register_sonoa_algo( algo_gate_t* gate )
{
#if defined (SONOA_4WAY)
//  init_sonoa_4way_ctx();
  gate->scanhash  = (void*)&scanhash_sonoa_4way;
  gate->hash      = (void*)&sonoa_4way_hash;
#else
  init_sonoa_ctx();
  gate->scanhash  = (void*)&scanhash_sonoa;
  gate->hash      = (void*)&sonoa_hash;
#endif
  gate->get_max64     = (void*)&get_max64_0x1ffff;
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT;
  return true;
};

