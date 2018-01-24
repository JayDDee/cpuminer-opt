#include "quark-gate.h"

bool register_quark_algo( algo_gate_t* gate )
{
#if defined (QUARK_4WAY)
  init_quark_4way_ctx();
  gate->scanhash  = (void*)&scanhash_quark_4way;
  gate->hash      = (void*)&quark_4way_hash;
#else
  init_quark_ctx();
  gate->scanhash  = (void*)&scanhash_quark;
  gate->hash      = (void*)&quark_hash;
#endif
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT;
  return true;
};

