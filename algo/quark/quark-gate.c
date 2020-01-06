#include "quark-gate.h"

bool register_quark_algo( algo_gate_t* gate )
{
#if defined (QUARK_8WAY)
  init_quark_8way_ctx();
  gate->scanhash  = (void*)&scanhash_quark_8way;
  gate->hash      = (void*)&quark_8way_hash;
#elif defined (QUARK_4WAY)
  init_quark_4way_ctx();
  gate->scanhash  = (void*)&scanhash_quark_4way;
  gate->hash      = (void*)&quark_4way_hash;
#else
  gate->scanhash  = (void*)&scanhash_quark;
  gate->hash      = (void*)&quark_hash;
#endif
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT | AVX512_OPT | VAES_OPT;
  return true;
};

