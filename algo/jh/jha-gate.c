#include "jha-gate.h"


bool register_jha_algo( algo_gate_t* gate )
{
#if defined (JHA_4WAY)
  four_way_not_tested();
  gate->scanhash         = (void*)&scanhash_jha_4way;
  gate->hash             = (void*)&jha_hash_4way;
#else
  gate->scanhash         = (void*)&scanhash_jha;
  gate->hash             = (void*)&jha_hash;
#endif
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT;
  opt_target_factor = 65536.0;
  return true;
};

