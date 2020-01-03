#include "hmq1725-gate.h"

bool register_hmq1725_algo( algo_gate_t* gate )
{
#if defined(HMQ1725_8WAY)
  gate->scanhash  = (void*)&scanhash_hmq1725_8way;
  gate->hash      = (void*)&hmq1725_8way_hash;
#elif defined(HMQ1725_4WAY)
  gate->scanhash  = (void*)&scanhash_hmq1725_4way;
  gate->hash      = (void*)&hmq1725_4way_hash;
#else
  init_hmq1725_ctx();
  gate->scanhash  = (void*)&scanhash_hmq1725;
  gate->hash      = (void*)&hmq1725hash;
#endif
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT | AVX512_OPT | VAES_OPT;
  opt_target_factor = 65536.0;
  return true;
};

