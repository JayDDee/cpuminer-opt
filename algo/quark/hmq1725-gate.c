#include "hmq1725-gate.h"

bool register_hmq1725_algo( algo_gate_t* gate )
{
#if defined(HMQ1725_4WAY)
  gate->scanhash  = (void*)&scanhash_hmq1725_4way;
  gate->hash      = (void*)&hmq1725_4way_hash;
#else
  init_hmq1725_ctx();
  gate->scanhash  = (void*)&scanhash_hmq1725;
  gate->hash      = (void*)&hmq1725hash;
#endif
  gate->set_target       = (void*)&scrypt_set_target;
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT;
  return true;
};

