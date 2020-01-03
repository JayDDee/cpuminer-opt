#include "myrgr-gate.h"

bool register_myriad_algo( algo_gate_t* gate )
{
#if defined (MYRGR_8WAY)
  init_myrgr_8way_ctx();
  gate->scanhash  = (void*)&scanhash_myriad_8way;
  gate->hash      = (void*)&myriad_8way_hash;
  gate->optimizations = AES_OPT | AVX2_OPT | VAES_OPT;
#elif defined (MYRGR_4WAY)
  init_myrgr_4way_ctx();
  gate->scanhash  = (void*)&scanhash_myriad_4way;
  gate->hash      = (void*)&myriad_4way_hash;
  gate->optimizations = AES_OPT | SSE2_OPT | AVX2_OPT | VAES_OPT;
#else
  init_myrgr_ctx();
  gate->scanhash  = (void*)&scanhash_myriad;
  gate->hash      = (void*)&myriad_hash;
  gate->optimizations = AES_OPT | SSE2_OPT | AVX2_OPT | SHA_OPT | VAES_OPT;
#endif
  return true;
};

