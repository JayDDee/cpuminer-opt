#include "x13sm3-gate.h"

bool register_x13sm3_algo( algo_gate_t* gate )
{
#if defined (X13SM3_4WAY)
  init_x13sm3_4way_ctx();
  gate->scanhash  = (void*)&scanhash_x13sm3_4way;
  gate->hash      = (void*)&x13sm3_4way_hash;
#else
  init_x13sm3_ctx();
  gate->scanhash  = (void*)&scanhash_x13sm3;
  gate->hash      = (void*)&x13sm3_hash;
#endif
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT;
  return true;
};

bool register_x13bcd_algo( algo_gate_t* gate )
{
#if defined (X13BCD_8WAY)
  init_x13bcd_8way_ctx();
  gate->scanhash  = (void*)&scanhash_x13bcd_8way;
  gate->hash      = (void*)&x13bcd_8way_hash;
#elif defined (X13BCD_4WAY)
  init_x13bcd_4way_ctx();
  gate->scanhash  = (void*)&scanhash_x13bcd_4way;
  gate->hash      = (void*)&x13bcd_4way_hash;
#else
  init_x13bcd_ctx();
  gate->scanhash  = (void*)&scanhash_x13bcd;
  gate->hash      = (void*)&x13bcd_hash;
#endif
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT | AVX512_OPT | VAES_OPT;
  return true;
};

