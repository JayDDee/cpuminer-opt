#include "x22i-gate.h"

bool register_x22i_algo( algo_gate_t* gate )
{
#if defined (X22I_4WAY)
  gate->scanhash  = (void*)&scanhash_x22i_4way;
  gate->hash      = (void*)&x22i_4way_hash;
#else
  gate->scanhash  = (void*)&scanhash_x22i;
  gate->hash      = (void*)&x22i_hash;
#endif
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT | SHA_OPT;
  return true;
};

bool register_x25x_algo( algo_gate_t* gate )
{
#if defined (X22I_4WAY)
  gate->scanhash  = (void*)&scanhash_x25x_4way;
  gate->hash      = (void*)&x25x_4way_hash;
#else
  gate->scanhash  = (void*)&scanhash_x25x;
  gate->hash      = (void*)&x25x_hash;
#endif
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT | SHA_OPT;
  return true;
};

