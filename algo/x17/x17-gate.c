#include "x17-gate.h"

bool register_x17_algo( algo_gate_t* gate )
{
#if defined (X17_4WAY)
printf("register x17 4way\n");
//  init_x17_4way_ctx();
  gate->scanhash  = (void*)&scanhash_x17_4way;
  gate->hash      = (void*)&x17_4way_hash;
#else
printf("register x17 no 4way\n");
  init_x17_ctx();
  gate->scanhash  = (void*)&scanhash_x17;
  gate->hash      = (void*)&x17_hash;
#endif
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT;
  return true;
};

