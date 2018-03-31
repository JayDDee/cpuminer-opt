#include "qubit-gate.h"

bool register_qubit_algo( algo_gate_t* gate )
{
#if defined (QUBIT_2WAY)
  init_qubit_2way_ctx();
  gate->scanhash  = (void*)&scanhash_qubit_2way;
  gate->hash      = (void*)&qubit_2way_hash;
#else
  init_qubit_ctx();
  gate->scanhash  = (void*)&scanhash_qubit;
  gate->hash      = (void*)&qubit_hash;
#endif
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT;
  return true;
};

