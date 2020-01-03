#include "qubit-gate.h"

bool register_qubit_algo( algo_gate_t* gate )
{
   
#if defined (QUBIT_4WAY)
  init_qubit_4way_ctx();
  gate->scanhash  = (void*)&scanhash_qubit_4way;
  gate->hash      = (void*)&qubit_4way_hash;
#elif defined (QUBIT_2WAY)
  init_qubit_2way_ctx();
  gate->scanhash  = (void*)&scanhash_qubit_2way;
  gate->hash      = (void*)&qubit_2way_hash;
#else
  init_qubit_ctx();
  gate->scanhash  = (void*)&scanhash_qubit;
  gate->hash      = (void*)&qubit_hash;
#endif
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT | AVX512_OPT | VAES_OPT;
  return true;
};

