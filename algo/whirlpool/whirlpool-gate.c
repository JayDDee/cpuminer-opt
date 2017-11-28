#include "whirlpool-gate.h"

bool register_whirlpool_algo( algo_gate_t* gate )
{
//#if defined (WHIRLPOOL_4WAY)
//  gate->scanhash  = (void*)&scanhash_whirlpool_4way;
//  gate->hash      = (void*)&whirlpool_hash_4way;
//#else
  gate->scanhash  = (void*)&scanhash_whirlpool;
  gate->hash      = (void*)&whirlpool_hash;
  init_whirlpool_ctx();
//#endif
  return true;
};

