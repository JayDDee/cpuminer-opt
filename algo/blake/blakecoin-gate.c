#include "blakecoin-gate.h"
#include <memory.h>

// vanilla uses default gen merkle root, otherwise identical to blakecoin
bool register_vanilla_algo( algo_gate_t* gate )
{
#if defined(BLAKECOIN_8WAY)
  gate->scanhash  = (void*)&scanhash_blakecoin_8way;
  gate->hash      = (void*)&blakecoin_8way_hash;

#elif defined(BLAKECOIN_4WAY)
  gate->scanhash  = (void*)&scanhash_blakecoin_4way;
  gate->hash      = (void*)&blakecoin_4way_hash;
#else
  gate->scanhash = (void*)&scanhash_blakecoin;
  gate->hash     = (void*)&blakecoinhash;
#endif
  gate->optimizations = SSE42_OPT | AVX2_OPT;
  return true;
}

bool register_blakecoin_algo( algo_gate_t* gate )
{
  register_vanilla_algo( gate );
  gate->gen_merkle_root = (void*)&SHA256_gen_merkle_root;
  return true;
}

